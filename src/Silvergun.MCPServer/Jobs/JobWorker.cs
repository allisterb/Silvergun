namespace Silvergun.MCPServer.Jobs;

using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>One job's analysis, supplied by the CLI so the report is exactly <c>scan-package --json</c>'s projection.</summary>
public delegate Result<JobScanOutput> JobScan(string nupkgPath, string extractionDir, JobDepth depth, bool network, IProgress<PackageScanProgress> progress);

/// <summary>
/// What <see cref="JobScan"/> produced: the typed report, its <c>--json</c> text, the gate, and which indicator categories
/// gate (the CLI's own predicate, so the summary never keeps a second copy of it).
/// </summary>
public sealed record JobScanOutput(PackageCapabilityReport Report, string ReportJson, JobGate Gate, IReadOnlySet<IndicatorCategory> GatingIndicators);

/// <summary>
/// The child half of job worker protocol v1 (<see cref="JobProtocol"/>), run by <c>__worker job</c>. It reads one request,
/// runs <see cref="JobScan"/> into <c>files/</c> beside the package, writes the artifacts, and reports. When its stdin ends
/// after the request (the server is gone) it exits at once. Never throws: every failure is one <c>fatal</c> record.
/// </summary>
public static class JobWorker
{
    #region Methods
    /// <summary>Serves one request over the raw streams; returns the process exit code.</summary>
    public static int Run(string? protocol, Stream stdin, Stream stdout, JobScan scan) =>
        Run(protocol, stdin, stdout, scan, () => Environment.Exit(JobProtocol.ExitParentGone));

    /// <summary>One <c>fatal</c> record for a command line that never reached <see cref="Run(string?, Stream, Stream, JobScan)"/>; returns its exit code.</summary>
    public static int Refuse(Stream stdout, string reason) => new Writer(stdout).Fatal(reason);

    /// <summary><see cref="Run(string?, Stream, Stream, JobScan)"/> with the parent-gone action as a test seam.</summary>
    public static int Run(string? protocol, Stream stdin, Stream stdout, JobScan scan, Action parentGone)
    {
        var writer = new Writer(stdout);
        if (protocol != JobProtocol.Version.ToString())
            return writer.Fatal($"unsupported protocol; expected __worker job --protocol {JobProtocol.Version}");

        var reader = new WorkerLineReader(stdin, JobProtocol.MaxRequestLineBytes);
        var (status, line) = reader.ReadLine();
        if (status != WorkerLineStatus.Line)
            return writer.Fatal("no request line was read");
        if (RequestProblem(line, out var request) is { } problem)
            return writer.Fatal(problem);

        // Anything after the request, or its end, means the server has gone or given up.
        new Thread(() => { try { reader.ReadLine(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { } parentGone(); })
            { IsBackground = true, Name = "job-worker-stdin-watch" }.Start();

        var clock = new StageClock(writer);
        try
        {
            writer.Write(new JobReady(JobProtocol.Version));
            var nupkg = Path.Combine(request!.JobDir, JobProtocol.PackageFile);
            var files = Path.Combine(request.JobDir, JobProtocol.FilesDir);
            var result = scan(nupkg, files, request.Depth, request.Network, clock);
            if (!result.IsSuccess)
                return writer.Fatal(result.Message ?? "the scan failed");

            clock.Enter("write");
            var output = result.Value;
            // What agents read never names a host directory (D6.5): the job's own, then the machine's.
            var hostPaths = HostPaths.ForJob(request.JobDir, files, Directory.Exists(files) ? NuGetPackage.ContentRootOf(files, nupkg) : null);
            JobArtifacts.WriteAtomic(request.JobDir, JobProtocol.ReportFile, Encoding.UTF8.GetBytes(output.ReportJson));
            JobArtifacts.WriteAtomic(request.JobDir, JobProtocol.GateFile, JsonSerializer.SerializeToUtf8Bytes(output.Gate, JobProtocol.JsonOptions));
            JobArtifacts.WriteAtomic(request.JobDir, JobProtocol.SummaryFile,
                Encoding.UTF8.GetBytes(PackageSummary.Build(output.Report, output.Gate, request.Depth, output.GatingIndicators, hostPaths).ToJsonString(JobProtocol.JsonOptions)));
            WriteDrillDown(request.JobDir, output, files, nupkg, hostPaths);
            var (elapsed, stages) = clock.Finish();
            writer.Write(new JobDone(elapsed, stages));
            return JobProtocol.ExitDone;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return writer.Fatal($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    // The drill-down row files (tasks S2, S3), then their index, last: the inventory first, so the other lists name files as it
    // does; the members before the findings, which carry the caller tokens the members walk found.
    private static void WriteDrillDown(string jobDir, JobScanOutput output, string files, string nupkg, IReadOnlyList<(string Path, string Label)> hostPaths)
    {
        PackagePaths paths;
        JsonObject inventory;
        using (var rows = new RowWriter(jobDir, JobProtocol.InventoryFile, PackageInventory.MaxRows, PackageInventory.MaxChars))
        {
            paths = PackageInventory.Write(output.Report, files, nupkg, hostPaths, rows);
            rows.Commit();
            inventory = rows.Index();
        }
        var members = MemberRows.Write(jobDir, output.Report, paths);
        var index = new JsonObject
        {
            ["files"] = inventory,
            ["findings"] = PackageFindings.Write(jobDir, output.Report, output.GatingIndicators, paths, hostPaths, members),
            ["reachability"] = ReachabilityRows.Write(jobDir, output.Report, hostPaths),
            ["members"] = members.Members,
            ["strings"] = members.Strings,
        };
        JobArtifacts.WriteAtomic(jobDir, JobProtocol.IndexFile, Encoding.UTF8.GetBytes(index.ToJsonString(JobProtocol.JsonOptions)));
    }

    // Why `line` is not a usable request, or null with `request` set.
    private static string? RequestProblem(byte[] line, out JobRequest? request)
    {
        request = null;
        try
        {
            request = JsonSerializer.Deserialize<JobRequest>(line, JobProtocol.JsonOptions);
        }
        catch (JsonException)
        {
            return "the request is not valid JSON for the protocol";
        }
        return request is null ? "the request is null"
            : request.Protocol != JobProtocol.Version ? $"the request is for protocol {request.Protocol}"
            : request.JobDir is null || !Path.IsPathFullyQualified(request.JobDir) || !Directory.Exists(request.JobDir) ? "the job directory is not an existing absolute path"
            : !File.Exists(Path.Combine(request.JobDir, JobProtocol.PackageFile)) ? "the job directory holds no package"
            : Path.Exists(Path.Combine(request.JobDir, JobProtocol.FilesDir)) ? "the job directory already has extracted files"
            : !Enum.IsDefined(request.Depth) ? "the depth is not known"
            : null;
    }
    #endregion

    #region Types
    // The stdout writer: one compact JSON record per line, never longer than the protocol allows. Thread-safe. Shared with
    // the inspect worker, which speaks the same records.
    internal sealed class Writer(Stream stdout)
    {
        public void Write(JobMessage message)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(message, JobProtocol.JsonOptions);
            lock (sync)
            {
                stdout.Write(bytes);
                stdout.WriteByte((byte)'\n');
                stdout.Flush();
            }
        }

        public int Fatal(string reason)
        {
            Runtime.Error("job worker: fatal: {0}", WorkerProtocol.Safe(reason, JobProtocol.MaxReasonChars));
            try
            {
                Write(new JobFatal(WorkerProtocol.Safe(reason, JobProtocol.MaxReasonChars)));
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or NotSupportedException)
            {
                Runtime.Error("job worker: cannot write to stdout ({0}).", ex.GetType().Name);
            }
            return JobProtocol.ExitFatal;
        }

        private readonly object sync = new();
    }

    // Receives the scan's progress synchronously, times each stage, and writes a progress record when a stage starts or,
    // within one, at most every ProgressInterval.
    private sealed class StageClock(Writer writer) : IProgress<PackageScanProgress>
    {
        public void Report(PackageScanProgress value)
        {
            var name = value.Stage.ToString().ToLowerInvariant();
            var changed = Enter(name);
            if (changed || Stopwatch.GetElapsedTime(lastWrite) >= ProgressInterval)
            {
                writer.Write(new JobProgress(name, Math.Max(0, value.Done), Math.Max(0, value.Total)));
                lastWrite = Stopwatch.GetTimestamp();
            }
        }

        // Starts `stage` when it is not the current one; true when it started.
        public bool Enter(string stage)
        {
            if (stage == current)
                return false;
            Close();
            (current, stageStart) = (stage, Stopwatch.GetTimestamp());
            return true;
        }

        public (long ElapsedMs, IReadOnlyList<JobStageTime> Stages) Finish()
        {
            Close();
            current = null;
            return ((long)total.Elapsed.TotalMilliseconds, stages);
        }

        private void Close()
        {
            if (current is not null)
                stages.Add(new(current, (long)Stopwatch.GetElapsedTime(stageStart).TotalMilliseconds));
        }

        private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(250);
        private readonly Stopwatch total = Stopwatch.StartNew();
        private readonly List<JobStageTime> stages = [];
        private string? current;
        private long stageStart;
        private long lastWrite;
    }
    #endregion
}
