namespace Silvergun.MCPServer.Jobs;

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>How to start a job child: the executable (or why there is none) and its arguments.</summary>
public sealed record JobLaunch(string? Executable, string? Problem, IReadOnlyList<string> Arguments)
{
    #region Methods
    /// <summary>The production launch: the Silvergun CLI apphost, resolved exactly as the graph worker's is (never PATH, never <c>dotnet</c>).</summary>
    public static JobLaunch Cli()
    {
        var (path, problem) = GraphWorkerLaunch.Resolve(Environment.ProcessPath, AppContext.BaseDirectory);
        return new(path, problem is null ? null : "there is no Silvergun CLI executable to run the job in", JobProtocol.Arguments);
    }
    #endregion
}

/// <summary>How a job run ended.</summary>
public enum JobRunStatus { Completed, Failed, TimedOut, Cancelled }

/// <summary>A job run's end: its status, why it is not <see cref="JobRunStatus.Completed"/> (escaped, bounded), and the child's <c>done</c>.</summary>
public sealed record JobRunResult(JobRunStatus Status, string? Reason, JobDone? Done);

/// <summary>
/// Runs one job child over one request (task S1, D2). The child is contained before it is sent anything: a kill-on-close
/// Job Object with a per-process and a whole-tree memory limit on Windows; a GC heap hard limit everywhere; and on Linux
/// its own parent watch. Every wait is bounded by the job's budget or <paramref name="ct"/>, and the child's whole tree is
/// killed when <see cref="Run"/> returns, whatever happened. Never throws for anything the child does.
/// </summary>
public static class JobProcess
{
    #region Methods
    /// <summary>
    /// Runs one child. <paramref name="memoryLimitBytes"/> caps the whole tree (Windows; 0 for none);
    /// <paramref name="heapLimitBytes"/> is the child's own GC heap hard limit (0 for none), kept below the tree's so its
    /// own workers (YARA-X, graph) have room under the same Job Object.
    /// </summary>
    public static JobRunResult Run(JobLaunch launch, JobRequest request, TimeSpan budget, long memoryLimitBytes, long heapLimitBytes,
        Action<JobProgress> onProgress, CancellationToken ct)
    {
        if (launch.Executable is null || !Path.IsPathFullyQualified(launch.Executable))
            return Failed(launch.Problem ?? "the job executable's path is unknown or not absolute");

        using var process = new Process { StartInfo = StartInfo(launch, heapLimitBytes) };
        try
        {
            if (!process.Start())
                return Failed("the job process did not start");
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or PlatformNotSupportedException)
        {
            return Failed($"the job process could not be started ({ex.GetType().Name})");
        }

        var job = Contain(process, memoryLimitBytes, out var uncontained);
        using var stop = new CancellationTokenSource();
        using var lines = new BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)>(boundedCapacity: 4);
        Task[] background = [];
        try
        {
            if (uncontained is not null)
                return Failed(uncontained);

            var deadline = Stopwatch.GetTimestamp() + (long)(budget.TotalSeconds * Stopwatch.Frequency);
            background =
            [
                Background(() => Send(process, request)),
                Background(() => RelayStderr(process.StandardError.BaseStream)),
                Background(() => Pump(new WorkerLineReader(process.StandardOutput.BaseStream, JobProtocol.MaxRecordLineBytes), lines, stop.Token)),
            ];
            return Read(process, lines, deadline, onProgress, ct);
        }
        finally
        {
            Kill(process);
            stop.Cancel();
            CloseInput(process);
            WaitQuietly(background, DrainTimeout);
            job?.Dispose();
        }
    }

    // ready, then progress records, then done (and a clean exit) or fatal. Every wait is bounded.
    private static JobRunResult Read(Process process, BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)> lines, long deadline, Action<JobProgress> onProgress, CancellationToken ct)
    {
        var ready = false;
        var started = Stopwatch.GetTimestamp();
        while (true)
        {
            var bound = ready ? Remaining(deadline) : Min(ReadyTimeout - Stopwatch.GetElapsedTime(started), Remaining(deadline));
            (WorkerLineStatus Status, byte[] Bytes) line;
            try
            {
                // A take can wake a little before the Stopwatch deadline: only a spent budget, or (before ready) a spent ready
                // clock, ends the run; otherwise wait again (S1 test finding).
                if (!lines.TryTake(out line, (int)Math.Max(0, Math.Ceiling(Min(bound, MaxWait).TotalMilliseconds)), ct))
                {
                    if (lines.IsCompleted)
                        return Failed($"the job worker's output ended{ExitNote(process)}");
                    if (Remaining(deadline) <= TimeSpan.Zero)
                        return new(JobRunStatus.TimedOut, "the job ran past its time budget, so it was killed", null);
                    if (!ready && Stopwatch.GetElapsedTime(started) >= ReadyTimeout)
                        return Failed($"the job worker sent no 'ready' within {ReadyTimeout.TotalSeconds:0} s");
                    continue;
                }
            }
            catch (OperationCanceledException)
            {
                return new(JobRunStatus.Cancelled, "the job was cancelled", null);
            }
            catch (InvalidOperationException)
            {
                return Failed($"the job worker's output ended{ExitNote(process)}");
            }

            if (line.Status != WorkerLineStatus.Line)
                return Failed($"the job worker stopped: {Ending(line.Status)}{ExitNote(process)}");
            var (message, problem) = Parse(line.Bytes);
            switch (message)
            {
                case null:
                    return Failed($"the job worker broke protocol v{JobProtocol.Version}: {problem}");
                case JobFatal fatal:
                    return Failed($"the job failed: {WorkerProtocol.Safe(fatal.Reason, JobProtocol.MaxReasonChars)}");
                case JobReady { Protocol: JobProtocol.Version } when !ready:
                    ready = true;
                    break;
                case JobProgress progress when ready && stageName.IsMatch(progress.Stage ?? "") && progress.Done >= 0 && progress.Total >= 0:
                    onProgress(progress);
                    break;
                case JobDone done when ready && DoneProblem(done) is null:
                    return !process.WaitForExit(ExitTimeout) ? Failed($"the job worker did not exit within {ExitTimeout.TotalSeconds:0} s of 'done'")
                        : process.ExitCode != JobProtocol.ExitDone ? Failed($"the job worker exited with {GraphWorkerProcess.DescribeExit(process.ExitCode)} after 'done'")
                        : new(JobRunStatus.Completed, null, done);
                default:
                    return Failed($"the job worker broke protocol v{JobProtocol.Version}: an unexpected or malformed '{message.GetType().Name}' record");
            }
        }
    }

    private static string? DoneProblem(JobDone done) =>
        done.ElapsedMs < 0 || done.Stages is null || done.Stages.Count > MaxStages
            || done.Stages.Any(s => s is null || !stageName.IsMatch(s.Stage ?? "") || s.ElapsedMs < 0)
            ? "malformed 'done'" : null;

    private static (JobMessage? Message, string? Problem) Parse(byte[] bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<JobMessage>(bytes, JobProtocol.JsonOptions) is { } message ? (message, null) : (null, "a null record");
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return (null, $"a record that is not valid JSON for the protocol: '{WorkerLineReader.Excerpt(bytes)}'");
        }
    }

    private static ProcessStartInfo StartInfo(JobLaunch launch, long heapLimitBytes)
    {
        var info = new ProcessStartInfo(launch.Executable!)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        };
        foreach (var argument in launch.Arguments)
            info.ArgumentList.Add(argument);
        // A managed allocation past the heap limit fails in the child as an OutOfMemoryException, which is a fatal record.
        if (heapLimitBytes > 0)
            info.Environment["DOTNET_GCHeapHardLimit"] = "0x" + heapLimitBytes.ToString("x", CultureInfo.InvariantCulture);
        return info;
    }

    private static IDisposable? Contain(Process process, long memoryLimitBytes, out string? uncontained)
    {
        uncontained = null;
#if WINDOWS
        WorkerJobObject? job = null;
        try
        {
            var limit = memoryLimitBytes > 0 ? (ulong)memoryLimitBytes : 0;
            job = WorkerJobObject.Create(processMemoryLimit: limit, jobMemoryLimit: limit);
            job.Assign(process);
            return job;
        }
        catch (Exception ex) when (ex is Win32Exception or ObjectDisposedException or InvalidOperationException)
        {
            job?.Dispose();
            uncontained = $"the job process could not be placed in a kill-on-close Job Object ({ex.GetType().Name}), so it was killed";
            return null;
        }
#else
        return null;
#endif
    }

    private static void Send(Process process, JobRequest request)
    {
        try
        {
            var stdin = process.StandardInput.BaseStream;
            stdin.Write(JsonSerializer.SerializeToUtf8Bytes(request, JobProtocol.JsonOptions));
            stdin.WriteByte((byte)'\n');
            stdin.Flush();
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            /* the child is gone: the reader sees its output end */
        }
    }

    private static void Pump(WorkerLineReader reader, BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)> lines, CancellationToken stop)
    {
        try
        {
            while (true)
            {
                var line = reader.ReadLine();
                lines.Add(line, stop);
                if (line.Status != WorkerLineStatus.Line)
                    return;
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException or OperationCanceledException)
        {
            /* the pipe broke, or the run is over */
        }
        finally
        {
            try { lines.CompleteAdding(); }
            catch (ObjectDisposedException) { /* the run is over */ }
        }
    }

    // The child's stderr: diagnostics only, relayed at Debug, escaped and bounded per line; past the cap, read and dropped.
    private static void RelayStderr(Stream stderr)
    {
        var kept = new byte[MaxStderrBytes];
        var length = 0;
        try
        {
            var chunk = new byte[4096];
            int read;
            while ((read = stderr.Read(chunk, 0, chunk.Length)) > 0)
            {
                var take = Math.Min(read, kept.Length - length);
                chunk.AsSpan(0, take).CopyTo(kept.AsSpan(length));
                length += take;
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            /* relay what arrived */
        }

        foreach (var line in Encoding.UTF8.GetString(kept, 0, length).Split('\n'))
            if (line.TrimEnd('\r') is { Length: > 0 } text)
                Runtime.Debug("[job-worker] {0}", WorkerProtocol.Safe(text, StderrLineChars));
    }

    private static void Kill(Process process)
    {
        try
        {
            if (process.HasExited)
                return;
            process.Kill(entireProcessTree: true);
            process.WaitForExit(KillWait);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException or AggregateException)
        {
            /* already gone, or the job's close takes it */
        }
    }

    private static void CloseInput(Process process)
    {
        try { process.StandardInput.Close(); }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException) { /* already gone */ }
    }

    private static string ExitNote(Process process)
    {
        try
        {
            return process.WaitForExit(ExitNoteWait) ? $"; it exited with {GraphWorkerProcess.DescribeExit(process.ExitCode)}" : string.Empty;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return string.Empty;
        }
    }

    private static string Ending(WorkerLineStatus status) => status switch
    {
        WorkerLineStatus.Eof => "its output ended",
        WorkerLineStatus.Truncated => "its output ended part-way through a record",
        WorkerLineStatus.TooLong => $"it sent a record over {JobProtocol.MaxRecordLineBytes} bytes",
        WorkerLineStatus.InvalidUtf8 => "it sent a record that is not UTF-8",
        _ => "its output pipe broke",
    };

    private static JobRunResult Failed(string reason) => new(JobRunStatus.Failed, WorkerProtocol.Safe(reason, JobProtocol.MaxReasonChars), null);

    private static TimeSpan Remaining(long deadline) =>
        Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline) is var left && left > TimeSpan.Zero ? left : TimeSpan.Zero;

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private static Task Background(Action action) =>
        Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    private static void WaitQuietly(Task[] tasks, TimeSpan bound)
    {
        try { Task.WaitAll(tasks, bound); }
        catch (AggregateException) { /* each task reports its own failure */ }
    }
    #endregion

    #region Fields
    /// <summary>How long a started child has to read its request and send <c>ready</c>.</summary>
    public static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(60);

    private static readonly TimeSpan ExitTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan KillWait = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ExitNoteWait = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxWait = TimeSpan.FromMilliseconds(int.MaxValue - 1);

    private const int MaxStages = 16;
    private const int MaxStderrBytes = 64 * 1024;
    private const int StderrLineChars = 1024;

    private static readonly Regex stageName = new("^[a-z]{1,16}$", RegexOptions.CultureInvariant);
    #endregion
}
