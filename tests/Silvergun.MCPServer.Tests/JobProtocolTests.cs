namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// The child half of job protocol v1 in-process: <see cref="JobWorker.Run(string?, Stream, Stream, JobScan, Action)"/> with
/// a fake <see cref="JobScan"/>. Every refusal is one <c>fatal</c> record and exit 3; nothing is scanned before the request
/// checks out.
/// </summary>
public sealed class JobWorkerTests
{
    #region Methods
    [Theory]
    [InlineData(null)]
    [InlineData("2")]
    [InlineData("01")]
    public void Run_WithAnUnsupportedProtocol_IsOneFatal(string? protocol)
    {
        using var dirs = new TestDirs();
        var run = Run(protocol, Request(JobDir(dirs)), NeverScan);

        AssertSingleFatal(run, "protocol");
    }

    [Fact]
    public void Run_WithNoRequestLine_IsOneFatal() => AssertSingleFatal(Run("1", "", NeverScan), "request");

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"protocol\":1,\"jobDir\":")]
    [InlineData("null")]
    [InlineData("[1,2,3]")]
    public void Run_WithABadRequestLine_IsOneFatal(string line) => AssertSingleFatal(Run("1", line + "\n", NeverScan), "request");

    [Fact]
    public void Run_WithARequestForAnotherProtocol_IsOneFatal()
    {
        using var dirs = new TestDirs();
        AssertSingleFatal(Run("1", Request(JobDir(dirs), protocol: 2), NeverScan), "protocol");
    }

    [Fact]
    public void Run_WithARelativeOrMissingJobDir_IsOneFatal()
    {
        using var dirs = new TestDirs();
        AssertSingleFatal(Run("1", Request("relative" + Path.DirectorySeparatorChar + "job"), NeverScan), "job directory");
        AssertSingleFatal(Run("1", Request(Path.Combine(dirs.Base, "no-such-job")), NeverScan), "job directory");
    }

    [Fact]
    public void Run_WithNoPackageInTheJobDir_IsOneFatal()
    {
        using var dirs = new TestDirs();
        var dir = dirs.NewDir("job-empty");

        AssertSingleFatal(Run("1", Request(dir), NeverScan), "package");
    }

    [Fact]
    public void Run_WhenFilesAlreadyExist_IsOneFatal()
    {
        using var dirs = new TestDirs();
        var dir = JobDir(dirs);
        Directory.CreateDirectory(Path.Combine(dir, JobProtocol.FilesDir));

        AssertSingleFatal(Run("1", Request(dir), NeverScan), "extracted files");
    }

    [Fact]
    public void Run_WhenTheScanFails_SendsReadyThenAnEscapedFatal_AndPassesTheRequestThrough()
    {
        using var dirs = new TestDirs();
        var dir = JobDir(dirs);
        var rlo = (char)0x202E;
        (string Nupkg, string Files, JobDepth Depth, bool Network)? seen = null;
        JobScan scan = (nupkg, files, depth, network, progress) =>
        {
            seen = (nupkg, files, depth, network);
            progress.Report(new PackageScanProgress(PackageScanStage.Extract, 0, 1));
            progress.Report(new PackageScanProgress(PackageScanStage.Assemblies, 1, 3));
            return Result.Failure<JobScanOutput>("bad" + (char)10 + "[ERR] forged" + rlo + " package");
        };

        var run = Run("1", Request(dir, depth: JobDepth.Deep, network: true), scan);

        Assert.Equal(JobProtocol.ExitFatal, run.Exit);
        Assert.Equal((Path.Combine(dir, JobProtocol.PackageFile), Path.Combine(dir, JobProtocol.FilesDir), JobDepth.Deep, true), seen);
        Assert.Equal("ready", Type(run.Records[0]));
        Assert.Equal(JobProtocol.Version, run.Records[0].GetProperty("protocol").GetInt32());
        Assert.Equal(["extract", "assemblies"], run.Records.Where(r => Type(r) == "progress").Select(r => r.GetProperty("stage").GetString()));
        var fatal = run.Records[^1];
        Assert.Equal("fatal", Type(fatal));
        Assert.Single(run.Records, r => Type(r) == "fatal");
        var reason = fatal.GetProperty("reason").GetString()!;
        Assert.DoesNotContain(rlo, reason);
        Assert.DoesNotContain((char)10, reason);
        Assert.Contains("forged", reason);
        Assert.True(reason.Length <= JobProtocol.MaxReasonChars + 64, $"reason is {reason.Length} chars");
        Assert.True(run.RawStdout.All(b => b < 0x80), "a stdout record is not ASCII");
    }

    [Fact]
    public void Run_WhenTheScanThrows_IsAFatalNamingTheExceptionType()
    {
        using var dirs = new TestDirs();
        JobScan scan = (_, _, _, _, _) => throw new InvalidDataException("corrupt zip");

        var run = Run("1", Request(JobDir(dirs)), scan);

        Assert.Equal(JobProtocol.ExitFatal, run.Exit);
        Assert.Equal("fatal", Type(run.Records[^1]));
        Assert.Contains(nameof(InvalidDataException), run.Records[^1].GetProperty("reason").GetString());
    }

    /// <summary>stdin ending after the request means the server is gone: the parent-gone action runs while the scan is still going.</summary>
    [Fact]
    public void Run_WhenStdinEndsAfterTheRequest_CallsParentGone()
    {
        using var dirs = new TestDirs();
        using var gone = new ManualResetEventSlim();
        var calledDuringScan = false;
        JobScan scan = (_, _, _, _, _) =>
        {
            calledDuringScan = gone.Wait(TimeSpan.FromSeconds(10));
            return Result.Failure<JobScanOutput>("stopped");
        };

        var run = Run("1", Request(JobDir(dirs)), scan, () => gone.Set());

        Assert.True(calledDuringScan, "parent-gone did not run while the scan was in progress");
        Assert.Equal(JobProtocol.ExitFatal, run.Exit);
    }

    [Fact]
    public void Run_WhileStdinStaysOpen_DoesNotCallParentGone()
    {
        using var dirs = new TestDirs();
        var calls = 0;
        using var stdin = new BlockingStdin(Encoding.UTF8.GetBytes(Request(JobDir(dirs))));
        JobScan scan = (_, _, _, _, _) =>
        {
            Thread.Sleep(500);
            return Result.Failure<JobScanOutput>("stopped");
        };

        using var stdout = new MemoryStream();
        var exit = JobWorker.Run("1", stdin, stdout, scan, () => Interlocked.Increment(ref calls));

        Assert.Equal(JobProtocol.ExitFatal, exit);
        Assert.Equal(0, Volatile.Read(ref calls));
    }

    [Fact]
    public void Refuse_IsOneFatalRecord()
    {
        using var stdout = new MemoryStream();

        var exit = JobWorker.Refuse(stdout, "bad arguments");

        Assert.Equal(JobProtocol.ExitFatal, exit);
        var record = Assert.Single(Records(stdout.ToArray()));
        Assert.Equal("fatal", Type(record));
        Assert.Equal("bad arguments", record.GetProperty("reason").GetString());
    }
    #endregion

    #region Methods: helpers
    private static readonly JobScan NeverScan = (_, _, _, _, _) => throw new InvalidOperationException("the scan must not run");

    // A job directory with a package file in it (its content is never read by a fake scan).
    private static string JobDir(TestDirs dirs)
    {
        var dir = dirs.NewDir("job-" + Guid.NewGuid().ToString("N")[..8]);
        File.WriteAllBytes(Path.Combine(dir, JobProtocol.PackageFile), [0x50, 0x4B, 5, 6]);
        return dir;
    }

    private static string Request(string jobDir, int protocol = 1, JobDepth depth = JobDepth.Standard, bool network = false) =>
        JsonSerializer.Serialize(new JobRequest(protocol, jobDir, depth, network), JobProtocol.JsonOptions) + "\n";

    private static WorkerRun Run(string? protocol, string stdinText, JobScan scan, Action? parentGone = null)
    {
        using var stdin = new MemoryStream(Encoding.UTF8.GetBytes(stdinText));
        using var stdout = new MemoryStream();
        var exit = JobWorker.Run(protocol, stdin, stdout, scan, parentGone ?? (() => { }));
        var raw = stdout.ToArray();
        return new WorkerRun(exit, Records(raw), raw);
    }

    private static List<JsonElement> Records(byte[] stdout)
    {
        var text = Encoding.UTF8.GetString(stdout);
        Assert.True(text.Length == 0 || text.EndsWith('\n'), "the last stdout record is not newline-terminated");
        return [.. text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => JsonDocument.Parse(l).RootElement.Clone())];
    }

    private static string Type(JsonElement record) => record.GetProperty("type").GetString()!;

    private static void AssertSingleFatal(WorkerRun run, string reasonMentions)
    {
        Assert.Equal(JobProtocol.ExitFatal, run.Exit);
        var record = Assert.Single(run.Records);
        Assert.Equal("fatal", Type(record));
        Assert.Contains(reasonMentions, record.GetProperty("reason").GetString(), StringComparison.OrdinalIgnoreCase);
    }
    #endregion

    #region Nested types
    private sealed record WorkerRun(int Exit, List<JsonElement> Records, byte[] RawStdout);

    // A stdin that yields its bytes and then blocks (as a pipe the server keeps open does) until disposed.
    private sealed class BlockingStdin(byte[] bytes) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (position < bytes.Length)
            {
                var n = Math.Min(count, bytes.Length - position);
                Array.Copy(bytes, position, buffer, offset, n);
                position += n;
                return n;
            }
            closed.Wait();
            return 0;
        }

        protected override void Dispose(bool disposing)
        {
            closed.Set();
            base.Dispose(disposing);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private readonly ManualResetEventSlim closed = new();
        private int position;
    }
    #endregion
}

/// <summary>The CLI's <c>__worker job</c> command lines that never reach a session: one fatal record on stdout, exit 3.</summary>
public sealed class JobWorkerCliTests
{
    #region Methods
    public static TheoryData<string[]> BadCommandLines() => new()
    {
        { ["__worker", "job", "--bogus"] },
        { ["__worker", "job", "--protocol", "1", "--bogus"] },
        { ["__worker", "job", "--protocol", "2"] },
        { ["__worker", "job"] },
    };

    [Theory]
    [MemberData(nameof(BadCommandLines))]
    public async Task BadCommandLine_IsOneFatalRecord_AndExit3(string[] args)
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(args, dirs.Root);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"{string.Join(' ', args)}: did not exit\n{exit.Stderr}");
        Assert.True(exit.ExitCode == JobProtocol.ExitFatal, $"{string.Join(' ', args)}: exit {exit.ExitCode}\n{exit.Stderr}");
        Assert.Equal(0, child.TrailingBytes);
        var line = Assert.Single(child.Lines);
        using var doc = JsonDocument.Parse(line);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("reason").GetString()));
    }
    #endregion
}

/// <summary>
/// The parent half of job protocol v1: <see cref="JobProcess.Run"/> against fake children (a PowerShell script on Windows,
/// <c>/bin/sh</c> elsewhere) that keep or break the protocol. Each fake writes its pid first, so the test can check the
/// child is gone when <c>Run</c> returns, whatever happened.
/// </summary>
public sealed class JobProcessTests
{
    #region Methods
    [Fact]
    public void Run_AValidSession_Completes_AndRelaysProgress()
    {
        using var dirs = new TestDirs();
        var progress = new List<JobProgress>();

        var (result, pid) = RunFake(dirs, [Ready, """{"type":"progress","stage":"extract","done":0,"total":1}""", ValidDone], exitCode: 0, sleep: false,
            onProgress: progress.Add);

        Assert.True(result.Status == JobRunStatus.Completed, $"{result.Status}: {result.Reason}");
        Assert.Equal(5, result.Done!.ElapsedMs);
        Assert.Equal("extract", Assert.Single(result.Done.Stages).Stage);
        Assert.Equal("extract", Assert.Single(progress).Stage);
        AssertGone(pid);
    }

    [Fact]
    public void Run_ACleanDoneButANonZeroExit_Fails()
    {
        using var dirs = new TestDirs();

        var (result, pid) = RunFake(dirs, [Ready, ValidDone], exitCode: 5, sleep: false);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("exited", result.Reason);
        AssertGone(pid);
    }

    public static TheoryData<string, string[], string> ProtocolViolations() => new()
    {
        { "garbage", ["this is not json at all"], "broke protocol" },
        { "two readys", [Ready, Ready], "broke protocol" },
        { "done before ready", [ValidDone], "broke protocol" },
        { "progress before ready", ["""{"type":"progress","stage":"extract","done":0,"total":1}"""], "broke protocol" },
        { "a ready for another protocol", ["""{"type":"ready","protocol":2}"""], "broke protocol" },
        { "an unknown record type", [Ready, """{"type":"surprise"}"""], "broke protocol" },
        { "a bad stage name", [Ready, """{"type":"progress","stage":"EXTRACT now","done":0,"total":1}"""], "broke protocol" },
        { "a negative count", [Ready, """{"type":"progress","stage":"extract","done":-1,"total":1}"""], "broke protocol" },
        { "a malformed done", [Ready, """{"type":"done","elapsedMs":-5,"stages":[]}"""], "broke protocol" },
    };

    [Theory]
    [MemberData(nameof(ProtocolViolations))]
    public void Run_AProtocolViolation_Fails_AndKillsTheChild(string what, string[] lines, string reason)
    {
        using var dirs = new TestDirs();

        var (result, pid) = RunFake(dirs, lines, exitCode: 0, sleep: true);

        Assert.True(result.Status == JobRunStatus.Failed, $"{what}: {result.Status} {result.Reason}");
        Assert.Contains(reason, result.Reason);
        AssertGone(pid);
    }

    [Fact]
    public void Run_ARecordOverTheLineLimit_Fails()
    {
        using var dirs = new TestDirs();
        var huge = "{\"type\":\"fatal\",\"reason\":\"" + new string('x', JobProtocol.MaxRecordLineBytes + 10) + "\"}";

        var (result, pid) = RunFake(dirs, [Ready, huge], exitCode: 0, sleep: true);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains(JobProtocol.MaxRecordLineBytes.ToString(), result.Reason);
        AssertGone(pid);
    }

    [Fact]
    public void Run_AFatal_FailsWithItsReasonEscaped()
    {
        using var dirs = new TestDirs();
        var rlo = (char)0x202E;
        // The JSON escape for U+202E, built so no such escape appears in this source.
        var fatal = "{\"type\":\"fatal\",\"reason\":\"zip" + Backslash + "u202e" + " broke\"}";

        var (result, pid) = RunFake(dirs, [Ready, fatal], exitCode: 3, sleep: false);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("zip", result.Reason);
        Assert.DoesNotContain(rlo, result.Reason!);
        AssertGone(pid);
    }

    [Fact]
    public void Run_OutputEndingWithoutDone_Fails()
    {
        using var dirs = new TestDirs();

        var (result, pid) = RunFake(dirs, [Ready], exitCode: 0, sleep: false);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        AssertGone(pid);
    }

    /// <summary>
    /// The budget's clock starts when <see cref="JobProcess.Run"/> starts the child, so it also covers the fake's own start-up.
    /// Under full-suite load a PowerShell fake once took over 3 s to write its pid file, and a 3 s budget killed it first. The
    /// budget is 15 s, far above any start-up seen; the run must end by the budget (no sooner) and promptly after it.
    /// </summary>
    [Fact]
    public void Run_AChildSilentPastTheBudget_TimesOut_AndIsKilled()
    {
        using var dirs = new TestDirs();
        var budget = TimeSpan.FromSeconds(15);
        var clock = Stopwatch.StartNew();

        var (result, pid) = RunFake(dirs, [Ready], exitCode: 0, sleep: true, budget: budget);

        Assert.True(result.Status == JobRunStatus.TimedOut, $"{result.Status}: {result.Reason}");
        Assert.True(clock.Elapsed >= budget, $"timed out after {clock.Elapsed}, inside its {budget} budget");
        Assert.True(clock.Elapsed < budget + TimeSpan.FromSeconds(27), $"took {clock.Elapsed}");
        AssertGone(pid);
    }

    [Fact]
    public void Run_Cancelled_IsCancelled_AndTheChildIsKilled()
    {
        using var dirs = new TestDirs();
        using var cts = new CancellationTokenSource();
        var started = new ManualResetEventSlim();

        var (result, pid) = RunFake(dirs, [Ready, """{"type":"progress","stage":"extract","done":0,"total":1}"""], exitCode: 0, sleep: true,
            onProgress: _ => { started.Set(); cts.CancelAfter(TimeSpan.FromMilliseconds(300)); }, ct: cts.Token);

        Assert.True(started.IsSet, "the fake never reported progress");
        Assert.True(result.Status == JobRunStatus.Cancelled, $"{result.Status}: {result.Reason}");
        AssertGone(pid);
    }

    [Fact]
    public void Run_WithARelativeExecutable_FailsWithoutStarting()
    {
        var result = JobProcess.Run(new JobLaunch("Silvergun.CLI", null, JobProtocol.Arguments), new JobRequest(1, Path.GetTempPath(), JobDepth.Standard, false),
            TimeSpan.FromSeconds(5), 0, 0, _ => { }, CancellationToken.None);

        Assert.Equal(JobRunStatus.Failed, result.Status);
    }

    [Fact]
    public void Run_WithNoExecutable_FailsWithTheLaunchProblem()
    {
        var result = JobProcess.Run(new JobLaunch(null, "there is no CLI here", JobProtocol.Arguments), new JobRequest(1, Path.GetTempPath(), JobDepth.Standard, false),
            TimeSpan.FromSeconds(5), 0, 0, _ => { }, CancellationToken.None);

        Assert.Equal(JobRunStatus.Failed, result.Status);
        Assert.Contains("there is no CLI here", result.Reason);
    }
    #endregion

    #region Methods: helpers
    // Writes a fake child that records its pid, prints `lines` one per line, optionally sleeps for 60 s, and exits with
    // `exitCode`; runs it through JobProcess.Run. Returns the result and the fake's pid.
    private static (JobRunResult Result, int Pid) RunFake(TestDirs dirs, string[] lines, int exitCode, bool sleep, Action<JobProgress>? onProgress = null,
        TimeSpan? budget = null, CancellationToken ct = default)
    {
        var pidFile = Path.Combine(dirs.Base, "fake.pid");
        JobLaunch launch;
        if (OperatingSystem.IsWindows())
        {
            var script = new StringBuilder();
            script.Append("Set-Content -LiteralPath '").Append(pidFile).Append("' -Value $PID").Append((char)10);
            foreach (var line in lines)
                script.Append("[Console]::Out.Write('").Append(line.Replace("'", "''")).Append("' + [char]10); [Console]::Out.Flush()").Append((char)10);
            if (sleep)
                script.Append("Start-Sleep -Seconds 60").Append((char)10);
            script.Append("exit ").Append(exitCode).Append((char)10);
            var path = Path.Combine(dirs.Base, "fake.ps1");
            File.WriteAllText(path, script.ToString(), new UTF8Encoding(false));
            launch = new JobLaunch(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), null,
                ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]);
        }
        else
        {
            var script = new StringBuilder("echo $$ > '").Append(pidFile).Append('\'').Append((char)10);
            foreach (var line in lines)
                script.Append("printf '%s\\n' '").Append(line.Replace("'", "'\\''")).Append('\'').Append((char)10);
            if (sleep)
                script.Append("sleep 60").Append((char)10);
            script.Append("exit ").Append(exitCode).Append((char)10);
            var path = Path.Combine(dirs.Base, "fake.sh");
            File.WriteAllText(path, script.ToString(), new UTF8Encoding(false));
            launch = new JobLaunch("/bin/sh", null, [path]);
        }

        var result = JobProcess.Run(launch, new JobRequest(JobProtocol.Version, dirs.Base, JobDepth.Standard, false), budget ?? TimeSpan.FromSeconds(60), 0, 0,
            onProgress ?? (_ => { }), ct);
        Assert.True(File.Exists(pidFile), $"the fake never started ({result.Status}: {result.Reason})");
        return (result, int.Parse(File.ReadAllText(pidFile).Trim()));
    }

    private static void AssertGone(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            Assert.True(p.WaitForExit(5_000), $"the fake child {pid} is still running after Run returned");
        }
        catch (ArgumentException)
        {
            /* gone */
        }
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";
    private const string Ready = """{"type":"ready","protocol":1}""";
    private const string ValidDone = """{"type":"done","elapsedMs":5,"stages":[{"stage":"extract","elapsedMs":5}]}""";
    #endregion
}
