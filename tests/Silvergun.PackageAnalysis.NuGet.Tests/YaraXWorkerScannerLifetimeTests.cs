#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;
using Silvergun.Tests.Shared;

using Xunit;

using static FakeWorkerScript;

/// <summary>
/// <see cref="YaraXWorkerScanner"/>'s lifetime and configuration (ADR 0033; <c>docs/agent/tasks/yarax-worker.md</c> T4 and
/// the FR round): <see cref="YaraXWorkerScanner.Available"/> is probed once and cached, and false after
/// <see cref="YaraXWorkerScanner.Dispose"/>, after which every scan fails closed; the kill-on-close Job Object kills a
/// worker mid-scan on Dispose, and a Dispose racing the first use never leaks a job and never reads as available
/// without one; which executable is the worker (amendment (o)); and the one timeout range, [2, 3600] s, that the
/// configured <see cref="YaraOptions.Timeout"/> is clamped into (W-D, (k), (i)).
/// </summary>
public sealed class YaraXWorkerScannerLifetimeTests
{
    #region Methods: Available
    [Fact]
    public void Available_IsProbedOnce_AndCached()
    {
        using var script = new FakeWorkerScript("cached").GenuineThroughout();
        using var scanner = script.Scanner();

        Assert.True(scanner.Available);
        Assert.True(scanner.Available);
        Assert.True(scanner.Available);

        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    // A failed probe is cached too (amendment (r): a WPF follow-up may retry; the CLI must not re-probe per package).
    [Fact]
    public void Available_WhenTheProbeFails_IsCachedAsFalse()
    {
        using var script = new FakeWorkerScript("cached-false").Otherwise("out " + Fatal("no engine"), "exit 3");
        using var scanner = script.Scanner();

        Assert.False(scanner.Available);
        Assert.False(scanner.Available);

        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    [Fact]
    public void AfterDispose_AvailableIsFalse_AndEveryScanFailsClosed()
    {
        using var script = new FakeWorkerScript("disposed").GenuineThroughout();
        using var tree = new ScanTree("disposed");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner();
        Assert.True(scanner.Available);

        scanner.Dispose();
        scanner.Dispose();   // idempotent

        Assert.False(scanner.Available);
        Assert.Contains("has been disposed", Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root)).Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(file)).Message, StringComparison.Ordinal);
        Assert.Single(script.Pids);   // no worker started after Dispose
        script.AssertNoOrphans();
    }

    // Disposed before its first use: never probed, never a worker, never available.
    [Fact]
    public void DisposedBeforeFirstUse_NeverStartsAWorker()
    {
        using var script = new FakeWorkerScript("disposed-early").GenuineThroughout();
        var scanner = script.Scanner();

        scanner.Dispose();

        Assert.False(scanner.Available);
        Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(@"C:\x\a.bin"));
        Assert.Empty(script.Pids);
        Assert.Null(ScannerInternals.FieldOrNull(scanner, "job"));
    }

    // The constructor seam requires an absolute worker path: a relative or missing one is never resolved through PATH or
    // the working directory; every run fails closed.
    [Theory]
    [InlineData(null)]
    [InlineData("Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe.exe")]
    [InlineData(@".\Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe.exe")]
    public void AWorkerPathThatIsNotAbsolute_IsNeverRun(string? workerPath)
    {
        using var warnings = new WarningCapture();
        using var scanner = new YaraXWorkerScanner(workerPath, ["--fake-worker", "unused"], 30, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

        Assert.False(scanner.Available);
        Assert.Contains(warnings.Warnings, w => w.Contains("the worker executable's path is unknown or not absolute", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: the Job Object
    // Dispose closes the kill-on-close job: a worker hung mid-scan (with a 60 s backstop, far beyond this test) is killed
    // at once, the scan ends incomplete well before its own clock, and nothing is left running.
    [Fact]
    public void Dispose_MidScan_KillsTheWorker_AndTheScanEndsIncomplete()
    {
        using var script = new FakeWorkerScript("dispose-mid").GenuineProbe().Otherwise("out " + Ready(), "answer 1", "hang");
        using var tree = new ScanTree("dispose-mid");
        tree.Write("a.bin");
        tree.Write("b.bin");
        var scanner = script.Scanner(engineTimeoutSeconds: 60);
        Assert.True(scanner.Available);

        var clock = Stopwatch.StartNew();
        var scan = Task.Factory.StartNew(() => scanner.ScanDirectory(tree.Root), TaskCreationOptions.LongRunning);
        SpinWait.SpinUntil(() => script.Pids.Length == 2 && script.SentPaths.Length >= 1, TimeSpan.FromSeconds(30));   // it read (and answered) one
        Assert.Equal(2, script.Pids.Length);
        var worker = script.Pids[1];
        Thread.Sleep(300);
        Assert.True(WorkerProcesses.IsAlive(worker, WorkerProcesses.FakeWorkerName), "the worker was not running when Dispose was called");

        scanner.Dispose();

        Assert.True(Task.WaitAny([scan], TimeSpan.FromSeconds(20)) == 0, "the scan did not end after Dispose: the worker was not killed");
        clock.Stop();
        var ex = Assert.IsType<YaraScanIncompleteException>(scan.Exception?.InnerException);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"the scan took {clock.Elapsed}");
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // Dispose and the first use (the probe, which creates the job) race at a spread of offsets. Whatever the
    // interleaving: a job, if one was made, is closed; a scanner that never got a job was never available; nothing runs.
    [Fact]
    public void Dispose_RacingFirstUse_NeverLeaksAJob_AndFailsClosed()
    {
        using var script = new FakeWorkerScript("race").GenuineThroughout();
        var outcomes = new List<string>();
        for (var i = 0; i < 12; i++)
        {
            var scanner = script.Scanner();
            using var go = new Barrier(2);
            var first = Task.Factory.StartNew(() => { go.SignalAndWait(); return scanner.Available; }, TaskCreationOptions.LongRunning);
            var delay = i * 25;
            var dispose = Task.Factory.StartNew(() => { go.SignalAndWait(); Thread.Sleep(delay); scanner.Dispose(); }, TaskCreationOptions.LongRunning);
            Assert.True(Task.WaitAll([first, dispose], TimeSpan.FromSeconds(30)), $"iteration {i} did not finish");

            var job = ScannerInternals.FieldOrNull(scanner, "job");
            var available = first.Result;
            outcomes.Add($"{delay} ms: available={available}, job={(job is null ? "none" : "made")}");
            Assert.False(scanner.Available);
            if (job is null)
                Assert.False(available, $"iteration {i}: available without a Job Object");
            else
                Assert.True(ScannerInternals.Field<SafeHandle>(job, "handle").IsClosed, $"iteration {i}: the job outlived Dispose");
            Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(@"C:\x\a.bin"));
        }

        script.AssertNoOrphans();
        Assert.Contains(outcomes, o => o.Contains("job=made", StringComparison.Ordinal));   // the race was really run both ways
    }
    #endregion

    #region Methods: which executable is the worker (amendment (o))
    [Theory]
    [InlineData(@"C:\Program Files\Silvergun\Silvergun.CLI.exe")]
    [InlineData(@"C:\tools\SILVERGUN.cli.EXE")]
    public void Resolve_Step1_IsTheProcessItself_WhenItIsTheCliApphost_ByFileName(string processPath)
    {
        var (path, problem) = YaraXWorkerScanner.ResolveWorkerExecutable(processPath, @"C:\nowhere-in-particular");

        Assert.Equal(processPath, path);
        Assert.Null(problem);
    }

    [Theory]
    [InlineData("Silvergun.CLI.exe")]
    [InlineData("Silvergun.CLI")]
    public void Resolve_Step2_IsTheApphostInTheApplicationDirectory_ByAbsolutePath(string onDisk)
    {
        using var dir = new YaraXTempDir("resolve");
        File.WriteAllBytes(dir.Combine(onDisk + (onDisk.EndsWith(".exe", StringComparison.Ordinal) ? "" : ".EXE")), []);

        var (path, problem) = YaraXWorkerScanner.ResolveWorkerExecutable(@"C:\Program Files\dotnet\testhost.exe", dir.Root);

        Assert.Equal(Path.Combine(dir.Root, "Silvergun.CLI.exe"), path, ignoreCase: true);
        Assert.True(Path.IsPathFullyQualified(path!));
        Assert.Null(problem);
    }

    // (process path, application directory, what the application directory holds). None of these has a worker: no PATH
    // lookup, no `dotnet <dll>`, no relative path, no directory that merely has the apphost's name.
    public static TheoryData<string?, string, string> NoWorker() => new()
    {
        { @"C:\Program Files\dotnet\testhost.exe", "absolute", "nothing" },
        { @"C:\Program Files\dotnet\dotnet.exe", "absolute", "Silvergun.CLI.dll" },
        { @"C:\Program Files\dotnet\dotnet.exe", "absolute", "a directory named Silvergun.CLI.exe" },
        { "Silvergun.CLI.exe", "absolute", "nothing" },
        { @"bin\Silvergun.CLI.exe", "absolute", "nothing" },
        { null, "absolute", "nothing" },
        { @"C:\Program Files\dotnet\testhost.exe", "relative", "Silvergun.CLI.exe" },
        { @"C:\Program Files\dotnet\testhost.exe", "null", "nothing" },
        { @"C:\apps\Silvergun.CLI.exe.bak", "absolute", "nothing" },
        { @"C:\apps\NotSilvergun.CLI.exe", "absolute", "nothing" },
    };

    [Theory]
    [MemberData(nameof(NoWorker))]
    public void Resolve_Step3_IsNoWorker_WithAReason(string? processPath, string baseKind, string holds)
    {
        using var dir = new YaraXTempDir("resolve-none");
        switch (holds)
        {
            case "Silvergun.CLI.dll": File.WriteAllBytes(dir.Combine("Silvergun.CLI.dll"), []); break;
            case "a directory named Silvergun.CLI.exe": Directory.CreateDirectory(dir.Combine("Silvergun.CLI.exe")); break;
            case "Silvergun.CLI.exe": File.WriteAllBytes(dir.Combine("Silvergun.CLI.exe"), []); break;
        }
        var baseDirectory = baseKind switch
        {
            "absolute" => dir.Root,
            "relative" => Path.GetRelativePath(Environment.CurrentDirectory, dir.Root) is var r && !Path.IsPathFullyQualified(r) ? r : "relative-dir",
            _ => null,
        };

        var (path, problem) = YaraXWorkerScanner.ResolveWorkerExecutable(processPath, baseDirectory);

        Assert.Null(path);
        Assert.StartsWith("there is no worker executable", problem, StringComparison.Ordinal);
        Assert.Contains("Silvergun.CLI.exe", problem, StringComparison.Ordinal);
    }

    // The reason quotes the process's file name and the application directory: both escaped and bounded.
    [Fact]
    public void Resolve_TheReasonEscapesWhatItQuotes()
    {
        var hostile = @"C:\x\evil" + "\n[WRN] forged" + (char)0x202E + new string('x', 300) + ".exe";

        var (_, problem) = YaraXWorkerScanner.ResolveWorkerExecutable(hostile, @"C:\base" + "\r\n" + new string('y', 400));

        Assert.NotNull(problem);
        Assert.DoesNotContain('\n', problem);
        Assert.DoesNotContain('\r', problem);
        Assert.DoesNotContain((char)0x202E, problem);
        Assert.Contains("evil\\n[WRN] forged\\u202e", problem, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('x', 100), problem, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('y', 250), problem, StringComparison.Ordinal);
    }

    // Under `dotnet test` this process is testhost.exe, and this test project carries the net10.0-windows CLI apphost (its
    // ProjectReference, for the real-engine verb tests), so the PRODUCTION constructor resolves the worker by step 2: the
    // apphost beside it, by absolute path. Only the resolution is read here; the worker is not run (that is the
    // probe-host test, which can give it a private rules cache).
    [Fact]
    public void ProductionConstructor_UnderTesthost_ResolvesTheCliApphostInTheTestBin()
    {
        Assert.False(string.Equals(Path.GetFileName(Environment.ProcessPath), "Silvergun.CLI.exe", StringComparison.OrdinalIgnoreCase), "this test assumes the host is not the CLI");
        var expected = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe");
        Assert.True(File.Exists(expected), $"the CLI apphost is not in the test bin at '{expected}'; it is a net10.0-windows ProjectReference of this project");

        using var scanner = new YaraXWorkerScanner();

        Assert.Equal(expected, ScannerInternals.FieldOrNull(scanner, "workerPath"));
        Assert.Null(ScannerInternals.FieldOrNull(scanner, "workerPathProblem"));
    }
    #endregion

    #region Methods: the timeout range (W-D, (k), (i))
    // (configured, what the worker is told, whether it warns). Null is the ONE default (i); anything else outside
    // [2, 3600] is clamped with exactly one warning, so a large configured value cannot make YARA permanently
    // unavailable (the worker would answer it with fatal).
    public static TheoryData<int?, int, bool> TimeoutClamp() => new()
    {
        { null, 30, false },
        { 45, 45, false },
        { 2, 2, false },
        { 3600, 3600, false },
        { 1, 2, true },
        { 0, 2, true },
        { -5, 2, true },
        { int.MinValue, 2, true },
        { 3601, 3600, true },
        { 99999, 3600, true },
        { int.MaxValue, 3600, true },
    };

    [Theory]
    [MemberData(nameof(TimeoutClamp))]
    public void TheConfiguredTimeout_IsClampedIntoTheWorkersRange_WithOneWarningWhenItMoves(int? configured, int expected, bool warns)
    {
        using var warnings = new WarningCapture();

        using var scanner = new YaraXWorkerScanner(new YaraOptions { Timeout = configured });

        var arguments = ScannerInternals.Field<IReadOnlyList<string>>(scanner, "workerArguments");
        Assert.Equal(["__worker", "yara", "--protocol", "1", "--timeout", expected.ToString(System.Globalization.CultureInfo.InvariantCulture)], arguments);
        Assert.Equal(expected, ScannerInternals.Field<int>(scanner, "engineTimeoutSeconds"));   // and the backstop runs on it
        var clampWarnings = warnings.Warnings.Where(w => w.Contains("configured scan timeout", StringComparison.Ordinal)).ToArray();
        Assert.Equal(warns ? 1 : 0, clampWarnings.Length);
        if (warns)
            Assert.Contains($"is outside 2..3600 s; using {expected} s", clampWarnings[0], StringComparison.Ordinal);
    }

    [Fact]
    public void NoOptions_MeansTheProductDefault_NeverNoTimeout()
    {
        using var scanner = new YaraXWorkerScanner();

        Assert.Equal(WorkerProtocol.DefaultTimeoutSeconds, ScannerInternals.Field<int>(scanner, "engineTimeoutSeconds"));
        Assert.Equal(30, WorkerProtocol.DefaultTimeoutSeconds);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(3601)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void LaunchArguments_RefuseATimeoutOutsideTheRange(int seconds) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => WorkerProtocol.YaraWorkerLaunchArguments(seconds));

    [Theory]
    [InlineData(2)]
    [InlineData(30)]
    [InlineData(3600)]
    public void LaunchArguments_CarryTheTimeoutAfterTheFixedArguments(int seconds) =>
        Assert.Equal(["__worker", "yara", "--protocol", "1", "--timeout", seconds.ToString(System.Globalization.CultureInfo.InvariantCulture)],
            WorkerProtocol.YaraWorkerLaunchArguments(seconds));
    #endregion
}
#endif
