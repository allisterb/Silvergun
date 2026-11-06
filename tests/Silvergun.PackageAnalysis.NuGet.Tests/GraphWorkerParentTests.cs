namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// The parent side of graph worker protocol v1 (<c>GraphWorkerProcess</c>, <see cref="PackageReachability"/>;
/// <c>docs/agent/tasks/graph-worker.md</c> G2–G4) against the scripted fake worker (<c>FakeGraphWorker</c> in the
/// FakeYaraProbe). A worker that crashes, hangs, floods, lies or exits wrong costs at most its folder, Crashed or TimedOut
/// with the reason, and a restarted worker takes the folders after it; one that fails before <c>ready</c> blames no folder
/// and is not retried; the package budget, the folder cap and deduplication bound the work; no worker outlives the run.
/// Folders are named <c>lib/a</c>, <c>lib/b</c>, ... so their order is the alphabet's.
/// </summary>
public sealed class GraphWorkerParentTests : IDisposable
{
    #region Constructors
    public GraphWorkerParentTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        stage = new GraphStage("parent");
    }
    #endregion

    #region Methods: a genuine worker
    /// <summary>A genuine worker: each folder's outcome, report, size and paths are the in-process ones, from one start.</summary>
    [Fact]
    public void AGenuineWorker_AnswersEveryFolder_AsInProcess_FromOneStart()
    {
        using var script = new FakeGraphScript("genuine").Genuine();
        var a = stage.Mechanisms("lib/a");
        var b = stage.Small("lib/b");

        var report = Analyze(script, Options(), a, b);

        Assert.Equal(["lib/a", "lib/b"], report.Folders.Select(f => f.Folder));
        var analyzed = report.Folders[0];
        var expected = GraphJson.InProcess(0, "lib/a", [.. a.Select(m => (m.RelativePath, m.FullPath))]);
        Assert.Equal(FolderOutcome.Analyzed, analyzed.Outcome);
        Assert.Equal(GraphJson.Of(expected.Report), GraphJson.Of(analyzed.Report));
        Assert.Equal(expected.Assemblies, analyzed.Assemblies);
        Assert.Equal((expected.Nodes, expected.Edges), (analyzed.Nodes, analyzed.Edges));
        Assert.Null(analyzed.Reason);
        Assert.Null(analyzed.SameAs);
        var nothing = report.Folders[1];
        Assert.Equal(FolderOutcome.NothingLoaded, nothing.Outcome);
        Assert.Null(nothing.Report);
        Assert.Empty(nothing.Assemblies);
        Assert.Equal("lib/b/a.dll", Assert.Single(nothing.LoadFailures).RelativePath);
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    /// <summary>No assemblies: an empty report, and no worker is started at all.</summary>
    [Fact]
    public void NoAssemblies_IsAnEmptyReport_WithNoStart()
    {
        using var script = new FakeGraphScript("none").Genuine();

        var report = PackageReachability.Analyze([], Options(), script.Launch());

        Assert.Empty(report.Folders);
        Assert.Empty(script.Pids);
    }

    /// <summary>The worker's stderr is diagnostics only: relayed at Debug, never part of the result.</summary>
    [Fact]
    public void TheWorkersStderr_IsRelayedAtDebug()
    {
        using var script = new FakeGraphScript("stderr").Otherwise("request", "err hello-from-the-graph-worker", "ready", "empty", "done");
        using var capture = new WarningCapture();

        var report = Analyze(script, Options(), stage.Small("lib/a"));

        Assert.Equal(FolderOutcome.NothingLoaded, Assert.Single(report.Folders).Outcome);
        Assert.Contains(capture.Debugs, d => d.Contains("[graph-worker] hello-from-the-graph-worker", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: a crash costs its folder, and a new worker takes the rest
    /// <summary>
    /// The worker answers folder a, then dies (exit 9) on b. b is Crashed with the exit code in its reason; a new worker
    /// is sent only c, and builds it for real (Analyzed). Two starts.
    /// </summary>
    [Fact]
    public void ACrashMidPackage_BlamesTheFolderInFlight_AndARestartedWorkerAnalyzesTheRest()
    {
        using var script = new FakeGraphScript("crash")
            .Run(1, "request", "ready", "empty 1", "exit 9")
            .Otherwise("request", "ready", "build", "done");
        var c = stage.Mechanisms("lib/c");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"), c);

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.Crashed, FolderOutcome.Analyzed], report.Folders.Select(f => f.Outcome));
        var crashed = report.Folders[1];
        Assert.Contains("code 9 (0x00000009)", crashed.Reason, StringComparison.Ordinal);
        Assert.Null(crashed.Report);
        Assert.Equal(["lib/b/a.dll"], crashed.Assemblies);
        Assert.Empty(crashed.LoadFailures);
        Assert.Equal((0, 0), (crashed.Nodes, crashed.Edges));
        Assert.NotNull(report.Folders[2].Report);
        Assert.Equal(2, script.Pids.Length);
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c"], ["lib/c"]), script.RequestedFolders);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// Real uncatchable deaths (ADR 0021): a stack overflow, <see cref="Environment.FailFast(string)"/> and
    /// <see cref="Debug.Fail(string)"/> (CCI's path) each cost the folder, and the reason names what the exit code means
    /// (measured on Windows: 0xC00000FD and 0x80131623).
    /// </summary>
    [Theory]
    [InlineData("stackoverflow", "a stack overflow")]
    [InlineData("failfast", "Environment.FailFast")]
    [InlineData("debugfail", "Environment.FailFast")]
    public void AnUncatchableDeath_IsCrashed_WithTheExitCodeNamed(string death, string named)
    {
        using var script = new FakeGraphScript("death-" + death)
            .Run(1, "request", "ready", death)
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.Crashed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        if (OperatingSystem.IsWindows())
            Assert.Contains(named, report.Folders[0].Reason, StringComparison.Ordinal);
        Assert.Equal(2, script.Pids.Length);
    }

    /// <summary>A <c>fatal</c> record in place of a folder record blames that folder, with the worker's (escaped) reason.</summary>
    [Fact]
    public void AFatalMidPackage_IsCrashed_WithTheWorkersReason()
    {
        using var script = new FakeGraphScript("fatal-mid")
            .Run(1, "request", "ready", "out {\"type\":\"fatal\",\"reason\":\"boom\\nnext\"}", "exit 3")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.Equal(FolderOutcome.Crashed, report.Folders[0].Outcome);
        Assert.Contains("failed while building it: boom\\nnext", report.Folders[0].Reason, StringComparison.Ordinal);
        Assert.Equal(FolderOutcome.NothingLoaded, report.Folders[1].Outcome);
    }

    /// <summary>A worker that crashes on every folder costs one start per folder, and every folder is Crashed: nothing hides behind a crasher.</summary>
    [Fact]
    public void AWorkerThatCrashesOnEveryFolder_CostsOneStartPerFolder()
    {
        using var script = new FakeGraphScript("crash-all").Otherwise("request", "ready", "exit 1");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.Crashed, f.Outcome));
        Assert.Equal(3, script.Pids.Length);
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c"], ["lib/b", "lib/c"], ["lib/c"]), script.RequestedFolders);
    }
    #endregion

    #region Methods: clocks and the package budget
    /// <summary>A hang on b: b alone is TimedOut after the folder timeout, the hung worker is killed, and c is answered by a new one.</summary>
    [Fact]
    public void AHang_IsTimedOutOnThatFolderOnly_ThenARestart()
    {
        using var script = new FakeGraphScript("hang")
            .Run(1, "request", "ready", "empty 1", "hang")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(folderSeconds: 2), stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.TimedOut, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.Contains("not built within 2 s", report.Folders[1].Reason, StringComparison.Ordinal);
        Assert.Equal(2, script.Pids.Length);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// The package budget runs out while b is being built: b is TimedOut for the budget, c and d are NotRun for it, no new
    /// worker is started, and the call returns near the budget rather than the folder timeout.
    /// </summary>
    [Fact]
    public void ThePackageBudget_CutsTheFolderInFlight_AndLeavesTheRestNotRun()
    {
        using var script = new FakeGraphScript("budget").Otherwise("request", "ready", "empty 1", "hang");
        var clock = Stopwatch.StartNew();

        var report = Analyze(script, Options(folderSeconds: 120, packageSeconds: 3), stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"), stage.Small("lib/d"));

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"took {clock.Elapsed}");
        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.TimedOut, FolderOutcome.NotRun, FolderOutcome.NotRun], report.Folders.Select(f => f.Outcome));
        // Fixed text (review N2): a reason carries no timing, so two runs of one package give one reason.
        Assert.Equal("the package budget ran out while it was being built, so the worker was killed", report.Folders[1].Reason);
        Assert.All(report.Folders.Skip(2), f => Assert.Equal("the package budget of 3 s was spent before it was started", f.Reason));
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    /// <summary>A zero budget is spent before anything starts: every folder NotRun, no worker started.</summary>
    [Fact]
    public void AZeroPackageBudget_StartsNoWorker()
    {
        using var script = new FakeGraphScript("budget-zero").Genuine();

        var report = Analyze(script, Options(packageSeconds: 0), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NotRun, f.Outcome));
        Assert.Empty(script.Pids);
    }

    /// <summary>
    /// The budget is wall-clock across restarts: a worker that takes a second and then dies on every folder spends it, and
    /// once it is spent no further worker is started. No folder reads as answered.
    /// </summary>
    [Fact]
    public void ThePackageBudget_HoldsAcrossRestarts()
    {
        using var script = new FakeGraphScript("budget-restarts").Otherwise("request", "ready", "sleep 1000", "exit 1");
        var folders = Enumerable.Range(0, 8).Select(i => stage.Small($"lib/{(char)('a' + i)}")).ToArray();

        var report = Analyze(script, Options(folderSeconds: 60, packageSeconds: 2.5), folders);

        Assert.All(report.Folders, f => Assert.Contains(f.Outcome, new[] { FolderOutcome.Crashed, FolderOutcome.TimedOut, FolderOutcome.NotRun }));
        Assert.Contains(report.Folders, f => f.Outcome == FolderOutcome.NotRun);
        Assert.True(script.Pids.Length < folders.Length, $"{script.Pids.Length} starts for {folders.Length} folders");
        var firstUnrun = report.Folders.ToList().FindIndex(f => f.Outcome == FolderOutcome.NotRun);
        Assert.All(report.Folders.Skip(firstUnrun), f => Assert.Equal(FolderOutcome.NotRun, f.Outcome));
    }
    #endregion

    #region Methods: floods and protocol violations
    [Theory]
    [InlineData("outbig 16777217")]
    [InlineData("flood")]
    public void AnOversizeRecord_IsCrashed_AndTheRestAreStillAnswered(string flood)
    {
        using var script = new FakeGraphScript("flood")
            .Run(1, "request", "ready", flood, "hang")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.Crashed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.Contains($"over {GraphWorkerProtocol.MaxRecordLineBytes} bytes", report.Folders[0].Reason, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    public static TheoryData<string, string, string> Violations() => new()
    {
        // what, the run-1 command in place of folder a's record, a fragment of the reason
        { "garbage", "out this is not json", "not valid JSON" },
        { "a JSON null", "out null", "the record is null" },
        { "a wrong index", "answer empty index", "its index is 1, expected 0" },
        { "a wrong folder", "answer empty folder", "it names another folder" },
        { "an assembly dropped", "answer empty drop", "not the folder's assemblies, each once" },
        { "an assembly twice", "answer empty dup", "not the folder's assemblies, each once" },
        { "an assembly not requested", "answer empty extra", "not the folder's assemblies, each once" },
        { "a report although nothing loaded", "answer build reportnothing", "it has a report but loaded nothing" },
        { "no report although assemblies loaded", "answer build noreport", "it loaded assemblies but has no report" },
        { "a negative graph size", "answer empty negative", "its graph size is negative" },
        { "a second ready", "out {\"type\":\"ready\",\"protocol\":1,\"folders\":2}", "got 'GraphWorkerReady'" },
        { "an early done", "out {\"type\":\"done\",\"count\":2}", "got 'GraphWorkerDone'" },
        { "a record cut short", "raw {\"type\":\"folder\",\"index\":0", "" },
        { "an unknown member", "out {\"type\":\"folder\",\"index\":0,\"folder\":\"lib/a\",\"assemblies\":[],\"loadFailures\":[],\"report\":null,\"nodes\":0,\"edges\":0,\"x\":1}", "not valid JSON" },
        { "no discriminator", "out {\"index\":0,\"folder\":\"lib/a\"}", "" },
        { "the discriminator not first", "out {\"index\":0,\"type\":\"folder\",\"folder\":\"lib/a\",\"assemblies\":[],\"loadFailures\":[],\"report\":null,\"nodes\":0,\"edges\":0}", "" },
        { "an escaped lone surrogate", "out {\"type\":\"folder\",\"index\":0,\"folder\":\"lib/a\",\"assemblies\":[],\"loadFailures\":[{\"relativePath\":\"lib/a/Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Dependency.dll\",\"reason\":\"\\uD800\"},{\"relativePath\":\"lib/a/Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.dll\",\"reason\":\"x\"}],\"report\":null,\"nodes\":0,\"edges\":0}", "" },
        // A null list element (review W1): System.Text.Json checks members for null, not list elements.
        { "assemblies:[null]", "out {\"type\":\"folder\",\"index\":0,\"folder\":\"lib/a\",\"assemblies\":[null],\"loadFailures\":[],\"report\":null,\"nodes\":0,\"edges\":0}", "it holds a null list element" },
        { "loadFailures:[null]", "out {\"type\":\"folder\",\"index\":0,\"folder\":\"lib/a\",\"assemblies\":[],\"loadFailures\":[null],\"report\":null,\"nodes\":0,\"edges\":0}", "it holds a null list element" },
        { "a null among the assemblies", "answer build nullassembly", "it holds a null list element" },
        { "a null among the load failures", "answer empty nullfailure", "it holds a null list element" },
        { "a null reach", "answer build nullreach", "it holds a null list element" },
        { "a null profile", "answer build nullprofile", "it holds a null list element" },
        { "a null class", "answer build nullclass", "it holds a null list element" },
        { "a null class reason", "answer build nullreason", "it holds a null list element" },
        { "a null ignored edge", "answer build nullignored", "it holds a null list element" },
        { "a null example path", "answer build nullexample", "it holds a null list element" },
        { "a null hop", "answer build nullhop", "it holds a null list element" },
    };

    /// <summary>
    /// Each record that is not exactly the expected next one fails the folder in flight (Crashed, "broke protocol" or the
    /// line's own problem), the lying worker is killed, and a new worker answers the folder after it.
    /// </summary>
    [Theory]
    [MemberData(nameof(Violations))]
    public void AProtocolViolation_IsCrashed_AndTheNextFolderIsStillAnswered(string what, string command, string reason)
    {
        using var script = new FakeGraphScript("lie")
            .Run(1, "request", "ready", command, command.StartsWith("raw", StringComparison.Ordinal) ? "exit 0" : "hang")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        Assert.True(report.Folders[0].Outcome == FolderOutcome.Crashed, $"{what}: {report.Folders[0].Outcome} ({report.Folders[0].Reason})");
        Assert.Contains(reason, report.Folders[0].Reason, StringComparison.Ordinal);
        Assert.True(report.Folders[1].Outcome == FolderOutcome.NothingLoaded, $"{what}: folder b is {report.Folders[1].Outcome} ({report.Folders[1].Reason})");
        Assert.Equal(2, script.Pids.Length);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: a worker that fails before ready
    public static TheoryData<string, string[]> NoReady() => new()
    {
        { "exits at once", ["exit 0"] },
        { "exits non-zero at once", ["exit 5"] },
        { "dies of a stack overflow at once", ["stackoverflow"] },
        { "refuses the request with fatal", ["request", "out {\"type\":\"fatal\",\"reason\":\"nope\"}", "exit 3"] },
        { "sends garbage first", ["request", "out hello", "hang"] },
        { "announces another folder count", ["request", "ready 7", "empty", "done"] },
        { "announces another protocol", ["request", "out {\"type\":\"ready\",\"protocol\":2,\"folders\":2}", "empty", "done"] },
        { "sends a folder record first", ["request", "empty", "done"] },
        { "sends a record without a discriminator first", ["request", "out {\"protocol\":1,\"folders\":2}", "hang"] },
    };

    /// <summary>
    /// A worker that fails before <c>ready</c> is an environment problem (G4): no folder is blamed, every folder is NotRun
    /// with the reason, and nothing is retried: exactly one start.
    /// </summary>
    [Theory]
    [MemberData(nameof(NoReady))]
    public void AWorkerThatFailsBeforeReady_LeavesEveryFolderNotRun_WithOneStart(string what, string[] commands)
    {
        using var script = new FakeGraphScript("noready").Otherwise(commands);

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.True(report.Folders.All(f => f.Outcome == FolderOutcome.NotRun), $"{what}: {string.Join(", ", report.Folders.Select(f => $"{f.Outcome} ({f.Reason})"))}");
        Assert.All(report.Folders, f => Assert.StartsWith("the graph worker could not run: ", f.Reason, StringComparison.Ordinal));
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    [Fact]
    public void AFatalBeforeReady_CarriesTheWorkersReason()
    {
        using var script = new FakeGraphScript("refuse").Otherwise("request", "out {\"type\":\"fatal\",\"reason\":\"nope\"}", "exit 3");

        var report = Analyze(script, Options(), stage.Small("lib/a"));

        Assert.Contains("it refused the request: nope", Assert.Single(report.Folders).Reason, StringComparison.Ordinal);
    }

    /// <summary>A worker that never sends <c>ready</c> is waited for no longer than the package budget allows (the 30 s ready clock is cut to it).</summary>
    [Fact]
    public void AWorkerThatHangsBeforeReady_IsCutByThePackageBudget_AndNotRetried()
    {
        using var script = new FakeGraphScript("noready-hang").Otherwise("request", "hang");
        var clock = Stopwatch.StartNew();

        var report = Analyze(script, Options(packageSeconds: 2), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20), $"took {clock.Elapsed}");
        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NotRun, f.Outcome));
        // The reason names the wait the worker was given (the budget left when it started, a little under 2 s), not what
        // was left after the wait (0).
        Assert.True(WaitIn(report.Folders[0].Reason, "sent no 'ready' within ") is > 0 and <= 2, report.Folders[0].Reason);
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: every record received, but a bad ending
    public static TheoryData<string, string[]> BadEndings() => new()
    {
        { "exit 7 after done", ["request", "ready", "empty", "done", "exit 7"] },
        { "no done", ["request", "ready", "empty"] },
        { "a done with the wrong count", ["request", "ready", "empty", "done 5"] },
        { "garbage instead of done", ["request", "ready", "empty", "out junk", "hang"] },
        { "no exit after done", ["request", "ready", "empty", "done", "hang"] },
    };

    /// <summary>Every record was received and checked, so they are kept (AfterAll), with a warning; one start.</summary>
    [Theory]
    [MemberData(nameof(BadEndings))]
    public void ABadEndingAfterEveryRecord_KeepsTheRecords_WithAWarning(string what, string[] commands)
    {
        using var script = new FakeGraphScript("ending").Otherwise(commands);
        using var capture = new WarningCapture();

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.True(report.Folders.All(f => f.Outcome == FolderOutcome.NothingLoaded), $"{what}: {string.Join(", ", report.Folders.Select(f => f.Outcome))}");
        Assert.Contains(capture.Warnings, w => w.Contains("folder record(s) are kept", StringComparison.Ordinal));
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    [Fact]
    public void AnExitCodeAfterDone_IsNamedInTheWarning()
    {
        using var script = new FakeGraphScript("ending-code").Otherwise("request", "ready", "empty", "done", "exit 7");
        using var capture = new WarningCapture();

        Analyze(script, Options(), stage.Small("lib/a"));

        Assert.Contains(capture.Warnings, w => w.Contains("exited with code 7 (0x00000007) after 'done'", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: no worker executable
    [Fact]
    public void NoWorkerExecutable_IsNotRun_WithTheProblem_NeverInProcess()
    {
        var report = PackageReachability.Analyze([.. stage.Mechanisms("lib/a")], Options(),
            new GraphWorkerLaunch(null, "there is no graph worker here", GraphWorkerProtocol.Arguments, 0));

        var folder = Assert.Single(report.Folders);
        Assert.Equal(FolderOutcome.NotRun, folder.Outcome);
        Assert.Contains("there is no graph worker here", folder.Reason, StringComparison.Ordinal);
        Assert.Null(folder.Report);
    }

    [Theory]
    [InlineData("Silvergun.CLI.exe", "not absolute")]
    [InlineData(@"bin\Silvergun.CLI.exe", "not absolute")]
    public void ARelativeWorkerExecutable_IsNotRun(string executable, string reason)
    {
        var report = PackageReachability.Analyze([.. stage.Small("lib/a")], Options(), new GraphWorkerLaunch(executable, null, GraphWorkerProtocol.Arguments, 0));

        var folder = Assert.Single(report.Folders);
        Assert.Equal(FolderOutcome.NotRun, folder.Outcome);
        Assert.Contains(reason, folder.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingWorkerExecutable_IsNotRun()
    {
        var missing = Path.Combine(stage.Root, "no-such-worker.exe");

        var report = PackageReachability.Analyze([.. stage.Small("lib/a"), .. stage.Small("lib/b")], Options(), new GraphWorkerLaunch(missing, null, GraphWorkerProtocol.Arguments, 0));

        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NotRun, f.Outcome));
        Assert.All(report.Folders, f => Assert.Contains("could not be started", f.Reason, StringComparison.Ordinal));
    }
    #endregion

    #region Methods: paths that cannot go on the wire
    [Fact]
    public void AFolderWithARelativeOrIllFormedPath_IsNotRun_AndTheOthersAreStillBuilt()
    {
        using var script = new FakeGraphScript("unsendable").Empty();
        var relative = new PackageAssembly("lib/a/x.dll", Path.Combine("relative", "x.dll"), null, PackageItemRole.Lib, "aa");
        var illFormed = new PackageAssembly("lib/b/y\uD800.dll", Path.Combine(stage.Root, "lib", "b", "y\uD800.dll"), null, PackageItemRole.Lib, "bb");

        var report = PackageReachability.Analyze([relative, illFormed, .. stage.Small("lib/c")], Options(), script.Launch());

        Assert.Equal(["lib/a", "lib/b", "lib/c"], report.Folders.Select(f => f.Folder));
        Assert.Equal([FolderOutcome.NotRun, FolderOutcome.NotRun, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.Contains("no absolute path", report.Folders[0].Reason, StringComparison.Ordinal);
        Assert.Contains("not well-formed UTF-16", report.Folders[1].Reason, StringComparison.Ordinal);
        Assert.Equal(Runs(["lib/c"]), script.RequestedFolders);
    }
    #endregion

    #region Methods: identical folders are built once
    /// <summary>
    /// lib/a and lib/b hold the same files (names and bytes): one build, for a, and b shares its result with
    /// <see cref="FolderReachability.SameAs"/> = lib/a and its own paths. Observed on the worker's side: it was asked for
    /// a and c only.
    /// </summary>
    [Fact]
    public void IdenticalFolders_AreBuiltOnce_AndTheCopyHasItsOwnPaths()
    {
        using var script = new FakeGraphScript("dedup").Genuine();

        var report = Analyze(script, Options(), stage.Mechanisms("lib/a"), stage.Mechanisms("lib/b"), stage.Small("lib/c"));

        Assert.Equal(Runs(["lib/a", "lib/c"]), script.RequestedFolders);
        Assert.Equal(["lib/a", "lib/c"], script.Answered);
        var (first, copy) = (report.Folders[0], report.Folders[1]);
        Assert.Equal(FolderOutcome.Analyzed, copy.Outcome);
        Assert.Equal("lib/b", copy.Folder);
        Assert.Equal("lib/a", copy.SameAs);
        Assert.Null(first.SameAs);
        Assert.Equal(first.Assemblies.Select(a => a.Replace("lib/a/", "lib/b/", StringComparison.Ordinal)), copy.Assemblies);
        Assert.All(copy.Assemblies, a => Assert.StartsWith("lib/b/", a, StringComparison.Ordinal));
        Assert.Equal(GraphJson.Of(first.Report), GraphJson.Of(copy.Report));
        Assert.Equal((first.Nodes, first.Edges), (copy.Nodes, copy.Edges));
        Assert.Null(report.Folders[2].SameAs);
    }

    /// <summary>The W2 attack shape: one DLL copied into K folders costs one build; every copy names the first, not a chain.</summary>
    [Fact]
    public void KIdenticalFolders_CostOneBuild()
    {
        using var script = new FakeGraphScript("dedup-k").Empty();
        var bytes = GraphStage.Shared;

        var report = Analyze(script, Options(), [.. Enumerable.Range(0, 6).Select(i => stage.Small($"lib/{(char)('a' + i)}", "same.dll", bytes))]);

        Assert.Equal(Runs(["lib/a"]), script.RequestedFolders);
        Assert.All(report.Folders.Skip(1), f => Assert.Equal("lib/a", f.SameAs));
        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NothingLoaded, f.Outcome));
        Assert.Equal(report.Folders.Select(f => $"{f.Folder}/same.dll"), report.Folders.Select(f => Assert.Single(f.LoadFailures).RelativePath));
    }

    /// <summary>A copy shares its first's failure too: it never reads as clean because its twin crashed.</summary>
    [Fact]
    public void ACopyOfACrashedFolder_IsCrashedToo()
    {
        using var script = new FakeGraphScript("dedup-crash").Otherwise("request", "ready", "exit 9");
        var bytes = GraphStage.Shared;

        var report = Analyze(script, Options(), stage.Small("lib/a", "same.dll", bytes), stage.Small("lib/b", "same.dll", bytes));

        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.Crashed, f.Outcome));
        Assert.Equal("lib/a", report.Folders[1].SameAs);
        Assert.Equal(["lib/b/same.dll"], report.Folders[1].Assemblies);
        Assert.Single(script.Pids);
    }

    [Theory]
    [InlineData("the same bytes under another file name")]
    [InlineData("a missing hash")]
    public void FoldersThatAreNotProvablyIdentical_AreEachBuilt(string what)
    {
        using var script = new FakeGraphScript("nodedup").Empty();
        var bytes = GraphStage.Shared;
        var b = what == "a missing hash"
            ? new[] { stage.Put("lib/b", "same.dll", bytes, hash: false) }
            : stage.Small("lib/b", "other.dll", bytes);

        Analyze(script, Options(), stage.Small("lib/a", "same.dll", bytes), b);

        Assert.Equal(Runs(["lib/a", "lib/b"]), script.RequestedFolders);
    }
    #endregion

    #region Methods: the folder cap
    /// <summary>
    /// MaxFolders 2 over four distinct folders and a copy: the first two are built, the other two NotRun with the cap as the
    /// reason, and the copy (which is not a distinct folder) shares its first's result.
    /// </summary>
    [Fact]
    public void TheFolderCap_CountsDistinctFolders_AndLeavesThoseBeyondItNotRun()
    {
        using var script = new FakeGraphScript("cap").Empty();
        var bytes = GraphStage.Shared;

        var report = Analyze(script, Options(maxFolders: 2),
            stage.Small("lib/a", "same.dll", bytes), stage.Small("lib/b"), stage.Small("lib/c"), stage.Small("lib/d"), stage.Small("lib/e", "same.dll", bytes));

        Assert.Equal(Runs(["lib/a", "lib/b"]), script.RequestedFolders);
        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.NothingLoaded, FolderOutcome.NotRun, FolderOutcome.NotRun, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.All(report.Folders.Skip(2).Take(2), f => Assert.Contains("more than 2 distinct folders", f.Reason, StringComparison.Ordinal));
        Assert.Equal("lib/a", report.Folders[4].SameAs);
    }

    [Fact]
    public void AFolderCapOfZero_StartsNoWorker()
    {
        using var script = new FakeGraphScript("cap-zero").Empty();

        var report = Analyze(script, Options(maxFolders: 0), stage.Small("lib/a"));

        Assert.Equal(FolderOutcome.NotRun, Assert.Single(report.Folders).Outcome);
        Assert.Empty(script.Pids);
    }
    #endregion

    #region Methods: memory
    /// <summary>
    /// <c>DOTNET_GCHeapHardLimit</c> (¾ of the memory limit, every platform): a worker that allocates 512 MiB of managed
    /// memory under a 256 MiB limit fails that folder; the control without a limit allocates it and answers.
    /// </summary>
    [Theory]
    [InlineData("alloc managed 512")]
#if WINDOWS
    // The Job Object's per-process limit (Windows): native memory the GC limit does not see.
    [InlineData("alloc native 512")]
#endif
    public void AWorkerPastItsMemoryLimit_FailsThatFolder(string allocation)
    {
        using var limited = new FakeGraphScript("mem")
            .Run(1, "request", "ready", allocation, "empty", "done")
            .Otherwise("request", "ready", "empty", "done");
        using var control = new FakeGraphScript("mem-control").Otherwise("request", "ready", allocation, "empty", "done");
        var a = stage.Small("lib/a");
        var b = stage.Small("lib/b");

        var capped = PackageReachability.Analyze([.. a, .. b], Options(), limited.Launch(256L * 1024 * 1024));
        var free = PackageReachability.Analyze([.. a, .. b], Options(), control.Launch(0));

        Assert.Equal([FolderOutcome.Crashed, FolderOutcome.NothingLoaded], capped.Folders.Select(f => f.Outcome));
        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.NothingLoaded], free.Folders.Select(f => f.Outcome));
    }
    #endregion

    #region Methods: no worker outlives the run
    /// <summary>
    /// A hung worker that has started a grandchild holding its stdout: when the run gives up on it, both are gone by the
    /// time <see cref="PackageReachability.Analyze(System.Collections.Generic.IEnumerable{PackageAssembly}, PackageReachabilityOptions?)"/> returns.
    /// </summary>
    [Fact]
    public void AHungWorkerAndItsGrandchild_AreGoneWhenTheRunReturns()
    {
        using var grandchild = new FakeGraphScript("grandchild").Otherwise("hang");
        grandchild.Launch();
        using var script = new FakeGraphScript("orphan")
            .Run(1, "request", "ready", "spawn " + grandchild.ScriptPath, "sleep 1500", "hang")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(folderSeconds: 4), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.TimedOut, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        var grand = Assert.Single(grandchild.Pids);
        // The point is that both are gone, not how fast: a few seconds keeps it meaningful under a loaded machine.
        GraphProcesses.AssertGone([.. script.Pids, grand], TimeSpan.FromSeconds(5));
    }
    #endregion

    #region Methods: one run, directly
    /// <summary><c>GraphWorkerProcess.Run</c>: a failure's <c>Answered</c> are the records accepted, so the folder in flight is <c>Answered.Count</c>.</summary>
    [Fact]
    public void OneRun_OnACrash_ReportsTheAcceptedRecords_AndTheKind()
    {
        using var script = new FakeGraphScript("run").Otherwise("request", "ready", "empty 2", "exit 9");
        var request = GraphJson.Request(("lib/a", stage.Small("lib/a")), ("lib/b", stage.Small("lib/b")), ("lib/c", stage.Small("lib/c")));

        var run = GraphWorkerProcess.Run(script.Launch(), request, TimeSpan.FromSeconds(60), Stopwatch.GetTimestamp() + 300 * Stopwatch.Frequency);

        Assert.Equal(GraphWorkerFailureKind.Crashed, run.Failure);
        Assert.Equal([0, 1], run.Answered.Select(r => r.Index));
        Assert.Contains("code 9", run.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void OneRun_Complete_HasNoFailure()
    {
        using var script = new FakeGraphScript("run-ok").Empty();
        var request = GraphJson.Request(("lib/a", stage.Small("lib/a")));

        var run = GraphWorkerProcess.Run(script.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue);

        Assert.Null(run.Failure);
        Assert.Null(run.Reason);
        Assert.Single(run.Answered);
    }
    #endregion

    #region Methods: exit codes and the executable
    [Theory]
    [InlineData(0, "code 0 (0x00000000)")]
    [InlineData(9, "code 9 (0x00000009)")]
    [InlineData(3, "code 3 (0x00000003, the worker's fatal)")]
    [InlineData(4, "code 4 (0x00000004, the worker saw its stdin end)")]
    [InlineData(unchecked((int)0xC00000FD), "code -1073741571 (0xC00000FD, a stack overflow)")]
    [InlineData(unchecked((int)0xC0000005), "code -1073741819 (0xC0000005, an access violation)")]
    [InlineData(unchecked((int)0x80131623), "code -2146232797 (0x80131623, Environment.FailFast)")]
    [InlineData(unchecked((int)0xC0000409), "code -1073740791 (0xC0000409, a fail-fast (stack buffer overrun or __fastfail))")]
    [InlineData(unchecked((int)0xE0434352), "code -532462766 (0xE0434352, an unhandled .NET exception)")]
    [InlineData(unchecked((int)0xC0000017), "code -1073741801 (0xC0000017, out of memory)")]
    [InlineData(134, "code 134 (0x00000086, SIGABRT)")]
    [InlineData(137, "code 137 (0x00000089, SIGKILL)")]
    [InlineData(139, "code 139 (0x0000008B, SIGSEGV)")]
    public void DescribeExit_NamesTheKnownCrashCodes(int code, string described) =>
        Assert.Equal(described, GraphWorkerProcess.DescribeExit(code));

    [Fact]
    public void Resolve_PrefersThisProcess_WhenItIsTheCliApphost_ThenTheOneBesideIt_ElseSaysWhy()
    {
        var apphost = OperatingSystem.IsWindows() ? "Silvergun.CLI.exe" : "Silvergun.CLI";
        var self = Path.Combine(stage.Root, "self", apphost);
        var beside = Path.Combine(Directory.CreateDirectory(Path.Combine(stage.Root, "app")).FullName, apphost);
        File.WriteAllBytes(beside, []);

        Assert.Equal((self, (string?)null), GraphWorkerLaunch.Resolve(self, null));
        Assert.Equal((beside, (string?)null), GraphWorkerLaunch.Resolve(Path.Combine(stage.Root, "testhost.exe"), Path.GetDirectoryName(beside)));
        Assert.Equal(beside, GraphWorkerLaunch.Resolve(apphost, Path.GetDirectoryName(beside)).Path);   // a relative self is not trusted

        var (none, problem) = GraphWorkerLaunch.Resolve(Path.Combine(stage.Root, "testhost.exe"), Path.Combine(stage.Root, "empty"));
        Assert.Null(none);
        Assert.Contains("there is no graph worker executable", problem, StringComparison.Ordinal);
        Assert.Null(GraphWorkerLaunch.Resolve(null, "relative-dir").Path);
    }
    #endregion

    #region Methods: review round 1
    /// <summary>
    /// W2: a worker that never reads stdin, sent a request far larger than a pipe buffer (300 folders with 4000-char names,
    /// about 2.4 MB). The write is bounded by the ready clock cut to the package budget: every folder is NotRun with the
    /// reason, from one start, promptly, and the worker is gone.
    /// </summary>
    [Fact]
    public void AWorkerThatNeverReadsItsRequest_IsNotRun_WithinTheBound()
    {
        using var script = new FakeGraphScript("noread").Otherwise("hang");
        var name = new string('n', 4000);
        var folders = Enumerable.Range(0, 300)
            .Select(i => new PackageAssembly($"lib/f{i:D3}/{name}.dll", Path.Combine(stage.Root, $"f{i:D3}", name + ".dll"), null, PackageItemRole.Lib, ""))
            .ToArray();
        var clock = Stopwatch.StartNew();

        var report = PackageReachability.Analyze(folders, Options(packageSeconds: 3, maxFolders: 1000), script.Launch());

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20), $"took {clock.Elapsed}");
        Assert.Equal(300, report.Folders.Count);
        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NotRun, f.Outcome));
        Assert.Contains("did not read its request within ", report.Folders[0].Reason, StringComparison.Ordinal);
        Assert.True(WaitIn(report.Folders[0].Reason, "did not read its request within ") is > 0 and <= 3, report.Folders[0].Reason);
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// W3: a corrupt DLL in lib/a and its identical copy in lib/b, built for real by the worker. Each reason names the
    /// assembly by its own package path (the copy's by lib/b, never lib/a) and never by where it lies on disk.
    /// </summary>
    [Fact]
    public void LoadFailureReasons_NameThePackagePath_AndACopyNamesItsOwn()
    {
        using var script = new FakeGraphScript("reasons").Genuine();
        var bytes = "not a portable executable"u8.ToArray();

        var report = Analyze(script, Options(), stage.Small("lib/a", "corrupt.dll", bytes), stage.Small("lib/b", "corrupt.dll", bytes));

        Assert.Equal(Runs(["lib/a"]), script.RequestedFolders);
        var (first, copy) = (Assert.Single(report.Folders[0].LoadFailures), Assert.Single(report.Folders[1].LoadFailures));
        Assert.Equal("lib/a/corrupt.dll", first.RelativePath);
        Assert.Contains("lib/a/corrupt.dll", first.Reason, StringComparison.Ordinal);
        Assert.Equal("lib/b/corrupt.dll", copy.RelativePath);
        Assert.Contains("lib/b/corrupt.dll", copy.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("lib/a/", copy.Reason, StringComparison.Ordinal);
        Assert.Equal(first.Reason.Replace("lib/a/", "lib/b/", StringComparison.Ordinal), copy.Reason);
        Assert.All(new[] { first.Reason, copy.Reason }, r => Assert.DoesNotContain(stage.Root, r, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("lib/a", report.Folders[1].SameAs);
    }

#if !WINDOWS
    /// <summary>
    /// W4 end to end through the real worker loop (the fake's <c>relay</c> is <see cref="GraphWorker.Run"/> on its own stdin
    /// and stdout), under a 5 MiB GC heap (¾ of 6990506 bytes): the mechanism folder runs out of memory. Whatever allocation
    /// it lands in, a folder that could not be analysed for lack of memory must be Crashed (the worker's <c>fatal</c>), never
    /// NothingLoaded and never Analyzed with an assembly missing, and a restarted worker answers the next folder.
    /// <para>Measured 2026-11-05 on the fake, two runs per limit: at 4, 5 and 6 MiB the OOM lands while the SECOND assembly
    /// loads, inside AssemblyDisassembler.Create, whose catch-all reports it as "Failed to load assembly …"; the folder is then
    /// built from the first assembly alone and reads Analyzed. At 7 MiB it lands in BuildFolder and is <c>fatal</c>; at 8 MiB
    /// the build fits. (net10.0 only: on net10.0-windows the same limit is also the Job Object's per-process commit limit,
    /// which the runtime cannot start under.)</para>
    /// </summary>
    [Fact]
    public void AFolderThatRunsOutOfMemory_IsCrashed_NeverNothingLoadedOrPartlyAnalyzed_AndTheNextFolderIsAnswered()
    {
        using var script = new FakeGraphScript("w4").Otherwise("relay");

        var report = PackageReachability.Analyze([.. stage.Mechanisms("lib/a"), .. stage.Small("lib/b")], Options(), script.Launch(6990506));

        Assert.True(report.Folders[0].Outcome == FolderOutcome.Crashed, $"{report.Folders[0].Outcome} ({report.Folders[0].Reason}; {string.Join("; ", report.Folders[0].LoadFailures.Select(f => f.Reason))})");
        Assert.Contains("OutOfMemoryException", report.Folders[0].Reason, StringComparison.Ordinal);
        Assert.Equal(FolderOutcome.NothingLoaded, report.Folders[1].Outcome);
        Assert.Equal(2, script.Pids.Length);
        Assert.Equal(Runs(["lib/a", "lib/b"], ["lib/b"]), script.RequestedFolders);
    }
#endif

    /// <summary>
    /// W4, the parent's half, deterministically: the worker answers folder a, then sends the <c>fatal</c> it sends for a build
    /// that failed as a whole (BuildFailure) on folder b. b is Crashed with that reason, not NothingLoaded; a restarted worker
    /// is sent only c and builds it for real.
    /// </summary>
    [Fact]
    public void AWorkersFatalForAFailedBuild_IsCrashed_AndARestartedWorkerAnalyzesTheRest()
    {
        using var script = new FakeGraphScript("w4-scripted")
            .Run(1, "request", "ready", "empty 1", "out {\"type\":\"fatal\",\"reason\":\"the folder's graph could not be built: Exception of type 'System.OutOfMemoryException' was thrown.\"}", "exit 3")
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"), stage.Mechanisms("lib/c"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.Crashed, FolderOutcome.Analyzed], report.Folders.Select(f => f.Outcome));
        Assert.Equal("the graph worker failed while building it: the folder's graph could not be built: Exception of type 'System.OutOfMemoryException' was thrown.", report.Folders[1].Reason);
        Assert.Null(report.Folders[1].Report);
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c"], ["lib/c"]), script.RequestedFolders);
    }

    /// <summary>N4: a negative folder timeout is a zero one; it times the folder out (or leaves it unrun), and never fails the pass.</summary>
    [Fact]
    public void ANegativeFolderTimeout_TimesOut_NeverFailsThePass()
    {
        using var script = new FakeGraphScript("negative-folder").Otherwise("request", "ready", "sleep 500", "empty", "done");

        var report = Analyze(script, Options(folderSeconds: -5), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.Equal(FolderOutcome.TimedOut, report.Folders[0].Outcome);
        Assert.All(report.Folders, f => Assert.Contains(f.Outcome, new[] { FolderOutcome.TimedOut, FolderOutcome.NotRun, FolderOutcome.NothingLoaded }));
        Assert.All(report.Folders, f => Assert.False(f.Reason?.StartsWith("the graph pass failed", StringComparison.Ordinal) ?? false, f.Reason));
        script.AssertNoOrphans();
    }

    /// <summary>N4: a negative package budget is spent at once: every folder NotRun, no worker started.</summary>
    [Fact]
    public void ANegativePackageBudget_StartsNoWorker()
    {
        using var script = new FakeGraphScript("negative-budget").Empty();

        var report = Analyze(script, Options(packageSeconds: -5), stage.Small("lib/a"));

        Assert.Equal(FolderOutcome.NotRun, Assert.Single(report.Folders).Outcome);
        Assert.Empty(script.Pids);
    }

    /// <summary>N4's other end: the largest timeouts are no deadline at all, and the pass runs normally.</summary>
    [Fact]
    public void TheLargestTimeouts_AreNoDeadline()
    {
        using var script = new FakeGraphScript("max-timeouts").Empty();
        var options = Options() with { FolderTimeout = TimeSpan.MaxValue, PackageBudget = TimeSpan.MaxValue };

        var report = Analyze(script, options, stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NothingLoaded, f.Outcome));
    }
    #endregion

    #region Methods: review round 2
    /// <summary>
    /// W-A (a): folder records are kept while their line bytes total at most MaxReportBytes. With room for one and a half
    /// records, folder a is answered, folder b's record is built but not kept (NotRun, saying so), folder c is NotRun because
    /// the limit was reached, and no worker is restarted.
    /// </summary>
    [Fact]
    public void TheReportLimit_StopsKeepingRecords_AndLeavesTheRestNotRun()
    {
        var record = EmptyRecordBytes();
        var limit = record + record / 2;
        using var script = new FakeGraphScript("reports").Empty();

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.NotRun, FolderOutcome.NotRun], report.Folders.Select(f => f.Outcome));
        Assert.Equal($"its record would take the package's folder records over {limit} bytes, so it was not kept", report.Folders[1].Reason);
        Assert.Equal($"the package's folder records reached their limit of {limit} bytes before it was started", report.Folders[2].Reason);
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// W-A (b): the bytes kept are counted across worker restarts. Folder a is answered (one record), b crashes the worker,
    /// and the restarted worker's record for c needs a whole record when only half of one is left: c is NotRun. Had the
    /// restart been given the whole limit again, c would have been answered.
    /// </summary>
    [Fact]
    public void TheReportLimit_CarriesAcrossARestart()
    {
        var record = EmptyRecordBytes();
        using var script = new FakeGraphScript("reports-restart")
            .Run(1, "request", "ready", "empty 1", "exit 9")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options() with { MaxReportBytes = record + record / 2 }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.Crashed, FolderOutcome.NotRun], report.Folders.Select(f => f.Outcome));
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c"], ["lib/c"]), script.RequestedFolders);
    }

    /// <summary>
    /// W-A (b), the reason: a record cut on a restarted worker names the package's limit, as the text says ("the package's
    /// folder records over N bytes"), not what was left of it when that worker started.
    /// </summary>
    [Fact]
    public void TheReportLimitReason_NamesThePackagesLimit_AfterARestart()
    {
        var record = EmptyRecordBytes();
        var limit = record + record / 2;
        using var script = new FakeGraphScript("reports-restart-reason")
            .Run(1, "request", "ready", "empty 1", "exit 9")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.Equal($"its record would take the package's folder records over {limit} bytes, so it was not kept", report.Folders[2].Reason);
    }

    /// <summary>
    /// Final review, fix 1: a <c>fatal</c> is exempt from the report limit. With room for one record and 10 bytes more,
    /// folder a is answered; folder b's worker sends a <c>fatal</c> far longer than the 10 bytes left. b is Crashed with the
    /// worker's reason, not NotRun, and a restart follows. The restarted worker's record for c does not fit in the 10 bytes:
    /// c, the folder in flight, is NotRun for the limit, and d, never started, is NotRun because the limit was reached.
    /// </summary>
    [Fact]
    public void AFatal_IsExemptFromTheReportLimit_SoItsFolderIsCrashed_AndARestartFollows()
    {
        var record = EmptyRecordBytes();
        var limit = record + 10;
        var reason = new string('r', 200);
        using var script = new FakeGraphScript("reports-fatal")
            .Run(1, "request", "ready", "empty 1", $"out {{\"type\":\"fatal\",\"reason\":\"{reason}\"}}", "exit 3")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"), stage.Small("lib/d"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.Crashed, FolderOutcome.NotRun, FolderOutcome.NotRun], report.Folders.Select(f => f.Outcome));
        Assert.Equal($"the graph worker failed while building it: {reason}", report.Folders[1].Reason);
        Assert.Equal($"its record would take the package's folder records over {limit} bytes, so it was not kept", report.Folders[2].Reason);
        Assert.Equal($"the package's folder records reached their limit of {limit} bytes before it was started", report.Folders[3].Reason);
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c", "lib/d"], ["lib/c", "lib/d"]), script.RequestedFolders);
        script.AssertNoOrphans();
    }

    /// <summary>Fix 1, one run directly: a <c>fatal</c> line longer than the bytes left is Crashed, never ReportsSpent.</summary>
    [Fact]
    public void OneRun_AFatalLongerThanTheBytesLeft_IsCrashed_NotReportsSpent()
    {
        using var script = new FakeGraphScript("reports-fatal-run")
            .Otherwise("request", "ready", $"out {{\"type\":\"fatal\",\"reason\":\"{new string('f', 100)}\"}}", "exit 3");
        var request = GraphJson.Request(("lib/a", stage.Small("lib/a")));

        var run = GraphWorkerProcess.Run(script.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue, maxReportBytes: 5);

        Assert.Equal(GraphWorkerFailureKind.Crashed, run.Failure);
        Assert.Equal($"the graph worker failed while building it: {new string('f', 100)}", run.Reason);
        Assert.Empty(run.Answered);
    }

    /// <summary>W-A (c): MaxReportBytes 0, or below, means no limit: every record is kept.</summary>
    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void AReportLimitOfZeroOrLess_IsNoLimit(long limit)
    {
        using var script = new FakeGraphScript("reports-none").Empty();

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.All(report.Folders, f => Assert.Equal(FolderOutcome.NothingLoaded, f.Outcome));
    }

    /// <summary>W-A (d): the default limit is 128 MiB, for the shared default and for options built from scratch.</summary>
    [Fact]
    public void TheReportLimit_DefaultsTo128MiB()
    {
        Assert.Equal(128L * 1024 * 1024, PackageReachabilityOptions.Default.MaxReportBytes);
        Assert.Equal(128L * 1024 * 1024, new PackageReachabilityOptions(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1), 1, 0, CodeAnalysis.IL.GraphBudget.Default).MaxReportBytes);
    }

    /// <summary>W-A, one run directly: a record of exactly the bytes left is kept; with one byte less left, it is not.</summary>
    [Fact]
    public void OneRun_KeepsARecordOfExactlyTheBytesLeft_AndNotOneByteMore()
    {
        var record = EmptyRecordBytes();
        using var exact = new FakeGraphScript("reports-exact").Empty();
        using var over = new FakeGraphScript("reports-over").Empty();
        var request = GraphJson.Request(("lib/a", stage.Small("lib/a")));

        var kept = GraphWorkerProcess.Run(exact.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue, record);
        var cut = GraphWorkerProcess.Run(over.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue, record - 1);

        Assert.Null(kept.Failure);
        Assert.Single(kept.Answered);
        Assert.Equal(record, kept.AnsweredBytes);
        Assert.Equal(GraphWorkerFailureKind.ReportsSpent, cut.Failure);
        Assert.Empty(cut.Answered);
        Assert.Equal(0, cut.AnsweredBytes);
    }

    /// <summary>
    /// N1: lib/a holds a.dll and a.dll.dll, and x/lib/a is an identical copy. Each path in the copy's reasons is remapped
    /// once: "lib/a/a.dll" inside the already remapped "x/lib/a/a.dll.dll" is never rewritten into "x/x/…".
    /// </summary>
    [Fact]
    public void ACopysReasons_RemapEachPathOnce_NeverInsideAnotherRemappedPath()
    {
        using var script = new FakeGraphScript("remap").Genuine();
        var dll = "not a portable executable: a.dll"u8.ToArray();
        var dlldll = "not a portable executable: a.dll.dll"u8.ToArray();

        var report = Analyze(script, Options(),
            [stage.Put("lib/a", "a.dll", dll), stage.Put("lib/a", "a.dll.dll", dlldll)],
            [stage.Put("x/lib/a", "a.dll", dll), stage.Put("x/lib/a", "a.dll.dll", dlldll)]);

        Assert.Equal(Runs(["lib/a"]), script.RequestedFolders);
        var (first, copy) = (report.Folders[0], report.Folders[1]);
        Assert.Equal("x/lib/a", copy.Folder);
        Assert.Equal("lib/a", copy.SameAs);
        Assert.Equal(["x/lib/a/a.dll", "x/lib/a/a.dll.dll"], copy.LoadFailures.Select(f => f.RelativePath));
        Assert.Equal(first.LoadFailures.Select(f => f.Reason.Replace("lib/a/", "x/lib/a/", StringComparison.Ordinal)), copy.LoadFailures.Select(f => f.Reason));
        Assert.Contains("x/lib/a/a.dll.dll", copy.LoadFailures[1].Reason, StringComparison.Ordinal);
        Assert.All(copy.LoadFailures, f => Assert.DoesNotContain("x/x/", f.Reason, StringComparison.Ordinal));
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => stage.Dispose();

    // The line bytes of the fake's "nothing loaded" record for a folder like lib/a holding one a.dll, at a one-digit index:
    // every lib/<letter> folder of stage.Small has a record of exactly this size. Measured through the parent itself.
    private long EmptyRecordBytes()
    {
        using var script = new FakeGraphScript("record-size").Empty();
        var run = GraphWorkerProcess.Run(script.Launch(), GraphJson.Request(("lib/z", stage.Small("lib/z"))), TimeSpan.FromSeconds(60), long.MaxValue);
        Assert.Null(run.Failure);
        Assert.True(run.AnsweredBytes > 50, $"a record of {run.AnsweredBytes} bytes");
        return run.AnsweredBytes;
    }

    private static PackageReachabilityOptions Options(double folderSeconds = 60, double packageSeconds = 300, int maxFolders = 256) =>
        PackageReachabilityOptions.Default with
        {
            FolderTimeout = TimeSpan.FromSeconds(folderSeconds),
            PackageBudget = TimeSpan.FromSeconds(packageSeconds),
            MaxFolders = maxFolders,
            WorkerMemoryBytes = 0,
        };

    private static PackageReachabilityReport Analyze(FakeGraphScript script, PackageReachabilityOptions options, params PackageAssembly[][] folders) =>
        PackageReachability.Analyze(folders.SelectMany(f => f), options, script.Launch());

    // The seconds a reason names right after `prefix` ("... within 1.734 s"), or -1 when it names none.
    private static double WaitIn(string? reason, string prefix)
    {
        var match = System.Text.RegularExpressions.Regex.Match(reason ?? "", System.Text.RegularExpressions.Regex.Escape(prefix) + "([0-9]+(\\.[0-9]+)?) s");
        return match.Success ? double.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : -1;
    }

    // The folders of each request the fake was sent, one array per start.
    private static string[][] Runs(params string[][] runs) => runs;
    #endregion

    #region Fields
    private readonly GraphStage stage;
    #endregion
}
