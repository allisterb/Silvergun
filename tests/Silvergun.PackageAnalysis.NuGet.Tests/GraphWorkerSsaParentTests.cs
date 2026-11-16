namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// The parent side of graph worker protocol v2's SSA phase (<c>docs/agent/tasks/ssa-facts-s4.md</c> §4 and "As built
/// (S4.4)"; <c>GraphWorkerProcess</c>, <see cref="PackageReachability"/>) against the scripted fake worker
/// (<c>FakeGraphWorker</c>, whose <c>graph</c> and <c>ssa</c> commands script the SSA phase) and the real worker loop in a
/// child (its <c>relay</c>). Each folder's <c>ssa</c> record must follow its <c>folder</c> record; a worker that dies, hangs,
/// runs out of memory or breaks protocol in the SSA phase costs only that folder's SSA (Crashed or TimedOut), its graph
/// result stands and a restarted worker takes the next folder; SSA spends a time and a record-byte budget of its own and
/// never a graph's (review round 1, W2); every <c>ssa</c> record is checked against its contract (W3); copies share
/// their primary's SSA; and SSA never changes the graph pass (additive). Folders are named <c>lib/a</c>, <c>lib/b</c>, ...
/// </summary>
public sealed class GraphWorkerSsaParentTests : IDisposable
{
    #region Constructors
    public GraphWorkerSsaParentTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        stage = new GraphStage("ssa-parent");
    }
    #endregion

    #region Methods: SSA off, and the ssa record after its folder
    /// <summary>D2: SSA is off by default. Every <see cref="FolderReachability.Ssa"/> is null, and the request says <c>"ssa":null</c>.</summary>
    [Fact]
    public void WorkerV2_SsaOff_FolderSsaIsNull_AndTheRequestAsksForNone()
    {
        using var script = new FakeGraphScript("ssa-off").Genuine();

        var report = Analyze(script, Options(on: false), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        Assert.Null(PackageReachabilityOptions.Default.Ssa);
        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.All(report.Folders, f => Assert.Null(f.Ssa));
        Assert.Null(Assert.Single(Requests(script)).Ssa);
        Assert.Contains("\"ssa\":null", Assert.Single(GraphFiles.Lines(script.RequestLog)), StringComparison.Ordinal);
    }

    /// <summary>
    /// SSA on: the request carries the options' bounds; each folder's SSA comes from the <c>ssa</c> record after its folder
    /// record. The mechanism folder is Analyzed with facts (its env read's constant read); the garbage folder, whose graph was
    /// not built, is NotRun with the worker's reason; the host stubs, a graph with no sink site, are Analyzed with no sites.
    /// One start.
    /// </summary>
    [Fact]
    public void WorkerV2_SsaRecordFollowsFolder()
    {
        using var script = new FakeGraphScript("ssa-follows").Genuine();
        var a = stage.Mechanisms("lib/a");

        var report = Analyze(script, Options(), a, stage.Small("lib/b"), [stage.Put("lib/c", GraphStage.HostStubsFixture, GraphStage.HostStubs)]);

        // The options' bounds, but for the worker's FolderTime backstop: 60 s, kept within half the 60 s folder timeout.
        Assert.Equal(GraphWorkerSsaBounds.Of(SsaFactBounds.Default with { FolderTime = TimeSpan.FromSeconds(30) }), Assert.Single(Requests(script)).Ssa);
        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.NothingLoaded, FolderOutcome.Analyzed], report.Folders.Select(f => f.Outcome));
        Assert.Equal(GraphJson.Of(GraphJson.InProcess(0, "lib/a", [.. a.Select(m => (m.RelativePath, m.FullPath))]).Report), GraphJson.Of(report.Folders[0].Report));
        var facts = report.Folders[0].Ssa;
        Assert.Equal((SsaFolderOutcome.Analyzed, (string?)null), (facts!.Outcome, facts.Reason));
        Assert.Contains(facts.Facts!.Sites, s => s.Status == SsaSiteStatus.Analyzed && s.Site.CalleeKey.Contains("GetEnvironmentVariable", StringComparison.Ordinal)
            && s.Arguments is [{ Kind: SsaValueKind.Constant, Constants: [{ Text: "SILVERGUN_MECHANISM_FIXTURE" }] }, ..]);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, "the folder's graph was not built, so it has no sink sites"), report.Folders[1].Ssa);
        var none = report.Folders[2].Ssa!;
        Assert.Equal(SsaFolderOutcome.Analyzed, none.Outcome);
        Assert.Empty(none.Facts!.Sites);
        Assert.Equal(0, none.Facts.SitesTotal);
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// The real worker loop (the fake's <c>relay</c>: <see cref="GraphWorker.Run"/> over its own stdin and stdout) answers a
    /// three-folder package exactly as the scripted genuine worker does, folder for folder, graph and SSA. The scripted one runs
    /// each folder alone, so this also shows a folder's facts do not depend on the folders around it.
    /// </summary>
    [Fact]
    public void WorkerV2_SsaRecordFollowsFolder_ThroughTheRealLoop_AsTheScriptedWorker()
    {
        using var relay = new FakeGraphScript("ssa-relay").Otherwise("relay");
        using var scripted = new FakeGraphScript("ssa-scripted").Genuine();
        PackageAssembly[][] folders = [stage.Mechanisms("lib/a"), stage.Small("lib/b"), [stage.Put("lib/c", GraphStage.MechanismDependency, GraphStage.Dependency)]];

        var real = Analyze(relay, Options(), folders);
        var fake = Analyze(scripted, Options(), folders);

        Assert.Equal(fake.Folders.Select(GraphJson.GraphOf), real.Folders.Select(GraphJson.GraphOf));
        Assert.Equal(fake.Folders.Select(f => GraphJson.Of(f.Ssa)), real.Folders.Select(f => GraphJson.Of(f.Ssa)));
        Assert.Equal([SsaFolderOutcome.Analyzed, SsaFolderOutcome.NotRun, SsaFolderOutcome.Analyzed], real.Folders.Select(f => f.Ssa!.Outcome));
        Assert.Single(relay.Pids);
    }

    /// <summary>
    /// The <c>ssa</c> record has a folder timeout of its own, counted from its folder record (§4, "its clock"): the folder
    /// record and the <c>ssa</c> record each take 2 s of a 3 s timeout, 4 s in all, and both are accepted.
    /// </summary>
    [Fact]
    public void WorkerV2_TheSsaRecord_HasAFolderTimeoutOfItsOwn()
    {
        using var script = new FakeGraphScript("ssa-clock").Otherwise("request", "ready", "sleep 2000", "graph empty", "sleep 2000", "ssa none", "done");

        var report = Analyze(script, Options(folderSeconds: 3), stage.Small("lib/a"));

        var folder = Assert.Single(report.Folders);
        Assert.Equal(FolderOutcome.NothingLoaded, folder.Outcome);
        Assert.Equal(SsaFolderOutcome.NotRun, folder.Ssa!.Outcome);
        Assert.Equal("the folder's graph was not built, so it has no sink sites", folder.Ssa.Reason);
    }
    #endregion

    #region Methods: a death, hang or out-of-memory during SSA costs only that folder's SSA
    public static TheoryData<string, string[], string, bool> SsaDeaths() => new()
    {
        // what, the commands after folder a's record, a fragment of a's SSA reason, whether the fragment is Windows-only
        { "exit 9", ["exit 9"], "stopped while extracting its SSA facts: its output ended; it exited with code 9 (0x00000009)", false },
        { "a stack overflow", ["stackoverflow"], "a stack overflow", true },
        { "Environment.FailFast", ["failfast"], "Environment.FailFast", true },
        // The fake's genuine `graph build` ran a whole SSA phase in this process first. Its session is disposed by then, which
        // releases CilicaAssertions' throwing Trace listener, so a Debug.Fail after it fails fast exactly as without SSA (as in
        // GraphWorkerParentTests' graph-phase row), never an exception that some catch could swallow.
        { "Debug.Fail after an SSA phase", ["debugfail"], "Environment.FailFast", true },
        { "a fatal", ["out {\"type\":\"fatal\",\"reason\":\"boom\\nnext\"}", "exit 3"], "the graph worker failed while extracting its SSA facts: boom\\nnext", false },
        { "output cut mid-record", ["raw {\"type\":\"ssa\",\"index\":0", "exit 0"], "stopped while extracting its SSA facts: its output ended part-way through a record", false },
    };

    /// <summary>
    /// Acceptance 2: the worker sends folder a's record, then dies in its SSA phase. a's graph stands (Analyzed, the
    /// in-process report and size); its SSA is Crashed with the reason; a restarted worker is sent only b, and analyses it,
    /// SSA and all. Two starts.
    /// </summary>
    [Theory]
    [MemberData(nameof(SsaDeaths))]
    public void WorkerV2_DeathDuringSsa_GraphStandsSsaCrashed(string what, string[] death, string reason, bool windowsOnly)
    {
        using var script = new FakeGraphScript("ssa-death")
            .Run(1, ["request", "ready", "graph build", .. death])
            .Otherwise("request", "ready", "build", "done");
        var a = stage.Mechanisms("lib/a");
        var expected = GraphJson.InProcess(0, "lib/a", [.. a.Select(m => (m.RelativePath, m.FullPath))]);

        var report = Analyze(script, Options(), a, [stage.Put("lib/b", GraphStage.MechanismDependency, GraphStage.Dependency)]);

        var first = report.Folders[0];
        Assert.True(first.Outcome == FolderOutcome.Analyzed, $"{what}: {first.Outcome} ({first.Reason})");
        Assert.Equal(GraphJson.Of(expected.Report), GraphJson.Of(first.Report));
        Assert.Equal((expected.Nodes, expected.Edges, (string?)null), (first.Nodes, first.Edges, first.Reason));
        Assert.Equal((SsaFolderOutcome.Crashed, (SsaFolderFacts?)null), (first.Ssa!.Outcome, first.Ssa.Facts));
        if (!windowsOnly || OperatingSystem.IsWindows())
            Assert.True(first.Ssa.Reason!.Contains(reason, StringComparison.Ordinal), $"{what}: '{reason}' is not in '{first.Ssa.Reason}'");
        Assert.Contains("SSA facts", first.Ssa.Reason, StringComparison.Ordinal);
        Assert.Equal((FolderOutcome.Analyzed, SsaFolderOutcome.Analyzed), (report.Folders[1].Outcome, report.Folders[1].Ssa!.Outcome));
        Assert.NotEmpty(report.Folders[1].Ssa!.Facts!.Sites);
        Assert.Equal(Runs(["lib/a", "lib/b"], ["lib/b"]), script.RequestedFolders);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// A hang in folder a's SSA phase: after its own folder timeout the worker is killed and a's SSA is TimedOut, its graph
    /// standing; a new worker answers b. No worker outlives the run.
    /// </summary>
    [Fact]
    public void WorkerV2_HangDuringSsa_SsaTimedOut()
    {
        using var script = new FakeGraphScript("ssa-hang")
            .Run(1, "request", "ready", "graph build", "hang")
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options(folderSeconds: 8), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.NotNull(report.Folders[0].Report);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.TimedOut, null, "its SSA facts were not extracted within 8 s, so the worker was killed"), report.Folders[0].Ssa);
        Assert.Equal(SsaFolderOutcome.NotRun, report.Folders[1].Ssa!.Outcome);
        Assert.Equal(2, script.Pids.Length);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// §4, "out of memory": a worker that runs out of memory in its SSA phase (past the GC heap limit, or on Windows the Job
    /// Object's limit for native memory) costs only that folder's SSA: Crashed, the graph record standing. The control
    /// without a limit makes the same allocation and answers.
    /// </summary>
    [Theory]
    [InlineData("alloc managed 512")]
#if WINDOWS
    [InlineData("alloc native 512")]
#endif
    public void WorkerV2_OomDuringSsa_SsaCrashed(string allocation)
    {
        using var limited = new FakeGraphScript("ssa-mem")
            .Run(1, "request", "ready", "graph empty", allocation, "ssa none", "empty", "done")
            .Otherwise("request", "ready", "empty", "done");
        using var control = new FakeGraphScript("ssa-mem-control").Otherwise("request", "ready", "graph empty", allocation, "ssa none", "empty", "done");
        var a = stage.Small("lib/a");
        var b = stage.Small("lib/b");

        var capped = PackageReachability.Analyze([.. a, .. b], Options(), limited.Launch(256L * 1024 * 1024));
        var free = PackageReachability.Analyze([.. a, .. b], Options(), control.Launch(0));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.NothingLoaded], capped.Folders.Select(f => f.Outcome));
        Assert.Equal([SsaFolderOutcome.Crashed, SsaFolderOutcome.NotRun], capped.Folders.Select(f => f.Ssa!.Outcome));
        Assert.Contains("while extracting its SSA facts", capped.Folders[0].Ssa!.Reason, StringComparison.Ordinal);
        Assert.Equal(2, limited.Pids.Length);
        Assert.Equal([SsaFolderOutcome.NotRun, SsaFolderOutcome.NotRun], free.Folders.Select(f => f.Ssa!.Outcome));
        Assert.Single(control.Pids);
    }

    /// <summary>
    /// The worker's own answer to an out-of-memory in its SSA phase is <c>fatal</c> (<c>GraphWorkerLoopTests</c> pins it):
    /// the parent reads that folder's SSA Crashed with the worker's reason, keeps its graph, and restarts for the next.
    /// </summary>
    [Fact]
    public void WorkerV2_TheWorkersOomFatalDuringSsa_IsSsaCrashed_AndTheGraphStands()
    {
        const string oom = "the folder's SSA facts could not be extracted: OutOfMemoryException: Insufficient memory to continue the execution of the program.";
        using var script = new FakeGraphScript("ssa-oom-fatal")
            .Run(1, "request", "ready", "graph build", $"out {{\"type\":\"fatal\",\"reason\":\"{oom}\"}}", "exit 3")
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options(), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.Equal(new FolderSsa(SsaFolderOutcome.Crashed, null, "the graph worker failed while extracting its SSA facts: " + oom), report.Folders[0].Ssa);
        Assert.Equal(Runs(["lib/a", "lib/b"], ["lib/b"]), script.RequestedFolders);
    }
    #endregion

    #region Methods: the ssa record is checked
    public static TheoryData<string, string[], string> SsaViolations() => new()
    {
        // what, the commands in place of a genuine SSA phase for folder a, a fragment of a's SSA reason
        { "a wrong index", ["graph build", "ssa index"], "broke protocol v2: its index is 1, expected 0" },
        { "a TimedOut outcome", ["graph build", "ssa timedout"], "its outcome is TimedOut, which only the parent decides" },
        { "Crashed with facts", ["graph build", "ssa crashedfacts"], "it must carry facts exactly when Analyzed, and a reason otherwise" },
        { "Analyzed without facts", ["graph build", "ssa analyzednofacts"], "it must carry facts exactly when Analyzed, and a reason otherwise" },
        { "Analyzed with a reason too", ["graph build", "ssa reasonandfacts"], "it must carry facts exactly when Analyzed, and a reason otherwise" },
        { "NotRun without a reason", ["graph build", "ssa noreason"], "it must carry facts exactly when Analyzed, and a reason otherwise" },
        { "facts for a folder with no report", ["graph empty", "ssa analyzed"], "it has facts for a folder whose graph was not analysed" },
        { "a null site", ["graph build", "ssa nullsite"], "it holds a null list element" },
        { "a null failure count", ["graph build", "ssa nullunknown"], "it holds a null list element" },
        { "a null argument", ["graph build", "ssa nullargument"], "it holds a null list element" },
        { "a null constant", ["graph build", "ssa nullconstant"], "it holds a null list element" },
        { "a null candidate", ["graph build", "ssa nullcandidate"], "it holds a null list element" },
        { "sites over MaxSites", ["graph build", "ssa oversites"], FolderCounts },
        { "more sites than sitesTotal", ["graph build", "ssa inconsistent"], FolderCounts },
        { "truncated contradicting the counts", ["graph build", "ssa truncatedlie"], FolderCounts },
        { "a negative methodsLifted", ["graph build", "ssa negative"], FolderCounts },
        { "a negative assembliesLost", ["graph build", "ssa negativelost"], FolderCounts },
        // Review round 1, W3: the folder's, each site's and each value's contract.
        { "a failure count of -9", ["graph build", "ssa unknownneg"], FolderCounts },
        { "one failure kind twice", ["graph build", "ssa unknowndup"], FolderCounts },
        { "assembliesLost with Analyzed sites", ["graph build", "ssa lostanalyzed"], "it lost assemblies but did not read every site MethodUnknown" },
        { "a NotRun site without a budget flag", ["graph build", "ssa notrunsite"], "it has a NotRun site but no budget was spent" },
        // In-lift deadline, review round 1: Extract turns a TimedOut lift into its time cut, so the kind is never a fact.
        { "a TimedOut failure count", ["graph build", "ssa unknowntimedout"], TimedOutFact },
        { "a MethodUnknown site of kind TimedOut", ["graph build", "ssa sitetimedout"], TimedOutFact },
        { "arguments over MaxArguments", ["graph build", "ssa overargs"], ArgumentCounts },
        { "an ArgumentCount of -7", ["graph build", "ssa argcountneg"], ArgumentCounts },
        { "an Analyzed site with a reason", ["graph build", "ssa analyzedreason"], ArgumentCounts },
        { "MethodUnknown without its failure kind", ["graph build", "ssa unknownnokind"], "a MethodUnknown site carries values, or lacks its reason or failure kind" },
        { "MethodUnknown without its reason", ["graph build", "ssa unknownnoreason"], "a MethodUnknown site carries values, or lacks its reason or failure kind" },
        { "MethodUnknown with arguments", ["graph build", "ssa unknownwithargs"], "a MethodUnknown site carries values, or lacks its reason or failure kind" },
        { "a site name past its bound", ["graph build", "ssa longname"], "a site's names are over their bound" },
        // recall-levers-1: the entry name of a P/Invoke callee is bounded, escaped, and only on an Analyzed site.
        { "an import name past its bound", ["graph build", "ssa importlong"], ImportProblem },
        { "an unescaped control char in an import name", ["graph build", "ssa importraw"], ImportProblem },
        { "an import name on a MethodUnknown site", ["graph build", "ssa importunknown"], "a MethodUnknown site carries values, or lacks its reason or failure kind" },
        { "a Constant with no constant", ["graph build", "ssa constempty"], MalformedValue },
        { "a OneOf of one constant", ["graph build", "ssa oneofone"], MalformedValue },
        { "a Dynamic without its origin", ["graph build", "ssa dynnoorigin"], MalformedValue },
        { "a Parameter of -5", ["graph build", "ssa paramneg"], MalformedValue },
        { "a 100,000-char constant", ["graph build", "ssa hugeconst"], MalformedValue },
        { "an unescaped control char in a constant", ["graph build", "ssa controlconst"], MalformedValue },
        { "candidates over MaxCandidates", ["graph build", "ssa overcandidates"], MalformedTarget },
        { "a Type target with a member", ["graph build", "ssa targetmember"], MalformedTarget },
        { "more candidates than candidatesTotal", ["graph build", "ssa candidatestotal"], MalformedTarget },
        { "a v1 worker: the next folder record", ["graph build", "graph build"], "expected the 'ssa' record for index 0, got 'GraphWorkerFolder'" },
        { "an early done", ["graph build", "done"], "expected the 'ssa' record for index 0, got 'GraphWorkerDone'" },
        { "a second ready", ["graph build", "ready"], "expected the 'ssa' record for index 0, got 'GraphWorkerReady'" },
        { "garbage", ["graph build", "out not json"], "not valid JSON" },
        { "a JSON null", ["graph build", "out null"], "the record is null" },
        { "an unknown member", ["graph build", "out {\"type\":\"ssa\",\"index\":0,\"outcome\":\"NotRun\",\"facts\":null,\"reason\":\"r\",\"x\":1}"], "not valid JSON" },
        { "an integer outcome", ["graph build", "out {\"type\":\"ssa\",\"index\":0,\"outcome\":2,\"facts\":null,\"reason\":\"r\"}"], "not valid JSON" },
        { "an escaped lone surrogate", ["graph build", "out {\"type\":\"ssa\",\"index\":0,\"outcome\":\"NotRun\",\"facts\":null,\"reason\":\"\\uD800\"}"], "not valid JSON" },
        { "a record over 16 MiB", ["graph build", "outbig 16777217"], $"over {GraphWorkerProtocol.MaxRecordLineBytes} bytes" },
    };

    private const string ImportProblem = "a site's import name is over its bound or not escaped";
    private const string FolderCounts = "its folder counts are inconsistent or over the request's bounds";
    private const string ArgumentCounts = "an Analyzed site carries a reason, or its argument counts are inconsistent";
    private const string MalformedValue = "a site holds a malformed value";
    private const string MalformedTarget = "a site's reflection target is malformed";
    private const string TimedOutFact = "it reports a TimedOut lift as a fact";

    /// <summary>
    /// <c>SsaMismatch</c> and the line checks: an <c>ssa</c> record that is not exactly folder a's fails a's SSA only
    /// (Crashed, with why); a's graph record stands, the lying worker is killed, and a new worker answers b. The request's
    /// bounds are tight (2 sites, 1 argument, 1 candidate) so the genuine record sits at them and one more is over.
    /// </summary>
    [Theory]
    [MemberData(nameof(SsaViolations))]
    public void WorkerV2_SsaRecordWrongIndex_ProtocolViolation(string what, string[] commands, string reason)
    {
        using var script = new FakeGraphScript("ssa-lie")
            .Run(1, ["request", "ready", .. commands, "hang"])
            .Otherwise("request", "ready", "build", "done");
        var bounds = SsaFactBounds.Default with { MaxSites = 2, MaxArguments = 1, MaxCandidates = 1 };

        var report = Analyze(script, Options(ssa: bounds), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        var first = report.Folders[0];
        var graph = commands[0] == "graph build" ? FolderOutcome.Analyzed : FolderOutcome.NothingLoaded;
        Assert.True(first.Outcome == graph, $"{what}: the graph is {first.Outcome} ({first.Reason})");
        Assert.True(first.Ssa is { Outcome: SsaFolderOutcome.Crashed, Facts: null }, $"{what}: SSA {first.Ssa?.Outcome} ({first.Ssa?.Reason})");
        Assert.Contains(reason, first.Ssa!.Reason, StringComparison.Ordinal);
        Assert.Equal((FolderOutcome.NothingLoaded, SsaFolderOutcome.NotRun), (report.Folders[1].Outcome, report.Folders[1].Ssa!.Outcome));
        Assert.Equal(2, script.Pids.Length);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// The control for the violations: the same tight bounds, a genuine phase, and the records the worker may send
    /// itself (NotRun or Crashed with a reason, no facts) are accepted as they are, from one start.
    /// </summary>
    [Theory]
    [InlineData("ssa none", SsaFolderOutcome.Analyzed, null)]
    [InlineData("ssa crashed", SsaFolderOutcome.Crashed, "fake: crashed")]
    [InlineData("ssa notrun", SsaFolderOutcome.NotRun, "fake: not run")]
    [InlineData("ssa unknownok", SsaFolderOutcome.Analyzed, null)]
    [InlineData("ssa notrunok", SsaFolderOutcome.Analyzed, null)]
    public void WorkerV2_AnSsaRecordTheWorkerMaySend_IsAccepted(string command, SsaFolderOutcome outcome, string? reason)
    {
        using var script = new FakeGraphScript("ssa-valid").Otherwise("request", "ready", "graph build", command, "build", "done");
        var bounds = SsaFactBounds.Default with { MaxSites = 2, MaxArguments = 1, MaxCandidates = 1 };

        var report = Analyze(script, Options(ssa: bounds), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        Assert.Equal((outcome, reason), (report.Folders[0].Ssa!.Outcome, report.Folders[0].Ssa!.Reason));
        Assert.Equal(outcome == SsaFolderOutcome.Analyzed, report.Folders[0].Ssa!.Facts is not null);
        if (outcome == SsaFolderOutcome.Analyzed)
            Assert.Equal((2, true), (report.Folders[0].Ssa!.Facts!.Sites.Count, report.Folders[0].Ssa!.Facts!.Truncated));
        Assert.Equal(SsaFolderOutcome.NotRun, report.Folders[1].Ssa!.Outcome);
        Assert.Single(script.Pids);
    }

    /// <summary>
    /// recall-levers-1: a valid entry name on an Analyzed site is accepted and reaches the parent's facts as sent (a record
    /// without one reads null: the field is optional, as old workers wrote it).
    /// </summary>
    [Fact]
    public void WorkerV2_AnImportNameOnAnAnalyzedSite_IsAccepted_AndKept()
    {
        using var script = new FakeGraphScript("ssa-import-ok").Otherwise("request", "ready", "graph build", "ssa importok", "build", "done");

        var report = Analyze(script, Options(), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        var ssa = report.Folders[0].Ssa!;
        Assert.Equal(SsaFolderOutcome.Analyzed, ssa.Outcome);
        Assert.Contains(ssa.Facts!.Sites, s => s is { Status: SsaSiteStatus.Analyzed, Import: "VirtualAlloc" });
        Assert.Contains(ssa.Facts.Sites, s => s.Import is null);
        Assert.Single(script.Pids);
    }
    #endregion

    #region Methods: constant text is the escaper's own (review round 2, N1)
    // Text whose backslashes do not each start an EscapeBounded escape: a lone backslash before a quote (which would let
    // a forged name close its literal in the summary: SsaSummary escapes the quote but trusts the worker's backslashes),
    // a lone trailing backslash, an unknown escape, a short or ill-cased one. Built from code points; the source holds
    // no escape of a hostile character.
    public static TheoryData<string, string, bool> BadlyEscapedConstants() => new()
    {
        // what, the constant's text, as a Type constant (else a String)
        { "a lone backslash before a quote", "T" + Bs + "\"), typeof(\"cmd", false },
        { "a lone backslash before a quote, in a Type name", "T" + Bs + "\"), typeof(\"cmd", true },
        { "a lone trailing backslash", "abc" + Bs, false },
        { "a lone trailing backslash, in a Type name", "abc" + Bs, true },
        { "an unknown escape", Bs + "q", false },
        { "a short hex escape at the end", "a" + Bs + "x1", false },
        { "a short hex escape", Bs + "x1g", false },
        { "a hex escape of non-hex", Bs + "xZZ", false },
        { "an upper-case hex escape", Bs + "x1B", false },
        { "a short BMP escape", Bs + "u20", false },
        { "a lower-case astral escape", Bs + "U000e0041", true },
        { "an odd run of backslashes", "a" + Bs + Bs + Bs + "b", false },
    };

    [Theory]
    [MemberData(nameof(BadlyEscapedConstants))]
    public void WorkerV2_AConstantNotEscapedByTheEscaper_IsAProtocolBreak(string what, string text, bool type)
    {
        using var script = new FakeGraphScript("ssa-escape")
            .Run(1, ["request", "ready", "graph build", $"ssa {(type ? "typeconst" : "textconst")} {Hex(text)}", "hang"])
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options(ssa: SsaFactBounds.Default), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        var first = report.Folders[0];
        Assert.True(first.Outcome == FolderOutcome.Analyzed, $"{what}: the graph is {first.Outcome} ({first.Reason})");
        Assert.True(first.Ssa is { Outcome: SsaFolderOutcome.Crashed, Facts: null }, $"{what}: SSA {first.Ssa?.Outcome} ({first.Ssa?.Reason})");
        Assert.Contains(MalformedValue, first.Ssa!.Reason, StringComparison.Ordinal);
        Assert.Equal(2, script.Pids.Length);
        script.AssertNoOrphans();
    }

    // The control: what EscapeBounded writes (a doubled backslash, \n \r \t, \xNN lower-case, \uXXXX either case since a
    // lone surrogate is written upper-case, \UXXXXXXXX upper-case) and an unescaped quote, which the escaper leaves.
    public static TheoryData<string, bool> WellEscapedConstants() => new()
    {
        { "a" + Bs + Bs + "b", false },
        { "C:" + Bs + Bs + "Windows" + Bs + Bs, false },
        { Bs + "x1b[31m", false },
        { Bs + "u202e", false },
        { Bs + "uD800" + Bs + "uDFFF", false },
        { Bs + "U000E0041", true },
        { Bs + "n" + Bs + "r" + Bs + "t", false },
        { "say \"hi\"", false },
        { "Own.T\"), typeof(\"cmd", true },
        { string.Empty, false },
    };

    [Theory]
    [MemberData(nameof(WellEscapedConstants))]
    public void WorkerV2_AConstantTheEscaperWrites_IsAccepted(string text, bool type)
    {
        using var script = new FakeGraphScript("ssa-escaped")
            .Otherwise("request", "ready", "graph build", $"ssa {(type ? "typeconst" : "textconst")} {Hex(text)}", "build", "done");

        var report = Analyze(script, Options(ssa: SsaFactBounds.Default), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        var ssa = report.Folders[0].Ssa!;
        Assert.True(ssa.Outcome == SsaFolderOutcome.Analyzed, $"SSA {ssa.Outcome} ({ssa.Reason})");
        var constant = ssa.Facts!.Sites.First(s => s.Status == SsaSiteStatus.Analyzed && s.Arguments.Count > 0).Arguments[0].Constants.Single();
        Assert.Equal((type ? SsaConstantKind.Type : SsaConstantKind.String, text), (constant.Kind, constant.Text));
        Assert.Single(script.Pids);
    }

    // UTF-16 code units in hex, 4 digits each: FakeGraphWorker's textconst / typeconst argument.
    private static string Hex(string text) => string.Concat(text.Select(c => ((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture)));

    private const char Bs = (char)0x5C;
    #endregion

    #region Methods: copies share their primary's SSA
    /// <summary>
    /// lib/b is a copy of lib/a: built once, and b's SSA is a's, facts and all, byte for byte. Observed on the worker's
    /// side: it was asked for a and c only.
    /// </summary>
    [Fact]
    public void WorkerV2_SameAs_SharesSsa()
    {
        using var script = new FakeGraphScript("ssa-dedup").Genuine();

        var report = Analyze(script, Options(), stage.Mechanisms("lib/a"), stage.Mechanisms("lib/b"), stage.Small("lib/c"));

        Assert.Equal(Runs(["lib/a", "lib/c"]), script.RequestedFolders);
        var (first, copy) = (report.Folders[0], report.Folders[1]);
        Assert.Equal("lib/a", copy.SameAs);
        Assert.Equal(SsaFolderOutcome.Analyzed, first.Ssa!.Outcome);
        Assert.NotEmpty(first.Ssa.Facts!.Sites);
        Assert.Equal(GraphJson.Of(first.Ssa), GraphJson.Of(copy.Ssa));
        Assert.Equal(SsaFolderOutcome.NotRun, report.Folders[2].Ssa!.Outcome);
    }

    /// <summary>
    /// A copy shares a failed SSA too, never reading as analysed because its twin was not: a death in a's SSA phase makes the
    /// copy's SSA Crashed as well; and a NotRun reason naming a's assembly names the copy's own in the copy.
    /// </summary>
    [Theory]
    [InlineData("exit 9", SsaFolderOutcome.Crashed)]
    [InlineData("ssa notrun fake: lib/a/same.dll was not read", SsaFolderOutcome.NotRun)]
    public void WorkerV2_SameAs_ACopySharesAFailedSsa_WithItsOwnPaths(string command, SsaFolderOutcome outcome)
    {
        using var script = new FakeGraphScript("ssa-dedup-failed").Otherwise("request", "ready", "graph empty", command, "done");
        var bytes = GraphStage.Shared;

        var report = Analyze(script, Options(), stage.Small("lib/a", "same.dll", bytes), stage.Small("lib/b", "same.dll", bytes));

        var (first, copy) = (report.Folders[0], report.Folders[1]);
        Assert.Equal("lib/a", copy.SameAs);
        Assert.Equal((outcome, outcome), (first.Ssa!.Outcome, copy.Ssa!.Outcome));
        Assert.Equal(first.Ssa.Reason!.Replace("lib/a/", "lib/b/", StringComparison.Ordinal), copy.Ssa.Reason);
        if (outcome == SsaFolderOutcome.NotRun)
            Assert.Equal("fake: lib/b/same.dll was not read", copy.Ssa.Reason);
        Assert.Single(script.Pids);
    }
    #endregion

    #region Methods: SSA has a record-byte budget of its own
    /// <summary>
    /// Review round 1, W2: <c>ssa</c> records spend a byte budget of their own (<c>MaxReportBytes</c> again), never the
    /// graphs'. a's <c>ssa</c> record is padded past the limit while every folder record fits: a's graph is kept, a's SSA is
    /// NotRun for the SSA limit, and a fresh worker runs b without SSA, so b's graph is Analyzed as normal and its SSA reads
    /// NotRun because the SSA limit was reached.
    /// </summary>
    [Fact]
    public void WorkerV2_MaxReportBytes_CountsSsa()
    {
        var (folder, _) = RecordBytes();
        var b = stage.Mechanisms("lib/b");
        var bRecord = Encoding.UTF8.GetByteCount(GraphJson.Of(GraphJson.InProcess(0, "lib/b", [.. b.Select(m => (m.RelativePath, m.FullPath))]))) + 1;
        var limit = folder + bRecord + 100;
        using var script = new FakeGraphScript("ssa-reports")
            .Run(1, "request", "ready", "graph empty", $"ssa pad {limit}", "hang")
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), b);

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.Analyzed], report.Folders.Select(f => f.Outcome));
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, $"its SSA record would take the package's SSA records over {limit} bytes, so it was not kept"), report.Folders[0].Ssa);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, $"the package's SSA records reached their limit of {limit} bytes before it was started"), report.Folders[1].Ssa);
        Assert.NotNull(report.Folders[1].Report);
        var requests = Requests(script);
        Assert.Equal(2, requests.Length);
        Assert.NotNull(requests[0].Ssa);
        Assert.Null(requests[1].Ssa);   // the rest run without SSA
        script.AssertNoOrphans();
    }

    /// <summary>
    /// One run directly: folder and <c>ssa</c> bytes are counted apart (<c>AnsweredBytes</c>, <c>SsaBytes</c>). With
    /// exactly the folder record's bytes for the graphs and the ssa record's for SSA, both are kept; one SSA byte less is an
    /// InSsa ReportsSpent that keeps the folder record; and an SSA limit never cuts a folder record.
    /// </summary>
    [Fact]
    public void WorkerV2_OneRun_KeepsAnSsaRecordOfExactlyTheBytesLeft_AndNotOneByteMore()
    {
        var (folder, ssa) = RecordBytes();
        using var exact = new FakeGraphScript("ssa-reports-exact").Empty();
        using var over = new FakeGraphScript("ssa-reports-over").Empty();
        var request = SsaRequest(("lib/a", stage.Small("lib/a")));

        var kept = GraphWorkerProcess.Run(exact.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue, folder, maxSsaBytes: ssa);
        var cut = GraphWorkerProcess.Run(over.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue, folder, maxSsaBytes: ssa - 1);

        Assert.Null(kept.Failure);
        Assert.Equal((1, 1, folder, ssa, false), (kept.Answered.Count, kept.Ssa.Count, kept.AnsweredBytes, kept.SsaBytes, kept.InSsa));
        Assert.Equal(GraphWorkerFailureKind.ReportsSpent, cut.Failure);
        Assert.Equal((1, 0, folder, 0L, true), (cut.Answered.Count, cut.Ssa.Count, cut.AnsweredBytes, cut.SsaBytes, cut.InSsa));
        Assert.Equal($"its SSA record would take this run's SSA records over {ssa - 1} bytes, so it was not kept", cut.Reason);
    }

    /// <summary>
    /// A <c>fatal</c> in the SSA phase is exempt from the limits, as in the graph phase: with room for a's folder record and
    /// 10 bytes more (for graphs, and for SSA), a's SSA <c>fatal</c> (far longer) makes a's SSA Crashed with the worker's
    /// reason, not NotRun. The restarted worker's record for b does not fit in the 10 graph bytes left: b is NotRun for the
    /// limit, c because it was reached.
    /// </summary>
    [Fact]
    public void WorkerV2_AFatalDuringSsa_IsExemptFromTheReportLimit()
    {
        var (folder, _) = RecordBytes();
        var limit = folder + 10;
        var why = new string('r', 200);
        using var script = new FakeGraphScript("ssa-reports-fatal")
            .Run(1, "request", "ready", "graph empty", $"out {{\"type\":\"fatal\",\"reason\":\"{why}\"}}", "exit 3")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.NotRun, FolderOutcome.NotRun], report.Folders.Select(f => f.Outcome));
        Assert.Equal(new FolderSsa(SsaFolderOutcome.Crashed, null, $"the graph worker failed while extracting its SSA facts: {why}"), report.Folders[0].Ssa);
        Assert.Equal($"its record would take the package's folder records over {limit} bytes, so it was not kept", report.Folders[1].Reason);
        Assert.Equal($"the package's folder records reached their limit of {limit} bytes before it was started", report.Folders[2].Reason);
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c"], ["lib/b", "lib/c"]), script.RequestedFolders);
    }
    #endregion

    #region Methods: a folder whose graph was not analysed has SSA NotRun
    public static TheoryData<string, FolderOutcome, string> GraphNotAnalyzed() => new()
    {
        // how, the graph outcome, a's SSA reason
        { "nothing loads", FolderOutcome.NothingLoaded, "the folder's graph was not built, so it has no sink sites" },
        { "the worker dies on it", FolderOutcome.Crashed, "the folder's graph was not analysed (Crashed), so it has no sink sites" },
        { "the worker hangs on it", FolderOutcome.TimedOut, "the folder's graph was not analysed (TimedOut), so it has no sink sites" },
        { "the folder cap leaves it out", FolderOutcome.NotRun, "the folder's graph was not analysed (NotRun), so it has no sink sites" },
        { "no worker can start", FolderOutcome.NotRun, "the folder's graph was not analysed (NotRun), so it has no sink sites" },
    };

    /// <summary>
    /// §4: SSA is asked for, but folder a's graph never reached Analyzed: its SSA is NotRun with the reason, never absent
    /// and never Analyzed (ADR 0030). The worker says so for a folder that loaded nothing; the parent for the rest.
    /// </summary>
    [Theory]
    [MemberData(nameof(GraphNotAnalyzed))]
    public void WorkerV2_GraphNotAnalyzed_SsaNotRun(string how, FolderOutcome graph, string reason)
    {
        using var script = how switch
        {
            "the worker dies on it" => new FakeGraphScript("ssa-notrun").Otherwise("request", "ready", "exit 9"),
            "the worker hangs on it" => new FakeGraphScript("ssa-notrun").Otherwise("request", "ready", "hang"),
            _ => new FakeGraphScript("ssa-notrun").Genuine(),
        };
        var options = how == "the folder cap leaves it out" ? Options(maxFolders: 0) : Options(folderSeconds: how == "the worker hangs on it" ? 2 : 60);
        var launch = how == "no worker can start" ? new GraphWorkerLaunch(null, "there is no graph worker here", GraphWorkerProtocol.Arguments, 0) : script.Launch();

        var report = PackageReachability.Analyze(stage.Small("lib/a"), options, launch);

        var folder = Assert.Single(report.Folders);
        Assert.Equal(graph, folder.Outcome);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, reason), folder.Ssa);
    }
    #endregion

    #region Methods: the SSA circuit breaker, and restart accounting
    public static TheoryData<string, string> ThreeSsaDeaths() => new()
    {
        // what, how the third worker dies in c's SSA phase
        { "three crashes", "exit 9" },
        { "two crashes and a hang", "hang" },
    };

    /// <summary>
    /// Review round 2: after the worker dies or hangs in the SSA phase of 3 folders (InSsa Crashed or TimedOut), the rest run
    /// without SSA. a, b and c each cost a worker in their SSA phase (graphs kept, SSA Crashed or TimedOut); the fourth
    /// worker is sent <c>ssa: null</c> and builds d (Analyzed) and e, whose SSA reads NotRun: d for the breaker, e because
    /// it loaded nothing.
    /// </summary>
    [Theory]
    [MemberData(nameof(ThreeSsaDeaths))]
    public void WorkerV2_ThreeSsaDeaths_TurnSsaOff_ForTheRest(string what, string third)
    {
        using var script = new FakeGraphScript("ssa-breaker")
            .Run(1, "request", "ready", "graph empty", "exit 9")
            .Run(2, "request", "ready", "graph empty", "exit 9")
            .Run(3, "request", "ready", "graph empty", third)
            .Otherwise("request", "ready", "build", "done");

        // A short folder timeout for the hang, but long enough for the fourth worker to build d for real.
        var report = Analyze(script, Options(folderSeconds: third == "hang" ? 8 : 60), stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"), stage.Mechanisms("lib/d"), stage.Small("lib/e"));

        Assert.True(report.Folders.Select(f => f.Outcome).SequenceEqual([FolderOutcome.NothingLoaded, FolderOutcome.NothingLoaded, FolderOutcome.NothingLoaded, FolderOutcome.Analyzed, FolderOutcome.NothingLoaded]),
            $"{what}: {string.Join(", ", report.Folders.Select(f => $"{f.Outcome} ({f.Reason})"))}");
        Assert.Equal(
            [SsaFolderOutcome.Crashed, SsaFolderOutcome.Crashed, third == "hang" ? SsaFolderOutcome.TimedOut : SsaFolderOutcome.Crashed, SsaFolderOutcome.NotRun, SsaFolderOutcome.NotRun],
            report.Folders.Select(f => f.Ssa!.Outcome));
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, "the graph worker died or hung in the SSA phase of 3 folders, so SSA was not run for the rest"), report.Folders[3].Ssa);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, "no assembly of the folder loaded, so it has no sink sites"), report.Folders[4].Ssa);
        Assert.Equal(Runs(["lib/a", "lib/b", "lib/c", "lib/d", "lib/e"], ["lib/b", "lib/c", "lib/d", "lib/e"], ["lib/c", "lib/d", "lib/e"], ["lib/d", "lib/e"]), script.RequestedFolders);
        Assert.Equal([true, true, true, false], Requests(script).Select(r => r.Ssa is not null));
        script.AssertNoOrphans();
    }

    /// <summary>Two SSA-phase deaths keep SSA on: the third worker is still asked for SSA, and c's facts are Analyzed.</summary>
    [Fact]
    public void WorkerV2_TwoSsaDeaths_KeepSsaOn()
    {
        using var script = new FakeGraphScript("ssa-breaker-two")
            .Run(1, "request", "ready", "graph empty", "exit 9")
            .Run(2, "request", "ready", "graph empty", "exit 9")
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options(), stage.Small("lib/a"), stage.Small("lib/b"), stage.Mechanisms("lib/c"));

        Assert.Equal([SsaFolderOutcome.Crashed, SsaFolderOutcome.Crashed, SsaFolderOutcome.Analyzed], report.Folders.Select(f => f.Ssa!.Outcome));
        Assert.Equal(FolderOutcome.Analyzed, report.Folders[2].Outcome);
        Assert.NotEmpty(report.Folders[2].Ssa!.Facts!.Sites);
        Assert.Equal([true, true, true], Requests(script).Select(r => r.Ssa is not null));
    }

    /// <summary>
    /// The SSA byte limit is not a death: two deaths, then the third folder's SSA record over the SSA byte budget. SSA turns
    /// off for that limit, and d reads its reason, not the breaker's.
    /// </summary>
    [Fact]
    public void WorkerV2_AReportsSpentAfterTwoDeaths_IsNotTheThirdDeath()
    {
        var d = stage.Mechanisms("lib/d");
        var limit = Encoding.UTF8.GetByteCount(GraphJson.Of(GraphJson.InProcess(0, "lib/d", [.. d.Select(m => (m.RelativePath, m.FullPath))]))) + 5_000;
        using var script = new FakeGraphScript("ssa-breaker-bytes")
            .Run(1, "request", "ready", "graph empty", "exit 9")
            .Run(2, "request", "ready", "graph empty", "exit 9")
            .Run(3, "request", "ready", "graph empty", $"ssa pad {limit}", "hang")
            .Otherwise("request", "ready", "build", "done");

        var report = Analyze(script, Options() with { MaxReportBytes = limit }, stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"), d);

        Assert.Equal([SsaFolderOutcome.Crashed, SsaFolderOutcome.Crashed, SsaFolderOutcome.NotRun, SsaFolderOutcome.NotRun], report.Folders.Select(f => f.Ssa!.Outcome));
        Assert.Equal($"its SSA record would take the package's SSA records over {limit} bytes, so it was not kept", report.Folders[2].Ssa!.Reason);
        Assert.Equal(FolderOutcome.Analyzed, report.Folders[3].Outcome);
        Assert.Equal($"the package's SSA records reached their limit of {limit} bytes before it was started", report.Folders[3].Ssa!.Reason);
    }

    /// <summary>
    /// <c>GraphWorkerRun.ReadyAt</c> and <c>FailedAt</c>: an InSsa failure has both, <c>FailedAt</c> after <c>ReadyAt</c>; a
    /// complete run and a graph-phase crash have <c>ReadyAt</c> and no <c>FailedAt</c>; a run that never got <c>ready</c> has
    /// neither.
    /// </summary>
    [Fact]
    public void OneRun_ReadyAtAndFailedAt_AreSetExactlyWhenTheyHappened()
    {
        using var inSsa = new FakeGraphScript("ssa-at-inssa").Otherwise("request", "ready", "graph empty", "exit 9");
        using var complete = new FakeGraphScript("ssa-at-complete").Empty();
        using var inGraph = new FakeGraphScript("ssa-at-graph").Otherwise("request", "ready", "exit 9");
        using var noReady = new FakeGraphScript("ssa-at-noready").Otherwise("request", "exit 5");
        var request = SsaRequest(("lib/a", stage.Small("lib/a")));
        var before = Stopwatch.GetTimestamp();

        var died = GraphWorkerProcess.Run(inSsa.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue);
        var done = GraphWorkerProcess.Run(complete.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue);
        var crashed = GraphWorkerProcess.Run(inGraph.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue);
        var refused = GraphWorkerProcess.Run(noReady.Launch(), request, TimeSpan.FromSeconds(60), long.MaxValue);

        Assert.True(died.InSsa);
        Assert.True(died.ReadyAt > before, $"ReadyAt {died.ReadyAt}");
        Assert.True(died.FailedAt > died.ReadyAt, $"FailedAt {died.FailedAt}, ReadyAt {died.ReadyAt}");
        Assert.True(died.FailedAt <= Stopwatch.GetTimestamp());
        Assert.Null(done.Failure);
        Assert.True(done.ReadyAt > died.FailedAt);
        Assert.Equal(0, done.FailedAt);
        Assert.Equal((GraphWorkerFailureKind.Crashed, false, 0L), (crashed.Failure!.Value, crashed.InSsa, crashed.FailedAt));
        Assert.True(crashed.ReadyAt > done.ReadyAt);
        Assert.Equal((GraphWorkerFailureKind.NotStarted, 0L, 0L), (refused.Failure!.Value, refused.ReadyAt, refused.FailedAt));
    }

    /// <summary>
    /// Restart accounting across several restarts: each restart an SSA death forces (from <c>FailedAt</c> to the next
    /// worker's <c>ReadyAt</c>) is SSA's time, credited inside the restarted run and carried on through <c>SsaTicks</c>.
    /// Package budget 9 s. a dies in its SSA phase; the second worker takes 5 s to send <c>ready</c>, answers b's graph,
    /// and dies in b's SSA phase; the third takes 4 s before <c>ready</c> and answers c at about 12 s, past the budget plus
    /// SSA's own waiting. Every graph is answered.
    /// </summary>
    [Fact]
    public void WorkerV2_ARestartAfterAnSsaDeath_DoesNotSpendTheGraphsBudget_ForTheRunsAfterIt()
    {
        using var script = new FakeGraphScript("ssa-restart-later")
            .Run(1, "request", "ready", "graph empty", "exit 9")
            .Run(2, "request", "sleep 5000", "ready", "graph empty", "exit 9")
            .Run(3, "request", "sleep 4000", "ready", "empty", "done");

        var report = Analyze(script, Options(packageSeconds: 9), stage.Small("lib/a"), stage.Small("lib/b"), stage.Small("lib/c"));

        Assert.True(report.Folders.All(f => f.Outcome == FolderOutcome.NothingLoaded), string.Join(", ", report.Folders.Select(f => $"{f.Outcome} ({f.Reason})")));
        Assert.Equal([SsaFolderOutcome.Crashed, SsaFolderOutcome.Crashed], report.Folders.Take(2).Select(f => f.Ssa!.Outcome));
        // c's ssa record comes after SSA's own budget (9 s, never moved back), so it is TimedOut for it, or NotRun when the
        // record was already queued when the parent looked.
        Assert.Contains(report.Folders[2].Ssa!.Outcome, new[] { SsaFolderOutcome.NotRun, SsaFolderOutcome.TimedOut });
        Assert.Equal(3, script.Pids.Length);
    }

    /// <summary>
    /// The case the review asked for: a's SSA phase dies, and the restarted worker takes 5 s to send <c>ready</c>, which with
    /// a 4 s package budget ends past the budget. The restart is SSA's time, so b's graph is still answered.
    /// <para>Found by this test against the round-2 src: the credit came only after the restarted run returned, so its ready
    /// wait was cut to the unmoved deadline and b (and every folder after it) read NotRun. Now the restarted run is passed
    /// <c>restartedFrom</c>, waits for <c>ready</c> on the ready clock alone, and moves its own deadline back on <c>ready</c>.</para>
    /// </summary>
    [Fact]
    public void WorkerV2_ARestartAfterAnSsaDeath_DoesNotSpendTheGraphsBudget_ForTheNextFolder()
    {
        using var script = new FakeGraphScript("ssa-restart-next")
            .Run(1, "request", "ready", "graph empty", "exit 9")
            .Otherwise("request", "sleep 5000", "ready", "empty", "done");

        var report = Analyze(script, Options(packageSeconds: 4), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.True(report.Folders[1].Outcome == FolderOutcome.NothingLoaded, $"b is {report.Folders[1].Outcome} ({report.Folders[1].Reason})");
        Assert.Equal(SsaFolderOutcome.Crashed, report.Folders[0].Ssa!.Outcome);
        Assert.Equal(2, script.Pids.Length);
    }

    /// <summary>
    /// <c>GraphWorkerProcess.Run</c> with <c>restartedFrom</c>: a worker that takes 3 s to send <c>ready</c>, against a graph
    /// deadline 1 s away, is waited for on the ready clock alone; on <c>ready</c> the run moves its deadline back by the time
    /// since <c>restartedFrom</c>, so its folder is answered, and that span is in <c>SsaTicks</c>. The control, the same
    /// worker and deadline with no <c>restartedFrom</c>, is NotStarted with the wait cut to the deadline and no SSA time.
    /// </summary>
    [Fact]
    public void OneRun_RestartedFrom_WaitsPastTheGraphDeadlineForReady_AndCountsTheRestartAsSsaTime()
    {
        using var restarted = new FakeGraphScript("ssa-restarted-from").Otherwise("request", "sleep 3000", "ready", "empty", "done");
        using var control = new FakeGraphScript("ssa-restarted-control").Otherwise("request", "sleep 3000", "ready", "empty", "done");
        var request = GraphJson.Request(("lib/a", stage.Small("lib/a")));

        var failedAt = Stopwatch.GetTimestamp();
        var run = GraphWorkerProcess.Run(restarted.Launch(), request, TimeSpan.FromSeconds(60), failedAt + Stopwatch.Frequency, restartedFrom: failedAt);
        var cut = GraphWorkerProcess.Run(control.Launch(), request, TimeSpan.FromSeconds(60), Stopwatch.GetTimestamp() + Stopwatch.Frequency);

        Assert.True(run.Failure is null, $"{run.Failure}: {run.Reason}");
        Assert.Single(run.Answered);
        Assert.True(run.ReadyAt - failedAt >= 2 * Stopwatch.Frequency, $"ready came {Stopwatch.GetElapsedTime(failedAt, run.ReadyAt).TotalSeconds:F2} s after the failure");
        Assert.True(run.SsaTicks >= run.ReadyAt - failedAt, $"SsaTicks {run.SsaTicks}, restart {run.ReadyAt - failedAt}");
        Assert.Equal(0, run.FailedAt);
        Assert.Equal(GraphWorkerFailureKind.NotStarted, cut.Failure);
        Assert.Contains("sent no 'ready' within ", cut.Reason, StringComparison.Ordinal);
        Assert.Equal((0L, 0L), (cut.SsaTicks, cut.ReadyAt));
    }
    #endregion

    #region Methods: the package budget, and a bad bound
    /// <summary>
    /// Review round 1, W2: SSA's time budget (the package budget again) runs out in folder a's SSA phase. a's SSA is
    /// TimedOut for it, its graph standing; the graph budget is untouched, because SSA's waiting moved its deadline back, so a
    /// fresh worker builds b without SSA (Analyzed, as normal), and b's SSA reads NotRun for the SSA budget.
    /// </summary>
    [Fact]
    public void WorkerV2_BudgetSpentDuringSsa_SsaTimedOut_AndTheRestRunWithoutSsa()
    {
        using var script = new FakeGraphScript("ssa-budget")
            .Run(1, "request", "ready", "graph empty", "hang")
            .Otherwise("request", "ready", "build", "done");
        var clock = Stopwatch.StartNew();

        var report = Analyze(script, Options(folderSeconds: 120, packageSeconds: 8), stage.Small("lib/a"), stage.Mechanisms("lib/b"));

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(60), $"took {clock.Elapsed}");
        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.Analyzed], report.Folders.Select(f => f.Outcome));
        Assert.Equal(new FolderSsa(SsaFolderOutcome.TimedOut, null, "the package's SSA budget ran out while its SSA facts were being extracted, so the worker was killed"), report.Folders[0].Ssa);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, "the package's SSA budget of 8 s was spent before it was started"), report.Folders[1].Ssa);
        var requests = Requests(script);
        Assert.Equal(2, requests.Length);
        Assert.Null(requests[1].Ssa);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// W2, the graph's side: time spent waiting on <c>ssa</c> records moves the graph's deadline back. With a 6 s package
    /// budget, a's SSA phase takes 3 s and b's folder record comes 4 s after it, past 6 s from the start: b's graph is still
    /// answered (NothingLoaded here), never cut by the budget. (b's own SSA may or may not beat SSA's spent budget.) The
    /// margins: the worker's start may take up to 2 s.
    /// </summary>
    [Fact]
    public void WorkerV2_TimeSpentOnSsa_DoesNotSpendTheGraphsBudget()
    {
        using var script = new FakeGraphScript("ssa-later")
            .Run(1, "request", "ready", "graph empty", "sleep 3000", "ssa none", "sleep 4000", "graph empty", "ssa none", "done")
            .Otherwise("request", "ready", "empty", "done");

        var report = Analyze(script, Options(packageSeconds: 6), stage.Small("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.NothingLoaded, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, "the folder's graph was not built, so it has no sink sites"), report.Folders[0].Ssa);
        Assert.Contains(report.Folders[1].Ssa!.Outcome, new[] { SsaFolderOutcome.NotRun, SsaFolderOutcome.TimedOut });
    }

    /// <summary><c>GraphWorkerProcess.Later</c>: no deadline stays none, a negative shift is none, and no shift overflows.</summary>
    [Fact]
    public void Later_MovesADeadlineBack_WithoutOverflow()
    {
        Assert.Equal(1_000L + 500, GraphWorkerProcess.Later(1_000, 500));
        Assert.Equal(1_000L, GraphWorkerProcess.Later(1_000, -500));
        Assert.Equal(long.MaxValue, GraphWorkerProcess.Later(long.MaxValue, 5));
        Assert.Equal(long.MaxValue, GraphWorkerProcess.Later(long.MaxValue - 10, 10));
        Assert.Equal(long.MaxValue, GraphWorkerProcess.Later(long.MaxValue - 10, long.MaxValue));
    }

    /// <summary>
    /// W2: options whose SSA bounds are not valid turn SSA off, never the graph pass. The worker is sent no <c>ssa</c>, the
    /// graphs run as normal, and the analysed folder's SSA reads NotRun naming the bad bounds (the folder that loaded nothing
    /// reads NotRun because it has no sink sites). One start.
    /// </summary>
    [Fact]
    public void WorkerV2_ABadSsaBound_TurnsSsaOff_AndTheGraphsStillRun()
    {
        using var script = new FakeGraphScript("ssa-bad-bound").Otherwise("relay");

        var report = Analyze(script, Options(ssa: SsaFactBounds.Default with { MaxSites = 0 }), stage.Mechanisms("lib/a"), stage.Small("lib/b"));

        Assert.Equal([FolderOutcome.Analyzed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        var off = report.Folders[0].Ssa!;
        Assert.Equal((SsaFolderOutcome.NotRun, (SsaFolderFacts?)null), (off.Outcome, off.Facts));
        Assert.StartsWith("the SSA fact bounds are not valid (", off.Reason, StringComparison.Ordinal);
        Assert.EndsWith("), so SSA was not run", off.Reason, StringComparison.Ordinal);
        Assert.Equal(new FolderSsa(SsaFolderOutcome.NotRun, null, "no assembly of the folder loaded, so it has no sink sites"), report.Folders[1].Ssa);
        Assert.Null(Assert.Single(Requests(script)).Ssa);
    }

    /// <summary>
    /// W2: the worker's own <c>FolderTime</c> backstop is sent at most half of <c>FolderTimeout</c> (at least 1 ms), so it
    /// ends a slow SSA phase before the parent must; a smaller one, or no folder timeout, is sent as it is.
    /// </summary>
    [Theory]
    [InlineData(10.0, 60_000L, 5_000L)]
    [InlineData(60.0, 10_000L, 10_000L)]
    [InlineData(60.0, 30_000L, 30_000L)]
    [InlineData(0.001, 60_000L, 1L)]
    [InlineData(0.0, 60_000L, 60_000L)]
    public void WorkerV2_TheSentFolderTime_IsAtMostHalfTheFolderTimeout(double folderSeconds, long folderTimeMs, long sentMs)
    {
        using var script = new FakeGraphScript("ssa-folder-time").Otherwise("request", "ready", "empty", "done");

        Analyze(script, Options(folderSeconds: folderSeconds, ssa: SsaFactBounds.Default with { FolderTime = TimeSpan.FromMilliseconds(folderTimeMs) }), stage.Small("lib/a"));

        var sent = Assert.Single(Requests(script)).Ssa!;
        Assert.Equal(sentMs, sent.FolderTimeMilliseconds);
        Assert.Equal(GraphWorkerSsaBounds.Of(SsaFactBounds.Default) with { FolderTimeMilliseconds = sentMs }, sent);
    }
    #endregion

    #region Methods: additivity
    /// <summary>
    /// Acceptance 1 on the fixture packages: through the real worker loop, every folder's graph result (outcome, assemblies,
    /// load failures, size, reason, SameAs, and the report serialized by the protocol's context) is byte-identical with SSA
    /// off and with <see cref="SsaFactBounds.Default"/>; only <see cref="FolderReachability.Ssa"/> differs (null, then
    /// present for every folder, Analyzed exactly for the Analyzed graphs).
    /// </summary>
    [Fact]
    public void Additive_FixturePackages_ReportsByteIdenticalSsaOnOff()
    {
        using var offScript = new FakeGraphScript("additive-off").Otherwise("relay");
        using var onScript = new FakeGraphScript("additive-on").Otherwise("relay");
        PackageAssembly[][] folders =
        [
            stage.Mechanisms("lib/net10.0"),
            [stage.Put("lib/net8.0", GraphStage.SharedFixture, GraphStage.Shared)],
            stage.Mechanisms("lib/net9.0"),
            stage.Small("lib/net7.0", "garbage.dll"),
            [stage.Put("lib/net6.0", GraphStage.MechanismDependency, GraphStage.Dependency), stage.Put("lib/net6.0", "native.dll", NupkgBuilder.NotManagedBytes)],
            [stage.Put("lib/netstandard2.0", GraphStage.HostStubsFixture, GraphStage.HostStubs)],
        ];

        var off = Analyze(offScript, Options(on: false), folders);
        var on = Analyze(onScript, Options(), folders);

        Assert.Equal(off.Folders.Select(GraphJson.GraphOf), on.Folders.Select(GraphJson.GraphOf));
        Assert.Equal(4, off.Folders.Count(f => f.Outcome == FolderOutcome.Analyzed && f.SameAs is null));   // not vacuous
        Assert.Contains(off.Folders, f => f.SameAs is not null);
        Assert.All(off.Folders, f => Assert.Null(f.Ssa));
        Assert.All(on.Folders, f => Assert.Equal(f.Outcome == FolderOutcome.Analyzed ? SsaFolderOutcome.Analyzed : SsaFolderOutcome.NotRun, f.Ssa!.Outcome));
        Assert.Contains(on.Folders, f => f.Ssa!.Facts is { Sites.Count: > 0 });
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => stage.Dispose();

    // The line bytes of the fake's "nothing loaded" folder record and its ssa record for a lib/<letter> folder holding one
    // a.dll at a one-digit index, measured through the parent itself.
    private (long Folder, long Ssa) RecordBytes()
    {
        using var off = new FakeGraphScript("ssa-record-size-off").Empty();
        using var on = new FakeGraphScript("ssa-record-size-on").Empty();
        var folder = stage.Small("lib/z");
        var graphOnly = GraphWorkerProcess.Run(off.Launch(), GraphJson.Request(("lib/z", folder)), TimeSpan.FromSeconds(60), long.MaxValue);
        var both = GraphWorkerProcess.Run(on.Launch(), SsaRequest(("lib/z", folder)), TimeSpan.FromSeconds(60), long.MaxValue);
        Assert.Null(graphOnly.Failure);
        Assert.Null(both.Failure);
        Assert.Single(both.Ssa);
        Assert.Equal(graphOnly.AnsweredBytes, both.AnsweredBytes);   // ssa bytes are counted apart
        Assert.True(both.SsaBytes > 50, $"an ssa record of {both.SsaBytes} bytes");
        return (graphOnly.AnsweredBytes, both.SsaBytes);
    }

    private static GraphWorkerRequest SsaRequest(params (string Folder, PackageAssembly[] Members)[] folders) =>
        GraphJson.Request(folders) with { Ssa = GraphWorkerSsaBounds.Of(SsaFactBounds.Default) };

    // The requests the fake was sent, parsed by the protocol's context.
    private static GraphWorkerRequest[] Requests(FakeGraphScript script) =>
        [.. GraphFiles.Lines(script.RequestLog).Select(l => JsonSerializer.Deserialize(l, GraphWorkerJsonContext.Default.GraphWorkerRequest)!)];

    // SSA on with `ssa` (the default bounds when null), or off with `on` false; the package options as GraphWorkerParentTests
    // sets them.
    private static PackageReachabilityOptions Options(double folderSeconds = 60, double packageSeconds = 300, int maxFolders = 256, SsaFactBounds? ssa = null, bool on = true) =>
        PackageReachabilityOptions.Default with
        {
            FolderTimeout = TimeSpan.FromSeconds(folderSeconds),
            PackageBudget = TimeSpan.FromSeconds(packageSeconds),
            MaxFolders = maxFolders,
            WorkerMemoryBytes = 0,
            Ssa = ssa ?? (on ? SsaFactBounds.Default : null),
        };

    private static PackageReachabilityReport Analyze(FakeGraphScript script, PackageReachabilityOptions options, params PackageAssembly[][] folders) =>
        PackageReachability.Analyze(folders.SelectMany(f => f), options, script.Launch());

    private static string[][] Runs(params string[][] runs) => runs;
    #endregion

    #region Fields
    private readonly GraphStage stage;
    #endregion
}
