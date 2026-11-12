namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// Runs alone (review round 2, N4). <see cref="GraphWorker.Run"/> watches first-chance exceptions process-wide while it
/// builds, so a parallel test's out-of-memory exception could flip a session here, and this class's injected ones could
/// reach any other in-process session.
/// </summary>
[CollectionDefinition(nameof(GraphWorkerLoopCollection), DisableParallelization = true)]
public sealed class GraphWorkerLoopCollection;

/// <summary>
/// The worker side of graph worker protocol v2 in-process (<see cref="GraphWorker.Run"/> over streams the test owns;
/// <c>docs/agent/tasks/graph-worker.md</c> G1, G2): its folder records are exactly the in-process
/// <see cref="PackageGraphs"/> build plus <see cref="Silvergun.CodeAnalysis.IL.Reachability"/>, a bad request is one
/// <c>fatal</c> and exit 3, and the stdin watchdog fires when stdin ends or carries more after the request.
/// </summary>
[Collection(nameof(GraphWorkerLoopCollection))]
public sealed class GraphWorkerLoopTests : IDisposable
{
    #region Constructors
    public GraphWorkerLoopTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        stage = new GraphStage("loop");
    }
    #endregion

    #region Methods: a genuine session
    /// <summary>
    /// Three folders: the mechanism fixture with its Dependency (a real graph), one of garbage (nothing loads), and one
    /// naming a missing file. The output is <c>ready</c>, one record per folder, <c>done</c>, byte for byte what the
    /// in-process build and analysis serialize to, BOM-free and <c>\n</c>-terminated; exit 0.
    /// </summary>
    [Fact]
    public void Run_AnswersEachFolder_ExactlyAsTheInProcessBuildAndAnalysis()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var garbage = stage.Small("lib/net9.0", "garbage.dll");
        var missing = new PackageAssembly("lib/net8.0/gone.dll", Path.Combine(stage.Root, "lib", "net8.0", "gone.dll"), null, PackageItemRole.Lib, "");
        var request = GraphJson.Request(("lib/net10.0", mechanisms), ("lib/net9.0", garbage), ("lib/net8.0", [missing]));
        using var stdout = new MemoryStream();

        var exit = GraphWorker.Run(Protocol, new MemoryStream(GraphJson.Line(request)), stdout);

        Assert.Equal(GraphWorkerProtocol.ExitDone, exit);
        var expected = request.Folders.Select((f, i) => GraphJson.Of(GraphJson.InProcess(i, f.Folder, [.. f.Assemblies.Select(a => (a.RelativePath, a.FullPath))]))).ToArray();
        Assert.Equal(["{\"type\":\"ready\",\"protocol\":2,\"folders\":3}", .. expected, "{\"type\":\"done\",\"count\":3}"], Lines(stdout));

        var records = Lines(stdout)[1..^1].Select(l => (GraphWorkerFolder)JsonSerializer.Deserialize(l, GraphWorkerJsonContext.Default.GraphWorkerMessage)!).ToArray();
        Assert.NotNull(records[0].Report);
        Assert.True(records[0].Nodes > 0 && records[0].Edges > 0);
        Assert.Equal([.. mechanisms.Select(m => m.RelativePath).Order(StringComparer.Ordinal)], records[0].Assemblies);
        Assert.Null(records[1].Report);
        Assert.Equal("lib/net9.0/garbage.dll", Assert.Single(records[1].LoadFailures).RelativePath);
        Assert.Null(records[2].Report);
        Assert.Equal("lib/net8.0/gone.dll", Assert.Single(records[2].LoadFailures).RelativePath);
    }

    /// <summary>The request's graph budget is the one each folder is built under: a 5-edge budget truncates the graph at 5.</summary>
    [Fact]
    public void Run_BuildsUnderTheRequestsBudget()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var request = GraphJson.Request(("lib/net10.0", mechanisms)) with { Budget = new GraphWorkerBudget(int.MaxValue, 5, long.MaxValue) };
        using var stdout = new MemoryStream();

        Assert.Equal(0, GraphWorker.Run(Protocol, new MemoryStream(GraphJson.Line(request)), stdout));

        var record = (GraphWorkerFolder)JsonSerializer.Deserialize(Lines(stdout)[1], GraphWorkerJsonContext.Default.GraphWorkerMessage)!;
        Assert.Equal(5, record.Edges);
        Assert.True(record.Report!.Graph.Truncated);
        Assert.True(record.Report.Partial);
        Assert.Equal(GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", [.. mechanisms.Select(m => (m.RelativePath, m.FullPath))], new(int.MaxValue, 5, long.MaxValue))), Lines(stdout)[1]);
    }

    /// <summary>A request with no folders is a valid empty session: <c>ready</c> for 0, <c>done</c> 0, exit 0.</summary>
    [Fact]
    public void Run_ARequestWithNoFolders_IsReadyAndDone()
    {
        using var stdout = new MemoryStream();

        Assert.Equal(0, GraphWorker.Run(Protocol, new MemoryStream(GraphJson.Line(GraphJson.Request())), stdout));

        Assert.Equal(["{\"type\":\"ready\",\"protocol\":2,\"folders\":0}", "{\"type\":\"done\",\"count\":0}"], Lines(stdout));
    }
    #endregion

    #region Methods: out of memory
    /// <summary>
    /// Review round 2: any <see cref="OutOfMemoryException"/> raised while a folder is built, even one some catch-all
    /// swallows, fails that folder. The worker answers <c>fatal</c> naming it, never the folder record and never <c>done</c>.
    /// <para>The trigger is deterministic and cheap. The worker watches first-chance exceptions process-wide, so a test thread
    /// throws and catches an OutOfMemoryException every 20 ms while a 12-folder session builds, until <see cref="GraphWorker.Run"/>
    /// returns. This class runs in a collection of its own with parallelization disabled (N4), so no other session sees the
    /// injected exception, and no other test's exception reaches these sessions.</para>
    /// <para>Review round 2, N2: an OS call failing for want of memory counts too, as a <see cref="Win32Exception"/> with
    /// ERROR_COMMITMENT_LIMIT (1455), or any exception whose HResult is E_OUTOFMEMORY (0x8007000E), here an IOException.</para>
    /// </summary>
    [Theory]
    [InlineData("OutOfMemoryException")]
    [InlineData("Win32Exception 1455")]
    [InlineData("IOException 0x8007000E")]
    public async Task Run_AnOutOfMemoryCaughtWhileAFolderIsBuilt_IsFatal_NotAFolderRecord(string injected)
    {
        var exception = Injected(injected);

        var (exit, session) = await RunInjecting(exception);

        Assert.Equal(GraphWorkerProtocol.ExitFatal, exit);
        Assert.Equal($"the folder's graph could not be built: {exception.GetType().Name}: {exception.Message}", FatalReason(session.Stdout.LastLine));
        Assert.True(session.Stdout.Lines < session.Folders + 2, $"the session reached done ({session.Stdout.Lines} lines)");
    }

    /// <summary>
    /// The negative controls: an exception that is not about memory, injected the same way (an access-denied
    /// Win32Exception, a plain IOException), leaves the session alone: every folder record, then <c>done</c>, exit 0.
    /// </summary>
    [Theory]
    [InlineData("Win32Exception 5")]
    [InlineData("IOException")]
    public async Task Run_AnExceptionNotAboutMemory_CaughtWhileAFolderIsBuilt_EndsInDone(string injected)
    {
        var (exit, session) = await RunInjecting(Injected(injected));

        Assert.Equal(GraphWorkerProtocol.ExitDone, exit);
        Assert.Equal($"{{\"type\":\"done\",\"count\":{session.Folders}}}", session.Stdout.LastLine);
        Assert.Equal(session.Folders + 2, session.Stdout.Lines);
    }

    private static Exception Injected(string what) => what switch
    {
        "OutOfMemoryException" => new OutOfMemoryException("injected by the test"),
        "Win32Exception 1455" => new Win32Exception(1455),
        "IOException 0x8007000E" => new IOException("injected by the test", unchecked((int)0x8007000E)),
        "Win32Exception 5" => new Win32Exception(5),
        "IOException" => new IOException("injected by the test"),
        _ => throw new ArgumentOutOfRangeException(nameof(what), what, null),
    };

    // A long session, with `exception` thrown and caught on this thread every 20 ms from `ready` until the session returns.
    private async Task<(int Exit, LongSession Session)> RunInjecting(Exception exception)
    {
        var session = StartLongSession();
        Assert.True(SpinWait.SpinUntil(() => session.Stdout.Lines >= 1, 30_000), "no ready");
        while (!session.Run.IsCompleted)
        {
            try
            {
                throw exception;
            }
            catch (Exception ex) when (ReferenceEquals(ex, exception))
            {
                /* caught at once: only the first-chance notification matters */
            }
            await Task.Delay(20);
        }
        var exit = await session.Run;
        session.Stdin.End();
        return (exit, session);
    }
    #endregion

    #region Methods: bad requests
    private const string Budget = "\"budget\":{\"maxNodes\":1000,\"maxEdges\":1000,\"maxDispatchWork\":1000}";

    public static TheoryData<string, string?, string, string> BadRequests() => new()
    {
        // what, --protocol, stdin, the fatal reason (prefix)
        { "no --protocol", null, "", "missing --protocol; this build speaks 2" },
        { "--protocol 1 (v1, retired)", "1", "", "unsupported protocol '1'; this build speaks 2" },
        { "--protocol 02", "02", "", "unsupported protocol '02'; this build speaks 2" },
        { "an empty --protocol", "", "", "unsupported protocol ''; this build speaks 2" },
        { "no request line", "2", "", "no request line (Eof)" },
        { "a request line without its newline", "2", "{\"protocol\":2", "no request line (Truncated)" },
        { "a request that is not JSON", "2", "not json\n", "the request is not valid JSON for protocol 2: " },
        { "a request with an unknown member", "2", "{\"protocol\":2," + Budget + ",\"folders\":[],\"x\":1}\n", "the request is not valid JSON for protocol 2: " },
        { "a JSON null request", "2", "null\n", "the request is out of contract: it is null" },
        { "protocol 1 in the request", "2", "{\"protocol\":1," + Budget + ",\"folders\":[]}\n", "the request is out of contract: protocol 1, not 2" },
        { "a zero node budget", "2", "{\"protocol\":2,\"budget\":{\"maxNodes\":0,\"maxEdges\":1,\"maxDispatchWork\":1},\"folders\":[]}\n", "the request is out of contract: the graph budget is not positive" },
        { "a negative edge budget", "2", "{\"protocol\":2,\"budget\":{\"maxNodes\":1,\"maxEdges\":-1,\"maxDispatchWork\":1},\"folders\":[]}\n", "the request is out of contract: the graph budget is not positive" },
        { "a zero dispatch budget", "2", "{\"protocol\":2,\"budget\":{\"maxNodes\":1,\"maxEdges\":1,\"maxDispatchWork\":0},\"folders\":[]}\n", "the request is out of contract: the graph budget is not positive" },
        { "a folder with no assemblies", "2", "{\"protocol\":2," + Budget + ",\"folders\":[{\"folder\":\"lib\",\"assemblies\":[]}]}\n", "the request is out of contract: a folder has no assemblies" },
        { "a relative assembly path", "2", "{\"protocol\":2," + Budget + ",\"folders\":[{\"folder\":\"lib\",\"assemblies\":[{\"relativePath\":\"lib/a.dll\",\"fullPath\":\"lib/a.dll\"}]}]}\n", "the request is out of contract: an assembly path is not absolute" },
        { "a drive-relative assembly path", "2", "{\"protocol\":2," + Budget + ",\"folders\":[{\"folder\":\"lib\",\"assemblies\":[{\"relativePath\":\"lib/a.dll\",\"fullPath\":\"C:a.dll\"}]}]}\n", "the request is out of contract: an assembly path is not absolute" },
    };

    /// <summary>Each bad request is exactly one <c>fatal</c> line with its reason, no <c>ready</c>, and exit 3.</summary>
    [Theory]
    [MemberData(nameof(BadRequests))]
    public void Run_ABadRequest_IsOneFatal_AndExitThree(string what, string? protocol, string stdin, string reason)
    {
        using var stdout = new MemoryStream();

        var exit = GraphWorker.Run(protocol, new MemoryStream(Encoding.UTF8.GetBytes(stdin)), stdout);

        Assert.True(exit == GraphWorkerProtocol.ExitFatal, $"{what}: exit {exit}");
        var line = Assert.Single(Lines(stdout));
        Assert.StartsWith(reason, FatalReason(line), StringComparison.Ordinal);
    }

    /// <summary>A hostile --protocol value is escaped and bounded in the reason: still exactly one line, no raw control or bidi character.</summary>
    [Fact]
    public void Run_AHostileProtocolValue_IsEscapedAndBounded()
    {
        using var stdout = new MemoryStream();

        GraphWorker.Run("1\n{\"type\":\"done\",\"count\":0}" + (char)0x202E + new string('x', 1000), new MemoryStream(), stdout);

        var reason = FatalReason(Assert.Single(Lines(stdout)));
        Assert.True(reason.Length <= GraphWorkerProtocol.MaxReasonChars, $"reason is {reason.Length} chars");
        Assert.DoesNotContain(reason, c => c < ' ' || c == (char)0x202E);
        Assert.DoesNotContain(new string('x', 100), reason, StringComparison.Ordinal);
    }

    /// <summary><see cref="GraphWorker.Refuse"/> is one escaped, bounded <c>fatal</c> and exit 3.</summary>
    [Fact]
    public void Refuse_IsOneFatal_AndExitThree()
    {
        using var stdout = new MemoryStream();

        Assert.Equal(GraphWorkerProtocol.ExitFatal, GraphWorker.Refuse(stdout, "bad\nline" + new string('y', 2000)));

        var reason = FatalReason(Assert.Single(Lines(stdout)));
        Assert.StartsWith("bad\\nline", reason, StringComparison.Ordinal);
        Assert.True(reason.Length <= GraphWorkerProtocol.MaxReasonChars);
    }
    #endregion

    #region Methods: the stdin watchdog
    public static TheoryData<string> MidSessionEvents() => ["stdin ends", "a line arrives", "a byte arrives without a newline"];

    /// <summary>
    /// While the session is still running (folders being built, before <c>done</c>), stdin ending or carrying anything more
    /// (a line, or a single byte with no newline) means the parent is gone or has given up: <c>parentGone</c> is called
    /// before <c>done</c>. Until then, with stdin open and silent, it is not.
    /// </summary>
    [Theory]
    [MemberData(nameof(MidSessionEvents))]
    public async Task Watchdog_WhenStdinChangesMidSession_CallsParentGoneBeforeDone(string what)
    {
        var session = StartLongSession();
        Assert.True(SpinWait.SpinUntil(() => session.Stdout.Lines >= 1, 30_000), "no ready");
        Assert.False(session.Gone.Wait(100), $"{what}: parentGone was called while stdin was open and silent");

        switch (what)
        {
            case "stdin ends": session.Stdin.End(); break;
            case "a line arrives": session.Stdin.Feed("{\"protocol\":2}\n"u8.ToArray()); break;
            default: session.Stdin.Feed("x"u8.ToArray()); break;
        }

        Assert.True(session.Gone.Wait(10_000), $"{what}: parentGone was not called");
        Assert.True(session.LinesAtGone < session.Folders + 2, $"{what}: parentGone came only after done ({session.LinesAtGone} lines)");
        session.Stdin.End();
        await session.Run.WaitAsync(TimeSpan.FromSeconds(120));
    }

    /// <summary>
    /// Review N1: once the session is over (<c>done</c> written, <see cref="GraphWorker.Run"/> returned), stdin ending or
    /// carrying more is no news. <c>parentGone</c> is not called, so the CLI's exit 0 is never raced by the watchdog's exit 4.
    /// </summary>
    [Theory]
    [MemberData(nameof(MidSessionEvents))]
    public void Watchdog_AfterDone_StaysQuiet(string what)
    {
        using var stdin = new ControlledStream();
        stdin.Feed(GraphJson.Line(GraphJson.Request()));
        using var stdout = new MemoryStream();
        using var gone = new ManualResetEventSlim();

        Assert.Equal(0, GraphWorker.Run(Protocol, stdin, stdout, gone.Set));
        Assert.EndsWith("{\"type\":\"done\",\"count\":0}", Lines(stdout)[^1], StringComparison.Ordinal);
        switch (what)
        {
            case "stdin ends": stdin.End(); break;
            case "a line arrives": stdin.Feed("{\"protocol\":2}\n"u8.ToArray()); break;
            default: stdin.Feed("x"u8.ToArray()); break;
        }

        Assert.False(gone.Wait(1000), $"{what} after done: parentGone was called");
    }

    /// <summary>The watchdog starts only after a valid request: a fatal session never calls <c>parentGone</c>.</summary>
    [Fact]
    public void Watchdog_ABadRequest_NeverCallsParentGone()
    {
        using var stdin = new ControlledStream();
        stdin.Feed("not json\n"u8.ToArray());
        stdin.End();
        var calls = 0;

        Assert.Equal(GraphWorkerProtocol.ExitFatal, GraphWorker.Run(Protocol, stdin, new MemoryStream(), () => Interlocked.Increment(ref calls)));
        Thread.Sleep(200);

        Assert.Equal(0, calls);
    }

    #endregion

    #region Methods: SSA facts (protocol v2)
    /// <summary>
    /// <c>ssa-facts-s4.md</c> §4, acceptance 2: without <c>ssa</c> bounds (the member absent, or null as the parent writes
    /// it) the records are v1's but for the version: <c>ready</c>, one <c>folder</c> record per folder, byte for byte the
    /// in-process build and analysis, <c>done</c>, and no <c>ssa</c> record.
    /// </summary>
    [Theory]
    [InlineData("absent")]
    [InlineData("null")]
    public void WorkerV2_SsaOff_RecordsIdenticalToV1(string ssa)
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var garbage = stage.Small("lib/net9.0", "garbage.dll");
        var request = GraphJson.Request(("lib/net10.0", mechanisms), ("lib/net9.0", garbage));
        var line = GraphJson.Line(request);
        Assert.Contains("\"ssa\":null", Encoding.UTF8.GetString(line), StringComparison.Ordinal);   // the premise: the parent writes null
        if (ssa == "absent")
        {
            var node = JsonNode.Parse(line)!.AsObject();
            Assert.True(node.Remove("ssa"));
            line = Encoding.UTF8.GetBytes(node.ToJsonString() + "\n");
        }
        using var stdout = new MemoryStream();

        var exit = GraphWorker.Run(Protocol, new MemoryStream(line), stdout);

        Assert.Equal(GraphWorkerProtocol.ExitDone, exit);
        var expected = request.Folders.Select((f, i) => GraphJson.Of(GraphJson.InProcess(i, f.Folder, [.. f.Assemblies.Select(a => (a.RelativePath, a.FullPath))]))).ToArray();
        Assert.Equal(["{\"type\":\"ready\",\"protocol\":2,\"folders\":2}", .. expected, "{\"type\":\"done\",\"count\":2}"], Lines(stdout));
        Assert.DoesNotContain(Lines(stdout), l => l.Contains("\"type\":\"ssa\"", StringComparison.Ordinal));
    }

    /// <summary>
    /// With <c>ssa</c> bounds, each folder record is followed by its <c>ssa</c> record (§4, the child): the mechanism folder's
    /// facts are byte for byte <see cref="SsaSinkFacts.Extract"/> over exactly its loaded files with its sink sites and
    /// <see cref="OwnMembers"/>; a folder whose graph was not built is NotRun with the reason; a folder with no sink site is
    /// Analyzed with empty facts. The folder records are unchanged by SSA (additive).
    /// </summary>
    [Fact]
    public void WorkerV2_SsaRecordFollowsFolder()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var garbage = stage.Small("lib/net9.0", "garbage.dll");
        var stubs = new[] { stage.Put("lib/net8.0", GraphStage.HostStubsFixture, GraphStage.HostStubs) };
        var request = GraphJson.Request(("lib/net10.0", mechanisms), ("lib/net9.0", garbage), ("lib/net8.0", stubs)) with { Ssa = GraphWorkerSsaBounds.Of(SsaFactBounds.Default) };
        using var stdout = new MemoryStream();

        var exit = GraphWorker.Run(Protocol, new MemoryStream(GraphJson.Line(request)), stdout);

        Assert.Equal(GraphWorkerProtocol.ExitDone, exit);
        var lines = Lines(stdout);
        Assert.Equal(8, lines.Length);
        Assert.Equal("{\"type\":\"ready\",\"protocol\":2,\"folders\":3}", lines[0]);
        for (var i = 0; i < 3; i++)
        {
            var f = request.Folders[i];
            Assert.Equal(GraphJson.Of(GraphJson.InProcess(i, f.Folder, [.. f.Assemblies.Select(a => (a.RelativePath, a.FullPath))])), lines[1 + 2 * i]);
        }
        var facts = ExpectedFacts("lib/net10.0", mechanisms, SsaFactBounds.Default);
        Assert.Equal(GraphJson.Of(new GraphWorkerSsa(0, SsaFolderOutcome.Analyzed, facts, null)), lines[2]);
        Assert.Equal(GraphJson.Of(new GraphWorkerSsa(1, SsaFolderOutcome.NotRun, null, "the folder's graph was not built, so it has no sink sites")), lines[4]);
        Assert.Equal(GraphJson.Of(new GraphWorkerSsa(2, SsaFolderOutcome.Analyzed, new SsaFolderFacts([], 0, false, 0, [], false, false, false, 0), null)), lines[6]);
        Assert.Equal("{\"type\":\"done\",\"count\":3}", lines[7]);

        // Not vacuous: the mechanism folder's sink sites are there, each with a status, and the env read's constant is read.
        Assert.NotEmpty(facts.Sites);
        Assert.Equal(facts.Sites.Count, Enum.GetValues<SsaSiteStatus>().Sum(facts.Count));
        Assert.Contains(facts.Sites, s => s.Status == SsaSiteStatus.Analyzed && s.Site.CalleeKey.Contains("GetEnvironmentVariable", StringComparison.Ordinal)
            && s.Arguments is [{ Kind: SsaValueKind.Constant, Constants: [{ Kind: SsaConstantKind.String, Text: "SILVERGUN_MECHANISM_FIXTURE" }] }, ..]);
    }

    /// <summary>
    /// §4: an out-of-memory in the SSA phase (the first-chance watch covers it) ends the session with <c>fatal</c> after the
    /// folder's record, so the parent keeps the graph and reads the SSA Crashed. The OOM is injected only once the folder
    /// record is out, and thrown until the session ends.
    /// </summary>
    [Fact]
    public async Task WorkerV2_OomDuringSsa_IsFatalAfterTheFolderRecord()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var request = GraphJson.Request(("lib/net10.0", mechanisms)) with { Ssa = GraphWorkerSsaBounds.Of(SsaFactBounds.Default) };
        using var stdin = new ControlledStream();
        stdin.Feed(GraphJson.Line(request));
        var stdout = new ConcurrentLineStream();
        var exception = new OutOfMemoryException("injected by the test");

        var run = Task.Run(() => GraphWorker.Run(Protocol, stdin, stdout));
        var clock = Stopwatch.StartNew();
        while (stdout.Lines < 2 && !run.IsCompleted && clock.Elapsed < TimeSpan.FromSeconds(120))
            Thread.SpinWait(20);
        while (!run.IsCompleted)
        {
            try
            {
                throw exception;
            }
            catch (Exception ex) when (ReferenceEquals(ex, exception))
            {
                /* caught at once: only the first-chance notification matters */
            }
        }
        var exit = await run;
        stdin.End();

        Assert.Equal(GraphWorkerProtocol.ExitFatal, exit);
        var lines = stdout.AllLines;
        Assert.Equal(3, lines.Length);
        Assert.Equal(GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", [.. mechanisms.Select(m => (m.RelativePath, m.FullPath))])), lines[1]);
        Assert.Equal("the folder's SSA facts could not be extracted: OutOfMemoryException: injected by the test", FatalReason(lines[2]));
    }

    public static TheoryData<string, string, string> BadSsaBounds() => new()
    {
        // what, the edit to the request's ssa object, the fatal reason (prefix)
        { "maxSites 0", "maxSites=0", NotPositive },
        { "maxArguments -1", "maxArguments=-1", NotPositive },
        { "maxAlternatives 0", "maxAlternatives=0", NotPositive },
        { "maxPhiDepth 0", "maxPhiDepth=0", NotPositive },
        { "maxPhiInputs 0", "maxPhiInputs=0", NotPositive },
        { "maxTextChars 0", "maxTextChars=0", NotPositive },
        { "maxFactTextChars 0", "maxFactTextChars=0", NotPositive },
        { "maxLiftedMethods int.MinValue", "maxLiftedMethods=-2147483648", NotPositive },
        { "maxCandidates 0", "maxCandidates=0", NotPositive },
        { "folderTimeMilliseconds 0", "folderTimeMilliseconds=0", NotPositive },
        { "folderTimeMilliseconds -1", "folderTimeMilliseconds=-1", NotPositive },
        { "folderTimeMilliseconds long.MinValue", "folderTimeMilliseconds=-9223372036854775808", NotPositive },
        { "an unknown member", "extra=1", "the request is not valid JSON for protocol 2: " },
        { "a missing member", "-maxSites", "the request is not valid JSON for protocol 2: " },
        { "a null bound", "maxSites=null", "the request is not valid JSON for protocol 2: " },
        { "a fraction", "maxSites=1.5", "the request is not valid JSON for protocol 2: " },
        { "not an object", "=1", "the request is not valid JSON for protocol 2: " },
    };

    private const string NotPositive = "the request is out of contract: an SSA fact bound is not positive";

    /// <summary>A bad <c>ssa</c> bound is a refusal (§4, as built): one <c>fatal</c>, no <c>ready</c>, exit 3.</summary>
    [Theory]
    [MemberData(nameof(BadSsaBounds))]
    public void WorkerV2_ABadSsaBound_IsOneFatalRefusal(string what, string edit, string reason)
    {
        var request = JsonNode.Parse(GraphJson.Line(GraphJson.Request(("lib/a", stage.Small("lib/a"))) with { Ssa = GraphWorkerSsaBounds.Of(SsaFactBounds.Default) }))!.AsObject();
        var ssa = request["ssa"]!.AsObject();
        if (edit.StartsWith('-'))
            Assert.True(ssa.Remove(edit[1..]));
        else if (edit.StartsWith('='))
            request["ssa"] = JsonNode.Parse(edit[1..]);
        else
            ssa[edit[..edit.IndexOf('=')]] = JsonNode.Parse(edit[(edit.IndexOf('=') + 1)..]);
        using var stdout = new MemoryStream();

        var exit = GraphWorker.Run(Protocol, new MemoryStream(Encoding.UTF8.GetBytes(request.ToJsonString() + "\n")), stdout);

        Assert.True(exit == GraphWorkerProtocol.ExitFatal, $"{what}: exit {exit}");
        var line = Assert.Single(Lines(stdout));
        Assert.StartsWith(reason, FatalReason(line), StringComparison.Ordinal);
    }

    /// <summary>
    /// Review round 1, W1/W4: the SSA phase releases Analysis.Net's statics (<c>AssemblyDisassembler.ReleaseStatics</c>),
    /// so the next folder's graph is built after that. It must be the in-process graph all the same: the mechanism folder,
    /// then the shared fixture, both with SSA, each record byte for byte the in-process build and analysis.
    /// </summary>
    [Fact]
    public void WorkerV2_AGraphAfterAnSsaPhase_IsTheInProcessGraph()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var shared = new[] { stage.Put("lib/net8.0", GraphStage.SharedFixture, GraphStage.Shared) };
        var request = GraphJson.Request(("lib/net10.0", mechanisms), ("lib/net8.0", shared)) with { Ssa = GraphWorkerSsaBounds.Of(SsaFactBounds.Default) };
        using var stdout = new MemoryStream();

        Assert.Equal(GraphWorkerProtocol.ExitDone, GraphWorker.Run(Protocol, new MemoryStream(GraphJson.Line(request)), stdout));

        var lines = Lines(stdout);
        Assert.Equal(6, lines.Length);
        Assert.Equal(GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", [.. mechanisms.Select(m => (m.RelativePath, m.FullPath))])), lines[1]);
        Assert.Equal(GraphJson.Of(GraphJson.InProcess(1, "lib/net8.0", [.. shared.Select(m => (m.RelativePath, m.FullPath))])), lines[3]);
        Assert.All(new[] { lines[2], lines[4] }, l => Assert.Equal(SsaFolderOutcome.Analyzed, ((GraphWorkerSsa)JsonSerializer.Deserialize(l, GraphWorkerJsonContext.Default.GraphWorkerMessage)!).Outcome));
    }

    /// <summary>
    /// <c>AssemblyDisassembler.ReleaseStatics</c> is safe to call repeatedly, and loads after it work: a later
    /// <c>AssemblyDisassembler.Create</c> succeeds, and the same folder's graph and report are byte for byte what they were.
    /// </summary>
    [Fact]
    public void ReleaseStatics_IsSafeRepeatedly_AndLaterLoadsAreUnchanged()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var members = mechanisms.Select(m => (m.RelativePath, m.FullPath)).ToArray();
        var before = GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", members));

        AssemblyDisassembler.ReleaseStatics();
        AssemblyDisassembler.ReleaseStatics();
        AssemblyDisassembler.ReleaseStatics();

        var created = AssemblyDisassembler.Create(mechanisms[1].FullPath);
        Assert.True(created.IsSuccess, created.Message);
        created.Value.Dispose();
        Assert.Equal(before, GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", members)));
        AssemblyDisassembler.ReleaseStatics();
        Assert.Equal(before, GraphJson.Of(GraphJson.InProcess(0, "lib/net10.0", members)));
    }

    /// <summary>W6: <c>GraphWorker.Ssa</c> without a source (no graph) is NotRun, with no session opened.</summary>
    [Fact]
    public void Ssa_WithoutASource_IsNotRun() =>
        Assert.Equal(new GraphWorkerSsa(7, SsaFolderOutcome.NotRun, null, "the folder's graph was not built, so it has no sink sites"),
            GraphWorker.Ssa(7, null, SsaFactBounds.Default));

    /// <summary>
    /// W6: any exception in the SSA phase (here the source's graph already taken, so <c>Take</c> throws) is that folder's
    /// Crashed SSA, never an exception out of the worker: the reason names the exception, within the protocol's reason bound.
    /// </summary>
    [Fact]
    public void Ssa_WhenTheSourceThrows_IsCrashed_WithABoundedReason()
    {
        var source = Source("lib/net10.0", stage.Mechanisms("lib/net10.0"));
        var input = source.Take();
        Assert.NotEmpty(input.Sites);

        var ssa = GraphWorker.Ssa(3, source, SsaFactBounds.Default);

        Assert.Equal((3, SsaFolderOutcome.Crashed, (SsaFolderFacts?)null), (ssa.Index, ssa.Outcome, ssa.Facts));
        Assert.Equal("the SSA phase failed: InvalidOperationException: the folder's graph was already taken", ssa.Reason);
        Assert.True(ssa.Reason!.Length <= GraphWorkerProtocol.MaxReasonChars);
    }

    /// <summary>
    /// W6, the happy path through <c>GraphWorker.Ssa</c> directly: a source's facts are the independently extracted ones, and
    /// <c>Take</c> hands over each folder's loaded paths only (the folder's garbage file is not among them).
    /// </summary>
    [Fact]
    public void Ssa_OverASource_IsAnalyzed_OverExactlyTheLoadedFiles()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var garbage = stage.Put("lib/net10.0", "zz-garbage.dll", "not a portable executable"u8.ToArray());
        PackageAssembly[] members = [.. mechanisms, garbage];

        var ssa = GraphWorker.Ssa(0, Source("lib/net10.0", members), SsaFactBounds.Default);

        Assert.Equal(SsaFolderOutcome.Analyzed, ssa.Outcome);
        Assert.Equal(0, ssa.Facts!.AssembliesLost);
        Assert.Equal(GraphJson.Of(new GraphWorkerSsa(0, SsaFolderOutcome.Analyzed, ExpectedFacts("lib/net10.0", mechanisms, SsaFactBounds.Default), null)), GraphJson.Of(ssa));
        Assert.Equal(mechanisms.Select(m => m.FullPath), Source("lib/net10.0", members).Take().Paths);
    }

    /// <summary>
    /// W4: a Crashed reason names assemblies by package path. <c>SsaSource.Relative</c> maps every absolute path of the
    /// folder (in any letter case, as Windows paths compare) to its package path, longest first, so a path that extends
    /// another is mapped whole.
    /// </summary>
    [Fact]
    public void SsaSource_Relative_NamesAssembliesByPackagePath()
    {
        var a = stage.Put("lib/x", "a.dll", "not a portable executable: a"u8.ToArray());
        var aa = stage.Put("lib/x", "a.dll.dll", "not a portable executable: aa"u8.ToArray());
        var source = Source("lib/x", [stage.Mechanisms("lib/x")[1], a, aa]);

        var text = source.Relative($"could not read '{aa.FullPath}' nor '{a.FullPath.ToUpperInvariant()}'");

        Assert.Equal("could not read 'lib/x/a.dll.dll' nor 'lib/x/a.dll'", text);
        Assert.DoesNotContain(stage.Root, text, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// W6: an <c>ssa</c> record over the writer's line limit is not written; a NotRun record saying so is, whole and alone,
    /// with the same index, so the folder's SSA reads NotRun with why instead of costing the worker.
    /// </summary>
    [Fact]
    public void WriteSsa_ARecordOverTheLineLimit_WritesANotRunRecordInstead()
    {
        var big = new SsaFolderFacts(
            [new SsaSinkFact(new SinkSite("App.C.M()", 1, MethodEdgeKind.Call, "System.IO.File.ReadAllText(System.String)", "System.IO.File.ReadAllText", Capability.FileSystem),
                SsaSiteStatus.Analyzed, null, [SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, new string('x', 4000)))], 1, false, null, null)],
            1, false, 1, [], false, false, false, 0);
        using var stdout = new MemoryStream();

        GraphWorker.WriteSsa(new GraphWorkerWriter(stdout, 2000), new GraphWorkerSsa(5, SsaFolderOutcome.Analyzed, big, null));

        var record = (GraphWorkerSsa)JsonSerializer.Deserialize(Assert.Single(Lines(stdout)), GraphWorkerJsonContext.Default.GraphWorkerMessage)!;
        Assert.Equal((5, SsaFolderOutcome.NotRun, (SsaFolderFacts?)null), (record.Index, record.Outcome, record.Facts));
        Assert.StartsWith("its SSA record could not be written: the record is ", record.Reason, StringComparison.Ordinal);
        Assert.EndsWith("over the protocol's 2000", record.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// W6: a string the writer refuses (a lone surrogate, here in a Crashed reason) is never written raw or replaced: the
    /// fallback NotRun record is written instead, well-formed UTF-8, and says why.
    /// </summary>
    [Fact]
    public void WriteSsa_ALoneSurrogateInTheReason_WritesANotRunRecordInstead()
    {
        var lone = ((char)0xD800).ToString();
        using var stdout = new MemoryStream();

        GraphWorker.WriteSsa(new GraphWorkerWriter(stdout, GraphWorkerProtocol.MaxRecordLineBytes), new GraphWorkerSsa(2, SsaFolderOutcome.Crashed, null, "bad " + lone + " reason"));

        var line = Assert.Single(Lines(stdout));   // Lines decodes strictly: the bytes are well-formed UTF-8
        var record = (GraphWorkerSsa)JsonSerializer.Deserialize(line, GraphWorkerJsonContext.Default.GraphWorkerMessage)!;
        Assert.Equal((2, SsaFolderOutcome.NotRun, (SsaFolderFacts?)null), (record.Index, record.Outcome, record.Facts));
        Assert.StartsWith("its SSA record could not be written: a string is not well-formed UTF-16", record.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(lone, line, StringComparison.Ordinal);
    }

    /// <summary>The control: a record the writer accepts is written as it is.</summary>
    [Fact]
    public void WriteSsa_AWritableRecord_IsWrittenAsItIs()
    {
        var record = new GraphWorkerSsa(1, SsaFolderOutcome.Crashed, null, "the SSA phase failed: X: y");
        using var stdout = new MemoryStream();

        GraphWorker.WriteSsa(new GraphWorkerWriter(stdout, GraphWorkerProtocol.MaxRecordLineBytes), record);

        Assert.Equal([GraphJson.Of(record)], Lines(stdout));
    }

    // A folder's SsaSource as the worker holds it: its graph, and the assemblies that loaded.
    private static GraphWorker.SsaSource Source(string folder, PackageAssembly[] members)
    {
        var built = PackageGraphs.BuildFolder(folder, [.. members.Select(m => (m.RelativePath, m.FullPath))], GraphBudget.Default, CapabilityMap.Default);
        var loaded = built.Assemblies.ToHashSet(StringComparer.Ordinal);
        var request = new GraphWorkerFolderRequest(folder, [.. members.Select(m => new GraphWorkerAssembly(m.RelativePath, m.FullPath))]);
        return new GraphWorker.SsaSource(built.Graph!, request, [.. request.Assemblies.Where(a => loaded.Contains(a.RelativePath))]);
    }

    // The SSA facts the worker must send for one folder: SsaSinkFacts over exactly its loaded files, with its graph's sink
    // sites and own members (ssa-facts-s4.md §4, as built), computed here independently of GraphWorker.
    private static SsaFolderFacts ExpectedFacts(string folder, PackageAssembly[] members, SsaFactBounds bounds)
    {
        var built = PackageGraphs.BuildFolder(folder, [.. members.Select(m => (m.RelativePath, m.FullPath))], GraphBudget.Default, CapabilityMap.Default);
        var graph = built.Graph!;
        var loaded = built.Assemblies.ToHashSet(StringComparer.Ordinal);
        using var session = SsaSession.Open([.. members.Where(m => loaded.Contains(m.RelativePath)).Select(m => m.FullPath)]);
        return SsaSinkFacts.Extract(session, SinkSites.Of(graph, CapabilityMap.Default), bounds, members: OwnMembers.Of(graph));
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => stage.Dispose();

    // A session over 12 copies of the mechanism folder (several seconds of building), started on its own task; parentGone
    // records how many lines had been written when it was called.
    private LongSession StartLongSession()
    {
        var mechanisms = stage.Mechanisms("lib/net10.0");
        var request = GraphJson.Request([.. Enumerable.Range(0, 12).Select(i => ($"lib/f{i}", (PackageAssembly[])mechanisms))]);
        var stdin = new ControlledStream();
        stdin.Feed(GraphJson.Line(request));
        var session = new LongSession(stdin, new ConcurrentLineStream(), new ManualResetEventSlim(), request.Folders.Count);
        session.Run = Task.Run(() => GraphWorker.Run(Protocol, stdin, session.Stdout, () =>
        {
            session.LinesAtGone = session.Stdout.Lines;
            session.Gone.Set();
        }));
        return session;
    }

    private static string[] Lines(MemoryStream stdout)
    {
        var bytes = stdout.ToArray();
        Assert.False(bytes is [0xEF, 0xBB, 0xBF, ..], "stdout starts with a BOM");
        Assert.True(bytes.Length > 0 && bytes[^1] == (byte)'\n', "stdout does not end with a newline");
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes);
        Assert.DoesNotContain('\r', text);
        return text[..^1].Split('\n');
    }

    private static string FatalReason(string line)
    {
        using var doc = JsonDocument.Parse(line);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
        return doc.RootElement.GetProperty("reason").GetString()!;
    }
    #endregion

    #region Fields
    // This build's --protocol value.
    private static readonly string Protocol = GraphWorkerProtocol.Version.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private readonly GraphStage stage;
    #endregion

    #region Nested types
    private sealed class LongSession(ControlledStream stdin, ConcurrentLineStream stdout, ManualResetEventSlim gone, int folders)
    {
        public ControlledStream Stdin { get; } = stdin;
        public ConcurrentLineStream Stdout { get; } = stdout;
        public ManualResetEventSlim Gone { get; } = gone;
        public int Folders { get; } = folders;
        public Task<int> Run { get; set; } = Task.FromResult(0);
        public volatile int LinesAtGone = -1;
    }

    /// <summary>A read-only stream the test feeds chunk by chunk; a read blocks until a chunk arrives or the stream is ended.</summary>
    private sealed class ControlledStream : Stream
    {
        public void Feed(byte[] bytes) => chunks.Add(bytes);

        public void End() => chunks.CompleteAdding();

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (pending.Length == 0)
            {
                if (!chunks.TryTake(out var next, Timeout.Infinite))
                    return 0;
                pending = next;
            }
            var take = Math.Min(count, pending.Length);
            Array.Copy(pending, 0, buffer, offset, take);
            pending = pending[take..];
            return take;
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

        protected override void Dispose(bool disposing)
        {
            if (!chunks.IsAddingCompleted)
                chunks.CompleteAdding();
            base.Dispose(disposing);
        }

        private readonly BlockingCollection<byte[]> chunks = [];
        private byte[] pending = [];
    }

    /// <summary>A write-only stream that counts the <c>\n</c>s written to it and keeps the bytes, readable from another thread.</summary>
    private sealed class ConcurrentLineStream : Stream
    {
        public int Lines => Volatile.Read(ref lines);

        /// <summary>Every complete line written, without its <c>\n</c>.</summary>
        public string[] AllLines
        {
            get
            {
                lock (written)
                    return Encoding.UTF8.GetString(written.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            }
        }

        /// <summary>The last complete line written, without its <c>\n</c> ("" before any).</summary>
        public string LastLine
        {
            get
            {
                lock (written)
                    return Encoding.UTF8.GetString(written.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
            }
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            lock (written)
                written.Write(buffer);
            Interlocked.Add(ref lines, buffer.Count((byte)'\n'));
        }

        private readonly MemoryStream written = new();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        private int lines;
    }
    #endregion
}
