namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;

/// <summary>
/// The worker side of protocol v1 (ADR 0033; <c>docs/agent/tasks/yarax-worker.md</c> T3 and the FR round), over in-memory
/// streams with scripted engines, on every platform: <see cref="YaraWorker.Run(string?, string?, Stream, Stream, Func{int, IYaraWorkerEngine})"/>
/// and <see cref="WorkerPathForm.Verbatim"/>.
///
/// <list type="bullet">
/// <item><b>--timeout</b> (G3, (i), (k), W-D): absent means 30; whole seconds in [2, 3600] reach the engine; anything else
/// is <c>fatal</c>, exit 3, before an engine exists.</item>
/// <item><b>W-C</b>: no exception other than out-of-memory leaves <c>Run</c>. A failure after the arguments are read ends
/// the session with <c>fatal</c> where stdout still takes it, and exit 3 either way; an engine's Dispose cannot change the
/// exit code.</item>
/// <item><b>W3</b>: stdin that cannot be read is <c>fatal</c>, never a <c>done</c> over fewer requests.</item>
/// <item><b>G6 and "G4 vs (h)"</b>: whatever the engine returns, every line is within the contract. A result the contract
/// cannot carry is that file's <c>error</c> (never <c>scanned</c>, never an out-of-contract line), and the next file is
/// still scanned. Checked by reading the worker's output back through the parent's strict reader.</item>
/// <item><b>(e)</b>: a non-scanned result always has a reason ("no reason given" when the engine had none) and no hits.</item>
/// </list>
/// </summary>
public sealed class YaraWorkerLoopTests
{
    #region Methods: --timeout
    [Theory]
    [InlineData(null, 30)]
    [InlineData("2", 2)]
    [InlineData("30", 30)]
    [InlineData("3600", 3600)]
    [InlineData("0002", 2)]
    public void Timeout_InRange_ReachesTheEngine(string? timeout, int expected)
    {
        var created = new List<int>();

        var (exit, outcome) = Run(timeout, [Request(0, @"C:\a.bin")], seconds => { created.Add(seconds); return new Engine(); });

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
        Assert.Equal(new[] { expected }, created);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("3601")]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("+5")]
    [InlineData(" 5")]
    [InlineData("5 ")]
    [InlineData("")]
    [InlineData("99999999999")]
    [InlineData("2147483648")]
    [InlineData("0x10")]
    [InlineData("2.0")]
    [InlineData("1e3")]
    [InlineData("\u0663")]
    public void Timeout_OutOfRangeOrNotWholeSeconds_IsFatalExit3_AndNoEngineIsCreated(string timeout)
    {
        var created = 0;

        var (exit, stdout) = RunRaw(timeout, [Request(0, @"C:\a.bin")], _ => { created++; return new Engine(); });

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.Equal(0, created);
        var reason = SingleFatal(stdout);
        Assert.StartsWith("invalid --timeout '", reason, StringComparison.Ordinal);
        Assert.EndsWith("'; expected whole seconds from 2 to 3600", reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, 30)]
    [InlineData("2", 2)]
    [InlineData("3600", 3600)]
    [InlineData("1", null)]
    [InlineData("3601", null)]
    [InlineData("", null)]
    public void TimeoutSeconds_IsTheOneParser(string? timeout, int? expected) =>
        Assert.Equal(expected, YaraWorker.TimeoutSeconds(timeout));
    #endregion

    #region Methods: W-C, nothing escapes Run
    [Fact]
    public void AnEngineFactoryThatThrows_IsFatalExit3()
    {
        var (exit, stdout) = RunRaw(null, [Request(0, @"C:\a.bin")], _ => throw new InvalidOperationException("no engine\nfor you"));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.Equal("the engine failed to start: InvalidOperationException: no engine\\nfor you", SingleFatal(stdout));
    }

    [Theory]
    [InlineData("InvalidOperationException")]
    [InlineData("IOException")]
    [InlineData("DllNotFoundException")]
    [InlineData("ArgumentException")]
    public void AnEngineStartThatThrows_IsFatalExit3(string type)
    {
        var (exit, stdout) = RunRaw(null, [Request(0, @"C:\a.bin")], _ => new Engine(start: () => throw Make(type)));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.StartsWith($"the engine failed to start: {type}: ", SingleFatal(stdout), StringComparison.Ordinal);
    }

    [Fact]
    public void AnEngineStartThatReturnsANonReadyRecord_IsFatal()
    {
        var (exit, stdout) = RunRaw(null, [], _ => new Engine(start: () => new WorkerDone(0)));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.Equal("the engine answered start with a 'WorkerDone' record", SingleFatal(stdout));
    }

    [Fact]
    public void AnEngineStartThatReturnsNull_IsFatalExit3_WithoutThrowing()
    {
        var (exit, stdout) = RunRaw(null, [], _ => new Engine(start: () => null!));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.StartsWith("the worker failed: ", SingleFatal(stdout), StringComparison.Ordinal);
    }

    // (what, the ready the engine produced). Each is out of contract (c)/(d) and must never reach the parent as a ready.
    public static TheoryData<string> OutOfContractReadies() =>
        new("protocol 2", "a negative rule count", "a negative ruleSourceErrors", "a 257-char engine", "a lone surrogate in the version",
            "a null engine", "a null canary", "a 257-char rulesSha256");

    [Theory]
    [MemberData(nameof(OutOfContractReadies))]
    public void AnOutOfContractReady_IsFatal_NeverSent(string what)
    {
        var good = new WorkerReady(1, "yara-x", "1.22.0", 5, new string('a', 64), "passed");
        var ready = what switch
        {
            "protocol 2" => good with { Protocol = 2 },
            "a negative rule count" => good with { RuleCount = -1 },
            "a negative ruleSourceErrors" => good with { RuleSourceErrors = -1 },
            "a 257-char engine" => good with { Engine = new string('e', 257) },
            "a lone surrogate in the version" => good with { EngineVersion = "1." + (char)0xD800 },
            "a null engine" => good with { Engine = null! },
            "a null canary" => good with { Canary = null! },
            "a 257-char rulesSha256" => good with { RulesSha256 = new string('a', 257) },
            _ => throw new ArgumentOutOfRangeException(nameof(what)),
        };

        var (exit, stdout) = RunRaw(null, [Request(0, @"C:\a.bin")], _ => new Engine(start: () => ready));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.StartsWith("the engine's ready record is out of contract: ", SingleFatal(stdout), StringComparison.Ordinal);
    }

    // The 256-char boundary of a ready string is in contract (and reaches the parent's reader intact).
    [Fact]
    public void AReadyWithA256CharField_IsSent()
    {
        var ready = new WorkerReady(1, new string('e', 256), "1.22.0", 5, new string('a', 64), "passed");

        var (exit, outcome) = Run(null, [], _ => new Engine(start: () => ready));

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        Assert.Equal(ready, outcome.Ready);
    }

    // The writer failing (the pipe broke, the stream refused, or anything else): Run returns 3 and never throws, and when
    // the stream still takes a line after the failure, that line is the fatal.
    [Theory]
    [InlineData("IOException")]
    [InlineData("InvalidOperationException")]
    [InlineData("ArgumentException")]
    [InlineData("ObjectDisposedException")]
    [InlineData("NotSupportedException")]
    public void AWriteThatThrowsOnce_EndsTheSessionWithFatal_WhenStdoutStillAcceptsIt(string type)
    {
        var stdout = new FailingWriteStream(failOnWrite: 2, failures: 1, () => Make(type));   // write 1 = ready, 2 = result 0

        var exit = YaraWorker.Run("1", null, Input(Request(0, @"C:\a.bin"), Request(1, @"C:\b.bin")), stdout, _ => new Engine());

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        var lines = stdout.Lines;
        Assert.Equal(2, lines.Length);
        Assert.StartsWith("{\"type\":\"ready\"", lines[0], StringComparison.Ordinal);
        Assert.StartsWith($"the worker failed: {type}: ", FatalReason(lines[1]), StringComparison.Ordinal);
        Assert.DoesNotContain(lines, l => l.Contains("\"type\":\"done\"", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("IOException")]
    [InlineData("InvalidOperationException")]
    [InlineData("ArgumentException")]
    public void AWriteThatAlwaysThrows_ReturnsTheFatalExitCode_WithoutThrowing(string type)
    {
        var stdout = new FailingWriteStream(failOnWrite: 2, failures: int.MaxValue, () => Make(type));

        var exit = YaraWorker.Run("1", null, Input(Request(0, @"C:\a.bin")), stdout, _ => new Engine());

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.Single(stdout.Lines);   // only the ready got through
    }

    // A serialization failure while WRITING a result (here: a hit list that can be enumerated once, to check it, but not
    // a second time, to serialize it) ends the session as fatal; nothing escapes.
    [Fact]
    public void ASerializationFailureWhileWriting_IsFatalExit3()
    {
        var hits = new OnceOnlyList<WorkerHit>([new WorkerHit("R", "default", [])]);
        var stdout = new MemoryStream();

        var exit = YaraWorker.Run("1", null, Input(Request(0, @"C:\a.bin")), stdout,
            _ => new Engine(scan: r => new WorkerResult(r.Index, WorkerScanStatus.Scanned, Hits: hits)));

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        var lines = Lines(stdout);
        Assert.StartsWith("the worker failed: ", FatalReason(lines[^1]), StringComparison.Ordinal);
        Assert.DoesNotContain(lines, l => l.Contains("\"type\":\"done\"", StringComparison.Ordinal));
    }

    // A serialization failure while CHECKING one file's result (the hit list cannot be enumerated at all) costs that file
    // only: it is an error, and the next file is still scanned.
    [Fact]
    public void ASerializationFailureWhileCheckingAResult_CostsThatFileOnly()
    {
        var (exit, outcome) = Run(null, [Request(0, @"C:\a.bin"), Request(1, @"C:\b.bin")], _ => new Engine(scan: r => r.Index == 0
            ? new WorkerResult(0, WorkerScanStatus.Scanned, Hits: new OnceOnlyList<WorkerHit>([new WorkerHit("R", "default", [])], allowed: 0))
            : Scanned(r.Index)));

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
        Assert.Equal(WorkerScanStatus.Error, outcome.Results[0].Status);
        Assert.Equal(WorkerScanStatus.Scanned, outcome.Results[1].Status);
    }

    [Fact]
    public void AnEngineWhoseDisposeThrows_DoesNotChangeTheExitCode()
    {
        var engine = new DisposableEngine();

        var (exit, outcome) = Run(null, [Request(0, @"C:\a.bin")], _ => engine);

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        Assert.True(outcome.IsComplete, outcome.Terminal.ToString());
        Assert.True(engine.Disposed);
    }

    [Fact]
    public void AnEngineWhoseDisposeThrows_AfterAFatal_StillExits3()
    {
        var engine = new DisposableEngine(start: () => new WorkerFatal("rules failed"));

        var (exit, stdout) = RunRaw(null, [], _ => engine);

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        Assert.Equal("rules failed", SingleFatal(stdout));
        Assert.True(engine.Disposed);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    [InlineData(42)]
    public void AnUndefinedStatus_IsThatFilesError(int status)
    {
        var (exit, outcome) = Run(null, [Request(0, @"C:\a.bin"), Request(1, @"C:\b.bin")],
            _ => new Engine(scan: r => r.Index == 0 ? new WorkerResult(0, (WorkerScanStatus)status, Hits: []) : Scanned(r.Index)));

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        Assert.Equal($"the engine returned an undefined status ({status})", outcome.Results[0].Reason);
        Assert.Equal(WorkerScanStatus.Error, outcome.Results[0].Status);
        Assert.Equal(WorkerScanStatus.Scanned, outcome.Results[1].Status);
    }

    [Fact]
    public void ANullResult_IsThatFilesError()
    {
        var (_, outcome) = Run(null, [Request(0, @"C:\a.bin")], _ => new Engine(scan: _ => null!));

        Assert.Equal((WorkerScanStatus.Error, "the engine returned no result"), (outcome.Results[0].Status, outcome.Results[0].Reason));
    }
    #endregion

    #region Methods: W3, stdin
    [Fact]
    public void StdinThatCannotBeRead_IsFatalExit3_AndNeverDone()
    {
        var stdout = new MemoryStream();

        var exit = YaraWorker.Run("1", null, new ThrowingReadStream(), stdout, _ => new Engine());

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        var lines = Lines(stdout);
        Assert.Equal(2, lines.Length);
        Assert.StartsWith("{\"type\":\"ready\"", lines[0], StringComparison.Ordinal);
        Assert.Equal("could not read the request stream: read failed", FatalReason(lines[1]));
    }

    // Stdin that fails AFTER some requests: their results stand, then fatal, still never done.
    [Fact]
    public void StdinThatFailsMidStream_KeepsTheResultsSoFar_ThenFatal()
    {
        var stdout = new MemoryStream();
        var stdin = new ThrowingReadStream(Encoding.UTF8.GetBytes(Request(0, @"C:\a.bin") + "\n"));

        var exit = YaraWorker.Run("1", null, stdin, stdout, _ => new Engine());

        Assert.Equal(WorkerProtocol.ExitFatal, exit);
        stdout.Position = 0;
        var outcome = new WorkerResponseReader(stdout, 2).ReadToEnd();
        Assert.Equal("could not read the request stream: read failed", Assert.IsType<WorkerStreamTerminal.Fatal>(outcome.Terminal).Reason);
        Assert.Single(outcome.Results);
    }
    #endregion

    #region Methods: G6 and the 64 KiB line
    // (what the engine returned for file 0, whether it may stay `scanned`). File 1 is always a plain hit, which must be
    // scanned whatever happened to file 0.
    public static TheoryData<string, bool> EngineResults() => new()
    {
        { "1,024 hits", true },
        { "1,025 hits", false },
        { "an empty rule name", false },
        { "a null rule name", false },
        { "a 256-char rule", true },
        { "a 257-char rule", false },
        { "a 256-char namespace", true },
        { "a 257-char namespace", false },
        { "an empty namespace", true },
        { "a null namespace", false },
        { "a 256-char tag", true },
        { "a 257-char tag", false },
        { "64 tags", true },
        { "65 tags", false },
        { "a null tag list", false },
        { "a null tag", false },
        { "a null hit", false },
        { "a lone surrogate in a rule", false },
        { "a lone surrogate in a namespace", false },
        { "a lone surrogate in a tag", false },
        { "an astral rule name", true },
        { "scanned with null hits", false },
        { "scanned with a reason", true },
        { "a line of exactly 65,536 bytes", true },
        { "a line of 65,537 bytes", false },
    };

    [Theory]
    [MemberData(nameof(EngineResults))]
    public void WhateverTheEngineReturns_EveryLineIsInContract_AndTheNextFileIsScanned(string what, bool staysScanned)
    {
        var first = FirstResult(what);

        var (exit, outcome) = Run(null, [Request(0, @"C:\a.bin"), Request(1, @"C:\b.bin")],
            _ => new Engine(scan: r => r.Index == 0 ? first : Scanned(1, "next_file_rule")));

        Assert.Equal(WorkerProtocol.ExitDone, exit);
        Assert.True(outcome.IsComplete, $"{what}: the worker wrote an out-of-contract stream: {outcome.Terminal}");
        var result = outcome.Results[0];
        if (staysScanned)
        {
            Assert.Equal(WorkerScanStatus.Scanned, result.Status);
            Assert.Null(result.Reason);
        }
        else
        {
            Assert.Equal(WorkerScanStatus.Error, result.Status);
            Assert.Null(result.Hits);
            Assert.StartsWith("the matches cannot be reported within the protocol's limits, so the file is not reported as scanned: ", result.Reason, StringComparison.Ordinal);
            Assert.True(result.Reason!.Length <= WorkerProtocol.MaxReasonChars);
        }
        Assert.Equal(WorkerScanStatus.Scanned, outcome.Results[1].Status);
        Assert.Equal("next_file_rule", Assert.Single(outcome.Results[1].Hits!).Rule);
    }

    // The fixture's boundary lines really are 65,536 and 65,537 bytes (excluding the \n) as the writer serializes them.
    [Fact]
    public void TheBoundaryResults_SerializeToExactly65536And65537Bytes()
    {
        Assert.Equal(WorkerProtocol.MaxResultLineBytes, LineBytes(FirstResult("a line of exactly 65,536 bytes")));
        Assert.Equal(WorkerProtocol.MaxResultLineBytes + 1, LineBytes(FirstResult("a line of 65,537 bytes")));
        Assert.Equal(65536, WorkerProtocol.MaxResultLineBytes);
    }

    // Amendment (e): a non-scanned result always has a reason, and never hits.
    [Theory]
    [InlineData(WorkerScanStatus.Error, null)]
    [InlineData(WorkerScanStatus.Error, "")]
    [InlineData(WorkerScanStatus.Timeout, null)]
    [InlineData(WorkerScanStatus.Skipped, "")]
    public void ANonScannedResultWithoutAReason_GetsNoReasonGiven_AndLosesItsHits(WorkerScanStatus status, string? reason)
    {
        var (_, outcome) = Run(null, [Request(0, @"C:\a.bin")],
            _ => new Engine(scan: r => new WorkerResult(r.Index, status, reason, [new WorkerHit("would_be_lost", "default", [])])));

        var result = outcome.Results[0];
        Assert.Equal((status, "no reason given"), (result.Status, result.Reason));
        Assert.Null(result.Hits);
    }

    [Fact]
    public void ANonScannedResultsReason_IsEscapedAndBounded_AndItsHitsDropped()
    {
        var (_, outcome) = Run(null, [Request(0, @"C:\a.bin")],
            _ => new Engine(scan: r => new WorkerResult(r.Index, WorkerScanStatus.Timeout, "slow\n" + (char)0x202E + new string('x', 2000), [new WorkerHit("R", "", [])])));

        var result = outcome.Results[0];
        Assert.StartsWith("slow\\n\\u202e", result.Reason, StringComparison.Ordinal);
        Assert.True(result.Reason!.Length <= WorkerProtocol.MaxReasonChars);
        Assert.Null(result.Hits);
    }

    // The engine's own index is never trusted: the result carries the request's.
    [Fact]
    public void AResultIsAlwaysNumberedByItsRequest()
    {
        var (_, outcome) = Run(null, [Request(0, @"C:\a.bin"), Request(1, @"C:\b.bin")], _ => new Engine(scan: _ => new WorkerResult(7, WorkerScanStatus.Error, "x")));

        Assert.Equal(new[] { 0, 1 }, outcome.Results.Select(r => r.Index));
    }
    #endregion

    #region Methods: WorkerPathForm.Verbatim
    public static TheoryData<string, string> AcceptedPaths() => new()
    {
        { @"C:\a", @"\\?\C:\a" },
        { @"c:\a\b.bin", @"\\?\c:\a\b.bin" },
        { @"Z:\dir\nul.txt", @"\\?\Z:\dir\nul.txt" },
        { @"C:\dir\CON", @"\\?\C:\dir\CON" },
        { @"C:\dir\aux\lpt1.d", @"\\?\C:\dir\aux\lpt1.d" },
        { @"C:\dir\foo.\bar ", @"\\?\C:\dir\foo.\bar " },
        { @"C:\a\...\b", @"\\?\C:\a\...\b" },
        { @"\\srv\share\f", @"\\?\UNC\srv\share\f" },
        { @"\\srv\share\dir\f.bin", @"\\?\UNC\srv\share\dir\f.bin" },
        { @"\\srv.example\share$\f", @"\\?\UNC\srv.example\share$\f" },
    };

    [Theory]
    [MemberData(nameof(AcceptedPaths))]
    public void Verbatim_AcceptsTheProtocolsForm_AndPrefixesItLexically(string path, string expected) =>
        Assert.Equal(expected, WorkerPathForm.Verbatim(path, windows: true));

    [Fact]
    public void Verbatim_AcceptsASurrogatePair() =>
        Assert.Equal(@"\\?\C:\a\" + char.ConvertFromUtf32(0x1F600) + ".bin", WorkerPathForm.Verbatim(@"C:\a\" + char.ConvertFromUtf32(0x1F600) + ".bin", windows: true));

    // Named cases, built in code: NUL and lone surrogates must not travel through the test runner's serializer.
    public static TheoryData<string> RejectedPaths() => new(RejectedPathCases.Keys);

    [Theory]
    [MemberData(nameof(RejectedPaths))]
    public void Verbatim_RejectsEverythingElse(string what) =>
        Assert.Null(WorkerPathForm.Verbatim(RejectedPathCases[what], windows: true));
    #endregion

    #region Methods: WorkerPathForm.Verbatim, the Unix form (docs/agent/tasks/yarax-worker-linux.md, L3)
    // Absolute, '/'-separated, returned unchanged (no prefix). A backslash, a colon and a DOS device name are ordinary
    // name characters on Linux, and so are `...` and dot-prefixed names (only `.` and `..` themselves are segments).
    [Theory]
    [InlineData("/a")]
    [InlineData("/a/b.bin")]
    [InlineData(@"/a/dir\name.bin")]
    [InlineData(@"/a\b\c")]
    [InlineData(@"/C:\a")]
    [InlineData("/a/b:ads")]
    [InlineData("/a/nul.txt")]
    [InlineData("/a/CON")]
    [InlineData("/a/.../b")]
    [InlineData("/a/.hidden")]
    [InlineData("/a/..b/c..")]
    [InlineData("/a/b ")]
    [InlineData("/a/b.")]
    [InlineData("/tmp/silvergun/root/lib/net8.0/x.dll")]
    public void Verbatim_OnUnix_AcceptsTheProtocolsForm_Unchanged(string path) =>
        Assert.Equal(path, WorkerPathForm.Verbatim(path, windows: false));

    [Fact]
    public void Verbatim_OnUnix_AcceptsASurrogatePair()
    {
        var path = "/a/" + char.ConvertFromUtf32(0x1F600) + ".bin";

        Assert.Equal(path, WorkerPathForm.Verbatim(path, windows: false));
    }

    public static TheoryData<string> RejectedUnixPaths() => new(RejectedUnixPathCases.Keys);

    [Theory]
    [MemberData(nameof(RejectedUnixPaths))]
    public void Verbatim_OnUnix_RejectsEverythingElse(string what) =>
        Assert.Null(WorkerPathForm.Verbatim(RejectedUnixPathCases[what], windows: false));

    // The two forms are disjoint where it matters: neither OS's form is accepted as the other's.
    [Theory]
    [InlineData(@"C:\a\b.bin")]
    [InlineData(@"\\srv\share\f")]
    public void Verbatim_OnUnix_RejectsTheWindowsForm(string path) =>
        Assert.Null(WorkerPathForm.Verbatim(path, windows: false));

    [Fact]
    public void Verbatim_OnWindows_RejectsTheUnixForm() =>
        Assert.Null(WorkerPathForm.Verbatim("/a/b.bin", windows: true));

    // The one-argument form is this OS's.
    [Theory]
    [InlineData(@"C:\a\b.bin")]
    [InlineData("/a/b.bin")]
    [InlineData(@"/a/dir\name.bin")]
    public void Verbatim_WithoutAnOs_IsThisOsForm(string path) =>
        Assert.Equal(WorkerPathForm.Verbatim(path, OperatingSystem.IsWindows()), WorkerPathForm.Verbatim(path));
    #endregion

    #region Methods: helpers
    private static WorkerResult FirstResult(string what)
    {
        WorkerHit Hit(string rule = "R", string ns = "default", IReadOnlyList<string>? tags = null) => new(rule, ns, tags ?? []);
        WorkerResult With(params WorkerHit[] hits) => new(0, WorkerScanStatus.Scanned, Hits: hits);
        var lone = (char)0xD800;
        return what switch
        {
            "1,024 hits" => With([.. Enumerable.Range(0, 1024).Select(i => Hit("R" + i))]),
            "1,025 hits" => With([.. Enumerable.Range(0, 1025).Select(i => Hit("R" + i))]),
            "an empty rule name" => With(Hit("")),
            "a null rule name" => With(Hit(null!)),
            "a 256-char rule" => With(Hit(new string('r', 256))),
            "a 257-char rule" => With(Hit(new string('r', 257))),
            "a 256-char namespace" => With(Hit(ns: new string('n', 256))),
            "a 257-char namespace" => With(Hit(ns: new string('n', 257))),
            "an empty namespace" => With(Hit(ns: "")),
            "a null namespace" => With(Hit(ns: null!)),
            "a 256-char tag" => With(Hit(tags: [new string('t', 256)])),
            "a 257-char tag" => With(Hit(tags: [new string('t', 257)])),
            "64 tags" => With(Hit(tags: [.. Enumerable.Range(0, 64).Select(i => "t" + i)])),
            "65 tags" => With(Hit(tags: [.. Enumerable.Range(0, 65).Select(i => "t" + i)])),
            "a null tag list" => With(new WorkerHit("R", "default", null!)),
            "a null tag" => With(Hit(tags: [null!])),
            "a null hit" => new WorkerResult(0, WorkerScanStatus.Scanned, Hits: new WorkerHit[] { Hit(), null! }),
            "a lone surrogate in a rule" => With(Hit("R" + lone)),
            "a lone surrogate in a namespace" => With(Hit(ns: "n" + lone)),
            "a lone surrogate in a tag" => With(Hit(tags: ["t" + lone])),
            "an astral rule name" => With(Hit(string.Concat(Enumerable.Repeat(char.ConvertFromUtf32(0x1F600), 128)))),
            "scanned with null hits" => new WorkerResult(0, WorkerScanStatus.Scanned),
            "scanned with a reason" => new WorkerResult(0, WorkerScanStatus.Scanned, "ignored", [Hit()]),
            "a line of exactly 65,536 bytes" => OfLineBytes(WorkerProtocol.MaxResultLineBytes),
            "a line of 65,537 bytes" => OfLineBytes(WorkerProtocol.MaxResultLineBytes + 1),
            _ => throw new ArgumentOutOfRangeException(nameof(what), what, null),
        };
    }

    // A scanned result (every hit within every per-field limit) whose serialized line is exactly `target` bytes: full
    // 256-char rule names, then the last hit's name sized to land on the target.
    private static WorkerResult OfLineBytes(int target)
    {
        var hits = new List<WorkerHit>();
        WorkerResult Of(IEnumerable<WorkerHit> h) => new(0, WorkerScanStatus.Scanned, Hits: h.ToArray());
        while (LineBytes(Of([.. hits, new WorkerHit(new string('r', 256), "", [])])) <= target)
            hits.Add(new WorkerHit(new string('r', 256), "", []));

        var remaining = target - LineBytes(Of(hits));
        var cost = LineBytes(Of([.. hits, new WorkerHit("r", "", [])])) - LineBytes(Of(hits));   // a hit with a 1-char name
        if (remaining >= cost)
            hits.Add(new WorkerHit(new string('r', 1 + remaining - cost), "", []));
        else
        {
            hits[^1] = new WorkerHit(new string('r', 256 - (cost - remaining)), "", []);
            hits.Add(new WorkerHit("r", "", []));
        }
        return Of(hits);
    }

    private static int LineBytes(WorkerResult result)
    {
        var stream = new MemoryStream();
        new WorkerProtocolWriter(stream).Write(result);
        return (int)stream.Length - 1;
    }

    private static (int Exit, WorkerStreamOutcome Outcome) Run(string? timeout, string[] requests, Func<int, IYaraWorkerEngine> engine)
    {
        var (exit, stdout) = RunRaw(timeout, requests, engine);
        return (exit, new WorkerResponseReader(new MemoryStream(stdout), requests.Length).ReadToEnd());
    }

    private static (int Exit, byte[] Stdout) RunRaw(string? timeout, string[] requests, Func<int, IYaraWorkerEngine> engine)
    {
        var stdout = new MemoryStream();
        var exit = YaraWorker.Run("1", timeout, Input(requests), stdout, engine);
        return (exit, stdout.ToArray());
    }

    private static MemoryStream Input(params string[] requests) => new(Encoding.UTF8.GetBytes(string.Concat(requests.Select(r => r + "\n"))), writable: false);

    private static string Request(int index, string path) => $"{{\"index\":{index},\"path\":{JsonSerializer.Serialize(path)}}}";

    private static WorkerResult Scanned(int index, string rule = "R") => new(index, WorkerScanStatus.Scanned, Hits: [new WorkerHit(rule, "default", [])]);

    private static string[] Lines(MemoryStream stream) => Encoding.UTF8.GetString(stream.ToArray()).TrimEnd('\n').Split('\n');

    private static string SingleFatal(byte[] stdout)
    {
        var text = Encoding.UTF8.GetString(stdout);
        Assert.EndsWith("\n", text, StringComparison.Ordinal);
        return FatalReason(Assert.Single(text[..^1].Split('\n')));
    }

    private static string FatalReason(string line)
    {
        using var doc = JsonDocument.Parse(line);
        Assert.Equal("fatal", doc.RootElement.GetProperty("type").GetString());
        return doc.RootElement.GetProperty("reason").GetString()!;
    }

    private static Exception Make(string type) => type switch
    {
        "IOException" => new IOException("pipe broke"),
        "InvalidOperationException" => new InvalidOperationException("bad state"),
        "ArgumentException" => new ArgumentException("ill-formed"),
        "ObjectDisposedException" => new ObjectDisposedException("stdout"),
        "NotSupportedException" => new NotSupportedException("no"),
        "DllNotFoundException" => new DllNotFoundException("yara_x_capi.dll"),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, null),
    };
    #endregion

    #region Nested types
    private class Engine(Func<WorkerMessage>? start = null, Func<WorkerRequest, WorkerResult>? scan = null) : IYaraWorkerEngine
    {
        public WorkerMessage Start() => start is null ? new WorkerReady(1, "yara-x", "1.22.0", 5, new string('a', 64), "passed") : start();

        public WorkerResult Scan(WorkerRequest request) => scan is null ? Scanned(request.Index) : scan(request);
    }

    private sealed class DisposableEngine(Func<WorkerMessage>? start = null) : Engine(start), IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
            throw new InvalidOperationException("dispose failed");
        }
    }

    // Enumerable `allowed` times (indexer and Count always work), then every enumeration throws.
    private sealed class OnceOnlyList<T>(IReadOnlyList<T> items, int allowed = 1) : IReadOnlyList<T>
    {
        public T this[int index] => items[index];

        public int Count => items.Count;

        public IEnumerator<T> GetEnumerator() =>
            enumerations++ < allowed ? items.GetEnumerator() : throw new InvalidOperationException("Collection was modified; enumeration operation may not execute.");

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private int enumerations;
    }

    // Records each whole write as a line; the writes numbered failOnWrite.. (1-based, `failures` of them) throw instead.
    private sealed class FailingWriteStream(int failOnWrite, int failures, Func<Exception> make) : Stream
    {
        public string[] Lines => [.. written.Select(b => Encoding.UTF8.GetString(b).TrimEnd('\n'))];

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            writes++;
            if (writes >= failOnWrite && writes < failOnWrite + (long)failures)
                throw make();
            written.Add(buffer.ToArray());
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Flush() { }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        private readonly List<byte[]> written = [];
        private int writes;
    }

    // Serves `prefix`, then every read fails the way a broken pipe does.
    private sealed class ThrowingReadStream(byte[]? prefix = null) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (position < (prefix?.Length ?? 0))
            {
                var n = Math.Min(count, prefix!.Length - position);
                Array.Copy(prefix, position, buffer, offset, n);
                position += n;
                return n;
            }
            throw new IOException("the pipe broke");
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

        private int position;
    }
    #endregion

    #region Fields
    private static readonly Dictionary<string, string?> RejectedPathCases = new()
    {
        ["null"] = null,
        ["empty"] = "",
        ["a drive alone"] = "C:",
        ["a drive root"] = @"C:\",
        ["drive-relative"] = "C:foo",
        ["rooted without a drive"] = @"\foo",
        ["a forward-slash root"] = "/foo",
        ["a forward slash after the drive"] = "C:/a",
        ["a forward slash inside"] = @"C:\a/b",
        ["a NUL"] = @"C:\a" + (char)0 + "b",
        ["a double backslash after the drive"] = @"C:\\a",
        ["an empty segment"] = @"C:\a\\b",
        ["a trailing dot segment"] = @"C:\a\.",
        ["a dot segment"] = @"C:\a\.\b",
        ["a dot-dot segment"] = @"C:\a\..\b",
        ["a trailing dot-dot"] = @"C:\a\..",
        ["a trailing backslash"] = @"C:\a\b\",
        ["an alternate data stream"] = @"C:\a\b:ads",
        ["a ::$DATA stream"] = @"C:\a\b::$DATA",
        ["a colon in a directory"] = @"C:\a:b\c",
        ["UNC with two segments"] = @"\\srv\share",
        ["UNC with one segment"] = @"\\srv",
        ["UNC with a trailing backslash"] = @"\\srv\share\",
        ["UNC with an empty server"] = @"\\\share\f",
        ["UNC with a colon"] = @"\\srv\share\f:ads",
        ["UNC with a dot-dot"] = @"\\srv\share\..\f",
        ["a verbatim prefix"] = @"\\?\C:\a",
        ["a verbatim UNC prefix"] = @"\\?\UNC\srv\share\f",
        ["a device prefix"] = @"\\.\C:\a",
        ["a device pipe"] = @"\\.\pipe\x",
        ["an NT object prefix"] = @"\??\C:\a",
        ["a lone high surrogate"] = @"C:\a" + (char)0xD800,
        ["a lone low surrogate"] = @"C:\a" + (char)0xDC00 + "b",
        ["a reversed surrogate pair"] = @"C:\a" + (char)0xDC00 + (char)0xD800,
        ["a digit for a drive"] = @"1:\a",
        ["two letters for a drive"] = @"CC:\a",
    };

    private static readonly Dictionary<string, string?> RejectedUnixPathCases = new()
    {
        ["null"] = null,
        ["empty"] = "",
        ["the root alone"] = "/",
        ["relative"] = "a/b",
        ["a bare name"] = "b.bin",
        ["dot-relative"] = "./a",
        ["dot-dot-relative"] = "../a",
        ["home-relative"] = "~/a",
        ["a double slash at the root"] = "//a",
        ["an empty segment"] = "/a//b",
        ["a trailing slash"] = "/a/b/",
        ["a dot segment"] = "/a/./b",
        ["a trailing dot segment"] = "/a/.",
        ["a leading dot segment"] = "/./a",
        ["a dot-dot segment"] = "/a/../b",
        ["a trailing dot-dot"] = "/a/..",
        ["a leading dot-dot"] = "/../a",
        ["a NUL"] = "/a" + (char)0 + "b",
        ["a lone high surrogate"] = "/a" + (char)0xD800,
        ["a lone low surrogate"] = "/a" + (char)0xDC00 + "b",
        ["a reversed surrogate pair"] = "/a" + (char)0xDC00 + (char)0xD800,
        ["a backslash root"] = @"\a\b",
    };
    #endregion
}
