#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

using static FakeWorkerScript;

/// <summary>
/// <see cref="YaraXWorkerScanner"/>, the parent of the YARA-X worker (ADR 0033 FINAL FORM; task T4 and the FR round of
/// <c>docs/agent/tasks/yarax-worker.md</c>), driven through its internal test constructor against the FakeYaraProbe's
/// scripted <c>--fake-worker</c> role. The invariant under test: <b>a file not provably scanned by a genuine worker is
/// unscanned, reported through <see cref="YaraScanIncompleteException"/> with every hit that WAS genuinely reported
/// (ADR 0032), and never clean.</b>
///
/// <para>Covered here: G1 (a run's results are used only after a genuine <c>ready</c>: engine, canary, rule count, hash
/// shape and value, <c>ruleSourceErrors</c> = 0), the clocks (startup bound, the per-record backstop, the bounded wait
/// for exit after <c>done</c> and amendment (f)'s exit code), <c>fatal</c> at every point (b, G5), the G4 output budget,
/// broken streams, and the canary-prefix filter. Every scenario ends with the orphan check: no worker this scanner
/// started is still running.</para>
/// </summary>
public sealed class YaraXWorkerScannerProtocolTests
{
    #region Methods: G1, a genuine ready
    // (what, the ready line, a fragment of the reason the parent gives). Every one of these must make the worker
    // untrusted: amendment (c) and G1, with the hash compared to the parent's OWN recomputation (G9).
    public static TheoryData<string, string, string> NotGenuineReadies() => new()
    {
        { "the T1 stub", Ready(engine: "stub", canary: "skipped", ruleCount: 0, sha: ""), "its engine is 'stub', not 'yara-x'" },
        { "another engine", Ready(engine: "yara"), "its engine is 'yara', not 'yara-x'" },
        { "an engine in another case", Ready(engine: "YARA-X"), "its engine is 'YARA-X', not 'yara-x'" },
        { "a skipped canary", Ready(canary: "skipped"), "its canary is 'skipped', not 'passed'" },
        { "a failed canary", Ready(canary: "failed"), "its canary is 'failed', not 'passed'" },
        { "a canary in another case", Ready(canary: "Passed"), "its canary is 'Passed', not 'passed'" },
        { "no rules", Ready(ruleCount: 0), "it announced 0 rules" },
        { "an upper-case hash", Ready(sha: Expected.ToUpperInvariant()), "its rulesSha256 is not 64 lower-case hex digits" },
        { "a 63-digit hash", Ready(sha: Expected[..63]), "its rulesSha256 is not 64 lower-case hex digits" },
        { "a 65-digit hash", Ready(sha: Expected + "0"), "its rulesSha256 is not 64 lower-case hex digits" },
        { "a non-hex hash", Ready(sha: new string('g', 64)), "its rulesSha256 is not 64 lower-case hex digits" },
        { "an empty hash", Ready(sha: ""), "its rulesSha256 is not 64 lower-case hex digits" },
        { "another ruleset's hash", Ready(sha: new string('a', 64)), $"its rules (sha256 {new string('a', 64)}) are not this build's embedded rules (sha256 {Expected})" },
        { "one rule source with errors", Ready(ruleSourceErrors: 1), "1 of its rule sources had compile errors" },
        { "seven rule sources with errors", Ready(ruleSourceErrors: 7), "7 of its rule sources had compile errors" },
    };

    [Theory]
    [MemberData(nameof(NotGenuineReadies))]
    public void Available_WhenTheProbesReadyIsNotGenuine_IsFalse_WithTheReasonWarned(string what, string ready, string reason)
    {
        using var script = new FakeWorkerScript("g1-probe").Run(1, "out " + ready, "readall", "done").GenuineThroughout();
        using var tree = new ScanTree("g1-probe");
        tree.Write("a.bin");
        using var warnings = new WarningCapture();
        using var scanner = script.Scanner();

        Assert.False(scanner.Available, what);

        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X worker scanning UNAVAILABLE", StringComparison.Ordinal));
        Assert.Contains($"the worker is not a genuine YARA-X worker for this build ({reason}", warning, StringComparison.Ordinal);
        Assert.Empty(scanner.ScanDirectory(tree.Root));   // the backend has no answer (PackageScanner: Unavailable), and runs no worker
        Assert.Single(script.Pids);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }

    // The probe passed, but THIS run's ready is not genuine: whatever it sends afterwards (here a hit on every file and a
    // clean done) is never used, and every file is unscanned.
    [Theory]
    [MemberData(nameof(NotGenuineReadies))]
    public void ScanDirectory_WhenTheRunsReadyIsNotGenuine_UsesNoneOfItsResults(string what, string ready, string reason)
    {
        using var script = new FakeWorkerScript("g1-run").GenuineProbe().Otherwise("out " + ready, "answer", "done");
        using var tree = new ScanTree("g1-run");
        tree.Write("a.bin");
        tree.Write("b.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available, what);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Empty(ex.PartialFindings);
        Assert.Contains("did not scan 2 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"the worker is not a genuine YARA-X worker for this build ({reason}", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // A malformed or negative count is not even a well-formed ready: the reader refuses it before G1 is asked.
    [Theory]
    [InlineData("-1")]
    [InlineData("\"0\"")]
    public void Available_WhenRuleSourceErrorsIsMalformed_IsFalse(string value)
    {
        using var script = new FakeWorkerScript("g1-shape").Run(1, "out " + Ready().Replace("\"ruleSourceErrors\":0", "\"ruleSourceErrors\":" + value), "readall", "done");
        using var warnings = new WarningCapture();
        using var scanner = script.Scanner();

        Assert.False(scanner.Available);
        Assert.Contains(warnings.Warnings, w => w.Contains("broke protocol v1", StringComparison.Ordinal));
        script.AssertNoOrphans();
    }

    [Fact]
    public void Available_WhenTheReadyHasNoRuleSourceErrors_IsFalse()
    {
        using var script = new FakeWorkerScript("g1-missing").Run(1, "out " + Ready().Replace(",\"ruleSourceErrors\":0", ""), "readall", "done");
        using var scanner = script.Scanner();

        Assert.False(scanner.Available);
        script.AssertNoOrphans();
    }

    // The control: a genuine worker IS trusted, and its hits are attributed to the files they were reported for.
    [Fact]
    public void ScanDirectory_WithAGenuineWorker_ReturnsEveryHitAgainstItsFile()
    {
        using var script = new FakeWorkerScript("genuine").GenuineThroughout();
        using var tree = new ScanTree("genuine");
        var files = new[] { tree.Write("a.bin"), tree.Write(@"sub\b.bin"), tree.Write(@"sub\deeper\c.bin") };
        using var scanner = script.Scanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal(files.Order(StringComparer.Ordinal), hits.Select(h => h.FullPath).Order(StringComparer.Ordinal));
        Assert.All(hits, h => Assert.Equal("hit:" + Path.GetFileName(h.FullPath), h.Match.Rule));
        Assert.All(hits, h => Assert.Equal("default", h.Match.Namespace));
        Assert.Equal(files.Order(StringComparer.Ordinal), script.SentPaths.Order(StringComparer.Ordinal));
        Assert.Equal(2, script.Pids.Length);
        script.AssertNoOrphans();
    }

    // End to end through PackageScanner: a non-genuine run is Unavailable with no findings, never Completed.
    [Fact]
    public void PackageScanner_WhenTheRunIsNotGenuine_IsUnavailable_WithNoFindings()
    {
        using var script = new FakeWorkerScript("g1-pkg").GenuineProbe().Otherwise("out " + Ready(engine: "stub"), "answer", "done");
        using var dir = new YaraXTempDir("g1-pkg");
        var nupkg = Nupkg(dir, "SilvergunG1Package");
        using var scanner = script.Scanner();

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: scanner);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: clocks
    // G9's startup bound: no ready within it (here a 1 s seam; the worker sleeps 5 s first) means the probe kills it.
    [Fact]
    public void Available_WhenReadyIsSlowerThanTheStartupBound_KillsTheWorker_AndIsFalse()
    {
        using var script = new FakeWorkerScript("slow-ready").Run(1, "sleep 5000", "out " + Ready(), "readall", "done");
        using var warnings = new WarningCapture();
        using var scanner = script.Scanner(readySeconds: 1);

        var clock = Stopwatch.StartNew();
        var available = Bounded(() => scanner.Available);
        clock.Stop();

        Assert.False(available);
        Assert.Contains(warnings.Warnings, w => w.Contains("the worker sent no 'ready' within 1 s, so it was killed", StringComparison.Ordinal));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(4.5), $"the probe took {clock.Elapsed}: it waited for the slow worker instead of killing it");
        script.AssertNoOrphans();
    }

    // The bound is shared with the probe, which must make it under parallel load: 3 s, against a 10 s sleep.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanDirectory_WhenTheRunsReadyIsSlow_KillsTheWorker_AndEveryFileIsUnscanned()
    {
        using var script = new FakeWorkerScript("slow-ready-run").GenuineProbe().Otherwise("sleep 10000", "out " + Ready(), "answer", "done");
        using var tree = new ScanTree("slow-ready-run");
        tree.Write("a.bin");
        using var scanner = script.Scanner(readySeconds: 3);
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));

        Assert.Contains("sent no 'ready' within 3 s", ex.Message, StringComparison.Ordinal);
        Assert.Empty(ex.PartialFindings);
        script.AssertNoOrphans();
    }

    // The per-record backstop (amendment (g)): after k results the worker hangs. It is killed once nothing has arrived for
    // engine timeout + grace (1 s + 0.5 s here), the k results are partial findings, and the rest are unscanned.
    [Fact]
    public void ScanDirectory_WhenTheWorkerHangsAfterKResults_KillsItAfterTimeoutPlusGrace_KeepingTheK()
    {
        using var script = new FakeWorkerScript("hang").GenuineProbe().Otherwise("out " + Ready(), "answer 2", "hang");
        using var tree = new ScanTree("hang");
        tree.Write("a.bin");
        tree.Write("b.bin");
        tree.Write("c.bin");
        using var scanner = script.Scanner(engineTimeoutSeconds: 1, graceSeconds: 0.5);
        Assert.True(scanner.Available);

        var clock = Stopwatch.StartNew();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));
        clock.Stop();

        Assert.Contains("the worker sent nothing for 1.5 s (its 1 s engine timeout plus grace), so it was killed", ex.Message, StringComparison.Ordinal);
        Assert.True(clock.Elapsed >= TimeSpan.FromSeconds(1.4), $"killed after {clock.Elapsed}, before the bound");
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.All(ex.PartialFindings, p => Assert.Equal("hit:" + Path.GetFileName(p.FullPath), p.Match.Rule));
        Assert.Contains("did not scan 1 of 3 file(s)", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // Amendment (f): after done the parent waits, bounded, for the exit code. A worker that never exits is killed and the
    // run is not vouched for; its results are still real hits.
    [Fact]
    public void ScanDirectory_WhenTheWorkerDoesNotExitAfterDone_KillsIt_AndTheRunIsIncomplete()
    {
        using var script = new FakeWorkerScript("no-exit").GenuineProbe().Otherwise("out " + Ready(), "answer", "done", "hang");
        using var tree = new ScanTree("no-exit");
        tree.Write("a.bin");
        tree.Write("b.bin");
        using var scanner = script.Scanner(exitSeconds: 1.5);
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));

        Assert.Contains("the worker did not exit within 1.5 s of 'done', so it was killed", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        script.AssertNoOrphans();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(-1)]
    public void ScanDirectory_WhenTheWorkerExitsNonZeroAfterDone_IsIncomplete_KeepingTheHits(int exitCode)
    {
        using var script = new FakeWorkerScript("exit-code").GenuineProbe().Otherwise("out " + Ready(), "answer", "done", $"exit {exitCode}");
        using var tree = new ScanTree("exit-code");
        tree.Write("a.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains($"the worker exited with code {exitCode} after 'done'", ex.Message, StringComparison.Ordinal);
        Assert.Equal("hit:a.bin", Assert.Single(ex.PartialFindings).Match.Rule);
        script.AssertNoOrphans();
    }

    // The probe is held to the same rule: done, then a non-zero exit, is not a healthy worker.
    [Fact]
    public void Available_WhenTheProbeExitsNonZeroAfterDone_IsFalse()
    {
        using var script = new FakeWorkerScript("probe-exit").Run(1, "out " + Ready(), "readall", "done", "exit 2");
        using var scanner = script.Scanner();

        Assert.False(scanner.Available);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: fatal at any point (amendments (b), G5)
    [Fact]
    public void ScanDirectory_AFatalBeforeReady_IsIncomplete_WithNoFindings()
    {
        using var script = new FakeWorkerScript("fatal-early").GenuineProbe().Otherwise("out " + Fatal("rules failed to load"), "exit 3");
        using var tree = new ScanTree("fatal-early");
        tree.Write("a.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("the worker reported a fatal error: rules failed to load", ex.Message, StringComparison.Ordinal);
        Assert.Empty(ex.PartialFindings);
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanDirectory_AFatalAfterSomeResults_KeepsThem()
    {
        using var script = new FakeWorkerScript("fatal-mid").GenuineProbe().Otherwise("out " + Ready(), "answer 1", "out " + Fatal("engine crashed"), "exit 3");
        using var tree = new ScanTree("fatal-mid");
        tree.Write("a.bin");
        tree.Write("b.bin");
        tree.Write("c.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("the worker reported a fatal error: engine crashed", ex.Message, StringComparison.Ordinal);
        Assert.Contains("did not scan 2 of 3 file(s)", ex.Message, StringComparison.Ordinal);
        var kept = Assert.Single(ex.PartialFindings);
        Assert.Equal("hit:" + Path.GetFileName(kept.FullPath), kept.Match.Rule);
        script.AssertNoOrphans();
    }

    // G5: every result arrived, but the stream ended in fatal instead of done: the run is not vouched for, and every hit
    // is still reported.
    [Fact]
    public void ScanDirectory_AFatalAfterAllResultsButBeforeDone_IsIncomplete_KeepingEveryHit()
    {
        using var script = new FakeWorkerScript("fatal-g5").GenuineProbe().Otherwise("out " + Ready(), "answer", "out " + Fatal("late"), "exit 3");
        using var tree = new ScanTree("fatal-g5");
        tree.Write("a.bin");
        tree.Write("b.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("cannot be vouched for", ex.Message, StringComparison.Ordinal);
        Assert.Contains("the worker reported a fatal error: late", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        script.AssertNoOrphans();
    }

    [Fact]
    public void Available_WhenTheProbeSendsFatal_IsFalse_WithTheReason()
    {
        using var script = new FakeWorkerScript("fatal-probe").Run(1, "out " + Fatal("engine unavailable: yara_x_capi.dll is not in the application directory"), "exit 3");
        using var warnings = new WarningCapture();
        using var scanner = script.Scanner();

        Assert.False(scanner.Available);
        Assert.Contains(warnings.Warnings, w => w.Contains("fatal error: engine unavailable: yara_x_capi.dll is not in the application directory", StringComparison.Ordinal));
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: G4, the output budget
    // G4: n x (64 KiB + 1) + 1 MiB in total (1,179,650 bytes for n = 2: 2 x 65,537 + 1,048,576; the +1 is each result
    // line's '\n'), whatever the lines hold. Two results of ~1 MB each are individually within the reader's 1 MiB line
    // limit, and the stream ends in a clean done and exit 0: only the budget stands between this and a "complete" run.
    // The first result arrived within budget and is kept.
    [Fact]
    public void ScanDirectory_WhenTheOutputExceedsTheBudget_IsIncomplete_KeepingWhatArrivedWithinIt()
    {
        using var script = new FakeWorkerScript("g4").GenuineProbe().Otherwise("out " + Ready(), "readall", "outbig 0 60", "outbig 1 60", "done");
        using var tree = new ScanTree("g4");
        tree.Write("a.bin");
        tree.Write("b.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));

        Assert.Contains("the worker's output exceeded its 1179650-byte budget, so it was killed", ex.Message, StringComparison.Ordinal);
        Assert.Equal(60, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings.Select(p => p.FullPath).Distinct());
        script.AssertNoOrphans();
    }

    // A worker that writes forever is stopped and killed by a bound, whichever (line or budget) it meets first.
    [Fact]
    public void ScanDirectory_WhenTheWorkerFloodsStdout_KillsIt_AndIsIncomplete()
    {
        using var script = new FakeWorkerScript("flood").GenuineProbe().Otherwise("out " + Ready(), "answer 1", "flood");
        using var tree = new ScanTree("flood");
        tree.Write("a.bin");
        tree.Write("b.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));

        Assert.Single(ex.PartialFindings);
        Assert.Contains("did not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // The exact G4 boundary (polish round, Nit 1). An in-contract worker's largest output for n requests is n result lines
    // of exactly MaxResultLineBytes (65,536) bytes, each plus its '\n', plus the ready and done lines inside the fixed
    // 1 MiB. Here the ready line is padded with JSON whitespace so that ready + done fill that 1 MiB exactly: the whole
    // stream is then EXACTLY n x 65,537 + 1,048,576 bytes, the budget, and the run completes. Without the +1 per line the
    // budget is n bytes short and this run is killed as over budget. (The reader never reads past `done`, so a stream
    // that ends exactly at the budget is never mistaken for one that went past it.)
    [Fact]
    public void ScanDirectory_WhenTheOutputIsExactlyTheBudget_NMaximalResultsAndTheirNewlines_Completes()
    {
        const int n = 4;
        using var script = new FakeWorkerScript("g4-fit").GenuineProbe().Otherwise(BudgetFillingRun(n, extraBytes: 0, out var total));
        using var tree = new ScanTree("g4-fit");
        for (var i = 0; i < n; i++)
            tree.Write($"f{i}.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);
        Assert.Equal(n * (65_536L + 1) + 1_048_576L, total);   // the precondition: the stream is exactly the budget

        var hits = Bounded(() => scanner.ScanDirectory(tree.Root));

        Assert.Empty(hits);   // every file scanned (clean), and the run vouched for: no exception
        Assert.Equal(n, script.SentPaths.Length);
        script.AssertNoOrphans();
    }

    // One byte more than the budget (the same stream, its ready line one space longer) is over it: the run is killed and
    // cannot be vouched for, although every result arrived and the stream ends in a well-formed done.
    [Fact]
    public void ScanDirectory_WhenTheOutputIsOneByteOverTheBudget_IsIncomplete()
    {
        const int n = 4;
        using var script = new FakeWorkerScript("g4-over").GenuineProbe().Otherwise(BudgetFillingRun(n, extraBytes: 1, out var total));
        using var tree = new ScanTree("g4-over");
        for (var i = 0; i < n; i++)
            tree.Write($"f{i}.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);
        Assert.Equal(n * (65_536L + 1) + 1_048_576L + 1, total);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));

        Assert.Contains($"the worker's output exceeded its {n * (65_536L + 1) + 1_048_576L}-byte budget, so it was killed", ex.Message, StringComparison.Ordinal);
        Assert.Contains("cannot be vouched for", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: broken streams
    // (what, the scan run's commands after a genuine ready, the fragment of the reason, how many hits were kept).
    public static TheoryData<string, string[], string, int> BrokenStreams() => new()
    {
        { "a crash mid-stream", ["answer 1", "exit 9"], "the worker's output ended before 'done'; it exited with code 9", 1 },
        { "a truncated line", ["answer 1", "raw {\"type\":\"result\",\"index\":1,\"status\":\"scann"], "truncated line", 1 },
        { "a done count short of n", ["answer", "done 2"], "done count 2 but 3 requests were sent", 3 },
        { "a done count past n", ["answer", "done 4"], "done count 4 but 3 requests were sent", 3 },
        { "a duplicate index", ["answer 1", "out " + Scanned(0, "dup")], "result index 0 out of order (expected 1)", 1 },
        { "an index out of order", ["answer 1", "out " + Scanned(2, "skip")], "result index 2 out of order (expected 1)", 1 },
        { "an index out of range", ["answer 1", "out " + Scanned(3, "far")], "result index 3 out of range 0..2", 1 },
        { "a second ready", ["answer 1", "out " + Ready()], "a second ready", 1 },
        { "an unknown record", ["answer 1", "out {\"type\":\"progress\",\"index\":1}"], "malformed record", 1 },
        { "a result with an unknown field", ["answer 1", "out {\"type\":\"result\",\"index\":1,\"status\":\"scanned\",\"hits\":[],\"x\":1}"], "malformed record", 1 },
    };

    [Theory]
    [MemberData(nameof(BrokenStreams))]
    public void ScanDirectory_ABrokenStream_IsIncomplete_KeepingTheEarlierResults(string what, string[] after, string reason, int kept)
    {
        using var script = new FakeWorkerScript("broken").GenuineProbe().Otherwise(["out " + Ready(), .. after]);
        using var tree = new ScanTree("broken");
        tree.Write("a.bin");
        tree.Write("b.bin");
        tree.Write("c.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available, what);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => Bounded(() => scanner.ScanDirectory(tree.Root)));

        Assert.Contains(reason, ex.Message, StringComparison.Ordinal);
        Assert.Equal(kept, ex.PartialFindings.Count);
        Assert.All(ex.PartialFindings, p => Assert.Equal("hit:" + Path.GetFileName(p.FullPath), p.Match.Rule));
        script.AssertNoOrphans();
    }

    // A non-scanned status for one file costs that file only; the others keep their hits.
    [Theory]
    [InlineData("timeout")]
    [InlineData("error")]
    [InlineData("skipped")]
    public void ScanDirectory_ANonScannedResult_LeavesThatFileUnscanned_WithItsReason(string status)
    {
        using var script = new FakeWorkerScript("status").GenuineProbe().Otherwise(
            "out " + Ready(), "answer 1", $"out {{\"type\":\"result\",\"index\":1,\"status\":\"{status}\",\"reason\":\"why\\nnot\"}}", "skip 1", "answer", "done");
        using var tree = new ScanTree("status");
        tree.Write("a.bin");
        tree.Write("b.bin");
        tree.Write("c.bin");
        using var scanner = script.Scanner();
        Assert.True(scanner.Available);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("did not scan 1 of 3 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"({status}: why\\nnot)", ex.Message, StringComparison.Ordinal);   // the worker's reason, escaped
        Assert.Equal(2, ex.PartialFindings.Count);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: the canary filter
    // The worker strips its own canary by exact name; anything else using the reserved prefix that still reaches the
    // parent is not a detection: dropped (any letter case), with one warning, and the real hits beside it are kept.
    [Fact]
    public void ScanDirectory_DropsHitsUsingTheCanaryPrefix_WithAWarning()
    {
        using var script = new FakeWorkerScript("canary").GenuineProbe().Otherwise(
            "out " + Ready(), "readall", "out " + Scanned(0, "SilvergunCanary_0123456789abcdef0123456789abcdef", "real_rule", "silvergunCANARY_x"), "done");
        using var tree = new ScanTree("canary");
        tree.Write("only.bin");
        using var warnings = new WarningCapture();
        using var scanner = script.Scanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal("real_rule", Assert.Single(hits).Match.Rule);
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("reserved canary prefix", StringComparison.Ordinal));
        Assert.Contains("dropped 2 hit(s)", warning, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanDirectory_WhenOnlyCanaryPrefixedHitsArrive_ReportsNothing_AndStillCompletes()
    {
        using var script = new FakeWorkerScript("canary-only").GenuineProbe().Otherwise(
            "out " + Ready(), "readall", "out " + Scanned(0, "SilvergunCanary_ffffffffffffffffffffffffffffffff"), "done");
        using var tree = new ScanTree("canary-only");
        tree.Write("only.bin");
        using var scanner = script.Scanner();

        Assert.Empty(scanner.ScanDirectory(tree.Root));
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: helpers
    // A scan that must end by itself: a missing backstop would otherwise hang the test run instead of failing it.
    internal static T Bounded<T>(Func<T> scan, int seconds = 30)
    {
        var task = Task.Factory.StartNew(scan, TaskCreationOptions.LongRunning);
        if (Task.WaitAny([task], TimeSpan.FromSeconds(seconds)) < 0)
            Assert.Fail($"the scan did not end within {seconds} s: the parent's backstop did not fire.");
        return task.GetAwaiter().GetResult();
    }

    // A scan run's script whose stdout is: the ready line, padded with JSON whitespace; n clean results of exactly 65,536
    // bytes each (MaxResultLineBytes, the most an in-contract worker sends per file); then done. Ready and done fill the
    // fixed 1 MiB exactly, so the stream is the G4 budget for n requests plus `extraBytes`. `total` is its byte count
    // (every line is ASCII, so chars are bytes; each line's '\n' included).
    private static string[] BudgetFillingRun(int n, int extraBytes, out long total)
    {
        var results = Enumerable.Range(0, n)
            .Select(i => Padded($"{{\"type\":\"result\",\"index\":{i},\"status\":\"scanned\",\"hits\":[]}}", 65_536))
            .ToArray();
        var done = $"{{\"type\":\"done\",\"count\":{n}}}";   // what the fake's `done` writes once it has read n requests
        var ready = Padded(Ready(), 1_048_576 - (done.Length + 1) - 1 + extraBytes);
        total = ready.Length + 1 + results.Sum(r => r.Length + 1L) + done.Length + 1;
        return ["out " + ready, "readall", .. results.Select(r => "out " + r), "done"];
    }

    // `json` (an object) grown to exactly `length` chars by whitespace before its closing brace: the same record.
    private static string Padded(string json, int length)
    {
        Assert.True(json.Length <= length && json[^1] == '}', $"cannot pad a {json.Length}-char record to {length}");
        return json[..^1] + new string(' ', length - json.Length) + "}";
    }

    internal static string Nupkg(YaraXTempDir dir, string id)
    {
        var path = dir.Combine(id + ".nupkg");
        NupkgBuilder.WriteNupkg(path,
        [
            ($"{id}.nuspec", System.Text.Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(id, "1.0.0", "Silvergun Tests", "worker test package", "net8.0", []))),
            ("content/a.bin", [1, 2, 3]),
            ("content/b.bin", [4, 5, 6]),
        ]);
        return path;
    }
    #endregion
}
#endif
