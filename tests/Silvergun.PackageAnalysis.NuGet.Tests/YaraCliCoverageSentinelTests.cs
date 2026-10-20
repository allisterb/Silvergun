namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0032 <b>decision 9</b> (task round D) at the classic-CLI backend's seam: <b>coverage is asked for, not
/// inferred.</b> In <c>yara -r</c> mode (4.1.3) <c>--timeout</c> is ONE deadline for the whole run, and every file still
/// queued when it passes is dropped with exit 0 and nothing on stderr — so neither the exit code nor the decision-7
/// stderr check can tell a scanned file from a skipped one. The recursive pass therefore carries a
/// <c>condition: true</c> coverage-sentinel rule (<c>SilvergunCoverageSentinel_</c> + 32 random hex digits, fresh per
/// ruleset); a file with no sentinel line for it was not scanned and is re-scanned individually, the overflow past
/// <c>MaxIndividualScans</c> (64) or the pass budget making the scan incomplete with every hit carried.
///
/// <para><b>The engine is the <c>FakeYaraProbe</c></b> (see <see cref="FakeYaraBinary"/>): like real yara it prints
/// <c>&lt;sentinel&gt; [] &lt;file&gt;</c> for every file it "scans", the name read from the rules file it is handed, and
/// <c>sentinelSkip</c> withholds that line for the files a real run would have dropped at its deadline. Its invocation
/// log records, per launch, whether the rules were compiled and which sentinel (if any) they declared — which is how
/// these tests see which ruleset each launch got.</para>
///
/// <para><b>Deliberately written against API that predates round D</b>: nothing here names
/// <c>YaraCliScanner.SentinelPrefix</c> (the reserved prefix is spelled out below; the constant itself is pinned in
/// <see cref="YaraCliCoverageSentinelApiTests"/>), so this file compiles against the Round C scanner and its
/// coverage tests are shown RED there by assertion — a result that reads complete while missing hits.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliCoverageSentinelTests
{
    #region Methods
    // --- The baseline: every file has its line --------------------------------------------------------------

    // Every file covered ⇒ the one cheap recursive launch and nothing else, and its ruleset declared a sentinel of the
    // reserved shape. The sentinel lines themselves never become hits: exactly the one staged detection comes back.
    [Fact]
    public void ScanDirectory_WhenEveryFileHasACoverageLine_CompletesInOneLaunchWithOnlyTheRealHit()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/readme.txt", "ordinary text\n");
        tree.Write("lib/net8.0/other.dll", "ordinary content\n");
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(Path.Combine(tree.Root, "content", "payload.bin"), hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
        var batch = Assert.Single(fake.Invocations);
        Assert.Equal(tree.Root, Field(batch, "target"));
        Assert.Matches(SentinelShape, Field(batch, "sentinel"));
    }

    // --- Item 1: files without a coverage line are re-scanned, exactly those --------------------------------

    // The defect itself, at its smallest: exit 0, no stderr, two of four files have no coverage line. Before decision 9
    // this read Completed with ONE hit (the batch's) — the two dropped files' payloads silently missing. Now exactly those
    // two are re-scanned on their own (with the PLAIN ruleset: no sentinel), the covered ones are not, and since the
    // re-scans succeed the result is an ordinary complete one carrying all three hits.
    [Fact]
    public void ScanDirectory_WhenSomeFilesHaveNoCoverageLine_ReScansExactlyThoseAndCompletesWithEveryHit()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/covered.bin", "ordinary content\n");
        tree.Write("content/dropped1.bin", "ordinary content\n");
        tree.Write("lib/dropped2.bin", "ordinary content\n");
        var dropped1 = Path.Combine(tree.Root, "content", "dropped1.bin");
        var dropped2 = Path.Combine(tree.Root, "lib", "dropped2.bin");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "dropped1.bin|dropped2.bin");

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal(3, hits.Count);
        Assert.Single(hits, h => h.FullPath == Path.Combine(tree.Root, "content", "payload.bin"));
        Assert.Single(hits, h => h.FullPath == dropped1);
        Assert.Single(hits, h => h.FullPath == dropped2);
        Assert.DoesNotContain(hits, h => IsSentinelName(h.Match.Rule));

        var singles = SingleFileLaunches(fake, tree.Root);
        Assert.Equal(new[] { dropped1, dropped2 }.Order(StringComparer.Ordinal), singles.Select(i => Field(i, "target")).Order(StringComparer.Ordinal));
        Assert.All(singles, i => Assert.Equal("-", Field(i, "sentinel")));   // the plain ruleset: ScanOne gets no sentinel
    }

    // --- Item 2: the overflow is incomplete, carrying the batch AND the individual hits -----------------------

    // More uncovered files than MaxIndividualScans (64): 64 are re-scanned, the other two count as unrecovered, and the
    // exception carries the covered payload's batch hit plus the 64 recovered ones. (A package cannot buy a clean report
    // by being expensive enough to be dropped, nor erase its payload by being dropped in bulk.) Slow: 65 apphost launches.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanDirectory_WhenMoreFilesLackACoverageLineThanTheRecoveryCap_ThrowsCarryingBatchAndIndividualHits()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        for (var i = 0; i < 66; i++)
            tree.Write($"content/drop{i:D2}.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule", sentinelSkip: "drop*");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 2 of 66 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Equal(65, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == Path.Combine(tree.Root, "content", "payload.bin"));
        Assert.Equal(64, ex.PartialFindings.Count(h => Path.GetFileName(h.FullPath).StartsWith("drop", StringComparison.Ordinal)));
        Assert.DoesNotContain(ex.PartialFindings, h => IsSentinelName(h.Match.Rule));
    }

    // --- Item 3: the review's scenario — the batch dropped more files than the recovery budget can re-scan ---------

    // The same overflow through the aggregate wall-clock budget instead of the count, and the review's C2 scenario: the
    // batch printed no coverage line for four files, and re-scanning them costs more than the recovery pass may spend.
    // Through the grace seam the budget is 250 ms + 1.5 s = 1.75 s, and each re-scan sleeps 0.6 s, so the four need at
    // least 2.4 s: at most two can be recovered, and this can never read Completed. (Before decision 9 it did — one hit,
    // four files never examined. Without the budget all four would be recovered and it would read Completed again.)
    // Every recovered hit and the batch hit travel together; the split is timing-dependent, so it is read back out of the
    // message and the carried-hit count is checked against it rather than pinned.
    //
    // FOLDED (round E): this replaces `…WhenTheUncoveredFilesOutlastTheRecoveryBudget…` (1.5 s launches, 5 s grace) and
    // `…WhenALongBatchDropsMoreFilesThanTheBudgetCanRecover…` (2.5 s launches including the batch, 3 s + 5 s budget),
    // which were this test at two slow scales — the batch's own duration never entered the recovery budget, so its sleep
    // proved nothing. Both tests' assertions are kept.
    [Fact]
    public void ScanDirectory_WhenTheUncoveredFilesOutlastTheRecoveryBudget_ThrowsCarryingBatchAndRecoveredHits()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        for (var i = 0; i < 4; i++)
            tree.Write($"content/late{i}.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            singleFileSleepMs: 600, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "late*");

        using var cli = new YaraCliScanner(250, 1_500);
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        var unrecovered = UnrecoveredOf(ex.Message, 4);
        Assert.InRange(unrecovered, 2, 4);
        Assert.Equal(1 + (4 - unrecovered), ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == Path.Combine(tree.Root, "content", "payload.bin"));
        Assert.DoesNotContain(ex.PartialFindings, h => IsSentinelName(h.Match.Rule));
    }

    // A dropped file whose own re-scan fails (the engine exits 1 on every single-file scan): unrecovered however much
    // budget is left, so the result is incomplete, carrying the batch's payload hit. (This used to sleep 2.5 s per launch;
    // the exit code alone is what fails the re-scan, so the sleep proved nothing.)
    [Fact]
    public void ScanDirectory_WhenTheBatchDropsAFileAndItsReScanFails_ThrowsCarryingTheBatchHit()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/late.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", sentinelSkip: "late.bin", singleFileExitCode: 1);

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("late.bin", ex.Message, StringComparison.Ordinal);
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(Path.Combine(tree.Root, "content", "payload.bin"), hit.FullPath);
    }

    // ...and the legitimate recovery the D-impl note warns about: with only two dropped files the budget fits both
    // re-scans, every file is positively covered, and Completed is the CORRECT answer — with all three hits. Before
    // decision 9 the same run read Completed with one. (This used to sleep 2.5 s per launch against an 8 s budget; what
    // it pins is that a recoverable drop is recovered, which needs no sleep at all.)
    [Fact]
    public void ScanDirectory_WhenTheBatchDropsFewEnoughFilesToRecover_CompletesWithEveryHit()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/late0.bin", "ordinary content\n");
        tree.Write("content/late1.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule", sentinelSkip: "late*");

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal(3, hits.Count);
        Assert.Single(hits, h => h.FullPath == Path.Combine(tree.Root, "content", "payload.bin"));
        Assert.Single(hits, h => h.FullPath == Path.Combine(tree.Root, "content", "late0.bin"));
        Assert.Single(hits, h => h.FullPath == Path.Combine(tree.Root, "content", "late1.bin"));
    }

    // --- Item 4: the sentinel is never a hit, a partial finding or a dropped hit ------------------------------

    // ScanFile uses the PLAIN ruleset, so a single-file scan neither gets a sentinel nor returns one. (The fake prints a
    // sentinel line on a single-file scan whenever its ruleset declares one, exactly as real yara would, so a regression
    // that handed ScanOne the batch ruleset would surface here as a sentinel "hit".)
    [Fact]
    public void ScanFile_UsesTheRulesetWithoutASentinelAndReturnsOnlyTheRealHit()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        var file = Path.Combine(tree.Root, "content", "payload.bin");
        using var fake = new FakeYaraBinary(recordInvocations: true, echoRule: "Fake_Rule");

        using var cli = new YaraCliScanner();
        var hits = cli.ScanFile(file);

        Assert.Equal("Fake_Rule", Assert.Single(hits).Rule);
        Assert.Equal("-", Field(Assert.Single(fake.Invocations), "sentinel"));
    }

    // Decision 7's incomplete result (an error line) carries the real batch hits and never a sentinel record, though the
    // batch output held one per file.
    [Fact]
    public void ScanDirectory_WhenIncompleteThroughAnErrorLine_PartialFindingsHoldNoSentinel()
    {
        using var tree = new TempTree();
        tree.Write("content/a/real.bin", "ordinary content\n");
        tree.Write("content/b/real.bin", "ordinary content\n");
        tree.Write("content/notes.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "real.bin",
            batchStdErr: "error scanning content/locked.bin: could not open file");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.All(ex.PartialFindings, h => Assert.Equal("Fake_Rule", h.Match.Rule));
        Assert.DoesNotContain(SentinelPrefix, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // The decision-17 guard (an unattributable REAL hit under the root) carries the attributed and the unattributable
    // hit — and neither the sentinel lines of the enumerated files nor an unattributable SENTINEL line under the root:
    // exactly one target is counted as dropped, the ghost hit, not the ghost's coverage line.
    [Fact]
    public void ScanDirectory_WhenTheDroppedHitGuardFires_CarriesNoSentinelAndCountsOnlyTheRealDroppedHit()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "real.bin", batchGhost: "ghost.bin",
            sentinelGhost: Path.Combine("content", "phantom.bin"));

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("matched 1 target(s)", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("phantom.bin", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == Path.Combine(tree.Root, "content", "real.bin"));
        Assert.Single(ex.PartialFindings, h => h.FullPath == Path.Combine(tree.Root, "content", "ghost.bin"));
        Assert.DoesNotContain(ex.PartialFindings, h => IsSentinelName(h.Match.Rule));
    }

    // The report surfaces — PackageScanner's findings and the report's JSON — for a completed scan whose batch output
    // held a sentinel line for every extracted file (the nuspec and the content alike).
    [Fact]
    public void Scan_WhenComplete_TheReportAndItsJsonCarryNoSentinel()
    {
        using var tree = new TempTree();
        var nupkg = YaraCliStderrErrorLineTests.WritePackage(tree, "PkgSentinelComplete",
            [("content/payload.bin", "ordinary content\n"), ("content/readme.txt", "ordinary text\n")]);
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/payload.bin", finding.RelativePath);
        Assert.Equal("Fake_Rule", finding.RuleName);
        Assert.DoesNotContain(SentinelPrefix, scan.Value.ToJson(), StringComparison.OrdinalIgnoreCase);
        // The batch pass ran with a sentinel and nothing needed re-scanning — otherwise this proves nothing.
        Assert.Matches(SentinelShape, Field(Assert.Single(fake.Invocations), "sentinel"));
    }

    // ...and for an incomplete one (decision 7 error line + decision 17 ghost), where findings travel with Unavailable.
    [Fact]
    public void Scan_WhenIncomplete_TheReportAndItsJsonCarryNoSentinel()
    {
        using var tree = new TempTree();
        var nupkg = YaraCliStderrErrorLineTests.WritePackage(tree, "PkgSentinelIncomplete",
            [("content/payload.bin", "ordinary content\n"), ("content/readme.txt", "ordinary text\n")]);
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", batchGhost: "ghost.bin",
            batchStdErr: "error scanning content/locked.bin: could not open file");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal(2, scan.Value.YaraFindings.Count);
        Assert.All(scan.Value.YaraFindings, f => Assert.Equal("Fake_Rule", f.RuleName));
        Assert.DoesNotContain(SentinelPrefix, scan.Value.ToJson(), StringComparison.OrdinalIgnoreCase);
    }

    // --- Item 5: an unattributable sentinel line is ignored ---------------------------------------------------

    // A real sentinel line for a path under the root that no enumerated file owns. It is neither coverage (it credits
    // nothing) nor a detection (not a decision-17 dropped hit): the scan completes with exactly the real hit, in one
    // launch. Treating it as a dropped hit would flip every package with a deferred name to Unavailable, since yara -r
    // prints such lines for deferred files by design.
    [Fact]
    public void ScanDirectory_WhenASentinelLineNamesNoEnumeratedFile_IgnoresIt()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin",
            sentinelGhost: Path.Combine("content", "phantom.bin"));

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal("Fake_Rule", Assert.Single(hits).Match.Rule);
        Assert.Single(fake.Invocations);
    }

    // --- Item 6: a forged coverage line is no coverage --------------------------------------------------------

    // A line that LOOKS like coverage for a dropped file but names the wrong rule — a different suffix, or the reserved
    // prefix with a different 128-bit suffix (what a package would have to guess to forge coverage through an LF in a
    // file name). The file must still count as uncovered: it is re-scanned, and when that re-scan fails the result is
    // incomplete, naming it.
    [Theory]
    [InlineData("SilvergunCoverageSentinel_forged")]
    [InlineData("SilvergunCoverageSentinel_0123456789abcdef0123456789abcdef")]
    [InlineData("SilvergunCoverageSentinel")]
    public void ScanDirectory_WhenADroppedFileHasOnlyAForgedCoverageLine_TreatsItAsUncovered(string forgedRule)
    {
        using var tree = new TempTree();
        tree.Write("content/readme.txt", "ordinary text\n");
        tree.Write("content/victim.bin", "ordinary content\n");
        var victim = Path.Combine(tree.Root, "content", "victim.bin");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, sentinelSkip: "victim.bin", sentinelForge: forgedRule, singleFileExitCode: 1);

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("victim.bin", ex.Message, StringComparison.Ordinal);
        Assert.Equal(victim, Field(Assert.Single(SingleFileLaunches(fake, tree.Root)), "target"));
    }

    // --- Item 8: the uncompiled and the compiled path both carry the sentinel ---------------------------------

    // No yarac (the FakeYaraBinary default; the probe's name derives no yarac beside it): the rules go to yara as
    // SOURCE, and that source still declares the sentinel — so coverage works and nothing is re-scanned.
    [Fact]
    public void ScanDirectory_WithUncompiledRules_StillCarriesTheSentinelAndCoversEveryFile()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/readme.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Single(hits);
        var batch = Assert.Single(fake.Invocations);
        Assert.Equal("False", Field(batch, "compiled"));
        Assert.Matches(SentinelShape, Field(batch, "sentinel"));
    }

    // yarac present but failing: the scanner falls back to the uncompiled source, which still carries the sentinel.
    [Fact]
    public void ScanDirectory_WhenYaracFails_FallsBackToUncompiledRulesThatStillCarryTheSentinel()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", fakeYarac: true, yaracExitCode: 1);

        using var cli = new YaraCliScanner();
        Assert.Single(cli.ScanDirectory(tree.Root));

        var batch = Assert.Single(fake.Invocations);
        Assert.Equal("False", Field(batch, "compiled"));
        Assert.Matches(SentinelShape, Field(batch, "sentinel"));
    }

    // The compiled path (a fake yarac that byte-copies the source): the batch launch passes -C and its compiled rules
    // declare the sentinel; a dropped file's re-scan also runs compiled, against the PLAIN ruleset.
    [Fact]
    public void ScanDirectory_WithCompiledRules_CarriesTheSentinelInTheBatchRulesetOnly()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/dropped.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "dropped.bin", fakeYarac: true);

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal(2, hits.Count);
        Assert.Equal(2, fake.Invocations.Count);
        var batch = Assert.Single(fake.Invocations, i => Field(i, "target") == tree.Root);
        Assert.Equal("True", Field(batch, "compiled"));
        Assert.Matches(SentinelShape, Field(batch, "sentinel"));
        var single = Assert.Single(SingleFileLaunches(fake, tree.Root));
        Assert.Equal("True", Field(single, "compiled"));
        Assert.Equal("-", Field(single, "sentinel"));
    }

    // "Fresh per ruleset": two scanners never share a sentinel name, so one run's output cannot vouch for another's.
    [Fact]
    public void ScanDirectory_TwoScanners_UseDifferentSentinelNames()
    {
        using var tree = new TempTree();
        tree.Write("content/readme.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(recordInvocations: true);

        using var cli = new YaraCliScanner();
        cli.ScanDirectory(tree.Root);
        using var cli2 = new YaraCliScanner();
        cli2.ScanDirectory(tree.Root);

        var names = fake.Invocations.Select(i => Field(i, "sentinel")).ToArray();
        Assert.Equal(2, names.Length);
        Assert.All(names, n => Assert.Matches(SentinelShape, n));
        Assert.NotEqual(names[0], names[1]);
    }

    // --- Item 9: the plain ruleset fails while the batch one is fine ------------------------------------------

    // Out of process (the temp directory is process-global): a warm-up scan prepares the batch ruleset only (every file
    // covered, so no re-scan), then the temp directory is poisoned, then a scan whose batch pass drops two files. The
    // individual pass cannot prepare the plain ruleset, so it marks every target unrecovered — and the batch's payload
    // hit still travels with the exception.
    [Fact]
    public void ScanDirectory_WhenThePlainRulesetCannotBePrepared_MarksEveryReScanUnrecoveredAndCarriesTheBatchHit()
    {
        using var warm = new TempTree();
        warm.Write("content/warm.txt", "ordinary text\n");
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/dropped1.bin", "ordinary content\n");
        tree.Write("content/dropped2.bin", "ordinary content\n");
        using var scratch = new TempTree();
        var notADirectory = scratch.Write("temp-stand-in.bin", "a regular file, standing in for the temp directory\n");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule", sentinelSkip: "dropped*");

        var result = YaraHarness.ScanDirectoryAfterWarmup(tree.Root, warm.Root, FakeYaraBinary.ProbePath, notADirectory);

        Assert.True(result["warmup"] == "completed:0", "The warm-up must have prepared the batch ruleset and completed.\n" + result.Report);
        Assert.True(result["outcome"] == "incomplete", result.Report);
        Assert.Contains("could not scan 2 of 2 file(s)", result["message"] ?? string.Empty, StringComparison.Ordinal);
        Assert.True(result["partial"] == "1", result.Report);
        Assert.True(result["partialhits"] == "payload.bin:Fake_Rule", result.Report);
    }

    // --- Item 10: a link among the uncovered files is refused, not followed -----------------------------------

    // `yara -r -N` does not follow a link, so it prints no coverage line for one (the fake is told the same). The
    // individual pass must not hand the link to a single-file yara — which WOULD open it and scan content outside the
    // package — so it is unrecovered and the scan is incomplete, naming it. Before decision 9 this read Completed.
    [LinuxFact]
    public void ScanDirectory_WhenAnUncoveredFileIsASymlink_LeavesItUnrecoveredWithoutFollowingIt()
    {
        using var outside = new TempTree();
        var elsewhere = outside.Write("outside-the-package.bin", "content from outside the package\n");
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        var link = Path.Combine(tree.Root, "content", "link.bin");
        File.CreateSymbolicLink(link, elsewhere);
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "link.bin");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("link.bin", ex.Message, StringComparison.Ordinal);
        Assert.Empty(SingleFileLaunches(fake, tree.Root));
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(Path.Combine(tree.Root, "content", "payload.bin"), hit.FullPath);
    }

    // --- Item 11: a failed run's stderr is capped like every other package text -------------------------------

    // A nonzero exit puts yara's stderr into the message (Explain). It echoes package paths, so it is escaped and
    // capped: ten lines, then ", and N more" — the shared rendering — never the whole flood.
    [Fact]
    public void ScanDirectory_WhenTheBatchFailsWithManyStderrLines_NamesTenEscapedAndCountsTheRest()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        var lines = Enumerable.Range(0, 12).Select(i => i == 3
            ? "error scanning content/a" + Esc + "[31mred.bin: could not open file"
            : $"error scanning content/f{i:D2}.bin: could not open file");
        using var fake = new FakeYaraBinary(exitCode: 2, batchStdErr: string.Join("\\n", lines));

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("yara exited with code 2", ex.Message, StringComparison.Ordinal);
        Assert.Equal(10, Regex.Matches(ex.Message, @"'error scanning content/[^']*: could not open file'").Count);
        Assert.Contains(@"'error scanning content/a\x1b[31mred.bin: could not open file'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'error scanning content/f09.bin: could not open file', and 2 more", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("f10.bin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("f11.bin", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }
    #endregion

    #region Helpers
    // The reserved prefix, spelled out (not YaraCliScanner.SentinelPrefix) so this file compiles against the Round C
    // scanner; YaraCliCoverageSentinelApiTests pins that the two agree.
    internal const string SentinelPrefix = "SilvergunCoverageSentinel_";

    internal const string SentinelShape = "^SilvergunCoverageSentinel_[0-9a-f]{32}$";

    private const char Esc = (char)0x1B;

    internal static bool IsSentinelName(string rule) => rule.StartsWith(SentinelPrefix, StringComparison.OrdinalIgnoreCase);

    // One field of a FakeYaraProbe log line (`argc=…|target=…|dirmode=…|compiled=…|sentinel=…`).
    internal static string Field(string invocation, string key) =>
        invocation.Split('|').Select(p => p.Split('=', 2)).First(p => p[0] == key)[1];

    // The launches that were NOT the recursive pass over `root`: the individual re-scans.
    internal static string[] SingleFileLaunches(FakeYaraBinary fake, string root) =>
        fake.Invocations.Where(i => Field(i, "target") != root).ToArray();

    // "could not scan N of <total> file(s)" ⇒ N, asserting the total.
    private static int UnrecoveredOf(string message, int total)
    {
        var match = Regex.Match(message, @"could not scan (\d+) of (\d+) file\(s\)");
        Assert.True(match.Success, $"Unexpected message shape: {message}");
        Assert.Equal(total, int.Parse(match.Groups[2].Value));
        return int.Parse(match.Groups[1].Value);
    }
    #endregion
}
