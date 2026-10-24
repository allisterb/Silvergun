namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// ADR 0034 decision 2 through <see cref="YaraCliScanner.ScanFiles"/>, the classic-CLI backend (the Linux backend in
/// production). It keeps its one recursive <c>yara -r &lt;root&gt;</c> pass, but the files that need positive coverage
/// evidence are the LISTED ones: a listed file the batch pass never saw (it was deleted after the list was taken) has no
/// coverage-sentinel line, goes to the individual pass, is found gone there (I1b's <c>IsGone</c>, checked before the link
/// check) and is unrecovered, NAMED as missing — the warning says so and the message LEADS with
/// <c>"…did not cover: 1 of them no longer exists (removed after it was listed): …"</c> (or <c>"k of them no longer exist
/// (each removed after it was listed)"</c>), then <c>"; the others (…): …"</c>, each file named once (I3 review N1–N3; I4).
/// The missing clause comes first because the report's reason is bounded at 512 chars, and a trailing clause is the
/// first thing the bound cuts. With no missing file the message is unchanged.
///
/// <para>Verification (b) of I1: measured here with the <c>FakeYaraProbe</c> (every platform; it prints a sentinel line
/// for each file it finds under the root, as real yara does) and, under WSL, with the real <c>yara</c>
/// (<see cref="LinuxYaraFactAttribute"/>). The positive for the real engine is <see cref="HermeticWiperSample"/>.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraInventoryCliTests
{
    #region Constructors
    public YaraInventoryCliTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods: a listed file that is gone (FakeYaraProbe)
    [Fact]
    public void ScanFiles_WithAListedFileDeletedBeforeTheCall_IsIncomplete_NamesItAsGone_AndKeepsThePayloadHit()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        var gone = Path.GetFullPath(tree.Write("content/gone.bin", "ordinary content\n"));
        tree.Write("content/notes.txt", "ordinary text\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, Path.GetFullPath(hit.FullPath));
        Assert.Equal("Fake_Rule", hit.Match.Rule);
        Assert.Equal(
            Lead(1, 1) + $"1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.bin")}'" + Tail,
            ex.Message);
        Assert.Contains(warnings.Warnings, w => w == $"YARA will not re-scan {gone} on its own: it no longer exists (removed after it was listed).");
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("is a link", StringComparison.Ordinal));
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));   // nothing was launched on a file that is not there
    }

    // Every listed file gone: incomplete, never the empty list a clean package would get, and every one of them named
    // as missing.
    [Fact]
    public void ScanFiles_WithEveryListedFileDeleted_IsIncomplete_AndCountsEachAsGone()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/b.bin", "ordinary content\n");
        tree.Write("pkg.nuspec", "<package/>\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        foreach (var file in listed)
            File.Delete(file);
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Empty(ex.PartialFindings);
        Assert.StartsWith(Lead(3, 3) + "3 of them no longer exist (each removed after it was listed): ", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
        Assert.EndsWith(Tail, ex.Message, StringComparison.Ordinal);
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));
    }

    // The root itself gone. yara is still pointed at it (the probe, like a yara that finds nothing there, prints nothing
    // and exits 0); no listed file has a coverage line, and each is found gone.
    [Fact]
    public void ScanFiles_WhenTheRootIsDeleted_IsIncomplete()
    {
        using var tree = new TempTree();
        var root = Path.Combine(tree.Root, "extracted");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        File.WriteAllText(Path.Combine(root, "content", "a.bin"), "ordinary content\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(root);
        Directory.Delete(root, recursive: true);
        using var fake = new FakeYaraBinary();
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(root, listed));

        Assert.Equal(
            Lead(1, 1) + $"1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "a.bin")}'" + Tail,
            ex.Message);
    }

    // Mixed causes (N2): one listed file gone and one that is there but cannot be recovered (no coverage line, and its
    // own re-scan fails). The gone one LEADS under its own clause; the other follows under "the others"; each is named
    // exactly once, and the missing count is exactly the one that is gone.
    [Fact]
    public void ScanFiles_WithOneGoneAndOneOtherwiseUnrecoveredFile_LeadsWithTheGoneOne_AndNamesEachOnce()
    {
        using var tree = new TempTree();
        var gone = Path.GetFullPath(tree.Write("content/gone.bin", "ordinary content\n"));
        tree.Write("content/stuck.bin", "ordinary content\n");
        tree.Write("content/fine.bin", "ordinary content\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "stuck.bin", singleFileFail: "stuck.bin");
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(
            Lead(2, 2) + $"1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.bin")}'"
            + Others + $"'{Path.Combine("content", "stuck.bin")}'" + Tail,
            ex.Message);
        Assert.Equal(1, Occurrences(ex.Message, "gone.bin"));    // never listed twice
        Assert.Equal(1, Occurrences(ex.Message, "stuck.bin"));
        Assert.Single(warnings.Warnings, w => w.Contains("it no longer exists (removed after it was listed)", StringComparison.Ordinal));
        // The stuck file WAS launched on its own (and failed); the gone one was not.
        var launched = YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root).Select(i => YaraCliCoverageSentinelTests.Field(i, "target")).ToArray();
        Assert.Equal(new[] { Path.Combine(tree.Root, "content", "stuck.bin") }, launched.Select(Path.GetFullPath));
    }

    // N2's other half: with NO missing file the individual pass's message is the one it always was (the committed text),
    // byte for byte — no missing clause, no "the others".
    [Fact]
    public void ScanFiles_WithAnUnrecoveredFileAndNoneGone_TheMessageIsUnchanged()
    {
        using var tree = new TempTree();
        tree.Write("content/stuck.bin", "ordinary content\n");
        tree.Write("content/fine.bin", "ordinary content\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "stuck.bin", singleFileFail: "stuck.bin");
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(
            $"YARA could not scan 1 of 1 file(s) that its recursive pass did not cover (names its batch output cannot round-trip, or files it printed no coverage line for), so this package was NOT fully scanned and must not be reported as clean. Path(s), control characters escaped: '{Path.Combine("content", "stuck.bin")}'",
            ex.Message);
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("no longer exists", StringComparison.Ordinal));
    }

    // A file that appears under the root AFTER the list was taken, and matches, is not one of the listed files, so its
    // hit cannot be attributed (ADR 0029 decision 17): the scan fails closed, carrying that hit under the echoed path.
    // Unreachable in production (no package code runs); this pins that it is closed, not open.
    [Fact]
    public void ScanFiles_WhenAFileAddedAfterTheListHasAHit_IsIncomplete_BecauseTheHitIsUnattributable()
    {
        using var tree = new TempTree();
        tree.Write("content/a.bin", "ordinary content\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        var late = Path.GetFullPath(tree.Write("content/late.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "late.bin");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Contains("could not be attributed to any file it enumerated", ex.Message, StringComparison.Ordinal);
        Assert.Equal(late, Path.GetFullPath(Assert.Single(ex.PartialFindings).FullPath));
    }

    // The gone file's name is attacker-authored: the warning and the message carry it escaped. A bidi override is legal
    // on NTFS and ext4 alike, and leaves the name "safe" for the batch pass (C0 only is unsafe), so this is the
    // no-coverage-line route into the individual pass.
    [Fact]
    public void ScanFiles_AGoneFileWithABidiName_IsNamedEscaped_InTheWarningAndTheMessage()
    {
        using var tree = new TempTree();
        var gone = Path.GetFullPath(tree.Write($"content/exe.{Rlo}txt.bin", "ordinary content\n"));
        tree.Write("content/ok.bin", "ordinary content\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var fake = new FakeYaraBinary();
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(
            Lead(1, 1) + $"1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "exe." + EscapedRlo + "txt.bin")}'" + Tail,
            ex.Message);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("it no longer exists (removed after it was listed)", StringComparison.Ordinal));
        Assert.Contains("exe." + EscapedRlo + "txt.bin", warning, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(warning);
    }

    // A C0 name is UNSAFE, so it reaches the individual pass by the other route (never in the batch at all); gone, it
    // is named as gone, escaped. Only Linux can stage it.
    [LinuxFact]
    public void ScanFiles_AGoneFileWithAControlCharacterName_IsNamedEscaped_InTheWarningAndTheMessage()
    {
        using var tree = new TempTree();
        var gone = tree.Write("content/n" + (char)0x0A + "l.bin", "ordinary content\n");
        tree.Write("content/ok.bin", "ordinary content\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var fake = new FakeYaraBinary();
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Equal(Lead(1, 1) + @"1 of them no longer exists (removed after it was listed): 'content/n\nl.bin'" + Tail, ex.Message);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("it no longer exists (removed after it was listed)", StringComparison.Ordinal));
        Assert.Contains(@"n\nl.bin", warning, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(warning);
    }

    // A DANGLING symlink in the list is not "gone": the link itself exists (its attributes are read without following
    // it), so it keeps the link refusal — never re-scanned on its own, never named as removed. The probe withholds its
    // coverage line, as yara -r -N skips a symlink.
    [LinuxFact]
    public void ScanFiles_ADanglingSymlinkInTheList_IsRefusedAsALink_NotNamedAsGone()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        var link = Path.Combine(tree.Root, "content", "dangling.bin");
        File.CreateSymbolicLink(link, Path.Combine(tree.Root, "nowhere", "target.bin"));
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        Assert.Contains(link, listed);   // precondition: the enumeration lists a dangling link as a file
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "dangling.bin");
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("no longer exist", ex.Message, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w.Contains("dangling.bin", StringComparison.Ordinal) && w.Contains("it is a link or lies under a linked directory", StringComparison.Ordinal));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("no longer exists", StringComparison.Ordinal));
        Assert.Empty(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root));
    }
    #endregion

    #region Methods: a gone file takes no individual-scan slot (I5)
    // More gone files than the individual pass's 64-launch cap (MaxIndividualScans), ALL listed ahead of one recoverable
    // file that also needs its own re-scan (no coverage line). A gone file launches nothing, so it must not take a slot:
    // the recoverable file IS re-scanned and its hit kept, and every gone file is still named — one warning each, and the
    // leading clause counts all of them.
    [Fact]
    public void ScanFiles_WithMoreGoneFilesThanTheIndividualCap_StillReScansTheRecoverableFile_AndNamesEveryGoneFile()
    {
        using var tree = new TempTree();
        var gone = Enumerable.Range(0, GoneCount).Select(i => Path.GetFullPath(tree.Write($"content/gone-{i:D3}.bin", "ordinary content\n"))).ToArray();
        var stuck = Path.GetFullPath(tree.Write("content/stuck.bin", "ordinary content\n"));
        var fine = Path.GetFullPath(tree.Write("content/fine.bin", "ordinary content\n"));
        string[] listed = [.. gone, stuck, fine];   // the individual pass meets every gone file before the recoverable one
        foreach (var file in gone)
            File.Delete(file);
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "stuck.bin", echoRule: "Fake_Rule");
        using var scanner = new YaraCliScanner();
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        // The recoverable file was launched on its own (exactly one single-file run) and its hit is carried.
        var launched = YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root).Select(i => YaraCliCoverageSentinelTests.Field(i, "target")).ToArray();
        Assert.Equal(new[] { stuck }, launched.Select(Path.GetFullPath));
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal((stuck, "Fake_Rule"), (Path.GetFullPath(hit.FullPath), hit.Match.Rule));
        // Every gone file is named: the clause counts them all (the list is bounded at ten names), each has its own warning.
        Assert.StartsWith(Lead(GoneCount, GoneCount + 1) + $"{GoneCount} of them no longer exist (each removed after it was listed): '{Path.Combine("content", "gone-000.bin")}', ", ex.Message, StringComparison.Ordinal);
        Assert.Contains($", and {GoneCount - YaraPathSafety.MaxListedItems} more", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
        Assert.EndsWith(Tail, ex.Message, StringComparison.Ordinal);
        Assert.All(gone, g => Assert.Contains(warnings.Warnings, w => w == $"YARA will not re-scan {g} on its own: it no longer exists (removed after it was listed)."));
    }

    // The control for the test above: the same recoverable file BEHIND 64 files that are NOT gone and do need re-scans
    // (no coverage line, all present) is past the cap and unrecovered — so the cap is real, and it is the gone files'
    // exemption, not a generous cap, that let the recoverable file through above.
    [Fact]
    [Trait("Category", "Slow")]   // 64 single-file launches of the probe
    public void ScanFiles_WithTheCapTakenByRealReScans_TheRecoverableFileBehindThemIsUnrecovered()
    {
        using var tree = new TempTree();
        var present = Enumerable.Range(0, 64).Select(i => Path.GetFullPath(tree.Write($"content/redo-{i:D3}.bin", "ordinary content\n"))).ToArray();
        var stuck = Path.GetFullPath(tree.Write("content/stuck.bin", "ordinary content\n"));
        string[] listed = [.. present, stuck];
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "redo-*|stuck.bin", echoRule: "Fake_Rule");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        var launched = YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root).Select(i => Path.GetFullPath(YaraCliCoverageSentinelTests.Field(i, "target"))).ToArray();
        Assert.Equal(64, launched.Length);
        Assert.DoesNotContain(stuck, launched);
        Assert.DoesNotContain(ex.PartialFindings, h => Path.GetFullPath(h.FullPath) == stuck);
        Assert.Contains("could not scan 1 of 65 file(s)", ex.Message, StringComparison.Ordinal);
    }

    // A gone file is named even when the individual pass cannot prepare its (plain) ruleset at all: the gone check comes
    // before every bound, so the cause survives. Out of process, because the temp directory is process-global: a warm-up
    // prepares the batch ruleset only, the temp directory is then poisoned, and the child lists the tree, deletes
    // gone.bin and scans the list. stuck.bin (no coverage line) is unrecovered too, under "the others".
    [Fact]
    public void ScanFiles_WhenThePlainRulesetCannotBePrepared_AGoneFileIsStillNamedAsGone()
    {
        using var warm = new TempTree();
        warm.Write("content/warm.txt", "ordinary text\n");
        using var tree = new TempTree();
        tree.Write("content/gone.bin", "ordinary content\n");
        tree.Write("content/stuck.bin", "ordinary content\n");
        tree.Write("content/fine.bin", "ordinary content\n");
        using var scratch = new TempTree();
        var notADirectory = scratch.Write("temp-stand-in.bin", "a regular file, standing in for the temp directory\n");
        using var fake = new FakeYaraBinary(sentinelSkip: "stuck.bin");

        var result = YaraHarness.ScanFilesAfterWarmup(tree.Root, warm.Root, FakeYaraBinary.ProbePath, notADirectory, "gone.bin");

        Assert.True(result["warmup"] == "completed:0", "The warm-up must have prepared the batch ruleset and completed.\n" + result.Report);
        Assert.True(result["listed"] == "3" && result["deleted"] == "1", result.Report);
        Assert.True(result["outcome"] == "incomplete", result.Report);
        Assert.Equal(
            Lead(2, 2) + $"1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.bin")}'"
            + Others + $"'{Path.Combine("content", "stuck.bin")}'" + Tail,
            result["message"]);
    }

    // The slot accounting with the REAL yara: 70 gone files and one recoverable payload, all under C0 names (unsafe, so
    // each goes to the individual pass in list order, the payload through a safely named copy). The payload IS scanned —
    // the real HermeticWiper detection is carried — and every gone file is counted under the clause.
    [LinuxYaraFact]
    public void RealYara_ScanFiles_WithMoreGoneFilesThanTheIndividualCap_StillReScansTheRecoverableFile()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var gone = Enumerable.Range(0, GoneCount).Select(i => tree.Write($"content/g{(char)0x01}{i:D3}.bin", "ordinary content\n")).ToArray();
        var payload = tree.Write($"content/p{(char)0x01}ayload.dll", HermeticWiperSample.Bytes);
        var notes = tree.Write("content/notes.txt", "ordinary text\n");
        string[] listed = [.. gone, payload, notes];
        foreach (var file in gone)
            File.Delete(file);
        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal((payload, HermeticWiperSample.RuleName), (hit.FullPath, hit.Match.Rule));
        Assert.StartsWith(Lead(GoneCount, GoneCount + 1) + $"{GoneCount} of them no longer exist (each removed after it was listed): ", ex.Message, StringComparison.Ordinal);
        Assert.Contains($", and {GoneCount - YaraPathSafety.MaxListedItems} more", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }
    #endregion

    #region Methods: the edges of the contract
    // An empty list: empty, before anything is prepared or launched.
    [Fact]
    public void ScanFiles_WithAnEmptyList_ReturnsEmpty_WithoutLaunchingYara()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var scanner = new YaraCliScanner();

        Assert.Empty(scanner.ScanFiles(tree.Root, []));
        Assert.Empty(fake.Invocations);
    }

    [Fact]
    public void ScanFiles_WithANullList_ThrowsArgumentNullException()
    {
        using var tree = new TempTree();
        using var fake = new FakeYaraBinary();
        using var scanner = new YaraCliScanner();

        Assert.Throws<ArgumentNullException>(() => scanner.ScanFiles(tree.Root, null!));
    }

    // No behaviour change for an undisturbed package: the list of what is there scans exactly as the directory does.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanFiles_OverAnUndisturbedTree_ReturnsWhatScanDirectoryReturns(bool withHits)
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/nested/payload.bin", "ordinary content\n");
        tree.Write("content/notes.txt", "ordinary text\n");
        using var fake = withHits ? new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin") : new FakeYaraBinary();
        using var scanner = new YaraCliScanner();

        var viaFiles = scanner.ScanFiles(tree.Root, YaraInventoryDefaultLoopTests.Inventory(tree.Root));
        var viaDirectory = scanner.ScanDirectory(tree.Root);

        Assert.Equal(YaraInventoryDefaultLoopTests.Keys(viaDirectory), YaraInventoryDefaultLoopTests.Keys(viaFiles));
        Assert.Equal(withHits ? 2 : 0, viaFiles.Count);
    }
    #endregion

    #region Methods: the real yara (WSL)
    // Verification (b) with the real engine: the deleted listed file is unscanned and named as gone; the real
    // HermeticWiper detection in the other file is carried.
    [LinuxYaraFact]
    public void RealYara_ScanFiles_WithAListedFileDeleted_IsIncomplete_NamesItAsGone_AndKeepsTheRealHit()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.dll", HermeticWiperSample.Bytes));
        var gone = Path.GetFullPath(tree.Write("content/gone.dll", HermeticWiperSample.Bytes));
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        File.Delete(gone);
        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, Path.GetFullPath(hit.FullPath));
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        // Starts with, not equals: a real yara may add batch stderr lines after the message (ADR 0032 decision 7).
        Assert.StartsWith(Lead(1, 1) + "1 of them no longer exists (removed after it was listed): 'content/gone.dll'. This package was NOT fully scanned", ex.Message, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w == $"YARA will not re-scan {gone} on its own: it no longer exists (removed after it was listed).");
    }

    [LinuxYaraFact]
    public void RealYara_ScanFiles_WithEveryListedFileDeleted_IsIncomplete_NeverEmpty()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        tree.Write("content/payload.dll", HermeticWiperSample.Bytes);
        tree.Write("content/notes.txt", "ordinary text\n");
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        foreach (var file in listed)
            File.Delete(file);
        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Empty(ex.PartialFindings);
        Assert.StartsWith(Lead(2, 2) + "2 of them no longer exist (each removed after it was listed): ", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
    }

    [LinuxYaraFact]
    public void RealYara_ScanFiles_OverAnUndisturbedTree_ReturnsWhatScanDirectoryReturns()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var withHits = new TempTree();
        withHits.Write("content/payload.dll", HermeticWiperSample.Bytes);
        withHits.Write("content/notes.txt", "ordinary text\n");
        using var clean = new TempTree();
        clean.Write("content/notes.txt", "ordinary text\n");
        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");

        foreach (var root in new[] { withHits.Root, clean.Root })
        {
            var viaFiles = scanner.ScanFiles(root, YaraInventoryDefaultLoopTests.Inventory(root));
            var viaDirectory = scanner.ScanDirectory(root);

            Assert.Equal(YaraInventoryDefaultLoopTests.Keys(viaDirectory), YaraInventoryDefaultLoopTests.Keys(viaFiles));
            Assert.Equal(root == withHits.Root, viaFiles.Any(h => h.Match.Rule == HermeticWiperSample.RuleName));
        }
    }

    // The dangling symlink against the real yara -r -N, which skips the link: it keeps the link refusal.
    [LinuxYaraFact]
    public void RealYara_ScanFiles_ADanglingSymlinkInTheList_IsRefusedAsALink_NotNamedAsGone()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        var link = Path.Combine(tree.Root, "content", "dangling.bin");
        File.CreateSymbolicLink(link, Path.Combine(tree.Root, "nowhere", "target.bin"));
        var listed = YaraInventoryDefaultLoopTests.Inventory(tree.Root);
        Assert.Contains(link, listed);
        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.DoesNotContain("no longer exist", ex.Message, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w.Contains("dangling.bin", StringComparison.Ordinal) && w.Contains("it is a link or lies under a linked directory", StringComparison.Ordinal));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("no longer exists", StringComparison.Ordinal));
    }
    #endregion

    #region Helpers
    // The individual pass's message when some unrecovered file no longer exists (I4, N2): the lead, the missing clause,
    // optionally "the others", and the tail.
    internal static string Lead(int unrecovered, int targets) =>
        $"YARA could not scan {unrecovered} of {targets} file(s) that its recursive pass did not cover: ";

    internal const string Others = "; the others (names its batch output cannot round-trip, or files it printed no coverage line for): ";

    internal const string Tail = ". This package was NOT fully scanned and must not be reported as clean. Path(s), control characters escaped.";

    // More than the individual pass's 64-launch cap (YaraCliScanner.MaxIndividualScans).
    private const int GoneCount = 70;

    private static int Occurrences(string text, string value)
    {
        var count = 0;
        for (var i = text.IndexOf(value, StringComparison.Ordinal); i >= 0; i = text.IndexOf(value, i + value.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
    #endregion

    #region Fields
    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion
}
