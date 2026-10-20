namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Task round E: <b>one hit per (file, namespace, rule)</b>, on every exit of <see cref="YaraCliScanner.ScanDirectory"/>.
/// Since ADR 0032 decision 9 a file can be examined twice: a file with a batch hit but no coverage-sentinel line keeps
/// that hit AND is re-scanned individually, so the two passes can report the same rule on the same file. Real yara never
/// produced that shape in the measurements (it prints all of a file's rules together), but package-authored output can
/// (an LF in a file name starts a line of its own), and a doubled finding inflates the report. The fold must hold on the
/// completed return, on the recovery pass's rethrow, on the decision 7 (stderr error line) rethrow and on the decision 17
/// (unattributable hit) throw — and must never fold two DIFFERENT rules on one file.
///
/// <para>The engine is the <c>FakeYaraProbe</c>: <c>batchEchoRule</c> prints the batch hit, <c>sentinelSkip</c> withholds
/// the file's coverage line, <c>echoRule</c> makes its single-file re-scan report the rule again, and
/// <c>batchEchoRepeat</c> repeats batch lines byte for byte.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliHitDedupeTests
{
    #region Methods
    // The completed path: the batch hit and the re-scan's hit on the same file, same rule ⇒ one hit. The single-file
    // launch is asserted too — without it the duplicate was never produced and the test would prove nothing.
    [Fact]
    public void ScanDirectory_WhenAFileWithABatchHitHasNoCoverageLine_ReturnsItsHitOnce()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        tree.Write("content/readme.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "payload.bin");
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
        Assert.Equal(payload, YaraCliCoverageSentinelTests.Field(
            Assert.Single(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root)), "target"));
    }

    // The recovery pass's rethrow: the same doubled file, plus another uncovered file whose re-scan fails. The exception
    // carries the batch hits and the recovered ones — and the payload's hit once, not twice.
    [Fact]
    public void ScanDirectory_WhenTheRecoveryPassFails_CarriesTheDoubledFilesHitOnce()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        tree.Write("content/broken.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule",
            sentinelSkip: "payload.bin|broken.bin", singleFileFail: "broken.bin");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("broken.bin", ex.Message, StringComparison.Ordinal);
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
        Assert.Equal(2, YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root).Length);
    }

    // The decision 7 rethrow (an `error` line on the batch pass's stderr, thrown after the recovery pass): the doubled
    // file's hit is carried once.
    [Fact]
    public void ScanDirectory_WhenTheBatchPrintsAnErrorLine_CarriesTheDoubledFilesHitOnce()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule", sentinelSkip: "payload.bin",
            batchStdErr: "error scanning content/locked.bin: could not open file");
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("1 hit(s) found in the files that were scanned", ex.Message, StringComparison.Ordinal);
        Assert.Equal(payload, Assert.Single(ex.PartialFindings).FullPath);
    }

    // Byte-identical repeated batch records for a covered file collapse to one hit; nothing is re-scanned.
    [Fact]
    public void ScanDirectory_WhenTheBatchRepeatsAHitLine_ReturnsTheHitOnce()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", batchEchoRepeat: 3);
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal(payload, Assert.Single(hits).FullPath);
        Assert.Single(fake.Invocations);
    }

    // The decision 17 throw (a hit under the root that no enumerated file owns): with every batch line printed twice, the
    // exception carries the attributed hit once and the unattributable one once.
    [Fact]
    public void ScanDirectory_WhenTheDroppedHitGuardFiresOnRepeatedLines_CarriesEachHitOnce()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", batchGhost: "ghost.bin", batchEchoRepeat: 2);
        using var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Contains("could not be attributed", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == payload);
        Assert.Single(ex.PartialFindings, h => h.FullPath == Path.Combine(tree.Root, "content", "ghost.bin"));
    }

    // The control: the fold is per RULE. A file the batch pass reports under one rule and its re-scan under another has
    // two distinct detections, and both are kept.
    [Fact]
    public void ScanDirectory_WhenTheTwoPassesReportDifferentRulesOnOneFile_KeepsBoth()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Batch_Rule", batchEchoName: "payload.bin", echoRule: "Single_Rule", sentinelSkip: "payload.bin");
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal(2, hits.Count);
        Assert.All(hits, h => Assert.Equal(payload, h.FullPath));
        Assert.Equal(new[] { "Batch_Rule", "Single_Rule" }, hits.Select(h => h.Match.Rule).Order(StringComparer.Ordinal));
    }
    #endregion
}
