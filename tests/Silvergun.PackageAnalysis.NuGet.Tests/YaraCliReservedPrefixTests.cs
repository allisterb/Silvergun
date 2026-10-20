namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// Task round E: <b>a record whose rule name uses the reserved coverage-sentinel prefix but is not this scan's own
/// sentinel is forged output, and is dropped</b> — neither a finding, nor coverage, nor a decision 17 "dropped hit" — with
/// exactly one escaped warning. No shipped rule carries the prefix (<see cref="YaraCliCoverageSentinelApiTests"/> pins
/// that), so such a record can only come from package-authored output (an LF in a file name lets a package start a line
/// of its own). Before round E it was taken at face value: on an attributable file it became a FINDING named
/// <c>SilvergunCoverageSentinel_…</c>, and under the root but unattributable it fired the decision 17 guard and turned a
/// clean package Unavailable.
///
/// <para>"Not this scan's own sentinel" is ordinal: the real name in another case is foreign too. The single-file path
/// (<see cref="YaraCliScanner.ScanFile"/>, the plain ruleset, which has no sentinel at all) drops every such record.</para>
///
/// <para>The engine is the <c>FakeYaraProbe</c>: <c>sentinelForge</c> prints a forged coverage line in place of a file's
/// real one (<c>"@upper"</c>/<c>"@upper-suffix"</c>: the real name re-cased), <c>batchStdOut</c> prints arbitrary records,
/// and <c>echoRule</c> sets the rule a single-file scan reports.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliReservedPrefixTests
{
    #region Methods
    // A forged coverage record for an attributable file whose real coverage line is missing: it must not become a hit
    // (it did, before round E), and it must not count as coverage — the file is still re-scanned on its own. The re-scan
    // succeeds and finds nothing, so the honest result is Completed with no findings.
    [Theory]
    [InlineData("SilvergunCoverageSentinel_0123456789abcdef0123456789abcdef")]
    [InlineData("silverguncoveragesentinel_forged")]
    [InlineData("@upper")]
    [InlineData("@upper-suffix")]
    public void ScanDirectory_WhenAForgedSentinelRecordNamesAnAttributableFile_ItIsNeitherAFindingNorCoverage(string forged)
    {
        using var tree = new TempTree();
        tree.Write("content/readme.txt", "ordinary text\n");
        var victim = Path.GetFullPath(tree.Write("content/victim.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "victim.bin", sentinelForge: forged);
        using var warnings = new WarningCapture();
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Empty(hits);
        Assert.Equal(victim, YaraCliCoverageSentinelTests.Field(
            Assert.Single(YaraCliCoverageSentinelTests.SingleFileLaunches(fake, tree.Root)), "target"));
        var warning = Assert.Single(ForgedRecordWarnings(warnings, tree.Root));
        Assert.Contains("ignored 1 output record(s)", warning, StringComparison.Ordinal);
    }

    // A forged record for a path under the root that no enumerated file owns. A real hit there fires decision 17 (missing
    // coverage); a forged sentinel record must not — it is not a detection at all. The scan completes in one launch.
    [Fact]
    public void ScanDirectory_WhenAForgedSentinelRecordNamesNoEnumeratedFile_TheScanStillCompletes()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        var root = tree.Root.Replace('\\', '/');   // '/'-separated: the probe decodes a literal backslash-n in this text
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchStdOut: $"SilvergunCoverageSentinel_forged [] {root}/content/phantom.bin");
        using var warnings = new WarningCapture();
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Empty(hits);
        Assert.Single(fake.Invocations);
        Assert.Single(ForgedRecordWarnings(warnings, tree.Root));
    }

    // Several forged records in one pass — one with an escape sequence in its target — produce exactly ONE warning that
    // counts them and names their targets escaped: the warning is package text in our log, and must not be forgeable or
    // floodable through it. A genuine hit in the same output is unaffected.
    [Fact]
    public void ScanDirectory_WhenSeveralForgedRecordsArePrinted_LogsOneEscapedWarningAndKeepsTheRealHit()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        var root = tree.Root.Replace('\\', '/');
        var forged = string.Join("\\n",
            $"SilvergunCoverageSentinel_a [] {root}/content/payload.bin",
            $"SILVERGUNCOVERAGESENTINEL_B [] {root}/content/a" + Esc + "[31mred.bin",
            $"SilvergunCoverageSentinel_c [] {root}/content/phantom.bin");
        using var fake = new FakeYaraBinary(batchStdOut: forged, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var warnings = new WarningCapture();
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
        var warning = Assert.Single(ForgedRecordWarnings(warnings, tree.Root));
        Assert.Contains("ignored 3 output record(s)", warning, StringComparison.Ordinal);
        Assert.Contains(@"a\x1b[31mred.bin", warning, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(warning);
    }

    // The single-file scan uses the plain ruleset, which declares no sentinel: ANY reserved-prefix record on its target
    // is forged. It is dropped (before round E it came back as the file's one hit) with one warning naming the file.
    [Theory]
    [InlineData("SilvergunCoverageSentinel_0123456789abcdef0123456789abcdef")]
    [InlineData("SILVERGUNCOVERAGESENTINEL_forged")]
    public void ScanFile_WhenTheEngineReportsAReservedPrefixRule_ReturnsNoHitAndLogsOneWarning(string forged)
    {
        using var tree = new TempTree();
        var file = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(echoRule: forged);
        using var warnings = new WarningCapture();
        using var scanner = new YaraCliScanner();

        var hits = scanner.ScanFile(file);

        Assert.Empty(hits);
        var warning = Assert.Single(ForgedRecordWarnings(warnings, file));
        Assert.Contains("ignored 1 output record(s)", warning, StringComparison.Ordinal);
    }

    // The control for the theory above: an ordinary rule on the same single-file path is still a hit, with no warning —
    // so the drop is about the prefix, not about single-file output in general.
    [Fact]
    public void ScanFile_WhenTheEngineReportsAnOrdinaryRule_ReturnsItWithoutAWarning()
    {
        using var tree = new TempTree();
        var file = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(echoRule: "Fake_Rule");
        using var warnings = new WarningCapture();
        using var scanner = new YaraCliScanner();

        Assert.Equal("Fake_Rule", Assert.Single(scanner.ScanFile(file)).Rule);
        Assert.Empty(ForgedRecordWarnings(warnings, file));
    }
    #endregion

    #region Helpers
    private const char Esc = (char)0x1B;

    // The forged-record warnings for one scanned path (escaped as the scanner escapes it).
    private static string[] ForgedRecordWarnings(WarningCapture warnings, string scanned) =>
        warnings.Warnings
            .Where(w => w.Contains("reserved coverage-sentinel prefix", StringComparison.Ordinal)
                        && w.Contains(YaraPathSafety.Escape(scanned), StringComparison.Ordinal))
            .ToArray();
    #endregion
}
