namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0032 decisions 1 and 4 at the classic-CLI backend's own seam: <b>every
/// <see cref="YaraScanIncompleteException"/> <see cref="YaraCliScanner.ScanDirectory"/> throws with hits in hand
/// carries all of them</b> in <see cref="YaraScanIncompleteException.PartialFindings"/>. Context §2 of the ADR names
/// the three sites that used to discard them; one test per site:
/// <list type="bullet">
/// <item>the recovery pass giving up after the batch pass found something — by overflowing
/// <c>MaxIndividualScans</c> = 64 (the attacker-selectable headline: a payload plus 65 junk control-character names),
/// or by one unsafe-named file that cannot be re-scanned;</item>
/// <item>the ADR 0029 decision 17 guard firing on an unattributable batch hit — which must carry both the attributed
/// hits and the unattributable one, under the target yara echoed.</item>
/// </list>
/// (The third, the default loop's per-file timeout, is the in-process path and is pinned in
/// <see cref="YaraScanDirectoryTests"/>.) What reaches the <b>report</b> from each shape is pinned separately, against
/// the pre-ADR-0032 API, in <see cref="YaraIncompleteScanReachesTheReportTests"/>.
///
/// <para>The unsafe-name shapes are Linux-gated (NTFS cannot hold the names). The decision-17 shape needs no hostile
/// name and runs everywhere.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliPartialFindingsTests
{
    #region Methods
    // Site 1a, the headline. The batch pass attributes the payload; the 65 newline-named junk files leave it for the
    // recovery pass, which scans 64 and counts the 65th unrecovered. The exception must say exactly that — and carry
    // the payload's hit, which the ScanDirectory of ADR 0029 dropped on the floor with `[.. batch, .. throw]`.
    [LinuxFact]
    public void ScanDirectory_WithAPayloadPlus65UnsafeNames_CarriesThePayloadsBatchHit()
    {
        using var tree = new TempTree();
        var payload = tree.Write("content/payload.bin", "ordinary content\n");
        for (var i = 0; i < 65; i++)
            tree.Write($"content/junk\n{i:D2}.bin", "nothing here\n");
        using var engine = new ScriptedYaraStandIn("Fake_Rule", "content/payload.bin");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 65 file(s)", ex.Message, StringComparison.Ordinal);
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
    }

    // Site 1b. One unsafe-named file is recovered (and matches — the fake echoes a hit on the copy it is handed,
    // which the scanner attributes back to the original path), one cannot even be copied (mode 000). Every hit in hand
    // travels: the batch pass's AND the recovery pass's — and nothing is credited to the file that was not scanned.
    // Non-root for the same reason as its stderr twin: root reads a mode-000 file.
    [LinuxNonRootFact]
    public void ScanDirectory_WhenOneUnsafeNamedFileCannotBeRecovered_CarriesTheBatchAndTheRecoveredHits()
    {
        using var tree = new TempTree();
        var payload = tree.Write("content/payload.bin", "ordinary content\n");
        var recovered = tree.Write("content/re\ncovered.bin", "ordinary content\n");
        var unreadable = tree.Write("content/un\nreadable.bin", "ordinary content\n");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxFact] must have gated this test to Linux.");
        File.SetUnixFileMode(unreadable, UnixFileMode.None);
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllBytes(unreadable));   // not running as root
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {payload}", echoRule: "Fake_Rule");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"un\nreadable.bin", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == payload);
        Assert.Single(ex.PartialFindings, h => h.FullPath == recovered);
        Assert.DoesNotContain(ex.PartialFindings, h => h.FullPath == unreadable);
        Assert.All(ex.PartialFindings, h => Assert.Equal("Fake_Rule", h.Match.Rule));
    }

    // Site 2, ADR 0032 decision 4. The batch pass reports a hit on a real file AND one on a sibling that does not
    // exist. The decision-17 guard still fires (the package must not read Completed), but neither hit is lost: the
    // attributed one under its file, the unattributable one under the path yara echoed — raw here, escaped at the
    // report boundary. Platform-neutral: no hostile name is involved.
    [Fact]
    public void ScanDirectory_WhenTheBatchPassReportsAnUnattributableHit_CarriesItUnderTheEchoedTargetWithTheAttributedHit()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        // As the scanner enumerates it (TempTree.Write keeps the '/' it was given, which on Windows is not the
        // separator Directory.GetFiles reports).
        var real = Path.Combine(tree.Root, "content", "real.bin");
        var ghost = Path.Combine(tree.Root, "content", "ghost.bin");   // deliberately never created
        // The probe prints "<rule> <real>" and "<rule> <real's dir>/ghost.bin" (not SILVERGUN_FAKEYARA_STDOUT, whose
        // \n decoding would mangle a Windows path segment that happens to start with 'n').
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "real.bin", batchGhost: "ghost.bin");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not be attributed to any file it enumerated", ex.Message, StringComparison.Ordinal);
        Assert.Contains("reported under the path yara echoed", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == real);
        Assert.Single(ex.PartialFindings, h => h.FullPath == ghost);
        Assert.All(ex.PartialFindings, h => Assert.Equal("Fake_Rule", h.Match.Rule));
    }

    // The sites that throw BEFORE any hit is in hand (decision 14: the batch process did not produce a usable run)
    // must not fabricate one. Pinned so that "carry every hit" cannot drift into "carry whatever was parsed from a
    // failed process's output".
    [Fact]
    public void ScanDirectory_WhenTheBatchProcessFails_CarriesNoPartialFindings()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(exitCode: 3, batchEchoRule: "Fake_Rule", batchEchoName: "real.bin");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("exited with code 3", ex.Message, StringComparison.Ordinal);
        Assert.Empty(ex.PartialFindings);
    }
    #endregion
}
