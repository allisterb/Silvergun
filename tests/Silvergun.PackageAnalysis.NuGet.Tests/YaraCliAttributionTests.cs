namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0029 decision 15 and its amendment: <b>a package must not be able to choose which of its files a hit is
/// blamed on, and must not be able to suppress a hit by planting a colliding name.</b>
///
/// <para>The hole: excluding control-character names from batch <i>attribution</i> does not stop the collision,
/// because the truncated target of an unsafe path can equal a real, innocent, safe-named sibling. Shipping
/// <c>content/a.bin\nZZZ</c> next to a genuine <c>content/a.bin</c> made the hostile file's hit — detail lines
/// included — land on the innocent file, using nothing but names inside the attacker's own package. Merely
/// <i>rejecting</i> such hits would have handed the attacker the mirror-image trick: plant <c>a.bin\nZZZ</c> to
/// silence a genuine hit on <c>a.bin</c>. So both members of a colliding group leave the batch pass and are
/// re-scanned individually, where the target handed to yara is one we chose. Both directions are asserted
/// below.</para>
///
/// <para>These are <b>real-engine</b> tests: a fake that echoes whatever we tell it to would be asserting against
/// our own model of <c>yara -r</c> output, and this ADR exists because that model was wrong. They need a file
/// name NTFS cannot represent, so they run only under WSL — the ADR's own conclusion is that a Windows-only run
/// reports green on coverage that never executed. Set <c>SILVERGUN_REQUIRE_YARA=1</c> to make a Linux box without
/// the binary a failure rather than a skip.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliAttributionTests
{
    #region Constructors
    public YaraCliAttributionTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods
    // The demonstrated attack, in the direction the reviewer found it: the hostile entry matches, the innocent
    // sibling whose name is its truncation does not. Exactly one finding, against the hostile path, and nothing
    // whatsoever credited to the innocent file.
    [LinuxYaraFact]
    public void ScanDirectory_WhenAHostileNameTruncatesOntoAnInnocentSibling_BlamesOnlyTheRealFile()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var innocent = tree.Write("content/a.bin", "no signature here\n");
        var hostile = tree.Write("content/a.bin\nZZZ", HermeticWiperSample.Bytes);

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(hostile, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        Assert.DoesNotContain(hits, h => h.FullPath == innocent);
    }

    // The mirror image, and the reason the fix widened from "reject the colliding hit" to "re-scan both members
    // individually": the matching file is the INNOCENT one, and the hostile sibling exists only to collide with
    // its echoed name. Its coverage must survive — dropping the hit here would be a false negative bought with a
    // filename, which is the whole defect ADR 0029 is about.
    [LinuxYaraFact]
    public void ScanDirectory_WhenAHostileNameCollidesWithAMatchingInnocentFile_StillReportsTheInnocentFilesHit()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var innocent = tree.Write("content/a.bin", HermeticWiperSample.Bytes);
        tree.Write("content/a.bin\nZZZ", "no signature here\n");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(innocent, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
    }

    // The same collision without any control character at all: yara's output line is trimmed, so `x.bin` and
    // `"x.bin "` echo byte-identically. Exact-ordinal attribution alone cannot separate them — which is why the
    // partition is computed on the echoed form rather than on the raw name — and neither file may be credited
    // with the other's hit.
    [LinuxYaraFact]
    public void ScanDirectory_WhenTwoNamesDifferOnlyByTrailingWhitespace_BlamesOnlyTheMatchingFile()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var matching = tree.Write("content/x.bin", HermeticWiperSample.Bytes);
        var padded = tree.Write("content/x.bin ", "no signature here\n");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(matching, hit.FullPath);
        Assert.DoesNotContain(hits, h => h.FullPath == padded);
    }

    // Two names differing only in case. The comment here used to say they are "NOT ambiguous ... so they stay in
    // the cheap batch pass"; round 3 made that false (the partition compares echo keys with OrdinalIgnoreCase, so
    // the pair is ambiguous and both members are re-scanned individually). The ASSERTION is unchanged and is the
    // part that matters: whichever route the hit travels, it lands on the file that actually matched and the
    // other file collects nothing.
    [LinuxYaraFact]
    public void ScanDirectory_WhenTwoNamesDifferOnlyByCase_BlamesTheExactFileThatMatched()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var lower = tree.Write("content/a.bin", HermeticWiperSample.Bytes);
        var upper = tree.Write("content/A.bin", "no signature here\n");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(lower, hit.FullPath);
        Assert.DoesNotContain(hits, h => h.FullPath == upper);
    }

    // --- ADR 0029 Amendment 2 (decision 16): the two shapes the mixed comparers left open ---------------------

    // THE round-2 evasion, and it cost the attacker one empty file. Payload `content/mal.dll`; decoy
    // `content/MAL.dll\nx`, empty, matching nothing. While the partition grouped echo keys ordinally, the two keys
    // were distinct, so the payload stayed in the batch pass and remained attributable — but `forged` and the
    // attribution fallback compared case-insensitively, so the decoy's truncation `…/MAL.dll` vetoed the payload's
    // own genuine hit. Measured result: Completed, ZERO findings, on Linux, where this backend is the default and
    // filenames are case-sensitive.
    //
    // Exactly one finding, on the payload, and nothing whatsoever credited to the decoy.
    [LinuxYaraFact]
    public void ScanDirectory_WhenAnEmptyCaseOnlyDecoyEchoesThePayloadsName_StillReportsThePayloadsHit()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var payload = tree.Write("content/mal.dll", HermeticWiperSample.Bytes);
        var decoy = tree.Write("content/MAL.dll\nx", Array.Empty<byte>());

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        Assert.DoesNotContain(hits, h => h.FullPath == decoy);
    }

    // The second shape from the same amendment, and the cheaper one: NO control character anywhere. An innocent
    // `content/A.bin`, the payload `content/a.bin`, and a filler `content/a.bin ` whose only job is to be trimmed
    // onto the payload's echoed name. Under the mixed comparers the payload's hit could be credited to whichever
    // of the three attribution reached first — the package choosing who gets blamed. Under one comparer all three
    // share an echo key, all three leave the batch pass, and each is re-scanned under its own exact path.
    [LinuxYaraFact]
    public void ScanDirectory_WhenCaseAndWhitespaceVariantsCollide_BlamesOnlyThePayload()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var innocent = tree.Write("content/A.bin", "no signature here\n");
        var payload = tree.Write("content/a.bin", HermeticWiperSample.Bytes);
        var filler = tree.Write("content/a.bin ", "no signature here either\n");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        Assert.DoesNotContain(hits, h => h.FullPath == innocent || h.FullPath == filler);
    }

    // Evidence beats veto (decision 16): the `forged` set is consulted only AFTER the exact-ordinal check, because
    // an exact ordinal echo of a path we ourselves enumerated and handed to no one is the strongest evidence
    // available and must not be suppressible by a name the package chose.
    //
    // Honest note on what this can and cannot reach. Given the round-3 partition, `forged` and the attributable
    // set are provably DISJOINT: `forged` holds only the echo keys of control-character names, and any enumerated
    // file sharing an echo key with one of those is — under the same OrdinalIgnoreCase — ambiguous, hence deferred,
    // hence not attributable. So no shape staged through ScanDirectory can make the veto fire on an exact match,
    // and the ordering is defence in depth for the day the partition is narrowed again. What IS reachable, and is
    // asserted here, is the outcome the ordering exists to protect: with the veto set non-empty, an attributable
    // file's exact echo is still credited to it. Together with the two tests above, either fix alone keeps the
    // payload's finding — the ordering, or the single comparer — and both would have to regress to lose it.
    [LinuxYaraFact]
    public void ScanDirectory_WhenAnUnsafeNameFillsTheVetoSet_AnUnrelatedExactEchoIsStillCredited()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var payload = tree.Write("content/payload.bin", HermeticWiperSample.Bytes);
        tree.Write("content/decoy.bin\nx", Array.Empty<byte>());

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
    }

    // The round-2 evasion end to end, through the report the operator reads: one finding on the payload, and the
    // scan still reads Completed — a package that plays this trick and is otherwise scannable is fully covered,
    // not Unavailable. Before the fix this package produced `Completed` with an EMPTY findings list, which is the
    // single worst output this analyzer can produce.
    //
    // The payload is a .bin, not a .dll, on purpose: nothing here should route attacker-chosen bytes into the IL
    // analyzer, which is native code with its own failure modes.
    [LinuxYaraFact]
    public void Scan_PackageWithACaseOnlyDecoy_ReportsThePayloadsFindingAndCompletes()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        const string id = "PkgCaseOnlyDecoy";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", System.Text.Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "Case-only decoy regression package.",
                    "netstandard2.0", []))),
                ("content/mal.bin", HermeticWiperSample.Bytes),
            ],
            [
                ("content/MAL.bin\nx", Array.Empty<byte>()),
            ]);

        var scan = PackageScanner.Scan(nupkg, runYara: true, yaraScanner: new YaraCliScanner());

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/mal.bin", finding.RelativePath);
        Assert.Equal(HermeticWiperSample.RuleName, finding.RuleName);
    }

    // End to end, through the report: the truncation collision inside a real .nupkg (a newline is legal in a zip
    // entry name and RecursiveExtractor writes it to disk verbatim). The finding must name the hostile entry,
    // once, and the scan must still read Completed — a package that plays this trick and is otherwise scannable
    // is fully covered, not Unavailable.
    [LinuxYaraFact]
    public void Scan_PackageWhoseHostileEntryTruncatesOntoASibling_ReportsOneFindingAgainstTheHostileEntry()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        const string id = "PkgTruncationCollision";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", System.Text.Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "Truncation-collision regression package.",
                    "netstandard2.0", []))),
                ("content/a.bin", System.Text.Encoding.UTF8.GetBytes("no signature here\n")),
            ],
            [
                ("content/a.bin\nZZZ", HermeticWiperSample.Bytes),
            ]);

        var scan = PackageScanner.Scan(nupkg, runYara: true, yaraScanner: new YaraCliScanner());

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/a.bin\nZZZ", finding.RelativePath);
        Assert.Equal(HermeticWiperSample.RuleName, finding.RuleName);
    }
    #endregion
}
