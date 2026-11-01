namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using global::NuGet.Packaging;

using Xunit;

/// <summary>
/// ADR 0035 S5 review W-1: the manifest <see cref="NuGetPackage.Open"/> exposes as <see cref="NuGetPackage.NuspecPath"/>
/// (and <see cref="PackageScanner"/> rule-scans) must be the very file NuGet read the identity from, matched ordinally
/// against <c>PackageArchiveReader.GetNuspecFile()</c> — never merely the first root <c>*.nuspec</c> on disk.
///
/// <para><b>The decoy.</b> NuGet unescapes entry names, so a root entry <c>A%2Fx.nuspec</c> (or <c>A%5Cx.nuspec</c>) is a
/// NON-root path to NuGet, which therefore still reads <c>Real.nuspec</c>. The extractor writes the decoy verbatim at
/// the root, where it sorts before the real manifest; the old first-match pick scanned the decoy, so a real manifest
/// finding vanished and the scan still read <c>Completed</c>.</para>
///
/// <para><b>The escaped-only manifest.</b> A package whose only manifest entry is <c>Real%2Enuspec</c>: NuGet reads it as
/// <c>Real.nuspec</c>, but no such file exists on disk, so <see cref="NuGetPackage.NuspecPath"/> is null and the scan is
/// <see cref="ScriptScanStatus.Unavailable"/> with the manifest reason (ADR 0035 review W1), never a Completed scan that
/// skipped the manifest.</para>
///
/// <para>The rule-matching manifest content is the existing fixture's benign pastebin <c>&lt;projectUrl&gt;</c>
/// (<see cref="PackageFixture.NuspecMatchProjectUrl"/>), in a non-prose element so it survives prose redaction. All
/// packages are built here from BCL zips; no network.</para>
/// </summary>
public sealed class NuspecManifestSelectionTests
{
    #region Methods: the decoy
    // NuGet's own view is the premise of the fix: the decoy is not a root manifest to NuGet, the real one is.
    [Theory]
    [InlineData(DecoyForwardSlash)]
    [InlineData(DecoyBackslash)]
    public void NuGetsReader_WithARootPercentEscapedDecoy_StillReadsTheRealManifest(string decoy)
    {
        using var tree = new TempTree();
        var nupkg = DecoyPackage(tree, decoy);

        using var reader = new PackageArchiveReader(nupkg);

        Assert.Equal(RealManifest, reader.GetNuspecFile());
        Assert.Equal(RealId, reader.NuspecReader.GetId());
    }

    [Theory]
    [InlineData(DecoyForwardSlash)]
    [InlineData(DecoyBackslash)]
    public void Open_WithARootPercentEscapedDecoy_SelectsTheRealManifest_NotTheDecoy(string decoy)
    {
        using var tree = new TempTree();
        var nupkg = DecoyPackage(tree, decoy);

        using var package = OpenPackage(nupkg);

        // Precondition: the decoy really reached disk at the root, verbatim, so it was a candidate.
        Assert.True(File.Exists(Path.Combine(package.ContentRoot, decoy)), $"precondition: the decoy {decoy} is on disk at the root");
        Assert.NotNull(package.NuspecPath);
        Assert.Equal(RealManifest, Path.GetFileName(package.NuspecPath));
        Assert.True(File.Exists(package.NuspecPath));
    }

    // The behaviour the fix exists for: the real manifest's finding is reported, the scan completes, and nothing is
    // attributed to the decoy.
    [Theory]
    [InlineData(DecoyForwardSlash)]
    [InlineData(DecoyBackslash)]
    public void Scan_WithARootPercentEscapedDecoy_ReportsTheRealManifestsFinding(string decoy)
    {
        using var tree = new TempTree();
        var nupkg = DecoyPackage(tree, decoy);

        var report = Scan(nupkg);

        var manifestFindings = report.ScriptFindings.Where(f => f.RelativePath == RealManifest).ToArray();
        Assert.NotEmpty(manifestFindings);
        Assert.All(manifestFindings, f => Assert.Equal(ScriptFindingSource.PackageMetadata, f.Source));
        Assert.All(manifestFindings, f => Assert.False(string.IsNullOrEmpty(f.RuleId)));
        Assert.DoesNotContain(report.ScriptFindings, f => f.RelativePath.Contains('%'));
        Assert.Equal(ScriptScanStatus.Completed, report.ScriptScanStatus);
        Assert.Null(report.ScriptScanUnavailableReason);
    }
    #endregion

    #region Methods: a manifest NuGet and the disk spell differently
    [Fact]
    public void Open_WhenTheOnlyManifestEntryIsPercentEscaped_HasANullNuspecPath()
    {
        using var tree = new TempTree();
        var nupkg = EscapedOnlyPackage(tree);
        using (var reader = new PackageArchiveReader(nupkg))
            Assert.Equal(RealManifest, reader.GetNuspecFile());   // precondition: NuGet unescapes it to Real.nuspec

        using var package = OpenPackage(nupkg);

        Assert.True(File.Exists(Path.Combine(package.ContentRoot, EscapedOnlyEntry)), "precondition: the entry is on disk verbatim");
        Assert.Null(package.NuspecPath);
    }

    // ... so the manifest is reported unscanned: Unavailable, 1 of (1 script + the manifest), with the manifest reason.
    [Fact]
    public void Scan_WhenTheOnlyManifestEntryIsPercentEscaped_IsUnavailable_WithTheManifestReason()
    {
        using var tree = new TempTree();
        var nupkg = EscapedOnlyPackage(tree);

        var report = Scan(nupkg);

        Assert.Equal(ScriptScanStatus.Unavailable, report.ScriptScanStatus);
        Assert.Equal(
            $"1 of 2 script/manifest file(s) were not scanned: '{ScriptRuleScanner.ManifestPlaceholder} ({ScriptRuleScanner.ManifestNotOnDisk})'",
            report.ScriptScanUnavailableReason);
        Assert.DoesNotContain(report.ScriptFindings, f => f.RelativePath.EndsWith("nuspec", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Methods: ordinary packages are unchanged
    // A normal package: the root manifest is selected and scanned exactly as before the fix, whatever the extension's
    // case (NuGet and the disk both keep the entry's own spelling, so the ordinal match holds).
    [Theory]
    [InlineData("Real.nuspec")]
    [InlineData("Real.NuSpec")]
    public void OpenAndScan_ForAnOrdinaryPackage_SelectAndScanTheManifest(string manifest)
    {
        using var tree = new TempTree();
        var nupkg = Package(tree, "Ordinary", [(manifest, MatchingNuspec()), (PlainScript, PlainScriptBytes)]);

        using (var package = OpenPackage(nupkg))
        {
            Assert.NotNull(package.NuspecPath);
            Assert.Equal(manifest, Path.GetFileName(package.NuspecPath));
        }
        var report = Scan(nupkg);

        Assert.Contains(report.ScriptFindings, f => f.RelativePath == manifest && f.Source == ScriptFindingSource.PackageMetadata);
        Assert.Equal(ScriptScanStatus.Completed, report.ScriptScanStatus);
    }
    #endregion

    #region Methods: helpers
    private static PackageCapabilityReport Scan(string nupkg)
    {
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private static NuGetPackage OpenPackage(string nupkg)
    {
        var open = NuGetPackage.Open(nupkg);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    // The real manifest (rule-matching) beside a root decoy entry whose name NuGet unescapes to a non-root path, plus a
    // plain script. The decoy is benign, non-matching text: under the old pick it was what got scanned.
    private static string DecoyPackage(TempTree tree, string decoy) =>
        Package(tree, "Decoy", [(RealManifest, MatchingNuspec()), (decoy, Encoding.UTF8.GetBytes("decoy")), (PlainScript, PlainScriptBytes)]);

    private static string EscapedOnlyPackage(TempTree tree) =>
        Package(tree, "EscapedOnly", [(EscapedOnlyEntry, MatchingNuspec()), (PlainScript, PlainScriptBytes)]);

    // Raw entry names, stored verbatim by ZipArchive.CreateEntry (NupkgBuilder.WriteEntry).
    private static string Package(TempTree tree, string name, (string Name, byte[] Bytes)[] entries)
    {
        var path = Path.Combine(tree.Root, $"{name}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [], entries);
        return path;
    }

    private static byte[] MatchingNuspec() => Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
        RealId, "1.0.0", "Silvergun Tests", "ADR 0035 W-1 manifest-selection test package.", "net8.0", [],
        projectUrl: PackageFixture.NuspecMatchProjectUrl));
    #endregion

    #region Fields
    private const string RealId = "Real";
    private const string RealManifest = "Real.nuspec";
    private const string DecoyForwardSlash = "A%2Fx.nuspec";
    private const string DecoyBackslash = "A%5Cx.nuspec";
    private const string EscapedOnlyEntry = "Real%2Enuspec";
    private const string PlainScript = "tools/plain.ps1";
    private static readonly byte[] PlainScriptBytes = Encoding.UTF8.GetBytes("Write-Host 'installing'\n");
    #endregion
}
