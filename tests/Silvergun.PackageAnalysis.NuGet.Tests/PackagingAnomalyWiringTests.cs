namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using Xunit;

/// <summary>
/// End-to-end wiring for ADR 0031: a real <c>.nupkg</c> on disk → <see cref="NuGetPackage.DeclaredEntryNames"/> →
/// <see cref="PackageEntryNameAnalyzer"/> → <see cref="PackageCapabilityReport.PackagingAnomalies"/>. The analyzer's
/// own behaviour is covered exhaustively (and platform-independently) in
/// <see cref="PackageEntryNameAnalyzerTests"/>; what is asserted here is that the pipeline actually carries the
/// finding — the ADR exists because a detection that WAS being made was being silently discarded.
///
/// <para><b>Why the hostile names here are milder than the analyzer's.</b> These packages are really extracted, and
/// Windows rejects a filename containing a character below U+0020 outright — which is exactly why ADR 0029's
/// control-character tests are Linux-gated. Extraction is not what ADR 0031 is about, so the fixtures below use
/// hostile names every platform can materialize (bidi override, zero-width, case-only collision, trailing dot, and
/// PkgD's real <c>../../</c> zip-slip entry). A reserved device name is deliberately NOT packaged: creating
/// <c>content\CON.txt</c> on Windows opens the console device, which would be a test that breaks the test host
/// rather than one that covers the analyzer.</para>
/// </summary>
public sealed class PackagingAnomalyWiringTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public PackagingAnomalyWiringTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — DeclaredEntryNames is the ground truth the analyzer reads
    // The declared list is UNFILTERED: PkgD's zip-slip entry is present in it even though the extraction inventory
    // (correctly) refuses to inventory the corresponding file. That is the exact defect ADR 0031 fixes — the
    // detection used to be made and then thrown away, so the name has to survive the containment filter to be
    // reportable at all.
    [Fact]
    public void Open_PkgD_KeepsTheZipSlipEntryInDeclaredEntryNames_ThoughItIsNeverInventoried()
    {
        var opened = NuGetPackage.Open(fixture.PkgDPath);
        Assert.True(opened.IsSuccess, opened.Message);
        using var package = opened.Value;

        Assert.Contains(fixture.ZipSlipRelativeEntry, package.DeclaredEntryNames);
        Assert.DoesNotContain(
            package.Assemblies,
            a => a.RelativePath.EndsWith(fixture.ZipSlipFileName, StringComparison.Ordinal));
    }

    // A benign package's declared names are exactly what was written into the archive, in archive order — the
    // analyzer's input is the central directory, not the extracted tree.
    [Fact]
    public void Open_PkgA_ExposesEveryDeclaredEntryNameVerbatim()
    {
        var opened = NuGetPackage.Open(fixture.PkgAPath);
        Assert.True(opened.IsSuccess, opened.Message);
        using var package = opened.Value;

        Assert.Contains($"{PackageFixture.PkgAId}.nuspec", package.DeclaredEntryNames);
        Assert.Contains($"lib/netstandard2.0/{fixture.FixtureDllName}", package.DeclaredEntryNames);
        Assert.Contains("tools/init.ps1", package.DeclaredEntryNames);
        Assert.Contains("content/notmanaged.dll", package.DeclaredEntryNames);
    }
    #endregion

    #region Methods — the report carries the anomalies
    // The zip-slip entry ADR 0008 detects and discards is now REPORTED, once, as a PathTraversal anomaly naming it.
    [Fact]
    public void Scan_PkgD_ReportsTheZipSlipEntryAsAPathTraversalAnomaly()
    {
        var scan = PackageScanner.Scan(fixture.PkgDPath, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        var anomaly = Assert.Single(scan.Value.PackagingAnomalies);
        Assert.Equal(PackagingAnomalyCategory.PathTraversal, anomaly.Category);
        Assert.Equal(fixture.ZipSlipRelativeEntry, anomaly.EntryName);
    }

    // A package with several hostile names produces one anomaly per (entry, category), carried on the report.
    [Fact]
    public void Scan_PackageWithHostileEntryNames_CarriesEveryAnomalyOnTheReport()
    {
        using var tree = new TempTree();
        var nupkg = BuildHostileNupkg(tree);

        var scan = PackageScanner.Scan(nupkg, runYara: false);

        Assert.True(scan.IsSuccess, scan.Message);
        var anomalies = scan.Value.PackagingAnomalies;

        var bidi = Assert.Single(anomalies, a => a.Category == PackagingAnomalyCategory.BidiControl);
        Assert.Equal(@"content/gnp\u202ecod.bin", bidi.EntryName);

        var invisible = Assert.Single(anomalies, a => a.Category == PackagingAnomalyCategory.InvisibleCharacter);
        Assert.Contains("U+200B", invisible.Detail, StringComparison.Ordinal);

        var collision = Assert.Single(anomalies, a => a.Category == PackagingAnomalyCategory.CaseOnlyCollision);
        Assert.Equal("content/Same.bin", collision.EntryName);
        Assert.Contains("content/same.bin", collision.Detail, StringComparison.Ordinal);

        var trailing = Assert.Single(anomalies, a => a.Category == PackagingAnomalyCategory.TrailingSpaceOrDot);
        Assert.Equal("content/trailing.bin.", trailing.EntryName);

        Assert.Single(anomalies, a => a.Category == PackagingAnomalyCategory.PathTraversal);
    }

    // The false-positive guard, end to end and over real archives: the benign fixture packages — including PkgE,
    // whose entries deliberately use BACKSLASH separators as some Windows packing tools emit — must report NOTHING.
    // A category that fires on an ordinary package is a bug in the category (ADR 0031), and this is where that
    // would show up against archives the rest of the suite already treats as clean.
    [Theory]
    [InlineData("A")]
    [InlineData("B")]
    [InlineData("C")]
    [InlineData("E")]
    [InlineData("Script")]
    public void Scan_BenignFixturePackages_ReportNoPackagingAnomalies(string which)
    {
        var path = which switch
        {
            "A" => fixture.PkgAPath,
            "B" => fixture.PkgBPath,
            "C" => fixture.PkgCPath,
            "E" => fixture.PkgEPath,
            "Script" => fixture.PkgScriptPath,
            _ => throw new ArgumentOutOfRangeException(nameof(which)),
        };

        var scan = PackageScanner.Scan(path, runYara: false);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Empty(scan.Value.PackagingAnomalies);
    }

    // A report built without the field (the offline default, and every report produced before ADR 0031) exposes an
    // EMPTY, non-null list — the renderer's "(none)" path must never be a NullReferenceException.
    [Fact]
    public void PackageCapabilityReport_WithoutPackagingAnomalies_ExposesAnEmptyNonNullList()
    {
        var report = new PackageCapabilityReport(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>());

        Assert.NotNull(report.PackagingAnomalies);
        Assert.Empty(report.PackagingAnomalies);
    }
    #endregion

    #region Methods — fixtures
    // A .nupkg whose entry names carry a bidi override, a zero-width space, a case-only collision, a trailing dot
    // and a zip-slip traversal. Every one of these names is materializable on Windows AND Linux (see the class
    // summary for what is deliberately absent and why).
    private static string BuildHostileNupkg(TempTree tree)
    {
        const string id = "PkgHostileNames";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        var payload = Encoding.UTF8.GetBytes("not an assembly\n");

        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "Hostile-entry-name regression package (ADR 0031).",
                    "netstandard2.0", []))),
                ("content/gnp\u202Ecod.bin", payload),
                ("content/zero\u200Bwidth.bin", payload),
                ("content/Same.bin", payload),
                ("content/same.bin", payload),
                ("content/trailing.bin.", payload),
            ],
            [
                ($"../../silvergun-adr0031-{Guid.NewGuid():N}.bin", payload),
            ]);
        return nupkg;
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;
    #endregion
}
