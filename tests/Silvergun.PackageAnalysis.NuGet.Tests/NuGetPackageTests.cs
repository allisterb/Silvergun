namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.IO;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// NuGet package intake (ADR 0004, increment 1): open a local <c>.nupkg</c>, inventory its
/// assemblies and scripts, and run the CIL capability scan over each managed assembly. Covers the
/// eight cases in <c>docs/agent/tasks/nupkg-intake.md</c>. Packages are staged by
/// <see cref="PackageFixture"/> from real BCL-built zips.
/// </summary>
public sealed class NuGetPackageTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public NuGetPackageTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // Case 1 — identity + declared dependencies.
    [Fact]
    public void Open_PkgA_ExposesIdentityAndDependencies()
    {
        using var pkg = OpenPkgA();

        Assert.Equal(PackageFixture.PkgAId, pkg.Identity.Id);
        Assert.Equal(PackageFixture.PkgAVersion, pkg.Identity.Version);
        Assert.Equal(PackageFixture.PkgAAuthors, pkg.Identity.Authors);
        Assert.Equal(PackageFixture.PkgADescription, pkg.Identity.Description);

        Assert.Equal(2, pkg.Identity.Dependencies.Count);
        foreach (var (id, _) in PackageFixture.DependencyIds)
            Assert.Contains(pkg.Identity.Dependencies, d => d.Id == id);
    }

    // Case 2 — assemblies inventory (role/TFM/sha256) and scripts inventory.
    [Fact]
    public void Open_PkgA_InventoriesAssembliesAndScripts()
    {
        using var pkg = OpenPkgA();

        var lib = pkg.Assemblies.Single(a => Norm(a.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));
        Assert.Equal(PackageItemRole.Lib, lib.Role);
        Assert.Equal("netstandard2.0", lib.TargetFramework);
        Assert.Equal(fixture.ExpectedFixtureSha256, lib.Sha256);
        Assert.Matches("^[0-9a-f]{64}$", lib.Sha256);

        var content = pkg.Assemblies.Single(a => Norm(a.RelativePath).EndsWith("/notmanaged.dll", StringComparison.Ordinal));
        Assert.Equal(PackageItemRole.Content, content.Role);

        var initScript = pkg.Scripts.Single(s => Norm(s.RelativePath).EndsWith("/init.ps1", StringComparison.Ordinal));
        Assert.Equal(PackageItemRole.Tools, initScript.Role);

        var targets = pkg.Scripts.Single(s => Norm(s.RelativePath).EndsWith(".targets", StringComparison.Ordinal));
        Assert.Equal(PackageItemRole.Build, targets.Role);
    }

    // Case 3 — extraction dir lifecycle: files present, gone after Dispose, double-Dispose is safe.
    [Fact]
    public void Open_PkgA_ExtractsToDisk_AndDisposeCleansUpIdempotently()
    {
        var open = NuGetPackage.Open(fixture.PkgAPath);
        Assert.True(open.IsSuccess, open.Message);
        var pkg = open.Value;

        Assert.True(Directory.Exists(pkg.ExtractionDir));
        var lib = pkg.Assemblies.Single(a => Norm(a.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));
        Assert.True(File.Exists(lib.FullPath));
        Assert.StartsWith(pkg.ExtractionDir, lib.FullPath, StringComparison.Ordinal);

        pkg.Dispose();
        Assert.False(Directory.Exists(pkg.ExtractionDir));

        var ex = Record.Exception(() => pkg.Dispose());
        Assert.Null(ex);
    }

    // Case 4 — Open failure paths return a failure Result, never throw.
    [Fact]
    public void Open_NonexistentPath_ReturnsFailure()
    {
        var result = Record.Exception(() =>
        {
            var r = NuGetPackage.Open(fixture.MissingNupkgPath);
            Assert.False(r.IsSuccess);
        });
        Assert.Null(result);
    }

    [Fact]
    public void Open_FakeTextNupkg_ReturnsFailure()
    {
        var result = Record.Exception(() =>
        {
            var r = NuGetPackage.Open(fixture.FakeTextNupkgPath);
            Assert.False(r.IsSuccess);
        });
        Assert.Null(result);
    }

    // Case 5 — end-to-end scan: lib dll is analyzed (FileSystem finding), fake native dll is skipped.
    [Fact]
    public void Scan_PkgA_AnalyzesManagedLib_AndSkipsNativeContent()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath);
        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;

        var libResult = report.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));
        Assert.NotNull(libResult.Report);
        Assert.Null(libResult.SkipReason);
        Assert.Contains(
            libResult.Report!.Findings,
            f => f.Capability == Capability.FileSystem && f.CallerType.EndsWith("SensitiveOps", StringComparison.Ordinal));

        var contentResult = report.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith("/notmanaged.dll", StringComparison.Ordinal));
        Assert.Null(contentResult.Report);
        Assert.False(string.IsNullOrWhiteSpace(contentResult.SkipReason));
    }

    // Case 6 — empty package scans clean.
    [Fact]
    public void Scan_PkgB_SucceedsWithNoAssembliesOrFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath);
        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;

        Assert.Empty(report.Assemblies);
        Assert.Empty(report.AllFindings);
    }

    // Case 7 — JSON round-trip preserves identity, per-assembly reports, scripts, skip reasons; enums by name.
    [Fact]
    public void PackageReport_JsonRoundTrip_PreservesReportAndUsesEnumNames()
    {
        var report = PackageScanner.Scan(fixture.PkgAPath).Value;

        var json = report.ToJson();
        var restored = PackageCapabilityReport.FromJson(json);

        Assert.NotNull(restored);

        // Package identity.
        Assert.Equal(report.Package.Id, restored!.Package.Id);
        Assert.Equal(report.Package.Version, restored.Package.Version);
        Assert.Equal(report.Package.Authors, restored.Package.Authors);
        Assert.Equal(report.Package.Description, restored.Package.Description);
        Assert.Equal(report.Package.Dependencies, restored.Package.Dependencies);

        // Scripts (scalar records -> value equality).
        Assert.Equal(report.Scripts, restored.Scripts);

        // Per-assembly results, element-wise.
        Assert.Equal(report.Assemblies.Count, restored.Assemblies.Count);
        foreach (var (a, b) in report.Assemblies.Zip(restored.Assemblies))
        {
            Assert.Equal(a.Assembly, b.Assembly);        // scalar record
            Assert.Equal(a.SkipReason, b.SkipReason);
            if (a.Report is null)
            {
                Assert.Null(b.Report);
            }
            else
            {
                Assert.NotNull(b.Report);
                Assert.Equal(a.Report.AssemblyName, b.Report!.AssemblyName);
                Assert.Equal(a.Report.Findings, b.Report.Findings);
            }
        }

        // The [JsonIgnore] AllFindings must recompute identically off the restored per-assembly reports.
        Assert.Equal(report.AllFindings.ToArray(), restored.AllFindings.ToArray());

        // Enums serialized as names, not numbers.
        Assert.Contains("\"FileSystem\"", json);
        Assert.Contains("\"Content\"", json);
        Assert.DoesNotMatch(new Regex("\"Role\"\\s*:\\s*\\d"), json);
        Assert.DoesNotMatch(new Regex("\"Capability\"\\s*:\\s*\\d"), json);
    }

    // Case 8 — AllFindings is the ordered concatenation of the non-null per-assembly findings.
    [Fact]
    public void AllFindings_FlattensNonNullPerAssemblyFindingsInOrder()
    {
        var report = PackageScanner.Scan(fixture.PkgAPath).Value;

        var expected = report.Assemblies
            .Where(a => a.Report is not null)
            .SelectMany(a => a.Report!.Findings)
            .ToArray();

        Assert.Equal(expected, report.AllFindings.ToArray());
    }

    // Gap 1a — ADR 0004 §3 (amended): a root-level dll (no folder segment) must be inventoried as
    // Role=Other with a null TargetFramework, not silently dropped.
    [Fact]
    public void Open_PkgC_InventoriesRootLevelDll_AsOtherRoleWithNullTargetFramework()
    {
        using var pkg = OpenPkgC();

        var hidden = pkg.Assemblies.Single(
            a => Norm(a.RelativePath).EndsWith($"/{PackageFixture.HiddenDllName}", StringComparison.Ordinal)
                 || Norm(a.RelativePath) == PackageFixture.HiddenDllName);

        Assert.Equal(PackageItemRole.Other, hidden.Role);
        Assert.Null(hidden.TargetFramework);
        Assert.Equal(fixture.ExpectedFixtureSha256, hidden.Sha256);
    }

    // Gap 1b — the Role=Other root-level dll must actually be scanned: managed load succeeds (Report
    // non-null, no SkipReason) and SensitiveOps findings surface.
    [Fact]
    public void Scan_PkgC_AnalyzesOtherRoleRootDll_WithSensitiveOpsFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgCPath);
        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;

        var hidden = report.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith($"/{PackageFixture.HiddenDllName}", StringComparison.Ordinal)
                 || Norm(a.Assembly.RelativePath) == PackageFixture.HiddenDllName);

        Assert.Equal(PackageItemRole.Other, hidden.Assembly.Role);
        Assert.NotNull(hidden.Report);
        Assert.Null(hidden.SkipReason);
        Assert.Contains(
            hidden.Report!.Findings,
            f => f.CallerType.EndsWith("SensitiveOps", StringComparison.Ordinal));
    }

    // Gap 2 — runtimes/<rid>/lib/<tfm>/<dll> must be inventoried as Role=Runtimes with the TFM parsed
    // from the 4th path segment.
    [Fact]
    public void Open_PkgC_ParsesRuntimesTargetFramework()
    {
        using var pkg = OpenPkgC();

        var runtime = pkg.Assemblies.Single(a => Norm(a.RelativePath).StartsWith("runtimes/", StringComparison.Ordinal));

        Assert.Equal(PackageItemRole.Runtimes, runtime.Role);
        Assert.Equal("net6.0", runtime.TargetFramework);
        Assert.Contains("win-x64", Norm(runtime.RelativePath), StringComparison.Ordinal);
    }

    // Gap 3 — a build/*.props file must be recorded as a script with Role=Build (ADR 0004 §4).
    [Fact]
    public void Open_PkgC_InventoriesPropsScript_AsBuild()
    {
        using var pkg = OpenPkgC();

        var props = pkg.Scripts.Single(s => Norm(s.RelativePath).EndsWith(".props", StringComparison.Ordinal));

        Assert.Equal(PackageItemRole.Build, props.Role);
    }

    // Zip-slip regression — a package entry whose name escapes the extraction dir via "../../" must be
    // skipped: not written outside the sandbox, not inventoried. The benign lib alongside it is unaffected.
    [Fact]
    public void Open_PkgD_SkipsZipSlipEntry_AndExtractsBenignLibOnly()
    {
        using var pkg = OpenPkgD();

        var root = Path.GetFullPath(pkg.ExtractionDir);
        if (!root.EndsWith(Path.DirectorySeparatorChar))
            root += Path.DirectorySeparatorChar;

        // (a) Every inventoried assembly resolves strictly under the extraction directory.
        foreach (var assembly in pkg.Assemblies)
        {
            var resolved = Path.GetFullPath(assembly.FullPath);
            Assert.StartsWith(root, resolved, StringComparison.Ordinal);
        }

        // (a') The malicious entry was never inventoried.
        Assert.DoesNotContain(
            pkg.Assemblies,
            a => Norm(a.RelativePath).EndsWith($"/{fixture.ZipSlipFileName}", StringComparison.Ordinal)
                 || Norm(a.RelativePath).Contains(fixture.ZipSlipFileName, StringComparison.Ordinal));

        // (b) The traversal target on disk (../../<file> relative to the extraction dir) was never written.
        var strayTarget = Path.GetFullPath(Path.Combine(pkg.ExtractionDir, fixture.ZipSlipRelativeEntry));
        Assert.False(File.Exists(strayTarget), $"Zip-slip entry escaped to {strayTarget}.");

        // (c) The benign lib dll is inventoried and present on disk inside the sandbox.
        var lib = pkg.Assemblies.Single(
            a => Norm(a.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));
        Assert.Equal(PackageItemRole.Lib, lib.Role);
        Assert.True(File.Exists(lib.FullPath));
        Assert.StartsWith(root, Path.GetFullPath(lib.FullPath), StringComparison.Ordinal);
    }

    private NuGetPackage OpenPkgA()
    {
        var open = NuGetPackage.Open(fixture.PkgAPath);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private NuGetPackage OpenPkgC()
    {
        var open = NuGetPackage.Open(fixture.PkgCPath);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private NuGetPackage OpenPkgD()
    {
        var open = NuGetPackage.Open(fixture.PkgDPath);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private static string Norm(string path) => path.Replace('\\', '/');
    #endregion

    #region Fields
    private readonly PackageFixture fixture;
    #endregion
}
