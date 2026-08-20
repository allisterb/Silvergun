namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/indicator-cli-integration.md</c>, the <see cref="PackageScanner"/> half: <see cref="AssemblyScanResult.Indicators"/>
/// follows the exact same best-effort posture as <see cref="AssemblyScanResult.Obfuscation"/> (ADR 0010) —
/// populated off the same loaded <see cref="AssemblyAnalyzer"/> on the success branch, and left <c>null</c> when the
/// assembly could not even be loaded. Mirrors <c>NuGetPackageTests.Scan_PkgA_PopulatesObfuscationForManagedLib_AndNullForNativeContent</c>
/// exactly, one member over.
/// <para>
/// <b>Deliberately not covered here (and stated, not papered over):</b> the THIRD branch —
/// <c>AssemblyScanResult.Report is null because <see cref="CapabilityAnalysis"/>.Analyze() itself threw</c> (as
/// opposed to <see cref="AssemblyAnalyzer.Load"/> failing) — is currently unreachable from any fixture in this repo
/// without crafting a hostile/corrupt module. <c>CapabilityAnalysis.Analyze()</c>'s own doc comment locates that
/// failure at "Enumerating assembly.Methods advances CCI's lazy type resolution, which can throw on a corrupt/
/// hostile module" — CCI's <c>Debug.Assert</c> on such input routes to <c>Environment.FailFast</c> (ADR 0021,
/// measured exit 35), so deliberately constructing that input to chase this one branch risks taking the whole test
/// host down for a branch whose <c>Indicators</c> handling is, by construction (<see cref="PackageScanner.ScanAssembly"/>
/// computes <c>indicators</c> once, BEFORE calling <see cref="CapabilityAnalysis"/>, and passes the same local into
/// both arms of its <c>analysis.IsSuccess ? … : …</c>), unable to differ from the success branch this file DOES
/// cover. Per-method body failures (the closer, SAFE analogue) are counted and skipped rather than fatal since
/// <c>docs/agent/tasks/per-method-body-read-granularity.md</c>, so they do not reach this branch either.
/// </para>
/// </summary>
public sealed class PackageScannerIndicatorTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public PackageScannerIndicatorTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — H: success branch and Load-failure branch
    // Success branch: Scan runs IndicatorAnalysis off the SAME loaded analyzer per managed assembly, so the
    // managed lib's AssemblyScanResult.Indicators is a non-null report (findings may be empty; the point is
    // best-effort, no-throw population) — the load-failure native content dll (not a loadable managed assembly)
    // has a null Indicators alongside its existing SkipReason, exactly like its null Obfuscation.
    [Fact]
    public void Scan_PkgA_PopulatesIndicatorsForManagedLib_AndNullForNativeContent()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath);
        Assert.True(scan.IsSuccess, scan.Message);

        var libResult = scan.Value.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));
        Assert.NotNull(libResult.Indicators);
        Assert.NotNull(libResult.Indicators!.Findings);
        Assert.Equal(fixture.FixtureAssemblyName, libResult.Indicators.AssemblyName);

        var contentResult = scan.Value.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith("/notmanaged.dll", StringComparison.Ordinal));
        Assert.Null(contentResult.Indicators);
        Assert.False(string.IsNullOrWhiteSpace(contentResult.SkipReason));
    }

    // The real fixture assembly (IndicatorPayloads) carries genuine findings across several categories, so this
    // is not merely "an empty report was attached" — the analysis actually ran and found what is really there,
    // including a discriminating category (CallbackDomain: "x.pipedream.net").
    [Fact]
    public void Scan_PkgA_IndicatorsForManagedLib_ContainsRealFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath);
        Assert.True(scan.IsSuccess, scan.Message);

        var libResult = scan.Value.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));

        Assert.Contains(
            libResult.Indicators!.Findings,
            f => f.Category == IndicatorCategory.CallbackDomain && f.Value == "x.pipedream.net");
    }

    // resolveReferences has no bearing on indicator analysis (it reads string constants, not references) — the
    // same posture Obfuscation already has for this flag.
    [Fact]
    public void Scan_PkgA_WithoutResolution_StillPopulatesIndicatorsForManagedLib()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false);
        Assert.True(scan.IsSuccess, scan.Message);

        var libResult = scan.Value.Assemblies.Single(
            a => Norm(a.Assembly.RelativePath).EndsWith($"/{fixture.FixtureDllName}", StringComparison.Ordinal));
        Assert.NotNull(libResult.Indicators);
    }
    #endregion

    #region Methods — G: JSON round-trip (the package half — AssemblyScanResult.Indicators inside PackageCapabilityReport)
    [Fact]
    public void PackageReport_JsonRoundTrip_PreservesIndicators()
    {
        var report = PackageScanner.Scan(fixture.PkgAPath).Value;

        var json = report.ToJson();
        var restored = PackageCapabilityReport.FromJson(json);
        Assert.NotNull(restored);

        foreach (var (a, b) in report.Assemblies.Zip(restored!.Assemblies))
        {
            if (a.Indicators is null)
            {
                Assert.Null(b.Indicators);
            }
            else
            {
                Assert.NotNull(b.Indicators);
                Assert.Equal(a.Indicators.AssemblyName, b.Indicators!.AssemblyName);
                Assert.Equal(a.Indicators.Truncated, b.Indicators.Truncated);
                Assert.Equal(a.Indicators.Findings, b.Indicators.Findings);   // record equality per finding
            }
        }

        // Not vacuous: at least one assembly in PkgA really does carry a non-null, non-empty Indicators report.
        Assert.Contains(report.Assemblies, a => a.Indicators is { Findings.Count: > 0 });

        // Enums still written as names, not numbers (mirrors the existing PackageReport_JsonRoundTrip... assertion
        // for Role/Capability) — IndicatorCategory is exactly the same kind of append-only enum (ADR 0019 decision 5).
        Assert.Contains("\"CallbackDomain\"", json);
        Assert.DoesNotMatch(
            new System.Text.RegularExpressions.Regex("\"Category\"\\s*:\\s*\\d"), json);
    }

    // A package with NO managed assemblies at all (PkgB) round-trips with an empty Assemblies list — the
    // degenerate case that would otherwise let a null-vs-missing distinction hide inside a Zip over nothing.
    [Fact]
    public void PackageReport_JsonRoundTrip_WithNoAssemblies_RoundTripsCleanly()
    {
        var report = PackageScanner.Scan(fixture.PkgBPath).Value;
        Assert.Empty(report.Assemblies);

        var restored = PackageCapabilityReport.FromJson(report.ToJson());

        Assert.NotNull(restored);
        Assert.Empty(restored!.Assemblies);
    }

    // The exact hazard AssemblyScanResult's own doc comment names for Indicators (mirroring the report-level one
    // in AssemblyAnalysisReport): JSON written before Indicators existed — no such property at all on the
    // Assemblies[i] object — must still deserialize, reading identically to "the analysis was never attempted".
    [Fact]
    public void PackageCapabilityReport_LegacyJsonWithoutIndicatorsProperty_DeserializesWithIndicatorsNull()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before the Indicators field existed.",
                "Dependencies": []
              },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [
                {
                  "Assembly": {
                    "RelativePath": "lib/net10.0/Legacy.dll",
                    "FullPath": "/x/lib/net10.0/Legacy.dll",
                    "TargetFramework": "net10.0",
                    "Role": "Lib",
                    "Sha256": "abc123"
                  },
                  "Report": null,
                  "SkipReason": null,
                  "Metadata": null,
                  "Obfuscation": null
                }
              ],
              "Scripts": [],
              "ScriptFindings": []
            }
            """;

        var restored = PackageCapabilityReport.FromJson(legacyJson);

        Assert.NotNull(restored);
        var assembly = Assert.Single(restored!.Assemblies);
        Assert.Null(assembly.Indicators);
        Assert.Equal("lib/net10.0/Legacy.dll", assembly.Assembly.RelativePath);
    }
    #endregion

    #region Methods — helpers
    private static string Norm(string path) => path.Replace('\\', '/');
    #endregion

    #region Fields
    private readonly PackageFixture fixture;
    #endregion
}
