namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// JSON contract tests for the additive resolver-lite fields on <see cref="PackageCapabilityReport"/> —
/// <see cref="PackageCapabilityReport.ResolvedDependencies"/> and <see cref="PackageCapabilityReport.DependencyResolution"/>
/// (ADR 0018 / task <c>docs/agent/tasks/resolver-lite-transitive-dependencies.md</c>, Phase 2). A populated report must
/// survive <see cref="PackageCapabilityReport.ToJson"/> / <see cref="PackageCapabilityReport.FromJson"/> with its resolved
/// set + status intact, and — the back-compat guarantee — a report serialized <b>before</b> the fields existed (JSON with
/// no <c>ResolvedDependencies</c>/<c>DependencyResolution</c> property) must deserialize to an <b>empty, non-null</b> list
/// and the default <see cref="DependencyResolutionStatus.NotRun"/>, never a false Complete (mirrors
/// <see cref="PackageReportVulnerabilitiesJsonTests"/> for <c>Vulnerabilities</c>/<c>VulnerabilitiesStatus</c>).
/// </summary>
public sealed class PackageReportResolvedDependenciesJsonTests
{
    #region Methods
    // A report carrying resolved transitive nodes + a Partial status round-trips through ToJson => FromJson preserving
    // every field value (record equality over IReadOnlyList is reference-based, so compare field-wise, like the
    // Vulnerabilities round-trip test). Partial must NOT come back as Complete/NotRun — that would erase the honest
    // "coverage incomplete" signal.
    [Fact]
    public void PackageCapabilityReport_ResolvedFields_RoundTrip()
    {
        var resolved = new[]
        {
            new ResolvedDependency("Dep.Direct", "1.4.2", Depth: 1, IsDirect: true),
            new ResolvedDependency("Dep.Transitive", "2.0.0", Depth: 2, IsDirect: false),
        };
        var report = MakeReport() with
        {
            ResolvedDependencies = resolved,
            DependencyResolution = DependencyResolutionStatus.Partial,
        };

        var restored = PackageCapabilityReport.FromJson(report.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(DependencyResolutionStatus.Partial, restored!.DependencyResolution);
        Assert.Equal(2, restored.ResolvedDependencies.Count);

        var direct = restored.ResolvedDependencies[0];
        Assert.Equal("Dep.Direct", direct.Id);
        Assert.Equal("1.4.2", direct.Version);
        Assert.Equal(1, direct.Depth);
        Assert.True(direct.IsDirect);

        var transitive = restored.ResolvedDependencies[1];
        Assert.Equal("Dep.Transitive", transitive.Id);
        Assert.Equal("2.0.0", transitive.Version);
        Assert.Equal(2, transitive.Depth);
        Assert.False(transitive.IsDirect);
    }

    // The status serializes as its enum NAME (JsonStringEnumConverter), not a numeric ordinal — so the --json contract
    // stays human/tool-readable and stable across enum reordering (mirrors VulnerabilitiesStatus).
    [Fact]
    public void PackageCapabilityReport_ToJson_EmitsDependencyResolutionAsEnumName()
    {
        var json = (MakeReport() with { DependencyResolution = DependencyResolutionStatus.Partial }).ToJson();

        Assert.Contains("\"DependencyResolution\": \"Partial\"", json);
        Assert.DoesNotContain("\"DependencyResolution\": 2", json);   // never a bare ordinal
    }

    // Back-compat: OLD JSON that predates the resolver-lite fields (no ResolvedDependencies / DependencyResolution
    // properties at all) deserializes to an EMPTY, non-null list and the default NotRun status — never null, never a
    // false Complete. Mirrors the Vulnerabilities/YaraFindings back-compat guarantee.
    [Fact]
    public void PackageCapabilityReport_OldJsonWithoutResolvedFields_BackCompat()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before resolver-lite existed.",
                "Dependencies": []
              },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": []
            }
            """;

        var restored = PackageCapabilityReport.FromJson(legacyJson);

        Assert.NotNull(restored);
        Assert.NotNull(restored!.ResolvedDependencies);   // never null — the load-bearing back-compat guarantee
        Assert.Empty(restored.ResolvedDependencies);
        Assert.Equal(DependencyResolutionStatus.NotRun, restored.DependencyResolution);   // default, never a false Complete
        Assert.Equal("Legacy.Package", restored.Package.Id);   // the rest of the legacy report still deserialized
    }
    #endregion

    #region Helpers
    private static PackageCapabilityReport MakeReport() =>
        new(
            new PackageIdentityInfo("Root.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>());
    #endregion
}
