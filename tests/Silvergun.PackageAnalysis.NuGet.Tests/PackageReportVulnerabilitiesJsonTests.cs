namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// JSON contract tests for the additive <see cref="PackageCapabilityReport.Vulnerabilities"/> field (ADR 0017 /
/// ADR 0002 / task <c>docs/agent/tasks/osv-vulnerability-intel.md</c>, Phase 2). A populated report must survive
/// <see cref="PackageCapabilityReport.ToJson"/> / <see cref="PackageCapabilityReport.FromJson"/> with its
/// vulnerability findings intact, and — the back-compat guarantee — a report serialized <b>before</b> the field
/// existed (JSON with no <c>Vulnerabilities</c> property) must deserialize to an <b>empty, non-null</b> list, never
/// <c>null</c> (mirrors <see cref="PackageReportYaraJsonTests"/> for <c>YaraFindings</c>).
/// </summary>
public sealed class PackageReportVulnerabilitiesJsonTests
{
    #region Methods
    // A report carrying vulnerability findings round-trips through ToJson => FromJson preserving every field.
    [Fact]
    public void PackageReport_WithVulnerabilities_RoundTrips()
    {
        var findings = new[]
        {
            new VulnerabilityFinding(
                "GHSA-xxxx-yyyy-zzzz",
                new[] { "CVE-2024-21907" },
                "A deserialization vulnerability.",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "Vuln.Package",
                "2.0.0",
                false,
                new[] { "https://example.test/advisory" }),
            new VulnerabilityFinding(
                "GHSA-dep0-dep0-dep0",
                Array.Empty<string>(),
                null,
                null,
                "Some.Dependency",
                "1.0.0",
                true,
                Array.Empty<string>()),
        };
        var report = MakeReport(findings);

        var restored = PackageCapabilityReport.FromJson(report.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(2, restored!.Vulnerabilities.Count);

        // Compare field-wise: record equality over IReadOnlyList members is reference-based, so a deserialized
        // list never equals the original array — the field VALUES are what the JSON contract guarantees.
        var first = restored.Vulnerabilities[0];
        Assert.Equal("GHSA-xxxx-yyyy-zzzz", first.Id);
        Assert.Equal(new[] { "CVE-2024-21907" }, first.Aliases);
        Assert.Equal("A deserialization vulnerability.", first.Summary);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", first.Severity);
        Assert.Equal("Vuln.Package", first.PackageId);
        Assert.Equal("2.0.0", first.PackageVersion);
        Assert.False(first.IsDependency);
        Assert.Equal(new[] { "https://example.test/advisory" }, first.References);

        var second = restored.Vulnerabilities[1];
        Assert.Equal("GHSA-dep0-dep0-dep0", second.Id);
        Assert.Empty(second.Aliases);
        Assert.Null(second.Summary);
        Assert.Null(second.Severity);
        Assert.Equal("Some.Dependency", second.PackageId);
        Assert.Equal("1.0.0", second.PackageVersion);
        Assert.True(second.IsDependency);
        Assert.Empty(second.References);
    }

    // A fresh report always names the field, so a downstream JSON consumer can rely on it being present.
    [Fact]
    public void PackageReport_ToJson_EmitsVulnerabilitiesProperty()
    {
        var json = MakeReport(new[]
        {
            new VulnerabilityFinding("GHSA-a", Array.Empty<string>(), null, null, "P", "1.0.0", false, Array.Empty<string>()),
        }).ToJson();

        Assert.Contains("\"Vulnerabilities\"", json);
        Assert.Contains("\"Id\": \"GHSA-a\"", json);
    }

    // Back-compat: OLD JSON that predates the field (no Vulnerabilities property at all) deserializes to an EMPTY,
    // non-null list — the normalizing property initializer maps the absent constructor argument to Array.Empty.
    [Fact]
    public void PackageReport_FromLegacyJsonWithoutVulnerabilities_YieldsEmptyNonNullList()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before OSV intel existed.",
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
        Assert.NotNull(restored!.Vulnerabilities);   // never null — the load-bearing back-compat guarantee
        Assert.Empty(restored.Vulnerabilities);
        Assert.Equal("Legacy.Package", restored.Package.Id);   // the rest of the legacy report still deserialized
    }
    #endregion

    #region Helpers
    private static PackageCapabilityReport MakeReport(VulnerabilityFinding[] findings) =>
        new(
            new PackageIdentityInfo("Vuln.Package", "2.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            Vulnerabilities: findings);
    #endregion
}
