namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// JSON contract tests for the additive <see cref="PackageCapabilityReport.YaraFindings"/> field (ADR 0016 /
/// ADR 0002 / task <c>docs/agent/tasks/yara-scanning.md</c>, Phase 3). A populated report must survive
/// <see cref="PackageCapabilityReport.ToJson"/> / <see cref="PackageCapabilityReport.FromJson"/> with its YARA
/// findings intact, and — the back-compat guarantee — a report serialized <b>before</b> the field existed (JSON
/// with no <c>YaraFindings</c> property) must deserialize to an <b>empty, non-null</b> list, never <c>null</c>.
/// </summary>
public sealed class PackageReportYaraJsonTests
{
    #region Methods
    // A report carrying YARA findings round-trips through ToJson => FromJson preserving every finding (value-based).
    [Fact]
    public void PackageReport_WithYaraFindings_RoundTrips()
    {
        var findings = new[]
        {
            new YaraFinding("Win32_Trojan_Foo", "malware", "Foo", "Trojan.Win32.Foo", "MALWARE", new[] { "trojan" }, "lib/net10.0/evil.dll"),
            new YaraFinding("Bare_Rule", null, null, null, null, Array.Empty<string>(), "content/readme.txt"),
        };
        var report = MakeReport(findings);

        var restored = PackageCapabilityReport.FromJson(report.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(2, restored!.YaraFindings.Count);

        // Compare field-wise: record equality over IReadOnlyList members is reference-based, so a deserialized
        // list never equals the original array (mirrors YaraFindingJsonTests) — the field values are what matter.
        var first = restored.YaraFindings[0];
        Assert.Equal("Win32_Trojan_Foo", first.RuleName);
        Assert.Equal("malware", first.Namespace);
        Assert.Equal("Foo", first.MalwareFamily);
        Assert.Equal("Trojan.Win32.Foo", first.DetectionName);
        Assert.Equal("MALWARE", first.Category);
        Assert.Equal(new[] { "trojan" }, first.Tags);
        Assert.Equal("lib/net10.0/evil.dll", first.RelativePath);

        var second = restored.YaraFindings[1];
        Assert.Equal("Bare_Rule", second.RuleName);
        Assert.Null(second.Namespace);
        Assert.Null(second.MalwareFamily);
        Assert.Null(second.DetectionName);
        Assert.Null(second.Category);
        Assert.Empty(second.Tags);
        Assert.Equal("content/readme.txt", second.RelativePath);
    }

    // The field is present in ToJson output so a fresh report always names it (a downstream consumer can rely on it).
    [Fact]
    public void PackageReport_ToJson_EmitsYaraFindingsProperty()
    {
        var json = MakeReport(new[]
        {
            new YaraFinding("R", null, null, null, null, Array.Empty<string>(), "a.dll"),
        }).ToJson();

        Assert.Contains("\"YaraFindings\"", json);
        Assert.Contains("\"RuleName\": \"R\"", json);
    }

    // Back-compat: OLD JSON that predates the field (no YaraFindings property at all) deserializes to an EMPTY,
    // non-null list — the normalizing property initializer maps the absent constructor argument to Array.Empty.
    [Fact]
    public void PackageReport_FromLegacyJsonWithoutYaraFindings_YieldsEmptyNonNullList()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before YARA scanning existed.",
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
        Assert.NotNull(restored!.YaraFindings);   // never null — the load-bearing back-compat guarantee
        Assert.Empty(restored.YaraFindings);
        Assert.Equal("Legacy.Package", restored.Package.Id);   // the rest of the legacy report still deserialized
    }
    #endregion

    #region Helpers
    private static PackageCapabilityReport MakeReport(YaraFinding[] findings) =>
        new(
            new PackageIdentityInfo("Yara.Package", "2.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            YaraFindings: findings);
    #endregion
}
