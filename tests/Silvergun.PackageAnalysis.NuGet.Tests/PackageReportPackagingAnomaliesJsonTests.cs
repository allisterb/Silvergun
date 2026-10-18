namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.Text.Json;

using Xunit;

/// <summary>
/// JSON contract tests for the additive <see cref="PackageCapabilityReport.PackagingAnomalies"/> field (ADR 0031 /
/// ADR 0002), mirroring <see cref="PackageReportYaraJsonTests"/> exactly one member over. Three guarantees:
/// a populated report round-trips with its anomalies intact; the category serializes as its NAME (a consumer reads
/// <c>"BidiControl"</c>, not <c>1</c>, and an enum reordering must not silently renumber a published contract); and
/// a report serialized BEFORE the field existed deserializes to an empty, non-null list.
/// </summary>
public sealed class PackageReportPackagingAnomaliesJsonTests
{
    #region Methods
    // A report carrying anomalies round-trips through ToJson => FromJson preserving every field (value-based).
    [Fact]
    public void PackageReport_WithPackagingAnomalies_RoundTrips()
    {
        var anomalies = new[]
        {
            new PackagingAnomaly(PackagingAnomalyCategory.ControlCharacter, @"content/pay\nload.bin", "contains control character(s) U+000A"),
            new PackagingAnomaly(PackagingAnomalyCategory.PathTraversal, "../../evil.dll", "entry target escapes the package content root (zip slip)"),
        };

        var restored = PackageCapabilityReport.FromJson(MakeReport(anomalies).ToJson());

        Assert.NotNull(restored);
        Assert.Equal(2, restored!.PackagingAnomalies.Count);

        // Field-wise, like the YARA equivalent: record equality over IReadOnlyList members is reference-based, so a
        // deserialized list never equals the original array — the field values are what matter.
        var first = restored.PackagingAnomalies[0];
        Assert.Equal(PackagingAnomalyCategory.ControlCharacter, first.Category);
        Assert.Equal(@"content/pay\nload.bin", first.EntryName);
        Assert.Equal("contains control character(s) U+000A", first.Detail);

        var second = restored.PackagingAnomalies[1];
        Assert.Equal(PackagingAnomalyCategory.PathTraversal, second.Category);
        Assert.Equal("../../evil.dll", second.EntryName);
    }

    // The field is present in ToJson output, with the category written as its NAME.
    [Fact]
    public void PackageReport_ToJson_EmitsPackagingAnomaliesWithTheCategoryAsAName()
    {
        var json = MakeReport(
        [
            new PackagingAnomaly(PackagingAnomalyCategory.BidiControl, @"content/gnp\u202ecod.exe", "contains bidirectional control character(s) U+202E"),
        ]).ToJson();

        Assert.Contains("\"PackagingAnomalies\"", json, StringComparison.Ordinal);
        Assert.Contains("\"BidiControl\"", json, StringComparison.Ordinal);

        using var doc = JsonDocument.Parse(json);
        var element = Assert.Single(doc.RootElement.GetProperty("PackagingAnomalies").EnumerateArray());
        Assert.Equal("BidiControl", element.GetProperty("Category").GetString());
        Assert.Equal(@"content/gnp\u202ecod.exe", element.GetProperty("EntryName").GetString());
        Assert.False(string.IsNullOrWhiteSpace(element.GetProperty("Detail").GetString()));
    }

    // Every category name a consumer might key on is serializable and round-trips — enumerated from the live enum,
    // so a category added later is covered without editing this test.
    [Fact]
    public void PackageReport_EveryCategory_RoundTripsByName()
    {
        var all = Enum.GetValues<PackagingAnomalyCategory>();
        var report = MakeReport([.. all.Select(c => new PackagingAnomaly(c, "content/x.bin", "detail"))]);

        var restored = PackageCapabilityReport.FromJson(report.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(all, restored!.PackagingAnomalies.Select(a => a.Category).ToArray());
        Assert.All(all, c => Assert.Contains($"\"{c}\"", report.ToJson(), StringComparison.Ordinal));
    }

    // Back-compat: JSON that predates the field (no PackagingAnomalies property at all) deserializes to an EMPTY,
    // non-null list — the normalizing property initializer maps the absent constructor argument to Array.Empty.
    [Fact]
    public void PackageReport_FromLegacyJsonWithoutPackagingAnomalies_YieldsEmptyNonNullList()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before packaging anomalies existed.",
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
        Assert.NotNull(restored!.PackagingAnomalies);   // never null — the load-bearing back-compat guarantee
        Assert.Empty(restored.PackagingAnomalies);
        Assert.Equal("Legacy.Package", restored.Package.Id);   // the rest of the legacy report still deserialized
    }

    // The escaped name survives JSON verbatim: the backslash sequences the analyzer produced are JSON-escaped on the
    // way out and come back identical, so the anomaly a consumer reads is the anomaly the analyzer reported. What
    // must NEVER appear is a RAW control character in the serialized string.
    [Fact]
    public void PackageReport_ToJson_CarriesTheEscapedNameAndNoRawControlCharacter()
    {
        var json = MakeReport(
        [
            new PackagingAnomaly(PackagingAnomalyCategory.ControlCharacter, @"content/pay\nload.bin", "contains control character(s) U+000A"),
        ]).ToJson();

        using var doc = JsonDocument.Parse(json);
        var element = Assert.Single(doc.RootElement.GetProperty("PackagingAnomalies").EnumerateArray());
        var entryName = element.GetProperty("EntryName").GetString();

        Assert.Equal(@"content/pay\nload.bin", entryName);
        Assert.DoesNotContain("\n", entryName!, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", entryName!, StringComparison.Ordinal);
    }
    #endregion

    #region Helpers
    private static PackageCapabilityReport MakeReport(PackagingAnomaly[] anomalies) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            PackagingAnomalies: anomalies);
    #endregion
}
