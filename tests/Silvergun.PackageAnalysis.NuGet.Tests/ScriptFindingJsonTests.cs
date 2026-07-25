namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Xunit;

/// <summary>
/// JSON contract tests for <see cref="ScriptFinding"/>'s additive trailing members —
/// <see cref="ScriptFinding.Occurrences"/> and <see cref="ScriptFinding.Source"/>
/// (<c>docs/agent/tasks/script-rule-precision.md</c>; ADR 0002 string/record report shape). Two guarantees:
/// a populated report round-trips through <see cref="PackageCapabilityReport.ToJson"/> /
/// <see cref="PackageCapabilityReport.FromJson"/> with both members intact and the enum written by <b>name</b>
/// (never an ordinal a downstream consumer could misread), and — the back-compat half — JSON serialized
/// <b>before</b> the members existed deserializes to <c>Occurrences = 1</c> /
/// <see cref="ScriptFindingSource.Script"/> rather than 0 / garbage.
/// </summary>
public sealed class ScriptFindingJsonTests
{
    #region Methods
    // Both new members survive ToJson => FromJson, and the source discriminator is emitted as its NAME.
    [Fact]
    public void ScriptFinding_NewFields_RoundTrip()
    {
        var report = MakeReport(
            new ScriptFinding(
                "BD000600", "LOLBAS: Windows Indicator", "Moderate", "Low",
                "Some.Package.nuspec", 12, "certutil -urlcache", new[] { "Security.Backdoor.LOLBAS.Windows" },
                Occurrences: 7, Source: ScriptFindingSource.PackageMetadata),
            new ScriptFinding(
                "BD000500", "Backdoor: Pastebin", "Moderate", "High",
                "tools/install.ps1", 3, "pastebin.com/raw", new[] { "Security.Backdoor.Pastebin" }));

        var json = report.ToJson();

        Assert.Contains("\"Occurrences\": 7", json);                      // the count is serialized as a number ...
        Assert.Contains("\"Source\": \"PackageMetadata\"", json);         // ... and the source by NAME, not ordinal
        Assert.Contains("\"Source\": \"Script\"", json);
        Assert.DoesNotContain("\"Source\": 1", json);
        Assert.DoesNotContain("\"Source\": 0", json);

        var restored = PackageCapabilityReport.FromJson(json);
        Assert.NotNull(restored);
        Assert.Equal(2, restored!.ScriptFindings.Count);

        var metadata = restored.ScriptFindings[0];
        Assert.Equal("BD000600", metadata.RuleId);
        Assert.Equal(7, metadata.Occurrences);
        Assert.Equal(ScriptFindingSource.PackageMetadata, metadata.Source);
        Assert.Equal(12, metadata.StartLine);
        Assert.Equal("certutil -urlcache", metadata.Excerpt);
        Assert.Equal(new[] { "Security.Backdoor.LOLBAS.Windows" }, metadata.Tags);

        var script = restored.ScriptFindings[1];
        Assert.Equal("BD000500", script.RuleId);
        Assert.Equal(1, script.Occurrences);                              // the constructor default round-trips too
        Assert.Equal(ScriptFindingSource.Script, script.Source);
    }

    // Back-compat: a report serialized before the members existed (its ScriptFindings carry neither Occurrences nor
    // Source) deserializes to the additive defaults — one occurrence, Script-sourced — so an old report still gates
    // --strict exactly as it did when it was written.
    [Fact]
    public void ScriptFinding_OldJsonWithoutNewFields_DefaultsToOneAndScript()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before script findings carried a source.",
                "Dependencies": []
              },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": [
                {
                  "RuleId": "BD000600",
                  "RuleName": "LOLBAS: Windows Indicator",
                  "Severity": "Moderate",
                  "Confidence": "Low",
                  "RelativePath": "tools/install.ps1",
                  "StartLine": 4,
                  "Excerpt": "certutil -urlcache",
                  "Tags": [ "Security.Backdoor.LOLBAS.Windows" ]
                }
              ]
            }
            """;

        var restored = PackageCapabilityReport.FromJson(legacyJson);

        Assert.NotNull(restored);
        var finding = Assert.Single(restored!.ScriptFindings);
        Assert.Equal(1, finding.Occurrences);                             // never 0 — the load-bearing default
        Assert.Equal(ScriptFindingSource.Script, finding.Source);         // and old findings still gate --strict
        Assert.Equal("BD000600", finding.RuleId);                         // the rest of the legacy finding survived
        Assert.Equal(4, finding.StartLine);
        Assert.Equal("Legacy.Package", restored.Package.Id);
    }
    #endregion

    #region Helpers
    private static PackageCapabilityReport MakeReport(params ScriptFinding[] findings) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            findings);
    #endregion
}
