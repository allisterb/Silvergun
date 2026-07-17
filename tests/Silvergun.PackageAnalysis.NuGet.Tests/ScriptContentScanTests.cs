namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;

using Xunit;

/// <summary>
/// Script/content rule scanning (ADR 0012 / <c>docs/agent/tasks/appinspector-script-rules.md</c>): the
/// <see cref="ScriptRuleScanner"/> runs the embedded OSSGadget MIT backdoor rulesets over a package's
/// inventoried scripts during the open-package session, surfacing serializable <see cref="ScriptFinding"/>s
/// on the <see cref="PackageCapabilityReport"/>. Packages are staged by <see cref="PackageFixture"/> from
/// pure BCL-built zips — no network; all package content is untrusted per the project threat model.
/// </summary>
public sealed class ScriptContentScanTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public ScriptContentScanTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // A .ps1 carrying rule-matching tokens (IEX download + certutil LOLBAS) yields >=1 finding pinned to the
    // script's package-relative path, with a non-empty RuleId — the core acceptance criterion.
    [Fact]
    public void Scan_PkgScript_FlagsMaliciousPs1_WithRelativePathAndRuleId()
    {
        var report = ScanPkgScript();

        var ps1Findings = report.ScriptFindings
            .Where(f => Norm(f.RelativePath).EndsWith("/install.ps1", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(ps1Findings);
        Assert.All(ps1Findings, f => Assert.False(string.IsNullOrEmpty(f.RuleId)));
        Assert.All(ps1Findings, f => Assert.True(f.StartLine >= 1));
    }

    // The .psm1 is now inventoried as a script (ADR 0012) and is scanned: the package's Scripts list includes
    // the .psm1, and its certutil LOLBAS line produces a finding pinned to the .psm1's relative path.
    [Fact]
    public void Open_PkgScript_InventoriesPsm1_AndScanFlagsIt()
    {
        var open = NuGetPackage.Open(fixture.PkgScriptPath);
        Assert.True(open.IsSuccess, open.Message);
        using (var pkg = open.Value)
        {
            Assert.Contains(pkg.Scripts, s => Norm(s.RelativePath).EndsWith("/module.psm1", StringComparison.Ordinal));
        }

        var report = ScanPkgScript();
        Assert.Contains(
            report.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith("/module.psm1", StringComparison.Ordinal) && !string.IsNullOrEmpty(f.RuleId));
    }

    // Unknown-language build files (.targets) analyze via the default LanguageInfo without error and are not
    // skipped: the .targets is inventoried, the scan succeeds, and its certutil token produces a finding.
    [Fact]
    public void Scan_PkgScript_AnalyzesTargetsViaDefaultLanguage_WithoutError()
    {
        var open = NuGetPackage.Open(fixture.PkgScriptPath);
        Assert.True(open.IsSuccess, open.Message);
        using (var pkg = open.Value)
        {
            Assert.Contains(pkg.Scripts, s => Norm(s.RelativePath).EndsWith(".targets", StringComparison.Ordinal));
        }

        var report = ScanPkgScript();
        Assert.Contains(
            report.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith(".targets", StringComparison.Ordinal) && !string.IsNullOrEmpty(f.RuleId));
    }

    // Each finding maps the RulesEngine record defensively: severity/confidence are non-empty enum names and
    // tags are never null (ADR 0012 model contract).
    [Fact]
    public void Scan_PkgScript_FindingsCarryEnumNameStringsAndNonNullTags()
    {
        var report = ScanPkgScript();

        Assert.NotEmpty(report.ScriptFindings);
        Assert.All(report.ScriptFindings, f =>
        {
            Assert.False(string.IsNullOrEmpty(f.Severity));
            Assert.False(string.IsNullOrEmpty(f.Confidence));
            Assert.NotNull(f.Tags);
        });
    }

    // A package whose scripts are all benign (PkgA: a Write-Host install.ps1 and an empty .targets) yields zero
    // script findings, and the assembly/script inventory shape is unchanged (the additive field is just empty).
    [Fact]
    public void Scan_PkgA_BenignScripts_ProduceNoScriptFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath);
        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;

        Assert.Empty(report.ScriptFindings);
        Assert.NotEmpty(report.Scripts);        // scripts still inventoried
        Assert.NotEmpty(report.Assemblies);     // assembly side unchanged
    }

    // A package with no scripts at all (PkgB) scans clean with an empty — never null — ScriptFindings list.
    [Fact]
    public void Scan_PkgB_NoScripts_HasEmptyScriptFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath);
        Assert.True(scan.IsSuccess, scan.Message);

        Assert.NotNull(scan.Value.ScriptFindings);
        Assert.Empty(scan.Value.ScriptFindings);
    }

    // Never-throws: a package with an oversized (>5 MiB) script and a malformed/binary script must not crash the
    // scan. The huge and malformed files are skipped, but the small matching script's finding survives intact.
    [Fact]
    public void Scan_PkgOversize_SkipsHugeAndMalformed_ButKeepsOtherFindings()
    {
        var scan = default(Silvergun.Result<PackageCapabilityReport>);
        var ex = Record.Exception(() => scan = PackageScanner.Scan(fixture.PkgOversizePath));

        Assert.Null(ex);
        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;

        // The small script's finding is present ...
        Assert.Contains(
            report.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith("/small.ps1", StringComparison.Ordinal) && !string.IsNullOrEmpty(f.RuleId));

        // ... while the oversized script (skipped by the size cap) contributes no findings.
        Assert.DoesNotContain(
            report.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith("/big.ps1", StringComparison.Ordinal));
    }

    // Round-trip: PackageScript.FullPath and PackageCapabilityReport.ScriptFindings survive ToJson/FromJson.
    [Fact]
    public void PackageReport_JsonRoundTrip_PreservesFullPathAndScriptFindings()
    {
        var report = ScanPkgScript();
        Assert.NotEmpty(report.ScriptFindings);
        Assert.All(report.Scripts, s => Assert.False(string.IsNullOrEmpty(s.FullPath)));

        var restored = PackageCapabilityReport.FromJson(report.ToJson());
        Assert.NotNull(restored);

        // Scripts (scalar records) round-trip by value equality, which includes the additive FullPath.
        Assert.Equal(report.Scripts, restored!.Scripts);

        // Findings (scalar records save for the Tags list) round-trip element-wise.
        Assert.Equal(report.ScriptFindings.Count, restored.ScriptFindings.Count);
        foreach (var (a, b) in report.ScriptFindings.Zip(restored.ScriptFindings))
        {
            Assert.Equal(a.RuleId, b.RuleId);
            Assert.Equal(a.RuleName, b.RuleName);
            Assert.Equal(a.Severity, b.Severity);
            Assert.Equal(a.Confidence, b.Confidence);
            Assert.Equal(a.RelativePath, b.RelativePath);
            Assert.Equal(a.StartLine, b.StartLine);
            Assert.Equal(a.Excerpt, b.Excerpt);
            Assert.Equal(a.Tags, b.Tags);
        }
    }

    // --strict gate parity (ADR 0012 §6). The CLI exit-code gate lives in Program.cs (RunScanPackage) and is
    // validated interactively; here we assert the report-level predicate the gate keys on: a script finding
    // drives the non-zero path for the matching package, and stays false for a clean package.
    [Fact]
    public void ScriptFindings_Any_DrivesStrictGate_ForMatchingAndCleanPackages()
    {
        Assert.True(ScanPkgScript().ScriptFindings.Any());
        Assert.False(PackageScanner.Scan(fixture.PkgAPath).Value.ScriptFindings.Any());
    }

    private PackageCapabilityReport ScanPkgScript()
    {
        var scan = PackageScanner.Scan(fixture.PkgScriptPath);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private static string Norm(string path) => path.Replace('\\', '/');
    #endregion

    #region Fields
    private readonly PackageFixture fixture;
    #endregion
}
