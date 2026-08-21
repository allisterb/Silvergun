namespace Silvergun.CLI.Tests;

using Silvergun.CLI;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// Unit tests for the CLI's testable seams: <see cref="Program.SelectPopularitySource"/> source selection,
/// <see cref="Program.IsValidSource"/> validation, and the <see cref="Program.ScanExitCode"/> --strict gate.
/// <para>
/// ADR-0027 ("what --strict gates on") narrowed the gate from six sources to three — vulnerabilities, YARA
/// findings, and ADR-0026's gating indicator categories — because the other three (capability presence,
/// obfuscation findings, <c>Source=Script</c> script findings) were measured at 67-81%/29%/25% benign-package
/// prevalence with ZERO user-would-accept hits (Table C). Their booleans were REMOVED from
/// <see cref="Program.ScanExitCode"/>'s signature on purpose, not merely defaulted — a future attempt to re-gate
/// on them must fail to compile here. This file therefore pins two things with equal weight: the surviving
/// three-source gate (region A), and the explicit non-gating of the three de-gated sources, asserted individually
/// by name for both <c>analyze</c> and <c>scan-package</c> (region B) — the exclusions are the part most likely to
/// look like a bug to a future reader and be silently reverted.
/// </para>
/// </summary>
public sealed class ProgramTests
{
    #region Methods — source selection (unaffected by ADR-0027)
    [Fact]
    public void SelectPopularitySource_Auto_ReturnsNuGet_WhenKeyUnset()
    {
        using var _ = new ApiKeyScope(null);
        Assert.IsType<NuGetPopularitySource>(Program.SelectPopularitySource(null));
    }

    [Fact]
    public void SelectPopularitySource_Auto_ReturnsLibrariesIo_WhenKeySet()
    {
        using var _ = new ApiKeyScope("test-key");
        Assert.IsType<LibrariesIoPopularitySource>(Program.SelectPopularitySource(null));
    }

    [Theory]
    [InlineData("nuget")]
    [InlineData("NuGet")]
    [InlineData("  nuget  ")]
    public void SelectPopularitySource_ExplicitNuGet_ReturnsNuGet_EvenWithKey(string source)
    {
        using var _ = new ApiKeyScope("test-key");
        Assert.IsType<NuGetPopularitySource>(Program.SelectPopularitySource(source));
    }

    [Theory]
    [InlineData("librariesio")]
    [InlineData("LibrariesIo")]
    public void SelectPopularitySource_ExplicitLibrariesIo_ReturnsLibrariesIo_WhenKeySet(string source)
    {
        using var _ = new ApiKeyScope("test-key");
        Assert.IsType<LibrariesIoPopularitySource>(Program.SelectPopularitySource(source));
    }

    [Fact]
    public void SelectPopularitySource_ExplicitLibrariesIo_FallsBackToNuGet_WhenKeyUnset()
    {
        using var _ = new ApiKeyScope(null);
        Assert.IsType<NuGetPopularitySource>(Program.SelectPopularitySource("librariesio"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("nuget")]
    [InlineData("librariesio")]
    [InlineData("  NuGet ")]
    public void IsValidSource_AcceptsRecognizedValuesAndAbsent(string? source) =>
        Assert.True(Program.IsValidSource(source));

    [Theory]
    [InlineData("")]
    [InlineData("bogus")]
    [InlineData("nugets")]
    [InlineData("libraries.io")]
    public void IsValidSource_RejectsUnrecognizedValues(string source) =>
        Assert.False(Program.IsValidSource(source));
    #endregion

    #region Methods — A: the surviving three-source ScanExitCode gate (pure seam)
    // Every combination of the three surviving gate sources, strict on, nothing incomplete: 2 exactly when strict
    // AND at least one of {YARA, vulnerability, gating indicator} is set, else 0.
    [Theory]
    [InlineData(true, false, false, false, 0)]
    [InlineData(false, true, true, true, 0)]    // no --strict: never gates, no matter how many sources fire
    [InlineData(true, true, false, false, 2)]
    [InlineData(true, false, true, false, 2)]
    [InlineData(true, false, false, true, 2)]
    [InlineData(true, true, true, true, 2)]
    public void ScanExitCode_ReturnsTwoOnlyWhenStrictAndOneOfTheThreeSurvivingGates(
        bool strict, bool yara, bool vuln, bool gatingIndicator, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(
            strict, hasYaraFindings: yara, hasVulnerabilities: vuln, hasGatingIndicatorFindings: gatingIndicator,
            isIncomplete: false, allowIncomplete: false));

    // YARA alone (ADR 0016): a name-match on a malware signature is the strongest signal the tool has, so it trips
    // --strict on its own, stays silent when strict is off, and never fabricates a non-zero when no gate is present.
    [Theory]
    [InlineData(true, true, 2)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 0)]
    public void ScanExitCode_YaraFindingsAlone_GatesOnlyUnderStrict(bool strict, bool yara, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(
            strict, hasYaraFindings: yara, hasVulnerabilities: false, hasGatingIndicatorFindings: false,
            isIncomplete: false, allowIncomplete: false));

    // A known vulnerability alone (ADR 0017): a real CVE should fail a build on its own.
    [Theory]
    [InlineData(true, true, 2)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 0)]
    public void ScanExitCode_VulnerabilityAlone_GatesOnlyUnderStrict(bool strict, bool vuln, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(
            strict, hasYaraFindings: false, hasVulnerabilities: vuln, hasGatingIndicatorFindings: false,
            isIncomplete: false, allowIncomplete: false));

    // A gating indicator finding alone (ADR 0026's three categories, aggregated by Program.AnalyzeExitCode /
    // ScanPackageExitCode into this one boolean): gates --strict on its own too.
    [Theory]
    [InlineData(true, true, 2)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 0)]
    public void ScanExitCode_GatingIndicatorFindingsAlone_GatesOnlyUnderStrict(bool strict, bool gating, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(
            strict, hasYaraFindings: false, hasVulnerabilities: false, hasGatingIndicatorFindings: gating,
            isIncomplete: false, allowIncomplete: false));

    // OSV reachability (the Unavailable status) is NOT a --strict FINDINGS gate: that gate is findings-only, so an
    // Unavailable check with NO findings (hasVulnerabilities:false) never trips it — it returns 0 here, exactly like
    // a completed-clean scan, and an outage can never fabricate a policy verdict (2) at this pure seam.
    //
    // ⚠️ This is a statement about the FINDINGS gate only, NOT about the outage's overall exit code. Under ADR 0024
    // that outage is incompleteness, so the real scan-package run exits 3: Program.ScanPackageExitCode derives
    // isIncomplete from CompletenessAssessment.ForPackage, which treats Unavailable/NotChecked as "vulnerability data
    // not obtained" (see CompletenessExitCodeTests.ScanPackage_WhenVulnerabilityDataNotObtained_ExitsThree).
    [Fact]
    public void ScanExitCode_StrictWithUnavailableStatusButNoFindings_ReturnsZero() =>
        Assert.Equal(0, Program.ScanExitCode(
            strict: true, hasYaraFindings: false, hasVulnerabilities: false, hasGatingIndicatorFindings: false,
            isIncomplete: false, allowIncomplete: false));

    // Resolver-lite (ADR 0018): under --depth the transitive vulnerabilities OSV finds are MERGED into
    // report.Vulnerabilities (the CLI attaches them via the same `with { Vulnerabilities = ... }` step), so they
    // flow through the SAME hasVulnerabilities gate arg. This asserts a vulnerability of transitive origin still
    // trips --strict, exactly like a direct/dependency hit.
    [Fact]
    public void ScanExitCode_TransitiveVuln_GatesStrict() =>
        Assert.Equal(2, Program.ScanExitCode(
            strict: true, hasYaraFindings: false, hasVulnerabilities: true, hasGatingIndicatorFindings: false,
            isIncomplete: false, allowIncomplete: false));
    #endregion

    #region Methods — B: PIN THE DE-GATING — capability/obfuscation/script alone must NOT gate --strict
    // ADR-0027 Table C: every one of the 72/100 benign packages that failed the old six-source gate failed for a
    // noise-class reason (capability presence, obfuscation, or a script heuristic) — never a real CVE, a YARA
    // name-match, or a gating indicator. These three exclusions are the evidence-backed part of the decision most
    // likely to look like a bug to a future reader ("surely a capability finding should fail a strict build?") and
    // the most likely thing to be silently reverted, so each is pinned individually, by name, for both verbs where
    // it applies (script findings are scan-package-only: AssemblyAnalysisReport carries no ScriptFindings).
    //
    // A structural guard, not just a behavioral one: Program.ScanExitCode's signature has NO parameter for
    // capability/obfuscation/script findings at all, so a regression that tried to re-gate on them would have to
    // change the signature (and every call site) before it could even compile — these tests assert the observable
    // half of that same removal, at the report/verb level the run methods actually call.
    [Fact]
    public void AnalyzeExitCode_CapabilityFindingsAlone_DoesNotGateStrict()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0, findings: [CapabilityFinding]);

        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: true, allowIncomplete: false));
    }

    [Fact]
    public void ScanPackageExitCode_CapabilityFindingsAlone_DoesNotGateStrict()
    {
        var report = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0, findings: [CapabilityFinding]));

        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }

    [Fact]
    public void AnalyzeExitCode_ObfuscationFindingsAlone_DoesNotGateStrict()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0) with
        {
            Obfuscation = ObfuscationReportWithFinding("Sample.dll")
        };

        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: true, allowIncomplete: false));
    }

    [Fact]
    public void ScanPackageExitCode_ObfuscationFindingsAlone_DoesNotGateStrict()
    {
        var analyzed = Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0) with
        {
            Obfuscation = ObfuscationReportWithFinding("lib/net10.0/A.dll")
        };
        var report = Package(analyzed);

        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));
    }

    // Script-rule precision (docs/agent/tasks/script-rule-precision.md) established that PackageMetadata-sourced
    // script findings never gated; ADR-0027 goes further and stops Source=Script findings gating too — the 25%
    // benign share was "one benign package in four". Recall (that these findings are still real findings, still
    // reported) is asserted alongside the de-gating so this test cannot be satisfied by a report that silently drops
    // the finding instead of merely not gating on it.
    [Fact]
    public void ScanPackageExitCode_ScriptSourcedFindingsAlone_DoesNotGateStrict()
    {
        var report = ReportWithScriptFindings(Finding("SIL9001", ScriptFindingSource.Script));

        Assert.NotEmpty(report.ScriptFindings);   // still reported in full ...
        Assert.Equal(0, Program.ScanPackageExitCode(report, strict: true, allowIncomplete: false));   // ... but not a gate
    }
    #endregion

    #region Methods — fixtures
    private static readonly ApiCallFinding CapabilityFinding =
        new(Capability.FileSystem, ApiCallKind.Call, "T", "M", "System.IO.File.ReadAllText");

    private static ObfuscationReport ObfuscationReportWithFinding(string path) =>
        new(path, path, Epoch, [new ObfuscationFinding(HiddenContentKind.HighEntropyBlob, "high-entropy base64", "T", "M", 512, 7.9)]);

    private static ScriptFinding Finding(string ruleId, ScriptFindingSource source) =>
        new(
            ruleId, "A rule", "Moderate", "Low",
            source == ScriptFindingSource.PackageMetadata ? "Some.Package.nuspec" : "tools/install.ps1",
            7, "excerpt", Array.Empty<string>(), Occurrences: 1, Source: source);

    private static PackageCapabilityReport ReportWithScriptFindings(params ScriptFinding[] findings) =>
        PackageWith(scriptFindings: findings);
    #endregion

    #region Child types
    // Saves and restores SILVERGUN_LIBRARIESIO_API_KEY around a test so env-var mutation doesn't leak.
    private sealed class ApiKeyScope : IDisposable
    {
        public ApiKeyScope(string? value)
        {
            previous = Environment.GetEnvironmentVariable(EnvVar);
            Environment.SetEnvironmentVariable(EnvVar, value);
        }

        public void Dispose() => Environment.SetEnvironmentVariable(EnvVar, previous);

        private const string EnvVar = "SILVERGUN_LIBRARIESIO_API_KEY";
        private readonly string? previous;
    }
    #endregion
}
