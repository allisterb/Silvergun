namespace Silvergun.CLI.Tests;

using Silvergun.CLI;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

/// <summary>
/// Unit tests for the CLI's testable seams: <see cref="Program.SelectPopularitySource"/> source selection,
/// <see cref="Program.IsValidSource"/> validation, and the <see cref="Program.ScanExitCode"/> --strict gate
/// (including which script findings are allowed to gate it — see
/// <c>docs/agent/tasks/script-rule-precision.md</c>). No network is touched — the popularity sources build a
/// client/repository lazily, so asserting the concrete returned type is safe.
/// </summary>
public sealed class ProgramTests
{
    #region Methods
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

    [Theory]
    [InlineData(true, false, false, false, 0)]
    [InlineData(false, true, true, true, 0)]
    [InlineData(true, true, false, false, 2)]
    [InlineData(true, false, true, false, 2)]
    [InlineData(true, false, false, true, 2)]
    public void ScanExitCode_ReturnsTwoOnlyWhenStrictAndAnyGate(
        bool strict, bool cap, bool obf, bool script, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(strict, cap, obf, script));

    // The new trailing YARA gate (ADR 0016): a YARA finding is a high-confidence IOC, so it trips --strict on its
    // own (=> 2), stays silent when strict is off (=> 0), and never fabricates a non-zero when no gate is present.
    [Theory]
    [InlineData(true, false, false, false, true, 2)]    // strict + only YARA => 2
    [InlineData(false, false, false, false, true, 0)]   // non-strict + YARA => 0
    [InlineData(true, false, false, false, false, 0)]   // strict but nothing set => 0
    [InlineData(true, true, false, false, true, 2)]     // YARA alongside another gate is still 2
    public void ScanExitCode_WithYaraGate_ReturnsTwoOnlyWhenStrictAndAnyGate(
        bool strict, bool cap, bool obf, bool script, bool yara, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(strict, cap, obf, script, yara));

    // The 5th parameter defaults to false, so a strict scan whose only YARA-arg is omitted matches the 4-arg result:
    // pre-existing callers (assembly / check-squat) are unaffected by the additive gate.
    [Theory]
    [InlineData(true, false, false, false)]
    [InlineData(true, true, false, false)]
    [InlineData(false, true, true, true)]
    public void ScanExitCode_YaraDefaultsFalse_MatchesFourArgOverload(bool strict, bool cap, bool obf, bool script) =>
        Assert.Equal(
            Program.ScanExitCode(strict, cap, obf, script),
            Program.ScanExitCode(strict, cap, obf, script, hasYaraFindings: false));

    // The new trailing OSV known-vulnerability gate (ADR 0017): a known vuln is a concrete, actionable IOC, so it
    // trips --strict on its own (=> 2), stays silent when strict is off (=> 0), and never fabricates a non-zero when
    // no gate is present.
    [Theory]
    [InlineData(true, false, false, false, false, true, 2)]    // strict + only a vulnerability => 2
    [InlineData(false, false, false, false, false, true, 0)]   // non-strict + vulnerability => 0
    [InlineData(true, false, false, false, false, false, 0)]   // strict but nothing set => 0
    [InlineData(true, true, false, false, false, true, 2)]     // vulnerability alongside another gate is still 2
    [InlineData(true, false, false, false, true, true, 2)]     // vulnerability alongside a YARA hit is still 2
    public void ScanExitCode_WithVulnerabilityGate_ReturnsTwoOnlyWhenStrictAndAnyGate(
        bool strict, bool cap, bool obf, bool script, bool yara, bool vuln, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(strict, cap, obf, script, yara, vuln));

    // The 6th parameter defaults to false, so a strict scan whose vulnerability-arg is omitted matches the 5-arg
    // result: pre-existing callers (assembly / check-squat) are unaffected by the additive OSV gate.
    [Theory]
    [InlineData(true, false, false, false, false)]
    [InlineData(true, false, false, false, true)]
    [InlineData(false, true, true, true, false)]
    public void ScanExitCode_VulnerabilityDefaultsFalse_MatchesFiveArgOverload(
        bool strict, bool cap, bool obf, bool script, bool yara) =>
        Assert.Equal(
            Program.ScanExitCode(strict, cap, obf, script, yara),
            Program.ScanExitCode(strict, cap, obf, script, yara, hasVulnerabilities: false));

    // OSV reachability (the Unavailable status) is NOT a --strict FINDINGS gate: that gate is findings-only, so an
    // Unavailable check with NO findings (hasVulnerabilities:false) never trips it — it returns 0 here, exactly like a
    // completed-clean scan, and an outage can never fabricate a policy verdict (2).
    //
    // ⚠️ This is a statement about the FINDINGS gate only, NOT about the outage's overall exit code. Under ADR 0024
    // that outage is incompleteness, so the real scan-package run exits 3: Program.ScanPackageExitCode derives
    // isIncomplete from CompletenessAssessment.ForPackage, which treats Unavailable/NotChecked as "vulnerability data
    // not obtained" (see CompletenessExitCodeTests.ScanPackage_WhenVulnerabilityDataNotObtained_ExitsThree). The
    // assertion below is still exactly right because this is the PURE seam with isIncomplete defaulted to false — the
    // pre-ADR-0024 claim that the signal "lives in the report/stderr, not the code" is what no longer holds.
    [Fact]
    public void ScanExitCode_StrictWithUnavailableStatusButNoFindings_ReturnsZero() =>
        Assert.Equal(0, Program.ScanExitCode(
            strict: true, hasCapabilityFindings: false, hasObfuscation: false, hasScriptFindings: false,
            hasYaraFindings: false, hasVulnerabilities: false));

    // Resolver-lite (ADR 0018): under --depth the transitive vulnerabilities OSV finds are MERGED into
    // report.Vulnerabilities (the CLI attaches them via the same `with { Vulnerabilities = ... }` step), so they flow
    // through the SAME `hasVulnerabilities` gate arg — the ScanExitCode signature is unchanged. This asserts that a
    // vulnerability of transitive origin still trips --strict to exit 2, exactly like a direct/dependency hit.
    [Fact]
    public void ScanExitCode_TransitiveVuln_GatesStrict() =>
        Assert.Equal(2, Program.ScanExitCode(
            strict: true, hasCapabilityFindings: false, hasObfuscation: false, hasScriptFindings: false,
            hasYaraFindings: false, hasVulnerabilities: true));

    // Script-rule precision (docs/agent/tasks/script-rule-precision.md): findings from the declarative package
    // manifest (Source=PackageMetadata) are advisory — reported in full, but they must NOT fail CI on their own,
    // mirroring the ADR 0015 "advisory never gates" precedent. Nothing in a .nuspec executes.
    //
    // NOTE ON SHAPE: the gate expression lives INLINE in Program.RunScanPackage (`report.ScriptFindings.Any(f =>
    // f.Source == ScriptFindingSource.Script)`), with no seam to call. These two tests therefore apply that exact
    // predicate to a constructed report and feed the result to ScanExitCode, so a regression that widened the gate
    // back to "any script finding" would have to change this predicate too.
    [Fact]
    public void ScanExitCode_MetadataOnlyScriptFindings_DoesNotGateStrict()
    {
        var report = ReportWithScriptFindings(
            Finding("BD000600", ScriptFindingSource.PackageMetadata),
            Finding("BD000804", ScriptFindingSource.PackageMetadata));

        var hasScriptFindings = report.ScriptFindings.Any(f => f.Source == ScriptFindingSource.Script);

        Assert.NotEmpty(report.ScriptFindings);   // still reported in full ...
        Assert.False(hasScriptFindings);          // ... but not a gate
        Assert.Equal(0, Program.ScanExitCode(
            strict: true, hasCapabilityFindings: false, hasObfuscation: false, hasScriptFindings,
            hasYaraFindings: false, hasVulnerabilities: false));
    }

    // The recall half of the same contract: a finding from real script/build content still gates --strict, even when
    // it sits alongside advisory manifest findings.
    [Fact]
    public void ScanExitCode_ScriptSourcedFinding_GatesStrict()
    {
        var report = ReportWithScriptFindings(
            Finding("BD000600", ScriptFindingSource.PackageMetadata),
            Finding("BD000500", ScriptFindingSource.Script));

        var hasScriptFindings = report.ScriptFindings.Any(f => f.Source == ScriptFindingSource.Script);

        Assert.True(hasScriptFindings);
        Assert.Equal(2, Program.ScanExitCode(
            strict: true, hasCapabilityFindings: false, hasObfuscation: false, hasScriptFindings,
            hasYaraFindings: false, hasVulnerabilities: false));
    }
    #endregion

    #region Methods — fixtures
    private static ScriptFinding Finding(string ruleId, ScriptFindingSource source) =>
        new(
            ruleId, "A rule", "Moderate", "Low",
            source == ScriptFindingSource.PackageMetadata ? "Some.Package.nuspec" : "tools/install.ps1",
            7, "excerpt", Array.Empty<string>(), Occurrences: 1, Source: source);

    private static PackageCapabilityReport ReportWithScriptFindings(params ScriptFinding[] findings) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            findings);
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
