namespace Silvergun.CLI.Tests;

using Silvergun.CLI;
using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for the CLI's testable seams: <see cref="Program.SelectPopularitySource"/> source selection,
/// <see cref="Program.IsValidSource"/> validation, and the <see cref="Program.ScanExitCode"/> --strict gate.
/// No network is touched — the popularity sources build a client/repository lazily, so asserting the concrete
/// returned type is safe.
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

    // OSV reachability (the new Unavailable status) is NOT a --strict gate: the gate is findings-only. An Unavailable
    // check with NO findings (hasVulnerabilities:false) — the outage case — must still exit 0 under --strict, exactly
    // like a completed-clean scan. ScanExitCode takes only hasVulnerabilities (not the status), so this documents that
    // an outage never fabricates a non-zero exit; the "not verified" signal lives in the report/stderr, not the code.
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
