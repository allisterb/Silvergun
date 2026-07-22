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
