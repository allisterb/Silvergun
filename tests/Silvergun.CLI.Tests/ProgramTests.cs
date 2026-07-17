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
