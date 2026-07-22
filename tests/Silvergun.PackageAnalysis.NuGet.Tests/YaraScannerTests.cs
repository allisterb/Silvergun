namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for the cross-platform <see cref="IYaraScanner"/> backends (ADR 0016 / task
/// <c>docs/agent/tasks/yara-scanning.md</c>, Phases 1-2): <see cref="NullYaraScanner"/> is always a no-op, and
/// <see cref="YaraCliScanner"/> honours its "never throws" contract when no real <c>yara</c> engine is present —
/// unset or nonexistent <c>SILVERGUN_YARA_PATH</c> leaves it unavailable and its scans empty. No real engine or
/// binary is invoked; the environment variables are saved and restored around each test (see
/// <see cref="YaraEnvScope"/>). The Windows in-process backend and the nonzero-exit / timeout process paths are
/// covered by a manual Windows smoke, not here (native, engine-dependent — same posture as the network sources).
/// </summary>
public sealed class YaraScannerTests
{
    #region Methods
    // The null backend returns empty for a normal path...
    [Fact]
    public void NullYaraScanner_ScanFile_ReturnsEmpty()
    {
        Assert.Empty(NullYaraScanner.Instance.ScanFile("/tmp/whatever.dll"));
    }

    // ...and for degenerate inputs (missing or empty path), still without throwing.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("/nonexistent/path/to/file.dll")]
    public void NullYaraScanner_ScanFile_DegenerateInputs_ReturnEmpty(string path)
    {
        Assert.Empty(NullYaraScanner.Instance.ScanFile(path));
    }

    // With SILVERGUN_YARA_PATH unset, the CLI scanner reports itself unavailable...
    [Fact]
    public void YaraCliScanner_WhenPathUnset_IsUnavailable()
    {
        using var _ = new YaraEnvScope(yara: null, yarac: null);

        Assert.False(new YaraCliScanner().Available);
    }

    // ...and its scans return empty (degrades to a no-op) without throwing.
    [Fact]
    public void YaraCliScanner_WhenPathUnset_ScanFileReturnsEmpty()
    {
        using var _ = new YaraEnvScope(yara: null, yarac: null);

        var scanner = new YaraCliScanner();

        Assert.Empty(scanner.ScanFile("/tmp/whatever.dll"));
    }

    // A SILVERGUN_YARA_PATH pointing at a file that does not exist is treated as "no engine": unavailable + empty.
    [Fact]
    public void YaraCliScanner_WhenPathIsNonexistent_IsUnavailableAndScansEmpty()
    {
        var missing = Path.Combine(Path.GetTempPath(), "silvergun-no-such-yara-" + Guid.NewGuid().ToString("N"));
        using var _ = new YaraEnvScope(yara: missing, yarac: null);

        var scanner = new YaraCliScanner();

        Assert.False(scanner.Available);
        Assert.Empty(scanner.ScanFile("/tmp/whatever.dll"));
    }

    // Even when unavailable, scanning a real existing file must not throw and must be empty.
    [Fact]
    public void YaraCliScanner_WhenUnavailable_ScanExistingFileReturnsEmpty()
    {
        using var _ = new YaraEnvScope(yara: null, yarac: null);

        var file = Path.Combine(Path.GetTempPath(), "silvergun-yara-test-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllText(file, "harmless content");
        try
        {
            Assert.Empty(new YaraCliScanner().ScanFile(file));
        }
        finally
        {
            File.Delete(file);
        }
    }
    #endregion

    #region Nested types
    // Saves and restores both YARA path environment variables around a test (mirrors ProgramTests.ApiKeyScope),
    // so a developer's real SILVERGUN_YARA_PATH cannot leak into — or be clobbered by — these tests.
    private sealed class YaraEnvScope : IDisposable
    {
        public YaraEnvScope(string? yara, string? yarac)
        {
            _previousYara = Environment.GetEnvironmentVariable(YaraCliScanner.YaraPathVar);
            _previousYarac = Environment.GetEnvironmentVariable(YaraCliScanner.YaracPathVar);
            Environment.SetEnvironmentVariable(YaraCliScanner.YaraPathVar, yara);
            Environment.SetEnvironmentVariable(YaraCliScanner.YaracPathVar, yarac);
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable(YaraCliScanner.YaraPathVar, _previousYara);
            Environment.SetEnvironmentVariable(YaraCliScanner.YaracPathVar, _previousYarac);
        }

        private readonly string? _previousYara;
        private readonly string? _previousYarac;
    }
    #endregion
}
