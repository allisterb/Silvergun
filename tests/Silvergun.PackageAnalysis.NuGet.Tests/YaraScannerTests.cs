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
/// <see cref="YaraEnvScope"/>). The Windows backends are not covered here: the default, the out-of-process
/// <c>YaraXWorkerScanner</c> (ADR 0033), has its own net10.0-windows suites (<c>YaraXWorkerScanner*Tests</c>,
/// <c>YaraWorkerVerbWindowsTests</c>); the in-process <c>LibYaraScanner</c>, now only an explicit fallback
/// (<c>SILVERGUN_YARA_ENGINE=libyara</c>), is discussed below.
/// <para>
/// <b>LibYaraScanner.Available cannot be pinned from this test project</b> (ADR 0027 decision 4, task constraint D):
/// this project targets <c>net10.0</c> only, and <c>LibYaraScanner</c> lives entirely behind <c>#if WINDOWS</c>
/// (compiled only into <c>net10.0-windows</c>) — the type is simply absent from this build, not merely untested.
/// Even a <c>net10.0-windows</c> test project would not make the health check meaningful without the native
/// <c>libyara.NET</c> dependency actually deployed, which per ADR 0027 is not currently shipped ("the backend
/// itself is still broken — publishing the native libyara core is a dependency decision reserved for the user").
/// So the only thing a same-process test could pin today is <c>Available == false</c>, which is already covered
/// indirectly by <see cref="Silvergun.PackageAnalysis.NuGet.PackageScanner"/>'s try/catch defense-in-depth pin in
/// <c>YaraScanPackageWiringTests.Scan_WithThrowingFakeScanner_SwallowsFailure_ReportIntact</c> (the same failure
/// shape <c>LibYaraScanner</c> would produce when its native dependency fails to load). A real assertion on
/// <c>LibYaraScanner.Available</c> needs a Windows machine with the native core actually present, which is exactly
/// the "manual Windows smoke" this class already defers to.
/// </para>
/// <para>
/// This class mutates the process-global <c>SILVERGUN_YARA_PATH</c>/<c>SILVERGUN_YARAC_PATH</c>, so it shares one
/// xunit collection with every other class that does (see <see cref="YaraEnvCollection"/>); they used to run
/// concurrently, and either could decide what the other's scanner latched onto.
/// </para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraScannerTests
{
    #region Methods
    // ADR 0027 decision 4 / code-review fix: NullYaraScanner is the "no backend configured at all" case, so its
    // health signal must read false — the whole point of Available existing is that a caller must be able to ask
    // directly rather than infer health from exception-absence (every backend never throws by contract).
    [Fact]
    public void NullYaraScanner_Available_IsAlwaysFalse()
    {
        Assert.False(NullYaraScanner.Instance.Available);
    }

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

        using var cli = new YaraCliScanner();
        Assert.False(cli.Available);
    }

    // ...and its scans return empty (degrades to a no-op) without throwing.
    [Fact]
    public void YaraCliScanner_WhenPathUnset_ScanFileReturnsEmpty()
    {
        using var _ = new YaraEnvScope(yara: null, yarac: null);

        using var scanner = new YaraCliScanner();

        Assert.Empty(scanner.ScanFile("/tmp/whatever.dll"));
    }

    // A SILVERGUN_YARA_PATH pointing at a file that does not exist is treated as "no engine": unavailable + empty.
    [Fact]
    public void YaraCliScanner_WhenPathIsNonexistent_IsUnavailableAndScansEmpty()
    {
        var missing = Path.Combine(Path.GetTempPath(), "silvergun-no-such-yara-" + Guid.NewGuid().ToString("N"));
        using var _ = new YaraEnvScope(yara: missing, yarac: null);

        using var scanner = new YaraCliScanner();

        Assert.False(scanner.Available);
        Assert.Empty(scanner.ScanFile("/tmp/whatever.dll"));
    }

    // ADR 0027 decision 4: Available must also reflect a GENUINE positive — a SILVERGUN_YARA_PATH that resolves to
    // an existing file. Available checks only file existence (never launches the process), so a dummy placeholder
    // file is enough to pin the healthy side of the health-signal contract without invoking a real yara binary.
    [Fact]
    public void YaraCliScanner_WhenPathResolvesToAnExistingFile_IsAvailable()
    {
        var yara = Path.Combine(Path.GetTempPath(), "silvergun-fake-yara-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(yara, "not a real yara binary");
        using var _ = new YaraEnvScope(yara, yarac: null);
        try
        {
            using var cli = new YaraCliScanner();
            Assert.True(cli.Available);
        }
        finally
        {
            File.Delete(yara);
        }
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
            using var cli = new YaraCliScanner();
            Assert.Empty(cli.ScanFile(file));
        }
        finally
        {
            File.Delete(file);
        }
    }
    #endregion
}
