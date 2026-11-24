#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.Reflection;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// <c>SILVERGUN_YARA_ENGINE</c> on the net10.0 build (ADR 0033 polish round, Nit 4; <c>docs/agent/tasks/yarax-worker-linux.md</c>
/// L5). On Linux <c>yarax</c> (any case) selects the YARA-X worker, over <c>SILVERGUN_YARA_PATH</c>, with no warning;
/// the default (unset or empty) is unchanged in Phase 1. Every other platform this build runs on (Windows net10.0, which
/// has no YARA-X library) has no such backend, and <c>libyara</c> is Windows-only everywhere: there those values are
/// real values that have no effect on this build, and one warning says exactly that, rather than calling them
/// unrecognised. Any other set value keeps the "is not recognised" warning. Both quote the value escaped and bounded (it
/// is environment text), and the default backend is kept either way.
///
/// <para><see cref="YaraScannerFactory.Shared"/> reads the variable once per process (a <c>Lazy</c> with no reset hook,
/// by design), so each case calls the factory's private <c>Create</c> by reflection, which builds a fresh backend and
/// warns exactly as the first touch of <c>Shared</c> would. <c>SILVERGUN_YARA_PATH</c> is unset around it
/// (<see cref="YaraEnvScope"/>, which also pins <c>Shared</c> first), so the backend is the no-op one and no real
/// <c>yara</c> is ever started; the precedence tests set it to a <see cref="PlaceholderYaraBinary"/>, which selection only
/// checks exists. A selected <see cref="YaraXWorkerScanner"/> is disposed unused: selecting it starts no worker. In <see cref="YaraEnvCollection"/>, with every other class that sets these variables.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraScannerFactoryNonWindowsTests
{
    #region Methods
    // libyara is Windows-only on every platform this build runs on (Linux included, L5).
    [Theory]
    [InlineData("libyara")]
    [InlineData("LibYara")]
    [InlineData("LIBYARA")]
    public void LibYara_WarnsOnceThatItHasNoEffectOnThisBuild(string value) => AssertHasNoEffect(value);

    // yarax too, except on Linux, where it selects the worker (OnLinux_YaraX_SelectsTheWorker_WithoutAWarning).
    [NonLinuxTheory]
    [InlineData("yarax")]
    [InlineData("YaraX")]
    [InlineData("YARAX")]
    public void OffLinux_YaraX_WarnsOnceThatItHasNoEffectOnThisBuild(string value) => AssertHasNoEffect(value);

    // L5: on Linux `yarax` (any case) is the YARA-X worker, and says nothing (it is a value this build acts on). Selection
    // loads nothing: the worker's probe runs on first use.
    [OnLinuxTheory]
    [InlineData("yarax")]
    [InlineData("YaraX")]
    [InlineData("YARAX")]
    public void OnLinux_YaraX_SelectsTheWorker_WithoutAWarning(string value)
    {
        var (backend, warnings) = Create(value);
        using var _ = backend as IDisposable;

        Assert.IsType<YaraXWorkerScanner>(backend);
        Assert.DoesNotContain(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
    }

    // L5 precedence: an explicit `yarax` wins over a valid SILVERGUN_YARA_PATH, which alone would select the classic CLI.
    [OnLinuxFact]
    public void OnLinux_YaraX_WinsOverAValidYaraPath()
    {
        using var yara = new PlaceholderYaraBinary();

        var (backend, warnings) = Create("yarax", yara.BinaryPath);
        using var _ = backend as IDisposable;

        Assert.IsType<YaraXWorkerScanner>(backend);
        Assert.DoesNotContain(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
    }

    // L5, Phase 1: the default is unchanged — unset or empty, a valid SILVERGUN_YARA_PATH is the classic CLI (on every
    // platform this build runs on), and without one it is the no-op backend (UnsetOrEmpty_WarnsNothing).
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void UnsetOrEmpty_WithAValidYaraPath_IsStillTheClassicCli(string? value)
    {
        using var yara = new PlaceholderYaraBinary();

        var (backend, warnings) = Create(value, yara.BinaryPath);

        Assert.IsType<YaraCliScanner>(backend);
        Assert.DoesNotContain(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
    }

    // L5: libyara stays Windows-only, also over a valid SILVERGUN_YARA_PATH: warned, and the default (the CLI) is kept.
    [Fact]
    public void LibYara_WithAValidYaraPath_IsWarned_AndTheDefaultIsKept()
    {
        using var yara = new PlaceholderYaraBinary();

        var (backend, warnings) = Create("libyara", yara.BinaryPath);

        Assert.IsType<YaraCliScanner>(backend);
        Assert.Contains("has no effect on this build", Assert.Single(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal)), StringComparison.Ordinal);
    }

    // Anything else that is set is still unrecognised; exact match apart from case, so a padded or hyphenated name is too.
    [Theory]
    [InlineData("yara-x")]
    [InlineData(" yarax")]
    [InlineData("libyara ")]
    [InlineData("cli")]
    public void AnyOtherValue_IsStillNotRecognised(string value)
    {
        var (backend, warnings) = Create(value);

        Assert.IsType<NullYaraScanner>(backend);
        var warning = Assert.Single(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
        Assert.Equal($"SILVERGUN_YARA_ENGINE='{value}' is not recognised (this build has no alternative YARA backend to select); using the default YARA backend.", warning);
        Assert.DoesNotContain("has no effect", warning, StringComparison.Ordinal);
    }

    // Environment text is hostile: quoted escaped (no raw control or bidi character) and bounded to 64 chars.
    [Fact]
    public void AHostileValue_IsQuotedEscapedAndBounded()
    {
        var (_, warnings) = Create("yarax\n[ERR] forged" + (char)0x202E + (char)0x1B + new string('z', 300));

        var warning = Assert.Single(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
        Assert.DoesNotContain(warning, c => c < ' ' || c == (char)0x202E);
        var quoted = warning[(warning.IndexOf('\'') + 1)..warning.IndexOf("' is not recognised", StringComparison.Ordinal)];
        Assert.Equal(64, quoted.Length);
        Assert.StartsWith(@"yarax\n[ERR] forged" + EscapedRlo + @"\x1bzzz", quoted, StringComparison.Ordinal);
        Assert.EndsWith("...", quoted, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void UnsetOrEmpty_WarnsNothing(string? value)
    {
        var (backend, warnings) = Create(value);

        Assert.IsType<NullYaraScanner>(backend);
        Assert.DoesNotContain(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: helpers
    private static void AssertHasNoEffect(string value)
    {
        var (backend, warnings) = Create(value);

        Assert.IsType<NullYaraScanner>(backend);
        var warning = Assert.Single(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
        Assert.Equal($"SILVERGUN_YARA_ENGINE='{value}' has no effect on this build (it selects a backend this platform does not have); using the default YARA backend.", warning);
        Assert.DoesNotContain("not recognised", warning, StringComparison.Ordinal);
    }

    // A fresh factory choice with SILVERGUN_YARA_ENGINE = `value` and SILVERGUN_YARA_PATH = `yara` (none by default); the
    // warnings it logged.
    private static (IYaraScanner Backend, string[] Warnings) Create(string? value, string? yara = null)
    {
        var create = typeof(YaraScannerFactory).GetMethod("Create", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.True(create is not null, "YaraScannerFactory.Create is gone; these tests call it to make a fresh choice.");

        using var scope = new YaraEnvScope(yara, yarac: null);
        var previous = Environment.GetEnvironmentVariable(YaraScannerFactory.EngineVar);
        Environment.SetEnvironmentVariable(YaraScannerFactory.EngineVar, value);
        try
        {
            using var warnings = new WarningCapture();
            var backend = (IYaraScanner)create!.Invoke(null, null)!;
            return (backend, warnings.Warnings.ToArray());
        }
        finally
        {
            Environment.SetEnvironmentVariable(YaraScannerFactory.EngineVar, previous);
        }
    }
    #endregion

    #region Fields
    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries the escape
    // sequence (or the character) itself.
    private const string EscapedRlo = @"\" + "u202e";
    #endregion
}
#endif
