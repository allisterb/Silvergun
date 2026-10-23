#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.Reflection;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// <c>SILVERGUN_YARA_ENGINE</c> on the net10.0 (non-Windows) build (ADR 0033 polish round, Nit 4). The variable selects
/// a WINDOWS backend, so here <c>yarax</c> and <c>libyara</c> (any case) are real values that have no effect on this
/// build: one warning says exactly that, rather than calling them unrecognised. Any other set value keeps the
/// "is not recognised" warning. Both quote the value escaped and bounded (it is environment text), and the default
/// backend is kept either way.
///
/// <para><see cref="YaraScannerFactory.Shared"/> reads the variable once per process (a <c>Lazy</c> with no reset hook,
/// by design), so each case calls the factory's private <c>Create</c> by reflection, which builds a fresh backend and
/// warns exactly as the first touch of <c>Shared</c> would. <c>SILVERGUN_YARA_PATH</c> is unset around it
/// (<see cref="YaraEnvScope"/>, which also pins <c>Shared</c> first), so the backend is the no-op one and no real
/// <c>yara</c> is ever started. In <see cref="YaraEnvCollection"/>, with every other class that sets these variables.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraScannerFactoryNonWindowsTests
{
    #region Methods
    [Theory]
    [InlineData("yarax")]
    [InlineData("YaraX")]
    [InlineData("YARAX")]
    [InlineData("libyara")]
    [InlineData("LibYara")]
    [InlineData("LIBYARA")]
    public void AWindowsEngineValue_WarnsOnceThatItHasNoEffectOnThisBuild(string value)
    {
        var (backend, warnings) = Create(value);

        Assert.IsType<NullYaraScanner>(backend);
        var warning = Assert.Single(warnings, w => w.Contains("SILVERGUN_YARA_ENGINE", StringComparison.Ordinal));
        Assert.Equal($"SILVERGUN_YARA_ENGINE='{value}' has no effect on this build (it selects a Windows backend); using the default YARA backend.", warning);
        Assert.DoesNotContain("not recognised", warning, StringComparison.Ordinal);
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
    // A fresh factory choice with SILVERGUN_YARA_ENGINE = `value` and no classic yara configured; the warnings it logged.
    private static (IYaraScanner Backend, string[] Warnings) Create(string? value)
    {
        var create = typeof(YaraScannerFactory).GetMethod("Create", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.True(create is not null, "YaraScannerFactory.Create is gone; these tests call it to make a fresh choice.");

        using var scope = new YaraEnvScope(yara: null, yarac: null);
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
