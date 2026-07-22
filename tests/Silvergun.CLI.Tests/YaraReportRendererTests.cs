namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Behavioral tests for the "Malware signatures (YARA)" section of <see cref="PackageReportRenderer"/> (ADR 0016
/// Phase 3). Like <see cref="ReportRendererTests"/> and <see cref="HealthReportRendererTests"/>, these assert
/// security/correctness INVARIANTS — ASCII-only default output and markup-injection safety — not layout/color/wording,
/// which are validated interactively per CLAUDE.md. Every YARA field (rule name, malware family, detection name,
/// category, matched relative path) is untrusted package/rule content, so the renderer must route it through
/// <see cref="ReportTheme.Esc"/>; the injection payload proves it does, across both the ascii and rich consoles.
/// </summary>
public sealed class YaraReportRendererTests
{
    #region Methods
    // A report WITH YARA findings, default (no --rich) mode, must be pure 7-bit ASCII: no 0x1b, no byte > 0x7F, and
    // no leftover markup tags — and the section header + rule name must survive as substrings.
    [Fact]
    public void PackageRenderer_WithYaraFindings_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWithYara(CleanFinding()), "Evil.Package.1.2.3.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Malware signatures (YARA)", output);   // the section header renders
        Assert.Contains("Win32_Trojan_Foo", output);            // the (short, wrap-safe) rule name survives
    }

    // The same report through the --output/NO_COLOR plain path must carry no escape bytes and no leftover markup tags.
    [Fact]
    public void PackageRenderer_WithYaraFindings_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, ReportWithYara(CleanFinding()), "Evil.Package.1.2.3.nupkg");

        AssertPlainText(writer);
    }

    // Rich mode fed a markup-injection payload in EVERY untrusted YARA field must render the payload LITERALLY without
    // throwing — the unterminated tag would make Spectre's parser throw were any field not passed through Esc. Only the
    // YARA finding carries the payload here, so a pass isolates the YARA widget's escaping.
    [Fact]
    public void PackageRenderer_WithYaraInjectionPayload_RichConsole_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var injected = new YaraFinding(Inject, Inject, Inject, Inject, Inject, new[] { Inject }, Inject);

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWithYara(injected), "clean.nupkg"));

        AssertRenderedLiterally(ex, writer);
    }

    // The injection payload must also render literally in the ascii/plain path (Esc runs regardless of color), and the
    // ascii output must carry no escape byte and stay 7-bit even with the hostile field present. (The generic
    // "no leftover markup tags" check does NOT apply here: the payload's own literal text legitimately contains "[/]".)
    [Fact]
    public void PackageRenderer_WithYaraInjectionPayload_AsciiConsole_RendersLiterallyAndStaysAscii()
    {
        var (console, writer) = AsciiConsole();
        var injected = new YaraFinding(Inject, Inject, Inject, Inject, Inject, new[] { Inject }, Inject);

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWithYara(injected), "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output);   // the payload text survived, shown literally
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
    }

    // A clean report (empty YaraFindings) must render the "(none)" clean path without throwing and signal the clean
    // footer — the same shape as the other "no findings" sections.
    [Fact]
    public void PackageRenderer_CleanYara_RendersNoneWithoutThrowing()
    {
        var (console, writer) = AsciiConsole();

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWithYara(), "Benign.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("Malware signatures (YARA)", output);   // the section is always present
        Assert.Contains("(none)", output);                      // clean YARA renders the "(none)" placeholder
        Assert.Contains("Clean", output);                       // and the report footer stays clean
    }
    #endregion

    #region Methods — fixtures
    private static YaraFinding CleanFinding() =>
        new("Win32_Trojan_Foo", "malware", "Foo", "Trojan.Win32.Foo", "MALWARE", new[] { "trojan" }, "lib/net10.0/evil.dll");

    // A minimal, otherwise-clean scan-package report carrying exactly the given YARA findings (none => clean path).
    private static PackageCapabilityReport ReportWithYara(params YaraFinding[] findings)
    {
        var pkg = new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>());
        return new PackageCapabilityReport(
            pkg,
            Epoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            YaraFindings: findings);
    }
    #endregion

    #region Methods — console helpers (mirror ReportRendererTests)
    private static (IAnsiConsole Console, StringWriter Writer) PlainConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Width = 240;
        return (console, writer);
    }

    private static (IAnsiConsole Console, StringWriter Writer) AsciiConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = false;
        console.Profile.Width = 240;
        return (console, writer);
    }

    private static (IAnsiConsole Console, StringWriter Writer) RichConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.Yes,
            ColorSystem = ColorSystemSupport.Standard,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = true;
        console.Profile.Width = 240;
        return (console, writer);
    }

    private static void AssertSevenBitAscii(StringWriter writer)
    {
        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }

    private static void AssertRenderedLiterally(Exception? renderException, StringWriter writer)
    {
        Assert.Null(renderException);   // unescaped markup would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output);    // the payload text survived rendering
        Assert.Contains("[red]", output);    // and its markup was shown literally, not interpreted as color
    }

    private static void AssertPlainText(StringWriter writer)
    {
        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }
    #endregion

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";

    private static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;
    #endregion
}
