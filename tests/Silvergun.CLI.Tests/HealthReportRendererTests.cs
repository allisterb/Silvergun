namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

/// <summary>
/// Behavioral tests for the "Project Health" report surface (ADR 0015): <see cref="HealthReportRenderer"/> (the
/// <c>health</c> verb) and the shared health section as reached through <see cref="PackageReportRenderer"/> (the
/// <c>scan-package --health</c> path). Like <see cref="ReportRendererTests"/>, these assert security/correctness
/// INVARIANTS — markup-injection safety, ASCII-only default output — not layout/color/wording. Health data is
/// untrusted (repo owner/repo come from a nuspec/GitHub, license and red-flag text are echoed), so every renderer
/// is driven through both the plain/ascii console and the rich console.
/// </summary>
public sealed class HealthReportRendererTests
{
    #region Methods — health verb renderer
    // Populated health in default (no --rich) mode must be pure 7-bit ASCII: no 0x1b, no byte > 0x7F, no leftover tags.
    [Fact]
    public void HealthRenderer_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();
        HealthReportRenderer.Render(console, PopulatedHealthReport());
        AssertSevenBitAscii(writer);
    }

    // The --output/NO_COLOR (plain) path must carry no escape bytes and no leftover markup tags.
    [Fact]
    public void HealthRenderer_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();
        HealthReportRenderer.Render(console, PopulatedHealthReport());
        AssertPlainText(writer);
    }

    // Rich mode fed a markup-injection payload in every untrusted health field (owner/repo, license, red flags)
    // must render the payload LITERALLY without throwing — proving ReportTheme.Esc neutralized it.
    [Fact]
    public void HealthRenderer_RichConsole_WithInjectionPayload_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => HealthReportRenderer.Render(console, InjectionHealthReport()));

        AssertRenderedLiterally(ex, writer);
    }

    // The "health unavailable (reason)" path (null Health) must render without throwing and surface the reason.
    [Fact]
    public void HealthRenderer_NullHealth_RendersUnavailableWithoutThrowing()
    {
        var (console, writer) = AsciiConsole();
        var report = new ProjectHealthReport(
            "Some.Package", Repository: null, Health: null,
            UnavailableReason: "no GitHub repository resolved", GeneratedAt: Epoch);

        var ex = Record.Exception(() => HealthReportRenderer.Render(console, report));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("unavailable", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no GitHub repository resolved", output);
        AssertSevenBitAscii(writer);
    }

    // The unavailable-reason string is untrusted too: an injection payload in UnavailableReason (and in the resolved
    // repo owner/repo shown alongside it) must render literally without throwing, in rich mode.
    [Fact]
    public void HealthRenderer_NullHealth_WithInjectionReason_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var report = new ProjectHealthReport(
            Inject, Repository: new RepositoryRef("github", Inject, Inject), Health: null,
            UnavailableReason: Inject, GeneratedAt: Epoch);

        var ex = Record.Exception(() => HealthReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }
    #endregion

    #region Methods — scan-package --health section
    // scan-package with an attached health section, default mode, must remain pure 7-bit ASCII.
    [Fact]
    public void PackageRenderer_WithHealth_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();
        PackageReportRenderer.Render(console, PackageReportWith(PopulatedHealth()), "Some.Package.1.0.0.nupkg");
        AssertSevenBitAscii(writer);
    }

    // scan-package with an attached health section whose fields carry markup metacharacters must render literally
    // in rich mode without throwing (the health section runs through the same Esc as the rest of the report).
    [Fact]
    public void PackageRenderer_WithHealth_RichConsole_WithInjectionPayload_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, PackageReportWith(InjectionHealth()), "pkg.nupkg"));

        AssertRenderedLiterally(ex, writer);
    }
    #endregion

    #region Methods — fixtures
    private static ProjectHealthReport PopulatedHealthReport() =>
        new("Some.Package", PopulatedHealth().Repository, PopulatedHealth(), null, Epoch);

    // A markup-injection health report: owner/repo, license and every red flag carry the payload; PackageId too.
    private static ProjectHealthReport InjectionHealthReport() =>
        new(Inject, InjectionHealth().Repository, InjectionHealth(), UnavailableReason: null, Epoch);

    // A clean, populated ProjectHealth with red flags present (so the alert glyph/flag line is exercised).
    private static ProjectHealth PopulatedHealth() =>
        new(
            new RepositoryRef("github", "dotnet", "runtime"),
            Stars: 15_000, Forks: 4_000, Subscribers: 900, Watchers: 15_000, OpenIssues: 120, SizeKb: 500_000,
            CreatedAt: new DateTimeOffset(2016, 1, 1, 0, 0, 0, TimeSpan.Zero),
            PushedAt: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
            License: "MIT", Archived: false, Disabled: false, HasIssues: true, DefaultBranch: "main",
            ActivityScore: 95, PopularityScore: 90, MaturityScore: 100, OverallScore: 94,
            Band: HealthBand.Healthy, RedFlags: new[] { "no license" });

    // A ProjectHealth whose every untrusted field carries the markup-injection payload.
    private static ProjectHealth InjectionHealth() =>
        new(
            new RepositoryRef("github", Inject, Inject),
            Stars: 1, Forks: 0, Subscribers: null, Watchers: 1, OpenIssues: null, SizeKb: null,
            CreatedAt: null, PushedAt: null,
            License: Inject, Archived: true, Disabled: false, HasIssues: false, DefaultBranch: Inject,
            ActivityScore: 0, PopularityScore: 0, MaturityScore: 0, OverallScore: 0,
            Band: HealthBand.Poor, RedFlags: new[] { Inject });

    // A minimal, otherwise-clean scan-package report carrying the given health section.
    private static PackageCapabilityReport PackageReportWith(ProjectHealth health)
    {
        var pkg = new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", []);
        return new PackageCapabilityReport(pkg, Epoch, [], [], [], health);
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
