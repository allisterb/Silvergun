namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Behavioral tests for the "Packaging anomalies" section of <see cref="PackageReportRenderer"/> (ADR 0031).
/// Structured exactly like <see cref="YaraReportRendererTests"/>, and for the same reason: these assert
/// security/correctness INVARIANTS — ASCII-only default output, markup-injection safety, and that an absent list
/// reads as "none" rather than as an error — not layout, colour or wording, which CLAUDE.md validates interactively.
///
/// <para>Both of <see cref="PackagingAnomaly"/>'s text fields are attacker-authored package content that has
/// ALREADY been through <c>YaraPathSafety.Escape</c> at the analyzer boundary. That is a different concern from
/// Spectre markup escaping, and the renderer must still do the latter — the injection payload below is what proves
/// it, and <see cref="PackageRenderer_WithAnEscapedEntryName_PrintsTheEscapeSequenceLiterally"/> is what proves the
/// former survives to the terminal instead of being un-escaped on the way.</para>
/// </summary>
public sealed class PackagingAnomaliesReportRendererTests
{
    #region Methods — encoding and markup invariants
    // A report WITH anomalies, default (no --rich) mode, must be pure 7-bit ASCII: no 0x1b, no byte > 0x7F and no
    // leftover markup tags — and the section header plus the category name must survive as substrings.
    [Fact]
    public void PackageRenderer_WithPackagingAnomalies_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(CleanAnomaly()), "Evil.Package.1.2.3.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Packaging anomalies", output, StringComparison.Ordinal);
        Assert.Contains("ControlCharacter", output, StringComparison.Ordinal);
    }

    // The same report through the --output/NO_COLOR plain path must carry no escape bytes and no leftover markup.
    [Fact]
    public void PackageRenderer_WithPackagingAnomalies_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, ReportWith(CleanAnomaly()), "Evil.Package.1.2.3.nupkg");

        AssertPlainText(writer);
    }

    // Rich mode fed a markup-injection payload in EVERY untrusted field must render it LITERALLY without throwing —
    // the unterminated tag would make Spectre's parser throw were any field not passed through Esc. Only the
    // packaging anomaly carries the payload here, so a pass isolates THIS widget's escaping.
    [Fact]
    public void PackageRenderer_WithPackagingAnomalyInjectionPayload_RichConsole_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var injected = new PackagingAnomaly(PackagingAnomalyCategory.BidiControl, Inject, Inject);

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(injected), "clean.nupkg"));

        Assert.Null(ex);   // unescaped markup would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output, StringComparison.Ordinal);   // the payload text survived rendering
        Assert.Contains("[red]", output, StringComparison.Ordinal);   // ...shown literally, not interpreted as colour
    }

    // The payload must also render literally on the ascii path (Esc runs regardless of colour), and that output must
    // stay 7-bit with no escape byte. (The generic "no leftover markup tags" check does NOT apply: the payload's own
    // literal text legitimately contains "[/]".)
    [Fact]
    public void PackageRenderer_WithPackagingAnomalyInjectionPayload_AsciiConsole_RendersLiterallyAndStaysAscii()
    {
        var (console, writer) = AsciiConsole();
        var injected = new PackagingAnomaly(PackagingAnomalyCategory.BidiControl, Inject, Inject);

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(injected), "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output, StringComparison.Ordinal);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
    }
    #endregion

    #region Methods — the escaped name reaches the terminal escaped
    // The whole point of ADR 0031 decision 4: the entry name shown to an operator is the ESCAPED one. A hostile
    // entry "content/pay<LF>load.bin" must appear as the six visible characters "pay\nload", never as a real
    // newline that would split the table row and hide the rest of the finding. Asserted in BOTH modes, because
    // --rich and the ASCII default are separate code paths through the widget.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PackageRenderer_WithAnEscapedEntryName_PrintsTheEscapeSequenceLiterally(bool rich)
    {
        var (console, writer) = rich ? RichConsole() : AsciiConsole();
        var anomaly = new PackagingAnomaly(
            PackagingAnomalyCategory.ControlCharacter, @"content/pay\nload.bin", "contains control character(s) U+000A");

        PackageReportRenderer.Render(console, ReportWith(anomaly), "Evil.nupkg");

        var output = writer.ToString();
        Assert.Contains(@"pay\nload.bin", output, StringComparison.Ordinal);
        Assert.Contains("U+000A", output, StringComparison.Ordinal);
    }

    // ...and nothing the widget prints reintroduces a raw hostile character. The renderer receives already-escaped
    // text, so the only way one could appear is if the widget un-escaped it — this is the assertion that says so.
    // Line breaks are excluded, obviously: the report is made of lines.
    [Fact]
    public void PackageRenderer_WithHostileAnomalies_PrintsNoRawControlOrBidiCharacter()
    {
        var (console, writer) = AsciiConsole();
        PackagingAnomaly[] anomalies =
        [
            new(PackagingAnomalyCategory.ControlCharacter, @"content/pay\nload.bin", @"contains control character(s) U+000A"),
            new(PackagingAnomalyCategory.BidiControl, @"content/gnp\u202ecod.exe", @"contains bidirectional control character(s) U+202E"),
            new(PackagingAnomalyCategory.PathTraversal, "../../evil.dll", "entry target escapes the package content root (zip slip)"),
        ];

        PackageReportRenderer.Render(console, ReportWith(anomalies), "Evil.nupkg");

        var offender = writer.ToString().FirstOrDefault(IsHostile);
        Assert.True(offender == '\0', $"the rendered report carried raw U+{(int)offender:X4}.");
    }
    #endregion

    #region Methods — absent reads as none, never as an error
    // An empty list is a genuine "(none)". Unlike YARA/OSV this pass is pure, offline and cannot be unavailable, so
    // there is no third state — and an absent list must not render as a warning, a blank, or a crash.
    [Fact]
    public void PackageRenderer_WithNoPackagingAnomalies_RendersNoneWithoutThrowing()
    {
        var (console, writer) = AsciiConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(), "Benign.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("Packaging anomalies", output, StringComparison.Ordinal);   // the section is always present
        Assert.Contains("(none)", output, StringComparison.Ordinal);
    }

    // A report that predates the field (PackagingAnomalies left at its record default) renders identically — the
    // normalizing initializer means the widget can never see null.
    [Fact]
    public void PackageRenderer_WhenTheFieldWasNeverPopulated_RendersTheSectionAsNone()
    {
        var (console, writer) = AsciiConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWithoutTheField(), "Legacy.nupkg"));

        Assert.Null(ex);
        Assert.Contains("Packaging anomalies", writer.ToString(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods — the verdict headline is NOT moved by an anomaly (the render-level twin of the exit-code pin)
    // ADR 0031 decision 3 keeps this class of finding purely informational until its benign prevalence is measured.
    // "Attention" is the headline the exit-code gate mirrors, so anomalies are deliberately excluded from it: an
    // otherwise-clean, fully-verified package that ships a bidi-override entry name still reads "Clean" — with the
    // anomaly plainly visible in its own section and in the footer's count line. If a future ADR promotes these to
    // gating findings, THIS test and PackagingAnomalyExitCodeInvarianceTests are the two that must change together.
    [Fact]
    public void PackageRenderer_WithPackagingAnomalies_StillReportsTheCleanVerdict()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(CleanAnomaly()), "Anomalous.nupkg");

        Assert.Equal(
            FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail),
            FooterHeadline.Of(writer));
    }

    // The footer's count line mirrors the section either way, so an operator skimming only the summary still sees
    // that the package tripped something.
    [Fact]
    public void PackageRenderer_FooterCountLine_ReportsTheAnomalyCountWhenPresentAndNoneWhenAbsent()
    {
        var (withConsole, withWriter) = AsciiConsole();
        PackageReportRenderer.Render(withConsole, ReportWith(CleanAnomaly(), CleanAnomaly()), "Anomalous.nupkg");

        var (withoutConsole, withoutWriter) = AsciiConsole();
        PackageReportRenderer.Render(withoutConsole, ReportWith(), "Benign.nupkg");

        Assert.Contains("Packaging anomalies: 2 finding(s)", withWriter.ToString(), StringComparison.Ordinal);
        Assert.Contains("Packaging anomalies: none", withoutWriter.ToString(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods — fixtures
    private static PackagingAnomaly CleanAnomaly() =>
        new(PackagingAnomalyCategory.ControlCharacter, @"content/pay\nload.bin", "contains control character(s) U+000A");

    // A minimal, otherwise-clean and fully-VERIFIED scan-package report carrying exactly the given anomalies. Both
    // the OSV and YARA statuses are Completed for the same reason YaraReportRendererTests sets them: an unverified
    // scan reads "Not verified", and these tests are about the anomalies section, not about incompleteness.
    private static PackageCapabilityReport ReportWith(params PackagingAnomaly[] anomalies) =>
        ReportWithoutTheField() with { PackagingAnomalies = anomalies };

    private static PackageCapabilityReport ReportWithoutTheField() =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            Epoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            YaraScanStatus: YaraScanStatus.Completed);
    #endregion

    #region Methods — console helpers (mirror YaraReportRendererTests)
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

    private static void AssertPlainText(StringWriter writer)
    {
        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }

    // C0 (minus the line breaks the report is made of), DEL, the C1 controls, the Unicode line/paragraph separators
    // and the bidi embeddings/overrides and isolates.
    private static bool IsHostile(char c) =>
        (c < ' ' && c is not ('\n' or '\r' or '\t'))
        || c is >= (char)0x7F and <= (char)0x9F
             or (char)0x2028 or (char)0x2029
             or >= (char)0x202A and <= (char)0x202E
             or >= (char)0x2066 and <= (char)0x2069;
    #endregion

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";

    private static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;
    #endregion
}
