namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

/// <summary>
/// Behavioral tests for the "Script findings" section of <see cref="PackageReportRenderer"/> after the script-rule
/// precision fix (<c>docs/agent/tasks/script-rule-precision.md</c>): findings are aggregated per (rule, file), so a
/// rule matching N times renders once with an occurrence marker (<c>x7</c> in the default ASCII mode, <c>×7</c> in
/// <c>--rich</c>), and manifest-sourced findings carry a literal <c>[metadata]</c> marker because they are advisory
/// and never gate <c>--strict</c>.
///
/// Like <see cref="YaraReportRendererTests"/> and <see cref="VulnerabilitiesReportRendererTests"/>, these assert
/// security/correctness INVARIANTS — the ADR 0014 ASCII-only default and markup-injection safety — not layout, color
/// or wording, which are validated interactively per CLAUDE.md. The ASCII assertion is byte-level on purpose: a
/// hardcoded Unicode glyph in this exact spot is the class of bug this suite exists to catch.
/// </summary>
public sealed class ScriptFindingsReportRendererTests
{
    #region Methods
    // An aggregated finding (Occurrences > 1) renders its count once, with the ASCII "x" prefix in default mode ...
    [Fact]
    public void ScriptFindings_OccurrencesAboveOne_RendersCount()
    {
        var (ascii, asciiWriter) = AsciiConsole();
        PackageReportRenderer.Render(ascii, ReportWith(Finding(occurrences: 7)), "Some.Package.1.0.0.nupkg");

        var asciiOutput = asciiWriter.ToString();
        Assert.Contains("BD000600", asciiOutput);
        Assert.Contains("x7", asciiOutput);
        Assert.DoesNotContain("×7", asciiOutput);   // never the Unicode sign in the default mode

        // ... and the Unicode multiplication sign in --rich.
        var (rich, richWriter) = RichConsole();
        PackageReportRenderer.Render(rich, ReportWith(Finding(occurrences: 7)), "Some.Package.1.0.0.nupkg");

        Assert.Contains("×7", richWriter.ToString());
    }

    // A single match renders no count marker at all — "x1"/"×1" would be noise on the common case.
    [Fact]
    public void ScriptFindings_OccurrencesOne_OmitsCount()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(Finding(occurrences: 1)), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.Contains("BD000600", output);
        Assert.DoesNotContain("x1", output);
        Assert.DoesNotContain("×1", output);
    }

    // A manifest-sourced (advisory) finding is marked so a reader can tell it apart from a gating script finding.
    [Fact]
    public void ScriptFindings_MetadataSource_RendersMetadataMarker()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console, ReportWith(Finding(source: ScriptFindingSource.PackageMetadata)), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.Contains("Some.Package.nuspec:12", output);
        Assert.Contains("[metadata]", output);   // rendered literally (escaped), not interpreted as a markup tag
    }

    // A finding from real script content carries no metadata marker — the marker must not leak onto gating findings.
    [Fact]
    public void ScriptFindings_ScriptSource_OmitsMetadataMarker()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console, ReportWith(Finding(source: ScriptFindingSource.Script)), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.Contains("tools/install.ps1:12", output);
        Assert.DoesNotContain("[metadata]", output);
    }

    // The ADR 0014 invariant, asserted byte-level: with BOTH new renderings active (occurrence count + metadata
    // marker) the default (no --rich) output must stay pure 7-bit ASCII — no 0x1b, no char > 0x7F — and carry no
    // leftover markup tags.
    [Fact]
    public void ScriptFindings_DefaultMode_IsAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console,
            ReportWith(
                Finding(occurrences: 7, source: ScriptFindingSource.PackageMetadata),
                Finding(ruleId: "BD000500", occurrences: 3, source: ScriptFindingSource.Script)),
            "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.Contains("Script findings", output);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }

    // The same report through the --output/NO_COLOR plain path carries no escape bytes and no leftover markup tags.
    [Fact]
    public void ScriptFindings_PlainMode_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(
            console, ReportWith(Finding(occurrences: 7, source: ScriptFindingSource.PackageMetadata)), "Some.Package.nupkg");

        var output = writer.ToString();
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold]", output);
    }

    // Rule id, rule name, relative path, severity and confidence are all untrusted rule/package content. Fed a markup
    // -injection payload in every one of them, rich mode must render the payload LITERALLY without throwing — the
    // unterminated tag would make Spectre's parser throw were any field not passed through Esc. The occurrence count
    // is > 1 and the source is metadata so the payload flows through the two NEW label builders as well.
    [Fact]
    public void ScriptFindings_InjectionPayload_RichConsole_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(Injected()), "clean.nupkg"));

        Assert.Null(ex);   // unescaped markup would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output);    // the payload text survived rendering
        Assert.Contains("[red]", output);    // and its markup was shown literally, not interpreted as color
    }

    // The payload must render literally in the ascii path too (Esc runs regardless of color), and that output must
    // stay 7-bit with no escape byte even with the hostile fields present. (The generic "no leftover markup tags"
    // check does NOT apply here: the payload's own literal text legitimately contains "[/]".)
    [Fact]
    public void ScriptFindings_InjectionPayload_AsciiConsole_RendersLiterallyAndStaysAscii()
    {
        var (console, writer) = AsciiConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, ReportWith(Injected()), "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
    }

    // The footer's severity roll-up ("Script findings: 3 Moderate  -  1 Critical") interpolates ScriptFinding.Severity
    // into markup. That is only reachable through the FULL report (PackageReportRenderer.Render -> Footer), never
    // through ScriptFindingsWidget, so it is exercised here end-to-end. Today the value is always an AppInspector enum
    // name (ScriptRuleScanner writes `match.Severity.ToString()`), but the planned snapshot/diff feature deserializes a
    // PackageCapabilityReport from disk, which makes Severity attacker-controlled free text — the same untrusted-content
    // class as every other field in this section. Both hostile shapes are pinned: a well-formed tag must be rendered
    // LITERALLY (not interpreted as color), and an unterminated bracket must not make Spectre's parser throw.
    [Theory]
    [InlineData("[red]x[/]")]
    [InlineData("crit[")]
    public void Footer_ScriptFindingSeverityContainsMarkup_RendersWithoutThrowing(string severity)
    {
        foreach (var (console, writer) in new[] { AsciiConsole(), RichConsole() })
        {
            var ex = Record.Exception(
                () => PackageReportRenderer.Render(console, ReportWith(Finding(severity: severity)), "hostile.nupkg"));

            Assert.Null(ex);   // an unescaped severity throws InvalidOperationException on the unterminated bracket
            // The roll-up's "<count> <severity>" text, with the payload intact: an interpreted tag would have been
            // consumed by the markup parser and dropped from the output instead of appearing verbatim.
            Assert.Contains($"1 {severity}", writer.ToString());
        }
    }

    // Escaping the roll-up must be a no-op for the real, alphabetic severity names — the whole visible line is pinned in
    // the default ASCII mode (no stray "[[" or dropped count), and the same text still appears in --rich.
    [Fact]
    public void Footer_LegitimateSeverity_RollupOutputUnchanged()
    {
        var (ascii, asciiWriter) = AsciiConsole();
        PackageReportRenderer.Render(ascii, ReportWith(Finding(severity: "Critical")), "Some.Package.1.0.0.nupkg");

        var rollup = asciiWriter.ToString().Split('\n').Select(l => l.TrimEnd('\r'))
            .Single(l => l.StartsWith("Script findings:", StringComparison.Ordinal));
        Assert.Equal("Script findings: 1 Critical", rollup);

        var (rich, richWriter) = RichConsole();
        PackageReportRenderer.Render(rich, ReportWith(Finding(severity: "Critical")), "Some.Package.1.0.0.nupkg");

        Assert.Contains("1 Critical", richWriter.ToString());   // colored, so assert the text rather than the whole line
    }
    #endregion

    #region Methods — fixtures
    private static ScriptFinding Finding(
        string ruleId = "BD000600",
        int occurrences = 1,
        ScriptFindingSource source = ScriptFindingSource.Script,
        string severity = "Moderate") =>
        new(
            ruleId,
            "LOLBAS Windows Indicator",
            severity,
            "Low",
            source == ScriptFindingSource.PackageMetadata ? "Some.Package.nuspec" : "tools/install.ps1",
            12,
            "certutil -urlcache",
            new[] { "Security.Backdoor.LOLBAS.Windows" },
            Occurrences: occurrences,
            Source: source);

    // The free-text fields of an aggregated, metadata-sourced finding all carry the injection payload: rule id and
    // rule name (rule content), relative path (package content) and excerpt (matched package content).
    //
    // Severity/Confidence are deliberately left as real enum names here so this fixture keeps exercising the table's
    // own fields; the hostile-severity case is covered separately (and end-to-end, because it only shows up in the
    // footer roll-up) by Footer_ScriptFindingSeverityContainsMarkup_RendersWithoutThrowing.
    private static ScriptFinding Injected() =>
        new(Inject, Inject, "Moderate", "Low", Inject, 12, Inject, new[] { Inject },
            Occurrences: 7, Source: ScriptFindingSource.PackageMetadata);

    // A minimal, otherwise-clean scan-package report carrying exactly the given script findings. The vuln check is
    // treated as completed so the footer's other states stay out of the way of this section's assertions. So is the
    // script content scan itself: its record default is Unavailable since ADR 0035 S5/N5, which would add an
    // "INCOMPLETE" note to this very section (that state has its own coverage in ScriptScanCoverageCompletenessTests).
    private static PackageCapabilityReport ReportWith(params ScriptFinding[] findings) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            findings,
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            ScriptScanStatus: ScriptScanStatus.Completed);
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
    #endregion

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";
    #endregion
}
