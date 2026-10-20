namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.Json;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0032's report surfaces for a YARA scan that could not finish but found something —
/// <see cref="YaraScanStatus.Unavailable"/> <b>with</b> <see cref="PackageCapabilityReport.YaraFindings"/> — pinned
/// in-process over a hand-built report, where the console width is ours to set and exact wording can be asserted.
/// (<see cref="YaraIncompleteScanCliTests"/> drives the same state through the real verb, end to end.)
///
/// <para>The invariant across all of them: <b>neither half may hide the other.</b> The findings are real
/// detections and must render exactly as a completed scan's do; the other files are unverified and must say so.
/// Before ADR 0032 the widget keyed on status alone, so Unavailable rendered only "did NOT run" — over findings it
/// had in hand. Like <see cref="YaraReportRendererTests"/>, the default (no <c>--rich</c>) output must stay 7-bit
/// ASCII, and every untrusted field must still be escaped.</para>
/// </summary>
public sealed class YaraIncompleteScanRendererTests
{
    #region Methods — renderer
    // Both halves, in the default ASCII output: the reworded warning (ASCII glyph and dash) AND the findings table.
    [Fact]
    public void Renderer_UnavailableWithFindings_ShowsTheIncompleteWarningAndTheFindingsTable()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Report(YaraScanStatus.Unavailable, Finding("Win32_Trojan_Foo"), Finding("Bare_Rule")), "Evil.nupkg");

        var output = writer.ToString();
        Assert.Contains(
            "[!] YARA malware-signature scan INCOMPLETE - 2 match(es) found in the files that were scanned; other files NOT verified",
            output, StringComparison.Ordinal);
        Assert.Contains("Win32_Trojan_Foo", output, StringComparison.Ordinal);   // ...and the table under it
        Assert.Contains("Bare_Rule", output, StringComparison.Ordinal);
        Assert.Contains("lib/net10.0/evil.dll", output, StringComparison.Ordinal);
        Assert.DoesNotContain("did NOT run", output, StringComparison.Ordinal);   // that line would contradict the table
        AssertSevenBitAsciiWithoutMarkupOrControls(output);
    }

    // The summary line keeps the count — the hits are real — and marks it as a floor, because the other files were
    // not verified.
    [Fact]
    public void Renderer_UnavailableWithFindings_SummaryLineCountsTheMatchesAndMarksTheScanIncomplete()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Report(YaraScanStatus.Unavailable, Finding("A"), Finding("B")), "Evil.nupkg");

        Assert.Contains(
            "Malware signatures (YARA): 2 match(es) (scan INCOMPLETE - other files not verified)",
            writer.ToString(), StringComparison.Ordinal);
    }

    // The marker is specific to Unavailable: a COMPLETED scan with the same findings must not claim to be incomplete.
    [Fact]
    public void Renderer_CompletedWithFindings_SummaryLineIsNotMarkedIncomplete()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Report(YaraScanStatus.Completed, Finding("A"), Finding("B")), "Evil.nupkg");

        var output = writer.ToString();
        Assert.Contains("Malware signatures (YARA): 2 match(es)", output, StringComparison.Ordinal);
        Assert.DoesNotContain("INCOMPLETE", output, StringComparison.Ordinal);
    }

    // Unavailable WITHOUT findings is unchanged by ADR 0032: the "did NOT run" warning and "not verified" summary,
    // and no claim of matches or of an incomplete scan that found anything.
    [Fact]
    public void Renderer_UnavailableWithoutFindings_IsUnchanged()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Report(YaraScanStatus.Unavailable), "Benign.nupkg");

        var output = writer.ToString();
        Assert.Contains("[!] YARA malware-signature scan did NOT run (backend unavailable) - NOT verified", output, StringComparison.Ordinal);
        Assert.Contains("Malware signatures (YARA): not verified (scan did not run)", output, StringComparison.Ordinal);
        Assert.DoesNotContain("INCOMPLETE", output, StringComparison.Ordinal);
        Assert.DoesNotContain("match(es)", output, StringComparison.Ordinal);
    }

    // The partial findings' paths reach the renderer already escaped (PackageScanner escapes at the report boundary),
    // and a hostile one must stay inert through the new Rows layout too: no raw control character, the escape text
    // shown literally.
    [Fact]
    public void Renderer_UnavailableWithAnEscapedHostilePath_PrintsItLiterallyWithNoRawControlCharacter()
    {
        var (console, writer) = AsciiConsole();
        var hostile = new YaraFinding("Fake_Rule", null, null, null, null, Array.Empty<string>(), @"content/pay\nload" + EscapedRlo + ".bin");

        PackageReportRenderer.Render(console, Report(YaraScanStatus.Unavailable, hostile), "Evil.nupkg");

        var output = writer.ToString();
        Assert.Contains(@"content/pay\nload" + EscapedRlo + ".bin", output, StringComparison.Ordinal);
        AssertSevenBitAsciiWithoutMarkupOrControls(output);
    }

    // Markup injection in every untrusted field, under the NEW Unavailable-with-findings branch and the rich console:
    // must render literally without Spectre's parser throwing (an unescaped field would).
    [Fact]
    public void Renderer_UnavailableWithAnInjectionPayload_RichConsole_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var injected = new YaraFinding(Inject, Inject, Inject, Inject, Inject, new[] { Inject }, Inject);

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, Report(YaraScanStatus.Unavailable, injected), "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output, StringComparison.Ordinal);
        Assert.Contains("[red]", output, StringComparison.Ordinal);   // shown, not interpreted
        Assert.Contains("INCOMPLETE", output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods — JSON and exit code (pins of logic ADR 0032 deliberately did NOT change)
    // --json needs no new field (ADR 0032 decision 3): the existing two carry the combination.
    [Fact]
    public void Json_UnavailableWithFindings_CarriesBothTheFindingsAndTheStatus()
    {
        using var json = JsonDocument.Parse(Report(YaraScanStatus.Unavailable, Finding("A")).ToJson());

        Assert.Equal("Unavailable", json.RootElement.GetProperty("YaraScanStatus").GetString());
        var finding = Assert.Single(json.RootElement.GetProperty("YaraFindings").EnumerateArray().ToArray());
        Assert.Equal("A", finding.GetProperty("RuleName").GetString());
    }

    // ScanExitCode tests "strict && a YARA hit" BEFORE incompleteness, so once the findings reach the report the exit
    // code is already right; ADR 0032 changed no exit-code logic. This is the truth table over the report seam the
    // run method uses. NOTE: on its own this is NOT a regression guard for ADR 0032 — it passes against the
    // pre-change code too, because there the report never carried findings alongside Unavailable in the first
    // place. The end-to-end guard is YaraIncompleteScanCliTests.
    [Theory]
    [InlineData(true, false, 2)]    // --strict: the hit gates
    [InlineData(true, true, 2)]     // --strict --allow-incomplete: still gates — allow-incomplete cannot pass a detection
    [InlineData(false, false, 3)]   // no --strict: incomplete
    [InlineData(false, true, 0)]    // no --strict, --allow-incomplete: nothing gates
    public void ExitCode_UnavailableWithFindings(bool strict, bool allowIncomplete, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(Report(YaraScanStatus.Unavailable, Finding("A")), strict, allowIncomplete));

    // ...and without findings, unchanged: --strict has nothing to gate on, so incompleteness decides.
    [Theory]
    [InlineData(true, false, 3)]
    [InlineData(true, true, 0)]
    [InlineData(false, false, 3)]
    [InlineData(false, true, 0)]
    public void ExitCode_UnavailableWithoutFindings_IsUnchanged(bool strict, bool allowIncomplete, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(Report(YaraScanStatus.Unavailable), strict, allowIncomplete));
    #endregion

    #region Methods — fixtures and console helpers
    private static YaraFinding Finding(string rule) =>
        new(rule, "malware", "Foo", "Trojan.Win32.Foo", "MALWARE", new[] { "trojan" }, "lib/net10.0/evil.dll");

    // An otherwise-clean report (vulnerability check completed) whose only variable is the YARA state.
    private static PackageCapabilityReport Report(YaraScanStatus status, params YaraFinding[] findings) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            YaraFindings: findings,
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            YaraScanStatus: status);

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

    // 7-bit, no ANSI escape, no leftover markup tags, and no raw control character other than line breaks.
    private static void AssertSevenBitAsciiWithoutMarkupOrControls(string output)
    {
        Assert.NotEqual(0, output.Length);
        var offender = output.FirstOrDefault(c => c > (char)0x7F || (c < ' ' && c is not '\r' and not '\n'));
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII without raw controls; found U+{(int)offender:X4}.");
        Assert.DoesNotContain("[/]", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[yellow]", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[grey]", output, StringComparison.Ordinal);
    }
    #endregion

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";

    // The backslash-u form YaraPathSafety.Escape renders U+202E RIGHT-TO-LEFT OVERRIDE as (built, never typed raw).
    private const string EscapedRlo = @"\" + "u202e";
    #endregion
}
