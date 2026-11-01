namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.Json;

using Spectre.Console;

using Silvergun.CLI;
using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// ADR 0035 decision 2 (S2) in-process: <see cref="ScriptScanStatus.Unavailable"/> is a completeness caveat — "script
/// content scanning did not complete" — exactly like an Unavailable YARA scan, so it makes a run exit 3 unless
/// <c>--allow-incomplete</c> is given, never changes a tripped <c>--strict</c> gate's 2, reaches the <c>--json</c>
/// <c>Completeness</c> block, and keeps a findings-free report from ever reading "Clean". <see cref="ScriptScanStatus.NotRun"/>
/// (still honoured when written explicitly, but produced by nothing since S5) and <see cref="ScriptScanStatus.Completed"/>
/// raise nothing. JSON that predates the field reads as Unavailable since S5/N5 (ADR 0035 review), exactly like
/// YaraScanStatus, so it now carries the caveat. The report surfaces of decision 1 — the Script findings section's note,
/// its "Reason:" line (review W3) and the footer's summary line — are pinned here over hand-built reports, where the
/// console width is ours and the exact wording can be asserted (<see cref="ScriptScanCoverageCliTests"/> drives the
/// same state end to end).
/// </summary>
public sealed class ScriptScanCoverageCompletenessTests
{
    #region Methods: CompletenessAssessment.ForPackage
    [Fact]
    public void ForPackage_WhenTheScriptScanIsUnavailable_IsIncompleteWithItsCaveat()
    {
        var assessment = CompletenessAssessment.ForPackage(PackageWith(scriptStatus: ScriptScanStatus.Unavailable));

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { Caveat }, assessment.Caveats);
    }

    // The same caveat whether or not the scanned files produced findings: the findings are real, the rest unverified.
    [Fact]
    public void ForPackage_WhenTheScriptScanIsUnavailableWithFindings_IsStillIncomplete()
    {
        var assessment = CompletenessAssessment.ForPackage(
            PackageWith(scriptFindings: [Finding()], scriptStatus: ScriptScanStatus.Unavailable));

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { Caveat }, assessment.Caveats);
    }

    // Both scans incomplete: two caveats, YARA's first, each its own sentence.
    [Fact]
    public void ForPackage_WhenYaraAndTheScriptScanAreBothUnavailable_ListsTheScriptCaveatAfterYaras()
    {
        var assessment = CompletenessAssessment.ForPackage(
            PackageWith(yaraStatus: YaraScanStatus.Unavailable, scriptStatus: ScriptScanStatus.Unavailable));

        Assert.Equal(new[] { "the YARA malware-signature scan did not complete", Caveat }, assessment.Caveats);
    }

    // NotRun (written explicitly; nothing produces it since S5) and Completed raise no caveat.
    [Theory]
    [InlineData(ScriptScanStatus.NotRun)]
    [InlineData(ScriptScanStatus.Completed)]
    public void ForPackage_WhenTheScriptScanIsNotRunOrCompleted_RaisesNoCaveat(ScriptScanStatus status)
    {
        var assessment = CompletenessAssessment.ForPackage(PackageWith(scriptStatus: status));

        Assert.True(assessment.IsComplete);
        Assert.Empty(assessment.Caveats);
    }

    // Legacy JSON (no ScriptScanStatus) reaches Unavailable through FromJson since S5/N5, with no reason, and so raises
    // the script caveat — and only it: every other status in this JSON was written Completed (the legacy YARA/OSV defaults
    // are pinned by AnalysisCompletenessTests.ForPackage_LegacyJsonWithoutStatus_YieldsFlagFreeCaveats).
    [Fact]
    public void ForPackage_ForLegacyJsonWithoutTheField_IsUnavailable_AndRaisesTheScriptCaveat()
    {
        var legacy = PackageCapabilityReport.FromJson(LegacyJson())!;

        Assert.Equal(ScriptScanStatus.Unavailable, legacy.ScriptScanStatus);
        Assert.Null(legacy.ScriptScanUnavailableReason);
        var assessment = CompletenessAssessment.ForPackage(legacy);
        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { Caveat }, assessment.Caveats);
    }

    // ... and its human report is never "Clean": "Not verified", naming the script caveat, with the section's note and
    // no Reason line (there is none to show).
    [Fact]
    public void Renderer_ForLegacyJsonWithoutTheField_IsNotVerified_NeverClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, PackageCapabilityReport.FromJson(LegacyJson())!, "Legacy.Package.1.0.0.nupkg");

        var output = writer.ToString();
        var headline = FooterHeadline.Of(output);
        Assert.False(FooterHeadline.IsClean(headline));
        Assert.Equal(FooterHeadline.NotVerified(console, Caveat), headline);
        Assert.Contains("Script content scan did NOT complete", ScriptSection(output), StringComparison.Ordinal);
        Assert.DoesNotContain("Reason:", ScriptSection(output), StringComparison.Ordinal);
    }

    // The default only fills a MISSING field: JSON that says "NotRun" explicitly still reads NotRun, with no caveat.
    [Fact]
    public void ForPackage_ForJsonWithAnExplicitNotRun_RaisesNoScriptCaveat()
    {
        var json = PackageWith().ToJson().Replace("\"ScriptScanStatus\": \"Completed\"", "\"ScriptScanStatus\": \"NotRun\"", StringComparison.Ordinal);
        Assert.Contains("\"ScriptScanStatus\": \"NotRun\"", json, StringComparison.Ordinal);   // precondition

        var report = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(ScriptScanStatus.NotRun, report.ScriptScanStatus);
        var assessment = CompletenessAssessment.ForPackage(report);
        Assert.True(assessment.IsComplete);
        Assert.Empty(assessment.Caveats);
    }
    #endregion

    #region Methods: exit codes (Program.ScanPackageExitCode, the seam RunScanPackage returns)
    // Script-Unavailable alone: 3 with or without --strict (it is a statement about coverage, not a verdict); 0 only
    // with --allow-incomplete.
    [Theory]
    [InlineData(false, false, 3)]
    [InlineData(true, false, 3)]
    [InlineData(false, true, 0)]
    [InlineData(true, true, 0)]
    public void ExitCode_WhenOnlyTheScriptScanIsUnavailable(bool strict, bool allowIncomplete, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(
            PackageWith(scriptStatus: ScriptScanStatus.Unavailable), strict, allowIncomplete));

    // Script findings never gate (ADR 0027), even from an incomplete scan: the incompleteness decides.
    [Theory]
    [InlineData(false, false, 3)]
    [InlineData(true, false, 3)]
    [InlineData(true, true, 0)]
    public void ExitCode_WhenTheScriptScanIsUnavailableWithScriptFindings_TheFindingsDoNotGate(bool strict, bool allowIncomplete, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(
            PackageWith(scriptFindings: [Finding()], scriptStatus: ScriptScanStatus.Unavailable), strict, allowIncomplete));

    // A real gate under --strict still wins: 2 beats 3, with or without --allow-incomplete.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExitCode_UnderStrictWithAGatingFinding_IsStillTwo(bool allowIncomplete)
    {
        var report = PackageWith(
            [Analyzed("lib/net10.0/A.dll", methodsTotal: 4, methodsSkipped: 0) with { Indicators = GatingIndicators("lib/net10.0/A.dll") }],
            scriptStatus: ScriptScanStatus.Unavailable);

        Assert.Equal(2, Program.ScanPackageExitCode(report, strict: true, allowIncomplete));
    }

    [Theory]
    [InlineData(ScriptScanStatus.NotRun)]
    [InlineData(ScriptScanStatus.Completed)]
    public void ExitCode_WhenTheScriptScanIsNotRunOrCompleted_IsZero(ScriptScanStatus status) =>
        Assert.Equal(0, Program.ScanPackageExitCode(PackageWith(scriptStatus: status), strict: true, allowIncomplete: false));
    #endregion

    #region Methods: the --json Completeness block
    [Fact]
    public void Json_TheCompletenessBlock_IsIncompleteAndCarriesTheScriptCaveat()
    {
        var report = PackageWith(scriptStatus: ScriptScanStatus.Unavailable) with { ScriptScanUnavailableReason = Reason };

        var json = Program.WithCompleteness(report.ToJson(), CompletenessAssessment.ForPackage(report));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("Unavailable", root.GetProperty("ScriptScanStatus").GetString());
        Assert.Equal(Reason, root.GetProperty("ScriptScanUnavailableReason").GetString());
        var completeness = root.GetProperty("Completeness");
        Assert.False(completeness.GetProperty("IsComplete").GetBoolean());
        Assert.Equal(new[] { Caveat }, completeness.GetProperty("Caveats").EnumerateArray().Select(e => e.GetString()));
    }
    #endregion

    #region Methods: the renderer
    // No findings and an incomplete scan: the headline is "Not verified" naming the caveat — never "Clean" — the section
    // says the scan did not complete instead of "(none)", and the footer summary says "not verified".
    [Fact]
    public void Renderer_IncompleteWithoutFindings_IsNotVerified_NeverClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, PackageWith(scriptStatus: ScriptScanStatus.Unavailable), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        var headline = FooterHeadline.Of(output);
        Assert.False(FooterHeadline.IsClean(headline));
        Assert.Equal(FooterHeadline.NotVerified(console, Caveat), headline);
        Assert.Contains("[!] Script content scan did NOT complete - some or all script/manifest files NOT verified", output, StringComparison.Ordinal);
        Assert.Contains("Script findings: not verified (scan did not complete)", output, StringComparison.Ordinal);
        Assert.DoesNotContain("(none)", ScriptSection(output), StringComparison.Ordinal);
        Assert.DoesNotContain("Script findings: none", output, StringComparison.Ordinal);
        AssertSevenBitAscii(output);
    }

    // Findings from the files that were scanned: "Findings present", disclosed as "Analysis incomplete" naming the
    // caveat; the section shows the note AND the table; the footer count is marked as a floor.
    [Fact]
    public void Renderer_IncompleteWithFindings_IsFindingsPresent_AndDisclosesTheIncompleteScan()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console,
            PackageWith(scriptFindings: [Finding()], scriptStatus: ScriptScanStatus.Unavailable), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(output));
        Assert.Equal(FooterHeadline.Incomplete(console, Caveat), FooterHeadline.DisclosureOf(writer));
        Assert.Contains("[!] Script content scan INCOMPLETE - 1 finding(s) from the files that were scanned; other files NOT verified", output, StringComparison.Ordinal);
        Assert.Contains("SIL9001", output, StringComparison.Ordinal);   // the table is still there
        Assert.Contains("Script findings: 1 Critical (scan INCOMPLETE - other files not verified)", output, StringComparison.Ordinal);
        AssertSevenBitAscii(output);
    }

    // The control: a Completed scan renders as it always has — the clean "(none)" and "none" — with no incomplete marker
    // anywhere and never the NotRun wording.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Renderer_Completed_SaysNone_AndHasNoIncompleteMarker(bool unicode)
    {
        var (console, writer) = PlainConsole(unicode);

        PackageReportRenderer.Render(console, PackageWith(scriptStatus: ScriptScanStatus.Completed), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.True(FooterHeadline.IsClean(FooterHeadline.Of(output)));
        Assert.Contains("(none)", ScriptSection(output), StringComparison.Ordinal);
        Assert.Contains("Script findings: none", output, StringComparison.Ordinal);
        Assert.DoesNotContain("(not run)", ScriptSection(output), StringComparison.Ordinal);
        Assert.DoesNotContain("Script findings: not run", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Script content scan", output, StringComparison.Ordinal);
        Assert.DoesNotContain(Caveat, output, StringComparison.Ordinal);
    }

    // ADR 0035 S5 review N-1: NotRun with no findings is "not run" — "(not run)" in the section and "Script findings: not
    // run" in the footer — and never the clean "(none)" / "none" of a scan that ran. It is not an incomplete scan either:
    // no Unavailable note, no caveat (NotRun raises none, pinned above), so the headline is unchanged.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Renderer_NotRunWithoutFindings_SaysNotRun_NeverNone(bool unicode)
    {
        var (console, writer) = PlainConsole(unicode);

        PackageReportRenderer.Render(console, PackageWith(scriptStatus: ScriptScanStatus.NotRun), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        var section = ScriptSection(output);
        Assert.Contains("(not run)", section, StringComparison.Ordinal);
        Assert.DoesNotContain("(none)", section, StringComparison.Ordinal);
        Assert.Contains("Script findings: not run", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Script findings: none", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Script content scan", output, StringComparison.Ordinal);
        Assert.DoesNotContain(Caveat, output, StringComparison.Ordinal);
        Assert.True(FooterHeadline.IsClean(FooterHeadline.Of(output)));
        Assert.DoesNotContain("[grey]", output, StringComparison.Ordinal);   // the grey markup is consumed, not leaked
        if (!unicode)
            AssertSevenBitAscii(output);
    }

    // ... and a NotRun report that carries findings (hand-written JSON can) still lists them, with the ordinary footer
    // roll-up and no "not run" wording.
    [Fact]
    public void Renderer_NotRunWithFindings_StillListsThem()
    {
        var (console, writer) = PlainConsole(unicode: false);

        PackageReportRenderer.Render(console,
            PackageWith(scriptFindings: [Finding()], scriptStatus: ScriptScanStatus.NotRun), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        var section = ScriptSection(output);
        Assert.Contains("SIL9001", section, StringComparison.Ordinal);
        Assert.Contains("tools/install.ps1", section, StringComparison.Ordinal);
        Assert.DoesNotContain("(not run)", section, StringComparison.Ordinal);
        Assert.DoesNotContain("(none)", section, StringComparison.Ordinal);
        Assert.Contains("Script findings: 1 Critical", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Script findings: not run", output, StringComparison.Ordinal);
        Assert.DoesNotContain("scan INCOMPLETE", output, StringComparison.Ordinal);
    }

    // The rich console for NotRun: nothing throws and no markup leaks.
    [Fact]
    public void Renderer_NotRunWithoutFindings_RichConsole_SaysNotRun()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console,
            PackageWith(scriptStatus: ScriptScanStatus.NotRun), "Some.Package.1.0.0.nupkg"));

        Assert.Null(ex);
        Assert.Contains("(not run)", writer.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("[/]", writer.ToString(), StringComparison.Ordinal);
    }

    // The rich (Unicode) console too: no markup leaks and nothing throws on the new branches.
    [Fact]
    public void Renderer_IncompleteWithFindings_RichConsole_RendersWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console,
            PackageWith(scriptFindings: [Finding()], scriptStatus: ScriptScanStatus.Unavailable), "Some.Package.1.0.0.nupkg"));

        Assert.Null(ex);
        Assert.Contains("Script content scan INCOMPLETE", writer.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("[/]", writer.ToString(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the renderer's Reason line (ADR 0035 review W3)
    // An Unavailable report with a reason: the line right under the yellow note is "Reason: " + the report's reason, and
    // with findings the table follows it — the saved text report names which files were not scanned and why.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Renderer_UnavailableWithAReason_ShowsItOnTheLineUnderTheNote_BeforeAnyTable(bool withFindings)
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, Unavailable(withFindings, Reason), "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        var lines = Lines(ScriptSection(output));
        var note = Array.FindIndex(lines, l => l.StartsWith(withFindings ? NoteWithFindings : NoteWithoutFindings, StringComparison.Ordinal));
        Assert.True(note >= 0, "no script-scan note in the Script findings section");
        Assert.Equal("Reason: " + Reason, lines[note + 1]);
        Assert.Single(lines, l => l.StartsWith("Reason:", StringComparison.Ordinal));
        if (withFindings)
            Assert.True(Array.FindIndex(lines, l => l.Contains("SIL9001", StringComparison.Ordinal)) > note + 1, "the findings table must follow the Reason line");
        AssertSevenBitAscii(output);
    }

    // The reason is package-derived (it quotes file names): Spectre markup in it renders LITERALLY, plain and rich. A
    // rendered-as-markup "[red]x[/]" would lose its brackets in both modes, so seeing them proves the Esc.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Renderer_UnavailableWithAMarkupReason_RendersItLiterally(bool withFindings)
    {
        var (plain, plainWriter) = AsciiConsole();
        var (rich, richWriter) = RichConsole();
        var report = Unavailable(withFindings, MarkupReason);

        PackageReportRenderer.Render(plain, report, "Some.Package.1.0.0.nupkg");
        var ex = Record.Exception(() => PackageReportRenderer.Render(rich, report, "Some.Package.1.0.0.nupkg"));

        Assert.Equal(MarkupReason, report.ScriptScanUnavailableReason);   // precondition: the report kept the brackets
        Assert.Contains("Reason: " + MarkupReason, Lines(ScriptSection(plainWriter.ToString())));
        Assert.Null(ex);
        Assert.Contains("Reason: " + MarkupReason, richWriter.ToString(), StringComparison.Ordinal);
    }

    // No Reason line unless the scan is Unavailable AND there is a reason: not for Completed (even with a stray reason on
    // the record), not for an Unavailable report whose reason is null (legacy JSON) or empty.
    [Theory]
    [InlineData(ScriptScanStatus.Completed, null, false)]
    [InlineData(ScriptScanStatus.Completed, null, true)]
    [InlineData(ScriptScanStatus.Completed, Reason, false)]
    [InlineData(ScriptScanStatus.Completed, Reason, true)]
    [InlineData(ScriptScanStatus.Unavailable, null, false)]
    [InlineData(ScriptScanStatus.Unavailable, null, true)]
    [InlineData(ScriptScanStatus.Unavailable, "", false)]
    [InlineData(ScriptScanStatus.Unavailable, "", true)]
    public void Renderer_WithoutAnUnavailableReason_HasNoReasonLine(ScriptScanStatus status, string? reason, bool withFindings)
    {
        var (console, writer) = AsciiConsole();
        var report = PackageWith(scriptFindings: withFindings ? [Finding()] : null, scriptStatus: status) with { ScriptScanUnavailableReason = reason };

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        var section = ScriptSection(writer.ToString());
        Assert.DoesNotContain("Reason:", section, StringComparison.Ordinal);
        if (withFindings)
            Assert.Contains("SIL9001", section, StringComparison.Ordinal);   // the section did render its table
    }
    #endregion

    #region Methods: fixtures and console helpers
    private static ScriptFinding Finding() => new(
        "SIL9001", "A rule", "Critical", "High", "tools/install.ps1", 3, "excerpt", [], Occurrences: 1, Source: ScriptFindingSource.Script);

    private static IndicatorReport GatingIndicators(string path) =>
        new(path, path, Epoch, [new IndicatorFinding(IndicatorCategory.CallbackDomain, "x.pipedream.net", "see x.pipedream.net", "Evil.Loader", "M", 1)],
            Truncated: false);

    private static PackageCapabilityReport Unavailable(bool withFindings, string reason) =>
        PackageWith(scriptFindings: withFindings ? [Finding()] : null, scriptStatus: ScriptScanStatus.Unavailable)
            with { ScriptScanUnavailableReason = reason };

    // A report serialized before ScriptScanStatus existed: PackageWith's JSON with that one property taken out (swapped for
    // an unknown one, which FromJson ignores, so the commas stay valid).
    private static string LegacyJson()
    {
        const string field = "\"ScriptScanStatus\": \"Completed\"";
        var json = PackageWith().ToJson();
        Assert.Contains(field, json, StringComparison.Ordinal);   // precondition
        var legacy = json.Replace(field, "\"Unused\": 0", StringComparison.Ordinal);
        Assert.DoesNotContain("ScriptScanStatus", legacy, StringComparison.Ordinal);
        return legacy;
    }

    // The text's lines, trimmed (Spectre pads to the console width).
    private static string[] Lines(string text) => text.Split('\n').Select(l => l.Trim()).ToArray();

    // The "Script findings" section: from its rule to the next section's.
    private static string ScriptSection(string output)
    {
        var start = output.IndexOf("Script findings", StringComparison.Ordinal);
        Assert.True(start >= 0, "no Script findings section");
        var end = output.IndexOf("Packaging anomalies", start, StringComparison.Ordinal);
        return end < 0 ? output[start..] : output[start..end];
    }

    private static (IAnsiConsole Console, StringWriter Writer) AsciiConsole() => PlainConsole(unicode: false);

    // The plain (no ANSI, no colour) console of --output / NO_COLOR, with Unicode on or off (off is the default mode).
    private static (IAnsiConsole Console, StringWriter Writer) PlainConsole(bool unicode)
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = unicode;
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

    private static void AssertSevenBitAscii(string output)
    {
        var offender = output.FirstOrDefault(c => c > (char)0x7F || (c < ' ' && c is not '\r' and not '\n'));
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII without raw controls; found U+{(int)offender:X4}.");
        Assert.DoesNotContain("[/]", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[yellow]", output, StringComparison.Ordinal);
    }
    #endregion

    #region Fields
    private const string Caveat = "script content scanning did not complete";

    private const string Reason = "1 of 2 script/manifest file(s) were not scanned: 'tools/big.ps1 (is 6000000 bytes, over the 5242880-byte script cap)'";

    // A reason quoting a file name that carries Spectre markup (legal in a zip entry name, and escaping leaves it alone).
    private const string MarkupReason = "1 of 2 script/manifest file(s) were not scanned: 'tools/[red]x[/].ps1 (not found or not accessible)'";

    // The yellow note's text in the ASCII console, for each branch.
    private const string NoteWithoutFindings = "[!] Script content scan did NOT complete - some or all script/manifest files NOT verified";
    private const string NoteWithFindings = "[!] Script content scan INCOMPLETE - 1 finding(s) from the files that were scanned; other files NOT verified";
    #endregion
}
