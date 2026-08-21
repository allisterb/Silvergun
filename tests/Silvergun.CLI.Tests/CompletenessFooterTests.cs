namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// Behavioral tests for the shared completeness footer (ADR 0024) in BOTH verb renderers: the IL coverage line and
/// the three-tier <b>Findings present</b> / <b>Not verified</b> / <b>Clean</b> headline.
/// <para>
/// The load-bearing case is <c>analyze</c> with methods that could not be analyzed: before ADR 0024 that report read
/// "Clean", which is a false all-clear on the primary IL verb — an attacker who can make our analysis fail on their
/// own assembly turned the scanner into a rubber stamp. These tests pin that it now reads "Not verified" and NEVER
/// "Clean". Caveats embed untrusted package content (assembly paths), so the injection tests here mirror the existing
/// hostile-<c>CalledApi</c> precedent in <see cref="ReportRendererTests"/>.
/// </para>
/// </summary>
public sealed class CompletenessFooterTests
{
    #region Methods — assembly footer (the false-clean ADR 0024 removes)
    [Fact]
    public void AssemblyFooter_WhenMethodsCouldNotBeAnalyzed_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 120, methodsSkipped: 3));

        // Whole-line equality on the ONE verdict headline (see FooterHeadline): it states in a single assertion that
        // the report says "Not verified", that it names the gap, and that it is therefore not the Clean line — where
        // DoesNotContain("Clean") was a statement about the whole report, which these caveats can defeat by merely
        // embedding an assembly path that contains the token.
        Assert.Equal(
            FooterHeadline.NotVerified(console, "3 of 120 method(s) could not be analyzed"),
            FooterHeadline.Of(writer));
    }

    [Fact]
    public void AssemblyFooter_WhenObfuscationAnalysisDidNotComplete_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 5, methodsSkipped: 0, obfuscation: false));

        Assert.Equal(
            FooterHeadline.NotVerified(console, "the obfuscation analysis did not complete"),
            FooterHeadline.Of(writer));
    }

    // The sixth caveat source in the footer. This is where the metadata gap is visible to a human: the report prints
    // "(unavailable)" in its Metadata section, which is easy to skim past — the headline must refuse to say "Clean".
    // (Not reachable end-to-end through the analyze verb: an input whose metadata read fails fails AssemblyAnalyzer.Load
    // first and exits 1 with no report — see the note on
    // CompletenessExitCodeTests.Analyze_WhenAssemblyMetadataCouldNotBeRead_ExitsThree.)
    [Fact]
    public void AssemblyFooter_WhenMetadataCouldNotBeRead_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 5, methodsSkipped: 0, metadata: false));

        Assert.Equal(
            FooterHeadline.NotVerified(console, "the assembly metadata could not be read"),
            FooterHeadline.Of(writer));
    }

    // The complement: an assembly whose analyses all ran and found nothing is the ONE shape allowed to read "Clean".
    [Fact]
    public void AssemblyFooter_WhenCompleteAndFindingFree_SaysClean()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 5, methodsSkipped: 0));

        // The assembly verb's own cleanDetail tail — the package footer's is a different sentence, so the expected
        // line is built per renderer rather than shared.
        Assert.Equal(
            FooterHeadline.Clean(console, FooterHeadline.AssemblyCleanDetail),
            FooterHeadline.Of(writer));
    }

    // Findings win the HEADLINE (that verdict is accurate and actionable), but incompleteness is still DISCLOSED on
    // its own line — "there may be more". A reviewer must never see a finding list that silently omits the caveat.
    [Fact]
    public void AssemblyFooter_WhenFindingsAndIncomplete_ShowsFindingsHeadlineAndStillDisclosesCaveats()
    {
        var (console, writer) = PlainConsole();
        var report = AssemblyReport(
            methodsTotal: 10, methodsSkipped: 4,
            findings: [new ApiCallFinding(Capability.FileSystem, ApiCallKind.Call, "T", "M", "System.IO.File.ReadAllText")]);

        AssemblyReportRenderer.Render(console, report);

        // The verdict line is the findings one ...
        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
        // ... and the caveat is still disclosed, whole, on its own line.
        Assert.Equal(
            FooterHeadline.Incomplete(console, "4 of 10 method(s) could not be analyzed"),
            FooterHeadline.DisclosureOf(writer));
    }

    // Spec criterion 5: the coverage numbers were computed and invisible before ADR 0024 — a reviewer cannot judge a
    // report without them. The skipped count is called out explicitly when non-zero.
    [Fact]
    public void AssemblyFooter_ShowsCoverageNumbersWithSkippedCountCalledOut()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 120, methodsSkipped: 3));

        var output = writer.ToString();
        Assert.Contains("Methods analyzed:", output);
        Assert.Contains("117/120", output);
        Assert.Contains("(3 not analyzed)", output);
    }

    [Fact]
    public void AssemblyFooter_WhenNothingSkipped_ShowsPlainCoverageNumbers()
    {
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, AssemblyReport(methodsTotal: 42, methodsSkipped: 0));

        var output = writer.ToString();
        Assert.Contains("Methods analyzed:", output);
        Assert.Contains("42/42", output);
        Assert.DoesNotContain("not analyzed)", output);
    }
    #endregion

    #region Methods — package footer
    [Fact]
    public void PackageFooter_WhenMethodsCouldNotBeAnalyzedInOneAssembly_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 20, methodsSkipped: 0),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 10, methodsSkipped: 2));

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Equal(
            FooterHeadline.NotVerified(console, "2 of 30 method(s) could not be analyzed in lib/net10.0/B.dll"),
            FooterHeadline.Of(writer));
    }

    // A package whose only content is a binary nothing could be read out of used to read "Clean" — native payloads
    // are a known malware vector, so "we did not look inside this binary" must reach the footer.
    [Fact]
    public void PackageFooter_WhenOnlyContentCouldNotBeAnalysed_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();
        var report = Package(Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly."));

        PackageReportRenderer.Render(console, report, "Native.Package.1.0.0.nupkg");

        Assert.Equal(
            FooterHeadline.NotVerified(
                console, "1 of 1 file(s) could not be analysed: runtimes/win-x64/native/n.dll"),
            FooterHeadline.Of(writer));
    }

    [Theory]
    [InlineData(VulnerabilityScanStatus.Unavailable, "the known-vulnerability check did not complete")]
    [InlineData(VulnerabilityScanStatus.NotChecked, "the known-vulnerability check did not run")]
    public void PackageFooter_WhenVulnerabilityCheckDidNotProduceData_SaysNotVerifiedNeverClean(
        VulnerabilityScanStatus status, string caveat)
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, PackageWith(vulnStatus: status), "Some.Package.1.0.0.nupkg");

        Assert.Equal(FooterHeadline.NotVerified(console, caveat), FooterHeadline.Of(writer));
    }

    // ADR-0027 decision 4: an unverified YARA scan downgrades the footer exactly like an OSV outage does.
    [Fact]
    public void PackageFooter_WhenYaraScanUnavailable_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(
            console, PackageWith(yaraStatus: YaraScanStatus.Unavailable), "Some.Package.1.0.0.nupkg");

        Assert.Equal(
            FooterHeadline.NotVerified(console, "the YARA malware-signature scan did not complete"),
            FooterHeadline.Of(writer));
    }

    // The explicit --no-yara opt-out (NotRun) must NOT downgrade the footer: the caller chose to skip the scan,
    // which is a different statement from an outage, so a report that is otherwise complete still reads "Clean".
    [Fact]
    public void PackageFooter_WhenYaraScanNotRun_StillSaysClean()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(
            console,
            Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 7, methodsSkipped: 0)) with
            {
                YaraScanStatus = YaraScanStatus.NotRun
            },
            "Some.Package.1.0.0.nupkg");

        Assert.Equal(
            FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail),
            FooterHeadline.Of(writer));
    }

    [Fact]
    public void PackageFooter_WhenAnAssemblysMetadataCouldNotBeRead_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();
        var report = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 3, methodsSkipped: 0, metadata: false));

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Equal(
            FooterHeadline.NotVerified(console, "the assembly metadata could not be read for 1 assembly"),
            FooterHeadline.Of(writer));
    }

    [Fact]
    public void PackageFooter_WhenObfuscationAnalysisDidNotComplete_SaysNotVerifiedNeverClean()
    {
        var (console, writer) = PlainConsole();
        var report = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 3, methodsSkipped: 0, obfuscation: false));

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Equal(
            FooterHeadline.NotVerified(console, "the obfuscation analysis did not complete for 1 assembly"),
            FooterHeadline.Of(writer));
    }

    [Fact]
    public void PackageFooter_WhenCompleteAndFindingFree_SaysClean()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(
            console,
            Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 7, methodsSkipped: 0)),
            "Some.Package.1.0.0.nupkg");

        // The package verb's cleanDetail tail lists all five of its finding sources — a different sentence from the
        // assembly footer's, which is why the expected line is parameterised on the renderer under test.
        Assert.Equal(
            FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail),
            FooterHeadline.Of(writer));
    }

    [Fact]
    public void PackageFooter_ShowsCoverageNumbersAggregatedOverAssemblies()
    {
        var (console, writer) = PlainConsole();
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 20, methodsSkipped: 0),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 10, methodsSkipped: 2));

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        Assert.Contains("Methods analyzed:", output);
        Assert.Contains("28/30", output);
        Assert.Contains("(2 not analyzed)", output);
    }

    // Default (no --rich) output must stay pure 7-bit ASCII (ADR 0014) with the new footer lines present: the
    // headline glyph and the caveat separator both degrade to ASCII.
    [Fact]
    public void CompletenessFooter_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console,
            PackageWith(
                new[] { Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 4, obfuscation: false) },
                vulnStatus: VulnerabilityScanStatus.Unavailable,
                resolution: DependencyResolutionStatus.Partial),
            "Some.Package.1.0.0.nupkg");

        var output = writer.ToString();
        // Four caveats at once, so this headline WRAPS at the console width — the verdict is asserted on the (single)
        // glyph-prefixed line rather than by whole-line equality, which a wrapped line cannot satisfy.
        Assert.True(FooterHeadline.IsNotVerified(FooterHeadline.Of(output)), "the footer's verdict is not 'Not verified'.");
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[yellow]", output);
    }
    #endregion

    #region Methods — default(CompletenessAssessment) (an unreachable path, pinned fail-closed)
    // No code path produces default(CompletenessAssessment) today — both factories always construct one — but a record
    // STRUCT makes it representable, so the footer has to survive it. `default` runs no constructor, so Caveats would
    // be null without the coalescing getter and this call would NRE.
    //
    // What is pinned here is the FAIL-CLOSED BEHAVIOUR, not the grammar: with no caveats to name, the "Not verified —
    // no findings, but ." sentence reads awkwardly. That is accepted on a path nothing reaches. What must never happen
    // is the other outcome — a value nobody deliberately created handing out a "Clean" verdict.
    [Fact]
    public void Headline_WithDefaultAssessment_DoesNotThrowAndNeverSaysClean()
    {
        var (console, writer) = PlainConsole();

        var ex = Record.Exception(() => CompletenessFooter.WriteHeadline(
            console, rich: false, attention: false, default, FooterHeadline.AssemblyCleanDetail));

        Assert.Null(ex);
        // rich:false is passed explicitly here (the footer is driven directly, not through a renderer), so the ASCII
        // form is the expected one regardless of the console's own mode. The empty caveat join is the awkward
        // "no findings, but ." sentence the comment above accepts — pinned verbatim so a future grammar fix is a
        // deliberate change, not a silent one.
        Assert.Equal(FooterHeadline.NotVerified(rich: false), FooterHeadline.Of(writer));
    }

    // The findings-present branch joins the caveats too, so it needs the same null-safety proof.
    [Fact]
    public void Headline_WithDefaultAssessmentAndAttention_DoesNotThrowAndNeverSaysClean()
    {
        var (console, writer) = PlainConsole();

        var ex = Record.Exception(() => CompletenessFooter.WriteHeadline(
            console, rich: false, attention: true, default, FooterHeadline.AssemblyCleanDetail));

        Assert.Null(ex);
        Assert.Equal(FooterHeadline.FindingsPresent(rich: false), FooterHeadline.Of(writer));
    }

    [Fact]
    public void Coverage_WithDefaultAssessment_ReportsZeroOfZeroWithoutThrowing()
    {
        var (console, writer) = PlainConsole();

        var ex = Record.Exception(() => CompletenessFooter.WriteCoverage(console, default));

        Assert.Null(ex);
        Assert.Contains("0/0", writer.ToString());
    }
    #endregion

    #region Methods — markup-injection safety on the new caveat strings
    // A caveat naming an assembly path embeds UNTRUSTED package content. Unescaped, the trailing unterminated tag
    // would make Spectre's markup parser throw (killing the report on hostile input) and "[red]" would be
    // interpreted as a color. Rich mode (color on) proves the escape rather than mere tag-stripping.
    // Driven through CompletenessFooter.WriteHeadline directly so the assertion cannot be satisfied by some OTHER
    // escaped rendering of the same path elsewhere in the report.

    [Fact]
    public void Headline_WithMarkupInSkippedFilePath_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var assessment = CompletenessAssessment.ForPackage(Package(Skipped(Inject, "Failed to load assembly.")));

        var ex = Record.Exception(() =>
            CompletenessFooter.WriteHeadline(console, rich: true, attention: false, assessment, "no findings."));

        AssertRenderedLiterally(ex, writer);
    }

    [Fact]
    public void Headline_WithMarkupInSkippedMethodAssemblyPath_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var assessment = CompletenessAssessment.ForPackage(
            Package(Analyzed(Inject, methodsTotal: 10, methodsSkipped: 4)));

        var ex = Record.Exception(() =>
            CompletenessFooter.WriteHeadline(console, rich: true, attention: false, assessment, "no findings."));

        AssertRenderedLiterally(ex, writer);
    }

    // The same payload, but through the whole package renderer (rich) — the caveat now sits alongside the assembly
    // tree that also prints the hostile path, so this is the end-to-end "hostile package does not kill the report".
    [Fact]
    public void PackageRenderer_WithMarkupInSkippedFilePath_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var report = Package(
            Skipped(Inject, Inject),
            Analyzed(Inject, methodsTotal: 10, methodsSkipped: 4));

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, report, Inject));

        AssertRenderedLiterally(ex, writer);
    }

    // The findings-present branch prints the caveats on a SECOND line, so it needs its own escape proof.
    [Fact]
    public void Headline_WithAttentionAndMarkupInCaveat_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var assessment = CompletenessAssessment.ForPackage(Package(Skipped(Inject, "Failed to load assembly.")));

        var ex = Record.Exception(() =>
            CompletenessFooter.WriteHeadline(console, rich: true, attention: true, assessment, "no findings."));

        AssertRenderedLiterally(ex, writer);
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
        var (console, writer) = PlainConsole();
        console.Profile.Capabilities.Unicode = false;
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

    private static void AssertRenderedLiterally(Exception? renderException, StringWriter writer)
    {
        Assert.Null(renderException);   // unescaped markup would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output);    // the payload text survived rendering
        Assert.Contains("[red]", output);    // and its markup was shown literally, not interpreted as color
    }
    #endregion

    #region Fields
    // An interpreted-color attempt combined with an unterminated tag: unescaped, the trailing "[unterminated" makes
    // Spectre's markup parser throw, so a passing render proves the caveat was escaped.
    private const string Inject = "[red]PWNED[/][unterminated";
    #endregion
}
