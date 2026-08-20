namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// <c>docs/agent/tasks/indicator-cli-integration.md</c> plus the 2026-08-03 ARCHITECT DECISION that amended it:
/// <see cref="IndicatorReport"/> findings flow into both verb renderers, split into a DISCRIMINATING tier
/// (<see cref="IndicatorCategory.CallbackDomain"/>, <see cref="IndicatorCategory.ExfilSink"/>,
/// <see cref="IndicatorCategory.DynamicDns"/>, <see cref="IndicatorCategory.RawCodeHost"/>,
/// <see cref="IndicatorCategory.CredentialPath"/>, <see cref="IndicatorCategory.AutorunRegistry"/>,
/// <see cref="IndicatorCategory.PublicIpLiteral"/> — full detail rows AND they set the headline "attention" boolean)
/// and a NOISY tier (<see cref="IndicatorCategory.ReflectionTypeName"/>, <see cref="IndicatorCategory.GenericUrl"/>,
/// <see cref="IndicatorCategory.PrivateIpLiteral"/> — count-only, never attention). <b>Neither tier ever touches an
/// exit code</b> — that invariant is pinned separately, in <c>IndicatorExitCodeInvarianceTests</c>.
/// <para>
/// All reports here are CONSTRUCTED directly (mirrors <c>CompletenessExitCodeTests</c>' own rationale): the point
/// is to pin the renderer's pure predicate over arbitrary report shapes, not to depend on what one fixture
/// assembly's real <c>IndicatorAnalysis</c> run happens to produce today.
/// </para>
/// </summary>
public sealed class IndicatorHeadlineAndRenderingTests
{
    #region Methods — B: headline policy (assembly verb)
    // B1 — a discriminating-only finding must flip the headline to "Findings present", not "Clean": the corrected
    // policy this task pins (a CallbackDomain-only report must not print "Clean" with the domain listed above it).
    [Fact]
    public void Analyze_DiscriminatingIndicatorOnly_HeadlineReadsFindingsPresent()
    {
        var report = CleanAssembly() with { Indicators = IndicatorsOf(Callback("x.pipedream.net")) };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
    }

    // B2 — a noisy-only finding must NOT move the headline off "Clean": ReflectionTypeName/GenericUrl/
    // PrivateIpLiteral are 92%/28%/4% on benign input (measurements/indicator-prevalence-2026-08-03.md), so
    // gating the headline on them would make it fire on nearly every package.
    [Fact]
    public void Analyze_NoisyIndicatorOnly_HeadlineStaysClean()
    {
        var report = CleanAssembly() with { Indicators = IndicatorsOf(Noisy(IndicatorCategory.GenericUrl, "example.com")) };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.AssemblyCleanDetail), FooterHeadline.Of(writer));
    }

    // B3 — mixed discriminating + noisy: still "Findings present", and — the double-counting hazard the spec calls
    // out — exactly ONE verdict headline (FooterHeadline.Of itself asserts Assert.Single).
    [Fact]
    public void Analyze_MixedDiscriminatingAndNoisyIndicators_HeadlineReadsFindingsPresentOnce()
    {
        var report = CleanAssembly() with
        {
            Indicators = IndicatorsOf(
                Callback("x.pipedream.net"),
                Noisy(IndicatorCategory.GenericUrl, "example.com"),
                Noisy(IndicatorCategory.ReflectionTypeName, "System.Net.WebClient"))
        };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
    }

    // B4 — no indicators at all (Indicators: null, the pre-existing best-effort-failure posture): the headline is
    // unchanged from before this task — still "Clean" on an otherwise-clean report.
    [Fact]
    public void Analyze_NoIndicators_HeadlineUnchanged()
    {
        var report = CleanAssembly();
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        Assert.Null(report.Indicators);
        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.AssemblyCleanDetail), FooterHeadline.Of(writer));
    }
    #endregion

    #region Methods — B: headline policy (scan-package verb)
    [Fact]
    public void ScanPackage_DiscriminatingIndicatorOnly_HeadlineReadsFindingsPresent()
    {
        var report = CleanPackage(Callback("x.pipedream.net"));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
    }

    [Fact]
    public void ScanPackage_NoisyIndicatorOnly_HeadlineStaysClean()
    {
        var report = CleanPackage(Noisy(IndicatorCategory.PrivateIpLiteral, "10.0.0.5"));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail), FooterHeadline.Of(writer));
    }

    [Fact]
    public void ScanPackage_MixedDiscriminatingAndNoisyIndicators_HeadlineReadsFindingsPresentOnce()
    {
        var report = CleanPackage(
            Callback("x.pipedream.net"),
            Noisy(IndicatorCategory.GenericUrl, "example.com"),
            Noisy(IndicatorCategory.PrivateIpLiteral, "10.0.0.5"));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.Equal(FooterHeadline.FindingsPresent(console), FooterHeadline.Of(writer));
    }

    [Fact]
    public void ScanPackage_NoIndicators_HeadlineUnchanged()
    {
        var report = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        Assert.All(report.Assemblies, a => Assert.Null(a.Indicators));
        Assert.Equal(FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail), FooterHeadline.Of(writer));
    }
    #endregion

    #region Methods — the two-tier split itself
    // Pins the exact seven/three split named in the ARCHITECT DECISION, over EVERY category — so a future append
    // to IndicatorCategory fails loudly here instead of silently landing in the wrong tier.
    [Theory]
    [InlineData(IndicatorCategory.CallbackDomain, true)]
    [InlineData(IndicatorCategory.ExfilSink, true)]
    [InlineData(IndicatorCategory.DynamicDns, true)]
    [InlineData(IndicatorCategory.RawCodeHost, true)]
    [InlineData(IndicatorCategory.PublicIpLiteral, true)]
    [InlineData(IndicatorCategory.PrivateIpLiteral, false)]
    [InlineData(IndicatorCategory.GenericUrl, false)]
    [InlineData(IndicatorCategory.AutorunRegistry, true)]
    [InlineData(IndicatorCategory.CredentialPath, true)]
    [InlineData(IndicatorCategory.ReflectionTypeName, false)]
    public void IsDiscriminatingIndicatorCategory_MatchesTheTwoTierSplit(IndicatorCategory category, bool discriminating) =>
        Assert.Equal(discriminating, ReportThemeIsDiscriminating(category));

    // Every IndicatorCategory value is classified by the theory above — this fails if a category is ever added
    // without also being added to the theory (an un-InlineData'd category would just never run, not fail; this
    // proves the two lists are the same SET, not merely that the pinned seven test true).
    [Fact]
    public void IsDiscriminatingIndicatorCategory_CoversEveryCategoryExactlyOnce()
    {
        var all = Enum.GetValues<IndicatorCategory>();
        var discriminating = all.Where(ReportThemeIsDiscriminating).ToArray();
        var noisy = all.Except(discriminating).ToArray();

        Assert.Equal(7, discriminating.Length);
        Assert.Equal(3, noisy.Length);
        Assert.Equal(10, all.Length);   // guards against a silent append nobody classified either way
    }
    #endregion

    #region Methods — C: rendering selectivity
    // The count summary lists ALL ten categories, including the ones with zero findings — "a category present
    // with count 0 is information" (task spec).
    [Fact]
    public void IndicatorCountSummary_ListsAllTenCategoriesIncludingZero()
    {
        var (console, writer) = PlainConsole();

        console.Write(ReportTheme.IndicatorCountSummary([Callback("x.pipedream.net")]));
        var lines = writer.ToString().Split('\n').Select(l => l.TrimEnd('\r')).ToArray();

        // Every category gets its own row, and the row for a category with no findings ends in "0" while the
        // one populated category (CallbackDomain) ends in "1" — asserted PER CATEGORY so a category silently
        // sharing a zero row with another, or being omitted altogether, fails here.
        foreach (var category in Enum.GetValues<IndicatorCategory>())
        {
            var line = Assert.Single(lines, l => l.Contains(category.ToString()));
            var expected = category == IndicatorCategory.CallbackDomain ? "1" : "0";
            Assert.True(
                line.TrimEnd().EndsWith(expected, StringComparison.Ordinal),
                $"expected the {category} row to end with '{expected}': '{line}'");
        }
    }

    // I — the count summary reports AGGREGATED FINDING ROWS, not raw Occurrences: one finding carrying
    // Occurrences=5 must render "1", never "5" (matches how capability/obfuscation counts are reported elsewhere).
    [Fact]
    public void IndicatorCountSummary_CountsAggregatedRowsNotRawOccurrences()
    {
        var (console, writer) = PlainConsole();
        var fiveOccurrences = new IndicatorFinding(
            IndicatorCategory.CallbackDomain, "x.pipedream.net", "beacon to x.pipedream.net", "T", "M", Occurrences: 5);

        console.Write(ReportTheme.IndicatorCountSummary([fiveOccurrences]));
        var output = writer.ToString();

        Assert.DoesNotContain("5", output);
        Assert.Contains("1", output);
    }

    // Multiple aggregated findings in the SAME category count as multiple rows (2), not their summed Occurrences
    // (5 + 3 = 8) — the same "aggregated rows, not raw occurrences" semantics from the other direction.
    [Fact]
    public void IndicatorCountSummary_TwoAggregatedFindingsInOneCategory_CountsAsTwoNotTheirOccurrenceSum()
    {
        var (console, writer) = PlainConsole();
        var findings = new[]
        {
            new IndicatorFinding(IndicatorCategory.GenericUrl, "a.example", "see a.example", "T", "M1", 5),
            new IndicatorFinding(IndicatorCategory.GenericUrl, "b.example", "see b.example", "T", "M2", 3),
        };

        console.Write(ReportTheme.IndicatorCountSummary(findings));
        var output = writer.ToString();

        Assert.Contains("2", output);
        Assert.DoesNotContain("8", output);
    }

    // Detail rows appear ONLY for the seven discriminating categories: a noisy finding's distinctive Value/Excerpt
    // must not surface anywhere in the terminal report — only its category's row in the count summary (which
    // names every category regardless). The discriminating finding's Value DOES appear (it gets a detail row).
    [Fact]
    public void Analyze_NoisyFindingDetail_NeverAppearsInTerminal_OnlyDiscriminatingDoes()
    {
        var report = CleanAssembly() with
        {
            Indicators = IndicatorsOf(
                Callback("x.pipedream.net"),
                new IndicatorFinding(
                    IndicatorCategory.GenericUrl, "noisy-only-value.example", "totally-noisy-excerpt-xyz", "T", "NoisyCaller", 1))
        };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);
        var output = writer.ToString();

        Assert.Contains("x.pipedream.net", output);              // discriminating: detail row
        Assert.DoesNotContain("noisy-only-value.example", output);   // noisy: no detail row
        Assert.DoesNotContain("totally-noisy-excerpt-xyz", output);
        Assert.DoesNotContain("NoisyCaller", output);
        Assert.Contains("GenericUrl", output);                    // still named in the count summary
    }

    // The scan-package projection of the same rule, tagged with the assembly path in the detail row.
    [Fact]
    public void ScanPackage_NoisyFindingDetail_NeverAppearsInTerminal_OnlyDiscriminatingDoes()
    {
        var report = CleanPackage(
            Callback("x.pipedream.net"),
            new IndicatorFinding(
                IndicatorCategory.PrivateIpLiteral, "10.0.0.99", "totally-noisy-excerpt-xyz", "T", "NoisyCaller", 1));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");
        var output = writer.ToString();

        Assert.Contains("x.pipedream.net", output);
        Assert.DoesNotContain("10.0.0.99", output);
        Assert.DoesNotContain("totally-noisy-excerpt-xyz", output);
        Assert.DoesNotContain("NoisyCaller", output);
        Assert.Contains("PrivateIpLiteral", output);
    }
    #endregion

    #region Methods — E: escaping (attacker-authored indicator values)
    // Value/Excerpt/CallerType are untrusted package content: a hostile finding carrying Spectre markup metacharacters
    // must render LITERALLY — unescaped, the unterminated tag would make Spectre throw, and "[red]" would be
    // interpreted as a color rather than shown. Uses a DISCRIMINATING category so the payload actually reaches a
    // detail row (Value/CallerType/Excerpt are only rendered there).
    [Fact]
    public void Analyze_IndicatorValueWithMarkupMetacharacters_RendersLiterallyWithoutThrowing()
    {
        var report = CleanAssembly() with
        {
            Indicators = IndicatorsOf(new IndicatorFinding(IndicatorCategory.CallbackDomain, Inject, Inject, Inject, Inject, 1))
        };
        var (console, writer) = PlainConsole();

        var ex = Record.Exception(() => AssemblyReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }

    [Fact]
    public void ScanPackage_IndicatorValueWithMarkupMetacharacters_RendersLiterallyWithoutThrowing()
    {
        var report = CleanPackage(new IndicatorFinding(IndicatorCategory.ExfilSink, Inject, Inject, Inject, Inject, 1));
        var (console, writer) = PlainConsole();

        var ex = Record.Exception(() => PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg"));

        AssertRenderedLiterally(ex, writer);
    }

    // The --rich path runs a different console profile (ANSI + a color system + Unicode); Esc must still neutralize
    // the metacharacters there too.
    [Fact]
    public void Analyze_IndicatorValueWithMarkupMetacharacters_RichConsole_RendersLiterallyWithoutThrowing()
    {
        var report = CleanAssembly() with
        {
            Indicators = IndicatorsOf(new IndicatorFinding(IndicatorCategory.CallbackDomain, Inject, Inject, Inject, Inject, 1))
        };
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() => AssemblyReportRenderer.Render(console, report));

        AssertRenderedLiterally(ex, writer);
    }
    #endregion

    #region Methods — F: the Truncated caveat
    // A Truncated indicator report must render a visible caveat — the findings are a FLOOR, not a total, and
    // "could not analyse everything" must never read as a clean result.
    [Fact]
    public void Analyze_TruncatedIndicatorReport_RendersVisibleCaveat()
    {
        var report = CleanAssembly() with
        {
            Indicators = new IndicatorReport("Sample.dll", "lib/net10.0/Sample.dll", Epoch, [Callback("x.pipedream.net")], Truncated: true)
        };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);
        var output = writer.ToString();

        Assert.Contains("TRUNCATED", output);
        Assert.Contains("FLOOR", output);
    }

    // Untruncated stays silent about it — the caveat must not be a permanent fixture of the section.
    [Fact]
    public void Analyze_UntruncatedIndicatorReport_RendersNoTruncationCaveat()
    {
        var report = CleanAssembly() with { Indicators = IndicatorsOf(Callback("x.pipedream.net")) };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        Assert.DoesNotContain("TRUNCATED", writer.ToString());
    }

    // scan-package names WHICH assembly(ies) hit the cap.
    [Fact]
    public void ScanPackage_TruncatedIndicatorReport_RendersVisibleCaveatNamingTheAssembly()
    {
        const string relativePath = "lib/net10.0/A.dll";
        var analyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0) with
        {
            Indicators = new IndicatorReport(relativePath, relativePath, Epoch, [Callback("x.pipedream.net")], Truncated: true)
        };
        var report = Package(analyzed);
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");
        var output = writer.ToString();

        Assert.Contains("TRUNCATED", output);
        Assert.Contains("FLOOR", output);
        Assert.Contains(relativePath, output);
    }
    #endregion

    #region Methods — G: the footer "Indicators:" line's discriminating-count breakdown
    // The footer line now carries a discriminating subset count alongside the total finding count. When every
    // finding is discriminating (M == N) the "(see breakdown above)" parenthetical must NOT appear — it exists to
    // explain a NOISY remainder, and printing it when there is none would be misleading filler.
    [Fact]
    public void Analyze_AllIndicatorsDiscriminating_FooterLineOmitsBreakdownParenthetical()
    {
        var report = CleanAssembly() with
        {
            Indicators = IndicatorsOf(Callback("x.pipedream.net"), Discriminating(IndicatorCategory.ExfilSink, "10.0.0.1"))
        };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        var line = IndicatorFooterLineOf(writer.ToString());
        Assert.Contains("Indicators: 2 finding(s), 2 discriminating", line);
        Assert.DoesNotContain("(see breakdown above)", line);
    }

    // When the discriminating subset is a strict SUBSET of the total (M < N, a mixed report), the parenthetical
    // must appear — that is the whole point of the wording change: a large noisy remainder next to "M discriminating"
    // must not be misread as "M is the whole story".
    [Fact]
    public void Analyze_MixedIndicatorTiers_FooterLineIncludesBreakdownParenthetical()
    {
        var report = CleanAssembly() with
        {
            Indicators = IndicatorsOf(Callback("x.pipedream.net"), Noisy(IndicatorCategory.GenericUrl, "example.com"))
        };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        var line = IndicatorFooterLineOf(writer.ToString());
        Assert.Contains("Indicators: 2 finding(s), 1 discriminating (see breakdown above)", line);
    }

    // N == 0: the shipped behaviour is a completely different branch ("Indicators: none") — no "0 finding(s), 0
    // discriminating" text and, consequently, no parenthetical to omit. Pinned here rather than assumed.
    [Fact]
    public void Analyze_NoIndicatorFindings_FooterLineReadsNone()
    {
        var report = CleanAssembly() with { Indicators = IndicatorsOf() };
        var (console, writer) = PlainConsole();

        AssemblyReportRenderer.Render(console, report);

        var line = IndicatorFooterLineOf(writer.ToString());
        Assert.Equal("Indicators: none", line);
    }

    [Fact]
    public void ScanPackage_AllIndicatorsDiscriminating_FooterLineOmitsBreakdownParenthetical()
    {
        var report = CleanPackage(Callback("x.pipedream.net"), Discriminating(IndicatorCategory.ExfilSink, "10.0.0.1"));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        var line = IndicatorFooterLineOf(writer.ToString());
        Assert.Contains("Indicators: 2 finding(s), 2 discriminating", line);
        Assert.DoesNotContain("(see breakdown above)", line);
    }

    [Fact]
    public void ScanPackage_MixedIndicatorTiers_FooterLineIncludesBreakdownParenthetical()
    {
        var report = CleanPackage(Callback("x.pipedream.net"), Noisy(IndicatorCategory.PrivateIpLiteral, "10.0.0.5"));
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        var line = IndicatorFooterLineOf(writer.ToString());
        Assert.Contains("Indicators: 2 finding(s), 1 discriminating (see breakdown above)", line);
    }

    [Fact]
    public void ScanPackage_NoIndicatorFindings_FooterLineReadsNone()
    {
        var report = CleanPackage();
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        var line = IndicatorFooterLineOf(writer.ToString());
        Assert.Equal("Indicators: none", line);
    }
    #endregion

    #region Methods — helpers
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
        Assert.Null(renderException);
        var output = writer.ToString();
        Assert.Contains("PWNED", output);
        Assert.Contains("[red]", output);
    }

    // A findings-free, fully-complete assembly report — the Clean baseline every headline test starts from and
    // then attaches Indicators to (mirrors ReportRendererTests' "ranAndFoundNothing" pattern).
    private static AssemblyAnalysisReport CleanAssembly() => AssemblyReport(methodsTotal: 5, methodsSkipped: 0);

    // A findings-free, fully-complete package report carrying one packaged assembly whose Indicators are the given
    // findings — the Clean baseline every scan-package headline test starts from.
    private static PackageCapabilityReport CleanPackage(params IndicatorFinding[] findings)
    {
        const string relativePath = "lib/net10.0/A.dll";
        var analyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0) with
        {
            Indicators = new IndicatorReport(relativePath, relativePath, Epoch, findings, Truncated: false)
        };
        return Package(analyzed);
    }

    private static IndicatorReport IndicatorsOf(params IndicatorFinding[] findings) =>
        new("Sample.dll", "lib/net10.0/Sample.dll", Epoch, findings, Truncated: false);

    private static IndicatorFinding Callback(string host) =>
        new(IndicatorCategory.CallbackDomain, host, $"beacon to {host}", "Evil.Loader", "Beacon", 1);

    private static IndicatorFinding Noisy(IndicatorCategory category, string value) =>
        new(category, value, $"see {value}", "T", "M", 1);

    // A second discriminating finding distinct from Callback(), for tests that need two DIFFERENT discriminating
    // categories rather than two of the same.
    private static IndicatorFinding Discriminating(IndicatorCategory category, string value) =>
        new(category, value, $"see {value}", "T", "M", 1);

    // The one line in a rendered report that carries the "Indicators:" footer label. Fails if there is not exactly
    // one — mirrors FooterHeadline.Of's rationale (a duplicate would itself be a defect).
    private static string IndicatorFooterLineOf(string output) =>
        Assert.Single(output.Split('\n').Select(l => l.TrimEnd('\r', ' ')), l => l.Contains("Indicators:"));

    // ReportTheme.IsDiscriminatingIndicatorCategory is internal; reached via InternalsVisibleTo
    // (Program.cs: [assembly: InternalsVisibleTo("Silvergun.CLI.Tests")]), same seam ReportRendererTests already uses.
    private static bool ReportThemeIsDiscriminating(IndicatorCategory category) =>
        ReportTheme.IsDiscriminatingIndicatorCategory(category);
    #endregion

    #region Fields
    // Same injection payload ReportRendererTests uses: an interpreted-color attempt plus an unterminated tag, so a
    // passing render proves the data was escaped rather than merely benign-looking.
    private const string Inject = "[red]PWNED[/][unterminated";
    #endregion
}
