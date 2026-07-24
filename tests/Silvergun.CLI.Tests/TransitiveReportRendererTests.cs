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
/// Behavioral tests for the "Transitive dependencies (resolver-lite)" section of <see cref="PackageReportRenderer"/>
/// (ADR 0018 Phase 2). Like <see cref="VulnerabilitiesReportRendererTests"/> and <see cref="YaraReportRendererTests"/>,
/// these assert security/correctness INVARIANTS — the section is omitted at depth 0 (NotRun); a Partial walk surfaces an
/// incomplete-coverage note and downgrades the footer away from a false "Clean"; default output is pure 7-bit ASCII; and
/// every resolved id/version (untrusted package content) is routed through <see cref="ReportTheme.Esc"/> — not
/// layout/color/wording, which are validated interactively per CLAUDE.md.
/// </summary>
public sealed class TransitiveReportRendererTests
{
    #region Methods
    // Depth 0 / NotRun: the section is omitted entirely (no header, no footer transitive line) — a scan that never asked
    // for resolution must not grow a resolver-lite section.
    [Fact]
    public void TransitiveSection_NotRun_OmitsSection()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console, ReportWithTransitive(DependencyResolutionStatus.NotRun), "Benign.nupkg");

        var output = writer.ToString();
        Assert.DoesNotContain("Transitive dependencies (resolver-lite)", output);   // section header absent
        Assert.DoesNotContain("Transitive dependencies:", output);                  // footer line absent too
    }

    // A Partial walk must read as incomplete coverage, NEVER a clean all-clear: the section shows a "not fully resolved"
    // / "coverage incomplete" note, and — since there are no findings but the walk was partial — the footer says
    // "Not verified", not "Clean" (mirrors the OSV-outage downgrade). Default output stays 7-bit ASCII.
    [Fact]
    public void TransitiveSection_Partial_ShowsIncompleteCoverageNote_AndFooterNotClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console,
            ReportWithTransitive(
                DependencyResolutionStatus.Partial,
                new ResolvedDependency("Dep.A", "1.0.0", Depth: 1, IsDirect: true)),
            "Benign.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Transitive dependencies (resolver-lite)", output);   // the section renders
        Assert.Contains("NOT fully resolved", output);                        // ... with the incomplete-coverage note
        Assert.Contains("coverage incomplete", output);
        Assert.Contains("Not verified", output);                             // footer downgraded from clean ...
        Assert.DoesNotContain("Clean", output);                             // ... never a false all-clear
    }

    // A completed (Complete) walk with resolved nodes renders in the default mode as pure 7-bit ASCII with no ANSI and no
    // leftover markup, and the section header + resolved dep id + the "approximate - not a restore" caveat survive.
    //
    // NOTE (do NOT weaken this test): this guards the ADR-0014 ASCII-only-default invariant for the transitive section.
    // The Complete-status headline in PackageReportRenderer.TransitiveWidget renders the "approximate - not a restore."
    // caveat, and its dash is correctly routed through ReportTheme.Dash(rich) (which yields ASCII '-' in default mode, as
    // the first separator on that same line also does) rather than a hardcoded literal em-dash (U+2014). The existing
    // full-output ASCII smoke test cannot cover this because it scans at depth 0 (section omitted), so this test is the
    // one that exercises the section at depth and asserts the invariant end-to-end. Keep it asserting pure 7-bit ASCII.
    [Fact]
    public void TransitiveSection_AsciiOnlyByDefault()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(
            console,
            ReportWithTransitive(
                DependencyResolutionStatus.Complete,
                new ResolvedDependency("Newtonsoft.Json", "13.0.3", Depth: 1, IsDirect: true),
                new ResolvedDependency("System.Buffers", "4.5.1", Depth: 2, IsDirect: false)),
            "Benign.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Transitive dependencies (resolver-lite)", output);
        Assert.Contains("Newtonsoft.Json", output);        // a resolved dep id renders
        Assert.Contains("not a restore", output);          // the approximate-not-a-restore caveat renders
    }

    // Every resolved id/version is untrusted package content, so it must pass through Esc. A markup-injection payload in
    // BOTH the resolved id and version must render LITERALLY without throwing — an unescaped unterminated tag would make
    // Spectre's parser throw. Rich mode (color on) proves the escape, not just tag-stripping.
    [Fact]
    public void TransitiveSection_EscapesMarkupInResolvedIdAndVersion()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(
                console,
                ReportWithTransitive(
                    DependencyResolutionStatus.Complete,
                    new ResolvedDependency(Inject, Inject, Depth: 1, IsDirect: true)),
                "Benign.nupkg"));

        Assert.Null(ex);                              // unescaped markup would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output);             // the payload text survived rendering
        Assert.Contains("[red]", output);             // and its markup was shown literally, not interpreted as color
    }
    #endregion

    #region Methods — fixtures
    // A minimal, otherwise-clean scan-package report carrying the given resolver-lite status + resolved set. The OSV
    // check is treated as Completed-and-clean so the footer's "Clean" claim is gated ONLY by the transitive status — the
    // subject under test here (a Partial vuln check would independently downgrade the footer and confound the assertion).
    private static PackageCapabilityReport ReportWithTransitive(
        DependencyResolutionStatus status, params ResolvedDependency[] resolved)
    {
        var pkg = new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>());
        return new PackageCapabilityReport(
            pkg,
            Epoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            Vulnerabilities: Array.Empty<VulnerabilityFinding>(),
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            ResolvedDependencies: resolved,
            DependencyResolution: status);
    }
    #endregion

    #region Methods — console helpers (mirror VulnerabilitiesReportRendererTests)
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
    #endregion

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";

    private static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;
    #endregion
}
