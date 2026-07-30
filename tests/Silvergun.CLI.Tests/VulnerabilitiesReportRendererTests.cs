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
/// Behavioral tests for the "Known vulnerabilities (OSV)" section of <see cref="PackageReportRenderer"/> (ADR 0017
/// Phase 2). Like <see cref="YaraReportRendererTests"/>, these assert security/correctness INVARIANTS — ASCII-only
/// default output and markup-injection safety — not layout/color/wording, which are validated interactively per
/// CLAUDE.md. Every OSV field (id, aliases, summary, severity, attributed package id/version) is untrusted OSV/
/// package content, so the renderer must route it through <see cref="ReportTheme.Esc"/>; the injection payload proves
/// it does, across both the ascii and rich consoles. The <c>[dependency]</c> marker and the clean <c>(none)</c> path
/// are the section's two other contract points.
/// </summary>
public sealed class VulnerabilitiesReportRendererTests
{
    #region Methods
    // A report WITH vulnerabilities, default (no --rich) mode, must be pure 7-bit ASCII: no 0x1b, no byte > 0x7F, and
    // no leftover markup tags — and the section header + vuln id must survive as substrings.
    [Fact]
    public void PackageRenderer_WithVulnerabilities_AsciiConsole_EmitsSevenBitAsciiOnly()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWithVulns(CleanFinding()), "Vuln.Package.2.0.0.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Known vulnerabilities (OSV)", output);   // the section header renders
        Assert.Contains("GHSA-good", output);                     // the (short, wrap-safe) vuln id survives
    }

    // The same report through the --output/NO_COLOR plain path must carry no escape bytes and no leftover markup tags.
    [Fact]
    public void PackageRenderer_WithVulnerabilities_PlainConsole_EmitsNoEscapeBytesOrLeftoverMarkup()
    {
        var (console, writer) = PlainConsole();

        PackageReportRenderer.Render(console, ReportWithVulns(CleanFinding()), "Vuln.Package.2.0.0.nupkg");

        AssertPlainText(writer);
    }

    // Rich mode fed a markup-injection payload in EVERY untrusted OSV field (id, an alias, summary, severity, and the
    // attributed package id) must render the payload LITERALLY without throwing — the unterminated tag would make
    // Spectre's parser throw were any field not passed through Esc. Only the vuln finding carries the payload here, so
    // a pass isolates the vulnerabilities widget's escaping.
    [Fact]
    public void PackageRenderer_WithVulnInjectionPayload_RichConsole_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var injected = new VulnerabilityFinding(
            Inject,                       // id
            new[] { Inject },             // an alias
            Inject,                       // summary
            Inject,                       // severity
            Inject,                       // attributed package id
            "1.0.0",
            false,
            new[] { Inject });            // references (not rendered, but hostile all the same)

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWithVulns(injected), "clean.nupkg"));

        AssertRenderedLiterally(ex, writer);
    }

    // The injection payload must also render literally in the ascii/plain path (Esc runs regardless of color), and the
    // ascii output must carry no escape byte and stay 7-bit even with the hostile field present. (The generic
    // "no leftover markup tags" check does NOT apply here: the payload's own literal text legitimately contains "[/]".)
    [Fact]
    public void PackageRenderer_WithVulnInjectionPayload_AsciiConsole_RendersLiterallyAndStaysAscii()
    {
        var (console, writer) = AsciiConsole();
        var injected = new VulnerabilityFinding(
            Inject, new[] { Inject }, Inject, Inject, Inject, "1.0.0", false, new[] { Inject });

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWithVulns(injected), "clean.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output);   // the payload text survived, shown literally
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
    }

    // A vulnerability attributed to a declared dependency (checked at its range floor) must carry the "[dependency]"
    // marker in the rendered Package column so a reader can distinguish it from a direct hit on the scanned package.
    [Fact]
    public void PackageRenderer_DependencyVuln_ShowsDependencyMarker()
    {
        var (console, writer) = AsciiConsole();
        var depFinding = new VulnerabilityFinding(
            "GHSA-dep0", Array.Empty<string>(), "A dependency vuln.", null,
            "Some.Dependency", "1.0.0", IsDependency: true, Array.Empty<string>());

        PackageReportRenderer.Render(console, ReportWithVulns(depFinding), "Root.nupkg");

        var output = writer.ToString();
        Assert.Contains("Some.Dependency", output);
        Assert.Contains("[dependency]", output);   // the dependency marker renders literally (it is not a markup tag)
    }

    // A clean report (empty Vulnerabilities) with a COMPLETED check must render the "(none)" clean path without throwing
    // and signal the clean footer — the same shape as the other "no findings" sections.
    [Fact]
    public void PackageRenderer_CleanVulnerabilities_RendersNoneWithoutThrowing()
    {
        var (console, writer) = AsciiConsole();

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWithVulns(), "Benign.nupkg"));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("Known vulnerabilities (OSV)", output);   // the section is always present
        Assert.Contains("(none)", output);                        // clean OSV renders the "(none)" placeholder
        // The footer's verdict, as the whole headline LINE (see FooterHeadline): Contains("Clean", output) could be
        // satisfied by the token appearing in any package/assembly path the report echoes.
        Assert.Equal(
            FooterHeadline.Clean(console, FooterHeadline.PackageCleanDetail),
            FooterHeadline.Of(writer));
    }

    // An UNAVAILABLE check (OSV outage) must render distinctly from clean: a prominent "not verified"/"unavailable"
    // warning, NEVER the clean "(none)" placeholder, and the footer headline must NOT say "Clean" (it would be a false
    // all-clear on a security-gating signal). Default (ascii) output must still be pure 7-bit ASCII with no leftover
    // markup — the same invariant every other section upholds.
    [Fact]
    public void PackageRenderer_UnavailableVulnerabilities_AsciiConsole_ShowsNotVerifiedNotClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(VulnerabilityScanStatus.Unavailable), "Benign.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Known vulnerabilities (OSV)", output);
        Assert.Contains("unavailable", output);          // the outage is surfaced prominently
        Assert.Contains("not verified", output);         // ... and clearly labelled NOT verified (footer, lower-case)
        // ... and the verdict headline itself names the outage instead of claiming a clean bill of health.
        Assert.Equal(
            FooterHeadline.NotVerified(console, "the known-vulnerability check did not complete"),
            FooterHeadline.Of(writer));
    }

    // The same Unavailable report through the --rich path renders without throwing and carries the warning text.
    [Fact]
    public void PackageRenderer_UnavailableVulnerabilities_RichConsole_RendersWarningWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWith(VulnerabilityScanStatus.Unavailable), "Benign.nupkg"));

        Assert.Null(ex);
        Assert.Contains("unavailable", writer.ToString());
    }

    // A NOT-CHECKED report (e.g. --no-vulns) renders a dim "(not checked)" line, never the clean "(none)", and the
    // footer does NOT claim "Clean" (the package was not verified against known CVEs). Default output stays 7-bit ASCII.
    [Fact]
    public void PackageRenderer_NotCheckedVulnerabilities_AsciiConsole_ShowsNotCheckedNotClean()
    {
        var (console, writer) = AsciiConsole();

        PackageReportRenderer.Render(console, ReportWith(VulnerabilityScanStatus.NotChecked), "Benign.nupkg");

        AssertSevenBitAscii(writer);
        var output = writer.ToString();
        Assert.Contains("Known vulnerabilities (OSV)", output);
        Assert.Contains("(not checked)", output);        // the skip is surfaced as its own state
        Assert.Equal(                                    // and the verdict headline names the skip, never "Clean"
            FooterHeadline.NotVerified(console, "the known-vulnerability check did not run"),
            FooterHeadline.Of(writer));
    }

    // The same NotChecked report through the --rich path renders without throwing and carries the "(not checked)" line.
    [Fact]
    public void PackageRenderer_NotCheckedVulnerabilities_RichConsole_RendersNotCheckedWithoutThrowing()
    {
        var (console, writer) = RichConsole();

        var ex = Record.Exception(() =>
            PackageReportRenderer.Render(console, ReportWith(VulnerabilityScanStatus.NotChecked), "Benign.nupkg"));

        Assert.Null(ex);
        Assert.Contains("(not checked)", writer.ToString());
    }
    #endregion

    #region Methods — fixtures
    private static VulnerabilityFinding CleanFinding() =>
        new(
            "GHSA-good",
            new[] { "CVE-2024-21907" },
            "A deserialization vulnerability.",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Vuln.Package",
            "2.0.0",
            IsDependency: false,
            Array.Empty<string>());

    // A minimal, otherwise-clean scan-package report carrying exactly the given vulnerability findings (none => clean).
    // The OSV check is treated as Completed by default — the state under which findings render and an empty list is the
    // clean "(none)". Tests that exercise an outage / skip pass Unavailable / NotChecked explicitly.
    private static PackageCapabilityReport ReportWithVulns(params VulnerabilityFinding[] findings) =>
        ReportWith(VulnerabilityScanStatus.Completed, findings);

    private static PackageCapabilityReport ReportWith(VulnerabilityScanStatus status, params VulnerabilityFinding[] findings)
    {
        var pkg = new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>());
        return new PackageCapabilityReport(
            pkg,
            Epoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            Vulnerabilities: findings,
            VulnerabilitiesStatus: status);
    }
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
