namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/capability-diff-versions.md</c> Area E: <see cref="CapabilityDiffReportRenderer"/>. Like
/// <see cref="YaraReportRendererTests"/>/<see cref="HealthReportRendererTests"/>, these assert
/// security/correctness INVARIANTS — markup-injection safety for untrusted snapshot-file content (assembly names,
/// target-framework strings) and ADR 0014's ASCII-only default — plus which sections appear when, not
/// layout/color/wording (validated interactively per CLAUDE.md).
/// </summary>
public sealed class CapabilityDiffReportRendererTests
{
    #region Methods — markup-injection safety (untrusted snapshot-file content)
    [Fact]
    public void Render_RichConsole_WithInjectionPayloadInAssemblyNameAndTfm_RendersLiterallyWithoutThrowing()
    {
        var (console, writer) = RichConsole();
        var outcome = OutcomeWithAddedCapability(assemblyName: Inject, targetFramework: Inject);

        var ex = Record.Exception(() => CapabilityDiffReportRenderer.Render(console, outcome, Inject, Inject));

        Assert.Null(ex);   // unescaped markup / an unterminated tag would have thrown InvalidOperationException
        var output = writer.ToString();
        Assert.Contains("PWNED", output);
        Assert.Contains("[red]", output);   // shown literally, not interpreted as a color tag
    }

    [Fact]
    public void Render_AsciiConsole_WithInjectionPayloadInAssemblyNameAndTfm_RendersLiterallyAndStays7BitAscii()
    {
        var (console, writer) = AsciiConsole();
        var outcome = OutcomeWithAddedCapability(assemblyName: Inject, targetFramework: Inject);

        var ex = Record.Exception(() => CapabilityDiffReportRenderer.Render(console, outcome, Inject, Inject));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("PWNED", output);
        AssertSevenBitAscii(output);
    }

    // Assembly/TFM names also appear in the added/removed/count-change sections, the structural sections, and the
    // "Assessment" footer's caveats — this drives a report through EVERY section with the SAME hostile string so a
    // single un-escaped call site anywhere would surface as either a thrown exception or interpreted markup.
    [Fact]
    public void Render_InjectionPayload_ThroughEverySection_NeverThrowsAndAlwaysEscapes()
    {
        var (console, writer) = RichConsole();
        var diff = new CapabilityDiffReport(
            AssemblyDiffs:
            [
                new AssemblyCapabilityDiff(Inject, Inject, [Capability.FileSystem], [Capability.Network],
                    [new CapabilityCountChange(Capability.Registry, 1, 5)]),
            ],
            AssembliesAdded: [Inject],
            AssembliesRemoved: [Inject],
            TargetFrameworksAdded: [Inject],
            TargetFrameworksDropped: [Inject],
            MatchedPairCount: 1);
        var outcome = new CapabilityDiffOutcome(diff, BaselineComplete: false, BaselineCaveats: [Inject], CandidateComplete: true, CandidateCaveats: [], VacuousDiffOverridden: false);

        var ex = Record.Exception(() => CapabilityDiffReportRenderer.Render(console, outcome, Inject, Inject));

        Assert.Null(ex);
        var output = writer.ToString();
        Assert.Contains("[red]", output);
        Assert.DoesNotContain("System.InvalidOperationException", output);
    }
    #endregion

    #region Methods — ADR 0014 ASCII-by-default: no color, no box-drawing
    [Fact]
    public void Render_AsciiConsole_CleanDiff_Emits7BitAsciiWithNoLeftoverMarkupTags()
    {
        var (console, writer) = AsciiConsole();
        var outcome = CleanOutcome();

        CapabilityDiffReportRenderer.Render(console, outcome, "baseline.json", "candidate.json");

        var output = writer.ToString();
        AssertSevenBitAscii(output);
        Assert.DoesNotContain("[/]", output);
        Assert.DoesNotContain("[grey]", output);
        Assert.DoesNotContain("[bold", output);
    }

    [Fact]
    public void Render_AsciiConsole_FullReport_Emits7BitAsciiWithNoLeftoverMarkupTags()
    {
        var (console, writer) = AsciiConsole();
        var outcome = FullReportOutcome();

        CapabilityDiffReportRenderer.Render(console, outcome, "baseline.json", "candidate.json");

        AssertSevenBitAscii(writer.ToString());
    }

    [Fact]
    public void Render_PlainConsole_EmitsNoEscapeBytes()
    {
        var (console, writer) = PlainConsole();

        CapabilityDiffReportRenderer.Render(console, FullReportOutcome(), "baseline.json", "candidate.json");

        var output = writer.ToString();
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
    }
    #endregion

    #region Methods — section presence
    [Fact]
    public void Render_TargetFrameworkChanges_Present_ShowsSection()
    {
        var (console, writer) = AsciiConsole();
        var diff = new CapabilityDiffReport(
            [], [], [], TargetFrameworksAdded: ["A.dll (net8.0)"], TargetFrameworksDropped: [], MatchedPairCount: 1);
        var outcome = new CapabilityDiffOutcome(diff, true, [], true, [], VacuousDiffOverridden: false);

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        var output = writer.ToString();
        Assert.Contains("Target frameworks added / dropped", output);
        Assert.Contains("A.dll (net8.0)", output);
    }

    [Fact]
    public void Render_TargetFrameworkChanges_Absent_OmitsSection()
    {
        var (console, writer) = AsciiConsole();
        var outcome = CleanOutcome();

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        Assert.DoesNotContain("Target frameworks added / dropped", writer.ToString());
    }

    [Fact]
    public void Render_AssembliesAddedOrRemoved_Present_ShowsSection()
    {
        var (console, writer) = AsciiConsole();
        var diff = new CapabilityDiffReport([], AssembliesAdded: ["New.dll"], AssembliesRemoved: [], [], [], MatchedPairCount: 1);
        var outcome = new CapabilityDiffOutcome(diff, true, [], true, [], VacuousDiffOverridden: false);

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        var output = writer.ToString();
        Assert.Contains("Assemblies added / removed", output);
        Assert.Contains("New.dll", output);
    }

    [Fact]
    public void Render_AssembliesAddedOrRemoved_Absent_OmitsSection()
    {
        var (console, writer) = AsciiConsole();
        var outcome = CleanOutcome();

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        Assert.DoesNotContain("Assemblies added / removed", writer.ToString());
    }

    [Fact]
    public void Render_VacuousDiffOverridden_ShowsNothingMatchedBanner()
    {
        var (console, writer) = AsciiConsole();
        var diff = new CapabilityDiffReport([], [], [], TargetFrameworksAdded: ["A.dll (net8.0)"], TargetFrameworksDropped: ["A.dll (netstandard2.0)"], MatchedPairCount: 0);
        var outcome = new CapabilityDiffOutcome(diff, true, [], true, [], VacuousDiffOverridden: true);

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        Assert.Contains("NOTHING MATCHED", writer.ToString());
    }

    [Fact]
    public void Render_NonVacuousDiff_DoesNotShowNothingMatchedBanner()
    {
        var (console, writer) = AsciiConsole();
        var outcome = CleanOutcome();   // MatchedPairCount 1, VacuousDiffOverridden false

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        Assert.DoesNotContain("NOTHING MATCHED", writer.ToString());
    }

    [Fact]
    public void Render_CountChangesSection_Present_OnlyWhenACountChangeExists()
    {
        var (console, writer) = AsciiConsole();
        var diff = new CapabilityDiffReport(
            [new AssemblyCapabilityDiff("A.dll", "net10.0", [], [], [new CapabilityCountChange(Capability.Network, 3, 40)])],
            [], [], [], [], MatchedPairCount: 1);
        var outcome = new CapabilityDiffOutcome(diff, true, [], true, [], VacuousDiffOverridden: false);

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        var output = writer.ToString();
        Assert.Contains("Count changes", output);
        Assert.Contains("3 -> 40", output);
    }

    [Fact]
    public void Render_CountChangesSection_Absent_WhenNoCountChangeExists()
    {
        var (console, writer) = AsciiConsole();
        var outcome = CleanOutcome();

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        Assert.DoesNotContain("Count changes", writer.ToString());
    }

    // Incomplete side is disclosed even when real changes were found — findings still win the headline, but the
    // caveat is never dropped.
    [Fact]
    public void Render_IncompleteSideWithRealChanges_DisclosesCaveatAndStillShowsAddedCapability()
    {
        var (console, writer) = AsciiConsole();
        var outcome = OutcomeWithAddedCapability("A.dll", "net10.0") with
        {
            CandidateComplete = false,
            CandidateCaveats = ["A.dll: 1 of 5 method(s) could not be analyzed"],
        };

        CapabilityDiffReportRenderer.Render(console, outcome, "b.json", "c.json");

        var output = writer.ToString();
        Assert.Contains("Candidate scan INCOMPLETE", output);
        Assert.Contains("1 of 5 method(s) could not be analyzed", output);
        Assert.Contains("capability(ies) added", output);
    }
    #endregion

    #region Methods — fixtures
    private static CapabilityDiffOutcome CleanOutcome()
    {
        var diff = new CapabilityDiffReport([], [], [], [], [], MatchedPairCount: 1);
        return new CapabilityDiffOutcome(diff, true, [], true, [], VacuousDiffOverridden: false);
    }

    private static CapabilityDiffOutcome OutcomeWithAddedCapability(string assemblyName, string? targetFramework)
    {
        var diff = new CapabilityDiffReport(
            [new AssemblyCapabilityDiff(assemblyName, targetFramework, [Capability.ProcessExecution], [], [])],
            [], [], [], [], MatchedPairCount: 1);
        return new CapabilityDiffOutcome(diff, true, [], true, [], VacuousDiffOverridden: false);
    }

    private static CapabilityDiffOutcome FullReportOutcome()
    {
        var diff = new CapabilityDiffReport(
            AssemblyDiffs:
            [
                new AssemblyCapabilityDiff("A.dll", "net10.0", [Capability.ProcessExecution], [Capability.Registry],
                    [new CapabilityCountChange(Capability.Network, 3, 40)]),
            ],
            AssembliesAdded: ["New.dll"],
            AssembliesRemoved: ["Gone.dll"],
            TargetFrameworksAdded: ["A.dll (net8.0)"],
            TargetFrameworksDropped: ["A.dll (netstandard2.0)"],
            MatchedPairCount: 1);
        return new CapabilityDiffOutcome(diff, false, ["A.dll: the scan was marked incomplete"], true, [], VacuousDiffOverridden: false);
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

    private static void AssertSevenBitAscii(string output)
    {
        Assert.NotEqual(0, output.Length);
        Assert.False(output.Contains((char)27), "output must contain no ANSI escape byte (0x1b)");
        var offender = output.FirstOrDefault(c => c > (char)0x7f);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found char U+{(int)offender:x4}.");
    }
    #endregion

    #region Fields
    private const string Inject = "[red]PWNED[/][unterminated";
    #endregion
}
