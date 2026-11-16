namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// The value signals in the <c>scan-package --reachability --ssa</c> section (<c>docs/agent/tasks/recall-levers-1.md</c> §2,
/// "Terminal"): a <c>[Signal]</c> tag on each signal site, a <c>value signals:</c> line per folder, and the alert glyph only
/// on a Trigger. Pinned in-process over hand-built summaries, in ASCII and rich modes, as <see cref="SsaSectionRendererTests"/>
/// pins the rest of the section. A site's tag takes its kind from <see cref="SsaSummary.KindOf"/>, which marks no signal a
/// trigger until it is measured, so the glyph on a site tag has no seam here; the folder line takes its kind from the
/// <see cref="SsaSignalCount"/> it is given, which does.
/// </summary>
public sealed class SsaSignalRendererTests
{
    #region Methods: site tags
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_SignalSite_IsTaggedBeforeItsCapability(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "System.Diagnostics.Process.Start(\"cmd.exe\")", [SsaSignal.ShellInterpreter])]))));

        Assert.Contains("  [ShellInterpreter] ProcessExecution  System.Diagnostics.Process.Start(\"cmd.exe\")  in Own.A()", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_SiteWithTwoSignals_HasBothTags_InOrder(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", [SsaSignal.ShellInterpreter, SsaSignal.StealthArguments])]))));

        Assert.Contains("  [ShellInterpreter] [StealthArguments] ProcessExecution  K()  in Own.A()", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_SiteWithoutSignals_IsUntouched(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", null)]))));

        Assert.Contains("  ProcessExecution  K()  in Own.A()", lines);
        Assert.DoesNotContain(lines, l => l.Contains("value signals", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains('[') && !l.Contains("[!]", StringComparison.Ordinal));
    }

    // An information signal carries no glyph: only a measured trigger does.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_InformationalSignalSite_HasNoAlertGlyph(bool rich)
    {
        var output = string.Join("\n", Write(rich, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", [SsaSignal.SecretEnvironmentName])])))));

        Assert.DoesNotContain("[!]", output, StringComparison.Ordinal);
        Assert.DoesNotContain(char.ConvertFromUtf32(0x2716), output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the value signals line
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_FolderSignals_AreOneLineBeforeTheSites_InTheSummarysOrder(bool rich)
    {
        var ssa = Ssa([Site("Own.A()", "K()", [SsaSignal.ShellInterpreter])], signals: [Count(SsaSignal.ShellInterpreter, 2), Count(SsaSignal.SecretEnvironmentName, 1)]);

        var lines = Write(rich, Summary(Folder("lib/net8.0", ssa)));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal("  value signals: ShellInterpreter (2 site(s)), SecretEnvironmentName (1 site(s))", lines[header + 1]);
        Assert.Equal("  [ShellInterpreter] ProcessExecution  K()  in Own.A()", lines[header + 2]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_NoSignals_HasNoSignalsLine(bool rich) =>
        Assert.DoesNotContain(Write(rich, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", null)])))), l => l.Contains("value signals", StringComparison.Ordinal));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_EmptySignalsList_HasNoSignalsLine(bool rich) =>
        Assert.DoesNotContain(Write(rich, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", null)], signals: [])))), l => l.Contains("value signals", StringComparison.Ordinal));

    // A trigger's count is marked with the section's alert glyph, as the reachability section marks a trigger.
    [Fact]
    public void Write_TriggerSignalCount_HasTheAsciiAlertGlyph()
    {
        var ssa = Ssa([Site("Own.A()", "K()", null)], signals: [Count(SsaSignal.StealthArguments, 1, ReachStatementKind.Trigger), Count(SsaSignal.SecretEnvironmentName, 2)]);

        var lines = Write(false, Summary(Folder("lib/net8.0", ssa)));

        Assert.Contains("  value signals: [!] StealthArguments (1 site(s)), SecretEnvironmentName (2 site(s))", lines);
    }

    [Fact]
    public void Write_TriggerSignalCount_HasTheRichAlertGlyph()
    {
        var ssa = Ssa([Site("Own.A()", "K()", null)], signals: [Count(SsaSignal.ExecutableMemory, 1, ReachStatementKind.Trigger)]);

        var lines = Write(true, Summary(Folder("lib/net8.0", ssa)));

        Assert.Contains($"  value signals: {char.ConvertFromUtf32(0x2716)} ExecutableMemory (1 site(s))", lines);
    }

    // The folder whose listed sites the caps took still says its signals were there.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_FolderWhoseSitesWereAllDropped_StillShowsItsSignals(bool rich)
    {
        var ssa = Ssa([], dropped: 5, signals: [Count(SsaSignal.ShellInterpreter, 5)]);

        var lines = Write(rich, Summary(Folder("lib/net8.0", ssa)));

        Assert.Contains("  value signals: ShellInterpreter (5 site(s))", lines);
        Assert.Contains(lines, l => l.Contains("5 more site(s) with resolved values, not listed", StringComparison.Ordinal));
    }

    // A copy lists no sites and no signals: its primary's line is the one.
    [Fact]
    public void Write_CopyFolder_HasNoSignalsLine()
    {
        var primary = Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", [SsaSignal.ShellInterpreter])], signals: [Count(SsaSignal.ShellInterpreter, 1)]));
        var copy = Folder("lib/net9.0", Ssa([])) with { SameAs = "lib/net8.0" };

        var lines = Write(false, Summary(primary, copy));

        Assert.Single(lines, l => l.Contains("value signals", StringComparison.Ordinal));
    }

    // The count line still counts sites, not signals: a signal adds no resolved site.
    [Fact]
    public void Write_CountLine_IsUnchangedBySignals()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K()", [SsaSignal.ShellInterpreter])], signals: [Count(SsaSignal.ShellInterpreter, 1)]))));

        Assert.Contains("1 site(s) with resolved values in 1 folder(s); 0 folder(s) SSA-incomplete", lines);
    }

    // The call text is the package's own: markup in it stays literal beside a tag.
    [Fact]
    public void Write_SignalSiteWithMarkupInItsCall_RendersItLiterally()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa([Site("Own.A()", "K(\"[red]x[/]\")", [SsaSignal.ShellInterpreter])]))));

        Assert.Contains("  [ShellInterpreter] ProcessExecution  K(\"[red]x[/]\")  in Own.A()", lines);
    }
    #endregion

    #region Methods: helpers
    private static ReachabilitySummary Summary(params FolderReachSummary[] folders) => new(folders, 0, true);

    private static FolderReachSummary Folder(string folder, FolderSsaSummary? ssa) =>
        new(folder, PackageItemRole.Lib, FolderOutcome.Analyzed, null, null, [], [], [], ssa);

    private static FolderSsaSummary Ssa(IReadOnlyList<SsaSiteSummary> sites, int dropped = 0, IReadOnlyList<SsaSignalCount>? signals = null) =>
        new(SsaFolderOutcome.Analyzed, null, new SsaCounts(sites.Count + dropped, 0, 0, 0, sites.Count + dropped, false, 1, [], false, false, false, 0), sites, dropped, signals);

    private static SsaSiteSummary Site(string caller, string call, IReadOnlyList<SsaSignal>? signals) =>
        new(caller, "Ext.K(System.String)", Capability.ProcessExecution, 4, call, null, false, signals);

    private static SsaSignalCount Count(SsaSignal signal, int sites, ReachStatementKind kind = ReachStatementKind.Informational) => new(signal, kind, sites);

    private static List<string> Write(bool rich, ReachabilitySummary summary)
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = rich;
        console.Profile.Width = 240;
        SsaSectionRenderer.Write(console, rich, summary);
        var lines = writer.ToString().Split('\n').Select(l => l.TrimEnd('\r', ' ')).ToList();
        if (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);
        return lines;
    }
    #endregion
}
