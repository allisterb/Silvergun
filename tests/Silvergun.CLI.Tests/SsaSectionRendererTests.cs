namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// The <c>scan-package --reachability --ssa</c> section (<c>docs/agent/tasks/ssa-facts-s5.md</c> §4), pinned in-process
/// over hand-built <see cref="FolderSsaSummary"/> records, as <see cref="ReachabilitySectionRendererTests"/> pins the
/// reachability section: the title, the count line, per-folder site and target lines, the dropped line, every
/// <c>SSA incomplete:</c> gap, folders with nothing to say left out, markup in data rendered literally, and
/// <see cref="SsaSectionRenderer.IncompleteNote"/>. The end-to-end wiring is <see cref="SsaScanPackageCliTests"/>.
/// <para>Non-ASCII glyphs are built from code points, never typed.</para>
/// </summary>
public sealed class SsaSectionRendererTests
{
    #region Methods: the title and the count line
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Title_SaysSsaDerivedAndInformational(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa())));

        Assert.Contains(lines, l => l.Contains("Argument values (SSA-derived, informational; constants at sinks are common in benign packages)", StringComparison.Ordinal));
    }

    // Listed and dropped sites count as resolved; folders count when they have any; incomplete folders are counted apart.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_CountLine_CountsResolvedSitesFoldersAndIncompleteFolders(bool rich)
    {
        var summary = Summary(
            Folder("lib/net8.0", Ssa(sites: [Site("A()"), Site("B()")], dropped: 3)),
            Folder("lib/net9.0", Ssa(sites: [Site("C()")], counts: Counts(methodUnknown: 2, unknown: [new(SsaFailureKind.UnresolvedFact, 1)]))),
            Folder("lib/netstandard2.0", Ssa()),
            Folder("tools/any", NotAnalysed(SsaFolderOutcome.NotRun, "the folder's graph was not built")));

        var lines = Write(rich, summary);

        Assert.Contains("6 site(s) with resolved values in 2 folder(s); 2 folder(s) SSA-incomplete", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_NothingResolved_AllComplete_IsTheTitleAndTheCountLineOnly(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa()), Folder("lib/net9.0", Ssa())));

        Assert.Equal(2, lines.Count);
        Assert.Equal("0 site(s) with resolved values in 0 folder(s); 0 folder(s) SSA-incomplete", lines[1]);
    }

    // A folder with no SSA at all (the whole-pass failure) is counted SSA-incomplete: SSA was asked for and did not run.
    [Fact]
    public void Write_FolderWithoutSsa_IsCountedIncomplete()
    {
        var failed = new FolderReachSummary(string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, "the graph pass failed", null, [], [], []);

        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa()), failed));

        Assert.Contains("0 site(s) with resolved values in 0 folder(s); 1 folder(s) SSA-incomplete", lines);
    }
    #endregion

    #region Methods: sites
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Site_IsCapabilityCallAndCaller_UnderItsFolder(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.Type.Run()", "System.Diagnostics.Process.Start(\"cmd.exe\", _)")]))));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal("  ProcessExecution  System.Diagnostics.Process.Start(\"cmd.exe\", _)  in Own.Type.Run()", lines[header + 1]);
        Assert.Equal(header + 2, lines.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_MergedSite_SaysMergedDefinitions(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K(1)", merged: true)]))));

        Assert.Contains("  ProcessExecution  K(1)  in Own.A() (merged definitions)", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Target_IsTheNextLine_WithItsCandidates(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"Own.Loader\" :: \"Run\"", ["Own.Loader.Run()", "Own.Loader.Run(System.Int32)"], 2, null);
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.Boot()", "System.Reflection.MethodBase.Invoke(_, _)", capability: Capability.ReflectionInvocation, target: target)]))));

        var at = lines.IndexOf("  ReflectionInvocation  System.Reflection.MethodBase.Invoke(_, _)  in Own.Boot()");
        Assert.True(at >= 0, string.Join("\n", lines));
        Assert.Equal("      acts on Method \"Own.Loader\" :: \"Run\" (2 own candidate(s) by name: Own.Loader.Run(), Own.Loader.Run(System.Int32))", lines[at + 1]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithMoreCandidatesThanListed_EndsTheListWithAnEllipsis(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", ["T.M()"], 12, null);
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Method \"T\" :: \"M\" (12 own candidate(s) by name: T.M(), ...)", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithoutCandidates_HasNoCandidateClause(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Type, "Type \"Ext.T\"", [], 0, null);
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Type \"Ext.T\"", lines);
    }

    // Past the folder's text budget a target keeps its candidate count but no names (S4.3 W3): the clause must not read
    // as an empty list ("by name: , ...").
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithACountButNoNames_DoesNotRenderAnEmptyList(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", [], 3, null);
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        var line = Assert.Single(lines, l => l.Contains("acts on", StringComparison.Ordinal));
        Assert.DoesNotContain("by name: ,", line, StringComparison.Ordinal);
        Assert.DoesNotContain("by name: )", line, StringComparison.Ordinal);
        Assert.Equal("      acts on Method \"T\" :: \"M\" (3 own candidate(s) by name; names not kept, the folder's text budget ran out)", line);
    }

    // Null names (a crafted record) are skipped; the others are listed and the ellipsis still counts the total.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithNullCandidateNames_SkipsThem(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", [null!, "T.M()", null!], 3, null);

        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Method \"T\" :: \"M\" (3 own candidate(s) by name: T.M(), ...)", lines);
    }

    // Only null names, or no list at all: read as names not kept, and nothing throws.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithOnlyNullCandidateNames_ReadsNamesNotKept(bool nullList)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", nullList ? null! : [null!, null!], 2, null);

        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Method \"T\" :: \"M\" (2 own candidate(s) by name; names not kept, the folder's text budget ran out)", lines);
    }

    // A count of 0 has no clause, whatever the list holds.
    [Fact]
    public void Write_TargetWithNamesButACountOfZero_HasNoCandidateClause()
    {
        var target = new SsaTargetSummary(SsaTargetKind.Type, "Type \"T\"", ["T"], 0, null);

        Assert.Contains("      acts on Type \"T\"", Write(false, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)])))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_SiteWithoutTarget_HasNoActsOnLine(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K(1)")]))));

        Assert.DoesNotContain(lines, l => l.Contains("acts on", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Dropped_SaysHowManyAndTheCaps_AndNotInJson(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()")], dropped: 40))));

        Assert.Contains(
            $"  {Bullet(rich)} 40 more site(s) with resolved values, not listed (the summary's caps of 100 per folder and 1000 per package); not in --json either",
            lines);
    }

    // A folder whose sites the package cap took entirely still says so.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_FolderWithOnlyDroppedSites_IsListed(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(dropped: 7))));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.StartsWith($"  {Bullet(rich)} 7 more site(s) with resolved values, not listed", lines[header + 1], StringComparison.Ordinal);
        Assert.Contains("7 site(s) with resolved values in 1 folder(s); 0 folder(s) SSA-incomplete", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_FolderHeader_IsTheFolderAndItsRole_PackageLabelledForTheEmptyName(bool rich)
    {
        var lines = Write(rich, Summary(
            Folder("tools/net8.0/any", Ssa(sites: [Site("Own.A()")])),
            Folder(string.Empty, NotAnalysed(SsaFolderOutcome.Crashed, "exit 35"))));

        Assert.Contains("tools/net8.0/any (Tools)", lines);
        Assert.Contains("(package) (Other)", lines);
    }

    // Sites, then the dropped line, then the gaps.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_Folder_ListsSitesThenDroppedThenGaps(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Type, "Type \"T\"", [], 0, null);
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("A()", "K(1)", target: target), Site("B()", "K(2)")], dropped: 1, counts: Counts(notJoined: 4)))));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal(
            [
                "  ProcessExecution  K(1)  in A()",
                "      acts on Type \"T\"",
                "  ProcessExecution  K(2)  in B()",
                $"  {Bullet(rich)} 1 more site(s) with resolved values, not listed (the summary's caps of 100 per folder and 1000 per package); not in --json either",
                "  SSA incomplete: 4 site(s) not found in the lifted code",
            ],
            lines.Skip(header + 1).ToArray());
    }

    // A complete folder with nothing listed is counted but not written.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_CompleteFolderWithNothingResolved_IsNotListed(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("A()")])), Folder("lib/quiet", Ssa(counts: Counts(analyzed: 30)))));

        Assert.DoesNotContain(lines, l => l.Contains("lib/quiet", StringComparison.Ordinal));
    }

    // No alert glyph: that stays for reachability triggers (§4).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_HasNoAlertGlyph(bool rich)
    {
        var output = string.Join("\n", Write(rich, FullSummary()));

        Assert.DoesNotContain("[!]", output, StringComparison.Ordinal);
        Assert.DoesNotContain(char.ConvertFromUtf32(0x2716), output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the terminal's cap of 10 sites per folder (user's ruling on the corpus results)
    [Fact]
    public void Premise_TheTerminalCapIsTen() => Assert.Equal(10, SsaSectionRenderer.MaxSitesPerFolder);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TenSites_ListsAll_WithoutAMoreLine(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: Sites(10)))));

        Assert.Equal(Enumerable.Range(0, 10).Select(SiteLine), FolderBody(lines));
        Assert.DoesNotContain(lines, l => l.Contains("more site(s)", StringComparison.Ordinal));
    }

    // The first ten in the summary's order (resolved targets first, as the summary sorts them), then how many more.
    [Theory]
    [InlineData(false, 11)]
    [InlineData(true, 11)]
    [InlineData(false, 100)]
    [InlineData(true, 100)]
    public void Write_MoreThanTenSites_ListsTheFirstTen_ThenTheMoreLine(bool rich, int count)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: Sites(count)))));

        Assert.Equal(
            [.. Enumerable.Range(0, 10).Select(SiteLine), $"  {Bullet(rich)} {count - 10} more site(s) with resolved values in --json"],
            FolderBody(lines));
    }

    // Both lines: the terminal's "more" line, then the summary caps' dropped line, then the gaps.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TerminalCapAndSummaryCap_GiveBothLines_InOrder(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: Sites(100), dropped: 5, counts: Counts(analyzed: 105, notJoined: 1)))));

        Assert.Equal(
            [
                .. Enumerable.Range(0, 10).Select(SiteLine),
                $"  {Bullet(rich)} 90 more site(s) with resolved values in --json",
                $"  {Bullet(rich)} 5 more site(s) with resolved values, not listed (the summary's caps of 100 per folder and 1000 per package); not in --json either",
                "  SSA incomplete: 1 site(s) not found in the lifted code",
            ],
            FolderBody(lines));
    }

    // The count line totals every resolved site, listed on the terminal or not.
    [Fact]
    public void Write_CountLine_IsNotChangedByTheTerminalCap()
    {
        var lines = Write(false, Summary(
            Folder("lib/net8.0", Ssa(sites: Sites(100), dropped: 5)),
            Folder("lib/net9.0", Ssa(sites: Sites(11)))));

        Assert.Contains("116 site(s) with resolved values in 2 folder(s); 0 folder(s) SSA-incomplete", lines);
    }

    // A target line belongs to its site: sites past the tenth show neither.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetLines_OnlyForTheListedSites(bool rich)
    {
        var sites = Enumerable.Range(0, 15)
            .Select(i => Site($"Own.M{i:00}()", $"K({i})", target: new SsaTargetSummary(SsaTargetKind.Type, $"Type \"T{i:00}\"", [], 0, null)))
            .ToArray();

        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: sites))));

        var targets = lines.Where(l => l.Contains("acts on", StringComparison.Ordinal)).ToArray();
        Assert.Equal(Enumerable.Range(0, 10).Select(i => $"      acts on Type \"T{i:00}\""), targets);
        Assert.Equal($"  {Bullet(rich)} 5 more site(s) with resolved values in --json", lines[^1]);
        // Each target line follows its own site line.
        for (var i = 0; i < 10; i++)
            Assert.Equal($"      acts on Type \"T{i:00}\"", lines[lines.IndexOf($"  ProcessExecution  K({i})  in Own.M{i:00}()") + 1]);
    }

    // Per folder: each folder's own first ten.
    [Fact]
    public void Write_TerminalCap_IsPerFolder()
    {
        var lines = Write(false, Summary(Folder("lib/a", Ssa(sites: Sites(12))), Folder("lib/b", Ssa(sites: Sites(3)))));

        Assert.Equal(13, lines.Count(l => l.StartsWith("  ProcessExecution  ", StringComparison.Ordinal)));
        Assert.Single(lines, l => l.Contains("2 more site(s) with resolved values in --json", StringComparison.Ordinal));
    }

    private static SsaSiteSummary[] Sites(int count) => [.. Enumerable.Range(0, count).Select(i => Site($"Own.M{i:000}()", $"K({i})"))];

    private static string SiteLine(int i) => $"  ProcessExecution  K({i})  in Own.M{i:000}()";

    // The lines under the only folder's header.
    private static string[] FolderBody(List<string> lines) => [.. lines.SkipWhile(l => !l.EndsWith(" (Lib)", StringComparison.Ordinal)).Skip(1)];
    #endregion

    #region Methods: the candidate search's gaps (review W2)
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithCandidatesAndAGap_SaysTheSearchHasGaps(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", ["T.M()", "T.M(System.Int32)"], 2, "the graph was truncated");

        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Method \"T\" :: \"M\" (2 own candidate(s) by name: T.M(), T.M(System.Int32)); the search has gaps: the graph was truncated", lines);
    }

    // No candidate found is never "not own" when the search had holes: the gap is said even with a count of 0.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TargetWithoutCandidatesButAGap_StillSaysTheSearchHasGaps(bool rich)
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", [], 0, "no index was given");

        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Method \"T\" :: \"M\"; the search has gaps: no index was given", lines);
    }

    [Fact]
    public void Write_TargetWithNamesNotKeptAndAGap_SaysBoth()
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", [], 4, "past 16 type names");

        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)]))));

        Assert.Contains("      acts on Method \"T\" :: \"M\" (4 own candidate(s) by name; names not kept, the folder's text budget ran out); the search has gaps: past 16 type names", lines);
    }

    [Fact]
    public void Write_TargetWithoutAGap_HasNoGapClause()
    {
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", ["T.M()"], 1, null);

        var line = Assert.Single(Write(false, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)])))), l => l.Contains("acts on", StringComparison.Ordinal));

        Assert.DoesNotContain("gaps", line, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Write_MarkupInTheGap_RendersLiterally(bool rich, bool ansi)
    {
        var (console, writer) = MakeConsole(rich, ansi);
        var target = new SsaTargetSummary(SsaTargetKind.Method, "Method \"T\" :: \"M\"", [], 0, Inject + " [bold]gap[/] [");

        var ex = Record.Exception(() => SsaSectionRenderer.Write(console, rich, Summary(Folder("lib/net8.0", Ssa(sites: [Site("Own.A()", "K()", target: target)])))));

        Assert.Null(ex);
        Assert.Contains("; the search has gaps: " + Inject + " [bold]gap[/] [", writer.ToString(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: SameAs copies (review W3)
    // An SSA-analysed copy is listed under its header with where its sites are; it is counted as a copy, never in
    // "in M folder(s)".
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_AnalysedCopy_SaysWhereItsSitesAre_AndIsCountedAsACopy(bool rich)
    {
        var lines = Write(rich, Summary(
            Folder("lib/net8.0", Ssa(sites: [Site("A()"), Site("B()")])),
            Folder("lib/net9.0", Ssa()) with { SameAs = "lib/net8.0" }));

        Assert.Contains("2 site(s) with resolved values in 1 folder(s); 0 folder(s) SSA-incomplete; 1 folder(s) are copies, listed under their primary", lines);
        var header = lines.IndexOf("lib/net9.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal("  same files as lib/net8.0; its sites are listed there", lines[header + 1]);
        Assert.Equal(header + 2, lines.Count);
    }

    [Fact]
    public void Write_TwoCopies_AreCounted()
    {
        var lines = Write(false, Summary(
            Folder("lib/net8.0", Ssa(sites: [Site("A()")])),
            Folder("lib/net9.0", Ssa()) with { SameAs = "lib/net8.0" },
            Folder("lib/net10.0", Ssa()) with { SameAs = "lib/net8.0" }));

        Assert.Contains("1 site(s) with resolved values in 1 folder(s); 0 folder(s) SSA-incomplete; 2 folder(s) are copies, listed under their primary", lines);
    }

    // Without a copy the count line has no copies clause.
    [Fact]
    public void Write_NoCopy_HasNoCopiesClause()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(sites: [Site("A()")]))));

        Assert.DoesNotContain(lines, l => l.Contains("copies", StringComparison.Ordinal));
    }

    // An incomplete analysed copy: the copy line first, then its own gaps (its counts are its primary's).
    [Fact]
    public void Write_IncompleteAnalysedCopy_HasTheCopyLineThenItsGaps()
    {
        var lines = Write(false, Summary(
            Folder("lib/net8.0", Ssa(counts: Counts(notJoined: 2))),
            Folder("lib/net9.0", Ssa(counts: Counts(notJoined: 2))) with { SameAs = "lib/net8.0" }));

        var header = lines.IndexOf("lib/net9.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal(["  same files as lib/net8.0; its sites are listed there", "  SSA incomplete: 2 site(s) not found in the lifted code"], lines.Skip(header + 1).ToArray());
        Assert.Contains("0 site(s) with resolved values in 0 folder(s); 2 folder(s) SSA-incomplete; 1 folder(s) are copies, listed under their primary", lines);
    }

    // A copy whose SSA was not analysed is no copy for this rule: it renders its gap as any folder does.
    [Theory]
    [InlineData(SsaFolderOutcome.Crashed)]
    [InlineData(SsaFolderOutcome.TimedOut)]
    [InlineData(SsaFolderOutcome.NotRun)]
    public void Write_NonAnalysedCopy_RendersItsGapAsBefore(SsaFolderOutcome outcome)
    {
        var lines = Write(false, Summary(
            Folder("lib/net8.0", Ssa(sites: [Site("A()")])),
            Folder("lib/net9.0", NotAnalysed(outcome, "exit 35")) with { SameAs = "lib/net8.0" }));

        var header = lines.IndexOf("lib/net9.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal([$"  SSA incomplete: not analysed: {outcome}: exit 35"], lines.Skip(header + 1).ToArray());
        Assert.DoesNotContain(lines, l => l.Contains("same files as", StringComparison.Ordinal) || l.Contains("copies", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: crafted site lists (review N4)
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_NullSitesList_DoesNotThrow(bool rich)
    {
        var ssa = new FolderSsaSummary(SsaFolderOutcome.Analyzed, null, Counts(analyzed: 3), null!, 2);
        List<string>? lines = null;

        var ex = Record.Exception(() => lines = Write(rich, Summary(Folder("lib/net8.0", ssa))));

        Assert.Null(ex);
        Assert.Contains("2 site(s) with resolved values in 1 folder(s); 0 folder(s) SSA-incomplete", lines!);
        Assert.Contains(lines!, l => l.StartsWith($"  {Bullet(rich)} 2 more site(s) with resolved values", StringComparison.Ordinal));
    }

    [Fact]
    public void Write_NullSiteElement_IsSkipped_AndTheOthersListed()
    {
        var ssa = new FolderSsaSummary(SsaFolderOutcome.Analyzed, null, Counts(analyzed: 2), [null!, Site("Own.B()", "K(2)"), null!], 0);
        List<string>? lines = null;

        var ex = Record.Exception(() => lines = Write(false, Summary(Folder("lib/net8.0", ssa))));

        Assert.Null(ex);
        Assert.Single(lines!, l => l.Contains("  in ", StringComparison.Ordinal));
        Assert.Contains("  ProcessExecution  K(2)  in Own.B()", lines!);
    }

    [Fact]
    public void IncompleteNote_NullSitesList_DoesNotThrow()
    {
        var ssa = new FolderSsaSummary(SsaFolderOutcome.Analyzed, null, Counts(analyzed: 1), null!, 0);

        Assert.Null(Record.Exception(() => SsaSectionRenderer.IncompleteNote(Summary(Folder("lib/net8.0", ssa)))));
    }
    #endregion

    #region Methods: gaps
    [Theory]
    [InlineData(false, SsaFolderOutcome.Crashed)]
    [InlineData(false, SsaFolderOutcome.TimedOut)]
    [InlineData(false, SsaFolderOutcome.NotRun)]
    [InlineData(true, SsaFolderOutcome.Crashed)]
    [InlineData(true, SsaFolderOutcome.TimedOut)]
    [InlineData(true, SsaFolderOutcome.NotRun)]
    public void Write_NotAnalysedFolder_NamesItsOutcomeAndReason(bool rich, SsaFolderOutcome outcome)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", NotAnalysed(outcome, "its SSA facts were not extracted within 8 s"))));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal($"  SSA incomplete: not analysed: {outcome}: its SSA facts were not extracted within 8 s", lines[header + 1]);
        Assert.Equal(header + 2, lines.Count);
    }

    // Analyzed in name only (no counts): still not analysed, and a missing reason is said.
    [Fact]
    public void Write_AnalyzedWithoutCounts_ReadsNotAnalysed_NoReasonGiven()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", new FolderSsaSummary(SsaFolderOutcome.Analyzed, null, null, [], 0))));

        Assert.Contains("  SSA incomplete: not analysed: Analyzed: no reason was given", lines);
    }

    [Fact]
    public void Write_AssembliesLost_SaysNoMethodWasLifted()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: Counts(methodUnknown: 3, assembliesLost: 2, unknown: [new(SsaFailureKind.Unreadable, 3)])))));

        Assert.Contains("  SSA incomplete: 2 assembly(ies) could not be read, so no method was lifted", lines);
        Assert.Contains("  SSA incomplete: 3 site(s) in methods that did not lift (Unreadable 3)", lines);
    }

    [Fact]
    public void Write_MethodUnknown_NamesEachFailureKind()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: Counts(methodUnknown: 5, unknown: [new(SsaFailureKind.UnresolvedFact, 3), new(SsaFailureKind.Bounds, 1)])))));

        Assert.Contains("  SSA incomplete: 5 site(s) in methods that did not lift (UnresolvedFact 3, Bounds 1)", lines);
    }

    [Fact]
    public void Write_NotJoined_SaysNotFoundInTheLiftedCode()
    {
        Assert.Contains("  SSA incomplete: 2 site(s) not found in the lifted code", Write(false, Summary(Folder("lib/net8.0", Ssa(counts: Counts(notJoined: 2))))));
    }

    [Theory]
    [InlineData(true, false, "time")]
    [InlineData(false, true, "method")]
    [InlineData(true, true, "time")]
    public void Write_NotRun_NamesTheBudget(bool time, bool method, string budget)
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: Counts(notRun: 6, timeBudget: time, methodBudget: method)))));

        Assert.Contains($"  SSA incomplete: 6 site(s) not reached: the {budget} budget ran out", lines);
    }

    // N3: a budget that ran out with no site left unreached says only that.
    [Theory]
    [InlineData(true, false, "time")]
    [InlineData(false, true, "method")]
    [InlineData(true, true, "time")]
    public void Write_BudgetFlagWithoutNotRunSites_SaysOnlyTheBudgetRanOut(bool time, bool method, string budget)
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: Counts(analyzed: 4, timeBudget: time, methodBudget: method)))));

        Assert.Contains($"  SSA incomplete: the {budget} budget ran out", lines);
        Assert.DoesNotContain(lines, l => l.Contains("not reached", StringComparison.Ordinal));
    }

    [Fact]
    public void Write_Truncated_SaysHowManySitesWereExamined()
    {
        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: Counts(analyzed: 8_192, sitesTotal: 9_000, truncated: true)))));

        Assert.Contains("  SSA incomplete: only the first 8192 of 9000 sink site(s) were examined", lines);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_TextBudget_IsAGap_AndTheFolderIsIncomplete(bool rich)
    {
        var lines = Write(rich, Summary(Folder("lib/net8.0", Ssa(counts: Counts(analyzed: 5, textBudget: true)))));

        var header = lines.IndexOf("lib/net8.0 (Lib)");
        Assert.True(header >= 0, string.Join("\n", lines));
        Assert.Equal(
            "  SSA incomplete: the folder's text budget ran out: later constants keep only their hash, and targets no candidate names",
            lines[header + 1]);
        Assert.Equal(header + 2, lines.Count);
        Assert.Contains("0 site(s) with resolved values in 0 folder(s); 1 folder(s) SSA-incomplete", lines);
    }

    [Fact]
    public void IncompleteNote_TextBudgetAlone_GivesTheNote()
    {
        Assert.Equal(Note(1), SsaSectionRenderer.IncompleteNote(Summary(Folder("lib/net8.0", Ssa(counts: Counts(analyzed: 5, textBudget: true))))));
    }

    // Every gap of one folder, in the renderer's order.
    [Fact]
    public void Write_EveryGap_InOrder()
    {
        var counts = Counts(analyzed: 1, methodUnknown: 2, notJoined: 3, notRun: 4, sitesTotal: 20, truncated: true, methodBudget: true, textBudget: true, assembliesLost: 1, unknown: [new(SsaFailureKind.Import, 2)]);

        var lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: counts))));

        Assert.Equal(
            [
                "  SSA incomplete: 1 assembly(ies) could not be read, so no method was lifted",
                "  SSA incomplete: 2 site(s) in methods that did not lift (Import 2)",
                "  SSA incomplete: 3 site(s) not found in the lifted code",
                "  SSA incomplete: 4 site(s) not reached: the method budget ran out",
                "  SSA incomplete: the folder's text budget ran out: later constants keep only their hash, and targets no candidate names",
                "  SSA incomplete: only the first 10 of 20 sink site(s) were examined",
            ],
            lines.SkipWhile(l => l != "lib/net8.0 (Lib)").Skip(1).ToArray());
    }

    // A crafted record whose failure-kind list is null or holds null must not throw (the section never throws).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Write_CraftedUnknownList_DoesNotThrow(bool nullList)
    {
        var counts = Counts(methodUnknown: 1) with { Unknown = nullList ? null! : [null!] };

        List<string>? lines = null;
        var ex = Record.Exception(() => lines = Write(false, Summary(Folder("lib/net8.0", Ssa(counts: counts)))));

        Assert.Null(ex);
        Assert.Contains(lines!, l => l.StartsWith("  SSA incomplete: 1 site(s) in methods that did not lift (", StringComparison.Ordinal));
    }

    // A null element among real ones is skipped; the real ones are still named.
    [Fact]
    public void Write_UnknownListWithANullElement_NamesTheOthers()
    {
        var counts = Counts(methodUnknown: 3) with { Unknown = [null!, new(SsaFailureKind.Bounds, 3)] };

        Assert.Contains("  SSA incomplete: 3 site(s) in methods that did not lift (Bounds 3)", Write(false, Summary(Folder("lib/net8.0", Ssa(counts: counts)))));
    }
    #endregion

    #region Methods: IncompleteNote
    [Fact]
    public void IncompleteNote_AllComplete_IsNull()
    {
        Assert.Null(SsaSectionRenderer.IncompleteNote(Summary(Folder("lib/net8.0", Ssa(sites: [Site("A()")])), Folder("lib/net9.0", Ssa()))));
    }

    [Fact]
    public void IncompleteNote_EmptySummary_IsNull() => Assert.Null(SsaSectionRenderer.IncompleteNote(new ReachabilitySummary([], 0, true)));

    [Fact]
    public void IncompleteNote_CountsIncompleteFolders()
    {
        var summary = Summary(
            Folder("lib/a", Ssa()),
            Folder("lib/b", NotAnalysed(SsaFolderOutcome.TimedOut, "8 s")),
            Folder("lib/c", Ssa(counts: Counts(notJoined: 1))));

        Assert.Equal(Note(2), SsaSectionRenderer.IncompleteNote(summary));
    }

    // Called only when --ssa was given, so a folder without SSA facts is incomplete.
    [Fact]
    public void IncompleteNote_CountsFoldersWithoutSsa()
    {
        var failed = new FolderReachSummary(string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, "the graph pass failed", null, [], [], []);

        Assert.Equal(Note(1), SsaSectionRenderer.IncompleteNote(Summary(Folder("lib/a", Ssa()), failed)));
    }

    // The whole-pass failure: no folder has SSA, so the section is not written, and the note says where to look instead.
    [Fact]
    public void IncompleteNote_NoFolderHasSsa_PointsAtTheReachabilitySection()
    {
        var failed = new FolderReachSummary(string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, "the graph pass failed", null, [], [], []);

        Assert.Equal(Note(1, noSsaAnywhere: true), SsaSectionRenderer.IncompleteNote(new ReachabilitySummary([failed], 0, false)));
        Assert.Equal(
            "scan-package: SSA facts INCOMPLETE (2 folder(s) SSA did not fully analyse); no folder has SSA facts; see the reachability section.",
            SsaSectionRenderer.IncompleteNote(new ReachabilitySummary([failed, failed with { Folder = "lib/net8.0" }], 0, false)));
    }

    // One folder with SSA is enough for the usual tail.
    [Fact]
    public void IncompleteNote_SomeFolderHasSsa_SaysSeeTheReport()
    {
        var failed = new FolderReachSummary("lib/x", PackageItemRole.Lib, FolderOutcome.NotRun, "cap", null, [], [], []);

        Assert.EndsWith("); see the report.", SsaSectionRenderer.IncompleteNote(Summary(failed, Folder("lib/a", NotAnalysed(SsaFolderOutcome.Crashed, "x"))))!, StringComparison.Ordinal);
    }

    // Never folded into reachability's note (D4): a graph-complete summary still gets the SSA note, and the reverse.
    [Fact]
    public void IncompleteNote_IsIndependentOfReachabilitysNote()
    {
        var ssaIncomplete = new ReachabilitySummary([Folder("lib/a", NotAnalysed(SsaFolderOutcome.Crashed, "x"))], 0, true);
        var graphIncomplete = new ReachabilitySummary([Folder("lib/a", Ssa()) with { Outcome = FolderOutcome.NotRun, Reason = "cap" }], 0, false);

        Assert.Null(ReachabilitySectionRenderer.IncompleteNote(ssaIncomplete));
        Assert.Equal(Note(1), SsaSectionRenderer.IncompleteNote(ssaIncomplete));
        Assert.NotNull(ReachabilitySectionRenderer.IncompleteNote(graphIncomplete));
        Assert.Null(SsaSectionRenderer.IncompleteNote(graphIncomplete));
    }
    #endregion

    #region Methods: modes and markup injection
    [Fact]
    public void Write_Ascii_HasNoLeftoverMarkup_AndOnlyAsciiOutsideTheData()
    {
        var output = string.Join("\n", Write(false, FullSummary()));

        var offender = output.FirstOrDefault(c => c > (char)0x7F || (c < ' ' && c is not '\n'));
        Assert.True(offender == '\0', $"ASCII output carried U+{(int)offender:X4}.");
        foreach (var tag in new[] { "[/]", "[grey]", "[yellow]", "[bold]", "[red]" })
            Assert.DoesNotContain(tag, output, StringComparison.Ordinal);
    }

    [Fact]
    public void Write_Rich_UsesTheUnicodeBullet()
    {
        var output = string.Join("\n", Write(true, FullSummary()));

        Assert.Contains($"  {Bullet(true)} 40 more site(s)", output, StringComparison.Ordinal);
        Assert.DoesNotContain("  - 40 more site(s)", output, StringComparison.Ordinal);
    }

    // Markup in every string the section shows renders literally, on all three consoles, and nothing throws.
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Write_MarkupInEveryString_RendersLiterally_AndDoesNotThrow(bool rich, bool ansi)
    {
        var (console, writer) = MakeConsole(rich, ansi);
        var target = new SsaTargetSummary(SsaTargetKind.Method, Inject + " target", [Inject + " candidate"], 2, Inject + " gap");
        var summary = Summary(
            Folder(Inject + "/a", Ssa(sites: [Site(Inject + " caller", "K(\"" + Inject + "\")", target: target)], dropped: 1,
                counts: Counts(methodUnknown: 1, unknown: [new(SsaFailureKind.Adapter, 1)]))),
            Folder(Inject + "/b", NotAnalysed(SsaFolderOutcome.Crashed, Inject + " reason")),
            Folder(Inject + "/c", Ssa()) with { SameAs = Inject + "/a" });

        var ex = Record.Exception(() => SsaSectionRenderer.Write(console, rich, summary));

        Assert.Null(ex);
        var output = writer.ToString();
        foreach (var literal in new[] { Inject + "/a", Inject + " caller", "K(\"" + Inject + "\")", Inject + " target", Inject + " candidate", "; the search has gaps: " + Inject + " gap",
                     Inject + "/b", Inject + " reason", Inject + "/c", "same files as " + Inject + "/a; its sites are listed there" })
            Assert.Contains(literal, output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, "[")]
    [InlineData(false, "]")]
    [InlineData(true, "[[")]
    [InlineData(true, "]]")]
    public void Write_LoneBracketsInEveryString_DoNotThrow(bool rich, string bracket)
    {
        var (console, writer) = MakeConsole(rich, ansi: rich);
        var target = new SsaTargetSummary(SsaTargetKind.Method, "t" + bracket, ["c" + bracket], 1, "g" + bracket);
        var summary = Summary(
            Folder("f" + bracket, Ssa(sites: [Site("caller" + bracket, "K(" + bracket + ")", target: target)])),
            Folder("x" + bracket, NotAnalysed(SsaFolderOutcome.NotRun, "why" + bracket)));

        var ex = Record.Exception(() => SsaSectionRenderer.Write(console, rich, summary));

        Assert.Null(ex);
        Assert.Contains("why" + bracket, writer.ToString(), StringComparison.Ordinal);
        Assert.Contains("K(" + bracket + ")", writer.ToString(), StringComparison.Ordinal);
        Assert.Contains("; the search has gaps: g" + bracket, writer.ToString(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: through PackageReportRenderer
    // The section sits right after the reachability section and before the Assemblies section.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Render_WithSsa_SectionFollowsTheReachabilitySection(bool rich)
    {
        var lines = Render(rich, Report() with { Reachability = FullSummary() });

        var reach = lines.FindIndex(l => l.Contains("Reachability (informational", StringComparison.Ordinal));
        var section = lines.FindIndex(l => l.Contains("Argument values (SSA-derived", StringComparison.Ordinal));
        var assemblies = lines.FindIndex(l => l.Contains("Assemblies", StringComparison.Ordinal));
        Assert.True(reach >= 0 && section > reach && assemblies > section, $"reachability {reach}, section {section}, assemblies {assemblies}");
        Assert.Equal(1, lines.Count(l => l.Contains("Argument values (SSA-derived", StringComparison.Ordinal)));
    }

    // No folder with SSA: no section (SSA was not asked for).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Render_WithoutSsa_HasNoSection(bool rich)
    {
        var withoutSsa = new ReachabilitySummary([.. FullSummary().Folders.Select(f => f with { Ssa = null })], 0, false);

        var output = string.Join("\n", Render(rich, Report() with { Reachability = withoutSsa }));

        Assert.Contains("Reachability (informational", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Argument values", output, StringComparison.Ordinal);
        Assert.DoesNotContain("SSA", output, StringComparison.Ordinal);
    }

    // The section adds lines and changes nothing else.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Render_WithSsa_ChangesNothingButTheSection(bool rich)
    {
        var with = Render(rich, Report() with { Reachability = FullSummary() });
        var without = Render(rich, Report() with { Reachability = new ReachabilitySummary([.. FullSummary().Folders.Select(f => f with { Ssa = null })], 0, false) });

        var start = with.FindIndex(l => l.Contains("Argument values (SSA-derived", StringComparison.Ordinal));
        var end = with.FindIndex(start, l => l.Contains("Assemblies", StringComparison.Ordinal));
        Assert.True(start >= 0 && end > start, $"section {start}..{end}");
        Assert.Equal(without, with.Take(start).Concat(with.Skip(end)).ToList());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void ExitCodeAndCompleteness_IgnoreSsa(bool strict, bool allowIncomplete)
    {
        var withoutSsa = Report() with { Reachability = new ReachabilitySummary([.. FullSummary().Folders.Select(f => f with { Ssa = null })], 0, false) };
        var withSsa = Report() with { Reachability = FullSummary() };

        Assert.Equal(Program.ScanPackageExitCode(withoutSsa, strict, allowIncomplete), Program.ScanPackageExitCode(withSsa, strict, allowIncomplete));
        var a = CompletenessAssessment.ForPackage(withoutSsa);
        var b = CompletenessAssessment.ForPackage(withSsa);
        Assert.Equal(a.IsComplete, b.IsComplete);
        Assert.Equal(a.Caveats, b.Caveats);
    }
    #endregion

    #region Methods: fixtures
    private static ReachabilitySummary Summary(params FolderReachSummary[] folders) => new(folders, 0, true);

    // A graph-analysed, decided folder carrying `ssa`.
    private static FolderReachSummary Folder(string folder, FolderSsaSummary? ssa) =>
        new(folder, RoleOf(folder), FolderOutcome.Analyzed, null, null, [], [], [], ssa);

    private static FolderSsaSummary Ssa(IReadOnlyList<SsaSiteSummary>? sites = null, int dropped = 0, SsaCounts? counts = null) =>
        new(SsaFolderOutcome.Analyzed, null, counts ?? Counts(analyzed: (sites?.Count ?? 0) + dropped), sites ?? [], dropped);

    private static FolderSsaSummary NotAnalysed(SsaFolderOutcome outcome, string reason) => new(outcome, reason, null, [], 0);

    private static SsaCounts Counts(
        int analyzed = 0, int methodUnknown = 0, int notJoined = 0, int notRun = 0, int? sitesTotal = null, bool truncated = false,
        bool methodBudget = false, bool timeBudget = false, bool textBudget = false, int assembliesLost = 0, IReadOnlyList<SsaFailureCount>? unknown = null) =>
        new(analyzed, methodUnknown, notJoined, notRun, sitesTotal ?? analyzed + methodUnknown + notJoined + notRun, truncated, 1, unknown ?? [],
            methodBudget, timeBudget, textBudget, assembliesLost);

    private static SsaSiteSummary Site(string caller, string call = "K(\"x\")", Capability capability = Capability.ProcessExecution, SsaTargetSummary? target = null, bool merged = false) =>
        new(caller, "Ext.K(System.String)", capability, 4, call, target, merged);

    // Every kind of line: sites with and without a target, a merged one, the dropped line, gaps, a not-analysed folder, a
    // quiet folder, and a SameAs-style copy that lists nothing.
    private static ReachabilitySummary FullSummary() => new(
    [
        Folder("lib/net8.0", Ssa(
            sites:
            [
                Site("Own.Type.Run()", "System.Diagnostics.Process.Start(\"cmd.exe\", _)"),
                Site("Own.Boot()", "System.Reflection.MethodBase.Invoke(_, _)", Capability.ReflectionInvocation,
                    new SsaTargetSummary(SsaTargetKind.Method, "Method \"Own.Loader\" :: \"Run\"", ["Own.Loader.Run()"], 2, null), merged: true),
            ],
            dropped: 40,
            counts: Counts(analyzed: 42, methodUnknown: 3, unknown: [new(SsaFailureKind.UnresolvedFact, 1)]))),
        Folder("lib/net9.0", Ssa(counts: Counts(analyzed: 42, methodUnknown: 3, unknown: [new(SsaFailureKind.UnresolvedFact, 1)]))) with { SameAs = "lib/net8.0" },
        Folder("tools/net8.0/any", NotAnalysed(SsaFolderOutcome.TimedOut, "its SSA facts were not extracted within 60 s")),
        Folder("lib/netstandard2.0", Ssa()),
    ], 0, true);

    private static string Note(int incomplete, bool noSsaAnywhere = false) =>
        $"scan-package: SSA facts INCOMPLETE ({incomplete} folder(s) SSA did not fully analyse); " +
        (noSsaAnywhere ? "no folder has SSA facts; see the reachability section." : "see the report.");

    private static PackageItemRole RoleOf(string folder) =>
        folder.StartsWith("lib/", StringComparison.Ordinal) ? PackageItemRole.Lib
        : folder.StartsWith("tools/", StringComparison.Ordinal) ? PackageItemRole.Tools
        : PackageItemRole.Other;

    // An otherwise-clean report: vulnerabilities checked, YARA completed, no assemblies.
    private static PackageCapabilityReport Report() =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch,
            Array.Empty<AssemblyScanResult>(),
            Array.Empty<PackageScript>(),
            Array.Empty<ScriptFinding>(),
            VulnerabilitiesStatus: VulnerabilityScanStatus.Completed,
            YaraScanStatus: Silvergun.PackageAnalysis.NuGet.Yara.YaraScanStatus.Completed);
    #endregion

    #region Methods: console helpers
    private static List<string> Write(bool rich, ReachabilitySummary summary)
    {
        var (console, writer) = MakeConsole(rich, ansi: false);
        SsaSectionRenderer.Write(console, rich, summary);
        return Lines(writer);
    }

    private static List<string> Render(bool rich, PackageCapabilityReport report)
    {
        var (console, writer) = MakeConsole(rich, ansi: false);
        PackageReportRenderer.Render(console, report, "Some.Package.nupkg");
        return Lines(writer);
    }

    private static List<string> Lines(StringWriter writer)
    {
        var lines = writer.ToString().Split('\n').Select(l => l.TrimEnd('\r', ' ')).ToList();
        if (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);
        return lines;
    }

    private static (IAnsiConsole Console, StringWriter Writer) MakeConsole(bool rich, bool ansi)
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = ansi ? AnsiSupport.Yes : AnsiSupport.No,
            ColorSystem = ansi ? ColorSystemSupport.Standard : ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Capabilities.Unicode = rich;
        console.Profile.Width = 240;
        return (console, writer);
    }

    private static string Bullet(bool rich) => rich ? char.ConvertFromUtf32(0x00B7) : "-";
    #endregion

    #region Fields
    private const string Inject = "[red]x[/]";
    #endregion
}
