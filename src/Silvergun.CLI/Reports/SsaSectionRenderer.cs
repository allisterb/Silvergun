namespace Silvergun.CLI.Reports;

using System;
using System.Collections.Generic;
using System.Linq;

using Spectre.Console;

using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Graph;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// The <c>scan-package --reachability --ssa</c> section (<c>docs/agent/tasks/ssa-facts-s5.md</c> §4): sink sites whose
/// arguments or reflection targets SSA resolved, per folder, and what SSA did not analyse. SSA-derived and informational:
/// nothing here moves the exit code. Value signals are tagged on their sites (<c>docs/agent/tasks/recall-levers-1.md</c>
/// §2), a measured trigger with the alert glyph. Every summary string was escaped when the summary was built; here it is
/// only markup-escaped.
/// </summary>
internal static class SsaSectionRenderer
{
    #region Methods
    /// <summary>Writes the section for the folders of <paramref name="summary"/> that carry SSA facts.</summary>
    internal static void Write(IAnsiConsole console, bool rich, ReachabilitySummary summary)
    {
        console.Write(Section(rich, "Argument values (SSA-derived, informational; constants at sinks are common in benign packages)"));
        var folders = summary.Folders.Where(f => f.Ssa is not null).ToArray();
        var copies = folders.Count(IsCopy);
        console.MarkupLine(
            $"{folders.Sum(f => Resolved(f.Ssa!))} site(s) with resolved values in {folders.Count(f => Resolved(f.Ssa!) > 0)} folder(s); " +
            $"{Incomplete(summary)} folder(s) SSA-incomplete" + (copies > 0 ? $"; {copies} folder(s) are copies, listed under their primary" : string.Empty));

        foreach (var folder in folders.Where(f => IsCopy(f) || Resolved(f.Ssa!) > 0 || f.Ssa!.Incomplete()))
        {
            console.MarkupLine($"[bold]{Esc(folder.Folder.Length == 0 ? "(package)" : folder.Folder)}[/] [grey]({folder.Role})[/]");
            if (IsCopy(folder))
                console.MarkupLine($"  [grey]same files as {Esc(folder.SameAs)}; its sites are listed there[/]");
            foreach (var line in FolderLines(rich, folder.Ssa!))
                console.MarkupLine("  " + line);
        }
    }

    /// <summary>
    /// The one stderr line when SSA left any folder's sink sites unanalysed, or null. Called only when SSA was asked
    /// for, so a folder without SSA facts counts as incomplete.
    /// </summary>
    internal static string? IncompleteNote(ReachabilitySummary summary) =>
        Incomplete(summary) is var count and > 0
            ? $"scan-package: SSA facts INCOMPLETE ({count} folder(s) SSA did not fully analyse); " +
              (summary.Folders.Any(f => f.Ssa is not null) ? "see the report." : "no folder has SSA facts; see the reachability section.")
            : null;

    private static int Incomplete(ReachabilitySummary summary) => summary.Folders.Count(f => f.Ssa?.Incomplete() ?? true);

    // A SameAs copy whose sites are its primary's (SsaSummary lists none for it).
    private static bool IsCopy(FolderReachSummary folder) => folder.SameAs is not null && folder.Ssa?.Outcome == SsaFolderOutcome.Analyzed;

    private static int Resolved(FolderSsaSummary ssa) => (ssa.Sites?.Count ?? 0) + ssa.SitesDropped;

    private static IEnumerable<string> FolderLines(bool rich, FolderSsaSummary ssa)
    {
        var sites = (ssa.Sites ?? []).OfType<SsaSiteSummary>().ToArray();
        if ((ssa.Signals ?? []).OfType<SsaSignalCount>().ToArray() is { Length: > 0 } signals)
            yield return "value signals: " + string.Join(", ", signals.Select(s => $"{Mark(rich, s.Kind)}{s.Signal} ({s.Sites} site(s))"));
        foreach (var site in sites.Take(MaxSitesPerFolder))
        {
            var tags = (site.Signals ?? []).Select(s => $"{Mark(rich, SsaSummary.KindOf(s))}[[{s}]] ");
            yield return $"{string.Concat(tags)}{site.Capability}  {Esc(site.Call)}  [grey]in {Esc(site.Caller)}{(site.Merged ? " (merged definitions)" : string.Empty)}[/]";
            if (site.Target is { } target)
                yield return $"    [grey]acts on {Esc(target.Text)}{Esc(Candidates(target))}{Esc(target.CandidatesGap is { } gap ? $"; the search has gaps: {gap}" : string.Empty)}[/]";
        }
        if (sites.Length > MaxSitesPerFolder)
            yield return $"[grey]{Esc(Bullet(rich))} {sites.Length - MaxSitesPerFolder} more site(s) with resolved values in --json[/]";
        if (ssa.SitesDropped > 0)
            yield return $"[grey]{Esc(Bullet(rich))} {ssa.SitesDropped} more site(s) with resolved values, not listed (the summary's caps of " +
                         $"{SsaSummary.MaxSitesPerFolder} per folder and {SsaSummary.MaxSites} per package); not in --json either[/]";
        foreach (var gap in Gaps(ssa))
            yield return $"[yellow]SSA incomplete: {Esc(gap)}[/]";
    }

    // A trigger's alert glyph, as the reachability section marks one; nothing for information.
    private static string Mark(bool rich, ReachStatementKind kind) =>
        kind == ReachStatementKind.Trigger ? $"[red]{Esc(AlertGlyph(rich))}[/] " : string.Empty;

    private static string Candidates(SsaTargetSummary target) =>
        (target.CandidatesTotal, target.Candidates?.OfType<string>().ToArray() ?? []) switch
        {
            (<= 0, _) => string.Empty,
            (var total, []) => $" ({total} own candidate(s) by name; names not kept, the folder's text budget ran out)",
            (var total, var names) => $" ({total} own candidate(s) by name: {string.Join(", ", names)}{(total > names.Length ? ", ..." : string.Empty)})",
        };

    // What SSA did not analyse in one folder, each said plainly: an unanalysed site says nothing about its values.
    private static IEnumerable<string> Gaps(FolderSsaSummary ssa)
    {
        if (ssa.Outcome != SsaFolderOutcome.Analyzed || ssa.Counts is not { } c)
        {
            yield return $"not analysed: {ssa.Outcome}: {ssa.Reason ?? "no reason was given"}";
            yield break;
        }
        if (c.AssembliesLost > 0)
            yield return $"{c.AssembliesLost} assembly(ies) could not be read, so no method was lifted";
        if (c.MethodUnknown > 0)
            yield return $"{c.MethodUnknown} site(s) in methods that did not lift ({string.Join(", ", (c.Unknown ?? []).OfType<SsaFailureCount>().Select(u => $"{u.Kind} {u.Methods}"))})";
        if (c.NotJoined > 0)
            yield return $"{c.NotJoined} site(s) not found in the lifted code";
        if (c.NotRun > 0 || c.MethodBudget || c.TimeBudget)
            yield return (c.NotRun > 0 ? $"{c.NotRun} site(s) not reached: " : string.Empty) + $"the {(c.TimeBudget ? "time" : "method")} budget ran out";
        if (c.TextBudget)
            yield return "the folder's text budget ran out: later constants keep only their hash, and targets no candidate names";
        if (c.Truncated)
            yield return $"only the first {c.Analyzed + c.MethodUnknown + c.NotJoined + c.NotRun} of {c.SitesTotal} sink site(s) were examined";
    }
    #endregion

    #region Fields
    /// <summary>
    /// Sites listed per folder on the terminal; the rest of the summary's are in <c>--json</c> (user ruling,
    /// 2026-11-15: the corpus p95 was 341–458 lines at the summary's own cap).
    /// </summary>
    internal const int MaxSitesPerFolder = 10;
    #endregion
}
