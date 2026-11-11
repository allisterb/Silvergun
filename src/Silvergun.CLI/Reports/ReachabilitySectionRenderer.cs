namespace Silvergun.CLI.Reports;

using System;
using System.Collections.Generic;
using System.Linq;

using Spectre.Console;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// The <c>scan-package --reachability</c> section (<c>docs/agent/tasks/reachability-r3.md</c>, "The human section"):
/// a count line, then per folder its statements (triggers marked), notes, Unknown class verdicts, or why it was not
/// analysed. Informational: nothing here moves the exit code. Absent without the flag. Every summary string was escaped
/// when the summary was built (ADR 0031 decision 4); here it is only markup-escaped.
/// </summary>
internal static class ReachabilitySectionRenderer
{
    #region Methods
    /// <summary>Writes the section header and body for <paramref name="summary"/>.</summary>
    internal static void Write(IAnsiConsole console, bool rich, ReachabilitySummary summary)
    {
        console.Write(Section(rich, "Reachability (informational; does not affect the exit code)"));
        var statements = summary.Folders.SelectMany(f => f.Statements).ToArray();
        var triggers = statements.Count(s => s.Kind == ReachStatementKind.Trigger);
        console.MarkupLine(
            $"{triggers} trigger(s), {statements.Length - triggers} informational statement(s) in {summary.Folders.Count} folder(s); " +
            $"{NotAnalysed(summary)} folder(s) not analysed");

        foreach (var folder in summary.Folders.Where(HasAnythingToSay))
        {
            console.MarkupLine($"[bold]{Esc(FolderName(folder))}[/] [grey]({folder.Role})[/]");
            foreach (var line in FolderLines(rich, folder))
                console.MarkupLine("  " + line);
        }

        if (summary.StatementsDropped > 0)
            console.MarkupLine(
                $"[yellow]{summary.StatementsDropped} further statement(s) were not kept (the summary's cap of {ReachabilitySummary.MaxStatements}, " +
                "triggers kept first); they are not in --json either[/]");
    }

    /// <summary>Folders not analysed (<see cref="IsNotAnalysed"/>).</summary>
    internal static int NotAnalysed(ReachabilitySummary summary) => summary.Folders.Count(IsNotAnalysed);

    /// <summary>Unknown verdicts of presented classes in the analysed folders: the ones the section lists.</summary>
    internal static int UnknownVerdicts(ReachabilitySummary summary) =>
        summary.Folders.Where(f => !IsNotAnalysed(f)).Sum(f => f.Classes.Count(c => c.Verdict == RootClassVerdict.Unknown));

    /// <summary>
    /// The one stderr line for a pass that did not come out decided, or null. Decided from the folders as well as the
    /// stored <see cref="ReachabilitySummary.Complete"/>, which a crafted report could set (S1 review N2).
    /// </summary>
    internal static string? IncompleteNote(ReachabilitySummary summary) =>
        (NotAnalysed(summary), UnknownVerdicts(summary)) is var (notAnalysed, unknown)
        && (!summary.Complete || notAnalysed + unknown > 0)
            ? $"scan-package: reachability INCOMPLETE ({notAnalysed} folder(s) not analysed, {unknown} class verdict(s) Unknown); see the report."
            : null;

    // Not analysed: a reason (an Analyzed folder without a report has one, S0 test findings), or an outcome other than
    // Analyzed even without one, which only a crafted report could carry (S2 review N2).
    private static bool IsNotAnalysed(FolderReachSummary folder) => folder.Reason is not null || folder.Outcome != FolderOutcome.Analyzed;

    // The markup lines under one folder: why it was not analysed, or its statements, notes and Unknown verdicts.
    private static IEnumerable<string> FolderLines(bool rich, FolderReachSummary folder)
    {
        if (IsNotAnalysed(folder))
            return [$"[yellow]{Esc(AlertGlyph(rich))} not analysed{(folder.Outcome == FolderOutcome.Analyzed ? "" : $": {folder.Outcome}")}: {Esc(folder.Reason ?? "no reason was given")}[/]"];
        if (folder.SameAs is { } sameAs)
            return [$"[grey]same files as {Esc(sameAs)}[/]"];
        return
        [
            .. folder.Statements.SelectMany(s => StatementLines(rich, s)),
            .. folder.Notes.Select(n => $"[grey]{Esc(Bullet(rich))} {Esc(n)}[/]"),
            .. folder.Classes.Where(c => c.Verdict == RootClassVerdict.Unknown).SelectMany(c =>
                c.Reasons.Select(r => $"    [grey]{Esc(r)}[/]").Prepend($"[yellow]{c.Class}: Unknown[/]")),
        ];
    }

    // A statement, and its example path on the next line when it has one.
    private static IEnumerable<string> StatementLines(bool rich, ReachStatement statement)
    {
        var mark = statement.Kind == ReachStatementKind.Trigger ? $"[red]{Esc(AlertGlyph(rich))}[/]" : $"[grey]{Esc(Bullet(rich))}[/]";
        yield return $"{mark} {Esc(statement.Text)} [grey]({statement.Roots} root(s))[/]";
        if (statement.Example is { } example)
            yield return $"    [grey]{Esc(Path(rich, example))}[/]";
    }

    // The example's hops joined by an arrow, the hidden ones marked between the first and the last two.
    private static string Path(bool rich, ReachExample example)
    {
        var hops = example.Hops.ToList();
        if (example.HiddenHops > 0)
            hops.Insert(Math.Max(0, hops.Count - 2), rich ? $"…{example.HiddenHops} more…" : $"...{example.HiddenHops} more...");
        var path = string.Join(rich ? " → " : " -> ", hops);
        return example.Unseen is { } unseen ? $"{path} (ends in {unseen})" : path;
    }

    // Whether a folder has a line to show: a quiet, fully decided folder is counted in the summary line only.
    private static bool HasAnythingToSay(FolderReachSummary folder) =>
        IsNotAnalysed(folder) || folder.SameAs is not null || folder.Statements.Count > 0 || folder.Notes.Count > 0
        || folder.Classes.Any(c => c.Verdict == RootClassVerdict.Unknown);

    // A whole-pass failure has no folder name (ReachabilitySummary.Failed).
    private static string FolderName(FolderReachSummary folder) => folder.Folder.Length == 0 ? "(package)" : folder.Folder;
    #endregion
}
