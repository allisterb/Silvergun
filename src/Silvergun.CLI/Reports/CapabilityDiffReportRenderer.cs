namespace Silvergun.CLI.Reports;

using Spectre.Console;

using Silvergun.CodeAnalysis.IL;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// Renders a <see cref="CapabilityDiffOutcome"/> (the <c>capability-diff</c> verb) as a sectioned Spectre report
/// (ADR 0013): added capabilities (the headline), removed capabilities, count changes (visually subordinate to
/// added/removed), assemblies added/removed and target frameworks added/dropped (their own sections — trap 3 and
/// its 2026-08-20 composite-key correction), and a completeness / assessment footer that never lets an incomplete
/// side read as a clean delta (trap 1). Static widgets only — never interactive/live.
/// <para>
/// All names/paths rendered here (assembly names, target frameworks) come from the snapshot FILES the user handed
/// in — untrusted content, exactly like a package's own metadata elsewhere in these renderers — so every one passes
/// through <see cref="Esc"/> before reaching Spectre markup.
/// </para>
/// </summary>
internal static class CapabilityDiffReportRenderer
{
    #region Methods
    internal static void Render(IAnsiConsole console, CapabilityDiffOutcome outcome, string baselinePath, string candidatePath)
    {
        var rich = IsRich(console);
        var diff = outcome.Diff;

        console.Write(Header(rich, "capability-diff"));
        console.WriteLine();
        console.MarkupLine($"[grey]Baseline[/]  {Esc(baselinePath)}");
        console.MarkupLine($"[grey]Candidate[/] {Esc(candidatePath)}");
        console.WriteLine();

        // Vacuous-diff trap (repurposed trap 2, 2026-08-20): once overridden (--allow-tfm-mismatch), nothing
        // matched between the two files at all, so every section below can only ever show structural changes
        // (assemblies/target frameworks added or dropped) — there is no shared (assembly, TFM) pair left to run a
        // capability comparison over.
        if (outcome.VacuousDiffOverridden)
        {
            console.MarkupLine(
                $"[yellow]{Esc(AlertGlyph(rich))} NOTHING MATCHED[/] [grey]{Dash(rich)} no (assembly, target " +
                $"framework) pair is present in both files (--allow-tfm-mismatch given); no capability comparison " +
                $"was possible — sections below can only show structural changes.[/]");
            console.WriteLine();
        }

        console.Write(Section(rich, "Added capabilities"));
        WriteCapabilityChanges(console, diff, added: true);
        console.WriteLine();

        console.Write(Section(rich, "Removed capabilities"));
        WriteCapabilityChanges(console, diff, added: false);
        console.WriteLine();

        if (diff.AssemblyDiffs.Any(d => d.CountChanges.Count > 0))
        {
            console.Write(Section(rich, "Count changes"));
            WriteCountChanges(console, diff);
            console.WriteLine();
        }

        if (diff.AssembliesAdded.Count > 0 || diff.AssembliesRemoved.Count > 0)
        {
            console.Write(Section(rich, "Assemblies added / removed"));
            foreach (var name in diff.AssembliesAdded)
                console.MarkupLine($"[green]+[/] {Esc(name)}");
            foreach (var name in diff.AssembliesRemoved)
                console.MarkupLine($"[red]-[/] {Esc(name)}");
            console.WriteLine();
        }

        if (diff.HasTargetFrameworkChange)
        {
            console.Write(Section(rich, "Target frameworks added / dropped"));
            foreach (var entry in diff.TargetFrameworksAdded)
                console.MarkupLine($"[green]+[/] {Esc(entry)}");
            foreach (var entry in diff.TargetFrameworksDropped)
                console.MarkupLine($"[red]-[/] {Esc(entry)}");
            console.WriteLine();
        }

        console.Write(Section(rich, "Assessment"));
        Footer(console, rich, outcome);
    }

    // Added/removed capabilities are the headline — one line per (assembly, TFM, capability), colored by
    // capability. The TFM is always shown alongside the name: a multi-targeted package can have several diffs
    // sharing one AssemblyName (composite-key match, 2026-08-20 correction), so the name alone would be ambiguous.
    private static void WriteCapabilityChanges(IAnsiConsole console, CapabilityDiffReport diff, bool added)
    {
        var rows = diff.AssemblyDiffs
            .SelectMany(d => (added ? d.Added : d.Removed).Select(capability => (d.AssemblyName, d.TargetFramework, Capability: capability)))
            .ToArray();

        if (rows.Length == 0)
        {
            console.MarkupLine($"[green]No capabilities {(added ? "added" : "removed")}.[/]");
            return;
        }

        var glyph = added ? "[green]+[/]" : "[red]-[/]";
        foreach (var (assemblyName, targetFramework, capability) in rows)
            console.MarkupLine($"{glyph} {AssemblyLabel(assemblyName, targetFramework)}: {Colored(capability, Esc(capability.ToString()))}");
    }

    // Visually subordinate to added/removed by design (plain grey, no capability color): a count moving 3 -> 40 is
    // interesting, 3 -> 4 probably is not, so this section stays quiet and never gates the exit code.
    private static void WriteCountChanges(IAnsiConsole console, CapabilityDiffReport diff)
    {
        foreach (var assemblyDiff in diff.AssemblyDiffs)
            foreach (var change in assemblyDiff.CountChanges)
                console.MarkupLine(
                    $"[grey]{AssemblyLabel(assemblyDiff.AssemblyName, assemblyDiff.TargetFramework)}: {Esc(change.Capability.ToString())} " +
                    $"{change.BaselineCount} -> {change.CandidateCount}[/]");
    }

    // "AssemblyName (tfm)", Esc'd — the shared label for a matched (assembly, TFM) pair across the capability
    // sections above. "(unknown)" mirrors CapabilityDiffReport's own fallback for a null TFM (a bare analyze
    // --snapshot).
    private static string AssemblyLabel(string assemblyName, string? targetFramework) =>
        $"{Esc(assemblyName)} ({Esc(targetFramework ?? "(unknown)")})";

    // Trap 1, rendered: an incomplete side is ALWAYS disclosed (even when real changes were found — findings still
    // win the headline, exactly like the analyze/scan-package footers), and when there is otherwise nothing to
    // report, the reassuring "no capability changes" line is replaced with a plain refusal instead of printing it.
    private static void Footer(IAnsiConsole console, bool rich, CapabilityDiffOutcome outcome)
    {
        var diff = outcome.Diff;

        if (!outcome.BaselineComplete)
            console.MarkupLine(
                $"[yellow]{Esc(AlertGlyph(rich))} Baseline scan INCOMPLETE[/] [grey]{Dash(rich)} " +
                $"{Esc(string.Join("; ", outcome.BaselineCaveats))}[/]");
        if (!outcome.CandidateComplete)
            console.MarkupLine(
                $"[yellow]{Esc(AlertGlyph(rich))} Candidate scan INCOMPLETE[/] [grey]{Dash(rich)} " +
                $"{Esc(string.Join("; ", outcome.CandidateCaveats))}[/]");

        if (!diff.HasAnyChange)
        {
            console.MarkupLine(outcome.IsIncomplete
                ? $"[yellow]{Esc(AlertGlyph(rich))} Cannot compare[/] [grey]{Dash(rich)} the scan was incomplete on " +
                  "one or both sides; a clean result cannot be trusted.[/]"
                : $"[bold green]{Esc(CleanGlyph(rich))} No capability changes.[/] [grey]{Dash(rich)} both scans were complete.[/]");
            return;
        }

        console.MarkupLine(diff.HasAddedCapabilities
            ? $"[bold red]{Esc(AlertGlyph(rich))} {diff.AssemblyDiffs.Sum(d => d.Added.Count)} capability(ies) added[/] " +
              $"[grey]{Dash(rich)} review recommended.[/]"
            : "[grey]No capabilities added.[/]");
    }
    #endregion
}
