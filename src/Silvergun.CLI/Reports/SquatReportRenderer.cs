namespace Silvergun.CLI.Reports;

using Spectre.Console;

using Silvergun.PackageAnalysis.NuGet.Squats;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// Renders a <see cref="SquatCheckReport"/> (the <c>check-squat</c> verb) as a Spectre report: a package-identity
/// line, a findings table (candidate + reputation axes + mutator/reason), and a qualitative footer (ADR 0013).
/// Static widgets only.
/// </summary>
internal static class SquatReportRenderer
{
    #region Methods
    internal static void Render(IAnsiConsole console, SquatCheckReport report)
    {
        var rich = IsRich(console);

        console.Write(Header(rich, "check-squat"));
        console.WriteLine();
        console.MarkupLine($"[grey]Package[/]  [bold]{Esc(report.PackageId)}[/]");
        console.WriteLine();

        console.Write(Section(rich, "Typosquat findings"));
        if (report.Findings.Count == 0)
        {
            console.MarkupLine("[green]No likely typosquat targets found.[/]");
            return;
        }

        console.Write(FindingsTable(rich, report.Findings));
        console.WriteLine();
        console.Write(Section(rich, "Assessment"));
        console.MarkupLine($"[bold red]{Esc(AlertGlyph(rich))} {report.Findings.Count} likely typosquat target(s)[/] [grey]{Dash(rich)} review before installing.[/]");
    }

    private static Table FindingsTable(bool rich, IReadOnlyList<SquatFinding> findings)
    {
        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Popular candidate[/]");
        table.AddColumn("[bold]Reputation[/]");
        table.AddColumn("[bold]Mutator[/]");
        table.AddColumn("[bold]Reason[/]");

        foreach (var f in findings)
            table.AddRow(
                $"[bold]{Esc(f.SquattedCandidate)}[/]",
                Esc(Reputation(f)),
                $"[orange1]{Esc(f.Mutator.ToString())}[/]",
                Esc(f.Reason));

        return table;
    }

    // Prefer the libraries.io reputation axes when present, else fall back to raw download counts.
    private static string Reputation(SquatFinding f)
    {
        if (f.CandidateSourceRank is not null || f.CandidateDependents is not null)
            return $"SourceRank {f.CandidateSourceRank?.ToString() ?? "?"}, " +
                   $"dependents {f.CandidateDependents?.ToString() ?? "?"} " +
                   $"(candidate) vs target dependents";

        return $"{f.CandidateDownloads:N0} dl (candidate) vs {f.TargetDownloads:N0} dl (target)";
    }
    #endregion
}
