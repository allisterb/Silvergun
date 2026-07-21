namespace Silvergun.CLI.Reports;

using System;
using System.Globalization;
using System.Linq;

using Spectre.Console;
using Spectre.Console.Rendering;

using Silvergun.Intel;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// Renders the shared "Project Health" section (ADR 0015), reused by the <c>health</c> verb
/// (<see cref="HealthReportRenderer"/>) and the <c>scan-package --health</c> report
/// (<see cref="PackageReportRenderer"/>): overall score + band (band-colored in rich), the three sub-scores as a
/// Spectre <see cref="BarChart"/> (rich) or OSSGadget-style <c>*</c>-bars (default ASCII), <c>owner/repo</c>, key
/// raw stats, and any <see cref="ProjectHealth.RedFlags"/> prominently. Advisory only; all untrusted data is escaped
/// via <see cref="ReportTheme.Esc"/>. Static widgets only.
/// </summary>
internal static class HealthSectionRenderer
{
    #region Methods
    /// <summary>
    /// Writes the section header and body. When <paramref name="health"/> is <c>null</c> an "unavailable (reason)"
    /// line is shown (with <paramref name="repo"/> when it resolved); otherwise the full scored view is rendered.
    /// </summary>
    internal static void Write(IAnsiConsole console, bool rich, ProjectHealth? health, RepositoryRef? repo, string? unavailableReason)
    {
        console.Write(Section(rich, "Project Health"));

        if (repo is not null)
            console.MarkupLine($"[grey]Repository[/]  [bold]{Esc(repo.Owner)}/{Esc(repo.Repo)}[/]");

        if (health is null)
        {
            var reason = string.IsNullOrWhiteSpace(unavailableReason) ? "no GitHub repository resolved" : unavailableReason;
            console.MarkupLine($"[yellow]Health unavailable[/] [grey]({Esc(reason)})[/]");
            return;
        }

        var bandColor = BandColor(health.Band);
        console.MarkupLine(
            $"[grey]Overall[/]    [bold {bandColor}]{health.OverallScore}/100[/] [grey]{Dash(rich)}[/] [{bandColor}]{health.Band}[/]");
        console.WriteLine();

        console.Write(SubScores(rich, health));
        console.WriteLine();

        console.MarkupLine(Stats(health));

        if (health.RedFlags.Count > 0)
            console.MarkupLine(
                $"[bold red]{Esc(AlertGlyph(rich))} Red flags:[/] [red]{string.Join(", ", health.RedFlags.Select(Esc))}[/]");
        else
            console.MarkupLine($"[green]{Esc(CleanGlyph(rich))} No red flags.[/]");
    }

    // Rich: a Spectre BarChart. Default: ASCII '*'-bars in a Grid (OSSGadget-style), so plain output stays ASCII-only.
    private static IRenderable SubScores(bool rich, ProjectHealth h) =>
        rich
            ? new BarChart()
                .Width(BarWidth * 3)
                .Label("[grey]Sub-scores[/]")
                .AddItem("Activity", h.ActivityScore, Color.Aqua)
                .AddItem("Popularity", h.PopularityScore, Color.Green)
                .AddItem("Maturity", h.MaturityScore, Color.Yellow)
            : AsciiBars(h);

    private static IRenderable AsciiBars(ProjectHealth h)
    {
        var grid = new Grid();
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn();
        grid.AddRow("Activity", Esc(AsciiBar(h.ActivityScore)), h.ActivityScore.ToString(CultureInfo.InvariantCulture));
        grid.AddRow("Popularity", Esc(AsciiBar(h.PopularityScore)), h.PopularityScore.ToString(CultureInfo.InvariantCulture));
        grid.AddRow("Maturity", Esc(AsciiBar(h.MaturityScore)), h.MaturityScore.ToString(CultureInfo.InvariantCulture));
        return grid;
    }

    // A fixed-width '*'-filled bar scaling a 0–100 score to 0–BarWidth cells (brackets are escaped by the caller).
    private static string AsciiBar(int score)
    {
        var filled = (int)Math.Round(Math.Clamp(score, 0, 100) / 100.0 * BarWidth, MidpointRounding.AwayFromZero);
        return "[" + new string('*', filled) + new string(' ', BarWidth - filled) + "]";
    }

    private static string Stats(ProjectHealth h) =>
        $"[grey]Stars[/] {Num(h.Stars)}   [grey]Forks[/] {Num(h.Forks)}   [grey]Last push[/] {Esc(Date(h.PushedAt))}" +
        (h.License is null ? string.Empty : $"   [grey]License[/] {Esc(h.License)}");

    private static string Num(int? value) => value?.ToString("N0", CultureInfo.InvariantCulture) ?? "?";

    private static string Date(DateTimeOffset? value) =>
        value?.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "?";

    // Band color mirrors the severity palette: green (healthy) → red (poor).
    private static string BandColor(HealthBand band) => band switch
    {
        HealthBand.Healthy => "green",
        HealthBand.Moderate => "yellow",
        HealthBand.Low => "orange1",
        HealthBand.Poor => "red",
        _ => "silver",
    };
    #endregion

    #region Fields
    private const int BarWidth = 20;   // ASCII/rich bar width in cells (0–100 → 0–BarWidth)
    #endregion
}
