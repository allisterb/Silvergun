namespace Silvergun.CLI.Reports;

using Spectre.Console;

using Silvergun.Intel;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// Renders a <see cref="ProjectHealthReport"/> (the <c>health</c> verb) as a Spectre report: a package-identity line
/// followed by the shared "Project Health" section (<see cref="HealthSectionRenderer"/>). Advisory only; static
/// widgets only. All untrusted data is escaped via <see cref="ReportTheme.Esc"/>.
/// </summary>
internal static class HealthReportRenderer
{
    #region Methods
    internal static void Render(IAnsiConsole console, ProjectHealthReport report)
    {
        var rich = IsRich(console);

        console.Write(Header(rich, "health"));
        console.WriteLine();
        console.MarkupLine($"[grey]Package[/]  [bold]{Esc(report.PackageId)}[/]");
        console.WriteLine();

        HealthSectionRenderer.Write(console, rich, report.Health, report.Repository, report.UnavailableReason);
    }
    #endregion
}
