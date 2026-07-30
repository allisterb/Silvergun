namespace Silvergun.CLI.Reports;

using Spectre.Console;
using Spectre.Console.Rendering;

using Silvergun.CodeAnalysis.IL;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// Renders an <see cref="AssemblyAnalysisReport"/> (the <c>analyze</c> verb) as a sectioned Spectre report:
/// an identity/metadata grid, a capability table grouped by <see cref="Capability"/>, an obfuscation table,
/// and a qualitative assessment footer (ADR 0013). Static widgets only — never interactive/live components.
/// </summary>
internal static class AssemblyReportRenderer
{
    #region Methods
    internal static void Render(IAnsiConsole console, AssemblyAnalysisReport report)
    {
        var rich = IsRich(console);
        var caps = report.Capabilities;

        console.Write(Header(rich, "analyze"));
        console.WriteLine();
        console.Write(IdentityGrid(caps));
        console.WriteLine();

        console.Write(Section(rich, "Metadata"));
        console.Write(MetadataWidget(report.Metadata));
        console.WriteLine();

        console.Write(Section(rich, "Capabilities"));
        if (caps.Findings.Count == 0)
            console.MarkupLine("[green]No sensitive-API findings.[/]");
        else
            console.Write(CapabilityTable(rich, caps.Findings));
        console.WriteLine();

        console.Write(Section(rich, "Obfuscation"));
        console.Write(ObfuscationWidget(rich, report.Obfuscation));
        console.WriteLine();

        console.Write(Section(rich, "Assessment"));
        Footer(console, rich, report);
    }

    private static Grid IdentityGrid(CapabilityReport caps)
    {
        var grid = new Grid();
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn();
        grid.AddRow("[grey]Assembly[/]", $"[bold]{Esc(caps.AssemblyName)}[/]");
        grid.AddRow("[grey]Path[/]", Esc(caps.AssemblyPath));
        grid.AddRow("[grey]Findings[/]", caps.Findings.Count.ToString());
        return grid;
    }

    private static IRenderable MetadataWidget(AssemblyMetadataInfo? m)
    {
        if (m is null)
            return new Markup("[grey](unavailable)[/]");

        var resolved = m.References.Count(r => r.Resolved);
        var grid = new Grid();
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn();
        grid.AddRow("[grey]Name/Version[/]", $"{Esc(m.Name)} {Esc(m.Version ?? "?")}");
        grid.AddRow("[grey]Strong-named[/]", $"{YesNo(m.IsStrongNameSigned)}  [grey](PKT {Esc(m.PublicKeyToken ?? "none")})[/]");
        grid.AddRow("[grey]IL-only[/]",
            $"{YesNo(m.IsILOnly)}  [grey](32-bit {YN(m.Requires32Bit)}  64-bit {YN(m.Requires64Bit)}  AMD {YN(m.RequiresAmdInstructionSet)}  foreign-types {YN(m.ContainsForeignTypes)})[/]");
        grid.AddRow("[grey]Module kind[/]", Esc(m.ModuleKind));
        grid.AddRow("[grey]Target runtime[/]", Esc(m.TargetRuntimeVersion ?? "?"));
        grid.AddRow("[grey]Entry point[/]", YesNo(m.HasEntryPoint));
        grid.AddRow("[grey]Attributes[/]", m.CustomAttributes.Count.ToString());
        grid.AddRow("[grey]References[/]", $"{m.References.Count} [grey]({resolved} resolved)[/]");
        return grid;
    }

    // Capability findings as one table, grouped/sorted by capability with the capability cell colored.
    private static Table CapabilityTable(bool rich, IReadOnlyList<ApiCallFinding> findings)
    {
        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Capability[/]");
        table.AddColumn("[bold]Kind[/]");
        table.AddColumn("[bold]Caller[/]");
        table.AddColumn("[bold]Called API[/]");

        foreach (var group in findings.GroupBy(f => f.Capability).OrderBy(g => g.Key.ToString()))
            foreach (var f in group)
                table.AddRow(
                    Colored(f.Capability, Esc(f.Capability.ToString())),
                    Esc(f.Kind.ToString()),
                    Esc($"{f.CallerType}.{f.CallerMethod}"),
                    Esc(f.CalledApi));

        return table;
    }

    private static IRenderable ObfuscationWidget(bool rich, ObfuscationReport? obfuscation)
    {
        var findings = obfuscation?.Findings;
        if (findings is null || findings.Count == 0)
            return new Markup("[green](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Kind[/]");
        table.AddColumn("[bold]Detected as[/]");
        table.AddColumn("[bold]Caller[/]");
        table.AddColumn("[bold]Len[/]");
        table.AddColumn("[bold]Entropy[/]");

        foreach (var f in findings)
            table.AddRow(
                $"[orange1]{Esc(f.Kind.ToString())}[/]",
                Esc(f.DetectedAs),
                Esc($"{f.CallerType}.{f.CallerMethod}"),
                f.EncodedLength.ToString(),
                f.Entropy.ToString("F2"));

        return table;
    }

    // Qualitative footer: colored per-capability counts, obfuscation count, the IL coverage line, and the three-tier
    // Findings / Not verified / Clean headline. "Attention" is exactly what the --strict gate keys on (capability OR
    // obfuscation findings present); "not verified" comes from the SHARED CompletenessAssessment the exit code uses
    // (ADR 0024) — so a run that skipped methods, or whose obfuscation analysis failed, can never read "Clean".
    private static void Footer(IAnsiConsole console, bool rich, AssemblyAnalysisReport report)
    {
        var findings = report.Capabilities.Findings;
        var obfuscationCount = report.Obfuscation?.Findings.Count ?? 0;

        if (findings.Count == 0)
            console.MarkupLine("[grey]Capabilities:[/] [green]none[/]");
        else
        {
            var groups = findings.GroupBy(f => f.Capability).OrderBy(g => g.Key.ToString())
                .Select(g => Colored(g.Key, $"{g.Count()} {g.Key}"));
            console.MarkupLine($"[grey]Capabilities:[/] {string.Join($"  [grey]{Bullet(rich)}[/]  ", groups)}");
        }

        console.MarkupLine(obfuscationCount == 0
            ? "[grey]Obfuscation:[/] [green]none[/]"
            : $"[grey]Obfuscation:[/] [orange1]{obfuscationCount} finding(s)[/]");

        var assessment = CompletenessAssessment.ForAssembly(report);
        CompletenessFooter.WriteCoverage(console, assessment);

        var attention = findings.Count > 0 || obfuscationCount > 0;
        CompletenessFooter.WriteHeadline(
            console, rich, attention, assessment, "no sensitive-API or obfuscation findings.");
    }
    #endregion
}
