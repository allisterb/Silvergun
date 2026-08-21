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

        // Capability manifest (capability-manifest-reframe task): what this assembly CAN do, as an inventory
        // alongside the findings table above — not merged into it. All 11 Capability values, present or absent, in
        // enum order. Presentation only; does not change what --strict gates on (see the note it prints).
        console.Write(Section(rich, "Capability manifest"));
        console.Write(CapabilityManifest(caps.Findings));
        console.MarkupLine(CapabilityGateNote(rich));
        console.WriteLine();

        console.Write(Section(rich, "Obfuscation"));
        console.Write(ObfuscationWidget(rich, report.Obfuscation));
        console.WriteLine();

        console.Write(Section(rich, "Indicators"));
        console.Write(IndicatorsWidget(rich, report.Indicators));
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

    // Indicator (network / sensitive-target) findings — selective by design (ADR from indicator-prevalence
    // measurement, see the task spec): ALWAYS a per-category count summary, every category including zero, plus
    // full detail rows for only the discriminating categories (IsDiscriminatingIndicatorCategory). Truncated is
    // rendered as a visible caveat wherever indicator counts appear — the findings are a floor, not a total.
    private static IRenderable IndicatorsWidget(bool rich, IndicatorReport? indicators)
    {
        if (indicators is null)
            return new Markup("[grey](unavailable)[/]");

        var widgets = new List<IRenderable> { IndicatorCountSummary(indicators.Findings) };

        var detail = indicators.Findings.Where(f => IsDiscriminatingIndicatorCategory(f.Category)).ToArray();
        if (detail.Length > 0)
            widgets.Add(IndicatorDetailTable(rich, detail));

        if (indicators.Truncated)
            widgets.Add(new Markup(
                $"[yellow]{Esc(AlertGlyph(rich))} indicator analysis TRUNCATED {Dash(rich)} " +
                "the distinct-indicator cap was reached; these findings are a FLOOR, not a total[/]"));

        return new Rows(widgets);
    }

    // Detail rows for the discriminating indicator categories only (the counts-only categories never reach here).
    private static Table IndicatorDetailTable(bool rich, IReadOnlyList<IndicatorFinding> findings)
    {
        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Category[/]");
        table.AddColumn("[bold]Value[/]");
        table.AddColumn("[bold]Caller[/]");
        table.AddColumn("[bold]Occurrences[/]");
        table.AddColumn("[bold]Excerpt[/]");

        foreach (var f in findings)
            table.AddRow(
                $"[red]{Esc(f.Category.ToString())}[/]",
                Esc(f.Value),
                Esc($"{f.CallerType}.{f.CallerMethod}"),
                f.Occurrences.ToString(),
                Esc(f.Excerpt));

        return table;
    }

    // Qualitative footer: colored per-capability counts, obfuscation count, the IL coverage line, and the three-tier
    // Findings / Not verified / Clean headline. "Attention" is DELIBERATELY WIDER than the --strict gate (ARCHITECT
    // DECISION 2026-08-03): the headline also fires on the seven discriminating indicator categories
    // (IsDiscriminatingIndicatorCategory) so a CallbackDomain-only assembly cannot print "Clean" with the callback
    // domain listed in the section above it. As of ADR 0026, the gate (Program.AnalyzeExitCode) keys on capability OR
    // obfuscation findings OR one of three gating indicator categories (CallbackDomain, DynamicDns, CredentialPath —
    // IsGatingIndicatorCategory); the remaining four discriminating categories, and every counts-only category,
    // still never affect the exit code — "attention" stays the wider set. "Not verified" comes from the SHARED
    // CompletenessAssessment the exit code uses
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

        // The seven discriminating categories (the same split IndicatorsWidget renders as detail rows,
        // IsDiscriminatingIndicatorCategory) set "attention" below — ARCHITECT DECISION 2026-08-03: a
        // CallbackDomain-only finding must not print "Clean" while the callback domain sits in the section right
        // above it. The noisy categories (ReflectionTypeName/GenericUrl/PrivateIpLiteral) stay excluded from
        // attention. As of ADR 0026, three of the seven (CallbackDomain, DynamicDns, CredentialPath —
        // IsGatingIndicatorCategory) ALSO gate --strict via Program.AnalyzeExitCode; this "attention" count still
        // counts all seven, since attention is always the wider set (see the Footer-level note above). Truncated is
        // still surfaced here as a visible caveat: "could not analyse everything" must never read as a clean result.
        var indicatorCount = report.Indicators?.Findings.Count ?? 0;
        var discriminatingIndicatorCount = report.Indicators?.Findings
            .Count(f => IsDiscriminatingIndicatorCategory(f.Category)) ?? 0;
        console.MarkupLine(indicatorCount == 0
            ? "[grey]Indicators:[/] [green]none[/]"
            : $"[grey]Indicators:[/] [orange1]{indicatorCount} finding(s)[/], {discriminatingIndicatorCount} discriminating" +
              (discriminatingIndicatorCount < indicatorCount ? " [grey](see breakdown above)[/]" : string.Empty) +
              (report.Indicators!.Truncated ? " [yellow](truncated - floor, not a total)[/]" : string.Empty));

        var assessment = CompletenessAssessment.ForAssembly(report);
        CompletenessFooter.WriteCoverage(console, assessment);

        var attention = findings.Count > 0 || obfuscationCount > 0 || discriminatingIndicatorCount > 0;
        CompletenessFooter.WriteHeadline(
            console, rich, attention, assessment,
            "no sensitive-API, obfuscation, or discriminating-indicator findings.");
    }
    #endregion
}
