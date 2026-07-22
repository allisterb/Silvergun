namespace Silvergun.CLI.Reports;

using Spectre.Console;
using Spectre.Console.Rendering;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using static Silvergun.CLI.Reports.ReportTheme;

/// <summary>
/// Renders a <see cref="PackageCapabilityReport"/> (the <c>scan-package</c> verb) as a sectioned Spectre report:
/// a package-identity panel, a declared-dependencies table, a script-findings table (which already folds in
/// nuspec findings via the shared <see cref="ScriptFinding"/> list), a per-assembly section, and a qualitative
/// footer mirroring the count summary (ADR 0013). Static widgets only.
/// </summary>
internal static class PackageReportRenderer
{
    #region Methods
    internal static void Render(IAnsiConsole console, PackageCapabilityReport report, string nupkgPath)
    {
        var rich = IsRich(console);
        var pkg = report.Package;

        console.Write(Header(rich, "scan-package"));
        console.WriteLine();
        console.Write(IdentityPanel(rich, pkg, nupkgPath));
        console.WriteLine();

        console.Write(Section(rich, "Declared dependencies"));
        console.Write(DependenciesWidget(rich, pkg.Dependencies));
        console.WriteLine();

        if (report.Scripts.Count > 0)
        {
            console.Write(Section(rich, "Packaged scripts"));
            console.Write(ScriptsWidget(rich, report.Scripts));
            console.WriteLine();
        }

        console.Write(Section(rich, "Script findings"));
        console.Write(ScriptFindingsWidget(rich, report.ScriptFindings));
        console.WriteLine();

        // Malware-signature (YARA) hits are the highest-signal section (named-family IOCs, ADR 0016) — render it
        // prominently. Rendered consistently with Script findings (a green "(none)" when clean).
        console.Write(Section(rich, "Malware signatures (YARA)"));
        console.Write(YaraFindingsWidget(rich, report.YaraFindings));
        console.WriteLine();

        // Known-vulnerability (OSV.dev) hits are concrete, actionable IOCs (ADR 0017) — render prominently, like YARA.
        // Attached only when the OSV check ran (default; skipped under --no-vulns) — a green "(none)" when it ran clean.
        console.Write(Section(rich, "Known vulnerabilities (OSV)"));
        console.Write(VulnerabilitiesWidget(rich, report.Vulnerabilities));
        console.WriteLine();

        console.Write(Section(rich, "Assemblies"));
        console.Write(AssembliesTree(rich, report.Assemblies));
        console.WriteLine();

        // Opt-in project-health section (scan-package --health, ADR 0015); present only when health was attached.
        // Advisory only — it never influences the Assessment/exit-code contract.
        if (report.ProjectHealth is { } health)
        {
            HealthSectionRenderer.Write(console, rich, health, health.Repository, unavailableReason: null);
            console.WriteLine();
        }

        console.Write(Section(rich, "Assessment"));
        Footer(console, rich, report);
    }

    private static Panel IdentityPanel(bool rich, PackageIdentityInfo pkg, string nupkgPath)
    {
        var grid = new Grid();
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn();
        grid.AddRow("[grey]Package[/]", $"[bold]{Esc(pkg.Id)}[/] {Esc(pkg.Version)}");
        grid.AddRow("[grey]Authors[/]", Esc(pkg.Authors ?? "(unknown)"));
        grid.AddRow("[grey]Path[/]", Esc(nupkgPath));
        if (!string.IsNullOrWhiteSpace(pkg.Description))
            grid.AddRow("[grey]Description[/]", Esc(pkg.Description));

        return new Panel(grid).Header("[bold]Package[/]").Border(BoxBorderFor(rich)).Expand();
    }

    private static IRenderable DependenciesWidget(bool rich, IReadOnlyList<PackageDependencyInfo> dependencies)
    {
        if (dependencies.Count == 0)
            return new Markup("[grey](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Dependency[/]");
        table.AddColumn("[bold]Version range[/]");
        table.AddColumn("[bold]Target framework[/]");
        foreach (var d in dependencies)
            table.AddRow(Esc(d.Id), Esc(d.VersionRange), Esc(d.TargetFramework));
        return table;
    }

    // Inventory of packaged script/build files (role + path), shown only when the package ships any.
    private static Table ScriptsWidget(bool rich, IReadOnlyList<PackageScript> scripts)
    {
        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Role[/]");
        table.AddColumn("[bold]Path[/]");
        foreach (var s in scripts)
            table.AddRow(Esc(s.Role.ToString()), Esc(s.RelativePath));
        return table;
    }

    private static IRenderable ScriptFindingsWidget(bool rich, IReadOnlyList<ScriptFinding> findings)
    {
        if (findings.Count == 0)
            return new Markup("[green](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Rule[/]");
        table.AddColumn("[bold]Severity[/]");
        table.AddColumn("[bold]Location[/]");
        table.AddColumn("[bold]Name[/]");
        foreach (var f in findings)
            table.AddRow(
                Esc(f.RuleId),
                ColoredSeverity(f.Severity, Esc($"{f.Severity}/{f.Confidence}")),
                Esc($"{f.RelativePath}:{f.StartLine}"),
                Esc(f.RuleName));
        return table;
    }

    // Named-malware (YARA) matches across the extracted files (ADR 0016): rule name (red — high-confidence IOC),
    // malware family / detection-name, category, and the matched package-relative file. All fields are untrusted
    // package/rule content and pass through Esc; color is stripped in the default (ASCII) mode.
    private static IRenderable YaraFindingsWidget(bool rich, IReadOnlyList<YaraFinding> findings)
    {
        if (findings.Count == 0)
            return new Markup("[green](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Rule[/]");
        table.AddColumn("[bold]Malware family / detection[/]");
        table.AddColumn("[bold]Category[/]");
        table.AddColumn("[bold]File[/]");
        foreach (var f in findings)
            table.AddRow(
                $"[bold red]{Esc(f.RuleName)}[/]",
                Esc(FamilyDetection(f)),
                Esc(f.Category ?? "-"),
                Esc(f.RelativePath));
        return table;
    }

    // Known-vulnerability (OSV.dev) findings for the package and its declared dependencies (ADR 0017): the OSV/GHSA id
    // (red — a concrete, actionable IOC) plus CVE aliases, the attributed PackageId@Version (marked [dependency] for a
    // dependency checked at its range floor), the summary, and the raw CVSS severity. All fields are untrusted OSV/
    // package content and pass through Esc; color is stripped in the default (ASCII) mode.
    private static IRenderable VulnerabilitiesWidget(bool rich, IReadOnlyList<VulnerabilityFinding> findings)
    {
        if (findings.Count == 0)
            return new Markup("[green](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Vulnerability[/]");
        table.AddColumn("[bold]Package[/]");
        table.AddColumn("[bold]Severity[/]");
        table.AddColumn("[bold]Summary[/]");
        foreach (var f in findings)
            table.AddRow(
                $"[bold red]{Esc(f.Id)}[/]{AliasesSuffix(f)}",
                Esc(PackageLabel(f)),
                Esc(string.IsNullOrWhiteSpace(f.Severity) ? "-" : f.Severity),
                Esc(string.IsNullOrWhiteSpace(f.Summary) ? "-" : f.Summary));
        return table;
    }

    // A "  (CVE-…, CVE-…)" suffix listing the finding's aliases (typically CVE ids), or empty when there are none.
    private static string AliasesSuffix(VulnerabilityFinding f) =>
        f.Aliases.Count == 0 ? string.Empty : $" [grey]({Esc(string.Join(", ", f.Aliases))})[/]";

    // "id@version" plus a "[dependency]" marker when the vuln is attributed to a declared dependency (checked at floor).
    private static string PackageLabel(VulnerabilityFinding f) =>
        f.IsDependency
            ? $"{f.PackageId}@{f.PackageVersion} [dependency]"
            : $"{f.PackageId}@{f.PackageVersion}";

    // A single "family (detection)" label from a YARA finding's enriched metadata; each part is optional.
    private static string FamilyDetection(YaraFinding f)
    {
        var family = string.IsNullOrWhiteSpace(f.MalwareFamily) ? null : f.MalwareFamily;
        var detection = string.IsNullOrWhiteSpace(f.DetectionName) ? null : f.DetectionName;
        return (family, detection) switch
        {
            (not null, not null) => $"{family} ({detection})",
            (not null, null) => family!,
            (null, not null) => detection!,
            _ => "-",
        };
    }

    // A tree with one node per packaged assembly: meta line, grouped capability findings (or skip/none), obfuscation.
    private static Tree AssembliesTree(bool rich, IReadOnlyList<AssemblyScanResult> assemblies)
    {
        var root = new Tree("[bold]Assemblies[/]").Guide(TreeGuideFor(rich));
        if (assemblies.Count == 0)
        {
            root.AddNode("[grey](none)[/]");
            return root;
        }

        foreach (var result in assemblies)
        {
            var asm = result.Assembly;
            var node = root.AddNode($"[bold]{Esc(asm.RelativePath)}[/] [grey]({asm.Role}/{Esc(asm.TargetFramework ?? "?")})[/]");
            node.AddNode(MetaMarkup(result.Metadata));

            if (result.SkipReason is not null)
                node.AddNode($"[grey]skipped: {Esc(result.SkipReason)}[/]");
            else if (result.Report is null || result.Report.Findings.Count == 0)
                node.AddNode("[green]no findings[/]");
            else
                foreach (var group in result.Report.Findings.GroupBy(f => f.Capability).OrderBy(g => g.Key.ToString()))
                {
                    var capNode = node.AddNode(Colored(group.Key, $"{group.Key} ({group.Count()})"));
                    foreach (var f in group)
                        capNode.AddNode(Esc($"{f.CallerType}.{f.CallerMethod}  ->  {f.CalledApi}"));
                }

            AppendObfuscation(node, result.Obfuscation);
        }

        return root;
    }

    private static string MetaMarkup(AssemblyMetadataInfo? m)
    {
        if (m is null)
            return "[grey]meta: (unavailable)[/]";

        var resolved = m.References.Count(r => r.Resolved);
        return $"[grey]meta:[/] {Esc(m.Name)} {Esc(m.Version ?? "?")}  " +
               $"[grey]signed={YN(m.IsStrongNameSigned)} ilonly={YN(m.IsILOnly)} kind={Esc(m.ModuleKind)} " +
               $"refs={m.References.Count}({resolved} resolved)[/]";
    }

    private static void AppendObfuscation(TreeNode node, ObfuscationReport? obfuscation)
    {
        var findings = obfuscation?.Findings;
        if (findings is null || findings.Count == 0)
            return;

        var obf = node.AddNode($"[orange1]obfuscation: {findings.Count} finding(s)[/]");
        foreach (var f in findings)
            obf.AddNode(Esc($"{f.Kind} {f.DetectedAs}  {f.CallerType}.{f.CallerMethod}"));
    }

    // Footer: total findings, per-capability counts, script findings by severity, and a clean/attention headline
    // keyed on exactly what --strict gates (capability OR obfuscation OR script findings present).
    private static void Footer(IAnsiConsole console, bool rich, PackageCapabilityReport report)
    {
        var allFindings = report.AllFindings.ToList();
        console.MarkupLine($"[grey]Total capability findings:[/] {allFindings.Count}");

        if (allFindings.Count > 0)
        {
            var groups = allFindings.GroupBy(f => f.Capability).OrderBy(g => g.Key.ToString())
                .Select(g => Colored(g.Key, $"{g.Count()} {g.Key}"));
            console.MarkupLine($"[grey]Capabilities:[/] {string.Join($"  [grey]{Bullet(rich)}[/]  ", groups)}");
        }

        if (report.ScriptFindings.Count > 0)
        {
            var bySeverity = report.ScriptFindings.GroupBy(f => f.Severity).OrderBy(g => g.Key)
                .Select(g => ColoredSeverity(g.Key, $"{g.Count()} {g.Key}"));
            console.MarkupLine($"[grey]Script findings:[/] {string.Join($"  [grey]{Bullet(rich)}[/]  ", bySeverity)}");
        }
        else
            console.MarkupLine("[grey]Script findings:[/] [green]none[/]");

        var hasObfuscation = report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0);
        console.MarkupLine(hasObfuscation
            ? $"[grey]Obfuscation:[/] [orange1]present[/]"
            : "[grey]Obfuscation:[/] [green]none[/]");

        console.MarkupLine(report.YaraFindings.Count > 0
            ? $"[grey]Malware signatures (YARA):[/] [bold red]{report.YaraFindings.Count} match(es)[/]"
            : "[grey]Malware signatures (YARA):[/] [green]none[/]");

        console.MarkupLine(report.Vulnerabilities.Count > 0
            ? $"[grey]Known vulnerabilities (OSV):[/] [bold red]{report.Vulnerabilities.Count} finding(s)[/]"
            : "[grey]Known vulnerabilities (OSV):[/] [green]none[/]");

        var attention = allFindings.Count > 0 || report.ScriptFindings.Count > 0 || hasObfuscation
            || report.YaraFindings.Count > 0 || report.Vulnerabilities.Count > 0;
        console.MarkupLine(attention
            ? $"[bold red]{Esc(AlertGlyph(rich))} Findings present[/] [grey]{Dash(rich)} review recommended.[/]"
            : $"[bold green]{Esc(CleanGlyph(rich))} Clean[/] [grey]{Dash(rich)} no capability, script, obfuscation, malware-signature, or known-vulnerability findings.[/]");
    }
    #endregion
}
