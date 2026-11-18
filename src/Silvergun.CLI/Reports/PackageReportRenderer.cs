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
        console.Write(ScriptFindingsWidget(rich, report.ScriptFindings, report.ScriptScanStatus, report.ScriptScanUnavailableReason));
        console.WriteLine();

        // Packaging anomalies (ADR 0031): hostile constructions in the DECLARED zip entry names. Placed here, with the
        // container-level sections, because it describes the package as shipped rather than the content inside it —
        // and it is read before the content findings for the same reason. An empty list is a genuine "(none)": unlike
        // YARA/OSV this pass is pure, offline and cannot be unavailable, so there is no third state to distinguish.
        // Reported only — nothing in this section gates --strict or moves any exit code (ADR 0031 decision 3).
        console.Write(Section(rich, "Packaging anomalies"));
        console.Write(PackagingAnomaliesWidget(rich, report.PackagingAnomalies));
        console.WriteLine();

        // Native binaries (native-binaries-1): code the CIL analysis cannot see, named by header. Facts, not findings:
        // nothing here sets "attention" or gates --strict.
        console.Write(Section(rich, "Native binaries"));
        console.Write(NativeBinariesWidget(rich, report));
        console.WriteLine();

        // Malware-signature (YARA) hits are the highest-signal section (named-family IOCs, ADR 0016) — render it
        // prominently. Rendered consistently with Script findings (a green "(none)" when clean) EXCEPT that an
        // Unavailable scan (backend never selected, or selected but failed to initialize/scan — the libyara.NET
        // native-dependency defect this section exists to surface) is shown as a visible warning, never as the
        // clean "(none)": an empty YaraFindings list is not evidence of a clean package unless the scan actually ran.
        console.Write(Section(rich, "Malware signatures (YARA)"));
        console.Write(YaraFindingsWidget(rich, report.YaraFindings, report.YaraScanStatus));
        console.WriteLine();

        // Known-vulnerability (OSV.dev) hits are concrete, actionable IOCs (ADR 0017) — render prominently, like YARA.
        // Keyed on VulnerabilitiesStatus so an outage (Unavailable) is shown as a warning, never as the clean "(none)".
        console.Write(Section(rich, "Known vulnerabilities (OSV)"));
        console.Write(VulnerabilitiesWidget(rich, report.Vulnerabilities, report.VulnerabilitiesStatus));
        console.WriteLine();

        // Indicator (network / sensitive-target) findings, aggregated across every packaged assembly — selective by
        // design (see IndicatorsWidget). The seven discriminating categories set the Assessment headline (ARCHITECT
        // DECISION 2026-08-03) — see Footer below. As of ADR 0026, a strict subset of three of those seven
        // (CallbackDomain, DynamicDns, CredentialPath — ReportTheme.IsGatingIndicatorCategory) ALSO gate --strict
        // (Program.ScanPackageExitCode); the remaining four discriminating categories, and every counts-only
        // category, still never affect the exit code.
        console.Write(Section(rich, "Indicators"));
        console.Write(IndicatorsWidget(rich, report.Assemblies));
        console.WriteLine();

        // Resolver-lite transitive dependency coverage (ADR 0018), shown only when --depth resolution actually ran
        // (NotRun / depth 0 omits the section). Keyed on DependencyResolution so a Partial walk reads as incomplete
        // coverage, never as a clean all-clear.
        if (report.DependencyResolution != DependencyResolutionStatus.NotRun)
        {
            console.Write(Section(rich, "Transitive dependencies (resolver-lite)"));
            console.Write(TransitiveWidget(rich, report.ResolvedDependencies, report.DependencyResolution));
            console.WriteLine();
        }

        // Capability manifest (capability-manifest-reframe task): what this package CAN do, as a package-level
        // rollup across every analyzed assembly — an inventory alongside the findings sections above, not merged
        // into them. All 11 Capability values, present or absent, in enum order. Per-assembly detail stays where
        // it already is, in the Assemblies tree below. Presentation only; does not change what --strict gates on
        // (see the note it prints).
        console.Write(Section(rich, "Capability manifest"));
        console.Write(CapabilityManifest(report.AllFindings.ToList()));
        console.MarkupLine(CapabilityGateNote(rich));
        console.WriteLine();

        // Reachability (R3, scan-package --reachability): after the capability section it refines. Informational only,
        // and absent without the flag, so its absence is not a claim.
        if (report.Reachability is { } reachability)
        {
            ReachabilitySectionRenderer.Write(console, rich, reachability);
            console.WriteLine();
            // SSA facts (S5, scan-package --ssa): present exactly when asked for, so absent says nothing.
            if (reachability.Folders.Any(f => f.Ssa is not null))
            {
                SsaSectionRenderer.Write(console, rich, reachability);
                console.WriteLine();
            }
        }

        // Files only: a declared entry never written as a file of its own is not an assembly, so it is listed apart
        // (entry-aliasing review 2, W2) — with its verbatim SkipReason, under a heading that says what it is.
        console.Write(Section(rich, "Assemblies"));
        console.Write(AssembliesTree(rich, report.Assemblies.Where(a => !a.NotInventoried).ToList()));
        console.WriteLine();

        if (report.Assemblies.Where(a => a.NotInventoried).ToList() is { Count: > 0 } notExtracted)
        {
            console.Write(Section(rich, "Package entries never extracted"));
            console.Write(NotExtractedWidget(rich, notExtracted));
            console.WriteLine();
        }

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

    // Text-rule (backdoor/LOLBAS) matches in packaged script/build content and package metadata (ADR 0012). Findings are
    // aggregated per (rule, file), so a rule matching N times renders once with an "xN" repetition marker; manifest-sourced
    // rows carry a "[metadata]" marker (like "[dependency]" in the vulnerabilities section) because they are advisory —
    // manifest content, not executable script. Neither Source gates --strict (ADR 0027 stopped Script-sourced findings
    // gating too). All rule/path text is untrusted package content and passes through Esc; the repetition glyph comes
    // from the theme so the default mode stays ASCII-only (ADR 0014).
    //
    // Keyed on ScriptScanStatus like YaraFindingsWidget (ADR 0030): Unavailable means some or all script/manifest files
    // were NOT scanned, so it is a visible "not verified" note — never the clean "(none)" — above the findings the
    // scanned files did produce, which are real hits and are still shown (ADR 0032). The note is followed by the
    // report's ScriptScanUnavailableReason — which files were not scanned and why — so a saved text report says it too,
    // not only stderr and the JSON (ADR 0035 review W3); the report already escaped and bounded it, and Esc keeps it
    // literal inside the markup. Completed renders as it always has; NotRun reads "not run" (below).
    private static IRenderable ScriptFindingsWidget(
        bool rich, IReadOnlyList<ScriptFinding> findings, ScriptScanStatus status, string? unavailableReason)
    {
        if (status == ScriptScanStatus.Unavailable)
        {
            IRenderable[] note =
            [
                new Markup(findings.Count == 0
                    ? $"[yellow]{Esc(AlertGlyph(rich))} Script content scan did NOT complete {Dash(rich)} some or all script/manifest files NOT verified[/]"
                    : $"[yellow]{Esc(AlertGlyph(rich))} Script content scan INCOMPLETE {Dash(rich)} {findings.Count} finding(s) from the files that were scanned; other files NOT verified[/]"),
                .. unavailableReason is { Length: > 0 } reason ? [new Markup($"[grey]Reason: {Esc(reason)}[/]")] : Array.Empty<IRenderable>(),
            ];
            return findings.Count == 0 ? new Rows(note) : new Rows([.. note, ScriptFindingsTable(rich, findings)]);
        }
        // NotRun (no scan ran; nothing produces it today, but a report's JSON can say so) is grey "not run", like YARA's,
        // never the green "(none)" of a scan that ran clean (ADR 0035 S5 review N-1). Any findings it carries are shown.
        // It raises no completeness caveat (see AnalysisCompleteness.ScriptScanCaveat for when that must change).
        if (findings.Count == 0)
            return new Markup(status == ScriptScanStatus.NotRun ? "[grey](not run)[/]" : "[green](none)[/]");

        return ScriptFindingsTable(rich, findings);
    }

    private static Table ScriptFindingsTable(bool rich, IReadOnlyList<ScriptFinding> findings)
    {
        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Rule[/]");
        table.AddColumn("[bold]Severity[/]");
        table.AddColumn("[bold]Location[/]");
        table.AddColumn("[bold]Name[/]");
        foreach (var f in findings)
            table.AddRow(
                Esc(RuleLabel(f, rich)),
                ColoredSeverity(f.Severity, Esc($"{f.Severity}/{f.Confidence}")),
                Esc(FindingLocation(f)),
                Esc(f.RuleName));
        return table;
    }

    // "BD000600" plus an "x7" repetition marker when the rule matched the file more than once.
    private static string RuleLabel(ScriptFinding f, bool rich) =>
        f.Occurrences > 1 ? $"{f.RuleId} {Times(rich)}{f.Occurrences}" : f.RuleId;

    // "path:line" plus a "[metadata]" marker for findings from the declarative manifest (advisory — never gates).
    private static string FindingLocation(ScriptFinding f) =>
        f.Source == ScriptFindingSource.PackageMetadata
            ? $"{f.RelativePath}:{f.StartLine} [metadata]"
            : $"{f.RelativePath}:{f.StartLine}";

    // Named-malware (YARA) matches across the extracted files (ADR 0016): rule name (red — high-confidence IOC),
    // malware family / detection-name, category, and the matched package-relative file. All fields are untrusted
    // package/rule content and pass through Esc; color is stripped in the default (ASCII) mode.
    //
    // Keyed on YaraScanStatus exactly like VulnerabilitiesWidget is keyed on VulnerabilityScanStatus: Unavailable
    // (no backend selected, or a selected backend failed to initialize/scan) is a prominent warning — NOT the clean
    // "(none)" — because an empty finding list from a scan that never ran is not evidence of anything. NotRun
    // (--no-yara) stays dim, like OSV's NotChecked. Only a genuinely Completed scan earns the green "(none)".
    //
    // Unavailable WITH findings is an incomplete scan that found real hits before it could not go on (ADR 0032): the
    // hits are genuine detections and the other files are unverified, so BOTH are shown — the warning, reworded to
    // say the scan was incomplete rather than that it did not run, above the same findings table a completed scan
    // gets. Neither may hide the other.
    private static IRenderable YaraFindingsWidget(bool rich, IReadOnlyList<YaraFinding> findings, YaraScanStatus status)
    {
        if (status == YaraScanStatus.NotRun)
            return new Markup("[grey](not run)[/]");
        if (status == YaraScanStatus.Unavailable)
            return findings.Count == 0
                ? new Markup($"[yellow]{Esc(AlertGlyph(rich))} YARA malware-signature scan did NOT run (backend unavailable) {Dash(rich)} NOT verified[/]")
                : new Rows(
                    new Markup($"[yellow]{Esc(AlertGlyph(rich))} YARA malware-signature scan INCOMPLETE {Dash(rich)} {findings.Count} match(es) found in the files that were scanned; other files NOT verified[/]"),
                    YaraFindingsTable(rich, findings));
        if (findings.Count == 0)
            return new Markup("[green](none)[/]");

        return YaraFindingsTable(rich, findings);
    }

    private static Table YaraFindingsTable(bool rich, IReadOnlyList<YaraFinding> findings)
    {
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

    // Packaging anomalies in the package's declared zip entry names (ADR 0031): the category (orange1 — evidence of
    // intent, but never a gate), the offending entry, and a short detail (the offending code points, segment, or the
    // colliding partner names). Both text fields arrive ALREADY escaped by YaraPathSafety.Escape — a control
    // character or bidi override can no longer be in them by the time they get here — and still pass through Esc,
    // which is Spectre markup escaping and a different concern entirely.
    private static IRenderable PackagingAnomaliesWidget(bool rich, IReadOnlyList<PackagingAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new Markup("[green](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Anomaly[/]");
        table.AddColumn("[bold]Entry[/]");
        table.AddColumn("[bold]Detail[/]");
        foreach (var a in anomalies)
            table.AddRow(
                $"[bold orange1]{Esc(a.Category.ToString())}[/]",
                Esc(a.EntryName),
                Esc(a.Detail));
        return table;
    }

    // Native binaries: Unavailable is a yellow "not verified" note (with its reason) above whatever was found; NotRun is
    // grey; Completed and empty is "(none)". Paths arrive escaped at the DTO and still pass through Esc for markup.
    private static IRenderable NativeBinariesWidget(bool rich, PackageCapabilityReport report)
    {
        var binaries = report.NativeBinaries;
        if (NativeBinariesNotRecorded(report))
            return new Markup("[grey](not recorded in this report)[/]");
        IRenderable[] note = report.NativeBinaryScanStatus == NativeBinaryScanStatus.Unavailable
            ? [
                new Markup($"[yellow]{Esc(AlertGlyph(rich))} native binary scan did NOT complete {Dash(rich)} the list may be missing files[/]"),
                .. report.NativeBinaryScanUnavailableReason is { Length: > 0 } reason ? [new Markup($"[grey]Reason: {Esc(reason)}[/]")] : Array.Empty<IRenderable>(),
              ]
            : [];
        if (binaries.Count == 0)
            return note.Length > 0 ? new Rows(note)
                : new Markup(report.NativeBinaryScanStatus == NativeBinaryScanStatus.NotRun ? "[grey](not run)[/]" : "[green](none)[/]");

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Kind[/]");
        table.AddColumn("[bold]Format[/]");
        table.AddColumn("[bold]Arch[/]");
        table.AddColumn("[bold]Role[/]");
        table.AddColumn("[bold]Size[/]");
        table.AddColumn("[bold]Path[/]");
        foreach (var b in binaries)
            table.AddRow(
                (b.Kind == NativeBinaryKind.Executable ? $"[orange1]{b.Kind}[/]" : b.Kind.ToString()) + HostLabel(b),
                b.Code switch
                {
                    NativeBinaryCode.MixedMode => $"{b.Format} (mixed-mode)",
                    NativeBinaryCode.ReadyToRun => $"{b.Format} (ReadyToRun)",
                    NativeBinaryCode.ILOnly => $"{b.Format} (IL-only, not analysed)",
                    _ => b.Format.ToString(),
                },
                Esc(b.Architecture ?? "-"),
                b.Role.ToString(),
                b.Size.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Esc(b.RelativePath));
        return new Rows([.. note, table]);
    }

    // The .NET host marker (DotNetHost), as a suffix on the Kind cell. A bundle is orange: managed code packed inside a
    // native file, unseen by the CIL analysis. The marker is forgeable, so an apphost label is grey context, not a pass.
    private static string HostLabel(NativeBinary b) => b.DotNetHost switch
    {
        DotNetHost.AppHost => " [grey](.NET apphost)[/]",
        DotNetHost.SingleFileBundle => b.BundledFiles is { } n
            ? $" [orange1](.NET single-file bundle, {n} file(s) not analysed)[/]"
            : " [orange1](.NET single-file bundle, not analysed)[/]",
        DotNetHost.HostTemplate => " [grey](.NET host template)[/]",
        _ => string.Empty,
    };

    // A report that predates the field: Unavailable by the legacy default, with no binaries and no reason. A real
    // Unavailable (PackageScanner) always carries a reason, so this is "never checked", not "check failed".
    private static bool NativeBinariesNotRecorded(PackageCapabilityReport report) =>
        report.NativeBinaryScanStatus == NativeBinaryScanStatus.Unavailable
        && report.NativeBinaries.Count == 0
        && report.NativeBinaryScanUnavailableReason is null;

    // Known-vulnerability (OSV.dev) findings for the package and its declared dependencies (ADR 0017): the OSV/GHSA id
    // (red — a concrete, actionable IOC) plus CVE aliases, the attributed PackageId@Version (marked [dependency] for a
    // dependency checked at its range floor), the summary, and the raw CVSS severity. All fields are untrusted OSV/
    // package content and pass through Esc; color is stripped in the default (ASCII) mode.
    private static IRenderable VulnerabilitiesWidget(
        bool rich, IReadOnlyList<VulnerabilityFinding> findings, VulnerabilityScanStatus status)
    {
        // NotChecked (e.g. --no-vulns; also the DEFAULT of the field, so legacy JSON written before it existed
        // deserializes to it): dim, like other optional sections. Unavailable: a prominent warning that this is
        // NOT the clean state. Completed: the existing table, or a green "(none)" when it ran and found nothing.
        if (status == VulnerabilityScanStatus.NotChecked)
            return new Markup("[grey](not checked)[/]");
        if (status == VulnerabilityScanStatus.Unavailable)
            return new Markup($"[yellow]{Esc(AlertGlyph(rich))} known-vulnerability check unavailable {Dash(rich)} NOT verified[/]");
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

    // Indicator (network / sensitive-target) findings aggregated across every packaged assembly whose analysis
    // produced a report — selective by design (see ReportTheme.IsDiscriminatingIndicatorCategory /
    // IndicatorCountSummary): ALWAYS a per-category count summary, every category including zero, plus full detail
    // rows (tagged with the assembly they came from) for only the discriminating categories. An assembly whose
    // indicator analysis is null (failed, or the file was never analysed) simply contributes nothing here — that
    // gap already surfaces via CompletenessAssessment's obfuscation/metadata caveats' sibling reasoning, not
    // duplicated here. Truncated is rendered as a visible caveat, naming which assembly(ies) hit the cap.
    private static IRenderable IndicatorsWidget(bool rich, IReadOnlyList<AssemblyScanResult> assemblies)
    {
        var reports = assemblies
            .Where(a => a.Indicators is not null)
            .Select(a => (Path: a.Assembly.RelativePath, Report: a.Indicators!))
            .ToArray();

        if (reports.Length == 0)
            return new Markup("[grey](unavailable)[/]");

        var allFindings = reports.SelectMany(r => r.Report.Findings).ToArray();
        var widgets = new List<IRenderable> { IndicatorCountSummary(allFindings) };

        var detail = reports
            .SelectMany(r => r.Report.Findings
                .Where(f => IsDiscriminatingIndicatorCategory(f.Category))
                .Select(f => (r.Path, Finding: f)))
            .ToArray();
        if (detail.Length > 0)
            widgets.Add(IndicatorDetailTable(rich, detail));

        var truncated = reports.Where(r => r.Report.Truncated).Select(r => r.Path).ToArray();
        if (truncated.Length > 0)
            widgets.Add(new Markup(
                $"[yellow]{Esc(AlertGlyph(rich))} indicator analysis TRUNCATED for {Esc(string.Join(", ", truncated))} " +
                $"{Dash(rich)} these findings are a FLOOR, not a total[/]"));

        return new Rows(widgets);
    }

    // Detail rows for the discriminating indicator categories only, tagged with the packaged assembly they came from
    // (multiple assemblies can each contribute a row for the same category/value).
    private static Table IndicatorDetailTable(bool rich, IReadOnlyList<(string Path, IndicatorFinding Finding)> rows)
    {
        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Assembly[/]");
        table.AddColumn("[bold]Category[/]");
        table.AddColumn("[bold]Value[/]");
        table.AddColumn("[bold]Caller[/]");
        table.AddColumn("[bold]Occurrences[/]");

        foreach (var (path, f) in rows)
            table.AddRow(
                Esc(path),
                $"[red]{Esc(f.Category.ToString())}[/]",
                Esc(f.Value),
                Esc($"{f.CallerType}.{f.CallerMethod}"),
                f.Occurrences.ToString());

        return table;
    }

    // Resolver-lite transitive dependency coverage (ADR 0018): a headline keyed on the resolution status plus a table of
    // resolved nodes (id@version, depth, direct/transitive). Complete states the resolved count + max depth reached and
    // the "approximate — not a restore" caveat; Partial is a prominent (yellow in --rich) incomplete-coverage note so it
    // is never mistaken for a clean all-clear. All resolved ids/versions are untrusted and pass through Esc; color is
    // stripped in the default (ASCII) mode. Callers omit the section entirely for NotRun (depth 0).
    private static IRenderable TransitiveWidget(
        bool rich, IReadOnlyList<ResolvedDependency> resolved, DependencyResolutionStatus status)
    {
        var maxDepth = resolved.Count == 0 ? 0 : resolved.Max(r => r.Depth);
        var headline = status == DependencyResolutionStatus.Partial
            ? new Markup($"[yellow]{Esc(AlertGlyph(rich))} transitive dependencies NOT fully resolved {Dash(rich)} coverage incomplete[/] " +
                         $"[grey](resolved {resolved.Count} package(s) before the walk was interrupted)[/]")
            : new Markup($"[grey]Resolved[/] {resolved.Count} transitive package(s), max depth {maxDepth} {Dash(rich)} " +
                         $"[grey]approximate {Dash(rich)} not a restore.[/]");

        if (resolved.Count == 0)
            return headline;

        var table = new Table().Border(TableBorderFor(rich)).Expand();
        table.AddColumn("[bold]Dependency[/]");
        table.AddColumn("[bold]Version[/]");
        table.AddColumn("[bold]Depth[/]");
        table.AddColumn("[bold]Kind[/]");
        foreach (var d in resolved)
            table.AddRow(Esc(d.Id), Esc(d.Version), d.Depth.ToString(), d.IsDirect ? "direct" : "transitive");

        return new Rows(headline, table);
    }

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

    // Declared entries that were never written as an extracted file of their own (NuGetPackage.UninventoriedEntryNames):
    // a yellow note, then one row per entry name (escaped at the DTO, Esc'd for markup) with its verbatim SkipReason.
    private static IRenderable NotExtractedWidget(bool rich, IReadOnlyList<AssemblyScanResult> entries) =>
        new Rows(
        [
            new Markup(entries.Count == 1
                ? $"[yellow]{Esc(AlertGlyph(rich))} 1 declared entry was never written as a file of its own {Dash(rich)} " +
                  "its content, or the content it replaced, was NOT analysed[/]"
                : $"[yellow]{Esc(AlertGlyph(rich))} {entries.Count} declared entries were never written as a file of their own " +
                  $"{Dash(rich)} their content, or the content they replaced, was NOT analysed[/]"),
            .. entries.Select(e => new Markup($"  {Esc(e.Assembly.RelativePath)} [grey]{Esc(e.SkipReason ?? string.Empty)}[/]")),
        ]);

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

            AppendObfuscation(rich, node, result.Obfuscation);
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

    private static void AppendObfuscation(bool rich, TreeNode node, ObfuscationReport? obfuscation)
    {
        var findings = obfuscation?.Findings;
        if (obfuscation is { Truncated: true })
            node.AddNode($"[yellow]obfuscation: TRUNCATED (a blob or fold budget was spent) {Dash(rich)} these findings are a FLOOR, not a total[/]");
        if (findings is null || findings.Count == 0)
            return;

        var obf = node.AddNode(findings.Any(IsAttentionObfuscation)
            ? $"[orange1]obfuscation: {findings.Count} finding(s)[/]"
            : $"[grey]obfuscation: {findings.Count} embedded image(s)[/]");
        foreach (var f in findings)
            obf.AddNode(Esc($"{f.Kind} {ObfuscationDetected(f)}  {f.CallerType}.{f.CallerMethod}"));
    }

    // Footer: total findings, per-capability counts, script findings by severity, the IL coverage line, and the
    // three-tier Findings / Not verified / Clean headline. "Not verified" comes from the shared
    // CompletenessAssessment (ADR 0024).
    //
    // "Attention" is DELIBERATELY WIDER than the --strict gate, and must not be confused with it. It counts ANY
    // script finding (report.ScriptFindings.Count > 0), from either Source. As of ADR 0027, Program.ScanPackageExitCode
    // does not consult ScriptFindings at all — neither Source == Script (25% benign prevalence) nor Source ==
    // PackageMetadata (always advisory) gates. So a package whose only findings are script/nuspec matches prints
    // "Findings present" here and still exits 0 under --strict. Both sides are correct: a human should see every
    // script/manifest finding, and CI must not fail on a source measured too common in ordinary packages to be
    // signal. This is exactly why ADR 0024's invariant is an IMPLICATION — footer says "Clean" ⇒ exit 0 — and not a
    // biconditional (see the "CORRECTED AGAIN" note in that ADR). The same relationship holds for capability,
    // obfuscation, and indicators too (ARCHITECT DECISION 2026-08-03 for indicators): capability/obfuscation presence
    // and the seven discriminating indicator categories widen "Attention" regardless of --strict. As of ADR 0026 this
    // is no longer purely one-directional for indicators — three of the seven (CallbackDomain, DynamicDns,
    // CredentialPath) ALSO gate --strict — but "Attention" is still the wider set: a package whose only finding is a
    // capability/obfuscation presence, or one of the four non-gating discriminating indicator categories (e.g.
    // RawCodeHost), prints "Findings present" here and still exits 0 under --strict, exactly like the script/nuspec
    // case above.
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
                .Select(g => ColoredSeverity(g.Key, Esc($"{g.Count()} {g.Key}")));
            console.MarkupLine($"[grey]Script findings:[/] {string.Join($"  [grey]{Bullet(rich)}[/]  ", bySeverity)}"
                + (report.ScriptScanStatus == ScriptScanStatus.Unavailable
                    ? $" [yellow](scan INCOMPLETE {Dash(rich)} other files not verified)[/]"
                    : string.Empty));
        }
        else
            console.MarkupLine(report.ScriptScanStatus switch
            {
                ScriptScanStatus.Unavailable => "[grey]Script findings:[/] [yellow]not verified (scan did not complete)[/]",
                ScriptScanStatus.NotRun => "[grey]Script findings:[/] [grey]not run[/]",
                _ => "[grey]Script findings:[/] [green]none[/]",
            });

        // Images are listed but do not set attention (hidden-payloads-1 §7).
        var anyObfuscation = report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0);
        var hasObfuscation = report.Assemblies.Any(a => a.Obfuscation?.Findings.Any(IsAttentionObfuscation) ?? false);
        var obfuscationTruncated = report.Assemblies.Where(a => a.Obfuscation is { Truncated: true }).Select(a => a.Assembly.RelativePath).ToList();
        console.MarkupLine((hasObfuscation
            ? $"[grey]Obfuscation:[/] [orange1]present[/]"
            : anyObfuscation
                ? "[grey]Obfuscation:[/] [grey]embedded images only[/]"
                : "[grey]Obfuscation:[/] [green]none[/]")
            + (obfuscationTruncated.Count > 0
                ? $" [yellow](TRUNCATED for {Esc(string.Join(", ", obfuscationTruncated))} {Dash(rich)} a floor, not a total)[/]"
                : string.Empty));

        // Packaging anomalies mirror their section (ADR 0013's count summary). Deliberately NOT folded into the
        // "attention" predicate below: ADR 0031 decision 3 keeps this class of finding purely informational until its
        // benign prevalence is measured, and "attention" is the headline the exit-code gate is written to mirror.
        console.MarkupLine(report.PackagingAnomalies.Count > 0
            ? $"[grey]Packaging anomalies:[/] [orange1]{report.PackagingAnomalies.Count} finding(s)[/]"
            : "[grey]Packaging anomalies:[/] [green]none[/]");

        // Native binaries: a count line only, never part of "attention" (facts layer; base rate not yet measured).
        var nativeExecutables = report.NativeBinaries.Count(b => b.Kind == NativeBinaryKind.Executable);
        var nativeMalformed = report.NativeBinaries.Count(b => b.Kind == NativeBinaryKind.Malformed);
        var appHosts = report.NativeBinaries.Count(b => b.DotNetHost == DotNetHost.AppHost);
        var bundles = report.NativeBinaries.Count(b => b.DotNetHost == DotNetHost.SingleFileBundle);
        console.MarkupLine(NativeBinariesNotRecorded(report) ? "[grey]Native binaries:[/] [grey]not recorded[/]"
            : report.NativeBinaryScanStatus == NativeBinaryScanStatus.NotRun && report.NativeBinaries.Count == 0 ? "[grey]Native binaries:[/] [grey]not run[/]"
            : $"[grey]Native binaries:[/] {report.NativeBinaries.Count}"
              + (nativeExecutables > 0 ? $" [orange1]({nativeExecutables} executable(s))[/]" : string.Empty)
              + (appHosts > 0 ? $" [grey]({appHosts} .NET apphost(s))[/]" : string.Empty)
              + (bundles > 0 ? $" [orange1]({bundles} .NET single-file bundle(s))[/]" : string.Empty)
              + (nativeMalformed > 0 ? $" [grey]({nativeMalformed} malformed)[/]" : string.Empty)
              + (report.NativeBinaryScanStatus == NativeBinaryScanStatus.Unavailable ? $" [yellow](scan INCOMPLETE {Dash(rich)} may be missing files)[/]" : string.Empty));

        // Findings from an incomplete scan (Unavailable, ADR 0032) are real and counted, but marked: the other files
        // were not verified, so the count is a floor.
        console.MarkupLine(report.YaraFindings.Count > 0
            ? $"[grey]Malware signatures (YARA):[/] [bold red]{report.YaraFindings.Count} match(es)[/]"
              + (report.YaraScanStatus == YaraScanStatus.Unavailable
                  ? $" [yellow](scan INCOMPLETE {Dash(rich)} other files not verified)[/]"
                  : string.Empty)
            : report.YaraScanStatus switch
            {
                YaraScanStatus.Unavailable => "[grey]Malware signatures (YARA):[/] [yellow]not verified (scan did not run)[/]",
                YaraScanStatus.NotRun => "[grey]Malware signatures (YARA):[/] [grey]not run[/]",
                _ => "[grey]Malware signatures (YARA):[/] [green]none[/]",
            });

        console.MarkupLine(report.Vulnerabilities.Count > 0
            ? $"[grey]Known vulnerabilities (OSV):[/] [bold red]{report.Vulnerabilities.Count} finding(s)[/]"
            : report.VulnerabilitiesStatus switch
            {
                VulnerabilityScanStatus.Unavailable => "[grey]Known vulnerabilities (OSV):[/] [yellow]not verified (check unavailable)[/]",
                VulnerabilityScanStatus.NotChecked => "[grey]Known vulnerabilities (OSV):[/] [grey]not checked[/]",
                _ => "[grey]Known vulnerabilities (OSV):[/] [green]none[/]",
            });

        // The seven discriminating categories (the same split IndicatorsWidget renders as detail rows,
        // IsDiscriminatingIndicatorCategory) set "attention" below — ARCHITECT DECISION 2026-08-03: a
        // CallbackDomain-only finding must not print "Clean" while the callback domain sits in the section right
        // above it. The noisy categories (ReflectionTypeName/GenericUrl/PrivateIpLiteral) stay excluded from
        // attention. As of ADR 0026, three of the seven discriminating categories (CallbackDomain, DynamicDns,
        // CredentialPath — IsGatingIndicatorCategory) ALSO gate --strict via Program.ScanPackageExitCode; this
        // "attention" count still counts all seven, since attention is always the wider set (see the Footer-level
        // note above). Truncated is still surfaced here as a visible caveat, naming which assembly(ies): "could not
        // analyse everything" must never read as a clean result.
        var indicatorReports = report.Assemblies.Where(a => a.Indicators is not null).ToList();
        var indicatorCount = indicatorReports.Sum(a => a.Indicators!.Findings.Count);
        var discriminatingIndicatorCount = indicatorReports
            .Sum(a => a.Indicators!.Findings.Count(f => IsDiscriminatingIndicatorCategory(f.Category)));
        var indicatorsTruncated = indicatorReports.Where(a => a.Indicators!.Truncated).Select(a => a.Assembly.RelativePath).ToList();
        console.MarkupLine(indicatorCount == 0
            ? "[grey]Indicators:[/] [green]none[/]"
            : $"[grey]Indicators:[/] [orange1]{indicatorCount} finding(s)[/], {discriminatingIndicatorCount} discriminating" +
              (discriminatingIndicatorCount < indicatorCount ? " [grey](see breakdown above)[/]" : string.Empty));
        if (indicatorsTruncated.Count > 0)
            console.MarkupLine($"[yellow]{Esc(AlertGlyph(rich))} indicator analysis TRUNCATED for {Esc(string.Join(", ", indicatorsTruncated))} " +
                                $"{Dash(rich)} these findings are a FLOOR, not a total[/]");

        // Transitive coverage line (resolver-lite, ADR 0018), shown only when --depth resolution ran. A Partial walk is
        // surfaced as incomplete coverage so it can downgrade the clean claim below (like an OSV outage).
        if (report.DependencyResolution != DependencyResolutionStatus.NotRun)
            console.MarkupLine(report.DependencyResolution == DependencyResolutionStatus.Partial
                ? "[grey]Transitive dependencies:[/] [yellow]coverage incomplete (not fully resolved)[/]"
                : $"[grey]Transitive dependencies:[/] [green]{report.ResolvedDependencies.Count} resolved[/]");

        // "Clean" requires the analysis to have been COMPLETE, not merely finding-free: an OSV outage/skip
        // (Unavailable/NotChecked), a Partial transitive walk, methods that could not be analyzed, or a failed
        // obfuscation analysis all mean the package was NOT fully verified. The caveats come from the SHARED
        // CompletenessAssessment the exit code uses (ADR 0024), replacing the two inline locals this footer used to
        // key on — so the footer and exit code can no longer disagree, and IL coverage is no longer a blind spot.
        var assessment = CompletenessAssessment.ForPackage(report);
        CompletenessFooter.WriteCoverage(console, assessment);

        var attention = allFindings.Count > 0 || report.ScriptFindings.Count > 0 || hasObfuscation
            || report.YaraFindings.Count > 0 || report.Vulnerabilities.Count > 0 || discriminatingIndicatorCount > 0;
        CompletenessFooter.WriteHeadline(
            console, rich, attention, assessment,
            "no capability, script, obfuscation, malware-signature, known-vulnerability, or discriminating-indicator findings.");
    }
    #endregion
}
