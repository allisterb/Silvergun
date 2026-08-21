namespace Silvergun.CLI.Reports;

using System;
using System.Collections.Generic;
using System.Linq;

using Spectre.Console;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Shared presentation helpers for the Spectre.Console verb renderers (ADR 0013): severity/capability
/// colors, escaping, and small widget factories. Presentation-only — no analysis logic, no report types.
/// All interpolated data from reports (names, paths, rule text, excerpts) is untrusted and must pass
/// through <see cref="Esc"/> before it reaches Spectre markup.
/// </summary>
internal static class ReportTheme
{
    #region Methods
    /// <summary>Escapes untrusted text so it renders literally inside Spectre markup.</summary>
    internal static string Esc(string? value) => Markup.Escape(value ?? string.Empty);

    /// <summary>
    /// The single richness axis (ADR 0014): true ⇒ rich (ANSI color + Unicode borders/glyphs), false ⇒
    /// plain ASCII-only. Derived from the console's Unicode capability so callers branch in one place here.
    /// </summary>
    internal static bool IsRich(IAnsiConsole console) => console.Profile.Capabilities.Unicode;

    /// <summary>A left-justified section divider carrying a plain (already-safe) title.</summary>
    internal static Rule Section(bool rich, string title) =>
        new Rule($"[bold]{title}[/]") { Justification = Justify.Left, Style = Style.Parse("grey"), Border = BoxBorderFor(rich) };

    /// <summary>The report banner: tool name + verb, rendered as a heavy top rule.</summary>
    internal static Rule Header(bool rich, string verb) =>
        new Rule($"[bold aqua]Silvergun[/] [grey]{Bullet(rich)}[/] [bold]{verb}[/]") { Justification = Justify.Left, Border = BoxBorderFor(rich) };

    /// <summary>Table border for the current mode: Unicode box-drawing (rich) vs pure ASCII (default).</summary>
    internal static TableBorder TableBorderFor(bool rich) => rich ? TableBorder.Rounded : TableBorder.Ascii;

    /// <summary>Box/panel/rule border for the current mode.</summary>
    internal static BoxBorder BoxBorderFor(bool rich) => rich ? BoxBorder.Rounded : BoxBorder.Ascii;

    /// <summary>Tree guide lines for the current mode (Rule/Table borders don't auto-degrade — pick explicitly).</summary>
    internal static TreeGuide TreeGuideFor(bool rich) => rich ? TreeGuide.Line : TreeGuide.Ascii;

    /// <summary>Inline item separator: Unicode middle-dot (rich) vs ASCII hyphen (default).</summary>
    internal static string Bullet(bool rich) => rich ? "·" : "-";

    /// <summary>Prose separator: Unicode em-dash (rich) vs ASCII hyphen (default).</summary>
    internal static string Dash(bool rich) => rich ? "—" : "-";

    /// <summary>Repetition/count prefix (as in "x7"): Unicode multiplication sign (rich) vs ASCII "x" (default).</summary>
    internal static string Times(bool rich) => rich ? "×" : "x";

    /// <summary>Attention glyph for a clean/no-findings headline (ASCII-safe fallback; escape at the call site).</summary>
    internal static string CleanGlyph(bool rich) => rich ? "✔" : "[OK]";

    /// <summary>Attention glyph for a findings-present headline (ASCII-safe fallback; escape at the call site).</summary>
    internal static string AlertGlyph(bool rich) => rich ? "✖" : "[!]";

    /// <summary>Wraps a value in its capability color for inline markup.</summary>
    internal static string Colored(Capability capability, string text) =>
        $"[{CapabilityColor(capability)}]{text}[/]";

    /// <summary>Wraps a value in its script-severity color for inline markup.</summary>
    internal static string ColoredSeverity(string severity, string text) =>
        $"[{SeverityColor(severity)}]{text}[/]";

    /// <summary>Distinct, stable color per sensitive-capability category.</summary>
    internal static string CapabilityColor(Capability capability) => capability switch
    {
        Capability.FileSystem => "yellow",
        Capability.Network => "aqua",
        Capability.ProcessExecution => "red",
        Capability.Registry => "orange1",
        Capability.EnvironmentProbe => "fuchsia",
        Capability.DynamicCodeLoading => "orange3",
        Capability.NativeInterop => "purple",
        Capability.Cryptography => "green",
        Capability.ReflectionInvocation => "mediumpurple",
        _ => "silver",
    };

    /// <summary>Color for an AppInspector RulesEngine severity name (string-typed on the report).</summary>
    internal static string SeverityColor(string severity) => (severity ?? string.Empty).ToLowerInvariant() switch
    {
        "critical" => "red",
        "important" or "high" => "orange1",
        "moderate" or "medium" => "yellow",
        "bestpractice" or "low" => "blue",
        "manualreview" => "grey",
        _ => "silver",
    };

    internal static string YesNo(bool value) => value ? "yes" : "no";

    internal static string YN(bool value) => value ? "y" : "n";

    /// <summary>
    /// The <see cref="IndicatorCategory"/> values rendered as full detail rows in the human report — the seven
    /// categories measured at 0% (or, for <see cref="IndicatorCategory.PublicIpLiteral"/>, still judged
    /// discriminating) benign-corpus share in <c>docs/agent/measurements/indicator-prevalence-2026-08-03.md</c>.
    /// Every other category (<see cref="IndicatorCategory.ReflectionTypeName"/>, <see cref="IndicatorCategory.GenericUrl"/>,
    /// <see cref="IndicatorCategory.PrivateIpLiteral"/>) is counts-only in the terminal — <c>--json</c> always
    /// carries every category in full regardless of this list (indicator-cli-integration task).
    /// <para>ARCHITECT DECISION 2026-08-03: this same split also governs the Assessment headline — these seven
    /// categories DO set "attention" (so the headline reads "Findings present" rather than "Clean"), because a
    /// package whose only finding is e.g. a <see cref="IndicatorCategory.CallbackDomain"/> must not print "Clean"
    /// with that finding listed in the section directly above it. As of ADR 0026, a strict SUBSET of this group —
    /// see <see cref="IsGatingIndicatorCategory"/> — also gates <c>--strict</c>; the remaining discriminating
    /// categories, and every counts-only category, still never affect the exit code.</para>
    /// </summary>
    internal static bool IsDiscriminatingIndicatorCategory(IndicatorCategory category) => category is
        IndicatorCategory.CallbackDomain or IndicatorCategory.ExfilSink or IndicatorCategory.DynamicDns
        or IndicatorCategory.RawCodeHost or IndicatorCategory.CredentialPath or IndicatorCategory.AutorunRegistry
        or IndicatorCategory.PublicIpLiteral;

    /// <summary>
    /// The <see cref="IndicatorCategory"/> values that fail <c>--strict</c> (ADR 0026, "FINAL DECISION AS ACCEPTED"):
    /// <see cref="IndicatorCategory.CallbackDomain"/>, <see cref="IndicatorCategory.DynamicDns"/>, and
    /// <see cref="IndicatorCategory.CredentialPath"/> — each measured 0/113 contributing benign packages, including
    /// groups hand-picked to trip them. <b>Gating set ⊂ discriminating set</b>, expressed structurally here (not just
    /// documented) by requiring <see cref="IsDiscriminatingIndicatorCategory"/> first: a category can never gate
    /// without also setting the headline, so the two lists cannot silently diverge.
    /// <para>
    /// Deliberately NOT gating, despite also being discriminating: <see cref="IndicatorCategory.ExfilSink"/> (0/78,
    /// but 1/8 adversarial hits was a legitimate Discord logging sink), <see cref="IndicatorCategory.RawCodeHost"/>
    /// and <see cref="IndicatorCategory.PublicIpLiteral"/> (both have measured legitimate uses), and
    /// <see cref="IndicatorCategory.AutorunRegistry"/> (unmeasured — the adversarial corpus targeted Windows
    /// Services, a different mechanism). <see cref="IndicatorCategory.ReflectionTypeName"/>,
    /// <see cref="IndicatorCategory.GenericUrl"/>, and <see cref="IndicatorCategory.PrivateIpLiteral"/> are not
    /// discriminating either, so they cannot reach this predicate's "true" branch.
    /// </para>
    /// </summary>
    internal static bool IsGatingIndicatorCategory(IndicatorCategory category) =>
        IsDiscriminatingIndicatorCategory(category) && category is
            IndicatorCategory.CallbackDomain or IndicatorCategory.DynamicDns or IndicatorCategory.CredentialPath;

    /// <summary>
    /// Per-<see cref="IndicatorCategory"/> finding-count grid over EVERY category, including a count of zero — a
    /// category present at zero is information, so it is never omitted. Counts aggregated finding rows (already
    /// deduplicated per (Category, Value, CallerType, CallerMethod) by <see cref="IndicatorAnalysis"/>), not raw
    /// <see cref="IndicatorFinding.Occurrences"/>, matching how counts are reported elsewhere in these renderers
    /// (e.g. capability/obfuscation finding counts).
    /// </summary>
    internal static Grid IndicatorCountSummary(IReadOnlyList<IndicatorFinding> findings)
    {
        var grid = new Grid();
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn();
        foreach (var category in Enum.GetValues<IndicatorCategory>())
        {
            var count = findings.Count(f => f.Category == category);
            grid.AddRow($"[grey]{Esc(category.ToString())}[/]", count == 0 ? "[green]0[/]" : $"[orange1]{count}[/]");
        }
        return grid;
    }

    /// <summary>
    /// The full <see cref="Capability"/> manifest (capability-manifest-reframe task): EVERY enum value, present or
    /// absent, in enum-declaration order — the enum is documented append-only, so this ordering is stable across
    /// releases and makes two different packages' manifests visually comparable. Do NOT sort by count. An absent
    /// capability is itself information ("this package does NOT execute processes"), so zero rows are never
    /// omitted, matching <see cref="IndicatorCountSummary"/>'s posture toward zero-count categories.
    /// <para>
    /// Renders from the shared <c>Silvergun.CodeAnalysis.IL.CapabilityManifest</c> projection (capability-diff-versions
    /// task) rather than recomputing counts inline — the same projection the serializable
    /// <c>Silvergun.CodeAnalysis.IL.CapabilitySnapshot</c> carries, so the report and a snapshot can never disagree
    /// about what "present" means. No report record gains a member for this (that would reopen the <c>--json</c>
    /// splice's duplicate-property hazard); this method's own name and signature are unchanged on purpose — a fully
    /// qualified name is used for the projection type below because this class already declares a member with the
    /// same simple name (<c>CapabilityManifest</c>), which a bare reference to the type would otherwise collide with.
    /// </para>
    /// </summary>
    internal static Grid CapabilityManifest(IReadOnlyList<ApiCallFinding> findings)
    {
        var manifest = Silvergun.CodeAnalysis.IL.CapabilityManifest.From(findings);
        var grid = new Grid();
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn(new GridColumn().NoWrap().PadRight(2));
        grid.AddColumn();
        foreach (var entry in manifest.Entries)
            grid.AddRow(
                $"[grey]{Esc(entry.Capability.ToString())}[/]",
                entry.Present ? Colored(entry.Capability, "present") : "[grey]absent[/]",
                entry.Present ? $"[orange1]{entry.CallSiteCount}[/]" : "[green]0[/]");
        return grid;
    }

    /// <summary>
    /// Honesty line printed alongside <see cref="CapabilityManifest"/>: the manifest itself is purely
    /// informational, but presenting it as an inventory does NOT change the gate — <c>--strict</c> still fails the
    /// build on ANY capability finding, exactly as before this task. Stated explicitly so the report never reads as
    /// "purely informational" while silently controlling CI (whether presence alone SHOULD gate is the deferred,
    /// separate decision in ADR-0027 — not this task).
    /// </summary>
    internal static string CapabilityGateNote(bool rich) =>
        $"[grey]Note[/] {Dash(rich)} this manifest is informational; [bold]--strict[/] still fails the build on ANY capability present here.";
    #endregion
}
