namespace Silvergun.CLI.Reports;

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
    #endregion
}
