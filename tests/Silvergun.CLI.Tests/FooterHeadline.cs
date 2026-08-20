namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Spectre.Console;

using Xunit;

/// <summary>
/// Isolates the ADR 0024 completeness footer's <b>verdict headline</b> as a whole LINE, so tests can assert what the
/// report actually concluded instead of grepping stdout for a bare token.
/// <para>
/// <b>Why this exists.</b> <c>Assert.DoesNotContain("Clean", output)</c> is a statement about the whole report, not
/// about the headline: the footer's caveats embed <b>untrusted assembly paths</b>, so a package containing
/// <c>CleanArchitecture.Core.dll</c> (or a findings table naming a <c>Cleanup</c> method) fails such an assertion for
/// a reason that has nothing to do with the verdict — and, worse, the mirrored
/// <c>Assert.Contains("Clean", output)</c> can PASS while the headline says something else entirely, because the
/// token appeared elsewhere. Matching one glyph-prefixed line and comparing it whole removes both failure modes.
/// </para>
/// <para>
/// <see cref="Of(string)"/> uses <see cref="Assert.Single{T}(IEnumerable{T})"/> deliberately: a second verdict
/// headline in one report is itself a defect (two verdicts, one report), so it must fail loudly rather than let an
/// assertion silently pick whichever came first. Only the three VERDICT labels count — the glyph-prefixed lines that
/// other sections write ("[!] Red flags:", "[OK] No red flags.", "[!] N likely typosquat target(s)") are not
/// verdicts and are excluded by label.
/// </para>
/// <para>
/// The expected-line builders pin BOTH rendered forms verbatim (the rich Unicode glyphs and the ASCII fallbacks of
/// ADR 0014) and pick between them from the console the test itself created, so a test never has to know which mode
/// its console ended up in, and the two verbs' differing <c>cleanDetail</c> tails are passed in rather than assumed.
/// </para>
/// </summary>
internal static class FooterHeadline
{
    #region Methods
    /// <summary>The one verdict headline in a rendered report. Fails if there is not exactly one.</summary>
    internal static string Of(StringWriter writer) => Of(writer.ToString());

    /// <summary>The one verdict headline in a report's text (stdout of a CLI run, or a renderer's buffer).</summary>
    internal static string Of(string output) => Assert.Single(AllIn(output));

    /// <summary>Every verdict headline in the text — normally exactly one; empty when no report was printed.</summary>
    internal static IReadOnlyList<string> AllIn(string output) =>
        [.. Lines(output).Where(line => VerdictOf(line) is not null)];

    /// <summary>
    /// The findings-present branch's second line, which discloses the caveats ("... there may be more"). Fails if
    /// there is not exactly one.
    /// </summary>
    internal static string DisclosureOf(StringWriter writer) =>
        Assert.Single(Lines(writer.ToString()), line => LabelOf(line, IncompleteLabel) is not null);

    /// <summary>Which of the three verdicts a line carries, or null if it is not a verdict headline at all.</summary>
    internal static string? VerdictOf(string line) => Verdicts.FirstOrDefault(v => LabelOf(line, v) is not null);

    internal static bool IsClean(string line) => VerdictOf(line) == CleanLabel;

    internal static bool IsNotVerified(string line) => VerdictOf(line) == NotVerifiedLabel;

    /// <summary>The exact Clean headline for a console's mode, with the verb-specific detail tail.</summary>
    internal static string Clean(IAnsiConsole console, string detail) => Clean(IsRich(console), detail);

    internal static string Clean(bool rich, string detail) => $"{CleanGlyph(rich)} {CleanLabel} {Dash(rich)} {detail}";

    /// <summary>The exact Not-verified headline for a console's mode, naming the caveats in order.</summary>
    internal static string NotVerified(IAnsiConsole console, params string[] caveats) =>
        NotVerified(IsRich(console), caveats);

    internal static string NotVerified(bool rich, params string[] caveats) =>
        $"{AlertGlyph(rich)} {NotVerifiedLabel} {Dash(rich)} no findings, but {string.Join("; ", caveats)}.";

    /// <summary>The exact Findings-present headline for a console's mode.</summary>
    internal static string FindingsPresent(IAnsiConsole console) => FindingsPresent(IsRich(console));

    internal static string FindingsPresent(bool rich) =>
        $"{AlertGlyph(rich)} {FindingsLabel} {Dash(rich)} review recommended.";

    /// <summary>The exact caveat-disclosure line that accompanies a Findings-present headline.</summary>
    internal static string Incomplete(IAnsiConsole console, params string[] caveats) =>
        $"{AlertGlyph(IsRich(console))} {IncompleteLabel} {Dash(IsRich(console))} "
        + $"{string.Join("; ", caveats)}; there may be more.";

    // The line, if it is a glyph-prefixed line carrying exactly this label; null otherwise.
    private static string? LabelOf(string line, string label) =>
        Glyphs.Any(g => line.StartsWith(g, StringComparison.Ordinal)
                        && line[g.Length..].StartsWith($"{label} ", StringComparison.Ordinal))
            ? line
            : null;

    private static IEnumerable<string> Lines(string output) =>
        output.Split('\n').Select(line => line.TrimEnd('\r', ' '));

    private static bool IsRich(IAnsiConsole console) => console.Profile.Capabilities.Unicode;

    private static string CleanGlyph(bool rich) => rich ? "✔" : "[OK]";

    private static string AlertGlyph(bool rich) => rich ? "✖" : "[!]";

    private static string Dash(bool rich) => rich ? "—" : "-";
    #endregion

    #region Fields
    /// <summary>The <c>cleanDetail</c> tail <c>AssemblyReportRenderer</c> passes to the shared footer.</summary>
    internal const string AssemblyCleanDetail = "no sensitive-API, obfuscation, or discriminating-indicator findings.";

    /// <summary>The (different, longer) tail <c>PackageReportRenderer</c> passes.</summary>
    internal const string PackageCleanDetail =
        "no capability, script, obfuscation, malware-signature, known-vulnerability, or discriminating-indicator findings.";

    private const string CleanLabel = "Clean";
    private const string NotVerifiedLabel = "Not verified";
    private const string FindingsLabel = "Findings present";
    private const string IncompleteLabel = "Analysis incomplete";

    // Both rendered forms of both glyphs (ADR 0014: rich Unicode, ASCII by default), with their trailing space.
    private static readonly string[] Glyphs = ["[OK] ", "[!] ", "✔ ", "✖ "];

    private static readonly string[] Verdicts = [CleanLabel, NotVerifiedLabel, FindingsLabel];
    #endregion
}
