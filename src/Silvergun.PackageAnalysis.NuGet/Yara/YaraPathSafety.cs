namespace Silvergun.PackageAnalysis.NuGet.Yara;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Filename hostility helpers for the classic-CLI backend (ADR 0029). Two concerns, deliberately kept together
/// because they are two halves of the same threat: deciding which extracted names <c>yara</c>'s line-oriented
/// output cannot round-trip, and rendering such a name into a log line without letting it forge one.
/// </summary>
internal static class YaraPathSafety
{
    #region Methods
    /// <summary>
    /// <c>true</c> when <paramref name="path"/> contains any C0 control character (U+0000 to U+001F). Such a name
    /// is legal in a zip entry and on POSIX, is written to disk verbatim by the extractor, and is an evasion
    /// attempt (ADR 0029 decision 11): <c>yara -r</c> echoes the scanned path on each header line, and that line is
    /// cut at its first CR or LF before anything parses it — the stdout reader breaks lines at CR, LF and CRLF and
    /// rejoins them with LF, on which <see cref="YaraCliOutput.ParseAll"/> then splits. So a CR or a newline in the
    /// name splits one hit across two physical lines and the real hit is dropped. CR and LF are therefore the only
    /// characters that actually break parsing; the whole C0 range is treated as unsafe because none of it has any
    /// business being in a package entry name and the recovery path costs only one file copy.
    /// </summary>
    internal static bool IsUnsafeName(string? path) => path is not null && path.Any(IsC0);

    /// <summary>
    /// The prefix of <paramref name="path"/> up to (not including) its first C0 control character — i.e. a
    /// conservative bound on how much of an unsafe name a <c>yara -r</c> header line can still carry, since that
    /// line is cut at its first CR or LF (see <see cref="IsUnsafeName"/>) and any earlier C0 character is cut here
    /// but not there. Returns <paramref name="path"/> unchanged when the name is safe.
    ///
    /// This truncation is attacker-chosen, and that is the whole point of computing it (ADR 0029 decision 15): an
    /// entry named <c>content/a.bin\nZZZ</c> truncates to <c>content/a.bin</c>, which the package can also ship as
    /// a real, innocent file — so the truncations are exactly the targets a batch hit must never be attributed to.
    /// </summary>
    internal static string TruncateAtFirstControl(string path)
    {
        var i = path.AsSpan().IndexOfAnyInRange('\0', (char)0x1F);
        return i < 0 ? path : path[..i];
    }

    /// <summary>
    /// Renders attacker-authored path text safe to log: every control, line/paragraph separator, bidi-control and
    /// invisible (zero-width, soft hyphen, Tag-block) character is replaced by a printable escape, so the text can
    /// never inject a line into our own log, reorder what an operator reads, or hide itself from the reader
    /// entirely. Ordinary paths (including non-ASCII segments and emoji) pass through unchanged. Backslashes are
    /// NOT doubled — keeping Windows paths readable is worth the theoretical ambiguity, since the escapes only ever
    /// stand in for characters that cannot legitimately appear in a path.
    ///
    /// Iteration is by <b>rune</b>, not by <c>char</c>: the Unicode Tag block (U+E0000–U+E007F) is astral, so a
    /// char-wise loop only ever sees its surrogate halves, which are ≥ 0xD800 and match no predicate — the block
    /// was structurally unreachable, and an escaper property-tested exhaustively "over the BMP" could not have
    /// caught it (measured in <c>data/results/packaging-anomalies-top100-2026-08-22.md</c>). Escapes are
    /// <c>\n</c>/<c>\r</c>/<c>\t</c>, then <c>\xNN</c> below U+0100, <c>\uXXXX</c> through the BMP, and
    /// <c>\U000E0041</c> beyond it. A lone surrogate is not a code point at all; it decodes to U+FFFD and is
    /// emitted as such, so no ill-formed UTF-16 reaches a log line or a JSON writer. The escaper itself is
    /// <see cref="UntrustedText.Escape"/>, shared with the SSA facts.
    /// </summary>
    internal static string Escape(string? text) => UntrustedText.Escape(text);

    /// <summary>
    /// <paramref name="path"/> relative to <paramref name="rootDir"/>, for display: a lexical prefix strip at a
    /// separator boundary, or <paramref name="path"/> unchanged when it is not under the root. Deliberately not
    /// <see cref="Path.GetRelativePath(string, string)"/>: that resolves through the platform normalizer, which turns
    /// a device-named entry (<c>COM1.dll</c>) into <c>\\.\COM1</c> on Windows (ADR 0030, sixth instance). The result
    /// is still package text; <see cref="Escape"/> it before it reaches a log line or a message.
    /// </summary>
    internal static string Relative(string? rootDir, string path) =>
        !string.IsNullOrEmpty(rootDir) && path.Length > rootDir.Length && path.StartsWith(rootDir, StringComparison.Ordinal)
        && (IsSeparator(rootDir[^1]) || IsSeparator(path[rootDir.Length]))
            ? path[rootDir.Length..].TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            : path;

    /// <summary>
    /// Attacker-influenced text items (paths, yara's own output lines) rendered for a log line or an exception
    /// message: each quoted and <see cref="Escape"/>d, at most <see cref="MaxListedItems"/> of them, the rest summarized
    /// as <c>", and N more"</c> so a package full of them cannot flood either. The one rendering both the CLI backend
    /// and the per-file <see cref="IYaraScanner.ScanFiles"/> loop (<see cref="YaraScanLoop.Run"/>) use, so every YARA
    /// message reads the same way.
    /// </summary>
    internal static string Bounded(IReadOnlyList<string> items) =>
        string.Join(", ", items.Take(MaxListedItems).Select(p => "'" + Escape(p) + "'"))
        + (items.Count > MaxListedItems ? $", and {items.Count - MaxListedItems} more" : string.Empty);

    /// <summary>
    /// The clause naming how many of a message's unscanned files no longer exist (ADR 0034: listed, then gone by scan
    /// time) — "1 of them no longer exists …" or "<paramref name="count"/> of them no longer exist …" — shared by the CLI
    /// backend, the YARA-X worker backend and <see cref="YaraScanLoop.Run"/> so all three say it the same way. Messages lead with it: the report's
    /// reason is bounded, and a trailing clause is the first thing the bound cuts.
    /// </summary>
    internal static string NoLongerExist(int count) =>
        count == 1 ? $"1 of them no longer exists ({RemovedAfterListed})" : $"{count} of them no longer exist (each {RemovedAfterListed})";

    private static bool IsSeparator(char c) => c == Path.DirectorySeparatorChar || c == Path.AltDirectorySeparatorChar;

    // The C0 range — the definition of "unsafe name" (ADR 0029 decision 11).
    private static bool IsC0(char c) => c <= (char)0x1F;
    #endregion

    #region Fields
    /// <summary>How many items <see cref="Bounded"/> names before summarizing the rest as ", and N more".</summary>
    internal const int MaxListedItems = 10;

    /// <summary>
    /// Why one listed file was not scanned when it is gone at scan time (ADR 0034) — the wording every backend uses
    /// for it. "Listed", not "extracted": it holds for both callers of <see cref="IYaraScanner.ScanFiles"/>, the
    /// extraction inventory and <see cref="IYaraScanner.ScanDirectory"/>'s own enumeration.
    /// </summary>
    internal const string NoLongerExists = "it no longer exists (" + RemovedAfterListed + ")";

    private const string RemovedAfterListed = "removed after it was listed";
    #endregion
}
