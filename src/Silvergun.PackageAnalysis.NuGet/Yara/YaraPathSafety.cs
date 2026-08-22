namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Text;

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
    /// Renders attacker-authored path text safe to log: every control, line/paragraph separator and bidi-control
    /// character is replaced by a printable escape, so the text can never inject a line into our own log or
    /// reorder what an operator reads. Ordinary paths (including non-ASCII segments) pass through unchanged.
    /// Backslashes are NOT doubled — keeping Windows paths readable is worth the theoretical ambiguity, since the
    /// escapes only ever stand in for characters that cannot legitimately appear in a path.
    /// </summary>
    internal static string Escape(string? text)
    {
        if (string.IsNullOrEmpty(text) || !text.Any(NeedsEscape))
            return text ?? string.Empty;

        var sb = new StringBuilder(text.Length + 8);
        foreach (var c in text)
        {
            if (!NeedsEscape(c))
                sb.Append(c);
            else
                sb.Append(c switch
                {
                    Lf => "\\n",
                    Cr => "\\r",
                    Tab => "\\t",
                    < (char)0x100 => "\\x" + ((int)c).ToString("x2"),
                    _ => "\\u" + ((int)c).ToString("x4"),
                });
        }
        return sb.ToString();
    }

    // The C0 range — the definition of "unsafe name" (ADR 0029 decision 11).
    private static bool IsC0(char c) => c <= (char)0x1F;

    // Everything the log must not carry raw: C0, DEL and the C1 controls, plus the Unicode line and paragraph
    // separators and the bidirectional overrides/isolates (CLAUDE.md's hostile-text rules). A deliberate superset
    // of IsC0: hiding or reordering text in front of a reader is a distinct attack from breaking the parser.
    private static bool NeedsEscape(char c) =>
        IsC0(c)
        || c is >= (char)0x7F and <= (char)0x9F        // DEL and the C1 controls
             or (char)0x2028 or (char)0x2029           // LINE / PARAGRAPH SEPARATOR
             or >= (char)0x202A and <= (char)0x202E    // bidi embeddings and overrides
             or >= (char)0x2066 and <= (char)0x2069;   // bidi isolates
    #endregion

    #region Fields
    private const char Tab = (char)0x09;
    private const char Lf = (char)0x0A;
    private const char Cr = (char)0x0D;
    #endregion
}
