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
    /// caught it (measured in <c>docs/agent/measurements/packaging-anomalies-top100-2026-08-22.md</c>). Escapes are
    /// <c>\n</c>/<c>\r</c>/<c>\t</c>, then <c>\xNN</c> below U+0100, <c>\uXXXX</c> through the BMP, and
    /// <c>\U000E0041</c> beyond it. A lone surrogate is not a code point at all; it decodes to U+FFFD and is
    /// emitted as such, so no ill-formed UTF-16 reaches a log line or a JSON writer.
    /// </summary>
    internal static string Escape(string? text)
    {
        if (string.IsNullOrEmpty(text) || !text.Any(MayNeedEscape))
            return text ?? string.Empty;

        var sb = new StringBuilder(text.Length + 8);
        foreach (var rune in text.EnumerateRunes())
        {
            var cp = rune.Value;
            if (NeedsEscape(cp))
                sb.Append(cp switch
                {
                    Lf => "\\n",
                    Cr => "\\r",
                    Tab => "\\t",
                    < 0x100 => "\\x" + cp.ToString("x2"),
                    <= 0xFFFF => "\\u" + cp.ToString("x4"),
                    _ => "\\U" + cp.ToString("X8"),
                });
            else if (rune.IsBmp)
                sb.Append((char)cp);
            else
                sb.Append(rune.ToString());   // a surrogate pair, re-emitted verbatim (emoji, CJK ext, …)
        }
        return sb.ToString();
    }

    // The C0 range — the definition of "unsafe name" (ADR 0029 decision 11).
    private static bool IsC0(char c) => c <= (char)0x1F;

    // The cheap char-wise filter guarding the rune path: a string with no escapable BMP code unit AND no surrogate
    // cannot change under Escape. Surrogates always route to the slow path — an astral code point may be Tag-block
    // (invisible), and a lone surrogate must not be echoed back raw.
    private static bool MayNeedEscape(char c) => NeedsEscape(c) || char.IsSurrogate(c);

    // Everything the log must not carry raw, as a CODE POINT predicate. Three families, all of them things a
    // package entry name has no legitimate use for (CLAUDE.md's hostile-text rules):
    //   * parser attacks   — C0 (a deliberate superset of IsC0), DEL and the C1 controls;
    //   * display attacks  — the line/paragraph separators and the bidi embeddings/overrides/isolates;
    //   * invisibility     — zero-width characters, the marks, the word joiner and invisible operators, the BOM,
    //                        the soft hyphen, and the astral Tag block (ADR 0031's InvisibleCharacter category,
    //                        whose whole premise is that a reader cannot see it — reporting such a name with the
    //                        character still in it reports nothing at all, ADR 0031 decision 4).
    private static bool NeedsEscape(int cp) =>
        cp <= 0x1F                                  // C0
        || cp is 0x00AD                             // SOFT HYPHEN
               or >= 0x7F and <= 0x9F               // DEL and the C1 controls
               or >= 0x200B and <= 0x200D           // ZERO WIDTH SPACE / NON-JOINER / JOINER
               or 0x200E or 0x200F                  // LEFT-TO-RIGHT and RIGHT-TO-LEFT MARK
               or 0x2028 or 0x2029                  // LINE / PARAGRAPH SEPARATOR
               or >= 0x202A and <= 0x202E           // bidi embeddings and overrides
               or >= 0x2060 and <= 0x2064           // WORD JOINER and the invisible operators
               or >= 0x2066 and <= 0x2069           // bidi isolates
               or 0xFEFF                            // ZERO WIDTH NO-BREAK SPACE / BOM
               or >= 0xE0000 and <= 0xE007F;        // Unicode Tag block (astral — see Escape)
    #endregion

    #region Fields
    private const char Tab = (char)0x09;
    private const char Lf = (char)0x0A;
    private const char Cr = (char)0x0D;
    #endregion
}
