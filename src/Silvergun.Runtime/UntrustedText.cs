namespace Silvergun;

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// The one escaper for attacker-authored text (package entry names, yara output, string constants read from IL): every
/// control, line/paragraph separator, bidi-control and invisible (zero-width, soft hyphen, Tag-block) code point is
/// replaced by a printable escape, so the text cannot inject a line, reorder what a reader sees, or hide itself.
/// Ordinary text (non-ASCII, emoji) passes through unchanged. Never throws. In Silvergun.Runtime so the YARA worker can
/// use it without loading any analysis assembly (ADR 0033 decision 5).
/// </summary>
public static class UntrustedText
{
    #region Methods
    /// <summary>
    /// <paramref name="text"/> escaped for display. Backslashes are not doubled (Windows paths stay readable; the escapes
    /// only stand in for characters no path has). Iterates by rune, so the astral Tag block is seen; a lone surrogate
    /// decodes to U+FFFD and is emitted as such. Escapes are <c>\n</c>/<c>\r</c>/<c>\t</c>, then <c>\xNN</c> below U+0100,
    /// <c>\uXXXX</c> through the BMP, and <c>\U000E0041</c> beyond it.
    /// </summary>
    public static string Escape(string? text)
    {
        if (string.IsNullOrEmpty(text) || !text.Any(MayNeedEscape))
            return text ?? string.Empty;

        var sb = new StringBuilder(text.Length + 8);
        foreach (var rune in text.EnumerateRunes())
        {
            var cp = rune.Value;
            if (NeedsEscape(cp))
                sb.Append(EscapeOf(cp));
            else if (rune.IsBmp)
                sb.Append((char)cp);
            else
                sb.Append(rune.ToString());
        }
        return sb.ToString();
    }

    /// <summary>
    /// <paramref name="text"/> escaped losslessly, as data rather than for display, and bounded: what <see cref="Escape"/>
    /// escapes, plus a doubled backslash and a lone surrogate as <c>\uD800</c>, so distinct inputs stay distinct and the
    /// result is well-formed UTF-16. When the escaped text would exceed <paramref name="maxChars"/>, it keeps the escapes
    /// of the leading code points that fit and ends <c>…[+N chars, sha256:&lt;8 hex&gt;]</c> (ADR 0037 amendment a5), N the
    /// input chars cut and the hash over the whole input's UTF-16 code units. Only the kept prefix is escaped, so the cost
    /// of a huge input is its hash. Throws <see cref="ArgumentOutOfRangeException"/> when <paramref name="maxChars"/> is
    /// below 1.
    /// </summary>
    public static string EscapeBounded(string text, int maxChars) => EscapeBounded(text, maxChars, out _);

    /// <summary><see cref="EscapeBounded(string, int)"/>, also giving <see cref="HashOnly"/>, for one hash of the input.</summary>
    public static string EscapeBounded(string text, int maxChars, out string hashOnly) => EscapeBounded(text, maxChars, out hashOnly, out _);

    /// <summary>
    /// <see cref="EscapeBounded(string, int, out string)"/>, also saying whether the text was <paramref name="cut"/>, so a
    /// reader never has to parse the suffix (an uncut text may spell one).
    /// </summary>
    public static string EscapeBounded(string text, int maxChars, out string hashOnly, out bool cut)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxChars, 1);
        var hash = Hash(text);
        hashOnly = Suffix(text.Length, hash);
        var sb = new StringBuilder(Math.Min(text.Length, maxChars) + 8);
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            var pair = char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]);
            var cp = pair ? char.ConvertToUtf32(c, text[i + 1]) : c;
            var piece = c == '\\' ? @"\\"
                : char.IsSurrogate(c) && !pair ? "\\u" + ((int)c).ToString("X4")
                : NeedsEscape(cp) ? EscapeOf(cp)
                : pair ? text.Substring(i, 2)
                : null;
            if (sb.Length + (piece?.Length ?? 1) > maxChars)
                break;
            if (piece is null)
                sb.Append(c);
            else
                sb.Append(piece);
            i += pair ? 2 : 1;
        }
        cut = i < text.Length;
        return cut ? sb.Append(Suffix(text.Length - i, hash)).ToString() : sb.ToString();
    }

    /// <summary>
    /// The suffix <see cref="EscapeBounded(string, int)"/> ends a cut text with, standing alone for the whole of
    /// <paramref name="text"/>: <c>…[+N chars, sha256:&lt;8 hex&gt;]</c>, N its length.
    /// </summary>
    public static string HashOnly(string text) => Suffix(text.Length, Hash(text));

    /// <summary>
    /// Amendment a5's suffix for <paramref name="text"/> whose last <paramref name="cut"/> chars were dropped, hashed
    /// whole: the one renderer of it.
    /// </summary>
    public static string CutSuffix(string text, int cut) => Suffix(cut, Hash(text));

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(MemoryMarshal.AsBytes(text.AsSpan())))[..8];

    private static string Suffix(int cut, string hash) => $"…[+{cut} chars, sha256:{hash}]";

    private static string EscapeOf(int cp) => cp switch
    {
        Lf => "\\n",
        Cr => "\\r",
        Tab => "\\t",
        < 0x100 => "\\x" + cp.ToString("x2"),
        <= 0xFFFF => "\\u" + cp.ToString("x4"),
        _ => "\\U" + cp.ToString("X8"),
    };

    // The cheap char-wise filter guarding the rune path: a string with no escapable BMP code unit and no surrogate
    // cannot change under Escape. Surrogates always take the slow path: an astral code point may be Tag-block
    // (invisible), and a lone surrogate must not be echoed back raw.
    private static bool MayNeedEscape(char c) => NeedsEscape(c) || char.IsSurrogate(c);

    // Everything text must not carry raw, as a code point predicate (CLAUDE.md's hostile-text rules):
    //   * parser attacks   - C0, DEL and the C1 controls;
    //   * display attacks  - the line/paragraph separators and the bidi embeddings/overrides/isolates;
    //   * invisibility     - zero-width characters, the marks, the word joiner and invisible operators, the BOM, the
    //                        soft hyphen, and the astral Tag block (ADR 0031's InvisibleCharacter category).
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
               or >= 0xE0000 and <= 0xE007F;        // Unicode Tag block (astral)
    #endregion

    #region Fields
    private const char Tab = (char)0x09;
    private const char Lf = (char)0x0A;
    private const char Cr = (char)0x0D;
    #endregion
}
