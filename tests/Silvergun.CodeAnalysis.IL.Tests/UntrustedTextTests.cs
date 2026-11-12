namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="UntrustedText"/> (docs/agent/tasks/ssa-facts-s4.md §3, "Text"): <see cref="UntrustedText.EscapeBounded(string, int)"/>
/// is lossless (a backslash doubled, a lone surrogate as <c>\uD800</c>), always well-formed UTF-16, and bounded with
/// amendment a5's <c>…[+N chars, sha256:&lt;8 hex&gt;]</c> suffix; <see cref="UntrustedText.HashOnly"/> is that suffix alone.
/// Hostile characters are built from code points here, never written as escapes in the source (a typed escape once
/// landed in a file as the raw character). The hash oracle is SHA-256 over the UTF-16 code units, little-endian, written
/// independently of the code under test.
/// </summary>
public sealed class UntrustedTextTests
{
    #region Methods
    // ---- EscapeBounded: what is escaped ---------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("cmd.exe")]
    [InlineData("https://example.org/a?b=c")]
    public void EscapeBounded_PlainText_Unchanged(string text) =>
        Assert.Equal(text, UntrustedText.EscapeBounded(text, 256));

    [Fact]
    public void EscapeBounded_Backslash_IsDoubled()
    {
        var text = "C:" + Bs + "Users" + Bs + "x";

        Assert.Equal("C:" + Bs + Bs + "Users" + Bs + Bs + "x", UntrustedText.EscapeBounded(text, 256));
    }

    // Lossless: the text of an escape and the character it stands for stay distinct.
    [Fact]
    public void EscapeBounded_LiteralEscapeText_StaysDistinctFromTheCharacter()
    {
        var literal = UntrustedText.EscapeBounded(Bs + "n", 256);
        var newline = UntrustedText.EscapeBounded(C(0x0A), 256);
        var literalSurrogate = UntrustedText.EscapeBounded(Bs + "uD800", 256);
        var surrogate = UntrustedText.EscapeBounded(C(0xD800), 256);

        Assert.Equal(Bs + Bs + "n", literal);
        Assert.Equal(Bs + "n", newline);
        Assert.Equal(Bs + Bs + "uD800", literalSurrogate);
        Assert.Equal(Bs + "uD800", surrogate);
    }

    [Theory]
    [InlineData(0xD800, "uD800")]
    [InlineData(0xDBFF, "uDBFF")]
    [InlineData(0xDC00, "uDC00")]
    [InlineData(0xDFFF, "uDFFF")]
    public void EscapeBounded_LoneSurrogate_EscapedAsUHex(int surrogate, string escape)
    {
        Assert.Equal("a" + Bs + escape + "b", UntrustedText.EscapeBounded("a" + C(surrogate) + "b", 256));
        Assert.Equal(Bs + escape, UntrustedText.EscapeBounded(C(surrogate), 256));
    }

    // A low surrogate before a high one is two lone surrogates, not a pair.
    [Fact]
    public void EscapeBounded_ReversedPair_BothEscaped() =>
        Assert.Equal(Bs + "uDC00" + Bs + "uD800", UntrustedText.EscapeBounded(C(0xDC00) + C(0xD800), 256));

    // A high surrogate as the last char has no partner.
    [Fact]
    public void EscapeBounded_HighSurrogateAtEnd_Escaped() =>
        Assert.Equal("ab" + Bs + "uD83D", UntrustedText.EscapeBounded("ab" + C(0xD83D), 256));

    [Fact]
    public void EscapeBounded_ValidPair_PassesThrough()
    {
        var emoji = char.ConvertFromUtf32(0x1F600);

        Assert.Equal("x" + emoji + "y", UntrustedText.EscapeBounded("x" + emoji + "y", 256));
    }

    [Fact]
    public void EscapeBounded_TagBlockAstral_EscapedAsBigU() =>
        Assert.Equal("a" + Bs + "U000E0041" + "b", UntrustedText.EscapeBounded("a" + char.ConvertFromUtf32(0xE0041) + "b", 256));

    [Theory]
    [InlineData(0x0A, "n")]
    [InlineData(0x0D, "r")]
    [InlineData(0x09, "t")]
    [InlineData(0x00, "x00")]
    [InlineData(0x1B, "x1b")]
    [InlineData(0x7F, "x7f")]
    [InlineData(0x85, "x85")]
    [InlineData(0xAD, "xad")]
    [InlineData(0x200B, "u200b")]
    [InlineData(0x202E, "u202e")]
    [InlineData(0x2066, "u2066")]
    [InlineData(0x2028, "u2028")]
    [InlineData(0xFEFF, "ufeff")]
    public void EscapeBounded_ControlBidiInvisible_Escaped(int codePoint, string escape) =>
        Assert.Equal("a" + Bs + escape + "b", UntrustedText.EscapeBounded("a" + C(codePoint) + "b", 256));

    // What the display escaper (YaraPathSafety's, moved verbatim) does differently: no backslash doubling, and a lone
    // surrogate becomes U+FFFD. EscapeBounded agrees with it on everything else.
    [Fact]
    public void Escape_DisplayForm_KeepsBackslash_AndReplacesALoneSurrogate()
    {
        Assert.Equal("C:" + Bs + "x", UntrustedText.Escape("C:" + Bs + "x"));
        Assert.Equal("a" + C(0xFFFD) + "b", UntrustedText.Escape("a" + C(0xD800) + "b"));
        Assert.Equal("a" + Bs + "u202e" + Bs + "n", UntrustedText.Escape("a" + C(0x202E) + C(0x0A)));
        Assert.Equal(string.Empty, UntrustedText.Escape(null));
    }

    // ---- EscapeBounded: the cut -----------------------------------------------------------------------------------------

    [Fact]
    public void EscapeBounded_OverMax_KeepsPrefixAndAppendsCutCountAndHash()
    {
        var text = new string('A', 300);

        var bounded = UntrustedText.EscapeBounded(text, 256);

        Assert.Equal(new string('A', 256) + Ellipsis + "[+44 chars, sha256:" + Sha8(text) + "]", bounded);
    }

    [Fact]
    public void EscapeBounded_ExactlyMax_NotCut()
    {
        Assert.Equal("abcd", UntrustedText.EscapeBounded("abcd", 4));
        // The escaped length is what counts: "a\n" is three chars escaped.
        Assert.Equal("a" + Bs + "n", UntrustedText.EscapeBounded("a" + C(0x0A), 3));
    }

    [Fact]
    public void EscapeBounded_OneOverMax_Cut()
    {
        var bounded = UntrustedText.EscapeBounded("abcde", 4);

        Assert.Equal("abcd" + Suffix(1, "abcde"), bounded);
    }

    // The cut is between code points: a pair that does not fit whole is cut whole, and N counts its two chars.
    [Fact]
    public void EscapeBounded_Cut_NeverSplitsASurrogatePair()
    {
        var text = "a" + char.ConvertFromUtf32(0x1F600) + "b";

        var bounded = UntrustedText.EscapeBounded(text, 2);

        Assert.Equal("a" + Suffix(3, text), bounded);
        Assert.True(WellFormed(bounded));
    }

    // An escape that does not fit whole is cut whole: "\n" needs 2, "\U000E0041" 10, "\uD800" 6, "\\" 2.
    [Theory]
    [InlineData(0x0A, 2)]
    [InlineData(0xE0041, 10)]
    [InlineData(0xD800, 6)]
    [InlineData(0x5C, 2)]
    public void EscapeBounded_Cut_NeverSplitsAnEscape(int codePoint, int escapedLength)
    {
        var piece = codePoint > 0xFFFF ? char.ConvertFromUtf32(codePoint) : C(codePoint);
        var text = "a" + piece;

        var cut = UntrustedText.EscapeBounded(text, escapedLength);
        var whole = UntrustedText.EscapeBounded(text, escapedLength + 1);

        Assert.Equal("a" + Suffix(piece.Length, text), cut);
        Assert.Equal(1 + escapedLength, whole.Length);
        Assert.DoesNotContain(Ellipsis, whole);
    }

    // The escaped prefix never exceeds maxChars, on any input.
    [Fact]
    public void EscapeBounded_Prefix_NeverExceedsMax()
    {
        var random = new Random(4_2);
        for (var round = 0; round < 500; round++)
        {
            var text = RandomHostile(random, random.Next(0, 40));
            var max = random.Next(1, 30);

            var bounded = UntrustedText.EscapeBounded(text, max);

            var at = bounded.IndexOf(Ellipsis + "[+", StringComparison.Ordinal);
            var prefix = at < 0 ? bounded : bounded[..at];
            Assert.True(prefix.Length <= max, $"Round {round}: a {prefix.Length}-char prefix over max {max}.");
            if (at >= 0)
                Assert.EndsWith(" chars, sha256:" + Sha8(text) + "]", bounded, StringComparison.Ordinal);
        }
    }

    // Whatever comes in, what goes out is well-formed UTF-16 with no raw control, bidi or invisible character.
    [Fact]
    public void EscapeBounded_AnyInput_WellFormedAndNothingHostileRaw()
    {
        var random = new Random(7);
        for (var round = 0; round < 500; round++)
        {
            var text = RandomHostile(random, random.Next(0, 40));

            var bounded = UntrustedText.EscapeBounded(text, random.Next(1, 60));

            Assert.True(WellFormed(bounded), $"Round {round}: ill-formed output.");
            Assert.DoesNotContain(bounded.EnumerateRunes(), r => IsHostile(r.Value));
        }
    }

    // Lossless: distinct inputs that fit stay distinct.
    [Fact]
    public void EscapeBounded_DistinctInputs_DistinctOutputs()
    {
        var random = new Random(11);
        var inputs = Enumerable.Range(0, 2000).Select(_ => RandomHostile(random, random.Next(0, 6))).Distinct(StringComparer.Ordinal).ToArray();

        var outputs = inputs.Select(t => UntrustedText.EscapeBounded(t, 1000)).ToArray();

        Assert.Equal(inputs.Length, outputs.Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void EscapeBounded_MaxBelowOne_Throws(int max)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => UntrustedText.EscapeBounded("x", max));
        Assert.Throws<ArgumentOutOfRangeException>(() => UntrustedText.EscapeBounded("x", max, out _));
    }

    // ---- HashOnly ------------------------------------------------------------------------------------------------------

    [Fact]
    public void HashOnly_IsTheSuffixForTheWholeText()
    {
        Assert.Equal(Ellipsis + "[+7 chars, sha256:" + Sha8("cmd.exe") + "]", UntrustedText.HashOnly("cmd.exe"));
        // SHA-256 of nothing starts e3b0c442.
        Assert.Equal(Ellipsis + "[+0 chars, sha256:e3b0c442]", UntrustedText.HashOnly(string.Empty));
    }

    // The hash is over UTF-16 code units, so a lone surrogate hashes without being replaced first.
    [Fact]
    public void HashOnly_LoneSurrogate_HashedAsCodeUnits()
    {
        var withSurrogate = "a" + C(0xD800);
        var withReplacement = "a" + C(0xFFFD);

        Assert.NotEqual(UntrustedText.HashOnly(withSurrogate), UntrustedText.HashOnly(withReplacement));
        Assert.Equal(Suffix(2, withSurrogate), UntrustedText.HashOnly(withSurrogate));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(1000)]
    public void EscapeBounded_OutHashOnly_EqualsHashOnly_CutOrNot(int max)
    {
        var text = "abc" + C(0xD800) + "def" + C(0x202E);

        _ = UntrustedText.EscapeBounded(text, max, out var hashOnly);

        Assert.Equal(UntrustedText.HashOnly(text), hashOnly);
    }

    // The four-argument overload says whether the text was cut, and gives the same text and hash-only form.
    [Theory]
    [InlineData("abcd", 4, false)]
    [InlineData("abcde", 4, true)]
    [InlineData("", 1, false)]
    public void EscapeBounded_OutCut_TrueOnlyWhenCut(string text, int max, bool expected)
    {
        var bounded = UntrustedText.EscapeBounded(text, max, out var hashOnly, out var cut);

        Assert.Equal(expected, cut);
        Assert.Equal(UntrustedText.EscapeBounded(text, max), bounded);
        Assert.Equal(UntrustedText.HashOnly(text), hashOnly);
    }

    // An escape that pushes the text over the bound is a cut, though the raw text is within it.
    [Fact]
    public void EscapeBounded_OutCut_EscapeOverTheBound_IsCut()
    {
        _ = UntrustedText.EscapeBounded("ab" + C(0x0A), 3, out _, out var cut);
        _ = UntrustedText.EscapeBounded("ab" + C(0x0A), 4, out _, out var whole);

        Assert.True(cut);
        Assert.False(whole);
    }

    // A text that spells a suffix is not cut: the flag, not the text, says so.
    [Fact]
    public void EscapeBounded_OutCut_TextSpellingASuffix_NotCut()
    {
        var spelled = Ellipsis + "[+7 chars, sha256:0123abcd]";

        var bounded = UntrustedText.EscapeBounded(spelled, 256, out _, out var cut);

        Assert.Equal(spelled, bounded);
        Assert.False(cut);
    }

    [Fact]
    public void EscapeBounded_OutOverload_SameTextAsTwoArgument()
    {
        var text = new string('x', 50) + C(0x0A) + C(0xDC00);

        Assert.Equal(UntrustedText.EscapeBounded(text, 20), UntrustedText.EscapeBounded(text, 20, out _));
        Assert.Equal(UntrustedText.EscapeBounded(text, 200), UntrustedText.EscapeBounded(text, 200, out _));
    }

    // Reachability.BoundNameTo now renders its suffix through UntrustedText: its output is unchanged. The oracle is the
    // a5 rule written out: keep maxChars chars (one fewer when that would split a pair), then the suffix over the whole.
    [Theory]
    [InlineData(10, 5)]
    [InlineData(10, 10)]
    [InlineData(10, 11)]
    [InlineData(4, 1)]
    public void BoundNameTo_Unchanged(int length, int max)
    {
        var name = new string('n', length);
        var expected = length <= max ? name : name[..max] + Suffix(length - max, name);

        Assert.Equal(expected, Reachability.BoundNameTo(name, max));
    }

    [Fact]
    public void BoundNameTo_CutAtAHighSurrogate_KeepsOneFewer()
    {
        var name = "ab" + char.ConvertFromUtf32(0x1F600) + "cd";

        Assert.Equal("ab" + Suffix(4, name), Reachability.BoundNameTo(name, 3));
        Assert.Equal("ab" + char.ConvertFromUtf32(0x1F600) + Suffix(2, name), Reachability.BoundNameTo(name, 4));
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static string C(int codeUnit) => ((char)codeUnit).ToString();

    // Over the raw UTF-16 code units, little-endian, written out by hand: Encoding.Unicode would replace a lone surrogate
    // with U+FFFD first.
    internal static string Sha8(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(text.SelectMany(c => new[] { (byte)c, (byte)(c >> 8) }).ToArray()))[..8];

    private static string Suffix(int cut, string whole) => $"{Ellipsis}[+{cut} chars, sha256:{Sha8(whole)}]";

    internal static bool WellFormed(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                i++;
            else if (char.IsSurrogate(text[i]))
                return false;
        }
        return true;
    }

    // The escaper's predicate, written from its documentation: C0, DEL, C1, soft hyphen, zero-width, marks, separators,
    // bidi, word joiner and invisible operators, BOM, Tag block.
    private static bool IsHostile(int cp) =>
        cp <= 0x1F || cp is >= 0x7F and <= 0x9F or 0xAD or >= 0x200B and <= 0x200F or 0x2028 or 0x2029 or >= 0x202A and <= 0x202E
            or >= 0x2060 and <= 0x2064 or >= 0x2066 and <= 0x2069 or 0xFEFF or >= 0xE0000 and <= 0xE007F;

    // Text drawn from the classes the escaper treats differently: ASCII, backslash, controls, bidi, lone surrogates of
    // both halves, valid pairs, Tag-block pairs, and ordinary non-ASCII.
    private static string RandomHostile(Random random, int pieces)
    {
        var builder = new StringBuilder();
        for (var i = 0; i < pieces; i++)
        {
            builder.Append(random.Next(10) switch
            {
                0 => C(0xD800 + random.Next(0x400)),
                1 => C(0xDC00 + random.Next(0x400)),
                2 => char.ConvertFromUtf32(0x1F600 + random.Next(0x40)),
                3 => char.ConvertFromUtf32(0xE0000 + random.Next(0x80)),
                4 => C(random.Next(0x20)),
                5 => C(0x202A + random.Next(5)),
                6 => Bs,
                7 => C(0xE9),
                _ => C('a' + random.Next(26)),
            });
        }
        return builder.ToString();
    }
    #endregion

    #region Fields
    private const string Bs = "\\";

    private static readonly string Ellipsis = ((char)0x2026).ToString();
    #endregion
}
