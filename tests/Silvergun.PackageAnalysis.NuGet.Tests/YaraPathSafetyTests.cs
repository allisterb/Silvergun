namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for <see cref="YaraPathSafety"/> (ADR 0029, widened by ADR 0031 decision 4). Two halves of one
/// threat, so two halves of one test class:
/// <list type="number">
/// <item><see cref="YaraPathSafety.IsUnsafeName"/> decides which extracted names the classic-CLI backend's
/// line-oriented output cannot round-trip. Getting it <b>too narrow</b> re-opens the ADR 0029 false negative (a
/// hit silently dropped while the scan reads <c>Completed</c>); getting it <b>too wide</b> pushes ordinary
/// packages — spaces, non-ASCII segments, Windows backslashes — down the per-file copy-and-rescan path. The
/// definition is exactly the C0 range (U+0000..U+001F), nothing else.</item>
/// <item><see cref="YaraPathSafety.Escape"/> renders that same attacker-authored text into <b>our own log</b>,
/// and (ADR 0031 decision 4) into every entry name that leaves the analyzer. The example-based cases below pin
/// the shape of each escape, but the load-bearing assertions are the <b>properties</b>: whatever a package names
/// its entries, the escaped rendering can never carry a control character, a display control, or an
/// <b>invisible</b> one, and can therefore never forge a log line, reorder what an operator reads, or hide
/// itself from the reader entirely.</item>
/// </list>
///
/// <para><b>The properties are exhaustive over more than the BMP, deliberately.</b> They used to run over the
/// 65,536 UTF-16 code units and nothing else, and that is precisely how the ADR 0031 decision 4 defect shipped:
/// the Unicode Tag block (U+E0000–U+E007F) is a full invisible ASCII alphabet, it is <b>astral</b>, and a
/// char-wise domain only ever presents its surrogate halves — which are ≥ 0xD800 and match no predicate. The
/// escaper was structurally unable to see the block and the property was structurally unable to notice. Measured
/// in <c>data/results/packaging-anomalies-top100-2026-08-22.md</c>. Exhaustive over the wrong domain
/// reads exactly like exhaustive, so <see cref="EveryCodePointUnderTest"/> now covers the whole BMP, the whole
/// Tag block, and a sample of every other plane — and
/// <see cref="EveryCodePointUnderTest_CoversTheWholeTagBlockAndASampleOfEveryOtherPlane"/> guards the domain
/// itself against being narrowed back.</para>
///
/// <para><b>The escaper is a strict superset of ADR 0031's InvisibleCharacter category, on purpose.</b> U+200E/F
/// and U+2060–U+2064 are escaped here but are not categorised as anomalies: "never print this raw" is a cheaper
/// and safer bar than "call this an attack". Widening the categories to match is <i>not</i> the way to make the
/// two agree.</para>
///
/// Both members are <c>internal</c>; this project sees them through
/// <c>Silvergun.PackageAnalysis.NuGet</c>'s <c>InternalsVisibleTo</c>.
/// </summary>
public sealed class YaraPathSafetyTests
{
    #region Methods
    // --- IsUnsafeName: the C0 range, anywhere in the path ---------------------------------------------------------

    // Every C0 control character is unsafe wherever it appears — in the file name, in a DIRECTORY segment, leading
    // or trailing. LF and CR are the two that actually split `yara -r`'s echoed-path output across two physical
    // lines (the ADR 0029 defect); the rest of the range is unsafe by policy, since none of it can legitimately
    // appear in a package entry name.
    [Theory]
    // LF — the exact character that produced the measured false negative.
    [InlineData("/tmp/pkg/lib/net8.0/n\nl.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/trailing.bin\n")]
    [InlineData("\n/tmp/pkg/lib/net8.0/leading.bin")]
    // ...in a DIRECTORY segment, not just the file name (spec item 1, called out explicitly).
    [InlineData("/tmp/pkg/li\nb/net8.0/plain.bin")]
    [InlineData("/tmp/pkg/lib/ne\rt8.0/plain.bin")]
    // CR, NUL, and representative members of the rest of C0 (first, bell, tab, vertical tab, escape, last).
    [InlineData("/tmp/pkg/lib/net8.0/c\rr.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/nu\0l.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/so\u0001h.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/be\u0007ll.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/ta\tb.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/v\u000Bt.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/e\u001Bsc.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/u\u001Fs.bin")]
    // CRLF together, the classic pair.
    [InlineData("/tmp/pkg/lib/net8.0/cr\r\nlf.bin")]
    public void IsUnsafeName_ForAnyC0ControlCharacter_IsTrue(string path)
    {
        Assert.True(YaraPathSafety.IsUnsafeName(path));
    }

    // Ordinary and merely unusual names are NOT unsafe. Widening the predicate past C0 would send legitimate
    // packages — spaces, accents, CJK, emoji, Windows separators — down the per-file copy-and-rescan path for no
    // security gain. DEL (0x7F) and the C1 controls are deliberately excluded: they do not break yara's
    // line-oriented output (only CR/LF do), so they are a LOGGING concern (see Escape), not a SCANNING one.
    [Theory]
    [InlineData("/tmp/pkg/lib/net8.0/plain.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/with space.bin")]
    [InlineData("/tmp/pkg/content/uni-caf\u00E9/x.bin")]
    [InlineData("/tmp/pkg/content/\u65E5\u672C\u8A9E/x.bin")]
    [InlineData("/tmp/pkg/content/\U0001F600.bin")]
    [InlineData(@"C:\pkg\lib\net8.0\plain.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/back\\slash.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/de\u007Fl.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/nel\u0085.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/c1\u009F.bin")]
    // The bidi overrides are a display attack, not a parser attack: escaped in logs, but not "unsafe to scan".
    [InlineData("/tmp/pkg/lib/net8.0/rlo\u202Enib.exe")]
    // Same for the invisibles ADR 0031 decision 4 added to the escaper: they hide the name from a READER, they do
    // not split a yara header line, so they must not widen the copy-and-rescan path either.
    [InlineData("/tmp/pkg/lib/net8.0/zwsp\u200B.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/shy\u00AD.bin")]
    [InlineData("/tmp/pkg/lib/net8.0/tag\U000E0041.bin")]
    [InlineData("")]
    public void IsUnsafeName_ForOrdinaryOrMerelyUnusualNames_IsFalse(string path)
    {
        Assert.False(YaraPathSafety.IsUnsafeName(path));
    }

    // Null-safe: a null path is not a name at all, so it is not an unsafe name (and must not throw). The
    // partitioning call site feeds it real Directory.GetFiles output, but the guard is part of the contract.
    [Fact]
    public void IsUnsafeName_ForNull_IsFalseAndDoesNotThrow()
    {
        Assert.False(YaraPathSafety.IsUnsafeName(null));
    }

    // --- Escape: the shorthands, \xNN, \uXXXX, and identity --------------------------------------------------------

    // The three shorthands exist because CR/LF/TAB are the escapes a reader recognizes at a glance, and CR/LF are
    // the two characters the whole ADR is about.
    [Theory]
    [InlineData("\n", "\\n")]
    [InlineData("\r", "\\r")]
    [InlineData("\t", "\\t")]
    [InlineData("a\nb", "a\\nb")]
    [InlineData("\r\n", "\\r\\n")]
    public void Escape_ForCrLfTab_UsesTheShorthand(string input, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.Escape(input));
    }

    // Everything else below U+0100 that must not be logged raw — the rest of C0, DEL, and the C1 controls — renders
    // as two-digit lowercase \xNN.
    [Theory]
    [InlineData("\0", "\\x00")]
    [InlineData("\u0001", "\\x01")]
    [InlineData("\u0007", "\\x07")]
    [InlineData("\u000B", "\\x0b")]
    [InlineData("\u001B", "\\x1b")]
    [InlineData("\u001F", "\\x1f")]
    [InlineData("\u007F", "\\x7f")]
    [InlineData("\u0085", "\\x85")]
    [InlineData("\u009F", "\\x9f")]
    public void Escape_ForOtherC0AndDelAndC1_UsesLowercaseHexByteEscape(string input, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.Escape(input));
    }

    // The characters that reorder or hide text in front of an operator reading the log — the Unicode line and
    // paragraph separators and the bidi embeddings/overrides/isolates — render as four-digit lowercase \uXXXX.
    [Theory]
    [InlineData("\u2028", "\\u2028")]
    [InlineData("\u2029", "\\u2029")]
    [InlineData("\u202A", "\\u202a")]
    [InlineData("\u202B", "\\u202b")]
    [InlineData("\u202C", "\\u202c")]
    [InlineData("\u202D", "\\u202d")]
    [InlineData("\u202E", "\\u202e")]
    [InlineData("\u2066", "\\u2066")]
    [InlineData("\u2067", "\\u2067")]
    [InlineData("\u2068", "\\u2068")]
    [InlineData("\u2069", "\\u2069")]
    public void Escape_ForSeparatorsAndBidiControls_UsesUnicodeEscape(string input, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.Escape(input));
    }

    // Ordinary path text is returned unchanged — including non-ASCII segments and Windows backslashes, which are
    // deliberately NOT doubled (a log line has to stay readable, and the escapes only ever stand in for characters
    // that cannot legitimately appear in a path).
    [Theory]
    [InlineData("lib/net8.0/plain.bin")]
    [InlineData("lib/net8.0/with space.bin")]
    [InlineData("content/uni-caf\u00E9/x.bin")]
    [InlineData("content/\u65E5\u672C\u8A9E/x.bin")]
    [InlineData(@"C:\pkg\lib\net8.0\plain.bin")]
    [InlineData("content/\U0001F600.bin")]
    public void Escape_ForOrdinaryText_IsIdentity(string input)
    {
        Assert.Equal(input, YaraPathSafety.Escape(input));
    }

    // Degenerate inputs collapse to the empty string; Escape is never null, so a message template can always
    // interpolate it.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Escape_ForNullOrEmpty_IsEmptyString(string? input)
    {
        Assert.Equal(string.Empty, YaraPathSafety.Escape(input));
    }

    // A realistic hostile name mixing all three escape forms with ordinary text — the shape that actually reaches a
    // log line from RecoverUnsafeNamed's Describe().
    [Fact]
    public void Escape_ForMixedHostileName_EscapesEachClassInPlace()
    {
        Assert.Equal(
            @"lib/net8.0/n\nl\u202ednb.exe\x00",
            YaraPathSafety.Escape("lib/net8.0/n\nl\u202Ednb.exe\0"));
    }

    // --- Escape: the invisible alphabet (ADR 0031 decision 4) ------------------------------------------------------

    // The SOFT HYPHEN is the only invisible character below U+0100, so it takes the two-digit form. It renders as
    // nothing at all in most contexts, which is what makes "evil<SHY>name.dll" read as "evilname.dll".
    [Theory]
    [InlineData("\u00AD", @"\xad")]
    [InlineData("content/evil\u00ADname.dll", @"content/evil\xadname.dll")]
    public void Escape_ForTheSoftHyphen_UsesLowercaseHexByteEscape(string input, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.Escape(input));
    }

    // The BMP invisibles: the zero-width trio, the directional MARKS (distinct from the embeddings/overrides
    // above), the word joiner and the invisible math operators, and the BOM. Each renders as four-digit
    // LOWERCASE \uXXXX.
    //
    // U+200E/U+200F and U+2060-U+2064 are escaped but are NOT in ADR 0031's InvisibleCharacter category; see the
    // class summary for why that asymmetry is intentional.
    [Theory]
    [InlineData("\u200B", @"\u200b")]   // ZERO WIDTH SPACE — the character the measurement caught reported raw
    [InlineData("\u200C", @"\u200c")]   // ZERO WIDTH NON-JOINER
    [InlineData("\u200D", @"\u200d")]   // ZERO WIDTH JOINER
    [InlineData("\u200E", @"\u200e")]   // LEFT-TO-RIGHT MARK
    [InlineData("\u200F", @"\u200f")]   // RIGHT-TO-LEFT MARK
    [InlineData("\u2060", @"\u2060")]   // WORD JOINER
    [InlineData("\u2061", @"\u2061")]   // FUNCTION APPLICATION
    [InlineData("\u2062", @"\u2062")]   // INVISIBLE TIMES
    [InlineData("\u2063", @"\u2063")]   // INVISIBLE SEPARATOR
    [InlineData("\u2064", @"\u2064")]   // INVISIBLE PLUS
    [InlineData("\uFEFF", @"\ufeff")]   // ZERO WIDTH NO-BREAK SPACE / BOM
    public void Escape_ForZeroWidthAndInvisibleBmpCharacters_UsesLowercaseUnicodeEscape(string input, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.Escape(input));
    }

    // The zero-width case in an entry name, which is where the whole point of the category lives: unescaped, the
    // hostile name and the innocent one it impersonates print identically. Escaped, they do not.
    [Fact]
    public void Escape_ForAZeroWidthSpaceInAnEntryName_MakesItDistinguishableFromTheInnocentName()
    {
        var escaped = YaraPathSafety.Escape("content/pay" + Zwsp + "load.bin");

        Assert.Equal(@"content/pay\u200bload.bin", escaped);
        Assert.NotEqual(YaraPathSafety.Escape("content/payload.bin"), escaped);
    }

    // --- Escape: the astral Tag block, and the astral text that must NOT be touched --------------------------------

    // The Unicode Tag block (U+E0000-U+E007F) is a full invisible ASCII alphabet: U+E0041 is TAG LATIN CAPITAL
    // LETTER A and renders as nothing. It is ASTRAL, so the pre-fix char-wise loop only ever saw its surrogate
    // halves and the block was structurally unreachable.
    //
    // Its escape is the ONE uppercase-hex shape in the whole scheme: \U followed by eight UPPERCASE hex digits.
    // Escape_ForEveryEscapedCodePoint_UsesLowercaseHexExceptTheAstralForm is what keeps it the only one.
    [Theory]
    [InlineData(0xE0000, @"\U000E0000")]   // first
    [InlineData(0xE0001, @"\U000E0001")]   // LANGUAGE TAG
    [InlineData(0xE0020, @"\U000E0020")]   // TAG SPACE
    [InlineData(0xE0041, @"\U000E0041")]   // TAG LATIN CAPITAL LETTER A — the shape the fix names
    [InlineData(0xE007F, @"\U000E007F")]   // CANCEL TAG, last
    public void Escape_ForTheAstralTagBlock_UsesTheUppercaseEightDigitEscape(int codePoint, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.Escape(char.ConvertFromUtf32(codePoint)));
    }

    // Exhaustive over the block and in an entry-name context: all 128 code points are rewritten, the surrounding
    // text is untouched, and no surrogate pair survives.
    [Fact]
    public void Escape_ForEveryCodePointInTheTagBlock_EscapesItInPlace()
    {
        for (var cp = TagBlockFirst; cp <= TagBlockLast; cp++)
        {
            var escaped = YaraPathSafety.Escape("content/a" + char.ConvertFromUtf32(cp) + "b.bin");

            Assert.Equal($@"content/a\U{cp:X8}b.bin", escaped);
            Assert.All(escaped, c => Assert.False(char.IsSurrogate(c), $"U+{cp:X5} survived as a surrogate."));
        }
    }

    // The false-positive guard for the widening. Astral text OUTSIDE the Tag block is ordinary path text and must
    // survive verbatim as its own surrogate pair. A regression that escaped every astral rune — the easy way to
    // "fix" the Tag-block gap — would satisfy every "no invisible character" property in this file while mangling
    // the emoji and CJK-extension names real packages ship.
    [Theory]
    [InlineData(0x1F600)]    // GRINNING FACE
    [InlineData(0x1F4A9)]    // PILE OF POO
    [InlineData(0x1F1FA)]    // REGIONAL INDICATOR SYMBOL LETTER U (a flag half)
    [InlineData(0x20000)]    // CJK UNIFIED IDEOGRAPH-20000 (extension B, first)
    [InlineData(0x2A6DF)]    // CJK extension B, last
    [InlineData(0x2F800)]    // CJK COMPATIBILITY IDEOGRAPH-2F800
    [InlineData(0x1D11E)]    // MUSICAL SYMBOL G CLEF
    [InlineData(0xDFFFF)]    // the code point immediately BELOW the Tag block
    [InlineData(0xE0080)]    // ...and immediately above it
    [InlineData(0x100000)]   // plane 16 private use
    [InlineData(0x10FFFF)]   // the last code point there is
    public void Escape_ForAstralTextOutsideTheTagBlock_IsIdentity(int codePoint)
    {
        var name = "content/" + char.ConvertFromUtf32(codePoint) + "/x.bin";

        Assert.Equal(name, YaraPathSafety.Escape(name));
    }

    // ...including when a pass-through rune sits directly beside runes that ARE escaped, in one string: the rune
    // loop must not drop, reorder or re-encode its neighbours while rewriting them.
    [Fact]
    public void Escape_ForAstralPassThroughBesideEscapedNeighbours_RewritesOnlyTheNeighbours()
    {
        var hostile = "content/" + Emoji + Zwsp + TagA + Cjk + "pay\nload" + Shy + ".bin";

        var escaped = YaraPathSafety.Escape(hostile);

        Assert.Equal("content/" + Emoji + @"\u200b\U000E0041" + Cjk + @"pay\nload\xad.bin", escaped);
        Assert.Contains(Emoji, escaped, StringComparison.Ordinal);   // stated separately: the pass-through survived
        Assert.Contains(Cjk, escaped, StringComparison.Ordinal);
    }

    // The lowercase/uppercase split is a contract, not an accident: \xNN and \uXXXX are lowercase hex and the
    // astral \UXXXXXXXX is the only uppercase form. Checked over every code point Escape actually rewrites.
    [Fact]
    public void Escape_ForEveryEscapedCodePoint_UsesLowercaseHexExceptTheAstralForm()
    {
        foreach (var (codePoint, text) in EveryCodePointUnderTest())
        {
            var escaped = YaraPathSafety.Escape(text);
            if (string.Equals(escaped, text, StringComparison.Ordinal))
                continue;

            if (escaped.StartsWith(@"\U", StringComparison.Ordinal))
                Assert.Equal(@"\U" + codePoint.ToString("X8"), escaped);
            else
                Assert.Equal(escaped.ToLowerInvariant(), escaped);
        }
    }

    // --- Escape: ill-formed UTF-16 ---------------------------------------------------------------------------------

    // A zip entry name is bytes, so it is not guaranteed to decode to well-formed UTF-16. A LONE surrogate is not a
    // code point at all: it decodes to U+FFFD REPLACEMENT CHARACTER and is emitted as such, so no ill-formed UTF-16
    // ever reaches a log line, a JSON writer or a terminal from us.
    [Fact]
    public void Escape_ForALoneSurrogate_EmitsTheReplacementCharacter()
    {
        (string Input, string Expected)[] table =
        [
            ("\uD800", Fffd),                                        // lone HIGH surrogate, first
            ("\uDBFF", Fffd),                                        // ...last
            ("\uDC00", Fffd),                                        // lone LOW surrogate, first
            ("\uDFFF", Fffd),                                        // ...last
            ("\uDC00\uD800", Fffd + Fffd),                           // a REVERSED pair: two lone surrogates
            ("content/a\uD800b.bin", "content/a" + Fffd + "b.bin"),  // embedded; the ordinary text is preserved
            ("content/" + Zwsp + "\uD800.bin", @"content/\u200b" + Fffd + ".bin"),   // ...beside a real escape
            ("content/" + Emoji + "\uD800.bin", "content/" + Emoji + Fffd + ".bin"), // ...and a real pair, unharmed
        ];

        Assert.All(table, row => Assert.Equal(row.Expected, YaraPathSafety.Escape(row.Input)));
    }

    // U+FFFD is ordinary text once it is there, so a second pass changes nothing — a name that arrived ill-formed
    // cannot keep mutating each time it is logged. And the result is well-formed UTF-16: a PAIRED surrogate (the
    // emoji below) is fine and must survive; an unpaired one must not exist.
    [Fact]
    public void Escape_ForALoneSurrogate_IsIdempotentAndEmitsWellFormedUtf16()
    {
        string[] inputs =
        [
            "\uD800", "\uDFFF", "\uDC00\uD800", "content/a\uD800" + Zwsp + "b.bin", "content/" + Emoji + "\uDBFF.bin",
        ];

        foreach (var input in inputs)
        {
            var once = YaraPathSafety.Escape(input);

            Assert.Equal(once, YaraPathSafety.Escape(once));
            Assert.True(
                string.Equals(once, string.Concat(once.EnumerateRunes()), StringComparison.Ordinal),
                $"Escape emitted an unpaired surrogate for '{YaraPathSafety.Escape(input)}'.");
        }
    }

    // --- Escape: the properties that actually matter ---------------------------------------------------------------

    // THE load-bearing assertion of this class (spec item 2). The text handed to Escape is authored by the package
    // under analysis, so no example table can be exhaustive over what it might contain — but the alphabet CAN be
    // exhausted. For EVERY code point under test, the escaped rendering must contain nothing below 0x20: that is
    // precisely the guarantee that an entry name can never inject a line into our own log, and it is what makes
    // YaraScanIncompleteException.Message safe to log verbatim (spec item 4). Lone surrogates are in the domain
    // deliberately — an entry name is not guaranteed to be well-formed UTF-16.
    [Fact]
    public void Escape_ForEveryCodePointUnderTest_NeverEmitsAControlCharacter()
    {
        AssertNoCodePointSurvives(cp => cp <= 0x1F, "control");
    }

    // The same property over the display-attack alphabet: no DEL, no C1, no line/paragraph separator and no bidi
    // control survives escaping either, so escaped text cannot reorder what an operator reads.
    [Fact]
    public void Escape_ForEveryCodePointUnderTest_NeverEmitsADisplayControl()
    {
        AssertNoCodePointSurvives(IsDisplayControl, "display-control");
    }

    // THE property the ADR 0031 decision 4 defect needed and did not have. An InvisibleCharacter finding that
    // still contains the invisible character reports nothing at all, so the escaped rendering must contain no
    // zero-width character, no soft hyphen, no BOM, no directional mark, no invisible operator — and no Tag-block
    // code point, which is the half a BMP-only domain could not express.
    [Fact]
    public void Escape_ForEveryCodePointUnderTest_NeverEmitsAnInvisibleCharacter()
    {
        AssertNoCodePointSurvives(IsInvisible, "invisible");
    }

    // Well-formedness of the OUTPUT, over the same domain: whatever went in, what comes out is valid UTF-16 with
    // no lone surrogate. Rune enumeration substitutes U+FFFD for an unpaired surrogate, so re-joining the runes
    // and comparing is an exact ill-formedness test.
    [Fact]
    public void Escape_ForEveryCodePointUnderTest_EmitsWellFormedUtf16()
    {
        foreach (var (codePoint, text) in EveryCodePointUnderTest())
        {
            var escaped = YaraPathSafety.Escape(text);

            Assert.True(
                string.Equals(escaped, string.Concat(escaped.EnumerateRunes()), StringComparison.Ordinal),
                $"Escape(U+{codePoint:X4}) emitted ill-formed UTF-16 (an unpaired surrogate).");
        }
    }

    // Escaping is stable over the whole domain: text that came out of Escape contains nothing that needs escaping,
    // so a second pass is a no-op. Without this, a path escaped twice on its way to a log line would silently
    // mangle backslashes — or, for the astral forms, silently double-escape.
    [Fact]
    public void Escape_ForEveryCodePointUnderTest_IsIdempotent()
    {
        foreach (var (codePoint, text) in EveryCodePointUnderTest())
        {
            var once = YaraPathSafety.Escape(text);

            Assert.True(
                string.Equals(once, YaraPathSafety.Escape(once), StringComparison.Ordinal),
                $"Escape is not idempotent at U+{codePoint:X4}.");
        }
    }

    // The regression sentinel for the DOMAIN itself. The properties above are only as strong as the alphabet they
    // exhaust, and the alphabet is exactly what was wrong before: narrowing EveryCodePointUnderTest back to the BMP
    // must fail loudly here rather than quietly turn five properties into weaker ones.
    [Fact]
    public void EveryCodePointUnderTest_CoversTheWholeTagBlockAndASampleOfEveryOtherPlane()
    {
        var domain = EveryCodePointUnderTest().Select(x => x.CodePoint).ToHashSet();

        Assert.Equal(0x10000, domain.Count(cp => cp <= 0xFFFF));                             // the whole BMP...
        Assert.All(Enumerable.Range(TagBlockFirst, 0x80), cp => Assert.Contains(cp, domain));   // ...the whole Tag block...
        Assert.All(Enumerable.Range(1, 16), plane => Assert.Contains(domain, cp => cp >> 16 == plane));   // ...every plane
    }

    // The property again over MULTI-character adversarial strings, so it cannot pass by accident on singletons:
    // deterministic pseudo-random names drawn from a deliberately hostile alphabet (heavy on C0, DEL/C1, the bidi
    // block and ordinary path characters). Seeded, so a failure is exactly reproducible.
    [Fact]
    public void Escape_ForRandomHostileStrings_NeverEmitsAControlCharacter()
    {
        var random = new Random(0x0029);
        for (var trial = 0; trial < 2_000; trial++)
        {
            var input = string.Concat(Enumerable
                .Range(0, random.Next(1, 32))
                .Select(_ => HostileAlphabet[random.Next(HostileAlphabet.Count)]));

            var escaped = YaraPathSafety.Escape(input);

            Assert.All(escaped, c => Assert.False(
                c < ' ' || IsDisplayControl(c),
                $"Escape emitted raw U+{(int)c:X4} for a hostile input of length {input.Length}."));
        }
    }

    // ...and the same over multi-RUNE strings, where the fragments include Tag-block characters, real surrogate
    // pairs that must pass through, and lone surrogates that must not. A char-based generator cannot express any
    // of those three, which is the generator-side version of the same domain mistake.
    [Fact]
    public void Escape_ForRandomHostileRuneStrings_NeverEmitsAHostileCodePointAndStaysIdempotent()
    {
        var random = new Random(0x0031);
        for (var trial = 0; trial < 2_000; trial++)
        {
            var input = string.Concat(Enumerable
                .Range(0, random.Next(1, 12))
                .Select(_ => HostileFragments[random.Next(HostileFragments.Count)]));

            var escaped = YaraPathSafety.Escape(input);

            Assert.All(
                escaped.EnumerateRunes().Select(r => r.Value),
                cp => Assert.False(
                    cp <= 0x1F || IsDisplayControl(cp) || IsInvisible(cp),
                    $"Escape emitted raw U+{cp:X4} for a hostile input of length {input.Length}."));
            Assert.Equal(escaped, YaraPathSafety.Escape(escaped));
        }
    }

    // Escape only ever ADDS characters — it never drops the surrounding, legitimate path text. A regression that
    // simply stripped hostile characters would satisfy every "no control character" property above while making
    // the log useless, so pin that the ordinary characters survive in order.
    [Fact]
    public void Escape_PreservesTheOrdinaryCharactersAroundAnEscape()
    {
        Assert.Equal(@"lib/net8.0/rep\nort.bin", YaraPathSafety.Escape("lib/net8.0/rep\nort.bin"));
    }

    // --- helpers ---------------------------------------------------------------------------------------------------

    private static void AssertNoCodePointSurvives(Func<int, bool> forbidden, string what)
    {
        foreach (var (codePoint, text) in EveryCodePointUnderTest())
        {
            var offenders = YaraPathSafety.Escape(text)
                .EnumerateRunes()
                .Select(r => r.Value)
                .Where(forbidden)
                .ToArray();

            Assert.True(
                offenders.Length == 0,
                $"Escape(U+{codePoint:X4}) emitted raw {what} code point(s) "
                + string.Join(", ", offenders.Select(cp => $"U+{cp:X4}")) + '.');
        }
    }

    // Every code point the properties above run over, as (code point, single-code-point string):
    //   * the whole BMP, one UTF-16 code unit at a time — INCLUDING the surrogate range, so lone surrogates are in;
    //   * the whole Unicode Tag block, the astral block Escape must rewrite;
    //   * a sample of every other plane, so the astral PASS-THROUGH half is exercised too, plus the two code points
    //     that bracket the Tag block.
    // The BMP-only version of this domain is exactly what let the Tag-block defect ship.
    private static IEnumerable<(int CodePoint, string Text)> EveryCodePointUnderTest()
    {
        for (var i = 0; i <= 0xFFFF; i++)
            yield return (i, ((char)i).ToString());

        for (var cp = TagBlockFirst; cp <= TagBlockLast; cp++)
            yield return (cp, char.ConvertFromUtf32(cp));

        foreach (var cp in AstralSamples)
            yield return (cp, char.ConvertFromUtf32(cp));
    }

    // DEL, the C1 controls, the Unicode line/paragraph separators and the bidi embeddings/overrides/isolates: the
    // characters that do not break the parser but DO let attacker-authored text reorder or hide itself in a log.
    private static bool IsDisplayControl(int cp) =>
        cp is >= 0x7F and <= 0x9F
             or 0x2028 or 0x2029
             or >= 0x202A and <= 0x202E
             or >= 0x2066 and <= 0x2069;

    private static bool IsDisplayControl(char c) => IsDisplayControl((int)c);

    // The alphabet ADR 0031 decision 4 added: characters that render as nothing, so a name containing one is a name
    // the reader cannot see. A strict superset of the InvisibleCharacter CATEGORY (see the class summary).
    private static bool IsInvisible(int cp) =>
        cp is 0x00AD
             or >= 0x200B and <= 0x200F
             or >= 0x2060 and <= 0x2064
             or 0xFEFF
             or >= TagBlockFirst and <= TagBlockLast;
    #endregion

    #region Fields
    private const int TagBlockFirst = 0xE0000;
    private const int TagBlockLast = 0xE007F;

    private const string Zwsp = "\u200B";        // ZERO WIDTH SPACE
    private const string Shy = "\u00AD";         // SOFT HYPHEN
    private const string Fffd = "\uFFFD";        // REPLACEMENT CHARACTER
    private const string Emoji = "\U0001F600";   // GRINNING FACE — astral, and must pass through untouched
    private const string Cjk = "\U00020000";     // CJK extension B — likewise
    private const string TagA = "\U000E0041";    // TAG LATIN CAPITAL LETTER A — astral, and must NOT

    // The alphabet the randomized char property draws from: every C0 character, DEL/C1 samples, the separators and
    // bidi controls, plus ordinary path characters so the generated strings look like real (hostile) entry names.
    private static readonly IReadOnlyList<char> HostileAlphabet =
        Enumerable.Range(0x00, 0x20).Select(i => (char)i)                       // all of C0
            .Concat(new[] { '\u007F', '\u0085', '\u0090', '\u009F' })            // DEL + C1
            .Concat(new[] { '\u2028', '\u2029' })                                // LINE / PARAGRAPH SEPARATOR
            .Concat(Enumerable.Range(0x202A, 5).Select(i => (char)i))            // bidi embeddings/overrides
            .Concat(Enumerable.Range(0x2066, 4).Select(i => (char)i))            // bidi isolates
            .Concat("abzAZ09._-/\\ :\u00E9\u65E5")                               // ordinary (and non-ASCII) path text
            .ToArray();

    // The same idea one level up, in RUNES: fragments a char-based generator cannot produce — Tag-block characters,
    // real surrogate pairs (which must survive) and lone surrogates (which must not).
    private static readonly IReadOnlyList<string> HostileFragments =
    [
        "\n", "\r", "\t", "\0", "\u001B", "\u007F", "\u009F", "\u2028", "\u202E", "\u2069",
        Zwsp, "\u200C", "\u200D", "\u200E", "\u2060", "\uFEFF", Shy,
        TagA, "\U000E0000", "\U000E007F",
        Emoji, Cjk, "\U0001D11E", "\U0010FFFF",
        "\uD800", "\uDFFF",
        "content/", "lib/net8.0/", "a", "Z", "9", ".", "-", "_", "/", "\\", " ", "\u00E9", "\u65E5",
    ];

    // A sample of every astral plane, plus the two code points that bracket the Tag block. Plane 16 tops out at
    // U+10FFFD here and U+10FFFF is listed explicitly, so the very last code point is covered.
    private static readonly IReadOnlyList<int> AstralSamples =
    [
        .. Enumerable.Range(1, 16).SelectMany(plane =>
            new[] { 0x0000, 0x0041, 0x1234, 0xABCD, 0xFFFD }.Select(offset => (plane << 16) | offset)),
        0xDFFFF, 0xE0080, 0xE00FF, 0x10FFFF,
    ];
    #endregion
}
