namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for <see cref="YaraPathSafety"/> (ADR 0029). Two halves of one threat, so two halves of one test
/// class:
/// <list type="number">
/// <item><see cref="YaraPathSafety.IsUnsafeName"/> decides which extracted names the classic-CLI backend's
/// line-oriented output cannot round-trip. Getting it <b>too narrow</b> re-opens the ADR 0029 false negative (a
/// hit silently dropped while the scan reads <c>Completed</c>); getting it <b>too wide</b> pushes ordinary
/// packages — spaces, non-ASCII segments, Windows backslashes — down the per-file copy-and-rescan path. The
/// definition is exactly the C0 range (U+0000..U+001F), nothing else.</item>
/// <item><see cref="YaraPathSafety.Escape"/> renders that same attacker-authored text into <b>our own log</b>.
/// The example-based cases below pin the shape of each escape, but the load-bearing assertion is the
/// <see cref="Escape_ForEveryCharInTheBmp_NeverEmitsAControlCharacter"/> <b>property</b>: whatever a package
/// names its entries, the escaped rendering can never carry a character below 0x20 and therefore can never forge
/// a log line. A property is the right shape here because the input is chosen by an adversary, not by us — an
/// example table only proves the examples we happened to think of.</item>
/// </list>
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

    // --- Escape: the property that actually matters ----------------------------------------------------------------

    // THE load-bearing assertion of this class (spec item 2). The text handed to Escape is authored by the package
    // under analysis, so no example table can be exhaustive over what it might contain — but the alphabet CAN be
    // exhausted. For EVERY UTF-16 code unit in the BMP, the escaped rendering must contain nothing below 0x20:
    // that is precisely the guarantee that an entry name can never inject a line into our own log, and it is what
    // makes YaraScanIncompleteException.Message safe to log verbatim (spec item 4). Lone surrogates are included
    // deliberately — an entry name is not guaranteed to be well-formed UTF-16.
    [Fact]
    public void Escape_ForEveryCharInTheBmp_NeverEmitsAControlCharacter()
    {
        for (var i = 0; i <= 0xFFFF; i++)
        {
            var escaped = YaraPathSafety.Escape(((char)i).ToString());
            var offenders = escaped.Where(c => c < ' ').ToArray();

            Assert.True(
                offenders.Length == 0,
                $"Escape(U+{i:X4}) emitted raw control character(s) "
                + string.Join(", ", offenders.Select(c => $"U+{(int)c:X4}")) + '.');
        }
    }

    // The same property over the display-attack alphabet: no DEL, no C1, no line/paragraph separator and no bidi
    // control survives escaping either, so escaped text cannot reorder or hide what an operator reads.
    [Fact]
    public void Escape_ForEveryCharInTheBmp_NeverEmitsADisplayControl()
    {
        for (var i = 0; i <= 0xFFFF; i++)
        {
            var escaped = YaraPathSafety.Escape(((char)i).ToString());
            var offenders = escaped.Where(IsDisplayControl).ToArray();

            Assert.True(
                offenders.Length == 0,
                $"Escape(U+{i:X4}) emitted raw display-control character(s) "
                + string.Join(", ", offenders.Select(c => $"U+{(int)c:X4}")) + '.');
        }
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

    // Escaping is stable: text that came out of Escape contains nothing that needs escaping, so a second pass is a
    // no-op. Without this, a path escaped twice on its way to a log line would silently mangle backslashes.
    [Fact]
    public void Escape_IsIdempotent()
    {
        for (var i = 0; i <= 0xFFFF; i++)
        {
            var once = YaraPathSafety.Escape(((char)i).ToString());
            Assert.Equal(once, YaraPathSafety.Escape(once));
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

    // DEL, the C1 controls, the Unicode line/paragraph separators and the bidi embeddings/overrides/isolates: the
    // characters that do not break the parser but DO let attacker-authored text reorder or hide itself in a log.
    private static bool IsDisplayControl(char c) =>
        c is >= (char)0x7F and <= (char)0x9F
             or (char)0x2028 or (char)0x2029
             or >= (char)0x202A and <= (char)0x202E
             or >= (char)0x2066 and <= (char)0x2069;
    #endregion

    #region Fields
    // The alphabet the randomized property draws from: every C0 character, DEL/C1 samples, the separators and bidi
    // controls, plus ordinary path characters so the generated strings look like real (hostile) entry names.
    private static readonly IReadOnlyList<char> HostileAlphabet =
        Enumerable.Range(0x00, 0x20).Select(i => (char)i)                       // all of C0
            .Concat(new[] { '\u007F', '\u0085', '\u0090', '\u009F' })            // DEL + C1
            .Concat(new[] { '\u2028', '\u2029' })                                // LINE / PARAGRAPH SEPARATOR
            .Concat(Enumerable.Range(0x202A, 5).Select(i => (char)i))            // bidi embeddings/overrides
            .Concat(Enumerable.Range(0x2066, 4).Select(i => (char)i))            // bidi isolates
            .Concat("abzAZ09._-/\\ :\u00E9\u65E5")                               // ordinary (and non-ASCII) path text
            .ToArray();
    #endregion
}
