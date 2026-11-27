namespace Silvergun.MCPServer.Tests;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// <see cref="ToolEnvelope.Escaped"/> (S3 review W1): one cut, never two. With nothing invisible kept it is exactly
/// <see cref="UntrustedText.EscapeBounded(string, int)"/>; otherwise each kept code point is made displayable and the text ends
/// with <see cref="UntrustedText.CutSuffix"/> for the whole input. The suffixes are pinned from an independent hash.
/// </summary>
public sealed class EscapedTests
{
    #region Methods
    /// <summary>A 2,000-char ASCII input at 400 keeps 400 chars and ends with U+2026 then "[+1600 chars, sha256:&lt;whole input&gt;]".</summary>
    [Fact]
    public void Escaped_AnAsciiInputCut_EndsWithTheWholeInputsSuffix_Exactly()
    {
        var text = string.Concat(Enumerable.Range(0, 2_000).Select(i => (char)('a' + i % 26)));

        var escaped = ToolEnvelope.Escaped(text, 400);

        Assert.Equal(text[..400] + Ellipsis + "[+1600 chars, sha256:" + Hash(text) + "]", escaped);
        Assert.Equal(UntrustedText.EscapeBounded(text, 400), escaped);
    }

    /// <summary>
    /// A kept prefix holding U+061C: "ab", the escape of U+061C (6 chars), "cd", then 90 x's fill 100. 95 input chars are
    /// kept, so N is the rest, and the suffix is the whole input's, not the escaped text's.
    /// </summary>
    [Fact]
    public void Escaped_AnInputWithAnInvisibleKept_IsCutOnce_WithTheWholeInputsSuffix()
    {
        var text = "ab" + Hostile3.Alm + "cd" + new string('x', 2_000);
        const int kept = 2 + 1 + 2 + 90;
        var n = text.Length - kept;

        var escaped = ToolEnvelope.Escaped(text, 100);

        Assert.Equal(1_910, n);
        Assert.Equal("ab" + Backslash + "u061ccd" + new string('x', 90) + UntrustedText.CutSuffix(text, n), escaped);
        Assert.Equal(Ellipsis + $"[+{n} chars, sha256:" + Hash(text) + "]", UntrustedText.CutSuffix(text, n));
        Assert.Equal(2, escaped.Split(Ellipsis + "[").Length);   // one suffix: one cut
        Assert.True(ExtractedFile.IsDisplayable(escaped));
    }

    [Fact]
    public void Escaped_AnUncutInputWithInvisibles_IsEveryCodePointDisplayable_AndUncut()
    {
        var text = "p" + Hostile3.Alm + "q" + Hostile3.Vs16 + "r" + Hostile3.Vs17 + "s" + Hostile.Rlo + "t";

        var escaped = ToolEnvelope.Escaped(text, 400);

        Assert.Equal("p" + Backslash + "u061cq" + Backslash + "ufe0fr" + Backslash + "U000E0100s" + Backslash + "u202et", escaped);
        Assert.DoesNotContain(Ellipsis, escaped);
    }

    /// <summary>An invisible code point past the cut is not kept, so the result is EscapeBounded's own, suffix and all.</summary>
    [Fact]
    public void Escaped_AnInvisibleOnlyPastTheCut_IsEscapeBoundedsOwnResult()
    {
        var text = new string('y', 500) + Hostile3.Alm + "z";

        Assert.Equal(UntrustedText.EscapeBounded(text, 100), ToolEnvelope.Escaped(text, 100));
        Assert.EndsWith(UntrustedText.CutSuffix(text, text.Length - 100), ToolEnvelope.Escaped(text, 100));
    }

    /// <summary>An escape is never split by the cut: one that does not fit whole is dropped, and counted in N.</summary>
    [Fact]
    public void Escaped_AnEscapeThatDoesNotFit_IsLeftOut_NotSplit()
    {
        var text = new string('k', 97) + Hostile3.Alm + "tail";

        var escaped = ToolEnvelope.Escaped(text, 100);

        Assert.Equal(new string('k', 97) + UntrustedText.CutSuffix(text, text.Length - 97), escaped);
    }
    #endregion

    #region Methods: helpers
    // The first 8 hex of SHA-256 over the input's UTF-16 code units, little-endian, computed here independently.
    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.Unicode.GetBytes(text)))[..8];
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private static readonly string Ellipsis = char.ConvertFromUtf32(0x2026);
    #endregion
}
