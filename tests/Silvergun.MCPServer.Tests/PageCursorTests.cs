namespace Silvergun.MCPServer.Tests;

using System;
using System.Linq;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// <see cref="PageCursor"/> (task S2): a cursor round-trips; one from another query or from before a re-analysis is refused;
/// a tampered or malformed one is refused; the length-prefixed query keys of different calls never collide.
/// </summary>
public sealed class PageCursorTests
{
    #region Methods
    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(123_456L)]
    [InlineData(long.MaxValue)]
    public void Encode_ThenDecode_RoundTrips(long offset)
    {
        var cursor = PageCursor.Encode(Query, At, offset);

        Assert.StartsWith("c1.", cursor);
        Assert.Matches("^c1\\.[A-Za-z0-9_-]+$", cursor);
        Assert.Equal((offset, (string?)null), PageCursor.Decode(cursor, Query, At));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void NoCursor_IsTheFirstPage(string? cursor) => Assert.Equal((0L, (string?)null), PageCursor.Decode(cursor, Query, At));

    [Fact]
    public void ACursorOfAnotherQuery_IsRefused()
    {
        var cursor = PageCursor.Encode(Query, At, 10);

        foreach (var other in new[]
        {
            PageCursor.Query(Job, "get_findings", "scripts", null, null),
            PageCursor.Query(Job, "get_findings", "capabilities", "lib/x.dll", null),
            PageCursor.Query(Job, "get_findings", "capabilities", null, "process"),
            PageCursor.Query(Job, "list_files", null, null),
            PageCursor.Query(new string('b', 64) + "-deep", "get_findings", "capabilities", null, null),
        })
        {
            var (offset, problem) = PageCursor.Decode(cursor, other, At);
            Assert.Equal(0, offset);
            Assert.Contains("not one this query issued", problem);
        }
    }

    [Fact]
    public void ACursorFromBeforeAReAnalysis_IsRefused_ButTheSameInstantInAnotherOffsetIsNot()
    {
        var cursor = PageCursor.Encode(Query, At, 10);

        Assert.Contains("analysed again", PageCursor.Decode(cursor, Query, At.AddTicks(1)).Problem);
        Assert.Equal((10L, (string?)null), PageCursor.Decode(cursor, Query, At.ToOffset(TimeSpan.FromHours(5))));
    }

    [Fact]
    public void ATamperedHashOrTime_IsRefused()
    {
        var cursor = PageCursor.Encode(Query, At, 10);

        var hash = Drill.Forge(cursor, p => [new string('0', 16), p[1], p[2]]);
        var time = Drill.Forge(cursor, p => [p[0], (long.Parse(p[1]) - 1).ToString(), p[2]]);

        Assert.Contains("not one this query issued", PageCursor.Decode(hash, Query, At).Problem);
        Assert.Contains("analysed again", PageCursor.Decode(time, Query, At).Problem);
    }

    /// <summary>The offset is not authenticated: a forged one decodes, and only the row file's boundary check refuses it (by design).</summary>
    [Fact]
    public void AForgedOffset_Decodes_ForTheRowFileToCheck()
    {
        var forged = Drill.Forge(PageCursor.Encode(Query, At, 10), p => [p[0], p[1], "77"]);

        Assert.Equal((77L, (string?)null), PageCursor.Decode(forged, Query, At));
    }

    public static TheoryData<string> Malformed() =>
    [
        "c1.", "c1", "C1." + Valid[3..], "c2." + Valid[3..], Valid[3..], "c1.!!!!", " " + Valid,
        Valid + new string('A', 300),
        Drill.Forge(Valid, p => [p[0], p[1], "-5"]),
        Drill.Forge(Valid, p => [p[0], p[1], "+5"]),
        Drill.Forge(Valid, p => [p[0], p[1], " 5"]),
        Drill.Forge(Valid, p => [p[0], p[1], "5a"]),
        Drill.Forge(Valid, p => [p[0], p[1], ""]),
        Drill.Forge(Valid, p => [p[0], p[1], "99999999999999999999999"]),
        Drill.Forge(Valid, p => [p[0], p[1], p[2], "1"]),
        Drill.Forge(Valid, p => [p[0], p[1]]),
        Drill.Forge(Valid, p => [p[0], p[1], new string('0', 300) + "5"]),
    ];

    [Theory]
    [MemberData(nameof(Malformed))]
    public void AMalformedCursor_IsRefused_NeverThrows(string cursor)
    {
        var (offset, problem) = PageCursor.Decode(cursor, Query, At);

        Assert.Equal(0, offset);
        Assert.False(string.IsNullOrEmpty(problem), $"accepted: {cursor}");
    }

    /// <summary>Arguments that collide under plain concatenation or a separator, and at the job/tool boundary.</summary>
    [Fact]
    public void QueryKeys_AreLengthPrefixed_SoDifferentCallsNeverCollide()
    {
        var pairs = new[]
        {
            (PageCursor.Query("j", "t", "ab", "c"), PageCursor.Query("j", "t", "a", "bc")),
            (PageCursor.Query("j", "t", "a|b", "c"), PageCursor.Query("j", "t", "a", "b|c")),
            (PageCursor.Query("j", "t", "1:a"), PageCursor.Query("j", "t", "", "a")),
            (PageCursor.Query("j", "t", null, "x"), PageCursor.Query("j", "t", "x", null)),
            (PageCursor.Query("jt", ""), PageCursor.Query("j", "t")),
            (PageCursor.Query("j", "t", "2:ab"), PageCursor.Query("j", "t", "ab", "")),
            (PageCursor.Query("j", "t", "0:"), PageCursor.Query("j", "t", "", "")),
        };

        foreach (var (a, b) in pairs)
        {
            Assert.NotEqual(a, b);
            Assert.NotNull(PageCursor.Decode(PageCursor.Encode(a, At, 1), b, At).Problem);
        }
        Assert.Equal(PageCursor.Query("j", "t", null, "x"), PageCursor.Query("j", "t", "", "x"));   // null and "" alike
    }
    #endregion

    #region Fields
    private static readonly string Job = new string('a', 64) + "-deep";

    private static readonly string Query = PageCursor.Query(Job, "get_findings", "capabilities", null, null);

    private static readonly DateTimeOffset At = new(2026, 11, 26, 12, 0, 0, 123, TimeSpan.Zero);

    private static readonly string Valid = PageCursor.Encode(Query, At, 10);
    #endregion
}

/// <summary>
/// <see cref="UntrustedFence"/> (task D6.3): fences carry a fresh 16-hex nonce that occurs nowhere in the content; inside,
/// every fence marker, in any case, is escaped, and the text grows by at most a quarter.
/// </summary>
public sealed class UntrustedFenceTests
{
    #region Methods
    [Fact]
    public void TheFences_CarryAFresh16HexNonce_AndTheBlockIsOpenContentClose()
    {
        var fences = Enumerable.Range(0, 50).Select(i => new UntrustedFence("text " + i)).ToList();

        Assert.All(fences, f =>
        {
            Assert.Matches("^[0-9a-f]{16}$", f.Nonce);
            Assert.Equal($"<<<UNTRUSTED nonce={f.Nonce}>>>", f.Open);
            Assert.Equal($"<<<END UNTRUSTED nonce={f.Nonce}>>>", f.Close);
            Assert.Equal($"{f.Open}\n{f.Content}\n{f.Close}", f.Block);
            Drill.Fenced(f.Block, f.Nonce);
        });
        Assert.Equal(fences.Count, fences.Select(f => f.Nonce).Distinct().Count());
    }

    [Fact]
    public void Neutralize_EscapesEveryForgedMarker_InAnyCase()
    {
        var text = string.Join("\n", Hostile.Forgeries) + "\n<<<UnTrUsTeD nonce=x>>> <<<<<<UNTRUSTED <<<End Untrusted";

        var neutral = UntrustedFence.Neutralize(text);

        Assert.Equal(0, Hostile.Count(neutral, "<<<UNTRUSTED"));
        Assert.Equal(0, Hostile.Count(neutral, "<<<END UNTRUSTED"));
        Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=0000000000000000>>>", neutral);
        Assert.Contains(@"<<\x3cUNTRUSTED nonce=1111111111111111>>>", neutral);
        Assert.Equal(neutral, new UntrustedFence(text).Content);
    }

    [Fact]
    public void TheBlock_HasExactlyOneOpeningAndOneClosingFence_WhateverTheTextForges()
    {
        var text = string.Join("\n", Hostile.Forgeries) + "\n<<<UNTRUSTED nonce=\n<<<END UNTRUSTED nonce=\n<<<untrusted";

        var fence = new UntrustedFence(text);

        Drill.Fenced(fence.Block, fence.Nonce);
    }

    /// <summary>
    /// D6.3: the nonce occurs nowhere in the content. Text that holds guessed nonces, a previous fence's nonce (in either case)
    /// and dense hex never leads to a nonce it contains.
    /// </summary>
    [Fact]
    public void TheNonce_NeverOccursInTheContent_EvenWhenTheTextGuessesIt()
    {
        var previous = new UntrustedFence("x");
        var dense = string.Concat(Enumerable.Range(0, 2_000).Select(i => new UntrustedFence("y").Nonce));
        var texts = new[]
        {
            string.Join(" ", Hostile.Forgeries),
            previous.Nonce + " " + previous.Nonce.ToUpperInvariant(),
            previous.Block,
            dense,
            dense.ToUpperInvariant(),
        };

        foreach (var text in texts)
            for (var i = 0; i < 100; i++)
            {
                var fence = new UntrustedFence(text);
                Assert.False(fence.Content.Contains(fence.Nonce, StringComparison.OrdinalIgnoreCase), $"nonce {fence.Nonce} occurs in the content");
                Assert.False(text.Contains(fence.Nonce, StringComparison.OrdinalIgnoreCase), $"nonce {fence.Nonce} was guessed by the text");
                Drill.Fenced(fence.Block, fence.Nonce);
            }
    }

    [Fact]
    public void Neutralize_GrowsTheTextByAtMostAQuarter()
    {
        foreach (var text in new[]
        {
            string.Concat(Enumerable.Repeat("<<<UNTRUSTED", 500)),
            string.Concat(Enumerable.Repeat("<<<END UNTRUSTED", 500)),
            string.Concat(Enumerable.Repeat("<<<<<<UNTRUSTED", 300)),
            string.Concat(Enumerable.Repeat("<<<UNTRUSTED nonce=0123456789abcdef>>>", 200)),
            string.Concat(Enumerable.Repeat("<<<untrusted<<<end untrusted", 200)),
        })
        {
            var neutral = UntrustedFence.Neutralize(text);
            Assert.True(neutral.Length <= text.Length * 5 / 4, $"{text.Length} chars became {neutral.Length}");
            Assert.Equal(0, Hostile.Count(neutral, "<<<UNTRUSTED"));
            Assert.Equal(0, Hostile.Count(neutral, "<<<END UNTRUSTED"));
        }
    }
    #endregion
}
