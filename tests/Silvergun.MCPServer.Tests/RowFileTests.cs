namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// <see cref="RowFile"/> and <see cref="RowWriter"/> (task S2): cuts land on escape boundaries; a fitted row is within its
/// bound and keeps its <c>keep</c> keys whole; a page never splits a row, and every row comes once across pages; a cursor
/// offset off a row start, and every kind of corrupt line, is refused with its problem.
/// </summary>
public sealed class RowFileTests : IDisposable
{
    #region Methods
    // ---- Cut ----

    [Fact]
    public void Cut_LeavesTextWithinTheBound_Unchanged()
    {
        Assert.Equal("abc", RowFile.Cut("abc", 3));
        Assert.Equal("", RowFile.Cut("", 0));
    }

    /// <summary>Every cut point through a run of 10-char Tag escapes, a surrogate pair, \u, \x and doubled-backslash escapes.</summary>
    [Fact]
    public void Cut_NeverCutsInsideAnEscapeOrASurrogatePair_AtAnyBound()
    {
        var emoji = char.ConvertFromUtf32(0x1F600);
        var escaped = UntrustedText.EscapeBounded("ab" + Hostile.Tag + Hostile.Tag + emoji + Hostile.Rlo + (char)1 + Backslash + Hostile.Zwsp + "z", 10_000);
        var units = Units(escaped);
        Assert.Equal(string.Concat(units), escaped);
        Assert.Contains(Backslash + "U000E0041", units);
        Assert.Contains(Backslash + "x01", units);
        Assert.Contains(emoji, units);
        Assert.Contains(Backslash + Backslash, units);

        for (var max = 0; max < escaped.Length; max++)
        {
            var cut = RowFile.Cut(escaped, max);
            var suffix = cut.IndexOf((char)0x2026 + "[+", StringComparison.Ordinal);
            Assert.True(suffix >= 0, $"max {max}: no cut suffix: {cut}");
            var kept = cut[..suffix];
            Assert.True(kept.Length <= max, $"max {max}: kept {kept.Length} chars");
            Assert.Equal(KeepWhole(units, max), kept);
            Assert.Equal(kept + UntrustedText.CutSuffix(escaped, escaped.Length - kept.Length), cut);
        }
    }

    [Fact]
    public void Cut_OfAReportFormTagRun_KeepsOnlyWholeEscapes()
    {
        var escaped = UntrustedText.EscapeBounded("lib/" + string.Concat(Enumerable.Repeat(Hostile.Tag, 60)), 10_000);

        var cut = RowFile.Cut(escaped, 512);

        var kept = cut[..cut.IndexOf((char)0x2026 + "[+", StringComparison.Ordinal)];
        Assert.Matches(@"^lib/(\\U000E0041)+$", kept);
        Assert.True(kept.Length <= 512 && kept.Length > 512 - 10, $"kept {kept.Length}");
    }

    // ---- Fit ----

    [Fact]
    public void Fit_ARowWithinItsBound_IsUnchanged()
    {
        var row = Row(("a", U("short")), ("n", 3));
        var before = row.ToJsonString();

        Assert.True(RowFile.Fit(row, 1_000));
        Assert.Equal(before, row.ToJsonString());
    }

    /// <summary>The worst case: long Cyrillic, six chars each as served, in several values, nested in an array and an object.</summary>
    [Fact]
    public void Fit_HalvesTheLongestValues_UntilTheRowIsWithinItsBound_AsServed()
    {
        var wide = DrillFixtures.LongNonAscii(3_000);
        var row = Row(("a", U(wide)), ("b", U(wide[..1_500])), ("list", new JsonArray(U(wide), U("x"))), ("nested", Row(("c", U(wide)))));
        Assert.True(RowFile.Chars(row) > 40_000);

        Assert.True(RowFile.Fit(row, RowWriter.MaxRowChars));

        Assert.True(RowFile.Chars(row) <= RowWriter.MaxRowChars, $"{RowFile.Chars(row)} chars");
        Assert.Equal("x", row["list"]![1]!["untrusted"]!.GetValue<string>());
        foreach (var value in RowFile.Strings(row).Where(s => s.Length > 1))
            Assert.Matches("^[" + (char)0x0430 + "-" + (char)0x044F + "]*(" + (char)0x2026 + @"\[\+\d+ chars, sha256:[0-9a-f]{8}\])?$", value);
    }

    [Fact]
    public void Fit_NeverCutsAKeepKey_AndCutsTheOthersAtEscapeBoundaries()
    {
        var path = UntrustedText.EscapeBounded("content/" + string.Concat(Enumerable.Repeat(Hostile.Tag, 50)), 10_000);
        var tags = UntrustedText.EscapeBounded(string.Concat(Enumerable.Repeat(Hostile.Tag, 2_000)), 30_000);
        var row = Row(("path", U(path)), ("note", U(tags)));

        Assert.True(RowFile.Fit(row, 2_000, new HashSet<string> { "path" }));

        Assert.Equal(path, Drill.U(row, "path"));
        var note = Drill.U(row, "note")!;
        Assert.Matches(@"^(\\U000E0041)*" + (char)0x2026 + @"\[\+\d+ chars, sha256:[0-9a-f]{8}\]$", note);
        Assert.True(RowFile.Chars(row) <= 2_000);
    }

    [Fact]
    public void Fit_IsFalse_WhenOnlyAKeepKeyOrPlainTextIsLong()
    {
        var keepOnly = Row(("path", U(new string('p', 5_000))), ("note", U("n")));
        var plain = Row(("text", new string('t', 5_000)));

        Assert.False(RowFile.Fit(keepOnly, 1_000, new HashSet<string> { "path" }));
        Assert.Equal(5_000, Drill.U(keepOnly, "path")!.Length);
        Assert.False(RowFile.Fit(plain, 1_000));
    }

    // ---- UntrustedValue, Strings ----

    [Fact]
    public void UntrustedValue_IsTheWrappedString_Only()
    {
        var row = Row(("a", U("v")), ("b", "plain"), ("c", Row(("untrusted", "v"), ("extra", 1))), ("d", Row(("untrusted", 5))));

        Assert.Equal("v", RowFile.UntrustedValue(row, "a"));
        Assert.Null(RowFile.UntrustedValue(row, "b"));
        Assert.Null(RowFile.UntrustedValue(row, "c"));
        Assert.Null(RowFile.UntrustedValue(row, "d"));
        Assert.Null(RowFile.UntrustedValue(row, "missing"));
    }

    [Fact]
    public void Strings_AreEveryStringValue_NotKeys()
    {
        var row = Row(("key1", "a"), ("n", 1), ("list", new JsonArray("b", U("c"), null)), ("o", Row(("key2", U("d")))));

        Assert.Equal(["a", "b", "c", "d"], RowFile.Strings(row).ToArray());
    }

    // ---- Read ----

    [Fact]
    public void Read_PagesEveryRowExactlyOnce_NeverSplittingOne_AcrossBudgets()
    {
        var rows = Enumerable.Range(0, 40).Select(i => Row(("i", i), ("text", U(new string('x', i * 7))))).ToList();
        var path = Write(rows);

        foreach (var budget in new[] { 400, 450, 1_000, 3_333, 100_000 })
        {
            var seen = new List<int>();
            long? offset = 0;
            var pages = 0;
            while (offset is { } at)
            {
                var page = RowFile.Read(path, at, null, budget, 500, 50_000);
                Assert.Equal(RowProblem.None, page.Problem);
                Assert.NotEmpty(page.Rows);
                Assert.True(page.Rows.Sum(r => RowFile.Chars(r) + 1) <= budget, $"budget {budget}: a page over its budget");
                seen.AddRange(page.Rows.Select(r => r["i"]!.GetValue<int>()));
                offset = page.Next;
                pages++;
            }
            Assert.Equal(Enumerable.Range(0, 40), seen);
            if (budget < 1_000)
                Assert.True(pages > 3, $"budget {budget}: {pages} pages");
        }
    }

    /// <summary>
    /// Why the server's row budget floor is MaxRowChars + 1: Read charges a row its chars plus its newline, so a row at the
    /// row bound is over a budget of MaxRowChars (corrupt) and is served at MaxRowChars + 1.
    /// </summary>
    [Fact]
    public void Read_ARowOfExactlyMaxRowChars_NeedsABudgetOfOneMore()
    {
        JsonObject Sized(int pad) => Row(("text", U(DrillFixtures.LongCjk(500) + new string('x', pad))));
        var row = Sized(RowWriter.MaxRowChars - RowFile.Chars(Sized(0)));
        Assert.Equal(RowWriter.MaxRowChars, RowFile.Chars(row));
        var path = Write([row]);

        var tight = RowFile.Read(path, 0, null, RowWriter.MaxRowChars, 500, 50_000);
        var floored = RowFile.Read(path, 0, null, RowWriter.MaxRowChars + 1, 500, 50_000);

        Assert.Equal(RowProblem.Corrupt, tight.Problem);
        Assert.Empty(tight.Rows);
        Assert.Equal(RowProblem.None, floored.Problem);
        Assert.True(JsonNode.DeepEquals(row, Assert.Single(floored.Rows)));
        Assert.Null(floored.Next);
    }

    [Fact]
    public void Read_StopsAtMaxRows_AndTheNextPageContinues()
    {
        var path = Write(Enumerable.Range(0, 10).Select(i => Row(("i", i))));

        var first = RowFile.Read(path, 0, null, 100_000, 3, 50_000);
        var second = RowFile.Read(path, first.Next!.Value, null, 100_000, 3, 50_000);

        Assert.Equal([0, 1, 2], first.Rows.Select(r => r["i"]!.GetValue<int>()));
        Assert.Equal([3, 4, 5], second.Rows.Select(r => r["i"]!.GetValue<int>()));
        Assert.False(first.ScanLimited);
    }

    [Fact]
    public void Read_WithAFilter_KeepsOnlyMatches_AndAScanLimitSaysSo()
    {
        var path = Write(Enumerable.Range(0, 100).Select(i => Row(("i", i))));
        bool Odd(JsonObject r) => r["i"]!.GetValue<int>() % 2 == 1;

        var all = RowFile.Read(path, 0, Odd, 100_000, 500, 50_000);
        Assert.Equal(Enumerable.Range(0, 100).Where(i => i % 2 == 1), all.Rows.Select(r => r["i"]!.GetValue<int>()));
        Assert.Null(all.Next);

        var seen = new List<int>();
        long? offset = 0;
        var limited = 0;
        while (offset is { } at)
        {
            var page = RowFile.Read(path, at, Odd, 100_000, 500, 30);
            Assert.Equal(RowProblem.None, page.Problem);
            limited += page.ScanLimited ? 1 : 0;
            Assert.Equal(page.Next is not null, page.ScanLimited);
            seen.AddRange(page.Rows.Select(r => r["i"]!.GetValue<int>()));
            offset = page.Next;
        }
        Assert.Equal(Enumerable.Range(0, 100).Where(i => i % 2 == 1), seen);
        Assert.Equal(3, limited);
    }

    [Fact]
    public void Read_AnOffsetThatIsNotARowStart_IsACursorProblem()
    {
        var path = Write(Enumerable.Range(0, 3).Select(i => Row(("i", i))));
        var length = new FileInfo(path).Length;
        var second = File.ReadAllText(path).IndexOf('\n') + 1;

        Assert.Equal(RowProblem.Cursor, RowFile.Read(path, 1, null, 9_000, 500, 50_000).Problem);
        Assert.Equal(RowProblem.Cursor, RowFile.Read(path, second + 1, null, 9_000, 500, 50_000).Problem);
        Assert.Equal(RowProblem.Cursor, RowFile.Read(path, -1, null, 9_000, 500, 50_000).Problem);
        Assert.Equal(RowProblem.Cursor, RowFile.Read(path, length + 1, null, 9_000, 500, 50_000).Problem);
        Assert.Equal([1, 2], RowFile.Read(path, second, null, 9_000, 500, 50_000).Rows.Select(r => r["i"]!.GetValue<int>()));
        var end = RowFile.Read(path, length, null, 9_000, 500, 50_000);
        Assert.Equal(RowProblem.None, end.Problem);
        Assert.Empty(end.Rows);
        Assert.Null(end.Next);
    }

    public static TheoryData<string> Corruptions() =>
        ["a garbage line", "no trailing newline", "a line over MaxRowBytes", "an empty line", "an array row", "raw non-ASCII over the budget as served", "invalid UTF-8", "a duplicate key", "a bare string row"];

    [Theory]
    [MemberData(nameof(Corruptions))]
    public void Read_ACorruptList_IsCorrupt_NeverAPartialPage(string corruption)
    {
        var good = Encoding.ASCII.GetBytes("{\"i\":0}\n{\"i\":1}\n");
        byte[] bytes = corruption switch
        {
            "a garbage line" => [.. good, .. "not json\n"u8],
            "no trailing newline" => [.. good, .. "{\"i\":2}"u8],
            "a line over MaxRowBytes" => [.. good, .. Encoding.ASCII.GetBytes("{\"a\":\"" + new string('x', RowFile.MaxRowBytes) + "\"}\n")],
            "an empty line" => [.. good, .. "\n"u8],
            "an array row" => [.. good, .. "[1,2]\n"u8],
            "raw non-ASCII over the budget as served" => [.. good, .. Encoding.UTF8.GetBytes("{\"a\":\"" + DrillFixtures.LongNonAscii(1_000) + "\"}\n")],
            "invalid UTF-8" => [.. good, .. "{\"a\":\""u8, 0xFF, 0xFE, .. "\"}\n"u8],
            "a duplicate key" => [.. good, .. "{\"i\":2,\"i\":3}\n"u8],
            "a bare string row" => [.. good, .. "\"text\"\n"u8],
            _ => throw new ArgumentException(corruption),
        };
        var path = Path.Combine(dir, "list.jsonl");
        File.WriteAllBytes(path, bytes);

        // A line that only fails as served ends the page before it; the page that starts at it is the corrupt one.
        var page = RowFile.Read(path, 0, null, 3_000, 500, 50_000);
        if (page.Problem == RowProblem.None && page.Next is { } next)
        {
            Assert.Equal(2, page.Rows.Count);
            page = RowFile.Read(path, next, null, 3_000, 500, 50_000);
        }

        Assert.True(page.Problem == RowProblem.Corrupt, $"{corruption}: {page.Problem} ({page.Rows.Count} rows, next {page.Next})");
        Assert.Empty(page.Rows);
        Assert.Null(page.Next);
        Assert.False(string.IsNullOrWhiteSpace(page.Why));
    }

    [Fact]
    public void Read_AMissingList_IsUnreadable_AndNamesOnlyTheFile()
    {
        var page = RowFile.Read(Path.Combine(dir, "gone.jsonl"), 0, null, 9_000, 500, 50_000);

        Assert.Equal(RowProblem.Unreadable, page.Problem);
        Assert.DoesNotContain(dir, page.Why);
    }

    // ---- Find ----

    [Fact]
    public void Find_ParsesOnlyLinesWithTheNeedle_AndStopsAtMax()
    {
        var path = Path.Combine(dir, "find.jsonl");
        File.WriteAllText(path, "{\"k\":\"a\"}\nnot json at all\n{\"k\":\"b\",\"n\":1}\n{\"k\":\"b\",\"n\":2}\n{\"k\":\"b\",\"n\":3}\n", Encoding.ASCII);

        var (rows, problem, _) = RowFile.Find(path, "\"b\""u8.ToArray(), _ => true, 2);

        Assert.Equal(RowProblem.None, problem);
        Assert.Equal([1, 2], rows.Select(r => r["n"]!.GetValue<int>()));
        Assert.Equal(RowProblem.Corrupt, RowFile.Find(path, "json"u8.ToArray(), _ => true, 2).Problem);
        Assert.Empty(RowFile.Find(path, "\"b\""u8.ToArray(), r => r["n"]!.GetValue<int>() > 5, 2).Rows);
    }

    // ---- RowWriter ----

    [Fact]
    public void RowWriter_WritesFittedRows_AndCommitsByRename()
    {
        var wide = DrillFixtures.LongNonAscii(3_000);
        using (var writer = new RowWriter(dir, "rows.jsonl"))
        {
            Assert.True(writer.Add(Row(("a", U(wide)), ("b", U(wide)))));
            Assert.True(writer.Add(Row(("i", 2))));
            Assert.False(File.Exists(Path.Combine(dir, "rows.jsonl")));
            writer.Commit();
            Assert.Equal(2, writer.Rows);
            Assert.False(writer.Truncated);
            Assert.Equal("{\"rows\":2,\"truncated\":false}", writer.Index().ToJsonString());
        }

        var lines = File.ReadAllText(Path.Combine(dir, "rows.jsonl"), Encoding.ASCII);
        Assert.EndsWith("\n", lines);
        Assert.All(lines.Split('\n', StringSplitOptions.RemoveEmptyEntries), l => Assert.True(l.Length <= RowWriter.MaxRowChars, $"a line of {l.Length} chars"));
        Assert.True(lines.All(c => c < 0x80), "a row file holds non-ASCII");
        Assert.Empty(Directory.GetFiles(dir, ".*.tmp"));
    }

    [Fact]
    public void RowWriter_StopsAtItsRowCap_AndSaysTruncated()
    {
        using var writer = new RowWriter(dir, "capped.jsonl", maxRows: 3);

        var added = Enumerable.Range(0, 5).Select(i => writer.Add(Row(("i", i)))).ToList();
        writer.Commit();

        Assert.Equal([true, true, true, false, false], added);
        Assert.Equal(3, writer.Rows);
        Assert.True(writer.Truncated);
        Assert.Equal(3, File.ReadAllLines(Path.Combine(dir, "capped.jsonl")).Length);
    }

    [Fact]
    public void RowWriter_StopsAtItsByteCap_WithoutAPartialRow()
    {
        using var writer = new RowWriter(dir, "bytes.jsonl", maxBytes: 25);

        Assert.True(writer.Add(Row(("i", 1))));   // {"i":1}\n is 8 bytes
        Assert.True(writer.Add(Row(("i", 2))));
        Assert.True(writer.Add(Row(("i", 3))));
        Assert.False(writer.Add(Row(("i", 4))));
        writer.Commit();

        Assert.Equal(3, writer.Rows);
        Assert.Equal(24, writer.Bytes);
        Assert.True(writer.Truncated);
        Assert.Equal(24, new FileInfo(Path.Combine(dir, "bytes.jsonl")).Length);
    }

    [Fact]
    public void RowWriter_ARowThatCannotBeFitted_IsDropped_Counted_AndTheListGoesOn()
    {
        using var writer = new RowWriter(dir, "unfit.jsonl");

        Assert.True(writer.Add(Row(("path", U(new string('p', 20_000)))), new HashSet<string> { "path" }));
        Assert.True(writer.Add(Row(("i", 1))));
        writer.Commit();

        Assert.Equal(1, writer.Rows);
        Assert.Equal(1, writer.Unfitted);
        Assert.True(writer.Truncated);
        Assert.Equal(1, writer.Index()["unfitted"]!.GetValue<int>());
    }

    [Fact]
    public void RowWriter_ARowThatCannotBeFitted_IsWrittenInItsDegradedForm_WhenThatFits()
    {
        using var writer = new RowWriter(dir, "degraded.jsonl");

        Assert.True(writer.Add(Row(("path", U(new string('p', 20_000))), ("kept", 1)), new HashSet<string> { "path" },
            r => Row(("path", U("short")), ("kept", r["kept"]!.GetValue<int>()), ("cut", true))));
        writer.Commit();

        Assert.Equal(1, writer.Rows);
        Assert.Equal(0, writer.Unfitted);
        Assert.False(writer.Truncated);
        Assert.False(writer.Index().ContainsKey("unfitted"));
        Assert.Equal("{\"path\":{\"untrusted\":\"short\"},\"kept\":1,\"cut\":true}", File.ReadAllText(Path.Combine(dir, "degraded.jsonl")).TrimEnd('\n'));
    }

    [Fact]
    public void MaxRowChars_LeavesRoomForAPageOfOneRow_CarriedTwice() =>
        Assert.True(2 * (RowWriter.MaxRowChars + 3_000) <= McpLimits.ResponseBudgetChars && RowWriter.MaxRowChars < McpLimits.PageBudgetChars);

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Methods: helpers
    private static JsonObject U(string text) => new() { ["untrusted"] = text };

    private static JsonObject Row(params (string Key, JsonNode? Value)[] values)
    {
        var row = new JsonObject();
        foreach (var (key, value) in values)
            row[key] = value;
        return row;
    }

    private string Write(IEnumerable<JsonObject> rows)
    {
        var path = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".jsonl");
        File.WriteAllText(path, string.Concat(rows.Select(r => r.ToJsonString(JobProtocol.JsonOptions) + "\n")), Encoding.ASCII);
        return path;
    }

    // The escaper's output as its units: whole escapes, surrogate pairs and single chars.
    private static List<string> Units(string escaped) =>
        [.. Regex.Matches(escaped, @"\\U[0-9A-F]{8}|\\u[0-9a-fA-F]{4}|\\x[0-9a-f]{2}|\\.|\p{Cs}\p{Cs}|.", RegexOptions.Singleline).Select(m => m.Value)];

    private static string KeepWhole(List<string> units, int max)
    {
        var sb = new StringBuilder();
        foreach (var unit in units)
        {
            if (sb.Length + unit.Length > max)
                break;
            sb.Append(unit);
        }
        return sb.ToString();
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "rowfile-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}
