namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// <see cref="ExtractedFile"/> (task S2's <c>read_file</c>, server half), on synthetic entries: a path resolves only when
/// it equals one inventory row's path exactly, and only to a file inside <c>files/</c> or <c>files-bundles/</c>; text mode
/// renders for display (CRLF as LF, hostile code points escaped, invalid UTF-8 as U+FFFD, no sequence split at the range
/// end); hex mode is a 16-byte-a-line dump that reassembles to the exact bytes.
/// </summary>
public sealed class ExtractedFileTests : IDisposable
{
    #region Methods
    // ---- Text ----

    [Fact]
    public void Text_TurnsCrlfIntoLf_AndKeepsNewlinesAndTabs()
    {
        var (text, used, invalid) = ExtractedFile.Text("a\r\nb\nc\td"u8, 1_000, atEnd: true);

        Assert.Equal("a\nb\nc\td", text);
        Assert.Equal(8, used);
        Assert.Equal(0, invalid);
    }

    [Fact]
    public void Text_EscapesEveryHostileCodePoint()
    {
        var bytes = Encoding.UTF8.GetBytes("<" + Hostile.Rlo + Hostile.Zwsp + Hostile.Tag + (char)1 + "\r" + (char)0xFEFF + (char)0x2066 + ">");

        var (text, used, _) = ExtractedFile.Text(bytes, 1_000, atEnd: true);

        Hostile.AssertNoneRaw(text, "text mode");
        Assert.Equal("<" + string.Join("", new[] { "u202e", "u200b", "U000E0041", "x01", "r", "ufeff", "u2066" }.Select(e => Backslash + e)) + ">", text);
        Assert.Equal(bytes.Length, used);
    }

    [Fact]
    public void Text_InvalidUtf8_IsReplacementCharacters_AndCounted()
    {
        var (text, used, invalid) = ExtractedFile.Text(DrillFixtures.InvalidUtf8, 1_000, atEnd: true);

        Assert.Equal("a" + Replacement + "b" + Replacement + "(c", text);
        Assert.Equal(DrillFixtures.InvalidUtf8.Length, used);
        Assert.Equal(2, invalid);
    }

    [Fact]
    public void Text_NeverSplitsASequenceCutByTheRangeEnd_UnlessTheFileEndsThere()
    {
        var head = DrillFixtures.Euro.AsSpan(0, 10);   // nine 'e' and the euro sign's first byte

        var (text, used, invalid) = ExtractedFile.Text(head, 1_000, atEnd: false);
        var (atEnd, usedAtEnd, invalidAtEnd) = ExtractedFile.Text(head, 1_000, atEnd: true);

        Assert.Equal(new string('e', 9), text);
        Assert.Equal(9, used);
        Assert.Equal(0, invalid);
        Assert.Equal(new string('e', 9) + Replacement, atEnd);
        Assert.Equal(10, usedAtEnd);
        Assert.Equal(1, invalidAtEnd);
        Assert.Equal(char.ConvertFromUtf32(0x20AC) + "tail", ExtractedFile.Text(DrillFixtures.Euro.AsSpan(9), 1_000, atEnd: true).Text);
    }

    [Fact]
    public void Text_StaysWithinItsBudget_AndNeverCutsAnEscape()
    {
        var bytes = Encoding.UTF8.GetBytes("ab" + Hostile.Rlo + "cd");

        Assert.Equal(("abcd", 4, 0), ExtractedFile.Text("abcdefgh"u8, 4, atEnd: true));
        Assert.Equal(("ab", 2, 0), ExtractedFile.Text(bytes, 7, atEnd: true));
        Assert.Equal(("ab" + Backslash + "u202e", 5, 0), ExtractedFile.Text(bytes, 8, atEnd: true));
    }

    // ---- Hex ----

    [Fact]
    public void Hex_IsSixteenBytesALine_WithAbsoluteOffsetsAndPrintableAscii()
    {
        var bytes = Enumerable.Range(0x41, 20).Select(i => (byte)i).Append((byte)0x00).ToArray();

        var (text, used) = ExtractedFile.Hex(bytes, 0x100, 10_000);

        var lines = text.Split('\n');
        Assert.Equal(2, lines.Length);
        Assert.Equal("00000100  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|", lines[0]);
        Assert.Equal("00000110  51 52 53 54 00" + new string(' ', 48 - 14) + "  |QRST.|", lines[1]);
        Assert.Equal(bytes.Length, used);
    }

    [Fact]
    public void Hex_StopsAtAWholeLine_WithinItsBudget_AndReassemblesExactly()
    {
        var lineChars = "00000000  ".Length + 48 + "  |0123456789abcdef|\n".Length;

        var (text, used) = ExtractedFile.Hex(DrillFixtures.Binary, 0, lineChars * 5 + 3);

        Assert.Equal(80, used);
        Assert.True(text.Length <= lineChars * 5 + 3);
        Assert.Equal(DrillFixtures.Binary.Take(80), HexBytes(text, 0));
    }

    // ---- Resolve ----

    [Fact]
    public void Resolve_AnExactPath_IsTheRowsFile()
    {
        var entry = Entry(Row("content/a.txt", "files/pkg/content/a.txt"));

        var (row, full, status, problem, corrupt) = ExtractedFile.Resolve(entry, "content/a.txt");

        Assert.Equal(ToolStatus.Succeeded, status);
        Assert.Null(problem);
        Assert.Equal(RowProblem.None, corrupt);
        Assert.Equal(Path.GetFullPath(Path.Combine(entry, "files", "pkg", "content", "a.txt")), full);
        Assert.Equal("content/a.txt", Drill.U(row, "path"));
    }

    /// <summary>A path with a quote and a backslash still matches its row exactly: the pre-check encodes it as the writer did.</summary>
    [Fact]
    public void Resolve_APathWithJsonSpecialCharacters_MatchesExactly()
    {
        const string odd = "content/we\"ird\\x <b>+.txt";
        var entry = Entry(Row(odd, "files/pkg/content/odd.txt"), Row("content/we\"ird", "files/pkg/content/a.txt"));

        Assert.Equal(ToolStatus.Succeeded, ExtractedFile.Resolve(entry, odd).Status);
        Assert.Equal(ToolStatus.NotFound, ExtractedFile.Resolve(entry, "content/we").Status);
    }

    public static TheoryData<string> NotNamed() =>
    [
        "", "content/A.txt", "CONTENT/a.txt", "content/a.txt/", "content/a.txt" + Backslash, "content" + Backslash + "a.txt", " content/a.txt",
        "content/a.txt ", "./content/a.txt", "content//a.txt", "files/pkg/content/a.txt", "content/a.txt\"}", "content/a.tx", "content/a.txt" + (char)0,
    ];

    [Theory]
    [MemberData(nameof(NotNamed))]
    public void Resolve_APathNoRowNamesExactly_IsNotFound(string path)
    {
        var entry = Entry(Row("content/a.txt", "files/pkg/content/a.txt"));

        var (row, full, status, _, corrupt) = ExtractedFile.Resolve(entry, path);

        Assert.Equal(ToolStatus.NotFound, status);
        Assert.Null(full);
        Assert.Null(row);
        Assert.Equal(RowProblem.None, corrupt);
    }

    [Fact]
    public void Resolve_TwoRowsWithThePath_IsNotPermitted()
    {
        var entry = Entry(Row("content/a.txt", "files/pkg/content/a.txt"), Row("content/a.txt", "files/pkg/content/b.txt"));

        var (_, full, status, _, corrupt) = ExtractedFile.Resolve(entry, "content/a.txt");

        Assert.Equal(ToolStatus.NotPermitted, status);
        Assert.Null(full);
        Assert.Equal(RowProblem.None, corrupt);
    }

    [Fact]
    public void Resolve_ANotExtractedRow_IsNotFound_WithItsRow()
    {
        var row = Row("content/x.txt", null, kind: "notExtracted");
        row["note"] = new JsonObject { ["untrusted"] = "declared but never extracted" };
        var entry = Entry(row);

        var (found, full, status, _, _) = ExtractedFile.Resolve(entry, "content/x.txt");

        Assert.Equal(ToolStatus.NotFound, status);
        Assert.Null(full);
        Assert.Equal("declared but never extracted", Drill.U(found, "note"));
    }

    [Fact]
    public void Resolve_AnUnreadableRow_OrOneWithNoFile_IsNotPermitted()
    {
        var link = Row("content/link", "files/pkg/content/a.txt");
        link["readable"] = false;
        var entry = Entry(link, Row("content/long", null), Row("content/empty", ""));

        foreach (var path in new[] { "content/link", "content/long", "content/empty" })
        {
            var (_, full, status, _, corrupt) = ExtractedFile.Resolve(entry, path);
            Assert.True(status == ToolStatus.NotPermitted, $"{path}: {status}");
            Assert.Null(full);
            Assert.Equal(RowProblem.None, corrupt);
        }
    }

    public static TheoryData<string> Outside() =>
    [
        "job.json", "../job.json", "files/../job.json", "files/pkg/../../job.json", "files", "files-evil/a.txt", "filesx/a.txt",
        "files-bundles/../job.json", "files/pkg/../../../outside.txt", "C:/Windows/win.ini", "//server/share/x", "files" + Backslash + ".." + Backslash + "job.json",
        "files/pkg/content/a" + (char)0 + ".txt",
    ];

    [Theory]
    [MemberData(nameof(Outside))]
    public void Resolve_ARowWhoseFileIsOutsideTheExtractedTrees_IsNotPermitted_AndCorrupt(string file)
    {
        var entry = Entry(Row("content/a.txt", file));
        File.WriteAllText(Path.Combine(entry, "job.json"), "{}");

        var (_, full, status, _, corrupt) = ExtractedFile.Resolve(entry, "content/a.txt");

        Assert.Equal(ToolStatus.NotPermitted, status);
        Assert.Null(full);
        Assert.Equal(RowProblem.Corrupt, corrupt);
    }

    [Fact]
    public void Resolve_ABundleFile_IsInside()
    {
        var entry = Entry(Row("host.exe!/inner.dll", "files-bundles/0/inner.dll"));
        Directory.CreateDirectory(Path.Combine(entry, "files-bundles", "0"));
        File.WriteAllText(Path.Combine(entry, "files-bundles", "0", "inner.dll"), "x");

        Assert.Equal(ToolStatus.Succeeded, ExtractedFile.Resolve(entry, "host.exe!/inner.dll").Status);
    }

    [Fact]
    public void Resolve_AFileThatIsGone_IsNotFound_InAdr0034sWords()
    {
        var entry = Entry(Row("content/a.txt", "files/pkg/content/a.txt"));
        File.Delete(Path.Combine(entry, "files", "pkg", "content", "a.txt"));

        var (_, full, status, problem, corrupt) = ExtractedFile.Resolve(entry, "content/a.txt");

        Assert.Equal(ToolStatus.NotFound, status);
        Assert.Null(full);
        Assert.Contains("no longer exists", problem);
        Assert.Equal(RowProblem.None, corrupt);
    }

    [Fact]
    public void Resolve_AMissingOrCorruptInventory_SaysSo()
    {
        var entry = Entry(Row("content/a.txt", "files/pkg/content/a.txt"));
        File.Delete(Path.Combine(entry, JobProtocol.InventoryFile));
        Assert.Equal(RowProblem.Unreadable, ExtractedFile.Resolve(entry, "content/a.txt").Corrupt);

        File.WriteAllText(Path.Combine(entry, JobProtocol.InventoryFile), "{\"path\":{\"untrusted\":\"content/a.txt\"} garbage\n");
        var (_, full, status, _, corrupt) = ExtractedFile.Resolve(entry, "content/a.txt");
        Assert.Equal(RowProblem.Corrupt, corrupt);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Null(full);
    }

    [Fact]
    public void ReadRange_ReadsAtMostLength_AndRefusesAnOffsetPastTheEnd()
    {
        var file = Path.Combine(dir, "range.bin");
        File.WriteAllBytes(file, DrillFixtures.Binary);

        var (bytes, size, status, problem) = ExtractedFile.ReadRange(file, 990, 100);
        Assert.Equal(DrillFixtures.Binary[990..], bytes);
        Assert.Equal(1_000, size);
        Assert.Equal(ToolStatus.Succeeded, status);
        Assert.Null(problem);
        Assert.Empty(ExtractedFile.ReadRange(file, 1_000, 100).Bytes!);
        var past = ExtractedFile.ReadRange(file, 1_001, 100);
        Assert.Null(past.Bytes);
        Assert.Equal(1_000, past.Size);
        Assert.Equal(ToolStatus.InvalidArgument, past.Status);
        Assert.Contains("past the end", past.Problem);
    }

    [Fact]
    public void ReadRange_AFileThatVanished_IsNotFound_InAdr0034sWords()
    {
        var (bytes, _, status, problem) = ExtractedFile.ReadRange(Path.Combine(dir, "gone", "x.bin"), 0, 10);

        Assert.Null(bytes);
        Assert.Equal(ToolStatus.NotFound, status);
        Assert.Contains("no longer exists", problem);
    }

    [Fact]
    public void Text_EscapesTheDefaultIgnorableCodePointsUntrustedTextLetsThrough()
    {
        var points = new[] { 0x034F, 0x061C, 0x115F, 0x17B4, 0x180B, 0x2061, 0x206F, 0x3164, 0xFE0F, 0xFFA0, 0xFFF9, 0x1BCA0, 0x1D173, 0xE0100, 0xE0FFF };
        var bytes = Encoding.UTF8.GetBytes(string.Concat(points.Select(char.ConvertFromUtf32)));

        var (text, used, _) = ExtractedFile.Text(bytes, 10_000, atEnd: true);

        Assert.Equal(string.Concat(points.Select(p => p <= 0xFFFF ? Backslash + "u" + p.ToString("x4") : Backslash + "U" + p.ToString("X8"))), text);
        Assert.Equal(bytes.Length, used);
    }

    [Fact]
    public void Text_HoldsBackACrAtTheRangeEnd_SoACrlfSplitAcrossPagesIsStillOneLf()
    {
        Assert.Equal(("one", 3, 0), ExtractedFile.Text("one\r"u8, 1_000, atEnd: false));
        Assert.Equal(("\ntwo", 5, 0), ExtractedFile.Text("\r\ntwo"u8, 1_000, atEnd: false));
        Assert.Equal(("one" + Backslash + "r", 4, 0), ExtractedFile.Text("one\r"u8, 1_000, atEnd: true));
    }

    /// <summary>A range shorter than its first character, not at the end of the file, still moves on, as U+FFFD.</summary>
    [Fact]
    public void Text_ARangeTooShortForItsFirstCharacter_RendersAReplacement_AndAdvances()
    {
        var (text, used, invalid) = ExtractedFile.Text(DrillFixtures.Euro.AsSpan(9, 1), 1_000, atEnd: false);

        Assert.Equal(Replacement, text);
        Assert.Equal(1, used);
        Assert.Equal(1, invalid);
    }

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>The bytes a hex dump shows, checking each line's offset as it goes.</summary>
    internal static List<byte> HexBytes(string dump, long start)
    {
        var bytes = new List<byte>();
        foreach (var line in dump.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            Assert.Equal(start + bytes.Count, long.Parse(line[..8], NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            Assert.Equal("  ", line[8..10]);
            bytes.AddRange(line.Substring(10, 48).Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(h => byte.Parse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture)));
        }
        return bytes;
    }
    #endregion

    #region Methods: helpers
    // A synthetic entry: the inventory rows, and every row's file (when it names one under files/) with a byte in it.
    private string Entry(params JsonObject[] rows)
    {
        var entry = Directory.CreateDirectory(Path.Combine(dir, Guid.NewGuid().ToString("N")[..8])).FullName;
        Directory.CreateDirectory(Path.Combine(entry, "files", "pkg", "content"));
        File.WriteAllText(Path.Combine(entry, "files", "pkg", "content", "a.txt"), "a");
        File.WriteAllText(Path.Combine(entry, "files", "pkg", "content", "b.txt"), "b");
        File.WriteAllText(Path.Combine(entry, "files", "pkg", "content", "odd.txt"), "odd");
        File.WriteAllText(Path.Combine(entry, JobProtocol.InventoryFile), string.Concat(rows.Select(r => r.ToJsonString(JobProtocol.JsonOptions) + "\n")), Encoding.ASCII);
        return entry;
    }

    private static JsonObject Row(string path, string? file, string kind = "other") => new()
    {
        ["path"] = new JsonObject { ["untrusted"] = path },
        ["pathForm"] = "lossless",
        ["file"] = file,
        ["readable"] = file is not null && kind != "notExtracted",
        ["size"] = 1,
        ["kind"] = kind,
    };
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private static readonly string Replacement = char.ConvertFromUtf32(0xFFFD);

    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "extracted-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}
