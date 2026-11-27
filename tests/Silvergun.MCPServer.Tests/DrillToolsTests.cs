namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using ModelContextProtocol.Protocol;

using Silvergun.CodeAnalysis.IL;
using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S2 tools over completed entries, in-process (task S2, Accept): every list pages every row exactly once, filters
/// page correctly and keep <c>total</c> unfiltered, every result is within the response budget, package text is escaped
/// and only ever inside <c>{"untrusted": ...}</c> or the one fenced block, and every result passes
/// <see cref="Drill.Checked"/>. Nothing here changes an entry.
/// </summary>
[Collection(DrillCollection.Name)]
public sealed class DrillToolsTests(DrillFixture fixture)
{
    #region Methods
    [Fact]
    public void ListFiles_PagesEveryRowExactlyOnce_OverSeveralPages_AndNeverServesFile()
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.ListFiles(fixture.JobId, cursor: c));

        var expected = Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile, dropFile: true);
        Drill.SameRows(expected, rows, "list_files");
        Assert.True(pages >= 2, $"{rows.Count} rows in {pages} page(s)");
        Assert.Equal(expected.Count, last.GetProperty("total").GetInt32());
        Assert.Equal(expected.Count, Index()["files"]!["rows"]!.GetValue<int>());
        Assert.True(expected.Count > 300, $"{expected.Count} rows");
        Assert.False(last.TryGetProperty("listTruncated", out _));
        Assert.All(rows, r =>
        {
            Assert.False(r.AsObject().ContainsKey("file"), $"a served row has file: {r.ToJsonString()}");
            Assert.True(r["readable"] is JsonValue v && v.GetValueKind() is JsonValueKind.True or JsonValueKind.False);
        });
        Assert.Equal(rows.Count, rows.Select(r => Drill.U(r, "path")).Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [InlineData("content/many/", null, 2)]
    [InlineData("content/many/file01", null, 1)]
    [InlineData(null, "script", 1)]
    [InlineData(null, "Assembly", 1)]
    [InlineData(null, "notExtracted", 1)]
    [InlineData("content/", "other", 2)]
    [InlineData("build/", null, 1)]
    [InlineData("nope/", null, 1)]
    public void ListFiles_Filters_PageEveryMatchOnce_AndTotalStaysUnfiltered(string? prefix, string? kind, int minPages)
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.ListFiles(fixture.JobId, prefix, kind, c));

        var all = Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile, dropFile: true);
        var expected = all.Where(r => (prefix is null || Drill.U(r, "path")!.StartsWith(prefix, StringComparison.Ordinal))
            && (kind is null || string.Equals(Drill.Str(r["kind"]), kind, StringComparison.OrdinalIgnoreCase))).ToList();
        Drill.SameRows(expected, rows, $"list_files {prefix} {kind}");
        Assert.True(pages >= minPages, $"{rows.Count} rows in {pages} page(s)");
        Assert.Equal(all.Count, last.GetProperty("total").GetInt32());
        if (prefix != "nope/")
            Assert.NotEmpty(rows);
    }

    public static TheoryData<string> Kinds() => [.. Enum.GetValues<FindingKind>().Select(PackageFindings.Name)];

    [Theory]
    [MemberData(nameof(Kinds))]
    public void GetFindings_EveryKind_PagesEveryRowExactlyOnce_WithItsPass(string kind)
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, kind, cursor: c));

        var expected = Drill.Lines(fixture.EntryDir, $"findings-{kind}.jsonl");
        Drill.SameRows(expected, rows, kind);
        var list = Index()["findings"]![kind]!;
        Assert.Equal(list["rows"]!.GetValue<int>(), last.GetProperty("total").GetInt32());
        Assert.Equal(expected.Count, last.GetProperty("total").GetInt32());
        Assert.Equal(kind, last.GetProperty("kind").GetString());
        Assert.True(JsonNode.DeepEquals(list["pass"], JsonNode.Parse(last.GetProperty("pass").GetRawText())), $"{kind}: pass {last.GetProperty("pass")}");
        Assert.False(last.TryGetProperty("listTruncated", out _));
        if (kind is "capabilities" or "indicators" or "hidden-content" or "scripts" or "native" or "anomalies")
            Assert.True(rows.Count > 0, $"the fixture has no {kind} rows");
        if (kind is "capabilities" or "scripts")
            Assert.True(pages >= 2, $"{kind}: {rows.Count} rows in {pages} page(s)");
    }

    [Theory]
    [InlineData("capabilities", "lib/net8.0/Drill.Hostile.dll", null, 2)]
    [InlineData("capabilities", null, "fetch", 1)]
    [InlineData("capabilities", null, "PROCESSEXECUTION", 2)]
    [InlineData("capabilities", "lib/net8.0/Drill.Hostile.dll", "network", 1)]
    [InlineData("indicators", "lib/net8.0/Drill.Hostile.dll", "wide.example", 1)]
    [InlineData("hidden-content", "lib/net8.0/Other.dll", null, 1)]
    [InlineData("scripts", null, "SG0011", 1)]
    [InlineData("scripts", null, "drill03", 1)]
    [InlineData("native", null, "ELF", 1)]
    [InlineData("anomalies", null, "bidi", 1)]
    public void GetFindings_AssemblyAndFilter_PageEveryMatchOnce_AndTotalStaysUnfiltered(string kind, string? assembly, string? filter, int minPages)
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, kind, assembly, filter, c));

        var all = Drill.Lines(fixture.EntryDir, $"findings-{kind}.jsonl");
        var expected = all.Where(r => (assembly is null || Drill.U(r, "assembly") == assembly)
            && (filter is null || RowFile.Strings(r).Any(s => s.Contains(filter, StringComparison.OrdinalIgnoreCase)))).ToList();
        Drill.SameRows(expected, rows, $"{kind} {assembly} {filter}");
        Assert.True(pages >= minPages, $"{rows.Count} rows in {pages} page(s)");
        Assert.Equal(all.Count, last.GetProperty("total").GetInt32());
        if (!assembly?.EndsWith("Other.dll") ?? true)
            Assert.NotEmpty(rows);
    }

    /// <summary>
    /// Review C1: an assembly whose path is long CJK and '+' (six chars each as served) with long caller names. Its rows are
    /// cut to fit, never in the assembly key, so the assembly filter, given the list_files path, still matches every row.
    /// </summary>
    [Theory]
    [InlineData("capabilities")]
    [InlineData("indicators")]
    public void GetFindings_TheAssemblyFilter_MatchesALongCjkPathExactly_ThoughItsRowsWereCut(string kind)
    {
        var path = Drill.U(Assert.Single(Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile),
            r => Drill.U(r, "path")!.StartsWith("lib/netstandard2.0/", StringComparison.Ordinal)), "path")!;
        Assert.Equal(DrillFixtures.CjkAssembly, path);

        var (rows, _, _) = Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, kind, path, cursor: c));

        var all = Drill.Lines(fixture.EntryDir, $"findings-{kind}.jsonl");
        var expected = all.Where(r => Drill.U(r, "assembly") == path).ToList();
        Drill.SameRows(expected, rows, $"{kind} of the CJK assembly");
        Assert.NotEmpty(rows);
        Assert.All(rows, r => Assert.Equal(path, Drill.U(r, "assembly")));
        var wide = Assert.Single(rows, r => Drill.U(r, "callerMethod")?.StartsWith("Wide", StringComparison.Ordinal) == true);
        var callers = (Drill.U(wide, "callerType") + Drill.U(wide, "callerMethod")).Count(c => c is >= (char)0x0430 and <= (char)0x044F);
        Assert.True(callers < 2 * 500, $"the wide row keeps {callers} Cyrillic chars of its caller: it was not cut to fit");
        Assert.True(RowFile.Chars(wide.AsObject()) <= RowWriter.MaxRowChars);
    }

    [Fact]
    public void GetFindings_KindIsCaseInsensitive()
    {
        var result = Drill.Checked(fixture.Tools.GetFindings(fixture.JobId, " Hidden-Content "));

        Assert.Equal("Succeeded", Drill.Status(result));
        Assert.Equal("hidden-content", Drill.S(result).GetProperty("kind").GetString());
    }

    [Theory]
    [InlineData(null, null, 2)]
    [InlineData("lib/net8.0", null, 2)]
    [InlineData("nope", null, 1)]
    [InlineData(null, "processExecution", 2)]
    [InlineData(null, "PROCESSEXECUTION", 2)]
    [InlineData(null, "network", 1)]
    [InlineData("lib/net8.0", "fileSystem", 1)]
    public void GetReachability_PagesEveryRowExactlyOnce_AndFiltersKeepFolderRows(string? folder, string? capability, int minPages)
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.GetReachability(fixture.JobId, folder, capability, c));

        var sink = capability is null ? null : JsonNamingPolicy.CamelCase.ConvertName(Enum.Parse<Capability>(capability, ignoreCase: true).ToString());
        var all = Drill.Lines(fixture.EntryDir, JobProtocol.ReachabilityFile);
        var expected = all.Where(r => (folder is null || Drill.U(r, "folder") == folder)
            && (sink is null || Drill.Str(r["type"]) == "folder" || Drill.Str(r["capability"]) == sink || Drill.Str(r["with"]) == sink)).ToList();
        Drill.SameRows(expected, rows, $"reachability {folder} {capability}");
        Assert.True(pages >= minPages, $"{rows.Count} rows in {pages} page(s)");
        Assert.Equal(all.Count, last.GetProperty("total").GetInt32());
        Assert.Equal("completed", last.GetProperty("reachability").GetString());
        var index = Index()["reachability"]!;
        Assert.Equal(index["sitesDropped"]!.GetValue<int>(), last.TryGetProperty("sitesDropped", out var dropped) ? dropped.GetInt32() : 0);
        Assert.False(last.TryGetProperty("statementsDropped", out _) && index["statementsDropped"]!.GetValue<int>() == 0, "statementsDropped is news-only");
        if (folder is null && capability is null)
            Assert.Equal(["folder", "ssaSite", "statement"], rows.Select(r => Drill.Str(r["type"])!).Distinct().Order());
        if (folder != "nope")
            Assert.Contains(rows, r => Drill.Str(r["type"]) == "folder");
    }

    /// <summary>
    /// The worst case for bounds: rows of long Cyrillic (six chars each as served). Every stored row is within the row bound,
    /// a page of them is within the page budget (each page above was <see cref="Drill.Checked"/>), and the widest row was cut
    /// by <see cref="RowFile.Fit"/> beyond its fields' own bounds.
    /// </summary>
    [Fact]
    public void Bounds_EveryRowIsWithinTheRowBound_AndTheWidestWasFitted()
    {
        // The inventory, reachability, the eight finding kinds, and (since S3) members and strings.
        var files = Directory.GetFiles(fixture.EntryDir, "*.jsonl");
        Assert.Equal(12, files.Length);
        Assert.Contains(Path.Combine(fixture.EntryDir, JobProtocol.MembersFile), files);
        Assert.Contains(Path.Combine(fixture.EntryDir, JobProtocol.StringsFile), files);
        var widest = 0;
        foreach (var file in files)
            foreach (var line in File.ReadAllLines(file, Encoding.ASCII))
            {
                Assert.True(line.Length <= RowWriter.MaxRowChars, $"{Path.GetFileName(file)}: a row of {line.Length} chars");
                Assert.True(line.All(c => c < 0x80), $"{Path.GetFileName(file)}: a row holds non-ASCII");
                widest = Math.Max(widest, line.Length);
            }
        Assert.True(widest > McpLimits.PageBudgetChars / 2, $"the widest row is {widest} chars: no page holds only one row");

        var wides = Drill.Lines(fixture.EntryDir, "findings-indicators.jsonl", r => Drill.U(r, "value") == "wide.example");
        Assert.Equal(2, wides.Count);   // one per assembly
        foreach (var wide in wides)
        {
            var cyrillic = RowFile.Strings(wide).Sum(s => s.Count(c => c is >= (char)0x0430 and <= (char)0x044F));
            Assert.True(cyrillic < 3 * 512 - 100, $"the wide row keeps {cyrillic} Cyrillic chars: it was not fitted");
            Assert.True(RowFile.Chars(wide.AsObject()) <= RowWriter.MaxRowChars);
        }
    }

    [Fact]
    public void HostileNames_AreServedEscaped_InsideUntrusted()
    {
        var files = Drill.PageAll(c => fixture.Tools.ListFiles(fixture.JobId, "content/", null, c)).Rows;
        var named = Assert.Single(files, r => Drill.U(r, "path") == DrillFixtures.EscapedName);
        Assert.True(named["readable"]!.GetValue<bool>());
        Assert.Contains(files, r => Drill.U(r, "path") == "content/" + Hostile.Forgeries[0] + ".txt" && Drill.Str(r["kind"]) == "notExtracted");
        Assert.Contains(files, r => Drill.U(r, "path") == "content/line" + Backslash + "nbreak.txt" && Drill.Str(r["kind"]) == "notExtracted");

        var capabilities = Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, "capabilities", cursor: c)).Rows;
        var escapedType = "Drill.Ev" + Backslash + "u202eil" + Backslash + "u200bTy" + Backslash + "U000E0041pe";
        Assert.Contains(capabilities, r => Drill.U(r, "callerType") == escapedType && Drill.U(r, "callerMethod") == ".cctor");

        var indicators = Drill.PageAll(c => fixture.Tools.GetFindings(fixture.JobId, "indicators", cursor: c)).Rows;
        var excerpt = Drill.U(Assert.Single(indicators, r => Drill.U(r, "value") == "evil.example" && Drill.U(r, "assembly") == "lib/net8.0/Drill.Hostile.dll"), "excerpt")!;
        Assert.Contains(Backslash + "u202e", excerpt);
        Assert.Contains(Backslash + "U000E0041", excerpt);
        Assert.Contains(Hostile.Forgeries[0], excerpt);
    }

    public static TheoryData<string> HostileFiles() => [DrillFixtures.HostileTxt, "mcp.drill.nuspec", "tools/install.ps1", "build/net8.0/drill00.targets", "_escaped"];

    [Theory]
    [MemberData(nameof(HostileFiles))]
    public void ReadFile_HostileContent_IsFencedOnce_InBothModes_AndForgeriesAreNeutralised(string path)
    {
        path = path == "_escaped" ? DrillFixtures.EscapedName : path;

        var text = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, path));
        var hex = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, path, @as: "hex"));

        Assert.Equal("Succeeded", Drill.Status(text));
        Assert.Equal("Succeeded", Drill.Status(hex));
        Assert.NotEqual(Drill.S(text).GetProperty("content").GetProperty("fence").GetString(), Drill.S(hex).GetProperty("content").GetProperty("fence").GetString());
        Assert.Equal(path, Drill.U(JsonNode.Parse(Drill.S(text).GetRawText()), "path"));
        Assert.Equal(Drill.Inner(text).Length + 2 + Drill.Bulk(text)!.Split('\n')[0].Length + Drill.Bulk(text)!.Split('\n')[^1].Length, Drill.Bulk(text)!.Length);
        if (path == DrillFixtures.HostileTxt)
        {
            var inner = Drill.Inner(text);
            Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=0000000000000000>>>", inner);
            Assert.Contains(@"<<\x3cUNTRUSTED nonce=0000000000000000>>>", inner);
            Assert.Contains("x" + Backslash + "u202ey" + Backslash + "u200bz\nw" + Backslash + "U000E0041v", inner);
        }
        if (path == "mcp.drill.nuspec")
            Assert.Contains(@"<<\x3cEND UNTRUSTED nonce=ffffffffffffffff>>>", Drill.Inner(text));
    }

    public static TheoryData<string> NotNamed() =>
    [
        "../job.json", "job.json", "the raw file column", "an absolute extracted path", "an absolute job.json", "CONTENT/HOSTILE.TXT", "Content/hostile.txt",
        "content/hostile.txt/", "content/hostile.txt\\", "content\\hostile.txt", " content/hostile.txt", "content/hostile.txt ", "./content/hostile.txt",
        "content//hostile.txt", "the raw hostile name", "an escape in upper case", "an escape with its backslash doubled", "content/many", "content/many/",
        "a JSON injection", " ", "files", "index.json",
    ];

    [Theory]
    [MemberData(nameof(NotNamed))]
    public void ReadFile_RefusesEveryPathTheInventoryDoesNotName(string what)
    {
        var path = what switch
        {
            "the raw file column" => "files/package.nupkg/content/hostile.txt",
            "an absolute extracted path" => Path.Combine(fixture.EntryDir, "files", "package.nupkg", "content", "hostile.txt"),
            "an absolute job.json" => Path.Combine(fixture.EntryDir, JobProtocol.JobFile),
            "the raw hostile name" => "content/n" + Hostile.Rlo + "a" + Hostile.Zwsp + "m" + Hostile.Tag + "e.txt",
            "an escape in upper case" => DrillFixtures.EscapedName.Replace("u202e", "u202E"),
            "an escape with its backslash doubled" => DrillFixtures.EscapedName.Replace(Backslash + "u202e", Backslash + Backslash + "u202e"),
            "a JSON injection" => "x\"},\"path\":{\"untrusted\":\"content/hostile.txt",
            _ => what,
        };
        // The refused path names a real file wherever it can: the refusal is the inventory's, not a missing file's.
        Assert.True(File.Exists(Path.Combine(fixture.EntryDir, JobProtocol.JobFile)));
        if (what is "the raw file column")
            Assert.True(File.Exists(Path.Combine(fixture.EntryDir, path)), path);
        if (what is "an absolute extracted path" or "an absolute job.json")
            Assert.True(File.Exists(path), path);

        var result = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, path));

        Assert.True(result.IsError, $"{what}: served");
        Assert.Equal("NotFound", Drill.Status(result));
        Assert.False(Drill.S(result).GetProperty("retry").GetBoolean());
        Assert.Null(Drill.Bulk(result));
        Assert.True(Directory.Exists(fixture.EntryDir), "a refusal discarded the entry");
    }

    [Theory]
    [InlineData("")]
    [InlineData("long")]
    public void ReadFile_AnEmptyOrOverlongPath_IsInvalidArgument(string what)
    {
        var result = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, what == "long" ? "content/" + new string('a', 2_100) : what));

        Assert.Equal("InvalidArgument", Drill.Status(result));
    }

    /// <summary>The other side of refusing every unnamed path: every path list_files says is readable reads, as that row.</summary>
    [Fact]
    public void ReadFile_EveryReadableRow_Reads_AsItsRow()
    {
        var rows = Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile, dropFile: true);
        foreach (var row in rows.Where(r => r["readable"]!.GetValue<bool>()))
        {
            var result = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, Drill.U(row, "path")!, length: 16, @as: "hex"));
            var s = Drill.S(result);
            Assert.True(!result.IsError, $"{Drill.U(row, "path")}: {s}");
            Assert.Equal(row["size"]!.GetValue<long>(), s.GetProperty("size").GetInt64());
            Assert.Equal(Drill.Str(row["sha256"]), s.GetProperty("sha256").GetString());
        }
        Assert.True(rows.Count(r => r["readable"]!.GetValue<bool>()) > 300);
    }

    [Fact]
    public void ReadFile_ANotExtractedRow_IsNotFound_WithItsNoteAsUntrusted()
    {
        var notExtracted = Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile, r => Drill.Str(r["kind"]) == "notExtracted");
        Assert.Equal(2, notExtracted.Count);

        foreach (var row in notExtracted)
        {
            var result = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, Drill.U(row, "path")!));
            Assert.Equal("NotFound", Drill.Status(result));
            Assert.Contains("never extracted", Drill.S(result).GetProperty("message").GetString());
            Assert.False(string.IsNullOrEmpty(Drill.S(result).GetProperty("reason").GetProperty("untrusted").GetString()));
        }
    }

    // ---- read_file content ----

    [Theory]
    [InlineData("content/binary.bin", 256)]
    [InlineData("content/binary.bin", 65_536)]
    [InlineData("content/big.txt", 16_384)]
    [InlineData("content/big.txt", 65_536)]
    public void ReadFile_Hex_PagedViaNext_ReassemblesTheExactBytes(string path, int length)
    {
        var expected = path.EndsWith(".bin") ? DrillFixtures.Binary : DrillFixtures.Big;
        var bytes = new List<byte>();
        var cut = false;
        long? offset = 0;
        var pages = 0;
        while (offset is { } at)
        {
            var result = Read(path, at, length, "hex");
            var s = Drill.S(result);
            Assert.Equal("hex", s.GetProperty("as").GetString());
            var page = ExtractedFileTests.HexBytes(Drill.Inner(result), at);
            Assert.Equal(s.GetProperty("bytes").GetInt32(), page.Count);
            bytes.AddRange(page);
            cut |= s.GetProperty("truncated").GetBoolean();
            offset = s.TryGetProperty("next", out var next) ? next.GetInt64() : null;
            Assert.True(++pages < 1_000);
        }
        Assert.Equal(expected, bytes);
        if (path.EndsWith(".bin") && length == 256)
            Assert.True(pages >= 4);
        if (path.EndsWith(".txt"))
            Assert.True(cut, "the budget never cut a hex page");
    }

    [Fact]
    public void ReadFile_Text_PagedViaNext_ReassemblesTheFile()
    {
        var text = new StringBuilder();
        long? offset = 0;
        var pages = 0;
        while (offset is { } at)
        {
            var result = Read("content/big.txt", at, 65_536, "text");
            text.Append(Drill.Inner(result));
            offset = Drill.S(result).TryGetProperty("next", out var next) ? next.GetInt64() : null;
            pages++;
        }
        Assert.Equal(Encoding.ASCII.GetString(DrillFixtures.Big), text.ToString());
        Assert.True(pages >= 3, $"{pages} page(s)");
    }

    [Fact]
    public void ReadFile_Text_TurnsCrlfIntoLf()
    {
        var result = Read("content/crlf.txt", 0, 16_384, "text");

        Assert.Equal("one\ntwo\nthree\n", Drill.Inner(result));
        Assert.Equal(16, Drill.S(result).GetProperty("bytes").GetInt32());
        Assert.True(Drill.S(result).GetProperty("eof").GetBoolean());
    }

    [Fact]
    public void ReadFile_Text_InvalidUtf8_IsReplacementCharacters_Counted()
    {
        var result = Read("content/invalid.txt", 0, 16_384, "text");

        Assert.Equal("a" + Replacement + "b" + Replacement + "(c", Drill.Inner(result));
        Assert.Equal(2, Drill.S(result).GetProperty("invalidUtf8").GetInt32());
        Assert.False(Drill.S(Read("content/crlf.txt", 0, 16_384, "text")).TryGetProperty("invalidUtf8", out _));
    }

    [Fact]
    public void ReadFile_Text_AMultiByteCharacterCutByTheRange_IsNotSplit_AndNextContinuesAtIt()
    {
        var first = Read("content/euro.txt", 0, 10, "text");
        var s = Drill.S(first);
        Assert.Equal(new string('e', 9), Drill.Inner(first));
        Assert.Equal(9, s.GetProperty("bytes").GetInt32());
        Assert.Equal(9, s.GetProperty("next").GetInt64());
        Assert.True(s.GetProperty("truncated").GetBoolean());
        Assert.False(s.GetProperty("eof").GetBoolean());
        Assert.False(s.TryGetProperty("invalidUtf8", out _));

        var second = Read("content/euro.txt", 9, 10, "text");
        Assert.Equal(char.ConvertFromUtf32(0x20AC) + "tail", Drill.Inner(second));
        Assert.True(Drill.S(second).GetProperty("eof").GetBoolean());
    }

    /// <summary>
    /// Paging by next must end: a page that is not at the end of the file has read something. With a length smaller than
    /// the multi-byte character at the offset, the text renderer cannot render it whole.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void ReadFile_Text_EveryPageThatIsNotTheLastMakesProgress(int length)
    {
        var offsets = new List<long>();
        long? offset = 0;
        while (offset is { } at && offsets.Count < 50)
        {
            offsets.Add(at);
            var s = Drill.S(Read("content/euro.txt", at, length, "text"));
            offset = s.TryGetProperty("next", out var next) ? next.GetInt64() : null;
            Assert.True(offset is null || offset > at, $"length {length}: a page at offset {at} read {s.GetProperty("bytes")} bytes and its next is {offset}, so paging never ends");
        }
        Assert.Null(offset);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(3, 3)]
    [InlineData(1_000_000, 16)]
    public void ReadFile_LengthIsClamped(int length, int bytes)
    {
        var s = Drill.S(Read("content/crlf.txt", 0, length, "hex"));

        Assert.Equal(bytes, s.GetProperty("bytes").GetInt32());
        Assert.False(s.GetProperty("truncated").GetBoolean());
    }

    [Fact]
    public void ReadFile_AnOffsetAtTheEnd_IsAnEmptyLastPage_AndPastItIsInvalidArgument()
    {
        var end = Drill.S(Read("content/crlf.txt", 16, 100, "text"));
        Assert.Equal(0, end.GetProperty("bytes").GetInt32());
        Assert.True(end.GetProperty("eof").GetBoolean());
        Assert.False(end.TryGetProperty("next", out _));

        foreach (var offset in new[] { 17L, long.MaxValue, -1L })
        {
            var past = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, "content/crlf.txt", offset));
            Assert.True(Drill.Status(past) == "InvalidArgument", $"offset {offset}: {Drill.S(past)}");
        }
    }

    [Theory]
    [InlineData("HEX", "hex")]
    [InlineData(" hex ", "hex")]
    [InlineData("", "text")]
    [InlineData("Text", "text")]
    public void ReadFile_As_IsCaseInsensitive(string @as, string mode) =>
        Assert.Equal(mode, Drill.S(Read("content/crlf.txt", 0, 100, @as)).GetProperty("as").GetString());

    // ---- cursors ----

    [Fact]
    public void ACursorFromAnotherKindFilterToolOrJob_IsInvalidArgument()
    {
        var files = Next(fixture.Tools.ListFiles(fixture.JobId));
        var capabilities = Next(fixture.Tools.GetFindings(fixture.JobId, "capabilities"));
        var filtered = Next(fixture.Tools.GetFindings(fixture.JobId, "capabilities", filter: "processexecution"));
        var reachability = Next(fixture.Tools.GetReachability(fixture.JobId));

        var refused = new (string What, Func<CallToolResult> Call)[]
        {
            ("list_files cursor in get_findings", () => fixture.Tools.GetFindings(fixture.JobId, "capabilities", cursor: files)),
            ("list_files cursor in get_reachability", () => fixture.Tools.GetReachability(fixture.JobId, cursor: files)),
            ("list_files cursor with a prefix", () => fixture.Tools.ListFiles(fixture.JobId, "content/", cursor: files)),
            ("list_files cursor with a kind", () => fixture.Tools.ListFiles(fixture.JobId, kind: "other", cursor: files)),
            ("capabilities cursor for scripts", () => fixture.Tools.GetFindings(fixture.JobId, "scripts", cursor: capabilities)),
            ("capabilities cursor with a filter", () => fixture.Tools.GetFindings(fixture.JobId, "capabilities", filter: "x", cursor: capabilities)),
            ("capabilities cursor with an assembly", () => fixture.Tools.GetFindings(fixture.JobId, "capabilities", "lib/net8.0/Drill.Hostile.dll", cursor: capabilities)),
            ("filtered cursor without its filter", () => fixture.Tools.GetFindings(fixture.JobId, "capabilities", cursor: filtered)),
            ("filtered cursor with another filter", () => fixture.Tools.GetFindings(fixture.JobId, "capabilities", filter: "network", cursor: filtered)),
            ("reachability cursor with a folder", () => fixture.Tools.GetReachability(fixture.JobId, "lib/net8.0", cursor: reachability)),
            ("reachability cursor with a capability", () => fixture.Tools.GetReachability(fixture.JobId, capability: "network", cursor: reachability)),
            ("reachability cursor in list_files", () => fixture.Tools.ListFiles(fixture.JobId, cursor: reachability)),
            ("cursor of another job", () => fixture.Tools.ListFiles(fixture.SmallJobId, cursor: files)),
            ("findings cursor of another job", () => fixture.Tools.GetFindings(fixture.SmallJobId, "capabilities", cursor: capabilities)),
        };

        foreach (var (what, call) in refused)
        {
            var result = Drill.Checked(call());
            Assert.True(Drill.Status(result) == "InvalidArgument", $"{what}: {Drill.S(result)}");
            Assert.False(Drill.S(result).GetProperty("retry").GetBoolean());
            Assert.Contains("not one this query issued", Drill.S(result).GetProperty("message").GetString());
        }
        Assert.Equal("Succeeded", Drill.Status(fixture.Tools.GetFindings(fixture.JobId, "Capabilities", filter: "processexecution", cursor: filtered)));
    }

    [Fact]
    public void AForgedOffset_IsRefusedUnlessItStartsARowOfTheSameList()
    {
        var cursor = Next(fixture.Tools.ListFiles(fixture.JobId));
        var lines = File.ReadAllBytes(Path.Combine(fixture.EntryDir, JobProtocol.InventoryFile));
        var starts = new List<long> { 0 };
        for (var i = 0; i < lines.Length - 1; i++)
            if (lines[i] == '\n')
                starts.Add(i + 1);

        foreach (var offset in new[] { starts[5] + 1, starts[5] - 1, starts[7] + 10, lines.Length + 1L, 3 })
        {
            var result = Drill.Checked(fixture.Tools.ListFiles(fixture.JobId, cursor: Drill.Forge(cursor, p => [p[0], p[1], offset.ToString()])));
            Assert.True(Drill.Status(result) == "InvalidArgument", $"offset {offset}: {Drill.S(result)}");
        }

        var atRow = Drill.Checked(fixture.Tools.ListFiles(fixture.JobId, cursor: Drill.Forge(cursor, p => [p[0], p[1], starts[5].ToString()])));
        Assert.Equal("Succeeded", Drill.Status(atRow));
        var expected = Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile, dropFile: true)[5];
        Assert.True(JsonNode.DeepEquals(expected, JsonNode.Parse(Drill.S(atRow).GetProperty("rows")[0].GetRawText())));
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("c1.!!!")]
    [InlineData("a tampered hash")]
    [InlineData("a tampered time")]
    [InlineData("overlong")]
    public void AMalformedCursor_IsInvalidArgument(string what)
    {
        var cursor = Next(fixture.Tools.GetFindings(fixture.JobId, "scripts"));
        var bad = what switch
        {
            "a tampered hash" => Drill.Forge(cursor, p => [new string('0', 16), p[1], p[2]]),
            "a tampered time" => Drill.Forge(cursor, p => [p[0], "1", p[2]]),
            "overlong" => cursor + new string('A', 2_100),
            _ => what,
        };

        var result = Drill.Checked(fixture.Tools.GetFindings(fixture.JobId, "scripts", cursor: bad));

        Assert.Equal("InvalidArgument", Drill.Status(result));
    }

    // ---- other behaviour ----

    [Fact]
    public void GetReachability_OnAStandardJob_IsNotAnalysed()
    {
        var result = Drill.Checked(fixture.Tools.GetReachability(fixture.SmallJobId));

        var s = Drill.S(result);
        Assert.True(result.IsError);
        Assert.Equal("NotAnalysed", Drill.Status(result));
        Assert.False(s.GetProperty("retry").GetBoolean());
        Assert.Equal("notRun", s.GetProperty("reachability").GetString());
        Assert.Contains("deep", s.GetProperty("message").GetString());
        Assert.False(s.TryGetProperty("rows", out _));
    }

    [Fact]
    public void TheSmallStandardJob_ServesItsListsToo()
    {
        var (files, _, _) = Drill.PageAll(c => fixture.Tools.ListFiles(fixture.SmallJobId, cursor: c));
        Drill.SameRows(Drill.Lines(fixture.SmallEntryDir, JobProtocol.InventoryFile, dropFile: true), files, "small list_files");
        foreach (var kind in Enum.GetValues<FindingKind>().Select(PackageFindings.Name))
            Drill.SameRows(Drill.Lines(fixture.SmallEntryDir, $"findings-{kind}.jsonl"), Drill.PageAll(c => fixture.Tools.GetFindings(fixture.SmallJobId, kind, cursor: c)).Rows, $"small {kind}");
    }

    public static TheoryData<string> PerFileKinds() => ["scripts", "yara", "native", "anomalies", "vulnerabilities"];

    [Theory]
    [MemberData(nameof(PerFileKinds))]
    public void GetFindings_AssemblyOnAKindThatIsNotPerAssembly_IsInvalidArgument(string kind)
    {
        var result = Drill.Checked(fixture.Tools.GetFindings(fixture.JobId, kind, assembly: "lib/net8.0/Drill.Hostile.dll"));

        Assert.Equal("InvalidArgument", Drill.Status(result));
        Assert.False(Drill.S(result).TryGetProperty("rows", out _));
    }

    public static TheoryData<string> BadArguments() =>
    [
        "list_files kind dll", "list_files long prefix", "get_findings kind bogus", "get_findings kind empty", "get_findings kind null", "get_findings long filter",
        "read_file as binary", "get_reachability capability bogus", "get_reachability capability digits", "get_reachability capability list", "get_reachability capability or-ed pair", "get_reachability long folder",
    ];

    [Theory]
    [MemberData(nameof(BadArguments))]
    public void ABadArgument_IsInvalidArgument_BeforeTheJobIsRead(string what)
    {
        var tools = fixture.Tools;
        var job = fixture.JobId;
        var result = Drill.Checked(what switch
        {
            "list_files kind dll" => tools.ListFiles(job, kind: "dll"),
            "list_files long prefix" => tools.ListFiles(job, new string('p', 2_100)),
            "get_findings kind bogus" => tools.GetFindings(job, "bogus"),
            "get_findings kind empty" => tools.GetFindings(job, ""),
            "get_findings kind null" => tools.GetFindings(job, null!),
            "get_findings long filter" => tools.GetFindings(job, "scripts", filter: new string('f', 2_100)),
            "read_file as binary" => tools.ReadFile(job, DrillFixtures.HostileTxt, @as: "binary"),
            "get_reachability capability bogus" => tools.GetReachability(job, capability: "bogus"),
            "get_reachability capability digits" => tools.GetReachability(job, capability: "1"),
            "get_reachability capability list" => tools.GetReachability(job, capability: "network,fileSystem"),
            // Enum.TryParse ORs a comma list: ProcessExecution (2) | Registry (3) is Registry, served as if asked.
            "get_reachability capability or-ed pair" => tools.GetReachability(job, capability: "processExecution,registry"),
            "get_reachability long folder" => tools.GetReachability(job, new string('f', 2_100)),
            _ => throw new ArgumentException(what),
        });

        Assert.Equal("InvalidArgument", Drill.Status(result));
        Assert.False(Drill.S(result).GetProperty("retry").GetBoolean());
    }

    [Fact]
    public void AnUnknownOrMalformedJob_IsAValue_ForEveryTool()
    {
        var unknown = new string('0', 64) + "-deep";
        foreach (var (job, status) in new[]
        {
            (unknown, "NotFound"), ("nope", "InvalidArgument"), (fixture.Sha256.ToUpperInvariant() + "-deep", "InvalidArgument"),
            (fixture.JobId + "\n", "InvalidArgument"), (fixture.JobId + " ", "InvalidArgument"), ("\n" + fixture.JobId, "InvalidArgument"),
        })
        {
            Assert.Equal(status, Drill.Status(Drill.Checked(fixture.Tools.ListFiles(job))));
            Assert.Equal(status, Drill.Status(Drill.Checked(fixture.Tools.ReadFile(job, DrillFixtures.HostileTxt))));
            Assert.Equal(status, Drill.Status(Drill.Checked(fixture.Tools.GetFindings(job, "capabilities"))));
            Assert.Equal(status, Drill.Status(Drill.Checked(fixture.Tools.GetReachability(job))));
        }
    }
    #endregion

    #region Methods: helpers
    private JsonObject Index() => JsonNode.Parse(File.ReadAllText(Path.Combine(fixture.EntryDir, JobProtocol.IndexFile)))!.AsObject();

    // A read that succeeds, with its eof, next and truncated checked against each other.
    private CallToolResult Read(string path, long offset, int length, string @as)
    {
        var result = Drill.Checked(fixture.Tools.ReadFile(fixture.JobId, path, offset, length, @as));
        var s = Drill.S(result);
        Assert.True(!result.IsError, $"{path} at {offset}: {s}");
        var size = s.GetProperty("size").GetInt64();
        var bytes = s.GetProperty("bytes").GetInt32();
        var asked = Math.Clamp(length, 1, McpLimits.MaxReadBytes);
        Assert.Equal(offset, s.GetProperty("offset").GetInt64());
        Assert.InRange(bytes, 0, asked);
        Assert.Equal(offset + bytes >= size, s.GetProperty("eof").GetBoolean());
        Assert.Equal(!s.GetProperty("eof").GetBoolean(), s.TryGetProperty("next", out var next));
        if (next.ValueKind == JsonValueKind.Number)
            Assert.Equal(offset + bytes, next.GetInt64());
        Assert.Equal(bytes < Math.Min(asked, size - offset), s.GetProperty("truncated").GetBoolean());
        Assert.Equal(Drill.Inner(result).Length, Drill.S(result).GetProperty("content").GetProperty("chars").GetInt32());
        return result;
    }

    private static string Next(CallToolResult result)
    {
        var s = Drill.S(Drill.Checked(result));
        Assert.True(s.GetProperty("truncated").GetBoolean(), $"the first page is the only one: {s}");
        return s.GetProperty("next").GetString()!;
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private static readonly string Replacement = char.ConvertFromUtf32(0xFFFD);
    #endregion
}
