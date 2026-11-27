namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using ModelContextProtocol.Protocol;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S2 tools over copies of <see cref="DrillFixture"/>'s entries that a test changes, served by a fresh manager as
/// another server process would (from disk): a tampered inventory row is refused and its entry discarded; duplicate rows,
/// unreadable rows, links and vanished files are refused without discarding; a cursor continues in another server process.
/// </summary>
[Collection(DrillCollection.Name)]
public sealed class DrillEntryChangeTests(DrillFixture fixture)
{
    #region Methods
    public static TheoryData<string> OutsideFiles() =>
    [
        "../job.json", "job.json", "files/../job.json", "files/package.nupkg/../../job.json", "files", "files-evil/x.txt", "files-bundles/../index.json",
        "files/package.nupkg/../../../../outside.txt", "C:/Windows/win.ini", "//server/share/x", "files/package.nupkg/content/a" + (char)0 + ".txt",
    ];

    [Theory]
    [MemberData(nameof(OutsideFiles))]
    public void ReadFile_ARowWhoseFileIsOutsideFiles_IsNotPermitted_AndTheEntryIsDiscarded(string file)
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        Rewrite(entry, r => Drill.U(r, "path") == DrillFixtures.HostileTxt ? [With(r, "file", file)] : [r]);
        var tools = new DrillTools(InProcess.Manager(dirs));

        var result = Drill.Checked(tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt));

        Assert.True(Drill.Status(result) == "NotPermitted", $"{file}: {Drill.S(result)}");
        Assert.Null(Drill.Bulk(result));
        Assert.Contains("discarded", Drill.S(result).GetProperty("message").GetString());
        Assert.False(Directory.Exists(entry), $"{file}: the corrupt entry was not discarded");
        Assert.Equal("NotFound", Drill.Status(Drill.Checked(tools.ListFiles(fixture.JobId))));
    }

    [Fact]
    public void ReadFile_TwoRowsWithOnePath_IsNotPermitted_AndTheEntryIsKept()
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        Rewrite(entry, r => Drill.U(r, "path") == DrillFixtures.HostileTxt ? [r, (JsonObject)r.DeepClone()] : [r]);
        var tools = new DrillTools(InProcess.Manager(dirs));

        Assert.Equal("NotPermitted", Drill.Status(Drill.Checked(tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt))));
        Assert.True(Directory.Exists(entry));
        Assert.Equal("Succeeded", Drill.Status(Drill.Checked(tools.ReadFile(fixture.JobId, "content/crlf.txt"))));
    }

    [Theory]
    [InlineData("readable false")]
    [InlineData("file null")]
    [InlineData("file empty")]
    public void ReadFile_ARowThatIsNotReadable_IsNotPermitted_AndTheEntryIsKept(string what)
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        Rewrite(entry, r => Drill.U(r, "path") != DrillFixtures.HostileTxt ? [r] : what switch
        {
            "readable false" => [With(r, "readable", false)],
            "file null" => [With(r, "file", null)],
            _ => [With(r, "file", "")],
        });
        var tools = new DrillTools(InProcess.Manager(dirs));

        var result = Drill.Checked(tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt));

        Assert.Equal("NotPermitted", Drill.Status(result));
        Assert.True(Directory.Exists(entry));
    }

    [Fact]
    public void ReadFile_AFileThatIsGone_IsNotFound_InAdr0034sWords_AndTheEntryIsKept()
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        File.Delete(Path.Combine(entry, "files", "package.nupkg", "content", "hostile.txt"));
        var tools = new DrillTools(InProcess.Manager(dirs));

        var result = Drill.Checked(tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt));

        Assert.Equal("NotFound", Drill.Status(result));
        Assert.Contains("no longer exists", Drill.S(result).GetProperty("message").GetString());
        Assert.True(Directory.Exists(entry));
    }

    [JunctionFact]
    public void ReadFile_AJunctionAboveTheFile_IsNotPermitted()
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        var content = Path.Combine(entry, "files", "package.nupkg", "content");
        var moved = Path.Combine(dirs.Base, "moved-content");
        Directory.Move(content, moved);
        Assert.True(JunctionFactAttribute.TryCreate(content, moved), "mklink /J failed after the probe succeeded");
        var tools = new DrillTools(InProcess.Manager(dirs));

        try
        {
            var result = Drill.Checked(tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt));
            Assert.Equal("NotPermitted", Drill.Status(result));
            Assert.Null(Drill.Bulk(result));
            Assert.True(Directory.Exists(entry));
        }
        finally
        {
            Directory.Delete(content);   // the junction, not its target
        }
    }

    [DirectorySymlinkFact]
    public void ReadFile_ASymlinkedDirectoryOrFile_IsNotPermitted()
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        var content = Path.Combine(entry, "files", "package.nupkg", "content");
        var moved = Path.Combine(dirs.Base, "moved-content");
        Directory.Move(content, moved);
        Directory.CreateSymbolicLink(content, moved);
        var build = Path.Combine(entry, "files", "package.nupkg", "build", "net8.0", "drill00.targets");
        File.Delete(build);
        File.CreateSymbolicLink(build, Path.Combine(entry, JobProtocol.JobFile));
        var tools = new DrillTools(InProcess.Manager(dirs));

        try
        {
            Assert.Equal("NotPermitted", Drill.Status(Drill.Checked(tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt))));
            Assert.Equal("NotPermitted", Drill.Status(Drill.Checked(tools.ReadFile(fixture.JobId, "build/net8.0/drill00.targets"))));
            Assert.True(Directory.Exists(entry));
        }
        finally
        {
            Directory.Delete(content);
            File.Delete(build);
        }
    }

    /// <summary>
    /// A row with a duplicate key is corrupt: errors are values (D10), so the tool answers Failed and discards the entry,
    /// whether or not a filter reads the row before it is served.
    /// </summary>
    [Theory]
    [InlineData(JobProtocol.InventoryFile, null)]
    [InlineData(JobProtocol.InventoryFile, "build/")]
    [InlineData("findings-scripts.jsonl", null)]
    public void ARowWithADuplicateKey_IsFailed_NeverAThrow(string file, string? prefix)
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        var path = Path.Combine(entry, file);
        var text = File.ReadAllText(path, Encoding.ASCII);
        // The first row's own first key, given again: a duplicate in every list, whatever its row shape.
        var firstKey = text[1..(text.IndexOf(':') + 1)];
        File.WriteAllText(path, "{" + firstKey + "\"duplicate\"," + text[1..], Encoding.ASCII);
        var tools = new DrillTools(InProcess.Manager(dirs));

        var result = Record.Exception(() => Drill.Checked(file == JobProtocol.InventoryFile ? tools.ListFiles(fixture.JobId, prefix) : tools.GetFindings(fixture.JobId, "scripts")));

        Assert.True(result is null, $"{file} {prefix}: the tool threw {result?.GetType().Name}: {result?.Message}");
        Assert.False(Directory.Exists(entry), "the corrupt entry was not discarded");
    }

    /// <summary>
    /// The page budget's worst case (S2 review round 2): a <c>get_findings</c> page carries its pass twice, here with a
    /// 400-char CJK reason (six chars each as served), beside rows at the row bound. Every page is within the response
    /// budget, and a row of exactly <see cref="RowWriter.MaxRowChars"/> is served under the floored budget, not Corrupt.
    /// </summary>
    [Fact]
    public void GetFindings_TheWorstPage_IsWithinTheBudget_AndARowOfExactlyMaxRowCharsIsServed()
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        var rows = new List<JsonNode> { Exactly(RowWriter.MaxRowChars, 0) };
        for (var i = 1; i < 5; i++)
            rows.Add(Exactly(RowWriter.MaxRowChars - i, i));
        File.WriteAllText(Path.Combine(entry, "findings-scripts.jsonl"), string.Concat(rows.Select(r => r.ToJsonString(JobProtocol.JsonOptions) + "\n")), Encoding.ASCII);
        var indexFile = Path.Combine(entry, JobProtocol.IndexFile);
        var index = JsonNode.Parse(File.ReadAllText(indexFile))!.AsObject();
        var scripts = index["findings"]!["scripts"]!.AsObject();
        scripts["rows"] = rows.Count;
        scripts["pass"]!["reason"] = new JsonObject { ["untrusted"] = DrillFixtures.LongCjk(460) };
        File.WriteAllText(indexFile, index.ToJsonString(JobProtocol.JsonOptions));
        var tools = new DrillTools(InProcess.Manager(dirs));

        // The page's own data, shaped as DrillTools.Serve builds it, leaves the rows less than one row: the budget floors.
        var data = new JsonObject { ["jobId"] = fixture.JobId, ["kind"] = "scripts", ["pass"] = scripts["pass"]!.DeepClone() };
        const int pageFieldsChars = 400;   // DrillTools.PageFieldsChars
        var unfloored = McpLimits.PageBudgetChars - RowFile.Chars(data) - pageFieldsChars;
        Assert.True(unfloored < RowWriter.MaxRowChars, $"the data takes {RowFile.Chars(data)} chars: the budget ({unfloored}) does not reach the floor");

        var (served, pages, last) = Drill.PageAll(c => tools.GetFindings(fixture.JobId, "scripts", cursor: c));

        Drill.SameRows(rows, served, "rows at the bound");
        Assert.Equal(rows.Count, pages);
        Assert.Equal(DrillFixtures.LongCjk(460), last.GetProperty("pass").GetProperty("reason").GetProperty("untrusted").GetString());
        Assert.True(Directory.Exists(entry), "a row at the bound was taken for corruption");
    }

    /// <summary>An index that fails its shape check after the entry was committed: the entry is not served.</summary>
    [Fact]
    public void ACorruptIndex_IsNeverServed()
    {
        using var dirs = new TestDirs();
        var entry = fixture.CopyInto(dirs);
        File.WriteAllText(Path.Combine(entry, JobProtocol.IndexFile), "{\"files\":{\"rows\":1}}");
        var tools = new DrillTools(InProcess.Manager(dirs));

        foreach (var result in new[] { tools.ListFiles(fixture.JobId), tools.GetFindings(fixture.JobId, "capabilities"), tools.GetReachability(fixture.JobId), tools.ReadFile(fixture.JobId, DrillFixtures.HostileTxt) })
        {
            Drill.Checked(result);
            Assert.True(result.IsError);
            Assert.False(Drill.S(result).TryGetProperty("rows", out _));
            Assert.Null(Drill.Bulk(result));
        }
    }

    /// <summary>Cursors live in no server's memory: one manager's cursor continues in another's, over the same cache.</summary>
    [Fact]
    public void ACursor_ContinuesInAnotherManager_OverTheSameCache()
    {
        using var dirs = new TestDirs();
        fixture.CopyInto(dirs);
        var first = new DrillTools(InProcess.Manager(dirs));
        var second = new DrillTools(InProcess.Manager(dirs));

        var page = Drill.S(Drill.Checked(first.GetFindings(fixture.JobId, "capabilities")));
        var rows = page.GetProperty("rows").EnumerateArray().Select(r => JsonNode.Parse(r.GetRawText())!).ToList();
        var cursor = page.GetProperty("next").GetString();
        var rest = Drill.PageAll(c => second.GetFindings(fixture.JobId, "capabilities", cursor: c ?? cursor)).Rows;

        Drill.SameRows(Drill.Lines(fixture.EntryDir, "findings-capabilities.jsonl"), [.. rows, .. rest], "capabilities across managers");
    }

    /// <summary>The same, across two real <c>mcp</c> server processes: the first is gone before the second continues.</summary>
    [Fact]
    public async Task ACursor_ContinuesInASecondServerProcess()
    {
        using var dirs = new TestDirs();
        fixture.CopyInto(dirs);
        var args = new JsonObject { ["jobId"] = fixture.JobId };

        string? cursor;
        var rows = new List<JsonNode>();
        using (var a = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root))
        {
            var page = await a.CallAsync(ToolNames.ListFiles, (JsonObject)args.DeepClone());
            Assert.False(page.IsError, page.S.ToString());
            Assert.True(page.Text.Length + page.S.GetRawText().Length <= McpLimits.ResponseBudgetChars);
            rows.AddRange(page.S.GetProperty("rows").EnumerateArray().Select(r => JsonNode.Parse(r.GetRawText())!));
            cursor = page.Str("next")!;
            await a.Child.CloseStdinAndWaitForExitAsync();
        }

        using var b = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);
        for (var pages = 0; cursor is not null; pages++)
        {
            var call = (JsonObject)args.DeepClone();
            call["cursor"] = cursor;
            var page = await b.CallAsync(ToolNames.ListFiles, call);
            Assert.False(page.IsError, page.S.ToString());
            Assert.Equal(page.S.GetRawText(), page.Text);
            Assert.True(page.Text.Length * 2 <= McpLimits.ResponseBudgetChars);
            rows.AddRange(page.S.GetProperty("rows").EnumerateArray().Select(r => JsonNode.Parse(r.GetRawText())!));
            cursor = page.Str("next");
            Assert.True(pages < 1_000);
        }

        Drill.SameRows(Drill.Lines(fixture.EntryDir, JobProtocol.InventoryFile, dropFile: true), rows, "list_files across server processes");
    }
    #endregion

    #region Methods: helpers
    internal static void Rewrite(string entry, Func<JsonObject, IEnumerable<JsonObject>> change)
    {
        var path = Path.Combine(entry, JobProtocol.InventoryFile);
        var rows = File.ReadAllLines(path, Encoding.ASCII).Where(l => l.Length > 0).Select(l => JsonNode.Parse(l)!.AsObject()).ToList();
        File.WriteAllText(path, string.Concat(rows.SelectMany(change).Select(r => r.ToJsonString(JobProtocol.JsonOptions) + "\n")), Encoding.ASCII);
    }

    internal static JsonObject With(JsonObject row, string key, JsonNode? value)
    {
        row[key] = value;
        return row;
    }

    // A scripts row of exactly `chars` as served: CJK excerpt (six chars each), padded with ASCII to the exact size.
    private static JsonObject Exactly(int chars, int i)
    {
        JsonObject Row(int pad) => new()
        {
            ["path"] = new JsonObject { ["untrusted"] = $"tools/x{i}.ps1" },
            ["ruleId"] = new JsonObject { ["untrusted"] = "SG0010" },
            ["excerpt"] = new JsonObject { ["untrusted"] = DrillFixtures.LongCjk(800) },
            ["pad"] = new JsonObject { ["untrusted"] = new string('x', pad) },
        };
        var row = Row(chars - RowFile.Chars(Row(0)));
        Assert.Equal(chars, RowFile.Chars(row));
        return row;
    }
    #endregion
}

/// <summary>
/// The S2 tools and a re-run, over copies of a small completed entry: a corrupt row file or a tampered row is <c>Failed</c>
/// or <c>NotPermitted</c>, the entry is discarded, and <c>analyze_package</c> re-runs it rather than serve it again; a
/// schema-1 entry is re-run; a cursor from before a re-analysis is refused; an evicted or unfinished job is a status.
/// </summary>
public sealed class DrillRerunTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>
{
    #region Methods
    public static TheoryData<string, string> Corruptions() => new()
    {
        { JobProtocol.InventoryFile, "a garbage line" },
        { JobProtocol.InventoryFile, "no trailing newline" },
        { JobProtocol.InventoryFile, "a line over MaxRowBytes" },
        { "findings-capabilities.jsonl", "a garbage line" },
        { "findings-anomalies.jsonl", "no trailing newline" },
    };

    [Theory]
    [MemberData(nameof(Corruptions))]
    public async Task ACorruptRowFile_IsFailed_TheEntryIsDiscarded_AndAnalyzePackageReRunsIt(string file, string corruption)
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        var path = Path.Combine(entry, file);
        var text = File.ReadAllText(path, Encoding.ASCII);
        File.WriteAllText(path, corruption switch
        {
            "a garbage line" => text + "garbage\n",
            "no trailing newline" => (text.Length > 0 ? text.TrimEnd('\n') : "{\"category\":\"bidiControl\"}"),
            _ => text + "{\"a\":\"" + new string('x', RowFile.MaxRowBytes) + "\"}\n",
        }, Encoding.ASCII);
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        var result = Drill.Checked(file == JobProtocol.InventoryFile ? tools.ListFiles(fixture.JobId)
            : tools.GetFindings(fixture.JobId, file["findings-".Length..^".jsonl".Length]));

        Assert.True(Drill.Status(result) == "Failed", $"{file}, {corruption}: {Drill.S(result)}");
        Assert.Contains("discarded", Drill.S(result).GetProperty("message").GetString());
        Assert.False(Directory.Exists(entry), "the corrupt entry was not discarded");
        await AssertReRun(jobTools, manager, package);
        Assert.Equal("Succeeded", Drill.Status(Drill.Checked(tools.ListFiles(fixture.JobId))));
    }

    [Fact]
    public async Task ATamperedRowPointingOutsideFiles_IsDiscarded_AndAnalyzePackageReRunsIt()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        DrillEntryChangeTests.Rewrite(entry, r => [DrillEntryChangeTests.With(r, "file", "files/../job.json")]);
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        var result = Drill.Checked(tools.ReadFile(fixture.JobId, Dll));

        Assert.Equal("NotPermitted", Drill.Status(result));
        Assert.False(Directory.Exists(entry));
        await AssertReRun(jobTools, manager, package);
        var read = Drill.Checked(tools.ReadFile(fixture.JobId, Dll, length: 2, @as: "hex"));
        Assert.Equal("Succeeded", Drill.Status(read));
        Assert.Equal([(byte)'M', (byte)'Z'], ExtractedFileTests.HexBytes(Drill.Inner(read), 0));
    }

    /// <summary>An S1 entry (artifact schema 1, no row files) is never half-read: the tools do not serve it, and it is re-run.</summary>
    [Fact]
    public async Task ASchema1Entry_IsNotServed_AndIsReRun()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        var jobFile = Path.Combine(entry, JobProtocol.JobFile);
        var record = JsonNode.Parse(File.ReadAllText(jobFile))!.AsObject();
        record["schemaVersion"] = 1;
        File.WriteAllText(jobFile, record.ToJsonString());
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        Assert.Equal("NotFound", Drill.Status(Drill.Checked(tools.ListFiles(fixture.JobId))));
        Assert.Equal("NotFound", Drill.Status(Drill.Checked(tools.GetFindings(fixture.JobId, "capabilities"))));

        await AssertReRun(jobTools, manager, package);
        Assert.Equal(JobArtifacts.SchemaVersion, JsonNode.Parse(File.ReadAllText(jobFile))!["schemaVersion"]!.GetValue<int>());
    }

    /// <summary>
    /// A cursor binds to the result it pages: once the entry is gone it is NotFound (the manager that ran the job holds it in
    /// memory, and still re-reads the disk), and once it is re-analysed an old cursor is refused.
    /// </summary>
    [Fact]
    public async Task ACursorFromBeforeAReAnalysis_IsInvalidArgument_AndAnEvictedJobIsNotFound()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Nupkg(dirs.Root, "mcp.many", [.. Enumerable.Range(0, 400).Select(i => ($"content/f{i:D4}.txt", new[] { (byte)'x' }))]);
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);
        var first = await InProcess.RunToEndAsync(manager, package);
        Assert.True(first.State == JobState.Completed, $"{first.State} {first.Reason}");
        var page = Drill.S(Drill.Checked(tools.ListFiles(first.JobId)));
        var cursor = page.GetProperty("next").GetString()!;
        Assert.Equal("Succeeded", Drill.Status(tools.ListFiles(first.JobId, cursor: cursor)));

        Directory.Delete(first.EntryDir!, recursive: true);
        var evicted = Drill.Checked(tools.ListFiles(first.JobId, cursor: cursor));
        Assert.Equal("NotFound", Drill.Status(evicted));
        Assert.Contains("analyze_package", Drill.S(evicted).GetProperty("message").GetString());

        await Task.Delay(20);   // a later analyzedAt, whatever the clock's resolution
        var again = await InProcess.RunToEndAsync(manager, package);
        Assert.True(again.State == JobState.Completed && again.Record!.AnalyzedAt > first.Record!.AnalyzedAt, $"{again.State} {again.Reason}");
        var stale = Drill.Checked(tools.ListFiles(first.JobId, cursor: cursor));

        Assert.Equal("InvalidArgument", Drill.Status(stale));
        Assert.Contains("analysed again", Drill.S(stale).GetProperty("message").GetString());
        var (rows, _, _) = Drill.PageAll(c => tools.ListFiles(first.JobId, cursor: c));
        Assert.Equal(401, rows.Count);
    }

    /// <summary>
    /// Review round 2: manager A issues a cursor; manager B, over the same cache, discards the entry and re-runs it; A's
    /// cursor through A is then refused, because A reads the entry's record from disk, not from its own memory.
    /// </summary>
    [Fact]
    public async Task ACursor_IsRefusedInItsOwnManager_OnceAnotherManagerReRanTheEntry()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Nupkg(dirs.Root, "mcp.shared", [.. Enumerable.Range(0, 400).Select(i => ($"content/f{i:D4}.txt", new[] { (byte)'x' }))]);
        var a = InProcess.Manager(dirs);
        var aTools = new DrillTools(a);
        var first = await InProcess.RunToEndAsync(a, package);
        Assert.True(first.State == JobState.Completed, $"{first.State} {first.Reason}");
        var cursor = Drill.S(Drill.Checked(aTools.ListFiles(first.JobId))).GetProperty("next").GetString()!;

        var b = InProcess.Manager(dirs);
        Assert.True(JobManager.TryParse(first.JobId, out var sha, out var depth));
        Assert.True(b.Store.Invalidate(sha, depth), "B could not discard the entry");
        await Task.Delay(20);   // a later analyzedAt, whatever the clock's resolution
        var again = await InProcess.RunToEndAsync(b, package);
        Assert.True(again.State == JobState.Completed && !again.Cached && again.Record!.AnalyzedAt > first.Record!.AnalyzedAt, $"{again.State} {again.Reason}");

        var stale = Drill.Checked(aTools.ListFiles(first.JobId, cursor: cursor));

        Assert.Equal("InvalidArgument", Drill.Status(stale));
        Assert.Contains("analysed again", Drill.S(stale).GetProperty("message").GetString());
        Assert.Equal(401, Drill.PageAll(c => aTools.ListFiles(first.JobId, cursor: c)).Rows.Count);
    }

    [Fact]
    public async Task AJobThatHasNotCompleted_IsItsState_AndTheToolsSayToWait()
    {
        using var dirs = new TestDirs();
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);
        var jobId = InProcess.S(await jobTools.AnalyzePackage(Fixtures.Slow(dirs.Root))).GetProperty("jobId").GetString()!;
        try
        {
            foreach (var result in new[] { tools.ListFiles(jobId), tools.ReadFile(jobId, "x"), tools.GetFindings(jobId, "capabilities"), tools.GetReachability(jobId) })
            {
                var s = Drill.S(Drill.Checked(result));
                Assert.Contains(Drill.Status(result), new[] { "Queued", "Running" });
                Assert.True(s.GetProperty("retry").GetBoolean());
                Assert.Contains("wait_for_job", s.GetProperty("message").GetString());
                Assert.False(s.TryGetProperty("rows", out _));
            }
        }
        finally
        {
            await jobTools.CancelJob(jobId);
        }
    }
    #endregion

    #region Methods: helpers
    // analyze_package does not serve the discarded entry from the cache: it runs the job again, which completes.
    private async Task AssertReRun(JobTools jobTools, JobManager manager, string package)
    {
        var again = InProcess.S(await jobTools.AnalyzePackage(package));
        Assert.True(again.GetProperty("ok").GetBoolean(), again.ToString());
        Assert.False(again.TryGetProperty("cached", out _), $"analyze_package served the discarded entry: {again}");
        var done = await InProcess.WaitToEndAsync(manager, fixture.JobId);
        Assert.True(done.State == JobState.Completed, $"{done.State} {done.Reason}");
        Assert.True(done.Record!.AnalyzedAt > fixture.Record.AnalyzedAt, "the old record survived");
    }
    #endregion

    #region Fields
    private const string Dll = "lib/netstandard2.0/Nuclear.SemVer.dll";
    #endregion
}
