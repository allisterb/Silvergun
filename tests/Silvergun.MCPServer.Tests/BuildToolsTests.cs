namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// <c>get_build_integration</c> over a real completed job of <see cref="BuildFixtures.Package"/> (task S4, Accept): the
/// index carries the MSBuild list and its pass; every row pages exactly once; the type and file filters keep what they say
/// (file rows always); the fixture's elements are reported exactly; every package string is <c>{"untrusted": ...}</c>
/// (<see cref="Drill.Checked"/> on every page); a bad argument or an unfinished job is refused.
/// </summary>
[Collection(BuildCollection.Name)]
public sealed class BuildToolsTests(BuildFixture fixture)
{
    #region Methods
    [Fact]
    public void TheIndex_HasTheMsBuildList_WithAnIncompletePass_ForTheFileWithADtd()
    {
        var list = Index()["msbuild"]!.AsObject();

        // valuesCut 1: the orphan's Delete of 264 paths, past MsBuildAnalysis.MaxDestinations. anyPropertySet false: no file sets
        // a property it cannot name (no MSBuild or CreateItem task, no Output, no item metadata; the DTD file is never parsed).
        Assert.Equal(fixture.Rows().Count, list["rows"]!.GetValue<int>());
        Assert.False(list["truncated"]!.GetValue<bool>());
        var expected = JsonNode.Parse("""{"status":"incomplete","files":4,"parsed":3,"notParsed":1,"notProject":0,"expansionBudgetSpent":false,"factsCut":0,"valuesCut":1,"anyPropertySet":false}""");
        Assert.True(JsonNode.DeepEquals(expected, list["pass"]), list["pass"]!.ToJsonString());
        Assert.True(File.Exists(Path.Combine(fixture.EntryDir, JobProtocol.MsBuildFile)));
    }

    [Fact]
    public void GetBuildIntegration_PagesEveryRowExactlyOnce_WithThePass()
    {
        var (rows, pages, last) = Drill.PageAll(c => fixture.Tools.GetBuildIntegration(fixture.JobId, cursor: c));

        Drill.SameRows(fixture.Rows(), rows, "get_build_integration");
        Assert.True(pages >= 2, $"{rows.Count} rows in {pages} page(s)");
        Assert.Equal(rows.Count, last.GetProperty("total").GetInt32());
        Assert.True(JsonNode.DeepEquals(Index()["msbuild"]!["pass"], JsonNode.Parse(last.GetProperty("pass").GetRawText())), last.GetProperty("pass").ToString());
        Assert.Equal(4, rows.Count(r => Drill.Str(r["type"]) == "file"));
        Assert.True(rows.Count > 2 * BuildFixtures.InnerTargets, $"{rows.Count} rows");
    }

    [Theory]
    [InlineData("target")]
    [InlineData("exec")]
    [InlineData("write")]
    [InlineData("usingTask")]
    [InlineData("import")]
    [InlineData("property")]
    [InlineData("file")]
    [InlineData(" EXEC ")]
    [InlineData("usingtask")]
    public void GetBuildIntegration_TheTypeFilter_KeepsThatTypeAndEveryFileRow(string type)
    {
        var (rows, _, last) = Drill.PageAll(c => fixture.Tools.GetBuildIntegration(fixture.JobId, type: type, cursor: c));

        var wanted = new[] { "file", "target", "exec", "write", "usingTask", "import", "property" }.Single(t => t.Equals(type.Trim(), StringComparison.OrdinalIgnoreCase));
        var expected = fixture.Rows(r => Drill.Str(r["type"]) is var t && (t == "file" || t == wanted));
        Drill.SameRows(expected, rows, $"type {type}");
        Assert.Contains(rows, r => Drill.Str(r["type"]) == wanted);
        Assert.Equal(4, rows.Count(r => Drill.Str(r["type"]) == "file"));
        Assert.Equal(fixture.Rows().Count, last.GetProperty("total").GetInt32());
    }

    [Theory]
    [InlineData(BuildFixtures.AutoFile, null)]
    [InlineData(BuildFixtures.InnerFile, null)]
    [InlineData(BuildFixtures.InnerFile, "exec")]
    [InlineData(BuildFixtures.DtdFile, null)]
    [InlineData(BuildFixtures.AutoFile, "write")]
    [InlineData("build/nope.targets", null)]
    [InlineData("BUILD/MCP.BUILD.TARGETS", null)]
    public void GetBuildIntegration_TheFileFilter_MatchesTheListFilesPathExactly(string file, string? type)
    {
        var (rows, _, _) = Drill.PageAll(c => fixture.Tools.GetBuildIntegration(fixture.JobId, file, type, c));

        var expected = fixture.Rows(r => Drill.U(r, "file") == file && (type is null || Drill.Str(r["type"]) is "file" || Drill.Str(r["type"]) == type));
        Drill.SameRows(expected, rows, $"file {file} type {type}");
        if (file.StartsWith("build/", StringComparison.Ordinal) && file != "build/nope.targets")
            Assert.Equal("file", Drill.Str(Assert.Single(rows, r => Drill.Str(r["type"]) == "file")["type"]));
        else
            Assert.Empty(rows);
    }

    [Fact]
    public void TheFilePathOfEveryRow_IsAListFilesPath()
    {
        var listed = Drill.PageAll(c => fixture.Tools.ListFiles(fixture.JobId, cursor: c)).Rows.Select(r => Drill.U(r, "path")).ToHashSet(StringComparer.Ordinal);

        Assert.All(fixture.Rows(), r => Assert.Contains(Drill.U(r, "file"), listed));
        Assert.Equal([BuildFixtures.DtdFile, BuildFixtures.InnerFile, BuildFixtures.AutoFile, BuildFixtures.OrphanFile],
            fixture.Rows(r => Drill.Str(r["type"]) == "file").Select(r => Drill.U(r, "file")!).Order(StringComparer.Ordinal));
    }

    // ---- the fixture, reported exactly ----

    [Fact]
    public void TheAutoFile_IsAutoImportedFromBuild_AndTheOthersLoadAsTheirImportsSay()
    {
        var auto = FileRow(BuildFixtures.AutoFile);
        Assert.Equal("parsed", Drill.Str(auto["status"]));
        Assert.Equal("auto", Drill.Str(auto["load"]));
        Assert.Equal("build", Drill.Str(auto["autoImport"]!["folder"]));
        Assert.Null(auto["autoImport"]!["tfm"]);
        Assert.Empty(auto["importedBy"]!.AsArray());
        Assert.Equal(1, auto["counts"]!["targets"]!.GetValue<int>());
        Assert.Equal(1, auto["counts"]!["execs"]!.GetValue<int>());
        Assert.Equal(5, auto["counts"]!["writes"]!.GetValue<int>());
        Assert.Equal(2, auto["counts"]!["usingTasks"]!.GetValue<int>());
        Assert.Equal(1, auto["counts"]!["imports"]!.GetValue<int>());
        Assert.Equal(3, auto["counts"]!["properties"]!.GetValue<int>());

        var inner = FileRow(BuildFixtures.InnerFile);
        Assert.Equal("imported", Drill.Str(inner["load"]));
        Assert.Null(inner["autoImport"]);
        Assert.Equal([BuildFixtures.AutoFile], inner["importedBy"]!.AsArray().Select(f => Drill.Str(f!["untrusted"])));
        Assert.Equal(1, inner["importedByTotal"]!.GetValue<int>());
        Assert.Equal(BuildFixtures.InnerTargets, inner["counts"]!["targets"]!.GetValue<int>());

        Assert.Equal("none", Drill.Str(FileRow(BuildFixtures.OrphanFile)["load"]));

        var dtd = FileRow(BuildFixtures.DtdFile);
        Assert.Equal("notParsed", Drill.Str(dtd["status"]));
        Assert.Contains("DTD", Drill.U(dtd, "reason"));
        Assert.Equal("none", Drill.Str(dtd["load"]));
        Assert.Equal(0, dtd["counts"]!["properties"]!.GetValue<int>());
    }

    [Fact]
    public void TheTargetAfterBuild_HasItsOutputs_AndTheyAreNeverWritten()
    {
        var target = Assert.Single(fixture.Rows(r => Drill.Str(r["type"]) == "target" && Drill.U(r, "file") == BuildFixtures.AutoFile));

        Assert.Equal("RunTool", Drill.U(target, "name"));
        Assert.Equal("Build", Drill.U(target, "afterTargets"));
        Assert.Equal("$(MSBuildProjectFullPath)", Drill.U(target, "inputs"));
        Assert.Equal("$(IntermediateOutputPath)acme.stamp", Drill.U(target, "outputs"));
        Assert.False(target["outputsWritten"]!.GetValue<bool>());
        Assert.False(target.AsObject().ContainsKey("beforeTargets"));
        Assert.True(target["line"]!.GetValue<int>() > 1);
    }

    [Fact]
    public void TheExec_RunsDotnetOnThePackagesDll_AndContinuesOnError()
    {
        var exec = Assert.Single(fixture.Rows(r => Drill.Str(r["type"]) == "exec" && Drill.U(r, "file") == BuildFixtures.AutoFile));

        Assert.Equal("RunTool", Drill.U(exec, "target"));
        Assert.Equal("dotnet \"$(MSBuildThisFileDirectory)../lib/net8.0/Tool.dll\"", Drill.U(exec, "command"));
        Assert.Equal("dotnet", Drill.U(exec, "program"));
        Assert.Equal([BuildFixtures.ToolDll], exec["packageFiles"]!.AsArray().Select(f => Drill.Str(f!["untrusted"])));
        Assert.Equal("true", Drill.U(exec, "continueOnError"));
        Assert.False(exec.AsObject().ContainsKey("ignoreExitCode"));
        Assert.False(exec["unresolved"]!.GetValue<bool>());
        Assert.Empty(exec["agentConfigMentioned"]!.AsArray());
    }

    [Fact]
    public void TheCopiesIntoClaudeSkills_AndTheMcpJsonWrite_AreOutsideTheOutput_AndNameTheirAgentConfig()
    {
        var writes = fixture.Rows(r => Drill.Str(r["type"]) == "write");

        var project = Write(writes, "{project}/../.claude/skills");
        Assert.Equal("Copy", Drill.Str(project["task"]));
        Assert.Equal("DestinationFolder", Drill.Str(project["attribute"]));
        Assert.Equal("$(MSBuildProjectDirectory)/../.claude/skills/", Drill.U(project, "value"));
        var destination = Assert.Single(project["destinations"]!.AsArray())!;
        Assert.Equal("project", Drill.Str(destination["anchor"]));
        Assert.True(destination["outsideOutput"]!.GetValue<bool>());
        Assert.False(destination["unresolved"]!.GetValue<bool>());
        Assert.True(project["outsideOutput"]!.GetValue<bool>());
        Assert.Contains(".claude/", project["agentConfig"]!.AsArray().Select(Drill.Str));
        Assert.Equal([BuildFixtures.SkillFile], project["packageSources"]!.AsArray().Select(f => Drill.Str(f!["untrusted"])));

        var solution = Write(writes, "{solution}/.claude/skills");
        Assert.Equal("$(SkillDir)", Drill.U(solution, "value"));
        Assert.Equal("solution", Drill.Str(solution["destinations"]![0]!["anchor"]));
        Assert.Contains(".claude/", solution["agentConfig"]!.AsArray().Select(Drill.Str));

        var mcp = Write(writes, "{solution}/.mcp.json");
        Assert.Equal("WriteLinesToFile", Drill.Str(mcp["task"]));
        Assert.Equal([".mcp.json"], mcp["agentConfig"]!.AsArray().Select(Drill.Str));
        Assert.True(mcp["outsideOutput"]!.GetValue<bool>());

        var output = Write(writes, "{output}/skills");
        Assert.False(output["outsideOutput"]!.GetValue<bool>());
        Assert.Empty(output["agentConfig"]!.AsArray());
    }

    [Fact]
    public void TheUsingTasks_AnInlineBodyIsUntrustedEscapedText_AndAPackageDllIsNamed()
    {
        var tasks = fixture.Rows(r => Drill.Str(r["type"]) == "usingTask");

        var inline = Assert.Single(tasks, t => Drill.U(t, "taskName") == "AcmeInline");
        Assert.True(inline["inline"]!.GetValue<bool>());
        Assert.Equal("RoslynCodeTaskFactory", Drill.U(inline, "taskFactory"));
        Assert.Equal("Fragment", Drill.U(inline, "codeType"));
        Assert.Equal(1, inline["invoked"]!.GetValue<int>());
        Assert.Equal(BuildFixtures.InlineBody.Length, inline["bodyChars"]!.GetValue<int>());
        var body = Drill.U(inline, "body")!;
        Assert.Contains(Backslash + "u202e", body);
        Assert.Contains(Backslash + "U000E0041", body);
        Hostile.AssertNoneRaw(body, "the inline body");

        var dll = Assert.Single(tasks, t => Drill.U(t, "taskName") == "Acme.T");
        Assert.False(dll["inline"]!.GetValue<bool>());
        Assert.False(dll.AsObject().ContainsKey("body"));
        Assert.Equal([BuildFixtures.TaskDll], dll["packageFiles"]!.AsArray().Select(f => Drill.Str(f!["untrusted"])));
        Assert.Equal(1, dll["invoked"]!.GetValue<int>());
    }

    [Fact]
    public void TheImportAndTheNotableProperties_AreRows()
    {
        var import = Assert.Single(fixture.Rows(r => Drill.Str(r["type"]) == "import"));
        Assert.Equal("$(MSBuildThisFileDirectory)inner.targets", Drill.U(import, "project"));
        Assert.Equal(["{package}/build/inner.targets"], import["resolved"]!.AsArray().Select(f => Drill.Str(f!["untrusted"])));
        Assert.Equal([BuildFixtures.InnerFile], import["packageFiles"]!.AsArray().Select(f => Drill.Str(f!["untrusted"])));

        var properties = fixture.Rows(r => Drill.Str(r["type"]) == "property");
        Assert.Equal(["RestoreAdditionalProjectSources", "RestoreSources", "DisableFastUpToDateCheck"], properties.Select(p => Drill.U(p, "name")));
        Assert.Equal("https://feed.example/v3/index.json", Drill.U(properties[0], "value"));
        Assert.Equal("true", Drill.U(properties[2], "value"));
    }

    [Fact]
    public void EveryStoredRow_IsAsciiAndWithinTheRowBound()
    {
        foreach (var line in File.ReadAllLines(Path.Combine(fixture.EntryDir, JobProtocol.MsBuildFile)))
        {
            Assert.True(line.Length <= RowWriter.MaxRowChars, $"a row of {line.Length} chars");
            Assert.True(line.All(c => c < 0x80), "a row holds non-ASCII");
        }
    }

    // ---- S4 review round 1: row order, totals and the new row fields (W2, W9) ----

    [Fact]
    public void TheIndex_HasTotalsOverEveryFile_AndOverTheLoadedOnes()
    {
        // All: the auto file's three agent-config writes (two .claude Copies, .mcp.json) and its $(TEMP) Delete, the orphan's
        // AGENTS.md write; the auto file's Exec of Tool.dll; the inline tasks of the auto file and the orphan. The orphan is not loaded.
        // Unknown destinations (S4 review round 2, S1): only the orphan's Delete of 264 paths, cut past the destination cap,
        // so its outsideOutput is null; every auto-file write resolves ($(TEMP), project, $(SkillDir), $(OutputPath), solution).
        var expected = JsonNode.Parse("""
            {"agentConfigWrites":4,"outsideOutputWrites":5,"unknownDestinationWrites":1,"packageFileExecs":1,"inlineTasks":2,
             "loaded":{"agentConfigWrites":3,"outsideOutputWrites":4,"unknownDestinationWrites":0,"packageFileExecs":1,"inlineTasks":1}}
            """);

        var totals = Index()["msbuild"]!["totals"];

        Assert.True(JsonNode.DeepEquals(expected, totals), totals?.ToJsonString() ?? "no totals");
    }

    /// <summary>The tool's description and the guide promise the pass's totals to the agent; the index alone is not served.</summary>
    [Fact]
    public void GetBuildIntegration_ServesTheTotals()
    {
        var page = JsonNode.Parse(Drill.S(Drill.Checked(fixture.Tools.GetBuildIntegration(fixture.JobId))).GetRawText())!;

        var served = page["pass"]?["totals"] ?? page["totals"];

        Assert.True(served is not null, $"get_build_integration serves no totals: pass {page["pass"]?.ToJsonString()}");
        Assert.True(JsonNode.DeepEquals(Index()["msbuild"]!["totals"], served), served!.ToJsonString());
    }

    [Fact]
    public void TheFiles_AreAutoThenImportedThenNone_EachWithItsRowsTogether()
    {
        var rows = fixture.Rows();

        var files = rows.Where(r => Drill.Str(r["type"]) == "file").Select(r => Drill.U(r, "file")!).ToList();
        Assert.Equal([BuildFixtures.AutoFile, BuildFixtures.InnerFile], files.Take(2));
        Assert.Equal([BuildFixtures.DtdFile, BuildFixtures.OrphanFile], files.Skip(2).Order(StringComparer.Ordinal));
        Assert.Equal(["auto", "imported", "none", "none"], files.Select(f => Drill.Str(FileRow(f)["load"])));
        // Each file's rows follow its file row, and no other file's row comes between them.
        Assert.Equal("file", Drill.Str(rows[0]["type"]));
        for (var i = 1; i < rows.Count; i++)
            if (Drill.Str(rows[i]["type"]) != "file")
                Assert.True(Drill.U(rows[i], "file") == Drill.U(rows[i - 1], "file"), $"row {i} ({Drill.Str(rows[i]["type"])}) of {Drill.U(rows[i], "file")} follows {Drill.U(rows[i - 1], "file")}");
    }

    [Fact]
    public void TheAutoFilesRows_RunAndWriteFirst_AgentConfigWritesBeforeOtherOutsideWrites()
    {
        var rows = fixture.Rows(r => Drill.U(r, "file") == BuildFixtures.AutoFile);

        Assert.Equal(["file", "exec", "write", "write", "write", "write", "write", "usingTask", "usingTask", "import", "target", "property", "property", "property"],
            rows.Select(r => Drill.Str(r["type"])));
        // In the target: the $(TEMP) Delete, the Exec, the three Copies (project, $(SkillDir), output) and the .mcp.json write.
        Assert.Equal(["{project}/../.claude/skills", "{solution}/.claude/skills", "{solution}/.mcp.json", "{temp}/acme.tmp", "{output}/skills"],
            rows.Where(r => Drill.Str(r["type"]) == "write").Select(w => Drill.U(w["destinations"]![0], "path")));
    }

    [Fact]
    public void TheRows_CarryTheirListTotals()
    {
        var auto = fixture.Rows(r => Drill.U(r, "file") == BuildFixtures.AutoFile);
        var writes = auto.Where(r => Drill.Str(r["type"]) == "write").ToList();

        var copy = Write(writes, "{project}/../.claude/skills");
        Assert.Equal(1, copy["destinationsTotal"]!.GetValue<int>());
        Assert.False(copy.AsObject().ContainsKey("destinationsCut"));
        Assert.Equal(1, copy["packageSourcesTotal"]!.GetValue<int>());
        Assert.Equal(0, Write(writes, "{solution}/.mcp.json")["packageSourcesTotal"]!.GetValue<int>());
        Assert.Equal(1, Assert.Single(auto, r => Drill.Str(r["type"]) == "exec")["packageFilesTotal"]!.GetValue<int>());
        Assert.Equal(1, Assert.Single(auto, r => Drill.Str(r["type"]) == "import")["resolvedTotal"]!.GetValue<int>());
    }

    [Fact]
    public void AWritePastTheDestinationCap_SaysSo_AndIsNeitherInsideNorOutside()
    {
        var delete = Assert.Single(fixture.Rows(r => Drill.Str(r["type"]) == "write" && Drill.U(r, "file") == BuildFixtures.OrphanFile && Drill.Str(r["task"]) == "Delete"));

        Assert.True(delete["destinationsCut"]!.GetValue<bool>());
        Assert.Equal(256, delete["destinationsTotal"]!.GetValue<int>());
        Assert.Equal(4, delete["destinations"]!.AsArray().Count);
        Assert.All(delete["destinations"]!.AsArray(), d => Assert.False(d!["outsideOutput"]!.GetValue<bool>()));
        Assert.Null(delete["outsideOutput"]);
        Assert.True(delete.AsObject().ContainsKey("outsideOutput"));
    }

    [Fact]
    public void AnInlineTasksAgentConfigMention_PastTheServedBody_IsInItsRow()
    {
        var task = Assert.Single(fixture.Rows(r => Drill.Str(r["type"]) == "usingTask" && Drill.U(r, "taskName") == "OrphanInline"));

        Assert.True(task["inline"]!.GetValue<bool>());
        Assert.Equal(BuildFixtures.OrphanBody.Length, task["bodyChars"]!.GetValue<int>());
        Assert.DoesNotContain(".claude", Drill.U(task, "body"));
        Assert.Equal([".claude/"], task["agentConfigMentioned"]!.AsArray().Select(Drill.Str));
    }

    // ---- refusals ----

    [Theory]
    [InlineData("bogus")]
    [InlineData("files")]
    [InlineData("exec,write")]
    public void AnUnknownType_IsInvalidArgument(string type)
    {
        var result = Drill.Checked(fixture.Tools.GetBuildIntegration(fixture.JobId, type: type));

        Assert.Equal("InvalidArgument", Drill.Status(result));
        Assert.False(Drill.S(result).GetProperty("retry").GetBoolean());
        Assert.False(Drill.S(result).TryGetProperty("rows", out _));
    }

    [Fact]
    public void AnOverlongFileOrCursor_IsInvalidArgument()
    {
        Assert.Equal("InvalidArgument", Drill.Status(Drill.Checked(fixture.Tools.GetBuildIntegration(fixture.JobId, file: new string('f', 2_100)))));
        Assert.Equal("InvalidArgument", Drill.Status(Drill.Checked(fixture.Tools.GetBuildIntegration(fixture.JobId, cursor: new string('c', 2_100)))));
    }

    [Fact]
    public void ACursorFromAnotherFilterOrTool_IsInvalidArgument()
    {
        var all = Next(fixture.Tools.GetBuildIntegration(fixture.JobId));
        var execs = Next(fixture.Tools.GetBuildIntegration(fixture.JobId, type: "exec"));

        foreach (var (what, result) in new[]
        {
            ("unfiltered cursor with a type", fixture.Tools.GetBuildIntegration(fixture.JobId, type: "exec", cursor: all)),
            ("exec cursor for target", fixture.Tools.GetBuildIntegration(fixture.JobId, type: "target", cursor: execs)),
            ("unfiltered cursor with a file", fixture.Tools.GetBuildIntegration(fixture.JobId, BuildFixtures.InnerFile, cursor: all)),
            ("build cursor in list_files", fixture.Tools.ListFiles(fixture.JobId, cursor: all)),
        })
            Assert.True(Drill.Status(Drill.Checked(result)) == "InvalidArgument", $"{what}: {Drill.S(result)}");
        Assert.Equal("Succeeded", Drill.Status(fixture.Tools.GetBuildIntegration(fixture.JobId, type: "EXEC", cursor: execs)));
    }

    [Fact]
    public void AnUnknownOrMalformedJob_IsAValue()
    {
        Assert.Equal("NotFound", Drill.Status(Drill.Checked(fixture.Tools.GetBuildIntegration(new string('0', 64) + "-standard"))));
        Assert.Equal("InvalidArgument", Drill.Status(Drill.Checked(fixture.Tools.GetBuildIntegration("../job"))));
    }
    #endregion

    #region Methods: helpers
    private JsonObject Index() => JsonNode.Parse(File.ReadAllText(Path.Combine(fixture.EntryDir, JobProtocol.IndexFile)))!.AsObject();

    private JsonNode FileRow(string file) => Assert.Single(fixture.Rows(r => Drill.Str(r["type"]) == "file" && Drill.U(r, "file") == file));

    private static JsonNode Write(IEnumerable<JsonNode> writes, string destination) =>
        Assert.Single(writes, w => w["destinations"]!.AsArray().Any(d => Drill.U(d, "path") == destination));

    private static string Next(ModelContextProtocol.Protocol.CallToolResult result)
    {
        var s = Drill.S(Drill.Checked(result));
        Assert.True(s.GetProperty("truncated").GetBoolean(), $"the first page is the only one: {s}");
        return s.GetProperty("next").GetString()!;
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";
    #endregion
}

/// <summary>
/// The S4 cache rules over copies of a small completed entry (artifact schema 4): a schema-3 entry, or an index without the
/// MSBuild list or its pass, is never served and is re-run; an unfinished job is its state; a package with no MSBuild file
/// has an empty, complete pass.
/// </summary>
public sealed class BuildCacheTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>
{
    #region Methods
    [Fact]
    public void APackageWithNoMsBuildFile_HasNoRows_AndACompletePass()
    {
        using var dirs = new TestDirs();
        fixture.CopyInto(dirs);
        var tools = new DrillTools(InProcess.Manager(dirs));

        var (rows, pages, last) = Drill.PageAll(c => tools.GetBuildIntegration(fixture.JobId, cursor: c));

        Assert.Empty(rows);
        Assert.Equal(1, pages);
        Assert.Equal(0, last.GetProperty("total").GetInt32());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"completed","files":0,"parsed":0,"notParsed":0,"notProject":0,"expansionBudgetSpent":false,"factsCut":0,"valuesCut":0,"anyPropertySet":false}"""),
            JsonNode.Parse(last.GetProperty("pass").GetRawText())), last.GetProperty("pass").ToString());
    }

    [Fact]
    public async Task ASchema3Entry_IsNotServed_AndIsReRun()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        var jobFile = Path.Combine(entry, JobProtocol.JobFile);
        var record = JsonNode.Parse(File.ReadAllText(jobFile))!.AsObject();
        record["schemaVersion"] = 3;
        File.WriteAllText(jobFile, record.ToJsonString());
        File.Delete(Path.Combine(entry, JobProtocol.MsBuildFile));
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        Assert.Equal("NotFound", Drill.Status(Drill.Checked(tools.GetBuildIntegration(fixture.JobId))));

        await AssertReRun(jobTools, manager, package);
        Assert.Equal(4, JsonNode.Parse(File.ReadAllText(jobFile))!["schemaVersion"]!.GetValue<int>());
        Assert.Equal("Succeeded", Drill.Status(Drill.Checked(tools.GetBuildIntegration(fixture.JobId))));
    }

    [Theory]
    [InlineData("no msbuild")]
    [InlineData("msbuild without its pass")]
    [InlineData("msbuild without rows")]
    public async Task AnIndexMissingTheMsBuildListOrItsPass_IsNeverServed_AndIsReRun(string what)
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var indexFile = Path.Combine(fixture.EntryIn(dirs), JobProtocol.IndexFile);
        var index = JsonNode.Parse(File.ReadAllText(indexFile))!.AsObject();
        switch (what)
        {
            case "no msbuild": index.Remove("msbuild"); break;
            case "msbuild without its pass": index["msbuild"]!.AsObject().Remove("pass"); break;
            case "msbuild without rows": index["msbuild"]!.AsObject().Remove("rows"); break;
        }
        File.WriteAllText(indexFile, index.ToJsonString());
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        foreach (var result in new[] { tools.GetBuildIntegration(fixture.JobId), tools.ListFiles(fixture.JobId) })
        {
            Assert.True(Drill.Checked(result).IsError, $"{what}: served {Drill.S(result)}");
            Assert.False(Drill.S(result).TryGetProperty("rows", out _));
        }

        await AssertReRun(jobTools, manager, package);
        Assert.True(JsonNode.Parse(File.ReadAllText(indexFile))!["msbuild"]!["pass"] is JsonObject);
    }

    [Fact]
    public async Task AJobThatHasNotCompleted_IsItsState_AndTheToolSaysToWait()
    {
        using var dirs = new TestDirs();
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);
        var jobId = InProcess.S(await jobTools.AnalyzePackage(Fixtures.Slow(dirs.Root))).GetProperty("jobId").GetString()!;
        try
        {
            var result = Drill.Checked(tools.GetBuildIntegration(jobId));
            var s = Drill.S(result);
            Assert.Contains(Drill.Status(result), new[] { "Queued", "Running" });
            Assert.True(s.GetProperty("retry").GetBoolean());
            Assert.Contains("wait_for_job", s.GetProperty("message").GetString());
            Assert.False(s.TryGetProperty("rows", out _));
        }
        finally
        {
            await jobTools.CancelJob(jobId);
        }
    }
    #endregion

    #region Methods: helpers
    private async Task AssertReRun(JobTools jobTools, JobManager manager, string package)
    {
        var again = InProcess.S(await jobTools.AnalyzePackage(package));
        Assert.True(again.GetProperty("ok").GetBoolean(), again.ToString());
        Assert.False(again.TryGetProperty("cached", out _), $"analyze_package served the unusable entry: {again}");
        var done = await InProcess.WaitToEndAsync(manager, fixture.JobId);
        Assert.True(done.State == JobState.Completed, $"{done.State} {done.Reason}");
        Assert.True(done.Record!.AnalyzedAt > fixture.Record.AnalyzedAt, "the old record survived");
    }
    #endregion
}
