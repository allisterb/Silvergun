namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using ModelContextProtocol.Protocol;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S3 tools over copies of a small completed entry (task S3, artifact schema 3): a schema-2 entry is not served and is
/// re-run; an index without the members or strings list, or without their pass, is never served and is re-run; a job that has
/// not completed is answered as the S2 tools answer it.
/// </summary>
public sealed class S3CacheTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>
{
    #region Methods
    [Fact]
    public void TheFixturesEntry_IsSchema3_WithMembersAndStrings()
    {
        using var dirs = new TestDirs();
        fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);

        Assert.Equal(JobArtifacts.SchemaVersion, JsonNode.Parse(File.ReadAllText(Path.Combine(entry, JobProtocol.JobFile)))!["schemaVersion"]!.GetValue<int>());
        Assert.True(File.Exists(Path.Combine(entry, JobProtocol.MembersFile)));
        Assert.True(File.Exists(Path.Combine(entry, JobProtocol.StringsFile)));
        var tools = new DrillTools(InProcess.Manager(dirs));
        var members = Drill.PageAll(c => tools.ListMembers(fixture.JobId, Dll, cursor: c)).Rows;
        Assert.True(members.Count > 10, $"{members.Count} members");
    }

    /// <summary>An S2 entry (artifact schema 2, no members or strings) is never half-read: the S3 tools do not serve it, and it is re-run.</summary>
    [Fact]
    public async Task ASchema2Entry_IsNotServed_AndIsReRun()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        var jobFile = Path.Combine(entry, JobProtocol.JobFile);
        var record = JsonNode.Parse(File.ReadAllText(jobFile))!.AsObject();
        record["schemaVersion"] = 2;
        File.WriteAllText(jobFile, record.ToJsonString());
        File.Delete(Path.Combine(entry, JobProtocol.MembersFile));
        File.Delete(Path.Combine(entry, JobProtocol.StringsFile));
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        foreach (var result in Calls(tools))
            Assert.Equal("NotFound", Drill.Status(Drill.Checked(await result)));

        await AssertReRun(jobTools, manager, package);
        Assert.Equal(3, JsonNode.Parse(File.ReadAllText(jobFile))!["schemaVersion"]!.GetValue<int>());
        Assert.Equal("Succeeded", Drill.Status(Drill.Checked(tools.ListMembers(fixture.JobId, Dll))));
    }

    public static TheoryData<string> IndexDamage() => ["no members", "no strings", "members without its pass", "strings without its pass", "a pass that is not an object", "members without rows"];

    [Theory]
    [MemberData(nameof(IndexDamage))]
    public async Task AnIndexMissingMembersOrStringsOrTheirPass_IsNeverServed_AndIsReRun(string what)
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        var indexFile = Path.Combine(entry, JobProtocol.IndexFile);
        var index = JsonNode.Parse(File.ReadAllText(indexFile))!.AsObject();
        switch (what)
        {
            case "no members": index.Remove("members"); break;
            case "no strings": index.Remove("strings"); break;
            case "members without its pass": index["members"]!.AsObject().Remove("pass"); break;
            case "strings without its pass": index["strings"]!.AsObject().Remove("pass"); break;
            case "a pass that is not an object": index["members"]!["pass"] = "read"; break;
            case "members without rows": index["members"]!.AsObject().Remove("rows"); break;
        }
        File.WriteAllText(indexFile, index.ToJsonString());
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);

        foreach (var call in Calls(tools).Append(Task.FromResult(tools.ListFiles(fixture.JobId))))
        {
            var result = Drill.Checked(await call);
            Assert.True(result.IsError, $"{what}: served {Drill.S(result)}");
            Assert.False(Drill.S(result).TryGetProperty("rows", out _));
            Assert.Null(Drill.Bulk(result));
        }

        await AssertReRun(jobTools, manager, package);
        var rerun = JsonNode.Parse(File.ReadAllText(indexFile))!.AsObject();
        Assert.True(rerun["members"]!["pass"] is JsonObject && rerun["strings"]!["pass"] is JsonObject, rerun.ToJsonString());
        Assert.Equal("Succeeded", Drill.Status(Drill.Checked(tools.SearchStrings(fixture.JobId))));
    }

    [Fact]
    public async Task AJobThatHasNotCompleted_IsItsState_AndTheS3ToolsSayToWait()
    {
        using var dirs = new TestDirs();
        var jobTools = InProcess.Tools(dirs, out var manager);
        var tools = new DrillTools(manager);
        var jobId = InProcess.S(await jobTools.AnalyzePackage(Fixtures.Slow(dirs.Root))).GetProperty("jobId").GetString()!;
        try
        {
            foreach (var call in new[] { Task.FromResult(tools.ListMembers(jobId, Dll)), Task.FromResult(tools.SearchStrings(jobId)), tools.Disassemble(jobId, Dll, "0x06000001") })
            {
                var result = await call;
                var s = Drill.S(Drill.Checked(result));
                Assert.Contains(Drill.Status(result), new[] { "Queued", "Running" });
                Assert.True(s.GetProperty("retry").GetBoolean());
                Assert.Contains("wait_for_job", s.GetProperty("message").GetString());
                Assert.False(s.TryGetProperty("rows", out _));
                Assert.Null(Drill.Bulk(result));
            }
        }
        finally
        {
            await jobTools.CancelJob(jobId);
        }
    }
    #endregion

    #region Methods: helpers
    private IEnumerable<Task<CallToolResult>> Calls(DrillTools tools) =>
    [
        Task.FromResult(tools.ListMembers(fixture.JobId, Dll)),
        Task.FromResult(tools.SearchStrings(fixture.JobId)),
        tools.Disassemble(fixture.JobId, Dll, "0x06000001"),
    ];

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

    #region Fields
    private const string Dll = "lib/netstandard2.0/Nuclear.SemVer.dll";
    #endregion
}
