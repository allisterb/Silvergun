namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S2 artifact checks: <see cref="JobArtifacts.ReadIndex"/> accepts only the shape the child writes (every list's row
/// count and cut, every finding kind with its pass, a known reachability status); <see cref="HostPaths.ReduceReasons"/>
/// now also rewrites <c>reasons</c>, <c>note</c> and <c>notes</c>, and still never package evidence.
/// </summary>
public sealed class S2ArtifactTests : IDisposable
{
    #region Methods
    [Fact]
    public void SchemaVersion_IsTwo() => Assert.Equal(2, JobArtifacts.SchemaVersion);

    [Fact]
    public void ReadIndex_AcceptsTheChildsShape()
    {
        File.WriteAllText(Path.Combine(dir, JobProtocol.IndexFile), Index().ToJsonString());

        var (index, problem) = JobArtifacts.ReadIndex(dir);

        Assert.Null(problem);
        Assert.Equal(3, index!["files"]!["rows"]!.GetValue<int>());
    }

    public static TheoryData<string> BadIndexes() =>
    [
        "not JSON", "an array", "no files", "files without truncated", "negative rows", "rows not a number", "a finding kind missing",
        "a kind without its pass", "no reachability", "an unknown reachability status", "over its size cap", "missing",
    ];

    [Theory]
    [MemberData(nameof(BadIndexes))]
    public void ReadIndex_RefusesAnyOtherShape(string what)
    {
        var index = Index();
        string? text = what switch
        {
            "not JSON" => "{\"files\":",
            "an array" => "[]",
            "no files" => Without(index, i => i.Remove("files")),
            "files without truncated" => Without(index, i => i["files"]!.AsObject().Remove("truncated")),
            "negative rows" => Without(index, i => i["files"]!["rows"] = -1),
            "rows not a number" => Without(index, i => i["files"]!["rows"] = "3"),
            "a finding kind missing" => Without(index, i => i["findings"]!.AsObject().Remove("hidden-content")),
            "a kind without its pass" => Without(index, i => i["findings"]!["yara"]!.AsObject().Remove("pass")),
            "no reachability" => Without(index, i => i.Remove("reachability")),
            "an unknown reachability status" => Without(index, i => i["reachability"]!["status"] = "maybe"),
            "over its size cap" => Without(index, i => i["pad"] = new string(' ', (int)JobArtifacts.MaxIndexBytes)),
            "missing" => null,
            _ => throw new ArgumentException(what),
        };
        if (text is not null)
            File.WriteAllText(Path.Combine(dir, JobProtocol.IndexFile), text);

        var (read, problem) = JobArtifacts.ReadIndex(dir);

        Assert.Null(read);
        Assert.False(string.IsNullOrWhiteSpace(problem), what);
    }

    [Fact]
    public void ReduceReasons_RewritesReasonsNoteAndNotes_ButNeverEvidence()
    {
        var row = new JsonObject
        {
            ["path"] = U("/tmp/x.dll"),
            ["note"] = U("could not read /tmp/x.dll"),
            ["notes"] = new JsonArray(U("in /tmp/y"), U("fine")),
            ["reasons"] = new JsonArray(U("/root/z is missing")),
            ["classes"] = new JsonArray(new JsonObject { ["reasons"] = new JsonArray(U("/tmp/deep")), ["hops"] = new JsonArray(U("/tmp/hop")) }),
        };

        var reduced = HostPaths.ReduceReasons(row, Unix)!.AsObject();

        Assert.Equal("/tmp/x.dll", Drill.U(reduced, "path"));
        Assert.Equal("could not read <temp>/x.dll", Drill.U(reduced, "note"));
        Assert.Equal("in <temp>/y", reduced["notes"]![0]!["untrusted"]!.GetValue<string>());
        Assert.Equal("fine", reduced["notes"]![1]!["untrusted"]!.GetValue<string>());
        Assert.Equal("<home>/z is missing", reduced["reasons"]![0]!["untrusted"]!.GetValue<string>());
        Assert.Equal("<temp>/deep", reduced["classes"]![0]!["reasons"]![0]!["untrusted"]!.GetValue<string>());
        Assert.Equal("/tmp/hop", reduced["classes"]![0]!["hops"]![0]!["untrusted"]!.GetValue<string>());
    }

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Methods: helpers
    private static JsonObject Index()
    {
        static JsonObject List(int rows) => new() { ["rows"] = rows, ["truncated"] = false };
        var findings = new JsonObject();
        foreach (var kind in Enum.GetValues<FindingKind>())
        {
            var list = List(0);
            list["pass"] = new JsonObject { ["status"] = "completed" };
            findings[PackageFindings.Name(kind)] = list;
        }
        var reachability = List(0);
        reachability["status"] = "notRun";
        return new JsonObject { ["files"] = List(3), ["findings"] = findings, ["reachability"] = reachability };
    }

    private static string Without(JsonObject index, Action<JsonObject> change)
    {
        change(index);
        return index.ToJsonString();
    }

    private static JsonObject U(string text) => new() { ["untrusted"] = text };
    #endregion

    #region Fields
    private static readonly IReadOnlyList<(string Path, string Label)> Unix = [("/tmp", "<temp>"), ("/root", "<home>")];

    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "index-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}
