namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The row writers' keep sets (S2 review C1, W1), on synthetic reports so no long name touches the disk: when a finding or
/// reachability row must be cut to fit, its filter key (<c>assembly</c>, <c>path</c>, <c>folder</c>) is the longest value,
/// and still comes out exact, so <c>assembly=</c> and <c>folder=</c> filters keep matching. The drill entry's real report
/// is the base; the long values are put in with <c>with</c>. Also the degraded inventory row (review round 2).
/// </summary>
[Collection(DrillCollection.Name)]
public sealed class S2RowBoundsTests(DrillFixture fixture) : IDisposable
{
    #region Methods
    /// <summary>
    /// Without the keep set, <see cref="RowFile.Fit"/> cuts the longest value first, which here is the filter key: so the
    /// tests below fail if <c>PackageFindings</c> or <c>ReachabilityRows</c> stop passing theirs.
    /// </summary>
    [Fact]
    public void Fit_WithoutTheKeepSet_WouldCutTheFilterKey_InTheseRows()
    {
        foreach (var (key, value, keep) in new[] { ("assembly", Served(0), FindingKeys), ("path", Served(1), FindingKeys), ("folder", Folder(0), FolderKeys) })
        {
            JsonObject Row() => new()
            {
                [key] = U(value),
                ["a"] = U(Cyr(400)),
                ["b"] = U(Cyr(400)),
                ["list"] = new JsonArray(U(Cyr(200)), U(Cyr(200)), U(Cyr(200))),
            };

            var bare = Row();
            Assert.True(RowFile.Fit(bare, RowWriter.MaxRowChars));
            Assert.NotEqual(value, Drill.U(bare, key));

            var kept = Row();
            Assert.True(RowFile.Fit(kept, RowWriter.MaxRowChars, keep));
            Assert.Equal(value, Drill.U(kept, key));
        }
    }

    [Fact]
    public void PackageFindings_KeepsAssemblyAndPathExact_WhenTheyAreTheLongestValues()
    {
        var report = Report();
        var paths = new PackagePaths();
        var assemblies = report.Assemblies.Where(a => a.Report is not null).ToList();
        Assert.True(assemblies.Count >= 2);
        var served = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < assemblies.Count; i++)
        {
            served[assemblies[i].Assembly.FullPath] = Served(i);
            paths.Add(assemblies[i].Assembly.FullPath, assemblies[i].Assembly.RelativePath, Served(i));
        }
        var findings = new ApiCallFinding[] { new(Capability.Network, ApiCallKind.Call, Cyr(400), Cyr(400), Cyr(400)), new(Capability.FileSystem, ApiCallKind.Call, Cyr(400), Cyr(390), Cyr(380)) };
        var scripts = Enumerable.Range(0, 3).Select(i => new ScriptFinding("SG0010", Cyr(400), "Moderate", "High", $"tools/s{i}.ps1", 1, Cyr(1_000), [Cyr(100), Cyr(100)])).ToList();
        var yara = Enumerable.Range(0, 3).Select(i => new YaraFinding(Cyr(120), Cyr(120), Cyr(120), Cyr(120), Cyr(120), [Cyr(120), Cyr(120)], $"content/y{i}.bin")).ToList();
        for (var i = 0; i < 3; i++)
        {
            paths.Add(Path.Combine(dir, $"s{i}"), $"tools/s{i}.ps1", Served(100 + i));
            paths.Add(Path.Combine(dir, $"y{i}"), $"content/y{i}.bin", Served(200 + i));
        }
        foreach (var (n, i) in report.NativeBinaries.Select((n, i) => (n, i)))
            paths.Add(Path.Combine(dir, $"n{i}"), n.RelativePath, Served(300 + i));
        report = report with
        {
            Assemblies = [.. report.Assemblies.Select(a => a.Report is null ? a : a with { Report = a.Report with { Findings = findings } })],
            ScriptFindings = scripts,
            YaraFindings = yara,
        };

        var index = PackageFindings.Write(dir, report, new HashSet<IndicatorCategory>(), paths, []);

        var capabilities = Rows("findings-capabilities.jsonl");
        Assert.Equal(assemblies.Count * findings.Length, capabilities.Count);
        Assert.All(capabilities, r => Assert.Contains(Drill.U(r, "assembly"), served.Values));
        Assert.Contains(capabilities, r => Drill.U(r, "callerType")!.Length < 400);   // the others were cut instead
        foreach (var kind in new[] { "indicators", "hidden-content" })
        {
            var rows = Rows($"findings-{kind}.jsonl");
            Assert.NotEmpty(rows);
            Assert.All(rows, r => Assert.Contains(Drill.U(r, "assembly"), served.Values));
        }
        Assert.Equal([Served(100), Served(101), Served(102)], Rows("findings-scripts.jsonl").Select(r => Drill.U(r, "path")));
        Assert.Equal([Served(200), Served(201), Served(202)], Rows("findings-yara.jsonl").Select(r => Drill.U(r, "path")));
        var native = Rows("findings-native.jsonl");
        Assert.Equal(report.NativeBinaries.Count, native.Count);
        Assert.Equal(Enumerable.Range(0, native.Count).Select(i => Served(300 + i)), native.Select(r => Drill.U(r, "path")));
        foreach (var kind in Enum.GetValues<FindingKind>().Select(PackageFindings.Name))
        {
            Assert.False(index[kind]!.AsObject().ContainsKey("unfitted"), $"{kind}: a row was dropped");
            Assert.All(Rows($"findings-{kind}.jsonl"), r => Assert.True(RowFile.Chars(r) <= RowWriter.MaxRowChars));
        }
    }

    /// <summary>
    /// The worst a YARA row can be: a 512-char CJK path (kept whole) and every bounded field at its bound, with the 8 tags
    /// the list keeps. It must still be listed, not dropped as unfitted.
    /// </summary>
    [Fact]
    public void PackageFindings_TheWorstYaraRow_IsListed_NotDropped()
    {
        var report = Report() with
        {
            YaraFindings = [new YaraFinding(Cyr(200), Cyr(200), Cyr(200), Cyr(200), Cyr(200), [.. Enumerable.Range(0, 12).Select(_ => Cyr(200))], "content/w.bin")],
        };
        var paths = new PackagePaths();
        paths.Add(Path.Combine(dir, "w"), "content/w.bin", Served(9));

        var index = PackageFindings.Write(dir, report, new HashSet<IndicatorCategory>(), paths, []);

        Assert.True(!index["yara"]!.AsObject().ContainsKey("unfitted"), $"the row was dropped: {index["yara"]!.ToJsonString()}");
        Assert.Equal(Served(9), Drill.U(Assert.Single(Rows("findings-yara.jsonl")), "path"));
    }

    /// <summary>As above with ASCII rule metadata at its bounds (rules are rarely non-ASCII): listed, path whole.</summary>
    [Fact]
    public void PackageFindings_AYaraRowWithAsciiMetadataAtItsBounds_IsListed()
    {
        string A(int n) => new('m', n);
        var report = Report() with
        {
            YaraFindings = [new YaraFinding(A(200), A(200), A(200), A(200), A(200), [.. Enumerable.Range(0, 12).Select(_ => A(200))], "content/w.bin")],
        };
        var paths = new PackagePaths();
        paths.Add(Path.Combine(dir, "w"), "content/w.bin", Served(9));

        var index = PackageFindings.Write(dir, report, new HashSet<IndicatorCategory>(), paths, []);

        Assert.False(index["yara"]!.AsObject().ContainsKey("unfitted"));
        var row = Assert.Single(Rows("findings-yara.jsonl"));
        Assert.Equal(Served(9), Drill.U(row, "path"));
        Assert.Equal(12, row["tagsTotal"]!.GetValue<int>());
    }

    [Fact]
    public void ReachabilityRows_KeepFolderExact_OnEveryRowType_WhenItIsTheLongestValue()
    {
        var report = Report();
        var summary = report.Reachability!;
        Assert.True(summary.Folders.Count >= 2);
        var folders = summary.Folders.Select((f, i) => f with
        {
            Folder = Folder(i),
            Classes = [.. f.Classes.Select(c => c with { Reasons = [.. Enumerable.Range(0, 6).Select(_ => Cyr(200))] })],
            Notes = [.. Enumerable.Range(0, 6).Select(_ => Cyr(200))],
            Statements = [.. f.Statements.Select(s => s with { Example = new ReachExample(s.Example?.Evidence ?? default, [.. Enumerable.Range(0, 8).Select(_ => Cyr(200))], 0, null) })],
            Ssa = f.Ssa is null ? null : f.Ssa with
            {
                Sites = [.. f.Ssa.Sites.Take(5).Select(site => site with { Target = new SsaTargetSummary(SsaTargetKind.Type, Cyr(200), [.. Enumerable.Range(0, 8).Select(_ => Cyr(200))], 8, null) })],
            },
        }).ToList();
        report = report with { Reachability = summary with { Folders = folders } };

        var index = ReachabilityRows.Write(dir, report, []);

        var rows = Rows(JobProtocol.ReachabilityFile);
        var expected = folders.Sum(f => 1 + f.Statements.Count + (f.Ssa?.Sites.Count ?? 0));
        Assert.Equal(expected, rows.Count);
        Assert.False(index.ContainsKey("unfitted"), "a row was dropped");
        foreach (var type in new[] { "folder", "statement", "ssaSite" })
            Assert.Contains(rows, r => Drill.Str(r["type"]) == type);
        Assert.All(rows, r => Assert.Contains(Drill.U(r, "folder"), folders.Select(f => f.Folder)));
        Assert.All(rows, r => Assert.True(RowFile.Chars(r) <= RowWriter.MaxRowChars));
        Assert.All(rows.Where(r => Drill.Str(r["type"]) == "folder"), r =>
        {
            Assert.True(r["reasonsCut"]?.GetValue<bool>() == true, $"a folder row that cannot fit was not degraded: {r.ToJsonString()[..200]}");
            Assert.Equal(6, r["notesTotal"]!.GetValue<int>());
            Assert.All(r["classes"]!.AsArray(), c => Assert.False(string.IsNullOrEmpty(Drill.Str(c!["verdict"]))));
        });
    }

    /// <summary>
    /// Review round 2: a file whose raw <c>file</c> column keeps its row from fitting is still listed, with its whole path,
    /// never readable, and says why; read_file refuses it.
    /// </summary>
    [Fact]
    public void PackageInventory_ARowWhoseFileCannotFit_IsListedWhole_ButNotReadable()
    {
        var job = Directory.CreateDirectory(Path.Combine(dir, "job")).FullName;
        var files = Path.Combine(job, JobProtocol.FilesDir);
        var deep = Path.Combine(files, JobProtocol.PackageFile, "content", DrillFixtures.LongCjk(240), DrillFixtures.LongCjk(240), DrillFixtures.LongCjk(240));
        Directory.CreateDirectory(deep);
        var file = Path.Combine(deep, DrillFixtures.LongCjk(200) + ".txt");
        File.WriteAllText(file, "deep");
        File.WriteAllText(Path.Combine(files, JobProtocol.PackageFile, "short.txt"), "short");
        var rel = "content/" + string.Join("/", Enumerable.Repeat(DrillFixtures.LongCjk(240), 3)) + "/" + DrillFixtures.LongCjk(200) + ".txt";
        Assert.True(("files/package.nupkg/" + rel).Length <= 1_024, "the fixture's file column is over the inventory's own name cap");

        using (var writer = new RowWriter(job, JobProtocol.InventoryFile, PackageInventory.MaxRows, PackageInventory.MaxChars))
        {
            PackageInventory.Write(Report() with { Assemblies = [], Scripts = [], ScriptFindings = [], NativeBinaries = [] }, files, Path.Combine(job, JobProtocol.PackageFile), [], writer);
            writer.Commit();
            Assert.False(writer.Index().ContainsKey("unfitted"));
            Assert.Equal(2, writer.Rows);
        }

        var rows = Drill.Lines(job, JobProtocol.InventoryFile);
        var row = Assert.Single(rows, r => Drill.U(r, "path")!.StartsWith("content/", StringComparison.Ordinal));
        Assert.Equal(UntrustedText.EscapeBounded(rel, 512), Drill.U(row, "path"));
        Assert.False(row["readable"]!.GetValue<bool>());
        Assert.Null(row["file"]);
        Assert.Equal("its name is too long to serve", Drill.U(row, "note"));
        Assert.True(RowFile.Chars(row.AsObject()) <= RowWriter.MaxRowChars);
        Assert.True(Assert.Single(rows, r => Drill.U(r, "path") == "short.txt")["readable"]!.GetValue<bool>());

        var (_, full, status, _, corrupt) = ExtractedFile.Resolve(job, Drill.U(row, "path")!);
        Assert.Equal(ToolStatus.NotPermitted, status);
        Assert.Null(full);
        Assert.Equal(RowProblem.None, corrupt);
        Assert.Equal(ToolStatus.Succeeded, ExtractedFile.Resolve(job, "short.txt").Status);
    }

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Methods: helpers
    // The drill entry's real report (deep: it has a reachability summary with two folders).
    private PackageCapabilityReport Report() => PackageCapabilityReport.FromJson(File.ReadAllText(Path.Combine(fixture.EntryDir, JobProtocol.ReportFile)))!;

    private List<JsonNode> Rows(string file) => Drill.Lines(dir, file);

    // A served path of 512 CJK chars (the inventory's bound), distinct per index: longer than every other value of its row.
    private static string Served(int i) => DrillFixtures.LongCjk(509) + i.ToString("D3");

    // A folder at the reachability bound (256), longer than the 200-char names around it.
    private static string Folder(int i) => DrillFixtures.LongCjk(253) + i.ToString("D3");

    private static string Cyr(int n) => DrillFixtures.LongNonAscii(n);

    private static JsonObject U(string text) => new() { ["untrusted"] = text };
    #endregion

    #region Fields
    private static readonly IReadOnlySet<string> FindingKeys = new HashSet<string> { "assembly", "path" };

    private static readonly IReadOnlySet<string> FolderKeys = new HashSet<string> { "folder" };

    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "rowbounds-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}
