namespace Silvergun.MCPServer.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Win32.SafeHandles;

using Silvergun.MCPServer.Jobs;

/// <summary>One completed small-package entry, made once by a real job, that each cache test copies into its own cache.</summary>
public sealed class CompletedEntryFixture : IAsyncLifetime
{
    #region Properties
    public string CacheDir => dirs.Cache;

    public string Package { get; private set; } = "";

    public string Sha256 { get; private set; } = "";

    public string JobId => JobManager.JobId(Sha256, JobDepth.Standard);

    public JobRecord Record { get; private set; } = null!;
    #endregion

    #region Methods
    public async Task InitializeAsync()
    {
        Package = Fixtures.Small(dirs.Root);
        Sha256 = Fixtures.Sha256Of(Package);
        var view = await InProcess.RunToEndAsync(InProcess.Manager(dirs), Package);
        Assert.True(view.State == JobState.Completed, $"the fixture job did not complete: {view.State} {view.Reason}");
        Record = view.Record!;
    }

    /// <summary>A fresh cache holding a copy of the completed entry, and the package under <paramref name="dirs"/>' root.</summary>
    internal string CopyInto(TestDirs dirs)
    {
        Fixtures.CopyDirectory(Path.Combine(CacheDir, Sha256), Path.Combine(dirs.Cache, Sha256));
        var package = Path.Combine(dirs.Root, Path.GetFileName(Package));
        File.Copy(Package, package);
        return package;
    }

    internal string EntryIn(TestDirs dirs) => Path.Combine(dirs.Cache, Sha256, JobStore.EntryName(JobDepth.Standard));

    public Task DisposeAsync()
    {
        dirs.Dispose();
        return Task.CompletedTask;
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion
}

/// <summary>
/// The cache (task S1, D4, D4a), in-process: a <see cref="JobManager"/> or <see cref="JobTools"/> in the test, its jobs in
/// the real CLI apphost. A completed entry is served; a corrupt, foreign or orphaned one is never served and is re-run; a
/// directory whose name only resembles ours is never deleted.
/// </summary>
public sealed class JobCacheTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>
{
    #region Methods
    [Fact]
    public void TheFixtureEntry_HasTheS1Layout()
    {
        var entry = Path.Combine(fixture.CacheDir, fixture.Sha256, JobStore.EntryName(JobDepth.Standard));

        foreach (var name in new[] { JobProtocol.PackageFile, JobProtocol.ReportFile, JobProtocol.GateFile, JobProtocol.SummaryFile, JobProtocol.InventoryFile, JobProtocol.JobFile })
            Assert.True(File.Exists(Path.Combine(entry, name)), $"{name} is missing");
        Assert.True(Directory.Exists(Path.Combine(entry, JobProtocol.FilesDir)), "files/ is missing");
        Assert.Matches("^[0-9a-f]{16}-standard$", JobStore.EntryName(JobDepth.Standard));
        Assert.Equal(BuildIdentity.BuildKey, fixture.Record.BuildKey);
        Assert.Equal(JobArtifacts.SchemaVersion, fixture.Record.SchemaVersion);
        Assert.Equal(fixture.Sha256, fixture.Record.Sha256);
        Assert.Equal(Fixtures.Sha256Of(Path.Combine(entry, JobProtocol.PackageFile)), fixture.Sha256);   // the job used an exact copy
        Assert.Matches("^[0-9a-f]{64}-standard$", fixture.JobId);
        Assert.Empty(Directory.GetDirectories(Path.Combine(fixture.CacheDir, fixture.Sha256), "*.tmp-*"));
    }

    [Fact]
    public async Task ARepeatSubmit_IsServedFromTheCache_WithinOneSecond()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var manager = InProcess.Manager(dirs);

        var clock = Stopwatch.StartNew();
        var (view, status, problem) = await manager.SubmitAsync(package, JobDepth.Standard, CancellationToken.None);
        clock.Stop();

        Assert.True(view is not null, $"{status} {problem}");
        Assert.Equal(JobState.Completed, view!.State);
        Assert.True(view.Cached);
        Assert.Equal(fixture.JobId, view.JobId);
        Assert.Equal(fixture.Record.AnalyzedAt, view.Record!.AnalyzedAt);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"took {clock.ElapsedMilliseconds} ms");
        Assert.Empty(Directory.GetFiles(Path.Combine(dirs.Cache, "incoming")));   // the input copy was discarded
    }

    public static TheoryData<string> Corruptions() => ["truncated job.json", "foreign schemaVersion", "job.json over 64 KiB", "missing summary.json",
        "job.json for another package", "job.json of another build", "missing report.json"];

    [Theory]
    [MemberData(nameof(Corruptions))]
    public async Task ACorruptEntry_IsNeverServed_AndIsReRun(string corruption)
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        Corrupt(entry, corruption);
        var manager = InProcess.Manager(dirs);

        var (found, findStatus, _) = manager.Find(fixture.JobId);
        Assert.True(found is null && findStatus == ToolStatus.NotFound, $"{corruption}: served before the re-run ({findStatus}, {found?.State})");

        var (submitted, _, problem) = await manager.SubmitAsync(package, JobDepth.Standard, CancellationToken.None);
        Assert.True(submitted is not null, problem);
        Assert.False(submitted!.Cached, $"{corruption}: served from the cache");
        var done = await InProcess.WaitToEndAsync(manager, fixture.JobId);

        Assert.True(done.State == JobState.Completed, $"{corruption}: {done.State} {done.Reason}");
        Assert.False(done.Cached);
        Assert.True(done.Record!.AnalyzedAt > fixture.Record.AnalyzedAt, $"{corruption}: the old record survived");
        var (reread, why) = JobArtifacts.ReadRecord(entry, fixture.Sha256, JobDepth.Standard, BuildIdentity.BuildKey);
        Assert.True(reread is not null, $"{corruption}: the re-run entry does not read back: {why}");
    }

    /// <summary>
    /// W1: an entry whose summary or gate does not parse (same length, all <c>X</c>) is never served: <c>analyze_package</c>
    /// re-runs it, as <c>get_summary</c>'s advice says, and <c>get_summary</c> then succeeds.
    /// </summary>
    [Theory]
    [InlineData(JobProtocol.SummaryFile)]
    [InlineData(JobProtocol.GateFile)]
    public async Task AnUnparseableSummaryOrGate_IsReRunByAnalyzePackage_ThenGetSummarySucceeds(string artifact)
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var file = Path.Combine(fixture.EntryIn(dirs), artifact);
        File.WriteAllBytes(file, Enumerable.Repeat((byte)'X', (int)new FileInfo(file).Length).ToArray());
        var tools = InProcess.Tools(dirs, out var manager);

        var before = tools.GetSummary(fixture.JobId);
        Assert.True(before.IsError, $"{artifact}: a corrupt entry was served: {InProcess.Text(before)}");

        var again = InProcess.S(await tools.AnalyzePackage(package));
        Assert.True(again.GetProperty("ok").GetBoolean(), again.ToString());
        Assert.False(again.TryGetProperty("cached", out _), $"{artifact}: analyze_package served the corrupt entry: {again}");
        var done = await InProcess.WaitToEndAsync(manager, fixture.JobId);
        Assert.True(done.State == JobState.Completed, $"{artifact}: {done.State} {done.Reason}");

        var after = tools.GetSummary(fixture.JobId);
        Assert.False(after.IsError, $"{artifact}: {InProcess.Text(after)}");
        Assert.False(InProcess.S(after).TryGetProperty("cached", out _), "get_summary of a job this process just ran says cached");
    }

    /// <summary>A temporary sibling a killed server left (its lock is free) is deleted on the next touch of the key, never served.</summary>
    [Fact]
    public async Task AnOrphanedTempSibling_IsDeletedOnTheNextTouch_AndNeverServed()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        var orphan = entry + ".tmp-a1b2c3d4e5f6";
        Directory.Move(entry, orphan);   // a whole-looking result that was never committed
        var manager = InProcess.Manager(dirs);

        var (found, findStatus, _) = manager.Find(fixture.JobId);
        Assert.True(found is null && findStatus == ToolStatus.NotFound, $"the orphan was served ({findStatus})");

        var done = await InProcess.RunToEndAsync(manager, package);

        Assert.True(done.State == JobState.Completed, $"{done.State} {done.Reason}");
        Assert.False(done.Cached);
        Assert.False(Directory.Exists(orphan), "the orphaned temp sibling survived the next touch of its key");
        Assert.True(Directory.Exists(entry));
    }

    /// <summary>Deletion is anchored: on the same key's touch, every directory whose name only resembles ours survives.</summary>
    [Fact]
    public async Task DirectoriesThatOnlyResembleOurs_AreNeverDeleted()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var entry = fixture.EntryIn(dirs);
        Directory.Delete(entry, recursive: true);   // so the touch runs the job and cleans the key
        var name = JobStore.EntryName(JobDepth.Standard);
        var keyDir = Path.Combine(dirs.Cache, fixture.Sha256);
        var lookalikes = new[]
        {
            Path.Combine(keyDir, name + ".tmp-ABC"),
            Path.Combine(keyDir, name + ".tmpx-a1b2c3d4e5f6"),
            Path.Combine(keyDir, name + ".tmp-a1b2c3d4e5f"),          // 11
            Path.Combine(keyDir, name + ".tmp-a1b2c3d4e5f6a"),        // 13
            Path.Combine(keyDir, name + ".tmp-a1b2c3d4e5f_"),
            Path.Combine(keyDir, name + ".tmp-a1b2c3d4e5f6.bak"),
            Path.Combine(keyDir, "x" + name + ".tmp-a1b2c3d4e5f6"),
            Path.Combine(keyDir, "0123456789abcdef-standard.tmp-a1b2c3d4e5f6"),   // another build's run: not this key's
            Path.Combine(keyDir, JobStore.EntryName(JobDepth.Deep) + ".tmp-a1b2c3d4e5f6"),   // the other depth's run
            Path.Combine(dirs.Cache, fixture.Sha256[..63]),
            Path.Combine(dirs.Cache, fixture.Sha256[..63], name + ".tmp-a1b2c3d4e5f6"),
        };
        foreach (var dir in lookalikes)
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "marker.txt"), "keep me");
        }

        var done = await InProcess.RunToEndAsync(InProcess.Manager(dirs), package);

        Assert.True(done.State == JobState.Completed, $"{done.State} {done.Reason}");
        Assert.All(lookalikes, d => Assert.True(File.Exists(Path.Combine(d, "marker.txt")), $"deleted: {Path.GetFileName(d)}"));
    }

    [Fact]
    public async Task ADeepEntry_ServesAStandardRequest_ButAStandardOneNeverServesDeep()
    {
        using var dirs = new TestDirs();
        var package = fixture.CopyInto(dirs);
        var manager = InProcess.Manager(dirs);

        var deep = await InProcess.RunToEndAsync(manager, package, JobDepth.Deep);
        Assert.True(deep.State == JobState.Completed, $"deep: {deep.State} {deep.Reason}");
        Assert.False(deep.Cached, "a standard entry served a deep request");
        Assert.Equal(JobManager.JobId(fixture.Sha256, JobDepth.Deep), deep.JobId);

        Directory.Delete(fixture.EntryIn(dirs), recursive: true);
        var (standard, _, problem) = await manager.SubmitAsync(package, JobDepth.Standard, CancellationToken.None);
        Assert.True(standard is not null, problem);
        Assert.True(standard!.Cached && standard.State == JobState.Completed, $"standard after deep: {standard.State}, cached {standard.Cached}");
        Assert.Equal(deep.JobId, standard.JobId);
    }

    [Fact]
    public void TypicalSeconds_IsNullWithoutJobs_ThenTheMedianOfThisCachesJobs()
    {
        using var dirs = new TestDirs();
        Assert.Null(InProcess.Manager(dirs).TypicalSeconds(JobDepth.Standard));

        fixture.CopyInto(dirs);
        var typical = InProcess.Manager(dirs).TypicalSeconds(JobDepth.Standard);

        Assert.Equal(fixture.Record.ElapsedMs / 1000.0, typical);
        Assert.Null(InProcess.Manager(dirs).TypicalSeconds(JobDepth.Deep));
    }

    [Fact]
    public async Task UnknownAndMalformedJobIds_AreValuesNotThrows()
    {
        using var dirs = new TestDirs();
        var manager = InProcess.Manager(dirs);

        Assert.Equal(ToolStatus.InvalidArgument, (await manager.WaitAsync("nope", TimeSpan.FromSeconds(1), null, CancellationToken.None)).Status);
        Assert.Equal(ToolStatus.InvalidArgument, manager.Find(fixture.Sha256[..16] + "-standard").Status);
        Assert.Equal(ToolStatus.InvalidArgument, manager.Find(fixture.Sha256.ToUpperInvariant() + "-standard").Status);
        Assert.Equal(ToolStatus.NotFound, manager.Find(fixture.JobId).Status);
        Assert.Equal(ToolStatus.NotFound, (await manager.CancelAsync(fixture.JobId)).Status);
    }
    #endregion

    #region Methods: helpers
    private void Corrupt(string entry, string corruption)
    {
        var jobFile = Path.Combine(entry, JobProtocol.JobFile);
        var json = File.ReadAllText(jobFile);
        switch (corruption)
        {
            case "truncated job.json":
                File.WriteAllText(jobFile, json[..(json.Length / 2)]);
                break;
            case "foreign schemaVersion":
                File.WriteAllText(jobFile, With(json, "schemaVersion", JobArtifacts.SchemaVersion + 1));
                break;
            case "job.json over 64 KiB":
                File.WriteAllText(jobFile, json + new string(' ', (int)JobArtifacts.MaxRecordBytes));   // still valid JSON, but over the cap
                break;
            case "missing summary.json":
                File.Delete(Path.Combine(entry, JobProtocol.SummaryFile));
                break;
            case "missing report.json":
                File.Delete(Path.Combine(entry, JobProtocol.ReportFile));
                break;
            case "job.json for another package":
                File.WriteAllText(jobFile, With(json, "sha256", new string('0', 64)));
                break;
            case "job.json of another build":
                File.WriteAllText(jobFile, With(json, "buildKey", "0123456789abcdef"));
                break;
            default:
                throw new ArgumentException(corruption);
        }
    }

    private static string With(string json, string key, JsonNode value)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        Assert.True(node.ContainsKey(key), $"job.json has no '{key}': {json}");
        node[key] = value;
        return node.ToJsonString();
    }
    #endregion
}

/// <summary>
/// D10's zeros and the input checks, in-process through <see cref="JobTools"/>: an assembly that does not load is
/// <c>loaded: false</c> with a reason beside a <c>null</c> count; every refused path is an <c>isError</c> value with its
/// status, names no host path, and leaves the cache untouched.
/// </summary>
public sealed class JobToolInputTests
{
    #region Methods
    [Fact]
    public async Task AnAssemblyThatFailsToLoad_IsLoadedFalse_WithAReasonBesideANullCount()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Unloadable(dirs.Root);
        var tools = InProcess.Tools(dirs, out var manager);

        var analyzed = InProcess.S(await tools.AnalyzePackage(package));
        var jobId = analyzed.GetProperty("jobId").GetString()!;
        var done = await InProcess.WaitToEndAsync(manager, jobId);
        Assert.True(done.State == JobState.Completed, $"{done.State} {done.Reason}");
        var result = tools.GetSummary(jobId);

        Assert.False(result.IsError, InProcess.Text(result));
        var summary = InProcess.S(result).GetProperty("summary");
        var assembly = Assert.Single(summary.GetProperty("assemblies").EnumerateArray());
        Assert.False(assembly.GetProperty("loaded").GetBoolean());
        Assert.Equal(JsonValueKind.Null, assembly.GetProperty("capabilityCount").ValueKind);
        var reason = assembly.GetProperty("reason");
        Assert.Equal(JsonValueKind.Object, reason.ValueKind);
        Assert.False(string.IsNullOrWhiteSpace(reason.GetProperty("untrusted").GetString()));
        Assert.Equal("lib/netstandard2.0/Broken.dll", assembly.GetProperty("path").GetProperty("untrusted").GetString());
        var passes = summary.GetProperty("passes").GetProperty("assemblies");
        Assert.Equal(1, passes.GetProperty("files").GetInt32());
        Assert.Equal(0, passes.GetProperty("analyzed").GetInt32());
        Assert.Equal(1, passes.GetProperty("notAnalyzed").GetInt32());
    }

    [Fact]
    public async Task ASmallPackage_AnalyzeWaitSummary_HappyPath()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Small(dirs.Root);
        var tools = InProcess.Tools(dirs, out _);

        var analyzed = InProcess.S(await tools.AnalyzePackage(package));
        Assert.True(analyzed.GetProperty("ok").GetBoolean(), analyzed.ToString());
        var jobId = analyzed.GetProperty("jobId").GetString()!;
        Assert.Equal(JobManager.JobId(Fixtures.Sha256Of(package), JobDepth.Standard), jobId);

        JsonElement wait;
        var clock = Stopwatch.StartNew();
        do
            wait = InProcess.S(await tools.WaitForJob(jobId, 10));
        while (wait.GetProperty("retry").GetBoolean() && clock.Elapsed < InProcess.JobTimeout);
        Assert.Equal("Succeeded", wait.GetProperty("status").GetString());
        Assert.Equal("completed", wait.GetProperty("state").GetString());
        Assert.True(wait.GetProperty("elapsedMs").GetInt64() >= 0);
        Assert.True(wait.GetProperty("typicalSeconds").GetDouble() > 0);
        Assert.False(wait.TryGetProperty("cached", out _));   // news once: absent, not false
        Assert.False(wait.TryGetProperty("runningInAnotherServer", out _));

        var result = tools.GetSummary(jobId);
        Assert.False(result.IsError, InProcess.Text(result));
        var summary = InProcess.S(result).GetProperty("summary");
        Assert.Equal("mcp.small", summary.GetProperty("package").GetProperty("id").GetProperty("untrusted").GetString());
        Assert.Equal("standard", summary.GetProperty("depth").GetString());
        Assert.Equal(JsonValueKind.Object, summary.GetProperty("gate").ValueKind);
        Assert.True(InProcess.Text(result).Length <= McpLimits.ResponseBudgetChars);
    }

    [Fact]
    public async Task CancelJob_OnARunningJob_IsCancelled_AndAnalyzeAgainReRuns()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Slow(dirs.Root);
        var tools = InProcess.Tools(dirs, out var manager);
        var jobId = InProcess.S(await tools.AnalyzePackage(package)).GetProperty("jobId").GetString()!;
        await Task.Delay(1_500);

        var cancelled = await tools.CancelJob(jobId);

        // cancel_job did what was asked: ok, Succeeded, and the job's own state says it was cancelled.
        Assert.False(cancelled.IsError, InProcess.Text(cancelled));
        Assert.True(InProcess.S(cancelled).GetProperty("ok").GetBoolean());
        Assert.Equal("Succeeded", InProcess.S(cancelled).GetProperty("status").GetString());
        Assert.Equal("cancelled", InProcess.S(cancelled).GetProperty("state").GetString());
        Assert.Equal("Cancelled", InProcess.S(await tools.WaitForJob(jobId, 1)).GetProperty("status").GetString());
        var keyDir = Path.Combine(dirs.Cache, Fixtures.Sha256Of(package));
        Assert.True(!Directory.Exists(keyDir) || Directory.GetDirectories(keyDir).Length == 0, "a cancelled job left a directory in the cache");

        var again = InProcess.S(await tools.AnalyzePackage(package));   // failures are not cached
        Assert.True(again.GetProperty("ok").GetBoolean(), again.ToString());
        Assert.NotEqual("cancelled", again.GetProperty("state").GetString());
        await tools.CancelJob(jobId);
    }

    public static TheoryData<string, string> Refusals() => new()
    {
        { "outside every root", "OutsideRoots" },
        { "a sibling whose name extends the root's", "OutsideRoots" },
        { "dot-dot out of the root", "OutsideRoots" },
        { "a directory", "InvalidArgument" },
        { "a 0-byte file", "InvalidArgument" },
        { "a 21-byte file", "InvalidArgument" },
        { "no such file", "NotFound" },
        { "an empty path", "InvalidArgument" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task AnalyzePackage_RefusesABadPath(string what, string status)
    {
        using var dirs = new TestDirs();
        var path = what switch
        {
            "outside every root" => Fixtures.Small(dirs.NewDir("outside")),
            "a sibling whose name extends the root's" => Fixtures.Small(dirs.NewDir(Path.GetFileName(dirs.Root) + "-evil")),
            "dot-dot out of the root" => Path.Combine(dirs.Root, "..", "up", Path.GetFileName(Fixtures.Small(dirs.NewDir("up")))),
            "a directory" => Directory.CreateDirectory(Path.Combine(dirs.Root, "pkg.nupkg")).FullName,
            "a 0-byte file" => Write(dirs.Root, "empty.nupkg", 0),
            "a 21-byte file" => Write(dirs.Root, "tiny.nupkg", 21),
            "no such file" => Path.Combine(dirs.Root, "missing.nupkg"),
            "an empty path" => "",
            _ => throw new ArgumentException(what),
        };

        await AssertRefused(dirs, path, status, what);
    }

    [Fact]
    public async Task AnalyzePackage_RefusesABadDepth()
    {
        using var dirs = new TestDirs();
        var tools = InProcess.Tools(dirs, out _);

        var result = await tools.AnalyzePackage(Fixtures.Small(dirs.Root), "deeper");

        Assert.True(result.IsError);
        Assert.Equal("InvalidArgument", InProcess.S(result).GetProperty("status").GetString());
    }

    [JunctionFact]
    public async Task AnalyzePackage_RefusesAJunctionEscape()
    {
        using var dirs = new TestDirs();
        var target = dirs.NewDir("junction-target");
        var package = Fixtures.Small(target);
        var link = Path.Combine(dirs.Root, "link");
        Assert.True(JunctionFactAttribute.TryCreate(link, target), "mklink /J failed after the probe succeeded");

        await AssertRefused(dirs, Path.Combine(link, Path.GetFileName(package)), "NotPermitted", "a junction out of the root");
    }

    [DirectorySymlinkFact]
    public async Task AnalyzePackage_RefusesADirectorySymlinkEscape()
    {
        using var dirs = new TestDirs();
        var target = dirs.NewDir("symlink-target");
        var package = Fixtures.Small(target);
        var link = Path.Combine(dirs.Root, "link");
        Directory.CreateSymbolicLink(link, target);

        await AssertRefused(dirs, Path.Combine(link, Path.GetFileName(package)), "NotPermitted", "a directory symlink out of the root");
    }

    [SparseFileFact]
    public async Task AnalyzePackage_RefusesAFileOverTheLimit()
    {
        using var dirs = new TestDirs();
        var path = Path.Combine(dirs.Root, "huge.nupkg");
        Assert.True(SparseFileFactAttribute.TryCreate(path, PackageInput.MaxPackageBytes + 1), "the sparse file could not be created after the probe succeeded");

        await AssertRefused(dirs, path, "InvalidArgument", "a file over the limit");
    }
    #endregion

    #region Methods: helpers
    private static async Task AssertRefused(TestDirs dirs, string path, string status, string what)
    {
        var tools = InProcess.Tools(dirs, out _);

        var result = await tools.AnalyzePackage(path);

        Assert.True(result.IsError, $"{what}: not an error: {InProcess.Text(result)}");
        var s = InProcess.S(result);
        Assert.Equal(status, s.GetProperty("status").GetString());
        Assert.False(s.GetProperty("ok").GetBoolean());
        Assert.False(s.GetProperty("retry").GetBoolean());
        Assert.False(s.TryGetProperty("jobId", out _));
        Assert.DoesNotContain(JsonEncodedText.Encode(dirs.Base).ToString(), InProcess.Text(result), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFileSystemEntries(dirs.Cache));   // refused before anything touched the cache
    }

    private static string Write(string dir, string name, int bytes)
    {
        var path = Path.Combine(dir, name);
        File.WriteAllBytes(path, new byte[bytes]);
        return path;
    }
    #endregion
}

/// <summary>A fact that needs a directory junction (Windows, <c>mklink /J</c>); a skip when one cannot be made here.</summary>
public sealed class JunctionFactAttribute : FactAttribute
{
    #region Constructors
    public JunctionFactAttribute()
    {
        if (!probe.Value)
            Skip = "A directory junction could not be created here (Windows only, mklink /J).";
    }
    #endregion

    #region Methods
    public static bool TryCreate(string link, string target)
    {
        if (!OperatingSystem.IsWindows())
            return false;
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "/c", "mklink", "/J", link, target })
                psi.ArgumentList.Add(arg);
            using var p = Process.Start(psi)!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            return p.WaitForExit(30_000) && p.ExitCode == 0 && (File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool Probe()
    {
        var dir = Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "junction-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "target"));
            return TryCreate(Path.Combine(dir, "link"), Path.Combine(dir, "target"));
        }
        finally
        {
            // The junction first (a non-recursive delete removes the link, not its target), then the rest.
            try { if (Directory.Exists(Path.Combine(dir, "link"))) Directory.Delete(Path.Combine(dir, "link")); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
    #endregion

    #region Fields
    private static readonly Lazy<bool> probe = new(Probe);
    #endregion
}

/// <summary>A fact that needs a directory symbolic link (Linux always; Windows only with the privilege or developer mode).</summary>
public sealed class DirectorySymlinkFactAttribute : FactAttribute
{
    public DirectorySymlinkFactAttribute()
    {
        if (!probe.Value)
            Skip = "A directory symbolic link could not be created here (on Windows it needs the privilege or developer mode).";
    }

    private static bool Probe()
    {
        var dir = Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "symlink-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "target"));
            Directory.CreateSymbolicLink(Path.Combine(dir, "link"), Path.Combine(dir, "target"));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return false;
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private static readonly Lazy<bool> probe = new(Probe);
}

/// <summary>A fact that needs a sparse file (NTFS via FSCTL_SET_SPARSE; Linux file systems make one from a bare length).</summary>
public sealed class SparseFileFactAttribute : FactAttribute
{
    #region Constructors
    public SparseFileFactAttribute()
    {
        if (!probe.Value)
            Skip = "A sparse file could not be created here.";
    }
    #endregion

    #region Methods
    /// <summary>A file of <paramref name="length"/> bytes that takes (almost) no disk space.</summary>
    public static bool TryCreate(string path, long length)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            if (OperatingSystem.IsWindows() && !DeviceIoControl(stream.SafeFileHandle, FsctlSetSparse, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
                return false;
            stream.SetLength(length);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool Probe()
    {
        var dir = Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "sparse-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            return TryCreate(Path.Combine(dir, "probe.bin"), 1024L * 1024 * 1024);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr inBuffer, int inSize, IntPtr outBuffer, int outSize, out int returned, IntPtr overlapped);
    #endregion

    #region Fields
    private const uint FsctlSetSparse = 0x000900C4;

    private static readonly Lazy<bool> probe = new(Probe);
    #endregion
}
