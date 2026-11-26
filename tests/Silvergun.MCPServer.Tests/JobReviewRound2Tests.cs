namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// S1 review round 2, W1: <see cref="HostPaths.Reduce"/> replaces a known prefix only where it is a whole path, and
/// <see cref="HostPaths.ReduceReasons"/> rewrites only free text (<c>reason</c>, <c>caveats</c>), never package evidence.
/// </summary>
public sealed class HostPathsWholePathTests
{
    #region Methods
    [Theory]
    [InlineData("lib/net8.0/tmp.dll")]
    [InlineData("tools/tmpl/x.targets")]
    [InlineData("content/rootkit/payload.ps1")]
    [InlineData("xtmp")]
    [InlineData("/tmpfoo")]
    [InlineData("a/tmp/b")]
    [InlineData("_/root")]
    public void Reduce_LeavesAPrefixThatIsNotAWholePath(string text) => Assert.Equal(text, HostPaths.Reduce(text, Unix));

    [Theory]
    [InlineData("'/tmp/x.dll'", "'<temp>/x.dll'")]
    [InlineData("in /tmp", "in <temp>")]
    [InlineData("/tmp/a", "<temp>/a")]
    [InlineData("\"/root\"", "\"<home>\"")]
    [InlineData("/tmp", "<temp>")]
    [InlineData("see /root/.cache and /tmp/x", "see <home>/.cache and <temp>/x")]
    public void Reduce_ReplacesAWholePath(string text, string expected) => Assert.Equal(expected, HostPaths.Reduce(text, Unix));

    [Fact]
    public void Reduce_WindowsStyle_WholePathsOnly_InBothSpellings()
    {
        var file = WinTemp + Backslash + "x.dll";

        Assert.Equal("<temp>" + Backslash + "x.dll", HostPaths.Reduce(file, Windows));
        Assert.Equal("open '<temp>" + Backslash + "x.dll'", HostPaths.Reduce("open '" + file + "'", Windows));
        Assert.Equal("<temp>" + Backslash + Backslash + "x.dll", HostPaths.Reduce(Doubled(file), Windows));
        Assert.Equal("<temp>", HostPaths.Reduce(WinTemp, Windows));
        foreach (var untouched in new[] { WinTemp + "Files" + Backslash + "x", "x" + WinTemp, "D:" + Backslash + WinTemp, Doubled(WinTemp) + "Files" })
            Assert.Equal(untouched, HostPaths.Reduce(untouched, Windows));
    }

    // Round 3: punctuation after a prefix, the forward-slash spelling and the \\?\ spelling. The profile is C:\Users\X.
    public static TheoryData<string, string> Round3Reduced() => new()
    {
        { "access to " + Profile + ": denied", "access to <home>: denied" },
        { "(under " + Profile + ")", "(under <home>)" },
        { "[" + Profile + "]", "[<home>]" },
        { "{" + Profile + "}", "{<home>}" },
        { "in " + Profile + ".", "in <home>." },
        { Profile + ", then " + Profile + ";", "<home>, then <home>;" },
        { Profile.Replace(Backslash, "/") + "/a.dll", "<home>/a.dll" },
        { Backslash + Backslash + "?" + Backslash + Profile + Backslash + "a.dll", "<home>" + Backslash + "a.dll" },
    };

    [Theory]
    [MemberData(nameof(Round3Reduced))]
    public void Reduce_Round3_PunctuationAndOtherSpellings_AreWholePaths(string text, string expected) =>
        Assert.Equal(expected, HostPaths.Reduce(text, Home));

    public static TheoryData<string> Round3Untouched() =>
    [
        Profile + "avier" + Backslash + "a.dll",
        Profile.Replace(Backslash, "/") + "avier/a.dll",
        Backslash + Backslash + "?" + Backslash + Profile + "avier",
        "x" + Profile.Replace(Backslash, "/"),
        Profile + "-old",
    ];

    [Theory]
    [MemberData(nameof(Round3Untouched))]
    public void Reduce_Round3_StillOnlyWholePaths(string text) => Assert.Equal(text, HostPaths.Reduce(text, Home));

    [WindowsOnlyFact]
    public void Reduce_WindowsStyle_IsCaseInsensitiveOnWindows_InBothSpellings()
    {
        var upper = WinTemp.ToUpperInvariant() + Backslash + "x.dll";

        Assert.Equal("<temp>" + Backslash + "x.dll", HostPaths.Reduce(upper, Windows));
        Assert.Equal("<temp>" + Backslash + Backslash + "x.dll", HostPaths.Reduce(Doubled(upper), Windows));
    }

    [Fact]
    public void ReduceReasons_RewritesOnlyReasonsAndCaveats_AndLeavesEvidenceByteIdentical()
    {
        var summary = new JsonObject
        {
            ["package"] = new JsonObject { ["id"] = U("/tmp/evil") },
            ["gate"] = new JsonObject { ["caveats"] = new JsonArray(U("/tmp/z is missing"), U("fine")) },
            ["assemblies"] = new JsonArray(new JsonObject
            {
                ["path"] = U("/tmp/x.dll"),
                ["reason"] = U("could not load /tmp/x.dll"),
                ["capabilityCount"] = null,
            }),
            ["highlights"] = new JsonObject
            {
                ["yara"] = new JsonArray(new JsonObject { ["path"] = U("/tmp/y.bin"), ["rule"] = U("/root") }),
                ["scripts"] = new JsonArray(new JsonObject { ["path"] = U("/root/s.ps1") }),
            },
        };
        var evidence = new Func<JsonObject, string?>[]
        {
            s => s["package"]!["id"]!.ToJsonString(),
            s => s["assemblies"]![0]!["path"]!.ToJsonString(),
            s => s["highlights"]!["yara"]![0]!.ToJsonString(),
            s => s["highlights"]!["scripts"]![0]!.ToJsonString(),
        };
        var before = evidence.Select(e => e(summary)).ToArray();

        var reduced = HostPaths.ReduceReasons(summary, Unix)!.AsObject();

        Assert.Equal(before, evidence.Select(e => e(reduced)).ToArray());
        Assert.Equal("could not load <temp>/x.dll", reduced["assemblies"]![0]!["reason"]!["untrusted"]!.GetValue<string>());
        Assert.Equal("<temp>/z is missing", reduced["gate"]!["caveats"]![0]!["untrusted"]!.GetValue<string>());
        Assert.Equal("fine", reduced["gate"]!["caveats"]![1]!["untrusted"]!.GetValue<string>());
    }
    #endregion

    #region Methods: helpers
    private static JsonObject U(string text) => new() { ["untrusted"] = text };

    private static string Doubled(string path) => path.Replace(Backslash, Backslash + Backslash);
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private static readonly string WinTemp = string.Join(Backslash, "C:", "Users", "Someone", "AppData", "Local", "Temp");

    private static readonly IReadOnlyList<(string Path, string Label)> Unix = [("/tmp", "<temp>"), ("/root", "<home>")];

    private static readonly IReadOnlyList<(string Path, string Label)> Windows = [(WinTemp, "<temp>")];

    private static readonly string Profile = string.Join(Backslash, "C:", "Users", "X");

    private static readonly IReadOnlyList<(string Path, string Label)> Home = [(Profile, "<home>")];
    #endregion
}

/// <summary>S1 review round 2, W2: whether OSV ran is part of an entry's name, so a networked and an offline result never serve each other.</summary>
public sealed class JobNetworkNamingTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>
{
    #region Methods
    [Fact]
    public void EntryName_HasANetSuffixOnlyForNetworkedEntries()
    {
        Assert.Equal(BuildIdentity.BuildKey + "-standard", JobStore.EntryName(JobDepth.Standard));
        Assert.Equal(BuildIdentity.BuildKey + "-deep-net", JobStore.EntryName(JobDepth.Deep, network: true));
        Assert.EndsWith("-standard-net", new JobStore(Path.GetTempPath(), 1, network: true).EntryDir(new string('a', 64), JobDepth.Standard));
    }

    /// <summary>No networked job is run: the offline entry is a real one, the networked one a copy under its own name.</summary>
    [Fact]
    public void AnOfflineEntry_IsNotServedToANetworkedServer_NorTheReverse_AndTheyCoexist()
    {
        using var dirs = new TestDirs();
        fixture.CopyInto(dirs);
        var offline = InProcess.Manager(dirs);
        var networked = new JobManager(McpServerSettings.Create([dirs.Root], true, 1, dirs.Cache, 5, dirs.Logs, false).Value, InProcess.CliLaunch);
        var offlineEntry = fixture.EntryIn(dirs);
        var netEntry = Path.Combine(dirs.Cache, fixture.Sha256, JobStore.EntryName(JobDepth.Standard, network: true));

        Assert.Equal(ToolStatus.Succeeded, offline.Find(fixture.JobId).Status);
        Assert.Equal(ToolStatus.NotFound, networked.Find(fixture.JobId).Status);   // the offline result is not served with --network

        Fixtures.CopyDirectory(offlineEntry, netEntry);
        var jobFile = Path.Combine(netEntry, JobProtocol.JobFile);
        var record = JsonNode.Parse(File.ReadAllText(jobFile))!.AsObject();
        record["network"] = true;   // as a networked run would have recorded it
        File.WriteAllText(jobFile, record.ToJsonString());
        Assert.Equal(ToolStatus.Succeeded, networked.Find(fixture.JobId).Status);
        Assert.Equal(netEntry, networked.Find(fixture.JobId).View!.EntryDir);
        Assert.Equal(offlineEntry, offline.Find(fixture.JobId).View!.EntryDir);

        Directory.Delete(offlineEntry, recursive: true);
        Assert.Equal(ToolStatus.NotFound, offline.Find(fixture.JobId).Status);   // the networked result is not served without --network
        Assert.True(Directory.Exists(netEntry));
    }

    [Fact]
    public void Evict_RecognisesNetworkedEntries()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 0);
        var net = Path.Combine(dirs.Cache, new string('b', 64), JobStore.EntryName(JobDepth.Standard, network: true));
        Directory.CreateDirectory(net);
        File.WriteAllBytes(Path.Combine(net, "filler.bin"), new byte[100]);
        var near = Path.Combine(dirs.Cache, new string('b', 64), JobStore.EntryName(JobDepth.Standard) + "-netx");
        Directory.CreateDirectory(near);
        File.WriteAllBytes(Path.Combine(near, "filler.bin"), new byte[100]);

        Assert.Equal(1, store.Evict(null));

        Assert.False(Directory.Exists(net), "a -net entry was not considered for eviction");
        Assert.True(Directory.Exists(near), "a name that only resembles a -net entry was deleted");
    }
    #endregion
}

/// <summary>
/// S1 review round 2, W3 and the stage name: a run takes a slot and only then the key's lock, so a queued run holds no lock
/// another server could be waiting on, and a run that has started reports <c>starting</c>, never <c>queued</c>.
/// </summary>
public sealed class JobSlotThenLockTests
{
    #region Methods
    [Fact]
    public async Task AQueuedRun_HoldsNoLock_AndARunningRunNeverSaysQueued()
    {
        using var dirs = new TestDirs();
        var slow = Fixtures.Slow(dirs.Root);
        var queued = Fixtures.Small(dirs.Root, "mcp.queued");
        var manager = InProcess.Manager(dirs);   // --max-jobs 1
        var (running, _, p1) = await manager.SubmitAsync(slow, JobDepth.Standard, CancellationToken.None);
        Assert.True(running is not null, p1);
        var stages = new List<string?>();
        try
        {
            for (var i = 0; i < 20 && manager.Find(running!.JobId).View is { State: not JobState.Running }; i++)
                await Task.Delay(100);
            var (waiting, _, p2) = await manager.SubmitAsync(queued, JobDepth.Standard, CancellationToken.None);
            Assert.True(waiting is not null, p2);
            await Task.Delay(500);
            Assert.Equal(JobState.Queued, manager.Find(waiting!.JobId).View!.State);

            var queuedSha = Fixtures.Sha256Of(queued);
            Directory.CreateDirectory(Path.Combine(dirs.Cache, queuedSha));
            var lockPath = Path.Combine(dirs.Cache, queuedSha, JobStore.EntryName(JobDepth.Standard)) + ".lock";
            using (var taken = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))   // throws if the queued run held it
                Assert.True(taken.CanWrite);

            for (var i = 0; i < 10; i++)
            {
                var (view, _, _) = await manager.WaitAsync(running!.JobId, TimeSpan.FromMilliseconds(300), null, CancellationToken.None);
                if (view!.State == JobState.Running)
                    stages.Add(view.Stage);
            }
            Assert.NotEmpty(stages);
            Assert.DoesNotContain("queued", stages);
            Assert.All(stages, s => Assert.False(string.IsNullOrEmpty(s), "a running job with no stage"));
        }
        finally
        {
            await manager.CancelAsync(running!.JobId);
            await manager.CancelAsync(JobManager.JobId(Fixtures.Sha256Of(queued), JobDepth.Standard));
        }
    }

    /// <summary>The W3 restatement of the round-1 W4 test: a lock held elsewhere on A does not stop B under <c>--max-jobs 1</c>.</summary>
    [Fact]
    public async Task ALockHeldElsewhere_DoesNotHoldTheOnlySlot()
    {
        using var dirs = new TestDirs();
        var a = Fixtures.Small(dirs.Root, "mcp.a");
        var b = Fixtures.Small(dirs.Root, "mcp.b");
        var shaA = Fixtures.Sha256Of(a);
        Directory.CreateDirectory(Path.Combine(dirs.Cache, shaA));
        var manager = InProcess.Manager(dirs);

        using (new FileStream(Path.Combine(dirs.Cache, shaA, JobStore.EntryName(JobDepth.Standard)) + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            var (waiting, _, problem) = await manager.SubmitAsync(a, JobDepth.Standard, CancellationToken.None);
            Assert.True(waiting is not null, problem);
            await Task.Delay(1_500);

            var done = await InProcess.RunToEndAsync(manager, b);

            Assert.True(done.State == JobState.Completed, $"{done.State} {done.Reason}");
            Assert.True(manager.Find(waiting!.JobId).View is { Elsewhere: true }, $"A is not waiting on the lock's holder: {manager.Find(waiting.JobId).View}");
            await manager.CancelAsync(waiting.JobId);
        }
    }
    #endregion
}

/// <summary>Round 2: report-form inventory paths are cut at an escape boundary; a commit retries a leftover entry's delete.</summary>
public sealed class JobRound2StoreTests
{
    #region Methods
    /// <summary>
    /// A not-extracted entry (the same name declared twice, different bytes) of 60 Tag-block characters: escaped, the 512-char
    /// cut would fall one char into a 10-char escape; the row keeps whole escapes only, then the cut suffix.
    /// </summary>
    [Fact]
    public async Task Inventory_AReportFormPath_IsCutAtAnEscapeBoundary()
    {
        using var dirs = new TestDirs();
        var name = "lib/net8.0/" + string.Concat(Enumerable.Range(0, 60).Select(i => char.ConvertFromUtf32(0xE0041 + i % 26))) + ".dll";
        var dll = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Nuclear.SemVer.dll"));
        var other = new byte[256];
        new Random(3).NextBytes(other);
        (other[0], other[1]) = ((byte)'M', (byte)'Z');
        var package = Fixtures.Nupkg(dirs.Root, "mcp.cut", (name, dll), (name, other));

        var view = await InProcess.RunToEndAsync(InProcess.Manager(dirs), package);

        Assert.True(view.State == JobState.Completed, $"{view.State} {view.Reason}");
        var rows = JsonNode.Parse(File.ReadAllText(Path.Combine(view.EntryDir!, JobProtocol.InventoryFile)))!["rows"]!.AsArray();
        var row = Assert.Single(rows, r => r!["kind"]!.GetValue<string>() == "notExtracted")!;
        Assert.Equal("report", row["pathForm"]!.GetValue<string>());
        var path = row["path"]!.GetValue<string>();
        var cut = path.IndexOf((char)0x2026 + "[+", StringComparison.Ordinal);
        Assert.True(cut > 0, $"the path was not cut: {path}");
        Assert.True(cut <= 512, $"kept {cut} chars");
        Assert.Matches(@"^lib/net8\.0/(\\U000[Ee]00[0-9A-Fa-f]{2})+$", path[..cut]);
    }

    [Fact]
    public async Task CommitAsync_ReplacesALeftoverEntry()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, 1L << 30);
        var sha = new string('c', 64);
        var entry = store.EntryDir(sha, JobDepth.Standard);
        Directory.CreateDirectory(entry);
        File.WriteAllText(Path.Combine(entry, "old.txt"), "old");
        var temp = store.CreateTemp(sha, JobDepth.Standard);
        File.WriteAllText(Path.Combine(temp, "new.txt"), "new");

        Assert.Null(await store.CommitAsync(temp, sha, JobDepth.Standard, CancellationToken.None));

        Assert.True(File.Exists(Path.Combine(entry, "new.txt")));
        Assert.False(File.Exists(Path.Combine(entry, "old.txt")));
        Assert.False(Directory.Exists(temp));
    }

    /// <summary>Windows only: an open file blocks the delete; the commit waits it out when it is released within the retry window.</summary>
    [WindowsOnlyFact]
    public async Task CommitAsync_RetriesALeftoverEntryHeldOpenBriefly()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, 1L << 30);
        var sha = new string('d', 64);
        var entry = store.EntryDir(sha, JobDepth.Standard);
        Directory.CreateDirectory(entry);
        var held = new FileStream(Path.Combine(entry, "held.bin"), FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        var temp = store.CreateTemp(sha, JobDepth.Standard);
        File.WriteAllText(Path.Combine(temp, "new.txt"), "new");

        var commit = store.CommitAsync(temp, sha, JobDepth.Standard, CancellationToken.None);
        await Task.Delay(700);
        held.Dispose();

        Assert.Null(await commit);
        Assert.True(File.Exists(Path.Combine(entry, "new.txt")));
    }

    [WindowsOnlyFact]
    public async Task CommitAsync_ALeftoverHeldOpenThroughout_IsAReason_AndTheTempSurvives()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, 1L << 30);
        var sha = new string('e', 64);
        var entry = store.EntryDir(sha, JobDepth.Standard);
        Directory.CreateDirectory(entry);
        var temp = store.CreateTemp(sha, JobDepth.Standard);
        File.WriteAllText(Path.Combine(temp, "new.txt"), "new");

        string? reason;
        using (new FileStream(Path.Combine(entry, "held.bin"), FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            reason = await store.CommitAsync(temp, sha, JobDepth.Standard, CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(reason));
        Assert.DoesNotContain(dirs.Base, reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(Path.Combine(temp, "new.txt")), "the finished run was lost");
    }
    #endregion
}
