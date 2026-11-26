namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// D4 eviction, in-process, over handmade entries (valid <c>job.json</c>s of this build, <c>.accessed</c> times set by
/// hand): never on recency alone; entries this build cannot serve go first; the entry being kept and any locked entry are
/// never touched; and nothing whose name only resembles an entry is ever considered.
/// </summary>
public sealed class JobStoreEvictionTests
{
    #region Methods
    [Fact]
    public void Evict_KeepsACostlyIdleDeepEntry_OverANewerCheapStandardOne()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 1_500);
        var costly = Entry(store, Sha(1), JobDepth.Deep, costMs: 1_200_000, idle: TimeSpan.FromHours(3));
        var cheap = Entry(store, Sha(2), JobDepth.Standard, costMs: 2_000, idle: TimeSpan.FromMinutes(70));

        var deleted = store.Evict(null);

        Assert.Equal(1, deleted);
        Assert.True(Directory.Exists(costly), "the costly deep entry was evicted");
        Assert.False(Directory.Exists(cheap), "the cheap standard entry was kept");
    }

    [Fact]
    public void Evict_AmongIdleEntries_RemovesTheCheapestFirst_WhateverTheirAge()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 2_500);
        var oldCostly = Entry(store, Sha(1), JobDepth.Standard, costMs: 90_000, idle: TimeSpan.FromDays(3));
        var middle = Entry(store, Sha(2), JobDepth.Standard, costMs: 30_000, idle: TimeSpan.FromHours(5));
        var newCheap = Entry(store, Sha(3), JobDepth.Standard, costMs: 500, idle: TimeSpan.FromHours(2));

        Assert.Equal(1, store.Evict(null));

        Assert.True(Directory.Exists(oldCostly));
        Assert.True(Directory.Exists(middle));
        Assert.False(Directory.Exists(newCheap));
    }

    [Fact]
    public void Evict_AmongRecentEntries_RemovesTheLeastRecentlyUsed()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 1_500);
        var older = Entry(store, Sha(1), JobDepth.Standard, costMs: 900_000, idle: TimeSpan.FromMinutes(40));
        var newer = Entry(store, Sha(2), JobDepth.Standard, costMs: 10, idle: TimeSpan.FromMinutes(5));

        Assert.Equal(1, store.Evict(null));

        Assert.False(Directory.Exists(older));
        Assert.True(Directory.Exists(newer));
    }

    [Fact]
    public void Evict_IdleEntriesGoBeforeRecentOnes()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 1_500);
        var idleCostly = Entry(store, Sha(1), JobDepth.Deep, costMs: 1_400_000, idle: TimeSpan.FromHours(2));
        var recentCheap = Entry(store, Sha(2), JobDepth.Standard, costMs: 10, idle: TimeSpan.FromMinutes(1));

        Assert.Equal(1, store.Evict(null));

        Assert.False(Directory.Exists(idleCostly));
        Assert.True(Directory.Exists(recentCheap));
    }

    [Fact]
    public void Evict_ForeignBuildAndUnreadableEntries_GoFirst()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 2_100);
        var foreign = Entry(store, Sha(1), JobDepth.Standard, costMs: 1, idle: TimeSpan.Zero, buildKey: "0123456789abcdef");
        var unreadable = Entry(store, Sha(2), JobDepth.Standard, costMs: 1, idle: TimeSpan.Zero, recordBytes: Encoding.UTF8.GetBytes("{\"schemaVersion\": tru"));
        File.WriteAllBytes(Path.Combine(unreadable, "filler.bin"), new byte[1_000]);
        var idleCheap = Entry(store, Sha(3), JobDepth.Standard, costMs: 1, idle: TimeSpan.FromHours(4));
        var recent = Entry(store, Sha(4), JobDepth.Standard, costMs: 1, idle: TimeSpan.Zero);

        Assert.Equal(2, store.Evict(null));

        Assert.False(Directory.Exists(foreign), "the foreign-build entry was kept");
        Assert.False(Directory.Exists(unreadable), "the unreadable entry was kept");
        Assert.True(Directory.Exists(idleCheap));
        Assert.True(Directory.Exists(recent));
    }

    [Fact]
    public void Evict_NeverDeletesTheKeptOrALockedEntry()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 0);
        var kept = Entry(store, Sha(1), JobDepth.Standard, costMs: 1, idle: TimeSpan.FromDays(9));   // first in line, but kept
        var locked = Entry(store, Sha(2), JobDepth.Standard, costMs: 1, idle: TimeSpan.FromDays(9));
        var other = Entry(store, Sha(3), JobDepth.Standard, costMs: 1_000_000, idle: TimeSpan.Zero);
        using var held = new FileStream(locked + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        var deleted = store.Evict((Sha(1), JobDepth.Standard));

        Assert.Equal(1, deleted);
        Assert.True(Directory.Exists(kept), "the kept entry was deleted");
        Assert.True(Directory.Exists(locked), "a locked entry was deleted");
        Assert.False(Directory.Exists(other));
    }

    [Fact]
    public void Evict_UnderTheCap_DeletesNothing()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 10_000);
        var a = Entry(store, Sha(1), JobDepth.Standard, costMs: 1, idle: TimeSpan.FromDays(30), buildKey: "0123456789abcdef");
        var b = Entry(store, Sha(2), JobDepth.Deep, costMs: 1, idle: TimeSpan.FromDays(30));

        Assert.Equal(0, store.Evict(null));

        Assert.True(Directory.Exists(a));
        Assert.True(Directory.Exists(b));
    }

    [Fact]
    public void Evict_IgnoresDirectoriesThatOnlyResembleEntries()
    {
        using var dirs = new TestDirs();
        var store = new JobStore(dirs.Cache, maxBytes: 0);
        var key = BuildIdentity.BuildKey;
        var sha = Sha(1);
        var lookalikes = new[]
        {
            Path.Combine(dirs.Cache, sha[..63], key + "-standard"),                  // a 63-hex package directory
            Path.Combine(dirs.Cache, sha + "0", key + "-standard"),                  // 65 hex
            Path.Combine(dirs.Cache, sha, key + "-standardx"),
            Path.Combine(dirs.Cache, sha, key + "-standard.tmp-abcdefghijkl"),
            Path.Combine(dirs.Cache, sha, key[..15] + "-standard"),
            Path.Combine(dirs.Cache, sha, "x" + key + "-deep"),
            Path.Combine(dirs.Cache, "incoming"),
        };
        foreach (var dir in lookalikes)
        {
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, JobProtocol.JobFile), Record(sha, JobDepth.Standard, key, 1, 1_000_000));
        }

        Assert.Equal(0, store.Evict(null));

        Assert.All(lookalikes, d => Assert.True(Directory.Exists(d), $"deleted: {d}"));
    }
    #endregion

    #region Methods: helpers
    private static string Sha(int n) => Convert.ToHexStringLower(SHA256.HashData(BitConverter.GetBytes(n)));

    // A completed-looking entry of 1,000 bytes (by its record), last used `idle` ago.
    private static string Entry(JobStore store, string sha, JobDepth depth, long costMs, TimeSpan idle, string? buildKey = null, byte[]? recordBytes = null)
    {
        var key = buildKey ?? BuildIdentity.BuildKey;
        var dir = Path.Combine(store.Root, sha, $"{key}-{JobStore.DepthName(depth)}");
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, JobProtocol.JobFile), recordBytes ?? Record(sha, depth, key, costMs, 1_000));
        var marker = Path.Combine(dir, ".accessed");
        File.WriteAllBytes(marker, []);
        File.SetLastWriteTimeUtc(marker, DateTime.UtcNow - idle);
        return dir;
    }

    private static byte[] Record(string sha, JobDepth depth, string buildKey, long costMs, long entryBytes)
    {
        var now = DateTimeOffset.UtcNow;
        return JsonSerializer.SerializeToUtf8Bytes(
            new JobRecord(JobArtifacts.SchemaVersion, sha, depth, buildKey, ServerState.SilvergunVersion, BuildIdentity.RulesHash, false, 900,
                McpLimits.JobMemoryBytes, now, now, costMs, new List<JobStageTime> { new("extract", costMs) }, 100, entryBytes),
            JobProtocol.JsonOptions);
    }
    #endregion
}
