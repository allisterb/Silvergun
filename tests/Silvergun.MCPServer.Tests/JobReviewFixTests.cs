namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S1 review fixes, in-process (jobs in the real CLI apphost): no host path in a served summary (C1); the inventory's
/// per-row bound and lossless names under hostile entry names (W2, W3); a job waiting on another process's lock holds no
/// <c>--max-jobs</c> slot (W4); <see cref="PackageInput.Check"/> answers with a status, never a throw; the build key's shape.
/// </summary>
public sealed class JobReviewFixTests
{
    #region Methods
    /// <summary>C1: an unloadable assembly's reason used to carry the full extraction path; now it names the package-relative path.</summary>
    [Fact]
    public async Task GetSummary_ServesNoHostPath_AndTheLoadFailureNamesThePackageRelativePath()
    {
        using var dirs = new TestDirs();
        var bytes = new byte[512];
        new Random(11).NextBytes(bytes);
        (bytes[0], bytes[1]) = ((byte)'M', (byte)'Z');
        var package = Fixtures.Nupkg(dirs.Root, "mcp.evil", ("lib/net8.0/Evil.dll", bytes));
        var tools = InProcess.Tools(dirs, out var manager);

        var view = await InProcess.RunToEndAsync(manager, package);
        Assert.True(view.State == JobState.Completed, $"{view.State} {view.Reason}");
        var result = tools.GetSummary(view.JobId);

        Assert.False(result.IsError, InProcess.Text(result));
        var hostPaths = new[] { dirs.Cache, dirs.Base, Path.TrimEndingDirectorySeparator(Path.GetTempPath()), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) };
        var strings = Strings(InProcess.S(result)).ToList();
        foreach (var host in hostPaths)
            foreach (var form in new[] { host, host.Replace(Backslash, Backslash + Backslash) })
            {
                var leaked = strings.FirstOrDefault(s => s.Contains(form, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal));
                Assert.True(leaked is null, $"a served string names the host path '{form}': {leaked}");
            }

        var reason = InProcess.S(result).GetProperty("summary").GetProperty("assemblies")[0].GetProperty("reason").GetProperty("untrusted").GetString()!;
        Assert.True(new[] { "lib/net8.0/Evil.dll", "lib" + Backslash + "net8.0" + Backslash + "Evil.dll", "lib" + Backslash + Backslash + "net8.0" + Backslash + Backslash + "Evil.dll" }
            .Any(p => reason.Contains(p, StringComparison.Ordinal)), $"the reason does not name lib/net8.0/Evil.dll package-relatively: {reason}");
    }

    /// <summary>
    /// W2, W3: about 2,000 entries whose names carry ~120 Tag-block characters each, plus a real U+202E and the six-character
    /// text backslash-u-202e, plus a duplicate entry that is never extracted. The job completes; every row's path is bounded
    /// and holds no raw astral or bidi character; the two look-alike names stay distinct; rows say their path form.
    /// </summary>
    [Fact]
    public async Task Inventory_UnderHostileNames_IsBoundedPerRow_Lossless_AndSaysItsPathForm()
    {
        using var dirs = new TestDirs();
        var tags = string.Concat(Enumerable.Range(0, 120).Select(i => char.ConvertFromUtf32(0xE0041 + i % 26)));
        var rlo = (char)0x202E;
        var entries = new List<(string, byte[])>();
        for (var i = 0; i < 2_000; i++)
            entries.Add(($"content/{i:D4}{tags}.txt", [(byte)'x']));
        entries.Add(("content/a" + rlo + "b.txt", [(byte)'r']));
        entries.Add(("content/a" + Backslash + "u202eb.txt", [(byte)'l']));
        var dll = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Nuclear.SemVer.dll"));
        var other = new byte[256];
        new Random(5).NextBytes(other);
        (other[0], other[1]) = ((byte)'M', (byte)'Z');
        entries.Add(("lib/net8.0/Dup.dll", dll));
        entries.Add(("lib/net8.0/Dup.dll", other));   // the same name, other bytes: the second never becomes a file of its own
        var package = Fixtures.Nupkg(dirs.Root, "mcp.hostile", [.. entries]);
        var manager = InProcess.Manager(dirs);

        var view = await InProcess.RunToEndAsync(manager, package);

        Assert.True(view.State == JobState.Completed, $"{view.State} {view.Reason}");
        // S2: one row per line (inventory.jsonl), the list's cut in index.json, and the path wrapped as {"untrusted": ...}.
        var text = File.ReadAllText(Path.Combine(view.EntryDir!, JobProtocol.InventoryFile), Encoding.ASCII);
        Assert.EndsWith("\n", text);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        using var index = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(view.EntryDir!, JobProtocol.IndexFile)));
        var truncated = index.RootElement.GetProperty("files").GetProperty("truncated");
        Assert.Contains(truncated.ValueKind, new[] { JsonValueKind.True, JsonValueKind.False });
        Assert.Equal(lines.Length, index.RootElement.GetProperty("files").GetProperty("rows").GetInt32());
        var rows = lines.Select(l => JsonDocument.Parse(l).RootElement).ToList();
        Assert.NotEmpty(rows);
        Assert.True(rows.Count <= entries.Count + 1, $"{rows.Count} rows for {entries.Count + 1} entries");
        if (truncated.ValueKind == JsonValueKind.False)
            Assert.True(rows.Count >= 2_000, $"only {rows.Count} rows, yet not truncated");
        foreach (var row in rows)
        {
            var wrapped = row.GetProperty("path");
            Assert.Single(wrapped.EnumerateObject());
            var path = wrapped.GetProperty("untrusted").GetString()!;
            Assert.True(path.Length <= 560, $"a row path of {path.Length} chars");
            Assert.False(path.Any(char.IsSurrogate), $"a raw astral character in a row path: {path[..Math.Min(80, path.Length)]}");
            Assert.DoesNotContain(rlo, path);
            Assert.Contains(row.GetProperty("pathForm").GetString(), new[] { "lossless", "report" });
        }

        var extracted = rows.Where(r => r.GetProperty("kind").GetString() != "notExtracted").ToList();
        var notExtracted = rows.Where(r => r.GetProperty("kind").GetString() == "notExtracted").ToList();
        Assert.NotEmpty(extracted);
        Assert.All(extracted, r => Assert.Equal("lossless", r.GetProperty("pathForm").GetString()));   // no bundles in this fixture
        var dup = Assert.Single(notExtracted);
        Assert.Equal("report", dup.GetProperty("pathForm").GetString());
        Assert.Equal(JsonValueKind.Null, dup.GetProperty("file").ValueKind);
        Assert.False(dup.GetProperty("readable").GetBoolean());
        Assert.False(string.IsNullOrEmpty(dup.GetProperty("note").GetProperty("untrusted").GetString()));

        var lookalikes = rows.Select(r => r.GetProperty("path").GetProperty("untrusted").GetString()!).Where(p => p.StartsWith("content/a", StringComparison.Ordinal) && p.EndsWith("b.txt", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, lookalikes.Count);
        Assert.Equal(2, lookalikes.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>W4: a job waiting on another process's lock does not hold the one <c>--max-jobs</c> slot; another package still runs.</summary>
    [Fact]
    public async Task AJobWaitingOnAPeersLock_TakesNoSlot_SoAnotherPackageRuns()
    {
        using var dirs = new TestDirs();
        var waiting = Fixtures.Small(dirs.Root, "mcp.locked");
        var other = Fixtures.Small(dirs.Root, "mcp.free");
        var sha = Fixtures.Sha256Of(waiting);
        Directory.CreateDirectory(Path.Combine(dirs.Cache, sha));
        var manager = InProcess.Manager(dirs);   // --max-jobs 1
        var lockPath = Path.Combine(dirs.Cache, sha, JobStore.EntryName(JobDepth.Standard)) + ".lock";

        using (new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))   // "another server" runs it
        {
            var (held, _, problem) = await manager.SubmitAsync(waiting, JobDepth.Standard, CancellationToken.None);
            Assert.True(held is not null, problem);
            var (_, _, _) = await manager.WaitAsync(held!.JobId, TimeSpan.FromSeconds(2), null, CancellationToken.None);
            Assert.True(manager.Find(held.JobId).View is { Elsewhere: true }, $"the job is not waiting on the peer: {manager.Find(held.JobId).View}");

            var done = await InProcess.RunToEndAsync(manager, other);

            Assert.True(done.State == JobState.Completed, $"the other package did not run while one waited on a peer: {done.State} {done.Reason}");
            var (cancelled, _, _) = await manager.CancelAsync(held.JobId);
            Assert.Equal(JobState.Cancelled, cancelled!.State);
        }
    }

    public static TheoryData<string> UnusablePaths() => ["a NUL character", "a component that is a file", "a very long path", "a wildcard"];

    [Theory]
    [MemberData(nameof(UnusablePaths))]
    public void Check_NeverThrows_AndRefusesWithAStatus(string what)
    {
        using var dirs = new TestDirs();
        var file = Path.Combine(dirs.Root, "file.nupkg");
        File.WriteAllBytes(file, new byte[100]);
        var path = what switch
        {
            "a NUL character" => Path.Combine(dirs.Root, "a" + (char)0 + "b.nupkg"),
            "a component that is a file" => Path.Combine(file, "inner.nupkg"),
            "a very long path" => Path.Combine(dirs.Root, string.Join(Path.DirectorySeparatorChar, Enumerable.Repeat(new string('d', 200), 200)), "x.nupkg"),
            "a wildcard" => Path.Combine(dirs.Root, "*.nupkg"),
            _ => throw new ArgumentException(what),
        };

        var (full, status, problem) = PackageInput.Check(path, [dirs.Root]);

        Assert.Null(full);
        Assert.NotEqual(ToolStatus.Succeeded, status);
        Assert.False(string.IsNullOrWhiteSpace(problem));
    }

    [Fact]
    public void BuildKey_IsStable_And16LowercaseHex()
    {
        var first = BuildIdentity.BuildKey;

        Assert.Matches("^[0-9a-f]{16}$", first);
        Assert.Equal(first, BuildIdentity.BuildKey);
        Assert.Matches("^[0-9a-f]{64}$", BuildIdentity.RulesHash);
        Assert.Equal(first + "-standard", JobStore.EntryName(JobDepth.Standard));
        Assert.Equal(first + "-deep", JobStore.EntryName(JobDepth.Deep));
    }
    #endregion

    #region Methods: helpers
    private static IEnumerable<string> Strings(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => [e.GetString()!],
        JsonValueKind.Object => e.EnumerateObject().SelectMany(p => Strings(p.Value).Prepend(p.Name)),
        JsonValueKind.Array => e.EnumerateArray().SelectMany(Strings),
        _ => [],
    };
    #endregion

    #region Fields
    private const string Backslash = @"\";
    #endregion
}
