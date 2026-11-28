namespace Silvergun.MCPServer.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// S1 through real server processes (the CLI apphost's <c>mcp</c> verb) sharing one cache: any process resolves any
/// <c>jobId</c>; a repeat is cached within a second; two servers asked for one package at once run it once.
/// </summary>
public sealed class JobServerTests
{
    #region Methods
    [Fact]
    public async Task ACompletedJob_IsCachedWithinOneSecond_InTheSameServer_AndServedByASecondServer()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Small(dirs.Root);
        var sha = Fixtures.Sha256Of(package);
        string jobId;

        using (var first = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root))
        {
            var analyzed = await first.AnalyzeAsync(package);
            Assert.False(analyzed.IsError, analyzed.Text);
            jobId = analyzed.Str("jobId")!;
            Assert.Equal($"{sha}-standard", jobId);   // the full sha256, not a prefix
            var done = await first.WaitToEndAsync(jobId);
            Assert.True(done.Status == "Succeeded", done.Text);

            var clock = Stopwatch.StartNew();
            var repeat = await first.AnalyzeAsync(package);
            clock.Stop();
            Assert.True(repeat.Flag("cached"), repeat.Text);
            Assert.Equal(jobId, repeat.Str("jobId"));
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"the repeat took {clock.ElapsedMilliseconds} ms");
            var own = await first.CallAsync(ToolNames.GetSummary, new JsonObject { ["jobId"] = jobId });
            Assert.True(own.Status == "Succeeded", own.Text);
            Assert.False(own.S.TryGetProperty("cached", out _), "get_summary of a job this process ran says cached (W5)");
            Assert.Equal(0, (await first.Child.CloseStdinAndWaitForExitAsync()).ExitCode);
        }

        using var second = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);
        var summary = await second.CallAsync(ToolNames.GetSummary, new JsonObject { ["jobId"] = jobId });   // no analyze_package in this process
        Assert.True(summary.Status == "Succeeded", summary.Text);
        Assert.True(summary.Flag("cached"));
        Assert.Equal("mcp.small", summary.S.GetProperty("summary").GetProperty("package").GetProperty("id").GetProperty("untrusted").GetString());
        var wait = await second.CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = jobId, ["maxWaitSeconds"] = 1 });
        Assert.Equal("Succeeded", wait.Status);
        Assert.Equal("completed", wait.Str("state"));

        var secondClock = Stopwatch.StartNew();
        var again = await second.AnalyzeAsync(package);
        secondClock.Stop();
        Assert.True(again.Flag("cached"), again.Text);
        Assert.True(secondClock.Elapsed < TimeSpan.FromSeconds(1), $"the second server's repeat took {secondClock.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task TwoServers_AskedForOnePackageAtOnce_RunItOnce()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Slow(dirs.Root);
        using var a = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);
        using var b = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);

        var both = await Task.WhenAll(a.AnalyzeAsync(package), b.AnalyzeAsync(package));
        Assert.All(both, r => Assert.False(r.IsError, r.Text));
        var jobId = both[0].Str("jobId")!;
        Assert.Equal(jobId, both[1].Str("jobId"));

        var sawElsewhere = false;
        var longestElsewhereWait = TimeSpan.Zero;
        async Task<ToolCall> Follow(McpRpc rpc)
        {
            var clock = Stopwatch.StartNew();
            while (true)
            {
                var call = Stopwatch.StartNew();
                var wait = await rpc.CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = jobId, ["maxWaitSeconds"] = 2 });
                if (wait.Flag("runningInAnotherServer"))
                    (sawElsewhere, longestElsewhereWait) = (true, call.Elapsed > longestElsewhereWait ? call.Elapsed : longestElsewhereWait);
                if (!wait.Retry || clock.Elapsed > InProcess.JobTimeout)
                    return wait;
            }
        }
        var ends = await Task.WhenAll(Follow(a), Follow(b));

        Assert.All(ends, e => Assert.True(e.Status == "Succeeded", e.Text));
        Assert.Equal(1, ends.Count(e => !e.Flag("cached")));   // exactly one server ran it; the other was served its result
        Assert.True(sawElsewhere, "neither server reported waiting on the other");
        // A wait on a job another server runs waits (polling) up to maxWaitSeconds rather than returning at once.
        Assert.True(longestElsewhereWait >= TimeSpan.FromSeconds(1.5), $"the longest wait on the peer's job returned in {longestElsewhereWait.TotalMilliseconds:F0} ms");
        var keyDir = Path.Combine(dirs.Cache, Fixtures.Sha256Of(package));
        Assert.Equal(new[] { JobStore.EntryName(JobDepth.Standard) }, Directory.GetDirectories(keyDir).Select(d => Path.GetFileName(d)).ToArray());
        var analyzedAt = await Task.WhenAll(new[] { a, b }.Select(async r =>
            (await r.CallAsync(ToolNames.GetSummary, new JsonObject { ["jobId"] = jobId })).S.GetProperty("analyzedAt").GetString()));
        Assert.Equal(analyzedAt[0], analyzedAt[1]);
    }

    [Fact]
    public async Task OverTheWire_ARefusedPathAndAnUnknownJob_AreToolErrors_AndTheServerKeepsAnswering()
    {
        using var dirs = new TestDirs();
        var outside = Fixtures.Small(dirs.NewDir("outside"));
        using var rpc = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);

        var refused = await rpc.AnalyzeAsync(outside);
        var unknown = await rpc.CallAsync(ToolNames.GetSummary, new JsonObject { ["jobId"] = new string('a', 64) + "-standard" });
        var malformed = await rpc.CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = "../../etc" });
        var info = await rpc.CallAsync(ToolNames.GetServerInfo);

        Assert.True(refused.IsError);
        Assert.Equal("OutsideRoots", refused.Status);
        Assert.True(unknown.IsError);
        Assert.Equal("NotFound", unknown.Status);
        Assert.True(malformed.IsError);
        Assert.Equal("InvalidArgument", malformed.Status);
        Assert.False(info.IsError);
        Assert.Equal(BuildIdentity.RulesHash, info.S.GetProperty("versions").GetProperty("rulesHash").GetString());
        Assert.Equal(BuildIdentity.BuildKey, info.S.GetProperty("versions").GetProperty("cacheBuildKey").GetString());
    }
    #endregion
}

/// <summary>
/// Kills and lifetime (S1 Accept, D4a), checked by process listing: the tests run alone (<see cref="ProcessCountingCollection"/>),
/// and every process seen under the server (or the test host) during the job must be gone afterwards.
/// </summary>
[Collection(ProcessCountingCollection.Name)]
public sealed class JobLifetimeTests
{
    #region Methods
    [ProcessListingFact]
    public async Task UntilTheFirstToolCall_TheServerSpawnsNoChild_AndCreatesNoCache()
    {
        using var dirs = new TestDirs();
        var cache = Path.Combine(dirs.Base, "cache-not-yet");
        using var rpc = await McpRpc.StartAsync(["mcp", "--root", dirs.Root, "--cache-dir", cache, "--log-dir", dirs.Logs, "--no-network"], dirs.Root);
        using var watch = new TreeWatcher(rpc.Child.Id);

        rpc.Child.Send("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        await rpc.Child.WaitForResponseAsync(2);
        var info = await rpc.CallAsync(ToolNames.GetServerInfo);
        Assert.False(info.IsError, info.Text);
        await Task.Delay(1_000);

        Assert.DoesNotContain(watch.Seen, p => !ProcessTree.IsConsoleHost(p));
        Assert.False(Path.Exists(cache), "the cache directory exists before any job tool was called");

        // The positive control: the first job call creates the cache and starts a job child.
        var done = await rpc.WaitToEndAsync((await rpc.AnalyzeAsync(Fixtures.Small(dirs.Root))).Str("jobId")!);
        Assert.Equal("Succeeded", done.Status);
        Assert.True(Directory.Exists(cache));
        Assert.Contains(watch.Seen, ProcessTree.IsCli);
    }

    [ProcessListingFact]
    public async Task CancelJob_KillsTheJobTree_AndTheServerKeepsAnswering()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Slow(dirs.Root);
        using var rpc = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);
        using var watch = new TreeWatcher(rpc.Child.Id);
        var jobId = (await rpc.AnalyzeAsync(package)).Str("jobId")!;
        await rpc.WaitUntilRunningAsync(jobId);
        await watch.WaitForAsync(ProcessTree.IsCli, McpCli.Timeout);

        var progress = await rpc.CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = jobId, ["maxWaitSeconds"] = 2 }, progressToken: "p-1");
        var cancelled = await rpc.CallAsync(ToolNames.CancelJob, new JsonObject { ["jobId"] = jobId });

        Assert.False(cancelled.IsError, cancelled.Text);
        Assert.True(cancelled.S.GetProperty("ok").GetBoolean());
        Assert.Equal("Succeeded", cancelled.Status);
        Assert.Equal("cancelled", cancelled.Str("state"));
        await watch.AssertAllGoneAsync(TimeSpan.FromSeconds(5), "after cancel_job");
        Assert.True(progress.Retry, progress.Text);
        Assert.Contains(rpc.Child.Lines, l => l.Contains("\"notifications/progress\"") && l.Contains("\"p-1\""));

        Assert.Equal("Cancelled", (await rpc.CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = jobId, ["maxWaitSeconds"] = 1 })).Status);
        Assert.False((await rpc.CallAsync(ToolNames.GetServerInfo)).IsError);
        var small = await rpc.WaitToEndAsync((await rpc.AnalyzeAsync(Fixtures.Small(dirs.Root))).Str("jobId")!);
        Assert.True(small.Status == "Succeeded", small.Text);
    }

    [ProcessListingFact]
    public async Task ClosingStdin_DuringAJob_EndsTheServerWithin5s_AndLeavesNoTreeProcess()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Slow(dirs.Root);
        using var rpc = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);
        using var watch = new TreeWatcher(rpc.Child.Id);
        var jobId = (await rpc.AnalyzeAsync(package)).Str("jobId")!;
        await rpc.WaitUntilRunningAsync(jobId);
        await watch.WaitForAsync(ProcessTree.IsCli, McpCli.Timeout);

        var exit = await rpc.Child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"the server did not exit\n{exit.Stderr}");
        Assert.True(exit.Elapsed <= TimeSpan.FromSeconds(5), $"the server exited {exit.Elapsed.TotalMilliseconds:F0} ms after stdin closed (limit 5 s)");
        await watch.AssertAllGoneAsync(TimeSpan.FromSeconds(2), "after the server exited");
        Assert.False(Directory.Exists(Path.Combine(dirs.Cache, Fixtures.Sha256Of(package), JobStore.EntryName(JobDepth.Standard))), "a cancelled job was committed");
    }

    [ProcessListingFact]
    public async Task AHardKilledServer_LeavesNoChildAlive()
    {
        using var dirs = new TestDirs();
        var package = Fixtures.Slow(dirs.Root);
        using var rpc = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);
        using var watch = new TreeWatcher(rpc.Child.Id);
        var jobId = (await rpc.AnalyzeAsync(package)).Str("jobId")!;
        await rpc.WaitUntilRunningAsync(jobId);
        await watch.WaitForAsync(ProcessTree.IsCli, McpCli.Timeout);

        rpc.Child.KillServerOnly();   // TerminateProcess / SIGKILL of the server alone: none of its handlers run

        await watch.AssertAllGoneAsync(TimeSpan.FromSeconds(10), "after the server was hard-killed");
    }

    [ProcessListingFact]
    public async Task JobProcess_ARealJobPastItsBudget_TimesOut_AndLeavesNoTreeProcess()
    {
        using var dirs = new TestDirs();
        var jobDir = dirs.NewDir("job");
        File.Copy(Fixtures.Slow(dirs.Root), Path.Combine(jobDir, JobProtocol.PackageFile));
        using var watch = new TreeWatcher(Environment.ProcessId, ignoreExisting: true);   // the test host's own console host is not the job's
        var progress = 0;

        var clock = Stopwatch.StartNew();
        var result = await Task.Run(() => JobProcess.Run(InProcess.CliLaunch, new JobRequest(JobProtocol.Version, jobDir, JobDepth.Standard, false),
            TimeSpan.FromSeconds(2), McpLimits.JobMemoryBytes, McpLimits.JobHeapBytes, _ => progress++, default));
        clock.Stop();

        Assert.True(result.Status == JobRunStatus.TimedOut, $"{result.Status}: {result.Reason}");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20), $"Run took {clock.Elapsed}");
        Assert.Contains(watch.Seen, ProcessTree.IsCli);
        await watch.AssertAllGoneAsync(TimeSpan.FromSeconds(5), "after the timed-out job");
        Assert.False(File.Exists(Path.Combine(jobDir, JobProtocol.ReportFile)), "a timed-out job wrote its report");
    }
    #endregion
}
