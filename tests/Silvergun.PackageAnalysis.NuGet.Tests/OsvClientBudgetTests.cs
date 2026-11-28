namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// <see cref="OsvClient"/>'s <c>budget</c> (MCP task S5 review round 2, W-A): it bounds a whole <c>QueryAsync</c>. When it runs out,
/// the result is <c>Queried = false</c> with the findings gathered so far, and nothing more is sent; a caller's cancellation still
/// throws. A fake handler with deliberate delays serves every response: there is never a real network call.
/// </summary>
public sealed class OsvClientBudgetTests
{
    #region Methods
    /// <summary>
    /// Re-pinned in S5 review round 3 (W-B): a budget that runs out mid-details no longer drops the ids not yet looked up (it
    /// once returned Queried=false with only the enriched findings). Every id the completed batch returned is a finding; those
    /// looked up before the deadline carry their detail, the rest are id-only; the batch completed, so Queried stays true.
    /// Hardened for load: the first three details answer at once and the fourth hangs far past the budget, so exactly three are
    /// enriched and exactly four are sent whatever the machine's speed.
    /// </summary>
    [Fact]
    public async Task QueryAsync_WhenTheBudgetRunsOutDuringDetails_KeepsEveryId_EnrichesThoseLookedUp_AndSendsNothingAfter()
    {
        var fake = new SlowFake(batchDelay: TimeSpan.Zero, detailDelay: i => i < 3 ? TimeSpan.Zero : Hang, ids: 10);
        var client = new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test", budget: DetailsBudget);

        var clock = Stopwatch.StartNew();
        var result = await client.QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)]);
        var elapsed = clock.Elapsed;
        await Task.Delay(500);   // anything still scheduled would show up now

        Assert.True(result.Queried);
        Assert.True(elapsed < Bound, $"the query took {elapsed.TotalMilliseconds:0} ms: it waited for the {Hang.TotalSeconds:0} s hang, not its {DetailsBudget.TotalMilliseconds:0} ms budget");
        Assert.Equal(Enumerable.Range(1, 10).Select(i => $"GHSA-{i}").Order(), result.Findings.Select(f => f.Id).Order());
        Assert.All(result.Findings, f => Assert.Equal("VulnPkg", f.PackageId));
        Assert.Equal(3, result.Findings.Count(f => f.Summary is not null));
        Assert.All(result.Findings.Where(f => f.Summary is not null), f => Assert.Equal($"Detail of {f.Id}.", f.Summary));
        Assert.All(result.Findings.Where(f => f.Summary is null), f => Assert.Empty(f.Aliases));   // id-only
        Assert.Equal(3, fake.DetailsCompleted);
        Assert.Equal(4, fake.DetailStarts.Count);   // nothing is sent after the hung fourth
        Assert.Equal(1, fake.Cancelled);   // the hung request was cancelled at the budget, not waited out
    }

    /// <summary>W-B: when the first detail hangs past the budget, every id is still a finding, all id-only, and only that one detail was sent.</summary>
    [Fact]
    public async Task QueryAsync_WhenTheBudgetRunsOutBeforeAnyDetail_KeepsEveryIdAsIdOnly_AfterOneDetailRequest()
    {
        var fake = new SlowFake(batchDelay: TimeSpan.Zero, detailDelay: _ => Hang, ids: 10);
        var client = new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test", budget: Budget);

        var clock = Stopwatch.StartNew();
        var result = await client.QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)]);
        var elapsed = clock.Elapsed;
        await Task.Delay(500);

        Assert.True(result.Queried);
        Assert.True(elapsed < Bound, $"the query took {elapsed.TotalMilliseconds:0} ms: it waited for the {Hang.TotalSeconds:0} s hang, not its {Budget.TotalMilliseconds:0} ms budget");
        Assert.Equal(Enumerable.Range(1, 10).Select(i => $"GHSA-{i}").Order(), result.Findings.Select(f => f.Id).Order());
        Assert.All(result.Findings, f => Assert.Null(f.Summary));
        Assert.Single(fake.DetailStarts);
        Assert.Equal(0, fake.DetailsCompleted);
        Assert.Equal(1, fake.Cancelled);
    }

    [Fact]
    public async Task QueryAsync_WhenTheBudgetRunsOutDuringTheBatch_IsNotQueried_WithNoFindings()
    {
        var fake = new SlowFake(batchDelay: Hang, detailDelay: _ => TimeSpan.Zero, ids: 3);
        var client = new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test", budget: Budget);

        var clock = Stopwatch.StartNew();
        var result = await client.QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)]);
        var elapsed = clock.Elapsed;

        Assert.False(result.Queried);
        Assert.Empty(result.Findings);
        Assert.Empty(fake.DetailStarts);
        Assert.True(elapsed < Bound, $"the query took {elapsed.TotalMilliseconds:0} ms: it waited for the {Hang.TotalSeconds:0} s hang, not its {Budget.TotalMilliseconds:0} ms budget");
        Assert.Equal(1, fake.Cancelled);   // the hung batch was cancelled
    }

    [Fact]
    public async Task QueryAsync_CallerCancellation_StillThrows_UnderABudget()
    {
        var fake = new SlowFake(batchDelay: TimeSpan.Zero, detailDelay: _ => Hang, ids: 10);
        var client = new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test", budget: TimeSpan.FromSeconds(60));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)], cts.Token));
        Assert.Equal(1, fake.Cancelled);
    }

    [Fact]
    public async Task QueryAsync_WithinItsBudget_IsQueried_WithEveryFinding()
    {
        var fake = new SlowFake(batchDelay: TimeSpan.Zero, detailDelay: _ => TimeSpan.FromMilliseconds(10), ids: 3);
        var client = new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test", budget: TimeSpan.FromSeconds(60));

        var result = await client.QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)]);

        Assert.True(result.Queried);
        Assert.Equal(3, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.NotNull(f.Summary));
        Assert.Equal(0, fake.Cancelled);
    }
    #endregion

    #region Fields
    // A hung request: far past every budget and bound here, and ended at once by its request's token.
    private static readonly TimeSpan Hang = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Budget = TimeSpan.FromMilliseconds(300);
    // Long enough for three instant details on a loaded machine; the fourth hangs past it.
    private static readonly TimeSpan DetailsBudget = TimeSpan.FromSeconds(3);
    // Room for a loaded thread pool, and still a third of the hang: a client that waited the hang out cannot pass.
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    #endregion

    #region Types
    // A batch of `ids` vulnerability ids for the one query; the batch, and detail number i (from 0), wait `detailDelay(i)` before
    // answering, cancellably by the request's token. Counts the requests whose wait was cancelled.
    private sealed class SlowFake(TimeSpan batchDelay, Func<int, TimeSpan> detailDelay, int ids) : HttpMessageHandler
    {
        public int DetailsCompleted => completed;

        public int Cancelled => cancelled;

        public IReadOnlyList<TimeSpan> DetailStarts { get { lock (starts) return [.. starts]; } }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/querybatch", StringComparison.Ordinal))
            {
                await Wait(batchDelay, cancellationToken);
                var vulns = string.Join(",", Enumerable.Range(1, ids).Select(i => $"{{\"id\":\"GHSA-{i}\"}}"));
                return Ok($$"""{"results":[{"vulns":[{{vulns}}]}]}""");
            }
            int index;
            lock (starts)
            {
                index = starts.Count;
                starts.Add(clock.Elapsed);
            }
            await Wait(detailDelay(index), cancellationToken);
            Interlocked.Increment(ref completed);
            var id = Uri.UnescapeDataString(path[(path.LastIndexOf('/') + 1)..]);
            return Ok($$"""{"id":"{{id}}","summary":"Detail of {{id}}."}""");
        }

        private async Task Wait(TimeSpan delay, CancellationToken ct)
        {
            try
            {
                await Task.Delay(delay, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                Interlocked.Increment(ref cancelled);
                throw;
            }
        }

        private static HttpResponseMessage Ok(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json) };

        private readonly Stopwatch clock = Stopwatch.StartNew();
        private readonly List<TimeSpan> starts = [];
        private int completed;
        private int cancelled;
    }
    #endregion
}
