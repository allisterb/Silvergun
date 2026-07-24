namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="OsvClient"/> (ADR 0017 / task <c>docs/agent/tasks/osv-vulnerability-intel.md</c>,
/// Phase 1). All I/O is served by an injected stub <see cref="HttpMessageHandler"/> that routes by request
/// path/method (<c>POST /v1/querybatch</c> and <c>GET /v1/vulns/{id}</c>) — there is never a real network call.
/// Covers the happy path (a vuln attributed to the matching package, a clean package yielding none), a shared id
/// across queries (one finding per matching package), the never-throws contract (404/5xx/timeout/malformed on the
/// querybatch collapse to empty; a failed detail GET yields an id-only finding rather than a drop), cancellation
/// propagation, the outgoing request headers, the null/empty short-circuit (no HTTP at all), and the
/// <see cref="VulnerabilityFinding"/> JSON round-trip.
/// </summary>
public sealed class OsvClientTests
{
    #region Methods
    // Happy path — the batch returns one vuln for query[0] and {} (clean) for query[1]. The single vuln is
    // enriched from its /vulns/{id} detail and attributed to query[0]'s package; query[1] yields nothing.
    [Fact]
    public async Task QueryAsync_OneVulnerableOneClean_AttributesEnrichedFindingToVulnerablePackageOnly()
    {
        var handler = new StubHttpMessageHandler((req, _) => Route(req, BatchOneVulnThenClean, _ => Ok(DetailJson)));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[]
        {
            new OsvQuery("VulnPkg", "1.0.0", IsDependency: false),
            new OsvQuery("CleanPkg", "2.0.0", IsDependency: true),
        });

        Assert.True(result.Queried);   // every querybatch chunk completed => the check ran
        var finding = Assert.Single(result.Findings);
        Assert.Equal("GHSA-vvvv-vvvv-vvvv", finding.Id);
        Assert.Equal("VulnPkg", finding.PackageId);
        Assert.Equal("1.0.0", finding.PackageVersion);
        Assert.False(finding.IsDependency);
        Assert.Contains("CVE-2024-21907", finding.Aliases);
        Assert.Equal("A heap-based buffer overflow in VulnPkg.", finding.Summary);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.Severity);
        Assert.Contains("https://example.test/advisory/GHSA-vvvv-vvvv-vvvv", finding.References);
    }

    // A single vuln id returned for TWO queries yields one finding per matching package, each with its own
    // package attribution — the shared detail is applied to both.
    [Fact]
    public async Task QueryAsync_SharedIdAcrossTwoQueries_EmitsOneFindingPerMatchingPackage()
    {
        const string batch = """
            { "results": [ { "vulns": [ { "id": "GHSA-shared", "modified": "2024-01-01T00:00:00Z" } ] },
                           { "vulns": [ { "id": "GHSA-shared", "modified": "2024-01-01T00:00:00Z" } ] } ] }
            """;
        const string detail = """{ "id": "GHSA-shared", "summary": "Shared advisory." }""";
        var handler = new StubHttpMessageHandler((req, _) => Route(req, batch, _ => Ok(detail)));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[]
        {
            new OsvQuery("PkgA", "1.0.0", IsDependency: false),
            new OsvQuery("PkgB", "2.0.0", IsDependency: true),
        });

        Assert.True(result.Queried);
        var findings = result.Findings;
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("GHSA-shared", f.Id));

        var a = Assert.Single(findings, f => f.PackageId == "PkgA");
        Assert.Equal("1.0.0", a.PackageVersion);
        Assert.False(a.IsDependency);

        var b = Assert.Single(findings, f => f.PackageId == "PkgB");
        Assert.Equal("2.0.0", b.PackageVersion);
        Assert.True(b.IsDependency);
    }

    // A single-chunk querybatch hard-failing (non-success) collapses to empty findings AND flips Queried=false — an
    // outage is now distinguishable from a genuinely-clean result. Never throws.
    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData((HttpStatusCode)429)]
    public async Task QueryAsync_QueryBatchNonSuccess_ReturnsNotQueriedAndEmpty(HttpStatusCode status)
    {
        var handler = new StubHttpMessageHandler((_, _) => new HttpResponseMessage(status));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[] { new OsvQuery("VulnPkg", "1.0.0", false) });

        Assert.False(result.Queried);   // the check could not complete — NOT a clean all-clear
        Assert.Empty(result.Findings);
    }

    // Malformed JSON in a 200 querybatch body is a hard chunk failure: empty findings and Queried=false.
    [Fact]
    public async Task QueryAsync_QueryBatchMalformedJson_ReturnsNotQueriedAndEmpty()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok("{ not valid json "));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[] { new OsvQuery("VulnPkg", "1.0.0", false) });

        Assert.False(result.Queried);
        Assert.Empty(result.Findings);
    }

    // A transport-level exception on the querybatch is a hard chunk failure: empty findings, Queried=false, no throw.
    [Fact]
    public async Task QueryAsync_QueryBatchTransportException_ReturnsNotQueriedAndEmpty()
    {
        var handler = new StubHttpMessageHandler((_, _) => throw new HttpRequestException("simulated socket failure"));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[] { new OsvQuery("VulnPkg", "1.0.0", false) });

        Assert.False(result.Queried);
        Assert.Empty(result.Findings);
    }

    // A TWO-chunk scan where one chunk succeeds (with a vuln) and the other hard-fails: Queried=false (the ID set is
    // incomplete), yet the findings gathered from the succeeding chunk are STILL returned. ChunkSize is 1000, so 1001
    // queries force exactly two chunks; the handler fails the second querybatch call while the first reports a vuln for
    // query[0]. Detail enrichment succeeds so the retained finding is fully populated.
    [Fact]
    public async Task QueryAsync_OneChunkSucceedsOneChunkFails_ReturnsNotQueriedWithGatheredFindings()
    {
        var batchCall = 0;
        var handler = new StubHttpMessageHandler((req, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.EndsWith("/querybatch", StringComparison.Ordinal))
            {
                batchCall++;
                // First chunk completes with a vuln for query[0]; the second chunk hard-fails (5xx).
                return batchCall == 1
                    ? Ok(BatchOneVulnThenClean)
                    : new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }
            return Ok(DetailJson);
        });
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var queries = new OsvQuery[1001];
        queries[0] = new OsvQuery("VulnPkg", "1.0.0", IsDependency: false);
        for (var i = 1; i < queries.Length; i++)
            queries[i] = new OsvQuery($"Clean{i}", "1.0.0", IsDependency: false);

        var result = await client.QueryAsync(queries);

        Assert.Equal(2, batchCall);         // both chunks were attempted
        Assert.False(result.Queried);       // a chunk failed => the overall check is incomplete
        var finding = Assert.Single(result.Findings);   // but the first chunk's finding is still returned
        Assert.Equal("GHSA-vvvv-vvvv-vvvv", finding.Id);
        Assert.Equal("VulnPkg", finding.PackageId);
    }

    // A detail GET failing (non-success) while the querybatch succeeds still yields an id-only finding attributed to
    // the queried package — the vuln is never dropped just because enrichment was unavailable.
    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task QueryAsync_DetailFetchNonSuccess_RetainsIdOnlyFinding(HttpStatusCode status)
    {
        var handler = new StubHttpMessageHandler((req, _) =>
            Route(req, BatchOneVulnThenClean, _ => new HttpResponseMessage(status)));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[]
        {
            new OsvQuery("VulnPkg", "1.0.0", false),
            new OsvQuery("CleanPkg", "2.0.0", true),
        });

        Assert.True(result.Queried);   // a per-id DETAIL failure does NOT flip Queried — the ID set is complete
        var finding = Assert.Single(result.Findings);
        Assert.Equal("GHSA-vvvv-vvvv-vvvv", finding.Id);
        Assert.Equal("VulnPkg", finding.PackageId);
        Assert.Equal("1.0.0", finding.PackageVersion);
        Assert.Empty(finding.Aliases);
        Assert.Null(finding.Summary);
        Assert.Null(finding.Severity);
        Assert.Empty(finding.References);
    }

    // A detail GET returning malformed JSON is likewise degraded to an id-only finding, not a throw or a drop.
    [Fact]
    public async Task QueryAsync_DetailFetchMalformedJson_RetainsIdOnlyFinding()
    {
        var handler = new StubHttpMessageHandler((req, _) =>
            Route(req, BatchOneVulnThenClean, _ => Ok("{ not valid json ")));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[] { new OsvQuery("VulnPkg", "1.0.0", false) });

        Assert.True(result.Queried);   // detail malformed-JSON degrades to id-only but leaves Queried true
        var finding = Assert.Single(result.Findings);
        Assert.Equal("GHSA-vvvv-vvvv-vvvv", finding.Id);
        Assert.Null(finding.Summary);
        Assert.Null(finding.Severity);
        Assert.Empty(finding.Aliases);
    }

    // A cancelled token is honored (not swallowed): it propagates as OperationCanceledException.
    [Fact]
    public async Task QueryAsync_WhenCancelled_PropagatesCancellation()
    {
        var handler = new StubHttpMessageHandler((_, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            return Ok(BatchOneVulnThenClean);
        });
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.QueryAsync(new[] { new OsvQuery("VulnPkg", "1.0.0", false) }, cts.Token));
    }

    // An HttpClient timeout surfaces as a TaskCanceledException while the caller's token is NOT cancelled — the
    // client treats that as "unavailable": empty findings AND Queried=false, per the LibrariesIo/GitHub precedent.
    [Fact]
    public async Task QueryAsync_TimeoutWithoutCancellation_ReturnsNotQueriedAndEmpty()
    {
        var handler = new StubHttpMessageHandler((_, _) => throw new TaskCanceledException("simulated HttpClient timeout"));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[] { new OsvQuery("VulnPkg", "1.0.0", false) }, CancellationToken.None);

        Assert.False(result.Queried);
        Assert.Empty(result.Findings);
    }

    // The outgoing querybatch request carries the required User-Agent and Accept headers. The batch returns a clean
    // result so the querybatch is the only request, and its captured headers can be asserted directly.
    [Fact]
    public async Task QueryAsync_QueryBatchRequest_SendsUserAgentAndAcceptHeaders()
    {
        string? userAgent = null, accept = null;
        HttpMethod? method = null;
        var handler = new StubHttpMessageHandler((req, _) =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("/querybatch", StringComparison.Ordinal))
            {
                method = req.Method;
                userAgent = req.Headers.UserAgent.ToString();
                accept = req.Headers.Accept.ToString();
            }
            return Ok(BatchAllClean);
        });
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(new[] { new OsvQuery("CleanPkg", "1.0.0", false) });

        Assert.True(result.Queried);    // a completed batch with no vulns is still Queried=true (truly clean)
        Assert.Empty(result.Findings);
        Assert.Equal(HttpMethod.Post, method);
        Assert.Contains("Silvergun", userAgent);
        Assert.Equal("application/json", accept);
    }

    // A null query list short-circuits to empty and sends no HTTP request — but Queried=true (nothing to check ≠ outage).
    [Fact]
    public async Task QueryAsync_NullQueries_ReturnsQueriedEmptyAndSendsNoRequest()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok(BatchAllClean));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(null!);

        Assert.True(result.Queried);   // nothing to check is a completed (clean) result, not a failure
        Assert.Empty(result.Findings);
        Assert.Equal(0, handler.CallCount);
    }

    // An empty query list short-circuits to empty and sends no HTTP request — but Queried=true (nothing to check ≠ outage).
    [Fact]
    public async Task QueryAsync_EmptyQueries_ReturnsQueriedEmptyAndSendsNoRequest()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok(BatchAllClean));
        var client = new OsvClient(new HttpClient(handler), baseUrl: "https://osv.test");

        var result = await client.QueryAsync(Array.Empty<OsvQuery>());

        Assert.True(result.Queried);
        Assert.Empty(result.Findings);
        Assert.Equal(0, handler.CallCount);
    }

    // JSON round-trip preserves every field, including populated alias/reference lists.
    [Fact]
    public void VulnerabilityFinding_JsonRoundTrip_PreservesAllPopulatedFields()
    {
        var original = new VulnerabilityFinding(
            Id: "GHSA-vvvv-vvvv-vvvv",
            Aliases: new[] { "CVE-2024-21907", "CVE-2024-99999" },
            Summary: "A heap-based buffer overflow.",
            Severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            PackageId: "VulnPkg",
            PackageVersion: "1.0.0",
            IsDependency: true,
            References: new[] { "https://example.test/advisory", "https://example.test/commit" });

        var restored = VulnerabilityFinding.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(original.Id, restored!.Id);
        Assert.Equal(original.Aliases, restored.Aliases);
        Assert.Equal(original.Summary, restored.Summary);
        Assert.Equal(original.Severity, restored.Severity);
        Assert.Equal(original.PackageId, restored.PackageId);
        Assert.Equal(original.PackageVersion, restored.PackageVersion);
        Assert.Equal(original.IsDependency, restored.IsDependency);
        Assert.Equal(original.References, restored.References);
    }

    // JSON round-trip preserves nullable fields as null and empty lists as empty.
    [Fact]
    public void VulnerabilityFinding_JsonRoundTrip_PreservesNullFieldsAndEmptyLists()
    {
        var original = new VulnerabilityFinding(
            Id: "GHSA-idonly",
            Aliases: Array.Empty<string>(),
            Summary: null,
            Severity: null,
            PackageId: "VulnPkg",
            PackageVersion: "1.0.0",
            IsDependency: false,
            References: Array.Empty<string>());

        var restored = VulnerabilityFinding.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal("GHSA-idonly", restored!.Id);
        Assert.Null(restored.Summary);
        Assert.Null(restored.Severity);
        Assert.Empty(restored.Aliases);
        Assert.Empty(restored.References);
        Assert.False(restored.IsDependency);
    }
    #endregion

    #region Helpers
    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json) };

    // Routes a request by the OSV endpoint shape: a POST to /v1/querybatch returns the given batch body; a GET to
    // /v1/vulns/{id} is delegated to the detail responder with the (unescaped) id.
    private static HttpResponseMessage Route(
        HttpRequestMessage req, string batchJson, Func<string, HttpResponseMessage> detail)
    {
        var path = req.RequestUri!.AbsolutePath;
        if (path.EndsWith("/querybatch", StringComparison.Ordinal))
            return Ok(batchJson);

        var id = Uri.UnescapeDataString(path[(path.LastIndexOf('/') + 1)..]);
        return detail(id);
    }
    #endregion

    #region Fields
    // results[0] carries one vuln id; results[1] is {} (no vulns) — aligned to the input query order.
    private const string BatchOneVulnThenClean = """
        { "results": [ { "vulns": [ { "id": "GHSA-vvvv-vvvv-vvvv", "modified": "2024-01-01T00:00:00Z" } ] },
                       {} ] }
        """;

    // Every result is clean ({}), so no detail fetch follows.
    private const string BatchAllClean = """{ "results": [ {} ] }""";

    // A representative /v1/vulns/{id} detail body (trimmed to the fields the client reads).
    private const string DetailJson = """
        {
          "id": "GHSA-vvvv-vvvv-vvvv",
          "aliases": [ "CVE-2024-21907" ],
          "summary": "A heap-based buffer overflow in VulnPkg.",
          "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ],
          "references": [ { "type": "ADVISORY", "url": "https://example.test/advisory/GHSA-vvvv-vvvv-vvvv" } ]
        }
        """;
    #endregion

    #region Types
    /// <summary>
    /// A hand-rolled <see cref="HttpMessageHandler"/> test double: every request is answered by the supplied
    /// <c>responder</c> (which may return a response or throw to simulate a transport failure), and honors
    /// cancellation before responding. Captures the last request URI and a running call count so tests can assert
    /// request shape and that no request was sent. No real network is ever contacted.
    /// </summary>
    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        #region Constructors
        public StubHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> responder) =>
            this.responder = responder;
        #endregion

        #region Methods
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            LastRequestUri = request.RequestUri;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(responder(request, cancellationToken));
        }
        #endregion

        #region Properties
        public Uri? LastRequestUri { get; private set; }
        public int CallCount { get; private set; }
        #endregion

        #region Fields
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> responder;
        #endregion
    }
    #endregion
}
