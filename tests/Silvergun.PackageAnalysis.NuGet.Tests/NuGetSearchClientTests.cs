namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// <see cref="NuGetSearchClient"/> (MCP task S5): the service index (only https resources on <c>nuget.org</c> or a
/// <c>*.nuget.org</c> host are kept; an index over 1 MiB, malformed or not an object, is null), and exact-id and free-text
/// search parsing. It never throws except to honour cancellation. Every response comes from a fake handler (under the real
/// <see cref="PoliteHttpHandler"/> where the cap matters): there is never a real network call.
/// </summary>
public sealed class NuGetSearchClientTests
{
    #region Methods: service index
    [Fact]
    public async Task ResourceAsync_ReadsTheIndex_AndKeepsOnlyHttpsNuGetOrgResources()
    {
        var fake = Fake(Index(
            ("SearchQueryService", "http://azuresearch-usnc.nuget.org/query"),        // http: dropped
            ("SearchQueryService", "https://search.evil.test/query"),                 // another host: dropped
            ("SearchQueryService", "https://azuresearch-usnc.nuget.org/query"),       // the first kept one wins
            ("SearchQueryService", "https://azuresearch-ussc.nuget.org/query"),
            ("PackageBaseAddress/3.0.0", "https://api.nuget.org/v3-flatcontainer/"),
            ("RegistrationsBaseUrl", "https://nuget.org/reg/"),                        // the apex host is accepted
            ("OnlyElsewhere", "https://evilnuget.org/x"),                             // a suffix that is not a label
            ("OnlyElsewhere", "https://nuget.org.evil.test/x"),
            ("OnlyElsewhere", "ftp://api.nuget.org/x"),
            ("OnlyElsewhere", "not a url")));
        var client = new NuGetSearchClient(new HttpClient(fake));

        Assert.Equal(new Uri("https://azuresearch-usnc.nuget.org/query"), await client.ResourceAsync(NuGetSearchClient.SearchType));
        Assert.Equal(new Uri("https://api.nuget.org/v3-flatcontainer/"), await client.ResourceAsync(NuGetSearchClient.PackageBaseAddressType));
        Assert.Equal(new Uri("https://nuget.org/reg/"), await client.ResourceAsync("RegistrationsBaseUrl"));
        Assert.Null(await client.ResourceAsync("OnlyElsewhere"));
        Assert.Null(await client.ResourceAsync("Absent"));
        Assert.Equal(1, fake.Calls);   // the index is read once and cached
        Assert.Equal(new Uri(NuGetSearchClient.DefaultServiceIndex), fake.Urls.Single());
    }

    [Fact]
    public async Task ResourceAsync_UsesTheGivenIndexUrl_AndSendsTheUserAgentAndAccept()
    {
        HttpRequestMessage? seen = null;
        var fake = new Stub(r => { seen = r; return Json(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query"))); });
        var client = new NuGetSearchClient(new HttpClient(fake), "https://index.example.test/v3/index.json");

        await client.ResourceAsync(NuGetSearchClient.SearchType);

        Assert.Equal(new Uri("https://index.example.test/v3/index.json"), seen!.RequestUri);
        Assert.Contains(seen.Headers.UserAgent, p => p.Product?.Name == NuGetSearchClient.UserAgent);
        Assert.Contains(seen.Headers.Accept, a => a.MediaType == "application/json");
    }

    [Theory]
    [InlineData("{\"resources\":")]
    [InlineData("[]")]
    [InlineData("{\"resources\":{}}")]
    [InlineData("{\"version\":\"3.0.0\"}")]
    [InlineData("null")]
    [InlineData("")]
    public async Task ResourceAsync_AMalformedIndex_IsNull(string body)
    {
        var client = new NuGetSearchClient(new HttpClient(new Stub(_ => Json(body))));

        Assert.Null(await client.ResourceAsync(NuGetSearchClient.SearchType));
    }

    [Fact]
    public async Task ResourceAsync_ResourcesWithMissingOrNonStringFields_AreSkipped()
    {
        const string body = """
            {"resources":[{"@type":5,"@id":"https://api.nuget.org/a"},{"@id":"https://api.nuget.org/b"},{"@type":"T"},
              {"@type":"T","@id":7},"a string",{"@type":"T","@id":"https://api.nuget.org/ok"}]}
            """;
        var client = new NuGetSearchClient(new HttpClient(new Stub(_ => Json(body))));

        Assert.Equal(new Uri("https://api.nuget.org/ok"), await client.ResourceAsync("T"));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task ResourceAsync_ANonSuccessIndex_IsNull(HttpStatusCode status)
    {
        var client = new NuGetSearchClient(new HttpClient(new Stub(_ => new HttpResponseMessage(status) { Content = new StringContent(Index(("T", "https://api.nuget.org/x"))) })));

        Assert.Null(await client.ResourceAsync("T"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ResourceAsync_AnIndexOverOneMiB_IsNull_ThroughThePoliteHandler(bool declared)
    {
        // A valid index padded past 1 MiB: refused by its Content-Length, or while it is read.
        var body = Encoding.UTF8.GetBytes(Index(("T", "https://api.nuget.org/x")).TrimEnd('}') + ",\"pad\":\"" + new string('p', 1024 * 1024) + "\"}");
        var fake = new Stub(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = declared ? new ByteArrayContent(body) : new StreamContent(new NonSeekable(body)),
        });
        var client = new NuGetSearchClient(new HttpClient(new PoliteHttpHandler(fake, TimeSpan.Zero)));

        Assert.Null(await client.ResourceAsync("T"));
    }

    [Fact]
    public async Task ResourceAsync_AnIndexJustUnderOneMiB_IsRead()
    {
        var head = Index(("T", "https://api.nuget.org/x")).TrimEnd('}') + ",\"pad\":\"";
        var body = Encoding.UTF8.GetBytes(head + new string('p', 1024 * 1024 - head.Length - 2) + "\"}");
        Assert.Equal(1024 * 1024, body.Length);
        var client = new NuGetSearchClient(new HttpClient(new PoliteHttpHandler(new Stub(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }), TimeSpan.Zero)));

        Assert.Equal(new Uri("https://api.nuget.org/x"), await client.ResourceAsync("T"));
    }

    [Theory]
    [InlineData("https://nuget.org/x", true)]
    [InlineData("https://API.NuGet.ORG/x", true)]
    [InlineData("https://azuresearch-usnc.nuget.org/query", true)]
    [InlineData("http://api.nuget.org/x", false)]
    [InlineData("https://evilnuget.org/x", false)]
    [InlineData("https://nuget.org.evil.test/x", false)]
    [InlineData("https://nuget.org@evil.test/x", false)]
    public void IsNuGetOrgUrl_AcceptsOnlyHttpsOnNuGetOrgHosts(string url, bool expected) =>
        Assert.Equal(expected, NuGetSearchClient.IsNuGetOrgUrl(new Uri(url)));

    [Fact]
    public void IsNuGetOrgUrl_Null_IsFalse() => Assert.False(NuGetSearchClient.IsNuGetOrgUrl(null));
    #endregion

    #region Methods: search
    [Fact]
    public async Task SearchAsync_ParsesIdsAndDownloads_AndSendsTheQuery()
    {
        const string results = """
            {"totalHits":4,"data":[
              {"id":"Newtonsoft.Json","totalDownloads":5000000000},
              {"id":"NoDownloads"},
              {"id":"TextDownloads","totalDownloads":"many"},
              {"totalDownloads":7},
              {"id":12},
              "junk",
              {"id":"Fractional","totalDownloads":1.5}]}
            """;
        var fake = Fake(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")), results);
        var client = new NuGetSearchClient(new HttpClient(fake));

        var hits = await client.SearchAsync("newtonsoft json", 20);

        Assert.NotNull(hits);
        Assert.Equal(["Newtonsoft.Json", "NoDownloads", "TextDownloads", "Fractional"], hits!.Select(h => h.Id));
        Assert.Equal(5_000_000_000L, hits[0].TotalDownloads);
        Assert.Null(hits[1].TotalDownloads);
        Assert.Null(hits[2].TotalDownloads);
        Assert.Null(hits[3].TotalDownloads);
        var query = fake.Urls[^1];
        Assert.Equal("azuresearch-usnc.nuget.org", query.Host);
        Assert.Equal("/query", query.AbsolutePath);
        Assert.Contains("q=newtonsoft%20json", query.Query);
        Assert.Contains("take=20", query.Query);
        Assert.Contains("prerelease=true", query.Query);
        Assert.Contains("semVerLevel=2.0.0", query.Query);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(100, 100)]
    [InlineData(5000, 1000)]
    public async Task SearchAsync_TakeIsClamped(int take, int sent)
    {
        var fake = Fake(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")), """{"data":[]}""");
        var client = new NuGetSearchClient(new HttpClient(fake));

        Assert.Empty((await client.SearchAsync("x", take))!);
        Assert.Contains($"take={sent}&", fake.Urls[^1].Query);
    }

    [Theory]
    [InlineData("""{"totalHits":0}""")]
    [InlineData("""{"data":{}}""")]
    [InlineData("""[]""")]
    [InlineData("""{"data":[""")]
    public async Task SearchAsync_AMalformedResult_IsNull(string body)
    {
        var client = new NuGetSearchClient(new HttpClient(Fake(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")), body)));

        Assert.Null(await client.SearchAsync("x", 10));
    }

    [Fact]
    public async Task SearchAsync_WithNoSearchResource_IsNull_AndSendsOnlyTheIndexRequest()
    {
        var fake = Fake(Index(("SearchQueryService", "https://search.evil.test/query")), """{"data":[{"id":"x"}]}""");
        var client = new NuGetSearchClient(new HttpClient(fake));

        Assert.Null(await client.SearchAsync("x", 10));
        Assert.Equal(1, fake.Calls);
    }

    [Fact]
    public async Task ExactAsync_FindsTheHitCaseInsensitively_WithAPackageIdQuery()
    {
        var fake = Fake(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")),
            """{"data":[{"id":"Other.Pkg","totalDownloads":1},{"id":"MY.Package","totalDownloads":4321}]}""");
        var client = new NuGetSearchClient(new HttpClient(fake));

        var (ok, hit) = await client.ExactAsync("my.package");

        Assert.True(ok);
        Assert.Equal(new SearchHit("MY.Package", 4321), hit);
        Assert.Contains("q=packageid%3Amy.package", fake.Urls[^1].Query);
        Assert.Contains("take=1&", fake.Urls[^1].Query);
    }

    [Fact]
    public async Task ExactAsync_AnUnlistedId_IsOkWithNoHit()
    {
        var client = new NuGetSearchClient(new HttpClient(Fake(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")), """{"data":[{"id":"Near.Miss"}]}""")));

        Assert.Equal((true, (SearchHit?)null), await client.ExactAsync("my.package"));
    }

    [Fact]
    public async Task ExactAsync_AFailedSearch_IsNotOk()
    {
        var fake = new Stub(r => r.RequestUri!.Host == "api.nuget.org"
            ? Json(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")))
            : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var client = new NuGetSearchClient(new HttpClient(fake));

        Assert.Equal((false, (SearchHit?)null), await client.ExactAsync("my.package"));
    }
    #endregion

    #region Methods: failures and cancellation
    [Fact]
    public async Task ATransportFailureOrAClientTimeout_IsNull_NotAnException()
    {
        var failing = new NuGetSearchClient(new HttpClient(new Stub(_ => throw new HttpRequestException("socket"))));
        var timedOut = new NuGetSearchClient(new HttpClient(new Stub(_ => throw new TaskCanceledException("HttpClient timeout"))));

        Assert.Null(await failing.ResourceAsync("T"));
        Assert.Null(await failing.SearchAsync("x", 1));
        Assert.Null(await timedOut.ResourceAsync("T"));
        Assert.Equal((false, (SearchHit?)null), await timedOut.ExactAsync("x"));
    }

    [Fact]
    public async Task Cancellation_Propagates_FromTheIndexAndFromSearch()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var fake = Fake(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")), """{"data":[]}""");
        var client = new NuGetSearchClient(new HttpClient(fake));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ResourceAsync("T", cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.SearchAsync("x", 1, cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ExactAsync("x", cancelled.Token));

        // With the index cached, a search cancelled mid-request still propagates.
        Assert.NotNull(await client.SearchAsync("x", 1));
        using var mid = new CancellationTokenSource();
        var slow = new Stub(_ => Json(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query"))), async (r, ct) =>
        {
            if (r.RequestUri!.Host == "api.nuget.org")
                return Json(Index(("SearchQueryService", "https://azuresearch-usnc.nuget.org/query")));
            mid.Cancel();
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException("unreachable");
        });
        var midClient = new NuGetSearchClient(new HttpClient(slow));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => midClient.SearchAsync("x", 1, mid.Token));
    }
    #endregion

    #region Methods: helpers
    private static string Index(params (string Type, string Id)[] resources) =>
        "{\"version\":\"3.0.0\",\"resources\":[" + string.Join(",", resources.Select(r => $"{{\"@id\":\"{r.Id}\",\"@type\":\"{r.Type}\"}}")) + "]}";

    // The index from api.nuget.org; anything else answers `search`.
    private static Stub Fake(string index, string search = """{"data":[]}""") =>
        new(r => Json(r.RequestUri!.Host == "api.nuget.org" ? index : search));

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    #endregion

    #region Types
    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> respond, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? respondAsync = null)
        : HttpMessageHandler
    {
        public int Calls { get { lock (urls) return urls.Count; } }

        public Uri[] Urls { get { lock (urls) return [.. urls]; } }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (urls)
                urls.Add(request.RequestUri!);
            return respondAsync is null ? respond(request) : await respondAsync(request, cancellationToken);
        }

        private readonly System.Collections.Generic.List<Uri> urls = [];
    }

    private sealed class NonSeekable(byte[] bytes) : System.IO.MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }
    #endregion
}
