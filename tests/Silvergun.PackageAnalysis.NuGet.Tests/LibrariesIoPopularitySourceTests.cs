namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="LibrariesIoPopularitySource"/> (ADR 0011 / task
/// <c>docs/agent/tasks/intel-librariesio-source.md</c>). All I/O is served by an injected stub
/// <see cref="HttpMessageHandler"/> — there is never a real network call. Covers the happy path
/// (rank/dependents parsed, downloads left null), every failure mode collapsing to <c>null</c>
/// (404, 429, malformed JSON, transport exception), cancellation propagation, and request shape
/// (<c>api_key</c> present, package id URL-encoded).
/// </summary>
public sealed class LibrariesIoPopularitySourceTests
{
    #region Methods
    // Happy path — a representative libraries.io NuGet body maps rank => SourceRank and dependents_count =>
    // DependentsCount; downloads are not reliably exposed so DownloadCount stays null.
    [Fact]
    public async Task GetPopularityAsync_SuccessBody_ParsesRankAndDependentsAndLeavesDownloadsNull()
    {
        const string json = """
            { "name": "Newtonsoft.Json", "platform": "NuGet", "rank": 27, "dependents_count": 4211 }
            """;
        var handler = new StubHttpMessageHandler((_, _) => Ok(json));
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));

        var result = await source.GetPopularityAsync("Newtonsoft.Json");

        Assert.NotNull(result);
        Assert.Equal(27, result!.SourceRank);
        Assert.Equal(4211, result.DependentsCount);
        Assert.Null(result.DownloadCount);
    }

    // A 404 (unknown package) collapses to null — never throws.
    [Fact]
    public async Task GetPopularityAsync_NotFound_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => new HttpResponseMessage(HttpStatusCode.NotFound));
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));

        Assert.Null(await source.GetPopularityAsync("Does.Not.Exist"));
    }

    // A 429 (rate-limited) collapses to null — never throws.
    [Fact]
    public async Task GetPopularityAsync_RateLimited429_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => new HttpResponseMessage((HttpStatusCode)429));
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));

        Assert.Null(await source.GetPopularityAsync("Newtonsoft.Json"));
    }

    // Malformed JSON in a 200 body collapses to null — the parse failure is swallowed.
    [Fact]
    public async Task GetPopularityAsync_MalformedJson_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok("{ this is not valid json "));
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));

        Assert.Null(await source.GetPopularityAsync("Newtonsoft.Json"));
    }

    // A transport-level exception (e.g. DNS/socket failure) collapses to null — never propagates.
    [Fact]
    public async Task GetPopularityAsync_TransportException_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => throw new HttpRequestException("simulated socket failure"));
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));

        Assert.Null(await source.GetPopularityAsync("Newtonsoft.Json"));
    }

    // Cancellation is honored (not swallowed): a cancelled token propagates as OperationCanceledException.
    [Fact]
    public async Task GetPopularityAsync_WhenCancelled_PropagatesCancellation()
    {
        var handler = new StubHttpMessageHandler((_, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            return Ok("{}");
        });
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => source.GetPopularityAsync("Newtonsoft.Json", cts.Token));
    }

    // Request shape: the api_key is sent and the package id is URL-encoded (a space becomes %20, never a raw space).
    [Fact]
    public async Task GetPopularityAsync_SendsApiKeyAndUrlEncodesPackageId()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok("{}"));
        var source = new LibrariesIoPopularitySource("SECRET_KEY", new HttpClient(handler));

        await source.GetPopularityAsync("Some Package");

        var url = handler.LastRequestUri!.AbsoluteUri;
        Assert.Contains("api_key=SECRET_KEY", url);
        Assert.Contains("Some%20Package", url);
        Assert.DoesNotContain("Some Package", url);   // the raw (unencoded) id must not appear
    }

    // Missing/absent axes are tolerated: a body without rank/dependents parses to a non-null popularity with null axes.
    [Fact]
    public async Task GetPopularityAsync_BodyMissingAxes_ReturnsNonNullWithNullAxes()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok("""{ "name": "Foo", "platform": "NuGet" }"""));
        var source = new LibrariesIoPopularitySource("KEY", new HttpClient(handler));

        var result = await source.GetPopularityAsync("Foo");

        Assert.NotNull(result);
        Assert.Null(result!.SourceRank);
        Assert.Null(result.DependentsCount);
        Assert.Null(result.DownloadCount);
    }
    #endregion

    #region Helpers
    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json) };
    #endregion

    #region Types
    /// <summary>
    /// A hand-rolled <see cref="HttpMessageHandler"/> test double: every request is answered by the supplied
    /// <c>responder</c> (which may return a response or throw to simulate a transport failure), and honors
    /// cancellation before responding. Captures the last request URI so tests can assert request shape. No real
    /// network is ever contacted.
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
            LastRequestUri = request.RequestUri;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(responder(request, cancellationToken));
        }
        #endregion

        #region Properties
        public Uri? LastRequestUri { get; private set; }
        #endregion

        #region Fields
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> responder;
        #endregion
    }
    #endregion
}
