namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="GitHubProjectHealthSource"/> (ADR 0015 / task
/// <c>docs/agent/tasks/project-health-intel.md</c>, Phase 1). All I/O is served by an injected stub
/// <see cref="HttpMessageHandler"/> — there is never a real network call. Covers the happy path (raw fields
/// mapped and scored), every failure mode collapsing to <c>null</c> (404, 403 rate-limit, 5xx, malformed JSON,
/// transport exception, non-cancellation timeout), cancellation propagation, request shape (<c>User-Agent</c>,
/// <c>Accept</c>, and <c>Authorization</c> only when a token is supplied), and the invariant that the token
/// never leaks into the returned report.
/// </summary>
public sealed class GitHubProjectHealthSourceTests
{
    #region Methods
    // Happy path — a representative /repos body populates every raw field and yields sensible, in-range scores.
    // Popularity is asserted exactly (huge stars ⇒ clamped 100, independent of the wall clock); activity/maturity
    // depend on DateTimeOffset.UtcNow inside the source, so they are only range-checked.
    [Fact]
    public async Task GetHealthAsync_SuccessBody_MapsRawFieldsAndScores()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok(RepoJson));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        var health = await source.GetHealthAsync(Repo);

        Assert.NotNull(health);
        Assert.Equal(Repo, health!.Repository);
        Assert.Equal(50_000, health.Stars);
        Assert.Equal(8_000, health.Forks);
        Assert.Equal(1_200, health.Subscribers);
        Assert.Equal(50_000, health.Watchers);
        Assert.Equal(500, health.OpenIssues);
        Assert.Equal(24_000, health.SizeKb);
        Assert.Equal("MIT", health.License);
        Assert.False(health.Archived);
        Assert.False(health.Disabled);
        Assert.True(health.HasIssues);
        Assert.Equal("main", health.DefaultBranch);
        Assert.NotNull(health.CreatedAt);
        Assert.NotNull(health.PushedAt);

        Assert.Equal(100, health.PopularityScore);
        Assert.InRange(health.ActivityScore, 0, 100);
        Assert.InRange(health.MaturityScore, 0, 100);
        Assert.InRange(health.OverallScore, 0, 100);

        // Flags that are independent of the clock: licensed + not abandoned ⇒ none of these are present.
        Assert.DoesNotContain("archived", health.RedFlags);
        Assert.DoesNotContain("disabled", health.RedFlags);
        Assert.DoesNotContain("no license", health.RedFlags);
    }

    // The request targets GET {baseUrl}/repos/{owner}/{repo}.
    [Fact]
    public async Task GetHealthAsync_IssuesGetToReposEndpoint()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok(RepoJson));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler), baseUrl: "https://api.github.com");

        await source.GetHealthAsync(Repo);

        Assert.NotNull(handler.LastRequestUri);
        Assert.Equal("https://api.github.com/repos/dotnet/runtime", handler.LastRequestUri!.AbsoluteUri);
    }

    // A 404 (unknown repo) collapses to null — never throws.
    [Fact]
    public async Task GetHealthAsync_NotFound_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => new HttpResponseMessage(HttpStatusCode.NotFound));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        Assert.Null(await source.GetHealthAsync(Repo));
    }

    // A 403 (rate-limit exhausted) collapses to null — never throws.
    [Fact]
    public async Task GetHealthAsync_RateLimited403_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Forbidden));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        Assert.Null(await source.GetHealthAsync(Repo));
    }

    // A 5xx (server error) collapses to null — never throws.
    [Fact]
    public async Task GetHealthAsync_ServerError_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        Assert.Null(await source.GetHealthAsync(Repo));
    }

    // Malformed JSON in a 200 body collapses to null — the parse failure is swallowed.
    [Fact]
    public async Task GetHealthAsync_MalformedJson_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => Ok("{ not valid json "));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        Assert.Null(await source.GetHealthAsync(Repo));
    }

    // A transport-level exception (e.g. DNS/socket failure) collapses to null — never propagates.
    [Fact]
    public async Task GetHealthAsync_TransportException_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => throw new HttpRequestException("simulated socket failure"));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        Assert.Null(await source.GetHealthAsync(Repo));
    }

    // An HttpClient timeout surfaces as a TaskCanceledException while the caller's token is NOT cancelled — the
    // source treats that as "unavailable" (null), per the LibrariesIo precedent.
    [Fact]
    public async Task GetHealthAsync_TimeoutWithoutCancellation_ReturnsNull()
    {
        var handler = new StubHttpMessageHandler((_, _) => throw new TaskCanceledException("simulated HttpClient timeout"));
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        Assert.Null(await source.GetHealthAsync(Repo, CancellationToken.None));
    }

    // Cancellation is honored (not swallowed): a cancelled token propagates as OperationCanceledException.
    [Fact]
    public async Task GetHealthAsync_WhenCancelled_PropagatesCancellation()
    {
        var handler = new StubHttpMessageHandler((_, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            return Ok(RepoJson);
        });
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.GetHealthAsync(Repo, cts.Token));
    }

    // Request headers: GitHub requires a User-Agent, and the source asks for the v3 JSON media type. With no
    // token there is no Authorization header.
    [Fact]
    public async Task GetHealthAsync_NoToken_SendsUserAgentAndAcceptButNoAuthorization()
    {
        string? userAgent = null, accept = null, authorization = null;
        var handler = new StubHttpMessageHandler((req, _) =>
        {
            userAgent = req.Headers.UserAgent.ToString();
            accept = req.Headers.Accept.ToString();
            authorization = req.Headers.Authorization?.ToString();
            return Ok(RepoJson);
        });
        var source = new GitHubProjectHealthSource(httpClient: new HttpClient(handler));

        await source.GetHealthAsync(Repo);

        Assert.Contains("Silvergun", userAgent);
        Assert.Equal("application/vnd.github+json", accept);
        Assert.Null(authorization);
    }

    // When a token is supplied it is sent as a Bearer credential — and only then.
    [Fact]
    public async Task GetHealthAsync_WithToken_SendsBearerAuthorization()
    {
        string? authorization = null;
        var handler = new StubHttpMessageHandler((req, _) =>
        {
            authorization = req.Headers.Authorization?.ToString();
            return Ok(RepoJson);
        });
        var source = new GitHubProjectHealthSource(apiToken: "SECRET_TOKEN", httpClient: new HttpClient(handler));

        await source.GetHealthAsync(Repo);

        Assert.Equal("Bearer SECRET_TOKEN", authorization);
    }

    // The token is never surfaced: it must not appear anywhere in the returned report or its JSON.
    [Fact]
    public async Task GetHealthAsync_WithToken_NeverLeaksTokenIntoReport()
    {
        const string token = "ghp_SUPERSECRETTOKENVALUE";
        var handler = new StubHttpMessageHandler((_, _) => Ok(RepoJson));
        var source = new GitHubProjectHealthSource(apiToken: token, httpClient: new HttpClient(handler));

        var health = await source.GetHealthAsync(Repo);

        Assert.NotNull(health);
        Assert.DoesNotContain(token, health!.ToJson());
    }
    #endregion

    #region Helpers
    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json) };
    #endregion

    #region Fields
    private static readonly RepositoryRef Repo = new("github", "dotnet", "runtime");

    // A representative GitHub GET /repos/{owner}/{repo} body (trimmed to the fields the source reads).
    private const string RepoJson = """
        {
          "stargazers_count": 50000,
          "forks_count": 8000,
          "subscribers_count": 1200,
          "watchers_count": 50000,
          "open_issues_count": 500,
          "size": 24000,
          "created_at": "2011-03-01T00:00:00Z",
          "pushed_at": "2024-06-01T00:00:00Z",
          "license": { "spdx_id": "MIT", "name": "MIT License" },
          "archived": false,
          "disabled": false,
          "has_issues": true,
          "default_branch": "main"
        }
        """;
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
