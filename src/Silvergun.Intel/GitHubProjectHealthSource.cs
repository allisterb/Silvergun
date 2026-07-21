namespace Silvergun.Intel;

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// A best-effort <see cref="IProjectHealthSource"/> over the GitHub REST API (ADR 0015). A single
/// <c>GET /repos/{owner}/{repo}</c> supplies every raw field, which <see cref="ProjectHealthScorer"/> turns into a
/// <see cref="ProjectHealth"/>. An optional token (<c>SILVERGUN_GITHUB_TOKEN</c> upstream) raises the rate limit
/// from 60/hr to 5000/hr; keyless works too. All I/O is wrapped: any non-success (404/403 rate-limit/5xx), transport
/// error, or malformed JSON is reported as <c>null</c> ("unavailable"), never thrown. The token is never logged.
/// </summary>
public sealed class GitHubProjectHealthSource : IProjectHealthSource
{
    #region Constructors
    /// <summary>
    /// Creates a source with an optional GitHub <paramref name="apiToken"/>. <paramref name="httpClient"/> and
    /// <paramref name="baseUrl"/> are injectable for testing (no real network in unit tests); they default to a
    /// fresh <see cref="HttpClient"/> against the public GitHub API.
    /// </summary>
    public GitHubProjectHealthSource(string? apiToken = null, HttpClient? httpClient = null, string? baseUrl = null)
    {
        this.apiToken = apiToken;
        http = httpClient ?? new HttpClient();
        this.baseUrl = (baseUrl ?? DefaultBaseUrl).TrimEnd('/');
    }
    #endregion

    #region Methods
    /// <summary>
    /// Looks up <paramref name="repo"/> via <c>GET {baseUrl}/repos/{owner}/{repo}</c> and maps the response into a
    /// scored <see cref="ProjectHealth"/>. Returns <c>null</c> on any failure (404/403/5xx/transport/malformed JSON).
    /// Never throws (except honoring cancellation); the token is never surfaced.
    /// </summary>
    public async Task<ProjectHealth?> GetHealthAsync(RepositoryRef repo, CancellationToken ct = default)
    {
        if (repo is null || string.IsNullOrWhiteSpace(repo.Owner) || string.IsNullOrWhiteSpace(repo.Repo))
            return null;

        try
        {
            var url = $"{baseUrl}/repos/{Uri.EscapeDataString(repo.Owner)}/{Uri.EscapeDataString(repo.Repo)}";

            // Per-request headers (never mutate a shared HttpClient's defaults, and never leak the token).
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd(UserAgent);   // GitHub rejects requests without a User-Agent.
            request.Headers.Accept.ParseAdd(AcceptMediaType);
            if (!string.IsNullOrWhiteSpace(apiToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return null;   // 404 (unknown), 403 (rate-limited), 5xx, etc. — all "unavailable".

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

            return Map(repo, doc.RootElement);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;   // a real cancellation propagates; an HttpClient timeout falls through to "unavailable".
        }
        catch
        {
            // Transport/parse failure ⇒ "unavailable". No detail (incl. the URL/token) is surfaced.
            return null;
        }
    }

    private static ProjectHealth Map(RepositoryRef repo, JsonElement root) =>
        ProjectHealthScorer.Score(
            repo,
            stars: TryGetInt(root, "stargazers_count"),
            forks: TryGetInt(root, "forks_count"),
            subscribers: TryGetInt(root, "subscribers_count"),
            watchers: TryGetInt(root, "watchers_count"),
            openIssues: TryGetInt(root, "open_issues_count"),
            sizeKb: TryGetInt(root, "size"),
            createdAt: TryGetDate(root, "created_at"),
            pushedAt: TryGetDate(root, "pushed_at"),
            license: TryGetLicense(root),
            archived: TryGetBool(root, "archived"),
            disabled: TryGetBool(root, "disabled"),
            hasIssues: TryGetBool(root, "has_issues"),
            defaultBranch: TryGetString(root, "default_branch"),
            now: DateTimeOffset.UtcNow);

    // The license object may be JSON null; its spdx_id is "NOASSERTION" for unrecognized licenses — treated as none.
    private static string? TryGetLicense(JsonElement root)
    {
        if (!root.TryGetProperty("license", out var lic) || lic.ValueKind != JsonValueKind.Object)
            return null;
        var id = TryGetString(lic, "spdx_id") ?? TryGetString(lic, "name");
        return string.Equals(id, "NOASSERTION", StringComparison.OrdinalIgnoreCase) ? null : id;
    }

    private static int? TryGetInt(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var i)
                ? i
                : null;

    private static bool TryGetBool(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.True;

    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;

    private static DateTimeOffset? TryGetDate(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            && value.TryGetDateTimeOffset(out var dt)
                ? dt
                : null;
    #endregion

    #region Fields
    private const string DefaultBaseUrl = "https://api.github.com";
    private const string UserAgent = "Silvergun";
    private const string AcceptMediaType = "application/vnd.github+json";

    private readonly string? apiToken;
    private readonly HttpClient http;
    private readonly string baseUrl;
    #endregion
}
