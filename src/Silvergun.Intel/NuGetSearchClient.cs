namespace Silvergun.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>One search result: a package id and its total downloads (null when the feed did not say).</summary>
public sealed record SearchHit(string Id, long? TotalDownloads);

/// <summary>
/// nuget.org's V3 service index and search over a caller's <see cref="HttpClient"/> (MCP task S5), so every request goes
/// through the caller's handler (<see cref="PoliteHttpHandler"/>). Resource URLs come from the service index, as the
/// protocol requires, and must be https on <c>nuget.org</c> or a <c>*.nuget.org</c> host. Never throws except to honour
/// cancellation: a failure is null.
/// </summary>
public sealed class NuGetSearchClient(HttpClient http, string? serviceIndexUrl = null)
{
    #region Methods
    /// <summary>The first <paramref name="type"/> resource's URL in the service index (cached for this client), or null.</summary>
    public async Task<Uri?> ResourceAsync(string type, CancellationToken ct = default)
    {
        var resources = await IndexAsync(ct);
        return resources?.FirstOrDefault(r => r.Type == type).Url;
    }

    /// <summary>The exact-id hit for <paramref name="packageId"/>: null when the search failed, a hit with null downloads when absent.</summary>
    public async Task<(bool Ok, SearchHit? Hit)> ExactAsync(string packageId, CancellationToken ct = default)
    {
        var hits = await SearchAsync("packageid:" + packageId, 1, ct);
        return hits is null ? (false, null) : (true, hits.FirstOrDefault(h => string.Equals(h.Id, packageId, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>Up to <paramref name="take"/> hits for <paramref name="query"/> (pre-release and SemVer 2 included), or null on failure.</summary>
    public async Task<IReadOnlyList<SearchHit>?> SearchAsync(string query, int take, CancellationToken ct = default)
    {
        if (await ResourceAsync(SearchType, ct) is not { } search)
            return null;
        var url = $"{search.AbsoluteUri}?q={Uri.EscapeDataString(query)}&take={Math.Clamp(take, 1, 1000)}&prerelease=true&semVerLevel=2.0.0";
        using var doc = await GetJsonAsync(url, ct);
        if (doc is null || doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            return null;
        return [.. data.EnumerateArray()
            .Where(d => d.ValueKind == JsonValueKind.Object && d.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
            .Select(d => new SearchHit(d.GetProperty("id").GetString()!,
                d.TryGetProperty("totalDownloads", out var n) && n.ValueKind == JsonValueKind.Number && n.TryGetInt64(out var downloads) ? downloads : null))];
    }

    /// <summary>Whether <paramref name="url"/> is one Silvergun accepts from nuget.org's index.</summary>
    public static bool IsNuGetOrgUrl(Uri? url) =>
        url is { Scheme: "https" } && (url.IdnHost.Equals("nuget.org", StringComparison.OrdinalIgnoreCase) || url.IdnHost.EndsWith(".nuget.org", StringComparison.OrdinalIgnoreCase));

    private async Task<IReadOnlyList<(string Type, Uri Url)>?> IndexAsync(CancellationToken ct)
    {
        if (index is not null)
            return index;
        using var doc = await GetJsonAsync(serviceIndexUrl ?? DefaultServiceIndex, ct, MaxIndexBytes);
        if (doc is null || doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("resources", out var resources) || resources.ValueKind != JsonValueKind.Array)
            return null;
        return index = [.. resources.EnumerateArray()
            .Where(r => r.ValueKind == JsonValueKind.Object)
            .Select(r => (Type: Text(r, "@type"), Id: Text(r, "@id")))
            .Where(r => r.Type is not null && Uri.TryCreate(r.Id, UriKind.Absolute, out var u) && IsNuGetOrgUrl(u))
            .Select(r => (r.Type!, new Uri(r.Id!)))];
    }

    private async Task<JsonDocument?> GetJsonAsync(string url, CancellationToken ct, long? maxBytes = null)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd(UserAgent);
            request.Headers.Accept.ParseAdd("application/json");
            if (maxBytes is { } max)
                request.Options.Set(PoliteHttpHandler.MaxResponseBytesOption, max);
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return null;
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            return await JsonDocument.ParseAsync(stream, new JsonDocumentOptions { MaxDepth = 32 }, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    #endregion

    #region Fields
    public const string DefaultServiceIndex = "https://api.nuget.org/v3/index.json";
    public const string SearchType = "SearchQueryService";
    public const string PackageBaseAddressType = "PackageBaseAddress/3.0.0";
    public const string UserAgent = "Silvergun";
    private const long MaxIndexBytes = 1024 * 1024;

    private IReadOnlyList<(string Type, Uri Url)>? index;
    #endregion
}
