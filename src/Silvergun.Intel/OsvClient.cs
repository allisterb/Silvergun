namespace Silvergun.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// A keyless, best-effort <see cref="IVulnerabilitySource"/> over the OSV.dev API (ADR 0017). A single
/// <c>POST /v1/querybatch</c> resolves every queried package@version to its vulnerability IDs (results aligned to the
/// input order); each unique ID is then enriched via <c>GET /v1/vulns/{id}</c> for aliases/summary/severity/references,
/// and attributed back to the package(s) whose query matched. Mirrors <see cref="LibrariesIoPopularitySource"/>/
/// <see cref="GitHubProjectHealthSource"/>: all I/O is wrapped — any non-success (404/429/5xx), transport error, or
/// malformed JSON degrades to the findings gathered so far, never thrown (except honoring cancellation). No API key.
/// </summary>
public sealed class OsvClient : IVulnerabilitySource
{
    #region Constructors
    /// <summary>
    /// Creates a client. <paramref name="httpClient"/> and <paramref name="baseUrl"/> are injectable for testing (no
    /// real network in unit tests); they default to a fresh <see cref="HttpClient"/> against the public OSV.dev API.
    /// </summary>
    public OsvClient(HttpClient? httpClient = null, string? baseUrl = null)
    {
        http = httpClient ?? new HttpClient();
        this.baseUrl = (baseUrl ?? DefaultBaseUrl).TrimEnd('/');
    }
    #endregion

    #region Methods
    /// <summary>
    /// Batches <paramref name="queries"/> to <c>/v1/querybatch</c>, dedupes the resulting vulnerability IDs, enriches
    /// each via <c>/v1/vulns/{id}</c>, and emits one <see cref="VulnerabilityFinding"/> per (vulnerability, matching
    /// query). Empty for a <c>null</c>/empty list; never throws (except honoring cancellation).
    /// </summary>
    public async Task<IReadOnlyList<VulnerabilityFinding>> QueryAsync(
        IReadOnlyList<OsvQuery> queries, CancellationToken ct = default)
    {
        if (queries is null || queries.Count == 0)
            return Array.Empty<VulnerabilityFinding>();

        // vuln id → the input query indices it was returned for (an id can match multiple packages).
        var idToQueries = new Dictionary<string, List<int>>(StringComparer.Ordinal);

        for (var offset = 0; offset < queries.Count; offset += ChunkSize)
        {
            var take = Math.Min(ChunkSize, queries.Count - offset);
            var chunk = queries.Skip(offset).Take(take).ToArray();

            // results[i] aligns to chunk[i] by index; a failed chunk yields empty and simply contributes nothing.
            var results = await QueryBatchAsync(chunk, ct);
            var aligned = Math.Min(results.Count, take);
            for (var i = 0; i < aligned; i++)
                foreach (var id in results[i])
                    (idToQueries.TryGetValue(id, out var idxs)
                        ? idxs
                        : idToQueries[id] = new List<int>()).Add(offset + i);
        }

        if (idToQueries.Count == 0)
            return Array.Empty<VulnerabilityFinding>();

        var findings = new List<VulnerabilityFinding>();
        foreach (var (id, indices) in idToQueries)
        {
            var detail = await FetchDetailAsync(id, ct);   // null ⇒ id-only finding (never dropped).
            findings.AddRange(indices.Select(idx =>
            {
                var q = queries[idx];
                return new VulnerabilityFinding(
                    id,
                    detail?.Aliases ?? Array.Empty<string>(),
                    detail?.Summary,
                    detail?.Severity,
                    q.PackageId,
                    q.Version,
                    q.IsDependency,
                    detail?.References ?? Array.Empty<string>());
            }));
        }

        return findings;
    }

    // POSTs a chunk to /v1/querybatch; returns the vuln IDs per query, aligned to chunk order. Empty on any failure.
    private async Task<IReadOnlyList<IReadOnlyList<string>>> QueryBatchAsync(
        IReadOnlyList<OsvQuery> chunk, CancellationToken ct)
    {
        try
        {
            var payload = new
            {
                queries = chunk.Select(q => new
                {
                    package = new { name = q.PackageId, ecosystem = Ecosystem },
                    version = q.Version
                }).ToArray()
            };

            using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/v1/querybatch") { Content = content };
            request.Headers.UserAgent.ParseAdd(UserAgent);
            request.Headers.Accept.ParseAdd(AcceptMediaType);

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return Array.Empty<IReadOnlyList<string>>();

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            return ParseBatchResults(doc.RootElement);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;   // a real cancellation propagates; an HttpClient timeout falls through to "empty".
        }
        catch
        {
            return Array.Empty<IReadOnlyList<string>>();
        }
    }

    // GETs /v1/vulns/{id} detail. Returns null on any failure so the caller can still emit an id-only finding.
    private async Task<VulnDetail?> FetchDetailAsync(string id, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/v1/vulns/{Uri.EscapeDataString(id)}");
            request.Headers.UserAgent.ParseAdd(UserAgent);
            request.Headers.Accept.ParseAdd(AcceptMediaType);

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return null;

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            return ParseDetail(doc.RootElement);
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

    // { "results": [ { "vulns": [ { "id", "modified" } ] } | { } , ... ] } → ids per result, aligned to input order.
    private static IReadOnlyList<IReadOnlyList<string>> ParseBatchResults(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("results", out var results)
            || results.ValueKind != JsonValueKind.Array)
            return Array.Empty<IReadOnlyList<string>>();

        var list = new List<IReadOnlyList<string>>(results.GetArrayLength());
        foreach (var result in results.EnumerateArray())
        {
            var ids = new List<string>();
            if (result.ValueKind == JsonValueKind.Object
                && result.TryGetProperty("vulns", out var vulns)
                && vulns.ValueKind == JsonValueKind.Array)
                foreach (var vuln in vulns.EnumerateArray())
                {
                    var id = TryGetString(vuln, "id");
                    if (!string.IsNullOrEmpty(id))
                        ids.Add(id);
                }
            list.Add(ids);
        }
        return list;
    }

    private static VulnDetail ParseDetail(JsonElement root) => new(
        Aliases: ReadStringArray(root, "aliases"),
        Summary: TryGetString(root, "summary"),
        Severity: ReadCvssV3Score(root),
        References: ReadReferenceUrls(root));

    // Raw CVSS v3 score string from the severity[] entry whose type == "CVSS_V3"; else null.
    private static string? ReadCvssV3Score(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("severity", out var arr)
            || arr.ValueKind != JsonValueKind.Array)
            return null;

        foreach (var entry in arr.EnumerateArray())
            if (string.Equals(TryGetString(entry, "type"), "CVSS_V3", StringComparison.Ordinal))
                return TryGetString(entry, "score");
        return null;
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement root, string property)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty(property, out var arr)
            || arr.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();

        var list = new List<string>(arr.GetArrayLength());
        foreach (var entry in arr.EnumerateArray())
            if (entry.ValueKind == JsonValueKind.String)
            {
                var s = entry.GetString();
                if (!string.IsNullOrEmpty(s))
                    list.Add(s);
            }
        return list;
    }

    // references[] are objects { "type", "url" }; project to the url strings.
    private static IReadOnlyList<string> ReadReferenceUrls(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("references", out var arr)
            || arr.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();

        var list = new List<string>(arr.GetArrayLength());
        foreach (var entry in arr.EnumerateArray())
        {
            var url = TryGetString(entry, "url");
            if (!string.IsNullOrEmpty(url))
                list.Add(url);
        }
        return list;
    }

    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
    #endregion

    #region Fields
    private const string DefaultBaseUrl = "https://api.osv.dev";
    private const string Ecosystem = "NuGet";
    private const string UserAgent = "Silvergun";
    private const string AcceptMediaType = "application/json";
    private const int ChunkSize = 1000;

    private readonly HttpClient http;
    private readonly string baseUrl;
    #endregion

    #region Child types
    // Enriched detail from /v1/vulns/{id}; a null instance represents a failed/absent detail fetch.
    private sealed record VulnDetail(
        IReadOnlyList<string> Aliases,
        string? Summary,
        string? Severity,
        IReadOnlyList<string> References);
    #endregion
}
