namespace Silvergun.Intel;

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// A best-effort <see cref="IPackagePopularitySource"/> over the libraries.io API. Fills the stronger
/// <see cref="PackagePopularity.SourceRank"/> and <see cref="PackagePopularity.DependentsCount"/> axes (mapped from
/// the response's <c>rank</c> and <c>dependents_count</c>); downloads are not reliably exposed, so
/// <see cref="PackagePopularity.DownloadCount"/> is left <c>null</c>. Requires an API key (libraries.io is optional
/// intel: no key ⇒ this source is simply not selected). All I/O is wrapped: any transport/parse failure, 404, or
/// rate-limit (429) is reported as <c>null</c> ("unknown"), never thrown. The API key is never logged.
/// </summary>
public sealed class LibrariesIoPopularitySource : IPackagePopularitySource
{
    #region Constructors
    /// <summary>
    /// Creates a source with the libraries.io <paramref name="apiKey"/>. <paramref name="httpClient"/> and
    /// <paramref name="baseUrl"/> are injectable for testing (no real network in unit tests); both default to a
    /// fresh <see cref="HttpClient"/> against the public libraries.io API.
    /// </summary>
    public LibrariesIoPopularitySource(string apiKey, HttpClient? httpClient = null, string? baseUrl = null)
    {
        this.apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        http = httpClient ?? new HttpClient();
        this.baseUrl = (baseUrl ?? DefaultBaseUrl).TrimEnd('/');
    }
    #endregion

    #region Methods
    /// <summary>
    /// Looks up <paramref name="packageId"/> on the libraries.io NuGet platform and maps <c>rank</c> →
    /// <see cref="PackagePopularity.SourceRank"/> and <c>dependents_count</c> → <see cref="PackagePopularity.DependentsCount"/>.
    /// Returns <c>null</c> on any failure (404/429/transport/malformed JSON). Never throws (except honoring cancellation).
    /// </summary>
    public async Task<PackagePopularity?> GetPopularityAsync(string packageId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(packageId))
            return null;

        try
        {
            var url = $"{baseUrl}/NuGet/{Uri.EscapeDataString(packageId)}?api_key={Uri.EscapeDataString(apiKey)}";
            using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return null;   // 404 (unknown), 429 (rate-limited), etc. — all "unknown".

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

            var root = doc.RootElement;
            var rank = TryGetInt(root, "rank");
            var dependents = TryGetInt(root, "dependents_count");
            return new PackagePopularity(DownloadCount: null, SourceRank: rank, DependentsCount: dependents);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Transport/parse failure ⇒ "unknown". No detail (incl. the URL/key) is surfaced.
            return null;
        }
    }

    // Reads an optional non-negative integer property; absent/non-numeric ⇒ null.
    private static int? TryGetInt(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var i)
                ? i
                : null;
    #endregion

    #region Fields
    private const string DefaultBaseUrl = "https://libraries.io/api";

    private readonly string apiKey;
    private readonly HttpClient http;
    private readonly string baseUrl;
    #endregion
}
