namespace Silvergun.MCPServer.Jobs;

using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using NuGet.Packaging;
using NuGet.Versioning;

using Silvergun.Intel;

/// <summary>Where a downloaded package came from (task S5): written by the server, one file per id and version.</summary>
public sealed record NuGetSource(int Schema, string Id, string Version, string Sha256, long Bytes, string Url, DateTimeOffset FetchedAt);

/// <summary>
/// <c>analyze_package {id, version}</c> (task S5): checks the identity, finds nuget.org's flat container through its service
/// index, and streams the <c>.nupkg</c> into <c>incoming/</c> while hashing it, capped at
/// <see cref="PackageInput.MaxPackageBytes"/> and <see cref="Deadline"/>. <c>&lt;cache&gt;/nuget/&lt;sha256(id/version)&gt;.json</c>
/// records each download, so a repeat request whose entry is complete sends nothing. Problems are values.
/// </summary>
public static class NuGetDownload
{
    #region Methods
    /// <summary>The lowercased id and normalized, lowercased version (no build metadata), or why they are not acceptable.</summary>
    public static (string? Id, string? Version, string? Problem) Check(string? id, string? version)
    {
        // ASCII only: the validator's \w takes Unicode letters and marks, homoglyphs included (S5 review S6).
        if (string.IsNullOrWhiteSpace(id) || id.Length > MaxIdChars || !id.Trim().All(char.IsAscii) || !PackageIdValidator.IsValidPackageId(id.Trim()))
            return (null, null, $"id is not a valid NuGet package id (letters, digits, '.', '-', '_'; at most {MaxIdChars} chars)");
        if (string.IsNullOrWhiteSpace(version) || version.Length > MaxVersionChars || !NuGetVersion.TryParse(version.Trim(), out var parsed))
            return (null, null, "version is not a valid NuGet version");
        return (id.Trim().ToLowerInvariant(), parsed.ToNormalizedString().Split('+')[0].ToLowerInvariant(), null);
    }

    /// <summary>The recorded download of <paramref name="id"/> <paramref name="version"/> (both from <see cref="Check"/>), or null.</summary>
    public static NuGetSource? Recorded(string cacheRoot, string id, string version)
    {
        var (bytes, _) = JobArtifacts.ReadBounded(RecordPath(cacheRoot, id, version), MaxRecordBytes);
        try
        {
            return bytes is not null && JsonSerializer.Deserialize<NuGetSource>(bytes, JobProtocol.JsonOptions) is { } s
                && s.Schema == RecordSchema && s.Id == id && s.Version == version && s.Sha256 is not null && sha.IsMatch(s.Sha256) && s.Bytes > 0 && s.Url is not null
                ? s : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Records a download (best effort: without it, the next request downloads again).</summary>
    public static void Record(string cacheRoot, NuGetSource source)
    {
        try
        {
            var dir = Path.Combine(cacheRoot, RecordDir);
            JobStore.CreatePrivate(dir);
            JobArtifacts.WriteAtomic(dir, Path.GetFileName(RecordPath(cacheRoot, source.Id, source.Version)), JsonSerializer.SerializeToUtf8Bytes(source, JobProtocol.JsonOptions));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Runtime.Warn("mcp: could not record a download ({0}).", ex.GetType().Name);
        }
    }

    /// <summary>Downloads the package to <paramref name="destination"/>: its source, or the status and why not. The destination is deleted on failure.</summary>
    /// <remarks><paramref name="index"/>: a client whose service index is already cached; by default a fresh one on <paramref name="http"/>.</remarks>
    public static async Task<(NuGetSource? Source, ToolStatus Status, string? Problem)> FetchAsync(HttpClient http, PoliteHttpHandler? polite, string id, string version,
        string destination, CancellationToken ct, string? serviceIndexUrl = null, NuGetSearchClient? index = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(Deadline);
        var succeeded = false;
        try
        {
            var result = await DownloadAsync();
            succeeded = result.Item1 is not null;
            return result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (null, ToolStatus.Failed, $"the download did not finish within {Deadline.TotalSeconds:0} s");
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            return (null, ToolStatus.Failed, $"the download failed ({ex.GetType().Name})");
        }
        finally
        {
            // Every way out but success, cancellation included, leaves no partial package in incoming/ (S5 review W6).
            if (!succeeded)
                try { File.Delete(destination); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* incoming/ is swept later */ }
        }

        async Task<(NuGetSource?, ToolStatus, string?)> DownloadAsync()
        {
            var baseAddress = await (index ?? new NuGetSearchClient(http, serviceIndexUrl)).ResourceAsync(NuGetSearchClient.PackageBaseAddressType, deadline.Token);
            if (baseAddress is null)
                return Refused(polite, "nuget.org's service index could not be read or names no package download address");
            var url = new Uri(baseAddress.AbsoluteUri.TrimEnd('/') + $"/{id}/{version}/{id}.{version}.nupkg");

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd(NuGetSearchClient.UserAgent);
            request.Options.Set(PoliteHttpHandler.MaxResponseBytesOption, PackageInput.MaxPackageBytes);
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return (null, ToolStatus.NotFound, $"nuget.org has no package {id} {version}");
            if (!response.IsSuccessStatusCode)
                return Refused(polite, $"nuget.org answered {(int)response.StatusCode}");

            await using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.SequentialScan))
            {
                var buffer = new byte[1024 * 1024];
                int read;
                while ((read = await input.ReadAsync(buffer, deadline.Token)) > 0)
                {
                    total += read;
                    hash.AppendData(buffer.AsSpan(0, read));
                    await output.WriteAsync(buffer.AsMemory(0, read), deadline.Token);
                }
                await output.FlushAsync(deadline.Token);
            }
            return total < MinPackageBytes
                ? Fail(ToolStatus.Failed, "nuget.org sent too few bytes to be a package")
                : (new NuGetSource(RecordSchema, id, version, Convert.ToHexStringLower(hash.GetHashAndReset()), total, url.AbsoluteUri, DateTimeOffset.UtcNow), ToolStatus.Succeeded, null);
        }

        // The finally above deletes the destination.
        static (NuGetSource?, ToolStatus, string?) Fail(ToolStatus status, string why) => (null, status, why);

        static (NuGetSource?, ToolStatus, string?) Refused(PoliteHttpHandler? handler, string why) =>
            Fail(ToolStatus.Failed, handler?.Refusals is { Count: > 0 } r
                ? $"{why}; {r[^1].Host} refused a request ({r[^1].Why}), so this server sends it nothing more until it restarts"
                : handler?.Refused(NuGetHost) == true
                ? $"{why}; {NuGetHost} refused an earlier job's request, so this server sends it nothing more until it restarts"
                : why);
    }

    private static string RecordPath(string cacheRoot, string id, string version) =>
        Path.Combine(cacheRoot, RecordDir, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(id + "/" + version))) + ".json");
    #endregion

    #region Fields
    public static readonly TimeSpan Deadline = TimeSpan.FromSeconds(50);

    private const int RecordSchema = 1;
    private const int MaxIdChars = 100;
    private const int MaxVersionChars = 64;
    private const long MaxRecordBytes = 4096;
    private const long MinPackageBytes = 22;
    private const string RecordDir = "nuget";
    private const string NuGetHost = "api.nuget.org";

    private static readonly Regex sha = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    #endregion
}
