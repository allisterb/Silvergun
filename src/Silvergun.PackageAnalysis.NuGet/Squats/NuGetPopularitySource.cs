namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using global::NuGet.Common;
using global::NuGet.Protocol;
using global::NuGet.Protocol.Core.Types;

/// <summary>
/// A best-effort <see cref="IPackagePopularitySource"/> over <c>NuGet.Protocol</c>. Total download counts come from
/// the feed's search metadata (<see cref="IPackageSearchMetadata.DownloadCount"/>), queried with an exact
/// <c>packageid:</c> term against <c>https://api.nuget.org/v3/index.json</c> (overridable). All network I/O is
/// wrapped: any failure — or a package not present on the feed — is reported as <c>null</c> ("unknown"), never thrown.
/// </summary>
public sealed class NuGetPopularitySource : IPackagePopularitySource
{
    #region Constructors
    /// <summary>Creates a source against <paramref name="feedUrl"/> (defaults to the public nuget.org V3 feed).</summary>
    public NuGetPopularitySource(string? feedUrl = null)
    {
        repository = Repository.Factory.GetCoreV3(feedUrl ?? NuGetV3Feed);
    }
    #endregion

    #region Methods
    /// <summary>
    /// Returns the total download count for <paramref name="packageId"/>, or <c>null</c> if it is not on the feed
    /// or any lookup step fails. Never throws (except honoring cancellation).
    /// </summary>
    public async Task<long?> GetDownloadCountAsync(string packageId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(packageId))
            return null;

        try
        {
            var search = await repository.GetResourceAsync<PackageSearchResource>(ct);
            if (search is null)
                return null;

            var results = await search.SearchAsync(
                $"packageid:{packageId}",
                new SearchFilter(includePrerelease: true),
                skip: 0,
                take: 20,
                NullLogger.Instance,
                ct);

            var match = results.FirstOrDefault(r =>
                string.Equals(r.Identity.Id, packageId, StringComparison.OrdinalIgnoreCase));

            return match?.DownloadCount;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Any feed/transport/parse failure is treated as "unknown" — the checker skips it.
            return null;
        }
    }
    #endregion

    #region Fields
    private const string NuGetV3Feed = "https://api.nuget.org/v3/index.json";

    private readonly SourceRepository repository;
    #endregion
}
