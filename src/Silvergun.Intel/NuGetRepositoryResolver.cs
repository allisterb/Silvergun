namespace Silvergun.Intel;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using global::NuGet.Common;
using global::NuGet.Protocol;
using global::NuGet.Protocol.Core.Types;

/// <summary>
/// Best-effort resolution of a NuGet package id to its source <see cref="RepositoryRef"/> for the <c>health</c> verb
/// (ADR 0015). Fetches nuget.org package metadata via <c>NuGet.Protocol</c>'s
/// <see cref="PackageMetadataResource.GetMetadataAsync(string,bool,bool,SourceCacheContext,ILogger,CancellationToken)"/>,
/// then parses the newest version's <see cref="IPackageSearchMetadata.ProjectUrl"/> through
/// <see cref="GitHubRepoUrl.TryParse"/>. Only GitHub is resolved in v1; anything else (or any lookup failure) yields
/// <c>null</c> ("unavailable"). Mirrors <see cref="NuGetPopularitySource"/>: all network I/O is wrapped and never thrown.
/// </summary>
public sealed class NuGetRepositoryResolver
{
    #region Constructors
    /// <summary>Creates a resolver against <paramref name="feedUrl"/> (defaults to the public nuget.org V3 feed).</summary>
    public NuGetRepositoryResolver(string? feedUrl = null)
    {
        repository = Repository.Factory.GetCoreV3(feedUrl ?? NuGetV3Feed);
    }
    #endregion

    #region Methods
    /// <summary>
    /// Returns the GitHub <see cref="RepositoryRef"/> declared by <paramref name="packageId"/>'s nuget.org metadata,
    /// or <c>null</c> when no github repository can be resolved (non-github host, no project URL, package absent, or
    /// any lookup failure). Never throws (except honoring cancellation).
    /// </summary>
    public async Task<RepositoryRef?> ResolveAsync(string packageId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(packageId))
            return null;

        try
        {
            var metadataResource = await repository.GetResourceAsync<PackageMetadataResource>(ct);
            if (metadataResource is null)
                return null;

            using var cache = new SourceCacheContext();
            var metadata = await metadataResource.GetMetadataAsync(
                packageId, includePrerelease: true, includeUnlisted: false, cache, NullLogger.Instance, ct);

            // Prefer the newest version's ProjectUrl, but fall back through older versions if a newer one is missing it.
            var candidates = metadata
                .OrderByDescending(m => m.Identity.Version)
                .Select(m => m.ProjectUrl?.ToString());

            foreach (var url in candidates)
                if (GitHubRepoUrl.TryParse(url, out var repo))
                    return repo;

            return null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Any feed/transport/parse failure is treated as "unavailable" — the caller reports no resolved repo.
            return null;
        }
    }
    #endregion

    #region Fields
    private const string NuGetV3Feed = "https://api.nuget.org/v3/index.json";

    private readonly SourceRepository repository;
    #endregion
}
