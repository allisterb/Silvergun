namespace Silvergun.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using global::NuGet.Common;
using global::NuGet.Packaging;
using global::NuGet.Packaging.Core;
using global::NuGet.Protocol;
using global::NuGet.Protocol.Core.Types;
using global::NuGet.Versioning;

/// <summary>
/// Live nuget.org <see cref="IPackageDependencyFetcher"/> over <c>NuGet.Protocol</c>'s
/// <see cref="PackageMetadataResource"/> (mirrors <see cref="NuGetRepositoryResolver"/>). For a requested range it
/// picks the <b>lowest listed version that satisfies the range</b> (what NuGet restore installs) and returns that
/// version's dependencies as the union of all dependency groups' packages, deduped by id. Returns <c>null</c> when the
/// package/version is absent, no version satisfies the range, or any lookup fails. Never throws except honoring
/// cancellation. This class is live-only (not unit-tested), matching the <see cref="NuGetRepositoryResolver"/> posture.
/// </summary>
public sealed class NuGetPackageDependencyFetcher : IPackageDependencyFetcher
{
    #region Constructors
    /// <summary>Creates a fetcher against <paramref name="feedUrl"/> (defaults to the public nuget.org V3 feed).</summary>
    public NuGetPackageDependencyFetcher(string? feedUrl = null)
    {
        repository = Repository.Factory.GetCoreV3(feedUrl ?? NuGetV3Feed);
    }
    #endregion

    #region Methods
    /// <summary>
    /// Returns the lowest listed version of <paramref name="id"/> satisfying <paramref name="range"/> plus its unioned,
    /// deduped dependency set, or <c>null</c> when unresolvable. Never throws (except honoring <paramref name="ct"/>).
    /// </summary>
    public async Task<FetchedPackage?> GetAsync(string id, VersionRange range, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(id) || range is null)
            return null;

        try
        {
            var metadataResource = await repository.GetResourceAsync<PackageMetadataResource>(ct);
            if (metadataResource is null)
                return null;

            using var cache = new SourceCacheContext();
            var metadata = await metadataResource.GetMetadataAsync(
                id, includePrerelease: true, includeUnlisted: false, cache, NullLogger.Instance, ct);

            // Lowest listed version satisfying the range (what NuGet restore would install; range decides prerelease).
            var chosen = metadata
                .Where(m => m.Identity?.Version is not null && range.Satisfies(m.Identity.Version))
                .OrderBy(m => m.Identity.Version)
                .FirstOrDefault();

            if (chosen is null)
                return null;

            // Union of all dependency-group packages, deduped by id (no project TFM context — an over-approximation).
            var dependencies = (chosen.DependencySets ?? Enumerable.Empty<PackageDependencyGroup>())
                .SelectMany(g => g.Packages ?? Enumerable.Empty<PackageDependency>())
                .Where(p => !string.IsNullOrWhiteSpace(p.Id) && p.VersionRange is not null)
                .GroupBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                .Select(g => (g.First().Id, g.First().VersionRange))
                .ToArray();

            return new FetchedPackage(chosen.Identity.Id, chosen.Identity.Version.ToNormalizedString(), dependencies);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Any feed/transport/parse failure is treated as unresolved — the resolver marks the result Partial.
            return null;
        }
    }
    #endregion

    #region Fields
    private const string NuGetV3Feed = "https://api.nuget.org/v3/index.json";

    private readonly SourceRepository repository;
    #endregion
}
