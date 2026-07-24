namespace Silvergun.Intel;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using global::NuGet.Versioning;

/// <summary>
/// Fetches, for one package id and requested version range, the concrete version resolver-lite should use plus that
/// version's declared dependency ids and ranges. Returns <c>null</c> when the package/version cannot be obtained
/// (feed unreachable, package or version absent, no satisfying version). Implementations MUST never throw except to
/// honor cancellation (the <see cref="NuGetRepositoryResolver"/> precedent), so the resolver can degrade honestly.
/// </summary>
public interface IPackageDependencyFetcher
{
    #region Methods
    /// <summary>
    /// Resolves <paramref name="id"/> against <paramref name="range"/> to a concrete version and its declared
    /// dependencies, or <c>null</c> when unresolvable. Never throws except honoring <paramref name="ct"/>.
    /// </summary>
    Task<FetchedPackage?> GetAsync(string id, VersionRange range, CancellationToken ct = default);
    #endregion
}

/// <summary>
/// The concrete version chosen for a package plus its declared dependencies (the union of all dependency groups /
/// target-framework groups, deduped by id — an over-approximation since a package scan has no project TFM context).
/// </summary>
public sealed record FetchedPackage(
    string Id, string Version, IReadOnlyList<(string Id, VersionRange Range)> Dependencies);
