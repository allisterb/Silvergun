namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;

using global::NuGet.Versioning;

using Silvergun.Intel;

/// <summary>
/// Builds the OSV.dev query set (ADR 0017) for a scanned package: the package itself at its exact nuspec version
/// (<see cref="OsvQuery.IsDependency"/> <c>false</c>) plus each declared direct dependency at its version-range floor
/// (<see cref="VersionRange.MinVersion"/>, <c>IsDependency</c> <c>true</c>). Lives here (not in <c>Silvergun.Intel</c>)
/// so it can see <see cref="PackageIdentityInfo"/>; it depends on <c>NuGet.Versioning</c> for range parsing. Deps with
/// an unbounded/absent minimum or an unparseable range are skipped, and queries are deduped by (id, version) with a
/// case-insensitive id. Never throws.
/// </summary>
public static class OsvQueryBuilder
{
    #region Methods
    /// <summary>
    /// Projects <paramref name="package"/> to the OSV queries to run: the package@version plus each dependency at its
    /// resolvable range floor. Malformed/unbounded dependency ranges are skipped; the result is deduped and never throws.
    /// </summary>
    public static IReadOnlyList<OsvQuery> Build(PackageIdentityInfo package)
    {
        if (package is null)
            return Array.Empty<OsvQuery>();

        var queries = new List<OsvQuery>();
        var seen = new HashSet<(string Id, string Version)>(KeyComparer);

        void Add(string id, string version, bool isDependency)
        {
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(version))
                return;
            if (seen.Add((id, version)))
                queries.Add(new OsvQuery(id, version, isDependency));
        }

        Add(package.Id, package.Version, isDependency: false);

        foreach (var dep in package.Dependencies ?? Array.Empty<PackageDependencyInfo>())
        {
            var floor = ResolveFloor(dep.VersionRange);
            if (floor is not null)
                Add(dep.Id, floor, isDependency: true);
        }

        return queries;
    }

    // The normalized minimum-version string of a dependency's declared range, or null when the range is
    // unbounded-below, has no resolvable minimum, or fails to parse. Never throws.
    private static string? ResolveFloor(string? versionRange)
    {
        if (string.IsNullOrWhiteSpace(versionRange))
            return null;

        return VersionRange.TryParse(versionRange, out var range)
            ? range.MinVersion?.ToNormalizedString()
            : null;
    }
    #endregion

    #region Fields
    // Dedupe key comparer: case-insensitive package id (NuGet ids are case-insensitive), ordinal version.
    private static readonly IEqualityComparer<(string Id, string Version)> KeyComparer =
        new KeyEqualityComparer();
    #endregion

    #region Child types
    private sealed class KeyEqualityComparer : IEqualityComparer<(string Id, string Version)>
    {
        public bool Equals((string Id, string Version) x, (string Id, string Version) y) =>
            string.Equals(x.Id, y.Id, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Version, y.Version, StringComparison.Ordinal);

        public int GetHashCode((string Id, string Version) obj) =>
            HashCode.Combine(
                obj.Id.ToLowerInvariant(),
                obj.Version);
    }
    #endregion
}
