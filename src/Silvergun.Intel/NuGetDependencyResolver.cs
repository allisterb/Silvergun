namespace Silvergun.Intel;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using global::NuGet.Versioning;

/// <summary>
/// The pure, bounded, best-effort transitive dependency walk (resolver-lite, ADR 0018) over an
/// <see cref="IPackageDependencyFetcher"/>. This is a tractable <em>approximation</em>, deliberately <b>not</b> a
/// <c>dotnet restore</c>: version selection per range is the fetcher's lowest-satisfying pick, dependency groups are
/// unioned across target frameworks, and a package reached via multiple paths is unified to a single reported node
/// using a highest-wins conflict policy (a documented divergence from NuGet's nearest-wins — see <see cref="Unify"/>).
/// Subtree expansion is guarded by <b>(id, version)</b> (case-insensitive id, ordinal version), so each distinct
/// resolved <c>(id, version)</c> is expanded exactly once and an id reached at two versions has <em>both</em> closures
/// walked (spec rule 4). A finite number of distinct <c>(id, version)</c> pairs plus the depth cap guarantees
/// termination even with cycles. Because expansion is per-version but the reported node is unified per id to the single
/// highest version (rule 3), the resolved set <b>may include transitive deps of a superseded version</b> — intended
/// recall-over-precision behavior (ADR-0002), not a bug. The walk <b>never throws</b> except to honor cancellation:
/// any fetch that returns <c>null</c> or throws a non-cancellation exception degrades that node to unresolved and marks
/// the whole result <see cref="DependencyResolutionStatus.Partial"/> while resolution continues over the rest of the graph.
/// </summary>
public sealed class NuGetDependencyResolver
{
    #region Constructors
    /// <summary>Creates a resolver over <paramref name="fetcher"/> (the version/dependency data source).</summary>
    public NuGetDependencyResolver(IPackageDependencyFetcher fetcher)
    {
        this.fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    }
    #endregion

    #region Methods
    /// <summary>
    /// Walks the transitive graph from the root's declared <paramref name="directDependencies"/> (depth 1) up to
    /// <paramref name="maxDepth"/>. Subtree expansion is guarded per resolved <c>(id, version)</c> (case-insensitive id),
    /// so cycles terminate and an id reached at two versions has both closures walked; reported nodes are still unified
    /// per id to the single highest version (see <see cref="Unify"/>), so the resolved set may include transitive deps of
    /// a superseded version (intended recall-over-precision). <paramref name="maxDepth"/> &lt;= 0 yields
    /// <see cref="DependencyResolutionStatus.NotRun"/> and an empty set. Never throws except honoring
    /// <paramref name="ct"/>; any fetch failure yields <see cref="DependencyResolutionStatus.Partial"/>.
    /// </summary>
    public async Task<DependencyResolutionResult> ResolveAsync(
        IReadOnlyList<(string Id, VersionRange Range)> directDependencies,
        int maxDepth,
        CancellationToken ct = default)
    {
        if (maxDepth <= 0)
            return new DependencyResolutionResult(DependencyResolutionStatus.NotRun, Array.Empty<ResolvedDependency>());

        // Unified node per id (case-insensitive), the resolved (id, version) pairs whose subtree we've already expanded
        // (cycle / re-expansion guard — see rule 4), and the honesty flag flipped by any fetch failure.
        var resolved = new Dictionary<string, ResolvedDependency>(StringComparer.OrdinalIgnoreCase);
        var expanded = new HashSet<(string Id, string Version)>(KeyComparer);
        var complete = true;

        // Breadth-first so an id is first dequeued at its shallowest depth (where expansion decisions are made).
        var frontier = new Queue<(string Id, VersionRange Range, int Depth)>();
        // Dedupe seed ids (case-insensitive, first occurrence wins) so a duplicated seed id doesn't trigger a redundant
        // fetch. If two seeds share an id but differ in range, we keep it simple and drop the later range.
        var seenSeeds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, range) in directDependencies ?? Array.Empty<(string, VersionRange)>())
            if (!string.IsNullOrWhiteSpace(id) && range is not null && seenSeeds.Add(id))
                frontier.Enqueue((id, range, 1));

        while (frontier.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (id, range, depth) = frontier.Dequeue();

            FetchedPackage? fetched;
            try
            {
                fetched = await fetcher.GetAsync(id, range, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // A fetcher that throws (non-cancellation) degrades this node to unresolved (see class summary).
                complete = false;
                continue;
            }

            if (fetched is null)
            {
                complete = false;
                continue;
            }

            // Hostile-input guard: a malformed feed response could return a fetch with a null/blank id. The expansion-guard
            // key (KeyComparer.GetHashCode -> Id.ToLowerInvariant()) and unify below would NRE on it, so degrade this node
            // to unresolved exactly like the null-fetch path — never-throws must hold for all package/feed input.
            if (string.IsNullOrWhiteSpace(fetched.Id))
            {
                complete = false;
                continue;
            }

            var node = new ResolvedDependency(fetched.Id, fetched.Version, depth, IsDirect: depth == 1);
            resolved[id] = resolved.TryGetValue(id, out var existing) ? Unify(existing, node) : node;

            // Expand each resolved (id, version) subtree at most once — an id reached at two versions has both closures
            // walked (rule 4). Repeat encounters are still fetched above for cross-path unification.
            if (depth < maxDepth && expanded.Add((fetched.Id, fetched.Version)))
                foreach (var (childId, childRange) in fetched.Dependencies ?? Array.Empty<(string, VersionRange)>())
                    if (!string.IsNullOrWhiteSpace(childId) && childRange is not null)
                        frontier.Enqueue((childId, childRange, depth + 1));
        }

        var status = complete ? DependencyResolutionStatus.Complete : DependencyResolutionStatus.Partial;
        var ordered = resolved.Values
            .OrderBy(r => r.Depth)
            .ThenBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new DependencyResolutionResult(status, ordered);
    }

    /// <summary>
    /// Conflict-unification policy (spec rule 3 / ADR 0018), deliberately isolated so it can change without touching
    /// the walk: keep the <b>highest</b> resolved version as a close, order-independent proxy for NuGet's rule that no
    /// package resolves below the highest lower bound demanded anywhere in the graph. A documented divergence from
    /// NuGet's nearest-wins. Depth keeps the shallowest path seen (so a package that is also a direct dep stays direct).
    /// </summary>
    private static ResolvedDependency Unify(ResolvedDependency existing, ResolvedDependency candidate)
    {
        // Prefer the candidate when it parses and either the existing version doesn't (never keep an unparseable
        // version over a parseable one) or the candidate is strictly higher (highest-wins). Never throws.
        var version =
            NuGetVersion.TryParse(candidate.Version, out var c) &&
            (!NuGetVersion.TryParse(existing.Version, out var e) || c > e)
                ? candidate.Version
                : existing.Version;
        var depth = Math.Min(existing.Depth, candidate.Depth);
        return existing with { Version = version, Depth = depth, IsDirect = depth == 1 };
    }
    #endregion

    #region Fields
    private readonly IPackageDependencyFetcher fetcher;

    // Expansion-guard key comparer: case-insensitive package id (NuGet ids are case-insensitive), ordinal version.
    private static readonly IEqualityComparer<(string Id, string Version)> KeyComparer = new KeyEqualityComparer();
    #endregion

    #region Child types
    private sealed class KeyEqualityComparer : IEqualityComparer<(string Id, string Version)>
    {
        public bool Equals((string Id, string Version) x, (string Id, string Version) y) =>
            string.Equals(x.Id, y.Id, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Version, y.Version, StringComparison.Ordinal);

        public int GetHashCode((string Id, string Version) obj) =>
            HashCode.Combine(obj.Id.ToLowerInvariant(), obj.Version);
    }
    #endregion
}
