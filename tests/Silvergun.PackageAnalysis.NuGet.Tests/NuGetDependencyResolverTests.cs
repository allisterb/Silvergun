namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

using global::NuGet.Versioning;

/// <summary>
/// Unit tests for <see cref="NuGetDependencyResolver.ResolveAsync"/> (resolver-lite, ADR 0018 / task
/// <c>docs/agent/tasks/resolver-lite-transitive-dependencies.md</c>, Phase 1). The resolver is driven entirely by an
/// in-memory fake <see cref="IPackageDependencyFetcher"/> (<see cref="FakeDependencyFetcher"/>) that declares a small
/// dependency graph and picks the lowest listed version satisfying each requested range — there is never a network
/// call. Tests assert the documented algorithm and invariants: depth-1/IsDirect direct deps vs deeper transitive nodes,
/// linear-chain expansion to maxDepth, maxDepth pruning (via the fake's request log), cycle termination, highest-wins
/// version unification to a single node per id, that the fetcher's chosen version is carried through verbatim, that a
/// unioned dependency list is fully walked, all-success ⇒ Complete, deterministic ordering (Depth then Id), and the
/// never-throws-except-on-cancellation contract (a null fetch or a non-cancellation fetcher exception ⇒ Partial while
/// the rest of the graph still resolves; a cancelled token propagates).
/// </summary>
public sealed class NuGetDependencyResolverTests
{
    #region Methods
    // A straight chain A(1)->B(2)->C(3): with maxDepth 3 every node resolves, direct dep A is Depth 1 / IsDirect,
    // the transitive B and C are deeper and NOT direct, and all fetches succeeding yields Status=Complete.
    [Fact]
    public async Task ResolveAsync_LinearChain_ResolvesToMaxDepth()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("B"))
            .Add("B", "2.0.0", Dep("C"))
            .Add("C", "3.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A")), maxDepth: 3);

        Assert.Equal(DependencyResolutionStatus.Complete, result.Status);
        Assert.Collection(result.Resolved,
            a => AssertNode(a, "A", "1.0.0", depth: 1, isDirect: true),
            b => AssertNode(b, "B", "2.0.0", depth: 2, isDirect: false),
            c => AssertNode(c, "C", "3.0.0", depth: 3, isDirect: false));
    }

    // maxDepth <= 0 short-circuits to NotRun with an empty set (both zero and a negative), and never touches the fetcher.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task ResolveAsync_DepthZeroOrNegative_ReturnsNotRunEmpty(int maxDepth)
    {
        var fetcher = new FakeDependencyFetcher().Add("A", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A")), maxDepth);

        Assert.Equal(DependencyResolutionStatus.NotRun, result.Status);
        Assert.Empty(result.Resolved);
        Assert.Empty(fetcher.Requested);   // no resolution attempted => no fetch
    }

    // A cycle A->B->A must terminate (no hang / stack overflow) under the (id, version) expansion guard: the finite set
    // of distinct (id, version) pairs (each expanded once) plus the depth cap guarantees termination. It collapses to
    // exactly one node per id: A stays the direct depth-1 node and B is its depth-2 transitive dep, even though B
    // re-references A (A at 1.0.0 is already expanded, so it is not walked again).
    [Fact]
    public async Task ResolveAsync_Cycle_Terminates()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("B"))
            .Add("B", "1.0.0", Dep("A"));
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A")), maxDepth: 5);

        Assert.Equal(DependencyResolutionStatus.Complete, result.Status);
        Assert.Collection(result.Resolved,
            a => AssertNode(a, "A", "1.0.0", depth: 1, isDirect: true),
            b => AssertNode(b, "B", "1.0.0", depth: 2, isDirect: false));
    }

    // A diamond where id X is reached via two paths at different resolved versions (A->X[1.0,) => 1.0.0,
    // B->X[2.0,) => 2.0.0) unifies to a SINGLE node for X at the HIGHEST resolved version (highest-wins, spec rule 3).
    // Here both X versions declare the SAME (empty) dependency set, so per-(id,version) expansion walks both closures
    // but discovers nothing new — the resolved set is exactly {A, B, X}, proving no spurious nodes leak from the
    // superseded version when its deps match. (The different-deps case is covered by
    // ResolveAsync_SameIdDifferentVersionsDifferentDeps_WalksBothClosures.)
    [Fact]
    public async Task ResolveAsync_DiamondSameId_UnifiesToHighestVersionSingleNode()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("X", "[1.0.0,)"))
            .Add("B", "1.0.0", Dep("X", "[2.0.0,)"))
            .Add("X", new[] { "1.0.0", "2.0.0" });
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("B")), maxDepth: 2);

        Assert.Equal(DependencyResolutionStatus.Complete, result.Status);
        var x = Assert.Single(result.Resolved, r => r.Id == "X");
        Assert.Equal("2.0.0", x.Version);   // highest of the two conflicting resolved versions wins
        Assert.Equal(3, result.Resolved.Count);   // exactly {A, B, X} — no spurious nodes when both versions share deps
    }

    // Core of the (id, version) expansion fix (spec rule 4): id X is reached at 1.0.0 (declaring dep P) via A and at
    // 2.0.0 (declaring dep Q) via B. Because expansion is guarded per resolved (id, version) — not per id — BOTH
    // closures are walked, so P AND Q both appear in the resolved set even though X is unified/reported at the single
    // highest version (2.0.0). This is the false-negative the change closes: the older id-only guard would have walked
    // only the first-seen version's closure and silently dropped the other version's transitive dep.
    [Fact]
    public async Task ResolveAsync_SameIdDifferentVersionsDifferentDeps_WalksBothClosures()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("X", "[1.0.0,)"))
            .Add("B", "1.0.0", Dep("X", "[2.0.0,)"))
            .AddVersion("X", "1.0.0", Dep("P"))
            .AddVersion("X", "2.0.0", Dep("Q"))
            .Add("P", "1.0.0")
            .Add("Q", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("B")), maxDepth: 3);

        Assert.Equal(DependencyResolutionStatus.Complete, result.Status);
        var x = Assert.Single(result.Resolved, r => r.Id == "X");
        Assert.Equal("2.0.0", x.Version);   // single X node unified to the highest version (rule 3 invariant still holds)
        Assert.Contains(result.Resolved, r => r.Id == "P");   // 1.0.0's closure walked (superseded-version transitive dep)
        Assert.Contains(result.Resolved, r => r.Id == "Q");   // 2.0.0's closure walked (installed-version transitive dep)
    }

    // Seed dedupe: two seed entries with the same id (case-insensitive, first-occurrence-wins) trigger only ONE fetch.
    [Fact]
    public async Task ResolveAsync_DuplicateSeedId_FetchedOnce()
    {
        var fetcher = new FakeDependencyFetcher().Add("A", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("A")), maxDepth: 1);

        var a = Assert.Single(result.Resolved);
        AssertNode(a, "A", "1.0.0", depth: 1, isDirect: true);
        Assert.Single(fetcher.Requested);                 // duplicated seed id fetched exactly once
        Assert.Equal("A", fetcher.Requested[0]);
    }

    // Unify parseable preference (rule 3 / Unify): X is reached via two paths, one yielding an UNPARSEABLE version
    // string and the other a valid "2.0.0". The unparseable path is processed first (becomes "existing"); unification
    // must never keep an unparseable version over a parseable one, so the reported X version is the valid "2.0.0".
    [Fact]
    public async Task ResolveAsync_Unify_PrefersParseableVersionOverUnparseable()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("X", "[1.0.0,)"))
            .Add("B", "1.0.0", Dep("X", "[2.0.0,)"))
            .AddRaw("X", VersionRange.Parse("[1.0.0,)"), "not-a-semver")   // A's path: unparseable version string
            .AddRaw("X", VersionRange.Parse("[2.0.0,)"), "2.0.0");         // B's path: valid version string
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("B")), maxDepth: 2);

        Assert.Equal(DependencyResolutionStatus.Complete, result.Status);
        var x = Assert.Single(result.Resolved, r => r.Id == "X");
        Assert.Equal("2.0.0", x.Version);   // parseable candidate wins over the unparseable existing version
    }

    // Version selection is the fetcher's responsibility: given versions {1.0.0, 1.5.0, 2.0.0} and range "[1.2.0,)",
    // the fake picks the LOWEST satisfying version (1.5.0), and the resolver carries that choice through unchanged
    // rather than re-deriving a version from the range.
    [Fact]
    public async Task ResolveAsync_RangeSelectsLowestSatisfyingVersion()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("X", new[] { "1.0.0", "1.5.0", "2.0.0" });
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("X", "[1.2.0,)")), maxDepth: 1);

        var x = Assert.Single(result.Resolved);
        Assert.Equal("1.5.0", x.Version);   // lowest version satisfying [1.2.0,) — the fetcher's pick, unaltered
    }

    // The fetcher already unions dependency groups across TFMs into one deduped list; the resolver simply walks that
    // list. A single dep A returning three deps (Lib1/Lib2/Lib3) must yield all three transitive nodes.
    [Fact]
    public async Task ResolveAsync_UnionsDependencyGroupsAcrossTfms()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("Lib1"), Dep("Lib2"), Dep("Lib3"))
            .Add("Lib1", "1.0.0")
            .Add("Lib2", "1.0.0")
            .Add("Lib3", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A")), maxDepth: 2);

        Assert.Equal(DependencyResolutionStatus.Complete, result.Status);
        var transitive = result.Resolved.Where(r => !r.IsDirect).Select(r => r.Id).ToArray();
        Assert.Equal(new[] { "Lib1", "Lib2", "Lib3" }, transitive);   // all union members walked, ordered by id
    }

    // A single unresolvable dep (fetch returns null) marks the WHOLE result Partial but does not abort the walk: the
    // other reachable node is still resolved. Honest degradation — never a false all-clear.
    [Fact]
    public async Task ResolveAsync_FetchReturnsNull_MarksPartial_ContinuesRest()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0")
            .ReturnsNullFor("Missing");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("Missing")), maxDepth: 1);

        Assert.Equal(DependencyResolutionStatus.Partial, result.Status);
        var a = Assert.Single(result.Resolved);
        Assert.Equal("A", a.Id);
        Assert.DoesNotContain(result.Resolved, r => r.Id == "Missing");
    }

    // Hostile-input guard: a malformed/hostile feed response can yield a FetchedPackage whose Id is null or blank. That
    // node must degrade to unresolved exactly like a null fetch (never throw): the whole result is Partial, the malformed
    // node is absent from the resolved set, and the sibling dep still resolves — the walk continues over the frontier.
    [Theory]
    [InlineData(null)]
    [InlineData("  ")]
    public async Task ResolveAsync_FetchReturnsBlankId_MarksPartial_ContinuesRest(string? blankId)
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0")
            .AddMalformedId("Malformed", blankId);
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("Malformed")), maxDepth: 1);

        Assert.Equal(DependencyResolutionStatus.Partial, result.Status);
        var a = Assert.Single(result.Resolved);
        Assert.Equal("A", a.Id);   // sibling still resolves after the malformed node degrades
        Assert.DoesNotContain(result.Resolved, r => string.IsNullOrWhiteSpace(r.Id));
    }

    // maxDepth is a hard bound on EXPANSION: for A->B->C->D with maxDepth 2, only A (depth 1) and B (depth 2) resolve,
    // and — asserted via the fake's request log — C and D are never even fetched (no expansion beyond the bound).
    [Fact]
    public async Task ResolveAsync_MaxDepthHonored_DoesNotExpandBeyond()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0", Dep("B"))
            .Add("B", "1.0.0", Dep("C"))
            .Add("C", "1.0.0", Dep("D"))
            .Add("D", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A")), maxDepth: 2);

        Assert.Collection(result.Resolved,
            a => AssertNode(a, "A", "1.0.0", depth: 1, isDirect: true),
            b => AssertNode(b, "B", "1.0.0", depth: 2, isDirect: false));
        Assert.Contains("A", fetcher.Requested);
        Assert.Contains("B", fetcher.Requested);
        Assert.DoesNotContain("C", fetcher.Requested);   // depth-3 node never fetched
        Assert.DoesNotContain("D", fetcher.Requested);
    }

    // A pre-cancelled token is honored (not swallowed): the walk propagates an OperationCanceledException.
    [Fact]
    public async Task ResolveAsync_Cancellation_Throws()
    {
        var fetcher = new FakeDependencyFetcher().Add("A", "1.0.0", Dep("B")).Add("B", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => resolver.ResolveAsync(Seeds(Dep("A")), maxDepth: 3, cts.Token));
    }

    // A fetcher throwing a NON-cancellation exception for one id must NOT propagate: that node degrades to unresolved,
    // the result is Partial, and the rest of the graph still resolves.
    [Fact]
    public async Task ResolveAsync_NeverThrowsOnFetcherException()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("A", "1.0.0")
            .ThrowsFor("Boom");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("A"), Dep("Boom")), maxDepth: 1);

        Assert.Equal(DependencyResolutionStatus.Partial, result.Status);
        var a = Assert.Single(result.Resolved);
        Assert.Equal("A", a.Id);
        Assert.DoesNotContain(result.Resolved, r => r.Id == "Boom");
    }

    // Output is deterministic: ordered by Depth then Id (case-insensitive), regardless of seed / discovery order.
    [Fact]
    public async Task ResolveAsync_Result_IsOrderedByDepthThenId()
    {
        var fetcher = new FakeDependencyFetcher()
            .Add("Zebra", "1.0.0", Dep("mango"))
            .Add("Apple", "1.0.0", Dep("Cherry"))
            .Add("mango", "1.0.0")
            .Add("Cherry", "1.0.0");
        var resolver = new NuGetDependencyResolver(fetcher);

        var result = await resolver.ResolveAsync(Seeds(Dep("Zebra"), Dep("Apple")), maxDepth: 2);

        var ordered = result.Resolved.Select(r => (r.Depth, r.Id)).ToArray();
        Assert.Equal(
            new[] { (1, "Apple"), (1, "Zebra"), (2, "Cherry"), (2, "mango") },
            ordered);
    }
    #endregion

    #region Helpers
    // A declared dependency seed at a given range (default "[1.0.0,)"), mirroring the (Id, VersionRange) tuple shape.
    private static (string Id, VersionRange Range) Dep(string id, string range = "[1.0.0,)") =>
        (id, VersionRange.Parse(range));

    private static IReadOnlyList<(string Id, VersionRange Range)> Seeds(params (string Id, VersionRange Range)[] deps) =>
        deps;

    private static void AssertNode(ResolvedDependency node, string id, string version, int depth, bool isDirect)
    {
        Assert.Equal(id, node.Id);
        Assert.Equal(version, node.Version);
        Assert.Equal(depth, node.Depth);
        Assert.Equal(isDirect, node.IsDirect);
    }
    #endregion

    #region Types
    /// <summary>
    /// In-memory <see cref="IPackageDependencyFetcher"/> test double. A test declares a graph via <see cref="Add"/>
    /// (id -> available versions + child (id, range) deps); <see cref="GetAsync"/> returns the lowest available version
    /// satisfying the requested range plus that package's declared deps, exactly like the live nuget.org fetcher.
    /// Unknown ids (or ids registered via <see cref="ReturnsNullFor"/>) return <c>null</c> to simulate a fetch miss;
    /// ids registered via <see cref="ThrowsFor"/> throw a non-cancellation exception. Every requested id is recorded in
    /// <see cref="Requested"/> so tests can assert maxDepth pruning. No network is ever contacted.
    /// </summary>
    private sealed class FakeDependencyFetcher : IPackageDependencyFetcher
    {
        #region Methods
        public FakeDependencyFetcher Add(string id, string version, params (string Id, VersionRange Range)[] deps) =>
            Add(id, new[] { version }, deps);

        public FakeDependencyFetcher Add(string id, string[] versions, params (string Id, VersionRange Range)[] deps)
        {
            packages[id] = new PackageDef(versions, deps);
            return this;
        }

        // Registers a single available version of <paramref name="id"/> with its OWN dependency set, so the same id can
        // declare different deps at different versions (exercises per-(id, version) expansion). Accumulates across calls.
        public FakeDependencyFetcher AddVersion(string id, string version, params (string Id, VersionRange Range)[] deps)
        {
            if (!versionDeps.TryGetValue(id, out var map))
                versionDeps[id] = map = new Dictionary<string, IReadOnlyList<(string Id, VersionRange Range)>>(StringComparer.OrdinalIgnoreCase);
            map[NuGetVersion.Parse(version).ToNormalizedString()] = deps;
            return this;
        }

        // Registers a raw, unvalidated response for an exact requested range: returns <paramref name="rawVersion"/>
        // verbatim (bypassing version selection), letting a test emit an arbitrary/unparseable version string.
        public FakeDependencyFetcher AddRaw(string id, VersionRange range, string rawVersion, params (string Id, VersionRange Range)[] deps)
        {
            rawByRange[(id, range.ToNormalizedString())] = (rawVersion, deps);
            return this;
        }

        // Registers a hostile/malformed feed response for <paramref name="id"/>: GetAsync returns a FetchedPackage whose
        // OWN Id is <paramref name="malformedId"/> (null or blank), simulating a feed that echoes a garbage package id.
        public FakeDependencyFetcher AddMalformedId(string id, string? malformedId)
        {
            malformedIds[id] = malformedId;
            return this;
        }

        public FakeDependencyFetcher ReturnsNullFor(string id)
        {
            nullIds.Add(id);
            return this;
        }

        public FakeDependencyFetcher ThrowsFor(string id)
        {
            throwIds.Add(id);
            return this;
        }

        public Task<FetchedPackage?> GetAsync(string id, VersionRange range, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            lock (Requested)
                Requested.Add(id);

            if (throwIds.Contains(id))
                throw new InvalidOperationException($"simulated fetcher failure for '{id}'");

            // A malformed/hostile feed response: a FetchedPackage carrying a null/blank Id of its own (the resolver's
            // hostile-input guard must degrade this exactly like a null fetch rather than NRE on the id).
            if (malformedIds.TryGetValue(id, out var malformedId))
                return Task.FromResult<FetchedPackage?>(new FetchedPackage(malformedId!, "1.0.0", Array.Empty<(string Id, VersionRange Range)>()));

            // A raw, unvalidated per-range response takes precedence and is returned verbatim (arbitrary/unparseable
            // version string), bypassing version selection entirely.
            if (rawByRange.TryGetValue((id, range.ToNormalizedString()), out var raw))
                return Task.FromResult<FetchedPackage?>(new FetchedPackage(id, raw.Version, raw.Dependencies));

            if (nullIds.Contains(id))
                return Task.FromResult<FetchedPackage?>(null);

            // Available versions may be declared via Add (shared deps) and/or AddVersion (per-version deps).
            packages.TryGetValue(id, out var def);
            var available = new List<string>();
            if (def is not null)
                available.AddRange(def.Versions);
            if (versionDeps.TryGetValue(id, out var perVersion))
                available.AddRange(perVersion.Keys);

            if (available.Count == 0)
                return Task.FromResult<FetchedPackage?>(null);

            // Lowest listed version satisfying the range (what NuGet restore installs and the live fetcher mirrors).
            var chosen = available
                .Select(NuGetVersion.Parse)
                .Where(range.Satisfies)
                .OrderBy(v => v)
                .FirstOrDefault();

            if (chosen is null)
                return Task.FromResult<FetchedPackage?>(null);

            var chosenStr = chosen.ToNormalizedString();
            // A per-version dependency set (AddVersion) wins for the chosen version; otherwise the shared Add deps.
            var deps =
                perVersion is not null && perVersion.TryGetValue(chosenStr, out var vd)
                    ? vd
                    : def?.Dependencies ?? Array.Empty<(string Id, VersionRange Range)>();

            return Task.FromResult<FetchedPackage?>(new FetchedPackage(id, chosenStr, deps));
        }
        #endregion

        #region Properties
        public List<string> Requested { get; } = new();
        #endregion

        #region Fields
        private readonly Dictionary<string, PackageDef> packages = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Dictionary<string, IReadOnlyList<(string Id, VersionRange Range)>>> versionDeps =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<(string Id, string Range), (string Version, IReadOnlyList<(string Id, VersionRange Range)> Dependencies)> rawByRange =
            new();
        private readonly Dictionary<string, string?> malformedIds = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> nullIds = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> throwIds = new(StringComparer.OrdinalIgnoreCase);
        #endregion

        #region Types
        private sealed record PackageDef(string[] Versions, IReadOnlyList<(string Id, VersionRange Range)> Dependencies);
        #endregion
    }
    #endregion
}
