namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// The CHA work budget (A2 S1 review 2, W-A; docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md, "S1 review 2 … (S1d)"):
/// n unrelated own classes, each with a <c>newslot virtual Run()</c> and each called, make every one of the n declared
/// shapes scan all n <c>Run</c> candidates — quadratic, with not a single edge to show for it, so the edge budget never
/// sees the work. Two answers, each pinned here on SYNTHETIC Model objects (<see cref="SyntheticModel"/>'s stance: no host,
/// nothing resolved):
/// <list type="bullet">
/// <item><description>the <b>pre-filter</b>: a declared own class nothing derives from is answered <c>[]</c> at no cost
/// (case K);</description></item>
/// <item><description>the <b>work budget</b>, <see cref="GraphBudget.MaxDispatchWork"/> through
/// <see cref="MemberIndex.DispatchWork"/>: when the pre-filter is defeated (each class has an own subclass, case K'),
/// the fan-out stops at the budget, every static edge is still added, and the graph says it was truncated, and why.</description></item>
/// </list>
/// Plus what makes the budget safe to use: a build spends the same work and stops at the same place whatever earlier
/// builds over the same index memoized, and an abandoned shape memoizes nothing.
/// </summary>
public sealed class DispatchWorkBudgetTests
{
    #region Methods
    // ---- case K: the pre-filter --------------------------------------------------------------------------------------

    /// <summary>
    /// Case K: 4,000 unrelated own leaf classes <c>Ci : Object</c>, each with a virtual <c>Run()</c>, each called by
    /// <c>callvirt Ci::Run</c>. Every site still dispatches (to nothing), but each is answered by the pre-filter: no
    /// Dispatch edge, no work spent, not truncated, and well within the deadline.
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_ManyUnrelatedLeafClassesSharingAVirtualName_ArePreFilteredAtNoCost()
    {
        const int n = 4000;
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.None), TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index));

        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.Equal(0L, graph.Coverage.DispatchWork);
        Assert.False(graph.Coverage.Truncated);
        Assert.Null(graph.Coverage.TruncatedBy);
        Assert.Equal(n, graph.Coverage.DispatchSites);
        Assert.Equal(StaticEdges(n), graph.Edges);
        Assert.True(elapsed < TimeSpan.FromSeconds(5), $"case K, n={n}: {elapsed.TotalMilliseconds:F0} ms; expected under 5 s.");
    }

    /// <summary>The pre-filter, one call: a leaf class's shape is <c>[]</c> (not null: the site does dispatch) and costs nothing.</summary>
    [Fact]
    public void DispatchTargets_ThroughAnOwnClassNothingDerivesFrom_IsEmptyAndFree()
    {
        var index = MemberIndex.Build([(Unrelated(50, Subclasses.None), TypeForwarders.None)]);
        var reference = CallvirtTarget("C7", "Run");
        var work = new MemberIndex.DispatchWork(long.MaxValue);

        var targets = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, work);

        Assert.NotNull(targets);
        Assert.Empty(targets);
        Assert.Equal(0L, work.Spent);
        Assert.False(work.Exhausted);
    }

    // ---- case K': the work budget ------------------------------------------------------------------------------------

    /// <summary>
    /// Case K': as K, but each <c>Ci</c> has an own subclass <c>Di</c> without a <c>Run</c>, which defeats the pre-filter,
    /// so each of the n shapes really does consider all n candidates. With a budget of 1,000,000 units (about 1/30 of
    /// what n = 4,000 needs) the build stops the fan-out part-way: truncated "dispatch work budget …", exactly the limit
    /// spent, fewer dispatch sites answered than there are — and EVERY static <c>callvirt</c> edge still present, so a
    /// package cannot hide its direct calls by exhausting CHA. Well within the deadline.
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_TheQuadraticShapeUnderASmallWorkBudget_StopsTheFanOutButKeepsEveryStaticEdge()
    {
        const int n = 4000;
        const long limit = 1_000_000;
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.WithoutRun), TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index, new GraphBudget(1_000_000, 5_000_000, limit)));

        Assert.True(graph.Coverage.Truncated);
        Assert.StartsWith("dispatch work budget", graph.Coverage.TruncatedBy);
        Assert.Equal($"dispatch work budget of {limit} reached", graph.Coverage.TruncatedBy);
        Assert.Equal(limit, graph.Coverage.DispatchWork);
        Assert.Equal(n, graph.Coverage.CallSites);
        Assert.Equal(StaticEdges(n), graph.Edges);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.InRange(graph.Coverage.DispatchSites, 1, n - 1);
        Assert.Equal(n, graph.Coverage.BodiesRead);
        Assert.True(elapsed < TimeSpan.FromSeconds(5), $"case K', n={n}, limit {limit}: {elapsed.TotalMilliseconds:F0} ms; expected under 5 s.");
    }

    /// <summary>
    /// Case K' under the DEFAULT budget at a moderate n (1,000): it completes, is not truncated, and the work really is
    /// quadratic — between n² and 3n² units (each shape charges its n candidates plus one step per other candidate's
    /// walk: measured n(2n - 1) = 1,999,000). Measured 1.2 s; n = 3,000 took 9 s for 17,997,000 units, and n = 4,000
    /// exhausts the default 20,000,000 after about 10 s, so the default bounds this shape at roughly that.
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_TheQuadraticShapeUnderTheDefaultBudget_CompletesUntruncated()
    {
        const int n = 1000;
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.WithoutRun), TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index));

        Assert.False(graph.Coverage.Truncated, graph.Coverage.TruncatedBy);
        Assert.Equal(n, graph.Coverage.DispatchSites);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.InRange(graph.Coverage.DispatchWork, (long)n * n, 3L * n * n);
        Assert.Equal(StaticEdges(n), graph.Edges);
        Assert.True(elapsed < TimeSpan.FromSeconds(10), $"case K', n={n}, default budget: {elapsed.TotalMilliseconds:F0} ms; expected under 10 s.");
    }

    /// <summary>
    /// When the node or edge budget is also reached, both reasons are given, the dispatch one first, joined by "; ":
    /// case K' with a small work budget and an edge budget one short of the n static edges.
    /// </summary>
    [Fact]
    public void Build_WhenTheEdgeBudgetIsAlsoReached_GivesBothReasons_DispatchFirst()
    {
        const int n = 300;
        const long limit = 5_000;
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.WithoutRun), TypeForwarders.None)]);

        var graph = MethodGraph.Build(index, new GraphBudget(1_000_000, n - 1, limit));

        Assert.True(graph.Coverage.Truncated);
        Assert.Equal($"dispatch work budget of {limit} reached; edges budget of {n - 1} reached", graph.Coverage.TruncatedBy);
        Assert.Equal(limit, graph.Coverage.DispatchWork);
        Assert.Equal(n - 1, graph.Edges.Count);
    }

    // ---- determinism -------------------------------------------------------------------------------------------------

    /// <summary>
    /// Two builds over the SAME index — the second with every shape already memoized — give equal coverage, including
    /// the work spent: a memoized shape is charged what it cost to compute, once per build. (n = 200 base classes, each
    /// with an overriding subclass, so every site has a Dispatch edge; all share the name <c>Run</c>.)
    /// </summary>
    [Fact]
    public void Build_TwiceOverOneIndex_WithAnAmpleBudget_SpendsTheSameWork()
    {
        var index = MemberIndex.Build([(Unrelated(Overridden, Subclasses.WithRun), TypeForwarders.None)]);

        var cold = MethodGraph.Build(index);
        var warm = MethodGraph.Build(index);

        Assert.False(cold.Coverage.Truncated, cold.Coverage.TruncatedBy);
        Assert.Equal(Overridden, cold.Coverage.DispatchEdges);
        Assert.True(cold.Coverage.DispatchWork > 0);
        Assert.Equal(cold.Coverage, warm.Coverage);
        Assert.Equal(cold.Edges, warm.Edges);
    }

    /// <summary>
    /// With a budget of half the work the full build needs, the fan-out stops part-way — and at the SAME place every
    /// time: two exhausted builds over one index (the second with the first's shapes memoized) are equal, coverage and
    /// edges; so is an exhausted build over an index whose memo an AMPLE build has filled completely.
    /// </summary>
    [Fact]
    public void Build_TwiceOverOneIndex_WhenTheWorkRunsOut_StopsAtTheSamePlace()
    {
        var model = Unrelated(Overridden, Subclasses.WithRun);
        var limit = MethodGraph.Build(MemberIndex.Build([(model, TypeForwarders.None)])).Coverage.DispatchWork / 2;
        var budget = new GraphBudget(1_000_000, 5_000_000, limit);
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);

        var first = MethodGraph.Build(index, budget);
        var second = MethodGraph.Build(index, budget);

        Assert.True(first.Coverage.Truncated);
        Assert.Equal($"dispatch work budget of {limit} reached", first.Coverage.TruncatedBy);
        Assert.Equal(limit, first.Coverage.DispatchWork);
        Assert.InRange(first.Coverage.DispatchEdges, 1, Overridden - 1);
        Assert.Equal(first.Coverage, second.Coverage);
        Assert.Equal(first.Edges, second.Edges);

        var warmed = MemberIndex.Build([(model, TypeForwarders.None)]);
        _ = MethodGraph.Build(warmed);
        var afterAmple = MethodGraph.Build(warmed, budget);
        Assert.Equal(first.Coverage, afterAmple.Coverage);
        Assert.Equal(first.Edges, afterAmple.Edges);
    }

    /// <summary>
    /// An exhausted build memoizes nothing partial: after two exhausted builds, an ample build over the same index gives
    /// every Dispatch edge — the same graph, coverage included, as an ample build over a fresh index.
    /// </summary>
    [Fact]
    public void Build_AfterExhaustedBuilds_AnAmpleBuildOverTheSameIndex_IsComplete()
    {
        var model = Unrelated(Overridden, Subclasses.WithRun);
        var fresh = MethodGraph.Build(MemberIndex.Build([(model, TypeForwarders.None)]));
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);
        _ = MethodGraph.Build(index, new GraphBudget(1_000_000, 5_000_000, fresh.Coverage.DispatchWork / 3));
        _ = MethodGraph.Build(index, new GraphBudget(1_000_000, 5_000_000, fresh.Coverage.DispatchWork / 2));

        var full = MethodGraph.Build(index);

        Assert.False(full.Coverage.Truncated, full.Coverage.TruncatedBy);
        Assert.Equal(Overridden, full.Coverage.DispatchEdges);
        Assert.Equal(fresh.Edges, full.Edges);
        Assert.Equal(fresh.Coverage, full.Coverage);
    }

    // ---- DispatchTargets with and without a DispatchWork ------------------------------------------------------------

    /// <summary>
    /// <c>work: null</c> is unlimited and answers exactly as before S1d — the same targets as an explicit, ample
    /// <see cref="MemberIndex.DispatchWork"/> over a fresh index, which spends some work and is not exhausted.
    /// </summary>
    [Fact]
    public void DispatchTargets_WithoutWork_IsUnlimited_AndAnswersAsAnAmpleWorkDoes()
    {
        var model = Unrelated(3, Subclasses.WithRun);
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);
        var fresh = MemberIndex.Build([(model, TypeForwarders.None)]);
        var reference = CallvirtTarget("C0", "Run");
        var work = new MemberIndex.DispatchWork(long.MaxValue);

        var unlimited = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true);
        var counted = fresh.DispatchTargets(reference, fresh.Resolve(reference), virtualSite: true, work);

        Assert.Equal([Id("D0.Run()")], unlimited);
        Assert.Equal(unlimited, counted);
        Assert.True(work.Spent > 0);
        Assert.False(work.Exhausted);
        Assert.Equal(long.MaxValue, work.Limit);
    }

    /// <summary>
    /// A memoized shape — here computed with no work at all — is charged its recorded cost, the same as computing it
    /// cold; and only once per <see cref="MemberIndex.DispatchWork"/>: a second call on the same work is free.
    /// </summary>
    [Fact]
    public void DispatchTargets_AMemoizedShape_IsChargedItsRecordedCost_OncePerWork()
    {
        var model = Unrelated(20, Subclasses.WithRun);
        var reference = CallvirtTarget("C3", "Run");
        var cold = new MemberIndex.DispatchWork(long.MaxValue);
        var coldIndex = MemberIndex.Build([(model, TypeForwarders.None)]);
        _ = coldIndex.DispatchTargets(reference, coldIndex.Resolve(reference), virtualSite: true, cold);
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);
        _ = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true);
        var warm = new MemberIndex.DispatchWork(long.MaxValue);

        var first = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, warm);
        var spent = warm.Spent;
        var again = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, warm);

        Assert.True(cold.Spent > 0);
        Assert.Equal(cold.Spent, spent);
        Assert.Equal(spent, warm.Spent);
        Assert.Equal([Id("D3.Run()")], first);
        Assert.Equal(first, again);
    }

    /// <summary>
    /// The limit is inclusive: work of exactly a shape's cost answers it in full. One unit less is null — on a fresh
    /// index (cold) and on one that has the shape memoized (warm) alike — with <see cref="MemberIndex.DispatchWork.Exhausted"/>
    /// set and <see cref="MemberIndex.DispatchWork.Spent"/> capped at the limit. Once exhausted, every call is null, even
    /// one the pre-filter would answer for free. And the abandoned cold attempt memoized nothing: the exact work then gets
    /// the full answer at the full cost.
    /// </summary>
    [Fact]
    public void DispatchTargets_PastTheLimit_IsNull_CapsSpentAtTheLimit_AndMemoizesNothing()
    {
        var model = Unrelated(20, Subclasses.WithRun);
        var reference = CallvirtTarget("C3", "Run");
        var measured = new MemberIndex.DispatchWork(long.MaxValue);
        var probe = MemberIndex.Build([(model, TypeForwarders.None)]);
        _ = probe.DispatchTargets(reference, probe.Resolve(reference), virtualSite: true, measured);
        var cost = measured.Spent;
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);
        var resolution = index.Resolve(reference);
        var shortCold = new MemberIndex.DispatchWork(cost - 1);

        Assert.Null(index.DispatchTargets(reference, resolution, virtualSite: true, shortCold));
        Assert.True(shortCold.Exhausted);
        Assert.Equal(cost - 1, shortCold.Spent);
        var leaf = CallvirtTarget("D5", "Run");
        Assert.Null(index.DispatchTargets(leaf, index.Resolve(leaf), virtualSite: true, shortCold));
        Assert.Equal(cost - 1, shortCold.Spent);

        var exact = new MemberIndex.DispatchWork(cost);
        Assert.Equal([Id("D3.Run()")], index.DispatchTargets(reference, resolution, virtualSite: true, exact));
        Assert.False(exact.Exhausted);
        Assert.Equal(cost, exact.Spent);

        var shortWarm = new MemberIndex.DispatchWork(cost - 1);
        Assert.Null(index.DispatchTargets(reference, resolution, virtualSite: true, shortWarm));
        Assert.True(shortWarm.Exhausted);
        Assert.Equal(cost - 1, shortWarm.Spent);
    }

    // ---- the charge follows the text hashed and compared (S1e, review 3 W1) -------------------------------------------

    /// <summary>
    /// With short ids (at most 13 characters: <c>System.Object</c>) every candidate and every step costs exactly one unit,
    /// as before S1e: a whole build of case K' spends n(2n - 1) — each of the n shapes charges its n candidates, plus one
    /// step (to <c>System.Object</c>) for each of the n - 1 other candidates' walks.
    /// </summary>
    [Fact]
    public void Build_TheQuadraticShapeWithShortIds_SpendsExactlyOneUnitPerCandidateAndStep()
    {
        const int n = 100;
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.WithoutRun), TypeForwarders.None)]);

        var graph = MethodGraph.Build(index);

        Assert.False(graph.Coverage.Truncated, graph.Coverage.TruncatedBy);
        Assert.Equal((long)n * (2 * n - 1), graph.Coverage.DispatchWork);
    }

    /// <summary>
    /// A type id costs 1 + length / 64 units (u) each time it is charged — as a candidate's declaring type and as a
    /// hierarchy step (review 3 W1). One call <c>callvirt C3::Run</c> on case K' with overriding subclasses (n = 5), whose
    /// type ids <c>{ns}.Ci</c> / <c>{ns}.Di</c> are all <paramref name="idLength"/> characters long, costs 3n·u + n - 1:
    /// the 2n candidates <c>Cj.Run</c>, <c>Dj.Run</c> at u each; for each other j, a step from Cj to <c>System.Object</c>
    /// (13 characters: 1) and one from Dj to Cj (u); and D3's step to the key C3 (u). So a 63-character id costs 1 unit,
    /// a 64-character one 2, a 128-character one 3.
    /// </summary>
    [Theory]
    [InlineData(63, 1)]
    [InlineData(64, 2)]
    [InlineData(127, 2)]
    [InlineData(128, 3)]
    public void DispatchTargets_ChargesATypeIdOneUnitPer64Characters_PerCandidateAndPerStep(int idLength, long units)
    {
        const int n = 5;
        var ns = new string('N', idLength - "C3".Length - 1);
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.WithRun, ns), TypeForwarders.None)]);
        var reference = CallvirtTarget("C3", "Run", ns);
        var work = new MemberIndex.DispatchWork(long.MaxValue);

        var targets = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, work);

        Assert.Equal(idLength, Id("C3", ns).Length);
        Assert.Equal(units, Units(Id("C3", ns)));
        Assert.Equal([Id("D3.Run()", ns)], targets);
        Assert.Equal(3 * n * units + n - 1, work.Spent);
    }

    /// <summary>
    /// A candidate's parameter types — and the site's — are charged only when the site is NARROWED by them, i.e. declared
    /// on an own class (review 3 W1: <c>MayOverride</c> scans both sides only then). Model: an own interface <c>I</c> with
    /// <c>Run(P)</c>, n own classes <c>Ci : I</c> with <c>Run(P)</c>, each with an overriding <c>Di</c>; P an external
    /// type whose rendered name is short (<c>Ext.P</c>: U = 1 unit) or long (304 characters: U = 5).
    /// <list type="bullet">
    /// <item><description>Narrowed, <c>callvirt C0::Run(P)</c>: each of the 2n + 1 candidates (<c>I.Run</c> and every
    /// <c>Ci.Run</c>, <c>Di.Run</c>) costs 1 for its type id plus U for the site's parameter plus U for its own; the walks
    /// cost 3 per other class pair (Ci to I and to Object, Di to Ci) and 1 for D0 to C0: (2n + 1)(1 + 2U) + 3n - 2.</description></item>
    /// <item><description>Not narrowed, <c>callvirt I::Run(P)</c>: 1 per candidate and 2 per class pair's walks to I,
    /// whatever P's length: 4n + 1.</description></item>
    /// </list>
    /// </summary>
    [Fact]
    public void DispatchTargets_ChargesParameterTypesOnlyUnderNarrowing()
    {
        const int n = 4;
        ModelTypes.IType shortType = External("P");
        ModelTypes.IType longType = External(new string('P', 300));
        var shortUnits = Units(ModelNames.Of(CallvirtTarget("C0", "Run", parameters: [shortType])).ParameterTypes[0]);
        var longUnits = Units(ModelNames.Of(CallvirtTarget("C0", "Run", parameters: [longType])).ParameterTypes[0]);

        var (narrowShort, narrowShortTargets) = Spent(Implementing(n, shortType), CallvirtTarget("C0", "Run", parameters: [shortType]));
        var (narrowLong, narrowLongTargets) = Spent(Implementing(n, longType), CallvirtTarget("C0", "Run", parameters: [longType]));
        var (wideShort, wideShortTargets) = Spent(Implementing(n, shortType), CallvirtTarget("I", "Run", parameters: [shortType]));
        var (wideLong, wideLongTargets) = Spent(Implementing(n, longType), CallvirtTarget("I", "Run", parameters: [longType]));

        Assert.Equal((1L, 5L), (shortUnits, longUnits));
        Assert.Equal((2 * n + 1) * (1 + 2 * shortUnits) + 3 * n - 2, narrowShort);
        Assert.Equal((2 * n + 1) * (1 + 2 * longUnits) + 3 * n - 2, narrowLong);
        Assert.Equal(4 * n + 1, wideShort);
        Assert.Equal(4 * n + 1, wideLong);
        Assert.Equal([Id("D0.Run(Ext.P)")], narrowShortTargets);
        Assert.Single(narrowLongTargets);
        Assert.Equal(2 * n, wideShortTargets.Count);
        Assert.Equal(2 * n, wideLongTargets.Count);
    }

    /// <summary>
    /// Review 3 W1 (a), a long namespace: a file stores a namespace once, so a 20,000-character one costs an attacker
    /// nothing, and before S1e each unit of case K' then cost about 19 µs (n = 2,000: 154.6 s under the default budget,
    /// on the reviewer's machine). Now every candidate is charged 1 + 20,005 / 64 = 313 units for its type id, so:
    /// <list type="bullet">
    /// <item><description>one shape costs Σ Units(id of Cj) + (n - 1) — its n candidates, plus one step to
    /// <c>System.Object</c> for each other candidate's walk;</description></item>
    /// <item><description>the same n with the short namespace <c>Syn</c> spends n(2n - 1), untruncated;</description></item>
    /// <item><description>with the long namespace, under the DEFAULT budget, the build truncates at the dispatch work
    /// budget, over 100 times what the short one spends (the full build would need about 313 / 2 times as much) — every
    /// static edge still present — within the deadline.</description></item>
    /// </list>
    /// Deadline (<see cref="LongNamespaceDeadline"/>): the default budget at 1 µs per unit, twice the 0.5 µs per unit
    /// measured on short ids (S1d; 0.52 µs re-measured at n = 1,000), is 20 s. Measured on the dev machine (S1e): 3.1 s
    /// (0.16 µs per unit; 212 of 300 sites answered). The same model with unlimited work took 3.6 s for 28,259,700 units
    /// (0.13 µs per unit) — work the pre-S1e charge counted as 179,700 units, i.e. 20 µs per unit then.
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_TheQuadraticShapeWithALongNamespace_IsChargedByLength_AndTruncatesWithinTheDeadline()
    {
        const int n = 300;
        var ns = new string('N', 20_000);
        var shortGraph = MethodGraph.Build(MemberIndex.Build([(Unrelated(n, Subclasses.WithoutRun), TypeForwarders.None)]));
        var model = Unrelated(n, Subclasses.WithoutRun, ns);
        var shape = MemberIndex.Build([(model, TypeForwarders.None)]);
        var reference = CallvirtTarget("C0", "Run", ns);
        var work = new MemberIndex.DispatchWork(long.MaxValue);
        _ = shape.DispatchTargets(reference, shape.Resolve(reference), virtualSite: true, work);
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index));

        Assert.Equal(Enumerable.Range(0, n).Sum(j => Units(Id($"C{j}", ns))) + n - 1, work.Spent);
        Assert.Equal(313L, Units(Id("C0", ns)));
        Assert.False(shortGraph.Coverage.Truncated, shortGraph.Coverage.TruncatedBy);
        Assert.Equal((long)n * (2 * n - 1), shortGraph.Coverage.DispatchWork);
        Assert.True(graph.Coverage.Truncated);
        Assert.StartsWith("dispatch work budget", graph.Coverage.TruncatedBy);
        Assert.Equal(GraphBudget.DefaultDispatchWork, graph.Coverage.DispatchWork);
        Assert.True(graph.Coverage.DispatchWork > 100 * shortGraph.Coverage.DispatchWork,
            $"long namespace {graph.Coverage.DispatchWork} units; short {shortGraph.Coverage.DispatchWork}");
        Assert.InRange(graph.Coverage.DispatchSites, 1, n - 1);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.Equal(StaticEdges(n, ns), graph.Edges);
        Assert.True(elapsed < LongNamespaceDeadline, $"case K' with a 20,000-character namespace, n={n}, default budget: {elapsed.TotalMilliseconds:F0} ms; expected under {LongNamespaceDeadline.TotalSeconds} s.");
    }

    /// <summary>
    /// Review 3 W1 (b), many parameters: a file can share one signature blob across every <c>Run</c>, so 200 parameters cost
    /// an attacker nothing, and before S1e each unit of case K' with them cost about 4.3 µs (n = 1,000: 8.7 s). Now, under
    /// narrowing (the declared type is an own class), every candidate is charged its type id plus Units of each of the
    /// site's 200 parameter types plus each of its own. Here each parameter type is an external <c>Ext.P{k}pp…</c> of 98
    /// characters (2 units), so:
    /// <list type="bullet">
    /// <item><description>one shape costs n(1 + 2 · 400) + (n - 1);</description></item>
    /// <item><description>the same n with no parameters spends n(2n - 1), untruncated;</description></item>
    /// <item><description>with the 200 parameters, under the DEFAULT budget, the build truncates at the dispatch work
    /// budget — every static edge still present — within the deadline.</description></item>
    /// </list>
    /// Deadline: as <see cref="Build_TheQuadraticShapeWithALongNamespace_IsChargedByLength_AndTruncatesWithinTheDeadline"/>.
    /// Measured on the dev machine (S1e): 1.0 s (24 of 1,000 sites answered). The same model with unlimited work took
    /// 18.8 s for 801,999,000 units (0.023 µs per unit) — work the pre-S1e charge counted as 1,999,000 units, i.e. 9.4 µs
    /// per unit then (with 200 <c>System.Int32</c> parameters, the reviewer's shape: 11.9 s, 6.0 µs per old unit, now
    /// 401,999,000 units at 0.030 µs).
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_TheQuadraticShapeWithManyParameters_IsChargedByParameter_AndTruncatesWithinTheDeadline()
    {
        const int n = 1000;
        const int count = 200;
        ModelTypes.IType[] parameters = [.. Enumerable.Range(0, count).Select(k => External($"P{k:D3}" + new string('p', 90)))];
        var rendered = ModelNames.Of(CallvirtTarget("C0", "Run", parameters: parameters)).ParameterTypes;
        var shortGraph = MethodGraph.Build(MemberIndex.Build([(Unrelated(n, Subclasses.WithoutRun), TypeForwarders.None)]));
        var model = Unrelated(n, Subclasses.WithoutRun, parameters: parameters);
        var shape = MemberIndex.Build([(model, TypeForwarders.None)]);
        var reference = CallvirtTarget("C0", "Run", parameters: parameters);
        var work = new MemberIndex.DispatchWork(long.MaxValue);
        _ = shape.DispatchTargets(reference, shape.Resolve(reference), virtualSite: true, work);
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index));

        Assert.Equal(count, rendered.Count);
        Assert.All(rendered, r => Assert.Equal(2L, Units(r)));
        Assert.Equal((long)n * (1 + 2 * 2 * count) + n - 1, work.Spent);
        Assert.False(shortGraph.Coverage.Truncated, shortGraph.Coverage.TruncatedBy);
        Assert.Equal((long)n * (2 * n - 1), shortGraph.Coverage.DispatchWork);
        Assert.True(graph.Coverage.Truncated);
        Assert.StartsWith("dispatch work budget", graph.Coverage.TruncatedBy);
        Assert.Equal(GraphBudget.DefaultDispatchWork, graph.Coverage.DispatchWork);
        Assert.InRange(graph.Coverage.DispatchSites, 1, n - 1);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.Equal(StaticEdges(n, parameters: string.Join(",", rendered)), graph.Edges);
        Assert.True(elapsed < LongNamespaceDeadline, $"case K' with {count} parameters, n={n}, default budget: {elapsed.TotalMilliseconds:F0} ms; expected under {LongNamespaceDeadline.TotalSeconds} s.");
    }

    // ---- many definitions under one type id (S1f, review 4 W1-r4) -----------------------------------------------------

    /// <summary>
    /// Review 4 W1-r4, mode A: one file can carry many TypeDef rows of one name, and CCI loads every one. Here n interface
    /// definitions of the one id <c>Syn.X</c>, each declaring an abstract <c>Run()</c>, and m sites <c>callvirt Ext.Ei::Run()</c>
    /// on distinct external types (so m shapes, none memoized for another). Each shape has the n <c>X.Run</c> candidates and
    /// is charged exactly n units for them (<c>Syn.X</c> is 1 unit); the hierarchy questions about <c>Syn.X</c> are now
    /// per-id lookups, free (its supertype list is empty, and it is no class). Before S1f each of the n candidates scanned
    /// all n definitions uncharged (<c>InheritedBelow</c>'s <c>defined.Any</c>): n² per shape, so the work said n·m while
    /// the time grew as n²·m — the reviewer measured 22.4 s at n = 10,000, m = 20, i.e. about 5.6 s at this n = 5,000.
    /// <para>
    /// Asserted: no definition is lost (<c>Types("Syn.X").Count == n</c>); exactly n·m units, no Dispatch edge, every site
    /// dispatched and every static edge present, untruncated; within <see cref="DuplicateDefinitionsDeadline"/>.
    /// </para>
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_ManyInterfaceDefinitionsOfOneIdEachDeclaringTheMethod_ChargesNPerShape_AndRunsWithinTheDeadline()
    {
        const int n = 5000;
        const int m = 20;
        var index = MemberIndex.Build([(Duplicated(n, m, Duplicates.EachDeclaresRun), TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index));

        Assert.Equal(n, index.Types(DuplicateId).Count);
        Assert.All(index.Types(DuplicateId), t => Assert.IsType<ModelTypes.InterfaceDefinition>(t.Definition));
        Assert.Equal(n, index.Methods.Count(x => x.NodeId == DuplicateId + ".Run()"));
        Assert.False(graph.Coverage.Truncated, graph.Coverage.TruncatedBy);
        Assert.Equal((long)n * m, graph.Coverage.DispatchWork);
        Assert.Equal(m, graph.Coverage.DispatchSites);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.Equal(ExternalEdges(m), graph.Edges);
        Assert.True(elapsed < DuplicateDefinitionsDeadline,
            $"mode A, n={n}, m={m}: {elapsed.TotalMilliseconds:F0} ms; expected under {DuplicateDefinitionsDeadline.TotalSeconds} s.");
    }

    /// <summary>
    /// Review 4 W1-r4, mode B: n EMPTY interface definitions of <c>Syn.X</c>, one class <c>Syn.C : Object, X</c> with a
    /// virtual <c>Run()</c>, and m sites <c>callvirt Ext.Ei::Run()</c>. Each shape has one candidate, <c>C.Run</c> (1 unit),
    /// and one walk up from <c>Syn.C</c>: a step to <c>Syn.X</c> and one to <c>System.Object</c> (1 unit each), then
    /// <c>Syn.X</c>'s supertypes — before S1f a scan of all n definitions, uncharged; now one precomputed, empty list. So
    /// exactly 3 units per shape whatever n is: 3m at n = 50,000, as at n = 1. Before S1f the reviewer measured 5.6 s for
    /// this n and m (graph build only); now about 0.3 s.
    /// <para>
    /// Asserted: no definition is lost; the work is 3m at both n; no Dispatch edge (<c>C</c> is no subtype of any
    /// <c>Ei</c>), every static edge, untruncated; the graph build within <see cref="DuplicateDefinitionsDeadline"/>.
    /// </para>
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void Build_ManyEmptyDefinitionsOfOneSupertypeId_ChargesTheSameWorkWhateverTheirNumber_AndRunsWithinTheDeadline()
    {
        const int n = 50_000;
        const int m = 4000;
        var single = MethodGraph.Build(MemberIndex.Build([(Duplicated(1, m, Duplicates.Empty), TypeForwarders.None)]));
        var index = MemberIndex.Build([(Duplicated(n, m, Duplicates.Empty), TypeForwarders.None)]);

        var (graph, elapsed) = Timed(() => MethodGraph.Build(index));

        Assert.Equal(n, index.Types(DuplicateId).Count);
        Assert.False(graph.Coverage.Truncated, graph.Coverage.TruncatedBy);
        Assert.Equal(3L * m, graph.Coverage.DispatchWork);
        Assert.Equal(single.Coverage.DispatchWork, graph.Coverage.DispatchWork);
        Assert.Equal(m, graph.Coverage.DispatchSites);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.Equal(ExternalEdges(m), graph.Edges);
        Assert.True(elapsed < DuplicateDefinitionsDeadline,
            $"mode B, n={n}, m={m}: {elapsed.TotalMilliseconds:F0} ms; expected under {DuplicateDefinitionsDeadline.TotalSeconds} s.");
    }

    /// <summary>
    /// Found while verifying W1-r4: <c>MemberIndex.Build</c> was quadratic in the number of definitions sharing a name,
    /// because the fork's <c>TypeHelper.GetAllTypes</c> combined containers with <c>Union</c>, and Model hashes a type
    /// definition by its simple name alone — every one of n same-named definitions in one bucket. It now uses
    /// <c>Concat</c> (see <see cref="GetAllTypesParityTests"/> for the order). Measured before: 22 s at n = 50,000 (the
    /// reviewer, mode B); after: 0.14-0.45 s on the dev machine (S1f). n same-named definitions directly in a namespace:
    /// none is lost, and the build finishes within <see cref="DuplicateNamesIndexDeadline"/>.
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void IndexBuild_OverManySameNamedDefinitionsInANamespace_IsLinear_AndLosesNone() =>
        AssertLinearIndexBuild(nested: false);

    /// <summary>
    /// As <see cref="IndexBuild_OverManySameNamedDefinitionsInANamespace_IsLinear_AndLosesNone"/>, but the n same-named
    /// definitions are NESTED types of one class <c>Syn.Outer</c> — one file can carry that too (NestedClass rows), and
    /// the <c>ITypeDefinitionContainer</c> overload of <c>GetAllTypes</c> had the same <c>Union</c>.
    /// <para>
    /// History: in S1f this failed. Model's <c>ClassDefinition.Members</c> (and <c>StructDefinition.Members</c>) built
    /// <c>Types.Union(Fields).Union(Methods)</c>, hashing every nested type by its simple name, and
    /// <c>MemberIndex.Build</c> reads <c>Members</c> of every type for its methods, so the outer class cost n². It was
    /// measured at 9.8-25.6 s at n = 50,000. In S1g the fork's <c>Members</c> uses <c>Concat</c> (same sequence: see
    /// <see cref="GetAllTypesParityTests.Members_OfAClassOrStruct_IsNestedTypesThenFieldsThenMethods_EachOnce"/>), and
    /// the build took 0.26-0.39 s on the dev machine.
    /// </para>
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void IndexBuild_OverManySameNamedNestedTypesOfOneClass_IsLinear_AndLosesNone() =>
        AssertLinearIndexBuild(nested: true);

    private static void AssertLinearIndexBuild(bool nested)
    {
        const int n = 50_000;
        var (model, id) = SameNamed(n, nested);

        var (index, elapsed) = Timed(() => MemberIndex.Build([(model, TypeForwarders.None)]));

        Assert.Equal(n, index.Types(id).Count);
        Assert.Equal(n, index.Types(id).Select(t => t.Definition).Distinct(ReferenceEqualityComparer.Instance).Count());
        Assert.Equal(0, index.Coverage.TypesSkipped);
        Assert.True(elapsed < DuplicateNamesIndexDeadline,
            $"index build over {n} {(nested ? "nested " : "")}definitions of {id}: {elapsed.TotalMilliseconds:F0} ms; expected under {DuplicateNamesIndexDeadline.TotalSeconds} s.");
    }

    /// <summary>
    /// What S1f precomputes per id is an aggregate over EVERY definition of it, whatever their order: an id defined both
    /// as a class and as an interface may be an interface, so a site through it is NOT narrowed by parameter types (an
    /// interface may be variant) — <c>C.Run(Ext.Q)</c> is a target of <c>callvirt X::Run(Ext.P)</c>, with the interface
    /// definition first or second. The control, <c>X</c> defined only as a class, is narrowed and answers <c>[]</c>, so
    /// the case discriminates. (Over-matching costs precision only.)
    /// </summary>
    [Theory]
    [InlineData(MixedX.ClassThenInterface, new[] { "Syn.C.Run(Ext.Q)" })]
    [InlineData(MixedX.InterfaceThenClass, new[] { "Syn.C.Run(Ext.Q)" })]
    [InlineData(MixedX.ClassOnly, new string[0])]
    public void DispatchTargets_ThroughAnIdDefinedAsClassAndAsInterface_IsNotNarrowed_InEitherOrder(MixedX definitions, string[] expected)
    {
        var index = MemberIndex.Build([(Mixed(definitions), TypeForwarders.None)]);
        var reference = CallvirtTarget("X", "Run", parameters: [External("P")]);

        var targets = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true);

        Assert.Equal(definitions == MixedX.ClassOnly ? 1 : 2, index.Types(DuplicateId).Count);
        Assert.Equal(expected, targets);
    }

    /// <summary>
    /// The supertypes of an id are the union over all its definitions, whatever their order: <c>Syn.X</c> defined twice,
    /// as <c>interface X : I1</c> and <c>interface X : I2</c>, and <c>class C : Object, X</c> with <c>Run()</c>. A call
    /// through <c>I1</c> and one through <c>I2</c> both reach <c>C.Run</c> — through the first definition's supertype and
    /// through the second's, with the definitions in either order.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DispatchTargets_ThroughASupertypeOfAnyDefinitionOfAnId_ReachesItsSubtypes(bool swapped)
    {
        var index = MemberIndex.Build([(SplitSupertypes(swapped), TypeForwarders.None)]);
        var throughFirst = CallvirtTarget("I1", "Run");
        var throughSecond = CallvirtTarget("I2", "Run");

        Assert.Equal(2, index.Types(DuplicateId).Count);
        Assert.Equal([Id("C.Run()")], index.DispatchTargets(throughFirst, index.Resolve(throughFirst), virtualSite: true));
        Assert.Equal([Id("C.Run()")], index.DispatchTargets(throughSecond, index.Resolve(throughSecond), virtualSite: true));
    }

    /// <summary>
    /// S1g nit: an id's merged supertypes are ordinal-sorted, so the charged walk does not depend on TypeDef row order.
    /// <c>Syn.X</c> is defined twice, as <c>interface X : B, A</c> and <c>interface X : C, A</c>, in either row order.
    /// <c>class K : Object, X</c> has a virtual <c>Run()</c>, and the call is <c>callvirt C::Run()</c> through the own
    /// interface <c>C</c>. In both orders the answer is <c>[K.Run]</c> and the work is the same 7 units:
    /// <list type="bullet">
    /// <item><description>2 for the candidates <c>C.Run</c> and <c>K.Run</c>;</description></item>
    /// <item><description>2 for K's steps to <c>Syn.X</c> and <c>System.Object</c>;</description></item>
    /// <item><description>3 for X's steps to A, B, then the key C, its supertypes being the sorted
    /// <c>[A, B, C]</c>.</description></item>
    /// </list>
    /// Before the nit the merge kept row order, <c>[A, B, C]</c> or <c>[A, C, B]</c>, and the swapped order hit C one
    /// step sooner (6 units).
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DispatchTargets_ThroughASupertypeOfAnIdDefinedTwice_ChargesTheSameWorkInEitherRowOrder(bool swapped)
    {
        var index = MemberIndex.Build([(OverlappingSupertypes(swapped), TypeForwarders.None)]);
        var reference = CallvirtTarget("C", "Run");
        var work = new MemberIndex.DispatchWork(long.MaxValue);

        var targets = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, work);

        Assert.Equal(2, index.Types(DuplicateId).Count);
        Assert.Equal([Id("K.Run()")], targets);
        Assert.Equal(7L, work.Spent);
    }

    // ---- OpenTypes at index build (S1g, review 5 W1-r5) -------------------------------------------------------------

    /// <summary>
    /// Review 5 W1-r5, mode O: n class definitions of the one id <c>Syn.Y : System.Object</c>, and m classes
    /// <c>Syn.Ki : Syn.Y</c>. Before S1g, <c>OpenTypes</c> walked every start's base chain through every definition of
    /// each id it reached, so each of the m <c>Ki</c> read all n <c>Y</c> definitions: n·m at index build, with no
    /// budget. The reviewer measured 79.4 s at n = m = 8,000. Now each id gets one distinct base list and open-ness
    /// flows down once, so it took 0.42 s (the reviewer).
    /// <para>
    /// Asserted: no definition is lost (<c>Types("Syn.Y").Count == n</c>); nothing is open (every base is a closed root
    /// or an own closed class); the index build within <see cref="ModeODeadline"/>.
    /// </para>
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void IndexBuild_OverManyDefinitionsOfOneBaseIdAndManySubclasses_IsLinear_AndLosesNone()
    {
        const int n = 8000;
        const int m = 8000;
        var model = ManyDefinitionsOfOneBase(n, m);

        var (index, elapsed) = Timed(() => MemberIndex.Build([(model, TypeForwarders.None)]));

        Assert.Equal(n, index.Types(BaseId).Count);
        Assert.Equal(n, index.Types(BaseId).Select(t => t.Definition).Distinct(ReferenceEqualityComparer.Instance).Count());
        Assert.Equal(m + 1, index.TypeIds.Count());
        Assert.Equal(m, index.DirectSubtypes(BaseId).Count);
        Assert.Empty(index.TypeIds.Where(index.IsOpen));
        Assert.True(elapsed < ModeODeadline,
            $"mode O, n={n}, m={m}: index build {elapsed.TotalMilliseconds:F0} ms; expected under {ModeODeadline.TotalSeconds} s.");
    }

    /// <summary>
    /// Review 5 W1-r5, mode L: a chain of 20,000 own classes, <c>K0 : System.Object</c> and <c>Ki : K(i-1)</c>. Before
    /// S1g every start walked its whole chain (to the depth bound): linear times depth, about 12.4 s (the reviewer). Now
    /// one iterative Tarjan pass gives every height: 0.13 s (the reviewer).
    /// <para>
    /// Asserted: exactly the classes with 257 or more own bases above them are open, <c>K257..K19999</c>, and the top 257,
    /// <c>K0..K256</c>, are closed. That is the boundary derived and pinned in
    /// <see cref="MemberIndexOpenTypesTests.IsOpen_OnAChainOverObject_IsOpenExactlyFromTheClassWith257OwnBasesAbove"/>.
    /// Also the index build within <see cref="ModeLDeadline"/>, which is what catches a return to the pre-S1g algorithm
    /// (linear in n too, but up to 257 steps per class); a quadratic regression is caught by
    /// <see cref="IndexBuild_OverALongBaseChain_ScalesAboutLinearly"/>.
    /// </para>
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void IndexBuild_OverALongBaseChain_IsLinear_AndOpensExactlyPastTheDepthBound()
    {
        const int length = 20_000;
        var model = Chain(length);

        var (index, elapsed) = Timed(() => MemberIndex.Build([(model, TypeForwarders.None)]));

        Assert.Equal(length, index.TypeIds.Count());
        Assert.All(Enumerable.Range(0, 257), i => Assert.False(index.IsOpen(Id($"K{i}")), $"K{i} should be closed"));
        Assert.All(Enumerable.Range(257, length - 257), i => Assert.True(index.IsOpen(Id($"K{i}")), $"K{i} should be open"));
        Assert.Equal(length - 257, index.TypeIds.Count(index.IsOpen));
        Assert.True(elapsed < ModeLDeadline,
            $"mode L, length={length}: index build {elapsed.TotalMilliseconds:F0} ms; expected under {ModeLDeadline.TotalSeconds} s.");
    }

    /// <summary>
    /// Mode L's index build scales about linearly in chain length. After a warm-up build (so JIT time is not counted),
    /// chains of 10,000 and of 40,000 classes are each index-built 3 times, and the best of each is kept. The 40,000 build
    /// must take under 8 times the 10,000 one: linear gives about 4x, quadratic about 16x. Each larger chain also opens
    /// exactly its classes past the depth bound.
    /// <para>
    /// This catches a quadratic regression only. It cannot tell the pre-S1g algorithm apart: that stopped each walk at
    /// depth 257, so on a chain it cost about n × 257, also linear in n, with a ratio of about 4x. The old algorithm is
    /// caught by <see cref="ModeLDeadline"/> in
    /// <see cref="IndexBuild_OverALongBaseChain_IsLinear_AndOpensExactlyPastTheDepthBound"/> (12.4 s at 20,000 before
    /// S1g, against 5 s).
    /// </para>
    /// </summary>
    [Fact]
    [Trait("Category", "Cost")]
    public void IndexBuild_OverALongBaseChain_ScalesAboutLinearly()
    {
        _ = MemberIndex.Build([(Chain(500), TypeForwarders.None)]);   // JIT warm-up

        var small = BestIndexBuild(10_000);
        var large = BestIndexBuild(40_000);

        Assert.True(large.Ticks < 8 * small.Ticks,
            $"mode L: 10,000 classes {small.TotalMilliseconds:F0} ms, 40,000 classes {large.TotalMilliseconds:F0} ms (x{(double)large.Ticks / Math.Max(1, small.Ticks):F1}); expected under x8.");
    }

    // The fastest of 3 index builds over a fresh Chain(length), each checked for its open classes.
    private static TimeSpan BestIndexBuild(int length)
    {
        var best = TimeSpan.MaxValue;
        for (var run = 0; run < 3; run++)
        {
            var model = Chain(length);
            var (index, elapsed) = Timed(() => MemberIndex.Build([(model, TypeForwarders.None)]));
            Assert.Equal(length - 257, index.TypeIds.Count(index.IsOpen));
            best = elapsed < best ? elapsed : best;
        }
        return best;
    }

    // ---- a negative work limit (S1e nit; S1f reports the clamped limit) -----------------------------------------------

    /// <summary>A negative limit counts as 0; a new allowance has spent nothing and is not exhausted.</summary>
    [Theory]
    [InlineData(-5L)]
    [InlineData(-1L)]
    [InlineData(long.MinValue)]
    public void DispatchWork_WithANegativeLimit_HasALimitOfZero(long limit)
    {
        var work = new MemberIndex.DispatchWork(limit);

        Assert.Equal(0L, work.Limit);
        Assert.Equal(0L, work.Spent);
        Assert.False(work.Exhausted);
    }

    /// <summary>
    /// A graph build with <c>MaxDispatchWork: -1</c> over a model whose every site dispatches at a cost (n base classes,
    /// each with an overriding subclass): the first charge exhausts the clamped limit of 0, so no work is reported spent,
    /// no site is fanned out, and the build is truncated with the CLAMPED limit in its reason ("of 0", not "of -1") — and
    /// every static edge is still present. The coverage equals that of <c>MaxDispatchWork: 0</c>.
    /// </summary>
    [Fact]
    public void Build_WithANegativeDispatchWorkBudget_IsTruncatedAtZero_ReportsTheClampedLimit_AndKeepsEveryStaticEdge()
    {
        const int n = 5;
        var index = MemberIndex.Build([(Unrelated(n, Subclasses.WithRun), TypeForwarders.None)]);

        var negative = MethodGraph.Build(index, new GraphBudget(1_000_000, 5_000_000, MaxDispatchWork: -1));
        var zero = MethodGraph.Build(index, new GraphBudget(1_000_000, 5_000_000, MaxDispatchWork: 0));

        Assert.Equal(0L, negative.Coverage.DispatchWork);
        Assert.True(negative.Coverage.Truncated);
        Assert.Equal("dispatch work budget of 0 reached", negative.Coverage.TruncatedBy);
        Assert.Equal(0, negative.Coverage.DispatchSites);
        Assert.Equal(0, negative.Coverage.DispatchEdges);
        Assert.Equal(n, negative.Coverage.CallSites);
        Assert.Equal(StaticEdges(n), negative.Edges);
        Assert.Equal(zero.Coverage, negative.Coverage);
        Assert.Equal(zero.Edges, negative.Edges);
    }

    // The work one DispatchTargets call spends on a fresh index over `model`, and its answer.
    private static (long Spent, IReadOnlyList<string> Targets) Spent(Model.Assembly model, ModelTypes.MethodReference reference)
    {
        var index = MemberIndex.Build([(model, TypeForwarders.None)]);
        var work = new MemberIndex.DispatchWork(long.MaxValue);
        var targets = index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, work);
        Assert.NotNull(targets);
        return (work.Spent, targets);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    // {ns}.C0..C(n-1) : Object, each with a bodyless virtual int Run(parameters); per `subclasses`, also {ns}.Di : Ci without
    // a Run, or with its own (an override). {ns}.Callers.Go{i}() is the single instruction `callvirt Ci::Run(parameters)` at
    // SyntheticModel.CallOffset. The assembly is always Syn; the namespace {ns} is Syn unless given.
    private static Model.Assembly Unrelated(int n, Subclasses subclasses, string ns = Syn, ModelTypes.IType[]? parameters = null)
    {
        var (assembly, space) = NewAssembly(ns);
        parameters ??= [];

        var callers = Class(space, "Callers", ObjectRef);
        for (var i = 0; i < n; i++)
        {
            Virtual(Class(space, $"C{i}", ObjectRef), parameters);
            if (subclasses != Subclasses.None)
            {
                var sub = Class(space, $"D{i}", SyntheticModel.TypeRef(ns, $"C{i}", assembly: Syn));
                if (subclasses == Subclasses.WithRun)
                    Virtual(sub, parameters);
            }

            var body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode);
            body.Instructions.Add(new ModelBytecode.MethodCallInstruction(SyntheticModel.CallOffset, ModelBytecode.MethodCallOperation.Virtual, CallvirtTarget($"C{i}", "Run", ns, parameters)));
            callers.Methods.Add(new ModelTypes.MethodDefinition($"Go{i}", ModelTypes.PlatformTypes.Void) { ContainingType = callers, IsStatic = true, Body = body });
        }
        return assembly;
    }

    // Syn.I, an interface declaring an abstract int Run(parameter); Syn.Ci : Object, I with a virtual Run(parameter), and
    // Syn.Di : Ci overriding it. No callers: the tests ask DispatchTargets directly.
    private static Model.Assembly Implementing(int n, ModelTypes.IType parameter)
    {
        var (assembly, space) = NewAssembly(Syn);
        var face = new ModelTypes.InterfaceDefinition("I") { ContainingAssembly = assembly, ContainingNamespace = space };
        face.Methods.Add(new ModelTypes.MethodDefinition("Run", ModelTypes.PlatformTypes.Int32) { ContainingType = face, IsVirtual = true, IsAbstract = true });
        face.Methods[0].Parameters.Add(new ModelTypes.MethodParameter(0, "a0", parameter));
        space.Types.Add(face);
        for (var i = 0; i < n; i++)
        {
            var type = Class(space, $"C{i}", ObjectRef);
            type.Interfaces.Add(SyntheticModel.TypeRef(Syn, "I", assembly: Syn));
            Virtual(type, [parameter]);
            Virtual(Class(space, $"D{i}", SyntheticModel.TypeRef(Syn, $"C{i}", assembly: Syn)), [parameter]);
        }
        return assembly;
    }

    // The reviewer's W1-r4 probe shapes: n interface definitions of the one id Syn.X - each declaring an abstract int Run()
    // (mode A), or empty with one class Syn.C : Object, X declaring a virtual int Run() (mode B). Syn.Callers.Go{i}() is
    // the single instruction `callvirt Ext.E{i}::Run()` for i < m, each on its own type of the unindexed assembly Ext.
    private static Model.Assembly Duplicated(int n, int m, Duplicates shape)
    {
        var (assembly, space) = NewAssembly(Syn);
        for (var i = 0; i < n; i++)
        {
            var x = Interface(space, DuplicateName);
            if (shape == Duplicates.EachDeclaresRun)
                x.Methods.Add(new ModelTypes.MethodDefinition("Run", ModelTypes.PlatformTypes.Int32) { ContainingType = x, IsVirtual = true, IsAbstract = true });
        }
        if (shape == Duplicates.Empty)
        {
            var c = Class(space, "C", ObjectRef);
            c.Interfaces.Add(SyntheticModel.TypeRef(Syn, DuplicateName, assembly: Syn));
            Virtual(c);
        }

        var callers = Class(space, "Callers", ObjectRef);
        for (var i = 0; i < m; i++)
        {
            var body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode);
            body.Instructions.Add(new ModelBytecode.MethodCallInstruction(SyntheticModel.CallOffset, ModelBytecode.MethodCallOperation.Virtual, SyntheticModel.Method(External($"E{i}"), "Run")));
            callers.Methods.Add(new ModelTypes.MethodDefinition($"Go{i}", ModelTypes.PlatformTypes.Void) { ContainingType = callers, IsStatic = true, Body = body });
        }
        return assembly;
    }

    // The static edges of Duplicated(…, m, …): Callers.Go{i}() -callvirt-> Ext.E{i}.Run(), in the graph's edge order.
    private static MethodEdge[] ExternalEdges(int m) =>
        [.. Enumerable.Range(0, m)
            .Select(i => new MethodEdge(Id($"Callers.Go{i}()"), $"Ext.E{i}.Run()", MethodEdgeKind.CallVirt, SyntheticModel.CallOffset))
            .OrderBy(e => e.From, StringComparer.Ordinal)];

    // n empty interface definitions named X: directly in the namespace Syn (id Syn.X), or nested in one class Syn.Outer
    // (id Syn.Outer.X). Returns the model and that id.
    private static (Model.Assembly Model, string Id) SameNamed(int n, bool nested)
    {
        var (assembly, space) = NewAssembly(Syn);
        var outer = nested ? Class(space, "Outer", ObjectRef) : null;
        for (var i = 0; i < n; i++)
        {
            if (outer is null)
                Interface(space, DuplicateName);
            else
                outer.Types.Add(new ModelTypes.InterfaceDefinition(DuplicateName) { ContainingAssembly = assembly, ContainingNamespace = space, ContainingType = outer });
        }
        return (assembly, nested ? Id($"Outer.{DuplicateName}") : DuplicateId);
    }

    // Syn.X as a class (X : Object, with a virtual int Run(Ext.P)) and, unless ClassOnly, also as an empty interface, in
    // the order given; and Syn.C : X with a virtual int Run(Ext.Q).
    private static Model.Assembly Mixed(MixedX definitions)
    {
        var (assembly, space) = NewAssembly(Syn);
        if (definitions == MixedX.InterfaceThenClass)
            Interface(space, DuplicateName);
        Virtual(Class(space, DuplicateName, ObjectRef), [External("P")]);
        if (definitions == MixedX.ClassThenInterface)
            Interface(space, DuplicateName);
        Virtual(Class(space, "C", SyntheticModel.TypeRef(Syn, DuplicateName, assembly: Syn)), [External("Q")]);
        return assembly;
    }

    // Syn.I1 and Syn.I2, each an interface declaring an abstract int Run(); Syn.X defined twice, as `interface X : I1` and
    // `interface X : I2` (in that order unless swapped); and Syn.C : Object, X with a virtual int Run().
    private static Model.Assembly SplitSupertypes(bool swapped)
    {
        var (assembly, space) = NewAssembly(Syn);
        foreach (var name in new[] { "I1", "I2" })
        {
            var face = Interface(space, name);
            face.Methods.Add(new ModelTypes.MethodDefinition("Run", ModelTypes.PlatformTypes.Int32) { ContainingType = face, IsVirtual = true, IsAbstract = true });
        }
        foreach (var super in swapped ? new[] { "I2", "I1" } : ["I1", "I2"])
            Interface(space, DuplicateName).Interfaces.Add(SyntheticModel.TypeRef(Syn, super, assembly: Syn));
        var c = Class(space, "C", ObjectRef);
        c.Interfaces.Add(SyntheticModel.TypeRef(Syn, DuplicateName, assembly: Syn));
        Virtual(c);
        return assembly;
    }

    // Syn.A, Syn.B and Syn.C, empty interfaces but for C's abstract int Run(); Syn.X defined twice, as `interface X : B, A`
    // and `interface X : C, A` (in that row order unless swapped); and Syn.K : Object, X with a virtual int Run().
    private static Model.Assembly OverlappingSupertypes(bool swapped)
    {
        var (assembly, space) = NewAssembly(Syn);
        Interface(space, "A");
        Interface(space, "B");
        var c = Interface(space, "C");
        c.Methods.Add(new ModelTypes.MethodDefinition("Run", ModelTypes.PlatformTypes.Int32) { ContainingType = c, IsVirtual = true, IsAbstract = true });
        foreach (var first in swapped ? new[] { "C", "B" } : ["B", "C"])
        {
            var x = Interface(space, DuplicateName);
            x.Interfaces.Add(SyntheticModel.TypeRef(Syn, first, assembly: Syn));
            x.Interfaces.Add(SyntheticModel.TypeRef(Syn, "A", assembly: Syn));
        }
        var k = Class(space, "K", ObjectRef);
        k.Interfaces.Add(SyntheticModel.TypeRef(Syn, DuplicateName, assembly: Syn));
        Virtual(k);
        return assembly;
    }

    // The reviewer's W1-r5 mode O: n class definitions of Syn.Y : Object, then m classes Syn.Ki : Syn.Y.
    private static Model.Assembly ManyDefinitionsOfOneBase(int n, int m)
    {
        var (assembly, space) = NewAssembly(Syn);
        for (var i = 0; i < n; i++)
            Class(space, BaseName, ObjectRef);
        for (var i = 0; i < m; i++)
            Class(space, $"K{i}", SyntheticModel.TypeRef(Syn, BaseName, assembly: Syn));
        return assembly;
    }

    // The reviewer's W1-r5 mode L: Syn.K0 : Object, and Syn.Ki : Syn.K(i-1) for 0 < i < length.
    private static Model.Assembly Chain(int length)
    {
        var (assembly, space) = NewAssembly(Syn);
        Class(space, "K0", ObjectRef);
        for (var i = 1; i < length; i++)
            Class(space, $"K{i}", SyntheticModel.TypeRef(Syn, $"K{i - 1}", assembly: Syn));
        return assembly;
    }

    private static ModelTypes.InterfaceDefinition Interface(Model.Namespace space, string name)
    {
        var type = new ModelTypes.InterfaceDefinition(name) { ContainingAssembly = (Model.Assembly)space.ContainingAssembly, ContainingNamespace = space };
        space.Types.Add(type);
        return type;
    }

    private static (Model.Assembly Assembly, Model.Namespace Space) NewAssembly(string ns)
    {
        var assembly = new Model.Assembly(Syn);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace(ns) { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;
        return (assembly, space);
    }

    // The static edges of Unrelated(n, …, ns): Callers.Go{i}() -callvirt-> Ci.Run(parameters), with the parameter list as
    // rendered, in the graph's (ordinal) edge order.
    private static MethodEdge[] StaticEdges(int n, string ns = Syn, string parameters = "") =>
        [.. Enumerable.Range(0, n)
            .Select(i => new MethodEdge(Id($"Callers.Go{i}()", ns), Id($"C{i}.Run({parameters})", ns), MethodEdgeKind.CallVirt, SyntheticModel.CallOffset))
            .OrderBy(e => e.From, StringComparer.Ordinal)];

    private static ModelTypes.ClassDefinition Class(Model.Namespace space, string name, ModelTypes.IBasicType @base)
    {
        var type = new ModelTypes.ClassDefinition(name) { ContainingAssembly = (Model.Assembly)space.ContainingAssembly, ContainingNamespace = space, Base = @base };
        space.Types.Add(type);
        return type;
    }

    // A bodyless instance virtual int Run(parameters).
    private static void Virtual(ModelTypes.ClassDefinition type, ModelTypes.IType[]? parameters = null)
    {
        var run = new ModelTypes.MethodDefinition("Run", ModelTypes.PlatformTypes.Int32) { ContainingType = type, IsVirtual = true };
        foreach (var (parameter, k) in (parameters ?? []).Select((p, k) => (p, k)))
            run.Parameters.Add(new ModelTypes.MethodParameter((ushort)k, $"a{k}", parameter));
        type.Methods.Add(run);
    }

    private static ModelTypes.MethodReference CallvirtTarget(string type, string method, string ns = Syn, ModelTypes.IType[]? parameters = null) =>
        SyntheticModel.Method(SyntheticModel.TypeRef(ns, type, assembly: Syn), method, parameters ?? []);

    // An external class reference Ext.{name} in the unindexed assembly Ext, for a parameter type of a chosen length.
    private static ModelTypes.BasicType External(string name) => SyntheticModel.TypeRef("Ext", name, assembly: "Ext");

    // The DispatchWork units for text of this length, as documented on MemberIndex.DispatchWork: one per 64 characters, at least one.
    private static long Units(string text) => 1 + text.Length / 64;

    private static string Id(string nameWithoutNamespace, string ns = Syn) => $"{ns}.{nameWithoutNamespace}";

    // Runs on a worker with a deadline (a hang fails the test, not the run) and times it.
    private static (T Result, TimeSpan Elapsed) Timed<T>(Func<T> run)
    {
        var task = Task.Run(() =>
        {
            var watch = Stopwatch.StartNew();
            var result = run();
            return (result, watch.Elapsed);
        });
        Assert.True(task.Wait(TimeSpan.FromSeconds(60)), "the build did not finish within 60 s");
        return task.Result;
    }
    #endregion

    #region Fields
    private const string Syn = "Syn";

    // The size of the determinism model: base classes, each with an overriding subclass.
    private const int Overridden = 200;

    // The deadline for case K' with long names under the default budget: 20,000,000 units at 1 µs each, twice the slowest
    // unit measured (short ids, 0.5 µs); after S1e a long-named unit measured 0.02-0.16 µs (3.1 s and 1.0 s).
    private static readonly TimeSpan LongNamespaceDeadline = TimeSpan.FromSeconds(20);

    // The name, and id, defined many times over by the W1-r4 shapes.
    private const string DuplicateName = "X";
    private const string DuplicateId = $"{Syn}.{DuplicateName}";

    // The deadline for the graph builds of modes A and B (review 4 W1-r4). Measured on the dev machine (S1f), three runs
    // each: mode A (n = 5,000, m = 20) 31-82 ms, mode B (n = 50,000, m = 4,000) 53-187 ms. Before S1f: mode B 5.6 s at the
    // same n and m, mode A about 5.6 s (22.4 s measured at n = 10,000; n² per shape). 2 s is over 10 times the slowest
    // run now, and under half of either before.
    private static readonly TimeSpan DuplicateDefinitionsDeadline = TimeSpan.FromSeconds(2);

    // The deadline for an index build over 50,000 same-named definitions. In a namespace: 0.14-0.45 s on the dev machine
    // (S1f; the reviewer: 0.55 s) and 0.33-0.37 s (S1g); before the GetAllTypes fix, 22 s. Nested in one class: 0.26-0.39 s
    // (S1g); before the Members fix, 9.8-25.6 s (S1f). 5 s is over 10 times the slowest run now, and under half of the
    // fastest before.
    private static readonly TimeSpan DuplicateNamesIndexDeadline = TimeSpan.FromSeconds(5);

    // The deadline for mode O's index build (review 5 W1-r5, n = m = 8,000). Measured on the dev machine (S1g), three runs:
    // 252-336 ms (the reviewer: 0.42 s); before S1g, 79.4 s (the reviewer). 5 s is over 10 times the slowest run now, and
    // under a fifteenth of before.
    private static readonly TimeSpan ModeODeadline = TimeSpan.FromSeconds(5);

    // The deadline for mode L's index build (review 5 W1-r5, a 20,000-class chain). Measured on the dev machine (S1g), six
    // runs: 0.60-0.96 s (the reviewer: 0.13 s), mostly first-build cost; warm, the best of 3 builds of a 40,000-class chain
    // took 0.67-0.73 s, and 40,000 over 10,000 grew x2.3-x3.5 (IndexBuild_OverALongBaseChain_ScalesAboutLinearly).
    // Before S1g, 12.4 s (the reviewer). 5 s is over 5 times the slowest run now, and under half of before. This deadline,
    // not the scaling test, is what catches a return to the old algorithm: it stopped each walk at depth 257, so on a
    // chain it cost about n x 257, linear in n, and its 10,000 to 40,000 ratio would be about x4, under the scaling
    // test's x8. The scaling test catches a quadratic regression only.
    private static readonly TimeSpan ModeLDeadline = TimeSpan.FromSeconds(5);

    // The base id of mode O (review 5 W1-r5), defined many times over.
    private const string BaseName = "Y";
    private const string BaseId = $"{Syn}.{BaseName}";

    private static ModelTypes.BasicType ObjectRef => SyntheticModel.TypeRef("System", "Object", assembly: "System.Private.CoreLib");
    #endregion

    #region Child types
    /// <summary>How <see cref="DispatchTargets_ThroughAnIdDefinedAsClassAndAsInterface_IsNotNarrowed_InEitherOrder"/> defines <c>Syn.X</c>.</summary>
    public enum MixedX
    {
        ClassThenInterface,
        InterfaceThenClass,
        ClassOnly,
    }

    private enum Subclasses
    {
        None,
        WithoutRun,
        WithRun,
    }

    // The W1-r4 probe's modes: A, every definition of Syn.X declares Run; B, none does.
    private enum Duplicates
    {
        EachDeclaresRun,
        Empty,
    }
    #endregion
}
