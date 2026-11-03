namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Spec §1.5 test 4 — the ground-truth path theory, <b>gated</b> on <see cref="MechanismGroundTruth.CurrentPhase"/>:
/// every row with <c>ActiveFrom &lt;= CurrentPhase</c> is evaluated against the real <see cref="MethodGraph"/> (via
/// <see cref="MechanismGraphSource"/>) by <see cref="WaypointMatcher.Evaluate"/>. Rows are tagged with the EARLIEST
/// phase at which they hold, and the ratchet moves in slices: at <see cref="Phase.A1"/> the static-target graph
/// satisfied 65 of the 79 A1-era path rows and the opacity row; A2's first slice (<see cref="Phase.A2Dispatch"/>,
/// CHA fan-out) activated the seven CHA rows and its own twelve dispatch rows. The rest are pinned as pending, and
/// must still FAIL on today's graph — so a row that starts passing early is noticed and promoted, and none can
/// disappear silently. Bumping <c>CurrentPhase</c> to <see cref="Phase.A2"/> is the red-to-green moment of the
/// state-machine and type-initializer edges.
/// </summary>
public sealed class MechanismGroundTruthTests
{
    /// <summary>
    /// Path rows per <see cref="MechanismPath.ActiveFrom"/>, measured from the table. A row added, removed or
    /// re-phased changes this deliberately — never as a side effect. A1 went 63 -> 65 with A1-S1's two ExpressionTree
    /// rows. A2 S1 re-tagged the seven CHA rows (Interface x2, Virtual, TypeTest, Generics, Iterator x2) from A2 to
    /// A2Dispatch (A2 13 -> 6: the state machine x4 and type initializer x2 rows still pending), and A2Dispatch's 22 =
    /// those 7 + the 12 S1 dispatch rows (ObjectVirtual x3, ExplicitImpl x2, GenericInterface x2, StaticAbstract x2,
    /// OpenHierarchy x3) + S1b's 3 InheritedImpl rows (review C1). Reachability = the bodyless-extern capability row.
    /// </summary>
    private static readonly Dictionary<Phase, int> pathRowsPerPhase = new()
    {
        [Phase.A1] = 65,
        [Phase.A2Dispatch] = 22,
        [Phase.A2] = 6,
        [Phase.Reachability] = 1,
    };

    /// <summary>
    /// Path rows per expectation, measured from the table. A1-S1 added ExpressionTree.CompilesEnvTree (KnownGap 4 -> 5)
    /// and its twin ExpressionTree.CompilesSafeTree (Absent 35 -> 36). A2-S1 added 5 Present (one per dispatch
    /// mechanism), 5 Absent (ObjectVirtual.DescribesNumber, ExplicitImpl, GenericInterface and StaticAbstract twins,
    /// OpenHierarchy.FlushesJournal) and 2 KnownImprecision (the ObjectVirtual and OpenHierarchy twin drivers). S1b
    /// added InheritedImpl's 2 Present and 1 Absent.
    /// </summary>
    private static readonly Dictionary<Expectation, int> pathRowsPerExpectation = new()
    {
        [Expectation.Present] = 42,
        [Expectation.Absent] = 42,
        [Expectation.KnownImprecision] = 5,
        [Expectation.KnownGap] = 5,
    };

    /// <summary>The rows CHA fan-out (A2 S1) activated, by id — every one failed on the A1 graph.</summary>
    private static readonly string[] a2DispatchRows =
    [
        // The seven CHA rows pending since A1 (callvirt to own overrides / implementors, including through a
        // platform-declared virtual).
        "Interface.CallsThroughInterface", "Interface.ShouldHaveNoCapability", "Virtual.CallsThroughBase", "TypeTest.CallsMaybeTouch",
        "Generics.ConstrainedCall", "Iterator.Consumer", "Iterator.ConsumerOfSafeSequence",
        // The S1 dispatch mechanisms (cha-a2-dispatch-and-implicit-edges.md §8).
        "ObjectVirtual.DescribesEnv", "ObjectVirtual.DescribesSafe", "ObjectVirtual.DescribesNumber",
        "ExplicitImpl.CallsExplicit", "ExplicitImpl.CallsSafeExplicit",
        "GenericInterface.ComparesThroughInterface", "GenericInterface.ComparesThroughSafeInterface",
        "StaticAbstract.BuildsEnv", "StaticAbstract.BuildsSafe",
        "OpenHierarchy.FlushesEnvStream", "OpenHierarchy.FlushesSafeStream", "OpenHierarchy.FlushesJournal",
        // S1b (review C1): an interface slot filled by an inherited method.
        "InheritedImpl.CallsInherited", "InheritedImpl.CallsPlainInherited", "InheritedImpl.CallsSafeInherited",
    ];

    /// <summary>The rows that still wait for phase A2's later edges, by id — today's graph cannot satisfy any of them.</summary>
    private static readonly string[] pendingA2Rows =
    [
        // State-machine edges (stub -> MoveNext).
        "Async.Method", "Async.Lambda", "Async.LocalFunction", "Iterator.Stub",
        // Type-initializer edges (static member reference -> .cctor).
        "StaticInit.TriggersInit", "StaticInit.TriggersExplicitInit",
    ];

    public static TheoryData<string> ActivePathRows() =>
        Ids(MechanismGroundTruth.ActivePaths.Select(p => p.Id));

    public static TheoryData<string> ActiveOpacityRows() =>
        Ids(MechanismGroundTruth.ActiveOpacities.Select(o => o.Id));

    public static TheoryData<string> PendingPathRows() =>
        Ids(MechanismGroundTruth.Paths.Where(p => p.ActiveFrom > MechanismGroundTruth.CurrentPhase).Select(p => p.Id));

    [Theory]
    [MemberData(nameof(ActivePathRows))]
    public void GroundTruthPath_HoldsInTheCallGraph(string id)
    {
        if (id == NoRows)
        {
            Assert.Empty(MechanismGroundTruth.ActivePaths);
            return;
        }

        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.True(verdict.Holds, $"{verdict.Detail} Note: {row.Note}");
    }

    /// <summary>
    /// Every row tagged for a LATER phase genuinely fails on today's graph: the tag is the earliest phase at which the
    /// row holds. If one of these starts passing (an edge landed early, or a waypoint went slack), re-tag it.
    /// </summary>
    [Theory]
    [MemberData(nameof(PendingPathRows))]
    public void PendingPath_DoesNotYetHoldInTheCallGraph(string id)
    {
        if (id == NoRows)
        {
            Assert.DoesNotContain(MechanismGroundTruth.Paths, p => p.ActiveFrom > MechanismGroundTruth.CurrentPhase);
            return;
        }

        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.False(verdict.Holds,
            $"{row.Id} is tagged {row.ActiveFrom} but already holds at {MechanismGroundTruth.CurrentPhase}: {verdict.Detail} " +
            "Re-tag it to the earliest phase at which it holds (never change its Expect).");
    }

    public static TheoryData<string> DispatchDependentPathRows() =>
        Ids(MechanismGroundTruth.Paths
            .Where(p => p.ActiveFrom == Phase.A2Dispatch && p.Expect is Expectation.Present or Expectation.KnownImprecision)
            .Select(p => p.Id));

    /// <summary>
    /// Keeps the A2Dispatch tag honest now that its rows are active: every path row it asserts present FAILS once the
    /// <see cref="MethodEdgeKind.Dispatch"/> edges are taken out of the very same graph — so it holds because of CHA,
    /// and was rightly not an A1 row.
    /// </summary>
    [Theory]
    [MemberData(nameof(DispatchDependentPathRows))]
    public void A2DispatchPath_DoesNotHoldWithoutTheDispatchEdges(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.BuildStatic();

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.False(verdict.Holds, $"{row.Id} holds without any Dispatch edge: {verdict.Detail} It is not about CHA - re-tag it.");
    }

    [Theory]
    [MemberData(nameof(ActiveOpacityRows))]
    public void GroundTruthOpacity_IsRecordedAtItsSite(string id)
    {
        if (id == NoRows)
        {
            Assert.Empty(MechanismGroundTruth.ActiveOpacities);
            return;
        }

        var row = MechanismGroundTruth.Opacities.Single(o => o.Id == id);
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);
        var site = new Regex(row.Site);

        Assert.Contains(graph.Opacities, o => site.IsMatch(o.Site) && o.Kind == row.Kind);
    }

    [Fact]
    public void CurrentPhase_IsA2Dispatch_AndActivatesTheStaticAndTheChaRows()
    {
        Assert.Equal(Phase.A2Dispatch, MechanismGroundTruth.CurrentPhase);
        Assert.Equal(pathRowsPerPhase[Phase.A1] + pathRowsPerPhase[Phase.A2Dispatch], MechanismGroundTruth.ActivePaths.Count);
        Assert.Equal(["Opacity.FunctionPointerCalli"], MechanismGroundTruth.ActiveOpacities.Select(o => o.Id));
    }

    /// <summary>The ratchet's order: A2's first slice sits strictly between A1 and the whole of A2.</summary>
    [Fact]
    public void Phase_A2Dispatch_IsOrderedBetweenA1AndA2() =>
        Assert.True(Phase.A1 < Phase.A2Dispatch && Phase.A2Dispatch < Phase.A2 && Phase.A2 < Phase.A2Multi);

    [Fact]
    public void PendingPathRows_PerPhase_ArePinned()
    {
        var pending = MechanismGroundTruth.Paths
            .Where(p => p.ActiveFrom > MechanismGroundTruth.CurrentPhase)
            .GroupBy(p => p.ActiveFrom)
            .ToDictionary(g => g.Key, g => g.Count());
        var expected = pathRowsPerPhase
            .Where(e => e.Key > MechanismGroundTruth.CurrentPhase)
            .ToDictionary(e => e.Key, e => e.Value);

        Assert.Equal(expected.OrderBy(e => e.Key), pending.OrderBy(e => e.Key));
    }

    [Fact]
    public void PendingA2Rows_AreExactlyTheRowsThatNeedA2Edges()
    {
        Assert.Equal(
            pendingA2Rows.Order(StringComparer.Ordinal),
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.A2).Select(p => p.Id).Order(StringComparer.Ordinal));
        Assert.Equal(
            a2DispatchRows.Order(StringComparer.Ordinal),
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.A2Dispatch).Select(p => p.Id).Order(StringComparer.Ordinal));
        Assert.Equal(
            ["Opacity.PInvokeCapability"],
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.Reachability).Select(p => p.Id));
    }

    [Fact]
    public void PathRows_PerPhaseAndPerExpectation_ArePinned()
    {
        Assert.Equal(
            pathRowsPerPhase.OrderBy(e => e.Key),
            MechanismGroundTruth.Paths.GroupBy(p => p.ActiveFrom).ToDictionary(g => g.Key, g => g.Count()).OrderBy(e => e.Key));
        Assert.Equal(
            pathRowsPerExpectation.OrderBy(e => e.Key),
            MechanismGroundTruth.Paths.GroupBy(p => p.Expect).ToDictionary(g => g.Key, g => g.Count()).OrderBy(e => e.Key));
    }

    [Fact]
    public void PendingOpacityRows_AreNone() =>
        Assert.DoesNotContain(MechanismGroundTruth.Opacities, o => o.ActiveFrom > MechanismGroundTruth.CurrentPhase);

    /// <summary>
    /// The seam is the real graph over BOTH fixture assemblies — not a stub: the Dependency's method is a node with
    /// its sink as successor, and every adjacency key is a node.
    /// </summary>
    [Fact]
    public void GraphSource_IsTheRealGraph_OverBothFixtureAssemblies()
    {
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);

        Assert.Equal(
            ["System.Environment.GetEnvironmentVariable(System.String)"],
            graph.Adjacency["MechanismFixture.Dependency.EnvReader.Read()"]);
        Assert.Contains("MechanismFixture.CrossAssembly.Callers.UsesDependency()", graph.Adjacency.Keys);
        Assert.All(graph.Adjacency.Values.SelectMany(s => s), successor => Assert.True(graph.Adjacency.ContainsKey(successor), successor));
        Assert.Same(graph, MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase));
    }

    /// <summary>
    /// Only platform (External) nodes are classified, by the built-in map; an own node never is — not even the
    /// P/Invoke extern, whose NativeInterop belongs to the reachability ADR (row Opacity.PInvokeCapability).
    /// </summary>
    [Theory]
    [InlineData("System.Environment.GetEnvironmentVariable(System.String)", Capability.EnvironmentProbe)]
    [InlineData("System.Reflection.MethodBase.Invoke(System.Object,System.Object[])", Capability.ReflectionInvocation)]
    [InlineData("System.String.Concat(System.String,System.String)", null)]
    [InlineData("MechanismFixture.Opacity.Native.getpid()", null)]
    [InlineData("MechanismFixture.Direct.Probes.ReadsEnv()", null)]
    [InlineData("No.Such.Node()", null)]
    public void GraphSource_ClassifiesOnlyPlatformNodes(string nodeId, Capability? expected) =>
        Assert.Equal(expected, MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase).CapabilityOf(nodeId));

    [Fact]
    public void GraphSource_RefusesReachability_WhoseExternRuleItDoesNotModel() =>
        Assert.Throws<NotSupportedException>(() => MechanismGraphSource.Build(Phase.Reachability));

    // xUnit 2 fails a theory whose data source is empty ("No data found"), so an empty set is represented by one
    // sentinel case that asserts the emptiness itself - never by a silently passing row.
    private static TheoryData<string> Ids(IEnumerable<string> ids)
    {
        var data = new TheoryData<string>();
        foreach (var id in ids)
            data.Add(id);
        if (data.Count == 0)
            data.Add(NoRows);
        return data;
    }

    private const string NoRows = "(no rows in this set at the current phase)";
}
