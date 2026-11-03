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
/// phase at which they hold: at <see cref="Phase.A1"/> the static-target graph already satisfies 65 of the 79 path
/// rows and the opacity row; the rest are pinned as pending, and must still FAIL on today's graph — so a row that
/// starts passing early is noticed and promoted, and none can disappear silently. Bumping <c>CurrentPhase</c> to
/// <see cref="Phase.A2"/> is the red-to-green moment of phase A2.
/// </summary>
public sealed class MechanismGroundTruthTests
{
    /// <summary>
    /// Path rows per <see cref="MechanismPath.ActiveFrom"/>, measured from the table. A row added, removed or
    /// re-phased changes this deliberately — never as a side effect. A2 = the 13 rows needing A2 edges (CHA x7,
    /// state machine x4, type initializer x2); Reachability = the bodyless-extern capability row. A1 went 63 -> 65
    /// with S1's two ExpressionTree rows (KnownGap CompilesEnvTree + its Absent twin), both true on the static graph
    /// today: the gap holds because no instruction but <c>ldtoken</c> names the sink.
    /// </summary>
    private static readonly Dictionary<Phase, int> pathRowsPerPhase = new()
    {
        [Phase.A1] = 65,
        [Phase.A2] = 13,
        [Phase.Reachability] = 1,
    };

    /// <summary>
    /// Path rows per expectation, measured from the table. S1 added ExpressionTree.CompilesEnvTree (KnownGap 4 -> 5)
    /// and its twin ExpressionTree.CompilesSafeTree (Absent 35 -> 36).
    /// </summary>
    private static readonly Dictionary<Expectation, int> pathRowsPerExpectation = new()
    {
        [Expectation.Present] = 35,
        [Expectation.Absent] = 36,
        [Expectation.KnownImprecision] = 3,
        [Expectation.KnownGap] = 5,
    };

    /// <summary>The rows that wait for phase A2's edges, by id — the A1 graph cannot satisfy any of them.</summary>
    private static readonly string[] pendingA2Rows =
    [
        // CHA fan-out (callvirt to own overrides / implementors, including through a platform-declared virtual).
        "Interface.CallsThroughInterface", "Interface.ShouldHaveNoCapability", "Virtual.CallsThroughBase", "TypeTest.CallsMaybeTouch",
        "Generics.ConstrainedCall", "Iterator.Consumer", "Iterator.ConsumerOfSafeSequence",
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
    public void CurrentPhase_IsA1_AndActivatesEveryRowTheStaticGraphSatisfies()
    {
        Assert.Equal(Phase.A1, MechanismGroundTruth.CurrentPhase);
        Assert.Equal(pathRowsPerPhase[Phase.A1], MechanismGroundTruth.ActivePaths.Count);
        Assert.Equal(["Opacity.FunctionPointerCalli"], MechanismGroundTruth.ActiveOpacities.Select(o => o.Id));
    }

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
