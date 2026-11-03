namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase A1 acceptance criterion 6 (determinism) and the two ways a build can see less than everything — the
/// <see cref="GraphBudget"/> and an unreadable body — each of which must be REPORTED (truncation, opacity, coverage),
/// never a silently partial graph (ADR-0020 decision 8: "could not analyze" must never read as "no capability").
/// </summary>
public sealed class MethodGraphRobustnessTests : IClassFixture<MechanismMethodGraphFixture>
{
    #region Constructors
    public MethodGraphRobustnessTests(MechanismMethodGraphFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- acceptance 6: determinism -----------------------------------------------------------------------------

    /// <summary>Two INDEPENDENT loads (fresh hosts, fresh index) give identical node, edge, opacity and coverage sequences.</summary>
    [Fact]
    public void Build_TwiceFromIndependentLoads_IsIdentical()
    {
        using var again = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        var index = again.Index();
        var graph = MethodGraph.Build(index);

        AssertIdentical(fixture.Graph, graph);
        Assert.Equal(fixture.Index.Methods.Select(m => (m.Assembly, m.NodeId)), index.Methods.Select(m => (m.Assembly, m.NodeId)));
        Assert.Equal(fixture.Index.TypeIds, index.TypeIds);
        Assert.All(index.TypeIds, id => Assert.Equal(fixture.Index.DirectSubtypes(id), index.DirectSubtypes(id)));
    }

    /// <summary>The order the assemblies are handed over in does not leak into the graph.</summary>
    [Fact]
    public void Build_WithTheAssembliesInReverseOrder_IsIdentical()
    {
        using var reversed = ModelAssemblies.Load(MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.Fixture);

        AssertIdentical(fixture.Graph, MethodGraph.Build(reversed.Index()));
    }

    [Fact]
    public void Build_TwiceOverTheSameIndex_IsIdentical() =>
        AssertIdentical(fixture.Graph, MethodGraph.Build(fixture.Index));

    // ---- budget ------------------------------------------------------------------------------------------------

    /// <summary>A budget exactly the size of the graph is enough: the boundary is inclusive, and nothing is lost.</summary>
    [Fact]
    public void Build_WithABudgetExactlyTheGraphsSize_IsNotTruncated()
    {
        var exact = MethodGraph.Build(fixture.Index, new GraphBudget(fixture.Graph.Nodes.Count, fixture.Graph.Edges.Count));

        AssertIdentical(fixture.Graph, exact);
        Assert.False(exact.Coverage.Truncated);
    }

    [Fact]
    public void Build_OneNodeShortOfTheBudget_IsTruncatedByNodes()
    {
        var max = fixture.Graph.Nodes.Count - 1;

        var graph = MethodGraph.Build(fixture.Index, new GraphBudget(max, int.MaxValue));

        Assert.True(graph.Coverage.Truncated);
        Assert.Equal($"nodes budget of {max} reached", graph.Coverage.TruncatedBy);
        Assert.True(graph.Nodes.Count <= max, $"{graph.Nodes.Count} nodes exceed the budget of {max}.");
    }

    [Fact]
    public void Build_OneEdgeShortOfTheBudget_IsTruncatedByEdges()
    {
        var max = fixture.Graph.Edges.Count - 1;

        var graph = MethodGraph.Build(fixture.Index, new GraphBudget(int.MaxValue, max));

        Assert.True(graph.Coverage.Truncated);
        Assert.Equal($"edges budget of {max} reached", graph.Coverage.TruncatedBy);
        Assert.True(graph.Edges.Count <= max, $"{graph.Edges.Count} edges exceed the budget of {max}.");
        Assert.Equal(max, graph.Edges.Count);
    }

    /// <summary>
    /// A tiny budget: the own nodes alone exhaust it, so no body is walked at all — and the coverage says so
    /// (truncated, nothing read) rather than presenting an empty graph as a clean one.
    /// </summary>
    [Theory]
    [InlineData(0, 0)]
    [InlineData(5, 5)]
    [InlineData(5, 1_000_000)]
    public void Build_WithATinyNodeBudget_IsTruncated_AndSaysNothingWasWalked(int maxNodes, int maxEdges)
    {
        var graph = MethodGraph.Build(fixture.Index, new GraphBudget(maxNodes, maxEdges));

        Assert.True(graph.Coverage.Truncated);
        Assert.Equal($"nodes budget of {maxNodes} reached", graph.Coverage.TruncatedBy);
        Assert.True(graph.Nodes.Count <= maxNodes);
        Assert.True(graph.Edges.Count <= maxEdges);
        Assert.Equal(0, graph.Coverage.BodiesRead);
        Assert.Equal(fixture.Index.Methods.Count, graph.Coverage.MethodsIndexed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public void Build_WithATinyEdgeBudget_IsTruncated_AndNeverExceedsIt(int maxEdges)
    {
        var graph = MethodGraph.Build(fixture.Index, new GraphBudget(int.MaxValue, maxEdges));

        Assert.True(graph.Coverage.Truncated);
        Assert.Equal($"edges budget of {maxEdges} reached", graph.Coverage.TruncatedBy);
        Assert.Equal(maxEdges, graph.Edges.Count);
        Assert.True(graph.Coverage.BodiesRead < fixture.Graph.Coverage.BodiesRead, "A truncated build must stop walking bodies.");
    }

    [Fact]
    public void Build_WithTheDefaultBudget_IsNotTruncated()
    {
        Assert.Equal(GraphBudget.Default, new GraphBudget(1_000_000, 5_000_000));
        Assert.False(fixture.Graph.Coverage.Truncated);
        AssertIdentical(fixture.Graph, MethodGraph.Build(fixture.Index, GraphBudget.Default));
    }

    /// <summary>
    /// The default CHA work budget (A2 S1d): 20,000,000 units, about 100 times what the largest measured assembly
    /// spends (Microsoft.CodeAnalysis.CSharp 4.14, 202,824) — and the fixture graph spends some, but far less.
    /// </summary>
    [Fact]
    public void Build_WithTheDefaultBudget_HasTheDefaultDispatchWork_AndSpendsSomeOfIt()
    {
        Assert.Equal(20_000_000L, GraphBudget.DefaultDispatchWork);
        Assert.Equal(GraphBudget.DefaultDispatchWork, GraphBudget.Default.MaxDispatchWork);
        Assert.Equal(GraphBudget.DefaultDispatchWork, new GraphBudget(1, 1).MaxDispatchWork);
        Assert.InRange(fixture.Graph.Coverage.DispatchWork, 1, GraphBudget.DefaultDispatchWork - 1);
    }

    /// <summary>
    /// A2 S1d: a dispatch work budget of ZERO stops only the fan-out. The graph has no Dispatch edge, every other edge
    /// is exactly the default build's (static edges never depend on CHA), and so are the nodes, opacities, call sites
    /// and resolutions — but it is truncated, and says so with the dispatch reason, having spent nothing.
    /// </summary>
    [Fact]
    public void Build_WithNoDispatchWork_HasNoDispatchEdges_ButEveryStaticEdge()
    {
        Assert.Contains(fixture.Graph.Edges, e => e.Kind == MethodEdgeKind.Dispatch);

        var graph = MethodGraph.Build(fixture.Index, new GraphBudget(1_000_000, 5_000_000, MaxDispatchWork: 0));

        Assert.DoesNotContain(graph.Edges, e => e.Kind == MethodEdgeKind.Dispatch);
        Assert.Equal(fixture.Graph.Edges.Where(e => e.Kind != MethodEdgeKind.Dispatch), graph.Edges);
        Assert.Equal(fixture.Graph.Nodes, graph.Nodes);
        Assert.Equal(fixture.Graph.Opacities, graph.Opacities);
        Assert.True(graph.Coverage.Truncated);
        Assert.Equal("dispatch work budget of 0 reached", graph.Coverage.TruncatedBy);
        Assert.Equal(0L, graph.Coverage.DispatchWork);
        Assert.Equal(0, graph.Coverage.DispatchEdges);
        Assert.Equal(fixture.Graph.Coverage with { DispatchSites = graph.Coverage.DispatchSites, DispatchEdges = 0, DispatchWork = 0, Truncated = true, TruncatedBy = graph.Coverage.TruncatedBy },
            graph.Coverage);
    }

    // ---- an unreadable body ------------------------------------------------------------------------------------

    /// <summary>
    /// A body that is no longer bytecode (here: already lifted to three-address code by
    /// <see cref="AssemblyDisassembler.DisassembleMethod"/>, as a capability scan sharing the host would do) cannot
    /// be walked by A1. It becomes a <see cref="OpacityKind.BodyUnreadable"/> record and a failed body in the
    /// coverage; the method stays a node, and every other body is still walked.
    /// </summary>
    [Fact]
    public void Build_WhenABodyIsNotBytecode_RecordsBodyUnreadable_AndKeepsGoing()
    {
        using var assemblies = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        var index = assemblies.Index();
        var target = index.Methods.Single(m => m.NodeId == ReadsEnv);
        var fixtureAssembly = assemblies.Disassemblers.Single(d => d.Assembly.Name == MechanismFixtureAssemblies.FixtureName);
        var lifted = fixtureAssembly.DisassembleMethod(target.Definition);
        Assert.True(lifted.IsSuccess, lifted.Message);

        var graph = MethodGraph.Build(index);

        var opacity = Assert.Single(graph.Opacities, o => o.Kind == OpacityKind.BodyUnreadable);
        Assert.Equal(ReadsEnv, opacity.Site);
        Assert.Contains("ThreeAddressCode", opacity.Detail, StringComparison.Ordinal);
        Assert.Equal(1, graph.Coverage.BodiesFailed);
        Assert.Equal(fixture.Graph.Coverage.BodiesRead - 1, graph.Coverage.BodiesRead);
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(ReadsEnv)?.Kind);
        Assert.Empty(graph.Successors(ReadsEnv));
        Assert.Equal(fixture.Graph.Edges.Count - fixture.Graph.Successors(ReadsEnv).Count, graph.Edges.Count);
        Assert.False(graph.Coverage.Truncated);
    }

    private static void AssertIdentical(MethodGraph expected, MethodGraph actual)
    {
        Assert.Equal(expected.Nodes, actual.Nodes);
        Assert.Equal(expected.Edges, actual.Edges);
        Assert.Equal(expected.Opacities, actual.Opacities);
        Assert.Equal(expected.Coverage, actual.Coverage);
    }
    #endregion

    #region Fields
    private const string ReadsEnv = "MechanismFixture.Direct.Probes.ReadsEnv()";

    private readonly MechanismMethodGraphFixture fixture;
    #endregion
}
