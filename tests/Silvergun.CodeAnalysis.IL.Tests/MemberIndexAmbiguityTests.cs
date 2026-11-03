namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase A1 acceptance criterion 4: an ambiguous reference yields <see cref="ResolutionKind.Ambiguous"/>, never an
/// exception (Analysis.Net's own <c>Methods.SingleOrDefault(MatchSignature)</c> THROWS here — spec §2.1), and the
/// graph keeps the site: an <see cref="OpacityKind.Ambiguous"/> record AND an edge to EVERY candidate (S1, spec §2.5:
/// over-approximate, never pick one and drop the rest).
/// <para>
/// <b>Synthetic, by construction:</b> the same assembly file is loaded twice, each into its own Analysis.Net host
/// (two distinct <c>Model.Assembly</c> instances — not W3's same-instance case, which must NOT be ambiguous; see
/// <see cref="MemberIndexCoverageTests"/>), and both copies are indexed together. Every own type and method then has
/// two definitions with one node id in one assembly name — spec §2.2's "two indexed definitions with one node id and
/// one assembly ⇒ Ambiguous". Both resolution branches are covered: the exact-node-id branch (a reference whose
/// declaring type is not an instantiation) and the substituted branch (a reference through an instantiation). The
/// Dependency stays single, so references into it must still resolve.
/// </para>
/// <para>
/// <see cref="MethodResolution.Candidates"/> holds the DISTINCT node ids of the matching definitions. Two copies of
/// one definition share a node id, so a doubled definition yields ONE candidate id (and the graph, which merges them
/// into one node, one edge) — only genuinely different definitions (<c>Overloads&lt;int&gt;.M</c>) yield two.
/// </para>
/// </summary>
public sealed class MemberIndexAmbiguityTests
{
    #region Methods
    /// <summary>The exact-node-id branch: <c>Outer()</c> calls <c>Middle()</c> on a non-generic type.</summary>
    [Fact]
    public void Resolve_TwoDefinitionsWithOneNodeId_IsAmbiguous_NotAnException()
    {
        using var doubled = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        var index = doubled.Index();
        var sites = ModelCallSite.All(index).Where(s => s.Caller.NodeId == Outer && s.ReferenceNodeId == Middle).ToArray();
        Assert.Equal(2, sites.Length);   // one per copy of Outer
        Assert.Equal(2, index.Types("MechanismFixture.Transitive.Chain").Count);
        Assert.Equal(2, index.Methods.Count(m => m.NodeId == Middle));
        Assert.Empty(sites[0].Target.ContainingType.GenericArguments);

        MethodResolution? resolved = null;
        var thrown = Record.Exception(() => resolved = index.Resolve(sites[0].Target));

        Assert.Null(thrown);
        var resolution = Assert.IsType<MethodResolution>(resolved);
        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal(Middle, resolution.NodeId);
        Assert.Equal([Middle], resolution.Candidates);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Equal("several definitions share this node id", resolution.Reason);
    }

    /// <summary>
    /// The substituted branch: <c>Box&lt;int&gt;.Run</c> is through an instantiation, so both copies of <c>Box`1.Run()</c>
    /// are rendered with the instantiation's arguments and both match.
    /// </summary>
    [Fact]
    public void Resolve_ThroughAnInstantiation_WithTwoDefinitions_IsAmbiguous_OnTheSubstitutedSignature()
    {
        using var doubled = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        var index = doubled.Index();
        var site = ModelCallSite.All(index).First(s => s.Caller.NodeId == RunsBox && s.ReferenceNodeId == BoxRun);
        Assert.NotEmpty(site.Target.ContainingType.GenericArguments);

        var resolution = index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.Equal(BoxRun, resolution.NodeId);
        Assert.Equal([BoxRun], resolution.Candidates);
        Assert.Equal("several definitions match the instantiated signature", resolution.Reason);
    }

    /// <summary>
    /// A generic method instance resolves through its <c>GenericMethod</c> first — and is ambiguous there too. With no
    /// <see cref="MethodResolution.Definition"/>, <see cref="MethodResolution.NodeId"/> is the reference's OWN id (the
    /// instance <c>Foo`1(…A)</c>); the definition's id <c>Foo`1(!!0)</c> is the candidate, which is where the graph's
    /// edge goes.
    /// </summary>
    [Fact]
    public void Resolve_GenericMethodInstanceWithTwoDefinitions_IsAmbiguous_WithTheDefinitionIdAsCandidate()
    {
        using var doubled = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        var index = doubled.Index();
        var site = ModelCallSite.All(index).First(s => s.ReferenceNodeId == FooOfA);

        var resolution = index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.Equal(FooOfA, resolution.NodeId);
        Assert.Equal([FooDefinition], resolution.Candidates);
        Assert.Equal("several definitions share this node id", resolution.Reason);
    }

    /// <summary>
    /// The graph over the doubled index: never throws, every reference into the doubled assembly is Ambiguous and
    /// recorded as an opacity at its site, every candidate gets an edge, and references into the single Dependency
    /// still resolve exactly.
    /// </summary>
    [Fact]
    public void Build_OverAmbiguousReferences_RecordsAnOpacity_AndKeepsAnEdgeToEveryCandidate()
    {
        using var doubled = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        var index = doubled.Index();
        var sites = ModelCallSite.All(index);

        var graph = MethodGraph.Build(index);

        var intoFixture = sites.Count(s => s.DeclaringAssembly == MechanismFixtureAssemblies.FixtureName);
        var intoDependency = sites.Count(s => s.DeclaringAssembly == MechanismFixtureAssemblies.DependencyName);
        Assert.True(intoFixture > 0 && intoDependency > 0);
        Assert.Equal(intoFixture, graph.Coverage.Resolutions.Ambiguous);
        Assert.Equal(intoDependency, graph.Coverage.Resolutions.Exact);
        Assert.Equal(0, graph.Coverage.Resolutions.Substituted);
        Assert.Equal(0, graph.Coverage.Resolutions.Unresolved);
        Assert.Equal(intoFixture, graph.Opacities.Count(o => o.Kind == OpacityKind.Ambiguous));

        // Both copies of RunsBox carry the site, so it is recorded twice - identically.
        var opacities = graph.Opacities.Where(o => o.Kind == OpacityKind.Ambiguous && o.Site == RunsBox && o.Detail.StartsWith(BoxRun, StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, opacities.Length);
        var opacity = Assert.Single(opacities.Distinct());
        Assert.Equal($"{BoxRun}: several definitions match the instantiated signature", opacity.Detail);
        Assert.Equal(2, graph.Edges.Count(e => e == new MethodEdge(RunsBox, BoxRun, MethodEdgeKind.Call, opacity.Offset)));

        // One STATIC edge per (site, distinct candidate). A doubled definition is ONE candidate id, so most sites keep
        // one edge; only Overloads<int>.M(t:)/M(i:) (M(!0), M(System.Int32)) and, since S2, Outer4<string>.Mid.Inner<int>
        // .Innermost<bool>.M(t:)/M(s:) (M(!0), M(System.String)) have two genuinely different candidates, and each of
        // those four sites exists once per copy: 4 sites x 2 copies x 1 extra candidate = 8 extra edges. StateMachine
        // edges (A2 S2) are not call sites either, nor are TypeInitializer and LoadToken edges (A2 S3), so they are left
        // out here and checked on their own below.
        var staticEdges = graph.Edges.Where(e => e.Kind is MethodEdgeKind.Call or MethodEdgeKind.CallVirt or MethodEdgeKind.NewObj
            or MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn).ToArray();
        Assert.Equal(
            sites.Sum(s => index.Resolve(s.Target) is { Kind: ResolutionKind.Ambiguous } a ? a.Candidates.Count : 1),
            staticEdges.Length);
        Assert.Equal(sites.Count + 8, staticEdges.Length);
        Assert.Equal(8, sites.Count(s => index.Resolve(s.Target).Candidates.Count == 2));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(BoxRun)?.Kind);
        Assert.False(graph.Coverage.Truncated);

        // A2 S1: an Ambiguous resolution has no Definition to rule dispatch out, so CHA still fans out from it (never
        // drops a site on ambiguity). Every Dispatch edge is DispatchTargets' answer for its site, the coverage counts
        // agree, and the doubled hierarchy is still reached: both copies of CallsThroughInterface reach EnvProbe.Run.
        var expectedDispatch = sites
            .SelectMany(s => (s.DispatchTargets(index) ?? []).Select(to => new MethodEdge(s.Caller.NodeId, to, MethodEdgeKind.Dispatch, s.Offset)))
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Offset)
            .ToArray();
        Assert.Equal(expectedDispatch, graph.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch));
        Assert.Equal(expectedDispatch.Length, graph.Coverage.DispatchEdges);
        Assert.Equal(sites.Count(s => s.DispatchTargets(index) is not null), graph.Coverage.DispatchSites);
        Assert.Equal(2, graph.Edges.Count(e => e.Kind == MethodEdgeKind.Dispatch && e.From == CallsThroughInterface && e.To == EnvProbeRun));

        // A2 S2: state machines are found on the subtype map, not through Resolve, so ambiguity does not hide them
        // either. Every StateMachine edge is StateMachineTargets' answer for its site (a newobj, call or callvirt; the
        // caller itself excluded), and the doubled stub is linked once per copy.
        var expectedStateMachine = sites
            .Where(s => s.Kind is MethodEdgeKind.NewObj or MethodEdgeKind.Call or MethodEdgeKind.CallVirt)
            .SelectMany(s => index.StateMachineTargets(s.Target, s.Kind == MethodEdgeKind.NewObj).Where(to => to != s.Caller.NodeId)
                .Select(to => new MethodEdge(s.Caller.NodeId, to, MethodEdgeKind.StateMachine, s.Offset)))
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Offset)
            .ToArray();
        Assert.Equal(expectedStateMachine, graph.Edges.Where(e => e.Kind == MethodEdgeKind.StateMachine));
        Assert.Equal(2, graph.Edges.Count(e => e.Kind == MethodEdgeKind.StateMachine && e.From == IteratorStub && e.To == IteratorMoveNext));

        // A2 S3: static constructors are found by declaring-type id, not through Resolve, so ambiguity hides none: both
        // copies of TriggersInit reach the one FieldInit..cctor node, and both copies of CompilesEnvTree have their
        // LoadToken edge to the (unambiguous, external) sink. The module record is one per assembly NAME.
        Assert.Equal(2, graph.Edges.Count(e => e.Kind == MethodEdgeKind.TypeInitializer && e.From == TriggersInit && e.To == FieldInitCctor));
        Assert.Equal(2, graph.Edges.Count(e => e.Kind == MethodEdgeKind.LoadToken && e.From == CompilesEnvTree));
        Assert.Equal(4, graph.Coverage.TokenSites);
        Assert.Equal(1, graph.Coverage.ModuleInitializers);
        Assert.Single(graph.Opacities, o => o.Kind == OpacityKind.ModuleInitializerInvisible);
    }

    /// <summary>
    /// The substituted branch on the shared fixture: <c>GenericBox&lt;string&gt;.Holds(string)</c> names no definition,
    /// and both copies of <c>Holds(!0)</c> render <c>Holds(System.String)</c> under the instantiation. Ambiguous — and
    /// since S1 the edge goes to the candidate definition <c>Holds(!0)</c> (an own node), not to a made-up External node
    /// under the reference's id: no node of that id exists at all, so nothing can be classified through it.
    /// </summary>
    [Fact]
    public void Resolve_SubstitutedParameterWithTwoMatchingDefinitions_IsAmbiguous_AndTheEdgeGoesToTheCandidateDefinition()
    {
        using var doubled = ModelAssemblies.Load(SharedFixtureMethodGraphFixture.Path, SharedFixtureMethodGraphFixture.Path);
        var index = doubled.Index();
        var site = ModelCallSite.All(index).First(s => s.ReferenceNodeId == HoldsString);

        var resolution = index.Resolve(site.Target);
        var graph = MethodGraph.Build(index);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.Equal(HoldsString, resolution.NodeId);
        Assert.Equal([HoldsDefinition], resolution.Candidates);
        Assert.Equal("several definitions match the instantiated signature", resolution.Reason);

        Assert.Null(graph.Node(HoldsString));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(HoldsDefinition)?.Kind);
        Assert.Contains(graph.Edges, e => e.From == site.Caller.NodeId && e.To == HoldsDefinition && e.Offset == site.Offset);
        Assert.Contains(graph.Opacities, o => o.Kind == OpacityKind.Ambiguous && o.Site == site.Caller.NodeId && o.Offset == site.Offset);
    }
    #endregion

    #region Fields
    private const string Outer = "MechanismFixture.Transitive.Chain.Outer()";
    private const string Middle = "MechanismFixture.Transitive.Chain.Middle()";
    private const string RunsBox = "MechanismFixture.Generics.Boxes.RunsBox()";
    private const string BoxRun = "MechanismFixture.Generics.Box`1.Run()";
    private const string FooOfA = "MechanismFixture.Generics.Constrained.Foo`1(MechanismFixture.Generics.A)";
    private const string FooDefinition = "MechanismFixture.Generics.Constrained.Foo`1(!!0)";
    private const string HoldsString = "Silvergun.CodeAnalysis.IL.Tests.Fixture.GenericBox`1.Holds(System.String)";
    private const string HoldsDefinition = "Silvergun.CodeAnalysis.IL.Tests.Fixture.GenericBox`1.Holds(!0)";
    private const string CallsThroughInterface = "MechanismFixture.Interface.Dispatch.CallsThroughInterface()";
    private const string EnvProbeRun = "MechanismFixture.Interface.EnvProbe.Run()";
    private const string IteratorStub = "MechanismFixture.Iterator.Sequences.Enum()";
    private const string IteratorMoveNext = "MechanismFixture.Iterator.Sequences.<Enum>d__0.MoveNext()";
    private const string TriggersInit = "MechanismFixture.StaticInit.Triggers.TriggersInit()";
    private const string FieldInitCctor = "MechanismFixture.StaticInit.FieldInit..cctor()";
    private const string CompilesEnvTree = "MechanismFixture.ExpressionTree.Trees.CompilesEnvTree()";
    #endregion
}
