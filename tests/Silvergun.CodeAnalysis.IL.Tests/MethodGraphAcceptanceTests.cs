namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase A1 acceptance criteria 1 and 7 (<c>docs/agent/tasks/capslock-mechanism-fixtures-and-a1.md</c> §2.3) over
/// the mechanism fixture, both assemblies indexed together: every call-site reference into an indexed assembly
/// resolves <c>Own</c>, every platform reference <c>External</c>, and the graph's nodes, edges, opacities and
/// coverage agree with an independent walk of the same bytecode — and with the raw-CCI direct call sites
/// (<see cref="MechanismCallSites"/>) the ground truth was written against.
/// </summary>
public sealed class MethodGraphAcceptanceTests : IClassFixture<MechanismMethodGraphFixture>, IClassFixture<MechanismFixtureFixture>
{
    #region Constructors
    public MethodGraphAcceptanceTests(MechanismMethodGraphFixture graph, MechanismFixtureFixture cci)
    {
        this.graph = graph;
        this.cci = cci;
    }
    #endregion

    #region Methods
    // ---- acceptance 1: resolution ------------------------------------------------------------------------------

    [Fact]
    public void Resolve_EveryReferenceIntoAnIndexedAssembly_IsOwn_AndEveryOtherIsExternal()
    {
        var indexed = new HashSet<string>(graph.Index.Assemblies, StringComparer.OrdinalIgnoreCase);
        var own = graph.Sites.Where(s => s.DeclaringAssembly is { } a && indexed.Contains(a)).ToArray();
        var platform = graph.Sites.Except(own).ToArray();

        // Non-vacuous on both sides, and the own side really spans both assemblies.
        Assert.NotEmpty(platform);
        Assert.Contains(own, s => s.DeclaringAssembly == MechanismFixtureAssemblies.DependencyName);
        Assert.Contains(own, s => s.DeclaringAssembly == MechanismFixtureAssemblies.FixtureName);

        // The deliberate exceptions: Overloads<int>.M(t: 1) and .M(i: 1) both render M(System.Int32) once CCI has
        // substituted the instantiation, so Model cannot tell M(T) from M(int) and the honest answer is Ambiguous
        // (spec §2.5; WrongDefinitionResolutionTests). Since S2 (spec §2.6, C-A) the same holds four levels deep:
        // Outer4<string>.Mid.Inner<int>.Innermost<bool>.M(t:)/M(s:) both render M(System.String)
        // (NestedGenericResolutionTests). Exactly those four sites.
        var honestlyAmbiguous = own.Where(s => s.ReferenceNodeId == Fixture("Resolution.Overloads`1.M(System.Int32)") ||
                                               s.ReferenceNodeId == Fixture("Resolution.Outer4.Mid.Inner.Innermost`3.M(System.String)")).ToArray();
        Assert.Equal(4, honestlyAmbiguous.Length);

        var notOwn = own.Except(honestlyAmbiguous).Select(s => (Site: s, Resolution: graph.Index.Resolve(s.Target)))
            .Where(x => x.Resolution.Kind is not (ResolutionKind.Exact or ResolutionKind.Substituted) || !x.Resolution.IsOwn ||
                        graph.Index.Methods.Single(m => ReferenceEquals(m.Definition, x.Resolution.Definition)).NodeId != x.Resolution.NodeId ||
                        !x.Resolution.Candidates.SequenceEqual([x.Resolution.NodeId]))
            .Select(x => $"{x.Site.Caller.NodeId} -> {x.Site.ReferenceNodeId}: {x.Resolution.Kind} ({x.Resolution.Reason})")
            .ToArray();
        Assert.True(notOwn.Length == 0, $"{notOwn.Length} of {own.Length} own references did not resolve Own:{Environment.NewLine}{string.Join(Environment.NewLine, notOwn)}");

        var notExternal = platform.Select(s => (Site: s, Resolution: graph.Index.Resolve(s.Target)))
            .Where(x => x.Resolution.Kind != ResolutionKind.External || x.Resolution.IsOwn || x.Resolution.NodeId != x.Site.ReferenceNodeId ||
                        x.Resolution.Assembly != x.Site.DeclaringAssembly || x.Resolution.Candidates.Count != 0)
            .Select(x => $"{x.Site.Caller.NodeId} -> {x.Site.ReferenceNodeId}: {x.Resolution.Kind}")
            .ToArray();
        Assert.True(notExternal.Length == 0, $"{notExternal.Length} of {platform.Length} platform references did not resolve External:{Environment.NewLine}{string.Join(Environment.NewLine, notExternal)}");
    }

    /// <summary>
    /// <c>new Box&lt;int&gt;().Run()</c>: the reference really is through the instantiation <c>Box`1&lt;System.Int32&gt;</c>,
    /// and it lands on the definition <c>Box`1.Run()</c> — <see cref="ResolutionKind.Substituted"/> since S1 (it was
    /// <c>Exact</c> before). Why that is the right kind: the declaring type is an instantiation, and S1's rule is that
    /// such a reference is matched only by substituting its arguments into each same-shaped candidate and comparing
    /// (spec §2.5) — a bare node-id hit is no longer trusted, because that is exactly how <c>Flip</c>'s
    /// <c>Set(!1)</c> hit the wrong overload. <c>Run()</c> has nothing to substitute, so the single candidate matches.
    /// </summary>
    [Fact]
    public void Resolve_GenericOwnTypeInstantiation_BoxOfIntRun_ResolvesSubstitutedToTheDefinition()
    {
        var site = Assert.Single(graph.SitesIn(Fixture("Generics.Boxes.RunsBox()"), Fixture("Generics.Box`1.Run()")));
        Assert.Equal(["System.Int32"], site.Target.ContainingType.GenericArguments.Select(ModelNames.TypeName));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Substituted, resolution.Kind);
        Assert.Equal(Fixture("Generics.Box`1.Run()"), resolution.NodeId);
        Assert.Equal([Fixture("Generics.Box`1.Run()")], resolution.Candidates);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Contains(graph.Graph.Successors(Fixture("Generics.Boxes.RunsBox()")), e => e.To == resolution.NodeId);
    }

    /// <summary>
    /// <c>Foo&lt;A&gt;(new A())</c>: the site names the instance <c>Foo`1(MechanismFixture.Generics.A)</c>, which is
    /// NOT the definition's node id, and it resolves through <c>IMethodReference.GenericMethod</c> to
    /// <c>Foo`1(!!0)</c> exactly (spec §2.2, "Generic method instances").
    /// </summary>
    [Fact]
    public void Resolve_GenericMethodInstance_FooOfA_ResolvesExactThroughItsGenericMethod()
    {
        var site = Assert.Single(graph.SitesIn(Fixture("Generics.Constrained.Bar()"), Fixture("Generics.Constrained.Foo`1(MechanismFixture.Generics.A)")));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Exact, resolution.Kind);
        Assert.Equal(Fixture("Generics.Constrained.Foo`1(!!0)"), resolution.NodeId);
        Assert.NotEqual(site.ReferenceNodeId, resolution.NodeId);
    }

    /// <summary>
    /// The lambda nested in generic <c>Wraps&lt;T&gt;</c>: its display class is itself generic and is named through
    /// the instantiation <c>&lt;&gt;c__DisplayClass0_0`1&lt;!!0&gt;</c>; both the <c>newobj</c> of the closure and
    /// the <c>ldftn</c> of its body resolve to the definitions — <see cref="ResolutionKind.Substituted"/> since S1,
    /// because the declaring type is an instantiation (with the CALLER's <c>!!0</c> as its argument). The caller's
    /// <c>Wraps&lt;int&gt;</c> is a generic METHOD instance on a non-generic type: it goes through
    /// <c>GenericMethod</c>, has no type arguments to substitute, and stays <see cref="ResolutionKind.Exact"/>.
    /// </summary>
    [Theory]
    [InlineData("Generics.Closures.Wraps`1(!!0,System.String)", "Generics.Closures.<>c__DisplayClass0_0`1..ctor()", MethodEdgeKind.NewObj, ResolutionKind.Substituted)]
    [InlineData("Generics.Closures.Wraps`1(!!0,System.String)", "Generics.Closures.<>c__DisplayClass0_0`1.<Wraps>b__0()", MethodEdgeKind.Ldftn, ResolutionKind.Substituted)]
    [InlineData("Generics.Closures.WrapsInt()", "Generics.Closures.Wraps`1(!!0,System.String)", MethodEdgeKind.Call, ResolutionKind.Exact)]
    public void Resolve_LambdaInGenericMethod_ResolvesOwnWithTheRightEdgeKind(string caller, string definition, MethodEdgeKind kind, ResolutionKind resolutionKind)
    {
        var site = Assert.Single(graph.Sites, s =>
            s.Caller.NodeId == Fixture(caller) && graph.Index.Resolve(s.Target).NodeId == Fixture(definition));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.True(resolution.IsOwn, $"{site.ReferenceNodeId} resolved {resolution.Kind}");
        Assert.Equal(resolutionKind, resolution.Kind);
        Assert.Equal(kind, site.Kind);
        Assert.Contains(new MethodEdge(Fixture(caller), Fixture(definition), kind, site.Offset), graph.Graph.Edges);
    }

    /// <summary>
    /// Overloads told apart only by parameter SHAPE, reached through a generic type instance (the
    /// <c>MechanismFixture.Resolution</c> namespace; measured on ImageSharp 4.0.0's
    /// <c>ImageFrameCollection`1.AddFrame</c>). Since S1 (spec §2.5) each candidate is rendered with the
    /// instantiation's arguments substituted for its <c>!n</c> and compared exactly: <c>Add(!0[])</c> becomes
    /// <c>Add(System.Int32[])</c> on <c>Frames&lt;int&gt;</c> and only matches the array site, and each site has
    /// exactly one candidate.
    /// </summary>
    [Theory]
    [InlineData("Resolution.Callers.AddsIntFrame()", "Resolution.Frames`1.Add(MechanismFixture.Resolution.Frame`1<System.Int32>)",
        "Resolution.Frames`1.Add(MechanismFixture.Resolution.Frame`1<!0>)")]
    [InlineData("Resolution.Callers.AddsIntArray()", "Resolution.Frames`1.Add(System.Int32[])",
        "Resolution.Frames`1.Add(!0[])")]
    [InlineData("Resolution.Callers.AddsGenericFrame`1()", "Resolution.Frames`1.Add(MechanismFixture.Resolution.Frame`1<!!0>)",
        "Resolution.Frames`1.Add(MechanismFixture.Resolution.Frame`1<!0>)")]
    public void Resolve_OverloadsDifferingOnlyInParameterShape_PickTheOneThatFits(string caller, string reference, string definition)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(reference)));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Substituted,
            $"{site.ReferenceNodeId} resolved {resolution.Kind} (candidates [{string.Join(", ", resolution.Candidates)}]: {resolution.Reason}); expected Substituted to {Fixture(definition)}.");
        Assert.Equal(Fixture(definition), resolution.NodeId);
        Assert.Equal([Fixture(definition)], resolution.Candidates);
    }

    /// <summary>The definition fast path: handing <see cref="MemberIndex.Resolve"/> an indexed definition itself names it.</summary>
    [Fact]
    public void Resolve_AnIndexedDefinition_IsExactWithItsOwnNodeId()
    {
        Assert.All(graph.Index.Methods, m =>
        {
            var resolution = graph.Index.Resolve(m.Definition);
            Assert.Equal(ResolutionKind.Exact, resolution.Kind);
            Assert.Equal(m.NodeId, resolution.NodeId);
            Assert.Same(m.Definition, resolution.Definition);
        });
    }

    [Fact]
    public void Resolve_NullReference_IsUnresolved_AndDoesNotThrow()
    {
        var resolution = graph.Index.Resolve(null);

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Equal(CanonicalName.UnknownPart, resolution.NodeId);
        Assert.False(string.IsNullOrWhiteSpace(resolution.Reason));
    }

    // ---- the graph against an independent walk -----------------------------------------------------------------

    /// <summary>
    /// The STATIC edges (the call-site kinds <c>Call</c>, <c>CallVirt</c>, <c>NewObj</c>, <c>Ldftn</c>, <c>Ldvirtftn</c> —
    /// not <see cref="MethodEdgeKind.Dispatch"/>, <see cref="MethodEdgeKind.StateMachine"/>,
    /// <see cref="MethodEdgeKind.TypeInitializer"/> or <see cref="MethodEdgeKind.LoadToken"/>, none of which is a call
    /// site — A2 spec acceptance 3; S3's two are checked by their own tests below): one per call-site instruction to the
    /// node <see cref="MemberIndex.Resolve"/> names — or, for an <see cref="ResolutionKind.Ambiguous"/> site, one edge
    /// to EVERY candidate (S1: over-approximate, never pick one and drop the rest) — each with the instruction's kind
    /// and IL offset; the whole edge sequence, compared element by element.
    /// <para>
    /// Since A2 S1 a dispatching site ALSO has one <see cref="MethodEdgeKind.Dispatch"/> edge, at its own offset, to
    /// each node <see cref="MemberIndex.DispatchTargets"/> names for it — virtual for <c>callvirt</c>/<c>ldvirtftn</c>,
    /// not for <c>call</c>/<c>newobj</c>/<c>ldftn</c> — and there is no Dispatch edge anywhere else; that sequence is
    /// compared element by element too. Non-vacuous: the fixture's CHA rows' dispatch edges are among them.
    /// </para>
    /// <para>
    /// Since A2 S2 a site that creates (<c>newobj</c>) or names as a method generic argument (<c>call</c>/<c>callvirt</c>)
    /// an own state machine ALSO has one <see cref="MethodEdgeKind.StateMachine"/> edge, at its own offset, to each node
    /// <see cref="MemberIndex.StateMachineTargets"/> names for it except the caller itself; never at an <c>ldftn</c>
    /// or <c>ldvirtftn</c>, and nowhere else. Compared element by element as well.
    /// </para>
    /// </summary>
    [Fact]
    public void Edges_AreOnePerCallSiteAndTarget_ToTheResolvedNodeOrEveryAmbiguousCandidate()
    {
        var expected = graph.Sites
            .SelectMany(s => graph.Index.Resolve(s.Target) is { Kind: ResolutionKind.Ambiguous } ambiguous
                ? ambiguous.Candidates.Select(c => new MethodEdge(s.Caller.NodeId, c, s.Kind, s.Offset))
                : [new MethodEdge(s.Caller.NodeId, graph.Index.Resolve(s.Target).NodeId, s.Kind, s.Offset)])
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Kind).ThenBy(e => e.Offset)
            .ToArray();
        var expectedDispatch = graph.Sites
            .SelectMany(s => (s.DispatchTargets(graph.Index) ?? [])
                .Select(to => new MethodEdge(s.Caller.NodeId, to, MethodEdgeKind.Dispatch, s.Offset)))
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Offset)
            .ToArray();
        var expectedStateMachine = graph.Sites
            .Where(s => s.Kind is MethodEdgeKind.NewObj or MethodEdgeKind.Call or MethodEdgeKind.CallVirt)
            .SelectMany(s => graph.Index.StateMachineTargets(s.Target, s.Kind == MethodEdgeKind.NewObj)
                .Where(to => to != s.Caller.NodeId)
                .Select(to => new MethodEdge(s.Caller.NodeId, to, MethodEdgeKind.StateMachine, s.Offset)))
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Offset)
            .ToArray();

        Assert.Equal(expected, graph.Graph.Edges.Where(IsCallSiteEdge));
        Assert.Equal(expectedDispatch, graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch));
        Assert.Equal(expectedStateMachine, graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.StateMachine));
        Assert.NotEmpty(expectedStateMachine);
        Assert.DoesNotContain(graph.Sites, s => s.Kind is MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn &&
            graph.Graph.Edges.Any(e => e.Kind == MethodEdgeKind.StateMachine && e.From == s.Caller.NodeId && e.Offset == s.Offset));

        // Non-vacuous: interface, virtual, platform-declared (IEnumerator.MoveNext) and static-abstract fan-out.
        Assert.Contains(new MethodEdge(Fixture("Interface.Dispatch.CallsThroughInterface()"), Fixture("Interface.EnvProbe.Run()"), MethodEdgeKind.Dispatch,
            Assert.Single(graph.SitesIn(Fixture("Interface.Dispatch.CallsThroughInterface()"), Fixture("Interface.IProbe.Run()"))).Offset), graph.Graph.Edges);
        Assert.Contains(graph.Graph.Edges, e => e.Kind == MethodEdgeKind.Dispatch && e.From == Fixture("Virtual.Callers.CallsThroughBase()") && e.To == Fixture("Virtual.EnvWorker.Run()"));
        Assert.Contains(graph.Graph.Edges, e => e.Kind == MethodEdgeKind.Dispatch && e.To == Fixture("Iterator.Sequences.<Enum>d__0.MoveNext()"));
        Assert.Contains(graph.Graph.Edges, e => e.Kind == MethodEdgeKind.Dispatch && e.From == Fixture("StaticAbstract.Builders.Build`1()") && e.To == Fixture("StaticAbstract.EnvFactory.Make()"));
    }

    /// <summary>
    /// Every <see cref="MethodEdgeKind.Dispatch"/> edge, checked against properties read from the graph and the index
    /// rather than from <see cref="MemberIndex.DispatchTargets"/>: it sits at a real call site of its source whose
    /// instruction is <c>callvirt</c>/<c>ldvirtftn</c> or a <c>call</c> to a static method; it leads to an own method (a
    /// node that is not External) that is not the site's static target; and that method implements the declared
    /// method's name (exactly, or as the last segment of a C# explicit implementation) with the same parameter count.
    /// </summary>
    [Fact]
    public void DispatchEdges_LeaveOnlyDispatchingSites_ForOwnMethodsOfTheDeclaredShape()
    {
        var sitesAt = graph.Sites.GroupBy(s => (s.Caller.NodeId, s.Offset)).ToDictionary(g => g.Key, g => Assert.Single(g));
        var methods = graph.Index.Methods.ToLookup(m => m.NodeId, StringComparer.Ordinal);
        var dispatch = graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch).ToArray();
        Assert.NotEmpty(dispatch);

        foreach (var edge in dispatch)
        {
            var site = sitesAt[(edge.From, edge.Offset)];
            var declared = ModelNames.Of(site.Target.GenericMethod ?? site.Target);
            Assert.True(site.Kind is MethodEdgeKind.CallVirt or MethodEdgeKind.Ldvirtftn || (site.Kind == MethodEdgeKind.Call && site.Target.IsStatic),
                $"{edge}: dispatch from a {site.Kind} site");
            Assert.NotEqual(MethodNodeKind.External, graph.Graph.Node(edge.To)?.Kind);
            Assert.DoesNotContain(graph.Graph.Edges, e => e.From == edge.From && e.Offset == edge.Offset && e.To == edge.To && e.Kind != MethodEdgeKind.Dispatch);
            var target = Assert.Single(methods[edge.To]).Identity;
            Assert.True(target.MethodName == declared.MethodName || target.MethodName!.EndsWith("." + declared.MethodName, StringComparison.Ordinal),
                $"{edge}: {target.MethodName} does not implement {declared.MethodName}");
            Assert.Equal(declared.ParameterTypes.Count, target.ParameterTypes.Count);
            Assert.Equal(declared.GenericArity, target.GenericArity);
        }
    }

    /// <summary>
    /// The counts add up. Pinned: exactly FOUR <see cref="ResolutionKind.Ambiguous"/> sites — the
    /// <c>Overloads&lt;int&gt;.M(t: 1)</c>/<c>.M(i: 1)</c> pair (S1, spec §2.5) and, since S2 (spec §2.6, C-A), the
    /// <c>Outer4&lt;string&gt;.Mid.Inner&lt;int&gt;.Innermost&lt;bool&gt;.M(t:)</c>/<c>.M(s:)</c> pair, neither of which Model
    /// can tell apart — each with two candidate edges, so the graph has exactly four more STATIC edges than call sites.
    /// The <see cref="MethodEdgeKind.Dispatch"/> edges (A2 S1) are not call sites: <see cref="GraphCoverage.DispatchEdges"/>
    /// counts them, and <see cref="GraphCoverage.DispatchSites"/> counts the sites <see cref="MemberIndex.DispatchTargets"/>
    /// answers for (an empty answer included). Nor are the <see cref="MethodEdgeKind.StateMachine"/> edges (A2 S2,
    /// acceptance 3): they are in neither <see cref="GraphCoverage.CallSites"/> nor <see cref="GraphCoverage.Resolutions"/>,
    /// which stay exactly the call-site counts while the graph has state-machine edges — and since A2 S3 the same holds
    /// for the <see cref="MethodEdgeKind.TypeInitializer"/> and <see cref="MethodEdgeKind.LoadToken"/> edges; the
    /// <c>ldtoken</c>s of methods are counted in <see cref="GraphCoverage.TokenSites"/> instead (the two expression
    /// trees'), the Release fixture's module initializer in <see cref="GraphCoverage.ModuleInitializers"/>, and no
    /// fixture has a renamed implementation or unreadable module metadata. The member index itself skipped
    /// nothing (W1: <see cref="IndexCoverage"/> all zero — no unresolved supertype either — surfaced unchanged as
    /// <see cref="GraphCoverage.Index"/>).
    /// </summary>
    [Fact]
    public void Coverage_IsInternallyConsistent_WithTheCallSitesAndTheEdges()
    {
        var coverage = graph.Graph.Coverage;
        var counts = coverage.Resolutions;
        var resolved = counts.Exact + counts.Substituted + counts.External + counts.Ambiguous + counts.Unresolved;
        var calli = ModelCallSite.IndirectCalls(graph.Index);
        var indexed = new HashSet<string>(graph.Index.Assemblies, StringComparer.OrdinalIgnoreCase);
        var own = graph.Sites.Count(s => s.DeclaringAssembly is { } a && indexed.Contains(a));

        Assert.Equal(new IndexCoverage(0, 0, 0), coverage.Index);
        Assert.Same(graph.Index.Coverage, coverage.Index);
        Assert.True(coverage.Index.IsComplete);
        Assert.Equal(graph.Index.Methods.Count, coverage.MethodsIndexed);
        Assert.Equal(graph.Index.Methods.Count(m => m.Definition.HasBody), coverage.BodiesRead);
        Assert.Equal(0, coverage.BodiesFailed);
        Assert.Equal(graph.Sites.Count, resolved);
        Assert.Equal(graph.Sites.Count + calli, coverage.CallSites);
        Assert.Equal(calli, graph.Graph.Opacities.Count(o => o.Kind == OpacityKind.IndirectCall));
        Assert.Equal(4, counts.Ambiguous);
        Assert.Equal(resolved + counts.Ambiguous, graph.Graph.Edges.Count(IsCallSiteEdge));   // each ambiguous site: 2 candidates = 1 extra edge
        // ...and none of these is counted above.
        Assert.True(graph.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.StateMachine) > 0);
        Assert.True(graph.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.TypeInitializer) > 0);
        Assert.Equal(TokenInstructions().Length, coverage.TokenSites);
        Assert.Equal(2, coverage.TokenSites);
        Assert.Equal(coverage.TokenSites, graph.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.LoadToken));   // no token here is Ambiguous
        Assert.Equal(1, coverage.ModuleInitializers);
        Assert.Equal(0, coverage.RenamedImplementations);
        Assert.Equal(0, coverage.ModulesUnreadable);
        Assert.Equal(own, counts.Exact + counts.Substituted + counts.Ambiguous);
        Assert.Equal(graph.Sites.Count - own, counts.External);
        Assert.Equal(0, counts.Unresolved);
        Assert.False(coverage.Truncated);
        Assert.Null(coverage.TruncatedBy);

        var answers = graph.Sites.Select(s => s.DispatchTargets(graph.Index)).ToArray();
        Assert.Equal(graph.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.Dispatch), coverage.DispatchEdges);
        Assert.Equal(answers.Sum(a => a?.Count ?? 0), coverage.DispatchEdges);
        Assert.Equal(answers.Count(a => a is not null), coverage.DispatchSites);
        Assert.InRange(coverage.DispatchSites, 1, graph.Sites.Count);
        Assert.True(coverage.DispatchEdges > 0);
    }

    /// <summary>
    /// Every call-site instruction carries exactly its own kind. Counted per INSTRUCTION (caller + offset), not per
    /// edge: since S1 an Ambiguous site has one edge per candidate (each of the four honestly ambiguous <c>call</c>
    /// sites gives two Call edges), and every static edge of a site has the site's kind.
    /// <para>
    /// Since A2 S1 a dispatching site also carries <see cref="MethodEdgeKind.Dispatch"/> edges beside its static ones:
    /// never a site of its own (every Dispatch edge sits at an instruction that also has its static edge), and only at
    /// a <c>callvirt</c>, an <c>ldvirtftn</c> or a <c>call</c> (the static rule) — never at a <c>newobj</c> or an
    /// <c>ldftn</c> in this fixture. Since A2 S2 the same holds for <see cref="MethodEdgeKind.StateMachine"/> edges,
    /// at a <c>newobj</c>, a <c>call</c> or a <c>callvirt</c> only — never at an <c>ldftn</c> or <c>ldvirtftn</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void EdgeKinds_MatchTheInstructionKinds()
    {
        var staticEdges = graph.Graph.Edges.Where(IsCallSiteEdge).ToArray();
        var dispatchEdges = graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch).ToArray();
        var stateMachineEdges = graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.StateMachine).ToArray();

        Assert.Equal(
            graph.Sites.GroupBy(s => s.Kind).OrderBy(g => g.Key).Select(g => (g.Key, g.Count())),
            staticEdges.Select(e => (e.From, e.Offset, e.Kind)).Distinct().GroupBy(e => e.Kind).OrderBy(g => g.Key).Select(g => (g.Key, g.Count())));
        Assert.All(staticEdges.GroupBy(e => (e.From, e.Offset)), site => Assert.Single(site.Select(e => e.Kind).Distinct()));

        var staticKindAt = staticEdges.GroupBy(e => (e.From, e.Offset)).ToDictionary(g => g.Key, g => g.First().Kind);
        Assert.NotEmpty(dispatchEdges);
        Assert.All(dispatchEdges, e => Assert.True(
            staticKindAt.TryGetValue((e.From, e.Offset), out var kind) && kind is MethodEdgeKind.CallVirt or MethodEdgeKind.Ldvirtftn or MethodEdgeKind.Call,
            $"{e}: no static edge of a dispatching kind at this site"));
        Assert.Contains(dispatchEdges, e => staticKindAt[(e.From, e.Offset)] == MethodEdgeKind.CallVirt);
        Assert.Contains(dispatchEdges, e => staticKindAt[(e.From, e.Offset)] == MethodEdgeKind.Call);   // StaticAbstract's T.Make()

        Assert.NotEmpty(stateMachineEdges);
        Assert.All(stateMachineEdges, e => Assert.True(
            staticKindAt.TryGetValue((e.From, e.Offset), out var kind) && kind is MethodEdgeKind.NewObj or MethodEdgeKind.Call or MethodEdgeKind.CallVirt,
            $"{e}: no static edge of a state-machine-naming kind at this site"));
        Assert.Contains(stateMachineEdges, e => staticKindAt[(e.From, e.Offset)] == MethodEdgeKind.NewObj);   // iterators
        Assert.Contains(stateMachineEdges, e => staticKindAt[(e.From, e.Offset)] == MethodEdgeKind.Call);     // Start<S>

        // A2 S3: TypeInitializer and LoadToken edges are not call sites either. A TypeInitializer edge may sit at a
        // field access, which has no static edge at all; a LoadToken edge always sits where no call-site edge is.
        Assert.Contains(graph.Graph.Edges, e => e.Kind == MethodEdgeKind.TypeInitializer && staticKindAt.TryGetValue((e.From, e.Offset), out var kind) && kind == MethodEdgeKind.NewObj);
        Assert.Contains(graph.Graph.Edges, e => e.Kind == MethodEdgeKind.TypeInitializer && !staticKindAt.ContainsKey((e.From, e.Offset)));
        Assert.All(graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.LoadToken), e => Assert.False(staticKindAt.ContainsKey((e.From, e.Offset)), $"{e}"));
    }

    /// <summary>
    /// The <see cref="MethodEdgeKind.TypeInitializer"/> edges (A2 S3, §4), against an independent walk of the same bytecode:
    /// one per triggering instruction and target, at its offset — a <c>call</c>/<c>callvirt</c>, <c>newobj</c> or
    /// <c>ldftn</c>/<c>ldvirtftn</c> of a static method or a constructor, or a load, store or address of a static field —
    /// to each <c>.cctor</c> <see cref="MemberIndex.TypeInitializerTargets(Model.Types.IMethodReference)"/> names, the
    /// caller itself excluded; and since S3 review W3, the callee's edge of every walked instance method of an own value
    /// type, at offset 0, to each <c>.cctor</c> <see cref="MemberIndex.InstanceInitializerTargets"/> names; nothing
    /// anywhere else. Compared element by element.
    /// </summary>
    [Fact]
    public void TypeInitializerEdges_AreOnePerStaticMemberAccessAndStaticConstructor()
    {
        var expected = graph.Index.Methods.Where(m => m.Definition.HasBody)
            .SelectMany(m => graph.Index.InstanceInitializerTargets(m).Where(to => to != m.NodeId).Select(to => new MethodEdge(m.NodeId, to, MethodEdgeKind.TypeInitializer, 0))
                .Concat(m.Definition.Body.Instructions.OfType<Model.Bytecode.Instruction>().SelectMany(i => (i switch
                {
                    Model.Bytecode.MethodCallInstruction call => graph.Index.TypeInitializerTargets(call.Method),
                    Model.Bytecode.CreateObjectInstruction create => graph.Index.TypeInitializerTargets(create.Constructor),
                    Model.Bytecode.LoadMethodAddressInstruction load => graph.Index.TypeInitializerTargets(load.Method),
                    Model.Bytecode.LoadFieldInstruction field => graph.Index.TypeInitializerTargets(field.Field),
                    Model.Bytecode.StoreFieldInstruction field => graph.Index.TypeInitializerTargets(field.Field),
                    _ => [],
                }).Where(to => to != m.NodeId).Select(to => new MethodEdge(m.NodeId, to, MethodEdgeKind.TypeInitializer, i.Offset)))))
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Offset)
            .ToArray();

        Assert.Equal(expected, graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.TypeInitializer));
        Assert.Contains(new MethodEdge(Fixture("StaticInit.Triggers.TriggersInit()"), Fixture("StaticInit.FieldInit..cctor()"), MethodEdgeKind.TypeInitializer, 0), expected);
        Assert.Contains(new MethodEdge(Fixture("StaticInit.Creators.CreatesExplicitInit()"), Fixture("StaticInit.Constructed..cctor()"), MethodEdgeKind.TypeInitializer, 0), expected);
        Assert.Contains(new MethodEdge(Fixture("StaticInit.ValueInit.M()"), Fixture("StaticInit.ValueInit..cctor()"), MethodEdgeKind.TypeInitializer, 0), expected);
    }

    /// <summary>
    /// Every <see cref="MethodEdgeKind.TypeInitializer"/> edge, checked against the IL and the index rather than
    /// <see cref="MemberIndex.TypeInitializerTargets(Model.Types.IMethodReference)"/>: it leads to an own bodied static
    /// <c>.cctor()</c> other than its source; and the instruction at its offset is a call, <c>newobj</c> or <c>ldftn</c> of
    /// a static method or a constructor, or a field load/store of a static field, whose declaring type is the
    /// <c>.cctor</c>'s (generic arguments aside) — or, since S3 review W3, the source is an instance method of an own
    /// struct and the edge sits at offset 0 and leads to that struct's own <c>.cctor</c>. Non-vacuous over field loads,
    /// <c>newobj</c> and the value-type rule, and no edge leaves an instance field access or an instance method call.
    /// </summary>
    [Fact]
    public void TypeInitializerEdges_LeadFromAStaticMemberAccess_ToItsTypesStaticConstructor()
    {
        var bodies = graph.Index.Methods.Where(m => m.Definition.HasBody).ToDictionary(m => m.NodeId, m => m.Definition.Body.Instructions.OfType<Model.Bytecode.Instruction>().ToArray(), StringComparer.Ordinal);
        var methods = graph.Index.Methods.ToLookup(m => m.NodeId, StringComparer.Ordinal);
        var edges = graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.TypeInitializer).ToArray();
        var triggers = new HashSet<string>(StringComparer.Ordinal);

        foreach (var edge in edges)
        {
            Assert.NotEqual(edge.From, edge.To);
            var target = Assert.Single(methods[edge.To]);
            Assert.True(target.Definition.IsStatic && target.Definition.Name == ".cctor" && target.Definition.HasBody, $"{edge}: not a static constructor");
            // S3 review W3: the callee's edge - an instance method of an own struct, at offset 0, to its own type's .cctor.
            var source = Assert.Single(methods[edge.From]);
            if (edge.Offset == 0 && !source.Definition.IsStatic && source.DeclaringTypeId == target.DeclaringTypeId &&
                graph.Index.Types(source.DeclaringTypeId).Any(t => t.Definition is Model.Types.StructDefinition))
            {
                triggers.Add("value-type instance method");
                continue;
            }
            var instruction = Assert.Single(bodies[edge.From], i => i.Offset == edge.Offset);
            var (trigger, declaring) = instruction switch
            {
                Model.Bytecode.MethodCallInstruction { Method: var m } when m.IsStatic || m.Name == ".ctor" => ("call", m.ContainingType),
                Model.Bytecode.CreateObjectInstruction { Constructor: var c } => ("newobj", c.ContainingType),
                Model.Bytecode.LoadMethodAddressInstruction { Method: var m } when m.IsStatic || m.Name == ".ctor" => ("ldftn", m.ContainingType),
                Model.Bytecode.LoadFieldInstruction { Field: { IsStatic: true } f } => ("load", f.ContainingType),
                Model.Bytecode.StoreFieldInstruction { Field: { IsStatic: true } f } => ("store", f.ContainingType),
                _ => (null, null),
            };
            Assert.True(trigger is not null, $"{edge}: {instruction} is no trigger");
            triggers.Add(trigger!);
            var type = ModelNames.TypeName(declaring!);
            Assert.True(type == target.DeclaringTypeId || type.StartsWith(target.DeclaringTypeId + "<", StringComparison.Ordinal), $"{edge}: the member's type is {type}");
        }

        Assert.Contains("load", triggers);
        Assert.Contains("newobj", triggers);
        Assert.Contains("value-type instance method", triggers);
        Assert.DoesNotContain(edges, e => bodies[e.From].Single(i => i.Offset == e.Offset) is Model.Bytecode.LoadFieldInstruction { Field.IsStatic: false });
    }

    /// <summary>
    /// The <see cref="MethodEdgeKind.LoadToken"/> edges (A2 S3, §5), against an independent walk: one per <c>ldtoken</c> of
    /// a METHOD, at its offset, to the node <see cref="MemberIndex.Resolve"/> names (every candidate, if Ambiguous) —
    /// here the two expression trees', to the platform sinks as External leaves. An <c>ldtoken</c> of a type or a field
    /// (<c>typeof(...)</c>) adds no edge, and no <c>ldtoken</c> is fanned out by Dispatch.
    /// </summary>
    [Fact]
    public void LoadTokenEdges_AreOnePerMethodToken_ToTheResolvedNode_AndOtherTokensAddNothing()
    {
        var expected = TokenInstructions()
            .SelectMany(t => graph.Index.Resolve(t.Token) is { Kind: ResolutionKind.Ambiguous } ambiguous
                ? ambiguous.Candidates.Select(c => new MethodEdge(t.Caller, c, MethodEdgeKind.LoadToken, t.Offset))
                : [new MethodEdge(t.Caller, graph.Index.Resolve(t.Token).NodeId, MethodEdgeKind.LoadToken, t.Offset)])
            .OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Offset)
            .ToArray();
        var otherTokens = graph.Index.Methods.Where(m => m.Definition.HasBody)
            .SelectMany(m => m.Definition.Body.Instructions.OfType<Model.Bytecode.LoadTokenInstruction>()
                .Where(i => i.Token is not Model.Types.IMethodReference).Select(i => (m.NodeId, i.Offset)))
            .ToArray();

        Assert.Equal(expected, graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.LoadToken));
        Assert.Equal(
            [new MethodEdge(Fixture("ExpressionTree.Trees.CompilesEnvTree()"), "System.Environment.GetEnvironmentVariable(System.String)", MethodEdgeKind.LoadToken, 1),
             new MethodEdge(Fixture("ExpressionTree.Trees.CompilesSafeTree()"), "System.String.Concat(System.String,System.String)", MethodEdgeKind.LoadToken, 1)],
            expected);
        Assert.Equal(MethodNodeKind.External, graph.Graph.Node("System.Environment.GetEnvironmentVariable(System.String)")?.Kind);
        Assert.NotEmpty(otherTokens);
        Assert.DoesNotContain(graph.Graph.Edges, e => otherTokens.Contains((e.From, e.Offset)));
        Assert.DoesNotContain(graph.Graph.Edges, e => e.Kind == MethodEdgeKind.Dispatch && expected.Any(t => t.From == e.From && t.Offset == e.Offset));
    }

    // Every ldtoken of a method in the indexed bodies, read from Model independently of the graph.
    private (string Caller, uint Offset, Model.Types.IMethodReference Token)[] TokenInstructions() =>
        [.. graph.Index.Methods.Where(m => m.Definition.HasBody)
            .SelectMany(m => m.Definition.Body.Instructions.OfType<Model.Bytecode.LoadTokenInstruction>()
                .Where(i => i.Token is Model.Types.IMethodReference)
                .Select(i => (m.NodeId, i.Offset, (Model.Types.IMethodReference)i.Token)))];

    /// <summary>
    /// Every <see cref="MethodEdgeKind.StateMachine"/> edge, checked against properties read from the graph, the index and
    /// the IL rather than from <see cref="MemberIndex.StateMachineTargets"/>: it sits at a <c>newobj</c> or
    /// <c>call</c>/<c>callvirt</c> site of its own source; it leads to an own bodied method, not the source itself, that is
    /// an instance <c>MoveNext</c> or <c>MoveNextAsync</c> (by its implemented name) with no parameters, declared by an
    /// own type below <c>IAsyncStateMachine</c>, <c>IEnumerator</c>/<c>IEnumerator`1</c> or <c>IAsyncEnumerator`1</c>;
    /// and that type is the constructor's declaring type at a <c>newobj</c>, or one of the generic method's arguments at a
    /// call. Non-vacuous over every fixture shape: an iterator stub, a Release async stub, an async-iterator stub (to
    /// MoveNext AND MoveNextAsync), and MoveNextAsync to MoveNext.
    /// </summary>
    [Fact]
    public void StateMachineEdges_LeadFromANewobjOrACallNamingTheType_ToItsOwnMoveNext()
    {
        var sitesAt = graph.Sites.GroupBy(s => (s.Caller.NodeId, s.Offset)).ToDictionary(g => g.Key, g => Assert.Single(g));
        var methods = graph.Index.Methods.ToLookup(m => m.NodeId, StringComparer.Ordinal);
        string[] roots = ["System.Runtime.CompilerServices.IAsyncStateMachine", "System.Collections.IEnumerator", "System.Collections.Generic.IEnumerator`1", "System.Collections.Generic.IAsyncEnumerator`1"];
        var stateMachines = graph.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.StateMachine).ToArray();

        foreach (var edge in stateMachines)
        {
            var site = sitesAt[(edge.From, edge.Offset)];
            Assert.True(site.Kind is MethodEdgeKind.NewObj or MethodEdgeKind.Call or MethodEdgeKind.CallVirt, $"{edge}: from a {site.Kind} site");
            Assert.NotEqual(edge.From, edge.To);
            var target = Assert.Single(methods[edge.To]);
            Assert.Equal(MethodNodeKind.OwnWithBody, graph.Graph.Node(edge.To)?.Kind);
            Assert.False(target.Definition.IsStatic, $"{edge}: static target");
            Assert.Empty(target.Identity.ParameterTypes);
            var name = target.Definition.Name;
            Assert.True(name is "MoveNext" || name.EndsWith(".MoveNextAsync", StringComparison.Ordinal) || name.EndsWith(".MoveNext", StringComparison.Ordinal),
                $"{edge}: {name} is not a MoveNext");
            Assert.True(Below(target.DeclaringTypeId, roots), $"{edge}: {target.DeclaringTypeId} is below no state-machine root");

            var named = site.Kind == MethodEdgeKind.NewObj
                ? [CanonicalName.NodeId(ModelNames.Of(site.Target).DeclaringType)]
                : site.Target.GenericArguments.OfType<Model.Types.IBasicType>().Select(t => ModelNames.TypeName(t)).ToArray();
            Assert.True(named.Any(n => n == target.DeclaringTypeId || n.StartsWith(target.DeclaringTypeId + "<", StringComparison.Ordinal)),
                $"{edge}: the site names [{string.Join(", ", named)}], not {target.DeclaringTypeId}");
        }

        Assert.Contains(new MethodEdge(Fixture("Iterator.Sequences.Enum()"), Fixture("Iterator.Sequences.<Enum>d__0.MoveNext()"), MethodEdgeKind.StateMachine,
            Assert.Single(graph.SitesIn(Fixture("Iterator.Sequences.Enum()"), Fixture("Iterator.Sequences.<Enum>d__0..ctor(System.Int32)"))).Offset), stateMachines);
        Assert.Contains(stateMachines, e => e.From == Fixture("Async.AsyncProbes.Probe()") && e.To == Fixture("Async.AsyncProbes.<Probe>d__0.MoveNext()"));
        Assert.Contains(stateMachines, e => e.From == Fixture("AsyncIterator.Sequences.Env()") && e.To == Fixture("AsyncIterator.Sequences.<Env>d__0.MoveNext()"));
        Assert.Contains(stateMachines, e => e.From == Fixture("AsyncIterator.Sequences.Env()") && e.To == Fixture(EnvMoveNextAsync));
        Assert.Contains(stateMachines, e => e.From == Fixture(EnvMoveNextAsync) && e.To == Fixture("AsyncIterator.Sequences.<Env>d__0.MoveNext()"));
    }

    // Whether an own type id reaches one of roots by its supertypes (bounded: the fixture's hierarchies are shallow).
    private bool Below(string typeId, string[] roots)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var queue = new Queue<string>([typeId]);
        while (queue.TryDequeue(out var type) && seen.Count < 256)
            foreach (var super in graph.Index.Types(type).SelectMany(t => t.Supertypes))
            {
                if (roots.Contains(super))
                    return true;
                if (seen.Add(super))
                    queue.Enqueue(super);
            }
        return false;
    }

    /// <summary>
    /// <b>The independent oracle</b> (review 1: "every resolution test used <c>Resolve</c> as its own oracle"). Raw CCI
    /// knows which DEFINITION each call site names — <c>UnspecializedVersion</c>/<c>GenericMethod</c> keep it, where
    /// Model has substituted it away — so the A1 graph is checked against it <b>site by site</b> (caller + IL offset),
    /// for every own bodied method:
    /// <list type="bullet">
    /// <item><description>an own target: the site's single edge goes to exactly CCI's definition — a wrong-overload
    /// Exact/Substituted is caught here; or, if the site is <see cref="OpacityKind.Ambiguous"/>, CCI's definition is
    /// AMONG its candidate edges (S1 over-approximates);</description></item>
    /// <item><description>a platform target: one edge to an External node with CCI's classification key. (Compared by
    /// key because the graph keeps a generic platform method's INSTANTIATED node id —
    /// <c>Start`1(…&lt;Probe&gt;d__0&amp;)</c> — while the test-side reader maps it back to the definition.)</description></item>
    /// </list>
    /// The one method only CCI sees is <c>&lt;Module&gt;..cctor()</c>, which the Model drops (MechanismLayerParityTests).
    /// Covers the wrong-definition shapes in <c>MechanismFixture.Resolution</c> (Pair/Flip, Overloads, PointerOverloads,
    /// DeepOverloads) and, since S2 (spec §2.6), the nested-generic shapes (<c>Outer&lt;T&gt;.Nested</c> through
    /// <c>Outer&lt;int&gt;</c> and the caller's <c>Outer&lt;Y&gt;</c>; <c>Outer4</c>'s <c>Innermost</c> and <c>Lone</c>) —
    /// asserted non-vacuously at the end, including that all four Ambiguous sites were checked against CCI.
    /// </summary>
    [Fact]
    public void Graph_AgreesWithTheRawCciDirectCallSites_ExceptTheModuleTypeInitializer()
    {
        var sites = cci.CallSites;
        var problems = new List<string>();

        var ownWithBody = graph.Graph.Nodes.Where(n => n.Kind == MethodNodeKind.OwnWithBody).Select(n => n.NodeId).ToArray();
        var cciWithBody = sites.Definitions.Values.Where(d => d.HasBody).Select(d => d.NodeId).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(cciWithBody.Where(id => id != ModuleTypeInitializer), ownWithBody);
        Assert.Contains(ModuleTypeInitializer, cciWithBody);

        var ambiguousSites = graph.Graph.Opacities.Where(o => o.Kind == OpacityKind.Ambiguous).Select(o => (o.Site, o.Offset)).ToHashSet();
        var checkedAmbiguous = new List<string>();
        var dispatchChecked = 0;
        var stateMachinesChecked = 0;
        var typeInitializersChecked = 0;
        var tokensChecked = 0;
        // Every ldtoken of a method, from raw CCI: (caller, offset, the token's node id).
        var cciTokens = new[] { cci.Fixture, cci.Dependency }
            .SelectMany(a => a.Module.GetAllTypes().SelectMany(t => t.Methods))
            .SelectMany(m => (AssemblyAnalyzer.TryReadBody(m).Body?.Operations ?? [])
                .Where(op => op.OperationCode == Microsoft.Cci.OperationCode.Ldtoken && op.Value is Microsoft.Cci.IMethodReference)
                .Select(op => (CanonicalName.NodeId(CciNames.Of(m)), op.Offset, CanonicalName.NodeId(CciNames.Of((Microsoft.Cci.IMethodReference)op.Value)))))
            .ToHashSet();
        foreach (var caller in ownWithBody)
        {
            // The static edges only: Dispatch edges (A2 S1) are CHA's addition, and StateMachine edges (A2 S2) lead to a
            // MoveNext no instruction calls - neither is a call-site target CCI names.
            // Since A2 S3 TypeInitializer edges (implied by a member access) and LoadToken edges (an ldtoken) are not
            // call-site targets either; both are checked against CCI separately below.
            var edgesByOffset = graph.Graph.Successors(caller).Where(IsCallSiteEdge)
                .GroupBy(e => e.Offset).ToDictionary(g => g.Key, g => g.ToArray());
            var cciSites = sites.Sites.Where(s => s.Caller == caller).ToArray();

            var offsetsInGraph = edgesByOffset.Keys.Order().ToArray();
            var offsetsInCci = cciSites.Select(s => s.Offset).Order().ToArray();
            if (!offsetsInGraph.SequenceEqual(offsetsInCci))
                problems.Add($"{caller}: call-site offsets [{string.Join(", ", offsetsInGraph)}] vs CCI [{string.Join(", ", offsetsInCci)}]");

            // ...but each one sits at an instruction CCI also sees as a call site.
            foreach (var dispatch in graph.Graph.Successors(caller).Where(e => e.Kind == MethodEdgeKind.Dispatch))
            {
                dispatchChecked++;
                if (!offsetsInCci.Contains(dispatch.Offset))
                    problems.Add($"{caller} @IL_{dispatch.Offset:x4}: Dispatch edge to {dispatch.To} at no CCI call site");
            }
            foreach (var stateMachine in graph.Graph.Successors(caller).Where(e => e.Kind == MethodEdgeKind.StateMachine))
            {
                stateMachinesChecked++;
                if (!offsetsInCci.Contains(stateMachine.Offset) || !sites.Definitions.ContainsKey(stateMachine.To))
                    problems.Add($"{caller} @IL_{stateMachine.Offset:x4}: StateMachine edge to {stateMachine.To} at no CCI call site, or to no CCI definition");
            }
            foreach (var initializer in graph.Graph.Successors(caller).Where(e => e.Kind == MethodEdgeKind.TypeInitializer))
            {
                typeInitializersChecked++;
                if (!sites.Definitions.ContainsKey(initializer.To) || !initializer.To.EndsWith("..cctor()", StringComparison.Ordinal))
                    problems.Add($"{caller} @IL_{initializer.Offset:x4}: TypeInitializer edge to {initializer.To}, which is no CCI static constructor");
            }
            foreach (var token in graph.Graph.Successors(caller).Where(e => e.Kind == MethodEdgeKind.LoadToken))
            {
                tokensChecked++;
                if (!cciTokens.Contains((caller, token.Offset, token.To)))
                    problems.Add($"{caller} @IL_{token.Offset:x4}: LoadToken edge to {token.To}, which CCI's ldtoken there does not name");
            }

            foreach (var site in cciSites)
            {
                var edges = edgesByOffset.GetValueOrDefault(site.Offset) ?? [];
                var to = edges.Select(e => e.To).ToArray();
                var at = $"{caller} @IL_{site.Offset:x4}";

                if (sites.Definitions.ContainsKey(site.Target))
                {
                    if (ambiguousSites.Contains((caller, site.Offset)))
                    {
                        checkedAmbiguous.Add(at);
                        if (!to.Contains(site.Target, StringComparer.Ordinal) || to.Any(t => graph.Graph.Node(t)?.Kind == MethodNodeKind.External))
                            problems.Add($"{at}: Ambiguous candidates [{string.Join(", ", to)}] do not include CCI's definition {site.Target}, or are not all own");
                    }
                    else if (!to.SequenceEqual([site.Target]))
                    {
                        problems.Add($"{at}: graph -> [{string.Join(", ", to)}], CCI's definition is {site.Target}");
                    }
                }
                else if (edges.Length != 1 || graph.Graph.Node(to[0]) is not { Kind: MethodNodeKind.External } node ||
                         node.ClassificationKey != sites.Targets[site.Target])
                {
                    problems.Add($"{at}: graph -> [{string.Join(", ", to)}], CCI's platform target is {site.Target} (key {sites.Targets[site.Target]})");
                }
            }
        }

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));

        // Non-vacuous: the wrong-definition shapes are among the sites compared, and all four ambiguous sites (the
        // Overloads pair and the S2 Innermost pair) were checked against CCI's own answer.
        foreach (var definition in WrongDefinitionShapes)
            Assert.Contains(sites.Sites, s => s.Target == Fixture(definition) && s.Caller.StartsWith(Fixture("Resolution."), StringComparison.Ordinal));
        Assert.Equal(4, checkedAmbiguous.Count);
        Assert.Equal(2, checkedAmbiguous.Count(at => at.StartsWith(Fixture("Resolution.NestedCallers.CallsInnermost"), StringComparison.Ordinal)));
        Assert.Equal(graph.Graph.Coverage.DispatchEdges, dispatchChecked);
        Assert.True(dispatchChecked > 0);
        Assert.Equal(graph.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.StateMachine), stateMachinesChecked);
        Assert.True(stateMachinesChecked > 0);
        Assert.Equal(graph.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.TypeInitializer), typeInitializersChecked);
        Assert.True(typeInitializersChecked > 0);
        Assert.Equal(cciTokens.Count, tokensChecked);
        Assert.Equal(2, tokensChecked);
    }

    [Fact]
    public void Nodes_EveryIndexedMethodIsAnOwnNode_AndNoExternalNodeNamesAnIndexedMethod()
    {
        foreach (var method in graph.Index.Methods)
        {
            var node = graph.Graph.Node(method.NodeId);
            Assert.NotNull(node);
            Assert.Equal(method.Definition.HasBody ? MethodNodeKind.OwnWithBody : MethodNodeKind.OwnBodyless, node!.Kind);
        }

        // Bodyless own methods: the P/Invoke extern and an interface method are still nodes, so calls to them land.
        Assert.Equal(MethodNodeKind.OwnBodyless, graph.Graph.Node(Fixture("Opacity.Native.getpid()"))?.Kind);
        Assert.Equal(MethodNodeKind.OwnBodyless, graph.Graph.Node(Fixture("Interface.IProbe.Run()"))?.Kind);
        Assert.Contains(graph.Graph.Edges, e => e.From == Fixture("Opacity.Native.CallsNative()") && e.To == Fixture("Opacity.Native.getpid()"));

        var methodIds = graph.Index.Methods.Select(m => m.NodeId).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain(graph.Graph.Nodes, n => n.Kind == MethodNodeKind.External && methodIds.Contains(n.NodeId));
        Assert.Equal(
            graph.Graph.Nodes.Where(n => n.Kind != MethodNodeKind.External).Select(n => n.NodeId),
            methodIds.Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// Calli has no target in the instruction: exactly the two function-pointer calls are opaque, at their own
    /// offsets. The only other opacities are the four honestly <see cref="OpacityKind.Ambiguous"/> sites — the
    /// <c>Overloads&lt;int&gt;.M</c> pair (S1) and the <c>Outer4&lt;string&gt;.Mid.Inner&lt;int&gt;.Innermost&lt;bool&gt;.M</c>
    /// pair (S2, C-A); no <see cref="OpacityKind.NameShadowed"/> (the fixture shadows no platform name), and no
    /// <see cref="OpacityKind.Unresolved"/> (the S2 nested-generic sites all resolve). Since A2 S3 there is also one
    /// per-assembly module record (spec §6): the Release fixture's <c>&lt;Module&gt;</c> has a static constructor (its one
    /// method), so one <see cref="OpacityKind.ModuleInitializerInvisible"/> sited at
    /// <c>[Silvergun.CodeAnalysis.IL.Tests.MechanismFixture]&lt;Module&gt;</c>, offset 0, naming the method count; the
    /// Dependency has no module initializer and neither has a renamed implementation, so they add none.
    /// </summary>
    [Fact]
    public void Opacities_AreExactlyTheTwoCalliSites_TheFourHonestlyAmbiguousSites_AndTheModuleInitializer()
    {
        var module = MemberIndex.Qualified(MechanismFixtureAssemblies.FixtureName, "<Module>");
        Assert.Equal(
            [(Fixture("Opacity.Pointers.CallsThroughPointer()"), OpacityKind.IndirectCall),
             (Fixture("Opacity.Pointers.CallsThroughPointerSafe()"), OpacityKind.IndirectCall),
             (Fixture("Resolution.NestedCallers.CallsInnermostGeneric()"), OpacityKind.Ambiguous),
             (Fixture("Resolution.NestedCallers.CallsInnermostString()"), OpacityKind.Ambiguous),
             (Fixture("Resolution.WrongDefinitionCallers.CallsGenericOverload()"), OpacityKind.Ambiguous),
             (Fixture("Resolution.WrongDefinitionCallers.CallsIntOverload()"), OpacityKind.Ambiguous),
             (module, OpacityKind.ModuleInitializerInvisible)],
            graph.Graph.Opacities.Select(o => (o.Site, o.Kind)));
        Assert.Equal(
            new GraphOpacity(module, 0, OpacityKind.ModuleInitializerInvisible,
                "<Module> has a module initializer, which runs when the assembly loads, and 1 method; the model loads none of them"),
            graph.Graph.Opacities[^1]);
        Assert.Null(graph.Graph.Node(module));

        foreach (var opacity in graph.Graph.Opacities.Where(o => o.Site != module))
        {
            var body = graph.Index.Methods.Single(m => m.NodeId == opacity.Site).Definition.Body.Instructions;
            if (opacity.Kind == OpacityKind.IndirectCall)
                Assert.Contains(body.OfType<Model.Bytecode.IndirectMethodCallInstruction>(), i => i.Offset == opacity.Offset);
            else
                Assert.Contains(body.OfType<Model.Bytecode.MethodCallInstruction>(), i => i.Offset == opacity.Offset);
        }
    }

    [Fact]
    public void Collections_AreOrdinalSorted()
    {
        Assert.Equal(graph.Graph.Nodes.Select(n => n.NodeId).Order(StringComparer.Ordinal), graph.Graph.Nodes.Select(n => n.NodeId));
        Assert.Equal(graph.Graph.Nodes.Count, graph.Graph.Nodes.Select(n => n.NodeId).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            graph.Graph.Edges.OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Kind).ThenBy(e => e.Offset),
            graph.Graph.Edges);
        Assert.Equal(
            graph.Graph.Opacities.OrderBy(o => o.Site, StringComparer.Ordinal).ThenBy(o => o.Offset).ThenBy(o => o.Kind).ThenBy(o => o.Detail, StringComparer.Ordinal),
            graph.Graph.Opacities);
        Assert.Equal(
            graph.Index.Methods.OrderBy(m => m.NodeId, StringComparer.Ordinal).ThenBy(m => m.Assembly, StringComparer.Ordinal),
            graph.Index.Methods);
        Assert.Equal(graph.Index.TypeIds.Order(StringComparer.Ordinal), graph.Index.TypeIds);
        Assert.Equal(
            [MechanismFixtureAssemblies.FixtureName, MechanismFixtureAssemblies.DependencyName],
            graph.Index.Assemblies);
    }

    /// <summary>
    /// The ownership rule (spec §2.2, "Type identity across assemblies"): a reference is Own only if its declaring
    /// assembly is indexed. With the Dependency left out, the same call to <c>Dependency.EnvReader.Read()</c> is an
    /// External leaf — so the CrossAssembly path is lost, which is exactly what indexing both assemblies buys.
    /// </summary>
    [Fact]
    public void Resolve_WithTheDependencyNotIndexed_TheCrossAssemblyTargetIsExternal()
    {
        using var alone = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture);
        var index = alone.Index();
        var site = Assert.Single(ModelCallSite.All(index), s =>
            s.Caller.NodeId == Fixture("CrossAssembly.Callers.UsesDependency()") && s.ReferenceNodeId == Fixture("Dependency.EnvReader.Read()"));

        var resolution = index.Resolve(site.Target);
        var aloneGraph = MethodGraph.Build(index);

        Assert.Equal(ResolutionKind.External, resolution.Kind);
        Assert.Equal(MethodNodeKind.External, aloneGraph.Node(Fixture("Dependency.EnvReader.Read()"))?.Kind);
        Assert.Equal([MechanismFixtureAssemblies.FixtureName], index.Assemblies);

        var row = MechanismGroundTruth.Paths.Single(p => p.Id == "CrossAssembly.UsesDependency");
        Assert.False(WaypointMatcher.Evaluate(row, MechanismGraphSource.From(aloneGraph).Adjacency, MechanismGraphSource.From(aloneGraph).CapabilityOf).Holds);
        Assert.True(WaypointMatcher.Evaluate(row, MechanismGraphSource.From(graph.Graph).Adjacency, MechanismGraphSource.From(graph.Graph).CapabilityOf).Holds);
    }

    private static string Fixture(string nodeIdWithoutRoot) => $"{MechanismGroundTruth.RootNamespace}.{nodeIdWithoutRoot}";

    // A call-site instruction's own edge: not Dispatch, StateMachine, TypeInitializer or LoadToken (A2 acceptance 3).
    private static bool IsCallSiteEdge(MethodEdge edge) =>
        edge.Kind is MethodEdgeKind.Call or MethodEdgeKind.CallVirt or MethodEdgeKind.NewObj or MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn;
    #endregion

    #region Fields
    private const string ModuleTypeInitializer = "<Module>..cctor()";
    private const string EnvMoveNextAsync = "AsyncIterator.Sequences.<Env>d__0.System.Collections.Generic.IAsyncEnumerator<System.String>.MoveNextAsync()";

    /// <summary>The definitions the wrong-definition sites of <c>MechanismFixture.Resolution</c> really name (CCI's answer).</summary>
    private static readonly string[] WrongDefinitionShapes =
    [
        WrongDefinitionResolutionTests.PairSetFirst, WrongDefinitionResolutionTests.PairSetSecond,
        WrongDefinitionResolutionTests.OverloadOfT, WrongDefinitionResolutionTests.OverloadOfInt,
        WrongDefinitionResolutionTests.PointerOverload, WrongDefinitionResolutionTests.DeepOverload,
        NestedGenericResolutionTests.NestedOfT, NestedGenericResolutionTests.NestedOfString,
        NestedGenericResolutionTests.InnermostOfT, NestedGenericResolutionTests.InnermostOfString,
        NestedGenericResolutionTests.LoneOfT,
    ];

    private readonly MechanismMethodGraphFixture graph;
    private readonly MechanismFixtureFixture cci;
    #endregion
}

/// <summary>
/// <see cref="ResolutionKind.Substituted"/> (formerly <c>GenericFallback</c>), measured on the shared fixture: an own
/// generic type called through an instantiation that SUBSTITUTES a parameter type
/// (<c>GenericBox&lt;string&gt;.Holds(string)</c>) carries a node id that names no definition. Since S1 (spec §2.5)
/// each same-shaped candidate is rendered with the instantiation's arguments substituted for its <c>!n</c> and
/// compared exactly; the one that renders the site's signature is the definition.
/// </summary>
public sealed class SubstitutedResolutionTests : IClassFixture<SharedFixtureMethodGraphFixture>
{
    #region Constructors
    public SubstitutedResolutionTests(SharedFixtureMethodGraphFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    [Theory]
    [InlineData("CanonicalShapes.TakesOwnGeneric(Silvergun.CodeAnalysis.IL.Tests.Fixture.GenericBox`1<System.String>)",
        "GenericBox`1.Holds(System.String)", "GenericBox`1.Holds(!0)")]
    [InlineData("CanonicalShapes.UsesOwnGenerics()",
        "GenericOuter.Inner`2.TakesBoth(System.Int32,System.String)", "GenericOuter.Inner`2.TakesBoth(!0,!1)")]
    [InlineData("CanonicalShapes.UsesOwnGenerics()",
        "GenericOuter.Inner.Innermost`2.TakesOuterAndInnermost(System.Int32,System.Boolean)", "GenericOuter.Inner.Innermost`2.TakesOuterAndInnermost(!0,!1)")]
    public void Resolve_SubstitutedParameterOnAGenericOwnType_IsSubstitutedToTheDefinition(string caller, string reference, string definition)
    {
        var site = Assert.Single(fixture.Sites, s => s.Caller.NodeId == Shared(caller) && s.ReferenceNodeId == Shared(reference));

        var resolution = fixture.Index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Substituted, resolution.Kind);
        Assert.Equal(Shared(definition), resolution.NodeId);
        Assert.Equal([Shared(definition)], resolution.Candidates);
        Assert.Equal(SharedRoot, resolution.Assembly);
        Assert.Null(resolution.Reason);
    }

    /// <summary>A generic METHOD on a generic type is still Exact: <c>GenericMethod</c> carries the definition's <c>!0</c>/<c>!!0</c>.</summary>
    [Fact]
    public void Resolve_GenericMethodOnAGenericOwnType_IsExactThroughItsGenericMethod()
    {
        var site = Assert.Single(fixture.Sites, s => s.ReferenceNodeId == Shared("GenericBox`1.Convert`1(System.String,System.Int32)"));

        var resolution = fixture.Index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Exact, resolution.Kind);
        Assert.Equal(Shared("GenericBox`1.Convert`1(!0,!!0)"), resolution.NodeId);
    }

    /// <summary>
    /// Acceptance 1 on a second assembly: every own reference resolves Own (100%). Which kind is a pure function of
    /// the reference's SHAPE, read here straight from Model and independently of <see cref="MemberIndex"/>: a reference
    /// whose definition-carrying side (<c>GenericMethod</c> for a generic method instance, else the reference itself)
    /// is declared on a generic type INSTANTIATION is <see cref="ResolutionKind.Substituted"/>; every other one is
    /// <see cref="ResolutionKind.Exact"/>. Before S1 only the three sites whose parameters were actually substituted
    /// took the fallback; since S1 a bare node-id hit through an instantiation is no longer trusted (that is how
    /// <c>Flip</c>'s <c>Set(!1)</c> hit the wrong overload), so every site through an instantiation is Substituted —
    /// the three substituted-parameter sites among them (non-vacuity).
    /// </summary>
    [Fact]
    public void Resolve_OnTheSharedFixture_OwnReferencesAreAllOwn_AndExactlyThoseThroughAnInstantiationAreSubstituted()
    {
        var resolutions = fixture.Sites
            .Where(s => string.Equals(s.DeclaringAssembly, fixture.Index.Assemblies.Single(), StringComparison.OrdinalIgnoreCase))
            .Select(s => (Site: s, Resolution: fixture.Index.Resolve(s.Target)))
            .ToArray();

        Assert.NotEmpty(resolutions);
        Assert.All(resolutions, x => Assert.True(x.Resolution.IsOwn, $"{x.Site.ReferenceNodeId}: {x.Resolution.Kind}"));
        Assert.All(resolutions, x => Assert.True(
            x.Resolution.Kind == (ThroughATypeInstantiation(x.Site.Target) ? ResolutionKind.Substituted : ResolutionKind.Exact),
            $"{x.Site.Caller.NodeId} -> {x.Site.ReferenceNodeId}: {x.Resolution.Kind}"));

        var substituted = resolutions.Where(x => x.Resolution.Kind == ResolutionKind.Substituted)
            .Select(x => x.Resolution.NodeId[(SharedRoot.Length + 1)..]).ToHashSet(StringComparer.Ordinal);
        Assert.Subset(substituted,
            new HashSet<string>(["GenericBox`1.Holds(!0)", "GenericOuter.Inner.Innermost`2.TakesOuterAndInnermost(!0,!1)", "GenericOuter.Inner`2.TakesBoth(!0,!1)"], StringComparer.Ordinal));
        Assert.Contains(resolutions, x => x.Resolution.Kind == ResolutionKind.Exact);
    }

    /// <summary>
    /// Model-side shape only, no <see cref="MemberIndex"/>/<see cref="ModelNames"/>: does the reference that carries
    /// the definition's signature sit on a generic type instantiation — that is, does ANY link of its nesting chain
    /// carry generic arguments? Walking <c>ContainingType</c> outward matters (spec §2.6, W-1): CCIProvider prepends a
    /// container's arguments only when that link is itself instantiated, so a NON-generic nested type of an instantiated
    /// generic (<c>Outer&lt;int&gt;.Nested</c>) carries no arguments of its own, and the pre-S2 check on the innermost
    /// link alone (<c>GenericArguments.Count &gt; 0</c>) wrongly predicted <see cref="ResolutionKind.Exact"/> for it.
    /// Bounded, like every walk over metadata.
    /// </summary>
    internal static bool ThroughATypeInstantiation(Model.Types.IMethodReference target)
    {
        var type = (target.GenericMethod ?? target).ContainingType;
        for (var depth = 0; type is not null && depth < 16; depth++, type = type.ContainingType)
            if ((type.GenericArguments?.Count ?? 0) > 0)
                return true;
        return false;
    }

    private static string Shared(string nodeIdWithoutRoot) => $"{SharedRoot}.{nodeIdWithoutRoot}";
    #endregion

    #region Fields
    private const string SharedRoot = "Silvergun.CodeAnalysis.IL.Tests.Fixture";

    private readonly SharedFixtureMethodGraphFixture fixture;
    #endregion
}
