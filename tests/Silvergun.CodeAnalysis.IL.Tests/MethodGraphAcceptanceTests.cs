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
    /// One edge per call-site instruction to the node <see cref="MemberIndex.Resolve"/> names — or, for an
    /// <see cref="ResolutionKind.Ambiguous"/> site, one edge to EVERY candidate (S1: over-approximate, never pick one
    /// and drop the rest) — each with the instruction's kind and IL offset; the whole edge sequence, compared element
    /// by element.
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

        Assert.Equal(expected, graph.Graph.Edges);
    }

    /// <summary>
    /// The counts add up. Pinned: exactly FOUR <see cref="ResolutionKind.Ambiguous"/> sites — the
    /// <c>Overloads&lt;int&gt;.M(t: 1)</c>/<c>.M(i: 1)</c> pair (S1, spec §2.5) and, since S2 (spec §2.6, C-A), the
    /// <c>Outer4&lt;string&gt;.Mid.Inner&lt;int&gt;.Innermost&lt;bool&gt;.M(t:)</c>/<c>.M(s:)</c> pair, neither of which Model
    /// can tell apart — each with two candidate edges, so the graph has exactly four more edges than call sites. The
    /// member index itself skipped nothing (W1: <see cref="IndexCoverage"/> all zero, surfaced unchanged as
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
        Assert.Equal(resolved + counts.Ambiguous, graph.Graph.Edges.Count);   // each ambiguous site: 2 candidates = 1 extra edge
        Assert.Equal(own, counts.Exact + counts.Substituted + counts.Ambiguous);
        Assert.Equal(graph.Sites.Count - own, counts.External);
        Assert.Equal(0, counts.Unresolved);
        Assert.False(coverage.Truncated);
        Assert.Null(coverage.TruncatedBy);
    }

    /// <summary>
    /// Every call-site instruction carries exactly its own kind. Counted per INSTRUCTION (caller + offset), not per
    /// edge: since S1 an Ambiguous site has one edge per candidate (each of the four honestly ambiguous <c>call</c>
    /// sites gives two Call edges), and every edge of a site has the site's kind.
    /// </summary>
    [Fact]
    public void EdgeKinds_MatchTheInstructionKinds()
    {
        Assert.Equal(
            graph.Sites.GroupBy(s => s.Kind).OrderBy(g => g.Key).Select(g => (g.Key, g.Count())),
            graph.Graph.Edges.Select(e => (e.From, e.Offset, e.Kind)).Distinct().GroupBy(e => e.Kind).OrderBy(g => g.Key).Select(g => (g.Key, g.Count())));
        Assert.All(graph.Graph.Edges.GroupBy(e => (e.From, e.Offset)), site => Assert.Single(site.Select(e => e.Kind).Distinct()));

        // A1 records static targets only: the two A2 kinds are declared, never populated.
        Assert.DoesNotContain(graph.Graph.Edges, e => e.Kind is MethodEdgeKind.StateMachine or MethodEdgeKind.TypeInitializer);
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
        foreach (var caller in ownWithBody)
        {
            var edgesByOffset = graph.Graph.Successors(caller).GroupBy(e => e.Offset).ToDictionary(g => g.Key, g => g.ToArray());
            var cciSites = sites.Sites.Where(s => s.Caller == caller).ToArray();

            var offsetsInGraph = edgesByOffset.Keys.Order().ToArray();
            var offsetsInCci = cciSites.Select(s => s.Offset).Order().ToArray();
            if (!offsetsInGraph.SequenceEqual(offsetsInCci))
                problems.Add($"{caller}: call-site offsets [{string.Join(", ", offsetsInGraph)}] vs CCI [{string.Join(", ", offsetsInCci)}]");

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
    /// <see cref="OpacityKind.Unresolved"/> (the S2 nested-generic sites all resolve).
    /// </summary>
    [Fact]
    public void Opacities_AreExactlyTheTwoCalliSites_AndTheFourHonestlyAmbiguousSites()
    {
        Assert.Equal(
            [(Fixture("Opacity.Pointers.CallsThroughPointer()"), OpacityKind.IndirectCall),
             (Fixture("Opacity.Pointers.CallsThroughPointerSafe()"), OpacityKind.IndirectCall),
             (Fixture("Resolution.NestedCallers.CallsInnermostGeneric()"), OpacityKind.Ambiguous),
             (Fixture("Resolution.NestedCallers.CallsInnermostString()"), OpacityKind.Ambiguous),
             (Fixture("Resolution.WrongDefinitionCallers.CallsGenericOverload()"), OpacityKind.Ambiguous),
             (Fixture("Resolution.WrongDefinitionCallers.CallsIntOverload()"), OpacityKind.Ambiguous)],
            graph.Graph.Opacities.Select(o => (o.Site, o.Kind)));

        foreach (var opacity in graph.Graph.Opacities)
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
    #endregion

    #region Fields
    private const string ModuleTypeInitializer = "<Module>..cctor()";

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
