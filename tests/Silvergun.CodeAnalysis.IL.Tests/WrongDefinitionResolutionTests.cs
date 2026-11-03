namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Review 1 (spec §2.5, findings C1 and C3): three ways the A1 index resolved a call through a generic type
/// instantiation to the <b>wrong own definition</b> — invisible before, because the fixture had none of the shapes and
/// every resolution test used <see cref="MemberIndex.Resolve"/> as its own oracle. Here the oracle is
/// <b>independent</b>: raw CCI (<see cref="MechanismCallSites"/>) keeps the unspecialized member behind each site
/// (<c>ISpecializedMethodReference.UnspecializedVersion</c>), which Model has substituted away, so every case first
/// asks CCI which definition the IL names, then checks the index and the graph against that answer. The shapes live in
/// <c>MechanismFixture.Resolution</c> (Resolution.cs); none is executed.
/// <para><b>Red-proof — what the code before S1 returned</b> (from the review):</para>
/// <list type="bullet">
/// <item><description><c>Flip&lt;X,Y&gt;.BindsFirst</c> → the site renders <c>Pair`2.Set(!1)</c> (the CALLER's
/// <c>!1</c>), which Exact-matched the wrong definition <c>Set(T2)</c> = <c>Set(!1)</c>; <c>BindsSecond</c>
/// mirror-wise hit <c>Set(!0)</c>.</description></item>
/// <item><description><c>Overloads&lt;int&gt;.M(t: 1)</c> → renders <c>M(System.Int32)</c> and Exact-matched
/// <c>M(int)</c>, although the IL names <c>M(T)</c>.</description></item>
/// <item><description><c>PointerOverloads&lt;int&gt;.M(&amp;Ignore)</c> → the old <c>Compatible</c> heuristic's depth
/// bound said "no" for <c>fnptr:System.Void(!0)</c>, so the bare-<c>!0</c> sibling <c>M(!0)</c> won.</description></item>
/// </list>
/// Re-proven against today's src by mutation (S1 test round, src restored byte-for-byte after): forcing
/// <c>ResolveOwn</c> onto the exact-node-id branch unconditionally turned 5 of these cases red — Flip bound the sibling
/// both ways, both <c>Overloads</c> sites resolved Substituted to the single exact hit <c>M(System.Int32)</c> instead
/// of Ambiguous, and the <c>T[][][]</c> site named no definition — and the CCI parity test in
/// <see cref="MethodGraphAcceptanceTests"/> red on the same sites. The fnptr case is NOT caught by that mutation: CCI
/// leaves its <c>!0</c> unsubstituted, so its own node id happens to be the right definition's (see the premise test).
/// </summary>
public sealed class WrongDefinitionResolutionTests : IClassFixture<MechanismMethodGraphFixture>, IClassFixture<MechanismFixtureFixture>
{
    #region Constructors
    public WrongDefinitionResolutionTests(MechanismMethodGraphFixture graph, MechanismFixtureFixture cci)
    {
        this.graph = graph;
        this.cci = cci;
    }
    #endregion

    #region Methods
    /// <summary>
    /// The premise, measured: for the Flip pair and the <c>Overloads</c> pair the site's OWN node id textually names
    /// another indexed definition than the one the IL binds — so a node-id lookup is exactly the trap. Without this, the
    /// tests below could pass on a fixture that no longer contains the shape.
    /// </summary>
    [Theory]
    [InlineData("Resolution.Flip`2.BindsFirst(!1)", "Resolution.Pair`2.Set(!1)", PairSetFirst)]
    [InlineData("Resolution.Flip`2.BindsSecond(!0)", "Resolution.Pair`2.Set(!0)", PairSetSecond)]
    [InlineData("Resolution.WrongDefinitionCallers.CallsGenericOverload()", OverloadSite, OverloadOfT)]
    public void Premise_TheSitesOwnNodeId_IsAnotherOwnDefinition(string caller, string reference, string definition)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(reference)));

        Assert.True(graph.Index.IsOwnMethod(site.ReferenceNodeId), $"{site.ReferenceNodeId} is not an own method id.");
        Assert.Equal(Fixture(definition), CciDefinitionAt(site));
        Assert.NotEqual(Fixture(definition), site.ReferenceNodeId);
        Assert.NotEmpty(site.Target.ContainingType.GenericArguments);
    }

    /// <summary>
    /// Measured, and the reason the fnptr case differs from the others: CCI's specialization does NOT descend into a
    /// function-pointer type, so the site through <c>PointerOverloads&lt;int&gt;</c> keeps the definition's <c>!0</c>
    /// inside the pointer — <c>M(fnptr:System.Void(!0))</c>, not <c>M(fnptr:System.Void(System.Int32))</c> — although
    /// the declaring type IS the instantiation <c>PointerOverloads`1&lt;System.Int32&gt;</c>. Both layers agree on that
    /// rendering (<see cref="MechanismLayerParityTests"/>). Its own node id is therefore textually the RIGHT definition's.
    /// </summary>
    [Fact]
    public void Premise_TheFunctionPointerSite_KeepsTheDefinitionsGenericParameterInsideThePointer()
    {
        var site = Assert.Single(graph.Sites, s => s.Caller.NodeId == Fixture("Resolution.WrongDefinitionCallers.CallsPointerOverload()") &&
                                                   s.Kind == MethodEdgeKind.Call);

        Assert.Equal(Fixture(PointerSite), site.ReferenceNodeId);
        Assert.Equal(["System.Int32"], site.Target.ContainingType.GenericArguments.Select(ModelNames.TypeName));
        Assert.Equal(Fixture(PointerOverload), CciDefinitionAt(site));
    }

    /// <summary>
    /// C1 + C3: each site is through an instantiation; exactly one same-shaped candidate renders the site's signature
    /// once the instantiation's arguments are substituted, and it is the one CCI names. The sibling — the old wrong
    /// answer — gets no edge from the caller at all.
    /// </summary>
    [Theory]
    [InlineData("Resolution.Flip`2.BindsFirst(!1)", "Resolution.Pair`2.Set(!1)", PairSetFirst, PairSetSecond)]
    [InlineData("Resolution.Flip`2.BindsSecond(!0)", "Resolution.Pair`2.Set(!0)", PairSetSecond, PairSetFirst)]
    [InlineData("Resolution.WrongDefinitionCallers.CallsPointerOverload()", PointerSite, PointerOverload, PointerSibling)]
    [InlineData("Resolution.WrongDefinitionCallers.CallsDeepOverload()", "Resolution.DeepOverloads`1.M(System.Int32[][][])",
        DeepOverload, DeepSibling)]
    public void Resolve_ThroughAnInstantiation_BindsTheDefinitionCciNames_NotItsSibling(string caller, string reference, string definition, string sibling)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(reference)));
        Assert.Equal(Fixture(definition), CciDefinitionAt(site));
        Assert.True(graph.Index.IsOwnMethod(Fixture(sibling)), $"The sibling {sibling} must exist for the case to mean anything.");

        var resolution = graph.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Substituted && resolution.NodeId == Fixture(definition),
            $"{site.ReferenceNodeId} resolved {resolution.Kind} -> {resolution.NodeId} [{string.Join(", ", resolution.Candidates)}] " +
            $"({resolution.Reason}); CCI names {Fixture(definition)}.");
        Assert.Equal([Fixture(definition)], resolution.Candidates);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Equal([new MethodEdge(Fixture(caller), Fixture(definition), site.Kind, site.Offset)],
            graph.Graph.Successors(Fixture(caller)).Where(e => e.Offset == site.Offset));
        Assert.DoesNotContain(graph.Graph.Successors(Fixture(caller)), e => e.To == Fixture(sibling));
        Assert.DoesNotContain(graph.Graph.Opacities, o => o.Site == Fixture(caller));
    }

    /// <summary>
    /// <c>Overloads&lt;int&gt;.M(t: 1)</c> and <c>.M(i: 1)</c>: CCI says they bind DIFFERENT definitions, but under the
    /// instantiation both definitions render <c>M(System.Int32)</c> and Model keeps nothing else. The honest answer is
    /// <see cref="ResolutionKind.Ambiguous"/> with both candidates — CCI's true definition among them — an edge to each,
    /// and an opacity record; never a confident wrong Exact.
    /// </summary>
    [Theory]
    [InlineData("Resolution.WrongDefinitionCallers.CallsGenericOverload()", OverloadOfT)]
    [InlineData("Resolution.WrongDefinitionCallers.CallsIntOverload()", OverloadOfInt)]
    public void Resolve_OverloadsThatRenderAlikeUnderTheInstantiation_AreAmbiguous_WithAnEdgeToBothCandidates(string caller, string cciDefinition)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(OverloadSite)));
        Assert.Equal(Fixture(cciDefinition), CciDefinitionAt(site));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal(Fixture(OverloadSite), resolution.NodeId);
        Assert.Equal([Fixture(OverloadOfT), Fixture(OverloadOfInt)], resolution.Candidates);
        Assert.Contains(Fixture(cciDefinition), resolution.Candidates);
        Assert.Equal("several definitions match the instantiated signature", resolution.Reason);

        Assert.Equal(
            [new MethodEdge(Fixture(caller), Fixture(OverloadOfT), site.Kind, site.Offset), new MethodEdge(Fixture(caller), Fixture(OverloadOfInt), site.Kind, site.Offset)],
            graph.Graph.Successors(Fixture(caller)).Where(e => e.Offset == site.Offset));
        Assert.All(resolution.Candidates, c => Assert.NotEqual(MethodNodeKind.External, graph.Graph.Node(c)?.Kind));
        var opacity = Assert.Single(graph.Graph.Opacities, o => o.Site == Fixture(caller));
        Assert.Equal(new GraphOpacity(Fixture(caller), site.Offset, OpacityKind.Ambiguous,
            $"{Fixture(OverloadSite)}: several definitions match the instantiated signature"), opacity);
    }

    // Raw CCI's answer for the same site (caller + IL offset): the definition behind UnspecializedVersion.
    private string CciDefinitionAt(ModelCallSite site) =>
        Assert.Single(cci.CallSites.Sites, s => s.Caller == site.Caller.NodeId && s.Offset == site.Offset).Target;

    private static string Fixture(string nodeIdWithoutRoot) => $"{MechanismGroundTruth.RootNamespace}.{nodeIdWithoutRoot}";
    #endregion

    #region Fields
    /// <summary><c>Pair&lt;T1,T2&gt;.Set(T1)</c>: what <c>Flip.BindsFirst</c> binds.</summary>
    public const string PairSetFirst = "Resolution.Pair`2.Set(!0)";

    /// <summary><c>Pair&lt;T1,T2&gt;.Set(T2)</c>: what <c>Flip.BindsSecond</c> binds.</summary>
    public const string PairSetSecond = "Resolution.Pair`2.Set(!1)";

    /// <summary><c>Overloads&lt;T&gt;.M(T)</c>: what <c>M(t: 1)</c> binds.</summary>
    public const string OverloadOfT = "Resolution.Overloads`1.M(!0)";

    /// <summary><c>Overloads&lt;T&gt;.M(int)</c>: what <c>M(i: 1)</c> binds.</summary>
    public const string OverloadOfInt = "Resolution.Overloads`1.M(System.Int32)";

    /// <summary><c>PointerOverloads&lt;T&gt;.M(delegate*&lt;T, void&gt;)</c>: what <c>M(&amp;Ignore)</c> binds.</summary>
    public const string PointerOverload = "Resolution.PointerOverloads`1.M(fnptr:System.Void(!0))";

    /// <summary><c>DeepOverloads&lt;T&gt;.M(T[][][])</c>: what <c>M(new int[1][][])</c> binds.</summary>
    public const string DeepOverload = "Resolution.DeepOverloads`1.M(!0[][][])";

    private const string PointerSibling = "Resolution.PointerOverloads`1.M(!0)";
    private const string DeepSibling = "Resolution.DeepOverloads`1.M(!0)";

    /// <summary>What the <c>PointerOverloads&lt;int&gt;.M(&amp;Ignore)</c> site renders as: CCI left the <c>!0</c> inside the pointer.</summary>
    private const string PointerSite = "Resolution.PointerOverloads`1.M(fnptr:System.Void(!0))";

    /// <summary>What both <c>Overloads&lt;int&gt;.M</c> sites render as once CCI has substituted the instantiation.</summary>
    private const string OverloadSite = "Resolution.Overloads`1.M(System.Int32)";

    private readonly MechanismMethodGraphFixture graph;
    private readonly MechanismFixtureFixture cci;
    #endregion
}
