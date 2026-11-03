namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Review 2 (spec §2.6, S2): resolution through NESTED generic instantiations, checked against the independent CCI
/// oracle (<see cref="MechanismCallSites"/>: <c>UnspecializedVersion</c> names the definition each site binds), never
/// against <see cref="MemberIndex.Resolve"/> itself. CCIProvider prepends a containing type's arguments to a nested
/// type's Model <c>GenericArguments</c> only when that link is itself instantiated, so a non-generic link hides every
/// argument further out; <see cref="ModelNames.TypeArguments"/> recovers the missing prefix from the FRONT of the
/// container's full list. The shapes live in <c>MechanismFixture.Resolution</c> (Resolution.cs, at most four levels deep).
/// <list type="bullet">
/// <item><description><b>C-A</b> — <c>Outer4&lt;string&gt;.Mid.Inner&lt;int&gt;.Innermost&lt;bool&gt;.M(t:)</c>: the first S2
/// walk padded the hidden prefix with positional <c>!0</c>, rendered the true candidate <c>M(T)</c> as <c>M(!0)</c>,
/// and confidently bound the WRONG <c>M(string)</c>. Both render <c>M(System.String)</c>, so the honest answer is
/// <see cref="ResolutionKind.Ambiguous"/> with both.</description></item>
/// <item><description><b>W-1</b> — a non-generic nested type of an instantiated generic (<c>Outer&lt;int&gt;.Nested</c>)
/// carries no arguments of its own; before S2 that took the exact-node-id branch: Unresolved for <c>M(T)</c>, and
/// Exact by text alone for <c>M(string)</c>. Both are <see cref="ResolutionKind.Substituted"/> now.</description></item>
/// </list>
/// </summary>
public sealed class NestedGenericResolutionTests : IClassFixture<MechanismMethodGraphFixture>, IClassFixture<MechanismFixtureFixture>
{
    #region Constructors
    public NestedGenericResolutionTests(MechanismMethodGraphFixture graph, MechanismFixtureFixture cci)
    {
        this.graph = graph;
        this.cci = cci;
    }
    #endregion

    #region Methods
    // ---- C-A ----------------------------------------------------------------------------------------------------

    /// <summary>
    /// The premise, measured: both <c>Innermost</c> sites render the same node id, CCI says they bind DIFFERENT
    /// definitions, and Model's innermost link carries only <c>[int, bool]</c> — the outer <c>string</c> is reachable
    /// only through <c>ContainingType</c>, and <see cref="ModelNames.TypeArguments"/> recovers it in front.
    /// </summary>
    [Theory]
    [InlineData(InnermostGenericCaller, InnermostOfT)]
    [InlineData(InnermostStringCaller, InnermostOfString)]
    public void Premise_TheInnermostSites_RenderOneSignature_HideTheOuterArgument_AndBindDifferentDefinitions(string caller, string cciDefinition)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(InnermostSite)));
        var declaring = site.Target.ContainingType;

        Assert.Equal(Fixture(cciDefinition), CciDefinitionAt(site));
        Assert.Equal(3, declaring.GenericParameterCount);
        Assert.Equal(["System.Int32", "System.Boolean"], declaring.GenericArguments.Select(ModelNames.TypeName));
        Assert.Equal(["System.String", "System.Int32", "System.Boolean"], ModelNames.TypeArguments(declaring));
        Assert.True(graph.Index.IsOwnMethod(Fixture(InnermostOfT)) && graph.Index.IsOwnMethod(Fixture(InnermostOfString)));
    }

    /// <summary>
    /// C-A: both candidates render <c>M(System.String)</c> under the recovered arguments, so each site is
    /// <see cref="ResolutionKind.Ambiguous"/> with BOTH — CCI's true definition among them — an edge to each, and an
    /// Ambiguous opacity. Never a single (and for <c>t:</c>, wrong) Substituted.
    /// </summary>
    [Theory]
    [InlineData(InnermostGenericCaller, InnermostOfT)]
    [InlineData(InnermostStringCaller, InnermostOfString)]
    public void Resolve_InnermostOfAFourLevelChain_IsAmbiguous_WithBothCandidates_IncludingCcisDefinition(string caller, string cciDefinition)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(InnermostSite)));
        Assert.Equal(Fixture(cciDefinition), CciDefinitionAt(site));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"{site.ReferenceNodeId} resolved {resolution.Kind} -> {resolution.NodeId} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); " +
            $"expected Ambiguous over both, CCI names {Fixture(cciDefinition)}.");
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal(Fixture(InnermostSite), resolution.NodeId);
        Assert.Equal([Fixture(InnermostOfT), Fixture(InnermostOfString)], resolution.Candidates);
        Assert.Contains(Fixture(cciDefinition), resolution.Candidates);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Equal("several definitions match the instantiated signature", resolution.Reason);

        Assert.Equal(
            [new MethodEdge(Fixture(caller), Fixture(InnermostOfT), site.Kind, site.Offset), new MethodEdge(Fixture(caller), Fixture(InnermostOfString), site.Kind, site.Offset)],
            graph.Graph.Successors(Fixture(caller)).Where(e => e.Offset == site.Offset));
        Assert.Equal(
            new GraphOpacity(Fixture(caller), site.Offset, OpacityKind.Ambiguous, $"{Fixture(InnermostSite)}: several definitions match the instantiated signature"),
            Assert.Single(graph.Graph.Opacities, o => o.Site == Fixture(caller)));
    }

    /// <summary>
    /// The lone variant of the same four-level chain: only <c>M(T)</c> exists, so the one candidate that renders the
    /// site's <c>M(System.String)</c> is CCI's definition — <see cref="ResolutionKind.Substituted"/> to <c>M(!0)</c>.
    /// (The padded walk of C-A rendered it <c>M(!0)</c> and found nothing: Unresolved.)
    /// </summary>
    [Fact]
    public void Resolve_LoneOfAFourLevelChain_IsSubstitutedToMOfT()
    {
        var site = Assert.Single(graph.SitesIn(Fixture(LoneCaller), Fixture(LoneSite)));
        Assert.Equal(Fixture(LoneOfT), CciDefinitionAt(site));
        Assert.Equal(["System.String", "System.Int32", "System.Boolean"], ModelNames.TypeArguments(site.Target.ContainingType));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Substituted && resolution.NodeId == Fixture(LoneOfT),
            $"{site.ReferenceNodeId} resolved {resolution.Kind} -> {resolution.NodeId} ({resolution.Reason}); CCI names {Fixture(LoneOfT)}.");
        Assert.Equal([Fixture(LoneOfT)], resolution.Candidates);
        Assert.Null(resolution.Reason);
        Assert.Equal([new MethodEdge(Fixture(LoneCaller), Fixture(LoneOfT), site.Kind, site.Offset)],
            graph.Graph.Successors(Fixture(LoneCaller)).Where(e => e.Offset == site.Offset));
        Assert.DoesNotContain(graph.Graph.Opacities, o => o.Site == Fixture(LoneCaller));
    }

    // ---- W-1 ----------------------------------------------------------------------------------------------------

    /// <summary>
    /// The premise, measured: each site's declaring type is the NON-generic <c>Nested</c>, whose own Model arguments
    /// are empty — the instantiated <c>Outer&lt;…&gt;</c> is only its <c>ContainingType</c> — so a check of the innermost
    /// link alone calls it "not an instantiation". <c>M(string)</c>'s site renders, by text, the node id of its own
    /// definition: the trap that resolved it Exact before S2.
    /// </summary>
    [Theory]
    [InlineData(NestedGenericCaller, "Resolution.Outer.Nested`1.M(System.Int32)", NestedOfT, "System.Int32", false)]
    [InlineData(NestedStringCaller, NestedOfString, NestedOfString, "System.Int32", true)]
    [InlineData(NestedCallerMethod, "Resolution.Outer.Nested`1.M(!1)", NestedOfT, "!1", false)]
    public void Premise_TheNestedSites_CarryNoArgumentsOnTheInnermostLink(string caller, string reference, string cciDefinition, string outerArgument, bool idIsOwn)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(reference)));
        var declaring = site.Target.ContainingType;

        Assert.Equal(Fixture(cciDefinition), CciDefinitionAt(site));
        Assert.Empty(declaring.GenericArguments);
        Assert.Equal(1, declaring.GenericParameterCount);
        Assert.Equal([outerArgument], declaring.ContainingType.GenericArguments.Select(ModelNames.TypeName));
        Assert.Equal([outerArgument], ModelNames.TypeArguments(declaring));
        Assert.Equal(idIsOwn, graph.Index.IsOwnMethod(site.ReferenceNodeId));
        Assert.True(SubstitutedResolutionTests.ThroughATypeInstantiation(site.Target));
    }

    /// <summary>
    /// W-1: through a non-generic nested type of an instantiation, each site is <see cref="ResolutionKind.Substituted"/>
    /// — never Exact — to exactly CCI's definition, with one edge to it and no opacity; the sibling gets no edge.
    /// </summary>
    [Theory]
    [InlineData(NestedGenericCaller, "Resolution.Outer.Nested`1.M(System.Int32)", NestedOfT, NestedOfString)]
    [InlineData(NestedStringCaller, NestedOfString, NestedOfString, NestedOfT)]
    [InlineData(NestedCallerMethod, "Resolution.Outer.Nested`1.M(!1)", NestedOfT, NestedOfString)]
    public void Resolve_ThroughANonGenericNestedTypeOfAnInstantiation_IsSubstitutedToCcisDefinition(string caller, string reference, string definition, string sibling)
    {
        var site = Assert.Single(graph.SitesIn(Fixture(caller), Fixture(reference)));
        Assert.Equal(Fixture(definition), CciDefinitionAt(site));

        var resolution = graph.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Substituted && resolution.NodeId == Fixture(definition),
            $"{site.ReferenceNodeId} resolved {resolution.Kind} -> {resolution.NodeId} [{string.Join(", ", resolution.Candidates)}] " +
            $"({resolution.Reason}); expected Substituted to CCI's {Fixture(definition)}.");
        Assert.True(resolution.IsOwn);
        Assert.Equal([Fixture(definition)], resolution.Candidates);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Equal([new MethodEdge(Fixture(caller), Fixture(definition), site.Kind, site.Offset)],
            graph.Graph.Successors(Fixture(caller)).Where(e => e.Offset == site.Offset));
        Assert.DoesNotContain(graph.Graph.Successors(Fixture(caller)), e => e.To == Fixture(sibling));
        Assert.DoesNotContain(graph.Graph.Opacities, o => o.Site == Fixture(caller));
    }

    /// <summary>
    /// Over the whole mechanism fixture, the kind of every own, non-ambiguous resolution is a pure function of the
    /// reference's SHAPE, read from Model independently of the index: <see cref="ResolutionKind.Substituted"/> iff any
    /// link of the declaring chain is instantiated (<see cref="SubstitutedResolutionTests.ThroughATypeInstantiation"/>,
    /// which walks <c>ContainingType</c>), else <see cref="ResolutionKind.Exact"/>. Non-vacuous for W-1: the three
    /// <c>Nested</c> sites are among them, and on each the innermost link alone carries no arguments.
    /// </summary>
    [Fact]
    public void Resolve_OnTheMechanismFixture_ExactlyTheSitesThroughAnInstantiationAreSubstituted()
    {
        var indexed = new HashSet<string>(graph.Index.Assemblies, StringComparer.OrdinalIgnoreCase);
        var resolutions = graph.Sites
            .Where(s => s.DeclaringAssembly is { } a && indexed.Contains(a))
            .Select(s => (Site: s, Resolution: graph.Index.Resolve(s.Target)))
            .Where(x => x.Resolution.Kind != ResolutionKind.Ambiguous)
            .ToArray();

        var wrong = resolutions
            .Where(x => x.Resolution.Kind != (SubstitutedResolutionTests.ThroughATypeInstantiation(x.Site.Target) ? ResolutionKind.Substituted : ResolutionKind.Exact))
            .Select(x => $"{x.Site.Caller.NodeId} -> {x.Site.ReferenceNodeId}: {x.Resolution.Kind}")
            .ToArray();
        Assert.True(wrong.Length == 0, string.Join(Environment.NewLine, wrong));

        var hiddenByANonGenericLink = resolutions
            .Where(x => x.Resolution.Kind == ResolutionKind.Substituted && x.Site.Target.ContainingType.GenericArguments.Count == 0)
            .Select(x => x.Site.Caller.NodeId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal([Fixture(NestedCallerMethod), Fixture(NestedGenericCaller), Fixture(NestedStringCaller)], hiddenByANonGenericLink);
        Assert.Contains(resolutions, x => x.Resolution.Kind == ResolutionKind.Exact);
    }

    // Raw CCI's answer for the same site (caller + IL offset): the definition behind UnspecializedVersion.
    private string CciDefinitionAt(ModelCallSite site) =>
        Assert.Single(cci.CallSites.Sites, s => s.Caller == site.Caller.NodeId && s.Offset == site.Offset).Target;

    private static string Fixture(string nodeIdWithoutRoot) => $"{MechanismGroundTruth.RootNamespace}.{nodeIdWithoutRoot}";
    #endregion

    #region Fields
    /// <summary><c>Outer&lt;T&gt;.Nested.M(T)</c>.</summary>
    public const string NestedOfT = "Resolution.Outer.Nested`1.M(!0)";

    /// <summary><c>Outer&lt;T&gt;.Nested.M(string)</c>.</summary>
    public const string NestedOfString = "Resolution.Outer.Nested`1.M(System.String)";

    /// <summary><c>Outer4&lt;T&gt;.Mid.Inner&lt;U&gt;.Innermost&lt;V&gt;.M(T)</c>: what <c>M(t: "x")</c> binds.</summary>
    public const string InnermostOfT = "Resolution.Outer4.Mid.Inner.Innermost`3.M(!0)";

    /// <summary><c>Outer4&lt;T&gt;.Mid.Inner&lt;U&gt;.Innermost&lt;V&gt;.M(string)</c>: what <c>M(s: "x")</c> binds.</summary>
    public const string InnermostOfString = "Resolution.Outer4.Mid.Inner.Innermost`3.M(System.String)";

    /// <summary><c>Outer4&lt;T&gt;.Mid.Inner&lt;U&gt;.Lone&lt;V&gt;.M(T)</c>.</summary>
    public const string LoneOfT = "Resolution.Outer4.Mid.Inner.Lone`3.M(!0)";

    /// <summary>What both <c>Innermost</c> sites render as once CCI has substituted <c>&lt;string, int, bool&gt;</c>.</summary>
    private const string InnermostSite = "Resolution.Outer4.Mid.Inner.Innermost`3.M(System.String)";

    private const string LoneSite = "Resolution.Outer4.Mid.Inner.Lone`3.M(System.String)";

    private const string InnermostGenericCaller = "Resolution.NestedCallers.CallsInnermostGeneric()";
    private const string InnermostStringCaller = "Resolution.NestedCallers.CallsInnermostString()";
    private const string LoneCaller = "Resolution.NestedCallers.CallsLone()";
    private const string NestedGenericCaller = "Resolution.NestedCallers.CallsNestedGeneric()";
    private const string NestedStringCaller = "Resolution.NestedCallers.CallsNestedString()";
    private const string NestedCallerMethod = "Resolution.NestedCaller`2.BindsThroughNested(!1)";

    private readonly MechanismMethodGraphFixture graph;
    private readonly MechanismFixtureFixture cci;
    #endregion
}
