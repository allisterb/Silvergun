namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Reflection;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// Review 3, <b>C-D</b> (spec §2.7, S3): the depth bound broke substitution matching. A substituted argument is
/// rendered at depth 1 and pasted into the candidate, while CCI's reference renders it at its real, deeper position.
/// Past the bound the reference shows <c>&lt;unknown&gt;</c> and the true candidate does not, so the true candidate was
/// excluded and a sibling that truncated alike won ALONE — a wrong Own edge.
/// <para>
/// The shape, EMITTED at test time (<see cref="EmittedAssembly"/>; never compiled): <c>NS.C&lt;T&gt; { int M(T[]); int
/// M(long[] ×(R+1)) }</c> and <c>NS.Callers.BindsMOfTArray()</c>, whose IL binds <c>M(T[])</c> by token through
/// <c>C&lt;int[] ×R&gt;</c>. R = 63 puts the reference's element past the bound (the reference is <c>int[] ×64</c>);
/// R = 10 is the in-bound control. A non-generic <c>NS.D { static int M(int[] ×64); static int M(long[]) }</c> with
/// <c>NS.Callers.BindsDeepExact()</c> covers the exact branch, which needs no guard.
/// </para>
/// </summary>
public sealed class SubstitutionDepthBoundTests : IClassFixture<SubstitutionDepthBoundFixture>
{
    #region Constructors
    public SubstitutionDepthBoundTests(SubstitutionDepthBoundFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The trap, measured: the arguments ARE recovered (so this is not the unknown-arguments branch), the reference's
    /// signature is truncated, the true candidate substituted renders differently from it, and the decoy sibling
    /// renders exactly like it. A text comparison alone would pick the decoy.
    /// </summary>
    [Fact]
    public void Premise_PastTheBound_TheTrueCandidateRendersUnlikeTheReference_AndTheDecoyAlike()
    {
        var index = fixture.Deep.Index();
        var site = BindingSite(index);
        var arguments = ModelNames.TypeArguments(site.Target.ContainingType);
        var reference = ModelNames.Of(site.Target).ParameterTypes;

        Assert.NotNull(arguments);
        var argument = Assert.Single(arguments);
        Assert.DoesNotContain(CanonicalName.UnknownPart, argument, StringComparison.Ordinal);
        Assert.Contains(CanonicalName.UnknownPart, Assert.Single(reference), StringComparison.Ordinal);

        var bound = Own(index, BoundDefinition);
        var decoy = Assert.Single(SameShape(index), m => m.NodeId != BoundDefinition);
        Assert.NotEqual(reference, ModelNames.ParameterTypes(bound.Definition, arguments));
        Assert.Equal(reference, ModelNames.ParameterTypes(decoy.Definition, arguments));
    }

    /// <summary>
    /// C-D: past the bound nothing can be checked, so the answer is Ambiguous over EVERY same-shape candidate — both
    /// overloads, the IL-bound <c>M(!0[])</c> among them — with the "read in full" reason. Never a single Substituted.
    /// </summary>
    [Fact]
    public void Resolve_PastTheDepthBound_IsAmbiguousOverBothCandidates_NeverASingleSubstituted()
    {
        var index = fixture.Deep.Index();
        var site = BindingSite(index);

        var resolution = index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"resolved {resolution.Kind} -> {resolution.NodeId} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous over both overloads.");
        Assert.NotEqual(ResolutionKind.Substituted, resolution.Kind);
        Assert.Null(resolution.Definition);
        Assert.Contains(BoundDefinition, resolution.Candidates);
        Assert.Equal(SameShape(index).Select(m => m.NodeId).Order(StringComparer.Ordinal).ToArray(), resolution.Candidates);
        Assert.Equal(2, resolution.Candidates.Count);
        Assert.Equal(CanonicalName.NodeId(ModelNames.Of(site.Target)), resolution.NodeId);
        Assert.Equal(DeepAssembly, resolution.Assembly);
        Assert.Equal(ReadInFull, resolution.Reason);
    }

    /// <summary>The graph keeps the site: an Ambiguous opacity and an edge to EACH candidate, the true one included.</summary>
    [Fact]
    public void Build_PastTheDepthBound_RecordsAnAmbiguousOpacity_AndAnEdgeToEachCandidate()
    {
        var index = fixture.Deep.Index();
        var site = BindingSite(index);
        var candidates = SameShape(index).Select(m => m.NodeId).Order(StringComparer.Ordinal).ToArray();

        var graph = MethodGraph.Build(index);

        Assert.Equal(
            candidates.Select(c => new MethodEdge(BindsMOfTArray, c, MethodEdgeKind.CallVirt, site.Offset)),
            graph.Successors(BindsMOfTArray).Where(e => e.Offset == site.Offset));
        Assert.Contains(graph.Edges, e => e.From == BindsMOfTArray && e.To == BoundDefinition && e.Offset == site.Offset);
        Assert.Equal(
            [new GraphOpacity(BindsMOfTArray, site.Offset, OpacityKind.Ambiguous, $"{CanonicalName.NodeId(ModelNames.Of(site.Target))}: {ReadInFull}")],
            graph.Opacities.Where(o => o.Site == BindsMOfTArray));
        Assert.All(candidates, c => Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(c)?.Kind));
    }

    /// <summary>The in-bound control (R = 10): the same shape is checked and resolves Substituted to <c>M(!0[])</c>, one edge, no opacity.</summary>
    [Fact]
    public void Resolve_WithinTheDepthBound_IsSubstitutedToTheBoundDefinition_WithOneEdge()
    {
        var index = fixture.Shallow.Index();
        var site = BindingSite(index);
        Assert.DoesNotContain(CanonicalName.UnknownPart, Assert.Single(ModelNames.Of(site.Target).ParameterTypes), StringComparison.Ordinal);

        var resolution = index.Resolve(site.Target);
        var graph = MethodGraph.Build(index);

        Assert.True(resolution.Kind == ResolutionKind.Substituted && resolution.NodeId == BoundDefinition,
            $"resolved {resolution.Kind} -> {resolution.NodeId} ({resolution.Reason}); expected Substituted to {BoundDefinition}.");
        Assert.Same(Own(index, BoundDefinition).Definition, resolution.Definition);
        Assert.Equal([BoundDefinition], resolution.Candidates);
        Assert.Null(resolution.Reason);
        Assert.Equal(
            [new MethodEdge(BindsMOfTArray, BoundDefinition, MethodEdgeKind.CallVirt, site.Offset)],
            graph.Successors(BindsMOfTArray).Where(e => e.Offset == site.Offset));
        Assert.DoesNotContain(graph.Opacities, o => o.Site == BindsMOfTArray);
    }

    /// <summary>
    /// A2 S1 review C2: a TRUNCATED rendering verifies nothing, not even on the exact branch. A non-instantiated
    /// reference whose signature renders <c>&lt;unknown&gt;</c> (an <c>int[] ×64</c> parameter) is no longer Exact on a
    /// node-id match (before S1b it was): it is Ambiguous over every same-shaped candidate of <c>NS.D</c> — both
    /// one-parameter <c>M</c>s — with the reason "the signature could not be read in full", and the true depth-64
    /// definition (checked against the emitted IL by walking Model's parameter type: 64 array levels around
    /// <c>System.Int32</c>) is among the candidates.
    /// </summary>
    [Fact]
    public void Resolve_ANonInstantiatedTruncatedReference_IsAmbiguousOverEverySameShapedCandidate_TheTrueOneIncluded()
    {
        var index = fixture.Deep.Index();
        var site = Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == BindsDeepExact);
        Assert.Contains(CanonicalName.UnknownPart, CanonicalName.NodeId(ModelNames.Of(site.Target)), StringComparison.Ordinal);
        Assert.Equal(Array.Empty<string>(), ModelNames.TypeArguments(site.Target.ContainingType));
        var sameShape = index.Methods.Where(m => m.DeclaringTypeId == "NS.D" && m.Definition.Name == "M").ToArray();
        var deep = Assert.Single(sameShape, m => ElementOf(Assert.Single(m.Definition.Parameters).Type) == ("System", "Int32", 64));

        var resolution = index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"resolved {resolution.Kind} -> {resolution.NodeId} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous.");
        Assert.Null(resolution.Definition);
        Assert.Equal("the signature could not be read in full", resolution.Reason);
        Assert.Equal(sameShape.Select(m => m.NodeId).Distinct().Order(StringComparer.Ordinal), resolution.Candidates);
        Assert.Equal(2, resolution.Candidates.Count);
        Assert.Contains(deep.NodeId, resolution.Candidates);
        Assert.Equal(DeepAssembly, resolution.Assembly);
    }

    // The one call of M in BindsMOfTArray (its other site is the newobj of the instantiation).
    private static ModelCallSite BindingSite(MemberIndex index) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == BindsMOfTArray && s.Target.Name == "M");

    // Every indexed M of NS.C`1 - read from the index's definition list, not from Resolve.
    private static MemberIndex.IndexedMethod[] SameShape(MemberIndex index) =>
        [.. index.Methods.Where(m => m.DeclaringTypeId == "NS.C`1" && m.Definition.Name == "M")];

    private static MemberIndex.IndexedMethod Own(MemberIndex index, string nodeId) => Assert.Single(index.Methods, m => m.NodeId == nodeId);

    // Unwraps single-dimensional array levels down to a named element: (namespace, name, levels).
    private static (string? Namespace, string? Name, int Ranks) ElementOf(ModelTypes.IType type)
    {
        var ranks = 0;
        while (type is ModelTypes.ArrayType array)
        {
            ranks++;
            type = array.ElementsType;
        }
        return type is ModelTypes.IBasicType basic ? (basic.ContainingNamespace, basic.Name, ranks) : (null, null, ranks);
    }
    #endregion

    #region Fields
    internal const string DeepAssembly = "Silvergun.Tests.EmitDepth63";
    internal const string ShallowAssembly = "Silvergun.Tests.EmitDepth10";

    // The definition every BindsMOfTArray site names by token: M(T[]).
    private const string BoundDefinition = "NS.C`1.M(!0[])";
    private const string BindsMOfTArray = "NS.Callers.BindsMOfTArray()";
    private const string BindsDeepExact = "NS.Callers.BindsDeepExact()";
    private const string ReadInFull = "the instantiated signature could not be read in full";

    private readonly SubstitutionDepthBoundFixture fixture;
    #endregion
}

/// <summary>
/// Emits the C-D shapes for <see cref="SubstitutionDepthBoundTests"/> into this class fixture's own temporary directory
/// — R = 63 (past the bound) and R = 10 (the control), one assembly each — and reads each back on its own host.
/// </summary>
public sealed class SubstitutionDepthBoundFixture : IDisposable
{
    #region Constructors
    public SubstitutionDepthBoundFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            var deep = emitted.Save(SubstitutionDepthBoundTests.DeepAssembly, module => Define(module, 63));
            var shallow = emitted.Save(SubstitutionDepthBoundTests.ShallowAssembly, module => Define(module, 10));
            Deep = ModelAssemblies.Load(deep);
            try
            {
                Shallow = ModelAssemblies.Load(shallow);
            }
            catch (Exception)
            {
                Deep.Dispose();
                throw;
            }
        }
        catch (Exception)
        {
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    /// <summary>R = 63: the binding reference's parameter is <c>int[] ×64</c>, past the bound.</summary>
    public ModelAssemblies Deep { get; }

    /// <summary>R = 10: the same shape within the bound.</summary>
    public ModelAssemblies Shallow { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Deep.Dispose();
        Shallow.Dispose();
        emitted.Dispose();
    }

    // NS.C<T> { int M(T[]); int M(long[] x(ranks+1)) }, NS.D { static int M(int[] x64); static int M(long[]) } and the
    // callers BindsMOfTArray (M(T[]) through C<int[] x ranks>) and BindsDeepExact (D.M(int[] x64)).
    private static void Define(System.Reflection.Emit.ModuleBuilder module, int ranks)
    {
        var c = module.DefineType("NS.C", TypeAttributes.Public | TypeAttributes.Class);
        var t = c.DefineGenericParameters("T")[0];
        var constructor = c.DefineDefaultConstructor(MethodAttributes.Public);
        var bound = EmittedAssembly.Returning(c, "M", t.MakeArrayType(), 1);
        EmittedAssembly.Returning(c, "M", EmittedAssembly.Jagged(typeof(long), ranks + 1), 2);

        var d = module.DefineType("NS.D", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var deepExact = EmittedAssembly.Returning(d, "M", EmittedAssembly.Jagged(typeof(int), 64), 3, isStatic: true);
        EmittedAssembly.Returning(d, "M", typeof(long[]), 4, isStatic: true);

        var callers = module.DefineType("NS.Callers", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        EmittedAssembly.CallThroughInstantiation(callers, "BindsMOfTArray", c, constructor, bound, EmittedAssembly.Jagged(typeof(int), ranks));
        EmittedAssembly.CallStatic(callers, "BindsDeepExact", deepExact);

        foreach (var type in new[] { c, d, callers })
            type.CreateType();
    }
    #endregion

    #region Fields
    private readonly EmittedAssembly emitted;
    #endregion
}
