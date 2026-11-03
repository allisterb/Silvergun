namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Review 3, <b>W-4</b> (spec §2.7, S3): the <see cref="MemberIndex.Resolve"/> memo key was injective over its parts,
/// but a node id is not — <c>.</c> and <c>`</c> may occur in metadata names. Method <c>X`1.M</c> of type <c>NS.G`1</c>
/// and method <c>M</c> of type <c>NS.G`1.X`1</c> (namespace <c>NS.G`1</c>) render ONE node id, <c>NS.G`1.X`1.M(!0)</c>,
/// so through the same instantiation <c>&lt;int&gt;</c> the old key was one string, and whichever site was resolved
/// second got the first's <see cref="MethodResolution.Definition"/> — a wrong Own edge, in either order.
/// <para>
/// The shape is EMITTED at test time (<see cref="EmittedAssembly"/>): C# cannot name either declaration. The callers
/// <c>NS.Callers.CallsGMethod()</c> and <c>NS.Callers.CallsXMethod()</c> bind each by IL token, so the emit is the oracle.
/// The fix keys on every input <c>ResolveOwn</c> reads (declaring type id and method name among them) and rebinds a
/// memoized answer to each reference's own node id and classification key — rebinding is pinned on synthetic
/// references in <see cref="MemberIndexSynthesizedReferenceTests"/>.
/// </para>
/// </summary>
public sealed class MemoKeyNodeIdCollisionTests : IClassFixture<MemoKeyNodeIdCollisionFixture>
{
    #region Constructors
    public MemoKeyNodeIdCollisionTests(MemoKeyNodeIdCollisionFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The premise, measured: the two sites render one reference node id and one argument list, so the pre-S3 key
    /// <c>Key([assembly, nodeId, targetNodeId, "=", .. arguments])</c> is the same string for both — while the two
    /// declarations are different methods of different types.
    /// </summary>
    [Fact]
    public void Premise_TwoDifferentMethods_RenderOneNodeId_AndOneOldMemoKey()
    {
        var index = fixture.Assemblies.Index();
        var (g, x) = (Site(index, CallsGMethod), Site(index, CallsXMethod));

        Assert.Equal("NS.G`1.X`1.M(System.Int32)", CanonicalName.NodeId(ModelNames.Of(g.Target)));
        Assert.Equal("NS.G`1.X`1.M(System.Int32)", CanonicalName.NodeId(ModelNames.Of(x.Target)));
        Assert.Equal(["System.Int32"], ModelNames.TypeArguments(g.Target.ContainingType));
        Assert.Equal(["System.Int32"], ModelNames.TypeArguments(x.Target.ContainingType));
        Assert.Equal(OldKey(g), OldKey(x));

        Assert.Equal(2, index.Methods.Count(m => m.NodeId == SharedNodeId));
        Assert.Equal(["NS.G`1", "NS.G`1.X`1"], index.Methods.Where(m => m.NodeId == SharedNodeId).Select(m => m.DeclaringTypeId).Order(StringComparer.Ordinal).ToArray());
    }

    /// <summary>
    /// W-4: on a FRESH index (empty memo), in BOTH orders, each site resolves Substituted to its OWN declaration —
    /// checked by declaring type namespace and name and by method name, against the emitted IL.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Resolve_TwoMethodsSharingANodeId_EachResolveToTheirOwnDefinition_InEitherOrder(bool xFirst)
    {
        var index = fixture.Assemblies.Index();
        var (g, x) = (Site(index, CallsGMethod), Site(index, CallsXMethod));

        var first = index.Resolve((xFirst ? x : g).Target);
        var second = index.Resolve((xFirst ? g : x).Target);
        var (gResolution, xResolution) = xFirst ? (second, first) : (first, second);

        AssertDeclaration(gResolution, "NS", "G", "X`1.M");
        AssertDeclaration(xResolution, "NS.G`1", "X", "M");
        Assert.Same(Declaration(index, "NS.G`1"), gResolution.Definition);
        Assert.Same(Declaration(index, "NS.G`1.X`1"), xResolution.Definition);

        // Asked again, now from the memo: the same answers.
        Assert.Same(gResolution.Definition, index.Resolve(g.Target).Definition);
        Assert.Same(xResolution.Definition, index.Resolve(x.Target).Definition);
    }

    /// <summary>
    /// Each answer, after sharing an index with the other site, is exactly what an UNSHARED resolution of the same
    /// reference gives (a fresh index that resolves only it): kind, node id, classification key, candidates and
    /// definition. Nothing leaks from one memo entry into the other site's result.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Resolve_AfterTheOtherSite_EqualsAnUnsharedResolutionOfTheSameReference(bool xFirst)
    {
        var shared = fixture.Assemblies.Index();
        var (g, x) = (Site(shared, CallsGMethod), Site(shared, CallsXMethod));
        var order = xFirst ? new[] { x, g } : new[] { g, x };

        var answers = order.Select(s => (Site: s, Shared: shared.Resolve(s.Target))).ToArray();

        foreach (var (site, answer) in answers)
        {
            var unshared = fixture.Assemblies.Index().Resolve(site.Target);
            Assert.Equal(
                (unshared.Kind, unshared.NodeId, unshared.ClassificationKey, unshared.Assembly, unshared.Reason),
                (answer.Kind, answer.NodeId, answer.ClassificationKey, answer.Assembly, answer.Reason));
            Assert.Equal(unshared.Candidates, answer.Candidates);
            Assert.Same(unshared.Definition, answer.Definition);
            Assert.Equal(CanonicalName.ClassificationKey(ModelNames.Of(site.Target)), answer.ClassificationKey);
        }
    }

    private static void AssertDeclaration(MethodResolution resolution, string space, string type, string method)
    {
        Assert.True(resolution.Kind == ResolutionKind.Substituted,
            $"{space}::{type}.{method}: resolved {resolution.Kind} -> {resolution.NodeId} ({resolution.Reason}); expected Substituted.");
        var definition = Assert.IsType<Model.Types.MethodDefinition>(resolution.Definition);
        Model.Types.IBasicType declaring = definition.ContainingType;
        Assert.Equal((space, type, method), (declaring.ContainingNamespace, declaring.Name, definition.Name));
        Assert.Equal(SharedNodeId, resolution.NodeId);
        Assert.Equal([SharedNodeId], resolution.Candidates);
    }

    private static ModelCallSite Site(MemberIndex index, string caller) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == caller && s.Kind == MethodEdgeKind.CallVirt);

    private static Model.Types.MethodDefinition Declaration(MemberIndex index, string declaringTypeId) =>
        Assert.Single(index.Methods, m => m.NodeId == SharedNodeId && m.DeclaringTypeId == declaringTypeId).Definition;

    // The memo key as MemberIndex.Resolve built it before S3 (length-prefixed, S2): assembly, reference id, target id,
    // argument marker, arguments.
    private static string OldKey(ModelCallSite site)
    {
        var nodeId = CanonicalName.NodeId(ModelNames.Of(site.Target));
        var arguments = ModelNames.TypeArguments(site.Target.ContainingType);
        IEnumerable<string> parts = [site.DeclaringAssembly!, nodeId, nodeId, arguments is null ? "?" : "=", .. arguments ?? []];
        return string.Concat(parts.Select(p => $"{p.Length.ToString(CultureInfo.InvariantCulture)}:{p}"));
    }
    #endregion

    #region Fields
    internal const string AssemblyName = "Silvergun.Tests.EmitNodeIdCollision";

    private const string SharedNodeId = "NS.G`1.X`1.M(!0)";
    private const string CallsGMethod = "NS.Callers.CallsGMethod()";
    private const string CallsXMethod = "NS.Callers.CallsXMethod()";

    private readonly MemoKeyNodeIdCollisionFixture fixture;
    #endregion
}

/// <summary>
/// Emits the W-4 shape for <see cref="MemoKeyNodeIdCollisionTests"/> into this class fixture's own temporary directory:
/// namespace <c>NS</c> type <c>G`1</c> with a method literally named <c>X`1.M</c>(T), namespace <c>NS.G`1</c> type
/// <c>X`1</c> with method <c>M</c>(T), and one caller of each through <c>&lt;int&gt;</c>.
/// </summary>
public sealed class MemoKeyNodeIdCollisionFixture : IDisposable
{
    #region Constructors
    public MemoKeyNodeIdCollisionFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Assemblies = ModelAssemblies.Load(emitted.Save(MemoKeyNodeIdCollisionTests.AssemblyName, Define));
        }
        catch (Exception)
        {
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public ModelAssemblies Assemblies { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(System.Reflection.Emit.ModuleBuilder module)
    {
        var g = module.DefineType("NS.G`1", TypeAttributes.Public | TypeAttributes.Class);
        var gT = g.DefineGenericParameters("T")[0];
        var gConstructor = g.DefineDefaultConstructor(MethodAttributes.Public);
        var gMethod = EmittedAssembly.Returning(g, "X`1.M", gT, 10);

        // Namespace "NS.G`1", name "X`1": reflection splits a type's full name at its last dot.
        var x = module.DefineType("NS.G`1.X`1", TypeAttributes.Public | TypeAttributes.Class);
        var xT = x.DefineGenericParameters("T")[0];
        var xConstructor = x.DefineDefaultConstructor(MethodAttributes.Public);
        var xMethod = EmittedAssembly.Returning(x, "M", xT, 20);

        var callers = module.DefineType("NS.Callers", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        EmittedAssembly.CallThroughInstantiation(callers, "CallsGMethod", g, gConstructor, gMethod, typeof(int));
        EmittedAssembly.CallThroughInstantiation(callers, "CallsXMethod", x, xConstructor, xMethod, typeof(int));

        foreach (var type in new[] { g, x, callers })
            type.CreateType();
    }
    #endregion

    #region Fields
    private readonly EmittedAssembly emitted;
    #endregion
}
