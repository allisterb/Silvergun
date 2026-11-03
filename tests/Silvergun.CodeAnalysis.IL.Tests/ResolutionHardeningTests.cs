namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// The A1 hardening of <see cref="MemberIndex.Resolve"/> (docs/agent/tasks/capslock-mechanism-fixtures-and-a1.md,
/// A1-W2r5 and "A1-W2r5 and A1-TF: implemented"):
/// <list type="bullet">
/// <item><description>a non-generic site is one lookup by (assembly, node id, return type), so N duplicate definitions ×
/// M references that differ only in return type answer correctly without N×M work;</description></item>
/// <item><description>a substituted site compares at most 64 same-shaped candidates; past that it is Ambiguous without
/// comparing, with the whole shape bucket's candidate list, computed once and shared;</description></item>
/// <item><description>method buckets are keyed per canonical assembly, case-insensitively like ownership.</description></item>
/// </list>
/// The duplicates are hand-built Model objects (<see cref="SyntheticModel"/>), since no compiler or emitter writes N
/// TypeDefs of one name; the overload cap is an EMITTED assembly (<see cref="CapShapesFixture"/>).
/// </summary>
public sealed class ResolutionHardeningTests : IClassFixture<CapShapesFixture>
{
    #region Constructors
    public ResolutionHardeningTests(CapShapesFixture caps) => this.caps = caps;
    #endregion

    #region Methods
    // ---- A1-W2r5: duplicates x return types -------------------------------------------------------------------------

    /// <summary>
    /// 200 duplicate definitions of <c>Dup.T.M()</c> (one assembly, one node id, all returning <c>string</c>) against 200
    /// references that differ only in return type: the one returning <c>string</c> is Ambiguous among the duplicates (one
    /// distinct candidate id), and each of the other 199 is Unresolved "no indexed definition matches" — the return type
    /// is not in a node id, and it is what separates them. With a single definition the match is Exact.
    /// (Correctness only: no wall-clock cost pin, and no ratio check robust enough to keep.)
    /// </summary>
    [Theory]
    [InlineData(200, ResolutionKind.Ambiguous)]
    [InlineData(1, ResolutionKind.Exact)]
    public void Resolve_DuplicateDefinitionsAgainstReturnTypeVariants_OnlyTheMatchingReturnTypeResolves(int duplicates, ResolutionKind matchKind)
    {
        const string assembly = "Dups";
        var index = MemberIndex.Build([(Duplicates(assembly, duplicates), TypeForwarders.None)]);
        Assert.Equal(duplicates, index.Methods.Count(m => m.NodeId == "Dup.T.M()"));
        var references = Enumerable.Range(0, 200)
            .Select(i => Reference(assembly, i == 100 ? ModelTypes.PlatformTypes.String : SyntheticModel.TypeRef("R", $"T{i}", assembly: "Elsewhere")))
            .ToArray();

        var answers = references.Select(index.Resolve).ToArray();

        var match = answers[100];
        Assert.Equal(matchKind, match.Kind);
        Assert.Equal("Dup.T.M()", match.NodeId);
        Assert.Equal(["Dup.T.M()"], match.Candidates);
        Assert.Equal(matchKind == ResolutionKind.Ambiguous ? "several definitions share this node id" : null, match.Reason);
        Assert.All(answers.Where((_, i) => i != 100), a =>
        {
            Assert.Equal(ResolutionKind.Unresolved, a.Kind);
            Assert.Equal("no indexed definition matches", a.Reason);
            Assert.Empty(a.Candidates);
            Assert.Equal(assembly, a.Assembly);
        });
    }

    // ---- A1-W2r5: the substituted-site cap ---------------------------------------------------------------------------

    /// <summary>
    /// 64 same-shaped overloads (<c>M(!0, Pk)</c>, one name, two parameters, differing in the second) are compared, so a
    /// reference through <c>G64&lt;int&gt;</c> resolves Substituted to the one overload it names.
    /// </summary>
    [Fact]
    public void Resolve_SixtyFourSameShapedOverloads_AreCompared_AndTheSubstitutedReferenceResolves()
    {
        Assert.Equal(64, caps.Index.Methods.Count(m => m.DeclaringTypeId == "Caps.G64`1" && m.Definition.Name == "M"));

        var resolution = caps.Index.Resolve(caps.Target("Calls64Int"));

        Assert.Equal(ResolutionKind.Substituted, resolution.Kind);
        Assert.Equal("Caps.G64`1.M(!0,Caps.P3)", resolution.NodeId);
        Assert.Equal(["Caps.G64`1.M(!0,Caps.P3)"], resolution.Candidates);
        Assert.Null(resolution.Reason);
    }

    /// <summary>
    /// 65 same-shaped overloads are past the cap: Ambiguous without comparing, with the reason and EVERY candidate kept.
    /// Two instantiations (<c>G65&lt;int&gt;</c>, <c>G65&lt;string&gt;</c>) share the one candidate list of the shape bucket
    /// (computed once, <c>shapeCandidates</c>), ordinal-sorted.
    /// </summary>
    [Fact]
    public void Resolve_SixtyFiveSameShapedOverloads_AreAmbiguousWithoutComparing_AndShareOneCandidateList()
    {
        var overloads = caps.Index.Methods.Where(m => m.DeclaringTypeId == "Caps.G65`1" && m.Definition.Name == "M").Select(m => m.NodeId).ToArray();
        Assert.Equal(65, overloads.Length);

        var ofInt = caps.Index.Resolve(caps.Target("Calls65Int"));
        var ofString = caps.Index.Resolve(caps.Target("Calls65String"));

        foreach (var resolution in new[] { ofInt, ofString })
        {
            Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
            Assert.False(resolution.IsOwn);
            Assert.Equal("more than 64 definitions have this shape, too many to compare", resolution.Reason);
            Assert.Equal(overloads.Order(StringComparer.Ordinal), resolution.Candidates);
            Assert.Equal(CapShapesFixture.Name, resolution.Assembly);
        }
        Assert.Same(ofInt.Candidates, ofString.Candidates);
        Assert.NotEqual(ofInt.NodeId, ofString.NodeId);
    }

    /// <summary>
    /// In the graph, the capped site keeps an edge to every one of the 65 candidates and one Ambiguous opacity with the
    /// reason, as any Ambiguous site does; the compared one has its single Call edge.
    /// </summary>
    [Fact]
    public void Graph_ACappedSite_KeepsAnEdgeToEveryCandidate_AndRecordsTheReason()
    {
        var capped = caps.Site("Calls65Int");
        var compared = caps.Site("Calls64Int");

        Assert.Equal(65, caps.Graph.Successors(capped.Caller.NodeId).Count(e => e.Kind == MethodEdgeKind.Call && e.Offset == capped.Offset));
        Assert.Contains(caps.Graph.Opacities, o => o.Site == capped.Caller.NodeId && o.Kind == OpacityKind.Ambiguous &&
            o.Detail.EndsWith(": more than 64 definitions have this shape, too many to compare", StringComparison.Ordinal));
        Assert.Equal([new MethodEdge(compared.Caller.NodeId, "Caps.G64`1.M(!0,Caps.P3)", MethodEdgeKind.Call, compared.Offset)],
            caps.Graph.Successors(compared.Caller.NodeId));
    }

    // ---- A1-W2r5: per-assembly keys, case-insensitive -------------------------------------------------------------------

    /// <summary>
    /// A reference whose declaring-assembly name differs from the indexed one's only in case still resolves to own code
    /// (ownership is case-insensitive, and so are the method buckets' assembly keys).
    /// </summary>
    [Theory]
    [InlineData("CapShapes")]
    [InlineData("CAPSHAPES")]
    [InlineData("capshapes")]
    public void Resolve_ADeclaringAssemblyNameDifferingOnlyInCase_StillResolvesToOwnCode(string spelling)
    {
        var reference = SyntheticModel.Method(SyntheticModel.TypeRef("Caps", "Plain", assembly: spelling), "Run");

        var resolution = caps.Index.Resolve(reference);

        Assert.Equal(ResolutionKind.Exact, resolution.Kind);
        Assert.True(resolution.IsOwn);
        Assert.Equal("Caps.Plain.Run()", resolution.NodeId);
        Assert.Equal(CapShapesFixture.Name, resolution.Assembly);
    }

    // `duplicates` classes Dup.T in one assembly, each with a static `string M()` and no body.
    private static Model.Assembly Duplicates(string name, int duplicates)
    {
        var assembly = new Model.Assembly(name);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace("Dup") { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;
        for (var i = 0; i < duplicates; i++)
        {
            var type = new ModelTypes.ClassDefinition("T") { ContainingAssembly = assembly, ContainingNamespace = space };
            type.Methods.Add(new ModelTypes.MethodDefinition("M", ModelTypes.PlatformTypes.String) { ContainingType = type, IsStatic = true });
            space.Types.Add(type);
        }
        return assembly;
    }

    // A reference to static Dup.T.M() in `assembly`, returning `returnType`.
    private static ModelTypes.MethodReference Reference(string assembly, ModelTypes.IType returnType) =>
        new("M", returnType) { ContainingType = SyntheticModel.TypeRef("Dup", "T", assembly: assembly), IsStatic = true };
    #endregion

    #region Fields
    private readonly CapShapesFixture caps;
    #endregion
}

/// <summary>
/// One emitted assembly, <c>CapShapes</c> (<see cref="EmittedAssembly"/>; never loaded or run), namespace <c>Caps</c>:
/// classes <c>P0</c>..<c>P64</c>; generic <c>G64&lt;T&gt;</c> with 64 static overloads <c>M(T, Pk)</c> and <c>G65&lt;T&gt;</c>
/// with 65; <c>Plain</c> with a static <c>int Run()</c>; and <c>Callers</c>, one static method per site, each a single
/// call.
/// </summary>
public sealed class CapShapesFixture : IDisposable
{
    #region Constructors
    public CapShapesFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Path = emitted.Save(Name, Define);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            Sites = ModelCallSite.All(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>The single call site of <c>Caps.Callers.{caller}()</c>.</summary>
    public ModelCallSite Site(string caller) => Assert.Single(Sites, s => s.Caller.NodeId == $"Caps.Callers.{caller}()");

    /// <summary>The reference at that site.</summary>
    public ModelTypes.IMethodReference Target(string caller) => Site(caller).Target;

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        var parameters = Enumerable.Range(0, 65).Select(k => module.DefineType($"Caps.P{k}", TypeAttributes.Public | TypeAttributes.Class)).ToArray();
        var g64 = Overloads(module, "Caps.G64`1", parameters[..64]);
        var g65 = Overloads(module, "Caps.G65`1", parameters);

        var plain = module.DefineType("Caps.Plain", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var run = plain.DefineMethod("Run", StaticMethod, typeof(int), Type.EmptyTypes).GetILGenerator();
        run.Emit(OpCodes.Ldc_I4_0);
        run.Emit(OpCodes.Ret);

        var callers = module.DefineType("Caps.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(callers, "Calls64Int", g64.Type, g64.Methods[3], typeof(int));
        Caller(callers, "Calls65Int", g65.Type, g65.Methods[3], typeof(int));
        Caller(callers, "Calls65String", g65.Type, g65.Methods[3], typeof(string));

        foreach (var type in parameters.Append(g64.Type).Append(g65.Type).Append(plain).Append(callers))
            type.CreateType();
    }

    // A generic type `name` with one static void overload M(T, p) per p.
    private static (TypeBuilder Type, MethodBuilder[] Methods) Overloads(ModuleBuilder module, string name, TypeBuilder[] parameters)
    {
        var type = module.DefineType(name, TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var t = type.DefineGenericParameters("T")[0];
        var methods = parameters.Select(p =>
        {
            var method = type.DefineMethod("M", StaticMethod, typeof(void), [t, p]);
            method.GetILGenerator().Emit(OpCodes.Ret);
            return method;
        }).ToArray();
        return (type, methods);
    }

    // static void name() => generic<argument>.M(default, null);
    private static void Caller(TypeBuilder callers, string name, TypeBuilder generic, MethodBuilder method, Type argument)
    {
        var il = callers.DefineMethod(name, StaticMethod, typeof(void), Type.EmptyTypes).GetILGenerator();
        il.Emit(argument == typeof(int) ? OpCodes.Ldc_I4_0 : OpCodes.Ldnull);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Call, TypeBuilder.GetMethod(generic.MakeGenericType(argument), method));
        il.Emit(OpCodes.Ret);
    }
    #endregion

    #region Fields
    /// <summary>The emitted assembly's name.</summary>
    public const string Name = "CapShapes";

    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static;

    private readonly EmittedAssembly emitted;
    #endregion
}
