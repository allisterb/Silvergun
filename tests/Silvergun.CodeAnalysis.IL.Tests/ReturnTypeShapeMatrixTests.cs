namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// A2 S1 review 2, <b>W-C</b> (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md, "S1 review 2 … (S1d)"): the matrix of
/// return shapes for A1's return-type check in <c>ResolveOwn</c> (review 1, C2; the single-shape tests are
/// <see cref="ReturnTypeResolutionTests"/>). The shapes are the reviewer's probe case I — by-ref, <c>ref readonly</c>
/// (modreq <c>InAttribute</c>), a modopt, single- and multi-dimensional arrays, a nested generic, and generic method
/// instances — each defined TWICE in one type with the same name and parameters, differing only in the return type, so
/// the pair shares one node id and only the return type can tell them apart. Every shape is on a plain class and on
/// <c>Box&lt;T&gt;</c> called through <c>Box&lt;int&gt;</c>. The CLR is the oracle for which definition each emitted
/// reference binds: every body throws a marker naming itself.
/// <para>
/// Two shapes are not emitted as asked, because <see cref="PersistedAssemblyBuilder"/> (.NET 10) cannot write them:
/// a FUNCTION POINTER in a signature (<c>ArgumentException: Unexpected handle kind: TypeSpecification</c>), pinned on
/// SYNTHETIC Model objects instead (<see cref="SyntheticModel"/>: covers <c>ResolveOwn</c> and
/// <see cref="ModelNames.ReturnType"/>, not CCI's reading of the signature); and a multi-dimensional array of a generic
/// parameter (same exception), so on <c>Box</c> the multi-dimensional shapes have an <c>int</c> element. It also drops a
/// return type's custom modifiers from the MemberRef it writes for a loaded method, so the references of the four
/// modifier shapes are written as raw metadata rows (<see cref="ReturnShapesFixture"/>).
/// </para>
/// </summary>
public sealed class ReturnTypeShapeMatrixTests : IClassFixture<ReturnShapesFixture>, IClassFixture<ErasedReturnFixture>
{
    #region Constructors
    public ReturnTypeShapeMatrixTests(ReturnShapesFixture fixture, ErasedReturnFixture erased)
    {
        this.fixture = fixture;
        this.erased = erased;
    }
    #endregion

    #region Methods
    public static TheoryData<string, string, string> Cases()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var owner in ReturnShapesFixture.Owners)
            foreach (var name in ReturnShapesFixture.Names)
                foreach (var variant in ReturnShapesFixture.Variants)
                    data.Add(owner, name, variant);
        return data;
    }

    public static TheoryData<string, string> Pairs()
    {
        var data = new TheoryData<string, string>();
        foreach (var owner in ReturnShapesFixture.Owners)
            foreach (var name in ReturnShapesFixture.Names)
                data.Add(owner, name);
        return data;
    }

    /// <summary>
    /// The oracle: the reference emitted for each definition binds, at run time, to exactly that definition (its body's
    /// marker) — so the reference's signature carries the return shape (by-ref, modifiers and all), not just its name.
    /// </summary>
    [Theory]
    [MemberData(nameof(Cases))]
    public void Runtime_EachReference_BindsTheDefinitionItWasEmittedFor(string owner, string name, string variant) =>
        Assert.Equal($"{name}-{variant}", fixture.Run($"{owner}{name}{variant}"));

    /// <summary>The premise: both definitions of a pair are indexed, in definition order, under one node id — so a node id alone cannot choose.</summary>
    [Theory]
    [MemberData(nameof(Pairs))]
    public void Premise_APairSharesOneNodeId(string owner, string name)
    {
        var (main, sibling) = fixture.Pair(owner, name);

        Assert.Equal(main.NodeId, sibling.NodeId);
        Assert.Equal(name, main.Definition.Name);
    }

    /// <summary>
    /// THE CHECK: a reference to either definition of a pair resolves to that definition, never Unresolved, and so its
    /// return-type-only sibling is excluded (never Ambiguous over both). The kind: Exact on the plain class; Substituted
    /// through <c>Box&lt;int&gt;</c> — except a generic method instance there (<c>Gen&lt;int&gt;</c>, <c>GenT&lt;int&gt;</c>),
    /// which resolves through CCI's <c>GenericMethod</c>, the definition-level method typed by <c>!0</c>, so it is Exact.
    /// On failure the message gives the rendered <see cref="ModelNames.ReturnType"/> of the reference and of both
    /// definitions.
    /// </summary>
    [Theory]
    [MemberData(nameof(Cases))]
    public void Resolve_AReturnShape_IsItsOwnDefinition_NotItsReturnTypeSibling(string owner, string name, string variant)
    {
        var (main, sibling) = fixture.Pair(owner, name);
        var (expected, other) = variant == "Main" ? (main, sibling) : (sibling, main);
        var site = fixture.Site($"{owner}{name}{variant}");
        var kind = owner == "Plain" || name is "Gen" or "GenT" ? ResolutionKind.Exact : ResolutionKind.Substituted;

        var resolution = fixture.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == kind && ReferenceEquals(resolution.Definition, expected.Definition), Describe(owner, name, variant, kind, site, resolution, expected, other));
        Assert.Equal(expected.NodeId, resolution.NodeId);
        Assert.Null(resolution.Reason);
    }

    /// <summary>
    /// The function pointer pair, synthetic (see the class summary): <c>SynFn.Plain</c> defines <c>delegate*&lt;int&gt; Fn()</c>
    /// and <c>delegate*&lt;long&gt; Fn()</c>; a reference returning either resolves Exact to that one, never the other.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Resolve_AFunctionPointerReturn_IsItsOwnDefinition_NotItsReturnTypeSibling(int which)
    {
        ModelTypes.IType[] returns = [ModelTypes.PlatformTypes.Int32, ModelTypes.PlatformTypes.Int64];
        var assembly = new Model.Assembly("SynFn");
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace("SynFn") { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;
        var plain = new ModelTypes.ClassDefinition("Plain") { ContainingAssembly = assembly, ContainingNamespace = space, Base = SyntheticModel.TypeRef("System", "Object", assembly: "System.Private.CoreLib") };
        space.Types.Add(plain);
        var definitions = returns.Select(r => new ModelTypes.MethodDefinition("Fn", SyntheticModel.FunctionPointer(r)) { ContainingType = plain }).ToArray();
        foreach (var definition in definitions)
            plain.Methods.Add(definition);
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
        var reference = new ModelTypes.MethodReference("Fn", SyntheticModel.FunctionPointer(returns[which])) { ContainingType = SyntheticModel.TypeRef("SynFn", "Plain", assembly: "SynFn") };

        var resolution = index.Resolve(reference);

        Assert.Equal(2, index.Methods.Count(m => m.NodeId == "SynFn.Plain.Fn()"));
        Assert.True(resolution.Kind == ResolutionKind.Exact && ReferenceEquals(resolution.Definition, definitions[which]),
            $"resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); ReturnType: reference '{ModelNames.ReturnType(reference, [])}', " +
            $"definitions '{ModelNames.ReturnType(definitions[0], [])}' and '{ModelNames.ReturnType(definitions[1], [])}'.");
    }

    // ---- what an erased return type costs (review 1 C2, with by-ref-ness or a modifier as the only difference) --------

    /// <summary>
    /// The oracle for <see cref="ErasedReturnFixture"/>: <c>callvirt int Derived::Q()</c> (and <c>::R()</c>) never runs
    /// Derived's own non-virtual <c>ref int Q()</c> (<c>int modopt(IsConst) R()</c>) — whose signature differs — but the
    /// base's virtual, or the override on a <c>Sub</c>.
    /// </summary>
    [Theory]
    [InlineData("CallsQ", "Erased.Sub", "SUB-Q")]
    [InlineData("CallsQ", "Erased.Derived", "BASE-Q")]
    [InlineData("CallsR", "Erased.Sub", "SUB-R")]
    [InlineData("CallsR", "Erased.Derived", "BASE-R")]
    public void Runtime_ACallToTheBaseShape_NeverRunsTheErasedSibling(string caller, string receiver, string expected) =>
        Assert.Equal(expected, erased.Run(caller, receiver));

    /// <summary>
    /// Review 1 C2 again, where the only difference is by-ref-ness (<c>Q</c>) or a modopt (<c>R</c>): no indexed
    /// definition has the reference's signature, so it must be Unresolved — not Exact to Derived's non-virtual sibling,
    /// which would also stop CHA ("a non-virtual definition does not dispatch") from reaching <c>Sub</c>'s override,
    /// the method the CLR runs. On failure the message gives the rendered return types.
    /// </summary>
    [Theory]
    [InlineData("CallsQ", "Q")]
    [InlineData("CallsR", "R")]
    public void Resolve_AReferenceWhoseReturnDiffersOnlyByRefOrModifier_IsNotTheSibling_AndReachesTheOverride(string caller, string method)
    {
        var site = erased.Site(caller);
        var sibling = Assert.Single(erased.Index.Methods, m => m.NodeId == $"Erased.Derived.{method}()");
        Assert.False(sibling.Definition.IsVirtual);

        var resolution = erased.Index.Resolve(site.Target);
        var targets = site.DispatchTargets(erased.Index);

        Assert.True(resolution.Kind == ResolutionKind.Unresolved && targets is not null && targets.Contains($"Erased.Sub.{method}()"),
            $"resolved {resolution.Kind} to {(ReferenceEquals(resolution.Definition, sibling.Definition) ? "THE NON-VIRTUAL SIBLING" : resolution.NodeId)} ({resolution.Reason}); " +
            $"dispatch [{string.Join(", ", targets ?? [])}]; expected Unresolved, with a Dispatch target Erased.Sub.{method}(). " +
            $"ReturnType: reference '{ModelNames.ReturnType(site.Target, [])}', Derived's sibling '{ModelNames.ReturnType(sibling.Definition, [])}'.");
    }

    // What resolved, and the rendered return types on every side.
    private static string Describe(string owner, string name, string variant, ResolutionKind kind, ModelCallSite site, MethodResolution resolution, MemberIndex.IndexedMethod expected, MemberIndex.IndexedMethod other)
    {
        IReadOnlyList<string> arguments = owner == "Plain" ? [] : ["System.Int32"];
        var reference = site.Target.GenericMethod ?? site.Target;
        var resolved = resolution.Definition is null ? "no definition"
            : ReferenceEquals(resolution.Definition, expected.Definition) ? "this definition"
            : ReferenceEquals(resolution.Definition, other.Definition) ? "THE SIBLING" : "another definition";
        return $"{owner}.{name} ({variant}): resolved {resolution.Kind} to {resolved}, {resolution.NodeId} " +
               $"[{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected {kind} to this definition. " +
               $"ReturnType: reference '{ModelNames.ReturnType(reference, [])}', this definition '{ModelNames.ReturnType(expected.Definition, arguments)}', " +
               $"its sibling '{ModelNames.ReturnType(other.Definition, arguments)}' (definitions rendered with [{string.Join(", ", arguments)}]).";
    }
    #endregion

    #region Fields
    private readonly ReturnShapesFixture fixture;
    private readonly ErasedReturnFixture erased;
    #endregion
}

/// <summary>
/// The emitted assemblies of <see cref="ReturnTypeShapeMatrixTests"/>' matrix (never loaded into the default context):
/// <list type="bullet">
/// <item><description><c>ChaRetShapes</c>: <c>RS.Plain</c> and <c>RS.Box`1</c>, each declaring, for every name in
/// <see cref="Names"/>, a <c>Main</c> definition and then a <c>Sibling</c> with the same name and parameters (none) and
/// a different return type (<see cref="Shapes"/>; on <c>Box`1</c> the argument is <c>T</c>, on <c>Plain</c> it is
/// <c>int</c>). Every body throws <c>InvalidOperationException("{name}-{variant}")</c>.</description></item>
/// <item><description><c>ChaRetShapesCaller</c>: <c>RSCaller.Callers.{owner}{name}{variant}(owner)</c> =
/// <c>ldarg.0; call that definition (on Box&lt;int&gt;; a generic method as &lt;int&gt;); pop; ret</c> — emitted against the
/// loaded library, so each reference is written from the definition's own signature. All but the modifier shapes.</description></item>
/// <item><description><c>ChaRetShapesModCaller</c>: the same for the four modifier shapes (<see cref="Modified"/>), as
/// <c>RSCaller.ModCallers.{owner}{name}{variant}()</c> = <c>ldnull; call; pop; ret</c>, whose MemberRefs (with their
/// modreq/modopt) are raw metadata rows: Reflection.Emit writes a loaded method's MemberRef without them.</description></item>
/// </list>
/// </summary>
public sealed class ReturnShapesFixture : IDisposable
{
    #region Constructors
    public ReturnShapesFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Library = emitted.Save(LibraryName, DefineLibrary, "library");
            using (var context = new IsolatedLoadContext())
            {
                var library = context.LoadBytes(Library);
                Caller = emitted.Save("ChaRetShapesCaller", module => DefineCaller(module, library), "caller");
            }
            ModCaller = emitted.Save("ChaRetShapesModCaller", DefineModCaller, AddModReferences, "modcaller");
            Assemblies = ModelAssemblies.Load(Library, Caller, ModCaller);
            Index = Assemblies.Index();
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
    public string Library { get; }

    public string Caller { get; }

    public string ModCaller { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>The single call site of <c>RSCaller.Callers.{caller}</c> or <c>RSCaller.ModCallers.{caller}</c>.</summary>
    public ModelCallSite Site(string caller) =>
        Assert.Single(Sites, s => s.Caller.NodeId.StartsWith($"RSCaller.Callers.{caller}(", StringComparison.Ordinal)
                                  || s.Caller.NodeId.StartsWith($"RSCaller.ModCallers.{caller}(", StringComparison.Ordinal));

    /// <summary>The indexed Main and Sibling definitions of <paramref name="name"/> in <c>RS.{owner}</c>, in definition order.</summary>
    public (MemberIndex.IndexedMethod Main, MemberIndex.IndexedMethod Sibling) Pair(string owner, string name)
    {
        var typeId = owner == "Plain" ? "RS.Plain" : "RS.Box`1";
        var type = (ModelTypes.ClassDefinition)Assert.Single(Index.Types(typeId)).Definition;
        var definitions = type.Methods.Where(m => m.Name == name).ToArray();
        Assert.Equal(2, definitions.Length);
        MemberIndex.IndexedMethod Indexed(ModelTypes.MethodDefinition definition) => Assert.Single(Index.Methods, m => ReferenceEquals(m.Definition, definition));
        return (Indexed(definitions[0]), Indexed(definitions[1]));
    }

    /// <summary>Runs the caller <paramref name="caller"/> with the library pinned and returns the marker its target threw.</summary>
    public string? Run(string caller)
    {
        using var context = new IsolatedLoadContext(new Dictionary<string, string> { [LibraryName] = Library });
        var modified = Modified.Any(m => caller.EndsWith(m + "Main", StringComparison.Ordinal) || caller.EndsWith(m + "Sibling", StringComparison.Ordinal));
        var method = context.LoadBytes(modified ? ModCaller : Caller).GetType(modified ? "RSCaller.ModCallers" : "RSCaller.Callers", throwOnError: true)!.GetMethod(caller)!;
        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, modified ? null : [null]));
        return Assert.IsType<InvalidOperationException>(thrown.InnerException).Message;
    }

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void DefineLibrary(ModuleBuilder module)
    {
        var box = module.DefineType("RS.Box`1", TypeAttributes.Public | TypeAttributes.Class);
        var t = box.DefineGenericParameters("T")[0];
        var plain = module.DefineType("RS.Plain", TypeAttributes.Public | TypeAttributes.Class);

        foreach (var (owner, argument) in new[] { (box, (Type)t), (plain, typeof(int)) })
        {
            foreach (var (name, main, sibling) in Shapes)
            {
                foreach (var (variant, shape) in new[] { ("Main", main(argument)), ("Sibling", sibling(argument)) })
                    Throwing(owner.DefineMethod(name, Instance, CallingConventions.HasThis, shape.Type, shape.Required, shape.Optional, Type.EmptyTypes, null, null), $"{name}-{variant}");
            }

            // U Gen<U>() and int Gen<U>().
            foreach (var variant in Variants)
            {
                var gen = owner.DefineMethod("Gen", Instance);
                var u = gen.DefineGenericParameters("U")[0];
                gen.SetSignature(variant == "Main" ? u : typeof(int), null, null, Type.EmptyTypes, null, null);
                Throwing(gen, $"Gen-{variant}");
            }

            // Dictionary<argument, U> GenT<U>() and Dictionary<long, U> GenT<U>().
            foreach (var variant in Variants)
            {
                var gen = owner.DefineMethod("GenT", Instance);
                var u = gen.DefineGenericParameters("U")[0];
                gen.SetSignature(typeof(Dictionary<,>).MakeGenericType(variant == "Main" ? argument : typeof(long), u), null, null, Type.EmptyTypes, null, null);
                Throwing(gen, $"GenT-{variant}");
            }
        }

        box.CreateType();
        plain.CreateType();
    }

    private static void DefineCaller(ModuleBuilder module, Assembly library)
    {
        var callers = module.DefineType("RSCaller.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var owners = new Dictionary<string, Type>
        {
            ["Plain"] = library.GetType("RS.Plain", throwOnError: true)!,
            ["Box"] = library.GetType("RS.Box`1", throwOnError: true)!.MakeGenericType(typeof(int)),
        };

        foreach (var owner in Owners)
        {
            var type = owners[owner];
            foreach (var name in Names.Except(Modified))
            {
                // Main first, then Sibling: definition order is token order (also on Box<int>, whose methods carry the
                // generic definition's tokens).
                var pair = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                    .Where(m => m.Name == name).OrderBy(m => m.MetadataToken).ToArray();
                if (pair.Length != 2)
                    throw new InvalidOperationException($"{owner}.{name}: {pair.Length} definitions loaded, expected 2.");
                for (var i = 0; i < 2; i++)
                {
                    var target = pair[i].IsGenericMethodDefinition ? pair[i].MakeGenericMethod(typeof(int)) : pair[i];
                    var il = callers.DefineMethod($"{owner}{name}{Variants[i]}", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [type]).GetILGenerator();
                    il.Emit(OpCodes.Ldarg_0);
                    il.Emit(OpCodes.Call, target);
                    il.Emit(OpCodes.Pop);
                    il.Emit(OpCodes.Ret);
                }
            }
        }

        callers.CreateType();
    }

    // RSCaller.ModCallers: one parameterless static per (owner, modifier shape, variant), in ModCalls order, whose body
    // calls MemberRef row k (k = 1, 2, ...) - rows AddModReferences adds in the same order.
    private static void DefineModCaller(ModuleBuilder module)
    {
        var callers = module.DefineType("RSCaller.ModCallers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        foreach (var (call, row) in ModCalls.Select((c, i) => (c, i + 1)))
        {
            var il = callers.DefineMethod($"{call.Owner}{call.Name}{call.Variant}", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes).GetILGenerator();
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Call, MetadataTokens.GetToken(MetadataTokens.MemberReferenceHandle(row)));
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        }
        callers.CreateType();
    }

    // The MemberRefs DefineModCaller's bodies call, with the exact return signature of each definition (custom modifier,
    // then BYREF, then int32 / int64 / !0), parented by RS.Plain or Box<int32>.
    private static void AddModReferences(MetadataBuilder metadata)
    {
        if (metadata.GetRowCount(TableIndex.MemberRef) != 0)
            throw new InvalidOperationException($"ChaRetShapesModCaller already has {metadata.GetRowCount(TableIndex.MemberRef)} MemberRef rows; the call tokens assume none.");
        var library = EmittedAssembly.Reference(metadata, LibraryName);
        var core = EmittedAssembly.Reference(metadata, typeof(object).Assembly.GetName().Name!);
        var plain = metadata.AddTypeReference(library, metadata.GetOrAddString("RS"), metadata.GetOrAddString("Plain"));
        var boxDefinition = metadata.AddTypeReference(library, metadata.GetOrAddString("RS"), metadata.GetOrAddString("Box`1"));
        var boxSignature = new BlobBuilder();
        new BlobEncoder(boxSignature).TypeSpecificationSignature().GenericInstantiation(boxDefinition, 1, isValueType: false).AddArgument().Int32();
        var boxInt = metadata.AddTypeSpecification(metadata.GetOrAddBlob(boxSignature));
        var inAttribute = metadata.AddTypeReference(core, metadata.GetOrAddString("System.Runtime.InteropServices"), metadata.GetOrAddString(nameof(InAttribute)));
        var isConst = metadata.AddTypeReference(core, metadata.GetOrAddString("System.Runtime.CompilerServices"), metadata.GetOrAddString(nameof(IsConst)));

        foreach (var call in ModCalls)
        {
            var signature = new BlobBuilder();
            new BlobEncoder(signature).MethodSignature(isInstanceMethod: true).Parameters(0, out var returns, out _);
            var modifiers = returns.CustomModifiers();
            if (call.Return.Modifier is { } modifier)
                modifiers.AddModifier(modifier == nameof(InAttribute) ? inAttribute : isConst, isOptional: modifier == nameof(IsConst));
            var type = returns.Type(call.Return.ByRef);
            if (call.Return.Long)
                type.Int64();
            else if (call.Owner == "Box")
                type.GenericTypeParameter(0);
            else
                type.Int32();
            metadata.AddMemberReference(call.Owner == "Plain" ? plain : boxInt, metadata.GetOrAddString(call.Name), metadata.GetOrAddBlob(signature));
        }
    }

    // A multi-dimensional array of `element` - of int where `element` is a generic parameter: PersistedAssemblyBuilder
    // (.NET 10) writes a multi-dimensional array's element type as a plain type handle, which a generic parameter is not
    // (ArgumentException "Unexpected handle kind: TypeSpecification"). On Box<int> an int element still differs from its
    // sibling in the rank alone.
    private static Type MultiDimensional(Type element, int rank) => (element.IsGenericParameter ? typeof(int) : element).MakeArrayType(rank);

    private static void Throwing(MethodBuilder method, string marker)
    {
        var il = method.GetILGenerator();
        il.Emit(OpCodes.Ldstr, marker);
        il.Emit(OpCodes.Newobj, typeof(InvalidOperationException).GetConstructor([typeof(string)])!);
        il.Emit(OpCodes.Throw);
    }
    #endregion

    #region Fields
    public const string LibraryName = "ChaRetShapes";

    public static readonly string[] Owners = ["Plain", "Box"];

    public static readonly string[] Variants = ["Main", "Sibling"];

    /// <summary>
    /// The non-generic-method shapes: for an argument <c>a</c> (<c>T</c> on Box, <c>int</c> on Plain), the Main and the
    /// Sibling return. A sibling differs from Main in the return type only — in its element type, its by-ref-ness, a
    /// modifier, an array rank, or a nested type argument.
    /// </summary>
    private static readonly (string Name, Func<Type, Return> Main, Func<Type, Return> Sibling)[] Shapes =
    [
        ("RefGet", a => new(a.MakeByRefType()), _ => new(typeof(long).MakeByRefType())),
        ("RefVal", a => new(a.MakeByRefType()), a => new(a)),
        ("RoGet", a => new(a.MakeByRefType(), Required: [typeof(InAttribute)]), _ => new(typeof(long).MakeByRefType(), Required: [typeof(InAttribute)])),
        ("RoRef", a => new(a.MakeByRefType(), Required: [typeof(InAttribute)]), a => new(a.MakeByRefType())),
        ("ModOpt", a => new(a, Optional: [typeof(IsConst)]), _ => new(typeof(long), Optional: [typeof(IsConst)])),
        ("ModOptNone", a => new(a, Optional: [typeof(IsConst)]), a => new(a)),
        ("Arr", a => new(a.MakeArrayType()), _ => new(typeof(long).MakeArrayType())),
        ("ArrRank", a => new(a.MakeArrayType()), a => new(MultiDimensional(a, 2))),
        ("Mat", a => new(MultiDimensional(a, 3)), a => new(MultiDimensional(a, 2))),
        ("Nest", a => new(typeof(List<>).MakeGenericType(typeof(Dictionary<,>).MakeGenericType(typeof(string), a))),
                 _ => new(typeof(List<Dictionary<string, long>>))),
    ];

    /// <summary>Every name in the library: <see cref="Shapes"/>'s, then the two generic methods.</summary>
    public static readonly string[] Names = [.. Shapes.Select(s => s.Name), "Gen", "GenT"];

    /// <summary>The shapes whose references carry a custom modifier, written as raw rows: the same returns as <see cref="Shapes"/>' (the oracle checks they bind).</summary>
    private static readonly (string Name, RawReturn Main, RawReturn Sibling)[] ModifiedShapes =
    [
        ("RoGet", new(nameof(InAttribute), ByRef: true, Long: false), new(nameof(InAttribute), ByRef: true, Long: true)),
        ("RoRef", new(nameof(InAttribute), ByRef: true, Long: false), new(null, ByRef: true, Long: false)),
        ("ModOpt", new(nameof(IsConst), ByRef: false, Long: false), new(nameof(IsConst), ByRef: false, Long: true)),
        ("ModOptNone", new(nameof(IsConst), ByRef: false, Long: false), new(null, ByRef: false, Long: false)),
    ];

    private static readonly string[] Modified = [.. ModifiedShapes.Select(s => s.Name)];

    // Every raw call, in MemberRef row order.
    private static readonly (string Owner, string Name, string Variant, RawReturn Return)[] ModCalls =
        [.. Owners.SelectMany(owner => ModifiedShapes.SelectMany(s => new[] { (owner, s.Name, "Main", s.Main), (owner, s.Name, "Sibling", s.Sibling) }))];

    private const MethodAttributes Instance = MethodAttributes.Public | MethodAttributes.HideBySig;

    private readonly EmittedAssembly emitted;
    #endregion

    #region Child types
    // A return type with its custom modifiers.
    private sealed record Return(Type Type, Type[]? Required = null, Type[]? Optional = null);

    // A raw return signature: an optional modifier (InAttribute as modreq, IsConst as modopt), by-ref or not, and
    // int64 - or else the owner's argument (int32 on Plain, !0 on Box).
    private sealed record RawReturn(string? Modifier, bool ByRef, bool Long);
    #endregion
}

/// <summary>
/// Review 1 C2's shape with an ERASED difference (never loaded into the default context): <c>ChaRetErased</c> has
/// <c>Erased.Base { virtual int Q() =&gt; "BASE-Q"; virtual int R() =&gt; "BASE-R" }</c>,
/// <c>Erased.Derived : Base { ref int Q() =&gt; "DERIVED-Q"; int modopt(IsConst) R() =&gt; "DERIVED-R" }</c> (both
/// non-virtual: their signatures differ from Base's by by-ref-ness and by a modopt only), and
/// <c>Erased.Sub : Derived { override int Q() =&gt; "SUB-Q"; override int R() =&gt; "SUB-R" }</c> (each body throws its
/// marker). <c>ChaRetErasedCaller</c>'s <c>CallsQ(Derived)</c> / <c>CallsR(Derived)</c> are <c>callvirt int Derived::Q()</c>
/// / <c>::R()</c>, emitted against a stub <c>ChaRetErased</c> whose Derived declares <c>virtual int Q()</c> and <c>R()</c>.
/// </summary>
public sealed class ErasedReturnFixture : IDisposable
{
    #region Constructors
    public ErasedReturnFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            var stub = emitted.Save(RealName, module => Define(module, stub: true), "stub");
            Real = emitted.Save(RealName, module => Define(module, stub: false), "real");
            using (var context = new IsolatedLoadContext())
            {
                var derived = context.LoadBytes(stub).GetType("Erased.Derived", throwOnError: true)!;
                Caller = emitted.Save("ChaRetErasedCaller", module => DefineCaller(module, derived), "caller");
            }
            Assemblies = ModelAssemblies.Load(Real, Caller);
            Index = Assemblies.Index();
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
    public string Real { get; }

    public string Caller { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    public ModelCallSite Site(string caller) =>
        Assert.Single(Sites, s => s.Caller.NodeId.StartsWith($"ErasedCaller.Callers.{caller}(", StringComparison.Ordinal));

    /// <summary>Runs <c>ErasedCaller.Callers.{caller}(new {receiver}())</c> with <c>ChaRetErased</c> pinned to the real assembly.</summary>
    public string? Run(string caller, string receiver)
    {
        using var context = new IsolatedLoadContext(new Dictionary<string, string> { [RealName] = Real });
        var method = context.LoadBytes(Caller).GetType("ErasedCaller.Callers", throwOnError: true)!.GetMethod(caller)!;
        var instance = Activator.CreateInstance(context.LoadFromAssemblyName(new AssemblyName(RealName)).GetType(receiver, throwOnError: true)!);
        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, [instance]));
        return Assert.IsType<InvalidOperationException>(thrown.InnerException).Message;
    }

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module, bool stub)
    {
        var @base = module.DefineType("Erased.Base", TypeAttributes.Public | TypeAttributes.Class);
        @base.DefineDefaultConstructor(MethodAttributes.Public);
        Throwing(@base.DefineMethod("Q", NewVirtual, typeof(int), Type.EmptyTypes), "BASE-Q");
        Throwing(@base.DefineMethod("R", NewVirtual, typeof(int), Type.EmptyTypes), "BASE-R");
        @base.CreateType();

        var derived = module.DefineType("Erased.Derived", TypeAttributes.Public | TypeAttributes.Class, @base);
        derived.DefineDefaultConstructor(MethodAttributes.Public);
        if (stub)
        {
            Throwing(derived.DefineMethod("Q", NewVirtual, typeof(int), Type.EmptyTypes), "STUB");
            Throwing(derived.DefineMethod("R", NewVirtual, typeof(int), Type.EmptyTypes), "STUB");
        }
        else
        {
            Throwing(derived.DefineMethod("Q", Plain, typeof(int).MakeByRefType(), Type.EmptyTypes), "DERIVED-Q");
            Throwing(derived.DefineMethod("R", Plain, CallingConventions.HasThis, typeof(int), null, [typeof(IsConst)], Type.EmptyTypes, null, null), "DERIVED-R");
        }
        derived.CreateType();

        if (!stub)
        {
            var sub = module.DefineType("Erased.Sub", TypeAttributes.Public | TypeAttributes.Class, derived);
            sub.DefineDefaultConstructor(MethodAttributes.Public);
            Throwing(sub.DefineMethod("Q", Override, typeof(int), Type.EmptyTypes), "SUB-Q");
            Throwing(sub.DefineMethod("R", Override, typeof(int), Type.EmptyTypes), "SUB-R");
            sub.CreateType();
        }
    }

    private static void DefineCaller(ModuleBuilder module, Type derived)
    {
        var callers = module.DefineType("ErasedCaller.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        foreach (var name in new[] { "Q", "R" })
        {
            var il = callers.DefineMethod($"Calls{name}", MethodAttributes.Public | MethodAttributes.Static, typeof(int), [derived]).GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Callvirt, derived.GetMethod(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)!);
            il.Emit(OpCodes.Ret);
        }
        callers.CreateType();
    }

    private static void Throwing(MethodBuilder method, string marker)
    {
        var il = method.GetILGenerator();
        il.Emit(OpCodes.Ldstr, marker);
        il.Emit(OpCodes.Newobj, typeof(InvalidOperationException).GetConstructor([typeof(string)])!);
        il.Emit(OpCodes.Throw);
    }
    #endregion

    #region Fields
    public const string RealName = "ChaRetErased";

    private const MethodAttributes Plain = MethodAttributes.Public | MethodAttributes.HideBySig;
    private const MethodAttributes NewVirtual = Plain | MethodAttributes.Virtual | MethodAttributes.NewSlot;
    private const MethodAttributes Override = Plain | MethodAttributes.Virtual;

    private readonly EmittedAssembly emitted;
    #endregion
}
