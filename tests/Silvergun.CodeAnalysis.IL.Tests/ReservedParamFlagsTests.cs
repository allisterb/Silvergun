namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using Cci = Microsoft.Cci;
using ModelTypes = Model.Types;

/// <summary>
/// A2 S1 review 3, <b>C1</b> (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md, "S1 review 3 … (S1e)"): CCI's
/// <c>ParamFlags.ByReference</c> (0x0100) and <c>ParamArray</c> (0x0200) are its OWN flags, set from the signature and
/// from <c>ParamArrayAttribute</c>; in a metadata Param row those two bits are reserved (ECMA-335 II.23.1.13) and the CLR
/// ignores them. CCI used to OR the raw row flags in unmasked, so <c>int M()</c> whose Param row for sequence 0 carried
/// 0x0100 indexed with a return of <c>System.Int32&amp;</c> — and every MemberRef call to it (which reads the signature
/// only) resolved Unresolved: an attacker could cut own edges one bit per method. A parameter's row did the same to the
/// node id (A1): <c>int K(int)</c> with 0x0100 on sequence 1 indexed as <c>K(System.Int32&amp;)</c>. The fix, in the fork:
/// <c>PEFileToObjectModel.ParamInfo</c> masks both bits off the raw row.
/// <para>
/// The CLR is the oracle (every body throws a marker naming itself): each MemberRef call runs the definition it names,
/// flags or not. The genuine by-ref controls (<c>ref int</c> return, <c>ref int</c> parameter, each also with the reserved
/// bit set) pin that the mask did not erase REAL by-ref-ness; see also <see cref="ReturnTypeShapeMatrixTests"/> (the
/// <c>RefVal</c>/<c>RefGet</c> pairs: a <c>ref int</c> return is told apart from <c>int</c>) and
/// <see cref="CanonicalNameParityTests"/> (<c>ByRefParts</c>: compiled <c>ref</c>/<c>out</c>/<c>in</c> parameters render
/// <c>System.Int32&amp;</c>).
/// </para>
/// <para>
/// <b>What the 0x0200 rows can show through Model, and what they cannot</b> (A2 S1 review 4, "S1f"): CCIProvider never
/// reads CCI's <c>IsParameterArray</c>, and Model has no notion of <c>params</c>, so through the index the ParamArray rows
/// (<c>PlainA</c>, <c>PlainR</c>, and the 0x0200 half of <c>PlainB</c>) show only that the bit does not perturb node ids,
/// return types, parameter kinds or resolution — they would pass with the 0x0200 half of the mask removed. The mask
/// itself is pinned on CCI directly by
/// <see cref="Cci_IsParameterArray_IsFalseForTheReservedBit_AndTrueForAGenuineParamsArray"/>, against a genuine
/// <c>params int[]</c> (<c>ParamArrayAttribute</c>) as the control. On a return row 0x0200 has no CCI reader at all.
/// </para>
/// </summary>
public sealed class ReservedParamFlagsTests : IClassFixture<ReservedParamFlagsFixture>
{
    #region Constructors
    public ReservedParamFlagsTests(ReservedParamFlagsFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    public static TheoryData<string> Callers() => [.. ReservedParamFlagsFixture.Cases.Select(c => c.Caller)];

    public static TheoryData<string> FlaggedCallers() => [.. ReservedParamFlagsFixture.Cases.Where(c => c.Rows.Length > 0).Select(c => c.Caller)];

    /// <summary>
    /// The premise: <see cref="PersistedAssemblyBuilder"/> wrote every reserved bit asked for into the Param rows (read
    /// back with System.Reflection.Metadata), so the other tests are not vacuous.
    /// </summary>
    [Theory]
    [MemberData(nameof(FlaggedCallers))]
    public void Premise_TheParamRowsCarryTheReservedBits(string caller)
    {
        var @case = ReservedParamFlagsFixture.Case(caller);
        var rows = fixture.ParamRows(@case.Owner, @case.Method);

        foreach (var (sequence, flags) in @case.Rows)
        {
            Assert.True(rows.TryGetValue(sequence, out var written), $"{@case.Owner}.{@case.Method}: no Param row for sequence {sequence}");
            Assert.Equal(flags, (int)written & 0x0300);
        }
    }

    /// <summary>The oracle: the CLR ignores the reserved bits, so each MemberRef call runs exactly the definition it names.</summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public void Runtime_EachMemberRefCall_RunsTheDefinitionItNames(string caller) =>
        Assert.Equal(ReservedParamFlagsFixture.Case(caller).Marker, fixture.Run(caller));

    /// <summary>
    /// THE CHECK: each call resolves to its definition — Exact on the plain class, Substituted through
    /// <c>Box&lt;int&gt;</c> — never Unresolved because a reserved bit made the definition by-ref; the node id is the
    /// signature's, with <c>&amp;</c> only where the signature itself is by-ref.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public void Resolve_ACallToADefinitionWithReservedParamBits_IsThatDefinition(string caller)
    {
        var @case = ReservedParamFlagsFixture.Case(caller);
        var site = fixture.Site(caller);
        var definition = fixture.Definition(@case.Owner, @case.Method);

        var resolution = fixture.Index.Resolve(site.Target);

        Assert.True(resolution.Kind == @case.Kind && ReferenceEquals(resolution.Definition, definition.Definition),
            $"{caller}: resolved {resolution.Kind} to {resolution.NodeId} ({resolution.Reason}); expected {@case.Kind} to {definition.NodeId}. " +
            $"ReturnType: reference '{ModelNames.ReturnType(site.Target, [])}', definition '{ModelNames.ReturnType(definition.Definition, @case.TypeArguments)}'.");
        Assert.Equal(@case.NodeId, resolution.NodeId);
        Assert.Null(resolution.Reason);
    }

    /// <summary>
    /// The node ids: every definition's is its signature's — no <c>&amp;</c> from a reserved bit on a parameter's row
    /// (A1's half of C1), and <c>&amp;</c> kept on the genuine <c>ref int</c> parameters.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public void NodeId_OfEachDefinition_IsItsSignatures(string caller)
    {
        var @case = ReservedParamFlagsFixture.Case(caller);

        var definition = fixture.Definition(@case.Owner, @case.Method);

        Assert.Equal(@case.NodeId, definition.NodeId);
        Assert.Equal(@case.NodeId.Contains('&', StringComparison.Ordinal), @case.Method.StartsWith("RefK", StringComparison.Ordinal));
    }

    /// <summary>
    /// The rendered return type, on the definition and on the reference alike: <c>System.Int32</c> where the signature
    /// returns <c>int</c> (a reserved bit on the return's row does not make it by-ref), <c>System.Int32&amp;</c> where it
    /// returns <c>ref int</c> (with or without the bit) — and Model's <c>ReturnValueIsByRef</c> agrees.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public void ReturnType_OfDefinitionAndReference_IsTheSignatures(string caller)
    {
        var @case = ReservedParamFlagsFixture.Case(caller);
        var site = fixture.Site(caller);
        var definition = fixture.Definition(@case.Owner, @case.Method).Definition;

        Assert.Equal(@case.ReturnType, ModelNames.ReturnType(definition, @case.TypeArguments));
        Assert.Equal(@case.ReturnType, ModelNames.ReturnType(site.Target, []));
        Assert.Equal(@case.ReturnType.EndsWith('&'), definition.ReturnValueIsByRef);
    }

    /// <summary>
    /// A parameter's kind follows its signature: <c>In</c> for an <c>int</c> or <c>int[]</c> parameter whose row carries
    /// a reserved bit, <c>Ref</c> for a genuine <c>ref int</c> — on the definition and on the reference.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public void ParameterKind_OfDefinitionAndReference_IsTheSignatures(string caller)
    {
        var @case = ReservedParamFlagsFixture.Case(caller);
        var site = fixture.Site(caller);
        var definition = fixture.Definition(@case.Owner, @case.Method).Definition;
        var expected = @case.Method.StartsWith("RefK", StringComparison.Ordinal) ? ModelTypes.MethodParameterKind.Ref : ModelTypes.MethodParameterKind.In;

        Assert.All(definition.Parameters, p => Assert.Equal(expected, p.Kind));
        Assert.All(site.Target.Parameters, p => Assert.Equal(expected, p.Kind));
        Assert.Equal(definition.Parameters.Count, site.Target.Parameters.Count);
    }

    /// <summary>
    /// The edge an attacker could have cut: the graph has each caller's static <c>call</c> edge to the definition's own
    /// node, and no unresolved resolution among the fixture's calls.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public void Graph_HasTheOwnEdgeOfEachCall(string caller)
    {
        var @case = ReservedParamFlagsFixture.Case(caller);
        var site = fixture.Site(caller);

        var edge = Assert.Single(fixture.Graph.Edges, e => e.From == site.Caller.NodeId);

        Assert.Equal(MethodEdgeKind.Call, edge.Kind);
        Assert.Equal(@case.NodeId, edge.To);
    }

    /// <summary>
    /// The mask, on CCI's own parameter flags (the library loaded by a fresh <see cref="AssemblyAnalyzer"/> host):
    /// <c>IsParameterArray</c> is false where a Param row carries the reserved 0x0200 bit alone — <c>A(int[])</c>, a
    /// vector in last position, the one shape where CCI also looks for the attribute; and <c>B(int)</c>, 0x0300 — and true
    /// for the control <c>P(params int[])</c>, whose row has no reserved bit and whose <c>ParamArrayAttribute</c> is what
    /// sets it. Likewise <c>IsByReference</c> and <c>ReturnValueIsByRef</c> follow the signature: false under 0x0100 alone,
    /// true for the genuine <c>ref int</c>, flagged or not.
    /// </summary>
    [Fact]
    public void Cci_IsParameterArray_IsFalseForTheReservedBit_AndTrueForAGenuineParamsArray()
    {
        var loaded = AssemblyAnalyzer.Load(fixture.Library);
        Assert.True(loaded.IsSuccess, loaded.Message);
        using var cci = loaded.Value;
        var plain = cci.Module.GetAllTypes().OfType<Cci.INamedTypeDefinition>().Single(t => t.Name.Value == "Plain");
        Cci.IMethodDefinition Method(string name) => plain.Methods.Single(m => m.Name.Value == name);
        Cci.IParameterDefinition Parameter(string name) => Assert.Single(Method(name).Parameters);

        Assert.Equal(0, (int)fixture.ParamRows("Plain", ReservedParamFlagsFixture.GenuineParams)[1] & 0x0300);
        Assert.True(Parameter(ReservedParamFlagsFixture.GenuineParams).IsParameterArray);
        Assert.False(Parameter("A").IsParameterArray);
        Assert.False(Parameter("B").IsParameterArray);

        Assert.False(Parameter("K").IsByReference);
        Assert.False(Parameter("B").IsByReference);
        Assert.True(Parameter("RefK").IsByReference);
        Assert.True(Parameter("RefKFlagged").IsByReference);
        Assert.False(Method("M").ReturnValueIsByRef);
        Assert.False(Method("B").ReturnValueIsByRef);
        Assert.True(Method("RefM").ReturnValueIsByRef);
        Assert.True(Method("RefMFlagged").ReturnValueIsByRef);
    }
    #endregion

    #region Fields
    private readonly ReservedParamFlagsFixture fixture;
    #endregion
}

/// <summary>
/// The emitted assemblies of <see cref="ReservedParamFlagsTests"/> (never loaded into the default context):
/// <list type="bullet">
/// <item><description><c>ChaParamFlags</c>: <c>PF.Plain</c> and <c>PF.Box`1</c>, whose methods (<see cref="Cases"/>) carry
/// the reserved Param-row bits 0x0100 / 0x0200 asked of <c>DefineParameter</c> — or none, the controls. Every body throws
/// <c>InvalidOperationException</c> with the case's marker.</description></item>
/// <item><description><c>ChaParamFlagsCaller</c>: <c>PFCaller.Callers.{caller}(owner)</c> = <c>ldarg.0; (arguments); call
/// target; pop; ret</c>, emitted against the loaded library (on <c>Box&lt;int&gt;</c> for Box), so each call is a MemberRef
/// written from the definition's own signature, without the row flags.</description></item>
/// </list>
/// </summary>
public sealed class ReservedParamFlagsFixture : IDisposable
{
    #region Constructors
    public ReservedParamFlagsFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Library = emitted.Save(LibraryName, DefineLibrary, "library");
            using (var context = new IsolatedLoadContext())
            {
                var library = context.LoadBytes(Library);
                Caller = emitted.Save("ChaParamFlagsCaller", module => DefineCaller(module, library), "caller");
            }
            Assemblies = ModelAssemblies.Load(Library, Caller);
            Index = Assemblies.Index();
            Sites = ModelCallSite.All(Index);
            Graph = MethodGraph.Build(Index);
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

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }

    public MethodGraph Graph { get; }
    #endregion

    #region Methods
    public static FlagCase Case(string caller) => Cases.Single(c => c.Caller == caller);

    /// <summary>The single call site of <c>PFCaller.Callers.{caller}</c>.</summary>
    public ModelCallSite Site(string caller) =>
        Assert.Single(Sites, s => s.Caller.NodeId.StartsWith($"PFCaller.Callers.{caller}(", StringComparison.Ordinal));

    /// <summary>The single indexed definition of <paramref name="method"/> in <c>PF.{owner}</c>.</summary>
    public MemberIndex.IndexedMethod Definition(string owner, string method) =>
        Assert.Single(Index.Methods, m => m.DeclaringTypeId == (owner == "Plain" ? "PF.Plain" : "PF.Box`1") && m.Definition.Name == method);

    /// <summary>The Param rows of <c>PF.{owner}::{method}</c> as written: sequence number to raw attributes.</summary>
    public IReadOnlyDictionary<int, ParameterAttributes> ParamRows(string owner, string method)
    {
        using var pe = new PEReader(File.OpenRead(Library));
        var metadata = pe.GetMetadataReader();
        var typeName = owner == "Plain" ? "Plain" : "Box`1";
        var type = metadata.TypeDefinitions.Select(metadata.GetTypeDefinition).Single(t => metadata.GetString(t.Name) == typeName);
        var definition = type.GetMethods().Select(metadata.GetMethodDefinition).Single(m => metadata.GetString(m.Name) == method);
        return definition.GetParameters().Select(metadata.GetParameter).ToDictionary(p => p.SequenceNumber, p => p.Attributes);
    }

    /// <summary>Runs <paramref name="caller"/> with the library pinned and returns the marker its target threw.</summary>
    public string? Run(string caller)
    {
        using var context = new IsolatedLoadContext(new Dictionary<string, string> { [LibraryName] = Library });
        var method = context.LoadBytes(Caller).GetType("PFCaller.Callers", throwOnError: true)!.GetMethod(caller)!;
        var thrown = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, [null]));
        return Assert.IsType<InvalidOperationException>(thrown.InnerException).Message;
    }

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void DefineLibrary(ModuleBuilder module)
    {
        var plain = module.DefineType("PF.Plain", TypeAttributes.Public | TypeAttributes.Class);
        var box = module.DefineType("PF.Box`1", TypeAttributes.Public | TypeAttributes.Class);
        var t = box.DefineGenericParameters("T")[0];

        foreach (var @case in Cases)
        {
            var (owner, parameter) = @case.Owner == "Plain" ? (plain, @case.Parameter) : (box, @case.Parameter == typeof(int) ? t : @case.Parameter);
            var method = owner.DefineMethod(@case.Method, MethodAttributes.Public | MethodAttributes.HideBySig, @case.Returns,
                parameter is null ? Type.EmptyTypes : [parameter]);
            foreach (var (sequence, flags) in @case.Rows)
                method.DefineParameter(sequence, (ParameterAttributes)flags, sequence == 0 ? null : "a");
            var il = method.GetILGenerator();
            il.Emit(OpCodes.Ldstr, @case.Marker);
            il.Emit(OpCodes.Newobj, typeof(InvalidOperationException).GetConstructor([typeof(string)])!);
            il.Emit(OpCodes.Throw);
        }

        // The control for the ParamArray mask: a genuine int P(params int[] a), no reserved bit, never called.
        var genuine = plain.DefineMethod(GenuineParams, MethodAttributes.Public | MethodAttributes.HideBySig, typeof(int), [typeof(int[])]);
        genuine.DefineParameter(1, ParameterAttributes.None, "a")
            .SetCustomAttribute(new CustomAttributeBuilder(typeof(ParamArrayAttribute).GetConstructor(Type.EmptyTypes)!, []));
        var body = genuine.GetILGenerator();
        body.Emit(OpCodes.Ldstr, $"Plain-{GenuineParams}");
        body.Emit(OpCodes.Newobj, typeof(InvalidOperationException).GetConstructor([typeof(string)])!);
        body.Emit(OpCodes.Throw);

        plain.CreateType();
        box.CreateType();
    }

    private static void DefineCaller(ModuleBuilder module, Assembly library)
    {
        var callers = module.DefineType("PFCaller.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var owners = new Dictionary<string, Type>
        {
            ["Plain"] = library.GetType("PF.Plain", throwOnError: true)!,
            ["Box"] = library.GetType("PF.Box`1", throwOnError: true)!.MakeGenericType(typeof(int)),
        };

        foreach (var @case in Cases)
        {
            var type = owners[@case.Owner];
            var target = type.GetMethod(@case.Method, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)!;
            var il = callers.DefineMethod(@case.Caller, MethodAttributes.Public | MethodAttributes.Static, typeof(void), [type]).GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            if (@case.Parameter == typeof(int))
                il.Emit(OpCodes.Ldc_I4_1);
            else if (@case.Parameter == typeof(int[]))
                il.Emit(OpCodes.Ldnull);
            else if (@case.Parameter == typeof(int).MakeByRefType())
            {
                il.DeclareLocal(typeof(int));
                il.Emit(OpCodes.Ldloca_S, (byte)0);
            }
            il.Emit(OpCodes.Call, target);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        }

        callers.CreateType();
    }
    #endregion

    #region Fields
    public const string LibraryName = "ChaParamFlags";

    /// <summary>The name of <c>PF.Plain</c>'s genuine <c>params int[]</c> method, the ParamArray control (not a case).</summary>
    public const string GenuineParams = "P";

    private const int ByReference = 0x0100;
    private const int ParamArray = 0x0200;

    /// <summary>
    /// Every method, its Param rows (sequence, reserved bits) and what the signature alone says: the definition's node id,
    /// its rendered return type, and how a MemberRef to it resolves. On Box, an <c>int</c> parameter is <c>T</c>.
    /// </summary>
    public static readonly FlagCase[] Cases =
    [
        // int M() with ByReference on the return's row: the reviewer's case P.
        new("PlainM", "Plain", "M", typeof(int), null, [(0, ByReference)], "PF.Plain.M()", "System.Int32", ResolutionKind.Exact),
        // int K(int) with ByReference on the parameter's row: A1's half of C1.
        new("PlainK", "Plain", "K", typeof(int), typeof(int), [(1, ByReference)], "PF.Plain.K(System.Int32)", "System.Int32", ResolutionKind.Exact),
        // int A(int[]) - not params - with ParamArray on the parameter's row. Through Model this shows only that the bit
        // does not perturb ids or resolution (CCIProvider never reads IsParameterArray); the mask: Cci_IsParameterArray_….
        new("PlainA", "Plain", "A", typeof(int), typeof(int[]), [(1, ParamArray)], "PF.Plain.A(System.Int32[])", "System.Int32", ResolutionKind.Exact),
        // int R() with ParamArray on the return's row: no CCI reader at all, so a does-not-perturb case only.
        new("PlainR", "Plain", "R", typeof(int), null, [(0, ParamArray)], "PF.Plain.R()", "System.Int32", ResolutionKind.Exact),
        // int B(int) with both bits on both rows (through Model, its 0x0200 half is a does-not-perturb case, as PlainA).
        new("PlainB", "Plain", "B", typeof(int), typeof(int), [(0, ByReference | ParamArray), (1, ByReference | ParamArray)], "PF.Plain.B(System.Int32)", "System.Int32", ResolutionKind.Exact),
        // The control: int N(), no Param row.
        new("PlainN", "Plain", "N", typeof(int), null, [], "PF.Plain.N()", "System.Int32", ResolutionKind.Exact),
        // Genuine by-ref: ref int RefM(), int RefK(ref int) - and each again with the reserved bit set as well.
        new("PlainRefM", "Plain", "RefM", typeof(int).MakeByRefType(), null, [], "PF.Plain.RefM()", "System.Int32&", ResolutionKind.Exact),
        new("PlainRefMFlagged", "Plain", "RefMFlagged", typeof(int).MakeByRefType(), null, [(0, ByReference)], "PF.Plain.RefMFlagged()", "System.Int32&", ResolutionKind.Exact),
        new("PlainRefK", "Plain", "RefK", typeof(int), typeof(int).MakeByRefType(), [], "PF.Plain.RefK(System.Int32&)", "System.Int32", ResolutionKind.Exact),
        new("PlainRefKFlagged", "Plain", "RefKFlagged", typeof(int), typeof(int).MakeByRefType(), [(1, ByReference)], "PF.Plain.RefKFlagged(System.Int32&)", "System.Int32", ResolutionKind.Exact),
        // Through a MemberRef on the generic instance Box<int>: int M() and int K(T), each with ByReference on its row.
        new("BoxM", "Box", "M", typeof(int), null, [(0, ByReference)], "PF.Box`1.M()", "System.Int32", ResolutionKind.Substituted),
        new("BoxK", "Box", "K", typeof(int), typeof(int), [(1, ByReference)], "PF.Box`1.K(!0)", "System.Int32", ResolutionKind.Substituted),
        new("BoxN", "Box", "N", typeof(int), null, [], "PF.Box`1.N()", "System.Int32", ResolutionKind.Substituted),
    ];

    private readonly EmittedAssembly emitted;
    #endregion

    #region Child types
    /// <summary>
    /// One method of the library and its caller. <see cref="Parameter"/> is the single parameter's type (none when null;
    /// on Box an <c>int</c> is <c>T</c>), <see cref="Rows"/> the Param rows written with their reserved bits.
    /// </summary>
    public sealed record FlagCase(
        string Caller, string Owner, string Method, Type Returns, Type? Parameter, (int Sequence, int Flags)[] Rows,
        string NodeId, string ReturnType, ResolutionKind Kind)
    {
        public string Marker => $"{Owner}-{Method}";

        public IReadOnlyList<string> TypeArguments => Owner == "Plain" ? [] : ["System.Int32"];
    }
    #endregion
}
