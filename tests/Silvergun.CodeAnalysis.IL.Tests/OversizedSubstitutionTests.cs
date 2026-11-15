namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// Substitution composing two types each within <c>CCIProvider.TypeSize</c>'s bounds into one past them
/// (graph-names-hostile-types.md, review round 1, W2), under the char bound (names-chars-and-lift-cancellation.md). The
/// parameter <c>P</c> of <c>Big.Own&lt;X&gt;.M(P)</c> is T'_5 over <c>!0</c> (1,577 chars, 64 <c>!0</c> leaves), and
/// <c>Big.Own&lt;T_5&gt;</c> is 2,687 chars, so neither is oversized; but <c>P[!0 := T_5]</c> renders T_11's shape, 102,387
/// chars, past <c>ModelNames</c>' 65,536-char substitution budget. A call through <c>Own&lt;T_5&gt;</c> must resolve Unresolved
/// without that string being built; one through <c>Own&lt;int&gt;</c> (T_5's shape, 1,587 chars substituted) still joins its
/// definition. Also: a merged own node with the marker carries exactly one OversizedType opacity.
/// </summary>
public sealed class OversizedSubstitutionTests : IClassFixture<OversizedSubstitutionFixture>
{
    #region Constructors
    public OversizedSubstitutionTests(OversizedSubstitutionFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>The call through <c>Own&lt;T_5&gt;</c> is Unresolved at its offset, and draws no edge to <c>M</c>.</summary>
    [Fact]
    public void CallThroughAComposedOversizedInstantiation_ResolvesUnresolved_NeverMatched()
    {
        var offset = fixture.CallOffsets["OwnT5"];

        Assert.Contains(fixture.Graph.Opacities, o => o.Site == Caller && o.Offset == offset && o.Kind == OpacityKind.Unresolved);
        Assert.DoesNotContain(fixture.Graph.Successors(Caller), e => e.Offset == offset && e.To == MDefinition.NodeId);
    }

    /// <summary>The control: the call through <c>Own&lt;int&gt;</c> substitutes within the budget and joins <c>M</c>'s node.</summary>
    [Fact]
    public void CallThroughAnInstantiationWithinTheBudget_JoinsTheDefinition()
    {
        var offset = fixture.CallOffsets["OwnInt"];

        var edge = Assert.Single(fixture.Graph.Successors(Caller), e => e.Offset == offset);
        Assert.Equal(MDefinition.NodeId, edge.To);
        Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Site == Caller && o.Offset == offset && o.Kind is OpacityKind.Unresolved or OpacityKind.Ambiguous);
    }

    /// <summary>
    /// <see cref="ModelNames.ParameterTypes"/> with T_5's 1,587-char rendering as <c>!0</c>: <c>&lt;unknown&gt;</c>, promptly
    /// (the 102,387-char rendering is never built).
    /// </summary>
    [Fact]
    public void ParameterTypes_WithAComposedSubstitutionPastTheBudget_IsUnknown_Promptly()
    {
        var argument = OversizedTypeNameTestsSupport.Name(OversizedSubstitutionFixture.ArgumentDepth);
        Assert.Equal(1_587, argument.Length);

        var clock = Stopwatch.StartNew();
        var rendered = ModelNames.ParameterTypes(MDefinition.Definition, [argument]);
        clock.Stop();

        Assert.Equal([CanonicalName.UnknownPart], rendered);
        Assert.True(clock.Elapsed < TimeSpan.FromMilliseconds(500), $"{clock.ElapsedMilliseconds} ms.");
    }

    /// <summary>The same definition substituted with <c>System.Int32</c> renders whole: T_5's own name.</summary>
    [Fact]
    public void ParameterTypes_WithAShortSubstitution_RendersWhole() =>
        Assert.Equal([OversizedTypeNameTestsSupport.Name(OversizedSubstitutionFixture.ParameterDepth)], ModelNames.ParameterTypes(MDefinition.Definition, ["System.Int32"]));

    /// <summary>
    /// The premise, in numbers: the composition this fixture builds is reachable under the char bound. P (T'_5 over
    /// <c>!0</c>) and the argument T_5 are each within <c>MaxChars</c>, while their composition (T_11's shape) renders past
    /// the 65,536-char substitution budget; the whole-substituted control (T_5's shape) renders well under it.
    /// </summary>
    [Fact]
    public void Premise_TheComposedRendering_IsPastTheSubstitutionBudget_WhileEachPartIsWithinTheCharsBound()
    {
        const int budget = 65_536;
        var composedDepth = OversizedSubstitutionFixture.ParameterDepth + OversizedSubstitutionFixture.ArgumentDepth + 1;

        Assert.True(OversizedTypeFixture.TkChars(OversizedSubstitutionFixture.ArgumentDepth) <= CCIProvider.TypeSize.MaxChars);
        Assert.Equal(102_387, OversizedTypeNameTestsSupport.Name(composedDepth).Length);
        Assert.True(OversizedTypeNameTestsSupport.Name(composedDepth).Length > budget);
        Assert.True(OversizedTypeNameTestsSupport.Name(OversizedSubstitutionFixture.ParameterDepth).Length < budget);
    }

    /// <summary>The definition itself (no substitution) renders positionally, within the bound, with no marker.</summary>
    [Fact]
    public void Definition_RendersPositionally_WithNoMarker()
    {
        Assert.Equal("Big.Own`1.M(" + OversizedTypeNameTestsSupport.Name(OversizedSubstitutionFixture.ParameterDepth, "!0") + ")", MDefinition.NodeId);
        Assert.False(CanonicalName.HasOversized(MDefinition.NodeId));
    }

    /// <summary>
    /// Two definitions differing only by return type, both taking T_11 (the same TypeSpec), share one node, which carries
    /// exactly one OversizedType opacity (recorded when the node is created, not per merged method).
    /// </summary>
    [Fact]
    public void MergedOwnNode_WithTheMarker_HasExactlyOneOversizedTypeOpacity()
    {
        var merged = fixture.Index.Methods.Where(m => m.Definition.Name == "Merged").ToArray();
        Assert.Equal(2, merged.Length);
        var nodeId = Assert.Single(merged.Select(m => m.NodeId).Distinct(StringComparer.Ordinal));
        Assert.True(CanonicalName.HasOversized(nodeId), nodeId);
        Assert.NotNull(fixture.Graph.Node(nodeId));

        var opacity = Assert.Single(fixture.Graph.Opacities, o => o.Site == nodeId && o.Kind == OpacityKind.OversizedType);
        Assert.Equal(0u, opacity.Offset);
    }

    /// <summary>
    /// The premise, read from CCI's own call-site references: <c>Own&lt;T_5&gt;</c> is 2,687 chars (not oversized), and CCI's
    /// specialized parameter of the call through it is past the bound; through <c>Own&lt;int&gt;</c> it is T_5's shape,
    /// within it.
    /// </summary>
    [Fact]
    public void Premise_BothInstantiationsAreWithinTheBound_ButOnlyTheComposedParameterIsPastIt()
    {
        var caller = Assert.Single(fixture.Layers.CciAssembly.Methods, m => m.Name.Value == "Caller");
        var calls = AssemblyAnalyzer.TryReadBody(caller).Body!.Operations
            .Where(o => o.OperationCode == Microsoft.Cci.OperationCode.Call).Select(o => (Microsoft.Cci.IMethodReference)o.Value).ToArray();
        Assert.Equal(3, calls.Length);
        var (onT5, onInt) = (calls[0], calls[1]);

        Assert.Equal(8 + "type:Big.Own`1".Length + OversizedTypeFixture.TkChars(OversizedSubstitutionFixture.ArgumentDepth), CCIProvider.TypeSize.Chars(onT5.ContainingType));
        Assert.False(CCIProvider.TypeSize.IsOversized(onT5.ContainingType));
        Assert.True(CCIProvider.TypeSize.IsOversized(Assert.Single(onT5.Parameters).Type));
        Assert.Equal(OversizedTypeFixture.TkChars(OversizedSubstitutionFixture.ParameterDepth), CCIProvider.TypeSize.Chars(Assert.Single(onInt.Parameters).Type));
        Assert.False(CCIProvider.TypeSize.IsOversized(Assert.Single(onInt.Parameters).Type));
    }

    /// <summary>
    /// A composition the char bound newly separates from the substitution budget: <c>MWide</c>'s T'_6 over <c>!0</c> (3,177
    /// chars) through <c>Own&lt;int&gt;</c> is T_6's shape, 5,353 chars, past <c>MaxChars</c> as CCIProvider specializes the
    /// call's parameter, though substituting the definition renders only 3,187 chars, well within the 65,536-char budget.
    /// The call-site parameter is the marker on both layers, so it cannot match the definition substituted whole: the call
    /// does not join <c>MWide</c> but fails closed, to an External marker node with Unresolved and OversizedType at the
    /// site (never a silent edge, never clean). Under the parts bound alone (255 parts) it joined; this pins the trade-off
    /// of the ruling (names-chars-and-lift-cancellation.md), and should change only with it.
    /// </summary>
    [Fact]
    public void CallWhoseSpecializedParameterIsPastTheCharsBound_ButWithinTheBudget_FailsClosed()
    {
        var offset = fixture.CallOffsets["WideOwnInt"];
        var wide = Assert.Single(fixture.Index.Methods, m => m.Definition.Name == "MWide");
        var caller = Assert.Single(fixture.Layers.CciAssembly.Methods, m => m.Name.Value == "Caller");
        var specialized = AssemblyAnalyzer.TryReadBody(caller).Body!.Operations
            .Where(o => o.OperationCode == Microsoft.Cci.OperationCode.Call).Select(o => (Microsoft.Cci.IMethodReference)o.Value).Last();
        var parameter = Assert.Single(specialized.Parameters).Type;

        Assert.Equal(OversizedTypeFixture.TkChars(OversizedSubstitutionFixture.ParameterDepth + 1), CCIProvider.TypeSize.Chars(parameter));
        Assert.True(CCIProvider.TypeSize.Parts(parameter) <= CCIProvider.TypeSize.MaxParts);
        Assert.True(CCIProvider.TypeSize.IsOversized(parameter));
        Assert.Equal([OversizedTypeNameTestsSupport.Name(OversizedSubstitutionFixture.ParameterDepth + 1)], ModelNames.ParameterTypes(wide.Definition, ["System.Int32"]));

        var edge = Assert.Single(fixture.Graph.Successors(Caller), e => e.Offset == offset);
        Assert.NotEqual(wide.NodeId, edge.To);
        Assert.Equal("Big.Own`1.MWide(" + CanonicalName.Oversized(CCIProvider.TypeSize.Parts(parameter), CCIProvider.TypeSize.Hash(parameter)) + ")", edge.To);
        Assert.Equal(MethodNodeKind.External, fixture.Graph.Node(edge.To)?.Kind);
        var atSite = fixture.Graph.Opacities.Where(o => o.Site == Caller && o.Offset == offset).Select(o => o.Kind).ToArray();
        Assert.Contains(OpacityKind.Unresolved, atSite);
        Assert.Contains(OpacityKind.OversizedType, atSite);
    }

    /// <summary>Cross-layer parity (ADR 0025) on this assembly too, including the three calls through instantiations.</summary>
    [Fact]
    public void CciAndModelLayers_ProduceIdenticalKeySets_ForTheSubstitutionFixture() =>
        CanonicalNameParity.AssertLayersAgree(fixture.Layers.CciLayer, fixture.Layers.ModelLayer);

    private MemberIndex.IndexedMethod MDefinition => Assert.Single(fixture.Index.Methods, m => m.Definition.Name == "M");
    #endregion

    #region Fields
    private const string Caller = "Big.Holder.Caller()";

    private readonly OversizedSubstitutionFixture fixture;
    #endregion
}

/// <summary>Whole canonical names of the DAG levels, without a fixture.</summary>
internal static class OversizedTypeNameTestsSupport
{
    /// <summary>T_k whole: <c>Big.Pair`2&lt;T_k-1,T_k-1&gt;</c>, T_0 over <paramref name="leaf"/>.</summary>
    public static string Name(int k, string leaf = "System.Int32")
    {
        var name = $"Big.Pair`2<{leaf},{leaf}>";
        for (var i = 1; i <= k; i++)
            name = string.Concat("Big.Pair`2<", name, ",", name, ">");
        return name;
    }
}

/// <summary>
/// <c>OversizedSubstitution.dll</c> (<see cref="RawAssembly"/>): <c>Big.Pair`2</c>; <c>Big.Own`1&lt;X&gt;</c> with
/// <c>static void M(P)</c>, P = T'_5 over <c>!0</c>; <c>Big.Holder</c> with two <c>Merged(T_11)</c> differing only by return
/// type, <c>static void MWide(T'_6 over !0)</c>, and <c>Caller</c>, which calls <c>M</c> through MemberRefs on the TypeSpecs <c>Own&lt;T_5&gt;</c> and
/// <c>Own&lt;int&gt;</c> (the ordinary encoding of a call on a generic instance), and <c>MWide</c> through <c>Own&lt;int&gt;</c>. Metadata only; nothing runs.
/// </summary>
public sealed class OversizedSubstitutionFixture : IDisposable
{
    #region Constructors
    public OversizedSubstitutionFixture()
    {
        Path = Write(temp.Path, out var offsets);
        CallOffsets = offsets;
        try
        {
            Layers = new CanonicalNameLayersFixture(Path);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            Layers?.Dispose();
            temp.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public CanonicalNameLayersFixture Layers { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    /// <summary>The offset of <c>Caller</c>'s calls: <c>OwnT5</c>, <c>OwnInt</c> and <c>WideOwnInt</c>.</summary>
    public IReadOnlyDictionary<string, uint> CallOffsets { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Assemblies.Dispose();
        Layers.Dispose();
        temp.Dispose();
    }

    private static string Write(string directory, out IReadOnlyDictionary<string, uint> offsets)
    {
        var raw = new RawAssembly("OversizedSubstitution");
        var pair = raw.Type("Big", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);

        // T_0..T_11 over int32, and Q_0..Q_5 over !0 (M's P = Pair<Q_4,Q_4> is T'_5; MWide's Pair<Q_5,Q_5> is T'_6).
        var t = Chain(raw, pair, OversizedTypeFixture.OversizedDepth, e => e.Int32());
        var q = Chain(raw, pair, ParameterDepth, e => e.GenericTypeParameter(0));
        void PairOf(SignatureTypeEncoder e, TypeSpecificationHandle a)
        {
            var arguments = e.GenericInstantiation(pair, 2, isValueType: false);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), a);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), a);
        }
        void Ret(InstructionEncoder il) => il.OpCode(ILOpCode.Ret);

        var own = raw.Type("Big", "Own`1", raw.Object);
        raw.GenericParameter(own, "X", 0);
        BlobBuilder Over(int level) => RawAssembly.MethodSig(false, r => r.Void(), p => PairOf(p, q[level]));
        raw.Static("M", Over(ParameterDepth - 1), Ret);
        raw.Static("MWide", Over(ParameterDepth), Ret);

        var ownT5 = raw.TypeSpec(e => SsaTypeNameDagFixture.ClassOf(e.GenericInstantiation(own, 1, isValueType: false).AddArgument(), t[ArgumentDepth]));
        var ownInt = raw.TypeSpec(e => e.GenericInstantiation(own, 1, isValueType: false).AddArgument().Int32());
        var mOnT5 = raw.MemberRef(ownT5, "M", Over(ParameterDepth - 1));
        var mOnInt = raw.MemberRef(ownInt, "M", Over(ParameterDepth - 1));
        var mWideOnInt = raw.MemberRef(ownInt, "MWide", Over(ParameterDepth));

        raw.Type("Big", "Holder", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        raw.Static("Merged", RawAssembly.MethodSig(false, r => r.Void(), p => PairOf(p, t[OversizedTypeFixture.EdgeDepth])), Ret);
        raw.Static("Merged", RawAssembly.MethodSig(false, r => r.Type().Int32(), p => PairOf(p, t[OversizedTypeFixture.EdgeDepth])), il =>
        {
            il.OpCode(ILOpCode.Ldc_i4_0);
            il.OpCode(ILOpCode.Ret);
        });
        var at = new Dictionary<string, uint>();
        raw.Static("Caller", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var (name, target) in new[] { ("OwnT5", mOnT5), ("OwnInt", mOnInt), ("WideOwnInt", mWideOnInt) })
            {
                il.OpCode(ILOpCode.Ldnull);
                at[name] = (uint)il.Offset;
                il.Call(target);
            }
            il.OpCode(ILOpCode.Ret);
        });
        offsets = at;
        return raw.Save(directory);
    }

    private static List<TypeSpecificationHandle> Chain(RawAssembly raw, TypeDefinitionHandle pair, int depth, Action<SignatureTypeEncoder> leaf)
    {
        var specs = new List<TypeSpecificationHandle>
        {
            raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                leaf(arguments.AddArgument());
                leaf(arguments.AddArgument());
            }),
        };
        for (var k = 1; k <= depth; k++)
        {
            var previous = specs[^1];
            specs.Add(raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), previous);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), previous);
            }));
        }
        return specs;
    }
    #endregion

    #region Fields
    /// <summary>P is T'_5 over <c>!0</c>: the largest level within <c>TypeSize.MaxChars</c> over <c>int</c> too, so the control substitutes whole.</summary>
    public const int ParameterDepth = 5;

    /// <summary>Own's argument, T_5: within <c>MaxChars</c>, and long enough that P[!0 := T_5] passes the substitution budget.</summary>
    public const int ArgumentDepth = 5;

    private readonly SsaTempDirectory temp = new();
    #endregion
}
