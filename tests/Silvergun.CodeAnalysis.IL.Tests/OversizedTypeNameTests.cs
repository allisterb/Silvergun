namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

using CCIProvider;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using Cci = Microsoft.Cci;
using ModelTypes = Model.Types;
using Token = OversizedTypeFixture.Token;

/// <summary>
/// <c>CCIProvider.TypeSize</c> on an emitted TypeSpec DAG (docs/agent/tasks/graph-names-hostile-types.md): the parts
/// T_k = <c>Pair&lt;T_k-1,T_k-1&gt;</c> expands to (2^(k+2)-1, as <c>SsaBounds.MaxTypeParts</c> counts) and its name chars
/// (names-chars-and-lift-cancellation.md), measured in time linear in the metadata; both bounds; and a structural hash
/// that is stable across loads and tells shapes apart.
/// </summary>
public sealed class OversizedTypeSizeTests : IClassFixture<OversizedTypeFixture>
{
    #region Constructors
    public OversizedTypeSizeTests(OversizedTypeFixture fixture)
    {
        this.fixture = fixture;
        tokens = OversizedTypeFixture.Tokens(fixture.Layers.CciAssembly);
    }
    #endregion

    #region Methods
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(20)]
    public void Parts_OfTk_Is2ToTheKPlus2Minus1(int k) =>
        Assert.Equal((1L << (k + 2)) - 1, TypeSize.Parts(tokens[OversizedTypeFixture.T(k)]));

    /// <summary>
    /// T_20 (4,194,303 parts as a tree) on a fresh load, measured first: well under a second, because the walk is memoised by
    /// CCI's shared objects. An unmemoised walk would visit 4M nodes.
    /// </summary>
    [Fact]
    public void Parts_OfT20_OnAFreshLoad_ReturnsPromptly()
    {
        using var load = Load();
        var t20 = OversizedTypeFixture.Tokens(load)[Token.T20];

        var clock = Stopwatch.StartNew();
        var parts = TypeSize.Parts(t20);
        clock.Stop();

        Assert.Equal((1L << 22) - 1, parts);
        Assert.True(clock.Elapsed < TimeSpan.FromMilliseconds(500), $"Parts(T_20) took {clock.ElapsedMilliseconds} ms.");
    }

    /// <summary>Hash(T_20) on a fresh load is prompt too, and not the unreadable fallback.</summary>
    [Fact]
    public void Hash_OfT20_OnAFreshLoad_ReturnsPromptly()
    {
        using var load = Load();
        var t20 = OversizedTypeFixture.Tokens(load)[Token.T20];

        var clock = Stopwatch.StartNew();
        var hash = TypeSize.Hash(t20);
        clock.Stop();

        AssertHash(hash);
        Assert.True(clock.Elapsed < TimeSpan.FromMilliseconds(500), $"Hash(T_20) took {clock.ElapsedMilliseconds} ms.");
    }

    /// <summary>
    /// The char bound cuts the DAG first: T_5 (2,665 chars) is within it, T_6 (5,353) past it. T_6..T_10 are within
    /// <c>MaxParts</c>, so they are oversized by chars alone; T_11 and T_20 are past both.
    /// </summary>
    [Theory]
    [InlineData(0, false, false)]
    [InlineData(5, false, false)]
    [InlineData(6, true, false)]
    [InlineData(9, true, false)]
    [InlineData(10, true, false)]
    [InlineData(11, true, true)]
    [InlineData(20, true, true)]
    public void IsOversized_OfTk_ByCharsFromT6_ByPartsFromT11(int k, bool oversized, bool pastParts)
    {
        var tk = tokens[OversizedTypeFixture.T(k)];

        Assert.Equal(oversized, TypeSize.Chars(tk) > TypeSize.MaxChars);
        Assert.Equal(pastParts, TypeSize.Parts(tk) > TypeSize.MaxParts);
        Assert.Equal(oversized, TypeSize.IsOversized(tk));
    }

    /// <summary>
    /// The parts bound exactly (<c>Box&lt;T_10&gt;</c>, 4,096 parts) and one past it (<c>Pair&lt;T_10,int&gt;</c>, 4,097) are
    /// both oversized now, by chars: being within <c>MaxParts</c> no longer means within the bound.
    /// </summary>
    [Fact]
    public void IsOversized_AtThePartsBound_IsTrue_ByChars()
    {
        Assert.Equal(4096L, TypeSize.MaxParts);
        Assert.Equal(4096L, TypeSize.Parts(tokens[Token.BoxT10]));
        Assert.True(TypeSize.Chars(tokens[Token.BoxT10]) > TypeSize.MaxChars);
        Assert.True(TypeSize.IsOversized(tokens[Token.BoxT10]));
        Assert.Equal(4097L, TypeSize.Parts(tokens[Token.PairT10Int]));
        Assert.True(TypeSize.IsOversized(tokens[Token.PairT10Int]));
    }

    /// <summary>
    /// The premise of "the char bound always trips first": every node's payload is at least 2 chars, so any type past
    /// <c>MaxParts</c> is past <c>MaxChars</c> too. Checked on every type of the fixture; a cut by parts alone is not
    /// reachable from it.
    /// </summary>
    [Fact]
    public void PastMaxParts_ImpliesPastMaxChars_OnEveryFixtureType()
    {
        var pastParts = Enum.GetValues<Token>().Where(t => TypeSize.Parts(tokens[t]) > TypeSize.MaxParts).ToArray();

        Assert.NotEmpty(pastParts);
        Assert.All(pastParts, t => Assert.True(TypeSize.Chars(tokens[t]) > TypeSize.MaxChars, $"{t}"));
    }

    /// <summary>
    /// The char bound is strict and independent of parts: <c>Box&lt;leaf&gt;</c> (2 parts) at exactly 4,096 chars is not
    /// oversized, at 4,097 it is.
    /// </summary>
    [Fact]
    public void IsOversized_AtTheCharsBound_IsFalse_AndOnePastIt_IsTrue()
    {
        Assert.Equal(4096L, TypeSize.MaxChars);
        Assert.Equal(2L, TypeSize.Parts(tokens[Token.BoxCharEdge]));
        Assert.Equal(4096L, TypeSize.Chars(tokens[Token.BoxCharEdge]));
        Assert.False(TypeSize.IsOversized(tokens[Token.BoxCharEdge]));
        Assert.Equal(2L, TypeSize.Parts(tokens[Token.BoxCharJustOver]));
        Assert.Equal(4097L, TypeSize.Chars(tokens[Token.BoxCharJustOver]));
        Assert.True(TypeSize.IsOversized(tokens[Token.BoxCharJustOver]));
    }

    // ---- Chars ----------------------------------------------------------------------------------------------------------

    /// <summary>T_k sums "instance" + "type:Big.Pair`2" per level over two T_k-1, with "type:System.Int32`0" leaves: 84·2^k - 23.</summary>
    [Theory]
    [InlineData(0, 61)]
    [InlineData(1, 145)]
    [InlineData(5, 2665)]
    [InlineData(6, 5353)]
    [InlineData(10, 85993)]
    [InlineData(20, 88080361)]
    public void Chars_OfTk_SumsEachNodesPayloadOverTheTree(int k, long expected)
    {
        Assert.Equal(expected, OversizedTypeFixture.TkChars(k));
        Assert.Equal(expected, TypeSize.Chars(tokens[OversizedTypeFixture.T(k)]));
    }

    /// <summary>The payload rule on single nodes: a namespace type is "type:" + namespace + "." + name + "`" + arity.</summary>
    [Fact]
    public void Chars_OfANamedType_IsItsPayloadLength()
    {
        var t0 = Assert.IsAssignableFrom<Cci.IGenericTypeInstanceReference>(tokens[Token.T0]);
        var box = Assert.IsAssignableFrom<Cci.IGenericTypeInstanceReference>(tokens[Token.BoxT10]);

        Assert.Equal("type:Big.Pair`2".Length, TypeSize.Chars(t0.GenericType));
        Assert.Equal("type:Big.Box`1".Length, TypeSize.Chars(box.GenericType));
        Assert.Equal("type:System.Int32`0".Length, TypeSize.Chars(t0.GenericArguments.First()));
        Assert.Equal("instance".Length + "type:Big.Pair`2".Length + 2 * "type:System.Int32`0".Length, TypeSize.Chars(t0));
    }

    /// <summary>
    /// <c>Box&lt;leaf&gt;</c> counts its leaf's name in full; and wrapping nodes add their own payload: an SZ array "array:v",
    /// a function pointer "fnptr:" plus "-" per by-value parameter, and its return type.
    /// </summary>
    [Fact]
    public void Chars_OfLongLeavesAndWrappers_AddEachPayload()
    {
        Assert.Equal(OversizedTypeFixture.BoxChars(OversizedTypeFixture.LongNameA), TypeSize.Chars(tokens[Token.BoxLongA]));
        Assert.Equal(5033L, TypeSize.Chars(tokens[Token.BoxLongB]));

        var t11 = OversizedTypeFixture.TkChars(OversizedTypeFixture.OversizedDepth);
        Assert.Equal("array:v".Length + t11, TypeSize.Chars(ParameterType("TakeArray")));
        Assert.Equal("fnptr:-".Length + "type:System.Void`0".Length + t11, TypeSize.Chars(ParameterType("TakeFnPtr")));
    }

    [Fact]
    public void Chars_IsTheSame_OnRepeatedCalls_AndAcrossTwoSeparateLoads()
    {
        using var load = Load();
        var again = OversizedTypeFixture.Tokens(load);

        foreach (var token in Enum.GetValues<Token>())
        {
            var first = TypeSize.Chars(tokens[token]);
            Assert.True(first > 0, $"{token}");
            Assert.Equal(first, TypeSize.Chars(tokens[token]));
            Assert.Equal(first, TypeSize.Chars(again[token]));
        }
    }

    /// <summary>Chars(T_20) (88M chars over 4M nodes as a tree) on a fresh load is prompt: memoised by CCI's shared objects.</summary>
    [Fact]
    public void Chars_OfT20_OnAFreshLoad_ReturnsPromptly()
    {
        using var load = Load();
        var t20 = OversizedTypeFixture.Tokens(load)[Token.T20];

        var clock = Stopwatch.StartNew();
        var chars = TypeSize.Chars(t20);
        clock.Stop();

        Assert.Equal(OversizedTypeFixture.TkChars(20), chars);
        Assert.True(clock.Elapsed < TimeSpan.FromMilliseconds(500), $"Chars(T_20) took {clock.ElapsedMilliseconds} ms.");
    }

    [Fact]
    public void Null_MeasuresZeroChars() => Assert.Equal(0L, TypeSize.Chars(null!));

    /// <summary>
    /// A DAG deep enough that its tree's chars (84·2^62) and parts (2^64) overflow a long: both saturate at
    /// <see cref="long.MaxValue"/> instead of wrapping negative, so it stays oversized. A 63-row chain, written apart from
    /// the shared fixture and read through raw CCI only.
    /// </summary>
    [Fact]
    public void Chars_AndParts_Saturate_OnADagPastLongRange()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("SaturatingTypes");
        var pair = raw.Type("Big", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);
        var spec = raw.TypeSpec(e =>
        {
            var arguments = e.GenericInstantiation(pair, 2, isValueType: false);
            arguments.AddArgument().Int32();
            arguments.AddArgument().Int32();
        });
        for (var k = 1; k <= 62; k++)
        {
            var previous = spec;
            spec = raw.TypeSpec(e =>
            {
                var arguments = e.GenericInstantiation(pair, 2, isValueType: false);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), previous);
                SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), previous);
            });
        }
        raw.Type("Big", "Holder", raw.Object, System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Class | System.Reflection.TypeAttributes.Abstract | System.Reflection.TypeAttributes.Sealed);
        raw.Static("Tokens", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            il.OpCode(System.Reflection.Metadata.ILOpCode.Ldtoken);
            il.Token(spec);
            il.OpCode(System.Reflection.Metadata.ILOpCode.Pop);
            il.OpCode(System.Reflection.Metadata.ILOpCode.Ret);
        });
        var path = raw.Save(temp.Path);
        using var load = AssemblyAnalyzer.Load(path) is { IsSuccess: true } loaded ? loaded.Value : throw new InvalidOperationException("Could not load the saturation fixture.");
        var method = Assert.Single(load.Methods, m => m.Name.Value == "Tokens");
        var t62 = (Cci.ITypeReference)Assert.Single(AssemblyAnalyzer.TryReadBody(method).Body!.Operations, o => o.OperationCode == Cci.OperationCode.Ldtoken).Value;

        Assert.Equal(long.MaxValue, TypeSize.Chars(t62));
        Assert.Equal(long.MaxValue, TypeSize.Parts(t62));
        Assert.True(TypeSize.IsOversized(t62));
    }

    [Fact]
    public void Hash_IsSixteenLowerCaseHexChars_AndStableWithinALoad()
    {
        var first = TypeSize.Hash(tokens[Token.T11]);

        AssertHash(first);
        Assert.Equal(first, TypeSize.Hash(tokens[Token.T11]));
    }

    /// <summary>A second, independent host (other CCI objects, empty memo entries) hashes and counts every level the same.</summary>
    [Fact]
    public void Hash_AndParts_AreTheSame_AcrossTwoSeparateLoads()
    {
        using var load = Load();
        var again = OversizedTypeFixture.Tokens(load);

        foreach (var token in Enum.GetValues<Token>())
        {
            Assert.NotSame(tokens[token], again[token]);
            Assert.Equal(TypeSize.Hash(tokens[token]), TypeSize.Hash(again[token]));
            Assert.Equal(TypeSize.Parts(tokens[token]), TypeSize.Parts(again[token]));
        }
    }

    /// <summary>The hash is structural: <c>Pair&lt;T_11,T_11&gt;</c> written as its own row hashes as T_12 does.</summary>
    [Fact]
    public void Hash_IsStructural_TheSameShapeInAnotherRow_HashesAlike() =>
        Assert.Equal(TypeSize.Hash(tokens[Token.T12]), TypeSize.Hash(tokens[Token.PairT11T11]));

    /// <summary>Structurally different oversized types hash apart, including two of the same size (a different leaf).</summary>
    [Fact]
    public void Hash_OfStructurallyDifferentOversizedTypes_Differs()
    {
        Assert.Equal(TypeSize.Parts(tokens[Token.T11]), TypeSize.Parts(tokens[Token.U11]));
        Assert.NotEqual(TypeSize.Hash(tokens[Token.T11]), TypeSize.Hash(tokens[Token.U11]));
        Assert.NotEqual(TypeSize.Hash(tokens[Token.PairT11T11]), TypeSize.Hash(tokens[Token.PairT11T10]));
        Assert.NotEqual(TypeSize.Hash(tokens[Token.T11]), TypeSize.Hash(tokens[Token.BoxT11]));
        var all = Enum.GetValues<Token>().Where(t => t != Token.PairT11T11).Select(t => TypeSize.Hash(tokens[t])).ToArray();
        Assert.Equal(all.Length, all.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Null_MeasuresZeroParts_NotOversized()
    {
        Assert.Equal(0L, TypeSize.Parts(null!));
        Assert.False(TypeSize.IsOversized(null!));
    }

    /// <summary>The documented contract: "a reference that cannot be read measures 0 parts and hashes to "?"".</summary>
    [Fact]
    public void Null_HashesToQuestionMark() => Assert.Equal("?", TypeSize.Hash(null!));

    /// <summary>
    /// A nesting cycle (A nested in B nested in A, and A nested in itself) terminates on both walks. Built from CCI's mutable
    /// <c>NestedTypeReference</c>s, not read from metadata: whether CCI's reader can hand such a chain over is not tested here
    /// (loading hostile NestedClass rows in-process risks a CCI FailFast, ADR 0021).
    /// </summary>
    [Fact]
    public void NestingCycle_Terminates_WithSmallPartsAndAHash()
    {
        var names = new Cci.NameTable();
        var a = new Cci.MutableCodeModel.NestedTypeReference { Name = names.GetNameFor("A") };
        var b = new Cci.MutableCodeModel.NestedTypeReference { Name = names.GetNameFor("B"), ContainingType = a };
        a.ContainingType = b;
        var self = new Cci.MutableCodeModel.NestedTypeReference { Name = names.GetNameFor("Self") };
        self.ContainingType = self;

        var clock = Stopwatch.StartNew();
        var parts = new[] { TypeSize.Parts(a), TypeSize.Parts(b), TypeSize.Parts(self) };
        var hashes = new[] { TypeSize.Hash(a), TypeSize.Hash(b), TypeSize.Hash(self) };
        clock.Stop();

        Assert.All(parts, p => Assert.InRange(p, 1L, 3L));
        Assert.All(hashes, AssertHash);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"{clock.ElapsedMilliseconds} ms.");
    }

    /// <summary>
    /// Chars closes the same cycles: each link counts its own payload ("nested:A`0", 10) and the child that closes the
    /// cycle counts <see cref="TypeSize.UnknownChars"/> (9), as the namers render it &lt;unknown&gt;. Measured from A first:
    /// A = 10 + B, where B (A in progress) = 10 + 9 = 19, so A = 29 and B is memoised at 19; Self = "nested:Self`0" (13) + 9 = 22.
    /// </summary>
    [Fact]
    public void NestingCycle_Terminates_WithSmallChars()
    {
        var names = new Cci.NameTable();
        var a = new Cci.MutableCodeModel.NestedTypeReference { Name = names.GetNameFor("A") };
        var b = new Cci.MutableCodeModel.NestedTypeReference { Name = names.GetNameFor("B"), ContainingType = a };
        a.ContainingType = b;
        var self = new Cci.MutableCodeModel.NestedTypeReference { Name = names.GetNameFor("Self") };
        self.ContainingType = self;

        var clock = Stopwatch.StartNew();
        var chars = new[] { TypeSize.Chars(a), TypeSize.Chars(b), TypeSize.Chars(self) };
        clock.Stop();

        Assert.Equal(29L, chars[0]);
        Assert.Equal(19L, chars[1]);
        Assert.Equal("nested:Self`0".Length + TypeSize.UnknownChars, chars[2]);
        Assert.False(TypeSize.IsOversized(a));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"{clock.ElapsedMilliseconds} ms.");
    }

    /// <summary>
    /// A null generic argument counts <see cref="TypeSize.UnknownChars"/> (9, "&lt;unknown&gt;".Length), hand-built since CCI's
    /// reader never yields one (it substitutes <c>Dummy.TypeReference</c>, see <see cref="OversizedSelfReferenceTests"/>):
    /// <c>Pair&lt;null,null&gt;</c> is "instance" (8) + "type:Big.Pair`2" (15) + 2 × 9 = 41. Chars(null) itself stays 0.
    /// </summary>
    [Fact]
    public void Chars_OfANullGenericArgument_IsUnknownChars()
    {
        var pair = ((Cci.IGenericTypeInstanceReference)tokens[Token.T0]).GenericType;
        var instance = new Cci.MutableCodeModel.GenericTypeInstanceReference { GenericType = pair, GenericArguments = [null!, null!] };

        Assert.Equal(9L, TypeSize.UnknownChars);
        Assert.Equal("<unknown>".Length, TypeSize.UnknownChars);
        Assert.Equal(8 + "type:Big.Pair`2".Length + 2 * TypeSize.UnknownChars, TypeSize.Chars(instance));
        Assert.Equal(0L, TypeSize.Chars(null!));
    }

    /// <summary>
    /// A node whose payload cannot be read (a nested reference with no name: reading <c>Name.Value</c> throws) counts
    /// <see cref="TypeSize.UnknownChars"/> for itself, and its null container 9 more: 18, not the 0 a whole-walk fallback gives.
    /// </summary>
    [Fact]
    public void Chars_OfAnUnreadableNode_IsUnknownChars()
    {
        var unnamed = new Cci.MutableCodeModel.NestedTypeReference { Name = null!, ContainingType = null! };

        Assert.Equal(2 * TypeSize.UnknownChars, TypeSize.Chars(unnamed));
    }

    internal static void AssertHash(string hash) => Assert.Matches(HexHash, hash);

    // The CCI type of the one parameter of a Big.Holder method.
    private Cci.ITypeReference ParameterType(string method) =>
        Assert.Single(Assert.Single(fixture.Layers.CciAssembly.Methods, m => m.Name.Value == method).Parameters).Type;

    private AssemblyAnalyzer Load() =>
        AssemblyAnalyzer.Load(fixture.Path) is { IsSuccess: true } loaded ? loaded.Value : throw new InvalidOperationException("Could not reload the fixture.");
    #endregion

    #region Fields
    private static readonly Regex HexHash = new("^[0-9a-f]{16}$");

    private readonly OversizedTypeFixture fixture;
    private readonly System.Collections.Generic.IReadOnlyDictionary<Token, Cci.ITypeReference> tokens;
    #endregion
}

/// <summary>
/// An oversized generic instance in a signature (graph-names-hostile-types.md, step 2): <see cref="ModelNames"/> and
/// <see cref="CciNames"/> render the same <see cref="CanonicalName.Oversized"/> marker from the one measure, so node ids
/// agree (ADR 0025) and stay short; the graph records an <see cref="OpacityKind.OversizedType"/> at each own node and call
/// site; overloads that differ only in the oversized type stay apart by its hash; and a type within the bound renders whole.
/// </summary>
public sealed class OversizedTypeNameTests : IClassFixture<OversizedTypeFixture>
{
    #region Constructors
    public OversizedTypeNameTests(OversizedTypeFixture fixture)
    {
        this.fixture = fixture;
        tokens = OversizedTypeFixture.Tokens(fixture.Layers.CciAssembly);
    }
    #endregion

    #region Methods
    [Fact]
    public void CciAndModelLayers_ProduceIdenticalKeySets_ForTheOversizedFixture() =>
        CanonicalNameParity.AssertLayersAgree(fixture.Layers.CciLayer, fixture.Layers.ModelLayer);

    /// <summary>Guards the parity assertion against passing vacuously: every shape is a definition and a call site on both sides.</summary>
    [Fact]
    public void ParitySets_CoverEveryShape_OnBothLayers()
    {
        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            // The sixteen targets, Tokens and Caller (Holder is abstract sealed: no .ctor; the leaf types have no methods).
            Assert.Equal(18, layer.Definitions.Count);
            Assert.Equal(OversizedTypeFixture.Calls.Length, layer.CallSites.Count);
            Assert.Equal(OversizedTypeFixture.Calls.Length, layer.CallSiteNodeIds.Count);
            Assert.All(layer.DefinitionNodeIds.Concat(layer.CallSiteNodeIds), id => Assert.DoesNotContain(CanonicalName.UnknownPart, id, StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// Each oversized position renders the marker with the measured parts and the hash of the same shape's own TypeSpec row,
    /// on both layers, as a definition and as a call site. The marker sits at the outermost instance past the bound
    /// (<c>Box&lt;T_11&gt;</c> is one marker of 8,192 parts, not <c>Box&lt;marker&gt;</c>).
    /// </summary>
    [Theory]
    [InlineData("TakeOversized")]
    [InlineData("TakeArray")]
    [InlineData("TakeByRef")]
    [InlineData("TakeBox")]
    [InlineData("TakeNestedOwn")]
    [InlineData("OverT")]
    [InlineData("OverU")]
    [InlineData("TakeJustOver")]
    [InlineData("TakeFnPtr")]
    [InlineData("TakeBoxEdge")]
    [InlineData("TakeCharJustOver")]
    [InlineData("OverLongA")]
    [InlineData("OverLongB")]
    public void OversizedParameter_RendersTheMarker_AlikeOnBothLayers(string method)
    {
        var expected = Expected(method);

        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(expected, layer.DefinitionNodeIds);
            Assert.Contains(expected, layer.CallSiteNodeIds);
        }
    }

    /// <summary>
    /// <c>Outer&lt;T_11&gt;.Inner</c>, a nested type with no parameters of its own whose containing instance is past the bound:
    /// as for any uninstantiated inner link (<c>GenericOuter&lt;int&gt;.Inner</c> renders <c>GenericOuter.Inner`1</c>, pinned
    /// as a known defect in <see cref="CanonicalNameParityTests"/>), no node id carries the container's arguments, so both
    /// layers render <c>Big.Outer.Inner`1</c>: short, alike, and with no marker. The Model still never built the container.
    /// </summary>
    [Fact]
    public void NestedTypeWithNoOwnParameters_InAnOversizedContainer_RendersAsTheUninstantiatedLink_AlikeOnBothLayers()
    {
        var expected = Prefix + "TakeNested(Big.Outer.Inner`1)";

        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(expected, layer.DefinitionNodeIds);
            Assert.Contains(expected, layer.CallSiteNodeIds);
        }
        Assert.True(TypeSize.IsOversized(tokens[Token.InnerT11]));
        var parameter = Assert.IsAssignableFrom<ModelTypes.IBasicType>(Assert.Single(ModelDefinition("TakeNested").Parameters).Type);
        var container = Assert.IsType<ModelTypes.BasicType>(parameter.ContainingType);
        Assert.Equal(8192L, container.Oversized?.Parts);
        Assert.Empty(container.GenericArguments);
    }

    /// <summary>Two overloads of <c>Over</c> that differ only in which 8,191-part type they take keep distinct node ids, by the hash.</summary>
    [Fact]
    public void Overloads_DifferingOnlyInTheOversizedType_HaveDistinctNodeIds()
    {
        var overloads = fixture.Graph.Nodes.Where(n => n.ClassificationKey == Prefix + "Over" && n.Kind != MethodNodeKind.External).ToArray();

        Assert.Equal(2, overloads.Length);
        Assert.Equal(new[] { Expected("OverT"), Expected("OverU") }.Order(StringComparer.Ordinal), overloads.Select(n => n.NodeId).Order(StringComparer.Ordinal));
        Assert.Contains("<oversized:8191 parts:", overloads[0].NodeId, StringComparison.Ordinal);
        Assert.Contains("<oversized:8191 parts:", overloads[1].NodeId, StringComparison.Ordinal);
    }

    /// <summary>
    /// Two overloads of <c>OverLong</c> whose <c>Box&lt;leaf&gt;</c> is cut by chars alone (2 parts, 5,033 chars each) keep
    /// distinct, short node ids, by the hash, though both markers read 2 parts.
    /// </summary>
    [Fact]
    public void Overloads_DifferingOnlyInATypeCutByCharsAlone_HaveDistinctNodeIds()
    {
        var overloads = fixture.Graph.Nodes.Where(n => n.ClassificationKey == Prefix + "OverLong" && n.Kind != MethodNodeKind.External).ToArray();

        Assert.Equal(2, overloads.Length);
        Assert.Equal(new[] { Expected("OverLongA"), Expected("OverLongB") }.Order(StringComparer.Ordinal), overloads.Select(n => n.NodeId).Order(StringComparer.Ordinal));
        Assert.All(overloads, n => Assert.Contains("<oversized:2 parts:", n.NodeId, StringComparison.Ordinal));
        Assert.All(overloads, n => Assert.True(n.NodeId.Length <= MaxNodeIdLength, n.NodeId));
    }

    /// <summary>
    /// No node id of the graph, nor any rendered name, is long, except the two methods whose type is within the bound (T_5
    /// and <c>Box&lt;leaf&gt;</c> at 4,096 chars); <c>Box&lt;T_10&gt;</c>, within <c>MaxParts</c>, is short now too.
    /// </summary>
    [Fact]
    public void NodeIds_StayShort_ExceptForTypesWithinTheBound()
    {
        bool Whole(string id) => id.StartsWith(Prefix + "TakeEdge(", StringComparison.Ordinal) || id.StartsWith(Prefix + "TakeCharEdge(", StringComparison.Ordinal);
        var ids = fixture.Graph.Nodes.Select(n => n.NodeId)
            .Concat(fixture.Layers.CciLayer.DefinitionNodeIds).Concat(fixture.Layers.CciLayer.CallSiteNodeIds)
            .Concat(fixture.Layers.ModelLayer.DefinitionNodeIds).Concat(fixture.Layers.ModelLayer.CallSiteNodeIds)
            .Where(id => !Whole(id))
            .ToArray();

        Assert.NotEmpty(ids);
        Assert.All(ids, id => Assert.True(id.Length <= MaxNodeIdLength, $"{id.Length} chars: {id[..Math.Min(id.Length, 200)]}"));
    }

    /// <summary>Each own node whose id carries the marker has an OversizedType opacity at offset 0, and no other own node does.</summary>
    [Fact]
    public void Graph_RecordsOversizedType_AtEachOwnNodeWithTheMarker()
    {
        var marked = fixture.Graph.Nodes.Where(n => n.Kind != MethodNodeKind.External && CanonicalName.HasOversized(n.NodeId)).Select(n => n.NodeId).ToArray();
        var atOwn = fixture.Graph.Opacities.Where(o => o.Kind == OpacityKind.OversizedType && o.Site != Caller).ToArray();

        // TakeOversized, TakeArray, TakeByRef, TakeBox, TakeNestedOwn, the two Overs, TakeJustOver, TakeFnPtr, TakeBoxEdge,
        // TakeCharJustOver and the two OverLongs (not TakeNested, TakeEdge or TakeCharEdge).
        Assert.Equal(13, marked.Length);
        Assert.Equal(marked.Order(StringComparer.Ordinal), atOwn.Select(o => o.Site).Order(StringComparer.Ordinal));
        Assert.All(atOwn, o => Assert.Equal(0u, o.Offset));
    }

    /// <summary>
    /// Caller's call to each target whose node id carries the marker has an OversizedType opacity at that call's offset,
    /// those cut by chars alone included; its calls to T_5, <c>Box&lt;leaf&gt;</c> at 4,096 chars and the markerless
    /// <c>TakeNested</c> have none.
    /// </summary>
    [Fact]
    public void Graph_RecordsOversizedType_AtEachCallSiteToAMarkedTarget()
    {
        var expected = OversizedTypeFixture.Calls.Where(c => c is not ("TakeEdge" or "TakeCharEdge" or "TakeNested")).Select(c => fixture.CallOffsets[c]).Order();
        var atCaller = fixture.Graph.Opacities.Where(o => o.Kind == OpacityKind.OversizedType && o.Site == Caller).Select(o => o.Offset).Order();

        Assert.Equal(expected, atCaller);
    }

    /// <summary>Every call edge out of Caller lands on its own definition's node at its offset: nothing is External, Unresolved or Ambiguous.</summary>
    [Fact]
    public void Graph_EveryCallEdge_JoinsItsDefinitionNode()
    {
        var edges = fixture.Graph.Successors(Caller);

        Assert.Equal(OversizedTypeFixture.Calls.Length, edges.Count);
        foreach (var call in OversizedTypeFixture.Calls)
        {
            var edge = Assert.Single(edges, e => e.Offset == fixture.CallOffsets[call]);
            Assert.Equal(MethodNodeKind.OwnWithBody, fixture.Graph.Node(edge.To)?.Kind);
            Assert.Contains(fixture.Index.Methods, m => m.NodeId == edge.To);
        }
        Assert.Equal(edges.Count, edges.Select(e => e.To).Distinct(StringComparer.Ordinal).Count());
        Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Kind is OpacityKind.Unresolved or OpacityKind.Ambiguous);
        Assert.DoesNotContain(fixture.Graph.Nodes, n => n.Kind == MethodNodeKind.External && n.NodeId.StartsWith(Prefix, StringComparison.Ordinal));
    }

    /// <summary>
    /// Not oversized stays unchanged (the S4.5 behaviour): T_5 (2,665 chars, the largest level within the bound) and
    /// <c>Box&lt;leaf&gt;</c> (4,096 chars, the bound itself) render whole on both layers, with no marker and no opacity at
    /// their nodes or call sites; the rendered parameter is no longer than the bound.
    /// </summary>
    [Theory]
    [InlineData("TakeEdge")]
    [InlineData("TakeCharEdge")]
    public void WithinTheBound_RendersWhole_WithNoMarkerAndNoOpacity(string method)
    {
        var expected = Expected(method);

        Assert.False(CanonicalName.HasOversized(expected));
        Assert.InRange(expected.Length - Id(method, string.Empty).Length, 1, (int)TypeSize.MaxChars);
        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(expected, layer.DefinitionNodeIds);
            Assert.Contains(expected, layer.CallSiteNodeIds);
        }
        Assert.Equal(MethodNodeKind.OwnWithBody, fixture.Graph.Node(expected)?.Kind);
        Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Site == expected);
        Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Site == Caller && o.Offset == fixture.CallOffsets[method]);
    }

    /// <summary>
    /// End to end on the built graph: the fixture's public methods are roots, and both forms of the opacity (each marked own
    /// node, and Caller's call sites) are unseen sinks, so the public API reads Unseen, ending in OversizedType, never clean.
    /// </summary>
    [Fact]
    public void Reachability_OverTheFixtureGraph_ReadsUnseen_EndingInOversizedType()
    {
        var report = Reachability.Analyze(fixture.Graph);

        var unseen = Assert.Single(report.Reaches, r => r.Class == RootClass.PublicApi && r.Capability is null);
        Assert.NotEmpty(unseen.Examples);
        Assert.All(unseen.Examples, p => Assert.Equal((OpacityKind?)OpacityKind.OversizedType, p.EndsInOpacity));
        Assert.Equal(RootClassVerdict.Unknown, Assert.Single(report.Classes, c => c.Class == RootClass.PublicApi).Verdict);
    }

    /// <summary>
    /// The Model side really skipped the tree (the premise of the bound): the definition's parameter is its definition's
    /// <c>BasicType</c> with <c>Oversized</c> set, <c>GenericType</c> kept and no arguments; T_10's parameter is built whole.
    /// </summary>
    [Fact]
    public void Premise_ModelParameter_PastTheBound_IsAnOversizedBasicTypeWithNoArguments()
    {
        var oversized = Assert.IsType<ModelTypes.BasicType>(Assert.Single(ModelDefinition("TakeOversized").Parameters).Type);
        Assert.NotNull(oversized.Oversized);
        Assert.Equal(8191L, oversized.Oversized.Parts);
        Assert.Equal(TypeSize.Hash(tokens[Token.T11]), oversized.Oversized.Hash);
        Assert.NotNull(oversized.GenericType);
        Assert.Empty(oversized.GenericArguments);
        Assert.Null(ModelNames.TypeArguments(oversized));

        var edge = Assert.IsType<ModelTypes.BasicType>(Assert.Single(ModelDefinition("TakeEdge").Parameters).Type);
        Assert.Null(edge.Oversized);
        Assert.Equal(2, edge.GenericArguments.Count);
    }

    /// <summary>
    /// The same on the Model side for a cut by chars alone: <c>Box&lt;leaf&gt;</c> at 4,097 chars is an oversized
    /// <c>BasicType</c> of 2 parts with no arguments; at 4,096 it is built whole, its one argument the long-named leaf.
    /// </summary>
    [Fact]
    public void Premise_ModelParameter_PastTheCharsBoundOnly_IsAnOversizedBasicTypeWithNoArguments()
    {
        var oversized = Assert.IsType<ModelTypes.BasicType>(Assert.Single(ModelDefinition("TakeCharJustOver").Parameters).Type);
        Assert.NotNull(oversized.Oversized);
        Assert.Equal(2L, oversized.Oversized.Parts);
        Assert.Equal(TypeSize.Hash(tokens[Token.BoxCharJustOver]), oversized.Oversized.Hash);
        Assert.Empty(oversized.GenericArguments);

        var edge = Assert.IsType<ModelTypes.BasicType>(Assert.Single(ModelDefinition("TakeCharEdge").Parameters).Type);
        Assert.Null(edge.Oversized);
        Assert.Equal(OversizedTypeFixture.CharEdgeName, Assert.IsAssignableFrom<ModelTypes.IBasicType>(Assert.Single(edge.GenericArguments)).Name);
    }

    // The node id each Caller target is expected to have.
    private string Expected(string method) => method switch
    {
        "TakeOversized" => Id(method, Marker(Token.T11)),
        "TakeArray" => Id(method, CanonicalName.ArrayOf(Marker(Token.T11))),
        "TakeByRef" => Id(method, CanonicalName.ByRefTo(Marker(Token.T11))),
        "TakeBox" => Id(method, Marker(Token.BoxT11)),
        "TakeNestedOwn" => Id(method, Marker(Token.Inner2T11)),
        "OverT" => Id("Over", Marker(Token.T11)),
        "OverU" => Id("Over", Marker(Token.U11)),
        "TakeJustOver" => Id(method, Marker(Token.PairT10Int)),
        "TakeFnPtr" => Id(method, CanonicalName.FunctionPointer("System.Void", [Marker(Token.T11)])),
        "TakeEdge" => Id(method, Name(OversizedTypeFixture.CharEdgeDepth)),
        "TakeBoxEdge" => Id(method, Marker(Token.BoxT10)),
        "TakeCharEdge" => Id(method, "Big.Box`1<Big." + OversizedTypeFixture.CharEdgeName + ">"),
        "TakeCharJustOver" => Id(method, Marker(Token.BoxCharJustOver)),
        "OverLongA" => Id("OverLong", Marker(Token.BoxLongA)),
        "OverLongB" => Id("OverLong", Marker(Token.BoxLongB)),
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, null),
    };

    private string Marker(Token token)
    {
        var parts = TypeSize.Parts(tokens[token]);
        Assert.True(TypeSize.IsOversized(tokens[token]), $"{token} is not past the bound ({parts} parts, {TypeSize.Chars(tokens[token])} chars).");
        var hash = TypeSize.Hash(tokens[token]);
        OversizedTypeSizeTests.AssertHash(hash);
        return CanonicalName.Oversized(parts, hash);
    }

    private static string Id(string method, string parameter) => $"{Prefix}{method}({parameter})";

    // T_k whole: Big.Pair`2<T_k-1,T_k-1>, T_0 over System.Int32.
    private static string Name(int k) =>
        k == 0 ? "Big.Pair`2<System.Int32,System.Int32>" : string.Concat("Big.Pair`2<", Name(k - 1), ",", Name(k - 1), ">");

    private ModelTypes.MethodDefinition ModelDefinition(string name) => Assert.Single(fixture.Index.Methods, m => m.Definition.Name == name).Definition;
    #endregion

    #region Fields
    private const string Prefix = "Big.Holder.";
    private const string Caller = Prefix + "Caller()";
    private const int MaxNodeIdLength = 300;

    private readonly OversizedTypeFixture fixture;
    private readonly System.Collections.Generic.IReadOnlyDictionary<Token, Cci.ITypeReference> tokens;
    #endregion
}
