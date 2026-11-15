namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using CCIProvider;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using Cci = Microsoft.Cci;
using ModelTypes = Model.Types;

/// <summary>
/// Review round 1, W1 (names-chars-and-lift-cancellation.md): a TypeSpec whose generic arguments all name the TypeSpec
/// itself. Measured, not as the review assumed: CCI does not hand such an argument back as null. Its generic-instance
/// reader turns the unfinished self-reference into <c>Dummy.TypeReference</c> (PEFileToObjectModel.GetModuleGenericTypeInstanceReference,
/// <c>GetTypeReference() ?? Dummy.TypeReference</c>), whose payload <c>"type:.`0"</c> measures 8 chars, while both namers render it
/// <c>&lt;unknown&gt;</c> (9). So <see cref="TypeSize.UnknownChars"/> is not what counts here, and the rendered name runs about
/// 25% past the measure (the separators and one char per argument), bounded, not amplified. <c>Few&lt;self × 3&gt;</c> and
/// <c>Edge&lt;self × 508&gt;</c> are within the bound; <c>Many&lt;self × 600&gt;</c> (601 parts) is past it by its dummies' chars
/// alone. The rule for a real null, a cycle and an unreadable node is pinned on hand-built references in
/// <see cref="OversizedTypeSizeTests"/>. One generic level; metadata only, nothing runs.
/// </summary>
public sealed class OversizedSelfReferenceTests : IClassFixture<OversizedSelfReferenceFixture>
{
    #region Constructors
    public OversizedSelfReferenceTests(OversizedSelfReferenceFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>The premise: CCI reads every self-referencing argument as the one shared <c>Dummy.TypeReference</c>, not null.</summary>
    [Theory]
    [InlineData(nameof(OversizedSelfReferenceFixture.Few), OversizedSelfReferenceFixture.FewArity)]
    [InlineData(nameof(OversizedSelfReferenceFixture.Edge), OversizedSelfReferenceFixture.EdgeArity)]
    [InlineData(nameof(OversizedSelfReferenceFixture.Many), OversizedSelfReferenceFixture.ManyArity)]
    public void Premise_CciReadsEachSelfReferencingArgumentAsTheDummyReference(string token, int arity)
    {
        var instance = Assert.IsAssignableFrom<Cci.IGenericTypeInstanceReference>(fixture.Token(token));
        var arguments = instance.GenericArguments.ToArray();

        Assert.Equal(arity, arguments.Length);
        Assert.All(arguments, a => Assert.Same(Cci.Dummy.TypeReference, a));
    }

    /// <summary>The dummy argument is one part of "type:.`0" (8 chars), and renders as &lt;unknown&gt; on the CCI side.</summary>
    [Fact]
    public void DummyArgument_MeasuresItsPayload_ButRendersUnknown()
    {
        Assert.Equal("type:.`0".Length, TypeSize.Chars(Cci.Dummy.TypeReference));
        Assert.Equal(1L, TypeSize.Parts(Cci.Dummy.TypeReference));
        Assert.Equal("Big.Few`3<<unknown>,<unknown>,<unknown>>", CciNames.TypeName(fixture.Few));
    }

    /// <summary>
    /// Chars = "instance" (8) + the definition's payload + 8 per dummy argument: Few is 8 + "type:Big.Few`3" (14) + 24 = 46;
    /// Edge 8 + "type:Big.Edge`508" (17) + 4,064 = 4,089; Many 8 + "type:Big.Many`600" (17) + 4,800 = 4,825.
    /// </summary>
    [Fact]
    public void Chars_CountsEightPerDummyArgument()
    {
        Assert.Equal(8 + "type:Big.Few`3".Length + 3 * 8L, TypeSize.Chars(fixture.Few));
        Assert.Equal(46L, TypeSize.Chars(fixture.Few));
        Assert.Equal(4089L, TypeSize.Chars(fixture.Edge));
        Assert.Equal(8 + "type:Big.Many`600".Length + 600 * 8L, TypeSize.Chars(fixture.Many));
        Assert.Equal(4825L, TypeSize.Chars(fixture.Many));
    }

    /// <summary>Few and Edge are within both bounds; Many is within MaxParts (601) and oversized by its dummies' chars alone.</summary>
    [Fact]
    public void IsOversized_OnlyManyAndOnlyByChars()
    {
        Assert.False(TypeSize.IsOversized(fixture.Few));
        Assert.False(TypeSize.IsOversized(fixture.Edge));
        Assert.Equal(1L + OversizedSelfReferenceFixture.ManyArity, TypeSize.Parts(fixture.Many));
        Assert.True(TypeSize.Parts(fixture.Many) <= TypeSize.MaxParts);
        Assert.True(TypeSize.IsOversized(fixture.Many));
    }

    /// <summary>
    /// The measure under-counts a dummy-argument instance by a bounded factor: Edge, within the bound at 4,089 chars,
    /// renders whole on both layers as 13 + 508 × 9 + 507 commas + 1 = 5,093 chars (about 1.25 × the measure).
    /// </summary>
    [Fact]
    public void Edge_WithinTheBound_RendersWhole_AboutAQuarterPastItsMeasure()
    {
        var name = "Big.Edge`508<" + string.Join(",", Enumerable.Repeat("<unknown>", OversizedSelfReferenceFixture.EdgeArity)) + ">";
        var expected = $"{Prefix}TakeEdge({name})";

        Assert.Equal(5093, name.Length);
        Assert.Equal(name, CciNames.TypeName(fixture.Edge));
        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(expected, layer.DefinitionNodeIds);
            Assert.Contains(expected, layer.CallSiteNodeIds);
        }
        Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Site == expected);
    }

    /// <summary>Both namers render <c>TakeMany</c> with the marker of the measured parts and hash, as a definition and a call site.</summary>
    [Fact]
    public void ManyParameter_RendersTheMarker_AlikeOnBothLayers()
    {
        var expected = $"{Prefix}TakeMany({CanonicalName.Oversized(TypeSize.Parts(fixture.Many), TypeSize.Hash(fixture.Many))})";

        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(expected, layer.DefinitionNodeIds);
            Assert.Contains(expected, layer.CallSiteNodeIds);
        }
        var model = Assert.IsType<ModelTypes.BasicType>(Assert.Single(fixture.Index.Methods, m => m.Definition.Name == "TakeMany").Definition.Parameters.Single().Type);
        Assert.Equal(TypeSize.Parts(fixture.Many), model.Oversized?.Parts);
        Assert.Empty(model.GenericArguments);
    }

    [Fact]
    public void CciAndModelLayers_ProduceIdenticalKeySets_ForTheSelfReferenceFixture() =>
        CanonicalNameParity.AssertLayersAgree(fixture.Layers.CciLayer, fixture.Layers.ModelLayer);

    /// <summary>TakeMany's own node and Caller's call to it carry OversizedType; TakeFew's and TakeEdge's do not.</summary>
    [Fact]
    public void Graph_RecordsOversizedType_ForManyOnly()
    {
        string NodeId(string name) => Assert.Single(fixture.Index.Methods, m => m.Definition.Name == name).NodeId;
        var many = NodeId("TakeMany");

        Assert.True(CanonicalName.HasOversized(many), many);
        Assert.True(many.Length <= 300, many);
        Assert.Contains(fixture.Graph.Opacities, o => o.Site == many && o.Kind == OpacityKind.OversizedType && o.Offset == 0);
        Assert.Contains(fixture.Graph.Opacities, o => o.Site == Caller && o.Offset == fixture.CallOffsets["TakeMany"] && o.Kind == OpacityKind.OversizedType);
        foreach (var name in new[] { "TakeFew", "TakeEdge" })
        {
            Assert.False(CanonicalName.HasOversized(NodeId(name)));
            Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Site == NodeId(name) && o.Kind == OpacityKind.OversizedType);
            Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Site == Caller && o.Offset == fixture.CallOffsets[name] && o.Kind == OpacityKind.OversizedType);
        }
    }
    #endregion

    #region Fields
    private const string Prefix = "Big.Holder.";
    private const string Caller = Prefix + "Caller()";

    private readonly OversizedSelfReferenceFixture fixture;
    #endregion
}

/// <summary>
/// <c>SelfReferences.dll</c> (<see cref="RawAssembly"/>): <c>Big.Few`3</c>, <c>Big.Edge`508</c> and <c>Big.Many`600</c>, a
/// TypeSpec of each whose every argument is <c>class</c> of that same TypeSpec, <c>Big.Holder.TakeFew/TakeEdge/TakeMany</c>
/// taking them, <c>Tokens</c> (<c>ldtoken</c> Few, Edge, Many) and <c>Caller</c>, calling each once.
/// </summary>
public sealed class OversizedSelfReferenceFixture : IDisposable
{
    #region Constructors
    public OversizedSelfReferenceFixture()
    {
        Path = Write(temp.Path, out var offsets);
        CallOffsets = offsets;
        try
        {
            Layers = new CanonicalNameLayersFixture(Path);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            var method = Assert.Single(Layers.CciAssembly.Methods, m => m.Name.Value == "Tokens");
            var types = AssemblyAnalyzer.TryReadBody(method).Body!.Operations
                .Where(o => o.OperationCode == Cci.OperationCode.Ldtoken).Select(o => (Cci.ITypeReference)o.Value).ToArray();
            (Few, Edge, Many) = (types[0], types[1], types[2]);
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

    public IReadOnlyDictionary<string, uint> CallOffsets { get; }

    /// <summary><c>Few&lt;self,self,self&gt;</c>'s TypeSpec row, read by CCI.</summary>
    public Cci.ITypeReference Few { get; }

    /// <summary><c>Edge&lt;self × 508&gt;</c>'s TypeSpec row, read by CCI.</summary>
    public Cci.ITypeReference Edge { get; }

    /// <summary><c>Many&lt;self × 600&gt;</c>'s TypeSpec row, read by CCI.</summary>
    public Cci.ITypeReference Many { get; }
    #endregion

    #region Methods
    public Cci.ITypeReference Token(string name) => name switch { nameof(Few) => Few, nameof(Edge) => Edge, _ => Many };

    public void Dispose()
    {
        Assemblies.Dispose();
        Layers.Dispose();
        temp.Dispose();
    }

    private static string Write(string directory, out IReadOnlyDictionary<string, uint> offsets)
    {
        var raw = new RawAssembly("SelfReferences");
        TypeDefinitionHandle Generic(string name, int arity)
        {
            var type = raw.Type("Big", $"{name}`{arity}", raw.Object);
            for (var i = 0; i < arity; i++)
                raw.GenericParameter(type, $"T{i}", i);
            return type;
        }
        // A TypeSpec whose every argument is class <itself>: its own row number is the next one.
        TypeSpecificationHandle SelfSpec(TypeDefinitionHandle generic, int arity)
        {
            var self = MetadataTokens.TypeSpecificationHandle(raw.Metadata.GetRowCount(TableIndex.TypeSpec) + 1);
            var spec = raw.TypeSpec(e =>
            {
                var arguments = e.GenericInstantiation(generic, arity, isValueType: false);
                for (var i = 0; i < arity; i++)
                    SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), self);
            });
            Assert.Equal(self, spec);
            return spec;
        }

        var few = SelfSpec(Generic("Few", FewArity), FewArity);
        var edge = SelfSpec(Generic("Edge", EdgeArity), EdgeArity);
        var many = SelfSpec(Generic("Many", ManyArity), ManyArity);

        raw.Type("Big", "Holder", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        void Ret(InstructionEncoder il) => il.OpCode(ILOpCode.Ret);
        var targets = new (string Name, MethodDefinitionHandle Handle)[]
        {
            ("TakeFew", raw.Static("TakeFew", RawAssembly.MethodSig(false, r => r.Void(), p => SsaTypeNameDagFixture.ClassOf(p, few)), Ret)),
            ("TakeEdge", raw.Static("TakeEdge", RawAssembly.MethodSig(false, r => r.Void(), p => SsaTypeNameDagFixture.ClassOf(p, edge)), Ret)),
            ("TakeMany", raw.Static("TakeMany", RawAssembly.MethodSig(false, r => r.Void(), p => SsaTypeNameDagFixture.ClassOf(p, many)), Ret)),
        };
        raw.Static("Tokens", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var spec in new[] { few, edge, many })
            {
                il.OpCode(ILOpCode.Ldtoken);
                il.Token(spec);
                il.OpCode(ILOpCode.Pop);
            }
            Ret(il);
        });
        var at = new Dictionary<string, uint>();
        raw.Static("Caller", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var (name, handle) in targets)
            {
                il.OpCode(ILOpCode.Ldnull);
                at[name] = (uint)il.Offset;
                il.Call(handle);
            }
            Ret(il);
        });
        offsets = at;
        return raw.Save(directory);
    }
    #endregion

    #region Fields
    public const int FewArity = 3;

    /// <summary>The most dummy arguments within MaxChars: 25 + 8 × 508 = 4,089.</summary>
    public const int EdgeArity = 508;

    public const int ManyArity = 600;

    private readonly SsaTempDirectory temp = new();
    #endregion
}
