namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.PointerParameterFixture;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// ADR 0025: <see cref="ModelNames"/> and <see cref="CciNames"/> must name a pointer or by-ref parameter alike. CCIProvider
/// gives an <c>[Out]</c> parameter that is <em>not</em> by-ref (<c>[Out] byte** p</c>, the Microsoft.DiaSymReader
/// <c>MetadataAdapterBase</c> shape) <c>MethodParameterKind.Out</c>; ModelNames used to read the kind and render it
/// <c>System.Byte*&amp;</c>, where CCI renders <c>System.Byte**</c> — and a call-site reference, which never carries
/// <c>[Out]</c>, rendered <c>Byte**</c>, so the edge missed its own definition. The by-ref rows guard the other
/// direction: every C# by-ref flavour (including the newer <c>in</c> and <c>ref readonly</c>, which CCI predates) must
/// still render <c>&amp;</c> on both sides.
/// </summary>
public sealed class PointerParameterParityTests : IClassFixture<PointerParameterLayersFixture>
{
    #region Constructors
    public PointerParameterParityTests(PointerParameterLayersFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>Whole-assembly parity: identical key and node-id sets for definitions and call sites.</summary>
    [Fact]
    public void CciAndModelLayers_ProduceIdenticalKeySets_ForThePointerParameterFixture() =>
        CanonicalNameParity.AssertLayersAgree(fixture.Layers.CciLayer, fixture.Layers.ModelLayer);

    /// <summary>Guards the parity assertion against passing vacuously.</summary>
    [Fact]
    public void ParitySets_CoverEveryBodiedShape_AndBothLayersWalkedTheSamePopulation()
    {
        var cci = fixture.Layers.CciLayer;
        var model = fixture.Layers.ModelLayer;

        // 12 bodied shape methods + CallsEveryShape + the implicit .ctor; the extern P/Invoke has no body.
        Assert.Equal(14, cci.Definitions.Count);
        Assert.Equal(cci.Definitions.Count, model.Definitions.Count);
        Assert.Equal(cci.CallSites.Count, model.CallSites.Count);
        foreach (var layer in new[] { cci, model })
            Assert.All(layer.DefinitionNodeIds.Concat(layer.CallSiteNodeIds), id => Assert.DoesNotContain(CanonicalName.UnknownPart, id, StringComparison.Ordinal));
    }

    /// <summary>
    /// An <c>[Out]</c> (or <c>[In, Out]</c>) unmanaged pointer is not by-ref: both layers render <c>T*</c>, as a
    /// definition and as a call-site reference, and the <c>T*&amp;</c> the old ModelNames produced appears nowhere.
    /// </summary>
    [Theory]
    [InlineData("OutIntPointer", "System.Int32*")]
    [InlineData("OutBytePointerPointer", "System.Byte**")]
    [InlineData("InOutIntPointer", "System.Int32*")]
    [InlineData("VirtualOutBytePointerPointer", "System.Byte**")]
    public void OutAttributedPointerParameter_RendersAsAPointer_InBothLayers(string method, string parameter)
    {
        var nodeId = $"{Prefix}{method}({parameter})";
        var byRefRendering = $"{Prefix}{method}({parameter}&)";

        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(nodeId, layer.DefinitionNodeIds);
            Assert.Contains(nodeId, layer.CallSiteNodeIds);
            Assert.DoesNotContain(byRefRendering, layer.DefinitionNodeIds);
            Assert.DoesNotContain(byRefRendering, layer.CallSiteNodeIds);
        }
    }

    /// <summary>
    /// Regression guard: every by-ref flavour still renders <c>&amp;</c> on both sides — <c>in</c> (modreq
    /// <c>InAttribute</c> on the virtual one), <c>ref readonly</c> (C# 12, <c>RequiresLocation</c>), <c>out T*</c> and a
    /// by-ref inside a function pointer.
    /// </summary>
    [Theory]
    [InlineData("RefInt", "System.Int32&")]
    [InlineData("OutInt", "System.Int32&")]
    [InlineData("InInt", "System.Int32&")]
    [InlineData("RefReadonlyInt", "System.Int32&")]
    [InlineData("VirtualInInt", "System.Int32&")]
    [InlineData("VirtualRefReadonlyInt", "System.Int32&")]
    [InlineData("OutBytePointer", "System.Byte*&")]
    [InlineData("FunctionPointerWithRefInt", "fnptr:System.Void(System.Int32&)")]
    public void ByRefParameter_StillRendersAsByRef_InBothLayers(string method, string parameter)
    {
        var nodeId = $"{Prefix}{method}({parameter})";

        foreach (var layer in new[] { fixture.Layers.CciLayer, fixture.Layers.ModelLayer })
        {
            Assert.Contains(nodeId, layer.DefinitionNodeIds);
            Assert.Contains(nodeId, layer.CallSiteNodeIds);
        }
    }

    /// <summary>
    /// The premise, so the rows above exercise the defect rather than pass by accident: on the Model side the
    /// <c>[Out] byte**</c> definition really is kind <c>Out</c> on an unmanaged pointer, and on the CCI side it is
    /// <c>IsOut</c> without <c>IsByReference</c>.
    /// </summary>
    [Fact]
    public void Premise_OutAttributedBytePointerPointer_IsKindOut_ButNotByRef_InBothObjectModels()
    {
        var definition = fixture.ModelDefinition("OutBytePointerPointer");
        var modelParameter = Assert.Single(definition.Parameters);
        Assert.Equal(ModelTypes.MethodParameterKind.Out, modelParameter.Kind);
        var pointer = Assert.IsType<ModelTypes.PointerType>(modelParameter.Type);
        Assert.False(pointer.IsManaged);
        Assert.False(Assert.IsType<ModelTypes.PointerType>(pointer.TargetType).IsManaged);

        var cciParameter = Assert.Single(
            fixture.Layers.CciAssembly.Methods.Single(m => m.Name.Value == "OutBytePointerPointer").Parameters);
        Assert.True(cciParameter.IsOut);
        Assert.False(cciParameter.IsByReference);
    }

    /// <summary>The by-ref counterpart of the premise: an <c>out byte*</c> is a managed pointer to an unmanaged one.</summary>
    [Fact]
    public void Premise_OutBytePointer_IsAManagedPointerToAnUnmanagedPointer_InTheModel()
    {
        var parameter = Assert.Single(fixture.ModelDefinition("OutBytePointer").Parameters);
        var managed = Assert.IsType<ModelTypes.PointerType>(parameter.Type);

        Assert.True(managed.IsManaged);
        Assert.False(Assert.IsType<ModelTypes.PointerType>(managed.TargetType).IsManaged);
    }

    /// <summary>
    /// The graph half of the defect: a call site to the <c>[Out] byte**</c> method — static, virtual and the bodyless
    /// P/Invoke — must land on the definition's own node (an edge whose target is the definition's node id, the node
    /// own, no Unresolved opacity), not on a separate External node named by the reference.
    /// </summary>
    [Theory]
    [InlineData("OutBytePointerPointer", MethodNodeKind.OwnWithBody)]
    [InlineData("VirtualOutBytePointerPointer", MethodNodeKind.OwnWithBody)]
    [InlineData("NativeOutBytePointerPointer", MethodNodeKind.OwnBodyless)]
    public void CallSiteEdge_ToOutAttributedPointerMethod_JoinsTheDefinitionNode(string method, MethodNodeKind kind)
    {
        var definitionId = Assert.Single(fixture.Index.Methods, m => m.Definition.Name == method).NodeId;

        Assert.Equal($"{Prefix}{method}(System.Byte**)", definitionId);
        Assert.Equal(kind, fixture.Graph.Node(definitionId)?.Kind);
        Assert.Contains(fixture.Graph.Successors(Caller), e => e.To == definitionId);
        Assert.DoesNotContain(fixture.Graph.Nodes, n => n.NodeId.StartsWith($"{Prefix}{method}(", StringComparison.Ordinal) && n.NodeId != definitionId);
    }

    /// <summary>Every call in the caller resolves to an own definition: nothing in the fixture is left Unresolved.</summary>
    [Fact]
    public void Graph_ResolvesEveryOwnCallSite_WithNoUnresolvedOpacity()
    {
        Assert.DoesNotContain(fixture.Graph.Opacities, o => o.Kind is OpacityKind.Unresolved or OpacityKind.Ambiguous);
        Assert.All(
            fixture.Graph.Successors(Caller).Where(e => e.To.StartsWith(Prefix, StringComparison.Ordinal)),
            e => Assert.NotEqual(MethodNodeKind.External, fixture.Graph.Node(e.To)?.Kind));
    }
    #endregion

    #region Fields
    private const string Prefix = "Silvergun.CodeAnalysis.IL.Tests.PointerParameterFixture.PointerParameters.";
    private const string Caller = Prefix + "CallsEveryShape()";

    private readonly PointerParameterLayersFixture fixture;
    #endregion
}

/// <summary>
/// The pointer-parameter fixture assembly read both ways (<see cref="CanonicalNameLayersFixture"/>) and, separately,
/// loaded into a <see cref="MemberIndex"/> with its <see cref="MethodGraph"/> built. Metadata only; nothing runs.
/// </summary>
public sealed class PointerParameterLayersFixture : IDisposable
{
    #region Constructors
    public PointerParameterLayersFixture()
    {
        var path = typeof(PointerParameters).Assembly.Location;
        Layers = new CanonicalNameLayersFixture(path);
        try
        {
            Assemblies = ModelAssemblies.Load(path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            Layers.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public CanonicalNameLayersFixture Layers { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }
    #endregion

    #region Methods
    /// <summary>The Model definition of the one fixture method named <paramref name="name"/> (bodied or not).</summary>
    public ModelTypes.MethodDefinition ModelDefinition(string name) =>
        Assert.Single(Index.Methods, m => m.Definition.Name == name).Definition;

    public void Dispose()
    {
        Assemblies.Dispose();
        Layers.Dispose();
    }
    #endregion
}
