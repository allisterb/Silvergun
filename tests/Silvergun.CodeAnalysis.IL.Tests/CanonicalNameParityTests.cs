namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using Cci = Microsoft.Cci;
using ModelTypes = Model.Types;

/// <summary>
/// The cross-layer contract: the fixture assembly is read through <b>both</b> object models (raw CCI via
/// <see cref="AssemblyAnalyzer"/> and Analysis.Net's <c>Model</c> via <see cref="AssemblyDisassembler"/>) and
/// every method definition and call-site reference is named with <see cref="CciNames"/> / <see cref="ModelNames"/>.
/// If the two layers ever render the same method differently, capability classification and call-graph nodes
/// silently diverge — so set equality of both keys is the highest-value assertion in this suite.
/// <para>
/// The per-shape tests below then pin the specific edge cases phase 1 measured as fragile (depth-3 nesting,
/// <c>Outer&lt;T&gt;.Inner&lt;U&gt;</c> versus the non-instantiated middle link of
/// <c>Outer&lt;T&gt;.Inner.Innermost&lt;V&gt;</c>, accessors, explicit interface implementations, compiler-generated
/// state machines and closures), asserting each from <em>both</em> layers.
/// </para>
/// </summary>
public sealed class CanonicalNameParityTests : IClassFixture<CanonicalNameLayersFixture>
{
    #region Constructors
    public CanonicalNameParityTests(CanonicalNameLayersFixture fixture) => this.fixture = fixture;
    #endregion

    #region Properties
    private IEnumerable<LayerNames> Layers => [fixture.CciLayer, fixture.ModelLayer];
    #endregion

    #region Methods
    /// <summary>
    /// The acceptance criterion: identical classification-key and node-id sets from both layers, for method
    /// definitions and for call sites. Any difference is reported as the symmetric difference, per side.
    /// </summary>
    [Fact]
    public void CciAndModelLayers_ProduceIdenticalKeySets_ForFixtureAssembly() =>
        CanonicalNameParity.AssertLayersAgree(fixture.CciLayer, fixture.ModelLayer);

    /// <summary>
    /// Guards the parity test against passing vacuously: both layers must have produced a substantial number
    /// of definitions and call sites, and the counts must match.
    /// </summary>
    [Fact]
    public void ParitySets_AreNonTrivial_AndCoverDefinitionsAndCallSites()
    {
        Assert.True(fixture.CciLayer.Definitions.Count > 50, $"Only {fixture.CciLayer.Definitions.Count} CCI definitions.");
        Assert.True(fixture.CciLayer.CallSites.Count > 50, $"Only {fixture.CciLayer.CallSites.Count} CCI call sites.");
        Assert.Equal(fixture.CciLayer.Definitions.Count, fixture.ModelLayer.Definitions.Count);
        Assert.Equal(fixture.CciLayer.CallSites.Count, fixture.ModelLayer.CallSites.Count);

        // Nothing degraded to the placeholder — in EITHER direction. A wholesale failure would otherwise
        // "agree" across layers and pass the set comparison above; call sites need this as much as definitions,
        // since they are where unresolvable and specialized references actually arrive.
        foreach (var layer in Layers)
        {
            Assert.All(layer.DefinitionNodeIds, id => Assert.DoesNotContain(CanonicalName.UnknownPart, id, StringComparison.Ordinal));
            Assert.All(layer.CallSiteNodeIds, id => Assert.DoesNotContain(CanonicalName.UnknownPart, id, StringComparison.Ordinal));
        }
    }

    /// <summary>Definition node ids both layers must produce verbatim — one per fixture edge shape.</summary>
    [Theory]
    // Plain nesting at depth 3: outer to inner, never reversed.
    [InlineData(Prefix + "NestedRoot.Level2.Level3.Deep()")]
    // Generic type with a generic method: arity on both, positional parameters.
    [InlineData(Prefix + "GenericBox`1.Convert`1(!0,!!0)")]
    [InlineData(Prefix + "GenericBox`1.Holds(!0)")]
    // Property and event accessors, verbatim from metadata.
    [InlineData(Prefix + "CanonicalShapes.get_Value()")]
    [InlineData(Prefix + "CanonicalShapes.set_Value(System.Int32)")]
    [InlineData(Prefix + "CanonicalShapes.add_Changed(System.EventHandler)")]
    [InlineData(Prefix + "CanonicalShapes.remove_Changed(System.EventHandler)")]
    // Explicit interface implementation: the namespace-qualified metadata name.
    [InlineData(Prefix + "CanonicalShapes.Silvergun.CodeAnalysis.IL.Tests.Fixture.ICanonicalMarker.Mark()")]
    // Static and instance constructors.
    [InlineData(Prefix + "CanonicalShapes..cctor()")]
    [InlineData(Prefix + "CanonicalShapes..ctor(System.Int32)")]
    // Overloads differing only by parameter type.
    [InlineData(Prefix + "CanonicalShapes.Describe(System.Int32)")]
    [InlineData(Prefix + "CanonicalShapes.Describe(System.String)")]
    [InlineData(Prefix + "CanonicalShapes.Describe(System.Int32[])")]
    // out/ref/in all render as the by-ref decoration.
    [InlineData(Prefix + "CanonicalShapes.ByRefParts(System.Int32,System.Int32&,System.Int32&,System.Int32&)")]
    // A rank-2 array parameter.
    [InlineData(Prefix + "CanonicalShapes.SumMatrix(System.Int32[,])")]
    // A deeply nested generic parameter, arguments rendered recursively.
    [InlineData(Prefix + "CanonicalShapes.CountNested(System.Collections.Generic.Dictionary`2<System.String," +
        "System.Collections.Generic.List`1<System.Collections.Generic.KeyValuePair`2<System.Int32,System.String>>>)")]
    // A signature mentioning the assembly's own generic type, instantiated.
    [InlineData(Prefix + "CanonicalShapes.TakesOwnGeneric(" + Prefix + "GenericBox`1<System.String>)")]
    // Nested generic instantiations in signature position — the argument-accumulation quirk, pinned verbatim.
    [InlineData(NestedGenericSignature)]
    public void DefinitionNodeId_IsProducedIdenticallyByBothLayers(string nodeId)
    {
        Assert.Contains(nodeId, fixture.CciLayer.DefinitionNodeIds);
        Assert.Contains(nodeId, fixture.ModelLayer.DefinitionNodeIds);
    }

    /// <summary>
    /// The reversal bug, measured on real metadata: <c>NestedRoot.Level2.Level3</c> must read outer to inner
    /// on both sides, and the reversed rendering must appear nowhere.
    /// </summary>
    [Fact]
    public void ClassificationKey_NestedTypeDepthThree_IsOuterToInner_InBothLayers()
    {
        const string outerToInner = Prefix + "NestedRoot.Level2.Level3.Deep";
        const string reversed = Prefix + "NestedRoot.Level3.Level2.Deep";

        Assert.Contains(outerToInner, fixture.CciLayer.DefinitionKeys);
        Assert.Contains(outerToInner, fixture.ModelLayer.DefinitionKeys);
        Assert.DoesNotContain(reversed, fixture.CciLayer.DefinitionKeys);
        Assert.DoesNotContain(reversed, fixture.ModelLayer.DefinitionKeys);
    }

    /// <summary>
    /// The pair the whole cross-layer reconciliation rests on: <c>GenericOuter&lt;T&gt;.Inner&lt;U&gt;</c>
    /// (both links generic) and <c>GenericOuter&lt;T&gt;.Inner.Innermost&lt;V&gt;</c> (a non-instantiated
    /// middle link). CCI numbers type parameters per type and reports arity per type; <c>Model</c> flattens
    /// both. Arity 2 and positional <c>!0</c>/<c>!1</c> must come out of <em>both</em> layers.
    /// </summary>
    [Fact]
    public void NestedGenericTypes_ArityAndPositionalParameters_AgreeAcrossLayers()
    {
        const string inner = Prefix + "GenericOuter.Inner`2.TakesBoth(!0,!1)";
        const string innermost = Prefix + "GenericOuter.Inner.Innermost`2.TakesOuterAndInnermost(!0,!1)";

        Assert.Contains(inner, fixture.CciLayer.DefinitionNodeIds);
        Assert.Contains(inner, fixture.ModelLayer.DefinitionNodeIds);
        Assert.Contains(innermost, fixture.CciLayer.DefinitionNodeIds);
        Assert.Contains(innermost, fixture.ModelLayer.DefinitionNodeIds);

        // The classification keys carry no arity at all, and stay outer to inner.
        Assert.Contains(Prefix + "GenericOuter.Inner.TakesBoth", fixture.CciLayer.DefinitionKeys);
        Assert.Contains(Prefix + "GenericOuter.Inner.TakesBoth", fixture.ModelLayer.DefinitionKeys);
        Assert.Contains(Prefix + "GenericOuter.Inner.Innermost.TakesOuterAndInnermost", fixture.CciLayer.DefinitionKeys);
        Assert.Contains(Prefix + "GenericOuter.Inner.Innermost.TakesOuterAndInnermost", fixture.ModelLayer.DefinitionKeys);
    }

    /// <summary>
    /// The counterpart of <see cref="NestedGenericTypes_ArityAndPositionalParameters_AgreeAcrossLayers"/> for a
    /// nested generic <em>instantiation in signature position</em> — where <see cref="CciNames"/> has to
    /// reproduce <c>CCIProvider.TypeExtractor.ExtractGenericType</c>'s argument accumulation by hand, including
    /// its quirk that <b>only an instantiated link contributes</b>. All three renderings below are what both
    /// layers produce today; if a future "fix" to that quirk makes one side saner than the other, this fails
    /// rather than silently splitting the graph in two.
    /// <list type="bullet">
    /// <item><description><c>GenericOuter&lt;int&gt;.Inner&lt;string&gt;</c> — both links instantiated, so both
    /// arguments are accumulated.</description></item>
    /// <item><description><c>GenericOuter&lt;int&gt;.Inner.Innermost&lt;bool&gt;</c> — the middle link is not
    /// instantiated, so the outer <c>int</c> is <em>dropped</em> even though the arity still counts it.</description></item>
    /// <item><description><c>GenericOuter&lt;int&gt;.Inner</c> — not instantiated itself, so no arguments render
    /// at all, while the arity still carries the outer link's parameter.</description></item>
    /// </list>
    /// </summary>
    [Fact]
    public void NestedGenericInstantiationInSignature_AccumulatesArgumentsIdenticallyInBothLayers()
    {
        foreach (var layer in Layers)
        {
            var signature = Assert.Single(
                layer.DefinitionNodeIds,
                id => id.StartsWith(Prefix + "CanonicalShapes.TakesNestedGenericInstantiations(", StringComparison.Ordinal));

            Assert.Contains(InnerInstantiated, signature, StringComparison.Ordinal);
            Assert.Contains(InnermostInstantiated, signature, StringComparison.Ordinal);
            Assert.Contains("," + InnerUninstantiated + ")", signature, StringComparison.Ordinal);
            Assert.Equal(NestedGenericSignature, signature);
        }
    }

    /// <summary>
    /// KNOWN DEFECT, pinned deliberately — <b><see cref="CciNames"/> renders <c>`N</c> with fewer than <em>N</em>
    /// generic arguments.</b> This is the same rendering the test above pins verbatim, but asserted as the
    /// self-inconsistency it is rather than as a string: the middle link of
    /// <c>GenericOuter&lt;int&gt;.Inner.Innermost&lt;bool&gt;</c> is not itself instantiated, so it contributes no
    /// argument, yet the arity still counts its container's parameter — arity <b>2</b>, arguments <b>1</b>. The
    /// non-instantiated <c>GenericOuter&lt;int&gt;.Inner</c> is the same defect at arity 1 / 0 arguments, and
    /// <c>Inner&lt;string&gt;</c> (both links instantiated) is the consistent control at 2 / 2.
    /// <para>
    /// Measured: <b>294 divergences in 415,057 paired entities (0.071 %)</b>, all from this one cause, and ILSpy
    /// — which flattens <c>TypeArguments</c> over the whole chain — is the correct side in all 294
    /// (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §1.4 category 1 and §1.10 item 2).
    /// <c>CciNames.GenericArguments</c> reproduces this on purpose, because
    /// <c>CCIProvider.TypeExtractor.ExtractGenericType</c> does it and <c>Model</c> cannot recover the dropped
    /// argument; that bug-compatibility is what keeps the two layers equal, so "fixing" one side alone would
    /// split the call graph. Do not change either renderer without deciding the cross-layer contract first
    /// (§1.9).
    /// </para>
    /// <para>
    /// ⚠️ <b>This is a <see cref="CanonicalName.NodeId(MethodIdentity)"/> concern only.</b>
    /// <see cref="CanonicalName.ClassificationKey(MethodIdentity)"/> — the seam the capability map and catalog
    /// key on — diverged <b>0 / 415,057</b>, because arity and arguments never render into it. The last block
    /// below asserts exactly that, so this pin can never be read as evidence that classification is affected.
    /// </para>
    /// </summary>
    [Fact]
    public void KnownDefect_NodeIdOfANonInstantiatedNestingLink_RendersHigherArityThanItHasGenericArguments()
    {
        // The three renderings really are what both layers produce — otherwise the arithmetic below would be
        // about constants rather than about behaviour.
        foreach (var layer in Layers)
        {
            var signature = Assert.Single(
                layer.DefinitionNodeIds,
                id => id.StartsWith(Prefix + "CanonicalShapes.TakesNestedGenericInstantiations(", StringComparison.Ordinal));

            Assert.Equal(NestedGenericSignature, signature);
        }

        // THE DEFECT: `2 carried by one argument. 1 < 2 is the whole finding.
        Assert.Equal(2, ArityOf(InnermostInstantiated));
        Assert.Equal(new[] { "System.Boolean" }, ArgumentsOf(InnermostInstantiated));
        Assert.True(
            ArgumentsOf(InnermostInstantiated).Count < ArityOf(InnermostInstantiated),
            $"'{InnermostInstantiated}' no longer under-reports its arguments. If CciNames was fixed, this test "
                + "must be rewritten to assert the correct rendering (…Innermost`2<System.Int32,System.Boolean>) "
                + "and the cross-layer contract re-decided — not deleted.");

        // The same defect one link out: arity 1, no arguments at all.
        Assert.Equal(1, ArityOf(InnerUninstantiated));
        Assert.Empty(ArgumentsOf(InnerUninstantiated));

        // The control, so the assertions above are not simply "the parser always reports fewer": an instantiation
        // whose every link is instantiated renders arity and arguments consistently.
        Assert.Equal(2, ArityOf(InnerInstantiated));
        Assert.Equal(new[] { "System.Int32", "System.String" }, ArgumentsOf(InnerInstantiated));

        // ...and the classification key of the very same method carries neither arity nor arguments, on either
        // layer — the measured 0/415,057 for ClassificationKey. The defect cannot reach the capability seam.
        foreach (var layer in Layers)
        {
            var key = Assert.Single(
                layer.DefinitionKeys,
                k => k == Prefix + "CanonicalShapes.TakesNestedGenericInstantiations");

            Assert.DoesNotContain("`", key, StringComparison.Ordinal);
            Assert.DoesNotContain("<", key, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Compiler-generated names (closures, the <c>&lt;&gt;c</c> singleton, async and iterator state machines,
    /// and the async <b>local function</b> shape <c>&lt;&lt;X&gt;g__Y|N&gt;d</c>) are carried verbatim by both
    /// layers. Matched by fragment because the compiler's ordinal suffixes are not part of the contract.
    /// </summary>
    [Theory]
    [InlineData(".<>c__DisplayClass")]
    [InlineData(".<MakeAdder>b__")]
    [InlineData(".<MakeDoubler>b__")]
    [InlineData(".<AddAsync>d__")]
    [InlineData(".<Counting>d__")]
    [InlineData(".<WithAsyncLocalFunction>d__")]
    [InlineData(".<<WithAsyncLocalFunction>g__DoubleAsync|")]
    // The iterator's explicit interface implementations keep their argument-bearing metadata names verbatim.
    [InlineData(".System.Collections.Generic.IEnumerable<System.Int32>.GetEnumerator()")]
    [InlineData(".System.Collections.Generic.IEnumerator<System.Int32>.get_Current()")]
    [InlineData(".System.IDisposable.Dispose()")]
    public void CompilerGeneratedName_IsCarriedVerbatimByBothLayers(string fragment)
    {
        Assert.Contains(fixture.CciLayer.DefinitionNodeIds, id => id.Contains(fragment, StringComparison.Ordinal));
        Assert.Contains(fixture.ModelLayer.DefinitionNodeIds, id => id.Contains(fragment, StringComparison.Ordinal));
    }

    /// <summary>
    /// Overloads differing only by a <em>generic argument</em> must stay distinct: retaining arguments in a
    /// node id's parameter types is the 2026-07-25 spec correction.
    /// </summary>
    [Fact]
    public void NodeId_ParameterGenericArgument_IsRetained_InBothLayers()
    {
        const string ints = Prefix + "CanonicalShapes.Accept(System.Nullable`1<System.Int32>)";
        const string bools = Prefix + "CanonicalShapes.Accept(System.Nullable`1<System.Boolean>)";

        Assert.Contains(ints, fixture.CciLayer.DefinitionNodeIds);
        Assert.Contains(bools, fixture.CciLayer.DefinitionNodeIds);
        Assert.Contains(ints, fixture.ModelLayer.DefinitionNodeIds);
        Assert.Contains(bools, fixture.ModelLayer.DefinitionNodeIds);
    }

    /// <summary>
    /// Overloads share one classification key (correct for the capability map) but never a node id.
    /// </summary>
    [Fact]
    public void Overloads_ShareOneClassificationKey_ButHaveDistinctNodeIds()
    {
        const string key = Prefix + "CanonicalShapes.Describe";

        foreach (var layer in Layers)
        {
            var overloads = layer.Definitions.Where(m => CanonicalName.ClassificationKey(m) == key).ToArray();

            Assert.Equal(3, overloads.Length);
            Assert.Equal(3, overloads.Select(CanonicalName.NodeId).Distinct(StringComparer.Ordinal).Count());
            Assert.Single(overloads.Select(CanonicalName.ClassificationKey).Distinct(StringComparer.Ordinal));
        }
    }

    /// <summary>
    /// A <em>declaring</em> type is normalized to its definition: <c>GenericBox&lt;string&gt;.Size()</c> and
    /// <c>GenericBox&lt;int&gt;.Size()</c> are two call sites with one node id, on both sides.
    /// </summary>
    [Fact]
    public void CallSite_DeclaringTypeGenericArguments_AreStripped_InBothLayers()
    {
        const string size = Prefix + "GenericBox`1.Size()";

        foreach (var layer in Layers)
        {
            Assert.Equal(2, layer.CallSiteNodeIdList.Count(id => id == size));
            Assert.DoesNotContain(layer.CallSiteNodeIds, id => id.StartsWith(Prefix + "GenericBox`1<", StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// A classification key never carries generic decoration of the declaring type — the capability catalog
    /// prefix-matches against it, so <c>`N</c> and <c>&lt;…&gt;</c> must not appear there.
    /// </summary>
    [Fact]
    public void ClassificationKeys_OfFixtureTypes_CarryNoGenericDecoration()
    {
        foreach (var layer in Layers)
        {
            var ownKeys = layer.DefinitionKeys.Where(k => k.StartsWith(Prefix, StringComparison.Ordinal)).ToArray();

            Assert.NotEmpty(ownKeys);
            Assert.All(ownKeys, key => Assert.DoesNotContain("`", key, StringComparison.Ordinal));
            Assert.Contains(Prefix + "GenericBox.Convert", ownKeys);
            Assert.Contains(Prefix + "GenericOuter.TakesOuter", ownKeys);
        }
    }

    /// <summary>
    /// Call sites into generic BCL machinery — the shapes the async/iterator lowering emits — are rendered
    /// identically, including by-ref state-machine arguments and method arity.
    /// </summary>
    [Theory]
    [InlineData("System.Threading.Interlocked.CompareExchange`1(System.EventHandler&,System.EventHandler,System.EventHandler)")]
    [InlineData("System.Nullable`1.get_HasValue()")]
    public void CallSiteNodeId_IsProducedIdenticallyByBothLayers(string nodeId)
    {
        Assert.Contains(nodeId, fixture.CciLayer.CallSiteNodeIds);
        Assert.Contains(nodeId, fixture.ModelLayer.CallSiteNodeIds);
    }

    /// <summary>
    /// A <b>non-named</b> CCI type reference — an array, a pointer, a function pointer — has no metadata name,
    /// no namespace and no nesting chain, so it has no type <em>identity</em>: <see cref="CciNames.Of(Cci.ITypeReference)"/>
    /// must degrade it to <see cref="TypeIdentity.Unknown"/> rather than invent a name for it. Reachable from
    /// any assembly with an array-typed parameter, and the branch it takes moved when the walk's post-loop
    /// check became <c>current is not null</c>: it now leaves through <see cref="CanonicalName.Truncated"/>
    /// with an empty chain, which is the same <em>value</em> — this pins that equality.
    /// <para>
    /// Only the identity degrades. Rendering the same reference in <em>signature</em> position is a different
    /// question with a real answer, and <see cref="CciNames.TypeName(Cci.ITypeReference)"/> still gives it.
    /// </para>
    /// </summary>
    [Fact]
    public void CciNames_NonNamedTypeReference_ReturnsUnknownIdentity()
    {
        var matrix = fixture.CciAssembly.Methods
            .Where(m => m.Name.Value == "SumMatrix")
            .SelectMany(m => m.Parameters)
            .Select(p => p.Type)
            .OfType<Cci.IArrayTypeReference>()
            .FirstOrDefault();

        Assert.NotNull(matrix);
        Assert.IsNotAssignableFrom<Cci.INamedTypeReference>(matrix);

        var identity = CciNames.Of(matrix);

        Assert.Equal(TypeIdentity.Unknown, identity);
        Assert.Equal(CanonicalName.UnknownPart, CanonicalName.ClassificationKey(identity));
        Assert.Equal(CanonicalName.UnknownPart, CanonicalName.NodeId(identity));
        Assert.Equal(CanonicalName.Truncated([]), identity);

        // ...while the signature rendering of the very same reference is unaffected.
        Assert.Equal("System.Int32[,]", CciNames.TypeName(matrix));
    }

    /// <summary>Both adapters degrade a null reference to the documented placeholder rather than throwing.</summary>
    [Fact]
    public void Adapters_OnNullInput_ReturnUnknown_AndDoNotThrow()
    {
        var exception = Record.Exception(() =>
        {
            Assert.Equal(MethodIdentity.Unknown, CciNames.Of((Cci.IMethodReference?)null));
            Assert.Equal(TypeIdentity.Unknown, CciNames.Of((Cci.ITypeReference?)null));
            Assert.Equal(CanonicalName.UnknownPart, CciNames.TypeName(null));

            Assert.Equal(MethodIdentity.Unknown, ModelNames.Of((ModelTypes.IMethodReference?)null));
            Assert.Equal(TypeIdentity.Unknown, ModelNames.Of((ModelTypes.IBasicType?)null));
            Assert.Equal(CanonicalName.UnknownPart, ModelNames.TypeName(null));
        });

        Assert.Null(exception);
    }

    // The CLR arity a rendering claims (`N before its argument list), or 0 when it claims none. Deliberately
    // parsed out of the rendered string rather than read from the identity: the defect above is that the two
    // disagree, so the assertion has to look at what a consumer of the node id actually sees.
    private static int ArityOf(string rendered)
    {
        var end = rendered.IndexOf('<') is var open && open >= 0 ? open : rendered.Length;
        var tick = rendered.LastIndexOf('`', end - 1);

        return tick < 0 ? 0 : int.Parse(rendered[(tick + 1)..end]);
    }

    // The generic arguments a rendering actually carries. Only flat argument lists occur in the three shapes this
    // is used on, so a plain split is exact; a nested instantiation would need a depth-aware scan.
    private static IReadOnlyList<string> ArgumentsOf(string rendered) =>
        rendered.IndexOf('<') is var open && open < 0
            ? []
            : rendered[(open + 1)..^1].Split(',');

    #endregion

    #region Fields
    private const string Prefix = "Silvergun.CodeAnalysis.IL.Tests.Fixture.";

    // The three parameter shapes of CanonicalShapes.TakesNestedGenericInstantiations, rendered.
    private const string InnerInstantiated = Prefix + "GenericOuter.Inner`2<System.Int32,System.String>";
    private const string InnermostInstantiated = Prefix + "GenericOuter.Inner.Innermost`2<System.Boolean>";
    private const string InnerUninstantiated = Prefix + "GenericOuter.Inner`1";

    private const string NestedGenericSignature =
        Prefix + "CanonicalShapes.TakesNestedGenericInstantiations(" +
        InnerInstantiated + "," + InnermostInstantiated + "," + InnerUninstantiated + ")";

    private readonly CanonicalNameLayersFixture fixture;
    #endregion
}
