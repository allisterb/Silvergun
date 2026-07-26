namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The cross-layer canonical-name contract (<see cref="CanonicalNameParity"/>) on a <b>net472</b> assembly we
/// control — the one flavour it had never been proven on. It was proven on the shared netstandard2.0 fixture
/// and on a net40 Newtonsoft, but net472 is the corner that matters here for a specific reason: it references
/// <c>mscorlib</c> where a modern assembly references <c>System.Runtime</c>, so the two layers resolve the core
/// library along different paths. If <see cref="CciNames"/> and <see cref="ModelNames"/> disagreed there, every
/// classification and call-graph node for an old package would silently split in two.
/// <para>
/// The subject is the net472 flavour of the multi-targeted matrix fixture, so the <em>same source</em> is behind
/// both this and the modern parity coverage. Reuses <see cref="CanonicalNameLayersFixture"/>'s walk and
/// <see cref="CanonicalNameParity"/>'s assertion rather than restating either.
/// </para>
/// </summary>
public sealed class Net472CanonicalNameParityTests : IClassFixture<Net472CanonicalNameLayersFixture>
{
    #region Constructors
    public Net472CanonicalNameParityTests(Net472CanonicalNameLayersFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The acceptance criterion, unchanged from the modern fixture: identical classification-key and node-id
    /// sets from both layers, for method definitions and for call sites.
    /// </summary>
    [Fact]
    public void CciAndModelLayers_ProduceIdenticalKeySets_ForTheNet472MatrixFixture() =>
        CanonicalNameParity.AssertLayersAgree(fixture.Layers.CciLayer, fixture.Layers.ModelLayer);

    /// <summary>
    /// Guards the parity assertion against passing vacuously. The net472 flavour is small by construction —
    /// almost every declaration in it is a bodyless <c>extern</c> — so the ">50 definitions" guard used for the
    /// shared fixture does not apply; what matters is that both layers walked the same non-empty population.
    /// </summary>
    [Fact]
    public void ParitySets_AreNonEmpty_AndBothLayersWalkedTheSamePopulation()
    {
        var cci = fixture.Layers.CciLayer;
        var model = fixture.Layers.ModelLayer;

        Assert.NotEmpty(cci.Definitions);
        Assert.NotEmpty(cci.CallSites);
        Assert.Equal(cci.Definitions.Count, model.Definitions.Count);
        Assert.Equal(cci.CallSites.Count, model.CallSites.Count);

        // Nothing degraded to the placeholder in EITHER direction — a wholesale failure would "agree" across
        // layers and pass the set comparison above.
        foreach (var layer in new[] { cci, model })
        {
            Assert.All(layer.DefinitionNodeIds, id => Assert.DoesNotContain(CanonicalName.UnknownPart, id, StringComparison.Ordinal));
            Assert.All(layer.CallSiteNodeIds, id => Assert.DoesNotContain(CanonicalName.UnknownPart, id, StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// The fixture's own bodied method on net472 is named identically by both layers — the definition side of
    /// the contract, stated on a name a reader can check against the source.
    /// </summary>
    [Fact]
    public void DefinitionNodeId_OfTheFixturesOwnMethod_IsProducedIdenticallyByBothLayers()
    {
        const string clean = TargetFrameworkMatrixFixture.FixtureNamespace + "ModernInteropOps.Clean(System.Int32)";

        Assert.Contains(clean, fixture.Layers.CciLayer.DefinitionNodeIds);
        Assert.Contains(clean, fixture.Layers.ModelLayer.DefinitionNodeIds);

        Assert.Contains(
            TargetFrameworkMatrixFixture.FixtureNamespace + "ModernInteropOps.Clean",
            fixture.Layers.CciLayer.DefinitionKeys);
        Assert.Contains(
            TargetFrameworkMatrixFixture.FixtureNamespace + "ModernInteropOps.Clean",
            fixture.Layers.ModelLayer.DefinitionKeys);
    }

    /// <summary>
    /// <b>The point of this whole class.</b> A call site into the core library is rendered identically by both
    /// layers on an assembly whose core library is <c>mscorlib</c>, not <c>System.Runtime</c> — so neither
    /// adapter's naming is sensitive to which assembly the core types were resolved from. Asserted on
    /// <c>System.Attribute..ctor()</c>, which on net472 lives in <c>mscorlib</c>.
    /// </summary>
    [Fact]
    public void CallSiteNodeId_IntoMscorlib_IsProducedIdenticallyByBothLayers()
    {
        const string attributeCtor = "System.Attribute..ctor()";

        Assert.Contains(attributeCtor, fixture.Layers.CciLayer.CallSiteNodeIds);
        Assert.Contains(attributeCtor, fixture.Layers.ModelLayer.CallSiteNodeIds);

        // A core-library name is not assembly-qualified on either side, so nothing betrays which core library
        // it came from — that equivalence is exactly what makes a key comparable across target frameworks.
        Assert.All(
            fixture.Layers.CciLayer.CallSiteNodeIds.Concat(fixture.Layers.ModelLayer.CallSiteNodeIds),
            id => Assert.DoesNotContain("mscorlib", id, StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Fields
    private readonly Net472CanonicalNameLayersFixture fixture;
    #endregion
}

/// <summary>
/// Binds <see cref="CanonicalNameLayersFixture"/> to the <b>net472</b> flavour of the matrix fixture. xUnit
/// requires a parameterless class fixture, so the parameterized layers fixture is composed rather than
/// subclassed.
/// </summary>
public sealed class Net472CanonicalNameLayersFixture : IDisposable
{
    #region Constructors
    public Net472CanonicalNameLayersFixture() =>
        Layers = new CanonicalNameLayersFixture(MatrixFixtureAssemblies.For("net472"));
    #endregion

    #region Properties
    /// <summary>Both object models' rendering of the net472 matrix fixture assembly.</summary>
    public CanonicalNameLayersFixture Layers { get; }
    #endregion

    #region Methods
    public void Dispose() => Layers.Dispose();
    #endregion
}
