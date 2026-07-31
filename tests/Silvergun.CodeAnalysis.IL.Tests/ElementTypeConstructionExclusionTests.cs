namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

using Xunit;

/// <summary>
/// Pins <c>CapabilityAnalysis.IsElementTypeConstruction</c> — the guard that keeps an <b>array, pointer or
/// managed-pointer declaring type</b> out of the capability catalog's prefix match.
/// <para>
/// <b>The false positive it removes.</b> The catalog matches
/// <c>AssemblyAnalyzer.TypeName(callee.ContainingType).StartsWith(prefix)</c>, and <c>TypeName</c> renders all
/// three constructions as the element type plus a suffix — <c>[]</c>, <c>[,]</c>, <c>*</c>, <c>&amp;</c>. So
/// <c>"System.Diagnostics.Process[,]".StartsWith("System.Diagnostics.Process")</c> is <b>true</b> and an array
/// of <see cref="System.Diagnostics.Process"/> would be classified <see cref="Capability.ProcessExecution"/>.
/// An array of <c>Process</c> is not a <c>Process</c>.
/// </para>
/// <para>
/// <b>Why this class calls the predicate directly rather than going through an assembly.</b> CCI never routes
/// such a declaring type to a call site: it rewrites multi-dimensional array accessors into the synthetic
/// <c>Array_Get</c>/<c>Array_Set</c>/<c>Array_Addr</c>/<c>Array_Create</c> opcodes whose operand is the array
/// <em>type</em> and not an <see cref="IMethodReference"/> (pinned by
/// <see cref="MultiDimensionalArrayCallSiteGapTests"/>), and C# vectors use dedicated IL instructions with no
/// call site at all. No fixture assembly can therefore reach the guard through <c>Match</c>, and a test that
/// went through an assembly could not tell the three arms apart. That is why the predicate is
/// <c>internal</c> rather than <c>private</c> (<c>src/Silvergun.CodeAnalysis.IL/Properties/AssemblyInfo.cs</c>
/// carries the <c>InternalsVisibleTo</c>); without this class the guard is unfalsifiable by the suite —
/// <b>the rest of the tests prove only that adding it broke nothing.</b> Measured at 4 real false positives on
/// the fixture assembly with a reader that does surface those call sites:
/// <c>docs/agent/measurements/ilspy-provider-spike.md</c> §C.3.
/// </para>
/// <para>
/// <b>Every reference asserted on here comes from a real loaded assembly</b>
/// (<see cref="ElementTypeConstructions"/>, read through <see cref="AssemblyAnalyzer"/>), not from a hand-built
/// stub, so each arm is evidence that CCI actually produces that interface for that shape — see
/// <see cref="ElementTypeConstructionFixture"/> for why the shapes are carried in <em>field</em> position.
/// </para>
/// <para>
/// <b>Deliberately not covered: a <c>modopt</c>-wrapped containing type</b>, which returns <c>false</c> (not
/// excluded). That is a considered decision, recorded in the comment above
/// <c>IsElementTypeConstruction</c> in <c>src/Silvergun.CodeAnalysis.IL/CapabilityAnalysis.cs</c>: CCI carries
/// custom modifiers in signature positions, not on a <c>ContainingType</c>, so there is no reachable case to
/// exercise an unwrap against and constructing one would need a hand-emitted signature. Should a modifier ever
/// reach a <c>ContainingType</c>, the fix named there is a depth-bounded unwrap mirroring
/// <c>CciNames.Definition</c> — and this class is where its coverage belongs.
/// </para>
/// </summary>
public sealed class ElementTypeConstructionExclusionTests : IClassFixture<ElementTypeConstructionFixture>
{
    #region Constructors
    public ElementTypeConstructionExclusionTests(ElementTypeConstructionFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// EXCLUDED — a <b>rank-1 vector</b>, <c>System.Diagnostics.Process[]</c>. This is the least reachable arm
    /// and the one most worth pinning: the multi-dimensional fixture exercises rank 2 only, because C# vectors
    /// are read and written with dedicated IL instructions rather than accessor call sites, so no assembly-level
    /// test reaches a vector declaring type at all. It prefix-matches the catalog exactly as <c>[,]</c> does.
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForARankOneVectorOfACataloguedElementType_ReturnsTrue()
    {
        var vector = Assert.IsAssignableFrom<IArrayTypeReference>(fixture.FieldType(nameof(ElementTypeConstructions.ProcessVector)));

        Assert.True(vector.IsVector, "The vector arm is only meaningful if CCI reports rank 1.");
        Assert.Equal(ProcessVector, AssemblyAnalyzer.TypeName(vector));

        Assert.True(CapabilityAnalysis.IsElementTypeConstruction(vector));
    }

    /// <summary>
    /// EXCLUDED — a <b>multi-dimensional array</b>, <c>System.Diagnostics.Process[,]</c>: the exact rendering of
    /// the latent false positive in <see cref="MultiDimensionalArrayCallSiteGapTests"/>.
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForAMultiDimensionalArray_ReturnsTrue()
    {
        var matrix = Assert.IsAssignableFrom<IArrayTypeReference>(fixture.FieldType(nameof(ElementTypeConstructions.ProcessMatrix)));

        Assert.False(matrix.IsVector);
        Assert.Equal(2u, matrix.Rank);
        Assert.Equal(ProcessMatrix, AssemblyAnalyzer.TypeName(matrix));

        Assert.True(CapabilityAnalysis.IsElementTypeConstruction(matrix));
    }

    /// <summary>
    /// EXCLUDED — an <b>unmanaged pointer</b>, <c>System.Int32*</c>. The element type is not a catalogued one
    /// here because it cannot be: C# permits a pointer only to an unmanaged type and every entry in
    /// <see cref="CapabilityAnalysis.Catalog"/> names a class, so no <c>Process*</c> is expressible. What is
    /// asserted is therefore the exclusion itself, on a real <see cref="IPointerTypeReference"/>.
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForAPointer_ReturnsTrue()
    {
        var pointer = Assert.IsAssignableFrom<IPointerTypeReference>(fixture.FieldType(nameof(ElementTypeConstructions.PointerCell)));

        Assert.Equal("System.Int32*", AssemblyAnalyzer.TypeName(pointer));

        Assert.True(CapabilityAnalysis.IsElementTypeConstruction(pointer));
    }

    /// <summary>
    /// EXCLUDED — a <b>managed (by-ref) pointer</b>, <c>System.Diagnostics.Process&amp;</c>, which prefix-matches
    /// the catalog just as the array shapes do.
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForAManagedPointer_ReturnsTrue()
    {
        var byRef = Assert.IsAssignableFrom<IManagedPointerTypeReference>(fixture.FieldType(nameof(ElementTypeConstructions.ManagedPointerCell)));

        Assert.Equal(ProcessByRef, AssemblyAnalyzer.TypeName(byRef));

        Assert.True(CapabilityAnalysis.IsElementTypeConstruction(byRef));
    }

    /// <summary>
    /// NOT EXCLUDED — the plain named type <see cref="System.Diagnostics.Process"/> itself, taken from a real
    /// call site's <c>ContainingType</c>: exactly the reference <c>CapabilityAnalysis.Match</c> is handed when it
    /// classifies <c>Process.Start</c>. If this were ever excluded the detector would stop detecting.
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForAPlainNamedType_ReturnsFalse()
    {
        var named = fixture.CalleeContainingType(nameof(ThreeApis.StartsProcess));

        Assert.Equal(ProcessPrefix, AssemblyAnalyzer.TypeName(named));

        Assert.False(CapabilityAnalysis.IsElementTypeConstruction(named));
    }

    /// <summary>
    /// NOT EXCLUDED — a <b>generic instance</b>, <c>List&lt;Process&gt;</c>. This is the negative control that
    /// matters: generic instances must keep classifying normally. No false match is possible for them because the
    /// <em>container</em> name leads the rendering and the catalogued name can only appear inside the
    /// <c>&lt;…&gt;</c> argument list, where <see cref="string.StartsWith(string, StringComparison)"/> cannot
    /// reach it (pinned end to end by <see cref="CapabilityMatcherSeamTests"/>). If this ever returns
    /// <c>true</c>, real detection has been broken.
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForAGenericInstance_ReturnsFalse()
    {
        var instance = Assert.IsAssignableFrom<IGenericTypeInstanceReference>(fixture.FieldType(nameof(ElementTypeConstructions.ProcessList)));

        Assert.Equal(ListOfProcess, AssemblyAnalyzer.TypeName(instance));

        Assert.False(CapabilityAnalysis.IsElementTypeConstruction(instance));
    }

    /// <summary>
    /// NOT EXCLUDED — <c>null</c>. <c>Match</c> reads <c>callee.ContainingType</c>, which a hostile or truncated
    /// reference can leave null, and the guard must answer rather than throw: a throw there would be attributed
    /// to the whole method as a skip, turning a naming edge case into lost coverage (ADR-0024).
    /// </summary>
    [Fact]
    public void IsElementTypeConstruction_ForNull_ReturnsFalse()
    {
        Assert.False(CapabilityAnalysis.IsElementTypeConstruction(null));
    }

    /// <summary>
    /// NON-VACUITY, and the reason the guard exists: each excluded construction over a <em>catalogued</em>
    /// element type really does prefix-match the catalog's <see cref="Capability.ProcessExecution"/> entry. The
    /// guard is the only thing standing between these renderings and a finding — remove it and every one of them
    /// classifies, which is precisely the 4 false positives measured with a reader that surfaces these call
    /// sites (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §C.3).
    /// </summary>
    [Theory]
    [InlineData(ProcessVector)]
    [InlineData(ProcessMatrix)]
    [InlineData(ProcessByRef)]
    public void ExcludedConstruction_OfACataloguedElementType_WouldOtherwisePrefixMatchTheCatalog(string rendering)
    {
        Assert.StartsWith(ProcessPrefix, rendering, StringComparison.Ordinal);
        Assert.NotEqual(ProcessPrefix, rendering);

        var matching = CapabilityAnalysis.Catalog
            .Where(api => rendering.StartsWith(api.TypePrefix, StringComparison.Ordinal))
            .ToArray();

        Assert.Contains(matching, api => api.Capability == Capability.ProcessExecution);
    }

    /// <summary>
    /// The counterpart for the generic-instance control, which is why it must <em>not</em> be excluded:
    /// <c>List&lt;Process&gt;</c> does not prefix-match the catalog at all, so nothing about it needs
    /// suppressing — and excluding it would silently remove a whole shape from detection instead.
    /// </summary>
    [Fact]
    public void GenericInstance_OfACataloguedArgument_DoesNotPrefixMatchTheCatalog()
    {
        Assert.Contains(ProcessPrefix, ListOfProcess);

        Assert.DoesNotContain(
            CapabilityAnalysis.Catalog,
            api => ListOfProcess.StartsWith(api.TypePrefix, StringComparison.Ordinal));
    }
    #endregion

    #region Fields
    private const string ProcessPrefix = "System.Diagnostics.Process";
    private const string ProcessVector = "System.Diagnostics.Process[]";
    private const string ProcessMatrix = "System.Diagnostics.Process[,]";
    private const string ProcessByRef = "System.Diagnostics.Process&";
    private const string ListOfProcess = "System.Collections.Generic.List<System.Diagnostics.Process>";

    private readonly ElementTypeConstructionFixture fixture;
    #endregion
}
