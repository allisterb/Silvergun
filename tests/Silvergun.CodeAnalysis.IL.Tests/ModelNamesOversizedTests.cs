namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SyntheticModel;

using ModelTypes = Model.Types;

/// <summary>
/// graph-names-hostile-types.md on hand-built <c>Model</c>: a <see cref="ModelTypes.BasicType"/> with <c>Oversized</c> set
/// (what CCIProvider builds for a generic instance past <c>TypeSize.MaxParts</c>) renders as
/// <see cref="CanonicalName.Oversized"/> wherever it sits, and is never taken for a definition (its arguments are unknown).
/// </summary>
public sealed class ModelNamesOversizedTests
{
    #region Methods
    [Fact]
    public void Oversized_RendersAsMarker()
    {
        Assert.Equal(Marker, CanonicalName.Oversized(8191, Hash));
        Assert.Equal(Marker, ModelNames.TypeName(Oversized()));
    }

    [Fact]
    public void Oversized_InANodeId_RendersAsMarker_InEveryPosition()
    {
        var method = Method(TypeRef("NS", "C"), "M",
            Oversized(),
            new ModelTypes.ArrayType(Oversized()),
            TypeRef("NS", "Box", 1, arguments: [Oversized()]));
        method.Parameters.Add(ByRef(3, Oversized()));

        Assert.Equal($"NS.C.M({Marker},{Marker}[],NS.Box`1<{Marker}>,{Marker}&)", CanonicalName.NodeId(ModelNames.Of(method)));
    }

    /// <summary>The marker wins over any arguments the type happens to carry: the tree is never walked.</summary>
    [Fact]
    public void Oversized_WithArguments_StillRendersOnlyTheMarker()
    {
        var type = Oversized();
        type.GenericArguments.Add(TypeRef("System", "Int32"));
        type.GenericArguments.Add(TypeRef("System", "Int32"));

        Assert.Equal(Marker, ModelNames.TypeName(type));
        Assert.Null(ModelNames.TypeArguments(type));
    }

    /// <summary>Its identity is still the definition's: classification keys do not change.</summary>
    [Fact]
    public void Oversized_IdentityIsTheDefinitions() =>
        Assert.Equal("Big.Pair`2", CanonicalName.NodeId(ModelNames.Of(Oversized())));

    /// <summary>No arguments, but no definition either: unknown (null), never empty.</summary>
    [Fact]
    public void TypeArguments_OfOversized_IsNull() => Assert.Null(ModelNames.TypeArguments(Oversized()));

    /// <summary>A nested type that takes its arguments from an oversized container: unknown too.</summary>
    [Fact]
    public void TypeArguments_OfANestedTypeInAnOversizedContainer_IsNull() =>
        Assert.Null(ModelNames.TypeArguments(TypeRef(null, "Inner", 2, container: Oversized())));

    /// <summary>The same type without <c>Oversized</c> is an ordinary instance, so the marker is the flag's doing alone.</summary>
    [Fact]
    public void WithoutTheFlag_RendersWhole()
    {
        var type = TypeRef("Big", "Pair", 2, arguments: [TypeRef("System", "Int32"), TypeRef("System", "Int32")]);

        Assert.Equal("Big.Pair`2<System.Int32,System.Int32>", ModelNames.TypeName(type));
        Assert.Equal(new[] { "System.Int32", "System.Int32" }, ModelNames.TypeArguments(type));
        Assert.False(CanonicalName.HasOversized(ModelNames.TypeName(type)));
    }

    [Fact]
    public void HasOversized_FindsTheMarkerAnywhere_AndNothingElse()
    {
        Assert.True(CanonicalName.HasOversized(Marker));
        Assert.True(CanonicalName.HasOversized($"NS.C.M(NS.Box`1<{Marker}>)"));
        Assert.False(CanonicalName.HasOversized("NS.C.M(System.Int32)"));
        Assert.False(CanonicalName.HasOversized(null));
        Assert.False(CanonicalName.HasOversized(string.Empty));
    }

    /// <summary>An unreadable hash still renders a well-formed marker.</summary>
    [Fact]
    public void Oversized_WithNoHash_RendersUnknownPart() =>
        Assert.Equal($"<oversized:8191 parts:{CanonicalName.UnknownPart}>", CanonicalName.Oversized(8191, null));

    // ---- Substitution budget (ModelNames.Substituted, MaxSubstitutedChars = 65,536) -------------------------------------

    /// <summary>An ordinary <c>List&lt;!0&gt;</c> with a short argument still substitutes exactly.</summary>
    [Fact]
    public void ParameterTypes_AnOrdinarySubstitution_IsExact() =>
        Assert.Equal(
            ["System.Collections.Generic.List`1<System.Int32>", "System.Int32"],
            ModelNames.ParameterTypes(
                Method(TypeRef("NS", "Own", 1), "M", TypeRef("System.Collections.Generic", "List", 1, arguments: [TypeParameter(0)]), TypeParameter(0)),
                ["System.Int32"]));

    /// <summary>
    /// The bound is on the substituted length: a bare <c>!0</c> (2 chars) substituted by an argument of exactly 65,536
    /// chars renders it; one more char is past the budget, <c>&lt;unknown&gt;</c>.
    /// </summary>
    [Theory]
    [InlineData(65_535, true)]
    [InlineData(65_536, true)]
    [InlineData(65_537, false)]
    public void ParameterTypes_AtTheSubstitutionBudget_SubstitutesUpToIt_AndNotPast(int length, bool substitutes)
    {
        var argument = new string('A', length);

        var rendered = Assert.Single(ModelNames.ParameterTypes(Method(TypeRef("NS", "Own", 1), "M", TypeParameter(0)), [argument]));

        Assert.Equal(substitutes ? argument : CanonicalName.UnknownPart, rendered);
    }

    /// <summary>The budget applies to the return type too.</summary>
    [Fact]
    public void ReturnType_PastTheSubstitutionBudget_IsUnknown()
    {
        var method = new ModelTypes.MethodReference("M", TypeParameter(0)) { ContainingType = TypeRef("NS", "Own", 1) };

        Assert.Equal("System.Int32", ModelNames.ReturnType(method, ["System.Int32"]));
        Assert.Equal(CanonicalName.UnknownPart, ModelNames.ReturnType(method, [new string('A', 65_537)]));
    }

    /// <summary>
    /// The composed case on hand-built Model: a parameter that is a Pair DAG of shared <c>BasicType</c>s with 2,048
    /// <c>!0</c> leaves (T'_10), substituted by a 51K-char argument: <c>&lt;unknown&gt;</c>, promptly, the ~100M chars never built.
    /// </summary>
    [Fact]
    public void ParameterTypes_AComposedDagPastTheBudget_IsUnknown_Promptly()
    {
        ModelTypes.IType level = TypeRef("Big", "Pair", 2, arguments: [TypeParameter(0), TypeParameter(0)]);
        for (var k = 1; k <= 10; k++)
            level = TypeRef("Big", "Pair", 2, arguments: [level, level]);
        var argument = new string('A', 51_187);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var rendered = ModelNames.ParameterTypes(Method(TypeRef("NS", "Own", 1), "M", level), [argument]);
        clock.Stop();

        Assert.Equal([CanonicalName.UnknownPart], rendered);
        Assert.True(clock.Elapsed < System.TimeSpan.FromMilliseconds(500), $"{clock.ElapsedMilliseconds} ms.");
    }

    // ---- BasicType.Equals (our fork) ------------------------------------------------------------------------------------

    [Fact]
    public void Equals_TwoOversizedInstancesWithDifferentHashes_AreNotEqual()
    {
        Assert.NotEqual(Oversized(assembly: "Lib"), Oversized("fedcba9876543210", "Lib"));
        Assert.False(Oversized(assembly: "Lib").Equals(Oversized("fedcba9876543210", "Lib")));
    }

    [Fact]
    public void Equals_TwoOversizedInstancesWithDifferentParts_AreNotEqual()
    {
        var other = Oversized(assembly: "Lib");
        other.Oversized = new ModelTypes.Oversize(8192, Hash);

        Assert.False(Oversized(assembly: "Lib").Equals(other));
    }

    [Fact]
    public void Equals_AnOversizedInstanceAndItsBareDefinition_AreNotEqual_EitherWay()
    {
        var bare = TypeRef("Big", "Pair", 2, assembly: "Lib");

        Assert.False(Oversized(assembly: "Lib").Equals(bare));
        Assert.False(bare.Equals(Oversized(assembly: "Lib")));
    }

    /// <summary>The control: the same size and hash are equal, so the inequalities above are the measure's doing.</summary>
    [Fact]
    public void Equals_TwoOversizedInstancesWithTheSameMeasure_AreEqual()
    {
        Assert.True(Oversized(assembly: "Lib").Equals(Oversized(assembly: "Lib")));
        Assert.Equal(Oversized(assembly: "Lib").GetHashCode(), Oversized(assembly: "Lib").GetHashCode());
    }

    // Big.Pair`2 past the bound, as TypeExtractor builds it: the definition's name, no arguments, Oversized set.
    private static ModelTypes.BasicType Oversized(string hash = Hash, string? assembly = null)
    {
        var type = TypeRef("Big", "Pair", 2, assembly: assembly);
        type.GenericType = TypeRef("Big", "Pair", 2, assembly: assembly);
        type.Oversized = new ModelTypes.Oversize(8191, hash);
        return type;
    }
    #endregion

    #region Fields
    private const string Hash = "0123456789abcdef";
    private const string Marker = "<oversized:8191 parts:0123456789abcdef>";
    #endregion
}
