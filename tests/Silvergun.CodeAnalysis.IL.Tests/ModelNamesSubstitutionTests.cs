namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SyntheticModel;

using ModelTypes = Model.Types;

/// <summary>
/// <see cref="ModelNames.TypeArguments"/> and <see cref="ModelNames.ParameterTypes"/> (spec §2.6, S2) on hand-built
/// <c>Model</c> objects (<see cref="SyntheticModel"/>), so every shape is exact and none needs a compiled fixture: deep
/// chains are never compiled (spec §2.5's fixture incident).
/// <para>
/// Model's quirk being undone: a nested type's <c>GenericArguments</c> include its container's only when that link is
/// itself instantiated, while <c>GenericParameterCount</c> is always cumulative. So the arguments a link carries are a
/// SUFFIX of its full list, and the missing prefix is the FRONT of the container's full list. Anything that does not
/// add up is <c>null</c> — unknown — never padded with positional <c>!n</c> (C-A) and never guessed.
/// </para>
/// </summary>
public sealed class ModelNamesSubstitutionTests
{
    #region Methods
    // ---- TypeArguments: chains that add up ------------------------------------------------------------------------

    [Fact]
    public void TypeArguments_OfNull_IsNull() => Assert.Null(ModelNames.TypeArguments(null));

    [Fact]
    public void TypeArguments_OfANonGenericType_IsEmpty() =>
        Assert.Equal(Array.Empty<string>(), ModelNames.TypeArguments(TypeRef("NS", "Plain")));

    /// <summary>A definition chain — no link instantiated — is a definition: empty, at every level.</summary>
    [Fact]
    public void TypeArguments_OfADefinitionChain_IsEmpty()
    {
        var outer = TypeRef("NS", "Outer4", 1);
        var mid = TypeRef(null, "Mid", 1, outer);
        var inner = TypeRef(null, "Inner", 2, mid);
        var innermost = TypeRef(null, "Innermost", 3, inner);

        Assert.All(new ModelTypes.IBasicType[] { outer, mid, inner, innermost }, t => Assert.Equal(Array.Empty<string>(), ModelNames.TypeArguments(t)));
        Assert.Equal(Array.Empty<string>(), ModelNames.TypeArguments(TypeRef(null, "Nested", 1, TypeRef("NS", "Outer", 1))));
    }

    [Fact]
    public void TypeArguments_OfATopLevelInstance_AreItsArguments() =>
        Assert.Equal(["System.Int32", "System.String"], ModelNames.TypeArguments(TypeRef("NS", "G", 2, arguments: [IntType, StringType])));

    /// <summary>Every link instantiated: Model's list is already cumulative and is taken as-is.</summary>
    [Fact]
    public void TypeArguments_WhenEveryLinkIsInstantiated_AreTheInnermostLinksCumulativeList()
    {
        var outer = TypeRef("NS", "Outer", 1, arguments: [IntType]);
        var inner = TypeRef(null, "Inner", 2, outer, arguments: [IntType, StringType]);

        Assert.Equal(["System.Int32", "System.String"], ModelNames.TypeArguments(inner));
    }

    /// <summary>W-1: <c>Outer&lt;int&gt;.Nested</c> carries no arguments of its own; they are all its container's.</summary>
    [Fact]
    public void TypeArguments_OfANonGenericNestedTypeOfAnInstance_AreTheContainersArguments()
    {
        var nested = TypeRef(null, "Nested", 1, TypeRef("NS", "Outer", 1, arguments: [IntType]));

        Assert.Empty(nested.GenericArguments);
        Assert.Equal(["System.Int32"], ModelNames.TypeArguments(nested));
    }

    /// <summary><c>Outer&lt;int&gt;.Mid.Inner&lt;string&gt;</c>: the non-generic middle link hides <c>int</c>; it is prepended.</summary>
    [Fact]
    public void TypeArguments_ThroughANonGenericMiddleLink_PrependTheOuterArguments()
    {
        var mid = TypeRef(null, "Mid", 1, TypeRef("NS", "Outer", 1, arguments: [IntType]));
        var inner = TypeRef(null, "Inner", 2, mid, arguments: [StringType]);

        Assert.Equal(["System.Int32"], ModelNames.TypeArguments(mid));
        Assert.Equal(["System.Int32", "System.String"], ModelNames.TypeArguments(inner));
    }

    /// <summary>
    /// C-A: <c>Outer4&lt;string&gt;.Mid.Inner&lt;int&gt;.Innermost&lt;bool&gt;</c>. Innermost carries <c>[int, bool]</c>; one
    /// argument is missing, and it is the FRONT of Inner's full list <c>[string, int]</c> — not the back (<c>int</c>), and
    /// not a positional <c>!0</c> (the padded walk that excluded the true candidate).
    /// </summary>
    [Fact]
    public void TypeArguments_OfTheFourLevelChain_TakeTheFrontOfTheContainersFullList()
    {
        var mid = TypeRef(null, "Mid", 1, TypeRef("NS", "Outer4", 1, arguments: [StringType]));
        var inner = TypeRef(null, "Inner", 2, mid, arguments: [IntType]);
        var innermost = TypeRef(null, "Innermost", 3, inner, arguments: [IntType, BoolType]);

        Assert.Equal(["System.String", "System.Int32"], ModelNames.TypeArguments(inner));
        Assert.Equal(["System.String", "System.Int32", "System.Boolean"], ModelNames.TypeArguments(innermost));
    }

    // ---- TypeArguments: unknown -----------------------------------------------------------------------------------

    public static TheoryData<string, ModelTypes.IBasicType> ChainsThatDoNotAddUp => new()
    {
        // A top-level type has nowhere to take the missing argument from.
        { "top-level, too few arguments", TypeRef("NS", "G", 2, arguments: [IntType]) },
        // Two missing, but the container's full list has only one.
        { "container too short", TypeRef(null, "Inner", 3, TypeRef("NS", "Outer", 1, arguments: [IntType]), arguments: [StringType]) },
        // An instantiated link under a definition container: its prefix is unknown.
        { "instantiated under a definition", TypeRef(null, "Inner", 2, TypeRef("NS", "Outer", 1), arguments: [StringType]) },
        // ...and that unknown propagates inward through a non-generic link.
        {
            "unknown propagates inward",
            TypeRef(null, "Innermost", 3, TypeRef(null, "Inner", 2, TypeRef(null, "Mid", 1, TypeRef("NS", "Outer4", 1)), arguments: [IntType]), arguments: [IntType, BoolType])
        },
    };

    [Theory]
    [MemberData(nameof(ChainsThatDoNotAddUp))]
    public void TypeArguments_OfAChainThatDoesNotAddUp_IsNull(string shape, ModelTypes.IBasicType type) =>
        Assert.True(ModelNames.TypeArguments(type) is null, $"{shape}: [{string.Join(", ", ModelNames.TypeArguments(type) ?? [])}]");

    /// <summary>
    /// The depth bound, built synthetically (never compiled): a generic outer, then a long run of non-generic links,
    /// then an instantiated innermost link. Ten links recover the outer argument; a hundred exceed the bound and are
    /// unknown — not truncated, not padded.
    /// </summary>
    [Fact]
    public void TypeArguments_BeyondTheDepthBound_IsNull_WhileTheSameShapeWithinItIsRecovered()
    {
        Assert.Equal(["System.Int32", "System.Boolean"], ModelNames.TypeArguments(DeepChain(10)));
        Assert.Null(ModelNames.TypeArguments(DeepChain(100)));
    }

    /// <summary>A hostile cyclic chain (a type that contains itself) ends at the bound as unknown, without a stack overflow.</summary>
    [Fact]
    public void TypeArguments_OfACyclicChain_IsNull()
    {
        var cyclic = TypeRef("NS", "Cycle", 2, arguments: [IntType]);
        cyclic.ContainingType = cyclic;

        Assert.Null(ModelNames.TypeArguments(cyclic));
    }

    [Theory]
    [InlineData("innermost GenericArguments")]
    [InlineData("container GenericArguments")]
    [InlineData("innermost ContainingType")]
    [InlineData("innermost GenericParameterCount")]
    public void TypeArguments_WhenAReadThrows_IsNull(string read)
    {
        var outer = TypeRef("NS", "Outer", 1, arguments: [IntType]);
        ModelTypes.IBasicType type = read switch
        {
            "innermost GenericArguments" => new ThrowingBasicType(TypeRef(null, "Nested", 1, outer)) { ThrowOnGenericArguments = true },
            "container GenericArguments" => TypeRef(null, "Nested", 1, new ThrowingBasicType(outer) { ThrowOnGenericArguments = true }),
            "innermost ContainingType" => new ThrowingBasicType(TypeRef(null, "Nested", 1, outer)) { ThrowOnContainingType = true },
            _ => new ThrowingBasicType(TypeRef(null, "Nested", 1, outer)) { ThrowOnGenericParameterCount = true },
        };

        // The same shape without the throwing read is recovered, so only the read makes the difference.
        Assert.Equal(["System.Int32"], ModelNames.TypeArguments(TypeRef(null, "Nested", 1, outer)));
        Assert.Null(Record.Exception(() => ModelNames.TypeArguments(type)));
        Assert.Null(ModelNames.TypeArguments(type));
    }

    // ---- TypeArguments: tightened after the S2 test round (spec §2.6, last bullet) --------------------------------

    /// <summary>
    /// A link carrying MORE Model arguments than its cumulative <c>GenericParameterCount</c> does not add up: unknown —
    /// never taken as-is (the extra argument would shift every <c>!n</c> it is substituted for).
    /// </summary>
    public static TheoryData<string, ModelTypes.IBasicType> LinksWithMoreArgumentsThanTheirArity => new()
    {
        { "top-level", TypeRef("NS", "G", 1, arguments: [IntType, StringType]) },
        { "innermost link", TypeRef(null, "Inner", 2, TypeRef("NS", "Outer", 1, arguments: [IntType]), arguments: [IntType, StringType, BoolType]) },
        // The prefix is taken from a container that itself carries too many.
        { "container link", TypeRef(null, "Nested", 1, TypeRef("NS", "Outer", 1, arguments: [IntType, StringType])) },
    };

    [Theory]
    [MemberData(nameof(LinksWithMoreArgumentsThanTheirArity))]
    public void TypeArguments_WhenALinkCarriesMoreArgumentsThanItsArity_IsNull(string shape, ModelTypes.IBasicType type) =>
        Assert.True(ModelNames.TypeArguments(type) is null, $"{shape}: [{string.Join(", ", ModelNames.TypeArguments(type) ?? [])}]");

    /// <summary>
    /// Arguments that are read without throwing yet RENDER <c>&lt;unknown&gt;</c>. Substituting one would be a guess that
    /// can exclude the true candidate, so the whole list is unknown. Shared with
    /// <see cref="MemberIndexSynthesizedReferenceTests"/>, which drives the same arguments through <c>Resolve</c>.
    /// </summary>
    public static TheoryData<string, ModelTypes.IType?> ArgumentsThatRenderUnknown => new()
    {
        { "a null argument", null },
        { "an argument whose nesting chain cannot be read", new ThrowingBasicType(TypeRef("NS", "Hostile")) { ThrowOnContainingType = true } },
        { "an argument nested past the depth bound (a truncated chain)", NestedChain(100) },
        { "an array argument decorated past the depth bound", JaggedArray(IntType, 100) },
    };

    /// <summary>
    /// An <c>&lt;unknown&gt;</c>-rendering argument makes <see cref="ModelNames.TypeArguments"/> null whether it is the link's
    /// own argument or the prefix recovered from its container; the same shapes with a readable argument are recovered.
    /// </summary>
    [Theory]
    [MemberData(nameof(ArgumentsThatRenderUnknown))]
    public void TypeArguments_WhenARecoveredArgumentRendersUnknown_IsNull(string what, ModelTypes.IType? argument)
    {
        Assert.True(ModelNames.TypeName(argument).Contains(CanonicalName.UnknownPart, StringComparison.Ordinal), $"{what} renders {ModelNames.TypeName(argument)}");
        Assert.Equal(["System.Int32", "System.String"], ModelNames.TypeArguments(TypeRef("NS", "G", 2, arguments: [IntType, StringType])));
        Assert.Equal(["System.String"], ModelNames.TypeArguments(TypeRef(null, "Nested", 1, TypeRef("NS", "Outer", 1, arguments: [StringType]))));

        Assert.Null(ModelNames.TypeArguments(TypeRef("NS", "G", 2, arguments: [IntType, argument!])));
        Assert.Null(ModelNames.TypeArguments(TypeRef(null, "Nested", 1, TypeRef("NS", "Outer", 1, arguments: [argument!]))));
    }

    // ---- ParameterTypes -------------------------------------------------------------------------------------------

    [Fact]
    public void ParameterTypes_OfNull_IsEmpty() => Assert.Empty(ModelNames.ParameterTypes(null, ["System.Int32"]));

    /// <summary>With no arguments, exactly the identity's parameter types.</summary>
    [Fact]
    public void ParameterTypes_WithNoArguments_AreTheIdentitysParameterTypes()
    {
        var method = Decorated();

        Assert.Equal(ModelNames.Of(method).ParameterTypes, ModelNames.ParameterTypes(method, []));
        Assert.Contains("!0", ModelNames.ParameterTypes(method, []));
    }

    /// <summary>
    /// Substitution goes through every decoration CCI's specialization goes through — arrays (any rank), pointers,
    /// by-ref, generic arguments — while method parameters (<c>!!n</c>) and positions beyond the arguments stay positional.
    /// </summary>
    [Fact]
    public void ParameterTypes_SubstituteThroughArraysPointersByRefAndGenericArguments() =>
        Assert.Equal(
            ["System.Int32", "System.Int32[]", "System.Int32[,]", "System.Int32*", "System.Int32&",
             "System.Collections.Generic.List`1<System.Int32>", "!!0", "!1"],
            ModelNames.ParameterTypes(Decorated(), ["System.Int32"]));

    /// <summary>
    /// CCI's <c>TypeHelper.SpecializeTypeReference</c> has no function-pointer case, so a site keeps the definition's
    /// <c>!n</c> inside <c>fnptr:…</c> — in its parameters, its return type, by-ref inside it, and wherever the pointer
    /// itself sits (an array element, a generic argument, a pointer target). The bare <c>!0</c> beside it IS substituted:
    /// substitution is not off, only stopped at the function pointer.
    /// </summary>
    [Fact]
    public void ParameterTypes_NeverSubstituteInsideAFunctionPointer_WhereverItSits()
    {
        var byRefInside = new ModelTypes.FunctionPointerType(VoidType);
        byRefInside.Parameters.Add(ByRef(0, TypeParameter(0)));
        var method = Method(
            TypeRef("NS", "G", 1),
            "M",
            TypeParameter(0),
            FunctionPointer(VoidType, TypeParameter(0)),
            FunctionPointer(TypeParameter(0)),
            byRefInside,
            new ModelTypes.ArrayType(FunctionPointer(VoidType, TypeParameter(0))),
            TypeRef("System.Collections.Generic", "List", 1, arguments: [FunctionPointer(VoidType, TypeParameter(0))]),
            new ModelTypes.PointerType(FunctionPointer(VoidType, TypeParameter(0))));

        Assert.Equal(
            ["System.Int32", "fnptr:System.Void(!0)", "fnptr:!0()", "fnptr:System.Void(!0&)", "fnptr:System.Void(!0)[]",
             "System.Collections.Generic.List`1<fnptr:System.Void(!0)>", "fnptr:System.Void(!0)*"],
            ModelNames.ParameterTypes(method, ["System.Int32"]));
    }

    // NS.G`1.M(!0, !0[], !0[,], !0*, ref !0, List<!0>, !!0, !1) - every decoration around a type parameter.
    private static ModelTypes.MethodReference Decorated()
    {
        var method = Method(
            TypeRef("NS", "G", 1),
            "M",
            TypeParameter(0),
            new ModelTypes.ArrayType(TypeParameter(0)),
            new ModelTypes.ArrayType(TypeParameter(0), 2),
            new ModelTypes.PointerType(TypeParameter(0)));
        method.Parameters.Add(ByRef(4, TypeParameter(0)));
        method.Parameters.Add(new ModelTypes.MethodParameterReference(5, TypeRef("System.Collections.Generic", "List", 1, arguments: [TypeParameter(0)])));
        method.Parameters.Add(new ModelTypes.MethodParameterReference(6, MethodParameter(0)));
        method.Parameters.Add(new ModelTypes.MethodParameterReference(7, TypeParameter(1)));
        return method;
    }

    // Outer<int>, then `links` non-generic links, then Innermost<bool> (cumulative arity 2, carrying only [bool]).
    private static ModelTypes.BasicType DeepChain(int links)
    {
        ModelTypes.IBasicType current = TypeRef("NS", "Outer", 1, arguments: [IntType]);
        for (var i = 0; i < links; i++)
            current = TypeRef(null, "N" + i, 1, current);
        return TypeRef(null, "Innermost", 2, current, arguments: [BoolType]);
    }

    // A non-generic type nested `links` deep: its nesting chain exceeds the depth bound and renders truncated.
    private static ModelTypes.BasicType NestedChain(int links)
    {
        var current = TypeRef("NS", "Root");
        for (var i = 0; i < links; i++)
            current = TypeRef(null, "N" + i, 0, current);
        return current;
    }

    // `element` wrapped in `ranks` single-dimensional array levels - synthetic, never compiled.
    private static ModelTypes.IType JaggedArray(ModelTypes.IType element, int ranks)
    {
        var current = element;
        for (var i = 0; i < ranks; i++)
            current = new ModelTypes.ArrayType(current);
        return current;
    }
    #endregion

    #region Fields
    private static readonly ModelTypes.BasicType IntType = TypeRef("System", "Int32");
    private static readonly ModelTypes.BasicType StringType = TypeRef("System", "String");
    private static readonly ModelTypes.BasicType BoolType = TypeRef("System", "Boolean");
    private static readonly ModelTypes.BasicType VoidType = TypeRef("System", "Void");
    #endregion
}
