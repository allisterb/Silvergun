namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SyntheticModel;

using ModelTypes = Model.Types;

/// <summary>
/// ADR 0025 on hand-built <c>Model</c>: <see cref="ModelNames"/> renders a <see cref="ModelTypes.PointerType"/> from its
/// <c>IsManaged</c> flag alone — <c>T&amp;</c> when managed, <c>T*</c> otherwise — and never consults the parameter
/// <see cref="ModelTypes.MethodParameterKind"/> (which CCIProvider sets to <c>Out</c> for a non-by-ref <c>[Out] T*</c>).
/// </summary>
public sealed class ModelNamesPointerKindTests
{
    #region Methods
    /// <summary>An unmanaged pointer renders <c>T*</c> whatever the parameter kind — the <c>[Out] byte**</c> case is <c>Out</c>.</summary>
    [Theory]
    [InlineData(ModelTypes.MethodParameterKind.In)]
    [InlineData(ModelTypes.MethodParameterKind.Out)]
    [InlineData(ModelTypes.MethodParameterKind.Ref)]
    public void UnmanagedPointerParameter_RendersAsPointer_WhateverItsKind(ModelTypes.MethodParameterKind kind)
    {
        var method = WithParameter(new ModelTypes.PointerType(new ModelTypes.PointerType(ByteType)), kind);

        Assert.Equal(["System.Byte**"], ModelNames.Of(method).ParameterTypes);
        Assert.Equal("NS.C.M(System.Byte**)", CanonicalName.NodeId(ModelNames.Of(method)));
    }

    /// <summary>A managed pointer renders <c>T&amp;</c> whatever the parameter kind, even <c>In</c>.</summary>
    [Theory]
    [InlineData(ModelTypes.MethodParameterKind.In)]
    [InlineData(ModelTypes.MethodParameterKind.Out)]
    [InlineData(ModelTypes.MethodParameterKind.Ref)]
    public void ManagedPointerParameter_RendersAsByRef_WhateverItsKind(ModelTypes.MethodParameterKind kind)
    {
        var method = WithParameter(new ModelTypes.PointerType(IntType, isManaged: true), kind);

        Assert.Equal(["System.Int32&"], ModelNames.Of(method).ParameterTypes);
    }

    /// <summary><c>out byte*</c>: a managed pointer to an unmanaged one, each level rendered by its own flag.</summary>
    [Fact]
    public void ManagedPointerToUnmanagedPointer_RendersPointerThenByRef() =>
        Assert.Equal(
            ["System.Byte*&"],
            ModelNames.Of(WithParameter(new ModelTypes.PointerType(new ModelTypes.PointerType(ByteType), isManaged: true), ModelTypes.MethodParameterKind.Out)).ParameterTypes);

    /// <summary>The flag is read anywhere a pointer sits, not only at a parameter's top level.</summary>
    [Fact]
    public void TypeName_RendersTheFlag_OutsideAParameterToo()
    {
        Assert.Equal("System.Int32&", ModelNames.TypeName(new ModelTypes.PointerType(IntType, isManaged: true)));
        Assert.Equal("System.Int32*", ModelNames.TypeName(new ModelTypes.PointerType(IntType)));
        Assert.Equal("System.Int32*", ModelNames.TypeName(new ModelTypes.PointerType(IntType, isManaged: false)));
    }

    /// <summary>
    /// Inside a function pointer too: a managed parameter renders <c>&amp;</c> (<c>delegate*&lt;ref int, void&gt;</c>) and an
    /// unmanaged one <c>*</c> even with kind <c>Out</c>.
    /// </summary>
    [Fact]
    public void FunctionPointerParameter_RendersFromTheFlag_NotTheKind()
    {
        var pointer = new ModelTypes.FunctionPointerType(VoidType);
        pointer.Parameters.Add(new ModelTypes.MethodParameterReference(0, new ModelTypes.PointerType(IntType, isManaged: true)) { Kind = ModelTypes.MethodParameterKind.In });
        pointer.Parameters.Add(new ModelTypes.MethodParameterReference(1, new ModelTypes.PointerType(IntType)) { Kind = ModelTypes.MethodParameterKind.Out });

        Assert.Equal("fnptr:System.Void(System.Int32&,System.Int32*)", ModelNames.TypeName(pointer));
    }

    /// <summary>The <see cref="ByRef"/> helper mirrors CCIProvider's output: managed, kind <c>Ref</c>, rendered <c>T&amp;</c>.</summary>
    [Fact]
    public void ByRefHelper_BuildsAManagedPointer_RenderedAsByRef()
    {
        var parameter = ByRef(0, IntType);

        Assert.True(Assert.IsType<ModelTypes.PointerType>(parameter.Type).IsManaged);
        Assert.Equal(ModelTypes.MethodParameterKind.Ref, parameter.Kind);
        Assert.Equal("System.Int32&", ModelNames.TypeName(parameter.Type));
    }

    // NS.C.M(type) with its one parameter of the given kind.
    private static ModelTypes.MethodReference WithParameter(ModelTypes.IType type, ModelTypes.MethodParameterKind kind)
    {
        var method = Method(TypeRef("NS", "C"), "M");
        method.Parameters.Add(new ModelTypes.MethodParameterReference(0, type) { Kind = kind });
        return method;
    }
    #endregion

    #region Fields
    private static readonly ModelTypes.BasicType IntType = TypeRef("System", "Int32");
    private static readonly ModelTypes.BasicType ByteType = TypeRef("System", "Byte");
    private static readonly ModelTypes.BasicType VoidType = TypeRef("System", "Void");
    #endregion
}
