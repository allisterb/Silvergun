namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Model.Types;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The model flags the analysis-net fork now records (reachability R1, S1.1; acceptance criterion 1): declared
/// <see cref="VisibilityKind"/> on every type and member definition, <see cref="ClassDefinition.IsAbstract"/> and
/// <see cref="ClassDefinition.IsSealed"/>, and <see cref="MethodDefinition.IsSealed"/>, <see cref="MethodDefinition.IsNewSlot"/>
/// and <see cref="MethodDefinition.IsPlatformInvoke"/>. Read through the real loader (<see cref="AssemblyDisassembler"/>
/// and <see cref="MemberIndex"/>) over <c>RootFixture.Flags</c>, so each value is what CCI's metadata says of C#
/// source whose accessibility is known.
/// </summary>
public sealed class ModelDefinitionFlagsTests : IClassFixture<RootFixtureModel>
{
    #region Constructors
    public ModelDefinitionFlagsTests(RootFixtureModel fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Visibility: methods
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("PublicMethod", VisibilityKind.Public)]
    [InlineData("InternalMethod", VisibilityKind.Assembly)]
    [InlineData("PrivateMethod", VisibilityKind.Private)]
    [InlineData("ProtectedMethod", VisibilityKind.Family)]
    [InlineData("ProtectedInternalMethod", VisibilityKind.FamilyOrAssembly)]
    [InlineData("PrivateProtectedMethod", VisibilityKind.FamilyAndAssembly)]
    public void Method_Visibility_IsTheDeclaredAccessibility(string name, VisibilityKind expected)
    {
        Assert.Equal(expected, fixture.Method($"{Flags}.Accessibility.{name}()").Definition.Visibility);
    }

    // A C# explicit implementation is a private method named after the interface member.
    [Fact]
    public void Method_ExplicitImplementation_IsPrivate_Virtual_Sealed_AndNewSlot()
    {
        var method = Assert.Single(fixture.Index.Methods, m => m.DeclaringTypeId == $"{Flags}.ExplicitShape" && m.Definition.Name.EndsWith(".Run", StringComparison.Ordinal)).Definition;

        Assert.Equal($"{Flags}.IPublicInterface.Run", method.Name);
        Assert.Equal(VisibilityKind.Private, method.Visibility);
        Assert.True(method.IsVirtual);
        Assert.True(method.IsSealed);
        Assert.True(method.IsNewSlot);
    }

    // ---------------------------------------------------------------------------------------------------
    // Visibility: fields and enum constants
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("PublicField", VisibilityKind.Public)]
    [InlineData("InternalField", VisibilityKind.Assembly)]
    [InlineData("privateField", VisibilityKind.Private)]
    [InlineData("ProtectedField", VisibilityKind.Family)]
    [InlineData("ProtectedInternalField", VisibilityKind.FamilyOrAssembly)]
    [InlineData("PrivateProtectedField", VisibilityKind.FamilyAndAssembly)]
    public void Field_Visibility_IsTheDeclaredAccessibility(string name, VisibilityKind expected)
    {
        var type = Assert.IsType<ClassDefinition>(fixture.Type($"{Flags}.Accessibility"));

        Assert.Equal(expected, Assert.Single(type.Fields, f => f.Name == name).Visibility);
    }

    [Fact]
    public void Field_OfAStruct_IsPublic()
    {
        var type = Assert.IsType<StructDefinition>(fixture.Type($"{Flags}.PublicStruct"));

        Assert.Equal(VisibilityKind.Public, Assert.Single(type.Fields, f => f.Name == "X").Visibility);
    }

    // An enum member is a public constant whichever the enum's own accessibility; value__ is not a constant.
    [Theory]
    [InlineData("PublicEnum", new[] { "First", "Second" })]
    [InlineData("InternalEnum", new[] { "Only" })]
    public void EnumConstant_Visibility_IsPublic(string enumName, string[] constants)
    {
        var type = Assert.IsType<EnumDefinition>(fixture.Type($"{Flags}.{enumName}"));

        Assert.Equal(constants, type.Constants.Select(c => c.Name));
        Assert.All(type.Constants, c => Assert.Equal(VisibilityKind.Public, c.Visibility));
    }

    // ---------------------------------------------------------------------------------------------------
    // Visibility: types, namespace and nested
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Accessibility", VisibilityKind.Public)]
    [InlineData("InternalType", VisibilityKind.Assembly)]
    [InlineData("PublicStruct", VisibilityKind.Public)]
    [InlineData("InternalStruct", VisibilityKind.Assembly)]
    [InlineData("IPublicInterface", VisibilityKind.Public)]
    [InlineData("IInternalInterface", VisibilityKind.Assembly)]
    [InlineData("PublicEnum", VisibilityKind.Public)]
    [InlineData("InternalEnum", VisibilityKind.Assembly)]
    public void NamespaceType_Visibility_IsPublicOrAssembly(string name, VisibilityKind expected)
    {
        Assert.Equal(expected, fixture.Type($"{Flags}.{name}").Visibility);
    }

    [Theory]
    [InlineData("PublicNested", VisibilityKind.Public)]
    [InlineData("PrivateNested", VisibilityKind.Private)]
    [InlineData("ProtectedNested", VisibilityKind.Family)]
    [InlineData("InternalNested", VisibilityKind.Assembly)]
    [InlineData("ProtectedInternalNested", VisibilityKind.FamilyOrAssembly)]
    [InlineData("PrivateProtectedNested", VisibilityKind.FamilyAndAssembly)]
    public void NestedType_Visibility_IsItsMemberAccessibility(string name, VisibilityKind expected)
    {
        var type = fixture.Type($"{Flags}.Accessibility.{name}");

        Assert.Equal(expected, type.Visibility);
        Assert.Equal($"{Flags}.Accessibility", CanonicalName.NodeId(ModelNames.Of((IBasicType)type.ContainingType)));
    }

    // Depth 2: each link of the chain carries its own accessibility.
    [Theory]
    [InlineData("PublicDeeper", VisibilityKind.Public)]
    [InlineData("PrivateDeeper", VisibilityKind.Private)]
    public void NestedType_AtDepthTwo_CarriesItsOwnAccessibility(string name, VisibilityKind expected)
    {
        var type = fixture.Type($"{Flags}.Accessibility.PublicNested.{name}");

        Assert.Equal(expected, type.Visibility);
        Assert.Equal(VisibilityKind.Public, type.ContainingType.Visibility);
        Assert.Equal(VisibilityKind.Public, type.ContainingType.ContainingType.Visibility);
        Assert.Null(type.ContainingType.ContainingType.ContainingType);
    }

    // No definition read from real metadata is left Unknown: the default is only for definitions built by hand. Covers
    // all seven implementers of ITypeMemberDefinition (classes, structs, interfaces, enums, methods, fields, constants),
    // compiler-generated ones (<Module>, <PrivateImplementationDetails>) included.
    [Fact]
    public void EveryDefinitionInTheFixture_HasAKnownVisibility()
    {
        var types = fixture.Index.TypeIds.SelectMany(fixture.Index.Types).Select(t => t.Definition).ToArray();
        var members = types.SelectMany<ITypeDefinition, ITypeMemberDefinition>(t => t switch
        {
            ClassDefinition c => [.. c.Methods, .. c.Fields],
            StructDefinition s => [.. s.Methods, .. s.Fields],
            InterfaceDefinition i => [.. i.Methods],
            EnumDefinition e => [.. e.Constants],
            _ => [],
        }).ToArray();

        Assert.Contains(types, t => t is ClassDefinition);
        Assert.Contains(types, t => t is StructDefinition);
        Assert.Contains(types, t => t is InterfaceDefinition);
        Assert.Contains(types, t => t is EnumDefinition);
        Assert.Contains(members, m => m is FieldDefinition);
        Assert.Contains(members, m => m is ConstantDefinition);
        Assert.Empty(types.Where(t => t.Visibility == VisibilityKind.Unknown).Select(t => t.Name));
        Assert.Empty(members.Where(m => m.Visibility == VisibilityKind.Unknown).Select(m => m.ToString()));
    }

    // ---------------------------------------------------------------------------------------------------
    // Classes: abstract and sealed
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("AbstractShape", true, false)]
    [InlineData("OpenShape", false, false)]
    [InlineData("SealedShape", false, true)]
    [InlineData("StaticShape", true, true)]     // a C# static class is abstract sealed in metadata
    public void Class_IsAbstractAndIsSealed_AreTheMetadataFlags(string name, bool isAbstract, bool isSealed)
    {
        var type = Assert.IsType<ClassDefinition>(fixture.Type($"{Flags}.{name}"));

        Assert.Equal((isAbstract, isSealed), (type.IsAbstract, type.IsSealed));
    }

    // ---------------------------------------------------------------------------------------------------
    // Methods: sealed and new-slot
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("AbstractShape.Draw()", true, false, true)]       // abstract: a new slot
    [InlineData("AbstractShape.Resize()", true, false, true)]     // new virtual: a new slot
    [InlineData("AbstractShape.Plain()", false, false, false)]    // not virtual at all
    [InlineData("OpenShape.Draw()", true, false, false)]          // override: reuses the slot
    [InlineData("OpenShape.Resize()", true, true, false)]         // sealed override: final, reuses the slot
    public void Method_IsSealedAndIsNewSlot_AreTheVtableFlags(string method, bool isVirtual, bool isSealed, bool isNewSlot)
    {
        var definition = fixture.Method($"{Flags}.{method}").Definition;

        Assert.Equal((isVirtual, isSealed, isNewSlot), (definition.IsVirtual, definition.IsSealed, definition.IsNewSlot));
    }

    // ---------------------------------------------------------------------------------------------------
    // Methods: P/Invoke vs internalcall
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("GetTickCount()", true, true)]
    [InlineData("InternalCall()", true, false)]   // external, but not a P/Invoke
    [InlineData("Managed()", false, false)]
    public void Method_IsPlatformInvoke_SeparatesAPInvokeFromAnInternalCall(string method, bool isExternal, bool isPlatformInvoke)
    {
        var definition = fixture.Method($"{Flags}.Externs.{method}").Definition;

        Assert.Equal((isExternal, isPlatformInvoke), (definition.IsExternal, definition.IsPlatformInvoke));
    }
    #endregion

    #region Fields
    private const string Flags = "RootFixture.Flags";

    private readonly RootFixtureModel fixture;
    #endregion
}
