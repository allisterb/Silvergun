namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Reflection;

using Model.Types;

using Xunit;

using Cci = Microsoft.Cci;

/// <summary>
/// The fork's CCI-to-Model accessibility mapping, <c>CCIProvider.TypeExtractor.ExtractVisibility(Cci.TypeMemberVisibility)</c>
/// (reachability R1, S1.1), over every CCI value, including the two that C# never emits: <c>Other</c>
/// (compiler-controlled, privatescope) maps to <see cref="VisibilityKind.Private"/>, and <c>Default</c> to
/// <see cref="VisibilityKind.Unknown"/>.
/// <para>
/// <c>TypeExtractor</c> is <c>internal</c> to CCIProvider, which grants no <c>InternalsVisibleTo</c>, so the public
/// static method is reached by reflection. The CCI enum itself is public and referenced directly. A missing method
/// fails loudly, naming what it looked for.
/// </para>
/// </summary>
public sealed class CciVisibilityMappingTests
{
    #region Methods
    [Theory]
    [InlineData(Cci.TypeMemberVisibility.Public, VisibilityKind.Public)]
    [InlineData(Cci.TypeMemberVisibility.FamilyOrAssembly, VisibilityKind.FamilyOrAssembly)]
    [InlineData(Cci.TypeMemberVisibility.Family, VisibilityKind.Family)]
    [InlineData(Cci.TypeMemberVisibility.Assembly, VisibilityKind.Assembly)]
    [InlineData(Cci.TypeMemberVisibility.FamilyAndAssembly, VisibilityKind.FamilyAndAssembly)]
    [InlineData(Cci.TypeMemberVisibility.Private, VisibilityKind.Private)]
    [InlineData(Cci.TypeMemberVisibility.Other, VisibilityKind.Private)]      // compiler-controlled: even less accessible
    [InlineData(Cci.TypeMemberVisibility.Default, VisibilityKind.Unknown)]    // unspecified
    public void ExtractVisibility_MapsEachCciValue(Cci.TypeMemberVisibility visibility, VisibilityKind expected)
    {
        Assert.Equal(expected, Extract(visibility));
    }

    // Every named CCI value is covered above (Mask aside), so a value added to CCI later is caught here.
    [Fact]
    public void ExtractVisibility_TheTheoryCoversEveryNamedCciValue()
    {
        Assert.Equal(9, Enum.GetValues<Cci.TypeMemberVisibility>().Length);   // the eight values above, plus Mask
    }

    // The mapping masks with TypeMemberVisibility.Mask, so flag bits stored above it do not change the answer.
    [Theory]
    [InlineData(0x10 | (int)Cci.TypeMemberVisibility.Public, VisibilityKind.Public)]
    [InlineData(0x30 | (int)Cci.TypeMemberVisibility.Family, VisibilityKind.Family)]
    public void ExtractVisibility_IgnoresBitsAboveTheMask(int raw, VisibilityKind expected)
    {
        Assert.Equal(expected, Extract((Cci.TypeMemberVisibility)raw));
    }

    // A value inside the mask that names no visibility (hostile or future metadata, or Mask itself) is Unknown, never a guess.
    [Theory]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData((int)Cci.TypeMemberVisibility.Mask)]
    public void ExtractVisibility_AnUnnamedValue_IsUnknown(int raw)
    {
        Assert.Equal(VisibilityKind.Unknown, Extract((Cci.TypeMemberVisibility)raw));
    }

    private static VisibilityKind Extract(Cci.TypeMemberVisibility visibility) =>
        (VisibilityKind)extract.Value.Invoke(null, [visibility])!;
    #endregion

    #region Fields
    private static readonly Lazy<MethodInfo> extract = new(() =>
    {
        var type = typeof(CCIProvider.Loader).Assembly.GetType("CCIProvider.TypeExtractor", throwOnError: true)!;
        return type.GetMethod("ExtractVisibility", BindingFlags.Public | BindingFlags.Static, [typeof(Cci.TypeMemberVisibility)])
            ?? throw new InvalidOperationException("CCIProvider.TypeExtractor.ExtractVisibility(Microsoft.Cci.TypeMemberVisibility) was not found.");
    });
    #endregion
}
