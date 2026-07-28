namespace Silvergun.CodeAnalysis.IL.Tests;

using Model;
using Model.Types;

using Xunit;

/// <summary>
/// Regression coverage for the corlib-unification fix to <see cref="BasicType.Equals"/> in
/// <c>ext/analysis-net</c> — see <c>docs/agent/tasks/platformtypes-comparison-fix.md</c> and
/// <c>docs/agent/measurements/platformtypes-comparison-audit.md</c>.
/// <para>
/// <see cref="PlatformTypes"/> is pinned to assembly <c>"mscorlib"</c>, but modern IL stamps
/// <c>System.Void</c>/<c>System.Boolean</c>/etc. with the module's own corlib (<c>System.Runtime</c>,
/// <c>System.Private.CoreLib</c>, <c>netstandard</c>). <c>BasicType.Equals</c> now treats two
/// <see cref="IBasicType"/>s as equal when name, namespace, generic arity and generic arguments all match
/// <em>and</em> both <see cref="IBasicType.ContainingAssembly"/> values are known core libraries
/// (<c>CoreLibraryNames</c>) — not "ignore the assembly": a corlib type is never unified with a same-named type
/// from an arbitrary third-party assembly. These tests build <see cref="BasicType"/> instances directly (no CCI,
/// no host resolution needed — <c>Equals</c> never calls <c>ResolvedType</c>), so they run in-process like
/// <see cref="NullGuardRegressionTests"/>.
/// </para>
/// </summary>
public sealed class BasicTypeCoreLibraryEqualityTests
{
    #region Unification across known core-library pairings
    public static TheoryData<string, string> CoreLibraryPairs => new()
    {
        { "mscorlib", "System.Runtime" },
        { "System.Runtime", "System.Private.CoreLib" },
        { "netstandard", "mscorlib" },
        { "MSCORLIB", "System.Runtime" }, // case-insensitive: assembly-name binding is case-insensitive in .NET.
    };

    [Theory]
    [MemberData(nameof(CoreLibraryPairs))]
    public void Equals_SameShapeDifferentCoreLibraryAssembly_Unifies(string assemblyA, string assemblyB)
    {
        var a = MakeBasicType("Boolean", "System", assemblyA);
        var b = MakeBasicType("Boolean", "System", assemblyB);

        Assert.True(a.Equals(b));
        Assert.True(b.Equals(a)); // Equals is meant to be symmetric here; check both directions.
    }
    #endregion

    #region The boundary: a non-corlib assembly never unifies with a corlib type, in either direction
    // This is what stops the fix being "assembly-agnostic". A type named identically to a platform type, but
    // declared in an ordinary third-party assembly, must NOT be treated as the same type as the real platform
    // type — otherwise a hostile package could shadow System.Boolean/System.Object and silently match every
    // PlatformTypes comparison in the analyzer.
    [Theory]
    [InlineData("mscorlib")]
    [InlineData("System.Runtime")]
    [InlineData("System.Private.CoreLib")]
    [InlineData("netstandard")]
    public void Equals_SameShapeCoreLibraryVsOrdinaryThirdPartyAssembly_DoesNotUnify(string coreLibraryAssembly)
    {
        var coreLibraryType = MakeBasicType("Boolean", "System", coreLibraryAssembly);
        // A real, non-corlib assembly name from the audit's own corpus.
        var thirdPartyType = MakeBasicType("Boolean", "System", "SixLabors.ImageSharp");

        Assert.False(coreLibraryType.Equals(thirdPartyType));
        Assert.False(thirdPartyType.Equals(coreLibraryType)); // both directions.
    }
    #endregion

    #region Other discriminators still apply, even when both assemblies are corlibs
    // A suite that only proves unification would pass if Equals were made to return true too eagerly (e.g. by
    // dropping the name/namespace/arity checks for corlib pairs). These pin that it doesn't.
    [Fact]
    public void Equals_DifferentNameBothCoreLibraries_ReturnsFalse()
    {
        var a = MakeBasicType("Boolean", "System", "mscorlib");
        var b = MakeBasicType("Char", "System", "System.Runtime");

        Assert.False(a.Equals(b));
    }

    [Fact]
    public void Equals_DifferentNamespaceBothCoreLibraries_ReturnsFalse()
    {
        var a = MakeBasicType("Void", "System", "mscorlib");
        var b = MakeBasicType("Void", "System.SomethingElse", "System.Runtime");

        Assert.False(a.Equals(b));
    }

    [Fact]
    public void Equals_DifferentGenericParameterCountBothCoreLibraries_ReturnsFalse()
    {
        var a = MakeBasicType("ICollection", "System.Collections.Generic", "mscorlib", genericParameterCount: 1);
        var b = MakeBasicType("ICollection", "System.Collections.Generic", "System.Runtime", genericParameterCount: 2);

        Assert.False(a.Equals(b));
    }
    #endregion

    #region Generic arguments still recurse through corlib unification
    [Fact]
    public void Equals_GenericArgumentsUnifyAcrossCoreLibraries_ReturnsTrue()
    {
        // List<[mscorlib]String> vs List<[System.Runtime]String>: outer AND inner type both cross corlibs.
        var listOfMscorlibString = MakeGenericBasicType(
            "List", "System.Collections.Generic", "mscorlib", MakeBasicType("String", "System", "mscorlib"));
        var listOfRuntimeString = MakeGenericBasicType(
            "List", "System.Collections.Generic", "System.Runtime", MakeBasicType("String", "System", "System.Runtime"));

        Assert.True(listOfMscorlibString.Equals(listOfRuntimeString));
    }

    [Fact]
    public void Equals_DifferentGenericArgumentsEvenAcrossCoreLibraries_ReturnsFalse()
    {
        // List<[mscorlib]String> vs List<[System.Runtime]Int32>: outer type unifies, but the generic argument
        // itself genuinely differs (String vs Int32) - SequenceEqual over GenericArguments must still catch it.
        var listOfMscorlibString = MakeGenericBasicType(
            "List", "System.Collections.Generic", "mscorlib", MakeBasicType("String", "System", "mscorlib"));
        var listOfRuntimeInt32 = MakeGenericBasicType(
            "List", "System.Collections.Generic", "System.Runtime", MakeBasicType("Int32", "System", "System.Runtime"));

        Assert.False(listOfMscorlibString.Equals(listOfRuntimeInt32));
    }
    #endregion

    #region The accepted residual: name-only assembly identity is spoofable (known limitation, not a bug)
    [Fact]
    public void Equals_AssemblyNamedMscorlibButNotTheRealOne_IsAcceptedKnownLimitationNotABug()
    {
        // IAssemblyReference (Model/Assembly.cs) has name-only identity: no public key token, no version. So
        // an assembly that simply CALLS itself "mscorlib" while declaring a hostile type of the same
        // name+namespace is indistinguishable, at this layer, from the genuine platform type -- and is treated
        // as a match. This is NOT introduced by the corlib-unification fix: BasicType.Equals's first branch,
        // `ContainingAssembly.Equals(other.ContainingAssembly)`, was always name-only, so this residual predates
        // the fix and is merely carried forward (see CoreLibraryNames' own header comment). Pinned here,
        // explicitly and by name, so it stays visible: if IAssemblyReference ever grows strong identity (public
        // key token/version), this test is exactly the one that should start failing, and whoever changes it
        // should update this comment rather than delete the test (mirrors the documented-residual style of the
        // canary test in CapabilityShapesAcrossTfmsTests.cs).
        var genuinePlatformBoolean = MakeBasicType("Boolean", "System", "mscorlib");
        var hostileTypeInAnAssemblyThatClaimsToBeMscorlib = MakeBasicType("Boolean", "System", "mscorlib");

        Assert.True(genuinePlatformBoolean.Equals(hostileTypeInAnAssemblyThatClaimsToBeMscorlib));
    }
    #endregion

    #region Helpers
    private static BasicType MakeBasicType(string name, string containingNamespace, string assemblyName, int genericParameterCount = 0) =>
        new(name, TypeKind.ValueType)
        {
            ContainingAssembly = new AssemblyReference(assemblyName),
            ContainingNamespace = containingNamespace,
            GenericParameterCount = genericParameterCount,
        };

    private static BasicType MakeGenericBasicType(string name, string containingNamespace, string assemblyName, params IType[] genericArguments)
    {
        var type = MakeBasicType(name, containingNamespace, assemblyName, genericArguments.Length);
        foreach (var argument in genericArguments)
        {
            type.GenericArguments.Add(argument);
        }

        return type;
    }
    #endregion
}
