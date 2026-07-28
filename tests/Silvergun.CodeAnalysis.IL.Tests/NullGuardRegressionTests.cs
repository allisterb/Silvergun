namespace Silvergun.CodeAnalysis.IL.Tests;

using Model.ThreeAddressCode.Values;
using Model.Types;

using Xunit;

/// <summary>
/// Regression coverage for five null-guards in <c>ext/analysis-net</c> — see
/// <c>docs/agent/measurements/dereference-type-nre-fix.md</c> and
/// <c>docs/agent/measurements/typeinference-nullguard-fixes.md</c>. Types on stack temporaries are assigned
/// <b>lazily</b> by <c>TypeInferenceAnalysis</c>'s fixed-point pass, so a variable with <c>Type == null</c> is a
/// normal "not yet known" state, not an error. Each guarded getter/helper below used to throw
/// <c>NullReferenceException</c> unconditionally on that state; each now returns <c>null</c> instead —
/// deliberately <b>not</b> <c>PlatformTypes.Unknown</c>, which would permanently pin a wrong answer, since
/// nothing in the fixed point overwrites an already-non-null <c>Type</c> (see the fix comments in
/// <c>Operands.cs</c>/<c>TypeHelper.cs</c> for the full self-healing-retry rationale).
/// <para>
/// <b>None of these sites are reachable from any <c>src/</c> path today</b> — <c>TypeInferenceAnalysis</c> isn't
/// wired into Silvergun's pipeline yet. These tests exist purely so a future upstream merge into
/// <c>ext/analysis-net</c> can't silently revert a one-character <c>?.</c>/early-return without a red test
/// catching it. Ordinary catchable exceptions from <c>Model</c>/<c>Backend</c> types — not the CCI
/// <c>FailFast</c> hazard (ADR-0021) — so these run in-process, unlike
/// <see cref="TypedReferencePointerRegressionTests"/>.
/// </para>
/// <para>
/// Every guard is exercised in both directions: the null case (proving the getter/helper no longer throws) and
/// a positive control (proving the guard didn't turn into an unconditional null return that would still pass a
/// null-only test).
/// </para>
/// </summary>
public sealed class NullGuardRegressionTests
{
    #region Dereference.Type (Model/ThreeAddressCode/Operands.cs)
    [Fact]
    public void DereferenceType_WhenReferenceTypeIsNull_ReturnsNull()
    {
        var reference = new TemporalVariable("$t", 0); // Type left unset (null) - the "not yet known" state.
        var dereference = new Dereference(reference);

        Assert.Null(dereference.Type);
    }

    [Fact]
    public void DereferenceType_WhenReferenceIsPointerType_ReturnsTargetType()
    {
        var reference = new TemporalVariable("$t", 0) { Type = new PointerType(PlatformTypes.Int32) };
        var dereference = new Dereference(reference);

        Assert.Same(PlatformTypes.Int32, dereference.Type);
    }
    #endregion

    #region ArrayElementAccess.Type (Model/ThreeAddressCode/Operands.cs)
    [Fact]
    public void ArrayElementAccessType_WhenArrayTypeIsNull_ReturnsNull()
    {
        var array = new TemporalVariable("$t", 0); // Type left unset (null).
        var index = new TemporalVariable("$t", 1) { Type = PlatformTypes.Int32 };
        var access = new ArrayElementAccess(array, index);

        Assert.Null(access.Type);
    }

    [Fact]
    public void ArrayElementAccessType_WhenArrayIsArrayType_ReturnsElementsType()
    {
        var array = new TemporalVariable("$t", 0) { Type = new ArrayType(PlatformTypes.String) };
        var index = new TemporalVariable("$t", 1) { Type = PlatformTypes.Int32 };
        var access = new ArrayElementAccess(array, index);

        Assert.Same(PlatformTypes.String, access.Type);
    }
    #endregion

    #region TypeHelper.BinaryLogicalOperationType (Model/Types/TypeHelper.cs)
    [Fact]
    public void BinaryLogicalOperationType_WhenLeftIsNull_ReturnsNull()
    {
        Assert.Null(TypeHelper.BinaryLogicalOperationType(null, PlatformTypes.Boolean));
    }

    [Fact]
    public void BinaryLogicalOperationType_WhenRightIsNull_ReturnsNull()
    {
        Assert.Null(TypeHelper.BinaryLogicalOperationType(PlatformTypes.Boolean, null));
    }

    [Fact]
    public void BinaryLogicalOperationType_WhenBothOperandsAreBoolean_ReturnsBoolean()
    {
        var result = TypeHelper.BinaryLogicalOperationType(PlatformTypes.Boolean, PlatformTypes.Boolean);

        Assert.Same(PlatformTypes.Boolean, result);
    }
    #endregion

    #region TypeHelper.UnsignedEquivalent (Model/Types/TypeHelper.cs)
    [Fact]
    public void UnsignedEquivalent_WhenTypeIsNull_ReturnsNull()
    {
        Assert.Null(TypeHelper.UnsignedEquivalent(null));
    }

    public static TheoryData<IType, IType> SignedToUnsignedPairs => new()
    {
        { PlatformTypes.Int8, PlatformTypes.UInt8 },
        { PlatformTypes.Int16, PlatformTypes.UInt16 },
        { PlatformTypes.Int32, PlatformTypes.UInt32 },
        { PlatformTypes.Int64, PlatformTypes.UInt64 },
        { PlatformTypes.IntPtr, PlatformTypes.UIntPtr },
    };

    [Theory]
    [MemberData(nameof(SignedToUnsignedPairs))]
    public void UnsignedEquivalent_ForSignedIntegerType_ReturnsUnsignedCounterpart(IType signed, IType unsigned)
    {
        var result = TypeHelper.UnsignedEquivalent(signed);

        Assert.Same(unsigned, result);
    }

    [Fact]
    public void UnsignedEquivalent_WhenTypeIsNonInteger_ReturnsSameTypeUnchanged()
    {
        // Boolean is neither a signed integer type nor null - the "otherwise return the given type" branch.
        var result = TypeHelper.UnsignedEquivalent(PlatformTypes.Boolean);

        Assert.Same(PlatformTypes.Boolean, result);
    }
    #endregion

    #region TypeHelper.BinarySignedNumericOperationType (Model/Types/TypeHelper.cs)
    [Fact]
    public void BinarySignedNumericOperationType_WhenLeftIsNull_ReturnsNull()
    {
        Assert.Null(TypeHelper.BinarySignedNumericOperationType(null, PlatformTypes.Int32));
    }

    [Fact]
    public void BinarySignedNumericOperationType_WhenRightIsNull_ReturnsNull()
    {
        Assert.Null(TypeHelper.BinarySignedNumericOperationType(PlatformTypes.Int32, null));
    }

    [Fact]
    public void BinarySignedNumericOperationType_WhenBothOperandsAreInt32_ReturnsInt32()
    {
        var result = TypeHelper.BinarySignedNumericOperationType(PlatformTypes.Int32, PlatformTypes.Int32);

        Assert.Same(PlatformTypes.Int32, result);
    }
    #endregion
}
