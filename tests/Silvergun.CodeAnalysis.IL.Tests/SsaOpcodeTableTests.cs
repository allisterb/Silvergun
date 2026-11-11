namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Cilica.AsmIO;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// The opcode table of the SSA adapter (docs/agent/tasks/ssa-adapter.md S2): CCI's <see cref="OperationCode"/>s are
/// ECMA-335's encodings, so each maps to the Cilica <see cref="ILCode"/> of the same value; CCI's array
/// pseudo-operations map back to the <c>call</c>/<c>newobj</c> of the MD-array intrinsic they replaced.
/// </summary>
public sealed class SsaOpcodeTableTests
{
    #region Methods
    [Fact]
    public void OpCode_EveryEcmaOperationCode_MapsToTheILCodeOfTheSameValue()
    {
        var ecma = Enum.GetValues<OperationCode>().Where(c => (int)c <= LastEcma).ToArray();

        Assert.True(ecma.Length > 200, $"Only {ecma.Length} ECMA operation codes found: is the enum read right?");
        foreach (var code in ecma)
        {
            var mapped = CciModuleSource.OpCode(code);
            Assert.True(mapped == (ILCode)(ushort)code, $"{code} (0x{(int)code:X4}) maps to {mapped?.ToString() ?? "null"}");
        }
    }

    /// <summary>The other direction: no Cilica opcode (prefix bytes aside) lacks a CCI operation code that reaches it.</summary>
    [Fact]
    public void OpCode_EveryILCodeButThePrefixBytes_IsReachedFromCci()
    {
        foreach (var code in Enum.GetValues<ILCode>().Where(c => c is < ILCode.Prefix7 or > ILCode.Prefixref))
        {
            Assert.True(Enum.IsDefined((OperationCode)(int)code), $"{code} (0x{(int)code:X4}) has no CCI operation code");
            Assert.Equal(code, CciModuleSource.OpCode((OperationCode)(int)code));
        }
    }

    [Theory]
    [InlineData(0xF8)]
    [InlineData(0xF9)]
    [InlineData(0xFA)]
    [InlineData(0xFB)]
    [InlineData(0xFC)]
    [InlineData(0xFD)]
    [InlineData(0xFE)]
    [InlineData(0xFF)]
    public void OpCode_APrefixByte_IsNull(int value) => Assert.Null(CciModuleSource.OpCode((OperationCode)value));

    [Theory]
    [InlineData(0x24)]      // unused one-byte slots
    [InlineData(0xA6)]
    [InlineData(0xE1)]
    [InlineData(0xFE08)]    // unused two-byte slots
    [InlineData(0xFE10)]
    [InlineData(0xFE1B)]
    [InlineData(0xFEFF)]
    [InlineData(0x10000)]   // out of range either way
    [InlineData(-1)]
    public void OpCode_AnUndefinedValue_IsNull(int value) => Assert.Null(CciModuleSource.OpCode((OperationCode)value));

    /// <summary>CCI's pseudo-operations sit just past the ECMA range; they are not opcodes, and only <see cref="CciModuleSource.ArrayOperation"/> maps them.</summary>
    [Theory]
    [InlineData(OperationCode.Array_Create)]
    [InlineData(OperationCode.Array_Create_WithLowerBound)]
    [InlineData(OperationCode.Array_Get)]
    [InlineData(OperationCode.Array_Set)]
    [InlineData(OperationCode.Array_Addr)]
    [InlineData(OperationCode.Invalid)]
    public void OpCode_ACciPseudoOperation_IsNull(OperationCode code) => Assert.Null(CciModuleSource.OpCode(code));

    [Theory]
    [InlineData(OperationCode.Array_Create, ILCode.Newobj, MDArrayMethod.OpKind.SizeCtor)]
    [InlineData(OperationCode.Array_Create_WithLowerBound, ILCode.Newobj, MDArrayMethod.OpKind.RangeCtor)]
    [InlineData(OperationCode.Array_Get, ILCode.Call, MDArrayMethod.OpKind.Get)]
    [InlineData(OperationCode.Array_Set, ILCode.Call, MDArrayMethod.OpKind.Set)]
    [InlineData(OperationCode.Array_Addr, ILCode.Call, MDArrayMethod.OpKind.Address)]
    public void ArrayOperation_MapsEachPseudoOperation_ToItsIntrinsic(OperationCode code, ILCode expected, MDArrayMethod.OpKind kind) =>
        Assert.Equal((expected, kind), CciModuleSource.ArrayOperation(code));

    [Fact]
    public void ArrayOperation_OfEveryOtherOperationCode_IsNull()
    {
        var pseudo = new[]
        {
            OperationCode.Array_Create, OperationCode.Array_Create_WithLowerBound, OperationCode.Array_Get, OperationCode.Array_Set, OperationCode.Array_Addr,
        };
        foreach (var code in Enum.GetValues<OperationCode>().Except(pseudo))
            Assert.True(CciModuleSource.ArrayOperation(code) is null, $"{code} maps to an array intrinsic");
    }
    #endregion

    #region Fields
    // readonly. (0xFE1E) is the last ECMA-335 opcode; CCI numbers its pseudo-operations from 0xFE1F on.
    private const int LastEcma = 0xFE1E;
    #endregion
}
