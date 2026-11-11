namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using Cilica.AsmIO;

using Xunit;

/// <summary>
/// The SSA adapter's body conversion, on real converted bodies (docs/agent/tasks/ssa-adapter.md S2): each method of
/// <see cref="SsaBodyFixture"/> is lifted, and the <see cref="ILMethodBody"/> the adapter built from CCI's operations is
/// read back through <see cref="MethodDef.ILBody"/>. Covers operand mapping per operand type (argument and local
/// indexes, absolute branch and switch targets, constants, strings, <c>newarr</c>'s element type, <c>calli</c>'s
/// signature, <c>ldtoken</c>, MD-array intrinsics, prefix operands), locals, and exception regions. The emitted IL, or
/// System.Reflection.Metadata's reading of the same file, is the oracle; never the adapter's own reading.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaBodyConversionTests : IClassFixture<SsaBodyFixture>
{
    #region Constructors
    public SsaBodyConversionTests(SsaBodyFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- Every body --------------------------------------------------------------------------------------------------

    /// <summary>
    /// Every method of the fixture lifts, and its instructions sit at the metadata's offsets: contiguous from 0, and as
    /// long in total as the body System.Reflection.Metadata reads (a wrong operand size, e.g. a switch table, would shift
    /// every offset after it and break the join to <c>MethodGraph</c> by offset).
    /// </summary>
    [Fact]
    public void EveryOperandFixtureMethod_Lifts_WithInstructionsAtTheMetadataOffsets()
    {
        var lengths = IlLengths(fixture.OperandsPath);
        var outcomes = fixture.Lifted.Outcomes.Where(o => o.AssemblyPath == fixture.OperandsPath).ToArray();

        Assert.Equal(lengths.Keys.Order(), outcomes.Select(o => o.Method.MethodName).Order());
        foreach (var outcome in outcomes)
        {
            SsaLifted.AssertLifted(outcome);
            Assert.Equal(lengths[outcome.Method.MethodName], outcome.Body!.Definition.ILBody!.GetCodeSize());
        }
    }

    // ---- Arguments and locals ----------------------------------------------------------------------------------------

    [Fact]
    public void Arguments_OfAStaticMethod_AreParameterIndexes_FromZero()
    {
        var body = fixture.Lifted.Il("Ops", "StaticArgs");

        Assert.Equal([1], Ints(body, ILCode.Ldarg_S));
        Assert.Equal([0], Ints(body, ILCode.Starg_S));
        Assert.Equal([2], Ints(body, ILCode.Ldarga_S));
        Assert.Equal([0], Ints(body, ILCode.Ldarg));
        Assert.Equal([1], Ints(body, ILCode.Starg));
        Assert.Equal([1], Ints(body, ILCode.Ldarga));
    }

    [Fact]
    public void Arguments_OfAnInstanceMethod_CountTheInstanceAsZero()
    {
        var body = fixture.Lifted.Il("Ops", "InstanceArgs");

        Assert.Equal([0, 2], Ints(body, ILCode.Ldarg_S));
        Assert.Equal([1], Ints(body, ILCode.Starg_S));
        Assert.Equal([1], Ints(body, ILCode.Ldarga_S));
        Assert.Equal([2], Ints(body, ILCode.Ldarg));
    }

    [Fact]
    public void Locals_AreIndexes_InShortAndLongForms()
    {
        var body = fixture.Lifted.Il("Ops", "LocalIndexes");

        Assert.Equal([1], Ints(body, ILCode.Stloc_S));
        Assert.Equal([0], Ints(body, ILCode.Ldloca_S));
        Assert.Equal([1], Ints(body, ILCode.Ldloc_S));
        Assert.Equal([0], Ints(body, ILCode.Ldloc));
        Assert.Equal([0], Ints(body, ILCode.Stloc));
        Assert.Equal([1], Ints(body, ILCode.Ldloca));
        Assert.Equal([0, 1], body.Locals.Select(l => l.Index));
        Assert.All(body.Locals, l => Assert.Same(PrimType.Int32, l.Type));
    }

    // ---- Branches ----------------------------------------------------------------------------------------------------

    [Fact]
    public void Branches_ShortAndLong_TargetAbsoluteOffsets()
    {
        var body = fixture.Lifted.Il("Ops", "Branches");

        Assert.Equal([OffsetOfConstant(body, 111)], Ints(body, ILCode.Brtrue_S));
        Assert.Equal([OffsetOfConstant(body, 222)], Ints(body, ILCode.Br));
    }

    [Fact]
    public void Branches_Backward_TargetTheAbsoluteOffsetOfTheLoopHead()
    {
        var body = fixture.Lifted.Il("Ops", "Loop");
        var head = body.Instructions.SkipWhile(i => i.OpCode != ILCode.Pop).Skip(1).First();
        var branch = body.Instructions.Single(i => i.OpCode == ILCode.Brtrue_S);

        Assert.Equal(head.Offset, branch.Operand);
        Assert.True(head.Offset is > 0 && head.Offset < branch.Offset, $"Loop head IL_{head.Offset:X4}, branch IL_{branch.Offset:X4}");
    }

    [Fact]
    public void Switch_TargetsAreAbsoluteOffsets_InTableOrder()
    {
        var body = fixture.Lifted.Il("Ops", "Switch");

        var table = Assert.IsType<int[]>(body.Instructions.Single(i => i.OpCode == ILCode.Switch).Operand);

        Assert.Equal([OffsetOfConstant(body, 100), OffsetOfConstant(body, 101), OffsetOfConstant(body, 102)], table);
    }

    // ---- Constants and strings ---------------------------------------------------------------------------------------

    [Fact]
    public void Constants_KeepTheirValues_AndTheirClrTypes()
    {
        var body = fixture.Lifted.Il("Ops", "Constants");

        Assert.Null(body.Instructions.Single(i => i.OpCode == ILCode.Ldc_I4_M1).Operand);
        Assert.Equal(-5, Assert.IsType<int>(Single(body, ILCode.Ldc_I4_S)));
        Assert.Equal(123456, Assert.IsType<int>(Single(body, ILCode.Ldc_I4)));
        Assert.Equal(1.5f, Assert.IsType<float>(Single(body, ILCode.Ldc_R4)));
        Assert.Equal(2.25, Assert.IsType<double>(Single(body, ILCode.Ldc_R8)));
        Assert.Equal(0x1_0000_0000L, Assert.IsType<long>(Single(body, ILCode.Ldc_I8)));
    }

    [Fact]
    public void Ldstr_IsTheString() =>
        Assert.Equal("silvergun-ssa", Single(fixture.Lifted.Il("Ops", "Str"), ILCode.Ldstr));

    // ---- Types, signatures and tokens --------------------------------------------------------------------------------

    /// <summary>CCI hands <c>newarr</c> the array type; the encoding, and Cilica, carry the ELEMENT type.</summary>
    [Fact]
    public void Newarr_IsTheElementType_NotTheArrayType()
    {
        var operands = Operands(fixture.Lifted.Il("Ops", "NewArrays"), ILCode.Newarr);

        Assert.Equal(3, operands.Count);
        Assert.Same(PrimType.Int32, operands[0]);
        Assert.Same(PrimType.String, operands[1]);
        var ops = Assert.IsType<TypeDef>(operands[2]);
        Assert.Equal(("Ssa", "Ops"), (ops.Namespace, ops.Name));
    }

    [Fact]
    public void Calli_IsAFunctionPointerType_OfTheCallSiteSignature()
    {
        var body = fixture.Lifted.Il("Ops", "Calli");

        var pointer = Assert.IsType<FuncPtrType>(Single(body, ILCode.Calli));
        Assert.Same(PrimType.Int32, pointer.Signature.ReturnType.Type);
        Assert.Same(PrimType.Int32, Assert.Single(pointer.Signature.ParamTypes).Type);
        Assert.Equal("Target", Assert.IsType<MethodDef>(Single(body, ILCode.Ldftn)).Name);
    }

    [Fact]
    public void Ldtoken_OfATypeAMethodAndAField_AreThoseEntities()
    {
        var operands = Operands(fixture.Lifted.Il("Ops", "Tokens"), ILCode.Ldtoken);

        Assert.Equal(3, operands.Count);
        Assert.Same(PrimType.Int32, operands[0]);
        var method = Assert.IsType<MethodDef>(operands[1]);
        Assert.Equal(("Target", "Ops"), (method.Name, method.DeclaringType.Name));
        var field = Assert.IsType<FieldDef>(operands[2]);
        Assert.Equal(("Field", "Ops", true), (field.Name, field.DeclaringType.Name, field.IsStatic));
    }

    /// <summary>csc's MD-array accessors, which CCI turns into its Array_* pseudo-operations, come back as the intrinsics.</summary>
    [Fact]
    public void MultiDimensionalArrayAccessors_FromCsc_AreMDArrayMethods()
    {
        var body = fixture.Lifted.Il("MultiDimArrayOps", "CopiesMatrixCellsAndReadsAFile");

        var intrinsics = body.Instructions.Where(i => i.Operand is MDArrayMethod).Select(i => (i.OpCode, ((MDArrayMethod)i.Operand!).Kind)).ToArray();

        Assert.Contains((ILCode.Newobj, MDArrayMethod.OpKind.SizeCtor), intrinsics);
        Assert.Contains((ILCode.Call, MDArrayMethod.OpKind.Get), intrinsics);
        Assert.Contains((ILCode.Call, MDArrayMethod.OpKind.Set), intrinsics);
        Assert.Contains((ILCode.Call, MDArrayMethod.OpKind.Address), intrinsics);
        Assert.All(body.Instructions.Select(i => i.Operand).OfType<MDArrayMethod>(), m =>
        {
            Assert.Equal(2, m.DeclaringType.Rank);
            Assert.Same(PrimType.Int32, m.DeclaringType.ElemType);
        });
    }

    [Fact]
    public void MultiDimensionalArray_LowerBoundConstructor_IsTheRangeConstructor()
    {
        var created = Assert.IsType<MDArrayMethod>(Single(fixture.Lifted.Il("Ops", "RangeArray"), ILCode.Newobj));

        Assert.Equal(MDArrayMethod.OpKind.RangeCtor, created.Kind);
        Assert.Equal(2, created.DeclaringType.Rank);
    }

    // ---- Prefixes ----------------------------------------------------------------------------------------------------

    [Fact]
    public void Unaligned_ItsAlignmentIsAnInt() =>
        Assert.Equal(1, Assert.IsType<int>(Single(fixture.Lifted.Il("Ops", "Unaligned"), ILCode.Unaligned_)));

    [Fact]
    public void Volatile_IsKept_WithNoOperand()
    {
        var body = fixture.Lifted.Il("Ops", "Volatile");

        var prefix = body.Instructions.Single(i => i.OpCode == ILCode.Volatile_);
        Assert.Null(prefix.Operand);
        Assert.Equal(ILCode.Ldind_I4, body.Instructions.SkipWhile(i => i.OpCode != ILCode.Volatile_).ElementAt(1).OpCode);
    }

    /// <summary>CCI decodes <c>no.</c>'s operand as a flags enum; Cilica wants the byte as an int.</summary>
    [Fact]
    public void No_ItsCheckFlagsAreAnInt() =>
        Assert.Equal(2, Assert.IsType<int>(Single(fixture.Lifted.Il("Prefixes", "NoRangeCheck"), ILCode.No_)));

    // ---- Locals ------------------------------------------------------------------------------------------------------

    /// <summary>SSA must never promote a pinned slot, so the flag has to survive: C#'s <c>fixed</c> shape.</summary>
    [Fact]
    public void Locals_PinnedAndByref_AreKept()
    {
        var locals = fixture.Lifted.Il("Ops", "Pinned").Locals;

        Assert.Equal(3, locals.Length);
        Assert.Equal([0, 1, 2], locals.Select(l => l.Index));
        Assert.True(locals[0].IsPinned);
        Assert.Same(PrimType.Int32, Assert.IsType<ByrefType>(locals[0].Type).ElemType);
        Assert.False(locals[1].IsPinned);
        Assert.Same(PrimType.Int32, Assert.IsType<ByrefType>(locals[1].Type).ElemType);
        Assert.False(locals[2].IsPinned);
        Assert.Same(PrimType.Int32, Assert.IsType<PointerType>(locals[2].Type).ElemType);
    }

    [Fact]
    public void Locals_InitLocals_FollowsTheHeaderFlag()
    {
        Assert.False(fixture.Lifted.Il("Ops", "SkipsLocalsInit").InitLocals);
        Assert.True(fixture.Lifted.Il("Ops", "ZeroesLocals").InitLocals);
    }

    // ---- Exception regions -------------------------------------------------------------------------------------------

    /// <summary>Clause for clause as the metadata has them: kind, try and handler ranges, filter start, catch type.</summary>
    [Fact]
    public void ExceptionRegions_AreTheMetadatasClauses_InTheMetadatasOrder()
    {
        var expected = Regions(fixture.OperandsPath, "Regions");
        var clauses = fixture.Lifted.Il("Ops", "Regions").ExceptionClauses;

        Assert.Equal(
            expected,
            clauses.Select(c => (c.Kind, c.TryStart, c.TryEnd, c.HandlerStart, c.HandlerEnd, c.FilterStart, c.CatchType is { } t ? t.Namespace + "." + t.Name : null)));
    }

    /// <summary>ECMA-335's search order, which the importer assumes: a clause nested in another's try comes before it.</summary>
    [Fact]
    public void ExceptionRegions_AreInnermostFirst_WithEachKind()
    {
        var clauses = fixture.Lifted.Il("Ops", "Regions").ExceptionClauses;

        Assert.Equal([ExceptionRegionKind.Catch, ExceptionRegionKind.Filter, ExceptionRegionKind.Finally, ExceptionRegionKind.Fault], clauses.Select(c => c.Kind));
        var outer = clauses[2];
        Assert.All(clauses[..2], inner => Assert.True(inner.TryStart >= outer.TryStart && inner.TryEnd <= outer.TryEnd, "An inner try lies outside the outer one."));
        for (var i = 0; i < clauses.Length; i++)
        {
            for (var j = i + 1; j < clauses.Length; j++)
                Assert.False(clauses[i].TryStart <= clauses[j].TryStart && clauses[j].TryEnd <= clauses[i].TryEnd && (clauses[i].TryStart, clauses[i].TryEnd) != (clauses[j].TryStart, clauses[j].TryEnd),
                    $"Clause {i} encloses the later clause {j}.");
        }
        Assert.Equal(("System", "InvalidOperationException"), (clauses[0].CatchType!.Namespace, clauses[0].CatchType!.Name));
        Assert.True(clauses[1].FilterStart >= clauses[1].TryEnd && clauses[1].FilterStart < clauses[1].HandlerStart, $"Filter at IL_{clauses[1].FilterStart:X4}");
        Assert.All(clauses.Where(c => c.Kind != ExceptionRegionKind.Filter), c => Assert.Equal(-1, c.FilterStart));
        Assert.All(clauses.Where(c => c.Kind != ExceptionRegionKind.Catch), c => Assert.Null(c.CatchType));
    }

    // ---- Helpers -----------------------------------------------------------------------------------------------------

    private static List<object?> Operands(ILMethodBody body, ILCode code) =>
        body.Instructions.Where(i => i.OpCode == code).Select(i => i.Operand).ToList();

    // Index and target operands, each asserted to be an int (not, say, CCI's parameter object or a uint).
    private static List<int> Ints(ILMethodBody body, ILCode code) =>
        Operands(body, code).Select(o => Assert.IsType<int>(o)).ToList();

    private static object? Single(ILMethodBody body, ILCode code) => body.Instructions.Single(i => i.OpCode == code).Operand;

    // PersistedAssemblyBuilder writes a small ldc.i4 as ldc.i4.s, so either form marks the target.
    private static int OffsetOfConstant(ILMethodBody body, int value) =>
        body.Instructions.Single(i => i.OpCode is ILCode.Ldc_I4 or ILCode.Ldc_I4_S && i.Operand is int v && v == value).Offset;

    // The IL length of every method body of the file, by method name, read by System.Reflection.Metadata.
    private static Dictionary<string, int> IlLengths(string path)
    {
        using var pe = new PEReader(File.OpenRead(path));
        var reader = pe.GetMetadataReader();
        return reader.MethodDefinitions.Select(reader.GetMethodDefinition).Where(m => m.RelativeVirtualAddress != 0)
            .ToDictionary(m => reader.GetString(m.Name), m => pe.GetMethodBody(m.RelativeVirtualAddress).GetILBytes()!.Length);
    }

    // The exception regions of a method, as System.Reflection.Metadata reads them.
    private static List<(ExceptionRegionKind, int, int, int, int, int, string?)> Regions(string path, string method)
    {
        using var pe = new PEReader(File.OpenRead(path));
        var reader = pe.GetMetadataReader();
        var definition = reader.MethodDefinitions.Select(reader.GetMethodDefinition).Single(m => reader.GetString(m.Name) == method);
        return pe.GetMethodBody(definition.RelativeVirtualAddress).ExceptionRegions.Select(r =>
        (
            r.Kind, r.TryOffset, r.TryOffset + r.TryLength, r.HandlerOffset, r.HandlerOffset + r.HandlerLength, r.FilterOffset,
            r.CatchType.IsNil ? null
                : r.CatchType.Kind == HandleKind.TypeReference ? Name(reader, reader.GetTypeReference((TypeReferenceHandle)r.CatchType))
                : throw new InvalidOperationException("The fixture's catch type is expected to be a TypeRef.")
        )).ToList();
    }

    private static string Name(MetadataReader reader, TypeReference type) => reader.GetString(type.Namespace) + "." + reader.GetString(type.Name);
    #endregion

    #region Fields
    private readonly SsaBodyFixture fixture;
    #endregion
}
