namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;

using Cilica.AsmIO;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

/// <summary>Method bodies: CCI operations to Cilica IL instructions, operands to the universe's entities.</summary>
internal sealed partial class CciModuleSource
{
    #region Methods
    /// <summary>
    /// The opcode Cilica decodes for a CCI operation code, or null for one it cannot. CCI's codes are ECMA-335's encodings,
    /// except its array pseudo-operations, which <see cref="ArrayOperation"/> maps back.
    /// </summary>
    internal static ILCode? OpCode(OperationCode code) =>
        (int)code is >= 0 and <= 0xFFFF && Enum.IsDefined((ILCode)(ushort)code) && (ushort)code is < (ushort)ILCode.Prefix7 or > (ushort)ILCode.Prefixref
            ? (ILCode)(ushort)code
            : null;

    /// <summary>The instruction behind a CCI array pseudo-operation: the MD-array intrinsic it calls, or null if it is not one.</summary>
    internal static (ILCode Code, MDArrayMethod.OpKind Kind)? ArrayOperation(OperationCode code) => code switch
    {
        OperationCode.Array_Create => (ILCode.Newobj, MDArrayMethod.OpKind.SizeCtor),
        OperationCode.Array_Create_WithLowerBound => (ILCode.Newobj, MDArrayMethod.OpKind.RangeCtor),
        // CCI folds call and callvirt alike into these; both encode in five bytes, and Cilica imports the two the same
        // way for the runtime-provided accessors.
        OperationCode.Array_Get => (ILCode.Call, MDArrayMethod.OpKind.Get),
        OperationCode.Array_Set => (ILCode.Call, MDArrayMethod.OpKind.Set),
        OperationCode.Array_Addr => (ILCode.Call, MDArrayMethod.OpKind.Address),
        _ => null,
    };

    private ILMethodBody? ConvertBody(IMethodDefinition cci)
    {
        var read = AssemblyAnalyzer.TryReadBody(cci);
        if (read.IsUnreadable)
            throw new SsaAdapterException("Its body could not be read: " + read.Error, kind: SsaFailureKind.Unreadable);
        if (read.Body is not { } body)
            return null;
        var bounds = universe.Bounds;

        var cciLocals = body.LocalVariables.ToArray();
        var localIndex = new Dictionary<ILocalDefinition, int>(ReferenceEqualityComparer.Instance);
        for (var i = 0; i < cciLocals.Length; i++)
            localIndex.TryAdd(cciLocals[i], i);
        var locals = cciLocals.Select((l, i) => new ILVariable(LocalType(l), i, l.IsPinned)).ToArray();

        var instructions = new List<ILInstruction>();
        foreach (var operation in body.Operations)
        {
            if (instructions.Count >= bounds.MaxInstructions)
                throw new SsaAdapterException($"More than {bounds.MaxInstructions} instructions", kind: SsaFailureKind.Bounds);
            instructions.Add(Convert(operation, cci, localIndex));
        }

        var clauses = new List<ExceptionClause>();
        // Kept in the metadata's order: ECMA-335 makes it the search order (innermost first), and the importer relies on it.
        foreach (var region in body.OperationExceptionInformation)
        {
            if (clauses.Count >= bounds.MaxExceptionClauses)
                throw new SsaAdapterException($"More than {bounds.MaxExceptionClauses} exception clauses", kind: SsaFailureKind.Bounds);
            clauses.Add(Clause(region));
        }

        return new ILMethodBody
        {
            Instructions = instructions.ToArray(),
            Locals = locals,
            ExceptionClauses = [.. clauses],
            MaxStack = body.MaxStack,
            InitLocals = body.LocalsAreZeroed,
        };
    }

    private ILInstruction Convert(IOperation operation, IMethodDefinition owner, Dictionary<ILocalDefinition, int> locals)
    {
        var offset = checked((int)operation.Offset);
        try
        {
            if (ArrayOperation(operation.OperationCode) is var (arrayCode, kind))
            {
                var array = MapType(operation.Value as IArrayTypeReference, default, 0) as MDArrayType
                    ?? throw new SsaAdapterException("An array accessor on a single-dimensional array");
                return new ILInstruction(arrayCode, array.Methods[(int)kind]) { Offset = offset };
            }
            var code = OpCode(operation.OperationCode) ?? throw new SsaAdapterException($"Unknown opcode 0x{(int)operation.OperationCode:X4}");
            return new ILInstruction(code, Operand(code, operation.Value, owner, locals)) { Offset = offset };
        }
        catch (Exception ex) when (ex is InvalidCastException or NullReferenceException or OverflowException or IndexOutOfRangeException)
        {
            throw new SsaAdapterException($"The instruction at IL_{offset:X4} has an operand that cannot be read", ex);
        }
    }

    private object? Operand(ILCode code, object? value, IMethodDefinition owner, Dictionary<ILocalDefinition, int> locals) => code.GetOperandType() switch
    {
        ILOperandType.None => null,
        // ldc.i4.s and ldc.i4 (int), unaligned. (byte) and no. (a byte enum) all decode to int.
        ILOperandType.ShortI or ILOperandType.I => System.Convert.ToInt32(value),
        ILOperandType.I8 => (long)value!,
        ILOperandType.ShortR => (float)value!,
        ILOperandType.R => (double)value!,
        ILOperandType.ShortBrTarget or ILOperandType.BrTarget => checked((int)(uint)value!),
        ILOperandType.Switch => ((uint[])value!).Select(t => checked((int)t)).ToArray(),
        ILOperandType.ShortVar or ILOperandType.Var => code is ILCode.Ldarg_S or ILCode.Ldarga_S or ILCode.Starg_S or ILCode.Ldarg or ILCode.Ldarga or ILCode.Starg
            ? ArgumentIndex(value, owner)
            : value is ILocalDefinition local && locals.TryGetValue(local, out var index) ? index
            : throw new SsaAdapterException("A local variable index out of range"),
        ILOperandType.String => (string)value!,
        ILOperandType.Method => MapMethod((IMethodReference)value!, 0),
        ILOperandType.Field => MapField((IFieldReference)value!, code is ILCode.Ldsfld or ILCode.Stsfld or ILCode.Ldsflda, 0),
        // CCI hands newarr the array type; Cilica, like the encoding, the element type.
        ILOperandType.Type => code == ILCode.Newarr ? MapType(((IArrayTypeReference)value!).ElementType, default, 0) : MapType((ITypeReference)value!, default, 0),
        ILOperandType.Tok => value switch
        {
            IMethodReference method => MapMethod(method, 0),
            IFieldReference field => MapField(field, null, 0),
            ITypeReference type => MapType(type, default, 0),
            _ => throw new SsaAdapterException("An ldtoken operand that is not a type, method or field"),
        },
        ILOperandType.Sig => value is IFunctionPointerTypeReference function
            ? new FuncPtrType(MapSignature(function, function.ExtraArgumentTypes, 0, default, 0))
            : throw new SsaAdapterException("A calli signature that cannot be read"),
        var other => throw new SsaAdapterException($"An operand type the adapter does not map ({other})"),
    };

    // CCI hands an argument operand as its parameter definition, and the instance argument as null.
    private static int ArgumentIndex(object? value, IMethodDefinition owner) => value switch
    {
        null when !owner.IsStatic => 0,
        IParameterDefinition parameter when parameter is not Dummy => parameter.Index + (owner.IsStatic ? 0 : 1),
        _ => throw new SsaAdapterException("An argument index out of range"),
    };

    // As Cilica's decoder: a local's leading modifiers are dropped, a by-ref local keeps its element's.
    private TypeDesc LocalType(ILocalDefinition local)
    {
        if (local is Dummy)
            throw new SsaAdapterException("An unreadable local variable");
        if (local.IsReference)
        {
            var (element, modifiers) = MapElement(local.Type, default, 0);
            return modifiers.IsDefaultOrEmpty ? element.CreateByref() : new ByrefType(element, modifiers);
        }
        return MapType(local.Type is IModifiedTypeReference modified ? modified.UnmodifiedType : local.Type, default, 0);
    }

    private ExceptionClause Clause(IOperationExceptionInformation region)
    {
        var kind = region.HandlerKind switch
        {
            HandlerKind.Catch => ExceptionRegionKind.Catch,
            HandlerKind.Filter => ExceptionRegionKind.Filter,
            HandlerKind.Finally => ExceptionRegionKind.Finally,
            HandlerKind.Fault => ExceptionRegionKind.Fault,
            _ => throw new SsaAdapterException("An exception clause of an unknown kind"),
        };
        return new ExceptionClause
        {
            Kind = kind,
            CatchType = kind == ExceptionRegionKind.Catch ? MapType(region.ExceptionType, default, 0) : null,
            TryStart = checked((int)region.TryStartOffset),
            TryEnd = checked((int)region.TryEndOffset),
            HandlerStart = checked((int)region.HandlerStartOffset),
            HandlerEnd = checked((int)region.HandlerEndOffset),
            FilterStart = kind == ExceptionRegionKind.Filter ? checked((int)region.FilterDecisionStartOffset) : -1,
        };
    }
    #endregion
}
