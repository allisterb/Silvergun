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
        // Each body its own operand memo (Once): CCI resolves a token's generic parameters against the body's owner.
        var outer = operands;
        operands = new();
        try
        {
            return ConvertBody(cci, body);
        }
        finally
        {
            operands = outer;
        }
    }

    private ILMethodBody ConvertBody(IMethodDefinition cci, IMethodBody body)
    {
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
                var array = OperandType(operation.Value as IArrayTypeReference) as MDArrayType
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
        ILOperandType.Method => OperandMethod((IMethodReference)value!),
        ILOperandType.Field => OperandField((IFieldReference)value!, code is ILCode.Ldsfld or ILCode.Stsfld or ILCode.Ldsflda),
        // CCI hands newarr the array type; Cilica, like the encoding, the element type.
        ILOperandType.Type => code == ILCode.Newarr ? OperandType(((IArrayTypeReference)value!).ElementType) : OperandType((ITypeReference)value!),
        ILOperandType.Tok => value switch
        {
            IMethodReference method => OperandMethod(method),
            IFieldReference field => OperandField(field, null),
            ITypeReference type => OperandType(type),
            _ => throw new SsaAdapterException("An ldtoken operand that is not a type, method or field"),
        },
        ILOperandType.Sig => value is IFunctionPointerTypeReference function
            ? Once(function, OperandKind.Signature, () => Bounded(new FuncPtrType(MapSignature(function, function.ExtraArgumentTypes, 0, default, 0))))
            : throw new SsaAdapterException("A calli signature that cannot be read"),
        var other => throw new SsaAdapterException($"An operand type the adapter does not map ({other})"),
    };

    private TypeDesc OperandType(ITypeReference? type) =>
        type is null ? MapType(type, default, 0) : Once(type, OperandKind.Type, () => MapType(type, default, 0));

    private MethodDesc OperandMethod(IMethodReference method) => Once(method, OperandKind.Method, () => MapMethod(method, 0));

    private FieldDesc OperandField(IFieldReference field, bool? isStatic) =>
        Once(field, isStatic switch { true => OperandKind.StaticField, false => OperandKind.InstanceField, null => OperandKind.TokenField },
            () => MapField(field, isStatic, 0));

    // A context-free operand (a token, a local's or a handler's type) maps the same wherever one body names it, so it is
    // mapped once per body, failures included: a body naming one large type a thousand times pays for it once. Only within
    // a body: a token's generic parameters resolve against its owner, so another body may read it otherwise. Keyed by its
    // token (CCI may hand out a new reference per use), else by the reference; a source maps one module, so a token is
    // one row. A path-dependent failure, or a mapping CCI asserted on, is not kept.
    private T Once<T>(object reference, OperandKind kind, Func<T> map) where T : class
    {
        if (operands is null)
            return map();
        var key = (reference is IMetadataObjectWithToken { TokenValue: var token } && token is not (0 or uint.MaxValue) ? (object)token : reference, kind);
        if (operands.TryGetValue(key, out var known))
            return known is ExceptionBox box ? throw box.Exception : (T)known;
        using var reads = CciAssertions.BeginScope();
        try
        {
            var value = map();
            if (reads.Count == 0)
                operands[key] = value;
            return value;
        }
        catch (Exception ex) when (ex is UnresolvedFactException or SsaAdapterException { IsPathDependent: false } && reads.Count == 0)
        {
            operands[key] = new ExceptionBox(ex);
            throw;
        }
    }

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
        return OperandType(local.Type is IModifiedTypeReference modified ? modified.UnmodifiedType : local.Type);
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
            CatchType = kind == ExceptionRegionKind.Catch ? OperandType(region.ExceptionType) : null,
            TryStart = checked((int)region.TryStartOffset),
            TryEnd = checked((int)region.TryEndOffset),
            HandlerStart = checked((int)region.HandlerStartOffset),
            HandlerEnd = checked((int)region.HandlerEndOffset),
            FilterStart = kind == ExceptionRegionKind.Filter ? checked((int)region.FilterDecisionStartOffset) : -1,
        };
    }
    #endregion
}
