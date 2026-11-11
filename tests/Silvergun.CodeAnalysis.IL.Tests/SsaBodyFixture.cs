namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;

/// <summary>
/// The bodies the SSA adapter's conversion tests inspect (docs/agent/tasks/ssa-adapter.md S2), lifted once in one session:
/// <list type="bullet">
/// <item><description><c>SsaOperands</c>, emitted with <see cref="PersistedAssemblyBuilder"/>: one method per operand
/// type, the locals shapes and the exception regions, written opcode by opcode with explicit index operands, so the
/// argument and local encodings are the ones under test (it does shorten a small <c>ldc.i4</c> to <c>ldc.i4.s</c>);</description></item>
/// <item><description><c>SsaPrefixes</c>, written row by row (<see cref="RawAssembly"/>): the <c>no.</c> prefix, which
/// <see cref="OpCodes"/> has no member for;</description></item>
/// <item><description>the compiled, netstandard2.0 <c>Silvergun.CodeAnalysis.IL.Tests.Fixture</c>, for csc's own
/// multi-dimensional array accessors (<c>MultiDimArrayOps</c>), read by path, never loaded.</description></item>
/// </list>
/// </summary>
public sealed class SsaBodyFixture : IDisposable
{
    #region Constructors
    public SsaBodyFixture()
    {
        OperandsPath = emitted.Save("SsaOperands", DefineOperands);
        PrefixesPath = WritePrefixes(temp.Path);
        Lifted = new SsaLifted([OperandsPath, PrefixesPath, CompiledFixturePath]);
    }
    #endregion

    #region Properties
    public static string CompiledFixturePath { get; } = Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.Fixture.dll");

    public string OperandsPath { get; }

    public string PrefixesPath { get; }

    internal SsaLifted Lifted { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Lifted.Dispose();
        emitted.Dispose();
        temp.Dispose();
    }

    internal static void DefineOperands(ModuleBuilder module)
    {
        var ops = module.DefineType("Ssa.Ops", TypeAttributes.Public | TypeAttributes.Class);
        var field = ops.DefineField("Field", typeof(int), FieldAttributes.Public | FieldAttributes.Static);
        ops.DefineDefaultConstructor(MethodAttributes.Public);

        var target = ops.DefineMethod("Target", MethodAttributes.Public | MethodAttributes.Static, typeof(int), [typeof(int)]);
        Body(target, il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ret);
        });

        // Arguments: short and long forms, static (a is 0) and instance (this is 0).
        Body(Static(ops, "StaticArgs", typeof(int), typeof(int), typeof(int), typeof(int)), il =>
        {
            il.Emit(OpCodes.Ldarg_S, (byte)1);
            il.Emit(OpCodes.Starg_S, (byte)0);
            il.Emit(OpCodes.Ldarga_S, (byte)2);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ldarg, (short)0);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Starg, (short)1);
            il.Emit(OpCodes.Ldarga, (short)1);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ret);
        });
        Body(ops.DefineMethod("InstanceArgs", MethodAttributes.Public, typeof(int), [typeof(int), typeof(int)]), il =>
        {
            il.Emit(OpCodes.Ldarg_S, (byte)0);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldarg_S, (byte)2);
            il.Emit(OpCodes.Starg_S, (byte)1);
            il.Emit(OpCodes.Ldarga_S, (byte)1);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ldarg, (short)2);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Ret);
        });

        // Locals: short and long forms.
        Body(Static(ops, "LocalIndexes", typeof(int)), il =>
        {
            il.DeclareLocal(typeof(int));
            il.DeclareLocal(typeof(int));
            il.Emit(OpCodes.Ldc_I4_7);
            il.Emit(OpCodes.Stloc_S, (byte)1);
            il.Emit(OpCodes.Ldloca_S, (byte)0);
            il.Emit(OpCodes.Ldc_I4_3);
            il.Emit(OpCodes.Stind_I4);
            il.Emit(OpCodes.Ldloc_S, (byte)1);
            il.Emit(OpCodes.Ldloc, (short)0);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Stloc, (short)0);
            il.Emit(OpCodes.Ldloca, (short)1);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ret);
        });

        // Branches: forward short, forward long, and a backward short one.
        Body(Static(ops, "Branches", typeof(int), typeof(int)), il =>
        {
            var one = il.DefineLabel();
            var two = il.DefineLabel();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brtrue_S, one);
            il.Emit(OpCodes.Br, two);
            il.MarkLabel(one);
            il.Emit(OpCodes.Ldc_I4, 111);
            il.Emit(OpCodes.Ret);
            il.MarkLabel(two);
            il.Emit(OpCodes.Ldc_I4, 222);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Loop", typeof(int), typeof(int)), il =>
        {
            var top = il.DefineLabel();
            il.Emit(OpCodes.Ldc_I4, 444);
            il.Emit(OpCodes.Pop);
            il.MarkLabel(top);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Sub);
            il.Emit(OpCodes.Starg_S, (byte)0);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brtrue_S, top);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Switch", typeof(int), typeof(int)), il =>
        {
            var cases = new[] { il.DefineLabel(), il.DefineLabel(), il.DefineLabel() };
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Switch, cases);
            il.Emit(OpCodes.Ldc_I4_M1);
            il.Emit(OpCodes.Ret);
            for (var i = 0; i < cases.Length; i++)
            {
                il.MarkLabel(cases[i]);
                il.Emit(OpCodes.Ldc_I4, 100 + i);
                il.Emit(OpCodes.Ret);
            }
        });

        Body(Static(ops, "Constants", typeof(long)), il =>
        {
            il.Emit(OpCodes.Ldc_I4_M1);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_I4_S, (sbyte)-5);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_I4, 123456);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_R4, 1.5f);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_R8, 2.25);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_I8, 0x1_0000_0000L);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Str", typeof(string)), il =>
        {
            il.Emit(OpCodes.Ldstr, "silvergun-ssa");
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "NewArrays", typeof(object)), il =>
        {
            il.Emit(OpCodes.Ldc_I4_3);
            il.Emit(OpCodes.Newarr, typeof(int));
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_I4_2);
            il.Emit(OpCodes.Newarr, typeof(string));
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Newarr, ops);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Calli", typeof(int)), il =>
        {
            il.Emit(OpCodes.Ldc_I4_5);
            il.Emit(OpCodes.Ldftn, target);
            il.EmitCalli(OpCodes.Calli, CallingConventions.Standard, typeof(int), [typeof(int)], null);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Tokens", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldtoken, typeof(int));
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldtoken, target);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldtoken, field);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Unaligned", typeof(int), typeof(int).MakeByRefType()), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Unaligned, (byte)1);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "Volatile", typeof(int), typeof(int).MakeByRefType()), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Volatile);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ret);
        });
        // newobj int32[,]::.ctor(lo, len, lo, len): the lower-bound constructor csc never emits.
        Body(Static(ops, "RangeArray", typeof(object)), il =>
        {
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Ldc_I4_2);
            il.Emit(OpCodes.Ldc_I4_3);
            il.Emit(OpCodes.Ldc_I4_4);
            il.Emit(OpCodes.Newobj, typeof(int[,]).GetConstructor([typeof(int), typeof(int), typeof(int), typeof(int)])!);
            il.Emit(OpCodes.Ret);
        });

        // Locals: C#'s fixed (a pinned int32& local, and the int32* taken from it), a plain byref local, an unpinned local.
        Body(Static(ops, "Pinned", typeof(int), typeof(int[])), il =>
        {
            il.DeclareLocal(typeof(int).MakeByRefType(), pinned: true);
            il.DeclareLocal(typeof(int).MakeByRefType());
            il.DeclareLocal(typeof(int).MakePointerType());
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldelema, typeof(int));
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Conv_U);
            il.Emit(OpCodes.Stloc_2);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldelema, typeof(int));
            il.Emit(OpCodes.Stloc_1);
            il.Emit(OpCodes.Ldloc_2);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Ldloc_1);
            il.Emit(OpCodes.Ldind_I4);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Conv_U);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ret);
        });
        var noInit = Static(ops, "SkipsLocalsInit", typeof(int));
        noInit.InitLocals = false;
        Body(noInit, il =>
        {
            il.DeclareLocal(typeof(int));
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(ops, "ZeroesLocals", typeof(int)), il =>
        {
            il.DeclareLocal(typeof(int));
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ret);
        });

        // Exception regions: a try/catch and a try/filter nested in a try/finally, then a try/fault after it.
        Body(Static(ops, "Regions", typeof(int), typeof(int)), il =>
        {
            il.BeginExceptionBlock();
            il.BeginExceptionBlock();
            AddTo(il, 1);
            il.BeginCatchBlock(typeof(InvalidOperationException));
            il.Emit(OpCodes.Pop);
            AddTo(il, 2);
            il.EndExceptionBlock();
            il.BeginExceptionBlock();
            AddTo(il, 3);
            il.BeginExceptFilterBlock();
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldc_I4_1);
            il.BeginCatchBlock(null!);
            il.Emit(OpCodes.Pop);
            AddTo(il, 4);
            il.EndExceptionBlock();
            il.BeginFinallyBlock();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Pop);
            il.EndExceptionBlock();
            il.BeginExceptionBlock();
            AddTo(il, 5);
            il.BeginFaultBlock();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Pop);
            il.EndExceptionBlock();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ret);
        });

        ops.CreateType();
    }

    // x += value, on argument 0.
    private static void AddTo(ILGenerator il, int value)
    {
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldc_I4, value);
        il.Emit(OpCodes.Add);
        il.Emit(OpCodes.Starg_S, (byte)0);
    }

    private static MethodBuilder Static(TypeBuilder type, string name, Type returns, params Type[] parameters) =>
        type.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, returns, parameters);

    private static void Body(MethodBuilder method, Action<ILGenerator> emit) => emit(method.GetILGenerator());

    // The no. prefix (0xFE19) and its flags byte: 0x02 skips the range check of the ldelem it prefixes.
    private static string WritePrefixes(string directory)
    {
        var raw = new RawAssembly("SsaPrefixes");
        raw.Type("Ssa", "Prefixes", raw.Object);
        raw.Static("NoRangeCheck", RawAssembly.MethodSig(false, r => r.Type().Int32(), p => p.SZArray().Int32()), il =>
        {
            il.LoadArgument(0);
            il.LoadConstantI4(0);
            il.OpCode((ILOpCode)0xFE19);
            il.CodeBuilder.WriteByte(0x02);
            il.OpCode(ILOpCode.Ldelem_i4);
            il.OpCode(ILOpCode.Ret);
        });
        return raw.Save(directory);
    }
    #endregion

    #region Fields
    private readonly EmittedAssembly emitted = new();
    private readonly SsaTempDirectory temp = new();
    #endregion
}
