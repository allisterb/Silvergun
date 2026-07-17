namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Reflection.Emit;

/// <summary>
/// The two handoff-item-B techniques that are NOT part of the netstandard2.0 surface (so they cannot live
/// in the shared netstandard2.0 fixture without a forbidden NuGet package): <c>System.Reflection.Emit.*</c>
/// and <c>Activator.CreateInstanceFrom</c>. This type lives in the net10.0 test assembly and is analyzed by
/// loading that assembly with <see cref="AssemblyAnalyzer"/> — the same self-load pattern the real-assembly
/// smoke test uses. Analyzed statically, never executed.
/// </summary>
public static class Net10OnlyGapOps
{
    /// <summary>Builds a <see cref="DynamicMethod"/> and an <see cref="ILGenerator"/> (System.Reflection.Emit.*).</summary>
    public static void EmitsDynamicMethod()
    {
        var dm = new DynamicMethod("dyn", typeof(void), Type.EmptyTypes);
        var il = dm.GetILGenerator();
        il.Emit(OpCodes.Ret);
    }

    /// <summary>Activates a type from an on-disk assembly file via <c>Activator.CreateInstanceFrom</c>.</summary>
    public static object? ActivatesFromFile(string path, string typeName) =>
        Activator.CreateInstanceFrom(path, typeName);
}
