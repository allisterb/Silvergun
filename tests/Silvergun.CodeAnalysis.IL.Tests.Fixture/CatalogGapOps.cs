namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;

// NOTE (handoff item B): this fixture targets netstandard2.0. Two item-B techniques —
// System.Reflection.Emit.* (DynamicMethod/ILGenerator) and Activator.CreateInstanceFrom — are NOT part
// of the netstandard2.0 surface and would require extra NuGet packages (forbidden by CLAUDE.md). Those two
// are exercised from a net10.0 target inside the test project instead (see Net10OnlyGapOps in the test
// project). Everything here compiles on netstandard2.0.

/// <summary>
/// Reflection-invocation targets (handoff item B): <see cref="MethodBase.Invoke(object, object[])"/> and
/// <see cref="Delegate.DynamicInvoke(object[])"/>. Analyzed statically, never executed.
/// </summary>
public class ReflectionInvocationOps
{
    /// <summary>
    /// Invokes a method through reflection. <c>GetMethod</c> yields a <see cref="MethodInfo"/>, but the
    /// <c>Invoke(object, object[])</c> overload is declared on <see cref="MethodBase"/>, so the emitted
    /// callvirt targets <c>System.Reflection.MethodBase.Invoke</c>.
    /// </summary>
    public object InvokesViaMethodInfo(object target)
    {
        MethodInfo m = target.GetType().GetMethod("ToString");
        return m.Invoke(target, null);
    }

    /// <summary>Invokes a delegate late-bound via <see cref="Delegate.DynamicInvoke(object[])"/>.</summary>
    public object InvokesViaDelegate()
    {
        Func<int> d = () => 42;
        return d.DynamicInvoke(null);
    }
}

/// <summary>
/// Dynamic-codegen / unsafe-load targets (handoff item B) that are available on netstandard2.0:
/// <see cref="System.Linq.Expressions.Expression{TDelegate}.Compile()"/> and <c>Assembly.UnsafeLoadFrom</c>.
/// Analyzed statically, never executed.
/// </summary>
public class DynamicCodeOps
{
    /// <summary>Compiles an expression tree via <see cref="System.Linq.Expressions.Expression{TDelegate}.Compile()"/>.</summary>
    public Func<int> CompilesExpression()
    {
        Expression<Func<int>> expr = () => 42;
        return expr.Compile();
    }

    /// <summary>Loads an assembly bypassing evidence checks via <c>Assembly.UnsafeLoadFrom</c>.</summary>
    public Assembly UnsafeLoads(string path) => Assembly.UnsafeLoadFrom(path);
}

/// <summary>
/// P/Invoke declarations (handoff item B). These are <c>[DllImport]</c>/pinvokeimpl externs with NO IL body
/// and NO call site anywhere in the assembly — they exist only to prove attribute/metadata-seam detection.
/// They are never invoked (the native entry points may not even resolve at runtime); analysis is purely static.
/// </summary>
public static class NativeInteropOps
{
    /// <summary>P/Invoke into <c>user32.dll!MessageBoxW</c>. Declared, never called.</summary>
    [DllImport("user32.dll", EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode)]
    public static extern int ShowMessage(IntPtr hWnd, string text, string caption, uint type);

    /// <summary>P/Invoke into <c>kernel32.dll!GetCurrentProcessId</c>. Declared, never called.</summary>
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
    public static extern uint CurrentProcessId();
}
