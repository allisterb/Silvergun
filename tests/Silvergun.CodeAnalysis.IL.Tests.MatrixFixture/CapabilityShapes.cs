namespace Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
#if NETFRAMEWORK
using System.Runtime.Serialization;
#endif
#if NET5_0_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
#endif

// This fixture is built for the whole target matrix — net472 and net10.0 — so the CAPABILITY seam
// (CapabilityAnalysis) can be read against a call site compiled by EACH flavour of the toolchain. Detection today
// is driven entirely by the legacy in-code 32-entry Catalog (src/Silvergun.CodeAnalysis.IL/CapabilityAnalysis.cs);
// capabilities.cm is parsed but NOT YET consulted by this seam — it stays inert until capability-map phase 2 wires
// it in (see docs/agent/tasks/capability-map.md). Today that seam is only ever exercised on the netstandard2.0
// fixture (tests/Silvergun.CodeAnalysis.IL.Tests.Fixture) — there is no net472 or net10.0 assembly anywhere in the repo
// with, say, a Process.Start call site, so a TFM-sensitive regression in detection would go uncaught.
// One representative call site per capability is enough: catalog BREADTH is already covered on netstandard2.0;
// the matrix's job is cross-TFM EQUIVALENCE.
// Everything here is analyzed statically — nothing is ever executed, so arguments and return values need not be
// meaningful, and native/managed resources need not resolve at runtime.
//
// KNOWN NON-COVERAGE: Registry (Microsoft.Win32.Registry / RegistryKey) has NO shape in this file. On net10.0
// the type lives in the out-of-box Microsoft.Win32.Registry package, which is not part of the base net10.0
// shared framework — adding it would mean adding a NuGet package, which the no-new-packages guardrail forbids.
// Registry stays covered by the netstandard2.0 fixture only.
//
// SHAPES ARE NOT IDENTICAL ACROSS THE MATRIX, deliberately: the three guarded shapes below exist on only one
// side of the matrix each, which is the entire point of this file — see the SUBJECT comments.

#pragma warning disable SYSLIB0014 // WebClient is obsolete; used only as a static-analysis target, never executed.

/// <summary>
/// One representative call site per <c>Capability</c> value, present on every TFM where the underlying API
/// exists. Eight are actually detected by <c>CapabilityAnalysis</c>'s legacy <c>Catalog</c> today —
/// <c>FileSystem</c>, <c>Network</c>, <c>ProcessExecution</c>, <c>EnvironmentProbe</c>,
/// <c>DynamicCodeLoading</c>, <c>ReflectionInvocation</c>, <c>NativeInterop</c>, <c>Cryptography</c> — and are
/// asserted as detected. <c>RuntimeControl</c> (<c>GC</c>/<c>AssemblyLoadContext</c>) and <c>UnsafeMemory</c>
/// (<c>Unsafe</c>) have shapes here too, deliberately guarded and asserted as NOT-YET-detected: their APIs are
/// absent from the legacy <c>Catalog</c> and exist only in <c>capabilities.cm</c>, which this seam does not
/// consult until capability-map phase 2. Every method returns the call's result rather than discarding it, so
/// the compiler cannot fold or elide the call — nothing here is ever invoked.
/// </summary>
public static class CapabilityShapes
{
    /// <summary>FileSystem: <see cref="File.ReadAllBytes(string)"/>. Never called.</summary>
    public static byte[] ReadsFileBytes(string path) => File.ReadAllBytes(path);

    /// <summary>Network: constructs a <see cref="WebClient"/>. Never called.</summary>
    public static WebClient CreatesWebClient() => new WebClient();

    /// <summary>ProcessExecution: <see cref="Process.Start(string)"/>. Never called.</summary>
    public static Process StartsProcess(string path) => Process.Start(path);

    /// <summary>EnvironmentProbe: <see cref="Environment.GetEnvironmentVariable(string)"/>. Never called.</summary>
    public static string ProbesEnvironment(string name) => Environment.GetEnvironmentVariable(name);

    /// <summary>DynamicCodeLoading: <see cref="Assembly.Load(byte[])"/>. Never called.</summary>
    public static Assembly LoadsAssembly(byte[] rawAssembly) => Assembly.Load(rawAssembly);

    /// <summary>
    /// ReflectionInvocation: <c>GetMethod</c> yields a <see cref="MethodInfo"/>, but the
    /// <c>Invoke(object, object[])</c> overload it calls is declared on <see cref="MethodBase"/>, so the
    /// emitted callvirt targets <c>System.Reflection.MethodBase.Invoke</c>. Never called.
    /// </summary>
    public static object InvokesViaReflection(object target)
    {
        MethodInfo method = target.GetType().GetMethod("ToString");
        return method.Invoke(target, null);
    }

    /// <summary>NativeInterop: <see cref="Marshal.AllocHGlobal(int)"/>. Never called.</summary>
    public static IntPtr AllocatesUnmanagedMemory(int size) => Marshal.AllocHGlobal(size);

    /// <summary>Cryptography: <see cref="Aes.Create()"/>. Never called.</summary>
    public static Aes CreatesAes() => Aes.Create();

    /// <summary>
    /// RuntimeControl: <see cref="GC.Collect()"/>. <see cref="GC.CollectionCount(int)"/> gives the void call
    /// a return value to carry, so the method still fits the "return the result" rule uniformly. Never called.
    /// </summary>
    public static int TriggersGarbageCollection()
    {
        GC.Collect();
        return GC.CollectionCount(0);
    }

    // NetDataContractSerializer never shipped in .NET Core/5+ (see capabilities.cm's SCOPE note: a scanned
    // .nupkg routinely ships a net472/netstandard2.0 target, and Framework-only map entries are kept
    // deliberately for exactly that traffic) — NETFRAMEWORK is the ONLY matrix TFM where the type exists at
    // all, so this shape is guarded to it. This is the actual payoff of the task: nothing before this proved
    // the Framework-only deserialization-gadget entry is detected on a REAL net472 assembly, only assumed
    // from the map file.
#if NETFRAMEWORK
    /// <summary>
    /// SUBJECT — DynamicCodeLoading on net472 only: constructs a
    /// <see cref="NetDataContractSerializer"/>, the classic deserialization-gadget vector that never shipped
    /// outside .NET Framework. Never called.
    /// </summary>
    public static NetDataContractSerializer CreatesNetDataContractSerializer() => new NetDataContractSerializer();
#endif

    // AssemblyLoadContext exists on net5.0+ only — net472 has no managed load-context abstraction, only the
    // much heavier AppDomain — so this shape is guarded to NET5_0_OR_GREATER: the modern-only half of the
    // TFM-divergence this task exists to prove.
#if NET5_0_OR_GREATER
    /// <summary>
    /// SUBJECT — RuntimeControl on net10.0 only: reads <see cref="AssemblyLoadContext.Default"/>, a member the
    /// <c>System.Runtime.Loader.AssemblyLoadContext</c> type entry in <c>capabilities.cm</c> catches with no
    /// more specific override. Never called.
    /// </summary>
    public static AssemblyLoadContext GetsDefaultAssemblyLoadContext() => AssemblyLoadContext.Default;

    // System.Runtime.CompilerServices.Unsafe has lived in CoreLib itself since net5.0; reaching it on net472
    // would need the separate Unsafe NuGet package, which the no-new-packages guardrail forbids — so this
    // shape is guarded the same way as AssemblyLoadContext above.
    /// <summary>
    /// SUBJECT — UnsafeMemory on net10.0 only: <see cref="Unsafe.SizeOf{T}"/>. Never called.
    /// </summary>
    public static int SizeOfInt32() => Unsafe.SizeOf<int>();
#endif
}

#pragma warning restore SYSLIB0014
