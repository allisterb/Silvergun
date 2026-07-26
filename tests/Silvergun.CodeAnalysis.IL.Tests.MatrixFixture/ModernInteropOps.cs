namespace Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

using System.Runtime.InteropServices;

// This fixture is built for the whole target matrix — net472, net8.0 and net10.0 — so the analyzer can be
// read against the SAME declarations as compiled by each flavour of the toolchain (the netstandard2.0 fixture
// cannot express the modern shapes at all).
// Everything here is a *declaration* analyzed statically — nothing is ever executed, and the native
// entry points need not resolve at runtime.
//
// SHAPES ARE NOT IDENTICAL ACROSS THE MATRIX, deliberately: the attributes below were introduced in different
// framework versions, so each is guarded to the TFMs on which it exists. Anything available everywhere
// ([DllImport], and the Clean negative control) is left UNGUARDED so every flavour carries it.

/// <summary>
/// Interop declaration shapes for the metadata/attribute detection seam
/// (<c>CapabilityAnalysis.ScanInteropDeclarations</c>).
/// </summary>
public static partial class ModernInteropOps
{
    // [LibraryImport] and StringMarshalling exist on net7.0+ only, so on the matrix they are present in the
    // net8.0 and net10.0 flavours and absent from net472. The `partial` declarations must be guarded together
    // with the attribute: without the source generator there is no implementing part, which is a compile error
    // (CS8795) rather than a missing shape.
#if NET7_0_OR_GREATER
    /// <summary>
    /// SUBJECT — the modern source-generated P/Invoke. <c>[LibraryImport]</c> is net7+, so this shape
    /// only exists on a modern TFM. The generator emits the <c>pinvokeimpl</c> stub itself; the signature
    /// is deliberately blittable (no strings, no pointers) so no marshalling helpers are generated.
    /// Declared, never called.
    /// </summary>
    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
    internal static partial uint CurrentProcessId();

    /// <summary>
    /// SUBJECT B — the same attribute on a signature that <em>requires marshalling</em> (a UTF-8 string
    /// parameter). Unlike <see cref="CurrentProcessId"/>, the generator cannot emit a direct forwarder here:
    /// it emits a bodied stub under the declared name plus a nested <c>pinvokeimpl</c> local function with a
    /// mangled name, so this is the shape that decides how attribution reads. Declared, never called.
    /// </summary>
    [LibraryImport("kernel32.dll", EntryPoint = "OutputDebugStringA", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial void DebugMessage(string message);
#endif

    /// <summary>
    /// CONTROL — the classic <c>[DllImport]</c> extern, already known to be detected. Same native module
    /// as the subject but a different entry point, so the two findings are unambiguous. Declared, never called.
    /// </summary>
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentThreadId")]
    internal static extern uint CurrentThreadId();

    // [UnmanagedCallersOnly] exists on net5.0+ only, so on the matrix the reverse-P/Invoke shapes are present
    // in the net8.0 and net10.0 flavours and absent from net472, which has no managed-export mechanism at all.
#if NET5_0_OR_GREATER
    /// <summary>
    /// SUBJECT C — <em>reverse</em> P/Invoke: a managed method published as a native-callable entry point.
    /// The attribute requires a <c>static</c> method with a blittable signature and no generic parameters,
    /// and its <c>EntryPoint</c> names the export, so this pins the named-argument read. Never called.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "silvergun_callback")]
    public static int NamedCallback(int x) => x + 1;

    /// <summary>
    /// SUBJECT D — the same shape with <b>no</b> <c>EntryPoint</c> argument, so the entry point falls back
    /// to the method's own name. Never called.
    /// </summary>
    [UnmanagedCallersOnly]
    public static int UnnamedCallback(int x) => x + 2;
#endif

    /// <summary>
    /// NEGATIVE CONTROL — an ordinary managed method with no interop attribute and no sensitive call.
    /// Must produce zero findings.
    /// </summary>
    public static int Clean(int x) => (x * 3) + 7;
}
