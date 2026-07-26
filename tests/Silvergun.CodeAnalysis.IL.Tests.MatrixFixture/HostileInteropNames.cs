namespace Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

using System.Runtime.InteropServices;

// This fixture is built for the whole target matrix — net472, net8.0 and net10.0 (the netstandard2.0 fixture
// cannot express [UnmanagedCallersOnly] at all).
// Everything here is a *declaration* analyzed statically — nothing is ever executed, and the native
// entry points need not resolve at runtime (several of these names could not resolve on any platform).
//
// The hostile [DllImport] names below are UNGUARDED, so the import-side injection cases exist in every flavour
// of the matrix; only the export-side ones, which need an attribute that does not exist on net472, are guarded.
//
// WHY A SEPARATE TYPE: ModernInteropOps is the well-formed baseline, and ModernInteropDeclarationTests
// pins its exact shape. The hostile names live here so those tests keep reading a clean type, and so a
// reader can never mistake one of these declarations for a realistic one.

/// <summary>
/// Interop declarations whose <em>names</em> are hostile: they smuggle the <c>'!'</c> separator and control
/// characters into the metadata that <c>CapabilityAnalysis</c> composes into <c>ApiCallFinding.CalledApi</c>
/// as <c>module!entryPoint</c> / <c>&lt;managed&gt;!entryPoint</c>.
/// <para>
/// Every declaration below is plain C# that Roslyn compiles without complaint — that is the whole point.
/// A native module name or export name is attacker-controlled metadata in an untrusted package, so nothing
/// stops a second <c>'!'</c> (which would break the documented "exactly one <c>'!'</c>" split contract that
/// renderers rely on) or a newline (which would break a report table's row layout).
/// </para>
/// </summary>
public static class HostileInteropNames
{
    /// <summary>
    /// Worst case on the import side: an injected <c>'!'</c> in <b>both</b> composed components at once.
    /// A naive composition would yield three <c>'!'</c>-separated segments. Declared, never called.
    /// </summary>
    [DllImport("evil!mod.dll", EntryPoint = "also!bad")]
    internal static extern int BangInModuleAndEntryPoint();

    /// <summary>
    /// An injected <c>'!'</c> in the native module name only — the left component of the composition.
    /// Declared, never called.
    /// </summary>
    [DllImport("evil!mod.dll", EntryPoint = "fn")]
    internal static extern int BangInModuleName();

    /// <summary>
    /// A CRLF inside the import name: the report-row-layout case. A raw newline in <c>CalledApi</c> would
    /// split one finding across two rows of any line-oriented report. Declared, never called.
    /// </summary>
    [DllImport("evil.dll", EntryPoint = "fn\r\nx")]
    internal static extern int ControlCharactersInEntryPoint();

    /// <summary>
    /// Degenerate import name: <em>nothing but</em> control characters, so sanitization empties it entirely
    /// and the entry point must fall back to the managed method name rather than compose an empty segment.
    /// Declared, never called.
    /// </summary>
    [DllImport("evil.dll", EntryPoint = "\r\n\t")]
    internal static extern int OnlyControlCharactersInEntryPoint();

    // [UnmanagedCallersOnly] exists on net5.0+ only, so the export-side hostile names are present in the
    // net8.0 and net10.0 flavours and absent from net472, which has no managed-export mechanism at all.
#if NET5_0_OR_GREATER
    /// <summary>
    /// The export-side <c>'!'</c> injection: an <c>[UnmanagedCallersOnly]</c> entry point that tries to
    /// forge a second separator, which would let a renderer read the wrong owner segment. Never called.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "evil!injected")]
    public static int BangInExportEntryPoint(int x) => x;

    /// <summary>
    /// The export-side control-character case: CR, LF and TAB in one entry point. Never called.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "evil\r\ninjected\tmore")]
    public static int ControlCharactersInExportEntryPoint(int x) => x;

    /// <summary>
    /// Degenerate export name: <em>nothing but</em> control characters, so the entry point must fall back
    /// to the managed method name — the export-side twin of
    /// <see cref="OnlyControlCharactersInEntryPoint"/>. Never called.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "\r\n\t")]
    public static int OnlyControlCharactersInExportEntryPoint(int x) => x;
#endif
}
