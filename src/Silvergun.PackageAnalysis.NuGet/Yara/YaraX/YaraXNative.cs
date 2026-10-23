#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Reflection;
using System.Runtime.InteropServices;

/// <summary>
/// The result codes of the YARA-X C API (<c>enum YRX_RESULT</c> in <c>yara_x.h</c> 1.22.0), in declaration order.
/// </summary>
internal enum YaraXResult
{
    Success = 0,
    SyntaxError,
    VariableError,
    ScanError,
    ScanTimeout,
    InvalidArgument,
    InvalidUtf8,
    InvalidState,
    SerializationError,
    NoMetadata,
    NotSupported,
}

/// <summary><c>YRX_BUFFER</c>: a native-owned byte buffer, released with <c>yrx_buffer_destroy</c>.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct YaraXBuffer
{
    #region Fields
    internal byte* data;
    internal nuint length;
    #endregion
}

/// <summary>
/// Source-generated P/Invoke declarations for the YARA-X 1.22.0 C API (<c>yara_x_capi.dll</c>, ADR 0033), derived from
/// the pinned <c>yara_x.h</c> installed by <c>build/fetch-yara.ps1</c>, and the loader that binds them.
///
/// <para><b>Loading.</b> Nothing here touches the DLL until <see cref="TryLoad(out string?)"/> is called — there is no
/// static constructor and no field initialiser that does, so merely loading this assembly (the CLI, WPF, the tests) never
/// loads the engine (ADR 0033 FINAL FORM decision 5). <see cref="TryLoad(out string?)"/> loads the DLL by ABSOLUTE path
/// from the application directory and registers an import resolver for this assembly that hands back exactly that
/// module, and refuses (<see cref="DllNotFoundException"/>) rather than falling back to the default search order. A
/// missing or unloadable DLL is a returned failure ("engine unavailable"), never a crash at first use. Every managed
/// entry point of the binding calls <see cref="EnsureLoaded"/> before its first native call.</para>
///
/// <para><b>Process-fatal hazards</b> (C API spike, <c>docs/agent/measurements/yara-x-capi-spike-2026-10-21.md</c>): a
/// Rust panic aborts the host (0xC0000409) and no managed handler runs, which is why this binding only ever runs inside
/// the <c>__worker yara</c> child process. The only panic observed came from one scanner used by two threads at once;
/// <see cref="YaraXScanner"/> refuses use from any thread but its creator's.</para>
/// </summary>
internal static unsafe partial class YaraXNative
{
    #region Methods
    /// <summary>
    /// Loads <see cref="LibraryFileName"/> from <see cref="AppContext.BaseDirectory"/> (once per process) and binds the
    /// imports below to it. <c>false</c>, with the reason, when the engine is unavailable.
    /// </summary>
    internal static bool TryLoad(out string? failure) => TryLoad(AppContext.BaseDirectory, out failure);

    /// <summary>
    /// <see cref="TryLoad(out string?)"/> from <paramref name="directory"/>, which must be an absolute path. The FIRST call
    /// in a process decides the outcome for the rest of it (an import resolver can be registered once per assembly).
    /// </summary>
    internal static bool TryLoad(string directory, out string? failure)
    {
        lock (gate)
        {
            if (!attempted)
            {
                attempted = true;
                loadFailure = Load(directory);
            }
            failure = loadFailure;
            return failure is null;
        }
    }

    /// <summary>Throws unless <see cref="TryLoad(out string?)"/> has succeeded: no import may bind any other way.</summary>
    internal static void EnsureLoaded()
    {
        if (Volatile.Read(ref library) == 0)
            throw new InvalidOperationException($"The YARA-X engine is not loaded; call {nameof(YaraXNative)}.{nameof(TryLoad)} first.");
    }

    /// <summary>
    /// The calling thread's last C API error, escaped and bounded, or <c>null</c>. It is per thread and only valid until the
    /// next call on that thread, so read it right after the failing call.
    /// </summary>
    internal static string? LastError()
    {
        var message = yrx_last_error();
        return message is null ? null : YaraXText.Bounded(Marshal.PtrToStringUTF8((nint)message));
    }

    private static string? Load(string directory)
    {
        if (!Path.IsPathFullyQualified(directory))
            return $"engine unavailable: the application directory '{YaraXText.Bounded(directory)}' is not an absolute path.";

        var path = Path.Combine(directory, LibraryFileName);
        if (!File.Exists(path))
            return $"engine unavailable: {LibraryFileName} is not in the application directory '{YaraXText.Bounded(directory)}'.";

        nint handle;
        try
        {
            handle = NativeLibrary.Load(path);
        }
        catch (Exception ex)
        {
            return $"engine unavailable: {LibraryFileName} could not be loaded: {YaraXText.Bounded(ex.Message)}";
        }

        try
        {
            NativeLibrary.SetDllImportResolver(typeof(YaraXNative).Assembly, Resolve);
        }
        catch (Exception ex)
        {
            NativeLibrary.Free(handle);
            return $"engine unavailable: could not register the {LibraryFileName} import resolver: {YaraXText.Bounded(ex.Message)}";
        }

        Volatile.Write(ref library, handle);
        return null;
    }

    // Our library name resolves to the module loaded above, or nowhere: returning 0 would let the runtime fall back to its
    // default search order, which is exactly what this resolver exists to prevent. Other names are not ours to decide.
    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName is not (LibraryName or LibraryFileName))
            return 0;

        var handle = Volatile.Read(ref library);
        return handle != 0 ? handle
            : throw new DllNotFoundException($"{LibraryFileName} is only ever loaded from the application directory, by {nameof(YaraXNative)}.{nameof(TryLoad)}.");
    }

    [LibraryImport(LibraryName)]
    internal static partial byte* yrx_last_error();

    [LibraryImport(LibraryName)]
    internal static partial void yrx_buffer_destroy(YaraXBuffer* buf);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_compiler_create(uint flags, out YaraXCompilerHandle compiler);

    [LibraryImport(LibraryName)]
    internal static partial void yrx_compiler_destroy(nint compiler);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial YaraXResult yrx_compiler_add_source_with_origin(YaraXCompilerHandle compiler, string src, string origin);

    [LibraryImport(LibraryName)]
    internal static partial YaraXRulesHandle yrx_compiler_build(YaraXCompilerHandle compiler);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_compiler_errors_json(YaraXCompilerHandle compiler, out YaraXBuffer* buf);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_rule_identifier(nint rule, out byte* ident, out nuint len);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_rule_namespace(nint rule, out byte* ns, out nuint len);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_rule_iter_tags(nint rule, delegate* unmanaged[Cdecl]<byte*, nint, void> callback, nint userData);

    [LibraryImport(LibraryName)]
    internal static partial int yrx_rules_count(YaraXRulesHandle rules);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_rules_serialize(YaraXRulesHandle rules, out YaraXBuffer* buf);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_rules_deserialize(byte* data, nuint len, out YaraXRulesHandle rules);

    [LibraryImport(LibraryName)]
    internal static partial void yrx_rules_destroy(nint rules);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_scanner_create(YaraXRulesHandle rules, out YaraXScannerHandle scanner);

    [LibraryImport(LibraryName)]
    internal static partial void yrx_scanner_destroy(nint scanner);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_scanner_set_timeout(YaraXScannerHandle scanner, ulong timeout);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_scanner_on_matching_rule(YaraXScannerHandle scanner, delegate* unmanaged[Cdecl]<nint, nint, void> callback, nint userData);

    [LibraryImport(LibraryName)]
    internal static partial YaraXResult yrx_scanner_scan(YaraXScannerHandle scanner, byte* data, nuint len);
    #endregion

    #region Fields
    /// <summary>The import name every declaration above binds through (resolved by <see cref="Resolve"/> only).</summary>
    internal const string LibraryName = "yara_x_capi";

    /// <summary>The DLL's file name in the application directory.</summary>
    internal const string LibraryFileName = "yara_x_capi.dll";

    /// <summary>The engine version this binding is written against: the pinned C API (<c>YARA_X_MAJOR/MINOR/PATCH</c>).</summary>
    internal const string EngineVersion = "1.22.0";

    /// <summary><c>YRX_DISABLE_INCLUDES</c>: an <c>include</c> would read a file relative to the working directory.</summary>
    internal const uint DisableIncludes = 32;

    private static readonly Lock gate = new();
    private static bool attempted;
    private static string? loadFailure;
    private static nint library;
    #endregion
}
#endif
