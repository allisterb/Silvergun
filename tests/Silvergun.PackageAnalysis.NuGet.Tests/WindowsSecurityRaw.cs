#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

using Xunit;

/// <summary>
/// DPAPI called raw, with flags of the test's choosing (review C1, 2026-10-23). The product's
/// <c>WindowsSecurityNative.Protect</c> only ever makes CurrentUser blobs, and its <c>Unprotect</c> refuses every other
/// scope, so neither can stage, or observe, what C1 is about: a <c>CRYPTPROTECT_LOCAL_MACHINE</c> blob, which ANY local
/// user can make with the cache's public entropy, and which plain <c>CryptUnprotectData</c> unprotects for every user on
/// the machine. Plain P/Invoke (no package), System32 only. Machine-scope blobs are just bytes: nothing about them persists
/// on the machine, so there is nothing to clean up beyond the fixture directories.
/// </summary>
internal static class RawDpapi
{
    #region Methods
    /// <summary><c>CryptProtectData(data, entropy, flags)</c>, no description, no prompt struct; asserts it succeeded.</summary>
    internal static byte[] Protect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy, uint flags)
    {
        var (blob, error) = Call(protect: true, data, entropy, flags);
        Assert.True(blob is not null, $"the test could not CryptProtectData with flags 0x{flags:x}: error 0x{error:x8}");
        return blob!;
    }

    /// <summary>
    /// <c>CryptUnprotectData(blob, entropy, CRYPTPROTECT_UI_FORBIDDEN)</c>, with NO scope check: the payload, or <c>null</c>
    /// and the error (<c>GetLastError</c>).
    /// </summary>
    internal static (byte[]? Data, int Error) Unprotect(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> entropy) =>
        Call(protect: false, blob, entropy, UiForbidden);

    /// <summary>The blob's <c>dwVersion</c> (u32 LE at offset 0).</summary>
    internal static uint Version(ReadOnlySpan<byte> blob) => BinaryPrimitives.ReadUInt32LittleEndian(blob);

    /// <summary>The blob's <c>dwFlags</c> (u32 LE at offset 40): the CryptProtectData flags, as measured.</summary>
    internal static uint Flags(ReadOnlySpan<byte> blob) => BinaryPrimitives.ReadUInt32LittleEndian(blob[FlagsOffset..]);

    /// <summary>A copy of <paramref name="blob"/> with its <c>dwFlags</c> replaced by <paramref name="flags"/>.</summary>
    internal static byte[] WithFlags(ReadOnlySpan<byte> blob, uint flags)
    {
        var copy = blob.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(FlagsOffset), flags);
        return copy;
    }

    /// <summary>A copy of <paramref name="blob"/> with its <c>dwVersion</c> replaced by <paramref name="version"/>.</summary>
    internal static byte[] WithVersion(ReadOnlySpan<byte> blob, uint version)
    {
        var copy = blob.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(copy, version);
        return copy;
    }

    private static (byte[]? Data, int Error) Call(bool protect, ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy, uint flags)
    {
        var input = Allocate(data);
        var salt = Allocate(entropy);
        var output = default(DataBlob);
        try
        {
            var ok = protect
                ? CryptProtectData(ref input, IntPtr.Zero, ref salt, IntPtr.Zero, IntPtr.Zero, flags, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref salt, IntPtr.Zero, IntPtr.Zero, flags, out output);
            if (!ok)
                return (null, Marshal.GetLastPInvokeError());

            var result = new byte[output.Length];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return (result, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(input.Data);
            Marshal.FreeHGlobal(salt.Data);
            if (output.Data != IntPtr.Zero)
                LocalFree(output.Data);
        }
    }

    // An unmanaged copy of `bytes` (freed by the caller); an empty span is a zero-length blob with no data.
    private static DataBlob Allocate(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
            return default;
        var memory = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes.ToArray(), 0, memory, bytes.Length);
        return new DataBlob { Length = (uint)bytes.Length, Data = memory };
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptProtectData(ref DataBlob dataIn, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptUnprotectData(ref DataBlob dataIn, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
    #endregion

    #region Nested types
    // DATA_BLOB (dpapi.h).
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public uint Length;
        public IntPtr Data;
    }
    #endregion

    #region Fields
    internal const uint UiForbidden = 0x1;      // CRYPTPROTECT_UI_FORBIDDEN
    internal const uint LocalMachine = 0x4;     // CRYPTPROTECT_LOCAL_MACHINE
    internal const int FlagsOffset = 40;        // DPAPI_BLOB.dwFlags, as measured (WindowsSecurityNative.UserScope's layout)
    internal const int HeaderBytes = 44;        // dwVersion .. dwFlags: what UserScope reads

    /// <summary>NTE_BAD_KEY_STATE, what clearing the machine bit was measured to give (review C1).</summary>
    internal const int NteBadKeyState = unchecked((int)0x8009000B);
    #endregion
}

/// <summary>
/// <c>GetNamedSecurityInfoW</c> called raw, with the path exactly as given: the precondition of the long-path tests (N1),
/// that WITHOUT the extended-length form Windows refuses a path longer than <c>MAX_PATH</c>.
/// </summary>
internal static class RawNamedSecurity
{
    #region Methods
    /// <summary>The Win32 error of reading <paramref name="path"/>'s owner and DACL by that exact name (0 when it worked).</summary>
    internal static uint Read(string path)
    {
        var error = GetNamedSecurityInfoW(path, FileObject, OwnerAndDacl, out _, out _, out _, out _, out var descriptor);
        if (descriptor != IntPtr.Zero)
            LocalFree(descriptor);
        return error;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetNamedSecurityInfoW(string objectName, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
    #endregion

    #region Fields
    internal const uint InvalidName = 123;     // ERROR_INVALID_NAME, what an unprefixed long path was measured to give
    private const int FileObject = 1;          // SE_FILE_OBJECT
    private const uint OwnerAndDacl = 0x1 | 0x4;
    #endregion
}
#endif
