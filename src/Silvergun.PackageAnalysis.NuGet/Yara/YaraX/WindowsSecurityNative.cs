#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// The Windows security calls <see cref="YaraXRulesCache"/> makes natively (ADR 0033 amendment, "Finding"; task
/// <c>yarax-worker.md</c>, "DPAPI entry binding"): DPAPI, and the RAW security descriptor of a file or directory.
/// <see cref="Protect"/> makes CurrentUser blobs; <see cref="Unprotect"/> accepts only those. <c>CryptUnprotectData</c>
/// alone does not bind anything to this user: it takes the key from the blob, and a machine-scope blob
/// (<c>CRYPTPROTECT_LOCAL_MACHINE</c>), which ANY local user can make, unprotects for every user on the machine (review C1).
/// So <see cref="Unprotect"/> also refuses, after DPAPI has verified it, every blob that is not user-scope. Together: a
/// blob is accepted only when this user's DPAPI key made it. <see cref="FileSecurity"/> and <see cref="DirectorySecurity"/>
/// canonicalise the DACL they read (they drop a file's inherit-only ACEs and merge allow ACEs for the same SID), so a
/// check of "exactly one ACE" on them judges a rewritten ACL; the descriptor read here is the one Windows stores.
///
/// <para><b>DLL search.</b> Every import names a System32 DLL and is looked up in System32 only
/// (<see cref="DefaultDllImportSearchPathsAttribute"/>): <see cref="YaraXNative"/>'s import resolver leaves these names to
/// the default search, which looks in the application directory first, and Silvergun runs beside hostile extracted
/// packages. Plain P/Invoke; no package dependency (not <c>System.Security.Cryptography.ProtectedData</c>).</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class WindowsSecurityNative
{
    #region Methods
    /// <summary>
    /// <c>CryptProtectData</c> of <paramref name="data"/> for the current user, with <paramref name="entropy"/>, no prompt
    /// (<c>CRYPTPROTECT_UI_FORBIDDEN</c>) and no description: the protected blob, or <c>null</c> with the reason.
    /// </summary>
    internal static byte[]? Protect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy, out string? failure) =>
        Dpapi(protect: true, data, entropy, out failure);

    /// <summary>
    /// <c>CryptUnprotectData</c> of <paramref name="blob"/> with <paramref name="entropy"/> and no prompt, accepted only
    /// for a CurrentUser blob (<see cref="UserScope"/>): the data it protects, or <c>null</c> with the reason (corrupt,
    /// another user's, other entropy, …, or <see cref="NotUserScope"/> for a blob DPAPI unprotects that is not bound to
    /// this user). The native output is zeroed before it is freed, and the managed copy too when the blob is refused.
    /// </summary>
    internal static byte[]? Unprotect(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> entropy, out string? failure)
    {
        var data = Dpapi(protect: false, blob, entropy, out failure);
        if (data is null || UserScope(blob))
            return data;

        CryptographicOperations.ZeroMemory(data);
        failure = NotUserScope;
        return null;
    }

    // C1: true when `blob`, which DPAPI has just unprotected, is a CurrentUser blob. CryptUnprotectData takes its key from
    // the blob, so a CRYPTPROTECT_LOCAL_MACHINE blob, which any local user can make (and our entropy is public),
    // unprotects for everyone; that is refused here. The DPAPI_BLOB layout, as measured (review C1, 2026-10-23):
    //   0   4  dwVersion (u32 LE), 1
    //   4  16  guidProvider
    //  20   4  dwMasterKeyVersion
    //  24  16  guidMasterKey
    //  40   4  dwFlags (u32 LE): the CryptProtectData flags, 0x4 (CRYPTPROTECT_LOCAL_MACHINE) for a machine blob
    // This couples us to an undocumented layout, which is acceptable because every surprise fails closed: a blob that is
    // shorter, of another version, or flagged machine-scope is refused, and a refusal is only a cache miss (the rules are
    // recompiled). The length and version arms are defence in depth: DPAPI itself rejects a dwVersion other than 1
    // (error 13) and a short blob (error 87) before this runs, so in practice those arrive as "CryptUnprotectData failed".
    // It cannot be bypassed by editing the blob: dwFlags is covered by DPAPI's HMAC, and it is read only after DPAPI has
    // verified it. Measured (DPAPI scope fix review, round 2): flipping 0x10 in a machine blob's dwFlags makes
    // CryptUnprotectData fail with ERROR_INVALID_DATA (13), and so does clearing 0x4 AND writing in the user's own
    // master-key GUID, the only way past the master-key store lookup. The documented alternative, DPAPI-NG
    // (NCryptProtectSecret with the "LOCAL=user" descriptor, checked on unprotect), gives the same property with more
    // interop, and is not taken (ADR 0033 amendment, "Why it holds, CORRECTED 2026-10-23").
    private static bool UserScope(ReadOnlySpan<byte> blob) =>
        blob.Length >= BlobFlagsOffset + sizeof(uint)
            && BinaryPrimitives.ReadUInt32LittleEndian(blob) == BlobVersion
            && (BinaryPrimitives.ReadUInt32LittleEndian(blob[BlobFlagsOffset..]) & LocalMachine) == 0;

    /// <summary>
    /// The owner and DACL of the file or directory open as <paramref name="handle"/>, read on that handle
    /// (<c>GetSecurityInfo</c>), exactly as stored. Throws <see cref="UnauthorizedAccessException"/> or
    /// <see cref="Win32Exception"/> when it cannot be read, <see cref="InvalidDataException"/> when Windows returns no
    /// descriptor or one that is not self-relative, and <see cref="ArgumentException"/> (from
    /// <see cref="RawSecurityDescriptor"/>) for an ACE .NET cannot parse.
    /// </summary>
    internal static RawSecurityDescriptor Descriptor(SafeFileHandle handle) =>
        Descriptor(GetSecurityInfo(handle, FileObject, OwnerAndDacl, out _, out _, out _, out _, out var descriptor), descriptor, nameof(GetSecurityInfo));

    /// <summary>
    /// The owner and DACL of the file or directory at <paramref name="path"/>, read by path (<c>GetNamedSecurityInfoW</c>),
    /// exactly as stored. The path is passed in its extended-length form (<see cref="ExtendedLength"/>), so a path longer
    /// than <c>MAX_PATH</c> is read too. Throws as <see cref="Descriptor(SafeFileHandle)"/> does.
    /// </summary>
    internal static RawSecurityDescriptor Descriptor(string path) =>
        Descriptor(GetNamedSecurityInfoW(ExtendedLength(path), FileObject, OwnerAndDacl, out _, out _, out _, out _, out var descriptor), descriptor, "GetNamedSecurityInfo");

    // N1: GetNamedSecurityInfoW fails beyond MAX_PATH (error 123, measured on a 487-character directory) unless the path
    // is extended-length: \\?\ + the full path, or \\?\UNC\server\share\… for a UNC path. A path that is already
    // extended-length, or a \\.\ device path, is passed as it is (GetFullPath leaves both prefixes in place). A \\.\ path
    // therefore keeps the MAX_PATH limit, which fails closed: a longer one is not read, and Descriptor throws.
    private static string ExtendedLength(string path) =>
        Path.GetFullPath(path) switch
        {
            var full when full.StartsWith(@"\\?\", StringComparison.Ordinal) || full.StartsWith(@"\\.\", StringComparison.Ordinal) => full,
            var full when full.StartsWith(@"\\", StringComparison.Ordinal) => @"\\?\UNC\" + full[2..],
            var full => @"\\?\" + full,
        };

    private static byte[]? Dpapi(bool protect, ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy, out string? failure)
    {
        fixed (byte* dataBytes = data, entropyBytes = entropy)
        {
            var input = new DataBlob { length = (uint)data.Length, data = (nint)dataBytes };
            var salt = new DataBlob { length = (uint)entropy.Length, data = (nint)entropyBytes };
            var output = default(DataBlob);
            try
            {
                var ok = protect
                    ? CryptProtectData(&input, 0, &salt, 0, 0, UiForbidden, &output)
                    : CryptUnprotectData(&input, 0, &salt, 0, 0, UiForbidden, &output);
                if (!ok)
                {
                    failure = Failure(protect ? nameof(CryptProtectData) : nameof(CryptUnprotectData), Marshal.GetLastPInvokeError());
                    return null;
                }

                var bytes = new Span<byte>((void*)output.data, checked((int)output.length));
                var result = bytes.ToArray();
                if (!protect)
                    bytes.Clear();
                failure = null;
                return result;
            }
            finally
            {
                if (output.data != 0)
                    LocalFree(output.data);
            }
        }
    }

    // `error` is GetSecurityInfo's or GetNamedSecurityInfoW's result: 0, and `descriptor` is a self-relative descriptor
    // (freed here), or a Win32 error code, and nothing was allocated. Never trusted on failure: it throws. N5: the control
    // word (SECURITY_DESCRIPTOR.Control, a u16 at offset 2, after the revision and Sbz1 bytes) is checked for
    // SE_SELF_RELATIVE BEFORE GetSecurityDescriptorLength, which is only meaningful for a self-relative descriptor.
    private static RawSecurityDescriptor Descriptor(uint error, nint descriptor, string call)
    {
        if (error != 0)
            throw error == AccessDenied
                ? new UnauthorizedAccessException($"{call} failed: access is denied (error {error}).")
                : new Win32Exception((int)error, Failure(call, (int)error));

        try
        {
            if (descriptor == 0)
                throw new InvalidDataException($"{call} returned no security descriptor.");
            if ((*(ushort*)(descriptor + 2) & SelfRelative) == 0)
                throw new InvalidDataException($"{call} returned a security descriptor that is not self-relative.");
            var bytes = new ReadOnlySpan<byte>((void*)descriptor, checked((int)GetSecurityDescriptorLength(descriptor))).ToArray();
            return new RawSecurityDescriptor(bytes, 0);
        }
        finally
        {
            if (descriptor != 0)
                LocalFree(descriptor);
        }
    }

    private static string Failure(string call, int error) => $"{call} failed: {new Win32Exception(error).Message} (error {error})";

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptProtectData(DataBlob* dataIn, nint description, DataBlob* entropy, nint reserved, nint prompt, uint flags, DataBlob* dataOut);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptUnprotectData(DataBlob* dataIn, nint description, DataBlob* entropy, nint reserved, nint prompt, uint flags, DataBlob* dataOut);

    [LibraryImport("advapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        out nint owner, out nint group, out nint dacl, out nint sacl, out nint securityDescriptor);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetNamedSecurityInfoW(string objectName, int objectType, uint securityInfo,
        out nint owner, out nint group, out nint dacl, out nint sacl, out nint securityDescriptor);

    [LibraryImport("advapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetSecurityDescriptorLength(nint securityDescriptor);

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint LocalFree(nint memory);
    #endregion

    #region Fields
    /// <summary>
    /// <see cref="Unprotect"/>'s failure for a blob DPAPI unprotected but that is not bound to this user (C1).
    /// </summary>
    internal const string NotUserScope =
        "it is not bound to this user (a machine-scope DPAPI blob, which any local user can make, or a DPAPI blob layout Silvergun does not recognise)";

    private const uint UiForbidden = 0x1;                // CRYPTPROTECT_UI_FORBIDDEN
    private const uint LocalMachine = 0x4;               // CRYPTPROTECT_LOCAL_MACHINE, in the blob's dwFlags
    private const uint BlobVersion = 1;                  // DPAPI_BLOB.dwVersion
    private const int BlobFlagsOffset = 40;              // DPAPI_BLOB.dwFlags (UserScope)
    private const int FileObject = 1;                    // SE_FILE_OBJECT
    private const uint OwnerAndDacl = 0x1 | 0x4;         // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    private const uint AccessDenied = 5;                 // ERROR_ACCESS_DENIED
    private const ushort SelfRelative = 0x8000;          // SE_SELF_RELATIVE
    #endregion

    #region Child types
    // DATA_BLOB (dpapi.h).
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        #region Fields
        internal uint length;
        internal nint data;
        #endregion
    }
    #endregion
}
#endif
