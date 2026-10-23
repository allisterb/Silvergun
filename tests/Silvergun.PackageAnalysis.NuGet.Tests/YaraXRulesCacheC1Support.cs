#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;

/// <summary>
/// A fixture root that ONLY the user controls (review C1): <c>C:\Temp\sg-c1-&lt;purpose&gt;-&lt;guid&gt;</c>, created in one
/// step with a PROTECTED DACL granting full control to the user, LocalSystem and Administrators and nobody else. It must
/// not inherit <c>C:\Temp</c>'s ACEs: there, Authenticated Users get an inheritable write/delete grant
/// (<c>(A;OICIIOID;SDGXGWGR;;;AU)</c> on this machine). Every directory created inside it inherits only those trusted
/// ACEs, so whatever a test stages there is caused by the ACE the test adds itself. (It was made for the configured cache
/// location, removed by the ADR 0033 amendment of 2026-10-22; the rules-cache tests still stage their directories here.)
/// Never under <c>%TEMP%</c>, never a real shared folder. Removed (recursively, through its <c>\\?\</c> form) on dispose.
/// </summary>
internal sealed class ControlledTempDir : IDisposable
{
    #region Constructors
    public ControlledTempDir(string purpose)
    {
        Root = Path.Combine(Base, $"sg-c1-{purpose}-{Guid.NewGuid():N}");
        using var identity = WindowsIdentity.GetCurrent();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { identity.User!, Sids.System, Sids.Administrators })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(Root).Create(security);
        // Written again through SetNamedSecurityInfo (what SetAccessControl uses), which marks the DACL auto-inherited
        // (D:PAI): directories created inside then carry their ACEs as INHERITED (ID), as real ones under C:\Temp do.
        new DirectoryInfo(Root).SetAccessControl(security);
    }
    #endregion

    #region Properties
    public string Root { get; }
    #endregion

    #region Methods
    public string Combine(string name) => Path.Combine(Root, name);

    /// <summary>Creates <paramref name="name"/> under the root (inheriting only the trusted ACEs); its full path.</summary>
    public string CreateDirectory(string name) => Directory.CreateDirectory(Combine(name)).FullName;

    // Retried briefly, as YaraXTempDir does: a just-written entry can still be delete-pending for a moment. A test may have
    // left a DACL that keeps even the user out (or a quarantine); the owner's implicit WRITE_DAC always allows resetting
    // it, so a refused delete first gives the user back full control over everything below the root, top-down.
    public void Dispose()
    {
        for (var attempt = 0; attempt < 20 && Directory.Exists(Root); attempt++)
        {
            try
            {
                Directory.Delete(@"\\?\" + Root, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (ex is UnauthorizedAccessException)
                    Unlock(Root);
                Thread.Sleep(100);
            }
        }
    }

    // Best effort: full control for the user on `path` and (once it can be listed) everything in it. Links are not followed.
    private static void Unlock(string path)
    {
        try
        {
            RawAcl.SetDacl(path, RawAcl.OwnerOnlyDacl());
        }
        catch (Win32Exception)
        {
            // not ours to unlock, or gone
        }

        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            return;
        try
        {
            foreach (var child in Directory.EnumerateFileSystemEntries(path))
                Unlock(child);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // best effort
        }
    }
    #endregion

    #region Fields
    /// <summary>Where every fixture root lives (the task's rule: under C:\Temp, never %TEMP%).</summary>
    internal const string Base = @"C:\Temp";
    #endregion
}

/// <summary>The SIDs these tests name.</summary>
internal static class Sids
{
    internal static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    internal static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    internal static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    internal static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    internal static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    internal static SecurityIdentifier User()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User!;
    }
}

/// <summary>
/// Raw security descriptors, read and written through Win32 (<c>GetFileSecurityW</c>/<c>SetFileSecurityW</c>) rather than
/// <see cref="DirectorySecurity"/>, so an ACE .NET does not model (a conditional/callback <c>XA</c> ACE) or a null DACL
/// reaches the disk exactly as written, and a before/after comparison sees every ACE.
/// </summary>
internal static class RawAcl
{
    #region Methods
    /// <summary>
    /// Replaces <paramref name="path"/>'s DACL with the one in <paramref name="sddl"/> (e.g. <c>D:P(A;OICI;FA;;;&lt;sid&gt;)</c>,
    /// <c>D:NO_ACCESS_CONTROL</c>), protected when the SDDL says <c>P</c>. Only the DACL is written, which the owner's
    /// implicit WRITE_DAC always allows.
    /// </summary>
    internal static void SetDacl(string path, string sddl)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not parse the SDDL '{sddl}'");
        try
        {
            var isProtected = sddl.StartsWith("D:P", StringComparison.Ordinal) || sddl.Contains("D:P(", StringComparison.Ordinal);
            var info = DaclSecurityInformation | (isProtected ? ProtectedDaclSecurityInformation : UnprotectedDaclSecurityInformation);
            if (!SetFileSecurityW(path, info, descriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not set the DACL '{sddl}' on '{path}'");
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    /// <summary>
    /// Writes <paramref name="selfRelative"/> (a self-relative security descriptor in binary form) as
    /// <paramref name="path"/>'s DACL, protected. For ACEs that SDDL cannot express (a custom ACE type, a compound ACE):
    /// the bytes reach the disk exactly as built, without going through .NET's ACL model, which cannot represent them.
    /// </summary>
    internal static void SetDaclBytes(string path, byte[] selfRelative)
    {
        if (!SetFileSecurityBytes(path, DaclSecurityInformation | ProtectedDaclSecurityInformation, selfRelative))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not set a raw DACL on '{path}'");
    }

    /// <summary>
    /// <paramref name="path"/>'s owner, group and DACL exactly as Windows returns them (<c>GetFileSecurityW</c>), as hex.
    /// Nothing parses them, so this compares descriptors that neither .NET nor SDDL can render.
    /// </summary>
    internal static string Bytes(string path) => Convert.ToHexString(Buffer(path));

    /// <summary>The owner, group and DACL of <paramref name="path"/> as SDDL, from its raw descriptor.</summary>
    internal static string Sddl(string path, AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access) =>
        Descriptor(path).GetSddlForm(sections);

    /// <summary><paramref name="path"/>'s raw descriptor (owner, group and DACL).</summary>
    internal static RawSecurityDescriptor Descriptor(string path) => new(Buffer(path), 0);

    private static byte[] Buffer(string path)
    {
        const uint info = OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation;
        GetFileSecurityW(path, info, null, 0, out var needed);
        if (needed == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not size the security descriptor of '{path}'");
        var buffer = new byte[needed];
        if (!GetFileSecurityW(path, info, buffer, needed, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not read the security descriptor of '{path}'");
        return buffer;
    }

    /// <summary>
    /// The DACL of <paramref name="sddl"/> in normalised form: rendered by Windows (so <c>FA</c> and <c>0x1f01ff</c> compare
    /// equal), ACEs as stored, and of the DACL control bits only "protected" kept. The auto-inherit bits (<c>AI</c>,
    /// <c>AR</c>) record how the DACL was written (SetNamedSecurityInfo sets <c>AI</c>), not who has access.
    /// </summary>
    internal static string Normalized(string sddl) => NormalizedDacl(new RawSecurityDescriptor(sddl));

    /// <summary><paramref name="path"/>'s DACL, normalised as <see cref="Normalized"/> does.</summary>
    internal static string Dacl(string path) => NormalizedDacl(Descriptor(path));

    private static string NormalizedDacl(RawSecurityDescriptor descriptor) =>
        new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected),
            null, null, null, descriptor.DiscretionaryAcl).GetSddlForm(AccessControlSections.Access);

    /// <summary>The trusted owner-only DACL the cache builds, for the current user: <c>D:P(A;OICI;FA;;;&lt;user&gt;)</c>.</summary>
    internal static string OwnerOnlyDacl() => $"D:P(A;OICI;FA;;;{Sids.User().Value})";

    /// <summary>
    /// A real conditional (callback) ACE: allow Everyone full control when the caller is a member of Administrators
    /// (<c>XA</c>). The current, non-elevated user is not (its Administrators group is deny-only), so it changes nothing
    /// for this process; Windows enforces it nevertheless, which is why the cache must not ignore it.
    /// </summary>
    internal const string ConditionalAce = "(XA;;FA;;;WD;(Member_of {SID(BA)}))";

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetFileSecurityW(string path, uint information, IntPtr descriptor);

    [DllImport("advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetFileSecurityBytes(string path, uint information, byte[] descriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetFileSecurityW(string path, uint information, byte[]? descriptor, uint length, out uint needed);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    #endregion

    #region Fields
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint GroupSecurityInformation = 0x00000002;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    private const uint UnprotectedDaclSecurityInformation = 0x20000000;
    #endregion
}

/// <summary>
/// Runs an action with SeRestorePrivilege ENABLED on a dedicated thread's impersonation token, so it can name any SID as an
/// object's owner, without enabling anything process-wide (other tests in this host rely on not holding it). Only an
/// elevated token holds the privilege at all; elsewhere it throws.
/// </summary>
internal static class RestorePrivilege
{
    #region Methods
    internal static void Run(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                if (!ImpersonateSelf(SecurityImpersonation))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ImpersonateSelf failed");
                try
                {
                    if (!OpenThreadToken(GetCurrentThread(), TokenAdjustPrivileges | TokenQuery, true, out var token))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenThreadToken failed");
                    try
                    {
                        if (!LookupPrivilegeValueW(null, "SeRestorePrivilege", out var luid))
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValueW failed");
                        var privileges = new TokenPrivileges { Count = 1, LowPart = luid.LowPart, HighPart = luid.HighPart, Attributes = SePrivilegeEnabled };
                        if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "SeRestorePrivilege could not be enabled (is this token elevated?)");
                    }
                    finally
                    {
                        CloseHandle(token);
                    }

                    action();
                }
                finally
                {
                    RevertToSelf();
                }
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.Start();
        thread.Join();
        if (failure is not null)
            throw new InvalidOperationException($"the privileged action failed: {failure.GetType().Name}: {failure.Message}", failure);
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ImpersonateSelf(int level);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state, uint length, IntPtr previous, IntPtr returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    #endregion

    #region Nested types
    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint Count;
        public uint LowPart;
        public int HighPart;
        public uint Attributes;
    }
    #endregion

    #region Fields
    private const int SecurityImpersonation = 2;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;
    #endregion
}

/// <summary>Snapshots for "nothing changed" assertions.</summary>
internal static class Snapshot
{
    /// <summary>
    /// <paramref name="directory"/>'s raw owner, group and DACL, then every file directly in it (name, sha256, mtime), one
    /// per line: one string, so an assertion compares contents (and prints both sides) rather than array references.
    /// </summary>
    internal static string State(string directory) =>
        string.Join(Environment.NewLine, Files(directory).Prepend(RawAcl.Sddl(directory)));

    /// <summary>Every file directly in <paramref name="directory"/>: name, sha256 and last-write time.</summary>
    internal static string[] Files(string directory) =>
        Directory.GetFiles(directory)
            .Select(f => $"{Path.GetFileName(f)}|{Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f)))}|{File.GetLastWriteTimeUtc(f):O}")
            .Order(StringComparer.Ordinal)
            .ToArray();

    /// <summary>Every entry under <paramref name="root"/> (relative path, and whether it is a directory), links unfollowed.</summary>
    internal static string[] Tree(string root) =>
        Directory.EnumerateFileSystemEntries(root, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 })
            .Select(e => $"{Path.GetRelativePath(root, e)}|{Directory.Exists(e)}")
            .Order(StringComparer.Ordinal)
            .ToArray();
}
#endif
