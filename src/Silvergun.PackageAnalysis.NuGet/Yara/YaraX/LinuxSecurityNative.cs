#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

/// <summary>A file's type, permissions, owner, link count and identity, as <c>statx</c> reports them.</summary>
internal readonly record struct LinuxFileStatus(uint Mode, uint Uid, uint Links, ulong Device, ulong Inode)
{
    #region Properties
    internal bool IsDirectory => (Mode & TypeMask) == DirectoryType;

    internal bool IsRegularFile => (Mode & TypeMask) == RegularType;

    /// <summary>The permission bits, with set-uid, set-gid and sticky (<c>07777</c>).</summary>
    internal UnixFileMode Permissions => (UnixFileMode)(Mode & 0xFFF);
    #endregion

    #region Fields
    private const uint TypeMask = 0xF000;       // S_IFMT
    private const uint DirectoryType = 0x4000;  // S_IFDIR
    private const uint RegularType = 0x8000;    // S_IFREG
    #endregion
}

/// <summary>
/// What the Linux rules cache (<see cref="YaraXLinuxRulesCache"/>) needs from the kernel that .NET does not expose: a
/// file's owner, mode, link count and identity, by path WITHOUT following a link (lstat semantics) or on an open handle
/// (fstat semantics), and the effective uid. Through glibc's <c>statx</c> (glibc 2.28, Linux 4.11): <c>struct statx</c>
/// has one fixed layout on every architecture, unlike <c>struct stat</c> (docs/agent/tasks/yarax-worker-linux.md,
/// Phase 2). <c>libc.so.6</c> is looked up by the system loader, never in the application directory (no
/// <see cref="DllImportSearchPath.AssemblyDirectory"/>); it is already loaded in every glibc process.
/// </summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LinuxSecurityNative
{
    #region Methods
    /// <summary>
    /// The status of <paramref name="path"/> itself (a link is not followed), or <c>null</c> when it does not exist.
    /// Throws on any other failure.
    /// </summary>
    internal static LinuxFileStatus? Lstat(string path) => Statx(AtFdCwd, path, AtSymlinkNoFollow, missingIsNull: true);

    /// <summary>The status of the file open on <paramref name="handle"/>. Throws on failure.</summary>
    internal static LinuxFileStatus Fstat(SafeFileHandle handle)
    {
        var added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            return Statx((int)handle.DangerousGetHandle(), "", AtEmptyPath, missingIsNull: false) ?? throw new UnreachableException();
        }
        finally
        {
            if (added)
                handle.DangerousRelease();
        }
    }

    /// <summary>This process's effective uid: the owner of every file it creates.</summary>
    internal static uint EffectiveUid() => geteuid();

    private static LinuxFileStatus? Statx(int dirfd, string path, int flags, bool missingIsNull)
    {
        byte* buffer = stackalloc byte[StatxBytes];
        if (statx(dirfd, path, flags, RequiredMask, buffer) != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            return errno == NoEntry && missingIsNull ? null : throw new Win32Exception(errno);
        }

        var stx = new ReadOnlySpan<byte>(buffer, StatxBytes);
        if ((Read<uint>(stx, MaskOffset) & RequiredMask) != RequiredMask)
            throw new IOException("statx did not report the file's type, mode, owner, link count and inode");

        return new(Read<ushort>(stx, ModeOffset), Read<uint>(stx, UidOffset), Read<uint>(stx, NlinkOffset),
            ((ulong)Read<uint>(stx, DevMajorOffset) << 32) | Read<uint>(stx, DevMinorOffset), Read<ulong>(stx, InoOffset));
    }

    // statx fields are in native byte order.
    private static T Read<T>(ReadOnlySpan<byte> stx, int offset) where T : unmanaged => MemoryMarshal.Read<T>(stx[offset..]);

    [LibraryImport("libc.so.6", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int statx(int dirfd, string pathname, int flags, uint mask, byte* statxbuf);

    [LibraryImport("libc.so.6")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial uint geteuid();
    #endregion

    #region Fields
    private const int NoEntry = 2;                 // ENOENT
    private const int AtFdCwd = -100;              // AT_FDCWD
    private const int AtSymlinkNoFollow = 0x100;   // AT_SYMLINK_NOFOLLOW
    private const int AtEmptyPath = 0x1000;        // AT_EMPTY_PATH

    // STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_INO
    private const uint RequiredMask = 0x1 | 0x2 | 0x4 | 0x8 | 0x100;

    // struct statx (linux/stat.h): 256 bytes, the same on every architecture.
    private const int StatxBytes = 256;
    private const int MaskOffset = 0;        // __u32 stx_mask
    private const int NlinkOffset = 16;      // __u32 stx_nlink
    private const int UidOffset = 20;        // __u32 stx_uid
    private const int ModeOffset = 28;       // __u16 stx_mode
    private const int InoOffset = 32;        // __u64 stx_ino
    private const int DevMajorOffset = 136;  // __u32 stx_dev_major
    private const int DevMinorOffset = 140;  // __u32 stx_dev_minor
    #endregion
}
#endif
