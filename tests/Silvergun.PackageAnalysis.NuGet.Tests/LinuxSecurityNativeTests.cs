#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

using static LinuxRulesCache;

/// <summary>
/// <see cref="LinuxSecurityNative"/> (docs/agent/tasks/yarax-worker-linux.md, Phase 2, P2): glibc <c>statx</c> read at
/// fixed offsets, checked against what the BCL and coreutils' <c>stat</c> report for the same files. <c>stat</c> without
/// <c>-L</c> does not follow links, which is <see cref="LinuxSecurityNative.Lstat"/>'s contract. Every file is one the
/// test created under its own <c>/tmp</c> tree.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxSecurityNativeTests
{
    #region Methods: mode
    // The whole st_mode, type bits included, equals coreutils' raw mode (%f, hex); the permission bits equal the BCL's.
    [OnLinuxTheory]
    [InlineData(0b110_000_000)]          // 600
    [InlineData(0b110_100_100)]          // 644
    [InlineData(0b111_101_000)]          // 750
    [InlineData(0b111_111_111)]          // 777
    public void Lstat_OfARegularFile_ReportsItsModeAsTheBclAndStatDo(int mode)
    {
        using var tree = new LinuxCacheTree("statx-mode");
        var file = tree.File("file.bin");
        File.SetUnixFileMode(file, (UnixFileMode)mode);

        var status = LinuxSecurityNative.Lstat(file)!.Value;

        Assert.True(status.IsRegularFile);
        Assert.False(status.IsDirectory);
        Assert.Equal(File.GetUnixFileMode(file), status.Permissions);
        Assert.Equal((UnixFileMode)mode, status.Permissions);
        Assert.Equal(uint.Parse(Stat("%f", file), NumberStyles.HexNumber, CultureInfo.InvariantCulture), status.Mode);
    }

    // Directories, special bits included: the sticky /tmp, and a setgid directory of the test's own.
    [OnLinuxFact]
    public void Lstat_OfADirectory_ReportsItsTypeAndSpecialBits()
    {
        using var tree = new LinuxCacheTree("statx-dir");
        var setgid = tree.Dir("setgid", LinuxCacheTree.OwnerOnly | UnixFileMode.SetGroup);

        var tmp = LinuxSecurityNative.Lstat("/tmp")!.Value;
        var own = LinuxSecurityNative.Lstat(setgid)!.Value;

        Assert.True(tmp.IsDirectory);
        Assert.False(tmp.IsRegularFile);
        Assert.Equal(File.GetUnixFileMode("/tmp"), tmp.Permissions);
        Assert.True((tmp.Permissions & UnixFileMode.StickyBit) != 0, "the precondition failed: /tmp is not sticky");
        Assert.Equal(uint.Parse(Stat("%f", "/tmp"), NumberStyles.HexNumber, CultureInfo.InvariantCulture), tmp.Mode);
        Assert.True(own.IsDirectory);
        Assert.Equal(LinuxCacheTree.OwnerOnly | UnixFileMode.SetGroup, own.Permissions);
    }
    #endregion

    #region Methods: owner
    // A file this process created is owned by its effective uid, which coreutils also reports.
    [OnLinuxFact]
    public void Uid_OfAFileThisProcessCreated_IsTheEffectiveUid()
    {
        using var tree = new LinuxCacheTree("statx-uid");
        var file = tree.File("file.bin");

        var status = LinuxSecurityNative.Lstat(file)!.Value;

        Assert.Equal(LinuxSecurityNative.EffectiveUid(), status.Uid);
        Assert.Equal(uint.Parse(Stat("%u", file), CultureInfo.InvariantCulture), status.Uid);
        Assert.Equal(uint.Parse(Stat("%u", tree.Base), CultureInfo.InvariantCulture), LinuxSecurityNative.EffectiveUid());
    }

    // Another owner than this process: `/` is root's (a skip in a user namespace, where it can show as the overflow uid),
    // as coreutils also reports it.
    [OnLinuxOwnershipFact(RootOwnsSystemDirs = true)]
    public void Uid_OfTheRootDirectory_IsZero_AsStatReportsIt()
    {
        var status = LinuxSecurityNative.Lstat("/")!.Value;

        Assert.Equal(0u, status.Uid);
        Assert.Equal(uint.Parse(Stat("%u", "/"), CultureInfo.InvariantCulture), status.Uid);
    }
    #endregion

    #region Methods: links and identity
    // nlink is 1, then 2 for both names after a hard link (by path and on an open handle), and both names are one inode.
    [OnLinuxFact]
    public void Links_AfterAHardLink_AreTwo_AndBothNamesAreOneFile()
    {
        using var tree = new LinuxCacheTree("statx-nlink");
        var file = tree.File("file.bin");
        Assert.Equal(1u, LinuxSecurityNative.Lstat(file)!.Value.Links);
        var link = tree.Path("link.bin");

        HardLink(file, link);
        var named = LinuxSecurityNative.Lstat(file)!.Value;
        var other = LinuxSecurityNative.Lstat(link)!.Value;
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read);
        var opened = LinuxSecurityNative.Fstat(stream.SafeFileHandle);

        Assert.Equal((2u, 2u, 2u), (named.Links, other.Links, opened.Links));
        Assert.Equal(uint.Parse(Stat("%h", file), CultureInfo.InvariantCulture), named.Links);
        Assert.Equal((named.Device, named.Inode), (other.Device, other.Inode));
    }

    // The same file by path and on a handle is one (device, inode), and it is the one coreutils reports (%i; %d is glibc's
    // makedev of statx's major and minor). A second file in the same directory has the same device and another inode.
    [OnLinuxFact]
    public void DeviceAndInode_AreEqualForOneFile_AndDifferForTwo()
    {
        using var tree = new LinuxCacheTree("statx-ino");
        var a = tree.File("a.bin");
        var b = tree.File("b.bin");

        var byPath = LinuxSecurityNative.Lstat(a)!.Value;
        LinuxFileStatus onHandle;
        using (var stream = new FileStream(a, FileMode.Open, FileAccess.Read))
            onHandle = LinuxSecurityNative.Fstat(stream.SafeFileHandle);
        var second = LinuxSecurityNative.Lstat(b)!.Value;

        Assert.Equal((byPath.Device, byPath.Inode), (onHandle.Device, onHandle.Inode));
        Assert.Equal(byPath, onHandle);
        Assert.Equal(ulong.Parse(Stat("%i", a), CultureInfo.InvariantCulture), byPath.Inode);
        Assert.Equal(ulong.Parse(Stat("%d", a), CultureInfo.InvariantCulture), MakeDev(byPath.Device));
        Assert.Equal(byPath.Device, second.Device);
        Assert.NotEqual(byPath.Inode, second.Inode);
    }

    // A handle keeps the inode it opened: after another file is renamed over the path, fstat on the old handle and lstat
    // of the path disagree. That disagreement is what the cache's "replaced while it was being opened" check relies on.
    [OnLinuxFact]
    public void Fstat_OnAHandle_KeepsItsInode_AfterTheNameIsReplaced()
    {
        using var tree = new LinuxCacheTree("statx-replaced");
        var path = tree.File("entry.bin");
        var replacement = tree.File("replacement.bin");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read);
        var before = LinuxSecurityNative.Fstat(stream.SafeFileHandle);

        File.Move(replacement, path, overwrite: true);
        var opened = LinuxSecurityNative.Fstat(stream.SafeFileHandle);
        var named = LinuxSecurityNative.Lstat(path)!.Value;

        Assert.Equal(before.Inode, opened.Inode);
        Assert.NotEqual(opened.Inode, named.Inode);
        Assert.Equal(0u, opened.Links);   // the old name is gone; the open inode has no name left
    }
    #endregion

    #region Methods: what lstat does not follow, and failures
    [OnLinuxFact]
    public void Lstat_OfAMissingPath_IsNull()
    {
        using var tree = new LinuxCacheTree("statx-missing");

        Assert.Null(LinuxSecurityNative.Lstat(tree.Path("not-there")));
        Assert.Null(LinuxSecurityNative.Lstat(tree.Path("not-there/below")));
    }

    // A link is reported as itself (S_IFLNK), never as its target: not a directory for a link to one, not a regular file
    // for a link to one, and not missing for a dangling one.
    [OnLinuxFact]
    public void Lstat_OfASymlink_IsNeitherADirectoryNorARegularFile()
    {
        using var tree = new LinuxCacheTree("statx-symlink");
        var dir = tree.Dir("dir");
        var file = tree.File("file.bin");
        var toDir = tree.Symlink("to-dir", dir);
        var toFile = tree.Symlink("to-file", file);
        var dangling = tree.Symlink("dangling", tree.Path("nowhere"));

        foreach (var link in new[] { toDir, toFile, dangling })
        {
            var status = LinuxSecurityNative.Lstat(link);
            Assert.True(status is not null, $"{link}: a link was reported missing");
            Assert.False(status!.Value.IsDirectory, $"{link}: reported as a directory");
            Assert.False(status.Value.IsRegularFile, $"{link}: reported as a regular file");
            Assert.Equal(0xA000u, status.Value.Mode & 0xF000);   // S_IFLNK
            Assert.Equal(uint.Parse(Stat("%f", link), NumberStyles.HexNumber, CultureInfo.InvariantCulture), status.Value.Mode);
        }
        Assert.True(LinuxSecurityNative.Lstat(dir)!.Value.IsDirectory);   // the control: the target itself is a directory
    }

    // A FIFO is stat'ed, never opened: lstat returns at once (a blocking open would hang this test).
    [OnLinuxFact]
    public async Task Lstat_OfAFifo_IsNeitherADirectoryNorARegularFile_AndDoesNotBlock()
    {
        using var tree = new LinuxCacheTree("statx-fifo");
        var fifo = tree.Path("fifo");
        LinuxYaraX.MakeFifo(fifo);

        var status = await Task.Run(() => LinuxSecurityNative.Lstat(fifo)).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.False(status!.Value.IsDirectory);
        Assert.False(status.Value.IsRegularFile);
        Assert.Equal(0x1000u, status.Value.Mode & 0xF000);   // S_IFIFO
    }

    // "Throws on any other failure": a path through a regular file is ENOTDIR, not "missing".
    [OnLinuxFact]
    public void Lstat_ThroughARegularFile_Throws_NotNull()
    {
        using var tree = new LinuxCacheTree("statx-enotdir");
        var file = tree.File("file.bin");

        var ex = Assert.Throws<Win32Exception>(() => LinuxSecurityNative.Lstat(file + "/below"));

        Assert.Equal(20, ex.NativeErrorCode);   // ENOTDIR
    }
    #endregion

    #region Methods: helpers
    // glibc's makedev, which coreutils prints as %d.
    private static ulong MakeDev(ulong device)
    {
        var (major, minor) = (device >> 32, device & 0xFFFF_FFFF);
        return ((major & 0xFFFF_F000) << 32) | ((major & 0xFFF) << 8) | ((minor & 0xFFFF_FF00) << 12) | (minor & 0xFF);
    }
    #endregion
}
#endif
