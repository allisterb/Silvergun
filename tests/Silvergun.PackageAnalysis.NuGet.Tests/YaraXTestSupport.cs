#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

using Microsoft.Win32.SafeHandles;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// Shared helpers for the YARA-X C API binding tests (ADR 0033 T2): the engine is loaded once per test process from the
/// test output directory (the pinned <c>yara_x_capi.dll</c> is copied there by the product's csproj), and every ruleset is
/// a small synthetic one, compiled in milliseconds. The rules never match malware: each "positive" is a random 32-byte
/// marker the test writes itself, the same construction as the binding's own canary (and nothing Defender would flag).
/// </summary>
internal static class YaraX
{
    #region Methods
    /// <summary>Loads the engine for this process, failing the test (never skipping it) when the DLL is unavailable.</summary>
    internal static void EnsureEngine()
    {
        var loaded = YaraXNative.TryLoad(out var failure);
        Assert.True(loaded,
            $"The YARA-X engine did not load in the test host: {failure}. It is installed by build/fetch-yara.ps1 -Engine YaraXCapi "
            + "and copied next to the net10.0-windows test assembly by the product's csproj; a missing DLL is a red build, not a skip.");
    }

    /// <summary>Compiles <paramref name="sources"/> (one rule source per entry) plus a fresh canary; asserts it compiled.</summary>
    internal static YaraXRules Compile(params string[] sources)
    {
        EnsureEngine();
        var rules = YaraXRules.Compile(Sources(sources), out var failure);
        Assert.True(rules is not null, $"the test rules did not compile: {failure}");
        return rules!;
    }

    internal static IReadOnlyList<(string Name, string Text)> Sources(params string[] sources) =>
        sources.Select((text, i) => ($"test-{i}.yar", text)).ToArray();

    /// <summary>32 random bytes: a marker no other test, file or rule will contain.</summary>
    internal static byte[] Marker() => RandomNumberGenerator.GetBytes(32);

    /// <summary>A rule that matches exactly <paramref name="marker"/> (a hex string), optionally tagged.</summary>
    internal static string MarkerRule(string name, byte[] marker, params string[] tags) =>
        $"rule {name}{(tags.Length > 0 ? " : " + string.Join(" ", tags) : "")} {{ strings: $m = {{ {Convert.ToHexString(marker)} }} condition: $m }}";

    /// <summary>
    /// The C API spike's slow rule (<c>data/results/yara-x-capi-spike-2026-10-21.md</c>, Q2): a nested loop over
    /// every byte pair. On zeros it never matches, so its cost is quadratic in the input: 18,212 bytes took ~6 s untimed.
    /// </summary>
    internal const string SlowRule =
        "rule slow_quadratic { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( uint8(i) == 1 and uint8(j) == 2 ) ) }";

    /// <summary>The rule names in <paramref name="result"/>, asserting it is a <see cref="YaraXScanResult.Scanned"/>.</summary>
    internal static string[] Hits(YaraXScanResult result) =>
        Assert.IsType<YaraXScanResult.Scanned>(result).Hits.Select(h => h.Rule).ToArray();
    #endregion
}

/// <summary>
/// A temp directory named <c>silvergun-yara-x-…</c> (so the suite's temp-leak check counts it), removed through its
/// <c>\\?\</c> form so entries named like DOS devices (<c>NUL</c>, <c>CON</c>) and junctions inside it are deleted as
/// themselves.
/// </summary>
internal sealed class YaraXTempDir : IDisposable
{
    #region Constructors
    public YaraXTempDir(string purpose)
    {
        Root = Path.Combine(Path.GetTempPath(), $"silvergun-yara-x-{purpose}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Root);
    }
    #endregion

    #region Properties
    public string Root { get; }
    #endregion

    #region Methods
    public string Combine(string name) => Path.Combine(Root, name);

    // Retried briefly: a just-written entry can still be delete-pending (another handle, e.g. an on-access scanner, has it
    // open), which leaves its parent "not empty" for a moment. Measured: without the retry, empty roots were left behind.
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
                Thread.Sleep(100);   // best-effort temp cleanup; the suite's temp-leak check counts what remains
            }
        }
    }
    #endregion
}

/// <summary>Win32 file-system operations the BCL does not expose: sparse files and directory junctions.</summary>
internal static class WindowsFileSystem
{
    #region Methods
    /// <summary>Marks an open file sparse, so a multi-GiB length costs no disk space and no zero-fill.</summary>
    internal static void SetSparse(SafeFileHandle file)
    {
        if (!DeviceIoControl(file, FsctlSetSparse, null, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_SET_SPARSE failed");
    }

    /// <summary>
    /// Creates <paramref name="link"/> as a directory junction (a mount-point reparse point) to <paramref name="target"/>.
    /// Unlike a symbolic link, a junction needs no privilege, so this works for an ordinary user.
    /// </summary>
    internal static void CreateJunction(string link, string target)
    {
        Directory.CreateDirectory(link);
        var substitute = Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target));
        var print = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        var pathBuffer = substitute.Concat(new byte[2]).Concat(print).Concat(new byte[2]).ToArray();

        var buffer = new byte[16 + pathBuffer.Length];
        BitConverter.GetBytes(IoReparseTagMountPoint).CopyTo(buffer, 0);
        BitConverter.GetBytes((ushort)(8 + pathBuffer.Length)).CopyTo(buffer, 4);
        BitConverter.GetBytes((ushort)0).CopyTo(buffer, 8);                          // substitute name offset
        BitConverter.GetBytes((ushort)substitute.Length).CopyTo(buffer, 10);
        BitConverter.GetBytes((ushort)(substitute.Length + 2)).CopyTo(buffer, 12);   // print name offset
        BitConverter.GetBytes((ushort)print.Length).CopyTo(buffer, 14);
        pathBuffer.CopyTo(buffer, 16);

        using var handle = CreateFileW(link, GenericWrite, 0, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not open '{link}' to make it a junction");
        if (!DeviceIoControl(handle, FsctlSetReparsePoint, buffer, buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_SET_REPARSE_POINT failed");
    }

    /// <summary>
    /// Makes the existing FILE <paramref name="file"/> a reparse point with a third-party (non-Microsoft, non-name-surrogate)
    /// tag and a GUID buffer. Unlike a file symbolic link this needs no privilege and no Developer Mode, so it is how an
    /// ordinary user stages "a cache entry that is a reparse point": the file still exists as a file (File.Exists is true),
    /// but no filter owns the tag, so opening it without FILE_FLAG_OPEN_REPARSE_POINT fails. Deleting it deletes the
    /// reparse point itself.
    /// </summary>
    internal static void SetOpaqueReparsePoint(string file)
    {
        var data = new byte[8];
        var buffer = new byte[24 + data.Length];
        BitConverter.GetBytes(OpaqueReparseTag).CopyTo(buffer, 0);
        BitConverter.GetBytes((ushort)data.Length).CopyTo(buffer, 4);
        BitConverter.GetBytes((ushort)0).CopyTo(buffer, 6);
        OpaqueReparseGuid.ToByteArray().CopyTo(buffer, 8);
        data.CopyTo(buffer, 24);

        using var handle = CreateFileW(file, GenericWrite, 0, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"could not open '{file}' to make it a reparse point");
        if (!DeviceIoControl(handle, FsctlSetReparsePoint, buffer, buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_SET_REPARSE_POINT (opaque tag) failed");
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[]? input, int inputSize, IntPtr output, int outputSize, out int returned, IntPtr overlapped);
    #endregion

    #region Fields
    private const uint FsctlSetSparse = 0x000900C4;
    private const uint FsctlSetReparsePoint = 0x000900A4;
    private const uint IoReparseTagMountPoint = 0xA0000003;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    // A third-party tag: bit 31 (Microsoft) and bit 29 (name surrogate) clear, so it is neither a link the OS follows nor
    // a tag that needs a privilege to set.
    private const uint OpaqueReparseTag = 0x00005347;
    private static readonly Guid OpaqueReparseGuid = new("5c8f6f2e-6b1d-4c43-9d0e-2a7c3e9b1f42");
    #endregion
}

/// <summary>
/// A <see cref="FactAttribute"/> that runs only under an elevated (administrator) token, and is otherwise a VISIBLE skip
/// with the reason, never an early-return "pass". For the S1 case of a rules-cache entry owned by someone other than the
/// user: a non-elevated token can name only the user itself as an object's owner (no group in it carries the owner
/// attribute), so such an entry cannot be staged without elevation (where BUILTIN\Administrators may be named), a second
/// account, or SeRestorePrivilege. No real system file is ever used instead.
/// </summary>
public sealed class ElevatedWindowsFactAttribute : FactAttribute
{
    #region Constructors
    public ElevatedWindowsFactAttribute()
    {
        if (!IsElevated())
            Skip = "S1 (ADR 0033 polish round): staging a rules-cache entry that is NOT owned by the current user needs an elevated "
                 + "token (to name BUILTIN\\Administrators as its owner), SeRestorePrivilege or a second account; this process is "
                 + "not elevated. Run the net10.0-windows suite from an elevated prompt for this to execute.";
    }
    #endregion

    #region Properties
    /// <summary>
    /// What the test needs elevation for, when it is not the S1 case above (e.g. an entry stored under an elevated token,
    /// whose default owner can be BUILTIN\Administrators): replaces the skip reason's wording. The test still skips
    /// visibly when not elevated.
    /// </summary>
    public string? Needs
    {
        get => _needs;
        set
        {
            _needs = value;
            if (Skip is not null && value is not null)
                Skip = $"needs an elevated token: {value}. This process is not elevated; run the net10.0-windows suite from an elevated prompt for this to execute.";
        }
    }
    #endregion

    #region Methods
    internal static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
    #endregion

    #region Fields
    private string? _needs;
    #endregion
}
#endif
