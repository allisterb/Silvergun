#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

using Entry = YaraXRulesCacheEntryV3;
using SystemRawAcl = System.Security.AccessControl.RawAcl;

/// <summary>
/// <see cref="WindowsSecurityNative"/>'s descriptor reads (task <c>yarax-worker.md</c>, "DPAPI entry binding", "Also in
/// this round: the raw-DACL fix"). The rules cache judges "exactly one ACE" on what these return, so they must return the
/// DACL exactly as Windows stores it. <see cref="FileSecurity"/> does not (measured, and pinned in
/// <c>YaraXRulesCacheEntryDaclTests.OnThisRuntime_FileSecurity_CanonicalisesAFilesDacl_SoItIsNotTheRawDacl</c>): for a
/// file it drops an inherit-only ACE and merges two allow ACEs for the same SID. Each shape here is written raw
/// (<c>SetFileSecurityW</c>, through <see cref="RawAcl"/>), checked on disk with <c>GetFileSecurityW</c> (two ACEs), checked
/// to be one the .NET view rewrites (so the row discriminates), and then read natively: on the handle
/// (<c>GetSecurityInfo</c>, how an entry is read) and by path (<c>GetNamedSecurityInfoW</c>, how the directory is read).
/// The native DACL must be byte-for-byte the one on disk, and the owner the user. By path, that holds beyond
/// <c>MAX_PATH</c> too, for a drive-letter, an already extended-length and a UNC path (review N1).
///
/// <para><b>DPAPI scope</b> (review C1, 2026-10-23): <see cref="WindowsSecurityNative.Unprotect"/> accepts only a
/// CurrentUser blob. A machine-scope blob, which raw DPAPI unprotects for every local user (each test's precondition), is
/// refused with <see cref="WindowsSecurityNative.NotUserScope"/>; the scope check itself fails closed on every layout it
/// does not recognise; and the DPAPI property it rests on (the scope bit is under DPAPI's HMAC) is pinned as measured.
/// Machine-scope blobs are staged raw (<see cref="RawDpapi"/>): the product cannot make one.</para>
/// </summary>
public sealed class WindowsSecurityNativeTests
{
    #region Methods
    // On a handle: files only, as the cache reads an entry (a FileStream opened for reading, which carries READ_CONTROL).
    [Theory]
    [InlineData("a file with an inherit-only ACE")]
    [InlineData("a file with the user's full control split in two")]
    public void Descriptor_OnAFilesHandle_IsTheDaclAsStored_WhereTheDotNetViewRewritesIt(string shape)
    {
        using var dir = new ControlledTempDir("native-handle");
        var path = Stage(dir, shape, directory: false);

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var native = WindowsSecurityNative.Descriptor(stream.SafeFileHandle);

        AssertAsStored(path, native, shape);
    }

    // By path: files, and a directory, as the cache reads its directory.
    [Theory]
    [InlineData("a file with an inherit-only ACE", false)]
    [InlineData("a file with the user's full control split in two", false)]
    [InlineData("a directory with the user's full control split in two", true)]
    public void Descriptor_ByPath_IsTheDaclAsStored_WhereTheDotNetViewRewritesIt(string shape, bool directory)
    {
        using var dir = new ControlledTempDir("native-path");
        var path = Stage(dir, shape, directory);

        AssertAsStored(path, WindowsSecurityNative.Descriptor(path), shape);
    }

    // A descriptor that cannot be read is never returned as something to judge: it throws.
    [Fact]
    public void Descriptor_ByPath_OfAMissingFile_Throws()
    {
        using var dir = new ControlledTempDir("native-missing");

        Assert.IsType<Win32Exception>(Record.Exception(() => WindowsSecurityNative.Descriptor(dir.Combine("missing.dat"))));
    }

    // Writes `shape`'s two-ACE DACL on a new file or directory under `dir`, and checks the preconditions: two ACEs on disk,
    // one through the .NET view. Its path.
    private static string Stage(ControlledTempDir dir, string shape, bool directory)
    {
        var user = Sids.User().Value;
        string path;
        if (directory)
            path = dir.CreateDirectory("staged");
        else
        {
            path = dir.Combine("staged.dat");
            File.WriteAllBytes(path, [1]);
        }
        var flags = directory ? "OICI" : "";
        RawAcl.SetDacl(path, "D:P" + (shape.Contains("inherit-only", StringComparison.Ordinal)
            ? $"(A;;FA;;;{user})(A;OICIIO;FA;;;WD)"
            : $"(A;{flags};FR;;;{user})(A;{flags};0x{FullControl & ~0x120089:x};;;{user})"));

        Assert.Equal(2, RawAcl.Descriptor(path).DiscretionaryAcl!.Count);   // on disk: two ACEs
        var dotNet = directory
            ? new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorBinaryForm()
            : new FileInfo(path).GetAccessControl().GetSecurityDescriptorBinaryForm();
        Assert.True(new RawSecurityDescriptor(dotNet, 0).DiscretionaryAcl!.Count == 1,
            $"{shape}: the precondition failed: the .NET view no longer rewrites this DACL, so the row does not discriminate");
        return path;
    }

    private static void AssertAsStored(string path, RawSecurityDescriptor native, string shape)
    {
        var stored = RawAcl.Descriptor(path);
        Assert.Equal(Sids.User(), native.Owner);
        Assert.NotNull(native.DiscretionaryAcl);
        Assert.True(Bytes(stored.DiscretionaryAcl!).AsSpan().SequenceEqual(Bytes(native.DiscretionaryAcl!)),
            $"{shape}: the native DACL is not the one on disk.{Environment.NewLine}on disk: {Sddl(stored)}{Environment.NewLine}native:  {Sddl(native)}");
        Assert.Equal(2, native.DiscretionaryAcl!.Count);
        Assert.True((native.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, "the protected flag was lost");
    }

    private static byte[] Bytes(SystemRawAcl acl)
    {
        var bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static string Sddl(RawSecurityDescriptor descriptor) => descriptor.GetSddlForm(AccessControlSections.Access);
    #endregion

    #region Methods: Unprotect accepts only this user's blobs (review C1)
    // C1: CryptUnprotectData takes its key from the blob, so a machine-scope blob (CRYPTPROTECT_LOCAL_MACHINE), which any
    // local user can make with the cache's public entropy, unprotects for this user too. The precondition shows exactly
    // that, raw; Unprotect must still refuse it, as not bound to this user.
    [Fact]
    public void Unprotect_OfAMachineScopeBlobThatDpapiItselfUnprotects_IsNull_WithNotUserScope()
    {
        var payload = RandomNumberGenerator.GetBytes(32);
        var machine = RawDpapi.Protect(payload, Entry.Entropy(), RawDpapi.UiForbidden | RawDpapi.LocalMachine);
        var (raw, error) = RawDpapi.Unprotect(machine, Entry.Entropy());
        Assert.True(raw is not null && raw.AsSpan().SequenceEqual(payload),
            $"the precondition failed: raw CryptUnprotectData no longer unprotects a machine-scope blob for this user (error 0x{error:x8}), so this test does not discriminate");

        var vouched = WindowsSecurityNative.Unprotect(machine, Entry.Entropy(), out var failure);

        Assert.Null(vouched);
        Assert.Equal(WindowsSecurityNative.NotUserScope, failure);
    }

    // The control: a user-scope blob, made by the product or raw with the same flags it uses, unprotects to its payload.
    [Theory]
    [InlineData("made by WindowsSecurityNative.Protect")]
    [InlineData("made raw, CRYPTPROTECT_UI_FORBIDDEN only")]
    public void Unprotect_OfAUserScopeBlob_ReturnsItsPayload(string how)
    {
        var payload = RandomNumberGenerator.GetBytes(32);
        var blob = how.StartsWith("made by", StringComparison.Ordinal)
            ? WindowsSecurityNative.Protect(payload, Entry.Entropy(), out var protectFailure) ?? throw new InvalidOperationException(protectFailure)
            : RawDpapi.Protect(payload, Entry.Entropy(), RawDpapi.UiForbidden);
        Assert.Equal(0u, RawDpapi.Flags(blob) & RawDpapi.LocalMachine);   // the precondition: really user-scope

        var vouched = WindowsSecurityNative.Unprotect(blob, Entry.Entropy(), out var failure);

        Assert.True(vouched is not null, $"{how}: a user-scope blob was refused: {failure}");
        Assert.Equal(payload, vouched);
        Assert.Null(failure);
    }

    // NOT a rule of ours: a measured property of DPAPI that UserScope relies on (review C1; WindowsSecurityNative's comment
    // on UserScope). The scope bit lives in the blob's dwFlags (offset 40), which DPAPI's HMAC covers: clearing it on a
    // machine-scope blob does not make a user-scope blob, DPAPI refuses it (measured: NTE_BAD_KEY_STATE). If this ever
    // unprotects, the scope check could be bypassed by editing the blob, and UserScope must be redesigned (DPAPI-NG).
    [Fact]
    public void MeasuredDpapiProperty_ClearingTheMachineBitOfAMachineScopeBlob_IsRefusedByDpapi_SoTheScopeCheckCannotBeBypassed()
    {
        var payload = RandomNumberGenerator.GetBytes(32);
        var machine = RawDpapi.Protect(payload, Entry.Entropy(), RawDpapi.UiForbidden | RawDpapi.LocalMachine);
        var flags = RawDpapi.Flags(machine);
        Assert.True((flags & RawDpapi.LocalMachine) != 0, $"the precondition failed: a machine-scope blob's dwFlags (offset 40) is 0x{flags:x}, without 0x4");
        var cleared = RawDpapi.WithFlags(machine, flags & ~RawDpapi.LocalMachine);

        var (raw, error) = RawDpapi.Unprotect(cleared, Entry.Entropy());

        Assert.True(raw is null,
            "DPAPI now unprotects a machine-scope blob whose 0x4 bit was cleared: dwFlags is no longer covered by its HMAC, and the scope check can be bypassed. The measured property changed.");
        Assert.True(error != 0, "CryptUnprotectData failed without an error code");   // measured 2026-10-23: NTE_BAD_KEY_STATE; any refusal will do
        // And through the product, it is DPAPI's refusal, not the scope check's.
        Assert.Null(WindowsSecurityNative.Unprotect(cleared, Entry.Entropy(), out var failure));
        Assert.NotEqual(WindowsSecurityNative.NotUserScope, failure);
    }

    // UserScope is coupled to an undocumented layout, so every surprise must fail closed (a cache miss, never a load). Each
    // row is built from a real blob; UserScope is read in isolation (by reflection: it is private), so a row that DPAPI
    // would refuse anyway (a version other than 1) still shows the layout check itself.
    public static TheoryData<string, bool> ScopeShapes() => new()
    {
        { "a real user-scope blob", true },
        { "its first 44 bytes, the header UserScope reads", true },
        { "its first 43 bytes, one short of dwFlags' end", false },
        { "its first 4 bytes", false },
        { "empty", false },
        { "dwVersion 0", false },
        { "dwVersion 2", false },
        { "dwVersion 0x01000000 (1, big-endian)", false },
        { "dwFlags with the 0x4 bit set", false },
        { "a real machine-scope blob", false },
    };

    [Theory]
    [MemberData(nameof(ScopeShapes))]
    public void UserScope_IsTrueOnlyForTheMeasuredUserScopeLayout_AndFailsClosedOnAnythingElse(string shape, bool expected)
    {
        var payload = RandomNumberGenerator.GetBytes(32);
        var user = RawDpapi.Protect(payload, Entry.Entropy(), RawDpapi.UiForbidden);
        Assert.Equal(1u, RawDpapi.Version(user));                          // the preconditions: the layout as measured
        Assert.Equal(0u, RawDpapi.Flags(user) & RawDpapi.LocalMachine);
        byte[] blob = shape switch
        {
            "a real user-scope blob" => user,
            "its first 44 bytes, the header UserScope reads" => user[..RawDpapi.HeaderBytes],
            "its first 43 bytes, one short of dwFlags' end" => user[..(RawDpapi.HeaderBytes - 1)],
            "its first 4 bytes" => user[..4],
            "empty" => [],
            "dwVersion 0" => RawDpapi.WithVersion(user, 0),
            "dwVersion 2" => RawDpapi.WithVersion(user, 2),
            "dwVersion 0x01000000 (1, big-endian)" => RawDpapi.WithVersion(user, 0x01000000),
            "dwFlags with the 0x4 bit set" => RawDpapi.WithFlags(user, RawDpapi.Flags(user) | RawDpapi.LocalMachine),
            "a real machine-scope blob" => RawDpapi.Protect(payload, Entry.Entropy(), RawDpapi.UiForbidden | RawDpapi.LocalMachine),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
        };

        Assert.True(UserScope()(blob) == expected, $"{shape}: UserScope was {!expected}, expected {expected}");
    }

    // WindowsSecurityNative.UserScope (private static bool UserScope(ReadOnlySpan<byte>)), as a delegate: a span cannot be
    // boxed into MethodInfo.Invoke's object[].
    private static UserScopeCheck UserScope() =>
        typeof(WindowsSecurityNative).GetMethod("UserScope", BindingFlags.Static | BindingFlags.NonPublic, [typeof(ReadOnlySpan<byte>)])?.CreateDelegate<UserScopeCheck>()
            ?? throw new InvalidOperationException("WindowsSecurityNative.UserScope(ReadOnlySpan<byte>) was not found: the C1 scope check moved or was renamed");

    private delegate bool UserScopeCheck(ReadOnlySpan<byte> blob);
    #endregion

    #region Methods: a path longer than MAX_PATH (N1)
    // N1: GetNamedSecurityInfoW refuses a path beyond MAX_PATH unless it is extended-length. The precondition shows it, raw
    // (error 123 on this machine, even with LongPathsEnabled); Descriptor(string) must still read the directory, by path,
    // and see its owner (the user) and its DACL exactly as stored.
    [Fact]
    public void Descriptor_ByPath_OfADirectoryLongerThanMaxPath_ReadsIt_WithTheUserAsOwner()
    {
        using var dir = new ControlledTempDir("native-long");
        var path = LongDirectory(dir);
        Assert.Equal(RawNamedSecurity.InvalidName, RawNamedSecurity.Read(path));   // the precondition: unprefixed, Windows refuses it

        AssertReadAsStored(path, WindowsSecurityNative.Descriptor(path));
    }

    // A path that is already extended-length is passed as it is (not prefixed twice).
    [Fact]
    public void Descriptor_ByPath_OfAnAlreadyExtendedLengthLongPath_ReadsIt_WithTheUserAsOwner()
    {
        using var dir = new ControlledTempDir("native-long-prefixed");
        var path = LongDirectory(dir);

        AssertReadAsStored(path, WindowsSecurityNative.Descriptor(ExtendedPrefix + path));
    }

    // UNC: \\server\share\… becomes \\?\UNC\server\share\…. Through the loopback administrative share (C$), to the same
    // directory under C:\Temp; skipped, visibly, where that share cannot be reached.
    [LoopbackAdminShareFact]
    public void Descriptor_ByPath_OfALongUncPath_ReadsIt_WithTheUserAsOwner()
    {
        using var dir = new ControlledTempDir("native-long-unc");
        var path = LongDirectory(dir);
        var unc = LoopbackAdminShareFactAttribute.Unc(path);
        Assert.True(Directory.Exists(ExtendedPrefix + @"UNC\" + unc[2..]), $"the precondition failed: {unc} is not reachable through the loopback share");
        Assert.Equal(RawNamedSecurity.InvalidName, RawNamedSecurity.Read(unc));   // the precondition: unprefixed, Windows refuses it

        AssertReadAsStored(path, WindowsSecurityNative.Descriptor(unc));
    }

    // A directory under `dir` whose full path is longer than 300 characters (each component well under 255), created with
    // inherited, trusted ACEs only (ControlledTempDir); its full, unprefixed path.
    private static string LongDirectory(ControlledTempDir dir)
    {
        var path = dir.Root;
        for (var i = 0; path.Length <= LongPathLength; i++)
            path = Path.Combine(path, $"long-path-segment-{i:D2}-" + new string('x', 40));
        Directory.CreateDirectory(path);
        Assert.True(path.Length > LongPathLength && Directory.Exists(ExtendedPrefix + path), $"the precondition failed: {path.Length} characters, or not created");
        return path;
    }

    // The owner is the user, and the DACL is byte-for-byte the one GetFileSecurityW reads through the extended-length path.
    private static void AssertReadAsStored(string path, RawSecurityDescriptor native)
    {
        var stored = RawAcl.Descriptor(ExtendedPrefix + path);
        Assert.Equal(Sids.User(), native.Owner);
        Assert.NotNull(native.DiscretionaryAcl);
        Assert.True(Bytes(stored.DiscretionaryAcl!).AsSpan().SequenceEqual(Bytes(native.DiscretionaryAcl!)),
            $"the native DACL is not the one on disk.{Environment.NewLine}on disk: {Sddl(stored)}{Environment.NewLine}native:  {Sddl(native)}");
    }
    #endregion

    #region Fields
    private const int FullControl = 0x1F01FF;
    private const int LongPathLength = 300;
    private const string ExtendedPrefix = @"\\?\";
    #endregion
}

/// <summary>
/// A <see cref="FactAttribute"/> for a test that reaches a <c>C:\Temp</c> fixture through the loopback administrative share
/// (<c>\\localhost\C$</c>): a VISIBLE skip, with the reason, where that share cannot be reached (the Server service off,
/// admin shares disabled, or a token that may not use them), never an early-return "pass".
/// </summary>
public sealed class LoopbackAdminShareFactAttribute : FactAttribute
{
    #region Constructors
    public LoopbackAdminShareFactAttribute()
    {
        if (!Reachable())
            Skip = $"needs the loopback administrative share {Share}\\Temp (the UNC form of a long path, N1), which this machine or "
                 + "token cannot reach. The drive-letter long-path tests still run.";
    }
    #endregion

    #region Methods
    /// <summary><paramref name="path"/> (a full <c>C:\</c> path) through the loopback share: <c>\\localhost\C$\…</c>.</summary>
    internal static string Unc(string path) => Share + path[2..];

    private static bool Reachable()
    {
        try
        {
            return Directory.Exists(Share + @"\Temp");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
    #endregion

    #region Fields
    private const string Share = @"\\localhost\C$";
    #endregion
}
#endif
