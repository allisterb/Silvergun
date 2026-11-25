#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// The Linux on-disk cache of compiled YARA-X rules (docs/agent/tasks/yarax-worker-linux.md, Phase 2, option B): the
/// Windows cache's job (<c>YaraXRulesCache</c>, ADR 0033 decision 6) with integrity resting on the PATH, not on DPAPI.
/// Compiling the embedded rules costs ~2.2 s per worker on Linux.
///
/// <para><b>Why the path is enough here.</b> A forged entry is native code in the worker (yara-x 1.22.0 deserializes
/// precompiled code), so an entry is read only from a directory nobody but this user and root can change. Every
/// directory from <c>/</c> down to the cache, checked with lstat semantics (<see cref="LinuxSecurityNative"/>), must be:
/// a real directory (not a link); owned by root or this user; and not writable by group or others, unless it is sticky
/// (<c>/tmp</c>) and the next directory down is this user's. The cache directory itself is this user's, mode 700 (special
/// bits aside). With POSIX ACLs the group bits are the ACL mask, which caps every named grant, so "no group or other
/// write" also rules out ACL grants. Only a directory's owner or root can change its mode or ACL, and renaming or
/// replacing an entry needs write access to its parent (in a sticky one, owning the entry), so once the walk passes no
/// other user can change any component: the checks cannot be raced, as a junction swap raced them on Windows (ADR 0033
/// amendment of 2026-10-22). The environment (<c>XDG_CACHE_HOME</c>, <c>HOME</c>) chooses the location, but the
/// location must still pass. Same-user code and root already own the worker, and are out of scope; so is a network
/// filesystem whose server does not honour the mode bits (no weaker than <c>$HOME</c> itself).</para>
///
/// <para><b>Nothing is corrected.</b> Missing directories are created one at a time, each mode 700 (never wider: the
/// umask only narrows), then the whole walk is repeated. A directory that fails is never chmodded or cleaned: the cache
/// is not used, with a warning. A cache directory that was ever open to others must be DELETED, not chmodded back: while
/// open, someone could have planted a hard link to a user-owned 600 file of their choosing (an extracted payload), and
/// nlink == 1 holds again once the original is gone; the warning says so. There is no quarantine state to survive a
/// crash (Windows W-B), and no lock: an entry is written to a new temp file (<c>O_CREAT|O_EXCL</c>, mode 600) and renamed
/// over the old one, which is atomic, and a reader keeps the inode it opened.</para>
///
/// <para><b>Whose entry.</b> lstat by path first: a regular file, so a link or a FIFO is never opened. Then, on the very
/// handle it is read through (fstat): the same device and inode as that lstat, owned by this user, mode 600 (special bits
/// aside), and one link (a hard link to a user file planted from elsewhere has two while that file exists). A device or
/// inode mismatch is read once more first (a parallel worker's store renamed over it). An entry that fails is ignored with
/// one warning, not deleted: the store that follows the recompile renames over it.</para>
///
/// <para><b>What.</b> One file per key (<see cref="YaraXRulesEntry.FileName"/>), only for a ruleset in which every source
/// compiled (amendment G1):
/// <code>
///   0   8  magic "SGYXRL01" (bump the digit whenever the entry's meaning changes)
///   8  32  sha256 of the body
///  40   …  the body (<see cref="YaraXRulesEntry"/>)
/// </code>
/// The hash is not a secret binding (the path is that): it catches corruption, which matters because most corrupt blobs
/// deserialize without error (C API spike: 48 of 60 single-byte flips). A load checks the location, the entry, its size,
/// the magic, the hash (<see cref="CryptographicOperations.FixedTimeEquals"/>) and the key, and only then deserializes.
/// Any failure is a miss, with one warning, and the rules are recompiled and rewritten.</para>
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class YaraXLinuxRulesCache : IYaraXRulesCache
{
    #region Constructors
    /// <summary>
    /// A cache in <see cref="DefaultDirectory"/>, or in <paramref name="directory"/> when it is not <c>null</c> (for tests;
    /// it is checked exactly as the default location is).
    /// </summary>
    internal YaraXLinuxRulesCache(string? directory = null) => Location = directory ?? DefaultDirectory();
    #endregion

    #region Properties
    /// <summary>The cache directory, or <c>null</c> when there is no per-user location.</summary>
    internal string? Location { get; }
    #endregion

    #region Methods
    /// <summary>
    /// <c>$XDG_CACHE_HOME/silvergun/yara-x-rules</c>, or <c>~/.cache/silvergun/yara-x-rules</c> when that is unset or not
    /// absolute (the XDG rule), or <c>null</c> without a home.
    /// </summary>
    internal static string? DefaultDirectory()
    {
        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        var root = !string.IsNullOrEmpty(xdg) && Path.IsPathFullyQualified(xdg) ? xdg
            : Path.IsPathFullyQualified(home) ? Path.Combine(home, ".cache")
            : null;
        return root is null ? null : Path.Combine(root, "silvergun", "yara-x-rules");
    }

    /// <summary>The cache file for <paramref name="sourcesSha256"/>, or <c>null</c> without a cache directory.</summary>
    internal string? EntryPath(string sourcesSha256) => Location is null ? null : Path.Combine(Location, YaraXRulesEntry.FileName(sourcesSha256));

    /// <summary>
    /// The cached rules for <paramref name="sourcesSha256"/>, with the canary compiled into them, or <c>null</c>: a miss
    /// (Debug), or an untrusted, corrupt or unusable entry or location (a warning). The caller still runs the canary.
    /// </summary>
    public YaraXRules? TryLoad(string sourcesSha256)
    {
        var path = EntryPath(sourcesSha256);
        try
        {
            var (entry, why) = path is null || PrepareDirectory() is null ? (null, null) : ReadOwnEntry(path, LinuxSecurityNative.EffectiveUid());
            // A worker that stored at the same moment renamed a new entry over the path between our lstat and open: benign,
            // so the first time it is read again rather than warned about.
            if (why == Replaced)
                (entry, why) = ReadOwnEntry(path!, LinuxSecurityNative.EffectiveUid());
            why ??= entry is null ? null : Invalid(entry, sourcesSha256);
            if (why is not null)
            {
                Runtime.Warn("YARA-X rules cache: ignoring {0}: {1}. The rules will be recompiled.", YaraXText.Bounded(path), why);
                return null;
            }
            if (entry is null)
            {
                Runtime.Debug("YARA-X rules cache: no usable entry for {0}.", sourcesSha256);
                return null;
            }

            // The path vouches for whose entry it is (ReadOwnEntry), the hash for its bytes (Invalid): only now is the body read.
            var rules = YaraXRulesEntry.Rules(entry.AsSpan(HeaderBytes), sourcesSha256, out var failure);
            if (rules is null)
                Runtime.Warn("YARA-X rules cache: ignoring {0}: {1}. The rules will be recompiled.", YaraXText.Bounded(path), failure ?? "");
            return rules;
        }
        catch (Exception ex)
        {
            Runtime.Warn("YARA-X rules cache: could not read {0}: {1}. The rules will be recompiled.",
                YaraXText.Bounded(path), YaraXText.Bounded($"{ex.GetType().Name}: {ex.Message}"));
            return null;
        }
    }

    /// <summary>
    /// Writes <paramref name="rules"/> as the entry for its key, replacing any previous one. Best effort: <c>false</c>, with
    /// a warning, when it could not be written. A ruleset with <see cref="YaraXRules.SourceErrors"/> is never written.
    /// </summary>
    public bool Store(YaraXRules rules)
    {
        var path = EntryPath(rules.SourcesSha256);
        string? temp = null;
        try
        {
            if (path is null)
                return false;
            if (rules.SourceErrors > 0)
            {
                Runtime.Warn("YARA-X rules cache: not caching these rules: {0} rule source(s) had compile errors.", rules.SourceErrors);
                return false;
            }

            var body = YaraXRulesEntry.Body(rules);
            var entry = new byte[HeaderBytes + body.Length];
            Encoding.ASCII.GetBytes(Magic, entry.AsSpan(0, MagicBytes));
            SHA256.HashData(body, entry.AsSpan(MagicBytes, YaraXRulesEntry.Sha256Bytes));
            body.CopyTo(entry.AsSpan(HeaderBytes));

            if (PrepareDirectory() is not { } dir)
                return false;

            YaraXRulesEntry.SweepStaleTemps(dir);
            temp = YaraXRulesEntry.TempPath(dir, path);
            using (var stream = new FileStream(temp, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = OwnerOnlyFile,
            }))
            {
                stream.Write(entry);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
            temp = null;
            Runtime.Debug("YARA-X rules cache: wrote {0} ({1} bytes).", YaraXText.Bounded(path), entry.Length);
            return true;
        }
        catch (Exception ex)
        {
            Runtime.Warn("YARA-X rules cache: could not write {0}: {1}",
                YaraXText.Bounded(path), YaraXText.Bounded($"{ex.GetType().Name}: {ex.Message}"));
            return false;
        }
        finally
        {
            if (temp is not null)
                try { File.Delete(temp); } catch { /* best effort */ }
        }
    }

    // The cache directory when it is trusted (class doc), creating it and any missing ancestor mode 700 first; otherwise
    // null, with one warning. A failure to create throws.
    private string? PrepareDirectory()
    {
        if (Location is null)
            return null;

        var user = LinuxSecurityNative.EffectiveUid();
        var why = Untrusted(Location, user, out var missing);
        if (why is null && missing)
        {
            // One component at a time, top-down: Directory.CreateDirectory(path, mode) gives the mode to the leaf only, and
            // its parents the umask's default (measured). Each parent exists when its child is made, so each call makes one.
            // Every component is re-checked before its child is made (review S1): one found missing by the walk may since have
            // been planted, as a link or another user's directory, in a sticky parent, and CreateDirectory would make the child
            // under it. The re-walk refuses that anyway; this stops before anything is created there.
            foreach (var component in Components(Location))
            {
                if (LinuxSecurityNative.Lstat(component) is null)
                    Directory.CreateDirectory(component, OwnerOnlyDirectory);
                if (LinuxSecurityNative.Lstat(component) is not { IsDirectory: true } status || (status.Uid != user && status.Uid != 0))
                    break;
            }
            why = Untrusted(Location, user, out missing) ?? (missing ? "it is still missing after it was created" : null);
        }
        if (why is null)
            return Location;

        Runtime.Warn("YARA-X rules cache: not using {0}: {1}.", YaraXText.Bounded(Location), YaraXText.Bounded(why));
        return null;
    }

    /// <summary>
    /// Null when every directory from <c>/</c> down to <paramref name="dir"/> is as the class doc requires for
    /// <paramref name="user"/>, or when the first that does not exist (<paramref name="missing"/>) comes after only ones
    /// that are; otherwise why not. Pure apart from the lstat calls.
    /// </summary>
    internal static string? Untrusted(string dir, uint user, out bool missing)
    {
        missing = false;
        if (!Path.IsPathFullyQualified(dir) || dir.Split('/').Any(name => name is "." or ".."))
            return "it is not an absolute path free of '.' and '..'";

        string[] paths = ["/", .. Components(dir)];
        var underSticky = false;
        for (var i = 0; i < paths.Length; i++)
        {
            // The reason comes first and the path last, so a long path cannot push the reason out of a bounded warning.
            var path = paths[i];
            if (LinuxSecurityNative.Lstat(path) is not { } status)
            {
                missing = true;
                return null;
            }

            var mode = status.Permissions;
            if (!status.IsDirectory)
                return $"a component is not a directory (it is a link, or another kind of file): {path}";
            if (i == paths.Length - 1)
                return status.Uid != user ? $"it is owned by uid {status.Uid}, not by you (uid {user})"
                    : (mode & PermissionBits) != OwnerOnlyDirectory ? $"its mode is {Octal(mode)}, not 700 (delete it and Silvergun will recreate it)"
                    : null;
            if (status.Uid != user && (underSticky || status.Uid != 0))
                return underSticky ? $"a directory in a shared sticky directory is owned by uid {status.Uid}, not by you: {path}"
                    : $"a directory on the way is owned by uid {status.Uid}, not by you or root: {path}";

            underSticky = (mode & GroupOrOtherWrite) != 0;
            if (underSticky && (mode & UnixFileMode.StickyBit) == 0)
                return $"a directory on the way is writable by other users (mode {Octal(mode)}): {path}";
        }
        return null;
    }

    // Every directory from the first below / down to `dir` ("/a", "/a/b", …): an empty segment ("//", a trailing "/") is
    // dropped, as the kernel does.
    private static IEnumerable<string> Components(string dir)
    {
        var path = "";
        foreach (var name in dir.Split('/', StringSplitOptions.RemoveEmptyEntries))
            yield return path += "/" + name;
    }

    // The entry at `path` when it is this user's own (class doc, "Whose entry"), checked on the handle it is read through;
    // (null, null) when there is none; (null, why) when there is one that is not.
    private static (byte[]? Entry, string? Why) ReadOwnEntry(string path, uint user)
    {
        if (LinuxSecurityNative.Lstat(path) is not { } named)
            return (null, null);
        if (!named.IsRegularFile)
            return (null, "it is not a regular file (it is a link, or another kind of file)");

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var why = NotOwnEntry(named, LinuxSecurityNative.Fstat(stream.SafeFileHandle), user);
        return why is null ? (YaraXRulesEntry.ReadBounded(stream, MinEntryBytes), null) : (null, why);
    }

    /// <summary>
    /// Null when the file opened (<paramref name="opened"/>, by fstat) is the regular file lstat found at the path
    /// (<paramref name="named"/>) and is <paramref name="user"/>'s own entry: the same device and inode, owned by the user,
    /// mode 600 (special bits aside), one link. Otherwise why not; <see cref="Replaced"/> for a device or inode mismatch.
    /// </summary>
    internal static string? NotOwnEntry(LinuxFileStatus named, LinuxFileStatus opened, uint user) =>
        (opened.Device, opened.Inode) != (named.Device, named.Inode) ? Replaced
        : opened.Uid != user ? $"it is owned by uid {opened.Uid}, not by you (uid {user})"
        : (opened.Permissions & PermissionBits) != OwnerOnlyFile ? $"its mode is {Octal(opened.Permissions)}, not 600"
        : opened.Links != 1 ? $"it has {opened.Links} hard links, not 1"
        : null;

    // Null when `entry` is this format, its body matches its hash, and it is for this key; otherwise what is wrong with it.
    private static string? Invalid(byte[] entry, string sourcesSha256)
    {
        var body = entry.AsSpan(HeaderBytes);
        return !entry.AsSpan(0, MagicBytes).SequenceEqual(Encoding.ASCII.GetBytes(Magic)) ? "unknown format"
            : !CryptographicOperations.FixedTimeEquals(entry.AsSpan(MagicBytes, YaraXRulesEntry.Sha256Bytes), SHA256.HashData(body))
                ? "its body does not match its hash (corrupt)"
            : !YaraXRulesEntry.IsFor(body, sourcesSha256) ? "it is for other rule sources"
            : null;
    }

    private static string Octal(UnixFileMode mode) => Convert.ToString((int)mode, 8);
    #endregion

    #region Fields
    /// <summary>Why an entry whose lstat and fstat disagree on device and inode is refused; TryLoad reads once more first.</summary>
    internal const string Replaced = "it was replaced while it was being opened";

    private const string Magic = "SGYXRL01";
    private const int MagicBytes = 8;
    private const int HeaderBytes = MagicBytes + YaraXRulesEntry.Sha256Bytes;

    // The smallest entry with a header and a body header: smaller is not an entry at all.
    private const int MinEntryBytes = HeaderBytes + YaraXRulesEntry.BodyHeaderBytes;

    private const UnixFileMode OwnerOnlyDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode GroupOrOtherWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    // 0777: the permission bits without set-uid, set-gid and sticky, which mean nothing for an owner-only directory or file.
    private const UnixFileMode PermissionBits = OwnerOnlyDirectory
        | UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
    #endregion
}
#endif
