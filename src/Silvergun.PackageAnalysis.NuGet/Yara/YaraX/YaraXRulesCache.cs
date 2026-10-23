#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

/// <summary>
/// The on-disk cache of compiled YARA-X rules (ADR 0033 FINAL FORM decision 6): compiling the embedded rules costs
/// ~1.6 s, loading a serialized blob ~0.15 s.
///
/// <para><b>Integrity rests on DPAPI</b> (ADR 0033 amendment, "Finding", and the user's decision (i) of 2026-10-23). In
/// yara-x 1.22.0, <c>yrx_rules_deserialize</c> (<see cref="YaraXRules.Deserialize"/>) loads precompiled native code from
/// a blob that carries it, whatever features the engine was built with, so a forged entry is code execution in the
/// worker, not just a false-clean scan. Every entry therefore carries the sha256 of its body protected with DPAPI for the
/// current user (<c>CryptProtectData</c>, a CurrentUser blob, with this format's and engine's entropy), and nothing from
/// an entry reaches <see cref="YaraXRules.Deserialize"/> until DPAPI has unprotected that hash, the blob has been found to
/// be user-scope, and the hash equals the body's (compared in constant time). The scope check is what binds an entry to
/// this user (review C1): <c>CryptUnprotectData</c> takes its key from the blob, so a machine-scope blob
/// (<c>CRYPTPROTECT_LOCAL_MACHINE</c>), which any local user can make with our public entropy, would unprotect for every
/// user; <see cref="WindowsSecurityNative.Unprotect"/> refuses it. With that, only a blob made with this user's own DPAPI
/// key is accepted, and this user's own <see cref="Store"/> only ever protects bodies Silvergun compiled from its embedded
/// sources. The location, directory and entry checks below are a second layer behind it. A location steered by the
/// environment (<c>USERPROFILE</c> moves <c>%LOCALAPPDATA%</c>) is accepted: integrity does not depend on it, and what it
/// can still cause is denial of service of the cache (misses and recompiles), nothing more. A DPAPI failure (a refused
/// machine-scope blob included) is a miss or a skipped write, with a warning; it never blocks a scan.</para>
///
/// <para><b>Where.</b> One location, per user (<see cref="DefaultDirectory"/>): <c>%LOCALAPPDATA%\Silvergun\yara-x-rules\</c>
/// on Windows; <c>$XDG_CACHE_HOME/silvergun/yara-x-rules/</c> (or <c>~/.cache/…</c>) on Unix. There is no override (ADR
/// 0033, amendment of 2026-10-22): the cache decides what a scan trusts, and a user-chosen location cannot be trusted by
/// its path, because anyone who can rename one of its ancestors can race every path-based check, swapping in a junction
/// to files of their choosing between the checks and the use. Other users cannot rename the default location's ancestors
/// (<c>%USERPROFILE%</c>, <c>%LOCALAPPDATA%</c>). The constructor's directory argument exists for tests, and is used
/// exactly as the default location is.</para>
///
/// <para><b>Owner-only.</b> The cache directory is owner-only: on Windows a protected DACL (inheritance disabled) with one
/// ACE, full control for the current user, inherited by everything created in it, and the user as owner; on Unix mode
/// 0700. The directory and its parent are checked for being links (reparse points) before anything reads or changes the
/// directory's ACL, and a link is never used; directories above the parent are not checked. A missing directory is created
/// owner-only in one step (its parent first, when that is missing too). An existing directory that is not exactly
/// owner-only (owner included) is corrected and its entries deleted (while it was open, anyone could have written one); if
/// it cannot be corrected, or the entries cannot be deleted, the cache is not used.</para>
///
/// <para><b>Correction is two-step, so it can never leave an untrusted entry in a trusted directory</b> (review W-B). The
/// directory is first QUARANTINED: a protected DACL whose one ACE gives the user full control of the directory and its
/// subdirectories but is not inherited by files. Only the user can then reach it, but it is deliberately not the
/// owner-only shape this class trusts. The entries are deleted under that ACL, and only once every
/// one is gone is the trusted shape applied. If a deletion fails (a reader holds the entry), or this process dies or is
/// killed in between (the parent kills a worker not ready in 15 s), the directory stays quarantined, so the next run sees
/// "not owner-only" and corrects and deletes again. Restoring inheritance would also be distrusted next time, but it
/// reopens the directory to whatever the parent grants, and it cannot cover a process that dies before restoring;
/// restoring the old DACL re-grants whatever it granted.</para>
///
/// <para><b>Concurrency.</b> Workers start in parallel (one per package), so correction+deletion and every entry read
/// and write run under a cross-process named mutex (<c>Local\…</c>, named from a hash of the directory). The wait is
/// bounded (<see cref="LockTimeout"/>), inside the worker's 15 s startup bound: a timed-out load compiles, and a
/// timed-out store skips the write. A mutex abandoned by a worker that was killed is taken over, which is safe because
/// every step above survives a holder dying part-way.</para>
///
/// <para><b>What.</b> One file per key, <c>rules-&lt;engine version&gt;-&lt;sources sha256&gt;.sgyx</c>, written to a temp
/// name and moved into place, so a reader sees a whole entry or none (each write first sweeps temp files orphaned by a
/// writer that died, best effort). Only a ruleset in which every source compiled cleanly is stored
/// (<see cref="YaraXRules.SourceErrors"/> = 0), so a loaded entry vouches for the whole ruleset (amendment G1). It holds
/// a body (the serialized blob, and the canary compiled into it, whose marker and name cannot be recovered from the
/// blob) and, before it, the DPAPI binding of the body's sha256:
/// <code>
///   0     8  magic "SGYXRC03" (bump the digit whenever the entry's meaning changes: compile flags, canary shape, …;
///            02: from a compile with no source errors; 03: bound with DPAPI)
///   8     4  P, the length of the DPAPI blob (int32, little-endian), 1 &lt;= P &lt;= 1024 and within the entry
///  12     P  the DPAPI blob: CryptProtectData(sha256 of the body, entropy "Silvergun YARA-X rules cache " + magic + "|"
///            + engine version, CRYPTPROTECT_UI_FORBIDDEN), for the current user (a user-scope blob; no other is loaded)
///  12+P   …  the body:
///     +0  32    sources sha256 (must equal the key)
///    +32  16    canary id
///    +48  32    canary marker
///    +80   4    rule count, not counting the canary (int32, little-endian)
///    +84   …    the serialized rules
/// </code>
/// A load checks, in order: the entry's location, owner and DACL (below); its size; the magic and P (no DPAPI call for a
/// P out of range); <c>CryptUnprotectData</c>, whose blob must be user-scope and whose output must be exactly 32 bytes;
/// that output against the body's sha256 (<see cref="CryptographicOperations.FixedTimeEquals"/>); and only then the key,
/// the canary, the rule count and <see cref="YaraXRules.Deserialize"/>. The hash also catches corruption, which matters
/// because most corrupt blobs deserialize without error (C API spike: 48 of 60 single-byte flips). Any failure is a
/// miss, with one warning, and the rules are recompiled and rewritten; so is a canary that then fails. An entry of the
/// previous format (<c>SGYXRC02</c>) is a silent miss (Debug), overwritten by the next store, so an upgrade does not
/// warn.</para>
///
/// <para><b>Whose entry</b> (reviews S1, W-A; ADR 0033 amendment of 2026-10-22). An entry is read only when it is not a
/// link (checked by path, before it is opened) and, checked on the very handle it is then read through (never by path),
/// its OWNER is the current user and its DACL is exactly the one Silvergun gives its own entries: a single plain allow
/// ACE, for the user, with full control, that applies to the file itself (not inherit-only; whether it is marked
/// inherited is not weighed). Our own entries pass: they carry <c>(A;ID;FA;;;&lt;user&gt;)</c>, inherited from the
/// owner-only directory. The descriptor is read natively, exactly as stored (<see cref="WindowsSecurityNative"/>): a
/// <see cref="FileSecurity"/> would canonicalise the DACL first, dropping inherit-only ACEs and merging the user's split
/// ones, and "exactly one ACE" would be judged on a rewritten ACL. This is defense-in-depth behind DPAPI and the
/// directory: a file that did not come from <see cref="Store"/> carries other grants, so it is refused even when the user
/// owns it (a file restored into the NuGet global-packages folder, for one, also grants LocalSystem and Administrators).
/// The owner check covers a WRITE_DAC handle opened while the directory was still open, which survives its correction: an
/// entry created through it is owned by its creator, and another user cannot make the victim the owner without
/// SeRestorePrivilege. Any other entry is deleted (best effort) with one warning, and the rules are recompiled. An entry
/// that cannot be opened, or whose ACL cannot be read or parsed, is not deleted: it is skipped (a "could not read" miss,
/// with one warning) and overwritten by the store that follows the recompile. Every entry is written through a handle
/// opened with the right to change its owner, and when its creator's default owner is someone else (an elevated
/// administrator's can be the Administrators group), the user is made its owner through that same handle, so the check
/// never distrusts our own writes. The owner is never set by path: by then the file at that path may not be the one this
/// process created, and setting it would vouch for someone else's entry (review W1).</para>
/// </summary>
internal sealed class YaraXRulesCache
{
    #region Constructors
    /// <summary>
    /// A cache in <see cref="DefaultDirectory"/>, or in <paramref name="directory"/> (absolute) when it is not <c>null</c>.
    /// That argument exists for tests, and the directory is used exactly as the default location is (see the class doc).
    /// </summary>
    internal YaraXRulesCache(string? directory = null) => Location = directory ?? DefaultDirectory();
    #endregion

    #region Properties
    /// <summary>The cache directory, or <c>null</c> when the platform offers no per-user location.</summary>
    internal string? Location { get; }
    #endregion

    #region Methods
    /// <summary>The per-user default location (see the class doc), or <c>null</c> when there is none.</summary>
    internal static string? DefaultDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
            return Path.IsPathFullyQualified(local) ? Path.Combine(local, "Silvergun", "yara-x-rules") : null;
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        var root = !string.IsNullOrEmpty(xdg) && Path.IsPathFullyQualified(xdg) ? xdg
            : Path.IsPathFullyQualified(home) ? Path.Combine(home, ".cache")
            : null;
        return root is null ? null : Path.Combine(root, "silvergun", "yara-x-rules");
    }

    // W2: an ACE whose effect is just its SID, mask and flags: an allow or deny CommonAce that is not a callback
    // (conditional) ACE. Anything else (object, callback, custom, …) cannot be evaluated here, so it is distrusted.
    private static bool Plain(GenericAce ace) =>
        ace is CommonAce { IsCallback: false, AceQualifier: AceQualifier.AccessAllowed or AceQualifier.AccessDenied };

    /// <summary>The cache file for <paramref name="sourcesSha256"/>, or <c>null</c> without a cache directory.</summary>
    internal string? EntryPath(string sourcesSha256) =>
        Location is null ? null : Path.Combine(Location, $"rules-{YaraXNative.EngineVersion}-{sourcesSha256}.sgyx");

    /// <summary>
    /// The cached rules for <paramref name="sourcesSha256"/>, with the canary compiled into them, or <c>null</c> (a miss,
    /// logged at Debug, as is an entry of the previous format; a corrupt, unvouched or unusable entry, logged as a
    /// warning). DPAPI must vouch for the entry's exact body before any of it goes near the engine (class doc). The caller
    /// still runs the canary.
    /// </summary>
    internal YaraXRules? TryLoad(string sourcesSha256)
    {
        var path = EntryPath(sourcesSha256);
        try
        {
            // Under the lock: the directory check (and any correction), the entry's owner and DACL checks (S1, W-A) and the
            // read. Verifying and deserializing need no lock.
            var entry = path is null ? null
                : Locked(() => PrepareDirectory() is null || !File.Exists(path) ? null
                    : OperatingSystem.IsWindows() ? ReadOwnEntry(path) : ReadBounded(path), timedOut: null);
            if (entry is null)
            {
                Runtime.Debug("YARA-X rules cache: no usable entry for {0}.", sourcesSha256);
                return null;
            }

            if (entry.AsSpan(0, MagicBytes).SequenceEqual(Encoding.ASCII.GetBytes(PreviousMagic)))
            {
                Runtime.Debug("YARA-X rules cache: {0} is in the previous format ({1}); the next store replaces it.", YaraXText.Bounded(path), PreviousMagic);
                return null;
            }

            if (Invalid(entry, sourcesSha256) is { } problem)
            {
                Runtime.Warn("YARA-X rules cache: ignoring {0}: {1}. The rules will be recompiled.", YaraXText.Bounded(path), problem);
                return null;
            }

            // DPAPI has vouched for exactly these bytes (Invalid): only now is anything read from the body.
            var body = entry.AsSpan(BodyOffset(entry));
            var canary = YaraXCanary.From(body.Slice(CanaryIdOffset, CanaryIdBytes), body.Slice(MarkerOffset, YaraXCanary.MarkerBytes))!;
            var ruleCount = BinaryPrimitives.ReadInt32LittleEndian(body.Slice(RuleCountOffset, sizeof(int)));
            var rules = YaraXRules.Deserialize(body[BodyHeaderBytes..], canary, sourcesSha256, ruleCount, out var failure);
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
    /// a warning, when it could not be written; the rules in hand are unaffected. A ruleset with
    /// <see cref="YaraXRules.SourceErrors"/> is never written: a cache hit must vouch for every source (amendment G1).
    /// Neither is one whose body DPAPI could not bind (class doc): nothing is written, and the cache simply misses.
    /// </summary>
    internal bool Store(YaraXRules rules)
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

            var blob = rules.Serialize(out var failure)
                ?? throw new InvalidOperationException(failure ?? "the rules could not be serialized");

            var body = new byte[BodyHeaderBytes + blob.Length];
            Convert.FromHexString(rules.SourcesSha256).CopyTo(body.AsSpan(SourcesOffset, Sha256Bytes));
            rules.Canary.IdBytes().CopyTo(body.AsSpan(CanaryIdOffset, CanaryIdBytes));
            rules.Canary.Marker.CopyTo(body.AsSpan(MarkerOffset, YaraXCanary.MarkerBytes));
            BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(RuleCountOffset, sizeof(int)), rules.RuleCount);
            blob.CopyTo(body.AsSpan(BodyHeaderBytes));

            var binding = WindowsSecurityNative.Protect(SHA256.HashData(body), Entropy, out var protectFailure);
            if (binding is null || binding.Length > MaxProtectedBytes)
            {
                Runtime.Warn("YARA-X rules cache: not caching these rules: {0}.", binding is null ? YaraXText.Bounded(protectFailure)
                    : $"the DPAPI blob is {binding.Length} bytes, more than the {MaxProtectedBytes} a load accepts");
                return false;
            }

            var entry = new byte[ProtectedOffset + binding.Length + body.Length];
            Encoding.ASCII.GetBytes(Magic, entry.AsSpan(0, MagicBytes));
            BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(ProtectedLengthOffset, sizeof(int)), binding.Length);
            binding.CopyTo(entry.AsSpan(ProtectedOffset));
            body.CopyTo(entry.AsSpan(ProtectedOffset + binding.Length));

            // Under the lock: the directory check (and any correction), the sweep, and the write and move.
            return Locked(() =>
            {
                if (PrepareDirectory() is not { } dir)
                    return false;

                SweepStaleTemps(dir);
                temp = Path.Combine(dir, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
                using (var stream = OperatingSystem.IsWindows() ? CreateOwnedByUser(temp)
                    : new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(entry);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temp, path, overwrite: true);
                temp = null;
                Runtime.Debug("YARA-X rules cache: wrote {0} ({1} bytes).", YaraXText.Bounded(path), entry.Length);
                return true;
            }, timedOut: false);
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

    // Creates the directory owner-only, or checks an existing one and corrects it if need be. Null when the cache must not
    // be used: no location, a link, or permissions that are not (or could not be made) owner-only. The link check comes
    // FIRST (N1), on the directory and on its parent (…\Silvergun): reading or rewriting the ACL of a link's target would
    // apply our permissions to, and trust, a directory somewhere else. It is repeated after, for a directory created in
    // between. Directories above the parent are not checked: in the default location, other users cannot rename them (ADR
    // 0033 amendment of 2026-10-22).
    private string? PrepareDirectory()
    {
        if (Location is null || !Path.IsPathFullyQualified(Location))
            return null;
        if (Link(Location) is { } before)
            return Refuse(before, "it is a link");

        var ok = OperatingSystem.IsWindows() ? PrepareWindows(Location) : PrepareUnix(Location);
        if (!ok)
            return null;

        return Link(Location) is { } after ? Refuse(after, "it is a link") : Location;

        static string? Refuse(string dir, string why)
        {
            Runtime.Warn("YARA-X rules cache: not using {0}: {1}.", YaraXText.Bounded(dir), why);
            return null;
        }
    }

    // The first of `dir`'s parent and `dir` itself that exists and is a reparse point (a junction, a symbolic link, …),
    // or null. Reads the entry's own attributes: a link is not followed.
    private static string? Link(string dir) =>
        new[] { Path.GetDirectoryName(dir), dir }.FirstOrDefault(p => p is not null && IsReparsePoint(p));

    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
    }

    // Creates `dir` owner-only (its parent first, when missing), or corrects an existing one that is not owner-only:
    // quarantine, delete its entries, then trust (W-B, class doc). True only when it ends up exactly owner-only.
    [SupportedOSPlatform("windows")]
    private static bool PrepareWindows(string dir)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new InvalidOperationException("the current user has no SID");
        var info = new DirectoryInfo(dir);
        if (!info.Exists)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dir)!);
            info.Create(OwnerOnly(user));
        }
        else if (ReadableAcl(dir) is not { } current)
            return false;   // N-1: never correct an ACL that cannot be read
        else if (!IsOwnerOnly(current, user))
        {
            Runtime.Warn("YARA-X rules cache: {0} was not owner-only; restricting it to the current user and deleting its entries.", YaraXText.Bounded(dir));
            // N2: while the directory was open, anyone could have written an entry whose hash verifies; none is trusted.
            // W-B: quarantine (user-only, but not the trusted shape) BEFORE deleting, and trust only after every entry is
            // gone; a failed deletion, or a death in between, leaves it quarantined for the next run to redo (class doc).
            // FR2.2: the owner is written only when it is not already the user, so a DACL-only correction needs no
            // WRITE_OWNER. The quarantine sets it when needed, so the trusted shape never has to; if either write is
            // refused it throws, and the caller does not use the cache (fail closed), as does the re-check below.
            info.SetAccessControl(Quarantined(user, setOwner: current.Owner != user));
            if (!DeleteEntries(dir))
                return false;
            info.SetAccessControl(OwnerOnly(user, setOwner: false));
        }

        if (ReadableAcl(dir) is not { } final)
            return false;
        if (IsOwnerOnly(final, user))
            return true;

        Runtime.Warn("YARA-X rules cache: not using {0}: it could not be made owner-only.", YaraXText.Bounded(dir));
        return false;
    }

    // N-1: `dir`'s owner and DACL, exactly as stored (read natively, by path: a DirectorySecurity would canonicalise the
    // DACL, merging split ACEs), or null, with one warning, when .NET cannot parse them. Measured on .NET 10, parsing
    // throws ArgumentException only for an ACE it cannot model: a compound ACE, or a custom ACE whose size is not a
    // multiple of 4 (it is now RawSecurityDescriptor's constructor that throws). An aligned custom ACE parses fine, as a
    // CustomAce, which is not Plain, so the directory is not owner-only and is corrected. InvalidOperationException was
    // never observed; catching it too is harmless. Anything else propagates, a descriptor that cannot be read at all
    // included (never trusted). When it is null the cache is not used, and the ACL is never corrected: what it grants is
    // unknown, and in the default location only the user or an administrator can write the directory's ACL, so the warning
    // tells the user to delete the directory.
    [SupportedOSPlatform("windows")]
    private static RawSecurityDescriptor? ReadableAcl(string dir)
    {
        try
        {
            return WindowsSecurityNative.Descriptor(dir);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            Runtime.Warn("YARA-X rules cache: not using {0}: its permissions cannot be read (an unsupported ACE); delete it "
                + "and Silvergun will recreate it.", YaraXText.Bounded(dir));
            return null;
        }
    }

    // Deletes every cache entry and temp file directly in `dir` (never anything else, never recursively); a link is
    // deleted as a link. False, with a warning, when any could not be deleted: the cache must then not be used.
    private static bool DeleteEntries(string dir)
    {
        var failed = 0;
        foreach (var file in Directory.EnumerateFiles(dir, EntryPattern).Concat(Directory.EnumerateFiles(dir, TempPattern)).ToArray())
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed++;
            }
        }

        if (failed == 0)
            return true;

        Runtime.Warn("YARA-X rules cache: not using {0}: {1} untrusted entr(ies) could not be deleted; it stays quarantined until a later run deletes them.", YaraXText.Bounded(dir), failed);
        return false;
    }

    // Runs `action` holding this cache's cross-process mutex (W-B), or returns `timedOut` (with a warning) when the mutex is
    // not free within LockTimeout. A mutex abandoned by a holder that died is ours: every guarded step tolerates that.
    private T Locked<T>(Func<T> action, T timedOut)
    {
        using var mutex = new Mutex(initiallyOwned: false, MutexName(Location!));
        bool owned;
        try
        {
            owned = mutex.WaitOne(LockTimeout);
        }
        catch (AbandonedMutexException)
        {
            Runtime.Debug("YARA-X rules cache: took over the cache lock from a process that died holding it.");
            owned = true;
        }

        if (!owned)
        {
            Runtime.Warn("YARA-X rules cache: another process held the cache lock for {0} s; not using the cache this time.", LockTimeout.TotalSeconds);
            return timedOut;
        }

        try
        {
            return action();
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    // Local\ (this session) and derived from the directory, case-folded as Windows compares paths; hex only, so the name
    // carries no path text.
    private static string MutexName(string dir) =>
        @"Local\Silvergun.YaraXRulesCache."
        + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Path.TrimEndingDirectorySeparator(dir).ToUpperInvariant())))[..32];

    // N3: best-effort removal of temp files left by a writer that died between writing and moving its entry. A live
    // writer's temp exists only for the write and move of one ~2.3 MB entry, which happens while a worker starts — and
    // the parent kills a worker that is not ready within 15 s (amendment G9) — so a temp file not written to for
    // StaleTempAge is an orphan. Never throws.
    private static void SweepStaleTemps(string dir)
    {
        try
        {
            foreach (var file in new DirectoryInfo(dir).EnumerateFiles(TempPattern))
            {
                try
                {
                    if (DateTime.UtcNow - file.LastWriteTimeUtc > StaleTempAge)
                        file.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // best effort: in use, or already gone
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Runtime.Debug("YARA-X rules cache: could not sweep stale temp files: {0}", YaraXText.Bounded(ex.Message));
        }
    }

    // Owner: the user. DACL: protected (nothing inherited from the parent), exactly one ACE — full control for the user,
    // inherited by every file and subdirectory created inside. With setOwner false the owner is left out of the descriptor:
    // SetAccessControl writes only the sections that were set (DACL here), so no WRITE_OWNER is needed (FR2.2).
    [SupportedOSPlatform("windows")]
    private static DirectorySecurity OwnerOnly(SecurityIdentifier user, bool setOwner = true) =>
        UserOnly(user, setOwner, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);

    // W-B's quarantine: as OwnerOnly — owner the user (when setOwner), DACL protected, one ACE for the user — but the ACE is
    // not inherited by files, so IsOwnerOnly rejects it. Nobody else can reach the directory, and it is never trusted as it
    // stands.
    [SupportedOSPlatform("windows")]
    private static DirectorySecurity Quarantined(SecurityIdentifier user, bool setOwner) =>
        UserOnly(user, setOwner, InheritanceFlags.ContainerInherit);

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity UserOnly(SecurityIdentifier user, bool setOwner, InheritanceFlags inheritance)
    {
        var security = new DirectorySecurity();
        if (setOwner)
            security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    // Exactly what OwnerOnly builds (N4): owner the user, DACL protected, and exactly one ACE — allow the user full control,
    // inherited by files and subdirectories, not inherit-only. Judged on the raw DACL as stored (W2; ReadableAcl), so a null
    // DACL, an ACE that is not plain, or the owner-only ACE split in two makes it not owner-only: GetAccessRules would
    // report a callback (conditional) ACE as unconditional and silently omit an object ACE, and a DirectorySecurity would
    // merge the split ACEs into one. On disk, OwnerOnly is exactly one ACE, D:P(A;OICI;FA;;;<user>) (mask 0x001F01FF),
    // both when created and when applied by the correction.
    [SupportedOSPlatform("windows")]
    private static bool IsOwnerOnly(RawSecurityDescriptor descriptor, SecurityIdentifier user) =>
        (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0
            && descriptor.Owner is { } owner && user.Equals(owner)
            && descriptor.DiscretionaryAcl is { Count: 1 } acl
            && acl[0] is CommonAce only
            && Plain(only)
            && only.AceQualifier == AceQualifier.AccessAllowed
            && user.Equals(only.SecurityIdentifier)
            && (only.AccessMask & (int)FileSystemRights.FullControl) == (int)FileSystemRights.FullControl
            && only.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)
            && only.PropagationFlags == PropagationFlags.None;

    // Unix (not built yet: this file is Windows-only until the Linux C API build, ADR 0033 revision decision 5).
    // TODO(T8, Linux YARA-X): the Windows rules are not honoured here yet: an existing directory is made 0700 without the
    // quarantine and without deleting its entries (W-B), and an entry's owner and mode are not checked before it is read
    // (S1, W-A). The whole file is compiled only under #if WINDOWS, so none of this is compiled or tested yet. Also,
    // DefaultDirectory honours XDG_CACHE_HOME and HOME, both user-chosen paths: T8 must apply the threat model of the ADR
    // 0033 amendment of 2026-10-22 (a renamable ancestor races every path-based check) before trusting them. And there is
    // no DPAPI on Unix, which is what entry integrity rests on here (class doc): T8 must choose between binding entries
    // with a key kept in a 0700 directory (e.g. a MAC) and no cache at all.
    [UnsupportedOSPlatform("windows")]
    private static bool PrepareUnix(string dir)
    {
        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(dir, ownerOnly);
        File.SetUnixFileMode(dir, ownerOnly);
        return File.GetUnixFileMode(dir) == ownerOnly;
    }

    // S1, W-A (class doc, "Whose entry"): the entry at `path` when it is not a link, the current user owns it and its DACL
    // is exactly the one our own entries carry; otherwise null, after deleting it (best effort) with one warning. The link
    // check is by path, before opening; the owner and the DACL are checked on the handle, which is the very handle the
    // entry is then read through.
    [SupportedOSPlatform("windows")]
    private static byte[]? ReadOwnEntry(string path)
    {
        var (entry, why) = IsReparsePoint(path) ? (null, "it is a link") : ReadIfOwned(path);
        if (why is null)
            return entry;

        Runtime.Warn("YARA-X rules cache: ignoring {0}: {1}; {2}. The rules will be recompiled.",
            YaraXText.Bounded(path), why, TryDelete(path) ? "it was deleted" : "it could not be deleted");
        return null;
    }

    // W-A, tightened by the ADR 0033 amendment of 2026-10-22: the owner must be the current user, and the DACL exactly
    // what our own entries carry (NotOwnEntryDacl). FileAccess.Read includes READ_CONTROL, so the descriptor is read on
    // this handle, never by path, and natively, exactly as stored (a FileSecurity would canonicalise it). A descriptor
    // that cannot be read or parsed throws: the entry is then skipped, not deleted (class doc).
    [SupportedOSPlatform("windows")]
    private static (byte[]? Entry, string? Why) ReadIfOwned(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var descriptor = WindowsSecurityNative.Descriptor(stream.SafeFileHandle);
        var why = identity.User is not { } user || descriptor.Owner is not { } owner || !user.Equals(owner) ? "its owner is not the current user"
            : NotOwnEntryDacl(descriptor.DiscretionaryAcl, user) is { } detail ? $"{NotOwnEntryPermissions}: {detail}"
            : null;
        return why is null ? (ReadBounded(stream), null) : (null, why);
    }

    // Null when `dacl` is exactly what our own entries carry, (A;ID;FA;;;<user>) inherited from the owner-only directory:
    // one ACE, Plain (read raw, W2), an allow, for `user`, with full control, that applies to the file itself (not
    // inherit-only). Whether it is marked inherited is not weighed. Otherwise which part differs.
    [SupportedOSPlatform("windows")]
    private static string? NotOwnEntryDacl(RawAcl? dacl, SecurityIdentifier user) =>
        dacl is null ? "it has no access control list (a null DACL, which lets anyone do anything)"
        : dacl.Count != 1 ? $"it has {dacl.Count} permission entries, not one"
        : dacl[0] is not CommonAce only || !Plain(only) ? "its one permission entry is of a kind Silvergun does not evaluate (not a plain allow or deny)"
        : only.AceQualifier == AceQualifier.AccessAllowed
            && user.Equals(only.SecurityIdentifier)
            && (only.AccessMask & (int)FileSystemRights.FullControl) == (int)FileSystemRights.FullControl
            && (only.AceFlags & AceFlags.InheritOnly) == 0 ? null
        : "its one permission entry is not an allow entry giving you full control of the file";

    // The other half of S1: a new file's owner is its creator token's default owner, which for an elevated administrator
    // (CI runners run elevated) can be the Administrators group, not the user; ReadOwnEntry would then distrust every
    // entry this process wrote. So the file is created (CreateNew: never an existing one) through a handle that may also
    // read its security and change its owner, and the owner is set to the user on THAT handle, only when it differs (W1:
    // never by path). Naming one's own user SID as owner needs no privilege, and only the owner is written (the DACL,
    // inherited from the owner-only directory, is left as it is; no FileSecurity is passed at creation, which would
    // replace it). Throws when it cannot, and then the stream is closed.
    [SupportedOSPlatform("windows")]
    private static FileStream CreateOwnedByUser(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new InvalidOperationException("the current user has no SID");
        var stream = new FileInfo(path).Create(FileMode.CreateNew,
            FileSystemRights.Write | FileSystemRights.ReadPermissions | FileSystemRights.TakeOwnership,
            FileShare.None, TempBufferBytes, FileOptions.None, fileSecurity: null);
        try
        {
            var security = stream.GetAccessControl();
            if (!user.Equals(security.GetOwner(typeof(SecurityIdentifier))))
            {
                security.SetOwner(user);
                stream.SetAccessControl(security);
            }
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static bool TryDelete(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static byte[] ReadBounded(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ReadBounded(stream);
    }

    private static byte[] ReadBounded(FileStream stream)
    {
        if (stream.Length is < MinEntryBytes or > MaxEntryBytes)
            throw new InvalidDataException($"the entry is {stream.Length} bytes, outside [{MinEntryBytes}, {MaxEntryBytes}]");

        var entry = new byte[stream.Length];
        stream.ReadExactly(entry);
        return entry;
    }

    // Null when the entry is this format, this user's DPAPI (a user-scope blob, C1, with this format's and engine's
    // entropy) vouches for its exact body, and it is for this key; otherwise what is wrong with it. P is bounded before any
    // DPAPI call, and nothing in the body is looked at before DPAPI has vouched for it (class doc). The DPAPI output is a
    // hash, not a secret, but it is zeroed after use all the same (Unprotect zeroes it itself when it refuses the scope).
    private static string? Invalid(byte[] entry, string sourcesSha256)
    {
        if (!entry.AsSpan(0, MagicBytes).SequenceEqual(Encoding.ASCII.GetBytes(Magic)))
            return "unknown format";
        var length = ProtectedLength(entry);
        if (length is < 1 or > MaxProtectedBytes || length > entry.Length - ProtectedOffset - BodyHeaderBytes)
            return $"its DPAPI blob length ({length}) is out of range";

        var body = entry.AsSpan(ProtectedOffset + length);
        var vouched = WindowsSecurityNative.Unprotect(entry.AsSpan(ProtectedOffset, length), Entropy, out var failure);
        try
        {
            return vouched is null && failure == WindowsSecurityNative.NotUserScope ? $"DPAPI did not vouch for it as this user's: {failure}"
                : vouched is null ? $"DPAPI did not vouch for it ({YaraXText.Bounded(failure)})"
                : vouched.Length != Sha256Bytes ? $"its DPAPI payload is {vouched.Length} bytes, not {Sha256Bytes}"
                : !CryptographicOperations.FixedTimeEquals(vouched, SHA256.HashData(body))
                    ? "its body does not match the hash DPAPI vouches for (corrupt, or not written by Silvergun for you)"
                : !Convert.ToHexStringLower(body[..Sha256Bytes]).Equals(sourcesSha256, StringComparison.Ordinal) ? "it is for other rule sources"
                : null;
        }
        finally
        {
            if (vouched is not null)
                CryptographicOperations.ZeroMemory(vouched);
        }
    }

    // P, the length of the DPAPI blob (unchecked: Invalid bounds it).
    private static int ProtectedLength(byte[] entry) => BinaryPrimitives.ReadInt32LittleEndian(entry.AsSpan(ProtectedLengthOffset, sizeof(int)));

    // Where the body starts, in an entry Invalid has accepted.
    private static int BodyOffset(byte[] entry) => ProtectedOffset + ProtectedLength(entry);
    #endregion

    #region Fields
    // Why an entry whose DACL is not our own entries' is refused (ReadIfOwned); NotOwnEntryDacl says which part differs.
    private const string NotOwnEntryPermissions =
        "its permissions are not the ones Silvergun gives its own entries (a single full-control entry for you)";

    // The buffer of the stream a temp entry is written through (one ~2.3 MB write; any size will do).
    private const int TempBufferBytes = 4096;

    // The entry format (class doc). PreviousMagic's entries are silent misses, replaced by the next store.
    private const string Magic = "SGYXRC03";
    private const string PreviousMagic = "SGYXRC02";
    private const int MagicBytes = 8;
    private const int Sha256Bytes = 32;
    private const int CanaryIdBytes = 16;

    // The entry: the magic, P, the DPAPI blob (P bytes, at most MaxProtectedBytes), then the body.
    private const int ProtectedLengthOffset = MagicBytes;
    private const int ProtectedOffset = ProtectedLengthOffset + sizeof(int);
    private const int MaxProtectedBytes = 1024;

    // The body, at offsets from its start: sources sha256, canary id, canary marker, rule count, then the serialized rules.
    private const int SourcesOffset = 0;
    private const int CanaryIdOffset = SourcesOffset + Sha256Bytes;
    private const int MarkerOffset = CanaryIdOffset + CanaryIdBytes;
    private const int RuleCountOffset = MarkerOffset + YaraXCanary.MarkerBytes;
    private const int BodyHeaderBytes = RuleCountOffset + sizeof(int);

    // The smallest entry with a DPAPI blob and a body header: smaller is not an entry at all.
    private const int MinEntryBytes = ProtectedOffset + 1 + BodyHeaderBytes;

    // The 1,240-rule blob is ~2.3 MB; anything near this is not ours.
    private const long MaxEntryBytes = 256L * 1024 * 1024;

    // The cache's own files: entries (EntryPath) and the temp files they are written through (Store).
    private const string EntryPattern = "rules-*.sgyx";
    private const string TempPattern = "*.tmp";

    // A temp file untouched this long is an orphan (see SweepStaleTemps): 40× the 15 s startup bound inside which every
    // live writer finishes or is killed, so no live writer's temp is swept; an orphan goes at the next write after that.
    private static readonly TimeSpan StaleTempAge = TimeSpan.FromMinutes(10);

    // How long a load or store waits for the cache lock (W-B). A holder only checks the directory and reads or writes one
    // ~2.3 MB entry, so this is generous; and two waits plus a ~1.6 s compile stay well inside the 15 s startup bound (G9).
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(2);

    // The DPAPI entropy (class doc), derived from Magic, so bumping the format changes it: a blob made for another format
    // or engine version does not unprotect.
    private static readonly byte[] Entropy = Encoding.ASCII.GetBytes($"Silvergun YARA-X rules cache {Magic}|{YaraXNative.EngineVersion}");
    #endregion
}
#endif
