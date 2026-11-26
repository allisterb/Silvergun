namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// The on-disk job cache (task D4, D4a and the S1 design). Layout under <see cref="Root"/>:
/// <c>&lt;sha256&gt;/&lt;buildKey&gt;-&lt;depth&gt;/</c> is a completed entry; <c>….tmp-&lt;12&gt;</c> is a run in progress;
/// <c>….lock</c> is the entry's lock, held by the one process that runs or deletes it; <c>incoming/</c> holds input copies
/// not yet hashed into a key. Deletion only ever acts on names that match this code's exact, anchored patterns. Every
/// directory is created private to the user.
/// </summary>
public sealed class JobStore(string root, long maxBytes, bool network = false)
{
    #region Properties
    public string Root { get; } = root;

    public long MaxBytes { get; } = maxBytes;

    /// <summary>Whether this server's jobs may run OSV: part of every entry's name, so results with and without it never mix (S1 review round 2, W2).</summary>
    public bool Network { get; } = network;
    #endregion

    #region Methods
    /// <summary>Creates the cache root private to the user when it is missing; null, or why the cache cannot be used (a link).</summary>
    public string? Prepare()
    {
        try
        {
            if (new[] { Path.GetDirectoryName(Root), Root }.FirstOrDefault(p => p is not null && IsLink(p)) is { } link)
                return $"the cache directory or its parent is a link ({UntrustedText.Escape(Path.GetFileName(link))})";
            CreatePrivate(Root);
            return IsLink(Root) ? "the cache directory is a link" : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return $"the cache directory could not be created ({ex.GetType().Name})";
        }
    }

    /// <summary>An entry's directory name: <c>&lt;buildKey&gt;-&lt;depth&gt;</c>, with <c>-net</c> when OSV may run.</summary>
    public static string EntryName(JobDepth depth, bool network = false) => $"{BuildIdentity.BuildKey}-{DepthName(depth)}{(network ? NetworkSuffix : "")}";

    public static string DepthName(JobDepth depth) => depth == JobDepth.Deep ? "deep" : "standard";

    public string EntryDir(string sha256, JobDepth depth) => Path.Combine(Root, sha256, EntryName(depth, Network));

    /// <summary>The completed entry for the key, or null with why not (absent, or present but not usable: re-run it).</summary>
    public (JobRecord? Record, string? Problem) Completed(string sha256, JobDepth depth)
    {
        var dir = EntryDir(sha256, depth);
        return Directory.Exists(dir) ? JobArtifacts.ReadRecord(dir, sha256, depth, BuildIdentity.BuildKey) : (null, null);
    }

    /// <summary>The entry's lock, held exclusively until disposed, or null when another process holds it.</summary>
    public FileStream? TryLock(string sha256, JobDepth depth)
    {
        CreatePrivate(Path.Combine(Root, sha256));
        try
        {
            return new FileStream(EntryDir(sha256, depth) + LockSuffix, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None);
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// Under the key's lock: deletes the temporary siblings a killed server left (their lock is free, so nothing runs in them)
    /// and an entry that failed its checks. Only exact names this code writes are touched.
    /// </summary>
    public void Clean(string sha256, JobDepth depth, bool deleteEntry)
    {
        var name = EntryName(depth, Network);
        var temp = new Regex($"^{name}{Regex.Escape(TempMarker)}[a-z0-9]{{12}}$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        foreach (var dir in Directory.EnumerateDirectories(Path.Combine(Root, sha256)).Where(d => temp.IsMatch(Path.GetFileName(d))))
            TryDelete(dir);
        if (deleteEntry)
            TryDelete(EntryDir(sha256, depth));
    }

    /// <summary>A new, private temporary directory for the key's run.</summary>
    public string CreateTemp(string sha256, JobDepth depth)
    {
        var dir = EntryDir(sha256, depth) + TempMarker + Runtime.RandomString(12);
        CreatePrivate(dir);
        return dir;
    }

    /// <summary>
    /// Renames a finished temporary directory into place, so the entry appears whole or not at all. On Windows a rename fails
    /// while any file inside is open (an antivirus scanning the fresh extraction, say), so it is retried, bounded. Null, or
    /// why it could not be committed.
    /// </summary>
    public async Task<string?> CommitAsync(string tempDir, string sha256, JobDepth depth, CancellationToken ct)
    {
        var entry = EntryDir(sha256, depth);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                // A leftover entry here already failed its checks (we hold the key's lock); its deletion is retried like the move.
                if (Directory.Exists(entry))
                    Directory.Delete(entry, recursive: true);
                Directory.Move(tempDir, entry);
                return null;
            }
            catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) && attempt < CommitAttempts)
            {
                await Task.Delay(CommitRetry, ct);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return $"the finished job could not be moved into the cache ({ex.GetType().Name}); a file in it, or in a previous entry, may be held open";
            }
        }
    }

    /// <summary>Marks the entry as used now, for eviction (best effort).</summary>
    public void Touch(string sha256, JobDepth depth)
    {
        try
        {
            var marker = Path.Combine(EntryDir(sha256, depth), AccessMarker);
            using (new FileStream(marker, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite)) { }
            File.SetLastWriteTimeUtc(marker, DateTime.UtcNow);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* an access time is a hint */ }
    }

    /// <summary>A fresh path under <c>incoming/</c> for an input copy; copies a killed server left there over a day ago are deleted first.</summary>
    public string IncomingPath()
    {
        var dir = Path.Combine(Root, IncomingDir);
        CreatePrivate(dir);
        foreach (var stale in Directory.EnumerateFiles(dir).Where(f => incoming.IsMatch(Path.GetFileName(f)) && File.GetLastWriteTimeUtc(f) < DateTime.UtcNow - StaleIncoming))
            try { File.Delete(stale); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* next time */ }
        return Path.Combine(dir, Runtime.RandomString(12) + ".nupkg");
    }

    /// <summary>The total size of a directory's files, not following links.</summary>
    public static long SizeOf(string dir) =>
        new DirectoryInfo(dir).EnumerateFiles("*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true })
            .Sum(f => f.Length);

    /// <summary>
    /// Deletes entries until the cache is under <see cref="MaxBytes"/> (task D4; ADR-0015 §13 in the prior project: recency
    /// alone is no reason). First entries this build can never serve (another build key, or unreadable); then those idle
    /// for an hour, cheapest to rebuild first; only then the least recently used. <paramref name="keep"/> and any entry whose
    /// lock is held (running, or being read for deletion elsewhere) are never touched.
    /// </summary>
    public int Evict((string Sha256, JobDepth Depth)? keep)
    {
        var entries = Entries().ToList();
        var total = entries.Sum(e => e.Bytes);
        if (total <= MaxBytes)
            return 0;

        var keepDir = keep is { } k ? EntryDir(k.Sha256, k.Depth) : null;
        var now = DateTime.UtcNow;
        var order = entries
            .Where(e => !string.Equals(e.Dir, keepDir, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Record is null || e.Record.BuildKey != BuildIdentity.BuildKey ? 0 : now - e.LastUsed >= IdleBeforeCostEviction ? 1 : 2)
            .ThenBy(e => e.Record is not null && now - e.LastUsed >= IdleBeforeCostEviction ? e.Record.ElapsedMs : 0)
            .ThenBy(e => e.LastUsed);
        var deleted = 0;
        foreach (var entry in order)
        {
            if (total <= MaxBytes)
                break;
            using var held = TryLockPath(entry.Dir + LockSuffix);
            if (held is null || !TryDelete(entry.Dir))
                continue;
            total -= entry.Bytes;
            deleted++;
            Runtime.Info("mcp: evicted a cache entry of {0} bytes (cost {1} ms) to keep the cache under {2} bytes.", entry.Bytes, entry.Record?.ElapsedMs ?? 0, MaxBytes);
        }
        return deleted;
    }

    // Every completed-looking entry of any build: a 64-hex package directory, then a <16 hex>-<depth> directory.
    private IEnumerable<(string Dir, JobRecord? Record, long Bytes, DateTime LastUsed)> Entries()
    {
        if (!Directory.Exists(Root))
            yield break;
        foreach (var shaDir in Directory.EnumerateDirectories(Root).Where(d => shaName.IsMatch(Path.GetFileName(d))))
            foreach (var dir in Directory.EnumerateDirectories(shaDir).Where(d => entryName.IsMatch(Path.GetFileName(d))))
            {
                var record = ReadAnyRecord(dir);
                var marker = Path.Combine(dir, AccessMarker);
                var used = File.Exists(marker) ? File.GetLastWriteTimeUtc(marker) : Directory.GetLastWriteTimeUtc(dir);
                yield return (dir, record, record?.EntryBytes ?? SizeOf(dir), used);
            }
    }

    // A record of any build, for eviction's sizes and costs only; null when unreadable.
    private static JobRecord? ReadAnyRecord(string dir)
    {
        var (bytes, _) = JobArtifacts.ReadBounded(Path.Combine(dir, JobProtocol.JobFile), JobArtifacts.MaxRecordBytes);
        try
        {
            return bytes is null ? null : JsonSerializer.Deserialize<JobRecord>(bytes, JobProtocol.JsonOptions) is { EntryBytes: >= 0, ElapsedMs: >= 0 } r ? r : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static FileStream? TryLockPath(string path)
    {
        try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static bool TryDelete(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Runtime.Warn("mcp: could not delete a cache directory ({0}); it is left for later.", ex.GetType().Name);
            return false;
        }
    }

    private static bool IsLink(string path)
    {
        try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return false; }
    }

    // Creates `dir` (and missing parents) private to the user: owner-only and inherited on Windows, 0700 elsewhere.
    private static void CreatePrivate(string dir)
    {
        if (Directory.Exists(dir))
            return;
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dir)!);
            new DirectoryInfo(dir).Create(OwnerOnly());
        }
        else
            Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity OwnerOnly()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new InvalidOperationException("the current user has no SID");
        var security = new DirectorySecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }
    #endregion

    #region Fields
    private const string LockSuffix = ".lock";
    private const string TempMarker = ".tmp-";
    private const string AccessMarker = ".accessed";
    private const string IncomingDir = "incoming";

    private const int CommitAttempts = 5;
    private static readonly TimeSpan CommitRetry = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan IdleBeforeCostEviction = TimeSpan.FromHours(1);
    private static readonly TimeSpan StaleIncoming = TimeSpan.FromDays(1);

    private static readonly Regex shaName = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    private const string NetworkSuffix = "-net";

    private static readonly Regex entryName = new("^[0-9a-f]{16}-(standard|deep)(-net)?$", RegexOptions.CultureInvariant);
    private static readonly Regex incoming = new("^[a-z0-9]{12}\\.nupkg$", RegexOptions.CultureInvariant);
    #endregion
}
