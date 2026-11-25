#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// A tree for the Linux rules-cache tests (docs/agent/tasks/yarax-worker-linux.md, Phase 2, P4): <see cref="Base"/> is a
/// <c>silvergun-yara-x-…</c> directory directly under the sticky <c>/tmp</c>, created mode 700, so it passes the cache's
/// secure-path walk; the test then sets the modes of what it builds under it. Disposal touches nothing outside
/// <see cref="Base"/>: links are unlinked as links (never followed), every real directory is made 700 again so its
/// contents can be removed, and only then is <see cref="Base"/> deleted.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxCacheTree : IDisposable
{
    #region Constructors
    public LinuxCacheTree(string purpose)
    {
        Base = $"/tmp/silvergun-yara-x-linuxcache-{purpose}-{Guid.NewGuid():N}";
        Directory.CreateDirectory(Base, OwnerOnly);
        System.IO.File.SetUnixFileMode(Base, OwnerOnly);   // the umask only narrows, but be exact
    }
    #endregion

    #region Properties
    public string Base { get; }
    #endregion

    #region Methods
    public string Path(string relative) => System.IO.Path.Combine(Base, relative);

    /// <summary>Creates <paramref name="relative"/> (and any missing parent, 700), then sets its mode exactly.</summary>
    public string Dir(string relative, UnixFileMode mode = OwnerOnly)
    {
        var dir = Path(relative);
        Directory.CreateDirectory(dir, OwnerOnly);
        System.IO.File.SetUnixFileMode(dir, mode);
        Assert.Equal(mode, System.IO.File.GetUnixFileMode(dir));
        return dir;
    }

    /// <summary>A regular file at <paramref name="relative"/>.</summary>
    public string File(string relative, byte[]? bytes = null)
    {
        var file = Path(relative);
        System.IO.File.WriteAllBytes(file, bytes ?? [1, 2, 3]);
        return file;
    }

    /// <summary>A symbolic link at <paramref name="relative"/> to <paramref name="target"/>.</summary>
    public string Symlink(string relative, string target)
    {
        var link = Path(relative);
        System.IO.File.CreateSymbolicLink(link, target);
        Assert.True((System.IO.File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"'{relative}' is not reported as a link");
        return link;
    }

    public void Dispose()
    {
        if (!Base.StartsWith("/tmp/silvergun-yara-x-linuxcache-", StringComparison.Ordinal) || !Directory.Exists(Base))
            return;
        try
        {
            Unlock(Base);
            Directory.Delete(Base, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // best effort: the suite's temp-leak check counts what remains
        }

        static void Unlock(string dir)
        {
            System.IO.File.SetUnixFileMode(dir, OwnerOnly);
            foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
            {
                var attributes = System.IO.File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    System.IO.File.Delete(entry);   // the link itself
                else if ((attributes & FileAttributes.Directory) != 0)
                    Unlock(entry);
            }
        }
    }
    #endregion

    #region Fields
    internal const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    internal const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    internal const UnixFileMode Mode755 = OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
    internal const UnixFileMode Mode777 = Mode755 | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
    #endregion
}

/// <summary>The rules, keys and file-system helpers the Linux rules-cache tests share.</summary>
[SupportedOSPlatform("linux")]
internal static class LinuxRulesCache
{
    #region Properties
    // The cache key of Sources, for TryLoad called directly.
    internal static string Key => YaraXRules.SourcesSha256Of(Sources);
    #endregion

    #region Methods
    internal static void EnsureEngine() =>
        Assert.True(YaraXNative.TryLoad(out var failure), $"the YARA-X engine did not load in the test host: {failure}");

    /// <summary>The two-rule ruleset through <see cref="YaraXEngine.Load(IReadOnlyList{ValueTuple{string, string}}, IYaraXRulesCache?)"/>.</summary>
    internal static YaraXRulesCacheTestRulesLoaded Load(YaraXLinuxRulesCache cache)
    {
        EnsureEngine();
        var result = YaraXEngine.Load(Sources, cache);
        Assert.True(result.Rules is not null, $"the engine did not load: {result.Failure}");
        return new(result.Rules!, result.FromCache);
    }

    /// <summary>A fresh compile of the two-rule ruleset (its own canary), for Store/TryLoad called directly.</summary>
    internal static YaraXRules Compile(IReadOnlyList<(string Name, string Text)>? sources = null)
    {
        EnsureEngine();
        var rules = YaraXRules.Compile(sources ?? Sources, out var failure);
        Assert.True(rules is not null, $"the test rules did not compile: {failure}");
        return rules!;
    }

    internal static string EntryPath(YaraXLinuxRulesCache cache) => cache.EntryPath(Key)!;

    /// <summary>A hard link <paramref name="link"/> to <paramref name="target"/> (<c>ln</c>: the BCL has no hard link).</summary>
    internal static void HardLink(string target, string link) => Tool("ln", "--", target, link);

    /// <summary>One line of <c>stat -c <paramref name="format"/></c> for <paramref name="path"/> (links not followed).</summary>
    internal static string Stat(string format, string path) => Tool("stat", "-c", format, "--", path).Trim();

    private static string Tool(string name, params string[] args)
    {
        var psi = new ProcessStartInfo(name) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(10_000), $"{name} did not exit within 10 s");
        Assert.True(process.ExitCode == 0, $"{name} {string.Join(' ', args)} failed ({process.ExitCode}): {stderr.Result}");
        return stdout.Result;
    }
    #endregion

    #region Fields
    internal static readonly IReadOnlyList<(string Name, string Text)> Sources =
    [
        ("linux-cache-a.yar", "rule linux_cache_a { condition: false }"),
        ("linux-cache-b.yar", "rule linux_cache_b { strings: $s = \"silvergun linux rules cache\" condition: $s }"),
    ];
    #endregion
}

internal sealed record YaraXRulesCacheTestRulesLoaded(YaraXRules Rules, bool FromCache) : IDisposable
{
    public void Dispose() => Rules.Dispose();
}

/// <summary>
/// Runs on Linux only, and is a VISIBLE skip when a row's ownership premise does not hold here (review S3):
/// <see cref="NotRoot"/>, the suite does not run as euid 0; <see cref="RootOwnsSystemDirs"/>, <c>/</c>, <c>/usr</c> and
/// <c>/tmp</c> are uid 0's (in a user namespace they can show as the overflow uid).
/// </summary>
public sealed class OnLinuxOwnershipFactAttribute : FactAttribute
{
    #region Constructors
    public OnLinuxOwnershipFactAttribute() => Skip = PlatformSkip.UnlessLinux;
    #endregion

    #region Properties
    public bool NotRoot
    {
        get => _notRoot;
        set { _notRoot = value; Skip = Reason(); }
    }

    public bool RootOwnsSystemDirs
    {
        get => _rootOwnsSystemDirs;
        set { _rootOwnsSystemDirs = value; Skip = Reason(); }
    }
    #endregion

    #region Methods
    private string? Reason()
    {
        if (!OperatingSystem.IsLinux())
            return PlatformSkip.UnlessLinux;
        if (_notRoot && LinuxSecurityNative.EffectiveUid() == 0)
            return "this row needs a user other than root (the suite runs as euid 0, which owns what root owns).";
        if (_rootOwnsSystemDirs && new[] { "/", "/usr", "/tmp" }.Any(d => LinuxSecurityNative.Lstat(d) is not { Uid: 0 }))
            return "this row needs /, /usr and /tmp owned by uid 0; here one is not (a user namespace?).";
        return null;
    }
    #endregion

    #region Fields
    private bool _notRoot;
    private bool _rootOwnsSystemDirs;
    #endregion
}

/// <summary>
/// Runs on Linux only when <c>/tmp</c> holds a directory that is not this user's (WSL has root's <c>/tmp/.X11-unix</c>):
/// the walk's "directly under a sticky directory, root is not enough" row needs one, and only root could make one. A
/// VISIBLE skip otherwise.
/// </summary>
public sealed class OnLinuxWithForeignTmpDirFactAttribute : FactAttribute
{
    #region Constructors
    public OnLinuxWithForeignTmpDirFactAttribute() =>
        Skip = PlatformSkip.UnlessLinux ?? (ForeignTmpDir() is null
            ? "no directory directly under /tmp is owned by another user (WSL has root's /tmp/.X11-unix); only root could make one."
            : null);
    #endregion

    #region Methods
    /// <summary>A real directory (not a link) directly under <c>/tmp</c> owned by another uid, or <c>null</c>.</summary>
    internal static (string Path, uint Uid)? ForeignTmpDir()
    {
        if (!OperatingSystem.IsLinux())
            return null;
        var user = LinuxSecurityNative.EffectiveUid();
        foreach (var dir in Directory.EnumerateDirectories("/tmp").Order(StringComparer.Ordinal))
        {
            try
            {
                if (LinuxSecurityNative.Lstat(dir) is { IsDirectory: true } status && status.Uid != user)
                    return (dir, status.Uid);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // gone, or not ours to stat: try the next
            }
        }
        return null;
    }
    #endregion
}
#endif
