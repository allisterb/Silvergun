#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;
using Xunit.Abstractions;

using static LinuxRulesCache;

/// <summary>
/// The Linux compiled-rules cache, <see cref="YaraXLinuxRulesCache"/> (docs/agent/tasks/yarax-worker-linux.md, Phase 2,
/// P3; the test list is P4). Integrity rests on the PATH: every directory from <c>/</c> down to the cache must be a real
/// directory owned by root or the user and not group- or other-writable unless sticky (and then the next one down is the
/// user's), the cache directory the user's at 700, and an entry a regular file of the user's at 600 with one link, checked
/// on the handle it is read through. Each row is built for real under a <c>/tmp</c> tree the test owns
/// (<see cref="LinuxCacheTree"/>); the reasons asserted are the warning text. Owner rows that need another (non-root) uid
/// cannot be built without root and are not here; root's <c>/</c> and, where WSL has one, root's <c>/tmp/.X11-unix</c>
/// stand in.
///
/// <para>Entry layout (<c>SGYXRL01</c>): magic 0..8, sha256(body) 8..40, then the body (<see cref="YaraXRulesEntry"/>):
/// sources sha256 +0..32, canary id +32..48, marker +48..80, rule count +80..84, the serialized rules +84..end.</para>
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class YaraXLinuxRulesCacheTests(ITestOutputHelper output)
{
    #region Methods: the walk accepts
    // The base tree is a user-owned 700 directory directly under the sticky, world-writable, root-owned /tmp.
    [OnLinuxOwnershipFact(RootOwnsSystemDirs = true)]
    public void Walk_AStickyTmp_WithAUserOwnedChild_IsTrusted()
    {
        using var tree = new LinuxCacheTree("walk-tmp");
        var cache = tree.Dir("cache");
        var tmp = LinuxSecurityNative.Lstat("/tmp")!.Value;
        Assert.True((tmp.Permissions & UnixFileMode.StickyBit) != 0 && (tmp.Permissions & UnixFileMode.OtherWrite) != 0 && tmp.Uid == 0,
            $"the precondition failed: /tmp is not root's sticky world-writable directory (mode {Convert.ToString((int)tmp.Permissions, 8)}, uid {tmp.Uid})");

        Assert.Equal((null, false), Walk(cache));
    }

    // A sticky world-writable directory of the user's own, then the cache directory directly under it.
    [OnLinuxFact]
    public void Walk_AStickyWorldWritableAncestor_WithAUserOwnedChild_IsTrusted()
    {
        using var tree = new LinuxCacheTree("walk-sticky");
        tree.Dir("shared", LinuxCacheTree.Mode777 | UnixFileMode.StickyBit);
        var cache = tree.Dir("shared/cache");

        Assert.Equal((null, false), Walk(cache));
    }

    // Set-uid, set-gid and sticky mean nothing for an owner-only directory (set-gid is inherited from a set-gid parent).
    [OnLinuxTheory]
    [InlineData(UnixFileMode.SetGroup)]
    [InlineData(UnixFileMode.SetUser)]
    [InlineData(UnixFileMode.StickyBit)]
    public void Walk_ACacheDirectoryAt700_WithASpecialBit_IsTrusted(UnixFileMode special)
    {
        using var tree = new LinuxCacheTree("walk-special");
        var cache = tree.Dir("cache", LinuxCacheTree.OwnerOnly | special);

        Assert.Equal((null, false), Walk(cache));
    }

    // Root may own an ancestor (here /usr) that is not under a sticky directory. Nothing is created: only the walk runs.
    [OnLinuxOwnershipFact(RootOwnsSystemDirs = true)]
    public void Walk_ARootOwnedAncestor_IsTrusted_AndAMissingDirectoryBelowItIsMissing()
    {
        var dir = $"/usr/silvergun-yara-x-not-created-{Guid.NewGuid():N}/cache";
        Assert.Equal(0u, LinuxSecurityNative.Lstat("/usr")!.Value.Uid);

        Assert.Equal((null, true), Walk(dir));
        Assert.False(Directory.Exists(Path.GetDirectoryName(dir)));
    }

    // Every existing component passed and the first missing one ends the walk: "missing", not a refusal.
    [OnLinuxFact]
    public void Walk_MissingComponentsBelowTrustedOnes_AreMissing_NotRefused()
    {
        using var tree = new LinuxCacheTree("walk-missing");

        Assert.Equal((null, true), Walk(tree.Path("a/b/cache")));
        Assert.Equal((null, true), Walk(tree.Path("cache")));
        Assert.False(Directory.Exists(tree.Path("a")));
    }
    #endregion

    #region Methods: the walk refuses
    // Group- or other-writable without the sticky bit: anyone with that write can rename the cache's parent away.
    [OnLinuxTheory]
    [InlineData(0b111_111_000, "770")]
    [InlineData(0b111_010_000, "720")]
    [InlineData(0b111_000_010, "702")]
    [InlineData(0b111_111_111, "777")]
    [InlineData(0b111_101_111, "757")]
    public void Walk_AGroupOrOtherWritableNonStickyAncestor_IsRefused(int mode, string octal)
    {
        using var tree = new LinuxCacheTree("walk-writable");
        var open = tree.Dir("open", (UnixFileMode)mode);
        var cache = tree.Dir("open/cache");

        Assert.Equal(($"a directory on the way is writable by other users (mode {octal}): {open}", false), Walk(cache));
    }

    // Root owning a directory directly under a sticky shared one is NOT enough (only the user's is): anyone could have
    // made it before root took it, or root made it shared on purpose.
    [OnLinuxWithForeignTmpDirFact]
    public void Walk_ADirectoryUnderAStickyOneOwnedBySomeoneElse_IsRefused()
    {
        var (foreign, uid) = OnLinuxWithForeignTmpDirFactAttribute.ForeignTmpDir()!.Value;

        Assert.Equal(($"a directory in a shared sticky directory is owned by uid {uid}, not by you: {foreign}", false),
            Walk($"{foreign}/silvergun/yara-x-rules"));
    }

    // The cache directory itself must be the user's: root's `/` is not. A skip as root, or where `/` is not uid 0's.
    [OnLinuxOwnershipFact(NotRoot = true, RootOwnsSystemDirs = true)]
    public void Walk_ACacheDirectoryOwnedByRoot_IsRefused()
    {
        var user = LinuxSecurityNative.EffectiveUid();

        Assert.Equal(($"it is owned by uid 0, not by you (uid {user})", false), Walk("/"));
    }

    [OnLinuxFact]
    public void Walk_ASymlinkedAncestor_IsRefused()
    {
        using var tree = new LinuxCacheTree("walk-link-ancestor");
        var real = tree.Dir("real");
        tree.Dir("real/cache");
        var link = tree.Symlink("link", real);

        Assert.Equal(($"a component is not a directory (it is a link, or another kind of file): {link}", false), Walk(link + "/cache"));
        Assert.Equal((null, false), Walk(real + "/cache"));   // the control: the same directory by its real path
    }

    [OnLinuxFact]
    public void Walk_ASymlinkedCacheDirectory_IsRefused()
    {
        using var tree = new LinuxCacheTree("walk-link-cache");
        var real = tree.Dir("real");
        var link = tree.Symlink("cache", real);

        Assert.Equal(($"a component is not a directory (it is a link, or another kind of file): {link}", false), Walk(link));
    }

    [OnLinuxTheory]
    [InlineData(0b111_101_000, "750")]
    [InlineData(0b111_101_101, "755")]
    [InlineData(0b111_001_001, "711")]
    [InlineData(0b101_000_000, "500")]
    [InlineData(0b111_111_111, "777")]
    public void Walk_ACacheDirectoryNotAt700_IsRefused(int mode, string octal)
    {
        using var tree = new LinuxCacheTree("walk-cache-mode");
        var cache = tree.Dir("cache", (UnixFileMode)mode);

        Assert.Equal(($"its mode is {octal}, not 700 (delete it and Silvergun will recreate it)", false), Walk(cache));
    }

    [OnLinuxTheory]
    [InlineData("/tmp/./silvergun/yara-x-rules")]
    [InlineData("/tmp/../tmp/silvergun/yara-x-rules")]
    [InlineData("/tmp/silvergun/yara-x-rules/.")]
    [InlineData("/tmp/silvergun/yara-x-rules/..")]
    [InlineData("tmp/silvergun/yara-x-rules")]
    [InlineData("")]
    public void Walk_APathWithDotSegmentsOrNotAbsolute_IsRefused(string dir) =>
        Assert.Equal(("it is not an absolute path free of '.' and '..'", false), Walk(dir));

    // A regular file where a directory should be, as an ancestor and as the cache directory itself; and a FIFO.
    [OnLinuxFact]
    public void Walk_ANonDirectoryComponent_IsRefused()
    {
        using var tree = new LinuxCacheTree("walk-file");
        var file = tree.File("file");
        var fifo = tree.Path("fifo");
        LinuxYaraX.MakeFifo(fifo);
        const string notADirectory = "a component is not a directory (it is a link, or another kind of file):";

        Assert.Equal(($"{notADirectory} {file}", false), Walk(file + "/cache"));
        Assert.Equal(($"{notADirectory} {file}", false), Walk(file));
        Assert.Equal(($"{notADirectory} {fifo}", false), Walk(fifo));
    }

    // A refusal ends the walk: a missing directory below a refused one is not "missing" (it would then be created).
    [OnLinuxFact]
    public void Walk_AMissingDirectoryBelowARefusedOne_IsRefused_NotMissing()
    {
        using var tree = new LinuxCacheTree("walk-refused-missing");
        var open = tree.Dir("open", LinuxCacheTree.Mode777);

        Assert.Equal(($"a directory on the way is writable by other users (mode 777): {open}", false), Walk(open + "/silvergun/yara-x-rules"));
    }
    #endregion

    #region Methods: path forms (review S2)
    // An empty segment ("//", a trailing "/") is dropped, as the kernel does: the same trusted directory.
    [OnLinuxFact]
    public void Walk_ATrailingSlashOrADoubleSlash_IsTheSameTrustedDirectory()
    {
        using var tree = new LinuxCacheTree("walk-slashes");
        var cache = tree.Dir("cache");

        Assert.Equal((null, false), Walk(cache + "/"));
        Assert.Equal((null, false), Walk(tree.Base + "//cache"));
        Assert.Equal((null, false), Walk(tree.Base + "//cache//"));
    }

    // A location with a trailing slash or a double slash stores, and the next load hits.
    [LinuxYaraXTheory]
    [InlineData("xdg/silvergun/yara-x-rules/")]
    [InlineData("xdg//silvergun/yara-x-rules")]
    public void Load_ThroughALocationWithEmptySegments_StoresThenHits(string relative)
    {
        using var tree = new LinuxCacheTree("load-slashes");
        var cache = new YaraXLinuxRulesCache(tree.Base + "/" + relative);

        using (var first = Load(cache))
            Assert.False(first.FromCache);
        using var second = Load(cache);

        Assert.True(second.FromCache);
        Assert.Single(Directory.GetFiles(tree.Path("xdg/silvergun/yara-x-rules"), "rules-*.sgyx"));
        AssertCreatedOwnerOnly(tree.Path("xdg"), tree.Path("xdg/silvergun"), tree.Path("xdg/silvergun/yara-x-rules"));
    }
    #endregion

    #region Methods: the location through the cache (created, or refused and never corrected)
    // Constructing a cache (and naming its entry) touches nothing on disk: only TryLoad and Store prepare the directory.
    [OnLinuxFact]
    public void Constructing_ACache_CreatesNothing()
    {
        using var tree = new LinuxCacheTree("construct");

        var cache = new YaraXLinuxRulesCache(tree.Path("xdg/silvergun/yara-x-rules"));
        _ = cache.EntryPath(Key);

        Assert.Empty(Directory.EnumerateFileSystemEntries(tree.Base));
    }

    // Review S1, the outcome (not the race): a middle component of the location is already a link to a directory of the
    // test's own. The store is refused at the link, and nothing is created under the link's target.
    [LinuxYaraXFact]
    public void Store_WhenAMiddleComponentIsASymlink_IsRefused_AndCreatesNothingUnderItsTarget()
    {
        using var tree = new LinuxCacheTree("store-planted-link");
        tree.Dir("xdg");
        var target = tree.Dir("target");
        var link = tree.Symlink("xdg/silvergun", target);
        var cache = new YaraXLinuxRulesCache(tree.Path("xdg/silvergun/yara-x-rules"));
        using var rules = Compile();
        using var warnings = new WarningCapture();

        Assert.False(cache.Store(rules));

        AssertOnlyWarning(warnings, $"YARA-X rules cache: not using {cache.Location}: a component is not a directory (it is a link, or another kind of file): {link}.");
        Assert.Empty(Directory.EnumerateFileSystemEntries(target));
    }

    // Missing components are created 700 (every one, never wider whatever the umask), the entry 600 with one link, and no
    // temp file is left.
    [LinuxYaraXFact]
    public void Store_CreatesTheMissingDirectoriesAt700_AndTheEntryAt600_AndLeavesNoTempFile()
    {
        using var tree = new LinuxCacheTree("store");
        var cache = new YaraXLinuxRulesCache(tree.Path("xdg/silvergun/yara-x-rules"));
        using var rules = Compile();

        Assert.True(cache.Store(rules));

        AssertCreatedOwnerOnly(tree.Path("xdg"), tree.Path("xdg/silvergun"), tree.Path("xdg/silvergun/yara-x-rules"));
        var path = EntryPath(cache);
        var entry = LinuxSecurityNative.Lstat(path)!.Value;
        Assert.True(entry.IsRegularFile);
        Assert.Equal((LinuxCacheTree.OwnerOnlyFile, 1u, LinuxSecurityNative.EffectiveUid()), (entry.Permissions, entry.Links, entry.Uid));
        Assert.Equal(new[] { path }, Directory.GetFileSystemEntries(cache.Location!));
        Assert.Empty(Directory.EnumerateFiles(cache.Location!, "*.tmp"));
    }

    // The file name, magic and hash: rules-<engine version>-<key>.sgyx, "SGYXRL01", sha256 of exactly the body after it.
    [LinuxYaraXFact]
    public void Store_WritesTheSgyxrl01Format()
    {
        using var tree = new LinuxCacheTree("format");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        using var rules = Compile();

        Assert.True(cache.Store(rules));

        var path = EntryPath(cache);
        Assert.Equal(Path.Combine(tree.Path("cache"), $"rules-{YaraXNative.EngineVersion}-{Key}.sgyx"), path);
        var entry = File.ReadAllBytes(path);
        Assert.Equal("SGYXRL01", Encoding.ASCII.GetString(entry, 0, 8));
        Assert.Equal(SHA256.HashData(entry.AsSpan(40)), entry[8..40]);
        Assert.Equal(Key, Convert.ToHexStringLower(entry.AsSpan(40, 32)));
        Assert.Equal(rules.Canary.Marker.ToArray(), entry[88..120]);
        Assert.Equal(2, BitConverter.ToInt32(entry, 120));
    }

    // A ruleset with a source in error is never written (amendment G1): a hit must vouch for every source.
    [LinuxYaraXFact]
    public void Store_ARulesetWithSourceErrors_IsNotWritten()
    {
        using var tree = new LinuxCacheTree("source-errors");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        using var rules = Compile([.. Sources, ("broken.yar", "rule broken { condition: not_an_identifier_anywhere }")]);
        Assert.Equal(1, rules.SourceErrors);
        using var warnings = new WarningCapture();

        Assert.False(cache.Store(rules));

        Assert.Contains("YARA-X rules cache: not caching these rules: 1 rule source(s) had compile errors.", warnings.Warnings);
        Assert.False(File.Exists(cache.EntryPath(rules.SourcesSha256)));
    }

    // N3 on Linux: a temp file nobody has written for 10 minutes is an orphan and goes at the next store; a fresh one stays.
    [LinuxYaraXFact]
    public void Store_SweepsStaleTempFiles_AndKeepsFreshOnes()
    {
        using var tree = new LinuxCacheTree("sweep");
        var cache = new YaraXLinuxRulesCache(tree.Dir("cache"));
        var stale = tree.File("cache/orphan.tmp");
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddHours(-1));
        var fresh = tree.File("cache/live.tmp");
        using var rules = Compile();

        Assert.True(cache.Store(rules));

        Assert.False(File.Exists(stale));
        Assert.True(File.Exists(fresh));
    }

    // A group-writable ancestor: the cache is not used (the rules still compile), the missing cache directory is NOT created
    // under it, and the ancestor's mode is left as it was. The warning is the walk's reason.
    [LinuxYaraXFact]
    public void Load_UnderAGroupWritableAncestor_DoesNotUseTheCache_CreatesNothing_AndCorrectsNothing()
    {
        using var tree = new LinuxCacheTree("load-writable");
        var open = tree.Dir("open", (UnixFileMode)0b111_111_000);
        var cache = new YaraXLinuxRulesCache(open + "/silvergun/yara-x-rules");
        using var warnings = new WarningCapture();

        using (var first = Load(cache))
            Assert.False(first.FromCache);
        using (var second = Load(cache))
            Assert.False(second.FromCache);

        AssertOnlyWarning(warnings, $"YARA-X rules cache: not using {cache.Location}: a directory on the way is writable by other users (mode 770): {open}.");
        Assert.Empty(Directory.EnumerateFileSystemEntries(open));
        Assert.Equal((UnixFileMode)0b111_111_000, File.GetUnixFileMode(open));
    }

    // A valid entry in a directory that has become 755 is not read, and the directory is neither chmodded nor rewritten.
    [LinuxYaraXFact]
    public void Load_FromACacheDirectoryAt755_IgnoresItsValidEntry_AndChangesNothing()
    {
        using var tree = new LinuxCacheTree("load-755");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        Warm(cache);
        var path = EntryPath(cache);
        var before = File.ReadAllBytes(path);
        var written = File.GetLastWriteTimeUtc(path);
        File.SetUnixFileMode(cache.Location!, LinuxCacheTree.Mode755);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, "an entry in a 755 directory was loaded");

        AssertOnlyWarning(warnings, $"YARA-X rules cache: not using {cache.Location}: its mode is 755, not 700 (delete it and Silvergun will recreate it).");
        Assert.Equal(LinuxCacheTree.Mode755, File.GetUnixFileMode(cache.Location!));
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Equal(written, File.GetLastWriteTimeUtc(path));
    }

    // A valid cache reached through a symlinked ancestor is not read, and its entry is not rewritten through the link.
    [LinuxYaraXFact]
    public void Load_ThroughASymlinkedAncestor_IgnoresTheValidCacheBehindIt()
    {
        using var tree = new LinuxCacheTree("load-link");
        var real = tree.Dir("real");
        var target = new YaraXLinuxRulesCache(real + "/cache");
        Warm(target);
        var planted = File.ReadAllBytes(EntryPath(target));
        var link = tree.Symlink("link", real);
        var cache = new YaraXLinuxRulesCache(link + "/cache");
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, "the cache behind a symlinked ancestor was loaded");

        AssertOnlyWarning(warnings, $"YARA-X rules cache: not using {cache.Location}: a component is not a directory (it is a link, or another kind of file): {link}.");
        Assert.Equal(planted, File.ReadAllBytes(EntryPath(target)));
        Assert.Equal(new[] { EntryPath(target) }, Directory.GetFileSystemEntries(target.Location!));
    }

    // A relative location is refused (and nothing is created relative to the working directory).
    [LinuxYaraXFact]
    public void Load_FromARelativeLocation_DoesNotUseTheCache()
    {
        var relative = $"silvergun-yara-x-relative-{Guid.NewGuid():N}";
        var cache = new YaraXLinuxRulesCache(relative);
        using var warnings = new WarningCapture();

        using (var loaded = Load(cache))
            Assert.False(loaded.FromCache);

        AssertOnlyWarning(warnings, $"YARA-X rules cache: not using {relative}: it is not an absolute path free of '.' and '..'.");
        Assert.False(Directory.Exists(Path.Combine(Environment.CurrentDirectory, relative)));
    }
    #endregion

    #region Methods: hit
    [LinuxYaraXFact]
    public void Load_CompilesAndStores_ThenTheNextLoadComesFromTheCache_AndScans()
    {
        using var tree = new LinuxCacheTree("hit");
        var cache = new YaraXLinuxRulesCache(tree.Path("xdg/silvergun/yara-x-rules"));
        using var warnings = new WarningCapture();

        using (var first = Load(cache))
            Assert.False(first.FromCache);
        Assert.True(File.Exists(EntryPath(cache)));
        using var second = Load(cache);
        using var scanner = second.Rules.CreateScanner(5);

        Assert.True(second.FromCache);
        Assert.Equal((2, Key), (second.Rules.RuleCount, second.Rules.SourcesSha256));
        Assert.Null(scanner.CheckCanary());
        var hits = Assert.IsType<YaraXScanResult.Scanned>(scanner.Scan(Encoding.ASCII.GetBytes("xx silvergun linux rules cache xx"))).Hits;
        Assert.Equal(new[] { "linux_cache_b" }, hits.Select(h => h.Rule));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache", StringComparison.Ordinal));
    }

    // The cache in this host is XDG_CACHE_HOME's (the private one TestHostXdgCache set), as for any process.
    [OnLinuxFact]
    public void DefaultDirectory_IsUnderXdgCacheHome()
    {
        Assert.NotNull(TestHostXdgCache.Root);

        Assert.Equal(Path.Combine(TestHostXdgCache.Root!, "silvergun", "yara-x-rules"), YaraXLinuxRulesCache.DefaultDirectory());
        Assert.Equal(YaraXLinuxRulesCache.DefaultDirectory(), new YaraXLinuxRulesCache().Location);
    }
    #endregion

    #region Methods: whose entry
    // Each kind of entry that is not this user's own regular 600 single-link file is refused on sight, with ONE warning
    // naming why; the rules are recompiled, the store renames a fresh entry over it, and the next load hits.
    public static TheoryData<string> NotOwnEntry() => new() { "symlink", "mode 644", "mode 640", "mode 400", "hard link", "fifo" };

    [LinuxYaraXTheory]
    [MemberData(nameof(NotOwnEntry))]
    public async Task AnEntryThatIsNotTheUsersOwn_IsRefused_Recompiled_AndReplaced(string what)
    {
        using var tree = new LinuxCacheTree("entry");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        Warm(cache);
        var path = EntryPath(cache);
        var elsewhere = tree.Dir("elsewhere") + "/entry.sgyx";
        var expected = Stage(what, path, elsewhere);
        var aside = File.Exists(elsewhere) ? File.ReadAllBytes(elsewhere) : null;
        using var warnings = new WarningCapture();

        // Off this thread with a bound: opening a FIFO would block forever.
        var reloaded = await Task.Run(() => Load(cache)).WaitAsync(TimeSpan.FromSeconds(60));
        using (reloaded)
            Assert.False(reloaded.FromCache, $"{what}: the entry was loaded");

        Assert.Equal($"YARA-X rules cache: ignoring {path}: {expected}. The rules will be recompiled.", Assert.Single(warnings.Warnings));
        AssertRewrittenAndHits(cache, path);
        if (aside is not null)
            Assert.Equal(aside, File.ReadAllBytes(elsewhere));   // what the bad entry pointed at is untouched
    }

    // A directory where the entry should be is refused on sight, and a file cannot be renamed over it: no hit, and the
    // write fails with a warning (the rules in hand are still used).
    [LinuxYaraXFact]
    public void ADirectoryWhereTheEntryShouldBe_IsRefused_AndTheStoreFailsWithAWarning()
    {
        using var tree = new LinuxCacheTree("entry-dir");
        var cache = new YaraXLinuxRulesCache(tree.Dir("cache"));
        var path = EntryPath(cache);
        Directory.CreateDirectory(path, LinuxCacheTree.OwnerOnly);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Equal(2, warnings.Warnings.Count);
        Assert.Equal($"YARA-X rules cache: ignoring {path}: it is not a regular file (it is a link, or another kind of file). The rules will be recompiled.", warnings.Warnings[0]);
        Assert.StartsWith($"YARA-X rules cache: could not write {path}: ", warnings.Warnings[1], StringComparison.Ordinal);
        Assert.Empty(Directory.EnumerateFiles(cache.Location!, "*.tmp"));
    }
    #endregion

    #region Methods: whose entry, on constructed statuses (review W1: NotOwnEntry)
    // `named` is what lstat found at the path, `opened` what fstat reports on the handle the entry is read through. Pure, so
    // the rows are exact statuses rather than files: in particular the dev/ino mismatch (Replaced), which only a race makes.
    public static TheoryData<string> OwnEntryRows() => new()
    {
        "good", "setuid", "setgid", "sticky", "device", "inode", "uid", "mode 644", "mode 700", "links 2", "links 0",
        "device and mode 644", "inode and uid and links 2",
    };

    [Theory]
    [MemberData(nameof(OwnEntryRows))]
    public void NotOwnEntry_JudgesTheOpenedFileAgainstTheNamedOne(string row)
    {
        const uint user = 1000;
        var good = new LinuxFileStatus(Mode: 0x8180, Uid: user, Links: 1, Device: (8UL << 32) | 1, Inode: 42);   // S_IFREG | 0600
        (LinuxFileStatus Named, LinuxFileStatus Opened, string? Expected) data = row switch
        {
            "good" => (good, good, null),
            "setuid" => (good, good with { Mode = 0x8980 }, null),    // 04600
            "setgid" => (good, good with { Mode = 0x8580 }, null),    // 02600
            "sticky" => (good, good with { Mode = 0x8380 }, null),    // 01600
            "device" => (good, good with { Device = (8UL << 32) | 2 }, YaraXLinuxRulesCache.Replaced),
            "inode" => (good, good with { Inode = 43 }, YaraXLinuxRulesCache.Replaced),
            "uid" => (good, good with { Uid = 1001 }, "it is owned by uid 1001, not by you (uid 1000)"),
            "mode 644" => (good, good with { Mode = 0x81A4 }, "its mode is 644, not 600"),
            "mode 700" => (good, good with { Mode = 0x81C0 }, "its mode is 700, not 600"),
            "links 2" => (good, good with { Links = 2 }, "it has 2 hard links, not 1"),
            "links 0" => (good, good with { Links = 0 }, "it has 0 hard links, not 1"),
            "device and mode 644" => (good, good with { Device = (9UL << 32) | 1, Mode = 0x81A4 }, YaraXLinuxRulesCache.Replaced),
            "inode and uid and links 2" => (good, good with { Inode = 7, Uid = 0, Links = 2 }, YaraXLinuxRulesCache.Replaced),
            _ => throw new ArgumentOutOfRangeException(nameof(row)),
        };

        Assert.Equal(data.Expected, YaraXLinuxRulesCache.NotOwnEntry(data.Named, data.Opened, user));
    }

    [Fact]
    public void Replaced_IsTheReasonText() =>
        Assert.Equal("it was replaced while it was being opened", YaraXLinuxRulesCache.Replaced);
    #endregion

    #region Methods: what the entry holds
    // Format: magic 0..8, hash 8..40, body 40.. (sources 40..72, canary id 72..88, marker 88..120, rule count 120..124,
    // serialized rules 124..). Every change to the bytes is a miss with one warning, then a rewrite and a hit.
    public static TheoryData<string, string> Damage() => new()
    {
        { "magic first byte", "unknown format" },
        { "magic version digit", "unknown format" },
        { "hash byte", "its body does not match its hash (corrupt)" },
        { "sources field", "its body does not match its hash (corrupt)" },
        { "canary id", "its body does not match its hash (corrupt)" },
        { "canary marker", "its body does not match its hash (corrupt)" },
        { "rule count", "its body does not match its hash (corrupt)" },
        { "first blob byte", "its body does not match its hash (corrupt)" },
        { "middle blob byte", "its body does not match its hash (corrupt)" },
        { "last byte", "its body does not match its hash (corrupt)" },
        { "truncated blob", "its body does not match its hash (corrupt)" },
        { "appended byte", "its body does not match its hash (corrupt)" },
    };

    [LinuxYaraXTheory]
    [MemberData(nameof(Damage))]
    public void ADamagedEntry_IsAMissWithAWarning_ThenRewritten(string damage, string why)
    {
        using var tree = new LinuxCacheTree("damage");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        Warm(cache);
        var path = EntryPath(cache);
        File.WriteAllBytes(path, Damaged(File.ReadAllBytes(path), damage));   // same inode, mode and link count
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, $"{damage}: the damaged entry was loaded");

        Assert.Equal($"YARA-X rules cache: ignoring {path}: {why}. The rules will be recompiled.", Assert.Single(warnings.Warnings));
        AssertRewrittenAndHits(cache, path);
    }

    // Shorter than a header plus a body header (124 bytes), or longer than the 256 MiB bound (sparse: no disk), is refused
    // before it is read.
    [LinuxYaraXTheory]
    [InlineData(0L)]
    [InlineData(123L)]
    [InlineData(256L * 1024 * 1024 + 1)]
    public void AnEntryOutsideTheSizeBounds_IsAMissWithAWarning_ThenRewritten(long length)
    {
        using var tree = new LinuxCacheTree("size");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        Warm(cache);
        var path = EntryPath(cache);
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
            stream.SetLength(length);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Equal($"YARA-X rules cache: could not read {path}: InvalidDataException: the entry is {length} bytes, outside [124, 268435456]. The rules will be recompiled.",
            Assert.Single(warnings.Warnings));
        AssertRewrittenAndHits(cache, path);
    }

    // An intact entry for OTHER sources, under this key's name: its hash verifies, but it is not this key's.
    [LinuxYaraXFact]
    public void AnEntryForOtherSources_IsAMissWithAWarning_ThenRewritten()
    {
        using var tree = new LinuxCacheTree("other");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        (string, string)[] other = [("other.yar", "rule other { condition: true }")];
        EnsureEngine();
        YaraXEngine.Load(other, cache).Rules!.Dispose();
        Warm(cache);
        var path = EntryPath(cache);
        File.WriteAllBytes(path, File.ReadAllBytes(cache.EntryPath(YaraXRules.SourcesSha256Of(other))!));
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Equal($"YARA-X rules cache: ignoring {path}: it is for other rule sources. The rules will be recompiled.", Assert.Single(warnings.Warnings));
        AssertRewrittenAndHits(cache, path);
    }

    // The hash is not a binding (the path is): this user can forge an entry whose hash verifies. A forged marker passes
    // every check of the entry and deserializes, and the canary run by the engine after the load is what catches it.
    [LinuxYaraXFact]
    public void AnEntryWithAValidHashWhoseCanaryFails_IsRecompiled_AndRewritten()
    {
        using var tree = new LinuxCacheTree("canary");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        Warm(cache);
        var path = EntryPath(cache);
        File.WriteAllBytes(path, Rehashed(File.ReadAllBytes(path), entry => YaraXCanary.Create().Marker.CopyTo(entry.AsSpan(88, 32))));
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
        {
            Assert.False(reloaded.FromCache);
            using var scanner = reloaded.Rules.CreateScanner(5);
            Assert.Null(scanner.CheckCanary());
        }

        Assert.Contains(warnings.Warnings, w => w.StartsWith("YARA-X rules cache: the cached rules failed their canary", StringComparison.Ordinal));
        AssertRewrittenAndHits(cache, path);
    }

    // A forged rule count with a valid hash is refused when the body is deserialized.
    [LinuxYaraXFact]
    public void AnEntryWithAValidHashAndTheWrongRuleCount_IsAMissWithAWarning_ThenRewritten()
    {
        using var tree = new LinuxCacheTree("count");
        var cache = new YaraXLinuxRulesCache(tree.Path("cache"));
        Warm(cache);
        var path = EntryPath(cache);
        File.WriteAllBytes(path, Rehashed(File.ReadAllBytes(path), entry => entry[120]++));
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        var warning = Assert.Single(warnings.Warnings);
        Assert.StartsWith($"YARA-X rules cache: ignoring {path}: ", warning, StringComparison.Ordinal);
        Assert.Contains("besides the canary, expected 3", warning, StringComparison.Ordinal);
        AssertRewrittenAndHits(cache, path);
    }
    #endregion

    #region Methods: the real worker (P4 "Engine")
    // Two runs of the real CLI worker with a fresh XDG_CACHE_HOME: the first compiles and writes the entry (600, in
    // directories it created at 700), the second loads it. Both are genuinely ready, canary passed.
    [LinuxYaraXFact]
    public void TheWorker_RunTwiceWithAFreshXdgCacheHome_CompilesThenLoadsFromTheCache()
    {
        using var tree = new LinuxCacheTree("worker-xdg");
        var xdg = tree.Path("xdg");
        var env = new Dictionary<string, string?> { ["XDG_CACHE_HOME"] = xdg };

        var first = WorkerReady(env, "compiled");
        var second = WorkerReady(env, "from the rules cache");

        var dir = Path.Combine(xdg, "silvergun", "yara-x-rules");
        var entry = Assert.Single(Directory.GetFileSystemEntries(dir));
        Assert.Equal($"rules-{YaraXNative.EngineVersion}-{YaraXWorkerScanner.ExpectedRulesSha256}.sgyx", Path.GetFileName(entry));
        Assert.Equal(LinuxCacheTree.OwnerOnlyFile, File.GetUnixFileMode(entry));
        Assert.Equal(first.RuleCount, second.RuleCount);
        AssertCreatedOwnerOnly(xdg, Path.Combine(xdg, "silvergun"), dir);
    }

    // "Never wider: the umask only narrows" (P3). Under umask 002 (the user-private-group default on many distributions) the
    // directories the first worker creates must still be 700, or the second worker's walk refuses them as group-writable
    // and the cache is never used. The umask is set in the worker's own shell, never in this host.
    [LinuxYaraXFact]
    public void TheWorker_UnderUmask002_CreatesTheCacheAt700_AndTheSecondRunLoadsFromIt()
    {
        using var tree = new LinuxCacheTree("worker-umask");
        var xdg = tree.Path("xdg");

        var first = RunUnderUmask("002", xdg);
        var second = RunUnderUmask("002", xdg);

        AssertReady(first, "compiled");
        Assert.DoesNotContain("YARA-X rules cache: not using", second.Stderr, StringComparison.Ordinal);
        AssertReady(second, "from the rules cache");
        AssertCreatedOwnerOnly(xdg, Path.Combine(xdg, "silvergun"), Path.Combine(xdg, "silvergun", "yara-x-rules"));
    }

    // Without an absolute XDG_CACHE_HOME (unset, or relative: the XDG rule), the cache is $HOME/.cache/silvergun/yara-x-rules.
    [LinuxYaraXTheory]
    [InlineData(null)]
    [InlineData("relative/xdg")]
    public void TheWorker_WithoutAnAbsoluteXdgCacheHome_CachesUnderHome(string? xdg)
    {
        using var tree = new LinuxCacheTree("worker-home");
        var home = tree.Dir("home");
        var env = new Dictionary<string, string?> { ["XDG_CACHE_HOME"] = xdg, ["HOME"] = home };

        WorkerReady(env, "compiled", workingDirectory: tree.Base);
        WorkerReady(env, "from the rules cache", workingDirectory: tree.Base);

        Assert.Single(Directory.GetFiles(Path.Combine(home, ".cache", "silvergun", "yara-x-rules"), "rules-*.sgyx"));
        Assert.Equal(new[] { home }, Directory.GetFileSystemEntries(tree.Base));   // nothing relative to the working directory
    }

    // An XDG_CACHE_HOME under an other-writable, non-sticky directory: the worker is still ready (compiled) every time,
    // warns, and creates nothing there.
    [LinuxYaraXFact]
    public void TheWorker_WithAnUntrustedXdgCacheHome_StillCompiles_AndWritesNothingThere()
    {
        using var tree = new LinuxCacheTree("worker-untrusted");
        var open = tree.Dir("open", LinuxCacheTree.Mode777);
        var env = new Dictionary<string, string?> { ["XDG_CACHE_HOME"] = open + "/xdg" };

        var first = Run(env);
        var second = Run(env);

        foreach (var run in new[] { first, second })
        {
            AssertReady(run, "compiled");
            Assert.Contains($"not using {open}/xdg/silvergun/yara-x-rules: a directory on the way is writable by other users (mode 777): {open}.", run.Stderr, StringComparison.Ordinal);
        }
        Assert.Empty(Directory.EnumerateFileSystemEntries(open));
    }
    #endregion

    #region Methods: helpers
    private static (string? Why, bool Missing) Walk(string dir)
    {
        var why = YaraXLinuxRulesCache.Untrusted(dir, LinuxSecurityNative.EffectiveUid(), out var missing);
        return (why, missing);
    }

    // P3/P4: every directory the cache created is 700, never wider whatever the umask (class doc: "Missing directories are
    // created mode 700"). All of them at once, so a failure names each one's mode.
    private static void AssertCreatedOwnerOnly(params string[] created) =>
        Assert.Equal(created.Select(d => (d, "700")), created.Select(d => (d, Convert.ToString((int)File.GetUnixFileMode(d), 8))));

    private static void Warm(YaraXLinuxRulesCache cache)
    {
        using var warm = Load(cache);
        Assert.False(warm.FromCache, "the precondition failed: the first load came from the cache");
        Assert.True(File.Exists(EntryPath(cache)), "the precondition failed: the first load wrote no entry");
    }

    // The entry at `path` is again this user's own (a regular 600 file with one link) and the next load hits.
    private static void AssertRewrittenAndHits(YaraXLinuxRulesCache cache, string path)
    {
        var entry = LinuxSecurityNative.Lstat(path);
        Assert.True(entry is { IsRegularFile: true }, "the entry was not rewritten as a regular file");
        Assert.Equal((LinuxCacheTree.OwnerOnlyFile, 1u), (entry!.Value.Permissions, entry.Value.Links));
        Assert.Empty(Directory.EnumerateFiles(cache.Location!, "*.tmp"));
        using var next = Load(cache);
        Assert.True(next.FromCache, "the rewritten entry did not load from the cache");
    }

    // Every cache warning captured is `expected` (there is at least one). The count is reported, not pinned: see the report.
    private void AssertOnlyWarning(WarningCapture warnings, string expected)
    {
        var mine = warnings.Warnings.Where(w => w.StartsWith("YARA-X rules cache:", StringComparison.Ordinal)).ToArray();
        output.WriteLine($"{mine.Length} cache warning(s): {string.Join(" | ", mine)}");
        Assert.NotEmpty(mine);
        Assert.All(mine, w => Assert.Equal(expected, w));
    }

    // Makes the entry at `path` (valid, 600, one link) into `what`; returns the refusal reason.
    private static string Stage(string what, string path, string elsewhere)
    {
        switch (what)
        {
            case "symlink":
                File.Move(path, elsewhere);   // a valid entry of the user's own, at 600 with one link: only the link is wrong
                File.CreateSymbolicLink(path, elsewhere);
                return "it is not a regular file (it is a link, or another kind of file)";
            case "mode 644":
                File.SetUnixFileMode(path, (UnixFileMode)0b110_100_100);
                return "its mode is 644, not 600";
            case "mode 640":
                File.SetUnixFileMode(path, (UnixFileMode)0b110_100_000);
                return "its mode is 640, not 600";
            case "mode 400":
                File.SetUnixFileMode(path, UnixFileMode.UserRead);
                return "its mode is 400, not 600";
            case "hard link":
                HardLink(path, elsewhere);
                return "it has 2 hard links, not 1";
            case "fifo":
                File.Delete(path);
                LinuxYaraX.MakeFifo(path);
                return "it is not a regular file (it is a link, or another kind of file)";
            default:
                throw new ArgumentOutOfRangeException(nameof(what));
        }
    }

    private static byte[] Damaged(byte[] entry, string damage)
    {
        var copy = (byte[])entry.Clone();
        switch (damage)
        {
            case "magic first byte": copy[0] ^= 0x01; return copy;
            case "magic version digit": copy[7] = (byte)'2'; return copy;
            case "hash byte": copy[20] ^= 0x01; return copy;
            case "sources field": copy[40] ^= 0x01; return copy;
            case "canary id": copy[72] ^= 0x01; return copy;
            case "canary marker": copy[88] ^= 0x01; return copy;
            case "rule count": copy[120] ^= 0x01; return copy;
            case "first blob byte": copy[124] ^= 0x01; return copy;
            case "middle blob byte": copy[124 + (copy.Length - 124) / 2] ^= 0x01; return copy;
            case "last byte": copy[^1] ^= 0x01; return copy;
            case "truncated blob": return copy[..^10];
            case "appended byte": return [.. copy, 0];
            default: throw new ArgumentOutOfRangeException(nameof(damage));
        }
    }

    // `entry` changed by `edit`, then re-hashed exactly as Store hashes (anyone who is this user can do the same).
    private static byte[] Rehashed(byte[] entry, Action<byte[]> edit)
    {
        var copy = (byte[])entry.Clone();
        edit(copy);
        SHA256.HashData(copy.AsSpan(40), copy.AsSpan(8, 32));
        return copy;
    }

    private static LinuxWorkerRun Run(IReadOnlyDictionary<string, string?> env, string? workingDirectory = null) =>
        LinuxYaraX.Run(LinuxYaraX.WorkerArgs, [], workingDirectory, env);

    // The real worker with no requests, exec'd from a shell that first sets `umask`, with its own XDG_CACHE_HOME.
    private static LinuxWorkerRun RunUnderUmask(string umask, string xdg)
    {
        var psi = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            ArgumentList = { "-c", "umask \"$0\" && exec \"$1\" __worker yara --protocol 1", umask, LinuxYaraX.CliPath },
        };
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment["XDG_CACHE_HOME"] = xdg;
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        psi.Environment.Remove("SILVERGUN_YARA_ENGINE");
        psi.Environment.Remove(YaraCliScanner.YaraPathVar);

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = new MemoryStream();
        var readOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var readErr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the worker did not exit within 120 s and was killed");
        }
        process.WaitForExit();
        readOut.GetAwaiter().GetResult();
        return new LinuxWorkerRun(process.ExitCode, stdout.ToArray(), readErr.GetAwaiter().GetResult(), process.Id);
    }

    private static WorkerReadyLine WorkerReady(IReadOnlyDictionary<string, string?> env, string how, string? workingDirectory = null) =>
        AssertReady(Run(env, workingDirectory), how);

    // The ready line is genuine (the embedded rules' hash, canary passed, no source errors), and stderr says how the rules
    // were loaded: " rules (compiled)" or " rules (from the rules cache)".
    private static WorkerReadyLine AssertReady(LinuxWorkerRun run, string how)
    {
        Assert.True(run.Exit == 0, $"the worker exited {run.Exit}\n{run.Stderr}");
        var lines = LinuxYaraX.Lines(run);
        using var ready = JsonDocument.Parse(lines[0]);
        var root = ready.RootElement;
        Assert.Equal("ready", root.GetProperty("type").GetString());
        Assert.Equal(WorkerProtocol.CanaryPassed, root.GetProperty("canary").GetString());
        Assert.Equal(0, root.GetProperty("ruleSourceErrors").GetInt32());
        Assert.Equal(YaraXWorkerScanner.ExpectedRulesSha256, root.GetProperty("rulesSha256").GetString());
        Assert.Contains($" rules ({how})", run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(how == "compiled" ? "from the rules cache" : " rules (compiled)", run.Stderr, StringComparison.Ordinal);
        return new(root.GetProperty("ruleCount").GetInt32());
    }
    #endregion

    #region Nested types
    private sealed record WorkerReadyLine(int RuleCount);
    #endregion
}
#endif
