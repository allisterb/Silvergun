#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;

using Entry = YaraXRulesCacheEntryV3;

/// <summary>
/// The compiled-rules cache (ADR 0033 decision 6; task T2) and <see cref="YaraXEngine.Load(IReadOnlyList{ValueTuple{string, string}}, YaraXRulesCache?)"/>,
/// its one caller. Every test uses its own temp cache directory through the constructor; the real
/// <c>%LOCALAPPDATA%\Silvergun\yara-x-rules</c> is never touched.
///
/// <para>DPAPI must vouch for the entry's exact body before every load (format v3; it also catches corruption, which
/// matters because 48 of 60 single-byte corruptions deserialize silently: C API spike). Each kind of damage below must be
/// detected, recompiled over, and the entry rewritten so the next load comes from the cache again. An entry DPAPI vouches
/// for but whose canary fails (a blob and a canary that do not belong together, bound by this very user) is recompiled
/// too. The directory is owner-only (one ACE, protected), an open one is corrected, and a link is refused. The DPAPI
/// binding itself is pinned in <see cref="YaraXRulesCacheDpapiTests"/>.</para>
///
/// <para>Entry layout (format v3, <see cref="YaraXRulesCacheEntryV3"/>): magic 0..8, P (the DPAPI blob's length) 8..12,
/// the DPAPI blob 12..12+P (P = 262 measured), then the body: sources sha256 +0..32, canary id +32..48, canary marker
/// +48..80, rule count +80..84, the serialized rules +84..end. The blob protects the body's sha256.</para>
/// </summary>
public sealed class YaraXRulesCacheTests(Xunit.Abstractions.ITestOutputHelper output)
{
    #region Methods: hit and miss
    [Fact]
    public void Load_CompilesAndStores_ThenTheNextLoadComesFromTheCache()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));

        using (var first = Load(cache))
        {
            Assert.False(first.FromCache);
            Assert.True(File.Exists(EntryPath(cache)));
        }

        using var second = Load(cache);
        Assert.True(second.FromCache);
        Assert.Equal(2, second.Rules.RuleCount);
        Assert.Empty(Directory.EnumerateFiles(cache.Location!, "*.tmp"));
    }

    // The cached rules scan for real (the canary passed on load, and a rule from the sources still hits).
    [Fact]
    public void CachedRules_ScanLikeCompiledOnes()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();

        using var cached = Load(cache);
        using var scanner = cached.Rules.CreateScanner(5);

        Assert.True(cached.FromCache);
        Assert.Null(scanner.CheckCanary());
        Assert.Equal(new[] { "cache_probe" }, YaraX.Hits(scanner.Scan(Marker)));
    }

    [Fact]
    public void EntryPath_IsKeyedByEngineVersionAndSourcesSha256()
    {
        var cache = new YaraXRulesCache(@"C:\cache-dir");
        var key = YaraXRules.SourcesSha256Of(Sources);

        Assert.Equal($@"C:\cache-dir\rules-1.22.0-{key}.sgyx", cache.EntryPath(key));
        Assert.Matches("^[0-9a-f]{64}$", key);
        Assert.NotEqual(key, YaraXRules.SourcesSha256Of([.. Sources, ("extra.yar", "rule extra { condition: true }")]));
        // Framed by length: moving text from a source's name into its text changes the key.
        Assert.NotEqual(YaraXRules.SourcesSha256Of([("ab", "c")]), YaraXRules.SourcesSha256Of([("a", "bc")]));
    }

    // The production default location; read, never created, by this test.
    [Fact]
    public void DefaultDirectory_IsUnderLocalAppData()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);

        Assert.Equal(Path.Combine(local, "Silvergun", "yara-x-rules"), YaraXRulesCache.DefaultDirectory());
    }

    [Fact]
    public void ARelativeCacheLocation_IsNotUsed_AndTheRulesStillCompile()
    {
        var relative = $"silvergun-yara-x-relative-{Guid.NewGuid():N}";
        var cache = new YaraXRulesCache(relative);

        using var loaded = Load(cache);

        Assert.False(loaded.FromCache);
        Assert.False(Directory.Exists(relative));
        Assert.False(Directory.Exists(Path.Combine(Environment.CurrentDirectory, relative)));
    }
    #endregion

    #region Methods: damage is detected, recompiled over, and rewritten
    // Format v3: "magic" flips a byte other than [7] (flipping [7]'s low bit turns SGYXRC03 into SGYXRC02, which is by
    // design a SILENT miss: YaraXRulesCacheDpapiTests). "P field" and "DPAPI blob byte" replace v2's "stored sha256"; the
    // blob byte is outside entry offsets 16..31 (blob 4..19), the provider GUID DPAPI does not authenticate (measured; also
    // pinned there). The body rows name the body's fields; "blob" there is the serialized rules, as in v2.
    public static TheoryData<string> Damage() => new()
    {
        "magic", "P field", "DPAPI blob byte", "sources field", "canary id", "canary marker", "rule count", "first blob byte",
        "middle blob byte", "last blob byte", "truncated blob", "truncated header", "empty", "appended byte",
    };

    [Theory]
    [MemberData(nameof(Damage))]
    public void ADamagedEntry_IsDetected_Recompiled_AndRewritten(string damage)
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        var entry = File.ReadAllBytes(path);
        File.WriteAllBytes(path, Damaged(entry, damage));
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, $"{damage}: the damaged entry was loaded");

        Assert.Contains(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal) && w.Contains("recompiled", StringComparison.Ordinal));
        AssertRewrittenAndLoadable(cache, path);
    }

    // An entry larger than any real one (the 1,240-rule blob is ~2.3 MB; the bound is 256 MiB) is refused before it is
    // read into memory. Sparse, so the test costs no disk.
    [Fact]
    public void AnOversizedEntry_IsRefusedUnread_AndRecompiled()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            WindowsFileSystem.SetSparse(stream.SafeFileHandle);
            stream.SetLength(256L * 1024 * 1024 + 1);
        }
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Contains(warnings.Warnings, w => w.Contains("outside [97, 268435456]", StringComparison.Ordinal));
        AssertRewrittenAndLoadable(cache, path);
    }

    // An intact entry for OTHER sources, placed under this key's name: its sha256 verifies, but it is not this key's.
    [Fact]
    public void AnEntryForOtherSources_IsRefused_AndRecompiled()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        (string, string)[] other = [("other.yar", "rule other { condition: true }")];
        YaraXEngine.Load(other, cache).Rules!.Dispose();
        Load(cache).Dispose();
        var otherPath = cache.EntryPath(YaraXRules.SourcesSha256Of(other))!;
        var path = EntryPath(cache);
        File.Copy(otherPath, path, overwrite: true);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Contains(warnings.Warnings, w => w.Contains("it is for other rule sources", StringComparison.Ordinal));
        AssertRewrittenAndLoadable(cache, path);
    }

    // DPAPI vouches for what this user bound, not for its meaning: the checks after it must still run. An entry whose blob
    // and canary do not belong together (here: another canary's marker, the body then bound with DPAPI exactly as Store
    // binds one, which this test can do because it runs as the user) is vouched for and deserializes, and only the canary
    // check after loading catches it. It must then be recompiled, never used.
    [Fact]
    public void AVerifiedEntryWhoseCanaryFails_IsRecompiled_AndRewritten()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        var entry = Entry.Rebound(File.ReadAllBytes(path), body => YaraXCanary.Create().Marker.CopyTo(body.AsSpan(Entry.MarkerOffset, 32)));
        Entry.AssertVouched(entry, YaraXRules.SourcesSha256Of(Sources));   // the precondition: DPAPI vouches for it
        File.WriteAllBytes(path, entry);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
        {
            Assert.False(reloaded.FromCache);
            using var scanner = reloaded.Rules.CreateScanner(5);
            Assert.Null(scanner.CheckCanary());
        }

        Assert.Contains(warnings.Warnings, w => w.Contains("failed their canary", StringComparison.Ordinal));
        AssertRewrittenAndLoadable(cache, path);
    }

    // An entry DPAPI vouches for (bound by this user, as above) that claims a different rule count is refused at
    // deserialization.
    [Fact]
    public void AVerifiedEntryWithTheWrongRuleCount_IsRecompiled()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        var entry = Entry.Rebound(File.ReadAllBytes(path), body => body[Entry.RuleCountOffset]++);
        Entry.AssertVouched(entry, YaraXRules.SourcesSha256Of(Sources));   // the precondition: DPAPI vouches for it
        File.WriteAllBytes(path, entry);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Contains(warnings.Warnings, w => w.Contains("besides the canary, expected 3", StringComparison.Ordinal));
        AssertRewrittenAndLoadable(cache, path);
    }
    #endregion

    #region Methods: the directory is owner-only
    [Fact]
    public void ANewCacheDirectory_IsOwnerOnly_ProtectedWithExactlyOneAce()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));

        Load(cache).Dispose();

        AssertOwnerOnly(cache.Location!);
        AssertOnlyTheUserHasAccess(new FileInfo(EntryPath(cache)).GetAccessControl());
    }

    // A missing parent (...\Silvergun, as on a fresh profile) is created along with the owner-only directory. (Moved here
    // from the configured-mode tests, where it was the control for "a configured directory is never created".)
    [Fact]
    public void ADefaultStyleLocation_StillCreatesItsParent()
    {
        using var dir = new YaraXTempDir("cfg-default-style");
        var parent = dir.Combine("Silvergun");
        var cache = new YaraXRulesCache(Path.Combine(parent, "yara-x-rules"));
        using var rules = YaraX.Compile("rule cfg_default_style { condition: false }");

        Assert.True(cache.Store(rules));

        Assert.True(Directory.Exists(parent));
        AssertOwnerOnly(cache.Location!);
    }

    // A directory that already exists with the inherited (temp-directory) ACL is corrected, with a warning.
    [Fact]
    public void AnExistingDirectoryWithAnOpenAcl_IsMadeOwnerOnly()
    {
        using var dir = new YaraXTempDir("cache");
        var location = dir.Combine("rules");
        Directory.CreateDirectory(location);
        var before = new DirectoryInfo(location).GetAccessControl();
        Assert.False(before.AreAccessRulesProtected && before.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count == 1,
            "the precondition failed: a fresh temp subdirectory already looked owner-only");
        using var warnings = new WarningCapture();

        using var loaded = Load(new YaraXRulesCache(location));

        Assert.Contains(warnings.Warnings, w => w.Contains("was not owner-only; restricting it", StringComparison.Ordinal));
        AssertOwnerOnly(location);
        Assert.True(File.Exists(EntryPath(new YaraXRulesCache(location))));
    }

    // A cache directory that is a junction is refused: nothing is written through it, the rules still compile, and every
    // load compiles. The junction's TARGET must not be altered either.
    [Fact]
    public void AJunctionCacheDirectory_IsRefused_AndTheRulesStillCompile()
    {
        using var dir = new YaraXTempDir("cache");
        var target = dir.Combine("elsewhere");
        Directory.CreateDirectory(target);
        var link = dir.Combine("rules");
        WindowsFileSystem.CreateJunction(link, target);
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, "the junction was not created");
        var targetAclBefore = new DirectoryInfo(target).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);
        var cache = new YaraXRulesCache(link);
        using var warnings = new WarningCapture();

        using (var first = Load(cache))
            Assert.False(first.FromCache);
        using (var second = Load(cache))
            Assert.False(second.FromCache);

        Assert.Empty(Directory.EnumerateFileSystemEntries(target));
        Assert.Contains(warnings.Warnings, w => w.Contains("it is a link", StringComparison.Ordinal));
        var targetAclAfter = new DirectoryInfo(target).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);
        Assert.True(targetAclBefore == targetAclAfter,
            $"refusing the junction still rewrote its TARGET's ACL.{Environment.NewLine}before: {targetAclBefore}{Environment.NewLine}after:  {targetAclAfter}");
    }
    // N1: the PARENT (...\Silvergun) is checked for being a link before anything reads or changes the directory's ACL. Here
    // the parent is a junction to a directory whose `yara-x-rules` is open and holds an entry: following the link would
    // correct that ACL and delete that entry. Neither happens, nothing is written there, and the rules still compile.
    [Fact]
    public void AJunctionAsTheParentDirectory_IsRefused_AndTheTargetsAclAndEntriesAreUntouched()
    {
        using var dir = new YaraXTempDir("cache");
        var target = dir.Combine("elsewhere");
        var targetRules = Path.Combine(target, "yara-x-rules");
        Directory.CreateDirectory(targetRules);
        var planted = Path.Combine(targetRules, $"rules-1.22.0-{new string('0', 64)}.sgyx");
        File.WriteAllBytes(planted, [1, 2, 3]);
        var parent = dir.Combine("Silvergun");
        WindowsFileSystem.CreateJunction(parent, target);
        var aclBefore = (Sddl(target), Sddl(targetRules));
        var cache = new YaraXRulesCache(Path.Combine(parent, "yara-x-rules"));
        using var warnings = new WarningCapture();

        using (var first = Load(cache))
            Assert.False(first.FromCache);
        using (var second = Load(cache))
            Assert.False(second.FromCache);

        Assert.Equal(aclBefore, (Sddl(target), Sddl(targetRules)));
        Assert.Equal(new[] { planted }, Directory.GetFiles(targetRules));
        Assert.Contains(warnings.Warnings, w => w.Contains($"not using {parent}: it is a link", StringComparison.Ordinal));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("not owner-only", StringComparison.Ordinal));
    }

    // N2: while the directory was open, anyone could have written an entry whose hash verifies. Every cache entry and temp
    // file in it is deleted when it is corrected (a VALID entry for this very key included: it is never trusted), and
    // nothing else is touched.
    [Fact]
    public void AnOpenDirectory_IsCorrected_AndEveryEntryInItIsDeletedUnused()
    {
        using var dir = new YaraXTempDir("cache");
        var location = dir.Combine("rules");
        Directory.CreateDirectory(location);
        var valid = ValidEntryFrom(dir.Combine("donor"));
        var key = Path.GetFileName(valid);
        File.Copy(valid, Path.Combine(location, key));
        File.WriteAllBytes(Path.Combine(location, $"rules-1.22.0-{new string('f', 64)}.sgyx"), [1]);
        File.WriteAllBytes(Path.Combine(location, "orphan.tmp"), [2]);
        File.WriteAllBytes(Path.Combine(location, "unrelated.dat"), [3]);
        var cache = new YaraXRulesCache(location);
        using var warnings = new WarningCapture();

        using (var loaded = Load(cache))
            Assert.False(loaded.FromCache, "an entry found in a directory that was open was trusted");

        Assert.Contains(warnings.Warnings, w => w.Contains("was not owner-only; restricting it to the current user and deleting its entries", StringComparison.Ordinal));
        AssertOwnerOnly(location);
        Assert.Equal(new[] { key, "unrelated.dat" }, Directory.GetFiles(location).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        using var next = Load(cache);   // the entry there now is the one this run wrote, in a trusted directory
        Assert.True(next.FromCache);
    }

    // W-B: correction is two-step. If an entry cannot be deleted (a reader holds it), the directory is left QUARANTINED
    // (protected, one ACE for the user, not inherited by files: not the trusted shape) and the cache is not used, then or
    // on the next run while it is still held. Once released, the next run corrects and deletes, and trusts it after.
    [Fact]
    public void AnEntryThatCannotBeDeleted_LeavesTheDirectoryQuarantinedAndUntrusted_UntilALaterRunDeletesIt()
    {
        using var dir = new YaraXTempDir("cache");
        var location = dir.Combine("rules");
        Directory.CreateDirectory(location);
        var donor = ValidEntryFrom(dir.Combine("donor"));
        var held = Path.Combine(location, Path.GetFileName(donor));
        File.Copy(donor, held);
        var cache = new YaraXRulesCache(location);
        using var warnings = new WarningCapture();

        using (new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.Read))   // no delete sharing: deletion fails
        {
            using (var first = Load(cache))
                Assert.False(first.FromCache, "the held entry in an uncorrected directory was trusted");
            AssertQuarantined(location);
            Assert.True(File.Exists(held));
            Assert.Contains(warnings.Warnings, w => w.Contains("could not be deleted; it stays quarantined until a later run deletes them", StringComparison.Ordinal));

            using (var second = Load(cache))
                Assert.False(second.FromCache, "a quarantined directory was trusted on the next run");
            AssertQuarantined(location);
        }

        using (var third = Load(cache))
            Assert.False(third.FromCache);   // corrected and deleted now; this run compiled and stored
        AssertOwnerOnly(location);
        using var fourth = Load(cache);
        Assert.True(fourth.FromCache);
    }

    // A quarantine ACL found at start (a run died between quarantine and trust) is not trusted: corrected, entries deleted.
    [Fact]
    public void AManuallyAppliedQuarantineAcl_IsCorrectedAgain_AndItsEntriesDeleted()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        SetAcl(cache.Location!, (security, user) => security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow)));
        AssertQuarantined(cache.Location!);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, "the entry in a quarantined directory was trusted");

        Assert.Contains(warnings.Warnings, w => w.Contains("was not owner-only", StringComparison.Ordinal));
        AssertOwnerOnly(cache.Location!);
        using var next = Load(cache);
        Assert.True(next.FromCache);
    }

    // N4: anything but EXACTLY the owner-only shape is corrected (and its entries deleted).
    public static TheoryData<string> NotOwnerOnlyShapes() =>
        new("two ACEs for the user", "a non-inheriting ACE", "less than full control", "a second SID", "inheritance enabled");

    [Theory]
    [MemberData(nameof(NotOwnerOnlyShapes))]
    public void ADirectoryThatIsNotExactlyOwnerOnly_IsCorrected(string shape)
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        SetAcl(cache.Location!, (security, user) =>
        {
            switch (shape)
            {
                case "two ACEs for the user":
                    security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.Read, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                    break;
                case "a non-inheriting ACE":
                    security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                    break;
                case "less than full control":   // everything but deleting children: still able to re-own and re-ACL it
                    security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl & ~FileSystemRights.DeleteSubdirectoriesAndFiles,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    break;
                case "a second SID":
                    security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    security.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Read, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                    break;
                case "inheritance enabled":
                    security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                    security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    break;
            }
        });
        try
        {
            using var warnings = new WarningCapture();

            using (var reloaded = Load(cache))
                Assert.False(reloaded.FromCache, $"{shape}: an entry in a directory that was not owner-only was trusted");

            Assert.Contains(warnings.Warnings, w => w.Contains("was not owner-only", StringComparison.Ordinal));
            AssertOwnerOnly(cache.Location!);
        }
        finally
        {
            // Whatever happened, leave it deletable (the DACL alone, which the owner may always write).
            SetAcl(cache.Location!, (security, user) => security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)), daclOnly: true);
        }
    }

    // FR2.2 (2026-10-22). A directory whose one user ACE does not grant WRITE_OWNER on the directory itself (Modify; or an
    // inherit-only ACE, which grants nothing on it) is still the user's own, so it is corrected with the DACL alone, which
    // the owner's implicit WRITE_DAC allows. Before FR2 the corrected descriptors always carried the owner too, and writing
    // the owner needs WRITE_OWNER even when it does not change, so this shape could not be corrected and failed closed.
    // Now: corrected, every entry in it deleted unused (the one for this key included), a FRESH entry written (a fresh
    // compile carries a fresh canary, so its bytes differ), and the next run trusts and loads that entry.
    [Theory]
    [InlineData("modify")]
    [InlineData("an inherit-only ACE")]
    public void ADirectoryTheUserCannotReOwn_IsCorrectedWithoutWriteOwner_AndItsFreshEntryIsTrustedNextRun(string shape)
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var entryBefore = File.ReadAllBytes(EntryPath(cache));
        var otherKey = Path.Combine(cache.Location!, $"rules-1.22.0-{new string('e', 64)}.sgyx");
        File.WriteAllBytes(otherKey, [1]);
        SetAcl(cache.Location!, (security, user) => security.AddAccessRule(shape == "modify"
            ? new FileSystemAccessRule(user, FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)
            : new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow)));
        try
        {
            AssertTheOwnerCannotBeWritten(cache.Location!);   // the precondition: this process has no WRITE_OWNER here
            using var warnings = new WarningCapture();

            using (var first = Load(cache))
                Assert.False(first.FromCache, "an entry in a directory that was not owner-only was trusted");

            Assert.Contains(warnings.Warnings, w => w.Contains("was not owner-only; restricting it to the current user and deleting its entries", StringComparison.Ordinal));
            Assert.DoesNotContain(warnings.Warnings, w => w.Contains("could not", StringComparison.Ordinal));   // not read, write, be made owner-only, be deleted
            AssertOwnerOnly(cache.Location!);
            Assert.False(File.Exists(otherKey), "an entry from the uncorrected directory survived the correction");
            var fresh = File.ReadAllBytes(EntryPath(cache));
            Assert.False(fresh.AsSpan().SequenceEqual(entryBefore), "the entry from the uncorrected directory was kept, not deleted and rewritten");

            using (var second = Load(cache))
                Assert.True(second.FromCache, "the corrected directory's fresh entry was not trusted on the next run");
            Assert.Equal(fresh, File.ReadAllBytes(EntryPath(cache)));   // loaded, not rewritten
        }
        finally
        {
            // Whatever happened, leave it deletable: the owner's implicit WRITE_DAC is enough (the DACL alone; see SetAcl).
            SetAcl(cache.Location!, (security, user) => security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)), daclOnly: true);
        }
    }

    // FR2.2 changed only CORRECTION: a directory the cache CREATES is still created with the user written as its owner.
    // On this (non-elevated) token the default owner of a new object is the user anyway, so the end-to-end check below
    // (ANewCacheDirectory_IsOwnerOnly_ProtectedWithExactlyOneAce) cannot tell an explicit owner from a defaulted one; an
    // elevated token would default to BUILTIN\Administrators, where it can. This pins the creation descriptor itself:
    // OwnerOnly, called the way creation calls it (its default arguments), carries the user as owner and the one ACE.
    [Fact]
    public void TheCreationDescriptor_StillSetsTheOwner()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var method = typeof(YaraXRulesCache).GetMethod("OwnerOnly", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.True(method is not null, "YaraXRulesCache.OwnerOnly is gone; this test reads the creation descriptor.");
        var setOwner = Assert.Single(method!.GetParameters(), p => p.ParameterType == typeof(bool));
        Assert.True(setOwner.HasDefaultValue && Equals(setOwner.DefaultValue, true), "OwnerOnly's owner flag no longer defaults to setting the owner");

        var security = (DirectorySecurity)method.Invoke(null, [identity.User!, setOwner.DefaultValue])!;

        // The raw descriptor it would write (review N-3), not GetAccessRules' view of it.
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        Assert.Equal(identity.User, descriptor.Owner);
        Assert.True((descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, "the creation DACL is not protected");
        Assert.NotNull(descriptor.DiscretionaryAcl);
        var ace = Assert.IsType<CommonAce>(Assert.Single(descriptor.DiscretionaryAcl!));
        Assert.False(ace.IsCallback);
        Assert.Equal(AceQualifier.AccessAllowed, ace.AceQualifier);
        Assert.Equal(identity.User, ace.SecurityIdentifier);
        Assert.Equal((int)FileSystemRights.FullControl, ace.AccessMask & (int)FileSystemRights.FullControl);
        Assert.Equal(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, ace.InheritanceFlags);
        Assert.Equal(PropagationFlags.None, ace.PropagationFlags);
    }

    // N3: a temp file orphaned by a writer that died is swept at the next write once it is older than 10 minutes (40x the
    // 15 s startup bound inside which every live writer finishes); a younger one may be a live writer's and is kept, and
    // nothing that is not a temp file is touched.
    [Fact]
    public void AStaleTempFile_IsSweptAtTheNextWrite_AndAFreshOneIsKept()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var stale = Path.Combine(cache.Location!, "stale.sgyx.0123.tmp");
        var fresh = Path.Combine(cache.Location!, "fresh.sgyx.4567.tmp");
        var other = Path.Combine(cache.Location!, "old-but-not-a-temp.dat");
        foreach (var (path, age) in new[] { (stale, 11), (fresh, 9), (other, 60) })
        {
            File.WriteAllBytes(path, [1]);
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(-age));
        }
        File.Delete(EntryPath(cache));   // a miss, so this load compiles and WRITES

        using (var loaded = Load(cache))
            Assert.False(loaded.FromCache);

        Assert.False(File.Exists(stale), "the stale temp file was not swept");
        Assert.True(File.Exists(fresh), "a temp file a live writer could still own was swept");
        Assert.True(File.Exists(other), "the sweep touched a file that is not a temp file");
        Assert.True(File.Exists(EntryPath(cache)));
    }

    // W-B: a held cache lock (another worker) bounds the wait at ~2 s: the load is a miss (the rules compile), and the
    // store is skipped, never written outside the lock.
    [Fact]
    [Trait("Category", "Slow")]
    public void ACacheLockHeldElsewhere_MakesTheLoadAMissWithinAbout2s_AndTheStoreIsSkipped()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var key = YaraXRules.SourcesSha256Of(Sources);
        using var rules = YaraXRules.Compile(Sources, out _)!;
        File.Delete(EntryPath(cache));
        using var held = new Mutex(initiallyOwned: true, MutexName(cache.Location!));
        using var warnings = new WarningCapture();

        // Another thread, because a mutex is re-entrant for its owner. The stopwatch runs INSIDE that thread, around
        // TryLoad alone: it used to wrap a blocking Task.Run(...).GetAwaiter().GetResult(), so under full-suite load it also
        // measured thread-pool queueing (10.44 s against the 8 s ceiling, I2b). A dedicated thread is not pool-queued at
        // all, and it is not a blocking wait on a Task (xUnit1031); the test cannot simply await instead, because the
        // continuation could resume on another thread and ReleaseMutex must run on the one that owns the mutex.
        var loadTime = TimeSpan.Zero;
        var loaded = OffTheOwnerThread(() =>
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var result = cache.TryLoad(key);
            loadTime = clock.Elapsed;
            return result;
        });
        var stored = OffTheOwnerThread(() => cache.Store(rules));
        held.ReleaseMutex();
        output.WriteLine($"TryLoad under a held cache lock took {loadTime.TotalMilliseconds:F0} ms (bound 1500..8000 ms).");

        Assert.Null(loaded);
        Assert.InRange(loadTime, TimeSpan.FromSeconds(1.5), TimeSpan.FromSeconds(8));
        Assert.False(stored);
        Assert.False(File.Exists(EntryPath(cache)), "the store wrote without the lock");
        Assert.Empty(Directory.EnumerateFiles(cache.Location!, "*.tmp"));
        Assert.Equal(2, warnings.Warnings.Count(w => w.Contains("another process held the cache lock", StringComparison.Ordinal)));
    }

    // A holder that died holding the lock (a worker killed mid-load) leaves it abandoned; the next run takes it over at
    // once instead of waiting out the timeout, and the cache works.
    [Fact]
    public void AnAbandonedCacheLock_IsTakenOver()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var name = MutexName(cache.Location!);
        Mutex? abandoned = null;
        var holder = new Thread(() => abandoned = new Mutex(initiallyOwned: true, name));   // the thread ends owning it
        holder.Start();
        holder.Join();
        using var warnings = new WarningCapture();

        var clock = System.Diagnostics.Stopwatch.StartNew();
        using var loaded = cache.TryLoad(YaraXRules.SourcesSha256Of(Sources));
        clock.Stop();
        abandoned?.Dispose();

        Assert.NotNull(loaded);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1.5), $"the load waited {clock.Elapsed} for an abandoned lock");
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("held the cache lock", StringComparison.Ordinal));
    }

    // Amendment G1: a cache hit must vouch for every source, so a ruleset with compile errors is never stored, and the
    // engine's next load compiles again.
    [Fact]
    public void Store_RefusesARulesetWithSourceErrors()
    {
        YaraX.EnsureEngine();
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        (string, string)[] partial = [("bad.yar", "rule bad { condition: nope }"), ("ok.yar", "rule ok { condition: true }")];
        using var rules = YaraXRules.Compile(partial, out var failure);
        Assert.True(rules is not null, failure);
        Assert.Equal(1, rules!.SourceErrors);
        using var warnings = new WarningCapture();

        Assert.False(cache.Store(rules));

        Assert.Contains(warnings.Warnings, w => w.Contains("not caching these rules: 1 rule source(s) had compile errors", StringComparison.Ordinal));
        Assert.False(File.Exists(cache.EntryPath(rules.SourcesSha256)));
        var viaEngine = YaraXEngine.Load(partial, cache);
        using (viaEngine.Rules)
            Assert.False(viaEngine.FromCache);
        var again = YaraXEngine.Load(partial, cache);
        using (again.Rules)
            Assert.False(again.FromCache, "a ruleset with source errors came back from the cache");
    }

    // The magic was bumped to SGYXRC02 when entries started to mean "compiled with no source errors", then to SGYXRC03 when
    // they were bound with DPAPI: an SGYXRC01 entry (intact otherwise) is an unknown format, recompiled over and rewritten
    // in the current format. (SGYXRC02, the previous format, is a silent miss instead: YaraXRulesCacheDpapiTests.)
    [Fact]
    public void AnEntryWithTheOldMagic_IsIgnored_Recompiled_AndRewritten()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        var entry = File.ReadAllBytes(path);
        System.Text.Encoding.ASCII.GetBytes("SGYXRC01").CopyTo(entry, 0);
        File.WriteAllBytes(path, entry);
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache);

        Assert.Contains(warnings.Warnings, w => w.Contains("unknown format", StringComparison.Ordinal));
        Assert.Equal("SGYXRC03", System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(path), 0, 8));
        AssertRewrittenAndLoadable(cache, path);
    }
    #endregion

    #region Methods: whose entry (S1)
    // S1: an entry is read only when it is not a link, checked without following it. Here the entry, in an owner-only
    // directory, is a reparse point (a third-party tag: staged without privilege, unlike a file symlink). It is never read:
    // ONE warning names it, it is deleted, the rules are recompiled and a real entry is written in its place, which the next
    // load trusts.
    [Fact]
    public void AnEntryThatIsAReparsePoint_IsNotLoaded_WarnedOnce_Deleted_AndRecompiled()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        File.Delete(path);
        File.WriteAllBytes(path, []);
        WindowsFileSystem.SetOpaqueReparsePoint(path);
        Assert.True((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0, "the precondition failed: the entry is not a reparse point");
        Assert.True(File.Exists(path), "the precondition failed: the reparse-point entry does not read as an existing file");
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, "an entry that is a reparse point was loaded");

        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        Assert.Contains($"ignoring {path}: it is a link; it was deleted. The rules will be recompiled.", warning, StringComparison.Ordinal);
        Assert.Equal((FileAttributes)0, File.GetAttributes(path) & FileAttributes.ReparsePoint);   // replaced by a real entry
        AssertRewrittenAndLoadable(cache, path);
    }

    // The other half of S1: every entry this process writes is owned by the user, so the owner check never distrusts our
    // own writes. On this (non-elevated) token the default owner is the user anyway; under an elevated token, whose default
    // owner can be BUILTIN\Administrators, this is what OwnByUser exists for (run elevated to make it discriminating).
    [Fact]
    public void EntriesThisProcessWrites_AreOwnedByTheUser_AndLoadFromTheCache()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        using var identity = WindowsIdentity.GetCurrent();

        Load(cache).Dispose();

        Assert.Equal(identity.User, new FileInfo(EntryPath(cache)).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)));
        using var next = Load(cache);
        Assert.True(next.FromCache, "an entry this process wrote was not trusted");
    }

    // S1's real case: an entry in the owner-only directory whose OWNER is not the user (e.g. created through a handle that
    // survived the directory's correction). It is never read: one warning, deleted, recompiled, and the entry written in its
    // place is the user's. Its DACL is still exactly ours (one full-control ACE for the user), so only the owner check can
    // refuse it. Needs a token that can name another owner (see ElevatedWindowsFactAttribute): a skip otherwise.
    [ElevatedWindowsFact]
    public void AnEntryOwnedBySomeoneElse_IsNotLoaded_WarnedOnce_Deleted_AndRecompiled()
    {
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        Load(cache).Dispose();
        var path = EntryPath(cache);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var other = new FileSecurity();
        other.SetOwner(administrators);
        new FileInfo(path).SetAccessControl(other);
        Assert.Equal(administrators, new FileInfo(path).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)));
        using var warnings = new WarningCapture();

        using (var reloaded = Load(cache))
            Assert.False(reloaded.FromCache, "an entry owned by someone else was loaded");

        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        Assert.Contains($"ignoring {path}: its owner is not the current user; it was deleted. The rules will be recompiled.", warning, StringComparison.Ordinal);
        using var identity = WindowsIdentity.GetCurrent();
        Assert.Equal(identity.User, new FileInfo(path).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)));
        AssertRewrittenAndLoadable(cache, path);
    }
    #endregion

    #region Methods: concurrency
    // Writers race to store DIFFERENT rules (each compile has its own canary) under the same key while readers load it.
    // Every entry a reader sees must be whole: it verifies and its canary passes, never "corrupt". A writer may lose a
    // race (the move is refused while a reader holds the file); that is a warning, not a torn entry.
    [Fact]
    public async Task ConcurrentWritersAndReaders_NeverSeeATornEntry()
    {
        YaraX.EnsureEngine();
        using var dir = new YaraXTempDir("cache");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        var key = YaraXRules.SourcesSha256Of(Sources);
        var rulesets = Enumerable.Range(0, 4).Select(i => YaraXRules.Compile(Sources, out _)!).ToArray();
        using var warnings = new WarningCapture();
        using var start = new ManualResetEventSlim();
        var loadedFromCache = 0;
        var canaryFailures = 0;

        var writers = rulesets.Select(rules => Task.Factory.StartNew(() =>
        {
            start.Wait();
            for (var i = 0; i < 15; i++)
                cache.Store(rules);
        }, TaskCreationOptions.LongRunning));
        var readers = Enumerable.Range(0, 4).Select(_ => Task.Factory.StartNew(() =>
        {
            start.Wait();
            for (var i = 0; i < 15; i++)
            {
                using var loaded = cache.TryLoad(key);
                if (loaded is null)
                    continue;
                Interlocked.Increment(ref loadedFromCache);
                using var scanner = loaded.CreateScanner(5);
                if (scanner.CheckCanary() is not null)
                    Interlocked.Increment(ref canaryFailures);
            }
        }, TaskCreationOptions.LongRunning));
        var all = writers.Concat(readers).ToArray();
        start.Set();
        await Task.WhenAll(all);
        foreach (var rules in rulesets)
            rules.Dispose();

        Assert.Equal(0, canaryFailures);
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("does not match the hash DPAPI vouches for", StringComparison.Ordinal)
            || w.Contains("DPAPI did not vouch", StringComparison.Ordinal) || w.Contains("DPAPI blob length", StringComparison.Ordinal)
            || w.Contains("unknown format", StringComparison.Ordinal) || w.Contains("outside [", StringComparison.Ordinal));
        Assert.Empty(Directory.EnumerateFiles(cache.Location!, "*.tmp"));
        Assert.True(cache.TryLoad(key) is { } final && Disposed(final), "the final entry did not load");
    }
    #endregion

    #region Methods: helpers
    private static LoadedRules Load(YaraXRulesCache cache)
    {
        YaraX.EnsureEngine();
        var result = YaraXEngine.Load(Sources, cache);
        Assert.True(result.Rules is not null, $"the engine did not load: {result.Failure}");
        Assert.Null(result.Failure);
        return new LoadedRules(result.Rules!, result.FromCache);
    }

    private static string EntryPath(YaraXRulesCache cache) => cache.EntryPath(YaraXRules.SourcesSha256Of(Sources))!;

    // The entry was rewritten whole, in the current format, DPAPI vouches for its body, and the next load uses it.
    private static void AssertRewrittenAndLoadable(YaraXRulesCache cache, string path)
    {
        var entry = File.ReadAllBytes(path);
        Assert.True(entry.Length >= Entry.MinEntryBytes, "the entry was not rewritten");
        Entry.AssertVouched(entry, YaraXRules.SourcesSha256Of(Sources));
        using var next = Load(cache);
        Assert.True(next.FromCache, "the rewritten entry was not used by the next load");
    }

    // Each row damages the field it names, at its v3 offset (see Damage()). The precondition asserts keep each row honest
    // about where it lands: the magic row never touches [7], and the blob row stays out of DPAPI's unauthenticated range.
    private static byte[] Damaged(byte[] entry, string damage)
    {
        var copy = entry.ToArray();
        var p = Entry.P(entry);
        var body = Entry.BodyOffset(entry);
        var rules = body + Entry.BodyHeaderBytes;
        Assert.True(p is >= 1 and <= Entry.MaxProtectedBytes && copy.Length > rules, $"the precondition failed: not a v3 entry (P = {p})");
        switch (damage)
        {
            case "magic": copy[0] ^= 0x01; return copy;
            case "P field": copy[Entry.ProtectedLengthOffset] ^= 0x01; return copy;
            case "DPAPI blob byte":
                var blobByte = Entry.ProtectedOffset + p / 2;
                Assert.False(blobByte - Entry.ProtectedOffset is >= Entry.UnauthenticatedBlobFrom and <= Entry.UnauthenticatedBlobTo,
                    $"the precondition failed: blob offset {blobByte - Entry.ProtectedOffset} is one DPAPI does not authenticate");
                copy[blobByte] ^= 0x01;
                return copy;
            case "sources field": copy[body + Entry.SourcesOffset + 10] ^= 0x01; return copy;
            case "canary id": copy[body + Entry.CanaryIdOffset + 8] ^= 0x01; return copy;
            case "canary marker": copy[body + Entry.MarkerOffset + 12] ^= 0x01; return copy;
            case "rule count": copy[body + Entry.RuleCountOffset] ^= 0x01; return copy;
            case "first blob byte": copy[rules] ^= 0x01; return copy;
            case "middle blob byte": copy[rules + (copy.Length - rules) / 2] ^= 0x01; return copy;
            case "last blob byte": copy[^1] ^= 0x01; return copy;
            case "truncated blob": return copy[..(rules + (copy.Length - rules) / 2)];
            case "truncated header": return copy[..60];
            case "empty": return [];
            case "appended byte": return [.. copy, 0x00];
            default: throw new ArgumentOutOfRangeException(nameof(damage), damage, null);
        }
    }

    private static bool Disposed(YaraXRules rules)
    {
        rules.Dispose();
        return true;
    }

    // Owner the user, protected, exactly one plain allow ACE (the user, full control, inherited by files and subdirectories,
    // not inherit-only: that grants nothing on the directory itself), read from the RAW descriptor (review N-3).
    private static void AssertOwnerOnly(string directory) => YaraXRulesCacheTestRules.AssertOwnerOnly(directory);

    // W-B's quarantine shape: owner the user, protected, exactly one plain allow ACE (the user, full control) inherited by
    // subdirectories but NOT by files, which is what keeps it from ever reading as owner-only. Raw descriptor (N-3).
    private static void AssertQuarantined(string directory) => YaraXRulesCacheTestRules.AssertRawShape(directory, InheritanceFlags.ContainerInherit);

    // Replaces `directory`'s DACL: protected unless the shape says otherwise, rules from `shape`; and sets the owner to the
    // user unless `daclOnly` (writing the owner needs WRITE_OWNER, even when it does not change; the DACL alone needs
    // only the owner's implicit WRITE_DAC).
    private static void SetAcl(string directory, Action<DirectorySecurity, SecurityIdentifier> shape, bool daclOnly = false)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new DirectorySecurity();
        if (!daclOnly)
            security.SetOwner(identity.User!);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        shape(security, identity.User!);
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    // Asserts this process lacks WRITE_OWNER on `directory`: a descriptor carrying ONLY the owner (the user, who already owns
    // it, so a success would change nothing) is refused. Only the owner section is written (SetAccessControl persists the
    // sections that were set), so the DACL is not touched either way.
    private static void AssertTheOwnerCannotBeWritten(string directory)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var ownerOnlySection = new DirectorySecurity();
        ownerOnlySection.SetOwner(identity.User!);

        var refused = Record.Exception(() => new DirectoryInfo(directory).SetAccessControl(ownerOnlySection));

        Assert.True(refused is UnauthorizedAccessException,
            $"the precondition failed: this process could write the directory's owner ({refused?.GetType().Name ?? "no exception"}), so the test would not show a correction WITHOUT WRITE_OWNER");
    }

    private static string Sddl(string directory) =>
        new DirectoryInfo(directory).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

    // A valid, verified entry for this suite's Sources, written by a real cache in `donorDirectory`; its path.
    private static string ValidEntryFrom(string donorDirectory)
    {
        var donor = new YaraXRulesCache(donorDirectory);
        Load(donor).Dispose();
        return EntryPath(donor);
    }

    // The cache's cross-process lock name (YaraXRulesCache.MutexName, private).
    private static string MutexName(string directory)
    {
        var method = typeof(YaraXRulesCache).GetMethod("MutexName", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.True(method is not null, "YaraXRulesCache.MutexName is gone; the lock tests cannot name the lock.");
        return (string)method!.Invoke(null, [directory])!;
    }

    // Runs `body` on a dedicated (never pooled) thread and returns its result, rethrowing its exception with the original
    // stack: a thread that does not own a mutex the caller holds, with no pool-queueing delay in front of it.
    private static T OffTheOwnerThread<T>(Func<T> body)
    {
        T result = default!;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? fault = null;
        var thread = new Thread(() =>
        {
            try { result = body(); }
            catch (Exception ex) { fault = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex); }
        })
        { IsBackground = true, Name = "silvergun-cache-lock-test" };
        thread.Start();
        thread.Join();
        fault?.Throw();
        return result;
    }

    private static void AssertOnlyTheUserHasAccess(FileSecurity security)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();

        Assert.NotEmpty(rules);
        Assert.All(rules, r => Assert.Equal(identity.User, r.IdentityReference));
    }
    #endregion

    #region Nested types
    private sealed record LoadedRules(YaraXRules Rules, bool FromCache) : IDisposable
    {
        public void Dispose() => Rules.Dispose();
    }
    #endregion

    #region Fields
    private static readonly byte[] Marker = RandomNumberGenerator.GetBytes(32);

    // Two rules, compiled in milliseconds; one of them matches Marker.
    private static readonly (string Name, string Text)[] Sources =
    [
        ("probe.yar", YaraX.MarkerRule("cache_probe", Marker)),
        ("plain.yar", "rule cache_plain { condition: false }"),
    ];
    #endregion
}
#endif
