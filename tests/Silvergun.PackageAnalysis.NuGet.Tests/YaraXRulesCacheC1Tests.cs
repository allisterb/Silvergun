#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// Review C1 and W1/W2 of its review: how a cache USES its directory. (Configured mode, and every test of it, was removed
/// by the ADR 0033 amendment of 2026-10-22; what remains is the default location's behaviour.)
/// <list type="bullet">
/// <item>An otherwise owner-only directory with a conditional ACE is corrected (read from the raw DACL).</item>
/// <item>Entries are owned by the user through the creating handle, keeping the DACL they inherit.</item>
/// <item>A directory the cache itself made owner-only (created, or corrected) is trusted on the next use, silently.</item>
/// <item>The runtime fact the raw-DACL reading rests on (W2), pinned.</item>
/// </list>
/// Every directory is a <see cref="ControlledTempDir"/>.
///
/// <para><b>Measured on .NET 10.0.1 (2026-10-22):</b> <see cref="CommonObjectSecurity.GetAccessRules"/> does NOT skip a
/// conditional ACE: it returns <c>(XA;;FA;;;WD;(Member_of {SID(BA)}))</c> as an unconditional "Everyone, Allow,
/// FullControl" rule (the condition is dropped). See <see cref="OnThisRuntime_GetAccessRules_ReturnsAConditionalAce_AsAnUnconditionalAllow"/>.</para>
/// </summary>
public sealed class YaraXRulesCacheC1UseTests
{
    #region Methods: the runtime fact the W2 decision rests on
    // Records what .NET 10 does with a conditional ACE, which decides whether "GetAccessRules skips callback ACEs" (the
    // premise of W2 in YaraXRulesCache's comments) holds here. It does NOT: the XA ACE comes back as an UNCONDITIONAL allow
    // for Everyone (its condition dropped), so IsOwnerOnly built on GetAccessRules would also have seen two ACEs. Reading
    // the raw DACL is then defence in depth, plus the fail-closed policy for every non-plain ACE. If this ever fails, a
    // runtime started SKIPPING such ACEs, and the raw-DACL reading in YaraXRulesCache became load-bearing.
    [Fact]
    public void OnThisRuntime_GetAccessRules_ReturnsAConditionalAce_AsAnUnconditionalAllow()
    {
        using var dir = new ControlledTempDir("cfg-measure");
        var measured = dir.CreateDirectory("measured");
        RawAcl.SetDacl(measured, $"D:P(A;OICI;FA;;;{Sids.User().Value}){RawAcl.ConditionalAce}");

        var security = new DirectoryInfo(measured).GetAccessControl(AccessControlSections.Access);
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var raw = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl!.Cast<GenericAce>().ToArray();

        Assert.Equal(2, rules.Length);
        var everyone = Assert.Single(rules, r => Sids.Everyone.Equals(r.IdentityReference));
        Assert.Equal(AccessControlType.Allow, everyone.AccessControlType);
        Assert.Equal(FileSystemRights.FullControl, everyone.FileSystemRights);
        Assert.Contains(raw, a => a is CommonAce { IsCallback: true, AceType: AceType.AccessAllowedCallback });
    }
    #endregion

    #region Methods: a conditional ACE is corrected
    // W2: an otherwise owner-only directory plus a conditional ACE is not owner-only (raw DACL), so it is corrected: one
    // "was not owner-only" warning, its entries deleted unused, a fresh entry written, and its DACL ends up exactly
    // D:P(A;OICI;FA;;;<user>). The next use trusts it.
    [Fact]
    public void ADefaultModeDirectoryWithAConditionalAce_IsCorrected_AndItsEntriesDeleted()
    {
        using var dir = new ControlledTempDir("cache-xa");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        YaraXRulesCacheTestRules.Load(cache).Dispose();
        var entry = YaraXRulesCacheTestRules.EntryPath(cache);
        var entryBefore = File.ReadAllBytes(entry);
        var otherKey = Path.Combine(cache.Location!, $"rules-1.22.0-{new string('e', 64)}.sgyx");
        File.WriteAllBytes(otherKey, [1]);
        RawAcl.SetDacl(cache.Location!, RawAcl.OwnerOnlyDacl() + RawAcl.ConditionalAce);
        Assert.Contains("(XA;", RawAcl.Sddl(cache.Location!), StringComparison.Ordinal);
        using var warnings = new WarningCapture();

        using (var first = YaraXRulesCacheTestRules.Load(cache))
            Assert.False(first.FromCache, "an entry in a directory with a conditional ACE was trusted");

        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        Assert.Contains($"{cache.Location} was not owner-only; restricting it to the current user and deleting its entries", warning, StringComparison.Ordinal);
        Assert.False(File.Exists(otherKey), "an entry from the uncorrected directory survived the correction");
        Assert.False(File.ReadAllBytes(entry).AsSpan().SequenceEqual(entryBefore), "the entry from the uncorrected directory was kept");
        Assert.Equal(RawAcl.Normalized(RawAcl.OwnerOnlyDacl()), RawAcl.Dacl(cache.Location!));
        using var next = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(next.FromCache, "the corrected directory was not trusted on the next use");
    }

    // IsOwnerOnly's "exactly one ACE" on the RAW DACL (W2, N4): a directory whose one owner-only ACE is split in two (FR,
    // then the rest of FA, both OICI, for the user) is two ACEs on disk (asserted with GetFileSecurityW), so it is not
    // owner-only, and is corrected like any other such shape: one warning, its entries deleted, exactly owner-only after.
    [Fact]
    public void ADirectoryWhoseOwnerOnlyAceIsSplitInTwo_IsNotOwnerOnly_AndIsCorrected()
    {
        using var dir = new ControlledTempDir("cache-split");
        var cache = new YaraXRulesCache(dir.Combine("rules"));
        YaraXRulesCacheTestRules.Load(cache).Dispose();
        var otherKey = Path.Combine(cache.Location!, $"rules-1.22.0-{new string('e', 64)}.sgyx");
        File.WriteAllBytes(otherKey, [1]);
        var user = Sids.User().Value;
        RawAcl.SetDacl(cache.Location!, $"D:P(A;OICI;FR;;;{user})(A;OICI;0x{0x1F01FF & ~0x120089:x};;;{user})");
        Assert.Equal(2, RawAcl.Descriptor(cache.Location!).DiscretionaryAcl!.Count);   // the precondition: two ACEs on disk
        using var warnings = new WarningCapture();

        using (var first = YaraXRulesCacheTestRules.Load(cache))
            Assert.False(first.FromCache, "an entry in a directory whose DACL is not exactly owner-only was trusted");

        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        Assert.Contains($"{cache.Location} was not owner-only; restricting it to the current user and deleting its entries", warning, StringComparison.Ordinal);
        Assert.False(File.Exists(otherKey), "an entry from the uncorrected directory survived the correction");
        Assert.Equal(RawAcl.Normalized(RawAcl.OwnerOnlyDacl()), RawAcl.Dacl(cache.Location!));
    }
    #endregion

    #region Methods: the entry's owner is set through the creating handle
    // S1's other half, done through the creating handle: a stored entry is owned by the user and loads, and its DACL is the
    // one it inherits from the owner-only directory: not empty, not protected, one allow ACE for the user, full control,
    // not set explicitly (a FileSecurity passed at creation would replace it: an owner-only one gives an EMPTY DACL).
    [Fact]
    public void AStoredEntry_IsOwnedByTheUser_KeepsTheDaclItInherits_AndLoads()
    {
        using var dir = new ControlledTempDir("cache-owner");
        var cache = Cache(dir);
        using var rules = YaraXRulesCacheTestRules.Compile();

        Assert.True(cache.Store(rules));

        var entry = YaraXRulesCacheTestRules.EntryPath(cache);
        var descriptor = RawAcl.Descriptor(entry);
        Assert.Equal(Sids.User(), descriptor.Owner);
        Assert.Equal((ControlFlags)0, descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected);
        var ace = Assert.IsType<CommonAce>(Assert.Single(descriptor.DiscretionaryAcl!));
        Assert.Equal(AceQualifier.AccessAllowed, ace.AceQualifier);
        Assert.Equal(Sids.User(), ace.SecurityIdentifier);
        Assert.Equal((int)FileSystemRights.FullControl, ace.AccessMask & (int)FileSystemRights.FullControl);
        // A file's copy of the directory's OICI ACE: no flags of its own. (The kernel marks it INHERITED only when the
        // directory's DACL is auto-inherited; the cache creates its directory with a plain protected DACL, D:P, so not here.)
        Assert.Equal(AceFlags.None, ace.AceFlags & ~AceFlags.Inherited);
        var security = new FileInfo(entry).GetAccessControl();
        Assert.False(security.AreAccessRulesProtected, "the entry's DACL was set explicitly (protected), not inherited");
        using var loaded = cache.TryLoad(rules.SourcesSha256);
        Assert.NotNull(loaded);
    }

    // Under an elevated token the default owner of a new file can be BUILTIN\Administrators; the entry must still be the
    // user's (set through the creating handle), or S1 would distrust every entry this process writes. (Ran in configured
    // mode until that mode was removed; the creating handle is the same in the default location.)
    [ElevatedWindowsFact(Needs = "an elevated token's default owner can be BUILTIN\\Administrators, which is what setting the entry's owner through its handle corrects")]
    public void AnEntryStoredElevated_IsOwnedByTheUser_AndLoads()
    {
        using var dir = new ControlledTempDir("cache-owner-elevated");
        var probe = dir.Combine("probe.dat");
        File.WriteAllBytes(probe, [1]);
        var defaultOwner = RawAcl.Descriptor(probe).Owner;
        var cache = Cache(dir);
        using var rules = YaraXRulesCacheTestRules.Compile();

        Assert.True(cache.Store(rules));

        Assert.True(Sids.User() == RawAcl.Descriptor(YaraXRulesCacheTestRules.EntryPath(cache)).Owner,
            $"the entry is not the user's (this token's default owner is {defaultOwner?.Value})");
        using var loaded = cache.TryLoad(rules.SourcesSha256);
        Assert.NotNull(loaded);
    }
    #endregion

    #region Methods: what the cache made owner-only is trusted next time
    // A regression guard for the raw-DACL IsOwnerOnly: a directory the cache CREATED owner-only is trusted on the next use,
    // with no "not owner-only" warning.
    [Fact]
    public void ADirectoryTheCacheCreated_IsTrustedOnTheNextUse_Silently()
    {
        using var dir = new ControlledTempDir("cache-trust");
        var cache = Cache(dir);
        YaraXRulesCacheTestRules.Load(cache).Dispose();
        using var warnings = new WarningCapture();

        using (var next = YaraXRulesCacheTestRules.Load(cache))
            Assert.True(next.FromCache, "the directory the cache created was not trusted");
        using var rules = YaraXRulesCacheTestRules.Compile();
        Assert.True(cache.Store(rules));

        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        YaraXRulesCacheTestRules.AssertOwnerOnly(cache.Location!);
    }

    // ...and so is one the cache CORRECTED.
    [Fact]
    public void ADirectoryTheCacheCorrected_IsTrustedOnTheNextUse_Silently()
    {
        using var dir = new ControlledTempDir("cache-trust-corrected");
        var location = dir.CreateDirectory("rules");   // exists, inherited ACL: not owner-only
        var cache = new YaraXRulesCache(location);
        using (var warnings = new WarningCapture())
        {
            YaraXRulesCacheTestRules.Load(cache).Dispose();
            Assert.Contains(warnings.Warnings, w => w.Contains("was not owner-only", StringComparison.Ordinal));
        }

        using (var warnings = new WarningCapture())
        {
            using (var next = YaraXRulesCacheTestRules.Load(cache))
                Assert.True(next.FromCache, "the directory the cache corrected was not trusted");
            Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        }
        Assert.Equal(RawAcl.Normalized(RawAcl.OwnerOnlyDacl()), RawAcl.Dacl(location));
    }
    #endregion

    #region Methods: helpers
    // A cache in its own ...\rules directory inside `dir`, used exactly as the default location is.
    private static YaraXRulesCache Cache(ControlledTempDir dir) => new(dir.Combine("rules"));
    #endregion
}
#endif
