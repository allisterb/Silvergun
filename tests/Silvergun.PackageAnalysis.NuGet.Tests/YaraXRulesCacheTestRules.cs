#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Security.AccessControl;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// The rules-cache helpers shared by <see cref="YaraXRulesCacheTests"/>, <see cref="YaraXRulesCacheC1UseTests"/> and
/// <see cref="YaraXRulesCacheEntryDaclTests"/>: a tiny two-rule ruleset, loading it through the engine, and the raw-ACL
/// shape assertions. (Moved here from the configured-mode tests when that mode was removed: ADR 0033 amendment of
/// 2026-10-22.)
/// </summary>
internal static class YaraXRulesCacheTestRules
{
    #region Methods
    internal static Loaded Load(YaraXRulesCache cache)
    {
        YaraX.EnsureEngine();
        var result = YaraXEngine.Load(Sources, cache);
        Assert.True(result.Rules is not null, $"the engine did not load: {result.Failure}");
        return new Loaded(result.Rules!, result.FromCache);
    }

    internal static string EntryPath(YaraXRulesCache cache) => cache.EntryPath(Key)!;

    // The cache key of Sources, for TryLoad called directly.
    internal static string Key => YaraXRules.SourcesSha256Of(Sources);

    // A fresh compile of Sources (its own canary), for Store/TryLoad called directly.
    internal static YaraXRules Compile()
    {
        YaraX.EnsureEngine();
        var rules = YaraXRules.Compile(Sources, out var failure);
        Assert.True(rules is not null, $"the test rules did not compile: {failure}");
        return rules!;
    }

    // A valid, verified entry for Sources, written by a real cache in `donorDirectory`; its path.
    internal static string ValidEntryFrom(string donorDirectory)
    {
        var donor = new YaraXRulesCache(donorDirectory);
        Load(donor).Dispose();
        return EntryPath(donor);
    }

    // Owner the user, protected, exactly one ACE: the user, full control, inherited by files and subdirectories (not
    // inherit-only: that would grant nothing on the directory itself). Asserted on the RAW descriptor (review N-3):
    // GetAccessRules reports a conditional ACE as an unconditional one and omits ACEs it does not model, so counting its
    // rules could miss an ACE that is really there.
    internal static void AssertOwnerOnly(string directory) => AssertRawShape(directory, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);

    // `directory`'s raw descriptor, read through GetFileSecurityW: owner the user, DACL protected, and exactly one ACE, a
    // plain (not callback) allow for the user with full control, the given inheritance and no propagation flags.
    internal static void AssertRawShape(string directory, InheritanceFlags inheritance)
    {
        var user = Sids.User();
        var descriptor = RawAcl.Descriptor(directory);

        Assert.True((descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, "the DACL inherits from the parent");
        Assert.Equal(user, descriptor.Owner);
        Assert.NotNull(descriptor.DiscretionaryAcl);
        var ace = Assert.IsType<CommonAce>(Assert.Single(descriptor.DiscretionaryAcl!));
        Assert.False(ace.IsCallback, "the one ACE is a conditional (callback) ACE");
        Assert.Equal(AceQualifier.AccessAllowed, ace.AceQualifier);
        Assert.Equal(user, ace.SecurityIdentifier);
        Assert.Equal((int)FileSystemRights.FullControl, ace.AccessMask & (int)FileSystemRights.FullControl);
        Assert.Equal(inheritance, ace.InheritanceFlags);
        Assert.Equal(PropagationFlags.None, ace.PropagationFlags);
    }
    #endregion

    #region Nested types
    internal sealed record Loaded(YaraXRules Rules, bool FromCache) : IDisposable
    {
        public void Dispose() => Rules.Dispose();
    }
    #endregion

    #region Fields
    private static readonly IReadOnlyList<(string Name, string Text)> Sources =
    [
        ("cache-a.yar", "rule cache_a { condition: false }"),
        ("cache-b.yar", "rule cache_b { strings: $s = \"silvergun rules cache\" condition: $s }"),
    ];
    #endregion
}
#endif
