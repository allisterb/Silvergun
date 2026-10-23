#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;

using SystemRawAcl = System.Security.AccessControl.RawAcl;

/// <summary>
/// Review W-A, tightened by the ADR 0033 amendment of 2026-10-22: a cache entry is read only when, checked on the very
/// handle it is then read through, its owner is the user (S1) and its DACL is EXACTLY the one Silvergun gives its own
/// entries: non-null, one ACE, a plain (non-callback) allow, for the user, with full control, not inherit-only. Whether
/// that ACE is marked inherited is not weighed. Anything else is refused with one warning naming which part differs, the
/// entry is deleted (best effort), the rules are recompiled and a fresh entry is stored, which the next load trusts.
///
/// <para><b>The shapes this refuses that the old "no untrusted writer" rule let through.</b> Read-only or deny grants,
/// full control for LocalSystem or Administrators, inherit-only grants: none lets anyone else change the file, but none
/// is what <c>Store</c> writes, so such a file did not come from the cache. The real-world one is a file restored into the
/// NuGet global-packages folder, owned by the user with <c>(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;&lt;user&gt;)</c>.</para>
///
/// <para><b>How a refusal is staged.</b> A VALID entry (the bytes of a real stored one, so its hash, key, canary and blob
/// all check out), owned by the user, carrying the DACL under test, either moved in under the entry's name (a move keeps
/// owner and DACL) or set in place (the owner may always write the DACL). Only the DACL check can refuse it, so each such
/// test goes red the moment that check loosens.</para>
///
/// <para><b>A single ACE that gives the user no read access</b> (a deny, SYSTEM only, inherit-only, an object ACE with a
/// GUID, a custom ACE: measured) cannot be opened for reading at all, so the DACL check is never reached: the open fails,
/// the load is a "could not read" miss, and the store that follows replaces the entry. Those clauses are pinned on the
/// check itself (<see cref="TheEntryDaclCheck_NamesWhichPartDiffers"/>), through reflection, as a pure function.</para>
///
/// <para><b>Review N-1.</b> A cache directory whose DACL holds an ACE .NET cannot parse (measured: a custom ACE whose size
/// is not a multiple of 4, or a compound ACE with two SIDs) makes <see cref="DirectoryInfo"/>'s <c>GetAccessControl</c>
/// throw. The cache is then not used, with one warning telling the user to delete the directory, and its ACL is never
/// "corrected": the raw descriptor is byte-for-byte unchanged. A custom ACE of an aligned size (types 0x11, 0x30) is
/// parsed, so it takes the ordinary not-owner-only path instead (also pinned here).</para>
///
/// <para>Every directory is a <see cref="ControlledTempDir"/> (under <c>C:\Temp</c>, protected: the user, LocalSystem and
/// Administrators only).</para>
/// </summary>
public sealed class YaraXRulesCacheEntryDaclTests
{
    #region Methods: our own entry loads
    // Our own entry, as stored; the same ACE set explicitly (not marked inherited); and a valid entry moved in from a
    // directory whose DACL is auto-inherited, so its one ACE IS marked inherited (as after a correction, which writes the
    // directory's DACL through SetNamedSecurityInfo). Each loads, unchanged, with no warning, and the engine takes it
    // from the cache: the Inherited flag is not weighed either way.
    [Theory]
    [InlineData("as stored")]
    [InlineData("set explicitly, not marked inherited")]
    [InlineData("moved in, marked inherited")]
    public void AnEntryWithExactlyOurOneAce_Loads_Silently_WhetherOrNotItIsMarkedInherited(string shape)
    {
        using var dir = new ControlledTempDir("entry-ours");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var user = Sids.User().Value;
        switch (shape)
        {
            case "as stored": break;
            case "set explicitly, not marked inherited": RawAcl.SetDacl(path, $"D:P(A;;FA;;;{user})"); break;
            case "moved in, marked inherited":
                var valid = File.ReadAllBytes(path);
                MoveIn(ForgedIn(dir, "auto-inherited", $"D:PAI(A;OICI;FA;;;{user})", valid), path, valid);
                break;
            default: throw new ArgumentOutOfRangeException(nameof(shape), shape, null);
        }
        var ace = Assert.IsType<CommonAce>(Assert.Single(RawAcl.Descriptor(path).DiscretionaryAcl!));
        Assert.True(ace is { IsCallback: false, AceQualifier: AceQualifier.AccessAllowed } && ace.SecurityIdentifier == Sids.User()
            && (ace.AccessMask & FullControl) == FullControl && (ace.AceFlags & AceFlags.InheritOnly) == 0, $"{shape}: the precondition failed: the one ACE is not ours");
        if (shape != "as stored")
            Assert.Equal(shape == "moved in, marked inherited", (ace.AceFlags & AceFlags.Inherited) != 0);   // the precondition
        var before = File.ReadAllBytes(path);

        YaraXRules? loaded;
        using (var warnings = new WarningCapture())
        {
            loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key);
            Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        }

        using (loaded)
            Assert.True(loaded is not null, $"{shape}: an entry with exactly our one ACE was refused");
        Assert.Equal(before, File.ReadAllBytes(path));
        using var viaEngine = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(viaEngine.FromCache, $"{shape}: the engine did not take the entry from the cache");
    }
    #endregion

    #region Methods: the NuGet global-packages shape
    // The shape that motivated the tightening: a file restored into the NuGet global-packages folder is owned by the user
    // and carries the profile's inherited (A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;<user>). No one but trusted principals can
    // change it, so the old rule accepted it; but it did not come from Store. Staged as exactly such a file (created in a
    // directory with that inheritable, auto-inherited DACL) holding a VALID entry's bytes, and moved in: refused for its
    // three entries, deleted, recompiled, and the next load comes from the cache.
    [Fact]
    public void AValidEntryWithTheNuGetGlobalPackagesShape_IsRefused_Deleted_Recompiled_AndTheNextLoadIsFromTheCache()
    {
        using var dir = new ControlledTempDir("entry-nuget");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var valid = File.ReadAllBytes(path);
        var forged = ForgedIn(dir, "global-packages-like", $"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{Sids.User().Value})", valid);
        var aces = RawAcl.Descriptor(forged).DiscretionaryAcl!.Cast<GenericAce>().ToArray();
        Assert.Equal(3, aces.Length);   // the precondition: the global-packages shape, all three inherited full control
        Assert.All(aces, a => Assert.True(a is CommonAce { IsCallback: false, AceQualifier: AceQualifier.AccessAllowed } c
            && (c.AceFlags & AceFlags.Inherited) != 0 && (c.AccessMask & FullControl) == FullControl, $"not an inherited full-control allow: {a.AceType}"));
        Assert.Equal(new[] { Sids.System, Sids.Administrators, Sids.User() }.Select(s => s.Value).Order(StringComparer.Ordinal),
            aces.Cast<CommonAce>().Select(a => a.SecurityIdentifier.Value).Order(StringComparer.Ordinal));
        MoveIn(forged, path, valid);

        AssertRefusedDeletedAndRecompiled(cache, path, Entries(3));
    }
    #endregion

    #region Methods: a valid entry moved in with a foreign write grant
    // (grantee as an SDDL alias, rights as an SDDL token). Each is refused as soon as it is a second ACE; GW and GA are
    // written as generic rights, which NTFS stores mapped (asserted as a precondition).
    public static TheoryData<string, string> ForeignWriteGrants()
    {
        var data = new TheoryData<string, string>();
        foreach (var who in new[] { "WD", "AU" })
            foreach (var rights in new[] { WriteData, AppendData, Delete, WriteDac, WriteOwner, "GW", "GA" })
                data.Add(who, rights);
        return data;
    }

    [Theory]
    [MemberData(nameof(ForeignWriteGrants))]
    public void AValidEntryMovedInWithAForeignWriteGrant_IsRefused_Deleted_AndRecompiled(string who, string rights)
    {
        using var dir = new ControlledTempDir("entry-moved");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var valid = File.ReadAllBytes(path);
        var forged = Path.Combine(dir.CreateDirectory("shared"), "victim-owned.dat");
        WriteUserOwned(forged, valid);
        RawAcl.SetDacl(forged, $"D:P(A;;FA;;;{Sids.User().Value})(A;;{rights};;;{who})");
        var grantee = Sid(who);
        var grant = ForeignAce(forged, grantee);
        if (rights is "GW" or "GA")
        {
            // Measured: NTFS stores a generic right mapped (GW as FILE_GENERIC_WRITE, GA as FILE_ALL_ACCESS).
            Assert.Equal(0, grant.AccessMask & unchecked((int)0xF0000000));
            Assert.NotEqual(0, grant.AccessMask & (int)FileSystemRights.WriteData);
        }
        else
            Assert.Equal(Convert.ToInt32(rights, 16), grant.AccessMask);
        MoveIn(forged, path, valid, grantee);

        AssertRefusedDeletedAndRecompiled(cache, path, Entries(2));
    }

    // The real-world shape of a file created by the user in a folder like C:\Temp, whose inheritable
    // (A;OICIIOID;SDGXGWGR;;;AU) gives every new file an INHERITED Authenticated Users write grant. Moved in, it keeps it.
    [Fact]
    public void AValidEntryMovedInFromACTempLikeFolder_IsRefusedForItsInheritedGrant()
    {
        using var dir = new ControlledTempDir("entry-ctemp");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var valid = File.ReadAllBytes(path);
        var forged = ForgedIn(dir, "ctemp-like", $"D:PAI(A;OICI;FA;;;{Sids.User().Value})(A;OICIIO;SDGXGWGR;;;AU)", valid);
        var grant = ForeignAce(forged, Sids.AuthenticatedUsers);
        Assert.True((grant.AceFlags & AceFlags.Inherited) != 0, "the precondition failed: the grant is not inherited");
        Assert.NotEqual(0, grant.AccessMask & (int)FileSystemRights.WriteData);
        MoveIn(forged, path, valid, Sids.AuthenticatedUsers);

        AssertRefusedDeletedAndRecompiled(cache, path, Entries(2));
    }
    #endregion

    #region Methods: any ACE besides ours
    // Grants the old rule accepted because none lets anyone but a trusted principal change the entry: read-only grants, a
    // deny, full control for LocalSystem or Administrators, an object ACE without a GUID (which NTFS stores as a plain
    // allow: measured, asserted below), and an inherit-only grant (stored on a file with its inherit-only flag kept:
    // measured, asserted below). Next to our own ACE, each is a second entry: refused, deleted, recompiled.
    // Also a second allow for the user that only splits our full control in two (FR, then the rest of FA): two ACEs, though
    // together they grant the user exactly what ours does. (Our own ACE twice cannot be staged: measured, Windows keeps one
    // copy of an exact duplicate, whether the DACL is written from SDDL or from raw bytes.)
    public static TheoryData<string> ExtraAceShapes() => new(
        "read-only for Everyone", "read-and-execute for Authenticated Users", "a write deny for Everyone", "full control for SYSTEM",
        "full control for Administrators", "a read-only OA without a GUID", "inherit-only full control for Everyone",
        "full control for the user, split in two");

    [Theory]
    [MemberData(nameof(ExtraAceShapes))]
    public void AnEntryWithAnyAceBesidesOurs_IsRefused_ForItsEntryCount(string shape)
    {
        using var dir = new ControlledTempDir("entry-extra");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var user = Sids.User().Value;
        var extra = shape switch
        {
            "read-only for Everyone" => "(A;;FR;;;WD)",
            "read-and-execute for Authenticated Users" => "(A;;0x1200a9;;;AU)",
            "a write deny for Everyone" => "(D;;0x6;;;WD)",
            "full control for SYSTEM" => "(A;;FA;;;SY)",
            "full control for Administrators" => "(A;;FA;;;BA)",
            "a read-only OA without a GUID" => "(OA;;FR;;;WD)",
            "inherit-only full control for Everyone" => "(A;OICIIO;FA;;;WD)",
            "full control for the user, split in two" => SplitFullControl(),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
        };
        RawAcl.SetDacl(path, shape == "full control for the user, split in two" ? "D:P" + extra
            : extra.StartsWith("(D;", StringComparison.Ordinal) ? $"D:P{extra}(A;;FA;;;{user})" : $"D:P(A;;FA;;;{user}){extra}");
        var stored = RawAcl.Descriptor(path).DiscretionaryAcl!.Cast<GenericAce>().ToArray();
        Assert.Equal(2, stored.Length);
        Assert.All(stored, a => Assert.True(a is CommonAce { IsCallback: false }, $"{shape}: an ACE that is not plain is on disk: {a.GetType().Name}"));
        if (shape == "inherit-only full control for Everyone")
            Assert.Contains(stored, a => a is CommonAce c && c.SecurityIdentifier == Sids.Everyone && (c.AceFlags & AceFlags.InheritOnly) != 0);

        AssertRefusedDeletedAndRecompiled(cache, path, Entries(2));
    }

    // A conditional (callback, XA) ACE, or an object ACE WITH an object-type GUID (OA), next to our own: a second entry,
    // whatever it grants (full control, or read only). Set in place (the owner may always write the DACL): the check is
    // on the handle, so where the entry came from does not matter.
    public static TheoryData<string> UnevaluableAces() =>
        new("XA full control", "XA read-only", "OA with a GUID, full control", "OA with a GUID, read-only");

    [Theory]
    [MemberData(nameof(UnevaluableAces))]
    public void AnEntryWithAnAceSilvergunCannotEvaluate_BesidesOurs_IsRefused_ForItsEntryCount(string ace)
    {
        using var dir = new ControlledTempDir("entry-unevaluable");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var rights = ace.EndsWith("read-only", StringComparison.Ordinal) ? "FR" : "FA";
        var sddl = ace.StartsWith("XA", StringComparison.Ordinal)
            ? RawAcl.ConditionalAce.Replace(";;FA;;;", $";;{rights};;;", StringComparison.Ordinal)
            : $"(OA;;{rights};{ObjectTypeGuid};;WD)";
        RawAcl.SetDacl(path, $"D:P(A;;FA;;;{Sids.User().Value}){sddl}");
        var stored = RawAcl.Descriptor(path).DiscretionaryAcl!.Cast<GenericAce>().ToArray();
        Assert.Contains(stored, a => ace.StartsWith("XA", StringComparison.Ordinal)
            ? a is CommonAce { IsCallback: true }
            : a is ObjectAce { ObjectAceFlags: ObjectAceFlags.ObjectAceTypePresent });   // the precondition: on disk as written

        AssertRefusedDeletedAndRecompiled(cache, path, Entries(2));
    }

    [Fact]
    public void AnEntryWithANullDacl_IsRefused_Deleted_AndRecompiled()
    {
        using var dir = new ControlledTempDir("entry-nulldacl");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        RawAcl.SetDacl(path, "D:NO_ACCESS_CONTROL");
        Assert.Null(RawAcl.Descriptor(path).DiscretionaryAcl);   // the precondition: really a null DACL on disk

        AssertRefusedDeletedAndRecompiled(cache, path, NotOursBecause(NullDaclDetail));
    }
    #endregion

    #region Methods: a single ACE that is not ours
    // One ACE, but not ours, in the shapes the user can still open for reading (so the check on the handle is reached):
    // less than full control, or a conditional allow whose condition holds (Everyone is in every token). Each is refused
    // with the detail naming what differs, deleted, and recompiled.
    public static TheoryData<string, string> ReadableSingleAces() => new()
    {
        { "the user with read only", NotFullControlDetail },
        { "the user with modify (no WRITE_DAC or WRITE_OWNER)", NotFullControlDetail },
        { "a conditional allow of full control for the user, whose condition holds", NotEvaluatedDetail },
    };

    [Theory]
    [MemberData(nameof(ReadableSingleAces))]
    public void ASingleAceThatIsNotOurs_IsRefusedWithItsDetail_Deleted_AndRecompiled(string shape, string detail)
    {
        using var dir = new ControlledTempDir("entry-single");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        RawAcl.SetDacl(path, "D:P" + SingleAceSddl(shape));
        var ace = Assert.Single(RawAcl.Descriptor(path).DiscretionaryAcl!);   // the precondition: one ACE, as written
        Assert.Equal(shape.StartsWith("a conditional", StringComparison.Ordinal), ace is CommonAce { IsCallback: true });
        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) { }   // ...and the user can read it

        AssertRefusedDeletedAndRecompiled(cache, path, NotOursBecause(detail));
    }

    // One ACE that gives the user no read access at all (measured): the entry cannot even be opened, so it is never read
    // and the DACL check is never reached. The load is a "could not read" miss with one warning, the rules are recompiled,
    // and the store replaces the entry with one of our own (the cache directory's FILE_DELETE_CHILD lets the user replace
    // it), which the next load trusts. Fail closed, by the open rather than by the check (which is pinned by
    // TheEntryDaclCheck_NamesWhichPartDiffers).
    [Theory]
    [InlineData("a deny of full control for the user")]
    [InlineData("full control for SYSTEM only")]
    [InlineData("the user's full control, inherit-only")]
    [InlineData("an object ACE with a GUID, full control for the user")]
    [InlineData("an aligned custom ACE")]
    public void ASingleAceThatGivesTheUserNoReadAccess_IsNeverRead_AndTheStoreReplacesIt(string shape)
    {
        using var dir = new ControlledTempDir("entry-noread");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        if (shape == "an aligned custom ACE")
            RawAcl.SetDaclBytes(path, SingleAceDescriptor(AceBytes("custom type 0x30")));
        else
            RawAcl.SetDacl(path, "D:P" + SingleAceSddl(shape));
        Assert.Single(RawAcl.Descriptor(path).DiscretionaryAcl!);   // the precondition: one ACE, as written
        Assert.IsType<UnauthorizedAccessException>(Record.Exception(() => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read).Dispose()));

        AssertNeverReadAndReplaced(cache, path);
    }

    // Every clause of the check, on the check itself (YaraXRulesCache.NotOwnEntryDacl, private, through reflection): a
    // pure function of the DACL and the user, so the shapes the user cannot open on disk are pinned too. Null for our own
    // shape (marked inherited or not); otherwise the detail naming the first part that differs.
    public static TheoryData<string, string?> DaclShapes() => new()
    {
        { "ours, not marked inherited", null },
        { "ours, marked inherited", null },
        { "a null DACL", NullDaclDetail },
        { "an empty DACL", "it has 0 permission entries, not one" },
        { "ours, plus read for Everyone", "it has 2 permission entries, not one" },
        { "the NuGet global-packages shape", "it has 3 permission entries, not one" },
        { "a deny of full control for the user", NotFullControlDetail },
        { "full control for SYSTEM only", NotFullControlDetail },
        { "the user with read only", NotFullControlDetail },
        { "the user with modify (no WRITE_DAC or WRITE_OWNER)", NotFullControlDetail },
        { "the user's full control, inherit-only", NotFullControlDetail },
        { "a conditional allow of full control for the user, whose condition holds", NotEvaluatedDetail },
        { "an object ACE with a GUID, full control for the user", NotEvaluatedDetail },
        { "an aligned custom ACE", NotEvaluatedDetail },
    };

    [Theory]
    [MemberData(nameof(DaclShapes))]
    public void TheEntryDaclCheck_NamesWhichPartDiffers(string shape, string? expected)
    {
        var user = Sids.User().Value;
        var dacl = shape switch
        {
            "a null DACL" => null,
            "an empty DACL" => new SystemRawAcl(GenericAcl.AclRevision, 0),
            "ours, not marked inherited" => Parse($"(A;;FA;;;{user})"),
            "ours, marked inherited" => Parse($"(A;ID;FA;;;{user})"),
            "ours, plus read for Everyone" => Parse($"(A;;FA;;;{user})(A;;FR;;;WD)"),
            "the NuGet global-packages shape" => Parse($"(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{user})"),
            "an aligned custom ACE" => new RawSecurityDescriptor(SingleAceDescriptor(AceBytes("custom type 0x30")), 0).DiscretionaryAcl,
            _ => Parse(SingleAceSddl(shape)),
        };
        if (shape is "ours, not marked inherited" or "ours, marked inherited")
            Assert.Equal(shape == "ours, marked inherited", (dacl![0].AceFlags & AceFlags.Inherited) != 0);   // the precondition
        if (shape == "an aligned custom ACE")
            Assert.IsType<CustomAce>(dacl![0]);   // the precondition: parsed, as a custom ACE

        Assert.Equal(expected, NotOwnEntryDacl(dacl));
    }
    #endregion

    #region Methods: the runtime fact the handle check's DACL reading meets
    // Records what .NET 10 gives back for a FILE's DACL through FileSecurity, which is how ReadIfOwned USED to read the
    // entry's DACL on its handle (stream.GetAccessControl(), then GetSecurityDescriptorBinaryForm()). FileSecurity is a
    // CommonSecurityDescriptor for a non-container, which canonicalises the DACL it is given: so its binary form is NOT the
    // raw DACL on disk (read here with GetFileSecurityW, which shows two ACEs in each case). That is why ReadIfOwned now
    // reads the descriptor natively (WindowsSecurityNative.Descriptor, pinned in WindowsSecurityNativeTests), and why the
    // two "ExtraAceShapes" rows this explains go red if it ever reads through FileSecurity again.
    [Theory]
    [InlineData("inherit-only full control for Everyone")]
    [InlineData("full control for the user, split in two")]
    public void OnThisRuntime_FileSecurity_CanonicalisesAFilesDacl_SoItIsNotTheRawDacl(string shape)
    {
        using var dir = new ControlledTempDir("measure-filesecurity");
        var path = dir.Combine("measured.dat");
        File.WriteAllBytes(path, [1]);
        RawAcl.SetDacl(path, "D:P" + (shape == "full control for the user, split in two" ? SplitFullControl() : $"(A;;FA;;;{Sids.User().Value})(A;OICIIO;FA;;;WD)"));
        Assert.Equal(2, RawAcl.Descriptor(path).DiscretionaryAcl!.Count);   // on disk: two ACEs

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var viaFileSecurity = new RawSecurityDescriptor(stream.GetAccessControl().GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl!;

        var only = Assert.IsType<CommonAce>(Assert.Single(viaFileSecurity));   // through FileSecurity: one
        Assert.Equal(Sids.User(), only.SecurityIdentifier);
        Assert.Equal(FullControl, only.AccessMask & FullControl);
    }
    #endregion

    #region Methods: an entry whose ACL .NET cannot read
    // Not W-A's rule but its neighbour, fail closed: an ENTRY whose DACL holds an ACE .NET cannot model (here a compound
    // ACE) cannot be read on its handle, so it is never loaded ("could not read", recompiled), and the store that follows
    // replaces it with an entry of our own, which the next load trusts.
    [Fact]
    public void AnEntryWithAnAceDotNetCannotRead_IsNeverLoaded_AndTheStoreReplacesIt()
    {
        using var dir = new ControlledTempDir("entry-compound");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        RawAcl.SetDaclBytes(path, Descriptor(OneAce(PlainAllowType, 0, FullControl, Sids.User()), AceBytes("a compound ACE")));
        Assert.NotNull(Record.Exception(() => new FileInfo(path).GetAccessControl()));   // the precondition: .NET cannot read it

        using (var warnings = new WarningCapture())
        {
            using (var first = YaraXRulesCacheTestRules.Load(cache))
                Assert.False(first.FromCache, "an entry whose ACL cannot be read was loaded");
            var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
            Assert.Contains($"could not read {path}: ", warning, StringComparison.Ordinal);
        }

        Assert.All(RawAcl.Descriptor(path).DiscretionaryAcl!.Cast<GenericAce>(), a => Assert.True(a is CommonAce c && c.SecurityIdentifier == Sids.User()));
        using var next = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(next.FromCache, "the entry the store wrote over it was not trusted");
    }
    #endregion

    #region Methods: N-1, a cache directory whose ACL .NET cannot read
    // An ACE .NET cannot parse, written with SetFileSecurityW next to the owner-only ACE, on the cache directory, which
    // holds a valid entry. Measured on .NET 10 (2026-10-22): NTFS stores both, and GetAccessControl throws
    // ArgumentException ("The binary form of an ACE object is invalid") for both: a custom ACE (type 0x30) whose size, 14,
    // is not a multiple of 4; and a compound ACE (type 4) as Windows defines it, with two SIDs (.NET's CompoundAce has
    // one). A custom ACE of an aligned size is NOT unreadable: see ACacheDirectoryWithAReadableCustomAce_IsCorrected.
    //
    // Every use: exactly one "cannot be read; delete it" warning, the cache not used (Store false, TryLoad null, the engine
    // compiles), and the directory's raw descriptor (read with GetFileSecurityW, never .NET) and files exactly as before:
    // nothing was corrected and nothing deleted.
    [Theory]
    [InlineData("an unaligned custom ACE")]
    [InlineData("a compound ACE")]
    public void ACacheDirectoryWithAnAceDotNetCannotRead_IsNotUsed_NeverCorrected_WithOneWarning(string ace)
    {
        using var dir = new ControlledTempDir("dir-unreadable");
        var cache = Cache(dir);
        StoredEntry(cache);
        var location = cache.Location!;
        try
        {
            RawAcl.SetDaclBytes(location, Descriptor(OneAce(PlainAllowType, ObjectAndContainerInherit, FullControl, Sids.User()), AceBytes(ace)));
            var thrown = Record.Exception(() => new DirectoryInfo(location).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner));
            Assert.True(thrown is InvalidOperationException or ArgumentException,
                $"the precondition failed: .NET read the DACL with {ace} ({thrown?.GetType().Name ?? "no exception"})");
            var aclBefore = RawAcl.Bytes(location);
            var filesBefore = Snapshot.Files(location);
            using var rules = YaraXRulesCacheTestRules.Compile();

            using (var warnings = new WarningCapture())
            {
                Assert.False(cache.Store(rules), $"{ace}: the store used a directory whose ACL cannot be read");
                AssertUnreadable(warnings, location);
            }
            using (var warnings = new WarningCapture())
            {
                Assert.Null(cache.TryLoad(YaraXRulesCacheTestRules.Key));
                AssertUnreadable(warnings, location);
            }
            using (var viaEngine = YaraXRulesCacheTestRules.Load(cache))
                Assert.False(viaEngine.FromCache, $"{ace}: an entry in a directory whose ACL cannot be read was loaded");

            Assert.Equal(aclBefore, RawAcl.Bytes(location));
            Assert.Equal(filesBefore, Snapshot.Files(location));
        }
        finally
        {
            RawAcl.SetDacl(location, RawAcl.OwnerOnlyDacl());   // leave it deletable
        }
    }

    // The custom ACE types the review expected to throw (0x11, the mandatory-label type, in a DACL; 0x30, undefined) do
    // NOT, at an aligned size: .NET 10 parses each as a CustomAce (measured 2026-10-22, asserted below). N-1's path is then
    // not taken, and the ACE is handled as any ACE that is not plain: the directory is not owner-only, so it is corrected
    // (one warning, its entries deleted, exactly owner-only after, the cache used again). Fail closed.
    [Theory]
    [InlineData("custom type 0x11")]
    [InlineData("custom type 0x30")]
    public void ACacheDirectoryWithAReadableCustomAce_IsCorrected(string ace)
    {
        using var dir = new ControlledTempDir("dir-custom");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var entryBefore = File.ReadAllBytes(path);
        var location = cache.Location!;
        try
        {
            RawAcl.SetDaclBytes(location, Descriptor(OneAce(PlainAllowType, ObjectAndContainerInherit, FullControl, Sids.User()), AceBytes(ace)));
            var read = new DirectoryInfo(location).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            Assert.Contains(new RawSecurityDescriptor(read.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl!.Cast<GenericAce>(), a => a is CustomAce);
            using var warnings = new WarningCapture();

            using (var first = YaraXRulesCacheTestRules.Load(cache))
                Assert.False(first.FromCache, $"{ace}: an entry in a directory with a custom ACE was trusted");

            var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
            Assert.Contains($"{location} was not owner-only; restricting it to the current user and deleting its entries", warning, StringComparison.Ordinal);
            Assert.Equal(RawAcl.Normalized(RawAcl.OwnerOnlyDacl()), RawAcl.Dacl(location));
            Assert.False(File.ReadAllBytes(path).AsSpan().SequenceEqual(entryBefore), "the entry from the uncorrected directory was kept");
            using var next = YaraXRulesCacheTestRules.Load(cache);
            Assert.True(next.FromCache, "the corrected directory was not trusted on the next use");
        }
        finally
        {
            RawAcl.SetDacl(location, RawAcl.OwnerOnlyDacl());   // leave it deletable
        }
    }
    #endregion

    #region Methods: helpers
    // A cache in its own ...\rules directory inside `dir`, used exactly as the default location is.
    private static YaraXRulesCache Cache(ControlledTempDir dir) => new(dir.Combine("rules"));

    // Has the engine compile and store the test rules in `cache`, and checks the result is a real, trusted entry of ours;
    // its path.
    private static string StoredEntry(YaraXRulesCache cache)
    {
        using (var first = YaraXRulesCacheTestRules.Load(cache))
            Assert.False(first.FromCache);
        var path = YaraXRulesCacheTestRules.EntryPath(cache);
        Assert.True(File.Exists(path), "the precondition failed: no entry was stored");
        Assert.Equal(Sids.User(), RawAcl.Descriptor(path).Owner);
        return path;
    }

    // Writes `bytes` to a new file at `path` OWNED BY THE USER: an elevated token's default owner can be
    // BUILTIN\Administrators, so the owner is named explicitly (one's own SID needs no privilege; the owner's section only).
    private static void WriteUserOwned(string path, byte[] bytes)
    {
        File.WriteAllBytes(path, bytes);
        var owner = new FileSecurity();
        owner.SetOwner(Sids.User());
        new FileInfo(path).SetAccessControl(owner);
    }

    // A user-owned file holding `bytes`, created in a new directory `name` under `dir` whose DACL is `directorySddl`,
    // written through SetAccessControl (SetNamedSecurityInfo), which marks it auto-inherited: the file's copies of the
    // directory's inheritable ACEs are then marked INHERITED (ID), as under a real profile or C:\Temp. (SetFileSecurityW
    // does not, measured: no ID.) Its path.
    private static string ForgedIn(ControlledTempDir dir, string name, string directorySddl, byte[] bytes)
    {
        var directory = dir.CreateDirectory(name);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(directorySddl, AccessControlSections.Access);
        new DirectoryInfo(directory).SetAccessControl(security);
        var forged = Path.Combine(directory, "victim-owned.dat");
        WriteUserOwned(forged, bytes);
        return forged;
    }

    // Replaces our entry at `path` by `forged` (same bytes) with File.Move, which keeps its owner and DACL, and checks both
    // (and, when given, that the grant to `grantee` came along).
    private static void MoveIn(string forged, string path, byte[] valid, SecurityIdentifier? grantee = null)
    {
        var dacl = RawAcl.Dacl(forged);
        File.Delete(path);
        File.Move(forged, path);
        Assert.Equal(valid, File.ReadAllBytes(path));
        Assert.Equal(Sids.User(), RawAcl.Descriptor(path).Owner);
        Assert.Equal(dacl, RawAcl.Dacl(path));
        if (grantee is not null)
            ForeignAce(path, grantee);
    }

    // The single allow ACE for `grantee` in `path`'s raw DACL.
    private static CommonAce ForeignAce(string path, SecurityIdentifier grantee) =>
        Assert.Single(RawAcl.Descriptor(path).DiscretionaryAcl!.OfType<CommonAce>(), a => a.SecurityIdentifier == grantee && a.AceQualifier == AceQualifier.AccessAllowed);

    // TryLoad refuses the entry at `path` with exactly one warning (`why`, and that it was deleted) and it is gone; then
    // the engine recompiles (not from the cache) and stores, silently, an entry of our own (the user's ACE only), which the
    // next load trusts.
    private static void AssertRefusedDeletedAndRecompiled(YaraXRulesCache cache, string path, string why)
    {
        YaraXRules? loaded;
        string[] seen;
        using (var warnings = new WarningCapture())
        {
            loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key);
            seen = warnings.Warnings.Where(w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal)).ToArray();
        }

        using (loaded)
            Assert.True(loaded is null, "the entry was LOADED: the DACL check on the handle did not refuse it");
        Assert.Equal($"YARA-X rules cache: ignoring {path}: {why}; it was deleted. The rules will be recompiled.", Assert.Single(seen));
        Assert.False(File.Exists(path), "the refused entry was not deleted");

        AssertRecompiledAndReplacedByOurs(cache, path);
    }

    // TryLoad cannot even open the entry at `path` (the user has no read access): a miss with exactly one "could not read"
    // warning, nothing loaded; then the engine recompiles, and its store replaces the entry with one of our own.
    private static void AssertNeverReadAndReplaced(YaraXRulesCache cache, string path)
    {
        YaraXRules? loaded;
        string[] seen;
        using (var warnings = new WarningCapture())
        {
            loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key);
            seen = warnings.Warnings.Where(w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal)).ToArray();
        }

        using (loaded)
            Assert.True(loaded is null, "an entry the user cannot read was LOADED");
        var warning = Assert.Single(seen);
        Assert.StartsWith($"YARA-X rules cache: could not read {path}: UnauthorizedAccessException: ", warning, StringComparison.Ordinal);
        Assert.EndsWith(". The rules will be recompiled.", warning, StringComparison.Ordinal);

        using (var recompiled = YaraXRulesCacheTestRules.Load(cache))
            Assert.False(recompiled.FromCache);
        AssertOurs(path);
        using var next = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(next.FromCache, "the entry the store wrote over it was not trusted");
    }

    private static void AssertRecompiledAndReplacedByOurs(YaraXRulesCache cache, string path)
    {
        using (var warnings = new WarningCapture())
        {
            using (var recompiled = YaraXRulesCacheTestRules.Load(cache))
                Assert.False(recompiled.FromCache);
            Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        }
        AssertOurs(path);
        using var next = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(next.FromCache, "the rewritten entry was not trusted");
    }

    // `path` carries exactly our own shape: one plain allow ACE, the user's, full control, not inherit-only.
    private static void AssertOurs(string path)
    {
        var ace = Assert.IsType<CommonAce>(Assert.Single(RawAcl.Descriptor(path).DiscretionaryAcl!));
        Assert.True(ace is { IsCallback: false, AceQualifier: AceQualifier.AccessAllowed } && ace.SecurityIdentifier == Sids.User()
            && (ace.AccessMask & FullControl) == FullControl && (ace.AceFlags & AceFlags.InheritOnly) == 0, "the rewritten entry is not ours");
    }

    // Exactly one rules-cache warning, and it is N-1's: `location`'s ACL cannot be read, delete it.
    private static void AssertUnreadable(WarningCapture warnings, string location)
    {
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        Assert.Equal($"YARA-X rules cache: not using {location}: its permissions cannot be read (an unsupported ACE); delete it and Silvergun will recreate it.", warning);
    }

    // YaraXRulesCache.NotOwnEntryDacl (private): null for our own shape, else which part differs.
    private static string? NotOwnEntryDacl(SystemRawAcl? dacl)
    {
        var method = typeof(YaraXRulesCache).GetMethod("NotOwnEntryDacl", BindingFlags.Static | BindingFlags.NonPublic, [typeof(SystemRawAcl), typeof(SecurityIdentifier)]);
        Assert.True(method is not null, "YaraXRulesCache.NotOwnEntryDacl(RawAcl, SecurityIdentifier) is gone; this test pins the entry check through it.");
        return (string?)method!.Invoke(null, [dacl, Sids.User()]);
    }

    // The DACL of the SDDL "D:P" + `aces`, parsed by Windows (so XA and OA ACEs come out as .NET models them).
    private static SystemRawAcl Parse(string aces) => new RawSecurityDescriptor("D:P" + aces).DiscretionaryAcl!;

    // One ACE, as SDDL, for each named single-ACE shape.
    private static string SingleAceSddl(string shape)
    {
        var user = Sids.User().Value;
        return shape switch
        {
            "a deny of full control for the user" => $"(D;;FA;;;{user})",
            "full control for SYSTEM only" => "(A;;FA;;;SY)",
            "the user with read only" => $"(A;;FR;;;{user})",
            "the user with modify (no WRITE_DAC or WRITE_OWNER)" => $"(A;;0x1301bf;;;{user})",
            "the user's full control, inherit-only" => $"(A;OICIIO;FA;;;{user})",
            "a conditional allow of full control for the user, whose condition holds" => $"(XA;;FA;;;{user};(Member_of {{SID(WD)}}))",
            "an object ACE with a GUID, full control for the user" => $"(OA;;FA;{ObjectTypeGuid};;{user})",
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
        };
    }

    private static string NotOursBecause(string detail) => $"{NotOwnEntryPermissions}: {detail}";

    private static string Entries(int count) => NotOursBecause($"it has {count} permission entries, not one");

    private static SecurityIdentifier Sid(string alias) => alias switch
    {
        "WD" => Sids.Everyone,
        "AU" => Sids.AuthenticatedUsers,
        _ => throw new ArgumentOutOfRangeException(nameof(alias), alias, null),
    };

    // An ACE that is not a plain allow or deny, as raw bytes (header, then mask, then body), paired with the ACL revision it
    // needs (a compound ACE needs revision 3): a custom type (0x11 in a DACL, or 0x30, granting Everyone), a custom type
    // 0x30 of 14 bytes (not a multiple of 4), or a compound ACE as Windows defines it (type 4: compound type 1,
    // impersonation, a reserved word, then two SIDs, here Everyone twice).
    private static (byte[] Ace, byte Revision) AceBytes(string ace)
    {
        var everyone = SidBytes(Sids.Everyone);
        return ace switch
        {
            "custom type 0x11" => (RawAce(0x11, 0, 0x1, SidBytes(new SecurityIdentifier("S-1-16-4096"))), 2),
            "custom type 0x30" => (RawAce(0x30, 0, FullControl, everyone), 2),
            "an unaligned custom ACE" => (RawAce(0x30, 0, FullControl, [1, 2, 3, 4, 5, 6]), 2),
            "a compound ACE" => (RawAce(4, 0, FullControl, [1, 0, 0, 0, .. everyone, .. everyone]), 3),
            _ => throw new ArgumentOutOfRangeException(nameof(ace), ace, null),
        };
    }

    private static byte[] OneAce(byte type, byte flags, int mask, SecurityIdentifier sid) => RawAce(type, flags, mask, SidBytes(sid));

    // Two allow ACEs for the user that add up to full control: FR (0x120089), then the rest of FA (0x1F01FF & ~0x120089).
    private static string SplitFullControl()
    {
        var user = Sids.User().Value;
        return $"(A;;FR;;;{user})(A;;0x{FullControl & ~0x120089:x};;;{user})";
    }

    private static byte[] RawAce(byte type, byte flags, int mask, byte[] body)
    {
        var ace = new byte[8 + body.Length];
        ace[0] = type;
        ace[1] = flags;
        BitConverter.GetBytes((ushort)ace.Length).CopyTo(ace, 2);
        BitConverter.GetBytes(mask).CopyTo(ace, 4);
        body.CopyTo(ace, 8);
        return ace;
    }

    // A self-relative descriptor holding only a protected DACL: `first`, then the given ACE.
    private static byte[] Descriptor(byte[] first, (byte[] Ace, byte Revision) extra) => Descriptor(extra.Revision, first, extra.Ace);

    // A self-relative descriptor holding only a protected DACL with exactly the given `ace` (at its revision).
    private static byte[] SingleAceDescriptor((byte[] Ace, byte Revision) ace) => Descriptor(ace.Revision, ace.Ace);

    // A self-relative descriptor holding only a protected DACL of `aces`, in order, at ACL revision `revision`.
    private static byte[] Descriptor(byte revision, params byte[][] aces)
    {
        var body = aces.SelectMany(a => a).ToArray();
        var acl = new byte[8 + body.Length];
        acl[0] = revision;
        BitConverter.GetBytes((ushort)acl.Length).CopyTo(acl, 2);
        BitConverter.GetBytes((ushort)aces.Length).CopyTo(acl, 4);
        body.CopyTo(acl, 8);

        var descriptor = new byte[20 + acl.Length];
        descriptor[0] = 1;                                                   // revision
        BitConverter.GetBytes((ushort)(0x8000 | 0x1000 | 0x0004)).CopyTo(descriptor, 2);   // self-relative, DACL protected, DACL present
        BitConverter.GetBytes(20).CopyTo(descriptor, 16);                    // DACL offset
        acl.CopyTo(descriptor, 20);
        return descriptor;
    }

    private static byte[] SidBytes(SecurityIdentifier sid)
    {
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        return bytes;
    }
    #endregion

    #region Fields
    // The refusal, as YaraXRulesCache words it (ADR 0033 amendment of 2026-10-22), and the detail naming what differs.
    private const string NotOwnEntryPermissions = "its permissions are not the ones Silvergun gives its own entries (a single full-control entry for you)";
    private const string NullDaclDetail = "it has no access control list (a null DACL, which lets anyone do anything)";
    private const string NotEvaluatedDetail = "its one permission entry is of a kind Silvergun does not evaluate (not a plain allow or deny)";
    private const string NotFullControlDetail = "its one permission entry is not an allow entry giving you full control of the file";

    // The rights tokens of the moved-in grants, as SDDL hex masks.
    private const string WriteData = "0x2";
    private const string AppendData = "0x4";
    private const string Delete = "0x10000";
    private const string WriteDac = "0x40000";
    private const string WriteOwner = "0x80000";

    private const byte PlainAllowType = 0;
    private const byte ObjectAndContainerInherit = 0x03;
    private const int FullControl = 0x1F01FF;

    // Any GUID will do: what matters is that the object ACE carries one (without it, NTFS stores a plain allow ACE).
    private const string ObjectTypeGuid = "bf967aba-0de6-11d0-a285-00aa003049e2";
    #endregion
}
#endif
