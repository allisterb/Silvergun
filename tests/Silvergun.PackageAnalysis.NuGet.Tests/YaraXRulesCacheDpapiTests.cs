#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;

using Entry = YaraXRulesCacheEntryV3;

/// <summary>
/// The DPAPI binding of rules-cache entries, format v3 (task <c>yarax-worker.md</c>, "DPAPI entry binding", user decision
/// (i) of 2026-10-23; ADR 0033 amendment, "Finding"). <c>yrx_rules_deserialize</c> can load precompiled native code from
/// a blob that carries it, so no byte of an entry may reach <see cref="YaraXRules.Deserialize"/> until this user's DPAPI
/// has vouched for the entry's exact body: <c>CryptUnprotectData</c> of the entry's blob, with this format's and engine's
/// entropy, must give exactly the body's sha256, and the blob must be a CurrentUser one (review C1): a machine-scope blob,
/// which any local user can make and raw DPAPI unprotects for everyone, is refused as not this user's.
///
/// <para><b>Order</b>, as <c>YaraXRulesCache.TryLoad</c> runs it after the location, owner and DACL checks and the bounded
/// read: the previous format (<c>SGYXRC02</c>) is a silent miss; then the magic; then P, the blob's length, which is
/// bounded BEFORE any DPAPI call; then DPAPI; then the hash; and only then the key, the canary, the rule count and
/// <c>Deserialize</c>. Every refusal is a miss with exactly one warning, the rules are recompiled, and the store that
/// follows writes an entry the next load trusts.</para>
///
/// <para><b>How "never reaches Deserialize" is shown.</b> There is no seam in <c>src</c> that counts or intercepts
/// <c>Deserialize</c>, so it is shown indirectly: each alteration of the body would, without the DPAPI check, produce a
/// DIFFERENT outcome — a load (Deserialize reached and accepted it), or a warning from a later check (other sources,
/// Deserialize's own failure, the rule count) — and the test asserts that the one warning is the DPAPI binding's own. The
/// "another compile of the same sources" row is a body every later check accepts, so without the binding it LOADS: that
/// row is the direct evidence that the binding, and nothing after it, is what keeps a body from Deserialize. The
/// red-proof that removes the DPAPI check turns every row red.</para>
///
/// <para>Every directory is a <see cref="ControlledTempDir"/> (under <c>C:\Temp</c>, protected: the user, LocalSystem and
/// Administrators only). The tests run as the user, so they can bind a body with DPAPI exactly as <c>Store</c> does
/// (<see cref="YaraXRulesCacheEntryV3.Rebound"/>).</para>
/// </summary>
public sealed class YaraXRulesCacheDpapiTests
{
    #region Methods: the round trip
    [Fact]
    public void Store_WritesAV3EntryDpapiVouchesFor_AndTheNextLoadHitsIt()
    {
        using var dir = new ControlledTempDir("dpapi-roundtrip");
        var cache = Cache(dir);
        using var rules = YaraXRulesCacheTestRules.Compile();
        var serialized = rules.Serialize(out var failure);
        Assert.True(serialized is not null, failure);

        Assert.True(cache.Store(rules), "the store failed");

        var entry = File.ReadAllBytes(YaraXRulesCacheTestRules.EntryPath(cache));
        Assert.Equal("SGYXRC03", Encoding.ASCII.GetString(entry, 0, 8));
        Assert.InRange(Entry.P(entry), 1, 1024);
        Entry.AssertVouched(entry, YaraXRulesCacheTestRules.Key);
        var body = Entry.Body(entry);
        Assert.Equal(rules.Canary.IdBytes(), body[Entry.CanaryIdOffset..Entry.MarkerOffset]);
        Assert.Equal(rules.Canary.Marker.ToArray(), body[Entry.MarkerOffset..Entry.RuleCountOffset]);
        Assert.Equal(rules.RuleCount, BinaryPrimitives.ReadInt32LittleEndian(body.AsSpan(Entry.RuleCountOffset, 4)));
        Assert.Equal(serialized, body[Entry.BodyHeaderBytes..]);

        using (var warnings = new WarningCapture())
        {
            using var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key);
            Assert.True(loaded is not null, "the entry just stored was not loaded");
            Assert.Equal(rules.RuleCount, loaded!.RuleCount);
            using var scanner = loaded.CreateScanner(5);
            Assert.Null(scanner.CheckCanary());
            Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        }
        using var viaEngine = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(viaEngine.FromCache, "the engine did not take the stored entry from the cache");
    }

    // The control for every forged entry below: the body of a real entry, bound again by this test exactly as Store binds
    // one (sha256, DPAPI, this format's entropy), loads. A refusal of a forged entry is therefore its forgery's doing, not
    // the forging helper's. (DPAPI blobs are randomised: the new blob differs from the stored one, and still vouches.)
    [Fact]
    public void ABodyBoundAgainWithThisFormatsEntropy_IsVouchedFor_AndLoads()
    {
        using var dir = new ControlledTempDir("dpapi-control");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var original = File.ReadAllBytes(path);
        var rebound = Entry.Rebound(original);
        Assert.False(Entry.Blob(rebound).AsSpan().SequenceEqual(Entry.Blob(original)), "the precondition failed: DPAPI made the same blob twice");
        Assert.Equal(Entry.Body(original), Entry.Body(rebound));
        File.WriteAllBytes(path, rebound);

        using var warnings = new WarningCapture();
        using var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key);

        Assert.True(loaded is not null, "a body bound with this format's entropy was refused: the forging helper does not bind as Store does");
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: P is bounded before any DPAPI call
    // P outside [1, 1024], or a blob that would leave less than the body's 84-byte header, is invalid with its own message,
    // which only the bounds check gives: DPAPI is never called for it (no seam counts the calls; a call would give "DPAPI
    // did not vouch", or the slice would throw: "could not read"). The rest of the entry is random bytes.
    public static TheoryData<string, int, int> ProtectedLengthsOutOfRange() => new()
    {
        { "zero", 0, 2000 },
        { "negative", -1, 2000 },
        { "1025, one more than the bound", 1025, 2000 },
        { "int.MaxValue", int.MaxValue, 2000 },
        { "past the end of the entry", 1000, 212 },
        { "leaving the body one byte short of its header", 212 - 12 - 84 + 1, 212 },
    };

    [Theory]
    [MemberData(nameof(ProtectedLengthsOutOfRange))]
    public void AnOutOfRangeP_IsInvalid_WithoutADpapiCall_AndRecompiled(string what, int p, int entryBytes)
    {
        using var dir = new ControlledTempDir("dpapi-p");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        File.WriteAllBytes(path, Garbage(p, entryBytes));

        AssertRefusedThenReplaced(cache, path, $"its DPAPI blob length ({p}) is out of range", what);
    }

    // The bounds are inclusive and no tighter than the format's: P = 1, P = 1024, and a blob that leaves exactly the body
    // header, over random bytes, pass them and reach DPAPI, which does not vouch.
    public static TheoryData<string, int, int> ProtectedLengthsInRange() => new()
    {
        { "one", 1, 2000 },
        { "1024, the bound", 1024, 2000 },
        { "leaving exactly the body header", 212 - 12 - 84, 212 },
    };

    [Theory]
    [MemberData(nameof(ProtectedLengthsInRange))]
    public void AnInRangeP_OverRandomBytes_ReachesDpapi_WhichDoesNotVouch(string what, int p, int entryBytes)
    {
        using var dir = new ControlledTempDir("dpapi-p-in");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        File.WriteAllBytes(path, Garbage(p, entryBytes));

        AssertRefusedThenReplaced(cache, path, DidNotVouchPrefix, what, prefixOnly: true);
    }
    #endregion

    #region Methods: what DPAPI vouches for
    // A body bound by this very user, but with another entropy: another engine version (what a cache entry of a different
    // yara-x build would carry), no entropy at all, an older wording ("v2|", and "v3|", the wording before N3 derived the
    // entropy from the magic), the previous format's magic, or this format's prefix with no version. DPAPI itself refuses
    // each. (The stored entry is not checked against this format's entropy first, so that a cache that used the wrong
    // entropy fails HERE, by loading the "" row, rather than at that precondition; the round trip and
    // TheEntropy_IsDerivedFromTheMagic pin the entropy itself.)
    public static TheoryData<string> OtherEntropies() => new(
        "Silvergun YARA-X rules cache v3|9.9.9",
        "",
        "Silvergun YARA-X rules cache v2|" + YaraXNative.EngineVersion,
        "Silvergun YARA-X rules cache v3|",
        "Silvergun YARA-X rules cache v3|" + YaraXNative.EngineVersion,
        "Silvergun YARA-X rules cache SGYXRC02|" + YaraXNative.EngineVersion,
        "Silvergun YARA-X rules cache SGYXRC03|");

    [Theory]
    [MemberData(nameof(OtherEntropies))]
    public void ABodyBoundWithAnotherEntropy_IsNotVouchedFor_AndRecompiled(string entropy)
    {
        using var dir = new ControlledTempDir("dpapi-entropy");
        var cache = Cache(dir);
        var path = StoredEntry(cache, assertVouched: false);
        var other = Encoding.ASCII.GetBytes(entropy);
        var forged = Entry.Rebound(File.ReadAllBytes(path), entropy: other);
        var payload = WindowsSecurityNative.Unprotect(Entry.Blob(forged), other, out var failure);   // the precondition: really bound, with that entropy
        Assert.True(payload is not null && payload.AsSpan().SequenceEqual(SHA256.HashData(Entry.Body(forged))), $"the precondition failed: {failure}");
        File.WriteAllBytes(path, forged);

        AssertRefusedThenReplaced(cache, path, DidNotVouchPrefix, $"entropy '{entropy}'", prefixOnly: true);
    }

    // Two real entries, for two rule-source sets: the blob of A (which vouches for A's body) with the body of B (vouched for
    // by B's blob) is refused, under A's name: DPAPI vouches for a hash, and it is not this body's.
    [Fact]
    public void TheBlobOfOneEntryWithTheBodyOfAnother_IsRefused_AndRecompiled()
    {
        using var dir = new ControlledTempDir("dpapi-swap");
        var cache = Cache(dir);
        var pathA = StoredEntry(cache);
        using var other = YaraX.Compile("rule dpapi_other_set { condition: false }");
        Assert.True(cache.Store(other), "the second entry could not be stored");
        var a = File.ReadAllBytes(pathA);
        var b = File.ReadAllBytes(cache.EntryPath(other.SourcesSha256)!);
        Entry.AssertVouched(b, other.SourcesSha256);   // the precondition: B is a real entry too
        File.WriteAllBytes(pathA, Entry.Build(Entry.Blob(a), Entry.Body(b)));

        AssertRefusedThenReplaced(cache, pathA, BodyMismatch, "A's blob, B's body");
    }

    // ADR 0033 amendment, "Finding": an entry DPAPI does not vouch for must never reach yrx_rules_deserialize. A real entry
    // with its body altered anywhere (its blob untouched) is refused by the binding, and by the binding ALONE: the one
    // warning is its own, never a later check's. The last row is a body every later check accepts (the body of another
    // compile of the same sources: same key, its own consistent canary, count and rules), so it is the row that would LOAD
    // without the binding. See the class remarks for why this is the evidence, and the red-proof that removes the check.
    public static TheoryData<string> BodyAlterations() => new(
        "sources field", "canary id", "canary marker", "rule count", "first serialized-rules byte", "middle serialized-rules byte",
        "last serialized-rules byte", "an appended byte", "the last byte removed", "the body of another compile of the same sources");

    [Theory]
    [MemberData(nameof(BodyAlterations))]
    public void ABodyAlteredAnywhere_IsRefusedByTheDpapiBindingAlone_SoItNeverReachesDeserialize(string alteration)
    {
        using var dir = new ControlledTempDir("dpapi-guard");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var original = File.ReadAllBytes(path);
        var body = Entry.Body(original);
        var rules = Entry.BodyHeaderBytes;
        byte[] altered = alteration switch
        {
            "sources field" => Flip(body, Entry.SourcesOffset + 7),
            "canary id" => Flip(body, Entry.CanaryIdOffset + 3),
            "canary marker" => Flip(body, Entry.MarkerOffset + 21),
            "rule count" => Flip(body, Entry.RuleCountOffset),
            "first serialized-rules byte" => Flip(body, rules),
            "middle serialized-rules byte" => Flip(body, rules + (body.Length - rules) / 2),
            "last serialized-rules byte" => Flip(body, body.Length - 1),
            "an appended byte" => [.. body, 0x00],
            "the last byte removed" => body[..^1],
            "the body of another compile of the same sources" => AnotherCompilesBody(dir),
            _ => throw new ArgumentOutOfRangeException(nameof(alteration), alteration, null),
        };
        Assert.False(altered.AsSpan().SequenceEqual(body), "the precondition failed: the body was not altered");
        File.WriteAllBytes(path, Entry.Build(Entry.Blob(original), altered));

        AssertRefusedThenReplaced(cache, path, BodyMismatch, alteration);
    }
    #endregion

    #region Methods: the blob must be this user's (review C1)
    // C1: CryptUnprotectData takes its key from the blob, so a machine-scope blob (CRYPTPROTECT_LOCAL_MACHINE), which ANY
    // local user can make with the cache's public entropy, unprotects for every user. Here it is the forgery itself: an
    // otherwise valid entry (the real body, the real entropy) whose blob is CryptProtectData(sha256(body), entropy,
    // UI_FORBIDDEN | LOCAL_MACHINE). The precondition is what makes the row discriminate: raw DPAPI unprotects it, for this
    // user, to exactly the body's hash, so every check but the scope check would pass it, and without that check it LOADS
    // (red-proof). It must be refused as not this user's, recompiled, and replaced by a user-scope entry.
    [Fact]
    public void AMachineScopeBlobOverTheRealBody_WithTheRealEntropy_IsRefusedAsNotThisUsers_AndRecompiled()
    {
        using var dir = new ControlledTempDir("dpapi-machine");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var body = Entry.Body(File.ReadAllBytes(path));
        var hash = SHA256.HashData(body);
        var machine = RawDpapi.Protect(hash, Entry.Entropy(), RawDpapi.UiForbidden | RawDpapi.LocalMachine);
        var (payload, error) = RawDpapi.Unprotect(machine, Entry.Entropy());
        Assert.True(payload is not null && payload.AsSpan().SequenceEqual(hash),
            $"the precondition failed: raw CryptUnprotectData does not unprotect the machine-scope blob to the body's hash (error 0x{error:x8}), so this row does not discriminate");
        Assert.True((RawDpapi.Flags(machine) & RawDpapi.LocalMachine) != 0, "the precondition failed: the blob is not flagged machine-scope");
        File.WriteAllBytes(path, Entry.Build(machine, body));

        AssertRefusedThenReplaced(cache, path, NotThisUsers + WindowsSecurityNative.NotUserScope, "a machine-scope blob");
        Assert.Equal(0u, RawDpapi.Flags(Entry.Blob(File.ReadAllBytes(path))) & RawDpapi.LocalMachine);   // rewritten user-scope
    }

    // The control for the forgery above: the same body, bound raw with the flags Store uses (UI_FORBIDDEN, user scope),
    // loads. So the refusal above is the machine scope's doing, not the raw helper's.
    [Fact]
    public void AUserScopeBlobMadeRaw_OverTheRealBody_Loads_TheControlForTheMachineScopeForgery()
    {
        using var dir = new ControlledTempDir("dpapi-user-raw");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var body = Entry.Body(File.ReadAllBytes(path));
        File.WriteAllBytes(path, Entry.Build(RawDpapi.Protect(SHA256.HashData(body), Entry.Entropy(), RawDpapi.UiForbidden), body));

        using var warnings = new WarningCapture();
        using (var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key))
            Assert.True(loaded is not null, "a user-scope blob made raw with Store's flags was refused: the raw helper does not bind as Store does");
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: the entropy (N3)
    // N3: the entropy is derived from the magic, "Silvergun YARA-X rules cache " + Magic + "|" + engine version, so a format
    // bump changes it and a blob made for another format does not unprotect. Read from the product (private, by
    // reflection) and compared with the spelling written out here, and with the derivation from the product's own Magic.
    // (A literal that happens to equal today's derivation cannot be told apart from it; one unrelated to Magic can.)
    [Fact]
    public void TheEntropy_IsDerivedFromTheMagic_AndTheEngineVersion()
    {
        const BindingFlags flags = BindingFlags.Static | BindingFlags.NonPublic;
        var entropy = typeof(YaraXRulesCache).GetField("Entropy", flags)?.GetValue(null) as byte[]
            ?? throw new InvalidOperationException("YaraXRulesCache.Entropy (a private static byte[]) was not found");
        var magic = typeof(YaraXRulesCache).GetField("Magic", flags)?.GetRawConstantValue() as string
            ?? throw new InvalidOperationException("YaraXRulesCache.Magic (a private const string) was not found");

        Assert.Equal(Entry.Magic, magic);
        Assert.Equal("Silvergun YARA-X rules cache SGYXRC03|" + YaraXNative.EngineVersion, Encoding.ASCII.GetString(entropy));
        Assert.Equal(Encoding.ASCII.GetBytes($"Silvergun YARA-X rules cache {magic}|{YaraXNative.EngineVersion}"), entropy);
        Assert.Equal(Entry.Entropy(), entropy);   // and the forging helper binds with exactly it
    }
    #endregion

    #region Methods: the previous format
    // An upgrade must not warn: an entry of the previous format is a silent miss (one Debug line, no warning at all), the
    // rules are recompiled, and the store overwrites it with a v3 entry the next load trusts. Both a well-formed SGYXRC02
    // entry (exactly what a v2 build wrote) and a v3 entry whose magic's last bit flipped (SGYXRC03 -> SGYXRC02: by design
    // the same silent miss, which is why the damage tests flip another byte of the magic).
    [Theory]
    [InlineData("a well-formed v2 entry")]
    [InlineData("a v3 entry whose magic's last bit flipped")]
    public void AnEntryOfThePreviousFormat_IsASilentMiss_ThenRecompiled_AndOverwrittenWithV3(string shape)
    {
        using var dir = new ControlledTempDir("dpapi-v2");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var v3 = File.ReadAllBytes(path);
        var previous = shape == "a well-formed v2 entry" ? Entry.AsV2(v3) : Flip(v3, 7);
        Assert.Equal("SGYXRC02", Encoding.ASCII.GetString(previous, 0, 8));   // the precondition
        File.WriteAllBytes(path, previous);

        using (var capture = new WarningCapture())
        {
            using (var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key))
                Assert.True(loaded is null, $"{shape}: an entry of the previous format was loaded");
            Assert.Empty(capture.Warnings);
            Assert.Equal($"YARA-X rules cache: {path} is in the previous format (SGYXRC02); the next store replaces it.",
                Assert.Single(capture.Debugs, d => d.Contains("YARA-X rules cache:", StringComparison.Ordinal)));
        }

        AssertRecompiledAndReplaced(cache, path);
    }
    #endregion

    #region Methods: a measured DPAPI property
    // NOT a rule of ours: a measured property of DPAPI, pinned so that a change in it becomes visible (task yarax-worker.md,
    // "DPAPI implementation (2026-10-23)"). DPAPI does not authenticate blob offsets 4..19 (the provider GUID; entry offsets
    // 16..31): a bit flipped there still unprotects, to the IDENTICAL payload, so the entry still loads with its body
    // unchanged. That forges nothing (the body binding holds) and the cache deliberately does not pin the GUID. Offsets 3 and
    // 20, just outside, are refused, as is every other offset (measured; the damage tests flip one).
    [Fact]
    public void MeasuredDpapiProperty_ABitFlippedInTheBlobsProviderGuid_StillUnprotects_AndTheEntryLoadsWithItsBodyUnchanged()
    {
        using var dir = new ControlledTempDir("dpapi-guid");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var original = File.ReadAllBytes(path);
        var hash = SHA256.HashData(Entry.Body(original));

        for (var offset = Entry.UnauthenticatedBlobFrom; offset <= Entry.UnauthenticatedBlobTo; offset++)
        {
            var flipped = Flip(original, Entry.ProtectedOffset + offset);
            var payload = WindowsSecurityNative.Unprotect(Entry.Blob(flipped), Entry.Entropy(), out var failure);
            Assert.True(payload is not null, $"blob offset {offset} (entry {Entry.ProtectedOffset + offset}): DPAPI now refuses a flipped provider-GUID bit ({failure}). The measured property changed.");
            Assert.True(payload!.AsSpan().SequenceEqual(hash), $"blob offset {offset}: DPAPI returned a different payload");
            File.WriteAllBytes(path, flipped);

            using var warnings = new WarningCapture();
            using (var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key))
                Assert.True(loaded is not null, $"blob offset {offset}: the entry was refused");
            Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
            Assert.Equal(Entry.Body(original), Entry.Body(File.ReadAllBytes(path)));
        }

        foreach (var offset in new[] { Entry.UnauthenticatedBlobFrom - 1, Entry.UnauthenticatedBlobTo + 1 })
            Assert.True(WindowsSecurityNative.Unprotect(Entry.Blob(Flip(original, Entry.ProtectedOffset + offset)), Entry.Entropy(), out _) is null,
                $"blob offset {offset}, just outside the provider GUID, now unprotects with a bit flipped. The measured property changed.");
    }

    // NOT a rule of ours: a measured property of DPAPI, pinned so that a change in it becomes visible (review N2,
    // 2026-10-23). CryptUnprotectData ignores bytes after the blob's own end, so an entry whose P covers the blob plus 4
    // junk bytes still unprotects, to the IDENTICAL payload, and (its body intact, right after P) still loads. That forges
    // nothing: the body is still exactly the one DPAPI vouches for. The cache deliberately does not require P to be the
    // blob's exact length (that would mean parsing DPAPI's undocumented layout further).
    [Fact]
    public void MeasuredDpapiProperty_JunkAfterTheBlobInsideP_IsIgnoredByDpapi_AndTheEntryLoadsWithItsBodyVouched()
    {
        using var dir = new ControlledTempDir("dpapi-trailing");
        var cache = Cache(dir);
        var path = StoredEntry(cache);
        var original = File.ReadAllBytes(path);
        var body = Entry.Body(original);
        byte[] padded = [.. Entry.Blob(original), 0xA5, 0x5A, 0xC3, 0x3C];
        var payload = WindowsSecurityNative.Unprotect(padded, Entry.Entropy(), out var failure);
        Assert.True(payload is not null, $"DPAPI now refuses a blob followed by 4 junk bytes ({failure}). The measured property changed.");
        Assert.True(payload!.AsSpan().SequenceEqual(SHA256.HashData(body)), "DPAPI returned a different payload for the blob with trailing junk");
        var entry = Entry.Build(padded, body);
        Assert.Equal(Entry.P(original) + 4, Entry.P(entry));
        File.WriteAllBytes(path, entry);

        using var warnings = new WarningCapture();
        using (var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key))
            Assert.True(loaded is not null, "an entry whose P covers its blob plus 4 junk bytes was refused");
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal));
        Assert.Equal(body, Entry.Body(File.ReadAllBytes(path)));
    }
    #endregion

    #region Methods: helpers
    private static YaraXRulesCache Cache(ControlledTempDir dir) => new(dir.Combine("rules"));

    // The engine compiles and stores the test rules in `cache` (in an owner-only directory, so the entry carries our own
    // DACL and any bytes later written to it keep it); a real v3 entry DPAPI vouches for (asserted unless `assertVouched`
    // is false). Its path.
    private static string StoredEntry(YaraXRulesCache cache, bool assertVouched = true)
    {
        using (var first = YaraXRulesCacheTestRules.Load(cache))
            Assert.False(first.FromCache);
        var path = YaraXRulesCacheTestRules.EntryPath(cache);
        Assert.True(File.Exists(path), "the precondition failed: no entry was stored");
        if (assertVouched)
            Entry.AssertVouched(File.ReadAllBytes(path), YaraXRulesCacheTestRules.Key);
        return path;
    }

    // The body of an entry for the same sources, from a second compile (its own canary) stored in a separate cache: a body
    // every check after DPAPI accepts. The precondition shows it: that entry loads, from its own cache.
    private static byte[] AnotherCompilesBody(ControlledTempDir dir)
    {
        var donor = new YaraXRulesCache(dir.Combine("donor"));
        using var rules = YaraXRulesCacheTestRules.Compile();
        Assert.True(donor.Store(rules), "the donor entry could not be stored");
        using (var loaded = donor.TryLoad(YaraXRulesCacheTestRules.Key))
            Assert.True(loaded is not null, "the precondition failed: the donor entry does not load from its own cache");
        return Entry.Body(File.ReadAllBytes(YaraXRulesCacheTestRules.EntryPath(donor)));
    }

    // A copy of `bytes` with the low bit of [index] flipped.
    private static byte[] Flip(byte[] bytes, int index)
    {
        var copy = bytes.ToArray();
        copy[index] ^= 0x01;
        return copy;
    }

    // An `entryBytes`-byte v3 "entry": the magic, P = `p`, then random bytes.
    private static byte[] Garbage(int p, int entryBytes)
    {
        var entry = RandomNumberGenerator.GetBytes(entryBytes);
        Encoding.ASCII.GetBytes(Entry.Magic, entry.AsSpan(0, Entry.MagicBytes));
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(Entry.ProtectedLengthOffset, 4), p);
        return entry;
    }

    // TryLoad refuses the entry at `path` with exactly one rules-cache warning, which gives `why` (exactly, or as its start
    // when `prefixOnly`); then the engine recompiles, silently, and its store writes an entry the next load trusts.
    private static void AssertRefusedThenReplaced(YaraXRulesCache cache, string path, string why, string row, bool prefixOnly = false)
    {
        string[] seen;
        using (var warnings = new WarningCapture())
        {
            using (var loaded = cache.TryLoad(YaraXRulesCacheTestRules.Key))
                Assert.True(loaded is null, $"{row}: the entry was LOADED");
            seen = warnings.Warnings.Where(w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal)).ToArray();
        }

        Assert.True(seen.Length == 1, $"{row}: expected one rules-cache warning, saw {seen.Length}: {string.Join(" | ", seen)}");
        var expected = $"YARA-X rules cache: ignoring {path}: {why}";
        if (prefixOnly)
        {
            Assert.StartsWith(expected, seen[0], StringComparison.Ordinal);
            Assert.EndsWith(". The rules will be recompiled.", seen[0], StringComparison.Ordinal);
        }
        else
            Assert.Equal(expected + ". The rules will be recompiled.", seen[0]);

        AssertRecompiledAndReplaced(cache, path, seen[0]);
    }

    // The engine's own load misses too (an entry that is refused but not deleted is refused again: `refusal`, the same one
    // warning; a silent miss stays silent when `refusal` is null), compiles, and its store writes an entry DPAPI vouches
    // for, which the next load trusts.
    private static void AssertRecompiledAndReplaced(YaraXRulesCache cache, string path, string? refusal = null)
    {
        using (var warnings = new WarningCapture())
        {
            using (var recompiled = YaraXRulesCacheTestRules.Load(cache))
                Assert.False(recompiled.FromCache, "the refused entry was used");
            var seen = warnings.Warnings.Where(w => w.Contains("YARA-X rules cache:", StringComparison.Ordinal)).ToArray();
            string[] expected = refusal is null ? [] : [refusal];
            Assert.Equal(expected, seen);
        }
        Entry.AssertVouched(File.ReadAllBytes(path), YaraXRulesCacheTestRules.Key);
        using var next = YaraXRulesCacheTestRules.Load(cache);
        Assert.True(next.FromCache, "the entry the store wrote was not trusted");
    }
    #endregion

    #region Fields
    // The refusals, as YaraXRulesCache words them.
    private const string DidNotVouchPrefix = "DPAPI did not vouch for it (";
    private const string NotThisUsers = "DPAPI did not vouch for it as this user's: ";
    private const string BodyMismatch = "its body does not match the hash DPAPI vouches for (corrupt, or not written by Silvergun for you)";
    #endregion
}
#endif
