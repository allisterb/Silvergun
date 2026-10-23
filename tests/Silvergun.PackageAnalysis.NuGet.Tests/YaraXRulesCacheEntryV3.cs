#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// The rules-cache entry, format v3, as the tests read and forge it (task <c>yarax-worker.md</c>, "DPAPI entry binding";
/// the layout from <c>YaraXRulesCache</c>'s class doc). Written out here, not read from the product's private constants,
/// so a layout change in <c>src</c> shows up as a red test rather than moving the tests along with it.
/// <code>
///   0     8  magic "SGYXRC03"
///   8     4  P, the DPAPI blob's length (int32 LE), 1 &lt;= P &lt;= 1024
///  12     P  the DPAPI blob: CryptProtectData(sha256(body), entropy "Silvergun YARA-X rules cache SGYXRC03|" + engine
///            version), a CurrentUser (user-scope) blob: a machine-scope one is refused (review C1)
///  12+P   …  the body: sources sha256 (32) | canary id (16) | canary marker (32) | rule count (int32 LE) | serialized rules
/// </code>
/// The tests run as the user whose DPAPI the cache uses, so they can bind a body exactly as <c>Store</c> does
/// (<see cref="Rebound"/>): that is how an entry that DPAPI vouches for but that must still fail a LATER check (the
/// canary, the rule count) is staged.
/// </summary>
internal static class YaraXRulesCacheEntryV3
{
    #region Methods
    /// <summary>The DPAPI entropy of format v3 for <paramref name="engineVersion"/> (default: this build's engine).</summary>
    internal static byte[] Entropy(string engineVersion = YaraXNative.EngineVersion) => Encoding.ASCII.GetBytes(EntropyPrefix + engineVersion);

    /// <summary>The entry's P field (unchecked).</summary>
    internal static int P(byte[] entry) => BinaryPrimitives.ReadInt32LittleEndian(entry.AsSpan(ProtectedLengthOffset, sizeof(int)));

    /// <summary>Where the body starts in a well-formed entry.</summary>
    internal static int BodyOffset(byte[] entry) => ProtectedOffset + P(entry);

    /// <summary>A copy of the entry's DPAPI blob.</summary>
    internal static byte[] Blob(byte[] entry) => entry.AsSpan(ProtectedOffset, P(entry)).ToArray();

    /// <summary>A copy of the entry's body.</summary>
    internal static byte[] Body(byte[] entry) => entry.AsSpan(BodyOffset(entry)).ToArray();

    /// <summary>An entry of <paramref name="magic"/>, with <paramref name="blob"/> (and its length as P) and <paramref name="body"/>.</summary>
    internal static byte[] Build(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> body, string magic = Magic)
    {
        var entry = new byte[ProtectedOffset + blob.Length + body.Length];
        Encoding.ASCII.GetBytes(magic, entry.AsSpan(0, MagicBytes));
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(ProtectedLengthOffset, sizeof(int)), blob.Length);
        blob.CopyTo(entry.AsSpan(ProtectedOffset));
        body.CopyTo(entry.AsSpan(ProtectedOffset + blob.Length));
        return entry;
    }

    /// <summary>The DPAPI blob <c>Store</c> would make for <paramref name="body"/>, protected with <paramref name="entropy"/>.</summary>
    internal static byte[] Bind(ReadOnlySpan<byte> body, byte[] entropy)
    {
        var blob = WindowsSecurityNative.Protect(SHA256.HashData(body), entropy, out var failure);
        Assert.True(blob is not null, $"the test could not DPAPI-protect a body: {failure}");
        return blob!;
    }

    /// <summary>
    /// <paramref name="entry"/> with its body changed by <paramref name="edit"/> and then bound again, as <c>Store</c>
    /// binds one (sha256 of the new body, DPAPI, with <paramref name="entropy"/>, default this format's).
    /// </summary>
    internal static byte[] Rebound(byte[] entry, Action<byte[]>? edit = null, byte[]? entropy = null)
    {
        var body = Body(entry);
        edit?.Invoke(body);
        return Build(Bind(body, entropy ?? Entropy()), body);
    }

    /// <summary>
    /// Asserts <paramref name="entry"/> is a v3 entry whose body this user's DPAPI vouches for with this format's entropy
    /// (P in range, the unprotected payload is exactly the body's sha256), and is for <paramref name="key"/>.
    /// </summary>
    internal static void AssertVouched(byte[] entry, string key)
    {
        Assert.True(entry.Length >= MinEntryBytes, $"the entry is {entry.Length} bytes, less than the {MinEntryBytes} of the smallest one");
        Assert.Equal(Magic, Encoding.ASCII.GetString(entry, 0, MagicBytes));
        Assert.InRange(P(entry), 1, MaxProtectedBytes);
        Assert.True(entry.Length >= BodyOffset(entry) + BodyHeaderBytes, "the entry's body is shorter than its header");
        var payload = WindowsSecurityNative.Unprotect(Blob(entry), Entropy(), out var failure);
        Assert.True(payload is not null, $"DPAPI does not vouch for the entry: {failure}");
        Assert.True(payload!.AsSpan().SequenceEqual(SHA256.HashData(Body(entry))), "the DPAPI payload is not the sha256 of the entry's body");
        Assert.Equal(key, Convert.ToHexStringLower(Body(entry).AsSpan(SourcesOffset, 32)));
    }

    /// <summary>
    /// A well-formed entry of the PREVIOUS format, <c>SGYXRC02</c>, for <paramref name="v3"/>'s body: magic | sha256 of
    /// the rest (32) | the body. Exactly what a v2 build wrote, so only its format makes it a miss.
    /// </summary>
    internal static byte[] AsV2(byte[] v3)
    {
        var body = Body(v3);
        return [.. Encoding.ASCII.GetBytes(PreviousMagic), .. SHA256.HashData(body), .. body];
    }
    #endregion

    #region Fields
    internal const string Magic = "SGYXRC03";
    internal const string PreviousMagic = "SGYXRC02";
    // N3 (2026-10-23): "Silvergun YARA-X rules cache " + the magic + "|", so a format bump changes the entropy. Spelled out
    // here, not built from Magic, so a change in the product's derivation turns a test red.
    internal const string EntropyPrefix = "Silvergun YARA-X rules cache SGYXRC03|";
    internal const int MagicBytes = 8;
    internal const int ProtectedLengthOffset = 8;
    internal const int ProtectedOffset = 12;
    internal const int MaxProtectedBytes = 1024;

    // Body offsets, from the body's start.
    internal const int SourcesOffset = 0;
    internal const int CanaryIdOffset = 32;
    internal const int MarkerOffset = 48;
    internal const int RuleCountOffset = 80;
    internal const int BodyHeaderBytes = 84;

    /// <summary>The smallest entry a load reads: magic, P, a one-byte blob and a body header.</summary>
    internal const int MinEntryBytes = ProtectedOffset + 1 + BodyHeaderBytes;

    /// <summary>
    /// Measured (implementer, 2026-10-23): the blob offsets DPAPI does not authenticate (its provider GUID). A bit flipped
    /// there still unprotects, to the identical payload; every other offset is refused.
    /// </summary>
    internal const int UnauthenticatedBlobFrom = 4;
    internal const int UnauthenticatedBlobTo = 19;
    #endregion
}
#endif
