#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Security.Cryptography;

/// <summary>
/// The worker protocol v1 canary (<c>docs/agent/tasks/yarax-worker.md</c>; the same pattern as ADR 0032's coverage
/// sentinel): one rule, <see cref="Prefix"/> + 128 random bits as hex, compiled INTO the real ruleset, whose only
/// condition is a random 32-byte <see cref="Marker"/> generated with it. Scanning the marker and seeing that exact rule
/// hit proves the real compiled rules object scans. It is never malware-matching content, and it is stripped from every
/// result by exact name (<see cref="Strip"/>).
/// </summary>
internal sealed class YaraXCanary
{
    #region Constructors
    private YaraXCanary(string id, byte[] marker) => (Id, this.marker) = (id, marker);
    #endregion

    #region Properties
    /// <summary>The 32 lower-case hex characters (128 bits) after <see cref="Prefix"/>.</summary>
    internal string Id { get; }

    /// <summary>The canary rule's exact identifier.</summary>
    internal string RuleName => Prefix + Id;

    /// <summary>The 32 bytes the canary rule matches.</summary>
    internal ReadOnlySpan<byte> Marker => marker;

    /// <summary>The canary rule's YARA source, appended after the embedded rules, in the default namespace.</summary>
    internal string RuleSource =>
        $"// Silvergun worker canary (ADR 0033): proves the compiled rules scan; never a finding.\nrule {RuleName} {{ strings: $marker = {{ {Convert.ToHexString(marker)} }} condition: $marker }}\n";
    #endregion

    #region Methods
    /// <summary>A fresh canary: 128 random bits of name and 32 random bytes of marker.</summary>
    internal static YaraXCanary Create() =>
        new(RandomNumberGenerator.GetHexString(IdHexChars, lowercase: true), RandomNumberGenerator.GetBytes(MarkerBytes));

    /// <summary>A canary read back from the rules cache; <c>null</c> unless both parts have exactly the generated shape.</summary>
    internal static YaraXCanary? From(ReadOnlySpan<byte> id, ReadOnlySpan<byte> marker) =>
        id.Length == IdHexChars / 2 && marker.Length == MarkerBytes
            ? new(Convert.ToHexStringLower(id), marker.ToArray())
            : null;

    /// <summary>The 16 raw bytes of <see cref="Id"/>, as the rules cache stores them.</summary>
    internal byte[] IdBytes() => Convert.FromHexString(Id);

    /// <summary>
    /// <paramref name="hits"/> without this canary (exact, ordinal name). A hit that uses <see cref="Prefix"/>
    /// (case-insensitively) under any other name is not ours and no shipped rule may use the prefix
    /// (<see cref="YaraXRules.Compile"/> refuses such sources), so it is dropped too, with a warning.
    /// </summary>
    internal IReadOnlyList<YaraXHit> Strip(IReadOnlyList<YaraXHit> hits)
    {
        var foreign = hits.Where(IsForeign).ToArray();
        if (foreign.Length > 0)
            Runtime.Warn("YARA-X: dropped {0} hit(s) on rule(s) using the reserved canary prefix that are not this ruleset's canary: {1}",
                foreign.Length, YaraPathSafety.Bounded(foreign.Select(h => h.Rule).ToArray()));

        return hits.Any(Reserved) ? hits.Where(h => !Reserved(h)).ToArray() : hits;

        static bool Reserved(YaraXHit hit) => hit.Rule.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary><c>true</c> when <paramref name="hits"/> contains this canary, by exact name.</summary>
    internal bool HitIn(IReadOnlyList<YaraXHit> hits) => hits.Any(h => string.Equals(h.Rule, RuleName, StringComparison.Ordinal));

    private bool IsForeign(YaraXHit hit) =>
        hit.Rule.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) && !string.Equals(hit.Rule, RuleName, StringComparison.Ordinal);
    #endregion

    #region Fields
    /// <summary>The reserved name prefix of the canary rule.</summary>
    internal const string Prefix = "SilvergunCanary_";

    /// <summary>Length of the random marker the canary rule matches.</summary>
    internal const int MarkerBytes = 32;

    private const int IdHexChars = 32;

    private readonly byte[] marker;
    #endregion
}
#endif
