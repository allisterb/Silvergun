namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using System.Buffers.Binary;

/// <summary>
/// What the two rules caches share: the entry BODY, the entry file names, and the cache directory's housekeeping. The
/// Windows cache (<c>YaraXRulesCache</c>, DPAPI) and the Linux cache (<c>YaraXLinuxRulesCache</c>, a secure path)
/// differ only in what vouches for a body. Nothing here vouches for one: a caller must have done so before
/// <see cref="Rules"/> reads it, because a forged body is native code in the worker (ADR 0033 amendment, "Finding").
/// <code>
///   +0  32  sources sha256 (must equal the key)
///  +32  16  canary id
///  +48  32  canary marker
///  +80   4  rule count, not counting the canary (int32, little-endian)
///  +84   …  the serialized rules
/// </code>
/// </summary>
internal static class YaraXRulesEntry
{
    #region Methods
    /// <summary>The entry file name for <paramref name="sourcesSha256"/>, in the cache directory.</summary>
    internal static string FileName(string sourcesSha256) => $"rules-{YaraXNative.EngineVersion}-{sourcesSha256}.sgyx";

    /// <summary>The body for <paramref name="rules"/>; throws when they cannot be serialized.</summary>
    internal static byte[] Body(YaraXRules rules)
    {
        var blob = rules.Serialize(out var failure) ?? throw new InvalidOperationException(failure ?? "the rules could not be serialized");
        var body = new byte[BodyHeaderBytes + blob.Length];
        Convert.FromHexString(rules.SourcesSha256).CopyTo(body.AsSpan(SourcesOffset, Sha256Bytes));
        rules.Canary.IdBytes().CopyTo(body.AsSpan(CanaryIdOffset, CanaryIdBytes));
        rules.Canary.Marker.CopyTo(body.AsSpan(MarkerOffset, YaraXCanary.MarkerBytes));
        BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(RuleCountOffset, sizeof(int)), rules.RuleCount);
        blob.CopyTo(body.AsSpan(BodyHeaderBytes));
        return body;
    }

    /// <summary>
    /// Whether a vouched-for <paramref name="body"/> (at least <see cref="BodyHeaderBytes"/>) is for
    /// <paramref name="sourcesSha256"/>.
    /// </summary>
    internal static bool IsFor(ReadOnlySpan<byte> body, string sourcesSha256) =>
        Convert.ToHexStringLower(body[..Sha256Bytes]).Equals(sourcesSha256, StringComparison.Ordinal);

    /// <summary>
    /// The rules in a VOUCHED-FOR <paramref name="body"/> for <paramref name="sourcesSha256"/>, with the canary compiled
    /// into them, or <c>null</c> with the reason. The caller still runs the canary.
    /// </summary>
    internal static YaraXRules? Rules(ReadOnlySpan<byte> body, string sourcesSha256, out string? failure)
    {
        var canary = YaraXCanary.From(body.Slice(CanaryIdOffset, CanaryIdBytes), body.Slice(MarkerOffset, YaraXCanary.MarkerBytes))!;
        var ruleCount = BinaryPrimitives.ReadInt32LittleEndian(body.Slice(RuleCountOffset, sizeof(int)));
        return YaraXRules.Deserialize(body[BodyHeaderBytes..], canary, sourcesSha256, ruleCount, out failure);
    }

    /// <summary>
    /// All of <paramref name="stream"/>; throws when its length is outside [<paramref name="minimum"/>,
    /// <see cref="MaxEntryBytes"/>].
    /// </summary>
    internal static byte[] ReadBounded(FileStream stream, int minimum)
    {
        if (stream.Length < minimum || stream.Length > MaxEntryBytes)
            throw new InvalidDataException($"the entry is {stream.Length} bytes, outside [{minimum}, {MaxEntryBytes}]");

        var entry = new byte[stream.Length];
        stream.ReadExactly(entry);
        return entry;
    }

    /// <summary>
    /// N3: best-effort removal of temp files left by a writer that died between writing and moving its entry. A live
    /// writer's temp exists only for the write and move of one ~2.3 MB entry, which happens while a worker starts — and
    /// the parent kills a worker that is not ready within 15 s (amendment G9) — so a temp file not written to for
    /// <see cref="StaleTempAge"/> is an orphan. Never throws.
    /// </summary>
    internal static void SweepStaleTemps(string dir)
    {
        try
        {
            foreach (var file in new DirectoryInfo(dir).EnumerateFiles(TempPattern))
            {
                try
                {
                    if (DateTime.UtcNow - file.LastWriteTimeUtc > StaleTempAge)
                        file.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // best effort: in use, or already gone
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Runtime.Debug("YARA-X rules cache: could not sweep stale temp files: {0}", YaraXText.Bounded(ex.Message));
        }
    }

    /// <summary>A new, unique temp file name in <paramref name="dir"/> for the entry at <paramref name="path"/>.</summary>
    internal static string TempPath(string dir, string path) => Path.Combine(dir, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
    #endregion

    #region Fields
    internal const int Sha256Bytes = 32;

    /// <summary>The body's fixed header, before the serialized rules: the smallest body there is.</summary>
    internal const int BodyHeaderBytes = RuleCountOffset + sizeof(int);

    /// <summary>The 1,240-rule entry is ~2.3 MB; anything near this is not ours.</summary>
    internal const long MaxEntryBytes = 256L * 1024 * 1024;

    /// <summary>The cache's own files: entries (<see cref="FileName"/>) and the temp files they are written through.</summary>
    internal const string EntryPattern = "rules-*.sgyx";
    internal const string TempPattern = "*.tmp";

    private const int CanaryIdBytes = 16;
    private const int SourcesOffset = 0;
    private const int CanaryIdOffset = SourcesOffset + Sha256Bytes;
    private const int MarkerOffset = CanaryIdOffset + CanaryIdBytes;
    private const int RuleCountOffset = MarkerOffset + YaraXCanary.MarkerBytes;

    // A temp file untouched this long is an orphan (see SweepStaleTemps): 40× the 15 s startup bound inside which every
    // live writer finishes or is killed, so no live writer's temp is swept; an orphan goes at the next write after that.
    private static readonly TimeSpan StaleTempAge = TimeSpan.FromMinutes(10);
    #endregion
}
