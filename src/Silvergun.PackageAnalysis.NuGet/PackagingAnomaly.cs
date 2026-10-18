namespace Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// The kind of hostile construction found in a declared package entry name (ADR 0031 decision 2). Every
/// category is chosen for precision rather than coverage: each is something a legitimate NuGet package
/// essentially never does, so a hit is evidence of intent rather than of capability. None of them gates
/// <c>--strict</c> or influences any exit code (ADR 0031 decision 3 — prevalence is measured before gating).
/// </summary>
public enum PackagingAnomalyCategory
{
    /// <summary>A C0 control character (U+0000–U+001F) or DEL (U+007F) anywhere in the name — the ADR 0029 attack.</summary>
    ControlCharacter,

    /// <summary>A bidirectional embedding/override/isolate (U+202A–U+202E, U+2066–U+2069) — "Trojan Source": makes <c>…exe.txt</c> display as <c>…txt.exe</c>.</summary>
    BidiControl,

    /// <summary>A zero-width character (U+200B–U+200D, U+FEFF), a soft hyphen (U+00AD), or a Unicode Tag-block character (U+E0000–U+E007F, astral).</summary>
    InvisibleCharacter,

    /// <summary>The entry's target escapes the package content root (classic zip-slip), or the name is rooted/drive-qualified.</summary>
    PathTraversal,

    /// <summary>Two or more distinct entries that are equal under <see cref="System.StringComparer.OrdinalIgnoreCase"/>; on a Windows extraction one silently overwrites the other, so the file scanned is not the file shipped.</summary>
    CaseOnlyCollision,

    /// <summary>A path segment ending in a space or a <c>.</c> — Windows silently strips those, so <c>evil.dll&#160;</c> and <c>evil.dll</c> are the same file there and different everywhere else.</summary>
    TrailingSpaceOrDot,

    /// <summary>A path segment whose stem is a reserved Windows device name (<c>CON</c>, <c>PRN</c>, <c>AUX</c>, <c>NUL</c>, <c>COM1</c>–<c>COM9</c>, <c>LPT1</c>–<c>LPT9</c>), with or without an extension.</summary>
    ReservedDeviceName,
}

/// <summary>
/// One packaging anomaly found in a package's declared entry names (ADR 0031). Strings only and serializable
/// (ADR 0002), like every other report DTO.
///
/// ⚠️ <paramref name="EntryName"/> and <paramref name="Detail"/> are attacker-authored text and are therefore
/// ALREADY ESCAPED by <c>YaraPathSafety.Escape</c> when the record is constructed (ADR 0031 decision 4) — the
/// raw name never reaches a log, a report, or the JSON. Consumers render them as-is; do not attempt to
/// "un-escape" them, and do not treat them as a path that can be opened.
/// </summary>
public sealed record PackagingAnomaly(
    PackagingAnomalyCategory Category,
    string EntryName,       // escaped declared entry name, verbatim from the zip central directory
    string Detail);         // escaped, short human-readable explanation (offending code points, segment, or partners)
