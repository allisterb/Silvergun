namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// One matched YARA string within a rule hit: the string's <paramref name="Identifier"/> (e.g. <c>$a</c>)
/// and the byte <paramref name="Offset"/> at which it matched. Optional detail, produced by the in-process
/// backend's per-string matches (or the classic CLI's <c>-s</c> output in Phase 2). Strings only (ADR 0002).
/// </summary>
public sealed record YaraStringMatch(string Identifier, long Offset);
