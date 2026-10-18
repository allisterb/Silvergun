namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The report DTO for a YARA match in a package's extracted files (ADR 0016). Strings only and
/// serializable (ADR 0002) so the report stays stable across engine versions and platforms. The
/// matched <paramref name="RuleName"/>, <paramref name="Namespace"/> and <paramref name="Tags"/> come
/// from the backend hit; <paramref name="MalwareFamily"/>, <paramref name="DetectionName"/> and
/// <paramref name="Category"/> are enriched from the rule-metadata index (Phase 2); and
/// <paramref name="RelativePath"/> is the package-relative path of the matched file.
///
/// ⚠️ <paramref name="RelativePath"/> derives from an attacker-authored zip entry name and is therefore ALREADY
/// ESCAPED with <c>YaraPathSafety.Escape</c> by the time it reaches this record (ADR 0031 decision 4, closing the
/// wart ADR 0029 left open — a raw newline in a matched path used to reach the report layer). Render it as-is;
/// it is display text, not a path that can be opened.
/// </summary>
public sealed record YaraFinding(
    string RuleName,
    string? Namespace,
    string? MalwareFamily,
    string? DetectionName,
    string? Category,
    IReadOnlyList<string> Tags,
    string RelativePath);
