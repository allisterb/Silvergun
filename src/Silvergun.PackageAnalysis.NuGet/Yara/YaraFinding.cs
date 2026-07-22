namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The report DTO for a YARA match in a package's extracted files (ADR 0016). Strings only and
/// serializable (ADR 0002) so the report stays stable across engine versions and platforms. The
/// matched <paramref name="RuleName"/>, <paramref name="Namespace"/> and <paramref name="Tags"/> come
/// from the backend hit; <paramref name="MalwareFamily"/>, <paramref name="DetectionName"/> and
/// <paramref name="Category"/> are enriched from the rule-metadata index (Phase 2); and
/// <paramref name="RelativePath"/> is the package-relative path of the matched file.
/// </summary>
public sealed record YaraFinding(
    string RuleName,
    string? Namespace,
    string? MalwareFamily,
    string? DetectionName,
    string? Category,
    IReadOnlyList<string> Tags,
    string RelativePath);
