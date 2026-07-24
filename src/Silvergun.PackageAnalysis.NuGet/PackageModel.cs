namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>One declared dependency of a package (surfaced even when not analyzed — ADR 0004 §6).</summary>
public sealed record PackageDependencyInfo(string Id, string VersionRange, string TargetFramework);

/// <summary>
/// Package identity and its declared dependency tree, read from the nuspec. <see cref="RepositoryUrl"/>
/// (nuspec <c>&lt;repository url&gt;</c>) and <see cref="ProjectUrl"/> (nuspec <c>&lt;projectUrl&gt;</c>) are
/// additive intel used for offline project-health repo resolution (ADR 0015); both may be <c>null</c>.
/// </summary>
public sealed record PackageIdentityInfo(
    string Id,
    string Version,
    string? Authors,
    string? Description,
    IReadOnlyList<PackageDependencyInfo> Dependencies,
    string? RepositoryUrl = null,
    string? ProjectUrl = null);

/// <summary>The role a packaged file plays, derived from its first path segment (ADR 0004 §3).</summary>
public enum PackageItemRole { Lib, Runtimes, Tools, Build, BuildTransitive, Analyzers, Content, Other }

/// <summary>A managed/native binary of interest inside the package, extracted to disk for analysis.</summary>
public sealed record PackageAssembly(
    string RelativePath,        // path inside the package, e.g. "lib/netstandard2.0/Foo.dll"
    string FullPath,            // extracted absolute path on disk
    string? TargetFramework,    // TFM folder segment when present (e.g. "netstandard2.0"), else null
    PackageItemRole Role,
    string Sha256);             // content hash, lowercase hex

/// <summary>A packaged script/build file recorded as intel — presence and path (ADR 0004 §4).</summary>
public sealed record PackageScript(
    string RelativePath,        // path inside the package, e.g. "tools/install.ps1"
    string FullPath,            // extracted absolute path on disk (mirrors PackageAssembly.FullPath)
    PackageItemRole Role);      // .ps1/.psm1/.targets/.props

/// <summary>
/// One text-rule match found in a packaged script/build file by the AppInspector RulesEngine (ADR 0012).
/// Strings only (ADR 0002) so the report stays serialization-stable across engine/enum versions.
/// </summary>
public sealed record ScriptFinding(
    string RuleId,
    string RuleName,
    string Severity,            // RulesEngine Severity name (e.g. "Moderate", "Important", "Critical")
    string Confidence,          // RulesEngine Confidence name (e.g. "Low", "Medium", "High")
    string RelativePath,        // package-relative path of the matched script
    int StartLine,
    string? Excerpt,            // matched snippet, when available
    IReadOnlyList<string> Tags);

/// <summary>The outcome of scanning a single <see cref="PackageAssembly"/>.</summary>
public sealed record AssemblyScanResult(
    PackageAssembly Assembly,
    CapabilityReport? Report,   // null when not analyzable
    string? SkipReason,         // non-null when Report is null (e.g. "not a managed assembly")
    AssemblyMetadataInfo? Metadata,   // null if metadata read failed or assembly not analyzable
    ObfuscationReport? Obfuscation);   // null if obfuscation analysis failed or assembly not analyzable

/// <summary>Aggregate, serializable scan result for one package (ADR 0002 pattern — strings/records only).</summary>
public sealed record PackageCapabilityReport(
    PackageIdentityInfo Package,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<AssemblyScanResult> Assemblies,
    IReadOnlyList<PackageScript> Scripts,
    IReadOnlyList<ScriptFinding> ScriptFindings,
    ProjectHealth? ProjectHealth = null,   // additive (ADR 0015); populated only under scan-package --health, else null
    IReadOnlyList<YaraFinding>? YaraFindings = null,   // additive (ADR 0016); YARA malware-signature hits, empty when disabled/unavailable
    IReadOnlyList<VulnerabilityFinding>? Vulnerabilities = null,   // additive (ADR 0017); OSV known-vuln hits, attached by the CLI, empty when skipped/unavailable
    VulnerabilityScanStatus VulnerabilitiesStatus = VulnerabilityScanStatus.NotChecked)   // additive (ADR 0017 amendment); whether the OSV check ran — old JSON ⇒ NotChecked
{
    #region Properties
    /// <summary>
    /// YARA malware-signature findings across the package's extracted files (ADR 0016). Normalized to an empty
    /// list when absent — old JSON that predates this field deserializes to empty, not <c>null</c>.
    /// </summary>
    public IReadOnlyList<YaraFinding> YaraFindings { get; init; } = YaraFindings ?? Array.Empty<YaraFinding>();

    /// <summary>
    /// Known-vulnerability (OSV.dev) findings for the package and its declared dependencies (ADR 0017). Populated by
    /// the CLI's network step (never by the offline <see cref="PackageScanner"/>); normalized to an empty list when
    /// absent — old JSON that predates this field deserializes to empty, not <c>null</c>.
    /// </summary>
    public IReadOnlyList<VulnerabilityFinding> Vulnerabilities { get; init; } = Vulnerabilities ?? Array.Empty<VulnerabilityFinding>();

    /// <summary>Every finding across all analyzed assemblies, flattened in stored order.</summary>
    [JsonIgnore]
    public IEnumerable<ApiCallFinding> AllFindings =>
        Assemblies.Where(a => a.Report is not null).SelectMany(a => a.Report!.Findings);
    #endregion

    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="PackageCapabilityReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static PackageCapabilityReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<PackageCapabilityReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
