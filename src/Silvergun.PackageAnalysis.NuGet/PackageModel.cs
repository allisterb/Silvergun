namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet.Graph;
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
/// What kind of packaged content a <see cref="ScriptFinding"/> came from. <see cref="Script"/> is executable
/// script/build content; <see cref="PackageMetadata"/> is declarative manifest content (the <c>.nuspec</c>). Both
/// are reported but neither gates <c>--strict</c> (ADR-0027 stopped <see cref="Script"/> gating — 25% benign
/// prevalence; <see cref="PackageMetadata"/> was always advisory-only, mirroring ADR 0015).
/// </summary>
public enum ScriptFindingSource { Script, PackageMetadata }

/// <summary>
/// One text-rule match found in a packaged script/build file by the AppInspector RulesEngine (ADR 0012).
/// Strings only (ADR 0002) so the report stays serialization-stable across engine/enum versions. Matches are
/// aggregated per (rule, file): <see cref="Occurrences"/> counts how many times the rule matched, while the
/// line/excerpt describe the first match. <see cref="Occurrences"/>/<see cref="Source"/> are additive trailing
/// members — old JSON that predates them deserializes to 1 / <see cref="ScriptFindingSource.Script"/>.
/// </summary>
public sealed record ScriptFinding(
    string RuleId,
    string RuleName,
    string Severity,            // RulesEngine Severity name (e.g. "Moderate", "Important", "Critical")
    string Confidence,          // RulesEngine Confidence name (e.g. "Low", "Medium", "High")
    string RelativePath,        // package-relative path of the matched script
    int StartLine,
    string? Excerpt,            // matched snippet, when available
    IReadOnlyList<string> Tags,
    int Occurrences = 1,        // additive; number of matches of this rule in this file (>= 1)
    ScriptFindingSource Source = ScriptFindingSource.Script);   // additive; neither Source gates --strict (ADR-0027)

/// <summary>The outcome of scanning a single <see cref="PackageAssembly"/>.</summary>
public sealed record AssemblyScanResult(
    PackageAssembly Assembly,
    // null when no capability report was produced — either nothing could be read out of the file OR analysis was
    // attempted and threw. Not a statement that the file is inherently un-analyzable; SkipReason carries the detail.
    CapabilityReport? Report,
    // Non-null when Report is null. Carries no single cause: PackageScanner sets it for a file nothing could be read
    // out of, for a valid managed assembly whose capability analysis threw — the more security-relevant case — and
    // for a DECLARED entry that never reached the inventory at all, where Assembly.FullPath/Sha256 are empty because
    // no file exists (ADR 0030; e.g. an entry named COM1.dll, which Windows cannot write to disk).
    // Consumers must surface it verbatim and must not paraphrase it into a benign-sounding diagnosis.
    string? SkipReason,
    AssemblyMetadataInfo? Metadata,   // null if the metadata read failed or the assembly produced no analysis
    ObfuscationReport? Obfuscation,   // null if obfuscation analysis failed or the assembly produced no analysis
    // Additive trailing member (indicator-cli-integration task), same posture as Obfuscation: null if indicator
    // analysis failed, was never attempted (SkipReason case), or predates this field in old JSON.
    IndicatorReport? Indicators = null)
{
    #region Properties
    /// <summary>
    /// Whether this row is a DECLARED package entry that was never written as an extracted file of its own (see
    /// <see cref="NuGetPackage.UninventoriedEntryNames"/>) rather than a file on disk. Such a row has empty
    /// <see cref="PackageAssembly.FullPath"/> and <see cref="PackageAssembly.Sha256"/> by construction (PackageScanner),
    /// which an inventoried file never has; both are serialized, so this holds for a report read back from JSON too.
    /// Reports count and list these apart from files (entry-aliasing review 2, W2): they are entries, not files.
    /// </summary>
    [JsonIgnore]
    public bool NotInventoried => string.IsNullOrEmpty(Assembly.FullPath) && string.IsNullOrEmpty(Assembly.Sha256);
    #endregion
}

/// <summary>Aggregate, serializable scan result for one package (ADR 0002 pattern — strings/records only).</summary>
public sealed record PackageCapabilityReport(
    PackageIdentityInfo Package,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<AssemblyScanResult> Assemblies,
    IReadOnlyList<PackageScript> Scripts,
    IReadOnlyList<ScriptFinding> ScriptFindings,
    ProjectHealth? ProjectHealth = null,   // additive (ADR 0015); populated only under scan-package --health, else null
    // additive (ADR 0016); YARA malware-signature hits. Empty when YARA was not run or there is no engine. Under
    // YaraScanStatus.Unavailable it may hold the partial hits of an incomplete scan, which are real detections; an
    // empty list is never by itself evidence of a clean package; read it with YaraScanStatus (ADR 0032 decision 3).
    IReadOnlyList<YaraFinding>? YaraFindings = null,
    IReadOnlyList<VulnerabilityFinding>? Vulnerabilities = null,   // additive (ADR 0017); OSV known-vuln hits, attached by the CLI, empty when skipped/unavailable
    VulnerabilityScanStatus VulnerabilitiesStatus = VulnerabilityScanStatus.NotChecked,   // additive (ADR 0017 amendment); whether the OSV check ran — old JSON ⇒ NotChecked
    IReadOnlyList<ResolvedDependency>? ResolvedDependencies = null,   // additive (ADR 0018); resolver-lite transitive set, attached by the CLI, empty when depth 0 / not run
    DependencyResolutionStatus DependencyResolution = DependencyResolutionStatus.NotRun,   // additive (ADR 0018); whether transitive resolution ran — old JSON ⇒ NotRun
    // additive; whether the YARA pass actually completed (see Yara/YaraScanStatus.cs). Old JSON — including every
    // report the libyara.NET native-dependency defect silently produced — predates this tracking and deserializes
    // to Unavailable ("not verified"), never a false Completed; PackageScanner.Scan sets the real value going forward.
    YaraScanStatus YaraScanStatus = YaraScanStatus.Unavailable,
    // additive (ADR 0031); hostile constructions in the package's DECLARED zip entry names — control characters,
    // bidi overrides, zip slip, case-only collisions and friends. Already escaped (see PackagingAnomaly). Purely
    // reported: no anomaly gates --strict or changes any exit code (ADR 0031 decision 3). Old JSON ⇒ empty.
    IReadOnlyList<PackagingAnomaly>? PackagingAnomalies = null,
    // additive (ADR 0030; ADR 0032 shape); whether the script content pass scanned every script/manifest file (see
    // ScriptScanStatus.cs). Under Unavailable, ScriptFindings may hold the real hits of the files that were scanned.
    // Old JSON predates it and deserializes to Unavailable ("not verified"), exactly like YaraScanStatus above: every
    // report written before this field came from a scanner that turned an unscannable script into a silent zero
    // (ADR 0035), so Completed would be a false clean. PackageScanner.Scan sets Completed or Unavailable going forward.
    ScriptScanStatus ScriptScanStatus = ScriptScanStatus.Unavailable,
    // additive (R3, docs/agent/tasks/reachability-r3.md); the graph pass's bounded summary, set only under
    // PackageScanner.Scan(runReachability: true). Informational: gates nothing. Written to JSON only when set.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ReachabilitySummary? Reachability = null,
    // additive (native-binaries-1); native PE/ELF/Mach-O files by header. Facts only: gates nothing. Old JSON ⇒ empty
    // list with status Unavailable, so a pre-field report never reads as "no native code".
    IReadOnlyList<NativeBinary>? NativeBinaries = null,
    NativeBinaryScanStatus NativeBinaryScanStatus = NativeBinaryScanStatus.Unavailable)
{
    #region Properties
    /// <summary>
    /// Whether the graph pass ran and came out decided: <see cref="ReachabilityScanStatus.NotRun"/> without a
    /// <see cref="Reachability"/>, else its <see cref="ReachabilitySummary.Status"/>. Derived, so it cannot disagree with
    /// the summary; written to JSON only when not NotRun, and ignored on reading. Old JSON reads NotRun, which is honest:
    /// no report before R3 ran the pass.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ReachabilityScanStatus ReachabilityStatus => Reachability?.Status() ?? ReachabilityScanStatus.NotRun;

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

    /// <summary>
    /// Resolver-lite transitive dependency set for the package (ADR 0018). Populated by the CLI's <c>--depth</c> network
    /// step (never by the offline <see cref="PackageScanner"/>); normalized to an empty list when absent — old JSON that
    /// predates this field deserializes to empty, not <c>null</c>.
    /// </summary>
    public IReadOnlyList<ResolvedDependency> ResolvedDependencies { get; init; } = ResolvedDependencies ?? Array.Empty<ResolvedDependency>();

    /// <summary>
    /// Packaging anomalies found in the package's declared zip entry names (ADR 0031) — names a legitimate package
    /// essentially never ships. Produced offline by <see cref="PackageEntryNameAnalyzer"/> during
    /// <see cref="PackageScanner.Scan"/>; already escaped, and never gating. Normalized to an empty list when absent —
    /// old JSON that predates this field deserializes to empty, not <c>null</c>.
    /// </summary>
    public IReadOnlyList<PackagingAnomaly> PackagingAnomalies { get; init; } = PackagingAnomalies ?? Array.Empty<PackagingAnomaly>();

    /// <summary>Native binaries shipped in the package (see <see cref="NativeBinary"/>); read with
    /// <see cref="NativeBinaryScanStatus"/>. Normalized to empty when absent.</summary>
    public IReadOnlyList<NativeBinary> NativeBinaries { get; init; } = NativeBinaries ?? Array.Empty<NativeBinary>();

    /// <summary>
    /// Why <see cref="NativeBinaryScanStatus"/> is Unavailable (which files could not be read), else <c>null</c>. Written
    /// to JSON only when set; escaped and cut by <c>WorkerProtocol.Safe</c> on every assignment, like
    /// <see cref="YaraUnavailableReason"/>.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NativeBinaryScanUnavailableReason
    {
        get => _nativeBinaryScanUnavailableReason;
        init => _nativeBinaryScanUnavailableReason = value is null ? null : Yara.Worker.WorkerProtocol.Safe(value, MaxNativeBinaryScanUnavailableReasonChars);
    }

    /// <summary>
    /// Additive: why YARA did not complete, for a CI log to show (e.g. the YARA-X DLL is missing). Set by
    /// <see cref="PackageScanner.Scan"/> exactly when <see cref="YaraScanStatus"/> is <see cref="Yara.YaraScanStatus.Unavailable"/>;
    /// <c>null</c> when it is Completed or NotRun, and in old JSON that predates it. Written to JSON only when set, so a
    /// Completed or NotRun report's JSON is exactly what it was before this field. The text can quote package paths and
    /// engine output, so EVERY assignment (including deserialization) goes through <c>WorkerProtocol.Safe</c>, which
    /// escapes it and then cuts it to <see cref="MaxYaraUnavailableReasonChars"/> chars. Both steps are idempotent, so a
    /// round trip is unchanged.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? YaraUnavailableReason
    {
        get => _yaraUnavailableReason;
        init => _yaraUnavailableReason = value is null ? null : Yara.Worker.WorkerProtocol.Safe(value, MaxYaraUnavailableReasonChars);
    }

    /// <summary>
    /// Additive (ADR 0030; ADR 0032): why the script content scan did not complete — how many script/manifest files were
    /// not scanned, then which, each with its reason (e.g. over the size cap, gone since extraction, no ruleset loaded).
    /// Set by <see cref="PackageScanner.Scan"/> exactly when <see cref="ScriptScanStatus"/> is
    /// <see cref="Silvergun.PackageAnalysis.NuGet.ScriptScanStatus.Unavailable"/>; <c>null</c> when it is Completed or NotRun, and in old JSON that
    /// predates it. Written to JSON only when set, so a Completed report's JSON gains only the status property. The text
    /// quotes package paths, so EVERY assignment (including deserialization) goes through <c>WorkerProtocol.Safe</c>,
    /// exactly like <see cref="YaraUnavailableReason"/>: escaped, then cut to <see cref="MaxScriptScanUnavailableReasonChars"/>
    /// chars. Both steps are idempotent, so a round trip is unchanged.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ScriptScanUnavailableReason
    {
        get => _scriptScanUnavailableReason;
        init => _scriptScanUnavailableReason = value is null ? null : Yara.Worker.WorkerProtocol.Safe(value, MaxScriptScanUnavailableReasonChars);
    }

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
    /// <summary>The most chars <see cref="YaraUnavailableReason"/> holds.</summary>
    public const int MaxYaraUnavailableReasonChars = 512;

    /// <summary>The most chars <see cref="ScriptScanUnavailableReason"/> holds — the same bound as YARA's.</summary>
    public const int MaxScriptScanUnavailableReasonChars = MaxYaraUnavailableReasonChars;

    /// <summary>The most chars <see cref="NativeBinaryScanUnavailableReason"/> holds — the same bound as YARA's.</summary>
    public const int MaxNativeBinaryScanUnavailableReasonChars = MaxYaraUnavailableReasonChars;

    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string? _yaraUnavailableReason;
    private readonly string? _scriptScanUnavailableReason;
    private readonly string? _nativeBinaryScanUnavailableReason;
    #endregion
}
