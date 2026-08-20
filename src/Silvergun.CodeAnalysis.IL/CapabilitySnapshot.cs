namespace Silvergun.CodeAnalysis.IL;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// The completeness state of the scan that produced a <see cref="CapabilitySnapshot"/> (ADR 0024): methods
/// analysed/skipped and whether any assembly failed to load, so a later diff drawn from an incomplete scan can be
/// told apart from a genuinely clean one instead of the two silently reading the same — "no capability changes" may
/// actually mean "we could not look" (capability-diff-versions task, trap 1).
/// </summary>
public sealed record ScanCompleteness(
    bool IsComplete,
    int MethodsTotal,
    int MethodsAnalyzed,
    int MethodsSkipped,
    int AssemblyLoadFailures);   // assemblies that produced no CapabilityReport at all (e.g. an unreadable managed image)

/// <summary>
/// A serializable capability-manifest snapshot for one assembly (capability-diff-versions task): a small,
/// committable inventory meant to be diffed against another snapshot of the same package at a different version —
/// deliberately not a findings dump, so it carries no individual <see cref="ApiCallFinding"/> call sites.
/// <para>
/// <b><see cref="SchemaVersion"/> is non-negotiable.</b> A snapshot format without one cannot be safely evolved, and
/// a silently misread old snapshot produces a WRONG diff, which is worse than a refused one. <see cref="CurrentSchemaVersion"/>
/// is the version this type currently writes; a future shape change bumps it. Refusing an unrecognized version on
/// read is a consumer-side (diff) judgment, not this record's — it is not enforced here.
/// </para>
/// <para>
/// <b>Deliberately carries NO wall-clock timestamp — do not add one.</b> Two runs over the same input must be
/// byte-identical so the file is stable in version control and a repo diff shows only real capability changes; a
/// timestamp would make every regeneration a spurious diff, defeating the CI-baseline use case this snapshot exists
/// for.
/// </para>
/// </summary>
public sealed record CapabilitySnapshot(
    int SchemaVersion,
    string? PackageId,
    string? PackageVersion,
    string AssemblyName,
    string? TargetFramework,
    CapabilityManifest Manifest,
    ScanCompleteness Completeness)
{
    #region Methods
    /// <summary>
    /// Builds a snapshot at <see cref="CurrentSchemaVersion"/> from a <see cref="CapabilityReport"/>'s findings and
    /// the caller-supplied identity/completeness facts (package id/version and target framework are not known to
    /// <see cref="CapabilityReport"/> itself — a single assembly can be analyzed outside any package).
    /// </summary>
    public static CapabilitySnapshot From(
        CapabilityReport report, string? packageId, string? packageVersion, string? targetFramework, ScanCompleteness completeness) =>
        new(CurrentSchemaVersion, packageId, packageVersion, report.AssemblyName, targetFramework,
            CapabilityManifest.From(report.Findings), completeness);

    /// <summary>Serializes this snapshot to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="CapabilitySnapshot"/> from JSON produced by <see cref="ToJson"/>. Returns
    /// <c>null</c> for <c>null</c> input; malformed JSON throws. Does not itself refuse an unrecognized
    /// <see cref="SchemaVersion"/> — that judgment belongs to the consumer comparing two snapshots (the
    /// capability-diff verb, a later task), which knows which versions it can safely compare.
    /// </summary>
    public static CapabilitySnapshot? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<CapabilitySnapshot>(json, jsonOptions);
    #endregion

    #region Fields
    /// <summary>The <see cref="SchemaVersion"/> this type currently writes.</summary>
    public const int CurrentSchemaVersion = 1;

    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
