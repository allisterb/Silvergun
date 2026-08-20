namespace Silvergun.CLI.Reports;

using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// The result of one <c>capability-diff</c> run (capability-diff-versions task, Phase B): the structural
/// <see cref="CapabilityDiffReport"/> plus each side's completeness (ADR 0024, trap 1). Carried together, on
/// purpose — a consumer must never see the delta without also seeing whether either side could be trusted, which
/// is exactly the failure mode ("no new capabilities" silently meaning "we could not look") this task exists to
/// prevent.
/// </summary>
internal sealed record CapabilityDiffOutcome(
    CapabilityDiffReport Diff,
    bool BaselineComplete,
    IReadOnlyList<string> BaselineCaveats,
    bool CandidateComplete,
    IReadOnlyList<string> CandidateCaveats,
    bool VacuousDiffOverridden)
{
    #region Properties
    /// <summary>Whether either side's scan was incomplete — the trap-1 gate input.</summary>
    internal bool IsIncomplete => !BaselineComplete || !CandidateComplete;
    #endregion

    #region Methods
    /// <summary>Serializes this outcome to indented JSON with enums written as their names.</summary>
    internal string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Whether one side (the baseline or the candidate array) is complete: EVERY element's
    /// <see cref="CapabilitySnapshot.Completeness"/> must say so, since any one incomplete assembly means the
    /// side as a whole cannot be trusted to show a clean delta (trap 1). Caveats are ordinal-sorted by assembly
    /// name for determinism.
    /// </summary>
    internal static (bool IsComplete, IReadOnlyList<string> Caveats) SideCompleteness(IReadOnlyList<CapabilitySnapshot> snapshots)
    {
        var incomplete = snapshots.Where(s => !s.Completeness.IsComplete)
            .OrderBy(s => s.AssemblyName, StringComparer.Ordinal)
            .ToArray();

        return incomplete.Length == 0
            ? (true, Array.Empty<string>())
            : (false, incomplete.Select(s => $"{s.AssemblyName}: {CompletenessCaveat(s.Completeness)}").ToArray());
    }

    // States only what the ScanCompleteness counters carry, never a diagnosis (mirrors AnalysisCompleteness's own
    // caveats). Falls back to a generic note when IsComplete is false but neither counter explains why — e.g. a
    // hand-edited snapshot file — so an incomplete entry always produces SOME caveat text.
    private static string CompletenessCaveat(ScanCompleteness c)
    {
        var parts = new List<string>();
        if (c.MethodsSkipped > 0)
            parts.Add($"{c.MethodsSkipped} of {c.MethodsTotal} method(s) could not be analyzed");
        if (c.AssemblyLoadFailures > 0)
            parts.Add($"{c.AssemblyLoadFailures} assembl{(c.AssemblyLoadFailures == 1 ? "y" : "ies")} failed to load");
        return parts.Count > 0 ? string.Join("; ", parts) : "the scan was marked incomplete";
    }
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
