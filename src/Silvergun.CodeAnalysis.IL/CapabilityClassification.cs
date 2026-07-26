namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// The outcome classes of a capability-map lookup (ADR 0019, Capslock's semantics). The map is consulted with a
/// <see cref="CanonicalName.ClassificationKey(MethodIdentity)"/>, so these are properties of an <em>API</em>, not
/// of a call site.
/// </summary>
public enum CapabilityClass
{
    /// <summary>No entry matched. No verdict — keep walking.</summary>
    None,

    /// <summary>A sink: classify and stop looking for capabilities beyond this node.</summary>
    Capability,

    /// <summary>Allowlisted. <b>Terminates</b> traversal, so a wrong entry silently under-reports.</summary>
    Safe,

    /// <summary>
    /// Explicitly clears an inherited type-level or subtree classification for this member, so analysis continues
    /// into it ("catch-all with holes").
    /// </summary>
    Unspecified,

    /// <summary>We cannot see through it — report as opacity, never silently drop it.</summary>
    Unanalyzed
}

/// <summary>
/// The result of classifying one <c>ClassificationKey</c>: its <see cref="Class"/>, plus the
/// <see cref="Capability"/> it grants when (and only when) the class is <see cref="CapabilityClass.Capability"/>.
/// </summary>
public readonly record struct CapabilityVerdict(CapabilityClass Class, Capability? Capability)
{
    #region Properties
    /// <summary>The verdict for a key no entry matched: <see cref="CapabilityClass.None"/> and no capability.</summary>
    public static CapabilityVerdict None => default;
    #endregion
}

/// <summary>
/// Diagnostics for a loaded <see cref="CapabilityMap"/>: how many entries of each class it holds (after layering,
/// so overridden entries are counted once) and every line that was rejected while building it. A rejected line is
/// recorded as <c>source(lineNumber): reason</c> — a typo that silently disables an entry is the worst failure
/// mode for a security tool, so rejects are surfaced rather than swallowed.
/// </summary>
public sealed record CapabilityMapStats(
    int CapabilityEntries,
    int SafeEntries,
    int UnspecifiedEntries,
    int UnanalyzedEntries,
    int IgnoredEdges,
    IReadOnlyList<string> RejectedLines)
{
    #region Properties
    /// <summary>Total classification entries (excluding <c>ignore-edge</c> rules).</summary>
    public int TotalEntries => CapabilityEntries + SafeEntries + UnspecifiedEntries + UnanalyzedEntries;

    /// <summary>How many lines were rejected — expected to be <b>zero</b> for the built-in map.</summary>
    public int RejectedLineCount => RejectedLines.Count;
    #endregion

    #region Methods
    /// <summary>
    /// Value equality, <see cref="RejectedLines"/> compared element-wise and in order rather than by reference,
    /// so two loads of the same input compare equal — that is the loader's determinism contract.
    /// </summary>
    public bool Equals(CapabilityMapStats? other) =>
        other is not null &&
        (CapabilityEntries, SafeEntries, UnspecifiedEntries, UnanalyzedEntries, IgnoredEdges) ==
        (other.CapabilityEntries, other.SafeEntries, other.UnspecifiedEntries, other.UnanalyzedEntries, other.IgnoredEdges) &&
        RejectedLines.SequenceEqual(other.RejectedLines, StringComparer.Ordinal);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        RejectedLines.Aggregate(
            HashCode.Combine(CapabilityEntries, SafeEntries, UnspecifiedEntries, UnanalyzedEntries, IgnoredEdges),
            (hash, line) => HashCode.Combine(hash, StringComparer.Ordinal.GetHashCode(line)));
    #endregion
}
