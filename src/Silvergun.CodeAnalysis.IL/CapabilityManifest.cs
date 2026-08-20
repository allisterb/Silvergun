namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// One row of a <see cref="CapabilityManifest"/>: whether <see cref="Capability"/> was observed at all in the
/// finding set the manifest was built from, and how many call sites contributed to it (0 when absent).
/// </summary>
public sealed record CapabilityManifestEntry(Capability Capability, bool Present, int CallSiteCount);

/// <summary>
/// The full per-capability present/absent + call-site-count inventory over a set of <see cref="ApiCallFinding"/>
/// rows (capability-manifest-reframe / capability-diff-versions tasks). One projection, shared by the CLI's
/// "Capability manifest" section (<c>Silvergun.CLI.Reports.ReportTheme.CapabilityManifest</c>) and the serializable
/// <see cref="CapabilitySnapshot"/> — a fix or semantics change applied to one and not the other would silently
/// diverge what a report shows from what a snapshot records, which is precisely the duplication hazard this type
/// exists to remove.
/// <para>
/// <b>All <see cref="Capability"/> values, always</b> — including absent ones, derived from
/// <see cref="Enum.GetValues{TEnum}"/>, never a literal list: <see cref="Capability"/> is documented append-only, so
/// a future 12th value flows through automatically. An absent capability is itself information ("this assembly does
/// NOT execute processes"), so a manifest that recorded only present capabilities could not distinguish "genuinely
/// absent" from "not recorded by an older projection" — which would make removals unreportable and additions
/// ambiguous for a diff drawn from it.
/// </para>
/// <para>
/// <see cref="Entries"/> is always in <see cref="Capability"/> enum-declaration order, so two different manifests
/// are directly, positionally comparable — the same posture the CLI's per-category indicator-count summary takes
/// toward <see cref="IndicatorCategory"/>.
/// </para>
/// </summary>
public sealed record CapabilityManifest(IReadOnlyList<CapabilityManifestEntry> Entries)
{
    #region Methods
    /// <summary>
    /// Projects a finding set into the full manifest: one <see cref="CapabilityManifestEntry"/> per
    /// <see cref="Capability"/> value, in enum-declaration order.
    /// </summary>
    public static CapabilityManifest From(IReadOnlyList<ApiCallFinding> findings) =>
        new([.. Enum.GetValues<Capability>().Select(capability =>
        {
            var count = findings.Count(f => f.Capability == capability);
            return new CapabilityManifestEntry(capability, count > 0, count);
        })]);
    #endregion
}
