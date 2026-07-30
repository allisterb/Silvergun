namespace Silvergun.Intel;

using System.Collections.Generic;

/// <summary>
/// Whether the known-vulnerability (OSV.dev) check ran for a package (ADR 0017, 2026-07-17 amendment). Distinguishes a
/// genuinely-clean result from an outage so a security-gating signal is never a false all-clear: <see cref="NotChecked"/>
/// (skipped, e.g. <c>--no-vulns</c>; also the <b>default</b> value, so a report deserialized from legacy JSON written
/// before the field existed lands here and names no cause), <see cref="Completed"/> (the check ran — findings may be
/// empty = truly clean), and
/// <see cref="Unavailable"/> (the check could not complete, so the package is NOT verified against known CVEs).
/// </summary>
public enum VulnerabilityScanStatus
{
    NotChecked,
    Completed,
    Unavailable
}

/// <summary>
/// The outcome of an <see cref="IVulnerabilitySource.QueryAsync"/> call (ADR 0017, 2026-07-17 amendment).
/// <see cref="Queried"/> is <c>true</c> only when every OSV <c>/v1/querybatch</c> call completed (the vulnerability-ID
/// set is complete); a batch failure makes it <c>false</c> (incomplete/unreachable), while a per-id detail-fetch failure
/// does not flip it (it degrades to an id-only finding). <see cref="Findings"/> holds whatever was gathered either way.
/// </summary>
public sealed record OsvQueryResult(bool Queried, IReadOnlyList<VulnerabilityFinding> Findings);
