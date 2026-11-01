namespace Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// The outcome of a <c>scan-package</c> script content pass: the <see cref="ScriptRuleScanner"/> run over the package's
/// inventoried script/build files and its <c>.nuspec</c> (ADR 0012). Mirrors <see cref="Yara.YaraScanStatus"/>: a caller
/// must be able to tell "scanned and found nothing" apart from "could not scan" (ADR 0030). This exists because every
/// failure path in the scanner (a missing, oversized or unreadable file, a redaction or engine failure, no ruleset
/// loaded) used to log a warning and yield no findings, so an unscanned script rendered exactly like a clean one
/// (<c>docs/agent/tasks/script-scan-coverage.md</c>, F1–F7).
/// </summary>
public enum ScriptScanStatus
{
    /// <summary>No script scan was run. Not produced by <see cref="PackageScanner.Scan"/>, which always sets
    /// <see cref="Completed"/> or <see cref="Unavailable"/>; and not the legacy-JSON default either: a report that
    /// predates this field deserializes to <see cref="Unavailable"/> (see <see cref="PackageCapabilityReport"/>), because
    /// the scanner that wrote it could not tell an unscanned script from a clean one.</summary>
    NotRun,

    /// <summary>Every inventoried script/build file and the <c>.nuspec</c> was scanned with a loaded ruleset;
    /// <see cref="PackageCapabilityReport.ScriptFindings"/> reflects the real (possibly empty) result.</summary>
    Completed,

    /// <summary>The script scan did not complete: some or all of the package's script/manifest files were <b>NOT
    /// scanned</b>. The meaning, for every consumer: <b>findings present are real hits; absence of findings is not
    /// evidence</b> of a clean package (ADR 0030; ADR 0032 decision 3). The hits found in the files that were scanned
    /// are kept in <see cref="PackageCapabilityReport.ScriptFindings"/>, so the list may be non-empty, and every entry in
    /// it is a genuine match (ADR 0032). <see cref="PackageCapabilityReport.ScriptScanUnavailableReason"/> says which
    /// files were not scanned and why.
    ///
    /// Deliberately not split into a separate "partial" value, for the reason <see cref="Yara.YaraScanStatus.Unavailable"/>
    /// gives: an additive member would read as verified to every consumer that tests <c>== Unavailable</c> for "not
    /// verified" — fail-open (ADR 0032 decision 3).
    /// </summary>
    Unavailable,
}
