namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The outcome of a <c>scan-package</c> YARA malware-signature pass (ADR 0016 caveat). Mirrors the shape of
/// <see cref="Silvergun.Intel.VulnerabilityScanStatus"/>: a caller must be able to tell "ran and found nothing"
/// apart from "did not run at all". This exists because a selected-but-broken in-process backend (the native
/// <c>libyara.NET.dll</c> dependency failing to load) previously returned an empty <c>YaraFindings</c> list
/// indistinguishable from a genuine clean scan — see the <c>scan-package-prevalence</c> measurement that found it.
/// </summary>
public enum YaraScanStatus
{
    /// <summary>The caller explicitly opted out (<c>--no-yara</c> / <c>runYara: false</c>); no backend was touched.</summary>
    NotRun,

    /// <summary>The scan ran to completion against a working backend; <see cref="PackageCapabilityReport.YaraFindings"/>
    /// reflects the real (possibly empty) result.</summary>
    Completed,

    /// <summary>YARA was requested but the scan did not complete: some or all of the package's files were
    /// <b>not verified</b>. The meaning, for every consumer: <b>findings present are real hits; absence of findings
    /// is not evidence</b> of a clean package (ADR 0032 decision 3).
    ///
    /// Three ways in. (1) A backend whose <see cref="IYaraScanner.Available"/> reports <c>false</c> — no engine ever
    /// initialized, e.g. <see cref="NullYaraScanner"/> (no backend configured at all) or a
    /// <c>YaraXWorkerScanner</c>/<c>LibYaraScanner</c>/<c>YaraCliScanner</c> whose worker/native/CLI dependency did not come up. Derived by asking the
    /// backend directly, never inferred from the absence of an exception (ADR 0027 decision 4); findings are empty.
    /// (2) A <b>partial</b> failure: a <see cref="YaraScanIncompleteException"/> means specific files are known not
    /// to have been scanned (ADR 0029 decision 13; ADR 0032), and the hits already found in the files that were
    /// scanned are reported in <see cref="PackageCapabilityReport.YaraFindings"/> — so the list may be
    /// <b>non-empty</b>, and every entry in it is a genuine detection, never to be discounted because the scan was
    /// incomplete (ADR 0030, "the converse also holds"). (3) Defense in depth: any other failure at a call site
    /// outside a backend's own guards (e.g. the Windows in-process engine's native dependency failing to load when
    /// its types are first JIT-resolved); findings are empty.
    ///
    /// Deliberately not split into a separate "partial" value: an additive enum member would read as verified to
    /// every existing consumer that tests <c>== Unavailable</c> for "not verified" — fail-open (ADR 0032 decision 3).
    /// </summary>
    Unavailable,
}
