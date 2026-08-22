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

    /// <summary>YARA was requested but could not actually run. The primary cause is a backend whose
    /// <see cref="IYaraScanner.Available"/> reports <c>false</c> — no engine ever initialized, e.g.
    /// <see cref="NullYaraScanner"/> (no backend configured at all) or a <c>LibYaraScanner</c>/<c>YaraCliScanner</c>
    /// whose native/CLI dependency did not come up. This is NOT the "a selected backend threw" case that older
    /// code assumed: every <see cref="IYaraScanner"/> implementation contracts to never throw and swallows its own
    /// failures, so exception-absence from scanning carries no information about whether it actually worked — this
    /// status is derived by asking the backend directly, not by inferring health from a catch block. The remaining,
    /// rarer path is genuine defense in depth: a backend that reports <c>Available</c> can still fail at a call
    /// site outside its own guards (e.g. the Windows in-process engine's native dependency failing to load when its
    /// types are first JIT-resolved), and that failure is still caught and mapped here. The same catch is how a
    /// <b>partial</b> failure fails closed: a <see cref="YaraScanIncompleteException"/> means specific files are
    /// known not to have been scanned (ADR 0029 decision 13), which is reported here rather than as a
    /// <see cref="Completed"/> result that is quietly missing hits.
    /// <see cref="PackageCapabilityReport.YaraFindings"/> is empty in every case, but that emptiness is NOT
    /// evidence of a clean package — the files were never examined.</summary>
    Unavailable,
}
