namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A backend that scans a package's extracted files against the embedded YARA ruleset (ADR 0016).
/// Implementations compile the embedded rules once (lazy/shared) and are selected at runtime:
/// on Windows (<c>#if WINDOWS</c>) the out-of-process <c>YaraXWorkerScanner</c> by default, or the in-process
/// <c>LibYaraScanner</c> as an explicit fallback; elsewhere the classic-CLI backend (Phase 2), or
/// <see cref="NullYaraScanner"/> when no engine is available.
///
/// Contract: <b>an empty result means "scanned, nothing matched"</b> — or that there is no engine at all, which
/// <see cref="Available"/> reports. It never means "something went wrong". All package content is hostile (threat
/// model), and a hostile package can provoke most failures on demand, so a failure is never flattened into an empty
/// list (ADR 0030; ADR 0032 decision 5). "Scanned" has to be established from <b>positive evidence</b> that each file
/// was examined, not inferred from the absence of an error: an engine can skip files without saying so — <c>yara
/// -r</c>'s <c>--timeout</c> is one deadline for the whole run, and files still queued when it passes are dropped with
/// exit 0 and nothing on stderr (ADR 0032 decision 9). By contract, exactly two exception types carry a failure out
/// (anything else is a defence-in-depth path, last paragraph):
///
/// <b><see cref="YaraScanIncompleteException"/></b> — some file is <b>known</b> not to have been scanned (ADR 0029
/// decisions 13, 14 and 17; ADR 0032). <see cref="ScanFile"/> throws it when <i>its</i> file was not scanned
/// (missing or unopenable, a native or process fault, a result that would not map, a ruleset that would not
/// prepare); <see cref="ScanFiles"/> throws it when any listed file was not, and <see cref="ScanDirectory"/> when any
/// file under the root was not, carrying every hit it did find in
/// <see cref="YaraScanIncompleteException.PartialFindings"/>. <c>PackageScanner.ScanYara</c> reports those hits
/// alongside <see cref="YaraScanStatus.Unavailable"/>: the hits are real, the rest is not verified.
///
/// <b>Coverage is judged against the extraction inventory</b> (ADR 0034): <c>PackageScanner.ScanYara</c> hands
/// <see cref="ScanFiles"/> the list of files <c>NuGetPackage.Open</c> recorded straight after extraction, not a walk
/// of the extraction directory taken later. A listed file that is gone by the time YARA runs (deleted mid-run, by
/// Windows Storage Sense or anything else) is therefore unscanned, never silently absent from a "completed" scan.
///
/// <b><see cref="TimeoutException"/> out of <see cref="ScanFile"/></b> — a scan that exceeded the backend's own
/// wall-clock bound (ADR 0028 decision 10; <c>LibYaraScanner</c> does). Its result is unknown, and swallowing it as
/// "no matches" would be indistinguishable from a healthy scan that found nothing (ADR 0027 decision 4).
/// The per-file <see cref="ScanFiles"/> loop converts it into a <see cref="YaraScanIncompleteException"/> carrying the hits so far,
/// with the timeout as <see cref="Exception.InnerException"/>.
///
/// One per-file failure no longer costs the other files their findings: every <see cref="ScanFiles"/> (the per-file
/// loop included) isolates each file's <see cref="YaraScanIncompleteException"/> and keeps going (ADR 0032 decision 6), so there is
/// no longer any reason for a backend to swallow one. Any other exception type is outside the contract, not a third
/// channel: if one does escape (e.g. the in-process engine's native dependency failing to load), it is caught by
/// <c>PackageScanner.ScanYara</c>'s outer catch as defence in depth and reported as
/// <see cref="YaraScanStatus.Unavailable"/> with no findings.
/// </summary>
public interface IYaraScanner
{
    #region Properties
    /// <summary>
    /// Whether this backend actually initialized and can scan — a genuine health signal, not a "was a backend
    /// selected" check. A backend with no engine returns empty from every scan, which is otherwise
    /// indistinguishable from a healthy one that found nothing, so callers (<c>PackageScanner.ScanYara</c>) must be
    /// able to ask the backend directly rather than infer health from whether scanning throws. Deliberately has
    /// <b>no default implementation</b>: a health signal that defaults to healthy is worthless, and this project has
    /// already shipped that exact defect twice (once here, once as the <c>YaraScanStatus</c> gap it was added to
    /// close — see ADR 0027). Every implementation, present and future, must state its health explicitly; there is
    /// no safe convention to forget.
    /// </summary>
    bool Available { get; }

    /// <summary>
    /// Why <see cref="Available"/> is <c>false</c>, for an operator to act on (e.g. "the YARA-X DLL is missing"), or
    /// <c>null</c> when it is available or the backend cannot say. Descriptive only, never a health signal, so unlike
    /// <see cref="Available"/> it may default: a backend that does not say leaves its caller a generic reason. May be raw
    /// text; <c>PackageScanner</c> escapes and bounds it before it reaches a report.
    /// </summary>
    string? UnavailableReason => null;
    #endregion

    #region Methods
    /// <summary>
    /// Scans the single file at <paramref name="fullPath"/> and returns the rule hits — empty when nothing matched,
    /// or when the backend has no engine at all (<see cref="Available"/> is <c>false</c>). Throws
    /// <see cref="YaraScanIncompleteException"/> when <b>this file</b> was not scanned: it is missing or cannot be
    /// opened, the native scan or <c>yara</c> process faulted, or the result could not be mapped (ADR 0032 decision
    /// 5). Throws <see cref="TimeoutException"/> when the scan exceeded the backend's own bound. An empty list is
    /// therefore always a scan that happened.
    /// </summary>
    IReadOnlyList<YaraMatch> ScanFile(string fullPath);

    /// <summary>
    /// Scans every file under <paramref name="rootDir"/> (recursively) and returns each hit paired with the
    /// absolute path of the file it matched. Returns empty when nothing matched, the root <b>verifiably does not
    /// exist</b>, or the backend is unavailable. Throws <see cref="YaraScanIncompleteException"/> when any file under the
    /// root is known not to have been scanned, carrying <b>every</b> hit found in
    /// <see cref="YaraScanIncompleteException.PartialFindings"/> — a detection is never discarded because some other
    /// file could not be examined (ADR 0032).
    ///
    /// Every implementation is "enumerate, then <see cref="ScanFiles"/>" (ADR 0034 decision 2), through the one shared
    /// enumeration (<see cref="YaraTree.Files"/>): only a root that verifiably does not exist is "nothing to scan"; one
    /// that exists but is not a directory or cannot be read, or a tree that cannot be <b>enumerated</b>, throws rather
    /// than returning empty — reporting a package whose files were never listed as a completed, empty scan is the defect
    /// ADR 0030 exists to stop (ADR 0034 decision 4; the same site ADR 0029 decision 14 closed in the CLI backend).
    /// <c>PackageScanner.ScanYara</c> does not call this: it scans the package's extraction inventory through
    /// <see cref="ScanFiles"/>, so a file deleted after extraction is unscanned rather than absent (ADR 0034).
    /// </summary>
    IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) =>
        ScanFiles(rootDir, YaraTree.Files(rootDir, "YARA") ?? []);

    /// <summary>
    /// Scans <b>exactly</b> <paramref name="files"/> (absolute paths) and returns each hit paired with the listed path of
    /// the file it matched (ADR 0034 decision 2). Coverage is judged against the list, not against what is on disk now:
    /// a listed file that is missing or cannot be opened at scan time is <b>unscanned</b>, and any unscanned file throws
    /// <see cref="YaraScanIncompleteException"/> carrying every hit found in the other files (ADR 0032). An empty list
    /// is nothing to scan and returns empty; so does a backend with no engine at all (<see cref="Available"/> is
    /// <c>false</c>). <paramref name="rootDir"/> is the tree the files were listed from: it renders them relative in
    /// messages, bounds the link checks of the backends that make them, and is the CLI backend's <c>yara -r</c> batch
    /// target; it is never re-enumerated to decide what to scan.
    ///
    /// Deliberately has <b>no default implementation</b> (ADR 0034, review W1), on the same principle as
    /// <see cref="Available"/>: a default that changes coverage semantics silently is worthless. It had one — a per-file
    /// <see cref="ScanFile"/> loop — and an implementer that overrode only <see cref="ScanDirectory"/> then had its
    /// list scans routed around its own scan path, lost its hits and read <see cref="YaraScanStatus.Completed"/>
    /// (measured). The compile-time break for such an implementer is intended: loud, not silent. Each backend says how
    /// it scans a list: the in-memory backend (<c>LibYaraScanner</c>, the explicit Windows fallback) loops
    /// <see cref="ScanFile"/> through the shared helper (<c>YaraScanLoop.Run</c>, which isolates each file's
    /// <see cref="YaraScanIncompleteException"/> and stops at a <see cref="TimeoutException"/>, ADR 0032 decision 6); the
    /// classic-CLI backend runs a single recursive <c>yara -r</c> process; and the default Windows backend,
    /// <c>YaraXWorkerScanner</c>, scans the whole list in one worker run. A backend with no engine returns empty,
    /// consistent with <see cref="Available"/> being <c>false</c> (<see cref="NullYaraScanner"/>).
    /// </summary>
    IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files);
    #endregion
}
