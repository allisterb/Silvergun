namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A backend that scans a package's extracted files against the embedded YARA ruleset (ADR 0016).
/// Implementations compile the embedded rules once (lazy/shared) and are selected at runtime:
/// the Windows in-process <c>LibYaraScanner</c> (<c>#if WINDOWS</c>), the classic-CLI backend (Phase 2),
/// or <see cref="NullYaraScanner"/> when no engine is available.
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
/// prepare); <see cref="ScanDirectory"/> throws it when any file under the root was not, carrying every hit it did
/// find in <see cref="YaraScanIncompleteException.PartialFindings"/>. <c>PackageScanner.ScanYara</c> reports those
/// hits alongside <see cref="YaraScanStatus.Unavailable"/>: the hits are real, the rest is not verified.
///
/// <b><see cref="TimeoutException"/> out of <see cref="ScanFile"/></b> — a scan that exceeded the backend's own
/// wall-clock bound (ADR 0028 decision 10; <c>LibYaraScanner</c> does). Its result is unknown, and swallowing it as
/// "no matches" would be indistinguishable from a healthy scan that found nothing (ADR 0027 decision 4).
/// <see cref="ScanDirectory"/> converts it into a <see cref="YaraScanIncompleteException"/> carrying the hits so far,
/// with the timeout as <see cref="Exception.InnerException"/>.
///
/// One per-file failure no longer costs the other files their findings: the default <see cref="ScanDirectory"/>
/// isolates each file's <see cref="YaraScanIncompleteException"/> and keeps going (ADR 0032 decision 6), so there is
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
    /// absolute path of the file it matched. Returns empty when nothing matched, the directory is missing, or the
    /// backend is unavailable. Throws <see cref="YaraScanIncompleteException"/> when any file under the root is known
    /// not to have been scanned, carrying <b>every</b> hit found in
    /// <see cref="YaraScanIncompleteException.PartialFindings"/> — a detection is never discarded because some other
    /// file could not be examined (ADR 0032).
    ///
    /// The default implementation loops <see cref="ScanFile"/> over the files — the cheap primitive for the
    /// in-memory backend, and the production path on Windows (<c>LibYaraScanner</c> does not override it); the
    /// classic-CLI backend overrides this to run a single recursive <c>yara -r</c> process. Per file (ADR 0032
    /// decision 6): a <see cref="YaraScanIncompleteException"/> records that file as unscanned (its own partial hits,
    /// if any, are kept) and the loop <b>continues</b>; a <see cref="TimeoutException"/> <b>stops</b> the loop,
    /// because a bound that was reached means the engine's health can no longer be vouched for and the remaining
    /// files' "no matches" would not be trustworthy either (ADR 0028 decision 10), and is rethrown as
    /// <see cref="YaraScanIncompleteException"/> with the hits so far and the timeout as
    /// <see cref="Exception.InnerException"/>. After the loop, any unscanned file means the same exception, carrying
    /// all the hits. A tree that cannot be <b>enumerated</b> also throws it rather than returning empty: reporting a
    /// package whose files were never listed as a completed, empty scan is the defect ADR 0030 exists to stop — the
    /// same site ADR 0029 decision 14 closed in the CLI backend. Messages name the unscanned files escaped and
    /// bounded. Any other exception from <see cref="ScanFile"/> propagates unchanged.
    /// </summary>
    IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
    {
        string[] files;
        try
        {
            // A missing or degenerate root is not a failed scan and is not reachable in production: rootDir is
            // NuGetPackage.ExtractionDir, which the package CREATES and validates before any scan is requested. So
            // "there was nothing to scan" is the honest reading here, and no package content is being written off
            // as clean — unlike an enumeration that actually threw, below.
            files = !string.IsNullOrEmpty(rootDir) && Directory.Exists(rootDir)
                ? Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories)
                : Array.Empty<string>();
        }
        catch (Exception ex)
        {
            throw new YaraScanIncompleteException(
                $"YARA could not enumerate '{YaraPathSafety.Escape(rootDir)}', so an unknown number of files went unscanned: {YaraPathSafety.Escape(ex.Message)}. This package was NOT scanned and must not be reported as clean.",
                ex);
        }

        var hits = new List<(string FullPath, YaraMatch Match)>();
        var unscanned = new List<string>();
        for (var i = 0; i < files.Length; i++)
        {
            var file = files[i];
            try
            {
                hits.AddRange(ScanFile(file).Select(match => (file, match)));
            }
            catch (YaraScanIncompleteException ex)
            {
                hits.AddRange(ex.PartialFindings);
                unscanned.Add(file);
            }
            catch (TimeoutException ex)
            {
                var remaining = files.Length - i - 1;
                throw new YaraScanIncompleteException(
                    $"YARA timed out scanning '{YaraPathSafety.Escape(Relative(rootDir, file))}' under '{YaraPathSafety.Escape(rootDir)}', so that file was not scanned and the engine's health can no longer be vouched for"
                    + (remaining > 0 ? $"; the remaining {remaining} file(s) were not scanned" : string.Empty)
                    + (unscanned.Count > 0 ? $"; {unscanned.Count} earlier file(s) were not scanned either: {DescribeUnscanned(rootDir, unscanned)}" : string.Empty)
                    + $". {hits.Count} hit(s) found before that are reported; this package was NOT fully scanned and must not be reported as clean.",
                    ex,
                    hits);
            }
        }

        return unscanned.Count == 0
            ? hits
            : throw new YaraScanIncompleteException(
                $"YARA could not scan {unscanned.Count} of {files.Length} file(s) under '{YaraPathSafety.Escape(rootDir)}': {DescribeUnscanned(rootDir, unscanned)}. {hits.Count} hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
                null,
                hits);
    }

    // The unscanned files for an exception message: root-relative where possible, control-escaped (the names are
    // attacker-authored and the message is logged verbatim), and bounded so a package of thousands cannot flood it —
    // through the one rendering every YARA message shares (YaraPathSafety.Bounded).
    private static string DescribeUnscanned(string rootDir, IReadOnlyList<string> files) =>
        YaraPathSafety.Bounded(files.Select(f => Relative(rootDir, f)).ToArray());

    // A lexical prefix strip, deliberately not Path.GetRelativePath (ADR 0030, sixth instance) — see
    // YaraPathSafety.Relative, which the CLI backend's messages share.
    private static string Relative(string rootDir, string file) => YaraPathSafety.Relative(rootDir, file);
    #endregion
}
