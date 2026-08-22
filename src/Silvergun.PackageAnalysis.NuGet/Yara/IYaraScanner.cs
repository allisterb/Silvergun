namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A backend that scans a package's extracted files against the embedded YARA ruleset (ADR 0016).
/// Implementations compile the embedded rules once (lazy/shared) and are selected at runtime:
/// the Windows in-process <c>LibYaraScanner</c> (<c>#if WINDOWS</c>), the classic-CLI backend (Phase 2),
/// or <see cref="NullYaraScanner"/> when no engine is available.
///
/// Contract: <b>never throws</b>, with exactly one carve-out (below). All package content is hostile (threat
/// model). Any failure — a ruleset that would not compile, a missing/unreadable file, an engine or native
/// error — is logged and yields an empty result for that file; the scan always continues.
///
/// <b>The one carve-out: a scan that exceeds the backend's own wall-clock bound may throw
/// <see cref="TimeoutException"/></b> (ADR 0028 decision 10; <c>LibYaraScanner</c> does). A timed-out scan is
/// a scan whose result is unknown, and swallowing it as an empty list would be indistinguishable from a
/// healthy scan that found nothing — the precise confusion <see cref="YaraScanStatus"/> exists to prevent
/// (ADR 0027 decision 4). It therefore propagates to <c>PackageScanner.ScanYara</c>, which reports the package
/// as <see cref="YaraScanStatus.Unavailable"/>. Nothing else may escape: in particular a per-file native error
/// must NOT, because it would take down the whole package's scan along with every other file's findings.
/// </summary>
public interface IYaraScanner
{
    #region Properties
    /// <summary>
    /// Whether this backend actually initialized and can scan — a genuine health signal, not a "was a backend
    /// selected" check. This exists because every implementation below contracts to <b>never throw</b>: an
    /// unhealthy backend that quietly returns empty is otherwise indistinguishable from a healthy one that found
    /// nothing, so callers (<c>PackageScanner.ScanYara</c>) must be able to ask the backend directly rather than
    /// infer health from whether scanning throws. Deliberately has <b>no default implementation</b>: a health
    /// signal that defaults to healthy is worthless, and this project has already shipped that exact defect
    /// twice (once here, once as the <c>YaraScanStatus</c> gap it was added to close — see ADR 0027). Every
    /// implementation, present and future, must state its health explicitly; there is no safe convention to
    /// forget.
    /// </summary>
    bool Available { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Scans the single file at <paramref name="fullPath"/> and returns the rule hits, or an empty list
    /// when nothing matched or the backend is unavailable. Never throws, <b>except</b> the
    /// <see cref="TimeoutException"/> carve-out in the type doc: a scan that exceeded the backend's own bound
    /// is reported, never swallowed as "no matches". A missing/unreadable file or a native error is logged and
    /// returns empty.
    /// </summary>
    IReadOnlyList<YaraMatch> ScanFile(string fullPath);

    /// <summary>
    /// Scans every file under <paramref name="rootDir"/> (recursively) and returns each hit paired with the
    /// absolute path of the file it matched. The default implementation loops <see cref="ScanFile"/> over the
    /// files — the cheap primitive for the in-memory backend; the classic-CLI backend overrides this to run a
    /// single recursive <c>yara -r</c> process. Returns empty when the directory is missing or the backend is
    /// unavailable. Never throws, <b>except</b> the <see cref="TimeoutException"/> carve-out in the type doc:
    /// this default implementation deliberately does NOT guard the loop, so one file's timeout aborts the
    /// remaining files and surfaces to <c>PackageScanner.ScanYara</c> as
    /// <see cref="YaraScanStatus.Unavailable"/> — a bound that was reached means the backend's health can no
    /// longer be vouched for, so the rest of the directory's "no matches" would not be trustworthy either.
    /// </summary>
    IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
    {
        string[] files;
        try
        {
            files = !string.IsNullOrEmpty(rootDir) && Directory.Exists(rootDir)
                ? Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories)
                : Array.Empty<string>();
        }
        catch
        {
            return Array.Empty<(string, YaraMatch)>();
        }

        return files
            .SelectMany(file => ScanFile(file).Select(match => (file, match)))
            .ToArray();
    }
    #endregion
}
