namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A backend that scans a package's extracted files against the embedded YARA ruleset (ADR 0016).
/// Implementations compile the embedded rules once (lazy/shared) and are selected at runtime:
/// the Windows in-process <c>LibYaraScanner</c> (<c>#if WINDOWS</c>), the classic-CLI backend (Phase 2),
/// or <see cref="NullYaraScanner"/> when no engine is available.
///
/// Contract: <b>never throws</b>, with exactly two carve-outs (below). All package content is hostile (threat
/// model). Any failure — a ruleset that would not compile, a missing/unreadable file, an engine or native
/// error — is logged and yields an empty result for that file; the scan always continues.
///
/// <b>Carve-out 1: a scan that exceeds the backend's own wall-clock bound may throw
/// <see cref="TimeoutException"/></b> (ADR 0028 decision 10; <c>LibYaraScanner</c> does). A timed-out scan is
/// a scan whose result is unknown, and swallowing it as an empty list would be indistinguishable from a
/// healthy scan that found nothing — the precise confusion <see cref="YaraScanStatus"/> exists to prevent
/// (ADR 0027 decision 4). It therefore propagates to <c>PackageScanner.ScanYara</c>, which reports the package
/// as <see cref="YaraScanStatus.Unavailable"/>.
///
/// <b>Carve-out 2, the same principle applied to a partial failure: <see cref="ScanDirectory"/> may throw
/// <see cref="YaraScanIncompleteException"/> when some file under the root is known not to have been
/// scanned</b> (ADR 0029 decisions 13 and 14; <c>YaraCliScanner</c> does, for names carrying control characters
/// that its line-oriented backend cannot attribute, for a batch pass that produced no usable run at all — a
/// process that failed to start, exited nonzero or timed out, which a hostile package can provoke on demand — and
/// for a batch hit under the root it could not attribute to any enumerated file, ADR 0029 decision 17; the
/// <see cref="ScanDirectory"/> default below does the same for a tree it cannot enumerate).
/// It reaches <c>PackageScanner.ScanYara</c>'s existing catch and
/// becomes <see cref="YaraScanStatus.Unavailable"/> — deliberately reusing that seam rather than adding a
/// status channel.
///
/// Nothing else may escape: in particular a per-file native error must NOT, because it would take down the
/// whole package's scan along with every other file's findings.
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
    /// unavailable. Never throws, <b>except</b> the two carve-outs in the type doc
    /// (<see cref="TimeoutException"/>, <see cref="YaraScanIncompleteException"/>):
    /// this default implementation deliberately does NOT guard the loop, so one file's timeout aborts the
    /// remaining files and surfaces to <c>PackageScanner.ScanYara</c> as
    /// <see cref="YaraScanStatus.Unavailable"/> — a bound that was reached means the backend's health can no
    /// longer be vouched for, so the rest of the directory's "no matches" would not be trustworthy either. For the
    /// same reason a tree that cannot be <b>enumerated</b> throws <see cref="YaraScanIncompleteException"/> rather
    /// than returning empty: this default is the production path on Windows (<c>LibYaraScanner</c> does not
    /// override it), and reporting a package whose files were never listed as a completed, empty scan is the
    /// defect ADR 0030 exists to stop — the same site ADR 0029 decision 14 closed in the CLI backend.
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

        return files
            .SelectMany(file => ScanFile(file).Select(match => (file, match)))
            .ToArray();
    }
    #endregion
}
