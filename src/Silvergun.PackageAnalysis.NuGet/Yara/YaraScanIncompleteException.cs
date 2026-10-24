namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Thrown by an <see cref="IYaraScanner"/> when part of a scan is <b>known</b> not to have happened, so the result
/// cannot honestly be presented as a completed scan (ADR 0029 decision 13 — fail closed).
///
/// It is the one "partial result plus degraded status" channel ADR 0030 asked for (ADR 0032 decision 1), and it is
/// <b>not a new status channel</b>: it is the existing seam (ADR 0029 decision 14). <c>PackageScanner.ScanYara</c>
/// catches it, reports <see cref="YaraScanStatus.Unavailable"/> with a single logged warning per package, and
/// reports <see cref="PartialFindings"/> alongside that status. Two things therefore travel together and neither
/// may be dropped: the hits already in hand are <b>real detections</b> (ADR 0030, "the converse also holds" —
/// <c>Unavailable</c> must mean "we could not tell", never "we could tell and threw it away"), and the files that
/// were not examined are <b>not verified</b>, so the result can never read as <see cref="YaraScanStatus.Completed"/>.
/// Every site that throws this with hits in hand passes <b>all</b> of them.
///
/// Raised for: a file that was not scanned (missing, unopenable, a native or process fault — ADR 0032 decision 5);
/// a name the CLI backend's batch output cannot attribute and that could not be re-scanned through a safely named
/// copy (ADR 0029 decision 13, attacker-selected); a pass that produced no usable run — a process that failed to
/// start, exited nonzero or timed out (decision 14), which a package can drive simply by being expensive to scan; a
/// <c>yara -r</c> pass that exited 0 but printed an <c>error</c> line on stderr (ADR 0032 decision 7 — an unopenable
/// file, or the one file mid-scan when the run's <c>--timeout</c> deadline passed); a file that pass printed no
/// coverage line for — the files still queued at that deadline are dropped with no line at all — and whose individual
/// re-scan then failed (ADR 0032 decision 9); a hit that could not be attributed to any enumerated file (decision 17);
/// and a per-file timeout in the per-file <see cref="IYaraScanner.ScanFiles"/> loop (<see cref="YaraScanLoop.Run"/>, ADR
/// 0032 decision 6). For a timeout, <see cref="Exception.InnerException"/> is a <see cref="TimeoutException"/>, so the
/// cause remains machine-readable through the one seam; likewise, for a file that no longer exists (ADR 0034),
/// <c>LibYaraScanner.ScanFile</c> carries the <see cref="FileNotFoundException"/> or
/// <see cref="DirectoryNotFoundException"/> that said so, which, once the loop has confirmed the file missing on disk
/// (<see cref="YaraTree.Missing"/>), is how it names it.
///
/// Partial findings travel only through the three-argument constructor, as
/// <c>(message, innerException, partialFindings)</c> with a <c>null</c> inner exception where there is none (ADR
/// 0032 decision 8). There is deliberately no <c>(message, partialFindings)</c> overload: beside
/// <c>(message, innerException)</c> it would make <c>new YaraScanIncompleteException(message, null)</c> ambiguous.
///
/// <see cref="Message"/> is safe to log verbatim: every path in it is escaped through
/// <c>YaraPathSafety.Escape</c> before it reaches the message. The paths in <see cref="PartialFindings"/> are
/// <b>raw</b> (they must still resolve against the extraction root) and are escaped at the report boundary.
/// </summary>
public sealed class YaraScanIncompleteException : Exception
{
    #region Constructors
    public YaraScanIncompleteException(string message) : this(message, null, null) { }

    public YaraScanIncompleteException(string message, Exception? innerException) : this(message, innerException, null) { }

    public YaraScanIncompleteException(
        string message, Exception? innerException, IReadOnlyList<(string FullPath, YaraMatch Match)>? partialFindings)
        : base(message, innerException) =>
        PartialFindings = partialFindings is null ? Array.Empty<(string, YaraMatch)>() : partialFindings.ToArray();
    #endregion

    #region Properties
    /// <summary>
    /// The hits found, each paired with the absolute path of the file it matched (for an unattributable batch hit,
    /// ADR 0032 decision 4: the target <c>yara</c> echoed), before the scan was known to be incomplete. Never null;
    /// empty when none were in hand. A snapshot — later changes to the list the thrower passed do not show here.
    /// These are real detections; their absence is <b>not</b> evidence of a clean package.
    /// </summary>
    public IReadOnlyList<(string FullPath, YaraMatch Match)> PartialFindings { get; }
    #endregion
}
