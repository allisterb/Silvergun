namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Thrown by an <see cref="IYaraScanner"/> when part of a directory scan is <b>known</b> not to have happened, so
/// the result cannot honestly be presented as a scan (ADR 0029 decision 13 — fail closed).
///
/// This is the second, narrow carve-out from the interface's never-throws contract and it works exactly like the
/// first (the <see cref="TimeoutException"/> of ADR 0028 decision 10): it is <b>not a new status channel</b>, it
/// is the existing one. <c>PackageScanner.ScanYara</c> already converts any exception out of
/// <c>ScanDirectory</c> into <see cref="YaraScanStatus.Unavailable"/> with a single logged warning per package,
/// which is precisely the required outcome. Returning the partial hit list instead would report
/// <see cref="YaraScanStatus.Completed"/> over files that were never examined — the exact
/// "did not scan reads as clean" confusion <see cref="YaraScanStatus"/> exists to prevent.
///
/// The distinction from a per-file error that must stay swallowed (a missing or unreadable file) is that this one
/// is <b>attacker-selected</b>: the package chose the file name that defeated the batch pass, so treating its
/// unscanned bytes as clean is exactly what the package is asking for. The same is true of a batch pass that
/// produced no usable run — a process that failed to start, exited nonzero, or timed out (ADR 0029 decision 14):
/// a package can drive the last of those simply by being expensive to scan, and an empty result there would be a
/// clean report bought on demand. For a timeout, <see cref="Exception.InnerException"/> is a
/// <see cref="TimeoutException"/>, so the cause remains machine-readable through the one seam.
///
/// <see cref="Message"/> is safe to log verbatim: every path in it is escaped through
/// <c>YaraPathSafety.Escape</c> before it reaches the message.
/// </summary>
public sealed class YaraScanIncompleteException : Exception
{
    #region Constructors
    public YaraScanIncompleteException(string message) : base(message) { }

    public YaraScanIncompleteException(string message, Exception? innerException) : base(message, innerException) { }
    #endregion
}
