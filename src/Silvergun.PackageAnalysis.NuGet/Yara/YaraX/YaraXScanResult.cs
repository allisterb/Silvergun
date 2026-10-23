#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

/// <summary>One matching rule: its identifier, namespace (<c>default</c> unless a rule set one) and tags.</summary>
internal sealed record YaraXHit(string Rule, string Namespace, IReadOnlyList<string> Tags);

/// <summary>
/// The outcome of one <see cref="YaraXScanner"/> call: exactly one of <see cref="Scanned"/> (the scan happened; its
/// hits, possibly none), <see cref="Timeout"/> (the engine's timeout aborted it: NOT scanned) or <see cref="Error"/>
/// (NOT scanned, with an escaped, bounded message). Only <see cref="Scanned"/> may ever be reported as clean (ADR 0030).
/// </summary>
internal abstract record YaraXScanResult
{
    #region Constructors
    private YaraXScanResult() { }
    #endregion

    #region Child types
    /// <summary>The scan completed; <see cref="Hits"/> excludes the canary rule.</summary>
    internal sealed record Scanned(IReadOnlyList<YaraXHit> Hits) : YaraXScanResult;

    /// <summary><c>YRX_SCAN_TIMEOUT</c>: the file was not (fully) scanned. The scanner stays usable.</summary>
    internal sealed record Timeout : YaraXScanResult;

    /// <summary>The file was not scanned. <see cref="Message"/> is escaped and at most <see cref="YaraXText.MaxChars"/> chars.</summary>
    internal sealed record Error : YaraXScanResult
    {
        internal Error(string message) => Message = YaraXText.Bounded(message);

        public string Message { get; }
    }
    #endregion
}
#endif
