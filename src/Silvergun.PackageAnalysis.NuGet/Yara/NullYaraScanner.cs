namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A no-op <see cref="IYaraScanner"/> that always returns no matches. Used when no YARA engine is available
/// (the net10.0 build with no configured CLI backend, or when rule compilation produced nothing), so callers
/// need no null checks and the scan degrades gracefully (ADR 0016).
/// </summary>
public sealed class NullYaraScanner : IYaraScanner
{
    #region Methods
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => Array.Empty<YaraMatch>();

    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) =>
        Array.Empty<(string, YaraMatch)>();
    #endregion

    #region Fields
    /// <summary>Shared instance; the scanner is stateless.</summary>
    public static readonly NullYaraScanner Instance = new();
    #endregion
}
