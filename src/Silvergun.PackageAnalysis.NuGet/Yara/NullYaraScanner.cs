namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// A no-op <see cref="IYaraScanner"/> that always returns no matches. Used when no YARA engine is available
/// (the net10.0 build with no configured CLI backend, or when rule compilation produced nothing), so callers
/// need no null checks and the scan degrades gracefully (ADR 0016).
/// </summary>
public sealed class NullYaraScanner : IYaraScanner
{
    #region Properties
    /// <summary>Always <c>false</c> — there is no backend here at all, only the no-op (ADR 0027 decision 4).</summary>
    public bool Available => false;

    /// <summary>The factory selects this scanner only when <c>SILVERGUN_YARA_PATH</c> names no usable classic <c>yara</c>.</summary>
    public string? UnavailableReason => "no YARA engine is configured (SILVERGUN_YARA_PATH is unset or does not name a usable yara executable)";
    #endregion

    #region Methods
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => Array.Empty<YaraMatch>();

    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) =>
        Array.Empty<(string, YaraMatch)>();

    /// <summary>Always empty, like <see cref="ScanDirectory"/>: there is no engine, which <see cref="Available"/> says.</summary>
    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        return Array.Empty<(string, YaraMatch)>();
    }
    #endregion

    #region Fields
    /// <summary>Shared instance; the scanner is stateless.</summary>
    public static readonly NullYaraScanner Instance = new();
    #endregion
}
