namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The one enumeration every <see cref="IYaraScanner.ScanDirectory"/> implementation shares (ADR 0034 decision 4): which
/// files lie under a root, and whether there was a root at all. It replaces the <c>Directory.Exists(root) ? enumerate :
/// empty</c> test each backend used to carry, which read a root that exists but cannot be accessed as "nothing to scan"
/// — <see cref="Directory.Exists"/> answers <c>false</c> for that too, and an empty result is a completed, clean scan
/// (ADR 0030).
/// </summary>
internal static class YaraTree
{
    #region Methods
    /// <summary>
    /// Every file under <paramref name="rootDir"/>, recursively, with the same
    /// <c>Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories)</c> call (and so the same link semantics) that
    /// <c>NuGetPackage.YaraInventory</c> is taken with. Returns <c>null</c> only when the root <b>verifiably does not
    /// exist</b> — it is null or empty, reading its attributes reports it (or a directory on its path) not found, or the
    /// runtime refuses the path as malformed (empty once normalized, or carrying a NUL), so it can name nothing — which
    /// is "nothing to scan", not a failed scan.
    ///
    /// Throws <see cref="YaraScanIncompleteException"/>, its message escaped and naming <paramref name="engine"/>, when the
    /// root exists but is not a directory, when its attributes cannot be read for any other reason (access denied, an IO
    /// error, a path too long), or when the enumeration itself throws: in each case an unknown number of files
    /// went unscanned, and that must never read as clean.
    /// </summary>
    internal static string[]? Files(string? rootDir, string engine)
    {
        if (string.IsNullOrEmpty(rootDir))
            return null;

        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(rootDir);
        }
        // Not found, or a path the runtime refuses to even form (ArgumentException: empty once normalized, as an
        // all-whitespace path is on Windows, or carrying a NUL) — which therefore names nothing on disk either.
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or ArgumentException)
        {
            return null;
        }
        catch (Exception ex)
        {
            throw new YaraScanIncompleteException(
                $"{engine} could not read '{YaraPathSafety.Escape(rootDir)}' ({YaraPathSafety.Escape(ex.Message)}), so an unknown number of files under it went unscanned. This package was NOT scanned and must not be reported as clean.",
                ex);
        }

        if ((attributes & FileAttributes.Directory) == 0)
            throw new YaraScanIncompleteException(
                $"{engine} could not read '{YaraPathSafety.Escape(rootDir)}' as a directory: it exists but is not one, so an unknown number of files went unscanned. This package was NOT scanned and must not be reported as clean.");

        try
        {
            return Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            throw new YaraScanIncompleteException(
                $"{engine} could not enumerate '{YaraPathSafety.Escape(rootDir)}', so an unknown number of files went unscanned: {YaraPathSafety.Escape(ex.Message)}. This package was NOT scanned and must not be reported as clean.",
                ex);
        }
    }

    /// <summary>
    /// Why <paramref name="path"/> verifiably does not exist — the <see cref="FileNotFoundException"/> or
    /// <see cref="DirectoryNotFoundException"/> reading its attributes threw (which does not follow a link, so a
    /// dangling link still exists) — or <c>null</c> when it exists or the read failed for any other reason (access
    /// denied, a malformed path), which is NOT read as missing and so keeps its own reason. For naming a listed file
    /// that is gone at scan time (ADR 0034); never a decision to scan or skip it.
    /// </summary>
    internal static IOException? Missing(string? path)
    {
        try
        {
            File.GetAttributes(path!);
            return null;
        }
        catch (IOException ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return ex;
        }
        catch
        {
            return null;
        }
    }
    #endregion
}
