namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The per-file loop that implements <see cref="IYaraScanner.ScanFiles"/> on top of <see cref="IYaraScanner.ScanFile"/>,
/// for a backend whose cheap primitive is one file (<c>LibYaraScanner</c>, the explicit Windows fallback). It is a
/// helper a backend calls, not an interface default: a default <c>ScanFiles</c> silently changed what a
/// <c>ScanDirectory</c>-only implementer covered and lost its hits (measured, ADR 0034 review W1), so every backend now
/// states how it scans a list, and this is one way to.
/// </summary>
internal static class YaraScanLoop
{
    #region Methods
    /// <summary>
    /// Scans <b>exactly</b> <paramref name="files"/> with <paramref name="scanner"/>'s <see cref="IYaraScanner.ScanFile"/>,
    /// one at a time, and returns each hit paired with the listed path of the file it matched (ADR 0034 decision 2).
    /// <paramref name="rootDir"/> only renders the files relative in messages; it is never enumerated.
    ///
    /// Per file (ADR 0032 decision 6): a <see cref="YaraScanIncompleteException"/> — which <see cref="IYaraScanner.ScanFile"/>
    /// throws for a missing file — records that file as unscanned (its own partial hits, if any, are kept) and the loop
    /// <b>continues</b>; a <see cref="TimeoutException"/> <b>stops</b> the loop, because a bound that was reached means the
    /// engine's health can no longer be vouched for and the remaining files' "no matches" would not be trustworthy either
    /// (ADR 0028 decision 10), and is rethrown as <see cref="YaraScanIncompleteException"/> with the hits so far and the
    /// timeout as <see cref="Exception.InnerException"/>. After the loop, any unscanned file means the same exception,
    /// carrying all the hits. Any other exception from <see cref="IYaraScanner.ScanFile"/> propagates unchanged.
    ///
    /// Messages name the unscanned files escaped and bounded, and lead with the ones that <b>no longer exist</b>: a file
    /// whose exception carries a <see cref="FileNotFoundException"/> or <see cref="DirectoryNotFoundException"/> as its
    /// <see cref="Exception.InnerException"/> <b>and</b> that is confirmed missing on disk (<see cref="YaraTree.Missing"/>,
    /// the predicate the CLI backend's own check uses) is named as removed after it was listed, ahead of the rest, so the
    /// report's bounded reason keeps that cause. The inner exception alone is not evidence: libyara.NET throws
    /// <see cref="FileNotFoundException"/> for ANY failure to open a file, a share lock or an ACL denial on a file that
    /// exists included (measured), and such a file must keep the plain unscanned wording.
    /// </summary>
    internal static IReadOnlyList<(string FullPath, YaraMatch Match)> Run(
        IYaraScanner scanner, string rootDir, IReadOnlyList<string> files)
    {
        ArgumentNullException.ThrowIfNull(scanner);
        ArgumentNullException.ThrowIfNull(files);

        var hits = new List<(string FullPath, YaraMatch Match)>();
        var unscanned = new List<(string File, bool Gone)>();
        for (var i = 0; i < files.Count; i++)
        {
            var file = files[i];
            try
            {
                hits.AddRange(scanner.ScanFile(file).Select(match => (file, match)));
            }
            catch (YaraScanIncompleteException ex)
            {
                hits.AddRange(ex.PartialFindings);
                unscanned.Add((file, IsGone(ex, file)));
            }
            catch (TimeoutException ex)
            {
                var remaining = files.Count - i - 1;
                throw new YaraScanIncompleteException(
                    $"YARA timed out scanning '{YaraPathSafety.Escape(YaraPathSafety.Relative(rootDir, file))}' under '{YaraPathSafety.Escape(rootDir)}', so that file was not scanned and the engine's health can no longer be vouched for"
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
                $"YARA could not scan {unscanned.Count} of {files.Count} file(s) under '{YaraPathSafety.Escape(rootDir)}': {DescribeUnscanned(rootDir, unscanned)}. {hits.Count} hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
                null,
                hits);
    }

    // Whether an unscanned file is gone: its exception says not-found AND the disk agrees (see Run's summary).
    private static bool IsGone(YaraScanIncompleteException ex, string file) =>
        ex.InnerException is FileNotFoundException or DirectoryNotFoundException && YaraTree.Missing(file) is not null;

    // The unscanned files for an exception message: the ones that no longer exist first, under their own clause, then
    // the others; each root-relative where possible, control-escaped (the names are attacker-authored and the message is
    // logged verbatim), and bounded so a package of thousands cannot flood it — through the one rendering every YARA
    // message shares (YaraPathSafety.Bounded). The relative form is the lexical YaraPathSafety.Relative, deliberately not
    // Path.GetRelativePath (ADR 0030, sixth instance).
    private static string DescribeUnscanned(string rootDir, IReadOnlyList<(string File, bool Gone)> unscanned)
    {
        var parts = unscanned.ToLookup(u => u.Gone, u => YaraPathSafety.Relative(rootDir, u.File));
        var (gone, others) = (parts[true].ToArray(), parts[false].ToArray());
        return gone.Length == 0
            ? YaraPathSafety.Bounded(others)
            : $"{YaraPathSafety.NoLongerExist(gone.Length)}: {YaraPathSafety.Bounded(gone)}"
              + (others.Length == 0 ? string.Empty : $"; the others: {YaraPathSafety.Bounded(others)}");
    }
    #endregion
}
