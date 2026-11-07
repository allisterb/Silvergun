namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using Xunit;

/// <summary>
/// The harness's <see cref="Program.DisplayPath(string)"/> and <see cref="Program.Redact(string)"/>, which keep the
/// machine's account name out of committed reports: a path under local app-data or the user profile is printed from
/// <c>%LOCALAPPDATA%</c> or <c>%USERPROFILE%</c> (<c>~</c> for the home folder off Windows). Covers the root matching
/// rules, the free-text rules, <see cref="ReachabilityCorpusReport.Deterministic"/>'s order (temp first), the writers other
/// than the reachability report that print a cache root or a free-text reason (<see cref="CorpusReport"/>,
/// <see cref="WorkerParity"/>), and the default <c>--out</c>, <c>data/results</c>. The reachability report's rows are
/// covered in <see cref="ReachabilityR2bHarnessTests"/>.
/// <para>
/// The synthetic-root tests build their roots and paths from this OS's root and separator (<see cref="Rooted"/>), so
/// they hold on Windows and off it. The machine tests read the real special folders and are guarded by OS: the names
/// differ (<c>%LOCALAPPDATA%</c>/<c>%USERPROFILE%</c> on Windows, <c>~</c> elsewhere).
/// </para>
/// </summary>
public sealed class HarnessDisplayPathTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // DisplayPath(path, roots)
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void DisplayPath_WhenPathIsExactlyTheRoot_ReturnsTheName()
    {
        Assert.Equal(U, Program.DisplayPath(Alice, [(Alice, U)]));
    }

    [Fact]
    public void DisplayPath_WhenPathContinuesWithTheSeparator_ReplacesTheRoot()
    {
        Assert.Equal(Path.Combine(U, "cache", "x"), Program.DisplayPath(Path.Combine(Alice, "cache", "x"), [(Alice, U)]));
    }

    // '/' is the alternate separator on Windows and the separator elsewhere: either way the root ends there.
    [Fact]
    public void DisplayPath_WhenPathContinuesWithAForwardSlash_ReplacesTheRootAndKeepsTheRest()
    {
        Assert.Equal(U + "/cache/x", Program.DisplayPath(Alice + "/cache/x", [(Alice, U)]));
    }

    [Fact]
    public void DisplayPath_MatchesTheRootCaseInsensitively()
    {
        Assert.Equal(U + Separator + "Cache", Program.DisplayPath(Alice.ToUpperInvariant() + Separator + "Cache", [(Alice, U)]));
    }

    [Fact]
    public void DisplayPath_WhenTheRootHasATrailingSeparator_StillMatchesAndKeepsOneSeparator()
    {
        IReadOnlyList<(string, string)> roots = [(Alice + Separator, U)];

        Assert.Equal(Path.Combine(U, "cache"), Program.DisplayPath(Path.Combine(Alice, "cache"), roots));
        Assert.Equal(U, Program.DisplayPath(Alice, roots));
    }

    // Whole segments only: <root>/Users/Al is a prefix of <root>/Users/Alice's text but not one of its directories.
    [Fact]
    public void DisplayPath_WhenASiblingMerelySharesThePrefix_DoesNotMatch()
    {
        var path = Path.Combine(Alice, "x");

        Assert.Equal(path, Program.DisplayPath(path, [(Rooted("Users", "Al"), U)]));
    }

    // Local app-data is under the profile, so both match; the first listed wins, in either order (first, not longest).
    [Fact]
    public void DisplayPath_WhenTwoRootsMatch_TheFirstListedWins()
    {
        var local = Path.Combine(Alice, "AppData", "Local");
        var path = Path.Combine(local, "Silvergun", "benign-corpus");

        Assert.Equal(Path.Combine(L, "Silvergun", "benign-corpus"), Program.DisplayPath(path, [(local, L), (Alice, U)]));
        Assert.Equal(Path.Combine(U, "AppData", "Local", "Silvergun", "benign-corpus"), Program.DisplayPath(path, [(Alice, U), (local, L)]));
    }

    // An unset special folder is the empty string; as a root it would otherwise prefix every path.
    [Fact]
    public void DisplayPath_IgnoresAnEmptyRoot()
    {
        Assert.Equal(Rooted("cache"), Program.DisplayPath(Rooted("cache"), [(string.Empty, "%EMPTY%")]));
        Assert.Equal(Path.Combine(U, "x"), Program.DisplayPath(Path.Combine(Alice, "x"), [(string.Empty, "%EMPTY%"), (Alice, U)]));
    }

    [Fact]
    public void DisplayPath_WhenNoRootMatches_ReturnsThePathUnchanged()
    {
        var path = Rooted("corpus", "cache");

        Assert.Equal(path, Program.DisplayPath(path, [(Path.Combine(Alice, "AppData", "Local"), L), (Alice, U)]));
        Assert.Equal(path, Program.DisplayPath(path, []));
    }

    // ---------------------------------------------------------------------------------------------------
    // Redact(text, roots)
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Redact_ReplacesARootInTheMiddleOfASentence()
    {
        Assert.Equal($"Failed to load assembly {Path.Combine(U, "x", "y.dll")}.",
            Program.Redact($"Failed to load assembly {Path.Combine(Alice, "x", "y.dll")}.", [(Alice, U)]));
    }

    // At the start, after a quote, before a separator, before punctuation and at the very end.
    [Fact]
    public void Redact_ReplacesEveryOccurrence()
    {
        var text = $"{Path.Combine(Alice, "a")} then '{Path.Combine(Alice, "b")}', {Alice}. Again: {Alice}";

        Assert.Equal($"{Path.Combine(U, "a")} then '{Path.Combine(U, "b")}', {U}. Again: {U}", Program.Redact(text, [(Alice, U)]));
    }

    [Fact]
    public void Redact_MatchesTheRootCaseInsensitively()
    {
        Assert.Equal($"at {Path.Combine(U, "x")} and {Path.Combine(U, "y")}",
            Program.Redact($"at {Path.Combine(Alice.ToUpperInvariant(), "x")} and {Path.Combine(Alice.ToLowerInvariant(), "y")}", [(Alice, U)]));
    }

    // <root>2, <root>-old, <root>_bak and <root>B name another folder: the root is not a whole segment of them.
    [Theory]
    [InlineData("2")]
    [InlineData("-old")]
    [InlineData("_bak")]
    [InlineData("B")]
    public void Redact_WhenTheRootIsFollowedByANameCharacter_LeavesItAlone(string suffix)
    {
        var text = $"moved to {Path.Combine(Alice + suffix, "x")} from {Alice + suffix}";

        Assert.Equal(text, Program.Redact(text, [(Alice, U)]));
    }

    [Fact]
    public void Redact_TrimsTheRootsTrailingSeparator()
    {
        Assert.Equal($"at {Path.Combine(U, "x")} and {U}.", Program.Redact($"at {Path.Combine(Alice, "x")} and {Alice}.", [(Alice + Separator, U)]));
    }

    // ProfileRoots lists local app-data first, so <profile>/AppData/Local/x is printed from %LOCALAPPDATA%; listed the
    // other way round, the profile would claim it.
    [Fact]
    public void Redact_WithLocalAppDataListedFirst_PrintsItsPathsFromLocalAppData()
    {
        var local = Path.Combine(Alice, "AppData", "Local");
        var text = $"{Path.Combine(local, "x")} and {Path.Combine(Alice, "y")}";

        Assert.Equal($"{Path.Combine(L, "x")} and {Path.Combine(U, "y")}", Program.Redact(text, [(local, L), (Alice, U)]));
        Assert.Equal($"{Path.Combine(U, "AppData", "Local", "x")} and {Path.Combine(U, "y")}", Program.Redact(text, [(Alice, U), (local, L)]));
    }

    // An empty root would match everywhere and this OS's bare root (C:\ on Windows, / elsewhere) almost everywhere: both
    // are skipped, and a later real root still applies.
    [Fact]
    public void Redact_IgnoresEmptyAndBareRoots()
    {
        var text = $"{Rooted("cache", "x")} and {Path.Combine(Alice, "y")} / {Rooted()}";

        Assert.Equal($"{Rooted("cache", "x")} and {Path.Combine(U, "y")} / {Rooted()}",
            Program.Redact(text, [(string.Empty, "%EMPTY%"), (Rooted(), "%BARE%"), (Alice, U)]));
    }

    // "/" is a bare root on every OS (on Windows the root of the current drive), so it is skipped everywhere.
    [Fact]
    public void Redact_IgnoresTheSlashRoot()
    {
        const string text = "a / b, /c and /";

        Assert.Equal(text, Program.Redact(text, [("/", "%SLASH%")]));
    }

    // $0, $1, ${x} and $$ are substitution syntax in Regex.Replace: the name must be inserted as written.
    [Fact]
    public void Redact_InsertsANameContainingDollarsLiterally()
    {
        const string name = "$0$1${x}$$";

        Assert.Equal($"at {Path.Combine(name, "x")}", Program.Redact($"at {Path.Combine(Alice, "x")}", [(Alice, name)]));
    }

    [Fact]
    public void Redact_WhenNoRootOccurs_ReturnsTheTextUnchanged()
    {
        var text = $"nothing here: {Rooted("corpus", "x.dll")} (exit 35)";

        Assert.Equal(text, Program.Redact(text, [(Path.Combine(Alice, "AppData", "Local"), L), (Alice, U)]));
        Assert.Equal(text, Program.Redact(text, []));
        Assert.Equal(string.Empty, Program.Redact(string.Empty, [(Alice, U)]));
    }

    // ---------------------------------------------------------------------------------------------------
    // DisplayPath(path) and Redact(text) on this machine
    // ---------------------------------------------------------------------------------------------------

    // The default cache root (Program.DefaultCacheRoot) is <local app-data>\Silvergun\benign-corpus.
    [Fact]
    public void DisplayPath_OnWindows_PrintsTheDefaultCacheRootFromLocalAppData()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local)
            return; // %LOCALAPPDATA% is a Windows name; off Windows see the ~ test below.

        Assert.Equal(Path.Combine(L, "Silvergun", "benign-corpus"), Program.DisplayPath(Path.Combine(local, "Silvergun", "benign-corpus")));
    }

    [Fact]
    public void DisplayPath_OnWindows_PrintsOtherProfilePathsFromUserProfile()
    {
        if (!OperatingSystem.IsWindows() || NotUnderLocalAppData("silvergun-not-local") is not { } path)
            return; // Needs Windows and a profile folder that does not itself lie under local app-data.

        Assert.Equal(Path.Combine(U, "silvergun-not-local"), Program.DisplayPath(path));
    }

    [Fact]
    public void Redact_OnWindows_PrintsLocalAppDataAndProfilePathsByName()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local || NotUnderLocalAppData("y") is not { } profilePath)
            return;

        Assert.Equal($"Failed to load {Path.Combine(L, "x.dll")} from {Path.Combine(U, "y")}.",
            Program.Redact($"Failed to load {Path.Combine(local, "x.dll")} from {profilePath}."));
    }

    // Off Windows only the home folder is mapped, to ~ (local app-data, ~/.local/share, is under it).
    [Fact]
    public void DisplayPathAndRedact_OffWindows_PrintTheHomeFolderAsTilde()
    {
        if (OperatingSystem.IsWindows() || UserProfile is not { Length: > 1 } home)
            return; // A home of "" or "/" is ignored by design: nothing to map.

        Assert.Equal(Path.Combine("~", "x"), Program.DisplayPath(Path.Combine(home, "x")));
        Assert.Equal($"Failed to load {Path.Combine("~", "x.dll")}.", Program.Redact($"Failed to load {Path.Combine(home, "x.dll")}."));
    }

    // Deterministic masks the temp directory before redacting: on Windows the temp directory is under local app-data, and
    // must still read <temp>/..., not %LOCALAPPDATA%\Temp\... (two runs with different temp settings stay comparable).
    [Fact]
    public void Deterministic_MasksTheTempDirectoryBeforeRedactingProfilePaths()
    {
        var path = Path.Combine(Path.GetTempPath(), "silvergun", "pkg-abcdef012345", "x.dll");

        var masked = ReachabilityCorpusReport.Deterministic($"load failed: {path}");

        Assert.Equal($"load failed: <temp>/{Path.Combine("silvergun", "pkg-<random>", "x.dll")}", masked);
        Assert.DoesNotContain(L, masked);
        Assert.DoesNotContain(U, masked);
        if (OperatingSystem.IsWindows() && LocalAppData is { Length: > 0 } local && path.StartsWith(local + Separator, StringComparison.OrdinalIgnoreCase))
            Assert.StartsWith(L, Program.Redact(path)); // The premise: redacting first would have named local app-data.
    }

    // ---------------------------------------------------------------------------------------------------
    // The writers
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void CorpusReport_WriteMarkdown_PrintsTheCacheRootWithoutTheAccountName()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local)
            return;
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "density.md");

        CorpusReport.WriteMarkdown(path, "density.tsv", new DateOnly(2026, 11, 7), Manifest(dir), Path.Combine(local, "Silvergun", "benign-corpus"), []);

        AssertNoAccountPath(File.ReadAllText(path), $"| `{Path.Combine(L, "Silvergun", "benign-corpus")}` |");
    }

    [Fact]
    public void CorpusReport_WriteIndicatorMarkdown_PrintsTheCacheRootWithoutTheAccountName()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local)
            return;
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "indicators.md");

        CorpusReport.WriteIndicatorMarkdown(path, "indicators.tsv", new DateOnly(2026, 11, 7), Manifest(dir), Path.Combine(local, "Silvergun", "benign-corpus"), []);

        AssertNoAccountPath(File.ReadAllText(path), $"| `{Path.Combine(L, "Silvergun", "benign-corpus")}` |");
    }

    // An incomplete package's Note (an exception message naming an extracted file) is free text: the Reason column redacts
    // it. The cache root is elsewhere, so only the note could name local app-data.
    [Fact]
    public void CorpusReport_WriteMarkdown_RedactsAnIncompletePackagesReason()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local)
            return;
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "density.md");

        CorpusReport.WriteMarkdown(path, "density.tsv", new DateOnly(2026, 11, 7), Manifest(dir), Rooted("corpus-cache"), [Incomplete(local)]);

        AssertNoAccountPath(File.ReadAllText(path), $"| Display.A | 1.0.0 | {PackageResult.ScanFailed} | **no** | {RedactedNote} |");
    }

    [Fact]
    public void CorpusReport_WriteIndicatorMarkdown_RedactsAnIncompletePackagesReason()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local)
            return;
        using var dir = new TempDirectory();
        var path = Path.Combine(dir.Path, "indicators.md");

        CorpusReport.WriteIndicatorMarkdown(path, "indicators.tsv", new DateOnly(2026, 11, 7), Manifest(dir), Rooted("corpus-cache"), [Incomplete(local)]);

        AssertNoAccountPath(File.ReadAllText(path), $"| Display.A | 1.0.0 | {PackageResult.ScanFailed} | **no** | {RedactedNote} |");
    }

    // A cache root that holds none of the manifest's packages: every entry is not-cached, so Run starts no child and
    // no worker and only writes its files. The cache root is only probed with File.Exists, never created.
    [Fact]
    public void WorkerParity_Summary_PrintsTheCacheRootWithoutTheAccountName()
    {
        if (!OperatingSystem.IsWindows() || LocalAppData is not { Length: > 0 } local)
            return;
        using var dir = new TempDirectory();
        var cacheName = $"silvergun-no-such-cache-{Guid.NewGuid():N}";
        var cacheRoot = Path.Combine(local, cacheName);

        var (paths, _, measured, notCached, _) = WorkerParity.Run(
            Manifest(dir), cacheRoot, "no-harness", TimeSpan.FromSeconds(1), Path.Combine(dir.Path, "out"), new DateOnly(2026, 11, 7), TextWriter.Null);
        var summary = File.ReadAllText(paths.Single(p => p.EndsWith(".md", StringComparison.Ordinal)));

        Assert.Equal((0, 2), (measured, notCached));
        Assert.False(Directory.Exists(cacheRoot));
        AssertNoAccountPath(summary, $"- cache: `{Path.Combine(L, cacheName)}`");
    }

    // ---------------------------------------------------------------------------------------------------
    // Default --out
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void ParseReachability_WithoutOut_WritesIntoDataResults()
    {
        var options = Program.ParseReachability(["--reachability", "--results", "r"])!;

        Assert.Equal(Path.Combine(RepositoryRoot(), "data", "results"), options.Common.OutputDirectory);
        Assert.Equal(Path.GetFullPath("o"), Program.ParseReachability(["--reachability", "--results", "r", "--out", "o"])!.Common.OutputDirectory);
    }

    [Fact]
    public void ParseCombine_WithoutOut_WritesIntoDataResults()
    {
        string[] full = ["--combine", "--c100-manifest", "c100.manifest", "--c100-results", "r1", "--c100-repeat", "r2", "--cbuild-results", "b1", "--cbuild-repeat", "b2"];

        Assert.Equal(Path.Combine(RepositoryRoot(), "data", "results"), Program.ParseCombine(full)!.OutputDirectory);
        Assert.Equal(Path.GetFullPath("o"), Program.ParseCombine([.. full, "--out", "o"])!.OutputDirectory);
    }

    // The report names the path by its placeholder and contains neither the expanded local app-data nor the expanded
    // profile folder (the account name is in both), as written or as a markdown escape would render it.
    private static void AssertNoAccountPath(string text, string expected)
    {
        Assert.Contains(expected, text);
        Assert.Contains(L, text);
        foreach (var root in new[] { LocalAppData, UserProfile }.Where(r => r.Length > 0))
        {
            Assert.DoesNotContain(root, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(ReachabilityCorpusReport.Escape(root), text, StringComparison.OrdinalIgnoreCase);
        }
    }

    // Two entries, neither of which any test cache holds.
    private static CorpusManifest Manifest(TempDirectory dir)
    {
        var path = Path.Combine(dir.Path, "display.manifest");
        File.WriteAllLines(path, ["Display.A,1.0.0", "Display.B,2.0.0"]);
        return CorpusManifest.Load(path, 0);
    }

    // A scan-failed package whose note names a file extracted under local app-data.
    private static PackageResult Incomplete(string local) =>
        new(new ManifestEntry("Display.A", "1.0.0"), PackageResult.ScanFailed, new TfmChoice(null, []), [], Note(local));

    private static string Note(string local) => $"BadImageFormatException: Could not load '{Path.Combine(local, "Silvergun", "benign-corpus", "extracted", "x.dll")}'.";

    // A path from this OS's filesystem root (C:\ on Windows, / elsewhere), so its separators are real ones there.
    private static string Rooted(params string[] parts) => Path.Combine([OperatingSystem.IsWindows() ? @"C:\" : "/", .. parts]);

    // <profile>/<name>, or null when there is no profile folder or the path would lie under local app-data.
    private static string? NotUnderLocalAppData(string name) =>
        UserProfile.Length > 0 && Path.Combine(UserProfile, name) is var path
            && !(LocalAppData.Length > 0 && path.StartsWith(LocalAppData, StringComparison.OrdinalIgnoreCase))
            ? path
            : null;

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, ".git")) || File.Exists(Path.Combine(dir.FullName, ".git")))
                return dir.FullName;
        throw new InvalidOperationException("no repository above the test output");
    }
    #endregion

    #region Properties
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);

    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);

    // A synthetic profile folder, <root>/Users/Alice.
    private static string Alice => Rooted("Users", "Alice");

    private static string RedactedNote => Note(L);

    private static char Separator => Path.DirectorySeparatorChar;
    #endregion

    #region Fields
    private const string L = "%LOCALAPPDATA%";
    private const string U = "%USERPROFILE%";
    #endregion

    #region Child types
    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateDirectory(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "silvergun-displaypath-tests", Guid.NewGuid().ToString("N"))).FullName;

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
    #endregion
}
