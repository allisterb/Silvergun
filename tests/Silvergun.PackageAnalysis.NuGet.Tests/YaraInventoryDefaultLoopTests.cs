namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// ADR 0034 decision 2 through the interface's DEFAULT <see cref="IYaraScanner.ScanFiles"/> loop: the path of
/// <c>LibYaraScanner</c>, the explicit Windows fallback, which overrides neither <c>ScanFiles</c> nor
/// <c>ScanDirectory</c>. Coverage is judged against the list it is handed, not against the tree as it is now: a listed
/// file that is gone at scan time is unscanned (<see cref="YaraScanIncompleteException"/>, every other file's hits
/// carried), never silently absent from a completed scan.
///
/// <para>The cross-platform half drives the loop with <see cref="ContentScanner"/>, a fake whose <c>ScanFile</c> reads the
/// file and keeps the per-file contract every real backend keeps (a missing file is not scanned: it throws, ADR 0032
/// decision 5). The <c>#if WINDOWS</c> half repeats the headline cases with the REAL in-process <see cref="LibYaraScanner"/>
/// and the <see cref="HermeticWiperSample"/> positive, so the claim is about a real engine's real output.</para>
///
/// <para>"The list" is always taken exactly as <c>NuGetPackage.Open</c> takes a package's YARA inventory,
/// <c>Directory.GetFiles(root, "*", AllDirectories)</c>, and the tree is disturbed only afterwards.</para>
/// </summary>
public sealed class YaraInventoryDefaultLoopTests
{
    #region Methods: a listed file that is gone
    // The headline (verification (a) for the default loop): one listed file deleted after it was listed. The loop still
    // hands it to ScanFile, which reports it unscanned; the scan is incomplete, names it, and keeps the other file's hit.
    [Fact]
    public void ScanFiles_WithAListedFileDeletedBeforeTheCall_IsIncomplete_NamesIt_AndKeepsTheOtherFilesHit()
    {
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.bin", Evil));
        var gone = Path.GetFullPath(tree.Write("content/gone.bin", Evil));
        tree.Write("content/clean.txt", "ordinary text\n");
        var listed = Inventory(tree.Root);
        File.Delete(gone);
        IYaraScanner scanner = new ContentScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Contains(gone, ((ContentScanner)scanner).Visited);   // the listed file was asked for, not skipped
        Assert.Equal(payload, Assert.Single(ex.PartialFindings).FullPath);
        // Named as gone, under the singular clause, and with no "others" (it is the only unscanned file).
        Assert.Equal(
            $"YARA could not scan 1 of 3 file(s) under '{tree.Root}': 1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.bin")}'. 1 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // Every listed file gone (Storage Sense swept the whole package): incomplete, never the empty list that would read
    // as "scanned, clean". Before ADR 0034 this was exactly a clean report.
    [Fact]
    public void ScanFiles_WithEveryListedFileDeleted_IsIncomplete_NeverEmpty()
    {
        using var tree = new TempTree();
        tree.Write("content/a.bin", Evil);
        tree.Write("content/b.bin", "ordinary text\n");
        var listed = Inventory(tree.Root);
        foreach (var file in listed)
            File.Delete(file);
        IYaraScanner scanner = new ContentScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, listed));

        Assert.Empty(ex.PartialFindings);
        Assert.Contains("could not scan 2 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains(": 2 of them no longer exist (each removed after it was listed): ", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the others", ex.Message, StringComparison.Ordinal);
    }

    // The root itself gone: still the list's files, all unscanned.
    [Fact]
    public void ScanFiles_WhenTheRootIsDeleted_IsIncomplete()
    {
        using var tree = new TempTree();
        var root = Path.Combine(tree.Root, "extracted");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        File.WriteAllText(Path.Combine(root, "content", "a.bin"), Evil);
        var listed = Inventory(root);
        Directory.Delete(root, recursive: true);
        IYaraScanner scanner = new ContentScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(root, listed));

        Assert.Contains("could not scan 1 of 1 file(s)", ex.Message, StringComparison.Ordinal);
        // A missing ANCESTOR is gone too (DirectoryNotFound through YaraTree.Missing), and named as such.
        Assert.Contains(": 1 of them no longer exists (removed after it was listed): ", ex.Message, StringComparison.Ordinal);
    }

    // "Exactly these files", in the other direction too: a file that appeared after the list was taken is not the
    // list's, so the loop never hands it to the engine (and the scan of the list completes).
    [Fact]
    public void ScanFiles_ScansExactlyTheList_NotAFileAddedAfterIt()
    {
        using var tree = new TempTree();
        var listedFile = Path.GetFullPath(tree.Write("content/a.bin", Evil));
        var listed = Inventory(tree.Root);
        var late = Path.GetFullPath(tree.Write("content/late.bin", Evil));
        var scanner = new ContentScanner();

        var hits = ((IYaraScanner)scanner).ScanFiles(tree.Root, listed);

        Assert.Equal(listedFile, Assert.Single(hits).FullPath);
        Assert.DoesNotContain(late, scanner.Visited);
    }

    // An attacker-authored name reaches the message escaped, never raw. A bidi override is legal on NTFS and ext4 alike.
    [Fact]
    public void ScanFiles_ADeletedFileWithABidiName_IsNamedEscaped()
    {
        using var tree = new TempTree();
        var gone = Path.GetFullPath(tree.Write($"content/exe.{Rlo}txt.bin", Evil));
        tree.Write("content/ok.bin", "ordinary text\n");
        var listed = Inventory(tree.Root);
        File.Delete(gone);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)new ContentScanner()).ScanFiles(tree.Root, listed));

        Assert.Contains("exe." + EscapedRlo + "txt.bin", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }

    // The same for a C0 control character, which only Linux can stage as a file name.
    [LinuxFact]
    public void ScanFiles_ADeletedFileWithAControlCharacterName_IsNamedEscaped()
    {
        using var tree = new TempTree();
        var gone = tree.Write("content/n" + (char)0x0A + "l.bin", Evil);
        tree.Write("content/ok.bin", "ordinary text\n");
        var listed = Inventory(tree.Root);
        File.Delete(gone);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)new ContentScanner()).ScanFiles(tree.Root, listed));

        Assert.Contains(@"n\nl.bin", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }
    #endregion

    #region Methods: the edges of the contract
    // An empty list is nothing to scan: empty, and the engine is never asked.
    [Fact]
    public void ScanFiles_WithAnEmptyList_ReturnsEmpty_WithoutScanningAnything()
    {
        using var tree = new TempTree();
        tree.Write("content/a.bin", Evil);
        var scanner = new ContentScanner();

        Assert.Empty(((IYaraScanner)scanner).ScanFiles(tree.Root, []));
        Assert.Empty(scanner.Visited);
    }

    [Fact]
    public void ScanFiles_WithANullList_ThrowsArgumentNullException()
    {
        using var tree = new TempTree();

        Assert.Throws<ArgumentNullException>(() => ((IYaraScanner)new ContentScanner()).ScanFiles(tree.Root, null!));
    }

    // No behaviour change for an undisturbed package (the task's constraint): over the tree as it stands, scanning the
    // list is scanning the directory, hit for hit — on a tree with hits and on a clean one.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanFiles_OverAnUndisturbedTree_ReturnsWhatScanDirectoryReturns(bool withHits)
    {
        using var tree = new TempTree();
        tree.Write("content/a.bin", withHits ? Evil : "ordinary text\n");
        tree.Write("content/nested/b.bin", withHits ? Evil : "ordinary text\n");
        tree.Write("content/c.txt", "ordinary text\n");
        IYaraScanner scanner = new ContentScanner();

        var viaFiles = scanner.ScanFiles(tree.Root, Inventory(tree.Root));
        var viaDirectory = scanner.ScanDirectory(tree.Root);

        Assert.Equal(Keys(viaDirectory), Keys(viaFiles));
        Assert.Equal(withHits ? 2 : 0, viaFiles.Count);
    }
    #endregion

#if WINDOWS
    #region Methods: the real in-process engine (LibYaraScanner, net10.0-windows)
    // Verification (a) with libyara itself: the deleted listed file is unscanned (LibYaraScanner.ScanFile throws for a
    // missing file and logs why), and the HermeticWiper positive in the other file is a real, carried detection.
    [Fact]
    public void LibYara_ScanFiles_WithAListedFileDeleted_IsIncomplete_AndKeepsTheRealHit()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        using var tree = new TempTree();
        var payload = Path.GetFullPath(tree.Write("content/payload.dll", HermeticWiperSample.Bytes));
        var gone = Path.GetFullPath(tree.Write("content/gone.dll", HermeticWiperSample.Bytes));
        var listed = Inventory(tree.Root);
        File.Delete(gone);
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanFiles(tree.Root, listed));

        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        // The engine's own per-file exception carries the FileNotFound that proves the file gone, so the loop leads with it.
        Assert.Equal(
            $"YARA could not scan 1 of 2 file(s) under '{tree.Root}': 1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.dll")}'. 1 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
        Assert.Contains(warnings.Warnings, w => w == $"Skipping YARA scan for {gone}: it no longer exists (removed after it was listed).");
    }

    // LibYaraScanner.ScanFile on a listed file that is gone (ADR 0034, I4): named as removed, with the FileNotFound that
    // said so as the inner exception (the signal YaraScanLoop.Run keys on), and the warning says the same.
    [Fact]
    public void LibYara_ScanFile_ForAMissingFile_SaysItNoLongerExists_WithTheFileNotFoundAsInner()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would short-circuit before the missing-file check.");
        using var tree = new TempTree();
        var gone = Path.GetFullPath(tree.Write("content/gone.dll", "x"));
        File.Delete(gone);
        using var warnings = new WarningCapture();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(gone));

        Assert.Equal($"YARA did not scan '{gone}': it no longer exists (removed after it was listed). This file was NOT scanned and must not be reported as clean.", ex.Message);
        Assert.IsType<FileNotFoundException>(ex.InnerException);
        Assert.Contains(warnings.Warnings, w => w == $"Skipping YARA scan for {gone}: it no longer exists (removed after it was listed).");
    }

    // The same when a DIRECTORY on the way is gone: the inner exception is then DirectoryNotFound, still "gone".
    [Fact]
    public void LibYara_ScanFile_ForAFileUnderAMissingDirectory_SaysItNoLongerExists_WithTheDirectoryNotFoundAsInner()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would short-circuit before the missing-file check.");
        using var tree = new TempTree();
        var gone = Path.GetFullPath(Path.Combine(tree.Root, "content", "vanished", "a.dll"));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(gone));

        Assert.Contains(": it no longer exists (removed after it was listed). ", ex.Message, StringComparison.Ordinal);
        Assert.IsType<DirectoryNotFoundException>(ex.InnerException);
    }

    // Every OTHER way File.Exists says false keeps "file not found on disk", and no inner exception: a directory path
    // exists, so it is not "gone", and the loop must not name it as removed.
    [Fact]
    public void LibYara_ScanFile_ForADirectoryPath_KeepsFileNotFoundOnDisk_WithNoInner()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; ScanFile would short-circuit before the missing-file check.");
        using var tree = new TempTree();
        var directory = Path.Combine(tree.Root, "content");
        Directory.CreateDirectory(directory);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(directory));

        Assert.Equal($"YARA did not scan '{directory}': file not found on disk. This file was NOT scanned and must not be reported as clean.", ex.Message);
        Assert.Null(ex.InnerException);
    }

    // Through the real engine's ScanFiles: one gone and one not-gone unscanned file (a directory path in the list). The
    // gone one leads under its own clause; the other follows under "the others", each named once.
    [Fact]
    public void LibYara_ScanFiles_WithAGoneAndAnotherUnscannedFile_LeadsWithTheGoneClause()
    {
        IYaraScanner scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        using var tree = new TempTree();
        var directory = Path.Combine(tree.Root, "content", "adir");
        Directory.CreateDirectory(directory);
        var gone = Path.Combine(tree.Root, "content", "gone.dll");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, [directory, gone]));

        Assert.Equal(
            $"YARA could not scan 2 of 2 file(s) under '{tree.Root}': 1 of them no longer exists (removed after it was listed): '{Path.Combine("content", "gone.dll")}'; the others: '{Path.Combine("content", "adir")}'. 0 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    [Fact]
    public void LibYara_ScanFiles_WithEveryListedFileDeleted_IsIncomplete_NeverEmpty()
    {
        var scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        using var tree = new TempTree();
        tree.Write("content/payload.dll", HermeticWiperSample.Bytes);
        tree.Write("content/notes.txt", "ordinary text\n");
        var listed = Inventory(tree.Root);
        foreach (var file in listed)
            File.Delete(file);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanFiles(tree.Root, listed));

        Assert.Empty(ex.PartialFindings);
        Assert.Contains("could not scan 2 of 2 file(s)", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void LibYara_ScanFiles_OverAnUndisturbedTree_ReturnsWhatScanDirectoryReturns(bool withHits)
    {
        IYaraScanner scanner = new LibYaraScanner();
        Assert.True(scanner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        using var tree = new TempTree();
        if (withHits)
            tree.Write("content/payload.dll", HermeticWiperSample.Bytes);
        tree.Write("content/notes.txt", "ordinary text\n");

        var viaFiles = scanner.ScanFiles(tree.Root, Inventory(tree.Root));
        var viaDirectory = scanner.ScanDirectory(tree.Root);

        Assert.Equal(Keys(viaDirectory), Keys(viaFiles));
        Assert.Equal(withHits, viaFiles.Any(h => h.Match.Rule == HermeticWiperSample.RuleName));
    }
    #endregion
#endif

    #region Helpers
    // A package's YARA inventory is taken with exactly this call (NuGetPackage.Open).
    internal static string[] Inventory(string root) => Directory.GetFiles(root, "*", SearchOption.AllDirectories);

    // A scan's hits as comparable keys, ordered.
    internal static string[] Keys(IEnumerable<(string FullPath, YaraMatch Match)> hits) =>
        hits.Select(h => $"{Path.GetFullPath(h.FullPath)}|{h.Match.Namespace}|{h.Match.Rule}").Order(StringComparer.Ordinal).ToArray();

    private static YaraMatch Match(string rule) => new(rule, null, [], []);

    private const string Evil = "EVIL marker content\n";

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw, and the
    // backslash-u form YaraPathSafety.Escape renders it as.
    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion

    #region Nested types
    // A healthy backend shaped exactly like LibYaraScanner: ScanFiles is the shared per-file loop (YaraScanLoop.Run) over
    // its own ScanFile, and ScanDirectory is the interface's default enumeration over that. ScanFile keeps the per-file
    // contract (ADR 0032 decision 5) the way LibYaraScanner does: a file that is not on disk was not scanned, and says so
    // by throwing — with the FileNotFound/DirectoryNotFound that proves it gone as the inner exception (YaraTree.Missing,
    // the same call LibYaraScanner makes), which is what lets the loop name it as removed; otherwise it "matches" files
    // whose text holds the marker. Every path it is handed is recorded.
    private sealed class ContentScanner : IYaraScanner
    {
        public bool Available => true;

        public List<string> Visited { get; } = [];

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            YaraScanLoop.Run(this, rootDir, files);

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
        {
            Visited.Add(fullPath);
            if (!File.Exists(fullPath))
            {
                var gone = YaraTree.Missing(fullPath);
                throw new YaraScanIncompleteException(
                    $"YARA did not scan '{YaraPathSafety.Escape(fullPath)}': {(gone is null ? "file not found on disk" : YaraPathSafety.NoLongerExists)}. This file was NOT scanned and must not be reported as clean.",
                    gone);
            }
            return File.ReadAllText(fullPath).Contains("EVIL", StringComparison.Ordinal) ? [Match("Content_Rule")] : [];
        }
    }
    #endregion
}
