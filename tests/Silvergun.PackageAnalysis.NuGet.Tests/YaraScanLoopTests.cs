namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// <see cref="YaraScanLoop.Run"/>, called directly: the per-file loop that used to be <see cref="IYaraScanner"/>'s
/// default <c>ScanFiles</c> and is now a helper a backend calls (ADR 0034 review W1; <c>LibYaraScanner.ScanFiles</c> is
/// exactly <c>Run(this, …)</c>). It must behave as the default did — isolate a failing file and continue, stop at a
/// timeout with the remaining count, carry every hit — and, since I4, lead its messages with the files that <b>no longer
/// exist</b>: a file whose per-file exception carries a <see cref="FileNotFoundException"/> or
/// <see cref="DirectoryNotFoundException"/> as its inner exception, AND that the disk confirms missing
/// (<see cref="YaraTree.Missing"/>, I5 W-a), is named under its own clause ahead of the rest, because the report's reason
/// is bounded and a trailing clause is the first thing the bound cuts.
///
/// <para>Most paths never touch the disk: <see cref="Scripted"/> decides each file's outcome by name under a root that is
/// never created (so the disk confirms every "gone" one), and every message is deterministic and asserted whole. The
/// no-missing texts are pinned <b>byte for byte</b> against the pre-I4 format (the committed default loop's), so leading
/// the gone clause cannot have changed any other message. <see cref="OnDisk"/> covers the cases where the disk disagrees
/// with the inner exception: a file that exists is never gone, whatever its exception says.</para>
/// </summary>
public sealed class YaraScanLoopTests
{
    #region Methods: what the old default did
    // Per-file isolation (ADR 0032 decision 6): the failing file is recorded, the loop goes on, and every hit — the other
    // files' and the failing file's own partial one — travels out in the exception.
    [Fact]
    public void Run_WhenOneFileIsNotScanned_ScansTheRestAndCarriesEveryHit()
    {
        var scanner = new Scripted(name => name switch
        {
            "a.bin" or "c.bin" => Outcome.Hit,
            "b.bin" => Outcome.NotScannedWithPartialHit,
            _ => Outcome.Clean,
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("a.bin", "b.bin", "c.bin", "d.bin")));

        Assert.Equal(Files("a.bin", "b.bin", "c.bin", "d.bin"), scanner.Visited);   // the failing file did not stop it
        Assert.Equal(3, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == F("b.bin") && h.Match.Rule == "Partial");
        Assert.Null(ex.InnerException);
    }

    // A timeout stops the loop (the engine's health can no longer be vouched for): nothing after it is handed to the
    // engine, the remaining count is stated, the timeout is the inner exception, and the hits before it are carried.
    [Fact]
    public void Run_WhenAFileTimesOut_StopsThere_WithTheRemainingCount_AndTheEarlierHits()
    {
        var scanner = new Scripted(name => name == "b.bin" ? Outcome.Timeout : Outcome.Hit);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("a.bin", "b.bin", "c.bin", "d.bin")));

        Assert.Equal(Files("a.bin", "b.bin"), scanner.Visited);
        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Equal(F("a.bin"), Assert.Single(ex.PartialFindings).FullPath);
        Assert.Equal(
            $"YARA timed out scanning 'b.bin' under '{Root}', so that file was not scanned and the engine's health can no longer be vouched for; the remaining 2 file(s) were not scanned. 1 hit(s) found before that are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // Undisturbed: every hit, paired with the listed path, and no throw.
    [Fact]
    public void Run_WhenEveryFileScans_ReturnsEachHitWithItsListedPath()
    {
        var scanner = new Scripted(name => name == "clean.bin" ? Outcome.Clean : Outcome.Hit);

        var hits = YaraScanLoop.Run(scanner, Root, Files("a.bin", "clean.bin", "nested/b.bin"));

        Assert.Equal([F("a.bin"), F("nested/b.bin")], hits.Select(h => h.FullPath));
    }

    [Fact]
    public void Run_WithAnEmptyList_ReturnsEmpty_WithoutAskingTheEngine()
    {
        var scanner = new Scripted(_ => Outcome.Hit);

        Assert.Empty(YaraScanLoop.Run(scanner, Root, []));
        Assert.Empty(scanner.Visited);
    }

    [Fact]
    public void Run_WithANullScanner_ThrowsArgumentNullException() =>
        Assert.Equal("scanner", Assert.Throws<ArgumentNullException>(() => YaraScanLoop.Run(null!, Root, Files("a.bin"))).ParamName);

    [Fact]
    public void Run_WithANullList_ThrowsArgumentNullException() =>
        Assert.Equal("files", Assert.Throws<ArgumentNullException>(() => YaraScanLoop.Run(new Scripted(_ => Outcome.Hit), Root, null!)).ParamName);

    // Anything outside the contract's two exception types propagates unchanged, at the first file that throws it.
    [Fact]
    public void Run_WhenScanFileThrowsAnythingElse_PropagatesItUnchanged()
    {
        var scanner = new Scripted(_ => Outcome.Crash);

        Assert.Throws<InvalidOperationException>(() => YaraScanLoop.Run(scanner, Root, Files("a.bin", "b.bin")));
        Assert.Single(scanner.Visited);
    }
    #endregion

    #region Methods: files that no longer exist lead the message
    // ONE gone file, listed AFTER the other unscanned file: it still leads, under the singular clause, then "; the
    // others: …". Each file is named once.
    [Fact]
    public void Run_WithOneGoneFileAndOneOther_LeadsWithTheSingularClause_ThenTheOthers()
    {
        var scanner = new Scripted(name => name switch
        {
            "x.bin" => Outcome.NotScanned,
            "content/gone.bin" => Outcome.GoneFile,
            _ => Outcome.Hit,
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("x.bin", "a.bin", "content/gone.bin")));

        Assert.Equal(
            $"YARA could not scan 2 of 3 file(s) under '{Root}': 1 of them no longer exists (removed after it was listed): '{Rel("content/gone.bin")}'; the others: 'x.bin'. 1 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // TWO gone files — one a missing leaf (FileNotFound), one under a missing directory (DirectoryNotFound) — take the
    // plural clause with "each", in list order, then the others.
    [Fact]
    public void Run_WithTwoGoneFiles_LeadsWithThePluralEachClause_ThenTheOthers()
    {
        var scanner = new Scripted(name => name switch
        {
            "x.bin" => Outcome.NotScanned,
            "g1.bin" => Outcome.GoneFile,
            "vanished/g2.bin" => Outcome.GoneDirectory,
            _ => Outcome.Hit,
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("g1.bin", "x.bin", "vanished/g2.bin")));

        Assert.Equal(
            $"YARA could not scan 3 of 3 file(s) under '{Root}': 2 of them no longer exist (each removed after it was listed): 'g1.bin', '{Rel("vanished/g2.bin")}'; the others: 'x.bin'. 0 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // Only gone files: the clause, and no "the others" at all.
    [Fact]
    public void Run_WithOnlyGoneFiles_HasNoOthersClause()
    {
        var scanner = new Scripted(name => name == "keep.bin" ? Outcome.Hit : Outcome.GoneFile);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("keep.bin", "g.bin")));

        Assert.Equal(
            $"YARA could not scan 1 of 2 file(s) under '{Root}': 1 of them no longer exists (removed after it was listed): 'g.bin'. 1 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // No gone file: the message is BYTE-IDENTICAL to the pre-I4 default loop's (the committed IYaraScanner default:
    // "… under '{root}': {Bounded(relative names)}. {h} hit(s) …").
    [Fact]
    public void Run_WithNoGoneFile_TheMessageIsByteIdenticalToTheOldFormat()
    {
        var scanner = new Scripted(name => name == "a.bin" ? Outcome.Hit : Outcome.NotScanned);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("x.bin", "a.bin", "nested/y.bin")));

        Assert.Equal(
            $"YARA could not scan 2 of 3 file(s) under '{Root}': 'x.bin', '{Rel("nested/y.bin")}'. 1 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // Only FileNotFound/DirectoryNotFound mean gone. Some other IOException as the inner cause (a share violation, access
    // denied) is an ordinary unscanned file, and the text stays the old one.
    [Fact]
    public void Run_WhenTheInnerIsAnotherIOException_ItIsNotNamedAsGone()
    {
        var scanner = new Scripted(name => name == "locked.bin" ? Outcome.NotScannedWithIOException : Outcome.Hit);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("locked.bin")));

        Assert.Equal(
            $"YARA could not scan 1 of 1 file(s) under '{Root}': 'locked.bin'. 0 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // The timeout message's "earlier file(s)" clause renders gone files the same way: leading, under their clause.
    [Fact]
    public void Run_WhenATimeoutFollowsAGoneAndAnUnscannedFile_TheEarlierClauseLeadsWithTheGoneOne()
    {
        var scanner = new Scripted(name => name switch
        {
            "x.bin" => Outcome.NotScanned,
            "content/gone.bin" => Outcome.GoneFile,
            "slow.bin" => Outcome.Timeout,
            _ => Outcome.Hit,
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() =>
            YaraScanLoop.Run(scanner, Root, Files("x.bin", "a.bin", "content/gone.bin", "slow.bin", "after.bin")));

        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Equal(
            $"YARA timed out scanning 'slow.bin' under '{Root}', so that file was not scanned and the engine's health can no longer be vouched for; the remaining 1 file(s) were not scanned; 2 earlier file(s) were not scanned either: 1 of them no longer exists (removed after it was listed): '{Rel("content/gone.bin")}'; the others: 'x.bin'. 1 hit(s) found before that are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // ...and with no gone file, the timeout text is byte-identical to the old one.
    [Fact]
    public void Run_WhenATimeoutFollowsAnUnscannedFile_WithNoGoneFile_TheMessageIsByteIdenticalToTheOldFormat()
    {
        var scanner = new Scripted(name => name switch
        {
            "x.bin" => Outcome.NotScanned,
            "slow.bin" => Outcome.Timeout,
            _ => Outcome.Hit,
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files("x.bin", "slow.bin")));

        Assert.Equal(
            $"YARA timed out scanning 'slow.bin' under '{Root}', so that file was not scanned and the engine's health can no longer be vouched for; 1 earlier file(s) were not scanned either: 'x.bin'. 0 hit(s) found before that are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // Both lists stay bounded (ten names, then a count), each on its own: 12 gone and 12 others.
    [Fact]
    public void Run_WithManyGoneAndManyOtherFiles_BoundsEachListSeparately()
    {
        var gone = Enumerable.Range(0, 12).Select(i => $"g{i:D2}.bin").ToArray();
        var others = Enumerable.Range(0, 12).Select(i => $"u{i:D2}.bin").ToArray();
        var scanner = new Scripted(name => name.StartsWith('g') ? Outcome.GoneFile : Outcome.NotScanned);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files([.. others, .. gone])));

        Assert.Contains(
            ": 12 of them no longer exist (each removed after it was listed): " + string.Join(", ", gone.Take(10).Select(g => $"'{g}'")) + ", and 2 more; the others: "
            + string.Join(", ", others.Take(10).Select(u => $"'{u}'")) + ", and 2 more. ",
            ex.Message,
            StringComparison.Ordinal);
    }

    // A gone file's attacker-authored name is escaped in the clause, like every other name.
    [Fact]
    public void Run_AGoneFileWithABidiName_IsNamedEscaped()
    {
        var hostile = "exe." + Rlo + "txt.bin";
        var scanner = new Scripted(_ => Outcome.GoneFile);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, Root, Files(hostile)));

        Assert.Contains("(removed after it was listed): 'exe." + EscapedRlo + "txt.bin'.", ex.Message, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }
    #endregion

    #region Methods: gone needs the disk to agree (I5 W-a)
    // libyara.NET throws FileNotFound for ANY failed open (a share lock, an ACL), so a not-found inner exception is not
    // evidence on its own. A file that is still on disk keeps the plain unscanned wording, byte for byte the no-gone text.
    [Fact]
    public void Run_WhenTheInnerIsFileNotFound_ButTheFileExists_ItIsNotNamedAsGone()
    {
        using var tree = new TempTree();
        var present = Path.GetFullPath(tree.Write("content/locked.bin", "x"));
        var scanner = new OnDisk(path =>
            throw new YaraScanIncompleteException($"YARA could not scan '{path}'.", new FileNotFoundException("libyara says not found", path)));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, tree.Root, [present]));

        Assert.True(File.Exists(present), "precondition: the file is still there");
        Assert.Equal(
            $"YARA could not scan 1 of 1 file(s) under '{tree.Root}': '{Rel("content/locked.bin")}'. 0 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // The same with DirectoryNotFound as the inner exception, for a file whose directory is still there.
    [Fact]
    public void Run_WhenTheInnerIsDirectoryNotFound_ButTheFileExists_ItIsNotNamedAsGone()
    {
        using var tree = new TempTree();
        var present = Path.GetFullPath(tree.Write("content/sub/kept.bin", "x"));
        var scanner = new OnDisk(path =>
            throw new YaraScanIncompleteException($"YARA could not scan '{path}'.", new DirectoryNotFoundException("not found")));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, tree.Root, [present]));

        Assert.DoesNotContain("no longer exist", ex.Message, StringComparison.Ordinal);
        Assert.Contains($": '{Rel("content/sub/kept.bin")}'. ", ex.Message, StringComparison.Ordinal);
    }

    // The race the disk check exists to tell apart: the file is there when the backend looks (File.Exists), and gone by
    // the time it opens it — the backend's own not-found is then CONFIRMED by the disk, so the file is named as gone.
    // Staged deterministically by a double that deletes the file between its own File.Exists and its throw.
    [Fact]
    public void Run_WhenAFileIsDeletedBetweenTheExistsCheckAndTheOpen_ItIsNamedAsGone()
    {
        using var tree = new TempTree();
        var racing = Path.GetFullPath(tree.Write("content/racing.bin", "x"));
        var kept = Path.GetFullPath(tree.Write("content/kept.bin", "x"));
        var sawItFirst = false;
        var scanner = new OnDisk(path =>
        {
            if (path != racing)
                return [new YaraMatch("Hit", null, [], [])];
            sawItFirst = File.Exists(path);   // the backend's own check passes...
            File.Delete(path);                // ...and the file goes before the open
            throw new YaraScanIncompleteException($"YARA could not scan '{path}'.", new FileNotFoundException("not found", path));
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, tree.Root, [racing, kept]));

        Assert.True(sawItFirst, "precondition: the file existed when the backend checked");
        Assert.Equal(kept, Assert.Single(ex.PartialFindings).FullPath);
        Assert.Equal(
            $"YARA could not scan 1 of 2 file(s) under '{tree.Root}': 1 of them no longer exists (removed after it was listed): '{Rel("content/racing.bin")}'. 1 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }

    // Mixed: one existing file with a not-found inner (a lock) and one genuinely gone file. Only the gone one is under
    // the clause; the locked one is under "the others".
    [Fact]
    public void Run_WithALockedLookingFileAndAGoneFile_OnlyTheGoneOneIsUnderTheClause()
    {
        using var tree = new TempTree();
        var locked = Path.GetFullPath(tree.Write("content/locked.bin", "x"));
        var gone = Path.GetFullPath(Path.Combine(tree.Root, "content", "gone.bin"));
        var scanner = new OnDisk(path =>
            throw new YaraScanIncompleteException($"YARA could not scan '{path}'.", new FileNotFoundException("not found", path)));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => YaraScanLoop.Run(scanner, tree.Root, [locked, gone]));

        Assert.Equal(
            $"YARA could not scan 2 of 2 file(s) under '{tree.Root}': 1 of them no longer exists (removed after it was listed): '{Rel("content/gone.bin")}'; the others: '{Rel("content/locked.bin")}'. 0 hit(s) found in the other files are reported; this package was NOT fully scanned and must not be reported as clean.",
            ex.Message);
    }
    #endregion

    #region Helpers
    // A root that never exists on disk: Run never enumerates it, it only renders names relative to it.
    private static readonly string Root = Path.Combine(Path.GetTempPath(), "silvergun-loop-never-created");

    private static string F(string relative) => Path.Combine(Root, Rel(relative));

    private static string Rel(string relative) => relative.Replace('/', Path.DirectorySeparatorChar);

    private static string[] Files(params string[] relatives) => relatives.Select(F).ToArray();

    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion

    #region Nested types
    private enum Outcome { Clean, Hit, NotScanned, NotScannedWithPartialHit, NotScannedWithIOException, GoneFile, GoneDirectory, Timeout, Crash }

    // A backend whose ScanFile outcome is chosen by the file's path relative to Root ('/'-separated), and which records
    // every path it was handed. The gone outcomes throw what LibYaraScanner.ScanFile throws for a file that is gone: the
    // per-file exception with the FileNotFound/DirectoryNotFound as its inner exception.
    private sealed class Scripted(Func<string, Outcome> outcome) : IYaraScanner
    {
        public bool Available => true;

        public List<string> Visited { get; } = [];

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            YaraScanLoop.Run(this, rootDir, files);

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
        {
            Visited.Add(fullPath);
            var name = YaraPathSafety.Relative(Root, fullPath).Replace(Path.DirectorySeparatorChar, '/');
            return outcome(name) switch
            {
                Outcome.Clean => [],
                Outcome.Hit => [Match("Hit")],
                Outcome.NotScanned => throw new YaraScanIncompleteException($"YARA could not scan '{name}'."),
                Outcome.NotScannedWithPartialHit => throw new YaraScanIncompleteException($"YARA could not finish '{name}'.", null, [(fullPath, Match("Partial"))]),
                Outcome.NotScannedWithIOException => throw new YaraScanIncompleteException($"YARA could not scan '{name}'.", new IOException("sharing violation")),
                Outcome.GoneFile => throw new YaraScanIncompleteException($"YARA did not scan '{name}': {YaraPathSafety.NoLongerExists}.", new FileNotFoundException("gone", fullPath)),
                Outcome.GoneDirectory => throw new YaraScanIncompleteException($"YARA did not scan '{name}': {YaraPathSafety.NoLongerExists}.", new DirectoryNotFoundException("gone")),
                Outcome.Timeout => throw new TimeoutException("bound reached"),
                _ => throw new InvalidOperationException("native dependency did not load"),
            };
        }

        private static YaraMatch Match(string rule) => new(rule, null, [], []);
    }

    // A backend over REAL paths whose ScanFile is the given body, for the cases where the disk's answer matters (I5 W-a).
    private sealed class OnDisk(Func<string, IReadOnlyList<YaraMatch>> scan) : IYaraScanner
    {
        public bool Available => true;

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            YaraScanLoop.Run(this, rootDir, files);

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => scan(fullPath);
    }
    #endregion
}
