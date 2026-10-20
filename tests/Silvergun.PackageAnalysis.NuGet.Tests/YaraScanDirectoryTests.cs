namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for the <see cref="IYaraScanner.ScanDirectory"/> batch entry (ADR 0016 Phase 3, review note #2).
/// <see cref="NullYaraScanner"/> overrides it to a no-op; every other backend inherits the default-interface-method
/// implementation that loops the cheap <see cref="IYaraScanner.ScanFile"/> primitive and pairs each hit with the
/// file it matched. A <see cref="FakeScanner"/> (no real engine or binary) drives that default loop over a temp
/// directory tree, proving hits are attributed to the correct absolute path — including multiple hits per file.
///
/// <para><b>ADR 0032 decision 6.</b> The same default loop is the Windows production path (<c>LibYaraScanner</c>
/// does not override it), and it now isolates per-file failures: a file that was not scanned is recorded and the
/// loop continues; a timeout stops it; either way every hit already found travels out in
/// <see cref="YaraScanIncompleteException.PartialFindings"/>. A <see cref="ScriptedScanner"/> drives those paths
/// without any native engine, so this runs on every platform.</para>
/// </summary>
public sealed class YaraScanDirectoryTests
{
    #region Methods
    // The null backend's ScanDirectory is empty even over a populated tree — it never touches the filesystem.
    [Fact]
    public void NullYaraScanner_ScanDirectory_OverPopulatedTree_ReturnsEmpty()
    {
        using var dir = new TempDir();
        dir.WriteFile("a.dll");
        dir.WriteFile("nested/b.dll");

        Assert.Empty(NullYaraScanner.Instance.ScanDirectory(dir.Root));
    }

    // The default ScanDirectory loops ScanFile recursively and pairs each hit with the exact file that matched;
    // non-matching files (and their absence of hits) are dropped.
    [Fact]
    public void DefaultScanDirectory_LoopsScanFile_AttributingHitsPerFile()
    {
        using var dir = new TempDir();
        var evil1 = dir.WriteFile("evil1.dll");
        var evil2 = dir.WriteFile("nested/evil2.dll");
        dir.WriteFile("clean.txt");

        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "Win32_Test");
        var hits = scanner.ScanDirectory(dir.Root);

        Assert.Equal(2, hits.Count);
        Assert.Contains(hits, h => h.FullPath == evil1 && h.Match.Rule == "Win32_Test");
        Assert.Contains(hits, h => h.FullPath == evil2 && h.Match.Rule == "Win32_Test");
        Assert.DoesNotContain(hits, h => Path.GetFileName(h.FullPath) == "clean.txt");
    }

    // Multiple rule hits on a single file are all surfaced, each attributed to that same file (SelectMany fan-out).
    [Fact]
    public void DefaultScanDirectory_MultipleMatchesPerFile_AllAttributedToThatFile()
    {
        using var dir = new TempDir();
        var evil = dir.WriteFile("evil.dll");

        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R", matchesPerFile: 3);
        var hits = scanner.ScanDirectory(dir.Root);

        Assert.Equal(3, hits.Count);
        Assert.All(hits, h => Assert.Equal(evil, h.FullPath));
    }

    // --- ADR 0030: the two ways this default can return no files, and only one of them means "clean" -----------

    // A missing root directory yields empty (the default implementation guards Directory.Exists) and never throws.
    // This is NOT the same condition as the one below, and the distinction is the whole of ADR 0030: in production
    // rootDir is NuGetPackage.ExtractionDir, which the package creates and validates before a scan can be
    // requested, so a missing root means "there was nothing to scan", not "we failed to scan something". No
    // package content is being written off as clean here.
    [Fact]
    public void DefaultScanDirectory_MissingDirectory_ReturnsEmpty()
    {
        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R");
        var missing = Path.Combine(Path.GetTempPath(), "silvergun-no-such-dir-" + Guid.NewGuid().ToString("N"));

        Assert.Empty(scanner.ScanDirectory(missing));
    }

    // ...and the enumeration that actually threw, which must NOT return empty. This is the Windows production
    // path: LibYaraScanner does not override ScanDirectory, so this default is what runs there, and a tree whose
    // files were never listed and then reported as a completed, empty scan is exactly the defect ADR 0030 exists
    // to stop — the same site ADR 0029 decision 14 closed in the CLI backend, which used to be the only one of
    // the two that failed closed.
    //
    // Linux-gated for the same reason its CLI-backend sibling is: it needs a directory the current user cannot
    // read, and the Windows ACL APIs are not available to a net10.0 build. The arrange step asserts that the mode
    // really does deny THIS user (running the suite as root would defeat it) rather than passing vacuously.
    [LinuxFact]
    public void DefaultScanDirectory_WhenTheTreeCannotBeEnumerated_FailsClosedAsAnIncompleteScan()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        tree.Write("secret/evil.dll", "content");
        var unreadable = Path.Combine(tree.Root, "secret");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxFact] must have gated this test to Linux.");
        File.SetUnixFileMode(unreadable, UnixFileMode.None);
        Assert.Throws<UnauthorizedAccessException>(
            () => Directory.GetFiles(tree.Root, "*", SearchOption.AllDirectories));

        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains("could not enumerate", ex.Message, StringComparison.Ordinal);
        Assert.Contains("unknown number of files went unscanned", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        Assert.IsAssignableFrom<UnauthorizedAccessException>(ex.InnerException);
    }

    // A ScanFile that reached its backend's own wall-clock bound must never be swallowed into an empty list: a bound
    // that was reached means the rest of the directory's "no matches" is not trustworthy either. REWRITTEN for ADR
    // 0032 decision 6 (it used to assert a raw TimeoutException out of the default loop): the loop now converts the
    // timeout into the one fail-closed seam, YaraScanIncompleteException, so the hits found before it can travel
    // out with it — and keeps the cause machine-readable as the InnerException. The original intent ("propagates
    // rather than returning empty") is unchanged.
    [Fact]
    public void DefaultScanDirectory_WhenScanFileTimesOut_ThrowsIncompleteWithTheTimeoutAsInnerException()
    {
        using var dir = new TempDir();
        dir.WriteFile("evil.dll");
        dir.WriteFile("clean.txt");

        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R", throwOnMatch: true);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(dir.Root));
        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
    }

    // --- ADR 0032 decision 6: per-file failures are isolated, and every hit in hand survives ------------------

    // The headline of decision 6. One file that could not be scanned no longer costs every other file its findings:
    // the loop records it as unscanned, KEEPS GOING, and the hits from the files it did scan travel out inside the
    // exception. Before ADR 0032 the exception aborted the loop on the spot and the other files' hits were gone.
    [Fact]
    public void DefaultScanDirectory_WhenOneFileIsNotScanned_ScansEveryOtherFileAndCarriesTheirHits()
    {
        using var dir = new TempDir();
        var a = dir.WriteFile("a-evil.bin");
        var b = dir.WriteFile("b-evil.bin");
        var locked = dir.WriteFile("locked.bin");
        dir.WriteFile("c-clean.txt");

        var scanner = new ScriptedScanner(path =>
            Path.GetFileName(path) == "locked.bin" ? throw NotScanned(path)
            : Path.GetFileName(path).Contains("evil", StringComparison.Ordinal) ? [Match("Hit")]
            : []);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));

        Assert.Equal(4, scanner.Visited.Count);   // the failing file did not stop the loop
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == a && h.Match.Rule == "Hit");
        Assert.Single(ex.PartialFindings, h => h.FullPath == b && h.Match.Rule == "Hit");
        Assert.DoesNotContain(ex.PartialFindings, h => h.FullPath == locked);
        Assert.Null(ex.InnerException);   // not a timeout
        Assert.Contains("could not scan 1 of 4 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'locked.bin'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("2 hit(s) found in the other files", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
    }

    // A per-file failure can itself carry hits (a backend that found something before it could not finish the
    // file). Those are real detections too: the loop keeps them alongside the other files' hits rather than
    // treating "this file was not fully scanned" as "this file had nothing".
    [Fact]
    public void DefaultScanDirectory_KeepsTheFailingFilesOwnPartialFindings()
    {
        using var dir = new TempDir();
        var partial = dir.WriteFile("partial.bin");
        var whole = dir.WriteFile("whole.bin");

        var scanner = new ScriptedScanner(path =>
            path == partial
                ? throw new YaraScanIncompleteException("only part of this file was examined", null, [(path, Match("FoundBeforeFailing"))])
                : [Match("Hit")]);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));

        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == partial && h.Match.Rule == "FoundBeforeFailing");
        Assert.Single(ex.PartialFindings, h => h.FullPath == whole && h.Match.Rule == "Hit");
        Assert.Contains("could not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
    }

    // A timeout is different from a per-file failure: it says the ENGINE's health can no longer be vouched for
    // (ADR 0028 decision 10), so the loop STOPS — files after it are not scanned — but the hits from the files
    // before it are carried out. Enumeration order is the filesystem's, so the fake times out on its k-th CALL and
    // the assertions are phrased over what it actually visited.
    [Fact]
    public void DefaultScanDirectory_WhenTheKthFileTimesOut_CarriesEarlierHitsAndScansNothingAfterIt()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 6; i++)
            dir.WriteFile($"f{i}.bin");

        var scanner = new ScriptedScanner((_, call) => call == 3 ? throw new TimeoutException("bound reached") : [Match("Hit")]);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));

        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Equal(3, scanner.Visited.Count);   // stopped at the timeout: f-files 4..6 were never handed to the engine
        Assert.Equal(scanner.Visited.Take(2).Order(), ex.PartialFindings.Select(h => h.FullPath).Order());
        Assert.DoesNotContain(ex.PartialFindings, h => h.FullPath == scanner.Visited[2]);
        Assert.Contains($"timed out scanning '{Path.GetFileName(scanner.Visited[2])}'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("the remaining 3 file(s) were not scanned", ex.Message, StringComparison.Ordinal);
        Assert.Contains("2 hit(s) found before that", ex.Message, StringComparison.Ordinal);
    }

    // The message must not invent unscanned files: a timeout on the LAST file leaves nothing "remaining".
    [Fact]
    public void DefaultScanDirectory_WhenTheLastFileTimesOut_DoesNotClaimRemainingFiles()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 3; i++)
            dir.WriteFile($"f{i}.bin");

        var scanner = new ScriptedScanner((_, call) => call == 3 ? throw new TimeoutException("bound reached") : [Match("Hit")]);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));

        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Equal(3, scanner.Visited.Count);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.DoesNotContain("remaining", ex.Message, StringComparison.Ordinal);
    }

    // A timeout after earlier per-file failures must still disclose those failures — the exception it becomes is the
    // only record of them — and must still carry the hits found in between.
    [Fact]
    public void DefaultScanDirectory_WhenATimeoutFollowsAnUnscannedFile_NamesBothAndKeepsTheHitsBetween()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 4; i++)
            dir.WriteFile($"f{i}.bin");

        var scanner = new ScriptedScanner((path, call) => call switch
        {
            1 => throw NotScanned(path),
            3 => throw new TimeoutException("bound reached"),
            _ => [Match("Hit")],
        });

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));

        Assert.IsType<TimeoutException>(ex.InnerException);
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(scanner.Visited[1], hit.FullPath);
        Assert.Contains("1 earlier file(s) were not scanned either", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"'{Path.GetFileName(scanner.Visited[0])}'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("the remaining 1 file(s) were not scanned", ex.Message, StringComparison.Ordinal);
    }

    // The message is logged verbatim, so a package of thousands of unscannable files must not be able to flood it:
    // ten names, then a count.
    [Fact]
    public void DefaultScanDirectory_WithManyUnscannedFiles_NamesTenAndCountsTheRest()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 25; i++)
            dir.WriteFile($"u{i:D2}.bin");

        var scanner = new ScriptedScanner(path => throw NotScanned(path));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));

        Assert.Equal(25, scanner.Visited.Count);
        Assert.Empty(ex.PartialFindings);
        Assert.Contains("could not scan 25 of 25 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Equal(10, Regex.Matches(ex.Message, @"'u\d\d\.bin'").Count);
        Assert.Contains(", and 15 more", ex.Message, StringComparison.Ordinal);
    }

    // The unscanned names are attacker-authored. A bidi override is legal on NTFS and ext4 alike, so this runs on
    // every platform: the name must reach the message escaped (as backslash-u202e), never raw — in both the after-the-loop
    // message and the timeout message.
    [Fact]
    public void DefaultScanDirectory_EscapesHostileNamesInEveryMessage()
    {
        using var dir = new TempDir();
        var hostile = dir.WriteFile($"exe.{Rlo}txt.bin");
        dir.WriteFile("ok.bin");

        var notScanned = Assert.Throws<YaraScanIncompleteException>(() =>
            ((IYaraScanner)new ScriptedScanner(path => path == hostile ? throw NotScanned(path) : [])).ScanDirectory(dir.Root));
        var timedOut = Assert.Throws<YaraScanIncompleteException>(() =>
            ((IYaraScanner)new ScriptedScanner(path => path == hostile ? throw new TimeoutException("bound") : [])).ScanDirectory(dir.Root));

        foreach (var ex in new[] { notScanned, timedOut })
        {
            Assert.Contains("exe." + EscapedRlo + "txt.bin", ex.Message, StringComparison.Ordinal);
            AssertNoRawControlOrBidi(ex.Message);
        }
    }

    // The same for a C0 control character, which only Linux can stage as a file name. A raw newline in the message
    // would let a package forge a line in our own log.
    [LinuxFact]
    public void DefaultScanDirectory_EscapesControlCharacterNamesInTheMessage()
    {
        using var tree = new TempTree();
        var hostile = tree.Write("content/n\nl.bin", "content");
        tree.Write("content/ok.bin", "content");

        var ex = Assert.Throws<YaraScanIncompleteException>(() =>
            ((IYaraScanner)new ScriptedScanner(path => path == hostile ? throw NotScanned(path) : [])).ScanDirectory(tree.Root));

        Assert.Contains(@"n\nl.bin", ex.Message, StringComparison.Ordinal);
        AssertNoRawControlOrBidi(ex.Message);
    }

    // Only the two exception types of the contract are absorbed by the loop. Anything else from ScanFile — e.g. the
    // in-process engine's native dependency failing to load — propagates unchanged, to PackageScanner.ScanYara's
    // catch-all, rather than being misreported as "one file was not scanned" while the loop carries on.
    [Fact]
    public void DefaultScanDirectory_WhenScanFileThrowsAnythingElse_PropagatesItUnchanged()
    {
        using var dir = new TempDir();
        dir.WriteFile("a.bin");
        dir.WriteFile("b.bin");

        var scanner = new ScriptedScanner(_ => throw new InvalidOperationException("native dependency did not load"));

        Assert.Throws<InvalidOperationException>(() => ((IYaraScanner)scanner).ScanDirectory(dir.Root));
        Assert.Single(scanner.Visited);
    }

    // An empty/whitespace root is a degenerate input the default implementation must tolerate — empty, no throw.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void DefaultScanDirectory_DegenerateRoot_ReturnsEmpty(string root)
    {
        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R");

        Assert.Empty(scanner.ScanDirectory(root));
    }
    #endregion

    #region Helpers
    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so the source itself never carries it raw, and the
    // backslash-u form YaraPathSafety.Escape renders it as.
    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";

    private static YaraMatch Match(string rule) =>
        new(rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>());

    // What a backend's ScanFile throws for "this file was not scanned" (ADR 0032 decision 5). The one-argument
    // constructor on purpose: it is the shape that predates PartialFindings.
    private static YaraScanIncompleteException NotScanned(string path) =>
        new($"YARA did not scan '{Path.GetFileName(path)}'. This file was NOT scanned and must not be reported as clean.");

    // No C0, DEL/C1, line/paragraph separator, or bidi control — the predicate YaraCliScannerUnsafePathTests uses.
    private static void AssertNoRawControlOrBidi(string message) =>
        Assert.All(message, c => Assert.False(
            c < ' ' || c is >= (char)0x7F and <= (char)0x9F or (char)0x2028 or (char)0x2029
                        or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069,
            $"YaraScanIncompleteException.Message carried raw U+{(int)c:X4}."));
    #endregion

    #region Nested types
    // A fake IYaraScanner whose ScanFile does whatever the test scripts — return hits, throw "not scanned", time out —
    // keyed on the path or on the 1-based call number (enumeration order is the filesystem's, so "the k-th file" is
    // only knowable as "the k-th call"). It records every path it was handed, in order, which is how a test tells
    // "the loop stopped" from "the loop continued". Like FakeScanner it implements ONLY the primitive, so
    // ScanDirectory is the interface's default loop under test.
    private sealed class ScriptedScanner : IYaraScanner
    {
        public ScriptedScanner(Func<string, IReadOnlyList<YaraMatch>> behavior) : this((path, _) => behavior(path)) { }

        public ScriptedScanner(Func<string, int, IReadOnlyList<YaraMatch>> behavior) => _behavior = behavior;

        public bool Available => true;

        public List<string> Visited { get; } = [];

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
        {
            Visited.Add(fullPath);
            return _behavior(fullPath, Visited.Count);
        }

        private readonly Func<string, int, IReadOnlyList<YaraMatch>> _behavior;
    }

    // A fake IYaraScanner with no real engine: ScanFile returns `matchesPerFile` hits for any file whose name
    // contains `nameContains`, else empty. It implements ONLY the primitive so tests exercise the interface's
    // default ScanDirectory loop. Available defaults to true (a healthy backend) since these tests are about the
    // default ScanDirectory loop's file-attribution logic, not about the health signal (that is
    // YaraScanPackageWiringTests' concern) — but it is a constructible flag, not hard-coded, so a future test here
    // could exercise the unhealthy path too without a second fake type.
    private sealed class FakeScanner : IYaraScanner
    {
        public FakeScanner(
            string nameContains, string rule, int matchesPerFile = 1, bool available = true, bool throwOnMatch = false)
        {
            _nameContains = nameContains;
            _rule = rule;
            _matchesPerFile = matchesPerFile;
            _throwOnMatch = throwOnMatch;
            Available = available;
        }

        public bool Available { get; }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) =>
            !Path.GetFileName(fullPath).Contains(_nameContains, StringComparison.Ordinal)
                ? Array.Empty<YaraMatch>()
                : _throwOnMatch
                    ? throw new TimeoutException("The backend's own wall-clock bound was reached.")
                    : Enumerable.Range(0, _matchesPerFile)
                        .Select(_ => new YaraMatch(_rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>()))
                        .ToArray();

        private readonly string _nameContains;
        private readonly string _rule;
        private readonly int _matchesPerFile;
        private readonly bool _throwOnMatch;
    }

    // A self-cleaning temp directory; WriteFile creates any parent folders and returns the absolute path written.
    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Root = Path.Combine(Path.GetTempPath(), "silvergun-yara-scandir-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string WriteFile(string relative)
        {
            var full = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, "content");
            return full;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                    Directory.Delete(Root, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
        }
    }
    #endregion
}
