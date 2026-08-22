namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for the <see cref="IYaraScanner.ScanDirectory"/> batch entry (ADR 0016 Phase 3, review note #2).
/// <see cref="NullYaraScanner"/> overrides it to a no-op; every other backend inherits the default-interface-method
/// implementation that loops the cheap <see cref="IYaraScanner.ScanFile"/> primitive and pairs each hit with the
/// file it matched. A <see cref="FakeScanner"/> (no real engine or binary) drives that default loop over a temp
/// directory tree, proving hits are attributed to the correct absolute path — including multiple hits per file.
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

    // A healthy backend whose ScanFile throws is a different contract (the per-file never-throws rule), but the
    // default loop deliberately does not guard it: a bound that was reached means the rest of the directory's
    // "no matches" is not trustworthy either, so it surfaces rather than being swallowed into an empty list.
    [Fact]
    public void DefaultScanDirectory_WhenScanFileTimesOut_PropagatesRatherThanReturningEmpty()
    {
        using var dir = new TempDir();
        dir.WriteFile("evil.dll");
        dir.WriteFile("clean.txt");

        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R", throwOnMatch: true);

        Assert.Throws<TimeoutException>(() => scanner.ScanDirectory(dir.Root));
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

    #region Nested types
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
