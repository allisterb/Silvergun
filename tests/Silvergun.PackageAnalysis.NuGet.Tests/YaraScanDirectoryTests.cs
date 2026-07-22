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

    // A missing root directory yields empty (the default implementation guards Directory.Exists) and never throws.
    [Fact]
    public void DefaultScanDirectory_MissingDirectory_ReturnsEmpty()
    {
        IYaraScanner scanner = new FakeScanner(nameContains: "evil", rule: "R");
        var missing = Path.Combine(Path.GetTempPath(), "silvergun-no-such-dir-" + Guid.NewGuid().ToString("N"));

        Assert.Empty(scanner.ScanDirectory(missing));
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
    // default ScanDirectory loop.
    private sealed class FakeScanner : IYaraScanner
    {
        public FakeScanner(string nameContains, string rule, int matchesPerFile = 1)
        {
            _nameContains = nameContains;
            _rule = rule;
            _matchesPerFile = matchesPerFile;
        }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) =>
            Path.GetFileName(fullPath).Contains(_nameContains, StringComparison.Ordinal)
                ? Enumerable.Range(0, _matchesPerFile)
                    .Select(_ => new YaraMatch(_rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>()))
                    .ToArray()
                : Array.Empty<YaraMatch>();

        private readonly string _nameContains;
        private readonly string _rule;
        private readonly int _matchesPerFile;
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
