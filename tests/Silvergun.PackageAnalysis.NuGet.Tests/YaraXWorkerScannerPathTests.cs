#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;
using Xunit.Abstractions;

/// <summary>
/// What <see cref="YaraXWorkerScanner"/> refuses to send (ADR 0033; amendments G2, (j'), (q) and W-A of
/// <c>docs/agent/tasks/yarax-worker.md</c>). A refused file is unscanned (never clean), no request for it ever reaches
/// the worker (observed in the fake worker's own request log), and every other file's hits are kept.
///
/// <para><b>(j'):</b> the parent's form refusal IS <see cref="WorkerPathForm.Verbatim"/> returning null, on the wire form
/// (<c>/</c> folded to <c>\</c>). Each grid case checks that equality in both directions: a path Verbatim rejects is
/// refused for its form, and a path it accepts is sent. Accepted cases name real files, so they are scanned; UNC paths
/// in the accepted form are covered at the <see cref="WorkerPathForm"/> level only (a parent would touch the network to
/// check them for links).</para>
///
/// <para><b>W-A:</b> the link check walks the VERBATIM form of the file and of every directory under the root, because
/// the plain form normalises <c>con</c> to <c>\\.\con</c> and strips the dot from <c>bar.</c>, losing the link. Real
/// (non-link) files and directories with such names are still scanned. Junctions are created through <c>\\?\</c> and
/// removed as links, never followed (<see cref="ScanTree"/>).</para>
/// </summary>
public sealed class YaraXWorkerScannerPathTests(YaraXWorkerScannerPathTests.Grid grid, ITestOutputHelper output)
    : IClassFixture<YaraXWorkerScannerPathTests.Grid>
{
    #region Methods: G2 / (j'), the grid
    private static readonly string[] Cases =
    [
        "drive", "drive, lower-case letter", "folded slash", "folded slash in a subdirectory", "a device-like file name",
        "drive-relative", "rooted without a drive", "NUL", "empty segment", "dot segment", "dot-dot segment",
        "trailing backslash", "alternate data stream", "::$DATA", "UNC with two segments", "verbatim prefix",
        "device prefix", "NT object prefix", "verbatim UNC", "lone high surrogate", "lone low surrogate",
        "reversed surrogate pair", "drive root only", "a digit for a drive", "empty",
    ];

    public static TheoryData<string> GridCases() => new(Cases);

    [Theory]
    [MemberData(nameof(GridCases))]
    public void ScanFile_RefusesExactlyThePathsVerbatimRejects(string name)
    {
        var path = grid.Path(name);
        var wire = path.Replace('/', '\\');
        var formRejected = WorkerPathForm.Verbatim(wire) is null;
        var sentBefore = grid.Script.SentPaths.Length;
        var runsBefore = grid.Script.Pids.Length;

        var ex = Record.Exception(() => grid.Scanner.ScanFile(path));

        var sent = grid.Script.SentPaths.Skip(sentBefore).ToArray();
        if (formRejected)
        {
            var incomplete = Assert.IsType<YaraScanIncompleteException>(ex);
            Assert.Contains("its path is not in the worker protocol's form", incomplete.Message, StringComparison.Ordinal);
            Assert.Contains("must not be reported as clean", incomplete.Message, StringComparison.Ordinal);
            Assert.Empty(sent);
            Assert.Equal(runsBefore, grid.Script.Pids.Length);   // no worker was even started for it
        }
        else
        {
            Assert.Null(ex);
            Assert.Equal(new[] { wire }, sent);
        }
        grid.Script.AssertNoOrphans();
    }

    // The grid really does exercise both sides (a guard against a grid that only ever expects one answer).
    [Fact]
    public void TheGrid_HoldsBothAcceptedAndRejectedPaths()
    {
        var verdicts = Cases.Select(c => WorkerPathForm.Verbatim(grid.Path(c).Replace('/', '\\')) is null).ToArray();

        Assert.Equal(5, verdicts.Count(rejected => !rejected));
        Assert.Equal(Cases.Length - 5, verdicts.Count(rejected => rejected));
    }

    // A file whose name the protocol cannot carry (a lone surrogate: NTFS allows it, UTF-8 cannot hold it) is refused and
    // unscanned; the files beside it are sent, scanned, and their hits kept as partial findings.
    [Fact]
    public void ScanDirectory_ARefusedFile_IsUnscanned_AndTheOtherFilesHitsAreKept()
    {
        using var script = new FakeWorkerScript("g2-dir").GenuineThroughout();
        using var tree = new ScanTree("g2-dir");
        var good = new[] { tree.Write("a.bin"), tree.Write(@"sub\b.bin") };
        var bad = tree.Write("bad" + (char)0xD800 + ".bin");
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Equal(good.Order(StringComparer.Ordinal), script.SentPaths.Order(StringComparer.Ordinal));
        Assert.Equal(good.Order(StringComparer.Ordinal), ex.PartialFindings.Select(p => p.FullPath).Order(StringComparer.Ordinal));
        Assert.Contains("did not scan 1 of 3 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("its path is not in the worker protocol's form", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(ex.PartialFindings, p => p.FullPath == bad);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: W-A, links
    // Measured before the FR fix: junctions named `con`, `bar.` and `lpt1.d` escaped the plain-path link check. Every one
    // of them, and an ordinary junction, is refused, and nothing under it is ever sent.
    [Theory]
    [InlineData("con")]
    [InlineData("CON")]
    [InlineData("bar.")]
    [InlineData("lpt1.d")]
    [InlineData("nul.txt")]
    [InlineData("ordinary-link")]
    public void ScanDirectory_AJunctionUnderTheRoot_IsRefused_WithNoRequestSent(string name)
    {
        using var script = new FakeWorkerScript("wa").GenuineThroughout();
        using var tree = new ScanTree("wa");
        var kept = tree.Write("a.bin");
        tree.Junction(name);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Equal(new[] { kept }, script.SentPaths);
        Assert.Equal(kept, Assert.Single(ex.PartialFindings).FullPath);
        Assert.Contains("did not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("it is a link, lies under a linked directory, or could not be checked for either", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // The walk covers every directory between the root and the file, not only the leaf's parent.
    [Theory]
    [InlineData(@"sub\inner")]
    [InlineData(@"sub\con")]
    [InlineData(@"a.\b.\c")]
    public void ScanDirectory_AJunctionAsANestedAncestor_IsRefused(string relative)
    {
        using var script = new FakeWorkerScript("wa-nested").GenuineThroughout();
        using var tree = new ScanTree("wa-nested");
        var kept = tree.Write("a.bin");
        var target = tree.Junction(relative);
        Directory.CreateDirectory(Path.Combine(target, "deeper"));
        File.WriteAllBytes(Path.Combine(target, "deeper", "x.bin"), [7]);
        using var scanner = script.Scanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Equal(new[] { kept }, script.SentPaths);
        Assert.Contains("did not scan 2 of 3 file(s)", ex.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // A file symbolic link is refused too. Creating one needs SeCreateSymbolicLinkPrivilege (or Developer Mode); when this
    // account cannot, the test says so in its output and checks only that the precondition really is the privilege.
    [Fact]
    public void ScanDirectory_AFileSymbolicLink_IsRefused()
    {
        using var script = new FakeWorkerScript("wa-symlink").GenuineThroughout();
        using var tree = new ScanTree("wa-symlink");
        var kept = tree.Write("a.bin");
        var outside = Path.Combine(tree.Outside, "secret.bin");
        File.WriteAllBytes(outside, [5]);
        try
        {
            File.CreateSymbolicLink(Path.Combine(tree.Root, "link.bin"), outside);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"NOT EXERCISED: this account cannot create a file symbolic link ({ex.GetType().Name}: {ex.Message}).");
            Assert.Contains("privilege", ex.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }
        using var scanner = script.Scanner();

        var thrown = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Equal(new[] { kept }, script.SentPaths);
        Assert.Contains("it is a link", thrown.Message, StringComparison.Ordinal);
        script.AssertNoOrphans();
    }

    // The other side of W-A: REAL files and directories whose names a plain path would turn into a device or trim
    // (`nul.txt`, `aux\`, `foo.\`, `CON`) are not links, so they are sent, scanned, and the scan completes.
    [Fact]
    public void ScanDirectory_RealFilesWithDeviceLikeOrTrailingDotNames_AreSentAndScanned()
    {
        using var script = new FakeWorkerScript("wa-real").GenuineThroughout();
        using var tree = new ScanTree("wa-real");
        var files = new[] { tree.Write("nul.txt"), tree.Write(@"aux\real.bin"), tree.Write(@"foo.\real.bin"), tree.Write("CON"), tree.Write(@"lpt1.d\x.bin") };
        using var scanner = script.Scanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal(files.Order(StringComparer.Ordinal), script.SentPaths.Order(StringComparer.Ordinal));
        Assert.Equal(files.Order(StringComparer.Ordinal), hits.Select(h => h.FullPath).Order(StringComparer.Ordinal));
        script.AssertNoOrphans();
    }

    // ScanFile has no root to bound the walk, so only the file itself is checked: a link is refused.
    [Fact]
    public void ScanFile_OfAFileSymbolicLink_IsRefused()
    {
        using var script = new FakeWorkerScript("wa-file").GenuineThroughout();
        using var tree = new ScanTree("wa-file");
        var outside = Path.Combine(tree.Outside, "real.bin");
        File.WriteAllBytes(outside, [1]);
        var link = Path.Combine(tree.Root, "file-link.bin");
        try
        {
            File.CreateSymbolicLink(link, outside);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"NOT EXERCISED: this account cannot create a file symbolic link ({ex.Message}).");
            return;
        }
        using var scanner = script.Scanner();

        var thrown = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(link));

        Assert.Contains("it is a link", thrown.Message, StringComparison.Ordinal);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }

    // The fixture's own cleanup removes a junction as a link: the directory it points at, outside the tree, survives.
    [Fact]
    public void ScanTreeCleanup_RemovesJunctionsWithoutFollowingThem()
    {
        using var elsewhere = new YaraXTempDir("wa-elsewhere");
        var precious = elsewhere.Combine("precious.bin");
        File.WriteAllBytes(precious, [1]);
        string root;
        using (var tree = new ScanTree("wa-cleanup"))
        {
            root = tree.Root;
            WindowsFileSystem.CreateJunction(@"\\?\" + Path.Combine(tree.Root, "con"), elsewhere.Root);
            Assert.True(File.Exists(Path.Combine(tree.Root, "con", "precious.bin")), "the junction does not reach its target");
        }

        Assert.False(Directory.Exists(root));
        Assert.True(File.Exists(precious), "cleaning the tree deleted the junction's target");
    }
    #endregion

    #region Nested types
    // One genuine fake worker and one scanner for the whole grid (the cases run one at a time within this class).
    public sealed class Grid : IDisposable
    {
        public Grid()
        {
            Script = new FakeWorkerScript("g2-grid").GenuineThroughout();
            tree = new ScanTree("g2-grid");
            tree.Write("ok.bin");
            tree.Write(@"sub\ok2.bin");
            tree.Write("nul.txt");
            Scanner = Script.Scanner();
            Assert.True(Scanner.Available, "the grid's genuine fake worker is not available");
        }

        internal FakeWorkerScript Script { get; }

        public YaraXWorkerScanner Scanner { get; }

        public string Path(string name)
        {
            var root = tree.Root;
            return name switch
            {
                "drive" => root + @"\ok.bin",
                "drive, lower-case letter" => char.ToLowerInvariant(root[0]) + root[1..] + @"\ok.bin",
                "folded slash" => root + "/ok.bin",
                "folded slash in a subdirectory" => root + @"\sub/ok2.bin",
                "a device-like file name" => root + @"\nul.txt",
                "drive-relative" => root[..2] + "ok.bin",
                "rooted without a drive" => root[2..] + @"\ok.bin",
                "NUL" => root + @"\o" + (char)0 + "k.bin",
                "empty segment" => root + @"\\ok.bin",
                "dot segment" => root + @"\.\ok.bin",
                "dot-dot segment" => root + @"\sub\..\ok.bin",
                "trailing backslash" => root + @"\sub\",
                "alternate data stream" => root + @"\ok.bin:ads",
                "::$DATA" => root + @"\ok.bin::$DATA",
                "UNC with two segments" => @"\\srv\share",
                "verbatim prefix" => @"\\?\" + root + @"\ok.bin",
                "device prefix" => @"\\.\" + root + @"\ok.bin",
                "NT object prefix" => @"\??\" + root + @"\ok.bin",
                "verbatim UNC" => @"\\?\UNC\srv\share\ok.bin",
                "lone high surrogate" => root + @"\ok" + (char)0xD800 + ".bin",
                "lone low surrogate" => root + @"\ok" + (char)0xDC00 + ".bin",
                "reversed surrogate pair" => root + @"\ok" + (char)0xDC00 + (char)0xD800 + ".bin",
                "drive root only" => root[..3],
                "a digit for a drive" => "1" + root[1..] + @"\ok.bin",
                "empty" => "",
                _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
            };
        }

        public void Dispose()
        {
            Scanner.Dispose();
            tree.Dispose();
            Script.Dispose();
        }

        private readonly ScanTree tree;
    }
    #endregion
}
#endif
