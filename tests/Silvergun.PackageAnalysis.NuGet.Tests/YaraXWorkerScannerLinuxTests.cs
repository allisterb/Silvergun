#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;

using static LinuxYaraX;

/// <summary>
/// The parent backend <see cref="YaraXWorkerScanner"/> on Linux, over the REAL worker (<c>docs/agent/tasks/yarax-worker-linux.md</c>,
/// Phase 1: L3 path form, L4 containment, L7 worker executable). The class's scanner has the production launch arguments
/// and engine timeout over the real <c>Silvergun.CLI</c> apphost in the CLI's own output (<see cref="LinuxYaraX.CliPath"/>),
/// and its probe must pass. Every link target
/// holds the positive control, so a followed link would show up as a hit; a refused file is unscanned, never clean.
/// <para>The containment tests find their worker among this test host's <c>Silvergun.CLI</c> children, so the class runs
/// alone (<see cref="LinuxWorkerProcessesCollection"/>), never beside another class that starts workers.</para>
/// </summary>
[Collection(LinuxWorkerProcessesCollection.Name)]
public sealed class YaraXWorkerScannerLinuxTests(YaraXWorkerScannerLinuxTests.Shared shared) : IClassFixture<YaraXWorkerScannerLinuxTests.Shared>
{
    #region Methods: L7, the production worker
    // L7: on Linux the worker is the extension-less `Silvergun.CLI` apphost, found as the process itself (step 1) or beside
    // it (step 2), never a `.exe`; and the real one's probe is genuine.
    [LinuxYaraXFact]
    public void TheWorkerExecutable_IsTheExtensionlessApphost_AndItsProbeIsGenuine()
    {
        Assert.Equal((CliPath, (string?)null), YaraXWorkerScanner.ResolveWorkerExecutable(CliPath, AppContext.BaseDirectory));
        Assert.Equal((CliPath, (string?)null), YaraXWorkerScanner.ResolveWorkerExecutable("/usr/bin/dotnet", CliDirectory));
        Assert.Contains("there is no Silvergun.CLI in its application directory",
            YaraXWorkerScanner.ResolveWorkerExecutable("/usr/bin/dotnet", AppContext.BaseDirectory).Problem, StringComparison.Ordinal);
        Assert.True(shared.Scanner.Available, shared.Scanner.UnavailableReason);
    }
    #endregion

    #region Methods: L3, the path form
    // A backslash is a name character: the file `dir\positive.bin` goes on the wire unchanged (no '/'→'\' folding, no
    // '\'→'/'), the worker opens it as named, and its hit is reported against the path as listed.
    [LinuxYaraXFact]
    public void ScanFiles_ABackslashInAFileName_IsSentUnchanged_AndItsHitIsKept()
    {
        using var tree = new LinuxScanTree("scanner-linux-backslash");
        var named = tree.Write(@"dir\positive.bin", HermeticWiperSample.Bytes);

        var hits = shared.Scanner.ScanFiles(tree.Root, [named]);

        var (path, match) = Assert.Single(hits);
        Assert.Equal(named, path);
        Assert.Equal(HermeticWiperSample.RuleName, match.Rule);
    }

    [LinuxYaraXFact]
    public void ScanDirectory_ATreeWithABackslashName_FindsThePositive()
    {
        using var tree = new LinuxScanTree("scanner-linux-backslash-dir");
        var named = tree.Write(@"a\b\positive.bin", HermeticWiperSample.Bytes);
        tree.Write("sub/benign.txt");

        var hits = shared.Scanner.ScanDirectory(tree.Root);

        Assert.Equal(named, Assert.Single(hits).FullPath);
    }

    // A path the worker would refuse is refused by the parent first (amendment (j'): the same WorkerPathForm), with the
    // Linux wording, and is unscanned; the file listed beside it is still scanned and its hit kept as a partial finding.
    [LinuxYaraXTheory]
    [InlineData("relative")]
    [InlineData("a dot segment")]
    [InlineData("a dot-dot segment")]
    [InlineData("an empty segment")]
    public void ScanFiles_APathOutOfForm_IsRefused_AndTheOtherFileIsStillScanned(string what)
    {
        using var tree = new LinuxScanTree("scanner-linux-form");
        var good = tree.Write("good.bin", HermeticWiperSample.Bytes);
        tree.Write("sub/positive.bin", HermeticWiperSample.Bytes);
        var bad = what switch
        {
            "relative" => "sub/positive.bin",
            "a dot segment" => tree.Root + "/sub/./positive.bin",
            "a dot-dot segment" => tree.Root + "/sub/../sub/positive.bin",
            "an empty segment" => tree.Root + "/sub//positive.bin",
            _ => throw new ArgumentOutOfRangeException(nameof(what)),
        };
        Assert.Null(WorkerPathForm.Verbatim(bad, windows: false));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => shared.Scanner.ScanFiles(tree.Root, [good, bad]));

        Assert.Contains("did not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("its path is not in the worker protocol's form (absolute, well-formed UTF-16, no NUL, no '.', '..' or empty segment)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        Assert.Equal(good, Assert.Single(ex.PartialFindings).FullPath);
    }
    #endregion

    #region Methods: L3, links
    // A symlinked file under the root, pointing at the positive outside it, is refused (lstat: the link itself is seen, not
    // followed): no hit from outside the package, and the run is incomplete.
    [LinuxYaraXFact]
    public void ScanFiles_ASymlinkedFile_IsRefused_AndItsTargetIsNeverScanned()
    {
        using var tree = new LinuxScanTree("scanner-linux-filelink");
        var good = tree.Write("good.bin", HermeticWiperSample.Bytes);
        var link = tree.Symlink("linked.bin", tree.WriteOutside("secret.bin", HermeticWiperSample.Bytes));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => shared.Scanner.ScanFiles(tree.Root, [good, link]));

        AssertRefusedAsLink(ex, good);
    }

    // The walk covers every directory between the root (exclusive) and the file: a symlinked directory as the parent, or
    // further up, is refused just the same.
    [LinuxYaraXTheory]
    [InlineData("linked", "linked/secret.bin")]
    [InlineData("sub/linked", "sub/linked/secret.bin")]
    [InlineData("a/linked", "a/linked/b/secret.bin")]
    public void ScanFiles_AFileUnderASymlinkedAncestor_IsRefused(string linkAt, string file)
    {
        using var tree = new LinuxScanTree("scanner-linux-dirlink");
        var good = tree.Write("good.bin", HermeticWiperSample.Bytes);
        var target = Path.Combine(tree.Outside, "t");
        var underTarget = Path.GetRelativePath(linkAt, file);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(target, underTarget))!);
        File.WriteAllBytes(Path.Combine(target, underTarget), HermeticWiperSample.Bytes);
        tree.Symlink(linkAt, target);
        var through = Path.Combine(tree.Root, file);
        Assert.True(File.Exists(through), "the staged file is not reachable through the link");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => shared.Scanner.ScanFiles(tree.Root, [good, through]));

        AssertRefusedAsLink(ex, good);
    }

    // ScanFile has no root to bound the walk, so only the file itself is checked, and a symlink is refused.
    [LinuxYaraXFact]
    public void ScanFile_ASymlink_IsRefused()
    {
        using var tree = new LinuxScanTree("scanner-linux-scanfile-link");
        var link = tree.Symlink("linked.bin", tree.WriteOutside("secret.bin", HermeticWiperSample.Bytes));

        var ex = Assert.Throws<YaraScanIncompleteException>(() => shared.Scanner.ScanFile(link));

        Assert.Contains("it is a link, lies under a linked directory", ex.Message, StringComparison.Ordinal);
        Assert.Empty(ex.PartialFindings);
    }

    // The control for the link tests: the same layout with a real directory is scanned, and the positive found.
    [LinuxYaraXFact]
    public void ScanFiles_TheSameLayoutWithoutALink_IsScanned()
    {
        using var tree = new LinuxScanTree("scanner-linux-nolink");
        var file = tree.Write("a/linked/b/secret.bin", HermeticWiperSample.Bytes);

        var hits = shared.Scanner.ScanFiles(tree.Root, [file]);

        Assert.Equal(file, Assert.Single(hits).FullPath);
    }
    #endregion

    #region Methods: L4 and L3, a worker that blocks
    // L4: with no Job Object, Dispose kills this instance's live workers itself. A FIFO blocks the worker in open (L3: a
    // planted FIFO); Dispose ends the scan at once (long before the 30 s + 5 s backstop): incomplete, never clean, and the
    // worker is gone.
    [LinuxYaraXFact]
    [Trait("Category", "Slow")]
    public void Dispose_KillsALiveWorker_AndTheScanEndsIncomplete()
    {
        using var tree = new LinuxScanTree("scanner-linux-dispose");
        var fifo = Path.Combine(tree.Root, "blocks.bin");
        MakeFifo(fifo);
        var scanner = LinuxYaraX.Scanner();
        Assert.True(scanner.Available, scanner.UnavailableReason);
        Assert.Empty(ChildWorkers());

        var scan = Task.Run(() => Record.Exception(() => scanner.ScanFiles(tree.Root, [fifo])));
        var worker = WaitFor(() => ChildWorkers().SingleOrDefault(), TimeSpan.FromSeconds(30));
        // A real signal, not a sleep past the compile: the worker is ready (it reads requests only after ready) and blocked
        // in the kernel opening the FIFO, which no writer will ever open.
        Assert.True(SpinWait.SpinUntil(() => IsBlockedOpeningAFifo(worker), TimeSpan.FromSeconds(60)),
            $"worker {worker} never blocked opening the FIFO");
        Assert.False(scan.IsCompleted, "the scan over a FIFO ended by itself");

        var clock = Stopwatch.StartNew();
        scanner.Dispose();
        Assert.True(scan.Wait(TimeSpan.FromSeconds(10)), "the scan did not end within 10 s of Dispose");
        clock.Stop();

        var incomplete = Assert.IsType<YaraScanIncompleteException>(scan.Result);
        Assert.Contains("must not be reported as clean", incomplete.Message, StringComparison.Ordinal);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"Dispose took {clock.Elapsed} to end the scan");
        Assert.False(IsAlive(worker, WorkerComm), $"worker {worker} outlived Dispose");
    }

    // L3, the FIFO a planted entry could be: it blocks the worker, the parent's backstop (engine timeout plus grace) kills
    // it, and the scan is incomplete, never clean: fail-closed, with no file-type check.
    [LinuxYaraXFact]
    [Trait("Category", "Slow")]
    public void APlantedFifo_IsKilledByTheBackstop_AndTheScanIsIncomplete()
    {
        using var tree = new LinuxScanTree("scanner-linux-fifo");
        var good = tree.Write("good.bin", HermeticWiperSample.Bytes);
        var fifo = Path.Combine(tree.Root, "blocks.bin");
        MakeFifo(fifo);
        using var scanner = LinuxYaraX.Scanner(engineTimeoutSeconds: 2, graceSeconds: 1);

        var clock = Stopwatch.StartNew();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFiles(tree.Root, [good, fifo]));
        clock.Stop();

        Assert.Contains("the worker sent nothing for 3 s", ex.Message, StringComparison.Ordinal);
        Assert.Equal(good, Assert.Single(ex.PartialFindings).FullPath);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(60), $"the scan took {clock.Elapsed}");
        Assert.Empty(ChildWorkers());
    }
    #endregion

    #region Methods: helpers
    private static void AssertRefusedAsLink(YaraScanIncompleteException ex, string good)
    {
        Assert.Contains("did not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("it is a link, lies under a linked directory, or could not be checked for either", ex.Message, StringComparison.Ordinal);
        Assert.Equal(good, Assert.Single(ex.PartialFindings).FullPath);
    }

    private static int WaitFor(Func<int> probe, TimeSpan within)
    {
        var deadline = DateTime.UtcNow + within;
        while (DateTime.UtcNow < deadline)
        {
            if (probe() is var found and > 0)
                return found;
            Thread.Sleep(25);
        }
        Assert.Fail($"no worker appeared within {within}");
        return 0;
    }
    #endregion

    #region Nested types
    /// <summary>One production-shaped scanner for the class: its probe (one compile) runs once.</summary>
    public sealed class Shared : IDisposable
    {
        public YaraXWorkerScanner Scanner { get; } = LinuxYaraX.Scanner();

        public void Dispose() => Scanner.Dispose();
    }
    #endregion
}

/// <summary>Runs its classes with no other test class in parallel: they count this host's worker children.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LinuxWorkerProcessesCollection
{
    public const string Name = "linux-worker-processes";
}
#endif
