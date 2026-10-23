#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static FakeWorkerScript;

/// <summary>
/// FR2.1 of <c>docs/agent/tasks/yarax-worker.md</c> (ADR 0030's failure mode): once <see cref="YaraXWorkerScanner.Available"/>
/// may have been observed <c>true</c>, a Dispose that lands before the scan has started must make the scan THROW
/// <see cref="YaraScanIncompleteException"/>, never return an empty list. <c>PackageScanner</c> has already read
/// <c>Available == true</c> by then, so an empty list would be reported as <c>Completed</c> and clean.
///
/// <para>The gate is <c>HasEngine</c>: a disposed check, the probe's value, then a second disposed check. The window
/// between the first check and the second is reached deterministically by swapping the scanner's private
/// <c>availability</c> (a <see cref="Lazy{T}"/>) for one whose read disposes the scanner and then yields the real probe's
/// cached value. Dispose landing DURING a first-use probe is driven for real: the probe's worker hangs after
/// <c>ready</c> and the test disposes while it runs, which closes the kill-on-close job and kills it.</para>
///
/// <para>The converse stays pinned: a scanner whose probe FAILED was never available, so it has no answer and returns
/// empty (PackageScanner reports <c>Unavailable</c> from <c>Available == false</c>) and runs no worker.</para>
/// </summary>
public sealed class YaraXWorkerScannerDisposeTests
{
    #region Methods: the probe already passed
    [Fact]
    public void ScanFile_WhenDisposedBetweenTheProbeReadAndTheScan_Throws_NeverReturnsEmpty()
    {
        using var script = new FakeWorkerScript("dispose-window-file").GenuineThroughout();
        using var tree = new ScanTree("dispose-window-file");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner();
        Assert.True(scanner.Available);   // what PackageScanner sees before it asks for the scan
        var reads = DisposeOnTheNextProbeRead(scanner);

        var ex = Record.Exception(() => scanner.ScanFile(file));

        Assert.Equal(1, reads());   // the Dispose really landed inside HasEngine, after its first disposed check
        AssertDisposedIncomplete(ex, file);
        Assert.Single(script.Pids);   // the probe only: no scan worker was started
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanDirectory_WhenDisposedBetweenTheProbeReadAndTheScan_Throws_NeverReturnsEmpty()
    {
        using var script = new FakeWorkerScript("dispose-window-dir").GenuineThroughout();
        using var tree = new ScanTree("dispose-window-dir");
        tree.Write("a.bin");
        tree.Write("b.bin");
        var scanner = script.Scanner();
        Assert.True(scanner.Available);
        var reads = DisposeOnTheNextProbeRead(scanner);

        var ex = Record.Exception(() => scanner.ScanDirectory(tree.Root));

        Assert.Equal(1, reads());
        AssertDisposedIncomplete(ex, tree.Root);
        Assert.Single(script.Pids);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: Dispose during the first-use probe
    // The scan is the scanner's first use, so it runs the probe itself. Dispose lands while the probe's worker is running
    // (it said ready, then hangs instead of answering done): the job closes, the worker dies, and the probe fails because
    // of the Dispose. The scan must throw; it must not read the failed probe as "never had an engine" and return empty.
    [Fact]
    public void ScanFile_WhenDisposedDuringTheFirstUseProbe_Throws_NeverReturnsEmpty()
    {
        using var script = HangingProbe("dispose-probe-file");
        using var tree = new ScanTree("dispose-probe-file");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner(engineTimeoutSeconds: 60, readySeconds: 60);

        var ex = DisposeWhileTheProbeRuns(script, scanner, () => scanner.ScanFile(file));

        AssertDisposedIncomplete(ex, file);
        Assert.False(scanner.Available);
        Assert.Single(script.Pids);   // the probe only
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanDirectory_WhenDisposedDuringTheFirstUseProbe_Throws_NeverReturnsEmpty()
    {
        using var script = HangingProbe("dispose-probe-dir");
        using var tree = new ScanTree("dispose-probe-dir");
        tree.Write("a.bin");
        var scanner = script.Scanner(engineTimeoutSeconds: 60, readySeconds: 60);

        var ex = DisposeWhileTheProbeRuns(script, scanner, () => scanner.ScanDirectory(tree.Root));

        AssertDisposedIncomplete(ex, tree.Root);
        Assert.False(scanner.Available);
        Assert.Single(script.Pids);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: a probe that failed on its own (the converse, kept)
    // Never available, so never observed available: empty is the honest "no answer" (PackageScanner reports Unavailable
    // from Available == false), and no worker is run for the scan. ScanDirectory's twin is pinned in
    // YaraXWorkerScannerProtocolTests (Available_WhenTheProbesReadyIsNotGenuine_IsFalse_WithTheReasonWarned).
    [Fact]
    public void ScanFile_WhenTheProbeFailed_ReturnsEmpty_AndRunsNoWorker()
    {
        using var script = new FakeWorkerScript("probe-failed-file").Run(1, "out " + Fatal("no engine"), "exit 3").GenuineThroughout();
        using var tree = new ScanTree("probe-failed-file");
        var file = tree.Write("a.bin");
        using var scanner = script.Scanner();

        Assert.False(scanner.Available);
        Assert.Empty(scanner.ScanFile(file));
        Assert.Single(script.Pids);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }

    [Fact]
    public void ScanFile_WhenTheProbeFailsOnItsFirstUseInsideTheScan_ReturnsEmpty_AndRunsNoWorker()
    {
        using var script = new FakeWorkerScript("probe-failed-first-use").Run(1, "out " + Fatal("no engine"), "exit 3").GenuineThroughout();
        using var tree = new ScanTree("probe-failed-first-use");
        var file = tree.Write("a.bin");
        using var scanner = script.Scanner();

        Assert.Empty(scanner.ScanFile(file));   // the probe runs here, inside the scan, and fails by itself

        Assert.False(scanner.Available);
        Assert.Single(script.Pids);
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: helpers
    // Run 1 (the probe) says a genuine ready, then hangs instead of sending done; later runs would be genuine.
    private static FakeWorkerScript HangingProbe(string purpose) =>
        new FakeWorkerScript(purpose).Run(1, "out " + Ready(), "hang").GenuineThroughout();

    // Starts `scan` (the scanner's first use, so it runs the probe), waits until the probe's worker is running, disposes,
    // and returns what the scan threw (null when it returned). Bounded: a scan that does not end fails the test.
    private static Exception? DisposeWhileTheProbeRuns(FakeWorkerScript script, YaraXWorkerScanner scanner, Func<object> scan)
    {
        var task = Task.Factory.StartNew(scan, TaskCreationOptions.LongRunning);
        SpinWait.SpinUntil(() => script.Pids.Length == 1, TimeSpan.FromSeconds(30));
        Assert.True(script.Pids.Length == 1, "the probe's worker never started");
        Thread.Sleep(300);   // let the probe reach its read loop; any point after the worker started is a Dispose DURING the probe
        Assert.False(task.IsCompleted, "the probe finished before Dispose; the scenario was not exercised");

        scanner.Dispose();

        Assert.True(Task.WaitAny([task], TimeSpan.FromSeconds(20)) == 0, "the scan did not end after Dispose: the probe's worker was not killed");
        return task.Exception?.InnerException;
    }

    // Replaces the scanner's probe outcome (a Lazy<bool> already computed as true) with one whose next read disposes the
    // scanner and then returns the real cached value: the deterministic form of a Dispose landing after HasEngine's first
    // disposed check and before its second. Returns a counter of how many times that read happened.
    private static Func<int> DisposeOnTheNextProbeRead(YaraXWorkerScanner scanner)
    {
        var field = typeof(YaraXWorkerScanner).GetField("availability", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.True(field is not null, "YaraXWorkerScanner.availability is gone; this test swaps it.");
        var probed = (Lazy<bool>)field!.GetValue(scanner)!;
        Assert.True(probed.IsValueCreated && probed.Value, "the precondition failed: the probe had not already passed");
        var reads = 0;
        field.SetValue(scanner, new Lazy<bool>(() =>
        {
            Interlocked.Increment(ref reads);
            scanner.Dispose();
            return probed.Value;
        }));
        return () => Volatile.Read(ref reads);
    }

    private static void AssertDisposedIncomplete(Exception? ex, string path)
    {
        Assert.True(ex is not null, "the scan RETURNED after Dispose (an empty result reads as Completed and clean); it must throw");
        var incomplete = Assert.IsType<YaraScanIncompleteException>(ex);
        Assert.Contains("has been disposed", incomplete.Message, StringComparison.Ordinal);
        Assert.Contains(path, incomplete.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", incomplete.Message, StringComparison.Ordinal);
        Assert.Empty(incomplete.PartialFindings);
    }
    #endregion
}
#endif
