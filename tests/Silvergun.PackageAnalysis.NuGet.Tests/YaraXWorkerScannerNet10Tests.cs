#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

using static FakeWorkerScript;

/// <summary>
/// <see cref="YaraXWorkerScanner"/> in the net10.0 build over the FakeYaraProbe's scripted worker (ADR 0033 decision 8),
/// where there is no Job Object (<c>docs/agent/tasks/yarax-worker-linux.md</c>, L4).
/// <list type="bullet">
/// <item><b>Windows (W1):</b> this build has nothing that would contain a worker there, so every run ends at containment:
/// the worker is killed and the scanner is never available, with the reason.</item>
/// <item><b>Linux (S1):</b> the fake-worker lifetime and Dispose cases of the Windows suite
/// (<c>YaraXWorkerScannerLifetimeTests</c>, <c>YaraXWorkerScannerDisposeTests</c>), where Dispose kills the instance's live
/// workers itself instead of closing a job: Dispose mid-scan, during the first-use probe, racing first use, between the
/// probe read and the scan, and between a worker's start and its registration as live (<c>Contain</c>).</item>
/// </list>
/// </summary>
public sealed class YaraXWorkerScannerNet10Tests
{
    #region Methods: W1, Windows net10.0 has no containment
    [NonLinuxFact]
    public void OffLinux_EveryRunEndsAtContainment_TheWorkerIsKilled_AndTheScannerIsNeverAvailable()
    {
        using var script = new FakeWorkerScript("w1-nocontain").Otherwise("out " + Ready(), "readall", "hang");
        using var warnings = new WarningCapture();
        using var dir = new YaraXTempDir("w1-nocontain");
        var file = dir.Combine("a.bin");
        System.IO.File.WriteAllBytes(file, [1, 2, 3]);
        using var scanner = script.Scanner(engineTimeoutSeconds: 60, readySeconds: 60);

        var clock = Stopwatch.StartNew();
        Assert.False(scanner.Available);
        clock.Stop();

        Assert.StartsWith("this build has no worker containment on this platform", scanner.UnavailableReason, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w.Contains("YARA-X worker scanning UNAVAILABLE: this build has no worker containment on this platform", StringComparison.Ordinal));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"the probe took {clock.Elapsed}: the hung worker was not killed at containment");
        Assert.Empty(scanner.ScanFile(file));   // never available: no answer, and no further worker
        Assert.Empty(script.SentPaths);
        script.AssertNoOrphans();
    }
    #endregion

    #region Methods: S1, Available and Dispose on Linux
    [OnLinuxFact]
    public void Available_IsProbedOnce_AndCached()
    {
        using var script = new FakeWorkerScript("linux-cached").GenuineThroughout();
        using var scanner = script.Scanner();

        Assert.True(scanner.Available, scanner.UnavailableReason);
        Assert.True(scanner.Available);

        Assert.Single(script.Pids);
        Assert.Empty(Live(scanner));   // a finished run is released
        script.AssertNoOrphans();
    }

    [OnLinuxFact]
    public void ScanDirectory_WithAGenuineWorker_IsComplete_AndReleasesTheWorker()
    {
        using var script = new FakeWorkerScript("linux-genuine").GenuineThroughout();
        using var tree = new LinuxScanTree("linux-genuine");
        var file = tree.Write("a.bin");
        using var scanner = script.Scanner();

        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Equal(file, Assert.Single(hits).FullPath);
        Assert.Equal(new[] { file }, script.SentPaths);
        Assert.Empty(Live(scanner));
        script.AssertNoOrphans();
    }

    [OnLinuxFact]
    public void AfterDispose_AvailableIsFalse_AndEveryScanFailsClosed()
    {
        using var script = new FakeWorkerScript("linux-disposed").GenuineThroughout();
        using var tree = new LinuxScanTree("linux-disposed");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner();
        Assert.True(scanner.Available, scanner.UnavailableReason);

        scanner.Dispose();
        scanner.Dispose();   // idempotent

        Assert.False(scanner.Available);
        Assert.Contains("has been disposed", Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root)).Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(file)).Message, StringComparison.Ordinal);
        Assert.Single(script.Pids);   // no worker started after Dispose
        script.AssertNoOrphans();
    }

    [OnLinuxFact]
    public void DisposedBeforeFirstUse_NeverStartsAWorker()
    {
        using var script = new FakeWorkerScript("linux-disposed-early").GenuineThroughout();
        var scanner = script.Scanner();

        scanner.Dispose();

        Assert.False(scanner.Available);
        Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile("/x/a.bin"));
        Assert.Empty(script.Pids);
        Assert.Empty(Live(scanner));
    }

    // Dispose kills the live worker itself: a worker hung mid-scan (with a 60 s backstop) is killed at once, the scan ends
    // incomplete well before its own clock, and nothing is left running or registered.
    [OnLinuxFact]
    public void Dispose_MidScan_KillsTheWorker_AndTheScanEndsIncomplete()
    {
        using var script = new FakeWorkerScript("linux-dispose-mid").GenuineProbe().Otherwise("out " + Ready(), "answer 1", "hang");
        using var tree = new LinuxScanTree("linux-dispose-mid");
        tree.Write("a.bin");
        tree.Write("b.bin");
        var scanner = script.Scanner(engineTimeoutSeconds: 60);
        Assert.True(scanner.Available, scanner.UnavailableReason);

        var clock = Stopwatch.StartNew();
        var scan = Task.Factory.StartNew(() => scanner.ScanDirectory(tree.Root), TaskCreationOptions.LongRunning);
        SpinWait.SpinUntil(() => script.Pids.Length == 2 && script.SentPaths.Length >= 1, TimeSpan.FromSeconds(30));
        Assert.Equal(2, script.Pids.Length);
        var worker = script.Pids[1];
        Assert.True(SpinWait.SpinUntil(() => Live(scanner).Count == 1, TimeSpan.FromSeconds(10)), "the scan worker was never registered as live");
        Assert.True(WorkerProcesses.IsAlive(worker, WorkerProcesses.FakeWorkerName), "the worker was not running when Dispose was called");

        scanner.Dispose();

        Assert.True(Task.WaitAny([scan], TimeSpan.FromSeconds(20)) == 0, "the scan did not end after Dispose: the worker was not killed");
        clock.Stop();
        var ex = Assert.IsType<YaraScanIncompleteException>(scan.Exception?.InnerException);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"the scan took {clock.Elapsed}");
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        Assert.Empty(Live(scanner));
        script.AssertNoOrphans();
    }

    // The first use runs the probe; Dispose lands while the probe's worker hangs after ready. The worker is killed, and the
    // scan throws: a probe failed BY Dispose is never read as "never had an engine" (empty).
    [OnLinuxFact]
    public void ScanFile_WhenDisposedDuringTheFirstUseProbe_Throws_NeverReturnsEmpty()
    {
        using var script = new FakeWorkerScript("linux-dispose-probe").Run(1, "out " + Ready(), "hang").GenuineThroughout();
        using var tree = new LinuxScanTree("linux-dispose-probe");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner(engineTimeoutSeconds: 60, readySeconds: 60);

        var task = Task.Factory.StartNew(() => scanner.ScanFile(file), TaskCreationOptions.LongRunning);
        Assert.True(SpinWait.SpinUntil(() => Live(scanner).Count == 1 && script.Pids.Length == 1, TimeSpan.FromSeconds(30)), "the probe's worker never ran while registered as live");
        Assert.False(task.IsCompleted, "the probe finished before Dispose; the scenario was not exercised");

        scanner.Dispose();

        Assert.True(Task.WaitAny([task], TimeSpan.FromSeconds(20)) == 0, "the scan did not end after Dispose: the probe's worker was not killed");
        AssertDisposedIncomplete(task.Exception?.InnerException, file);
        Assert.False(scanner.Available);
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    // The window inside HasEngine (after its first disposed check, before its second), reached deterministically by
    // swapping the computed probe outcome for one whose read disposes the scanner.
    [OnLinuxFact]
    public void ScanFile_WhenDisposedBetweenTheProbeReadAndTheScan_Throws_NeverReturnsEmpty()
    {
        using var script = new FakeWorkerScript("linux-dispose-window").GenuineThroughout();
        using var tree = new LinuxScanTree("linux-dispose-window");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner();
        Assert.True(scanner.Available, scanner.UnavailableReason);
        var field = typeof(YaraXWorkerScanner).GetField("availability", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.True(field is not null, "YaraXWorkerScanner.availability is gone; this test swaps it.");
        var probed = (Lazy<bool>)field!.GetValue(scanner)!;
        field.SetValue(scanner, new Lazy<bool>(() => { scanner.Dispose(); return probed.Value; }));

        var ex = Record.Exception(() => scanner.ScanFile(file));

        AssertDisposedIncomplete(ex, file);
        Assert.Single(script.Pids);   // the probe only
        script.AssertNoOrphans();
    }

    // Review S1: Dispose lands after a worker has STARTED but before Contain registered it as live. Deterministic: this
    // thread holds the scanner's (re-entrant) job lock, so the scan blocks in Contain right after Process.Start; Dispose runs
    // on this same thread inside that window. Contain must then refuse, so the worker is killed, never registered behind
    // Dispose's back (which would leave it running, unkillable by this instance), and the scan is incomplete.
    [OnLinuxFact]
    public void Dispose_BetweenTheWorkersStartAndContain_KillsIt_AndTheScanIsIncomplete()
    {
        using var script = new FakeWorkerScript("linux-dispose-contain").GenuineProbe().Otherwise("out " + Ready(), "answer", "done");
        using var tree = new LinuxScanTree("linux-dispose-contain");
        var file = tree.Write("a.bin");
        var scanner = script.Scanner();
        Assert.True(scanner.Available, scanner.UnavailableReason);
        var jobLock = ScannerInternals.Field<Lock>(scanner, "jobLock");

        Task<Exception?> scan;
        jobLock.Enter();
        try
        {
            scan = Task.Factory.StartNew<Exception?>(() => Record.Exception(() => scanner.ScanFile(file)), TaskCreationOptions.LongRunning);
            Assert.True(SpinWait.SpinUntil(() => script.Pids.Length == 2, TimeSpan.FromSeconds(30)), "the scan's worker never started");
            Assert.False(scan.IsCompleted, "the scan finished without passing Contain");

            scanner.Dispose();   // re-entrant: this thread already holds the job lock
        }
        finally
        {
            jobLock.Exit();
        }

        Assert.True(scan.Wait(TimeSpan.FromSeconds(20)), "the scan did not end");
        var incomplete = Assert.IsType<YaraScanIncompleteException>(scan.Result);
        Assert.Contains("the scanner has been disposed", incomplete.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", incomplete.Message, StringComparison.Ordinal);
        Assert.Empty(incomplete.PartialFindings);
        Assert.Empty(Live(scanner));
        script.AssertNoOrphans();
    }

    // Dispose and the first use race at a spread of offsets. Whatever the interleaving: nothing is left registered or
    // running, the scanner ends unavailable, and every later scan fails closed.
    [OnLinuxFact]
    public void Dispose_RacingFirstUse_LeavesNoLiveWorker_AndFailsClosed()
    {
        using var script = new FakeWorkerScript("linux-race").GenuineThroughout();
        var outcomes = new List<bool>();
        for (var i = 0; i < 12; i++)
        {
            var scanner = script.Scanner();
            using var go = new Barrier(2);
            var first = Task.Factory.StartNew(() => { go.SignalAndWait(); return scanner.Available; }, TaskCreationOptions.LongRunning);
            var delay = i * 25;
            var dispose = Task.Factory.StartNew(() => { go.SignalAndWait(); Thread.Sleep(delay); scanner.Dispose(); }, TaskCreationOptions.LongRunning);
            Assert.True(Task.WaitAll([first, dispose], TimeSpan.FromSeconds(30)), $"iteration {i} did not finish");

            outcomes.Add(first.Result);
            Assert.False(scanner.Available);
            Assert.Empty(Live(scanner));
            Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile("/x/a.bin"));
        }

        script.AssertNoOrphans();
        Assert.Contains(false, outcomes);   // Dispose did land during at least one probe
    }
    #endregion

    #region Methods: helpers
    private static HashSet<Process> Live(YaraXWorkerScanner scanner)
    {
        var live = ScannerInternals.Field<HashSet<Process>>(scanner, "live");
        lock (ScannerInternals.Field<Lock>(scanner, "jobLock"))
            return [.. live];
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
