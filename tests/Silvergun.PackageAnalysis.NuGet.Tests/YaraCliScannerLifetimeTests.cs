namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Task round E, W4: <b>the temp rules dirs a <see cref="YaraCliScanner"/> prepares are deleted when it is done.</b>
/// Each instance writes up to two ~3.4 MB rulesets (the batch one with the coverage sentinel, the plain one for
/// single-file scans), each in its own <c>silvergun-yara-&lt;guid&gt;</c> temp directory; before round E nothing deleted
/// them, and a test suite or a CI agent scanning many packages grew <c>%TEMP%</c>/<c>/tmp</c> without bound.
///
/// <para>Pinned here: <see cref="YaraCliScanner.Dispose"/> deletes both dirs and is idempotent; a scan after it fails
/// closed (<see cref="YaraScanIncompleteException"/>, no launch) rather than run without rules; a Dispose that races an
/// in-flight scan defers the deletion until that scan returns; on Unix the dirs are owner-only (0700, they hold the
/// sentinel's secret name); and a scanner that is never disposed — the process-wide one
/// <see cref="YaraScannerFactory"/> hands out — still loses its dirs when its process exits normally (observed in a child
/// process, since the exit is the thing under test). Also the internal grace seam the faster budget tests use.</para>
///
/// <para>The rules dirs are located through the <c>FakeYaraProbe</c>'s invocation log, which records the rules file each
/// launch was handed (<see cref="FakeYaraBinary.RulesDirs"/>): the scanner exposes no such path, and none is needed.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliScannerLifetimeTests
{
    #region Methods
    // --- Dispose ---------------------------------------------------------------------------------------------

    // A scan that needs both rulesets (one file has no coverage line, so it is re-scanned with the plain one) leaves two
    // dirs while the scanner lives; Dispose deletes both, and a second Dispose is a quiet no-op.
    [Fact]
    public void Dispose_AfterAScanThatPreparedBothRulesets_DeletesBothRulesDirsAndIsIdempotent()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/dropped.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "dropped.bin");
        using var scanner = new YaraCliScanner();   // disposed explicitly below too: idempotence is part of the contract

        Assert.Empty(scanner.ScanDirectory(tree.Root));
        var dirs = fake.RulesDirs;
        Assert.Equal(2, dirs.Count);   // the batch ruleset and the plain one, each in its own dir
        Assert.All(dirs, d => Assert.True(Directory.Exists(d), $"'{d}' should exist while the scanner is alive."));

        scanner.Dispose();

        Assert.All(dirs, d => Assert.False(Directory.Exists(d), $"Dispose left the rules dir '{d}' behind."));
        Assert.Null(Record.Exception(scanner.Dispose));
        Assert.All(dirs, d => Assert.False(Directory.Exists(d)));
    }

    // A scanner that never prepared anything has nothing to delete: Dispose must not throw, nor touch anything else.
    [Fact]
    public void Dispose_OnAScannerThatNeverScanned_DoesNotThrow()
    {
        using var fake = new FakeYaraBinary();
        using var scanner = new YaraCliScanner();   // disposed explicitly below too: idempotence is part of the contract

        Assert.Null(Record.Exception(scanner.Dispose));
        Assert.Null(Record.Exception(scanner.Dispose));
    }

    // After Dispose a scan cannot run against its (deleted) rules, so it must not pretend to: both entry points throw
    // the one fail-closed exception and launch nothing — never an empty list that would read as a clean scan.
    [Fact]
    public void Scan_AfterDispose_ThrowsIncompleteAndLaunchesNothing()
    {
        using var tree = new TempTree();
        var file = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", echoRule: "Fake_Rule");
        using var scanner = new YaraCliScanner();   // disposed explicitly below too: idempotence is part of the contract
        Assert.Single(scanner.ScanDirectory(tree.Root));   // a working scanner first: the refusal is the dispose's doing

        scanner.Dispose();

        var directory = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        var single = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(file));
        Assert.Contains("disposed", directory.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", directory.Message, StringComparison.Ordinal);
        Assert.Contains("payload.bin", single.Message, StringComparison.Ordinal);
        Assert.Empty(directory.PartialFindings);
        Assert.Single(fake.Invocations);   // only the scan before Dispose ran
    }

    // Dispose while a scan is in flight (the contract says not to, but a caller can): the dirs that scan is using must
    // survive until it returns — deleting them under a running yara would turn its result into garbage — and are then
    // deleted by the scan's own exit. The slow fake (every launch sleeps) holds the scan open long enough to dispose it.
    [Fact]
    public async Task Dispose_DuringAnInFlightScan_DefersTheDeletionUntilTheScanReturns()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            sleepMs: 1_000, recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var scanner = new YaraCliScanner();   // disposed explicitly below too: idempotence is part of the contract

        var scan = Task.Run(() => scanner.ScanDirectory(tree.Root));
        var rulesDir = WaitForFirstRulesDir(fake, scan);
        // The probe logs its launch BEFORE it reads the rules file; give it time to finish reading and start sleeping, so
        // that on Windows an eager (wrong) deletion is not merely blocked by the probe's own open handle on that file —
        // which would let a Dispose that deletes under a running scan pass the next assertion. Measured as exactly that,
        // against a mutant whose Dispose ignored the scan in flight.
        Thread.Sleep(250);

        scanner.Dispose();

        Assert.False(scan.IsCompleted, "The scan finished before Dispose ran, so this run did not exercise the in-flight case.");
        Assert.True(Directory.Exists(rulesDir), "Dispose deleted the rules dir from under a scan that was still using it.");
        var hits = await scan;
        Assert.Equal("Fake_Rule", Assert.Single(hits).Match.Rule);
        Assert.False(Directory.Exists(rulesDir), "The in-flight scan returned, but the deferred deletion did not happen.");
    }

    // The rules dirs hold the batch ruleset, whose sentinel name is the secret that keeps package-authored output from
    // claiming coverage, in a /tmp every local user can list — so they are created owner-only, like the staging dir.
    [LinuxFact]
    public void ScanDirectory_CreatesItsRulesDirsOwnerOnly()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/dropped.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(recordInvocations: true, sentinelSkip: "dropped.bin");
        using var scanner = new YaraCliScanner();

        scanner.ScanDirectory(tree.Root);

        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxFact] must have gated this test to Linux.");
        var dirs = fake.RulesDirs;
        Assert.Equal(2, dirs.Count);
        foreach (var dir in dirs)
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                File.GetUnixFileMode(dir) & (UnixFileMode)0x1FF);
    }

    // --- The never-disposed instance (YaraScannerFactory.Shared's shape) -------------------------------------

    // A scanner nobody disposes loses its dirs when its process exits normally (the ProcessExit fallback). Observed in a
    // child process — the FakeYaraProbe harness, with --no-dispose — whose temp directory is private to this test, so the
    // count is exact: the child itself reports the two dirs it prepared, and none is left once it has exited. (The vstest
    // host is not such a process: it may be torn down without a clean exit, which is why every test here disposes.)
    [Fact]
    public void ANeverDisposedScanner_LosesItsRulesDirsWhenItsProcessExits()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/dropped.bin", "ordinary content\n");
        using var temp = new TempTree();
        using var fake = new FakeYaraBinary(sentinelSkip: "dropped.bin");

        var result = YaraHarness.ScanDirectoryInPrivateTemp(tree.Root, FakeYaraBinary.ProbePath, temp.Root, dispose: false);

        Assert.True(result["outcome"] == "completed", result.Report);
        Assert.True(result["temp"]?.TrimEnd('/', '\\') == temp.Root.TrimEnd('/', '\\'), "The child must have used the private temp dir.\n" + result.Report);
        Assert.True(result["rulesdirs"] == "2", "The child should have prepared both rulesets before exiting.\n" + result.Report);
        Assert.Empty(RulesDirsIn(temp.Root));
    }

    // The control for the test above: the same child, disposing explicitly, also leaves nothing — so the harness's
    // default (dispose) is not itself a leak, and the --no-dispose case is the one that exercises the exit fallback.
    [Fact]
    public void ADisposedScanner_InAChildProcess_LeavesNoRulesDirs()
    {
        using var tree = new TempTree();
        tree.Write("content/payload.bin", "ordinary content\n");
        tree.Write("content/dropped.bin", "ordinary content\n");
        using var temp = new TempTree();
        using var fake = new FakeYaraBinary(sentinelSkip: "dropped.bin");

        var result = YaraHarness.ScanDirectoryInPrivateTemp(tree.Root, FakeYaraBinary.ProbePath, temp.Root, dispose: true);

        Assert.True(result["outcome"] == "completed", result.Report);
        Assert.True(result["rulesdirs"] == "2", result.Report);
        Assert.Empty(RulesDirsIn(temp.Root));
    }

    // --- The grace seam -------------------------------------------------------------------------------------

    // The internal (scanTimeoutMs, graceMs) constructor sets the wall clock a launch gets over yara's own --timeout before
    // it is killed: with a 250 ms budget a never-ending fake is killed after ~250 ms + grace. Two graces, two kill times —
    // and neither is the public constructor's 5 s default, which is what the budget tests rely on to stay fast.
    [Theory]
    [InlineData(0, 0, 1_600)]
    [InlineData(1_500, 1_650, 4_900)]
    public void ScanFile_WithAGraceThroughTheTestSeam_KillsTheLaunchAfterTimeoutPlusGrace(int graceMs, int minMs, int maxMs)
    {
        using var tree = new TempTree();
        var file = Path.GetFullPath(tree.Write("content/payload.bin", "ordinary content\n"));
        using var fake = new FakeYaraBinary(sleepMs: 120_000);
        using var scanner = new YaraCliScanner(250, graceMs);
        var elapsed = Stopwatch.StartNew();

        Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanFile(file));

        elapsed.Stop();
        Assert.InRange(elapsed.ElapsedMilliseconds, minMs, maxMs);
    }

    // A negative grace would put the wall clock BELOW yara's own --timeout: refused, not normalized.
    [Fact]
    public void Constructor_WithANegativeGrace_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new YaraCliScanner(250, -1));
    }
    #endregion

    #region Helpers
    // The first rules dir the in-flight scan's launch was handed, read off the probe's log (written before it sleeps).
    // The probe may be appending to the log at the moment it is read; a sharing violation just means "look again".
    private static string WaitForFirstRulesDir(FakeYaraBinary fake, Task scan)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.ElapsedMilliseconds < 60_000)
        {
            try
            {
                if (fake.RulesDirs.FirstOrDefault() is { } dir)
                    return dir;
            }
            catch (IOException)
            {
                /* the probe holds the log open for its append: retry */
            }

            if (scan.IsCompleted)
                break;
            Thread.Sleep(10);
        }

        throw new InvalidOperationException($"The scan never launched the fake engine (completed: {scan.IsCompleted}; {scan.Exception?.GetBaseException().Message}).");
    }

    // YaraCliScanner's rules dirs under `temp`: `silvergun-yara-` + a 32-hex-digit Guid (not the `-safe-` staging dirs).
    private static string[] RulesDirsIn(string temp) =>
        Directory.EnumerateDirectories(temp, "silvergun-yara-*")
            .Where(d => Path.GetFileName(d) is { Length: 47 } n && n[15..].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))
            .ToArray();
    #endregion
}
