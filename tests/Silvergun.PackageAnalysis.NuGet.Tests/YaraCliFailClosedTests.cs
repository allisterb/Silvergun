namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0029 decision 14 (the Amendment): <b>a batch scan that did not produce a usable run is
/// <c>Unavailable</c>, not empty</b>. There are five ways <see cref="YaraCliScanner.ScanDirectory"/> can end up
/// having examined fewer files than it was pointed at, and every one of them must fail closed — the recursive
/// process exiting non-zero, failing to launch, or outliving its timeout; the tree failing to enumerate; and the
/// embedded ruleset failing to prepare. Each is covered here, together with the <see cref="YaraScanStatus"/> a
/// package scan ends up reporting.
///
/// <para><b>These tests replace two that pinned the opposite behaviour.</b> The suite previously asserted that a
/// <c>ScanDirectory</c> whose engine could not be launched — and one whose engine exited non-zero — returned an
/// <b>empty list</b>, on the stated grounds that the case was "already covered by <c>Available</c> / the
/// Unavailable status". That claim was false, and it is the reason the defect survived review:
/// <see cref="YaraCliScanner.Available"/> is a one-time <c>File.Exists</c> on the binary path, so it stays
/// <c>true</c> for an engine that cannot launch, hangs, or exits non-zero. Every test below therefore asserts
/// <c>Available == true</c> <i>first</i>: a healthy-looking backend whose scan did not happen is exactly the state
/// the old rationale claimed was impossible, and a package could reach it on demand simply by being expensive to
/// scan. Returning empty there reported a package that was never examined as a completed, clean scan.</para>
///
/// <para><b>How the failures are staged.</b> A non-zero exit and a timeout need a real executable that misbehaves
/// on demand, so they drive the <c>FakeYaraProbe</c> apphost (see <see cref="FakeYaraBinary"/>) rather than a
/// platform-specific binary such as <c>/bin/false</c> — the same test then runs on Windows and Linux alike. The
/// ruleset-preparation failure is reached by making <c>Path.GetTempPath()</c> unusable, which is process-global,
/// so it runs in a child process (<see cref="YaraHarness"/>). Only the enumeration failure is Linux-gated: it
/// needs a directory the user cannot read, and the Windows ACL APIs are not available to a <c>net10.0</c>
/// build.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliFailClosedTests
{
    #region Methods
    // --- ScanDirectory: the five "the scan did not really run" sites -----------------------------------------

    // Site 1: the recursive process ran and exited non-zero. Nothing under the root was scanned, so the result is
    // not "clean" — it is unknown. Before ADR 0029's amendment this returned an empty list and the report read
    // Completed with zero findings.
    [Fact]
    public void ScanDirectory_WhenTheBatchProcessExitsNonZero_FailsClosedAsAnIncompleteScan()
    {
        using var fake = new FakeYaraBinary(exitCode: 3);
        using var tree = new TempTree();
        tree.Write("lib/net8.0/payload.bin", HermeticWiperSample.Bytes);
        tree.Write("content/notes.txt", "ordinary text\n");

        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available, "Available is a one-time File.Exists, so an engine that fails at run time still reads as available.");
        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains("exited with code 3", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
        Assert.Null(ex.InnerException);
    }

    // Site 2: the process could not be launched at all (the configured "binary" is not an executable). The
    // backend still reports Available — the very reason the deleted test's rationale did not hold.
    [Fact]
    public void ScanDirectory_WhenTheYaraBinaryCannotBeLaunched_FailsClosedAsAnIncompleteScan()
    {
        using var fake = new PlaceholderYaraBinary();
        using var tree = new TempTree();
        tree.Write("lib/net8.0/payload.bin", HermeticWiperSample.Bytes);
        tree.Write("content/notes.txt", "ordinary text\n");

        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available, "A SILVERGUN_YARA_PATH that resolves to an existing file reads as available.");
        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains("was NOT scanned", ex.Message, StringComparison.Ordinal);
    }

    // Site 3: the process outlived its budget and was killed. This is the cheapest attack of the lot — a hostile
    // package only has to be expensive to scan — so the cause is kept machine-readable: the thrown exception
    // carries a TimeoutException as its InnerException (the ADR 0028 decision 10 carve-out, funnelled through the
    // one ADR 0029 seam).
    [Fact]
    public void ScanDirectory_WhenTheBatchProcessOutlivesItsTimeout_FailsClosedWithATimeoutInnerException()
    {
        using var fake = new FakeYaraBinary(sleepMs: 120_000);
        using var tree = new TempTree();
        tree.Write("lib/net8.0/payload.bin", HermeticWiperSample.Bytes);

        // The scanner's hard wall clock is this budget plus a fixed 5 s grace, so the test costs about that long.
        var scanner = new YaraCliScanner(scanTimeoutMs: 250);

        Assert.True(scanner.Available);
        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Contains("time budget", ex.Message, StringComparison.Ordinal);
    }

    // Site 4: the ruleset would not prepare, so no file was scanned against anything. Driven out of process
    // because the failure is induced by pointing Path.GetTempPath() at a regular file, and TMPDIR/TEMP are
    // process-global — poisoning them inside the test host would break whichever unrelated test is running in
    // parallel.
    [Fact]
    public void ScanDirectory_WhenTheEmbeddedRulesetCannotBePrepared_FailsClosedAsAnIncompleteScan()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        var notADirectory = tree.Write("temp-stand-in.bin", "a regular file, standing in for the temp directory\n");

        var result = YaraHarness.ScanDirectory(tree.Root, yaraPath: FakeYaraBinary.ProbePath, poisonTempWith: notADirectory);

        Assert.True(result["available"] == "True", "The backend must still report Available.\n" + result.Report);
        Assert.True(result.ExitCode == 1, "The harness must have caught a YaraScanIncompleteException.\n" + result.Report);
        Assert.True(result["outcome"] == "incomplete", result.Report);
        Assert.Contains("could not prepare its embedded ruleset", result["message"] ?? string.Empty, StringComparison.Ordinal);
    }

    // Site 5: the tree would not enumerate, so an unknown number of files went unscanned. Linux-gated because it
    // needs a directory the current user cannot read; the arrange step asserts that the mode actually denies this
    // user (running the suite as root would defeat it) rather than letting the test pass vacuously.
    [LinuxFact]
    public void ScanDirectory_WhenTheTreeCannotBeEnumerated_FailsClosedAsAnIncompleteScan()
    {
        using var fake = new FakeYaraBinary();
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        tree.Write("secret/payload.bin", HermeticWiperSample.Bytes);
        var unreadable = Path.Combine(tree.Root, "secret");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxFact] must have gated this test to Linux.");
        File.SetUnixFileMode(unreadable, UnixFileMode.None);
        Assert.Throws<UnauthorizedAccessException>(
            () => Directory.GetFiles(tree.Root, "*", SearchOption.AllDirectories));

        var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains("could not enumerate", ex.Message, StringComparison.Ordinal);
        Assert.Contains("unknown number of files went unscanned", ex.Message, StringComparison.Ordinal);
    }

    // --- The status the operator actually sees ----------------------------------------------------------------

    // The end of the wire, and the assertion the deleted test's rationale got wrong: a healthy-LOOKING backend
    // (Available == true) whose recursive pass failed must make the package report Unavailable, never Completed
    // with zero findings. A regression that returns an empty list instead of throwing shows up here as a clean
    // bill of health for a package no engine ever looked at.
    [Fact]
    public void Scan_WhenTheBatchProcessFails_ReportsUnavailableRatherThanACleanCompletedScan()
    {
        using var fake = new FakeYaraBinary(exitCode: 3);
        using var tree = new TempTree();
        const string id = "PkgYaraProcessFails";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "A package whose YARA pass cannot be performed.",
                    "netstandard2.0", []))),
                ("content/payload.bin", HermeticWiperSample.Bytes),
            ]);

        var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The status must be Unavailable DESPITE the health signal reading available.");

        var scan = PackageScanner.Scan(nupkg, runYara: true, yaraScanner: scanner);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
    }

    // --- ScanFile's opposite contract -------------------------------------------------------------------------

    // ScanFile is NOT part of the fail-closed change and must stay as it was: a per-file failure is swallowed so
    // the rest of a scan continues. (Its caller cannot mistake this for a clean package — ScanDirectory is what
    // decides the status, and the recovery pass distinguishes "did not scan" from "scanned, no hits" internally.)
    [Fact]
    public void ScanFile_WhenTheYaraProcessExitsNonZero_ReturnsEmptyAndNeverThrows()
    {
        using var fake = new FakeYaraBinary(exitCode: 3);
        using var tree = new TempTree();
        var target = tree.Write("lib/net8.0/payload.bin", HermeticWiperSample.Bytes);

        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available);
        Assert.Empty(scanner.ScanFile(target));
    }

    // The same for a timeout: the one condition ScanDirectory turns into an exception must still be swallowed by
    // the per-file primitive.
    [Fact]
    public void ScanFile_WhenTheYaraProcessOutlivesItsTimeout_ReturnsEmptyAndNeverThrows()
    {
        using var fake = new FakeYaraBinary(sleepMs: 120_000);
        using var tree = new TempTree();
        var target = tree.Write("lib/net8.0/payload.bin", HermeticWiperSample.Bytes);

        var scanner = new YaraCliScanner(scanTimeoutMs: 250);

        Assert.Empty(scanner.ScanFile(target));
    }
    #endregion
}
