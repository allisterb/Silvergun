namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0032 decisions 7 and 7a at the classic-CLI backend's own seam, asserting on
/// <see cref="YaraScanIncompleteException.PartialFindings"/> directly: <b>a batch pass that exited 0 but printed an
/// <c>error</c> line on stderr throws, and the exception carries every hit in hand</b> — the batch pass's attributed
/// hits, any unattributable one (decision 4), and the recovery pass's hits, because the decision-7 throw happens in
/// <see cref="YaraCliScanner.ScanDirectory"/> only <i>after</i> the recovery pass has run (decision 7a).
///
/// <para>The API-neutral half (scanner outcome and message, and the report-level view of these same shapes) is
/// <see cref="YaraCliStderrErrorLineTests"/>, which also compiles against the pre-ADR-0032 code. The shapes that need a
/// control-character file name are Linux-gated; the rest run everywhere on the <c>FakeYaraProbe</c>.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliStderrErrorPartialFindingsTests
{
    #region Methods
    // Decision 7: the batch hits are already in hand when the error line is seen, and they are real. They travel with
    // the exception; the inner exception is null because nothing of OURS timed out (yara's own --timeout is just one
    // more error line).
    [Fact]
    public void ScanDirectory_WhenTheBatchExitsZeroWithAnErrorLine_CarriesEveryBatchHit()
    {
        using var tree = new TempTree();
        tree.Write("content/a/real.bin", "ordinary content\n");
        tree.Write("content/b/real.bin", "ordinary content\n");
        tree.Write("content/notes.txt", "ordinary text\n");
        var a = Path.Combine(tree.Root, "content", "a", "real.bin");
        var b = Path.Combine(tree.Root, "content", "b", "real.bin");
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "real.bin",
            batchStdErr: "error scanning content/locked.bin: scanning timed out");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Null(ex.InnerException);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == a);
        Assert.Single(ex.PartialFindings, h => h.FullPath == b);
        Assert.All(ex.PartialFindings, h => Assert.Equal("Fake_Rule", h.Match.Rule));
        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("2 hit(s) found in the files that were scanned", ex.Message, StringComparison.Ordinal);
    }

    // With no hit in hand the exception carries none — "carry every hit" must not drift into inventing one.
    [Fact]
    public void ScanDirectory_WhenTheBatchExitsZeroWithAnErrorLineAndNoHits_CarriesNoPartialFindings()
    {
        using var tree = new TempTree();
        tree.Write("content/notes.txt", "ordinary text\n");
        using var fake = new FakeYaraBinary(batchStdErr: "error scanning content/locked.bin: could not open file");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Empty(ex.PartialFindings);
    }

    // The decision-17 guard and decision 7 in the same pass. The guard still throws from ScanBatch (decision 7a leaves
    // it there), so it must be the ONE exception that names BOTH causes — and it must carry the attributed hit and the
    // unattributable one (under the path yara echoed), whichever check would have fired alone.
    [Fact]
    public void ScanDirectory_WhenAnUnattributableHitAndAnErrorLineCoincide_ThrowsOnceNamingBothAndCarryingBothHits()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        var real = Path.Combine(tree.Root, "content", "real.bin");
        var ghost = Path.Combine(tree.Root, "content", "ghost.bin");   // never created
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "real.bin", batchGhost: "ghost.bin",
            batchStdErr: "error scanning content/locked.bin: could not open file");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Null(ex.InnerException);
        Assert.Contains("could not be attributed to any file it enumerated", ex.Message, StringComparison.Ordinal);
        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'error scanning content/locked.bin: could not open file'", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == real);
        Assert.Single(ex.PartialFindings, h => h.FullPath == ghost);
    }

    // Decision 7a, the evasion it closes. The payload is under a control-character name, so only the recovery pass can
    // find it; another file makes yara print an error line. The recovery pass must still RUN (two launches: the batch
    // and one individual scan), and its hit must travel alongside the batch hit. Throwing from ScanBatch instead would
    // have skipped it: Unavailable with zero findings for a package whose payload is right there.
    [LinuxFact]
    public void ScanDirectory_WhenTheBatchHasAnErrorLineAndAFileIsDeferred_StillRunsTheRecoveryPassAndCarriesItsHit()
    {
        using var tree = new TempTree();
        var real = tree.Write("content/real.bin", "ordinary content\n");
        var deferred = tree.Write("content/pay\nload.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            recordInvocations: true, batchEchoRule: "Fake_Rule", batchEchoName: "real.bin", echoRule: "Fake_Rule",
            batchStdErr: "error scanning content/slow.bin: scanning timed out");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Equal(2, fake.Invocations.Count);   // the batch pass, then the recovery scan of the deferred file
        Assert.Null(ex.InnerException);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == real);
        Assert.Single(ex.PartialFindings, h => h.FullPath == deferred);
        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("2 hit(s) found in the files that were scanned", ex.Message, StringComparison.Ordinal);
    }

    // Both incompleteness causes at once on the deferred path: an error line from the batch AND an unsafe-named file
    // the recovery pass cannot copy (mode 000). One combined message naming both, and every hit — the batch's and
    // the recovered file's — carried; nothing credited to the file that was never scanned. Non-root: root reads a
    // mode-000 file, so the copy would succeed and the arrange step's denial check would fail.
    [LinuxNonRootFact]
    public void ScanDirectory_WhenTheBatchHasAnErrorLineAndTheRecoveryPassFails_CombinesBothCausesAndCarriesAllHits()
    {
        using var tree = new TempTree();
        var real = tree.Write("content/real.bin", "ordinary content\n");
        var recovered = tree.Write("content/re\ncovered.bin", "ordinary content\n");
        var unreadable = tree.Write("content/un\nreadable.bin", "ordinary content\n");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxFact] must have gated this test to Linux.");
        File.SetUnixFileMode(unreadable, UnixFileMode.None);
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllBytes(unreadable));   // not running as root
        using var fake = new FakeYaraBinary(
            batchEchoRule: "Fake_Rule", batchEchoName: "real.bin", echoRule: "Fake_Rule",
            batchStdErr: "error scanning content/slow.bin: scanning timed out");

        using var cli = new YaraCliScanner();
        var ex = Assert.Throws<YaraScanIncompleteException>(() => cli.ScanDirectory(tree.Root));

        Assert.Contains("could not scan 1 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"un\nreadable.bin", ex.Message, StringComparison.Ordinal);
        Assert.Contains("exited 0 but reported 1 error line(s)", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Single(ex.PartialFindings, h => h.FullPath == real);
        Assert.Single(ex.PartialFindings, h => h.FullPath == recovered);
        Assert.DoesNotContain(ex.PartialFindings, h => h.FullPath == unreadable);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(ex.Message);
    }
    #endregion
}

/// <summary>
/// ADR 0032 decision 7 against the <b>real</b> <c>yara</c>, at the scanner seam: a readable matching file plus a
/// mode-000 copy of it. Real <c>yara -r</c> prints <c>error scanning …: could not open file</c> for the copy and exits
/// 0 — the measured behaviour the decision rests on. The scan must be incomplete and must carry the readable file's
/// hit. The positive control is built from the embedded rule's own literal bytes (<see cref="HermeticWiperSample"/>).
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliStderrErrorRealEngineTests
{
    #region Constructors
    public YaraCliStderrErrorRealEngineTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods
    [LinuxYaraNonRootFact]
    public void ScanDirectory_WhenRealYaraCannotOpenOneFile_ThrowsIncompleteCarryingTheReadableFilesHit()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var payload = tree.Write("content/payload.bin", HermeticWiperSample.Bytes);
        var locked = tree.Write("content/locked.bin", HermeticWiperSample.Bytes);
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxYaraNonRootFact] must have gated this test to Linux.");
        File.SetUnixFileMode(locked, UnixFileMode.None);
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllBytes(locked));

        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        Assert.Null(ex.InnerException);
        Assert.Contains("exited 0 but reported", ex.Message, StringComparison.Ordinal);
        Assert.Contains("locked.bin", ex.Message, StringComparison.Ordinal);
        var hit = Assert.Single(ex.PartialFindings);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
    }

    // The control: the same two files, both readable, complete with both hits and no error line. Without it the test
    // above could pass because real yara writes SOMETHING to stderr for every run (it does not — a clean run is silent).
    [LinuxYaraFact]
    public void ScanDirectory_WhenRealYaraCanOpenEveryFile_CompletesWithEveryHit()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var payload = tree.Write("content/payload.bin", HermeticWiperSample.Bytes);
        var copy = tree.Write("content/locked.bin", HermeticWiperSample.Bytes);

        using var cli = new YaraCliScanner();
        var hits = cli.ScanDirectory(tree.Root);

        Assert.Equal(2, hits.Count);
        Assert.Single(hits, h => h.FullPath == payload);
        Assert.Single(hits, h => h.FullPath == copy);
    }
    #endregion
}
