namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The bounds and the escape hatches of the ADR 0029 <b>recovery pass</b> — the one-process-per-file scan
/// <see cref="YaraCliScanner.ScanDirectory"/> falls back to for entries the single <c>yara -r</c> pass cannot
/// name faithfully.
///
/// <para>Every test here is Linux-gated, and not for convenience: the recovery pass only triggers for names NTFS
/// cannot represent (a control character, a trailing space, a case-only duplicate), so on Windows the scenario
/// cannot be <i>staged</i>, let alone tested. They appear in the skipped count on Windows and in the passed count
/// under WSL. None of them needs a real engine — what is under test is which files the scanner hands to a
/// process, how many processes it is willing to spend, and what it does with the leftovers — so they drive a fake
/// binary and count its invocations.</para>
///
/// <para>The through-line is decision 13: whatever the recovery pass could not do counts as <b>unrecovered</b>,
/// and one unrecovered file makes the whole package <c>Unavailable</c>. A bound that silently dropped its
/// overflow would hand a package a false negative for the price of shipping enough hostile names — the exact
/// trade the bound exists to prevent.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliRecoveryBoundsTests
{
    #region Methods
    // The cap (MaxIndividualScans = 64). A package with thousands of unattributable names must not turn one
    // process into thousands — but the files past the cap were NOT scanned, so they count as unrecovered and the
    // package fails closed. 33 colliding pairs = 66 files in the recovery pass: 64 attempted, 2 over the cap.
    // Pinning both numbers out of the message is what makes this a test of the cap rather than of "it threw".
    [LinuxFact]
    public void ScanDirectory_WhenTheRecoveryPassExceedsItsScanCap_TreatsTheOverflowAsUnrecovered()
    {
        using var yara = new TrivialYaraStandIn();
        using var tree = new TempTree();
        const int pairs = 33;
        for (var i = 0; i < pairs; i++)
        {
            // Two names with the same echoed form: `yara -r` prints the path and the parser trims the line, so
            // these are indistinguishable in batch output and both must be re-scanned individually.
            tree.Write($"content/f{i:D2}.bin", "ordinary content\n");
            tree.Write($"content/f{i:D2}.bin ", "ordinary content\n");
        }

        var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains($"could not scan 2 of {pairs * 2} file(s)", ex.Message, StringComparison.Ordinal);
    }

    // The aggregate wall clock (the scan timeout plus its grace, for the whole pass). Ten colliding files, each
    // costing 1.5 s against a 5.25 s budget: the first few are scanned, the rest are over budget. Both halves
    // matter — some files WERE recovered (so this is the budget, not a blanket failure) and the leftovers make
    // the package Unavailable instead of quietly clean.
    [LinuxFact]
    public void ScanDirectory_WhenTheRecoveryPassExceedsItsWallClockBudget_TreatsTheRemainderAsUnrecovered()
    {
        using var fake = new FakeYaraBinary(sleepMs: 1_500);
        using var tree = new TempTree();
        const int pairs = 5;
        for (var i = 0; i < pairs; i++)
        {
            tree.Write($"content/g{i}.bin", "ordinary content\n");
            tree.Write($"content/g{i}.bin ", "ordinary content\n");
        }

        // 250 ms + the fixed 5 s grace: 10 files at 1.5 s each cannot fit, and the first one comfortably can.
        var scanner = new YaraCliScanner(scanTimeoutMs: 250);

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        var match = Regex.Match(ex.Message, @"could not scan (\d+) of (\d+) file\(s\)");
        Assert.True(match.Success, $"Unexpected message shape: {ex.Message}");
        Assert.Equal(pairs * 2, int.Parse(match.Groups[2].Value));
        var unrecovered = int.Parse(match.Groups[1].Value);
        Assert.InRange(unrecovered, 1, pairs * 2 - 1);
    }

    // The recovery pass's OTHER way of failing, and the one that keeps ADR 0030 honest for a deferred file:
    // ScanOne returns null for "this scan did not happen" — a nonzero exit here — as distinct from "it happened
    // and matched nothing", which is an empty list. Null counts as unrecovered, and one unrecovered file makes
    // the whole package Unavailable. If the two were flattened together (the `catch { return Array.Empty<>(); }`
    // shape ADR 0030 is about) this tree would report as a completed, clean scan of two files nothing looked at.
    //
    // Every file in the tree collides, so nothing is attributable and no batch pass runs: the nonzero exit can
    // only be coming from the individual re-scans.
    [LinuxFact]
    public void ScanDirectory_WhenTheEngineCannotScanADeferredFile_CountsItUnrecoveredRatherThanClean()
    {
        using var fake = new FakeYaraBinary(exitCode: 3);
        using var tree = new TempTree();
        tree.Write("content/k.bin", "ordinary content\n");
        tree.Write("content/k.bin ", "ordinary content\n");

        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available, "Available is a one-time File.Exists; an engine that fails at run time still reads as available.");
        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains("could not scan 2 of 2 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);
    }

    // A symlink is never dereferenced to recover coverage. Both yara invocations pass -N precisely so package
    // content cannot point the engine outside the extraction tree; File.Copy has no such option and WOULD follow
    // it. So a link with an unsafe name is unrecovered — the package is Unavailable — rather than being copied,
    // scanned, and reported against a path whose bytes came from somewhere else entirely.
    [LinuxFact]
    public void ScanDirectory_WhenAnUnsafeNamedEntryIsASymlink_LeavesItUnrecoveredWithoutFollowingIt()
    {
        using var fake = new FakeYaraBinary(recordInvocations: true);
        using var tree = new TempTree();
        using var outside = new TempTree();
        var elsewhere = outside.Write("outside-the-package.bin", HermeticWiperSample.Bytes);
        tree.Write("lib/net8.0/safe.bin", "ordinary content\n");
        var link = Path.Combine(tree.Root, "content", "li\nnk.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        File.CreateSymbolicLink(link, elsewhere);

        var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains(@"li\nnk.bin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(
            fake.Invocations,
            i => i.Contains("silvergun-yara-safe-", StringComparison.Ordinal));
    }

    // The staging directory briefly holds a copy of hostile package content in a world-writable /tmp, so it is
    // created owner-only. It is created and deleted inside a single ScanDirectory call, which is why the mode is
    // observed by the fake engine from the inside: its last argument is the copy it was asked to scan.
    [LinuxFact]
    public void ScanDirectory_WhenRecoveringAnUnsafeNamedFile_StagesTheCopyInAnOwnerOnlyDirectory()
    {
        using var fake = new FakeYaraBinary(recordInvocations: true);
        using var tree = new TempTree();
        tree.Write("lib/net8.0/safe.bin", "ordinary content\n");
        tree.Write("content/n\nl.bin", "ordinary content\n");

        var scanner = new YaraCliScanner();
        scanner.ScanDirectory(tree.Root);

        var staged = Assert.Single(fake.Invocations, i => i.Contains("silvergun-yara-safe-", StringComparison.Ordinal));
        Assert.Contains("dirmode=700", staged, StringComparison.Ordinal);
    }

    // The cost pin — DELIBERATELY UPDATED in ADR 0029 round 3, not weakened. It used to assert that `a.bin` and
    // `A.bin` "are NOT ambiguous, stay in the cheap single recursive pass, and the whole tree still costs exactly
    // one process". That was true while the partition grouped echo keys with StringComparer.Ordinal, and it is
    // now WRONG: decision 16 makes one comparer — OrdinalIgnoreCase — decide the partition, the `forged` veto,
    // the attribution fallback and TargetMatches alike, because mixing them is what reopened the false negative
    // (`content/mal.dll` plus an empty `content/MAL.dll\nx` decoy: ordinally distinct, so the payload stayed
    // attributable, and the case-folded veto then swallowed its genuine hit — Completed, zero findings).
    //
    // So a case-only pair on Linux now leaves the batch pass and is re-scanned individually. The ADR names that
    // as the accepted price of a single conservative comparer over an OS-conditional one, and this test is what
    // keeps the price BOUNDED: only the colliding pair pays. `b.bin` — an ordinary file sharing the tree — must
    // still cost no process of its own, and the batch pass must still happen. A regression that put every file
    // into the recovery pass would show up here as four invocations, not three.
    [LinuxFact]
    public void ScanDirectory_WithACaseOnlyDuplicatePair_MovesBothFilesIntoTheRecoveryPassAndNothingElse()
    {
        using var fake = new FakeYaraBinary(recordInvocations: true);
        using var tree = new TempTree();
        var lower = tree.Write("content/a.bin", "ordinary content\n");
        var upper = tree.Write("content/A.bin", "different but equally ordinary content\n");
        tree.Write("content/b.bin", "ordinary content\n");

        var scanner = new YaraCliScanner();
        var hits = scanner.ScanDirectory(tree.Root);

        Assert.Empty(hits);
        Assert.Equal(3, fake.Invocations.Count);
        Assert.Single(fake.Invocations, i => i.Contains($"target={tree.Root}|", StringComparison.Ordinal));
        Assert.Single(fake.Invocations, i => i.Contains($"target={lower}|", StringComparison.Ordinal));
        Assert.Single(fake.Invocations, i => i.Contains($"target={upper}|", StringComparison.Ordinal));
        Assert.DoesNotContain(fake.Invocations, i => i.Contains("target=" + Path.Combine(tree.Root, "content", "b.bin") + "|", StringComparison.Ordinal));
    }

    // The aggregate budget is spent DOWN, not handed out fresh: each scan is given only what is left of it. The
    // difference is observable as a count, which is why this is not a wall-clock test. Three colliding names, a
    // 5.25 s aggregate budget (250 ms + the fixed 5 s grace) and an engine that takes 4 s per file:
    //
    //   remaining-budget (correct): f1 runs 4 s and is recovered; f2 gets the remaining ~1.2 s and is KILLED;
    //                               f3 gets nothing.                                    => 2 of 3 unrecovered
    //   fresh-budget    (the bug):  f1 runs 4 s; f2 passes the "is there budget left?" check and is then granted
    //                               a whole new 5.25 s, so it completes at ~8 s; f3 is over. => 1 of 3
    //
    // The second shape overruns the wall clock a batch pass was allowed by almost one entire scan budget, which is
    // the bound's whole purpose. The elapsed assertion is the secondary pin on exactly that overrun.
    [LinuxFact]
    public void ScanDirectory_WhenTheRecoveryPassIsNearlyOutOfBudget_CutsTheNextScanToWhatRemains()
    {
        using var fake = new FakeYaraBinary(sleepMs: 4_000);
        using var tree = new TempTree();
        tree.Write("content/h.bin", "ordinary content\n");
        tree.Write("content/h.bin ", "ordinary content\n");
        tree.Write("content/h.bin  ", "ordinary content\n");

        // Every file collides, so nothing is attributable and no batch process runs: what is measured below is the
        // recovery pass alone.
        var scanner = new YaraCliScanner(scanTimeoutMs: 250);
        var elapsed = System.Diagnostics.Stopwatch.StartNew();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        elapsed.Stop();
        Assert.Contains("could not scan 2 of 3 file(s)", ex.Message, StringComparison.Ordinal);
        Assert.True(
            elapsed.ElapsedMilliseconds < 7_500,
            $"The recovery pass took {elapsed.ElapsedMilliseconds} ms against a 5.25 s aggregate budget; granting "
            + "a scan a fresh budget instead of the remainder lets the pass overrun by almost a whole scan.");
    }
    #endregion
}
