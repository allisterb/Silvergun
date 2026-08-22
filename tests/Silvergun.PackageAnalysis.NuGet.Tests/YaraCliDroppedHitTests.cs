namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0029 <b>decision 17 and its resolution 17a</b> — the seam where two decisions written in different rounds
/// contradicted each other, and the one this class exists to keep resolved.
///
/// <para><b>Decision 17.</b> <c>ScanBatch</c> used to discard every record it could not attribute, with no counter
/// and no log line. That silence is the channel the round-2 comparer evasion travelled through: a genuine hit was
/// vetoed, dropped, and the package read <c>Completed</c> with zero findings. A dropped hit whose target resolves
/// <i>under the scanned root</i> is missing coverage, so it is counted, logged with control characters escaped,
/// and fails the package closed. A target outside the root is not this package's coverage (the attacker-authored
/// second line of ADR 0029's opening example names <c>/etc/passwd.bin</c>) and must not fail anything.</para>
///
/// <para><b>Decision 17a — the priority of this file.</b> A deferred file's batch echo is <i>by construction</i>
/// unattributable: the recursive pass still walks the whole tree, so it prints a (truncated, or ambiguous) header
/// line for every file the partition just moved into the recovery pass. Counting those would fire decision 17 on
/// <b>every single recovery</b> — turning a correctly recovered, correctly attributed finding into
/// <c>Unavailable</c> with zero findings, which is exactly the outcome decisions 11–13 exist to prevent. The
/// counter therefore excludes targets whose echo key belongs to a deferred file. Delete that one exclusion and
/// <see cref="ScanDirectory_WhenTheUnattributableHitBelongsToADeferredFile_RecoversItInsteadOfFailingClosed"/>
/// goes red — it is the regression guard for the conflict, not a nicety.</para>
///
/// <para><b>How the output is staged.</b> Attribution has exactly one input: the bytes yara wrote to stdout. A
/// real engine cannot be made to print a hit for a file that does not exist, so these tests drive the
/// <c>FakeYaraProbe</c> with a staged stdout (see <see cref="FakeYaraBinary"/>) — the two cross-platform cases as
/// plain facts, and the deferred-file cases Linux-gated because a deferred file requires a name NTFS cannot
/// represent.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliDroppedHitTests
{
    #region Methods
    // --- Decision 17: a hit we saw and could not credit to anything --------------------------------------------

    // The counter itself. The batch pass reports a hit on a path under the scanned root that is not one of the
    // files it enumerated — the residue of any attribution bug, and of the evasion that motivated the decision.
    // Returning the survivors would present a package with a KNOWN missing hit as a completed scan; instead the
    // scan fails closed and the message names the escaped target, so the operator can see which one was lost.
    [Fact]
    public void ScanDirectory_WhenABatchHitNamesAnUnenumeratedFileUnderTheRoot_FailsClosedNamingTheTarget()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        var ghost = Path.Combine(tree.Root, "content", "ghost.bin");   // deliberately never created
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {ghost}");

        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available);
        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));
        Assert.Contains("could not be attributed to any file it enumerated", ex.Message, StringComparison.Ordinal);
        Assert.Contains("ghost.bin", ex.Message, StringComparison.Ordinal);
        Assert.Contains("must not be reported as clean", ex.Message, StringComparison.Ordinal);

        // Not a process failure: the engine ran fine and exited 0. This is the "we saw a hit and lost it" site,
        // which is a different defect from the decision-14 sites and must not be reported as one of them.
        Assert.Null(ex.InnerException);
    }

    // The other half of decision 17, and the reason it is scoped to the root at all: ADR 0029's opening example is
    // an attacker-authored SECOND line naming /etc/passwd.bin. That target is a real file, and it is not this
    // package's coverage — so it is rejected (never credited to anything) and it fails nothing. A counter that
    // fired on it would let any package make any scan Unavailable by printing one line, which is a denial of
    // service against the analyzer rather than a safety property.
    [Fact]
    public void ScanDirectory_WhenABatchHitNamesARealFileOutsideTheRoot_IsRejectedWithoutFailingTheScan()
    {
        using var tree = new TempTree();
        using var outside = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        var elsewhere = outside.Write("outside-the-package.bin", "not part of this package at all\n");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {elsewhere}");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        Assert.Empty(hits);
        Assert.DoesNotContain(hits, h => h.FullPath == elsewhere);
    }

    // The scanned root echoed as its own target — a directory, not a file under the root. `yara -r` prints paths,
    // and prose or a warning line can also parse as a header; neither is a lost hit. IsUnderRoot is STRICTLY
    // below the root for exactly this reason, and getting it wrong would make every scan of a tree whose engine
    // says anything at all fail closed.
    [Fact]
    public void ScanDirectory_WhenABatchLineNamesTheRootItself_IsRejectedWithoutFailingTheScan()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {tree.Root}\\nsome warning yara printed");

        Assert.Empty(new YaraCliScanner().ScanDirectory(tree.Root));
    }

    // --- Decision 17a: the deferred set is excluded, or decision 12 is destroyed --------------------------------

    // THE regression guard for the conflict between decisions 17 and 12. The tree holds one ordinary file (so the
    // batch pass runs at all) and one file whose name carries a newline. The recursive pass walks the whole tree,
    // so it prints that hostile file's hit — and, because the parser splits stdout on LF, its target arrives
    // truncated to `<root>/content/n`. That target resolves under the root and matches no enumerated file, so
    // decision 17's counter would fire on it; but the file is deferred and is being re-scanned individually right
    // now, so the coverage is being taken elsewhere, not lost.
    //
    // Both halves are asserted, and both fail without the `!deferred.Contains(key)` exclusion: the scan must NOT
    // throw, and the recovered hit must still be reported against the file's ORIGINAL path. Without the exclusion
    // this shape — the ordinary, expected outcome of ADR 0029's whole recovery design — becomes Unavailable with
    // zero findings on every package that trips it.
    [LinuxFact]
    public void ScanDirectory_WhenTheUnattributableHitBelongsToADeferredFile_RecoversItInsteadOfFailingClosed()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        var hostile = tree.Write("content/n\nl.bin", "ordinary content\n");

        // Exactly what `yara -r` prints for the hostile name: the header line ends in the echoed path, whose
        // newline puts "l.bin" on a physical line of its own (which parses as nothing at all).
        var truncated = Path.Combine(tree.Root, "content", "n");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {truncated}\\nl.bin", echoRule: "Fake_Rule");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(hostile, hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);
        Assert.True(File.Exists(hit.FullPath), "The attributed path must be the real file, not the temp copy scanned.");
    }

    // The negative control for the test above, and the pair is the point: byte-for-byte the same staged engine
    // output, the same target `<root>/content/n`, the same everything — except that the file whose truncated echo
    // that target IS has been removed, so the target no longer belongs to anything deferred. Now it is a hit that
    // was seen and lost, and the scan fails closed.
    //
    // The two tests differ in exactly one input: whether the deferred set contains the key. That is precisely the
    // condition `!deferred.Contains(key)` tests, so deleting that clause collapses the pair — the test above turns
    // into this one and goes red — without any need to mutate the source to find out.
    [LinuxFact]
    public void ScanDirectory_WhenTheSameTargetBelongsToNoDeferredFile_FailsClosed()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        var truncated = Path.Combine(tree.Root, "content", "n");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {truncated}\\nl.bin", echoRule: "Fake_Rule");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => new YaraCliScanner().ScanDirectory(tree.Root));

        Assert.Contains("matched 1 target(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("could not be attributed to any file it enumerated", ex.Message, StringComparison.Ordinal);
    }

    // The same exclusion for the deferral route that needs no control character: two names differing only by a
    // trailing space share an echoed form, so both leave the batch pass and the batch's echo of that shared form
    // belongs to both of them. Neither file's finding may be lost, and the unattributable echo must not fail the
    // scan — each file is re-scanned under its own exact path, where the engine's echo is unambiguous.
    [LinuxFact]
    public void ScanDirectory_WhenTheUnattributableHitBelongsToAnAmbiguousPair_RecoversBothFilesFindings()
    {
        using var tree = new TempTree();
        tree.Write("content/other.bin", "ordinary content\n");
        var plain = tree.Write("content/dup.bin", "ordinary content\n");
        var padded = tree.Write("content/dup.bin ", "ordinary content\n");
        var shared = Path.Combine(tree.Root, "content", "dup.bin");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {shared}", echoRule: "Fake_Rule");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        Assert.Equal(2, hits.Count);
        Assert.Single(hits, h => h.FullPath == plain);
        Assert.Single(hits, h => h.FullPath == padded);

        // ...and the ordinary file, which the batch pass never reported a hit for, collects nothing from the
        // ambiguous echo either.
        Assert.DoesNotContain(hits, h => Path.GetFileName(h.FullPath) == "other.bin");
    }

    // The counter is not disarmed by the presence of a deferred file: an escaped target that belongs to NO file —
    // deferred or otherwise — still fails the scan closed even while a recovery pass is running successfully
    // alongside it. Decision 17a narrows decision 17 to the deferred set; it does not switch it off.
    [LinuxFact]
    public void ScanDirectory_WhenARecoveryIsRunningAndAnotherHitIsStillUnattributable_FailsClosed()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");
        tree.Write("content/n\nl.bin", "ordinary content\n");
        var truncated = Path.Combine(tree.Root, "content", "n");
        var ghost = Path.Combine(tree.Root, "content", "ghost.bin");
        using var fake = new FakeYaraBinary(
            batchStdOut: $"Fake_Rule {truncated}\\nl.bin\\nFake_Rule {ghost}", echoRule: "Fake_Rule");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => new YaraCliScanner().ScanDirectory(tree.Root));

        Assert.Contains("ghost.bin", ex.Message, StringComparison.Ordinal);

        // Exactly one target was counted: the deferred file's truncated echo is excluded, not merely outvoted.
        Assert.Contains("matched 1 target(s)", ex.Message, StringComparison.Ordinal);
    }

    // --- The message is attacker-authored text, and is treated as such ------------------------------------------

    // The dropped target comes straight from package content, is put in a log line AND in an exception message,
    // and decision 17 requires it escaped. A raw newline here would let a package forge a line in our own log —
    // the same reasoning as the recovery-failure message, applied to the counter added in round 3.
    [LinuxFact]
    public void ScanDirectory_WhenTheUnattributableTargetCarriesControlCharacters_EscapesThemInTheMessage()
    {
        using var tree = new TempTree();
        tree.Write("content/real.bin", "ordinary content\n");

        // A tab survives the parser (only LF splits lines), so it reaches the message raw unless it is escaped.
        var ghost = Path.Combine(tree.Root, "content", "gh\tost.bin");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {ghost}");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => new YaraCliScanner().ScanDirectory(tree.Root));

        Assert.All(ex.Message, c => Assert.False(
            c < ' ' || c is >= (char)0x7F and <= (char)0x9F or (char)0x2028 or (char)0x2029
                        or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069,
            $"YaraScanIncompleteException.Message carried raw U+{(int)c:X4}."));
        Assert.Contains(@"gh\tost.bin", ex.Message, StringComparison.Ordinal);
    }
    #endregion
}
