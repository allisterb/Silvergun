namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0029 decision 17a and the <b>converse invariant</b> of ADR 0030: <c>Unavailable</c> must mean "we could not
/// tell", never "we could tell and threw it away."
///
/// <para><b>The defect this class exists for.</b> Decision 17 counts every batch record that resolves under the
/// scanned root and cannot be attributed, and fails the package closed. Decision 17a excludes the files the
/// recovery pass is re-scanning, because their batch echo is unattributable <i>by construction</i>. The first
/// implementation of that exclusion compared the whole normalised echoed target against a set of <b>truncated</b>
/// echo keys. Those two strings coincide only when the output path itself cuts the name back to that truncation:
/// at a CR or an LF, where the stdout reader breaks the line, or at a trailing whitespace control, which
/// <c>YaraCliOutput.ParseAll</c>'s per-line <c>TrimEnd</c> removes. For a TAB, or any of 0x01–0x08 / 0x0B / 0x0C /
/// 0x0E–0x1F with more of the name behind it, the echoed target arrives with the control character <b>intact</b>,
/// misses the deferred set, is counted as a dropped hit, and <c>ScanBatch</c> throws <i>before</i> the recovery
/// pass runs. A matching payload at <c>content/pay\tload.bin</c> therefore reported <c>Unavailable</c> with
/// <b>zero findings</b> instead of <c>Completed</c> with the hit correctly attributed. It fails closed, so nothing
/// read as clean — but a definite detection was converted into an incompleteness, and under
/// <c>--strict --allow-incomplete</c> that is exit 2 collapsing to exit 0. The fix compares
/// <c>EchoKey(target)</c>.</para>
///
/// <para><b>Why the existing suite could not see it.</b> Every test that staged a <i>matching</i> deferred file
/// used <c>'\n'</c>, and the only non-LF control-character name in the suite (the <c>'\r'</c> in
/// <see cref="YaraCliScannerUnsafePathTests"/>) belonged to a file that does not match, so no record was ever
/// produced for it. The blind spot was a whole class of control characters, which is why the guard below is a
/// <see cref="LinuxYaraTheoryAttribute"/> over a non-LF/CR set rather than one more example — and why the CR
/// shape, the other half of the cut set, now has a matching file of its own here too.</para>
///
/// <para><b>Both sides of the guard are pinned, deliberately.</b> Widening an exclusion is exactly as dangerous as
/// leaving it too narrow: the same tree must recover its finding <i>and</i> still fail closed on a target that
/// belongs to no enumerated file. Pinning one side alone is what let this round's fix be judged only against the
/// direction that had just broken. That pair is staged with a fake engine — the only way to print output no real
/// engine can produce — and therefore lives in <see cref="YaraCliDeferredEchoFakeEngineTests"/> below.</para>
///
/// <para><b>Verified red — re-measured, not inherited.</b> Numbers below are from a re-run on 2026-08-22 under
/// WSL with <c>SILVERGUN_REQUIRE_YARA=1</c>, suite size <b>576</b>, each mutation applied to a throw-away copy of
/// the tree. Re-measure before editing them; the previous revision of this paragraph pinned counts from a
/// smaller suite and drew the wrong conclusion from them.</para>
///
/// <para><i>Mutation 1 — the round-1 predicate</i> (<c>!deferred.Contains(key)</c> over the target's normalised
/// form instead of its echo key): <b>8 fail, 568 pass</b>, and all 8 are in this file — the five theory cases,
/// the <c>.nupkg</c> case, and the fake-engine pair over the shared tree. Nothing else in the suite moves at all:
/// that is the blind spot, measured rather than asserted. The CR case is deliberately not among the 8; it cannot
/// tell the two predicates apart, because its echo is cut at the CR and both then compare the same string.</para>
///
/// <para><i>Mutation 2 — <c>IsUnderRoot</c> accepting <c>'\\'</c> as a separator</i>: <b>exactly 1 fails</b>,
/// <c>..._IsNotCountedAsLost</c>, with the other 575 green. Its partner <c>..._SeparatedBySlash_FailsClosed</c> is
/// insensitive to this mutation <i>by design</i> — it is the control that makes the separator, rather than the
/// shape of the ghost name, the thing under test, and a control that moved with the mutation would prove nothing.
/// (An earlier revision claimed both survivors of mutation 1 fail here; they do not, and its own "574 pass"
/// already implied a single failure.)</para>
///
/// <para><i>Mutation 3 — <c>TruncateAtFirstControl</c> no longer cutting at 0x0D</i>, i.e. the "CR behaves like
/// TAB" mistake the source comment warns against: <b>2 fail</b> — the CR case here, and
/// <c>YaraEchoKeyTests</c>' CR inline case, which pins the helper in isolation. See that test's own comment.</para>
///
/// <para><b>Two tiers, two classes.</b> The recovery cases run against a <b>real</b> yara over a real matching
/// sample, because this ADR exists because our model of <c>yara -r</c>'s output was wrong; a fake would only
/// re-assert the model. They are gathered here, behind the constructor's real-binary requirement. The cases that
/// need output no real engine can be made to produce — a hit on a file that does not exist — drive the
/// <c>FakeYaraProbe</c> and are in the sibling class, which must NOT carry that requirement: it would fail those
/// four on a yara-less Linux box under <c>SILVERGUN_REQUIRE_YARA=1</c> for a reason that does not apply to them.
/// Both tiers need names NTFS cannot represent, so both are Linux-gated and appear in the <c>Skipped</c> count on
/// Windows.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliDeferredEchoTests
{
    #region Constructors
    public YaraCliDeferredEchoTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods
    // --- The defect, real engine, over the whole class of characters that reached it -------------------------

    // THE regression. A matching payload whose name carries a control character that the output path does NOT cut
    // the line at, beside a benign file with an ordinary name.
    //
    // The benign sibling is load-bearing, not scenery: with nothing attributable, ScanDirectory skips ScanBatch
    // entirely and the dropped-hit guard never executes, so the test would pass vacuously against the broken
    // predicate. That is asserted below rather than assumed.
    //
    // Expected: the batch pass sees the payload's hit, cannot attribute it (the payload is deferred), recognises
    // it as a deferred file's echo and leaves it alone; the recovery pass then scans the payload through a safely
    // named copy and attributes the hit to its ORIGINAL path. One finding, no throw.
    //
    // Why five samples and not all 31: both halves of the decision treat C0 as ONE alphabet by construction —
    // IsUnsafeName is `c <= 0x1F` applied to every character, and TruncateAtFirstControl is a single
    // IndexOfAnyInRange('\0', (char)0x1F). Neither has a per-character branch for a 31-row table to find. Do NOT
    // justify the sampling by saying those two are exhaustively tested elsewhere — they are not: YaraPathSafety-
    // Tests samples each with about a dozen inline cases, and only Escape, which really does branch per
    // character, is exhausted (over the whole BMP).
    //
    // What varies across C0 downstream is char.IsWhiteSpace, and only that: whitespace is the sole property
    // anything past the partition tests a control character for (TryNormalize's IsNullOrWhiteSpace and Trim,
    // ParseAll's per-line TrimEnd and the `\s+` in its header regex). It is true for 0x09/0x0B/0x0C and false for
    // 0x01/0x1F, so the set below covers both classes as well as both ends of the range.
    //
    // 0x00 is absent because it is UNSTAGEABLE, not because 0x01 stands in for it: a NUL terminates a POSIX
    // filename, so no file can carry one, and no process argument can carry one either — there is no way to put
    // that scenario on disk or in front of the engine at all. LF and CR are absent for the opposite reason: they
    // ARE cut out of the echoed target, which is different behaviour with its own tests — the CR case immediately
    // below, and the LF cases in YaraCliAttributionTests.
    [LinuxYaraTheory]
    [InlineData('\t')]        // 0x09 — the character the defect was reported on
    [InlineData('\u0001')]    // 0x01 — the bottom of the range the output path leaves intact
    [InlineData('\u000B')]    // 0x0B — vertical tab: whitespace to Trim, but not a line break to the stdout reader
    [InlineData('\u000C')]    // 0x0C — form feed, same shape
    [InlineData('\u001F')]    // 0x1F — the top of the C0 range
    public void ScanDirectory_WhenAMatchingDeferredNameCarriesANonNewlineControlCharacter_RecoversTheHitInsteadOfFailingClosed(char control)
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var benign = tree.Write("content/benign.bin", "no signature here\n");
        var payload = tree.Write($"content/pay{control}load.bin", HermeticWiperSample.Bytes);

        // The precondition that makes this test non-vacuous: `benign` stays in the batch pass, so ScanBatch — and
        // therefore decision 17's counter — actually runs. If this ever fails, the assertions below stop meaning
        // anything, because the guard under test would not be reached at all.
        Assert.False(YaraPathSafety.IsUnsafeName(benign), "The sibling must be attributable or ScanBatch is skipped.");
        Assert.NotEqual(
            YaraCliScanner.TryNormalize(benign),
            YaraCliScanner.TryNormalize(YaraPathSafety.TruncateAtFirstControl(payload)));

        // ...and the precondition that makes it the RIGHT test: the payload's echo is not line-split, so the
        // target that reaches the guard still carries the control character.
        Assert.True(YaraPathSafety.IsUnsafeName(payload));
        Assert.False(
            payload.Contains('\n') || payload.Contains('\r'),
            "This theory covers the characters the output path does NOT cut a line at; an LF or CR case is the "
            + "shape that already worked and would not exercise this defect (the CR shape has its own test below).");

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        Assert.True(File.Exists(hit.FullPath), "The attributed path must be the real file, not the temp copy scanned.");
        Assert.DoesNotContain(hits, h => h.FullPath == benign);
    }

    // The other half of the cut set, and the claim in YaraCliScanner that nothing else enforces: a CR is absent
    // from the theory above *because it cuts the line*, so a CR-named file's echoed target arrives already
    // truncated. The source comment says exactly that and says "do not restore it here" — a statement about
    // behaviour with, until this test, no behaviour pinned.
    //
    // The premise is measured, not assumed. A child process printing three header lines that differ only in the
    // control character produces FOUR OutputDataReceived events: the CR line arrives as "…/pay" and "load.bin",
    // while the 0x09 and 0x0B lines arrive whole and still carry their character after the reader rejoins on LF
    // (probe re-run under WSL on 2026-08-22; Round A's independent probe found the same). The split remainder
    // ("load.bin") cannot be mistaken for a hit either — ParseAll's header regex needs whitespace before a
    // target, and that fragment has none.
    //
    // Read the two together: TAB survives, so the guard must compare echo keys; CR does not survive, so the guard
    // must still recognise the bare truncation.
    //
    // Verified red, in a throw-away copy of the tree, against the literal mistake the source warns about —
    // TruncateAtFirstControl changed to skip 0x0D, i.e. "CR behaves like TAB, so it need not be truncated". The
    // deferred key then keeps its CR, this echoed target ('…/content/pay') matches nothing in `deferred`, a hit
    // that was about to be recovered is counted as lost, and the single finding below becomes a
    // YaraScanIncompleteException. Measured: 2 of 576 fail — this test and YaraEchoKeyTests' CR inline case,
    // which pins the helper in isolation; the other 10 cases in this file pass, the theory above included, since
    // its characters never reach the cut. This is the test that pins the CONSEQUENCE the source comment claims —
    // that a real, matching, CR-named file is recovered and attributed rather than counted as missing coverage.
    [LinuxYaraFact]
    public void ScanDirectory_WhenAMatchingDeferredNameCarriesACarriageReturn_RecoversTheHitAndAttributesItToTheCrNamedPath()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var benign = tree.Write("content/benign.bin", "no signature here\n");
        var payload = tree.Write("content/pay\rload.bin", HermeticWiperSample.Bytes);

        // Same non-vacuity precondition as the theory: something must stay attributable or ScanBatch — and with
        // it the dropped-hit guard this test is about — never runs at all.
        Assert.False(YaraPathSafety.IsUnsafeName(benign), "The sibling must be attributable or ScanBatch is skipped.");
        Assert.True(YaraPathSafety.IsUnsafeName(payload));
        Assert.NotEqual(
            YaraCliScanner.TryNormalize(benign),
            YaraCliScanner.TryNormalize(YaraPathSafety.TruncateAtFirstControl(payload)));

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Contains('\r', hit.FullPath);   // attributed to the real, CR-carrying name — not to its truncation
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
        Assert.True(File.Exists(hit.FullPath), "The attributed path must be the real file, not the temp copy scanned.");
        Assert.DoesNotContain(hits, h => h.FullPath == benign);
    }

    // The same shape as the operator sees it, end to end through a real .nupkg. This is the assertion the ADR 0030
    // converse is about: the status must be Completed WITH the finding. `Unavailable` with zero findings is what
    // the broken predicate produced, and it is not the safe direction — it is a detection downgraded to
    // "we don't know", which --strict --allow-incomplete turns from exit 2 into exit 0.
    [LinuxYaraFact]
    public void Scan_PackageWhoseTabNamedEntryMatches_ReportsTheFindingAndCompletes()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        const string id = "PkgTabNamedPayload";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");

        // The tab-named entry is an ordinary `entries` member, not a `rawEntries` one: both are stored verbatim,
        // but rawEntries exists for names that must be SKIPPED on extraction (zip-slip), and this entry must be
        // extracted — the finding below is the whole point.
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "Tab-named payload regression package (ADR 0029 decision 17a).",
                    "netstandard2.0", []))),
                ("content/benign.bin", Encoding.UTF8.GetBytes("no signature here\n")),
                ("content/pay\tload.bin", HermeticWiperSample.Bytes),
            ]);

        var scan = PackageScanner.Scan(nupkg, runYara: true, yaraScanner: new YaraCliScanner());

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/pay\tload.bin", finding.RelativePath);
        Assert.Equal(HermeticWiperSample.RuleName, finding.RuleName);
    }
    #endregion
}

/// <summary>
/// The fake-engine half of <see cref="YaraCliDeferredEchoTests"/> — read that class's summary first; it carries
/// the defect narrative these cases belong to.
///
/// <para><b>Why a separate class.</b> These four cases need a hostile <b>name</b> and a staged engine output, not
/// a real engine: three of them assert on a hit for a target that is not on disk at all, and the fourth on a hit
/// for a file whose contents match nothing — output no real yara can be made to print. Applying the other class's
/// <c>EnforceBinaryRequirement()</c> here would fail all four on a yara-less Linux box under
/// <c>SILVERGUN_REQUIRE_YARA=1</c>, for a missing dependency none of them uses. The collection attribute stays:
/// <c>FakeYaraBinary</c> writes the process-global <c>SILVERGUN_*</c> variables.</para>
///
/// <para><b>The pair is the point.</b> The first two cases are the two sides of one guard over one tree, whose
/// staged output differs in nothing but the extra ghost line. Pinning only the recovery invites the exclusion to
/// be widened until it swallows genuine losses; pinning only the fail-closed side is what produced this round's
/// Critical.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliDeferredEchoFakeEngineTests
{
    #region Methods
    // --- Both sides of the same guard, over one tree ----------------------------------------------------------

    // Side one, with the engine's output staged so the two tests below differ in NOTHING but the extra line: the
    // batch echo of a deferred file, control character intact, is coverage taken elsewhere and must not be
    // counted as lost. The invocation count is asserted because it is the only direct evidence that the cheap
    // batch pass ran at all — one recursive pass plus exactly one recovery scan.
    [LinuxFact]
    public void ScanDirectory_WhenABatchEchoKeepsADeferredFilesControlCharacter_RecoversItWithoutFailingClosed()
    {
        using var tree = new TempTree();
        tree.Write("content/benign.bin", "no signature here\n");
        var payload = tree.Write("content/pay\tload.bin", "ordinary content\n");
        using var fake = new FakeYaraBinary(
            batchStdOut: $"Fake_Rule {payload}", echoRule: "Fake_Rule", recordInvocations: true);

        var hits = new YaraCliScanner().ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(payload, hit.FullPath);
        Assert.Equal("Fake_Rule", hit.Match.Rule);

        // Exactly two processes, and which two: the recursive pass over the root — the direct evidence that the
        // guard under test was reached at all — and one scan of a safely named copy of the deferred file.
        Assert.Equal(2, fake.Invocations.Count);
        Assert.Single(fake.Invocations, i => i.Contains($"target={tree.Root}|", StringComparison.Ordinal));
        Assert.Single(fake.Invocations, i => i.Contains("silvergun-yara-safe-", StringComparison.Ordinal));
    }

    // Side two, over the SAME tree and the same staged echo, plus one target that belongs to no file the scan
    // enumerated. Narrowing decision 17 to the deferred set must not switch it off: a hit that was seen and can
    // be credited to nothing is still missing coverage, even while a recovery is succeeding beside it. Exactly
    // one target is counted, which is the assertion that separates "the deferred echo was excluded" from "the
    // guard fired on both".
    [LinuxFact]
    public void ScanDirectory_WhenTheSameTreeAlsoEchoesAGhostUnderTheRoot_StillFailsClosed()
    {
        using var tree = new TempTree();
        tree.Write("content/benign.bin", "no signature here\n");
        var payload = tree.Write("content/pay\tload.bin", "ordinary content\n");
        var ghost = Path.Combine(tree.Root, "content", "ghost.bin");   // deliberately never created
        using var fake = new FakeYaraBinary(
            batchStdOut: $"Fake_Rule {payload}\\nFake_Rule {ghost}", echoRule: "Fake_Rule");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => new YaraCliScanner().ScanDirectory(tree.Root));

        Assert.Contains("matched 1 target(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("ghost.bin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(@"pay\tload.bin", ex.Message, StringComparison.Ordinal);
    }

    // --- IsUnderRoot: '/' separates, and on Linux a backslash does not ----------------------------------------

    // `IsUnderRoot` is a local function inside ScanBatch, so its separator rule is only reachable through a real
    // ScanDirectory. On Linux a backslash is an ordinary filename character, so `<root>\evil` is a SIBLING of the
    // scanned root, not a child of it — someone else's file, not this package's missing coverage. Accepting it
    // would let any tree that happens to have such a neighbour, or any engine line that names one, turn a healthy
    // scan into Unavailable.
    [LinuxFact]
    public void ScanDirectory_WhenAGhostTargetIsASiblingSeparatedByABackslash_IsNotCountedAsLost()
    {
        using var tree = new TempTree();
        tree.Write("content/benign.bin", "no signature here\n");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {tree.Root}\\evil");

        Assert.Empty(new YaraCliScanner().ScanDirectory(tree.Root));
    }

    // The control for the test above: the same ghost name, the same length of prefix, separated by '/' instead —
    // now genuinely under the root, and therefore a hit that was seen and lost. The two differ in one byte, which
    // is what makes the separator check itself the thing under test rather than the shape of the name. Only its
    // partner moves when the separator rule is widened to accept '\\'; this one is deliberately insensitive to
    // that, which is what a control is for.
    [LinuxFact]
    public void ScanDirectory_WhenTheSameGhostTargetIsSeparatedBySlash_FailsClosed()
    {
        using var tree = new TempTree();
        tree.Write("content/benign.bin", "no signature here\n");
        using var fake = new FakeYaraBinary(batchStdOut: $"Fake_Rule {tree.Root}/evil");

        var ex = Assert.Throws<YaraScanIncompleteException>(() => new YaraCliScanner().ScanDirectory(tree.Root));

        Assert.Contains("matched 1 target(s)", ex.Message, StringComparison.Ordinal);
        Assert.Contains("evil", ex.Message, StringComparison.Ordinal);
    }
    #endregion
}
