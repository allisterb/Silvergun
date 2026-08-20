namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/capability-diff-versions.md</c>, plus its appended "ARCHITECT CORRECTION" section
/// (2026-08-20): <see cref="CapabilityDiffReport.Compare"/> must match elements by the COMPOSITE key
/// (<see cref="CapabilitySnapshot.AssemblyName"/>, <see cref="CapabilitySnapshot.TargetFramework"/>), never by
/// <c>AssemblyName</c> alone — a multi-targeted package's <c>--snapshot</c> file carries one array element per
/// <c>lib/&lt;tfm&gt;</c> folder, all sharing one <c>AssemblyName</c>.
/// <para>
/// Region B covers the composite-key contract, with a dedicated regression (<see cref="Compare_MultiTargetedAssembly_ChangeInOneVariantOnly_IsAttributedToThatVariant_NotCollapsedToTheFirstEncountered"/>)
/// engineered so that a name-only "collapse to first encountered element" implementation gives a WRONG answer —
/// see that test's own comment for exactly how. It also covers the follow-on "CRITICAL (2026-08-20, code review)"
/// null-vs-NUL-sentinel regressions (see the two tests immediately after
/// <see cref="Compare_NullTargetFramework_MatchesNullTargetFramework"/>).
/// </para>
/// Region F covers determinism: enum-declaration order for capabilities, ordinal order for names/TFMs, regardless
/// of input array order.
/// </summary>
public sealed class CapabilityDiffTests
{
    #region Methods — B: the composite-key regression (discriminating against name-only matching)
    // THE regression test. Setup, deliberately adversarial to a name-only match:
    //   - ONE assembly name, THREE target-framework variants (mirrors the verified BouncyCastle.Cryptography
    //     2.5.1 case cited in the architect correction: 3 elements, 1 AssemblyName).
    //   - The two files enumerate those three TFMs in DIFFERENT orders (baseline: net472, net8.0,
    //     netstandard2.0; candidate: netstandard2.0, net472, net8.0) — exactly the "different enumeration
    //     order" hazard the correction calls out.
    //   - The FIRST element of the baseline array (net472) and the FIRST element of the candidate array
    //     (netstandard2.0) both have ProcessExecution ABSENT — they show no change at all if compared to each
    //     other.
    //   - The capability change (ProcessExecution gained) lives ONLY in the net8.0 variant, which is neither
    //     file's first element.
    //
    // A "match by AssemblyName alone, collapse to first encountered" implementation (the bug the architect
    // correction fixed) would group each side down to ONE entry per name: baseline's net472 (no
    // ProcessExecution) vs candidate's netstandard2.0 (no ProcessExecution). Those two show NO capability
    // difference, so the bug's answer is "nothing changed" — a false negative that silently hides a
    // ProcessExecution addition, which is exactly the "security-relevant false negative, not a cosmetic issue"
    // the correction describes. A test that only varied the change's TFM without also reordering the arrays
    // could still pass under a buggy "zip the two lists positionally" variant; reordering closes that gap too.
    //
    // The correct, composite-keyed answer: all three TFMs match structurally regardless of array order
    // (MatchedPairCount == 3), and the ONE capability delta is attributed to exactly the net8.0 pair.
    [Fact]
    public void Compare_MultiTargetedAssembly_ChangeInOneVariantOnly_IsAttributedToThatVariant_NotCollapsedToTheFirstEncountered()
    {
        const string name = "Contoso.Crypto.dll";

        var baseline = new[]
        {
            Snapshot(name, "net472"),
            Snapshot(name, "net8.0"),                                   // no ProcessExecution yet
            Snapshot(name, "netstandard2.0"),
        };
        var candidate = new[]
        {
            Snapshot(name, "netstandard2.0"),                           // reordered relative to baseline
            Snapshot(name, "net472"),
            Snapshot(name, "net8.0", Capability.ProcessExecution),       // ONLY this variant gains a capability
        };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(3, report.MatchedPairCount);           // all three TFMs matched structurally
        Assert.True(report.HasAddedCapabilities);           // the false-negative the bug would produce
        var changed = Assert.Single(report.AssemblyDiffs);  // only ONE (name, TFM) pair actually differs
        Assert.Equal(name, changed.AssemblyName);
        Assert.Equal("net8.0", changed.TargetFramework);    // attributed to the RIGHT variant
        Assert.Equal([Capability.ProcessExecution], changed.Added);
        Assert.Empty(changed.Removed);
        Assert.Empty(changed.CountChanges);

        // No structural change: the assembly and all three TFMs are present on both sides.
        Assert.Empty(report.AssembliesAdded);
        Assert.Empty(report.AssembliesRemoved);
        Assert.Empty(report.TargetFrameworksAdded);
        Assert.Empty(report.TargetFrameworksDropped);
    }

    [Fact]
    public void Compare_NullTargetFramework_MatchesNullTargetFramework()
    {
        // analyze --snapshot always writes TargetFramework: null (accepted-as-is per the task spec) — a
        // null-to-null match must work like any other value, not be treated as "missing".
        var baseline = new[] { Snapshot("Bare.dll", null) };
        var candidate = new[] { Snapshot("Bare.dll", null, Capability.Network) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(1, report.MatchedPairCount);
        var changed = Assert.Single(report.AssemblyDiffs);
        Assert.Null(changed.TargetFramework);
        Assert.Equal([Capability.Network], changed.Added);
    }

    // Regression for the "CRITICAL (2026-08-20, code review)" section of the task spec: the FIRST broken
    // implementation (Dictionary<string?, T>, keyed directly on the nullable TargetFramework) threw
    // ArgumentNullException the instant ByAssemblyNameAndFramework tried to insert a null key — which is exactly
    // the shape every `analyze --snapshot` file has (case A of the regression request: two IDENTICAL null-TFM
    // snapshots for the same assembly, the single most ordinary use of the verb). This pins the precise "diff
    // cleanly, no throw, no changes" shape at the library level, distinct from
    // Compare_NullTargetFramework_MatchesNullTargetFramework above (which deliberately varies a capability to
    // pin attribution, not the "nothing changed" case). The CLI end-to-end equivalent
    // (CapabilityDiffCliTests.CapabilityDiff_TwoIdenticalAnalyzeSnapshots_BothNullTargetFramework_ExitsZero)
    // drives this through a real `analyze --snapshot` round-trip and the exit-code contract; this test isolates
    // the same shape at the Compare seam so a failure here points straight at ByAssemblyNameAndFramework.
    [Fact]
    public void Compare_IdenticalNullTargetFrameworkSnapshots_ReportsNoChanges_NoThrow()
    {
        var baseline = new[] { Snapshot("Bare.dll", null, Capability.FileSystem) };
        var candidate = new[] { Snapshot("Bare.dll", null, Capability.FileSystem) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(1, report.MatchedPairCount);
        Assert.False(report.HasAnyChange);
        Assert.Empty(report.AssemblyDiffs);
        Assert.Empty(report.AssembliesAdded);
        Assert.Empty(report.AssembliesRemoved);
        Assert.Empty(report.TargetFrameworksAdded);
        Assert.Empty(report.TargetFrameworksDropped);
    }

    // Regression for the SECOND broken implementation named in the same "CRITICAL" section: encoding a null
    // TargetFramework in-band as a sentinel string holding a single NUL character (Unicode code point U+0000).
    // That fix collapsed the encoding of null and the encoding of a NUL-character string to the same dictionary
    // key, so a single snapshot ARRAY carrying both a null-TFM entry and a literal-NUL-character-TFM entry for
    // the same AssemblyName collided on one key within ByAssemblyNameAndFramework's per-side GroupBy: either an
    // unhandled ArgumentException on a duplicate insert, or a silent collapse to whichever element the grouping
    // happened to keep — in both cases losing one of the two entries. It ALSO throws under the first broken
    // implementation (Dictionary&lt;string?, T&gt;), since the null-TFM element alone is enough to hit the
    // null-key throw before either entry is even compared.
    // <para>
    // The correct (current) behaviour, per the ValueTuple-keyed fix: null and the NUL-character string are
    // FULLY distinct TargetFramework values, so both the (name, null) pair and the (name, NUL-character) pair
    // match independently on both sides — MatchedPairCount == 2, not 1 (collapsed) and not a throw — and a
    // capability change made on ONLY the null-TFM entry is attributed to that entry alone, with the
    // NUL-character-TFM entry reporting no change at all (excluded from AssemblyDiffs, which only carries pairs
    // WITH a change).
    // </para>
    [Fact]
    public void Compare_NullAndLiteralNulCharacterTfmForSameAssembly_OnBothSides_MatchIndependently_NoThrow_NoLostEntry()
    {
        const string name = "Contoso.Mixed.dll";
        // Built at runtime from a character code point — never typed as an escape sequence in this source file.
        // (The Write/Edit tooling was observed silently corrupting a 4-hex-digit unicode escape sequence typed
        // directly into file content into a raw control byte; see the test-engineer report for how this was
        // found and worked around.) The assertions immediately below verify this really is a single NUL
        // character, not an empty string or a space.
        var nulTfm = new string((char)0, 1);
        Assert.Equal(1, nulTfm.Length);
        Assert.Equal('\0', nulTfm[0]);
        Assert.Equal(0, nulTfm[0]);
        Assert.NotEqual(string.Empty, nulTfm);
        Assert.NotEqual(" ", nulTfm);

        var baseline = new[]
        {
            Snapshot(name, null),          // null-TFM entry
            Snapshot(name, nulTfm),        // literal-NUL-TFM entry — must stay distinct from the one above
        };
        var candidate = new[]
        {
            Snapshot(name, null, Capability.ProcessExecution),   // the ONLY change, on the null-TFM entry
            Snapshot(name, nulTfm),                              // unchanged
        };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(2, report.MatchedPairCount);            // both pairs matched independently — neither lost
        var changed = Assert.Single(report.AssemblyDiffs);   // only the null-TFM pair has anything to report
        Assert.Null(changed.TargetFramework);
        Assert.Equal([Capability.ProcessExecution], changed.Added);
        Assert.Empty(changed.Removed);
        Assert.Empty(changed.CountChanges);

        // No structural fallout: both TFM identities were present on both sides, so nothing reads as
        // added/dropped/collapsed.
        Assert.Empty(report.AssembliesAdded);
        Assert.Empty(report.AssembliesRemoved);
        Assert.Empty(report.TargetFrameworksAdded);
        Assert.Empty(report.TargetFrameworksDropped);
    }

    [Fact]
    public void Compare_TfmPresentOnlyOnCandidate_IsTargetFrameworkAdded_NotAssemblyAdded()
    {
        const string name = "Contoso.Widgets.dll";
        var baseline = new[] { Snapshot(name, "netstandard2.0") };
        var candidate = new[] { Snapshot(name, "netstandard2.0"), Snapshot(name, "net10.0") };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Empty(report.AssembliesAdded);          // NOT an added assembly ...
        Assert.Empty(report.AssembliesRemoved);
        Assert.Equal(["Contoso.Widgets.dll (net10.0)"], report.TargetFrameworksAdded);  // ... a target-framework addition
        Assert.Empty(report.TargetFrameworksDropped);
        Assert.Equal(1, report.MatchedPairCount);       // the shared netstandard2.0 pair still matched
    }

    [Fact]
    public void Compare_TfmPresentOnlyOnBaseline_IsTargetFrameworkDropped_NotAssemblyRemoved()
    {
        const string name = "Contoso.Widgets.dll";
        var baseline = new[] { Snapshot(name, "netstandard2.0"), Snapshot(name, "net472") };
        var candidate = new[] { Snapshot(name, "netstandard2.0") };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Empty(report.AssembliesAdded);
        Assert.Empty(report.AssembliesRemoved);
        Assert.Empty(report.TargetFrameworksAdded);
        Assert.Equal(["Contoso.Widgets.dll (net472)"], report.TargetFrameworksDropped);
        Assert.Equal(1, report.MatchedPairCount);
    }

    [Fact]
    public void Compare_AssemblyNameAbsentFromCandidate_IsAssemblyRemoved_NotTargetFrameworkDropped()
    {
        var baseline = new[] { Snapshot("Gone.dll", "net10.0"), Snapshot("Stays.dll", "net10.0") };
        var candidate = new[] { Snapshot("Stays.dll", "net10.0") };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(["Gone.dll"], report.AssembliesRemoved);
        Assert.Empty(report.AssembliesAdded);
        Assert.Empty(report.TargetFrameworksDropped);   // the whole assembly is gone, not just one TFM of it
        Assert.Empty(report.TargetFrameworksAdded);
    }

    [Fact]
    public void Compare_AssemblyNameAbsentFromBaseline_IsAssemblyAdded_NotTargetFrameworkAdded()
    {
        var baseline = new[] { Snapshot("Stays.dll", "net10.0") };
        var candidate = new[] { Snapshot("Stays.dll", "net10.0"), Snapshot("New.dll", "net10.0") };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(["New.dll"], report.AssembliesAdded);
        Assert.Empty(report.AssembliesRemoved);
        Assert.Empty(report.TargetFrameworksAdded);
        Assert.Empty(report.TargetFrameworksDropped);
    }

    [Fact]
    public void Compare_DisjointTargetFrameworksForSharedName_ReturnsZeroMatchedPairCount()
    {
        // The repurposed trap 2: same assembly name, but the TFM sets don't overlap at all — the vacuous-diff
        // shape the CLI verb must refuse on (MatchedPairCount == 0), even though the name matched.
        var baseline = new[] { Snapshot("Contoso.Crypto.dll", "netstandard2.0") };
        var candidate = new[] { Snapshot("Contoso.Crypto.dll", "net8.0") };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(0, report.MatchedPairCount);
        Assert.Empty(report.AssemblyDiffs);
        Assert.Equal(["Contoso.Crypto.dll (net8.0)"], report.TargetFrameworksAdded);
        Assert.Equal(["Contoso.Crypto.dll (netstandard2.0)"], report.TargetFrameworksDropped);
    }

    [Fact]
    public void Compare_NullTfmOnlyOnCandidate_FormatsTargetFrameworkEntryAsUnknown()
    {
        const string name = "Bare.dll";
        var baseline = new[] { Snapshot(name, "net10.0") };
        var candidate = new[] { Snapshot(name, "net10.0"), Snapshot(name, null) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.Equal(["Bare.dll (unknown)"], report.TargetFrameworksAdded);
    }
    #endregion

    #region Methods — general correctness
    [Fact]
    public void Compare_IdenticalSnapshots_ReportsNoChanges()
    {
        var baseline = new[] { Snapshot("A.dll", "net10.0", Capability.FileSystem) };
        var candidate = new[] { Snapshot("A.dll", "net10.0", Capability.FileSystem) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        Assert.False(report.HasAnyChange);
        Assert.Empty(report.AssemblyDiffs);
        Assert.Equal(1, report.MatchedPairCount);
    }

    [Fact]
    public void Compare_CapabilityGainedInCandidate_ReportsAdded()
    {
        var baseline = new[] { Snapshot("A.dll", "net10.0") };
        var candidate = new[] { Snapshot("A.dll", "net10.0", Capability.Registry) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        var diff = Assert.Single(report.AssemblyDiffs);
        Assert.Equal([Capability.Registry], diff.Added);
        Assert.Empty(diff.Removed);
        Assert.True(report.HasAddedCapabilities);
    }

    [Fact]
    public void Compare_CapabilityLostInCandidate_ReportsRemoved()
    {
        var baseline = new[] { Snapshot("A.dll", "net10.0", Capability.Registry) };
        var candidate = new[] { Snapshot("A.dll", "net10.0") };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        var diff = Assert.Single(report.AssemblyDiffs);
        Assert.Equal([Capability.Registry], diff.Removed);
        Assert.Empty(diff.Added);
        Assert.False(report.HasAddedCapabilities);   // a removal never trips the added-capability gate
    }

    [Fact]
    public void Compare_CallSiteCountChangedButPresentOnBothSides_ReportsCountChange_NotAddedOrRemoved()
    {
        var baseline = new[] { SnapshotWithCount("A.dll", "net10.0", Capability.Network, 3) };
        var candidate = new[] { SnapshotWithCount("A.dll", "net10.0", Capability.Network, 40) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        var diff = Assert.Single(report.AssemblyDiffs);
        Assert.Empty(diff.Added);
        Assert.Empty(diff.Removed);
        var change = Assert.Single(diff.CountChanges);
        Assert.Equal(Capability.Network, change.Capability);
        Assert.Equal(3, change.BaselineCount);
        Assert.Equal(40, change.CandidateCount);
        Assert.False(report.HasAddedCapabilities);   // a count change is not an "added" capability
    }
    #endregion

    #region Methods — F: determinism
    [Fact]
    public void Compare_AddedAndRemovedCapabilities_AreListedInEnumDeclarationOrder_NotInsertionOrder()
    {
        // Added out of enum-declaration order on purpose (RuntimeControl declared last, FileSystem first).
        var baseline = new[] { Snapshot("A.dll", "net10.0", Capability.Cryptography) };
        var candidate = new[] { Snapshot("A.dll", "net10.0", Capability.RuntimeControl, Capability.FileSystem) };

        var report = CapabilityDiffReport.Compare(baseline, candidate);

        var diff = Assert.Single(report.AssemblyDiffs);
        Assert.Equal([Capability.FileSystem, Capability.RuntimeControl], diff.Added);   // FileSystem before RuntimeControl
        Assert.Equal([Capability.Cryptography], diff.Removed);
    }

    [Fact]
    public void Compare_OutputOrdering_IsStableRegardlessOfInputElementOrder()
    {
        // Three assembly names deliberately out of ordinal order, each multi-targeted, with a mix of added/
        // removed/count-change/structural deltas, so every ordered output list has something to sort.
        var baselineCanonical = new[]
        {
            Snapshot("Mu.dll", "net10.0", Capability.FileSystem),
            Snapshot("Mu.dll", "netstandard2.0"),
            SnapshotWithCount("Alpha.dll", "net10.0", Capability.Network, 2),
            Snapshot("Zeta.dll", "net10.0"),
            Snapshot("OnlyBaseline.dll", "net10.0"),
        };
        var candidateCanonical = new[]
        {
            Snapshot("Mu.dll", "net10.0"),                                          // FileSystem removed
            Snapshot("Mu.dll", "netstandard2.0", Capability.Registry),              // Registry added
            SnapshotWithCount("Alpha.dll", "net10.0", Capability.Network, 9),        // count change
            Snapshot("Zeta.dll", "net10.0"), Snapshot("Zeta.dll", "net8.0"),         // TFM added
            Snapshot("OnlyCandidate.dll", "net10.0"),
        };

        var canonical = CapabilityDiffReport.Compare(baselineCanonical, candidateCanonical);

        // Reversed order, and a shuffled order, over the SAME logical elements.
        var reversed = CapabilityDiffReport.Compare(
            [.. baselineCanonical.Reverse()], [.. candidateCanonical.Reverse()]);
        var shuffled = CapabilityDiffReport.Compare(
            Permute(baselineCanonical), Permute(candidateCanonical));

        foreach (var alternate in new[] { reversed, shuffled })
        {
            Assert.Equal(Describe(canonical.AssemblyDiffs), Describe(alternate.AssemblyDiffs));
            Assert.Equal(canonical.AssembliesAdded, alternate.AssembliesAdded);
            Assert.Equal(canonical.AssembliesRemoved, alternate.AssembliesRemoved);
            Assert.Equal(canonical.TargetFrameworksAdded, alternate.TargetFrameworksAdded);
            Assert.Equal(canonical.TargetFrameworksDropped, alternate.TargetFrameworksDropped);
            Assert.Equal(canonical.MatchedPairCount, alternate.MatchedPairCount);
        }

        // And pin the actual expected order explicitly, not just "the same as some other run": ordinal by name
        // ("Alpha" < "Mu" < "OnlyBaseline"/"OnlyCandidate" < "Zeta").
        Assert.Equal(["Alpha.dll|net10.0", "Mu.dll|net10.0", "Mu.dll|netstandard2.0"], Describe(canonical.AssemblyDiffs).Select(d => d.Split('|')[0] + "|" + d.Split('|')[1]).ToArray());
        Assert.Equal(["OnlyCandidate.dll"], canonical.AssembliesAdded);
        Assert.Equal(["OnlyBaseline.dll"], canonical.AssembliesRemoved);
        Assert.Equal(["Zeta.dll (net8.0)"], canonical.TargetFrameworksAdded);
        Assert.Empty(canonical.TargetFrameworksDropped);
    }

    // A deterministic "shuffle" that is NOT simply reverse or sorted: reverses pairs of adjacent elements plus
    // wraps the last element to the front, so the element order genuinely differs from both the canonical and
    // the plain-reversed arrangement used alongside it in the same test.
    private static CapabilitySnapshot[] Permute(CapabilitySnapshot[] source)
    {
        var result = new System.Collections.Generic.List<CapabilitySnapshot>(source.Length);
        for (var i = 0; i + 1 < source.Length; i += 2)
        {
            result.Add(source[i + 1]);
            result.Add(source[i]);
        }
        if (source.Length % 2 == 1)
            result.Add(source[^1]);
        if (result.Count > 1)
        {
            var first = result[0];
            result.RemoveAt(0);
            result.Add(first);
        }
        return [.. result];
    }

    // One line per (name, TFM) diff, in the exact order Compare returned them, naming every added/removed/
    // count-changed capability so ordering WITHIN a diff (enum-declaration order) is pinned too, not just the
    // ordering OF diffs.
    private static string[] Describe(System.Collections.Generic.IReadOnlyList<AssemblyCapabilityDiff> diffs) =>
        [.. diffs.Select(d =>
            $"{d.AssemblyName}|{d.TargetFramework}|+{string.Join(",", d.Added)}|-{string.Join(",", d.Removed)}"
            + $"|~{string.Join(",", d.CountChanges.Select(c => $"{c.Capability}:{c.BaselineCount}->{c.CandidateCount}"))}")];
    #endregion

    #region Methods — fixtures
    private static CapabilitySnapshot Snapshot(string assemblyName, string? targetFramework, params Capability[] present) =>
        SnapshotWithCounts(assemblyName, targetFramework, present.Select(c => (c, 1)).ToArray());

    private static CapabilitySnapshot SnapshotWithCount(string assemblyName, string? targetFramework, Capability capability, int count) =>
        SnapshotWithCounts(assemblyName, targetFramework, [(capability, count)]);

    private static CapabilitySnapshot SnapshotWithCounts(
        string assemblyName, string? targetFramework, (Capability Capability, int Count)[] presentCounts)
    {
        var counts = presentCounts.ToDictionary(p => p.Capability, p => p.Count);
        var entries = Enum.GetValues<Capability>()
            .Select(c => new CapabilityManifestEntry(c, counts.TryGetValue(c, out var n) && n > 0, counts.GetValueOrDefault(c)))
            .ToArray();

        return new CapabilitySnapshot(
            CapabilitySnapshot.CurrentSchemaVersion,
            PackageId: "Contoso.Package",
            PackageVersion: "1.0.0",
            AssemblyName: assemblyName,
            TargetFramework: targetFramework,
            Manifest: new CapabilityManifest(entries),
            Completeness: new ScanCompleteness(IsComplete: true, MethodsTotal: 10, MethodsAnalyzed: 10, MethodsSkipped: 0, AssemblyLoadFailures: 0));
    }
    #endregion
}
