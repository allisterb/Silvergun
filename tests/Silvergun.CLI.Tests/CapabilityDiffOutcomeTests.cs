namespace Silvergun.CLI.Tests;

using System;
using System.Linq;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/capability-diff-versions.md</c> Area D: <see cref="CapabilityDiffOutcome.SideCompleteness"/> —
/// the "trap 1" gate input. A side (baseline or candidate array) is incomplete when ANY element says so, its
/// caveat text states only the facts the <see cref="ScanCompleteness"/> counters carry, and multiple incomplete
/// elements' caveats are ordinal-sorted by assembly name for determinism.
/// </summary>
public sealed class CapabilityDiffOutcomeTests
{
    #region Methods
    [Fact]
    public void SideCompleteness_AllElementsComplete_ReturnsCompleteWithNoCaveats()
    {
        var side = new[] { Snapshot("A.dll", Complete()), Snapshot("B.dll", Complete()) };

        var (isComplete, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.True(isComplete);
        Assert.Empty(caveats);
    }

    // ANY one incomplete element makes the WHOLE side untrustworthy — this is the exact statement trap 1 depends
    // on: a clean-looking side with one bad apple must not read as complete.
    [Fact]
    public void SideCompleteness_OneOfManyElementsIncomplete_MakesTheWholeSideIncomplete()
    {
        var side = new[]
        {
            Snapshot("A.dll", Complete()),
            Snapshot("B.dll", new ScanCompleteness(IsComplete: false, MethodsTotal: 10, MethodsAnalyzed: 8, MethodsSkipped: 2, AssemblyLoadFailures: 0)),
            Snapshot("C.dll", Complete()),
        };

        var (isComplete, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.False(isComplete);
        Assert.Single(caveats);
        Assert.Contains("B.dll", caveats[0]);
    }

    [Fact]
    public void SideCompleteness_CaveatText_NamesMethodsSkippedCount()
    {
        var side = new[] { Snapshot("A.dll", new ScanCompleteness(false, MethodsTotal: 10, MethodsAnalyzed: 7, MethodsSkipped: 3, AssemblyLoadFailures: 0)) };

        var (_, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.Equal("A.dll: 3 of 10 method(s) could not be analyzed", Assert.Single(caveats));
    }

    [Theory]
    [InlineData(1, "1 assembly failed to load")]
    [InlineData(2, "2 assemblies failed to load")]
    public void SideCompleteness_CaveatText_PluralizesAssemblyLoadFailuresCorrectly(int failures, string expectedTail)
    {
        var side = new[] { Snapshot("A.dll", new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 5, MethodsSkipped: 0, AssemblyLoadFailures: failures)) };

        var (_, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.Equal($"A.dll: {expectedTail}", Assert.Single(caveats));
    }

    [Fact]
    public void SideCompleteness_CaveatText_CombinesSkippedMethodsAndLoadFailuresWhenBothNonZero()
    {
        var side = new[] { Snapshot("A.dll", new ScanCompleteness(false, MethodsTotal: 10, MethodsAnalyzed: 8, MethodsSkipped: 2, AssemblyLoadFailures: 1)) };

        var (_, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.Equal("A.dll: 2 of 10 method(s) could not be analyzed; 1 assembly failed to load", Assert.Single(caveats));
    }

    // IsComplete=false but neither explaining counter is set (e.g. a hand-edited snapshot file) must still
    // produce SOME caveat text, never a blank/empty one.
    [Fact]
    public void SideCompleteness_IncompleteWithNoExplainingCounters_FallsBackToGenericCaveat()
    {
        var side = new[] { Snapshot("A.dll", new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 5, MethodsSkipped: 0, AssemblyLoadFailures: 0)) };

        var (_, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.Equal("A.dll: the scan was marked incomplete", Assert.Single(caveats));
    }

    [Fact]
    public void SideCompleteness_MultipleIncompleteElements_CaveatsAreOrdinalSortedByAssemblyName()
    {
        var incomplete = new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 4, MethodsSkipped: 1, AssemblyLoadFailures: 0);
        var side = new[]
        {
            Snapshot("Zebra.dll", incomplete),
            Snapshot("Apple.dll", incomplete),
            Snapshot("Mango.dll", incomplete),
            Snapshot("Complete.dll", Complete()),
        };

        var (isComplete, caveats) = CapabilityDiffOutcome.SideCompleteness(side);

        Assert.False(isComplete);
        Assert.Equal(
            ["Apple.dll: 1 of 5 method(s) could not be analyzed",
             "Mango.dll: 1 of 5 method(s) could not be analyzed",
             "Zebra.dll: 1 of 5 method(s) could not be analyzed"],
            caveats);
    }

    [Fact]
    public void SideCompleteness_EmptyArray_ReturnsCompleteWithNoCaveats()
    {
        // Not itself the "empty array" refusal (that lives in Program.RunCapabilityDiff, checked earlier) — this
        // just pins that SideCompleteness in isolation over an empty sequence has no incomplete element to find.
        var (isComplete, caveats) = CapabilityDiffOutcome.SideCompleteness([]);

        Assert.True(isComplete);
        Assert.Empty(caveats);
    }

    [Fact]
    public void IsIncomplete_TrueWhenEitherSideIsIncomplete()
    {
        var complete = new CapabilityDiffOutcome(
            MinimalDiff(), BaselineComplete: true, BaselineCaveats: [], CandidateComplete: true, CandidateCaveats: [], VacuousDiffOverridden: false);
        var baselineBad = complete with { BaselineComplete = false };
        var candidateBad = complete with { CandidateComplete = false };

        Assert.False(complete.IsIncomplete);
        Assert.True(baselineBad.IsIncomplete);
        Assert.True(candidateBad.IsIncomplete);
    }
    #endregion

    #region Methods — fixtures
    private static CapabilitySnapshot Snapshot(string assemblyName, ScanCompleteness completeness) =>
        new(
            CapabilitySnapshot.CurrentSchemaVersion, PackageId: null, PackageVersion: null,
            AssemblyName: assemblyName, TargetFramework: "net10.0",
            Manifest: new CapabilityManifest([.. Enum.GetValues<Capability>().Select(c => new CapabilityManifestEntry(c, false, 0))]),
            Completeness: completeness);

    private static ScanCompleteness Complete() => new(true, MethodsTotal: 5, MethodsAnalyzed: 5, MethodsSkipped: 0, AssemblyLoadFailures: 0);

    private static CapabilityDiffReport MinimalDiff() =>
        new([], AssembliesAdded: [], AssembliesRemoved: [], TargetFrameworksAdded: [], TargetFrameworksDropped: [], MatchedPairCount: 1);
    #endregion
}
