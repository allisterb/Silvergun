namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests;
using Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using Xunit;

/// <summary>
/// The reachability R2 instrument (<c>docs/agent/tasks/reachability-r2.md</c>, "The instrument"): the benign-corpus
/// harness's <c>--reachability</c> mode. The aggregation and the pre-registered E1/E2 decision are pure functions over
/// child results, so they are pinned here on synthetic results; the offline driver runs over a fake cache with a fake
/// child; the child's status rule, folder rules and parity copy are pinned directly; and one test measures a synthetic
/// package in-process, end to end, over our own ShadowFixture (read as metadata, never loaded).
/// </summary>
public sealed class ReachabilityHarnessTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Populations, shares and denominators
    // ---------------------------------------------------------------------------------------------------

    // P-lib reads only the lib/<tfm> folder; P-all every loaded folder. A build-only package is in P-all alone. A crashed
    // package with a lib TFM is an unmeasured floor package in both denominators (R2 "Known instrument limitation", fixed;
    // this test used to pin it out of both), and its folders, if any, are not read.
    [Fact]
    public void View_PlibAndPall_HaveTheirOwnDenominators()
    {
        var results = new[]
        {
            Package("A", Lib(presence: [(Capability.Network, 1)])),
            Package("B", Lib(), Folder("build", "build", presence: [(Capability.Network, 2)])),
            Package("C", Folder("build", "build")),
            Package("D", Lib(presence: [(Capability.Network, 1)])) with { Status = PackageReachResult.Crashed },
        };

        var plib = ReachabilityAggregation.View(results, Population.Plib);
        var pall = ReachabilityAggregation.View(results, Population.Pall);

        Assert.Equal(["A", "B", "D"], plib.Units.Select(u => u.Id));
        Assert.Equal(["A", "B", "C", "D"], pall.Units.Select(u => u.Id));
        Assert.Equal(new Share(1, 3), ReachabilityAggregation.Presence(plib, Capability.Network));
        Assert.Equal(new Share(2, 4), ReachabilityAggregation.Presence(pall, Capability.Network));
    }

    // Only a folder neither side read is left out (no graph, and no presence scan that read an assembly). A package whose
    // only scoped folder is graph-failed - presence read it, the graph did not - stays in the denominator as a floor
    // package (review round 2, C1-r2); a package with only unread folders is in no population.
    [Fact]
    public void View_KeepsGraphFailedFoldersAsFloors_AndExcludesOnlyFoldersNeitherSideRead()
    {
        var graphFailed = Lib() with { GraphBuilt = false, Assemblies = [] };
        var unread = graphFailed with { Presence = [new AssemblyPresence("lib/net8.0/a.dll", false, "load failed", 0, 0, [])] };
        var results = new[] { Package("A", graphFailed), Package("B", unread, Folder("tools/net8.0", "tools")), Package("C", unread) };

        var plib = ReachabilityAggregation.View(results, Population.Plib);
        var pall = ReachabilityAggregation.View(results, Population.Pall);

        Assert.Equal(["A"], plib.Units.Select(u => u.Id));
        Assert.True(plib.Units.Single().Floor);
        Assert.Equal(["A", "B"], pall.Units.Select(u => u.Id));
        Assert.Equal(["tools/net8.0"], pall.Units[1].Folders.Select(f => f.Folder));
        Assert.False(pall.Units[1].Floor);
    }

    // In P-all a package counts for (class, capability) when any folder does, once, however many folders do.
    [Fact]
    public void Reach_InPall_CountsAPackageOnceWhenAnyFolderReaches()
    {
        var results = new[]
        {
            Package("A", Lib(reaches: [Reach(RootClass.HostContract, Capability.FileSystem, 2)]),
                Folder("build", "build", reaches: [Reach(RootClass.HostContract, Capability.FileSystem, 5)])),
            Package("B", Lib(), Folder("build", "build", reaches: [Reach(RootClass.HostContract, Capability.FileSystem, 1)])),
            Package("C", Lib()),
        };

        Assert.Equal(new Share(2, 3), ReachabilityAggregation.Reach(ReachabilityAggregation.View(results, Population.Pall), RootClass.HostContract, Capability.FileSystem));
        Assert.Equal(new Share(1, 3), ReachabilityAggregation.Reach(ReachabilityAggregation.View(results, Population.Plib), RootClass.HostContract, Capability.FileSystem));
    }

    // The Bound tier counts Bound > 0, ChaOnly counts Roots > 0; a null capability is the Unseen sink.
    [Fact]
    public void Reach_ByTier_AndTheUnseenSink()
    {
        var results = new[]
        {
            Package("A", Lib(reaches: [Reach(RootClass.LoadTime, Capability.Network, 3, bound: 1), Reach(RootClass.LoadTime, null, 1)])),
            Package("B", Lib(reaches: [Reach(RootClass.LoadTime, Capability.Network, 3, bound: 0)])),
        };
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        Assert.Equal(new Share(2, 2), ReachabilityAggregation.Reach(plib, RootClass.LoadTime, Capability.Network));
        Assert.Equal(new Share(1, 2), ReachabilityAggregation.Reach(plib, RootClass.LoadTime, Capability.Network, Tier.Bound));
        Assert.Equal(new Share(1, 2), ReachabilityAggregation.Reach(plib, RootClass.LoadTime, null));
    }

    // Every P-all share by role: the role's folders only, over the packages that have one.
    [Fact]
    public void View_ByRole_UsesTheRolesFoldersAndDenominator()
    {
        var results = new[]
        {
            Package("A", Lib(presence: [(Capability.Registry, 1)]), Folder("build", "build", reaches: [Reach(RootClass.HostContract, Capability.Registry, 1)])),
            Package("B", Lib(reaches: [Reach(RootClass.HostContract, Capability.Registry, 1)])),
            Package("C", Folder("build", "build")),
            Package("D", Folder("analyzers/dotnet/cs", "analyzers")),
        };

        var build = ReachabilityAggregation.View(results, Population.Pall, "build");

        Assert.Equal(["analyzers", "build", "lib"], ReachabilityAggregation.Roles(results));
        Assert.Equal(["A", "C"], build.Units.Select(u => u.Id));
        Assert.Equal(new Share(1, 2), ReachabilityAggregation.Reach(build, RootClass.HostContract, Capability.Registry));
        Assert.Equal(new Share(0, 2), ReachabilityAggregation.Presence(build, Capability.Registry));
        Assert.Equal("P-all, role build", build.Name);
    }

    // ---------------------------------------------------------------------------------------------------
    // E1
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void E1_WhenEveryJudgedReachIsAtMostHalfOfPresence_Passes()
    {
        var plib = Corpus(10, network: 6, reachNetwork: 2);

        var e1 = ReachabilityAggregation.E1(plib, RootClass.LoadTime);

        Assert.Equal(Outcome.Pass, e1.Outcome);
        var cell = e1.Cells.Single(c => c.Capability == Capability.Network);
        Assert.True(cell.Judged);
        Assert.Equal(new Share(6, 10), cell.Presence);
        Assert.Equal(new Share(2, 10), cell.Reach);
    }

    [Fact]
    public void E1_WhenOneJudgedReachExceedsHalfOfPresence_Fails()
    {
        var plib = Corpus(10, network: 6, reachNetwork: 4);

        Assert.Equal(Outcome.Fail, ReachabilityAggregation.E1(plib, RootClass.LoadTime).Outcome);
    }

    // The boundary is inclusive: exactly 0.5 x presence passes, one package more fails.
    [Theory]
    [InlineData(4, 2, Outcome.Pass)]
    [InlineData(4, 3, Outcome.Fail)]
    [InlineData(5, 2, Outcome.Pass)]
    [InlineData(5, 3, Outcome.Fail)]
    public void E1_AtExactlyHalfOfPresence_Passes(int presence, int reach, Outcome expected)
    {
        var plib = Corpus(10, network: presence, reachNetwork: reach);

        Assert.Equal(expected, ReachabilityAggregation.E1(plib, RootClass.LoadTime).Outcome);
    }

    // Presence in fewer than 3 packages: reported, "too rare to judge", and no fail however high its reach.
    [Fact]
    public void E1_ACapabilityPresentInFewerThanThreePackages_IsNotJudged()
    {
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : i < 8 ? [(Capability.Registry, 1)] : [],
            reaches: i < 2 ? [Reach(RootClass.LoadTime, Capability.Registry, 1)] : []))).ToArray();
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        var e1 = ReachabilityAggregation.E1(plib, RootClass.LoadTime);

        var registry = e1.Cells.Single(c => c.Capability == Capability.Registry);
        Assert.False(registry.Judged);
        Assert.Equal(Outcome.Fail, registry.Outcome);
        Assert.Equal(Outcome.Pass, e1.Outcome);
        Assert.True(e1.Cells.Single(c => c.Capability == Capability.Network).Judged);
    }

    // Exactly 3 packages is judged.
    [Fact]
    public void Judged_AtThreePackages()
    {
        Assert.False(ReachabilityAggregation.Judged(new Share(2, 78)));
        Assert.True(ReachabilityAggregation.Judged(new Share(3, 78)));
    }

    // No signal capability judged at all: not a pass.
    [Fact]
    public void E1_WhenNoSignalCapabilityIsJudged_IsNothingJudged()
    {
        var plib = Corpus(10, network: 2, reachNetwork: 0);

        Assert.Equal(Outcome.NothingJudged, ReachabilityAggregation.E1(plib, RootClass.LoadTime).Outcome);
    }

    // ---------------------------------------------------------------------------------------------------
    // E2
    // ---------------------------------------------------------------------------------------------------

    // 10% exactly passes (1 of 10); one package over (2 of 19, 10.5%) fails.
    [Theory]
    [InlineData(10, 1, Outcome.Pass)]
    [InlineData(20, 2, Outcome.Pass)]
    [InlineData(19, 2, Outcome.Fail)]
    [InlineData(10, 2, Outcome.Fail)]
    public void E2_PassesAtExactlyTenPercent_AndFailsAbove(int packages, int composed, Outcome expected)
    {
        var results = Enumerable.Range(0, packages).Select(i => Package($"P{i}", Lib(
            profiles: i < composed ? [Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])] : []))).ToArray();

        var e2 = ReachabilityAggregation.E2(ReachabilityAggregation.View(results, Population.Plib), RootClass.HostContract);

        Assert.Equal(expected, e2.Outcome);
        Assert.Equal(new Share(composed, packages), e2.Inclusive);
    }

    // Only signal capabilities count toward the two; a profile of one signal and non-signals is not a composition.
    [Fact]
    public void E2_CountsOnlyDistinctSignalCapabilities()
    {
        var results = new[]
        {
            Package("A", Lib(profiles: [Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Cryptography, Capability.EnvironmentProbe])])),
            Package("B", Lib(profiles: [Profile(RootClass.HostContract, [Capability.ProcessExecution, Capability.Registry])])),
            Package("C", Lib(profiles: [Profile(RootClass.LoadTime, [Capability.ProcessExecution, Capability.Registry])])),
        };

        var e2 = ReachabilityAggregation.E2(ReachabilityAggregation.View(results, Population.Plib), RootClass.HostContract);

        Assert.Equal(new Share(1, 3), e2.Inclusive);
    }

    // Unseen-inclusive (the judged count) counts every composed profile; it is also split by whether Unseen is in it.
    [Fact]
    public void E2_UnseenInclusiveAndExclusiveCounts()
    {
        var two = new[] { Capability.FileSystem, Capability.Network };
        var results = new[]
        {
            Package("A", Lib(profiles: [Profile(RootClass.TypeInitializer, two, unseen: true)])),
            Package("B", Lib(profiles: [Profile(RootClass.TypeInitializer, two, unseen: false)])),
            Package("C", Lib(profiles: [Profile(RootClass.TypeInitializer, two, unseen: true), Profile(RootClass.TypeInitializer, two, unseen: false)])),
            Package("D", Lib(profiles: [Profile(RootClass.TypeInitializer, [Capability.FileSystem], unseen: true)])),
        };

        var e2 = ReachabilityAggregation.E2(ReachabilityAggregation.View(results, Population.Plib), RootClass.TypeInitializer);

        Assert.Equal(new Share(3, 4), e2.Inclusive);
        Assert.Equal(new Share(2, 4), e2.Exclusive);
        Assert.Equal(new Share(2, 4), e2.WithUnseen);
    }

    // ---------------------------------------------------------------------------------------------------
    // No data, and the per-class verdict
    // ---------------------------------------------------------------------------------------------------

    // A class with zero roots in a population is "no data" there for E1 and E2: never a pass.
    [Fact]
    public void E1AndE2_WithZeroRootsOfTheClass_AreNoData()
    {
        var noLoadTime = Roots(loadTime: 0);
        var results = Enumerable.Range(0, 5).Select(i => Package($"P{i}", Lib(presence: [(Capability.Network, 1)], roots: noLoadTime))).ToArray();
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        Assert.Equal(Outcome.NoData, ReachabilityAggregation.E1(plib, RootClass.LoadTime).Outcome);
        Assert.Equal(Outcome.NoData, ReachabilityAggregation.E2(plib, RootClass.LoadTime).Outcome);
        var verdict = ReachabilityAggregation.Verdicts(plib, plib).Single(v => v.Class == RootClass.LoadTime);
        Assert.Equal(ClassVerdict.Undecided, verdict.Verdict);
    }

    [Theory]
    [InlineData(Outcome.Pass, Outcome.Pass, Outcome.Pass, Outcome.Pass, ClassVerdict.Discriminates)]
    [InlineData(Outcome.Pass, Outcome.Pass, Outcome.Fail, Outcome.Pass, ClassVerdict.DoesNotDiscriminate)]
    [InlineData(Outcome.Pass, Outcome.Fail, Outcome.Pass, Outcome.Pass, ClassVerdict.DoesNotDiscriminate)]
    [InlineData(Outcome.NoData, Outcome.NoData, Outcome.Fail, Outcome.Pass, ClassVerdict.DoesNotDiscriminate)]
    [InlineData(Outcome.NoData, Outcome.NoData, Outcome.Pass, Outcome.Pass, ClassVerdict.Undecided)]
    [InlineData(Outcome.NothingJudged, Outcome.Pass, Outcome.Pass, Outcome.Pass, ClassVerdict.Undecided)]
    [InlineData(Outcome.Pass, Outcome.Floor, Outcome.Pass, Outcome.Pass, ClassVerdict.UndecidedFloor)]
    [InlineData(Outcome.Floor, Outcome.NoData, Outcome.Pass, Outcome.Pass, ClassVerdict.UndecidedFloor)]
    [InlineData(Outcome.Floor, Outcome.Pass, Outcome.Fail, Outcome.Pass, ClassVerdict.DoesNotDiscriminate)]
    public void ClassVerdict_FollowsTheOutcomeRule(Outcome plibE1, Outcome plibE2, Outcome pallE1, Outcome pallE2, string expected)
    {
        Assert.Equal(expected, new ClassVerdict(RootClass.HostContract, plibE1, plibE2, pallE1, pallE2).Verdict);
    }

    // ---------------------------------------------------------------------------------------------------
    // Q2-Q4
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void RootShares_AreMedianAndNearestRankP90OfPerPackageShares()
    {
        var results = Enumerable.Range(1, 10).Select(i => Package($"P{i}", Lib(ownMethods: 10, roots: Roots(publicContract: i)))).ToArray();

        var stats = ReachabilityAggregation.RootShares(ReachabilityAggregation.View(results, Population.Plib), RootClass.PublicContract);

        Assert.Equal(10, stats.Packages);
        Assert.Equal(0.55, stats.Median, 6);
        Assert.Equal(0.9, stats.P90, 6);
    }

    [Fact]
    public void Tiers_SplitReachedPairsByTheStrongestTier()
    {
        var results = new[]
        {
            Package("A", Lib(reaches: [Reach(RootClass.PublicApi, Capability.FileSystem, 2, bound: 1, instantiated: 2), Reach(RootClass.PublicApi, Capability.Network, 2, bound: 0, instantiated: 1)])),
            Package("B", Lib(reaches: [Reach(RootClass.PublicApi, Capability.FileSystem, 2, bound: 0, instantiated: 0), Reach(RootClass.PublicApi, null, 9)])),
        };

        var split = ReachabilityAggregation.Tiers(ReachabilityAggregation.View(results, Population.Plib), RootClass.PublicApi);

        Assert.Equal(new TierSplit(RootClass.PublicApi, 3, 1, 1, 1), split);
    }

    // The gap reasons as the facts write them (RootGap.Reason never holds the assembly name, which is its own field).
    [Theory]
    [InlineData("<Module>..cctor runs at load and is invisible to the model", "module-initializer")]
    [InlineData("module metadata unreadable: whether a module initializer runs at load is unknown", "module-metadata-unreadable")]
    [InlineData("visibility unknown for 3 method(s); counted as PublicApi", "visibility-unknown")]
    [InlineData("root facts unreadable for 1 method(s); counted as PublicApi", "root-facts-unreadable")]
    [InlineData("root facts could not be collected: boom", "root-facts-failed")]
    [InlineData("dispatch work budget reached while finding PublicContract targets", "dispatch-budget")]
    [InlineData("slot work budget reached; the remaining virtual methods were counted as PublicContract", "slot-budget")]
    [InlineData("a reason no one has written yet", "other")]
    [InlineData("x <Module>..cctor runs at load", "other")]
    public void GapCategory_MatchesTheFactsFixedPhraseAtTheStart(string reason, string expected)
    {
        Assert.Equal(expected, ReachabilityChild.GapCategory(reason));
    }

    // N5: the category comes from RootGap.Class and RootGap.Reason, never from the assembly name a package controls. An
    // assembly named like another reason's phrase steers nothing, and a gap of another class does not leak in.
    [Fact]
    public void CategoriesOf_IgnoresACraftedAssemblyName()
    {
        var gaps = new[] { new RootGap("evil: the graph is truncated: 12 root(s) reach code the graph cannot see", RootClass.LoadTime, "<Module>..cctor runs at load and is invisible to the model") };
        var report = Reachability.Analyze(MethodGraph.FromParts([], [], [], completeCoverage, new GraphFacts([], [], gaps)));

        Assert.Equal(["module-initializer"], ReachabilityChild.CategoriesOf(RootClass.LoadTime, report, gaps));
        Assert.Empty(ReachabilityChild.CategoriesOf(RootClass.PublicApi, report, gaps));
        Assert.Contains(report.Classes.Single(c => c.Class == RootClass.LoadTime).Reasons, r => r.Contains("the graph is truncated", StringComparison.Ordinal));
    }

    // Pinned against the library: for every class, one category per reason Reachability writes.
    [Fact]
    public void CategoriesOf_MirrorsTheLibrarysReasons()
    {
        var gaps = new[] { new RootGap("A.dll", RootClass.LoadTime, "<Module>..cctor runs at load and is invisible to the model") };
        var coverage = completeCoverage with { Truncated = true, TruncatedBy = "nodes", ModulesUnreadable = 1, RenamedImplementations = 2, Index = new IndexCoverage(1, 0, 0) };
        var graph = MethodGraph.FromParts(
            [new MethodNode("App.Root()", "App.Root", MethodNodeKind.OwnWithBody)], [],
            [new GraphOpacity("App.Root()", 0, OpacityKind.IndirectCall, "calli")], coverage,
            new GraphFacts([new OwnMethodFacts("App.Root()", "A.dll", "App", RootClass.LoadTime | RootClass.PublicApi, false, true)], [], gaps));
        var report = Reachability.Analyze(graph);

        foreach (var status in report.Classes)
            Assert.Equal(status.Reasons.Count, ReachabilityChild.CategoriesOf(status.Class, report, gaps).Count);
        Assert.Equal(["index-incomplete", "module-initializer", "modules-unreadable", "renamed-implementations", "truncated", "unseen"],
            ReachabilityChild.CategoriesOf(RootClass.LoadTime, report, gaps));
    }

    // A failed analysis (Partial, not truncated) is analysis-failed alone, as its one reason is.
    [Fact]
    public void CategoriesOf_AFailedAnalysis_IsAnalysisFailedAlone()
    {
        var report = new ReachabilityReport([], [], false,
            [new RootClassStatus(RootClass.LoadTime, 0, RootClassVerdict.Unknown, ["reachability could not be computed: boom"])], 0, [], 0, completeCoverage, true, "boom");

        Assert.Equal(["analysis-failed"], ReachabilityChild.CategoriesOf(RootClass.LoadTime, report, [new RootGap("A.dll", RootClass.LoadTime, "<Module>..cctor runs at load")]));
    }

    [Fact]
    public void Unknown_CountsPackagesPerReasonAndUnseenEnd()
    {
        var unknown = new VerdictRecord(RootClass.LoadTime, RootClassVerdict.Unknown,
            ["A.dll: <Module>..cctor runs at load and is invisible to the model", "2 root(s) reach code the graph cannot see"], ["module-initializer", "unseen"]);
        var unseen = new UnseenBreakdown([new NamedCount("IndirectCall", 1)], 1, 0,
            [new UnseenEnd(RootClass.LoadTime, "opacity:IndirectCall", 2), new UnseenEnd(RootClass.LoadTime, "internal-call", 1)]);
        var results = new[]
        {
            Package("A", Lib(verdicts: [unknown]) with { Unseen = unseen }),
            Package("B", Lib(verdicts: [new VerdictRecord(RootClass.LoadTime, RootClassVerdict.None, [], [])]) with { LoadFailures = [new LoadFailureRecord("lib/net8.0/n.dll", "native")] }),
        };

        var split = ReachabilityAggregation.Unknown(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);

        Assert.Equal(new Share(1, 2), split.Unknown);
        Assert.Equal([new NamedCount("module-initializer", 1), new NamedCount("unseen", 1)], split.Reasons);
        Assert.Equal([new NamedCount("internal-call", 1), new NamedCount("opacity:IndirectCall", 1)], split.UnseenEnds);
        Assert.Equal(1, split.PackagesWithLoadFailures);
    }

    // ---------------------------------------------------------------------------------------------------
    // The regression oracle
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Oracle_WhenPlibPresenceReproducesTheBaseline_Matches()
    {
        var oracle = PresenceOracle.Parse(OracleText);
        var plib = ReachabilityAggregation.View(OracleResults(), Population.Plib);

        var comparison = ReachabilityAggregation.CompareOracle(oracle, plib, OracleHash);

        Assert.True(comparison.Full);
        Assert.True(comparison.Match, string.Join(Environment.NewLine, comparison.Differences));
        Assert.Equal(2, comparison.PackagesCompared);
    }

    [Fact]
    public void Oracle_WhenOneFindingMoves_MismatchesAndNamesIt()
    {
        var results = OracleResults();
        results[1] = results[1] with { Folders = [Lib(presence: [(Capability.Network, 4)], methods: 7)] };

        var comparison = ReachabilityAggregation.CompareOracle(PresenceOracle.Parse(OracleText), ReachabilityAggregation.View(results, Population.Plib), OracleHash);

        Assert.False(comparison.Match);
        Assert.Contains("B 2.0.0 Network findings: expected 3, measured 4", comparison.Differences);
        Assert.Contains("Network findings: expected 4, measured 5", comparison.Differences);
    }

    // The oracle counts the baseline's rule: lib/<tfm>/*.dll only, so a P-lib .exe does not move it.
    [Fact]
    public void Oracle_CountsOnlyDllAssemblies()
    {
        var results = OracleResults();
        var withExe = results[0].Folders[0] with
        {
            Presence = [.. results[0].Folders[0].Presence, new AssemblyPresence("lib/net8.0/tool.exe", true, null, 99, 0, [new PresenceCount(Capability.Network, ApiCallKind.Call, 9)])],
        };
        results[0] = results[0] with { Folders = [withExe] };

        Assert.True(ReachabilityAggregation.CompareOracle(PresenceOracle.Parse(OracleText), ReachabilityAggregation.View(results, Population.Plib), OracleHash).Match);
    }

    [Fact]
    public void Oracle_WhenAPackageIsMissingFromPlib_Mismatches()
    {
        var results = OracleResults().Take(1).ToArray();

        var comparison = ReachabilityAggregation.CompareOracle(PresenceOracle.Parse(OracleText), ReachabilityAggregation.View(results, Population.Plib), OracleHash);

        Assert.False(comparison.Match);
        Assert.Contains("denominator (P-lib packages): expected 2, measured 1", comparison.Differences);
        Assert.Contains("B 2.0.0: in the baseline, not in P-lib", comparison.Differences);
    }

    // On another manifest (a smoke subset) the totals are not compared, only the packages both hold.
    [Fact]
    public void Oracle_OnAnotherManifest_ComparesOnlyThePackagesBothHold()
    {
        var results = OracleResults().Take(1).ToArray();

        var comparison = ReachabilityAggregation.CompareOracle(PresenceOracle.Parse(OracleText), ReachabilityAggregation.View(results, Population.Plib), "another-hash");

        Assert.False(comparison.Full);
        Assert.True(comparison.Match, string.Join(Environment.NewLine, comparison.Differences));
        Assert.Equal(1, comparison.PackagesCompared);
    }

    // Each checked-in oracle is internally consistent: its packages sum to its totals (it was copied, not retyped). R2's
    // 2026-08-21 file and R2b's 2026-11-06 default (the S2 map), both over C100.
    [Theory]
    [InlineData(Program.OracleFileName)]
    [InlineData(Program.R2OracleFileName)]
    public void Oracle_TheCheckedInFile_IsConsistentWithItself(string file)
    {
        var oracle = PresenceOracle.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, file)));

        Assert.Equal("9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6", oracle.ManifestHash);
        Assert.Equal(oracle.Denominator, oracle.Packages.Count);
        Assert.Equal(oracle.Assemblies, oracle.Packages.Sum(p => p.Assemblies));
        Assert.Equal(oracle.MethodsAnalysed, oracle.Packages.Sum(p => p.MethodsAnalysed));
        Assert.Equal(oracle.TotalFindings, oracle.Packages.Sum(p => p.Findings));
        Assert.All(oracle.Capabilities, c =>
        {
            Assert.Equal(c.Packages, oracle.Packages.Count(p => p.ByCapability.GetValueOrDefault(c.Capability) > 0));
            Assert.Equal(c.Total, oracle.Packages.Sum(p => p.ByCapability.GetValueOrDefault(c.Capability)));
        });
        Assert.Equal(Enum.GetValues<Capability>().Order(), oracle.Capabilities.Select(c => c.Capability).Order());
    }

    // ---------------------------------------------------------------------------------------------------
    // Refusing to mix builds
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void EnsureOneBuild_WithAResultOfAnotherBuild_RefusesAndNamesIt()
    {
        var other = new BuildIdentity("0ther", "5ha");
        var results = new[] { Package("A", Lib()), Package("B", Lib()) with { Identity = other } };

        var ex = Assert.Throws<MixedBuildException>(() => ReachabilityAggregation.EnsureOneBuild(results, identity));

        Assert.Contains("B 1.0.0 was measured by commit 0ther, assemblies 5ha", ex.Message);
        Assert.Contains(identity.ToString(), ex.Message);
        Assert.DoesNotContain("A 1.0.0", ex.Message);
    }

    [Fact]
    public void EnsureOneBuild_WithOneBuild_Accepts()
    {
        ReachabilityAggregation.EnsureOneBuild([Package("A", Lib()), Package("B", Lib())], identity);
    }

    // The report refuses too, so a mixed set can never be rendered whatever reaches it.
    [Fact]
    public void Write_WithResultsOfTwoBuilds_Refuses()
    {
        using var dir = new TempDirectory();
        var results = new[] { Package("A", Lib()) with { Identity = new BuildIdentity("x", "y") } };

        Assert.Throws<MixedBuildException>(() => ReachabilityCorpusReport.Write(dir.Path, Context(Manifest(dir, "A")), results));
        Assert.Empty(Directory.GetFiles(dir.Path, "reachability-benign-*"));
    }

    // A stale cached result refuses the driver before any child runs.
    [Fact]
    public void Driver_WithACachedResultOfAnotherBuild_RefusesBeforeAnyChild()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "B");
        var cache = FakeCache(dir, "A", "B");
        var results = Directory.CreateDirectory(Path.Combine(dir.Path, "results")).FullName;
        PackageReachResult.WriteAtomically(PackageReachResult.PathOf(results, manifest.Entries[1]),
            (Package("B", Lib()) with { Identity = new BuildIdentity("old", "old") }).ToJson());
        var children = 0;

        var driver = new ReachabilityDriver(cache, results, int.MaxValue, identity, (e, _) => { children++; return Package(e.Id, Lib()); });

        var ex = Assert.Throws<MixedBuildException>(() => driver.Run(manifest, TextWriter.Null));
        Assert.Contains("Refusing to mix builds", ex.Message);
        Assert.Contains("commit old", ex.Message);
        Assert.Equal(0, children);
    }

    // ---------------------------------------------------------------------------------------------------
    // The offline driver
    // ---------------------------------------------------------------------------------------------------

    // A package not in the cache is not-cached: no child, no result file, and no PackageCache (so no feed) is built.
    [Fact]
    public void Driver_WithAMissingPackage_RecordsNotCached_AndNeverTouchesAFeed()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "Missing", "C");
        var cache = FakeCache(dir, "A", "C");
        var results = Path.Combine(dir.Path, "results");
        var asked = new List<string>();
        var before = PackageCache.Constructed;

        var run = new ReachabilityDriver(cache, results, int.MaxValue, identity, (e, nupkg) =>
        {
            asked.Add(e.Id);
            Assert.Equal(CachedNupkg.PathOf(cache, e), nupkg);
            return Package(e.Id, Lib());
        }).Run(manifest, TextWriter.Null);

        Assert.Equal(before, PackageCache.Constructed);
        Assert.Equal(["A", "C"], asked);
        Assert.True(run.Complete);
        Assert.Equal([PackageReachResult.Scanned, PackageReachResult.NotCached, PackageReachResult.Scanned], run.Results.Select(r => r.Status));
        Assert.Equal("no Missing.1.0.0.nupkg in the cache", run.Results[1].Detail);
        Assert.False(File.Exists(PackageReachResult.PathOf(results, manifest.Entries[1])));
        Assert.True(File.Exists(PackageReachResult.PathOf(results, manifest.Entries[0])));
    }

    // The cache path is the one PackageCache downloads to: <cache>/packages/<Id>.<Version>.nupkg.
    [Fact]
    public void CachedNupkg_PathOf_IsTheDownloadCachesPath()
    {
        Assert.Equal(Path.Combine("C:\\c", "packages", "Polly.8.7.0.nupkg"), CachedNupkg.PathOf("C:\\c", new ManifestEntry("Polly", "8.7.0")));
    }

    // Results are cached per (id, version): a rerun reuses them; --max-children caps NEW children, the rest are pending.
    [Fact]
    public void Driver_ReusesCachedResults_AndStopsAfterMaxChildren()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A", "B", "C");
        var cache = FakeCache(dir, "A", "B", "C");
        var results = Path.Combine(dir.Path, "results");
        var asked = new List<string>();
        PackageReachResult Child(ManifestEntry e, string _) { asked.Add(e.Id); return Package(e.Id, Lib()); }

        var first = new ReachabilityDriver(cache, results, 2, identity, Child).Run(manifest, TextWriter.Null);
        var second = new ReachabilityDriver(cache, results, 2, identity, Child).Run(manifest, TextWriter.Null);

        Assert.False(first.Complete);
        Assert.Equal(["C"], first.Pending.Select(e => e.Id));
        Assert.Equal(2, first.ChildrenRun);
        Assert.True(second.Complete);
        Assert.Equal(1, second.ChildrenRun);
        Assert.Equal(["A", "B", "C"], asked);
        Assert.Equal(["A", "B", "C"], second.Results.Select(r => r.Id));
    }

    // A crashed, timed-out or incomplete child is a cached result too: accounted for, never silently dropped.
    [Fact]
    public void Driver_CachesAbnormalChildResults()
    {
        using var dir = new TempDirectory();
        var manifest = Manifest(dir, "A");
        var cache = FakeCache(dir, "A");
        var results = Path.Combine(dir.Path, "results");

        new ReachabilityDriver(cache, results, int.MaxValue, identity,
            (e, _) => PackageReachResult.Without(e, PackageReachResult.Crashed, "child exited 35", 35, identity)).Run(manifest, TextWriter.Null);
        var rerun = new ReachabilityDriver(cache, results, int.MaxValue, identity, (_, _) => throw new InvalidOperationException("must not run")).Run(manifest, TextWriter.Null);

        Assert.Equal(PackageReachResult.Crashed, rerun.Results.Single().Status);
        Assert.Equal(35, rerun.Results.Single().ExitCode);
    }

    // ---------------------------------------------------------------------------------------------------
    // The child's status rule
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Classify_ANonZeroExit_IsCrashed_AndNamesFailFast()
    {
        var result = ReachabilityChildRunner.Classify(Entry("A"), 35, "", "Process terminated. Assertion failed.\nmore", null, identity, 5);

        Assert.Equal(PackageReachResult.Crashed, result.Status);
        Assert.Equal(35, result.ExitCode);
        Assert.Equal("child exited 35 (35 = Environment.FailFast - uncatchable, see ADR-0021): Process terminated. Assertion failed.", result.Detail);
    }

    [Fact]
    public void Classify_ExitZeroWithoutDone_IsIncomplete()
    {
        var result = ReachabilityChildRunner.Classify(Entry("A"), 0, "partial output\n", "", Payload(), identity, 5);

        Assert.Equal(PackageReachResult.Incomplete, result.Status);
    }

    [Fact]
    public void Classify_DoneWithoutAPayload_IsIncomplete()
    {
        Assert.Equal(PackageReachResult.Incomplete, ReachabilityChildRunner.Classify(Entry("A"), 0, "DONE\r\n", "", null, identity, 5).Status);
        Assert.Equal(PackageReachResult.Incomplete, ReachabilityChildRunner.Classify(Entry("A"), 0, "DONE\n", "", "{ not json", identity, 5).Status);
    }

    // A native binary fails both sides: no graph, and a failed presence scan. (One that presence did read is graph-failed;
    // see From_AFolderPresenceReadButTheGraphDidNot_IsGraphFailed.)
    [Fact]
    public void Classify_DoneWithAPayload_IsScanned_OrNoAssemblies()
    {
        var scanned = ReachabilityChildRunner.Classify(Entry("A"), 0, "DONE\n", "", Payload(Lib()), identity, 5);
        var none = ReachabilityChildRunner.Classify(Entry("B"), 0, "DONE\n", "", Payload(), identity, 5);
        var native = ReachabilityChildRunner.Classify(Entry("C"), 0, "DONE\n", "", Payload(Folder("runtimes/win-x64/native", "runtimes") with
        {
            GraphBuilt = false,
            Assemblies = [],
            LoadFailures = [new LoadFailureRecord("runtimes/win-x64/native/sni.dll", "not managed")],
            Presence = [new AssemblyPresence("runtimes/win-x64/native/sni.dll", false, "load failed: not a managed assembly", 0, 0, [])],
        }), identity, 5);

        Assert.Equal(PackageReachResult.Scanned, scanned.Status);
        Assert.Equal(5, scanned.Cost.ChildWallMs);
        Assert.Equal(identity, scanned.Identity);
        Assert.Equal(PackageReachResult.NoAssemblies, none.Status);
        Assert.Equal("the package ships no .dll or .exe", none.Detail);
        Assert.Equal(PackageReachResult.NoAssemblies, native.Status);
        Assert.Equal("1 binar(ies) in 1 folder(s), none loadable as a managed assembly", native.Detail);
    }

    // A result survives its JSON round trip, enums by name.
    [Fact]
    public void Result_RoundTripsThroughJson()
    {
        var result = Package("A", Lib(presence: [(Capability.Network, 2)], reaches: [Reach(RootClass.LoadTime, null, 1)],
            profiles: [Profile(RootClass.LoadTime, [Capability.Network], unseen: true)]));

        var json = result.ToJson();
        var back = PackageReachResult.FromJson(json);

        Assert.Equal(json, back.ToJson());
        Assert.Contains("\"Class\": \"LoadTime\"", json);
        Assert.Contains("\"Capability\": null", json);
    }

    // ---------------------------------------------------------------------------------------------------
    // Folder rules: P-lib, roles
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("lib/net8.0", "net8.0", true)]
    [InlineData("Lib/net8.0", "net8.0", true)]
    [InlineData("lib/net8.0/de", "net8.0", false)]
    [InlineData("lib/net8.0", "net9.0", false)]
    [InlineData("lib/net8.0", null, false)]
    [InlineData("build/net8.0", "net8.0", false)]
    [InlineData("lib/portable-net45%2Bwin8", "portable-net45+win8", true)]
    [InlineData("lib%2Fnet8.0", "net8.0", true)]
    [InlineData("lib", "net8.0", false)]
    public void IsPlibFolder_MatchesLibPlusTheChosenTfm_AsNuGetReadsTheName(string folder, string? tfm, bool expected)
    {
        Assert.Equal(expected, ReachabilityChild.IsPlibFolder(folder, tfm));
    }

    [Theory]
    [InlineData("", "(root)")]
    [InlineData("lib/net8.0", "lib")]
    [InlineData("BuildTransitive/net8.0", "buildTransitive")]
    [InlineData("buildtransitive", "buildTransitive")]
    [InlineData("analyzers/dotnet/cs", "analyzers")]
    [InlineData("tools/net8.0/any", "tools")]
    [InlineData("runtimes/win-x64/lib/net8.0", "runtimes")]
    [InlineData("Custom/x", "custom")]
    [InlineData("build%2Fnet8.0", "build")]
    public void RoleOf_IsTheFirstSegmentInNuGetsSpelling(string folder, string expected)
    {
        Assert.Equal(expected, ReachabilityChild.RoleOf(folder));
    }

    // The harness and the default mode pick the same P-lib TFM (one rule, TfmSelection).
    [Fact]
    public void TfmSelection_PicksTheHighestNetThenNetstandard20()
    {
        Assert.Equal("net10.0", TfmSelection.Choose(["lib/net8.0/A.dll", "lib/net10.0/A.dll", "lib/netstandard2.0/A.dll", "lib/net10.0-windows/A.dll"]).Tfm);
        Assert.Equal("netstandard2.0", TfmSelection.Choose(["lib/netstandard2.0/A.dll", "lib/net462/A.dll"]).Tfm);
        Assert.Null(TfmSelection.Choose(["build/A.dll"]).Tfm);
    }

    // ---------------------------------------------------------------------------------------------------
    // The parity copy
    // ---------------------------------------------------------------------------------------------------

    // PresenceParityTests' NameShadowed rule (S3 review N1): only a call-site edge from that caller to the own namesake
    // explains a scanner-only triple; another caller's call, an own node alone, or a LoadToken edge does not.
    [Fact]
    public void Parity_NameShadowed_NeedsACallSiteEdgeFromThatCallerToTheOwnNamesake()
    {
        const string shadowId = "System.Environment.GetEnvironmentVariable(System.String)";
        const string shadowKey = "System.Environment.GetEnvironmentVariable";
        var graph = MethodGraph.FromParts(
            [
                new MethodNode("App.Calls()", "App.Calls", MethodNodeKind.OwnWithBody),
                new MethodNode("App.Lone()", "App.Lone", MethodNodeKind.OwnWithBody),
                new MethodNode("App.Token()", "App.Token", MethodNodeKind.OwnWithBody),
                new MethodNode(shadowId, shadowKey, MethodNodeKind.OwnWithBody),
            ],
            [new MethodEdge("App.Calls()", shadowId, MethodEdgeKind.Call, 1), new MethodEdge("App.Token()", shadowId, MethodEdgeKind.LoadToken, 2)],
            [], completeCoverage, GraphFacts.None);
        var findings = new[] { "Calls", "Lone", "Token" }
            .Select(m => new ApiCallFinding(Capability.EnvironmentProbe, ApiCallKind.Call, "App", m, shadowKey));

        var parity = ReachabilityParity.Compare(findings, graph);

        Assert.Equal(1, parity.NameShadowed.Count);
        Assert.Equal(["App.Calls -[EnvironmentProbe]-> System.Environment.GetEnvironmentVariable"], parity.NameShadowed.Items);
        Assert.Equal(2, parity.ScannerOnly.Count);
        Assert.Equal(["App.Lone -[EnvironmentProbe]-> System.Environment.GetEnvironmentVariable", "App.Token -[EnvironmentProbe]-> System.Environment.GetEnvironmentVariable"],
            parity.ScannerOnly.Items);
        Assert.Equal(0, parity.GraphOnly.Count);
        Assert.Equal("DIFFERS", parity.Verdict);
    }

    // C-build S4 (ReportGenerator 5.5.12 tools/net47, bundled Microsoft.CSharp.dll): the own callee's graph key keeps an
    // explicit generic-interface implementation's argument list, the scanner's drops it; the copy reduces the own callee's
    // key by ScannerKey, as PresenceParityTests does, so the triple is NameShadowed and the folder NAMED.
    [Fact]
    public void Parity_NameShadowed_MatchesAnExplicitGenericInterfaceCallee_ByItsScannerKey()
    {
        const string iterator = "Microsoft.CSharp.RuntimeBinder.Semantics.AggregateType.<get_TypeHierarchy>d__17";
        const string callerMethod = "System.Collections.IEnumerable.GetEnumerator";
        const string calleeKey = iterator + ".System.Collections.Generic.IEnumerable<Microsoft.CSharp.RuntimeBinder.Semantics.AggregateType>.GetEnumerator";
        var graph = MethodGraph.FromParts(
            [
                new MethodNode($"{iterator}.{callerMethod}()", $"{iterator}.{callerMethod}", MethodNodeKind.OwnWithBody),
                new MethodNode(calleeKey + "()", calleeKey, MethodNodeKind.OwnWithBody),
            ],
            [new MethodEdge($"{iterator}.{callerMethod}()", calleeKey + "()", MethodEdgeKind.Call, 1)],
            [], completeCoverage, GraphFacts.None);
        var findings = new[] { new ApiCallFinding(Capability.DynamicCodeLoading, ApiCallKind.Call, iterator, callerMethod, calleeKey) };

        var parity = ReachabilityParity.Compare(findings, graph);

        Assert.Equal(1, parity.NameShadowed.Count);
        Assert.Equal([$"{iterator}.{callerMethod} -[DynamicCodeLoading]-> {iterator}.System.Collections.Generic.IEnumerable.GetEnumerator"], parity.NameShadowed.Items);
        Assert.Equal(0, parity.ScannerOnly.Count);
        Assert.Equal(0, parity.GraphOnly.Count);
        Assert.Equal("NAMED", parity.Verdict);
    }

    // PresenceParityTests' caller rule: only the callee is reduced. The scanner's caller key is ScannerKey(CallerType).CallerMethod,
    // the method name verbatim, as the graph keys it: a caller that is itself an explicit generic-interface implementation
    // matches unreduced, and a finding whose caller method had that argument list dropped is explained by nothing.
    [Fact]
    public void Parity_NameShadowed_MatchesTheCallerKeyVerbatim()
    {
        const string callerKey = "App.Items.System.Collections.Generic.IEnumerable<App.Item>.GetEnumerator";
        const string shadowKey = "System.Environment.GetEnvironmentVariable";
        var graph = MethodGraph.FromParts(
            [new MethodNode(callerKey + "()", callerKey, MethodNodeKind.OwnWithBody), new MethodNode(shadowKey + "(System.String)", shadowKey, MethodNodeKind.OwnWithBody)],
            [new MethodEdge(callerKey + "()", shadowKey + "(System.String)", MethodEdgeKind.Call, 1)],
            [], completeCoverage, GraphFacts.None);
        var findings = new[]
        {
            new ApiCallFinding(Capability.EnvironmentProbe, ApiCallKind.Call, "App.Items", "System.Collections.Generic.IEnumerable<App.Item>.GetEnumerator", shadowKey),
            new ApiCallFinding(Capability.EnvironmentProbe, ApiCallKind.Call, "App.Items", "System.Collections.Generic.IEnumerable.GetEnumerator", shadowKey),
        };

        var parity = ReachabilityParity.Compare(findings, graph);

        Assert.Equal(1, parity.NameShadowed.Count);
        Assert.Equal([$"{callerKey} -[EnvironmentProbe]-> {shadowKey}"], parity.NameShadowed.Items);
        Assert.Equal(1, parity.ScannerOnly.Count);
        Assert.Equal([$"App.Items.System.Collections.Generic.IEnumerable.GetEnumerator -[EnvironmentProbe]-> {shadowKey}"], parity.ScannerOnly.Items);
        Assert.Equal(0, parity.GraphOnly.Count);
        Assert.Equal("DIFFERS", parity.Verdict);
    }

    // The keying matches the scanner's: generic argument lists dropped, NativeImport keyed as one callee, both sides.
    [Fact]
    public void Parity_KeysGenericsAndNativeImportsAsThePinnedRuleDoes()
    {
        var graph = MethodGraph.FromParts(
            [
                new MethodNode("App.Run()", "App.Run", MethodNodeKind.OwnWithBody),
                new MethodNode("App.Native()", "App.Native", MethodNodeKind.OwnBodyless),
                new MethodNode("System.Linq.Expressions.Expression`1.Compile()", "System.Linq.Expressions.Expression.Compile", MethodNodeKind.External),
            ],
            [new MethodEdge("App.Run()", "System.Linq.Expressions.Expression`1.Compile()", MethodEdgeKind.CallVirt, 3)],
            [], completeCoverage,
            new GraphFacts([new OwnMethodFacts("App.Native()", "App.dll", "App", RootClass.PublicApi, NativeImport: true, IsStatic: true)], [], []));
        var findings = new[]
        {
            new ApiCallFinding(Capability.DynamicCodeLoading, ApiCallKind.Call, "App", "Run", "System.Linq.Expressions.Expression<System.Func<System.String>>.Compile"),
            new ApiCallFinding(Capability.NativeInterop, ApiCallKind.NativeImport, "App", "Native", "kernel32!Beep"),
            new ApiCallFinding(Capability.NativeInterop, ApiCallKind.NativeExport, "App", "Exported", "<managed>!Exported"),
        };

        var parity = ReachabilityParity.Compare(findings, graph);

        Assert.Equal("EXACT", parity.Verdict);
        Assert.Equal(2, parity.Matched);
    }

    // Lists keep 50 items and the true count.
    [Fact]
    public void Parity_CapsEachListAtFifty_KeepingTheTrueCount()
    {
        var graph = MethodGraph.FromParts([], [], [], completeCoverage, GraphFacts.None);
        var findings = Enumerable.Range(0, 70).Select(i => new ApiCallFinding(Capability.FileSystem, ApiCallKind.Call, "App", $"M{i:D2}", "System.IO.File.ReadAllText"));

        var parity = ReachabilityParity.Compare(findings, graph);

        Assert.Equal(70, parity.ScannerOnly.Count);
        Assert.Equal(ReachabilityChild.MaxListed, parity.ScannerOnly.Items.Count);
        Assert.Equal("App.M00 -[FileSystem]-> System.IO.File.ReadAllText", parity.ScannerOnly.Items[0]);
    }

    [Theory]
    [InlineData("System.Linq.Expressions.Expression<System.Func<System.String>>.Compile", "System.Linq.Expressions.Expression.Compile")]
    [InlineData("A.<<Run>b__0_0>d.MoveNext", "A.<<Run>b__0_0>d.MoveNext")]
    [InlineData("A.Box<System.Int32>.<Wraps>b__0", "A.Box.<Wraps>b__0")]
    [InlineData("A.<get_X>d__17.System.Collections.Generic.IEnumerable<A.T>.GetEnumerator", "A.<get_X>d__17.System.Collections.Generic.IEnumerable.GetEnumerator")]
    public void ScannerKey_IsThePinnedProjection(string rendered, string expected)
    {
        Assert.Equal(expected, ReachabilityParity.ScannerKey(rendered));
    }

    // ---------------------------------------------------------------------------------------------------
    // The report
    // ---------------------------------------------------------------------------------------------------

    // The main report and TSV never depend on what a run cost: times and working sets go to the cost file only.
    [Fact]
    public void Report_DoesNotDependOnCost()
    {
        using var dir = new TempDirectory();
        var context = Context(Manifest(dir, "A", "B"));
        var results = new[] { Package("A", Lib(presence: [(Capability.Network, 1)])), Package("B", Folder("build", "build")) };
        var costly = results.Select(r => r with { Cost = new PackageCost(999, 888, 77, 123_456_789, [new FolderCost("lib/net8.0", 5, 6, 7, 8)]) }).ToArray();

        Assert.Equal(ReachabilityCorpusReport.Markdown(context, results), ReachabilityCorpusReport.Markdown(context, costly));
        Assert.Equal(ReachabilityCorpusReport.Tsv(results), ReachabilityCorpusReport.Tsv(costly));
        Assert.NotEqual(ReachabilityCorpusReport.Cost(context, results), ReachabilityCorpusReport.Cost(context, costly));
    }

    // Every spec section is present, with the date from --date in the title and the file names.
    [Fact]
    public void Report_HasEverySectionOfTheSpec()
    {
        using var dir = new TempDirectory();
        var context = Context(Manifest(dir, "A"));

        var paths = ReachabilityCorpusReport.Write(dir.Path, context, [Package("A", Lib())]).Paths;
        var md = File.ReadAllText(paths[0]);

        Assert.Equal(["reachability-benign-2026-11-05.md", "reachability-benign-2026-11-05.tsv", "reachability-benign-2026-11-05-cost.md"], paths.Select(Path.GetFileName));
        foreach (var section in new[] { "## 1. Parameters", "## 2. Regression oracle", "## 3. E1", "## 4. E2", "## 5. Class x capability", "## 6. Q2", "## 7. Q3",
                     "## 8. Q4", "## 9. Q5", "## 10. Q6", "## 11. Trigger-class evidence", "## 12. Coverage honesty" })
            Assert.Contains(section, md);
        Assert.DoesNotContain("\r", md);
    }

    // Package-derived text cannot split a table row, open a tag or code span, or hide behind a bidi override.
    [Fact]
    public void Escape_NeutralisesMarkdownAndHiddenCharacters()
    {
        Assert.Equal("a\\|b \\<Module> \\`1 x\\u{202e}y\\u{200b}z\\u{000a}", ReachabilityCorpusReport.Escape("a|b <Module> `1 x\u202Ey\u200Bz\n"));
        Assert.Equal("t\\u{e0041}", ReachabilityCorpusReport.Escape("t\U000E0041"));
    }

    [Fact]
    public void Deterministic_MasksTheTempDirectoryAndRandomExtractionNames()
    {
        var text = $"could not read {Path.Combine(Path.GetTempPath(), "silvergun", "pkg-abcDEF123456", "x.dll")}";

        Assert.Equal($"could not read <temp>/{Path.Combine("silvergun", "pkg-<random>", "x.dll")}", ReachabilityCorpusReport.Deterministic(text));
    }

    // ---------------------------------------------------------------------------------------------------
    // The child, end to end, in process, over a synthetic package of our own fixture
    // ---------------------------------------------------------------------------------------------------

    // Three folders of ShadowFixture: lib/net10.0 (P-lib, chosen over netstandard2.0), lib/netstandard2.0 and build. Each is
    // its own graph and role; presence finds the fixture's EnvironmentProbe uses; parity is NAMED by the one NameShadowed
    // triple PresenceParityTests pins; and a second measurement serializes identically.
    [Fact]
    public void Measure_ASyntheticPackage_MeasuresEveryFolder_Deterministically()
    {
        using var dir = new TempDirectory();
        var nupkg = SyntheticPackage(dir, ShadowFixtureAssembly.Path,
            "lib/net10.0/Shadow.dll", "lib/netstandard2.0/Shadow.dll", "build/Shadow.dll");

        var first = ReachabilityChild.Measure(nupkg);
        var second = ReachabilityChild.Measure(nupkg);

        Assert.Equal("net10.0", first.LibTfm);
        Assert.Equal(["net10.0", "netstandard2.0"], first.LibTfms);
        Assert.Equal(["build", "lib/net10.0", "lib/netstandard2.0"], first.Folders.Select(f => f.Folder));
        Assert.Equal(["build", "lib", "lib"], first.Folders.Select(f => f.Role));
        Assert.Equal([false, true, false], first.Folders.Select(f => f.IsPlib));
        Assert.All(first.Folders, f =>
        {
            Assert.True(f.GraphBuilt);
            Assert.True(f.OwnMethods > 0);
            Assert.True(f.PresenceOf(Capability.EnvironmentProbe) > 0);
            Assert.Equal("NAMED", f.Parity!.Verdict);
            Assert.Equal(1, f.Parity.NameShadowed.Count);
            Assert.Equal(ReachabilityChild.AllClasses, f.RootCounts.Select(c => c.Class));
        });
        Assert.Equal(Serialize(first with { Cost = PackageCost.None }), Serialize(second with { Cost = PackageCost.None }));
        Assert.Equal(3, first.Cost.Folders.Count);
    }

    // A package with no binary at all: no folders, so the parent records no-assemblies.
    [Fact]
    public void Measure_APackageWithNoAssemblies_HasNoFolders()
    {
        using var dir = new TempDirectory();
        var nupkg = SyntheticPackage(dir, null);

        var payload = ReachabilityChild.Measure(nupkg);

        Assert.Empty(payload.Folders);
        Assert.Null(payload.LibTfm);
        Assert.Equal(PackageReachResult.NoAssemblies, PackageReachResult.From(Entry("Synthetic"), payload, identity, 1).Status);
    }

    // ---------------------------------------------------------------------------------------------------
    // C1: no pass from floor data
    // ---------------------------------------------------------------------------------------------------

    // 1 of 10 composed passes on counted data (exactly 10%), but one more package's HostContract profiles were cut at 64:
    // counted against it, 2 of 10 > 10%. Floor, not a pass.
    [Fact]
    public void E2_ATruncatedClassProfileSet_ThatWouldPassOnCountedData_IsFloor()
    {
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", Lib(
            profiles: i == 0 ? [Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])] : []) with
        {
            ProfilesTruncatedClasses = i == 1 ? [RootClass.HostContract] : [],
        })).ToArray();
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        var e2 = ReachabilityAggregation.E2(plib, RootClass.HostContract);

        Assert.Equal(new Share(1, 10), e2.Inclusive);
        Assert.Equal(Outcome.Floor, e2.Outcome);
        Assert.Equal(1, e2.FloorPackages);
        Assert.Equal(1, e2.TruncatedPackages);
        // Another class's cut profiles are no floor for this one.
        Assert.Equal(Outcome.Pass, ReachabilityAggregation.E2(ReachabilityAggregation.View(
            results.Select(r => r with { Folders = [r.Folders[0] with { ProfilesTruncatedClasses = [RootClass.Hidden] }] }).ToArray(), Population.Plib), RootClass.HostContract).Outcome);
    }

    // Counted data already over 10% fails, floor or no floor.
    [Fact]
    public void E2_WhenCountedDataAlreadyFails_IsFail_EvenWithFloorPackages()
    {
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", Lib(
            profiles: i < 2 ? [Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])] : []) with
        {
            ProfilesTruncatedClasses = [RootClass.HostContract],
        })).ToArray();

        Assert.Equal(Outcome.Fail, ReachabilityAggregation.E2(ReachabilityAggregation.View(results, Population.Plib), RootClass.HostContract).Outcome);
    }

    // Presence 6, reach 3 passes on counted data (2 x 3 <= 6); a Partial folder that does not reach counts against it
    // (2 x 4 > 6). Floor.
    [Fact]
    public void E1_APartialReachFolder_ThatWouldPassOnCountedData_IsFloor()
    {
        var results = PartialCorpus(reach: 3, partial: [8]);

        var e1 = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);

        var cell = e1.Cells.Single(c => c.Capability == Capability.Network);
        Assert.Equal(1, cell.FloorPackages);
        Assert.Equal(Outcome.Floor, cell.Outcome);
        Assert.Equal(Outcome.Floor, e1.Outcome);
        Assert.Equal(ClassVerdict.UndecidedFloor, new ClassVerdict(RootClass.LoadTime, e1.Outcome, Outcome.Pass, Outcome.Pass, Outcome.Pass).Verdict);
    }

    // The same, with the floor package already reaching the capability: nothing to count against, so a pass.
    [Fact]
    public void E1_APartialFolderThatAlreadyReaches_DoesNotMakeAFloor()
    {
        var results = PartialCorpus(reach: 3, partial: [0]);

        Assert.Equal(Outcome.Pass, ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime).Outcome);
    }

    // Counted data already over half of presence fails, Partial folders or not.
    [Fact]
    public void E1_WhenCountedDataAlreadyFails_IsFail_EvenWithPartialFolders()
    {
        var results = PartialCorpus(reach: 4, partial: [8, 9]);

        Assert.Equal(Outcome.Fail, ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime).Outcome);
    }

    // A pass with room to spare survives its floor packages.
    [Fact]
    public void E1_WithRoomForEveryFloorPackage_Passes()
    {
        var results = PartialCorpus(reach: 1, partial: [8]);

        Assert.Equal(Outcome.Pass, ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime).Outcome);
    }

    // The harness's class lists follow the library after amendment a1: every single class in Reachability's order, and
    // R2's three trigger classes with RuntimeInvoked split three ways (TypeInitializer, Finalizer, NativeEntry).
    [Fact]
    public void ClassLists_FollowTheLibrarysOrder_AndTheTriggerClassesAreTheFiveSplitOnes()
    {
        var report = Reachability.Analyze(MethodGraph.FromParts([], [], [], completeCoverage, GraphFacts.None));

        Assert.Equal(report.Classes.Select(c => c.Class), ReachabilityChild.AllClasses);
        Assert.Equal(
            [RootClass.LoadTime, RootClass.HostContract, RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry],
            ReachabilityChild.TriggerClasses);
        Assert.Equal(ReachabilityChild.AllClasses.Take(5), ReachabilityChild.TriggerClasses);
    }

    // The child flags a class as cut when the report was cut and the class holds exactly MaxProfiles profiles.
    [Fact]
    public void TruncatedClasses_AreTheClassesHoldingTheCap_OnlyWhenTheReportWasCut()
    {
        var profiles = Enumerable.Range(0, ReachabilityChild.MaxProfiles).Select(i => new ReachProfile(RootClass.PublicApi, [Capability.FileSystem], false, [Capability.FileSystem], false, 1, $"R{i}"))
            .Append(new ReachProfile(RootClass.Hidden, [Capability.Network], false, [Capability.Network], false, 1, "H")).ToArray();
        ReachabilityReport Report(bool cut) => new([], profiles, cut, [], 0, [], 0, completeCoverage, false, null);

        Assert.Equal([RootClass.PublicApi], ReachabilityChild.TruncatedClasses(Report(true)));
        Assert.Empty(ReachabilityChild.TruncatedClasses(Report(false)));
    }

    // Pinned against the library: 127 roots reaching 127 distinct capability sets are cut to MaxProfiles PublicApi
    // profiles, and the child names exactly that class.
    [Fact]
    public void TruncatedClasses_OnARealCutReport_NamesTheCutClass()
    {
        var keys = new[]
        {
            "System.IO.File.ReadAllText", "System.Net.Http.HttpClient.SendAsync", "System.Diagnostics.Process.Start", "Microsoft.Win32.Registry.GetValue",
            "System.Environment.GetEnvironmentVariable", "System.Security.Cryptography.SHA256.HashData", "System.Reflection.Assembly.LoadFrom",
        };
        var capabilities = keys.Select(k => CapabilityMap.Default.Classify(k)).Select(c => c.Class == CapabilityClass.Capability ? c.Capability : null).ToArray();
        Assert.All(capabilities, c => Assert.NotNull(c));
        Assert.Equal(keys.Length, capabilities.Distinct().Count());

        var roots = Enumerable.Range(1, (1 << keys.Length) - 1).ToArray();
        var graph = MethodGraph.FromParts(
            [.. keys.Select(k => new MethodNode($"{k}()", k, MethodNodeKind.External)), .. roots.Select(i => new MethodNode($"App.R{i:D3}()", $"App.R{i:D3}", MethodNodeKind.OwnWithBody))],
            [.. roots.SelectMany(i => keys.Where((_, bit) => (i & (1 << bit)) != 0).Select(k => new MethodEdge($"App.R{i:D3}()", $"{k}()", MethodEdgeKind.Call, 1)))],
            [], completeCoverage,
            new GraphFacts([.. roots.Select(i => new OwnMethodFacts($"App.R{i:D3}()", "App.dll", "App", RootClass.PublicApi, false, true))], [], []));

        var report = Reachability.Analyze(graph);

        Assert.True(report.ProfilesTruncated);
        Assert.Equal(ReachabilityChild.MaxProfiles, report.Profiles.Count(p => p.Class == RootClass.PublicApi));
        Assert.Equal([RootClass.PublicApi], ReachabilityChild.TruncatedClasses(report));
    }

    // ---------------------------------------------------------------------------------------------------
    // W1: graph-failed
    // ---------------------------------------------------------------------------------------------------

    // A folder with no graph whose presence still read an assembly makes the package graph-failed, with the count named;
    // no-assemblies stays for packages where neither side loaded anything.
    [Fact]
    public void From_AFolderPresenceReadButTheGraphDidNot_IsGraphFailed()
    {
        var failed = Folder("build", "build") with { GraphBuilt = false, Assemblies = [], LoadFailures = [new LoadFailureRecord("build/a.dll", "boom")] };
        var neither = failed with { Presence = [new AssemblyPresence("build/a.dll", false, "load failed", 0, 0, [])] };

        var graphFailed = PackageReachResult.From(Entry("A"), new ChildPayload("net8.0", [], [Lib(), failed], PackageCost.None), identity, 1);
        var none = PackageReachResult.From(Entry("B"), new ChildPayload(null, [], [neither], PackageCost.None), identity, 1);

        Assert.Equal(PackageReachResult.GraphFailed, graphFailed.Status);
        Assert.Equal("1 assembl(ies) scanned by presence but not in the graph", graphFailed.Detail);
        Assert.Equal(["build/a.dll"], failed.PresenceOnly);
        Assert.Equal(PackageReachResult.NoAssemblies, none.Status);
    }

    // A graph-failed package is still measured: in the populations, as a floor package, and in section 12 by count.
    [Fact]
    public void GraphFailed_IsAFloorPackage_AndNamedInCoverageHonesty()
    {
        using var dir = new TempDirectory();
        var failed = Folder("build", "build") with { GraphBuilt = false, Assemblies = [] };
        var result = PackageReachResult.From(Entry("A"), new ChildPayload("net8.0", [], [Lib(), failed], PackageCost.None), identity, 1);

        var pall = ReachabilityAggregation.View([result], Population.Pall);
        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A")), [result]));

        Assert.True(pall.Units.Single().Floor);
        Assert.False(ReachabilityAggregation.View([result], Population.Plib).Units.Single().Floor);
        Assert.Contains("| A | 1.0.0 | build | no assembly of the folder loaded\\: no graph; 1 assembl(ies) scanned by presence but not in the graph", md);
    }

    // Presence the graph never saw cannot push E1 toward Pass: 6 packages present Network, but 2 of them only through an
    // assembly the graph did not load. Counted: 2 x 2 <= 6, no fail; worst case: 2 x (2 + 2) > 4 seen. Floor.
    [Fact]
    public void E1_PresenceOnlyAssemblies_CannotPushACellTowardPass()
    {
        var results = Enumerable.Range(0, 10).Select(i =>
        {
            var lib = Lib(presence: i < 6 ? [(Capability.Network, 1)] : [], reaches: i < 2 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []);
            return Package($"P{i}", i is 4 or 5 ? lib with { Assemblies = [] } : lib);
        }).ToArray();

        var cell = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime).Cells.Single(c => c.Capability == Capability.Network);

        Assert.Equal(new Share(6, 10), cell.Presence);
        Assert.Equal(6, cell.PresenceBest);
        Assert.Equal(4, cell.PresenceSeen);
        Assert.Equal(2, cell.FloorPackages);
        Assert.Equal(Outcome.Floor, cell.Outcome);
    }

    // C1-r2: a P-all package whose only folder is a graph-failed tools/ folder stays in the denominator as a floor package.
    // Without it the cell passes (2 x 3 <= 6); with it counted against the cell (2 x 4 > 6) it is Floor.
    [Fact]
    public void E1_APallPackageWithOnlyAGraphFailedToolsFolder_TurnsAPassIntoFloor()
    {
        var libs = Enumerable.Range(0, 9).Select(i => Package($"P{i}", Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();
        var toolsOnly = Package("P9", Folder("tools/net8.0", "tools") with { GraphBuilt = false, Assemblies = [] });

        var without = ReachabilityAggregation.E1(ReachabilityAggregation.View(libs, Population.Pall), RootClass.LoadTime);
        var pall = ReachabilityAggregation.View([.. libs, toolsOnly], Population.Pall);
        var with = ReachabilityAggregation.E1(pall, RootClass.LoadTime);

        Assert.Equal(Outcome.Pass, without.Outcome);
        Assert.Equal(10, pall.Denominator);
        Assert.True(pall.Units.Single(u => u.Id == "P9").Floor);
        Assert.Equal(1, with.Cells.Single(c => c.Capability == Capability.Network).FloorPackages);
        Assert.Equal(Outcome.Floor, with.Outcome);
    }

    // W1-r2: presence found only in a graph-failed sibling folder counts in the best case, so it cannot make a spurious
    // Fail. P0-P3 present Network in lib; P4 and P5 only in a graph-failed tools/ sibling; P0-P2 reach it. Ignoring the
    // siblings, 2 x 3 > 4 would fail; with them, 2 x 3 <= 6. The worst case (2 x 5 > 4 seen) leaves it Floor.
    [Fact]
    public void E1_PresenceOnlyInAGraphFailedSibling_MakesNoSpuriousFail()
    {
        var results = Enumerable.Range(0, 10).Select(i => i is 4 or 5
            ? Package($"P{i}", Lib(), Folder("tools/net8.0", "tools", presence: [(Capability.Network, 1)]) with { GraphBuilt = false, Assemblies = [] })
            : Package($"P{i}", Lib(presence: i < 4 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : [])))
            .ToArray();

        var cell = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Pall), RootClass.LoadTime).Cells.Single(c => c.Capability == Capability.Network);

        Assert.Equal(new Share(6, 10), cell.Presence);
        Assert.True(cell.Judged);
        Assert.Equal(6, cell.PresenceBest);
        Assert.Equal(4, cell.PresenceSeen);
        Assert.Equal(new Share(3, 10), cell.Reach);
        Assert.Equal(Outcome.Floor, cell.Outcome);
    }

    // W1-r2: a graph-loaded assembly whose presence scan failed makes its package a floor package, and its unmeasured
    // presence counts in the best case. P0-P3 present Network, P0-P2 reach it: 2 x 3 > 4 would fail; P4 and P5 failed their
    // presence scans, so the best case is 2 x 3 <= 6 - no Fail - and the worst case 2 x 5 > 4 - no Pass. Floor.
    [Fact]
    public void E1_APresenceScanFailureOnAGraphLoadedAssembly_SuppressesFail()
    {
        var failedScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", false, "capability analysis failed: boom", 0, 0, []) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", i is 4 or 5
            ? Lib() with { Presence = failedScan }
            : Lib(presence: i < 4 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        var cell = ReachabilityAggregation.E1(plib, RootClass.LoadTime).Cells.Single(c => c.Capability == Capability.Network);

        Assert.All(plib.Units.Where(u => u.Id is "P4" or "P5"), u => Assert.True(u.Floor && u.PresenceFloor));
        Assert.Equal(["lib/net8.0/a.dll"], results[4].Folders[0].PresenceUnmeasured);
        Assert.Equal(new Share(4, 10), cell.Presence);
        Assert.Equal(6, cell.PresenceBest);
        Assert.Equal(2, cell.FloorPackages);
        Assert.Equal(Outcome.Floor, cell.Outcome);
    }

    // ... and suppresses a Pass: 2 x 3 <= 6 on the counted data, but the failed-scan package counted as reaching gives
    // 2 x 4 > 6. Floor.
    [Fact]
    public void E1_APresenceScanFailureOnAGraphLoadedAssembly_SuppressesPass()
    {
        var failedScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", false, "load failed", 0, 0, []) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", i == 8
            ? Lib() with { Presence = failedScan }
            : Lib(presence: i < 6 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();

        var e1 = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);
        var withoutFailure = ReachabilityAggregation.E1(ReachabilityAggregation.View(results.Where(r => r.Id != "P8").ToArray(), Population.Plib), RootClass.LoadTime);

        Assert.Equal(Outcome.Pass, withoutFailure.Outcome);
        Assert.Equal(Outcome.Floor, e1.Outcome);
    }

    // C1-r3, the reviewer's scenario: P0 and P1 have measured Network presence and LoadTime reach; P2's presence scan
    // failed but its graph reaches Network. Measured presence 2 is under the gate, but the best case (3) is not, so the
    // Network cell is possibly judged, and its worst case (2 x 3 > 2 seen) does not pass: Floor. Beside a judged FileSystem
    // cell that passes, the class is Floor, not Pass.
    [Fact]
    public void E1_APossiblyJudgedCellWhoseWorstCaseFails_MakesTheClassFloor_NotPass()
    {
        var failedScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", false, "capability analysis failed: boom", 0, 0, []) };
        var reach = new[] { Reach(RootClass.LoadTime, Capability.Network, 1) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}",
            i < 2 ? Lib(presence: [(Capability.Network, 1)], reaches: reach)
            : i == 2 ? Lib(reaches: reach) with { Presence = failedScan }
            : Lib(presence: i < 9 ? [(Capability.FileSystem, 1)] : []))).ToArray();

        var e1 = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);

        var network = e1.Cells.Single(c => c.Capability == Capability.Network);
        Assert.False(network.Judged);
        Assert.Equal(3, network.PresenceBest);
        Assert.True(network.PossiblyJudged);
        Assert.False(network.WorstCasePasses);
        Assert.Equal(Outcome.Floor, network.Contribution);
        var fileSystem = e1.Cells.Single(c => c.Capability == Capability.FileSystem);
        Assert.True(fileSystem.Judged);
        Assert.Equal(Outcome.Pass, fileSystem.Contribution);
        Assert.Equal(Outcome.Floor, e1.Outcome);
    }

    // A class whose only candidates are possibly judged is Floor, even when every one of them passes in its worst case:
    // P0 and P1 present Network, P2's scan failed, nothing reaches (2 x (0 + 1) <= 2 seen). "Pass (may be judged)", class Floor.
    [Fact]
    public void E1_AClassWhoseOnlyCandidatesArePossiblyJudged_IsFloor()
    {
        using var dir = new TempDirectory();
        var failedScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", false, "load failed", 0, 0, []) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}",
            i < 2 ? Lib(presence: [(Capability.Network, 1)]) : i == 2 ? Lib() with { Presence = failedScan } : Lib())).ToArray();

        var e1 = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);
        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A")) with { Oracle = PresenceOracle.Parse(OracleText) }, results));

        var network = e1.Cells.Single(c => c.Capability == Capability.Network);
        Assert.True(network.PossiblyJudged);
        Assert.Equal(Outcome.Pass, network.Contribution);
        Assert.DoesNotContain(e1.Cells, c => c.Judged);
        Assert.Equal(Outcome.Floor, e1.Outcome);
        Assert.Equal(ReachabilityAggregation.NotComparable(new OracleComparison(false, true, 0, []), 0), ReachabilityCorpusReport.NotComparable(Context(Manifest(dir, "A")), results));
        Assert.Contains("not comparable", md);
    }

    // The rendering of possibly judged cells, on a comparable population: "Pass (may be judged)" or "Floor (may be judged)".
    // R2b: the cells are a runtime class's (TypeInitializer, Finalizer), since HostContract and LoadTime read "judged by
    // --combine" in a single run; R2 pinned the same two renderings on LoadTime and HostContract.
    [Fact]
    public void Report_RendersPossiblyJudgedCells()
    {
        using var dir = new TempDirectory();
        var failedScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", false, "load failed", 0, 0, []) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}",
            i < 2 ? Lib(presence: [(Capability.Network, 1)], reaches: i == 0 ? [Reach(RootClass.TypeInitializer, Capability.Network, 1)] : [])
            : i == 2 ? Lib() with { Presence = failedScan } : Lib())).ToArray();
        var manifestPath = Path.Combine(dir.Path, "ten.manifest");
        File.WriteAllLines(manifestPath, results.Select(r => $"{r.Id},{r.Version}"));
        var manifest = CorpusManifest.Load(manifestPath, 0);
        var oracle = PresenceOracle.Parse(string.Join("\n",
            [$"manifest-hash\t{manifest.Hash}", "denominator\t10", "assemblies\t9", "methods-analysed\t45", "total-findings\t2",
             .. Enum.GetValues<Capability>().Select(c => $"capability\t{c}\t{(c == Capability.Network ? 2 : 0)}\t{(c == Capability.Network ? 2 : 0)}"),
             .. results.Select((r, i) => $"package\t{r.Id}\t{r.Version}\tnet8.0\t{(i == 2 ? 0 : 1)}\t{(i == 2 ? 0 : 5)}\t{(i < 2 ? 1 : 0)}"),
             "package-capability\tP0\tNetwork\t1", "package-capability\tP1\tNetwork\t1"]));
        var context = Context(manifest) with { Oracle = oracle };

        Assert.Null(ReachabilityCorpusReport.NotComparable(context, results));
        var e1 = Section(string.Join("\n", ReachabilityCorpusReport.Markdown(context, results)), "## 3.", "## 4.");

        // TypeInitializer reaches from P0: 2 x (1 + 1) > 2 seen. Finalizer reaches nothing: its worst case passes. The
        // ChaOnly table's columns are LoadTime, HostContract (data, judged by --combine), then the runtime classes.
        Assert.Contains("| Network | 2/10 (20.0%) | 0/10 (0.0%) | 0/10 (0.0%) | judged by --combine | 0/10 (0.0%) | 0/10 (0.0%) | judged by --combine | " +
            "1/10 (10.0%) | 0/10 (0.0%) | Floor (may be judged) | 0/10 (0.0%) | 0/10 (0.0%) | Pass (may be judged) |", e1);
    }

    // A possibly judged cell never contributes Fail, however far its counted reach exceeds half of presence.
    [Fact]
    public void E1_APossiblyJudgedCell_NeverContributesFail()
    {
        var failedScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", false, "load failed", 0, 0, []) };
        var reach = new[] { Reach(RootClass.LoadTime, Capability.Network, 1) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}",
            i < 2 ? Lib(presence: [(Capability.Network, 1)], reaches: reach)
            : i == 2 ? Lib() with { Presence = failedScan }
            : Lib(reaches: i < 7 ? reach : []))).ToArray();

        var e1 = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);

        var network = e1.Cells.Single(c => c.Capability == Capability.Network);
        Assert.True(network.PossiblyJudged);
        Assert.Equal(Outcome.Fail, network.Outcome);
        Assert.Equal(Outcome.Floor, network.Contribution);
        Assert.Equal(Outcome.Floor, e1.Outcome);
    }

    // A cell under the gate even in its best case is "too rare to judge" and contributes nothing.
    [Fact]
    public void E1_ACellUnderTheGateEvenInItsBestCase_ContributesNothing()
    {
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", Lib(presence: i < 2 ? [(Capability.Network, 1)] : []))).ToArray();

        var cell = ReachabilityAggregation.E1(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime).Cells.Single(c => c.Capability == Capability.Network);

        Assert.False(cell.Judged);
        Assert.False(cell.PossiblyJudged);
        Assert.Null(cell.Contribution);
    }

    // Spec, round 3: an assembly presence scanned only partly (MethodsSkipped > 0) makes its package a floor package, and
    // counts like an unmeasured scan in the best case. P0-P3 present Network, P0-P2 reach it (2 x 3 > 4 counted); P4 and P5
    // were scanned with skipped methods, so the best case is 2 x 3 <= 6 (no Fail) and the worst 2 x 5 > 4 (no Pass). Floor.
    [Fact]
    public void E1_APartialPresenceScan_IsAFloorPackage_CountedLikeAnUnmeasuredScan()
    {
        var partialScan = new[] { new AssemblyPresence("lib/net8.0/a.dll", true, null, 5, 2, []) };
        var results = Enumerable.Range(0, 10).Select(i => Package($"P{i}", i is 4 or 5
            ? Lib() with { Presence = partialScan }
            : Lib(presence: i < 4 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();
        var plib = ReachabilityAggregation.View(results, Population.Plib);

        var cell = ReachabilityAggregation.E1(plib, RootClass.LoadTime).Cells.Single(c => c.Capability == Capability.Network);

        Assert.Equal(["lib/net8.0/a.dll"], results[4].Folders[0].PresencePartial);
        Assert.Empty(results[4].Folders[0].PresenceUnmeasured);
        Assert.All(plib.Units.Where(u => u.Id is "P4" or "P5"), u => Assert.True(u.Floor && u.PresenceFloor));
        Assert.Equal(new Share(4, 10), cell.Presence);
        Assert.Equal(6, cell.PresenceBest);
        Assert.Equal(2, cell.FloorPackages);
        Assert.Equal(Outcome.Floor, cell.Outcome);
    }

    // W1-r3: section 12 tells a graph-failed P-lib folder (a floor package, still in P-lib) from one neither side read.
    [Fact]
    public void Coverage_TellsAGraphFailedPlibFolder_FromOneNeitherSideRead()
    {
        using var dir = new TempDirectory();
        var graphFailed = Lib() with { GraphBuilt = false, Assemblies = [] };
        var unread = graphFailed with { Presence = [new AssemblyPresence("lib/net8.0/a.dll", false, "load failed", 0, 0, [])] };
        var a = PackageReachResult.From(Entry("A"), new ChildPayload("net8.0", ["net8.0"], [graphFailed], PackageCost.None), identity, 1);
        var b = PackageReachResult.From(Entry("B"), new ChildPayload("net8.0", ["net8.0"], [unread, Folder("tools/net8.0", "tools")], PackageCost.None), identity, 1);

        var coverage = Section(string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A", "B")), [a, b])) + "\n## end", "## 12.", "## end");

        Assert.Equal(["A"], ReachabilityAggregation.View([a, b], Population.Plib).Units.Select(u => u.Id));
        Assert.Contains("| A | 1.0.0 | lib/net8.0 | P-lib folder graph-failed (floor package) |", coverage);
        Assert.Contains("| B | 1.0.0 | lib/net8.0 | lib TFM chosen, but no P-lib folder either side read\\: the package is outside P-lib |", coverage);
        Assert.DoesNotContain("| A | 1.0.0 | lib/net8.0 | lib TFM chosen", coverage);
    }

    // N-a: -dirty also when git status lists anything under src/, ext/ or tests/ (untracked included), or cannot be read.
    [Theory]
    [InlineData("abc", "", "abc")]
    [InlineData("abc", "  \n", "abc")]
    [InlineData("abc", "?? tests/new.cs\n", "abc-dirty")]
    [InlineData("abc", " M src/x.cs\n", "abc-dirty")]
    [InlineData("abc-dirty", "?? tests/new.cs\n", "abc-dirty")]
    [InlineData("abc-dirty", "", "abc-dirty")]
    [InlineData("abc", null, "abc-dirty")]
    public void WithUntracked_AddsDirtyOnceForAnyListedPath(string described, string? porcelain, string expected)
    {
        Assert.Equal(expected, BuildIdentities.WithUntracked(described, porcelain));
    }

    // N-d: the commit goes in a code span, where backslash escapes do not work, so it is reduced to [0-9a-f-] plus -dirty.
    [Theory]
    [InlineData("c9d7f76d40fe1bd018f9ae41b8443d2906a955e8", "c9d7f76d40fe1bd018f9ae41b8443d2906a955e8")]
    [InlineData("c9d7f76d40fe1bd018f9ae41b8443d2906a955e8-dirty", "c9d7f76d40fe1bd018f9ae41b8443d2906a955e8-dirty")]
    [InlineData("abc`|x\\ <img>-dirty", "abc-dirty")]
    [InlineData("unknown", "unknown")]
    [InlineData("`", "unknown")]
    public void SafeCommit_KeepsOnlyHexDashesAndDirty(string commit, string expected)
    {
        Assert.Equal(expected, ReachabilityCorpusReport.SafeCommit(commit));
    }

    // N-b: the cost distribution counts graph-failed children too.
    [Fact]
    public void Cost_CountsGraphFailedChildren()
    {
        using var dir = new TempDirectory();
        var failed = Folder("build", "build") with { GraphBuilt = false, Assemblies = [] };
        var result = PackageReachResult.From(Entry("A"), new ChildPayload(null, [], [failed], PackageCost.None with { PeakWorkingSetBytes = 1 << 20 }), identity, 1);

        var cost = ReachabilityCorpusReport.Cost(Context(Manifest(dir, "A")), [result]);

        Assert.Equal(PackageReachResult.GraphFailed, result.Status);
        Assert.Contains("| Peak working set per child (MB) | 1 | 1.0 | 1.0 | 1.0 |", cost);
    }

    // ---------------------------------------------------------------------------------------------------
    // Unmeasured floor packages: crashed, timeout, incomplete (R2 "Known instrument limitation")
    // ---------------------------------------------------------------------------------------------------

    // (a) A crashed, timed-out or incomplete package whose .nupkg has a lib TFM is a floor package, with no folders and
    // unmeasured presence, in P-lib and P-all, and in both denominators. It survives the --results JSON round trip.
    [Theory]
    [InlineData(PackageReachResult.Crashed)]
    [InlineData(PackageReachResult.Timeout)]
    [InlineData(PackageReachResult.Incomplete)]
    public void View_AnUnmeasuredPackageWithALibTfm_IsAFloorInBothPopulations_AndInBothDenominators(string status)
    {
        var results = new[]
        {
            Package("A", Lib(presence: [(Capability.Network, 1)])),
            Package("B", Folder("build", "build")),
            PackageReachResult.FromJson(Unmeasured("C", status, "lib/net8.0/c.dll", "build/c.dll").ToJson()),
        };

        var plib = ReachabilityAggregation.View(results, Population.Plib);
        var pall = ReachabilityAggregation.View(results, Population.Pall);

        Assert.Equal("net8.0", results[2].LibTfm);
        Assert.Equal(["A", "C"], plib.Units.Select(u => u.Id));
        Assert.Equal(["A", "B", "C"], pall.Units.Select(u => u.Id));
        Assert.Equal(new Share(1, 2), ReachabilityAggregation.Presence(plib, Capability.Network));
        Assert.Equal(new Share(1, 3), ReachabilityAggregation.Presence(pall, Capability.Network));
        Assert.All(new[] { plib.Units[1], pall.Units[2] }, u =>
        {
            Assert.True(u.Floor);
            Assert.True(u.PresenceFloor);
            Assert.True(u.ProfileFloor(RootClass.HostContract));
            Assert.Empty(u.Folders);
        });
    }

    // (b) Without a lib TFM (TfmSelection over its file list finds none) it is a floor in P-all only.
    [Theory]
    [InlineData(PackageReachResult.Crashed)]
    [InlineData(PackageReachResult.Timeout)]
    [InlineData(PackageReachResult.Incomplete)]
    public void View_AnUnmeasuredPackageWithNoLibTfm_IsAFloorInPallOnly(string status)
    {
        var results = new[]
        {
            Package("A", Lib()),
            Unmeasured("C", status, "build/c.dll", "tools/net462/c.dll", "lib/net8.0-windows/c.dll"),
        };

        var plib = ReachabilityAggregation.View(results, Population.Plib);
        var pall = ReachabilityAggregation.View(results, Population.Pall);

        Assert.Null(results[1].LibTfm);
        Assert.Equal(["A"], plib.Units.Select(u => u.Id));
        Assert.Equal(["A", "C"], pall.Units.Select(u => u.Id));
        Assert.True(pall.Units[1].Floor);
    }

    // Which roles an unmeasured package holds was not measured, so no role table counts it.
    [Fact]
    public void View_ByRole_LeavesOutUnmeasuredPackages()
    {
        var results = new[] { Package("A", Lib()), Unmeasured("C", PackageReachResult.Crashed, "lib/net8.0/c.dll", "build/c.dll") };

        Assert.Equal(["A"], ReachabilityAggregation.View(results, Population.Pall, "lib").Units.Select(u => u.Id));
        Assert.Empty(ReachabilityAggregation.View(results, Population.Pall, "build").Units);
        Assert.Equal(["lib"], ReachabilityAggregation.Roles(results));
    }

    // (c) 9 packages, `presence` of them present Network and `reach` reach it from LoadTime; a 10th crashed with a lib TFM.
    // It counts in E1's favour for Fail (best-case presence + 1) and against it for Pass (one more reaching package, against
    // presence seen): a Pass without room for it becomes Floor, a Pass with room stays Pass, a Fail that holds even in E1's
    // favour stays Fail, and a Fail that does not becomes Floor. Both populations alike.
    [Theory]
    [InlineData(6, 3, Outcome.Pass, Outcome.Floor)] // 2 x 3 <= 6; with it, 2 x 4 > 6 seen and 2 x 3 <= 7 best
    [InlineData(6, 1, Outcome.Pass, Outcome.Pass)]  // 2 x (1 + 1) <= 6
    [InlineData(6, 4, Outcome.Fail, Outcome.Fail)]  // 2 x 4 > 7 best
    [InlineData(7, 4, Outcome.Fail, Outcome.Floor)] // 2 x 4 > 7; with it, 2 x 4 <= 8 best and 2 x 5 > 7 seen
    public void E1_ACrashedPackage_CountsInE1sFavourForFail_AndAgainstItForPass(int presence, int reach, Outcome without, Outcome with)
    {
        var measured = Enumerable.Range(0, 9).Select(i => Package($"P{i}", Lib(
            presence: i < presence ? [(Capability.Network, 1)] : [],
            reaches: i < reach ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();
        PackageReachResult[] withCrash = [.. measured, Unmeasured("P9", PackageReachResult.Crashed, "lib/net8.0/p.dll")];

        foreach (var population in new[] { Population.Plib, Population.Pall })
        {
            var view = ReachabilityAggregation.View(withCrash, population);
            var cell = ReachabilityAggregation.E1(view, RootClass.LoadTime).Cells.Single(c => c.Capability == Capability.Network);

            Assert.Equal(without, ReachabilityAggregation.E1(ReachabilityAggregation.View(measured, population), RootClass.LoadTime).Outcome);
            Assert.Equal(10, view.Denominator);
            Assert.Equal(new Share(presence, 10), cell.Presence);
            Assert.Equal(presence + 1, cell.PresenceBest);
            Assert.Equal(presence, cell.PresenceSeen);
            Assert.Equal(1, cell.FloorPackages);
            Assert.Equal(with, ReachabilityAggregation.E1(view, RootClass.LoadTime).Outcome);
        }
    }

    // (c) for E2: `count` measured packages, `composed` of them with a >= 2-signal HostContract profile, and one more
    // crashed (denominator count + 1): counted against a Pass (10 x (composed + 1) <= count + 1), never toward a Fail
    // (10 x composed > count + 1). The last row is a Fail without the crash (10 > 9) that only the larger denominator
    // undoes (10 <= 10), and the floor package then blocks the Pass (20 > 10): Floor.
    [Theory]
    [InlineData(10, 1, Outcome.Pass, Outcome.Floor)]
    [InlineData(10, 0, Outcome.Pass, Outcome.Pass)]
    [InlineData(10, 2, Outcome.Fail, Outcome.Fail)]
    [InlineData(9, 1, Outcome.Fail, Outcome.Floor)]
    public void E2_ACrashedPackage_IsCountedAgainstAPass_AndNeverTowardAFail(int count, int composed, Outcome without, Outcome with)
    {
        var measured = Enumerable.Range(0, count).Select(i => Package($"P{i}", Lib(
            profiles: i < composed ? [Profile(RootClass.HostContract, [Capability.FileSystem, Capability.Network])] : []))).ToArray();
        PackageReachResult[] withCrash = [.. measured, Unmeasured($"P{count}", PackageReachResult.Crashed, "lib/net8.0/p.dll")];

        foreach (var population in new[] { Population.Plib, Population.Pall })
        {
            var e2 = ReachabilityAggregation.E2(ReachabilityAggregation.View(withCrash, population), RootClass.HostContract);

            Assert.Equal(without, ReachabilityAggregation.E2(ReachabilityAggregation.View(measured, population), RootClass.HostContract).Outcome);
            Assert.Equal(new Share(composed, count + 1), e2.Inclusive);
            Assert.Equal(1, e2.FloorPackages);
            Assert.Equal(0, e2.TruncatedPackages);
            Assert.Equal(with, e2.Outcome);
        }
    }

    // The floor-aware judged gate: 2 of 9 present Network (too rare), but a crashed 10th could be a third, so the cell is
    // possibly judged. Its worst case passes (2 x (0 + 1) <= 2), but a class whose only candidates are possibly judged is
    // Floor, not "nothing judged".
    [Fact]
    public void E1_ACrashedPackage_CanMakeACellPossiblyJudged_AndTheClassFloor()
    {
        var measured = Enumerable.Range(0, 9).Select(i => Package($"P{i}", Lib(presence: i < 2 ? [(Capability.Network, 1)] : []))).ToArray();
        PackageReachResult[] withCrash = [.. measured, Unmeasured("P9", PackageReachResult.Crashed, "lib/net8.0/p.dll")];

        var e1 = ReachabilityAggregation.E1(ReachabilityAggregation.View(withCrash, Population.Plib), RootClass.LoadTime);

        Assert.Equal(Outcome.NothingJudged, ReachabilityAggregation.E1(ReachabilityAggregation.View(measured, Population.Plib), RootClass.LoadTime).Outcome);
        var network = e1.Cells.Single(c => c.Capability == Capability.Network);
        Assert.False(network.Judged);
        Assert.Equal(3, network.PresenceBest);
        Assert.True(network.PossiblyJudged);
        Assert.Equal(Outcome.Pass, network.Contribution);
        Assert.Equal(Outcome.Floor, e1.Outcome);
    }

    // A class with no roots in the measured packages is Floor, not "no data", when a crashed package might hold some (the
    // R2 write-up: "LoadTime would read Floor instead of no data").
    [Fact]
    public void E1AndE2_WithZeroRootsAndACrashedPackage_AreFloor_NotNoData()
    {
        var measured = Enumerable.Range(0, 5).Select(i => Package($"P{i}", Lib(presence: [(Capability.Network, 1)], roots: Roots(loadTime: 0)))).ToArray();
        PackageReachResult[] withCrash = [.. measured, Unmeasured("P5", PackageReachResult.Crashed, "build/p.dll")];
        var pall = ReachabilityAggregation.View(withCrash, Population.Pall);
        var plib = ReachabilityAggregation.View(withCrash, Population.Plib);

        Assert.Equal(Outcome.NoData, ReachabilityAggregation.E1(ReachabilityAggregation.View(measured, Population.Pall), RootClass.LoadTime).Outcome);
        Assert.Equal(Outcome.Floor, ReachabilityAggregation.E1(pall, RootClass.LoadTime).Outcome);
        Assert.Equal(Outcome.Floor, ReachabilityAggregation.E2(pall, RootClass.LoadTime).Outcome);
        // No lib TFM: P-lib is untouched, still "no data" there.
        Assert.Equal(Outcome.NoData, ReachabilityAggregation.E1(plib, RootClass.LoadTime).Outcome);
        Assert.Equal(ClassVerdict.UndecidedFloor, ReachabilityAggregation.Verdicts(plib, pall).Single(v => v.Class == RootClass.LoadTime).Verdict);
    }

    // (d) Timeout and incomplete behave exactly like crashed: the same units, cells, outcomes and verdicts.
    [Theory]
    [InlineData(PackageReachResult.Timeout)]
    [InlineData(PackageReachResult.Incomplete)]
    public void TimeoutAndIncomplete_AggregateExactlyLikeCrashed(string status)
    {
        PackageReachResult[] Corpus(string s) =>
        [
            .. Enumerable.Range(0, 9).Select(i => Package($"P{i}", Lib(
                presence: i < 6 ? [(Capability.Network, 1)] : [],
                reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : [],
                profiles: i < 1 ? [Profile(RootClass.LoadTime, [Capability.FileSystem, Capability.Network])] : []))),
            Unmeasured("P9", s, "lib/net8.0/p.dll"),
            Unmeasured("P10", s, "build/p.dll"),
        ];
        var crashed = Corpus(PackageReachResult.Crashed);
        var other = Corpus(status);

        foreach (var population in new[] { Population.Plib, Population.Pall })
        {
            var (c, o) = (ReachabilityAggregation.View(crashed, population), ReachabilityAggregation.View(other, population));
            Assert.Equal(c.Units.Select(u => (u.Id, u.Floor, u.PresenceFloor)), o.Units.Select(u => (u.Id, u.Floor, u.PresenceFloor)));
            foreach (var k in ReachabilityChild.TriggerClasses)
            {
                Assert.Equal(ReachabilityAggregation.E1(c, k).Cells, ReachabilityAggregation.E1(o, k).Cells);
                Assert.Equal(ReachabilityAggregation.E1(c, k).Outcome, ReachabilityAggregation.E1(o, k).Outcome);
                Assert.Equal(ReachabilityAggregation.E2(c, k), ReachabilityAggregation.E2(o, k));
            }
        }
        Assert.Equal(Outcome.Floor, ReachabilityAggregation.E1(ReachabilityAggregation.View(other, Population.Plib), RootClass.LoadTime).Outcome);
        Assert.Equal(
            ReachabilityAggregation.Verdicts(ReachabilityAggregation.View(crashed, Population.Plib), ReachabilityAggregation.View(crashed, Population.Pall)),
            ReachabilityAggregation.Verdicts(ReachabilityAggregation.View(other, Population.Plib), ReachabilityAggregation.View(other, Population.Pall)));
    }

    // (e) no-assemblies is not a floor, even with a lib TFM (a native binary in lib/net8.0): in no population, no floor
    // package in any cell. not-cached is not a floor either; it still makes the run not comparable.
    [Fact]
    public void NoAssembliesAndNotCached_AreStillNotFloors()
    {
        using var dir = new TempDirectory();
        var native = Lib() with
        {
            GraphBuilt = false, Assemblies = [], LoadFailures = [new LoadFailureRecord("lib/net8.0/a.dll", "not a managed assembly")],
            Presence = [new AssemblyPresence("lib/net8.0/a.dll", false, "not a managed assembly", 0, 0, [])],
        };
        var noAssemblies = PackageReachResult.From(Entry("N"), new ChildPayload("net8.0", ["net8.0"], [native], PackageCost.None), identity, 1);
        var notCached = PackageReachResult.Without(Entry("M"), PackageReachResult.NotCached, "no M.1.0.0.nupkg in the cache", null, identity);
        var measured = Enumerable.Range(0, 9).Select(i => Package($"P{i}", Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();
        PackageReachResult[] results = [.. measured, noAssemblies, notCached];

        Assert.Equal(PackageReachResult.NoAssemblies, noAssemblies.Status);
        Assert.False(noAssemblies.UnmeasuredFloor);
        Assert.False(notCached.UnmeasuredFloor);
        foreach (var population in new[] { Population.Plib, Population.Pall })
        {
            var view = ReachabilityAggregation.View(results, population);
            Assert.Equal(9, view.Denominator);
            Assert.DoesNotContain(view.Units, u => u.Floor);
            Assert.Equal(Outcome.Pass, ReachabilityAggregation.E1(view, RootClass.LoadTime).Outcome);
        }
        var coverage = Section(string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A")), results)) + "\n## end", "## 12.", "## end");
        Assert.DoesNotContain("floor package, presence and reach unmeasured", coverage);
        Assert.Contains("not-cached 1", ReachabilityCorpusReport.NotComparable(Context(Manifest(dir, "A")), results));
    }

    // Coverage honesty: section 12 names each unmeasured floor package, its status and the populations it is a floor in;
    // section 1 counts them; the E1 headings count them as floor packages.
    [Fact]
    public void Report_NamesEachUnmeasuredFloorPackage_AndItsStatus()
    {
        using var dir = new TempDirectory();
        var results = new[]
        {
            Package("A", Lib()),
            Unmeasured("C", PackageReachResult.Crashed, "lib/net8.0/c.dll"),
            Unmeasured("I", PackageReachResult.Incomplete, "lib/netstandard2.0/i.dll", "build/i.dll"),
            Unmeasured("T", PackageReachResult.Timeout, "build/t.dll"),
        };

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A", "C", "I", "T")), results));
        var coverage = Section(md + "\n## end", "## 12.", "## end");

        Assert.Contains("| C | 1.0.0 | lib/net8.0 | crashed\\: boom; floor package, presence and reach unmeasured (E1 and E2 floor package)\\: in P-all and P-lib |", coverage);
        Assert.Contains("| I | 1.0.0 | lib/netstandard2.0 | incomplete\\: boom; floor package, presence and reach unmeasured (E1 and E2 floor package)\\: in P-all and P-lib |", coverage);
        Assert.Contains("| T | 1.0.0 | - | timeout\\: boom; floor package, presence and reach unmeasured (E1 and E2 floor package)\\: in P-all; " +
            "not in P-lib, TfmSelection over the .nupkg finds no lib TFM |", coverage);
        Assert.Contains("(a lib TFM by `TfmSelection` over the `.nupkg`, or unknown) | 3 / 2 |", md);
        Assert.Contains("### P-lib (denominator 3; floor packages 2)", md);
        Assert.Contains("### P-all (denominator 4; floor packages 3)", md);
    }

    // A crashed P-lib package of the baseline cannot reproduce its presence: the oracle mismatches and names it.
    [Fact]
    public void Oracle_WhenABaselinePackageCrashed_MismatchesAndNamesIt()
    {
        var results = OracleResults();
        results[1] = Unmeasured("B", PackageReachResult.Crashed, "lib/net8.0/b.dll") with { Version = "2.0.0" };

        var comparison = ReachabilityAggregation.CompareOracle(PresenceOracle.Parse(OracleText), ReachabilityAggregation.View(results, Population.Plib), OracleHash);

        Assert.False(comparison.Match);
        Assert.Contains("B 2.0.0: crashed, presence not measured", comparison.Differences);
        Assert.DoesNotContain("B 2.0.0: in the baseline, not in P-lib", comparison.Differences);
    }

    // The runner reads the lib TFM of an unmeasured package from the .nupkg's file list (TfmSelection, the P-lib rule).
    [Fact]
    public void WithLibTfm_AnUnmeasuredResult_TakesTheLibTfmTfmSelectionPicksOverTheNupkg()
    {
        using var withLib = new TempDirectory();
        using var withoutLib = new TempDirectory();
        var lib = SyntheticPackage(withLib, ShadowFixtureAssembly.Path, "lib/net8.0/Shadow.dll", "lib/netstandard2.0/Shadow.dll", "build/Shadow.dll");
        var buildOnly = SyntheticPackage(withoutLib, ShadowFixtureAssembly.Path, "build/Shadow.dll", "tools/net462/Shadow.dll");
        var crashed = PackageReachResult.Without(Entry("Synthetic"), PackageReachResult.Crashed, "child exited 35", 35, identity);

        var a = ReachabilityChildRunner.WithLibTfm(crashed, lib);
        var b = ReachabilityChildRunner.WithLibTfm(crashed with { Status = PackageReachResult.Timeout }, buildOnly);

        Assert.Equal("net8.0", a.LibTfm);
        Assert.Equal(["net8.0", "netstandard2.0"], a.LibTfms);
        Assert.Equal("child exited 35", a.Detail);
        Assert.Null(b.LibTfm);
        Assert.Empty(b.LibTfms);
    }

    // Only unmeasured results are touched; an unreadable archive marks the lib TFM unknown and says so. A readable one
    // sets the state to chosen or none.
    [Fact]
    public void WithLibTfm_LeavesOtherResultsAlone_AndNamesAnUnreadableArchive()
    {
        using var dir = new TempDirectory();
        var bogus = Path.Combine(dir.Path, "bogus.nupkg");
        File.WriteAllText(bogus, "not a real package");
        var scanned = Package("A", Lib()) with { LibTfm = null };
        var noAssemblies = PackageReachResult.From(Entry("N"), new ChildPayload(null, [], [], PackageCost.None), identity, 1);

        var unreadable = ReachabilityChildRunner.WithLibTfm(PackageReachResult.Without(Entry("A"), PackageReachResult.Incomplete, "cut short", 0, identity), bogus);

        Assert.Same(scanned, ReachabilityChildRunner.WithLibTfm(scanned, bogus));
        Assert.Same(noAssemblies, ReachabilityChildRunner.WithLibTfm(noAssemblies, bogus));
        Assert.Null(unreadable.LibTfm);
        Assert.True(unreadable.LibTfmUnknown);
        Assert.Equal(LibTfmState.Unknown, unreadable.LibTfmState);
        Assert.StartsWith("cut short; lib TFM unknown, the .nupkg file list is unreadable (", unreadable.Detail);
        Assert.Equal(LibTfmState.Chosen, Unmeasured("C", PackageReachResult.Crashed, "lib/net8.0/c.dll").LibTfmState);
        Assert.Equal(LibTfmState.None, Unmeasured("C", PackageReachResult.Crashed, "build/c.dll").LibTfmState);
    }

    // Call 4, the cautious option: when the parent cannot read the .nupkg's file list, whether the package has a lib TFM
    // is unknown, so it is a floor in P-lib as well as P-all (leaving it out of P-lib's denominator would be the optimistic
    // direction). It survives the --results JSON round trip, moves a P-lib Pass to Floor, and section 12 says why.
    [Theory]
    [InlineData(PackageReachResult.Crashed)]
    [InlineData(PackageReachResult.Timeout)]
    [InlineData(PackageReachResult.Incomplete)]
    public void View_AnUnmeasuredPackageWithAnUnreadableNupkg_IsAFloorInBothPopulations(string status)
    {
        using var dir = new TempDirectory();
        var bogus = Path.Combine(dir.Path, "bogus.nupkg");
        File.WriteAllText(bogus, "not a real package");
        var unreadable = PackageReachResult.FromJson(ReachabilityChildRunner.WithLibTfm(
            PackageReachResult.Without(Entry("U"), status, "boom", null, identity), bogus).ToJson());
        // 9 P-lib packages: 6 present Network, 3 reach it. 2 x 3 <= 6 passes; with U counted against it, 2 x 4 > 6.
        var measured = Enumerable.Range(0, 9).Select(i => Package($"P{i}", Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [], reaches: i < 3 ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray();
        PackageReachResult[] results = [.. measured, unreadable];

        var plib = ReachabilityAggregation.View(results, Population.Plib);
        var pall = ReachabilityAggregation.View(results, Population.Pall);

        Assert.Equal(LibTfmState.Unknown, unreadable.LibTfmState);
        Assert.Equal(10, plib.Denominator);
        Assert.Equal(10, pall.Denominator);
        Assert.All(new[] { plib.Units.Single(u => u.Id == "U"), pall.Units.Single(u => u.Id == "U") }, u =>
        {
            Assert.True(u.Floor);
            Assert.True(u.PresenceFloor);
            Assert.Empty(u.Folders);
        });
        Assert.Equal(Outcome.Pass, ReachabilityAggregation.E1(ReachabilityAggregation.View(measured, Population.Plib), RootClass.LoadTime).Outcome);
        Assert.Equal(Outcome.Floor, ReachabilityAggregation.E1(plib, RootClass.LoadTime).Outcome);
        Assert.DoesNotContain(ReachabilityAggregation.View(results, Population.Pall, "lib").Units, u => u.Id == "U");

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "U")), results));
        var coverage = Section(md + "\n## end", "## 12.", "## end");
        Assert.Contains($"| U | 1.0.0 | - | {status}\\: boom; lib TFM unknown, the .nupkg file list is unreadable (", coverage);
        Assert.Contains("; floor package, presence and reach unmeasured (E1 and E2 floor package)\\: in P-all and P-lib, since whether it has a lib TFM is unknown |", coverage);
        Assert.Contains("(a lib TFM by `TfmSelection` over the `.nupkg`, or unknown) | 1 / 1 |", md);
    }

    // S0 review W1: the cautious lib TFM state is structural. A crashed, timed-out or incomplete result starts Unknown (a
    // P-lib floor), whoever builds it; only reading the .nupkg (WithLibTfm) settles it to Chosen or None. Other statuses
    // start None.
    [Theory]
    [InlineData(PackageReachResult.Crashed, LibTfmState.Unknown)]
    [InlineData(PackageReachResult.Timeout, LibTfmState.Unknown)]
    [InlineData(PackageReachResult.Incomplete, LibTfmState.Unknown)]
    [InlineData(PackageReachResult.NotCached, LibTfmState.None)]
    public void Without_StartsAnUnmeasuredResultWithTheLibTfmUnknown(string status, LibTfmState expected)
    {
        var result = PackageReachResult.Without(Entry("A"), status, "boom", null, identity);
        string[] inPlib = expected == LibTfmState.Unknown ? ["A"] : [];

        Assert.Equal(expected, result.LibTfmState);
        Assert.Equal(inPlib, ReachabilityAggregation.View([result], Population.Plib).Units.Select(u => u.Id));
        Assert.Equal(LibTfmState.Chosen, result.WithLibTfm(TfmSelection.Choose(["lib/net8.0/a.dll"])).LibTfmState);
        Assert.Equal(LibTfmState.None, result.WithLibTfm(TfmSelection.Choose(["build/a.dll"])).LibTfmState);
    }

    // S0 review W1, end to end: ReachabilityChildRunner.Run against the real harness executable. The .nupkg has a lib TFM
    // and no .nuspec: the parent (and the child, first) can list it, but NuGetPackage.Open rejects it, so the child exits
    // non-zero. Crashed, with the lib TFM Chosen from the parent's own listing.
    [Fact]
    public void Run_AChildThatCannotOpenThePackage_IsCrashed_WithTheLibTfmChosen()
    {
        using var dir = new TempDirectory();
        var nupkg = Path.Combine(dir.Path, "NoNuspec.1.0.0.nupkg");
        using (var zip = ZipFile.Open(nupkg, ZipArchiveMode.Create))
            foreach (var path in new[] { "lib/net8.0/NoNuspec.dll", "lib/netstandard2.0/NoNuspec.dll", "build/NoNuspec.dll" })
                using (var writer = new StreamWriter(zip.CreateEntry(path).Open()))
                    writer.Write("not an assembly");
        var results = Directory.CreateDirectory(Path.Combine(dir.Path, "results")).FullName;
        var harness = Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.exe");

        var result = ReachabilityChildRunner.Run(harness, results, new ManifestEntry("NoNuspec", "1.0.0"), nupkg, TimeSpan.FromSeconds(120), identity);

        Assert.Equal(PackageReachResult.Crashed, result.Status);
        Assert.NotEqual(0, result.ExitCode);
        Assert.Equal(LibTfmState.Chosen, result.LibTfmState);
        Assert.Equal("net8.0", result.LibTfm);
        Assert.Equal(["net8.0", "netstandard2.0"], result.LibTfms);
        Assert.Empty(result.Folders);
        Assert.Equal(["NoNuspec"], ReachabilityAggregation.View([result], Population.Plib).Units.Select(u => u.Id));
        Assert.False(File.Exists(Path.Combine(results, "NoNuspec.1.0.0.child.json")));
    }

    // S0 review W2: any unmeasured package in P-lib makes the oracle a MISMATCH, whether the baseline holds it or not and
    // whether its lib TFM is chosen or unknown; so the P-lib floor branch never decides a verdict. One with no lib TFM
    // leaves the oracle alone.
    [Fact]
    public void Oracle_AnyUnmeasuredPlibPackage_MakesItMismatch_AndOneWithNoLibTfmDoesNot()
    {
        var oracle = PresenceOracle.Parse(OracleText);
        PackageReachResult[] With(PackageReachResult extra) => [.. OracleResults(), extra];
        var chosen = Unmeasured("X", PackageReachResult.Crashed, "lib/net8.0/x.dll");
        var unknown = PackageReachResult.Without(Entry("Y"), PackageReachResult.Timeout, "boom", null, identity);
        var none = Unmeasured("Z", PackageReachResult.Incomplete, "build/z.dll");

        OracleComparison Compare(PackageReachResult extra) => ReachabilityAggregation.CompareOracle(oracle, ReachabilityAggregation.View(With(extra), Population.Plib), OracleHash);

        Assert.False(Compare(chosen).Match);
        Assert.Contains("X 1.0.0: in P-lib, not in the baseline", Compare(chosen).Differences);
        Assert.False(Compare(unknown).Match);
        Assert.Contains("Y 1.0.0: in P-lib, not in the baseline", Compare(unknown).Differences);
        Assert.True(Compare(none).Match, string.Join(Environment.NewLine, Compare(none).Differences));
    }

    // S0 review W2: sections 2 and 3 say so plainly.
    [Fact]
    public void Report_SaysAnUnmeasuredPlibPackageMeansNoVerdict()
    {
        using var dir = new TempDirectory();
        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A")), [Package("A", Lib())]));

        Assert.Contains("has no measured presence, so it always makes the oracle\na MISMATCH, and the run then gives no verdict", Section(md, "## 2.", "## 3."));
        Assert.Contains("makes the regression oracle a MISMATCH (section 2), so no verdict is\ngiven at all", Section(md, "## 3.", "## 4."));
        Assert.Contains("only the P-all floors of packages with no lib TFM ever feed a\nverdict", Section(md, "## 3.", "## 4."));
    }

    // S0 review N1: Q4 counts an unmeasured package as Unknown for every class, with its own reason, beside the other
    // reasons.
    [Fact]
    public void Unknown_CountsAnUnmeasuredPackageAsUnknown_WithItsOwnReason()
    {
        var unknown = new VerdictRecord(RootClass.LoadTime, RootClassVerdict.Unknown, ["2 root(s) reach code the graph cannot see"], ["unseen"]);
        var results = new[]
        {
            Package("A", Lib(verdicts: [unknown])),
            Package("B", Lib(verdicts: [new VerdictRecord(RootClass.LoadTime, RootClassVerdict.None, [], [])])),
            Unmeasured("C", PackageReachResult.Crashed, "lib/net8.0/c.dll"),
            Unmeasured("D", PackageReachResult.Timeout, "build/d.dll"),
        };

        var plib = ReachabilityAggregation.Unknown(ReachabilityAggregation.View(results, Population.Plib), RootClass.LoadTime);
        var pall = ReachabilityAggregation.Unknown(ReachabilityAggregation.View(results, Population.Pall), RootClass.LoadTime);
        var hostContract = ReachabilityAggregation.Unknown(ReachabilityAggregation.View(results, Population.Pall), RootClass.HostContract);

        Assert.Equal(new Share(2, 3), plib.Unknown);
        Assert.Equal([new NamedCount("unmeasured (crashed/timeout/incomplete)", 1), new NamedCount("unseen", 1)], plib.Reasons);
        Assert.Equal(new Share(3, 4), pall.Unknown);
        Assert.Equal([new NamedCount(ReachabilityAggregation.UnmeasuredReason, 2), new NamedCount("unseen", 1)], pall.Reasons);
        Assert.Equal(new Share(2, 4), hostContract.Unknown);
        Assert.Equal([new NamedCount(ReachabilityAggregation.UnmeasuredReason, 2)], hostContract.Reasons);
    }

    // S0 review N1: the section 5 matrix and the Q2 tables print the unmeasured count beside the denominator; the shares
    // themselves are unchanged (over the full denominator, the unmeasured package contributing nothing).
    [Fact]
    public void Report_PrintsTheUnmeasuredCountBesideTheMatrixAndQ2Denominators()
    {
        using var dir = new TempDirectory();
        var results = new[]
        {
            Package("A", Lib(presence: [(Capability.Network, 1)], reaches: [Reach(RootClass.PublicApi, Capability.Network, 1)])),
            Package("B", Lib()),
            Unmeasured("C", PackageReachResult.Crashed, "lib/net8.0/c.dll"),
            Unmeasured("D", PackageReachResult.Incomplete, "build/d.dll"),
        };

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(Context(Manifest(dir, "A", "B", "C", "D")), results));
        var matrix = Section(md, "## 5.", "## 6.");
        var q2 = Section(md, "## 6.", "## 7.");

        Assert.Equal(1, ReachabilityAggregation.View(results, Population.Plib).Unmeasured);
        Assert.Contains("### P-lib - ChaOnly (denominator 3; unmeasured 1)", matrix);
        Assert.Contains("### P-all - Bound (denominator 4; unmeasured 2)", matrix);
        Assert.Contains("### P-all, role lib - ChaOnly (denominator 2; unmeasured 0)", matrix);
        Assert.Contains("### P-lib (denominator 3; unmeasured 1; ", q2);
        Assert.Contains("### P-all (denominator 4; unmeasured 2; ", q2);
        Assert.Contains("| Network | 1/3 (33.3%) | ", q2);
        Assert.Contains("| Network | 1/4 (25.0%) | ", q2);
    }

    // ---------------------------------------------------------------------------------------------------
    // W2: no verdict without a comparable population
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void NotComparable_NamesEachReason_AndIsNullOnlyForAFullMatchWithNothingMissing()
    {
        Assert.Null(ReachabilityAggregation.NotComparable(new OracleComparison(true, true, 78, []), 0));
        Assert.Equal("not comparable (oracle not applicable: another manifest)", ReachabilityAggregation.NotComparable(new OracleComparison(false, true, 2, []), 0));
        Assert.Equal("not comparable (oracle MISMATCH)", ReachabilityAggregation.NotComparable(new OracleComparison(true, false, 78, ["x"]), 0));
        Assert.Equal("not comparable (oracle MISMATCH; not-cached 2)", ReachabilityAggregation.NotComparable(new OracleComparison(true, false, 78, ["x"]), 2));
        Assert.Equal("not comparable (not-cached 1)", ReachabilityAggregation.NotComparable(new OracleComparison(true, true, 78, []), 1));
    }

    // The smoke-style case: a partial manifest. Every E1/E2 cell and verdict reads "not comparable"; no pass or fail is shown.
    [Fact]
    public void Report_OnAPartialManifest_RendersNoVerdict()
    {
        using var dir = new TempDirectory();
        var results = new[] { Package("A", Lib(presence: [(Capability.Network, 1)])) };

        var (paths, notComparable) = ReachabilityCorpusReport.Write(dir.Path, Context(Manifest(dir, "A")), results);
        var md = File.ReadAllText(paths[0]);
        var verdicts = Section(md, "## 3.", "## 5.");

        Assert.Equal("not comparable (oracle not applicable: another manifest)", notComparable);
        Assert.Contains("not comparable (oracle not applicable: another manifest)", verdicts);
        Assert.DoesNotContain("| pass |", verdicts);
        Assert.DoesNotContain("FAIL", verdicts);
        Assert.DoesNotContain(ClassVerdict.Undecided, verdicts);
        Assert.DoesNotContain("too rare to judge", verdicts);
    }

    // A full MATCH with nothing missing renders the verdicts.
    [Fact]
    public void Report_OnAComparablePopulation_RendersVerdicts()
    {
        using var dir = new TempDirectory();
        var manifestPath = Path.Combine(dir.Path, "oracle.manifest");
        File.WriteAllLines(manifestPath, ["A,1.0.0", "B,2.0.0"]);
        var manifest = CorpusManifest.Load(manifestPath, 0);
        var context = Context(manifest) with { Oracle = PresenceOracle.Parse(OracleText.Replace(OracleHash, manifest.Hash, StringComparison.Ordinal)) };

        var md = string.Join("\n", ReachabilityCorpusReport.Markdown(context, OracleResults()));

        Assert.Null(ReachabilityCorpusReport.NotComparable(context, OracleResults()));
        Assert.Contains("**The population is comparable:**", md);
        Assert.DoesNotContain("not comparable (", Section(md, "## 3.", "## 5."));
    }

    // End to end: the harness writes its report and exits 3 when the population is not comparable. 26 entries, none
    // cached, so no child runs and nothing is fetched; --take defaults to 0 here, so all 26 are in the manifest (N1).
    [Fact]
    public async Task Harness_WhenNotComparable_WritesTheReportAndExitsThree()
    {
        using var dir = new TempDirectory();
        var manifest = Path.Combine(dir.Path, "missing.manifest");
        File.WriteAllLines(manifest, Enumerable.Range(0, 26).Select(i => $"Silvergun.R2Test.NotCached{i:D2},0.0.1"));
        var cache = Directory.CreateDirectory(Path.Combine(dir.Path, "cache")).FullName;
        var output = Path.Combine(dir.Path, "out");

        var psi = new System.Diagnostics.ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.exe"))
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
        };
        foreach (var arg in new[] { "--reachability", "--manifest", manifest, "--cache", cache, "--results", Path.Combine(dir.Path, "results"), "--out", output, "--date", "2026-11-05" })
            psi.ArgumentList.Add(arg);
        using var process = System.Diagnostics.Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "the harness did not finish");

        Assert.Equal(Program.NotComparableExitCode, process.ExitCode);
        Assert.Contains("NOT-COMPARABLE not comparable (oracle not applicable: another manifest; not-cached 26)", await stderr);
        var md = File.ReadAllText(Path.Combine(output, "reachability-benign-2026-11-05.md"));
        Assert.Contains("| Manifest entries | 26 |", md);
        Assert.Contains("0 / 0 / 0 / 0 / 0 / 0 / 26", md);
        Assert.Contains("COMPLETE 26 result(s)", await stdout);
    }

    // ---------------------------------------------------------------------------------------------------
    // W3: the duplicated rules, pinned against the library
    // ---------------------------------------------------------------------------------------------------

    // One own root with one opacity of each kind sited at it: Reachability gives an Unseen reach exactly for the kinds in
    // the harness's set.
    [Theory]
    [MemberData(nameof(OpacityKinds))]
    public void UnseenOpacityKinds_AreExactlyTheKindsReachabilityTreatsAsUnseen(OpacityKind kind)
    {
        var graph = MethodGraph.FromParts(
            [new MethodNode("App.Root()", "App.Root", MethodNodeKind.OwnWithBody)], [],
            [new GraphOpacity("App.Root()", 0, kind, "x")], completeCoverage,
            new GraphFacts([new OwnMethodFacts("App.Root()", "App.dll", "App", RootClass.PublicApi, false, true)], [], []));

        var unseen = Reachability.Analyze(graph).Reaches.Any(r => r.Capability is null);

        Assert.Equal(ReachabilityChild.UnseenOpacityKinds.Contains(kind), unseen);
    }

    public static TheoryData<OpacityKind> OpacityKinds()
    {
        var data = new TheoryData<OpacityKind>();
        foreach (var kind in Enum.GetValues<OpacityKind>())
            data.Add(kind);
        return data;
    }

    // An entry name NuGet unescapes: '%2F' in the folder and '%2E' in the TFM both name NuGet's lib/net10.0. The
    // extractor writes the raw name, so the graph's folder is the raw one, and the child must still mark it P-lib, with
    // the LibTfm TfmSelection gives over NuGet's own GetFiles.
    [Theory]
    [InlineData("lib%2Fnet10.0/Shadow.dll", "lib%2Fnet10.0")]
    [InlineData("lib/net10%2E0/Shadow.dll", "lib/net10%2E0")]
    [InlineData("lib/net10.0/Shadow.dll", "lib/net10.0")]
    public void Measure_APercentEncodedLibEntry_IsPlib_WithNuGetsTfm(string entry, string rawFolder)
    {
        using var dir = new TempDirectory();
        var nupkg = SyntheticPackage(dir, ShadowFixtureAssembly.Path, entry);
        string? nugetTfm;
        using (var reader = new global::NuGet.Packaging.PackageArchiveReader(nupkg))
            nugetTfm = TfmSelection.Choose(reader.GetFiles()).Tfm;

        var payload = ReachabilityChild.Measure(nupkg);

        Assert.Equal("net10.0", nugetTfm);
        Assert.Equal(nugetTfm, payload.LibTfm);
        var folder = Assert.Single(payload.Folders);
        Assert.Equal(rawFolder, folder.Folder);
        Assert.True(folder.IsPlib);
        Assert.Equal("lib", folder.Role);
        Assert.True(folder.GraphBuilt);
    }

    // ---------------------------------------------------------------------------------------------------
    // W4/N3: escaping
    // ---------------------------------------------------------------------------------------------------

    // A '\|' in a name cannot split a cell: the backslash is escaped first, then the pipe.
    [Fact]
    public void Escape_ABackslashPipe_CannotSplitACell()
    {
        var escaped = ReachabilityCorpusReport.Escape("a\\|b");

        Assert.Equal("a\\\\\\|b", escaped);
        Assert.Equal(1, escaped.Count(c => c == '|'));
        Assert.EndsWith("\\|b", escaped);
    }

    // Image and link syntax, and a scheme autolink, are neutralised.
    [Fact]
    public void Escape_AnImageBeacon_RendersNeitherAnImageNorALink()
    {
        var escaped = ReachabilityCorpusReport.Escape("![x](https://host/beacon) [y](z) a@b.c");

        Assert.Equal("\\!\\[x\\](https\\://host/beacon) \\[y\\](z) a\\@b.c", escaped);
        Assert.DoesNotContain("![", escaped);
        Assert.DoesNotContain("](", escaped.Replace("\\](", string.Empty, StringComparison.Ordinal));
        Assert.DoesNotContain("https://", escaped);
    }

    [Fact]
    public void Tab_NeutralisesSeparatorsAndHiddenCharacters()
    {
        Assert.Equal("a b c\\u{202e}d\\u{2066}e\\u{200b}f\\u{2028}g\\u{2029}h\\u{0085}i\\u{e0041}",
            ReachabilityCorpusReport.Tab(string.Concat("a\tb\rc", (char)0x202E, "d", (char)0x2066, "e", (char)0x200B, "f", (char)0x2028, "g",
                (char)0x2029, "h", (char)0x0085, "i", char.ConvertFromUtf32(0xE0041))));
    }

    // ---------------------------------------------------------------------------------------------------
    // W5, N2, N6
    // ---------------------------------------------------------------------------------------------------

    // The identity's commit is git describe --always --dirty --abbrev=40 of this checkout: a full commit (after a tag
    // description, when one exists), with -dirty when the tree has changes.
    [Fact]
    public void Describe_IsTheFullCommit_WithDirtyWhenTheTreeHasChanges()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !Directory.Exists(Path.Combine(root.FullName, ".git")) && !File.Exists(Path.Combine(root.FullName, ".git")))
            root = root.Parent;

        var described = BuildIdentities.Describe(root?.FullName ?? AppContext.BaseDirectory);

        Assert.Matches(@"^((.+-g)?[0-9a-f]{40}(-dirty)?|unknown)$", described);
    }

    [Fact]
    public void TimeoutMilliseconds_IsClampedBeforeTheIntConversion()
    {
        Assert.Equal(int.MaxValue, ReachabilityChildRunner.TimeoutMilliseconds(TimeSpan.MaxValue));
        Assert.Equal(int.MaxValue, ReachabilityChildRunner.TimeoutMilliseconds(TimeSpan.FromDays(30)));
        Assert.Equal(600_000, ReachabilityChildRunner.TimeoutMilliseconds(TimeSpan.FromSeconds(600)));
        Assert.Equal(1, ReachabilityChildRunner.TimeoutMilliseconds(TimeSpan.Zero));
        Assert.Equal(1, ReachabilityChildRunner.TimeoutMilliseconds(TimeSpan.FromSeconds(-5)));
    }

    // Only <temp>/silvergun/pkg-<12 of a-z0-9>, named on the child's EXTRACTION line, is ever a cleanup target.
    [Fact]
    public void ExtractionDirOf_AcceptsOnlyTheShapeNuGetPackageOpenCreates()
    {
        var parent = Path.Combine(Path.GetTempPath(), "silvergun");
        string Line(string path) => $"noise\nEXTRACTION\t{path}\r\nProcess terminated.";

        Assert.Equal(Path.Combine(parent, "pkg-abcdef012345"), ReachabilityChildRunner.ExtractionDirOf(Line(Path.Combine(parent, "pkg-abcdef012345"))));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf(Line(Path.Combine(Path.GetTempPath(), "other", "pkg-abcdef012345"))));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf(Line(Path.Combine(parent, "..", "pkg-abcdef012345"))));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf(Line(Path.Combine(parent, "pkg-ABCDEF012345"))));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf(Line(Path.Combine(parent, "pkg-abc"))));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf(Line(parent)));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf(Line("silvergun\\pkg-abcdef012345")));
        Assert.Null(ReachabilityChildRunner.ExtractionDirOf("no marker at all"));
    }

    // A dead child's extraction is removed exactly: its sibling stays.
    [Fact]
    public void RemoveExtraction_DeletesExactlyTheNamedDirectory()
    {
        string Fresh() => Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun", "pkg-" + Guid.NewGuid().ToString("N")[..12])).FullName;
        var named = Fresh();
        var sibling = Fresh();
        File.WriteAllText(Path.Combine(named, "x.dll"), "x");
        try
        {
            ReachabilityChildRunner.RemoveExtraction($"EXTRACTION\t{named}\nProcess terminated.");

            Assert.False(Directory.Exists(named));
            Assert.True(Directory.Exists(sibling));
        }
        finally
        {
            Directory.Delete(sibling, recursive: true);
        }
    }

    // The crash detail skips the child's EXTRACTION line, so it names the failure rather than a random temp path.
    [Fact]
    public void Classify_ACrash_SkipsTheExtractionLine()
    {
        var result = ReachabilityChildRunner.Classify(Entry("A"), 35, "", $"EXTRACTION\t{Path.Combine(Path.GetTempPath(), "silvergun", "pkg-abcdef012345")}\nProcess terminated. Assertion failed.", null, identity, 5);

        Assert.EndsWith(": Process terminated. Assertion failed.", result.Detail);
    }

    // ---------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------

    // The text of a markdown report from one heading up to the next given one.
    private static string Section(string md, string from, string to) =>
        md[md.IndexOf(from, StringComparison.Ordinal)..md.IndexOf(to, StringComparison.Ordinal)];

    // 10 P-lib packages: the first 6 present Network, the first `reach` reach it from LoadTime, and the `partial` ones
    // have Partial reachability.
    private static PackageReachResult[] PartialCorpus(int reach, int[] partial) =>
        [.. Enumerable.Range(0, 10).Select(i => Package($"P{i}", Lib(
            presence: i < 6 ? [(Capability.Network, 1)] : [],
            reaches: i < reach ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []) with
        {
            ReachPartial = partial.Contains(i),
            PartialReason = partial.Contains(i) ? "the graph is truncated: nodes" : null,
        }))];

    // A crashed, timed-out or incomplete result as the runner writes it: no folders, and the lib TFM TfmSelection picks
    // over the .nupkg's `files`.
    private static PackageReachResult Unmeasured(string id, string status, params string[] files) =>
        PackageReachResult.Without(Entry(id), status, "boom", status == PackageReachResult.Crashed ? 35 : null, identity).WithLibTfm(TfmSelection.Choose(files));

    private static string Serialize(ChildPayload payload) => System.Text.Json.JsonSerializer.Serialize(payload, PackageReachResult.JsonOptions);

    private static ManifestEntry Entry(string id) => new(id, "1.0.0");

    private static string Payload(params FolderResult[] folders) =>
        Serialize(new ChildPayload(folders.Any(f => f.IsPlib) ? "net8.0" : null, [], folders, PackageCost.None));

    private static PackageReachResult Package(string id, params FolderResult[] folders) =>
        new(PackageReachResult.CurrentSchema, id, "1.0.0", PackageReachResult.Scanned, null, 0, identity,
            folders.Any(f => f.IsPlib) ? "net8.0" : null, [], folders, PackageCost.None);

    private static FolderResult Lib(
        IReadOnlyList<(Capability, int)>? presence = null, IReadOnlyList<ReachRecord>? reaches = null, IReadOnlyList<ProfileRecord>? profiles = null,
        IReadOnlyList<ClassCount>? roots = null, IReadOnlyList<VerdictRecord>? verdicts = null, int ownMethods = 10, int methods = 5) =>
        Folder("lib/net8.0", "lib", presence, reaches, profiles, roots, verdicts, ownMethods, methods) with { IsPlib = true };

    private static FolderResult Folder(
        string folder, string role, IReadOnlyList<(Capability, int)>? presence = null, IReadOnlyList<ReachRecord>? reaches = null,
        IReadOnlyList<ProfileRecord>? profiles = null, IReadOnlyList<ClassCount>? roots = null, IReadOnlyList<VerdictRecord>? verdicts = null,
        int ownMethods = 10, int methods = 5) =>
        new(folder, role, false, [$"{folder}/a.dll"], [], true, null, ownMethods, roots ?? Roots(), 0, 0, reaches ?? [], verdicts ?? [], profiles ?? [],
            [], false, null, 0, null,
            [new AssemblyPresence($"{folder}/a.dll", true, null, methods, 0, [.. (presence ?? []).Select(p => new PresenceCount(p.Item1, ApiCallKind.Call, p.Item2))])],
            null, []);

    private static IReadOnlyList<ClassCount> Roots(
        int loadTime = 1, int hostContract = 1, int typeInitializer = 1, int finalizer = 1, int nativeEntry = 1, int publicApi = 5, int publicContract = 2, int hidden = 3) =>
    [
        new(RootClass.LoadTime, loadTime), new(RootClass.HostContract, hostContract), new(RootClass.TypeInitializer, typeInitializer),
        new(RootClass.Finalizer, finalizer), new(RootClass.NativeEntry, nativeEntry),
        new(RootClass.PublicApi, publicApi), new(RootClass.PublicContract, publicContract), new(RootClass.Hidden, hidden),
    ];

    private static ReachRecord Reach(RootClass @class, Capability? capability, int roots, int bound = 0, int instantiated = 0, int direct = 0) =>
        new(@class, capability, roots, bound, instantiated, direct);

    private static ProfileRecord Profile(RootClass @class, IReadOnlyList<Capability> capabilities, bool unseen = false) =>
        new(@class, capabilities, unseen, [], false, 1, "App.M()");

    // n P-lib packages: the first `network` present Network, the first `reachNetwork` reach it from LoadTime.
    private static PopulationView Corpus(int n, int network, int reachNetwork) =>
        ReachabilityAggregation.View(Enumerable.Range(0, n).Select(i => Package($"P{i:D2}", Lib(
            presence: i < network ? [(Capability.Network, 1)] : [],
            reaches: i < reachNetwork ? [Reach(RootClass.LoadTime, Capability.Network, 1)] : []))).ToArray(), Population.Plib);

    private static PackageReachResult[] OracleResults() =>
    [
        Package("A", Lib(presence: [(Capability.Network, 1), (Capability.FileSystem, 2)], methods: 10)) with { Version = "1.0.0" },
        Package("B", Lib(presence: [(Capability.Network, 3)], methods: 7)) with { Version = "2.0.0" },
    ];

    private static ReachabilityReportContext Context(CorpusManifest manifest) =>
        new(new DateOnly(2026, 11, 5), manifest, "C:\\cache", identity, TimeSpan.FromSeconds(600), PresenceOracle.Parse(OracleText));

    private static CorpusManifest Manifest(TempDirectory dir, params string[] ids)
    {
        var path = Path.Combine(dir.Path, "test.manifest");
        File.WriteAllLines(path, ids.Select(i => $"{i},1.0.0"));
        return CorpusManifest.Load(path, 0);
    }

    // A cache directory holding a (dummy) .nupkg for each id: the driver only ever tests that the file exists.
    private static string FakeCache(TempDirectory dir, params string[] ids)
    {
        var root = Path.Combine(dir.Path, "cache");
        foreach (var id in ids)
        {
            var path = CachedNupkg.PathOf(root, new ManifestEntry(id, "1.0.0"));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "not a real package");
        }
        return root;
    }

    // A minimal .nupkg: a nuspec, and a copy of `assembly` at each package path.
    private static string SyntheticPackage(TempDirectory dir, string? assembly, params string[] paths)
    {
        var nupkg = Path.Combine(dir.Path, "Synthetic.1.0.0.nupkg");
        using (var zip = ZipFile.Open(nupkg, ZipArchiveMode.Create))
        {
            using (var writer = new StreamWriter(zip.CreateEntry("Synthetic.nuspec").Open(), new UTF8Encoding(false)))
                writer.Write("""
                    <?xml version="1.0" encoding="utf-8"?>
                    <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                      <metadata>
                        <id>Synthetic</id>
                        <version>1.0.0</version>
                        <authors>Silvergun tests</authors>
                        <description>A synthetic package for the R2 harness tests.</description>
                      </metadata>
                    </package>
                    """);
            if (assembly is not null)
                foreach (var path in paths)
                    zip.CreateEntryFromFile(assembly, path);
        }
        return nupkg;
    }
    #endregion

    #region Fields
    private const string OracleHash = "oracle-hash";

    // A two-package oracle: A 1.0.0 (Network 1, FileSystem 2, 10 methods) and B 2.0.0 (Network 3, 7 methods).
    private const string OracleText = """
        # a test oracle
        manifest-hash	oracle-hash
        denominator	2
        assemblies	2
        methods-analysed	17
        total-findings	6
        capability	FileSystem	1	2
        capability	Network	2	4
        package	A	1.0.0	net8.0	1	10	3
        package	B	2.0.0	net8.0	1	7	3
        package-capability	A	FileSystem	2
        package-capability	A	Network	1
        package-capability	B	Network	3
        """;

    private static readonly BuildIdentity identity = new("c0ffee", "5ha256");

    private static readonly GraphCoverage completeCoverage = new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);
    #endregion

    #region Child types
    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateDirectory(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "silvergun-r2-tests", Guid.NewGuid().ToString("N"))).FullName;

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
    #endregion
}
