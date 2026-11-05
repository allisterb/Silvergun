namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="Reachability.Analyze"/> over hand-built graphs (<see cref="MethodGraph.FromParts"/>; reachability R1, S2;
/// acceptance criteria 4 and 8): sinks, the three evidence tiers, <c>ignore-edge</c> cuts, paths and next hops, rows,
/// profiles, the class verdicts and <see cref="ReachabilityReport.Partial"/>. Node ids are their own classification
/// keys unless a test says otherwise, every own node is in assembly <c>App</c>, and the map is <see cref="map"/>.
/// A seeded random graph is checked against a forward-BFS oracle written from the spec, per root and per tier.
/// </summary>
public sealed class ReachabilitySyntheticTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Premise
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Premise_TheTestMapsParseCleanly_AndClassifyTheirExternals()
    {
        Assert.Empty(map.Stats.RejectedLines);
        Assert.Empty(allSinksMap.Stats.RejectedLines);
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.EnvironmentProbe), map.Classify(Env));
        Assert.Equal(CapabilityClass.Unanalyzed, map.Classify(Dyn).Class);
        Assert.Equal(CapabilityClass.Safe, map.Classify(Safe).Class);
        Assert.True(map.IsIgnoredEdge("App.Cutter", "Ext.Net.Send"));
        Assert.Equal(11, Enum.GetValues<Capability>().Length);   // 11 capabilities + Unseen = the 12 sinks
    }

    // ---------------------------------------------------------------------------------------------------
    // Sinks
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Sink_AnExternalNodeTheMapClassifies_IsASinkForThatCapability()
    {
        var report = new Parts().Own("App.A", RootClass.PublicApi).Ext(Env).Edge("App.A", Env, MethodEdgeKind.Call, 3).Analyze();

        var row = Assert.Single(report.Reaches);
        Assert.Equal((RootClass.PublicApi, (Capability?)Capability.EnvironmentProbe, 1, 1, 1), (row.Class, row.Capability, row.Roots, row.Bound, row.Instantiated));
        AssertPath(Assert.Single(row.Examples), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), new ReachHop(Env, null, MethodEdgeKind.Call, 3));
    }

    // Twin: the same call to a safe external, and to one the map does not name at all.
    [Theory]
    [InlineData(Safe)]
    [InlineData("Ext.Unmapped.Op")]
    public void Sink_AnExternalNodeTheMapDoesNotClassifyAsACapability_IsNoSink(string external)
    {
        var report = new Parts().Own("App.A", RootClass.PublicApi).Ext(external).Edge("App.A", external).Analyze();

        Assert.Empty(report.Reaches);
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.PublicApi).Verdict);
    }

    // An own P/Invoke is a NativeInterop sink: for its caller, and for itself as a root (a one-hop path).
    [Fact]
    public void Sink_AnOwnNativeImport_IsANativeInteropSink()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.Native", RootClass.Hidden, native: true)
            .Edge("App.A", "App.Native", MethodEdgeKind.Call, 1)
            .Analyze();

        Assert.Equal([(RootClass.PublicApi, (Capability?)Capability.NativeInterop), (RootClass.Hidden, Capability.NativeInterop)], report.Reaches.Select(r => (r.Class, r.Capability)));
        AssertPath(Assert.Single(report.Reaches[0].Examples), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), OwnHop("App.Native", MethodEdgeKind.Call, 1));
        AssertPath(Assert.Single(report.Reaches[1].Examples), "App.Native", ReachEvidence.Bound, null, OwnHop("App.Native"));
    }

    // Twin: the same bodyless own node without NativeImport.
    [Fact]
    public void Sink_AnOwnBodylessNodeWithoutNativeImport_IsNoSink()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Node("App.Abstract", MethodNodeKind.OwnBodyless)
            .Edge("App.A", "App.Abstract")
            .Analyze();

        Assert.Empty(report.Reaches);
    }

    // A package naming its own method like a platform capability is walked, never classified: with or without facts,
    // with or without a body, and even when the map's capability key is its classification key.
    [Theory]
    [InlineData(MethodNodeKind.OwnWithBody, true)]
    [InlineData(MethodNodeKind.OwnBodyless, true)]
    [InlineData(MethodNodeKind.OwnWithBody, false)]
    [InlineData(MethodNodeKind.OwnBodyless, false)]
    public void Sink_AnOwnNodeWhoseKeyTheMapClassifies_IsNeverClassified(MethodNodeKind kind, bool withFacts)
    {
        var parts = new Parts().Own("App.A", RootClass.PublicApi).Node("App.Shadow", kind, key: Env).Edge("App.A", "App.Shadow");
        if (withFacts)
            parts.Methods.Add(new OwnMethodFacts("App.Shadow", Assembly, DefaultType, RootClass.Hidden, false, true));

        Assert.Empty(parts.Analyze().Reaches);
        Assert.Equal(RootClassVerdict.None, Status(parts.Analyze(), RootClass.PublicApi).Verdict);
    }

    // Each unseen opacity kind makes its site an Unseen sink (Capability null), for a caller and for the site itself.
    [Theory]
    [InlineData(OpacityKind.IndirectCall)]
    [InlineData(OpacityKind.Unresolved)]
    [InlineData(OpacityKind.Ambiguous)]
    [InlineData(OpacityKind.BodyUnreadable)]
    public void Sink_AnUnseenOpacitySite_IsAnUnseenSink_EndingInThatOpacity(OpacityKind kind)
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.Hidden)
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 2)
            .Opacity("App.B", kind, 4)
            .Analyze();

        Assert.Equal([(RootClass.PublicApi, (Capability?)null), (RootClass.Hidden, (Capability?)null)], report.Reaches.Select(r => (r.Class, r.Capability)));
        AssertPath(Assert.Single(report.Reaches[0].Examples), "App.A", ReachEvidence.Bound, kind, OwnHop("App.A"), OwnHop("App.B", MethodEdgeKind.Call, 2));
        AssertPath(Assert.Single(report.Reaches[1].Examples), "App.B", ReachEvidence.Bound, kind, OwnHop("App.B"));
    }

    // Twin: the opacity kinds that are not about a call site's target are no sinks.
    [Theory]
    [InlineData(OpacityKind.ModuleInitializerInvisible)]
    [InlineData(OpacityKind.NameShadowed)]
    [InlineData(OpacityKind.RenamedImplementation)]
    public void Sink_AnOpacitySiteOfAnotherKind_IsNoSink(OpacityKind kind)
    {
        var report = new Parts().Own("App.A", RootClass.PublicApi).Own("App.B", RootClass.Hidden).Edge("App.A", "App.B").Opacity("App.B", kind).Analyze();

        Assert.Empty(report.Reaches);
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.PublicApi).Verdict);
    }

    // An external the map marks unanalyzed is Unseen too; it is no opacity record, so EndsInOpacity is null.
    [Fact]
    public void Sink_AnUnanalyzedExternal_IsAnUnseenSink_WithNoOpacityKind()
    {
        var report = new Parts().Own("App.A", RootClass.PublicApi).Ext(Dyn).Edge("App.A", Dyn, MethodEdgeKind.CallVirt, 6).Analyze();

        var row = Assert.Single(report.Reaches);
        Assert.Null(row.Capability);
        AssertPath(Assert.Single(row.Examples), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), new ReachHop(Dyn, null, MethodEdgeKind.CallVirt, 6));
    }

    // EndsInOpacity names the FIRST unseen opacity at the sink in graph order (offset, then kind), skipping other kinds:
    // Unresolved@9 sorts after Ambiguous@1 despite the smaller kind, and Ambiguous@1 before BodyUnreadable@1.
    [Fact]
    public void Sink_AnOpacitySiteWithSeveralRecords_EndsInTheFirstUnseenKindInGraphOrder()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Edge("App.A", "App.A")
            .Opacity("App.A", OpacityKind.Unresolved, 9)
            .Opacity("App.A", OpacityKind.BodyUnreadable, 1)
            .Opacity("App.A", OpacityKind.Ambiguous, 1)
            .Opacity("App.A", OpacityKind.NameShadowed, 0)
            .Analyze();

        Assert.Equal(OpacityKind.Ambiguous, Assert.Single(Assert.Single(report.Reaches).Examples).EndsInOpacity);
    }

    // ---------------------------------------------------------------------------------------------------
    // Tiers
    // ---------------------------------------------------------------------------------------------------

    // Every edge kind except Dispatch is in all three tiers, whatever the target's liveness.
    [Theory]
    [InlineData(MethodEdgeKind.Call)]
    [InlineData(MethodEdgeKind.CallVirt)]
    [InlineData(MethodEdgeKind.NewObj)]
    [InlineData(MethodEdgeKind.Ldftn)]
    [InlineData(MethodEdgeKind.Ldvirtftn)]
    [InlineData(MethodEdgeKind.StateMachine)]
    [InlineData(MethodEdgeKind.TypeInitializer)]
    [InlineData(MethodEdgeKind.LoadToken)]
    public void Tier_ANonDispatchEdge_IsBound_EvenToADeadType(MethodEdgeKind kind)
    {
        var report = DispatchCase(DispatchTarget.DeadInstance, kind).Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Instantiated));
        AssertPath(Assert.Single(row.Examples), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), OwnHop("App.T.M", kind, 4), new ReachHop(Env, null, MethodEdgeKind.Call, 1));
    }

    // A Dispatch edge is never Bound. It is Instantiated when its target is static, its declaring type is live, its
    // declaring type has no facts, or the target has no facts at all; otherwise it is ChaOnly.
    [Theory]
    [InlineData(DispatchTarget.DeadInstance, ReachEvidence.ChaOnly)]
    [InlineData(DispatchTarget.LiveInstance, ReachEvidence.Instantiated)]
    [InlineData(DispatchTarget.DeadStatic, ReachEvidence.Instantiated)]
    [InlineData(DispatchTarget.NoTypeFacts, ReachEvidence.Instantiated)]
    [InlineData(DispatchTarget.NoMethodFacts, ReachEvidence.Instantiated)]
    public void Tier_ADispatchEdge_IsInstantiatedOnlyToALiveTarget(DispatchTarget target, ReachEvidence expected)
    {
        var report = DispatchCase(target, MethodEdgeKind.Dispatch).Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((1, 0, expected == ReachEvidence.Instantiated ? 1 : 0), (row.Roots, row.Bound, row.Instantiated));
        // A node without facts has no assembly to report.
        var assembly = target == DispatchTarget.NoMethodFacts ? null : Assembly;
        AssertPath(Assert.Single(row.Examples), "App.A", expected, null, OwnHop("App.A"), new ReachHop("App.T.M", assembly, MethodEdgeKind.Dispatch, 4), new ReachHop(Env, null, MethodEdgeKind.Call, 1));
    }

    // An example's path is its strongest tier's, even when a weaker tier has a shorter one.
    [Fact]
    public void Tier_AnExamplesPath_ComesFromItsStrongestTier_NotTheShortestOverall()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.Hidden)
            .Own("App.C", RootClass.Hidden)
            .Own("App.Dead.M", RootClass.Hidden, type: "App.Dead")
            .Type("App.Dead", live: false)
            .Ext(Env)
            .Edge("App.A", "App.Dead.M", MethodEdgeKind.Dispatch, 1)
            .Edge("App.Dead.M", Env, MethodEdgeKind.Call, 2)
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 3)
            .Edge("App.B", "App.C", MethodEdgeKind.Call, 4)
            .Edge("App.C", Env, MethodEdgeKind.Call, 5)
            .Analyze();

        AssertPath(Assert.Single(Row(report, RootClass.PublicApi, Capability.EnvironmentProbe).Examples), "App.A", ReachEvidence.Bound, null,
            OwnHop("App.A"), OwnHop("App.B", MethodEdgeKind.Call, 3), OwnHop("App.C", MethodEdgeKind.Call, 4), new ReachHop(Env, null, MethodEdgeKind.Call, 5));
    }

    // Bound ⊆ Instantiated ⊆ ChaOnly per root, and every tier, sink, count, evidence and path agrees with an
    // independent forward BFS written from the spec. Each root is analysed alone (the others' classes cleared), so a
    // row's counts are that one root's membership in each tier.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(2026)]
    public void Tier_PerRoot_BoundWithinInstantiatedWithinChaOnly_AndAgreesWithAForwardOracle(int seed)
    {
        var parts = RandomParts(seed);
        var roots = parts.Methods.Select(m => m.NodeId).ToArray();
        var oracle = new Oracle(parts, map);
        var tiered = 0;

        foreach (var root in roots)
        {
            var alone = parts.Copy(m => m with { Roots = m.NodeId == root ? RootClass.PublicApi : RootClass.None });
            var report = alone.Analyze();
            Assert.False(report.Partial, report.PartialReason);

            for (var sink = 0; sink < Sinks; sink++)
            {
                var capability = sink < Sinks - 1 ? (Capability?)sink : null;
                var (bound, instantiated, chaOnly) = (oracle.Distance(root, ReachEvidence.Bound, sink), oracle.Distance(root, ReachEvidence.Instantiated, sink), oracle.Distance(root, ReachEvidence.ChaOnly, sink));
                var row = report.Reaches.SingleOrDefault(r => r.Class == RootClass.PublicApi && r.Capability == capability);
                if (chaOnly is null)
                {
                    Assert.Null(row);
                    continue;
                }

                Assert.NotNull(row);
                Assert.True(row.Bound <= row.Instantiated && row.Instantiated <= row.Roots, $"{root} → {capability}: {row.Bound}/{row.Instantiated}/{row.Roots}");
                Assert.Equal((1, bound is null ? 0 : 1, instantiated is null ? 0 : 1), (row.Roots, row.Bound, row.Instantiated));
                var expected = bound is not null ? ReachEvidence.Bound : instantiated is not null ? ReachEvidence.Instantiated : ReachEvidence.ChaOnly;
                var path = Assert.Single(row.Examples);
                Assert.Equal(expected, path.Evidence);
                oracle.AssertShortestPath(path, sink, expected == ReachEvidence.Bound ? bound!.Value : expected == ReachEvidence.Instantiated ? instantiated!.Value : chaOnly.Value);
                tiered += bound is null ? 1 : 0;
            }
        }

        Assert.True(tiered > 0, "the random graph has no root that needs a Dispatch edge; pick another seed");
    }

    // The same graph with every root analysed at once: the row counts are the oracle's per-tier root counts.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(2026)]
    public void Tier_AllRootsTogether_CountsAreTheOraclesPerTierCounts(int seed)
    {
        var parts = RandomParts(seed);
        var oracle = new Oracle(parts, map);
        var report = parts.Analyze();
        var roots = parts.Methods.Select(m => m.NodeId).ToArray();

        for (var sink = 0; sink < Sinks; sink++)
        {
            var capability = sink < Sinks - 1 ? (Capability?)sink : null;
            var expected = (
                roots.Count(r => oracle.Distance(r, ReachEvidence.ChaOnly, sink) is not null),
                roots.Count(r => oracle.Distance(r, ReachEvidence.Bound, sink) is not null),
                roots.Count(r => oracle.Distance(r, ReachEvidence.Instantiated, sink) is not null));
            var row = report.Reaches.SingleOrDefault(r => r.Class == RootClass.PublicApi && r.Capability == capability);
            Assert.Equal(expected, row is null ? (0, 0, 0) : (row.Roots, row.Bound, row.Instantiated));
            Assert.True(row is null || row.Examples.Count == Math.Min(3, row.Roots));
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // ignore-edge
    // ---------------------------------------------------------------------------------------------------

    // The cut matches on classification keys (not node ids), each cut edge is counted, and each key pair is listed
    // once, ordinal ("…B" before "…a"). The caller's uncut edge, and another caller's matching callee, stay.
    [Fact]
    public void IgnoreEdge_CutsEachMatchingEdge_CountsEvery_AndListsKeyPairsDistinctAndOrdinal()
    {
        var report = new Parts()
            .Own("App.Cutter(int)", RootClass.PublicApi, key: "App.Cutter")
            .Own("App.Other", RootClass.Hidden)
            .Ext("Ext.Net.a", "Ext.Net.B", Env)
            .Edge("App.Cutter(int)", "Ext.Net.a", MethodEdgeKind.Call, 1)
            .Edge("App.Cutter(int)", "Ext.Net.a", MethodEdgeKind.CallVirt, 2)
            .Edge("App.Cutter(int)", "Ext.Net.B", MethodEdgeKind.Call, 3)
            .Edge("App.Cutter(int)", Env, MethodEdgeKind.Call, 4)
            .Edge("App.Other", "Ext.Net.a", MethodEdgeKind.Call, 5)
            .Analyze();

        Assert.Equal(3, report.EdgesIgnored);
        Assert.Equal([new IgnoredEdge("App.Cutter", "Ext.Net.B"), new IgnoredEdge("App.Cutter", "Ext.Net.a")], report.IgnoredEdges);
        Assert.Equal(
            [(RootClass.PublicApi, (Capability?)Capability.EnvironmentProbe), (RootClass.Hidden, Capability.Network)],
            report.Reaches.Select(r => (r.Class, r.Capability)));
    }

    // A cut edge is gone from every tier: a Dispatch edge to a live target and a Call both lead nowhere.
    [Fact]
    public void IgnoreEdge_ACutEdge_IsAbsentFromEveryTier()
    {
        var report = new Parts()
            .Own("App.Cutter", RootClass.PublicApi)
            .Own("App.Mid", RootClass.Hidden, key: "Ext.Net.Mid")
            .Own("App.Live.M", RootClass.Hidden, type: "App.Live", key: "Ext.Net.Live")
            .Type("App.Live", live: true)
            .Ext(Env, File)
            .Edge("App.Cutter", "App.Mid", MethodEdgeKind.Call, 1)
            .Edge("App.Cutter", "App.Live.M", MethodEdgeKind.Dispatch, 2)
            .Edge("App.Mid", Env)
            .Edge("App.Live.M", File)
            .Analyze();

        Assert.Equal(2, report.EdgesIgnored);
        Assert.Equal([new IgnoredEdge("App.Cutter", "Ext.Net.Live"), new IgnoredEdge("App.Cutter", "Ext.Net.Mid")], report.IgnoredEdges);
        Assert.DoesNotContain(report.Reaches, r => r.Class == RootClass.PublicApi);
        Assert.Equal(2, report.Reaches.Count(r => r.Class == RootClass.Hidden));   // the callees still reach their sinks
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.PublicApi).Verdict);
    }

    // Keys may contain " -> ": these two cut pairs both read "App.Cut.a -> Ext.Net.b -> Ext.Net.c" when joined, but are
    // two distinct IgnoredEdges, ordinal by Caller (the shorter, prefix caller first), then Callee.
    [Fact]
    public void IgnoreEdge_KeysContainingTheArrow_StayDistinctPairs_OrderedByCallerThenCallee()
    {
        var arrowMap = CapabilityMap.Load(new StringReader("ignore-edge App.Cut.* Ext.*"), "arrow.cm");
        var report = new Parts()
            .Own("App.N1", RootClass.PublicApi, key: "App.Cut.a -> Ext.Net.b")
            .Own("App.N2", RootClass.PublicApi, key: "App.Cut.a")
            .Node("Ext.1", MethodNodeKind.External, key: "Ext.Net.c")
            .Node("Ext.2", MethodNodeKind.External, key: "Ext.Net.b -> Ext.Net.c")
            .Edge("App.N1", "Ext.1")
            .Edge("App.N2", "Ext.2")
            .Analyze(arrowMap);

        Assert.Empty(arrowMap.Stats.RejectedLines);
        Assert.Equal(2, report.EdgesIgnored);
        Assert.Equal([new IgnoredEdge("App.Cut.a", "Ext.Net.b -> Ext.Net.c"), new IgnoredEdge("App.Cut.a -> Ext.Net.b", "Ext.Net.c")], report.IgnoredEdges);
        Assert.Single(report.IgnoredEdges.Select(e => $"{e.Caller} -> {e.Callee}").Distinct());   // what the string form lost
    }

    [Fact]
    public void IgnoreEdge_WithNoMatchingRule_IgnoresNothing()
    {
        var report = new Parts().Own("App.A", RootClass.PublicApi).Ext(Net).Edge("App.A", Net).Analyze();

        Assert.Equal(0, report.EdgesIgnored);
        Assert.Empty(report.IgnoredEdges);
        Assert.Single(report.Reaches);
    }

    // ---------------------------------------------------------------------------------------------------
    // Paths and next hops
    // ---------------------------------------------------------------------------------------------------

    // A path starts at the root (Via null, offset 0), carries each edge's kind and offset, and ends at the sink. Own
    // hops carry their facts' assembly; external hops none.
    [Fact]
    public void Path_StartsAtTheRoot_CarriesEachEdge_AndEndsAtTheSink()
    {
        var parts = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.Hidden)
            .Own("App.C", RootClass.Hidden)
            .Ext(Env)
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 3)
            .Edge("App.B", "App.C", MethodEdgeKind.NewObj, 7)
            .Edge("App.C", Env, MethodEdgeKind.CallVirt, 9);
        parts.Methods[1] = parts.Methods[1] with { Assembly = "Other" };

        AssertPath(Assert.Single(Row(parts.Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe).Examples), "App.A", ReachEvidence.Bound, null,
            OwnHop("App.A"), new ReachHop("App.B", "Other", MethodEdgeKind.Call, 3), OwnHop("App.C", MethodEdgeKind.NewObj, 7), new ReachHop(Env, null, MethodEdgeKind.CallVirt, 9));
    }

    // The nearest sink wins: two hops via App.Y beat three via App.B, although App.B is ordinal-first.
    [Fact]
    public void NextHop_TheNearestSinkWins_OverAnOrdinalEarlierLongerPath()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.Hidden)
            .Own("App.C", RootClass.Hidden)
            .Own("App.Y", RootClass.Hidden)
            .Ext(Env)
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 1)
            .Edge("App.B", "App.C", MethodEdgeKind.Call, 2)
            .Edge("App.C", Env, MethodEdgeKind.Call, 3)
            .Edge("App.A", "App.Y", MethodEdgeKind.Call, 4)
            .Edge("App.Y", Env, MethodEdgeKind.Call, 5)
            .Analyze();

        AssertPath(Example(report, "App.A"), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), OwnHop("App.Y", MethodEdgeKind.Call, 4), new ReachHop(Env, null, MethodEdgeKind.Call, 5));
    }

    // On equal length to one sink, the ordinal-least predecessor of the sink is discovered first, so it is the hop.
    [Fact]
    public void NextHop_OnEqualLength_FollowsTheOrdinalLeastPredecessor()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.C", RootClass.Hidden)
            .Own("App.B", RootClass.Hidden)
            .Ext(Env)
            .Edge("App.A", "App.C", MethodEdgeKind.Call, 1)
            .Edge("App.C", Env, MethodEdgeKind.Call, 2)
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 3)
            .Edge("App.B", Env, MethodEdgeKind.Call, 4)
            .Analyze();

        AssertPath(Example(report, "App.A"), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), OwnHop("App.B", MethodEdgeKind.Call, 3), new ReachHop(Env, null, MethodEdgeKind.Call, 4));
    }

    // Pinned BFS-frontier behaviour: with two sinks of one capability at equal distance, seeds go in ordinal node order,
    // so the ordinal-first SINK's frontier is expanded first and decides the hop, before predecessor order does. Here
    // App.C (towards Ext.Env.X) wins over the ordinal-earlier App.B (towards Ext.Env.Y).
    [Fact]
    public void NextHop_OnEqualLengthToTwoSinks_TheOrdinalFirstSinksFrontierWins()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.Hidden)
            .Own("App.C", RootClass.Hidden)
            .Ext("Ext.Env.X", "Ext.Env.Y")
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 1)
            .Edge("App.B", "Ext.Env.Y", MethodEdgeKind.Call, 2)
            .Edge("App.A", "App.C", MethodEdgeKind.Call, 3)
            .Edge("App.C", "Ext.Env.X", MethodEdgeKind.Call, 4)
            .Analyze();

        AssertPath(Example(report, "App.A"), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), OwnHop("App.C", MethodEdgeKind.Call, 3), new ReachHop("Ext.Env.X", null, MethodEdgeKind.Call, 4));
    }

    // Parallel edges between the same two nodes: the hop is the (Kind, Offset)-least, so Call@4 over Call@9 and CallVirt@1.
    [Fact]
    public void NextHop_AmongParallelEdges_IsTheKindThenOffsetLeast()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Ext(Env)
            .Edge("App.A", Env, MethodEdgeKind.CallVirt, 1)
            .Edge("App.A", Env, MethodEdgeKind.Call, 9)
            .Edge("App.A", Env, MethodEdgeKind.Call, 4)
            .Analyze();

        AssertPath(Example(report, "App.A"), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), new ReachHop(Env, null, MethodEdgeKind.Call, 4));
    }

    // A root that is itself a sink gets a one-hop path, for a capability and for Unseen.
    [Fact]
    public void Path_ARootThatIsItselfASink_HasAOneHopPath()
    {
        var report = new Parts()
            .Own("App.Native", RootClass.PublicApi, native: true)
            .Opacity("App.Native", OpacityKind.IndirectCall, 3)
            .Analyze();

        AssertPath(Example(report, "App.Native", Capability.NativeInterop), "App.Native", ReachEvidence.Bound, null, OwnHop("App.Native"));
        AssertPath(Example(report, "App.Native", null), "App.Native", ReachEvidence.Bound, OpacityKind.IndirectCall, OwnHop("App.Native"));
    }

    // ---------------------------------------------------------------------------------------------------
    // Path truncation (MaxPathHops)
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void PathTruncation_Premise_MaxPathHopsIs64()
    {
        Assert.Equal(64, Reachability.MaxPathHops);
    }

    // Exactly MaxPathHops hops fit whole.
    [Fact]
    public void PathTruncation_APathOfExactlyMaxPathHops_IsKeptWhole()
    {
        var (parts, expected) = Chain(64, Env);

        var path = Example(parts.Analyze(), "App.C0000");

        Assert.Equal(64, expected.Length);
        Assert.Equal((64, false), (path.Length, path.Truncated));
        Assert.Equal(expected, path.Hops);
    }

    // One more: the first 62 hops in order, then the last two (hop 63 is dropped), Length still the whole 65.
    [Fact]
    public void PathTruncation_APathOfMaxPathHopsPlusOne_KeepsTheFirst62AndTheLast2()
    {
        var (parts, expected) = Chain(65, Env);

        var path = Example(parts.Analyze(), "App.C0000");

        Assert.Equal((65, true), (path.Length, path.Truncated));
        Assert.Equal(64, path.Hops.Count);
        Assert.Equal(expected[..62], path.Hops.Take(62));
        Assert.Equal(expected[^2..], path.Hops.Skip(62));
        Assert.DoesNotContain(expected[62], path.Hops);
    }

    // A 1,000-hop path: 64 hops kept, the last the sink and the second-last its predecessor, Length exact.
    [Fact]
    public void PathTruncation_AThousandHopPath_KeepsItsHeadAndTheSinkWithItsPredecessor_AndCountsItAll()
    {
        var (parts, expected) = Chain(1000, Env);

        var path = Example(parts.Analyze(), "App.C0000");

        Assert.Equal((1000, true, ReachEvidence.Bound), (path.Length, path.Truncated, path.Evidence));
        Assert.Equal(64, path.Hops.Count);
        Assert.Equal(expected[..62], path.Hops.Take(62));
        Assert.Equal(new ReachHop("App.C0998", Assembly, MethodEdgeKind.Call, 997), path.Hops[^2]);
        Assert.Equal(new ReachHop(Env, null, MethodEdgeKind.Call, 998), path.Hops[^1]);
    }

    // A truncated Unseen path still names the opacity at its (kept) last hop.
    [Fact]
    public void PathTruncation_ATruncatedUnseenPath_StillEndsInItsOpacity()
    {
        var (parts, _) = Chain(100, "App.Opaque", sinkIsOwn: true);
        parts.Opacity("App.Opaque", OpacityKind.BodyUnreadable);

        var path = Example(parts.Analyze(), "App.C0000", null);

        Assert.Equal((100, true, (OpacityKind?)OpacityKind.BodyUnreadable), (path.Length, path.Truncated, path.EndsInOpacity));
        Assert.Equal("App.Opaque", path.Hops[^1].NodeId);
    }

    // ---------------------------------------------------------------------------------------------------
    // Examples
    // ---------------------------------------------------------------------------------------------------

    // At most three: Bound roots first (R1, R3), then Instantiated (R2), then ChaOnly (R0, R4), each group ordinal.
    // The counts are exact, and a Bound root is counted as Instantiated too.
    [Fact]
    public void Examples_AreAtMostThree_BoundFirstThenInstantiatedThenChaOnly_EachOrdinal()
    {
        var row = Row(ExampleCase("App.R0", "App.R1", "App.R2", "App.R3", "App.R4").Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe);

        Assert.Equal((5, 2, 3), (row.Roots, row.Bound, row.Instantiated));
        Assert.Equal([("App.R1", ReachEvidence.Bound), ("App.R3", ReachEvidence.Bound), ("App.R2", ReachEvidence.Instantiated)], row.Examples.Select(e => (e.Root, e.Evidence)));
        AssertPath(row.Examples[2], "App.R2", ReachEvidence.Instantiated, null, OwnHop("App.R2"), OwnHop("App.Live.M", MethodEdgeKind.Dispatch, 1), new ReachHop(Env, null, MethodEdgeKind.Call, 2));
    }

    // Without Bound roots, Instantiated leads and the ChaOnly roots fill in, ordinal; each with its tier's path.
    [Fact]
    public void Examples_WithoutBoundRoots_InstantiatedLeads_ThenChaOnlyInOrdinalOrder()
    {
        var row = Row(ExampleCase("App.R0", "App.R2", "App.R4").Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe);

        Assert.Equal((3, 0, 1), (row.Roots, row.Bound, row.Instantiated));
        Assert.Equal([("App.R2", ReachEvidence.Instantiated), ("App.R0", ReachEvidence.ChaOnly), ("App.R4", ReachEvidence.ChaOnly)], row.Examples.Select(e => (e.Root, e.Evidence)));
        AssertPath(row.Examples[1], "App.R0", ReachEvidence.ChaOnly, null, OwnHop("App.R0"), OwnHop("App.Dead.M", MethodEdgeKind.Dispatch, 1), new ReachHop(Env, null, MethodEdgeKind.Call, 2));
    }

    // ---------------------------------------------------------------------------------------------------
    // Rows
    // ---------------------------------------------------------------------------------------------------

    // One row per single class × reached sink: classes strongest first, sinks in Capability order, then Unseen (null).
    // A PublicApi|RuntimeInvoked root counts in both classes.
    [Fact]
    public void Rows_OnePerSingleClassAndReachedSink_InClassThenSinkOrder_AMultiClassRootCountingInEach()
    {
        var report = new Parts()
            .Own("App.Multi", RootClass.PublicApi | RootClass.RuntimeInvoked)
            .Own("App.Load", RootClass.LoadTime)
            .Ext(Env, File, Dyn, Net)
            .Edge("App.Multi", Env)
            .Edge("App.Multi", File)
            .Edge("App.Multi", Dyn)
            .Edge("App.Load", Net)
            .Analyze();

        Assert.Equal(
            [
                (RootClass.LoadTime, (Capability?)Capability.Network),
                (RootClass.RuntimeInvoked, Capability.FileSystem), (RootClass.RuntimeInvoked, Capability.EnvironmentProbe), (RootClass.RuntimeInvoked, null),
                (RootClass.PublicApi, Capability.FileSystem), (RootClass.PublicApi, Capability.EnvironmentProbe), (RootClass.PublicApi, null),
            ],
            report.Reaches.Select(r => (r.Class, r.Capability)));
        Assert.All(report.Reaches, r => Assert.Equal((1, 1, 1), (r.Roots, r.Bound, r.Instantiated)));
        Assert.Equal("App.Multi", Assert.Single(Row(report, RootClass.RuntimeInvoked, Capability.FileSystem).Examples).Root);
    }

    // ---------------------------------------------------------------------------------------------------
    // Profiles
    // ---------------------------------------------------------------------------------------------------

    // One profile per distinct non-empty ChaOnly mask per class (Unseen included in the mask): count descending, then
    // mask (FileSystem=bit 0 < Network=bit 1 < Network|Env < FileSystem|Unseen), example the ordinal-least root ("App.B"
    // before "App.b"). The root reaching nothing has no profile.
    [Fact]
    public void Profiles_PerDistinctMask_CountDescendingThenMask_ExampleOrdinalLeast_NoneForANonReachingRoot()
    {
        var report = new Parts()
            .Own("App.b", RootClass.PublicApi)
            .Own("App.B", RootClass.PublicApi)
            .Own("App.a", RootClass.PublicApi)
            .Own("App.c", RootClass.PublicApi)
            .Own("App.d", RootClass.PublicApi)
            .Own("App.f", RootClass.PublicApi)
            .Own("App.e", RootClass.PublicApi)
            .Own("App.h", RootClass.Hidden)
            .Ext(Env, Net, File, Dyn, Safe)
            .Edge("App.b", Env)
            .Edge("App.B", Env)
            .Edge("App.a", Net)
            .Edge("App.c", Net)
            .Edge("App.c", Env)
            .Edge("App.d", File)
            .Edge("App.d", Dyn)
            .Edge("App.f", File)
            .Edge("App.e", Safe)
            .Edge("App.h", Env)
            .Analyze();

        Assert.Equal(
            [
                "PublicApi [EnvironmentProbe] False 2 App.B",
                "PublicApi [FileSystem] False 1 App.f",
                "PublicApi [Network] False 1 App.a",
                "PublicApi [Network,EnvironmentProbe] False 1 App.c",
                "PublicApi [FileSystem] True 1 App.d",
                "Hidden [EnvironmentProbe] False 1 App.h",
            ],
            report.Profiles.Select(Describe));
        Assert.False(report.ProfilesTruncated);
        Assert.Equal(Status(report, RootClass.PublicApi).Roots - 1, report.Profiles.Where(p => p.Class == RootClass.PublicApi).Sum(p => p.Roots));
    }

    // 70 distinct masks over the 12 sinks (2013..2082, straddling the Unseen bit 11) in each of two classes: the 64
    // least masks are kept per class, and ProfilesTruncated is set.
    [Fact]
    public void Profiles_BeyondSixtyFourPerClass_AreCutToTheSixtyFourFirst_AndFlagged()
    {
        var report = MaskCase(2013, 70).Analyze(allSinksMap);

        Assert.True(report.ProfilesTruncated);
        foreach (var cls in new[] { RootClass.PublicApi, RootClass.PublicContract })
        {
            var profiles = report.Profiles.Where(p => p.Class == cls).ToArray();
            Assert.Equal(Enumerable.Range(2013, 64).Select(i => $"App.R{i:0000}"), profiles.Select(p => p.ExampleRoot));
            Assert.All(profiles, p => Assert.Equal(MaskDescription(cls, int.Parse(p.ExampleRoot[^4..])), Describe(p)));
        }
        Assert.Contains(report.Profiles, p => p.Unseen);
        Assert.Contains(report.Profiles, p => !p.Unseen);
    }

    // Twin: exactly 64 distinct masks per class are all kept, unflagged.
    [Fact]
    public void Profiles_ExactlySixtyFourPerClass_AreAllKept_AndNotFlagged()
    {
        var report = MaskCase(2013, 64).Analyze(allSinksMap);

        Assert.False(report.ProfilesTruncated);
        Assert.Equal(64, report.Profiles.Count(p => p.Class == RootClass.PublicApi));
        Assert.Equal(64, report.Profiles.Count(p => p.Class == RootClass.PublicContract));
    }

    // ---------------------------------------------------------------------------------------------------
    // Classes and verdicts
    // ---------------------------------------------------------------------------------------------------

    // Every class is present, strongest first, with its root count, including the empty ones.
    [Fact]
    public void Classes_AllSixArePresent_InOrder_WithTheirRootCounts()
    {
        var report = new Parts()
            .Own("App.a", RootClass.PublicApi)
            .Own("App.b", RootClass.PublicApi)
            .Own("App.c", RootClass.PublicApi | RootClass.RuntimeInvoked)
            .Own("App.d", RootClass.Hidden)
            .Analyze();

        Assert.Equal(
            [
                (RootClass.LoadTime, 0), (RootClass.HostContract, 0), (RootClass.RuntimeInvoked, 1),
                (RootClass.PublicApi, 3), (RootClass.PublicContract, 0), (RootClass.Hidden, 1),
            ],
            report.Classes.Select(c => (c.Class, c.Roots)));
        Assert.All(report.Classes, c => Assert.Equal(RootClassVerdict.None, c.Verdict));
        Assert.All(report.Classes, c => Assert.Empty(c.Reasons));
    }

    // Reaches when a capability is reached and nothing is uncertain; None for the class beside it that reaches nothing.
    [Fact]
    public void Classes_AClassReachingACapability_Reaches_AndOneReachingNothing_IsNone()
    {
        var report = new Parts().Own("App.a", RootClass.PublicApi).Own("App.d", RootClass.Hidden).Ext(Env, Safe).Edge("App.a", Env).Edge("App.d", Safe).Analyze();

        Assert.Equal((RootClassVerdict.Reaches, 0), (Status(report, RootClass.PublicApi).Verdict, Status(report, RootClass.PublicApi).Reasons.Count));
        Assert.Equal((RootClassVerdict.None, 0), (Status(report, RootClass.Hidden).Verdict, Status(report, RootClass.Hidden).Reasons.Count));
    }

    // Each cause alone turns a None class Unknown, with one reason naming it.
    [Theory]
    [InlineData(UnknownCause.GapOnTheClass, "App: synthetic gap")]
    [InlineData(UnknownCause.UnseenReach, "cannot see")]
    [InlineData(UnknownCause.Truncated, "truncated: MaxEdges (synthetic)")]
    [InlineData(UnknownCause.AssembliesUnreadable, "member index is incomplete")]
    [InlineData(UnknownCause.TypesSkipped, "member index is incomplete")]
    [InlineData(UnknownCause.MethodsSkipped, "member index is incomplete")]
    [InlineData(UnknownCause.ForwardersUnreadable, "member index is incomplete")]
    [InlineData(UnknownCause.SupertypesUnresolved, "member index is incomplete")]
    [InlineData(UnknownCause.RenamedImplementations, "2 MethodImpl row(s)")]
    [InlineData(UnknownCause.ModulesUnreadable, "3 module(s) unreadable")]
    public void Classes_EachUnknownCauseAlone_TurnsANoneClassUnknown(UnknownCause cause, string reason)
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi).Ext(Safe).Edge("App.a", Safe);
        Assert.Equal(RootClassVerdict.None, Status(parts.Analyze(), RootClass.PublicApi).Verdict);   // the premise: None without it

        var status = Status(Apply(parts, cause).Analyze(), RootClass.PublicApi);

        Assert.Equal(RootClassVerdict.Unknown, status.Verdict);
        Assert.Contains(reason, Assert.Single(status.Reasons), StringComparison.Ordinal);
    }

    // ...and a Reaches class too: an uncertain class never claims to know what it reaches.
    [Theory]
    [InlineData(UnknownCause.GapOnTheClass)]
    [InlineData(UnknownCause.UnseenReach)]
    [InlineData(UnknownCause.Truncated)]
    [InlineData(UnknownCause.MethodsSkipped)]
    [InlineData(UnknownCause.RenamedImplementations)]
    [InlineData(UnknownCause.ModulesUnreadable)]
    public void Classes_EachUnknownCauseAlone_TurnsAReachesClassUnknown(UnknownCause cause)
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi).Ext(Env).Edge("App.a", Env);
        Assert.Equal(RootClassVerdict.Reaches, Status(parts.Analyze(), RootClass.PublicApi).Verdict);

        Assert.Equal(RootClassVerdict.Unknown, Status(Apply(parts, cause).Analyze(), RootClass.PublicApi).Verdict);
    }

    // The graph-wide causes make every class Unknown, the empty ones included.
    [Theory]
    [InlineData(UnknownCause.Truncated)]
    [InlineData(UnknownCause.AssembliesUnreadable)]
    [InlineData(UnknownCause.RenamedImplementations)]
    [InlineData(UnknownCause.ModulesUnreadable)]
    public void Classes_AGraphWideCause_TurnsEveryClassUnknown(UnknownCause cause)
    {
        var report = Apply(new Parts().Own("App.a", RootClass.PublicApi), cause).Analyze();

        Assert.All(report.Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
    }

    // A gap covers the classes its mask overlaps, and only those.
    [Fact]
    public void Classes_AGap_CoversExactlyTheClassesItsMaskOverlaps()
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi).Own("App.h", RootClass.Hidden).Own("App.r", RootClass.RuntimeInvoked);
        parts.Gaps.Add(new RootGap(Assembly, RootClass.PublicApi | RootClass.Hidden, "visibility"));
        parts.Gaps.Add(new RootGap("Other", RootClass.LoadTime, "module"));

        var report = parts.Analyze();

        Assert.Equal(
            [
                (RootClass.LoadTime, RootClassVerdict.Unknown), (RootClass.HostContract, RootClassVerdict.None), (RootClass.RuntimeInvoked, RootClassVerdict.None),
                (RootClass.PublicApi, RootClassVerdict.Unknown), (RootClass.PublicContract, RootClassVerdict.None), (RootClass.Hidden, RootClassVerdict.Unknown),
            ],
            report.Classes.Select(c => (c.Class, c.Verdict)));
        Assert.Equal(["Other: module"], Status(report, RootClass.LoadTime).Reasons);
        Assert.Equal(["App: visibility"], Status(report, RootClass.Hidden).Reasons);
    }

    // An Unseen reach is the reaching root's class's uncertainty only; Unseen is never a capability for Reaches.
    [Fact]
    public void Classes_AnUnseenReach_MakesOnlyItsRootsClassUnknown_AndIsNoCapability()
    {
        var report = new Parts().Own("App.a", RootClass.PublicApi).Own("App.h", RootClass.Hidden).Ext(Env, Dyn).Edge("App.a", Env).Edge("App.h", Dyn).Analyze();

        Assert.Equal(RootClassVerdict.Reaches, Status(report, RootClass.PublicApi).Verdict);
        var hidden = Status(report, RootClass.Hidden);
        Assert.Equal(RootClassVerdict.Unknown, hidden.Verdict);
        Assert.Equal("1 root(s) reach code the graph cannot see", Assert.Single(hidden.Reasons));
    }

    // ---------------------------------------------------------------------------------------------------
    // Partial
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Partial_ACompleteGraph_IsNotPartial_AndCarriesItsCoverage()
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi);
        var report = parts.Analyze();

        Assert.False(report.Partial);
        Assert.Null(report.PartialReason);
        Assert.Equal(complete, report.Graph);
    }

    // A truncated graph is Partial with the reason; what it did reach is still reported.
    [Fact]
    public void Partial_ATruncatedGraph_IsPartialWithItsReason_AndStillReportsItsReaches()
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi).Ext(Env).Edge("App.a", Env);
        parts.Coverage = truncated;

        var report = parts.Analyze();

        Assert.True(report.Partial);
        Assert.Contains("MaxEdges (synthetic)", report.PartialReason, StringComparison.Ordinal);
        Assert.Equal(truncated, report.Graph);
        Assert.Single(report.Reaches);
        Assert.All(report.Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
    }

    // Facts that break their one-row-per-id invariant make the analysis throw inside; Analyze catches it and returns a
    // Partial report with every class Unknown, instead of throwing.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Partial_AnInternalFailure_YieldsAPartialReport_EveryClassUnknown(bool duplicateMethodFacts)
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi).Ext(Env).Edge("App.a", Env).Type("App.T", live: true);
        if (duplicateMethodFacts)
            parts.Methods.Add(parts.Methods[0]);
        else
            parts.Types.Add(parts.Types[0]);

        var report = parts.Analyze();

        Assert.True(report.Partial);
        Assert.False(string.IsNullOrWhiteSpace(report.PartialReason));
        Assert.Equal(allClasses, report.Classes.Select(c => c.Class));
        Assert.All(report.Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
        Assert.All(report.Classes, c => Assert.Contains("could not be computed", Assert.Single(c.Reasons), StringComparison.Ordinal));
        Assert.Empty(report.Reaches);
        Assert.Empty(report.Profiles);
        Assert.Equal(complete, report.Graph);
    }

    // A null graph is a caller's bug, not an input: it is the one argument check that throws.
    [Fact]
    public void Analyze_ANullGraph_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => Reachability.Analyze(null!));
    }

    // With no map, the built-in map classifies.
    [Fact]
    public void Analyze_WithoutAMap_ClassifiesByTheBuiltInMap()
    {
        const string GetEnv = "System.Environment.GetEnvironmentVariable(System.String)";
        var graph = new Parts()
            .Own("App.a", RootClass.PublicApi)
            .Node(GetEnv, MethodNodeKind.External, key: "System.Environment.GetEnvironmentVariable")
            .Edge("App.a", GetEnv)
            .Graph();

        Assert.Equal(Capability.EnvironmentProbe, Assert.Single(Reachability.Analyze(graph).Reaches).Capability);
    }

    // ---------------------------------------------------------------------------------------------------
    // Cycles, determinism, dangling parts
    // ---------------------------------------------------------------------------------------------------

    // Self-loops (in two tiers) and a 2-cycle on the way to a sink terminate with the shortest path; a cycle reaching
    // no sink terminates with nothing.
    [Fact]
    public void Cycles_SelfLoopsAndATwoCycleOnTheWay_Terminate_WithTheShortestPath()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.Hidden)
            .Own("App.C", RootClass.Hidden)
            .Own("App.D", RootClass.PublicApi)
            .Own("App.E", RootClass.Hidden)
            .Ext(Env)
            .Edge("App.A", "App.A", MethodEdgeKind.Call, 0)
            .Edge("App.A", "App.A", MethodEdgeKind.Dispatch, 5)
            .Edge("App.A", "App.B", MethodEdgeKind.Call, 1)
            .Edge("App.B", "App.A", MethodEdgeKind.Call, 2)
            .Edge("App.B", "App.B", MethodEdgeKind.CallVirt, 6)
            .Edge("App.B", "App.C", MethodEdgeKind.Call, 3)
            .Edge("App.C", Env, MethodEdgeKind.Call, 4)
            .Edge("App.D", "App.E", MethodEdgeKind.Call, 7)
            .Edge("App.E", "App.D", MethodEdgeKind.Call, 8)
            .Edge("App.E", "App.E", MethodEdgeKind.Call, 9)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal(1, row.Roots);
        AssertPath(Assert.Single(row.Examples), "App.A", ReachEvidence.Bound, null,
            OwnHop("App.A"), OwnHop("App.B", MethodEdgeKind.Call, 1), OwnHop("App.C", MethodEdgeKind.Call, 3), new ReachHop(Env, null, MethodEdgeKind.Call, 4));
        Assert.Equal(2, Row(report, RootClass.Hidden, Capability.EnvironmentProbe).Roots);   // B and C, not E
        Assert.Equal(2, report.Reaches.Count);
    }

    // Two runs over one graph give equal reports, compared in full (records with list members do not compare by value).
    [Theory]
    [InlineData(1)]
    [InlineData(2026)]
    public void Determinism_TwoRunsOverOneGraph_GiveEqualReports(int seed)
    {
        var graph = RandomParts(seed).Graph();

        Assert.Equal(Canonical(Reachability.Analyze(graph, map)), Canonical(Reachability.Analyze(graph, map)));
    }

    // The report does not depend on the order the parts were given in: FromParts orders them, and the facts are
    // keyed, so reversed input gives the same report.
    [Theory]
    [InlineData(1)]
    [InlineData(2026)]
    public void Determinism_ThePartsInReverseOrder_GiveTheSameReport(int seed)
    {
        var parts = RandomParts(seed);
        var forward = parts.Graph();
        var backward = MethodGraph.FromParts(
            Enumerable.Reverse(parts.Nodes), Enumerable.Reverse(parts.Edges), Enumerable.Reverse(parts.Opacities), parts.Coverage,
            new GraphFacts([.. Enumerable.Reverse(forward.Facts.Methods)], [.. Enumerable.Reverse(forward.Facts.Types)], [.. Enumerable.Reverse(forward.Facts.Gaps)]));

        Assert.Equal(Canonical(Reachability.Analyze(forward, map)), Canonical(Reachability.Analyze(backward, map)));
    }

    // Edges with an endpoint that is no node are skipped (and never counted as ignored, even when a rule matches),
    // facts of no node are no roots, and an opacity sited at no node is no sink.
    [Fact]
    public void DanglingParts_AreSkippedWithoutThrowing()
    {
        var parts = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.Cutter", RootClass.PublicApi)
            .Ext(Env)
            .Edge("App.A", "Ghost.Callee")
            .Edge("Ghost.Caller", Env)
            .Edge("App.Cutter", "Ext.Net.Ghost")
            .Opacity("[App]<Module>", OpacityKind.Unresolved);
        parts.Methods.Add(new OwnMethodFacts("Ghost.Root", Assembly, DefaultType, RootClass.PublicApi, true, false));

        var report = parts.Analyze();

        Assert.False(report.Partial, report.PartialReason);
        Assert.Empty(report.Reaches);
        Assert.Equal(0, report.EdgesIgnored);
        Assert.Empty(report.IgnoredEdges);
        Assert.Equal((2, RootClassVerdict.None), (Status(report, RootClass.PublicApi).Roots, Status(report, RootClass.PublicApi).Verdict));
    }

    // ---------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------

    // App.A -[kind@4]-> App.T.M -Call@1-> Env, with App.T.M's facts and its type's shaped by target.
    private static Parts DispatchCase(DispatchTarget target, MethodEdgeKind kind)
    {
        var parts = new Parts().Own("App.A", RootClass.PublicApi).Ext(Env).Edge("App.A", "App.T.M", kind, 4).Edge("App.T.M", Env, MethodEdgeKind.Call, 1);
        if (target == DispatchTarget.NoMethodFacts)
            parts.Node("App.T.M", MethodNodeKind.OwnWithBody).Type("App.T", live: false);
        else
            parts.Own("App.T.M", RootClass.Hidden, type: "App.T", isStatic: target == DispatchTarget.DeadStatic);
        if (target is DispatchTarget.DeadInstance or DispatchTarget.DeadStatic or DispatchTarget.LiveInstance)
            parts.Type("App.T", live: target == DispatchTarget.LiveInstance);
        return parts;
    }

    // Each named root reaches Env: R0 and R4 by Dispatch to a dead type (ChaOnly), R2 by Dispatch to a live one
    // (Instantiated), R1 and R3 by a Call (Bound).
    private static Parts ExampleCase(params string[] roots)
    {
        var parts = new Parts()
            .Own("App.Dead.M", RootClass.Hidden, type: "App.Dead")
            .Own("App.Live.M", RootClass.Hidden, type: "App.Live")
            .Type("App.Dead", live: false)
            .Type("App.Live", live: true)
            .Ext(Env)
            .Edge("App.Dead.M", Env, MethodEdgeKind.Call, 2)
            .Edge("App.Live.M", Env, MethodEdgeKind.Call, 2);
        foreach (var root in roots)
        {
            parts.Own(root, RootClass.PublicApi);
            _ = root switch
            {
                "App.R0" or "App.R4" => parts.Edge(root, "App.Dead.M", MethodEdgeKind.Dispatch, 1),
                "App.R2" => parts.Edge(root, "App.Live.M", MethodEdgeKind.Dispatch, 1),
                _ => parts.Edge(root, Env, MethodEdgeKind.Call, 1),
            };
        }
        return parts;
    }

    // Roots App.R{i} for i in [first, first + count), PublicApi|PublicContract, each calling the sinks of i's bits under
    // allSinksMap: bit k < 11 is Ext.{Capability k}.Call, bit 11 the unanalyzed Ext.Dyn.Call. So root i's mask is i.
    private static Parts MaskCase(int first, int count)
    {
        var sinks = Enum.GetValues<Capability>().Select(c => $"Ext.{c}.Call").Append(Dyn).ToArray();
        var parts = new Parts().Ext(sinks);
        foreach (var i in Enumerable.Range(first, count))
        {
            var root = $"App.R{i:0000}";
            parts.Own(root, RootClass.PublicApi | RootClass.PublicContract);
            for (var bit = 0; bit < Sinks; bit++)
                if ((i & (1 << bit)) != 0)
                    parts.Edge(root, sinks[bit]);
        }
        return parts;
    }

    // The profile a lone root App.R{mask} of cls has under MaskCase, written from the mask's bits.
    private static string MaskDescription(RootClass cls, int mask) =>
        $"{cls} [{string.Join(",", Enum.GetValues<Capability>().Where(c => (mask & (1 << (int)c)) != 0))}] {(mask & (1 << 11)) != 0} 1 App.R{mask:0000}";

    private static string Describe(ReachProfile p) => $"{p.Class} [{string.Join(",", p.Capabilities)}] {p.Unseen} {p.Roots} {p.ExampleRoot}";

    private static Parts Apply(Parts parts, UnknownCause cause)
    {
        var copy = parts.Copy(m => m);
        switch (cause)
        {
            case UnknownCause.GapOnTheClass: copy.Gaps.Add(new RootGap(Assembly, RootClass.PublicApi, "synthetic gap")); break;
            case UnknownCause.UnseenReach: copy.Opacity("App.a", OpacityKind.Unresolved, 1); break;
            case UnknownCause.Truncated: copy.Coverage = truncated; break;
            case UnknownCause.AssembliesUnreadable: copy.Coverage = complete with { Index = new IndexCoverage(1, 0, 0) }; break;
            case UnknownCause.TypesSkipped: copy.Coverage = complete with { Index = new IndexCoverage(0, 1, 0) }; break;
            case UnknownCause.MethodsSkipped: copy.Coverage = complete with { Index = new IndexCoverage(0, 0, 1) }; break;
            case UnknownCause.ForwardersUnreadable: copy.Coverage = complete with { Index = new IndexCoverage(0, 0, 0, ForwardersUnreadable: 1) }; break;
            case UnknownCause.SupertypesUnresolved: copy.Coverage = complete with { Index = new IndexCoverage(0, 0, 0, SupertypesUnresolved: 1) }; break;
            case UnknownCause.RenamedImplementations: copy.Coverage = complete with { RenamedImplementations = 2 }; break;
            case UnknownCause.ModulesUnreadable: copy.Coverage = complete with { ModulesUnreadable = 3 }; break;
        }
        return copy;
    }

    // A seeded graph mixing every edge kind, live/dead/unknown types, static targets, P/Invokes, own nodes without
    // facts, unseen and other opacities, every sink kind and an ignore-edge caller. Every own node with facts is a
    // PublicApi root.
    private static Parts RandomParts(int seed)
    {
        var random = new Random(seed);
        var parts = new Parts();
        string[] types = ["App.T0", "App.T1", "App.T2", "App.T3"];
        parts.Type("App.T0", live: true).Type("App.T1", live: false).Type("App.T2", live: random.Next(2) == 0);   // App.T3 has no facts
        var own = Enumerable.Range(0, 24).Select(i => $"App.N{i:00}").Append("App.Cutter").ToArray();
        foreach (var id in own)
            parts.Own(id, RootClass.PublicApi, type: types[random.Next(types.Length)], native: random.Next(10) == 0, isStatic: random.Next(4) == 0);
        parts.Node("App.NoFacts", MethodNodeKind.OwnWithBody);
        string[] externals = [Env, Net, File, Dyn, Safe, "Ext.Net.Recv"];
        parts.Ext(externals);
        var targets = own.Append("App.NoFacts").Concat(externals).ToArray();
        var sources = own.Append("App.NoFacts").ToArray();
        var kinds = Enum.GetValues<MethodEdgeKind>();
        for (var i = 0; i < 60; i++)
            parts.Edge(sources[random.Next(sources.Length)], targets[random.Next(targets.Length)], kinds[random.Next(kinds.Length)], (uint)random.Next(20));
        // Bias towards Dispatch so the tiers separate.
        for (var i = 0; i < 15; i++)
            parts.Edge(sources[random.Next(sources.Length)], own[random.Next(own.Length)], MethodEdgeKind.Dispatch, (uint)random.Next(20));
        var opacityKinds = Enum.GetValues<OpacityKind>();
        for (var i = 0; i < 4; i++)
            parts.Opacity(sources[random.Next(sources.Length)], opacityKinds[random.Next(opacityKinds.Length)], (uint)random.Next(20));
        return parts;
    }

    private static CapabilityReach Row(ReachabilityReport report, RootClass cls, Capability? capability) =>
        report.Reaches.SingleOrDefault(r => r.Class == cls && r.Capability == capability)
            ?? throw new InvalidOperationException($"No {cls} × {capability?.ToString() ?? "Unseen"} row. Rows: {string.Join("; ", report.Reaches.Select(r => $"{r.Class} × {r.Capability}"))}");

    // root's single example for Env (or capability) in its first class row.
    private static ReachPath Example(ReachabilityReport report, string root, Capability? capability = Capability.EnvironmentProbe) =>
        Assert.Single(Row(report, RootClass.PublicApi, capability).Examples, e => e.Root == root);

    private static RootClassStatus Status(ReachabilityReport report, RootClass cls) => Assert.Single(report.Classes, c => c.Class == cls);

    private static ReachHop OwnHop(string nodeId, MethodEdgeKind? via = null, uint offset = 0) => new(nodeId, Assembly, via, offset);

    // A whole (short) path: exactly these hops, its Length their count, not truncated.
    private static void AssertPath(ReachPath path, string root, ReachEvidence evidence, OpacityKind? endsInOpacity, params ReachHop[] hops)
    {
        Assert.Equal(root, path.Root);
        Assert.Equal(evidence, path.Evidence);
        Assert.Equal(endsInOpacity, path.EndsInOpacity);
        Assert.Equal(hops, path.Hops);
        Assert.Equal(hops.Length, path.Length);
        Assert.False(path.Truncated);
    }

    // A PublicApi root App.C0000 calling down a chain of own nodes (in no class) App.C0001… to sink, so its path has
    // exactly hops hops, root and sink included. Edge i leaves App.C{i} at offset i.
    private static (Parts Parts, ReachHop[] Expected) Chain(int hops, string sink, bool sinkIsOwn = false)
    {
        var parts = new Parts().Own("App.C0000", RootClass.PublicApi);
        var expected = new List<ReachHop> { OwnHop("App.C0000") };
        for (var i = 1; i < hops - 1; i++)
        {
            var id = $"App.C{i:0000}";
            parts.Own(id, RootClass.None).Edge($"App.C{i - 1:0000}", id, MethodEdgeKind.Call, (uint)(i - 1));
            expected.Add(OwnHop(id, MethodEdgeKind.Call, (uint)(i - 1)));
        }
        if (sinkIsOwn)
            parts.Own(sink, RootClass.None);
        else
            parts.Ext(sink);
        parts.Edge($"App.C{hops - 2:0000}", sink, MethodEdgeKind.Call, (uint)(hops - 2));
        expected.Add(new ReachHop(sink, sinkIsOwn ? Assembly : null, MethodEdgeKind.Call, (uint)(hops - 2)));
        return (parts, [.. expected]);
    }

    // The whole report as text, lists included, so two reports compare in full.
    private static string Canonical(ReachabilityReport report) => JsonSerializer.Serialize(report);
    #endregion

    #region Fields
    private const string Assembly = "App";
    private const string DefaultType = "App.T";
    private const string Env = "Ext.Env.Get";
    private const string Net = "Ext.Net.Send";
    private const string File = "Ext.File.Read";
    private const string Dyn = "Ext.Dyn.Call";
    private const string Safe = "Ext.Safe.Op";
    private const int Sinks = 12;

    private static readonly RootClass[] allClasses =
        [RootClass.LoadTime, RootClass.HostContract, RootClass.RuntimeInvoked, RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden];

    private static readonly GraphCoverage complete = new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);

    private static readonly GraphCoverage truncated = complete with { Truncated = true, TruncatedBy = "MaxEdges (synthetic)" };

    private static readonly CapabilityMap map = CapabilityMap.Load(
        new StringReader(
            """
            capability  Ext.Env  EnvironmentProbe
            capability  Ext.Net  Network
            capability  Ext.File FileSystem
            unanalyzed  Ext.Dyn
            safe        Ext.Safe
            ignore-edge App.Cutter Ext.Net
            """),
        "reachability-synthetic.cm");

    // One external type per capability, Ext.<Capability>, plus the unanalyzed Ext.Dyn: all 12 sinks.
    private static readonly CapabilityMap allSinksMap = CapabilityMap.Load(
        new StringReader(string.Join("\n", Enum.GetValues<Capability>().Select(c => $"capability Ext.{c} {c}").Append("unanalyzed Ext.Dyn"))),
        "reachability-all-sinks.cm");
    #endregion

    #region Child types
    public enum DispatchTarget { DeadInstance, LiveInstance, DeadStatic, NoTypeFacts, NoMethodFacts }

    public enum UnknownCause
    {
        GapOnTheClass, UnseenReach, Truncated, AssembliesUnreadable, TypesSkipped, MethodsSkipped, ForwardersUnreadable, SupertypesUnresolved, RenamedImplementations, ModulesUnreadable
    }

    // The parts of a hand-made graph, built fluently. Own nodes are in assembly "App" and get facts; types are facts only.
    private sealed class Parts
    {
        public List<MethodNode> Nodes { get; } = [];
        public List<MethodEdge> Edges { get; } = [];
        public List<GraphOpacity> Opacities { get; } = [];
        public List<OwnMethodFacts> Methods { get; } = [];
        public List<OwnTypeFacts> Types { get; } = [];
        public List<RootGap> Gaps { get; } = [];
        public GraphCoverage Coverage { get; set; } = complete;

        public Parts Own(string id, RootClass roots, string type = DefaultType, bool native = false, bool isStatic = false, string? key = null)
        {
            Node(id, native ? MethodNodeKind.OwnBodyless : MethodNodeKind.OwnWithBody, key);
            Methods.Add(new OwnMethodFacts(id, Assembly, type, roots, native, isStatic));
            return this;
        }

        public Parts Node(string id, MethodNodeKind kind, string? key = null)
        {
            Nodes.Add(new MethodNode(id, key ?? id, kind));
            return this;
        }

        public Parts Ext(params string[] ids)
        {
            foreach (var id in ids)
                Node(id, MethodNodeKind.External);
            return this;
        }

        public Parts Type(string id, bool live)
        {
            Types.Add(new OwnTypeFacts(id, Assembly, live));
            return this;
        }

        public Parts Edge(string from, string to, MethodEdgeKind kind = MethodEdgeKind.Call, uint offset = 0)
        {
            Edges.Add(new MethodEdge(from, to, kind, offset));
            return this;
        }

        public Parts Opacity(string site, OpacityKind kind, uint offset = 0)
        {
            Opacities.Add(new GraphOpacity(site, offset, kind, "synthetic"));
            return this;
        }

        // A copy with each method fact mapped.
        public Parts Copy(Func<OwnMethodFacts, OwnMethodFacts> facts)
        {
            var copy = new Parts { Coverage = Coverage };
            copy.Nodes.AddRange(Nodes);
            copy.Edges.AddRange(Edges);
            copy.Opacities.AddRange(Opacities);
            copy.Methods.AddRange(Methods.Select(facts));
            copy.Types.AddRange(Types);
            copy.Gaps.AddRange(Gaps);
            return copy;
        }

        public MethodGraph Graph() =>
            MethodGraph.FromParts(Nodes, Edges, Opacities, Coverage,
                new GraphFacts([.. Methods.OrderBy(m => m.NodeId, StringComparer.Ordinal)], [.. Types.OrderBy(t => t.TypeId, StringComparer.Ordinal)], [.. Gaps]));

        public ReachabilityReport Analyze(CapabilityMap? with = null) => Reachability.Analyze(Graph(), with ?? map);
    }

    // Forward BFS from one root over one tier's edges, written from the spec rather than the implementation: which
    // nodes are which sink, which edges each tier keeps, and the distance to the nearest sink.
    private sealed class Oracle
    {
        public Oracle(Parts parts, CapabilityMap map)
        {
            nodes = parts.Nodes.ToDictionary(n => n.NodeId, StringComparer.Ordinal);
            facts = parts.Methods.ToDictionary(m => m.NodeId, StringComparer.Ordinal);
            live = parts.Types.ToDictionary(t => t.TypeId, t => t.Live, StringComparer.Ordinal);
            edges = [.. parts.Edges.Where(e => nodes.ContainsKey(e.From) && nodes.ContainsKey(e.To) && !map.IsIgnoredEdge(nodes[e.From].ClassificationKey, nodes[e.To].ClassificationKey))];
            unseenSites = parts.Opacities.Where(o => o.Kind is OpacityKind.IndirectCall or OpacityKind.Unresolved or OpacityKind.Ambiguous or OpacityKind.BodyUnreadable)
                .Select(o => o.Site).ToHashSet(StringComparer.Ordinal);
            this.map = map;
        }

        public int? Distance(string root, ReachEvidence tier, int sink)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal) { root };
            var frontier = new List<string> { root };
            for (var depth = 0; frontier.Count > 0; depth++)
            {
                if (frontier.Any(n => IsSink(n, sink)))
                    return depth;
                frontier = [.. frontier.SelectMany(n => edges.Where(e => e.From == n && InTier(e, tier)).Select(e => e.To)).Where(seen.Add)];
            }
            return null;
        }

        // The path is root-first with Via null at offset 0, each step an edge of its tier, it ends at a sink, and it is
        // as short as the nearest sink is (Length counts the root). A truncated path keeps the first MaxPathHops - 2 hops
        // and the last two, so the one step across the cut is not an edge and is not checked.
        public void AssertShortestPath(ReachPath path, int sink, int distance)
        {
            Assert.Equal(new ReachHop(path.Root, Assembly, null, 0), path.Hops[0]);
            Assert.Equal(distance + 1, path.Length);
            Assert.Equal(path.Length > Reachability.MaxPathHops, path.Truncated);
            Assert.Equal(Math.Min(path.Length, Reachability.MaxPathHops), path.Hops.Count);
            for (var i = 1; i < path.Hops.Count; i++)
            {
                if (path.Truncated && i == Reachability.MaxPathHops - 2)
                    continue;
                var (from, to) = (path.Hops[i - 1].NodeId, path.Hops[i]);
                Assert.Contains(edges, e => e.From == from && e.To == to.NodeId && e.Kind == to.Via && e.Offset == to.Offset && InTier(e, path.Evidence));
                Assert.Equal(facts.TryGetValue(to.NodeId, out var f) ? f.Assembly : null, to.Assembly);
            }
            Assert.True(IsSink(path.Hops[^1].NodeId, sink), $"{path.Hops[^1].NodeId} is not sink {sink}");
        }

        private bool IsSink(string id, int sink)
        {
            var node = nodes[id];
            var verdict = node.Kind == MethodNodeKind.External ? map.Classify(node.ClassificationKey) : CapabilityVerdict.None;
            return sink == Sinks - 1
                ? unseenSites.Contains(id) || verdict.Class == CapabilityClass.Unanalyzed
                : (verdict.Class == CapabilityClass.Capability && verdict.Capability == (Capability)sink)
                    || ((Capability)sink == Capability.NativeInterop && node.Kind != MethodNodeKind.External && facts.TryGetValue(id, out var f) && f.NativeImport);
        }

        private bool InTier(MethodEdge edge, ReachEvidence tier) => tier switch
        {
            ReachEvidence.Bound => edge.Kind != MethodEdgeKind.Dispatch,
            ReachEvidence.Instantiated => edge.Kind != MethodEdgeKind.Dispatch || IsLive(edge.To),
            _ => true,
        };

        private bool IsLive(string target) =>
            !facts.TryGetValue(target, out var f) || f.IsStatic || !live.TryGetValue(f.DeclaringTypeId, out var isLive) || isLive;

        private readonly Dictionary<string, MethodNode> nodes;
        private readonly Dictionary<string, OwnMethodFacts> facts;
        private readonly Dictionary<string, bool> live;
        private readonly MethodEdge[] edges;
        private readonly HashSet<string> unseenSites;
        private readonly CapabilityMap map;
    }
    #endregion
}
