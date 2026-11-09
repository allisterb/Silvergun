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

    // An own InternalCall (S3: a body-less extern that is no P/Invoke) is an Unseen sink, for its caller and for itself as
    // a root. It has no opacity record, so EndsInOpacity is null, and every class reaching it is Unknown.
    [Fact]
    public void Sink_AnOwnInternalCall_IsAnUnseenSink_WithNoOpacityKind_AndItsCallersClassIsUnknown()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.Icall", RootClass.Hidden, internalCall: true)
            .Edge("App.A", "App.Icall", MethodEdgeKind.Call, 5)
            .Analyze();

        Assert.Equal([(RootClass.PublicApi, (Capability?)null), (RootClass.Hidden, (Capability?)null)], report.Reaches.Select(r => (r.Class, r.Capability)));
        AssertPath(Assert.Single(report.Reaches[0].Examples), "App.A", ReachEvidence.Bound, null, OwnHop("App.A"), OwnHop("App.Icall", MethodEdgeKind.Call, 5));
        AssertPath(Assert.Single(report.Reaches[1].Examples), "App.Icall", ReachEvidence.Bound, null, OwnHop("App.Icall"));
        Assert.All(new[] { RootClass.PublicApi, RootClass.Hidden }, c =>
        {
            var status = Status(report, c);
            Assert.Equal(RootClassVerdict.Unknown, status.Verdict);
            Assert.Equal("1 root(s) reach code the graph cannot see", Assert.Single(status.Reasons));
        });
        Assert.All(report.Profiles, p => Assert.Equal((true, 0), (p.Unseen, p.Capabilities.Count)));
    }

    // Twin: the same node without the flag is no sink, and the class stays None.
    [Fact]
    public void Sink_TheSameOwnNodeWithoutInternalCall_IsNoSink()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.Icall", RootClass.Hidden, internalCall: true)
            .Edge("App.A", "App.Icall", MethodEdgeKind.Call, 5)
            .Copy(m => m with { InternalCall = false })
            .Analyze();

        Assert.Empty(report.Reaches);
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.PublicApi).Verdict);
    }

    // The flag is read from own facts only: an External node is classified by the map, never by facts carrying it.
    [Fact]
    public void Sink_InternalCallFactsOnAnExternalNode_AreIgnored()
    {
        var parts = new Parts().Own("App.A", RootClass.PublicApi).Ext(Safe).Edge("App.A", Safe);
        parts.Methods.Add(new OwnMethodFacts(Safe, Assembly, DefaultType, RootClass.None, false, true, InternalCall: true));

        Assert.Empty(parts.Analyze().Reaches);
    }

    // An InternalCall that is also (inconsistently) a NativeImport is both sinks: NativeInterop and Unseen.
    [Fact]
    public void Sink_AnOwnNodeBothNativeImportAndInternalCall_IsBothSinks()
    {
        var report = new Parts().Own("App.Both", RootClass.PublicApi, native: true, internalCall: true).Analyze();

        Assert.Equal([(Capability?)Capability.NativeInterop, null], report.Reaches.Select(r => r.Capability));
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

    // MaxPathHops - 1 (63) hops: the head holds the first 62 and the tail the one remaining, the sink. Kept whole, not
    // truncated, and in order across the head/tail seam (S2 status, carried into S3).
    [Fact]
    public void PathTruncation_APathOfMaxPathHopsMinusOne_KeepsAOneHopTail_AndIsWhole()
    {
        var (parts, expected) = Chain(63, Env);

        var path = Example(parts.Analyze(), "App.C0000");

        Assert.Equal(63, expected.Length);
        Assert.Equal((63, 63, false), (path.Hops.Count, path.Length, path.Truncated));
        Assert.Equal(expected, path.Hops);
        Assert.Equal(new ReachHop(Env, null, MethodEdgeKind.Call, 61), path.Hops[^1]);
        Assert.Equal(new ReachHop("App.C0061", Assembly, MethodEdgeKind.Call, 60), path.Hops[^2]);
    }

    // 62 hops: the head alone holds them all (no tail).
    [Fact]
    public void PathTruncation_APathOfMaxPathHopsMinusTwo_FitsTheHeadAlone()
    {
        var (parts, expected) = Chain(62, Env);

        var path = Example(parts.Analyze(), "App.C0000");

        Assert.Equal((62, 62, false), (path.Hops.Count, path.Length, path.Truncated));
        Assert.Equal(expected, path.Hops);
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
    // A PublicApi|TypeInitializer root counts in both classes.
    [Fact]
    public void Rows_OnePerSingleClassAndReachedSink_InClassThenSinkOrder_AMultiClassRootCountingInEach()
    {
        var report = new Parts()
            .Own("App.Multi", RootClass.PublicApi | RootClass.TypeInitializer)
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
                (RootClass.TypeInitializer, Capability.FileSystem), (RootClass.TypeInitializer, Capability.EnvironmentProbe), (RootClass.TypeInitializer, null),
                (RootClass.PublicApi, Capability.FileSystem), (RootClass.PublicApi, Capability.EnvironmentProbe), (RootClass.PublicApi, null),
            ],
            report.Reaches.Select(r => (r.Class, r.Capability)));
        Assert.All(report.Reaches, r => Assert.Equal((1, 1, 1), (r.Roots, r.Bound, r.Instantiated)));
        Assert.Equal("App.Multi", Assert.Single(Row(report, RootClass.TypeInitializer, Capability.FileSystem).Examples).Root);
    }

    // The three runtime classes come in their own order between HostContract and PublicApi (amendment a1): one root of
    // all three is a row in each, TypeInitializer, then Finalizer, then NativeEntry.
    [Fact]
    public void Rows_TheThreeRuntimeClasses_ComeInOrder_BetweenHostContractAndPublicApi()
    {
        var report = new Parts()
            .Own("App.All", RootClass.NativeEntry | RootClass.Finalizer | RootClass.TypeInitializer | RootClass.PublicApi | RootClass.HostContract)
            .Ext(Env)
            .Edge("App.All", Env)
            .Analyze();

        Assert.Equal(
            [RootClass.HostContract, RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry, RootClass.PublicApi],
            report.Reaches.Select(r => r.Class));
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
    public void Classes_AllEightArePresent_InOrder_WithTheirRootCounts()
    {
        var report = new Parts()
            .Own("App.a", RootClass.PublicApi)
            .Own("App.b", RootClass.PublicApi)
            .Own("App.c", RootClass.PublicApi | RootClass.TypeInitializer)
            .Own("App.d", RootClass.Hidden)
            .Own("App.e", RootClass.Finalizer | RootClass.PublicContract)
            .Own("App.f", RootClass.NativeEntry)
            .Own("App.g", RootClass.NativeEntry)
            .Analyze();

        Assert.Equal(
            [
                (RootClass.LoadTime, 0), (RootClass.HostContract, 0), (RootClass.TypeInitializer, 1), (RootClass.Finalizer, 1), (RootClass.NativeEntry, 2),
                (RootClass.PublicApi, 3), (RootClass.PublicContract, 1), (RootClass.Hidden, 1),
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
    [InlineData(UnknownCause.ReaderAssertions, "the metadata reader failed 2 assertion(s): the model may be degraded")]
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
    [InlineData(UnknownCause.ReaderAssertions)]
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
    [InlineData(UnknownCause.ReaderAssertions)]
    public void Classes_AGraphWideCause_TurnsEveryClassUnknown(UnknownCause cause)
    {
        var report = Apply(new Parts().Own("App.a", RootClass.PublicApi), cause).Analyze();

        Assert.All(report.Classes, c => Assert.Equal(RootClassVerdict.Unknown, c.Verdict));
    }

    // ADR 0022 Stage 1: reader assertions alone give every class, the empty ones included, the reader reason and only it:
    // the "member index is incomplete" reason is for the index's other counts, which are all 0 here.
    [Fact]
    public void Classes_ReaderAssertionsAlone_GiveEveryClassTheReaderReason_AndNotTheIncompleteIndexReason()
    {
        var report = Apply(new Parts().Own("App.a", RootClass.PublicApi).Own("App.h", RootClass.Hidden), UnknownCause.ReaderAssertions).Analyze();

        Assert.Equal(allClasses, report.Classes.Select(c => c.Class));
        Assert.All(report.Classes, c =>
        {
            Assert.Equal(RootClassVerdict.Unknown, c.Verdict);
            Assert.Equal(["the metadata reader failed 2 assertion(s): the model may be degraded"], c.Reasons);
        });
    }

    // ...and beside another index gap, both reasons: the incomplete index first, then the reader.
    [Fact]
    public void Classes_ReaderAssertionsWithASkippedType_GiveBothReasons()
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi);
        parts.Coverage = complete with { Index = new IndexCoverage(0, 1, 0, ReaderAssertions: 2) };

        var report = parts.Analyze();

        Assert.All(report.Classes, c =>
        {
            Assert.Equal(RootClassVerdict.Unknown, c.Verdict);
            Assert.Equal(
                [
                    "the member index is incomplete: some assemblies, types, methods, forwarders or supertypes could not be read",
                    "the metadata reader failed 2 assertion(s): the model may be degraded",
                ],
                c.Reasons);
        });
    }

    // Twin: a skipped type alone gives the incomplete-index reason and no reader reason.
    [Fact]
    public void Classes_ASkippedTypeAlone_GivesNoReaderReason()
    {
        var report = Apply(new Parts().Own("App.a", RootClass.PublicApi), UnknownCause.TypesSkipped).Analyze();

        Assert.All(report.Classes, c => Assert.DoesNotContain(c.Reasons, r => r.Contains("metadata reader", StringComparison.Ordinal)));
    }

    // A gap covers the classes its mask overlaps, and only those.
    [Fact]
    public void Classes_AGap_CoversExactlyTheClassesItsMaskOverlaps()
    {
        var parts = new Parts().Own("App.a", RootClass.PublicApi).Own("App.h", RootClass.Hidden).Own("App.r", RootClass.TypeInitializer)
            .Own("App.f", RootClass.Finalizer).Own("App.n", RootClass.NativeEntry);
        parts.Gaps.Add(new RootGap(Assembly, RootClass.PublicApi | RootClass.Hidden, "visibility"));
        parts.Gaps.Add(new RootGap("Other", RootClass.LoadTime, "module"));
        parts.Gaps.Add(new RootGap("Native", RootClass.Finalizer, "finalizers"));

        var report = parts.Analyze();

        Assert.Equal(
            [
                (RootClass.LoadTime, RootClassVerdict.Unknown), (RootClass.HostContract, RootClassVerdict.None), (RootClass.TypeInitializer, RootClassVerdict.None),
                (RootClass.Finalizer, RootClassVerdict.Unknown), (RootClass.NativeEntry, RootClassVerdict.None),
                (RootClass.PublicApi, RootClassVerdict.Unknown), (RootClass.PublicContract, RootClassVerdict.None), (RootClass.Hidden, RootClassVerdict.Unknown),
            ],
            report.Classes.Select(c => (c.Class, c.Verdict)));
        Assert.Equal(["Other: module"], Status(report, RootClass.LoadTime).Reasons);
        Assert.Equal(["App: visibility"], Status(report, RootClass.Hidden).Reasons);
        Assert.Equal(["Native: finalizers"], Status(report, RootClass.Finalizer).Reasons);
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
    // The Direct label (ADR 0037 amendment a2)
    // ---------------------------------------------------------------------------------------------------

    public static TheoryData<MethodEdgeKind> EdgeKinds() => [.. Enum.GetValues<MethodEdgeKind>()];

    // Exactly the deferred edges, which make a method value without calling it - Ldftn and Ldvirtftn (a delegate or a
    // function pointer) and LoadToken (a method handle; ADR a2's clarification, review W3) - take the label away. Every
    // other kind (a new one included, since the theory enumerates the enum) keeps the path Direct, Dispatch to a dead
    // type too: ChaOnly, yet Direct.
    [Theory]
    [MemberData(nameof(EdgeKinds))]
    public void Direct_APath_IsDirectExactlyWhenNoEdgeOnItIsLdftnLdvirtftnOrLoadToken(MethodEdgeKind kind)
    {
        var direct = kind is not (MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn or MethodEdgeKind.LoadToken);

        var row = Row(DispatchCase(DispatchTarget.DeadInstance, kind).Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe);

        Assert.Equal((1, direct ? 1 : 0), (row.Roots, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.Equal(direct, path.Direct);
        Assert.Equal(kind == MethodEdgeKind.Dispatch ? ReachEvidence.ChaOnly : ReachEvidence.Bound, path.Evidence);
    }

    // A deferred edge anywhere on the path takes the label away: the root's own edge, one in the middle, or the last
    // one, an ldftn (or ldtoken) of the sink itself. The reach is still reported, Bound (a deferred edge is in every tier).
    [Theory]
    [InlineData(MethodEdgeKind.Ldftn, 0)]
    [InlineData(MethodEdgeKind.Ldftn, 1)]
    [InlineData(MethodEdgeKind.Ldftn, 2)]
    [InlineData(MethodEdgeKind.Ldvirtftn, 0)]
    [InlineData(MethodEdgeKind.Ldvirtftn, 1)]
    [InlineData(MethodEdgeKind.Ldvirtftn, 2)]
    [InlineData(MethodEdgeKind.LoadToken, 0)]
    [InlineData(MethodEdgeKind.LoadToken, 1)]
    [InlineData(MethodEdgeKind.LoadToken, 2)]
    public void Direct_ADeferredEdgeAnywhereOnThePath_MakesItNotDirect(MethodEdgeKind kind, int at)
    {
        MethodEdgeKind KindAt(int i) => i == at ? kind : MethodEdgeKind.Call;
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.B", RootClass.None)
            .Own("App.C", RootClass.None)
            .Ext(Env)
            .Edge("App.A", "App.B", KindAt(0), 1)
            .Edge("App.B", "App.C", KindAt(1), 2)
            .Edge("App.C", Env, KindAt(2), 3)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((1, 1, 1, 0), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.False(path.Direct);
        AssertPath(path, "App.A", ReachEvidence.Bound, null,
            OwnHop("App.A"), OwnHop("App.B", KindAt(0), 1), OwnHop("App.C", KindAt(1), 2), new ReachHop(Env, null, KindAt(2), 3));
        Assert.Empty(Assert.Single(report.Profiles).DirectCapabilities);
    }

    // CapabilityReach.Direct counts every root with a delegate-free path, whichever path its example shows: R0 only through
    // a delegate, R1 only directly, R2 both (its shortest path, so its Bound example, being the delegate one).
    [Fact]
    public void Direct_TheRowCountsEveryRootWithADelegateFreePath()
    {
        var report = new Parts()
            .Own("App.R0", RootClass.PublicApi)
            .Own("App.R1", RootClass.PublicApi)
            .Own("App.R2", RootClass.PublicApi)
            .Own("App.M", RootClass.None)
            .Ext(Env)
            .Edge("App.R0", Env, MethodEdgeKind.Ldftn, 1)
            .Edge("App.R1", Env, MethodEdgeKind.Call, 1)
            .Edge("App.R2", Env, MethodEdgeKind.Ldftn, 1)
            .Edge("App.R2", "App.M", MethodEdgeKind.Call, 2)
            .Edge("App.M", Env, MethodEdgeKind.Call, 3)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((3, 3, 3, 2), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        Assert.Equal([("App.R1", true), ("App.R0", false), ("App.R2", false)], row.Examples.Select(e => (e.Root, e.Direct)));
    }

    // Example choice, evidence first: a Bound path through a delegate is kept over a ChaOnly Direct path of the same root,
    // which the row still counts as Direct.
    [Fact]
    public void Examples_ABoundPathThroughADelegate_IsKeptOverAChaOnlyDirectPath()
    {
        var report = new Parts()
            .Own("App.R", RootClass.PublicApi)
            .Own("App.P", RootClass.None)
            .Own("App.Dead.M", RootClass.None, type: "App.Dead")
            .Type("App.Dead", live: false)
            .Ext(Env)
            .Edge("App.R", "App.P", MethodEdgeKind.Ldftn, 1)
            .Edge("App.P", Env, MethodEdgeKind.Call, 2)
            .Edge("App.R", "App.Dead.M", MethodEdgeKind.Dispatch, 3)
            .Edge("App.Dead.M", Env, MethodEdgeKind.Call, 4)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.False(path.Direct);
        AssertPath(path, "App.R", ReachEvidence.Bound, null, OwnHop("App.R"), OwnHop("App.P", MethodEdgeKind.Ldftn, 1), new ReachHop(Env, null, MethodEdgeKind.Call, 2));
    }

    // At ChaOnly, a Direct path wins over a shorter one through a delegate: R's ChaOnly-shortest path (3 hops) ends in an
    // ldftn, so the example is its Direct path (4 hops), still ChaOnly.
    [Fact]
    public void Examples_AtChaOnly_ADirectPath_BeatsAShorterOneThroughADelegate()
    {
        var path = Assert.Single(Row(ChaOnlyDelegateCase(withDirectPath: true).Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe).Examples);

        Assert.True(path.Direct);
        AssertPath(path, "App.R", ReachEvidence.ChaOnly, null,
            OwnHop("App.R"), new ReachHop("App.D2.M", Assembly, MethodEdgeKind.Dispatch, 2), OwnHop("App.X", MethodEdgeKind.Call, 4), new ReachHop(Env, null, MethodEdgeKind.Call, 5));
    }

    // The same with an ldtoken of the sink in place of the ldftn (review W3): the 3-hop LoadToken path is not Direct, so
    // the 4-hop Direct path is the example; without that path, the LoadToken one stays and the row has no Direct root.
    [Fact]
    public void Examples_AtChaOnly_ALoadTokenPathIsNotDirect_SoADirectPathBeatsIt()
    {
        var withDirect = Row(ChaOnlyDelegateCase(withDirectPath: true, MethodEdgeKind.LoadToken).Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe);
        var without = Row(ChaOnlyDelegateCase(withDirectPath: false, MethodEdgeKind.LoadToken).Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe);

        Assert.Equal((1, 1), (withDirect.Roots, withDirect.Direct));
        var path = Assert.Single(withDirect.Examples);
        Assert.True(path.Direct);
        AssertPath(path, "App.R", ReachEvidence.ChaOnly, null,
            OwnHop("App.R"), new ReachHop("App.D2.M", Assembly, MethodEdgeKind.Dispatch, 2), OwnHop("App.X", MethodEdgeKind.Call, 4), new ReachHop(Env, null, MethodEdgeKind.Call, 5));
        Assert.Equal((1, 0), (without.Roots, without.Direct));
        Assert.False(Assert.Single(without.Examples).Direct);
        AssertPath(without.Examples[0], "App.R", ReachEvidence.ChaOnly, null,
            OwnHop("App.R"), new ReachHop("App.D1.M", Assembly, MethodEdgeKind.Dispatch, 1), new ReachHop(Env, null, MethodEdgeKind.LoadToken, 3));
    }

    // Twin: without a Direct path the ChaOnly example is the shortest, through the delegate, and the row has no Direct root.
    [Fact]
    public void Examples_AtChaOnly_WithoutADirectPath_TheShortestPathThroughTheDelegateStays()
    {
        var row = Row(ChaOnlyDelegateCase(withDirectPath: false).Analyze(), RootClass.PublicApi, Capability.EnvironmentProbe);

        Assert.Equal((1, 0, 0, 0), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.False(path.Direct);
        AssertPath(path, "App.R", ReachEvidence.ChaOnly, null,
            OwnHop("App.R"), new ReachHop("App.D1.M", Assembly, MethodEdgeKind.Dispatch, 1), new ReachHop(Env, null, MethodEdgeKind.Ldftn, 3));
    }

    // Across roots, examples order by evidence, then Direct first, then length, then node order: R2 (Bound, Direct, 2
    // hops), R1 (Bound, Direct, 3), then R0 (Bound, via a delegate, 2) before R3 (the same, later in node order), and the
    // Instantiated Direct R4 last, cut. Without length R1 would lead R2; without Direct R0 would lead R1.
    [Fact]
    public void Examples_OrderByEvidence_ThenDirectFirst_ThenLength_ThenNodeOrder()
    {
        var report = new Parts()
            .Own("App.R0", RootClass.PublicApi)
            .Own("App.R1", RootClass.PublicApi)
            .Own("App.R2", RootClass.PublicApi)
            .Own("App.R3", RootClass.PublicApi)
            .Own("App.R4", RootClass.PublicApi)
            .Own("App.M1", RootClass.None)
            .Own("App.Live.M", RootClass.None, type: "App.Live")
            .Type("App.Live", live: true)
            .Ext(Env)
            .Edge("App.R0", Env, MethodEdgeKind.Ldftn, 1)
            .Edge("App.R1", "App.M1", MethodEdgeKind.Call, 1)
            .Edge("App.M1", Env, MethodEdgeKind.Call, 2)
            .Edge("App.R2", Env, MethodEdgeKind.Call, 1)
            .Edge("App.R3", Env, MethodEdgeKind.Ldvirtftn, 1)
            .Edge("App.R4", "App.Live.M", MethodEdgeKind.Dispatch, 1)
            .Edge("App.Live.M", Env, MethodEdgeKind.Call, 2)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((5, 4, 5, 3), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        Assert.Equal(
            [("App.R2", ReachEvidence.Bound, true, 2), ("App.R1", ReachEvidence.Bound, true, 3), ("App.R0", ReachEvidence.Bound, false, 2)],
            row.Examples.Select(e => (e.Root, e.Evidence, e.Direct, e.Length)));
    }

    // Evidence beats Direct across roots: a Bound root through a delegate, then an Instantiated Direct one, then a ChaOnly
    // Direct one.
    [Fact]
    public void Examples_ABoundRootThroughADelegate_LeadsInstantiatedAndChaOnlyDirectRoots()
    {
        var report = new Parts()
            .Own("App.Q0", RootClass.PublicApi)
            .Own("App.Q1", RootClass.PublicApi)
            .Own("App.Q2", RootClass.PublicApi)
            .Own("App.Live.M", RootClass.None, type: "App.Live")
            .Own("App.Dead.M", RootClass.None, type: "App.Dead")
            .Type("App.Live", live: true)
            .Type("App.Dead", live: false)
            .Ext(Env)
            .Edge("App.Q2", Env, MethodEdgeKind.Ldftn, 1)
            .Edge("App.Q1", "App.Live.M", MethodEdgeKind.Dispatch, 1)
            .Edge("App.Live.M", Env, MethodEdgeKind.Call, 2)
            .Edge("App.Q0", "App.Dead.M", MethodEdgeKind.Dispatch, 1)
            .Edge("App.Dead.M", Env, MethodEdgeKind.Call, 2)
            .Analyze();

        Assert.Equal(
            [("App.Q2", ReachEvidence.Bound, false), ("App.Q1", ReachEvidence.Instantiated, true), ("App.Q0", ReachEvidence.ChaOnly, true)],
            Row(report, RootClass.PublicApi, Capability.EnvironmentProbe).Examples.Select(e => (e.Root, e.Evidence, e.Direct)));
    }

    // Profiles group by the ChaOnly mask AND the Direct mask: a and b (Env direct, Network only through a delegate) are one
    // profile, c and f (both direct) another with the same ChaOnly mask, ordered after it by Direct mask; Unseen through a
    // delegate (d) and directly (e) differ in DirectUnseen alone.
    [Fact]
    public void Profiles_GroupByTheChaOnlyMaskAndTheDirectMask_WithTheDirectCapabilitiesAndUnseen()
    {
        var parts = new Parts()
            .Own("App.P", RootClass.None)
            .Own("App.Q", RootClass.None)
            .Ext(Env, Net, Dyn)
            .Edge("App.P", Net)
            .Edge("App.Q", Net);
        foreach (var root in new[] { "App.a", "App.b" })
            parts.Own(root, RootClass.PublicApi).Edge(root, Env).Edge(root, "App.P", MethodEdgeKind.Ldftn);
        foreach (var root in new[] { "App.c", "App.f" })
            parts.Own(root, RootClass.PublicApi).Edge(root, Env).Edge(root, "App.Q");
        parts.Own("App.d", RootClass.PublicApi).Edge("App.d", Dyn, MethodEdgeKind.Ldvirtftn);
        parts.Own("App.e", RootClass.PublicApi).Edge("App.e", Dyn);

        var report = parts.Analyze();

        Assert.Equal(
            [
                "PublicApi [Network,EnvironmentProbe] False [EnvironmentProbe] False 2 App.a",
                "PublicApi [Network,EnvironmentProbe] False [Network,EnvironmentProbe] False 2 App.c",
                "PublicApi [] True [] False 1 App.d",
                "PublicApi [] True [] True 1 App.e",
            ],
            report.Profiles.Select(DescribeDirect));
        Assert.Equal(2, Row(report, RootClass.PublicApi, null).Roots);
        Assert.Equal(1, Row(report, RootClass.PublicApi, null).Direct);
        Assert.Equal(2, Row(report, RootClass.PublicApi, Capability.Network).Direct);
        Assert.Equal(4, Row(report, RootClass.PublicApi, Capability.EnvironmentProbe).Direct);
    }

    // An Unseen sink reached only through a delegate is not Direct: unanalyzed external, and an opacity site, whose
    // example still names its opacity. The class is still Unknown: Direct changes the claim, never the verdict.
    [Fact]
    public void Direct_AnUnseenSinkReachedThroughADelegate_IsNotDirect_AndTheClassIsStillUnknown()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.Opaque", RootClass.None)
            .Ext(Dyn)
            .Edge("App.A", Dyn, MethodEdgeKind.Ldftn, 1)
            .Edge("App.A", "App.Opaque", MethodEdgeKind.Ldftn, 2)
            .Opacity("App.Opaque", OpacityKind.IndirectCall, 7)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, null);
        Assert.Equal((1, 1, 0), (row.Roots, row.Bound, row.Direct));
        var path = Assert.Single(row.Examples);
        Assert.False(path.Direct);
        AssertPath(path, "App.A", ReachEvidence.Bound, OpacityKind.IndirectCall, OwnHop("App.A"), OwnHop("App.Opaque", MethodEdgeKind.Ldftn, 2));
        var profile = Assert.Single(report.Profiles);
        Assert.Equal((true, false), (profile.Unseen, profile.DirectUnseen));
        Assert.Equal(RootClassVerdict.Unknown, Status(report, RootClass.PublicApi).Verdict);
    }

    // Twin: the same Unseen sinks called directly are Direct.
    [Fact]
    public void Direct_AnUnseenSinkCalledDirectly_IsDirect()
    {
        var report = new Parts()
            .Own("App.A", RootClass.PublicApi)
            .Own("App.Opaque", RootClass.None)
            .Ext(Dyn)
            .Edge("App.A", Dyn, MethodEdgeKind.Call, 1)
            .Edge("App.A", "App.Opaque", MethodEdgeKind.Call, 2)
            .Opacity("App.Opaque", OpacityKind.IndirectCall, 7)
            .Analyze();

        var row = Row(report, RootClass.PublicApi, null);
        Assert.Equal((1, 1), (row.Roots, row.Direct));
        Assert.True(Assert.Single(row.Examples).Direct);
        Assert.True(Assert.Single(report.Profiles).DirectUnseen);
    }

    // A root that is itself a sink has a one-hop path, which crosses no edge: Direct.
    [Fact]
    public void Direct_ARootThatIsItselfASink_IsDirect()
    {
        var report = new Parts().Own("App.Native", RootClass.PublicApi, native: true).Analyze();

        var row = Row(report, RootClass.PublicApi, Capability.NativeInterop);
        Assert.Equal(1, row.Direct);
        Assert.True(Assert.Single(row.Examples).Direct);
    }

    // The Direct label against a forward oracle on the seeded random graphs, each root alone: the row's Direct count is
    // whether a ChaOnly path free of deferred edges exists; a path's label is whether its hops cross one; a ChaOnly
    // example is Direct whenever a Direct path exists, and then is the shortest such; a Bound or Instantiated example is
    // its tier's shortest path, Direct or not.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(2026)]
    public void Direct_PerRoot_AgreesWithAForwardOracle(int seed)
    {
        var parts = RandomParts(seed);
        var oracle = new Oracle(parts, map);
        var (direct, indirect) = (0, 0);

        foreach (var root in parts.Methods.Select(m => m.NodeId))
        {
            var report = parts.Copy(m => m with { Roots = m.NodeId == root ? RootClass.PublicApi : RootClass.None }).Analyze();
            for (var sink = 0; sink < Sinks; sink++)
            {
                var capability = sink < Sinks - 1 ? (Capability?)sink : null;
                var row = report.Reaches.SingleOrDefault(r => r.Class == RootClass.PublicApi && r.Capability == capability);
                if (row is null)
                    continue;
                var directDistance = oracle.DirectDistance(root, sink);
                Assert.Equal(directDistance is null ? 0 : 1, row.Direct);

                var path = Assert.Single(row.Examples);
                Assert.False(path.Truncated);
                Assert.Equal(path.Hops.Skip(1).All(h => h.Via is not (MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn or MethodEdgeKind.LoadToken)), path.Direct);
                if (path.Evidence == ReachEvidence.ChaOnly)
                {
                    Assert.Equal(directDistance is not null, path.Direct);
                    if (path.Direct)
                        oracle.AssertDirectShortestPath(path, sink, directDistance!.Value);
                }
                else
                    oracle.AssertShortestPath(path, sink, oracle.Distance(root, path.Evidence, sink)!.Value);
                (direct, indirect) = path.Direct ? (direct + 1, indirect) : (direct, indirect + 1);
            }
        }

        Assert.True(direct > 0 && indirect > 0, $"seed {seed}: {direct} Direct and {indirect} non-Direct examples; pick another seed");
    }

    // ...and with every root at once, the row's Direct count is the oracle's count of roots with a Direct path.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(2026)]
    public void Direct_AllRootsTogether_CountsAreTheOraclesDirectCounts(int seed)
    {
        var parts = RandomParts(seed);
        var oracle = new Oracle(parts, map);
        var report = parts.Analyze();
        var roots = parts.Methods.Select(m => m.NodeId).ToArray();

        for (var sink = 0; sink < Sinks; sink++)
        {
            var capability = sink < Sinks - 1 ? (Capability?)sink : null;
            var row = report.Reaches.SingleOrDefault(r => r.Class == RootClass.PublicApi && r.Capability == capability);
            Assert.Equal(roots.Count(r => oracle.DirectDistance(r, sink) is not null), row?.Direct ?? 0);
            Assert.True(row is null || row.Direct <= row.Roots);
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // Name bounding (ADR 0037 amendment a5)
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void BoundName_Premise_MaxNameCharsIs1024()
    {
        Assert.Equal(1024, Reachability.MaxNameChars);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1023)]
    [InlineData(1024)]
    public void BoundName_ANameOfAtMostMaxNameChars_IsUnchanged(int length)
    {
        var name = new string('n', length);

        Assert.Equal(name, Reachability.BoundName(name));
    }

    // One char over: the first 1,024 kept, then "…[+1 chars, sha256:<8 hex>]".
    [Fact]
    public void BoundName_1025Chars_KeepsTheFirst1024_ThenTheCutCountAndHash()
    {
        var name = new string('a', 1024) + "Z";

        Assert.Equal(new string('a', 1024) + $"…[+1 chars, sha256:{Hash8(name)}]", Reachability.BoundName(name));
    }

    // N is the chars cut, and the hash is over the WHOLE name's UTF-16 code units (not UTF-8, not the kept part; review
    // Nit 1): 8 lower-case hex. For a well-formed name the code units are Encoding.Unicode's bytes.
    [Fact]
    public void BoundName_TheSuffix_CountsTheCharsCut_AndHashesTheWholeNamesUtf16CodeUnits()
    {
        var name = "N." + new string('é', 3000);

        var bounded = Reachability.BoundName(name);

        Assert.Equal($"{name[..1024]}…[+{name.Length - 1024} chars, sha256:{Hash8(name)}]", bounded);
        Assert.Matches("sha256:[0-9a-f]{8}\\]$", bounded);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.Unicode.GetBytes(name)))[..8], Hash8(name));
        Assert.NotEqual(Utf8Hash8(name), Hash8(name));
        Assert.NotEqual(Hash8(name[..1024]), Hash8(name));
    }

    // Names differing only in a lone surrogate past char 1,024 bound to different strings (review Nit 1): UTF-8 would
    // replace each lone surrogate, and a real U+FFFD, by the same EF BF BD, so the three would share one hash. Each hash
    // is SHA-256 over the name's UTF-16 code units, the lone surrogate included.
    [Fact]
    public void BoundName_NamesDifferingOnlyInALoneSurrogatePastTheLimit_BoundDifferently()
    {
        var (prefix, suffix) = (new string('a', 1500), new string('b', 10));
        string[] names = [prefix + '\uD800' + suffix, prefix + '\uDFFF' + suffix, prefix + '�' + suffix];
        Assert.Single(names.Select(Utf8Hash8).Distinct());   // the premise: UTF-8 cannot tell them apart

        var bounded = names.Select(Reachability.BoundName).ToArray();

        Assert.Equal(3, bounded.Distinct(StringComparer.Ordinal).Count());
        Assert.All(names.Zip(bounded), p => Assert.Equal($"{prefix[..1024]}…[+{p.First.Length - 1024} chars, sha256:{Hash8(p.First)}]", p.Second));
        Assert.All(bounded, AssertWellFormed);   // the lone surrogate is in the cut part, never in the report
    }

    // A surrogate pair across the limit (high surrogate at index 1023) is not split: 1,023 chars are kept, N counts from
    // there, and the result is well-formed UTF-16.
    [Fact]
    public void BoundName_ASurrogatePairStraddlingTheLimit_IsNotSplit()
    {
        var name = new string('a', 1023) + "\U0001F600" + new string('b', 10);
        Assert.True(char.IsHighSurrogate(name[1023]) && char.IsLowSurrogate(name[1024]));   // the premise

        var bounded = Reachability.BoundName(name);

        Assert.Equal(new string('a', 1023) + $"…[+12 chars, sha256:{Hash8(name)}]", bounded);
        AssertWellFormed(bounded);
    }

    // A pair just inside the limit (1022-1023) and one just after it (1024-1025) are each kept whole or cut whole.
    [Theory]
    [InlineData(1022, 1024)]
    [InlineData(1024, 1024)]
    public void BoundName_ASurrogatePairBesideTheLimit_IsKeptOrCutWhole(int pairAt, int kept)
    {
        var name = new string('a', pairAt) + "\U0001F600" + new string('b', 5);

        var bounded = Reachability.BoundName(name);

        Assert.Equal($"{name[..kept]}…[+{name.Length - kept} chars, sha256:{Hash8(name)}]", bounded);
        AssertWellFormed(bounded);
    }

    // Two names of one length sharing their first 1,024 chars stay distinct, by their hash.
    [Fact]
    public void BoundName_TwoNamesSharingTheirFirst1024Chars_StayDistinct()
    {
        var prefix = new string('p', 1500);
        var (a, b) = (Reachability.BoundName(prefix + "A"), Reachability.BoundName(prefix + "B"));

        Assert.NotEqual(a, b);
        Assert.Equal(a[..1024], b[..1024]);
        Assert.Equal(Reachability.BoundName(prefix + "A"), a);   // and the same name bounds the same way every time
    }

    // BoundNameTo(name, maxChars) (reachability R3, S0): the same cut at a caller's limit.
    [Theory]
    [InlineData(1, 0)]
    [InlineData(1, 1)]
    [InlineData(256, 255)]
    [InlineData(256, 256)]
    public void BoundNameTo_ANameOfAtMostMaxChars_IsUnchanged(int maxChars, int length)
    {
        var name = new string('n', length);

        Assert.Equal(name, Reachability.BoundNameTo(name, maxChars));
    }

    [Theory]
    [InlineData(256, 257)]
    [InlineData(256, 1000)]
    [InlineData(1, 2)]
    public void BoundNameTo_OverTheLimit_KeepsTheFirstMaxChars_ThenTheCutCountAndHash(int maxChars, int length)
    {
        var name = string.Concat(Enumerable.Range(0, length).Select(i => (char)('a' + i % 26)));

        Assert.Equal($"{name[..maxChars]}…[+{length - maxChars} chars, sha256:{Hash8(name)}]", Reachability.BoundNameTo(name, maxChars));
    }

    [Fact]
    public void BoundNameTo_ASurrogatePairStraddlingTheLimit_IsNotSplit()
    {
        var name = new string('a', 255) + "\U0001F600" + new string('b', 4);
        Assert.True(char.IsHighSurrogate(name[255]) && char.IsLowSurrogate(name[256]));   // the premise

        var bounded = Reachability.BoundNameTo(name, 256);

        Assert.Equal(new string('a', 255) + $"…[+6 chars, sha256:{Hash8(name)}]", bounded);
        AssertWellFormed(bounded);
    }

    // At a limit of one, a leading pair is cut whole: nothing of the name is kept, only the suffix.
    [Fact]
    public void BoundNameTo_OfOne_ALeadingSurrogatePair_IsCutWhole()
    {
        var name = "\U0001F600x";

        var bounded = Reachability.BoundNameTo(name, 1);

        Assert.Equal($"…[+3 chars, sha256:{Hash8(name)}]", bounded);
        AssertWellFormed(bounded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void BoundNameTo_AMaxBelowOne_ThrowsArgumentOutOfRange(int maxChars)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Reachability.BoundNameTo(string.Empty, maxChars));
        Assert.Throws<ArgumentOutOfRangeException>(() => Reachability.BoundNameTo(new string('a', 2000), maxChars));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(3000)]
    public void BoundName_EqualsBoundNameToAt1024(int length)
    {
        var name = new string('q', length);

        Assert.Equal(Reachability.BoundNameTo(name, 1024), Reachability.BoundName(name));
    }

    [Fact]
    public void BoundName_EqualsBoundNameToAt1024_ForAPairStraddlingTheLimit()
    {
        var name = new string('a', 1023) + "\U0001F600" + new string('b', 10);

        Assert.Equal(Reachability.BoundNameTo(name, 1024), Reachability.BoundName(name));
    }

    // In a report, every name field is bounded - hop node ids and assemblies, path roots, profile example roots, ignored
    // edge keys, and a gap reason's assembly - and NamesCut counts each distinct long name once, however often it is
    // reported: longA (two rows, a profile, its hops), longB (sharing longA's first 1,024 chars), the assembly (every own
    // hop), and the two ignored-edge keys. Five.
    [Fact]
    public void NameBounding_EveryReportedNameField_IsBounded_AndNamesCutCountsEachDistinctNameOnce()
    {
        var shared = "App." + new string('a', 1500);
        var (longA, longB) = (shared + ".A()", shared + ".B()");
        var assembly = "Asm." + new string('m', 2000);
        var (callerKey, calleeKey) = ("App.Cutter." + new string('k', 1100), "Ext.Net." + new string('n', 1100));
        var parts = new Parts()
            .Own(longA, RootClass.PublicApi | RootClass.TypeInitializer)
            .Own(longB, RootClass.PublicApi)
            .Own("App.Mid", RootClass.None)
            .Own("App.Cutter", RootClass.Hidden, key: callerKey)
            .Node("Ext.Net.X", MethodNodeKind.External, key: calleeKey)
            .Ext(Env, File)
            .Edge(longA, "App.Mid", MethodEdgeKind.Call, 1)
            .Edge("App.Mid", Env, MethodEdgeKind.Call, 2)
            .Edge(longA, File, MethodEdgeKind.Call, 3)
            .Edge(longB, Env, MethodEdgeKind.Call, 4)
            .Edge("App.Cutter", "Ext.Net.X", MethodEdgeKind.Call, 5)
            .Copy(m => m with { Assembly = assembly });
        parts.Gaps.Add(new RootGap(assembly, RootClass.PublicApi, "synthetic gap"));
        Assert.True(map.IsIgnoredEdge(callerKey, calleeKey));   // the premise

        var report = parts.Analyze();

        Assert.Equal(5, report.NamesCut);
        var (boundA, boundB, boundAssembly) = (Reachability.BoundName(longA), Reachability.BoundName(longB), Reachability.BoundName(assembly));
        Assert.NotEqual(boundA, boundB);
        var env = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal([boundB, boundA], env.Examples.Select(e => e.Root));   // longB's path is the shorter
        Assert.Equal(
            [new ReachHop(boundA, boundAssembly, null, 0), new ReachHop("App.Mid", boundAssembly, MethodEdgeKind.Call, 1), new ReachHop(Env, null, MethodEdgeKind.Call, 2)],
            env.Examples[1].Hops);
        Assert.Equal(boundA, Assert.Single(Row(report, RootClass.TypeInitializer, Capability.FileSystem).Examples).Root);
        Assert.Equal([boundA, boundB], report.Profiles.Where(p => p.Class == RootClass.PublicApi).Select(p => p.ExampleRoot).Order(StringComparer.Ordinal));
        Assert.Equal([new IgnoredEdge(Reachability.BoundName(callerKey), Reachability.BoundName(calleeKey))], report.IgnoredEdges);
        Assert.Contains($"{boundAssembly}: synthetic gap", Status(report, RootClass.PublicApi).Reasons);

        var names = report.Reaches.SelectMany(r => r.Examples).SelectMany(p => p.Hops.SelectMany(h => new[] { h.NodeId, h.Assembly }).Append(p.Root))
            .Concat(report.Profiles.Select(p => p.ExampleRoot))
            .Concat(report.IgnoredEdges.SelectMany(e => new[] { e.Caller, e.Callee }))
            .OfType<string>().ToArray();
        Assert.All(names, n => Assert.True(n.Length <= Reachability.MaxNameChars + 64, $"{n.Length} chars"));
        Assert.DoesNotContain(names, n => n is { Length: > 1024 } && !n.Contains("…[+", StringComparison.Ordinal));
        Assert.All(report.Classes.SelectMany(c => c.Reasons), r => Assert.True(r.Length <= Reachability.MaxNameChars + 128, $"{r.Length} chars"));
    }

    // The same long name reported many times - one root id in two classes' rows and its profiles, one assembly on every own
    // hop - is cut once each: NamesCut 2.
    [Fact]
    public void NameBounding_TheSameLongNameReportedManyTimes_CountsOnce()
    {
        var root = "App." + new string('r', 1200) + "()";
        var assembly = "Asm." + new string('m', 1200);
        var parts = new Parts()
            .Own(root, RootClass.PublicApi | RootClass.TypeInitializer | RootClass.Finalizer)
            .Own("App.B", RootClass.Hidden)
            .Own("App.C", RootClass.Hidden)
            .Ext(Env, File, Net)
            .Edge(root, "App.B")
            .Edge("App.B", "App.C")
            .Edge("App.C", Env)
            .Edge(root, File)
            .Edge("App.B", Net)
            .Copy(m => m with { Assembly = assembly });

        var report = parts.Analyze();

        Assert.True(report.Reaches.Count(r => r.Examples.Any(e => e.Root == Reachability.BoundName(root))) >= 9);
        Assert.Equal(2, report.NamesCut);
    }

    // Exactly MaxNameChars is no cut: the name is reported whole and NamesCut is 0; and an ordinary report cuts nothing.
    [Fact]
    public void NameBounding_ANameOfExactlyMaxNameChars_IsReportedWhole_AndCutsNothing()
    {
        var root = "App." + new string('r', Reachability.MaxNameChars - 4);
        Assert.Equal(Reachability.MaxNameChars, root.Length);

        var report = new Parts().Own(root, RootClass.PublicApi).Ext(Env).Edge(root, Env).Analyze();

        Assert.Equal(root, Assert.Single(Row(report, RootClass.PublicApi, Capability.EnvironmentProbe).Examples).Root);
        Assert.Equal(0, report.NamesCut);
        Assert.Equal(0, RandomParts(1).Analyze().NamesCut);
    }

    // A failed analysis reports no names, so cuts none.
    [Fact]
    public void NameBounding_AFailedAnalysis_HasNamesCutZero()
    {
        var parts = new Parts().Own("App." + new string('x', 2000), RootClass.PublicApi);
        parts.Methods.Add(parts.Methods[0]);

        var report = parts.Analyze();

        Assert.True(report.Partial);
        Assert.Equal(0, report.NamesCut);
    }

    // A failure's exception text is bounded too (review Nit 2). Duplicated facts make the analysis's dictionary throw an
    // ArgumentException naming the key, so a 5,000-char node id gives a message over the limit: every class's reason and
    // PartialReason carry BoundName of it, and the raw id is in neither.
    [Fact]
    public void NameBounding_AFailedAnalysisWithALongExceptionMessage_BoundsItsReasonsAndPartialReason()
    {
        var id = "App." + new string('x', 5000);
        var parts = new Parts().Own(id, RootClass.PublicApi);
        parts.Methods.Add(parts.Methods[0]);
        // The message the analysis's own ToDictionary over the facts throws, rebuilt the same way.
        var message = Assert.IsType<ArgumentException>(Record.Exception(() => parts.Methods.ToDictionary(f => f.NodeId, StringComparer.Ordinal))).Message;
        Assert.True(message.Length > Reachability.MaxNameChars && message.Contains(id, StringComparison.Ordinal));   // the premise

        var report = parts.Analyze();

        Assert.True(report.Partial);
        Assert.Equal(Reachability.BoundName(message), report.PartialReason);
        Assert.All(report.Classes, c => Assert.Equal([$"reachability could not be computed: {Reachability.BoundName(message)}"], c.Reasons));
        Assert.All(report.Classes.SelectMany(c => c.Reasons).Append(report.PartialReason!), r =>
        {
            Assert.True(r.Length <= Reachability.MaxNameChars + 128, $"{r.Length} chars");
            Assert.DoesNotContain(id, r, StringComparison.Ordinal);
        });
    }

    // ---------------------------------------------------------------------------------------------------
    // Scale (review W1)
    // ---------------------------------------------------------------------------------------------------

    // Ordering a row's examples once walked every reaching root's whole path, so a chain of N roots cost O(N²): 160,000
    // took 110 s. Walk lengths are now memoised per sink and pass, O(N). Here a chain of 100,000 PublicApi roots
    // L000000 -> ... -> L099999 -> Env, every one reaching Env, with an ldftn into L099998, so the memo carries the deferred
    // bit down 99,997 nodes. The bound is deliberately generous, for a slow CI box: a linear run takes about a second here,
    // while the quadratic one would take about 43 s on the box that measured 110 s (scaled by (100/160)²). So 20 s still
    // fails the regression on any box where the quadratic run is slower than that, and passes wherever the linear run is
    // within 20x of this one. Only Analyze is timed, not building the graph.
    [Fact]
    public void Scale_AChainOfAHundredThousandRoots_IsAnalysedInLinearTime_AndAgreesWithTheForwardOracle()
    {
        const int n = 100_000;
        static string L(int i) => $"App.L{i:000000}";
        var parts = new Parts().Ext(Env);
        for (var i = 0; i < n; i++)
            parts.Own(L(i), RootClass.PublicApi);
        for (var i = 0; i < n - 1; i++)
            parts.Edge(L(i), L(i + 1), i == n - 3 ? MethodEdgeKind.Ldftn : MethodEdgeKind.Call, (uint)i);
        parts.Edge(L(n - 1), Env, MethodEdgeKind.Call, n - 1);
        var graph = parts.Graph();

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var report = Reachability.Analyze(graph, map);
        clock.Stop();

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20), $"Analyze over a {n:N0}-root chain took {clock.Elapsed.TotalSeconds:F1} s: the example ordering is no longer linear (review W1)");
        Assert.False(report.Partial, report.PartialReason);
        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Single(report.Reaches);
        // Every root reaches Env, in every tier (no Dispatch edge); only the two below the ldftn without a deferred edge.
        Assert.Equal((n, n, n, 2), (row.Roots, row.Bound, row.Instantiated, row.Direct));
        // Bound throughout, so Direct first, then length: L099999 (2 hops) and L099998 (3), then L099997 through the ldftn (4).
        Assert.Equal([(L(n - 1), true, 2), (L(n - 2), true, 3), (L(n - 3), false, 4)], row.Examples.Select(e => (e.Root, e.Direct, e.Length)));
        Assert.Equal(
            [$"PublicApi [EnvironmentProbe] False [] False {n - 2} {L(0)}", $"PublicApi [EnvironmentProbe] False [EnvironmentProbe] False 2 {L(n - 2)}"],
            report.Profiles.Select(DescribeDirect));

        // The forward oracle on the examples and on a sample along the chain. A forward BFS per root is O(N), so all N roots
        // would be the quadratic cost under test; on a chain each root's forward set is its own suffix, so the sample's
        // agreement and the counts above are the same claim.
        var oracle = new Oracle(parts, map);
        const int env = (int)Capability.EnvironmentProbe;
        foreach (var path in row.Examples)
        {
            oracle.AssertShortestPath(path, env, oracle.Distance(path.Root, ReachEvidence.Bound, env)!.Value);
            Assert.Equal(oracle.DirectDistance(path.Root, env) is not null, path.Direct);
            if (path.Direct)
                oracle.AssertDirectShortestPath(path, env, oracle.DirectDistance(path.Root, env)!.Value);
        }
        foreach (var i in new[] { 0, 1, n / 2, n - 4, n - 3, n - 2, n - 1 })
        {
            Assert.Equal(n - i, oracle.Distance(L(i), ReachEvidence.ChaOnly, env));
            Assert.Equal(n - i, oracle.Distance(L(i), ReachEvidence.Bound, env));
            Assert.Equal(i >= n - 2 ? n - i : (int?)null, oracle.DirectDistance(L(i), env));
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------

    // App.R reaches Env only through dead Dispatch edges (so ChaOnly): via App.D1.M, whose ldftn (or other deferred edge) of
    // Env makes a 3-hop path through it; and, withDirectPath, via App.D2.M and App.X, a 4-hop path with none.
    private static Parts ChaOnlyDelegateCase(bool withDirectPath, MethodEdgeKind deferred = MethodEdgeKind.Ldftn)
    {
        var parts = new Parts()
            .Own("App.R", RootClass.PublicApi)
            .Own("App.D1.M", RootClass.None, type: "App.D1")
            .Type("App.D1", live: false)
            .Ext(Env)
            .Edge("App.R", "App.D1.M", MethodEdgeKind.Dispatch, 1)
            .Edge("App.D1.M", Env, deferred, 3);
        if (withDirectPath)
            parts.Own("App.D2.M", RootClass.None, type: "App.D2").Own("App.X", RootClass.None).Type("App.D2", live: false)
                .Edge("App.R", "App.D2.M", MethodEdgeKind.Dispatch, 2)
                .Edge("App.D2.M", "App.X", MethodEdgeKind.Call, 4)
                .Edge("App.X", Env, MethodEdgeKind.Call, 5);
        return parts;
    }

    private static string DescribeDirect(ReachProfile p) =>
        $"{p.Class} [{string.Join(",", p.Capabilities)}] {p.Unseen} [{string.Join(",", p.DirectCapabilities)}] {p.DirectUnseen} {p.Roots} {p.ExampleRoot}";

    // The first 8 lower-case hex digits of the SHA-256 of a name's UTF-16 code units, little-endian, each unit as it is (a
    // lone surrogate included; review Nit 1). Spelled out byte by byte, not through an Encoding, which would replace a
    // lone surrogate with U+FFFD.
    private static string Hash8(string name) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(name.SelectMany(c => new[] { (byte)(c & 0xFF), (byte)(c >> 8) }).ToArray()))[..8];

    private static string Utf8Hash8(string name) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(name)))[..8];

    // Well-formed UTF-16: a strict UTF-8 encoder accepts it (no lone surrogate).
    private static void AssertWellFormed(string text) =>
        Assert.Null(Record.Exception(() => new System.Text.UTF8Encoding(false, throwOnInvalidBytes: true).GetBytes(text)));

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
            case UnknownCause.ReaderAssertions: copy.Coverage = complete with { Index = new IndexCoverage(0, 0, 0, ReaderAssertions: 2) }; break;
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
    [
        RootClass.LoadTime, RootClass.HostContract, RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry,
        RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden,
    ];

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
        GapOnTheClass, UnseenReach, Truncated, AssembliesUnreadable, TypesSkipped, MethodsSkipped, ForwardersUnreadable, SupertypesUnresolved, RenamedImplementations, ModulesUnreadable,
        ReaderAssertions
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

        public Parts Own(string id, RootClass roots, string type = DefaultType, bool native = false, bool isStatic = false, string? key = null, bool internalCall = false)
        {
            Node(id, native || internalCall ? MethodNodeKind.OwnBodyless : MethodNodeKind.OwnWithBody, key);
            Methods.Add(new OwnMethodFacts(id, Assembly, type, roots, native, isStatic, internalCall));
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
            // Each node's out-edges, in input order: the same edges the BFS scanned, indexed so a long chain is linear.
            outgoing = edges.ToLookup(e => e.From, StringComparer.Ordinal);
            unseenSites = parts.Opacities.Where(o => o.Kind is OpacityKind.IndirectCall or OpacityKind.Unresolved or OpacityKind.Ambiguous or OpacityKind.BodyUnreadable)
                .Select(o => o.Site).ToHashSet(StringComparer.Ordinal);
            this.map = map;
        }

        public int? Distance(string root, ReachEvidence tier, int sink) => Distance(root, e => InTier(e, tier), sink);

        // Amendment a2's Direct edge set: the ChaOnly edges (all of them) except a deferred one (IsDirectEdge).
        public int? DirectDistance(string root, int sink) => Distance(root, IsDirectEdge, sink);

        // A ChaOnly example that is Direct: as short as the nearest sink over the Direct edges, each step one of them.
        public void AssertDirectShortestPath(ReachPath path, int sink, int distance)
        {
            Assert.Equal(new ReachHop(path.Root, Assembly, null, 0), path.Hops[0]);
            Assert.Equal(distance + 1, path.Length);
            for (var i = 1; i < path.Hops.Count; i++)
            {
                var (from, to) = (path.Hops[i - 1].NodeId, path.Hops[i]);
                Assert.Contains(edges, e => e.From == from && e.To == to.NodeId && e.Kind == to.Via && e.Offset == to.Offset && IsDirectEdge(e));
            }
            Assert.True(IsSink(path.Hops[^1].NodeId, sink), $"{path.Hops[^1].NodeId} is not sink {sink}");
        }

        private int? Distance(string root, Func<MethodEdge, bool> keep, int sink)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal) { root };
            var frontier = new List<string> { root };
            for (var depth = 0; frontier.Count > 0; depth++)
            {
                if (frontier.Any(n => IsSink(n, sink)))
                    return depth;
                frontier = [.. frontier.SelectMany(n => outgoing[n].Where(keep).Select(e => e.To)).Where(seen.Add)];
            }
            return null;
        }

        // Amendment a2 with its 2026-11-06 clarification (review W3): no edge that makes a method value without calling it.
        private static bool IsDirectEdge(MethodEdge edge) => edge.Kind is not (MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn or MethodEdgeKind.LoadToken);

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
                    || (node.Kind != MethodNodeKind.External && facts.TryGetValue(id, out var own) && own.InternalCall)
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
        private readonly ILookup<string, MethodEdge> outgoing;
        private readonly HashSet<string> unseenSites;
        private readonly CapabilityMap map;
    }
    #endregion
}
