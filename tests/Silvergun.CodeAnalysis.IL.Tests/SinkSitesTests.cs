namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="SinkSites.Of"/> over hand-built graphs (<see cref="MethodGraph.FromParts"/>; docs/agent/tasks/ssa-facts-s4.md
/// §2, S4.2): the call-site edges from own nodes to capability sinks, by <see cref="Reachability"/>'s own sink rule
/// (<see cref="Reachability.SinkOf"/>, pinned here directly too), with the map's <c>ignore-edge</c> cuts, unseen-only sinks,
/// implied and Dispatch edges left out, distinct and ordinal-sorted. Node ids are their own classification keys unless a
/// test says otherwise.
/// </summary>
public sealed class SinkSitesTests
{
    #region Methods
    // ---- Reachability.SinkOf (the shared predicate) -------------------------------------------------------------------

    [Fact]
    public void SinkOf_ExternalCapability_IsThatCapability_NotUnseen() =>
        Assert.Equal(((Capability?)Capability.EnvironmentProbe, false), Reachability.SinkOf(External(Env), null, map));

    [Fact]
    public void SinkOf_ExternalUnanalyzed_IsUnseenOnly() =>
        Assert.Equal(((Capability?)null, true), Reachability.SinkOf(External(Dyn), null, map));

    [Theory]
    [InlineData(Safe)]
    [InlineData("Ext.Unmapped.Op")]
    public void SinkOf_ExternalSafeOrUnmapped_IsNoSink(string id) =>
        Assert.Equal(((Capability?)null, false), Reachability.SinkOf(External(id), null, map));

    // An External node is classified by the map only: own facts on it are ignored.
    [Fact]
    public void SinkOf_ExternalWithNativeFacts_IgnoresTheFacts() =>
        Assert.Equal(((Capability?)null, false), Reachability.SinkOf(External(Safe), Facts(Safe, native: true, internalCall: true), map));

    [Theory]
    [InlineData(true, false, false, Capability.NativeInterop, false)]
    [InlineData(false, true, false, Capability.NativeInterop, false)]
    [InlineData(false, false, true, null, true)]
    [InlineData(true, false, true, Capability.NativeInterop, true)]
    [InlineData(false, false, false, null, false)]
    public void SinkOf_OwnNode_ByItsFacts(bool native, bool com, bool internalCall, Capability? capability, bool unseen) =>
        Assert.Equal((capability, unseen), Reachability.SinkOf(new MethodNode("App.N", "App.N", MethodNodeKind.OwnBodyless), Facts("App.N", native, com, internalCall), map));

    // An own node is walked, never classified, even when its key is a capability key; with no facts it is no sink.
    [Theory]
    [InlineData(MethodNodeKind.OwnWithBody)]
    [InlineData(MethodNodeKind.OwnBodyless)]
    public void SinkOf_OwnNodeWithACapabilityKey_IsNoSink(MethodNodeKind kind)
    {
        var node = new MethodNode("App.Shadow", Env, kind);

        Assert.Equal(((Capability?)null, false), Reachability.SinkOf(node, null, map));
        Assert.Equal(((Capability?)null, false), Reachability.SinkOf(node, Facts("App.Shadow"), map));
    }

    // ---- SinkSites.Of: which edges ------------------------------------------------------------------------------------

    [Theory]
    [InlineData(MethodEdgeKind.Call)]
    [InlineData(MethodEdgeKind.CallVirt)]
    [InlineData(MethodEdgeKind.NewObj)]
    [InlineData(MethodEdgeKind.Ldftn)]
    [InlineData(MethodEdgeKind.Ldvirtftn)]
    public void Of_CallSiteKindToCapabilitySink_IsASite(MethodEdgeKind kind)
    {
        var graph = new Parts().Own("App.A").Ext(Env).Edge("App.A", Env, kind, 7).Graph();

        var site = Assert.Single(SinkSites.Of(graph, map));

        Assert.Equal(new SinkSite("App.A", 7, kind, Env, Env, Capability.EnvironmentProbe), site);
    }

    [Theory]
    [InlineData(MethodEdgeKind.Dispatch)]
    [InlineData(MethodEdgeKind.StateMachine)]
    [InlineData(MethodEdgeKind.TypeInitializer)]
    [InlineData(MethodEdgeKind.LoadToken)]
    public void Of_ImpliedDispatchOrTokenEdge_IsNoSite(MethodEdgeKind kind)
    {
        var graph = new Parts().Own("App.A").Ext(Env).Edge("App.A", Env, kind, 7).Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    // Twin pair: the same call to a safe external, to an unmapped one, and to an own body-ful method.
    [Theory]
    [InlineData(Safe)]
    [InlineData("Ext.Unmapped.Op")]
    public void Of_CallToNonSinkExternal_IsNoSite(string external)
    {
        var graph = new Parts().Own("App.A").Ext(external).Edge("App.A", external).Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    [Fact]
    public void Of_CallToOwnMethod_IsNoSite()
    {
        var graph = new Parts().Own("App.A").Own("App.B").Edge("App.A", "App.B").Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    // The map's ignore-edge rule cuts App.Cutter -> Ext.Net, as reachability does; the twin from App.A stays.
    [Fact]
    public void Of_IgnoredEdge_IsNoSite_ItsTwinIs()
    {
        var graph = new Parts().Own("App.Cutter").Own("App.A").Ext(Net)
            .Edge("App.Cutter", Net, MethodEdgeKind.Call, 1)
            .Edge("App.A", Net, MethodEdgeKind.Call, 2)
            .Graph();

        var site = Assert.Single(SinkSites.Of(graph, map));

        Assert.Equal(("App.A", Capability.Network), (site.NodeId, site.Capability));
    }

    // ignore-edge is matched on classification keys, not node ids.
    [Fact]
    public void Of_IgnoredEdge_MatchedOnClassificationKeys()
    {
        var graph = new Parts().Node("App.Cutter(System.String)", MethodNodeKind.OwnWithBody, "App.Cutter").Node(Net + "(System.Byte[])", MethodNodeKind.External, Net)
            .Edge("App.Cutter(System.String)", Net + "(System.Byte[])")
            .Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Of_CallToOwnPInvokeOrComImport_IsANativeInteropSite(bool native, bool com)
    {
        var graph = new Parts().Own("App.A").Own("App.Native", native: native, com: com).Edge("App.A", "App.Native", MethodEdgeKind.Call, 3).Graph();

        var site = Assert.Single(SinkSites.Of(graph, map));

        Assert.Equal(new SinkSite("App.A", 3, MethodEdgeKind.Call, "App.Native", "App.Native", Capability.NativeInterop), site);
    }

    // A sink for unseen code only is no capability, so no site: an unanalyzed external, an own InternalCall.
    [Fact]
    public void Of_UnseenOnlySinks_AreNoSites()
    {
        var graph = new Parts().Own("App.A").Ext(Dyn).Own("App.Icall", internalCall: true)
            .Edge("App.A", Dyn, MethodEdgeKind.CallVirt, 1)
            .Edge("App.A", "App.Icall", MethodEdgeKind.Call, 2)
            .Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    // Twin: an InternalCall that is also a P/Invoke is a NativeInterop sink, so its call is a site.
    [Fact]
    public void Of_InternalCallThatIsAlsoNative_IsASite()
    {
        var graph = new Parts().Own("App.A").Own("App.Both", native: true, internalCall: true).Edge("App.A", "App.Both", MethodEdgeKind.Call, 2).Graph();

        Assert.Equal(Capability.NativeInterop, Assert.Single(SinkSites.Of(graph, map)).Capability);
    }

    // An own P/Invoke has no call site in its own body: the sink alone gives no site.
    [Fact]
    public void Of_OwnPInvokeWithNoCaller_GivesNoSite()
    {
        var graph = new Parts().Own("App.Native", native: true).Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    // Only own callers' sites: an edge from an External node, or from a node not in the graph, is none.
    [Fact]
    public void Of_EdgeFromExternalOrUnknownNode_IsNoSite()
    {
        var graph = new Parts().Ext(Safe, Env).Edge(Safe, Env).Edge("Nowhere.M", Env).Graph();

        Assert.Empty(SinkSites.Of(graph, map));
    }

    // From an own body-less node (an abstract method cannot call, but the rule is "own", not "with a body").
    [Fact]
    public void Of_EdgeFromOwnBodylessNode_IsASite()
    {
        var graph = new Parts().Node("App.Abstract", MethodNodeKind.OwnBodyless).Ext(Env).Edge("App.Abstract", Env).Graph();

        Assert.Single(SinkSites.Of(graph, map));
    }

    // Callee is the target's node id and CalleeKey its classification key, which is what the map matched.
    [Fact]
    public void Of_CalleeAndCalleeKey_AreIdAndKey()
    {
        var graph = new Parts().Node("App.A(System.Int32)", MethodNodeKind.OwnWithBody, "App.A").Node(Env + "(System.String)", MethodNodeKind.External, Env)
            .Edge("App.A(System.Int32)", Env + "(System.String)", MethodEdgeKind.Call, 4)
            .Graph();

        var site = Assert.Single(SinkSites.Of(graph, map));

        Assert.Equal(new SinkSite("App.A(System.Int32)", 4, MethodEdgeKind.Call, Env + "(System.String)", Env, Capability.EnvironmentProbe), site);
    }

    // No map: the built-in one.
    [Fact]
    public void Of_NoMap_UsesTheDefaultMap()
    {
        const string ReadAllText = "System.IO.File.ReadAllText";
        var graph = new Parts().Own("App.A").Node(ReadAllText + "(System.String)", MethodNodeKind.External, ReadAllText)
            .Edge("App.A", ReadAllText + "(System.String)", MethodEdgeKind.Call, 6)
            .Graph();

        var site = Assert.Single(SinkSites.Of(graph));

        Assert.Equal(Capability.FileSystem, site.Capability);
        Assert.Equal(CapabilityMap.Default.Classify(ReadAllText).Capability, site.Capability);
    }

    [Fact]
    public void Of_NullGraph_Throws() => Assert.Throws<ArgumentNullException>(() => SinkSites.Of(null!, map));

    // ---- SinkSites.Of: order and distinctness --------------------------------------------------------------------------

    // Ordinal by node id ('B' before 'a'), then numeric offset (9 before 10), then callee (ordinal), then edge kind.
    [Fact]
    public void Of_Sites_OrdinalByNodeIdOffsetCalleeKind()
    {
        var graph = new Parts().Own("App.a").Own("App.B").Ext(Env, Net, File)
            .Edge("App.a", Env, MethodEdgeKind.Call, 1)
            .Edge("App.B", Env, MethodEdgeKind.Call, 10)
            .Edge("App.B", Net, MethodEdgeKind.Call, 9)
            .Edge("App.B", File, MethodEdgeKind.CallVirt, 9)
            .Edge("App.B", File, MethodEdgeKind.Call, 9)
            .Graph();

        var sites = SinkSites.Of(graph, map).Select(s => (s.NodeId, s.Offset, s.Callee, s.EdgeKind)).ToArray();

        Assert.Equal(
            [
                ("App.B", 9u, File, MethodEdgeKind.Call),
                ("App.B", 9u, File, MethodEdgeKind.CallVirt),
                ("App.B", 9u, Net, MethodEdgeKind.Call),
                ("App.B", 10u, Env, MethodEdgeKind.Call),
                ("App.a", 1u, Env, MethodEdgeKind.Call),
            ],
            sites);
    }

    // Merged definitions give the same edge twice: one site.
    [Fact]
    public void Of_DuplicateEdges_OneSite()
    {
        var graph = new Parts().Own("App.A").Ext(Env).Edge("App.A", Env, MethodEdgeKind.Call, 3).Edge("App.A", Env, MethodEdgeKind.Call, 3).Graph();

        Assert.Single(SinkSites.Of(graph, map));
    }

    // An Ambiguous site's candidates, all sinks, at one offset: one site per callee.
    [Fact]
    public void Of_SeveralCalleesAtOneOffset_OneSiteEach()
    {
        var graph = new Parts().Own("App.A").Ext(Env, Net).Edge("App.A", Env, MethodEdgeKind.Call, 3).Edge("App.A", Net, MethodEdgeKind.Call, 3).Graph();

        Assert.Equal([Env, Net], SinkSites.Of(graph, map).Select(s => s.Callee));
    }

    // Every own->sink call-site edge Reachability would follow is a site, and every site is such an edge: a seeded random
    // graph against an oracle written from the spec's rule.
    [Fact]
    public void Of_RandomGraph_MatchesTheSpecsRule()
    {
        var random = new Random(38);
        string[] owns = [.. Enumerable.Range(0, 12).Select(i => $"App.M{i}"), "App.Cutter"];
        string[] externals = [Env, Net, File, Dyn, Safe, "Ext.Unmapped.Op"];
        var parts = new Parts().Ext(externals);
        foreach (var own in owns)
            parts.Own(own, native: random.Next(6) == 0, com: random.Next(8) == 0, internalCall: random.Next(6) == 0);
        var kinds = Enum.GetValues<MethodEdgeKind>();
        string[] targets = [.. owns, .. externals];
        for (var i = 0; i < 200; i++)
            parts.Edge(owns[random.Next(owns.Length)], targets[random.Next(targets.Length)], kinds[random.Next(kinds.Length)], (uint)random.Next(20));
        var graph = parts.Graph();

        var facts = parts.Methods.ToDictionary(m => m.NodeId, StringComparer.Ordinal);
        Capability? CapabilityOf(string id) =>
            externals.Contains(id) ? map.Classify(id) is { Class: CapabilityClass.Capability } v ? v.Capability : null
            : facts[id].NativeImport || facts[id].ComImport ? Capability.NativeInterop : null;
        var expected = parts.Edges
            .Where(e => e.Kind is MethodEdgeKind.Call or MethodEdgeKind.CallVirt or MethodEdgeKind.NewObj or MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn)
            .Where(e => CapabilityOf(e.To) is not null && !map.IsIgnoredEdge(e.From, e.To))
            .Select(e => new SinkSite(e.From, e.Offset, e.Kind, e.To, e.To, CapabilityOf(e.To)!.Value))
            .Distinct()
            .OrderBy(s => s.NodeId, StringComparer.Ordinal).ThenBy(s => s.Offset).ThenBy(s => s.Callee, StringComparer.Ordinal).ThenBy(s => s.EdgeKind)
            .ToArray();

        var actual = SinkSites.Of(graph, map);

        Assert.True(expected.Length > 20, $"Only {expected.Length} expected sites: the seed no longer exercises the rule.");
        Assert.Equal(expected, actual);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static MethodNode External(string id) => new(id, id, MethodNodeKind.External);

    private static OwnMethodFacts Facts(string id, bool native = false, bool com = false, bool internalCall = false) =>
        new(id, Assembly, "App.T", RootClass.PublicApi, native, false, internalCall, com);
    #endregion

    #region Fields
    private const string Assembly = "App";
    private const string Env = "Ext.Env.Get";
    private const string Net = "Ext.Net.Send";
    private const string File = "Ext.File.Read";
    private const string Dyn = "Ext.Dyn.Call";
    private const string Safe = "Ext.Safe.Op";

    private static readonly GraphCoverage complete = new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);

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
        "sink-sites.cm");
    #endregion

    #region Child types
    // The parts of a hand-made graph. Own nodes get facts in assembly App; a native, COM or InternalCall one is body-less.
    private sealed class Parts
    {
        public List<MethodNode> Nodes { get; } = [];
        public List<MethodEdge> Edges { get; } = [];
        public List<OwnMethodFacts> Methods { get; } = [];

        public Parts Own(string id, bool native = false, bool com = false, bool internalCall = false)
        {
            Node(id, native || com || internalCall ? MethodNodeKind.OwnBodyless : MethodNodeKind.OwnWithBody);
            Methods.Add(Facts(id, native, com, internalCall));
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

        public Parts Edge(string from, string to, MethodEdgeKind kind = MethodEdgeKind.Call, uint offset = 0)
        {
            Edges.Add(new MethodEdge(from, to, kind, offset));
            return this;
        }

        public MethodGraph Graph() =>
            MethodGraph.FromParts(Nodes, Edges, [], complete, new GraphFacts([.. Methods.OrderBy(m => m.NodeId, StringComparer.Ordinal)], [], []));
    }
    #endregion
}
