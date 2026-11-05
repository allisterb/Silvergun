namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Capability reachability over a <see cref="MethodGraph"/> (ADR 0037). Every own method is a root, tagged with its
/// <see cref="RootClass"/>es (<see cref="MethodGraph.Facts"/>).
/// <para>
/// <b>Sinks.</b> A sink is an external node the map classifies as a capability, or an own P/Invoke or COM call
/// (<c>NativeInterop</c>). Code the graph cannot see is a sink too: an opacity site, or an external node the map marks
/// <c>unanalyzed</c>, or an own body-less extern that is no P/Invoke (<see cref="OwnMethodFacts.InternalCall"/>). Own
/// methods are never classified; their bodies are walked.
/// </para>
/// <para>
/// <b>Search.</b> One multi-source backward BFS per sink and per edge set (<see cref="ReachEvidence"/>), after the map's
/// <c>ignore-edge</c> cuts. Each node gets a next hop toward its nearest sink, so every example path is read off in
/// O(length), with no search per root.
/// </para>
/// <para>Deterministic: nodes, edges and roots are taken in ordinal order. Never throws.</para>
/// </summary>
public static class Reachability
{
    #region Methods
    /// <summary>
    /// What the roots of <paramref name="graph"/> reach, with sinks classified by <paramref name="map"/> (default
    /// <see cref="CapabilityMap.Default"/>). A failure yields a <see cref="ReachabilityReport.Partial"/> report in which
    /// every root class is <see cref="RootClassVerdict.Unknown"/> with no roots counted. A null graph is a caller bug and
    /// throws <see cref="ArgumentNullException"/>.
    /// </summary>
    public static ReachabilityReport Analyze(MethodGraph graph, CapabilityMap? map = null)
    {
        ArgumentNullException.ThrowIfNull(graph);
        try
        {
            return new Analysis(graph, map ?? CapabilityMap.Default).Run();
        }
        catch (Exception ex)
        {
            return new ReachabilityReport([], [], false,
                [.. classes.Select(c => new RootClassStatus(c, 0, RootClassVerdict.Unknown, [$"reachability could not be computed: {ex.Message}"]))],
                0, [], graph.Coverage, true, ex.Message);
        }
    }
    #endregion

    #region Fields
    /// <summary>The hops a <see cref="ReachPath"/> keeps at most: the first <c>MaxPathHops - 2</c> and the last two.</summary>
    public const int MaxPathHops = 64;

    // The single root classes, strongest first (ADR 0037 decision 4).
    private static readonly RootClass[] classes =
        [RootClass.LoadTime, RootClass.HostContract, RootClass.RuntimeInvoked, RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden];

    private static readonly Capability[] capabilities = Enum.GetValues<Capability>();

    // The opacity kinds that make a node a site of unseen code. Module-level kinds are sited at [assembly]<Module>, which
    // is no node, and reach the verdicts through the facts' gaps and the coverage instead.
    private static readonly HashSet<OpacityKind> unseenKinds =
        [OpacityKind.IndirectCall, OpacityKind.Unresolved, OpacityKind.Ambiguous, OpacityKind.BodyUnreadable];

    private const int MaxProfiles = 64;
    private const int MaxExamples = 3;
    #endregion

    #region Child types
    // One analysis: the graph flattened to node indexes, the sinks per node, and the next hops per tier and sink.
    private sealed class Analysis
    {
        #region Constructors
        public Analysis(MethodGraph graph, CapabilityMap map)
        {
            this.graph = graph;
            nodes = [.. graph.Nodes];
            indexOf = Enumerable.Range(0, nodes.Length).ToDictionary(i => nodes[i].NodeId, StringComparer.Ordinal);
            facts = graph.Facts.Methods.Where(f => indexOf.ContainsKey(f.NodeId)).ToDictionary(f => f.NodeId, StringComparer.Ordinal);
            var live = graph.Facts.Types.ToDictionary(t => t.TypeId, t => t.Live, StringComparer.Ordinal);
            unseenSink = capabilities.Length;
            sinks = unseenSink + 1;
            hops = new int[Tiers, sinks][];

            // Edges kept after the ignore-edge cuts, each with the tiers it belongs to. Graph order is (From, To, Kind,
            // Offset), so each node's incoming list comes out in (From, Kind, Offset) order.
            var kept = new List<(int From, int To, MethodEdgeKind Kind, uint Offset, int Tiers)>();
            var ignored = new SortedSet<(string Caller, string Callee)>(Comparer<(string Caller, string Callee)>.Create((a, b) =>
                string.CompareOrdinal(a.Caller, b.Caller) is var c && c != 0 ? c : string.CompareOrdinal(a.Callee, b.Callee)));
            foreach (var edge in graph.Edges)
            {
                if (!indexOf.TryGetValue(edge.From, out var from) || !indexOf.TryGetValue(edge.To, out var to))
                    continue;
                if (map.IsIgnoredEdge(nodes[from].ClassificationKey, nodes[to].ClassificationKey))
                {
                    edgesIgnored++;
                    ignored.Add((nodes[from].ClassificationKey, nodes[to].ClassificationKey));
                    continue;
                }
                var tiers = edge.Kind != MethodEdgeKind.Dispatch ? AllTiers
                    : IsLiveTarget(edge.To, live) ? TierBit(ReachEvidence.Instantiated) | TierBit(ReachEvidence.ChaOnly)
                    : TierBit(ReachEvidence.ChaOnly);
                kept.Add((from, to, edge.Kind, edge.Offset, tiers));
            }
            this.ignored = [.. ignored.Select(e => new IgnoredEdge(e.Caller, e.Callee))];
            edgeTo = [.. kept.Select(e => e.To)];
            edgeFrom = [.. kept.Select(e => e.From)];
            edgeKind = [.. kept.Select(e => e.Kind)];
            edgeOffset = [.. kept.Select(e => e.Offset)];
            edgeTiers = [.. kept.Select(e => e.Tiers)];
            incoming = [.. Enumerable.Range(0, nodes.Length).Select(_ => new List<int>())];
            for (var e = 0; e < kept.Count; e++)
                incoming[kept[e].To].Add(e);

            // The sinks each node is, and the first unseen opacity kind at each opacity site, in the graph's order.
            sinkMask = new int[nodes.Length];
            for (var i = 0; i < nodes.Length; i++)
                sinkMask[i] = nodes[i].Kind == MethodNodeKind.External
                    ? map.Classify(nodes[i].ClassificationKey) switch
                    {
                        { Class: CapabilityClass.Capability, Capability: { } c } => 1 << (int)c,
                        { Class: CapabilityClass.Unanalyzed } => 1 << unseenSink,
                        _ => 0,
                    }
                    : facts.TryGetValue(nodes[i].NodeId, out var own)
                        ? (own.NativeImport || own.ComImport ? 1 << (int)Capability.NativeInterop : 0) | (own.InternalCall ? 1 << unseenSink : 0)
                        : 0;
            foreach (var opacity in graph.Opacities.Where(o => unseenKinds.Contains(o.Kind)))
                if (indexOf.TryGetValue(opacity.Site, out var site))
                {
                    sinkMask[site] |= 1 << unseenSink;
                    opacityAt.TryAdd(site, opacity.Kind);
                }
        }
        #endregion

        #region Methods
        public ReachabilityReport Run()
        {
            for (var tier = 0; tier < Tiers; tier++)
                for (var sink = 0; sink < sinks; sink++)
                    hops[tier, sink] = Propagate(tier, sink);

            var roots = facts.Values.Select(f => (Index: indexOf[f.NodeId], f.Roots)).OrderBy(r => r.Index).ToArray();
            var reaches = new List<CapabilityReach>();
            var profiles = new List<ReachProfile>();
            var statuses = new List<RootClassStatus>();
            var profilesTruncated = false;
            foreach (var cls in classes)
            {
                var members = roots.Where(r => r.Roots.HasFlag(cls)).Select(r => r.Index).ToArray();
                for (var sink = 0; sink < sinks; sink++)
                {
                    var reaching = members.Where(r => Reached(ReachEvidence.ChaOnly, sink, r)).ToArray();
                    if (reaching.Length == 0)
                        continue;
                    var examples = reaching.OrderBy(r => Strongest(sink, r)).ThenBy(r => r).Take(MaxExamples)
                        .Select(r => Path(Strongest(sink, r), sink, r)).ToArray();
                    reaches.Add(new CapabilityReach(cls, sink == unseenSink ? null : capabilities[sink], reaching.Length,
                        reaching.Count(r => Reached(ReachEvidence.Bound, sink, r)),
                        reaching.Count(r => Reached(ReachEvidence.Instantiated, sink, r)),
                        examples));
                }

                var grouped = members.Select(r => (Root: r, Mask: Mask(r))).Where(m => m.Mask != 0)
                    .GroupBy(m => m.Mask)
                    .Select(g => (Mask: g.Key, Count: g.Count(), Example: g.Min(m => m.Root)))
                    .OrderByDescending(g => g.Count).ThenBy(g => g.Mask).ThenBy(g => g.Example)
                    .ToArray();
                profilesTruncated |= grouped.Length > MaxProfiles;
                profiles.AddRange(grouped.Take(MaxProfiles).Select(g => new ReachProfile(cls,
                    [.. Enumerable.Range(0, capabilities.Length).Where(c => (g.Mask & (1 << c)) != 0).Select(c => capabilities[c])],
                    (g.Mask & (1 << unseenSink)) != 0, g.Count, nodes[g.Example].NodeId)));

                statuses.Add(Status(cls, members));
            }

            return new ReachabilityReport(reaches, profiles, profilesTruncated, statuses, edgesIgnored, ignored, graph.Coverage,
                graph.Coverage.Truncated, graph.Coverage.Truncated ? $"the graph is truncated: {graph.Coverage.TruncatedBy}" : null);
        }

        // Multi-source BFS over reverse edges of one tier from every node that is the sink: each node's next hop is the
        // edge it was first discovered over (Sink at a sink, Unreached when it cannot reach one).
        private int[] Propagate(int tier, int sink)
        {
            var hop = new int[nodes.Length];
            Array.Fill(hop, Unreached);
            var queue = new Queue<int>();
            var bit = 1 << sink;
            var tierBit = 1 << tier;
            for (var i = 0; i < nodes.Length; i++)
                if ((sinkMask[i] & bit) != 0)
                {
                    hop[i] = Sink;
                    queue.Enqueue(i);
                }
            while (queue.TryDequeue(out var node))
                foreach (var edge in incoming[node])
                {
                    var from = edgeFrom[edge];
                    if ((edgeTiers[edge] & tierBit) == 0 || hop[from] != Unreached)
                        continue;
                    hop[from] = edge;
                    queue.Enqueue(from);
                }
            return hop;
        }

        // The path from root to the nearest sink on one tier, read off the next hops: the first MaxPathHops - 2 hops are
        // kept, and the last two always, so the report stays small however long the path (S2 review W1). The walk is
        // bounded by the node count: next hops come from a BFS, so they cannot cycle, and the bound only guards that.
        private ReachPath Path(ReachEvidence evidence, int sink, int root)
        {
            var hop = hops[(int)evidence, sink];
            var head = new List<ReachHop> { Hop(root, null, 0) };
            var tail = new Queue<(int Node, MethodEdgeKind Kind, uint Offset)>();
            var length = 1;
            var at = root;
            for (var edge = hop[at]; edge >= 0 && length <= nodes.Length; edge = hop[at])
            {
                at = edgeTo[edge];
                length++;
                if (head.Count < MaxPathHops - 2)
                    head.Add(Hop(at, edgeKind[edge], edgeOffset[edge]));
                else
                {
                    tail.Enqueue((at, edgeKind[edge], edgeOffset[edge]));
                    if (tail.Count > 2)
                        tail.Dequeue();
                }
            }
            var truncated = length > MaxPathHops;
            // Up to MaxPathHops hops fit whole: the tail then holds the remaining one or two.
            return new ReachPath(nodes[root].NodeId, evidence, [.. head, .. tail.Select(t => Hop(t.Node, t.Kind, t.Offset))], length, truncated,
                sink == unseenSink && opacityAt.TryGetValue(at, out var kind) ? kind : null);
        }

        private RootClassStatus Status(RootClass cls, int[] members)
        {
            var reasons = graph.Facts.Gaps.Where(g => (g.Class & cls) != 0).Select(g => $"{g.Assembly}: {g.Reason}").ToList();
            var unseen = members.Count(r => Reached(ReachEvidence.ChaOnly, unseenSink, r));
            if (unseen > 0)
                reasons.Add($"{unseen} root(s) reach code the graph cannot see");
            var coverage = graph.Coverage;
            if (coverage.Truncated)
                reasons.Add($"the graph is truncated: {coverage.TruncatedBy}");
            if (!coverage.Index.IsComplete)
                reasons.Add("the member index is incomplete: some assemblies, types, methods, forwarders or supertypes could not be read");
            if (coverage.ModulesUnreadable > 0)
                reasons.Add($"{coverage.ModulesUnreadable} module(s) unreadable: whether they have renamed implementations that CHA does not follow is unknown");
            if (coverage.RenamedImplementations > 0)
                reasons.Add($"{coverage.RenamedImplementations} MethodImpl row(s) bind renamed implementations that CHA does not follow");

            var verdict = reasons.Count > 0 ? RootClassVerdict.Unknown
                : members.Any(r => (Mask(r) & ~(1 << unseenSink)) != 0) ? RootClassVerdict.Reaches
                : RootClassVerdict.None;
            return new RootClassStatus(cls, members.Length, verdict, reasons);
        }

        // The sinks a root reaches over all edges, as bits (capabilities by enum value, then Unseen).
        private int Mask(int root) =>
            Enumerable.Range(0, sinks).Where(s => Reached(ReachEvidence.ChaOnly, s, root)).Aggregate(0, (mask, s) => mask | (1 << s));

        private bool Reached(ReachEvidence evidence, int sink, int node) => hops[(int)evidence, sink][node] != Unreached;

        // Bound before Instantiated before ChaOnly: each tier's edges contain the one before's.
        private ReachEvidence Strongest(int sink, int node) =>
            Reached(ReachEvidence.Bound, sink, node) ? ReachEvidence.Bound
            : Reached(ReachEvidence.Instantiated, sink, node) ? ReachEvidence.Instantiated
            : ReachEvidence.ChaOnly;

        private ReachHop Hop(int node, MethodEdgeKind? via, uint offset) =>
            new(nodes[node].NodeId, facts.TryGetValue(nodes[node].NodeId, out var own) ? own.Assembly : null, via, offset);

        // A Dispatch target may really run when it is static, when its declaring type is live, or when nothing is known
        // about it (the facts fallback marks nothing dead).
        private bool IsLiveTarget(string target, IReadOnlyDictionary<string, bool> live) =>
            !facts.TryGetValue(target, out var method) || method.IsStatic || !live.TryGetValue(method.DeclaringTypeId, out var isLive) || isLive;

        private static int TierBit(ReachEvidence evidence) => 1 << (int)evidence;
        #endregion

        #region Fields
        private readonly MethodGraph graph;
        private readonly MethodNode[] nodes;
        private readonly Dictionary<string, int> indexOf;
        private readonly Dictionary<string, OwnMethodFacts> facts;
        private readonly int[] edgeFrom;
        private readonly int[] edgeTo;
        private readonly MethodEdgeKind[] edgeKind;
        private readonly uint[] edgeOffset;
        private readonly int[] edgeTiers;
        private readonly List<int>[] incoming;
        private readonly int[] sinkMask;
        private readonly Dictionary<int, OpacityKind> opacityAt = [];
        private readonly int unseenSink;
        private readonly int sinks;
        private readonly int edgesIgnored;
        private readonly IReadOnlyList<IgnoredEdge> ignored;
        // Per tier and sink, each node's next hop: an index into the edge arrays, Sink, or Unreached.
        private readonly int[,][] hops;

        private const int Tiers = 3;
        private const int AllTiers = 0b111;
        private const int Sink = -1;
        private const int Unreached = -2;
        #endregion
    }
    #endregion
}
