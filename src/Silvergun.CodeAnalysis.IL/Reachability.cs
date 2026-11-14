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
/// <c>ignore-edge</c> cuts, and one more per sink over the ChaOnly edges without the deferred ones,
/// <see cref="MethodEdgeKind.Ldftn"/>, <see cref="MethodEdgeKind.Ldvirtftn"/> and <see cref="MethodEdgeKind.LoadToken"/>
/// (the Direct label, ADR 0037 amendment a2). Each node gets a next hop toward its nearest sink, so every example path is
/// read off in O(length), and path lengths are memoised per sink, so ordering a row's examples is O(nodes).
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
                [.. classes.Select(c => new RootClassStatus(c, 0, RootClassVerdict.Unknown, [$"reachability could not be computed: {BoundName(ex.Message)}"]))],
                0, [], 0, graph.Coverage, true, BoundName(ex.Message));
        }
    }

    /// <summary>
    /// <paramref name="name"/>, or when longer than <see cref="MaxNameChars"/> its first chars (never half a surrogate
    /// pair) followed by <c>…[+N chars, sha256:&lt;8 hex&gt;]</c>, N the chars cut and the hash over the whole name's UTF-16
    /// code units, so names differing only in a lone surrogate differ too. Eight hex digits tell benign names apart; a
    /// crafted collision costs about 2^16 tries, so the suffix is no identity for hostile ones.
    /// </summary>
    public static string BoundName(string name) => BoundNameTo(name, MaxNameChars);

    /// <summary>
    /// <see cref="BoundName"/> at <paramref name="maxChars"/> instead of <see cref="MaxNameChars"/>. Throws
    /// <see cref="ArgumentOutOfRangeException"/> when <paramref name="maxChars"/> is below 1. Not an overload of
    /// <see cref="BoundName"/>, so that stays usable as a <c>Select</c> method group (S0 review W3).
    /// </summary>
    public static string BoundNameTo(string name, int maxChars)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxChars, 1);
        if (name.Length <= maxChars)
            return name;
        var keep = char.IsHighSurrogate(name[maxChars - 1]) ? maxChars - 1 : maxChars;
        return name[..keep] + UntrustedText.CutSuffix(name, name.Length - keep);
    }

    /// <summary>
    /// What <paramref name="node"/> is a sink for (decision 2): an external node the map classifies as a capability, or
    /// as unanalyzed (unseen code); an own P/Invoke or COM import (<c>NativeInterop</c>), or an own body-less extern that
    /// is no P/Invoke (unseen). <paramref name="own"/> is the node's facts, when it is own. Opacity sites are not covered.
    /// </summary>
    internal static (Capability? Capability, bool Unseen) SinkOf(MethodNode node, OwnMethodFacts? own, CapabilityMap map) =>
        node.Kind == MethodNodeKind.External
            ? map.Classify(node.ClassificationKey) switch
            {
                { Class: CapabilityClass.Capability, Capability: { } c } => (c, false),
                { Class: CapabilityClass.Unanalyzed } => (null, true),
                _ => (null, false),
            }
            : own is null ? (null, false)
            : (own.NativeImport || own.ComImport ? Capability.NativeInterop : null, own.InternalCall);
    #endregion

    #region Fields
    /// <summary>The hops a <see cref="ReachPath"/> keeps at most: the first <c>MaxPathHops - 2</c> and the last two.</summary>
    public const int MaxPathHops = 64;

    /// <summary>The chars of a name a report keeps whole (<see cref="BoundName"/>).</summary>
    public const int MaxNameChars = 1024;

    // The single root classes, strongest first (ADR 0037 decision 4, amendment a1).
    private static readonly RootClass[] classes =
    [
        RootClass.LoadTime, RootClass.HostContract, RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry,
        RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden,
    ];

    private static readonly Capability[] capabilities = Enum.GetValues<Capability>();

    // The opacity kinds that make a node a site of unseen code. Module-level kinds are sited at [assembly]<Module>, which
    // is no node, and reach the verdicts through the facts' gaps and the coverage instead. An OversizedType node may be
    // several methods merged under one id, so which one runs is not seen.
    private static readonly HashSet<OpacityKind> unseenKinds =
        [OpacityKind.IndirectCall, OpacityKind.Unresolved, OpacityKind.Ambiguous, OpacityKind.BodyUnreadable, OpacityKind.OversizedType];

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
            hops = new int[Passes, sinks][];

            // Edges kept after the ignore-edge cuts, each with the passes it belongs to: the tiers, and Direct for every
            // edge but a deferred one (IsDeferred). Graph order is (From, To, Kind, Offset), so each node's incoming list comes
            // out in (From, Kind, Offset) order.
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
                kept.Add((from, to, edge.Kind, edge.Offset, IsDeferred(edge.Kind) ? tiers : tiers | DirectBit));
            }
            this.ignored = [.. ignored.Select(e => new IgnoredEdge(Bound(e.Caller), Bound(e.Callee)))];
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
            {
                var (capability, unseen) = SinkOf(nodes[i], facts.GetValueOrDefault(nodes[i].NodeId), map);
                sinkMask[i] = (capability is { } c ? 1 << (int)c : 0) | (unseen ? 1 << unseenSink : 0);
            }
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
            for (var pass = 0; pass < Passes; pass++)
                for (var sink = 0; sink < sinks; sink++)
                    hops[pass, sink] = Propagate(pass, sink);

            var roots = facts.Values.Select(f => (Index: indexOf[f.NodeId], f.Roots)).OrderBy(r => r.Index).ToArray();
            var members = classes.Select(cls => roots.Where(r => r.Roots.HasFlag(cls)).Select(r => r.Index).ToArray()).ToArray();

            // Sink by sink, so each sink's walk memos (O(nodes) per pass, review W1) live only while its rows are built.
            var rows = new CapabilityReach?[classes.Length, sinks];
            for (var sink = 0; sink < sinks; sink++)
            {
                var walks = new int[Passes][];
                for (var c = 0; c < classes.Length; c++)
                {
                    var reaching = members[c].Where(r => Reached((int)ReachEvidence.ChaOnly, sink, r)).ToArray();
                    if (reaching.Length == 0)
                        continue;
                    var examples = reaching.Select(r => Example(walks, sink, r))
                        .OrderBy(e => e.Evidence).ThenBy(e => !e.Direct).ThenBy(e => e.Length).ThenBy(e => e.Root).Take(MaxExamples)
                        .Select(e => Path(e.Pass, e.Evidence, sink, e.Root)).ToArray();
                    rows[c, sink] = new CapabilityReach(classes[c], sink == unseenSink ? null : capabilities[sink], reaching.Length,
                        reaching.Count(r => Reached((int)ReachEvidence.Bound, sink, r)),
                        reaching.Count(r => Reached((int)ReachEvidence.Instantiated, sink, r)),
                        reaching.Count(r => Reached(DirectPass, sink, r)),
                        examples);
                }
            }

            var reaches = new List<CapabilityReach>();
            var profiles = new List<ReachProfile>();
            var statuses = new List<RootClassStatus>();
            var profilesTruncated = false;
            for (var c = 0; c < classes.Length; c++)
            {
                var cls = classes[c];
                for (var sink = 0; sink < sinks; sink++)
                    if (rows[c, sink] is { } row)
                        reaches.Add(row);

                var grouped = members[c].Select(r => (Root: r, Mask: Mask((int)ReachEvidence.ChaOnly, r), Direct: Mask(DirectPass, r))).Where(m => m.Mask != 0)
                    .GroupBy(m => (m.Mask, m.Direct))
                    .Select(g => (g.Key.Mask, g.Key.Direct, Count: g.Count(), Example: g.Min(m => m.Root)))
                    .OrderByDescending(g => g.Count).ThenBy(g => g.Mask).ThenBy(g => g.Direct).ThenBy(g => g.Example)
                    .ToArray();
                profilesTruncated |= grouped.Length > MaxProfiles;
                profiles.AddRange(grouped.Take(MaxProfiles).Select(g => new ReachProfile(cls,
                    Capabilities(g.Mask), (g.Mask & (1 << unseenSink)) != 0, Capabilities(g.Direct), (g.Direct & (1 << unseenSink)) != 0,
                    g.Count, Bound(nodes[g.Example].NodeId))));

                statuses.Add(Status(cls, members[c]));
            }

            return new ReachabilityReport(reaches, profiles, profilesTruncated, statuses, edgesIgnored, ignored, bounded.Count, graph.Coverage,
                graph.Coverage.Truncated, graph.Coverage.Truncated ? $"the graph is truncated: {graph.Coverage.TruncatedBy}" : null);
        }

        // A root's example for one sink: the path at its strongest tier, unless that is ChaOnly and not Direct and a
        // Direct path exists (also ChaOnly), which is then preferred (amendment a2: evidence, then Direct, then length).
        private (int Root, int Pass, ReachEvidence Evidence, bool Direct, int Length) Example(int[][] walks, int sink, int root)
        {
            var evidence = Strongest(sink, root);
            var (length, direct) = Walk(walks, (int)evidence, sink, root);
            if (direct || evidence != ReachEvidence.ChaOnly || !Reached(DirectPass, sink, root))
                return (root, (int)evidence, evidence, direct, length);
            return (root, DirectPass, ReachEvidence.ChaOnly, true, Walk(walks, DirectPass, sink, root).Length);
        }

        // The hop count of a pass's path from a reached root to its sink, and whether no edge on it is deferred, memoised
        // per node in walks[pass] as length * 2 + (deferred ? 1 : 0), 0 for not yet known. The next hops form a forest
        // rooted at the sinks, so each node is walked once per pass and sink: O(nodes) in all, however many roots.
        private (int Length, bool Direct) Walk(int[][] walks, int pass, int sink, int root)
        {
            var memo = walks[pass] ??= new int[nodes.Length];
            if (memo[root] == 0)
            {
                var hop = hops[pass, sink];
                var chain = new List<int>();
                var at = root;
                for (; memo[at] == 0 && hop[at] >= 0 && chain.Count <= nodes.Length; at = edgeTo[hop[at]])
                    chain.Add(at);
                var value = memo[at] = memo[at] == 0 ? 2 : memo[at];
                for (var i = chain.Count - 1; i >= 0; i--)
                    memo[chain[i]] = value = (value & ~1) + 2 | (value & 1) | (IsDeferred(edgeKind[hop[chain[i]]]) ? 1 : 0);
            }
            return (memo[root] >> 1, (memo[root] & 1) == 0);
        }

        // Multi-source BFS over the reverse edges of one pass from every node that is the sink: each node's next hop is
        // the edge it was first discovered over (Sink at a sink, Unreached when it cannot reach one).
        private int[] Propagate(int pass, int sink)
        {
            var hop = new int[nodes.Length];
            Array.Fill(hop, Unreached);
            var queue = new Queue<int>();
            var bit = 1 << sink;
            var tierBit = 1 << pass;
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

        // The path from root to the nearest sink on one pass, read off the next hops: the first MaxPathHops - 2 hops are
        // kept, and the last two always, so the report stays small however long the path (S2 review W1). The walk is
        // bounded by the node count: next hops come from a BFS, so they cannot cycle, and the bound only guards that.
        private ReachPath Path(int pass, ReachEvidence evidence, int sink, int root)
        {
            var hop = hops[pass, sink];
            var head = new List<ReachHop> { Hop(root, null, 0) };
            var tail = new Queue<(int Node, MethodEdgeKind Kind, uint Offset)>();
            var length = 1;
            var direct = true;
            var at = root;
            for (var edge = hop[at]; edge >= 0 && length <= nodes.Length; edge = hop[at])
            {
                at = edgeTo[edge];
                length++;
                direct &= !IsDeferred(edgeKind[edge]);
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
            return new ReachPath(Bound(nodes[root].NodeId), evidence, direct, [.. head, .. tail.Select(t => Hop(t.Node, t.Kind, t.Offset))], length, truncated,
                sink == unseenSink && opacityAt.TryGetValue(at, out var kind) ? kind : null);
        }

        private RootClassStatus Status(RootClass cls, int[] members)
        {
            var reasons = graph.Facts.Gaps.Where(g => (g.Class & cls) != 0).Select(g => $"{Bound(g.Assembly)}: {g.Reason}").ToList();
            var unseen = members.Count(r => Reached((int)ReachEvidence.ChaOnly, unseenSink, r));
            if (unseen > 0)
                reasons.Add($"{unseen} root(s) reach code the graph cannot see");
            var coverage = graph.Coverage;
            if (coverage.Truncated)
                reasons.Add($"the graph is truncated: {coverage.TruncatedBy}");
            if (!(coverage.Index with { ReaderAssertions = 0 }).IsComplete)
                reasons.Add("the member index is incomplete: some assemblies, types, methods, forwarders or supertypes could not be read");
            if (coverage.Index.ReaderAssertions > 0)
                reasons.Add($"the metadata reader failed {coverage.Index.ReaderAssertions} assertion(s): the model may be degraded");
            if (coverage.ModulesUnreadable > 0)
                reasons.Add($"{coverage.ModulesUnreadable} module(s) unreadable: whether they have renamed implementations that CHA does not follow is unknown");
            if (coverage.RenamedImplementations > 0)
                reasons.Add($"{coverage.RenamedImplementations} MethodImpl row(s) bind renamed implementations that CHA does not follow");

            var verdict = reasons.Count > 0 ? RootClassVerdict.Unknown
                : members.Any(r => (Mask((int)ReachEvidence.ChaOnly, r) & ~(1 << unseenSink)) != 0) ? RootClassVerdict.Reaches
                : RootClassVerdict.None;
            return new RootClassStatus(cls, members.Length, verdict, reasons);
        }

        // The sinks a root reaches on one pass, as bits (capabilities by enum value, then Unseen).
        private int Mask(int pass, int root) =>
            Enumerable.Range(0, sinks).Where(s => Reached(pass, s, root)).Aggregate(0, (mask, s) => mask | (1 << s));

        private static Capability[] Capabilities(int mask) =>
            [.. Enumerable.Range(0, capabilities.Length).Where(c => (mask & (1 << c)) != 0).Select(c => capabilities[c])];

        private bool Reached(int pass, int sink, int node) => hops[pass, sink][node] != Unreached;

        // Bound before Instantiated before ChaOnly: each tier's edges contain the one before's.
        private ReachEvidence Strongest(int sink, int node) =>
            Reached((int)ReachEvidence.Bound, sink, node) ? ReachEvidence.Bound
            : Reached((int)ReachEvidence.Instantiated, sink, node) ? ReachEvidence.Instantiated
            : ReachEvidence.ChaOnly;

        private ReachHop Hop(int node, MethodEdgeKind? via, uint offset) =>
            new(Bound(nodes[node].NodeId), facts.TryGetValue(nodes[node].NodeId, out var own) ? Bound(own.Assembly) : null, via, offset);

        // A name bounded once and counted once however often it is reported (amendment a5).
        private string Bound(string name)
        {
            if (name.Length <= MaxNameChars)
                return name;
            if (!bounded.TryGetValue(name, out var cut))
                bounded[name] = cut = BoundName(name);
            return cut;
        }

        // An edge that makes a method value (a delegate, a function pointer, a method handle) without calling it: the
        // target runs only if that value is invoked later (amendment a2; LoadToken by the S0–S3 review, W3).
        private static bool IsDeferred(MethodEdgeKind kind) => kind is MethodEdgeKind.Ldftn or MethodEdgeKind.Ldvirtftn or MethodEdgeKind.LoadToken;

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
        // Per pass (the three tiers, then Direct) and sink, each node's next hop: an index into the edge arrays, Sink, or
        // Unreached.
        private readonly int[,][] hops;
        // Each name cut so far, to its bounded form.
        private readonly Dictionary<string, string> bounded = new(StringComparer.Ordinal);

        private const int Passes = 4;
        private const int DirectPass = 3;
        private const int DirectBit = 1 << DirectPass;
        private const int AllTiers = 0b111;
        private const int Sink = -1;
        private const int Unreached = -2;
        #endregion
    }
    #endregion
}
