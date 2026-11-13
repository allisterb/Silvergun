namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Cilica.AsmIO;
using Cilica.IR;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// One folder of the <c>ssa-join</c> child (<c>docs/agent/tasks/ssa-facts-s4.md</c>, S4.5): the per-site join of every
/// lifted method's call sites with the graph's call-site edges, by (node id, IL offset), and the product path's facts.
/// <list type="bullet">
/// <item><description>Methods: definitions SSA listed, lifted or Unknown, and how many of each have their node id among
/// the graph's own nodes. Own nodes with a body, and how many have an SSA outcome.</description></item>
/// <item><description>SSA sites: every call, <c>newobj</c> and <c>ldftn</c>/<c>ldvirtftn</c> instruction of a lifted body
/// whose node is own; joined when an edge of the same kind group from the node at the offset has the callee's
/// classification key. <see cref="SsaSitesKindExact"/>: joined with call/callvirt the same too.</description></item>
/// <item><description>Edge sites: every (node, offset, kind group) of call-site edges from an own node with a lifted
/// definition; joined when an SSA site there has one of the edges' callee keys. Nodes with only Unknown definitions are
/// left out (<see cref="EdgeSitesOfUnknownNodes"/>), and nodes with no SSA outcome at all are counted apart
/// (<see cref="EdgeSitesOfNodesNotInSsa"/>, also a miss class).</description></item>
/// <item><description>Misses by class, with up to <see cref="SsaJoinChild.ExamplesPerClass"/> examples each; in a
/// truncated graph every class is prefixed <c>truncated:</c>.</description></item>
/// <item><description>The product path (<see cref="SsaSinkFacts.Extract"/> over <see cref="SinkSites.Of"/>, as the
/// worker runs it): its facts' digest and whether a budget cut them, for comparison with the worker's, and its NotJoined
/// sites by join class. <see cref="Misaligned"/>: facts whose site did not match the raw site at its position.</description></item>
/// </list>
/// </summary>
public sealed record SsaJoinFolder(
    string Folder,
    bool Built,
    int Nodes,
    int Edges,
    bool GraphTruncated,
    int AssembliesLost,
    int Methods,
    int Lifted,
    int LiftedInGraph,
    int Unknown,
    int UnknownInGraph,
    int OwnBodies,
    int OwnBodiesInSsa,
    int SsaSites,
    int SsaSitesJoined,
    int SsaSitesKindExact,
    Dictionary<string, int> SsaMisses,
    int EdgeSites,
    int EdgeSitesJoined,
    int EdgeSitesAmbiguous,
    int EdgeSitesOfUnknownNodes,
    int EdgeSitesOfNodesNotInSsa,
    Dictionary<string, int> EdgeMisses,
    int SinkSites,
    string? FactsDigest,
    bool FactsCut,
    int Misaligned,
    Dictionary<string, int> NotJoinedByClass,
    List<string> Examples,
    long GraphMs,
    long LiftAllMs,
    long FactsMs);

/// <summary>What the <c>ssa-join</c> child measured for one package.</summary>
public sealed record SsaJoinPayload(IReadOnlyList<SsaJoinFolder> Folders, string Configuration);

/// <summary>
/// The child half of <c>--ssa</c>: in its own process (ADR 0021), every folder of <b>one</b> cached <c>.nupkg</c>: the
/// graph, built alone per folder and reduced to plain data, then every method lifted (in node-id order) and joined to the
/// graph's edges, then the product path's facts in a fresh session.
/// <para>
/// Protocol: <c>&lt;harness&gt; ssa-join &lt;nupkg&gt; &lt;out-json&gt;</c> writes a <see cref="SsaJoinPayload"/>, then prints
/// <c>DONE</c>; the extraction directory is named on stderr as for <c>reach</c>. Exit codes: 0 done; 1 a catchable failure;
/// 2 bad usage.
/// </para>
/// </summary>
public static class SsaJoinChild
{
    #region Methods
    public static int Execute(string[] args)
    {
        try
        {
            if (args.Length != 3)
            {
                Console.Error.WriteLine($"USAGE: <harness> {Verb} <nupkg> <out-json>");
                return 2;
            }

            Runtime.Initialize("Silvergun", "CORPUS");
            var payload = Measure(args[1], dir => Console.Error.WriteLine($"{ReachabilityChild.ExtractionMarker}\t{dir}"));
            PackageReachResult.WriteAtomically(args[2], JsonSerializer.Serialize(payload, PackageReachResult.JsonOptions));
            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>The join over the package at <paramref name="nupkgPath"/>. Unguarded: only ever called in a child.</summary>
    public static SsaJoinPayload Measure(string nupkgPath, Action<string>? reportExtraction = null)
    {
        var opened = NuGetPackage.Open(nupkgPath);
        if (!opened.IsSuccess)
            throw new InvalidOperationException($"the package could not be opened: {opened.Message}");
        using var package = opened.Value;
        reportExtraction?.Invoke(package.ExtractionDir);

        // A folder is the directory its assemblies were extracted to, as PackageGraphs groups them; each is built alone.
        var folders = new List<SsaJoinFolder>();
        foreach (var members in package.Assemblies.GroupBy(a => Path.GetDirectoryName(a.FullPath) ?? string.Empty, StringComparer.Ordinal))
        {
            var clock = Stopwatch.StartNew();
            var input = Prepare([.. members]);
            var graphMs = clock.ElapsedMilliseconds;
            folders.Add(input.Built ? Join(input, graphMs) : Empty(input.Folder, graphMs));
        }
        return new SsaJoinPayload([.. folders.OrderBy(f => f.Folder, StringComparer.Ordinal)], SsaMeasure.Configuration);
    }

    /// <summary>The SHA-256 of <paramref name="facts"/> serialized with <see cref="FactsOptions"/>; null for none.</summary>
    public static string? Digest(SsaFolderFacts? facts) =>
        facts is null ? null : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(facts, FactsOptions))));

    private static SsaJoinFolder Empty(string folder, long graphMs) =>
        new(folder, false, 0, 0, false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, [], 0, 0, 0, 0, 0, [], 0, null, false, 0, [], [], graphMs, 0, 0);

    // One folder's graph, reduced to what the join needs; nothing returned holds the graph, so it is collectable once
    // this returns. Not inlined, so no caller frame keeps it.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static JoinInput Prepare(PackageAssembly[] members)
    {
        var built = PackageGraphs.Build(members).Single();
        if (built.Graph is not { } graph)
            return new JoinInput(built.Folder, false, [], 0, 0, false, [], OwnMembers.None, [], [], []);
        // The loaded files in the graph's order (ordinal by package path), as the worker opens its session.
        var fullPaths = members.GroupBy(m => m.RelativePath, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().FullPath, StringComparer.Ordinal);
        var own = graph.Nodes.Where(n => n.Kind != MethodNodeKind.External).Select(n => n.NodeId).ToHashSet(StringComparer.Ordinal);
        var edges = graph.Edges
            .Where(e => callSiteKinds.Contains(e.Kind) && own.Contains(e.From))
            .GroupBy(e => e.From, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(e => new EdgeSite(e.Offset, Group(e.Kind), e.Kind, e.To, graph.Node(e.To)?.ClassificationKey)).ToArray(), StringComparer.Ordinal);
        return new JoinInput(built.Folder, true, [.. built.Assemblies.Select(a => fullPaths[a])],
            graph.Nodes.Count, graph.Edges.Count, graph.Coverage.Truncated, SinkSites.Of(graph, CapabilityMap.Default), OwnMembers.Of(graph), own,
            graph.Nodes.Where(n => n.Kind == MethodNodeKind.OwnWithBody).Select(n => n.NodeId).ToHashSet(StringComparer.Ordinal), edges);
    }

    private static SsaJoinFolder Join(JoinInput input, long graphMs)
    {
        // As the worker does before its SSA phase, so the graph's statics do not add to the lift's memory.
        AssemblyDisassembler.ReleaseStatics();
        var prefix = input.Truncated ? "truncated:" : "";
        var examples = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        void Note(Dictionary<string, int> counts, string @class, string example)
        {
            @class = prefix + @class;
            counts[@class] = counts.GetValueOrDefault(@class) + 1;
            if (!examples.TryGetValue(@class, out var list))
                examples[@class] = list = [];
            if (list.Count < ExamplesPerClass)
                list.Add(example);
        }

        var sinkNodes = input.Sinks.Select(s => s.NodeId).ToHashSet(StringComparer.Ordinal);
        var outcomes = new Dictionary<string, (int Lifted, int Unknown)>(StringComparer.Ordinal);
        // Kept only for nodes with sink sites, to class the product path's NotJoined sites.
        var sinkSsa = new Dictionary<string, NodeSsa>(StringComparer.Ordinal);
        var ssaMisses = new Dictionary<string, int>(StringComparer.Ordinal);
        var edgeMisses = new Dictionary<string, int>(StringComparer.Ordinal);
        var c = new Counts();
        ILookup<string, string>? ownByShape = null;
        // Graph nodes whose id is an SSA node's with pointers rendered as by-refs, that SSA node being off the graph.
        var byrefRendered = new HashSet<string>(StringComparer.Ordinal);

        var lift = Stopwatch.StartNew();
        string? current = null;
        var state = new NodeSsa();
        using (var session = SsaSession.Open(input.Paths))
        {
            c.Lost = session.Assemblies.Count(a => !a.IsLoaded);
            // Node-id order, so each node's sites are joined and dropped before the next.
            foreach (var outcome in session.Lift(_ => true))
            {
                var node = outcome.NodeId;
                if (node != current)
                {
                    if (current is not null)
                        Finish(current, state);
                    current = node;
                    state = new NodeSsa();
                }
                c.Methods++;
                var inGraph = input.Own.Contains(node);
                if (!outcome.IsLifted)
                {
                    c.Unknown++;
                    c.UnknownInGraph += inGraph ? 1 : 0;
                    state.Unknown++;
                    if (!inGraph)
                        Note(ssaMisses, "method:unknown-node-not-in-graph" + NotInGraphReason(node), Show(node));
                    continue;
                }
                c.Lifted++;
                state.Lifted++;
                if (!inGraph)
                {
                    Note(ssaMisses, "method:lifted-node-not-in-graph" + NotInGraphReason(node), Show(node));
                    continue;
                }
                c.LiftedInGraph++;
                foreach (var instruction in outcome.Body!.Instructions())
                {
                    if (outcome.OffsetOf(instruction) is not { } offset)
                        continue;
                    if (instruction is CilIntrinsic.InitializeArray)
                        state.InitializeArray.Add(offset);
                    else if (instruction is CilIntrinsic.CallIndirect)
                        state.CallIndirect.Add(offset);
                    else if (instruction is CallInst { Method: MDArrayMethod } or NewObjInst { Constructor: MDArrayMethod })
                        state.ArrayAccessor.Add(offset);
                }
                state.EdgesByOffset ??= (input.Edges.GetValueOrDefault(node) ?? []).ToLookup(e => e.Offset);
                foreach (var site in SsaSinkFacts.CallSites(outcome))
                {
                    c.SsaSites++;
                    if (!state.Sites.TryGetValue(site.Offset, out var atOffset))
                        state.Sites[site.Offset] = atOffset = [];
                    atOffset.Add(site);
                    var there = state.EdgesByOffset[site.Offset].ToArray();
                    var sameGroup = there.Where(e => e.Group == Group(site.Kind)).ToArray();
                    var example = $"{Show(node)} @{site.Offset} {site.Kind} {Show(site.CalleeKey ?? "?")}";
                    if (there.Length == 0)
                        Note(ssaMisses, state.ArrayAccessor.Contains(site.Offset) ? "site:no-edge(md-array-accessor)" : "site:no-edge", example);
                    else if (sameGroup.Length == 0)
                        Note(ssaMisses, "site:edge-of-another-kind", example + " vs " + string.Join(",", there.Select(e => e.Kind).Distinct()));
                    else if (site.CalleeKey is null)
                        Note(ssaMisses, "site:callee-unreadable", example);
                    else if (!sameGroup.Any(e => e.Key == site.CalleeKey))
                        Note(ssaMisses, "site:callee-key-differs", example + " vs " + string.Join(",", sameGroup.Select(e => Show(e.Key ?? "?")).Distinct().Take(3)));
                    else
                    {
                        c.SsaSitesJoined++;
                        c.SsaSitesKindExact += sameGroup.Any(e => e.Key == site.CalleeKey && e.Kind == site.Kind) ? 1 : 0;
                    }
                }
            }
            if (current is not null)
                Finish(current, state);
        }
        var liftMs = lift.ElapsedMilliseconds;

        // Edge sites of own nodes SSA listed nothing under.
        foreach (var (node, edges) in input.Edges.Where(e => !outcomes.ContainsKey(e.Key)))
        {
            var reason = byrefRendered.Contains(node) ? "(pointer-as-byref)" : "";
            foreach (var group in edges.GroupBy(e => (e.Offset, e.Group)))
            {
                c.EdgeSitesNotInSsa++;
                Note(edgeMisses, "edge:node-not-in-ssa" + reason, $"{Show(node)} @{group.Key.Offset} {group.Key.Group}");
            }
        }

        // The product path, in a fresh session as the worker opens it, with its NotJoined sites classed by the join.
        var factsClock = Stopwatch.StartNew();
        SsaFolderFacts? facts = null;
        if (input.Sinks.Count > 0)
        {
            using var session = SsaSession.Open(input.Paths);
            facts = SsaSinkFacts.Extract(session, input.Sinks, SsaFactBounds.Default, members: input.Members);
        }
        var factsMs = factsClock.ElapsedMilliseconds;
        var notJoined = new Dictionary<string, int>(StringComparer.Ordinal);
        var misaligned = 0;
        // Extract's own site order, whose facts carry bounded names, so the raw sites are matched by position and checked.
        var ordered = input.Sinks.Distinct()
            .OrderBy(s => s.NodeId, StringComparer.Ordinal).ThenBy(s => s.Offset).ThenBy(s => s.Callee, StringComparer.Ordinal).ThenBy(s => s.EdgeKind)
            .ThenBy(s => s.CalleeKey, StringComparer.Ordinal).ThenBy(s => s.Capability)
            .ToArray();
        foreach (var (site, fact) in facts is null ? [] : ordered.Zip(facts.Sites).ToArray())
        {
            if (fact.Site.Offset != site.Offset || fact.Site.EdgeKind != site.EdgeKind || fact.Site.NodeId != Reachability.BoundName(site.NodeId))
            {
                misaligned++;
                continue;
            }
            if (fact.Status != SsaSiteStatus.NotJoined)
                continue;
            var counts = outcomes.GetValueOrDefault(site.NodeId);
            var node = sinkSsa.GetValueOrDefault(site.NodeId);
            var ssa = node?.Sites.GetValueOrDefault(site.Offset) ?? [];
            var sameGroup = ssa.Where(s => Group(s.Kind) == Group(site.EdgeKind)).ToArray();
            var @class = counts.Lifted == 0 ? (counts.Unknown > 0 ? "sink:node-only-unknown" : "sink:node-not-in-ssa")
                : ssa.Count == 0 ? (node?.InitializeArray.Contains(site.Offset) == true ? "sink:initialize-array-intrinsic" : "sink:no-ssa-instruction")
                : sameGroup.Length == 0 ? "sink:ssa-site-of-another-kind"
                : !sameGroup.Any(s => s.CalleeKey == site.CalleeKey) ? "sink:callee-key-differs"
                : "sink:unexplained";
            Note(notJoined, @class, $"{Show(site.NodeId)} @{site.Offset} {site.EdgeKind} {Show(site.CalleeKey)}");
        }

        return new SsaJoinFolder(input.Folder, true, input.Nodes, input.EdgeCount, input.Truncated, c.Lost,
            c.Methods, c.Lifted, c.LiftedInGraph, c.Unknown, c.UnknownInGraph,
            input.OwnBodies.Count, input.OwnBodies.Count(outcomes.ContainsKey),
            c.SsaSites, c.SsaSitesJoined, c.SsaSitesKindExact, ssaMisses,
            c.EdgeSites, c.EdgeSitesJoined, c.Ambiguous, c.EdgeSitesOfUnknown, c.EdgeSitesNotInSsa, edgeMisses,
            input.Sinks.Count, Digest(facts), facts is { TimeBudget: true } or { MethodBudget: true }, misaligned, notJoined,
            [.. examples.OrderBy(e => e.Key, StringComparer.Ordinal).SelectMany(e => e.Value.Select(x => $"{e.Key}\t{x}"))],
            graphMs, liftMs, factsMs);

        // Why a node SSA listed is not an own graph node, when the cause is known (S4.5): the Model drops the module type, so
        // `<Module>` methods (module initializers, global functions) are not in the graph (GraphCoverage.ModuleInitializers);
        // and the Model renders some pointer parameters as by-refs, so the graph's id has `&` where CCI's has `*` (one way only).
        // A graph node matched here is recorded, and only its edges are classed pointer-as-byref.
        string NotInGraphReason(string node)
        {
            if (node.StartsWith("<Module>.", StringComparison.Ordinal))
                return "(module-type)";
            ownByShape ??= input.Own.ToLookup(Shape, StringComparer.Ordinal);
            var rendered = ownByShape[Shape(node)].Where(own => ByrefRendered(own, node)).ToArray();
            byrefRendered.UnionWith(rendered);
            return rendered.Length > 0 ? "(pointer-as-byref)" : "";
        }

        // One node's edge sites against its SSA sites, once all its definitions are read.
        void Finish(string node, NodeSsa ssa)
        {
            outcomes[node] = (ssa.Lifted, ssa.Unknown);
            if (sinkNodes.Contains(node))
                sinkSsa[node] = ssa;
            if (input.Edges.GetValueOrDefault(node) is not { } edges)
                return;
            foreach (var group in edges.GroupBy(e => (e.Offset, e.Group)))
            {
                if (ssa.Lifted == 0)
                {
                    c.EdgeSitesOfUnknown++;
                    continue;
                }
                c.EdgeSites++;
                var (offset, kindGroup) = group.Key;
                c.Ambiguous += group.Select(e => e.To).Distinct(StringComparer.Ordinal).Count() > 1 ? 1 : 0;
                var keys = group.Select(e => e.Key).OfType<string>().ToHashSet(StringComparer.Ordinal);
                var there = ssa.Sites.GetValueOrDefault(offset) ?? [];
                var sameGroup = there.Where(s => Group(s.Kind) == kindGroup).ToArray();
                var example = $"{Show(node)} @{offset} {string.Join(",", group.Select(e => e.Kind).Distinct())} {string.Join(",", keys.Take(3).Select(Show))}";
                if (sameGroup.Any(s => s.CalleeKey is { } key && keys.Contains(key)))
                    c.EdgeSitesJoined++;
                else if (sameGroup.Length > 0)
                    Note(edgeMisses, "edge:callee-key-differs", example + " vs " + string.Join(",", sameGroup.Select(s => Show(s.CalleeKey ?? "?")).Distinct().Take(3)));
                else if (ssa.InitializeArray.Contains(offset))
                    Note(edgeMisses, "edge:initialize-array-intrinsic", example);
                else if (ssa.CallIndirect.Contains(offset))
                    Note(edgeMisses, "edge:call-indirect-intrinsic", example);
                else if (ssa.Unknown > 0)
                    Note(edgeMisses, "edge:node-partly-lifted", example);
                else if (there.Count > 0)
                    Note(edgeMisses, "edge:ssa-site-of-another-kind", example + " vs " + string.Join(",", there.Select(s => s.Kind).Distinct()));
                else
                    Note(edgeMisses, "edge:no-ssa-instruction", example);
            }
        }
    }

    // A node id with by-refs and pointers alike, to recognise the Model's pointer-as-byref rendering.
    private static string Shape(string nodeId) => nodeId.Replace('&', '*');

    // Whether the graph's id is CCI's with some pointers rendered as by-refs: equal but for `&` in the graph's where CCI's has `*`.
    private static bool ByrefRendered(string graph, string cci) =>
        graph != cci && graph.Length == cci.Length && graph.Zip(cci).All(p => p.First == p.Second || (p.First == '&' && p.Second == '*'));

    // Call and callvirt join each other, as in SsaSinkFacts.Extract; the rest only themselves.
    private static string Group(MethodEdgeKind kind) => kind is MethodEdgeKind.Call or MethodEdgeKind.CallVirt ? "call" : kind.ToString();

    // Package-controlled text as one bounded printable line.
    private static string Show(string text) => Reachability.BoundName(UntrustedText.Escape(text));
    #endregion

    #region Fields
    public const string Verb = "ssa-join";

    public const int ExamplesPerClass = 3;

    /// <summary>How facts are serialized for their digest: compact, enum names, every member.</summary>
    public static readonly JsonSerializerOptions FactsOptions = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        IgnoreReadOnlyProperties = true,
    };

    private static readonly HashSet<MethodEdgeKind> callSiteKinds =
        [MethodEdgeKind.Call, MethodEdgeKind.CallVirt, MethodEdgeKind.NewObj, MethodEdgeKind.Ldftn, MethodEdgeKind.Ldvirtftn];
    #endregion

    #region Child types
    // One call-site edge, as plain data.
    private sealed record EdgeSite(uint Offset, string Group, MethodEdgeKind Kind, string To, string? Key);

    // A folder's graph as the join needs it, holding no graph.
    private sealed record JoinInput(
        string Folder, bool Built, IReadOnlyList<string> Paths, int Nodes, int EdgeCount, bool Truncated, IReadOnlyList<SinkSite> Sinks, OwnMembers Members,
        HashSet<string> Own, HashSet<string> OwnBodies, Dictionary<string, EdgeSite[]> Edges);

    // One node's SSA side: its definitions' outcomes, call sites by offset, and the offsets of intrinsics and MD-array accessors.
    private sealed class NodeSsa
    {
        public int Lifted;
        public int Unknown;
        public readonly Dictionary<uint, List<SsaCallSite>> Sites = [];
        public readonly HashSet<uint> InitializeArray = [];
        public readonly HashSet<uint> CallIndirect = [];
        public readonly HashSet<uint> ArrayAccessor = [];
        public ILookup<uint, EdgeSite>? EdgesByOffset;
    }

    private sealed class Counts
    {
        public int Lost, Methods, Lifted, LiftedInGraph, Unknown, UnknownInGraph, SsaSites, SsaSitesJoined, SsaSitesKindExact;
        public int EdgeSites, EdgeSitesJoined, Ambiguous, EdgeSitesOfUnknown, EdgeSitesNotInSsa;
    }
    #endregion
}
