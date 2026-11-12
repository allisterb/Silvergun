namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// One call site of a capability sink in an own body: the edge from <paramref name="NodeId"/> at IL offset
/// <paramref name="Offset"/> to <paramref name="Callee"/> (a node id; <paramref name="CalleeKey"/> its classification
/// key), which is a sink for <paramref name="Capability"/>. Names are raw graph node ids.
/// </summary>
public sealed record SinkSite(string NodeId, uint Offset, MethodEdgeKind EdgeKind, string Callee, string CalleeKey, Capability Capability);

/// <summary>The capability-sink call sites of a <see cref="MethodGraph"/>, for the SSA facts (ADR 0038, S4).</summary>
public static class SinkSites
{
    #region Methods
    /// <summary>
    /// Every edge from an own node to a node that is a sink for a capability (<see cref="Reachability"/>'s rule, decision
    /// 2) and that is an instruction of the caller: <see cref="MethodEdgeKind.Call"/>, <see cref="MethodEdgeKind.CallVirt"/>,
    /// <see cref="MethodEdgeKind.NewObj"/>, <see cref="MethodEdgeKind.Ldftn"/> or <see cref="MethodEdgeKind.Ldvirtftn"/>.
    /// Edges the map's <c>ignore-edge</c> rules cut are left out, as reachability leaves them out; so are sinks for unseen
    /// code only, and implied, Dispatch and LoadToken edges. Distinct, ordinal by node id, offset, callee and kind.
    /// <paramref name="map"/> defaults to <see cref="CapabilityMap.Default"/>.
    /// </summary>
    public static IReadOnlyList<SinkSite> Of(MethodGraph graph, CapabilityMap? map = null)
    {
        ArgumentNullException.ThrowIfNull(graph);
        map ??= CapabilityMap.Default;
        var facts = new Dictionary<string, OwnMethodFacts>(StringComparer.Ordinal);
        foreach (var method in graph.Facts.Methods)
            facts.TryAdd(method.NodeId, method);
        var sinks = new Dictionary<string, Capability>(StringComparer.Ordinal);
        foreach (var node in graph.Nodes)
        {
            if (Reachability.SinkOf(node, facts.GetValueOrDefault(node.NodeId), map).Capability is { } capability)
                sinks[node.NodeId] = capability;
        }

        return
        [
            .. graph.Edges
                .Where(e => callSiteKinds.Contains(e.Kind) && sinks.ContainsKey(e.To))
                .Select(e => (Edge: e, From: graph.Node(e.From), To: graph.Node(e.To)!))
                .Where(e => e.From is { Kind: not MethodNodeKind.External } && !map.IsIgnoredEdge(e.From.ClassificationKey, e.To.ClassificationKey))
                .Select(e => new SinkSite(e.Edge.From, e.Edge.Offset, e.Edge.Kind, e.Edge.To, e.To.ClassificationKey, sinks[e.Edge.To]))
                .Distinct()
                .OrderBy(s => s.NodeId, StringComparer.Ordinal).ThenBy(s => s.Offset).ThenBy(s => s.Callee, StringComparer.Ordinal).ThenBy(s => s.EdgeKind),
        ];
    }
    #endregion

    #region Fields
    private static readonly HashSet<MethodEdgeKind> callSiteKinds =
        [MethodEdgeKind.Call, MethodEdgeKind.CallVirt, MethodEdgeKind.NewObj, MethodEdgeKind.Ldftn, MethodEdgeKind.Ldvirtftn];
    #endregion
}
