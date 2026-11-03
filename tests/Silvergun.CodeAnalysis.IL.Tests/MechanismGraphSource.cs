namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// What the gated ground-truth theories need from a call graph, in the matcher's own minimal terms: adjacency
/// (node id → successors, every node a key), a node classifier, and the opacity records as (site node id, kind).
/// </summary>
public sealed record MechanismGraph(
    IReadOnlyDictionary<string, IReadOnlyList<string>> Adjacency,
    Func<string, Capability?> CapabilityOf,
    IReadOnlyList<(string Site, OpacityKind Kind)> Opacities);

/// <summary>
/// The single seam between <see cref="MechanismGroundTruthTests"/> and the real <see cref="MethodGraph"/>.
/// <para>
/// The graph is built over <b>both</b> mechanism-fixture assemblies in one <see cref="MemberIndex"/> (so the
/// CrossAssembly rows see the Dependency side), each loaded with <see cref="AssemblyDisassembler"/>. It is whatever
/// <c>src/</c> builds today: phase A1 records static targets only, and A2 adds its CHA, state-machine and
/// type-initializer edges inside <see cref="MethodGraph.Build"/> itself — so bumping
/// <see cref="MechanismGroundTruth.CurrentPhase"/> to A2 before those land turns the A2 rows red, never green.
/// </para>
/// <para>
/// <see cref="MechanismGraph.CapabilityOf"/> classifies <see cref="MethodNodeKind.External"/> nodes only, with
/// <c>CapabilityMap.Default.Classify(node.ClassificationKey)</c>: an own node is never a capability by itself. The
/// <see cref="Phase.Reachability"/> rule for own bodyless externs (P/Invoke) has no test-side counterpart yet, so
/// asking for that phase throws rather than evaluating its rows under a classifier that cannot pass them.
/// </para>
/// </summary>
public static class MechanismGraphSource
{
    #region Methods
    public static MechanismGraph Build(Phase phase) =>
        phase < Phase.Reachability
            ? graph.Value
            : throw new NotSupportedException(
                $"Phase {phase} needs the bodyless-extern classification rule (reachability ADR), which MechanismGraphSource does not model yet.");

    /// <summary>The matcher's view of a real graph: every node a key, successors distinct and in edge order.</summary>
    public static MechanismGraph From(MethodGraph graph)
    {
        var adjacency = graph.Nodes.ToDictionary(
            n => n.NodeId,
            n => (IReadOnlyList<string>)graph.Successors(n.NodeId).Select(e => e.To).Distinct(StringComparer.Ordinal).ToArray(),
            StringComparer.Ordinal);
        var external = graph.Nodes.Where(n => n.Kind == MethodNodeKind.External)
            .ToDictionary(n => n.NodeId, n => n.ClassificationKey, StringComparer.Ordinal);

        Capability? CapabilityOf(string nodeId) =>
            external.TryGetValue(nodeId, out var key) && CapabilityMap.Default.Classify(key) is { Class: CapabilityClass.Capability } verdict
                ? verdict.Capability
                : null;

        return new MechanismGraph(adjacency, CapabilityOf, [.. graph.Opacities.Select(o => (o.Site, o.Kind))]);
    }

    // Built once per test run: plain strings only, so the Analysis.Net hosts are released as soon as it exists.
    private static MechanismGraph BuildFixtureGraph()
    {
        using var assemblies = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        return From(MethodGraph.Build(assemblies.Index()));
    }
    #endregion

    #region Fields
    private static readonly Lazy<MechanismGraph> graph = new(BuildFixtureGraph);
    #endregion
}
