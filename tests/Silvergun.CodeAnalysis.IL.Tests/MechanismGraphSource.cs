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
/// The graph is built over <b>all three</b> mechanism-fixture assemblies in one <see cref="MemberIndex"/>: the Release
/// fixture, its Dependency (so the CrossAssembly rows see the far side) and, since A2 S2, the Debug-built fixture
/// (namespace root <c>MechanismFixture.Debug</c>, class state machines) — each loaded with
/// <see cref="AssemblyDisassembler"/>. It is whatever <c>src/</c> builds today: phase A1 records static targets only,
/// and A2 adds its CHA, state-machine, type-initializer and <c>ldtoken</c> edges (and the module opacity) inside
/// <see cref="MethodGraph.Build"/> itself — so bumping <see cref="MechanismGroundTruth.CurrentPhase"/> past what has
/// landed (today the whole of <see cref="Phase.A2"/>) turns the later rows red, never green. <see cref="BuildStatic"/>
/// is the same graph with every <see cref="MethodEdgeKind.Dispatch"/> edge removed, <see cref="BuildWithoutStateMachines"/>
/// with every <see cref="MethodEdgeKind.StateMachine"/> edge removed, <see cref="BuildWithout"/> with the edges of any
/// given kinds removed, and <see cref="BuildWithoutDebugFixture"/> the full graph over the Release fixture and its
/// Dependency alone (what the table was checked against before S2).
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

    /// <summary>The fixture graph without its <see cref="MethodEdgeKind.Dispatch"/> edges.</summary>
    public static MechanismGraph BuildStatic() => BuildWithout(MethodEdgeKind.Dispatch);

    /// <summary>The fixture graph without its <see cref="MethodEdgeKind.StateMachine"/> edges.</summary>
    public static MechanismGraph BuildWithoutStateMachines() => BuildWithout(MethodEdgeKind.StateMachine);

    /// <summary>The fixture graph without its edges of the given <paramref name="kinds"/>; each view is built once.</summary>
    public static MechanismGraph BuildWithout(params MethodEdgeKind[] kinds)
    {
        var key = string.Join(",", kinds.Distinct().Order());
        return without.GetOrAdd(key, _ => new Lazy<MechanismGraph>(() => From(built.Value, e => !kinds.Contains(e.Kind)))).Value;
    }

    /// <summary>The full graph over the Release fixture and its Dependency only, without the Debug-built fixture.</summary>
    public static MechanismGraph BuildWithoutDebugFixture() => withoutDebugFixture.Value;

    /// <summary>
    /// The matcher's view of a real graph: every node a key, successors distinct and in edge order — only the edges
    /// <paramref name="keep"/> accepts, when given.
    /// </summary>
    public static MechanismGraph From(MethodGraph graph, Func<MethodEdge, bool>? keep = null)
    {
        var adjacency = graph.Nodes.ToDictionary(
            n => n.NodeId,
            n => (IReadOnlyList<string>)graph.Successors(n.NodeId).Where(e => keep?.Invoke(e) ?? true).Select(e => e.To).Distinct(StringComparer.Ordinal).ToArray(),
            StringComparer.Ordinal);
        var external = graph.Nodes.Where(n => n.Kind == MethodNodeKind.External)
            .ToDictionary(n => n.NodeId, n => n.ClassificationKey, StringComparer.Ordinal);

        Capability? CapabilityOf(string nodeId) =>
            external.TryGetValue(nodeId, out var key) && CapabilityMap.Default.Classify(key) is { Class: CapabilityClass.Capability } verdict
                ? verdict.Capability
                : null;

        return new MechanismGraph(adjacency, CapabilityOf, [.. graph.Opacities.Select(o => (o.Site, o.Kind))]);
    }

    // Built once per test run. The MethodGraph holds plain strings only (nodes, edges, opacities, coverage), so the
    // Analysis.Net hosts are released as soon as it exists.
    private static MethodGraph BuildFixtureGraph()
    {
        using var assemblies = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.DebugFixture);
        return MethodGraph.Build(assemblies.Index());
    }

    private static MechanismGraph BuildReleaseGraph()
    {
        using var assemblies = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        return From(MethodGraph.Build(assemblies.Index()));
    }
    #endregion

    #region Fields
    private static readonly Lazy<MethodGraph> built = new(BuildFixtureGraph);
    private static readonly Lazy<MechanismGraph> graph = new(() => From(built.Value));
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<MechanismGraph>> without = new(StringComparer.Ordinal);
    private static readonly Lazy<MechanismGraph> withoutDebugFixture = new(BuildReleaseGraph);
    #endregion
}
