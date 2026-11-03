namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// The test-side ordered-subsequence path matcher for <see cref="MechanismGroundTruth"/> (Capslock's waypoint
/// semantics): over a minimal adjacency abstraction — node id → successors — it decides whether some path visits
/// nodes matching each waypoint regex <b>in order, not necessarily consecutively</b>.
/// <para>
/// A breadth-first search over (node, waypoints matched so far) states with a visited set, so it terminates on
/// cycles and self-loops, and a node may be revisited at a later waypoint index. Each waypoint is satisfied by a
/// distinct path position; advancing greedily at the first match is optimal for a fixed path, and every path is
/// explored, so the search is exact. Successors are visited in their given order and starts ordinally, so the
/// witness path is deterministic. A node that appears only as a successor is still a node.
/// </para>
/// </summary>
public static class WaypointMatcher
{
    #region Methods
    /// <summary>
    /// A shortest witness path visiting <paramref name="waypoints"/> in order, or null if none exists.
    /// <paramref name="acceptFinal"/>, when given, must also hold for the node that satisfies the LAST waypoint
    /// (how <see cref="Expectation.Present"/> checks the sink's capability).
    /// </summary>
    public static IReadOnlyList<string>? FindPath(
        IReadOnlyDictionary<string, IReadOnlyList<string>> graph,
        IReadOnlyList<string> waypoints,
        Func<string, bool>? acceptFinal = null)
    {
        if (waypoints.Count == 0)
            throw new ArgumentException("A path needs at least one waypoint.", nameof(waypoints));

        var patterns = waypoints.Select(Compile).ToArray();
        var last = patterns.Length - 1;
        bool Satisfies(string node, int index) =>
            patterns[index].IsMatch(node) && (index != last || acceptFinal is null || acceptFinal(node));

        var parents = new Dictionary<(string Node, int Matched), (string Node, int Matched)?>();
        var queue = new Queue<(string Node, int Matched)>();

        foreach (var start in Nodes(graph).Where(n => Satisfies(n, 0)))
        {
            if (patterns.Length == 1)
                return [start];

            var state = (start, 1);
            if (parents.TryAdd(state, null))
                queue.Enqueue(state);
        }

        while (queue.Count > 0)
        {
            var (node, matched) = queue.Dequeue();
            foreach (var next in Successors(graph, node))
            {
                var advanced = Satisfies(next, matched) ? matched + 1 : matched;
                var state = (next, advanced);
                if (!parents.TryAdd(state, (node, matched)))
                    continue;
                if (advanced == patterns.Length)
                    return Unwind(parents, state);
                queue.Enqueue(state);
            }
        }

        return null;
    }

    /// <summary>
    /// A shortest witness path from any node matching <paramref name="startWaypoint"/> to any node for which
    /// <paramref name="isSink"/> holds (the start itself included), or null if none is reachable.
    /// </summary>
    public static IReadOnlyList<string>? FindPathToSink(
        IReadOnlyDictionary<string, IReadOnlyList<string>> graph,
        string startWaypoint,
        Func<string, bool> isSink)
    {
        var pattern = Compile(startWaypoint);
        var parents = new Dictionary<string, string?>(StringComparer.Ordinal);
        var queue = new Queue<string>();

        foreach (var start in Nodes(graph).Where(n => pattern.IsMatch(n)))
        {
            if (isSink(start))
                return [start];
            if (parents.TryAdd(start, null))
                queue.Enqueue(start);
        }

        while (queue.Count > 0)
        {
            var node = queue.Dequeue();
            foreach (var next in Successors(graph, node))
            {
                if (!parents.TryAdd(next, node))
                    continue;
                if (isSink(next))
                {
                    var path = new List<string>();
                    for (string? at = next; at is not null; at = parents[at])
                        path.Insert(0, at);
                    return path;
                }
                queue.Enqueue(next);
            }
        }

        return null;
    }

    /// <summary>
    /// Applies <paramref name="row"/>'s <see cref="MechanismPath.Expect"/> to <paramref name="graph"/>.
    /// <paramref name="capabilityOf"/> classifies a node id (null = no capability). Never vacuous: an Absent or
    /// KnownGap row whose waypoints match no node at all FAILS, since "no path" between nodes that do not exist
    /// proves nothing.
    /// </summary>
    public static PathVerdict Evaluate(
        MechanismPath row,
        IReadOnlyDictionary<string, IReadOnlyList<string>> graph,
        Func<string, Capability?> capabilityOf)
    {
        var nodes = Nodes(graph).ToArray();
        var unmatched = row.Waypoints.Where(w => !nodes.Any(Compile(w).IsMatch)).ToArray();

        switch (row.Expect)
        {
            case Expectation.Present or Expectation.KnownImprecision:
            {
                var path = FindPath(graph, row.Waypoints, row.Capability is { } wanted ? n => capabilityOf(n) == wanted : null);
                return path is not null
                    ? new(true, $"{row.Id}: path found: {Render(path)}")
                    : new(false, $"{row.Id}: expected a path through [{string.Join(", ", row.Waypoints)}]" +
                                 (row.Capability is { } c ? $" ending at a {c} node" : string.Empty) +
                                 $", found none. Waypoints matching no node: [{string.Join(", ", unmatched)}].");
            }
            case Expectation.KnownGap:
            {
                if (unmatched.Length > 0)
                    return new(false, $"{row.Id}: vacuous KnownGap - waypoints matching no node: [{string.Join(", ", unmatched)}].");
                var path = FindPath(graph, row.Waypoints);
                return path is null
                    ? new(true, $"{row.Id}: gap confirmed - no path through the waypoints.")
                    : new(false, $"{row.Id}: the known gap has CLOSED (path {Render(path)}). Promote the row to Present - a design decision recorded in the spec.");
            }
            case Expectation.Absent:
            {
                if (unmatched.Length > 0)
                    return new(false, $"{row.Id}: vacuous Absent - the start waypoint matches no node.");
                var path = FindPathToSink(graph, row.Waypoints[0],
                    n => capabilityOf(n) is { } found && (row.Capability is null || found == row.Capability));
                return path is null
                    ? new(true, $"{row.Id}: no capability reachable.")
                    : new(false, $"{row.Id}: expected no {(row.Capability?.ToString() ?? "capability")} to be reachable, found {Render(path)} ({capabilityOf(path[^1])}).");
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(row), row.Expect, "Unknown expectation.");
        }
    }

    // Every node: keys and successors alike, ordinally, so start order (and hence the witness) is deterministic.
    private static IEnumerable<string> Nodes(IReadOnlyDictionary<string, IReadOnlyList<string>> graph) =>
        graph.Keys.Concat(graph.Values.SelectMany(s => s)).Distinct(StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);

    private static IReadOnlyList<string> Successors(IReadOnlyDictionary<string, IReadOnlyList<string>> graph, string node) =>
        graph.TryGetValue(node, out var successors) ? successors : [];

    private static IReadOnlyList<string> Unwind(
        Dictionary<(string Node, int Matched), (string Node, int Matched)?> parents, (string Node, int Matched) state)
    {
        var path = new List<string>();
        for ((string Node, int Matched)? at = state; at is { } current; at = parents[current])
            path.Insert(0, current.Node);
        return path;
    }

    private static Regex Compile(string waypoint) =>
        new(waypoint, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static string Render(IEnumerable<string> path) => string.Join(" -> ", path);
    #endregion

    #region Child types
    /// <summary>Whether a row's expectation holds, with a human-readable reason either way.</summary>
    public sealed record PathVerdict(bool Holds, string Detail);
    #endregion
}
