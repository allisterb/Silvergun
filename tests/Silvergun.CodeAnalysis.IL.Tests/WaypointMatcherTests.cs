namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The ordered-subsequence waypoint matcher (<see cref="WaypointMatcher"/>) on hand-built graphs: order,
/// non-consecutive matching, cycles (must terminate), multi-match waypoints, the final-node acceptance used for a
/// Present row's capability, and the Present / Absent / KnownImprecision / KnownGap semantics of
/// <see cref="WaypointMatcher.Evaluate"/>, including its refusal to pass vacuously.
/// </summary>
public sealed class WaypointMatcherTests
{
    [Fact]
    public void FindPath_ConsecutiveWaypoints_ReturnsThePath()
    {
        var graph = Graph(("a", ["b"]), ("b", ["c"]));

        Assert.Equal(["a", "b", "c"], WaypointMatcher.FindPath(graph, [Exact("a"), Exact("b"), Exact("c")]));
    }

    [Fact]
    public void FindPath_NonConsecutiveWaypoints_SkipIntermediateNodes()
    {
        var graph = Graph(("a", ["x"]), ("x", ["y"]), ("y", ["c"]));

        Assert.Equal(["a", "x", "y", "c"], WaypointMatcher.FindPath(graph, [Exact("a"), Exact("c")]));
    }

    [Fact]
    public void FindPath_WaypointsOutOfOrder_FindsNothing()
    {
        var graph = Graph(("a", ["b"]), ("b", ["c"]));

        Assert.Null(WaypointMatcher.FindPath(graph, [Exact("a"), Exact("c"), Exact("b")]));
    }

    [Fact]
    public void FindPath_EdgesAreDirected()
    {
        var graph = Graph(("a", ["b"]));

        Assert.Null(WaypointMatcher.FindPath(graph, [Exact("b"), Exact("a")]));
    }

    [Fact]
    public void FindPath_CycleWithoutTheTarget_TerminatesWithNothing()
    {
        var graph = Graph(("a", ["b"]), ("b", ["c"]), ("c", ["a"]));

        Assert.Null(WaypointMatcher.FindPath(graph, [Exact("a"), Exact("missing")]));
    }

    [Fact]
    public void FindPath_SelfLoop_Terminates()
    {
        var graph = Graph(("a", ["a"]));

        Assert.Null(WaypointMatcher.FindPath(graph, [Exact("a"), Exact("b")]));
    }

    [Fact]
    public void FindPath_CycleWithAnExit_FindsThePathOut()
    {
        var graph = Graph(("a", ["b"]), ("b", ["a", "c"]));

        Assert.Equal(["a", "b", "c"], WaypointMatcher.FindPath(graph, [Exact("a"), Exact("c")]));
    }

    [Fact]
    public void FindPath_NodeRevisitedAtALaterWaypoint_IsAllowed()
    {
        // a -> b -> c -> b -> d: b must be visited, then c, then b AGAIN, then d.
        var graph = Graph(("a", ["b"]), ("b", ["c", "d"]), ("c", ["b"]));

        Assert.Equal(
            ["a", "b", "c", "b", "d"],
            WaypointMatcher.FindPath(graph, [Exact("a"), Exact("b"), Exact("c"), Exact("b"), Exact("d")]));
    }

    [Fact]
    public void FindPath_RepeatedWaypoint_NeedsTwoDistinctPathPositions()
    {
        var single = Graph(("a", ["x1"]));
        var twice = Graph(("a", ["x1"]), ("x1", ["x2"]));

        Assert.Null(WaypointMatcher.FindPath(single, [Exact("a"), "^x", "^x"]));
        Assert.Equal(["a", "x1", "x2"], WaypointMatcher.FindPath(twice, [Exact("a"), "^x", "^x"]));
    }

    [Fact]
    public void FindPath_WaypointMatchingSeveralNodes_UsesWhicheverLeadsOn()
    {
        // ^mid matches mid.1 (dead end) and mid.2 (leads to the sink).
        var graph = Graph(("start", ["mid.1", "mid.2"]), ("mid.2", ["sink"]));

        Assert.Equal(["start", "mid.2", "sink"], WaypointMatcher.FindPath(graph, [Exact("start"), @"^mid\.", Exact("sink")]));
    }

    [Fact]
    public void FindPath_FirstWaypointMatchingSeveralStarts_TriesEachStart()
    {
        var graph = Graph(("s.1", ["dead"]), ("s.2", ["sink"]));

        Assert.Equal(["s.2", "sink"], WaypointMatcher.FindPath(graph, [@"^s\.", Exact("sink")]));
    }

    [Fact]
    public void FindPath_SingleWaypoint_MatchesANodeThatIsOnlyASuccessor()
    {
        var graph = Graph(("a", ["leaf"]));

        Assert.Equal(["leaf"], WaypointMatcher.FindPath(graph, [Exact("leaf")]));
        Assert.Null(WaypointMatcher.FindPath(graph, [Exact("nowhere")]));
    }

    [Fact]
    public void FindPath_AcceptFinal_SkipsALastWaypointMatchThatIsNotAccepted()
    {
        var graph = Graph(("a", ["sink.unclassified", "b"]), ("b", ["sink.classified"]));

        var path = WaypointMatcher.FindPath(graph, [Exact("a"), @"^sink\."], node => node == "sink.classified");

        Assert.Equal(["a", "b", "sink.classified"], path);
    }

    [Fact]
    public void FindPath_AcceptFinal_NoAcceptedFinalNode_FindsNothing()
    {
        var graph = Graph(("a", ["sink"]));

        Assert.Null(WaypointMatcher.FindPath(graph, [Exact("a"), Exact("sink")], _ => false));
    }

    [Fact]
    public void FindPath_IsDeterministic()
    {
        var graph = Graph(("s", ["m2", "m1"]), ("m1", ["t"]), ("m2", ["t"]));

        var first = WaypointMatcher.FindPath(graph, [Exact("s"), Exact("t")]);
        var second = WaypointMatcher.FindPath(graph, [Exact("s"), Exact("t")]);

        // Successors are taken in their given order, so the witness goes through m2.
        Assert.Equal(["s", "m2", "t"], first);
        Assert.Equal(first, second);
    }

    [Fact]
    public void FindPath_NoWaypoints_Throws() =>
        Assert.Throws<ArgumentException>(() => WaypointMatcher.FindPath(Graph(("a", [])), []));

    [Fact]
    public void FindPathToSink_ReachableThroughACycle_ReturnsTheWitness()
    {
        var graph = Graph(("start", ["loop"]), ("loop", ["start", "sink"]));

        Assert.Equal(["start", "loop", "sink"], WaypointMatcher.FindPathToSink(graph, Exact("start"), n => n == "sink"));
    }

    [Fact]
    public void FindPathToSink_Unreachable_TerminatesWithNothing()
    {
        var graph = Graph(("start", ["loop"]), ("loop", ["start"]), ("other", ["sink"]));

        Assert.Null(WaypointMatcher.FindPathToSink(graph, Exact("start"), n => n == "sink"));
    }

    [Fact]
    public void FindPathToSink_StartIsItselfASink_CountsAsReached()
    {
        var graph = Graph(("start", []));

        Assert.Equal(["start"], WaypointMatcher.FindPathToSink(graph, Exact("start"), _ => true));
    }

    [Fact]
    public void Evaluate_Present_HoldsOnlyWhenTheFinalNodeHasTheCapability()
    {
        var graph = Graph(("caller", ["sink"]));
        var row = Row(Expectation.Present, [Exact("caller"), Exact("sink")], Capability.EnvironmentProbe);

        Assert.True(WaypointMatcher.Evaluate(row, graph, n => n == "sink" ? Capability.EnvironmentProbe : null).Holds);
        Assert.False(WaypointMatcher.Evaluate(row, graph, n => n == "sink" ? Capability.FileSystem : null).Holds);
        Assert.False(WaypointMatcher.Evaluate(row, graph, _ => null).Holds);
    }

    [Fact]
    public void Evaluate_PresentWithoutCapability_NeedsOnlyThePath()
    {
        var graph = Graph(("caller", ["extern"]));
        var row = Row(Expectation.Present, [Exact("caller"), Exact("extern")], null);

        Assert.True(WaypointMatcher.Evaluate(row, graph, _ => null).Holds);
        Assert.False(WaypointMatcher.Evaluate(row, Graph(("caller", [])), _ => null).Holds);
    }

    [Fact]
    public void Evaluate_KnownImprecision_IsAssertedAsPresent()
    {
        var graph = Graph(("caller", ["impl"]), ("impl", ["sink"]));
        var row = Row(Expectation.KnownImprecision, [Exact("caller"), Exact("sink")], Capability.FileSystem);

        Assert.True(WaypointMatcher.Evaluate(row, graph, n => n == "sink" ? Capability.FileSystem : null).Holds);
        Assert.False(WaypointMatcher.Evaluate(row, Graph(("caller", []), ("impl", ["sink"])), n => n == "sink" ? Capability.FileSystem : null).Holds);
    }

    [Fact]
    public void Evaluate_KnownGap_HoldsWhileThePathIsMissing_AndFailsWhenItCloses()
    {
        var row = Row(Expectation.KnownGap, [Exact("raiser"), Exact("handler")], Capability.EnvironmentProbe);
        var gap = Graph(("raiser", ["Invoke"]), ("subscriber", ["handler"]));
        var closed = Graph(("raiser", ["handler"]));

        Assert.True(WaypointMatcher.Evaluate(row, gap, _ => null).Holds);

        var verdict = WaypointMatcher.Evaluate(row, closed, _ => null);
        Assert.False(verdict.Holds);
        Assert.Contains("CLOSED", verdict.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Evaluate_KnownGap_WithAWaypointMatchingNoNode_IsVacuousAndFails()
    {
        var row = Row(Expectation.KnownGap, [Exact("raiser"), Exact("renamed-handler")], null);

        var verdict = WaypointMatcher.Evaluate(row, Graph(("raiser", ["handler"])), _ => null);

        Assert.False(verdict.Holds);
        Assert.Contains("vacuous", verdict.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Evaluate_Absent_FailsWhenAnyCapabilityIsReachable()
    {
        var row = Row(Expectation.Absent, [Exact("twin")], null);
        var clean = Graph(("twin", ["safe"]), ("other", ["sink"]));
        var dirty = Graph(("twin", ["safe", "helper"]), ("helper", ["sink"]));
        Capability? Classify(string n) => n == "sink" ? Capability.Network : null;

        Assert.True(WaypointMatcher.Evaluate(row, clean, Classify).Holds);
        Assert.False(WaypointMatcher.Evaluate(row, dirty, Classify).Holds);
    }

    [Fact]
    public void Evaluate_AbsentForOneCapability_IgnoresOtherCapabilities()
    {
        var row = Row(Expectation.Absent, [Exact("twin")], Capability.ProcessExecution);
        var graph = Graph(("twin", ["sink"]));

        Assert.True(WaypointMatcher.Evaluate(row, graph, _ => Capability.EnvironmentProbe).Holds);
        Assert.False(WaypointMatcher.Evaluate(row, graph, n => n == "sink" ? Capability.ProcessExecution : null).Holds);
    }

    [Fact]
    public void Evaluate_Absent_WithAStartMatchingNoNode_IsVacuousAndFails()
    {
        var verdict = WaypointMatcher.Evaluate(Row(Expectation.Absent, [Exact("renamed")], null), Graph(("twin", [])), _ => null);

        Assert.False(verdict.Holds);
        Assert.Contains("vacuous", verdict.Detail, StringComparison.Ordinal);
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> Graph(params (string Node, string[] Successors)[] edges) =>
        edges.ToDictionary(e => e.Node, e => (IReadOnlyList<string>)e.Successors, StringComparer.Ordinal);

    private static string Exact(string node) => "^" + System.Text.RegularExpressions.Regex.Escape(node) + "$";

    private static MechanismPath Row(Expectation expect, string[] waypoints, Capability? capability) =>
        new("Test.Row", "Test", waypoints, capability, expect, Phase.A2, "hand-built");
}
