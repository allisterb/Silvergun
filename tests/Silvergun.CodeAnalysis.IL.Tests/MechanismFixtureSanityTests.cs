namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Spec §1.5 test 1 — fixture sanity, plus the ground-truth table's own consistency. Catches a fixture that
/// silently tests nothing: a waypoint naming no real node (a typo, or a compiler-generated name that moved), a sink
/// that the built-in <see cref="CapabilityMap"/> does not classify as intended, a twin that is not actually benign,
/// or a fixture built Debug-shaped. Everything here is measured on the BUILT fixture through
/// <see cref="MechanismCallSites"/> (direct call sites only — no graph exists yet).
/// </summary>
public sealed class MechanismFixtureSanityTests : IClassFixture<MechanismFixtureFixture>
{
    public MechanismFixtureSanityTests(MechanismFixtureFixture fixture) => this.fixture = fixture;

    // ---- the table itself ------------------------------------------------------------------------------------

    [Fact]
    public void GroundTruth_RowIdsAreUnique()
    {
        var ids = MechanismGroundTruth.Paths.Select(p => p.Id).Concat(MechanismGroundTruth.Opacities.Select(o => o.Id)).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void GroundTruth_EveryRowHasANoteAndWaypoints_AndEveryWaypointCompiles()
    {
        foreach (var row in MechanismGroundTruth.Paths)
        {
            Assert.False(string.IsNullOrWhiteSpace(row.Note), $"{row.Id}: every row carries a Note (spec §1.4).");
            Assert.NotEmpty(row.Waypoints);
            foreach (var waypoint in row.Waypoints)
                _ = new Regex(waypoint);
        }

        Assert.All(MechanismGroundTruth.Opacities, o => Assert.False(string.IsNullOrWhiteSpace(o.Note), o.Id));
    }

    [Fact]
    public void GroundTruth_NotesFollowTheIdealAndLeverConvention()
    {
        foreach (var row in MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.KnownImprecision))
            Assert.True(row.Note.Contains("ideal: Absent", StringComparison.Ordinal), $"{row.Id}: a KnownImprecision note states the ideal is Absent.");

        foreach (var row in MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.KnownGap))
        {
            Assert.True(row.Note.Contains("ideal: Present", StringComparison.Ordinal), $"{row.Id}: a KnownGap note states the ideal is Present.");
            Assert.True(row.Note.Contains("lever:", StringComparison.Ordinal), $"{row.Id}: a KnownGap note names the design lever.");
        }
    }

    [Fact]
    public void GroundTruth_RowShapesMatchTheirExpectation()
    {
        foreach (var row in MechanismGroundTruth.Paths)
        {
            switch (row.Expect)
            {
                case Expectation.Absent:
                    Assert.True(row.Waypoints.Length == 1, $"{row.Id}: an Absent row names only its start.");
                    break;
                case Expectation.Present or Expectation.KnownImprecision or Expectation.KnownGap:
                    Assert.True(row.Waypoints.Length >= 2, $"{row.Id}: a path row names at least a start and an end.");
                    break;
            }

            // The start is always own code, in the row's own mechanism namespace.
            Assert.StartsWith("^" + Regex.Escape($"{MechanismGroundTruth.RootNamespace}.{row.Mechanism}."), row.Waypoints[0], StringComparison.Ordinal);
        }
    }

    [Fact]
    public void GroundTruth_EveryCatalogueMechanismHasAnInterestingRowAndAnAbsentTwin()
    {
        Assert.Equal(
            MechanismGroundTruth.Mechanisms.OrderBy(m => m, StringComparer.Ordinal),
            MechanismGroundTruth.Paths.Select(p => p.Mechanism).Distinct().OrderBy(m => m, StringComparer.Ordinal));

        foreach (var mechanism in MechanismGroundTruth.Mechanisms)
        {
            var rows = MechanismGroundTruth.Paths.Where(p => p.Mechanism == mechanism).ToArray();
            Assert.Contains(rows, r => r.Expect == Expectation.Absent);
            if (mechanism != "Safe")
                Assert.Contains(rows, r => r.Expect != Expectation.Absent);
        }
    }

    // ---- the table against the built fixture -----------------------------------------------------------------

    [Fact]
    public void EveryWaypoint_MatchesARealNode_OwnOnesADefinitionAndPlatformOnesACallSite()
    {
        var problems = new List<string>();
        var waypoints = MechanismGroundTruth.Paths.SelectMany(p => p.Waypoints.Select(w => (p.Id, Waypoint: w)))
            .Concat(MechanismGroundTruth.Opacities.Select(o => (o.Id, Waypoint: o.Site)));

        foreach (var (id, waypoint) in waypoints)
        {
            var pattern = new Regex(waypoint);
            if (MechanismGroundTruth.IsOwn(waypoint))
            {
                // A definition, so the waypoint names what the graph's nodes will be (ADR-0020 amendment 6) and
                // never a call site's instantiated name. Exactly one: own waypoints are exact node ids.
                var matches = fixture.CallSites.Definitions.Keys.Count(pattern.IsMatch);
                if (matches != 1)
                    problems.Add($"{id}: own waypoint {waypoint} matches {matches} fixture definitions (expected exactly 1).");
            }
            else if (!fixture.CallSites.Targets.Keys.Where(t => !fixture.CallSites.Definitions.ContainsKey(t)).Any(pattern.IsMatch))
            {
                problems.Add($"{id}: platform waypoint {waypoint} matches no platform call-site target.");
            }
        }

        Assert.True(problems.Count == 0,
            string.Join(Environment.NewLine, problems) + Environment.NewLine + "Known node ids:" + Environment.NewLine +
            string.Join(Environment.NewLine, fixture.CallSites.AllNodeIds));
    }

    [Fact]
    public void EveryInterestingSink_ClassifiesToTheIntendedCapability()
    {
        var rows = MechanismGroundTruth.Paths
            .Where(p => p.Expect is Expectation.Present or Expectation.KnownImprecision or Expectation.KnownGap && p.Capability is not null);

        foreach (var row in rows)
        {
            var sink = new Regex(row.Waypoints[^1]);
            if (MechanismGroundTruth.IsOwn(row.Waypoints[^1]))
            {
                // An own sink is a bodyless extern whose capability the map cannot give (Opacity.PInvokeCapability).
                // Prove the fixture still carries it: CapabilityAnalysis's metadata seam reports it on the declaration.
                var own = fixture.CallSites.Definitions.Values.Single(d => sink.IsMatch(d.NodeId));
                Assert.False(own.HasBody, $"{row.Id}: an own sink is expected to be a bodyless extern.");
                Assert.Contains(fixture.Findings, f =>
                    f.Kind == ApiCallKind.NativeImport && f.Capability == row.Capability &&
                    f.CallerType == own.CallerType && f.CallerMethod == own.CallerMethod);
                continue;
            }

            var targets = fixture.CallSites.Targets.Where(t => sink.IsMatch(t.Key)).ToArray();
            Assert.NotEmpty(targets);
            foreach (var (nodeId, key) in targets)
                Assert.True(
                    CapabilityMap.Default.Classify(key) == new CapabilityVerdict(CapabilityClass.Capability, row.Capability),
                    $"{row.Id}: sink {nodeId} (key {key}) classifies as {CapabilityMap.Default.Classify(key)}, expected {row.Capability}.");
        }
    }

    /// <summary>
    /// A twin reaches no capability over direct edges — or, for a row scoped to one capability (spec §1.4: Absent's
    /// <c>Capability</c>, null = any), none of THAT capability.
    /// </summary>
    [Fact]
    public void EveryTwin_DirectlyReachesOnlySafeOrUnclassifiedApis()
    {
        foreach (var row in MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.Absent))
        {
            var start = StartOf(row);
            var classified = Classified(fixture.CallSites.DirectlyReachable(start), row.Capability);
            Assert.True(classified.Length == 0, $"{row.Id}: the twin directly reaches capability sinks: {string.Join(", ", classified)}");
        }
    }

    /// <summary>
    /// Keeps the scoping honest: an Absent row is narrowed to one capability ONLY when its twin really reaches another
    /// one over direct edges (ExpressionTree: <c>Expression`1.Compile</c> is DynamicCodeLoading for both methods), so
    /// that every row that can be an any-capability Absent stays one.
    /// </summary>
    [Fact]
    public void EveryCapabilityScopedTwin_ReallyReachesAnotherCapability()
    {
        var scoped = MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.Absent && p.Capability is not null).ToArray();

        Assert.Equal(["ExpressionTree.CompilesSafeTree"], scoped.Select(r => r.Id));
        foreach (var row in scoped)
            Assert.True(Classified(fixture.CallSites.DirectlyReachable(StartOf(row))).Length > 0,
                $"{row.Id}: the twin reaches no capability at all - make it an any-capability Absent (Capability = null).");
    }

    [Fact]
    public void EveryKnownImprecisionStart_ReachesNoCapabilityOverDirectEdges()
    {
        // The imprecision must come from CHA fan-out alone: over direct edges these starts are as clean as a twin.
        foreach (var row in MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.KnownImprecision))
        {
            var classified = Classified(fixture.CallSites.DirectlyReachable(StartOf(row)));
            Assert.True(classified.Length == 0, $"{row.Id}: reaches {string.Join(", ", classified)} without any dispatch.");
        }
    }

    [Fact]
    public void EveryKnownGap_IsAGapEvenOverDirectEdges()
    {
        foreach (var row in MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.KnownGap))
        {
            Assert.Null(WaypointMatcher.FindPath(fixture.CallSites.Edges, row.Waypoints));
            var target = new Regex(row.Waypoints[1]);
            Assert.DoesNotContain(fixture.CallSites.DirectlyReachable(StartOf(row)), target.IsMatch);
        }
    }

    [Fact]
    public void Fixture_IsReleaseShaped_AsyncStateMachinesAreStructs()
    {
        var stateMachines = new[]
        {
            "MechanismFixture.Async.AsyncProbes.<Probe>d__0",
            "MechanismFixture.Async.AsyncLambdaCase.<>c.<<RunsAsyncLambda>b__0_0>d",
            "MechanismFixture.Async.AsyncLocalCase.<<CallsAsyncLocal>g__Read|0_0>d",
        };
        var types = fixture.Fixture.Module.GetAllTypes()
            .ToDictionary(t => CanonicalName.NodeId(CciNames.Of(t)), t => t, StringComparer.Ordinal);

        foreach (var name in stateMachines)
        {
            Assert.True(types.TryGetValue(name, out var type), $"No type {name} in the fixture.");
            Assert.True(type!.IsValueType, $"{name} is a class: the fixture was built Debug-shaped (Optimize must be true).");
        }
    }

    [Fact]
    public void Fixture_TypeTriggersHaveNoCallSiteToTheInitializer()
    {
        // The StaticInit premise: reading a static field is not a call, so only A2's TypeInitializer edge can link it.
        foreach (var trigger in new[] { "TriggersInit()", "TriggersExplicitInit()", "TriggersSafeInit()" })
            Assert.Empty(fixture.CallSites.Edges[$"MechanismFixture.StaticInit.Triggers.{trigger}"]);
    }

    [Fact]
    public void Fixture_ModuleInitializersAreCalledOnlyFromTheModuleTypeInitializer()
    {
        var callers = fixture.CallSites.Edges
            .Where(e => e.Value.Contains("MechanismFixture.ModuleInit.Startup.Init()", StringComparer.Ordinal))
            .Select(e => e.Key);

        Assert.Equal(["<Module>..cctor()"], callers);
    }

    /// <summary>
    /// The ExpressionTree premise, read from the built IL through raw CCI: the sink appears in
    /// <c>CompilesEnvTree</c> only as an <c>ldtoken</c> operand (turned into a MethodInfo by
    /// <c>MethodBase.GetMethodFromHandle</c> and handed to <c>Expression.Call</c>), never as a call-site target — so the
    /// KnownGap row is about exactly the missing <c>ldtoken</c> edge, and its twin tokens the safe <c>String.Concat</c>.
    /// </summary>
    [Theory]
    [InlineData("MechanismFixture.ExpressionTree.Trees.CompilesEnvTree()", "System.Environment.GetEnvironmentVariable(System.String)")]
    [InlineData("MechanismFixture.ExpressionTree.Trees.CompilesSafeTree()", "System.String.Concat(System.String,System.String)")]
    public void Fixture_ExpressionTreesNameTheirTargetOnlyThroughLdtoken(string method, string tokenTarget)
    {
        var definition = fixture.Fixture.Module.GetAllTypes().SelectMany(t => t.Methods)
            .Single(m => CanonicalName.NodeId(CciNames.Of(m)) == method);
        var operations = AssemblyAnalyzer.TryReadBody(definition).Body!.Operations.ToArray();

        var tokens = operations
            .Where(op => op.OperationCode == Microsoft.Cci.OperationCode.Ldtoken && op.Value is Microsoft.Cci.IMethodReference)
            .Select(op => CanonicalName.NodeId(CciNames.Of((Microsoft.Cci.IMethodReference)op.Value)));

        Assert.Equal([tokenTarget], tokens);
        Assert.DoesNotContain(tokenTarget, fixture.CallSites.Edges[method]);
        Assert.Contains("System.Reflection.MethodBase.GetMethodFromHandle(System.RuntimeMethodHandle)", fixture.CallSites.Edges[method]);
        Assert.Contains(
            "System.Linq.Expressions.Expression.Call(System.Linq.Expressions.Expression,System.Reflection.MethodInfo,System.Linq.Expressions.Expression[])",
            fixture.CallSites.Edges[method]);
    }

    private string StartOf(MechanismPath row) =>
        fixture.CallSites.Definitions.Keys.Single(new Regex(row.Waypoints[0]).IsMatch);

    // Every reachable node the built-in map classifies as a capability (as `only`, when given), rendered for a
    // failure message.
    private string[] Classified(IEnumerable<string> nodes, Capability? only = null) =>
        nodes.Where(n => fixture.CallSites.Targets.TryGetValue(n, out var key) &&
                         CapabilityMap.Default.Classify(key) is { Class: CapabilityClass.Capability } verdict &&
                         (only is null || verdict.Capability == only))
             .Select(n => $"{n} ({CapabilityMap.Default.Classify(fixture.CallSites.Targets[n]).Capability})")
             .ToArray();

    private readonly MechanismFixtureFixture fixture;
}
