namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Spec §1.5 test 4 — the ground-truth path theory, <b>gated</b> on <see cref="MechanismGroundTruth.CurrentPhase"/>:
/// every row with <c>ActiveFrom &lt;= CurrentPhase</c> is evaluated against the real <see cref="MethodGraph"/> (via
/// <see cref="MechanismGraphSource"/>) by <see cref="WaypointMatcher.Evaluate"/>. Rows are tagged with the EARLIEST
/// phase at which they hold, and the ratchet moves in slices: at <see cref="Phase.A1"/> the static-target graph
/// satisfied 65 of the 79 A1-era path rows and the opacity row; A2's first slice (<see cref="Phase.A2Dispatch"/>,
/// CHA fan-out) activated the seven CHA rows and its own fifteen dispatch rows; its second
/// (<see cref="Phase.A2StateMachine"/>, state-machine edges) the four state-machine rows and its own ten AsyncIterator
/// and Debug rows; the whole of A2 (<see cref="Phase.A2"/>, S3: type-initializer and <c>ldtoken</c> edges, module
/// opacity) the two type-initializer rows, S3's <c>newobj</c> pair, the promoted ExpressionTree.CompilesEnvTree and the
/// module-initializer opacity row; and <see cref="Phase.Reachability"/> (reachability R1, S3) the last one, the P/Invoke
/// NativeInterop row. Rows tagged for a later phase are pinned as pending and must still FAIL on today's graph (none
/// are left), so a row that starts passing early is noticed and promoted, and none can disappear silently; the
/// per-phase "does not hold without" theories keep each tag honest now that every row is active.
/// </summary>
public sealed class MechanismGroundTruthTests
{
    /// <summary>
    /// Path rows per <see cref="MechanismPath.ActiveFrom"/>, measured from the table. A row added, removed or
    /// re-phased changes this deliberately — never as a side effect. A1 went 63 -> 65 with A1-S1's two ExpressionTree
    /// rows. A2 S1 re-tagged the seven CHA rows (Interface x2, Virtual, TypeTest, Generics, Iterator x2) from A2 to
    /// A2Dispatch (A2 13 -> 6: the state machine x4 and type initializer x2 rows still pending), and A2Dispatch's 22 =
    /// those 7 + the 12 S1 dispatch rows (ObjectVirtual x3, ExplicitImpl x2, GenericInterface x2, StaticAbstract x2,
    /// OpenHierarchy x3) + S1b's 3 InheritedImpl rows (review C1). A2 S2 re-tagged the four state-machine rows (Async x3,
    /// Iterator.Stub) from A2 to A2StateMachine (A2 6 -> 2: the type initializer x2 rows still pending), and
    /// A2StateMachine's 14 = those 4 + S2's 4 AsyncIterator rows + its 6 Debug rows (spec §8). A2 S3 moved
    /// ExpressionTree.CompilesEnvTree from A1 to A2 with its Expect (spec §5; A1 65 -> 64) and added the StaticInit
    /// newobj pair (§8), and S3 review W3 the value-type pair, so A2's 7 = the type initializer x2 + CompilesEnvTree + the
    /// newobj pair + the value-type pair. Reachability = the bodyless-extern capability row.
    /// </summary>
    private static readonly Dictionary<Phase, int> pathRowsPerPhase = new()
    {
        [Phase.A1] = 64,
        [Phase.A2Dispatch] = 22,
        [Phase.A2StateMachine] = 14,
        [Phase.A2] = 7,
        [Phase.Reachability] = 1,
    };

    /// <summary>
    /// Path rows per expectation, measured from the table. A1-S1 added ExpressionTree.CompilesEnvTree (KnownGap 4 -> 5)
    /// and its twin ExpressionTree.CompilesSafeTree (Absent 35 -> 36). A2-S1 added 5 Present (one per dispatch
    /// mechanism), 5 Absent (ObjectVirtual.DescribesNumber, ExplicitImpl, GenericInterface and StaticAbstract twins,
    /// OpenHierarchy.FlushesJournal) and 2 KnownImprecision (the ObjectVirtual and OpenHierarchy twin drivers). S1b
    /// added InheritedImpl's 2 Present and 1 Absent. S2 added 5 Present (AsyncIterator.Stub and .Consumer, Debug x3),
    /// 4 Absent (AsyncIterator.StubSafe, the Debug twins x3) and 1 KnownImprecision (the AsyncIterator twin driver). S3
    /// moved ExpressionTree.CompilesEnvTree from KnownGap to Present (spec §5, the only Expect change of A2; KnownGap
    /// 5 -> 4) and added StaticInit.CreatesExplicitInit (Present) and its twin StaticInit.CreatesSafeInit (Absent); S3
    /// review W3 added StaticInit.CallsValueMember (Present) and its twin StaticInit.CallsSafeValueMember (Absent).
    /// </summary>
    private static readonly Dictionary<Expectation, int> pathRowsPerExpectation = new()
    {
        [Expectation.Present] = 50,
        [Expectation.Absent] = 48,
        [Expectation.KnownImprecision] = 6,
        [Expectation.KnownGap] = 4,
    };

    /// <summary>The rows CHA fan-out (A2 S1) activated, by id — every one failed on the A1 graph.</summary>
    private static readonly string[] a2DispatchRows =
    [
        // The seven CHA rows pending since A1 (callvirt to own overrides / implementors, including through a
        // platform-declared virtual).
        "Interface.CallsThroughInterface", "Interface.ShouldHaveNoCapability", "Virtual.CallsThroughBase", "TypeTest.CallsMaybeTouch",
        "Generics.ConstrainedCall", "Iterator.Consumer", "Iterator.ConsumerOfSafeSequence",
        // The S1 dispatch mechanisms (cha-a2-dispatch-and-implicit-edges.md §8).
        "ObjectVirtual.DescribesEnv", "ObjectVirtual.DescribesSafe", "ObjectVirtual.DescribesNumber",
        "ExplicitImpl.CallsExplicit", "ExplicitImpl.CallsSafeExplicit",
        "GenericInterface.ComparesThroughInterface", "GenericInterface.ComparesThroughSafeInterface",
        "StaticAbstract.BuildsEnv", "StaticAbstract.BuildsSafe",
        "OpenHierarchy.FlushesEnvStream", "OpenHierarchy.FlushesSafeStream", "OpenHierarchy.FlushesJournal",
        // S1b (review C1): an interface slot filled by an inherited method.
        "InheritedImpl.CallsInherited", "InheritedImpl.CallsPlainInherited", "InheritedImpl.CallsSafeInherited",
    ];

    /// <summary>The rows the state-machine edges (A2 S2) activated, by id.</summary>
    private static readonly string[] a2StateMachineRows =
    [
        // The four state-machine rows pending since A1 (stub -> MoveNext); every one failed on the A2Dispatch graph.
        "Async.Method", "Async.Lambda", "Async.LocalFunction", "Iterator.Stub",
        // The S2 mechanisms (cha-a2-dispatch-and-implicit-edges.md §8).
        "AsyncIterator.Stub", "AsyncIterator.StubSafe", "AsyncIterator.Consumer", "AsyncIterator.ConsumerOfSafeSequence",
        "Debug.AsyncMethod", "Debug.AsyncMethodSafe", "Debug.AsyncLambda", "Debug.AsyncLambdaSafe", "Debug.IteratorStub", "Debug.IteratorStubSafe",
    ];

    /// <summary>The rows A2's last slice (S3) activated, by id.</summary>
    private static readonly string[] a2Rows =
    [
        // The two type-initializer rows pending since A1 (static field access -> .cctor); both failed on the
        // A2StateMachine graph.
        "StaticInit.TriggersInit", "StaticInit.TriggersExplicitInit",
        // S3's newobj pair (§8): a constructor call -> .cctor.
        "StaticInit.CreatesExplicitInit", "StaticInit.CreatesSafeInit",
        // S3 review W3's value-type pair: an instance method of a struct -> its own .cctor (the callee's edge).
        "StaticInit.CallsValueMember", "StaticInit.CallsSafeValueMember",
        // KnownGap until the ldtoken edge, Present since (spec §5).
        "ExpressionTree.CompilesEnvTree",
    ];

    public static TheoryData<string> ActivePathRows() =>
        Ids(MechanismGroundTruth.ActivePaths.Select(p => p.Id));

    public static TheoryData<string> ActiveOpacityRows() =>
        Ids(MechanismGroundTruth.ActiveOpacities.Select(o => o.Id));

    public static TheoryData<string> PendingPathRows() =>
        Ids(MechanismGroundTruth.Paths.Where(p => p.ActiveFrom > MechanismGroundTruth.CurrentPhase).Select(p => p.Id));

    [Theory]
    [MemberData(nameof(ActivePathRows))]
    public void GroundTruthPath_HoldsInTheCallGraph(string id)
    {
        if (id == NoRows)
        {
            Assert.Empty(MechanismGroundTruth.ActivePaths);
            return;
        }

        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.True(verdict.Holds, $"{verdict.Detail} Note: {row.Note}");
    }

    /// <summary>
    /// Every row tagged for a LATER phase genuinely fails on today's graph: the tag is the earliest phase at which the
    /// row holds. If one of these starts passing (an edge landed early, or a waypoint went slack), re-tag it.
    /// </summary>
    [Theory]
    [MemberData(nameof(PendingPathRows))]
    public void PendingPath_DoesNotYetHoldInTheCallGraph(string id)
    {
        if (id == NoRows)
        {
            Assert.DoesNotContain(MechanismGroundTruth.Paths, p => p.ActiveFrom > MechanismGroundTruth.CurrentPhase);
            return;
        }

        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.False(verdict.Holds,
            $"{row.Id} is tagged {row.ActiveFrom} but already holds at {MechanismGroundTruth.CurrentPhase}: {verdict.Detail} " +
            "Re-tag it to the earliest phase at which it holds (never change its Expect).");
    }

    public static TheoryData<string> DispatchDependentPathRows() =>
        Ids(MechanismGroundTruth.Paths
            .Where(p => p.ActiveFrom == Phase.A2Dispatch && p.Expect is Expectation.Present or Expectation.KnownImprecision)
            .Select(p => p.Id));

    /// <summary>
    /// Keeps the A2Dispatch tag honest now that its rows are active: every path row it asserts present FAILS once the
    /// <see cref="MethodEdgeKind.Dispatch"/> edges are taken out of the very same graph — so it holds because of CHA,
    /// and was rightly not an A1 row.
    /// </summary>
    [Theory]
    [MemberData(nameof(DispatchDependentPathRows))]
    public void A2DispatchPath_DoesNotHoldWithoutTheDispatchEdges(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.BuildStatic();

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.False(verdict.Holds, $"{row.Id} holds without any Dispatch edge: {verdict.Detail} It is not about CHA - re-tag it.");
    }

    public static TheoryData<string> StateMachineDependentPathRows() =>
        Ids(MechanismGroundTruth.Paths
            .Where(p => p.ActiveFrom == Phase.A2StateMachine && p.Expect is Expectation.Present or Expectation.KnownImprecision)
            .Select(p => p.Id));

    /// <summary>
    /// Keeps the A2StateMachine tag honest, as <see cref="A2DispatchPath_DoesNotHoldWithoutTheDispatchEdges"/> does for
    /// A2Dispatch: every path row it asserts present FAILS once the <see cref="MethodEdgeKind.StateMachine"/> edges are
    /// taken out of the very same graph (Dispatch edges kept) — so it holds because of the state-machine edges.
    /// </summary>
    [Theory]
    [MemberData(nameof(StateMachineDependentPathRows))]
    public void A2StateMachinePath_DoesNotHoldWithoutTheStateMachineEdges(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.BuildWithoutStateMachines();

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.False(verdict.Holds, $"{row.Id} holds without any StateMachine edge: {verdict.Detail} It is not about state machines - re-tag it.");
    }

    public static TheoryData<string> TypeInitializerOrTokenDependentPathRows() =>
        Ids(MechanismGroundTruth.Paths
            .Where(p => p.ActiveFrom == Phase.A2 && p.Expect is Expectation.Present or Expectation.KnownImprecision)
            .Select(p => p.Id));

    /// <summary>
    /// Keeps the A2 tag honest, as the Dispatch and StateMachine theories do for theirs: every path row tagged A2 and
    /// asserted present (the StaticInit triggers and newobj row, ExpressionTree.CompilesEnvTree) FAILS once the
    /// <see cref="MethodEdgeKind.TypeInitializer"/> and <see cref="MethodEdgeKind.LoadToken"/> edges are taken out of the
    /// very same graph (every other kind kept) — so it holds because of S3's edges.
    /// </summary>
    [Theory]
    [MemberData(nameof(TypeInitializerOrTokenDependentPathRows))]
    public void A2Path_DoesNotHoldWithoutTheTypeInitializerAndLoadTokenEdges(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var graph = MechanismGraphSource.BuildWithout(MethodEdgeKind.TypeInitializer, MethodEdgeKind.LoadToken);

        var verdict = WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf);

        Assert.False(verdict.Holds, $"{row.Id} holds without any TypeInitializer or LoadToken edge: {verdict.Detail} It is not about S3's edges - re-tag it.");
    }

    /// <summary>
    /// Each A2 row needs the ONE S3 kind its note names: the StaticInit rows the TypeInitializer edge (and hold without
    /// LoadToken), CompilesEnvTree the LoadToken edge (and holds without TypeInitializer).
    /// </summary>
    [Theory]
    [InlineData("StaticInit.TriggersInit", MethodEdgeKind.TypeInitializer, MethodEdgeKind.LoadToken)]
    [InlineData("StaticInit.TriggersExplicitInit", MethodEdgeKind.TypeInitializer, MethodEdgeKind.LoadToken)]
    [InlineData("StaticInit.CreatesExplicitInit", MethodEdgeKind.TypeInitializer, MethodEdgeKind.LoadToken)]
    [InlineData("StaticInit.CallsValueMember", MethodEdgeKind.TypeInitializer, MethodEdgeKind.LoadToken)]
    [InlineData("ExpressionTree.CompilesEnvTree", MethodEdgeKind.LoadToken, MethodEdgeKind.TypeInitializer)]
    public void A2Path_NeedsExactlyItsOwnS3EdgeKind(string id, MethodEdgeKind needed, MethodEdgeKind unneeded)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        bool Holds(MechanismGraph graph) => WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf).Holds;

        Assert.False(Holds(MechanismGraphSource.BuildWithout(needed)));
        Assert.True(Holds(MechanismGraphSource.BuildWithout(unneeded)));
    }

    public static TheoryData<string> ReachabilityPathRows() =>
        Ids(MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.Reachability).Select(p => p.Id));

    /// <summary>
    /// Keeps the Reachability tag honest, as the A2 theories do for theirs: every row tagged Reachability FAILS on the
    /// same graph under the A2 classifier (<see cref="MechanismGraphSource.Build"/> at <see cref="Phase.A2"/>, which
    /// never classifies an own node) and holds under today's, so it holds because of the extern sink rule alone.
    /// </summary>
    [Theory]
    [MemberData(nameof(ReachabilityPathRows))]
    public void ReachabilityPath_HoldsOnlyWithTheOwnPInvokeSinkRule(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        bool Holds(MechanismGraph graph) => WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf).Holds;

        Assert.False(Holds(MechanismGraphSource.Build(Phase.A2)), $"{row.Id} holds without the extern sink rule - re-tag it.");
        Assert.True(Holds(MechanismGraphSource.Build(Phase.Reachability)));
    }

    /// <summary>
    /// The <c>await foreach</c> consumer needs BOTH A2 edge kinds, as its note says: the StateMachine edges (into its own
    /// state machine, and from the iterator's <c>MoveNextAsync</c> into <c>MoveNext</c>) and the Dispatch edge (from
    /// <c>IAsyncEnumerator`1.MoveNextAsync</c> to the implementation). Removing either kind breaks the row.
    /// </summary>
    [Fact]
    public void AsyncIteratorConsumer_NeedsBothTheDispatchAndTheStateMachineEdges()
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == "AsyncIterator.Consumer");
        bool Holds(MechanismGraph graph) => WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf).Holds;

        Assert.True(Holds(MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase)));
        Assert.False(Holds(MechanismGraphSource.BuildStatic()));
        Assert.False(Holds(MechanismGraphSource.BuildWithoutStateMachines()));
    }

    /// <summary>
    /// Indexing the Debug-built fixture beside the Release fixture and its Dependency (S2) moves no other row's verdict:
    /// every row outside the Debug mechanism evaluates the same over the three-assembly graph as over the two-assembly
    /// one. (The Release consumers' CHA fan-out does reach the Debug iterators — Iterator.Consumes's
    /// <c>IEnumerator.MoveNext</c> — which is why this is checked rather than assumed.)
    /// </summary>
    [Fact]
    public void AddingTheDebugFixture_MovesNoOtherRowsVerdict()
    {
        var all = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);
        var release = MechanismGraphSource.BuildWithoutDebugFixture();
        bool Holds(MechanismPath row, MechanismGraph graph) => WaypointMatcher.Evaluate(row, graph.Adjacency, graph.CapabilityOf).Holds;

        var rows = MechanismGroundTruth.Paths.Where(p => p.Mechanism != "Debug" && p.ActiveFrom < Phase.Reachability).ToArray();
        var moved = rows.Where(p => Holds(p, all) != Holds(p, release)).Select(p => p.Id).ToArray();

        Assert.True(moved.Length == 0, $"Adding the Debug fixture moved: {string.Join(", ", moved)}");
        Assert.Contains(all.Adjacency["MechanismFixture.Iterator.Consumers.Consumes(System.Collections.Generic.IEnumerable`1<System.String>)"],
            to => to.StartsWith("MechanismFixture.Debug.", StringComparison.Ordinal));
        Assert.DoesNotContain(release.Adjacency.Keys, id => id.StartsWith("MechanismFixture.Debug.", StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(ActiveOpacityRows))]
    public void GroundTruthOpacity_IsRecordedAtItsSite(string id)
    {
        if (id == NoRows)
        {
            Assert.Empty(MechanismGroundTruth.ActiveOpacities);
            return;
        }

        var row = MechanismGroundTruth.Opacities.Single(o => o.Id == id);
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);
        var site = new Regex(row.Site);

        Assert.Contains(graph.Opacities, o => site.IsMatch(o.Site) && o.Kind == row.Kind);
    }

    // Reachability R1, S3 moved the ratchet from A2 to its last phase: the one row pending since A1 (the P/Invoke
    // NativeInterop row) is active now, and so is every other.
    [Fact]
    public void CurrentPhase_IsReachability_AndActivatesEveryRow()
    {
        Assert.Equal(Phase.Reachability, MechanismGroundTruth.CurrentPhase);
        Assert.Equal(Enum.GetValues<Phase>().Max(), MechanismGroundTruth.CurrentPhase);
        Assert.Equal(pathRowsPerPhase.Values.Sum(), MechanismGroundTruth.ActivePaths.Count);
        Assert.Equal(MechanismGroundTruth.Paths.Count, MechanismGroundTruth.ActivePaths.Count);
        Assert.Contains(MechanismGroundTruth.ActivePaths, p => p.Id == "Opacity.PInvokeCapability");
        Assert.Equal(["Opacity.FunctionPointerCalli", "ModuleInit.ModuleInitializerInvisible"], MechanismGroundTruth.ActiveOpacities.Select(o => o.Id));
    }

    /// <summary>The ratchet's order: A2's first and second slices sit strictly between A1 and the whole of A2, in slice order.</summary>
    [Fact]
    public void Phase_A2Slices_AreOrderedBetweenA1AndA2() =>
        Assert.True(Phase.A1 < Phase.A2Dispatch && Phase.A2Dispatch < Phase.A2StateMachine && Phase.A2StateMachine < Phase.A2 && Phase.A2 < Phase.A2Multi);

    [Fact]
    public void PendingPathRows_PerPhase_ArePinned()
    {
        var pending = MechanismGroundTruth.Paths
            .Where(p => p.ActiveFrom > MechanismGroundTruth.CurrentPhase)
            .GroupBy(p => p.ActiveFrom)
            .ToDictionary(g => g.Key, g => g.Count());
        var expected = pathRowsPerPhase
            .Where(e => e.Key > MechanismGroundTruth.CurrentPhase)
            .ToDictionary(e => e.Key, e => e.Value);

        Assert.Equal(expected.OrderBy(e => e.Key), pending.OrderBy(e => e.Key));
    }

    [Fact]
    public void A2SliceRows_AreExactlyTheRowsEachSliceActivated()
    {
        Assert.Equal(
            a2Rows.Order(StringComparer.Ordinal),
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.A2).Select(p => p.Id).Order(StringComparer.Ordinal));
        Assert.Equal(
            a2DispatchRows.Order(StringComparer.Ordinal),
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.A2Dispatch).Select(p => p.Id).Order(StringComparer.Ordinal));
        Assert.Equal(
            a2StateMachineRows.Order(StringComparer.Ordinal),
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.A2StateMachine).Select(p => p.Id).Order(StringComparer.Ordinal));
        Assert.Equal(
            ["Opacity.PInvokeCapability"],
            MechanismGroundTruth.Paths.Where(p => p.ActiveFrom == Phase.Reachability).Select(p => p.Id));
    }

    [Fact]
    public void PathRows_PerPhaseAndPerExpectation_ArePinned()
    {
        Assert.Equal(
            pathRowsPerPhase.OrderBy(e => e.Key),
            MechanismGroundTruth.Paths.GroupBy(p => p.ActiveFrom).ToDictionary(g => g.Key, g => g.Count()).OrderBy(e => e.Key));
        Assert.Equal(
            pathRowsPerExpectation.OrderBy(e => e.Key),
            MechanismGroundTruth.Paths.GroupBy(p => p.Expect).ToDictionary(g => g.Key, g => g.Count()).OrderBy(e => e.Key));
    }

    [Fact]
    public void PendingOpacityRows_AreNone() =>
        Assert.DoesNotContain(MechanismGroundTruth.Opacities, o => o.ActiveFrom > MechanismGroundTruth.CurrentPhase);

    /// <summary>
    /// The seam is the real graph over ALL THREE fixture assemblies — not a stub: the Dependency's method is a node with
    /// its sink as successor, the Debug fixture's stub is a node, and every adjacency key is a node.
    /// </summary>
    [Fact]
    public void GraphSource_IsTheRealGraph_OverAllThreeFixtureAssemblies()
    {
        var graph = MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase);

        Assert.Equal(
            ["System.Environment.GetEnvironmentVariable(System.String)"],
            graph.Adjacency["MechanismFixture.Dependency.EnvReader.Read()"]);
        Assert.Contains("MechanismFixture.CrossAssembly.Callers.UsesDependency()", graph.Adjacency.Keys);
        Assert.Contains("MechanismFixture.Debug.Async.AsyncProbes.<Probe>d__0.MoveNext()", graph.Adjacency["MechanismFixture.Debug.Async.AsyncProbes.Probe()"]);
        Assert.All(graph.Adjacency.Values.SelectMany(s => s), successor => Assert.True(graph.Adjacency.ContainsKey(successor), successor));
        Assert.Same(graph, MechanismGraphSource.Build(MechanismGroundTruth.CurrentPhase));
    }

    /// <summary>
    /// Before <see cref="Phase.Reachability"/> only platform (External) nodes are classified, by the built-in map; an own
    /// node never is, not even the P/Invoke extern. From it, the own P/Invoke is NativeInterop (row
    /// Opacity.PInvokeCapability), and every other own node still is not.
    /// </summary>
    [Theory]
    [InlineData(Phase.A2, "System.Environment.GetEnvironmentVariable(System.String)", Capability.EnvironmentProbe)]
    [InlineData(Phase.A2, "System.Reflection.MethodBase.Invoke(System.Object,System.Object[])", Capability.ReflectionInvocation)]
    [InlineData(Phase.A2, "System.String.Concat(System.String,System.String)", null)]
    [InlineData(Phase.A2, "MechanismFixture.Opacity.Native.getpid()", null)]
    [InlineData(Phase.A2, "MechanismFixture.Direct.Probes.ReadsEnv()", null)]
    [InlineData(Phase.A2, "No.Such.Node()", null)]
    [InlineData(Phase.Reachability, "System.Environment.GetEnvironmentVariable(System.String)", Capability.EnvironmentProbe)]
    [InlineData(Phase.Reachability, "System.Reflection.MethodBase.Invoke(System.Object,System.Object[])", Capability.ReflectionInvocation)]
    [InlineData(Phase.Reachability, "System.String.Concat(System.String,System.String)", null)]
    [InlineData(Phase.Reachability, "MechanismFixture.Opacity.Native.getpid()", Capability.NativeInterop)]
    [InlineData(Phase.Reachability, "MechanismFixture.Opacity.Native.CallsNative()", null)]
    [InlineData(Phase.Reachability, "MechanismFixture.Direct.Probes.ReadsEnv()", null)]
    [InlineData(Phase.Reachability, "No.Such.Node()", null)]
    public void GraphSource_ClassifiesPlatformNodes_AndFromReachabilityOwnPInvokes(Phase phase, string nodeId, Capability? expected) =>
        Assert.Equal(expected, MechanismGraphSource.Build(phase).CapabilityOf(nodeId));

    /// <summary>
    /// At <see cref="Phase.Reachability"/> the own nodes classified are exactly the facts' NativeImport nodes (the
    /// fixture's one P/Invoke), each NativeInterop; at A2 none is.
    /// </summary>
    [Fact]
    public void GraphSource_AtReachability_ClassifiesExactlyTheOwnNativeImports()
    {
        var own = MechanismGraphSource.Graph.Nodes.Where(n => n.Kind != MethodNodeKind.External).Select(n => n.NodeId).ToArray();
        var reachability = MechanismGraphSource.Build(Phase.Reachability);

        Assert.Equal(["MechanismFixture.Opacity.Native.getpid()"], MechanismGraphSource.Graph.Facts.Methods.Where(f => f.NativeImport).Select(f => f.NodeId));
        Assert.Equal(["MechanismFixture.Opacity.Native.getpid()"], own.Where(id => reachability.CapabilityOf(id) is not null));
        Assert.Equal(Capability.NativeInterop, reachability.CapabilityOf("MechanismFixture.Opacity.Native.getpid()"));
        Assert.DoesNotContain(own, id => MechanismGraphSource.Build(Phase.A2).CapabilityOf(id) is not null);
    }

    // xUnit 2 fails a theory whose data source is empty ("No data found"), so an empty set is represented by one
    // sentinel case that asserts the emptiness itself - never by a silently passing row.
    private static TheoryData<string> Ids(IEnumerable<string> ids)
    {
        var data = new TheoryData<string>();
        foreach (var id in ids)
            data.Add(id);
        if (data.Count == 0)
            data.Add(NoRows);
        return data;
    }

    private const string NoRows = "(no rows in this set at the current phase)";
}
