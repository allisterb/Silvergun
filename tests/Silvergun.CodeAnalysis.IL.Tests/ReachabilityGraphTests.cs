namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Smoke tests of <see cref="Reachability.Analyze"/> on real graphs (reachability R1, S2): the mechanism fixture graph
/// (<see cref="MechanismGraphSource.Graph"/>) and <c>RootFixture</c> (<see cref="RootFixtureModel"/>), both with the
/// built-in map. A case is checked "alone": every other own method's classes are cleared (<see cref="Alone"/>), so the
/// rows are that one root's, while every node, edge, opacity and NativeImport fact stays. This is not the S3 ground
/// truth; it only shows the analysis reads real graphs the way the hand-built tests pin.
/// </summary>
public sealed class ReachabilityGraphTests : IClassFixture<RootFixtureModel>
{
    #region Constructors
    public ReachabilityGraphTests(RootFixtureModel fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Mechanism fixture
    // ---------------------------------------------------------------------------------------------------

    // Direct: a public static method calling Environment.GetEnvironmentVariable is a Bound EnvironmentProbe reach of
    // each of its classes, by that one call, and of nothing else.
    [Fact]
    public void Mechanism_DirectReadsEnv_ReachesEnvironmentProbe_Bound_ByItsCall()
    {
        var graph = MechanismGraphSource.Graph;
        var report = Reachability.Analyze(Alone(graph, DirectReadsEnv));
        var classes = SingleClasses(Facts(graph, DirectReadsEnv).Roots);

        Assert.Contains(RootClass.PublicApi, classes);
        Assert.Equal(classes, report.Reaches.Select(r => r.Class));
        Assert.All(report.Reaches, r => Assert.Equal(Capability.EnvironmentProbe, r.Capability));
        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Instantiated));
        var call = Assert.Single(graph.Edges, e => e.From == DirectReadsEnv && e.To == GetEnv);
        var path = Assert.Single(row.Examples);
        Assert.Equal((DirectReadsEnv, ReachEvidence.Bound, (OpacityKind?)null, 2, false), (path.Root, path.Evidence, path.EndsInOpacity, path.Length, path.Truncated));
        Assert.Equal([new ReachHop(DirectReadsEnv, MechanismFixtureAssemblies.FixtureName, null, 0), new ReachHop(GetEnv, null, call.Kind, call.Offset)], path.Hops);
    }

    // Twin: the same shape calling only safe APIs reaches nothing.
    [Fact]
    public void Mechanism_DirectReadsEnvSafe_ReachesNothing()
    {
        Assert.Empty(Reachability.Analyze(Alone(MechanismGraphSource.Graph, "MechanismFixture.Direct.Probes.ReadsEnvSafe()")).Reaches);
    }

    // P/Invoke: the caller of an own [DllImport] reaches NativeInterop at the extern, Bound.
    [Fact]
    public void Mechanism_CallsNative_ReachesNativeInterop_AtTheOwnPInvoke()
    {
        var graph = MechanismGraphSource.Graph;
        var report = Reachability.Analyze(Alone(graph, CallsNative));

        Assert.True(Facts(graph, GetPid).NativeImport);   // the premise
        Assert.All(report.Reaches, r => Assert.Equal(Capability.NativeInterop, r.Capability));
        var path = Assert.Single(Row(report, RootClass.PublicApi, Capability.NativeInterop).Examples);
        var call = Assert.Single(graph.Edges, e => e.From == CallsNative && e.To == GetPid);
        Assert.Equal((ReachEvidence.Bound, 2, false), (path.Evidence, path.Length, path.Truncated));
        Assert.Equal(
            [new ReachHop(CallsNative, MechanismFixtureAssemblies.FixtureName, null, 0), new ReachHop(GetPid, MechanismFixtureAssemblies.FixtureName, call.Kind, call.Offset)],
            path.Hops);
    }

    // Twin: the managed computation in its place reaches nothing.
    [Fact]
    public void Mechanism_CallsManaged_ReachesNothing()
    {
        Assert.Empty(Reachability.Analyze(Alone(MechanismGraphSource.Graph, "MechanismFixture.Opacity.Native.CallsManaged()")).Reaches);
    }

    // The P/Invoke as a root is itself the sink: a one-hop NativeInterop path in each of its classes.
    [Fact]
    public void Mechanism_ThePInvokeItself_IsAOneHopNativeInteropReach()
    {
        var graph = MechanismGraphSource.Graph;
        var report = Reachability.Analyze(Alone(graph, GetPid));

        Assert.Equal(SingleClasses(Facts(graph, GetPid).Roots), report.Reaches.Select(r => r.Class));
        Assert.All(report.Reaches, r =>
        {
            Assert.Equal(Capability.NativeInterop, r.Capability);
            Assert.Equal([new ReachHop(GetPid, MechanismFixtureAssemblies.FixtureName, null, 0)], Assert.Single(r.Examples).Hops);
        });
    }

    // A [ModuleInitializer] reaching a sink is a LoadTime row; the class stays Unknown, for its module initializer gap.
    [Fact]
    public void Mechanism_TheModuleInitializer_ReachesEnvironmentProbe_AsLoadTime_AndLoadTimeIsUnknown()
    {
        var graph = MechanismGraphSource.Graph;
        var report = Reachability.Analyze(Alone(graph, ModuleInit));

        Assert.True(Facts(graph, ModuleInit).Roots.HasFlag(RootClass.LoadTime));
        var row = Row(report, RootClass.LoadTime, Capability.EnvironmentProbe);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Instantiated));
        Assert.Equal([ModuleInit, GetEnv], Assert.Single(row.Examples).Hops.Select(h => h.NodeId));
        AssertLoadTimeUnknownForItsGaps(graph, report);
    }

    // Twin: the benign module initializer reaches nothing, and LoadTime is still Unknown, never None.
    [Fact]
    public void Mechanism_TheSafeModuleInitializer_ReachesNothing_AndLoadTimeIsStillUnknown()
    {
        var graph = MechanismGraphSource.Graph;
        var report = Reachability.Analyze(Alone(graph, "MechanismFixture.ModuleInit.SafeStartup.InitSafe()"));

        Assert.Empty(report.Reaches);
        AssertLoadTimeUnknownForItsGaps(graph, report);
    }

    // A calli is an IndirectCall opacity at its caller: the caller is an Unseen sink itself (a one-hop path), and the
    // ldftn'd target still carries the EnvironmentProbe reach.
    [Fact]
    public void Mechanism_CallsThroughPointer_ReachesUnseenAtItself_AndEnvironmentProbeThroughTheLdftn()
    {
        var report = Reachability.Analyze(Alone(MechanismGraphSource.Graph, CallsThroughPointer));

        var unseen = Assert.Single(Row(report, RootClass.PublicApi, null).Examples);
        Assert.Equal(OpacityKind.IndirectCall, unseen.EndsInOpacity);
        Assert.Equal([CallsThroughPointer], unseen.Hops.Select(h => h.NodeId));
        var env = Assert.Single(Row(report, RootClass.PublicApi, Capability.EnvironmentProbe).Examples);
        Assert.Equal([CallsThroughPointer, "MechanismFixture.Opacity.Targets.ReadsEnv()", GetEnv], env.Hops.Select(h => h.NodeId));
        Assert.Equal(MethodEdgeKind.Ldftn, env.Hops[1].Via);
        Assert.Equal(RootClassVerdict.Unknown, Status(report, RootClass.PublicApi).Verdict);
    }

    // The same case on a real graph, for the Direct label (amendment a2): the EnvironmentProbe reach runs through the
    // ldftn, so it is not Direct, though Bound; the Unseen reach is the root itself, so it is.
    [Fact]
    public void Mechanism_CallsThroughPointer_TheReachThroughTheLdftn_IsNotDirect_TheUnseenOneIs()
    {
        var report = Reachability.Analyze(Alone(MechanismGraphSource.Graph, CallsThroughPointer));

        var env = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal((1, 1, 0), (env.Roots, env.Bound, env.Direct));
        Assert.Equal((ReachEvidence.Bound, false), (Assert.Single(env.Examples).Evidence, env.Examples[0].Direct));
        var unseen = Row(report, RootClass.PublicApi, null);
        Assert.Equal(1, unseen.Direct);
        Assert.True(Assert.Single(unseen.Examples).Direct);
        var profile = Assert.Single(report.Profiles, p => p.Class == RootClass.PublicApi);
        Assert.Equal([Capability.EnvironmentProbe], profile.Capabilities);
        Assert.Empty(profile.DirectCapabilities);
        Assert.Equal((true, true), (profile.Unseen, profile.DirectUnseen));
    }

    // Twin on a real graph: a direct call to the sink is Direct.
    [Fact]
    public void Mechanism_DirectReadsEnv_IsDirect()
    {
        var report = Reachability.Analyze(Alone(MechanismGraphSource.Graph, DirectReadsEnv));

        var row = Row(report, RootClass.PublicApi, Capability.EnvironmentProbe);
        Assert.Equal(1, row.Direct);
        Assert.True(Assert.Single(row.Examples).Direct);
        Assert.Equal([Capability.EnvironmentProbe], Assert.Single(report.Profiles, p => p.Class == RootClass.PublicApi).DirectCapabilities);
    }

    // Twin: the safe pointer call is still Unseen (the calli), but reaches no capability.
    [Fact]
    public void Mechanism_CallsThroughPointerSafe_ReachesOnlyUnseen()
    {
        var report = Reachability.Analyze(Alone(MechanismGraphSource.Graph, "MechanismFixture.Opacity.Pointers.CallsThroughPointerSafe()"));

        Assert.Equal([(RootClass.PublicApi, (Capability?)null)], report.Reaches.Select(r => (r.Class, r.Capability)));
    }

    // The whole graph: complete, every class present, the known reaches there, and two runs equal.
    [Fact]
    public void Mechanism_TheWholeGraph_IsNotPartial_HasTheKnownReaches_AndIsDeterministic()
    {
        var graph = MechanismGraphSource.Graph;
        var report = Reachability.Analyze(graph);

        Assert.False(report.Partial, report.PartialReason);
        Assert.Equal(allClasses, report.Classes.Select(c => c.Class));
        Assert.Contains(Row(report, RootClass.PublicApi, Capability.EnvironmentProbe).Examples, e => e.Evidence == ReachEvidence.Bound);
        Assert.True(Row(report, RootClass.PublicApi, Capability.NativeInterop).Roots >= 1);
        Assert.True(Row(report, RootClass.LoadTime, Capability.EnvironmentProbe).Roots >= 1);
        Assert.Equal(graph.Facts.Methods.Count(f => f.Roots.HasFlag(RootClass.PublicApi)), Status(report, RootClass.PublicApi).Roots);
        Assert.All(report.Reaches.SelectMany(r => r.Examples), p =>
        {
            Assert.Equal(p.Length > Reachability.MaxPathHops, p.Truncated);
            Assert.Equal(Math.Min(p.Length, Reachability.MaxPathHops), p.Hops.Count);
        });
        Assert.Equal(JsonSerializer.Serialize(report), JsonSerializer.Serialize(Reachability.Analyze(graph)));
    }

    // ---------------------------------------------------------------------------------------------------
    // RootFixture
    // ---------------------------------------------------------------------------------------------------

    // RootFixture's [ModuleInitializer] gap makes LoadTime Unknown, with that gap as a reason, though OnLoad is empty.
    [Fact]
    public void RootFixture_LoadTime_IsUnknown_ForItsModuleInitializerGap()
    {
        var report = Reachability.Analyze(fixture.Graph);

        var gap = Assert.Single(fixture.Graph.Facts.Gaps);
        Assert.Equal(GraphFacts.ModuleInitializerGap, gap.Reason);   // the text ReachabilitySummary's LoadTime note matches by suffix
        var status = Status(report, RootClass.LoadTime);
        Assert.Equal(RootClassVerdict.Unknown, status.Verdict);
        Assert.Contains($"{gap.Assembly}: {gap.Reason}", status.Reasons);
        Assert.Equal(fixture.Graph.Facts.Methods.Count(f => f.Roots.HasFlag(RootClass.LoadTime)), status.Roots);
        Assert.DoesNotContain(report.Reaches, r => r.Class == RootClass.LoadTime);
    }

    // Each of RootFixture's P/Invokes, alone, is a one-hop Bound NativeInterop reach in each of its classes.
    [Theory]
    [InlineData("RootFixture.Native.NativeMethods.GetTickCount()")]
    [InlineData("RootFixture.Flags.Externs.GetTickCount()")]
    public void RootFixture_APInvoke_IsAOneHopNativeInteropReach(string pinvoke)
    {
        var report = Reachability.Analyze(Alone(fixture.Graph, pinvoke));

        Assert.Equal(SingleClasses(Facts(fixture.Graph, pinvoke).Roots), report.Reaches.Select(r => r.Class));
        Assert.All(report.Reaches, r =>
        {
            Assert.Equal((Capability.NativeInterop, 1, 1), (r.Capability, r.Roots, r.Bound));
            var path = Assert.Single(r.Examples);
            Assert.Equal((ReachEvidence.Bound, 1, false), (path.Evidence, path.Length, path.Truncated));
            Assert.Equal([new ReachHop(pinvoke, RootFixtureAssemblies.FixtureName, null, 0)], path.Hops);
        });
    }

    // The internalcall beside it is external but no P/Invoke: native code a Mono or Unity host may bind, which the graph
    // cannot see. So it is an Unseen sink (S3; it read None in S2, a design change recorded in the spec): a one-hop
    // Unseen reach with no opacity kind (there is no opacity record), no capability, and its classes Unknown for it.
    [Fact]
    public void RootFixture_AnInternalCall_ReachesUnseen_AndItsClassesAreUnknown()
    {
        const string internalCall = "RootFixture.Native.NativeMethods.InternalTickCount()";
        var facts = Facts(fixture.Graph, internalCall);
        var report = Reachability.Analyze(Alone(fixture.Graph, internalCall));

        Assert.True(facts.InternalCall && !facts.NativeImport);   // the premise
        Assert.Equal(SingleClasses(facts.Roots), report.Reaches.Select(r => r.Class));
        Assert.All(report.Reaches, r =>
        {
            Assert.Equal(((Capability?)null, 1, 1, 1), (r.Capability, r.Roots, r.Bound, r.Instantiated));
            var path = Assert.Single(r.Examples);
            Assert.Equal((ReachEvidence.Bound, 1, false, (OpacityKind?)null), (path.Evidence, path.Length, path.Truncated, path.EndsInOpacity));
            Assert.Equal([new ReachHop(internalCall, RootFixtureAssemblies.FixtureName, null, 0)], path.Hops);
        });
        Assert.All(SingleClasses(facts.Roots), c =>
        {
            var status = Status(report, c);
            Assert.Equal(RootClassVerdict.Unknown, status.Verdict);
            Assert.Contains("1 root(s) reach code the graph cannot see", status.Reasons);
        });
    }

    // Twin: the managed method of the same shape reaches nothing.
    [Fact]
    public void RootFixture_TheManagedTwinOfTheInternalCall_ReachesNothing()
    {
        Assert.Empty(Reachability.Analyze(Alone(fixture.Graph, "RootFixture.Native.NativeMethods.ManagedTickCount()")).Reaches);
    }

    // S3 review W1: a call to a COM member (newobj of a [ComImport] class, a call through a [ComImport] interface) reaches
    // NativeInterop at that member, Bound, one hop from the caller; never Unseen, so it makes no class Unknown.
    [Theory]
    [InlineData("RootFixture.Com.ComCallers.MakesCoThing()", "RootFixture.Com.CoThing..ctor()", MethodEdgeKind.NewObj)]
    [InlineData("RootFixture.Com.ComCallers.CallsCoThing(RootFixture.Com.ICoThing)", "RootFixture.Com.ICoThing.Run()", MethodEdgeKind.CallVirt)]
    public void RootFixture_ACallToAComMember_ReachesNativeInteropAtIt_AndNotUnseen(string caller, string com, MethodEdgeKind kind)
    {
        var report = Reachability.Analyze(Alone(fixture.Graph, caller));

        Assert.Equal(RootClass.PublicApi, Facts(fixture.Graph, caller).Roots);   // the premise
        var row = Assert.Single(report.Reaches);
        Assert.Equal((RootClass.PublicApi, (Capability?)Capability.NativeInterop, 1, 1, 1), (row.Class, row.Capability, row.Roots, row.Bound, row.Instantiated));
        var call = Assert.Single(fixture.Graph.Edges, e => e.From == caller && e.To == com && e.Kind == kind);
        var path = Assert.Single(row.Examples);
        Assert.Equal((ReachEvidence.Bound, 2, false, (OpacityKind?)null), (path.Evidence, path.Length, path.Truncated, path.EndsInOpacity));
        Assert.Equal(
            [new ReachHop(caller, RootFixtureAssemblies.FixtureName, null, 0), new ReachHop(com, RootFixtureAssemblies.FixtureName, kind, call.Offset)],
            path.Hops);
        var status = Status(report, RootClass.PublicApi);
        Assert.Equal((RootClassVerdict.Reaches, 0), (status.Verdict, status.Reasons.Count));
    }

    // Twin: the same call through an ordinary own interface (bodyless, no implementor) reaches nothing, not even Unseen.
    [Fact]
    public void RootFixture_TheSameCallThroughAnOrdinaryInterface_ReachesNothing()
    {
        const string caller = "RootFixture.Com.ComCallers.CallsPlainThing(RootFixture.Com.IPlainThing)";
        var report = Reachability.Analyze(Alone(fixture.Graph, caller));

        Assert.Contains(fixture.Graph.Edges, e => e.From == caller && e.To == "RootFixture.Com.IPlainThing.Run()");   // the premise
        Assert.Empty(report.Reaches);
        Assert.Equal(RootClassVerdict.None, Status(report, RootClass.PublicApi).Verdict);
    }

    // A delegate's runtime-implemented members are no sinks: as roots they reach nothing.
    [Fact]
    public void RootFixture_ADelegatesMembers_ReachNothing()
    {
        var members = fixture.Graph.Facts.Methods.Where(f => f.DeclaringTypeId == "RootFixture.Native.TickSource").Select(f => f.NodeId).ToArray();

        Assert.Equal(4, members.Length);
        Assert.All(members, m => Assert.Empty(Reachability.Analyze(Alone(fixture.Graph, m)).Reaches));
    }

    // A call through an own interface reaches the abstract slot (bodyless, no internalcall) and, by Dispatch, its
    // benign implementation: nothing, and no Unseen either.
    [Fact]
    public void Mechanism_ACallThroughAnOwnInterfaceToABenignImplementor_ReachesNothing_NotEvenUnseen()
    {
        var graph = MechanismGraphSource.Graph;
        const string caller = "MechanismFixture.Interface.Dispatch.CallsThroughSafeInterface()";

        Assert.Contains(graph.Edges, e => e.From == caller && e.To == "MechanismFixture.Interface.ISafeProbe.Run()");   // the premise
        Assert.Empty(Reachability.Analyze(Alone(graph, caller)).Reaches);
    }

    [Fact]
    public void RootFixture_TheWholeGraph_IsNotPartial_AndIsDeterministic()
    {
        var report = Reachability.Analyze(fixture.Graph);

        Assert.False(report.Partial, report.PartialReason);
        Assert.Equal(allClasses, report.Classes.Select(c => c.Class));
        Assert.Equal(JsonSerializer.Serialize(report), JsonSerializer.Serialize(Reachability.Analyze(fixture.Graph)));
    }

    // ---------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------

    // graph with only root's classes kept: every other own method stays a node with its facts, in no class.
    private static MethodGraph Alone(MethodGraph graph, string root)
    {
        _ = Facts(graph, root);
        return MethodGraph.FromParts(graph.Nodes, graph.Edges, graph.Opacities, graph.Coverage,
            graph.Facts with { Methods = [.. graph.Facts.Methods.Select(f => f.NodeId == root ? f : f with { Roots = RootClass.None })] });
    }

    private static void AssertLoadTimeUnknownForItsGaps(MethodGraph graph, ReachabilityReport report)
    {
        var gaps = graph.Facts.Gaps.Where(g => g.Class.HasFlag(RootClass.LoadTime)).ToArray();
        Assert.Contains(gaps, g => g.Assembly == MechanismFixtureAssemblies.FixtureName);
        var status = Status(report, RootClass.LoadTime);
        Assert.Equal(RootClassVerdict.Unknown, status.Verdict);
        Assert.All(gaps, g => Assert.Contains($"{g.Assembly}: {g.Reason}", status.Reasons));
    }

    private static RootClass[] SingleClasses(RootClass roots) => [.. allClasses.Where(c => roots.HasFlag(c))];

    private static OwnMethodFacts Facts(MethodGraph graph, string nodeId) =>
        graph.Facts.Methods.SingleOrDefault(f => f.NodeId == nodeId) ?? throw new InvalidOperationException($"No facts for '{nodeId}'.");

    private static CapabilityReach Row(ReachabilityReport report, RootClass cls, Capability? capability) =>
        report.Reaches.SingleOrDefault(r => r.Class == cls && r.Capability == capability)
            ?? throw new InvalidOperationException($"No {cls} × {capability?.ToString() ?? "Unseen"} row. Rows: {string.Join("; ", report.Reaches.Select(r => $"{r.Class} × {r.Capability?.ToString() ?? "Unseen"}"))}");

    private static RootClassStatus Status(ReachabilityReport report, RootClass cls) => Assert.Single(report.Classes, c => c.Class == cls);
    #endregion

    #region Fields
    private const string GetEnv = "System.Environment.GetEnvironmentVariable(System.String)";
    private const string DirectReadsEnv = "MechanismFixture.Direct.Probes.ReadsEnv()";
    private const string CallsNative = "MechanismFixture.Opacity.Native.CallsNative()";
    private const string GetPid = "MechanismFixture.Opacity.Native.getpid()";
    private const string ModuleInit = "MechanismFixture.ModuleInit.Startup.Init()";
    private const string CallsThroughPointer = "MechanismFixture.Opacity.Pointers.CallsThroughPointer()";

    private static readonly RootClass[] allClasses =
    [
        RootClass.LoadTime, RootClass.HostContract, RootClass.TypeInitializer, RootClass.Finalizer, RootClass.NativeEntry,
        RootClass.PublicApi, RootClass.PublicContract, RootClass.Hidden,
    ];

    private readonly RootFixtureModel fixture;
    #endregion
}
