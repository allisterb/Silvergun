namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="MemberIndex.StateMachineTargets"/> and the graph's <see cref="MethodEdgeKind.StateMachine"/> edges (A2 S2,
/// docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md §3 and "S2 outcome") over an EMITTED assembly
/// (<see cref="StateMachineShapesFixture"/>) whose every type and call site is written by hand, so each shape is exactly
/// the one named: which types are state machines (by the subtype map, never by name), which of their methods is the
/// target, which instructions trigger, the self-edge rule, the edge budget and call-site accounting, determinism.
/// The compiler-generated shapes (Release and Debug async methods, iterators, async iterators) are the mechanism
/// fixtures' (<see cref="MechanismGroundTruth"/>). Two shapes that would perturb every other case live in a second
/// emitted assembly (<see cref="StateMachineEdgeCasesFixture"/>): a shadowed state-machine root, and one generic
/// argument list naming one state machine many times (S2 review 1, W2 and W1).
/// </summary>
public sealed class StateMachineTargetsTests : IClassFixture<StateMachineShapesFixture>, IClassFixture<StateMachineEdgeCasesFixture>
{
    #region Constructors
    public StateMachineTargetsTests(StateMachineShapesFixture shapes, StateMachineEdgeCasesFixture edgeCases)
    {
        this.shapes = shapes;
        this.edgeCases = edgeCases;
    }
    #endregion

    #region Methods
    // ---- a shadowed root (S2 review 1, W2) ---------------------------------------------------------------------------

    /// <summary>
    /// An own type named <c>System.Collections.IEnumerator</c> shadows the platform interface, so a type implementing
    /// the PLATFORM one is linked under the <see cref="MemberIndex.Qualified"/> key (<c>[corelib]System.Collections.IEnumerator</c>)
    /// and one implementing the OWN shadow under the bare key. Both roots are walked (S2 outcome, "Root keys"), so both
    /// <c>newobj</c>s get their StateMachine edge. The precondition makes the Qualified path non-vacuous: the platform
    /// implementor has NO bare-key link, so without the Qualified clause of <c>StateMachines</c> it would get no edge.
    /// </summary>
    [Theory]
    [InlineData("CreatesPlatformMachine", "PlatformMachine", true)]
    [InlineData("CreatesOwnMachine", "OwnMachine", false)]
    public void StateMachineTargets_UnderAShadowedRoot_FindsTheImplementorsOfBothThePlatformAndTheOwnInterface(string caller, string type, bool qualified)
    {
        const string root = "System.Collections.IEnumerator";
        Assert.True(edgeCases.Index.IsOwnMethod($"{root}.MoveNext()"));
        var supertypes = Assert.Single(edgeCases.Index.Types(Shadow(type))).Supertypes;
        if (qualified)
        {
            var key = Assert.Single(supertypes, s => s.EndsWith($"]{root}", StringComparison.Ordinal));
            Assert.StartsWith("[", key, StringComparison.Ordinal);
            Assert.DoesNotContain(root, supertypes);
            Assert.Contains(Shadow(type), edgeCases.Index.DirectSubtypes(key));
        }
        else
        {
            Assert.Contains(root, supertypes);
            Assert.DoesNotContain(supertypes, s => s.StartsWith("[", StringComparison.Ordinal));
        }
        var site = edgeCases.Site(caller);

        Assert.Equal([Shadow($"{type}.MoveNext()")], edgeCases.Index.StateMachineTargets(site.Target, construction: true));
        Assert.Equal(
            [new MethodEdge(site.Caller.NodeId, Shadow($"{type}.MoveNext()"), MethodEdgeKind.StateMachine, site.Offset)],
            edgeCases.Graph.Successors(site.Caller.NodeId).Where(e => e.Kind == MethodEdgeKind.StateMachine));
    }

    // ---- one argument list naming a state machine many times (S2 review 1, W1) -------------------------------------

    /// <summary>
    /// A generic method instance whose 64 arguments all name the same state machine (<c>Many&lt;S, S, …, S&gt;</c>, a flat
    /// list) gets that state machine's <c>MoveNext</c> exactly once: the same answer as <c>Start&lt;S&gt;</c>, and one
    /// StateMachine edge in the graph. Interleaving two state machines 32 times each gives each <c>MoveNext</c> once,
    /// ordinal-sorted. (Correctness only: the review's G×K cost is not pinned by wall clock.)
    /// </summary>
    [Fact]
    public void StateMachineTargets_AnArgumentListNamingOneStateMachineManyTimes_NamesEachMoveNextOnce()
    {
        var single = edgeCases.Site("StartsPlatformMachine");
        var repeated = edgeCases.Site("StartsRepeated");
        var interleaved = edgeCases.Site("StartsInterleaved");
        Assert.Equal(StateMachineEdgeCasesFixture.Copies, repeated.Target.GenericArguments.Count);
        Assert.Equal(StateMachineEdgeCasesFixture.Copies, interleaved.Target.GenericArguments.Count);
        var once = edgeCases.Index.StateMachineTargets(single.Target, construction: false);
        Assert.Equal([Shadow("PlatformMachine.MoveNext()")], once);

        Assert.Equal(once, edgeCases.Index.StateMachineTargets(repeated.Target, construction: false));
        Assert.Equal([Shadow("OwnMachine.MoveNext()"), Shadow("PlatformMachine.MoveNext()")],
            edgeCases.Index.StateMachineTargets(interleaved.Target, construction: false));
        Assert.Equal([new MethodEdge(repeated.Caller.NodeId, Shadow("PlatformMachine.MoveNext()"), MethodEdgeKind.StateMachine, repeated.Offset)],
            edgeCases.Graph.Successors(repeated.Caller.NodeId).Where(e => e.Kind == MethodEdgeKind.StateMachine));
        Assert.Equal(2, edgeCases.Graph.Successors(interleaved.Caller.NodeId).Count(e => e.Kind == MethodEdgeKind.StateMachine));
    }

    // ---- which types are state machines -----------------------------------------------------------------------------

    /// <summary>
    /// A hand-written class implementing <c>System.Collections.IEnumerator</c> — a name no compiler would give — is a
    /// state machine: its <c>newobj</c> gets a StateMachine edge to its <c>MoveNext</c>, at the instruction's offset.
    /// And the converse: a type NAMED like an iterator closure (<c>&lt;Fake&gt;d__0</c>) with a <c>MoveNext</c> but no
    /// state-machine interface is not one. No name heuristic either way.
    /// </summary>
    [Fact]
    public void StateMachineTargets_NewobjOfAHandWrittenIEnumerator_IsAStateMachine_WithoutAnyNameHeuristic()
    {
        var hand = shapes.Site("CreatesHand");
        var fake = shapes.Site("CreatesFake");
        Assert.Equal(MethodEdgeKind.NewObj, hand.Kind);
        Assert.True(shapes.Index.IsOwnMethod(Machines("<Fake>d__0.MoveNext()")));

        Assert.Equal([Machines("HandEnumerator.MoveNext()")], shapes.Index.StateMachineTargets(hand.Target, construction: true));
        Assert.Contains(new MethodEdge(hand.Caller.NodeId, Machines("HandEnumerator.MoveNext()"), MethodEdgeKind.StateMachine, hand.Offset), shapes.Graph.Edges);
        Assert.Empty(shapes.Index.StateMachineTargets(fake.Target, construction: true));
        Assert.Empty(shapes.StateMachineEdges("CreatesFake"));
    }

    /// <summary>
    /// A class whose <c>InterfaceImpl</c> names <c>IEnumerator&lt;string&gt;</c> ALONE (not the non-generic
    /// <c>IEnumerator</c> it extends, which C# would also list) is still found: <c>IEnumerator`1</c> is a root of its own,
    /// because the subtype map holds only the links own types declare.
    /// </summary>
    [Fact]
    public void StateMachineTargets_AnEnumeratorListingOnlyIEnumeratorOfT_IsStillFound()
    {
        Assert.Equal(["System.Collections.Generic.IEnumerator`1", "System.Object"], Assert.Single(shapes.Index.Types(Machines("GenericOnly"))).Supertypes);
        Assert.DoesNotContain(Machines("GenericOnly"), shapes.Index.DirectSubtypes("System.Collections.IEnumerator"));

        Assert.Equal([Machines("GenericOnly.MoveNext()")], shapes.Index.StateMachineTargets(shapes.Site("CreatesGenericOnly").Target, construction: true));
        Assert.Equal([Machines("GenericOnly.MoveNext()")], shapes.StateMachineEdges("CreatesGenericOnly").Select(e => e.To));
    }

    /// <summary>
    /// A type below an OWN interface that extends <c>IEnumerator</c>, listing only that interface, is found: the walk
    /// down the subtype map is transitive. The interface itself declares no <c>MoveNext</c>, so it adds no target.
    /// </summary>
    [Fact]
    public void StateMachineTargets_BelowAnOwnInterfaceThatExtendsIEnumerator_IsFound()
    {
        Assert.Equal([Machines("IMyEnumerator"), "System.Object"], Assert.Single(shapes.Index.Types(Machines("Deep"))).Supertypes);
        Assert.Equal([Machines("IMyEnumerator")], shapes.Index.DirectSubtypes("System.Collections.IEnumerator").Where(t => t.Contains("MyEnumerator", StringComparison.Ordinal)));

        Assert.Equal([Machines("Deep.MoveNext()")], shapes.Index.StateMachineTargets(shapes.Site("CreatesDeep").Target, construction: true));
    }

    // ---- which methods are the target ------------------------------------------------------------------------------

    /// <summary>An explicit implementation, named <c>System.Collections.IEnumerator.MoveNext</c>, is the target.</summary>
    [Fact]
    public void StateMachineTargets_AnExplicitMoveNext_IsTheTarget() =>
        Assert.Equal([Machines("ExplicitEnumerator.System.Collections.IEnumerator.MoveNext()")],
            shapes.Index.StateMachineTargets(shapes.Site("CreatesExplicit").Target, construction: true));

    /// <summary>
    /// The accepted boundary (S2 outcome): a subclass that declares no <c>MoveNext</c> of its own is not given its
    /// base's — no StateMachine edge at all from its <c>newobj</c>. The inherited <c>MoveNext</c> is still reached by
    /// <see cref="MethodEdgeKind.Dispatch"/> from the code that runs the enumerator (<c>callvirt IEnumerator::MoveNext</c>).
    /// </summary>
    [Fact]
    public void StateMachineTargets_AnInheritedMoveNext_IsNotATarget()
    {
        Assert.Equal([Machines("HandEnumerator")], Assert.Single(shapes.Index.Types(Machines("InheritingEnumerator"))).Supertypes);
        Assert.DoesNotContain(shapes.Index.Methods, m => m.DeclaringTypeId == Machines("InheritingEnumerator") && m.Definition.Name == "MoveNext");

        Assert.Empty(shapes.Index.StateMachineTargets(shapes.Site("CreatesInheriting").Target, construction: true));
        Assert.Empty(shapes.StateMachineEdges("CreatesInheriting"));
        Assert.Contains(Machines("HandEnumerator.MoveNext()"), shapes.Site("MovesNext").DispatchTargets(shapes.Index)!);
    }

    /// <summary>
    /// A static <c>MoveNext()</c> is never a target: of a state machine declaring both a static <c>MoveNext()</c> and an
    /// explicit instance implementation, only the explicit one is.
    /// </summary>
    [Fact]
    public void StateMachineTargets_AStaticMoveNext_IsNotATarget()
    {
        Assert.True(shapes.Index.IsOwnMethod(Machines("StaticMover.MoveNext()")));

        Assert.Equal([Machines("StaticMover.System.Collections.IEnumerator.MoveNext()")],
            shapes.Index.StateMachineTargets(shapes.Site("CreatesStaticMover").Target, construction: true));
    }

    // ---- which instructions trigger ---------------------------------------------------------------------------------

    /// <summary>
    /// Only the generic arguments of a generic METHOD instance name a state machine (<c>Start&lt;HandEnumerator&gt;()</c>);
    /// a generic TYPE's arguments never do, whether the site is its constructor (<c>new List&lt;HandEnumerator&gt;()</c>)
    /// or a non-generic method on it (<c>Holder&lt;HandEnumerator&gt;.Touch()</c>). Every one of these sites does carry
    /// <c>HandEnumerator</c> as a generic argument somewhere.
    /// </summary>
    [Theory]
    [InlineData("StartsHand", false, true)]
    [InlineData("CreatesListOfHand", true, false)]
    [InlineData("TouchesHolderOfHand", false, false)]
    public void StateMachineTargets_OnlyAGenericMethodInstancesArgumentsTrigger(string caller, bool construction, bool triggers)
    {
        var site = shapes.Site(caller);
        var arguments = site.Target.GenericArguments.Concat(site.Target.ContainingType.GenericArguments).OfType<Model.Types.IBasicType>();
        Assert.Contains(arguments, a => ModelNames.TypeName(a) == Machines("HandEnumerator"));

        IReadOnlyList<string> expected = triggers ? [Machines("HandEnumerator.MoveNext()")] : [];
        Assert.Equal(expected, shapes.Index.StateMachineTargets(site.Target, construction));
        Assert.Equal(expected, shapes.StateMachineEdges(caller).Select(e => e.To));
    }

    /// <summary>
    /// <c>ldftn Start&lt;HandEnumerator&gt;</c> is not a trigger (§3 names <c>newobj</c> and calls only): the graph adds
    /// no StateMachine edge there, although the same reference handed to <see cref="MemberIndex.StateMachineTargets"/>
    /// as a call would name the state machine.
    /// </summary>
    [Fact]
    public void Graph_LdftnOfAGenericMethodInstance_IsNotATrigger()
    {
        var site = shapes.Site("LoadsStart");
        Assert.Equal(MethodEdgeKind.Ldftn, site.Kind);
        Assert.NotEmpty(shapes.Index.StateMachineTargets(site.Target, construction: false));

        Assert.Empty(shapes.StateMachineEdges("LoadsStart"));
    }

    /// <summary>
    /// A state machine in a generic type is keyed by its DEFINITION: <c>new GenEnum&lt;int&gt;()</c> and
    /// <c>Start&lt;GenEnum&lt;int&gt;&gt;()</c> both reach <c>GenEnum`1.MoveNext()</c>.
    /// </summary>
    [Theory]
    [InlineData("CreatesGeneric", true)]
    [InlineData("StartsGeneric", false)]
    public void StateMachineTargets_AStateMachineInAGenericType_IsKeyedByItsDefinition(string caller, bool construction)
    {
        Assert.Equal([Machines("GenEnum`1.MoveNext()")], shapes.Index.StateMachineTargets(shapes.Site(caller).Target, construction));
        Assert.Equal([Machines("GenEnum`1.MoveNext()")], shapes.StateMachineEdges(caller).Select(e => e.To));
    }

    // ---- the graph ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// A <c>MoveNext</c> that names its own state machine (as an async <c>MoveNext</c>'s
    /// <c>AwaitUnsafeOnCompleted&lt;TAwaiter, S&gt;</c> does) gets no self-edge, although
    /// <see cref="MemberIndex.StateMachineTargets"/> names it; another method naming the same state machine does get its edge.
    /// </summary>
    [Fact]
    public void Graph_AMoveNextNamingItsOwnStateMachine_HasNoSelfEdge()
    {
        var self = Machines("SelfNaming.MoveNext()");
        var site = Assert.Single(shapes.Sites, s => s.Caller.NodeId == self);

        Assert.Equal([self], shapes.Index.StateMachineTargets(site.Target, construction: false));
        Assert.DoesNotContain(shapes.Graph.Edges, e => e.Kind == MethodEdgeKind.StateMachine && e.From == self);
        Assert.Contains(new MethodEdge(site.Caller.NodeId, Machines("Starter.Start`1()"), MethodEdgeKind.Call, site.Offset), shapes.Graph.Edges);
        Assert.Equal([self], shapes.StateMachineEdges("CreatesSelfNaming").Select(e => e.To));
    }

    /// <summary>
    /// StateMachine edges are not call sites (A2 spec acceptance 3): <see cref="GraphCoverage.CallSites"/> and
    /// <see cref="GraphCoverage.Resolutions"/> count exactly the call-site instructions, while the graph's edges are
    /// exactly those of the call sites, the Dispatch fan-out and the StateMachine edges. There are ten of those, one
    /// per triggering site: the newobj of HandEnumerator, GenericOnly, ExplicitEnumerator, StaticMover, Deep,
    /// GenEnum&lt;int&gt; and SelfNaming, and the three Start&lt;S&gt; calls (StartsHand, StartsGeneric, Zz.Last.Starts) —
    /// SelfNaming's own MoveNext, the ldftn, the inheriting, fake, List and Holder sites and the constructors add none.
    /// </summary>
    [Fact]
    public void Graph_StateMachineEdges_AreNotCountedAsCallSites()
    {
        var coverage = shapes.Graph.Coverage;
        var counts = coverage.Resolutions;
        var stateMachines = shapes.Graph.Edges.Count(e => e.Kind == MethodEdgeKind.StateMachine);
        Assert.Equal(10, stateMachines);

        Assert.Equal(shapes.Sites.Count, coverage.CallSites);
        Assert.Equal(shapes.Sites.Count, counts.Exact + counts.Substituted + counts.External + counts.Ambiguous + counts.Unresolved);
        Assert.Equal(0, counts.Ambiguous);
        Assert.Equal(shapes.Sites.Count + coverage.DispatchEdges + stateMachines, shapes.Graph.Edges.Count);
    }

    /// <summary>
    /// StateMachine edges count against <see cref="GraphBudget.MaxEdges"/>, and reaching the budget on one marks the
    /// graph truncated by "edges". The last method walked (<c>Zz.Last.Starts()</c>, last by node id) has one site, whose
    /// Call edge is added before its StateMachine edge — the build's very last edge. With one edge fewer than the
    /// unbounded build, exactly that StateMachine edge is refused; with the full count, nothing is.
    /// </summary>
    [Fact]
    public void Graph_StateMachineEdges_CountAgainstMaxEdges_AndTruncateTheGraphByEdges()
    {
        const string last = "Zz.Last.Starts()";
        Assert.Equal(last, shapes.Index.Methods.Last(m => m.Definition.HasBody).NodeId);
        var lastEdge = new MethodEdge(last, Machines("HandEnumerator.MoveNext()"), MethodEdgeKind.StateMachine, Assert.Single(shapes.Sites, s => s.Caller.NodeId == last).Offset);
        Assert.Contains(lastEdge, shapes.Graph.Edges);
        var all = shapes.Graph.Edges.Count;

        var truncated = MethodGraph.Build(shapes.Index, new GraphBudget(int.MaxValue, all - 1));
        var exact = MethodGraph.Build(shapes.Index, new GraphBudget(int.MaxValue, all));

        Assert.True(truncated.Coverage.Truncated);
        Assert.Equal($"edges budget of {all - 1} reached", truncated.Coverage.TruncatedBy);
        Assert.Equal(shapes.Graph.Edges.Where(e => e != lastEdge), truncated.Edges);
        Assert.False(exact.Coverage.Truncated);
        Assert.Equal(shapes.Graph.Edges, exact.Edges);
    }

    /// <summary>
    /// Two builds give identical StateMachine edges: over fresh loads of the emitted shapes, and over the three mechanism
    /// fixtures loaded in two different orders (where they are not empty either).
    /// </summary>
    [Fact]
    public void Build_TwiceOverFreshLoads_GivesIdenticalStateMachineEdges()
    {
        using var again = ModelAssemblies.Load(shapes.Path);
        Assert.Equal(StateMachineEdges(shapes.Graph), StateMachineEdges(MethodGraph.Build(again.Index())));

        using var forward = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.DebugFixture);
        using var reversed = ModelAssemblies.Load(MechanismFixtureAssemblies.DebugFixture, MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.Fixture);
        var first = MethodGraph.Build(forward.Index());
        var second = MethodGraph.Build(reversed.Index());

        Assert.NotEmpty(StateMachineEdges(first));
        Assert.Equal(StateMachineEdges(first), StateMachineEdges(second));
        Assert.Equal(first.Edges, second.Edges);
        Assert.Equal(first.Coverage, second.Coverage);
    }

    // ---- degenerate input -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void StateMachineTargets_ANullReference_IsEmpty(bool construction) =>
        Assert.Empty(shapes.Index.StateMachineTargets(null, construction));

    /// <summary>
    /// An index with no state machines answers empty, even for a reference that names one in another index (where the
    /// same reference is answered).
    /// </summary>
    [Fact]
    public void StateMachineTargets_AnIndexWithNoStateMachines_IsEmpty()
    {
        var site = shapes.Site("CreatesHand");
        var target = SyntheticModel.Method(SyntheticModel.TypeRef("System", "Object"), "GetHashCode");
        var none = MemberIndex.Build([(SyntheticModel.CallerAssembly("NoMachines", ("Calls", target)), TypeForwarders.None)]);
        Assert.NotEmpty(shapes.Index.StateMachineTargets(site.Target, construction: true));

        Assert.Empty(none.StateMachineTargets(site.Target, construction: true));
        Assert.Empty(none.StateMachineTargets(site.Target, construction: false));
        Assert.DoesNotContain(MethodGraph.Build(none).Edges, e => e.Kind == MethodEdgeKind.StateMachine);
    }

    private static MethodEdge[] StateMachineEdges(MethodGraph graph) => graph.Edges.Where(e => e.Kind == MethodEdgeKind.StateMachine).ToArray();

    private static string Machines(string nodeIdWithoutNamespace) => $"Machines.{nodeIdWithoutNamespace}";

    private static string Shadow(string nodeIdWithoutNamespace) => $"Shadow.{nodeIdWithoutNamespace}";
    #endregion

    #region Fields
    private readonly StateMachineShapesFixture shapes;
    private readonly StateMachineEdgeCasesFixture edgeCases;
    #endregion
}

/// <summary>
/// A second emitted assembly, <c>MachineEdgeCases</c> (<see cref="EmittedAssembly"/>; never loaded or run), kept apart
/// from <see cref="StateMachineShapesFixture"/> because its own <c>System.Collections.IEnumerator</c> re-keys every
/// platform <c>IEnumerator</c> link in its index as <see cref="MemberIndex.Qualified"/>:
/// <list type="bullet">
/// <item><description>an own interface <c>System.Collections.IEnumerator</c> (with <c>MoveNext()</c>) shadowing the platform one;</description></item>
/// <item><description><c>Shadow.PlatformMachine</c> implementing the PLATFORM <c>IEnumerator</c>, and
/// <c>Shadow.OwnMachine</c> implementing the own shadow;</description></item>
/// <item><description><c>Shadow.Starter.Start&lt;S&gt;()</c> and <c>Shadow.Starter.Many&lt;T0, …, T63&gt;()</c>;</description></item>
/// <item><description><c>Shadow.Callers</c>: one static method per site, each with exactly one call-site instruction.</description></item>
/// </list>
/// </summary>
public sealed class StateMachineEdgeCasesFixture : IDisposable
{
    #region Constructors
    public StateMachineEdgeCasesFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Path = emitted.Save(Name, Define);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            Sites = ModelCallSite.All(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>The single call site of <c>Shadow.Callers.{caller}(…)</c>.</summary>
    public ModelCallSite Site(string caller) =>
        Assert.Single(Sites, s => s.Caller.NodeId.StartsWith($"Shadow.Callers.{caller}(", StringComparison.Ordinal));

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        var objectCtor = typeof(object).GetConstructor(Type.EmptyTypes)!;

        // The own shadow of the platform interface.
        var shadow = module.DefineType("System.Collections.IEnumerator", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
        shadow.DefineMethod("MoveNext", InterfaceMember, typeof(bool), Type.EmptyTypes);

        // One implementor of each.
        var platformMachine = module.DefineType("Shadow.PlatformMachine", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator)]);
        var platformCtor = Constructor(platformMachine, objectCtor);
        Body(platformMachine.DefineMethod("MoveNext", Implementation, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0);
        Body(platformMachine.DefineMethod("get_Current", Implementation, typeof(object), Type.EmptyTypes), OpCodes.Ldnull);
        Body(platformMachine.DefineMethod("Reset", Implementation, typeof(void), Type.EmptyTypes), null);
        var ownMachine = module.DefineType("Shadow.OwnMachine", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [shadow]);
        var ownCtor = Constructor(ownMachine, objectCtor);
        Body(ownMachine.DefineMethod("MoveNext", Implementation, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0);

        // Start<S>() and Many<T0, ..., T63>(): one generic argument, and a flat list of Copies.
        var starter = module.DefineType("Shadow.Starter", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var start = starter.DefineMethod("Start", StaticMethod, typeof(void), Type.EmptyTypes);
        start.DefineGenericParameters("S");
        start.GetILGenerator().Emit(OpCodes.Ret);
        var many = starter.DefineMethod("Many", StaticMethod, typeof(void), Type.EmptyTypes);
        many.DefineGenericParameters(Enumerable.Range(0, Copies).Select(i => $"T{i}").ToArray());
        many.GetILGenerator().Emit(OpCodes.Ret);

        var callers = module.DefineType("Shadow.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(callers, "CreatesPlatformMachine", il => { il.Emit(OpCodes.Newobj, platformCtor); il.Emit(OpCodes.Pop); });
        Caller(callers, "CreatesOwnMachine", il => { il.Emit(OpCodes.Newobj, ownCtor); il.Emit(OpCodes.Pop); });
        Caller(callers, "StartsPlatformMachine", il => il.Emit(OpCodes.Call, start.MakeGenericMethod(platformMachine)));
        Caller(callers, "StartsRepeated", il => il.Emit(OpCodes.Call, many.MakeGenericMethod(Enumerable.Repeat<Type>(platformMachine, Copies).ToArray())));
        Caller(callers, "StartsInterleaved", il => il.Emit(OpCodes.Call,
            many.MakeGenericMethod(Enumerable.Range(0, Copies).Select(i => i % 2 == 0 ? (Type)platformMachine : ownMachine).ToArray())));

        foreach (var type in new[] { shadow, platformMachine, ownMachine, starter, callers })
            type.CreateType();
    }

    // A public parameterless constructor: ldarg.0; call baseCtor; ret.
    private static ConstructorBuilder Constructor(TypeBuilder type, ConstructorInfo baseCtor)
    {
        var ctor = type.DefineConstructor(MethodAttributes.Public | MethodAttributes.HideBySig, CallingConventions.Standard, Type.EmptyTypes);
        var il = ctor.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, baseCtor);
        il.Emit(OpCodes.Ret);
        return ctor;
    }

    // A public static void parameterless method: `emit` then ret.
    private static void Caller(TypeBuilder callers, string name, Action<ILGenerator> emit)
    {
        var il = callers.DefineMethod(name, StaticMethod, typeof(void), Type.EmptyTypes).GetILGenerator();
        emit(il);
        il.Emit(OpCodes.Ret);
    }

    // A body that loads one constant (or nothing) and returns.
    private static void Body(MethodBuilder method, OpCode? load)
    {
        var il = method.GetILGenerator();
        if (load is { } op)
            il.Emit(op);
        il.Emit(OpCodes.Ret);
    }
    #endregion

    #region Fields
    /// <summary>The emitted assembly's name.</summary>
    public const string Name = "MachineEdgeCases";

    /// <summary>How many generic arguments <c>Many</c> takes (a flat list, never nested).</summary>
    public const int Copies = 64;

    private const MethodAttributes Implementation = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final;
    private const MethodAttributes InterfaceMember = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.Abstract | MethodAttributes.NewSlot;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static;

    private readonly EmittedAssembly emitted;
    #endregion
}

/// <summary>
/// One emitted assembly, <c>MachineShapes</c> (<see cref="EmittedAssembly"/>; never loaded or run), holding the
/// state-machine shapes of <see cref="StateMachineTargetsTests"/>, in namespace <c>Machines</c> (and one caller in
/// <c>Zz.Last</c>, which sorts after it):
/// <list type="bullet">
/// <item><description><c>HandEnumerator : IEnumerator</c>, and <c>InheritingEnumerator : HandEnumerator</c> declaring no
/// <c>MoveNext</c>;</description></item>
/// <item><description><c>GenericOnly : IEnumerator&lt;string&gt;</c> (that interface alone in its <c>InterfaceImpl</c>);</description></item>
/// <item><description><c>ExplicitEnumerator : IEnumerator</c> with an explicit <c>System.Collections.IEnumerator.MoveNext</c>;</description></item>
/// <item><description><c>StaticMover : IEnumerator</c> with a static <c>MoveNext()</c> beside its explicit one;</description></item>
/// <item><description><c>IMyEnumerator : IEnumerator</c> and <c>Deep : IMyEnumerator</c> (that interface alone);</description></item>
/// <item><description><c>GenEnum&lt;T&gt; : IEnumerator</c>; <c>SelfNaming : IEnumerator</c>, whose <c>MoveNext</c> calls
/// <c>Start&lt;SelfNaming&gt;()</c>;</description></item>
/// <item><description><c>&lt;Fake&gt;d__0</c>: an iterator's name and a <c>MoveNext</c>, but no interface;</description></item>
/// <item><description><c>Starter.Start&lt;S&gt;()</c>, <c>Holder&lt;T&gt;.Touch()</c>, and <c>Callers</c>: one static method
/// per site, each with exactly one call-site instruction.</description></item>
/// </list>
/// </summary>
public sealed class StateMachineShapesFixture : IDisposable
{
    #region Constructors
    public StateMachineShapesFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Path = emitted.Save(Name, Define);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Graph = MethodGraph.Build(Index);
            Sites = ModelCallSite.All(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>The single call site of <c>Machines.Callers.{caller}(…)</c>.</summary>
    public ModelCallSite Site(string caller) =>
        Assert.Single(Sites, s => s.Caller.NodeId.StartsWith($"Machines.Callers.{caller}(", StringComparison.Ordinal));

    /// <summary>The StateMachine edges leaving <c>Machines.Callers.{caller}(…)</c>.</summary>
    public IReadOnlyList<MethodEdge> StateMachineEdges(string caller) =>
        [.. Graph.Successors(Site(caller).Caller.NodeId).Where(e => e.Kind == MethodEdgeKind.StateMachine)];

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        var objectCtor = typeof(object).GetConstructor(Type.EmptyTypes)!;
        var enumeratorMoveNext = typeof(IEnumerator).GetMethod(nameof(IEnumerator.MoveNext))!;
        var enumeratorCurrent = typeof(IEnumerator).GetProperty(nameof(IEnumerator.Current))!.GetGetMethod()!;

        // Starter.Start<S>() and Holder<T>.Touch(): the generic-method and generic-type sites.
        var starter = module.DefineType("Machines.Starter", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var start = starter.DefineMethod("Start", StaticMethod, typeof(void), Type.EmptyTypes);
        start.DefineGenericParameters("S");
        start.GetILGenerator().Emit(OpCodes.Ret);
        var holder = module.DefineType("Machines.Holder`1", TypeAttributes.Public | TypeAttributes.Class);
        holder.DefineGenericParameters("T");
        var touch = holder.DefineMethod("Touch", StaticMethod, typeof(void), Type.EmptyTypes);
        touch.GetILGenerator().Emit(OpCodes.Ret);

        // A hand-written IEnumerator, and a subclass that declares no MoveNext.
        var hand = module.DefineType("Machines.HandEnumerator", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator)]);
        var handCtor = Constructor(hand, objectCtor);
        Enumerator(hand);
        var inheriting = module.DefineType("Machines.InheritingEnumerator", TypeAttributes.Public | TypeAttributes.Class, hand);
        var inheritingCtor = Constructor(inheriting, handCtor);

        // IEnumerator<string> alone in the InterfaceImpl table.
        var genericOnly = module.DefineType("Machines.GenericOnly", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator<string>)]);
        var genericOnlyCtor = Constructor(genericOnly, objectCtor);
        Body(genericOnly.DefineMethod("MoveNext", Implementation, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0);
        Body(genericOnly.DefineMethod("get_Current", Implementation, typeof(string), Type.EmptyTypes), OpCodes.Ldnull);
        Body(genericOnly.DefineMethod("Reset", Implementation, typeof(void), Type.EmptyTypes), null);
        Body(genericOnly.DefineMethod("Dispose", Implementation, typeof(void), Type.EmptyTypes), null);
        genericOnly.DefineMethodOverride(Body(genericOnly.DefineMethod("System.Collections.IEnumerator.get_Current", Explicit, typeof(object), Type.EmptyTypes), OpCodes.Ldnull), enumeratorCurrent);

        // An explicit MoveNext.
        var @explicit = module.DefineType("Machines.ExplicitEnumerator", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator)]);
        var explicitCtor = Constructor(@explicit, objectCtor);
        @explicit.DefineMethodOverride(Body(@explicit.DefineMethod("System.Collections.IEnumerator.MoveNext", Explicit, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0), enumeratorMoveNext);
        Enumerator(@explicit, moveNext: false);

        // A static MoveNext() beside the explicit instance one.
        var staticMover = module.DefineType("Machines.StaticMover", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator)]);
        var staticMoverCtor = Constructor(staticMover, objectCtor);
        Body(staticMover.DefineMethod("MoveNext", StaticMethod, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_1);
        staticMover.DefineMethodOverride(Body(staticMover.DefineMethod("System.Collections.IEnumerator.MoveNext", Explicit, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0), enumeratorMoveNext);
        Enumerator(staticMover, moveNext: false);

        // Below an own interface that extends IEnumerator, listing only that interface.
        var myEnumerator = module.DefineType("Machines.IMyEnumerator", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract, null, [typeof(IEnumerator)]);
        var deep = module.DefineType("Machines.Deep", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [myEnumerator]);
        var deepCtor = Constructor(deep, objectCtor);
        Enumerator(deep);

        // A generic state machine.
        var genEnum = module.DefineType("Machines.GenEnum`1", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator)]);
        genEnum.DefineGenericParameters("T");
        var genEnumCtor = Constructor(genEnum, objectCtor);
        Enumerator(genEnum);

        // A MoveNext that names its own state machine.
        var selfNaming = module.DefineType("Machines.SelfNaming", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator)]);
        var selfNamingCtor = Constructor(selfNaming, objectCtor);
        var selfMoveNext = selfNaming.DefineMethod("MoveNext", Implementation, typeof(bool), Type.EmptyTypes).GetILGenerator();
        selfMoveNext.Emit(OpCodes.Call, start.MakeGenericMethod(selfNaming));
        selfMoveNext.Emit(OpCodes.Ldc_I4_0);
        selfMoveNext.Emit(OpCodes.Ret);
        Enumerator(selfNaming, moveNext: false);

        // An iterator's name and a MoveNext, but no state-machine interface.
        var fake = module.DefineType("Machines.<Fake>d__0", TypeAttributes.Public | TypeAttributes.Class);
        var fakeCtor = Constructor(fake, objectCtor);
        Body(fake.DefineMethod("MoveNext", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0);

        // One caller per site.
        var callers = module.DefineType("Machines.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Creates(callers, "CreatesHand", handCtor);
        Creates(callers, "CreatesInheriting", inheritingCtor);
        Creates(callers, "CreatesGenericOnly", genericOnlyCtor);
        Creates(callers, "CreatesExplicit", explicitCtor);
        Creates(callers, "CreatesStaticMover", staticMoverCtor);
        Creates(callers, "CreatesDeep", deepCtor);
        Creates(callers, "CreatesGeneric", TypeBuilder.GetConstructor(genEnum.MakeGenericType(typeof(int)), genEnumCtor));
        Creates(callers, "CreatesSelfNaming", selfNamingCtor);
        Creates(callers, "CreatesFake", fakeCtor);
        Creates(callers, "CreatesListOfHand", TypeBuilder.GetConstructor(typeof(List<>).MakeGenericType(hand), typeof(List<>).GetConstructor(Type.EmptyTypes)!));
        Caller(callers, "StartsHand", [], il => il.Emit(OpCodes.Call, start.MakeGenericMethod(hand)));
        Caller(callers, "StartsGeneric", [], il => il.Emit(OpCodes.Call, start.MakeGenericMethod(genEnum.MakeGenericType(typeof(int)))));
        Caller(callers, "TouchesHolderOfHand", [], il => il.Emit(OpCodes.Call, TypeBuilder.GetMethod(holder.MakeGenericType(hand), touch)));
        Caller(callers, "LoadsStart", [], il => { il.Emit(OpCodes.Ldftn, start.MakeGenericMethod(hand)); il.Emit(OpCodes.Pop); });
        Caller(callers, "MovesNext", [typeof(IEnumerator)], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, enumeratorMoveNext); il.Emit(OpCodes.Pop); });

        // The last method walked (node ids sort "Machines." < "Zz."), for the edge-budget test.
        var last = module.DefineType("Zz.Last", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(last, "Starts", [], il => il.Emit(OpCodes.Call, start.MakeGenericMethod(hand)));

        foreach (var type in new[] { starter, holder, myEnumerator, hand, inheriting, genericOnly, @explicit, staticMover, deep, genEnum, selfNaming, fake, callers, last })
            type.CreateType();
    }

    // A public parameterless constructor: ldarg.0; call baseCtor; ret.
    private static ConstructorBuilder Constructor(TypeBuilder type, ConstructorInfo baseCtor)
    {
        var ctor = type.DefineConstructor(MethodAttributes.Public | MethodAttributes.HideBySig, CallingConventions.Standard, Type.EmptyTypes);
        var il = ctor.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, baseCtor);
        il.Emit(OpCodes.Ret);
        return ctor;
    }

    // IEnumerator's members, implicitly, with no call sites: MoveNext (unless moveNext is false), get_Current, Reset.
    private static void Enumerator(TypeBuilder type, bool moveNext = true)
    {
        if (moveNext)
            Body(type.DefineMethod("MoveNext", Implementation, typeof(bool), Type.EmptyTypes), OpCodes.Ldc_I4_0);
        Body(type.DefineMethod("get_Current", Implementation, typeof(object), Type.EmptyTypes), OpCodes.Ldnull);
        Body(type.DefineMethod("Reset", Implementation, typeof(void), Type.EmptyTypes), null);
    }

    // A public static void method of the callers class: newobj constructor; pop; ret.
    private static void Creates(TypeBuilder callers, string name, ConstructorInfo constructor) =>
        Caller(callers, name, [], il => { il.Emit(OpCodes.Newobj, constructor); il.Emit(OpCodes.Pop); });

    // A public static void method: `emit` then ret.
    private static void Caller(TypeBuilder callers, string name, Type[] parameters, Action<ILGenerator> emit)
    {
        var il = callers.DefineMethod(name, StaticMethod, typeof(void), parameters).GetILGenerator();
        emit(il);
        il.Emit(OpCodes.Ret);
    }

    // A body that loads one constant (or nothing) and returns.
    private static MethodBuilder Body(MethodBuilder method, OpCode? load)
    {
        var il = method.GetILGenerator();
        if (load is { } op)
            il.Emit(op);
        il.Emit(OpCodes.Ret);
        return method;
    }
    #endregion

    #region Fields
    /// <summary>The emitted assembly's name.</summary>
    public const string Name = "MachineShapes";

    private const MethodAttributes Implementation = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final;
    private const MethodAttributes Explicit = MethodAttributes.Private | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static;

    private readonly EmittedAssembly emitted;
    #endregion
}
