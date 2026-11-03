namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// CHA (A2 S1) on shapes no compiled fixture may hold — built as SYNTHETIC Model objects (<see cref="SyntheticModel"/>'s
/// stance: no host, no metadata, nothing resolved), never compiled: a base-class cycle, a base chain past the open-ness
/// walk's depth bound, supertypes that cannot be settled, and a fan-out large enough to exhaust the edge budget on its
/// own. Each hostile walk runs on a worker with a deadline, so a hang fails the test instead of the run.
/// </summary>
public sealed class DispatchRobustnessTests
{
    #region Methods
    // ---- IndexCoverage.SupertypesUnresolved -------------------------------------------------------------------------

    /// <summary>
    /// Three supertypes the walk cannot settle, each counted once in <see cref="IndexCoverage.SupertypesUnresolved"/>
    /// (so the index is not complete) and still keyed by its bare id, so CHA over-approximates rather than loses the
    /// subtype: a base whose assembly is unreadable (null), an interface whose assembly is unreadable, and a base that
    /// names an INDEXED assembly that does not define it.
    /// </summary>
    [Fact]
    public void Build_CountsEverySupertypeThatCannotBeSettled_AndKeepsItsBareKey()
    {
        var (assembly, space) = NewAssembly(Syn);
        var orphan = Class(space, "Orphan", SyntheticModel.TypeRef("Ext", "Gone"));
        orphan.Interfaces.Add(SyntheticModel.TypeRef("Ext", "IGone"));
        Class(space, "Stray", SyntheticModel.TypeRef(Syn, "Missing", assembly: Syn));

        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);

        Assert.Equal(new IndexCoverage(0, 0, 0, 0, SupertypesUnresolved: 3), index.Coverage);
        Assert.False(index.Coverage.IsComplete);
        Assert.Equal([Id("Orphan")], index.DirectSubtypes("Ext.Gone"));
        Assert.Equal([Id("Orphan")], index.DirectSubtypes("Ext.IGone"));
        Assert.Equal([Id("Stray")], index.DirectSubtypes(Id("Missing")));
    }

    /// <summary>
    /// A supertype in an indexed assembly whose forwarders could not be read: unsettled (it may be forwarded anywhere),
    /// so counted — besides <see cref="IndexCoverage.ForwardersUnreadable"/> — and kept bare. The control, the same
    /// assemblies with readable (empty) forwarders, is complete.
    /// </summary>
    [Fact]
    public void Build_ASupertypeIntoAnAssemblyWithUnreadableForwarders_IsCounted()
    {
        var (other, otherSpace) = NewAssembly("Syn2");
        Class(otherSpace, "Root", ObjectRef);
        var (assembly, space) = NewAssembly(Syn);
        Class(space, "Leaf", SyntheticModel.TypeRef("Syn2", "Root", assembly: "Syn2"));

        var unreadable = MemberIndex.Build([(assembly, TypeForwarders.None), (other, TypeForwarders.Unreadable)]);
        var readable = MemberIndex.Build([(assembly, TypeForwarders.None), (other, TypeForwarders.None)]);

        Assert.Equal(new IndexCoverage(0, 0, 0, ForwardersUnreadable: 1, SupertypesUnresolved: 1), unreadable.Coverage);
        Assert.Equal([Id("Leaf")], unreadable.DirectSubtypes("Syn2.Root"));
        Assert.Equal(new IndexCoverage(0, 0, 0), readable.Coverage);
        Assert.True(readable.Coverage.IsComplete);
        Assert.Equal([Id("Leaf")], readable.DirectSubtypes("Syn2.Root"));
    }

    /// <summary>
    /// An own class whose base is unreadable counts as OPEN (over-approximate): its platform supertypes are unknown.
    /// One deriving from an unreadable <c>System.Object</c> is a closed root all the same.
    /// </summary>
    [Fact]
    public void IsOpen_AClassWithAnUnreadableNonRootBase_IsOpen()
    {
        var (assembly, space) = NewAssembly(Syn);
        Class(space, "Orphan", SyntheticModel.TypeRef("Ext", "Gone"));
        Class(space, "Plain", SyntheticModel.TypeRef("System", "Object"));

        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);

        Assert.True(index.IsOpen(Id("Orphan")));
        Assert.False(index.IsOpen(Id("Plain")));
    }

    // ---- hostile hierarchies ----------------------------------------------------------------------------------------

    /// <summary>
    /// A : B and B : A — a base-class cycle no CLR would load, but metadata can say it. The index builds, the open-ness
    /// walk stops at the repeat (both closed: nothing leaves the index), the subtype closure stops at its visited set, and
    /// a <c>callvirt A::Run</c> reaches B's Run.
    /// </summary>
    [Fact]
    public void DispatchTargets_OverABaseClassCycle_Terminates()
    {
        var (assembly, space) = NewAssembly(Syn);
        var a = Class(space, "A", SyntheticModel.TypeRef(Syn, "B", assembly: Syn));
        var b = Class(space, "B", SyntheticModel.TypeRef(Syn, "A", assembly: Syn));
        Virtual(a, "Run");
        Virtual(b, "Run");
        Caller(space, "Go", Callvirt("A", "Run"));

        var (index, graph) = WithinDeadline(() =>
        {
            var built = MemberIndex.Build([(assembly, TypeForwarders.None)]);
            return (built, MethodGraph.Build(built));
        });

        Assert.Equal([Id("B")], index.DirectSubtypes(Id("A")));
        Assert.Equal([Id("A")], index.DirectSubtypes(Id("B")));
        Assert.False(index.IsOpen(Id("A")));
        Assert.False(index.IsOpen(Id("B")));
        Assert.Contains(Id("B.Run()"), index.DispatchTargets(CallvirtTarget("A", "Run"), index.Resolve(CallvirtTarget("A", "Run")), virtualSite: true)!);
        Assert.Contains(new MethodEdge(Id("Callers.Go()"), Id("B.Run()"), MethodEdgeKind.Dispatch, SyntheticModel.CallOffset), graph.Edges);
    }

    /// <summary>
    /// A base chain C0 : C1 : … : C299 : System.Object, longer than the open-ness walk's bound (256). The walk is
    /// iterative and bounded, so it terminates, and a type whose chain does not reach a root within the bound counts as
    /// OPEN: C0..C42 (257+ steps to Object) are open, C43..C299 are closed. A <c>callvirt C299::Run</c> reaches all 299
    /// overrides below it.
    /// </summary>
    [Fact]
    public void IsOpen_PastTheDepthBound_IsOpen_AndTheWalkTerminates()
    {
        const int length = 300;
        var (assembly, space) = NewAssembly(Syn);
        for (var i = 0; i < length; i++)
            Virtual(Class(space, $"C{i}", i == length - 1 ? ObjectRef : SyntheticModel.TypeRef(Syn, $"C{i + 1}", assembly: Syn)), "Run");

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.True(index.IsOpen(Id("C0")));
        Assert.True(index.IsOpen(Id("C42")));
        Assert.False(index.IsOpen(Id("C43")));
        Assert.False(index.IsOpen(Id($"C{length - 1}")));
        Assert.Equal(43, Enumerable.Range(0, length).Count(i => index.IsOpen(Id($"C{i}"))));
        Assert.Equal(new IndexCoverage(0, 0, 0), index.Coverage);

        var reference = CallvirtTarget($"C{length - 1}", "Run");
        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true));
        Assert.Equal(length - 1, targets!.Count);
        Assert.DoesNotContain(Id($"C{length - 1}.Run()"), targets);
    }

    // ---- the bounded hierarchy walks (S1b, review W1) --------------------------------------------------------------

    /// <summary>
    /// <c>Below</c>'s upward walk stops after 4,096 visited supertypes and then counts as a MATCH (over-approximate):
    /// a class <c>X</c> with 5,000 own interfaces, none of them the declared one, is reached from
    /// <c>callvirt Target::Run</c>; with 4,000 it is walked to the end and correctly not reached.
    /// </summary>
    [Theory]
    [InlineData(5000, true)]
    [InlineData(4000, false)]
    public void DispatchTargets_PastTheUpwardWalkBound_CountsAsBelow(int interfaces, bool reached)
    {
        var (assembly, space) = NewAssembly(Syn);
        Interface(space, "Target", "Run");
        var x = Class(space, "X", ObjectRef);
        for (var i = 0; i < interfaces; i++)
        {
            Interface(space, $"I{i}");
            x.Interfaces.Add(SyntheticModel.TypeRef(Syn, $"I{i}", assembly: Syn));
        }
        Virtual(x, "Run");
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
        var reference = CallvirtTarget("Target", "Run");

        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true));

        Assert.Equal(reached, targets!.Contains(Id("X.Run()")));
    }

    /// <summary>
    /// The same bound on a deep base chain C0 : … : C4999 : Object: from C0 the walk passes 4,096 visits and counts as
    /// below the unrelated own class <c>Target</c>; from C4999 it reaches Object and does not.
    /// <para>
    /// <c>Target</c> has one own subclass, <c>TargetSub</c>, which defines no <c>Run</c>. It is there only so that the
    /// walk runs at all: since S1d, a declared own class that nothing derives from is answered <c>[]</c> by the
    /// pre-filter without walking (correct, and more precise). <c>TargetSub</c> is not a candidate and changes no answer.
    /// </para>
    /// </summary>
    [Fact]
    public void DispatchTargets_PastTheUpwardWalkBoundOnADeepChain_CountsAsBelow()
    {
        const int length = 5000;
        var (assembly, space) = NewAssembly(Syn);
        Virtual(Class(space, "Target", ObjectRef), "Run");
        Class(space, "TargetSub", SyntheticModel.TypeRef(Syn, "Target", assembly: Syn));
        for (var i = 0; i < length; i++)
        {
            var type = Class(space, $"C{i}", i == length - 1 ? ObjectRef : SyntheticModel.TypeRef(Syn, $"C{i + 1}", assembly: Syn));
            if (i is 0 or length - 1)
                Virtual(type, "Run");
        }
        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));
        var reference = CallvirtTarget("Target", "Run");
        var work = new MemberIndex.DispatchWork(long.MaxValue);

        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true, work));

        Assert.Equal([Id("C0.Run()")], targets);
        // Non-vacuity: the upward walk really ran into the bound (one unit per step), it was not pre-filtered.
        Assert.True(work.Spent > 4096, $"spent {work.Spent} units; the walk from C0 did not reach the 4,096-visit bound");
    }

    /// <summary>
    /// <c>InheritedBelow</c>'s downward walk has the same bound: a class <c>B</c> with a virtual <c>Run</c> and 5,000 own
    /// subclasses, NONE of which implements the declared interface <c>I</c>, is reached from <c>callvirt I::Run</c> as an
    /// inherited implementation (over-approximate); with 4,000 subclasses the walk ends and it is not.
    /// </summary>
    [Theory]
    [InlineData(5000, true)]
    [InlineData(4000, false)]
    public void DispatchTargets_PastTheDownwardWalkBound_CountsAsInheritedBelow(int subclasses, bool reached)
    {
        var (assembly, space) = NewAssembly(Syn);
        Interface(space, "I", "Run");
        Virtual(Class(space, "B", ObjectRef), "Run");
        for (var i = 0; i < subclasses; i++)
            Class(space, $"S{i}", SyntheticModel.TypeRef(Syn, "B", assembly: Syn));
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
        var reference = CallvirtTarget("I", "Run");

        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true));

        Assert.Equal(reached, targets!.Contains(Id("B.Run()")));
    }

    /// <summary>
    /// The walks share a memo within one Dispatch (S1b), and a walk that HITS THE BOUND must record nothing — above
    /// all not "not below". Two candidates in one Dispatch, <c>P : X</c> and <c>Q : X</c>, where <c>X</c> has 5,000 own
    /// interfaces: P's walk hits the bound (a match); Q's walk then crosses the same types and must hit it again,
    /// not stop on a "not below" left by P's walk. Both are reached.
    /// </summary>
    [Fact]
    public void DispatchTargets_AnUpwardWalkThatHitTheBound_RecordsNothingForTheNextWalk()
    {
        var (assembly, space) = NewAssembly(Syn);
        Interface(space, "Target", "Run");
        var x = Class(space, "X", ObjectRef);
        for (var i = 0; i < 5000; i++)
        {
            Interface(space, $"I{i}");
            x.Interfaces.Add(SyntheticModel.TypeRef(Syn, $"I{i}", assembly: Syn));
        }
        Virtual(Class(space, "P", SyntheticModel.TypeRef(Syn, "X", assembly: Syn)), "Run");
        Virtual(Class(space, "Q", SyntheticModel.TypeRef(Syn, "X", assembly: Syn)), "Run");
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
        var reference = CallvirtTarget("Target", "Run");

        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true));

        Assert.Equal([Id("P.Run()"), Id("Q.Run()")], targets);
    }

    /// <summary>
    /// The same for the downward walk. <c>B</c> (5,000 own subclasses, none implementing <c>I</c>) and its base
    /// <c>Top</c> both have a virtual <c>Run</c>; B's <c>InheritedBelow</c> hits the bound first (B sorts first), then
    /// Top's walk goes down through B and must hit it again rather than stop on a recorded "does not inherit". Both are
    /// reached (over-approximate), and a genuinely unrelated class with a <c>Run</c> is not.
    /// </summary>
    [Fact]
    public void DispatchTargets_ADownwardWalkThatHitTheBound_RecordsNothingForTheNextWalk()
    {
        var (assembly, space) = NewAssembly(Syn);
        Interface(space, "I", "Run");
        Virtual(Class(space, "Top", ObjectRef), "Run");
        Virtual(Class(space, "B", SyntheticModel.TypeRef(Syn, "Top", assembly: Syn)), "Run");
        for (var i = 0; i < 5000; i++)
            Class(space, $"S{i}", SyntheticModel.TypeRef(Syn, "B", assembly: Syn));
        Virtual(Class(space, "Unrelated", ObjectRef), "Run");
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
        var reference = CallvirtTarget("I", "Run");

        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true));

        Assert.Equal([Id("B.Run()"), Id("Top.Run()")], targets);
    }

    /// <summary>
    /// The memo keeps a genuine answer exact after a bound hit and after full "not below" walks in the same Dispatch:
    /// with <c>X</c> (5,000 interfaces) walked to the bound, and unrelated <c>Far</c> classes fully walked, <c>Real</c>
    /// — which really implements the declared interface through its base — is still reached, and every <c>Far</c> is
    /// not.
    /// </summary>
    [Fact]
    public void DispatchTargets_AfterABoundHitAndFullWalks_AGenuineSubtypeIsStillReached()
    {
        var (assembly, space) = NewAssembly(Syn);
        Interface(space, "Target", "Run");
        var x = Class(space, "A0", ObjectRef);
        for (var i = 0; i < 5000; i++)
        {
            Interface(space, $"I{i}");
            x.Interfaces.Add(SyntheticModel.TypeRef(Syn, $"I{i}", assembly: Syn));
        }
        Virtual(x, "Run");
        var implementor = Class(space, "Base", ObjectRef);
        implementor.Interfaces.Add(SyntheticModel.TypeRef(Syn, "Target", assembly: Syn));
        for (var i = 0; i < 3; i++)
            Virtual(Class(space, $"Far{i}", ObjectRef), "Run");
        Virtual(Class(space, "Real", SyntheticModel.TypeRef(Syn, "Base", assembly: Syn)), "Run");
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
        var reference = CallvirtTarget("Target", "Run");

        var targets = WithinDeadline(() => index.DispatchTargets(reference, index.Resolve(reference), virtualSite: true));

        Assert.Equal([Id("A0.Run()"), Id("Real.Run()")], targets);
    }

    // ---- cost of the walks (S1b, review W1) ---------------------------------------------------------------------------

    /// <summary>
    /// The two shapes where a walk per candidate would be quadratic (or worse), whatever the edge budget — both with
    /// ZERO targets, so only time shows the work:
    /// <list type="bullet">
    /// <item><description><b>Leaf</b> — a chain C0 &lt;- C1 &lt;- … &lt;- C(n-1), every class declaring <c>m</c>, called once
    /// through the leaf: n candidates, each an ancestor, each walked up to the root. The leaf has one own subclass
    /// <c>Below</c> without an <c>m</c>, so the S1d pre-filter (a declared class nothing derives from costs nothing)
    /// does not answer it before any walk;</description></item>
    /// <item><description><b>Downward</b> — a chain B0 &lt;- … &lt;- B(n-1), every class declaring <c>Run</c>, none
    /// implementing the own interface <c>I</c>, called through <c>I</c>: each candidate's <c>InheritedBelow</c> walks
    /// down the rest of the chain, calling <c>Below</c> at every step.</description></item>
    /// </list>
    /// One <see cref="MemberIndex.DispatchTargets"/> call, timed alone on a fresh index (best of 3). From n = 1000 to
    /// n = 4000 (inside the 4,096-visit bound) it may grow by less than 8x (linear: 4x, quadratic: 16x) unless it stays
    /// under 50 ms outright, and n = 4000 must take under 1 s.
    /// </summary>
    [Theory]
    [Trait("Category", "Cost")]
    [InlineData("Leaf")]
    [InlineData("Downward")]
    public void DispatchTargets_TheChainShapes_ScaleAboutLinearly(string shape)
    {
        _ = TimeDispatch(shape, 200);   // JIT warm-up

        var small = TimeDispatch(shape, 1000);
        var large = TimeDispatch(shape, 4000);

        Assert.True(large.TotalSeconds < 1 && (large.TotalMilliseconds < 50 || large.Ticks < 8 * small.Ticks),
            $"{shape}: n=1000 {small.TotalMilliseconds:F1} ms, n=4000 {large.TotalMilliseconds:F1} ms (x{(double)large.Ticks / Math.Max(1, small.Ticks):F1}); expected under x8 (or under 50 ms) and under 1 s.");
    }

    private static TimeSpan TimeDispatch(string shape, int n)
    {
        var best = TimeSpan.MaxValue;
        for (var run = 0; run < 3; run++)
        {
            var (assembly, space) = NewAssembly(Syn);
            ModelTypes.MethodReference reference;
            if (shape == "Leaf")
            {
                for (var i = 0; i < n; i++)
                    Virtual(Class(space, $"C{i}", i == 0 ? ObjectRef : SyntheticModel.TypeRef(Syn, $"C{i - 1}", assembly: Syn)), "m");
                Class(space, "Below", SyntheticModel.TypeRef(Syn, $"C{n - 1}", assembly: Syn));
                reference = CallvirtTarget($"C{n - 1}", "m");
            }
            else
            {
                Interface(space, "I", "Run");
                for (var i = 0; i < n; i++)
                    Virtual(Class(space, $"B{i}", i == 0 ? ObjectRef : SyntheticModel.TypeRef(Syn, $"B{i - 1}", assembly: Syn)), "Run");
                reference = CallvirtTarget("I", "Run");
            }
            var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);
            var resolution = index.Resolve(reference);
            Assert.NotNull(resolution.Definition);

            var (targets, elapsed) = WithinDeadline(() =>
            {
                var watch = System.Diagnostics.Stopwatch.StartNew();
                var answer = index.DispatchTargets(reference, resolution, virtualSite: true);
                return (answer, watch.Elapsed);
            });

            Assert.Empty(targets!);
            best = elapsed < best ? elapsed : best;
        }
        return best;
    }

    // ---- the edge budget --------------------------------------------------------------------------------------------

    /// <summary>
    /// One <c>callvirt Base::Run</c> and five bodyless overrides: one static edge, five Dispatch edges. A budget of 3
    /// fits the static edge and is then exhausted by the fan-out ALONE — the graph is truncated by the edges budget with
    /// exactly two Dispatch edges; a budget of 1 fits only the static edge; a budget of 6 fits everything.
    /// </summary>
    [Theory]
    [InlineData(1, 0, true)]
    [InlineData(3, 2, true)]
    [InlineData(6, 5, false)]
    public void Build_AnEdgeBudgetExhaustedByDispatchEdgesAlone_IsTruncatedByTheEdgesBudget(int maxEdges, int dispatchEdges, bool truncated)
    {
        var (assembly, space) = NewAssembly(Syn);
        Virtual(Class(space, "Base", ObjectRef), "Run", isAbstract: true);
        for (var i = 1; i <= 5; i++)
            Virtual(Class(space, $"D{i}", SyntheticModel.TypeRef(Syn, "Base", assembly: Syn)), "Run");
        Caller(space, "Go", Callvirt("Base", "Run"));
        var index = MemberIndex.Build([(assembly, TypeForwarders.None)]);

        var graph = MethodGraph.Build(index, new GraphBudget(1_000_000, maxEdges));

        Assert.Equal(truncated, graph.Coverage.Truncated);
        Assert.Equal(truncated ? $"edges budget of {maxEdges} reached" : null, graph.Coverage.TruncatedBy);
        Assert.Equal(1, graph.Coverage.CallSites);
        Assert.Equal(1, graph.Coverage.DispatchSites);
        Assert.Equal(dispatchEdges, graph.Coverage.DispatchEdges);
        Assert.Equal([new MethodEdge(Id("Callers.Go()"), Id("Base.Run()"), MethodEdgeKind.CallVirt, SyntheticModel.CallOffset)],
            graph.Edges.Where(e => e.Kind != MethodEdgeKind.Dispatch));
        Assert.Equal(dispatchEdges, graph.Edges.Count(e => e.Kind == MethodEdgeKind.Dispatch));
        Assert.Equal(Math.Min(maxEdges, 6), graph.Edges.Count);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static (Model.Assembly Assembly, Model.Namespace Space) NewAssembly(string name)
    {
        var assembly = new Model.Assembly(name);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace(name) { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;
        return (assembly, space);
    }

    private static ModelTypes.ClassDefinition Class(Model.Namespace space, string name, ModelTypes.IBasicType @base)
    {
        var type = new ModelTypes.ClassDefinition(name) { ContainingAssembly = (Model.Assembly)space.ContainingAssembly, ContainingNamespace = space, Base = @base };
        space.Types.Add(type);
        return type;
    }

    // An own interface, with an abstract int method() when one is named.
    private static void Interface(Model.Namespace space, string name, string? method = null)
    {
        var type = new ModelTypes.InterfaceDefinition(name) { ContainingAssembly = (Model.Assembly)space.ContainingAssembly, ContainingNamespace = space };
        if (method is not null)
            type.Methods.Add(new ModelTypes.MethodDefinition(method, ModelTypes.PlatformTypes.Int32) { ContainingType = type, IsVirtual = true, IsAbstract = true });
        space.Types.Add(type);
    }

    // A bodyless instance virtual (or abstract) int name().
    private static void Virtual(ModelTypes.ClassDefinition type, string name, bool isAbstract = false) =>
        type.Methods.Add(new ModelTypes.MethodDefinition(name, ModelTypes.PlatformTypes.Int32) { ContainingType = type, IsVirtual = true, IsAbstract = isAbstract });

    // Syn.Callers.name(): a static method whose body is the one instruction given, at SyntheticModel.CallOffset.
    private static void Caller(Model.Namespace space, string name, ModelBytecode.Instruction instruction)
    {
        var callers = space.Types.OfType<ModelTypes.ClassDefinition>().SingleOrDefault(t => t.Name == "Callers") ?? Class(space, "Callers", ObjectRef);
        var body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode);
        body.Instructions.Add(instruction);
        callers.Methods.Add(new ModelTypes.MethodDefinition(name, ModelTypes.PlatformTypes.Void) { ContainingType = callers, IsStatic = true, Body = body });
    }

    private static ModelBytecode.MethodCallInstruction Callvirt(string type, string method) =>
        new(SyntheticModel.CallOffset, ModelBytecode.MethodCallOperation.Virtual, CallvirtTarget(type, method));

    private static ModelTypes.MethodReference CallvirtTarget(string type, string method) =>
        SyntheticModel.Method(SyntheticModel.TypeRef(Syn, type, assembly: Syn), method);

    private static string Id(string nameWithoutNamespace) => $"{Syn}.{nameWithoutNamespace}";

    // Runs a walk over hostile metadata on a worker with a deadline, so a non-terminating walk fails the test.
    private static T WithinDeadline<T>(Func<T> walk)
    {
        var task = Task.Run(walk);
        Assert.True(task.Wait(TimeSpan.FromSeconds(60)), "the walk did not terminate within 60 s");
        return task.Result;
    }
    #endregion

    #region Fields
    private const string Syn = "Syn";

    private static ModelTypes.BasicType ObjectRef => SyntheticModel.TypeRef("System", "Object", assembly: "System.Private.CoreLib");
    #endregion
}
