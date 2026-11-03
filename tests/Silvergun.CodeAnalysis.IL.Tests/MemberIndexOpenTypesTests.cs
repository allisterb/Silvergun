namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// <see cref="MemberIndex.IsOpen"/> as rewritten in A2 S1g (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md,
/// "S1 review 5 … (S1g)", W1-r5): one distinct base list per id; an id is DIRECTLY open on an unreadable base or on a base
/// that leaves the index at anything but a closed root (<c>System.Object</c>, <c>System.ValueType</c>,
/// <c>System.Enum</c>, <c>System.Delegate</c>, <c>System.MulticastDelegate</c>); open-ness flows to every type below an
/// open one; and an id is open when its <c>BaseHeights</c> bound — a saturating upper bound on how many base edges a
/// walk can take before it repeats a type, per strongly connected component: n edges inside a component of n nodes that
/// holds a cycle (a self-loop included), none in a single node without one, plus 1 + the height of the highest component
/// below — exceeds <c>MaxBaseDepth</c> (256).
/// <para>
/// Each pin says what the pre-S1g per-start BFS (<c>OpenTypes</c> at commit 7db7cb9) would have answered, and the new rule
/// matches it exactly on every shape here. A first S1g draft counted a component as n − 1 edges and called a 257-cycle
/// closed where the old walk said open; that was fixed in <c>src/</c> and is pinned by
/// <see cref="IsOpen_OnABaseClassCycleWithNoExternalBase_IsOpenFrom257Classes"/>. A later draft counted a single type
/// whose base is itself as no edges, one fewer than the old walk; that was fixed too (review 6 N1) and is pinned by
/// <see cref="IsOpen_OnAChainIntoAClassThatIsItsOwnBase_CountsTheSelfLoopAsACycleOfOne"/>.
/// </para>
/// All SYNTHETIC Model objects (<see cref="SyntheticModel"/>'s stance: no host, nothing resolved, never compiled), each
/// build on a worker with a deadline.
/// </summary>
public sealed class MemberIndexOpenTypesTests
{
    #region Methods
    // ---- the depth bound on a chain ---------------------------------------------------------------------------------

    /// <summary>
    /// A chain of n own classes, <c>K0 : System.Object</c> and <c>Ki : K(i-1)</c> (the reviewer's mode L shape). The
    /// boundary, derived:
    /// <list type="bullet">
    /// <item><description><b>New rule.</b> Every component is one class; <c>System.Object</c> is not indexed, so it is no
    /// edge. Hence <c>height(K0) = 0</c> and <c>height(Ki) = i</c>, and <c>Ki</c> is open iff <c>i &gt; 256</c>, i.e.
    /// <c>i ≥ 257</c>.</description></item>
    /// <item><description><b>Old rule.</b> From start <c>Ki</c>, the BFS frontier at depth d is <c>{K(i-d)}</c>, non-empty
    /// for <c>d ≤ i</c>, and the start is open once a non-empty frontier reaches <c>d &gt; 256</c>: some base at distance
    /// ≥ 257, i.e. <c>i ≥ 257</c>. The same.</description></item>
    /// </list>
    /// So a chain of 256 or 257 classes is all closed: the deepest, <c>K256</c>, has a path of exactly 256 edges. At 258,
    /// exactly one class, <c>K257</c>, is open, and in general the open classes number max(0, n − 257), always the deepest.
    /// The top 257 (<c>K0..K256</c>) are always closed.
    /// </summary>
    [Theory]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(258)]
    [InlineData(259)]
    public void IsOpen_OnAChainOverObject_IsOpenExactlyFromTheClassWith257OwnBasesAbove(int n)
    {
        var (assembly, space) = NewAssembly();
        for (var i = 0; i < n; i++)
            Class(space, $"K{i}", i == 0 ? ObjectRef : Own($"K{i - 1}"));

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(Enumerable.Range(0, n).Select(i => i >= 257), Enumerable.Range(0, n).Select(i => index.IsOpen(Id($"K{i}"))));
        Assert.Equal(Math.Max(0, n - 257), index.TypeIds.Count(index.IsOpen));
        Assert.False(index.IsOpen(Id("K256")));
        Assert.Equal(n >= 258, index.IsOpen(Id($"K{n - 1}")));
    }

    // ---- cycles ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// A base-class cycle of n own classes <c>Ci : C((i+1) mod n)</c>, with no other base. It is one component of n &gt; 1,
    /// counted as n edges, so every member's height is n, and the cycle is open iff n &gt; 256, i.e. n ≥ 257. Cycles of 3
    /// and of 256 are closed (a short cycle alone stays closed); 257, 258 and 300 are open. An unrelated class stays
    /// closed. <c>Below : C0</c> is a chain of 1 into the cycle, with height n + 1: open from n = 256, as in
    /// <see cref="IsOpen_OnAChainIntoACycle_IsOpenFromTheClassWhoseChainAndCycleReach257"/>. So on the 256-cycle it is
    /// open while every member is closed.
    /// <para>
    /// This matches the old per-start BFS exactly. From any member, the frontier at depth d is the member d steps on, and
    /// at depth n it is the start again: the loop runs once more and tests <c>depth &gt; 256</c> before the repeat is
    /// filtered, so the old walk was open iff n ≥ 257. (A first S1g draft counted n − 1 edges and called the 257-cycle
    /// closed: the one shape where it was less open than the old walk. Fixed in <c>src/</c>.)
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(3, false)]
    [InlineData(256, false)]
    [InlineData(257, true)]
    [InlineData(258, true)]
    [InlineData(300, true)]
    public void IsOpen_OnABaseClassCycleWithNoExternalBase_IsOpenFrom257Classes(int n, bool open)
    {
        var (assembly, space) = NewAssembly();
        for (var i = 0; i < n; i++)
            Class(space, $"C{i}", Own($"C{(i + 1) % n}"));
        Class(space, "Below", Own("C0"));
        Class(space, "Apart", ObjectRef);

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.All(Enumerable.Range(0, n), i => Assert.Equal(open, index.IsOpen(Id($"C{i}"))));
        // Below : C0 is a chain of 1 into the cycle: height n + 1, so open from n = 256 (closed only on the 3-cycle).
        Assert.Equal(n + 1 >= 257, index.IsOpen(Id("Below")));
        Assert.False(index.IsOpen(Id("Apart")));
        Assert.Equal(new IndexCoverage(0, 0, 0), index.Coverage);
    }

    /// <summary>
    /// A chain of k classes into a cycle of m: <c>Ci : C((i+1) mod m)</c>, then <c>T1 : C0</c> and <c>Tj : T(j-1)</c> up to
    /// <c>Tk</c>. The cycle's height is m, so <c>Tj</c>'s is j + m, and <c>Tj</c> is open iff j + m ≥ 257. The cycle
    /// itself (m &lt; 257 here) stays closed. So the deepest class, <c>Tk</c>, is closed at k + m = 256 and open at
    /// k + m = 257, while <c>T(k-1)</c> is closed in both.
    /// <para>
    /// This matches the old per-start BFS exactly. From <c>Tj</c>, the frontier reaches <c>C0</c> at depth j, runs round
    /// the cycle, and holds <c>C0</c> again at depth j + m, where it tested <c>depth &gt; 256</c> before filtering the
    /// repeat.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(253, 3, false)]
    [InlineData(254, 3, true)]
    [InlineData(156, 100, false)]
    [InlineData(157, 100, true)]
    public void IsOpen_OnAChainIntoACycle_IsOpenFromTheClassWhoseChainAndCycleReach257(int k, int m, bool deepestOpen)
    {
        var (assembly, space) = NewAssembly();
        for (var i = 0; i < m; i++)
            Class(space, $"C{i}", Own($"C{(i + 1) % m}"));
        for (var j = 1; j <= k; j++)
            Class(space, $"T{j}", Own(j == 1 ? "C0" : $"T{j - 1}"));

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(deepestOpen, index.IsOpen(Id($"T{k}")));
        Assert.False(index.IsOpen(Id($"T{k - 1}")));
        Assert.All(Enumerable.Range(1, k), j => Assert.Equal(j + m >= 257, index.IsOpen(Id($"T{j}"))));
        Assert.All(Enumerable.Range(0, m), i => Assert.False(index.IsOpen(Id($"C{i}"))));
        Assert.Equal(deepestOpen ? 1 : 0, index.TypeIds.Count(index.IsOpen));
    }

    /// <summary>
    /// A class that is its own base, <c>S : S</c>, with a chain <c>T1 : S</c> and <c>Tj : T(j-1)</c> up to <c>T256</c>;
    /// optionally <c>S</c> is defined a second time as <c>S : System.Object</c>, in either row order. The boundary,
    /// derived:
    /// <list type="bullet">
    /// <item><description><b>New rule.</b> <c>{S}</c> is a single-node component with a self-edge, so it holds a cycle of
    /// 1: <c>height(S) = 1</c>. <c>System.Object</c> is a closed root and not indexed, so the second definition adds no
    /// edge and opens nothing. Each <c>Tj</c> is its own component, <c>height(Tj) = j + 1</c>, and <c>Tj</c> is open iff
    /// <c>j + 1 &gt; 256</c>, i.e. <c>j ≥ 256</c>. So <c>T256</c> is open, <c>T255</c> closed, and <c>S</c> (height 1)
    /// closed.</description></item>
    /// <item><description><b>Old rule.</b> From <c>Tj</c>, the frontier at depth d is <c>{T(j-d)}</c> for d &lt; j and
    /// <c>{S}</c> at depth j; S's base is S, so the frontier at depth j + 1 is <c>{S}</c> again, and the loop tested
    /// <c>depth &gt; 256</c> before the repeat was filtered. Open iff <c>j + 1 ≥ 257</c>, i.e. <c>j ≥ 256</c>; from
    /// <c>S</c> itself the repeat comes at depth 1, so it is closed. The same.</description></item>
    /// </list>
    /// Before review 6 N1, <c>src/</c> counted a single node as no edges even with a self-edge, so <c>height(T256)</c> was
    /// 256 and <c>IsOpen(T256)</c> False (the reviewer measured it): less open than the old walk.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void IsOpen_OnAChainIntoAClassThatIsItsOwnBase_CountsTheSelfLoopAsACycleOfOne(bool definedTwice, bool objectFirst)
    {
        const int k = 256;
        var (assembly, space) = NewAssembly();
        if (definedTwice && objectFirst)
            Class(space, "S", ObjectRef);
        Class(space, "S", Own("S"));
        if (definedTwice && !objectFirst)
            Class(space, "S", ObjectRef);
        for (var j = 1; j <= k; j++)
            Class(space, $"T{j}", Own(j == 1 ? "S" : $"T{j - 1}"));

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(definedTwice ? 2 : 1, index.Types(Id("S")).Count);
        Assert.True(index.IsOpen(Id("T256")), "T256 should be open: S's self-loop counts as one edge, 257 in all");
        Assert.False(index.IsOpen(Id("T255")));
        Assert.False(index.IsOpen(Id("S")));
        Assert.All(Enumerable.Range(1, k), j => Assert.Equal(j >= 256, index.IsOpen(Id($"T{j}"))));
        Assert.Equal(1, index.TypeIds.Count(index.IsOpen));
        Assert.Equal(new IndexCoverage(0, 0, 0), index.Coverage);
    }

    /// <summary>
    /// A 3-cycle <c>A : B : C : A</c> where <c>B</c> has a second definition, <c>B : System.IO.Stream</c>, in either row
    /// order: B is directly open (an external non-root base), and open-ness flows to every type below it. Inside a cycle
    /// that is every member, so A, B and C are all open, and so is <c>D : A</c> below the cycle. An unrelated class
    /// stays closed. The old walk agrees: every start reached B, and with it Stream.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IsOpen_OnACycleWhereOneMembersOtherDefinitionHasAnExternalBase_IsOpenForEveryMember(bool streamFirst)
    {
        var (assembly, space) = NewAssembly();
        Class(space, "A", Own("B"));
        if (streamFirst)
            Class(space, "B", StreamRef);
        Class(space, "B", Own("C"));
        if (!streamFirst)
            Class(space, "B", StreamRef);
        Class(space, "C", Own("A"));
        Class(space, "D", Own("A"));
        Class(space, "Apart", ObjectRef);

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(2, index.Types(Id("B")).Count);
        Assert.All(new[] { "A", "B", "C", "D" }, t => Assert.True(index.IsOpen(Id(t)), $"{t} should be open"));
        Assert.False(index.IsOpen(Id("Apart")));
    }

    // ---- duplicate definitions of one id ----------------------------------------------------------------------------

    /// <summary>
    /// An id <c>Syn.Y</c> defined twice: once as <c>Y : System.Object</c>, once with <paramref name="other"/> as its
    /// base, in either row order, with <c>Sub : Y</c> and <c>Leaf : Sub</c> below it. The id is open if ANY definition
    /// has a base that leaves the index at a non-root (<c>System.IO.Stream</c>) or an unreadable one, whatever the order,
    /// and so is everything below it. Two closed bases (<c>Object</c> again, or an own closed class <c>Z</c>) leave it
    /// closed. The old walk agrees: it read every definition of every id it reached.
    /// </summary>
    [Theory]
    [InlineData("Stream", false, true)]
    [InlineData("Stream", true, true)]
    [InlineData("Unreadable", false, true)]
    [InlineData("Unreadable", true, true)]
    [InlineData("Object", false, false)]
    [InlineData("Object", true, false)]
    [InlineData("OwnClosed", false, false)]
    [InlineData("OwnClosed", true, false)]
    public void IsOpen_OnAnIdDefinedTwice_IsOpenIfAnyDefinitionsBaseOpensIt_InEitherOrder(string other, bool otherFirst, bool open)
    {
        var (assembly, space) = NewAssembly();
        ModelTypes.IBasicType otherBase = other switch
        {
            "Stream" => StreamRef,
            "Unreadable" => UnreadableObjectRef,
            "Object" => ObjectRef,
            _ => Own("Z"),
        };
        Class(space, "Z", ObjectRef);
        if (otherFirst)
            Class(space, "Y", otherBase);
        Class(space, "Y", ObjectRef);
        if (!otherFirst)
            Class(space, "Y", otherBase);
        Class(space, "Sub", Own("Y"));
        Class(space, "Leaf", Own("Sub"));

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(2, index.Types(Id("Y")).Count);
        Assert.Equal(open, index.IsOpen(Id("Y")));
        Assert.Equal(open, index.IsOpen(Id("Sub")));
        Assert.Equal(open, index.IsOpen(Id("Leaf")));
        Assert.False(index.IsOpen(Id("Z")));
    }

    // ---- external bases --------------------------------------------------------------------------------------------

    /// <summary>
    /// A class over an external base in <c>System.Private.CoreLib</c> (not indexed), and an own class below it: closed
    /// over the five closed roots, open over any other platform class, and open over a class merely NAMED like a root in
    /// another namespace (<c>Ext.Object</c>). The roots are matched by full id. The old walk had the same root set.
    /// </summary>
    [Theory]
    [InlineData("System", "Object", false)]
    [InlineData("System", "ValueType", false)]
    [InlineData("System", "Enum", false)]
    [InlineData("System", "Delegate", false)]
    [InlineData("System", "MulticastDelegate", false)]
    [InlineData("System.IO", "Stream", true)]
    [InlineData("System", "Exception", true)]
    [InlineData("System", "Attribute", true)]
    [InlineData("System", "MarshalByRefObject", true)]
    [InlineData("Ext", "Object", true)]
    public void IsOpen_OverAnExternalBase_IsClosedOnlyOverAClosedRoot(string space, string name, bool open)
    {
        var (assembly, ns) = NewAssembly();
        Class(ns, "Over", SyntheticModel.TypeRef(space, name, assembly: CoreLib));
        Class(ns, "Under", Own("Over"));

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(open, index.IsOpen(Id("Over")));
        Assert.Equal(open, index.IsOpen(Id("Under")));
    }

    // ---- unreadable bases ------------------------------------------------------------------------------------------

    /// <summary>
    /// A base whose identity cannot be read is open, even when it would name <c>System.Object</c>: a
    /// <see cref="ThrowingBasicType"/> over <c>System.Object</c> that throws on <c>ContainingType</c> (or on
    /// <c>GenericParameterCount</c>). <c>ModelNames.Of</c> then gives the unknown identity, which is neither indexed nor a
    /// closed root, so the class is open, and so is its own subclass. The same base, readable, is closed (the control).
    /// The old walk keyed the base the same way.
    /// <para>
    /// This is NOT the <c>keys is null</c> branch of <c>OpenTypes</c> (the <c>Guard</c> around <c>scope.Of(b)</c>). No
    /// Model object of today's types can reach that branch: <c>TypeScope.Of</c> guards every read itself, and
    /// <c>ClassDefinition.Base</c> is a non-virtual auto-property. It is a defensive guard, kept for the never-throws
    /// contract, and is left untested on purpose.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("ContainingType")]
    [InlineData("GenericParameterCount")]
    [InlineData("None")]
    public void IsOpen_OverABaseWhoseIdentityCannotBeRead_IsOpen(string throwsOn)
    {
        var (assembly, space) = NewAssembly();
        Class(space, "Over", new ThrowingBasicType(ObjectRef)
        {
            ThrowOnContainingType = throwsOn == "ContainingType",
            ThrowOnGenericParameterCount = throwsOn == "GenericParameterCount",
        });
        Class(space, "Under", Own("Over"));

        var index = WithinDeadline(() => MemberIndex.Build([(assembly, TypeForwarders.None)]));

        Assert.Equal(throwsOn != "None", index.IsOpen(Id("Over")));
        Assert.Equal(throwsOn != "None", index.IsOpen(Id("Under")));
        Assert.Equal(0, index.Coverage.TypesSkipped);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static (Model.Assembly Assembly, Model.Namespace Space) NewAssembly()
    {
        var assembly = new Model.Assembly(Syn);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace(Syn) { ContainingAssembly = assembly, ContainingNamespace = root };
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

    // A reference to the own class Syn.{name}.
    private static ModelTypes.BasicType Own(string name) => SyntheticModel.TypeRef(Syn, name, assembly: Syn);

    private static string Id(string nameWithoutNamespace) => $"{Syn}.{nameWithoutNamespace}";

    // Runs an index build over hostile metadata on a worker with a deadline, so a non-terminating walk fails the test.
    private static T WithinDeadline<T>(Func<T> build)
    {
        var task = Task.Run(build);
        Assert.True(task.Wait(TimeSpan.FromSeconds(60)), "the index build did not finish within 60 s");
        return task.Result;
    }
    #endregion

    #region Fields
    private const string Syn = "Syn";
    private const string CoreLib = "System.Private.CoreLib";

    private static ModelTypes.BasicType ObjectRef => SyntheticModel.TypeRef("System", "Object", assembly: CoreLib);

    private static ModelTypes.BasicType StreamRef => SyntheticModel.TypeRef("System.IO", "Stream", assembly: CoreLib);

    private static ThrowingBasicType UnreadableObjectRef => new(ObjectRef) { ThrowOnContainingType = true };
    #endregion
}
