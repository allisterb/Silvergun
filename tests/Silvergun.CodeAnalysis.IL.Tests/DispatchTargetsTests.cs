namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="MemberIndex.DispatchTargets"/> — CHA for one call site (A2 S1, docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md
/// §2 and "S1 outcome") — over an EMITTED assembly (<see cref="DispatchShapesFixture"/>) whose every call site is
/// written by hand, so each shape is exactly the one named: which sites dispatch at all, <c>ldvirtftn</c>, the
/// implemented-name rule, parameter narrowing below an own class only, open types, and a struct reached from
/// <c>System.Object</c>. The C# shapes (an explicit generic implementation) come from the mechanism fixture.
/// </summary>
public sealed class DispatchTargetsTests : IClassFixture<DispatchShapesFixture>, IClassFixture<MechanismMethodGraphFixture>
{
    #region Constructors
    public DispatchTargetsTests(DispatchShapesFixture shapes, MechanismMethodGraphFixture mechanism)
    {
        this.shapes = shapes;
        this.mechanism = mechanism;
    }
    #endregion

    #region Methods
    // ---- which sites dispatch ---------------------------------------------------------------------------------------

    /// <summary>
    /// C# emits <c>callvirt</c> for an instance call on a receiver that may be null, but a target that is neither
    /// virtual nor abstract runs as named: no dispatch (null, not empty). Checked on the emitted
    /// <c>callvirt Base::Plain</c>, and on EVERY such site of the mechanism fixture (measured: one,
    /// <c>Opacity.Dynamic.CallsStatically</c>'s <c>target.Run()</c> — Roslyn emits a plain <c>call</c> for
    /// <c>new Box&lt;int&gt;().Run()</c>, whose receiver cannot be null).
    /// </summary>
    [Fact]
    public void DispatchTargets_ACallvirtToANonVirtualOwnDefinition_IsNull()
    {
        var site = shapes.Site("CallsPlain");
        Assert.Equal(MethodEdgeKind.CallVirt, site.Kind);
        Assert.False(shapes.Index.Resolve(site.Target).Definition!.IsVirtual);

        Assert.Null(site.DispatchTargets(shapes.Index));

        var nonVirtual = mechanism.Sites.Where(s => s.Kind == MethodEdgeKind.CallVirt &&
            mechanism.Index.Resolve(s.Target).Definition is { IsVirtual: false, IsAbstract: false }).ToArray();
        Assert.Contains(nonVirtual, s => s.Caller.NodeId == "MechanismFixture.Opacity.Dynamic.CallsStatically(MechanismFixture.Opacity.Runner)");
        Assert.All(nonVirtual, s => Assert.Null(s.DispatchTargets(mechanism.Index)));
    }

    /// <summary><c>call Base::Run</c> (C#'s <c>base.Run()</c>): a non-virtual site to an instance method never dispatches, virtual target or not.</summary>
    [Fact]
    public void DispatchTargets_ANonVirtualSiteToAnInstanceMethod_IsNull()
    {
        var site = shapes.Site("BaseCallsRun");
        Assert.Equal(MethodEdgeKind.Call, site.Kind);
        Assert.True(shapes.Index.Resolve(site.Target).Definition!.IsVirtual);

        Assert.Null(site.DispatchTargets(shapes.Index));
        Assert.NotEmpty(shapes.Site("CallsRun").DispatchTargets(shapes.Index)!);   // the same target through callvirt does
    }

    /// <summary>A <c>call</c> to a static own method that is not abstract (an ordinary helper) is null.</summary>
    [Fact]
    public void DispatchTargets_AStaticNonVirtualOwnMethod_IsNull()
    {
        var site = shapes.Site("CallsHelper");
        Assert.True(site.Target.IsStatic);

        Assert.Null(site.DispatchTargets(shapes.Index));
        Assert.Null(mechanism.SitesIn("MechanismFixture.Transitive.Chain.Outer()", "MechanismFixture.Transitive.Chain.Middle()").Single().DispatchTargets(mechanism.Index));
    }

    /// <summary>
    /// <c>ldvirtftn Base::Run</c> fans out exactly like <c>callvirt Base::Run</c>, and in the graph its Dispatch edges sit
    /// at the ldvirtftn's own offset, beside its <see cref="MethodEdgeKind.Ldvirtftn"/> edge.
    /// </summary>
    [Fact]
    public void DispatchTargets_Ldvirtftn_FansOutLikeCallvirt()
    {
        var load = shapes.Site("LoadsRun");
        Assert.Equal(MethodEdgeKind.Ldvirtftn, load.Kind);

        var targets = load.DispatchTargets(shapes.Index);

        Assert.Equal([Shapes("Derived.Run()")], targets);
        Assert.Equal(shapes.Site("CallsRun").DispatchTargets(shapes.Index), targets);
        Assert.Equal(
            [new MethodEdge(load.Caller.NodeId, Shapes("Base.Run()"), MethodEdgeKind.Ldvirtftn, load.Offset),
             new MethodEdge(load.Caller.NodeId, Shapes("Derived.Run()"), MethodEdgeKind.Dispatch, load.Offset)],
            shapes.Graph.Successors(load.Caller.NodeId));
    }

    // ---- the implemented name ---------------------------------------------------------------------------------------

    /// <summary>
    /// A C# explicit implementation of a GENERIC interface member: the iterators' <c>get_Current</c> is named
    /// <c>System.Collections.Generic.IEnumerator&lt;System.String&gt;.get_Current</c> (a dot inside the brackets), and
    /// the consumer's <c>callvirt IEnumerator&lt;string&gt;::get_Current</c> reaches both iterators' by that name's last
    /// segment. The rule matches the last segment only (spec §2), so each iterator's NON-generic explicit
    /// <c>System.Collections.IEnumerator.get_Current</c> — another interface's slot — is reached too: measured
    /// over-matching, precision only. Nothing else is: the targets are exactly the iterators' methods whose name is or
    /// ends in <c>.get_Current</c>, read from the index.
    /// </summary>
    [Fact]
    public void DispatchTargets_MatchesAGenericExplicitImplementation_ByItsLastSegment()
    {
        const string genericName = "System.Collections.Generic.IEnumerator<System.String>.get_Current";
        const string nonGenericName = "System.Collections.IEnumerator.get_Current";
        var consumer = "MechanismFixture.Iterator.Consumers.Consumes(System.Collections.Generic.IEnumerable`1<System.String>)";
        var site = Assert.Single(mechanism.Sites, s => s.Caller.NodeId == consumer && ModelNames.Of(s.Target).MethodName == "get_Current");
        var iterators = mechanism.Index.DirectSubtypes("System.Collections.Generic.IEnumerator`1");
        var getCurrent = mechanism.Index.Methods
            .Where(m => iterators.Contains(m.DeclaringTypeId) && (m.Definition.Name == "get_Current" || m.Definition.Name.EndsWith(".get_Current", StringComparison.Ordinal)))
            .ToArray();
        Assert.Equal(2, getCurrent.Count(m => m.Definition.Name == genericName));
        Assert.Equal(2, getCurrent.Count(m => m.Definition.Name == nonGenericName));

        var targets = site.DispatchTargets(mechanism.Index);

        Assert.Equal(getCurrent.Select(m => m.NodeId).Order(StringComparer.Ordinal), targets);
        Assert.All(getCurrent.Where(m => m.Definition.Name == genericName), m =>
            Assert.Contains(new MethodEdge(consumer, m.NodeId, MethodEdgeKind.Dispatch, site.Offset), mechanism.Graph.Edges));
    }

    /// <summary>
    /// The leading dot of <c>.cctor</c> is not a segment separator: a static call to <c>IStatic::cctor()</c> (a static
    /// abstract member really named <c>cctor</c>) reaches the implementor's <c>cctor()</c> and NOT its type initializer
    /// <c>.cctor()</c>, which would be the answer if the name were split at its leading dot.
    /// </summary>
    [Fact]
    public void DispatchTargets_DoesNotSplitTheLeadingDotOfATypeInitializer()
    {
        Assert.True(shapes.Index.IsOwnMethod(Shapes("StaticImpl..cctor()")));

        Assert.Equal([Shapes("StaticImpl.cctor()")], shapes.Site("BuildsCctor").DispatchTargets(shapes.Index));
    }

    // ---- the static rule (constrained. call to a static abstract member) ---------------------------------------------

    /// <summary>
    /// <c>constrained. !!T call IStatic::Make()</c> — Model drops the prefix and shows a plain static call — reaches the
    /// implementor's static <c>Make</c> (no other static member, and no instance method).
    /// </summary>
    [Fact]
    public void DispatchTargets_AStaticCallToAStaticAbstractMember_ReachesTheStaticImplementations()
    {
        var site = shapes.Site("BuildsMake");
        Assert.Equal(MethodEdgeKind.Call, site.Kind);

        Assert.Equal([Shapes("StaticImpl.Make()")], site.DispatchTargets(shapes.Index));
    }

    // ---- parameter narrowing ----------------------------------------------------------------------------------------

    /// <summary>
    /// Below an own CLASS, parameter types narrow the match (S1 outcome): <c>Base.M(int)</c> and <c>Base.M(string)</c>
    /// are both overridden in <c>Derived</c>, and each call reaches only the override of its own overload.
    /// </summary>
    [Theory]
    [InlineData("CallsMInt", "Derived.M(System.Int32)")]
    [InlineData("CallsMString", "Derived.M(System.String)")]
    public void DispatchTargets_BelowAnOwnClass_AConcreteParameterMismatchIsExcluded(string caller, string only) =>
        Assert.Equal([Shapes(only)], shapes.Site(caller).DispatchTargets(shapes.Index));

    /// <summary>
    /// Below an own INTERFACE, never narrowed (variance makes exact matching unsound there): <c>IOver.M(int)</c> reaches
    /// both of OverImpl's same-arity overloads.
    /// </summary>
    [Fact]
    public void DispatchTargets_BelowAnInterface_IsNotNarrowedByParameterTypes() =>
        Assert.Equal([Shapes("OverImpl.M(System.Int32)"), Shapes("OverImpl.M(System.String)")], shapes.Site("CallsOverInt").DispatchTargets(shapes.Index));

    /// <summary>
    /// A position holding a generic parameter matches anything, on either side. Through <c>GBase&lt;string&gt;</c>
    /// (declared <c>M(System.String)</c>): <c>GenDerived&lt;U&gt;.M(!0)</c> is kept, <c>IntDerived.M(System.Int32)</c> —
    /// concrete, and not string — is excluded. From inside <c>GBase&lt;T&gt;</c> (declared <c>M(!0)</c>): both are kept.
    /// </summary>
    [Theory]
    [InlineData("CallsGString", new[] { "GenDerived`1.M(!0)" })]
    [InlineData("GBase`1.CallsSelf", new[] { "GenDerived`1.M(!0)", "IntDerived.M(System.Int32)" })]
    public void DispatchTargets_AGenericParameterPositionMatchesAnything(string caller, string[] expected) =>
        Assert.Equal(expected.Select(Shapes), shapes.Site(caller).DispatchTargets(shapes.Index));

    /// <summary>
    /// The memo is keyed on the parameter types: answering <c>M(int)</c> first must not leak into <c>M(string)</c> or the
    /// other way round — each order on a FRESH index.
    /// </summary>
    [Theory]
    [InlineData("CallsMInt", "CallsMString")]
    [InlineData("CallsMString", "CallsMInt")]
    public void DispatchTargets_Memo_DoesNotLeakAcrossParameterTypes(string first, string second)
    {
        using var loaded = ModelAssemblies.Load(shapes.Path);
        var index = loaded.Index();
        var sites = ModelCallSite.All(index);
        IReadOnlyList<string>? Ask(string caller) => sites.Single(s => s.Caller.NodeId.StartsWith(Shapes($"Callers.{caller}("), StringComparison.Ordinal)).DispatchTargets(index);

        var answers = new Dictionary<string, IReadOnlyList<string>?> { [first] = Ask(first), [second] = Ask(second) };

        Assert.Equal([Shapes("Derived.M(System.Int32)")], answers["CallsMInt"]);
        Assert.Equal([Shapes("Derived.M(System.String)")], answers["CallsMString"]);
    }

    /// <summary>
    /// The memo is keyed on the static flag too: the same declared method asked as a static site (the static rule) and
    /// as an instance virtual site gives two different answers, in either order on a fresh index. The instance query is
    /// a hand-built reference to the same <c>Shapes.IStatic.Make()</c>, flagged instance.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DispatchTargets_Memo_DoesNotLeakAcrossTheStaticFlag(bool staticFirst)
    {
        using var loaded = ModelAssemblies.Load(shapes.Path);
        var index = loaded.Index();
        var asStatic = ModelCallSite.All(index).Single(s => s.Caller.NodeId.StartsWith(Shapes("Callers.BuildsMake`1("), StringComparison.Ordinal)).Target;
        var asInstance = SyntheticModel.Method(SyntheticModel.TypeRef("Shapes", "IStatic", assembly: DispatchShapesFixture.Name), "Make");
        Assert.True(asStatic.IsStatic);
        Assert.False(asInstance.IsStatic);
        IReadOnlyList<string>? Static() => index.DispatchTargets(asStatic, index.Resolve(asStatic), virtualSite: false);
        IReadOnlyList<string>? Instance() => index.DispatchTargets(asInstance, index.Resolve(asInstance), virtualSite: true);

        IReadOnlyList<string>? staticAnswer, instanceAnswer;
        if (staticFirst)
        {
            staticAnswer = Static();
            instanceAnswer = Instance();
        }
        else
        {
            instanceAnswer = Instance();
            staticAnswer = Static();
        }

        Assert.Equal([Shapes("StaticImpl.Make()")], staticAnswer);
        Assert.NotNull(instanceAnswer);
        Assert.Empty(instanceAnswer);
    }

    // ---- System.Object, structs and open types ---------------------------------------------------------------------

    /// <summary>
    /// Model gives a struct no base; the index adds the implicit <c>System.ValueType</c>, and the closure links
    /// <c>System.Object</c> to it — so <c>callvirt Object::ToString</c> (on a boxed struct, or on any object) reaches
    /// the struct's override.
    /// </summary>
    [Theory]
    [InlineData("CallsToString")]
    [InlineData("CallsPointToString")]
    public void DispatchTargets_FromObjectToString_ReachesAStructOverride(string caller)
    {
        Assert.Equal(["System.ValueType"], Assert.Single(shapes.Index.Types(Shapes("Point"))).Supertypes);

        Assert.Equal([Shapes("Point.ToString()")], shapes.Site(caller).DispatchTargets(shapes.Index));
    }

    /// <summary>
    /// <see cref="MemberIndex.IsOpen"/>: an own class whose base chain leaves the index at a platform class other than
    /// the closed roots (<c>MemoryStream</c>) is open, and so is its own subclass; a class deriving from
    /// <c>System.Object</c>, its own subclass, a struct and an interface are not.
    /// </summary>
    [Theory]
    [InlineData("OpenThing", true)]
    [InlineData("OpenChild", true)]
    [InlineData("Closed", false)]
    [InlineData("ClosedChild", false)]
    [InlineData("Base", false)]
    [InlineData("Point", false)]
    [InlineData("IOver", false)]
    public void IsOpen_IsTrueOnlyBelowANonRootPlatformClass(string type, bool open) =>
        Assert.Equal(open, shapes.Index.IsOpen(Shapes(type)));

    /// <summary>
    /// D2: a call through an EXTERNAL declared type (<c>Stream.Flush</c>) reaches the open type's override, which no
    /// subtype-map key links to <c>Stream</c>.
    /// </summary>
    [Fact]
    public void DispatchTargets_FromAnExternalDeclaredType_ReachesOpenTypes()
    {
        Assert.Empty(shapes.Index.DirectSubtypes("System.IO.Stream"));

        Assert.Equal([Shapes("OpenThing.Flush()")], shapes.Site("CallsStreamFlush").DispatchTargets(shapes.Index));
    }

    /// <summary>An OWN declared type never adds the open types: <c>Closed.Flush</c> reaches only its own subclass's override.</summary>
    [Fact]
    public void DispatchTargets_FromAnOwnDeclaredType_NeverAddsOpenTypes() =>
        Assert.Equal([Shapes("ClosedChild.Flush()")], shapes.Site("CallsClosedFlush").DispatchTargets(shapes.Index));

    /// <summary>
    /// <c>call Int32::Parse(string)</c> — static, into a platform type nothing own derives from — is a plain call since
    /// S1b (review W4): null, so it cannot reach the open type's same-shaped static <c>Parse(string)</c>. (S1's version of
    /// this test, "a static site never adds open types", was vacuous here: this site never dispatched at all. The
    /// non-vacuous one, through an external interface that own types DO implement, is
    /// <see cref="DispatchReviewFixesTests.DispatchTargets_AStaticCallThroughAnExternalInterface_ReachesImplementorsButNeverAddsOpenTypes"/>.)
    /// </summary>
    [Fact]
    public void DispatchTargets_AStaticCallIntoAPlatformTypeWithNoOwnSubtypes_IsNull()
    {
        Assert.True(shapes.Index.IsOwnMethod(Shapes("OpenThing.Parse(System.String)")));

        Assert.Null(shapes.Site("CallsParse").DispatchTargets(shapes.Index));
    }

    // ---- determinism ------------------------------------------------------------------------------------------------

    /// <summary>
    /// Two builds over fresh loads of the mechanism fixture — the second in REVERSED assembly order — give the identical
    /// Dispatch edge sequence and coverage, and it is not empty.
    /// </summary>
    [Fact]
    public void Build_TwiceOverFreshLoads_GivesIdenticalDispatchEdges()
    {
        using var forward = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency);
        using var reversed = ModelAssemblies.Load(MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.Fixture);

        var first = MethodGraph.Build(forward.Index());
        var second = MethodGraph.Build(reversed.Index());

        var dispatch = first.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch).ToArray();
        Assert.NotEmpty(dispatch);
        Assert.Equal(dispatch, second.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch));
        Assert.Equal(dispatch, mechanism.Graph.Edges.Where(e => e.Kind == MethodEdgeKind.Dispatch));
        Assert.Equal(first.Coverage, second.Coverage);
    }

    private static string Shapes(string nodeIdWithoutNamespace) => $"Shapes.{nodeIdWithoutNamespace}";
    #endregion

    #region Fields
    private readonly DispatchShapesFixture shapes;
    private readonly MechanismMethodGraphFixture mechanism;
    #endregion
}

/// <summary>
/// One emitted assembly, <c>ChaShapes</c> (<see cref="EmittedAssembly"/>; never loaded or run), holding the dispatch
/// shapes of <see cref="DispatchTargetsTests"/>, all in namespace <c>Shapes</c>:
/// <list type="bullet">
/// <item><description><c>Base</c> (virtual <c>Run()</c>, <c>M(int)</c>, <c>M(string)</c>; non-virtual <c>Plain()</c>; static
/// <c>Helper()</c>) and <c>Derived : Base</c> overriding the three virtuals;</description></item>
/// <item><description><c>IOver</c> (<c>M(int)</c>, <c>M(string)</c>) and <c>OverImpl : IOver</c>;</description></item>
/// <item><description><c>GBase&lt;T&gt;</c> (virtual <c>M(T)</c>, and <c>CallsSelf(T)</c> calling it through
/// <c>GBase&lt;T&gt;</c>), <c>IntDerived : GBase&lt;int&gt;</c>, <c>GenDerived&lt;U&gt; : GBase&lt;U&gt;</c>;</description></item>
/// <item><description>struct <c>Point</c> overriding <c>ToString</c>;</description></item>
/// <item><description><c>IStatic</c> (static abstract <c>Make()</c> and <c>cctor()</c>) and <c>StaticImpl : IStatic</c>,
/// which also has a type initializer <c>.cctor</c>;</description></item>
/// <item><description><c>OpenThing : System.IO.MemoryStream</c> (override <c>Flush()</c>, static <c>Parse(string)</c>),
/// <c>OpenChild : OpenThing</c>, and the closed <c>Closed</c> / <c>ClosedChild : Closed</c> with <c>Flush()</c>;</description></item>
/// <item><description><c>Callers</c>: one static method per site, each with exactly one call-site instruction.</description></item>
/// </list>
/// </summary>
public sealed class DispatchShapesFixture : IDisposable
{
    #region Constructors
    public DispatchShapesFixture()
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
    /// <summary>The single call site of the caller whose node id starts with <c>Shapes.Callers.{caller}(</c> (or <c>Shapes.{caller}(</c> when qualified).</summary>
    public ModelCallSite Site(string caller)
    {
        var prefix = caller.Contains('.', StringComparison.Ordinal) ? $"Shapes.{caller}(" : $"Shapes.Callers.{caller}(";
        return Assert.Single(Sites, s => s.Caller.NodeId.StartsWith(prefix, StringComparison.Ordinal) ||
                                         s.Caller.NodeId.StartsWith(prefix.Replace("(", "`1(", StringComparison.Ordinal), StringComparison.Ordinal));
    }

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        // Base / Derived: overloads and a non-virtual and a static member.
        var @base = module.DefineType("Shapes.Base", TypeAttributes.Public | TypeAttributes.Class);
        var run = Body(@base.DefineMethod("Run", NewVirtual, typeof(int), Type.EmptyTypes), 1);
        var mInt = Body(@base.DefineMethod("M", NewVirtual, typeof(int), [typeof(int)]), 1);
        var mString = Body(@base.DefineMethod("M", NewVirtual, typeof(int), [typeof(string)]), 1);
        var plain = Body(@base.DefineMethod("Plain", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(int), Type.EmptyTypes), 1);
        var helper = Body(@base.DefineMethod("Helper", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static, typeof(int), Type.EmptyTypes), 1);
        var derived = module.DefineType("Shapes.Derived", TypeAttributes.Public | TypeAttributes.Class, @base);
        Body(derived.DefineMethod("Run", Override, typeof(int), Type.EmptyTypes), 2);
        Body(derived.DefineMethod("M", Override, typeof(int), [typeof(int)]), 2);
        Body(derived.DefineMethod("M", Override, typeof(int), [typeof(string)]), 2);

        // An interface with the same overloads.
        var over = module.DefineType("Shapes.IOver", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
        var overInt = over.DefineMethod("M", InterfaceMember, typeof(int), [typeof(int)]);
        over.DefineMethod("M", InterfaceMember, typeof(int), [typeof(string)]);
        var overImpl = module.DefineType("Shapes.OverImpl", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [over]);
        Body(overImpl.DefineMethod("M", Implementation, typeof(int), [typeof(int)]), 3);
        Body(overImpl.DefineMethod("M", Implementation, typeof(int), [typeof(string)]), 3);

        // A generic base and two subclasses: one closed over int, one still generic.
        var gbase = module.DefineType("Shapes.GBase`1", TypeAttributes.Public | TypeAttributes.Class);
        var t = gbase.DefineGenericParameters("T")[0];
        var gm = Body(gbase.DefineMethod("M", NewVirtual, typeof(int), [t]), 4);
        var self = gbase.DefineMethod("CallsSelf", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(int), [t]).GetILGenerator();
        self.Emit(OpCodes.Ldarg_0);
        self.Emit(OpCodes.Ldarg_1);
        self.Emit(OpCodes.Callvirt, TypeBuilder.GetMethod(gbase.MakeGenericType(t), gm));
        self.Emit(OpCodes.Ret);
        var intDerived = module.DefineType("Shapes.IntDerived", TypeAttributes.Public | TypeAttributes.Class, gbase.MakeGenericType(typeof(int)));
        Body(intDerived.DefineMethod("M", Override, typeof(int), [typeof(int)]), 5);
        var genDerived = module.DefineType("Shapes.GenDerived`1", TypeAttributes.Public | TypeAttributes.Class);
        var u = genDerived.DefineGenericParameters("U")[0];
        genDerived.SetParent(gbase.MakeGenericType(u));
        Body(genDerived.DefineMethod("M", Override, typeof(int), [u]), 6);

        // A struct overriding ToString.
        var point = module.DefineType("Shapes.Point", TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout, typeof(ValueType));
        Body(point.DefineMethod("ToString", Override, typeof(string), Type.EmptyTypes), "POINT");

        // Static abstract members, one literally named "cctor", and an implementor that also has a type initializer.
        var istatic = module.DefineType("Shapes.IStatic", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
        var make = istatic.DefineMethod("Make", StaticAbstract, typeof(int), Type.EmptyTypes);
        var cctorNamed = istatic.DefineMethod("cctor", StaticAbstract, typeof(int), Type.EmptyTypes);
        var staticImpl = module.DefineType("Shapes.StaticImpl", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Sealed, typeof(object), [istatic]);
        staticImpl.DefineMethodOverride(Body(staticImpl.DefineMethod("Make", StaticMethod, typeof(int), Type.EmptyTypes), 7), make);
        staticImpl.DefineMethodOverride(Body(staticImpl.DefineMethod("cctor", StaticMethod, typeof(int), Type.EmptyTypes), 8), cctorNamed);
        staticImpl.DefineTypeInitializer().GetILGenerator().Emit(OpCodes.Ret);

        // Open and closed hierarchies.
        var openThing = module.DefineType("Shapes.OpenThing", TypeAttributes.Public | TypeAttributes.Class, typeof(MemoryStream));
        Body(openThing.DefineMethod("Flush", Override, typeof(void), Type.EmptyTypes), null);
        Body(openThing.DefineMethod("Parse", StaticMethod, typeof(int), [typeof(string)]), 9);
        var openChild = module.DefineType("Shapes.OpenChild", TypeAttributes.Public | TypeAttributes.Class, openThing);
        var closed = module.DefineType("Shapes.Closed", TypeAttributes.Public | TypeAttributes.Class);
        var closedFlush = Body(closed.DefineMethod("Flush", NewVirtual, typeof(void), Type.EmptyTypes), null);
        var closedChild = module.DefineType("Shapes.ClosedChild", TypeAttributes.Public | TypeAttributes.Class, closed);
        Body(closedChild.DefineMethod("Flush", Override, typeof(void), Type.EmptyTypes), null);

        // One caller per site.
        var callers = module.DefineType("Shapes.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(callers, "CallsRun", typeof(int), [@base], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, run); });
        Caller(callers, "LoadsRun", typeof(int), [@base], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldvirtftn, run); il.Emit(OpCodes.Pop); il.Emit(OpCodes.Ldc_I4_0); });
        Caller(callers, "BaseCallsRun", typeof(int), [@base], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Call, run); });
        Caller(callers, "CallsPlain", typeof(int), [@base], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, plain); });
        Caller(callers, "CallsHelper", typeof(int), [], il => il.Emit(OpCodes.Call, helper));
        Caller(callers, "CallsMInt", typeof(int), [@base], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Callvirt, mInt); });
        Caller(callers, "CallsMString", typeof(int), [@base], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Callvirt, mString); });
        Caller(callers, "CallsOverInt", typeof(int), [over], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Callvirt, overInt); });
        var gstring = gbase.MakeGenericType(typeof(string));
        Caller(callers, "CallsGString", typeof(int), [gstring], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Callvirt, TypeBuilder.GetMethod(gstring, gm)); });
        var objectToString = typeof(object).GetMethod(nameof(ToString), Type.EmptyTypes)!;
        Caller(callers, "CallsToString", typeof(string), [typeof(object)], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, objectToString); });
        Caller(callers, "CallsPointToString", typeof(string), [], il =>
        {
            il.DeclareLocal(point);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Box, point);
            il.Emit(OpCodes.Callvirt, objectToString);
        });
        Caller(callers, "CallsStreamFlush", typeof(void), [typeof(Stream)], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, typeof(Stream).GetMethod(nameof(Stream.Flush), Type.EmptyTypes)!); });
        Caller(callers, "CallsClosedFlush", typeof(void), [closed], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, closedFlush); });
        Caller(callers, "CallsParse", typeof(int), [], il => { il.Emit(OpCodes.Ldstr, "1"); il.Emit(OpCodes.Call, typeof(int).GetMethod(nameof(int.Parse), [typeof(string)])!); });
        ConstrainedCaller(callers, "BuildsMake", istatic, make);
        ConstrainedCaller(callers, "BuildsCctor", istatic, cctorNamed);

        foreach (var type in new[] { @base, derived, over, overImpl, gbase, intDerived, genDerived, point, istatic, staticImpl, openThing, openChild, closed, closedChild, callers })
            type.CreateType();
    }

    // A public static method of the callers class: `emit` then ret.
    private static void Caller(TypeBuilder callers, string name, Type returns, Type[] parameters, Action<ILGenerator> emit)
    {
        var il = callers.DefineMethod(name, StaticMethod, returns, parameters).GetILGenerator();
        emit(il);
        il.Emit(OpCodes.Ret);
    }

    // static int name<T>() where T : constraint => constrained. !!T call target; ret
    private static void ConstrainedCaller(TypeBuilder callers, string name, Type constraint, MethodInfo target)
    {
        var method = callers.DefineMethod(name, StaticMethod, typeof(int), Type.EmptyTypes);
        var t = method.DefineGenericParameters("T")[0];
        t.SetInterfaceConstraints(constraint);
        var il = method.GetILGenerator();
        il.Emit(OpCodes.Constrained, t);
        il.Emit(OpCodes.Call, target);
        il.Emit(OpCodes.Ret);
    }

    // A body returning the constant `value` (an int, a string, or nothing for void).
    private static MethodBuilder Body(MethodBuilder method, object? value)
    {
        var il = method.GetILGenerator();
        switch (value)
        {
            case int number:
                il.Emit(OpCodes.Ldc_I4, number);
                break;
            case string text:
                il.Emit(OpCodes.Ldstr, text);
                break;
        }
        il.Emit(OpCodes.Ret);
        return method;
    }
    #endregion

    #region Fields
    /// <summary>The emitted assembly's name.</summary>
    public const string Name = "ChaShapes";

    private const MethodAttributes NewVirtual = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot;
    private const MethodAttributes Override = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual;
    private const MethodAttributes InterfaceMember = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.Abstract | MethodAttributes.NewSlot;
    private const MethodAttributes Implementation = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final;
    private const MethodAttributes StaticAbstract = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static | MethodAttributes.Abstract | MethodAttributes.Virtual;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Static;

    private readonly EmittedAssembly emitted;
    #endregion
}
