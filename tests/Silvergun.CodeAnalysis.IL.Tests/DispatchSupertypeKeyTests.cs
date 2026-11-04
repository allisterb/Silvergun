namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The forwarder-aware type key behind CHA (A2 spec §1): an own type's supertypes and a call site's declared type are
/// keyed by the SAME walk over type forwarders, so the subtype map and the site agree on where the CLR lands the type.
/// Every assembly is EMITTED (<see cref="DispatchForwarderFixture"/>) and the CLR is the oracle for where an
/// implementor's interface really lands (an <see cref="IsolatedLoadContext"/>, as in <see cref="TypeForwarderResolutionTests"/>).
/// </summary>
public sealed class DispatchSupertypeKeyTests : IClassFixture<DispatchForwarderFixture>
{
    #region Constructors
    public DispatchSupertypeKeyTests(DispatchForwarderFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- a forward into another INDEXED assembly ----------------------------------------------------------------

    /// <summary>
    /// The oracle: <c>ChaC</c>'s <c>NS.Impl</c> implements <c>[ChaA]NS.IProbe</c>, and <c>ChaA</c> forwards it to
    /// <c>ChaB</c> — so the CLR lands the interface in <c>ChaB</c>.
    /// </summary>
    [Fact]
    public void Runtime_TheImplementorsInterface_LandsInTheForwardTarget() =>
        Assert.Equal("ChaB", InterfaceAssembly(new() { ["ChaA"] = fixture.ForwardsToB, ["ChaB"] = fixture.B }));

    /// <summary>
    /// The index follows the same forwarder: Impl's supertype key is <c>NS.IProbe</c> (ChaB's definition) and nothing is
    /// unresolved; a <c>callvirt [ChaB]NS.IProbe::Run</c> site (in <c>ChaD</c>) and the <c>callvirt [ChaA]NS.IProbe::Run</c>
    /// site in <c>ChaC</c> both fan out to <c>NS.Impl.Run()</c>, in the graph as Dispatch edges.
    /// </summary>
    [Fact]
    public void DispatchTargets_ThroughTheForwardTarget_ReachTheImplementorNamedThroughTheForwarder()
    {
        using var loaded = ModelAssemblies.Load(fixture.ForwardsToB, fixture.B, fixture.C, fixture.D);
        var index = loaded.Index();
        var graph = MethodGraph.Build(index);

        Assert.Equal(["NS.IProbe", "System.Object"], Assert.Single(index.Types(Impl)).Supertypes);
        Assert.Equal([Impl], index.DirectSubtypes("NS.IProbe"));
        Assert.True(index.Coverage.IsComplete, index.Coverage.ToString());

        foreach (var caller in new[] { CallerIn("D"), CallerIn("C") })
        {
            var site = Site(index, caller);
            Assert.Equal([ImplRun], site.DispatchTargets(index));
            Assert.Contains(new MethodEdge(caller, ImplRun, MethodEdgeKind.Dispatch, site.Offset), graph.Edges);
        }
        Assert.Equal("ChaB", index.Resolve(Site(index, CallerIn("C")).Target).Assembly);
    }

    /// <summary>
    /// The same inputs, but <c>ChaA</c>'s forwarders unreadable: where Impl's interface lands is unknown, so the
    /// supertype is counted in <see cref="IndexCoverage.SupertypesUnresolved"/> (the index is incomplete) and kept under
    /// its bare id — CHA over-approximates rather than loses the implementor.
    /// </summary>
    [Fact]
    public void DispatchTargets_WithTheForwarderUnreadable_CountsTheSupertype_AndStillReachesTheImplementor()
    {
        using var loaded = ModelAssemblies.Load(fixture.ForwardsToB, fixture.B, fixture.C, fixture.D);
        var (a, b, c, d) = (loaded.Disassemblers[0], loaded.Disassemblers[1], loaded.Disassemblers[2], loaded.Disassemblers[3]);
        var index = MemberIndex.Build([(a.Assembly, TypeForwarders.Unreadable), (b.Assembly, b.Forwarders), (c.Assembly, c.Forwarders), (d.Assembly, d.Forwarders)]);

        Assert.Equal(new IndexCoverage(0, 0, 0, ForwardersUnreadable: 1, SupertypesUnresolved: 1), index.Coverage);
        Assert.False(index.Coverage.IsComplete);
        Assert.Contains("NS.IProbe", Assert.Single(index.Types(Impl)).Supertypes);
        Assert.Equal([ImplRun], Site(index, CallerIn("D")).DispatchTargets(index));
    }

    // ---- a forward to an UNINDEXED assembly, with a same-named decoy ------------------------------------------------

    /// <summary>
    /// The oracle: <c>ChaA</c> DEFINES a decoy <c>NS.IProbe</c> and forwards the name to <c>ChaU</c> — the CLR follows
    /// the forwarder, so Impl's interface lands in <c>ChaU</c>, not on the decoy.
    /// </summary>
    [Fact]
    public void Runtime_WithADecoyAndAForwarder_TheImplementorsInterface_LandsInTheForwardTarget() =>
        Assert.Equal("ChaU", InterfaceAssembly(new() { ["ChaA"] = fixture.DecoyForwardsToU, ["ChaU"] = fixture.U }));

    /// <summary>
    /// With <c>ChaU</c> NOT indexed, the walk from <c>ChaA</c> finds two places: the own decoy (bare <c>NS.IProbe</c>)
    /// and ChaU's type, kept under a qualified key because an own type shares its id. Impl is a subtype of BOTH
    /// (over-approximation, the CLR's answer included), so a call through either reaches it: through ChaU (<c>ChaE</c>'s
    /// site, External) and through ChaA (<c>ChaC</c>'s site, Ambiguous over the decoy and ChaU).
    /// <para>
    /// Since A2Multi S2 the qualified subtype-map key of a shadowed EXTERNAL type is <c>[*]NS.IProbe</c> — one key for
    /// every unindexed assembly, so the spellings <c>[netstandard]X</c> and <c>[System.Runtime]X</c> join — instead of
    /// <c>[ChaU]NS.IProbe</c> per referencing spelling (cha-a2multi-package-graphs.md, S2 "Qualified spelling"). The key
    /// changes; the subtype links, the resolutions and the dispatch answers this test pins do not.
    /// </para>
    /// </summary>
    [Fact]
    public void DispatchTargets_WithADecoyAndAForwardToAnUnindexedAssembly_ReachTheImplementorThroughEither()
    {
        using var loaded = ModelAssemblies.Load(fixture.DecoyForwardsToU, fixture.C, fixture.E);
        var index = loaded.Index();
        var qualified = MemberIndex.Qualified("*", "NS.IProbe");
        Assert.Empty(index.DirectSubtypes(MemberIndex.Qualified("ChaU", "NS.IProbe")));

        Assert.Equal(new[] { "NS.IProbe", "System.Object", qualified }.Order(StringComparer.Ordinal), Assert.Single(index.Types(Impl)).Supertypes);
        Assert.Equal([Impl], index.DirectSubtypes("NS.IProbe"));
        Assert.Equal([Impl], index.DirectSubtypes(qualified));
        Assert.True(index.Coverage.IsComplete, index.Coverage.ToString());

        var throughU = Site(index, CallerIn("E"));
        var throughA = Site(index, CallerIn("C"));
        Assert.Equal(ResolutionKind.External, index.Resolve(throughU.Target).Kind);
        Assert.Equal(ResolutionKind.Ambiguous, index.Resolve(throughA.Target).Kind);
        Assert.Equal([ImplRun], throughU.DispatchTargets(index));
        Assert.Equal([ImplRun], throughA.DispatchTargets(index));
    }

    private static ModelCallSite Site(MemberIndex index, string caller) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == caller && s.Kind == MethodEdgeKind.CallVirt);

    private static string CallerIn(string assembly) => $"NS.{assembly}Callers.CallsRun(NS.IProbe)";

    // The assembly the CLR loads Impl's one interface from, with each named assembly pinned to the given file.
    private string? InterfaceAssembly(System.Collections.Generic.Dictionary<string, string> pinned)
    {
        using var context = new IsolatedLoadContext(pinned);
        var impl = context.LoadBytes(fixture.C).GetType(Impl, throwOnError: true)!;
        return Assert.Single(impl.GetInterfaces()).Assembly.GetName().Name;
    }
    #endregion

    #region Fields
    private const string Impl = "NS.Impl";
    private const string ImplRun = "NS.Impl.Run()";

    private readonly DispatchForwarderFixture fixture;
    #endregion
}

/// <summary>
/// The emitted assemblies of <see cref="DispatchSupertypeKeyTests"/>, each in its own subdirectory of one
/// <see cref="EmittedAssembly"/> (variants share the name <c>ChaA</c>). Each defines or names <c>NS.IProbe</c>, an
/// interface with <c>int Run()</c>:
/// <list type="bullet">
/// <item><description><c>ChaA</c> stub — defines <c>NS.IProbe</c>; only ever used to emit <see cref="C"/> against.</description></item>
/// <item><description><see cref="C"/> — <c>ChaC</c>: <c>NS.Impl : [ChaA]NS.IProbe</c> and <c>NS.CCallers.CallsRun(IProbe)</c>.</description></item>
/// <item><description><see cref="B"/> — <c>ChaB</c> defines <c>NS.IProbe</c>; <see cref="ForwardsToB"/> — <c>ChaA</c> forwards it there.</description></item>
/// <item><description><see cref="D"/> — <c>ChaD</c>: <c>NS.DCallers.CallsRun</c> through <c>[ChaB]NS.IProbe</c>.</description></item>
/// <item><description><see cref="U"/> — <c>ChaU</c> defines <c>NS.IProbe</c> (never indexed); <see cref="DecoyForwardsToU"/> —
/// <c>ChaA</c> defines a decoy <c>NS.IProbe</c> AND forwards the name to ChaU.</description></item>
/// <item><description><see cref="E"/> — <c>ChaE</c>: <c>NS.ECallers.CallsRun</c> through <c>[ChaU]NS.IProbe</c>.</description></item>
/// </list>
/// </summary>
public sealed class DispatchForwarderFixture : IDisposable
{
    #region Constructors
    public DispatchForwarderFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            var stub = emitted.Save("ChaA", Probe, "stub");
            C = EmitAgainst(stub, "ChaC", "stub", (module, probe) => { Implementor(module, probe); Callers(module, "C", probe); });
            B = emitted.Save("ChaB", Probe, "b");
            ForwardsToB = emitted.Save("ChaA", module => Marker(module, "FwdB"), EmittedAssembly.Forwarding(("NS", "IProbe", "ChaB")), "fwdb");
            D = EmitAgainst(B, "ChaD", "d", (module, probe) => Callers(module, "D", probe));
            U = emitted.Save("ChaU", Probe, "u");
            DecoyForwardsToU = emitted.Save("ChaA", Probe, EmittedAssembly.Forwarding(("NS", "IProbe", "ChaU")), "decoyu");
            E = EmitAgainst(U, "ChaE", "e", (module, probe) => Callers(module, "E", probe));
        }
        catch (Exception)
        {
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string C { get; }

    public string B { get; }

    public string ForwardsToB { get; }

    public string D { get; }

    public string U { get; }

    public string DecoyForwardsToU { get; }

    public string E { get; }
    #endregion

    #region Methods
    public void Dispose() => emitted.Dispose();

    // Emits `name`, naming NS.IProbe by token from the assembly at `against` - loaded from bytes into a collectible
    // context, so the default context never sees it.
    private string EmitAgainst(string against, string name, string subdirectory, Action<ModuleBuilder, Type> define)
    {
        using var context = new IsolatedLoadContext();
        var probe = context.LoadBytes(against).GetType("NS.IProbe", throwOnError: true)!;
        return emitted.Save(name, module => define(module, probe), subdirectory);
    }

    private static void Probe(ModuleBuilder module)
    {
        var probe = module.DefineType("NS.IProbe", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
        probe.DefineMethod("Run", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.Abstract | MethodAttributes.NewSlot,
            typeof(int), Type.EmptyTypes);
        probe.CreateType();
    }

    private static void Implementor(ModuleBuilder module, Type probe)
    {
        var impl = module.DefineType("NS.Impl", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [probe]);
        impl.DefineDefaultConstructor(MethodAttributes.Public);
        var il = impl.DefineMethod("Run", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final,
            typeof(int), Type.EmptyTypes).GetILGenerator();
        il.Emit(OpCodes.Ldc_I4_7);
        il.Emit(OpCodes.Ret);
        impl.CreateType();
    }

    // NS.{tag}Callers.CallsRun(IProbe p) => p.Run()
    private static void Callers(ModuleBuilder module, string tag, Type probe)
    {
        var callers = module.DefineType($"NS.{tag}Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var il = callers.DefineMethod("CallsRun", MethodAttributes.Public | MethodAttributes.Static, typeof(int), [probe]).GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Callvirt, probe.GetMethod("Run")!);
        il.Emit(OpCodes.Ret);
        callers.CreateType();
    }

    private static void Marker(ModuleBuilder module, string space) =>
        module.DefineType(space + ".Marker", TypeAttributes.Public | TypeAttributes.Class).CreateType();
    #endregion

    #region Fields
    private readonly EmittedAssembly emitted;
    #endregion
}
