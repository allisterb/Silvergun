namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// A2 S1 review <b>C2</b> (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md, "S1 review 1 … (S1b)"): a node id
/// carries no return type, so an Exact resolution was not verified. <c>callvirt string Derived::Q()</c>, where
/// <c>Derived</c> defines only <c>int Q()</c>, resolved Exact to the <c>int</c> method — a wrong Own edge — and S1's
/// "a non-virtual definition does not dispatch" rule then dropped <c>Sub.Q</c>. The CLR looks the method up in the base.
/// Since S1b <see cref="MemberIndex.Resolve"/> also compares the rendered return type. Every assembly is EMITTED
/// (<see cref="ReturnTypeFixture"/>), and the CLR is the oracle for what runs.
/// </summary>
public sealed class ReturnTypeResolutionTests : IClassFixture<ReturnTypeFixture>
{
    #region Constructors
    public ReturnTypeResolutionTests(ReturnTypeFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The oracle: <c>callvirt string Derived::Q()</c> runs <c>Sub.Q</c> on a <c>Sub</c> and <c>Base.Q</c> on a plain
    /// <c>Derived</c> — never <c>Derived</c>'s own <c>int Q()</c>.
    /// </summary>
    [Theory]
    [InlineData("Ret.Sub", "SUB")]
    [InlineData("Ret.Derived", "BASE")]
    public void Runtime_CallvirtStringDerivedQ_NeverRunsTheIntSibling(string receiver, string expected) =>
        Assert.Equal(expected, fixture.Run("CallsQ", receiver));

    /// <summary>
    /// Model renders <c>Derived.Q</c> with the same node id as the reference, and the reference's return type differs:
    /// the trap. The resolution is Unresolved ("no indexed definition matches"), never Exact to the <c>int</c> sibling.
    /// </summary>
    [Fact]
    public void Resolve_AReferenceWhoseReturnTypeNoDefinitionHas_IsUnresolved_NotTheSameNamedSibling()
    {
        using var loaded = ModelAssemblies.Load(fixture.Real, fixture.Caller);
        var index = loaded.Index();
        var site = Site(index, "CallsQ");
        var sibling = Assert.Single(index.Methods, m => m.NodeId == DerivedQ);
        Assert.Equal(DerivedQ, site.ReferenceNodeId);
        Assert.Equal("System.Int32", ModelNames.ReturnType(sibling.Definition, []));
        Assert.Equal("System.String", ModelNames.ReturnType(site.Target, []));

        var resolution = index.Resolve(site.Target);

        Assert.True(resolution.Kind == ResolutionKind.Unresolved,
            $"resolved {resolution.Kind} -> {resolution.NodeId} ({resolution.Reason}); expected Unresolved.");
        Assert.Null(resolution.Definition);
        Assert.Empty(resolution.Candidates);
        Assert.Equal("no indexed definition matches", resolution.Reason);
        Assert.Equal(ReturnTypeFixture.RealName, resolution.Assembly);
    }

    /// <summary>
    /// With no wrong Own definition to stop it, CHA reaches the override the CLR runs: <c>Sub.Q</c> (and not the
    /// non-virtual <c>int</c> sibling, nor <c>Base.Q</c>, which is not below <c>Derived</c>). In the graph the site keeps a
    /// leaf that is NOT the sibling's own node, an Unresolved opacity, and a Dispatch edge to <c>Sub.Q</c>.
    /// </summary>
    [Fact]
    public void DispatchTargets_FromTheUnresolvedSite_ReachTheOverrideTheClrRuns()
    {
        using var loaded = ModelAssemblies.Load(fixture.Real, fixture.Caller);
        var index = loaded.Index();
        var site = Site(index, "CallsQ");
        var graph = MethodGraph.Build(index);

        Assert.Equal([SubQ], site.DispatchTargets(index));
        var edges = graph.Successors(site.Caller.NodeId).Where(e => e.Offset == site.Offset).ToArray();
        Assert.Contains(new MethodEdge(site.Caller.NodeId, SubQ, MethodEdgeKind.Dispatch, site.Offset), edges);
        Assert.DoesNotContain(edges, e => e.To == DerivedQ);
        Assert.Contains(graph.Opacities, o => o.Site == site.Caller.NodeId && o.Offset == site.Offset && o.Kind == OpacityKind.Unresolved);
    }

    /// <summary>
    /// The precision gain: two conversion operators differing ONLY by return type (<c>int op_Explicit(Conv)</c> and
    /// <c>string op_Explicit(Conv)</c>) share a node id, which A1 left Ambiguous (§2.4). Each call now resolves Exact
    /// to the definition with its return type — the one the CLR runs.
    /// </summary>
    [Theory]
    [InlineData("ToInt", "System.Int32", 1)]
    [InlineData("ToText", "System.String", "TEXT")]
    public void Resolve_ReturnTypeOnlyOverloads_AreExactToTheRightOne(string caller, string returns, object value)
    {
        Assert.Equal(value, fixture.Run(caller, "Ret.Conv"));
        using var loaded = ModelAssemblies.Load(fixture.Real, fixture.Caller);
        var index = loaded.Index();
        var overloads = index.Methods.Where(m => m.NodeId == ConvExplicit).ToArray();
        Assert.Equal(2, overloads.Length);

        var resolution = index.Resolve(Site(index, caller).Target);

        Assert.True(resolution.Kind == ResolutionKind.Exact, $"resolved {resolution.Kind} ({resolution.Reason}); expected Exact.");
        var definition = Assert.Single(overloads, m => ReferenceEquals(m.Definition, resolution.Definition));
        Assert.Equal(returns, ModelNames.ReturnType(definition.Definition, []));
        Assert.Equal([ConvExplicit], resolution.Candidates);
        Assert.Null(resolution.Reason);
    }

    private static ModelCallSite Site(MemberIndex index, string caller) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId.StartsWith($"RetCaller.Callers.{caller}(", StringComparison.Ordinal));
    #endregion

    #region Fields
    private const string DerivedQ = "Ret.Derived.Q()";
    private const string SubQ = "Ret.Sub.Q()";
    private const string ConvExplicit = "Ret.Conv.op_Explicit(Ret.Conv)";

    private readonly ReturnTypeFixture fixture;
    #endregion
}

/// <summary>
/// The emitted assemblies of <see cref="ReturnTypeResolutionTests"/> (never loaded into the default context):
/// <list type="bullet">
/// <item><description><see cref="Real"/> — <c>ChaRet</c>: <c>Ret.Base { virtual string Q() =&gt; "BASE" }</c>,
/// <c>Ret.Derived : Base { int Q() =&gt; 7 }</c> (non-virtual), <c>Ret.Sub : Derived { override string Q() =&gt; "SUB" }</c>,
/// and <c>Ret.Conv</c> with <c>int op_Explicit(Conv) =&gt; 1</c> and <c>string op_Explicit(Conv) =&gt; "TEXT"</c>.</description></item>
/// <item><description>a stub <c>ChaRet</c> whose <c>Derived</c> declares <c>virtual string Q()</c> and whose <c>Conv</c>
/// has both operators — only to emit the caller against, which is how a <c>string Derived::Q()</c> MemberRef is
/// written.</description></item>
/// <item><description><see cref="Caller"/> — <c>ChaRetCaller</c>: <c>RetCaller.Callers.CallsQ(Derived)</c>
/// (<c>callvirt string Derived::Q()</c>), <c>ToInt(Conv)</c> and <c>ToText(Conv)</c> (a <c>call</c> to each operator).</description></item>
/// </list>
/// </summary>
public sealed class ReturnTypeFixture : IDisposable
{
    #region Constructors
    public ReturnTypeFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            var stub = emitted.Save(RealName, module => Define(module, stub: true), "stub");
            Real = emitted.Save(RealName, module => Define(module, stub: false), "real");
            using var context = new IsolatedLoadContext();
            var types = context.LoadBytes(stub);
            Caller = emitted.Save("ChaRetCaller", module => DefineCaller(module, types), "caller");
        }
        catch (Exception)
        {
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Real { get; }

    public string Caller { get; }
    #endregion

    #region Methods
    /// <summary>Runs <c>RetCaller.Callers.{method}(new {receiver}())</c> with <c>ChaRet</c> pinned to <see cref="Real"/>.</summary>
    public object? Run(string method, string receiver)
    {
        using var context = new IsolatedLoadContext(new Dictionary<string, string> { [RealName] = Real });
        var caller = context.LoadBytes(Caller);
        var instance = Activator.CreateInstance(context.LoadFromAssemblyName(new AssemblyName(RealName)).GetType(receiver, throwOnError: true)!);
        return caller.GetType("RetCaller.Callers", throwOnError: true)!.GetMethod(method)!.Invoke(null, [instance]);
    }

    public void Dispose() => emitted.Dispose();

    private static void Define(ModuleBuilder module, bool stub)
    {
        var @base = module.DefineType("Ret.Base", TypeAttributes.Public | TypeAttributes.Class);
        @base.DefineDefaultConstructor(MethodAttributes.Public);
        Returns(@base.DefineMethod("Q", NewVirtual, typeof(string), Type.EmptyTypes), "BASE");
        @base.CreateType();

        var derived = module.DefineType("Ret.Derived", TypeAttributes.Public | TypeAttributes.Class, @base);
        derived.DefineDefaultConstructor(MethodAttributes.Public);
        if (stub)
            Returns(derived.DefineMethod("Q", NewVirtual, typeof(string), Type.EmptyTypes), "STUB");
        else
            Returns(derived.DefineMethod("Q", Plain, typeof(int), Type.EmptyTypes), 7);
        derived.CreateType();

        if (!stub)
        {
            var sub = module.DefineType("Ret.Sub", TypeAttributes.Public | TypeAttributes.Class, derived);
            sub.DefineDefaultConstructor(MethodAttributes.Public);
            Returns(sub.DefineMethod("Q", Override, typeof(string), Type.EmptyTypes), "SUB");
            sub.CreateType();
        }

        var conv = module.DefineType("Ret.Conv", TypeAttributes.Public | TypeAttributes.Class);
        conv.DefineDefaultConstructor(MethodAttributes.Public);
        Returns(conv.DefineMethod("op_Explicit", Operator, typeof(int), [conv]), 1);
        Returns(conv.DefineMethod("op_Explicit", Operator, typeof(string), [conv]), "TEXT");
        conv.CreateType();
    }

    private static void DefineCaller(ModuleBuilder module, Assembly stub)
    {
        var derived = stub.GetType("Ret.Derived", throwOnError: true)!;
        var conv = stub.GetType("Ret.Conv", throwOnError: true)!;
        var callers = module.DefineType("RetCaller.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);

        var il = callers.DefineMethod("CallsQ", MethodAttributes.Public | MethodAttributes.Static, typeof(string), [derived]).GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Callvirt, derived.GetMethod("Q", BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)!);
        il.Emit(OpCodes.Ret);

        foreach (var (name, returns) in new[] { ("ToInt", typeof(int)), ("ToText", typeof(string)) })
        {
            il = callers.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, typeof(object), [conv]).GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, conv.GetMethods().Single(m => m.Name == "op_Explicit" && m.ReturnType == returns));
            if (returns.IsValueType)
                il.Emit(OpCodes.Box, returns);
            il.Emit(OpCodes.Ret);
        }

        callers.CreateType();
    }

    // A body returning the constant `value` (an int or a string).
    private static void Returns(MethodBuilder method, object value)
    {
        var il = method.GetILGenerator();
        if (value is string text)
            il.Emit(OpCodes.Ldstr, text);
        else
            il.Emit(OpCodes.Ldc_I4, (int)value);
        il.Emit(OpCodes.Ret);
    }
    #endregion

    #region Fields
    public const string RealName = "ChaRet";

    private const MethodAttributes Plain = MethodAttributes.Public | MethodAttributes.HideBySig;
    private const MethodAttributes NewVirtual = Plain | MethodAttributes.Virtual | MethodAttributes.NewSlot;
    private const MethodAttributes Override = Plain | MethodAttributes.Virtual;
    private const MethodAttributes Operator = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.SpecialName;

    private readonly EmittedAssembly emitted;
    #endregion
}
