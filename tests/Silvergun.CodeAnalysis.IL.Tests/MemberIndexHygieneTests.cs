namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// The two <see cref="MemberIndex"/> hygiene fixes of CHA A2Multi S2 (docs/agent/tasks/cha-a2multi-package-graphs.md,
/// M4 and "S1 and S2: implemented"):
/// <list type="bullet">
/// <item><description><b>Nested decoy.</b> Own definitions are bucketed by the declaring type's PARTS (namespace and
/// nesting chain), so a nested <c>System+Environment</c> is not the namespace type <c>System.Environment</c>, although
/// both join to one node id. With no forwarder a reference to the namespace type is now Unresolved — the CLR throws on
/// it — where before it was a wrong Exact; a reference to the nested type itself still resolves Exact. The CLR is the
/// oracle for both (<see cref="IsolatedLoadContext"/>, emitted assemblies only).</description></item>
/// <item><description><b>Qualified spelling.</b> A shadowed external type is keyed <c>[*]id</c> in the subtype map, one key
/// for every unindexed assembly, so an implementor linked through <c>[netstandard]System.IDisposable</c> is reached by
/// Dispatch from a <c>callvirt [System.Runtime]System.IDisposable::Dispose</c>. Hand-built Model objects, because an
/// emitter cannot spell the two assembly scopes.</description></item>
/// </list>
/// </summary>
public sealed class MemberIndexHygieneTests : IClassFixture<TypeForwarderFixture>
{
    #region Constructors
    public MemberIndexHygieneTests(TypeForwarderFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- nested decoy, no forwarder ----------------------------------------------------------------------------------

    /// <summary>
    /// The oracle: with FwdA defining only the NESTED <c>System+Environment</c>, the caller's
    /// <c>[FwdA]System.Environment::GetEnvironmentVariable</c> does not bind — the CLR throws a <see cref="TypeLoadException"/>
    /// — while the caller emitted against the nested type runs the decoy.
    /// </summary>
    [Fact]
    public void Runtime_ANamespaceTypeReference_DoesNotBindToTheNestedType_ButANestedReferenceDoes()
    {
        Environment.SetEnvironmentVariable(fixture.Variable, "PLATFORM-VALUE");
        try
        {
            var thrown = Record.Exception(() => Run(new() { ["FwdA"] = fixture.NestedOnly }, fixture.Caller, "Client.Caller"));
            var inner = thrown is TargetInvocationException { InnerException: { } e } ? e : thrown;
            Assert.True(inner is TypeLoadException, $"expected a TypeLoadException, got {inner?.GetType().Name ?? "no exception"}");

            Assert.Equal(TypeForwarderFixture.Decoy, Run(new() { ["FwdA"] = fixture.NestedOnly }, fixture.NestedCaller, "Client.NestedCaller"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(fixture.Variable, null);
        }
    }

    /// <summary>
    /// With no forwarder, the reference to the namespace type <c>System.Environment</c> is Unresolved: the only
    /// definition of that node id is the nested decoy, whose parts differ. In the graph it is a separate qualified leaf
    /// with an Unresolved opacity, never an edge to the decoy. (Before S2: a wrong Exact to the decoy.)
    /// </summary>
    [Fact]
    public void Resolve_ANamespaceTypeReferenceToANestedDecoy_IsUnresolved_NotTheDecoy()
    {
        using var loaded = ModelAssemblies.Load(fixture.NestedOnly, fixture.Caller);
        var index = loaded.Index();
        Assert.True(index.IsOwnMethod(GetEnvironmentVariable));   // the nested decoy joins to the same node id
        var site = Site(index, "Client.Caller.Env()");

        var resolution = index.Resolve(site.Target);
        var graph = MethodGraph.Build(index);

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Equal("FwdA", resolution.Assembly);
        Assert.Equal("no indexed definition matches", resolution.Reason);
        var qualified = MemberIndex.Qualified("FwdA", GetEnvironmentVariable);
        Assert.Equal([new MethodEdge("Client.Caller.Env()", qualified, MethodEdgeKind.Call, site.Offset)], graph.Successors("Client.Caller.Env()"));
        Assert.Contains(graph.Opacities, o => o.Site == "Client.Caller.Env()" && o.Kind == OpacityKind.Unresolved);
    }

    /// <summary>The positive control: a reference to the NESTED type itself still resolves Exact to the decoy, and the graph has that edge.</summary>
    [Fact]
    public void Resolve_ANestedTypeReference_StillResolvesExact()
    {
        using var loaded = ModelAssemblies.Load(fixture.NestedOnly, fixture.NestedCaller);
        var index = loaded.Index();
        var site = Site(index, "Client.NestedCaller.Env()");
        Assert.Equal(GetEnvironmentVariable, site.ReferenceNodeId);

        var resolution = index.Resolve(site.Target);

        Assert.Equal(ResolutionKind.Exact, resolution.Kind);
        Assert.True(resolution.IsOwn);
        Assert.Equal(GetEnvironmentVariable, resolution.NodeId);
        Assert.Equal("FwdA", resolution.Assembly);
        Assert.Equal([new MethodEdge("Client.NestedCaller.Env()", GetEnvironmentVariable, MethodEdgeKind.Call, site.Offset)],
            MethodGraph.Build(index).Successors("Client.NestedCaller.Env()"));
    }

    // ---- the Qualified spelling ----------------------------------------------------------------------------------------

    /// <summary>
    /// An own <c>System.IDisposable</c> shadows the platform one. <c>Impl.PlatformDisposable</c> implements the PLATFORM
    /// interface through a reference spelled <c>[netstandard]</c>; a call site does
    /// <c>callvirt [System.Runtime]System.IDisposable::Dispose</c>. Both spellings key to <c>[*]System.IDisposable</c>, so
    /// the implementor is reached by Dispatch — and the own shadow's implementor, under the bare key, is not.
    /// </summary>
    [Fact]
    public void DispatchTargets_TwoSpellingsOfAShadowedPlatformInterface_Join()
    {
        var index = MemberIndex.Build([(ShadowedSpellings(), TypeForwarders.None)]);
        var site = Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == "Impl.Callers.CallsDispose()");
        Assert.Equal("System.Runtime", site.DeclaringAssembly);

        Assert.Equal(["System.Object", "[*]System.IDisposable"], Assert.Single(index.Types("Impl.PlatformDisposable")).Supertypes);
        Assert.Equal(["Impl.PlatformDisposable"], index.DirectSubtypes("[*]System.IDisposable"));
        Assert.Empty(index.DirectSubtypes("[netstandard]System.IDisposable"));
        Assert.Equal(["Impl.ShadowDisposable"], index.DirectSubtypes("System.IDisposable"));
        Assert.Equal(ResolutionKind.External, index.Resolve(site.Target).Kind);

        Assert.Equal(["Impl.PlatformDisposable.Dispose()"], site.DispatchTargets(index));
        var graph = MethodGraph.Build(index);
        Assert.Contains(new MethodEdge(site.Caller.NodeId, "Impl.PlatformDisposable.Dispose()", MethodEdgeKind.Dispatch, site.Offset), graph.Edges);
        Assert.DoesNotContain(graph.Edges, e => e.To == "Impl.ShadowDisposable.Dispose()");
    }

    // Assembly "Shadows": an own interface System.IDisposable (Dispose), Impl.ShadowDisposable implementing it,
    // Impl.PlatformDisposable implementing [netstandard]System.IDisposable, and Impl.Callers.CallsDispose() whose body is
    // callvirt [System.Runtime]System.IDisposable::Dispose.
    private static Model.Assembly ShadowedSpellings()
    {
        var assembly = new Model.Assembly("Shadows");
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var system = new Model.Namespace("System") { ContainingAssembly = assembly, ContainingNamespace = root };
        var impl = new Model.Namespace("Impl") { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(system);
        root.Namespaces.Add(impl);
        assembly.RootNamespace = root;
        var objectType = SyntheticModel.TypeRef("System", "Object", assembly: "System.Runtime");

        var shadow = new ModelTypes.InterfaceDefinition("IDisposable") { ContainingAssembly = assembly, ContainingNamespace = system };
        shadow.Methods.Add(new ModelTypes.MethodDefinition("Dispose", ModelTypes.PlatformTypes.Void) { ContainingType = shadow, IsAbstract = true, IsVirtual = true });
        system.Types.Add(shadow);

        ModelTypes.ClassDefinition Implementor(string name, ModelTypes.IBasicType @interface)
        {
            var type = new ModelTypes.ClassDefinition(name) { ContainingAssembly = assembly, ContainingNamespace = impl, Base = objectType };
            type.Interfaces.Add(@interface);
            type.Methods.Add(new ModelTypes.MethodDefinition("Dispose", ModelTypes.PlatformTypes.Void) { ContainingType = type, IsVirtual = true, Body = Body() });
            impl.Types.Add(type);
            return type;
        }
        Implementor("PlatformDisposable", SyntheticModel.TypeRef("System", "IDisposable", assembly: "netstandard"));
        Implementor("ShadowDisposable", SyntheticModel.TypeRef("System", "IDisposable", assembly: "Shadows"));

        var callers = new ModelTypes.ClassDefinition("Callers") { ContainingAssembly = assembly, ContainingNamespace = impl, Base = objectType };
        var dispose = new ModelTypes.MethodReference("Dispose", ModelTypes.PlatformTypes.Void) { ContainingType = SyntheticModel.TypeRef("System", "IDisposable", assembly: "System.Runtime") };
        callers.Methods.Add(new ModelTypes.MethodDefinition("CallsDispose", ModelTypes.PlatformTypes.Void)
        {
            ContainingType = callers,
            IsStatic = true,
            Body = Body(new ModelBytecode.MethodCallInstruction(0x10, ModelBytecode.MethodCallOperation.Virtual, dispose)),
        });
        impl.Types.Add(callers);
        return assembly;
    }

    private static ModelTypes.MethodBody Body(params ModelBytecode.Instruction[] instructions)
    {
        var body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode);
        foreach (var instruction in instructions)
            body.Instructions.Add(instruction);
        return body;
    }

    // Runs type.Env() from `caller` with each named assembly pinned to the given file.
    private static object? Run(Dictionary<string, string> pinned, string caller, string type)
    {
        using var context = new IsolatedLoadContext(pinned);
        return context.LoadBytes(caller).GetType(type, throwOnError: true)!.GetMethod("Env")!.Invoke(null, null);
    }

    private static ModelCallSite Site(MemberIndex index, string caller) =>
        Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId == caller && s.Kind == MethodEdgeKind.Call);
    #endregion

    #region Fields
    private const string GetEnvironmentVariable = "System.Environment.GetEnvironmentVariable(System.String)";

    private readonly TypeForwarderFixture fixture;
    #endregion
}
