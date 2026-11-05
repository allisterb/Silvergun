namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Model.Types;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// S3 review W2: the InternalCall exemption covers only a delegate type's runtime methods (its instance <c>.ctor</c>,
/// <c>Invoke</c>, <c>BeginInvoke</c>, <c>EndInvoke</c>), never every member of a delegate type. C# cannot declare any
/// other member on a delegate, so the shape is emitted (<see cref="EmittedAssembly"/>): <c>Crafted.Hook :
/// System.MulticastDelegate</c> with runtime-implemented <c>.ctor</c> and <c>Invoke</c>, plus a static <c>internalcall</c>
/// <c>Steal</c> and (review round 2, W2-r2) an instance <c>internalcall</c> <c>Invoke(int)</c> named like a runtime method;
/// and public callers <c>Crafted.Api.CallsSteal</c> and <c>CallsInvokeIcall</c>. Read as metadata, never loaded or run.
/// </summary>
public sealed class CraftedDelegateInternalCallTests : IClassFixture<CraftedDelegateInternalCallTests.Fixture>
{
    #region Constructors
    public CraftedDelegateInternalCallTests(Fixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // The premise: the model sees Hook as a delegate, and all three of its members as external with no P/Invoke.
    [Fact]
    public void Premise_HookIsADelegate_AndItsMembersAreExternalWithoutPInvoke()
    {
        var hook = Assert.IsType<ClassDefinition>(Assert.Single(fixture.Index.Types("Crafted.Hook")).Definition);

        Assert.True(hook.IsDelegate);
        Assert.All([Ctor, Invoke, Steal], id =>
        {
            var definition = Assert.Single(fixture.Index.Definitions(id)).Definition;
            Assert.True(definition.IsExternal && !definition.IsPlatformInvoke && !definition.IsAbstract, id);
        });
        Assert.True(Assert.Single(fixture.Index.Definitions(Steal)).Definition.IsStatic);
    }

    // The model's MethodImpl flags on Hook (review round 2): the runtime methods are runtime-implemented; the two
    // internalcalls, Steal and the instance Invoke(int) named like a runtime method, are runtime-internal and not.
    [Theory]
    [InlineData(Ctor, true, false)]
    [InlineData(Invoke, true, false)]
    [InlineData(Steal, false, true)]
    [InlineData(InvokeIcall, false, true)]
    public void Premise_HooksMethodImplFlags_SeparateRuntimeMethodsFromInternalCalls(string method, bool runtimeImplemented, bool runtimeInternal)
    {
        var definition = Assert.Single(fixture.Index.Definitions(method)).Definition;

        Assert.Equal((runtimeImplemented, runtimeInternal), (definition.IsRuntimeImplemented, definition.IsRuntimeInternal));
        Assert.True(definition.IsExternal && !definition.IsAbstract && !definition.IsPlatformInvoke, method);
    }

    // Invoke(int) is an instance member named Invoke, but internalcall rather than runtime: not exempt.
    [Fact]
    public void Premise_InvokeIcall_IsAnInstanceOverloadOfInvoke()
    {
        var definition = Assert.Single(fixture.Index.Definitions(InvokeIcall)).Definition;

        Assert.Equal(("Invoke", false), (definition.Name, definition.IsStatic));
        Assert.Contains(fixture.Graph.Edges, e => e.From == CallsInvokeIcall && e.To == InvokeIcall && e.Kind == MethodEdgeKind.CallVirt);
    }

    // Steal sits in a delegate type but is no runtime method of one: an InternalCall, and so is the instance Invoke(int)
    // that only shares a runtime method's name. Hook's runtime methods are not.
    [Theory]
    [InlineData(Steal, true)]
    [InlineData(InvokeIcall, true)]
    [InlineData(Ctor, false)]
    [InlineData(Invoke, false)]
    public void Facts_OnlyTheDelegatesRuntimeMethodsAreExempt(string method, bool internalCall)
    {
        var facts = Facts(method);

        Assert.Equal((internalCall, false, false), (facts.InternalCall, facts.NativeImport, facts.ComImport));
    }

    // Each caller reaches Unseen at its internalcall, Bound, two hops; it reaches no capability, so PublicApi is Unknown,
    // never None.
    [Theory]
    [InlineData(CallsSteal, Steal, MethodEdgeKind.Call)]
    [InlineData(CallsInvokeIcall, InvokeIcall, MethodEdgeKind.CallVirt)]
    public void Reachability_ACallerOfAnInternalCall_ReachesUnseen_AndPublicApiIsUnknown(string caller, string internalCall, MethodEdgeKind via)
    {
        var report = Reachability.Analyze(Alone(fixture.Graph, caller));

        var row = Assert.Single(report.Reaches, r => r.Class == RootClass.PublicApi);
        Assert.Null(row.Capability);
        Assert.Equal((1, 1, 1), (row.Roots, row.Bound, row.Instantiated));
        var path = Assert.Single(row.Examples);
        Assert.Equal((ReachEvidence.Bound, 2, (OpacityKind?)null), (path.Evidence, path.Length, path.EndsInOpacity));
        Assert.Equal([caller, internalCall], path.Hops.Select(h => h.NodeId));
        Assert.Equal(via, path.Hops[1].Via);
        Assert.DoesNotContain(report.Reaches, r => r.Capability is not null);
        var status = Assert.Single(report.Classes, c => c.Class == RootClass.PublicApi);
        Assert.Equal(RootClassVerdict.Unknown, status.Verdict);
        Assert.Contains("1 root(s) reach code the graph cannot see", status.Reasons);
    }

    // The runtime methods, as roots, reach nothing.
    [Theory]
    [InlineData(Ctor)]
    [InlineData(Invoke)]
    public void Reachability_TheDelegatesRuntimeMethods_ReachNothing(string method)
    {
        Assert.Empty(Reachability.Analyze(Alone(fixture.Graph, method)).Reaches);
    }

    private OwnMethodFacts Facts(string nodeId) =>
        fixture.Graph.Facts.Methods.SingleOrDefault(f => f.NodeId == nodeId)
            ?? throw new InvalidOperationException($"No facts for '{nodeId}'. Own nodes: {string.Join(", ", fixture.Graph.Facts.Methods.Select(f => f.NodeId))}");

    private static MethodGraph Alone(MethodGraph graph, string root) =>
        MethodGraph.FromParts(graph.Nodes, graph.Edges, graph.Opacities, graph.Coverage,
            graph.Facts with { Methods = [.. graph.Facts.Methods.Select(f => f.NodeId == root ? f : f with { Roots = RootClass.None })] });
    #endregion

    #region Fields
    private const string Ctor = "Crafted.Hook..ctor(System.Object,System.IntPtr)";
    private const string Invoke = "Crafted.Hook.Invoke()";
    private const string Steal = "Crafted.Hook.Steal()";
    private const string CallsSteal = "Crafted.Api.CallsSteal()";
    private const string InvokeIcall = "Crafted.Hook.Invoke(System.Int32)";
    private const string CallsInvokeIcall = "Crafted.Api.CallsInvokeIcall(Crafted.Hook)";

    private readonly Fixture fixture;
    #endregion

    #region Child types
    /// <summary>The crafted assembly, emitted once into a temporary directory, indexed alone and its graph built.</summary>
    public sealed class Fixture : IDisposable
    {
        public Fixture()
        {
            emitted = new EmittedAssembly();
            try
            {
                Assemblies = ModelAssemblies.Load(emitted.Save("CraftedDelegate", Define));
                Index = Assemblies.Index();
                Graph = MethodGraph.Build(Index);
            }
            catch (Exception)
            {
                Assemblies?.Dispose();
                emitted.Dispose();
                throw;
            }
        }

        public ModelAssemblies Assemblies { get; }

        public MemberIndex Index { get; }

        public MethodGraph Graph { get; }

        public void Dispose()
        {
            Assemblies.Dispose();
            emitted.Dispose();
        }

        private static void Define(ModuleBuilder module)
        {
            var hook = module.DefineType("Crafted.Hook", TypeAttributes.Public | TypeAttributes.Sealed, typeof(MulticastDelegate));
            var ctor = hook.DefineConstructor(
                MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                CallingConventions.Standard, [typeof(object), typeof(IntPtr)]);
            ctor.SetImplementationFlags(MethodImplAttributes.Runtime | MethodImplAttributes.Managed);
            var invoke = hook.DefineMethod("Invoke", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot, typeof(int), Type.EmptyTypes);
            invoke.SetImplementationFlags(MethodImplAttributes.Runtime | MethodImplAttributes.Managed);
            var steal = hook.DefineMethod("Steal", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, typeof(int), Type.EmptyTypes);
            steal.SetImplementationFlags(MethodImplAttributes.InternalCall);
            // Review round 2 (W2-r2): an INSTANCE internalcall named like a runtime method, so the name alone exempts nothing.
            var invokeIcall = hook.DefineMethod("Invoke", MethodAttributes.Public | MethodAttributes.HideBySig, typeof(int), [typeof(int)]);
            invokeIcall.SetImplementationFlags(MethodImplAttributes.InternalCall);
            hook.CreateType();

            var api = module.DefineType("Crafted.Api", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
            var il = api.DefineMethod("CallsSteal", MethodAttributes.Public | MethodAttributes.Static, typeof(int), Type.EmptyTypes).GetILGenerator();
            il.Emit(OpCodes.Call, steal);
            il.Emit(OpCodes.Ret);
            var il2 = api.DefineMethod("CallsInvokeIcall", MethodAttributes.Public | MethodAttributes.Static, typeof(int), [hook]).GetILGenerator();
            il2.Emit(OpCodes.Ldarg_0);
            il2.Emit(OpCodes.Ldc_I4_1);
            il2.Emit(OpCodes.Callvirt, invokeIcall);
            il2.Emit(OpCodes.Ret);
            api.CreateType();
        }

        private readonly EmittedAssembly emitted;
    }
    #endregion
}
