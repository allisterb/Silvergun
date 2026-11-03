namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelBytecode = Model.Bytecode;

/// <summary>
/// The IL premises of the A2 S1 dispatch rows in <see cref="MechanismGroundTruth"/> (ObjectVirtual, ExplicitImpl,
/// GenericInterface, StaticAbstract, OpenHierarchy), read from the BUILT fixture — raw CCI for the instruction as
/// written, Model for what the graph sees. A row is only evidence about CHA if the compiler emitted the shape it names:
/// <c>o.ToString()</c> must be a <c>callvirt</c> on <c>System.Object</c>, <c>number.ToString()</c> a plain <c>call</c>,
/// <c>T.Make()</c> a <c>constrained.</c>-prefixed <c>call</c> that Model shows as a plain static call, and so on.
/// </summary>
public sealed class MechanismDispatchPremiseTests : IClassFixture<MechanismFixtureFixture>, IClassFixture<MechanismMethodGraphFixture>
{
    #region Constructors
    public MechanismDispatchPremiseTests(MechanismFixtureFixture cci, MechanismMethodGraphFixture model)
    {
        this.cci = cci;
        this.model = model;
    }
    #endregion

    #region Methods
    /// <summary>
    /// The one dispatching instruction of each row's dispatching method, as CCI reads it: its opcode and the node id
    /// of the reference it names (a node id carries no declaring-type arguments, so <c>IComparer&lt;string&gt;</c> renders
    /// <c>IComparer`1</c> with its parameters substituted).
    /// </summary>
    [Theory]
    [InlineData("ObjectVirtual.Describers.Describe(System.Object)", OperationCode.Callvirt, "System.Object.ToString()")]
    [InlineData("ObjectVirtual.Describers.DescribeSafe(System.Object)", OperationCode.Callvirt, "System.Object.ToString()")]
    [InlineData("ObjectVirtual.Describers.DescribesNumber(System.Int32)", OperationCode.Call, "System.Int32.ToString()")]
    [InlineData("ExplicitImpl.Callers.CallsExplicit()", OperationCode.Callvirt, "MechanismFixture.ExplicitImpl.IExplicitProbe.Run()")]
    [InlineData("ExplicitImpl.Callers.CallsSafeExplicit()", OperationCode.Callvirt, "MechanismFixture.ExplicitImpl.ISafeExplicitProbe.Run()")]
    [InlineData("GenericInterface.Sorters.ComparesThroughInterface()", OperationCode.Callvirt,
        "System.Collections.Generic.IComparer`1.Compare(System.String,System.String)")]
    [InlineData("GenericInterface.Sorters.ComparesThroughSafeInterface()", OperationCode.Callvirt,
        "MechanismFixture.GenericInterface.ISafeComparer`1.Compare(System.String,System.String)")]
    [InlineData("OpenHierarchy.Flushers.FlushIt(System.IO.Stream)", OperationCode.Callvirt, "System.IO.Stream.Flush()")]
    [InlineData("OpenHierarchy.Flushers.FlushItSafe(System.IO.Stream)", OperationCode.Callvirt, "System.IO.Stream.Flush()")]
    [InlineData("OpenHierarchy.Flushers.FlushesJournal()", OperationCode.Callvirt, "MechanismFixture.OpenHierarchy.Journal.Flush()")]
    public void Premise_TheDispatchingMethod_EmitsTheNamedInstruction(string method, OperationCode opcode, string target)
    {
        var calls = Calls(Fixture(method));

        var call = Assert.Single(calls, c => c.Target == target);

        Assert.Equal(opcode, call.Code);
    }

    /// <summary>
    /// StaticAbstract: <c>T.Make()</c> is <c>constrained. !!T call IFactory::Make()</c> in the IL, and Model — whose
    /// CCIProvider drops the prefix — shows a plain STATIC call to the abstract interface member. That is the shape
    /// the static CHA rule exists for. The twin has the same shape over <c>ISafeFactory</c>.
    /// </summary>
    [Theory]
    [InlineData("StaticAbstract.Builders.Build`1()", "MechanismFixture.StaticAbstract.IFactory.Make()")]
    [InlineData("StaticAbstract.Builders.BuildSafe`1()", "MechanismFixture.StaticAbstract.ISafeFactory.Make()")]
    [InlineData("StaticInherited.Builders.Create`1()", "MechanismFixture.StaticInherited.IFactory.Make()")]
    public void Premise_TMake_IsAConstrainedCall_ThatModelSeesAsAPlainStaticCall(string method, string target)
    {
        var operations = Operations(Fixture(method));
        var at = Array.FindIndex(operations, op => op.OperationCode == OperationCode.Call && op.Value is IMethodReference m && NodeId(m) == target);
        Assert.True(at > 0, $"no call to {target} in {method}");
        Assert.Equal(OperationCode.Constrained_, operations[at - 1].OperationCode);

        var body = model.Index.Methods.Single(m => m.NodeId == Fixture(method)).Definition.Body.Instructions;
        var call = Assert.Single(body.OfType<ModelBytecode.MethodCallInstruction>(), i => CanonicalName.NodeId(ModelNames.Of(i.Method)) == target);
        Assert.Equal(ModelBytecode.MethodCallOperation.Static, call.Operation);
        Assert.True(call.Method.IsStatic);
        var definition = model.Index.Resolve(call.Method).Definition;
        Assert.NotNull(definition);
        Assert.True(definition!.IsStatic && definition.IsAbstract);
    }

    /// <summary>
    /// ExplicitImpl and StaticAbstract, the definition side: an explicit implementation is an instance VIRTUAL method
    /// whose metadata name is interface-qualified; a static abstract member's implementation is a plain static method.
    /// </summary>
    [Fact]
    public void Premise_ImplementationShapes_AsModelSeesThem()
    {
        var explicitRun = Definition("ExplicitImpl.EnvExplicitProbe.MechanismFixture.ExplicitImpl.IExplicitProbe.Run()");
        Assert.Equal("MechanismFixture.ExplicitImpl.IExplicitProbe.Run", explicitRun.Name);
        Assert.True(explicitRun.IsVirtual && !explicitRun.IsStatic);

        var make = Definition("StaticAbstract.EnvFactory.Make()");
        Assert.True(make.IsStatic && !make.IsVirtual && !make.IsAbstract);
    }

    /// <summary>
    /// OpenHierarchy: EnvStream and SafeStream derive from the platform's MemoryStream, so they are OPEN; Journal and
    /// SafeJournal derive (through own code) from System.Object, so they are not. And the subtype map has no key under
    /// which <c>Stream</c> reaches EnvStream: only the open-type rule can.
    /// </summary>
    [Fact]
    public void Premise_TheStreamsAreOpen_AndTheJournalsAreNot()
    {
        Assert.True(model.Index.IsOpen(Fixture("OpenHierarchy.EnvStream")));
        Assert.True(model.Index.IsOpen(Fixture("OpenHierarchy.SafeStream")));
        Assert.False(model.Index.IsOpen(Fixture("OpenHierarchy.Journal")));
        Assert.False(model.Index.IsOpen(Fixture("OpenHierarchy.SafeJournal")));
        Assert.Equal(["System.IO.MemoryStream"], Assert.Single(model.Index.Types(Fixture("OpenHierarchy.EnvStream"))).Supertypes);
        Assert.Empty(model.Index.DirectSubtypes("System.IO.Stream"));
    }

    /// <summary>
    /// InheritedImpl (A2 S1 review C1), the shape and the focused answer. The inheritors declare no <c>Run</c> and list
    /// the interface; the bases do NOT list it, so no base is below the interface. <c>PlainBase.Run</c> is non-virtual in
    /// source but Roslyn emits it virtual (it fills <c>PlainInheritor</c>'s slot), so it is a candidate; the interface
    /// call reaches each inherited <c>Run</c> through its inheritor, and only that one — never the other bases'.
    /// </summary>
    [Theory]
    [InlineData("CallsInherited()", "EnvInheritor", "EnvBase", "IInheritedProbe")]
    [InlineData("CallsPlainInherited()", "PlainInheritor", "PlainBase", "IPlainProbe")]
    [InlineData("CallsSafeInherited()", "SafeInheritor", "SafeBase", "ISafeInheritedProbe")]
    public void Premise_AnInterfaceSlotFilledByAnInheritedMethod_IsReachedThroughTheInheritor(string caller, string inheritor, string @base, string probe)
    {
        var inherited = Definition($"InheritedImpl.{@base}.Run()");
        Assert.True(inherited.IsVirtual && !inherited.IsStatic, $"{@base}.Run is not virtual in Model");
        Assert.DoesNotContain(model.Index.Methods, m => m.DeclaringTypeId == Fixture($"InheritedImpl.{inheritor}") && m.Definition.Name == "Run");
        Assert.Contains(Fixture($"InheritedImpl.{probe}"), Assert.Single(model.Index.Types(Fixture($"InheritedImpl.{inheritor}"))).Supertypes);
        Assert.DoesNotContain(Fixture($"InheritedImpl.{probe}"), Assert.Single(model.Index.Types(Fixture($"InheritedImpl.{@base}"))).Supertypes);

        var site = Assert.Single(model.Sites, s => s.Caller.NodeId == Fixture($"InheritedImpl.Callers.{caller}") && s.Kind == MethodEdgeKind.CallVirt);

        Assert.Equal([Fixture($"InheritedImpl.{@base}.Run()")], site.DispatchTargets(model.Index));
    }

    // ---- StaticInherited (A2 S1 review 2, W-B) --------------------------------------------------------------------

    /// <summary>
    /// StaticInherited, the shape as C# compiled it. csc accepts <c>class SC : SB, IFactory {}</c> with the static
    /// <c>SB.Make</c> as the implementation, but does not leave the slot to the runtime: it SYNTHESIZES a private static
    /// stub in <c>SC</c>, named <c>MechanismFixture.StaticInherited.IFactory.Make</c>, bound to <c>IFactory.Make</c> by
    /// SC's one MethodImpl row, whose body calls <c>SB.Make</c>. <c>SC</c> lists <c>IFactory</c>; <c>SB</c> does not, and
    /// <c>SB.Make</c> is a plain static (neither virtual nor abstract).
    /// </summary>
    [Fact]
    public void Premise_StaticInherited_CscFillsTheSlotWithAStubInSCThatCallsSBMake()
    {
        using (var pe = new PEReader(File.OpenRead(MechanismFixtureAssemblies.Fixture)))
        {
            var metadata = pe.GetMetadataReader();
            var sc = metadata.TypeDefinitions.Select(metadata.GetTypeDefinition)
                .Single(t => metadata.GetString(t.Namespace) == "MechanismFixture.StaticInherited" && metadata.GetString(t.Name) == "SC");
            Assert.Equal([".ctor", "MechanismFixture.StaticInherited.IFactory.Make"], sc.GetMethods().Select(m => metadata.GetString(metadata.GetMethodDefinition(m).Name)).Order(StringComparer.Ordinal));
            var impl = metadata.GetMethodImplementation(Assert.Single(sc.GetMethodImplementations()));
            Assert.Equal("MechanismFixture.StaticInherited.IFactory.Make", metadata.GetString(metadata.GetMethodDefinition((System.Reflection.Metadata.MethodDefinitionHandle)impl.MethodBody).Name));
            Assert.Single(sc.GetInterfaceImplementations());
        }

        var stub = Definition(StaticInheritedStub);
        Assert.True(stub.IsStatic && !stub.IsAbstract);
        Assert.Contains(model.Sites, s => s.Caller.NodeId == Fixture(StaticInheritedStub) && s.Kind == MethodEdgeKind.Call
            && model.Index.Resolve(s.Target).NodeId == Fixture("StaticInherited.SB.Make()"));
        Assert.Equal([Fixture("StaticInherited.IFactory"), Fixture("StaticInherited.SB")], Assert.Single(model.Index.Types(Fixture("StaticInherited.SC"))).Supertypes);
        Assert.DoesNotContain(Fixture("StaticInherited.IFactory"), Assert.Single(model.Index.Types(Fixture("StaticInherited.SB"))).Supertypes);
        var make = Definition("StaticInherited.SB.Make()");
        Assert.True(make.IsStatic && !make.IsVirtual && !make.IsAbstract);
    }

    /// <summary>
    /// The C# shape's dispatch: the constrained static call through <c>IFactory</c> reaches SC's stub (below
    /// <c>IFactory</c>, by its explicit-implementation name) — the method the CLR runs, which calls <c>SB.Make</c> — and,
    /// by the W-B rule, <c>SB.Make</c> itself (an over-match here, harmless: the stub calls it). Nothing else: the
    /// same-shaped static <c>Make</c>s of the StaticAbstract factories implement a different <c>IFactory</c>.
    /// </summary>
    [Fact]
    public void DispatchTargets_TheCscStaticInheritedShape_ReachTheStubAndTheBaseMethod()
    {
        var site = Assert.Single(model.Sites, s => s.Caller.NodeId == Fixture("StaticInherited.Builders.Create`1()")
            && s.ReferenceNodeId == "MechanismFixture.StaticInherited.IFactory.Make()");
        Assert.Equal(MethodEdgeKind.Call, site.Kind);

        Assert.Equal([Fixture("StaticInherited.SB.Make()"), Fixture(StaticInheritedStub)], site.DispatchTargets(model.Index));
        Assert.Contains(new MethodEdge(site.Caller.NodeId, Fixture(StaticInheritedStub), MethodEdgeKind.Dispatch, site.Offset), model.Graph.Edges);
        Assert.Contains(new MethodEdge(site.Caller.NodeId, Fixture("StaticInherited.SB.Make()"), MethodEdgeKind.Dispatch, site.Offset), model.Graph.Edges);
    }

    /// <summary>
    /// Why csc writes a stub: the CLR does NOT fill a static abstract slot from a base class by itself. The emitted
    /// shape — <c>SC : SB, IFactory</c> with no method and no MethodImpl, <c>SB</c> with a plain static <c>Make</c> — is
    /// refused when <c>SC</c> loads.
    /// </summary>
    [Fact]
    public void Runtime_StaticInheritedWithoutAMethodImpl_IsRefusedByTheClr()
    {
        using var emitted = new EmittedAssembly();
        var path = EmitStaticInherited(emitted, methodImpl: false);

        using var context = new IsolatedLoadContext();
        var assembly = context.LoadBytes(path);

        var refused = Assert.Throws<TypeLoadException>(() => assembly.GetType("WB.SC", throwOnError: true));
        Assert.Contains("Make", refused.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nor does the CLR take the hand-written alternative: <c>SC</c>'s MethodImpl naming the INHERITED <c>SB::Make</c> as
    /// the body of <c>IFactory::Make</c> is refused too ("Body referenced in a method implementation must be defined in
    /// the same type"). So on CoreCLR a static abstract slot is only ever filled by a method of the type itself — a
    /// stub, as csc writes — and the W-B rule's targets in a stub-less shape are an over-approximation of a type that
    /// cannot load.
    /// </summary>
    [Fact]
    public void Runtime_StaticInheritedWithAMethodImplNamingTheBaseMethod_IsRefusedByTheClrToo()
    {
        using var emitted = new EmittedAssembly();
        var path = EmitStaticInherited(emitted, methodImpl: true);
        using (var pe = new PEReader(File.OpenRead(path)))
        {
            var metadata = pe.GetMetadataReader();
            var sc = metadata.TypeDefinitions.Select(metadata.GetTypeDefinition).Single(t => metadata.GetString(t.Name) == "SC");
            var impl = metadata.GetMethodImplementation(Assert.Single(sc.GetMethodImplementations()));
            Assert.Equal([".ctor"], sc.GetMethods().Select(m => metadata.GetString(metadata.GetMethodDefinition(m).Name)));
            Assert.Equal("SB", metadata.GetString(metadata.GetTypeDefinition(metadata.GetMethodDefinition((System.Reflection.Metadata.MethodDefinitionHandle)impl.MethodBody).GetDeclaringType()).Name));
        }

        using var context = new IsolatedLoadContext();
        var assembly = context.LoadBytes(path);

        var refused = Assert.Throws<TypeLoadException>(() => assembly.GetType("WB.SC", throwOnError: true));
        Assert.Contains("method implementation", refused.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// W-B: with no stub in <c>SC</c> (the literal shape: <c>SC : SB, IFactory</c>, nothing else), only the inherited
    /// rule — now applied to static sites — reaches <c>SB.Make</c> from the constrained static call through
    /// <c>IFactory</c>: <c>SB</c> is not below <c>IFactory</c>, but its own subclass <c>SC</c> is. The graph has the
    /// Dispatch edge. (The CLR refuses this type, see above: the edge costs precision only.)
    /// </summary>
    [Fact]
    public void DispatchTargets_AStaticAbstractSlotFilledByAnInheritedStatic_ReachTheBaseMethod()
    {
        using var emitted = new EmittedAssembly();
        using var loaded = ModelAssemblies.Load(EmitStaticInherited(emitted, methodImpl: false));
        var index = loaded.Index();
        Assert.DoesNotContain(index.Methods, m => m.DeclaringTypeId == "WB.SC" && m.Definition.Name.EndsWith("Make", StringComparison.Ordinal));
        var site = Assert.Single(ModelCallSite.All(index), s => s.Caller.NodeId.StartsWith("WB.Callers.Create`1(", StringComparison.Ordinal));
        Assert.Equal(MethodEdgeKind.Call, site.Kind);
        Assert.Equal("WB.IFactory.Make()", site.ReferenceNodeId);

        Assert.Equal(["WB.SB.Make()"], site.DispatchTargets(index));
        Assert.Contains(new MethodEdge(site.Caller.NodeId, "WB.SB.Make()", MethodEdgeKind.Dispatch, site.Offset), MethodGraph.Build(index).Edges);
    }

    // ChaStaticInherited: WB.IFactory { static abstract string Make(); }, WB.SB { static string Make() => "SB"; },
    // WB.SC : SB, IFactory with no methods (and, if methodImpl, `.override IFactory::Make with SB::Make`), and
    // WB.Callers.Create<T>() where T : IFactory => constrained. !!T call IFactory::Make(). Reflection.Emit refuses a
    // MethodImpl body from another type ("MethodOverride's body must be from this type"), so that row is added to the
    // generated metadata directly.
    private static string EmitStaticInherited(EmittedAssembly emitted, bool methodImpl)
    {
        const System.Reflection.MethodAttributes Static = System.Reflection.MethodAttributes.Public | System.Reflection.MethodAttributes.HideBySig | System.Reflection.MethodAttributes.Static;
        System.Reflection.Emit.TypeBuilder? sc = null;
        System.Reflection.Emit.MethodBuilder? sbMake = null;
        System.Reflection.Emit.MethodBuilder? abstractMake = null;

        void Define(System.Reflection.Emit.ModuleBuilder module)
        {
            var factory = module.DefineType("WB.IFactory", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Interface | System.Reflection.TypeAttributes.Abstract);
            abstractMake = factory.DefineMethod("Make", Static | System.Reflection.MethodAttributes.Abstract | System.Reflection.MethodAttributes.Virtual, typeof(string), Type.EmptyTypes);
            var sb = module.DefineType("WB.SB", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Class);
            sb.DefineDefaultConstructor(System.Reflection.MethodAttributes.Public);
            sbMake = sb.DefineMethod("Make", Static, typeof(string), Type.EmptyTypes);
            var body = sbMake.GetILGenerator();
            body.Emit(System.Reflection.Emit.OpCodes.Ldstr, "SB");
            body.Emit(System.Reflection.Emit.OpCodes.Ret);
            sc = module.DefineType("WB.SC", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Class | System.Reflection.TypeAttributes.Sealed, sb, [factory]);
            var callers = module.DefineType("WB.Callers", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Abstract | System.Reflection.TypeAttributes.Sealed | System.Reflection.TypeAttributes.Class);
            var create = callers.DefineMethod("Create", Static, typeof(string), Type.EmptyTypes);
            var t = create.DefineGenericParameters("T")[0];
            t.SetInterfaceConstraints(factory);
            var il = create.GetILGenerator();
            il.Emit(System.Reflection.Emit.OpCodes.Constrained, t);
            il.Emit(System.Reflection.Emit.OpCodes.Call, abstractMake);
            il.Emit(System.Reflection.Emit.OpCodes.Ret);
            foreach (var type in new[] { factory, sb, sc, callers })
                type.CreateType();
        }

        void AddMethodImpl(System.Reflection.Metadata.Ecma335.MetadataBuilder metadata)
        {
            if (sc!.MetadataToken == 0 || sbMake!.MetadataToken == 0 || abstractMake!.MetadataToken == 0)
                throw new InvalidOperationException("The builders have no metadata tokens yet.");
            metadata.AddMethodImplementation(
                (TypeDefinitionHandle)System.Reflection.Metadata.Ecma335.MetadataTokens.EntityHandle(sc.MetadataToken),
                System.Reflection.Metadata.Ecma335.MetadataTokens.EntityHandle(sbMake.MetadataToken),
                System.Reflection.Metadata.Ecma335.MetadataTokens.EntityHandle(abstractMake.MetadataToken));
        }

        return methodImpl
            ? emitted.Save("ChaStaticInherited", Define, AddMethodImpl, "with-methodimpl")
            : emitted.Save("ChaStaticInherited", Define, "without-methodimpl");
    }

    private (OperationCode Code, string Target)[] Calls(string method) =>
        [.. Operations(method)
            .Where(op => op.OperationCode is OperationCode.Call or OperationCode.Callvirt or OperationCode.Ldftn or OperationCode.Ldvirtftn && op.Value is IMethodReference)
            .Select(op => (op.OperationCode, NodeId((IMethodReference)op.Value)))];

    private IOperation[] Operations(string method)
    {
        var definition = cci.Fixture.Module.GetAllTypes().SelectMany(t => t.Methods).Single(m => NodeId(m) == method);
        return [.. AssemblyAnalyzer.TryReadBody(definition).Body!.Operations];
    }

    private Model.Types.MethodDefinition Definition(string nodeIdWithoutRoot) =>
        model.Index.Methods.Single(m => m.NodeId == Fixture(nodeIdWithoutRoot)).Definition;

    private static string NodeId(IMethodReference method) => CanonicalName.NodeId(CciNames.Of(method));

    private static string Fixture(string nodeIdWithoutRoot) => $"{MechanismGroundTruth.RootNamespace}.{nodeIdWithoutRoot}";
    #endregion

    #region Fields
    // The static stub csc synthesizes in StaticInherited.SC to fill IFactory.Make with the inherited SB.Make.
    private const string StaticInheritedStub = "StaticInherited.SC.MechanismFixture.StaticInherited.IFactory.Make()";

    private readonly MechanismFixtureFixture cci;
    private readonly MechanismMethodGraphFixture model;
    #endregion
}
