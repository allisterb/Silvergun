namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

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
    private readonly MechanismFixtureFixture cci;
    private readonly MechanismMethodGraphFixture model;
    #endregion
}
