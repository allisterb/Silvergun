namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// <see cref="GraphFacts"/> over hand-built <c>Model</c> definitions (reachability R1, S1.2), for what no compiled fixture
/// produces: <see cref="ModelTypes.VisibilityKind.Unknown"/> visibility (the default for a definition nobody filled in),
/// and two definitions sharing one node id (overloads differing only by return type, ADR 0019). Indexed with
/// <see cref="ModuleMetadata.None"/>, so no module gap is in play.
/// </summary>
public sealed class GraphFactsSyntheticTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Unknown visibility
    // ---------------------------------------------------------------------------------------------------

    // Unknown anywhere on the chain over-approximates to PublicApi: on the method, on its type, or both.
    [Theory]
    [InlineData("Syn.Unknown.KnownMember()")]
    [InlineData("Syn.Unknown.UnknownMember()")]
    [InlineData("Syn.Known.UnknownMember()")]
    public void UnknownVisibility_OnTheChain_IsPublicApi(string method)
    {
        Assert.Equal(RootClass.PublicApi, Facts(VisibilityAssembly(), method).Roots);
    }

    // ...while a fully known private member stays Hidden and is not counted.
    [Fact]
    public void KnownVisibility_PrivateOnAPublicType_IsHidden()
    {
        Assert.Equal(RootClass.Hidden, Facts(VisibilityAssembly(), "Syn.Known.Private()").Roots);
    }

    // One gap per assembly, counting the methods counted as PublicApi for it.
    [Fact]
    public void UnknownVisibility_RecordsOneGapCountingTheMethods()
    {
        var facts = Collect(VisibilityAssembly());

        Assert.Equal([new RootGap("Syn", RootClass.PublicApi | RootClass.Hidden, "visibility unknown for 3 method(s); counted as PublicApi")], facts.Gaps);
    }

    // ---------------------------------------------------------------------------------------------------
    // Merged node ids
    // ---------------------------------------------------------------------------------------------------

    // Syn.Merge.Op() is defined three times: twice in "Syn" (returning void and int) and once in "Aaa". Roots and
    // NativeImport are OR'd, the ordinal-least assembly is kept, and there is one row.
    [Fact]
    public void MergedNodeId_ORsRootsAndNativeImport_AndKeepsTheOrdinalLeastAssembly()
    {
        var index = MemberIndex.Build([(MergeAssembly("Syn", withOverloads: true), TypeForwarders.None), (MergeAssembly("Aaa", withOverloads: false), TypeForwarders.None)]);
        Assert.Equal(3, index.Definitions(MergedOp).Count);   // the premise: one id, three definitions

        var facts = Assert.Single(Collect(index, invokeMap).Methods, f => f.NodeId == MergedOp);

        Assert.Equal(new OwnMethodFacts(MergedOp, "Aaa", "Syn.Merge", RootClass.PublicApi | RootClass.RuntimeInvoked, true, true), facts);
    }

    // Each definition alone carries only its own part, so the OR above is a merge, not one definition's mask.
    [Fact]
    public void MergedNodeId_EachDefinitionAlone_CarriesOnlyItsPart()
    {
        var alone = Assert.Single(Collect(MemberIndex.Build([(MergeAssembly("Aaa", withOverloads: false), TypeForwarders.None)]), invokeMap).Methods, f => f.NodeId == MergedOp);

        Assert.Equal(new OwnMethodFacts(MergedOp, "Aaa", "Syn.Merge", RootClass.Hidden, false, false), alone);
    }

    // ---------------------------------------------------------------------------------------------------
    // Slot work: every supertype step is charged (S1 review W1-r2)
    // ---------------------------------------------------------------------------------------------------

    // Syn.C : Syn.B overrides ToString and lists 50 own interfaces. The override walk steps through all 51 supertypes of
    // C (plus B's Object): over a 20-unit allowance, so the Hidden slot gap is recorded. Before the fix only the class
    // steps (2) were charged and the gap never appeared.
    [Fact]
    public void SlotWork_AClassListingManyInterfaces_ChargesEachStep_AndRecordsTheHiddenGap()
    {
        var facts = GraphFacts.Collect(Wide(interfaces: 50), wideMethods, [], CapabilityMap.Default, maxDispatchWork: 20);

        Assert.Contains(facts.Gaps, g => g.Class == RootClass.Hidden && g.Reason.Contains("slot work budget", StringComparison.Ordinal));
        Assert.Equal(RootClass.PublicContract, Assert.Single(facts.Methods).Roots);   // exhausted: errs toward true
    }

    // Twin: the same chain with no interfaces fits the same allowance, so no gap.
    [Fact]
    public void SlotWork_TheSameChainWithoutInterfaces_FitsTheAllowance()
    {
        var facts = GraphFacts.Collect(Wide(interfaces: 0), wideMethods, [], CapabilityMap.Default, maxDispatchWork: 20);

        Assert.DoesNotContain(facts.Gaps, g => g.Class == RootClass.Hidden);
        Assert.Equal(RootClass.PublicContract, Assert.Single(facts.Methods).Roots);   // Object.ToString's slot: external
    }

    private static GraphFacts Collect(Model.Assembly assembly) => Collect(MemberIndex.Build([(assembly, TypeForwarders.None)]), CapabilityMap.Default);

    private static GraphFacts Collect(MemberIndex index, CapabilityMap map) =>
        GraphFacts.Collect(index, index.Methods.Select(m => m.NodeId).ToHashSet(StringComparer.Ordinal), [], map, long.MaxValue);

    private static OwnMethodFacts Facts(Model.Assembly assembly, string nodeId) =>
        Assert.Single(Collect(assembly).Methods, f => f.NodeId == nodeId);

    // "Syn": Syn.Unknown (visibility never set) with a public and an unset member; Syn.Known (public) with a private and
    // an unset member. Three methods have Unknown somewhere on their chain.
    private static Model.Assembly VisibilityAssembly()
    {
        var (assembly, space) = Shell("Syn");
        var unknown = Class(assembly, space, "Unknown", ModelTypes.VisibilityKind.Unknown);
        Method(unknown, "KnownMember", ModelTypes.VisibilityKind.Public);
        Method(unknown, "UnknownMember", ModelTypes.VisibilityKind.Unknown);
        var known = Class(assembly, space, "Known", ModelTypes.VisibilityKind.Public);
        Method(known, "Private", ModelTypes.VisibilityKind.Private);
        Method(known, "UnknownMember", ModelTypes.VisibilityKind.Unknown);
        return assembly;
    }

    // A public Syn.Merge with a private static void Op() carrying [Syn.InvokeAttribute]; with overloads, also a public int
    // Op() that is a P/Invoke. Every visibility is known.
    private static Model.Assembly MergeAssembly(string name, bool withOverloads)
    {
        var (assembly, space) = Shell(name);
        var type = Class(assembly, space, "Merge", ModelTypes.VisibilityKind.Public);
        var invoked = Method(type, "Op", ModelTypes.VisibilityKind.Private);
        invoked.IsStatic = withOverloads;
        if (withOverloads)
        {
            invoked.Attributes.Add(new ModelTypes.CustomAttribute { Type = SyntheticModel.TypeRef("Syn", "InvokeAttribute", assembly: name) });
            var native = Method(type, "Op", ModelTypes.VisibilityKind.Public, ModelTypes.PlatformTypes.Int32);
            native.IsStatic = true;
            native.IsExternal = true;
            native.IsPlatformInvoke = true;
            native.Body = null!;
        }
        return assembly;
    }

    // "Wide": internal Syn.B : Object, and internal Syn.C : Syn.B implementing `interfaces` own empty interfaces
    // Syn.I00…, with one public non-newslot virtual ToString(). Every visibility is known.
    private static MemberIndex Wide(int interfaces)
    {
        var (assembly, space) = Shell("Wide");
        Class(assembly, space, "B", ModelTypes.VisibilityKind.Assembly);
        var c = Class(assembly, space, "C", ModelTypes.VisibilityKind.Assembly);
        c.Base = SyntheticModel.TypeRef("Syn", "B", assembly: "Wide");
        for (var i = 0; i < interfaces; i++)
        {
            var name = $"I{i:00}";
            space.Types.Add(new ModelTypes.InterfaceDefinition(name) { ContainingAssembly = assembly, ContainingNamespace = space, Visibility = ModelTypes.VisibilityKind.Assembly });
            c.Interfaces.Add(SyntheticModel.TypeRef("Syn", name, assembly: "Wide"));
        }
        Method(c, "ToString", ModelTypes.VisibilityKind.Public, ModelTypes.PlatformTypes.String).IsVirtual = true;
        return MemberIndex.Build([(assembly, TypeForwarders.None)]);
    }

    private static (Model.Assembly Assembly, Model.Namespace Space) Shell(string name)
    {
        var assembly = new Model.Assembly(name);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace("Syn") { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;
        return (assembly, space);
    }

    private static ModelTypes.ClassDefinition Class(Model.Assembly assembly, Model.Namespace space, string name, ModelTypes.VisibilityKind visibility)
    {
        var type = new ModelTypes.ClassDefinition(name)
        {
            ContainingAssembly = assembly,
            ContainingNamespace = space,
            Base = SyntheticModel.TypeRef("System", "Object", assembly: "System.Runtime"),
            Visibility = visibility,
        };
        space.Types.Add(type);
        return type;
    }

    private static ModelTypes.MethodDefinition Method(ModelTypes.ClassDefinition type, string name, ModelTypes.VisibilityKind visibility, ModelTypes.IType? returnType = null)
    {
        var method = new ModelTypes.MethodDefinition(name, returnType ?? ModelTypes.PlatformTypes.Void)
        {
            ContainingType = type,
            Visibility = visibility,
            Body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode),
        };
        type.Methods.Add(method);
        return method;
    }
    #endregion

    #region Fields
    private const string MergedOp = "Syn.Merge.Op()";

    private static readonly HashSet<string> wideMethods = new(["Syn.C.ToString()"], StringComparer.Ordinal);

    private static readonly CapabilityMap invokeMap =
        CapabilityMap.Load(new StringReader("root-attribute Syn.InvokeAttribute RuntimeInvoked"), "synthetic.cm", CapabilityMap.Default);
    #endregion
}
