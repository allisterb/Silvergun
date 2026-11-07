namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The root classes, native imports, gaps and type liveness of <see cref="MethodGraph.Facts"/> (reachability R1, S1.2;
/// acceptance criterion 2), over <c>RootFixture</c> indexed alone with the built-in map. Every rule has a positive case
/// and its negative twin, as the fixture lays them out one namespace per rule. A method's mask is asserted exactly where
/// the rule leaves only one class possible, and by flag where another rule also applies (an internal type's
/// <c>Finalize</c> is also a <see cref="RootClass.PublicContract"/>, because its slot is the platform's).
/// </summary>
public sealed class RootClassTests : IClassFixture<RootFixtureModel>
{
    #region Constructors
    public RootClassTests(RootFixtureModel fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Premise
    // ---------------------------------------------------------------------------------------------------

    // The host stubs are next to the test assembly but never indexed or loaded, so the supertypes they declare are external.
    [Fact]
    public void Premise_OnlyTheFixtureIsIndexed_AndTheHostStubsAreExternal()
    {
        Assert.True(File.Exists(RootFixtureAssemblies.HostStubs));
        Assert.Equal([RootFixtureAssemblies.FixtureName], fixture.Index.Assemblies);
        Assert.Empty(fixture.Index.Types("Microsoft.Build.Framework.ITask"));
        Assert.Empty(fixture.Index.Types("Microsoft.CodeAnalysis.Diagnostics.DiagnosticAnalyzer"));
        Assert.Contains("Microsoft.Build.Framework.ITask", fixture.Index.SupertypeKeys($"{Host}.BuildTask"));
        Assert.DoesNotContain(AppDomain.CurrentDomain.GetAssemblies(), a => a.GetName().Name is RootFixtureAssemblies.FixtureName or RootFixtureAssemblies.HostStubsName);
    }

    // Every own node has facts, and only own nodes do; ordinal-sorted, one row per node id.
    [Fact]
    public void Facts_CoverEveryOwnNodeOnce_InOrdinalOrder()
    {
        var own = fixture.Graph.Nodes.Where(n => n.Kind != MethodNodeKind.External).Select(n => n.NodeId).ToArray();
        var facts = fixture.Graph.Facts.Methods.Select(f => f.NodeId).ToArray();

        Assert.Equal(own.Order(StringComparer.Ordinal), facts);
        Assert.Equal(facts.Order(StringComparer.Ordinal), facts);
        Assert.Equal(fixture.Index.Methods.Select(m => m.NodeId).Distinct().Order(StringComparer.Ordinal), facts);
        Assert.All(fixture.Graph.Facts.Methods, f => Assert.Equal(RootFixtureAssemblies.FixtureName, f.Assembly));
    }

    [Fact]
    public void Facts_CarryTheDeclaringTypeAndStaticness()
    {
        Assert.Equal(new OwnMethodFacts($"{Host}.BuildTask.Execute()", RootFixtureAssemblies.FixtureName, $"{Host}.BuildTask", Facts($"{Host}.BuildTask.Execute()").Roots, false, false), Facts($"{Host}.BuildTask.Execute()"));
        Assert.Equal($"{LoadTime}.Startup", Facts($"{LoadTime}.Startup.OnLoad()").DeclaringTypeId);
        Assert.True(Facts($"{LoadTime}.Startup.OnLoad()").IsStatic);
    }

    // Hidden is set exactly when no other class is.
    [Fact]
    public void Hidden_IsSetExactlyWhenNoOtherClassIs()
    {
        Assert.All(fixture.Graph.Facts.Methods, f =>
            Assert.True(f.Roots.HasFlag(RootClass.Hidden) == ((f.Roots & ~RootClass.Hidden) == RootClass.None) && f.Roots != RootClass.None, $"{f.NodeId}: {f.Roots}"));
    }

    // ---------------------------------------------------------------------------------------------------
    // LoadTime
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void LoadTime_AStaticModuleInitializer_IsLoadTimeOnly()
    {
        Assert.Equal(RootClass.LoadTime, Roots($"{LoadTime}.Startup.OnLoad()"));
    }

    [Fact]
    public void LoadTime_TheSameStaticMethodWithoutTheAttribute_IsHidden()
    {
        Assert.Equal(RootClass.Hidden, Roots($"{LoadTime}.Startup.NotOnLoad()"));
    }

    // The attribute list is data: under a map that does not name ModuleInitializerAttribute, nothing is LoadTime.
    [Fact]
    public void LoadTime_UnderAMapWithoutTheBuiltInEntry_IsNotTagged()
    {
        var graph = MethodGraph.Build(fixture.Index, map: CapabilityMap.Load(new StringReader(string.Empty), "empty.cm"));

        Assert.Equal(RootClass.Hidden, Roots(graph, $"{LoadTime}.Startup.OnLoad()"));
        Assert.DoesNotContain(graph.Facts.Methods, f => f.Roots.HasFlag(RootClass.LoadTime));
    }

    // A map's own root-attribute entries tag the methods carrying them; LoadTime only on a static method.
    [Theory]
    [InlineData("Custom.StaticLoad()", RootClass.LoadTime)]
    [InlineData("CustomInstance.InstanceLoad()", RootClass.Hidden)]
    [InlineData("Custom.StaticInvoke()", RootClass.NativeEntry)]
    [InlineData("CustomInstance.InstanceInvoke()", RootClass.NativeEntry)]
    public void RootAttribute_FromASuppliedMap_TagsTheMethodsCarryingIt(string method, RootClass expected)
    {
        var graph = MethodGraph.Build(fixture.Index, map: customAttributeMap);

        Assert.Equal(expected, Roots(graph, $"{LoadTime}.{method}"));
        Assert.Equal(RootClass.LoadTime, Roots(graph, $"{LoadTime}.Startup.OnLoad()"));   // the base's entry survives the layering
    }

    // ...and without that map the same methods are untagged.
    [Theory]
    [InlineData("Custom.StaticLoad()")]
    [InlineData("Custom.StaticInvoke()")]
    [InlineData("CustomInstance.InstanceInvoke()")]
    public void RootAttribute_NotInTheMap_TagsNothing(string method)
    {
        Assert.Equal(RootClass.Hidden, Roots($"{LoadTime}.{method}"));
    }

    // C# emits <Module>..cctor for a [ModuleInitializer]; the model cannot see it, so LoadTime is a gap for the assembly.
    // It is the only gap here: every visibility is known and the module is readable.
    [Fact]
    public void Gaps_AnAssemblyWithAModuleInitializer_HasExactlyOneLoadTimeGap()
    {
        var gap = Assert.Single(fixture.Graph.Facts.Gaps);

        Assert.Equal(RootFixtureAssemblies.FixtureName, gap.Assembly);
        Assert.Equal(RootClass.LoadTime, gap.Class);
        Assert.False(string.IsNullOrWhiteSpace(gap.Reason));
        Assert.True(fixture.Index.Module(RootFixtureAssemblies.FixtureName).HasModuleInitializer);
    }

    [Fact]
    public void Gaps_AnAssemblyWithoutAModuleInitializer_HasNoLoadTimeGap()
    {
        using var assemblies = ModelAssemblies.Load(MechanismFixtureAssemblies.Dependency);
        var index = assemblies.Index();
        var graph = MethodGraph.Build(index);

        Assert.True(index.Module(MechanismFixtureAssemblies.DependencyName).IsReadable);
        Assert.False(index.Module(MechanismFixtureAssemblies.DependencyName).HasModuleInitializer);
        Assert.Empty(graph.Facts.Gaps);
    }

    // ---------------------------------------------------------------------------------------------------
    // HostContract
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("BuildTask.Execute()")]
    [InlineData("BuildTask.Helper()")]
    [InlineData("BuildTask..ctor()")]
    [InlineData("DerivedBuildTask.More()")]          // below the contract through an own base class
    [InlineData("DerivedBuildTask..ctor()")]
    [InlineData("ViaOwnInterface.Execute()")]        // below it through an own interface
    [InlineData("ViaOwnInterface..ctor()")]
    [InlineData("IOwnTask.Log()")]                   // the own interface itself
    [InlineData("AbstractTask.Execute()")]           // an own abstract class: its members run through a concrete subtype
    [InlineData("AbstractTask.Shared()")]
    [InlineData("AbstractTask..ctor()")]
    [InlineData("Analyzer..ctor()")]                // below the abstract analyzer: its constructor is what the host runs
    [InlineData("Analyzer.Initialize(System.Object)")]
    public void HostContract_EveryMethodOfAnOwnTypeBelowAHostContract_IsTagged(string method)
    {
        Assert.True(Roots($"{Host}.{method}").HasFlag(RootClass.HostContract), Roots($"{Host}.{method}").ToString());
    }

    [Theory]
    [InlineData("NotATask.Execute()")]       // the same shape below a contract no entry names
    [InlineData("NotATask..ctor()")]
    [InlineData("PlainTask.Execute()")]      // the same shape below nothing
    [InlineData("PlainTask..ctor()")]
    public void HostContract_TheSameShapeBelowNoHostContract_IsNotTagged(string method)
    {
        Assert.False(Roots($"{Host}.{method}").HasFlag(RootClass.HostContract), Roots($"{Host}.{method}").ToString());
    }

    [Fact]
    public void HostContract_UnderAMapWithoutTheBuiltInEntries_IsNotTagged()
    {
        var graph = MethodGraph.Build(fixture.Index, map: CapabilityMap.Load(new StringReader(string.Empty), "empty.cm"));

        Assert.DoesNotContain(graph.Facts.Methods, f => f.Roots.HasFlag(RootClass.HostContract));
    }

    // A map's own host-contract entry tags below it, by exact type node id.
    [Fact]
    public void HostContract_FromASuppliedMap_TagsBelowItsSupertype()
    {
        var graph = MethodGraph.Build(fixture.Index, map: CapabilityMap.Load(new StringReader("host-contract HostStubs.INotAHostTask"), "override.cm", CapabilityMap.Default));

        Assert.True(Roots(graph, $"{Host}.NotATask.Execute()").HasFlag(RootClass.HostContract));
        Assert.True(Roots(graph, $"{Host}.NotATask..ctor()").HasFlag(RootClass.HostContract));
        Assert.False(Roots(graph, $"{Host}.PlainTask.Execute()").HasFlag(RootClass.HostContract));
    }

    // ---------------------------------------------------------------------------------------------------
    // TypeInitializer, Finalizer, NativeEntry (ADR 0037 amendment a1: RuntimeInvoked split three ways)
    // ---------------------------------------------------------------------------------------------------

    // Exact: TypeInitializer and nothing else, so neither Finalizer nor NativeEntry.
    [Fact]
    public void TypeInitializer_ATypeInitializer_IsTypeInitializerOnly()
    {
        Assert.Equal(RootClass.TypeInitializer, Roots($"{Invoked}.WithTypeInitializer..cctor()"));
    }

    [Fact]
    public void TypeInitializer_AStaticMethodThatIsNotATypeInitializer_IsHidden()
    {
        Assert.Empty(fixture.Index.Definitions($"{Invoked}.WithoutTypeInitializer..cctor()"));
        Assert.Equal(RootClass.Hidden, Roots($"{Invoked}.WithoutTypeInitializer.Initialize()"));
    }

    // ~T() compiles to an override of Object.Finalize. Its slot is the platform's, so it is a PublicContract as well, and
    // it is neither of the other two runtime classes.
    [Fact]
    public void Finalizer_AFinalizer_IsFinalizerAndPublicContract_NotTypeInitializerOrNativeEntry()
    {
        Assert.Equal(RootClass.Finalizer | RootClass.PublicContract, Roots($"{Invoked}.WithFinalizer.Finalize()"));
    }

    // A new-slot Finalize hides Object.Finalize, so the runtime never calls it; an overload with a parameter is not the
    // finalizer either. Neither is any runtime class.
    [Theory]
    [InlineData("WithNewSlotFinalize.Finalize()")]
    [InlineData("WithFinalizeOverload.Finalize(System.Int32)")]
    public void Finalizer_AFinalizeThatIsNotTheFinalizer_IsNotTagged(string method)
    {
        Assert.True(fixture.Method($"{Invoked}.{method}").Definition.Name == "Finalize");
        Assert.Equal(RootClass.None, Roots($"{Invoked}.{method}") & (RootClass.TypeInitializer | RootClass.Finalizer | RootClass.NativeEntry));
    }

    // Exact: NativeEntry and nothing else, so neither TypeInitializer nor Finalizer.
    [Fact]
    public void NativeEntry_AnUnmanagedCallersOnlyMethod_IsNativeEntryOnly()
    {
        Assert.Equal(RootClass.NativeEntry, Roots($"{Invoked}.Exports.Exported()"));
    }

    [Fact]
    public void NativeEntry_TheSameMethodWithoutUnmanagedCallersOnly_IsHidden()
    {
        Assert.Equal(RootClass.Hidden, Roots($"{Invoked}.Exports.NotExported()"));
    }

    // Over the whole fixture, each runtime class is on exactly its own members: TypeInitializer only on .cctors, Finalizer
    // only on Finalize(), NativeEntry only on the one [UnmanagedCallersOnly] method.
    [Fact]
    public void RuntimeClasses_AreEachSetOnlyOnTheirOwnKindOfMember()
    {
        var methods = fixture.Graph.Facts.Methods;

        Assert.All(methods.Where(f => f.Roots.HasFlag(RootClass.TypeInitializer)), f => Assert.EndsWith("..cctor()", f.NodeId, StringComparison.Ordinal));
        Assert.All(methods.Where(f => f.Roots.HasFlag(RootClass.Finalizer)), f => Assert.EndsWith(".Finalize()", f.NodeId, StringComparison.Ordinal));
        Assert.Equal([$"{Invoked}.Exports.Exported()"], methods.Where(f => f.Roots.HasFlag(RootClass.NativeEntry)).Select(f => f.NodeId));
        Assert.Contains(methods, f => f.Roots.HasFlag(RootClass.TypeInitializer));
        Assert.Contains(methods, f => f.Roots.HasFlag(RootClass.Finalizer));
    }

    // ---------------------------------------------------------------------------------------------------
    // PublicApi
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("OpenType.PublicMethod()")]
    [InlineData("OpenType..ctor()")]
    [InlineData("OpenType.ProtectedMethod()")]                // Family on an unsealed public type
    [InlineData("OpenType.ProtectedInternalMethod()")]        // FamilyOrAssembly on an unsealed public type
    [InlineData("OpenType.PublicNested.PublicMethod()")]      // public in public
    [InlineData("OpenType.ProtectedNested.PublicMethod()")]   // a Family nested type of an unsealed public type
    [InlineData("SealedType.PublicMethod()")]
    [InlineData("IApi.Run()")]
    [InlineData("PublicExplicit.RootFixture.Api.IApi.Run()")] // a private explicit implementation on a public type
    public void PublicApi_AnExternallyVisibleMethod_IsPublicApiOnly(string method)
    {
        Assert.Equal(RootClass.PublicApi, Roots($"{Api}.{method}"));
    }

    [Theory]
    [InlineData("OpenType.InternalMethod()")]
    [InlineData("OpenType.PrivateProtectedMethod()")]                // FamilyAndAssembly is not visible outside
    [InlineData("OpenType.PrivateMethod()")]                         // private, and not an explicit implementation
    [InlineData("OpenType.PrivateNested.PublicMethod()")]            // a private link on the nesting chain
    [InlineData("SealedType.ProtectedMethod()")]                     // Family on a sealed type: no subclass can call it
    [InlineData("SealedType.ProtectedInternalMethod()")]
    [InlineData("SealedType.ProtectedNested.M()")]                   // a Family nested type of a sealed container
    [InlineData("SealedType.ProtectedInternalNested.M()")]           // and a FamilyOrAssembly one
    [InlineData("InternalExplicit.RootFixture.Api.IInternalApi.Run()")] // an explicit implementation on an internal type
    [InlineData("InternalType.PublicMethod()")]                      // public on an internal type
    [InlineData("InternalType..ctor()")]
    public void PublicApi_AMethodNoConsumerCanName_IsHidden(string method)
    {
        Assert.Equal(RootClass.Hidden, Roots($"{Api}.{method}"));
    }

    // ---------------------------------------------------------------------------------------------------
    // PublicContract
    // ---------------------------------------------------------------------------------------------------

    // Rule (a): CHA from the visible IWidget.Spin reaches the internal Widget.Spin.
    [Fact]
    public void PublicContract_RuleA_AnInternalImplementationOfAPublicOwnInterface_IsPublicContractOnly()
    {
        Assert.Equal(RootClass.PublicApi, Roots($"{Contract}.IWidget.Spin()"));
        Assert.Equal(RootClass.PublicContract, Roots($"{Contract}.Widget.Spin()"));
    }

    [Fact]
    public void PublicContract_RuleA_TheSameShapeBehindAnInternalInterface_IsHidden()
    {
        Assert.Equal(RootClass.Hidden, Roots($"{Contract}.IGadget.Spin()"));
        Assert.Equal(RootClass.Hidden, Roots($"{Contract}.Gadget.Spin()"));
    }

    // Rule (b): the slot is declared outside the index - Object.ToString (an override) and IComparer<string>.Compare
    // (a new slot on a type implementing an external interface).
    [Theory]
    [InlineData("Printable.ToString()")]
    [InlineData("OrdinalComparer.Compare(System.String,System.String)")]
    public void PublicContract_RuleB_FillingAnExternallyDeclaredSlot_IsPublicContractOnly(string method)
    {
        Assert.Equal(RootClass.PublicContract, Roots($"{Contract}.{method}"));
    }

    // Twins of (b): a new slot on a type with no external interface, and an override of an own slot.
    [Theory]
    [InlineData("OwnSlot.Go()")]
    [InlineData("OwnSlotOverride.Go()")]
    public void PublicContract_RuleB_AVirtualWhoseSlotIsOwn_IsHidden(string method)
    {
        Assert.Equal(RootClass.Hidden, Roots($"{Contract}.{method}"));
    }

    // "Not PublicApi": a visible override is PublicApi and nothing else, though its slot is declared elsewhere too.
    [Fact]
    public void PublicContract_IsNeverSetOnAPublicApiMethod()
    {
        Assert.Equal(RootClass.PublicApi, Roots("RootFixture.Flags.OpenShape.Draw()"));
        Assert.DoesNotContain(fixture.Graph.Facts.Methods, f => f.Roots.HasFlag(RootClass.PublicApi) && f.Roots.HasFlag(RootClass.PublicContract));
    }

    // ---------------------------------------------------------------------------------------------------
    // PublicContract regressions (S1 review C1/C2/W1): slots the first ImplementsExternalSlot missed
    // ---------------------------------------------------------------------------------------------------

    // Each was a false negative: the method fills (or overrides an own method that fills) a slot declared outside the index.
    [Theory]
    [InlineData("D.Equals(System.Object)")]                          // a record's override of Object.Equals
    [InlineData("D.Equals(RootFixture.Slots.R)")]                    // overrides R.Equals(R), which implements IEquatable<R> (rule a)
    [InlineData("R.Equals(RootFixture.Slots.R)")]                    // the new slot implementing IEquatable<R> (rule b)
    [InlineData("EqDerived.Equals(System.Object)")]                  // an own new slot Equals(EqBase) does not mask it
    [InlineData("Named.ToString()")]                                 // an own interface's ToString does not mask Object's
    [InlineData("Both.Dispose()")]                                   // fills IMyDisposable's slot and IDisposable's at once
    [InlineData("CmpBase.Compare(System.String,System.String)")]     // an abstract new slot implementing IComparer<string> (rule b)
    [InlineData("CmpImpl.Compare(System.String,System.String)")]     // its override (rule a)
    [InlineData("ClosedSlotOverride.Take(System.String)")]           // a generic ancestor's slot (!0) masks nothing: errs toward true
    public void PublicContract_Regression_AnExternallyDeclaredSlot_IsPublicContractOnly(string method)
    {
        Assert.Equal(RootClass.PublicContract, Roots($"{Slots}.{method}"));
    }

    // The explicit default implementation an interface gives a platform interface member.
    [Fact]
    public void PublicContract_Regression_AnInterfacesExplicitDefaultOverride_IsPublicContractOnly()
    {
        var method = Assert.Single(fixture.Index.Methods, m => m.DeclaringTypeId == $"{Slots}.IDim" && m.Definition.Name.EndsWith(".GetEnumerator", StringComparison.Ordinal));

        Assert.Equal("System.Collections.Generic.IEnumerable<System.Int32>.GetEnumerator", method.Definition.Name);
        Assert.Equal(RootClass.PublicContract, Roots(method.NodeId));
    }

    // Twins: a fresh virtual nothing outside declares; an override of an own new slot with exactly the same, fully known
    // parameters, and that slot; the generic own slot; an own interface's own member (it declares a slot, fills none).
    [Theory]
    [InlineData("Fresh.Go()")]
    [InlineData("SlotBase.Take(System.String)")]
    [InlineData("SlotOverride.Take(System.String)")]
    [InlineData("GenericSlot`1.Take(!0)")]
    [InlineData("INamed.ToString()")]
    [InlineData("IMyDisposable.Dispose()")]
    public void PublicContract_Regression_AVirtualWhoseSlotIsOwn_IsHidden(string method)
    {
        Assert.Equal(RootClass.Hidden, Roots($"{Slots}.{method}"));
    }

    // N1 (S1 review): a public static method of a type with an external maybe-interface supertype may implement a
    // platform static abstract member (here IAdditionOperators<Num,Num,Num>.op_Addition), which generic code calls back.
    [Fact]
    public void PublicContract_N1_APublicStaticOperatorImplementingAPlatformStaticAbstract_IsPublicContractOnly()
    {
        Assert.Equal(RootClass.PublicContract, Roots($"{Statics}.Num.op_Addition({Statics}.Num,{Statics}.Num)"));
    }

    // Twins: a private non-explicit static on the same type; an internal static on it; a public static on an internal
    // type with no external interface.
    [Theory]
    [InlineData("Num.Twice(RootFixture.Statics.Num)")]
    [InlineData("Num.UseTwice(RootFixture.Statics.Num)")]
    [InlineData("Helpers.Pure(System.Int32)")]
    public void PublicContract_N1_AStaticThatCannotImplementAPlatformMember_IsHidden(string method)
    {
        Assert.Equal(RootClass.Hidden, Roots($"{Statics}.{method}"));
    }

    // ---------------------------------------------------------------------------------------------------
    // Budgets: past either allowance the answer errs toward more roots, and a gap says so
    // ---------------------------------------------------------------------------------------------------

    // A zero allowance: every virtual's slot counts as external, so a Hidden twin becomes PublicContract, and both a
    // Hidden and a PublicContract gap are recorded. The shared index serves, since the slot memo lives on the build's
    // DispatchWork rather than the index (S1 review W2-r2).
    [Fact]
    public void Budget_ExhaustedSlotAndDispatchWork_CountsVirtualsAsPublicContract_AndRecordsBothGaps()
    {
        var facts = Collect(fixture.Index, maxDispatchWork: 0);

        Assert.Contains(facts.Gaps, g => g.Class == RootClass.Hidden && g.Reason.Contains("slot work budget", StringComparison.Ordinal));
        Assert.Contains(facts.Gaps, g => g.Class == RootClass.PublicContract);
        Assert.Equal(RootClass.PublicContract, Assert.Single(facts.Methods, f => f.NodeId == $"{Slots}.SlotOverride.Take(System.String)").Roots);
        Assert.Equal(RootClass.Hidden, Assert.Single(facts.Methods, f => f.NodeId == "RootFixture.Hidden.Unreferenced.Nothing()").Roots);   // not virtual: no slot to guess
    }

    // The default budget leaves neither gap on this fixture.
    [Fact]
    public void Budget_NotExhausted_RecordsNoBudgetGap()
    {
        Assert.DoesNotContain(fixture.Graph.Facts.Gaps, g => g.Class is RootClass.Hidden or RootClass.PublicContract);
    }

    // W2-r2 (S1 review): one build's answers never depend on an earlier build over the same index. On a fresh index,
    // zero budget, then the default, then zero again: the two zero-budget builds are equal. With the memo on the index the
    // default build filled it, and the second zero build read answers the first could not afford.
    [Fact]
    public void Budget_BuildsOverOneIndex_AreIndependent_ZeroDefaultZeroGiveEqualZeroBudgetFacts()
    {
        var index = fixture.Assemblies.Index();

        var first = Collect(index, maxDispatchWork: 0);
        var full = Collect(index, maxDispatchWork: GraphBudget.Default.MaxDispatchWork);
        var second = Collect(index, maxDispatchWork: 0);

        Assert.Equal(first.Methods, second.Methods);
        Assert.Equal(first.Types, second.Types);
        Assert.Equal(first.Gaps, second.Gaps);
        // The premise: the full build really differs, so the equality above is not vacuous.
        Assert.NotEqual(first.Methods, full.Methods);
        Assert.Equal(fixture.Graph.Facts.Methods, full.Methods);
    }

    // ---------------------------------------------------------------------------------------------------
    // Fallback: if collection throws, nothing may read as None
    // ---------------------------------------------------------------------------------------------------

    // The edges are read after classification; an enumeration that throws there reaches Collect's catch.
    [Fact]
    public void Collect_WhenCollectionThrows_IsTotal_EveryNodePublicApi_EveryTypeLive_OneGapForAllClasses()
    {
        string[] own = ["Zeta.Unindexed()", $"{Host}.BuildTask.Execute()", "RootFixture.Hidden.Unreferenced.Nothing()"];

        var facts = GraphFacts.Collect(fixture.Index, own.ToHashSet(StringComparer.Ordinal), ThrowingEdges(), CapabilityMap.Default, maxDispatchWork: long.MaxValue);

        Assert.Equal(own.Order(StringComparer.Ordinal), facts.Methods.Select(f => f.NodeId));
        Assert.All(facts.Methods, f => Assert.Equal(RootClass.PublicApi, f.Roots));
        Assert.Equal(fixture.Index.TypeIds, facts.Types.Select(t => t.TypeId));
        Assert.All(facts.Types, t => Assert.True(t.Live, t.TypeId));
        var gap = Assert.Single(facts.Gaps);
        Assert.Equal(
            RootClass.LoadTime | RootClass.HostContract | RootClass.TypeInitializer | RootClass.Finalizer | RootClass.NativeEntry
                | RootClass.PublicApi | RootClass.PublicContract | RootClass.Hidden,
            gap.Class);
        Assert.Contains(EdgesFailure, gap.Reason, StringComparison.Ordinal);
    }

    // The fallback gap's reason bounds the exception text (S0-S3 review, Nit 2): a 5,000-char message is cut as a name is.
    [Fact]
    public void Collect_WhenCollectionThrowsALongMessage_TheGapReasonIsBounded()
    {
        var message = "the edges went away: " + new string('e', 5000);

        var facts = GraphFacts.Collect(fixture.Index, new HashSet<string>(StringComparer.Ordinal) { "RootFixture.Hidden.Unreferenced.Nothing()" },
            ThrowingEdges(message), CapabilityMap.Default, maxDispatchWork: long.MaxValue);

        var gap = Assert.Single(facts.Gaps);
        Assert.Equal($"root facts could not be collected: {Reachability.BoundName(message)}", gap.Reason);
        Assert.True(gap.Reason.Length <= Reachability.MaxNameChars + 128, $"{gap.Reason.Length} chars");
        Assert.DoesNotContain(message, gap.Reason, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------------------
    // Hidden
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Unreferenced.Nothing()")]
    [InlineData("Unreferenced..ctor()")]
    public void Hidden_AnInternalMethodOfAnInternalTypeNothingReferences_IsHiddenOnly(string method)
    {
        Assert.Equal(RootClass.Hidden, Roots($"RootFixture.Hidden.{method}"));
    }

    [Theory]
    [InlineData("RootFixture.Api.OpenType.PublicMethod()")]
    [InlineData("RootFixture.LoadTime.Startup.OnLoad()")]
    [InlineData("RootFixture.Contract.Widget.Spin()")]
    public void Hidden_IsNotSetOnAMethodCarryingAnotherClass(string method)
    {
        Assert.False(Roots(method).HasFlag(RootClass.Hidden));
    }

    // ---------------------------------------------------------------------------------------------------
    // NativeImport
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("RootFixture.Native.NativeMethods.GetTickCount()", true)]
    [InlineData("RootFixture.Native.NativeMethods.InternalTickCount()", false)]   // external, but an internalcall
    [InlineData("RootFixture.Native.NativeMethods.ManagedTickCount()", false)]
    public void NativeImport_IsSetOnlyForAPInvoke(string method, bool expected)
    {
        Assert.Equal(expected, Facts(method).NativeImport);
    }

    [Fact]
    public void NativeImport_IsSetOnExactlyTheFixturesTwoDllImports()
    {
        Assert.Equal(
            ["RootFixture.Flags.Externs.GetTickCount()", "RootFixture.Native.NativeMethods.GetTickCount()"],
            fixture.Graph.Facts.Methods.Where(f => f.NativeImport).Select(f => f.NodeId));
    }

    // ---------------------------------------------------------------------------------------------------
    // InternalCall (S3): a body-less extern that is no P/Invoke, outside a delegate
    // ---------------------------------------------------------------------------------------------------

    // [MethodImpl(MethodImplOptions.InternalCall)] extern: external, no P/Invoke, so an internalcall a Mono or Unity host
    // may bind to native code.
    [Theory]
    [InlineData("RootFixture.Native.NativeMethods.InternalTickCount()")]
    [InlineData("RootFixture.Flags.Externs.InternalCall()")]
    public void InternalCall_AnInternalCallExtern_IsSet_AndIsNoNativeImport(string method)
    {
        var definition = fixture.Method(method).Definition;
        Assert.True(definition.IsExternal && !definition.IsPlatformInvoke);   // the premise

        Assert.Equal((true, false), (Facts(method).InternalCall, Facts(method).NativeImport));
    }

    // A [DllImport] is external too, but it is a NativeImport, never an InternalCall.
    [Theory]
    [InlineData("RootFixture.Native.NativeMethods.GetTickCount()")]
    [InlineData("RootFixture.Flags.Externs.GetTickCount()")]
    public void InternalCall_APInvoke_IsNotSet_ItIsANativeImport(string method)
    {
        Assert.True(fixture.Method(method).Definition.IsExternal);   // the premise

        Assert.Equal((false, true), (Facts(method).InternalCall, Facts(method).NativeImport));
    }

    // A delegate's .ctor, Invoke, BeginInvoke and EndInvoke are runtime-implemented: external, no body and no P/Invoke,
    // exactly like an internalcall in the flags, but they run what the delegate was bound to, which the graph follows.
    [Fact]
    public void InternalCall_ADelegatesRuntimeImplementedMembers_AreNotSet()
    {
        var members = fixture.Graph.Facts.Methods.Where(f => f.DeclaringTypeId == $"{Native}.TickSource").ToArray();

        Assert.Equal([".ctor", "BeginInvoke", "EndInvoke", "Invoke"], members.Select(f => fixture.Method(f.NodeId).Definition.Name).Order(StringComparer.Ordinal));
        Assert.All(members, f =>
        {
            var definition = fixture.Method(f.NodeId).Definition;
            Assert.True(definition.IsExternal && !definition.IsPlatformInvoke, $"{f.NodeId}: the premise");
            Assert.False(f.InternalCall, f.NodeId);
            Assert.False(f.NativeImport, f.NodeId);
        });
    }

    // The fork's MethodImpl flags (review round 2): a C# delegate's four members are runtime-implemented and not
    // runtime-internal; an internalcall extern is runtime-internal; a bodied method is neither.
    [Theory]
    [InlineData(".ctor", true, false)]
    [InlineData("Invoke", true, false)]
    [InlineData("BeginInvoke", true, false)]
    [InlineData("EndInvoke", true, false)]
    public void MethodImplFlags_ACSharpDelegatesMembers_AreRuntimeImplemented_NotRuntimeInternal(string name, bool runtimeImplemented, bool runtimeInternal)
    {
        var member = Assert.Single(fixture.Graph.Facts.Methods, f => f.DeclaringTypeId == $"{Native}.TickSource" && fixture.Method(f.NodeId).Definition.Name == name);
        var definition = fixture.Method(member.NodeId).Definition;

        Assert.Equal((runtimeImplemented, runtimeInternal), (definition.IsRuntimeImplemented, definition.IsRuntimeInternal));
    }

    [Theory]
    [InlineData("RootFixture.Native.NativeMethods.InternalTickCount()", false, true)]
    [InlineData("RootFixture.Flags.Externs.InternalCall()", false, true)]
    [InlineData("RootFixture.Native.NativeMethods.ManagedTickCount()", false, false)]
    [InlineData("RootFixture.Api.OpenType.PublicMethod()", false, false)]
    public void MethodImplFlags_AnInternalCallIsRuntimeInternal_ABodiedMethodIsNeither(string method, bool runtimeImplemented, bool runtimeInternal)
    {
        var definition = fixture.Method(method).Definition;

        Assert.Equal((runtimeImplemented, runtimeInternal), (definition.IsRuntimeImplemented, definition.IsRuntimeInternal));
    }

    // Methods with a body, managed or not reachable from native code, are not internalcalls.
    [Theory]
    [InlineData("RootFixture.Native.NativeMethods.ManagedTickCount()")]
    [InlineData("RootFixture.Flags.Externs.Managed()")]
    [InlineData("RootFixture.Api.OpenType.PublicMethod()")]
    public void InternalCall_ABodiedMethod_IsNotSet(string method)
    {
        Assert.True(fixture.Method(method).Definition.HasBody);   // the premise

        Assert.False(Facts(method).InternalCall);
    }

    // An abstract or interface method has no body either, but it is no extern: what it runs is an override, which CHA's
    // Dispatch edges reach. Marking it unseen would make every call through an own interface "code we cannot see".
    [Theory]
    [InlineData("RootFixture.Live.AbstractBase.Run()")]
    [InlineData("RootFixture.Flags.AbstractShape.Draw()")]
    [InlineData("RootFixture.Api.IApi.Run()")]
    [InlineData("RootFixture.Contract.IWidget.Spin()")]
    public void InternalCall_AnAbstractOrInterfaceMethod_IsNotSet(string method)
    {
        Assert.False(fixture.Method(method).Definition.HasBody);   // the premise

        Assert.False(Facts(method).InternalCall, $"{method}: an abstract method is no internalcall");
    }

    // Over the whole fixture, exactly its two internalcalls.
    [Fact]
    public void InternalCall_IsSetOnExactlyTheFixturesTwoInternalCalls()
    {
        Assert.Equal(
            ["RootFixture.Flags.Externs.InternalCall()", "RootFixture.Native.NativeMethods.InternalTickCount()"],
            fixture.Graph.Facts.Methods.Where(f => f.InternalCall).Select(f => f.NodeId));
    }

    // ---------------------------------------------------------------------------------------------------
    // ComImport (S3 review W1): a body-less member of a [ComImport] class or interface is a COM call
    // ---------------------------------------------------------------------------------------------------

    // The premise: the fork records tdImport on both kinds of type, and only on [ComImport] ones.
    [Theory]
    [InlineData("RootFixture.Com.CoThing", true)]
    [InlineData("RootFixture.Com.ICoThing", true)]
    [InlineData("RootFixture.Com.IPlainThing", false)]
    [InlineData("RootFixture.Api.OpenType", false)]
    [InlineData("RootFixture.Api.IApi", false)]
    public void ComImport_Premise_TheModelTypesCarryIsComImport(string type, bool expected)
    {
        var isComImport = fixture.Type(type) switch
        {
            global::Model.Types.ClassDefinition c => c.IsComImport,
            global::Model.Types.InterfaceDefinition i => i.IsComImport,
            var other => throw new InvalidOperationException($"{type} is a {other.GetType().Name}"),
        };

        Assert.Equal(expected, isComImport);
    }

    // C# emits a [ComImport] class's implicit constructor `runtime managed internalcall`, and an interface method is
    // abstract: both external with no P/Invoke. Both are COM calls, never internalcalls.
    [Theory]
    [InlineData("RootFixture.Com.CoThing..ctor()", false)]
    [InlineData("RootFixture.Com.ICoThing.Run()", true)]
    public void ComImport_ABodylessMemberOfAComImportType_IsSet_AndIsNoInternalCall(string method, bool isAbstract)
    {
        var definition = fixture.Method(method).Definition;
        Assert.True(definition.IsExternal && !definition.IsPlatformInvoke && definition.IsAbstract == isAbstract);   // the premise

        Assert.Equal((true, false, false), (Facts(method).ComImport, Facts(method).InternalCall, Facts(method).NativeImport));
    }

    // Twin: the same shape on an ordinary own interface, and the callers themselves.
    [Theory]
    [InlineData("RootFixture.Com.IPlainThing.Run()")]
    [InlineData("RootFixture.Com.ComCallers.MakesCoThing()")]
    [InlineData("RootFixture.Com.ComCallers.CallsCoThing(RootFixture.Com.ICoThing)")]
    public void ComImport_AMemberOfAnOrdinaryType_IsNotSet(string method)
    {
        Assert.Equal((false, false), (Facts(method).ComImport, Facts(method).InternalCall));
    }

    // Over the whole fixture, exactly the two COM members.
    [Fact]
    public void ComImport_IsSetOnExactlyTheFixturesTwoComMembers()
    {
        Assert.Equal(
            ["RootFixture.Com.CoThing..ctor()", "RootFixture.Com.ICoThing.Run()"],
            fixture.Graph.Facts.Methods.Where(f => f.ComImport).Select(f => f.NodeId));
    }

    // ---------------------------------------------------------------------------------------------------
    // Live (the RTA tier)
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("NeverMade", false)]                 // internal, never instantiated
    [InlineData("Made", true)]                       // the same, instantiated with new
    [InlineData("PubliclyConstructible", true)]      // a consumer can construct it
    [InlineData("InternallyConstructible", false)]   // public, but no consumer-callable constructor and never made
    [InlineData("Value", true)]                      // a value type
    [InlineData("AbstractBase", true)]               // abstract, but its only subtype is instantiated
    [InlineData("Concrete", true)]
    [InlineData("LonelyBase", false)]                // the same hierarchy, never instantiated
    [InlineData("LonelyConcrete", false)]
    [InlineData("Makers", false)]                    // a static class is abstract
    public void Live_IsSetWhenTheTypeOrAnOwnSubtypeMayBeInstantiated(string type, bool expected)
    {
        var facts = Assert.Single(fixture.Graph.Facts.Types, t => t.TypeId == $"RootFixture.Live.{type}");

        Assert.Equal(expected, facts.Live);
        Assert.Equal(RootFixtureAssemblies.FixtureName, facts.Assembly);
    }

    // The instantiation premise of Made/Concrete is a NewObj edge to their constructors.
    [Fact]
    public void Live_Premise_TheMakersNewObjTheirTypes()
    {
        Assert.Contains(fixture.Graph.Edges, e => e.Kind == MethodEdgeKind.NewObj && e.To == "RootFixture.Live.Made..ctor()");
        Assert.Contains(fixture.Graph.Edges, e => e.Kind == MethodEdgeKind.NewObj && e.To == "RootFixture.Live.Concrete..ctor()");
        Assert.DoesNotContain(fixture.Graph.Edges, e => e.Kind == MethodEdgeKind.NewObj && e.To.StartsWith("RootFixture.Live.NeverMade.", StringComparison.Ordinal));
    }

    // One row per own type, ordinal-sorted.
    [Fact]
    public void Live_TypeFacts_CoverEveryOwnTypeOnce_InOrdinalOrder()
    {
        Assert.Equal(fixture.Index.TypeIds, fixture.Graph.Facts.Types.Select(t => t.TypeId));
    }

    // Facts of every own method of index, over the fixture graph's edges, with both allowances set to maxDispatchWork.
    private GraphFacts Collect(MemberIndex index, long maxDispatchWork) =>
        GraphFacts.Collect(index, index.Methods.Select(m => m.NodeId).ToHashSet(StringComparer.Ordinal), fixture.Graph.Edges, CapabilityMap.Default, maxDispatchWork);

    private static IEnumerable<MethodEdge> ThrowingEdges(string message = EdgesFailure)
    {
        yield return new MethodEdge("A.B()", "A.C()", MethodEdgeKind.NewObj, 0);
        throw new InvalidOperationException(message);
    }

    private OwnMethodFacts Facts(string nodeId) => Facts(fixture.Graph, nodeId);

    private RootClass Roots(string nodeId) => Facts(nodeId).Roots;

    private static RootClass Roots(MethodGraph graph, string nodeId) => Facts(graph, nodeId).Roots;

    private static OwnMethodFacts Facts(MethodGraph graph, string nodeId) =>
        graph.Facts.Methods.SingleOrDefault(f => f.NodeId == nodeId)
            ?? throw new InvalidOperationException($"No facts for '{nodeId}'. Own nodes: {string.Join(", ", graph.Facts.Methods.Select(f => f.NodeId))}");
    #endregion

    #region Fields
    private const string LoadTime = "RootFixture.LoadTime";
    private const string Host = "RootFixture.Host";
    private const string Invoked = "RootFixture.Runtime";
    private const string Api = "RootFixture.Api";
    private const string Contract = "RootFixture.Contract";
    private const string Slots = "RootFixture.Slots";
    private const string Statics = "RootFixture.Statics";
    private const string Native = "RootFixture.Native";
    private const string EdgesFailure = "the edges went away (synthetic)";

    // The built-in map with two fixture attributes added, one per class an attribute may confer.
    private static readonly CapabilityMap customAttributeMap = CapabilityMap.Load(
        new StringReader(
            """
            root-attribute RootFixture.LoadTime.CustomLoadAttribute LoadTime
            root-attribute RootFixture.LoadTime.CustomInvokeAttribute NativeEntry
            """),
        "override.cm",
        CapabilityMap.Default);

    private readonly RootFixtureModel fixture;
    #endregion
}
