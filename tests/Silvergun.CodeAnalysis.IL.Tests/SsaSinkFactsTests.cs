namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SsaSinkFactsFixture;

/// <summary>
/// The S4.2 sink facts (docs/agent/tasks/ssa-facts-s4.md §3, "Test cases to cover": Values, Text, Sites), end to end:
/// an emitted folder, <see cref="MethodGraph.Build"/>, <see cref="SinkSites.Of"/>, an <see cref="SsaSession"/> over the
/// same files, then <see cref="SsaSinkFacts.Extract"/>. Sites come from the graph (the join's other side), never written
/// by hand, except where a test needs a site the graph cannot give (a wrong offset or kind, a node not in the folder).
/// Also <see cref="SsaSession.Lift(Func{MethodIdentity, bool})"/>, which Extract lifts through.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaSinkFactsTests : IClassFixture<SsaSinkFactsFixture>
{
    #region Constructors
    public SsaSinkFactsTests(SsaSinkFactsFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- The sites, from the graph --------------------------------------------------------------------------------------

    // Every sink caller has a site, no other method has one, and each site names its edge kind, callee and capability.
    [Fact]
    public void Sites_FromTheGraph_EverySinkCallerAndNoOther()
    {
        var withSites = fixture.Sites.Select(s => s.NodeId).ToHashSet(StringComparer.Ordinal);

        Assert.All(SinkCallers, m => Assert.Contains(fixture.NodeIdOf(m), withSites));
        Assert.Equal(SinkCallers.Length, withSites.Count);
        Assert.Equal(2, fixture.Sites.Count(s => s.NodeId == fixture.NodeIdOf("TwoSites")));

        AssertSite("StartsCmd", MethodEdgeKind.Call, "System.Diagnostics.Process.Start(System.String)", "System.Diagnostics.Process.Start", Capability.ProcessExecution);
        AssertSite("ReadsConstant", MethodEdgeKind.Call, "System.IO.File.ReadAllText(System.String)", "System.IO.File.ReadAllText", Capability.FileSystem);
        AssertSite("NewFileStream", MethodEdgeKind.NewObj, "System.IO.FileStream..ctor(System.String,System.IO.FileMode)", "System.IO.FileStream..ctor", Capability.FileSystem);
        AssertSite("StartInstance", MethodEdgeKind.CallVirt, "System.Diagnostics.Process.Start()", "System.Diagnostics.Process.Start", Capability.ProcessExecution);
        AssertSite("StartInstanceCall", MethodEdgeKind.Call, "System.Diagnostics.Process.Start()", "System.Diagnostics.Process.Start", Capability.ProcessExecution);
        AssertSite("LdftnSink", MethodEdgeKind.Ldftn, "System.IO.File.ReadAllText(System.String)", "System.IO.File.ReadAllText", Capability.FileSystem);
        AssertSite("LdvirtftnSink", MethodEdgeKind.Ldvirtftn, "System.Reflection.MethodBase.Invoke(System.Object,System.Object[])", "System.Reflection.MethodBase.Invoke", Capability.ReflectionInvocation);
        AssertSite("TypeofString", MethodEdgeKind.Call, "System.Activator.CreateInstance(System.Type)", "System.Activator.CreateInstance", Capability.DynamicCodeLoading);
    }

    // ADR 0030: every site given reads with a status, in site order; here all Analyzed but the method that did not lift.
    [Fact]
    public void Facts_EveryFixtureSite_ReadsAStatus_AllAnalyzedButTheUnknownMethod()
    {
        var facts = fixture.Facts;
        var unknowable = fixture.NodeIdOf("Unknowable");

        Assert.Equal(fixture.Sites, facts.Sites.Select(f => f.Site));
        Assert.Equal((fixture.Sites.Count, false, false, false, false), (facts.SitesTotal, facts.Truncated, facts.MethodBudget, facts.TimeBudget, facts.TextBudget));
        Assert.All(facts.Sites, f =>
        {
            var expected = f.Site.NodeId == unknowable ? SsaSiteStatus.MethodUnknown : SsaSiteStatus.Analyzed;
            Assert.True(f.Status == expected, $"{Show(f)}: expected {expected}.");
            Assert.True(f.Status == SsaSiteStatus.Analyzed ? f.Reason is null && f.FailureKind is null : !string.IsNullOrEmpty(f.Reason), Show(f));
        });
        Assert.Equal(facts.Sites.Count - 1, facts.Count(SsaSiteStatus.Analyzed));
    }

    // ---- End to end ----------------------------------------------------------------------------------------------------

    [Fact]
    public void EndToEnd_ProcessStartOfConstant_ReadsAnalyzedConstant()
    {
        var fact = Fact("StartsCmd");

        Assert.Equal((SsaSiteStatus.Analyzed, Capability.ProcessExecution, 1, false), (fact.Status, fact.Site.Capability, fact.ArgumentCount, fact.Merged));
        Assert.Null(fact.Receiver);
        AssertValues([Str("cmd.exe")], fact.Arguments);
    }

    [Fact]
    public void EndToEnd_FileReadAllTextOfConstant_ReadsAnalyzedConstant()
    {
        var fact = Fact("ReadsConstant");

        Assert.Equal((SsaSiteStatus.Analyzed, Capability.FileSystem), (fact.Status, fact.Site.Capability));
        AssertValues([Str("x")], fact.Arguments);
    }

    // Two sites in one method, each with its own constant.
    [Fact]
    public void EndToEnd_TwoSitesInOneMethod_EachItsOwnConstant()
    {
        var facts = Facts(fixture.Facts, "TwoSites");

        Assert.Equal(2, facts.Length);
        Assert.True(facts[0].Site.Offset < facts[1].Site.Offset);
        AssertValues([Str("one")], facts[0].Arguments);
        AssertValues([Str("two")], facts[1].Arguments);
    }

    // ---- Values --------------------------------------------------------------------------------------------------------

    [Fact]
    public void Value_LdstrThroughPromotedLocal_IsConstant() =>
        AssertValues([Str(PromotedEscaped)], Fact("PromotedLocal").Arguments);

    // Ordinal: "Zeta" before "alpha" (a culture sort would put alpha first).
    [Fact]
    public void Value_PhiOfTwoConstants_IsOneOfSorted() =>
        AssertValues([OneOf(Str("Zeta"), Str("alpha"))], Fact("PhiOfTwo").Arguments);

    [Fact]
    public void Value_PhiOfMaxAlternatives_IsOneOf() =>
        AssertValues([OneOf(Str("c0"), Str("c1"), Str("c2"), Str("c3"))], Fact("PhiOfFour").Arguments);

    [Fact]
    public void Value_PhiOverMaxAlternatives_IsDynamicTooMany() =>
        AssertValues([Dynamic(SsaDynamicOrigin.TooManyAlternatives)], Fact("PhiOfFive").Arguments);

    // Twin: the same web under a bound one higher is the five constants.
    [Fact]
    public void Value_PhiOfFive_UnderBoundFive_IsOneOf()
    {
        var facts = Extract(new SsaFactBounds { MaxAlternatives = 5 }, fixture.SiteOf("PhiOfFive"));

        AssertValues([OneOf(Str("c0"), Str("c1"), Str("c2"), Str("c3"), Str("c4"))], Single(facts).Arguments);
    }

    // A loop: the header's phi and the join's phi feed each other.
    [Fact]
    public void Value_PhiCycle_Terminates() =>
        AssertValues([OneOf(Str("a"), Str("b"))], Fact("PhiCycle").Arguments);

    [Fact]
    public void Value_PhiCycle_PastMaxPhiDepth_IsDynamicTooDeep()
    {
        var facts = Extract(new SsaFactBounds { MaxPhiDepth = 1 }, fixture.SiteOf("PhiCycle"));

        AssertValues([Dynamic(SsaDynamicOrigin.TooDeep)], Single(facts).Arguments);
    }

    [Fact]
    public void Value_PhiCycle_PastMaxPhiInputs_IsDynamicTooDeep()
    {
        var facts = Extract(new SsaFactBounds { MaxPhiInputs = 1 }, fixture.SiteOf("PhiCycle"));

        AssertValues([Dynamic(SsaDynamicOrigin.TooDeep)], Single(facts).Arguments);
    }

    // MaxPhiInputs counts inputs read, not phis: the one phi of PhiOfFour has four, so 3 is past it and 4 is within.
    [Fact]
    public void Value_SinglePhi_PastMaxPhiInputs_IsDynamicTooDeep_AtTheBoundIsOneOf()
    {
        var past = Extract(new SsaFactBounds { MaxPhiInputs = 3 }, fixture.SiteOf("PhiOfFour"));
        var at = Extract(new SsaFactBounds { MaxPhiInputs = 4 }, fixture.SiteOf("PhiOfFour"));

        AssertValues([Dynamic(SsaDynamicOrigin.TooDeep)], Single(past).Arguments);
        AssertValues([OneOf(Str("c0"), Str("c1"), Str("c2"), Str("c3"))], Single(at).Arguments);
    }

    // Twin: one phi of two constants is no deeper than depth 1 and reads exactly two inputs.
    [Fact]
    public void Value_SinglePhi_UnderMaxPhiDepthOne_StillOneOf()
    {
        var facts = Extract(new SsaFactBounds { MaxPhiDepth = 1, MaxPhiInputs = 2 }, fixture.SiteOf("PhiOfTwo"));

        AssertValues([OneOf(Str("Zeta"), Str("alpha"))], Single(facts).Arguments);
    }

    // Sorted by kind, then text: String before Null.
    [Fact]
    public void Value_PhiOfStringAndNull_SortedByKindThenText()
    {
        var fact = Fact("PhiStringOrNull");

        AssertValue(Parameter(0), fact.Receiver);
        AssertValues([OneOf(Str("s"), Null), Null], fact.Arguments);
    }

    [Fact]
    public void Value_PhiOfConstantAndCall_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], Fact("PhiConstantOrCall").Arguments);

    [Fact]
    public void Value_PhiOfConstantAndParameter_IsDynamicOther() =>
        AssertValues([Dynamic(SsaDynamicOrigin.Other)], Fact("PhiConstantOrParameter").Arguments);

    [Fact]
    public void Value_PhiOfOneParameter_IsThatParameter() =>
        AssertValues([Parameter(1)], Fact("PhiSameParameter").Arguments);

    [Fact]
    public void Value_AddressTakenLocal_IsDynamicMemory() =>
        AssertValues([Dynamic(SsaDynamicOrigin.Memory)], Fact("AddressTaken").Arguments);

    // IL argument indexes: a static method's first is 0; an instance method's this is 0.
    [Fact]
    public void Value_OwnParameter_IsParameterN()
    {
        AssertValues([Parameter(1)], Fact("OwnParameter").Arguments);
        AssertValues([Parameter(1)], Fact("InstanceParameter").Arguments);

        var onThis = Fact("InvokeOnThis");
        AssertValue(Parameter(1), onThis.Receiver);
        AssertValues([Parameter(0), Null], onThis.Arguments);
    }

    [Theory]
    [InlineData("TypeofString", "System.String")]
    [InlineData("TypeofInt", "System.Int32")]
    [InlineData("TypeofNested", "Facts.Outer.Inner")]
    [InlineData("TypeofOwnGeneric", "Facts.G`1<System.Int32>")]
    [InlineData("TypeofListOfString", "System.Collections.Generic.List`1<System.String>")]
    [InlineData("TypeofOpenList", "System.Collections.Generic.List`1")]
    [InlineData("TypeofArray", "System.String[]")]
    [InlineData("TypeofMatrix", "System.Int32[,]")]
    public void Value_TypeofT_IsConstantTypeName(string method, string name) =>
        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Type, name))], Fact(method).Arguments);

    // W1: a type nested in a generic one renders as CciNames renders the same type in a signature. The oracle is the node
    // id CciNames gives Takes<Name>(that type), cross-checked against the graph's (the Model layer's) node id.
    [Theory]
    [InlineData("Enumerator")]
    [InlineData("KeyCollection")]
    [InlineData("OwnNested")]
    [InlineData("Deep")]
    public void Value_TypeofNestedInGeneric_IsCciNamesSignatureName(string name)
    {
        var takes = Assert.Single(fixture.Outcomes, o => o.MethodName == "Takes" + name).NodeId;
        Assert.Equal(fixture.NodeIdOf("Takes" + name), takes);
        var prefix = SitesType + ".Takes" + name + "(";
        Assert.StartsWith(prefix, takes, StringComparison.Ordinal);
        var oracle = takes[prefix.Length..^1];

        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Type, oracle))], Fact("Typeof" + name).Arguments);
    }

    // CciNames' rule, spelled out: a link adds its arguments only when it has parameters of its own, after its
    // container's; and a link without its own stops the containers' from being added.
    [Theory]
    [InlineData("Enumerator", "System.Collections.Generic.List.Enumerator`1")]
    [InlineData("KeyCollection", "System.Collections.Generic.Dictionary.KeyCollection`2")]
    [InlineData("OwnNested", "Facts.GOuter.Inner`2<System.Int32,System.String>")]
    [InlineData("Deep", "Facts.GOuter.Plain.Deep`2<System.Boolean>")]
    public void Value_TypeofNestedInGeneric_Spelled(string name, string expected) =>
        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Type, expected))], Fact("Typeof" + name).Arguments);

    [Fact]
    public void Value_StaticReadonlyField_IsDynamicFieldLoad() =>
        AssertValues([Dynamic(SsaDynamicOrigin.FieldLoad)], Fact("StaticField").Arguments);

    [Fact]
    public void Value_InstanceField_IsDynamicFieldLoad() =>
        AssertValues([Dynamic(SsaDynamicOrigin.FieldLoad)], Fact("InstanceField").Arguments);

    // No folding: string.Concat of two constants is a call's result.
    [Fact]
    public void Value_ConcatOfConstants_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], Fact("ConcatOfConstants").Arguments);

    [Fact]
    public void Value_CalliResult_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], Fact("CalliResult").Arguments);

    [Fact]
    public void Value_ArrayElement_IsDynamicArrayElement() =>
        AssertValues([Dynamic(SsaDynamicOrigin.ArrayElement)], Fact("ArrayElement").Arguments);

    [Fact]
    public void Value_Arithmetic_IsDynamicOther() =>
        AssertValues([Str("f"), Dynamic(SsaDynamicOrigin.Other)], Fact("FileStreamArithmetic").Arguments);

    // Int, Float and Null constants; a box is looked through.
    [Fact]
    public void Value_IntFloatNullConstants_AndBoxLookedThrough()
    {
        AssertValues([Str("f"), Int("3")], Fact("NewFileStream").Arguments);
        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Float, "2.5")), Null], Fact("InvokeFloat").Arguments);
        AssertValues([Int("-7"), Null], Fact("InvokeNegative").Arguments);
    }

    // ---- Receivers and arguments, per kind ------------------------------------------------------------------------------

    [Fact]
    public void Receiver_StaticCall_None()
    {
        var fact = Fact("WritesTwo");

        Assert.Null(fact.Receiver);
        Assert.Equal(2, fact.ArgumentCount);
        AssertValues([Str("p"), Str("c")], fact.Arguments);
    }

    [Theory]
    [InlineData("StartInstance", MethodEdgeKind.CallVirt)]
    [InlineData("StartInstanceCall", MethodEdgeKind.Call)]
    public void Receiver_InstanceCall_IsTheInstance_NotAnArgument(string method, MethodEdgeKind kind)
    {
        var fact = Fact(method);

        Assert.Equal((SsaSiteStatus.Analyzed, kind, 0), (fact.Status, fact.Site.EdgeKind, fact.ArgumentCount));
        AssertValue(Parameter(0), fact.Receiver);
        Assert.Empty(fact.Arguments);
    }

    [Fact]
    public void Receiver_NewObj_None()
    {
        var fact = Fact("NewFileStream");

        Assert.Equal((MethodEdgeKind.NewObj, 2), (fact.Site.EdgeKind, fact.ArgumentCount));
        Assert.Null(fact.Receiver);
    }

    [Fact]
    public void Receiver_Ldftn_NoneAndNoArguments()
    {
        var fact = Fact("LdftnSink");

        Assert.Equal((SsaSiteStatus.Analyzed, MethodEdgeKind.Ldftn, 0), (fact.Status, fact.Site.EdgeKind, fact.ArgumentCount));
        Assert.Null(fact.Receiver);
        Assert.Empty(fact.Arguments);
    }

    [Fact]
    public void Receiver_Ldvirtftn_IsTheObject()
    {
        var fact = Fact("LdvirtftnSink");

        Assert.Equal((SsaSiteStatus.Analyzed, MethodEdgeKind.Ldvirtftn, 0), (fact.Status, fact.Site.EdgeKind, fact.ArgumentCount));
        AssertValue(Parameter(0), fact.Receiver);
        Assert.Empty(fact.Arguments);
    }

    // The receiver does not count against MaxArguments; ArgumentCount is the whole signature's.
    [Fact]
    public void Arguments_OverMaxArguments_CutWithCount()
    {
        var facts = Extract(new SsaFactBounds { MaxArguments = 1 }, fixture.SiteOf("WritesTwo"), fixture.SiteOf("InvokeFloat"));

        var writes = Single(facts, "WritesTwo");
        var invoke = Single(facts, "InvokeFloat");

        Assert.Equal(2, writes.ArgumentCount);
        AssertValues([Str("p")], writes.Arguments);
        Assert.Equal(2, invoke.ArgumentCount);
        AssertValue(Parameter(0), invoke.Receiver);
        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Float, "2.5"))], invoke.Arguments);
    }

    // ---- Not joined ----------------------------------------------------------------------------------------------------

    // Offset 0 is the ldstr: the method lifted, but no call is there.
    [Fact]
    public void Sites_OffsetWithNoCall_NotJoined()
    {
        var real = fixture.SiteOf("ReadsConstant");
        Assert.NotEqual(0u, real.Offset);

        var fact = Single(Extract(SsaFactBounds.Default, real with { Offset = 0 }));

        AssertWithout(fact, SsaSiteStatus.NotJoined, NoCall(MethodEdgeKind.Call));
    }

    [Theory]
    [InlineData("ReadsConstant", MethodEdgeKind.NewObj)]
    [InlineData("ReadsConstant", MethodEdgeKind.Ldftn)]
    [InlineData("NewFileStream", MethodEdgeKind.Call)]
    [InlineData("LdftnSink", MethodEdgeKind.Ldvirtftn)]
    [InlineData("LdvirtftnSink", MethodEdgeKind.Ldftn)]
    public void Sites_WrongKindAtTheOffset_NotJoined(string method, MethodEdgeKind kind)
    {
        var fact = Single(Extract(SsaFactBounds.Default, fixture.SiteOf(method) with { EdgeKind = kind }));

        AssertWithout(fact, SsaSiteStatus.NotJoined, NoCall(kind));
    }

    // Call and CallVirt both join a call instruction (csc writes callvirt for non-virtual instance calls).
    [Theory]
    [InlineData("StartInstance", MethodEdgeKind.Call)]
    [InlineData("StartInstanceCall", MethodEdgeKind.CallVirt)]
    public void Sites_CallOrCallVirt_JoinsEitherCall(string method, MethodEdgeKind kind)
    {
        var fact = Single(Extract(SsaFactBounds.Default, fixture.SiteOf(method) with { EdgeKind = kind }));

        Assert.Equal(SsaSiteStatus.Analyzed, fact.Status);
        AssertValue(Parameter(0), fact.Receiver);
    }

    [Fact]
    public void Sites_NodeNotInTheFolder_NotJoined()
    {
        var fact = Single(Extract(SsaFactBounds.Default, fixture.SiteOf("ReadsConstant") with { NodeId = "Facts.Nowhere.M()" }));

        AssertWithout(fact, SsaSiteStatus.NotJoined, "no method with a body lifted under its node id");
        Assert.Equal(0, Extract(SsaFactBounds.Default, fixture.SiteOf("ReadsConstant") with { NodeId = "Facts.Nowhere.M()" }).MethodsLifted);
    }

    [Fact]
    public void Sites_OffsetPastInt32_NotJoined()
    {
        var fact = Single(Extract(SsaFactBounds.Default, fixture.SiteOf("ReadsConstant") with { Offset = uint.MaxValue }));

        AssertWithout(fact, SsaSiteStatus.NotJoined, NoCall(MethodEdgeKind.Call));
    }

    // A name past Reachability.MaxNameChars is bounded like a report's.
    [Fact]
    public void Sites_LongNames_BoundedLikeAReport()
    {
        var name = "Facts.Long." + new string('n', Reachability.MaxNameChars) + "()";
        var site = fixture.SiteOf("ReadsConstant") with { NodeId = name, Callee = name, CalleeKey = name };

        var fact = Single(Extract(SsaFactBounds.Default, site));

        Assert.Equal(Reachability.BoundName(name), fact.Site.NodeId);
        Assert.Equal(Reachability.BoundName(name), fact.Site.Callee);
        Assert.Equal(Reachability.BoundName(name), fact.Site.CalleeKey);
        Assert.StartsWith(name[..Reachability.MaxNameChars] + (char)0x2026 + "[+", fact.Site.NodeId, StringComparison.Ordinal);
        AssertWithout(fact, SsaSiteStatus.NotJoined, "no method with a body lifted under its node id");
    }

    // ---- Unknown methods and merged definitions -------------------------------------------------------------------------

    [Fact]
    public void Sites_UnknownMethod_ReadMethodUnknownWithKind()
    {
        var unknowable = fixture.NodeIdOf("Unknowable");
        var outcome = Assert.Single(fixture.Outcomes, o => o.NodeId == unknowable);
        Assert.NotNull(outcome.Failure);

        var fact = Fact("Unknowable");

        AssertWithout(fact, SsaSiteStatus.MethodUnknown, Reachability.BoundName(UntrustedText.Escape(outcome.Failure!.Reason)));
        Assert.Equal(outcome.Failure.Kind, fact.FailureKind);
        Assert.Contains(fixture.Facts.Unknown, u => u.Kind == outcome.Failure.Kind && u.Methods == 1);
    }

    [Fact]
    public void Sites_MergedDefinitions_UnionedAndMarked()
    {
        var run = Assert.Single(fixture.MergeFacts.Sites, f => f.Site.NodeId == fixture.MergeNodeIdOf("Run"));

        Assert.Equal((SsaSiteStatus.Analyzed, true), (run.Status, run.Merged));
        AssertValues([OneOf(Str("alpha"), Str("beta"))], run.Arguments);
    }

    // The same node id with the call at a different offset in each definition: two sites, each read from its own.
    [Fact]
    public void Sites_MergedDefinitionsAtDifferentOffsets_EachSiteFromItsOwnDefinition()
    {
        var shifted = fixture.MergeFacts.Sites.Where(f => f.Site.NodeId == fixture.MergeNodeIdOf("Shifted")).ToArray();

        Assert.Equal(2, shifted.Length);
        Assert.Equal(shifted[0].Site.Offset + 1, shifted[1].Site.Offset);
        Assert.All(shifted, f => Assert.Equal((SsaSiteStatus.Analyzed, false), (f.Status, f.Merged)));
        AssertValues([Str("s-alpha")], shifted[0].Arguments);
        AssertValues([Str("s-beta")], shifted[1].Arguments);
    }

    // One definition under the node id did not lift: the site is MethodUnknown even though the other did.
    [Fact]
    public void Sites_MergedWithOneUnknownDefinition_MethodUnknown()
    {
        var mixed = Assert.Single(fixture.MergeFacts.Sites, f => f.Site.NodeId == fixture.MergeNodeIdOf("Mixed"));

        Assert.Equal(SsaSiteStatus.MethodUnknown, mixed.Status);
        Assert.NotNull(mixed.FailureKind);
        Assert.Empty(mixed.Arguments);
        // Mixed: one of two; Run, Shifted and Swerve: two each; Walk: one.
        Assert.Equal(8, fixture.MergeFacts.MethodsLifted);
        Assert.Equal(1, fixture.MergeFacts.Unknown.Sum(u => u.Methods));
    }

    // C2: definition A calls the sink at the offset and B calls string.IsNullOrEmpty there. Only A's call joins: B's
    // constant is not unioned in, and the site is not Merged.
    [Fact]
    public void Sites_MergedDefinitionCallingAnotherMethodAtTheOffset_NotJoinedToIt()
    {
        var swerve = fixture.MergeNodeIdOf("Swerve");
        var site = Assert.Single(fixture.MergeSites, s => s.NodeId == swerve);
        Assert.Equal("System.IO.File.ReadAllText", site.CalleeKey);
        // Vacuity: the graph has B's other call at the very same offset.
        Assert.Contains(fixture.MergeGraph.Successors(swerve), e => e.Offset == site.Offset && e.To.StartsWith("System.String.IsNullOrEmpty(", StringComparison.Ordinal));

        var fact = Assert.Single(fixture.MergeFacts.Sites, f => f.Site.NodeId == swerve);

        Assert.Equal((SsaSiteStatus.Analyzed, false, 1), (fact.Status, fact.Merged, fact.ArgumentCount));
        AssertValues([Str("v-alpha")], fact.Arguments);
    }

    // C2: a site whose callee key is not the call's at its offset does not join it.
    [Theory]
    [InlineData("ReadsConstant", "System.IO.File.WriteAllText")]
    [InlineData("NewFileStream", "System.IO.FileStream.Dispose")]
    [InlineData("LdftnSink", "System.IO.File.ReadAllBytes")]
    [InlineData("LdvirtftnSink", "System.Reflection.MethodInfo.Invoke")]
    public void Sites_CalleeKeyNotTheCalls_NotJoined(string method, string calleeKey)
    {
        var real = fixture.SiteOf(method);

        var fact = Single(Extract(SsaFactBounds.Default, real with { CalleeKey = calleeKey }));

        AssertWithout(fact, SsaSiteStatus.NotJoined, OtherKey(real.EdgeKind));
        Assert.Equal(SsaSiteStatus.Analyzed, Single(Extract(SsaFactBounds.Default, real)).Status);
    }

    // C2: when the session lost an assembly, nothing is lifted and every kept site is MethodUnknown (Unreadable), naming
    // the lost file.
    [Fact]
    public void Sites_AssemblyLost_EverySiteMethodUnknown_NothingLifted()
    {
        using var temp = new SsaTempDirectory();
        var junk = WriteJunk(temp.Path, "junk.dll", 1);
        using var session = SsaSession.Open([fixture.SitesPath, junk]);
        Assert.Single(session.Assemblies, a => !a.IsLoaded);

        var facts = SsaSinkFacts.Extract(session, fixture.Sites, new SsaFactBounds { MaxSites = 5 });

        var reason = "SSA could not read 1 of the folder's assemblies ('junk.dll'), any of which may define a method under its node id";
        Assert.Equal((1, 0, fixture.Sites.Count, true, 5), (facts.AssembliesLost, facts.MethodsLifted, facts.SitesTotal, facts.Truncated, facts.Sites.Count));
        Assert.Empty(facts.Unknown);
        Assert.Equal((false, false, false), (facts.MethodBudget, facts.TimeBudget, facts.TextBudget));
        Assert.Equal(fixture.Sites.Take(5), facts.Sites.Select(f => f.Site));
        Assert.All(facts.Sites, f =>
        {
            AssertWithout(f, SsaSiteStatus.MethodUnknown, reason);
            Assert.Equal(SsaFailureKind.Unreadable, f.FailureKind);
        });
        Assert.Equal(0, fixture.Facts.AssembliesLost);
    }

    // Four lost: the first three by path are named, escaped (a bidi override in a file name), and the rest counted.
    [Fact]
    public void Sites_FourAssembliesLost_ThreeNamedEscaped()
    {
        using var temp = new SsaTempDirectory();
        var rlo = ((char)0x202E).ToString();
        string[] junk = [WriteJunk(temp.Path, "a" + rlo + ".dll", 2), WriteJunk(temp.Path, "j1.dll", 3), WriteJunk(temp.Path, "j2.dll", 4), WriteJunk(temp.Path, "j3.dll", 5)];
        using var session = SsaSession.Open([fixture.SitesPath, .. junk]);

        var facts = SsaSinkFacts.Extract(session, [fixture.SiteOf("ReadsConstant")]);

        var names = "'a" + Bs + "u202e.dll', 'j1.dll', 'j2.dll', and 1 more";
        Assert.Equal(4, facts.AssembliesLost);
        AssertWithout(Single(facts), SsaSiteStatus.MethodUnknown,
            $"SSA could not read 4 of the folder's assemblies ({names}), any of which may define a method under its node id");
        Assert.DoesNotContain(rlo, Single(facts).Reason!, StringComparison.Ordinal);
    }

    // ---- Site bounds ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Sites_OverMaxSites_Truncated()
    {
        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { MaxSites = 3 });

        Assert.Equal((fixture.Sites.Count, true), (facts.SitesTotal, facts.Truncated));
        Assert.Equal(fixture.Sites.Take(3), facts.Sites.Select(f => f.Site));
        // The cut sites' methods were not lifted: only the kept sites' nodes (one definition each) were tried.
        var keptNodes = fixture.Sites.Take(3).Select(s => s.NodeId).Distinct().ToArray();
        Assert.All(keptNodes, n => Assert.Single(fixture.Outcomes, o => o.NodeId == n));
        Assert.Equal(keptNodes.Length, facts.MethodsLifted + facts.Unknown.Sum(u => u.Methods));
        Assert.True(keptNodes.Length < fixture.Facts.MethodsLifted, "The cut must leave methods unlifted.");
    }

    [Fact]
    public void Sites_ExactlyMaxSites_NotTruncated()
    {
        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { MaxSites = fixture.Sites.Count });

        Assert.Equal((fixture.Sites.Count, false, fixture.Sites.Count), (facts.SitesTotal, facts.Truncated, facts.Sites.Count));
    }

    // Duplicates and order do not matter: the sites are de-duplicated and sorted before the cut, and SitesTotal counts
    // distinct sites.
    [Fact]
    public void Sites_DuplicatedAndShuffled_SameAsSorted()
    {
        var shuffled = fixture.Sites.Concat(fixture.Sites).Reverse().ToArray();

        var facts = SsaSinkFacts.Extract(fixture.Session, shuffled);

        Assert.Equal(Json(fixture.Facts), Json(facts));
    }

    [Fact]
    public void Sites_None_NothingLifted()
    {
        var facts = SsaSinkFacts.Extract(fixture.Session, []);

        Assert.Equal((0, 0, false, 0), (facts.Sites.Count, facts.SitesTotal, facts.Truncated, facts.MethodsLifted));
        Assert.Empty(facts.Unknown);
    }

    [Fact]
    public void Sites_NotLiftedBeyondMaxLiftedMethods_NotRun()
    {
        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { MaxLiftedMethods = 1 });

        var first = fixture.Sites[0].NodeId;
        Assert.Equal((true, false), (facts.MethodBudget, facts.TimeBudget));
        Assert.Equal(1, facts.MethodsLifted + facts.Unknown.Sum(u => u.Methods));
        Assert.All(facts.Sites.Where(f => f.Site.NodeId == first), f => Assert.NotEqual(SsaSiteStatus.NotRun, f.Status));
        var rest = facts.Sites.Where(f => f.Site.NodeId != first).ToArray();
        Assert.NotEmpty(rest);
        Assert.All(rest, f => AssertWithout(f, SsaSiteStatus.NotRun, "the folder's SSA method budget was spent before its method"));
    }

    // The budget is checked between node ids only: both definitions of the first node are read, the next node's none.
    [Fact]
    public void Sites_MethodBudget_NodeIsAllOrNothing()
    {
        var facts = SsaSinkFacts.Extract(fixture.MergeSession, fixture.MergeSites, new SsaFactBounds { MaxLiftedMethods = 1 });

        var mixed = fixture.MergeNodeIdOf("Mixed");
        Assert.Equal(mixed, fixture.MergeSites[0].NodeId);
        Assert.Equal((true, 1, 1), (facts.MethodBudget, facts.MethodsLifted, facts.Unknown.Sum(u => u.Methods)));
        Assert.Equal(SsaSiteStatus.MethodUnknown, Assert.Single(facts.Sites, f => f.Site.NodeId == mixed).Status);
        Assert.All(facts.Sites.Where(f => f.Site.NodeId != mixed), f => Assert.Equal(SsaSiteStatus.NotRun, f.Status));
    }

    [Fact]
    public void Sites_TimeBudgetSpent_LaterNodesNotRun()
    {
        // Time runs out at the second node's check, so the first node is read whole.
        var clock = new ScriptedClock(SecondNodeCheck());

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, clock);

        var first = fixture.Sites[0].NodeId;
        Assert.Equal((false, true), (facts.MethodBudget, facts.TimeBudget));
        Assert.All(facts.Sites.Where(f => f.Site.NodeId == first), f => Assert.NotEqual(SsaSiteStatus.NotRun, f.Status));
        var rest = facts.Sites.Where(f => f.Site.NodeId != first).ToArray();
        Assert.NotEmpty(rest);
        Assert.All(rest, f => AssertWithout(f, SsaSiteStatus.NotRun, "the folder's SSA time budget was spent before its method"));
    }

    // Under either budget, the cut point is the first node not processed (the second real node here). A site whose node
    // has no method in the folder reads NotJoined when it sorts before the cut, since the lift went past it, and NotRun
    // from the cut on. Hand-made node ids: one before every real node, one between the first node and the cut, one after
    // all of them.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sites_UnderABudget_NoMethodBeforeTheCut_NotJoined_FromTheCutOn_NotRun(bool byTime)
    {
        var nodes = fixture.Sites.Select(s => s.NodeId).Distinct().ToArray();
        var (first, cut) = (nodes[0], nodes[1]);
        var template = fixture.SiteOf("ReadsConstant");
        var before = template with { NodeId = "Facts.Aaa.Nowhere()" };
        var between = template with { NodeId = first + "!" };
        var after = template with { NodeId = "Facts.Zzz.Nowhere()" };
        string[] order = [before.NodeId, first, between.NodeId, cut, after.NodeId];
        Assert.Equal(order.Order(StringComparer.Ordinal), order);
        Assert.DoesNotContain(nodes, n => n == before.NodeId || n == between.NodeId || n == after.NodeId);
        var (bounds, clock) = byTime
            ? (new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, (TimeProvider?)new ScriptedClock(SecondNodeCheck()))
            : (new SsaFactBounds { MaxLiftedMethods = 1 }, (TimeProvider?)null);
        var notRun = byTime ? "the folder's SSA time budget was spent before its method" : "the folder's SSA method budget was spent before its method";

        var facts = SsaSinkFacts.Extract(fixture.Session, [.. fixture.Sites, before, between, after], bounds, clock);

        Assert.Equal((!byTime, byTime), (facts.MethodBudget, facts.TimeBudget));
        AssertWithout(Assert.Single(facts.Sites, f => f.Site.NodeId == before.NodeId), SsaSiteStatus.NotJoined, "no method with a body lifted under its node id");
        AssertWithout(Assert.Single(facts.Sites, f => f.Site.NodeId == between.NodeId), SsaSiteStatus.NotJoined, "no method with a body lifted under its node id");
        Assert.All(facts.Sites.Where(f => f.Site.NodeId == first), f => Assert.True(f.Status is SsaSiteStatus.Analyzed or SsaSiteStatus.MethodUnknown, Show(f)));
        var fromTheCut = facts.Sites.Where(f => string.CompareOrdinal(f.Site.NodeId, cut) >= 0).ToArray();
        Assert.Contains(fromTheCut, f => f.Site.NodeId == cut);
        Assert.Contains(fromTheCut, f => f.Site.NodeId == after.NodeId);
        Assert.All(fromTheCut, f => AssertWithout(f, SsaSiteStatus.NotRun, notRun));
        Assert.Equal(fixture.Sites.Count + 3, facts.Sites.Count);
    }

    // Twin: a clock that never moves never cuts, and the facts are the system clock's.
    [Fact]
    public void Sites_ClockWithinBudget_NoTimeBudget_SameFacts()
    {
        var clock = new ScriptedClock(int.MaxValue);

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { FolderTime = TimeSpan.FromTicks(1) }, clock);

        Assert.False(facts.TimeBudget);
        Assert.True(clock.Reads > 1, $"The clock was read {clock.Reads} time(s).");
        Assert.Equal(Json(fixture.Facts), Json(facts));
    }

    // C1: the clock is read before each site too. Sites ReadsConstant (one) then TwoSites (two) are read as: the start,
    // RC's node, RC's site, TS's node, TS's first site, TS's second site; six reads in all.
    [Fact]
    public void Sites_ClockReadBeforeEachSite()
    {
        var clock = new ScriptedClock(int.MaxValue);

        var facts = Extract(new SsaFactBounds(), clock, MidNodeSites());

        Assert.Equal(6, clock.Reads);
        Assert.All(facts.Sites, f => Assert.Equal(SsaSiteStatus.Analyzed, f.Status));
    }

    // Round 2: the string memo, by content. Two hundred separate ldstr of one 64K-char string, each passed straight to the
    // sink: no phi, no shared SSA value, and CCI reads each ldstr into a new string, so only a memo by content can make
    // every site's constant the same instance. It is reset between bodies: Twice's constant is another instance (equal).
    [Fact]
    public void Cost_SameLongStringAtManySites_EscapedOnce()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("SsaRepeats", DefineRepeats);
        MethodGraph graph;
        using (var model = ModelAssemblies.Load(path))
            graph = MethodGraph.Build(model.Index());
        var sites = SinkSites.Of(graph);
        Assert.Equal(RepeatSites + 2, sites.Count);
        Assert.Equal(RepeatSites + 2, sites.Select(s => (s.NodeId, s.Offset)).Distinct().Count());
        using var session = SsaSession.Open([path]);

        var facts = SsaSinkFacts.Extract(session, sites);

        var many = facts.Sites.Where(f => f.Site.NodeId.StartsWith("Facts.Repeats.Many(", StringComparison.Ordinal)).ToArray();
        var twice = facts.Sites.Where(f => f.Site.NodeId.StartsWith("Facts.Repeats.Twice(", StringComparison.Ordinal)).ToArray();
        Assert.Equal((RepeatSites, 2), (many.Length, twice.Length));
        var expected = CutStr(UntrustedText.EscapeBounded(RepeatedText, SsaFactBounds.Default.MaxTextChars));
        Assert.All(facts.Sites, f =>
        {
            Assert.Equal(SsaSiteStatus.Analyzed, f.Status);
            AssertValues([expected], f.Arguments);
        });
        Assert.False(facts.TextBudget);
        var manyConstant = many[0].Arguments[0].Constants[0];
        Assert.All(many, f => Assert.Same(manyConstant, f.Arguments[0].Constants[0]));
        Assert.All(twice, f => Assert.Same(twice[0].Arguments[0].Constants[0], f.Arguments[0].Constants[0]));
        Assert.NotSame(manyConstant, twice[0].Arguments[0].Constants[0]);
        Assert.Equal(manyConstant, twice[0].Arguments[0].Constants[0]);
    }

    // Round 2: CCIModuleSource quotes a non-framework core assembly's name escaped and bounded. A core reference named
    // "Evil" and 300 bidi overrides escapes to 1,804 chars; the reason holds it cut to MaxNameChars, with no raw override.
    // Lifted in a child, as SsaHostileShapeTests lifts its hostile cores.
    [Fact]
    public void CoreProblem_HostileCoreName_EscapedAndBounded()
    {
        using var temp = new SsaTempDirectory();
        var name = "Evil" + new string((char)0x202E, 300);
        var raw = new RawAssembly("HostileCore", withRuntime: false);
        var evil = raw.AssemblyRef(name);
        var evilObject = raw.TypeRef(evil, "System", "Object");
        raw.TypeRef(evil, "System", "Int32");
        raw.TypeRef(evil, "System", "String");
        raw.Type("Users", "User", evilObject);
        raw.Static("Plain", RawAssembly.MethodSig(false, r => r.Void()), il => il.OpCode(System.Reflection.Metadata.ILOpCode.Ret));
        Assert.True(UntrustedText.Escape(name).Length > Reachability.MaxNameChars);

        var run = SsaHostileShapeTests.Lift(raw.Save(temp.Path));

        var expected = $"Its primitive types cannot be trusted: CCI takes '{Reachability.BoundName(UntrustedText.Escape(name))}', not a framework assembly, as its core library";
        run.AssertFailed("Users.User::Plain", SsaFailureKind.Adapter, expected);
        var reason = run.Of("Users.User::Plain").Reason;
        Assert.Equal(expected, reason);
        Assert.DoesNotContain((char)0x202E, reason);
        Assert.Contains(UntrustedText.Escape(name)[..Reachability.MaxNameChars] + (char)0x2026 + "[+", reason, StringComparison.Ordinal);
    }

    // C1: time runs out before TwoSites' second site, after its first was read. The node is dropped whole: both its sites
    // read NotRun (time), and the earlier node stays Analyzed.
    [Theory]
    [InlineData(4)]
    [InlineData(5)]
    public void Sites_TimeRunsOutMidNode_TheNodeIsDroppedWhole(int jumpAtRead)
    {
        var facts = Extract(new SsaFactBounds { FolderTime = TimeSpan.FromSeconds(1) }, new ScriptedClock(jumpAtRead), MidNodeSites());

        Assert.Equal((false, true), (facts.MethodBudget, facts.TimeBudget));
        var reads = Single(facts, "ReadsConstant");
        Assert.Equal(SsaSiteStatus.Analyzed, reads.Status);
        AssertValues([Str("x")], reads.Arguments);
        var two = Facts(facts, "TwoSites");
        Assert.Equal(2, two.Length);
        Assert.All(two, f => AssertWithout(f, SsaSiteStatus.NotRun, "the folder's SSA time budget was spent before its method"));
    }

    // C1: one phi of a thousand and one inputs, passed to the sink at a thousand sites, is walked once per body. Before the
    // fix, the walk ran per site (2.5 s measured for this shape); now a thousand sites cost about what one does. The
    // structural proof: every site's constants are the same two instances. Every site reads the one phi value, so this
    // exercises the values memo (by reference); the string memo is Cost_SameLongStringAtManySites_EscapedOnce's.
    [Fact]
    public void Cost_OneWidePhiAtManySites_ReadOnce()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("SsaWide", DefineWide);
        MethodGraph graph;
        using (var model = ModelAssemblies.Load(path))
            graph = MethodGraph.Build(model.Index());
        var sites = SinkSites.Of(graph);
        Assert.Equal(WideSites, sites.Count);
        using var session = SsaSession.Open([path]);
        _ = SsaSinkFacts.Extract(session, [sites[0]]);

        var one = System.Diagnostics.Stopwatch.StartNew();
        var single = SsaSinkFacts.Extract(session, [sites[0]]);
        one.Stop();
        var all = System.Diagnostics.Stopwatch.StartNew();
        var facts = SsaSinkFacts.Extract(session, sites);
        all.Stop();

        AssertValues([OneOf(Str("a"), Str("b"))], Single(single).Arguments);
        Assert.Equal(WideSites, facts.Count(SsaSiteStatus.Analyzed));
        Assert.All(facts.Sites, f => AssertValues([OneOf(Str("a"), Str("b"))], f.Arguments));
        Assert.Equal(2, facts.Sites.SelectMany(f => f.Arguments[0].Constants).Distinct(ReferenceEqualityComparer.Instance).Count());
        Assert.True(all.Elapsed - one.Elapsed < TimeSpan.FromSeconds(1),
            $"{WideSites} sites took {all.ElapsedMilliseconds} ms, one site {one.ElapsedMilliseconds} ms.");
    }

    // Only the methods holding sites are lifted: the folder has more, and one of them (a jmp) would be Unknown.
    [Fact]
    public void Sites_OnlySinkMethodsLifted()
    {
        var siteNodes = fixture.Sites.Select(s => s.NodeId).ToHashSet(StringComparer.Ordinal);
        var ofSites = fixture.Outcomes.Where(o => siteNodes.Contains(o.NodeId)).ToArray();
        var others = fixture.Outcomes.Where(o => !siteNodes.Contains(o.NodeId)).ToArray();

        Assert.Equal(ofSites.Count(o => o.Failure is null), fixture.Facts.MethodsLifted);
        Assert.Equal(
            ofSites.Where(o => o.Failure is not null).GroupBy(o => o.Failure!.Kind).OrderBy(g => g.Key).Select(g => (g.Key, g.Count())),
            fixture.Facts.Unknown.Select(u => (u.Kind, u.Methods)));
        // Vacuity: the folder has non-sink methods with bodies, one of them Unknown, and none of them counted.
        Assert.All(NonSinkMethods, m => Assert.Contains(others, o => o.MethodName == m));
        Assert.Contains(others, o => o.MethodName == "NotASinkJumper" && o.Failure is not null);
        Assert.Equal(1, fixture.Facts.Unknown.Sum(u => u.Methods));
    }

    // ---- Text ----------------------------------------------------------------------------------------------------------

    [Fact]
    public void Text_OverMaxChars_CutWithHashSuffix()
    {
        AssertValues([CutStr(new string('A', 256) + Suffix(44, HugeText))], Fact("HugeConstant").Arguments);

        var facts = Extract(new SsaFactBounds { MaxTextChars = 10 }, fixture.SiteOf("HugeConstant"));

        AssertValues([CutStr(new string('A', 10) + Suffix(290, HugeText))], Single(facts).Arguments);
    }

    // The hostile constant reaches the facts escaped and well-formed, and the whole record serializes, including under a
    // writer that refuses ill-formed strings as the worker's does.
    [Fact]
    public void Text_LoneSurrogate_EscapedAndRecordWrites()
    {
        var fact = Fact("Hostile");

        AssertValues([Str(HostileEscaped)], fact.Arguments);
        var text = fact.Arguments[0].Constants[0].Text;
        Assert.True(UntrustedTextTests.WellFormed(text));
        Assert.DoesNotContain(text, c => c < 0x20 || c is (char)0x202E);

        var json = JsonSerializer.Serialize(fixture.Facts);
        var strict = JsonSerializer.Serialize(fixture.Facts, new JsonSerializerOptions { Converters = { new WellFormedOnly() } });
        Assert.Equal(json, strict);
        Assert.Contains("Hostile", json, StringComparison.Ordinal);
    }

    // Charged in site order (node id: NewFileStream, ReadsConstant, StartsCmd, WritesTwo): "f" and "x" fit in 3, "cmd.exe"
    // does not, and from then on every String constant is hash-only, even "p" and "c", which would fit. Int is not charged.
    [Fact]
    public void Text_FolderBudgetSpent_HashOnly()
    {
        var facts = Extract(new SsaFactBounds { MaxFactTextChars = 3 }, BudgetSites());

        Assert.True(facts.TextBudget);
        AssertValues([Str("f"), Int("3")], Single(facts, "NewFileStream").Arguments);
        AssertValues([Str("x")], Single(facts, "ReadsConstant").Arguments);
        AssertValues([CutStr(UntrustedText.HashOnly("cmd.exe"))], Single(facts, "StartsCmd").Arguments);
        AssertValues([CutStr(UntrustedText.HashOnly("p")), CutStr(UntrustedText.HashOnly("c"))], Single(facts, "WritesTwo").Arguments);
        Assert.Equal(Suffix(7, "cmd.exe"), UntrustedText.HashOnly("cmd.exe"));
    }

    // Exactly filling the budget is within it: "f", "x" and "cmd.exe" are 9.
    [Fact]
    public void Text_FolderBudget_ExactFitKept()
    {
        var facts = Extract(new SsaFactBounds { MaxFactTextChars = 9 }, BudgetSites());

        Assert.True(facts.TextBudget);
        AssertValues([Str("cmd.exe")], Single(facts, "StartsCmd").Arguments);
        AssertValues([CutStr(UntrustedText.HashOnly("p")), CutStr(UntrustedText.HashOnly("c"))], Single(facts, "WritesTwo").Arguments);

        var all = Extract(new SsaFactBounds { MaxFactTextChars = 11 }, BudgetSites());
        Assert.False(all.TextBudget);
        AssertValues([Str("p"), Str("c")], Single(all, "WritesTwo").Arguments);
    }

    // The escaped text is charged (14 chars for C:\secret.txt, 13 raw), and a cut constant hashes the raw text.
    [Fact]
    public void Text_FolderBudget_ChargesTheEscapedText()
    {
        var site = fixture.SiteOf("PromotedLocal");

        var fits = Extract(new SsaFactBounds { MaxFactTextChars = 14 }, site);
        var over = Extract(new SsaFactBounds { MaxFactTextChars = 13 }, site);

        Assert.False(fits.TextBudget);
        AssertValues([Str(PromotedEscaped)], Single(fits).Arguments);
        Assert.True(over.TextBudget);
        AssertValues([CutStr(UntrustedText.HashOnly(PromotedText))], Single(over).Arguments);
    }

    // A Type constant is charged like a String; Int, Float and Null are not.
    [Fact]
    public void Text_FolderBudget_TypeChargedIntFloatNullNot()
    {
        var typed = Extract(new SsaFactBounds { MaxFactTextChars = 1 }, fixture.SiteOf("TypeofString"));
        var numbers = Extract(new SsaFactBounds { MaxFactTextChars = 1 }, fixture.SiteOf("InvokeFloat"), fixture.SiteOf("InvokeNegative"));

        Assert.True(typed.TextBudget);
        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Type, UntrustedText.HashOnly("System.String"), Cut: true))], Single(typed).Arguments);
        Assert.False(numbers.TextBudget);
        AssertValues([SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Float, "2.5")), Null], Single(numbers, "InvokeFloat").Arguments);
    }

    // A OneOf's constants are charged in order: "Zeta" fits in 4, "alpha" does not.
    [Fact]
    public void Text_FolderBudget_OneOfChargedInOrder()
    {
        var facts = Extract(new SsaFactBounds { MaxFactTextChars = 4 }, fixture.SiteOf("PhiOfTwo"));

        Assert.True(facts.TextBudget);
        AssertValues([OneOf(Str("Zeta"), CutStr(UntrustedText.HashOnly("alpha")))], Single(facts).Arguments);
    }

    // A huge constant over the budget is hash-only of its whole raw text, not of its cut form.
    [Fact]
    public void Text_HugeConstantOverBudget_HashOnlyOfTheRawText()
    {
        var facts = Extract(new SsaFactBounds { MaxFactTextChars = 5 }, fixture.SiteOf("HugeConstant"));

        AssertValues([CutStr(UntrustedText.HashOnly(HugeText))], Single(facts).Arguments);
    }

    // Cut is false on whole text, true on a MaxTextChars cut and on a hash-only constant.
    [Fact]
    public void Text_CutFlag_FalseWhole_TrueCutOrHashOnly()
    {
        Assert.False(Fact("ReadsConstant").Arguments[0].Constants[0].Cut);
        Assert.False(Fact("TypeofString").Arguments[0].Constants[0].Cut);
        Assert.True(Fact("HugeConstant").Arguments[0].Constants[0].Cut);
        Assert.True(Single(Extract(new SsaFactBounds { MaxFactTextChars = 1 }, fixture.SiteOf("StartsCmd"))).Arguments[0].Constants[0].Cut);
        // A whole text that exactly fits MaxTextChars is not cut.
        Assert.False(Single(Extract(new SsaFactBounds { MaxTextChars = 7 }, fixture.SiteOf("StartsCmd"))).Arguments[0].Constants[0].Cut);
        Assert.True(Single(Extract(new SsaFactBounds { MaxTextChars = 6 }, fixture.SiteOf("StartsCmd"))).Arguments[0].Constants[0].Cut);
        Assert.All(Fact("NewFileStream").Arguments, a => Assert.False(a.Constants[0].Cut));
    }

    // A raw constant that spells a cut suffix was not cut: the flag, not the text, says so.
    [Fact]
    public void Text_ConstantSpellingASuffix_NotCut()
    {
        var constant = Fact("SpellsSuffix").Arguments[0].Constants[0];

        Assert.Equal((SpelledSuffix, false), (constant.Text, constant.Cut));
        Assert.EndsWith("]", constant.Text, StringComparison.Ordinal);
    }

    // W2: a MethodUnknown reason is escaped, then bounded like a name, once per node. A type name of 300 bidi overrides
    // escapes to over MaxNameChars, so the reason is cut to MaxNameChars plus the hash suffix.
    [Fact]
    public void Sites_LongHostileReason_EscapedAndBounded()
    {
        using var temp = new SsaTempDirectory();
        var hostile = "Ghost" + new string((char)0x202E, 300);
        var lib = new RawAssembly("GhostLib");
        lib.Type("Lib", "Present", lib.Object);
        var user = new RawAssembly("GhostUser");
        var ghost = user.TypeRef(user.AssemblyRef("GhostLib"), "Ghosts", hostile);
        var readAll = user.MemberRef(user.TypeRef(user.Runtime, "System.IO", "File"), "ReadAllText",
            RawAssembly.MethodSig(false, r => r.Type().String(), p => p.String()));
        user.Type("Users", "User", user.Object);
        user.Static("Hides", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            il.OpCode(System.Reflection.Metadata.ILOpCode.Ldtoken);
            il.Token(ghost);
            il.OpCode(System.Reflection.Metadata.ILOpCode.Pop);
            il.LoadString(user.Metadata.GetOrAddUserString("x"));
            il.Call(readAll);
            il.OpCode(System.Reflection.Metadata.ILOpCode.Pop);
            il.OpCode(System.Reflection.Metadata.ILOpCode.Ret);
        });
        string[] paths = [lib.Save(temp.Path), user.Save(temp.Path)];
        MethodGraph graph;
        using (var model = ModelAssemblies.Load(paths))
            graph = MethodGraph.Build(model.Index());
        var site = Assert.Single(SinkSites.Of(graph));
        using var lifted = new SsaLifted(paths);
        var raw = lifted.Of("User", "Hides").Failure;
        Assert.NotNull(raw);
        Assert.True(UntrustedText.Escape(raw!.Reason).Length > Reachability.MaxNameChars,
            $"The reason escapes to only {UntrustedText.Escape(raw.Reason).Length} chars: {SsaText.Printable(raw.Reason)}");

        var fact = Single(SsaSinkFacts.Extract(lifted.Session, [site]));

        var expected = Reachability.BoundName(UntrustedText.Escape(raw.Reason));
        AssertWithout(fact, SsaSiteStatus.MethodUnknown, expected);
        Assert.Equal(raw.Kind, fact.FailureKind);
        Assert.StartsWith(UntrustedText.Escape(raw.Reason)[..Reachability.MaxNameChars] + (char)0x2026 + "[+", fact.Reason!, StringComparison.Ordinal);
        Assert.True(fact.Reason!.Length <= Reachability.MaxNameChars + Suffix(99_999, raw.Reason).Length, $"{fact.Reason.Length} chars.");
        Assert.DoesNotContain((char)0x202E, fact.Reason);
    }

    // ---- Bounds and arguments ------------------------------------------------------------------------------------------

    // The spec's table (§3, "Bounds"); MaxPhiInputs is the code's own addition.
    [Fact]
    public void Bounds_Defaults_AreTheSpecs()
    {
        var bounds = SsaFactBounds.Default;

        Assert.Equal((8_192, 8, 4, 16, 256, 1_000_000, 50_000, TimeSpan.FromSeconds(60)),
            (bounds.MaxSites, bounds.MaxArguments, bounds.MaxAlternatives, bounds.MaxPhiDepth, bounds.MaxTextChars, bounds.MaxFactTextChars, bounds.MaxLiftedMethods, bounds.FolderTime));
        Assert.Equal(1_024, bounds.MaxPhiInputs);
        Assert.Same(bounds, bounds.Validated());
    }

    public static TheoryData<string> InvalidBounds => new() { "MaxSites", "MaxArguments", "MaxAlternatives", "MaxPhiDepth", "MaxPhiInputs", "MaxTextChars", "MaxFactTextChars", "MaxLiftedMethods", "FolderTime" };

    [Theory]
    [MemberData(nameof(InvalidBounds))]
    public void Bounds_NotPositive_Throws(string bound)
    {
        var zero = bound switch
        {
            "MaxSites" => new SsaFactBounds { MaxSites = 0 },
            "MaxArguments" => new SsaFactBounds { MaxArguments = 0 },
            "MaxAlternatives" => new SsaFactBounds { MaxAlternatives = 0 },
            "MaxPhiDepth" => new SsaFactBounds { MaxPhiDepth = 0 },
            "MaxPhiInputs" => new SsaFactBounds { MaxPhiInputs = 0 },
            "MaxTextChars" => new SsaFactBounds { MaxTextChars = 0 },
            "MaxFactTextChars" => new SsaFactBounds { MaxFactTextChars = 0 },
            "MaxLiftedMethods" => new SsaFactBounds { MaxLiftedMethods = -1 },
            _ => new SsaFactBounds { FolderTime = TimeSpan.Zero },
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => zero.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => SsaSinkFacts.Extract(fixture.Session, fixture.Sites, zero));
    }

    [Fact]
    public void Extract_NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => SsaSinkFacts.Extract(null!, fixture.Sites));
        Assert.Throws<ArgumentNullException>(() => SsaSinkFacts.Extract(fixture.Session, null!));
    }

    // Deterministic: the same facts from the same session twice, and from a fresh session.
    [Fact]
    public void Extract_Twice_AndOnAFreshSession_Identical()
    {
        using var fresh = SsaSession.Open([fixture.SitesPath]);

        var again = SsaSinkFacts.Extract(fixture.Session, fixture.Sites);
        var other = SsaSinkFacts.Extract(fresh, fixture.Sites);

        Assert.Equal(Json(fixture.Facts), Json(again));
        Assert.Equal(Json(fixture.Facts), Json(other));
    }

    // ---- SsaSession.Lift(select) ---------------------------------------------------------------------------------------

    // The selected methods only, ordinal by node id; together they are exactly Lift()'s.
    [Fact]
    public void Lift_SelectAll_SameMethodsAsLift_OrdinalByNodeId()
    {
        var ids = fixture.Session.Lift(_ => true).Select(o => o.NodeId).ToArray();

        Assert.Equal(ids.Order(StringComparer.Ordinal), ids);
        Assert.Equal(fixture.Outcomes.Select(o => o.NodeId).Order(StringComparer.Ordinal), ids);
    }

    [Fact]
    public void Lift_Select_OnlyTheSelected()
    {
        var wanted = new[] { fixture.NodeIdOf("PhiOfTwo"), fixture.NodeIdOf("ReadsConstant") };
        var asked = new List<string>();

        var outcomes = fixture.Session.Lift(m =>
        {
            asked.Add(CanonicalName.NodeId(m));
            return wanted.Contains(CanonicalName.NodeId(m));
        }).ToArray();

        Assert.Equal(wanted.Order(StringComparer.Ordinal), outcomes.Select(o => o.NodeId));
        Assert.All(outcomes, o => Assert.True(o.IsLifted, SsaText.Printable(o.NodeId)));
        Assert.True(asked.Count >= fixture.Outcomes.Count, $"The predicate saw {asked.Count} methods.");
        Assert.Empty(fixture.Session.Lift(_ => false));
    }

    // Definitions sharing a node id come together, in Lift()'s order (assembly path).
    [Fact]
    public void Lift_Select_MergedDefinitionsAdjacent_InPathOrder()
    {
        var run = fixture.MergeNodeIdOf("Run");

        var outcomes = fixture.MergeSession.Lift(m => CanonicalName.NodeId(m) == run).ToArray();

        Assert.Equal(2, outcomes.Length);
        Assert.Equal(fixture.MergePaths.Order(StringComparer.Ordinal), outcomes.Select(o => o.AssemblyPath));
        var all = fixture.MergeSession.Lift(_ => true).Select(o => o.NodeId).ToArray();
        Assert.Equal(all.Order(StringComparer.Ordinal), all);
    }

    [Fact]
    public void Lift_Select_OnADisposedSession_Throws()
    {
        var session = SsaSession.Open([fixture.SitesPath]);
        var pending = session.Lift(_ => true);
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => session.Lift(_ => true));
        Assert.Throws<ObjectDisposedException>(() => pending.First());
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private SsaSinkFact Fact(string method) => Assert.Single(fixture.Facts.Sites, f => f.Site.NodeId == fixture.NodeIdOf(method));

    private SsaSinkFact[] Facts(SsaFolderFacts facts, string method) => [.. facts.Sites.Where(f => f.Site.NodeId == fixture.NodeIdOf(method))];

    private SsaSinkFact Single(SsaFolderFacts facts, string method) => Assert.Single(Facts(facts, method));

    private static SsaSinkFact Single(SsaFolderFacts facts) => Assert.Single(facts.Sites);

    private SsaFolderFacts Extract(SsaFactBounds bounds, params SinkSite[] sites) => SsaSinkFacts.Extract(fixture.Session, sites, bounds);

    private SsaFolderFacts Extract(SsaFactBounds bounds, TimeProvider clock, params SinkSite[] sites) => SsaSinkFacts.Extract(fixture.Session, sites, bounds, clock);

    // ReadsConstant's one site, then TwoSites' two: two nodes, one definition each.
    private SinkSite[] MidNodeSites()
    {
        var two = fixture.Sites.Where(s => s.NodeId == fixture.NodeIdOf("TwoSites")).ToArray();
        Assert.Equal(2, two.Length);
        Assert.True(string.CompareOrdinal(fixture.NodeIdOf("ReadsConstant"), fixture.NodeIdOf("TwoSites")) < 0);
        return [fixture.SiteOf("ReadsConstant"), .. two];
    }

    // The clock read at which, over all the fixture's sites, the second node is checked: the start (0), the first node's
    // check (1), then one read per site of the first node, which must lift with one definition.
    private int SecondNodeCheck()
    {
        var first = fixture.Sites[0].NodeId;
        Assert.Null(Assert.Single(fixture.Outcomes, o => o.NodeId == first).Failure);
        return 2 + fixture.Sites.Count(s => s.NodeId == first);
    }

    private static string NoCall(MethodEdgeKind kind) => $"no {kind} instruction at this offset in the lifted body";

    private static string OtherKey(MethodEdgeKind kind) =>
        $"the {kind} instruction at this offset in the lifted body calls a method with another classification key";

    // A file of seeded random bytes: not an assembly.
    private static string WriteJunk(string directory, string name, int seed)
    {
        var bytes = new byte[4096];
        new Random(seed).NextBytes(bytes);
        var path = System.IO.Path.Combine(directory, name);
        System.IO.File.WriteAllBytes(path, bytes);
        return path;
    }

    private SinkSite[] BudgetSites() =>
        [fixture.SiteOf("WritesTwo"), fixture.SiteOf("StartsCmd"), fixture.SiteOf("ReadsConstant"), fixture.SiteOf("NewFileStream")];

    private void AssertSite(string method, MethodEdgeKind kind, string callee, string calleeKey, Capability capability) =>
        Assert.Equal(new SinkSite(fixture.NodeIdOf(method), fixture.SiteOf(method).Offset, kind, callee, calleeKey, capability), fixture.SiteOf(method));

    private static void AssertWithout(SsaSinkFact fact, SsaSiteStatus status, string reason)
    {
        Assert.True(fact.Status == status, $"{Show(fact)}: expected {status}.");
        Assert.Equal(reason, fact.Reason);
        Assert.Null(fact.Receiver);
        Assert.Empty(fact.Arguments);
        Assert.Equal((0, false), (fact.ArgumentCount, fact.Merged));
        if (status != SsaSiteStatus.MethodUnknown)
            Assert.Null(fact.FailureKind);
    }

    private static void AssertValues(SsaValue[] expected, IReadOnlyList<SsaValue> actual) =>
        Assert.True(expected.Length == actual.Count && expected.Zip(actual).All(p => p.First.SameAs(p.Second)),
            $"Expected {Show(expected)}\nActual   {Show(actual)}");

    private static void AssertValue(SsaValue expected, SsaValue? actual) =>
        Assert.True(actual is not null && expected.SameAs(actual), $"Expected {Show(expected)}\nActual   {Show(actual)}");

    private static SsaValue Str(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text));

    private static SsaValue CutStr(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text, Cut: true));

    private static SsaValue Int(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Int, text));

    private static SsaValue Null => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Null, "null"));

    private static SsaValue OneOf(params SsaValue[] values) => new(SsaValueKind.OneOf, [.. values.Select(v => v.Constants[0])], null, null);

    private static SsaValue Parameter(int index) => SsaValue.OfParameter(index);

    private static SsaValue Dynamic(SsaDynamicOrigin origin) => SsaValue.OfDynamic(origin);

    private static string Suffix(int cut, string whole) => $"{(char)0x2026}[+{cut} chars, sha256:{UntrustedTextTests.Sha8(whole)}]";

    private static string Json(object? value) => JsonSerializer.Serialize(value);

    private static string Show(object? value) => SsaText.Printable(Json(value));
    #endregion

    #region Fields
    private readonly SsaSinkFactsFixture fixture;
    #endregion

    #region Child types
    // A clock that reads 0 until its read number jumpAtRead (the first read is 0), and an hour from then on.
    private sealed class ScriptedClock(int jumpAtRead) : TimeProvider
    {
        public int Reads { get; private set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Reads++ >= jumpAtRead ? TimeSpan.FromHours(1).Ticks : 0;
    }

    // Writes only well-formed strings, as the graph worker's record writer does.
    private sealed class WellFormedOnly : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.GetString();

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
        {
            if (!UntrustedTextTests.WellFormed(value))
                throw new JsonException("an ill-formed string reached the writer");
            writer.WriteStringValue(value);
        }
    }
    #endregion
}
