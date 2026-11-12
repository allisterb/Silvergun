namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SsaReflectionFixture;

/// <summary>
/// The S4.3 reflection targets (docs/agent/tasks/ssa-facts-s4.md §3, "Reflection targets", D4; "Test cases to cover":
/// Reflection), end to end: an emitted folder, <see cref="MethodGraph.Build"/>, <see cref="SinkSites.Of"/> and
/// <see cref="OwnMembers.Of"/>, an <see cref="SsaSession"/> over the same files, then <see cref="SsaSinkFacts.Extract"/>
/// with the built-in <see cref="ReflectionMap"/>. Candidates are checked against the graph's own nodes by classification
/// key (<see cref="OwnNodes"/>), and pinned literally where the spelling is the point.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaReflectionTargetTests : IClassFixture<SsaReflectionFixture>
{
    #region Constructors
    public SsaReflectionTargetTests(SsaReflectionFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- Spec-named ----------------------------------------------------------------------------------------------------

    [Fact]
    public void Reflection_GetTypeGetMethodInvoke_ConstantsResolved()
    {
        var fact = Fact("GetTypeGetMethodInvoke", Invoke);

        Assert.Equal((SsaSiteStatus.Analyzed, Capability.ReflectionInvocation), (fact.Status, fact.Site.Capability));
        AssertTarget(fact.Target, SsaTargetKind.Method, null, Str(TargetType), Str("Run"), RunOverloads());
    }

    [Fact]
    public void Reflection_TypeofCreateInstance_Resolved()
    {
        var fact = Fact("TypeofCreateInstance", CreateInstance);

        Assert.Equal((SsaSiteStatus.Analyzed, Capability.DynamicCodeLoading), (fact.Status, fact.Site.Capability));
        AssertTarget(fact.Target, SsaTargetKind.Constructor, null, TypeConst(TargetType), null, TargetConstructors());
    }

    // Every overload of the name, labelled ByName, and none of the type's other methods; the oracle is pinned literally.
    [Fact]
    public void Reflection_OverloadsByName_AllCandidatesLabelled()
    {
        var target = Target("TypeofGetMethodInvoke", Invoke);

        string[] overloads = ["Own.Target.Run()", "Own.Target.Run(System.Int32)", "Own.Target.Run(System.String)"];
        Assert.Equal(overloads, RunOverloads());
        AssertTarget(target, SsaTargetKind.Method, null, TypeConst(TargetType), Str("Run"), overloads);
        Assert.Equal(SsaCandidateMatch.ByName, target.Match);
        Assert.DoesNotContain(target.Candidates, c => c.StartsWith("Own.Target.Solo", StringComparison.Ordinal));
    }

    // The member comes from a static field: the chain leaves the method, so both the type and the name are Dynamic(FieldLoad).
    [Fact]
    public void Reflection_ChainThroughField_IsDynamic() =>
        AssertTarget(Target("FieldInvoke", Invoke), SsaTargetKind.Member, null, Dynamic(SsaDynamicOrigin.FieldLoad), Dynamic(SsaDynamicOrigin.FieldLoad), []);

    // The type comes from a field, the name is still a constant: the lookup's kind stands, but nothing is a candidate.
    [Fact]
    public void Reflection_TypeThroughField_IsDynamic_NameKept() =>
        AssertTarget(Target("FieldTypeGetMethodInvoke", Invoke), SsaTargetKind.Method, null, Dynamic(SsaDynamicOrigin.FieldLoad), Str("Run"), []);

    [Fact]
    public void Reflection_ExternalType_NoOwnCandidates()
    {
        AssertTarget(Target("ExternalGetMethodInvoke", Invoke), SsaTargetKind.Method, null, Str("System.String"), Str("Concat"), []);
        AssertTarget(Target("ExternalGetMethodInvoke", TypeGetType), SsaTargetKind.Type, null, Str("System.String"), null, []);
        AssertTarget(Target("TypeofExternalCreateInstance", CreateInstance), SsaTargetKind.Constructor, null, TypeConst("System.Object"), null, []);
    }

    // ---- Assemblies ----------------------------------------------------------------------------------------------------

    // Assembly.Load("X").GetType("Ns.T").GetMethod("M").Invoke: the assembly is carried through both lookups.
    [Fact]
    public void Reflection_AssemblyLoadGetType_AssemblyAndTypeNamed() =>
        AssertTarget(Target("AssemblyLoadGetTypeInvoke", Invoke), SsaTargetKind.Method, Str("X"), Str("Ns.T"), Str("M"), []);

    [Fact]
    public void Reflection_AssemblyLoadGetTypeCreateInstance_CandidatesFromTheName() =>
        AssertTarget(Target("AssemblyLoadCreateInstance", CreateInstance), SsaTargetKind.Constructor, Str("Asm"), Str(TargetType), null, TargetConstructors());

    // Assembly.Load is a DynamicCodeLoading sink, but no target line lists it.
    [Fact]
    public void Reflection_AssemblyLoadSite_HasNoTarget()
    {
        var fact = Fact("AssemblyLoadGetTypeInvoke", "System.Reflection.Assembly.Load");

        Assert.Equal((SsaSiteStatus.Analyzed, Capability.DynamicCodeLoading), (fact.Status, fact.Site.Capability));
        Assert.Null(fact.Target);
    }

    // ---- Activator.CreateInstance's bindings ----------------------------------------------------------------------------

    // (string, string): type=0 and type=!!0 do not fit, so the group assembly=0,type-name=1 applies.
    [Fact]
    public void Reflection_CreateInstanceByNames_GroupBinding() =>
        AssertTarget(Target("CreateInstanceByNames", CreateInstance), SsaTargetKind.Constructor, Str("Asm"), Str(TargetType), null, TargetConstructors());

    // CreateInstance<Own.Target>(): type=!!0, the callee's generic argument, read as a Type constant.
    [Fact]
    public void Reflection_CreateInstanceOfT_GenericArgument() =>
        AssertTarget(Target("CreateInstanceGeneric", CreateInstance), SsaTargetKind.Constructor, null, TypeConst(TargetType), null, TargetConstructors());

    [Fact]
    public void Reflection_CreateInstanceTypeAndBool_Resolved() =>
        AssertTarget(Target("CreateInstanceNonPublic", CreateInstance), SsaTargetKind.Constructor, null, TypeConst(TargetType), null, TargetConstructors());

    // Own.G`1's constructor, from a closed and from an open typeof.
    [Theory]
    [InlineData("TypeofGenericCreateInstance", "Own.G`1<System.Int32>")]
    [InlineData("TypeofOpenGenericCreateInstance", "Own.G`1")]
    public void Reflection_TypeofGeneric_CandidatesOfTheDefinition(string method, string typeName)
    {
        var constructors = OwnNodes(fixture.Graph, "Own.G..ctor");
        Assert.Single(constructors);

        AssertTarget(Target(method, CreateInstance), SsaTargetKind.Constructor, null, TypeConst(typeName), null, constructors);
    }

    // ---- MethodBase.Invoke and the member lookups -----------------------------------------------------------------------

    // MethodBase.Invoke is a Member target; its chain's GetConstructor makes it a Constructor, with no member name.
    [Fact]
    public void Reflection_InvokeThroughGetConstructor_KindConstructor()
    {
        AssertTarget(Target("GetConstructorInvoke", Invoke), SsaTargetKind.Constructor, null, TypeConst(TargetType), null, TargetConstructors());
        AssertTarget(Target("GetConstructorConstructorInvoke", "System.Reflection.ConstructorInfo.Invoke"), SsaTargetKind.Constructor, null, TypeConst(TargetType), null, TargetConstructors());
    }

    // The member is the caller's argument 0: it stands for both the type and the name, and the kind stays Member.
    [Fact]
    public void Reflection_InvokeThroughParameter_IsParameter()
    {
        AssertTarget(Target("ParameterInvoke", Invoke), SsaTargetKind.Member, null, Parameter(0), Parameter(0), []);
        AssertTarget(Target("ParameterTypeGetMethodInvoke", Invoke), SsaTargetKind.Method, null, Parameter(0), Str("Run"), []);
    }

    // An own call that returns a MethodInfo is not a lookup: its result is Dynamic(CallResult).
    [Fact]
    public void Reflection_InvokeThroughOwnCall_IsDynamicCallResult() =>
        AssertTarget(Target("CallResultInvoke", Invoke), SsaTargetKind.Member, null, Dynamic(SsaDynamicOrigin.CallResult), Dynamic(SsaDynamicOrigin.CallResult), []);

    [Fact]
    public void Reflection_PropertyGetValue_AccessorCandidates()
    {
        var accessors = Own("Own.Target.get_P", "Own.Target.set_P");
        Assert.Equal(2, accessors.Length);

        AssertTarget(Target("PropertyGetValue", "System.Reflection.PropertyInfo.GetValue"), SsaTargetKind.Property, null, TypeConst(TargetType), Str("P"), accessors);
    }

    // Fields are not graph nodes: a named field has no candidates.
    [Fact]
    public void Reflection_FieldGetValue_NoCandidates() =>
        AssertTarget(Target("FieldGetValue", "System.Reflection.FieldInfo.GetValue"), SsaTargetKind.Field, null, TypeConst(TargetType), Str("F"), []);

    // Type.GetType is a sink of its own: its target is the type, and the own type's id is the candidate.
    [Fact]
    public void Reflection_TypeGetTypeSink_OwnTypeIdIsTheCandidate()
    {
        Assert.Contains(fixture.Graph.Facts.Types, t => t.TypeId == TargetType);

        AssertTarget(Target("Name0", TypeGetType), SsaTargetKind.Type, null, Str(TargetType), null, [TargetType]);
    }

    // InvokeMember("Dual"): a Member by name matches the method Dual and the accessor get_Dual (there is no set_Dual).
    [Fact]
    public void Reflection_InvokeMember_MethodAndAccessorCandidates()
    {
        var candidates = Own("Own.Target.Dual", "Own.Target.get_Dual");
        Assert.Equal(2, candidates.Length);
        Assert.Empty(Own("Own.Target.set_Dual"));

        AssertTarget(Target("InvokeMember", "System.Type.InvokeMember"), SsaTargetKind.Member, null, TypeConst(TargetType), Str("Dual"), candidates);
    }

    // (Type, MethodInfo): member=1 applies, through GetMethod.
    [Fact]
    public void Reflection_CreateDelegateOfMethodInfo_MemberThroughItsLookup() =>
        AssertTarget(Target("CreateDelegateOfMethodInfo", CreateDelegate), SsaTargetKind.Method, null, TypeConst(TargetType), Str("Solo"), Solo());

    // (Type, Type, string): member=1 and member=2 do not fit, so type=1 and name=2 apply.
    [Fact]
    public void Reflection_CreateDelegateOfTypeAndName_TypeAndNameBindings() =>
        AssertTarget(Target("CreateDelegateOfTypeAndName", CreateDelegate), SsaTargetKind.Method, null, TypeConst(TargetType), Str("Solo"), Solo());

    // (Type, object, string): only name=2 fits; the chain names no type.
    [Fact]
    public void Reflection_CreateDelegateOfObjectAndName_NoType() =>
        AssertTarget(Target("CreateDelegateOfObjectAndName", CreateDelegate), SsaTargetKind.Method, null, Dynamic(SsaDynamicOrigin.Other), Str("Solo"), []);

    [Fact]
    public void Reflection_MethodInfoCreateDelegate_Resolved() =>
        AssertTarget(Target("MethodInfoCreateDelegate", "System.Reflection.MethodInfo.CreateDelegate"), SsaTargetKind.Method, null, TypeConst(TargetType), Str("Solo"), Solo());

    // RuntimeReflectionExtensions.GetRuntimeMethod(type, name, ...): type=0 name=1.
    [Fact]
    public void Reflection_GetRuntimeMethod_Resolved() =>
        AssertTarget(Target("RuntimeMethodInvoke", Invoke), SsaTargetKind.Method, null, TypeConst(TargetType), Str("Solo"), Solo());

    // TypeInfo.GetDeclaredMethod on GetTypeInfo(typeof(T)): the type role reads a TypeInfo through its lookup.
    [Fact]
    public void Reflection_GetDeclaredMethodThroughTypeInfo_Resolved() =>
        AssertTarget(Target("DeclaredMethodInvoke", Invoke), SsaTargetKind.Method, null, TypeConst(TargetType), Str("Solo"), Solo());

    // ---- Phis ----------------------------------------------------------------------------------------------------------

    [Fact]
    public void Reflection_PhiOfTwoNames_CandidatesForBoth()
    {
        var both = OneOf(Str(InnerName), Str(TargetType));

        AssertTarget(Target("PhiOfNames", TypeGetType), SsaTargetKind.Type, null, both, null, ["Own.Outer.Inner", TargetType]);
        var constructors = Own("Own.Outer.Inner..ctor", "Own.Target..ctor");
        Assert.Equal(3, constructors.Length);
        AssertTarget(Target("PhiOfNamesCreateInstance", CreateInstance), SsaTargetKind.Constructor, null, both, null, constructors);
    }

    // No phis between lookups: a phi of two Type.GetType results is a call result, not a lookup.
    [Fact]
    public void Reflection_PhiOfLookups_IsDynamicCallResult() =>
        AssertTarget(Target("PhiOfLookups", CreateInstance), SsaTargetKind.Constructor, null, Dynamic(SsaDynamicOrigin.CallResult), null, []);

    // ---- Nesting -------------------------------------------------------------------------------------------------------

    // typeof(T) then 8 lookups (GetTypeInfo, AsType, ...) is within the bound; 9 is past it.
    [Fact]
    public void Reflection_NestingAtTheBound_Resolved() =>
        AssertTarget(Target("Nest" + MaxNesting, CreateInstance), SsaTargetKind.Constructor, null, TypeConst(TargetType), null, TargetConstructors());

    [Fact]
    public void Reflection_NestingPastTheBound_TooDeep() =>
        AssertTarget(Target("Nest" + (MaxNesting + 1), CreateInstance), SsaTargetKind.Constructor, null, Dynamic(SsaDynamicOrigin.TooDeep), null, []);

    // ---- Candidates ----------------------------------------------------------------------------------------------------

    // The first MaxCandidates, ordinal; CandidatesTotal is the full count. At the bound, all are kept.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void Reflection_MaxCandidates_FirstOrdinalKept_TotalIsAll(int max)
    {
        var target = Single(Extract(new SsaFactBounds { MaxCandidates = max }, Site("TypeofGetMethodInvoke", Invoke))).Target!;

        var all = RunOverloads();
        Assert.Equal(all.Take(max), target.Candidates);
        Assert.Equal(all.Length, target.CandidatesTotal);
    }

    [Fact]
    public void Reflection_MaxCandidates_DefaultAndValidated()
    {
        Assert.Equal(64, SsaFactBounds.Default.MaxCandidates);
        Assert.Throws<ArgumentOutOfRangeException>(() => new SsaFactBounds { MaxCandidates = 0 }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => SsaSinkFacts.Extract(fixture.Session, fixture.Sites, new SsaFactBounds { MaxCandidates = -1 }, members: fixture.Members));
    }

    // Without members, nothing is a candidate, and the gap says why (W2: no candidates never reads "not own"); the names
    // stand.
    [Fact]
    public void Reflection_MembersOmitted_NoCandidates_GapSaysSo()
    {
        var facts = SsaSinkFacts.Extract(fixture.Session, [Site("TypeofGetMethodInvoke", Invoke), Site("Name0", TypeGetType)]);

        AssertTarget(Single(facts, "TypeofGetMethodInvoke").Target, SsaTargetKind.Method, null, TypeConst(TargetType), Str("Run"), [], gap: NoIndex);
        AssertTarget(Single(facts, "Name0").Target, SsaTargetKind.Type, null, Str(TargetType), null, [], gap: NoIndex);
        AssertTarget(Single(SsaSinkFacts.Extract(fixture.Session, [Site("Name0", TypeGetType)], members: OwnMembers.None)).Target,
            SsaTargetKind.Type, null, Str(TargetType), null, [], gap: NoIndex);
    }

    // With the whole index of the folder's graph, no target has a gap.
    [Fact]
    public void Reflection_WholeIndex_NoGap()
    {
        Assert.Null(fixture.Members.Gap);
        Assert.False(fixture.Graph.Coverage.Truncated);

        Assert.All(fixture.Facts.Sites.Select(f => f.Target).OfType<SsaReflectionTarget>(), t => Assert.Null(t.CandidatesGap));
    }

    // The gap of whatever index is given is carried as is.
    [Fact]
    public void Reflection_IndexWithAGap_CarriedOnEveryTarget()
    {
        var graph = fixture.Graph;
        var truncated = OwnMembers.Of(MethodGraph.FromParts(graph.Nodes, graph.Edges, graph.Opacities, graph.Coverage with { Truncated = true }, graph.Facts));
        Assert.NotNull(truncated.Gap);

        var fact = Single(SsaSinkFacts.Extract(fixture.Session, [Site("Name0", TypeGetType)], members: truncated));

        AssertTarget(fact.Target, SsaTargetKind.Type, null, Str(TargetType), null, [TargetType], gap: truncated.Gap);
    }

    // A candidate whose node id is past MaxNameChars is bounded like a report's name. The name constant must be whole to
    // match, so MaxTextChars is raised past it.
    [Fact]
    public void Reflection_LongCandidateNodeId_BoundedLikeAReport()
    {
        var raw = Assert.Single(OwnNodes(fixture.Graph, "Own.Long." + LongName));
        Assert.True(raw.Length > Reachability.MaxNameChars);

        var target = Single(Extract(new SsaFactBounds { MaxTextChars = LongName.Length }, Site("LongNameInvoke", Invoke))).Target!;

        Assert.Equal([Reachability.BoundName(raw)], target.Candidates);
        Assert.Equal(1, target.CandidatesTotal);
        Assert.NotEqual(raw, target.Candidates[0]);
    }

    // Under the default MaxTextChars the long name is cut, and a cut name is never matched.
    [Fact]
    public void Reflection_CutName_NotMatched()
    {
        var member = Target("LongNameInvoke", Invoke).Member!;
        Assert.True(Assert.Single(member.Constants).Cut);
        AssertTarget(Target("LongNameInvoke", Invoke), SsaTargetKind.Method, null, TypeConst("Own.Long"), member, []);

        var cutType = Single(Extract(new SsaFactBounds { MaxTextChars = 5 }, Site("Name0", TypeGetType))).Target!;
        Assert.True(Assert.Single(cutType.Type.Constants).Cut);
        Assert.Empty(cutType.Candidates);
        Assert.Equal(0, cutType.CandidatesTotal);
    }

    // Reflection's spelling: nested '+', generic arity with [[...]] or [...] arguments, an assembly-qualified name; an
    // array, pointer, by-ref, malformed or escaped name, or one no own type has, names nothing.
    public static TheoryData<int> NameIndexes => [.. Enumerable.Range(0, Names.Length)];

    [Theory]
    [MemberData(nameof(NameIndexes))]
    public void Reflection_NameParsing_TypeGetTypeSink(int index)
    {
        var (name, typeId) = Names[index];
        if (typeId is not null)
            Assert.Contains(fixture.Graph.Facts.Types, t => t.TypeId == typeId);

        var target = Target("Name" + index, TypeGetType);

        AssertTarget(target, SsaTargetKind.Type, null, Str(UntrustedText.EscapeBounded(name, SsaFactBounds.Default.MaxTextChars)), null, typeId is null ? [] : [typeId]);
    }

    // The escaped name holds the escape: that, not the raw name, is why it is not matched.
    [Fact]
    public void Reflection_EscapedName_HoldsTheEscape()
    {
        var index = Array.FindIndex(Names, n => n.Name.Contains('\\'));
        Assert.True(index >= 0);

        var text = Assert.Single(Target("Name" + index, TypeGetType).Type.Constants).Text;

        Assert.Contains("\\\\", text, StringComparison.Ordinal);
    }

    // ---- Which sites get a target ----------------------------------------------------------------------------------------

    [Fact]
    public void Reflection_NonReflectionSink_NoTarget()
    {
        var fact = Fact("NotReflection", "System.IO.File.ReadAllText");

        Assert.Equal((SsaSiteStatus.Analyzed, Capability.FileSystem), (fact.Status, fact.Site.Capability));
        Assert.Null(fact.Target);
    }

    [Fact]
    public void Reflection_MethodUnknownSite_NoTarget()
    {
        var fact = Fact("Unknowable", TypeGetType);

        Assert.Equal(SsaSiteStatus.MethodUnknown, fact.Status);
        Assert.Null(fact.Target);
    }

    // Offset 0 is the ldstr: the method lifted, but no call is there.
    [Fact]
    public void Reflection_NotJoinedSite_NoTarget()
    {
        var real = Site("Name0", TypeGetType);
        Assert.NotEqual(0u, real.Offset);

        var fact = Single(SsaSinkFacts.Extract(fixture.Session, [real with { Offset = 0 }], members: fixture.Members));

        Assert.Equal(SsaSiteStatus.NotJoined, fact.Status);
        Assert.Null(fact.Target);
    }

    // An ldvirtftn of MethodBase.Invoke is an Analyzed sink site, but not a call: no target.
    [Fact]
    public void Reflection_LdvirtftnSite_NoTarget()
    {
        var fact = Fact("LdvirtftnInvoke", Invoke);

        Assert.Equal((SsaSiteStatus.Analyzed, MethodEdgeKind.Ldvirtftn), (fact.Status, fact.Site.EdgeKind));
        Assert.Null(fact.Target);
    }

    // Every Analyzed call site whose callee key has a target line has a target, and no other site has one.
    [Fact]
    public void Reflection_TargetExactlyOnAnalyzedCallSitesWithATargetLine()
    {
        Assert.All(fixture.Facts.Sites, f =>
        {
            var expected = f.Status == SsaSiteStatus.Analyzed && f.Site.EdgeKind is MethodEdgeKind.Call or MethodEdgeKind.CallVirt
                && ReflectionMap.Default.Target(f.Site.CalleeKey) is not null;
            Assert.True(expected == f.Target is not null, $"{SsaText.Printable(f.Site.NodeId)} -> {f.Site.CalleeKey}: target {(f.Target is null ? "absent" : "present")}.");
        });
        Assert.True(fixture.Facts.Sites.Count(f => f.Target is not null) > 30);
    }

    // ---- Merged definitions ----------------------------------------------------------------------------------------------

    [Fact]
    public void Reflection_MergedNode_TargetsUnioned()
    {
        var fact = Assert.Single(fixture.MergeFacts.Sites, f => f.Site.NodeId == fixture.MergeNodeIdOf("Run"));

        Assert.Equal((SsaSiteStatus.Analyzed, true), (fact.Status, fact.Merged));
        AssertTarget(fact.Target, SsaTargetKind.Type, null, OneOf(Str("Merge.Alpha"), Str("Merge.Beta")), null, ["Merge.Alpha", "Merge.Beta"]);
    }

    // A through GetMethod("Solo"), B through GetConstructor: differing kinds read Member, and a name only one definition
    // gives is not a name.
    [Fact]
    public void Reflection_MergedNode_DifferingKinds_Member()
    {
        var mixed = fixture.MergeNodeIdOf("Mixed");
        var fact = Assert.Single(fixture.MergeFacts.Sites, f => f.Site.NodeId == mixed && f.Site.CalleeKey == Invoke);

        Assert.Equal((SsaSiteStatus.Analyzed, true), (fact.Status, fact.Merged));
        AssertTarget(fact.Target, SsaTargetKind.Member, null, TypeConst("Merge.Shared"), Dynamic(SsaDynamicOrigin.Other), []);
    }

    // ---- Text ----------------------------------------------------------------------------------------------------------

    // Type.GetType("Own.Target"): the argument is charged first and fits the 10 chars; the target's type does not, and is
    // hash-only and Cut. Once spent, the candidate names are dropped too, but their count stands.
    [Fact]
    public void Reflection_TextBudget_TargetChargedAfterArguments_HashOnly()
    {
        var site = Site("Name0", TypeGetType);

        var spent = Extract(new SsaFactBounds { MaxFactTextChars = TargetType.Length }, site);

        Assert.True(spent.TextBudget);
        AssertValue(Str(TargetType), Assert.Single(Single(spent).Arguments));
        AssertTarget(Single(spent).Target, SsaTargetKind.Type, null, CutStr(UntrustedText.HashOnly(TargetType)), null, [], total: 1);
    }

    // W3: the candidate names are charged last, after the argument and the target's type. 30 chars hold all three "Own.Target"s;
    // at 29 the names do not fit, so none is kept, the count stands, and the folder reads TextBudget. The constants are whole.
    [Fact]
    public void Reflection_TextBudget_CandidatesChargedLast_PastItDroppedWhole_CountKept()
    {
        var site = Site("Name0", TypeGetType);

        var fits = Extract(new SsaFactBounds { MaxFactTextChars = 3 * TargetType.Length }, site);
        var past = Extract(new SsaFactBounds { MaxFactTextChars = 3 * TargetType.Length - 1 }, site);

        Assert.False(fits.TextBudget);
        AssertTarget(Single(fits).Target, SsaTargetKind.Type, null, Str(TargetType), null, [TargetType]);
        Assert.True(past.TextBudget);
        AssertValue(Str(TargetType), Assert.Single(Single(past).Arguments));
        AssertTarget(Single(past).Target, SsaTargetKind.Type, null, Str(TargetType), null, [], total: 1);
    }

    // Several candidates are charged together: all of them or none.
    [Fact]
    public void Reflection_TextBudget_CandidatesAllOrNone()
    {
        var site = Site("TypeofGetMethodInvoke", Invoke);
        var constants = TargetType.Length + "Run".Length;
        var names = RunOverloads().Sum(n => n.Length);

        var all = Extract(new SsaFactBounds { MaxFactTextChars = constants + names }, site);
        var none = Extract(new SsaFactBounds { MaxFactTextChars = constants + names - 1 }, site);

        Assert.False(all.TextBudget);
        AssertTarget(Single(all).Target, SsaTargetKind.Method, null, TypeConst(TargetType), Str("Run"), RunOverloads());
        Assert.True(none.TextBudget);
        AssertTarget(Single(none).Target, SsaTargetKind.Method, null, TypeConst(TargetType), Str("Run"), [], total: 3);
    }

    // The budget is the folder's: a later site's names are dropped once an earlier one spent it, even if they would fit alone.
    [Fact]
    public void Reflection_TextBudget_SpentByAnEarlierSite_LaterNamesDropped()
    {
        var earlier = Site("GetTypeGetMethodInvoke", Invoke);
        var later = Site("TypeofGetMethodInvoke", Invoke);
        Assert.True(string.CompareOrdinal(earlier.NodeId, later.NodeId) < 0);
        var budget = TargetType.Length + "Run".Length + RunOverloads().Sum(n => n.Length) + 1;

        var facts = Extract(new SsaFactBounds { MaxFactTextChars = budget }, earlier, later);

        Assert.True(facts.TextBudget);
        AssertTarget(Single(facts, "GetTypeGetMethodInvoke").Target, SsaTargetKind.Method, null, Str(TargetType), Str("Run"), RunOverloads());
        AssertTarget(Single(facts, "TypeofGetMethodInvoke").Target, SsaTargetKind.Method, null,
            SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Type, UntrustedText.HashOnly(TargetType), Cut: true)), CutStr(UntrustedText.HashOnly("Run")), [], total: 3);
    }

    // The Invoke site's receiver is a call result and its arguments are nulls, so only the target is charged: its type,
    // then its member, then the candidate names.
    [Fact]
    public void Reflection_TextBudget_TypeThenMemberThenNames()
    {
        var site = Site("GetTypeGetMethodInvoke", Invoke);
        var constants = TargetType.Length + "Run".Length;

        var memberCut = Extract(new SsaFactBounds { MaxFactTextChars = constants - 1 }, site);
        var bothCut = Extract(new SsaFactBounds { MaxFactTextChars = TargetType.Length - 1 }, site);
        var namesCut = Extract(new SsaFactBounds { MaxFactTextChars = constants }, site);
        var whole = Extract(new SsaFactBounds { MaxFactTextChars = constants + RunOverloads().Sum(n => n.Length) }, site);

        Assert.True(memberCut.TextBudget);
        AssertTarget(Single(memberCut).Target, SsaTargetKind.Method, null, Str(TargetType), CutStr(UntrustedText.HashOnly("Run")), [], total: 3);
        Assert.True(bothCut.TextBudget);
        AssertTarget(Single(bothCut).Target, SsaTargetKind.Method, null, CutStr(UntrustedText.HashOnly(TargetType)), CutStr(UntrustedText.HashOnly("Run")), [], total: 3);
        Assert.True(namesCut.TextBudget);
        AssertTarget(Single(namesCut).Target, SsaTargetKind.Method, null, Str(TargetType), Str("Run"), [], total: 3);
        Assert.False(whole.TextBudget);
        AssertTarget(Single(whole).Target, SsaTargetKind.Method, null, Str(TargetType), Str("Run"), RunOverloads());
    }

    // The assembly is charged before the type.
    [Fact]
    public void Reflection_TextBudget_AssemblyBeforeType()
    {
        var facts = Extract(new SsaFactBounds { MaxFactTextChars = 3 }, Site("AssemblyLoadCreateInstance", CreateInstance));

        Assert.True(facts.TextBudget);
        AssertTarget(Single(facts).Target, SsaTargetKind.Constructor, Str("Asm"), CutStr(UntrustedText.HashOnly(TargetType)), null, [], total: 2);
    }

    // The bounded names are what is charged: a long candidate costs its bounded length (here a little more than its raw
    // length, by the hash suffix), so one char short of it drops the names though the raw name would fit.
    [Fact]
    public void Reflection_TextBudget_ChargesTheBoundedNames()
    {
        var raw = Assert.Single(OwnNodes(fixture.Graph, "Own.Long." + LongName));
        var bounded = Reachability.BoundName(raw);
        Assert.True(raw.Length < bounded.Length, $"raw {raw.Length}, bounded {bounded.Length}");
        var site = Site("LongNameInvoke", Invoke);
        var constants = "Own.Long".Length + LongName.Length;

        var fits = Extract(new SsaFactBounds { MaxTextChars = LongName.Length, MaxFactTextChars = constants + bounded.Length }, site);
        var short1 = Extract(new SsaFactBounds { MaxTextChars = LongName.Length, MaxFactTextChars = constants + bounded.Length - 1 }, site);

        Assert.False(fits.TextBudget);
        Assert.Equal([bounded], Single(fits).Target!.Candidates);
        Assert.True(short1.TextBudget);
        Assert.Empty(Single(short1).Target!.Candidates);
        Assert.Equal(1, Single(short1).Target!.CandidatesTotal);
    }

    // ---- The map is data -------------------------------------------------------------------------------------------------

    [Fact]
    public void Reflection_EmptyMap_NoTargets()
    {
        var empty = ReflectionMap.Load(new StringReader(""), "empty");

        var facts = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, members: fixture.Members, reflection: empty);

        Assert.Equal(fixture.Facts.Count(SsaSiteStatus.Analyzed), facts.Count(SsaSiteStatus.Analyzed));
        Assert.All(facts.Sites, f => Assert.Null(f.Target));
    }

    // A target line for a non-reflection sink gives it a target, read by the same walk.
    [Fact]
    public void Reflection_CustomMap_TargetOnAnotherSink()
    {
        var map = ReflectionMap.Load(new StringReader("target System.IO.File.ReadAllText Type type-name=0"), "custom");
        Assert.Empty(map.RejectedLines);

        var fact = Single(SsaSinkFacts.Extract(fixture.Session, [Site("NotReflection", "System.IO.File.ReadAllText")], members: fixture.Members, reflection: map));

        AssertTarget(fact.Target, SsaTargetKind.Type, null, Str("x"), null, []);
    }

    // The chain follows only the map's lookups: without GetMethod's line, its result is a call result.
    [Fact]
    public void Reflection_CustomMap_UnlistedLookup_IsDynamicCallResult()
    {
        var map = ReflectionMap.Load(new StringReader("target System.Reflection.MethodBase.Invoke Member member=this\nlookup System.Type.GetType Type type-name=0"), "custom");

        var fact = Single(SsaSinkFacts.Extract(fixture.Session, [Site("GetTypeGetMethodInvoke", Invoke)], members: fixture.Members, reflection: map));

        AssertTarget(fact.Target, SsaTargetKind.Member, null, Dynamic(SsaDynamicOrigin.CallResult), Dynamic(SsaDynamicOrigin.CallResult), []);
    }

    // ---- OwnMembers over the fixture -------------------------------------------------------------------------------------

    [Fact]
    public void OwnMembers_OfTheFixtureGraph_OverloadsUnderOneKey_ExternalsExcluded()
    {
        Assert.Equal(RunOverloads(), fixture.Members.Methods(TargetType, "Own.Target.Run"));
        Assert.Equal(RunOverloads(), fixture.Members.Methods("OWN.TARGET", "own.target.run"));
        Assert.Equal(2, fixture.Members.Methods(TargetType, "Own.Target..ctor").Count);
        Assert.Equal(["Own.Outer.Inner"], fixture.Members.Types("Own.Outer.Inner"));
        Assert.Equal(["Own.G`1"], fixture.Members.Types("own.g`1"));
        Assert.Empty(fixture.Members.Types("System.String"));
        Assert.Empty(fixture.Members.Methods("System.String", "System.String.Concat"));
        Assert.Equal(fixture.Graph.Facts.Types.Count, fixture.Members.Count.Types);
    }

    // ---- Review round 1: W2, case and literal ticks ------------------------------------------------------------------------

    // Type.GetType("own.target", false, true).GetMethod("RUN", ... | IgnoreCase): the names match ignoring case.
    [Fact]
    public void Reflection_CaseInsensitiveNames_Candidates() =>
        AssertTarget(Target("CaseInsensitiveInvoke", Invoke), SsaTargetKind.Method, null, Str("own.target"), Str("RUN"), RunOverloads());

    // Ns.Bar`1 is not generic: its name's tick is its own, so the literal spelling matches it.
    [Fact]
    public void Reflection_LiteralTickName_NonGenericType_Candidates()
    {
        var bar = fixture.Graph.Facts.Types.Single(t => t.TypeId.StartsWith("Ns.Bar", StringComparison.Ordinal)).TypeId;
        var run = fixture.Graph.Facts.Methods.Where(m => m.DeclaringTypeId == bar && fixture.Graph.Node(m.NodeId)!.ClassificationKey.EndsWith(".Run", StringComparison.Ordinal))
            .Select(m => m.NodeId).ToArray();
        Assert.Single(run);

        AssertTarget(Target("LiteralTickInvoke", Invoke), SsaTargetKind.Method, null, Str(TickedType), Str("Run"), run);
        AssertTarget(Target("LiteralTickInvoke", TypeGetType), SsaTargetKind.Type, null, Str(TickedType), null, [bar]);
    }

    // ---- Review round 1: W1, definitions per body ----------------------------------------------------------------------

    // typeof(Own.Foo<int>) and typeof(Foo`1<System.Int32>) render as one Type constant, but each site in its own body
    // matches only its own type's methods.
    [Fact]
    public void Reflection_TypesRenderedAlike_InDifferentBodies_EachItsOwnCandidates()
    {
        var (generic, literal) = AliasRuns();
        var genericTarget = Target("AliasGeneric", Invoke);
        var literalTarget = Target("AliasLiteral", Invoke);
        // The premise: the two constants are the same text.
        Assert.True(genericTarget.Type.SameAs(literalTarget.Type), $"{Show(genericTarget.Type)} vs {Show(literalTarget.Type)}");

        AssertTarget(genericTarget, SsaTargetKind.Method, null, TypeConst(AliasType), Str("Run"), generic);
        AssertTarget(literalTarget, SsaTargetKind.Method, null, TypeConst(AliasType), Str("Run"), literal);
    }

    // In one body, the constant stands for both definitions: both sites over-approximate to both types' methods.
    [Fact]
    public void Reflection_TypesRenderedAlike_InOneBody_BothCandidates()
    {
        var (generic, literal) = AliasRuns();
        string[] both = [.. generic.Concat(literal).Order(StringComparer.Ordinal)];
        var sites = fixture.Facts.Sites.Where(f => f.Site.NodeId == fixture.NodeIdOf("AliasBoth") && f.Site.CalleeKey == Invoke).ToArray();

        Assert.Equal(2, sites.Length);
        Assert.All(sites, f => AssertTarget(f.Target, SsaTargetKind.Method, null, TypeConst(AliasType), Str("Run"), both));
    }

    // Extracted alone, in either order with the other, a site's candidates are its own: nothing carries across bodies.
    [Fact]
    public void Reflection_TypesRenderedAlike_OrderAcrossBodies_DoesNotMatter()
    {
        var (generic, literal) = AliasRuns();

        var facts = Extract(SsaFactBounds.Default, Site("AliasLiteral", Invoke), Site("AliasGeneric", Invoke));
        var genericAlone = Extract(SsaFactBounds.Default, Site("AliasGeneric", Invoke));

        Assert.Equal(generic, Single(facts, "AliasGeneric").Target!.Candidates);
        Assert.Equal(literal, Single(facts, "AliasLiteral").Target!.Candidates);
        Assert.Equal(generic, Single(genericAlone).Target!.Candidates);
    }

    // ---- Review round 1: W4, generic parameters ------------------------------------------------------------------------

    // CreateInstance<T>() with T the caller's own parameter: Dynamic(TypeParameter), not a !!0 constant.
    [Fact]
    public void Reflection_CreateInstanceOfOwnParameter_IsDynamicTypeParameter() =>
        AssertTarget(Target("GenericCreateInstanceOfT", CreateInstance), SsaTargetKind.Constructor, null, Dynamic(SsaDynamicOrigin.TypeParameter), null, []);

    // typeof(T) of a method's or a type's parameter, as an argument and as the target's type.
    [Fact]
    public void Reflection_TypeofMethodParameter_IsDynamicTypeParameter_InArgumentAndTarget()
    {
        var fact = Fact("GenericTypeofCreateInstance", CreateInstance);

        AssertValue(Dynamic(SsaDynamicOrigin.TypeParameter), Assert.Single(fact.Arguments));
        AssertTarget(fact.Target, SsaTargetKind.Constructor, null, Dynamic(SsaDynamicOrigin.TypeParameter), null, []);
    }

    [Fact]
    public void Reflection_TypeofTypeParameter_IsDynamicTypeParameter()
    {
        var site = fixture.SiteAt(HolderType + ".Make", CreateInstance);
        var fact = Assert.Single(fixture.Facts.Sites, f => f.Site == site);

        AssertValue(Dynamic(SsaDynamicOrigin.TypeParameter), Assert.Single(fact.Arguments));
        AssertTarget(fact.Target, SsaTargetKind.Constructor, null, Dynamic(SsaDynamicOrigin.TypeParameter), null, []);
    }

    // Twin: a closed CreateInstance<Own.Target>() stays a constant (Reflection_CreateInstanceOfT_GenericArgument), and no
    // fixture target or argument is a bare !0 or !!0 constant.
    [Fact]
    public void Reflection_NoBareGenericParameterConstant()
    {
        var values = fixture.Facts.Sites.SelectMany(f => f.Arguments
            .Concat(new[] { f.Receiver, f.Target?.Type, f.Target?.Member, f.Target?.Assembly }.OfType<SsaValue>()));
        Assert.Contains(values.SelectMany(v => v.Constants), c => c.Kind == SsaConstantKind.Type);

        Assert.DoesNotContain(values.SelectMany(v => v.Constants), c => c.Kind == SsaConstantKind.Type && c.Text.StartsWith('!'));
    }

    // ---- Review round 1: merged targets' type names ----------------------------------------------------------------------

    // A's Type.GetType("Merge.Alpha") and B's Type.GetType(field): the unioned type is Dynamic, so A's name is dropped and
    // nothing is a candidate.
    [Fact]
    public void Reflection_MergedNode_TypeUnionDynamic_NamesDropped()
    {
        var fact = Assert.Single(fixture.MergeFacts.Sites, f => f.Site.NodeId == fixture.MergeNodeIdOf("Swerve"));

        Assert.Equal((SsaSiteStatus.Analyzed, true), (fact.Status, fact.Merged));
        AssertTarget(fact.Target, SsaTargetKind.Type, null, Dynamic(SsaDynamicOrigin.FieldLoad), null, []);
        Assert.NotEmpty(fixture.MergeMembers.Types("Merge.Alpha"));
    }

    // Past MaxAlternatives the union of two names is Dynamic(TooManyAlternatives): both names are dropped.
    [Fact]
    public void Reflection_MergedNode_UnionPastMaxAlternatives_NamesDropped()
    {
        var site = Assert.Single(fixture.MergeSites, s => s.NodeId == fixture.MergeNodeIdOf("Run"));

        var fact = Assert.Single(SsaSinkFacts.Extract(fixture.MergeSession, [site], new SsaFactBounds { MaxAlternatives = 1 }, members: fixture.MergeMembers).Sites);

        Assert.True(fact.Merged);
        AssertTarget(fact.Target, SsaTargetKind.Type, null, Dynamic(SsaDynamicOrigin.TooManyAlternatives), null, []);
    }

    // ---- Review round 2: W5, the type-name cap ---------------------------------------------------------------------------

    // 9 tick-bearing names give 18 type names: past the cap, the gap says so. Own.G`1 sorts first, so it is still searched:
    // the Type sink lists the own type, and GetMethod("Run") lists its Run.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reflection_OverMaxTypeNames_GapSaysSo_OwnTypeWithinTheCapStillACandidate(bool invoke)
    {
        var target = TickedTarget("TickedOwnFirst9", invoke, fixture.Members);

        AssertTicked(target, TickedOwnFirst9, invoke, OwnG(invoke), TooManyNames);
    }

    // Own.G`1 sorts last: its two type names are the ones cut, so nothing is a candidate, and the gap says why.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reflection_OverMaxTypeNames_OwnTypePastTheCap_NotSearched(bool invoke)
    {
        var target = TickedTarget("TickedOwnLast9", invoke, fixture.Members);

        AssertTicked(target, TickedOwnLast9, invoke, [], TooManyNames);
    }

    // 8 names give exactly 16 type names: within the cap, no gap with the whole index.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reflection_AtMaxTypeNames_NoGap(bool invoke)
    {
        Assert.Equal(MaxTypeNames, 2 * TickedOwnFirst8.Length);

        var target = TickedTarget("TickedOwnFirst8", invoke, fixture.Members);

        AssertTicked(target, TickedOwnFirst8, invoke, OwnG(invoke), null);
    }

    // Both reasons: no index, and over the cap, joined in that order.
    [Fact]
    public void Reflection_NoIndexAndOverMaxTypeNames_BothReasons()
    {
        var target = TickedTarget("TickedOwnFirst9", invoke: false, members: null);

        AssertTicked(target, TickedOwnFirst9, invoke: false, [], NoIndex + "; " + TooManyNames);
    }

    // Twin: under the default MaxAlternatives the 9 names are Dynamic(TooManyAlternatives), so no type name is read and
    // there is no cap to report.
    [Fact]
    public void Reflection_TooManyAlternatives_NoTypeNames_NoCapGap() =>
        AssertTarget(Target("TickedOwnFirst9", TypeGetType), SsaTargetKind.Type, null, Dynamic(SsaDynamicOrigin.TooManyAlternatives), null, []);

    // The flag survives a merged union: A's 18 type names were cut to 16, B has the same 16, so the union's kept names are
    // 16, and only A's flag says some were left out.
    [Fact]
    public void Reflection_MergedNode_CapFlagSurvivesTheUnion()
    {
        var site = Assert.Single(fixture.MergeSites, s => s.NodeId == fixture.MergeNodeIdOf("Ticked"));

        var fact = Assert.Single(SsaSinkFacts.Extract(fixture.MergeSession, [site], new SsaFactBounds { MaxAlternatives = 9 }, members: fixture.MergeMembers).Sites);

        Assert.Equal((SsaSiteStatus.Analyzed, true), (fact.Status, fact.Merged));
        AssertTarget(fact.Target, SsaTargetKind.Type, null, OneOfNames(MergeTicked), null, [], gap: TooManyNames);
    }

    // ---- Review round 1: C1, cost ----------------------------------------------------------------------------------------

    // 2,000 overloads of Own.Many.Run and 2,000 sites naming them: each site keeps the first MaxCandidates ordinal, of
    // 2,000. Before the fix every site sorted every overload; the bound is generous (a regression, not a benchmark).
    [Fact]
    public void Cost_ManyOverloadsAtManySites_FirstMaxCandidates_Bounded()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("SsaReflectionMany", DefineMany);
        MethodGraph graph;
        using (var model = ModelAssemblies.Load(path))
            graph = MethodGraph.Build(model.Index());
        var sites = SinkSites.Of(graph).Where(s => s.CalleeKey == Invoke).ToArray();
        Assert.Equal(ManyMethods * ManySitesPerMethod, sites.Length);
        var overloads = OwnNodes(graph, ManyType + ".Run");
        Assert.Equal(ManyOverloads, overloads.Length);
        var members = OwnMembers.Of(graph);
        using var session = SsaSession.Open([path]);
        // Every name kept: 2,000 sites of 64 names each.
        var bounds = new SsaFactBounds { MaxFactTextChars = int.MaxValue };

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var facts = SsaSinkFacts.Extract(session, sites, bounds, members: members);
        clock.Stop();

        var first = overloads.Take(SsaFactBounds.Default.MaxCandidates).ToArray();
        Assert.False(facts.TextBudget);
        Assert.Equal(sites.Length, facts.Count(SsaSiteStatus.Analyzed));
        Assert.All(facts.Sites, f => AssertTarget(f.Target, SsaTargetKind.Method, null, TypeConst(ManyType), Str("Run"), first, total: ManyOverloads));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"{sites.Length} sites took {clock.ElapsedMilliseconds} ms.");
    }

    // ---- Determinism ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Reflection_ExtractTwice_Identical()
    {
        var again = SsaSinkFacts.Extract(fixture.Session, fixture.Sites, members: fixture.Members);

        Assert.Equal(JsonSerializer.Serialize(fixture.Facts), JsonSerializer.Serialize(again));
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private SinkSite Site(string method, string calleeKey) => fixture.SiteOf(method, calleeKey);

    private SsaSinkFact Fact(string method, string calleeKey)
    {
        var site = Site(method, calleeKey);
        return Assert.Single(fixture.Facts.Sites, f => f.Site == site);
    }

    // The target of an Analyzed site, asserting it has one.
    private SsaReflectionTarget Target(string method, string calleeKey)
    {
        var fact = Fact(method, calleeKey);
        Assert.True(fact.Status == SsaSiteStatus.Analyzed, $"{method} -> {calleeKey}: {fact.Status} ({fact.Reason}).");
        Assert.NotNull(fact.Target);
        return fact.Target!;
    }

    private SsaSinkFact Single(SsaFolderFacts facts, string method) => Assert.Single(facts.Sites, f => f.Site.NodeId == fixture.NodeIdOf(method));

    private static SsaSinkFact Single(SsaFolderFacts facts) => Assert.Single(facts.Sites);

    private SsaFolderFacts Extract(SsaFactBounds bounds, params SinkSite[] sites) => SsaSinkFacts.Extract(fixture.Session, sites, bounds, members: fixture.Members);

    private string[] Own(params string[] keys) => [.. keys.SelectMany(k => OwnNodes(fixture.Graph, k)).Order(StringComparer.Ordinal)];

    private string[] RunOverloads()
    {
        var overloads = Own("Own.Target.Run");
        Assert.Equal(3, overloads.Length);
        return overloads;
    }

    private string[] TargetConstructors()
    {
        var constructors = Own("Own.Target..ctor");
        Assert.Equal(2, constructors.Length);
        return constructors;
    }

    private string[] Solo() => [Assert.Single(Own("Own.Target.Solo"))];

    // The target of a Ticked caller's Type.GetType site (or, with invoke, its Invoke site), under MaxAlternatives 9.
    private SsaReflectionTarget TickedTarget(string method, bool invoke, OwnMembers? members)
    {
        var site = invoke ? Site(method + "Invoke", Invoke) : Site(method, TypeGetType);
        var fact = Single(SsaSinkFacts.Extract(fixture.Session, [site], new SsaFactBounds { MaxAlternatives = 9 }, members: members));
        Assert.Equal(SsaSiteStatus.Analyzed, fact.Status);
        return fact.Target!;
    }

    private static void AssertTicked(SsaReflectionTarget target, string[] names, bool invoke, string[] candidates, string? gap) =>
        AssertTarget(target, invoke ? SsaTargetKind.Method : SsaTargetKind.Type, null, OneOfNames(names), invoke ? Str("Run") : null, candidates, gap: gap);

    // Own.G`1 itself for a Type target, its Run for GetMethod("Run").
    private string[] OwnG(bool invoke) => invoke ? [Assert.Single(Own("Own.G.Run"))] : ["Own.G`1"];

    private static SsaValue OneOfNames(string[] names) => OneOf([.. names.Order(StringComparer.Ordinal).Select(Str)]);

    // The Run methods of Own.Foo`1 (one) and of the type literally named Foo`1<System.Int32> (two), by declaring type id.
    private (string[] Generic, string[] Literal) AliasRuns()
    {
        var graph = fixture.Graph;
        var types = graph.Facts.Types.Select(t => t.TypeId).Where(id => id.StartsWith("Own.Foo", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, types.Length);
        string[] Runs(string type) => [.. graph.Facts.Methods
            .Where(m => m.DeclaringTypeId == type && graph.Node(m.NodeId)!.ClassificationKey.EndsWith(".Run", StringComparison.Ordinal))
            .Select(m => m.NodeId).Order(StringComparer.Ordinal)];
        var generic = Runs("Own.Foo`1");
        var literal = Runs(Assert.Single(types, t => t != "Own.Foo`1"));
        Assert.Single(generic);
        Assert.Equal(2, literal.Length);
        return (generic, literal);
    }

    // Total defaults to the candidates' count; the gap to none (the fixture's index is whole).
    private static void AssertTarget(SsaReflectionTarget? actual, SsaTargetKind kind, SsaValue? assembly, SsaValue type, SsaValue? member, string[] candidates,
        int? total = null, string? gap = null)
    {
        Assert.NotNull(actual);
        var shown = SsaText.Printable(JsonSerializer.Serialize(actual));
        Assert.True(actual!.Kind == kind, $"Kind: expected {kind}\n{shown}");
        Assert.True(Same(assembly, actual.Assembly), $"Assembly: expected {Show(assembly)}\n{shown}");
        Assert.True(Same(type, actual.Type), $"Type: expected {Show(type)}\n{shown}");
        Assert.True(Same(member, actual.Member), $"Member: expected {Show(member)}\n{shown}");
        Assert.Equal(SsaCandidateMatch.ByName, actual.Match);
        Assert.Equal(candidates, actual.Candidates);
        Assert.Equal(total ?? candidates.Length, actual.CandidatesTotal);
        Assert.Equal(gap, actual.CandidatesGap);
    }

    private static bool Same(SsaValue? expected, SsaValue? actual) => expected is null ? actual is null : actual is not null && expected.SameAs(actual);

    private static void AssertValue(SsaValue expected, SsaValue? actual) =>
        Assert.True(actual is not null && expected.SameAs(actual), $"Expected {Show(expected)}\nActual   {Show(actual)}");

    private static SsaValue Str(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text));

    private static SsaValue CutStr(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text, Cut: true));

    private static SsaValue TypeConst(string name) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Type, name));

    private static SsaValue OneOf(params SsaValue[] values) => new(SsaValueKind.OneOf, [.. values.Select(v => v.Constants[0])], null, null);

    private static SsaValue Parameter(int index) => SsaValue.OfParameter(index);

    private static SsaValue Dynamic(SsaDynamicOrigin origin) => SsaValue.OfDynamic(origin);

    private static string Show(object? value) => SsaText.Printable(JsonSerializer.Serialize(value));
    #endregion

    #region Fields
    private const string Invoke = "System.Reflection.MethodBase.Invoke";
    private const string CreateInstance = "System.Activator.CreateInstance";
    private const string CreateDelegate = "System.Delegate.CreateDelegate";
    private const string TypeGetType = "System.Type.GetType";
    private const string NoIndex = "no own-member index was given";
    private const string TooManyNames = "the type stands for more than 16 type names, and only the first 16 were searched";

    private readonly SsaReflectionFixture fixture;
    #endregion
}
