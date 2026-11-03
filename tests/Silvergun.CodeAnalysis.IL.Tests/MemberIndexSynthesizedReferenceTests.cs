namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SyntheticModel;

using ModelTypes = Model.Types;

/// <summary>
/// Review 2's findings on <see cref="MemberIndex.Resolve"/> and the graph (spec §2.6, S2), driven by HAND-BUILT
/// references (<see cref="SyntheticModel"/>) into the real, indexed mechanism fixture — shapes no C# compiler emits:
/// <list type="bullet">
/// <item><description><b>Unknown arguments</b> — when <see cref="ModelNames.TypeArguments"/> is <c>null</c> (a chain that
/// does not add up, a throwing read), nothing was checked, so every same-shape candidate is kept and the answer is
/// <see cref="ResolutionKind.Ambiguous"/> — even for ONE candidate: "don't know" includes, never excludes.</description></item>
/// <item><description><b>C-B</b> — the memo key once joined its parts with U+0001, which metadata names may contain, so two
/// different references could share a key and the second got the first's answer.</description></item>
/// <item><description><b>W-3</b> — an Unresolved site whose id textually equals an own method's stays a QUALIFIED leaf,
/// never merged into the own node.</description></item>
/// <item><description><b>S2 tightenings</b> — more Model arguments than the arity, or an argument rendering
/// <c>&lt;unknown&gt;</c>, is unknown too (spec §2.6).</description></item>
/// <item><description><b>N-2 / W-4 rebinding</b> (review 3, spec §2.7) — unknown arguments with nothing of the shape
/// say "no indexed definition has this shape; …"; a memoized not-own answer is rebound to each reference's own node
/// id and key. The W-4 node-id collision itself is pinned on an emitted assembly in
/// <see cref="MemoKeyNodeIdCollisionTests"/>.</description></item>
/// </list>
/// The indexed definitions used: <c>Pair&lt;T1,T2&gt; { Set(T1); Set(T2) }</c> (<c>Set(!0)</c>, <c>Set(!1)</c>),
/// <c>Outer4&lt;T&gt;.Mid.Inner&lt;U&gt;.Lone&lt;V&gt; { M(T) }</c> and <c>Box&lt;T&gt; { Run() }</c>.
/// </summary>
public sealed class MemberIndexSynthesizedReferenceTests : IClassFixture<MechanismMethodGraphFixture>
{
    #region Constructors
    public MemberIndexSynthesizedReferenceTests(MechanismMethodGraphFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- unknown type arguments -----------------------------------------------------------------------------------

    /// <summary>
    /// <c>Pair`2</c> with ONE argument: the list does not add up, so neither <c>Set</c> can be checked — both are kept.
    /// </summary>
    [Fact]
    public void Resolve_WithUnrecoverableArguments_AndTwoSameShapeCandidates_IsAmbiguousWithBoth()
    {
        var reference = Method(PairOf(IntType), "Set", IntType);
        Assert.Null(ModelNames.TypeArguments(reference.ContainingType));

        var resolution = fixture.Index.Resolve(reference);

        Assert.Equal(ResolutionKind.Ambiguous, resolution.Kind);
        Assert.False(resolution.IsOwn);
        Assert.Null(resolution.Definition);
        Assert.Equal(Pair + ".Set(System.Int32)", resolution.NodeId);
        Assert.Equal([SetFirst, SetSecond], resolution.Candidates);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Equal(UnknownArguments, resolution.Reason);
    }

    /// <summary>
    /// <c>Lone</c>'s chain with an instantiated <c>Inner&lt;int&gt;</c> under a DEFINITION <c>Outer4</c>: the prefix is
    /// unknown, so the one same-shape candidate <c>M(!0)</c> is NOT accepted unchecked — Ambiguous over it alone, even
    /// when the reference's own text happens to be that candidate's node id.
    /// </summary>
    [Theory]
    [InlineData("System.String")]
    [InlineData("!0")]
    public void Resolve_WithUnrecoverableArguments_AndOneSameShapeCandidate_IsStillAmbiguous(string parameter)
    {
        var reference = Method(UnknownLone(), "M", parameter == "!0" ? TypeParameter(0) : StringType);
        Assert.Null(ModelNames.TypeArguments(reference.ContainingType));
        Assert.Equal(parameter == "!0", fixture.Index.IsOwnMethod(CanonicalName.NodeId(ModelNames.Of(reference))));

        var resolution = fixture.Index.Resolve(reference);

        Assert.True(resolution.Kind == ResolutionKind.Ambiguous,
            $"{resolution.NodeId} resolved {resolution.Kind} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}); expected Ambiguous over the lone candidate.");
        Assert.Null(resolution.Definition);
        Assert.Equal($"{Lone}.M({parameter})", resolution.NodeId);
        Assert.Equal([LoneOfT], resolution.Candidates);
        Assert.Equal(UnknownArguments, resolution.Reason);
    }

    /// <summary>A throwing <c>GenericArguments</c> read is unknown too: Ambiguous over the same shape, two candidates or one.</summary>
    [Fact]
    public void Resolve_WhenReadingTheArgumentsThrows_IsAmbiguousOverTheSameShape()
    {
        var pair = fixture.Index.Resolve(Method(new ThrowingBasicType(PairOf(IntType, StringType)) { ThrowOnGenericArguments = true }, "Set", IntType));
        var box = fixture.Index.Resolve(Method(
            new ThrowingBasicType(TypeRef(Generics, "Box", 1, assembly: MechanismFixtureAssemblies.FixtureName, arguments: [IntType])) { ThrowOnGenericArguments = true },
            "Run"));

        Assert.Equal((ResolutionKind.Ambiguous, UnknownArguments), (pair.Kind, pair.Reason));
        Assert.Equal([SetFirst, SetSecond], pair.Candidates);
        Assert.Equal((ResolutionKind.Ambiguous, UnknownArguments), (box.Kind, box.Reason));
        Assert.Equal([BoxRun], box.Candidates);
    }

    /// <summary>
    /// The same unknown-argument references, called from a synthetic caller indexed beside the fixture: the graph
    /// keeps an edge to EVERY candidate — to the lone own definition too — plus an Ambiguous opacity, and invents no
    /// node under the reference's own id.
    /// </summary>
    [Fact]
    public void Build_WithUnrecoverableArguments_EdgesGoToEveryCandidate_EvenALoneOne()
    {
        var lone = Method(UnknownLone(), "M", StringType);
        var pair = Method(PairOf(IntType), "Set", IntType);
        var (index, graph) = BuildWith(("CallsLone", lone), ("CallsPair", pair));

        Assert.Equal([new MethodEdge(CallerId("CallsLone"), LoneOfT, MethodEdgeKind.Call, CallOffset)], graph.Successors(CallerId("CallsLone")));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(LoneOfT)?.Kind);
        Assert.Null(graph.Node($"{Lone}.M(System.String)"));
        Assert.Equal(
            [new GraphOpacity(CallerId("CallsLone"), CallOffset, OpacityKind.Ambiguous, $"{Lone}.M(System.String): {UnknownArguments}")],
            graph.Opacities.Where(o => o.Site == CallerId("CallsLone")));

        Assert.Equal(
            [new MethodEdge(CallerId("CallsPair"), SetFirst, MethodEdgeKind.Call, CallOffset), new MethodEdge(CallerId("CallsPair"), SetSecond, MethodEdgeKind.Call, CallOffset)],
            graph.Successors(CallerId("CallsPair")));
        Assert.Equal(
            [new GraphOpacity(CallerId("CallsPair"), CallOffset, OpacityKind.Ambiguous, $"{Pair}.Set(System.Int32): {UnknownArguments}")],
            graph.Opacities.Where(o => o.Site == CallerId("CallsPair")));
        Assert.True(index.Coverage.IsComplete);
    }

    // ---- C-B: the memo key ----------------------------------------------------------------------------------------

    /// <summary>
    /// The premise, measured: R1 = <c>Pair&lt;NS.A, "Z\u0001NS.A"&gt;.Set(T1)</c> and R2 = <c>Pair&lt;"NS.A\u0001Z", NS.A&gt;.Set(T2)</c>
    /// render one node id and DIFFERENT argument lists, yet the pre-S2 key — every part joined with U+0001 — is the same
    /// string for both. They bind different definitions (R1 <c>Set(!0)</c>, R2 <c>Set(!1)</c>).
    /// </summary>
    [Fact]
    public void Premise_TwoDifferentReferences_HaveOneOldU0001JoinedKey()
    {
        var (r1, r2) = CollidingReferences();

        Assert.Equal(CanonicalName.NodeId(ModelNames.Of(r1)), CanonicalName.NodeId(ModelNames.Of(r2)));
        Assert.Equal(["NS.A", "Z\u0001NS.A"], ModelNames.TypeArguments(r1.ContainingType));
        Assert.Equal(["NS.A\u0001Z", "NS.A"], ModelNames.TypeArguments(r2.ContainingType));
        Assert.Equal(OldJoinedKey(r1), OldJoinedKey(r2));
    }

    /// <summary>
    /// C-B: on a FRESH index (empty memo) each reference resolves to its own definition whichever is resolved first —
    /// with the old key the second got the first's answer, in both orders. Length-prefixed keys keep them apart.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Resolve_TwoReferencesWhoseOldKeysCollide_EachResolveToTheirOwnDefinition_InEitherOrder(bool secondFirst)
    {
        var (r1, r2) = CollidingReferences();
        var index = MemberIndex.Build(fixture.Assemblies.Disassemblers);

        var (first, second) = secondFirst ? (r2, r1) : (r1, r2);
        var firstResolution = index.Resolve(first);
        var secondResolution = index.Resolve(second);
        var (resolved1, resolved2) = secondFirst ? (secondResolution, firstResolution) : (firstResolution, secondResolution);

        Assert.True(resolved1.Kind == ResolutionKind.Substituted && resolved1.NodeId == SetFirst,
            $"R1 resolved {resolved1.Kind} -> {resolved1.NodeId} ({resolved1.Reason}); expected Substituted to {SetFirst}.");
        Assert.True(resolved2.Kind == ResolutionKind.Substituted && resolved2.NodeId == SetSecond,
            $"R2 resolved {resolved2.Kind} -> {resolved2.NodeId} ({resolved2.Reason}); expected Substituted to {SetSecond}.");
        Assert.Equal([SetFirst], resolved1.Candidates);
        Assert.Equal([SetSecond], resolved2.Candidates);

        // Asking again (now from the memo) gives the same answers.
        Assert.Equal((ResolutionKind.Substituted, SetFirst), (index.Resolve(r1).Kind, index.Resolve(r1).NodeId));
        Assert.Equal((ResolutionKind.Substituted, SetSecond), (index.Resolve(r2).Kind, index.Resolve(r2).NodeId));
    }

    // ---- W-3 -------------------------------------------------------------------------------------------------------

    /// <summary>
    /// W-3: <c>Pair&lt;int,string&gt;.Set(!1)</c> — a stray type parameter in a reference through an instantiation —
    /// renders, by text, the node id of the own definition <c>Set(!1)</c>, yet neither definition matches once the
    /// arguments are substituted (<c>Set(System.Int32)</c>, <c>Set(System.String)</c>): Unresolved. The edge goes to the
    /// QUALIFIED leaf <c>[assembly]id</c>, not the own node; the Unresolved opacity detail starts with that same qualified
    /// id; and no NameShadowed is added (the site already carries its opacity).
    /// </summary>
    [Fact]
    public void Build_AnUnresolvedSiteWhoseIdIsAnOwnMethods_StaysAQualifiedLeaf_WithoutNameShadowed()
    {
        var stray = Method(PairOf(IntType, StringType), "Set", TypeParameter(1));
        var qualified = MemberIndex.Qualified(MechanismFixtureAssemblies.FixtureName, SetSecond);
        var (index, graph) = BuildWith(("CallsStray", stray));

        var resolution = index.Resolve(stray);
        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.Equal(SetSecond, resolution.NodeId);
        Assert.True(index.IsOwnMethod(resolution.NodeId));
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
        Assert.Equal("no indexed definition matches", resolution.Reason);

        Assert.Equal($"[{MechanismFixtureAssemblies.FixtureName}]{SetSecond}", qualified);
        Assert.Equal([new MethodEdge(CallerId("CallsStray"), qualified, MethodEdgeKind.Call, CallOffset)], graph.Successors(CallerId("CallsStray")));
        Assert.Equal(new MethodNode(qualified, Pair[..^2] + ".Set", MethodNodeKind.External), graph.Node(qualified));
        Assert.Equal(MethodNodeKind.OwnWithBody, graph.Node(SetSecond)?.Kind);

        var opacity = Assert.Single(graph.Opacities, o => o.Site == CallerId("CallsStray"));
        Assert.Equal(OpacityKind.Unresolved, opacity.Kind);
        Assert.Equal(CallOffset, opacity.Offset);
        Assert.StartsWith(qualified + ":", opacity.Detail, StringComparison.Ordinal);
        Assert.Equal($"{qualified}: no indexed definition matches", opacity.Detail);
        Assert.DoesNotContain(graph.Opacities, o => o.Kind == OpacityKind.NameShadowed);
        Assert.Equal(1, graph.Coverage.Resolutions.Unresolved);
    }

    // ---- S2 tightenings, through Resolve (spec §2.6, last bullet) ---------------------------------------------------

    /// <summary>
    /// More Model arguments than the arity (<c>Pair`2</c> with three, <c>Box`1</c> with two) is unknown, not taken as-is:
    /// Ambiguous over the same-shape bucket — both <c>Set</c>s, and the lone <c>Run</c> too. Taken as-is, the first
    /// argument would have substituted <c>!0</c> and <c>Set(!0)</c> would have won alone.
    /// </summary>
    [Fact]
    public void Resolve_WhenTheInstantiationCarriesMoreArgumentsThanItsArity_IsAmbiguousOverTheSameShape()
    {
        var index = FreshIndex();
        var pairReference = Method(PairOf(IntType, StringType, BoolType), "Set", IntType);
        var boxReference = Method(TypeRef(Generics, "Box", 1, assembly: MechanismFixtureAssemblies.FixtureName, arguments: [IntType, StringType]), "Run");
        Assert.Null(ModelNames.TypeArguments(pairReference.ContainingType));
        Assert.Null(ModelNames.TypeArguments(boxReference.ContainingType));

        var pair = index.Resolve(pairReference);
        var box = index.Resolve(boxReference);

        Assert.True((pair.Kind, pair.Reason) == (ResolutionKind.Ambiguous, UnknownArguments),
            $"Pair`2 with three arguments resolved {pair.Kind} -> {pair.NodeId} ({pair.Reason}).");
        Assert.Equal([SetFirst, SetSecond], pair.Candidates);
        Assert.Null(pair.Definition);
        Assert.True((box.Kind, box.Reason) == (ResolutionKind.Ambiguous, UnknownArguments),
            $"Box`1 with two arguments resolved {box.Kind} -> {box.NodeId} ({box.Reason}).");
        Assert.Equal([BoxRun], box.Candidates);
        Assert.Null(box.Definition);
    }

    /// <summary>
    /// <c>Pair&lt;int, X&gt;.Set(int)</c> where <c>X</c> renders <c>&lt;unknown&gt;</c>: the arguments are unknown, so both
    /// <c>Set</c>s are kept (Ambiguous) — with <c>X</c> substituted as a guess, <c>Set(!0)</c> would have won alone. The
    /// control, <c>Pair&lt;int, string&gt;.Set(int)</c>, resolves Substituted to <c>Set(!0)</c>.
    /// </summary>
    [Theory]
    [MemberData(nameof(ModelNamesSubstitutionTests.ArgumentsThatRenderUnknown), MemberType = typeof(ModelNamesSubstitutionTests))]
    public void Resolve_WhenARecoveredArgumentRendersUnknown_IsAmbiguousOverTheSameShape(string what, ModelTypes.IType? argument)
    {
        var index = FreshIndex();
        var control = index.Resolve(Method(PairOf(IntType, StringType), "Set", IntType));
        Assert.Equal((ResolutionKind.Substituted, SetFirst), (control.Kind, control.NodeId));

        var resolution = index.Resolve(Method(PairOf(IntType, argument!), "Set", IntType));

        Assert.True((resolution.Kind, resolution.Reason) == (ResolutionKind.Ambiguous, UnknownArguments),
            $"{what}: resolved {resolution.Kind} -> {resolution.NodeId} [{string.Join(", ", resolution.Candidates)}] ({resolution.Reason}).");
        Assert.Equal([SetFirst, SetSecond], resolution.Candidates);
        Assert.Null(resolution.Definition);
        Assert.Equal(Pair + ".Set(System.Int32)", resolution.NodeId);
    }

    // ---- N-2: unknown arguments and nothing of this shape ----------------------------------------------------------

    /// <summary>
    /// N-2: unknown arguments and an EMPTY same-shape bucket (no such method name; no such parameter count) is
    /// Unresolved, and says so: "no indexed definition has this shape; " followed by why nothing could be checked.
    /// </summary>
    [Theory]
    [InlineData("Absent", 1)]
    [InlineData("Set", 2)]
    public void Resolve_WithUnrecoverableArguments_AndNoDefinitionOfThatShape_IsUnresolved(string name, int parameters)
    {
        var reference = Method(PairOf(IntType), name, [.. Enumerable.Repeat<ModelTypes.IType>(IntType, parameters)]);
        Assert.Null(ModelNames.TypeArguments(reference.ContainingType));

        var resolution = FreshIndex().Resolve(reference);

        Assert.Equal(ResolutionKind.Unresolved, resolution.Kind);
        Assert.StartsWith("no indexed definition has this shape", resolution.Reason, StringComparison.Ordinal);
        Assert.Equal($"no indexed definition has this shape; {UnknownArguments}", resolution.Reason);
        Assert.Empty(resolution.Candidates);
        Assert.Null(resolution.Definition);
        Assert.Equal(CanonicalName.NodeId(ModelNames.Of(reference)), resolution.NodeId);
        Assert.Equal(MechanismFixtureAssemblies.FixtureName, resolution.Assembly);
    }

    // ---- W-4: a memoized answer is rebound to each reference ---------------------------------------------------------

    /// <summary>
    /// Two generic method instances (<c>Set&lt;int&gt;</c>, <c>Set&lt;string&gt;</c>) of ONE generic method share a memo
    /// entry — the key is about the target they resolve through — but are different references. A not-own answer
    /// (Ambiguous: the target's instantiation is unknown; Unresolved: nothing matches) carries the REFERENCE's node id
    /// and classification key, so each must get its own back, whichever is resolved first.
    /// </summary>
    [Theory]
    [InlineData(ResolutionKind.Ambiguous, false)]
    [InlineData(ResolutionKind.Ambiguous, true)]
    [InlineData(ResolutionKind.Unresolved, false)]
    [InlineData(ResolutionKind.Unresolved, true)]
    public void Resolve_TwoInstancesSharingAMemoEntry_EachGetTheirOwnNodeIdAndKey(ResolutionKind expected, bool secondFirst)
    {
        // Ambiguous: Pair`2 with one argument (unknown) - both Sets. Unresolved: Pair<int,string> has no Set(bool).
        var generic = expected == ResolutionKind.Ambiguous
            ? Method(PairOf(IntType), "Set", IntType)
            : Method(PairOf(IntType, StringType), "Set", BoolType);
        var (r1, r2) = (InstanceOf(generic, IntType), InstanceOf(generic, StringType));
        Assert.NotEqual(CanonicalName.NodeId(ModelNames.Of(r1)), CanonicalName.NodeId(ModelNames.Of(r2)));
        var index = FreshIndex();

        var first = index.Resolve(secondFirst ? r2 : r1);
        var second = index.Resolve(secondFirst ? r1 : r2);
        var (resolved1, resolved2) = secondFirst ? (second, first) : (first, second);

        foreach (var (reference, resolution) in new[] { (r1, resolved1), (r2, resolved2) })
        {
            var unshared = FreshIndex().Resolve(reference);
            Assert.Equal(expected, resolution.Kind);
            Assert.Equal(CanonicalName.NodeId(ModelNames.Of(reference)), resolution.NodeId);
            Assert.Equal(CanonicalName.ClassificationKey(ModelNames.Of(reference)), resolution.ClassificationKey);
            Assert.Equal(
                (unshared.Kind, unshared.NodeId, unshared.ClassificationKey, unshared.Reason),
                (resolution.Kind, resolution.NodeId, resolution.ClassificationKey, resolution.Reason));
            Assert.Equal(unshared.Candidates, resolution.Candidates);
        }
        string[] candidates = expected == ResolutionKind.Ambiguous ? [SetFirst, SetSecond] : [];
        Assert.Equal(candidates, resolved1.Candidates);
        Assert.Equal(candidates, resolved2.Candidates);
    }

    // A fresh index (empty memo) over the fixture's assemblies.
    private MemberIndex FreshIndex() => MemberIndex.Build(fixture.Assemblies.Disassemblers);

    // A generic method instance of `generic` with one method argument, as CCIProvider shapes it: its own parameters
    // are the substituted ones, and GenericMethod points back at the generic method.
    private static ModelTypes.MethodReference InstanceOf(ModelTypes.MethodReference generic, ModelTypes.IType argument)
    {
        var instance = Method(generic.ContainingType, generic.Name, argument);
        instance.GenericArguments.Add(argument);
        instance.GenericMethod = generic;
        return instance;
    }

    // The fixture's assemblies plus a synthetic caller assembly whose methods each make one call.
    private (MemberIndex Index, MethodGraph Graph) BuildWith(params (string Method, ModelTypes.IMethodReference Target)[] calls)
    {
        // The synthetic caller has no file, so it forwards nothing.
        var index = MemberIndex.Build([
            .. fixture.Assemblies.Disassemblers.Select(d => (d.Assembly, d.Forwarders)),
            (CallerAssembly(SyntheticAssembly, calls), TypeForwarders.None)]);
        Assert.All(calls, c => Assert.True(index.IsOwnMethod(CallerId(c.Method)), $"{CallerId(c.Method)} was not indexed."));
        return (index, MethodGraph.Build(index));
    }

    // Pair`2 declared by the fixture, with exactly the given Model arguments.
    private static ModelTypes.BasicType PairOf(params ModelTypes.IType[] arguments) =>
        TypeRef(ResolutionSpace, "Pair", 2, assembly: MechanismFixtureAssemblies.FixtureName, arguments: arguments);

    // Outer4.Mid.Inner<int>.Lone<int,bool> under a DEFINITION Outer4: the argument prefix cannot be recovered.
    private static ModelTypes.BasicType UnknownLone()
    {
        var outer = TypeRef(ResolutionSpace, "Outer4", 1, assembly: MechanismFixtureAssemblies.FixtureName);
        var mid = TypeRef(null, "Mid", 1, outer, MechanismFixtureAssemblies.FixtureName);
        var inner = TypeRef(null, "Inner", 2, mid, MechanismFixtureAssemblies.FixtureName, [IntType]);
        return TypeRef(null, "Lone", 3, inner, MechanismFixtureAssemblies.FixtureName, [IntType, BoolType]);
    }

    // R1 = Pair<NS.A, "Z\u0001NS.A">.Set(NS.A) binds Set(T1); R2 = Pair<"NS.A\u0001Z", NS.A>.Set(NS.A) binds Set(T2).
    private static (ModelTypes.MethodReference R1, ModelTypes.MethodReference R2) CollidingReferences()
    {
        var a = TypeRef("NS", "A");
        return (
            Method(PairOf(a, TypeRef(null, "Z\u0001NS.A")), "Set", a),
            Method(PairOf(TypeRef(null, "NS.A\u0001Z"), a), "Set", a));
    }

    // The memo key as MemberIndex.Resolve built it before S2: string.Join('\u0001', parts).
    private static string OldJoinedKey(ModelTypes.IMethodReference reference)
    {
        var nodeId = CanonicalName.NodeId(ModelNames.Of(reference));
        var arguments = ModelNames.TypeArguments(reference.ContainingType);
        IEnumerable<string> parts = [MechanismFixtureAssemblies.FixtureName, nodeId, nodeId, arguments is null ? "?" : "=", .. arguments ?? []];
        return string.Join('\u0001', parts);
    }
    #endregion

    #region Fields
    private const string ResolutionSpace = "MechanismFixture.Resolution";
    private const string Generics = "MechanismFixture.Generics";
    private const string Pair = ResolutionSpace + ".Pair`2";
    private const string SetFirst = Pair + ".Set(!0)";
    private const string SetSecond = Pair + ".Set(!1)";
    private const string Lone = ResolutionSpace + ".Outer4.Mid.Inner.Lone`3";
    private const string LoneOfT = Lone + ".M(!0)";
    private const string BoxRun = Generics + ".Box`1.Run()";
    private const string UnknownArguments = "the instantiation's type arguments could not be recovered";
    private const string SyntheticAssembly = "Silvergun.Tests.SyntheticCallers";

    private static readonly ModelTypes.BasicType IntType = TypeRef("System", "Int32");
    private static readonly ModelTypes.BasicType StringType = TypeRef("System", "String");
    private static readonly ModelTypes.BasicType BoolType = TypeRef("System", "Boolean");

    private readonly MechanismMethodGraphFixture fixture;
    #endregion
}
