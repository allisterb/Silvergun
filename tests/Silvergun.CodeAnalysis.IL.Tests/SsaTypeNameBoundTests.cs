namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// Types that double per level (docs/agent/tasks/ssa-facts-s4.md, S4.3's carry-over, fixed in S4.5). Metadata may name a
/// TypeSpec inside another TypeSpec's signature, so a linear chain of rows can describe a type whose tree, and name, double
/// per level. <see cref="SsaTypeNameDagFixture"/> writes such a DAG.
/// <list type="bullet">
/// <item><description>The lift refuses a type past <see cref="SsaBounds.MaxTypeParts"/> promptly: its method fails as
/// <see cref="SsaFailureKind.Bounds"/>, so the site reads MethodUnknown with why, never clean.</description></item>
/// <item><description>A type that lifts but whose name passes the renderer's 4,096-char budget comes back cut, its
/// rendering stopped near the budget; a shallow DAG (whose shared parts render from the memo) stays whole and exact; and one
/// name's spent budget never cuts another's.</description></item>
/// </list>
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaTypeNameBoundTests : IClassFixture<SsaTypeNameDagFixture>
{
    #region Constructors
    public SsaTypeNameBoundTests(SsaTypeNameDagFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- The lift's bound (SsaBounds.MaxTypeParts) -------------------------------------------------------------------

    /// <summary>
    /// <c>typeof(T_20)</c> (about 4M parts as a tree, a 52M-char name), end to end in a fresh session as the worker runs
    /// it: promptly (lifting it once took minutes), the site reads MethodUnknown, failure kind Bounds, the reason naming the
    /// parts bound.
    /// </summary>
    [Fact]
    public void Lift_TypeSpecDag_PastMaxTypeParts_MethodUnknownBoundsPromptly()
    {
        using var session = SsaSession.Open([fixture.Path]);
        var site = fixture.SiteOf("Deep");

        var clock = Stopwatch.StartNew();
        var facts = SsaSinkFacts.Extract(session, [site]);
        clock.Stop();

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"Extract took {clock.ElapsedMilliseconds} ms.");
        AssertRefused(Assert.Single(facts.Sites));
        Assert.Equal(new[] { new SsaFailureCount(SsaFailureKind.Bounds, 1) }, facts.Unknown);
    }

    /// <summary>
    /// The boundary: T_k is 2^(k+2) - 1 parts, so under the default 4,096 the largest that lifts is T_10 (4,095), which
    /// reads Analyzed (its 51,187-char name cut), and T_11 (8,191) is refused as Bounds.
    /// </summary>
    [Fact]
    public void Lift_TypeSpecDag_LargestUnderMaxTypePartsLifts_NextIsBounds()
    {
        var max = SsaBounds.Default.MaxTypeParts;
        Assert.True(SsaTypeNameDagFixture.Parts(SsaTypeNameDagFixture.EdgeDepth) <= max && SsaTypeNameDagFixture.Parts(SsaTypeNameDagFixture.EdgeDepth + 1) > max,
            $"T_{SsaTypeNameDagFixture.EdgeDepth} is no longer the largest DAG level within {max} parts.");

        var facts = SsaSinkFacts.Extract(fixture.Session, [fixture.SiteOf("Edge"), fixture.SiteOf("Over")]);

        var edge = Assert.Single(facts.Sites, f => f.Site.NodeId == fixture.SiteOf("Edge").NodeId);
        var over = Assert.Single(facts.Sites, f => f.Site.NodeId == fixture.SiteOf("Over").NodeId);
        Assert.True(edge.Status == SsaSiteStatus.Analyzed, $"{edge.Status}: {edge.Reason}");
        AssertCutPrefix(SsaTypeNameDagFixture.EdgeDepth, AssertTypeConstant(Assert.Single(edge.Arguments)));
        AssertRefused(over);
    }

    /// <summary>The bound is the session's: raised (through <see cref="SsaSession.Open"/>), T_11 lifts, and its name is cut.</summary>
    [Fact]
    public void Lift_TypeSpecDag_RaisedMaxTypeParts_OverLifts()
    {
        using var session = SsaSession.Open([fixture.Path], SsaBounds.Default with { MaxTypeParts = 1 << 14 });

        var fact = Assert.Single(SsaSinkFacts.Extract(session, [fixture.SiteOf("Over")]).Sites);

        Assert.True(fact.Status == SsaSiteStatus.Analyzed, $"{fact.Status}: {fact.Reason}");
        AssertCutPrefix(SsaTypeNameDagFixture.EdgeDepth + 1, AssertTypeConstant(Assert.Single(fact.Arguments)));
    }

    // ---- The name's bound (the renderer's 4,096 chars) ---------------------------------------------------------------

    /// <summary>
    /// <c>typeof(T_8)</c> (1,023 parts, so it lifts; 12,787 chars whole, past the renderer's budget): cut, with the true
    /// name's first chars, and its suffix counts the chars rendered past <see cref="SsaFactBounds.MaxTextChars"/>, which
    /// put the render near its budget, well short of the whole name.
    /// </summary>
    [Fact]
    public void Text_TypeSpecDagMid_RenderStopsNearTheBound()
    {
        Assert.True(SsaTypeNameDagFixture.Length(SsaTypeNameDagFixture.MidDepth) > MaxRendered, "The mid level's name no longer passes the bound by enough to tell.");

        var fact = Assert.Single(SsaSinkFacts.Extract(fixture.Session, [fixture.SiteOf("Mid")]).Sites);

        Assert.True(fact.Status == SsaSiteStatus.Analyzed, $"{fact.Status}: {fact.Reason}");
        var constant = AssertTypeConstant(Assert.Single(fact.Arguments));
        var dropped = AssertCutPrefix(SsaTypeNameDagFixture.MidDepth, constant);
        var rendered = SsaFactBounds.Default.MaxTextChars + dropped;
        Assert.True(rendered <= MaxRendered, $"{rendered} chars rendered, of {SsaTypeNameDagFixture.Length(SsaTypeNameDagFixture.MidDepth)}.");
    }

    /// <summary>
    /// A name that ran out of budget is not whole, so it reads Cut even when <see cref="SsaFactBounds.MaxTextChars"/> is far
    /// above its rendered length.
    /// </summary>
    [Fact]
    public void Text_TypeSpecDagMid_HighMaxTextChars_StillCut()
    {
        var facts = SsaSinkFacts.Extract(fixture.Session, [fixture.SiteOf("Mid")], new SsaFactBounds { MaxTextChars = 100_000 });

        var fact = Assert.Single(facts.Sites);
        Assert.Equal(SsaSiteStatus.Analyzed, fact.Status);
        var constant = AssertTypeConstant(Assert.Single(fact.Arguments));
        Assert.True(constant.Cut, $"A name past its budget read whole: {constant.Text.Length} chars.");
        Assert.StartsWith(SsaTypeNameDagFixture.Prefix(SsaTypeNameDagFixture.MidDepth, 256), constant.Text, StringComparison.Ordinal);
        Assert.Matches(endSuffix, constant.Text);
        Assert.True(constant.Text.Length <= MaxRendered + MaxSuffix, $"{constant.Text.Length} chars.");
    }

    /// <summary>
    /// The reflection target of the same site (Activator.CreateInstance's <c>type=0</c>) reads the same cut constant and,
    /// since a cut name is never matched, no candidates.
    /// </summary>
    [Fact]
    public void Text_TypeSpecDagMid_TargetTypeIsTheCutConstant()
    {
        var fact = Assert.Single(SsaSinkFacts.Extract(fixture.Session, [fixture.SiteOf("Mid")]).Sites);

        var target = Assert.IsType<SsaReflectionTarget>(fact.Target);
        Assert.True(target.Type.SameAs(fact.Arguments[0]), "The target's type is not the argument's constant.");
        Assert.Empty(target.Candidates);
    }

    /// <summary>Each render is fresh (a per-call renderer), so two extractions give the same cut text.</summary>
    [Fact]
    public void Text_TypeSpecDagMid_SameTextEachExtract()
    {
        var site = fixture.SiteOf("Mid");

        var first = SsaSinkFacts.Extract(fixture.Session, [site]).Sites[0].Arguments[0].Constants[0];
        var second = SsaSinkFacts.Extract(fixture.Session, [site]).Sites[0].Arguments[0].Constants[0];

        Assert.True(first.Cut);
        Assert.Equal(first, second);
    }

    /// <summary>
    /// <c>typeof(T_2)</c>: T_1 appears twice and T_0 four times, each rendered once and reused. The name is benign (187
    /// chars), so it is exact and whole.
    /// </summary>
    [Fact]
    public void Text_TypeSpecDagShallow_SharedPartsRenderedWhole()
    {
        var fact = Assert.Single(SsaSinkFacts.Extract(fixture.Session, [fixture.SiteOf("Shallow")]).Sites);

        Assert.Equal(SsaSiteStatus.Analyzed, fact.Status);
        var constant = AssertTypeConstant(Assert.Single(fact.Arguments));
        Assert.Equal((SsaTypeNameDagFixture.Name(2), false), (constant.Text, constant.Cut));
        Assert.Equal(187, constant.Text.Length);
    }

    /// <summary>
    /// <c>typeof(T_8)</c> then <c>typeof(T_2)</c> in one body: the first name spending its budget does not cut the second,
    /// which is still exact and whole.
    /// </summary>
    [Fact]
    public void Text_TypeSpecDagThenShallow_SameBody_ShallowStillWhole()
    {
        var sites = fixture.SitesOf("MidThenShallow");
        Assert.Equal(2, sites.Length);

        var facts = SsaSinkFacts.Extract(fixture.Session, sites);

        var (deep, shallow) = (facts.Sites[0], facts.Sites[1]);
        Assert.True(deep.Site.Offset < shallow.Site.Offset);
        Assert.All(facts.Sites, f => Assert.Equal(SsaSiteStatus.Analyzed, f.Status));
        Assert.True(AssertTypeConstant(Assert.Single(deep.Arguments)).Cut);
        var whole = AssertTypeConstant(Assert.Single(shallow.Arguments));
        Assert.Equal((SsaTypeNameDagFixture.Name(2), false), (whole.Text, whole.Cut));
    }

    /// <summary>
    /// <c>typeof(Pair&lt;int32[rank 5,000], string&gt;)</c>: a rank once charged in full (over the 4,096-char budget), which
    /// left the string argument <c>&lt;unknown&gt;</c> in an uncut name. The renderer charges what it renders, so the name is
    /// whole and canonical, the rank clamped as <see cref="CanonicalName.ArrayOf"/> clamps it.
    /// </summary>
    [Fact]
    public void Text_HighRankArrayArgument_WholeAndCanonical()
    {
        var fact = Assert.Single(SsaSinkFacts.Extract(fixture.Session, [fixture.SiteOf("WideRank")]).Sites);

        Assert.True(fact.Status == SsaSiteStatus.Analyzed, $"{fact.Status}: {fact.Reason}");
        var constant = AssertTypeConstant(Assert.Single(fact.Arguments));
        Assert.False(constant.Cut, $"Cut: {SsaText.Printable(constant.Text)}");
        Assert.Equal(CanonicalName.GenericInstance("Dag.Pair`2", [CanonicalName.ArrayOf("System.Int32", SsaTypeNameDagFixture.WideRank), "System.String"]), constant.Text);
    }

    // ---- Cost per reference (review round 2) -------------------------------------------------------------------------

    /// <summary>
    /// T_10 (4,095 parts, within the bound) named by a hundred <c>ldtoken</c>s in one body, then passed to the sink: the
    /// operand is mapped once, not per reference, so a fresh session's Extract is prompt and the method lifts.
    /// </summary>
    [Fact]
    public void Cost_ThousandLdtokensOfALargeType_MappedOnce_Prompt()
    {
        AssertPromptAndCut("ManyTokens");
    }

    /// <summary>
    /// T_10 named a hundred times through calls of <c>Take(T_10)</c> (a MethodDef whose signature holds it), then passed to
    /// the sink: the method operand is mapped once, so a fresh session's Extract is prompt and the method lifts.
    /// </summary>
    [Fact]
    public void Cost_ThousandCallsOfAMethodTakingALargeType_MappedOnce_Prompt()
    {
        AssertPromptAndCut("CallsTake");
    }

    /// <summary>
    /// <c>Wide&lt;T_10, T_10&gt;</c>: each argument fits <see cref="SsaBounds.MaxTypeParts"/>, two together do not. The
    /// running sum refuses it as Bounds promptly, in a fresh session.
    /// </summary>
    [Fact]
    public void Lift_WideInstanceOfLargeArguments_BoundsPromptly()
    {
        using var session = SsaSession.Open([fixture.Path]);
        var site = fixture.SiteOf("WideArity");

        var clock = Stopwatch.StartNew();
        var fact = Assert.Single(SsaSinkFacts.Extract(session, [site]).Sites);
        clock.Stop();

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"Extract took {clock.ElapsedMilliseconds} ms.");
        AssertRefused(fact);
    }

    // ---- Determinism of the operand memo -------------------------------------------------------------------------------

    /// <summary>
    /// The operand memo never makes an outcome depend on what was lifted first: each method's outcome (lifted or not, the
    /// failure's kind and reason) is the same when the whole module is lifted in module order and when it is lifted alone,
    /// each in a fresh session.
    /// </summary>
    [Theory]
    [InlineData("Deep")]
    [InlineData("Over")]
    [InlineData("Edge")]
    [InlineData("WideArity")]
    [InlineData("ManyTokens")]
    [InlineData("CallsTake")]
    [InlineData("MidThenShallow")]
    public void Memo_LiftAllOrLiftOne_SameOutcome(string method)
    {
        using var all = new SsaLifted([fixture.Path]);
        var together = all.Of("Holder", method);
        using var session = SsaSession.Open([fixture.Path]);

        var alone = Assert.Single(session.Lift(m => CanonicalName.NodeId(m) == together.NodeId));

        Assert.True(all.Outcomes.Count > 10, $"Only {all.Outcomes.Count} methods lifted together.");
        Assert.Equal((together.IsLifted, together.Failure?.Kind, together.Failure?.Reason), (alone.IsLifted, alone.Failure?.Kind, alone.Failure?.Reason));
        if (together.IsLifted)
            Assert.Equal(together.Body!.Instructions().Count(), alone.Body!.Instructions().Count());
    }

    /// <summary>
    /// One field token used as two operand kinds. <c>Ghosts.Box::F</c> lives in an assembly that is not there, so its field is
    /// a stub: <c>ldsfld</c> says it is static and maps, while <c>ldtoken</c> cannot, which fails as an UnresolvedFact. The
    /// memo keys the kind with the token, so a body that does both (<c>ldsfld</c> first) still fails, whatever was lifted
    /// before: <c>Both</c> (lifted first, by node id), then <c>Static</c> (Analyzed), then <c>Token</c> (MethodUnknown).
    /// </summary>
    [Fact]
    public void Memo_SameFieldTokenAsStaticAndToken_KeyedByKind()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("SsaFieldKinds");
        var field = raw.Metadata.AddMemberReference(raw.TypeRef(raw.AssemblyRef("GhostFields"), "Ghosts", "Box"),
            raw.Metadata.GetOrAddString("F"), raw.Metadata.GetOrAddBlob(RawAssembly.FieldSig(t => t.Int32())));
        var readAll = raw.MemberRef(raw.TypeRef(raw.Runtime, "System.IO", "File"), "ReadAllText",
            RawAssembly.MethodSig(false, r => r.Type().String(), p => p.String()));
        raw.Type("Kinds", "User", raw.Object);
        void Reads(string name, params ILOpCode[] codes) => raw.Static(name, RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var code in codes)
            {
                il.OpCode(code);
                il.Token(field);
                il.OpCode(ILOpCode.Pop);
            }
            il.LoadString(raw.Metadata.GetOrAddUserString("x"));
            il.Call(readAll);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        });
        Reads("Both", ILOpCode.Ldsfld, ILOpCode.Ldtoken);
        Reads("Static", ILOpCode.Ldsfld);
        Reads("Token", ILOpCode.Ldtoken);
        var path = raw.Save(temp.Path);
        MethodGraph graph;
        using (var model = ModelAssemblies.Load(path))
            graph = MethodGraph.Build(model.Index());
        var sites = SinkSites.Of(graph);
        using var session = SsaSession.Open([path]);

        var facts = SsaSinkFacts.Extract(session, sites);

        SsaSinkFact Of(string method) => Assert.Single(facts.Sites, f => f.Site.NodeId.StartsWith("Kinds.User." + method + "(", StringComparison.Ordinal));
        Assert.Equal(3, facts.Sites.Count);
        Assert.True(Of("Static").Status == SsaSiteStatus.Analyzed, $"{Of("Static").Status}: {Of("Static").Reason}");
        Assert.All(new[] { Of("Both"), Of("Token") }, f =>
        {
            Assert.True(f.Status == SsaSiteStatus.MethodUnknown, $"{f.Status}: {f.Reason}");
            Assert.Equal(SsaFailureKind.UnresolvedFact, f.FailureKind);
        });
    }

    /// <summary>
    /// The operand memo is per body (review round 3, W-1): one TypeSpec token, <c>Box&lt;!!0&gt;</c>, is
    /// <c>ldtoken</c>-ed by a generic <c>B.G&lt;T&gt;()</c>, where <c>!!0</c> is its own parameter, and by a non-generic
    /// <c>A.M()</c>, where it is out of range. Each method's outcome is the same lifted with the whole module (module order:
    /// <c>B.G</c> first), with both selected (node-id order: <c>A.M</c> first), and alone, each in a fresh session; and
    /// <c>G</c> lifts, its site Analyzed. No graph is built: the site is written by hand.
    /// </summary>
    [Fact]
    public void Memo_TokenOverMethodParameter_PerBody_SameOutcomeInAnyOrder()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("SsaPerBody");
        var (getTypeFromHandle, createInstance) = ReflectionRefs(raw);
        var box = raw.Type("PerBody", "Box`1", raw.Object);
        raw.GenericParameter(box, "T", 0);
        // A method of Box first, so G's MethodDef row (and so its GenericParam owner) sorts after Box's.
        raw.Static("Pad", RawAssembly.MethodSig(false, r => r.Void()), il => il.OpCode(ILOpCode.Ret));
        var spec = raw.TypeSpec(s => s.GenericInstantiation(box, 1, isValueType: false).AddArgument().GenericMethodTypeParameter(0));
        void Body(InstructionEncoder il)
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(spec);
            il.Call(getTypeFromHandle);
            il.Call(createInstance);
            il.OpCode(ILOpCode.Pop);
            il.OpCode(ILOpCode.Ret);
        }
        raw.Type("PerBody", "B", raw.Object);
        var genericSig = new BlobBuilder();
        new BlobEncoder(genericSig).MethodSignature(genericParameterCount: 1).Parameters(0, r => r.Void(), _ => { });
        var g = raw.Method("G", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig, genericSig, Body);
        raw.GenericParameter(g, "T", 0);
        raw.Type("PerBody", "A", raw.Object);
        raw.Static("M", RawAssembly.MethodSig(false, r => r.Void()), Body);
        var path = raw.Save(temp.Path);

        static (bool, SsaFailureKind?, string?) Outcome(SsaMethodOutcome o) => (o.IsLifted, o.Failure?.Kind, o.Failure?.Reason);
        using var all = new SsaLifted([path]);
        var (gAll, mAll) = (all.Of("B", "G"), all.Of("A", "M"));
        Assert.True(all.Outcomes.ToList().IndexOf(gAll) < all.Outcomes.ToList().IndexOf(mAll), "Module order no longer lifts B.G first.");
        using var both = SsaSession.Open([path]);
        var selected = both.Lift(m => CanonicalName.NodeId(m) == gAll.NodeId || CanonicalName.NodeId(m) == mAll.NodeId).ToArray();
        Assert.Equal(new[] { mAll.NodeId, gAll.NodeId }, selected.Select(o => o.NodeId));

        foreach (var together in new[] { gAll, mAll })
        {
            using var session = SsaSession.Open([path]);
            var alone = Assert.Single(session.Lift(m => CanonicalName.NodeId(m) == together.NodeId));
            var bySelection = Assert.Single(selected, o => o.NodeId == together.NodeId);
            Assert.Equal(Outcome(alone), Outcome(together));
            Assert.Equal(Outcome(alone), Outcome(bySelection));
        }
        SsaLifted.AssertLifted(gAll);
        var site = new SinkSite(gAll.NodeId, 10, MethodEdgeKind.Call, "System.Activator.CreateInstance(System.Type)", "System.Activator.CreateInstance", Capability.DynamicCodeLoading);
        var fact = Assert.Single(SsaSinkFacts.Extract(all.Session, [site]).Sites);
        Assert.True(fact.Status == SsaSiteStatus.Analyzed, $"{fact.Status}: {fact.Reason}");
    }

    /// <summary>
    /// A large instance named in many signatures (review round 3, W-2): <see cref="ManyTakers"/> methods each take T_10
    /// (4,095 parts, within the bound), and one body calls them all. Each distinct method operand maps its signature, and
    /// the instance is interned after the first, so lifting that body alone, in a fresh session, is prompt. No graph is
    /// built.
    /// </summary>
    [Fact]
    public void Cost_LargeInstanceInManySignatures_LiftPrompt()
    {
        using var temp = new SsaTempDirectory();
        var raw = new RawAssembly("SsaManySignatures");
        var pair = raw.Type("Dag", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);
        var specs = SsaTypeNameDagFixture.Chain(raw, pair, SsaTypeNameDagFixture.EdgeDepth - 1);
        raw.Type("Dag", "Many", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var takers = Enumerable.Range(0, ManyTakers).Select(i => raw.Static("Take" + i, RawAssembly.MethodSig(false, r => r.Void(), p =>
        {
            var arguments = p.GenericInstantiation(pair, 2, isValueType: false);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), specs[^1]);
            SsaTypeNameDagFixture.ClassOf(arguments.AddArgument(), specs[^1]);
        }), il => il.OpCode(ILOpCode.Ret))).ToArray();
        raw.Static("CallsAll", RawAssembly.MethodSig(false, r => r.Void()), il =>
        {
            foreach (var taker in takers)
            {
                il.OpCode(ILOpCode.Ldnull);
                il.Call(taker);
            }
            il.OpCode(ILOpCode.Ret);
        });
        var path = raw.Save(temp.Path);
        using var session = SsaSession.Open([path]);

        var clock = Stopwatch.StartNew();
        var outcome = Assert.Single(session.Lift(m => m.MethodName == "CallsAll"));
        clock.Stop();

        SsaLifted.AssertLifted(outcome);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"The lift took {clock.ElapsedMilliseconds} ms.");
        Assert.Equal(ManyTakers, outcome.Body!.Instructions().Count(i => i is Cilica.IR.CallInst));
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    // MemberRefs to Type.GetTypeFromHandle and Activator.CreateInstance(Type).
    private static (MemberReferenceHandle GetTypeFromHandle, MemberReferenceHandle CreateInstance) ReflectionRefs(RawAssembly raw)
    {
        var type = raw.TypeRef(raw.Runtime, "System", "Type");
        var handle = raw.TypeRef(raw.Runtime, "System", "RuntimeTypeHandle");
        var activator = raw.TypeRef(raw.Runtime, "System", "Activator");
        return (raw.MemberRef(type, "GetTypeFromHandle", RawAssembly.MethodSig(false, r => r.Type().Type(type, isValueType: false), p => p.Type(handle, isValueType: true))),
            raw.MemberRef(activator, "CreateInstance", RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Type(type, isValueType: false))));
    }

    private static SsaConstant AssertTypeConstant(SsaValue value)
    {
        Assert.Equal(SsaValueKind.Constant, value.Kind);
        var constant = Assert.Single(value.Constants);
        Assert.Equal(SsaConstantKind.Type, constant.Kind);
        return constant;
    }

    // In a fresh session (the lift timed too): Extract under 5 s, the method's one site Analyzed with T_10's cut name.
    private void AssertPromptAndCut(string method)
    {
        using var session = SsaSession.Open([fixture.Path]);
        var site = fixture.SiteOf(method);

        var clock = Stopwatch.StartNew();
        var fact = Assert.Single(SsaSinkFacts.Extract(session, [site]).Sites);
        clock.Stop();

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"Extract took {clock.ElapsedMilliseconds} ms.");
        Assert.True(fact.Status == SsaSiteStatus.Analyzed, $"{fact.Status}: {fact.Reason}");
        AssertCutPrefix(SsaTypeNameDagFixture.EdgeDepth, AssertTypeConstant(Assert.Single(fact.Arguments)));
    }

    // A site whose method the lift refused for its type's size: MethodUnknown, Bounds, the reason naming the bound.
    private static void AssertRefused(SsaSinkFact fact)
    {
        Assert.True(fact.Status == SsaSiteStatus.MethodUnknown, $"{fact.Status}: {fact.Reason}");
        Assert.Equal(SsaFailureKind.Bounds, fact.FailureKind);
        Assert.Contains($"expands to more than {SsaBounds.Default.MaxTypeParts} parts", fact.Reason, StringComparison.Ordinal);
        Assert.Empty(fact.Arguments);
        Assert.Null(fact.Receiver);
    }

    // Asserts a Cut constant: the first MaxTextChars of T_k's true name, then a5's suffix; returns the chars it says were dropped.
    private static int AssertCutPrefix(int k, SsaConstant constant)
    {
        var max = SsaFactBounds.Default.MaxTextChars;
        Assert.True(constant.Cut, "A name of thousands of chars must read Cut.");
        Assert.True(constant.Text.Length <= max + MaxSuffix, $"{constant.Text.Length} chars.");
        Assert.Equal(SsaTypeNameDagFixture.Prefix(k, max), constant.Text[..max]);
        var match = suffix.Match(constant.Text[max..]);
        Assert.True(match.Success, SsaText.Printable(constant.Text[max..]));
        return int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
    }
    #endregion

    #region Fields
    // "...[+N chars, sha256:xxxxxxxx]" for any N a name can have, with room to spare.
    private const int MaxSuffix = 48;

    // Chars a bounded render may reach: the renderer's own budget (4,096 chars) plus the brackets and commas its containers
    // add, with room to spare; an unbounded T_8 is 12,787.
    private const int MaxRendered = 8_192;

    // Methods taking T_10 in Cost_LargeInstanceInManySignatures_LiftPrompt.
    private const int ManyTakers = 200;

    private static readonly Regex suffix = new("^" + (char)0x2026 + "\\[\\+([1-9][0-9]*) chars, sha256:[0-9a-f]{8}\\]$", RegexOptions.CultureInvariant);

    private static readonly Regex endSuffix = new((char)0x2026 + "\\[\\+[1-9][0-9]* chars, sha256:[0-9a-f]{8}\\]$", RegexOptions.CultureInvariant);

    private readonly SsaTypeNameDagFixture fixture;
    #endregion
}

/// <summary>
/// <c>SsaTypeNameDag.dll</c>, written row by row (<see cref="RawAssembly"/>) and read as metadata only:
/// <list type="bullet">
/// <item><description><c>Dag.Pair`2&lt;A,B&gt;</c>, and TypeSpec rows T_0 = <c>Pair&lt;int32,int32&gt;</c> and T_k =
/// <c>Pair&lt;T_(k-1),T_(k-1)&gt;</c> up to <see cref="Depth"/>, each argument the TypeSpec handle of the row before
/// (CLASS and the TypeDefOrRefOrSpec coded index), so the metadata is linear in k and the tree and name
/// exponential;</description></item>
/// <item><description><c>Dag.Holder</c>, each method <c>Activator.CreateInstance(typeof(T_k))</c>: <c>Deep</c> (T_20),
/// <c>Over</c> (T_11) and <c>Edge</c> (T_10) either side of <see cref="SsaBounds.MaxTypeParts"/>, <c>Mid</c> (T_8),
/// <c>Shallow</c> (T_2), <c>MidThenShallow</c> (T_8, then T_2), <c>WideRank</c>
/// (<c>Pair&lt;int32[rank 5,000], string&gt;</c>) and <c>WideArity</c> (<c>Dag.Wide`2</c> of two T_10s); and
/// <c>ManyTokens</c> (a hundred <c>ldtoken T_10</c>) and <c>CallsTake</c> (a hundred calls of <c>Take(T_10)</c>), each
/// then passing T_10 to the sink.</description></item>
/// </list>
/// Built once as a <see cref="MethodGraph"/> (the sites' oracle) and opened once as an <see cref="SsaSession"/>. Depth is
/// 20, and no more.
/// </summary>
public sealed class SsaTypeNameDagFixture : IDisposable
{
    #region Constructors
    public SsaTypeNameDagFixture()
    {
        Path = Write(temp.Path);
        using (var model = ModelAssemblies.Load(Path))
            Graph = MethodGraph.Build(model.Index());
        Sites = SinkSites.Of(Graph);
        Session = SsaSession.Open([Path]);
        // Warm the session (CoreLib's provisioning) on a benign site.
        _ = SsaSinkFacts.Extract(Session, [SiteOf("Shallow")]);
    }
    #endregion

    #region Properties
    public string Path { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<SinkSite> Sites { get; }

    public SsaSession Session { get; }
    #endregion

    #region Methods
    /// <summary>The one site of <c>Dag.Holder.<paramref name="method"/></c>.</summary>
    public SinkSite SiteOf(string method) => Assert.Single(SitesOf(method));

    /// <summary>The sites of <c>Dag.Holder.<paramref name="method"/></c>, by offset.</summary>
    public SinkSite[] SitesOf(string method)
    {
        var node = Assert.Single(Graph.Nodes, n => n.Kind != MethodNodeKind.External && n.ClassificationKey == "Dag.Holder." + method);
        return [.. Sites.Where(s => s.NodeId == node.NodeId).OrderBy(s => s.Offset)];
    }

    /// <summary>T_<paramref name="k"/>'s canonical name, whole (for small k only).</summary>
    public static string Name(int k) => k == 0 ? Pair + "<" + Int + "," + Int + ">" : Pair + "<" + Name(k - 1) + "," + Name(k - 1) + ">";

    /// <summary>The length of T_<paramref name="k"/>'s canonical name: 50 * 2^k - 13.</summary>
    public static long Length(int k) => 50L * (1L << k) - 13;

    /// <summary>The parts T_<paramref name="k"/> expands to as a tree (each Pair and each int32): 2^(k+2) - 1.</summary>
    public static long Parts(int k) => (1L << (k + 2)) - 1;

    /// <summary>The first <paramref name="chars"/> of T_<paramref name="k"/>'s canonical name, without rendering the rest.</summary>
    public static string Prefix(int k, int chars)
    {
        var text = new StringBuilder();
        void Append(int level)
        {
            if (text.Length >= chars)
                return;
            text.Append(Pair).Append('<');
            if (level == 0)
                text.Append(Int).Append(',').Append(Int);
            else
            {
                Append(level - 1);
                if (text.Length >= chars)
                    return;
                text.Append(',');
                Append(level - 1);
            }
            if (text.Length < chars)
                text.Append('>');
        }
        Append(k);
        return text.ToString(0, Math.Min(chars, text.Length));
    }

    public void Dispose()
    {
        Session.Dispose();
        temp.Dispose();
    }

    /// <summary>TypeSpec rows T_0 = <c>Pair&lt;int32,int32&gt;</c> .. T_<paramref name="depth"/> over <paramref name="pair"/>.</summary>
    internal static List<TypeSpecificationHandle> Chain(RawAssembly raw, TypeDefinitionHandle pair, int depth)
    {
        var specs = new List<TypeSpecificationHandle>
        {
            raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                arguments.AddArgument().Int32();
                arguments.AddArgument().Int32();
            }),
        };
        for (var k = 1; k <= depth; k++)
        {
            var previous = specs[^1];
            specs.Add(raw.TypeSpec(s =>
            {
                var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
                ClassOf(arguments.AddArgument(), previous);
                ClassOf(arguments.AddArgument(), previous);
            }));
        }
        return specs;
    }

    /// <summary>
    /// CLASS and <paramref name="spec"/>'s TypeDefOrRefOrSpec coded index, written by hand: SignatureTypeEncoder.Type takes
    /// only a TypeDef or TypeRef.
    /// </summary>
    internal static void ClassOf(SignatureTypeEncoder encoder, TypeSpecificationHandle spec)
    {
        encoder.Builder.WriteByte((byte)SignatureTypeKind.Class);
        encoder.Builder.WriteCompressedInteger(CodedIndex.TypeDefOrRefOrSpec(spec));
    }

    private static string Write(string directory)
    {
        var raw = new RawAssembly("SsaTypeNameDag");
        var type = raw.TypeRef(raw.Runtime, "System", "Type");
        var handle = raw.TypeRef(raw.Runtime, "System", "RuntimeTypeHandle");
        var activator = raw.TypeRef(raw.Runtime, "System", "Activator");
        var getTypeFromHandle = raw.MemberRef(type, "GetTypeFromHandle",
            RawAssembly.MethodSig(false, r => r.Type().Type(type, isValueType: false), p => p.Type(handle, isValueType: true)));
        var createInstance = raw.MemberRef(activator, "CreateInstance",
            RawAssembly.MethodSig(false, r => r.Type().Object(), p => p.Type(type, isValueType: false)));

        var pair = raw.Type("Dag", "Pair`2", raw.Object);
        raw.GenericParameter(pair, "A", 0);
        raw.GenericParameter(pair, "B", 1);
        var wideType = raw.Type("Dag", "Wide`" + WideArity, raw.Object);
        for (var i = 0; i < WideArity; i++)
            raw.GenericParameter(wideType, "T" + i, i);

        var specs = Chain(raw, pair, Depth);

        // Pair<int32[,,...] of rank WideRank, string>.
        var wide = raw.TypeSpec(s =>
        {
            var arguments = s.GenericInstantiation(pair, 2, isValueType: false);
            arguments.AddArgument().Array(e => e.Int32(), shape => shape.Shape(WideRank, [], []));
            arguments.AddArgument().String();
        });

        // Wide<T_10, ..., T_10>: each argument within MaxTypeParts, two of them past it.
        var wideArity = raw.TypeSpec(s =>
        {
            var arguments = s.GenericInstantiation(wideType, WideArity, isValueType: false);
            for (var i = 0; i < WideArity; i++)
                ClassOf(arguments.AddArgument(), specs[EdgeDepth]);
        });

        // Activator.CreateInstance(typeof(T)), result dropped.
        void CreateInstanceOf(InstructionEncoder il, EntityHandle spec)
        {
            il.OpCode(ILOpCode.Ldtoken);
            il.Token(spec);
            il.Call(getTypeFromHandle);
            il.Call(createInstance);
            il.OpCode(ILOpCode.Pop);
        }
        var none = RawAssembly.MethodSig(false, r => r.Void());
        void Holds(string name, params EntityHandle[] types) => raw.Static(name, none, il =>
        {
            foreach (var t in types)
                CreateInstanceOf(il, t);
            il.OpCode(ILOpCode.Ret);
        });
        raw.Type("Dag", "Holder", raw.Object, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        // Take(T_10), its parameter written inline as Pair<T_9, T_9>.
        var take = raw.Static("Take", RawAssembly.MethodSig(false, r => r.Void(), p =>
        {
            var arguments = p.GenericInstantiation(pair, 2, isValueType: false);
            ClassOf(arguments.AddArgument(), specs[EdgeDepth - 1]);
            ClassOf(arguments.AddArgument(), specs[EdgeDepth - 1]);
        }), il => il.OpCode(ILOpCode.Ret));
        // typeof(T_10) Repeats times (each a separate ldtoken), then a sink of it.
        raw.Static("ManyTokens", none, il =>
        {
            for (var i = 0; i < Repeats; i++)
            {
                il.OpCode(ILOpCode.Ldtoken);
                il.Token(specs[EdgeDepth]);
                il.Call(getTypeFromHandle);
                il.OpCode(ILOpCode.Pop);
            }
            CreateInstanceOf(il, specs[EdgeDepth]);
            il.OpCode(ILOpCode.Ret);
        });
        // Take(null) Repeats times, then a sink of typeof(T_10).
        raw.Static("CallsTake", none, il =>
        {
            for (var i = 0; i < Repeats; i++)
            {
                il.OpCode(ILOpCode.Ldnull);
                il.Call(take);
            }
            CreateInstanceOf(il, specs[EdgeDepth]);
            il.OpCode(ILOpCode.Ret);
        });
        Holds("WideArity", wideArity);
        Holds("Deep", specs[Depth]);
        Holds("Over", specs[EdgeDepth + 1]);
        Holds("Edge", specs[EdgeDepth]);
        Holds("Mid", specs[MidDepth]);
        Holds("Shallow", specs[2]);
        Holds("MidThenShallow", specs[MidDepth], specs[2]);
        Holds("WideRank", wide);
        return raw.Save(directory);
    }
    #endregion

    #region Fields
    public const int Depth = 20;

    /// <summary>The largest level within the default <see cref="SsaBounds.MaxTypeParts"/> (4,095 of 4,096 parts).</summary>
    public const int EdgeDepth = 10;

    /// <summary>A level that lifts (1,023 parts) and whose name (12,787 chars) passes the renderer's 4,096-char budget.</summary>
    public const int MidDepth = 8;

    /// <summary>
    /// An MD array's rank past the renderer's 4,096-char budget (which a rank once charged in full), yet cheap for Cilica,
    /// whose array type and importer loop by rank.
    /// </summary>
    public const int WideRank = 5_000;

    /// <summary>Type parameters of <c>Dag.Wide</c>.</summary>
    public const int WideArity = 2;

    /// <summary>Times <c>ManyTokens</c> and <c>CallsTake</c> name T_10.</summary>
    public const int Repeats = 100;

    private const string Pair = "Dag.Pair`2";
    private const string Int = "System.Int32";

    private readonly SsaTempDirectory temp = new();
    #endregion
}
