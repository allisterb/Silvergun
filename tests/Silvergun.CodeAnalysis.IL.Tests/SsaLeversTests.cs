namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

using static Silvergun.CodeAnalysis.IL.Tests.SsaLeversFixture;

/// <summary>
/// recall-levers-1 L1 on real IL (docs/agent/tasks/recall-levers-1.md §2-3): <c>string.Concat</c> folding in the value walker,
/// and the P/Invoke entry name (<see cref="SsaSinkFact.Import"/>) a site carries. The classifier's own table is
/// <see cref="SsaValueSignalsTests"/>.
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaLeversTests : IClassFixture<SsaLeversFixture>
{
    #region Constructors
    public SsaLeversTests(SsaLeversFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- Folding -------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Concat2", "abcd")]
    [InlineData("Concat3", "abc")]
    [InlineData("Concat4", "abcd")]
    [InlineData("Nested", "abcd")]
    public void Fold_ConcatOfConstants_IsAConstant(string method, string expected) =>
        AssertValues([Str(expected)], fixture.Fact(method).Arguments);

    // Eight nested Concats fold; the ninth is past MaxFoldDepth and the whole value stays a call's result.
    [Fact]
    public void Fold_ChainAtMaxDepth_IsAConstant() =>
        AssertValues([Str("a" + new string('b', 8))], fixture.Fact("Chain8").Arguments);

    [Fact]
    public void Fold_ChainPastMaxDepth_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], fixture.Fact("Chain9").Arguments);

    [Theory]
    [InlineData("NullArgument")]
    [InlineData("PhiArgument")]
    [InlineData("ParameterArgument")]
    [InlineData("ConcatObjects")]
    [InlineData("ConcatArray")]
    public void Fold_NotAllStringConstants_StaysDynamicCallResult(string method) =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], fixture.Fact(method).Arguments);

    // MaxTextChars (256) x 4 raw chars fold, one more does not.
    [Fact]
    public void Fold_AtTheRawLengthBound_IsAConstantCutToMaxTextChars()
    {
        var whole = new string('x', 512) + new string('y', 512);

        var value = Assert.Single(fixture.Fact("AtLengthBound").Arguments);

        Assert.Equal(SsaValueKind.Constant, value.Kind);
        var constant = Assert.Single(value.Constants);
        Assert.True(constant.Cut);
        Assert.Equal(new string('x', 256) + Suffix(768, whole), constant.Text);
    }

    // Review W2: a site's value never depends on which other site of the body was read first. c3 is 3 deep and c9 is 9.
    [Theory]
    [InlineData("OrderLowFirst", true)]
    [InlineData("OrderHighFirst", false)]
    public void Fold_TwoSitesOnOneChain_EachKeepsItsOwnValue_InEitherSiteOrder(string method, bool lowFirst)
    {
        var facts = fixture.FactsOf(method);

        Assert.Equal(2, facts.Length);
        SsaValue low = Str("a" + new string('b', 3)), high = Dynamic(SsaDynamicOrigin.CallResult);
        AssertValues([lowFirst ? low : high], facts[0].Arguments);
        AssertValues([lowFirst ? high : low], facts[1].Arguments);
    }

    // The same, with the sites handed to Extract in the opposite order (so the walk reads them the other way round).
    [Fact]
    public void Fold_TwoSitesOnOneChain_AreTheSame_WhateverOrderTheSitesAreRead()
    {
        var reversed = fixture.ExtractReversed();

        Assert.All(new[] { "OrderLowFirst", "OrderHighFirst", "Diamond", "Diamond7", "Diamond8", "Chain8", "Chain9" }, method =>
        {
            var again = reversed.Sites.Where(f => f.Site.NodeId == fixture.NodeIdOf(method)).OrderBy(f => f.Site.Offset).ToArray();
            Assert.Equal(Json(fixture.FactsOf(method)), Json(again));
        });
    }

    // One Concat as both arguments of another: correct, and the walk stays bounded (the 8th doubling is past the height bound).
    [Fact]
    public void Fold_Diamond_IsTheDoubledText() =>
        AssertValues([Str("abab")], fixture.Fact("Diamond").Arguments);

    [Fact]
    public void Fold_DeepDiamondAtMaxHeight_IsAConstant() =>
        AssertValues([Str(string.Concat(Enumerable.Repeat("ab", 128)))], fixture.Fact("Diamond7").Arguments);

    [Fact]
    public void Fold_DeepDiamondPastMaxHeight_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], fixture.Fact("Diamond8").Arguments);

    [Fact]
    public void Fold_PastTheRawLengthBound_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], fixture.Fact("OverLengthBound").Arguments);

    // The bound is on the folded text of the whole tree, not each Concat.
    [Fact]
    public void Fold_NestedPastTheRawLengthBound_IsDynamicCallResult() =>
        AssertValues([Dynamic(SsaDynamicOrigin.CallResult)], fixture.Fact("OverLengthNested").Arguments);

    // The bound moves with MaxTextChars: at 100 the 1024-char Concat is over its 400.
    [Fact]
    public void Fold_UnderASmallerMaxTextChars_BoundMovesWithIt()
    {
        var facts = fixture.Extract(new SsaFactBounds { MaxTextChars = 100 });

        var value = Assert.Single(Assert.Single(facts.Sites, f => f.Site.NodeId == fixture.NodeIdOf("AtLengthBound")).Arguments);
        Assert.Equal(SsaValueKind.Dynamic, value.Kind);
        var small = Assert.Single(Assert.Single(facts.Sites, f => f.Site.NodeId == fixture.NodeIdOf("Concat4")).Arguments);
        Assert.Equal("abcd", Assert.Single(small.Constants).Text);
    }

    [Fact]
    public void Fold_InsideAPhi_JoinsTheConstants() =>
        AssertValues([OneOf(Str("ab"), Str("c"))], fixture.Fact("PhiOfConcat").Arguments);

    // The folded text is made as any constant is: escaped.
    [Fact]
    public void Fold_FoldedText_IsEscapedLikeAnyConstant() =>
        AssertValues([Str("C:" + Bs + Bs + "x.txt")], fixture.Fact("Backslash").Arguments);

    // Folding is what lets a value built from pieces reach the classifier.
    [Fact]
    public void Fold_BuiltShellName_ReachesTheClassifier()
    {
        var fact = fixture.Fact("StartsShell");

        AssertValues([Str("cmd.exe")], fact.Arguments);
        Assert.Equal([SsaSignal.ShellInterpreter], SsaValueSignals.Of(fact));
    }

    [Fact]
    public void Fold_IsDeterministic()
    {
        var again = fixture.Extract(new SsaFactBounds());

        Assert.Equal(Json(fixture.Facts.Sites), Json(again.Sites));
    }

    // ---- Import --------------------------------------------------------------------------------------------------------

    [Fact]
    public void Import_PInvokeCallee_IsItsEntryName()
    {
        var fact = fixture.Fact("CallsPlain");

        Assert.Equal((SsaSiteStatus.Analyzed, "VirtualAlloc"), (fact.Status, fact.Import));
        AssertValues([Int("0"), Int("4096"), Int("12288"), Int("64")], fact.Arguments);
    }

    // [DllImport(EntryPoint = "VirtualAlloc")] on a method named otherwise.
    [Fact]
    public void Import_RenamedEntryPoint_IsTheEntryNotTheMethodName()
    {
        var fact = fixture.Fact("CallsRenamed");

        Assert.Equal("VirtualAlloc", fact.Import);
        Assert.Contains(".Reserve(", fact.Site.Callee, StringComparison.Ordinal);
    }

    [Fact]
    public void Import_AnyOtherPInvoke_IsItsEntryName() =>
        Assert.Equal("GetTickCount", fixture.Fact("CallsOther").Import);

    [Fact]
    public void Import_ManagedSink_IsNull() =>
        Assert.Null(fixture.Fact("ReadsFile").Import);

    [Fact]
    public void Import_OnlyOnAnalyzedPInvokeSites()
    {
        var withImport = fixture.Facts.Sites.Where(f => f.Import is not null).Select(f => f.Site.NodeId).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(new[] { "CallsHostile", "CallsOther", "CallsOverlong", "CallsPlain", "CallsRenamed" }.Select(fixture.NodeIdOf).Order(StringComparer.Ordinal), withImport);
        Assert.All(fixture.Facts.Sites.Where(f => f.Import is not null), f => Assert.Equal(SsaSiteStatus.Analyzed, f.Status));
    }

    // An entry name is attacker text: the same escape as every other string of the facts.
    [Fact]
    public void Import_HostileEntryName_IsEscaped()
    {
        var import = fixture.Fact("CallsHostile").Import!;

        Assert.Equal(UntrustedText.Escape(HostileEntry), import);
        Assert.DoesNotContain((char)0x202E, import);
        Assert.DoesNotContain('\n', import);
    }

    [Fact]
    public void Import_OverlongEntryName_IsBounded()
    {
        var import = fixture.Fact("CallsOverlong").Import!;

        Assert.Equal(Reachability.BoundName(UntrustedText.Escape(OverlongEntry)), import);
        Assert.True(import.Length < OverlongEntry.Length);
        Assert.EndsWith("]", import, StringComparison.Ordinal);
    }

    // The renamed entry point is what reaches the classifier: the method name says nothing.
    [Theory]
    [InlineData("CallsPlain")]
    [InlineData("CallsRenamed")]
    public void Import_ExecutableProtection_ReachesTheClassifier(string method) =>
        Assert.Equal([SsaSignal.ExecutableMemory], SsaValueSignals.Of(fixture.Fact(method)));

    [Fact]
    public void Import_OtherEntry_GivesNoSignal() =>
        Assert.Empty(SsaValueSignals.Of(fixture.Fact("CallsOther")));

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static void AssertValues(SsaValue[] expected, IReadOnlyList<SsaValue> actual) =>
        Assert.True(expected.Length == actual.Count && expected.Zip(actual).All(p => p.First.SameAs(p.Second)),
            $"Expected {Json(expected)}\nActual   {Json(actual)}");

    private static SsaValue Str(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text));

    private static SsaValue Int(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Int, text));

    private static SsaValue OneOf(params SsaValue[] values) => new(SsaValueKind.OneOf, [.. values.Select(v => v.Constants[0])], null, null);

    private static SsaValue Dynamic(SsaDynamicOrigin origin) => SsaValue.OfDynamic(origin);

    private static string Suffix(int cut, string whole) => $"{(char)0x2026}[+{cut} chars, sha256:{UntrustedTextTests.Sha8(whole)}]";

    private static string Json(object? value) => SsaText.Printable(JsonSerializer.Serialize(value));
    #endregion

    #region Fields
    private readonly SsaLeversFixture fixture;
    #endregion
}
