namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Runtime.CompilerServices;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// <see cref="SsaSession.Classify"/>: an exception's own kind (an unresolved fact, an adapter failure with its kind, or a
/// CCI reader assertion) found anywhere in the inner-exception chain wins over the stage the exception surfaced in; only
/// an exception with none of them is classified by its stage.
/// </summary>
public sealed class SsaClassifyTests
{
    #region Methods
    [Theory]
    [InlineData(SsaFailureKind.Adapter)]
    [InlineData(SsaFailureKind.Import)]
    [InlineData(SsaFailureKind.Verify)]
    [InlineData(SsaFailureKind.Ssa)]
    [InlineData(SsaFailureKind.VerifyAfterSsa)]
    public void Classify_AnUntypedException_IsItsStage(SsaFailureKind stage) =>
        Assert.Equal(stage, SsaSession.Classify(new InvalidOperationException("boom"), stage));

    [Theory]
    [InlineData(SsaFailureKind.Import)]
    [InlineData(SsaFailureKind.Verify)]
    [InlineData(SsaFailureKind.Ssa)]
    public void Classify_AnUnresolvedFact_WinsOverTheStage(SsaFailureKind stage) =>
        Assert.Equal(SsaFailureKind.UnresolvedFact, SsaSession.Classify(Fact(), stage));

    /// <summary>A stub's unknown base thrown from inside the importer arrives wrapped: the fact still wins.</summary>
    [Fact]
    public void Classify_AnUnresolvedFact_DeepInTheInnerChain_WinsOverTheStage()
    {
        var wrapped = new InvalidOperationException("outer", new AggregateException("middle", new TypeInitializationException("T", Fact())));

        Assert.Equal(SsaFailureKind.UnresolvedFact, SsaSession.Classify(wrapped, SsaFailureKind.Import));
    }

    [Theory]
    [InlineData(SsaFailureKind.Adapter)]
    [InlineData(SsaFailureKind.Bounds)]
    [InlineData(SsaFailureKind.Unreadable)]
    [InlineData(SsaFailureKind.ReaderAssertion)]
    public void Classify_AnAdapterException_IsItsOwnKind_WrappedOrNot(SsaFailureKind kind)
    {
        var adapter = new SsaAdapterException("bad input", kind: kind);

        Assert.Equal(kind, SsaSession.Classify(adapter, SsaFailureKind.Verify));
        Assert.Equal(kind, SsaSession.Classify(new InvalidOperationException("outer", adapter), SsaFailureKind.Ssa));
    }

    [Fact]
    public void Classify_ACciAssertionException_IsReaderAssertion_WrappedOrNot()
    {
        var assertion = new CciAssertionException((CciAssertionRecord)RuntimeHelpers.GetUninitializedObject(typeof(CciAssertionRecord)));

        Assert.Equal(SsaFailureKind.ReaderAssertion, SsaSession.Classify(assertion, SsaFailureKind.Import));
        Assert.Equal(SsaFailureKind.ReaderAssertion, SsaSession.Classify(new InvalidOperationException("outer", assertion), SsaFailureKind.Verify));
    }

    /// <summary>The stack running low is a bound met, wherever it surfaced.</summary>
    [Theory]
    [InlineData(SsaFailureKind.Import)]
    [InlineData(SsaFailureKind.Ssa)]
    public void Classify_InsufficientExecutionStack_IsBounds(SsaFailureKind stage) =>
        Assert.Equal(SsaFailureKind.Bounds, SsaSession.Classify(new InsufficientExecutionStackException(), stage));

    /// <summary>A Debug-build Cilica assertion carries no kind of its own: it is the stage it failed in.</summary>
    [Fact]
    public void Classify_ACilicaAssertion_IsItsStage() =>
        Assert.Equal(SsaFailureKind.Ssa, SsaSession.Classify(new CilicaAssertionException("Assertion failed"), SsaFailureKind.Ssa));

    private static UnresolvedFactException Fact() => new(UnresolvedFact.BaseType, "Missing.Thing");
    #endregion
}
