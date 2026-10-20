namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The contract of <see cref="YaraScanIncompleteException.PartialFindings"/> (ADR 0032 decision 1): the one channel
/// that carries "partial result plus degraded status" out of a scan. Two properties matter to every consumer and
/// are pinned here directly, independent of any backend: it is <b>never null</b> (so a catch block can enumerate it
/// without a guard, and the two constructors that predate it stay source-compatible), and it is a <b>snapshot</b>
/// (a thrower that keeps appending to its own list after throwing cannot change what the catcher reports).
/// </summary>
public sealed class YaraScanIncompleteExceptionTests
{
    #region Methods
    // The two constructors every existing throw site uses: no hits in hand, so an empty — not null — list.
    [Fact]
    public void PartialFindings_FromTheMessageOnlyConstructor_IsEmptyNotNull()
    {
        var ex = new YaraScanIncompleteException("nothing was scanned");

        Assert.NotNull(ex.PartialFindings);
        Assert.Empty(ex.PartialFindings);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public void PartialFindings_FromTheMessageAndInnerConstructor_IsEmptyNotNull()
    {
        var inner = new TimeoutException("bound reached");
        var ex = new YaraScanIncompleteException("timed out", inner);

        Assert.NotNull(ex.PartialFindings);
        Assert.Empty(ex.PartialFindings);
        Assert.Same(inner, ex.InnerException);
    }

    // ADR 0032 decision 8. The literal `("m", null)` form must COMPILE and bind unambiguously to the pre-existing
    // (message, innerException) constructor: a (message, partialFindings) overload made it CS0121, which broke the
    // source-compatibility promise every pre-0032 caller relied on. This test is the compile-time pin — reintroducing
    // that overload stops this file building — and the assertions pin the binding's result.
    [Fact]
    public void PartialFindings_WithALiteralNullSecondArgument_BindsToTheInnerConstructorAndIsEmpty()
    {
        var ex = new YaraScanIncompleteException("m", null);

        Assert.Empty(ex.PartialFindings);
        Assert.Null(ex.InnerException);
    }

    // A null list in the full constructor is normalized, not stored.
    [Fact]
    public void PartialFindings_WithANullList_IsEmptyNotNull()
    {
        var ex = new YaraScanIncompleteException("m", null, null);

        Assert.NotNull(ex.PartialFindings);
        Assert.Empty(ex.PartialFindings);
    }

    // The hits are carried, in order, with their raw paths (escaping happens at the report boundary, not here — the
    // path must still resolve against the extraction root).
    [Fact]
    public void PartialFindings_CarryEveryHitPassedWithItsRawPath()
    {
        var raw = Path.Combine("root", "content", "pay\nload.bin");
        var inner = new IOException("copy failed");
        var hits = new List<(string FullPath, YaraMatch Match)> { (raw, Match("A")), ("b.bin", Match("B")) };

        var ex = new YaraScanIncompleteException("partial", inner, hits);

        Assert.Same(inner, ex.InnerException);
        Assert.Equal(2, ex.PartialFindings.Count);
        Assert.Equal(raw, ex.PartialFindings[0].FullPath);
        Assert.Equal("A", ex.PartialFindings[0].Match.Rule);
        Assert.Equal("b.bin", ex.PartialFindings[1].FullPath);
        Assert.Equal("B", ex.PartialFindings[1].Match.Rule);
    }

    // The snapshot property. The default ScanDirectory loop builds its hit list incrementally and hands that live
    // List to the exception; a thrower that mutated it afterwards (or a caller that cast it back and cleared it) must
    // not be able to change — least of all empty — what PackageScanner reports.
    [Fact]
    public void PartialFindings_IsASnapshot_UnaffectedByLaterChangesToThePassedList()
    {
        var hits = new List<(string FullPath, YaraMatch Match)> { ("a.bin", Match("A")) };

        var ex = new YaraScanIncompleteException("partial", null, hits);
        hits.Clear();
        hits.Add(("forged.bin", Match("Forged")));

        var only = Assert.Single(ex.PartialFindings);
        Assert.Equal("a.bin", only.FullPath);
        Assert.Equal("A", only.Match.Rule);
        Assert.False(ReferenceEquals(hits, ex.PartialFindings), "PartialFindings must not alias the thrower's list.");
    }
    #endregion

    #region Helpers
    private static YaraMatch Match(string rule) =>
        new(rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>());
    #endregion
}
