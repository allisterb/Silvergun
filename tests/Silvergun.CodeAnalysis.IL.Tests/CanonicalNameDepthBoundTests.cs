namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

using ModelTypes = Model.Types;

/// <summary>
/// The <b>adapters'</b> 64-link containing-type depth bound, not the formatter's rendering of it: that a
/// nesting chain longer than the bound actually reaches <see cref="CanonicalName.Truncated"/> rather than
/// falling through to an ordinary <see cref="TypeIdentity"/>. The bound is attacker-controlled — a hostile or
/// cyclic chain is exactly what it exists for — and a regression here would be invisible to every other test
/// in this suite, because no real assembly nests 64 deep.
/// <para>
/// Exercised on the <c>Model</c> side, where <see cref="ModelTypes.BasicType"/> is constructible in-process:
/// the chain is built exactly as <c>CCIProvider.TypeExtractor</c> builds one — every link carries the
/// outermost type's namespace, and <c>GenericParameterCount</c> is cumulative over the chain. Nothing is
/// loaded and no host is bound, so no metadata resolution happens.
/// </para>
/// <para>
/// The CCI half of the same bound needs a hand-written <c>INestedTypeReference</c> chain (a large stub) and is
/// a documented residual gap; the shared <see cref="CanonicalName.Truncated"/> contract it degrades to is
/// pinned in <see cref="CanonicalNameTests"/>.
/// </para>
/// </summary>
public sealed class CanonicalNameDepthBoundTests
{
    #region Methods
    /// <summary>
    /// Past the bound the walk cannot reach the outermost type, so the identity must be the shared truncation
    /// marker over the 64 <em>innermost</em> links: no namespace (none was ever legitimately read), no arity
    /// (the two layers count it incompatibly on a partial chain) and <see cref="CanonicalName.UnknownPart"/>
    /// prepended so the degradation is visible. Falling through to <c>new TypeIdentity(space, chain, arity)</c>
    /// would keep the namespace and the arity and lose the marker — all three are asserted.
    /// </summary>
    [Theory]
    [InlineData(MaxDepth + 1)]
    [InlineData(70)]
    public void ModelNames_ChainDeeperThanBound_ReturnsTruncatedIdentity(int length)
    {
        var innermost = Chain(length);

        var identity = ModelNames.Of(innermost);

        // The walk starts at the innermost link and goes outward, so exactly the last MaxDepth links are read,
        // in outer-to-inner order.
        var walked = Enumerable.Range(length - MaxDepth, MaxDepth).Select(LevelName).ToArray();

        Assert.Equal(CanonicalName.Truncated(walked), identity);
        Assert.Equal(string.Empty, identity.Namespace);
        Assert.Equal(0, identity.GenericArity);
        Assert.Equal(MaxDepth + 1, identity.NestingChain.Count);
        Assert.Equal(CanonicalName.UnknownPart, identity.NestingChain[0]);
        Assert.Equal(LevelName(length - 1), identity.NestingChain[^1]);
        // The links beyond the bound were never read, and the namespace lives on the outermost of them.
        Assert.DoesNotContain(LevelName(0), identity.NestingChain);
        Assert.DoesNotContain(DeepNamespace, CanonicalName.ClassificationKey(identity), StringComparison.Ordinal);
        Assert.StartsWith(CanonicalName.UnknownPart, CanonicalName.ClassificationKey(identity), StringComparison.Ordinal);
    }

    /// <summary>
    /// The counterpart that stops the truncation test above from passing vacuously: at or below the bound the
    /// walk completes, so the namespace and the cumulative arity are preserved and no marker appears anywhere.
    /// A chain of exactly <see cref="MaxDepth"/> links is still fully walked — the bound is on links read, not
    /// on the last index.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(MaxDepth - 1)]
    [InlineData(MaxDepth)]
    public void ModelNames_ChainAtOrBelowBound_IsNotTruncated(int length)
    {
        var innermost = Chain(length);

        var identity = ModelNames.Of(innermost);

        var chain = Enumerable.Range(0, length).Select(LevelName).ToArray();

        Assert.Equal(new TypeIdentity(DeepNamespace, chain, InnermostArity), identity);
        Assert.Equal(DeepNamespace, identity.Namespace);
        Assert.Equal(InnermostArity, identity.GenericArity);
        Assert.Equal(LevelName(0), identity.NestingChain[0]);
        Assert.DoesNotContain(CanonicalName.UnknownPart, CanonicalName.NodeId(identity), StringComparison.Ordinal);
        Assert.StartsWith(DeepNamespace + "." + LevelName(0), CanonicalName.ClassificationKey(identity), StringComparison.Ordinal);
    }

    /// <summary>
    /// The reason the bound exists at all: a containing-type chain that loops back on itself is legal in
    /// hostile metadata and would otherwise walk forever. It must terminate at the bound and degrade to the
    /// same visible marker, not hang and not throw.
    /// </summary>
    [Fact]
    public void ModelNames_CyclicContainingTypeChain_Truncates_AndDoesNotHang()
    {
        var self = new ModelTypes.BasicType("Loop") { ContainingNamespace = DeepNamespace };
        self.ContainingType = self;

        var identity = ModelNames.Of(self);

        Assert.Equal(CanonicalName.Truncated(Enumerable.Repeat("Loop", MaxDepth)), identity);
        Assert.Equal(string.Empty, identity.Namespace);
        Assert.Equal(MaxDepth + 1, identity.NestingChain.Count);
        Assert.Equal(CanonicalName.UnknownPart, identity.NestingChain[0]);
    }

    /// <summary>
    /// A truncated declaring type still names its method: the marker degrades the type, never discards the
    /// member, so a deeply nested method keeps whatever discriminating power the read part of the chain has.
    /// </summary>
    [Fact]
    public void ModelNames_MethodOnChainDeeperThanBound_KeepsMethodNameAndSignature()
    {
        var method = new ModelTypes.MethodReference("Run", ModelTypes.PlatformTypes.Void) { ContainingType = Chain(70) };

        var identity = ModelNames.Of(method);

        Assert.Equal("Run", identity.MethodName);
        Assert.Equal(CanonicalName.Truncated(Enumerable.Range(70 - MaxDepth, MaxDepth).Select(LevelName)), identity.DeclaringType);
        Assert.StartsWith(CanonicalName.UnknownPart + "." + LevelName(70 - MaxDepth), CanonicalName.NodeId(identity), StringComparison.Ordinal);
        Assert.EndsWith(".Run()", CanonicalName.NodeId(identity), StringComparison.Ordinal);
    }

    // Builds a containing-type chain of `length` links - "Level0" outermost to "Level{length-1}" innermost -
    // the way CCIProvider.TypeExtractor builds one: every link carries the outermost type's namespace, and
    // GenericParameterCount is cumulative over the chain (so only the innermost link's value is ever read).
    // Returns the innermost link, which is what an adapter is handed.
    private static ModelTypes.BasicType Chain(int length)
    {
        ModelTypes.BasicType? containing = null;

        for (var level = 0; level < length; level++)
        {
            containing = new ModelTypes.BasicType(LevelName(level))
            {
                ContainingNamespace = DeepNamespace,
                ContainingType = containing,
            };
        }

        // Non-zero so the truncation test can prove the arity is DROPPED rather than merely absent.
        containing!.GenericParameterCount = InnermostArity;

        return containing;
    }

    private static string LevelName(int level) => "Level" + level;
    #endregion

    #region Fields
    // Mirrors the private MaxDepth of both CciNames and ModelNames; the bound is part of the component's
    // contract (see the "generic nesting deeper than 64 levels" limitation in the task spec), not an
    // implementation detail.
    private const int MaxDepth = 64;

    private const int InnermostArity = 3;
    private const string DeepNamespace = "Silvergun.Deep";
    #endregion
}
