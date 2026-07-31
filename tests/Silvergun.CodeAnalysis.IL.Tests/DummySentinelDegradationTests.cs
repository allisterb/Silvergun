namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Pins the <b>one shape that genuinely degrades</b>: a CCI <c>Dummy</c> <em>reference</em> — what the reader
/// hands back for a corrupt <c>TypeRef</c>/<c>MemberRef</c> token — as opposed to a live reference whose
/// <em>resolution</em> is <c>Dummy</c> (that one costs nothing; see
/// <see cref="ReferenceSideNamingInvariantTests"/>).
/// <para>
/// <b>These assertions are not desired behaviour.</b> Each names a real miss: the rendered type name matches
/// no catalog prefix, and the classification key matches no <c>capabilities.cm</c> entry, so a capability
/// carried by such a call site would go undetected. They are pinned because the degradation is
/// <em>visible</em> — a name no legal C# and no compiler mangling can produce — and because it was measured at
/// <b>0 occurrences in 75,155 call sites</b> across two benign controls and five hostile inputs
/// (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §0.4). Pinning it means a future change that starts
/// producing these shapes shows up as a failing test here rather than as silent under-reporting.
/// </para>
/// <para>
/// If one of these ever fires in the field, the fix is upstream — stop producing a <c>Dummy</c> reference, or
/// surface it as opacity per ADR-0024 — <b>not</b> to relax the expected string.
/// </para>
/// </summary>
public sealed class DummySentinelDegradationTests
{
    #region Properties
    /// <summary>
    /// The literal CCI emits for a <c>Dummy</c> type reference
    /// (<c>ext/analysis-net/cci/.../TypeHelper.cs:3510</c>, the first line of <c>GetTypeName</c>). Shared with
    /// <see cref="ReferenceSideNamingInvariantTests"/>, whose degradation predicate has to recognise it.
    /// </summary>
    public const string DummyTypeReferenceName = "Microsoft.Cci.DummyTypeReference";
    #endregion

    #region Methods
    /// <summary>
    /// KNOWN DEGRADATION (measured at 0 occurrences). <see cref="AssemblyAnalyzer.TypeName"/> of the sentinel
    /// renders CCI's own class name, which no sensible catalog entry can prefix-match — so every capability
    /// call site behind such a reference is a miss, not a finding.
    /// </summary>
    [Fact]
    public void KnownDegradation_TypeNameOfADummyTypeReference_IsCcisSentinelNameAndMatchesNoCatalogEntry()
    {
        var name = AssemblyAnalyzer.TypeName(Dummy.TypeReference);

        Assert.Equal(DummyTypeReferenceName, name);
        Assert.DoesNotContain(
            CapabilityAnalysis.Catalog,
            api => name.StartsWith(api.TypePrefix, StringComparison.Ordinal));
    }

    /// <summary>
    /// KNOWN DEGRADATION (measured at 0 occurrences). The neutral-name adapter degrades the same sentinel
    /// differently — to <see cref="CanonicalName.UnknownPart"/> rather than to CCI's class name — because it
    /// walks the reference structurally and finds no usable name. Both renderings are misses; they are pinned
    /// together so the asymmetry is documented rather than discovered later.
    /// </summary>
    [Fact]
    public void KnownDegradation_CciNamesRenderingOfADummyTypeReference_IsTheUnknownPlaceholder()
    {
        Assert.Equal(CanonicalName.UnknownPart, CciNames.TypeName(Dummy.TypeReference));
        Assert.Equal(CanonicalName.UnknownPart, CanonicalName.ClassificationKey(CciNames.Of(Dummy.TypeReference)));
    }

    /// <summary>
    /// KNOWN DEGRADATION (measured at 0 occurrences). A <c>Dummy</c> <em>method</em> reference loses both
    /// halves of its identity: the declaring type and the method name each fall back to the placeholder, and
    /// the node id adds an empty signature.
    /// </summary>
    [Fact]
    public void KnownDegradation_KeysOfADummyMethodReference_AreUnknownDotUnknown()
    {
        var identity = CciNames.Of(Dummy.MethodReference);

        Assert.Equal($"{CanonicalName.UnknownPart}.{CanonicalName.UnknownPart}", CanonicalName.ClassificationKey(identity));
        Assert.Equal($"{CanonicalName.UnknownPart}.{CanonicalName.UnknownPart}()", CanonicalName.NodeId(identity));
        Assert.Empty(identity.ParameterTypes);
    }

    /// <summary>
    /// KNOWN DEGRADATION (measured at 0 occurrences), stated as the consequence that actually matters: the
    /// degraded key gets no verdict from the shipped map, i.e. the finding is lost. The control in the same
    /// test — a real key that does get a verdict — is what proves the map is loaded and matching at all, so a
    /// broken map cannot make this pass for the wrong reason.
    /// </summary>
    [Fact]
    public void KnownDegradation_DegradedKeys_GetNoCapabilityMapVerdict()
    {
        var map = CapabilityMap.Default;

        Assert.Equal(CapabilityVerdict.None, map.Classify(CanonicalName.ClassificationKey(CciNames.Of(Dummy.MethodReference))));
        Assert.Equal(CapabilityVerdict.None, map.Classify(DummyTypeReferenceName + ".Anything"));

        // Control: the map does classify a real key, so the two None verdicts above mean "no match", not
        // "nothing is ever matched".
        Assert.Equal(CapabilityClass.Capability, map.Classify("System.IO.File.ReadAllText").Class);
    }

    /// <summary>
    /// The sentinels are reachable and inspectable at all — <c>Dummy.TypeReference</c> and
    /// <c>Dummy.MethodReference</c> really are instances of CCI's <c>Dummy</c> base class, which is what
    /// <c>TypeHelper.GetTypeName</c>'s <c>type is Dummy</c> test keys on and what the corpus-wide
    /// zero-occurrence measurement in <see cref="ReferenceSideNamingInvariantTests"/> tests every call site
    /// against. Without this the other assertions could be about some unrelated object.
    /// </summary>
    [Fact]
    public void DummySentinels_AreInstancesOfTheDummyBaseClass()
    {
        Assert.IsAssignableFrom<Dummy>(Dummy.TypeReference);
        Assert.IsAssignableFrom<Dummy>(Dummy.MethodReference);
    }
    #endregion
}
