namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Pins the invariant that capability detection is built on CCI <b>type and method references</b> and never on
/// the definitions behind them (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §0).
/// <para>
/// The spike measured 75,155 call sites: the reference itself was <c>Dummy</c> <b>0</b> times and its
/// containing type reference <b>0</b> times, yet <c>ContainingType.ResolvedType</c> was <c>Dummy</c> for
/// 23,903 of them and <c>ResolvedMethod</c> for 21,930 — and the produced keys degraded <b>0</b> times. All
/// 185 catalog hits and 213 map verdicts in that corpus came out of unresolved references.
/// </para>
/// <para>
/// <b>This holds only because nothing under <c>src/</c> reads <c>ResolvedType</c>/<c>ResolvedMethod</c>, and
/// nothing enforces that.</b> A future change that reached for a resolved definition to build a name would
/// turn every BCL call site into a miss on any machine where the BCL does not resolve — a false negative in a
/// security detector, the worst direction available. These tests are the enforcement: they compare the same
/// bytes loaded with dependencies present against the same bytes loaded alone, and require the answer not to
/// move.
/// </para>
/// </summary>
public sealed class ReferenceSideNamingInvariantTests : IClassFixture<UnresolvedReferenceFixture>
{
    #region Constructors
    public ReferenceSideNamingInvariantTests(UnresolvedReferenceFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The A/B is real, not vacuous: the same bytes yield the same call sites in the same order, but isolating
    /// the file strictly increases how many of them fail to resolve. Without this, every equality below could
    /// pass simply because the two loads resolved identically.
    /// </summary>
    [Fact]
    public void IsolatedLoad_LosesResolutionsThatTheDependencyPresentLoadKeeps()
    {
        var withDependencies = fixture.WithDependencies;
        var isolated = fixture.Isolated;

        Assert.NotEmpty(withDependencies);
        Assert.Equal(withDependencies.Count, isolated.Count);

        var before = withDependencies.Count(site => site.ContainingTypeResolvesToDummy);
        var after = isolated.Count(site => site.ContainingTypeResolvesToDummy);

        // Both loads already lose the BCL (PeReader.DefaultHost does not probe for it), so `before` is large;
        // the siblings are what isolation additionally takes away.
        Assert.True(before > 0, "Expected the BCL to be unresolvable even with dependencies present.");
        Assert.True(
            after > before,
            $"Isolating the assembly must lose MORE resolutions, not the same: {after} vs {before} of {isolated.Count} call sites. "
                + "If these are equal the A/B proves nothing — check that the subject still has sibling references.");
        Assert.True(after < isolated.Count, "Expected at least one self-referencing call site to keep resolving.");
    }

    /// <summary>
    /// The distinction the spike drew and the one that matters: resolution fails constantly, but the
    /// <em>reference</em> is never the <c>Dummy</c> sentinel. That is why the names survive — a live
    /// <c>INamespaceTypeReference</c>/<c>INestedTypeReference</c> still carries its name, its namespace and its
    /// defining-assembly reference even when the definition behind it is missing.
    /// </summary>
    [Fact]
    public void CalleeAndContainingTypeReferences_AreNeverTheDummySentinel_EvenWhenResolutionIs()
    {
        var sites = fixture.WithDependencies.Concat(fixture.Isolated).ToArray();

        Assert.True(
            sites.Count(site => site.MethodResolvesToDummy) > 0,
            "Vacuous: no call site resolved to Dummy at all, so 'the reference is not Dummy' says nothing.");

        Assert.Empty(sites.Where(site => site.CalleeReferenceIsDummy));
        Assert.Empty(sites.Where(site => site.ContainingTypeReferenceIsDummy));
    }

    /// <summary>
    /// <see cref="AssemblyAnalyzer.TypeName"/> — the string the capability catalog prefix-matches — is
    /// positionally identical across the two loads. This is the assertion that fails the moment a name is
    /// built from a resolved definition.
    /// </summary>
    [Fact]
    public void TypeName_OfEveryCallSite_IsIdenticalWithAndWithoutResolution()
    {
        AssertPositionallyEqual(site => site.TypeName, nameof(CallSite.TypeName));
    }

    /// <summary>
    /// <see cref="CanonicalName.ClassificationKey(MethodIdentity)"/> — the key <c>capabilities.cm</c> matches —
    /// is positionally identical across the two loads.
    /// </summary>
    [Fact]
    public void ClassificationKey_OfEveryCallSite_IsIdenticalWithAndWithoutResolution()
    {
        AssertPositionallyEqual(site => site.ClassificationKey, nameof(CallSite.ClassificationKey));
    }

    /// <summary>
    /// <see cref="CanonicalName.NodeId(MethodIdentity)"/> too, parameter signature included: a parameter type
    /// is itself a reference that may be unresolvable, so the node id is the strictest of the three.
    /// </summary>
    [Fact]
    public void NodeId_OfEveryCallSite_IsIdenticalWithAndWithoutResolution()
    {
        AssertPositionallyEqual(site => site.NodeId, nameof(CallSite.NodeId));
    }

    /// <summary>
    /// And the keys produced from unresolved references are not merely <em>equal</em> but <em>usable</em>: none
    /// of the two degraded shapes pinned in <see cref="DummySentinelDegradationTests"/> occurs at any call
    /// site, and none is blank or carries <see cref="CanonicalName.UnknownPart"/>. Equality alone would still
    /// pass if both loads degraded identically.
    /// </summary>
    [Fact]
    public void KeysFromUnresolvedReferences_AreNeverDegraded()
    {
        var unresolved = fixture.Isolated
            .Where(site => site.ContainingTypeResolvesToDummy && site.MethodResolvesToDummy)
            .ToArray();

        Assert.NotEmpty(unresolved);

        var degraded = unresolved.Where(IsDegraded).ToArray();

        Assert.True(
            degraded.Length == 0,
            $"{degraded.Length} of {unresolved.Length} unresolved call sites produced a degraded key, e.g. "
                + string.Join("; ", degraded.Take(5).Select(site => $"[{site.TypeName}] / [{site.ClassificationKey}]")));
    }

    /// <summary>
    /// END TO END, no dependency resolvable: the fixture is copied alone into an empty directory, so every
    /// callee's <c>ContainingType.ResolvedType</c> and <c>ResolvedMethod</c> are <c>Dummy</c> — and all three
    /// capabilities are still detected, from the references alone. This is the test that fails if a
    /// <c>ResolvedType</c> dependency is ever introduced into the detection path.
    /// </summary>
    [Theory]
    [InlineData(Capability.FileSystem, ApiCallKind.Call, "System.IO.File.ReadAllText")]
    [InlineData(Capability.Network, ApiCallKind.Construct, "System.Net.Http.HttpClient..ctor")]
    [InlineData(Capability.ProcessExecution, ApiCallKind.Call, "System.Diagnostics.Process.Start")]
    public void Analyze_WithNothingResolvable_StillDetectsTheSensitiveApi(
        Capability capability, ApiCallKind kind, string calledApi)
    {
        Assert.Contains(
            fixture.ThreeApiReport.Findings,
            finding => finding.Capability == capability && finding.Kind == kind && finding.CalledApi == calledApi);
    }

    /// <summary>
    /// The precondition of the test above, asserted rather than assumed: the fixture really is alone in its
    /// directory, and every one of its call sites really did fail to resolve — both the containing type and
    /// the method. Without this, "detection still works" could just mean the BCL happened to be resolvable.
    /// </summary>
    [Fact]
    public void ThreeApiFixture_IsAloneInItsDirectory_AndNoCallSiteResolves()
    {
        Assert.Equal(1, UnresolvedReferenceFixture.FilesBesideAssembly(fixture.ThreeApiPath));

        Assert.NotEmpty(fixture.ThreeApiCallSites);
        Assert.All(fixture.ThreeApiCallSites, site =>
        {
            Assert.True(site.ContainingTypeResolvesToDummy, $"'{site.NodeId}' unexpectedly resolved its containing type.");
            Assert.True(site.MethodResolvesToDummy, $"'{site.NodeId}' unexpectedly resolved its method.");
        });
    }

    /// <summary>
    /// The full, exact keys the spike tabulated (§0.3) for those same four unresolved call sites — including
    /// the node id of the second <c>Process.Start</c> overload, whose parameter
    /// <c>System.Diagnostics.ProcessStartInfo</c> is itself an unresolved reference and must still render in
    /// full. Anything short of the whole key would still "contain" the type name, so the assertion is equality.
    /// </summary>
    [Theory]
    [InlineData("System.IO.File", "System.IO.File.ReadAllText", "System.IO.File.ReadAllText(System.String)")]
    [InlineData("System.Net.Http.HttpClient", "System.Net.Http.HttpClient..ctor", "System.Net.Http.HttpClient..ctor()")]
    [InlineData("System.Diagnostics.Process", "System.Diagnostics.Process.Start", "System.Diagnostics.Process.Start(System.String)")]
    [InlineData("System.Diagnostics.Process", "System.Diagnostics.Process.Start", "System.Diagnostics.Process.Start(System.Diagnostics.ProcessStartInfo)")]
    public void UnresolvedCallSite_ProducesTheFullTypeNameKeyAndNodeId(string typeName, string key, string nodeId)
    {
        var site = Assert.Single(fixture.ThreeApiCallSites, candidate => candidate.NodeId == nodeId);

        Assert.Equal(typeName, site.TypeName);
        Assert.Equal(key, site.ClassificationKey);
    }

    /// <summary>
    /// The same four keys are what the shipped <c>capabilities.cm</c> map classifies, so the invariant covers
    /// the map seam and not only the hard-coded catalog: an unresolved reference still yields a
    /// <see cref="CapabilityClass.Capability"/> verdict, never <see cref="CapabilityVerdict.None"/>.
    /// </summary>
    [Theory]
    [InlineData("System.IO.File.ReadAllText", Capability.FileSystem)]
    [InlineData("System.Net.Http.HttpClient..ctor", Capability.Network)]
    [InlineData("System.Diagnostics.Process.Start", Capability.ProcessExecution)]
    public void CapabilityMap_ClassifiesTheKeysProducedFromUnresolvedReferences(string key, Capability expected)
    {
        Assert.Contains(fixture.ThreeApiCallSites, site => site.ClassificationKey == key);

        var verdict = CapabilityMap.Default.Classify(key);

        Assert.Equal(CapabilityClass.Capability, verdict.Class);
        Assert.Equal(expected, verdict.Capability);
    }

    /// <summary>
    /// Unresolvable references cost no coverage either: nothing is skipped, so the report cannot claim
    /// completeness while quietly having analyzed less (ADR-0024).
    /// </summary>
    [Fact]
    public void Analyze_WithNothingResolvable_SkipsNoMethod()
    {
        var report = fixture.ThreeApiReport;

        Assert.True(report.MethodsTotal > 0);
        Assert.Equal(0, report.MethodsSkipped);
        Assert.Empty(report.SkippedMethods);
        Assert.Equal(report.MethodsTotal, report.MethodsAnalyzed);
    }

    // Compares one projection of the two loads element by element and reports the first few divergences by
    // index, because "the sequences differ" on 2,000+ entries is not actionable on its own.
    private void AssertPositionallyEqual(Func<CallSite, string> projection, string what)
    {
        var withDependencies = fixture.WithDependencies;
        var isolated = fixture.Isolated;

        Assert.Equal(withDependencies.Count, isolated.Count);

        var differences = Enumerable.Range(0, isolated.Count)
            .Where(i => !string.Equals(projection(withDependencies[i]), projection(isolated[i]), StringComparison.Ordinal))
            .ToArray();

        Assert.True(
            differences.Length == 0,
            $"{what} differed at {differences.Length} of {isolated.Count} call sites between the load WITH dependencies "
                + "and the load with nothing resolvable, so a name is being built from a resolved definition. First few: "
                + string.Join("; ", differences.Take(5).Select(i =>
                    $"#{i} [{projection(withDependencies[i])}] vs [{projection(isolated[i])}]")));
    }

    // The strict degradation predicate the spike measured at zero: an <unknown> part, a blank name, the Dummy
    // sentinel's name, or TypeHelper's last-resort "unknown type: ..." rendering.
    private static bool IsDegraded(CallSite site) =>
        site.ClassificationKey.Contains(CanonicalName.UnknownPart, StringComparison.Ordinal) ||
        site.NodeId.Contains(CanonicalName.UnknownPart, StringComparison.Ordinal) ||
        string.IsNullOrWhiteSpace(site.TypeName) ||
        site.TypeName == DummySentinelDegradationTests.DummyTypeReferenceName ||
        site.TypeName.StartsWith("unknown type:", StringComparison.Ordinal);
    #endregion

    #region Fields
    private readonly UnresolvedReferenceFixture fixture;
    #endregion
}
