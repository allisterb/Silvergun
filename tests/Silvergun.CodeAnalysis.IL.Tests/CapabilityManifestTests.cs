namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Xunit;

/// <summary>
/// <c>docs/agent/tasks/capability-diff-versions.md</c> "DESIGN REFINEMENT (2026-08-20)": the shared
/// findings-&gt;per-capability projection now lives in the IL library as <see cref="CapabilityManifest.From"/>, and
/// is consumed both by <c>ReportTheme.CapabilityManifest</c> (CLI rendering) and <see cref="CapabilitySnapshot"/>
/// (serialization). This class pins the PROJECTION itself — presence, call-site counts, and the enum-driven row
/// set/order — independent of either consumer. Rendering is already pinned by the 20 tests in
/// <c>tests/Silvergun.CLI.Tests/CapabilityManifestTests.cs</c>; this class does not duplicate those, it covers the
/// new data type those renderers (and the new snapshot) are refactored to sit on top of.
/// </summary>
public sealed class CapabilityManifestTests
{
    #region Methods — A: presence/count projection
    [Fact]
    public void From_EmptyFindingList_AllCapabilitiesAbsentWithZeroCount()
    {
        var manifest = CapabilityManifest.From([]);

        Assert.All(manifest.Entries, e =>
        {
            Assert.False(e.Present);
            Assert.Equal(0, e.CallSiteCount);
        });
        Assert.Equal(
            Enum.GetValues<Capability>(),
            manifest.Entries.Select(e => e.Capability).ToArray());   // enum-declaration order, empty input too
    }

    [Fact]
    public void From_MixedFindings_ReflectsCorrectPresenceAndPerCapabilityCounts()
    {
        var findings = new[]
        {
            Finding(Capability.FileSystem), Finding(Capability.FileSystem),
            Finding(Capability.Network),
            Finding(Capability.Registry), Finding(Capability.Registry), Finding(Capability.Registry),
        };

        var manifest = CapabilityManifest.From(findings);

        AssertEntry(manifest, Capability.FileSystem, present: true, count: 2);
        AssertEntry(manifest, Capability.Network, present: true, count: 1);
        AssertEntry(manifest, Capability.Registry, present: true, count: 3);

        // Every OTHER capability stays absent/zero — the projection is not just "present ones show up right",
        // it must also leave everything untouched by this finding set unaffected.
        foreach (var capability in Enum.GetValues<Capability>().Except([Capability.FileSystem, Capability.Network, Capability.Registry]))
            AssertEntry(manifest, capability, present: false, count: 0);
    }

    [Fact]
    public void From_OneCapabilityWithManyCallSites_CountReflectsAllOfThem()
    {
        var findings = Enumerable.Range(0, 47).Select(i => Finding(Capability.ReflectionInvocation, callerMethod: $"M{i}")).ToArray();

        var manifest = CapabilityManifest.From(findings);

        AssertEntry(manifest, Capability.ReflectionInvocation, present: true, count: 47);
        foreach (var capability in Enum.GetValues<Capability>().Where(c => c != Capability.ReflectionInvocation))
            AssertEntry(manifest, capability, present: false, count: 0);
    }

    [Fact]
    public void From_EntriesAlwaysInEnumDeclarationOrder_RegardlessOfFindingOrder()
    {
        // Findings deliberately supplied in an order that does NOT match enum-declaration order.
        var findings = new[] { Finding(Capability.RuntimeControl), Finding(Capability.FileSystem), Finding(Capability.Network) };

        var manifest = CapabilityManifest.From(findings);

        Assert.Equal(Enum.GetValues<Capability>(), manifest.Entries.Select(e => e.Capability).ToArray());
    }
    #endregion

    #region Methods — B: structural guard against a hardcoded list (⚠️ mutation-checked — see the comment below)
    // The reframe task's own warning (mirrored from the renderer-side guard in
    // tests/Silvergun.CLI.Tests/CapabilityManifestTests.cs): a test hardcoding "11" would silently keep passing
    // forever even if CapabilityManifest.From quietly reverted to a hardcoded list of today's names while
    // Capability grew a 12th value. This asserts against Enum.GetValues<Capability>().Length itself — the SAME
    // oracle CapabilityManifest.From is built from — never a literal.
    //
    // MUTATION-CHECK (documented here, not performed by editing src/, which this task forbids): built a standalone
    // scratch console harness outside the repo (not committed) defining two enums — an 11-member CapV1 mirroring
    // today's Capability, and a 12-member CapV2 mirroring a future append — and two candidate projections: one
    // deriving its row count from Enum.GetValues<T>().Length (the shipped CapabilityManifest.From pattern) and one
    // hardcoding a literal 11-name list (the mutant this guard exists to catch, i.e. CapabilityManifest.From
    // "simplified" back to a fixed array/switch). Comparing both against the oracle Enum.GetValues<T>().Length
    // reproduced exactly the failure mode this test is designed to catch:
    //   - 11-member enum: oracle=11, shipped=11 (guard PASS), mutant=11 (guard PASS — the two are indistinguishable
    //     here, which is also why a literal "11" baked into the TEST itself would look fine today).
    //   - 12-member enum (after an append): oracle=12, shipped=12 (guard PASS, tracks the growth), mutant=11
    //     (guard FAILS — 11 != 12).
    // A test whose own oracle was the literal 11 would have rated the mutant a false PASS in both cases; asserting
    // against Enum.GetValues<Capability>().Length instead catches it the moment the enum and the projection
    // diverge.
    [Fact]
    public void From_EntriesCount_EqualsEnumValuesLength_NeverALiteral()
    {
        var manifest = CapabilityManifest.From([Finding(Capability.FileSystem)]);

        var oracle = Enum.GetValues<Capability>().Length;   // NEVER hardcode this number
        Assert.Equal(oracle, manifest.Entries.Count);
    }

    [Fact]
    public void From_EveryCurrentEnumValueAppearsExactlyOnce()
    {
        var manifest = CapabilityManifest.From([]);

        foreach (var capability in Enum.GetValues<Capability>())
            Assert.Single(manifest.Entries, e => e.Capability == capability);
    }
    #endregion

    #region Methods — helpers
    private static void AssertEntry(CapabilityManifest manifest, Capability capability, bool present, int count)
    {
        var entry = Assert.Single(manifest.Entries, e => e.Capability == capability);
        Assert.Equal(present, entry.Present);
        Assert.Equal(count, entry.CallSiteCount);
    }

    private static ApiCallFinding Finding(
        Capability capability, string callerType = "T", string callerMethod = "M", string calledApi = "Some.Api.Call") =>
        new(capability, ApiCallKind.Call, callerType, callerMethod, calledApi);
    #endregion
}
