namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

using Xunit;

/// <summary>
/// Regression coverage for the self-referential enum
/// (<c>docs/agent/tasks/self-referential-enum-stack-overflow.md</c>,
/// <c>docs/agent/measurements/ilspy-provider-spike.md</c> §7). An enum's underlying type is the type of its
/// <c>value__</c> field, and nothing in ECMA-335 requires that field to be a primitive — so <c>E : E</c>, and
/// the two-step <c>Ping : Pong</c> / <c>Pong : Ping</c>, are representable. CCI <b>preserves</b> the cycle
/// rather than resolving it, so any walk that chased <c>UnderlyingType</c> would not terminate.
/// <para>
/// <b>This must run out of process.</b> A stack overflow is uncatchable — like the <c>FailFast</c> of
/// ADR-0021, no <c>catch</c> runs and <c>Assert.Throws</c>/<c>Record.Exception</c> cannot see it — and it
/// would take the whole xUnit host down, destroying every other result in the run. Every fact below asserts on
/// a child process's exit code and output instead. The fixture is generated at test time by
/// <see cref="CyclicEnumPatcher"/>; no crafted binary is committed.
/// </para>
/// </summary>
public sealed class CyclicEnumTerminationTests : IClassFixture<CyclicEnumFixture>
{
    #region Constructors
    public CyclicEnumTerminationTests(CyclicEnumFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The fixture is genuinely cyclic before anything is asserted about surviving it: the clean
    /// <c>value__</c> signature is <c>06 08</c> (<c>FIELD</c>, <c>ELEMENT_TYPE_I4</c>) and the patched one is
    /// <c>06 11 xx</c> (<c>FIELD</c>, <c>ELEMENT_TYPE_VALUETYPE</c>, a <c>TypeDef</c> token) — the same shape
    /// the spike verified on its hand-written IL. A patch that silently failed to take would make every other
    /// fact here pass while testing nothing.
    /// </summary>
    [Theory]
    [InlineData(nameof(SelfReferentialSubject))]
    [InlineData(nameof(PingSubject))]
    [InlineData(nameof(PongSubject))]
    public void GeneratedFixture_TypesEachSubjectsValueFieldAsAnEnum(string subject)
    {
        var clean = CyclicEnumPatcher.UnderlyingTypeSignature(fixture.CleanPath, subject);
        var patched = CyclicEnumPatcher.UnderlyingTypeSignature(fixture.PatchedPath, subject);

        Assert.Equal(new byte[] { FieldSignature, ElementTypeI4 }, clean);
        Assert.Equal(FieldSignature, patched[0]);
        Assert.Equal(ElementTypeValueType, patched[1]);
        Assert.True(patched.Length > 2, "A valuetype field signature must carry a TypeDefOrRef token after 0x11.");
    }

    /// <summary>
    /// The control enum in the same image is untouched, so "the analyzer read the cycle" cannot be confused
    /// with "the patcher corrupted every enum in the module".
    /// </summary>
    [Fact]
    public void GeneratedFixture_LeavesTheControlEnumPrimitive()
    {
        Assert.Equal(
            new byte[] { FieldSignature, ElementTypeI4 },
            CyclicEnumPatcher.UnderlyingTypeSignature(fixture.PatchedPath, nameof(SaneControl)));
    }

    /// <summary>
    /// THE regression: the shipping path — <see cref="AssemblyAnalyzer.Load"/>, the type walk,
    /// <see cref="AssemblyAnalyzer.TypeName"/> over every enum's underlying type, <c>CciNames.Of</c> over every
    /// method, and <see cref="CapabilityAnalysis.Analyze"/> — runs to completion on the cyclic module. A
    /// non-terminating walk shows up here as a timeout or an abnormal exit code, never as a lost test run.
    /// </summary>
    [Fact]
    public void Probe_AnalyzingTheCyclicEnumFixture_RunsToCompletion()
    {
        Assert.False(
            fixture.Probe.TimedOut,
            "The probe did not terminate, which is what an UnderlyingType walk that chases the cycle looks like: "
                + fixture.Probe.Describe());
        Assert.True(fixture.Probe.ExitedCleanly, $"Probe did not exit cleanly - {fixture.Probe.Describe()}");
        Assert.EndsWith("DONE", fixture.Probe.StandardOutput.TrimEnd(), StringComparison.Ordinal);
    }

    /// <summary>
    /// <see cref="AssemblyAnalyzer.TypeName"/> on the one-step cycle terminates and renders the enum as its own
    /// underlying type — CCI preserves the cycle, and the formatter returns after a single step because it
    /// renders a name rather than chasing <c>UnderlyingType</c>.
    /// </summary>
    [Fact]
    public void Probe_SelfReferentialEnum_RendersItselfAsItsUnderlyingType()
    {
        var self = typeof(SelfReferentialSubject).FullName;

        Assert.Contains($"ENUM {self} -> {self}", Output(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The two-step cycle terminates in both directions. It is asserted separately because a guard that only
    /// compared a type against itself would let this one through.
    /// </summary>
    [Fact]
    public void Probe_TwoStepEnumCycle_RendersBothDirections()
    {
        var ping = typeof(PingSubject).FullName;
        var pong = typeof(PongSubject).FullName;

        Assert.Contains($"ENUM {ping} -> {pong}", Output(), StringComparison.Ordinal);
        Assert.Contains($"ENUM {pong} -> {ping}", Output(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The control enum still renders <c>System.Int32</c> in the same run, so a module-wide decode failure
    /// cannot masquerade as the cycle being read correctly.
    /// </summary>
    [Fact]
    public void Probe_ControlEnum_StillRendersSystemInt32()
    {
        Assert.Contains($"ENUM {typeof(SaneControl).FullName} -> System.Int32", Output(), StringComparison.Ordinal);
    }

    /// <summary>
    /// Completion is not enough: the analysis must still be <em>complete</em>. Every method is analyzed, none
    /// is skipped, and all four sensitive call sites in the same module are still found — the cyclic enums cost
    /// no coverage and no finding (ADR-0024: "could not analyze" must never look like a clean result).
    /// </summary>
    [Fact]
    public void Probe_CapabilityAnalysis_LosesNoMethodAndNoFindingToTheCycle()
    {
        var match = Regex.Match(Output(), @"CAPABILITY-ANALYSIS-OK (\d+) (\d+) (\d+)");

        Assert.True(match.Success, $"No CAPABILITY-ANALYSIS-OK record - {fixture.Probe.Describe()}");
        Assert.Equal(ThreeApiCallSites, int.Parse(match.Groups[1].Value));
        Assert.True(int.Parse(match.Groups[2].Value) > 0, "Expected at least one analyzed method.");
        Assert.Equal(0, int.Parse(match.Groups[3].Value));
    }

    /// <summary>
    /// The signature decoder sees the pathological enums too — as parameter, return and array-element types —
    /// and renders each method's node id in full rather than degrading it.
    /// </summary>
    [Fact]
    public void Probe_MethodSignaturesMentioningTheCyclicEnums_RenderInFull()
    {
        var self = typeof(SelfReferentialSubject).FullName;
        var methods = Output().Split('\n').Where(line => line.StartsWith("METHOD ", StringComparison.Ordinal)).ToArray();

        Assert.Contains(methods, line => line.Contains($"{nameof(EnumOps)}.{nameof(EnumOps.Echo)}({self})", StringComparison.Ordinal));
        Assert.Contains(methods, line => line.Contains($"{nameof(EnumOps)}.{nameof(EnumOps.Count)}({self}[])", StringComparison.Ordinal));
        Assert.DoesNotContain(methods, line => line.Contains(CanonicalName.UnknownPart, StringComparison.Ordinal));
    }

    private string Output() =>
        fixture.Probe.ExitedCleanly
            ? fixture.Probe.StandardOutput
            : throw new InvalidOperationException($"Probe did not exit cleanly - {fixture.Probe.Describe()}");
    #endregion

    #region Fields
    // ECMA-335 II.23.2.4 (FIELD calling convention) and II.23.1.16 (element types).
    private const byte FieldSignature = 0x06;
    private const byte ElementTypeI4 = 0x08;
    private const byte ElementTypeValueType = 0x11;

    // ThreeApis declares exactly four sensitive call sites, and they live in the same module as the cyclic
    // enums - so this doubles as "the cycle cost no finding".
    private const int ThreeApiCallSites = 4;

    private readonly CyclicEnumFixture fixture;
    #endregion
}
