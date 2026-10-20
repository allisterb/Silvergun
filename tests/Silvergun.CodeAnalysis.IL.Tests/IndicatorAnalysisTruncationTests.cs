namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Reflection;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// Item H (bounds): <see cref="IndicatorReport.Truncated"/> is set — and a warning is emitted — when the
/// distinct-indicator cap is actually hit, and the cap only ever bounds DISTINCT indicators, never the
/// <see cref="IndicatorFinding.Occurrences"/> count of an already-tracked one.
/// <para>
/// Exercises the injectable <c>maxDistinctIndicators</c> constructor parameter added so this whole class no
/// longer needs the real (10,000-constant) cap or a machine-generated bulk fixture to trip it — see the
/// <c>&lt;param name="maxDistinctIndicators"&gt;</c> doc on <see cref="IndicatorAnalysis"/>'s constructor and
/// ARCHITECT DECISIONS #4 in <c>docs/agent/tasks/ldstr-indicator-classifier.md</c>. Two fixtures are used:
/// <see cref="CapFixture"/>, a small, deliberately isolated assembly (see
/// <see cref="IndicatorCapPayloads"/> for why isolation matters for the cap-boundary/accumulation
/// assertions), for the tests that need to pin an EXACT boundary; and the shared, ordinary
/// <see cref="AssemblyAnalyzerFixture"/> for the tests that only need "some assembly comfortably under the
/// cap" or "the same assembly with two equivalent constructions".
/// </para>
/// </summary>
public sealed class IndicatorAnalysisTruncationTests : IClassFixture<AssemblyAnalyzerFixture>, IClassFixture<IndicatorAnalysisTruncationTests.CapFixture>
{
    public IndicatorAnalysisTruncationTests(AssemblyAnalyzerFixture assemblyFixture, CapFixture capFixture)
    {
        this.assemblyFixture = assemblyFixture;
        this.capFixture = capFixture;
    }

    #region a — small cap over an assembly with more distinct indicators than the cap
    [Fact]
    public void Analyze_WithSmallCapOverAssemblyWithMoreDistinctIndicatorsThanTheCap_SetsTruncated()
    {
        var result = new IndicatorAnalysis(capFixture.Assembly, maxDistinctIndicators: 5).Analyze();

        Assert.True(result.IsSuccess, result.Message);
        Assert.True(result.Value.Truncated);
        Assert.Equal(5, result.Value.Findings.Count);
    }
    #endregion

    #region b — already-tracked keys keep accumulating Occurrences after the cap is hit
    // The subtle case: the cap bounds DISTINCT indicators, not counting. CapFixture's single method offers
    // six distinct hosts (.1-.6) followed by two more constants that embed the FIRST host (.1) again, all in
    // one straight-line method so CCI discovers them in exactly that order (see IndicatorCapPayloads' doc
    // comment). With a cap of 5: hosts .1-.5 fill the cap, .6 is refused (a genuinely NEW distinct key
    // arriving after the cap is full), and the two later .1 repeats — for a key already tracked BEFORE the
    // cap filled — must still land as additional Occurrences on .1's finding, not be silently dropped just
    // because Truncated is already true by the time they are processed.
    [Fact]
    public void Analyze_WithSmallCap_AlreadyTrackedKeyKeepsAccumulatingOccurrencesAfterCapHit()
    {
        var result = new IndicatorAnalysis(capFixture.Assembly, maxDistinctIndicators: 5).Analyze();

        Assert.True(result.IsSuccess, result.Message);
        Assert.True(result.Value.Truncated);

        var host1 = Assert.Single(result.Value.Findings, f => f.Value == "203.0.113.1");
        Assert.Equal(IndicatorCategory.PublicIpLiteral, host1.Category);
        // 1 initial occurrence + 2 later repeats, discovered AFTER the cap was already full.
        Assert.Equal(3, host1.Occurrences);

        // .6 was offered only after the cap's 5 slots were already claimed by .1-.5 — a genuinely new
        // distinct key, correctly refused rather than displacing an already-tracked one.
        Assert.DoesNotContain(result.Value.Findings, f => f.Value == "203.0.113.6");
    }
    #endregion

    #region c — cap of 0 and a negative cap behave as cap = 1
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Analyze_WithNonPositiveCap_DoesNotThrowAndBehavesAsCapOfOne(int nonPositiveCap)
    {
        var result = new IndicatorAnalysis(capFixture.Assembly, nonPositiveCap).Analyze();

        Assert.True(result.IsSuccess, result.Message);
        Assert.True(result.Value.Truncated);

        var host1 = Assert.Single(result.Value.Findings);
        Assert.Equal("203.0.113.1", host1.Value);
        // Every one of the eight constants after the very first (.2-.6, plus the two .1 repeats) is either a
        // refused new distinct key or an already-tracked-key repeat; only the repeats add to Occurrences.
        Assert.Equal(3, host1.Occurrences);
    }
    #endregion

    #region d — a cap above the default does not throw, behaves as the default, and never exceeds it
    // Direct unit test of the documented clamp (IndicatorAnalysis's constructor <param> doc): a value above
    // MaxDistinctIndicators clamps back down to it, so the parameter can only TIGHTEN the bound. Reflects the
    // private static helper directly (same technique StringConstantsSharedSeamTests already uses on
    // AssemblyAnalyzer.ScanMethodConstants) because proving the exact upper-bound value (10,000) end-to-end
    // would otherwise need an assembly with 10,001+ genuinely distinct indicators — the very machine-generated
    // fixture cost this injectable cap was added to eliminate.
    [Theory]
    [InlineData(null, 10_000)]
    [InlineData(int.MaxValue, 10_000)]
    [InlineData(10_001, 10_000)]
    [InlineData(10_000, 10_000)]
    [InlineData(9_999, 9_999)]
    [InlineData(5, 5)]
    [InlineData(1, 1)]
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    public void ClampMaxDistinctIndicators_ClampsToDocumentedRange(int? requested, int expected) =>
        Assert.Equal(expected, Clamp(requested));

    // End-to-end smoke test: on an assembly comfortably under the real cap, requesting a cap above the
    // documented default must not throw and must behave exactly like the default (null).
    [Fact]
    public void Analyze_WithCapAboveDefault_DoesNotThrowAndBehavesAsDefault()
    {
        var defaultResult = new IndicatorAnalysis(assemblyFixture.Assembly).Analyze();
        var aboveDefaultResult = new IndicatorAnalysis(assemblyFixture.Assembly, int.MaxValue).Analyze();

        Assert.True(defaultResult.IsSuccess, defaultResult.Message);
        Assert.True(aboveDefaultResult.IsSuccess, aboveDefaultResult.Message);
        Assert.False(aboveDefaultResult.Value.Truncated);
        Assert.Equal(defaultResult.Value.Findings, aboveDefaultResult.Value.Findings);
    }
    #endregion

    #region e — the no-arg and explicit-null constructors are equivalent (regression pin)
    // The constructor signature changed (maxDistinctIndicators was added as an optional trailing parameter):
    // pin that omitting it entirely is byte-for-byte equivalent to passing null explicitly, and that this
    // still matches pre-change classification behaviour on a known payload (AC1 from
    // IndicatorAnalysisTests.Analyze_CallbackDomainUrl_YieldsOneCallbackDomainFinding).
    [Fact]
    public void Analyze_NoArgConstructor_IsEquivalentToExplicitNullCap()
    {
        var implicitDefault = new IndicatorAnalysis(assemblyFixture.Assembly).Analyze();
        var explicitNull = new IndicatorAnalysis(assemblyFixture.Assembly, null).Analyze();

        Assert.True(implicitDefault.IsSuccess, implicitDefault.Message);
        Assert.True(explicitNull.IsSuccess, explicitNull.Message);
        Assert.Equal(implicitDefault.Value.Truncated, explicitNull.Value.Truncated);
        Assert.Equal(implicitDefault.Value.Findings, explicitNull.Value.Findings);

        // Pre-change behaviour pin: the ordinary fixture's known AC1 payload still classifies the same way.
        var callbackFinding = Assert.Single(implicitDefault.Value.Findings,
            f => f.CallerMethod == "GetCallbackDomainUrl");
        Assert.Equal(IndicatorCategory.CallbackDomain, callbackFinding.Category);
        Assert.Equal("x.pipedream.net", callbackFinding.Value);
    }
    #endregion

    #region f — negative control: comfortably under the cap is never Truncated
    // Without this, a suite that only ever observes Truncated == true would prove nothing about the flag
    // itself. Uses the SAME injected-cap mechanism as (a)-(c), just with a cap far above the fixture's actual
    // distinct-indicator count, so this is a control specifically for the injectable parameter, not merely a
    // restatement of IndicatorAnalysisTests.Analyze_OnTheOrdinaryFixture_IsNeverTruncated (which never passes
    // a non-null cap at all).
    [Fact]
    public void Analyze_WithCapComfortablyAboveDistinctCount_IsNotTruncated()
    {
        var result = new IndicatorAnalysis(capFixture.Assembly, maxDistinctIndicators: 1_000).Analyze();

        Assert.True(result.IsSuccess, result.Message);
        Assert.False(result.Value.Truncated);
        Assert.Equal(6, result.Value.Findings.Count); // hosts .1-.6; the two repeats merge into .1's Occurrences
    }
    #endregion

    // The truncation warns, same as every other bounded-output path in this codebase. Observed through the shared
    // WarningCapture (tests/Shared), never by swapping the process-global Runtime.logger, which a concurrent swap in
    // another collection could undo mid-test.
    [Fact]
    public void Analyze_OnAssemblyWithMoreDistinctIndicatorsThanTheCap_Warns()
    {
        using var capture = new WarningCapture();

        var result = new IndicatorAnalysis(capFixture.Assembly, maxDistinctIndicators: 5).Analyze();

        Assert.True(result.IsSuccess, result.Message);
        Assert.True(result.Value.Truncated);
        Assert.Contains(capture.Warnings, m => m.Contains("truncated", StringComparison.OrdinalIgnoreCase) ||
                                        m.Contains("cap", StringComparison.OrdinalIgnoreCase));
    }

    #region Helpers
    private static int Clamp(int? requested) => (int)ClampMaxDistinctIndicatorsMethod.Invoke(null, [requested])!;

    // Reflects the private clamp helper behind the constructor's maxDistinctIndicators parameter — see the
    // class doc comment on region d for why this is tested directly rather than only end-to-end.
    private static readonly MethodInfo ClampMaxDistinctIndicatorsMethod =
        typeof(IndicatorAnalysis).GetMethod("ClampMaxDistinctIndicators", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "IndicatorAnalysis.ClampMaxDistinctIndicators not found by reflection — its shape changed; update this test.");
    #endregion

    private readonly AssemblyAnalyzerFixture assemblyFixture;
    private readonly CapFixture capFixture;

    /// <summary>Loads the small, isolated cap-boundary fixture assembly once for this test class only.</summary>
    public sealed class CapFixture : System.IDisposable
    {
        public CapFixture()
        {
            Runtime.Initialize("Silvergun", "TESTS");

            var path = typeof(IndicatorCapPayloads).Assembly.Location;
            var result = AssemblyAnalyzer.Load(path);
            if (!result.IsSuccess)
                throw new System.InvalidOperationException($"Failed to load '{path}': {result.Message}", result.Exception);

            Assembly = result.Value;
        }

        public AssemblyAnalyzer Assembly { get; }

        public void Dispose() => Assembly.Dispose();
    }
}
