namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// Item B (<c>AssemblyAnalyzer.StringConstants</c> guard semantics) and item C (ARCHITECT DECISIONS #1 in
/// <c>docs/agent/tasks/ldstr-indicator-classifier.md</c>): behavioural equivalence between the shared
/// <c>ldstr</c>-extraction seam (<see cref="AssemblyAnalyzer.StringConstants"/>, which
/// <see cref="IndicatorAnalysis"/> reads) and <see cref="ObfuscationAnalysis"/>'s own, deliberately kept,
/// duplicate walk.
/// <para>
/// The refactor onto the shared seam was reverted because it moved <see cref="ObfuscationAnalysis"/>'s
/// <c>SafeName</c> call site into <c>AssemblyAnalyzer</c>'s IL, failing the structural guard
/// (<c>SafeNameTests.SafeName_BothConsumers_CallTheSharedSeam</c>) even though the produced findings were
/// byte-identical. That structural guard pins WHERE a call site lives, not the property that actually
/// matters — a divergence in the body-read walk ITSELF, which is what the duplication actually risks and
/// what these tests protect instead, behaviourally.
/// </para>
/// </summary>
public sealed class StringConstantsSharedSeamTests : IClassFixture<UnreadableMethodBodyFixture>
{
    public StringConstantsSharedSeamTests(UnreadableMethodBodyFixture fixture) => this.fixture = fixture;

    #region Item B — StringConstants() guard semantics
    // An unreadable method body is isolated: it costs only that method's constants, every other method's
    // constants survive unchanged, and the report is still produced (never lost to a top-level failure).
    [Fact]
    public void StringConstants_WhenOneMethodBodyIsUnreadable_OtherMethodsConstantsAreUnchanged()
    {
        var clean = fixture.Clean.StringConstants().ToList();
        var patched = fixture.Patched.StringConstants().ToList();

        Assert.NotEmpty(clean);
        // The patched method (Shapes.Loop) contributes no constants of its own either way (see
        // UnreadableMethodBodyFixture's doc comment on why it was chosen), so the two sequences — order
        // included — must be identical: any divergence here would mean some OTHER method's constants were
        // also lost, not just the corrupted one.
        Assert.Equal(clean, patched);
    }

    [Fact]
    public void IndicatorAnalysis_WhenOneMethodBodyIsUnreadable_SucceedsWithUnchangedFindings()
    {
        var clean = new IndicatorAnalysis(fixture.Clean).Analyze();
        var patched = new IndicatorAnalysis(fixture.Patched).Analyze();

        Assert.True(clean.IsSuccess, clean.Message);
        Assert.True(patched.IsSuccess, $"One unreadable body failed the whole indicator analysis: {patched.Message}");
        Assert.Equal(clean.Value.Findings, patched.Value.Findings);
    }

    // The warning path fires, naming the skipped method, exactly like ObfuscationAnalysis's own guard.
    // Observed through the shared WarningCapture (tests/Shared), never by swapping the process-global
    // Runtime.logger: two overlapping swaps in parallel collections restore each other's logger, and one of
    // them then goes deaf mid-test. The capture is scoped to this test's own flow.
    [Fact]
    public void StringConstants_WhenOneMethodBodyIsUnreadable_WarnsNamingTheMethod()
    {
        using var capture = new WarningCapture();

        _ = fixture.Patched.StringConstants().ToList();

        Assert.Contains(capture.Warnings, m =>
            m.Contains(UnreadableMethodBodyFixture.PatchedMethod, StringComparison.Ordinal) &&
            m.Contains("constant", StringComparison.OrdinalIgnoreCase));
    }
    #endregion

    #region Item C — behavioural equivalence between the two walks
    // Both consumers, run over the SAME corrupted method, agree it is skipped: neither throws (the
    // "never throws" contract each makes independently) and neither returns anything attributable to it.
    // This calls the REAL private per-method entry points via reflection — not a reimplementation of
    // either walk — so it exercises production code, not test-authored logic standing in for it.
    [Fact]
    public void SharedSeamAndObfuscationWalk_AgreeTheCorruptedMethodIsSkipped()
    {
        var patchedLoop = Method(fixture.Patched, UnreadableMethodBodyFixture.PatchedMethod);
        Assert.True(AssemblyAnalyzer.TryReadBody(patchedLoop).IsUnreadable,
            "Ground truth: the fixture's patched method must actually be unreadable, or this test is vacuous.");

        var seamException = Record.Exception(() => ScanMethodConstants.Invoke(null, [patchedLoop]));
        var obfuscationException = Record.Exception(() => ScanMethod.Invoke(null, ScanArguments(patchedLoop)));

        Assert.Null(seamException);
        Assert.Null(obfuscationException);

        var constants = (IEnumerable<AssemblyAnalyzer.StringConstant>)ScanMethodConstants.Invoke(null, [patchedLoop])!;
        var findings = (IEnumerable<ObfuscationFinding>)ScanMethod.Invoke(null, ScanArguments(patchedLoop))!;

        Assert.Empty(constants);
        Assert.Empty(findings);
    }

    // Across EVERY candidate method in the patched assembly (not just the one known-corrupted one), both
    // walks agree on "did this throw?" — the actual behaviour the duplication risks diverging on. If a
    // future edit made one walk start throwing (or silently swallowing) on some method the other still
    // handles, this fails without needing to know in advance which method exposed it.
    [Fact]
    public void SharedSeamAndObfuscationWalk_AgreeAcrossEveryCandidateMethod_NeitherThrowsNorLosesTheAssembly()
    {
        var candidates = fixture.Patched.Methods.ToArray();
        Assert.True(candidates.Length > 1, "Sanity: the fixture must expose more than just the corrupted method.");

        foreach (var method in candidates)
        {
            var name = AssemblyAnalyzer.SafeName(method);

            var seamException = Record.Exception(() => ScanMethodConstants.Invoke(null, [method]));
            Assert.True(seamException is null, $"Shared-seam walk threw for {name}: {seamException}");

            var obfuscationException = Record.Exception(() => ScanMethod.Invoke(null, ScanArguments(method)));
            Assert.True(obfuscationException is null, $"ObfuscationAnalysis walk threw for {name}: {obfuscationException}");
        }
    }

    // Both walks, run over the same corrupted method, warn — naming the SAME method. This is the
    // "same methods skipped" agreement from the outside: neither walk's warning path silently diverged
    // (e.g. warning for a different method, or not warning at all).
    [Fact]
    public void SharedSeamAndObfuscationWalk_BothWarnForTheSameUnreadableMethod()
    {
        using var capture = new WarningCapture();

        _ = fixture.Patched.StringConstants().ToList();
        var result = new ObfuscationAnalysis(fixture.Patched).Analyze();
        Assert.True(result.IsSuccess, result.Message);

        var loopWarnings = capture.Warnings
            .Where(m => m.Contains(UnreadableMethodBodyFixture.PatchedMethod, StringComparison.Ordinal))
            .ToList();

        Assert.True(loopWarnings.Count >= 2,
            $"Expected both the shared seam and ObfuscationAnalysis to warn about '{UnreadableMethodBodyFixture.PatchedMethod}'; " +
            $"captured {loopWarnings.Count}: {string.Join(" | ", loopWarnings)}");
    }
    #endregion

    #region Helpers
    private static IMethodDefinition Method(AssemblyAnalyzer assembly, string methodName) =>
        assembly.Module.GetAllTypes().SelectMany(t => t.Methods).Single(m =>
            m.Name.Value == methodName &&
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition).EndsWith(
                $".{UnreadableMethodBodyFixture.PatchedType}", StringComparison.Ordinal));

    // Reflects the private per-method entry point behind AssemblyAnalyzer.StringConstants().
    private static readonly MethodInfo ScanMethodConstants =
        typeof(AssemblyAnalyzer).GetMethod("ScanMethodConstants", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "AssemblyAnalyzer.ScanMethodConstants not found by reflection — the shared seam's shape changed; update this test.");

    // Reflects the private per-method entry point ObfuscationAnalysis deliberately keeps as its own copy
    // (see the class doc comment).
    private static readonly MethodInfo ScanMethod =
        typeof(ObfuscationAnalysis).GetMethod("ScanMethod", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "ObfuscationAnalysis.ScanMethod not found by reflection — its shape changed; update this test.");

    // ScanMethod(method, facts): a fresh private ModuleFacts per call, so one walk's records never leak into the next.
    private static readonly Type ModuleFacts =
        typeof(ObfuscationAnalysis).GetNestedType("ModuleFacts", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "ObfuscationAnalysis.ModuleFacts not found by reflection — its shape changed; update this test.");

    private static object[] ScanArguments(IMethodDefinition method) => [method, Activator.CreateInstance(ModuleFacts, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, [string.Empty], null)!];
    #endregion

    private readonly UnreadableMethodBodyFixture fixture;
}
