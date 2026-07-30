namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The regression for <c>docs/agent/tasks/per-method-body-read-granularity.md</c>: one unreadable method body must
/// cost <b>one method</b>, not the whole assembly. Before the fix, <c>AssemblyAnalyzer.Methods</c> dereferenced
/// <c>m.Body</c> from its own filter, so the throw happened during enumeration, outside every per-method guard, and
/// both consumers' outer catch discarded the entire assembly (<c>analyze</c> exited 1 with no report at all).
/// <para>
/// The hostile input is built at test time by <see cref="UnreadableMethodBodyFixture"/>: a byte-for-byte copy of the
/// fixture assembly with an out-of-range fat-header <c>CodeSize</c> on exactly one method.
/// </para>
/// </summary>
public sealed class UnreadableMethodBodyTests : IClassFixture<UnreadableMethodBodyFixture>
{
    public UnreadableMethodBodyTests(UnreadableMethodBodyFixture fixture) => this.fixture = fixture;

    // Acceptance criterion 1, part 1 — the headline: a report EXISTS. The pre-fix behaviour was a failure Result.
    [Fact]
    public void Analyze_WhenOneMethodBodyIsUnreadable_SucceedsWithExactlyOneSkippedMethod()
    {
        var result = new CapabilityAnalysis(fixture.Patched).Analyze();

        Assert.True(result.IsSuccess, $"The whole assembly was lost instead of one method: {result.Message}");

        var report = result.Value;
        Assert.Equal(1, report.MethodsSkipped);
        Assert.Equal(report.MethodsTotal - 1, report.MethodsAnalyzed);
        Assert.Single(report.SkippedMethods);
    }

    // Acceptance criterion 1, part 2 — the denominator did not move. An unreadable body is COUNTED and skipped, so
    // MethodsTotal must match the clean assembly exactly: if the corrupted method had silently dropped out of the
    // candidate set, the total would be 1 lower and "MethodsAnalyzed == MethodsTotal - 1" would still pass while
    // hiding the method entirely.
    [Fact]
    public void Analyze_WhenOneMethodBodyIsUnreadable_MethodsTotalMatchesTheCleanAssembly()
    {
        var clean = Analyze(fixture.Clean);
        var patched = Analyze(fixture.Patched);

        Assert.Equal(clean.MethodsTotal, patched.MethodsTotal);
        Assert.Equal(clean.MethodsAnalyzed - 1, patched.MethodsAnalyzed);
        Assert.Equal(0, clean.MethodsSkipped);
    }

    // Acceptance criterion 6 — the skip entry names the offender and carries the reason. The CCI exception message
    // is a localizable BCL string, so it is not pinned literally; instead it is cross-checked against what
    // TryReadBody reports for the very same method, which is a stronger statement than any hard-coded text: the
    // reason a reviewer reads is the actual read failure, not a generic placeholder.
    [Fact]
    public void Analyze_SkippedMethodEntry_NamesTheMethodAndCarriesTheReadFailure()
    {
        var entry = Assert.Single(Analyze(fixture.Patched).SkippedMethods);
        var error = AssemblyAnalyzer.TryReadBody(Method(fixture.Patched, UnreadableMethodBodyFixture.PatchedMethod)).Error;

        Assert.StartsWith($"{UnreadableMethodBodyFixture.PatchedQualifiedName}:", entry, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(error), "TryReadBody reported no error for the corrupted method.");
        Assert.Contains(error!, entry, StringComparison.Ordinal);
    }

    // Acceptance criterion 1, part 3 — every OTHER method's findings survive. Shapes.Loop contributes no capability
    // findings, so this is an exact sequence equality (order included) against the clean report, not a filtered
    // comparison: the pre-fix behaviour lost all of them.
    [Fact]
    public void Analyze_WhenOneMethodBodyIsUnreadable_RemainingFindingsAreIdenticalToTheCleanRun()
    {
        var clean = Analyze(fixture.Clean);
        var patched = Analyze(fixture.Patched);

        Assert.NotEmpty(clean.Findings);
        Assert.Equal(clean.Findings, patched.Findings);
    }

    // The second consumer, fixed in the same change and easy to forget: ObfuscationAnalysis reads bodies through the
    // same seam. Pre-fix, one unreadable body returned a failure Result and lost EVERY hidden-payload finding in the
    // assembly (visible since ADR 0024 only as the obfuscation caveat).
    [Fact]
    public void ObfuscationAnalyze_WhenOneMethodBodyIsUnreadable_SucceedsWithUnchangedFindings()
    {
        var clean = new ObfuscationAnalysis(fixture.Clean).Analyze();
        var patched = new ObfuscationAnalysis(fixture.Patched).Analyze();

        Assert.True(clean.IsSuccess, clean.Message);
        Assert.True(patched.IsSuccess, $"One unreadable body failed the whole obfuscation analysis: {patched.Message}");
        Assert.NotNull(patched.Value);

        Assert.NotEmpty(clean.Value.Findings);
        Assert.Equal(clean.Value.Findings, patched.Value.Findings);
    }

    #region Methods — TryReadBody's three-outcome contract
    // Outcome 1 of 3: a method with an IL body. Neither flag is set and Body is the readable body.
    [Fact]
    public void TryReadBody_OnMethodWithBody_ReturnsTheBodyAndNeitherFlag()
    {
        var read = AssemblyAnalyzer.TryReadBody(Method(fixture.Clean, UnreadableMethodBodyFixture.PatchedMethod));

        Assert.NotNull(read.Body);
        Assert.Null(read.Error);
        Assert.False(read.IsMissing);
        Assert.False(read.IsUnreadable);
    }

    // Outcome 2 of 3, both shapes: a method that HAS no body. Neither is a skip, and neither may count towards a
    // method total — that is the distinction the fix rests on, and getting it wrong would silently inflate
    // MethodsTotal against the pre-fix predicate.
    //   - an interface method is abstract;
    //   - a [DllImport] P/Invoke is external (declared here, never called — the body lives in native code).
    [Theory]
    [InlineData("Mark")]            // ICanonicalMarker.Mark — interface, therefore abstract
    [InlineData("ShowMessage")]     // NativeInteropOps.ShowMessage — [DllImport("user32.dll")]
    public void TryReadBody_OnMethodWithoutBody_IsMissingAndNotUnreadable(string methodName)
    {
        var method = AllMethods(fixture.Clean).First(m => m.Name.Value == methodName);

        var read = AssemblyAnalyzer.TryReadBody(method);

        Assert.True(read.IsMissing, $"'{methodName}' should have no body at all.");
        Assert.False(read.IsUnreadable);
        Assert.Null(read.Body);
        Assert.Null(read.Error);
    }

    // Guards the theory above against becoming vacuous: the two methods must really be the metadata shapes claimed,
    // otherwise "IsMissing" could be passing for an unrelated reason.
    [Fact]
    public void TryReadBody_BodylessCases_AreGenuinelyAbstractAndExternal()
    {
        Assert.True(AllMethods(fixture.Clean).First(m => m.Name.Value == "Mark").IsAbstract);
        Assert.True(AllMethods(fixture.Clean).First(m => m.Name.Value == "ShowMessage").IsExternal);
    }

    // Outcome 3 of 3: the read threw. Error carries the message, Body stays null, and IsMissing is explicitly NOT
    // set — an unreadable body must never be mistaken for a bodyless one, or the skip would vanish from the counts.
    [Fact]
    public void TryReadBody_OnUnreadableBody_IsUnreadableWithANonEmptyError()
    {
        var read = AssemblyAnalyzer.TryReadBody(Method(fixture.Patched, UnreadableMethodBodyFixture.PatchedMethod));

        Assert.True(read.IsUnreadable, "The corrupted body was read successfully; the fixture patch did not take.");
        Assert.False(read.IsMissing);
        Assert.Null(read.Body);
        Assert.False(string.IsNullOrWhiteSpace(read.Error));
    }

    // "Never throws" is the whole contract of the seam: if it threw, the exception would escape the consumer's
    // per-method guard through the very call that exists to contain it. Asserted over all three outcomes at once.
    [Fact]
    public void TryReadBody_NeverThrows_ForAnyOutcome()
    {
        IMethodDefinition[] methods =
        [
            Method(fixture.Clean, UnreadableMethodBodyFixture.PatchedMethod),
            AllMethods(fixture.Clean).First(m => m.Name.Value == "Mark"),
            AllMethods(fixture.Clean).First(m => m.Name.Value == "ShowMessage"),
            Method(fixture.Patched, UnreadableMethodBodyFixture.PatchedMethod),
        ];

        Assert.All(methods, method =>
            Assert.Null(Record.Exception(() => AssemblyAnalyzer.TryReadBody(method))));
    }
    #endregion

    #region Methods — helpers
    private static CapabilityReport Analyze(AssemblyAnalyzer assembly)
    {
        var result = new CapabilityAnalysis(assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private static IEnumerable<IMethodDefinition> AllMethods(AssemblyAnalyzer assembly) =>
        assembly.Module.GetAllTypes().SelectMany(type => type.Methods);

    // The single method definition with the given name declared on the fixture's patched type.
    private static IMethodDefinition Method(AssemblyAnalyzer assembly, string methodName) =>
        AllMethods(assembly).Single(m =>
            m.Name.Value == methodName &&
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition).EndsWith(
                $".{UnreadableMethodBodyFixture.PatchedType}", StringComparison.Ordinal));
    #endregion

    private readonly UnreadableMethodBodyFixture fixture;
}
