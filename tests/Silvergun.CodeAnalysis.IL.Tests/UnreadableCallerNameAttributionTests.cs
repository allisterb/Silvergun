namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Pins how <see cref="CapabilityAnalysis"/> degrades when a <b>caller's</b> <c>MethodDef.Name</c> cannot be
/// read (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.2.2 / §2.10 item 4). The spike's
/// <c>05-badname</c> input is the only place in three phases where the shipping CCI path produced a different
/// answer from the ILSpy prototype, and it produced the <em>better</em> one:
/// <code>
/// CCI  : 05-badname  FileSystem  Call  BigNames.Padding      (empty)        System.IO.File.ReadAllText
/// ILSPY: 05-badname  FileSystem  Call  &lt;unreadable-type&gt;     &lt;unreadable&gt;   System.IO.File.ReadAllText
/// </code>
/// The capability, the kind and the called API are all preserved; the declaring type is recovered; <b>only the
/// method-name field degrades</b>, to the empty string. That is what these tests pin.
/// <para>
/// <b>The empty method name is not desired behaviour</b> — it is the documented outcome. Attribution to
/// "some method of <c>SensitiveOps</c>" is materially worse than a name, and a future improvement that renders
/// it as <c>AssemblyAnalyzer.SafeName</c>'s <c>&lt;unreadable&gt;</c> marker, or surfaces it as opacity per
/// ADR-0024, would be a genuine improvement. If that happens the fix belongs in <c>src/</c> and these
/// assertions must be <em>rewritten to the new value</em> — never loosened, and never dropped, because the
/// property that must not regress is that <b>the finding still exists and still names its declaring type</b>.
/// </para>
/// </summary>
public sealed class UnreadableCallerNameAttributionTests : IClassFixture<UnreadableMethodNameFixture>
{
    #region Constructors
    public UnreadableCallerNameAttributionTests(UnreadableMethodNameFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// The precondition, asserted rather than assumed: the crafted copy really does have exactly one method
    /// whose name reads as empty, it is the intended one, and the clean assembly has none. Without this every
    /// assertion below could pass against an unpatched copy.
    /// </summary>
    [Fact]
    public void PatchedFixture_HasExactlyOneMethodWhoseNameCannotBeRead()
    {
        Assert.Empty(EmptyNamedMethods(fixture.Clean));

        var degraded = Assert.Single(EmptyNamedMethods(fixture.Patched));

        Assert.Equal(UnreadableMethodNameFixture.PatchedTypeFullName, AssemblyAnalyzer.TypeName(degraded.ContainingTypeDefinition));
        Assert.Equal(string.Empty, AssemblyAnalyzer.SafeName(degraded));
    }

    /// <summary>
    /// THE BEHAVIOUR: detection is preserved. Both findings the method carries are still produced, still
    /// classified <see cref="Capability.FileSystem"/>, still <see cref="ApiCallKind.Call"/>, and still name the
    /// API called — attributed to the <em>declaring type</em>, which CCI reads from the <c>TypeDef</c> row and
    /// which the corruption never touched.
    /// </summary>
    [Theory]
    [InlineData("System.IO.Directory.Exists")]
    [InlineData("System.IO.File.ReadAllText")]
    public void Analyze_WhenTheCallersNameIsUnreadable_StillAttributesTheFindingToItsDeclaringType(string calledApi)
    {
        var finding = Assert.Single(
            fixture.PatchedReport.Findings,
            f => f.CalledApi == calledApi && f.CallerType == UnreadableMethodNameFixture.PatchedTypeFullName);

        Assert.Equal(Capability.FileSystem, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);

        // THE DOCUMENTED DEGRADATION — the one field that is lost, and the only one.
        Assert.Equal(string.Empty, finding.CallerMethod);
    }

    /// <summary>
    /// Stated as an exact before/after rather than as two independent claims: renaming the patched method back
    /// to its real name in the clean report's findings reproduces the patched report's findings <b>exactly</b>,
    /// as a set. So nothing was gained, nothing was lost, and nothing was reclassified — the whole difference is
    /// the one string field. The two findings that actually move are asserted first, so this cannot pass because
    /// the reports happened to be identical.
    /// </summary>
    [Fact]
    public void Analyze_WhenTheCallersNameIsUnreadable_LosesNothingButTheMethodNameField()
    {
        var moved = fixture.CleanReport.Findings
            .Count(f => f.CallerMethod == UnreadableMethodNameFixture.PatchedMethod);

        Assert.Equal(2, moved);

        var expected = fixture.CleanReport.Findings
            .Select(f => Render(f.CallerMethod == UnreadableMethodNameFixture.PatchedMethod &&
                               f.CallerType == UnreadableMethodNameFixture.PatchedTypeFullName
                ? f with { CallerMethod = string.Empty }
                : f))
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToArray();

        var actual = fixture.PatchedReport.Findings
            .Select(Render)
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// The degradation costs no <em>coverage</em> either: the method is still analyzed, not skipped, and the
    /// method bookkeeping is byte-identical to the clean assembly's. An unreadable name must never look like an
    /// unreadable body — ADR-0024's "could not analyze" must not be claimed where analysis did in fact happen,
    /// and equally must not be silently omitted where it did not.
    /// </summary>
    [Fact]
    public void Analyze_WhenTheCallersNameIsUnreadable_SkipsNothingAndKeepsTheSameMethodCounts()
    {
        Assert.Equal(fixture.CleanReport.MethodsTotal, fixture.PatchedReport.MethodsTotal);
        Assert.Equal(fixture.CleanReport.MethodsAnalyzed, fixture.PatchedReport.MethodsAnalyzed);
        Assert.Equal(0, fixture.PatchedReport.MethodsSkipped);
        Assert.Empty(fixture.PatchedReport.SkippedMethods);
    }

    /// <summary>
    /// The degraded name does not leak past its own method: every <em>other</em> finding in the assembly still
    /// carries a non-empty caller method name. A corruption that quietly blanked more than one caller would
    /// otherwise satisfy the assertions above.
    /// </summary>
    [Fact]
    public void Analyze_WhenTheCallersNameIsUnreadable_LeavesEveryOtherCallerNamed()
    {
        var blank = fixture.PatchedReport.Findings
            .Where(f => string.IsNullOrEmpty(f.CallerMethod))
            .ToArray();

        Assert.Equal(2, blank.Length);
        Assert.All(blank, f => Assert.Equal(UnreadableMethodNameFixture.PatchedTypeFullName, f.CallerType));
    }
    #endregion

    #region Methods (helpers)
    private static IMethodDefinition[] EmptyNamedMethods(AssemblyAnalyzer assembly) =>
        assembly.Methods.Where(m => AssemblyAnalyzer.SafeName(m).Length == 0).ToArray();

    // The capmap row shape the spike diffed on, minus the assembly column.
    private static string Render(ApiCallFinding finding) =>
        $"{finding.Capability}\t{finding.Kind}\t{finding.CallerType}\t{finding.CallerMethod}\t{finding.CalledApi}";
    #endregion

    #region Fields
    private readonly UnreadableMethodNameFixture fixture;
    #endregion
}
