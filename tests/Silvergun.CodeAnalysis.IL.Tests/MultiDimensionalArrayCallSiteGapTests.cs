namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// KNOWN GAP, pinned deliberately: <b>multi-dimensional array accessors are invisible to the scan</b>.
/// <para>
/// <c>T[,]::Get</c>, <c>::Set</c>, <c>::Address</c> and <c>::.ctor</c> are real runtime-provided methods and the
/// compiler emits real <c>call</c>/<c>newobj</c> instructions for them, but CCI rewrites those instructions into
/// its synthetic <c>Array_Get</c>/<c>Array_Set</c>/<c>Array_Addr</c>/<c>Array_Create</c> opcodes and sets
/// <see cref="IOperation.Value"/> to the <em>array type</em> rather than to an <see cref="IMethodReference"/>
/// (<c>ext/analysis-net/cci/PEReaderAndWriter/PEReader/ILReader.cs:765-786</c> for <c>call</c> and
/// <c>:921-929</c> for <c>newobj</c>). Every call-site predicate we ship — <c>CapabilityAnalysis.Callee</c> and
/// the parity fixture's <c>IsCallSite</c> — therefore never matches them, so they contribute no call site and no
/// finding.
/// </para>
/// <para>
/// Measured: <b>53 such call sites in a 324,168-call-site corpus</b> (0.016 %), and <b>0</b> call-shaped CCI
/// operations in that whole corpus had a non-<see cref="IMethodReference"/> operand — CCI does not hand these
/// back as calls at all. See <c>docs/agent/measurements/ilspy-provider-spike.md</c> §1.4 category 9 and §1.10
/// item 1.
/// </para>
/// <para>
/// <b>These assertions are NOT desired behaviour.</b> They document a blind spot so it is not rediscovered as a
/// surprise. It is a <em>capability</em> blind spot only if a security-relevant API is ever reached through a
/// multi-dimensional array accessor — nothing in <see cref="CapabilityAnalysis.Catalog"/> or in
/// <c>capabilities.cm</c> is declared on an array type today, so the practical exposure is believed to be nil —
/// but that is unproven, not measured. If the gap is ever closed (by matching the synthetic opcodes and
/// recovering the accessor's method reference), the fix belongs in <c>src/</c> and these tests must be rewritten
/// to assert the new, better behaviour — <b>not</b> loosened to keep passing.
/// </para>
/// <para>
/// <b>⚠ The converse is the dangerous direction, and it is pinned in
/// <see cref="LatentFalsePositive_AnArrayOfACataloguedElementType_WouldPrefixMatchTheCatalog"/>.</b> An array of
/// a <em>catalogued</em> element type renders as <c>System.Diagnostics.Process[,]</c>, which
/// <b>does</b> prefix-match the catalog. Closing the gap without excluding array declaring types would not
/// merely recover missed capabilities — it would <em>manufacture</em> false ones out of ordinary element reads.
/// Read those two tests before changing the reader.
/// </para>
/// </summary>
public sealed class MultiDimensionalArrayCallSiteGapTests : IClassFixture<AssemblyAnalyzerFixture>
{
    #region Constructors
    public MultiDimensionalArrayCallSiteGapTests(AssemblyAnalyzerFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// Vacuity guard, and the precondition of everything below: the fixture method really does contain all four
    /// accessor shapes, so "no call sites for them" is a statement about something that is actually present. If
    /// a future compiler stops emitting one of these (e.g. optimizing <c>Address</c> away), this fails loudly
    /// instead of letting the gap tests pass on an empty set.
    /// </summary>
    [Theory]
    [InlineData(nameof(MultiDimArrayOps.CopiesMatrixCellsAndReadsAFile))]
    [InlineData(nameof(MultiDimArrayOps.CopiesProcessMatrixCellsAndStartsOne))]
    public void Fixture_EmitsAllFourMultiDimensionalArrayAccessorShapes(string method)
    {
        var codes = OperationsOf(method).Select(op => op.OperationCode).ToArray();

        Assert.Contains(OperationCode.Array_Create, codes);
        Assert.Contains(OperationCode.Array_Get, codes);
        Assert.Contains(OperationCode.Array_Set, codes);
        Assert.Contains(OperationCode.Array_Addr, codes);
    }

    /// <summary>
    /// KNOWN GAP — the root cause, asserted directly: each synthetic accessor operation carries the
    /// <see cref="IArrayTypeReference"/> and <b>no</b> <see cref="IMethodReference"/>, so there is nothing for a
    /// call-site predicate to match and nothing to name. The array type is the rank-2 <c>System.Int32[,]</c>.
    /// </summary>
    [Fact]
    public void KnownGap_ArrayAccessorOperations_CarryTheArrayTypeInsteadOfAMethodReference()
    {
        var accessors = OperationsOf(nameof(MultiDimArrayOps.CopiesMatrixCellsAndReadsAFile))
            .Where(op => IsArrayAccessor(op.OperationCode))
            .ToArray();

        // Six, re-derivable from the fixture source rather than taken on trust: one .ctor (`new int[2,2]`),
        // three Get (the right-hand side of the copy, the `+ 1` read, and the read in the return expression),
        // one Set (the copy's left-hand side) and one Address (the ref local).
        Assert.Equal(6, accessors.Length);
        Assert.Equal(1, accessors.Count(op => op.OperationCode == OperationCode.Array_Create));
        Assert.Equal(3, accessors.Count(op => op.OperationCode == OperationCode.Array_Get));
        Assert.Equal(1, accessors.Count(op => op.OperationCode == OperationCode.Array_Set));
        Assert.Equal(1, accessors.Count(op => op.OperationCode == OperationCode.Array_Addr));

        Assert.All(accessors, op =>
        {
            var array = Assert.IsAssignableFrom<IArrayTypeReference>(op.Value);

            Assert.IsNotAssignableFrom<IMethodReference>(op.Value);
            Assert.False(array.IsVector);
            Assert.Equal(2u, array.Rank);
            Assert.Equal("System.Int32[,]", AssemblyAnalyzer.TypeName(array));
        });
    }

    /// <summary>
    /// KNOWN GAP — the consequence. Eight call-shaped IL instructions are written in the fixture method (six
    /// array accessors — see the counts in the test above — plus two ordinary calls), and the scan records
    /// exactly the <b>two ordinary ones</b>. The two survivors are the positive control: the method is
    /// demonstrably being read, so the six missing accessors are a gap and not an unscanned body.
    /// </summary>
    [Fact]
    public void KnownGap_MultiDimensionalArrayAccessors_YieldNoCallSites_WhileOrdinaryCallsInTheSameBodyDo()
    {
        var callSites = OperationsOf(nameof(MultiDimArrayOps.CopiesMatrixCellsAndReadsAFile))
            .Where(op => IsCallSite(op.OperationCode) && op.Value is IMethodReference)
            .Select(op => CalledApi((IMethodReference)op.Value!))
            .OrderBy(api => api, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[] { "System.IO.File.ReadAllText", "System.String.get_Length" }, callSites);
        Assert.DoesNotContain(callSites, api => api.Contains("[,]", StringComparison.Ordinal));
    }

    /// <summary>
    /// KNOWN GAP — restated at the seam that ships: <see cref="CapabilityAnalysis"/> attributes exactly one
    /// finding to the fixture method (the control call), and no finding anywhere in the assembly names a
    /// multi-dimensional array accessor. The single finding is what stops this passing vacuously.
    /// </summary>
    [Fact]
    public void KnownGap_CapabilityAnalysis_FindsOnlyTheControlCall_InTheMultiDimensionalArrayMethod()
    {
        var result = new CapabilityAnalysis(fixture.Assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        var report = result.Value;

        var finding = Assert.Single(
            report.Findings,
            f => f.CallerMethod == nameof(MultiDimArrayOps.CopiesMatrixCellsAndReadsAFile));

        Assert.Equal(Capability.FileSystem, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("System.IO.File.ReadAllText", finding.CalledApi);
        Assert.Equal(DeclaringType, finding.CallerType);

        // Assembly-wide: no finding is carried by an array accessor, under any of its four names.
        Assert.DoesNotContain(report.Findings, f => f.CalledApi.Contains("[,]", StringComparison.Ordinal));
        Assert.DoesNotContain(
            report.Findings,
            f => AccessorNames.Any(name => f.CalledApi.EndsWith("]." + name, StringComparison.Ordinal)));
    }

    /// <summary>
    /// The corpus-wide counter from the measurement, reproduced in miniature: across <em>every</em> readable body
    /// in the fixture assembly, no call-shaped operation has a non-<see cref="IMethodReference"/> operand. That is
    /// what makes the gap structural rather than a matching bug — there is no operand to recover through the
    /// call-site seam, so closing the gap means matching the synthetic opcodes, not fixing a cast.
    /// </summary>
    [Fact]
    public void CallShapedOperations_InTheWholeFixtureAssembly_AlwaysCarryAMethodReference()
    {
        var callShaped = 0;
        var withoutMethodReference = new List<string>();

        foreach (var method in fixture.Assembly.Methods)
        {
            if (AssemblyAnalyzer.TryReadBody(method) is not { Body: { } body })
                continue;

            foreach (var operation in body.Operations.Where(op => IsCallSite(op.OperationCode)))
            {
                callShaped++;
                if (operation.Value is not IMethodReference)
                    withoutMethodReference.Add($"{AssemblyAnalyzer.SafeName(method)}: {operation.OperationCode}");
            }
        }

        Assert.True(callShaped > 50, $"Only {callShaped} call-shaped operations — too few to be meaningful.");
        Assert.Empty(withoutMethodReference);
    }

    /// <summary>
    /// THE LATENT FALSE POSITIVE, named so it cannot be missed — <b>the converse of the gap above, and the real
    /// hazard</b>. An array whose <em>element type is catalogued</em> renders as
    /// <c>System.Diagnostics.Process[,]</c>, and
    /// <c>"System.Diagnostics.Process[,]".StartsWith("System.Diagnostics.Process")</c> is <b>true</b> — the exact
    /// prefix <see cref="CapabilityAnalysis.Catalog"/> carries for <see cref="Capability.ProcessExecution"/>. So
    /// a bare array-element read <em>would</em> be reported as process execution the moment these accessors
    /// became visible as call sites. Both facts are asserted here: the rendering, and that it prefix-matches.
    /// <para>
    /// <b>The only thing preventing that false positive today is incidental</b> — CCI never emits these call
    /// sites at all, because it rewrites them to the synthetic <c>Array_*</c> opcodes documented on this class.
    /// It is not a check, not a filter, and nothing in <c>src/</c> would stop it. Measured at 0 occurrences over
    /// 75 <c>T[,]</c> accessor call sites in 16 assemblies
    /// (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.2.3), which is why it has never bitten.
    /// </para>
    /// <para>
    /// <b>Anyone changing the reader must read this.</b> A reader that recovers these accessors — the ILSpy
    /// provider of the spike does, seeing 75 call sites CCI does not — has to exclude array declaring types
    /// <em>explicitly</em>. Inheriting the coverage silently turns a matrix of <see cref="System.Diagnostics.Process"/>
    /// into a <see cref="Capability.ProcessExecution"/> finding.
    /// </para>
    /// </summary>
    [Fact]
    public void LatentFalsePositive_AnArrayOfACataloguedElementType_WouldPrefixMatchTheCatalog()
    {
        var accessors = OperationsOf(nameof(MultiDimArrayOps.CopiesProcessMatrixCellsAndStartsOne))
            .Where(op => IsArrayAccessor(op.OperationCode))
            .ToArray();

        // Five, re-derivable from the fixture source: one .ctor (`new Process[2,2]`), two Get (the copy's
        // right-hand side and the read in the return expression), one Set (the copy's left-hand side) and one
        // Address (the ref local).
        Assert.Equal(5, accessors.Length);
        Assert.All(accessors, op =>
        {
            var array = Assert.IsAssignableFrom<IArrayTypeReference>(op.Value);

            Assert.IsNotAssignableFrom<IMethodReference>(op.Value);
            Assert.Equal(2u, array.Rank);
            Assert.Equal(ProcessMatrix, AssemblyAnalyzer.TypeName(array));
        });

        // The hazard, stated as an assertion rather than a comment: the array type name DOES satisfy the
        // catalog's ProcessExecution prefix. If this ever stops being true the comment above is stale.
        var matching = CapabilityAnalysis.Catalog
            .Where(api => ProcessMatrix.StartsWith(api.TypePrefix, StringComparison.Ordinal))
            .ToArray();

        Assert.Contains(matching, api => api.Capability == Capability.ProcessExecution);
    }

    /// <summary>
    /// THE LATENT FALSE POSITIVE, at the shipping seam: despite the prefix matching, the scan produces
    /// <b>exactly one</b> finding for the method — the real <see cref="System.Diagnostics.Process.Start(string)"/>
    /// call, which is the positive control — and none of the five <c>System.Diagnostics.Process[,]</c> accessors
    /// contributes anything. Assembly-wide, no finding is carried by an array type at all.
    /// </summary>
    [Fact]
    public void LatentFalsePositive_ProcessMatrixAccessors_ProduceNoFinding_WhileTheControlCallDoes()
    {
        var result = new CapabilityAnalysis(fixture.Assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        var report = result.Value;

        var finding = Assert.Single(
            report.Findings,
            f => f.CallerMethod == nameof(MultiDimArrayOps.CopiesProcessMatrixCellsAndStartsOne));

        Assert.Equal(Capability.ProcessExecution, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("System.Diagnostics.Process.Start", finding.CalledApi);
        Assert.Equal(DeclaringType, finding.CallerType);

        Assert.DoesNotContain(report.Findings, f => f.CalledApi.StartsWith(ProcessMatrix, StringComparison.Ordinal));
    }

    // The method under test, located by name so nothing here depends on load order.
    private IReadOnlyList<IOperation> OperationsOf(string methodName)
    {
        var method = Assert.Single(
            fixture.Assembly.Methods,
            m => m.Name.Value == methodName &&
                 AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition) == DeclaringType);

        var read = AssemblyAnalyzer.TryReadBody(method);
        Assert.NotNull(read.Body);

        return read.Body!.Operations.ToArray();
    }

    // CCI's four synthetic rewrites of a multi-dimensional array accessor. Array_Create_WithLowerBound is
    // included for completeness: C# cannot express a non-zero lower bound, so the fixture cannot emit it.
    private static bool IsArrayAccessor(OperationCode code) =>
        code is OperationCode.Array_Get or OperationCode.Array_Set or OperationCode.Array_Addr
             or OperationCode.Array_Create or OperationCode.Array_Create_WithLowerBound;

    // Verbatim the predicate the shipping scan uses (CapabilityAnalysis.Callee) — this test is only meaningful
    // if it asks the same question the analysis asks.
    private static bool IsCallSite(OperationCode code) =>
        code is OperationCode.Call or OperationCode.Callvirt or OperationCode.Newobj
             or OperationCode.Ldftn or OperationCode.Ldvirtftn;

    private static string CalledApi(IMethodReference callee) =>
        $"{AssemblyAnalyzer.TypeName(callee.ContainingType)}.{callee.Name.Value}";
    #endregion

    #region Fields
    private const string DeclaringType = "Silvergun.CodeAnalysis.IL.Tests.Fixture.MultiDimArrayOps";

    // The rendering of a rank-2 array of a CATALOGUED element type — the latent false positive of §2.2.3.
    private const string ProcessMatrix = "System.Diagnostics.Process[,]";

    private static readonly string[] AccessorNames = ["Get", "Set", "Address", ".ctor"];

    private readonly AssemblyAnalyzerFixture fixture;
    #endregion
}
