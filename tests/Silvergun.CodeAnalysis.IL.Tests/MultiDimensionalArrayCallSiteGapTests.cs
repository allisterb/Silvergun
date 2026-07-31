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
    [Fact]
    public void Fixture_EmitsAllFourMultiDimensionalArrayAccessorShapes()
    {
        var codes = Operations.Select(op => op.OperationCode).ToArray();

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
        var accessors = Operations.Where(op => IsArrayAccessor(op.OperationCode)).ToArray();

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
        var callSites = Operations
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

    // The method under test, located by name so nothing here depends on load order.
    private IReadOnlyList<IOperation> Operations
    {
        get
        {
            var method = Assert.Single(
                fixture.Assembly.Methods,
                m => m.Name.Value == nameof(MultiDimArrayOps.CopiesMatrixCellsAndReadsAFile) &&
                     AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition) == DeclaringType);

            var read = AssemblyAnalyzer.TryReadBody(method);
            Assert.NotNull(read.Body);

            return read.Body!.Operations.ToArray();
        }
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

    private static readonly string[] AccessorNames = ["Get", "Set", "Address", ".ctor"];

    private readonly AssemblyAnalyzerFixture fixture;
    #endregion
}
