namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Regression coverage for ADR-0021 / ADR-0022 Stage 0: <c>TypedReference</c> nested one level under
/// <c>Pointer</c> (<c>TypedReference*</c>) used to reach CCI's <c>SignatureConverter.GetTypeReference()</c>
/// recursive <c>default:</c> arm — <c>Debug.Fail("?!?")</c>, which on .NET routes to
/// <c>Environment.FailFast</c>: process exit 35, no managed exception, no <c>catch</c> anywhere runs. The Stage
/// 0 fix added <c>case ElementType.TypedReference</c> to that switch
/// (<c>ext/analysis-net/cci/PEReaderAndWriter/PEReader/PEFileToObjectModel.cs</c>), so the shape now renders as
/// <c>System.TypedReference*</c> instead of killing the process.
/// <para>
/// <b>This must run out of process.</b> A FailFast is uncatchable — <c>Assert.Throws</c>/<c>Record.Exception</c>
/// cannot see it, and calling the crashing path in-process would take the whole xUnit host down with it,
/// destroying every other test result in the run instead of failing just this one. Every fact here spawns
/// the <c>Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe</c> apphost (see
/// <see cref="PathologicalSignatureProbe.PathologicalShapes"/>) as a child via <see cref="ChildProcessProbe"/>
/// and asserts on its exit code and output — a regression here must show up as a clean, attributable assertion
/// failure, never as "the test run died".
/// </para>
/// </summary>
public sealed class TypedReferencePointerRegressionTests
{
    #region Methods
    /// <summary>
    /// The positive case (ADR-0022 assertion 1): the probe runs to completion — exit 0, <c>DONE</c> printed —
    /// rather than terminating abnormally. If the Stage 0 fix regresses, the process FailFasts partway through
    /// the <c>CciNames.Of</c> walk and this is the fact that catches it: exit code stops being 0 and
    /// <c>DONE</c> is never printed, because the process died before reaching it.
    /// </summary>
    [Fact]
    public void Probe_AnalyzingTypedReferencePointerFixture_ExitsCleanly()
    {
        var result = RunProbe();

        // Assert.True with an explicit message rather than Assert.Equal(0, ...): on a regression ExitCode is
        // an OS-assigned abnormal-termination code (35 on .NET), and the message must say so plainly rather
        // than read as an ordinary "expected 0, got 35" value mismatch.
        Assert.True(result.ExitedCleanly, $"Probe did not exit cleanly - {result.Describe()}");
        Assert.Contains("DONE", result.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>
    /// The rendering assertion (ADR-0022 assertion 1): the <c>TypedReference*</c> parameter must render as
    /// <c>System.TypedReference*</c> — proving the decoder read it correctly — and specifically must
    /// <b>not</b> render as <c>&lt;unknown&gt;*</c>, the old Release-mode degradation ADR-0021 documented for
    /// this exact shape (Debug builds FailFast; Release silently drops to <c>Dummy.TypeReference</c>). Either
    /// old behaviour is wrong; only the exact rendered type proves the fix, not just a clean exit.
    /// </summary>
    [Fact]
    public void Probe_TypedReferencePointerParameter_RendersAsSystemTypedReferencePointer()
    {
        var result = RunProbe();

        Assert.True(result.ExitedCleanly, $"Probe did not exit cleanly - {result.Describe()}");
        Assert.Contains("PARAM TypedReferencePointer 0 System.TypedReference*", result.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("<unknown>*", result.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>
    /// The negative control renders normally alongside the pathological shape, so a decoder-wide degradation
    /// (every parameter turning into <c>&lt;unknown&gt;</c>) cannot masquerade as "the TypedReference case
    /// works" by accident of both looking equally broken.
    /// </summary>
    [Fact]
    public void Probe_CleanControlParameter_RendersNormally()
    {
        var result = RunProbe();

        Assert.True(result.ExitedCleanly, $"Probe did not exit cleanly - {result.Describe()}");
        Assert.Contains("PARAM Clean 0 System.String", result.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>
    /// The product-entry-point assertion (ADR-0022 assertion 3): <see cref="AssemblyAnalyzer.Load"/> and
    /// <see cref="CapabilityAnalysis.Analyze"/> both succeed on the very assembly that carries the
    /// <c>TypedReference*</c> fixture, pinning ADR-0021 Tier 1's boundary — these are the entry points the
    /// sweep found were never affected by this class of defect, and this keeps that true rather than just
    /// assumed.
    /// </summary>
    [Fact]
    public void Probe_AssemblyAnalyzerLoadAndCapabilityAnalysis_StayClean()
    {
        var result = RunProbe();

        Assert.True(result.ExitedCleanly, $"Probe did not exit cleanly - {result.Describe()}");
        Assert.DoesNotContain("LOAD-FAILED", result.StandardOutput + result.StandardError, StringComparison.Ordinal);
        Assert.DoesNotContain("CAPABILITY-ANALYSIS-FAILED", result.StandardOutput + result.StandardError, StringComparison.Ordinal);
        Assert.Contains("CAPABILITY-ANALYSIS-OK", result.StandardOutput, StringComparison.Ordinal);
        // No fixture declaration calls a sensitive API, so the capability scan over this assembly must be
        // finding-free - pins that the pathological shapes are metadata-only fixtures with no accidental
        // capability noise of their own.
        Assert.Contains("CAPABILITY-ANALYSIS-OK 0", result.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>
    /// DEFENCE IN DEPTH, and scoped accordingly — read this before trusting it as ADR-0021 coverage.
    /// <see cref="PathologicalSignatureProbe.PathologicalShapes.CallsTypedReferencePointer"/> puts a
    /// <c>TypedReference*</c>-signatured method on the far side of a real <c>call</c> instruction, so a full
    /// <c>CapabilityAnalysis</c> scan of the probe assembly really does hand that callee to <c>Match</c>. What is
    /// asserted is exactly that: <b>the scan completes</b> over an assembly carrying the shape.
    /// <para>
    /// <b>It does NOT discriminate the ADR-0021 key composition.</b> ADR-0022 Stage 0 added
    /// <c>case ElementType.TypedReference</c> to CCI's <c>GetTypeReference()</c> switch
    /// (<c>ext/analysis-net/cci/PEReaderAndWriter/PEReader/PEFileToObjectModel.cs</c>), so this shape no longer
    /// reaches the <c>Debug.Fail</c> default at all — the phase-2 review gate confirmed by measurement that running
    /// the <em>forbidden</em> composition (<c>CanonicalName.ClassificationKey(CciNames.Of(callee))</c>) over this
    /// same probe prints every key and exits 0. This test therefore passes identically whether <c>Match</c> keys on
    /// the containing type or on the method reference. The guard that does tell those apart is
    /// <see cref="CapabilityKeyCompositionArchitectureTests"/>, which reads the composition out of our own compiled
    /// IL; this one pins the layer beneath it — that the Stage 0 decoder fix holds at the scanner, so an assembly
    /// carrying the shape is scannable at all.
    /// </para>
    /// <para>
    /// <b>Still asserted as an exit code, not as an exception, and that is not a stylistic choice.</b> Should the
    /// Stage 0 fix regress, the failure mode is <c>Debug.Fail</c> → <c>Environment.FailFast</c>: no managed
    /// exception, no <c>catch</c>, no <c>finally</c>. <c>Assert.Throws</c>/<c>Record.Exception</c> can never see it,
    /// and running the path in-process would kill the xUnit host and every other result in the run. For that failure
    /// the child's exit code is the only observable.
    /// </para>
    /// </summary>
    [Fact]
    public void Probe_ScanningACalleeWithATypedReferenceSignature_CompletesWithoutAFailFast()
    {
        var result = RunProbe();

        Assert.True(result.ExitedCleanly, $"Probe did not exit cleanly - {result.Describe()}");

        // The scan reached its end rather than dying part-way: both markers, and in this order.
        Assert.Contains("CAPABILITY-ANALYSIS-OK", result.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("DONE", result.StandardOutput, StringComparison.Ordinal);

        // Non-vacuity, half one: the pathological signature really is in this assembly. Without it the clean
        // exit could just mean the shape was never compiled.
        Assert.Contains("PARAM TypedReferencePointer 0 System.TypedReference*", result.StandardOutput, StringComparison.Ordinal);

        // Non-vacuity, half two: and it really is on the far side of a CALL, so the scan's operation walk hands
        // that reference to Match. Read the same way Match reads it — callee name and containing type only,
        // never Parameters — so this check cannot itself trip the defect it exists to guard.
        Assert.Contains(nameof(PathologicalSignatureProbe.PathologicalShapes.TypedReferencePointer), CalleeNamesOfTheCallingShape());
    }

    // The callee names of PathologicalShapes.CallsTypedReferencePointer, read in-process from the probe assembly
    // that sits next to this test assembly. Safe in-process precisely because it reads no parameter list.
    private static string[] CalleeNamesOfTheCallingShape()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        var create = AssemblyAnalyzer.Load(ProbeAssembly);
        Assert.True(create.IsSuccess, create.Message);
        using var cci = create.Value;

        var method = Assert.Single(
            cci.Methods,
            m => m.Name.Value == nameof(PathologicalSignatureProbe.PathologicalShapes.CallsTypedReferencePointer));

        var body = AssemblyAnalyzer.TryReadBody(method).Body;
        Assert.NotNull(body);

        return [.. body!.Operations.Select(op => op.Value).OfType<IMethodReference>().Select(m => m.Name.Value)];
    }

    // Spawns the probe apphost, which the ProjectReference in this project's .csproj copies next to this test
    // assembly's own output (the same mechanism Silvergun.CLI.Tests uses for the CLI apphost).
    private static ProbeResult RunProbe() => ChildProcessProbe.Run(ProbeExe, Timeout);
    #endregion

    #region Fields
    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe");

    /// <summary>The probe's managed assembly, copied next to this one by the ProjectReference.</summary>
    private static readonly string ProbeAssembly =
        typeof(PathologicalSignatureProbe.PathologicalShapes).Assembly.Location;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    #endregion
}
