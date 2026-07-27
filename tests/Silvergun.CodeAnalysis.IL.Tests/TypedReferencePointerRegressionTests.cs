namespace Silvergun.CodeAnalysis.IL.Tests;

using System;

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
        // Neither fixture declaration calls a catalogued sensitive API, so the capability scan over this
        // assembly must be finding-free - pins that the pathological shapes are metadata-only fixtures with no
        // accidental capability noise of their own.
        Assert.Contains("CAPABILITY-ANALYSIS-OK 0", result.StandardOutput, StringComparison.Ordinal);
    }

    // Spawns the probe apphost, which the ProjectReference in this project's .csproj copies next to this test
    // assembly's own output (the same mechanism Silvergun.CLI.Tests uses for the CLI apphost).
    private static ProbeResult RunProbe() => ChildProcessProbe.Run(ProbeExe, Timeout);
    #endregion

    #region Fields
    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe");

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    #endregion
}
