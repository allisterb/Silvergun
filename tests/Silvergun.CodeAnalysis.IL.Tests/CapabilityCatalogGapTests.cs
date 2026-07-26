namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Capability-catalog gap closure (handoff item B): reflection invocation, dynamic codegen, unsafe
/// load/activation, and <c>[DllImport]</c> P/Invoke detection. Most techniques are exercised from the shared
/// netstandard2.0 fixture (<see cref="ReflectionInvocationOps"/>, <see cref="DynamicCodeOps"/>,
/// <see cref="NativeInteropOps"/>). The two techniques absent from the netstandard2.0 surface —
/// <c>System.Reflection.Emit.*</c> and <c>Activator.CreateInstanceFrom</c> — are exercised from
/// <see cref="Net10OnlyGapOps"/> in the net10.0 test assembly, loaded via the self-load pattern.
/// </summary>
public sealed class CapabilityCatalogGapTests : IClassFixture<AssemblyAnalyzerFixture>
{
    #region Constructors
    public CapabilityCatalogGapTests(AssemblyAnalyzerFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // 1a — MethodInfo/MethodBase.Invoke surfaces exactly one ReflectionInvocation Call finding. The
    // Invoke(object, object[]) overload is declared on MethodBase, so that is the CalledApi type.
    [Fact]
    public void Analyze_MethodInfoInvoke_SurfacesSingleReflectionInvocationCall()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.CallerType.EndsWith(nameof(ReflectionInvocationOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(ReflectionInvocationOps.InvokesViaMethodInfo));

        Assert.Equal(Capability.ReflectionInvocation, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.EndsWith(".Invoke", finding.CalledApi, StringComparison.Ordinal);
    }

    // 1b — Delegate.DynamicInvoke surfaces exactly one ReflectionInvocation Call finding.
    [Fact]
    public void Analyze_DelegateDynamicInvoke_SurfacesSingleReflectionInvocationCall()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.CallerType.EndsWith(nameof(ReflectionInvocationOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(ReflectionInvocationOps.InvokesViaDelegate));

        Assert.Equal(Capability.ReflectionInvocation, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("System.Delegate.DynamicInvoke", finding.CalledApi);
    }

    // 2a — Expression<TDelegate>.Compile surfaces a DynamicCodeLoading Call finding. The callee type is the
    // generic Expression instance, which still starts with the catalog's "System.Linq.Expressions.Expression"
    // prefix; the expression-tree builder calls (Constant/Lambda) do NOT match (method name isn't "Compile").
    [Fact]
    public void Analyze_ExpressionCompile_SurfacesSingleDynamicCodeLoadingCall()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.CallerType.EndsWith(nameof(DynamicCodeOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(DynamicCodeOps.CompilesExpression));

        Assert.Equal(Capability.DynamicCodeLoading, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.StartsWith("System.Linq.Expressions.Expression", finding.CalledApi, StringComparison.Ordinal);
        Assert.EndsWith(".Compile", finding.CalledApi, StringComparison.Ordinal);
    }

    // 2b — Assembly.UnsafeLoadFrom surfaces exactly one DynamicCodeLoading Call finding.
    [Fact]
    public void Analyze_AssemblyUnsafeLoadFrom_SurfacesSingleDynamicCodeLoadingCall()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.CallerType.EndsWith(nameof(DynamicCodeOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(DynamicCodeOps.UnsafeLoads));

        Assert.Equal(Capability.DynamicCodeLoading, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("System.Reflection.Assembly.UnsafeLoadFrom", finding.CalledApi);
    }

    // 2c — System.Reflection.Emit.* (DynamicMethod/ILGenerator) surfaces DynamicCodeLoading findings. Exercised
    // from the net10.0 test assembly (Emit types are outside the netstandard2.0 fixture surface). The newobj of
    // DynamicMethod is a Construct finding whose CalledApi is the Emit-prefixed .ctor.
    [Fact]
    public void Analyze_ReflectionEmit_SurfacesDynamicCodeLoadingConstruct()
    {
        var findings = AnalyzeSelf();

        Assert.Contains(findings, f =>
            f.Capability == Capability.DynamicCodeLoading &&
            f.Kind == ApiCallKind.Construct &&
            f.CallerMethod == nameof(Net10OnlyGapOps.EmitsDynamicMethod) &&
            f.CalledApi.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal) &&
            f.CalledApi.EndsWith(".ctor", StringComparison.Ordinal));
    }

    // 2d — Activator.CreateInstanceFrom surfaces a DynamicCodeLoading Call finding (net10.0 test assembly).
    [Fact]
    public void Analyze_ActivatorCreateInstanceFrom_SurfacesDynamicCodeLoadingCall()
    {
        var findings = AnalyzeSelf();

        var finding = Assert.Single(findings, f =>
            f.CallerType.EndsWith(nameof(Net10OnlyGapOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(Net10OnlyGapOps.ActivatesFromFile));

        Assert.Equal(Capability.DynamicCodeLoading, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("System.Activator.CreateInstanceFrom", finding.CalledApi);
    }

    // 3 — the [DllImport] attribute seam. ShowMessage is a bodyless P/Invoke extern that is NEVER called
    // anywhere in the assembly, so it can only be detected through metadata (pinvokeimpl), not a call site.
    // It must surface as exactly one NativeImport / NativeInterop finding with CalledApi == "module!entryPoint".
    [Fact]
    public void Analyze_DllImportExternWithNoCallSite_SurfacesSingleNativeImportFinding()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.CallerType.EndsWith(nameof(NativeInteropOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(NativeInteropOps.ShowMessage));

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(ApiCallKind.NativeImport, finding.Kind);
        Assert.Equal("user32.dll!MessageBoxW", finding.CalledApi);
    }

    // 3b — a second P/Invoke declaration, proving the scan enumerates every pinvokeimpl declaration and formats
    // "module!entryPoint" from PlatformInvokeData (entry point taken from the DllImport EntryPoint, not the
    // managed method name CurrentProcessId).
    [Fact]
    public void Analyze_SecondDllImportExtern_SurfacesNativeImportWithEntryPointName()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.CallerType.EndsWith(nameof(NativeInteropOps), StringComparison.Ordinal) &&
            f.CallerMethod == nameof(NativeInteropOps.CurrentProcessId));

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(ApiCallKind.NativeImport, finding.Kind);
        Assert.Equal("kernel32.dll!GetCurrentProcessId", finding.CalledApi);
    }

    // 3c — detection is not call-site dependent: the P/Invoke externs are never invoked, so there is NO Call/
    // Construct/MethodPointerLoad finding referencing the native entry points — only the NativeImport seam.
    [Fact]
    public void Analyze_NativeImports_HaveNoCallSiteKindFindings()
    {
        var report = Analyze();

        Assert.DoesNotContain(report.Findings, f =>
            f.Kind != ApiCallKind.NativeImport &&
            (f.CalledApi.Contains("MessageBoxW", StringComparison.Ordinal) ||
             f.CalledApi.Contains("GetCurrentProcessId", StringComparison.Ordinal)));
    }

    // 3d — the P/Invoke externs are bodyless, so they are excluded from method-count bookkeeping (never in
    // AssemblyAnalyzer.Methods) and cannot be double-counted or skipped. Coverage stays complete.
    [Fact]
    public void Analyze_DllImportExterns_DoNotAffectMethodBookkeeping()
    {
        var report = Analyze();

        Assert.Equal(0, report.MethodsSkipped);
        Assert.Empty(report.SkippedMethods);
        Assert.DoesNotContain(report.SkippedMethods, s => s.Contains(nameof(NativeInteropOps), StringComparison.Ordinal));
        Assert.Contains(report.Findings, f => f.Kind == ApiCallKind.NativeImport);
    }

    // 4a — the two metadata-seam kinds (a pinvokeimpl declaration, an [UnmanagedCallersOnly] export) sort AFTER
    // every bytecode call-site kind in the (…, ThenBy Kind) ordering, so a finding with no call instruction
    // behind it never interleaves with real call sites for the same caller. This is the stable property; which
    // single kind happens to be terminal is not — ApiCallKind is append-only, so the last value moves whenever a
    // seam is added (NativeExport displaced NativeImport as the maximum).
    [Fact]
    public void ApiCallKind_MetadataSeamKinds_SortAfterCallSiteKinds()
    {
        ApiCallKind[] callSiteKinds = [ApiCallKind.Call, ApiCallKind.Construct, ApiCallKind.MethodPointerLoad];
        ApiCallKind[] metadataSeamKinds = [ApiCallKind.NativeImport, ApiCallKind.NativeExport];

        Assert.All(
            metadataSeamKinds,
            seam => Assert.All(callSiteKinds, callSite => Assert.True(
                callSite < seam,
                $"{callSite} must sort before the metadata seam kind {seam}.")));

        // ...and the two groups together are the whole enum: a newly appended kind has to be classified here
        // rather than silently escaping the ordering contract.
        Assert.Equal(
            Enum.GetValues<ApiCallKind>().Order(),
            callSiteKinds.Concat(metadataSeamKinds).Order());
    }

    // 4b — the ordered output (which now includes NativeImport findings) is deterministic and honours the
    // documented composite key: (CallerType, CallerMethod, CalledApi, Kind) ordinal. Re-sorting is a no-op.
    [Fact]
    public void Analyze_OrderedFindings_AreDeterministicByCompositeKey()
    {
        var findings = Analyze().Findings;

        var resorted = findings
            .OrderBy(f => f.CallerType, StringComparer.Ordinal)
            .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
            .ThenBy(f => f.CalledApi, StringComparer.Ordinal)
            .ThenBy(f => f.Kind)
            .ToArray();

        Assert.Equal(resorted, findings);
    }

    // 4c — concretely, the two P/Invoke declarations on the same type sort by CallerMethod ordinal:
    // CurrentProcessId before ShowMessage.
    [Fact]
    public void Analyze_NativeImports_AreOrderedDeterministically()
    {
        var natives = Analyze().Findings
            .Where(f => f.Kind == ApiCallKind.NativeImport &&
                        f.CallerType.EndsWith(nameof(NativeInteropOps), StringComparison.Ordinal))
            .Select(f => f.CallerMethod)
            .ToArray();

        Assert.Equal(
            new[] { nameof(NativeInteropOps.CurrentProcessId), nameof(NativeInteropOps.ShowMessage) },
            natives);
    }

    // 5 — regression: the new fixture types add methods but never cause a skip; coverage stays complete and
    // the new capabilities are all represented alongside the pre-existing ones.
    [Fact]
    public void Analyze_WithNewGapFixtures_KeepsCompleteCoverageAndSelfConsistentCounts()
    {
        var report = Analyze();

        Assert.Equal(0, report.MethodsSkipped);
        Assert.Empty(report.SkippedMethods);
        Assert.Equal(report.MethodsTotal, report.MethodsAnalyzed);
        Assert.True(report.MethodsTotal > 0);

        Assert.Contains(report.Findings, f => f.Capability == Capability.ReflectionInvocation);
        Assert.Contains(report.Findings, f => f.Capability == Capability.NativeInterop);
        Assert.Contains(report.Findings, f => f.Capability == Capability.DynamicCodeLoading);
    }

    private CapabilityReport Analyze()
    {
        var result = new CapabilityAnalysis(fixture.Assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    // Loads the net10.0 test assembly itself (which holds Net10OnlyGapOps) and returns its findings. The
    // shared fixture's constructor has already initialized the Silvergun runtime. Never executes the targets.
    private System.Collections.Generic.IReadOnlyList<ApiCallFinding> AnalyzeSelf()
    {
        var path = typeof(Net10OnlyGapOps).Assembly.Location;
        var create = AssemblyAnalyzer.Load(path);
        Assert.True(create.IsSuccess, create.Message);
        using var cci = create.Value;

        var result = new CapabilityAnalysis(cci).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value.Findings;
    }
    #endregion

    #region Fields
    private readonly AssemblyAnalyzerFixture fixture;
    #endregion
}
