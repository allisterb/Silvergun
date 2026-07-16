namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Capability (sensitive-API) analysis over the shared fixture assembly, plus the serializable
/// <see cref="CapabilityReport"/> round-trip. Covers the seven cases in the capability-analysis spec.
/// </summary>
public sealed class CapabilityAnalysisTests : IClassFixture<AnalyzerFixture>
{
    public CapabilityAnalysisTests(AnalyzerFixture fixture) => this.fixture = fixture;

    // Case 1
    [Fact]
    public void Analyze_OnFixtureAssembly_SucceedsWithPopulatedReport()
    {
        var result = new CapabilityAnalysis(fixture.Analyzer).Analyze();

        Assert.True(result.IsSuccess, result.Message);

        var report = result.Value;
        Assert.False(string.IsNullOrWhiteSpace(report.AssemblyName));
        Assert.False(string.IsNullOrWhiteSpace(report.AssemblyPath));
        Assert.NotEmpty(report.Findings);
    }

    // Case 2
    [Theory]
    [InlineData(Capability.FileSystem, nameof(SensitiveOps.ReadsFiles))]
    [InlineData(Capability.Network, nameof(SensitiveOps.TalksToNetwork))]
    [InlineData(Capability.ProcessExecution, nameof(SensitiveOps.SpawnsProcess))]
    [InlineData(Capability.EnvironmentProbe, nameof(SensitiveOps.ProbesEnvironment))]
    [InlineData(Capability.DynamicCodeLoading, nameof(SensitiveOps.LoadsCode))]
    public void Analyze_AttributesCapabilityToExpectedCaller(Capability capability, string caller)
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Capability == capability && f.CallerMethod == caller);
    }

    // Case 3
    [Theory]
    [InlineData(nameof(SensitiveOps.Clean))]
    [InlineData(nameof(Shapes.Straight))]
    [InlineData(nameof(Shapes.Branch))]
    [InlineData(nameof(Shapes.Loop))]
    public void Analyze_ProducesNoFindingsForBenignMethods(string caller)
    {
        var report = Analyze();

        Assert.DoesNotContain(report.Findings, f => f.CallerMethod == caller);
    }

    // Case 4
    [Fact]
    public void Analyze_ReadsFilesFinding_CalledApiIsFileOrDirectory()
    {
        var report = Analyze();

        var finding = report.Findings.First(
            f => f.CallerMethod == nameof(SensitiveOps.ReadsFiles) && f.Capability == Capability.FileSystem);

        Assert.True(
            finding.CalledApi.StartsWith("System.IO.File", StringComparison.Ordinal) ||
            finding.CalledApi.StartsWith("System.IO.Directory", StringComparison.Ordinal),
            $"Unexpected CalledApi: {finding.CalledApi}");
    }

    // Case 4b — constructor-only detection guard: the sole sensitive call in CreatesFileStream is
    // the FileStream .ctor (no member access on the created object). Under the bytecode model this is
    // a CreateObjectInstruction (newobj), so the finding is Kind=Construct with CalledApi ending in
    // ".ctor". Fails if constructor (newobj) detection regresses.
    [Fact]
    public void Analyze_ConstructorOnlyCall_IsAttributedToFileSystem()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Capability == Capability.FileSystem &&
                 f.Kind == ApiCallKind.Construct &&
                 f.CallerMethod == nameof(SensitiveOps.CreatesFileStream) &&
                 f.CalledApi.StartsWith("System.IO.FileStream", StringComparison.Ordinal) &&
                 f.CalledApi.EndsWith(".ctor", StringComparison.Ordinal));
    }

    // Case 4c — the Network `new WebClient()` in TalksToNetwork is likewise a newobj: a Construct
    // finding for the WebClient .ctor. (DownloadString on the same method is a separate Call finding,
    // asserted below.)
    [Fact]
    public void Analyze_WebClientConstruction_IsConstructKindEndingInCtor()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Capability == Capability.Network &&
                 f.Kind == ApiCallKind.Construct &&
                 f.CallerMethod == nameof(SensitiveOps.TalksToNetwork) &&
                 f.CalledApi.StartsWith("System.Net.WebClient", StringComparison.Ordinal) &&
                 f.CalledApi.EndsWith(".ctor", StringComparison.Ordinal));
    }

    // Case 4d — a plain call (callvirt) surfaces as Kind=Call: DownloadString in TalksToNetwork.
    [Fact]
    public void Analyze_DownloadStringCall_IsCallKind()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Capability == Capability.Network &&
                 f.Kind == ApiCallKind.Call &&
                 f.CallerMethod == nameof(SensitiveOps.TalksToNetwork) &&
                 f.CalledApi.StartsWith("System.Net.WebClient", StringComparison.Ordinal) &&
                 f.CalledApi.EndsWith(".DownloadString", StringComparison.Ordinal));
    }

    // Case 5
    [Fact]
    public void Analyze_FindingsAreDistinctAndDeterministicallyOrdered()
    {
        var first = Analyze().Findings;
        var second = Analyze().Findings;

        // Distinct: no duplicate 4-tuples (record equality over scalar members).
        Assert.Equal(first.Count, first.Distinct().Count());

        // Deterministic: two scans yield the same sequence in the same order.
        Assert.Equal(first, second);
    }

    // Case 6
    [Fact]
    public void CapabilityReport_JsonRoundTrip_PreservesReportAndUsesEnumNames()
    {
        var report = Analyze();

        var json = report.ToJson();
        var restored = CapabilityReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Equal(report.AssemblyName, restored!.AssemblyName);
        Assert.Equal(report.AssemblyPath, restored.AssemblyPath);
        Assert.Equal(report.AnalyzedAt, restored.AnalyzedAt);
        Assert.Equal(report.Findings, restored.Findings);   // record equality includes Kind

        // Coverage fields survive the round-trip.
        Assert.Equal(report.MethodsTotal, restored.MethodsTotal);
        Assert.Equal(report.MethodsAnalyzed, restored.MethodsAnalyzed);
        Assert.Equal(report.MethodsSkipped, restored.MethodsSkipped);
        Assert.Equal(report.SkippedMethods, restored.SkippedMethods);

        // Both enums serialize by name, not as bare numbers.
        Assert.Contains("\"FileSystem\"", json);
        Assert.DoesNotMatch(new Regex("\"Capability\"\\s*:\\s*\\d"), json);
        Assert.Matches(new Regex("\"Kind\"\\s*:\\s*\"(Call|Construct|MethodPointerLoad)\""), json);
        Assert.DoesNotMatch(new Regex("\"Kind\"\\s*:\\s*\\d"), json);
    }

    // Case 7
    [Fact]
    public void Catalog_IsNonEmpty_AndCoversEveryCapability()
    {
        Assert.NotEmpty(CapabilityAnalysis.Catalog);

        foreach (var capability in Enum.GetValues<Capability>())
        {
            Assert.Contains(CapabilityAnalysis.Catalog, e => e.Capability == capability);
        }
    }

    // Case 8 (ADR 0005, the crux) — EH-heavy regression. DownloadInTryCatchAsync compiles to an async
    // state machine whose MoveNext carries the WebClient ctor + DownloadString + File.ReadAllText call
    // sites inside heavy try/catch. The old TAC lifter threw on that EH shape (skipping the method → no
    // findings); scanning the bytecode model surfaces them. The caller is the compiler-generated state
    // machine (a <DownloadInTryCatchAsync>d__N.MoveNext), so we match on CalledApi, NOT the caller name.
    [Fact]
    public void Analyze_AsyncTryCatchStateMachine_SurfacesSensitiveCalls()
    {
        var report = Analyze();

        // At least one Network or FileSystem finding for the APIs used inside the async try/catch.
        Assert.Contains(
            report.Findings,
            f => (f.Capability == Capability.Network &&
                  f.CalledApi.StartsWith("System.Net.WebClient", StringComparison.Ordinal)) ||
                 (f.Capability == Capability.FileSystem &&
                  f.CalledApi.StartsWith("System.IO.File", StringComparison.Ordinal)));

        // Concretely: all three call sites survive lifting through the state machine.
        Assert.Contains(report.Findings, f =>
            f.Kind == ApiCallKind.Construct &&
            f.CalledApi.StartsWith("System.Net.WebClient", StringComparison.Ordinal) &&
            f.CalledApi.EndsWith(".ctor", StringComparison.Ordinal));
        Assert.Contains(report.Findings, f =>
            f.Kind == ApiCallKind.Call &&
            f.CalledApi.EndsWith("System.Net.WebClient.DownloadString", StringComparison.Ordinal));
        Assert.Contains(report.Findings, f =>
            f.Kind == ApiCallKind.Call && f.Capability == Capability.FileSystem &&
            f.CalledApi.StartsWith("System.IO.File", StringComparison.Ordinal));

        // Proof it went through the state machine (not attributed elsewhere): the caller is the
        // compiler-generated <DownloadInTryCatchAsync>d__N type, whose MoveNext is the ONLY method
        // holding these call sites. Match the method name, not the mangled type name.
        Assert.Contains(
            report.Findings,
            f => f.CallerType.Contains("DownloadInTryCatchAsync", StringComparison.Ordinal) &&
                 (f.CalledApi.StartsWith("System.Net.WebClient", StringComparison.Ordinal) ||
                  f.CalledApi.StartsWith("System.IO.File", StringComparison.Ordinal)));
    }

    // Case 9 — MethodPointerLoad. CaptureFileReader returns File.ReadAllText as a delegate, emitting an
    // ldftn (LoadMethodAddressInstruction) with no call site. A call-site-only scan would miss it.
    [Fact]
    public void Analyze_DelegateCapture_SurfacesMethodPointerLoad()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Kind == ApiCallKind.MethodPointerLoad &&
                 f.Capability == Capability.FileSystem &&
                 f.CallerMethod == nameof(AsyncSensitiveOps.CaptureFileReader) &&
                 f.CalledApi.StartsWith("System.IO.File", StringComparison.Ordinal));
    }

    // Case 10 — coverage. Bytecode scanning should analyze every method-with-body: nothing skipped, and
    // the counts are internally consistent.
    [Fact]
    public void Analyze_OnFixtureAssembly_CoversEveryMethodWithBody()
    {
        var report = Analyze();

        Assert.True(report.MethodsTotal > 0, "Expected at least one method-with-body in the fixture.");
        Assert.Equal(0, report.MethodsSkipped);
        Assert.Empty(report.SkippedMethods);
        Assert.Equal(report.MethodsTotal - report.MethodsSkipped, report.MethodsAnalyzed);
        Assert.Equal(report.MethodsTotal, report.MethodsAnalyzed);
    }

    // Case 11 — real-assembly smoke. Silvergun.Runtime is genuine, EH-heavy IL (try/catch, using,
    // logging, async-free but rich). Bytecode scanning must survive it: succeed, analyze methods, and
    // skip only a small fraction. Deterministic and offline — the dll ships in the test output dir.
    [Fact]
    public void Analyze_OnRealRuntimeAssembly_SucceedsWithNearCompleteCoverage()
    {
        var runtimePath = typeof(Silvergun.Runtime).Assembly.Location;

        var create = AssemblyAnalyzer.Create(runtimePath);
        Assert.True(create.IsSuccess, create.Message);
        using var analyzer = create.Value;

        var result = new CapabilityAnalysis(analyzer).Analyze();
        Assert.True(result.IsSuccess, result.Message);

        var report = result.Value;
        Assert.True(report.MethodsTotal > 0, "Expected methods-with-body in Silvergun.Runtime.");
        Assert.True(report.MethodsAnalyzed > 0, "Expected at least one method to be analyzed.");
        Assert.Equal(report.MethodsTotal - report.MethodsSkipped, report.MethodsAnalyzed);

        // Skips must be a small fraction (< 10%) — the whole point of ADR 0005 is near-complete coverage.
        Assert.True(
            report.MethodsSkipped < report.MethodsTotal * 0.10,
            $"Skipped {report.MethodsSkipped} of {report.MethodsTotal} methods (>= 10%): "
                + string.Join("; ", report.SkippedMethods));
    }

    private CapabilityReport Analyze()
    {
        var result = new CapabilityAnalysis(fixture.Analyzer).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private readonly AnalyzerFixture fixture;
}
