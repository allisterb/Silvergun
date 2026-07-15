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
    // the FileStream .ctor (no member access on the created object), so this fails if constructor
    // (MethodCallInstruction for .ctor) detection regresses.
    [Fact]
    public void Analyze_ConstructorOnlyCall_IsAttributedToFileSystem()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Capability == Capability.FileSystem &&
                 f.CallerMethod == nameof(SensitiveOps.CreatesFileStream) &&
                 f.CalledApi.StartsWith("System.IO.FileStream", StringComparison.Ordinal));
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
        Assert.Equal(report.Findings, restored.Findings);

        // Enums serialize by name, not as bare numbers.
        Assert.Contains("\"FileSystem\"", json);
        Assert.DoesNotMatch(new Regex("\"Capability\"\\s*:\\s*\\d"), json);
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

    private CapabilityReport Analyze()
    {
        var result = new CapabilityAnalysis(fixture.Analyzer).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private readonly AnalyzerFixture fixture;
}
