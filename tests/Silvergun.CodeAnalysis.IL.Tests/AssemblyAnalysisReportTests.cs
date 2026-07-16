namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Round-trip tests for the composition record <see cref="AssemblyAnalysisReport"/> (ADR 0007): the
/// optional <see cref="AssemblyMetadataInfo"/> and the <see cref="CapabilityReport"/> serialized as one
/// DTO. Composes a report from real analyses over <c>Silvergun.Runtime.dll</c> (deterministic, shipped in
/// the test output dir) and asserts both halves survive <c>ToJson</c>/<c>FromJson</c>. The fixture is
/// injected only to guarantee <c>Runtime.Initialize</c> has run once.
/// </summary>
public sealed class AssemblyAnalysisReportTests : IClassFixture<AnalyzerFixture>
{
    #region Constructors
    public AssemblyAnalysisReportTests(AnalyzerFixture fixture) => _ = fixture;
    #endregion

    #region Methods
    // Round-trip with real metadata + capabilities: Metadata (Name) and Capabilities (Findings element-wise
    // plus coverage counts) all survive serialization.
    [Fact]
    public void AssemblyAnalysisReport_JsonRoundTrip_PreservesMetadataAndCapabilities()
    {
        var report = ComposeRuntimeReport();

        var json = report.ToJson();
        var restored = AssemblyAnalysisReport.FromJson(json);

        Assert.NotNull(restored);

        // Metadata half.
        Assert.NotNull(restored!.Metadata);
        Assert.Equal(report.Metadata!.Name, restored.Metadata!.Name);
        Assert.Equal(report.Metadata.Version, restored.Metadata.Version);
        Assert.Equal(report.Metadata.References, restored.Metadata.References);

        // Capabilities half.
        Assert.Equal(report.Capabilities.AssemblyName, restored.Capabilities.AssemblyName);
        Assert.Equal(report.Capabilities.Findings, restored.Capabilities.Findings);   // record equality incl. Kind
        Assert.Equal(report.Capabilities.MethodsTotal, restored.Capabilities.MethodsTotal);
        Assert.Equal(report.Capabilities.MethodsAnalyzed, restored.Capabilities.MethodsAnalyzed);
        Assert.Equal(report.Capabilities.MethodsSkipped, restored.Capabilities.MethodsSkipped);
    }

    // A metadata-read failure yields a null Metadata; the report must still round-trip with the capability
    // result intact.
    [Fact]
    public void AssemblyAnalysisReport_WithNullMetadata_RoundTripsWithCapabilitiesIntact()
    {
        var full = ComposeRuntimeReport();
        var report = new AssemblyAnalysisReport(null, full.Capabilities);

        var json = report.ToJson();
        var restored = AssemblyAnalysisReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Null(restored!.Metadata);
        Assert.Equal(report.Capabilities.AssemblyName, restored.Capabilities.AssemblyName);
        Assert.Equal(report.Capabilities.Findings, restored.Capabilities.Findings);
        Assert.Equal(report.Capabilities.MethodsTotal, restored.Capabilities.MethodsTotal);
        Assert.Equal(report.Capabilities.MethodsAnalyzed, restored.Capabilities.MethodsAnalyzed);
        Assert.Equal(report.Capabilities.MethodsSkipped, restored.Capabilities.MethodsSkipped);
    }

    private static AssemblyAnalysisReport ComposeRuntimeReport()
    {
        var metadata = AssemblyMetadata.Read(RuntimePath);
        Assert.True(metadata.IsSuccess, metadata.Message);

        var create = AssemblyAnalyzer.Create(RuntimePath);
        Assert.True(create.IsSuccess, create.Message);
        using var analyzer = create.Value;

        var analysis = new CapabilityAnalysis(analyzer).Analyze();
        Assert.True(analysis.IsSuccess, analysis.Message);

        return new AssemblyAnalysisReport(metadata.Value, analysis.Value);
    }
    #endregion

    #region Fields
    private static readonly string RuntimePath = typeof(Silvergun.Runtime).Assembly.Location;
    #endregion
}
