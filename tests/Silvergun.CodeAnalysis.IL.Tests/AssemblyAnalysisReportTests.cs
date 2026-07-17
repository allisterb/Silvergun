namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Round-trip tests for the composition record <see cref="AssemblyAnalysisReport"/> (ADR 0007/0010): the
/// optional <see cref="AssemblyMetadataInfo"/>, the <see cref="CapabilityReport"/>, and the optional
/// <see cref="ObfuscationReport"/> serialized as one DTO. Composes a report from real analyses over
/// <c>Silvergun.Runtime.dll</c> (deterministic, shipped in the test output dir) and asserts all three
/// halves survive <c>ToJson</c>/<c>FromJson</c>, including the null-<c>Obfuscation</c> case. The fixture is
/// injected only to guarantee <c>Runtime.Initialize</c> has run once.
/// </summary>
public sealed class AssemblyAnalysisReportTests : IClassFixture<AssemblyDisassemblerFixture>
{
    #region Constructors
    public AssemblyAnalysisReportTests(AssemblyDisassemblerFixture fixture) => _ = fixture;
    #endregion

    #region Methods
    // Round-trip with real metadata + capabilities + obfuscation: Metadata (Name), Capabilities (Findings
    // element-wise plus coverage counts) and Obfuscation (AssemblyName/AnalyzedAt/Findings element-wise) all
    // survive serialization.
    [Fact]
    public void AssemblyAnalysisReport_JsonRoundTrip_PreservesMetadataCapabilitiesAndObfuscation()
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

        // Obfuscation half (ADR 0010) — non-null report survives element-wise.
        Assert.NotNull(restored.Obfuscation);
        Assert.Equal(report.Obfuscation!.AssemblyName, restored.Obfuscation!.AssemblyName);
        Assert.Equal(report.Obfuscation.AnalyzedAt, restored.Obfuscation.AnalyzedAt);
        Assert.Equal(report.Obfuscation.Findings, restored.Obfuscation.Findings);   // record equality incl. Kind
    }

    // A metadata-read failure yields a null Metadata; the report must still round-trip with the capability
    // result (and the obfuscation half) intact.
    [Fact]
    public void AssemblyAnalysisReport_WithNullMetadata_RoundTripsWithCapabilitiesIntact()
    {
        var full = ComposeRuntimeReport();
        var report = new AssemblyAnalysisReport(null, full.Capabilities, full.Obfuscation);

        var json = report.ToJson();
        var restored = AssemblyAnalysisReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Null(restored!.Metadata);
        Assert.Equal(report.Capabilities.AssemblyName, restored.Capabilities.AssemblyName);
        Assert.Equal(report.Capabilities.Findings, restored.Capabilities.Findings);
        Assert.Equal(report.Capabilities.MethodsTotal, restored.Capabilities.MethodsTotal);
        Assert.Equal(report.Capabilities.MethodsAnalyzed, restored.Capabilities.MethodsAnalyzed);
        Assert.Equal(report.Capabilities.MethodsSkipped, restored.Capabilities.MethodsSkipped);
        Assert.NotNull(restored.Obfuscation);
        Assert.Equal(report.Obfuscation!.Findings, restored.Obfuscation!.Findings);
    }

    // A null Obfuscation (e.g. obfuscation analysis failed / was skipped) must round-trip as null without
    // disturbing the Capabilities half — the never-throw, best-effort contract of ADR 0010.
    [Fact]
    public void AssemblyAnalysisReport_WithNullObfuscation_RoundTripsWithCapabilitiesIntact()
    {
        var full = ComposeRuntimeReport();
        var report = new AssemblyAnalysisReport(full.Metadata, full.Capabilities, null);

        var json = report.ToJson();
        var restored = AssemblyAnalysisReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Null(restored!.Obfuscation);
        Assert.NotNull(restored.Metadata);
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

        var create = AssemblyAnalyzer.Load(RuntimePath);
        Assert.True(create.IsSuccess, create.Message);
        using var cci = create.Value;

        var analysis = new CapabilityAnalysis(cci).Analyze();
        Assert.True(analysis.IsSuccess, analysis.Message);

        // Obfuscation runs off the same loaded analyzer (ADR 0010), composed as the third half.
        var obfuscation = new ObfuscationAnalysis(cci).Analyze();
        Assert.True(obfuscation.IsSuccess, obfuscation.Message);

        return new AssemblyAnalysisReport(metadata.Value, analysis.Value, obfuscation.Value);
    }
    #endregion

    #region Fields
    private static readonly string RuntimePath = typeof(Silvergun.Runtime).Assembly.Location;
    #endregion
}
