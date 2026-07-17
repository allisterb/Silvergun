namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Obfuscation (hidden-payload) analysis over the shared fixture assembly, plus the serializable
/// <see cref="ObfuscationReport"/> round-trip. Covers the six cases in the obfuscation-analysis spec:
/// encoded executable/archive detection, false-positive guards, entropy/length population, JSON
/// round-trip, and a real-assembly robustness smoke.
/// </summary>
public sealed class ObfuscationAnalysisTests : IClassFixture<AssemblyDisassemblerFixture>
{
    public ObfuscationAnalysisTests(AssemblyDisassemblerFixture fixture) => this.fixture = fixture;

    // Case 1 — a base64 constant that decodes to bytes starting with "MZ" is flagged as an
    // EncodedExecutable, described as a Windows PE.
    [Fact]
    public void Analyze_EncodedPeConstant_DetectedAsEncodedExecutable()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Kind == HiddenContentKind.EncodedExecutable &&
                 (f.DetectedAs.Contains("PE", StringComparison.OrdinalIgnoreCase) ||
                  f.DetectedAs.Contains("Windows", StringComparison.OrdinalIgnoreCase)) &&
                 f.EncodedLength == HiddenPayloads.EncodedPeImage.Length);
    }

    // Case 2 — a base64 constant that decodes to bytes starting with "PK\x03\x04" is flagged as an
    // EncodedArchive, described as a zip.
    [Fact]
    public void Analyze_EncodedZipConstant_DetectedAsEncodedArchive()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Kind == HiddenContentKind.EncodedArchive &&
                 f.DetectedAs.Contains("zip", StringComparison.OrdinalIgnoreCase) &&
                 f.EncodedLength == HiddenPayloads.EncodedZipArchive.Length);
    }

    // Case 2b — a base64 constant that decodes to bytes starting with the gzip magic 0x1F 0x8B is
    // flagged as an EncodedArchive, described as gzip. Exercises the gzip magic-number branch.
    [Fact]
    public void Analyze_EncodedGzipConstant_DetectedAsEncodedArchive()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Kind == HiddenContentKind.EncodedArchive &&
                 f.DetectedAs.Contains("gzip", StringComparison.OrdinalIgnoreCase) &&
                 f.EncodedLength == HiddenPayloads.EncodedGzipArchive.Length);
    }

    // Case 2c — a hex-encoded constant that decodes to bytes starting with the ELF magic
    // 0x7F 45 4C 46 is flagged as an EncodedExecutable, described as ELF. Exercises both the
    // hex-decode path and the ELF magic-number branch.
    [Fact]
    public void Analyze_EncodedElfHexConstant_DetectedAsEncodedExecutable()
    {
        var report = Analyze();

        Assert.Contains(
            report.Findings,
            f => f.Kind == HiddenContentKind.EncodedExecutable &&
                 f.DetectedAs.Contains("ELF", StringComparison.OrdinalIgnoreCase) &&
                 f.EncodedLength == HiddenPayloads.EncodedElfExecutableHex.Length);
    }

    // Case 3a — a long, plain-English constant is not base64/hex and must not be flagged (guards
    // against flagging ordinary long strings on entropy alone). Identified by its distinct length.
    [Fact]
    public void Analyze_PlainEnglishConstant_ProducesNoFinding()
    {
        var report = Analyze();

        Assert.DoesNotContain(
            report.Findings,
            f => f.EncodedLength == HiddenPayloads.PlainEnglishSentence.Length ||
                 f.CallerMethod == nameof(HiddenPayloads.GetPlainEnglishSentence));
    }

    // Case 3b — a valid but short (< MinEncodedLength) base64 constant must not be flagged.
    [Fact]
    public void Analyze_ShortBase64Constant_ProducesNoFinding()
    {
        var report = Analyze();

        Assert.DoesNotContain(
            report.Findings,
            f => f.EncodedLength == HiddenPayloads.ShortBenignBase64.Length ||
                 f.CallerMethod == nameof(HiddenPayloads.GetShortBenignBase64));
    }

    // Case 4 — findings carry sensible metadata: the encoded length equals the constant's length and
    // the entropy of a base64 blob sits above the detector's threshold.
    [Fact]
    public void Analyze_EncodedFindings_PopulateEntropyAndLengthSensibly()
    {
        var report = Analyze();

        var zip = report.Findings.First(
            f => f.Kind == HiddenContentKind.EncodedArchive &&
                 f.EncodedLength == HiddenPayloads.EncodedZipArchive.Length);

        Assert.Equal(HiddenPayloads.EncodedZipArchive.Length, zip.EncodedLength);
        Assert.True(zip.EncodedLength >= ObfuscationAnalysis.MinEncodedLength,
            $"EncodedLength {zip.EncodedLength} below MinEncodedLength {ObfuscationAnalysis.MinEncodedLength}.");
        Assert.True(zip.Entropy > ObfuscationAnalysis.MinEntropyThreshold,
            $"Entropy {zip.Entropy} not above MinEntropyThreshold {ObfuscationAnalysis.MinEntropyThreshold}.");

        var pe = report.Findings.First(
            f => f.Kind == HiddenContentKind.EncodedExecutable &&
                 f.EncodedLength == HiddenPayloads.EncodedPeImage.Length);

        Assert.Equal(HiddenPayloads.EncodedPeImage.Length, pe.EncodedLength);
        Assert.True(pe.Entropy > ObfuscationAnalysis.MinEntropyThreshold,
            $"Entropy {pe.Entropy} not above MinEntropyThreshold {ObfuscationAnalysis.MinEntropyThreshold}.");
    }

    // Case 5 — JSON round-trip preserves the report and its findings, and the HiddenContentKind enum
    // serializes by name, not as a bare number.
    [Fact]
    public void ObfuscationReport_JsonRoundTrip_PreservesFindingsAndUsesEnumNames()
    {
        var report = Analyze();

        var json = report.ToJson();
        var restored = ObfuscationReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Equal(report.AssemblyName, restored!.AssemblyName);
        Assert.Equal(report.AssemblyPath, restored.AssemblyPath);
        Assert.Equal(report.AnalyzedAt, restored.AnalyzedAt);
        Assert.Equal(report.Findings, restored.Findings);   // record equality includes Kind

        // Kind serializes by name, not as a bare number.
        Assert.Matches(
            new Regex("\"Kind\"\\s*:\\s*\"(EncodedExecutable|EncodedArchive|HighEntropyBlob)\""),
            json);
        Assert.DoesNotMatch(new Regex("\"Kind\"\\s*:\\s*\\d"), json);
    }

    // Case 6 — real-assembly smoke: analysis over genuine IL (Silvergun.Runtime.dll) succeeds and does
    // not throw. The finding count is whatever it is; this only proves robustness on real IL.
    [Fact]
    public void Analyze_OnRealRuntimeAssembly_SucceedsWithoutThrowing()
    {
        var runtimePath = typeof(Silvergun.Runtime).Assembly.Location;

        var create = AssemblyDisassembler.Create(runtimePath);
        Assert.True(create.IsSuccess, create.Message);
        using var analyzer = create.Value;

        var result = new ObfuscationAnalysis(analyzer).Analyze();

        Assert.True(result.IsSuccess, result.Message);
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.Findings);
        Assert.False(string.IsNullOrWhiteSpace(result.Value.AssemblyName));
    }

    private ObfuscationReport Analyze()
    {
        var result = new ObfuscationAnalysis(fixture.Analyzer).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private readonly AssemblyDisassemblerFixture fixture;
}
