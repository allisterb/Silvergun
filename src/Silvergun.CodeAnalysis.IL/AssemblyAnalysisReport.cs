namespace Silvergun.CodeAnalysis.IL;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// The complete analysis of a single assembly (ADR 0007/0010): its optional CCI <see cref="AssemblyMetadataInfo"/>,
/// its <see cref="CapabilityReport"/>, its optional <see cref="ObfuscationReport"/>, and its optional
/// <see cref="IndicatorReport"/>, composed into one serializable DTO. <see cref="Metadata"/>,
/// <see cref="Obfuscation"/>, and <see cref="Indicators"/> are nullable so a metadata-read, obfuscation-analysis, or
/// indicator-analysis failure doesn't sink the capability result. Pure data — the CLI composes it;
/// no analysis logic lives here.
/// <para>
/// <see cref="Indicators"/> is an additive trailing member (indicator-cli-integration task, ADR 0007 composition):
/// old JSON written before it existed deserializes with it <c>null</c>, which reads identically to "the analysis
/// was never attempted" — the same posture <see cref="Obfuscation"/> already has.
/// </para>
/// </summary>
public sealed record AssemblyAnalysisReport(
    AssemblyMetadataInfo? Metadata,
    CapabilityReport Capabilities,
    ObfuscationReport? Obfuscation,
    IndicatorReport? Indicators = null)
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes an <see cref="AssemblyAnalysisReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static AssemblyAnalysisReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<AssemblyAnalysisReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
