namespace Silvergun.CodeAnalysis.IL;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// The complete analysis of a single assembly (ADR 0007/0010): its optional CCI <see cref="AssemblyMetadataInfo"/>,
/// its <see cref="CapabilityReport"/>, and its optional <see cref="ObfuscationReport"/>, composed into one
/// serializable DTO. <see cref="Metadata"/> and <see cref="Obfuscation"/> are nullable so a metadata-read or
/// obfuscation-analysis failure doesn't sink the capability result. Pure data — the CLI composes it;
/// no analysis logic lives here.
/// </summary>
public sealed record AssemblyAnalysisReport(
    AssemblyMetadataInfo? Metadata,
    CapabilityReport Capabilities,
    ObfuscationReport? Obfuscation)
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
