namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>The kind of hidden content a decoded IL constant was classified as.</summary>
public enum HiddenContentKind { EncodedExecutable, EncodedArchive, HighEntropyBlob }

/// <summary>
/// One detected instance of hidden/encoded content in an assembly's IL constants. Carries only
/// strings/enums — no Analysis.Net types (ADR 0001/0002). <paramref name="DetectedAs"/> names what the
/// decoded bytes matched (e.g. "Windows PE", "ELF", "zip") or the secondary signal ("high-entropy base64").
/// </summary>
public sealed record ObfuscationFinding(
    HiddenContentKind Kind,
    string DetectedAs,        // e.g. "Windows PE", "ELF", "zip", or "high-entropy base64"
    string CallerType,        // type where the constant lives (best-effort; "<unknown>" if not resolvable)
    string CallerMethod,      // method where the ldstr occurs (best-effort)
    int EncodedLength,        // length of the encoded constant
    double Entropy);          // Shannon entropy of the encoded constant

/// <summary>A serializable obfuscation report for a single analyzed assembly.</summary>
public sealed record ObfuscationReport(
    string AssemblyName,
    string AssemblyPath,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<ObfuscationFinding> Findings)
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes an <see cref="ObfuscationReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static ObfuscationReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<ObfuscationReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
