namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>The kind of hidden content a decoded IL constant or embedded blob was classified as. Append-only (JSON names).</summary>
public enum HiddenContentKind { EncodedExecutable, EncodedArchive, HighEntropyBlob, EncodedText, EncodedImage }

/// <summary>Where a finding's content was read from (<c>docs/agent/tasks/hidden-payloads-1.md</c>). Append-only.</summary>
public enum HiddenContentSource
{
    /// <summary>A whole <c>ldstr</c> constant.</summary>
    Constant,
    /// <summary>A base64/hex run inside a longer <c>ldstr</c> constant; reported only when its content is recognised.</summary>
    Substring,
    /// <summary>A <c>string.Concat</c> of constants and once-stored static string fields.</summary>
    Folded,
    /// <summary>A field's RVA-mapped data (the <c>InitializeArray</c> idiom).</summary>
    FieldData,
    /// <summary>An embedded managed resource.</summary>
    Resource,
}

/// <summary>
/// One detected instance of hidden/encoded content in an assembly. Carries only strings/enums — no Analysis.Net types
/// (ADR 0001/0002). <paramref name="DetectedAs"/> names what the content matched (e.g. "Windows PE", "zip", "PNG",
/// "UTF-16LE text") or the secondary signal ("high-entropy base64"). For text sources <paramref name="EncodedLength"/>
/// and <paramref name="Entropy"/> are the encoded text's length and per-char entropy; for <see cref="HiddenContentSource.FieldData"/>
/// and <see cref="HiddenContentSource.Resource"/>, the bytes read (capped) and their per-byte entropy.
/// </summary>
public sealed record ObfuscationFinding(
    HiddenContentKind Kind,
    string DetectedAs,        // e.g. "Windows PE", "ELF", "zip", or "high-entropy base64"
    string CallerType,        // type where the content lives (best-effort; "<unknown>" if not resolvable; "<resource>")
    string CallerMethod,      // method where the ldstr occurs / that loads the field; the field or resource name otherwise
    int EncodedLength,        // length of the encoded constant, or bytes read for a blob
    double Entropy,           // Shannon entropy of the encoded constant (per char) or blob (per byte)
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    HiddenContentSource Source = HiddenContentSource.Constant);

/// <summary>
/// A serializable obfuscation report for a single analyzed assembly. <paramref name="Truncated"/>: a blob-byte or
/// folded-char budget was spent, so some field data, resources or concatenations were not examined and the findings are
/// a floor, not a total.
/// </summary>
public sealed record ObfuscationReport(
    string AssemblyName,
    string AssemblyPath,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<ObfuscationFinding> Findings,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    bool Truncated = false)
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
