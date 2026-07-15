namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>Categories of sensitive behaviour a piece of CIL can exhibit.</summary>
public enum Capability
{
    FileSystem, Network, ProcessExecution, Registry, EnvironmentProbe,
    DynamicCodeLoading, NativeInterop, Cryptography
}

/// <summary>
/// One sensitive-API catalog entry. <paramref name="TypePrefix"/> matches the callee's containing
/// type full name (<c>Namespace.TypeName</c>) by ordinal <see cref="string.StartsWith(string, StringComparison)"/>;
/// <paramref name="Method"/> (when non-null) matches the callee method name exactly (property getters
/// appear as <c>get_X</c>).
/// </summary>
public sealed record SensitiveApi(Capability Capability, string TypePrefix, string? Method = null);

/// <summary>One detected sensitive-API call. Carries only strings/enums — no Analysis.Net types (ADR 0001/0002).</summary>
public sealed record ApiCallFinding(
    Capability Capability,
    string CallerType,      // full name of the type containing the calling method
    string CallerMethod,    // calling method name
    string CalledApi);      // "Namespace.TypeName.MethodName" of the callee

/// <summary>A serializable capability report for a single analyzed assembly.</summary>
public sealed record CapabilityReport(
    string AssemblyName,
    string AssemblyPath,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<ApiCallFinding> Findings)
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="CapabilityReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static CapabilityReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<CapabilityReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
