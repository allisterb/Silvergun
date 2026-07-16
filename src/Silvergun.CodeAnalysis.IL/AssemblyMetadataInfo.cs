namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// One referenced-assembly identity, projected from CCI's <c>IAssemblyReference</c>. Carries only
/// strings/bools — no CCI or Analysis.Net types leak (ADR 0002). <see cref="Resolved"/>/<see cref="ResolvedPath"/>
/// are populated best-effort by <see cref="AssemblyMetadata"/> via Nuclear.Assemblies (local, non-network).
/// </summary>
public sealed record AssemblyReferenceInfo(
    string Name,
    string? Version,
    string? Culture,
    string? PublicKeyToken,   // lowercase hex, null if none
    bool Resolved,            // Nuclear.Assemblies found a physical file
    string? ResolvedPath);    // resolved file's full path when Resolved

/// <summary>
/// A serializable snapshot of a single assembly's CCI metadata: identity/strong-name status, module
/// flags (IL-only, bitness, foreign types), kind, target runtime, custom-attribute type names and the
/// referenced-assembly identities. Produced by <see cref="AssemblyMetadata.Read(string, bool)"/>.
/// Carries only strings/enums/records (ADR 0002).
/// </summary>
public sealed record AssemblyMetadataInfo(
    string Name,
    string? Version,
    string? Culture,
    string? PublicKeyToken,           // lowercase hex, null if unsigned
    bool IsStrongNameSigned,
    string ModuleKind,               // CCI ModuleKind name (DynamicallyLinkedLibrary/ConsoleApplication/...)
    bool IsILOnly,
    bool Requires32Bit,
    bool Requires64Bit,
    bool RequiresAmdInstructionSet,
    bool ContainsForeignTypes,
    bool HasEntryPoint,              // module EntryPoint present (odd for a library dll)
    string? TargetRuntimeVersion,    // e.g. "v4.0.30319"
    string? DebugInformationLocation,// embedded PDB path (author build-machine intel; may be null)
    IReadOnlyList<string> CustomAttributes,   // assembly+module custom-attribute TYPE full names
    IReadOnlyList<AssemblyReferenceInfo> References)
{
    #region Methods
    /// <summary>Serializes this record to indented JSON with enum-derived strings written as names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes an <see cref="AssemblyMetadataInfo"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static AssemblyMetadataInfo? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<AssemblyMetadataInfo>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
