namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Categories of sensitive behaviour a piece of CIL can exhibit.
/// <para>
/// <b>Append-only.</b> New values go at the end and existing ones are never reordered or renamed: the ordinals
/// are load-bearing wherever a value is compared or persisted numerically, and a mid-enum insertion has bitten us
/// before (ADR 0019 decision 5). JSON is written by name, so appending is safe.
/// </para>
/// </summary>
public enum Capability
{
    FileSystem, Network, ProcessExecution, Registry, EnvironmentProbe,
    DynamicCodeLoading, NativeInterop, Cryptography, ReflectionInvocation,
    UnsafeMemory, RuntimeControl
}

/// <summary>
/// One sensitive-API catalog entry. <paramref name="TypePrefix"/> matches the callee's containing
/// type full name (<c>Namespace.TypeName</c>) by ordinal <see cref="string.StartsWith(string, StringComparison)"/>;
/// <paramref name="Method"/> (when non-null) matches the callee method name exactly (property getters
/// appear as <c>get_X</c>).
/// </summary>
public sealed record SensitiveApi(Capability Capability, string TypePrefix, string? Method = null);

/// <summary>
/// How the sensitive API was referenced. The first three are bytecode call sites; the last two are metadata
/// seams with no call instruction at all — <see cref="NativeImport"/> is a <c>[DllImport]</c>/pinvokeimpl
/// declaration (managed code calling <em>out</em> to native), <see cref="NativeExport"/> an
/// <c>[UnmanagedCallersOnly]</c> method (native code calling <em>into</em> the assembly).
/// <para><b>Append-only</b>, for the same reason as <see cref="Capability"/>.</para>
/// </summary>
public enum ApiCallKind { Call, Construct, MethodPointerLoad, NativeImport, NativeExport }

/// <summary>One detected sensitive-API call. Carries only strings/enums — no Analysis.Net types (ADR 0001/0002).</summary>
public sealed record ApiCallFinding(
    Capability Capability,
    ApiCallKind Kind,       // how the callee was referenced (call / newobj / ldftn)
    string CallerType,      // full name of the type containing the calling method
    string CallerMethod,    // calling method name
    string CalledApi);      // "Namespace.TypeName.MethodName" of the callee (TypeName + "..ctor" for Construct;
                            // "module!entryPoint" native target for NativeImport;
                            // "<managed>!entryPoint" exported entry point for NativeExport, where "<managed>" is a
                            // literal marker — the owning method is not repeated, it is already in CallerMethod)

/// <summary>A serializable capability report for a single analyzed assembly.</summary>
public sealed record CapabilityReport(
    string AssemblyName,
    string AssemblyPath,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<ApiCallFinding> Findings,
    int MethodsTotal,
    int MethodsAnalyzed,
    int MethodsSkipped,
    IReadOnlyList<string> SkippedMethods)   // "TypeName.MethodName: <reason>"
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
