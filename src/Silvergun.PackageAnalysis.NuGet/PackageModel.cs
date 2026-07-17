namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;

/// <summary>One declared dependency of a package (surfaced even when not analyzed — ADR 0004 §6).</summary>
public sealed record PackageDependencyInfo(string Id, string VersionRange, string TargetFramework);

/// <summary>Package identity and its declared dependency tree, read from the nuspec.</summary>
public sealed record PackageIdentityInfo(
    string Id,
    string Version,
    string? Authors,
    string? Description,
    IReadOnlyList<PackageDependencyInfo> Dependencies);

/// <summary>The role a packaged file plays, derived from its first path segment (ADR 0004 §3).</summary>
public enum PackageItemRole { Lib, Runtimes, Tools, Build, BuildTransitive, Analyzers, Content, Other }

/// <summary>A managed/native binary of interest inside the package, extracted to disk for analysis.</summary>
public sealed record PackageAssembly(
    string RelativePath,        // path inside the package, e.g. "lib/netstandard2.0/Foo.dll"
    string FullPath,            // extracted absolute path on disk
    string? TargetFramework,    // TFM folder segment when present (e.g. "netstandard2.0"), else null
    PackageItemRole Role,
    string Sha256);             // content hash, lowercase hex

/// <summary>A packaged script/build file recorded as intel — presence and path only (ADR 0004 §4).</summary>
public sealed record PackageScript(string RelativePath, PackageItemRole Role); // .ps1/.targets/.props

/// <summary>The outcome of scanning a single <see cref="PackageAssembly"/>.</summary>
public sealed record AssemblyScanResult(
    PackageAssembly Assembly,
    CapabilityReport? Report,   // null when not analyzable
    string? SkipReason,         // non-null when Report is null (e.g. "not a managed assembly")
    AssemblyMetadataInfo? Metadata,   // null if metadata read failed or assembly not analyzable
    ObfuscationReport? Obfuscation);   // null if obfuscation analysis failed or assembly not analyzable

/// <summary>Aggregate, serializable scan result for one package (ADR 0002 pattern — strings/records only).</summary>
public sealed record PackageCapabilityReport(
    PackageIdentityInfo Package,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<AssemblyScanResult> Assemblies,
    IReadOnlyList<PackageScript> Scripts)
{
    #region Properties
    /// <summary>Every finding across all analyzed assemblies, flattened in stored order.</summary>
    [JsonIgnore]
    public IEnumerable<ApiCallFinding> AllFindings =>
        Assemblies.Where(a => a.Report is not null).SelectMany(a => a.Report!.Findings);
    #endregion

    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="PackageCapabilityReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static PackageCapabilityReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<PackageCapabilityReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
