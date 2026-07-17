namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Runs the CIL capability analysis over every assembly in a <c>.nupkg</c>. <see cref="Scan"/> opens the
/// package, analyzes each inventoried assembly with <see cref="AssemblyAnalyzer"/> + <see cref="CapabilityAnalysis"/>,
/// and aggregates the per-assembly reports (plus identity and scripts) into a <see cref="PackageCapabilityReport"/>.
/// A per-assembly load/analysis failure becomes a skipped <see cref="AssemblyScanResult"/> — never fatal. Never throws.
/// </summary>
public sealed class PackageScanner : Runtime
{
    #region Methods
    /// <summary>
    /// Opens <paramref name="nupkgPath"/> and scans each assembly. The package is disposed internally (temp files
    /// cleaned up) before returning. Never throws: an open failure propagates as a failure <see cref="Result{T}"/>;
    /// a per-assembly failure is captured as an <see cref="AssemblyScanResult"/> with a <c>SkipReason</c>.
    /// </summary>
    public static Result<PackageCapabilityReport> Scan(string nupkgPath, bool resolveReferences = true)
    {
        var opened = NuGetPackage.Open(nupkgPath);
        if (!opened.IsSuccess)
            return Result.Failure<PackageCapabilityReport>(opened.Message, opened.Exception);

        using var package = opened.Value;
        try
        {
            var results = package.Assemblies.Select(a => ScanAssembly(a, resolveReferences)).ToArray();
            var report = new PackageCapabilityReport(
                package.Identity,
                DateTimeOffset.UtcNow,
                results,
                package.Scripts);
            return Result.Success(report);
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<PackageCapabilityReport>($"Failed to scan package {nupkgPath}.", ex);
        }
    }

    // Loads and analyzes one assembly; a Load/Analyze failure yields a skipped result carrying the Result message.
    // Metadata and obfuscation are read best-effort in every path — a failure never sinks the assembly (null member).
    // The CCI AssemblyAnalyzer is loaded once and shared by both the capability and obfuscation analyses (ADR 0010).
    private static AssemblyScanResult ScanAssembly(PackageAssembly assembly, bool resolveReferences)
    {
        var metadata = ReadMetadata(assembly.FullPath, resolveReferences);

        var loaded = AssemblyAnalyzer.Load(assembly.FullPath);
        if (!loaded.IsSuccess)
            return new AssemblyScanResult(assembly, null, loaded.Message ?? "Failed to load assembly.", metadata, null);

        using var cci = loaded.Value;
        var obfuscation = AnalyzeObfuscation(cci);
        var analysis = new CapabilityAnalysis(cci).Analyze();
        return analysis.IsSuccess
            ? new AssemblyScanResult(assembly, analysis.Value, null, metadata, obfuscation)
            : new AssemblyScanResult(assembly, null, analysis.Message ?? "Capability analysis failed.", metadata, obfuscation);
    }

    // Best-effort CCI metadata read; a failure logs a warning and yields null — never fatal.
    private static AssemblyMetadataInfo? ReadMetadata(string path, bool resolveReferences)
    {
        var result = AssemblyMetadata.Read(path, resolveReferences);
        if (result.IsSuccess)
            return result.Value;

        Warn("Could not read metadata for {0}: {1}", path, result.Message ?? "unknown error");
        return null;
    }

    // Best-effort obfuscation scan over the already-loaded analyzer; a failure logs a warning and yields null.
    private static ObfuscationReport? AnalyzeObfuscation(AssemblyAnalyzer cci)
    {
        var result = new ObfuscationAnalysis(cci).Analyze();
        if (result.IsSuccess)
            return result.Value;

        Warn("Could not analyze obfuscation for {0}: {1}", cci.AssemblyPath, result.Message ?? "unknown error");
        return null;
    }
    #endregion
}
