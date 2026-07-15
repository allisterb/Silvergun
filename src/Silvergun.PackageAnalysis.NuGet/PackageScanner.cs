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
    public static Result<PackageCapabilityReport> Scan(string nupkgPath)
    {
        var opened = NuGetPackage.Open(nupkgPath);
        if (!opened.IsSuccess)
            return Result.Failure<PackageCapabilityReport>(opened.Message, opened.Exception);

        using var package = opened.Value;
        try
        {
            var results = package.Assemblies.Select(ScanAssembly).ToArray();
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

    // Loads and analyzes one assembly; a Create/Analyze failure yields a skipped result carrying the Result message.
    private static AssemblyScanResult ScanAssembly(PackageAssembly assembly)
    {
        var created = AssemblyAnalyzer.Create(assembly.FullPath);
        if (!created.IsSuccess)
            return new AssemblyScanResult(assembly, null, created.Message ?? "Failed to load assembly.");

        using var analyzer = created.Value;
        var analysis = new CapabilityAnalysis(analyzer).Analyze();
        return analysis.IsSuccess
            ? new AssemblyScanResult(assembly, analysis.Value, null)
            : new AssemblyScanResult(assembly, null, analysis.Message ?? "Capability analysis failed.");
    }
    #endregion
}
