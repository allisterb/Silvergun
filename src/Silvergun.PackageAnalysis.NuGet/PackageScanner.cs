namespace Silvergun.PackageAnalysis.NuGet;

using System;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Runs the CIL capability analysis over every assembly in a <c>.nupkg</c>. <see cref="Scan"/> opens the
/// package, analyzes each inventoried assembly with <see cref="AssemblyAnalyzer"/> + <see cref="CapabilityAnalysis"/>
/// (plus the best-effort <see cref="ObfuscationAnalysis"/> and <see cref="IndicatorAnalysis"/> side analyses, ADR 0010),
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
    public static Result<PackageCapabilityReport> Scan(string nupkgPath, bool resolveReferences = true, bool runYara = true, IYaraScanner? yaraScanner = null)
    {
        var opened = NuGetPackage.Open(nupkgPath);
        if (!opened.IsSuccess)
            return Result.Failure<PackageCapabilityReport>(opened.Message, opened.Exception);

        using var package = opened.Value;
        try
        {
            var results = package.Assemblies.Select(a => ScanAssembly(a, resolveReferences)).ToArray();

            // Script content scanning runs while the package is still open (its extraction dir exists — ADR 0012).
            // Best-effort: a scanner failure yields empty findings and never sinks the whole scan.
            var scriptFindings = ScanScripts(package);

            // YARA malware-signature scanning over every extracted file (ADR 0016), while the extraction dir still
            // exists. Best-effort/never-throws: a scanner failure or an unavailable backend yields empty findings —
            // but ScanYara ALSO reports which of those it was (YaraScanStatus), so a caller can never mistake
            // "could not scan" for "scanned and clean" (the defect this status field exists to close).
            var (yaraFindings, yaraStatus) = runYara
                ? ScanYara(package, nupkgPath, yaraScanner)
                : (Array.Empty<YaraFinding>(), YaraScanStatus.NotRun);

            var report = new PackageCapabilityReport(
                package.Identity,
                DateTimeOffset.UtcNow,
                results,
                package.Scripts,
                scriptFindings,
                YaraFindings: yaraFindings,
                YaraScanStatus: yaraStatus);
            return Result.Success(report);
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<PackageCapabilityReport>($"Failed to scan package {nupkgPath}.", ex);
        }
    }

    // Loads and analyzes one assembly; a Load/Analyze failure yields a skipped result carrying the Result message.
    // Metadata, obfuscation, and indicators are read best-effort in every path — a failure never sinks the assembly
    // (null member). The CCI AssemblyAnalyzer is loaded once and shared by the capability, obfuscation, and
    // indicator analyses (ADR 0010; indicators follow the obfuscation precedent exactly, indicator-cli-integration
    // task).
    private static AssemblyScanResult ScanAssembly(PackageAssembly assembly, bool resolveReferences)
    {
        var metadata = ReadMetadata(assembly.FullPath, resolveReferences);

        var loaded = AssemblyAnalyzer.Load(assembly.FullPath);
        if (!loaded.IsSuccess)
            return new AssemblyScanResult(assembly, null, loaded.Message ?? "Failed to load assembly.", metadata, null);

        using var cci = loaded.Value;
        var obfuscation = AnalyzeObfuscation(cci);
        var indicators = AnalyzeIndicators(cci);
        var analysis = new CapabilityAnalysis(cci).Analyze();
        return analysis.IsSuccess
            ? new AssemblyScanResult(assembly, analysis.Value, null, metadata, obfuscation, indicators)
            : new AssemblyScanResult(assembly, null, analysis.Message ?? "Capability analysis failed.", metadata, obfuscation, indicators);
    }

    // Best-effort script/content rule scan over the open package (ADR 0012); ScriptRuleScanner already never throws,
    // but a defensive guard here keeps an unexpected failure from sinking the whole package scan. The manifest
    // (.nuspec) is scanned too — it is kept out of the script inventory but rule-scanned for content (ADR 0012 follow-up)
    // via ScanPackageMetadata, which redacts its prose elements first and tags the findings PackageMetadata (advisory).
    private static IReadOnlyList<ScriptFinding> ScanScripts(NuGetPackage package)
    {
        try
        {
            var scanner = new ScriptRuleScanner();
            var findings = scanner.Scan(package.Scripts);
            if (package.NuspecPath is null)
                return findings;

            // Re-order the concatenation so the report-level list keeps the same deterministic path -> line -> rule id
            // order each entry point already guarantees (the planned snapshot/diff feature depends on it).
            var nuspecFindings = scanner.ScanPackageMetadata(package.NuspecPath, Path.GetFileName(package.NuspecPath));
            return findings.Concat(nuspecFindings)
                .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
                .ThenBy(f => f.StartLine)
                .ThenBy(f => f.RuleId, StringComparer.Ordinal)
                .ToArray();
        }
        catch (Exception ex)
        {
            // Same reason as ScanYara's catch: the message can quote an attacker-authored entry name.
            Warn("Script rule scanning failed for {0}: {1}", package.Identity.Id, YaraPathSafety.Escape(ex.Message));
            return Array.Empty<ScriptFinding>();
        }
    }

    // Best-effort YARA malware-signature scan over the open package's extraction directory (ADR 0016). The shared
    // scanner is selected once by YaraScannerFactory (in-process on Windows, classic yara CLI elsewhere, or a no-op
    // when no engine is available); each raw hit is enriched with rule metadata (family/detection-name/category)
    // from YaraRuleIndex and a package-relative path.
    //
    // Status is derived from IYaraScanner.Available FIRST (ADR 0027 decision 4 code-review fix), not from whether
    // ScanDirectory throws: a backend swallows its own per-file failures (IYaraScanner's doc comment: never throws
    // apart from the two carve-outs), so exception-absence carries no information — a NullYaraScanner (no backend
    // configured at all, the common configuration) returns empty and throws nothing, which read as Completed before
    // this fix. The try/catch below is therefore NOT redundant, and is more than defense in depth: it is what
    // converts the deliberate carve-outs into Unavailable — a TimeoutException from LibYaraScanner.ScanFile, whose
    // bound being reached means the engine's health can no longer be vouched for (ADR 0028 decision 10), and a
    // YaraScanIncompleteException from YaraCliScanner.ScanDirectory, which means specific files (or, for a batch
    // pass that never produced a usable run, all of them) are KNOWN not to have been scanned (ADR 0029 decisions 13
    // and 14). It is also what still catches LibYaraScanner when its native libyara.NET dependency fails to load,
    // since that failure can surface at a call site OUTSIDE any scanner's own guards (inside the interface's default
    // ScanDirectory loop, or from LibYaraScanner.Available itself). What must NOT reach here is a single file's
    // native scan error: that stays inside LibYaraScanner.ScanFile precisely because arriving here would discard
    // every other file's findings and report a false Unavailable for the whole package. Never throws
    // overall — a failure (or an unhealthy backend) yields no findings AND YaraScanStatus.Unavailable, never a bare
    // empty list that would read as "scanned, clean". The catch is also why such a failure is logged exactly ONCE
    // per package scan, not once per file: an exception from ScanDirectory aborts its whole per-file loop
    // immediately (it never reaches a second file), so this is the only place it is ever observed.
    private static (IReadOnlyList<YaraFinding> Findings, YaraScanStatus Status) ScanYara(
        NuGetPackage package, string nupkgPath, IYaraScanner? yaraScanner = null)
    {
        try
        {
            var scanner = yaraScanner ?? YaraScannerFactory.Shared;
            if (!scanner.Available)
            {
                Warn("YARA scanning UNAVAILABLE for {0}: no working backend. Malware-signature findings for this package are NOT verified.",
                    package.Identity.Id);
                return (Array.Empty<YaraFinding>(), YaraScanStatus.Unavailable);
            }

            var index = YaraRuleIndex.Shared;
            var root = package.ExtractionDir;
            var findings = scanner.ScanDirectory(root)
                .Select(hit => Enrich(hit.Match, PackageRelativePath(root, nupkgPath, hit.FullPath), index))
                .ToArray();
            return (findings, YaraScanStatus.Completed);
        }
        catch (Exception ex)
        {
            // ex.Message routinely quotes a path out of the package (a YaraScanIncompleteException names the
            // offending entries; an IO error embeds the file name verbatim), and those names are attacker-authored:
            // escape before logging so one cannot forge a line in our own log. Escape is idempotent, so a message
            // that was already built from escaped text is unchanged.
            Warn("YARA scanning UNAVAILABLE for {0}: {1}. Malware-signature findings for this package are NOT verified.",
                package.Identity.Id, YaraPathSafety.Escape(ex.Message));
            return (Array.Empty<YaraFinding>(), YaraScanStatus.Unavailable);
        }
    }

    // Enriches a backend hit into the report DTO: rule metadata (family/detection-name/category) comes from the
    // embedded-rule index (the backends only reliably surface rule name + tags), the rest from the hit itself.
    private static YaraFinding Enrich(YaraMatch match, string relativePath, YaraRuleIndex index)
    {
        var info = index.Lookup(match.Rule);
        return new YaraFinding(
            match.Rule,
            match.Namespace,
            info?.MalwareFamily,
            info?.DetectionName,
            info?.Category,
            match.Tags,
            relativePath);
    }

    // The package-relative path of an extracted file, matching the inventory convention (RecursiveExtractor nests
    // entries under a directory named after the .nupkg): relative to that content root, forward-slash normalized.
    private static string PackageRelativePath(string extractionDir, string nupkgPath, string fullPath)
    {
        try
        {
            var contentRoot = Path.Combine(extractionDir, Path.GetFileName(nupkgPath));
            var root = Directory.Exists(contentRoot) ? contentRoot : extractionDir;
            return Path.GetRelativePath(root, fullPath).Replace('\\', '/');
        }
        catch
        {
            return fullPath;
        }
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

    // Best-effort indicator scan over the already-loaded analyzer, mirroring AnalyzeObfuscation exactly
    // (indicator-cli-integration task); a failure logs a warning and yields null.
    private static IndicatorReport? AnalyzeIndicators(AssemblyAnalyzer cci)
    {
        var result = new IndicatorAnalysis(cci).Analyze();
        if (result.IsSuccess)
            return result.Value;

        Warn("Could not analyze indicators for {0}: {1}", cci.AssemblyPath, result.Message ?? "unknown error");
        return null;
    }
    #endregion
}
