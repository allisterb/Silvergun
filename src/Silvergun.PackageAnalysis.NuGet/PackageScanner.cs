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
            // The inventoried assemblies, then the declared entries that never reached the inventory (ADR 0030).
            var results = package.Assemblies.Select(a => ScanAssembly(a, resolveReferences))
                .Concat(package.UninventoriedDeclaredEntries.Select(e => NotInventoried(e.Declared, e.Reported)))
                .ToArray();

            // Script content scanning runs while the package is still open (its extraction dir exists — ADR 0012).
            // Best-effort: a scanner failure never sinks the whole scan, and any file that could not be scanned makes
            // the status Unavailable — with the hits of the files that were scanned kept (ADR 0030, ADR 0032).
            var (scriptFindings, scriptStatus, scriptUnavailableReason) = ScanScripts(package);

            // YARA malware-signature scanning over every extracted file (ADR 0016), while the extraction dir still
            // exists. Best-effort/never-throws: an unavailable backend or a failed scan yields Unavailable — with
            // whatever hits an incomplete scan did find (ADR 0032), otherwise empty — so a caller can never mistake
            // "could not scan" for "scanned and clean" (the defect this status field exists to close).
            var (yaraFindings, yaraStatus, yaraUnavailableReason) = runYara
                ? ScanYara(package, yaraScanner)
                : (Array.Empty<YaraFinding>(), YaraScanStatus.NotRun, null);

            // Packaging anomalies (ADR 0031): a pure, offline pass over the DECLARED entry names — what the package
            // author wrote in the central directory, not what the extractor managed to put on disk. Reported, never
            // gating (ADR 0031 decision 3); every name it returns is already escaped.
            var packagingAnomalies = PackageEntryNameAnalyzer.Analyze(package.DeclaredEntryNames);

            var report = new PackageCapabilityReport(
                package.Identity,
                DateTimeOffset.UtcNow,
                results,
                package.Scripts,
                scriptFindings,
                YaraFindings: yaraFindings,
                YaraScanStatus: yaraStatus,
                PackagingAnomalies: packagingAnomalies,
                ScriptScanStatus: scriptStatus)
            {
                YaraUnavailableReason = yaraUnavailableReason,
                ScriptScanUnavailableReason = scriptUnavailableReason,
            };
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

    // A declared package entry that was never written as an extracted file of its own (see NuGetPackage.UninventoriedEntryNames),
    // reported as a scan result with NO CapabilityReport and a SkipReason.
    //
    // It travels through that channel deliberately: an AssemblyScanResult with a SkipReason is what
    // CompletenessAssessment.ForPackage already reads as "a whole binary that produced no analysis", so this entry
    // makes the package report NOT complete instead of vanishing. Without it, the sixth instance of ADR 0030 — a
    // payload named COM1.dll, which Windows cannot even write to disk — produced a report that said "Clean".
    // There is no file behind it, so FullPath and Sha256 are empty by construction, and role/TFM come from the entry
    // name like every other inventoried file's. The two forms of that name are NOT interchangeable: what is PUBLISHED
    // is `reportedName`, already escaped by NuGetPackage (ADR 0031 decision 4), while role and TFM are derived from the
    // RAW `declaredName` — because escaping EMITS BACKSLASHES and the path splitter treats a backslash as a separator,
    // so deriving from the escaped form re-segments the name and invents an answer: raw "lib/pay<LF>load.dll" has two
    // segments (Lib, no TFM), and its escape has three, which reads the TFM off as "pay". Derived values are escaped
    // where the DTO is built, on the same rule as RelativePath: a TFM segment is attacker-authored text that the
    // renderer prints. (MakeAssembly derives an inventoried file's TFM from its raw path too, and does not escape it —
    // the same latent exposure, left alone here because it is not this change.)
    private static AssemblyScanResult NotInventoried(string declaredName, string reportedName)
    {
        var role = NuGetPackage.RoleOf(declaredName);
        var tfm = NuGetPackage.TargetFrameworkOf(declaredName, role);
        var assembly = new PackageAssembly(
            reportedName, string.Empty, tfm is null ? null : YaraPathSafety.Escape(tfm), role, string.Empty);
        return new AssemblyScanResult(
            assembly,
            null,
            "declared package entry was NOT inventoried: it was never written as an extracted file of its own (dropped, " +
            "renamed, clamped back inside the content root, written over another entry's file, or written with bytes " +
            "other than those NuGet installs, or under a name NuGet installs as a different file), so its content, or " +
            "the content it replaced, was never analysed " +
            "(coverage not delivered — not a clean result)",
            null,
            null);
    }

    // Best-effort script/content rule scan over the open package (ADR 0012); ScriptRuleScanner already never throws,
    // but a defensive guard here keeps an unexpected failure from sinking the whole package scan. The manifest
    // (.nuspec) is scanned too — it is kept out of the script inventory but rule-scanned for content (ADR 0012 follow-up)
    // via ScanPackageMetadata, which redacts its prose elements first and tags the findings PackageMetadata (advisory).
    //
    // Coverage (ADR 0030; ADR 0032 shape, docs/agent/tasks/script-scan-coverage.md): Completed iff zero files — the
    // .nuspec included — were unscanned; otherwise Unavailable, with the findings of the files that did scan kept (real
    // detections) and a reason that leads with the count, then names the files with their reasons, the most actionable
    // clause first (ScriptRuleScanner.DescribeUnscanned), since the report bounds it to 512 chars. The outer catch (F7)
    // is Unavailable too, with no findings. The scanner's own per-file warnings stay; this adds ONE summary warning per
    // incomplete package, never one per file. The third element is the report's ScriptScanUnavailableReason (null
    // unless Unavailable); the report escapes and bounds it on assignment.
    private static (IReadOnlyList<ScriptFinding> Findings, ScriptScanStatus Status, string? UnavailableReason) ScanScripts(
        NuGetPackage package)
    {
        try
        {
            var scanner = new ScriptRuleScanner();
            var scripts = scanner.ScanWithCoverage(package.Scripts);
            var nuspec = package.NuspecPath is null
                ? null
                : scanner.ScanPackageMetadataWithCoverage(package.NuspecPath, Path.GetFileName(package.NuspecPath));

            // Re-order the concatenation so the report-level list keeps the same deterministic path -> line -> rule id
            // order each entry point already guarantees (the planned snapshot/diff feature depends on it).
            var findings = nuspec is null
                ? scripts.Findings
                : scripts.Findings.Concat(nuspec.Findings)
                    .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
                    .ThenBy(f => f.StartLine)
                    .ThenBy(f => f.RuleId, StringComparer.Ordinal)
                    .ToArray();

            // A package always has a manifest (Open requires one), so it always counts toward the total; one that never
            // reached disk is unscanned, not absent (ADR 0035 review W1).
            (string RelativePath, string Reason)[] manifest = nuspec is null
                ? [(ScriptRuleScanner.ManifestPlaceholder, ScriptRuleScanner.ManifestNotOnDisk)]
                : [.. nuspec.Unscanned];
            var unscanned = scripts.Unscanned.Concat(manifest).ToArray();
            if (unscanned.Length == 0)
                return (findings, ScriptScanStatus.Completed, null);

            var total = package.Scripts.Count + 1;
            var reason = $"{unscanned.Length} of {total} script/manifest file(s) were not scanned: {ScriptRuleScanner.DescribeUnscanned(unscanned)}";
            Warn("Script content scanning INCOMPLETE for {0}: {1}. {2} finding(s) from the files that were scanned are reported; the other files' script findings are NOT verified.",
                YaraPathSafety.Escape(package.Identity.Id), Yara.Worker.WorkerProtocol.Safe(reason, PackageCapabilityReport.MaxScriptScanUnavailableReasonChars), findings.Count);
            return (findings, ScriptScanStatus.Unavailable, reason);
        }
        catch (Exception ex)
        {
            // Same reason as ScanYara's catch: the message can quote an attacker-authored entry name.
            Warn("Script rule scanning failed for {0}: {1}. Script findings for this package are NOT verified.",
                YaraPathSafety.Escape(package.Identity.Id), YaraPathSafety.Escape(ex.Message).TrimEnd('.'));
            return (Array.Empty<ScriptFinding>(), ScriptScanStatus.Unavailable, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    // Best-effort YARA malware-signature scan over the open package's extracted files (ADR 0016). The shared
    // scanner is selected once by YaraScannerFactory (the YARA-X worker on Windows, or in-process libyara when explicitly
    // selected; classic yara CLI elsewhere, or a no-op
    // when no engine is available); each raw hit is enriched with rule metadata (family/detection-name/category)
    // from YaraRuleIndex and a package-relative path.
    //
    // What is scanned is the package's YARA inventory (ADR 0034): the files NuGetPackage.Open listed straight after
    // extraction, handed to IYaraScanner.ScanFiles — NOT a walk of the extraction directory taken now. This scan runs
    // only after the CIL analysis of every assembly, minutes later, and a file deleted in between (Windows Storage Sense
    // sweeps old-dated files under %TEMP%, and an extracted file keeps the timestamp its package chose) used to be simply
    // absent from the walk: never reported unscanned, so the package read Completed, and clean if every file was gone.
    // Judged against the inventory, a listed file that is missing at scan time is unscanned, through the same
    // YaraScanIncompleteException channel as any other unscanned file (first catch below).
    //
    // Status is derived from IYaraScanner.Available FIRST (ADR 0027 decision 4 code-review fix), not from whether
    // ScanFiles throws: a NullYaraScanner (no backend configured at all, the common configuration) returns empty
    // and throws nothing, which read as Completed before that fix. Available == false is the "no engine" answer.
    //
    // Past that gate, ScanFiles either returns (Completed — every listed file was scanned, which the backend has to
    // establish from positive per-file evidence: a clean `yara -r` exit code and an empty stderr are NOT that evidence,
    // because yara's --timeout is one deadline for the whole recursive run and the files still queued when it passes
    // are dropped silently, ADR 0032 decision 9) or throws, and the two catches below are what keep "could not tell"
    // honest in BOTH directions (ADR 0030 and its converse):
    //
    //  * YaraScanIncompleteException — specific files (for a pass that never produced a usable run, all of them) are
    //    KNOWN not to have been scanned: a listed file gone by scan time (ADR 0034), a file the backend could not open
    //    or scan, a per-file timeout in the per-file loop (YaraScanLoop.Run), a name the CLI batch output cannot
    //    round-trip, a file the CLI batch pass has no coverage line for and whose individual re-scan failed, an
    //    unattributable hit (ADR 0029 decisions 13, 14, 17; ADR 0032). It carries every hit already in hand in
    //    PartialFindings, and those are REAL detections: they are enriched and reported ALONGSIDE Unavailable (ADR
    //    0032 decision 2). Dropping them was the defect — a package with a matching payload plus 65 junk
    //    control-character names reported zero findings, so `--strict` exited 3
    //    instead of 2 and `--strict --allow-incomplete` exited 0. The catch must itself be total: if enriching the
    //    partial hits throws, it degrades to (empty, Unavailable) — still fail-closed — and never escapes.
    //
    //  * anything else — notably LibYaraScanner's native libyara.NET dependency failing to load, which can surface at
    //    a call site OUTSIDE any scanner's own guards (inside the per-file ScanFiles loop, YaraScanLoop.Run, or from
    //    LibYaraScanner.Available itself). No hits are known, so it is (empty, Unavailable).
    //
    // Never throws overall, and never yields a bare empty list that would read as "scanned, clean". A failure is
    // logged ONCE per package scan here, not once per file: ScanFiles aggregates its per-file failures into the
    // one exception it throws (the backends additionally log each failing file's own cause, escaped).
    //
    // The third element is why the status is Unavailable (null otherwise), for the report's YaraUnavailableReason: the
    // backend's own UnavailableReason, or the exception's message. The report escapes and bounds it on assignment.
    private static (IReadOnlyList<YaraFinding> Findings, YaraScanStatus Status, string? UnavailableReason) ScanYara(
        NuGetPackage package, IYaraScanner? yaraScanner = null)
    {
        try
        {
            var scanner = yaraScanner ?? YaraScannerFactory.Shared;
            if (!scanner.Available)
            {
                var why = scanner.UnavailableReason is { Length: > 0 } reason ? reason : "the YARA backend did not say why";
                Warn("YARA scanning UNAVAILABLE for {0}: no working backend ({1}). Malware-signature findings for this package are NOT verified.",
                    package.Identity.Id, Yara.Worker.WorkerProtocol.Safe(why, PackageCapabilityReport.MaxYaraUnavailableReasonChars));
                return (Array.Empty<YaraFinding>(), YaraScanStatus.Unavailable, $"no working YARA backend: {why}");
            }

            var index = YaraRuleIndex.Shared;
            var findings = scanner.ScanFiles(package.ExtractionDir, package.YaraInventory)
                .Select(hit => Enrich(hit.Match, PackageRelativePath(package, hit.FullPath), index))
                .ToArray();
            return (findings, YaraScanStatus.Completed, null);
        }
        catch (YaraScanIncompleteException ex)
        {
            // The backends' messages are whole sentences ending in '.'; the format below supplies its own, so the
            // message's is trimmed rather than doubled.
            var partial = EnrichPartialFindings(ex, package);
            if (partial.Count > 0)
                Warn("YARA scan INCOMPLETE for {0}: {1}. {2} match(es) found in the files that were scanned are reported; every other file's malware-signature findings are NOT verified.",
                    package.Identity.Id, YaraPathSafety.Escape(ex.Message).TrimEnd('.'), partial.Count);
            else
                Warn("YARA scanning UNAVAILABLE for {0}: {1}. Malware-signature findings for this package are NOT verified.",
                    package.Identity.Id, YaraPathSafety.Escape(ex.Message).TrimEnd('.'));
            return (partial, YaraScanStatus.Unavailable, ex.Message);
        }
        catch (Exception ex)
        {
            // ex.Message routinely quotes a path out of the package (a YaraScanIncompleteException names the
            // offending entries; an IO error embeds the file name verbatim), and those names are attacker-authored:
            // escape before logging so one cannot forge a line in our own log. Escape is idempotent, so a message
            // that was already built from escaped text is unchanged.
            Warn("YARA scanning UNAVAILABLE for {0}: {1}. Malware-signature findings for this package are NOT verified.",
                package.Identity.Id, YaraPathSafety.Escape(ex.Message).TrimEnd('.'));
            return (Array.Empty<YaraFinding>(), YaraScanStatus.Unavailable, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    // The partial hits an incomplete scan carried out (ADR 0032 decision 2), enriched exactly as a completed scan's
    // are. Total by construction — it runs inside ScanYara's catch, where nothing may escape: if enrichment throws,
    // the package degrades to no findings (still Unavailable, so still fail-closed) rather than failing the whole
    // package scan. The message is escaped like every other one here.
    private static IReadOnlyList<YaraFinding> EnrichPartialFindings(
        YaraScanIncompleteException ex, NuGetPackage package)
    {
        try
        {
            var index = YaraRuleIndex.Shared;
            return ex.PartialFindings
                .Select(hit => Enrich(hit.Match, PackageRelativePath(package, hit.FullPath), index))
                .ToArray();
        }
        catch (Exception enrichFailure)
        {
            Warn("Could not report the {0} partial YARA hit(s) for {1}: {2}",
                ex.PartialFindings.Count, package.Identity.Id, YaraPathSafety.Escape(enrichFailure.Message));
            return Array.Empty<YaraFinding>();
        }
    }

    // Enriches a backend hit into the report DTO: rule metadata (family/detection-name/category) comes from the
    // embedded-rule index (the backends only reliably surface rule name + tags), the rest from the hit itself.
    //
    // This is the report boundary, and it is where the matched path stops being raw (ADR 0031 decision 4). The path
    // derives from an attacker-authored entry name, so a hit on "content/pay\nload.bin" used to carry a real newline
    // into the report, the renderer and the JSON — the known wart ADR 0029 left open. Escape is idempotent, so a
    // backend that already escaped is unaffected.
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
            YaraPathSafety.Escape(relativePath));
    }

    // The package-relative path of an extracted file, matching the inventory convention (RecursiveExtractor nests
    // entries under a directory named after the .nupkg): relative to that content root, forward-slash normalized.
    // The root is the package's own NuGetPackage.ContentRoot, the one its inventories were taken against, never
    // re-derived here: a second derivation from the .nupkg path disagreed with the on-disk spelling for "x.nupkg."
    // and rendered every hit path absolute (ADR 0034, I5 W-b).
    //
    // Derived by NuGetPackage.RelativeUnderRoot — the same string-prefix computation the inventory itself uses —
    // rather than by Path.GetRelativePath, which resolves both operands through the platform normalizer and answers
    // "\\.\COM1" for a file named COM1.dll under the root (ADR 0030, sixth instance). It is also total, so the
    // try/catch it replaces is gone: a throw here would have been caught by ScanYara and turned a real, attributable
    // hit into a package-wide Unavailable — ADR 0030's converse, a detection downgraded to "we don't know".
    private static string PackageRelativePath(NuGetPackage package, string fullPath) =>
        NuGetPackage.RelativeUnderRoot(package.ContentRoot, fullPath);

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
