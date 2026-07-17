namespace Silvergun.CLI;

using System.CommandLine;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Squats;

/// <summary>
/// Entry point for the Silvergun CLI. Exposes the <c>analyze</c> verb, which runs
/// <see cref="AssemblyAnalyzer"/> + <see cref="CapabilityAnalysis"/> + <see cref="ObfuscationAnalysis"/> over a
/// .NET assembly; the <c>scan-package</c> verb, which runs <see cref="PackageScanner"/> over a <c>.nupkg</c>;
/// and the <c>check-squat</c> verb, which runs <see cref="SquatChecker"/> against a package id (network).
/// Exit codes are part of the CI contract (ADR 0003): 0 = success, 1 = load/analysis failure or bad arguments,
/// 2 = findings present under <c>--strict</c>.
/// </summary>
internal static class Program
{
    #region Methods
    private static int Main(string[] args)
    {
        var assemblyPathArgument = new Argument<string>("assembly-path")
        {
            Description = "Path to the .NET assembly to analyze."
        };
        var nupkgPathArgument = new Argument<string>("nupkg-path")
        {
            Description = "Path to the .nupkg package to scan."
        };
        var packageIdArgument = new Argument<string>("package-id")
        {
            Description = "The NuGet package id to check for typosquatting."
        };
        var jsonOption = new Option<bool>("--json")
        {
            Description = "Emit the capability report as JSON instead of the human summary."
        };
        var outputOption = new Option<string?>("--output")
        {
            Description = "Write the report to a file instead of stdout."
        };
        var strictOption = new Option<bool>("--strict")
        {
            Description = "Exit with code 2 when any findings are present (CI gate)."
        };
        var debugOption = new Option<bool>("--debug")
        {
            Description = "Enable verbose logging."
        };
        var noResolveOption = new Option<bool>("--no-resolve")
        {
            Description = "Skip best-effort assembly-reference resolution when reading metadata."
        };

        var analyzeCommand = new Command("analyze", "Analyze a .NET assembly for sensitive-API capabilities.")
        {
            assemblyPathArgument, jsonOption, outputOption, strictOption, debugOption, noResolveOption
        };
        analyzeCommand.SetAction(parse => RunAnalyze(
            parse.GetValue(assemblyPathArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(noResolveOption)));

        var scanPackageCommand = new Command("scan-package", "Scan a .nupkg for sensitive-API capabilities.")
        {
            nupkgPathArgument, jsonOption, outputOption, strictOption, debugOption, noResolveOption
        };
        scanPackageCommand.SetAction(parse => RunScanPackage(
            parse.GetValue(nupkgPathArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(noResolveOption)));

        // check-squat hits nuget.org, so its handler is async; the sync action bridges via GetAwaiter().GetResult()
        // to keep System.CommandLine's synchronous Invoke path (stdout purity handled by ConfigureLogging).
        var sourceOption = new Option<string?>("--source")
        {
            Description = "Popularity source: 'nuget', 'librariesio', or omit for auto " +
                          "(libraries.io when SILVERGUN_LIBRARIESIO_API_KEY is set, else nuget.org)."
        };
        var checkSquatCommand = new Command("check-squat", "Check a NuGet package id for likely typosquatting (network).")
        {
            packageIdArgument, jsonOption, outputOption, strictOption, debugOption, sourceOption
        };
        checkSquatCommand.SetAction(parse => RunCheckSquat(
            parse.GetValue(packageIdArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(sourceOption)).GetAwaiter().GetResult());

        var root = new RootCommand("Silvergun — static capability analysis for .NET assemblies.")
        {
            analyzeCommand, scanPackageCommand, checkSquatCommand
        };

        return root.Parse(args).Invoke();
    }

    private static int RunAnalyze(string assemblyPath, bool json, string? output, bool strict, bool debug, bool noResolve)
    {
        ConfigureLogging(json, output, debug);

        var cciResult = AssemblyAnalyzer.Load(assemblyPath);
        if (!cciResult.IsSuccess)
        {
            Console.Error.WriteLine(cciResult.Message);
            return 1;
        }

        using var cci = cciResult.Value;

        var reportResult = new CapabilityAnalysis(cci).Analyze();
        if (!reportResult.IsSuccess)
        {
            Console.Error.WriteLine(reportResult.Message);
            return 1;
        }

        // Obfuscation runs off the SAME loaded analyzer (ADR 0010); best-effort — a failure leaves it null.
        var obfuscationResult = new ObfuscationAnalysis(cci).Analyze();
        var obfuscation = obfuscationResult.IsSuccess ? obfuscationResult.Value : null;

        // Metadata read is best-effort — a failure leaves Metadata null and never changes the exit-code contract.
        var metadataResult = AssemblyMetadata.Read(assemblyPath, !noResolve);
        var report = new AssemblyAnalysisReport(
            metadataResult.IsSuccess ? metadataResult.Value : null, reportResult.Value, obfuscation);
        var text = json ? report.ToJson() : AssemblySummary(report);

        if (!TryEmit(text, output))
            return 1;

        return strict && (report.Capabilities.Findings.Count > 0 || (report.Obfuscation?.Findings.Count ?? 0) > 0) ? 2 : 0;
    }

    private static int RunScanPackage(string nupkgPath, bool json, string? output, bool strict, bool debug, bool noResolve)
    {
        ConfigureLogging(json, output, debug);

        var scanResult = PackageScanner.Scan(nupkgPath, resolveReferences: !noResolve);
        if (!scanResult.IsSuccess)
        {
            Console.Error.WriteLine(scanResult.Message);
            return 1;
        }

        var report = scanResult.Value;
        var text = json ? report.ToJson() : PackageSummary(report, nupkgPath);

        if (!TryEmit(text, output))
            return 1;

        var hasObfuscation = report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0);
        return strict && (report.AllFindings.Any() || hasObfuscation || report.ScriptFindings.Any()) ? 2 : 0;
    }

    // Runs the network squat check for one package id; logging is routed off stdout by ConfigureLogging.
    private static async Task<int> RunCheckSquat(string packageId, bool json, string? output, bool strict, bool debug, string? source)
    {
        ConfigureLogging(json, output, debug);

        var popularity = SelectPopularitySource(source);
        var result = await new SquatChecker(popularity).CheckAsync(packageId);
        if (!result.IsSuccess)
        {
            Console.Error.WriteLine(result.Message);
            return 1;
        }

        var findings = result.Value;
        var report = new SquatCheckReport(packageId, DateTimeOffset.UtcNow, findings);
        var text = json ? report.ToJson() : SquatSummary(report);

        if (!TryEmit(text, output))
            return 1;

        return strict && findings.Count > 0 ? 2 : 0;
    }

    // Chooses the popularity source for check-squat. Auto (default): libraries.io when the API key env var is set,
    // else keyless nuget.org. An explicit --source overrides. The selection (never the key) is logged to stderr so
    // stdout stays machine-parseable. Env var: SILVERGUN_LIBRARIESIO_API_KEY.
    private static IPackagePopularitySource SelectPopularitySource(string? source)
    {
        var apiKey = Environment.GetEnvironmentVariable(LibrariesIoApiKeyEnvVar);
        var hasKey = !string.IsNullOrWhiteSpace(apiKey);

        var useLibrariesIo = source?.Trim().ToLowerInvariant() switch
        {
            "librariesio" => true,
            "nuget" => false,
            _ => hasKey,   // auto
        };

        if (useLibrariesIo && hasKey)
        {
            Console.Error.WriteLine("check-squat: using libraries.io popularity source (SourceRank/dependents).");
            return new LibrariesIoPopularitySource(apiKey!);
        }

        if (useLibrariesIo)   // requested but no key available
            Console.Error.WriteLine($"check-squat: {LibrariesIoApiKeyEnvVar} not set; falling back to nuget.org.");

        Console.Error.WriteLine("check-squat: using nuget.org popularity source (download counts).");
        return new NuGetPopularitySource();
    }

    // Keep stdout machine-parseable: when JSON goes to stdout, log to file only.
    private static void ConfigureLogging(bool json, string? output, bool debug)
    {
        if (json && output is null)
            Runtime.WithFileLogging("Silvergun", "CLI", debug);
        else
            Runtime.WithFileAndConsoleLogging("Silvergun", "CLI", debug);
    }

    // Writes the report to stdout, or to a file when --output is given. Returns false on write failure.
    private static bool TryEmit(string text, string? output)
    {
        if (output is null)
        {
            Console.WriteLine(text);
            return true;
        }

        try
        {
            File.WriteAllText(output, text);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Failed to write report to {output}: {ex.Message}");
            return false;
        }
    }

    private static string AssemblySummary(AssemblyAnalysisReport report)
    {
        var capabilities = report.Capabilities;
        var lines = new List<string>
        {
            $"Assembly: {capabilities.AssemblyName}",
            $"Path:     {capabilities.AssemblyPath}",
            $"Findings: {capabilities.Findings.Count}",
            string.Empty
        };

        AppendMetadataSection(lines, report.Metadata);
        lines.Add(string.Empty);

        if (capabilities.Findings.Count == 0)
            lines.Add("No sensitive-API findings.");
        else
            AppendFindingsGrouped(lines, capabilities.Findings);

        lines.Add(string.Empty);
        AppendObfuscationSection(lines, report.Obfuscation);
        return string.Join(Environment.NewLine, lines);
    }

    // Lists each obfuscation finding, or "Obfuscation:  (none)" when the report is null/empty.
    private static void AppendObfuscationSection(List<string> lines, ObfuscationReport? obfuscation)
    {
        var findings = obfuscation?.Findings;
        if (findings is null || findings.Count == 0)
        {
            lines.Add("Obfuscation:  (none)");
            return;
        }

        lines.Add("Obfuscation:");
        lines.AddRange(findings.Select(f =>
            $"  {f.Kind}  {f.DetectedAs}  {f.CallerType}.{f.CallerMethod}  (len {f.EncodedLength}, entropy {f.Entropy:F2})"));
    }

    // Compact, security-relevant-first metadata block; "(unavailable)" when the read failed.
    private static void AppendMetadataSection(List<string> lines, AssemblyMetadataInfo? m)
    {
        if (m is null)
        {
            lines.Add("Metadata:  (unavailable)");
            return;
        }

        var resolved = m.References.Count(r => r.Resolved);
        lines.Add("Metadata:");
        lines.Add($"  Name/Version:   {m.Name} {m.Version ?? "?"}");
        lines.Add($"  Strong-named:   {YesNo(m.IsStrongNameSigned)}   (PKT {m.PublicKeyToken ?? "none"})");
        lines.Add($"  IL-only:        {YesNo(m.IsILOnly)}   (32-bit {YN(m.Requires32Bit)}  64-bit {YN(m.Requires64Bit)}  AMD {YN(m.RequiresAmdInstructionSet)}  foreign-types {YN(m.ContainsForeignTypes)})");
        lines.Add($"  Module kind:    {m.ModuleKind}");
        lines.Add($"  Target runtime: {m.TargetRuntimeVersion ?? "?"}");
        lines.Add($"  Entry point:    {YesNo(m.HasEntryPoint)}");
        lines.Add($"  Attributes:     {m.CustomAttributes.Count}");
        lines.Add($"  References:     {m.References.Count} ({resolved} resolved)");
    }

    private static string YesNo(bool b) => b ? "yes" : "no";

    private static string YN(bool b) => b ? "y" : "n";

    private static string PackageSummary(PackageCapabilityReport report, string nupkgPath)
    {
        var pkg = report.Package;
        var lines = new List<string>
        {
            $"Package: {pkg.Id} {pkg.Version}",
            $"Authors: {pkg.Authors ?? "(unknown)"}",
            $"Path:    {nupkgPath}",
            string.Empty,
            "Declared dependencies:"
        };

        if (pkg.Dependencies.Count == 0)
            lines.Add("  (none)");
        else
            lines.AddRange(pkg.Dependencies.Select(d => $"  {d.Id} {d.VersionRange} ({d.TargetFramework})"));

        if (report.Scripts.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Scripts:");
            lines.AddRange(report.Scripts.Select(s => $"  {s.Role}  {s.RelativePath}"));
        }

        AppendScriptFindingsSection(lines, report.ScriptFindings);

        lines.Add(string.Empty);
        lines.Add("Assemblies:");
        foreach (var result in report.Assemblies)
        {
            var asm = result.Assembly;
            lines.Add($"{asm.RelativePath} [{asm.Role}/{asm.TargetFramework ?? "?"}]");
            AppendMetaLine(lines, result.Metadata);
            if (result.SkipReason is not null)
                lines.Add($"  (skipped: {result.SkipReason})");
            else if (result.Report is null || result.Report.Findings.Count == 0)
                lines.Add("  (no findings)");
            else
                AppendFindingsGrouped(lines, result.Report.Findings);

            AppendObfuscationLine(lines, result.Obfuscation);
        }

        lines.Add(string.Empty);
        lines.Add($"Total findings: {report.AllFindings.Count()}");

        return string.Join(Environment.NewLine, lines);
    }

    // Lists script/content rule findings (rule id, severity, file, line), or a "none" line. Always emitted so the
    // section shape is stable whether or not a package ships scripts.
    private static void AppendScriptFindingsSection(List<string> lines, IReadOnlyList<ScriptFinding> findings)
    {
        lines.Add(string.Empty);
        if (findings.Count == 0)
        {
            lines.Add("Script findings:  (none)");
            return;
        }

        lines.Add($"Script findings: {findings.Count}");
        lines.AddRange(findings.Select(f =>
            $"  {f.RuleId} [{f.Severity}/{f.Confidence}]  {f.RelativePath}:{f.StartLine}  {f.RuleName}"));
    }

    // One compact per-assembly metadata line for scan-package; "(unavailable)" when the read failed.
    private static void AppendMetaLine(List<string> lines, AssemblyMetadataInfo? m)
    {
        if (m is null)
        {
            lines.Add("  meta: (unavailable)");
            return;
        }

        var resolved = m.References.Count(r => r.Resolved);
        lines.Add($"  meta: {m.Name} {m.Version ?? "?"}  signed={YN(m.IsStrongNameSigned)} ilonly={YN(m.IsILOnly)} kind={m.ModuleKind} refs={m.References.Count}({resolved} resolved)");
    }

    // Per-assembly obfuscation sub-section for scan-package; omitted entirely when null/empty.
    private static void AppendObfuscationLine(List<string> lines, ObfuscationReport? obfuscation)
    {
        var findings = obfuscation?.Findings;
        if (findings is null || findings.Count == 0)
            return;

        lines.Add($"  obfuscation: {findings.Count} finding(s)");
        lines.AddRange(findings.Select(f => $"    {f.Kind} {f.DetectedAs}  {f.CallerType}.{f.CallerMethod}"));
    }

    // Human summary for check-squat: a header and one line per finding, or a "none found" line.
    private static string SquatSummary(SquatCheckReport report)
    {
        var lines = new List<string> { $"Package: {report.PackageId}", string.Empty };

        if (report.Findings.Count == 0)
        {
            lines.Add("No likely typosquat targets found.");
            return string.Join(Environment.NewLine, lines);
        }

        lines.AddRange(report.Findings.Select(f =>
            $"  {f.SquattedCandidate}  (candidate {f.CandidateDownloads} dl vs target {f.TargetDownloads} dl)  [{f.Mutator}: {f.Reason}]"));
        return string.Join(Environment.NewLine, lines);
    }

    // Groups findings by Capability and appends the formatted lines (shared by both verbs).
    private static void AppendFindingsGrouped(List<string> lines, IEnumerable<ApiCallFinding> findings)
    {
        foreach (var group in findings.GroupBy(f => f.Capability).OrderBy(g => g.Key.ToString()))
        {
            lines.Add($"{group.Key} ({group.Count()})");
            lines.AddRange(group.Select(f =>
                $"  {f.Capability}  {f.CallerType}.{f.CallerMethod}  ->  {f.CalledApi}"));
            lines.Add(string.Empty);
        }
    }
    #endregion

    #region Fields
    // Env var carrying the libraries.io API key; presence auto-selects the libraries.io source. Never emitted.
    private const string LibrariesIoApiKeyEnvVar = "SILVERGUN_LIBRARIESIO_API_KEY";
    #endregion
}
