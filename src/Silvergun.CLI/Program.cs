using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Silvergun.CLI.Tests")]

namespace Silvergun.CLI;

using System.CommandLine;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Squats;
using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Entry point for the Silvergun CLI. Exposes the <c>analyze</c> verb, which runs
/// <see cref="AssemblyAnalyzer"/> + <see cref="CapabilityAnalysis"/> + <see cref="ObfuscationAnalysis"/> over a
/// .NET assembly; the <c>scan-package</c> verb, which runs <see cref="PackageScanner"/> over a <c>.nupkg</c>;
/// and the <c>check-squat</c> verb, which runs <see cref="SquatChecker"/> against a package id (network).
/// <para>
/// Exit codes are part of the CI contract (ADR 0003, amended by ADR 0024):
/// <list type="table">
///   <item><term>0</term><description>ran fine <b>and</b> the report's assessment says "Clean" — nothing gated and
///     the analysis was complete.</description></item>
///   <item><term>1</term><description>operational error: bad arguments, could not load the input, could not emit the
///     report. No verdict was produced.</description></item>
///   <item><term>2</term><description><c>--strict</c> <b>and</b> a finding gate tripped. A policy verdict on a
///     successful run — and it <b>beats 3</b>: a tripped gate is accurate and actionable even when coverage was
///     partial (the caveats are still printed).</description></item>
///   <item><term>3</term><description>analysis incomplete — one or more inputs could not be fully analysed (methods
///     that could not be analyzed, a packaged file that could not be analysed, a failed obfuscation analysis, a
///     failed assembly-metadata read, a partial transitive walk, vulnerability data not
///     obtained). A method is counted as not analyzed when the per-method guard catches <b>any</b> throw — including
///     the metadata reads that happen before its body is touched — so this contract names no cause beyond "could not
///     be analyzed"; on hostile input a metadata-read failure is a more suspicious signal than a lifting failure, and
///     CI must not read the count as the mundane case. <b>Not</b> gated on <c>--strict</c>: 1 and 3 both mean "the
///     tool could not do its job", and only 2 is a policy verdict. <c>--allow-incomplete</c> downgrades 3 to 0 while
///     still printing every caveat.</description></item>
/// </list>
/// <b>Any other code is a crash the OS chose, not one we return</b> — <c>Environment.FailFast</c> (which CCI's
/// <c>Debug.Assert</c> routes to, ADR 0021) is measured at <b>35</b> in this project, and a stack overflow's code is
/// not yet measured here. A killed process emits <b>no report at all</b>, so CI must treat an unknown exit code as a
/// tooling incident and must <b>never</b> read a missing or empty findings file as clean.
/// </para>
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
        var richOption = new Option<bool>("--rich")
        {
            Description = "Render the rich report (ANSI color + Unicode); default is plain ASCII."
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
        var allowIncompleteOption = new Option<bool>("--allow-incomplete")
        {
            Description = "Do not exit with code 3 when the analysis was incomplete (ADR 0024); the caveats are still reported."
        };
        var noResolveOption = new Option<bool>("--no-resolve")
        {
            Description = "Skip best-effort assembly-reference resolution when reading metadata."
        };
        var healthOption = new Option<bool>("--health")
        {
            Description = "Also resolve the package's GitHub repository from the local nuspec and attach a " +
                          "project-health section (network; advisory — never affects the exit code)."
        };
        var noYaraOption = new Option<bool>("--no-yara")
        {
            Description = "Skip YARA malware-signature scanning of the package's extracted files (perf/opt-out)."
        };
        var noVulnsOption = new Option<bool>("--no-vulns")
        {
            Description = "Skip the OSV.dev known-vulnerability check (runs by default; network — this restores fully offline)."
        };
        var depthOption = new Option<int>("--depth")
        {
            Description = "Resolve and vulnerability-check transitive dependencies up to this depth (default 0 = direct deps only; network). Approximate — not a restore."
        };
        // Reject a negative --depth at parse time (non-zero exit, message on stderr), mirroring the --source posture;
        // 0 (the default) and positive values stay valid. The handler clamps positives to a sane maximum.
        depthOption.Validators.Add(result =>
        {
            if (result.GetValueOrDefault<int>() < 0)
                result.AddError("Invalid --depth value; must be 0 or greater (0 = direct dependencies only).");
        });
        var healthPackageIdArgument = new Argument<string>("package-id")
        {
            Description = "The NuGet package id whose source-project (GitHub) health to report."
        };

        // --json (machine) and --rich (rich) are two mutually-exclusive format selectors; reject both at parse
        // time (non-zero exit, message on stderr) before any handler runs, mirroring the --source validation posture.
        void RejectJsonWithRich(System.CommandLine.Parsing.CommandResult result)
        {
            if (result.GetValue(jsonOption) && result.GetValue(richOption))
                result.AddError("--json and --rich are mutually exclusive; specify at most one output format.");
        }

        var analyzeCommand = new Command("analyze", "Analyze a .NET assembly for sensitive-API capabilities.")
        {
            assemblyPathArgument, jsonOption, richOption, outputOption, strictOption, debugOption, noResolveOption, allowIncompleteOption
        };
        analyzeCommand.Validators.Add(RejectJsonWithRich);
        analyzeCommand.SetAction(parse => RunAnalyze(
            parse.GetValue(assemblyPathArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(richOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(noResolveOption),
            parse.GetValue(allowIncompleteOption)));

        var scanPackageCommand = new Command("scan-package", "Scan a .nupkg for sensitive-API capabilities.")
        {
            nupkgPathArgument, jsonOption, richOption, outputOption, strictOption, debugOption, noResolveOption, healthOption, noYaraOption, noVulnsOption, depthOption, allowIncompleteOption
        };
        scanPackageCommand.Validators.Add(RejectJsonWithRich);
        scanPackageCommand.SetAction(parse => RunScanPackage(
            parse.GetValue(nupkgPathArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(richOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(noResolveOption),
            parse.GetValue(healthOption),
            parse.GetValue(noYaraOption),
            parse.GetValue(noVulnsOption),
            parse.GetValue(depthOption),
            parse.GetValue(allowIncompleteOption)));

        // check-squat hits nuget.org, so its handler is async; the sync action bridges via GetAwaiter().GetResult()
        // to keep System.CommandLine's synchronous Invoke path (stdout purity handled by ConfigureLogging).
        var sourceOption = new Option<string?>("--source")
        {
            Description = "Popularity source: 'nuget', 'librariesio', or omit for auto " +
                          "(libraries.io when SILVERGUN_LIBRARIESIO_API_KEY is set, else nuget.org)."
        };
        // Reject an explicit but unrecognized --source at parse time (non-zero exit, message on stderr);
        // null/absent stays valid (= auto). Absent options never trigger this validator.
        sourceOption.Validators.Add(result =>
        {
            var value = result.GetValueOrDefault<string?>();
            if (!IsValidSource(value))
                result.AddError($"Invalid --source value '{value}'. Valid values: nuget, librariesio (or omit for auto).");
        });
        var checkSquatCommand = new Command("check-squat", "Check a NuGet package id for likely typosquatting (network).")
        {
            packageIdArgument, jsonOption, richOption, outputOption, strictOption, debugOption, sourceOption
        };
        checkSquatCommand.Validators.Add(RejectJsonWithRich);
        checkSquatCommand.SetAction(parse => RunCheckSquat(
            parse.GetValue(packageIdArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(richOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(sourceOption)).GetAwaiter().GetResult());

        // health hits nuget.org + the GitHub API, so its handler is async; the sync action bridges via
        // GetAwaiter().GetResult(), like check-squat. Advisory-only: no --strict gate (health never gates exit codes).
        var healthCommand = new Command("health", "Report source-project (GitHub) health for a NuGet package (network, advisory).")
        {
            healthPackageIdArgument, jsonOption, richOption, outputOption, debugOption
        };
        healthCommand.Validators.Add(RejectJsonWithRich);
        healthCommand.SetAction(parse => RunHealth(
            parse.GetValue(healthPackageIdArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(richOption),
            parse.GetValue(outputOption),
            parse.GetValue(debugOption)).GetAwaiter().GetResult());

        var root = new RootCommand("Silvergun — static capability analysis for .NET assemblies.")
        {
            analyzeCommand, scanPackageCommand, checkSquatCommand, healthCommand
        };

        return root.Parse(args).Invoke();
    }

    private static int RunAnalyze(string assemblyPath, bool json, bool rich, string? output, bool strict, bool debug, bool noResolve, bool allowIncomplete)
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

        // Metadata read is best-effort — a failure leaves Metadata null. That null is a COMPLETENESS caveat (ADR 0024,
        // same class as the failed obfuscation analysis above): the report cannot claim "Clean" when the identity facts
        // it prints were never read, so it reaches the exit code as incompleteness (3), never as a finding (2).
        var metadataResult = AssemblyMetadata.Read(assemblyPath, !noResolve);
        var report = new AssemblyAnalysisReport(
            metadataResult.IsSuccess ? metadataResult.Value : null, reportResult.Value, obfuscation);

        // The SAME assessment drives the report footer (via the renderer, which calls this same factory) and the exit
        // code below — ADR 0024's load-bearing invariant is that exit 0 ⇔ the footer would say "Clean".
        var completeness = CompletenessAssessment.ForAssembly(report);

        var emitted = json
            ? TryEmit(WithCompleteness(report.ToJson(), completeness), output)
            : EmitHumanReport(c => AssemblyReportRenderer.Render(c, report), output, rich);
        if (!emitted)
            return 1;

        ReportIncompleteness("analyze", completeness, allowIncomplete);

        return AnalyzeExitCode(report, strict, allowIncomplete);
    }

    private static int RunScanPackage(string nupkgPath, bool json, bool rich, string? output, bool strict, bool debug, bool noResolve, bool health, bool noYara, bool noVulns, int depth, bool allowIncomplete)
    {
        ConfigureLogging(json, output, debug);

        var scanResult = PackageScanner.Scan(nupkgPath, resolveReferences: !noResolve, runYara: !noYara);
        if (!scanResult.IsSuccess)
        {
            Console.Error.WriteLine(scanResult.Message);
            return 1;
        }

        var report = scanResult.Value;

        // YARA was requested (not --no-yara) but no engine is available on this platform/config: note it on stderr
        // (like --health) so stdout/JSON stay unaffected. On Windows the in-process backend is always present.
        if (!noYara && !YaraScannerFactory.BackendAvailable)
            Console.Error.WriteLine(
                "scan-package: YARA malware-signature scanning unavailable (no engine; set SILVERGUN_YARA_PATH to the yara binary). Continuing without it.");

        // --health is the ONLY thing that adds a network call to scan-package (the offline scan above stays offline).
        // Repo resolution is offline (local nuspec); only the GitHub lookup is network. Advisory — never touches the
        // exit code below. Best-effort/never-throws: an unresolvable repo or a failed lookup just leaves ProjectHealth null.
        if (health)
        {
            report = report with { ProjectHealth = ResolveLocalHealth(report.Package) };
            if (report.ProjectHealth is null)
                Console.Error.WriteLine("scan-package: project-health requested but unavailable (no GitHub repository resolved or lookup failed).");
        }

        // Resolver-lite transitive dependency resolution (ADR 0018) is opt-in via --depth and runs ONLY when depth >= 1
        // AND OSV is enabled (!--no-vulns), because OSV is currently its ONLY consumer. Future consumers (transitive
        // typosquat/health/capability checks) should also trigger resolution here. It clamps depth to a sane max, lives
        // entirely in the CLI layer (PackageScanner.Scan stays offline, like --health/OSV), and degrades honestly: any
        // failure ⇒ DependencyResolution=Partial + empty set + one stderr note, never a crash or a false clean.
        var clampedDepth = Math.Clamp(depth, 0, MaxResolveDepth);
        if (clampedDepth >= 1 && !noVulns)
        {
            var resolution = ResolveTransitiveDependencies(report.Package, clampedDepth);
            report = report with { ResolvedDependencies = resolution.Resolved, DependencyResolution = resolution.Status };
            if (resolution.Status == DependencyResolutionStatus.Partial)
                Console.Error.WriteLine(
                    "scan-package: transitive dependency resolution INCOMPLETE (some packages unresolved); transitive coverage is PARTIAL.");
        }

        // OSV known-vulnerability check runs BY DEFAULT (opt out with --no-vulns) — the ONLY other network call besides
        // --health, and it too lives entirely in the CLI layer (PackageScanner.Scan stays offline). Best-effort/never-
        // throws: build queries from the local nuspec identity (+ resolved transitive set when --depth ran), ask OSV,
        // attach findings. Any failure/empty ⇒ no findings + a one-line stderr note; stdout/JSON and the exit-code gates
        // below are otherwise unaffected. --no-vulns leaves the status at its default NotChecked (no OSV call). Otherwise
        // ask OSV and record whether the check completed (Completed) or could not be reached (Unavailable) — so a genuine
        // clean result and an outage are distinguishable in both the human report and --json (ADR 0017 amendment).
        if (!noVulns)
        {
            // When a resolved transitive set is present, OSV checks every resolved package at its concrete version;
            // otherwise (depth 0) it checks the package + declared direct deps at their range floor (today's behavior).
            var (findings, status) = ResolveVulnerabilities(report.Package, report.ResolvedDependencies);
            report = report with { Vulnerabilities = findings, VulnerabilitiesStatus = status };
        }

        // As in RunAnalyze: one assessment, two projections (the footer via the renderer, the exit code below).
        var completeness = CompletenessAssessment.ForPackage(report);

        var emitted = json
            ? TryEmit(WithCompleteness(report.ToJson(), completeness), output)
            : EmitHumanReport(c => PackageReportRenderer.Render(c, report, nupkgPath), output, rich);
        if (!emitted)
            return 1;

        ReportIncompleteness("scan-package", completeness, allowIncomplete);

        return ScanPackageExitCode(report, strict, allowIncomplete);
    }

    // The analyze verb's exit code, as ONE seam over the whole report (ADR 0024). This exists so the gate predicate —
    // which findings gate, and how incompleteness is derived — is written exactly once: the run method above and the
    // invariant tests both call this, instead of the tests keeping a hand-written third copy that can silently drift
    // from what ships. Recomputing the assessment here (rather than taking it as a parameter) is deliberate: it is
    // pure, and it makes the exit code derive from the report itself, exactly as the footer does.
    internal static int AnalyzeExitCode(AssemblyAnalysisReport report, bool strict, bool allowIncomplete) =>
        ScanExitCode(
            strict,
            report.Capabilities.Findings.Count > 0,
            (report.Obfuscation?.Findings.Count ?? 0) > 0,
            hasScriptFindings: false,
            isIncomplete: !CompletenessAssessment.ForAssembly(report).IsComplete,
            allowIncomplete: allowIncomplete);

    // The scan-package verb's exit code, as ONE seam over the whole report (see AnalyzeExitCode).
    // Only findings from real script/build content gate --strict. Findings from the declarative package manifest
    // (ScriptFindingSource.PackageMetadata) are advisory: still reported in full — human report, footer counts and
    // --json are unchanged — but they never fail CI on their own, mirroring the ADR 0015 "advisory never gates"
    // precedent. Nothing in a .nuspec executes, and code-oriented rules over prose are noise by construction
    // (docs/agent/tasks/script-rule-precision.md).
    internal static int ScanPackageExitCode(PackageCapabilityReport report, bool strict, bool allowIncomplete) =>
        ScanExitCode(
            strict,
            report.AllFindings.Any(),
            report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0),
            report.ScriptFindings.Any(f => f.Source == ScriptFindingSource.Script),
            report.YaraFindings.Count > 0,
            report.Vulnerabilities.Count > 0,
            isIncomplete: !CompletenessAssessment.ForPackage(report).IsComplete,
            allowIncomplete: allowIncomplete);

    // Best-effort OSV.dev known-vulnerability lookup for scan-package (default-on; ADR 0017). Builds queries from the
    // LOCAL nuspec identity (package@version + declared deps at their range floor), then sync-bridges the network call
    // (like check-squat/health). Never throws: any exception degrades to Unavailable + empty. Reachability (Queried) is
    // mapped to a status and a single concise stderr note distinguishing "unavailable" (could not reach OSV — NOT a
    // clean result) from "no known vulnerabilities" (the check ran and found none) — so stdout/JSON stay pure.
    private static (IReadOnlyList<VulnerabilityFinding> Findings, VulnerabilityScanStatus Status) ResolveVulnerabilities(
        PackageIdentityInfo pkg, IReadOnlyList<ResolvedDependency> resolved)
    {
        try
        {
            // With a resolver-lite set (--depth >= 1) OSV covers every resolved package at its concrete version;
            // otherwise it uses the direct-only builder (package-exact + declared deps at range floor — depth 0).
            var queries = resolved.Count > 0
                ? OsvQueryBuilder.Build(pkg, resolved)
                : OsvQueryBuilder.Build(pkg);
            var result = new OsvClient().QueryAsync(queries).GetAwaiter().GetResult();
            var status = result.Queried ? VulnerabilityScanStatus.Completed : VulnerabilityScanStatus.Unavailable;
            Console.Error.WriteLine(status == VulnerabilityScanStatus.Unavailable
                ? "scan-package: known-vulnerability check UNAVAILABLE (could not reach OSV); package NOT verified against known CVEs."
                : result.Findings.Count == 0
                    ? "scan-package: no known vulnerabilities found."
                    : $"scan-package: found {result.Findings.Count} known vulnerabilit{(result.Findings.Count == 1 ? "y" : "ies")}.");
            return (result.Findings, status);
        }
        catch
        {
            Console.Error.WriteLine("scan-package: known-vulnerability check UNAVAILABLE (could not reach OSV); package NOT verified against known CVEs.");
            return (Array.Empty<VulnerabilityFinding>(), VulnerabilityScanStatus.Unavailable);
        }
    }

    // Best-effort resolver-lite transitive dependency walk for scan-package --depth (ADR 0018). Seeds the resolver from
    // the LOCAL nuspec's declared direct deps (mapping each dep's version range via NuGet.Versioning, skipping any that
    // don't parse), then sync-bridges the network walk (like ResolveVulnerabilities/health). The resolver never throws,
    // but this is wrapped defensively anyway: any failure degrades to a Partial result with an empty set (honest — never
    // a false clean), which the caller surfaces on stderr and in the render.
    private static DependencyResolutionResult ResolveTransitiveDependencies(PackageIdentityInfo pkg, int depth)
    {
        try
        {
            var seeds = (pkg.Dependencies ?? Array.Empty<PackageDependencyInfo>())
                .Select(d => global::NuGet.Versioning.VersionRange.TryParse(d.VersionRange, out var range) ? (d.Id, Range: range) : (d.Id, Range: null))
                .Where(s => s.Range is not null)
                .Select(s => (s.Id, s.Range!))
                .ToArray();

            return new NuGetDependencyResolver(new NuGetPackageDependencyFetcher())
                .ResolveAsync(seeds, depth)
                .GetAwaiter().GetResult();
        }
        catch
        {
            return new DependencyResolutionResult(DependencyResolutionStatus.Partial, Array.Empty<ResolvedDependency>());
        }
    }

    // Runs the network squat check for one package id; logging is routed off stdout by ConfigureLogging.
    private static async Task<int> RunCheckSquat(string packageId, bool json, bool rich, string? output, bool strict, bool debug, string? source)
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

        var emitted = json
            ? TryEmit(report.ToJson(), output)
            : EmitHumanReport(c => SquatReportRenderer.Render(c, report), output, rich);
        if (!emitted)
            return 1;

        return ScanExitCode(strict, findings.Count > 0, hasObfuscation: false, hasScriptFindings: false);
    }

    // Runs the advisory project-health lookup for one package id (ADR 0015): resolve its GitHub repo from nuget.org
    // metadata, then query the GitHub API. Advisory-only — exit 0 on success INCLUDING "unavailable" (no repo / no
    // health); 1 only on a hard emit failure. No --strict gate. The token (SILVERGUN_GITHUB_TOKEN) is never logged.
    private static async Task<int> RunHealth(string packageId, bool json, bool rich, string? output, bool debug)
    {
        ConfigureLogging(json, output, debug);

        Console.Error.WriteLine($"health: resolving GitHub repository for '{packageId}' via nuget.org metadata.");
        var repo = await new NuGetRepositoryResolver().ResolveAsync(packageId);

        ProjectHealth? health = null;
        string? unavailable;
        if (repo is null)
        {
            unavailable = "no GitHub repository resolved";
        }
        else
        {
            health = await new GitHubProjectHealthSource(GitHubToken("health")).GetHealthAsync(repo);
            unavailable = health is null ? "GitHub project-health lookup unavailable" : null;
        }

        var report = new ProjectHealthReport(packageId, repo, health, unavailable, DateTimeOffset.UtcNow);

        var emitted = json
            ? TryEmit(report.ToJson(), output)
            : EmitHumanReport(c => HealthReportRenderer.Render(c, report), output, rich);

        // Advisory: unavailable is a normal outcome (exit 0). Only a write/emit failure is a hard error.
        return emitted ? 0 : 1;
    }

    // Best-effort project-health lookup from the LOCAL nuspec (scan-package --health): repo resolution is offline
    // (GitHubRepoUrl.TryParse over the nuspec's repository/project URL); only the GitHub call is network. Prefers
    // <repository> then <projectUrl>. Never throws; a non-github or unresolvable URL, or a failed lookup, yields null.
    private static ProjectHealth? ResolveLocalHealth(PackageIdentityInfo pkg)
    {
        // Try each candidate in order (mirrors NuGetRepositoryResolver.ResolveAsync): fall back to <projectUrl> when
        // <repository> is absent OR non-GitHub. First that parses to a GitHub repo wins.
        foreach (var candidate in new[] { pkg.RepositoryUrl, pkg.ProjectUrl })
            if (GitHubRepoUrl.TryParse(candidate, out var repo))
                return new GitHubProjectHealthSource(GitHubToken("scan-package")).GetHealthAsync(repo).GetAwaiter().GetResult();

        return null;
    }

    // Reads the optional GitHub API token from the environment. Logs (to stderr) only WHICH mode is used — the token
    // value itself is never emitted. Keyless works (~60 req/hr); a token raises the limit to 5000/hr.
    private static string? GitHubToken(string verb)
    {
        var token = Environment.GetEnvironmentVariable(GitHubTokenEnvVar);
        var hasToken = !string.IsNullOrWhiteSpace(token);
        Console.Error.WriteLine(hasToken
            ? $"{verb}: using the GitHub API with a token ({GitHubTokenEnvVar} set)."
            : $"{verb}: using the GitHub API keyless ({GitHubTokenEnvVar} not set; ~60 requests/hour).");
        return hasToken ? token : null;
    }

    // Chooses the popularity source for check-squat. Auto (default): libraries.io when the API key env var is set,
    // else keyless nuget.org. An explicit --source overrides. The selection (never the key) is logged to stderr so
    // stdout stays machine-parseable. Env var: SILVERGUN_LIBRARIESIO_API_KEY.
    internal static IPackagePopularitySource SelectPopularitySource(string? source)
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

    // Whether an explicit --source value is recognized. null/absent = auto and is always valid; comparison is
    // case-insensitive and trims surrounding whitespace (mirrors SelectPopularitySource's parsing).
    internal static bool IsValidSource(string? source) =>
        source is null || source.Trim().ToLowerInvariant() is "nuget" or "librariesio";

    // The CI gate exit-code decision (ADR 0003, amended by ADR 0024). Pure — the run methods pass the concrete gate
    // inputs so this stays independently testable. YARA findings are high-confidence IOCs and gate too (ADR 0016);
    // known vulnerabilities gate too (ADR 0017). The trailing defaults keep the existing non-package callers/tests
    // unchanged.
    //
    // Precedence, exactly:
    //   1. strict && any finding gate  => 2. A tripped gate is accurate and actionable, so 2 BEATS 3 even when the
    //      analysis was incomplete — the incompleteness is a caveat in the report, not a reason to hide the verdict.
    //   2. else isIncomplete && !allowIncomplete => 3. NOT gated on --strict: opting out of *findings* gating is not
    //      opting out of being told coverage was partial.
    //   3. else => 0, which (with --allow-incomplete off) means the report's footer says "Clean".
    // --allow-incomplete only suppresses the GATE; the caveats are always disclosed (report + one stderr note).
    internal static int ScanExitCode(
        bool strict, bool hasCapabilityFindings, bool hasObfuscation, bool hasScriptFindings,
        bool hasYaraFindings = false, bool hasVulnerabilities = false,
        bool isIncomplete = false, bool allowIncomplete = false) =>
        strict && (hasCapabilityFindings || hasObfuscation || hasScriptFindings || hasYaraFindings || hasVulnerabilities) ? 2
        : isIncomplete && !allowIncomplete ? 3
        : 0;

    // Adds the completeness fields to a report's --json output ADDITIVELY, by TEXTUAL SPLICE: the report's own
    // canonical JSON is carried over verbatim and one "Completeness" object is inserted before its final "}", so
    // only the new block is ever serialized here. Existing properties therefore keep their names, values, order and
    // exact BYTES by construction — not because two writers happen to agree. They do not: re-serializing through
    // JsonNode round-trips a DateTimeOffset as a *string*, and Utf8JsonWriter.WriteStringValue(string) runs it
    // through JavaScriptEncoder.Default, which rewrites the '+' of an ISO-8601 UTC offset (AnalyzedAt's "+00:00")
    // into its \uXXXX escape, where WriteStringValue(DateTimeOffset) writes it literally. Relaxing the encoder is not the fix
    // either — it would stop escaping '<', '>', '&' and '\'', which legitimately occur in pre-existing fields
    // (generic type names in CalledApi), trading one silent corruption for another.
    // Done over the text (rather than on the report records, which live in the analysis libraries) so the CLI owns
    // its own projection.
    // internal (not private) so its eight degenerate paths — empty/whitespace, non-object, "{}", compact single-line,
    // LF vs CRLF, an unindented payload — are asserted by tests rather than by inspection.
    internal static string WithCompleteness(string json, CompletenessAssessment completeness)
    {
        // Anything we cannot splice into safely is returned UNCHANGED: a corrupt report is worse than a missing
        // completeness block. Covers empty/whitespace input, a payload that is not a top-level object, and "{}"
        // (no property to append after, and no observed formatting to imitate).
        var body = SplicableObjectBody(json);
        if (body is null)
            return json;

        // Match the payload's own formatting: its line ending, and the indentation of a top-level property — the
        // last line of the body is always one (a scalar property, or the closing brace/bracket of a nested value),
        // so its leading spaces are that level (2 for the WriteIndented default).
        var newline = body.Contains("\r\n", StringComparison.Ordinal) ? "\r\n"
            : body.Contains('\n') ? "\n"
            : Environment.NewLine;
        var lastLine = body[(body.LastIndexOf(newline, StringComparison.Ordinal) + newline.Length)..];
        var indent = lastLine.Length - lastLine.TrimStart(' ').Length is var width && width > 0
            ? new string(' ', width)
            : DefaultJsonIndent;

        var block = completeness.ToJson().ReplaceLineEndings(newline + indent);
        return $"{body},{newline}{indent}\"{CompletenessJsonProperty}\": {block}{newline}}}";
    }

    // The pre-existing bytes of a top-level JSON object, up to (excluding) its closing brace and any trailing
    // whitespace — i.e. everything a new last property can be appended after. Null when the payload has no such
    // shape (empty, not an object, or an object with no properties).
    private static string? SplicableObjectBody(string? json)
    {
        var trimmed = json?.TrimEnd() ?? string.Empty;
        if (trimmed.Length < 2 || trimmed[0] != '{' || trimmed[^1] != '}')
            return null;

        var body = trimmed[..^1].TrimEnd();
        return body[^1] == '{' ? null : body;
    }

    // Discloses incompleteness on stderr in EVERY output mode (including --json and --output, where a human may never
    // read the report), naming each specific gap. --allow-incomplete suppresses the exit-3 gate, never this note.
    private static void ReportIncompleteness(string verb, CompletenessAssessment completeness, bool allowIncomplete)
    {
        if (completeness.IsComplete)
            return;

        Console.Error.WriteLine(
            $"{verb}: analysis INCOMPLETE - {string.Join("; ", completeness.Caveats)}. " +
            (allowIncomplete
                ? "--allow-incomplete given; exit code NOT gated on this."
                : "Exit code 3; pass --allow-incomplete to downgrade it to 0."));
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

    // Renders a human (Spectre) report with explicit, flag-driven richness (ADR 0014). Default (rich=false):
    // plain ASCII-only, no-ANSI/no-color, forced regardless of TTY. --rich (rich=true): rich ANSI+color+Unicode,
    // forced regardless of redirection (NO_COLOR still strips color). To --output the same mode is written to a
    // buffer then persisted via TryEmit. Never uses interactive/live widgets.
    private static bool EmitHumanReport(Action<IAnsiConsole> render, string? output, bool rich)
    {
        if (output is null)
        {
            render(CreateConsole(Console.Out, rich, tty: !Console.IsOutputRedirected));
            return true;
        }

        var buffer = new StringWriter();
        render(CreateConsole(buffer, rich, tty: false));
        return TryEmit(buffer.ToString(), output);
    }

    // Builds the report console for a given richness. Rich: ANSI + a color system (stripped to NoColors under
    // NO_COLOR) + Unicode borders/glyphs. Plain: no ANSI, no color, ASCII-only. Off a TTY the width is pinned so
    // default output is deterministic regardless of redirection; on a TTY Spectre may detect it for wrapping.
    private static IAnsiConsole CreateConsole(TextWriter writer, bool rich, bool tty)
    {
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = rich ? AnsiSupport.Yes : AnsiSupport.No,
            ColorSystem = rich && !NoColorRequested() ? ColorSystemSupport.Standard : ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer)
        });
        console.Profile.Capabilities.Unicode = rich;
        if (!tty)
            console.Profile.Width = DefaultReportWidth;
        return console;
    }

    private static bool NoColorRequested() =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NO_COLOR"));
    #endregion

    #region Fields
    // Env var carrying the libraries.io API key; presence auto-selects the libraries.io source. Never emitted.
    private const string LibrariesIoApiKeyEnvVar = "SILVERGUN_LIBRARIESIO_API_KEY";

    // Env var carrying the optional GitHub API token for project-health lookups (health verb, scan-package --health).
    // Presence raises the GitHub rate limit from ~60/hr to 5000/hr. Never emitted/logged (only its presence is).
    private const string GitHubTokenEnvVar = "SILVERGUN_GITHUB_TOKEN";

    // Top-level --json property carrying the completeness projection (ADR 0024). Additive: every pre-existing
    // property keeps its name, value and position; this one is appended.
    private const string CompletenessJsonProperty = "Completeness";

    // Fallback indentation for the spliced completeness block when the payload's own formatting cannot be observed
    // (a compact, single-line report). Matches JsonSerializerOptions.WriteIndented's default.
    private const string DefaultJsonIndent = "  ";

    // Deterministic report width used when not attached to a TTY (redirected stdout or a file), so default
    // (ASCII) output doesn't vary with the ambient terminal. A TTY may still be measured for wrapping.
    private const int DefaultReportWidth = 100;

    // Sane upper bound for --depth (resolver-lite, ADR 0018): a positive request is clamped to this so a large value
    // can't fan out into an unbounded network walk. Resolver-lite is an approximation, not a restore — depth stays small.
    private const int MaxResolveDepth = 8;
    #endregion
}
