using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Silvergun.CLI.Tests")]

namespace Silvergun.CLI;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Text.Json;
using System.Text.Json.Serialization;

using Spectre.Console;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.MCPServer;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;
using Silvergun.PackageAnalysis.NuGet.Squats;
using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// Entry point for the Silvergun CLI. Exposes the <c>analyze</c> verb, which runs
/// <see cref="AssemblyAnalyzer"/> + <see cref="CapabilityAnalysis"/> + <see cref="ObfuscationAnalysis"/> over a
/// .NET assembly; the <c>scan-package</c> verb, which runs <see cref="PackageScanner"/> over a <c>.nupkg</c>;
/// the <c>check-squat</c> verb, which runs <see cref="SquatChecker"/> against a package id (network); and the
/// <c>capability-diff</c> verb, which compares two <c>--snapshot</c> files written by <c>analyze</c>/
/// <c>scan-package</c> (capability-diff-versions task, Phase B; offline).
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
        // `mcp` (ADR 0039 D9): stdout belongs to the MCP transport. Take the raw stream first, then point Console.Out at
        // stderr before anything can write, so help, parse errors and any library's Console.Out text land on stderr.
        var inMcp = args is [var first, ..] && first == McpVerb;
        Stream? mcpStdout = null;
        if (inMcp)
        {
            mcpStdout = Console.OpenStandardOutput();
            Console.SetOut(Console.Error);
        }

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
        var snapshotOption = new Option<string?>("--snapshot")
        {
            Description = "Also write a JSON array of CapabilitySnapshot (one per analyzed assembly) to this file, " +
                          "for later comparison with capability-diff. Does not affect stdout, the human report, --json, or the exit code."
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
        var reachabilityOption = new Option<bool>("--reachability")
        {
            Description = "Also run the call-graph reachability pass (out of process; up to 600 s and a 4 GiB worker per package). " +
                          "Informational: never affects the exit code, --strict, the completeness footer or --snapshot."
        };
        var ssaOption = new Option<bool>("--ssa")
        {
            Description = "With --reachability, also derive argument values at sink call sites with SSA (in the same worker; adds " +
                          "about half to its time). SSA-derived and informational, like --reachability."
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
        void RejectJsonWithRich(CommandResult result)
        {
            if (result.GetValue(jsonOption) && result.GetValue(richOption))
                result.AddError("--json and --rich are mutually exclusive; specify at most one output format.");
        }

        // SSA runs inside the reachability pass's worker, so its cost is only ever paid on purpose (ssa-facts-s5.md D1).
        void RejectSsaWithoutReachability(CommandResult result)
        {
            if (result.GetValue(ssaOption) && !result.GetValue(reachabilityOption))
                result.AddError("--ssa needs --reachability: SSA facts are derived at the call sites the reachability pass finds.");
        }

        var analyzeCommand = new Command("analyze", "Analyze a .NET assembly for sensitive-API capabilities.")
        {
            assemblyPathArgument, jsonOption, richOption, outputOption, strictOption, debugOption, noResolveOption, allowIncompleteOption, snapshotOption
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
            parse.GetValue(allowIncompleteOption),
            parse.GetValue(snapshotOption)));

        var scanPackageCommand = new Command("scan-package", "Scan a .nupkg for sensitive-API capabilities.")
        {
            nupkgPathArgument, jsonOption, richOption, outputOption, strictOption, debugOption, noResolveOption, healthOption, noYaraOption, noVulnsOption, depthOption, allowIncompleteOption, snapshotOption, reachabilityOption, ssaOption
        };
        scanPackageCommand.Validators.Add(RejectJsonWithRich);
        scanPackageCommand.Validators.Add(RejectSsaWithoutReachability);
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
            parse.GetValue(allowIncompleteOption),
            parse.GetValue(snapshotOption),
            parse.GetValue(reachabilityOption),
            parse.GetValue(ssaOption)));

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

        // capability-diff (capability-diff-versions task, Phase B; corrected 2026-08-20): compares two --snapshot
        // files, matched by the composite key (AssemblyName, TargetFramework) — see CapabilityDiffReport.Compare
        // for why name alone is wrong (multi-targeted packages emit one element per TFM under a shared name).
        // Offline, synchronous — no network call, unlike check-squat/health.
        //
        // TRUST NOTE (2026-08-20 code review): the baseline file is trusted by construction — see the verb
        // Description below and CapabilityDiffReport's class doc for the full statement.
        var baselineArgument = new Argument<string>("baseline")
        {
            Description = "Path to the baseline capability-snapshot JSON file (a --snapshot output of analyze/scan-package)."
        };
        var candidateArgument = new Argument<string>("candidate")
        {
            Description = "Path to the candidate capability-snapshot JSON file to compare against the baseline."
        };
        var allowTfmMismatchOption = new Option<bool>("--allow-tfm-mismatch")
        {
            Description = "Proceed when NOTHING matches between baseline and candidate — every (assembly, target " +
                          "framework) pair on one side is absent from the other, so no capability comparison is " +
                          "possible at all (a vacuous diff would otherwise silently read as \"no changes\"). Does " +
                          "NOT relax matching itself: a shared (assembly, TFM) pair is always compared, and TFMs " +
                          "unique to one side are always reported as added/dropped regardless of this flag."
        };
        var capabilityDiffCommand = new Command("capability-diff",
            "Compare two capability snapshots (--snapshot output of analyze/scan-package) and report what capabilities changed. " +
            "The baseline file is a TRUST ANCHOR: it is compared as-is, so a baseline hand-edited (or maliciously " +
            "committed) to already claim a capability makes a genuine addition in the candidate invisible. Review " +
            "changes to a baseline file like code, and regenerate it from a trusted scan rather than hand-editing it.")
        {
            baselineArgument, candidateArgument, jsonOption, richOption, outputOption, strictOption, debugOption, allowIncompleteOption, allowTfmMismatchOption
        };
        capabilityDiffCommand.Validators.Add(RejectJsonWithRich);
        capabilityDiffCommand.SetAction(parse => RunCapabilityDiff(
            parse.GetValue(baselineArgument)!,
            parse.GetValue(candidateArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(richOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(allowIncompleteOption),
            parse.GetValue(allowTfmMismatchOption)));

        // __worker (ADR 0033 FINAL FORM): HIDDEN internal verbs the CLI runs as its own child processes; never listed in
        // --help. `__worker yara --protocol 1` speaks worker protocol v1 (docs/agent/tasks/yarax-worker.md) on
        // stdin/stdout. The protocol value is taken as a string and checked by the worker itself, so an unsupported one
        // gets a protocol `fatal` (exit 3) rather than a parser error.
        var protocolOption = new Option<string?>("--protocol")
        {
            Description = "Worker protocol version (only 1 is supported)."
        };
        // --timeout (amendment G3) is taken as a string for the same reason: absent means the product default, and an
        // invalid value — out of range (W-D), or a bare `--timeout` with no value — is a protocol `fatal` (exit 3).
        var timeoutOption = new Option<string?>("--timeout")
        {
            Description = $"Per-file engine scan timeout in whole seconds ({WorkerProtocol.MinTimeoutSeconds} to {WorkerProtocol.MaxTimeoutSeconds}; default {WorkerProtocol.DefaultTimeoutSeconds}).",
            Arity = ArgumentArity.ZeroOrOne
        };
        var workerYaraCommand = new Command("yara", "Internal: the out-of-process YARA scan worker.")
        {
            protocolOption, timeoutOption
        };
        workerYaraCommand.SetAction(parse => RunYaraWorker(
            parse.GetValue(protocolOption),
            parse.GetResult(timeoutOption) is { } timeout ? timeout.Tokens.FirstOrDefault()?.Value ?? string.Empty : null));
        // `__worker graph --protocol 2` speaks graph worker protocol v2 (docs/agent/tasks/graph-worker.md, ssa-facts-s4.md
        // §4): the graph pass over one package's folders, and their SSA facts when asked, out of process (ADR 0021 Tier 2).
        // The same string-typed --protocol posture.
        var graphProtocolOption = new Option<string?>("--protocol")
        {
            Description = "Worker protocol version (only 2 is supported)."
        };
        var workerGraphCommand = new Command("graph", "Internal: the out-of-process call graph and reachability worker.")
        {
            graphProtocolOption
        };
        workerGraphCommand.SetAction(parse => RunGraphWorker(parse.GetValue(graphProtocolOption)));
        var workerCommand = new Command("__worker", "Internal: worker processes started by Silvergun itself.")
        {
            workerYaraCommand, workerGraphCommand
        };
        workerCommand.Hidden = true;

        // mcp (ADR 0039, docs/agent/tasks/mcp-server.md D1): the MCP server on stdio. Every option is fixed for the process;
        // no tool can change one.
        var mcpRootOption = new Option<string[]>("--root")
        {
            Description = "A directory that packages given to the server must lie under. Repeatable. Default: the working directory."
        };
        var mcpNetworkOption = new Option<bool>("--network")
        {
            Description = "Allow network intel (OSV, project health, squat checks). Default off."
        };
        var mcpMaxJobsOption = new Option<int>("--max-jobs")
        {
            Description = $"Analysis jobs that may run at once (1 to {McpServerSettings.MaxJobsCap}).",
            DefaultValueFactory = _ => McpServerSettings.DefaultMaxJobs
        };
        var mcpCacheDirOption = new Option<string?>("--cache-dir")
        {
            Description = "The job cache directory. Default: %LOCALAPPDATA%\\Silvergun\\mcp, or $XDG_CACHE_HOME/silvergun/mcp."
        };
        var mcpCacheMaxGbOption = new Option<int>("--cache-max-gb")
        {
            Description = "The job cache's size cap in GiB.",
            DefaultValueFactory = _ => McpServerSettings.DefaultCacheMaxGb
        };
        var mcpLogDirOption = new Option<string?>("--log-dir")
        {
            Description = "The directory for the server's log file. Default: the CLI's own directory."
        };
        var mcpCommand = new Command(McpVerb, "Run the Silvergun MCP server on stdin/stdout, for AI agents.")
        {
            mcpRootOption, mcpNetworkOption, mcpMaxJobsOption, mcpCacheDirOption, mcpCacheMaxGbOption, mcpLogDirOption, debugOption
        };
        mcpCommand.SetAction(parse => RunMcp(
            mcpStdout ??= Console.OpenStandardOutput(),
            parse.GetValue(mcpRootOption) ?? [],
            parse.GetValue(mcpNetworkOption),
            parse.GetValue(mcpMaxJobsOption),
            parse.GetValue(mcpCacheDirOption),
            parse.GetValue(mcpCacheMaxGbOption),
            parse.GetValue(mcpLogDirOption),
            parse.GetValue(debugOption)));

        var root = new RootCommand("Silvergun — static capability analysis for .NET assemblies.")
        {
            analyzeCommand, scanPackageCommand, checkSquatCommand, healthCommand, capabilityDiffCommand, mcpCommand, workerCommand
        };

        // Worker mode keeps stdout protocol-only even for a command line that does not parse (FR2.3): System.CommandLine
        // would print help to stdout and exit 1, so anything under `__worker` that does not resolve to a worker's own
        // action (a parse error such as a repeated --timeout, help, a directive) is one `fatal` record and exit 3: in the
        // graph protocol when the verb is `__worker graph`, otherwise in the yara protocol, as before.
        var parse = root.Parse(args);
        // A command line that reaches `mcp` some other way (a response file) gets the same posture; parsing wrote nothing.
        if (!inMcp && IsWithin(parse.CommandResult, mcpCommand))
        {
            inMcp = true;
            mcpStdout = Console.OpenStandardOutput();
            Console.SetOut(Console.Error);
        }
        // The parser's own output (help, version, parse errors) goes to stderr too; no Ctrl+C hook of its own (D9).
        if (inMcp)
            return parse.Invoke(new InvocationConfiguration { Output = Console.Error, Error = Console.Error, ProcessTerminationTimeout = null });
        var inWorker = (args is [var verb, ..] && verb == workerCommand.Name) || IsWithin(parse.CommandResult, workerCommand);
        // Every worker path, before any work: a worker's crash must end the process at once, not wait on WER
        // (WorkerErrorReporting). Process-wide, so never for the CLI's own verbs.
        if (inWorker)
            WorkerErrorReporting.OptOut();
        return !inWorker || ReferenceEquals(parse.Action, workerYaraCommand.Action) || ReferenceEquals(parse.Action, workerGraphCommand.Action)
            ? parse.Invoke()
            : IsWithin(parse.CommandResult, workerGraphCommand) || (args is [_, var worker, ..] && worker == workerGraphCommand.Name)
            ? RunGraphWorkerArgumentError(parse.Errors.Count)
            : RunYaraWorkerArgumentError(parse.Errors.Count);
    }

    private static int RunAnalyze(string assemblyPath, bool json, bool rich, string? output, bool strict, bool debug, bool noResolve, bool allowIncomplete, string? snapshot)
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

        // Indicators run off the SAME loaded analyzer too (indicator-cli-integration task, following the ADR 0010
        // obfuscation precedent exactly): one assembly load, three analyses. Best-effort — a failure leaves it null;
        // deliberately NOT wired into completeness (still true). It IS wired into the exit code below, but ONLY for
        // the three ADR 0026 gating categories (ReportTheme.IsGatingIndicatorCategory) — see AnalyzeExitCode.
        var indicatorResult = new IndicatorAnalysis(cci).Analyze();
        var indicators = indicatorResult.IsSuccess ? indicatorResult.Value : null;

        // Metadata read is best-effort — a failure leaves Metadata null. That null is a COMPLETENESS caveat (ADR 0024,
        // same class as the failed obfuscation analysis above): the report cannot claim "Clean" when the identity facts
        // it prints were never read, so it reaches the exit code as incompleteness (3), never as a finding (2).
        var metadataResult = AssemblyMetadata.Read(assemblyPath, !noResolve);
        var report = new AssemblyAnalysisReport(
            metadataResult.IsSuccess ? metadataResult.Value : null, reportResult.Value, obfuscation, indicators);

        // The SAME assessment drives the report footer (via the renderer, which calls this same factory) and the exit
        // code below — ADR 0024's load-bearing invariant is that exit 0 ⇔ the footer would say "Clean".
        var completeness = CompletenessAssessment.ForAssembly(report);

        var emitted = json
            ? TryEmit(WithCompleteness(report.ToJson(), completeness), output)
            : EmitHumanReport(c => AssemblyReportRenderer.Render(c, report), output, rich);
        if (!emitted)
            return 1;

        // --snapshot (capability-diff-versions task, Phase B): writes a ONE-element JSON array carrying the SAME
        // completeness the footer/exit code above used, so trap 1 (an incomplete scan must never diff clean) is
        // enforceable later. Deliberately does not touch stdout, the human report, --json, or the exit code below.
        if (snapshot is not null && !TryWriteSnapshotFile(snapshot,
            [CapabilitySnapshot.From(report.Capabilities, packageId: null, packageVersion: null, targetFramework: null,
                new ScanCompleteness(completeness.IsComplete, completeness.MethodsTotal, completeness.MethodsAnalyzed, completeness.MethodsSkipped, AssemblyLoadFailures: 0))]))
            return 1;

        ReportIncompleteness("analyze", completeness, allowIncomplete);

        return AnalyzeExitCode(report, strict, allowIncomplete);
    }

    private static int RunScanPackage(string nupkgPath, bool json, bool rich, string? output, bool strict, bool debug, bool noResolve, bool health, bool noYara, bool noVulns, int depth, bool allowIncomplete, string? snapshot, bool reachability, bool ssa)
    {
        ConfigureLogging(json, output, debug);

        var scanResult = PackageScanner.Scan(nupkgPath, resolveReferences: !noResolve, runYara: !noYara, runReachability: reachability, runSsa: ssa);
        if (!scanResult.IsSuccess)
        {
            Console.Error.WriteLine(scanResult.Message);
            return 1;
        }

        var report = scanResult.Value;

        // YARA was requested (not --no-yara) but the scan did not actually complete: note it on stderr (like
        // --health) so stdout/JSON stay unaffected. Keyed on the REPORT's own YaraScanStatus — the ground truth of
        // what just happened — rather than YaraScannerFactory.BackendAvailable, which only proves a backend was
        // SELECTED, not that it worked: on the net10.0-windows build a backend (the YARA-X worker by default, LibYaraScanner
        // when explicitly selected) is always selected but can still fail to initialize (the worker or its DLL missing, or
        // libyara.NET's native dependency missing). The latter previously produced zero findings
        // with NO advisory at all — exactly the silent-zero defect this check exists to close. Printed at most once
        // per run (report.YaraScanStatus is a single value for the whole scan, not per-file). Unavailable WITH findings
        // is a scan that started and could not finish (ADR 0032): saying it "did NOT run" would contradict the
        // matches in the report, so that case says what actually happened — hits found, the rest unverified. Either way
        // the line ends with the report's YaraUnavailableReason, so a CI log says WHY even when it shows only stderr (the
        // reason is also in the JSON report whenever it is set). It is printed as is: the report's init accessor already
        // escaped it and cut it to 512 chars (PackageCapabilityReport.MaxYaraUnavailableReasonChars).
        if (!noYara && report.YaraScanStatus == YaraScanStatus.Unavailable)
            Console.Error.WriteLine((report.YaraFindings.Count > 0
                ? $"scan-package: YARA malware-signature scanning did NOT complete; {report.YaraFindings.Count} match(es) were found " +
                  "in the files that were scanned, and the remaining files are NOT verified against the malware-signature ruleset."
                : "scan-package: YARA malware-signature scanning did NOT run (backend unavailable or failed to initialize); " +
                  "findings for this package are NOT verified against the malware-signature ruleset.")
                + (report.YaraUnavailableReason is { Length: > 0 } reason ? $" Reason: {reason}" : string.Empty));

        // The same advisory for the script content pass (ADR 0030; docs/agent/tasks/script-scan-coverage.md S1), keyed on
        // the report's own ScriptScanStatus and printed at most once per run (one status for the whole scan). Unavailable
        // means some or all script/manifest files were NOT scanned; the report does not say whether any were, so both
        // variants say "did NOT complete" — "did NOT run" would be false whenever some files did scan. With findings,
        // they are real hits from the files that were scanned (ADR 0032). The reason is printed as is: the report's init
        // accessor already escaped it and cut it to PackageCapabilityReport.MaxScriptScanUnavailableReasonChars. This note
        // names the reason; the gating is CompletenessAssessment.ForPackage's "script content scanning did not complete"
        // caveat (ADR 0035 decision 2), which makes the run incomplete (exit 3 unless --allow-incomplete), as for YARA.
        if (report.ScriptScanStatus == ScriptScanStatus.Unavailable)
            Console.Error.WriteLine((report.ScriptFindings.Count > 0
                ? $"scan-package: script content scanning did NOT complete; {report.ScriptFindings.Count} script finding(s) were found " +
                  "in the files that were scanned, and the remaining script/manifest files are NOT verified against the script ruleset."
                : "scan-package: script content scanning did NOT complete (some or all script/manifest files were not scanned); " +
                  "script findings for this package are NOT verified against the script ruleset.")
                + (report.ScriptScanUnavailableReason is { Length: > 0 } scriptReason ? $" Reason: {scriptReason}" : string.Empty));

        // Reachability (R3 S2): one note when the pass ran and did not come out decided, as for YARA. A caveat, not exit 3
        // (ADR 0037 decision 10): completeness, the footer, --strict, the exit code and --snapshot never read it. The counts
        // come from the folders, not the stored Complete (S1 review N2).
        if (report.Reachability is { } reachSummary && ReachabilitySectionRenderer.IncompleteNote(reachSummary) is { } reachNote)
            Console.Error.WriteLine(reachNote);
        // SSA (S5, D4): its own note, never folded into reachability's.
        if (ssa && report.Reachability is { } ssaSummary && SsaSectionRenderer.IncompleteNote(ssaSummary) is { } ssaNote)
            Console.Error.WriteLine(ssaNote);

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

        // --snapshot (capability-diff-versions task, Phase B): one CapabilitySnapshot per SCANNED assembly (Report
        // is non-null — mirrors PackageCapabilityReport.AllFindings' own filter), sharing the SAME package-level
        // completeness the footer/exit code above used, so a diff drawn from this file can never read the package
        // as more complete than the report just shown. AssemblyLoadFailures counts files that produced NO
        // CapabilityReport at all (SkipReason set) — the same class of gap CompletenessAssessment.ForPackage folds
        // into IsComplete, just not exposed as its own count there.
        // KNOWN GAP: a package with ZERO assemblies that produced a CapabilityReport (e.g. purely native DLLs)
        // writes an EMPTY array — there is no element left to carry the incomplete flag, so capability-diff cannot
        // detect that case (see the task write-up). Not fixed here: Phase B's design deliberately keeps the
        // snapshot file a plain array of self-describing elements, with no new container type for a package-level
        // low-water mark.
        if (snapshot is not null)
        {
            // Files only (entry-aliasing review 2, W2): a declared entry never extracted as its own file is not an
            // assembly that failed to load; it still makes the package incomplete via completeness.IsComplete.
            var assemblyLoadFailures = report.Assemblies.Count(a => a.SkipReason is not null && !a.NotInventoried);
            var scanCompleteness = new ScanCompleteness(
                completeness.IsComplete, completeness.MethodsTotal, completeness.MethodsAnalyzed, completeness.MethodsSkipped, assemblyLoadFailures);
            var snapshots = report.Assemblies
                .Where(a => a.Report is not null)
                .Select(a => CapabilitySnapshot.From(a.Report!, report.Package.Id, report.Package.Version, a.Assembly.TargetFramework, scanCompleteness))
                .ToArray();
            if (!TryWriteSnapshotFile(snapshot, snapshots))
                return 1;
        }

        ReportIncompleteness("scan-package", completeness, allowIncomplete);

        return ScanPackageExitCode(report, strict, allowIncomplete);
    }

    // The analyze verb's exit code, as ONE seam over the whole report (ADR 0024, gate narrowed by ADR 0027). This
    // exists so the gate predicate — which findings gate, and how incompleteness is derived — is written exactly
    // once: the run method above and the invariant tests both call this, instead of the tests keeping a hand-written
    // third copy that can silently drift from what ships. Recomputing the assessment here (rather than taking it as
    // a parameter) is deliberate: it is pure, and it makes the exit code derive from the report itself, exactly as
    // the footer does.
    //
    // ⚠️ ADR 0027 KNOWN CONSEQUENCE, not an oversight: `analyze` never carries YARA or vulnerability data (both are
    // scan-package-only, package/network-level checks) — only capability, obfuscation, and gating-indicator findings
    // exist at the single-assembly level, and the first two stopped gating (ADR 0027 Table C: 67-81% and 29% benign
    // prevalence respectively, zero user-would-accept hits). So `analyze --strict` gates on GATING INDICATOR FINDINGS
    // ALONE (ADR 0026's three categories — CallbackDomain, DynamicDns, CredentialPath), plus incompleteness (exit 3)
    // when the analysis could not fully run. Capability and obfuscation findings are still fully analyzed, rendered,
    // and set the "Findings present" headline — they just never fail the build.
    internal static int AnalyzeExitCode(AssemblyAnalysisReport report, bool strict, bool allowIncomplete) =>
        ScanExitCode(
            strict,
            hasYaraFindings: false,
            hasVulnerabilities: false,
            hasGatingIndicatorFindings: report.Indicators?.Findings.Any(f => ReportTheme.IsGatingIndicatorCategory(f.Category)) ?? false,
            isIncomplete: !CompletenessAssessment.ForAssembly(report).IsComplete,
            allowIncomplete: allowIncomplete);

    // The scan-package verb's exit code, as ONE seam over the whole report (see AnalyzeExitCode). Gate narrowed by
    // ADR 0027 to three sources — vulnerabilities, YARA findings, and gating indicator findings — a 0/100 benign
    // failure rate measured over the same pinned corpus that showed the PRIOR six-source gate failing 72% of benign
    // packages, every single one for a noise-class reason (capability presence, obfuscation, or a script heuristic —
    // never a real CVE, a YARA name-match, or a gating indicator). Capability, obfuscation, and Script-sourced script
    // findings are STILL fully analyzed, rendered, and set the "Findings present" headline — they simply no longer
    // fail the build. (Findings from the declarative package manifest, ScriptFindingSource.PackageMetadata, were
    // already excluded from the gate before this ADR and remain so — nothing in a .nuspec executes.) Indicator
    // findings gate too, but ONLY the three ADR 0026 categories (ReportTheme.IsGatingIndicatorCategory), aggregated
    // across every packaged assembly that produced an IndicatorReport — mirrors AllFindings' own "across every
    // analyzed assembly" posture.
    internal static int ScanPackageExitCode(PackageCapabilityReport report, bool strict, bool allowIncomplete) =>
        ScanExitCode(
            strict,
            hasYaraFindings: report.YaraFindings.Count > 0,
            hasVulnerabilities: report.Vulnerabilities.Count > 0,
            hasGatingIndicatorFindings: report.Assemblies
                .Where(a => a.Indicators is not null)
                .Any(a => a.Indicators!.Findings.Any(f => ReportTheme.IsGatingIndicatorCategory(f.Category))),
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

        // check-squat's typosquat findings are not one of ADR 0027's six analyze/scan-package sources — they are the
        // ONLY finding this verb ever produces, so its --strict gate is direct rather than routed through
        // ScanExitCode's per-source policy (which now names exactly three sources that do not apply here).
        return strict && findings.Count > 0 ? 2 : 0;
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

    // Compares two --snapshot files (capability-diff-versions task, Phase B; corrected 2026-08-20). Offline and
    // synchronous — unlike check-squat/health, nothing here touches the network. Elements are matched by the
    // composite key (AssemblyName, TargetFramework) — see CapabilityDiffReport.Compare's doc comment for why name
    // alone silently collapsed multi-targeted packages to one TFM variant. Four refusal traps, checked in this
    // order:
    //   1. an unrecognized SchemaVersion anywhere in either file (trap 3) -> exit 1, no report produced at all
    //      (CapabilitySnapshot.FromJson deliberately does not check this itself; it is this verb's judgment).
    //   2. an EMPTY snapshot array on either side (a scan-package of a package with no analyzable assemblies) ->
    //      exit 3, unconditional. An empty array cannot carry the incomplete flag, so left unchecked, diffing two
    //      empty arrays would report "no capability changes" for a comparison that never looked at anything.
    //   3. a matched-pair set that comes back EMPTY while both files are non-empty — the vacuous-diff trap
    //      (repurposed trap 2, since composite keying makes the old cross-TFM comparison impossible by
    //      construction): unless --allow-tfm-mismatch -> exit 3, no report produced. Nothing in common between the
    //      two files means no capability comparison happened at all, which must never read as a clean "no changes".
    //   4. an incomplete scan on either side (trap 1) -> the diff IS still computed and rendered (findings win the
    //      headline, exactly like analyze/scan-package), but the exit code is gated at 3 unless --allow-incomplete.
    private static int RunCapabilityDiff(
        string baselinePath, string candidatePath, bool json, bool rich, string? output, bool strict, bool debug,
        bool allowIncomplete, bool allowTfmMismatch)
    {
        ConfigureLogging(json, output, debug);

        var baselineResult = LoadSnapshotArray(baselinePath);
        if (!baselineResult.IsSuccess)
        {
            Console.Error.WriteLine(baselineResult.Message);
            return 1;
        }

        var candidateResult = LoadSnapshotArray(candidatePath);
        if (!candidateResult.IsSuccess)
        {
            Console.Error.WriteLine(candidateResult.Message);
            return 1;
        }

        var baseline = baselineResult.Value;
        var candidate = candidateResult.Value;

        // Trap 3: refuse outright rather than best-effort-parse a snapshot shape this build does not understand.
        var unknownVersion = baseline.Concat(candidate).FirstOrDefault(s => s.SchemaVersion != CapabilitySnapshot.CurrentSchemaVersion);
        if (unknownVersion is not null)
        {
            Console.Error.WriteLine(
                $"capability-diff: snapshot for '{unknownVersion.AssemblyName}' has schema version {unknownVersion.SchemaVersion}, " +
                $"but this build only understands version {CapabilitySnapshot.CurrentSchemaVersion}. Refusing to diff it.");
            return 1;
        }

        // Empty-array hole: a scan-package with nothing analyzable writes an empty array, which cannot carry the
        // incomplete flag. Unconditional — there is no meaningful comparison to override into existing.
        if (baseline.Count == 0 || candidate.Count == 0)
        {
            Console.Error.WriteLine(
                $"capability-diff: {(baseline.Count == 0 ? "baseline" : "candidate")} snapshot has no assemblies to compare " +
                "(an empty --snapshot array). Refusing to diff it.");
            return 3;
        }

        var diff = CapabilityDiffReport.Compare(baseline, candidate);

        // Vacuous-diff trap (repurposed trap 2): both files are non-empty, but nothing matched — e.g. the two
        // files' TFM sets are disjoint. A comparison of nothing must never read as a clean "no changes".
        if (diff.MatchedPairCount == 0 && !allowTfmMismatch)
        {
            Console.Error.WriteLine(
                "capability-diff: NOTHING MATCHED between baseline and candidate — no (assembly, target framework) " +
                "pair is present in both files, so no capability comparison is possible. Refusing to compare. " +
                "Pass --allow-tfm-mismatch to override.");
            return 3;
        }

        // Trap 1: any incomplete element on a side makes that WHOLE side untrustworthy for a clean result.
        var (baselineComplete, baselineCaveats) = CapabilityDiffOutcome.SideCompleteness(baseline);
        var (candidateComplete, candidateCaveats) = CapabilityDiffOutcome.SideCompleteness(candidate);

        var outcome = new CapabilityDiffOutcome(
            diff, baselineComplete, baselineCaveats, candidateComplete, candidateCaveats,
            VacuousDiffOverridden: diff.MatchedPairCount == 0);

        var emitted = json
            ? TryEmit(outcome.ToJson(), output)
            : EmitHumanReport(c => CapabilityDiffReportRenderer.Render(c, outcome, baselinePath, candidatePath), output, rich);
        if (!emitted)
            return 1;

        return CapabilityDiffExitCode(diff, strict, outcome.IsIncomplete, allowIncomplete);
    }

    // The capability-diff verb's exit code, as ONE seam (mirrors AnalyzeExitCode/ScanPackageExitCode). Same
    // precedence as ScanExitCode: a tripped --strict gate beats incompleteness, because an added capability is
    // accurate and actionable even when coverage was partial elsewhere.
    //
    // ⚠️ This is the FIRST place capability DATA gates an exit code by design (ADR — capability-diff-versions task).
    // That is acceptable ONLY because it gates on a DELTA (HasAddedCapabilities: a capability the candidate has that
    // the baseline did not), never on bare capability PRESENCE: presence alone fires on ~96% of benign packages
    // (docs/agent/measurements, capability-manifest-reframe task) and gating on it would be pure noise. Do NOT
    // "simplify" this into gating on diff.HasAnyCapabilityChange or on any single snapshot's manifest presence —
    // that would silently reintroduce the presence-gate this project deliberately rejected.
    internal static int CapabilityDiffExitCode(CapabilityDiffReport diff, bool strict, bool isIncomplete, bool allowIncomplete) =>
        strict && diff.HasAddedCapabilities ? 2
        : isIncomplete && !allowIncomplete ? 3
        : 0;

    // Reads a --snapshot JSON array (capability-diff-versions task). Never throws: a missing file, an unreadable
    // file, or malformed/non-array JSON all become a failure Result with a message meant for stderr.
    private static Result<IReadOnlyList<CapabilitySnapshot>> LoadSnapshotArray(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return Result.Failure<IReadOnlyList<CapabilitySnapshot>>($"Snapshot file '{path}' does not exist.");

        try
        {
            var json = File.ReadAllText(path);
            var snapshots = JsonSerializer.Deserialize<List<CapabilitySnapshot>>(json, snapshotJsonOptions);
            return snapshots is null
                ? Result.Failure<IReadOnlyList<CapabilitySnapshot>>($"Snapshot file '{path}' is empty or JSON 'null'.")
                : Result.Success<IReadOnlyList<CapabilitySnapshot>>(snapshots);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return Result.Failure<IReadOnlyList<CapabilitySnapshot>>($"Could not read snapshot file '{path}': {ex.Message}", ex);
        }
    }

    // Writes a --snapshot JSON array (analyze/scan-package). Same error posture as TryEmit's file branch.
    private static bool TryWriteSnapshotFile(string path, IReadOnlyList<CapabilitySnapshot> snapshots)
    {
        try
        {
            File.WriteAllText(path, JsonSerializer.Serialize(snapshots, snapshotJsonOptions));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Failed to write snapshot to {path}: {ex.Message}");
            return false;
        }
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

    // The CI gate exit-code decision (ADR 0003, amended by ADR 0024/0026, NARROWED by ADR 0027). Pure — the run
    // methods pass the concrete gate inputs so this stays independently testable.
    //
    // ⚠️ ADR 0027: capability findings, obfuscation findings, and Script-sourced script findings USED to gate here
    // and no longer do — measured at 67-81%, 29%, and 25% benign-package prevalence respectively (100-package
    // corpus), with EVERY one of the resulting 72/100 benign `--strict` failures landing on a noise-class reason,
    // never one a user would accept as signal. Their booleans are REMOVED from this signature on purpose (not just
    // ignored/defaulted): a future attempt to re-gate on them must fail to compile here, rather than silently
    // reintroducing a 72%-false-positive policy. They are still fully analyzed, rendered, and set the "Findings
    // present" headline — only build failure changed.
    //
    // What still gates, all three measured at 0/100 benign failures: YARA findings (ADR 0016 — a malware-family
    // name-match is the strongest signal the tool has), known vulnerabilities (ADR 0017 — a real CVE should fail a
    // build), and exactly three gating indicator categories (ADR 0026 — CallbackDomain, DynamicDns, CredentialPath,
    // per ReportTheme.IsGatingIndicatorCategory; every other indicator category, including the other four
    // discriminating ones, is reported but never reaches this call as "true").
    //
    // Precedence, exactly:
    //   1. strict && any finding gate  => 2. A tripped gate is accurate and actionable, so 2 BEATS 3 even when the
    //      analysis was incomplete — the incompleteness is a caveat in the report, not a reason to hide the verdict.
    //   2. else isIncomplete && !allowIncomplete => 3. NOT gated on --strict: opting out of *findings* gating is not
    //      opting out of being told coverage was partial.
    //   3. else => 0, which (with --allow-incomplete off) means the report's footer says "Clean".
    // --allow-incomplete only suppresses the GATE; the caveats are always disclosed (report + one stderr note).
    internal static int ScanExitCode(
        bool strict, bool hasYaraFindings, bool hasVulnerabilities, bool hasGatingIndicatorFindings,
        bool isIncomplete, bool allowIncomplete) =>
        strict && (hasYaraFindings || hasVulnerabilities || hasGatingIndicatorFindings) ? 2
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

    // The hidden `__worker yara` verb (ADR 0033). Worker-mode logging only (stderr, capped, no file sink — so nothing
    // reaches the normal Silvergun log), raw stdin/stdout streams (UTF-8, no BOM, no Console encoding), and nothing
    // from the analysis paths: no CCI, NuGet, OSV or libyara.NET code runs here. The engine is the platform's real one
    // (YARA-X on Windows and Linux; elsewhere a `fatal` "engine unavailable on this platform"), never the T1 stub. On
    // Linux the worker exits when its parent dies (WorkerParentWatch), which the Job Object does on Windows.
    private static int RunYaraWorker(string? protocol, string? timeout)
    {
        Runtime.WithStderrLogging("Silvergun", "worker-yara");
        WorkerParentWatch.Start();
        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();
        // W2: from here on only the protocol writer, over the raw stream above, can reach stdout.
        Console.SetOut(TextWriter.Null);
        return YaraWorker.Run(protocol, timeout, stdin, stdout, YaraWorkerEngines.ForPlatform);
    }

    // A `__worker` command line that did not parse to the yara worker (FR2.3): the same posture as RunYaraWorker — stderr-only
    // logging, stdout protocol-only — and the same answer YaraWorker.Run gives any other bad argument: one `fatal` record,
    // exit 3. The parser's messages can quote argument tokens, so they are not echoed; the reason is fixed text.
    private static int RunYaraWorkerArgumentError(int errors)
    {
        Runtime.WithStderrLogging("Silvergun", "worker-yara");
        var reason = (errors > 0 ? $"the worker's arguments did not parse ({errors} error(s))" : "the worker's arguments asked for something other than a worker session")
            + $"; expected __worker yara --protocol {WorkerProtocol.Version} [{WorkerProtocol.TimeoutOption} <seconds>]";
        Runtime.Error("yara worker: fatal: {0}", reason);
        using var stdout = Console.OpenStandardOutput();
        Console.SetOut(TextWriter.Null);
        try
        {
            new WorkerProtocolWriter(stdout).Write(new WorkerFatal(reason));
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or NotSupportedException)
        {
            Runtime.Error("yara worker: cannot write to stdout ({0}).", ex.GetType().Name);
        }
        return WorkerProtocol.ExitFatal;
    }

    // The hidden `__worker graph` verb (docs/agent/tasks/graph-worker.md). The yara worker's posture: stderr-only, capped
    // logging, and raw stdin/stdout. When stdin ends or carries anything after the request, the parent is gone or has given
    // up, and the process exits at once.
    private static int RunGraphWorker(string? protocol)
    {
        Runtime.WithStderrLogging("Silvergun", "worker-graph");
        // stdin is not disposed: the watchdog thread may still be reading it as the process ends (review N1).
        var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();
        Console.SetOut(TextWriter.Null);
        return GraphWorker.Run(protocol, stdin, stdout, () => Environment.Exit(GraphWorkerProtocol.ExitParentGone));
    }

    // A `__worker graph` command line that did not parse: one graph-protocol `fatal`, exit 3. The parser's messages can
    // quote argument tokens, so the reason is fixed text.
    private static int RunGraphWorkerArgumentError(int errors)
    {
        Runtime.WithStderrLogging("Silvergun", "worker-graph");
        using var stdout = Console.OpenStandardOutput();
        Console.SetOut(TextWriter.Null);
        return GraphWorker.Refuse(stdout, (errors > 0 ? $"the worker's arguments did not parse ({errors} error(s))" : "the worker's arguments asked for something other than a worker session")
            + $"; expected __worker graph --protocol {GraphWorkerProtocol.Version}");
    }

    // The `mcp` verb (ADR 0039). File log plus a capped stderr copy, never the console sink (it writes to stdout); the
    // transport gets the raw stdout taken in Main, and Console.Out is then a null writer, as in the workers.
    private static int RunMcp(Stream stdout, string[] roots, bool network, int maxJobs, string? cacheDir, int cacheMaxGb, string? logDir, bool debug)
    {
        var settings = McpServerSettings.Create(roots, network, maxJobs, cacheDir, cacheMaxGb, logDir, debug);
        if (!settings.IsSuccess)
        {
            Console.Error.WriteLine($"mcp: {settings.Message}.");
            return 1;
        }

        if (McpServerSettings.LogDirectoryProblem(settings.Value.LogDir ?? Runtime.AssemblyLocation) is { } logProblem)
        {
            Console.Error.WriteLine($"mcp: {logProblem}; pass a writable --log-dir.");
            return 1;
        }

        Runtime.WithFileAndStderrLogging("Silvergun", "MCP", debug, settings.Value.LogDir);
        Console.SetOut(TextWriter.Null);
        var stdin = Console.OpenStandardInput();
        try
        {
            SilvergunMcpServer.RunAsync(settings.Value, stdin, stdout).GetAwaiter().GetResult();
            return 0;
        }
        catch (Exception ex)
        {
            // Type and escaped message only: an SDK exception's text can be agent-chosen (D9).
            Runtime.Error("mcp: the server stopped on an error:{0}", SdkLogRedactor.RenderException(ex, debug));
            return 1;
        }
    }

    // Whether `result` is `command`'s, or lies under it in the parse tree.
    private static bool IsWithin(SymbolResult? result, Command command) =>
        result is not null && ((result is CommandResult { Command: var c } && ReferenceEquals(c, command)) || IsWithin(result.Parent, command));

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
    private const string McpVerb = "mcp";

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

    // Shared read/write options for --snapshot files and capability-diff's inputs (capability-diff-versions task):
    // indented so a committed baseline is reviewable, enums by name so CurrentSchemaVersion-stable JSON survives a
    // future Capability append without renumbering.
    private static readonly JsonSerializerOptions snapshotJsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
