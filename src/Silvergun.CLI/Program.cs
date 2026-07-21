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
        var noResolveOption = new Option<bool>("--no-resolve")
        {
            Description = "Skip best-effort assembly-reference resolution when reading metadata."
        };
        var healthOption = new Option<bool>("--health")
        {
            Description = "Also resolve the package's GitHub repository from the local nuspec and attach a " +
                          "project-health section (network; advisory — never affects the exit code)."
        };
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
            assemblyPathArgument, jsonOption, richOption, outputOption, strictOption, debugOption, noResolveOption
        };
        analyzeCommand.Validators.Add(RejectJsonWithRich);
        analyzeCommand.SetAction(parse => RunAnalyze(
            parse.GetValue(assemblyPathArgument)!,
            parse.GetValue(jsonOption),
            parse.GetValue(richOption),
            parse.GetValue(outputOption),
            parse.GetValue(strictOption),
            parse.GetValue(debugOption),
            parse.GetValue(noResolveOption)));

        var scanPackageCommand = new Command("scan-package", "Scan a .nupkg for sensitive-API capabilities.")
        {
            nupkgPathArgument, jsonOption, richOption, outputOption, strictOption, debugOption, noResolveOption, healthOption
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
            parse.GetValue(healthOption)));

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

    private static int RunAnalyze(string assemblyPath, bool json, bool rich, string? output, bool strict, bool debug, bool noResolve)
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

        var emitted = json
            ? TryEmit(report.ToJson(), output)
            : EmitHumanReport(c => AssemblyReportRenderer.Render(c, report), output, rich);
        if (!emitted)
            return 1;

        return ScanExitCode(
            strict,
            report.Capabilities.Findings.Count > 0,
            (report.Obfuscation?.Findings.Count ?? 0) > 0,
            hasScriptFindings: false);
    }

    private static int RunScanPackage(string nupkgPath, bool json, bool rich, string? output, bool strict, bool debug, bool noResolve, bool health)
    {
        ConfigureLogging(json, output, debug);

        var scanResult = PackageScanner.Scan(nupkgPath, resolveReferences: !noResolve);
        if (!scanResult.IsSuccess)
        {
            Console.Error.WriteLine(scanResult.Message);
            return 1;
        }

        var report = scanResult.Value;

        // --health is the ONLY thing that adds a network call to scan-package (the offline scan above stays offline).
        // Repo resolution is offline (local nuspec); only the GitHub lookup is network. Advisory — never touches the
        // exit code below. Best-effort/never-throws: an unresolvable repo or a failed lookup just leaves ProjectHealth null.
        if (health)
        {
            report = report with { ProjectHealth = ResolveLocalHealth(report.Package) };
            if (report.ProjectHealth is null)
                Console.Error.WriteLine("scan-package: project-health requested but unavailable (no GitHub repository resolved or lookup failed).");
        }

        var emitted = json
            ? TryEmit(report.ToJson(), output)
            : EmitHumanReport(c => PackageReportRenderer.Render(c, report, nupkgPath), output, rich);
        if (!emitted)
            return 1;

        var hasObfuscation = report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0);
        return ScanExitCode(strict, report.AllFindings.Any(), hasObfuscation, report.ScriptFindings.Any());
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

    // The --strict CI gate exit-code decision (ADR 0003): 2 when strict and any finding gate trips, else 0.
    // Pure — the run methods pass the concrete gate inputs so this stays independently testable.
    internal static int ScanExitCode(bool strict, bool hasCapabilityFindings, bool hasObfuscation, bool hasScriptFindings) =>
        strict && (hasCapabilityFindings || hasObfuscation || hasScriptFindings) ? 2 : 0;

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

    // Deterministic report width used when not attached to a TTY (redirected stdout or a file), so default
    // (ASCII) output doesn't vary with the ambient terminal. A TTY may still be measured for wrapping.
    private const int DefaultReportWidth = 100;
    #endregion
}
