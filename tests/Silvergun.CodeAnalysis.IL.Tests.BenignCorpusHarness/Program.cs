namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Globalization;
using System.IO;
using System.Linq;

/// <summary>
/// Resolved run configuration. Every default is chosen so that a bare <c>run</c> is a small, bounded, repeatable
/// measurement: 25 pinned packages, a cache outside the repository, and output into
/// <c>docs/agent/measurements</c>.
/// </summary>
public sealed record HarnessOptions(
    string Manifest,
    int Take,
    string CacheRoot,
    string OutputDirectory,
    TimeSpan ChildTimeout);

/// <summary>The <c>--reachability</c> options on top of the common ones.</summary>
public sealed record ReachabilityOptions(HarnessOptions Common, string Results, int MaxChildren, DateOnly Date);

/// <summary>
/// Benign-corpus harness - <b>a measurement instrument, not a shipped feature and not a unit test</b>. It scans a
/// pinned set of ordinary, widely-used NuGet packages and reports which capabilities and
/// <see cref="Silvergun.CodeAnalysis.IL.IndicatorCategory"/> values appear in what share of them, so that a later
/// risk-scoring ADR can calibrate a gate against evidence instead of intuition. It changes nothing about how
/// Silvergun scores or gates; it only measures.
/// <para>
/// Two roles in one executable. Without arguments (or with options) it is the <b>driver</b>. With
/// <c>scan &lt;assembly&gt;</c> it is the <b>child</b> (<see cref="ChildScan"/>) that analyses exactly one assembly
/// in its own process - the driver re-invokes itself per assembly, so a CCI <c>FailFast</c> (ADR-0021, exit 35,
/// uncatchable) costs one assembly instead of the whole corpus run.
/// </para>
/// <para>Options: <c>--manifest &lt;path&gt;</c>, <c>--take &lt;n&gt;</c> (0 = all, default 25),
/// <c>--cache &lt;dir&gt;</c>, <c>--out &lt;dir&gt;</c>, <c>--timeout &lt;seconds&gt;</c> (per child, default 300).
/// </para>
/// <para>Exit codes: <c>0</c> the instrument ran and wrote its report (packages it could not scan are *data*,
/// reported in the report, not a tool failure); <c>1</c> the run could not produce a report; <c>2</c> bad usage.
/// </para>
/// </summary>
public static class Program
{
    #region Methods
    public static int Main(string[] args)
    {
        if (args.Length > 0 && string.Equals(args[0], ChildScan.Verb, StringComparison.Ordinal))
            return ChildScan.Execute(args);
        if (args.Length > 0 && string.Equals(args[0], ReachabilityChild.Verb, StringComparison.Ordinal))
            return ReachabilityChild.Execute(args);
        if (args.Length > 0 && string.Equals(args[0], WorkerParityChild.Verb, StringComparison.Ordinal))
            return WorkerParityChild.Execute(args);

        try
        {
            if (args.Contains("--help") || args.Contains("-h"))
            {
                Console.WriteLine(Usage);
                return 0;
            }

            if (args.Contains(ReachabilityFlag))
                return RunReachability(args);
            if (args.Contains(WorkerParityFlag))
                return RunWorkerParity(args);

            var options = Parse(args);
            var manifest = CorpusManifest.Load(options.Manifest, options.Take);
            var date = DateOnly.FromDateTime(DateTime.Now);

            if (IsInsideRepository(options.CacheRoot))
            {
                Console.Error.WriteLine(
                    $"Refusing to cache .nupkg files inside the repository: {options.CacheRoot}. Pass --cache.");
                return 1;
            }

            Directory.CreateDirectory(options.OutputDirectory);
            Console.WriteLine($"manifest {manifest.Path}");
            Console.WriteLine($"manifest-hash {manifest.Hash} ({manifest.Entries.Count} package(s))");
            Console.WriteLine($"cache {options.CacheRoot}");

            var driver = new CorpusDriver(
                new PackageCache(options.CacheRoot), HarnessExecutable(), options.ChildTimeout);
            var results = driver.Run(manifest, Console.Out);

            var tsv = Path.Combine(options.OutputDirectory, $"benign-corpus-{date:yyyy-MM-dd}.tsv");
            var md = Path.Combine(options.OutputDirectory, $"benign-corpus-{date:yyyy-MM-dd}.md");
            CorpusReport.WriteFindingsTsv(tsv, results);
            CorpusReport.WriteMarkdown(md, Path.GetFileName(tsv), date, manifest, options.CacheRoot, results);

            var itsv = Path.Combine(options.OutputDirectory, $"indicator-prevalence-{date:yyyy-MM-dd}.tsv");
            var imd = Path.Combine(options.OutputDirectory, $"indicator-prevalence-{date:yyyy-MM-dd}.md");
            CorpusReport.WriteIndicatorFindingsTsv(itsv, results);
            CorpusReport.WriteIndicatorMarkdown(imd, Path.GetFileName(itsv), date, manifest, options.CacheRoot, results);

            Console.WriteLine($"wrote {tsv}");
            Console.WriteLine($"wrote {md}");
            Console.WriteLine($"wrote {itsv}");
            Console.WriteLine($"wrote {imd}");
            Console.WriteLine(
                $"counted {results.Count(r => r.Counted)}/{results.Count} package(s); " +
                $"{results.Count(r => r.Status == PackageResult.Scanned)} complete");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED {ex}");
            return 1;
        }
    }

    // --reachability (reachability R2): offline, one child per package, results cached in --results, the report rendered
    // once every manifest entry has a result. Never constructs a PackageCache, so nothing is ever downloaded.
    private static int RunReachability(string[] args)
    {
        if (ParseReachability(args) is not { } options)
        {
            Console.Error.WriteLine("--reachability needs --results <dir>; see --help.");
            return 2;
        }

        var common = options.Common;
        var manifest = CorpusManifest.Load(common.Manifest, common.Take);
        var identity = BuildIdentities.Current(RepositoryRoot(), AppContext.BaseDirectory);
        var oracle = PresenceOracle.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, OracleFileName)));
        var harness = HarnessExecutable();

        Console.WriteLine($"manifest {manifest.Path}");
        Console.WriteLine($"manifest-hash {manifest.Hash} ({manifest.Entries.Count} package(s))");
        Console.WriteLine($"cache {common.CacheRoot} (read only)");
        Console.WriteLine($"results {options.Results}");
        Console.WriteLine($"identity {identity}");

        try
        {
            var driver = new ReachabilityDriver(common.CacheRoot, options.Results, options.MaxChildren, identity,
                (entry, nupkg) => ReachabilityChildRunner.Run(harness, options.Results, entry, nupkg, common.ChildTimeout, identity));
            var run = driver.Run(manifest, Console.Out);

            var notCached = run.Results.Count(r => r.Status == PackageReachResult.NotCached);
            if (notCached > 0)
                Console.WriteLine($"WARNING {notCached} manifest entr(ies) not-cached; nothing was downloaded.");
            if (!run.Complete)
            {
                Console.WriteLine($"PENDING {run.Pending.Count} package(s) still to measure ({run.ChildrenRun} child(ren) run); rerun to continue.");
                return 0;
            }

            var context = new ReachabilityReportContext(options.Date, manifest, common.CacheRoot, identity, common.ChildTimeout, oracle);
            var (paths, notComparable) = ReachabilityCorpusReport.Write(common.OutputDirectory, context, run.Results);
            foreach (var path in paths)
                Console.WriteLine($"wrote {path}");
            Console.WriteLine($"COMPLETE {run.Results.Count} result(s); {run.ChildrenRun} child(ren) run in this invocation");
            if (notComparable is not null)
            {
                // The report is written, but no verdict may be read off it (spec, review W2).
                Console.Error.WriteLine($"NOT-COMPARABLE {notComparable}");
                return NotComparableExitCode;
            }
            return 0;
        }
        catch (MixedBuildException ex)
        {
            Console.Error.WriteLine($"FAILED {ex.Message}");
            return 1;
        }
    }

    // --worker-parity (graph worker S3): offline like --reachability, never constructs a PackageCache. Needs the CLI apphost
    // beside the harness (its ProjectReference), or every folder would only be NotRun.
    private static int RunWorkerParity(string[] args)
    {
        string? Value(string name)
        {
            var index = Array.IndexOf(args, name);
            return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
        }

        var common = Parse(args);
        if (Value("--take") is null)
            common = common with { Take = 0 };
        if (Value("--timeout") is null)
            common = common with { ChildTimeout = TimeSpan.FromSeconds(DefaultReachabilityTimeoutSeconds) };
        var date = Value("--date") is { } text
            ? DateOnly.ParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture)
            : DateOnly.FromDateTime(DateTime.UtcNow);

        var cli = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "Silvergun.CLI.exe" : "Silvergun.CLI");
        if (!File.Exists(cli))
        {
            Console.Error.WriteLine($"--worker-parity needs the graph worker beside the harness, and there is no {cli}.");
            return 1;
        }

        var manifest = CorpusManifest.Load(common.Manifest, common.Take);
        Console.WriteLine($"manifest {manifest.Path}");
        Console.WriteLine($"manifest-hash {manifest.Hash} ({manifest.Entries.Count} package(s))");
        Console.WriteLine($"cache {common.CacheRoot} (read only)");
        Console.WriteLine($"worker {cli}");

        // Null logging, as in the children: the TSV carries every folder's outcome and reason.
        Silvergun.Runtime.Initialize("Silvergun", "CORPUS");
        var (paths, mismatches, measured, notCached, incomplete) = WorkerParity.Run(manifest, common.CacheRoot, HarnessExecutable(), common.ChildTimeout, common.OutputDirectory, date, Console.Out);
        foreach (var path in paths)
            Console.WriteLine($"wrote {path}");
        if (mismatches > 0)
        {
            Console.Error.WriteLine($"MISMATCH {mismatches} folder(s) differ between the in-process pass and the worker; see the report.");
            return ParityMismatchExitCode;
        }
        // A run that measured nothing, or skipped part of the manifest, proves nothing about parity (review round 2, W-B):
        // the report is written, but no verdict may be read off it, as with --reachability.
        // So does a package where either half did not finish (status not ok), even if neither half produced a folder row.
        if (measured == 0 || notCached > 0 || incomplete.Count > 0)
        {
            if (measured == 0 || notCached > 0)
                Console.Error.WriteLine("NOT-COMPARABLE " + (measured == 0 ? "no package was measured" : $"{notCached} manifest entr(ies) not cached; nothing was downloaded"));
            foreach (var package in incomplete)
                Console.Error.WriteLine($"NOT-COMPARABLE {package}");
            return NotComparableExitCode;
        }
        Console.WriteLine("PARITY every folder agrees");
        return 0;
    }

    private static ReachabilityOptions? ParseReachability(string[] args)
    {
        string? Value(string name)
        {
            var index = Array.IndexOf(args, name);
            return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
        }

        if (Value("--results") is not { } results)
            return null;

        // This mode's own defaults: every manifest entry (--take 0) and a 600 s child timeout.
        var common = Parse(args);
        if (Value("--take") is null)
            common = common with { Take = 0 };
        if (Value("--timeout") is null)
            common = common with { ChildTimeout = TimeSpan.FromSeconds(DefaultReachabilityTimeoutSeconds) };
        return new ReachabilityOptions(
            common,
            Path.GetFullPath(results),
            Value("--max-children") is { } max ? int.Parse(max, CultureInfo.InvariantCulture) : int.MaxValue,
            Value("--date") is { } date
                ? DateOnly.ParseExact(date, "yyyy-MM-dd", CultureInfo.InvariantCulture)
                : DateOnly.FromDateTime(DateTime.UtcNow));
    }

    private static HarnessOptions Parse(string[] args)
    {
        string Value(string name, string fallback)
        {
            var index = Array.IndexOf(args, name);
            return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
        }

        var take = int.Parse(Value("--take", "25"), CultureInfo.InvariantCulture);
        var timeout = double.Parse(Value("--timeout", "300"), CultureInfo.InvariantCulture);

        return new HarnessOptions(
            Path.GetFullPath(Value("--manifest", Path.Combine(AppContext.BaseDirectory, ManifestFileName))),
            take,
            Path.GetFullPath(Value("--cache", DefaultCacheRoot())),
            Path.GetFullPath(Value("--out", Path.Combine(RepositoryRoot(), "docs", "agent", "measurements"))),
            TimeSpan.FromSeconds(timeout));
    }

    // Outside the repository by construction: the machine's local app-data, never a path under the checkout.
    private static string DefaultCacheRoot() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify)
                is { Length: > 0 } local ? local : Path.GetTempPath(),
            "Silvergun",
            "benign-corpus");

    // The .exe/apphost of THIS harness, which the driver re-invokes per assembly. Environment.ProcessPath is the
    // apphost for a built binary but is 'dotnet' under 'dotnet run', which would make the child a no-op - so prefer
    // the apphost sitting next to the managed assembly whenever it exists.
    private static string HarnessExecutable()
    {
        var name = typeof(Program).Assembly.GetName().Name!;
        var apphost = Path.Combine(
            AppContext.BaseDirectory, OperatingSystem.IsWindows() ? $"{name}.exe" : name);
        return File.Exists(apphost) ? apphost : Environment.ProcessPath
            ?? throw new InvalidOperationException("Could not locate this harness's own executable.");
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, ".git")) || File.Exists(Path.Combine(dir.FullName, ".git")))
                return dir.FullName;

        return Directory.GetCurrentDirectory();
    }

    private static bool IsInsideRepository(string path) =>
        path.StartsWith(RepositoryRoot() + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    #endregion

    #region Fields
    public const string ManifestFileName = "benign-corpus.manifest";

    /// <summary>The 2026-08-21 presence baseline as data, copied next to the executable.</summary>
    public const string OracleFileName = "presence-oracle-2026-08-21.tsv";

    private const string ReachabilityFlag = "--reachability";

    private const string WorkerParityFlag = "--worker-parity";

    /// <summary><c>--worker-parity</c> wrote its report, and some folder differs between the in-process pass and the worker.</summary>
    public const int ParityMismatchExitCode = 4;

    private const int DefaultReachabilityTimeoutSeconds = 600;

    /// <summary><c>--reachability</c> wrote its report, but the population is not comparable, so it carries no verdict.</summary>
    public const int NotComparableExitCode = 3;

    private const string Usage = """
        Benign-corpus harness (measurement instrument; changes no scoring).

          <harness> [--manifest <path>] [--take <n>] [--cache <dir>] [--out <dir>] [--timeout <seconds>]
          <harness> scan <assembly-path>     (child mode - one assembly, one process; see ADR-0021)

          --manifest  pinned 'id,version' list. Default: benign-corpus.manifest next to the executable.
          --take      keep the first n manifest entries; 0 keeps all. Default 25.
          --cache     .nupkg/extraction cache. Default %LOCALAPPDATA%/Silvergun/benign-corpus.
                      MUST be outside the repository - a .nupkg is never committed.
          --out       report directory. Default <repo>/docs/agent/measurements.
          --timeout   per-child-process timeout in seconds. Default 300.

          <harness> --reachability --results <dir> [--max-children <n>] [--date <yyyy-MM-dd>] [common options]
          <harness> reach <nupkg> <out-json>  (child mode - one package, one process)

          Reachability R2 (docs/agent/tasks/reachability-r2.md). OFFLINE: reads <cache>/packages/<Id>.<Version>.nupkg
          and never downloads; a missing package is 'not-cached'. One child per package (timeout default 600 s;
          --take defaults to 0, every entry); each result is cached as <results>/<Id>.<Version>.json and reused;
          results of another build (git describe --dirty + assembly hash) are refused.
          --max-children  new children to run in this invocation. Default unlimited.
          --date          the date in the report's file name. Default today (UTC).
          Once every entry has a result, writes reachability-benign-<date>.md, .tsv and -cost.md into --out.
          Exit 3 after writing it when the population is not comparable (oracle not a full MATCH, or not-cached).

          <harness> --worker-parity [--date <yyyy-MM-dd>] [common options]
          <harness> parity-inproc <nupkg> <out-json>  (child mode - the in-process graph pass of one package)

          Graph worker S3 (docs/agent/tasks/graph-worker.md). OFFLINE, the same cache and manifest as --reachability
          (--take defaults to 0, the child timeout to 600 s). Per cached package: the in-process PackageGraphs.Build +
          Reachability.Analyze in a child, then PackageReachability.Analyze through the Silvergun.CLI worker beside the
          harness. Writes worker-parity-<date>.tsv (per folder), -packages.tsv (per package, wall times) and .md into --out.
          Exit 4 after writing them when any folder differs; else exit 3 when no package was measured or any entry was
          not cached (not comparable).
        """;
    #endregion
}
