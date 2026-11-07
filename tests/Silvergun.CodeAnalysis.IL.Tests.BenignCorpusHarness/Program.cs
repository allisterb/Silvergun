namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

/// <summary>
/// Resolved run configuration. Every default is chosen so that a bare <c>run</c> is a small, bounded, repeatable
/// measurement: 25 pinned packages, a cache outside the repository, and output into <c>data/results</c>.
/// </summary>
public sealed record HarnessOptions(
    string Manifest,
    int Take,
    string CacheRoot,
    string OutputDirectory,
    TimeSpan ChildTimeout);

/// <summary>The <c>--reachability</c> options on top of the common ones; <see cref="Oracle"/> is the presence oracle's path.</summary>
public sealed record ReachabilityOptions(HarnessOptions Common, string Results, int MaxChildren, DateOnly Date, string Oracle);

/// <summary>The <c>--combine</c> options (R2b S4): both manifests, each with its results and repeat directories, and the oracle.</summary>
public sealed record CombineOptions(
    string C100Manifest, string C100Results, string C100Repeat, string CbuildManifest, string CbuildResults, string CbuildRepeat,
    string Oracle, string OutputDirectory, DateOnly Date);

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

            if (args.Contains(CombineFlag))
                return RunCombine(args);
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
        var oracle = PresenceOracle.Parse(File.ReadAllText(options.Oracle));
        var harness = HarnessExecutable();

        Console.WriteLine($"manifest {manifest.Path}");
        Console.WriteLine($"manifest-hash {manifest.Hash} ({manifest.Entries.Count} package(s))");
        Console.WriteLine($"cache {common.CacheRoot} (read only)");
        Console.WriteLine($"results {options.Results}");
        Console.WriteLine($"oracle {options.Oracle}");
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

            var context = new ReachabilityReportContext(options.Date, manifest, common.CacheRoot, identity, common.ChildTimeout, oracle, Path.GetFileName(options.Oracle));
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

    // --combine (reachability R2b S4): offline like --reachability, and it runs no child either: it reads four results
    // directories, never a package cache. Writes reachability-combine-<date>.md; exit 3 when a gate fails (no verdict).
    private static int RunCombine(string[] args)
    {
        if (ParseCombine(args) is not { } options)
        {
            Console.Error.WriteLine("--combine needs --c100-manifest, --c100-results, --c100-repeat, --cbuild-results and --cbuild-repeat; see --help.");
            return 2;
        }

        var identity = BuildIdentities.Current(RepositoryRoot(), AppContext.BaseDirectory);
        var oracle = PresenceOracle.Parse(File.ReadAllText(options.Oracle));
        var c100Manifest = CorpusManifest.Load(options.C100Manifest, 0);
        var cbuildManifest = CorpusManifest.Load(options.CbuildManifest, 0);
        Console.WriteLine($"c100 {c100Manifest.Path} ({c100Manifest.Entries.Count} package(s)); results {options.C100Results}; repeat {options.C100Repeat}");
        Console.WriteLine($"c-build {cbuildManifest.Path} ({cbuildManifest.Entries.Count} package(s), hash {cbuildManifest.Hash}); results {options.CbuildResults}; repeat {options.CbuildRepeat}");
        Console.WriteLine($"oracle {options.Oracle}");
        Console.WriteLine($"identity {identity}");

        try
        {
            var result = ReachabilityCombine.Combine(
                ReachabilityCombine.ReadSide(ReachabilityCombine.C100Name, c100Manifest, options.C100Results, options.C100Repeat),
                ReachabilityCombine.ReadSide(ReachabilityCombine.CbuildName, cbuildManifest, options.CbuildResults, options.CbuildRepeat),
                oracle, identity, ReachabilityCombine.PinnedCbuildManifestHash);
            Console.WriteLine($"wrote {ReachabilityCombine.Write(options.OutputDirectory, options.Date, Path.GetFileName(options.Oracle), identity, result)}");
            if (result.NotComparable is not null)
            {
                Console.Error.WriteLine($"NOT-COMPARABLE {result.NotComparable}");
                return NotComparableExitCode;
            }
            foreach (var verdict in ReachabilityAggregation.Labels.SelectMany(result.Verdicts))
                Console.WriteLine($"VERDICT {verdict.Class} {verdict.Label}: {verdict.Verdict}");
            return 0;
        }
        catch (MixedBuildException ex)
        {
            Console.Error.WriteLine($"FAILED {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// The <c>--combine</c> options, or null when a required one is missing. <c>--cbuild-manifest</c> defaults to
    /// <see cref="CbuildManifestFileName"/> beside the harness, <c>--oracle</c> as for <c>--reachability</c>
    /// (<see cref="OracleOf"/>), <c>--out</c> to <c>data/results</c>, <c>--date</c> to today (UTC).
    /// </summary>
    public static CombineOptions? ParseCombine(string[] args)
    {
        string? Value(string name)
        {
            var index = Array.IndexOf(args, name);
            return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
        }

        string[] required = ["--c100-manifest", "--c100-results", "--c100-repeat", "--cbuild-results", "--cbuild-repeat"];
        if (required.Select(Value).ToArray() is not [{ } c100, { } c100Results, { } c100Repeat, { } cbuildResults, { } cbuildRepeat])
            return null;
        return new CombineOptions(
            Path.GetFullPath(c100), Path.GetFullPath(c100Results), Path.GetFullPath(c100Repeat),
            Path.GetFullPath(Value("--cbuild-manifest") ?? Path.Combine(AppContext.BaseDirectory, CbuildManifestFileName)),
            Path.GetFullPath(cbuildResults), Path.GetFullPath(cbuildRepeat),
            OracleOf(args),
            Path.GetFullPath(Value("--out") ?? DefaultOutputDirectory()),
            DateOf(args));
    }

    /// <summary>The presence oracle's path: <c>--oracle &lt;path&gt;</c>, else <see cref="OracleFileName"/> beside the harness.</summary>
    public static string OracleOf(string[] args)
    {
        var index = Array.IndexOf(args, "--oracle");
        return Path.GetFullPath(index >= 0 && index + 1 < args.Length ? args[index + 1] : Path.Combine(AppContext.BaseDirectory, OracleFileName));
    }

    private static DateOnly DateOf(string[] args)
    {
        var index = Array.IndexOf(args, "--date");
        return index >= 0 && index + 1 < args.Length
            ? DateOnly.ParseExact(args[index + 1], "yyyy-MM-dd", CultureInfo.InvariantCulture)
            : DateOnly.FromDateTime(DateTime.UtcNow);
    }

    /// <summary>The <c>--reachability</c> options, or null without <c>--results</c>.</summary>
    public static ReachabilityOptions? ParseReachability(string[] args)
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
            DateOf(args),
            OracleOf(args));
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
            Path.GetFullPath(Value("--out", DefaultOutputDirectory())),
            TimeSpan.FromSeconds(timeout));
    }

    // Reports are tracked results: <repo>/data/results.
    private static string DefaultOutputDirectory() => Path.Combine(RepositoryRoot(), "data", "results");

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

    /// <summary>
    /// <paramref name="path"/> as a committed report shows it: under the local app-data or the user-profile folder it
    /// starts <c>%LOCALAPPDATA%</c> or <c>%USERPROFILE%</c> instead (<c>~</c> for the home folder off Windows), so no
    /// report names the machine's account. Only the spelling the OS reports is matched, not <c>\\?\</c> or 8.3 forms.
    /// </summary>
    public static string DisplayPath(string path) => DisplayPath(path, ProfileRoots());

    /// <summary>
    /// <paramref name="text"/> (an exception message, a child's stderr line) with every profile root in it replaced as
    /// <see cref="DisplayPath(string)"/> does. Apply before any escaping that rewrites separators.
    /// </summary>
    public static string Redact(string text) => Redact(text, ProfileRoots());

    /// <summary>
    /// <paramref name="text"/> with every occurrence of each root (case-insensitive, not followed by a name character)
    /// replaced by its name, roots in order; empty and bare drive or <c>/</c> roots are ignored.
    /// </summary>
    public static string Redact(string text, IReadOnlyList<(string Root, string Name)> roots) =>
        roots
            .Select(r => (Root: Path.TrimEndingDirectorySeparator(r.Root), r.Name))
            .Where(r => r.Root.Length > 0 && Path.GetPathRoot(r.Root)?.Length != r.Root.Length)
            .Aggregate(text, (t, r) => Regex.Replace(t, Regex.Escape(r.Root) + @"(?![\w-])", r.Name.Replace("$", "$$"),
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    private static IReadOnlyList<(string Root, string Name)> ProfileRoots() =>
        OperatingSystem.IsWindows()
            ?
            [
                (Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify), "%LOCALAPPDATA%"),
                (Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify), "%USERPROFILE%"),
            ]
            : [(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify), "~")];

    /// <summary><paramref name="path"/> with the first matching root (case-insensitive, whole segments) replaced by its name.</summary>
    public static string DisplayPath(string path, IReadOnlyList<(string Root, string Name)> roots) =>
        roots
            .Select(r => (Root: Path.TrimEndingDirectorySeparator(r.Root), r.Name))
            .Where(r => r.Root.Length > 0)
            .Where(r => path.Equals(r.Root, StringComparison.OrdinalIgnoreCase)
                || (path.StartsWith(r.Root, StringComparison.OrdinalIgnoreCase) && path.Length > r.Root.Length
                    && (path[r.Root.Length] == Path.DirectorySeparatorChar || path[r.Root.Length] == Path.AltDirectorySeparatorChar)))
            .Select(r => r.Name + path[r.Root.Length..])
            .FirstOrDefault() ?? path;
    #endregion

    #region Fields
    public const string ManifestFileName = "benign-corpus.manifest";

    /// <summary>
    /// The default presence oracle (<c>--oracle</c>), copied next to the executable: R2b's baseline on the S2 map
    /// (<c>reachability-r2b.md</c>, "Re-baseline").
    /// </summary>
    public const string OracleFileName = "presence-oracle-2026-11-06.tsv";

    /// <summary>R2's presence oracle, the 2026-08-21 baseline on the R2 map; kept beside it as R2's record.</summary>
    public const string R2OracleFileName = "presence-oracle-2026-08-21.tsv";

    /// <summary>The C-build manifest (R2b S3), copied next to the executable: <c>--combine</c>'s default <c>--cbuild-manifest</c>.</summary>
    public const string CbuildManifestFileName = "c-build.manifest";

    private const string ReachabilityFlag = "--reachability";

    private const string CombineFlag = "--combine";

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
          --out       report directory. Default <repo>/data/results.
          --timeout   per-child-process timeout in seconds. Default 300.

          <harness> --reachability --results <dir> [--max-children <n>] [--date <yyyy-MM-dd>] [--oracle <path>] [common options]
          <harness> reach <nupkg> <out-json>  (child mode - one package, one process)

          Reachability R2/R2b (docs/agent/tasks/reachability-r2.md, reachability-r2b.md). OFFLINE: reads
          <cache>/packages/<Id>.<Version>.nupkg and never downloads; a missing package is 'not-cached'. One child per
          package (timeout default 600 s; --take defaults to 0, every entry); each result is cached as
          <results>/<Id>.<Version>.json and reused (one of an older result schema is re-measured); results of another
          build (git describe --dirty + assembly hash) are refused.
          --max-children  new children to run in this invocation. Default unlimited.
          --date          the date in the report's file name. Default today (UTC).
          --oracle        the presence oracle. Default presence-oracle-2026-11-06.tsv next to the executable (R2b, the
                          S2 map); presence-oracle-2026-08-21.tsv beside it is R2's.
          Once every entry has a result, writes reachability-benign-<date>.md, .tsv and -cost.md into --out. Each trigger
          class is judged at ChaOnly and Direct; TypeInitializer, Finalizer and NativeEntry here (P-lib and P-all, both
          must pass); HostContract and LoadTime only by --combine (their cells read 'judged by --combine').
          Exit 3 after writing it when the population is not comparable (oracle not a full MATCH, or not-cached).

          <harness> --combine --c100-manifest <path> --c100-results <dir> --c100-repeat <dir>
                    --cbuild-results <dir> --cbuild-repeat <dir> [--cbuild-manifest <path>] [--oracle <path>]
                    [--out <dir>] [--date <yyyy-MM-dd>]

          Reachability R2b S4, the combine step. OFFLINE: reads the four --reachability results directories (a run and
          its repeat per manifest); runs no child and opens no cache. --cbuild-manifest defaults to c-build.manifest next
          to the executable. Gates: the C-build manifest is the pinned c-build.manifest (by its hash; no option changes
          that); C100's oracle, recomputed from its results, a full MATCH with 0 not-cached; C-build 0 not-cached; each
          run and its repeat identical per package (results without cost, temp paths masked); no id in both manifests. Judges HostContract and LoadTime at ChaOnly and Direct on P-all over C100 and C-build, one
          denominator, both runs' floor packages counted. Writes reachability-combine-<date>.md into --out.
          Exit 3 after writing it when a gate fails (no verdict); 1 when results of another build are found.

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
