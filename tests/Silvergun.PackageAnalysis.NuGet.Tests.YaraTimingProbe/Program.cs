namespace Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe;

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

// Drives libyara.NET's public API DIRECTLY (YaraContext / Compiler / Rules / Scanner) rather than
// Silvergun's LibYaraScanner: the product class caps every scan at 30 s (which would truncate every
// reading this probe wants) and compiles the whole ruleset in one shot (this probe needs subsets).
using libyaraNET;

/// <summary>
/// Out-of-process timing probe for the Windows in-process YARA backend
/// (<c>docs/agent/tasks/yara-inprocess-timing-probe.md</c>). Answers "why does an in-process scan of a
/// 26 KB file take &gt; 30 s on Windows when native yara 4.1.3 scans the same bytes with the same rules in
/// 0.03 s" by separating fixed per-scan overhead (H1) from per-byte cost (H2), per-rule cost (H3), the
/// <c>fd</c>/file-mapping path (H4) and input-specific pathology (H5).
///
/// <para>Every scan runs on a pool thread under a 120 s watchdog. A blocked native
/// <c>yr_rules_scan_fd</c>/<c>yr_rules_scan_mem</c> call cannot be cancelled from managed code, so a
/// watchdog hit is terminal for the process: the row is written as <c>ElapsedMs=-1 / Note=timeout</c>,
/// the TSV is flushed, the summary is printed and the process exits 2. Re-run with
/// <c>--experiments</c> / <c>--max-rules</c> / <c>--append</c> to continue with a smaller ruleset.</para>
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        // A third, unrelated set of modes: the process-isolation cost measurement (IsolationCost.cs,
        // docs/agent/tasks/yara-process-isolation-measurement.md). Every one of them exits explicitly: a worker
        // must not linger, and none of them may fall through to the timing probe's own argument parser.
        if (IsolationCost.Handles(args))
        {
            var code = IsolationCost.Run(args);
            Console.Out.Flush();
            Console.Error.Flush();
            Environment.Exit(code);
        }

        // A second, unrelated mode: the ADR 0028 canary mutation check (see PoisonCanaryCheck). It lives here
        // because this project is the one place in tests/ that already loads native libyara under -r win-x64,
        // and it must NOT run in the xUnit host — it deliberately abandons a native thread walking a corrupt
        // YR_RULES. The whole call is guarded because a libyara.NET LOAD failure surfaces when Run() is
        // JIT-resolved, i.e. at this call site, and must still leave a documented exit code behind.
        if (args is [PoisonCanaryCheck.Switch, ..])
        {
            int code;
            try
            {
                code = PoisonCanaryCheck.Run();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[poison-canary] FAIL({PoisonCanaryCheck.NativeLoadFailed}): could not load the native libyara.NET assembly: {ex.GetType().Name}: {ex.Message}");
                code = PoisonCanaryCheck.NativeLoadFailed;
            }

            Console.Out.Flush();
            Console.Error.Flush();
            // Leave AT ONCE. The verdict is already known and every further millisecond in this process is
            // exposure to the abandoned native thread the check deliberately left running.
            Environment.Exit(code);
        }

        var options = ProbeOptions.Parse(args);
        Directory.CreateDirectory(Path.GetDirectoryName(options.TsvPath)!);
        Directory.CreateDirectory(options.SyntheticDir);

        using var writer = new TsvWriter(options.TsvPath, options.Append);
        var probe = new Probe(options, writer);
        return probe.Run();
    }
}

/// <summary>Command line, all defaults chosen so a bare run reproduces the spec's experiment plan.</summary>
internal sealed record ProbeOptions(
    string RepoRoot,
    string PkgDir,
    string SyntheticDir,
    string TsvPath,
    TimeSpan Watchdog,
    int MaxRuleFiles,
    bool Append,
    IReadOnlySet<string> Experiments,
    IReadOnlyList<int> Subsets,
    IReadOnlyList<int> Sizes,
    int RuleOffset)
{
    public static ProbeOptions Parse(string[] args)
    {
        var repoRoot = FindRepoRoot();
        var pkg = Path.Combine(repoRoot, "scratch-yara", "pkg");
        var synthetic = Path.Combine(repoRoot, "scratch-yara", "synthetic");
        var tsv = Path.Combine(repoRoot, "docs", "agent", "measurements", "yara-inprocess-timing-2026-08-21.tsv");
        var watchdog = TimeSpan.FromSeconds(120);
        var maxRules = int.MaxValue;
        var append = false;
        var experiments = new HashSet<string>(AllExperiments, StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<int> subsets = DefaultSubsets;
        IReadOnlyList<int> sizes = DefaultSizes;
        var ruleOffset = 0;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            string Next() => ++i < args.Length ? args[i] : throw new ArgumentException($"Missing value for {arg}.");

            switch (arg)
            {
                case "--pkg": pkg = Next(); break;
                case "--synthetic": synthetic = Next(); break;
                case "--out": tsv = Next(); break;
                case "--timeout-seconds": watchdog = TimeSpan.FromSeconds(double.Parse(Next(), CultureInfo.InvariantCulture)); break;
                case "--max-rules": maxRules = int.Parse(Next(), CultureInfo.InvariantCulture); break;
                case "--append": append = true; break;
                case "--experiments":
                    experiments = new HashSet<string>(
                        Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                        StringComparer.OrdinalIgnoreCase);
                    break;
                case "--subsets":
                    subsets = Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(v => int.Parse(v, CultureInfo.InvariantCulture)).ToArray();
                    break;
                case "--sizes":
                    sizes = Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(v => int.Parse(v, CultureInfo.InvariantCulture)).ToArray();
                    break;
                case "--rule-offset": ruleOffset = int.Parse(Next(), CultureInfo.InvariantCulture); break;
                default: throw new ArgumentException($"Unknown argument '{arg}'.");
            }
        }

        return new ProbeOptions(repoRoot, pkg, synthetic, tsv, watchdog, maxRules, append, experiments, subsets, sizes, ruleOffset);
    }

    public bool Wants(string experiment) => Experiments.Contains(experiment);

    // Walks up from the probe's output directory to the directory holding CLAUDE.md, so the TSV lands in
    // the repo regardless of where the exe is launched from.
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CLAUDE.md")))
            dir = dir.Parent;

        return dir?.FullName ?? Directory.GetCurrentDirectory();
    }

    public static readonly string[] AllExperiments = ["E1", "E4", "E7", "E3", "E2"];

    /// <summary>The spec's E4 rule-count ladder. <c>--subsets</c> overrides it to densify the curve on a resume run.</summary>
    public static readonly int[] DefaultSubsets = [1, 2, 4, 8, 16, 32, 64, 128, 309];

    /// <summary>The spec's E3 size ladder. <c>--sizes</c> overrides it to locate a size knee.</summary>
    public static readonly int[] DefaultSizes = [1, 1024, 26653, 262144, 1048576];
}

/// <summary>Line-buffered, always-flushed TSV sink. Flushed after every row so a watchdog exit keeps the data.</summary>
internal sealed class TsvWriter : IDisposable
{
    public TsvWriter(string path, bool append)
    {
        var writeHeader = !append || !File.Exists(path);
        writer = new StreamWriter(new FileStream(path, append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.Read), new UTF8Encoding(false));
        if (writeHeader)
            writer.WriteLine("Experiment\tLabel\tBytes\tRuleFiles\tIteration\tElapsedMs\tMatches\tNote");
        writer.Flush();
    }

    public void Row(string experiment, string label, long bytes, int ruleFiles, int iteration, long elapsedMs, int matches, string note)
    {
        writer.WriteLine(string.Join('\t',
            Clean(experiment), Clean(label),
            bytes.ToString(CultureInfo.InvariantCulture),
            ruleFiles.ToString(CultureInfo.InvariantCulture),
            iteration.ToString(CultureInfo.InvariantCulture),
            elapsedMs.ToString(CultureInfo.InvariantCulture),
            matches.ToString(CultureInfo.InvariantCulture),
            Clean(note)));
        writer.Flush();
    }

    public void Dispose() => writer.Dispose();

    private static string Clean(string value) => value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

    private readonly StreamWriter writer;
}

/// <summary>Result of one watchdogged native call.</summary>
internal readonly record struct Timed(long ElapsedMs, int Matches, bool TimedOut, string? Error)
{
    public string Note => TimedOut ? "timeout" : Error is null ? string.Empty : "error:" + Error;
}

internal sealed class Probe
{
    public Probe(ProbeOptions options, TsvWriter tsv)
    {
        this.options = options;
        this.tsv = tsv;
    }

    public int Run()
    {
        WriteEnvironmentRows();

        var ruleTexts = LoadRuleResources();
        if (ruleTexts.Count == 0)
        {
            Console.Error.WriteLine("FATAL: no embedded .yara resources found.");
            return 1;
        }

        // yr_initialize for the process. Deliberately never disposed: yr_finalize while an abandoned native
        // scan thread is still running would be a use-after-free.
        context = new YaraContext();
        scanner = new Scanner();

        var p7s = Path.Combine(options.PkgDir, ".signature.p7s");
        if (!File.Exists(p7s))
        {
            Console.Error.WriteLine($"FATAL: expected test input not found: {p7s}");
            return 1;
        }

        // --- E1 compile: the whole discovered ruleset in one Compiler, exactly like LibYaraScanner.BuildEngine.
        if (options.Wants("E1"))
        {
            // --max-rules caps E1 too, so a resume run after a watchdog exit rebuilds only the smaller
            // working ruleset instead of paying for the full compile again.
            var e1Count = Math.Min(ruleTexts.Count, options.MaxRuleFiles);
            var full = CompileSubset("E1", e1Count == ruleTexts.Count ? "all" : $"capped{e1Count}", e1Count, ruleTexts);
            workingRules = full.Rules;
            workingRuleFiles = full.Compiled;
        }

        // --- E4 rulecount: the decisive H3 experiment. Fewest rules first so a watchdog hit loses least.
        if (options.Wants("E4"))
            RunRuleCount(ruleTexts, p7s);

        if (workingRules is null)
        {
            Console.Error.WriteLine("FATAL: no ruleset available for the remaining experiments.");
            return 1;
        }

        if (options.Wants("E7")) RunFileVsMemory(p7s);
        if (options.Wants("E3")) RunSizeScale();
        if (options.Wants("E2")) RunPerFile();

        PrintSummary();
        GC.KeepAlive(context);   // yr_initialize must outlive every scan above
        return 0;
    }

    #region Experiments
    // E4: fresh Compiler per subset, same process/YaraContext, first N rule files in sorted order, one scan
    // of the same .signature.p7s per N. A linear time-vs-N curve is H3; a flat curve is H1.
    private void RunRuleCount(IReadOnlyList<RuleResource> ruleTexts, string p7s)
    {
        var bytes = new FileInfo(p7s).Length;
        foreach (var n in Subsets(ruleTexts.Count))
        {
            var subset = CompileSubset("E4", $"first{n}", n, ruleTexts);
            var timed = Scan(() => scanner!.ScanFile(p7s, subset.Rules));
            Record("E4", $"first{n}", bytes, subset.Compiled, 1, timed, $"attempted={n};skipped={subset.Skipped}");

            if (!timed.TimedOut && timed.Error is null)
            {
                workingRules = subset.Rules;
                workingRuleFiles = subset.Compiled;
                largestCompletedSubset = n;
            }
        }
    }

    // E7: same bytes down two different native entry points - yr_rules_scan_fd vs yr_rules_scan_mem.
    // Interleaved so a watchdog hit still leaves one reading of each. H4.
    private void RunFileVsMemory(string p7s)
    {
        var buffer = File.ReadAllBytes(p7s);
        for (var i = 1; i <= 2; i++)
        {
            var mem = Scan(() => scanner!.ScanMemory(buffer, workingRules!));
            Record("E7", "ScanMemory", buffer.Length, workingRuleFiles, i, mem, "yr_rules_scan_mem");

            var file = Scan(() => scanner!.ScanFile(p7s, workingRules!));
            Record("E7", "ScanFile", buffer.Length, workingRuleFiles, i, file, "yr_rules_scan_fd");
        }
    }

    // E3: deterministic synthetic inputs, smallest first. Flat times => H1 (fixed overhead);
    // times proportional to size => H2 (per-byte cost).
    private void RunSizeScale()
    {
        foreach (var size in options.Sizes)
        {
            foreach (var (flavour, make) in SyntheticFlavours)
            {
                var path = Path.Combine(options.SyntheticDir, $"{flavour}-{size}.bin");
                File.WriteAllBytes(path, make(size));
                var timed = Scan(() => scanner!.ScanFile(path, workingRules!));
                Record("E3", $"{flavour}-{size}", size, workingRuleFiles, 1, timed, flavour == "rand" ? "Random(42)" : "all-zero");
            }
        }
    }

    // E2: every real package file, 3 consecutive iterations, smallest first. H5 + warm/cold.
    private void RunPerFile()
    {
        var files = Directory.EnumerateFiles(options.PkgDir, "*", SearchOption.AllDirectories)
            .Select(p => new FileInfo(p))
            .OrderBy(f => f.Length)
            .ThenBy(f => f.FullName, StringComparer.Ordinal)
            .ToArray();

        foreach (var file in files)
        {
            var label = Path.GetRelativePath(options.PkgDir, file.FullName).Replace('\\', '/');
            for (var i = 1; i <= 3; i++)
            {
                var timed = Scan(() => scanner!.ScanFile(file.FullName, workingRules!));
                Record("E2", label, file.Length, workingRuleFiles, i, timed, string.Empty);
            }
        }
    }
    #endregion

    #region Engine
    private CompiledSubset CompileSubset(string experiment, string label, int count, IReadOnlyList<RuleResource> ruleTexts)
    {
        var compiler = new Compiler();
        compilers.Add(compiler);   // rooted for the process lifetime; never disposed while its Rules are in use

        var compiled = 0;
        var skipped = new List<string>();
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < count; i++)
        {
            try
            {
                compiler.AddRuleString(ruleTexts[i].Text);
                compiled++;
            }
            catch (Exception ex)
            {
                skipped.Add(ruleTexts[i].ShortName);
                if (skippedReported.Add(ruleTexts[i].ShortName))
                    Console.WriteLine($"  skipped rule file {ruleTexts[i].ShortName}: {ex.Message.Replace('\n', '|').Replace("\r", string.Empty)}");
            }
        }

        var rules = compiler.GetRules();
        sw.Stop();
        rulesets.Add(rules);

        var span = count == 0 ? "none" : $"{ruleTexts[0].ShortName}..{ruleTexts[count - 1].ShortName}";
        var note = $"attempted={count};ruleOffset={options.RuleOffset};skipped={skipped.Count};files={span}" + (skipped.Count > 0 ? ";skippedFiles=" + string.Join('|', skipped) : string.Empty);
        var rowExperiment = experiment == "E1" ? "E1" : "E4";
        tsv.Row(rowExperiment, experiment == "E1" ? $"compile-{label}" : $"compile-subset-{label}", 0, compiled, 1, sw.ElapsedMilliseconds, 0, note);
        Console.WriteLine($"[{rowExperiment}] compile {label}: {compiled} file(s) compiled, {skipped.Count} skipped, {sw.ElapsedMilliseconds} ms [{span}]");
        summary.Add($"{rowExperiment} compile {label}: {sw.ElapsedMilliseconds} ms ({compiled} rule files)");

        if (experiment == "E1")
            compileAllMs = sw.ElapsedMilliseconds;

        return new CompiledSubset(rules, compiled, skipped.Count);
    }

    // The 120 s watchdog. The native call keeps running on its pool thread after a timeout - the process is
    // not recoverable, so the caller exits rather than pretending the next reading is comparable.
    private Timed Scan(Func<List<ScanResult>> scan)
    {
        var sw = Stopwatch.StartNew();
        var task = Task.Run(scan);
        if (!task.Wait(options.Watchdog))
            return new Timed(-1, 0, true, null);

        sw.Stop();
        if (task.IsFaulted)
            return new Timed(sw.ElapsedMilliseconds, 0, false, (task.Exception?.GetBaseException().Message ?? "unknown").Replace('\n', '|').Replace("\r", string.Empty));

        return new Timed(sw.ElapsedMilliseconds, task.Result?.Count ?? 0, false, null);
    }

    private void Record(string experiment, string label, long bytes, int ruleFiles, int iteration, Timed timed, string note)
    {
        var combined = string.IsNullOrEmpty(timed.Note) ? note : string.IsNullOrEmpty(note) ? timed.Note : timed.Note + ";" + note;
        tsv.Row(experiment, label, bytes, ruleFiles, iteration, timed.ElapsedMs, timed.Matches, combined);

        var line = timed.TimedOut
            ? $"[{experiment}] {label} ({bytes} B, {ruleFiles} rules) iter {iteration}: TIMEOUT after {options.Watchdog.TotalSeconds:0} s"
            : $"[{experiment}] {label} ({bytes} B, {ruleFiles} rules) iter {iteration}: {timed.ElapsedMs} ms, {timed.Matches} match(es){(timed.Error is null ? string.Empty : " ERROR " + timed.Error)}";
        Console.WriteLine(line);
        summary.Add(line);

        if (timed.TimedOut)
        {
            PrintSummary();
            Console.Error.WriteLine($"WATCHDOG: abandoning the process after a {options.Watchdog.TotalSeconds:0} s scan timeout (the native call cannot be cancelled).");
            Console.Error.WriteLine($"Resume with: --append --experiments <remaining> --max-rules <N smaller than {ruleFiles}>");
            Console.Out.Flush();
            Console.Error.Flush();
            tsv.Dispose();
            Environment.Exit(2);
        }
    }

    // Reads the embedded ruleset exactly as LibYaraScanner.BuildEngine does (marker + .yara suffix),
    // sorted by resource name for a deterministic subset selection.
    private List<RuleResource> LoadRuleResources()
    {
        var assembly = typeof(Silvergun.PackageAnalysis.NuGet.Yara.LibYaraScanner).Assembly;
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.Contains(RuleResourceMarker) && n.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        var result = new List<RuleResource>(names.Length);
        foreach (var name in names)
        {
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream is null) continue;
            using var reader = new StreamReader(stream);
            var index = name.IndexOf(RuleResourceMarker, StringComparison.Ordinal);
            result.Add(new RuleResource(name, name[(index + RuleResourceMarker.Length)..], reader.ReadToEnd()));
        }

        ruleFilesFound = result.Count;
        // --rule-offset drops the first K files so a single rule file can be compiled in isolation
        // (prefix bisect: `--rule-offset K --subsets 1` compiles exactly rule file index K).
        return options.RuleOffset > 0 ? result.Skip(options.RuleOffset).ToList() : result;
    }

    private IEnumerable<int> Subsets(int total)
    {
        var cap = Math.Min(total, options.MaxRuleFiles);
        return options.Subsets.Where(n => n <= cap).Distinct().OrderBy(n => n);
    }
    #endregion

    #region Reporting
    private void WriteEnvironmentRows()
    {
        var libyaraNet = Path.Combine(AppContext.BaseDirectory, "libyara.NET.dll");
        var rows = new (string Key, string Value)[]
        {
            ("Is64BitProcess", Environment.Is64BitProcess.ToString()),
            ("ProcessArchitecture", RuntimeInformation.ProcessArchitecture.ToString()),
            ("RuntimeIdentifier", RuntimeInformation.RuntimeIdentifier),
            ("FrameworkDescription", RuntimeInformation.FrameworkDescription),
            ("OSDescription", RuntimeInformation.OSDescription),
            ("BaseDirectory", AppContext.BaseDirectory),
            ("libyara.NET.dll", $"{libyaraNet} exists={File.Exists(libyaraNet)}"),
            ("ProcessorCount", Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture)),
            ("WatchdogSeconds", options.Watchdog.TotalSeconds.ToString(CultureInfo.InvariantCulture)),
            ("PkgDir", options.PkgDir),
            // Every invocation appends to the same TSV, so each run stamps its own arguments to make
            // rows attributable to the invocation that produced them.
            ("CommandLine", string.Join(' ', Environment.GetCommandLineArgs().Skip(1))),
        };

        foreach (var (key, value) in rows)
        {
            tsv.Row("env", key, 0, 0, 0, 0, 0, value);
            Console.WriteLine($"[env] {key} = {value}");
        }
    }

    private void PrintSummary()
    {
        // Rule accounting is only known after LoadRuleResources/CompileSubset, so it is emitted here as well
        // as on the console above; the spec asks for found/compiled/skipped and the compile ms as env rows.
        if (!environmentRuleRowsWritten && ruleFilesFound > 0)
        {
            environmentRuleRowsWritten = true;
            tsv.Row("env", "RuleFilesFound", 0, ruleFilesFound, 0, 0, 0, ruleFilesFound.ToString(CultureInfo.InvariantCulture));
            tsv.Row("env", "RuleFilesCompiled", 0, workingRuleFiles, 0, 0, 0, workingRuleFiles.ToString(CultureInfo.InvariantCulture));
            tsv.Row("env", "RuleFilesSkipped", 0, skippedReported.Count, 0, 0, 0, string.Join('|', skippedReported));
            // Only when E1 actually ran: ElapsedMs=-1 is reserved for the watchdog sentinel, so a
            // "not measured in this invocation" compile must not be written as -1.
            if (compileAllMs >= 0)
                tsv.Row("env", "CompileAllMs", 0, ruleFilesFound, 0, compileAllMs, 0, "E1 compile of every discovered rule file");
        }

        Console.WriteLine();
        Console.WriteLine("==== summary ====");
        Console.WriteLine($"rule files found={ruleFilesFound} compiled(working set)={workingRuleFiles} skipped={skippedReported.Count} compile-all={compileAllMs} ms");
        if (largestCompletedSubset > 0)
            Console.WriteLine($"largest E4 subset that completed within the watchdog: {largestCompletedSubset} rule file(s)");
        foreach (var line in summary)
            Console.WriteLine(line);
        Console.WriteLine($"TSV: {options.TsvPath}");
    }
    #endregion

    #region Types
    private readonly record struct RuleResource(string ResourceName, string ShortName, string Text);

    private readonly record struct CompiledSubset(Rules Rules, int Compiled, int Skipped);
    #endregion

    #region Fields
    private const string RuleResourceMarker = ".Resources.YaraRules.";

    private static readonly (string Flavour, Func<int, byte[]> Make)[] SyntheticFlavours =
    [
        ("zeros", size => new byte[size]),
        ("rand", size => { var b = new byte[size]; new Random(42).NextBytes(b); return b; }),
    ];

    private readonly ProbeOptions options;
    private readonly TsvWriter tsv;
    private readonly List<string> summary = [];
    private readonly List<Compiler> compilers = [];
    private readonly List<Rules> rulesets = [];
    private readonly HashSet<string> skippedReported = [];

    private YaraContext? context;
    private Scanner? scanner;
    private Rules? workingRules;
    private int workingRuleFiles;
    private int ruleFilesFound;
    private long compileAllMs = -1;
    private int largestCompletedSubset;
    private bool environmentRuleRowsWritten;
    #endregion
}
