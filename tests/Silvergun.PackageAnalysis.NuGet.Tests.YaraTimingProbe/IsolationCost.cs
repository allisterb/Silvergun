namespace Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Measurement for <c>docs/agent/tasks/yara-process-isolation-measurement.md</c> (input to ADR-0033): what does it
/// cost to host libyara.NET in a separate, killable worker process instead of in-process?
///
/// <para>Modes (each one is a separate process; the orchestrator never loads libyara itself):</para>
/// <list type="bullet">
/// <item><c>--isolation-cost</c> — the orchestrator. Spawns workers / in-process hosts, times them from the outside,
/// writes raw samples to a TSV. Every child is tracked by its <see cref="Process"/> object and killed by that
/// object only (never by name), and the orchestrator verifies at exit that every child it started is gone.</item>
/// <item><c>--worker</c> — the (W) design: native load, <c>YaraContext</c>, pass-1 validation of every rule
/// file in its own throwaway compiler, pass-2 compile of the valid ones, startup canary, then "ready" on stdout.
/// Afterwards it reads line-delimited JSON commands from stdin and answers on stdout. <c>--skip-pass1 &lt;file&gt;</c>
/// feeds pass 2 a known-good list (information only: the ADR-0028 poisoning guard depends on pass 1).
/// <c>--poisoned</c> deliberately rebuilds the ADR-0028 defect (one errored compiler, no canary) so a 4-byte
/// all-zero input never finishes scanning: the deterministic native hang M3 kills.</item>
/// <item><c>--inproc-host</c> — the in-process baseline: one engine built in this process exactly as the worker
/// builds it, each file scanned on a dedicated bounded thread exactly as <c>LibYaraScanner.TryRunBounded</c> does.</item>
/// <item><c>--extract</c> — extracts a list of corpus <c>.nupkg</c> files with .NET's <see cref="ZipFile"/>.</item>
/// <item><c>--dump-rules</c> — writes the embedded rule sources concatenated exactly as <c>YaraCliScanner</c> does,
/// for the WSL <c>yara</c>/<c>yarac</c> proxy (M5).</item>
/// </list>
///
/// <para>The engine build copies the SHAPE of <c>LibYaraScanner.BuildEngine</c> (two passes, canary of 64 zero
/// bytes under a 5 s bound) rather than calling its privates. All libyara-typed code lives in
/// <see cref="NativeYara"/> behind <see cref="MethodImplOptions.NoInlining"/> methods taking and returning
/// <see cref="object"/>, so the native assembly is loaded where the "nativeLoad" phase timer can see it rather
/// than when a caller is JIT-compiled.</para>
/// </summary>
internal static class IsolationCost
{
    #region Methods
    /// <summary>True when <paramref name="args"/> selects one of this file's modes.</summary>
    public static bool Handles(string[] args) =>
        args is [OrchestratorSwitch or WorkerSwitch or InProcSwitch or ExtractSwitch or DumpRulesSwitch, ..];

    public static int Run(string[] args) => args[0] switch
    {
        OrchestratorSwitch => Orchestrator.Run(args),
        WorkerSwitch => Worker.Run(args),
        InProcSwitch => InProcHost.Run(args),
        ExtractSwitch => Extract(args),
        DumpRulesSwitch => DumpRules(args),
        _ => 64,
    };

    internal static string? ValueOf(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    internal static string Required(string[] args, string name) =>
        ValueOf(args, name) ?? throw new ArgumentException($"Missing {name}.");

    // --extract --corpus <dir> --list <file of nupkg names> --dest <dir under C:\Temp\sg-iso> --trees-out <file>
    // Uses System.IO.Compression.ZipFile (.NET 10), which refuses entries that would land outside the destination.
    private static int Extract(string[] args)
    {
        var corpus = Required(args, "--corpus");
        var dest = Path.GetFullPath(Required(args, "--dest"));
        if (!dest.StartsWith(ScratchRoot, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"Refusing to extract outside {ScratchRoot}.");
            return 2;
        }

        var names = File.ReadAllLines(Required(args, "--list")).Select(l => l.Trim()).Where(l => l.Length > 0).ToArray();
        var trees = new List<string>();
        foreach (var name in names)
        {
            var src = Path.Combine(corpus, name);
            var tree = Path.Combine(dest, Path.GetFileNameWithoutExtension(name));
            if (Directory.Exists(tree))
            {
                Console.Error.WriteLine($"Destination already exists, refusing to overwrite: {tree}");
                return 3;
            }

            ZipFile.ExtractToDirectory(src, tree, overwriteFiles: false);
            var files = Directory.GetFiles(tree, "*", SearchOption.AllDirectories);
            Console.WriteLine($"{Path.GetFileName(tree)}\t{files.Length}\t{files.Sum(f => new FileInfo(f).Length)}");
            trees.Add(tree);
        }

        File.WriteAllLines(Required(args, "--trees-out"), trees);
        return 0;
    }

    // --dump-rules <file>: the embedded sources concatenated with the same "// name\n" + text + "\n" framing as
    // YaraCliScanner.CompileRules (without its per-run coverage sentinel).
    private static int DumpRules(string[] args)
    {
        var sb = new StringBuilder();
        var rules = RuleSources.ReadAll();
        foreach (var (name, text) in rules)
            sb.Append("// ").Append(name).Append('\n').Append(text).Append('\n');

        File.WriteAllText(args[1], sb.ToString(), new UTF8Encoding(false));
        Console.WriteLine($"{rules.Count} rule files, {sb.Length} chars -> {args[1]}");
        return 0;
    }
    #endregion

    #region Fields
    public const string OrchestratorSwitch = "--isolation-cost";
    public const string WorkerSwitch = "--worker";
    public const string InProcSwitch = "--inproc-host";
    public const string ExtractSwitch = "--extract";
    public const string DumpRulesSwitch = "--dump-rules";

    internal const string ScratchRoot = @"C:\Temp\sg-iso\";
    internal static readonly UTF8Encoding Utf8 = new(false);
    #endregion
}

/// <summary>The embedded rule sources, read exactly as <c>YaraRuleResources.ReadAll</c> reads them.</summary>
internal static class RuleSources
{
    // YaraOptions is a public, libyara-free type in the product assembly, so touching it loads the product
    // assembly (and its embedded resources) without loading libyara.NET.
    public static List<(string Name, string Text)> ReadAll()
    {
        var assembly = typeof(YaraOptions).Assembly;
        var result = new List<(string, string)>();
        foreach (var name in assembly.GetManifestResourceNames()
            .Where(n => n.Contains(Marker) && n.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream is null) continue;
            using var reader = new StreamReader(stream);
            result.Add((name, reader.ReadToEnd()));
        }

        return result;
    }

    private const string Marker = ".Resources.YaraRules.";
}

/// <summary>
/// Every libyara.NET reference in this measurement. Handles cross the boundary as <see cref="object"/> so no caller
/// is JIT-bound to libyara types (see <see cref="IsolationCost"/>).
/// </summary>
internal static class NativeYara
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string LoadAssembly() => typeof(libyaraNET.YaraContext).Assembly.FullName ?? "?";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object CreateContext() => Root(new libyaraNET.YaraContext());

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object CreateScanner() => Root(new libyaraNET.Scanner());

    // Pass 1 of LibYaraScanner.BuildEngine: one throwaway compiler per source, disposed either way.
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static bool CompilesCleanly(string text)
    {
        try
        {
            using var throwaway = new libyaraNET.Compiler();
            throwaway.AddRuleString(text);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // Pass 2: ONE fresh compiler over the validated sources, disposed at scope exit (the Rules stay valid).
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object CompileClean(IEnumerable<string> texts)
    {
        using var compiler = new libyaraNET.Compiler();
        foreach (var text in texts)
            compiler.AddRuleString(text);

        return Root(compiler.GetRules());
    }

    // The ADR-0028 defect, rebuilt on purpose for M3 (PoisonCanaryCheck's technique): one compiler, every source,
    // each CompilationException swallowed, GetRules() on the errored compiler. Nothing disposed.
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static object CompilePoisoned(IEnumerable<string> texts, out int swallowed)
    {
        var compiler = new libyaraNET.Compiler();
        Root(compiler);
        swallowed = 0;
        foreach (var text in texts)
        {
            try { compiler.AddRuleString(text); }
            catch { swallowed++; }
        }

        return Root(compiler.GetRules());
    }

    // The startup canary of LibYaraScanner.CanaryScanCompletes: 64 zero bytes, ScanMemory, 5 s bound, dedicated thread.
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static bool Canary(object rules, object scanner) =>
        Bounded.TryRun(() => ((libyaraNET.Scanner)scanner).ScanMemory(new byte[64], (libyaraNET.Rules)rules), TimeSpan.FromSeconds(5), out _, out var error)
        && error is null;

    // One native Scanner.ScanFile call; the rule identifiers it matched. Throws whatever the native call throws.
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string[] ScanFile(object rules, object scanner, string path) =>
        (((libyaraNET.Scanner)scanner).ScanFile(path, (libyaraNET.Rules)rules) ?? [])
            .Select(r => r?.MatchingRule?.Identifier ?? string.Empty)
            .ToArray();

    private static object Root(object o)
    {
        lock (roots) roots.Add(o);
        return o;
    }

    // Native objects live for the process; yr_finalize is never called (same as the product and the probe).
    private static readonly List<object> roots = [];
}

/// <summary>The shape of <c>LibYaraScanner.TryRunBounded</c>: a dedicated background thread, joined with a bound.</summary>
internal static class Bounded
{
    public static bool TryRun<T>(Func<T> body, TimeSpan bound, out T? value, out Exception? error)
        where T : class
    {
        T? outcome = null;
        Exception? fault = null;
        var thread = new Thread(() =>
        {
            try { outcome = body(); }
            catch (Exception ex) { fault = ex; }
        })
        {
            IsBackground = true,
            Name = "silvergun-yara-scan",
        };

        thread.Start();
        if (!thread.Join(bound))
        {
            try { thread.Priority = ThreadPriority.Lowest; } catch { /* raced with completion */ }
            (value, error) = (null, null);
            return false;
        }

        (value, error) = (outcome, fault);
        return true;
    }
}

/// <summary>Process-local memory snapshot, read the same way in the worker and the in-process host.</summary>
internal readonly record struct MemSnapshot(long WorkingSet, long PrivateBytes, long PeakWorkingSet, long ManagedHeap)
{
    public static MemSnapshot Take()
    {
        using var p = Process.GetCurrentProcess();
        p.Refresh();
        return new MemSnapshot(p.WorkingSet64, p.PrivateMemorySize64, p.PeakWorkingSet64, GC.GetTotalMemory(false));
    }
}

/// <summary>The engine build, phase-timed. Shared verbatim by the worker and the in-process host.</summary>
internal sealed class EngineBuild
{
    public static EngineBuild Run(bool poisoned, string? goodListPath)
    {
        var build = new EngineBuild();
        var sw = Stopwatch.StartNew();
        double Lap()
        {
            var ms = sw.Elapsed.TotalMilliseconds;
            sw.Restart();
            return ms;
        }

        var sources = RuleSources.ReadAll();
        build.Phases.Add(("readRules", Lap()));
        build.RuleFiles = sources.Count;

        build.NativeAssembly = NativeYara.LoadAssembly();
        build.Phases.Add(("nativeLoad", Lap()));

        NativeYara.CreateContext();
        build.Phases.Add(("yaraContext", Lap()));

        if (poisoned)
        {
            build.Rules = NativeYara.CompilePoisoned(sources.Select(s => s.Text), out var swallowed);
            build.Dropped = [$"<{swallowed} swallowed into one errored compiler>"];
            build.Phases.Add(("poisonedCompile", Lap()));
            build.Scanner = NativeYara.CreateScanner();
            build.Phases.Add(("scanner", Lap()));
            build.Valid = sources.Count;
            build.CanaryPassed = null;   // no canary: that is the point of the poisoned worker
            return build;
        }

        (string Name, string Text)[] valid;
        if (goodListPath is not null)
        {
            var good = new HashSet<string>(File.ReadAllLines(goodListPath), StringComparer.Ordinal);
            valid = sources.Where(s => good.Contains(s.Name)).ToArray();
            build.Dropped = sources.Where(s => !good.Contains(s.Name)).Select(s => s.Name).ToArray();
            build.Phases.Add(("pass1Skipped", Lap()));
        }
        else
        {
            var outcomes = sources.ToLookup(s => NativeYara.CompilesCleanly(s.Text));
            valid = outcomes[true].ToArray();
            build.Dropped = outcomes[false].Select(s => s.Name).ToArray();
            build.Phases.Add(("pass1", Lap()));
        }

        build.Valid = valid.Length;
        build.Rules = NativeYara.CompileClean(valid.Select(v => v.Text));
        build.Phases.Add(("pass2", Lap()));

        build.Scanner = NativeYara.CreateScanner();
        build.CanaryPassed = NativeYara.Canary(build.Rules, build.Scanner);
        build.Phases.Add(("canary", Lap()));
        return build;
    }

    public List<(string Name, double Ms)> Phases { get; } = [];
    public int RuleFiles { get; private set; }
    public int Valid { get; private set; }
    public string[] Dropped { get; private set; } = [];
    public string NativeAssembly { get; private set; } = string.Empty;
    public bool? CanaryPassed { get; private set; }
    public object Rules { get; private set; } = null!;
    public object Scanner { get; private set; } = null!;
}

/// <summary>Walks a tree the way the product's default <c>IYaraScanner.ScanDirectory</c> does (GetFiles, then per file).</summary>
internal static class TreeScan
{
    public sealed record FileOutcome(string Rel, long Bytes, string Status, double Ms, string[] Hits);

    public static (List<FileOutcome> Files, double Ms) Run(string root, Func<string, string[]> scanOne, Action<string>? announce, Action<FileOutcome>? onFile)
    {
        var sw = Stopwatch.StartNew();
        var files = Directory.Exists(root) ? Directory.GetFiles(root, "*", SearchOption.AllDirectories) : [];
        var outcomes = new List<FileOutcome>(files.Length);
        foreach (var file in files)
        {
            var rel = file.Length > root.Length ? file[(root.Length + 1)..].Replace('\\', '/') : file;
            announce?.Invoke(rel);
            var fsw = Stopwatch.StartNew();
            string status;
            string[] hits = [];
            long bytes = -1;
            try
            {
                if (!File.Exists(file))
                    status = "missing";
                else
                {
                    bytes = new FileInfo(file).Length;
                    hits = scanOne(file);
                    status = "ok";
                }
            }
            catch (TimeoutException)
            {
                status = "timeout";
            }
            catch (Exception ex)
            {
                status = "error:" + ex.GetType().Name;
            }

            var outcome = new FileOutcome(rel, bytes, status, fsw.Elapsed.TotalMilliseconds, hits);
            outcomes.Add(outcome);
            onFile?.Invoke(outcome);
        }

        return (outcomes, sw.Elapsed.TotalMilliseconds);
    }
}

/// <summary>The (W) worker: build, report ready, then serve line-delimited JSON commands on stdin.</summary>
internal static class Worker
{
    public static int Run(string[] args)
    {
        // Process start -> Main, from the kernel's creation time. Coarse (see the measurement doc); the parent's
        // outside view minus the in-child phases is the robust number.
        double runtimeToMain;
        using (var self = Process.GetCurrentProcess())
            runtimeToMain = (DateTime.Now - self.StartTime).TotalMilliseconds;

        var stdout = new StreamWriter(Console.OpenStandardOutput(), IsolationCost.Utf8) { AutoFlush = false, NewLine = "\n" };
        var stdin = new StreamReader(Console.OpenStandardInput(), IsolationCost.Utf8);
        void Emit(object o)
        {
            stdout.WriteLine(JsonSerializer.Serialize(o));
            stdout.Flush();
        }

        var poisoned = args.Contains("--poisoned");
        var build = EngineBuild.Run(poisoned, IsolationCost.ValueOf(args, "--skip-pass1"));
        Emit(new
        {
            type = "ready",
            pid = Environment.ProcessId,
            runtimeToMain,
            phases = build.Phases.ToDictionary(p => p.Name, p => p.Ms),
            ruleFiles = build.RuleFiles,
            valid = build.Valid,
            dropped = build.Dropped,
            canary = build.CanaryPassed,
            native = build.NativeAssembly,
            mem = MemSnapshot.Take(),
        });

        string? line;
        while ((line = stdin.ReadLine()) is not null)
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                var cmd = doc.RootElement.GetProperty("cmd").GetString();
                switch (cmd)
                {
                    case "scan":
                        var root = doc.RootElement.GetProperty("root").GetString()!;
                        var announce = doc.RootElement.TryGetProperty("announce", out var a) && a.GetBoolean();
                        var (files, ms) = TreeScan.Run(
                            root,
                            path => NativeYara.ScanFile(build.Rules, build.Scanner, path),   // inline: the parent's kill is the bound
                            announce ? rel => Emit(new { type = "scanning", rel }) : null,
                            f => Emit(new { type = "file", rel = f.Rel, bytes = f.Bytes, status = f.Status, ms = f.Ms, hits = f.Hits }));
                        Emit(new
                        {
                            type = "done",
                            files = files.Count,
                            failed = files.Count(f => f.Status != "ok"),
                            hits = files.Sum(f => f.Hits.Length),
                            scanMs = ms,
                        });
                        break;
                    case "mem":
                        Emit(new { type = "mem", mem = MemSnapshot.Take() });
                        break;
                    case "exit":
                        stdout.Flush();
                        Environment.Exit(0);
                        break;
                    default:
                        Emit(new { type = "error", message = "unknown command" });
                        break;
                }
            }
            catch (Exception ex)
            {
                Emit(new { type = "error", message = ex.GetType().Name + ": " + ex.Message });
            }
        }

        // stdin closed: the parent is gone. Leave at once.
        Environment.Exit(0);
        return 0;
    }
}

/// <summary>
/// (a) In-process baseline: the engine built in THIS process exactly as the worker builds it, each file scanned on
/// a dedicated thread under a 30 s bound like <c>LibYaraScanner.ScanFile</c>. Reports memory at Main entry (the bare
/// host), after the build and after each round, so the engine's delta in a host process can be read off.
/// </summary>
internal static class InProcHost
{
    public static int Run(string[] args)
    {
        var mainMem = MemSnapshot.Take();
        var stdout = new StreamWriter(Console.OpenStandardOutput(), IsolationCost.Utf8) { AutoFlush = false, NewLine = "\n" };
        void Emit(object o)
        {
            stdout.WriteLine(JsonSerializer.Serialize(o));
            stdout.Flush();
        }

        var trees = File.ReadAllLines(IsolationCost.Required(args, "--trees")).Where(l => l.Length > 0).ToArray();
        var rounds = int.Parse(IsolationCost.Required(args, "--rounds"), CultureInfo.InvariantCulture);

        Emit(new { type = "mem", at = "main", mem = mainMem });
        var build = EngineBuild.Run(poisoned: false, goodListPath: null);
        Emit(new { type = "built", phases = build.Phases.ToDictionary(p => p.Name, p => p.Ms), valid = build.Valid, canary = build.CanaryPassed });
        Emit(new { type = "mem", at = "ready", mem = MemSnapshot.Take() });

        // --inline: scan on the calling thread like the worker does, to separate the cost of the product's
        // per-file dedicated thread from everything else (information only; it removes the in-process bound).
        var inline = args.Contains("--inline");
        string[] ScanBounded(string path)
        {
            if (inline)
                return NativeYara.ScanFile(build.Rules, build.Scanner, path);
            if (!Bounded.TryRun(() => NativeYara.ScanFile(build.Rules, build.Scanner, path), TimeSpan.FromSeconds(30), out var hits, out var error))
                throw new TimeoutException();
            return error is not null ? throw error : hits ?? [];
        }

        for (var r = 1; r <= rounds; r++)
        {
            foreach (var tree in trees)
            {
                var (files, ms) = TreeScan.Run(tree, ScanBounded, null, null);
                Emit(new
                {
                    type = "tree",
                    round = r,
                    tree = Path.GetFileName(tree),
                    files = files.Count,
                    failed = files.Count(f => f.Status != "ok"),
                    hits = files.Sum(f => f.Hits.Length),
                    ms,
                });
            }

            Emit(new { type = "mem", at = $"after-round-{r}", mem = MemSnapshot.Take() });
        }

        Emit(new { type = "end" });
        stdout.Flush();
        Environment.Exit(0);
        return 0;
    }
}

/// <summary>A child process this measurement started, with its stdout read line by line on a dedicated thread.</summary>
internal sealed class Child : IDisposable
{
    private Child(Process process)
    {
        Process = process;
        reader = new Thread(() =>
        {
            try
            {
                string? l;
                while ((l = process.StandardOutput.ReadLine()) is not null)
                    lines.Add(l);
            }
            catch { /* stream torn down by a kill */ }
            finally { lines.CompleteAdding(); }
        })
        { IsBackground = true, Name = "child-stdout" };
        reader.Start();
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (stderr) stderr.AppendLine(e.Data); };
        process.BeginErrorReadLine();
    }

    public static Child Start(string exe, IEnumerable<string> args, List<(int Pid, DateTime Start)> registry)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = IsolationCost.Utf8,
            StandardOutputEncoding = IsolationCost.Utf8,
            StandardErrorEncoding = IsolationCost.Utf8,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);

        var p = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null.");
        registry.Add((p.Id, p.StartTime));   // PID + creation time: a recycled PID is never mistaken for ours
        return new Child(p);
    }

    public Process Process { get; }

    public string Stderr { get { lock (stderr) return stderr.ToString(); } }

    /// <summary>The next JSON line, or null on timeout or EOF. Non-JSON lines are skipped.</summary>
    public JsonElement? Next(TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (true)
        {
            var left = timeout - deadline.Elapsed;
            if (left < TimeSpan.Zero || !lines.TryTake(out var line, left))
                return null;

            try
            {
                using var doc = JsonDocument.Parse(line);
                return doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                // not ours; keep reading
            }
        }
    }

    /// <summary>Lines until one of type <paramref name="type"/> arrives (returned), or null on timeout/EOF.</summary>
    public JsonElement? Until(string type, TimeSpan timeout, Action<JsonElement>? other = null)
    {
        var sw = Stopwatch.StartNew();
        while (true)
        {
            var el = Next(timeout - sw.Elapsed);
            if (el is null) return null;
            if (el.Value.GetProperty("type").GetString() == type) return el;
            other?.Invoke(el.Value);
        }
    }

    public void Send(object command)
    {
        Process.StandardInput.Write(JsonSerializer.Serialize(command) + "\n");
        Process.StandardInput.Flush();
    }

    public void Dispose()
    {
        try
        {
            if (!Process.HasExited)
            {
                Process.Kill(entireProcessTree: true);
                Process.WaitForExit(10_000);
            }
        }
        catch { /* already gone */ }

        Process.Dispose();
    }

    private readonly BlockingCollection<string> lines = new();
    private readonly StringBuilder stderr = new();
    private readonly Thread reader;
}

/// <summary>Raw-sample TSV: one row per measured value.</summary>
internal sealed class SampleTsv : IDisposable
{
    public SampleTsv(string path, bool append)
    {
        var header = !append || !File.Exists(path);
        writer = new StreamWriter(new FileStream(path, append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.Read), IsolationCost.Utf8) { NewLine = "\n" };
        if (header)
            writer.WriteLine("Section\tMode\tLabel\tIter\tRound\tMetric\tValue\tNote");
        writer.Flush();
    }

    public void Row(string section, string mode, string label, int iter, int round, string metric, double value, string note = "")
    {
        writer.WriteLine(string.Join('\t', Clean(section), Clean(mode), Clean(label),
            iter.ToString(CultureInfo.InvariantCulture), round.ToString(CultureInfo.InvariantCulture),
            Clean(metric), value.ToString("0.###", CultureInfo.InvariantCulture), Clean(note)));
        writer.Flush();
    }

    public void Dispose() => writer.Dispose();

    private static string Clean(string v) => v.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

    private readonly StreamWriter writer;
}

/// <summary>The orchestrator for M1–M4. Never loads libyara itself.</summary>
internal static class Orchestrator
{
    public static int Run(string[] args)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("No process path.");
        var trees = File.ReadAllLines(IsolationCost.Required(args, "--trees")).Where(l => l.Length > 0).ToArray();
        var treesFile = Path.GetFullPath(IsolationCost.Required(args, "--trees"));
        var sections = (IsolationCost.ValueOf(args, "--sections") ?? "M1,M1skip,M2a,M2b,M2c,M3").Split(',').ToHashSet(StringComparer.OrdinalIgnoreCase);
        int Int(string name, int dflt) => int.Parse(IsolationCost.ValueOf(args, name) ?? dflt.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
        var n = Int("--n", 15);
        var hosts = Int("--hosts", 10);
        var workers = Int("--workers", 10);
        var rounds = Int("--rounds", 3);
        var perPkgRounds = Int("--per-pkg-rounds", 10);
        var kills = Int("--kills", 12);
        var hangDir = Path.GetFullPath(IsolationCost.ValueOf(args, "--hang-dir") ?? Path.Combine(IsolationCost.ScratchRoot, "hang"));

        var started = new List<(int Pid, DateTime Start)>();
        using var tsv = new SampleTsv(IsolationCost.Required(args, "--out"), args.Contains("--append"));
        var ready = TimeSpan.FromSeconds(120);
        var scanBound = TimeSpan.FromSeconds(300);
        var failures = 0;

        void Env(string key, string value)
        {
            tsv.Row("env", "-", key, 0, 0, "info", 0, value);
            Console.WriteLine($"[env] {key} = {value}");
        }

        Env("FrameworkDescription", RuntimeInformation.FrameworkDescription);
        Env("OSDescription", RuntimeInformation.OSDescription);
        Env("ProcessorCount", Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture));
        Env("ProcessPath", exe);
        Env("CommandLine", string.Join(' ', args));
        Env("Trees", string.Join('|', trees.Select(Path.GetFileName)));
        Env("StartedUtc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));

        // ---- helpers -------------------------------------------------------------------------------------------
        (Child Child, JsonElement Ready, double Ms)? Spawn(IEnumerable<string> workerArgs)
        {
            var sw = Stopwatch.StartNew();
            var child = Child.Start(exe, workerArgs, started);
            var r = child.Until("ready", ready);
            sw.Stop();
            if (r is null)
            {
                Console.Error.WriteLine($"worker {child.Process.Id} never became ready; stderr: {child.Stderr}");
                child.Dispose();
                failures++;
                return null;
            }

            return (child, r.Value, sw.Elapsed.TotalMilliseconds);
        }

        bool Exit(Child child, out double ms)
        {
            var sw = Stopwatch.StartNew();
            child.Send(new { cmd = "exit" });
            var ok = child.Process.WaitForExit(30_000);
            ms = sw.Elapsed.TotalMilliseconds;
            child.Dispose();
            if (!ok) failures++;
            return ok;
        }

        void ReadyRows(string section, string mode, int iter, JsonElement r, double outsideMs, string note)
        {
            tsv.Row(section, mode, "worker", iter, 0, "spawnToReadyMs", outsideMs, note);
            var inside = 0.0;
            foreach (var phase in r.GetProperty("phases").EnumerateObject())
            {
                tsv.Row(section, mode, "worker", iter, 0, "phase." + phase.Name, phase.Value.GetDouble(), note);
                inside += phase.Value.GetDouble();
            }

            tsv.Row(section, mode, "worker", iter, 0, "phase.sumInsideMain", inside, note);
            tsv.Row(section, mode, "worker", iter, 0, "runtimeToMainKernelClock", r.GetProperty("runtimeToMain").GetDouble(), note);
            tsv.Row(section, mode, "worker", iter, 0, "outsideMinusInsideMain", outsideMs - inside, "process create + runtime start + JIT of Main + ready-line IPC");
            MemRows(section, mode, "worker", iter, 0, "ready", r.GetProperty("mem"));
            tsv.Row(section, mode, "worker", iter, 0, "validRuleFiles", r.GetProperty("valid").GetInt32(), string.Join('|', r.GetProperty("dropped").EnumerateArray().Select(d => d.GetString())));
        }

        void MemRows(string section, string mode, string label, int iter, int round, string at, JsonElement mem)
        {
            tsv.Row(section, mode, label, iter, round, $"mem.{at}.workingSetBytes", mem.GetProperty("WorkingSet").GetInt64());
            tsv.Row(section, mode, label, iter, round, $"mem.{at}.privateBytes", mem.GetProperty("PrivateBytes").GetInt64());
            tsv.Row(section, mode, label, iter, round, $"mem.{at}.peakWorkingSetBytes", mem.GetProperty("PeakWorkingSet").GetInt64());
            tsv.Row(section, mode, label, iter, round, $"mem.{at}.managedHeapBytes", mem.GetProperty("ManagedHeap").GetInt64());
        }

        (JsonElement Done, double Ms)? ScanVia(Child child, string tree)
        {
            var sw = Stopwatch.StartNew();
            child.Send(new { cmd = "scan", root = tree });
            var done = child.Until("done", scanBound);
            sw.Stop();
            if (done is null)
            {
                failures++;
                Console.Error.WriteLine($"scan of {tree} did not finish; stderr: {child.Stderr}");
                return null;
            }

            return (done.Value, sw.Elapsed.TotalMilliseconds);
        }

        string[]? goodList = null;

        // ---- M1: spawn-to-ready, full two-pass build. Iteration 1 is the first spawn after the build. ----------
        if (sections.Contains("M1"))
        {
            for (var i = 1; i <= n; i++)
            {
                var s = Spawn([IsolationCost.WorkerSwitch]);
                if (s is null) continue;
                var (child, r, ms) = s.Value;
                ReadyRows("M1", "full", i, r, ms, i == 1 ? "first-spawn-after-build" : "warm");
                goodList ??= RuleSources.ReadAll().Select(x => x.Name)
                    .Except(r.GetProperty("dropped").EnumerateArray().Select(d => d.GetString()!)).ToArray();
                Exit(child, out var exitMs);
                tsv.Row("M1", "full", "worker", i, 0, "exitMs", exitMs);
                Console.WriteLine($"[M1] full #{i}: {ms:0} ms to ready");
            }
        }

        // ---- M1 variant: pass 1 skipped, pass 2 fed the known-good list. ---------------------------------------
        if (sections.Contains("M1skip"))
        {
            var listPath = Path.Combine(IsolationCost.ScratchRoot, "known-good-rules.txt");
            goodList ??= RuleSources.ReadAll().Select(x => x.Name).Where(x => !x.EndsWith("virus.Linux.Virus.Vit.yara", StringComparison.Ordinal)).ToArray();
            File.WriteAllLines(listPath, goodList);
            for (var i = 1; i <= n; i++)
            {
                var s = Spawn([IsolationCost.WorkerSwitch, "--skip-pass1", listPath]);
                if (s is null) continue;
                var (child, r, ms) = s.Value;
                ReadyRows("M1", "skipPass1", i, r, ms, "warm");
                Exit(child, out _);
                Console.WriteLine($"[M1] skip-pass1 #{i}: {ms:0} ms to ready");
            }

            File.Delete(listPath);
        }

        // ---- M2a: in-process baseline, one fresh host process per iteration. -----------------------------------
        // M2aInline is the same with --inline (no per-file dedicated thread): information only, see InProcHost.
        // When both run, hosts alternate between them so machine drift lands on both equally.
        for (var h = 1; h <= hosts; h++)
        {
            foreach (var (section, mode, inline) in new[] { ("M2a", "inproc", false), ("M2aInline", "inprocInline", true) })
            {
                if (!sections.Contains(section)) continue;
                var sw = Stopwatch.StartNew();
                List<string> hostArgs = [IsolationCost.InProcSwitch, "--trees", treesFile, "--rounds", rounds.ToString(CultureInfo.InvariantCulture)];
                if (inline) hostArgs.Add("--inline");
                using var host = Child.Start(exe, hostArgs, started);
                while (host.Next(TimeSpan.FromMinutes(20)) is { } el)
                {
                    switch (el.GetProperty("type").GetString())
                    {
                        case "mem":
                            MemRows(section, mode, "host", h, 0, el.GetProperty("at").GetString()!, el.GetProperty("mem"));
                            break;
                        case "built":
                            foreach (var phase in el.GetProperty("phases").EnumerateObject())
                                tsv.Row(section, mode, "host", h, 0, "phase." + phase.Name, phase.Value.GetDouble());
                            tsv.Row(section, mode, "host", h, 0, "buildToReadyMs", sw.Elapsed.TotalMilliseconds, "host process start -> engine built (outside view)");
                            break;
                        case "tree":
                            var tree = el.GetProperty("tree").GetString()!;
                            var round = el.GetProperty("round").GetInt32();
                            tsv.Row(section, mode, tree, h, round, "treeMs", el.GetProperty("ms").GetDouble(),
                                $"files={el.GetProperty("files").GetInt32()};failed={el.GetProperty("failed").GetInt32()};hits={el.GetProperty("hits").GetInt32()}");
                            if (el.GetProperty("failed").GetInt32() > 0) failures++;
                            break;
                    }
                }

                if (!host.Process.WaitForExit(30_000)) failures++;
                Console.WriteLine($"[{section}] host #{h} done in {sw.Elapsed.TotalSeconds:0.0} s");
            }
        }

        // ---- M2b: one long-lived worker per iteration, every tree sent `rounds` times. M4 rows ride along. ----
        if (sections.Contains("M2b"))
        {
            for (var w = 1; w <= workers; w++)
            {
                var s = Spawn([IsolationCost.WorkerSwitch]);
                if (s is null) continue;
                var (child, r, readyMs) = s.Value;
                ReadyRows("M2b", "longLived", w, r, readyMs, "warm");
                for (var round = 1; round <= rounds; round++)
                {
                    foreach (var tree in trees)
                    {
                        if (ScanVia(child, tree) is not { } res) continue;
                        var internalMs = res.Done.GetProperty("scanMs").GetDouble();
                        var note = $"files={res.Done.GetProperty("files").GetInt32()};failed={res.Done.GetProperty("failed").GetInt32()};hits={res.Done.GetProperty("hits").GetInt32()}";
                        tsv.Row("M2b", "longLived", Path.GetFileName(tree), w, round, "roundTripMs", res.Ms, note);
                        tsv.Row("M2b", "longLived", Path.GetFileName(tree), w, round, "workerScanMs", internalMs, note);
                        tsv.Row("M2b", "longLived", Path.GetFileName(tree), w, round, "ipcOverheadMs", res.Ms - internalMs, note);
                        if (res.Done.GetProperty("failed").GetInt32() > 0) failures++;
                    }

                    child.Send(new { cmd = "mem" });
                    if (child.Until("mem", TimeSpan.FromSeconds(30)) is { } m)
                        MemRows("M2b", "longLived", "worker", w, round, $"after-round-{round}", m.GetProperty("mem"));
                }

                Exit(child, out var exitMs);
                tsv.Row("M2b", "longLived", "worker", w, 0, "exitMs", exitMs);
                Console.WriteLine($"[M2b] worker #{w} done");
            }
        }

        // ---- M2c: one worker per package: spawn, ready, scan, exit. ----------------------------------------------
        if (sections.Contains("M2c"))
        {
            for (var round = 1; round <= perPkgRounds; round++)
            {
                foreach (var tree in trees)
                {
                    var total = Stopwatch.StartNew();
                    var s = Spawn([IsolationCost.WorkerSwitch]);
                    if (s is null) continue;
                    var (child, _, readyMs) = s.Value;
                    var res = ScanVia(child, tree);
                    Exit(child, out var exitMs);
                    total.Stop();
                    if (res is null) continue;
                    var name = Path.GetFileName(tree);
                    var note = $"files={res.Value.Done.GetProperty("files").GetInt32()};failed={res.Value.Done.GetProperty("failed").GetInt32()}";
                    tsv.Row("M2c", "perPackage", name, round, round, "totalMs", total.Elapsed.TotalMilliseconds, note);
                    tsv.Row("M2c", "perPackage", name, round, round, "spawnToReadyMs", readyMs, note);
                    tsv.Row("M2c", "perPackage", name, round, round, "roundTripMs", res.Value.Ms, note);
                    tsv.Row("M2c", "perPackage", name, round, round, "workerScanMs", res.Value.Done.GetProperty("scanMs").GetDouble(), note);
                    tsv.Row("M2c", "perPackage", name, round, round, "exitMs", exitMs, note);
                    if (res.Value.Done.GetProperty("failed").GetInt32() > 0) failures++;
                }

                Console.WriteLine($"[M2c] round {round} done");
            }
        }

        // ---- M3: kill a worker hung inside a native scan, then respawn. ------------------------------------------
        if (sections.Contains("M3"))
        {
            Directory.CreateDirectory(hangDir);
            File.WriteAllBytes(Path.Combine(hangDir, "zeros4.bin"), new byte[4]);
            var ownName = Path.GetFileNameWithoutExtension(exe);
            var smallest = trees.OrderBy(t => Directory.GetFiles(t, "*", SearchOption.AllDirectories).Length).First();

            // The first `kills` iterations use Kill(entireProcessTree: true), as the spec asks. The next `kills` use a
            // plain Kill() (one TerminateProcess, no descendant walk) purely to show what the tree walk itself costs.
            for (var k = 1; k <= 2 * kills; k++)
            {
                var treeKill = k <= kills;
                var mode = treeKill ? "killTree" : "killSingle";
                var s = Spawn([IsolationCost.WorkerSwitch, "--poisoned"]);
                if (s is null) continue;
                var (child, r, readyMs) = s.Value;
                var p = child.Process;
                var pid = p.Id;
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "spawnToReadyMs", readyMs, "poisoned build, no pass1, no canary");

                child.Send(new { cmd = "scan", root = hangDir, announce = true });
                if (child.Until("scanning", TimeSpan.FromSeconds(30)) is null)
                {
                    failures++;
                    Console.Error.WriteLine($"[M3] #{k}: worker never announced the scan; stderr: {child.Stderr}");
                    child.Dispose();
                    continue;
                }

                p.Refresh();
                var cpu0 = p.TotalProcessorTime;
                var hold = k == 1 ? TimeSpan.FromSeconds(30) : TimeSpan.FromSeconds(2);
                var holdSw = Stopwatch.StartNew();
                var early = child.Next(hold);   // anything here means the scan finished or the worker died: NOT hung
                var held = holdSw.Elapsed;
                p.Refresh();
                var alive = !p.HasExited;
                var cpu1 = alive ? p.TotalProcessorTime : cpu0;
                var busy = (cpu1 - cpu0).TotalMilliseconds / held.TotalMilliseconds;
                var hung = early is null && alive;
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "heldMs", held.TotalMilliseconds, hung ? "hung" : "NOT-HUNG " + early?.GetRawText());
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "cpuWhileHeldFraction", busy, "CPU-seconds per wall-second while held; ~1.0 = one core spinning in the native scan");
                if (!hung)
                {
                    failures++;
                    child.Dispose();
                    continue;
                }

                var sw = Stopwatch.StartNew();
                if (treeKill)
                    p.Kill(entireProcessTree: true);
                else
                    p.Kill();
                var killCallMs = sw.Elapsed.TotalMilliseconds;
                var exited = p.WaitForExit(30_000);
                var toExitMs = sw.Elapsed.TotalMilliseconds;
                var hasExited = p.HasExited;
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "killCallMs", killCallMs);
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "killToHasExitedMs", toExitMs, $"exited={exited};hasExited={hasExited};exitCode={(hasExited ? p.ExitCode : 0)}");

                // Orphan check: the PID is gone from the process table, and no process running this exe remains
                // besides the orchestrator itself (the worker starts no children of its own).
                var all = Process.GetProcesses();
                var pidPresent = all.Any(x => x.Id == pid);
                var sameExe = all.Count(x => x.Id != Environment.ProcessId && string.Equals(x.ProcessName, ownName, StringComparison.OrdinalIgnoreCase));
                foreach (var x in all) x.Dispose();
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "orphanPidPresent", pidPresent ? 1 : 0);
                tsv.Row("M3", mode, "poisonedWorker", k, 0, "otherProbeProcesses", sameExe);
                if (pidPresent || sameExe > 0 || !hasExited) failures++;
                child.Dispose();

                // Respawn a healthy worker immediately and prove it scans.
                var re = Spawn([IsolationCost.WorkerSwitch]);
                if (re is null) continue;
                var (fresh, freshReady, respawnMs) = re.Value;
                tsv.Row("M3", mode, "respawn", k, 0, "respawnToReadyMs", respawnMs, $"canary={freshReady.GetProperty("canary")}");
                tsv.Row("M3", mode, "respawn", k, 0, "killStartToReplacementReadyMs", sw.Elapsed.TotalMilliseconds);
                var proof = ScanVia(fresh, smallest);
                tsv.Row("M3", mode, "respawn", k, 0, "proofScanRoundTripMs", proof?.Ms ?? -1,
                    proof is { } pr ? $"tree={Path.GetFileName(smallest)};files={pr.Done.GetProperty("files").GetInt32()};failed={pr.Done.GetProperty("failed").GetInt32()}" : "FAILED");
                Exit(fresh, out _);
                Console.WriteLine($"[M3] #{k} {mode}: kill->exited {toExitMs:0.0} ms, respawn {respawnMs:0} ms, cpu {busy:0.00}");
            }

            File.Delete(Path.Combine(hangDir, "zeros4.bin"));
            Directory.Delete(hangDir);
        }

        // ---- Final accounting: every child this run started must be gone. ---------------------------------------
        var leftovers = 0;
        foreach (var (pid, start) in started)
        {
            try
            {
                using var q = Process.GetProcessById(pid);
                if (q.StartTime == start && !q.HasExited)
                {
                    leftovers++;
                    q.Kill(entireProcessTree: true);   // ours: same PID AND same creation time
                    q.WaitForExit(10_000);
                }
            }
            catch (ArgumentException) { /* no such PID: gone, as it should be */ }
            catch (InvalidOperationException) { /* exited between the lookup and the check */ }
        }

        Env("ChildrenStarted", started.Count.ToString(CultureInfo.InvariantCulture));
        Env("ChildrenAliveAtEnd", leftovers.ToString(CultureInfo.InvariantCulture));
        Env("Failures", failures.ToString(CultureInfo.InvariantCulture));
        Env("FinishedUtc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        return failures == 0 && leftovers == 0 ? 0 : 1;
    }
}
