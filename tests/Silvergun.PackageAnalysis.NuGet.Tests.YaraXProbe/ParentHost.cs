namespace Silvergun.PackageAnalysis.NuGet.Tests.YaraXProbe;

using System.Reflection;
using System.Text;

using Microsoft.Extensions.Logging;

using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// The YARA-X worker's PARENT (<see cref="YaraXWorkerScanner"/>, ADR 0033 task T4) hosted in a fresh process. Each mode
/// installs a recording logger as <c>Runtime.logger</c> first (this process is nobody else's, so nothing else writes it),
/// then prints <c>key=value</c> lines: <c>available</c>, <c>result</c> (<c>complete</c>/<c>incomplete</c>), one <c>hit</c>
/// or <c>partial</c> per hit (<c>&lt;path&gt;|&lt;rule&gt;</c>), the exception <c>message</c>, and every log record as
/// <c>log=&lt;level&gt;|&lt;base64 of the UTF-8 message&gt;</c>, so the test sees the exact characters that were logged.
/// The internal test constructor is reached by reflection (the product's InternalsVisibleTo names only the test assembly).
/// </summary>
internal static class ParentHost
{
    #region Methods
    // A scan by a scanner on the fake worker `worker --fake-worker script`, under the given clocks.
    internal static int Parent(string worker, string script, string root, int engineTimeoutSeconds, TimeSpan ready, TimeSpan grace, TimeSpan exit)
    {
        var recorder = Install();
        using (var scanner = Seam(worker, script, engineTimeoutSeconds, ready, grace, exit))
        {
            Console.WriteLine($"available={scanner.Available}");
            Report(() => scanner.ScanDirectory(root));
        }
        recorder.Print();
        return 0;
    }

    // Starts a scan whose worker hangs, waits until that worker (run 2 of the script) has recorded its PID, prints it,
    // and dies by Environment.FailFast: no finally, no Dispose, no ProcessExit handler runs. Only the kill-on-close Job
    // Object, whose handle the OS closes with this process, can stop the worker now.
    internal static int FailFast(string worker, string script, string root, string pidFile)
    {
        Install();
        var scanner = Seam(worker, script, 300, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        Console.WriteLine($"available={scanner.Available}");
        new Thread(() =>
        {
            try { scanner.ScanDirectory(root); }
            catch (YaraScanIncompleteException) { /* the fail-fast below ends this process first */ }
        }) { IsBackground = true }.Start();

        var deadline = DateTime.UtcNow.AddSeconds(30);
        string[] pids = [];
        while (DateTime.UtcNow < deadline && (pids = File.Exists(pidFile) ? File.ReadAllLines(pidFile).Where(l => l.Length > 0).ToArray() : []).Length < 2)
            Thread.Sleep(20);
        if (pids.Length < 2)
        {
            Console.WriteLine("worker=none");
            return 3;
        }

        Thread.Sleep(300);   // the worker is now past `ready`, inside its hang
        Console.WriteLine($"worker={pids[1]}");
        Console.Out.Flush();
        Environment.FailFast("YaraXProbe failfast mode: the parent dies with its YARA-X worker running (deliberate, a test).");
        return 4;   // unreachable
    }

    // The PRODUCTION constructor: the worker is whatever amendment (o) resolves for this process (the YaraXProbe is not the
    // CLI, so step 2: the CLI apphost in the application directory), with the real engine and the real rules. The test
    // starts this process with USERPROFILE pointed at a temp directory, so the worker's rules cache is private to it.
    internal static int Production(string root)
    {
        var recorder = Install();
        using (var scanner = new YaraXWorkerScanner())
        {
            Console.WriteLine($"worker={Field(scanner, "workerPath")}");
            Console.WriteLine($"available={scanner.Available}");
            Report(() => scanner.ScanDirectory(root));
        }
        recorder.Print();
        return 0;
    }

    // ADR 0034 with the REAL worker: the production constructor (as Production), but the files are listed FIRST, exactly as
    // NuGetPackage.Open records a package's YARA inventory, then the tree is disturbed, then that list is scanned. Ops, in
    // order: `del=<relative>` deletes a file, `rmdir=<relative>` a directory (recursively), `rmroot` the root itself (never
    // with a junction under it: the test removes those), `empty` scans an empty list, `directory` calls ScanDirectory(root)
    // instead of ScanFiles (the undisturbed parity check). Prints `listed=<n>` before the Report lines.
    internal static int ProductionFiles(string root, IReadOnlyList<string> ops)
    {
        var recorder = Install();
        using (var scanner = new YaraXWorkerScanner())
        {
            Console.WriteLine($"available={scanner.Available}");
            IReadOnlyList<string> files = Directory.GetFiles(root, "*", SearchOption.AllDirectories);
            Console.WriteLine($"listed={files.Count}");
            var directory = false;
            foreach (var op in ops)
                switch (op.Split('=', 2))
                {
                    case ["del", var relative]: File.Delete(Path.Combine(root, relative)); break;
                    case ["rmdir", var relative]: Directory.Delete(Path.Combine(root, relative), recursive: true); break;
                    case ["rmroot"]: Directory.Delete(root, recursive: true); break;
                    case ["empty"]: files = []; break;
                    case ["directory"]: directory = true; break;
                    default: throw new ArgumentException($"unknown production-files op '{Line(op)}'");
                }
            Report(() => directory ? scanner.ScanDirectory(root) : scanner.ScanFiles(root, files));
        }
        recorder.Print();
        return 0;
    }

    // ADR 0034 end to end with the REAL worker: PackageScanner.Scan over `nupkg`, its backend the production YaraXWorkerScanner
    // behind a double that deletes the extracted files named `delete` (`*`: every file) the moment YARA is reached, then
    // delegates. Prints the report's YARA status, every finding (`finding=<rule>|<relative path>`) and the reason, base64.
    internal static int ProductionPackage(string nupkg, string delete)
    {
        var recorder = Install();
        using (var inner = new YaraXWorkerScanner())
        {
            var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: new DeletingScanner(inner, delete));
            Console.WriteLine($"status={(scan.IsSuccess ? scan.Value.YaraScanStatus.ToString() : "scan-failed")}");
            if (scan.IsSuccess)
            {
                foreach (var finding in scan.Value.YaraFindings)
                    Console.WriteLine($"finding={Line(finding.RuleName)}|{Line(finding.RelativePath)}");
                Console.WriteLine($"reason={(scan.Value.YaraUnavailableReason is { } reason ? Convert.ToBase64String(Encoding.UTF8.GetBytes(reason)) : "<null>")}");
            }
        }
        recorder.Print();
        return 0;
    }

    // YaraScannerFactory.Shared reads SILVERGUN_YARA_ENGINE once per process: the backend it chose, and what it warned.
    internal static int Factory()
    {
        var recorder = Install();
        Console.WriteLine($"type={YaraScannerFactory.Shared.GetType().Name}");
        recorder.Print();
        return 0;
    }

    // T6b: the backend YaraScannerFactory.Shared chose (from whatever SILVERGUN_YARA_ENGINE the test set), driven the way
    // scan-package drives it, through PackageScanner.Scan's YARA step. Prints the chosen type, its health, the report's
    // YARA status, and whether either engine's code reached this process: libyara.NET (the in-process engine, which the
    // default must never fall back to) or yara_x_capi.dll (which only a worker may load).
    internal static int FactoryScan(string nupkg)
    {
        var recorder = Install();
        var scanner = YaraScannerFactory.Shared;
        Console.WriteLine($"type={scanner.GetType().Name}");
        Console.WriteLine($"available={scanner.Available}");
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false);
        Console.WriteLine($"status={(scan.IsSuccess ? scan.Value.YaraScanStatus.ToString() : "scan-failed")}");
        Console.WriteLine($"findings={(scan.IsSuccess ? scan.Value.YaraFindings.Count().ToString() : "-")}");
        Console.WriteLine($"libyara={AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name?.StartsWith("libyara", StringComparison.OrdinalIgnoreCase) == true)}");
        using (var self = System.Diagnostics.Process.GetCurrentProcess())
            foreach (var module in self.Modules.Cast<System.Diagnostics.ProcessModule>()
                .Where(m => m.ModuleName.StartsWith("yara", StringComparison.OrdinalIgnoreCase) || m.ModuleName.StartsWith("libyara", StringComparison.OrdinalIgnoreCase)))
                Console.WriteLine($"module={module.ModuleName}");
        recorder.Print();
        return 0;
    }

    // Amendment (o) under whatever PATH this process was given: the resolution never consults it.
    internal static int Resolve(string processPath, string baseDirectory)
    {
        var method = typeof(YaraXWorkerScanner).GetMethod("ResolveWorkerExecutable", BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("YaraXWorkerScanner.ResolveWorkerExecutable");
        var (path, problem) = ((string?, string?))method.Invoke(null, [processPath, baseDirectory])!;
        Console.WriteLine($"path={path ?? "<null>"}");
        Console.WriteLine($"problem={Line(problem)}");
        return 0;
    }

    private static YaraXWorkerScanner Seam(string worker, string script, int engineTimeoutSeconds, TimeSpan ready, TimeSpan grace, TimeSpan exit)
    {
        var constructor = typeof(YaraXWorkerScanner).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
            [typeof(string), typeof(IReadOnlyList<string>), typeof(int), typeof(TimeSpan), typeof(TimeSpan), typeof(TimeSpan)])
            ?? throw new MissingMethodException("YaraXWorkerScanner's internal test constructor");
        return (YaraXWorkerScanner)constructor.Invoke([worker, new[] { "--fake-worker", script }, engineTimeoutSeconds, ready, grace, exit]);
    }

    private static void Report(Func<IReadOnlyList<(string FullPath, YaraMatch Match)>> scan)
    {
        try
        {
            var hits = scan();
            Console.WriteLine("result=complete");
            foreach (var (path, match) in hits)
                Console.WriteLine($"hit={Line(path)}|{Line(match.Rule)}");
        }
        catch (YaraScanIncompleteException ex)
        {
            Console.WriteLine("result=incomplete");
            Console.WriteLine($"message={Convert.ToBase64String(Encoding.UTF8.GetBytes(ex.Message))}");
            foreach (var (path, match) in ex.PartialFindings)
                Console.WriteLine($"partial={Line(path)}|{Line(match.Rule)}");
        }
    }

    private static Recorder Install()
    {
        Silvergun.Runtime.Initialize("Silvergun", "YARAXPROBE");
        var recorder = new Recorder();
        Silvergun.Runtime.logger = recorder;
        return recorder;
    }

    private static object? Field(object target, string name) =>
        (target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new MissingFieldException(target.GetType().Name, name)).GetValue(target);

    private static string Line(object? value) => (value?.ToString() ?? "<null>").Replace('\r', ' ').Replace('\n', ' ');
    #endregion

    #region Nested types
    // Every record at every level, formatted as the product logged it.
    private sealed class Recorder : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (records)
                records.Add((logLevel, formatter(state, exception)));
        }

        public void Print()
        {
            lock (records)
                foreach (var (level, message) in records)
                    Console.WriteLine($"log={level}|{Convert.ToBase64String(Encoding.UTF8.GetBytes(message))}");
        }

        private readonly List<(LogLevel Level, string Message)> records = [];
    }

    // The ADR 0034 storage-sense double: on the way into either scan entry it deletes the files under the root named
    // `delete` (or all of them for `*`), then hands the call on unchanged. Deleting in BOTH entries is what makes it a
    // red-proof for PackageScanner.ScanYara: called through ScanDirectory (the pre-ADR-0034 wiring) the backend's own walk
    // then simply never sees the file, and the package reads Completed.
    private sealed class DeletingScanner(IYaraScanner inner, string delete) : IYaraScanner
    {
        public bool Available => inner.Available;

        public string? UnavailableReason => inner.UnavailableReason;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => inner.ScanFile(fullPath);

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
        {
            Delete(rootDir);
            return inner.ScanDirectory(rootDir);
        }

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            Delete(rootDir);
            return inner.ScanFiles(rootDir, files);
        }

        private void Delete(string rootDir)
        {
            foreach (var file in Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories)
                         .Where(f => delete == "*" || string.Equals(Path.GetFileName(f), delete, StringComparison.Ordinal)))
                File.Delete(file);
        }
    }
    #endregion
}
