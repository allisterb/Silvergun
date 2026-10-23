#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

/// <summary>
/// The parent side of the out-of-process YARA-X backend (ADR 0033 FINAL FORM; task T4 of
/// <c>docs/agent/tasks/yarax-worker.md</c>, whose "worker protocol v1" section and amendments are the contract). Each
/// scan runs <c>Silvergun.CLI __worker yara --protocol 1 --timeout &lt;s&gt;</c> as a child process, streams it the file
/// list on stdin, and reads one result per file back from stdout as <b>hostile input</b> (<see cref="WorkerResponseReader"/>).
/// The engine — and any native fault in it — lives in the child, which this process can always kill.
///
/// <para><b>Which executable</b> (amendment (o)). This process may not be the CLI (it is <c>testhost</c> under
/// <c>dotnet test</c>, <c>dotnet</c> under <c>dotnet Silvergun.CLI.dll</c>, the WPF app in WPF), so the worker is: this
/// process's own executable when it is the Silvergun CLI apphost; otherwise the CLI apphost in
/// <see cref="AppContext.BaseDirectory"/>, by absolute path, when it exists; otherwise there is none and the backend is
/// not <see cref="Available"/>. Never a PATH lookup, and never <c>dotnet &lt;dll&gt;</c>, which would trust whichever
/// <c>dotnet</c> resolved.</para>
///
/// The invariant: <b>a file is scanned only when a genuine YARA-X worker said so.</b> A run's results are used only when
/// that run's <c>ready</c> names engine <c>yara-x</c>, a passed canary, at least one rule, no rule source with compile
/// errors, and a <c>rulesSha256</c> equal to this process's own hash of its embedded rules (amendment G1); a stub or
/// foreign worker can never produce a scanned file. Everything else — a <c>timeout</c>, <c>error</c> or <c>skipped</c>
/// result, a missing result, a path refused before sending (a link, checked on the verbatim form of the path and of each
/// directory under the root (W-A), or a path not in <see cref="WorkerPathForm"/>'s form (G2, (j'))), a worker that hung,
/// crashed, broke the protocol, overran its output
/// budget (G4), sent <c>fatal</c> (G5) or exited non-zero after <c>done</c> (amendment (f)) — is <b>unscanned</b>, and any
/// unscanned file throws <see cref="YaraScanIncompleteException"/> carrying every hit that <i>was</i> genuinely reported
/// (ADR 0032), which <c>PackageScanner.ScanYara</c> reports alongside <see cref="YaraScanStatus.Unavailable"/>.
///
/// Clocks (the parent owns them; pipe reads are not cancellable, so every backstop is a kill, amendment (g)): <c>ready</c>
/// within 15 s (G9); then no more than the engine timeout plus a 5 s grace between records; then, after <c>done</c>, a
/// bounded wait for the exit code. Each run is placed in a kill-on-close Job Object (<see cref="WorkerJobObject"/>) held
/// for this instance's lifetime, so no worker outlives this process. Windows-only for now, like the binding it drives.
/// </summary>
public sealed class YaraXWorkerScanner : Runtime, IYaraScanner, IDisposable
{
    #region Constructors
    /// <param name="options">
    /// Only <see cref="YaraOptions.Timeout"/> is used: the per-file engine timeout in seconds, passed to the worker as
    /// <c>--timeout</c>. Null means the product default, <see cref="WorkerProtocol.DefaultTimeoutSeconds"/> — never "no
    /// timeout" (amendments G3, (i)). Any other value is clamped into [<see cref="WorkerProtocol.MinTimeoutSeconds"/>,
    /// <see cref="WorkerProtocol.MaxTimeoutSeconds"/>], with a warning when that changes it (amendment W-D): the worker
    /// refuses anything outside that range, and a configured value must not make YARA permanently unavailable.
    /// </param>
    public YaraXWorkerScanner(YaraOptions? options = null)
        : this(ResolveWorkerExecutable(Environment.ProcessPath, AppContext.BaseDirectory), EngineTimeoutSeconds(options))
    {
    }

    private YaraXWorkerScanner((string? Path, string? Problem) worker, int engineTimeoutSeconds)
        : this(worker.Path, WorkerProtocol.YaraWorkerLaunchArguments(engineTimeoutSeconds), engineTimeoutSeconds,
            DefaultReadyTimeout, DefaultGrace, DefaultExitTimeout)
    {
        workerPathProblem = worker.Problem;
    }

    // The test seam (ADR 0033 decision 8): the worker command line and the clock bounds. Production launches the worker
    // ResolveWorkerExecutable finds, with WorkerProtocol.YaraWorkerLaunchArguments. workerPath must be absolute (no PATH
    // lookup, ever); a relative or null one fails every run closed. engineTimeoutSeconds is the per-file engine budget the
    // backstop adds `grace` to; it is NOT added to workerArguments here, so a test's fake worker gets exactly the
    // arguments it is given (and may be below the worker's own minimum, for a fast backstop).
    internal YaraXWorkerScanner(
        string? workerPath, IReadOnlyList<string> workerArguments, int engineTimeoutSeconds,
        TimeSpan readyTimeout, TimeSpan grace, TimeSpan exitTimeout)
    {
        ArgumentNullException.ThrowIfNull(workerArguments);
        ArgumentOutOfRangeException.ThrowIfLessThan(engineTimeoutSeconds, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(readyTimeout, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(grace, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(exitTimeout, TimeSpan.Zero);

        this.workerPath = workerPath;
        this.workerArguments = [.. workerArguments];
        this.engineTimeoutSeconds = engineTimeoutSeconds;
        this.readyTimeout = Bounded(readyTimeout);
        lineTimeout = Bounded(TimeSpan.FromSeconds(engineTimeoutSeconds) + grace);
        this.exitTimeout = Bounded(exitTimeout);
        availability = new(Probe);
    }
    #endregion

    #region Properties
    /// <summary>
    /// <c>true</c> only once a probe run (zero files) reached a <c>ready</c> that satisfies amendment G1 — engine
    /// <c>yara-x</c>, canary passed, rules loaded with no rule source in error, the embedded rules' hash — then <c>done</c>
    /// and exit 0 (amendment (c)). The probe runs once, on first use, and its outcome is kept for this instance's
    /// lifetime. <c>false</c> when there is no worker executable (amendment (o)), the worker cannot start, sends
    /// <c>fatal</c> (e.g. the YARA-X DLL is absent), is not genuine, misses a clock, or after <see cref="Dispose"/>.
    /// </summary>
    public bool Available => !disposed && availability.Value;

    /// <summary>
    /// Why this backend is not <see cref="Available"/>: the availability probe's failure (e.g. the worker's <c>fatal</c>
    /// when the YARA-X DLL is missing, or that there is no worker executable), or that it was disposed. <c>null</c> when it
    /// is available. Reading it runs the probe if it has not run.
    /// </summary>
    public string? UnavailableReason => Available ? null : disposed ? "the scanner has been disposed" : probeFailure;

    /// <summary>
    /// The <c>rulesSha256</c> a genuine worker must announce (amendment G9): <see cref="YaraXRules.SourcesSha256Of"/> over
    /// this assembly's embedded rule sources, computed once in this process (no engine, no native code). <c>null</c> when
    /// the sources could not be hashed, in which case no worker is ever genuine.
    /// </summary>
    internal static string? ExpectedRulesSha256 => _expectedRulesSha256.Value;
    #endregion

    #region Methods
    /// <summary>
    /// Scans <paramref name="fullPath"/> in a one-file worker run, under the same rules as <see cref="ScanDirectory"/>.
    /// Returns the hits (empty when nothing matched), or empty when the backend never had an engine (its probe failed, so
    /// <see cref="Available"/> was never <c>true</c>). Throws <see cref="YaraScanIncompleteException"/> when this file was
    /// not scanned — the scanner is or became disposed, refused before sending (only the file itself is checked for being
    /// a link here: there is no root to bound the walk), or no genuine <c>scanned</c> result — or the run could not be
    /// vouched for, carrying any hits it did report.
    /// </summary>
    public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
    {
        if (!HasEngine(fullPath))
            return [];

        var outcome = Scan([fullPath], rootDir: null);
        return outcome.IsComplete
            ? outcome.Hits.Select(h => h.Match).ToArray()
            : throw new YaraScanIncompleteException(IncompleteMessage(null, 1, outcome), null, outcome.Hits);
    }

    /// <summary>
    /// Scans every file under <paramref name="rootDir"/> (recursively) in ONE worker run, and returns each hit paired
    /// with the enumerated path of the file it matched. Returns empty when nothing matched, the directory is missing or
    /// empty, or the backend never had an engine (its probe failed, so <see cref="Available"/> was never <c>true</c>).
    /// Throws <see cref="YaraScanIncompleteException"/> when the scanner is or became disposed, the tree cannot be
    /// enumerated, or any file has no genuine <c>scanned</c> result (see the class summary), carrying every hit that was
    /// reported.
    /// </summary>
    public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
    {
        if (!HasEngine(rootDir))
            return [];

        string[] files;
        try
        {
            // As the interface's default loop: a missing root is not reachable in production (rootDir is the package's
            // own, validated extraction dir), so "nothing to scan" is the honest reading; an enumeration that THROWS is not.
            files = !string.IsNullOrEmpty(rootDir) && Directory.Exists(rootDir)
                ? Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories)
                : [];
        }
        catch (Exception ex)
        {
            throw new YaraScanIncompleteException(
                $"YARA-X could not enumerate '{YaraPathSafety.Escape(rootDir)}', so an unknown number of files went unscanned: {YaraPathSafety.Escape(ex.Message)}. This package was NOT scanned and must not be reported as clean.",
                ex);
        }

        if (files.Length == 0)
            return [];

        var outcome = Scan(files, rootDir);
        return outcome.IsComplete
            ? outcome.Hits
            : throw new YaraScanIncompleteException(IncompleteMessage(rootDir, files.Length, outcome), null, outcome.Hits);
    }

    /// <summary>
    /// Closes the Job Object, which kills every worker still running for this instance; their scans end incomplete.
    /// Afterwards <see cref="Available"/> is <c>false</c> and every scan throws <see cref="YaraScanIncompleteException"/>.
    /// Idempotent. The process-wide instance <see cref="YaraScannerFactory.Shared"/> is never disposed: its job handle
    /// closes when the process exits, which kills any worker left.
    /// </summary>
    public void Dispose()
    {
        // Under the job lock, so a job being created right now is either disposed here or never created (review nit).
        lock (jobLock)
        {
            disposed = true;
            job?.Dispose();
        }
    }

    /// <summary>
    /// The worker executable (amendment (o)), from <paramref name="processPath"/> (<see cref="Environment.ProcessPath"/>)
    /// and <paramref name="baseDirectory"/> (<see cref="AppContext.BaseDirectory"/>): the process's own executable when its
    /// file name is the Silvergun CLI apphost's; otherwise that apphost in <paramref name="baseDirectory"/>, by absolute
    /// path, when it exists as a file; otherwise none, with an escaped, bounded reason. Never PATH, never <c>dotnet</c>.
    /// </summary>
    internal static (string? Path, string? Problem) ResolveWorkerExecutable(string? processPath, string? baseDirectory)
    {
        if (processPath is not null && Path.IsPathFullyQualified(processPath)
            && string.Equals(Path.GetFileName(processPath), CliApphost, StringComparison.OrdinalIgnoreCase))
            return (processPath, null);

        var beside = baseDirectory is not null && Path.IsPathFullyQualified(baseDirectory) ? Path.Combine(baseDirectory, CliApphost) : null;
        return beside is not null && File.Exists(beside)
            ? (beside, null)
            : (null, $"there is no worker executable: this process's executable ('{WorkerProtocol.Safe(Path.GetFileName(processPath), ShortChars)}') is not the Silvergun CLI apphost at an absolute path, and there is no {CliApphost} in its application directory '{WorkerProtocol.Safe(baseDirectory, ReasonChars)}'");
    }

    // One worker run over already-enumerated files: refuse what may not be sent, run the worker over the rest, and map
    // what came back. Never throws for a worker failure — that is the outcome's Failure, with every file lacking a genuine
    // 'scanned' result in Unscanned. Paths go on the wire with '/' folded to '\' (a separator on Windows, never a name
    // character; amendment (q)); hits are reported against the path as ENUMERATED, so they resolve against the root as given.
    private ScanOutcome Scan(IReadOnlyList<string> files, string? rootDir)
    {
        var refused = new List<(string File, string Why)>();
        var sent = new List<(string File, string Wire)>();
        foreach (var file in files)
        {
            var wire = file.Replace('/', '\\');
            var why = Refusal(rootDir, file, wire);
            if (why is null)
                sent.Add((file, wire));
            else
                refused.Add((file, why));
        }

        var run = sent.Count == 0 ? WorkerRun.Complete([]) : Converse(sent.Select(s => s.Wire).ToArray());
        var hits = new List<(string FullPath, YaraMatch Match)>();
        var unscanned = new List<(string File, string Why)>(refused);
        for (var i = 0; i < sent.Count; i++)
        {
            var file = sent[i].File;
            var result = i < run.Results.Count ? run.Results[i] : null;
            if (result is { Status: WorkerScanStatus.Scanned, Hits: { } found })
                hits.AddRange(Matches(found, file).Select(match => (file, match)));
            else
                unscanned.Add((file, result is null ? "no result" : $"{StatusName(result.Status)}: {WorkerProtocol.Safe(result.Reason, ReasonChars)}"));
        }

        return new(hits, unscanned, run.Failure);
    }

    // Why `file` (on the wire as `wire`) must not be sent, or null. The path form is the worker's own (amendment (j'):
    // WorkerPathForm.Verbatim, so both sides agree by construction; this class has no path rules of its own), and the link
    // check walks that verbatim form (W-A).
    private static string? Refusal(string? rootDir, string file, string wire) =>
        WorkerPathForm.Verbatim(wire) is null
            ? "its path is not in the worker protocol's form (absolute, backslash-separated, well-formed UTF-16, no NUL, no '.', '..' or empty segment, no ':' past the drive, not a device path)"
        : IsLink(rootDir, file, wire)
            ? "it is a link, lies under a linked directory, or could not be checked for either; following a link would scan content outside the package"
        : null;

    // A worker's hits on one file as YaraMatch (the protocol carries no matched strings). Results must never carry the
    // canary: a hit whose rule uses the reserved canary prefix (case-insensitively) is dropped with a warning — the
    // worker strips its own canary, and no shipped rule may use the prefix, so such a hit is not a detection.
    private static IEnumerable<YaraMatch> Matches(IReadOnlyList<WorkerHit> found, string file)
    {
        var reserved = found.Count(IsCanary);
        if (reserved > 0)
            Warn("YARA-X worker: dropped {0} hit(s) on {1} whose rule name uses the reserved canary prefix '{2}'; the canary is never a finding.",
                reserved, YaraPathSafety.Escape(file), YaraXCanary.Prefix);

        return found
            .Where(h => !IsCanary(h))
            .Select(h => new YaraMatch(h.Rule, h.Namespace.Length == 0 ? null : h.Namespace, [.. h.Tags], []))
            .ToArray();

        static bool IsCanary(WorkerHit hit) => hit.Rule.StartsWith(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase);
    }

    // Starts one worker, contains it, sends `paths` (index i = paths[i]) and reads its answers under the clocks. Never
    // throws for anything the worker does; the worker is dead or has exited when this returns.
    private WorkerRun Converse(IReadOnlyList<string> paths)
    {
        if (disposed)
            return WorkerRun.Failed("the scanner has been disposed");
        if (workerPathProblem is not null)
            return WorkerRun.Failed(workerPathProblem);
        if (workerPath is null || !Path.IsPathFullyQualified(workerPath))
            return WorkerRun.Failed("the worker executable's path is unknown or not absolute");

        using var process = new Process { StartInfo = StartInfo(workerPath) };
        try
        {
            if (!process.Start())
                return WorkerRun.Failed("the worker process did not start");
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or PlatformNotSupportedException)
        {
            return WorkerRun.Failed($"the worker process could not be started ({Describe(ex)})");
        }

        Task[] background = [];
        try
        {
            if (Contain(process) is { } uncontained)
                return Killed(process, uncontained, []);

            var stdout = new BudgetStream(process.StandardOutput.BaseStream, StdoutBudget(paths.Count));
            var reader = new WorkerResponseReader(stdout, paths.Count);
            var steps = new BlockingCollection<Step>();
            background =
            [
                Background(() => RelayStderr(process.StandardError.BaseStream)),
                Background(() => WriteRequests(process, paths)),   // amendment (a): never on the reading thread
                Background(() => Pump(reader, steps)),
            ];
            return Read(process, reader, stdout, steps);
        }
        finally
        {
            Kill(process);
            WaitQuietly(background, DrainTimeout);
        }
    }

    // The read loop and its clocks, on the calling thread. Records arrive through `steps` from the pump thread, so every
    // wait here is bounded even though the pipe read under it is not: a missed bound kills the worker (amendment (g)).
    private WorkerRun Read(Process process, WorkerResponseReader reader, BudgetStream stdout, BlockingCollection<Step> steps)
    {
        WorkerReady? ready = null;
        var results = new List<WorkerResult>();
        while (true)
        {
            var bound = ready is null ? readyTimeout : lineTimeout;
            if (!steps.TryTake(out var step, bound))
                return Killed(process, steps.IsCompleted ? "the worker's output ended without a terminal record"
                    : ready is null
                    ? $"the worker sent no 'ready' within {Seconds(bound)} s, so it was killed"
                    : $"the worker sent nothing for {Seconds(bound)} s (its {engineTimeoutSeconds} s engine timeout plus grace), so it was killed", results);

            if (step.Error is { } error)
                return Killed(process, error, results);

            switch (step.Message)
            {
                case WorkerReady announced:
                    if (NotGenuine(announced) is { } why)
                        return Killed(process, $"the worker is not a genuine YARA-X worker for this build ({why}); none of its results are used", []);
                    ready = announced;
                    break;
                case WorkerResult result:
                    results.Add(result);
                    break;
                case null:
                    return Ended(process, reader.Terminal, stdout, results);
            }
        }
    }

    // How a run whose record stream has ended is judged. Only `done` can complete it, and only with a prompt exit 0.
    private WorkerRun Ended(Process process, WorkerStreamTerminal? terminal, BudgetStream stdout, List<WorkerResult> results) =>
        stdout.Exceeded ? Killed(process, $"the worker's output exceeded its {stdout.Budget}-byte budget, so it was killed", results)
        : terminal switch
        {
            WorkerStreamTerminal.Done => AfterDone(process, results),
            WorkerStreamTerminal.Fatal fatal => Killed(process, $"the worker reported a fatal error: {fatal.Reason}", results),
            WorkerStreamTerminal.Violation violation => Killed(process, $"the worker's output broke protocol v{WorkerProtocol.Version}: {violation.Reason}", results),
            WorkerStreamTerminal.Eof eof => Killed(process, $"the worker's output ended before 'done'{(eof.Detail is { } detail ? $" ({detail})" : string.Empty)}{ExitNote(process)}", results),
            _ => Killed(process, "the worker's output ended in an unknown state", results),
        };

    // Amendment (f): after `done` the exit code still counts. Bytes after `done` are never read.
    private WorkerRun AfterDone(Process process, List<WorkerResult> results) =>
        !process.WaitForExit(exitTimeout) ? Killed(process, $"the worker did not exit within {Seconds(exitTimeout)} s of 'done', so it was killed", results)
        : process.ExitCode != WorkerProtocol.ExitDone ? WorkerRun.Failed($"the worker exited with code {process.ExitCode} after 'done'", results)
        : WorkerRun.Complete(results);

    // Amendment G1 (with (c) and G9): null when `ready` is from a genuine YARA-X worker running this build's rules.
    private static string? NotGenuine(WorkerReady ready) =>
        !string.Equals(ready.Engine, EngineName, StringComparison.Ordinal) ? $"its engine is '{WorkerProtocol.Safe(ready.Engine, ShortChars)}', not '{EngineName}'"
        : !string.Equals(ready.Canary, WorkerProtocol.CanaryPassed, StringComparison.Ordinal) ? $"its canary is '{WorkerProtocol.Safe(ready.Canary, ShortChars)}', not '{WorkerProtocol.CanaryPassed}'"
        : ready.RuleCount <= 0 ? $"it announced {ready.RuleCount} rules"
        : ready.RuleSourceErrors != 0 ? $"{ready.RuleSourceErrors} of its rule sources had compile errors, so its ruleset is not this build's whole ruleset"
        : !IsLowerHex64(ready.RulesSha256) ? "its rulesSha256 is not 64 lower-case hex digits"
        : ExpectedRulesSha256 is not { } expected ? "this process could not hash its own embedded rules to compare"
        : !string.Equals(ready.RulesSha256, expected, StringComparison.Ordinal) ? $"its rules (sha256 {ready.RulesSha256}) are not this build's embedded rules (sha256 {expected})"
        : null;

    private static bool IsLowerHex64(string text) => text.Length == 64 && text.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');

    // The reading thread (review N9: the reader is wrapped, and anything it throws is an incomplete stream, not an escape).
    // Posts every accepted record, then the terminal (a null message) or the error, then completes.
    private static void Pump(WorkerResponseReader reader, BlockingCollection<Step> steps)
    {
        try
        {
            WorkerMessage? message;
            do
            {
                message = reader.Next();
                steps.Add(new(message, null));
            }
            while (message is not null);
        }
        catch (Exception ex)
        {
            steps.Add(new(null, $"reading the worker's output failed ({Describe(ex)})"));
        }
        finally
        {
            steps.CompleteAdding();
        }
    }

    // The writing thread: one request per path, then stdin is closed. A write that fails (the worker died or stopped
    // reading) just stops sending: the worker then answers fewer than n requests, which the reader rejects, so a short
    // send can never pass for a complete run.
    private static void WriteRequests(Process process, IReadOnlyList<string> paths)
    {
        try
        {
            var writer = new WorkerProtocolWriter(process.StandardInput.BaseStream);
            for (var i = 0; i < paths.Count; i++)
                writer.Write(new WorkerRequest(i, paths[i]));
        }
        catch (Exception ex)
        {
            Debug("YARA-X worker: stopped sending requests ({0}).", Describe(ex));
        }
        finally
        {
            try { process.StandardInput.Close(); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException) { /* the pipe is already gone */ }
        }
    }

    // The worker's stderr: diagnostics only, never protocol. The first MaxStderrBytes are kept and relayed at Debug, one
    // escaped, bounded line at a time, prefixed; the rest is read and discarded so a flood can never block the worker.
    private static void RelayStderr(Stream stderr)
    {
        var kept = new byte[MaxStderrBytes];
        var length = 0;
        long discarded = 0;
        try
        {
            var chunk = new byte[StderrChunkBytes];
            int read;
            while ((read = stderr.Read(chunk, 0, chunk.Length)) > 0)
            {
                var take = Math.Min(read, kept.Length - length);
                chunk.AsSpan(0, take).CopyTo(kept.AsSpan(length));
                length += take;
                discarded += read - take;
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            /* the pipe closed under us: relay what arrived */
        }

        foreach (var line in Encoding.UTF8.GetString(kept, 0, length).Split('\n'))
            if (line.TrimEnd('\r') is { Length: > 0 } text)
                Debug("[yara-worker] {0}", WorkerProtocol.Safe(text, StderrLineChars));

        if (discarded > 0)
            Debug("[yara-worker] (stderr exceeded {0} bytes; {1} more byte(s) discarded)", MaxStderrBytes, discarded);
    }

    // Places the worker in this instance's kill-on-close Job Object; null on success, else why the run must not go on.
    // A worker that has already exited needs no containing: its output is still read and judged.
    private string? Contain(Process process)
    {
        try
        {
            (Job() ?? throw new InvalidOperationException(disposed ? "the scanner has been disposed" : "no Job Object could be created")).Assign(process);
            return null;
        }
        catch (Exception ex) when (ex is Win32Exception or ObjectDisposedException or InvalidOperationException)
        {
            return process.HasExited ? null : $"the worker could not be placed in its kill-on-close Job Object ({Describe(ex)}), so it was killed";
        }
    }

    // This instance's Job Object, created on first use (one attempt; a failure is warned about once), or null once
    // disposed. Creation and Dispose share jobLock, so a job is never created after, or leaked by, a racing Dispose.
    private WorkerJobObject? Job()
    {
        lock (jobLock)
        {
            if (!disposed && !jobAttempted)
            {
                jobAttempted = true;
                job = CreateJob();
            }
            return disposed ? null : job;
        }
    }

    private static WorkerJobObject? CreateJob()
    {
        try
        {
            return WorkerJobObject.Create();
        }
        catch (Win32Exception ex)
        {
            Warn("YARA-X worker: could not create a kill-on-close Job Object ({0}); no worker will be run.", Describe(ex));
            return null;
        }
    }

    // The availability probe (amendment (c)): a zero-file run must complete with a genuine ready.
    private bool Probe()
    {
        Debug("YARA-X worker: probing '{0}'.", WorkerProtocol.Safe(workerPath, ReasonChars));
        var run = Converse([]);
        if (run.Failure is null)
            return true;

        probeFailure = run.Failure;
        Warn("YARA-X worker scanning UNAVAILABLE: {0}.", run.Failure);
        return false;
    }

    private ProcessStartInfo StartInfo(string executable)
    {
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // Only the raw BaseStreams are used (amendment G8), but Process still wraps stdin in a StreamWriter at start,
            // and that writer emits its encoding's preamble at once; with the console code page at 65001 that is a UTF-8
            // BOM, which the worker's strict reader rejects. A BOM-less encoding keeps stdin protocol-only.
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        };
        foreach (var argument in workerArguments)
            info.ArgumentList.Add(argument);
        return info;
    }

    // Kills the worker and anything it started, then waits (bounded) for it to go. Never throws.
    private static void Kill(Process process)
    {
        try
        {
            if (process.HasExited)
                return;
            process.Kill(entireProcessTree: true);
            process.WaitForExit(KillWait);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException or AggregateException)
        {
            /* already gone, or the job's close will take it */
        }
    }

    private static WorkerRun Killed(Process process, string why, IReadOnlyList<WorkerResult> results)
    {
        Kill(process);
        return WorkerRun.Failed(why, results);
    }

    private static string ExitNote(Process process)
    {
        try
        {
            return process.WaitForExit(ExitNoteWait) ? $"; it exited with code {process.ExitCode}" : string.Empty;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return string.Empty;
        }
    }

    private static Task Background(Action action) =>
        Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    private static void WaitQuietly(Task[] tasks, TimeSpan bound)
    {
        try
        {
            Task.WaitAll(tasks, bound);
        }
        catch (AggregateException)
        {
            /* each background task reports its own failure; nothing here is a scan result */
        }
    }

    // The gate at the top of every scan (FR2.1, ADR 0030). False only for a backend that never had an engine: the probe's
    // outcome is a Lazy, fixed once computed, so a caller that ever saw Available == true can never get false here — the
    // only way Available turns false afterwards is Dispose, and a disposed scanner THROWS, never returns empty. It is not
    // read through Available: `!disposed && probe` would let a Dispose landing between the checks turn a requested scan
    // into an empty list, which PackageScanner (having already seen Available == true) reports as Completed and clean.
    // Disposal is checked again after the probe (a first use may run it, and Dispose may land during it); a Dispose
    // after that is caught by Converse (or the kill-on-close job ending the run), which fails the run, never empties it.
    private bool HasEngine(string? path)
    {
        ThrowIfDisposed(path);
        var probed = availability.Value;
        ThrowIfDisposed(path);
        return probed;
    }

    private void ThrowIfDisposed(string? path)
    {
        if (disposed)
            throw new YaraScanIncompleteException(
                $"YARA-X's worker scanner has been disposed, so '{YaraPathSafety.Escape(path)}' was NOT scanned and must not be reported as clean.");
    }

    // Whether opening `file` (on the wire as `wire`, the same length) could follow a link out of the package: the file
    // itself is a reparse point, or (when the root is known) any directory between rootDir (exclusive) and it is one. A
    // path not lexically under rootDir, an ancestor not in the protocol's form, or any exception reads as a link: we
    // cannot vouch for it, so it is not sent.
    // W-A: every path checked is the VERBATIM form the worker opens (WorkerPathForm.Verbatim). The plain form is
    // normalised first — a directory named `con` becomes \\.\con, and `bar.` loses its dot — so a junction with such a
    // name had no link target there and was walked straight through (measured: `con`, `bar.`, `lpt1.d`). Attributes are
    // read without following the link, and ANY reparse point counts, not only those .NET reports a target for.
    private static bool IsLink(string? rootDir, string file, string wire)
    {
        try
        {
            if (rootDir is null)
                return IsReparsePoint(wire);

            var start = file.Length - YaraPathSafety.Relative(rootDir, file).Length;
            return start == 0
                || Enumerable.Range(start, wire.Length - start)
                    .Where(i => wire[i] == '\\')
                    .Append(wire.Length)
                    .Any(end => IsReparsePoint(wire[..end]));
        }
        catch
        {
            return true;   // cannot tell ⇒ do not follow it
        }

        static bool IsReparsePoint(string path) =>
            WorkerPathForm.Verbatim(path) is not { } verbatim
            || (File.GetAttributes(verbatim) & FileAttributes.ReparsePoint) != 0;
    }

    private static string IncompleteMessage(string? rootDir, int total, ScanOutcome outcome)
    {
        var under = rootDir is null ? string.Empty : $" under '{YaraPathSafety.Escape(rootDir)}'";
        var what = outcome.Unscanned.Count == 0
            ? $"YARA-X's worker run over {total} file(s){under} cannot be vouched for"
            : $"YARA-X did not scan {outcome.Unscanned.Count} of {total} file(s){under}: "
              + YaraPathSafety.Bounded(outcome.Unscanned.Select(u => $"{YaraPathSafety.Relative(rootDir, u.File)} ({u.Why})").ToArray());
        return what
            + (outcome.Failure is null ? string.Empty : $". The worker run was incomplete: {outcome.Failure}")
            + $". {outcome.Hits.Count} hit(s) found in the files that were scanned are reported; the rest is NOT verified and must not be reported as clean.";
    }

    // W-D: null is the one default (i); anything else is clamped into the worker's range, with one warning when it moves.
    private static int EngineTimeoutSeconds(YaraOptions? options)
    {
        if (options?.Timeout is not int configured)
            return WorkerProtocol.DefaultTimeoutSeconds;

        var seconds = Math.Clamp(configured, WorkerProtocol.MinTimeoutSeconds, WorkerProtocol.MaxTimeoutSeconds);
        if (seconds != configured)
            Warn("YARA-X worker: the configured scan timeout of {0} s is outside {1}..{2} s; using {3} s.",
                configured, WorkerProtocol.MinTimeoutSeconds, WorkerProtocol.MaxTimeoutSeconds, seconds);
        return seconds;
    }

    // G4: n × (64 KiB + 1) + 1 MiB of stdout in total, whatever the lines hold: each result line may be MaxResultLineBytes
    // plus its '\n'. Cannot overflow: it is computed in long (the constants are long), and even int.MaxValue requests
    // × (64 KiB + 1) is ~1.4e14, far below long.MaxValue.
    private static long StdoutBudget(int requests) => requests * (PerRequestStdoutBytes + 1) + BaseStdoutBytes;

    // A wait bound BlockingCollection/Process accept (at most int.MaxValue ms).
    private static TimeSpan Bounded(TimeSpan bound) => bound <= MaxWait ? bound : MaxWait;

    private static string Seconds(TimeSpan bound) => bound.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture);

    private static string StatusName(WorkerScanStatus status) => status.ToString().ToLowerInvariant();

    private static string Describe(Exception ex) => WorkerProtocol.Safe($"{ex.GetType().Name}: {ex.Message}", ReasonChars);
    #endregion

    #region Fields
    /// <summary>The environment variable that selects the Windows YARA backend (<see cref="YaraScannerFactory"/>); this
    /// backend is the default when it is unset or empty.</summary>
    public const string EngineVar = YaraScannerFactory.EngineVar;

    /// <summary>The <see cref="EngineVar"/> value that selects this backend.</summary>
    public const string EngineValue = YaraScannerFactory.YaraXEngineValue;

    /// <summary>The <see cref="EngineVar"/> value that selects the in-process <see cref="LibYaraScanner"/> instead, an
    /// explicit fallback until its package is removed. Never selected automatically when this backend is unavailable.</summary>
    public const string LibYaraEngineValue = YaraScannerFactory.LibYaraEngineValue;

    private const string EngineName = "yara-x";
    private const long PerRequestStdoutBytes = WorkerProtocol.MaxResultLineBytes;
    private const long BaseStdoutBytes = 1024 * 1024;
    private const int MaxStderrBytes = 64 * 1024;
    private const int StderrChunkBytes = 4096;
    private const int StderrLineChars = 1024;
    private const int ReasonChars = 200;
    private const int ShortChars = 64;

    private static readonly TimeSpan DefaultReadyTimeout = TimeSpan.FromSeconds(15);   // G9: cold compile + canary + .NET start
    private static readonly TimeSpan DefaultGrace = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultExitTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan KillWait = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ExitNoteWait = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxWait = TimeSpan.FromMilliseconds(int.MaxValue - 1);

    // The Silvergun CLI's apphost: the only executable this backend runs as its worker (amendment (o)).
    private static readonly string CliApphost = OperatingSystem.IsWindows() ? "Silvergun.CLI.exe" : "Silvergun.CLI";

    private static readonly Lazy<string?> _expectedRulesSha256 = new(() =>
    {
        try
        {
            return YaraXRules.SourcesSha256Of(YaraRuleResources.ReadAll());
        }
        catch (Exception ex)
        {
            Warn("YARA-X worker: could not hash the embedded YARA rules ({0}); no worker can be trusted.", Describe(ex));
            return null;
        }
    });

    private readonly string? workerPath;
    private readonly string? workerPathProblem;   // why there is no worker executable (amendment (o)); null when there is
    private readonly IReadOnlyList<string> workerArguments;
    private readonly int engineTimeoutSeconds;
    private readonly TimeSpan readyTimeout;
    private readonly TimeSpan lineTimeout;
    private readonly TimeSpan exitTimeout;
    private readonly Lazy<bool> availability;
    private readonly Lock jobLock = new();
    private WorkerJobObject? job;
    private bool jobAttempted;
    private volatile bool disposed;
    private volatile string? probeFailure;   // why the probe failed (UnavailableReason); written once, by the probe, before availability is published
    #endregion

    #region Child types
    // One thing the pump thread saw: an accepted record, the end of the stream (both null), or a reader failure.
    private readonly record struct Step(WorkerMessage? Message, string? Error);

    // What one worker run produced: the results accepted in order (empty unless its ready was genuine), and why the run
    // cannot be vouched for (null only for done + exit 0).
    private sealed record WorkerRun(IReadOnlyList<WorkerResult> Results, string? Failure)
    {
        internal static WorkerRun Complete(IReadOnlyList<WorkerResult> results) => new(results, null);

        internal static WorkerRun Failed(string why, IReadOnlyList<WorkerResult>? results = null) => new(results ?? [], why);
    }

    // What one scan produced: every genuine hit, every file without a genuine 'scanned' result (and why), and the run's
    // failure, if any.
    private sealed record ScanOutcome(
        IReadOnlyList<(string FullPath, YaraMatch Match)> Hits, IReadOnlyList<(string File, string Why)> Unscanned, string? Failure)
    {
        internal bool IsComplete => Unscanned.Count == 0 && Failure is null;
    }

    // The worker's stdout under the G4 budget: reads past it are refused (end of stream) and flagged, never served.
    private sealed class BudgetStream(Stream inner, long budget) : Stream
    {
        public long Budget { get; } = budget;

        public bool Exceeded => exceeded;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (remaining <= 0)
            {
                exceeded = true;
                return 0;
            }

            var read = inner.Read(buffer, offset, (int)Math.Min(count, remaining));
            remaining -= read;
            return read;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private long remaining = budget;
        private volatile bool exceeded;
    }
    #endregion
}
#endif
