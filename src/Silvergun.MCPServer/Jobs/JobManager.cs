namespace Silvergun.MCPServer.Jobs;

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>Where a job is, as the tools report it.</summary>
public enum JobState { Queued, Running, Completed, Failed, Cancelled, Unknown }

/// <summary>
/// A snapshot of one job for the tools. <see cref="Elsewhere"/>: another server process holds the entry's lock and is
/// running it. <see cref="Cached"/>: the result was already on disk. <see cref="Reason"/> is escaped and bounded.
/// </summary>
public sealed record JobView(string JobId, JobState State, string? Stage, int Done, int Total, bool Cached, bool Elsewhere, string? Reason,
    JobRecord? Record, DateTimeOffset? StartedAt, long? ElapsedMs, string? EntryDir);

/// <summary>
/// Runs analysis jobs (task D3, D4a and the S1 design). At most <see cref="McpServerSettings.MaxJobs"/> run at once and
/// <see cref="McpLimits.MaxQueuedJobs"/> more wait. Each takes its entry's lock, so across every server process sharing
/// the cache one key runs once; a process that finds the lock held waits for the holder's result instead. A completed job
/// lives only on disk, so any process resolves any <c>jobId</c>; a failed or cancelled one lives only in the process that
/// ran it. Nothing here runs before the first tool call. <paramref name="inspector"/> starts <c>disassemble</c>'s inspect
/// children (task S3); by default it is <paramref name="launch"/>'s executable as the inspect worker.
/// </summary>
public sealed class JobManager(McpServerSettings settings, JobLaunch launch, JobLaunch? inspector = null)
{
    #region Properties
    public JobStore Store { get; } = new(settings.CacheDir, (long)settings.CacheMaxGb * 1024 * 1024 * 1024, settings.Network);
    #endregion

    #region Methods
    /// <summary>Copies a checked input into the cache, then serves it from disk or queues a job for it.</summary>
    public async Task<(JobView? View, ToolStatus Status, string? Problem)> SubmitAsync(string fullPath, JobDepth depth, CancellationToken ct)
    {
        if (Prepared() is { Length: > 0 } unusable)
            return (null, ToolStatus.Failed, unusable);
        // Checked before the copy, and copies are limited, so parallel calls cannot fill incoming/ past the cache's cap.
        if (QueueFull())
            return (null, ToolStatus.Busy, $"{McpLimits.MaxQueuedJobs} jobs are already queued; wait for one to finish");
        if (!await copies.WaitAsync(TimeSpan.Zero, ct))
            return (null, ToolStatus.Busy, $"{MaxConcurrentCopies} package copies are already in progress; try again shortly");

        var incoming = Store.IncomingPath();
        string? sha;
        long bytes;
        string? problem;
        try
        {
            (sha, bytes, problem) = await PackageInput.CopyAsync(fullPath, incoming, ct);
        }
        finally
        {
            copies.Release();
        }
        if (sha is null)
            return (null, ToolStatus.Failed, problem);

        // A deep entry serves a standard request too.
        foreach (var served in depth == JobDepth.Standard ? new[] { JobDepth.Standard, JobDepth.Deep } : [JobDepth.Deep])
            if (Store.Completed(sha, served) is ({ } record, null))
            {
                Discard(incoming);
                Store.Touch(sha, served);
                return (CompletedView(JobId(sha, served), record, Store.EntryDir(sha, served), cached: true), ToolStatus.Succeeded, null);
            }

        var id = JobId(sha, depth);
        lock (sync)
        {
            if (jobs.TryGetValue(id, out var existing) && !existing.Terminal)
            {
                Discard(incoming);
                return (existing.View(), ToolStatus.Succeeded, null);
            }
            if (QueueFull())
            {
                Discard(incoming);
                return (null, ToolStatus.Busy, $"{McpLimits.MaxQueuedJobs} jobs are already queued; wait for one to finish");
            }
            var run = new JobRun(id, sha, depth, incoming, bytes, CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token));
            jobs[id] = run;
            run.Task = Task.Run(() => ExecuteAsync(run));
            return (run.View(), ToolStatus.Succeeded, null);
        }
    }

    /// <summary>The job's state, waiting up to <paramref name="maxWait"/> for it to end, reporting progress as it moves.</summary>
    public async Task<(JobView? View, ToolStatus Status, string? Problem)> WaitAsync(string jobId, TimeSpan maxWait, IProgress<(double Progress, double Total, string Stage)>? progress, CancellationToken ct)
    {
        if (!TryParse(jobId, out _, out _))
            return (null, ToolStatus.InvalidArgument, "jobId is not one this server issues (<sha256>-standard or <sha256>-deep)");
        var deadline = Stopwatch.GetTimestamp() + (long)(maxWait.TotalSeconds * Stopwatch.Frequency);
        if (!jobs.TryGetValue(jobId, out var run))
        {
            // Another server process's run: poll the disk until it ends or the wait is over, rather than return at once.
            var found = FromDisk(jobId);
            while (found.View is { Elsewhere: true } && Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline) > TimeSpan.Zero)
            {
                await Task.Delay(PeerPoll, ct);
                found = FromDisk(jobId);
            }
            return found;
        }

        double reported = -1;
        while (!run.Terminal)
        {
            var changed = run.Changed;
            var view = run.View();
            if (progress is not null && Fraction(view) is var fraction && fraction > reported)
            {
                progress.Report((fraction, StageCount(run.Depth), view.Stage ?? "queued"));
                reported = fraction;
            }
            var left = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline);
            if (left <= TimeSpan.Zero)
                break;
            await Task.WhenAny(changed, Task.Delay(left, ct));
            ct.ThrowIfCancellationRequested();
        }
        return (run.View(), ToolStatus.Succeeded, null);
    }

    /// <summary>Cancels a job this process is running or queuing, and waits (bounded) until its process tree is gone.</summary>
    public async Task<(JobView? View, ToolStatus Status, string? Problem)> CancelAsync(string jobId)
    {
        if (!TryParse(jobId, out _, out _))
            return (null, ToolStatus.InvalidArgument, "jobId is not one this server issues (<sha256>-standard or <sha256>-deep)");
        if (!jobs.TryGetValue(jobId, out var run))
            return FromDisk(jobId) is ({ Elsewhere: true } view, _, _)
                ? (view, ToolStatus.NotPermitted, "the job is running in another server process; only that process can cancel it")
                : FromDisk(jobId);

        run.Cancel();
        await Task.WhenAny(run.Task ?? Task.CompletedTask, Task.Delay(CancelWait));
        return (run.View(), ToolStatus.Succeeded, null);
    }

    /// <summary>A completed job's entry directory and record, or the job's view when it has not completed.</summary>
    public (JobView? View, ToolStatus Status, string? Problem) Find(string jobId) =>
        !TryParse(jobId, out _, out _) ? (null, ToolStatus.InvalidArgument, "jobId is not one this server issues (<sha256>-standard or <sha256>-deep)")
        : jobs.TryGetValue(jobId, out var run) ? (run.View(), ToolStatus.Succeeded, null)
        : FromDisk(jobId);

    /// <summary>The median wall-clock seconds of this cache's completed jobs at <paramref name="depth"/>, or null when there are none.</summary>
    public double? TypicalSeconds(JobDepth depth)
    {
        var costs = Costs(depth);
        lock (costs)
            return costs.Count == 0 ? null : costs.Order().ElementAt(costs.Count / 2) / 1000.0;
    }

    /// <summary>Cancels every queued and running job and waits, at most <paramref name="bound"/>, for their trees to go (task D4a).</summary>
    public async Task StopAsync(TimeSpan bound)
    {
        shutdown.Cancel();
        var running = jobs.Values.Select(j => j.Task).OfType<Task>().ToArray();
        if (running.Length > 0)
            await Task.WhenAny(Task.WhenAll(running), Task.Delay(bound));
    }

    /// <summary>
    /// Runs one inspect child for <paramref name="request"/> (task S3) under its budget and containment; at most
    /// <see cref="McpLimits.MaxInspections"/> at once, and a call that cannot start within <see cref="InspectSlotWait"/> is
    /// <see cref="ToolStatus.Busy"/>. Its reason is escaped and bounded, with host paths reduced.
    /// </summary>
    public async Task<(JobRunResult? Result, ToolStatus Status, string? Problem)> InspectAsync(InspectRequest request, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, shutdown.Token);
        if (!await inspections.WaitAsync(InspectSlotWait, linked.Token))
            return (null, ToolStatus.Busy, $"{McpLimits.MaxInspections} inspections are already running; try again shortly");
        try
        {
            var result = await Task.Factory.StartNew(
                () => JobProcess.Run(inspector ?? launch.Inspector(), request, TimeSpan.FromSeconds(McpLimits.InspectBudgetSeconds), McpLimits.InspectMemoryBytes,
                    McpLimits.InspectHeapBytes, _ => { }, linked.Token, InspectProtocol.MaxResultLineBytes),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            // No default arm (task D10).
#pragma warning disable CS8524
            return result.Status switch
            {
                JobRunStatus.Completed => (result, ToolStatus.Succeeded, null),
                JobRunStatus.Cancelled => (null, ToolStatus.Cancelled, "the call was cancelled; the inspect process was killed"),
                JobRunStatus.TimedOut => (null, ToolStatus.Failed, $"listing the method ran past its {McpLimits.InspectBudgetSeconds} s budget, so it was stopped"),
                JobRunStatus.Failed => (null, ToolStatus.Failed, WithoutHostPaths(result.Reason ?? "the inspect process failed")),
            };
#pragma warning restore CS8524
        }
        finally
        {
            inspections.Release();
        }
    }

    public static string JobId(string sha256, JobDepth depth) => $"{sha256}-{JobStore.DepthName(depth)}";

    public static bool TryParse(string? jobId, out string sha256, out JobDepth depth)
    {
        var match = jobId is null ? Match.Empty : jobIdPattern.Match(jobId);
        sha256 = match.Success ? match.Groups[1].Value : string.Empty;
        depth = match.Success && match.Groups[2].Value == "deep" ? JobDepth.Deep : JobDepth.Standard;
        return match.Success;
    }

    // One job, start to end. Never throws; the run's state says how it ended.
    private async Task ExecuteAsync(JobRun run)
    {
        var ct = run.Token;
        var gateHeld = false;
        try
        {
            // A slot, then the key's lock, and never one held while waiting on the other (S1 review W4, round 2 W3): a run
            // queued here holds no lock another server waits on, and a wait on another server's run holds no slot. The lock is
            // held only while a run is in flight, which its budget bounds, so a fixed peer deadline is enough.
            // The peer deadline starts the first time the lock is seen held, never during this server's own queue (round 3, W1).
            long? peerDeadline = null;
            FileStream? held;
            while (true)
            {
                await gate.WaitAsync(ct);
                gateHeld = true;
                if ((held = Store.TryLock(run.Sha256, run.Depth)) is not null)
                    break;
                gate.Release();
                gateHeld = false;

                // Another server process runs this key: wait for its result rather than run a duplicate, but not for ever.
                run.Update("elsewhere", 0, 0, elsewhere: true);
                peerDeadline ??= Stopwatch.GetTimestamp() + (long)(PeerWait(run.Depth).TotalSeconds * Stopwatch.Frequency);
                while (!LockFree(run))
                {
                    if (Store.Completed(run.Sha256, run.Depth) is ({ } peer, null))
                    {
                        run.Complete(peer, Store.EntryDir(run.Sha256, run.Depth), cached: true);
                        return;
                    }
                    if (Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), peerDeadline.Value) <= TimeSpan.Zero)
                    {
                        run.End(JobState.Failed, $"another process has held this cache entry's lock for over {PeerWait(run.Depth).TotalSeconds:0} s without finishing it");
                        return;
                    }
                    await Task.Delay(PeerPoll, ct);
                }
                run.Update("queued", 0, 0);
            }

            using (held)
            {
                run.Start();
                var (existing, problem) = Store.Completed(run.Sha256, run.Depth);
                if (existing is not null)
                {
                    run.Complete(existing, Store.EntryDir(run.Sha256, run.Depth), cached: true);
                    return;
                }
                if (problem is not null)
                    Runtime.Warn("mcp: a cache entry failed its checks and is re-run: {0}", WorkerProtocol.Safe(problem, 200));
                Store.Clean(run.Sha256, run.Depth, deleteEntry: problem is not null);
                await RunInTempAsync(run, ct);
                return;
            }
        }
        catch (OperationCanceledException)
        {
            run.End(JobState.Cancelled, "the job was cancelled before it finished");
        }
        catch (Exception ex)
        {
            Runtime.Error("mcp: job failed unexpectedly: {0}", SdkLogRedactor.RenderException(ex, settings.Debug));
            run.End(JobState.Failed, $"the server failed while running the job ({ex.GetType().Name})");
        }
        finally
        {
            if (gateHeld)
                gate.Release();
            Discard(run.Incoming);
            if (!run.Terminal)
                run.End(JobState.Failed, "the job ended without a result");
        }
    }

    // Under the key's lock: run the child in a fresh temporary directory, check what it wrote, record it, rename it into place.
    private async Task RunInTempAsync(JobRun run, CancellationToken ct)
    {
        var temp = Store.CreateTemp(run.Sha256, run.Depth);
        var committed = false;
        try
        {
            File.Move(run.Incoming, Path.Combine(temp, JobProtocol.PackageFile));
            var deep = run.Depth == JobDepth.Deep;
            var budget = TimeSpan.FromSeconds(deep ? McpLimits.DeepJobBudgetSeconds : McpLimits.StandardJobBudgetSeconds);
            var memory = deep ? McpLimits.DeepJobMemoryBytes : McpLimits.JobMemoryBytes;
            var startedAt = DateTimeOffset.UtcNow;
            var result = await Task.Factory.StartNew(
                () => JobProcess.Run(launch, new JobRequest(JobProtocol.Version, temp, run.Depth, settings.Network), budget, memory, McpLimits.JobHeapBytes,
                    p => run.Update(p.Stage, p.Done, p.Total), ct),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

            switch (result.Status)
            {
                case JobRunStatus.Cancelled:
                    run.End(JobState.Cancelled, "the job was cancelled; its process tree was killed");
                    return;
                case JobRunStatus.TimedOut or JobRunStatus.Failed:
                    run.End(JobState.Failed, WithoutHostPaths(result.Reason ?? "the job failed"));
                    return;
            }

            if ((JobArtifacts.MissingArtifact(temp) ?? JobArtifacts.ReadGate(temp).Problem ?? JobArtifacts.ReadSummary(temp).Problem ?? JobArtifacts.ReadIndex(temp).Problem) is { } bad)
            {
                run.End(JobState.Failed, WithoutHostPaths($"the job's results failed their checks: {bad}"));
                return;
            }
            var record = new JobRecord(JobArtifacts.SchemaVersion, run.Sha256, run.Depth, BuildIdentity.BuildKey, ServerState.SilvergunVersion,
                BuildIdentity.RulesHash, settings.Network, (int)budget.TotalSeconds, memory, startedAt, DateTimeOffset.UtcNow,
                result.Done!.ElapsedMs, result.Done.Stages, run.PackageBytes, 0);
            record = record with { EntryBytes = JobStore.SizeOf(temp) + JsonSerializer.SerializeToUtf8Bytes(record, JobProtocol.JsonOptions).Length };
            JobArtifacts.WriteAtomic(temp, JobProtocol.JobFile, JsonSerializer.SerializeToUtf8Bytes(record, JobProtocol.JsonOptions));
            if (await Store.CommitAsync(temp, run.Sha256, run.Depth, ct) is { } uncommitted)
            {
                run.End(JobState.Failed, uncommitted);
                return;
            }
            committed = true;
            Store.Touch(run.Sha256, run.Depth);
            Record(run.Depth, record.ElapsedMs);
            run.Complete(record, Store.EntryDir(run.Sha256, run.Depth), cached: false);
            Store.Evict((run.Sha256, run.Depth));
        }
        finally
        {
            if (!committed && Directory.Exists(temp))
                try { Directory.Delete(temp, recursive: true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* an orphan; the next touch of the key deletes it */ }
        }
    }

    // A job this process does not hold: a completed entry, another process's run, or nothing.
    private (JobView? View, ToolStatus Status, string? Problem) FromDisk(string jobId)
    {
        TryParse(jobId, out var sha, out var depth);
        if (Prepared() is { Length: > 0 } unusable)
            return (null, ToolStatus.Failed, unusable);
        if (Store.Completed(sha, depth) is ({ } record, null))
        {
            Store.Touch(sha, depth);
            return (CompletedView(jobId, record, Store.EntryDir(sha, depth), cached: true), ToolStatus.Succeeded, null);
        }
        if (Directory.Exists(Path.Combine(Store.Root, sha)))
        {
            using var held = Store.TryLock(sha, depth);
            if (held is null)
                return (new JobView(jobId, JobState.Running, "elsewhere", 0, 0, false, true, null, null, null, null, null), ToolStatus.Succeeded, null);
        }
        return (null, ToolStatus.NotFound, "no result for this jobId: it never ran here, failed, was cancelled, or was evicted; call analyze_package again");
    }

    /// <summary>
    /// <paramref name="text"/> with the cache root, the temp directory and the user's profile reduced to labels (task D6.5):
    /// a scan's own message names the package file it opened, which is the copy in the job's directory.
    /// </summary>
    public string WithoutHostPaths(string text) => HostPaths.Reduce(text, HostPaths.ForServer(Store.Root));

    private static JobView CompletedView(string jobId, JobRecord record, string entryDir, bool cached) =>
        new(jobId, JobState.Completed, null, 0, 0, cached, false, null, record, record.StartedAt, record.ElapsedMs, entryDir);

    private string? Prepared()
    {
        lock (sync)
            return prepared ??= Store.Prepare() ?? string.Empty;
    }

    private void Record(JobDepth depth, long elapsedMs)
    {
        var costs = Costs(depth);
        lock (costs)
            costs.Add(elapsedMs);
    }

    // The depth's cost list, loaded from disk on first use, outside the manager's lock (the load reads many files).
    private List<long> Costs(JobDepth depth)
    {
        lock (sync)
            if ((depth == JobDepth.Deep ? deepCosts : standardCosts) is { } known)
                return known;
        var loaded = LoadCosts(depth);
        lock (sync)
            return depth == JobDepth.Deep ? deepCosts ??= loaded : standardCosts ??= loaded;
    }

    // Whether nobody holds the key's lock now (it is taken and released at once).
    private bool LockFree(JobRun run)
    {
        using var probe = Store.TryLock(run.Sha256, run.Depth);
        return probe is not null;
    }

    private bool QueueFull() => jobs.Values.Count(j => j.State == JobState.Queued) >= McpLimits.MaxQueuedJobs;

    // How long a run waits on another process's lock before giving up: that run's own budget, plus a margin.
    private static TimeSpan PeerWait(JobDepth depth) =>
        TimeSpan.FromSeconds((depth == JobDepth.Deep ? McpLimits.DeepJobBudgetSeconds : McpLimits.StandardJobBudgetSeconds) + 120);

    // This cache's completed costs at a depth, read once (lazily) from job.json files of this build.
    private List<long> LoadCosts(JobDepth depth)
    {
        var name = JobStore.EntryName(depth, settings.Network);
        try
        {
            return !Directory.Exists(Store.Root) ? []
                : Directory.EnumerateDirectories(Store.Root)
                    .Select(d => Path.Combine(d, name))
                    .Where(Directory.Exists)
                    .Take(MaxCostSamples)
                    .Select(d => JobArtifacts.ReadBounded(Path.Combine(d, JobProtocol.JobFile), JobArtifacts.MaxRecordBytes).Bytes)
                    .OfType<byte[]>()
                    .Select(b => { try { return JsonSerializer.Deserialize<JobRecord>(b, JobProtocol.JsonOptions); } catch (JsonException) { return null; } })
                    .Where(r => r is { ElapsedMs: >= 0 } && r.BuildKey == BuildIdentity.BuildKey)
                    .Select(r => r!.ElapsedMs)
                    .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    // The job's progress as stages completed plus the current stage's fraction; the stages are numbered from 0.
    private static double Fraction(JobView view)
    {
        var index = Array.IndexOf(stageOrder, view.Stage);
        return index < 0 ? 0 : index + (view.Total > 0 ? Math.Min(1.0, (double)view.Done / view.Total) : 0);
    }

    private static int StageCount(JobDepth depth) => depth == JobDepth.Deep ? stageOrder.Length : stageOrder.Length - 1;

    private static void Discard(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* incoming/ is swept later */ }
    }
    #endregion

    #region Fields
    private const int MaxConcurrentCopies = 2;
    private static readonly TimeSpan InspectSlotWait = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan PeerPoll = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan CancelWait = TimeSpan.FromSeconds(10);
    private const int MaxCostSamples = 10_000;

    // The stages in the order they run; reachability last, and only when deep.
    private static readonly string?[] stageOrder = ["extract", "assemblies", "scripts", "yara", "write", "reachability"];

    private static readonly Regex jobIdPattern = new(@"\A([0-9a-f]{64})-(standard|deep)\z", RegexOptions.CultureInvariant);

    private readonly SemaphoreSlim gate = new(settings.MaxJobs, settings.MaxJobs);
    private readonly SemaphoreSlim copies = new(MaxConcurrentCopies, MaxConcurrentCopies);
    private readonly SemaphoreSlim inspections = new(McpLimits.MaxInspections, McpLimits.MaxInspections);
    private readonly ConcurrentDictionary<string, JobRun> jobs = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource shutdown = new();
    private readonly object sync = new();
    private string? prepared;
    private List<long>? standardCosts;
    private List<long>? deepCosts;
    #endregion

    #region Types
    // One job this process owns. Every mutation is under its lock and wakes waiters through Changed.
    private sealed class JobRun(string jobId, string sha256, JobDepth depth, string incoming, long packageBytes, CancellationTokenSource cts)
    {
        public string Sha256 { get; } = sha256;
        public JobDepth Depth { get; } = depth;
        public string Incoming { get; } = incoming;
        public long PackageBytes { get; } = packageBytes;
        public CancellationToken Token => cts.Token;
        public Task? Task { get; set; }
        public JobState State { get { lock (sync) return state; } }
        public bool Terminal { get { lock (sync) return state is JobState.Completed or JobState.Failed or JobState.Cancelled; } }
        public Task Changed { get { lock (sync) return changed.Task; } }

        public void Start()
        {
            lock (sync)
            {
                (state, startedAt, stage, elsewhere) = (JobState.Running, DateTimeOffset.UtcNow, "starting", false);
                clock.Start();
            }
            Signal();
        }

        public void Update(string stage, int done, int total, bool elsewhere = false)
        {
            lock (sync)
                (this.stage, this.done, this.total, this.elsewhere) = (stage, done, total, elsewhere);
            Signal();
        }

        public void Complete(JobRecord record, string entryDir, bool cached)
        {
            lock (sync)
                (state, this.record, this.entryDir, this.cached, elsewhere, stage) = (JobState.Completed, record, entryDir, cached, false, null);
            Signal();
        }

        public void End(JobState end, string reason)
        {
            lock (sync)
            {
                if (state is JobState.Completed or JobState.Failed or JobState.Cancelled)
                    return;
                (state, this.reason, elsewhere) = (end, WorkerProtocol.Safe(reason, JobProtocol.MaxReasonChars), false);
                clock.Stop();
            }
            Signal();
        }

        public void Cancel()
        {
            try { cts.Cancel(); }
            catch (ObjectDisposedException) { /* already over */ }
        }

        public JobView View()
        {
            lock (sync)
                return new(jobId, state, stage, done, total, cached, elsewhere, reason, record, record?.StartedAt ?? startedAt,
                    record?.ElapsedMs ?? (clock.IsRunning || clock.ElapsedTicks > 0 ? (long)clock.Elapsed.TotalMilliseconds : null), entryDir);
        }

        private void Signal()
        {
            TaskCompletionSource fired;
            lock (sync)
                (fired, changed) = (changed, new(TaskCreationOptions.RunContinuationsAsynchronously));
            fired.TrySetResult();
        }

        private readonly object sync = new();
        private readonly Stopwatch clock = new();
        private TaskCompletionSource changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private JobState state = JobState.Queued;
        private string? stage;
        private int done;
        private int total;
        private bool elsewhere;
        private bool cached;
        private string? reason;
        private JobRecord? record;
        private string? entryDir;
        private DateTimeOffset? startedAt;
    }
    #endregion
}
