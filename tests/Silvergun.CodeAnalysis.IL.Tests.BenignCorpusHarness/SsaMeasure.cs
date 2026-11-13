namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// One folder of one package under <c>--ssa</c>: the worker's pass with SSA off, on, and on again, each from a fresh
/// extraction. <see cref="Differs"/>: the fields that differ between off and on (outcome, report, assemblies,
/// load-failures, reason, same-as, nodes, edges); empty when additive. <see cref="Child"/>: whether the off pass's graph
/// agrees with the join child's own build of the folder (Analyzed exactly when the child built a graph, with the same
/// nodes and edges): "equal", "differs", or "n/a" without a child result. <see cref="Repeat"/>: "equal", "differs", "cut"
/// (a run's time backstop or TimedOut), or "n/a" when neither run has facts. <see cref="InProcess"/>: whether the
/// worker's facts equal the join child's in-process facts: "equal", "differs", "cut" (a budget cut either), "n/a". The
/// rest describe the on run's facts.
/// </summary>
public sealed record SsaFolderRow(
    string Folder,
    string OffOutcome,
    string OnOutcome,
    List<string> Differs,
    string Child,
    string? SameAs,
    string SsaOutcome,
    string? SsaReason,
    string Repeat,
    string InProcess,
    int SitesTotal,
    int SitesKept,
    bool Truncated,
    bool MethodBudget,
    bool TimeBudget,
    bool TextBudget,
    int AssembliesLost,
    int MethodsLifted,
    Dictionary<string, int> ByStatus,
    Dictionary<string, int> NotJoinedReasons,
    Dictionary<string, int> UnknownKinds,
    int AnalyzedWithConstantArgument,
    Dictionary<string, int> ConstantSinks,
    int ReflectionSites,
    int TypeResolved,
    int MemberResolved,
    int WithCandidates,
    int CandidatesGap,
    long RecordChars,
    SsaObservedBounds Observed);

/// <summary>The largest values the facts of a folder reached, against <see cref="SsaFactBounds"/>; and ill-formed strings (none expected).</summary>
public sealed record SsaObservedBounds(int Arguments, int Alternatives, int ConstantChars, int Candidates, int SiteNameChars, int IllFormed)
{
    #region Methods
    public static SsaObservedBounds None { get; } = new(0, 0, 0, 0, 0, 0);

    public SsaObservedBounds Max(SsaObservedBounds other) => new(
        Math.Max(Arguments, other.Arguments), Math.Max(Alternatives, other.Alternatives), Math.Max(ConstantChars, other.ConstantChars),
        Math.Max(Candidates, other.Candidates), Math.Max(SiteNameChars, other.SiteNameChars), IllFormed + other.IllFormed);
    #endregion
}

/// <summary>
/// One package's <c>--ssa</c> result, cached in the results directory. The passes run off, on, repeat (on), then off
/// again, so a warm-up favours neither mode; <see cref="Off2Ms"/> is the last.
/// </summary>
public sealed record SsaPackageResult(
    string Package,
    string Identity,
    string Configuration,
    string JoinStatus,
    long JoinWallMs,
    long JoinPeakWorkingSet,
    SsaJoinPayload? Join,
    string WorkerStatus,
    long OffMs,
    long OnMs,
    long RepeatMs,
    long Off2Ms,
    long OffPeakWorkingSet,
    long OnPeakWorkingSet,
    long OnPeakPrivate,
    List<SsaFolderRow> Folders);

/// <summary>
/// <c>--ssa</c> (<c>docs/agent/tasks/ssa-facts-s4.md</c>, S4.5): per cached package, the <see cref="SsaJoinChild"/> and then
/// <see cref="PackageReachability.Analyze(NuGetPackage, PackageReachabilityOptions?)"/> through the real CLI worker beside
/// this harness, default options, with SSA off, on (<see cref="SsaFactBounds.Default"/>), and on again over a second
/// extraction. Each package's result is cached in the results directory and reused; the report is written once every
/// manifest entry has one. Package-controlled text is escaped and bounded before it is written.
/// </summary>
public static class SsaMeasure
{
    #region Properties
    /// <summary>The build configuration of this harness, and so of the worker and libraries beside it.</summary>
    public static string Configuration { get; } =
        typeof(SsaMeasure).Assembly.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration ?? "unknown";
    #endregion

    #region Methods
    /// <summary>
    /// Measures the packages without a result (at most <paramref name="maxPackages"/>, none started after
    /// <paramref name="maxTime"/>), then reports when all have one.
    /// </summary>
    public static (IReadOnlyList<string> Paths, int Pending, int NotCached, int Problems) Run(
        CorpusManifest manifest, string cacheRoot, string harness, TimeSpan childTimeout, string results, string outputDirectory,
        DateOnly date, string identity, int maxPackages, TimeSpan maxTime, TextWriter progress)
    {
        Directory.CreateDirectory(results);
        var done = new List<SsaPackageResult>();
        var (pending, notCached, measured) = (0, 0, 0);
        var clock = Stopwatch.StartNew();
        foreach (var (entry, number) in manifest.Entries.Select((e, i) => (e, i + 1)))
        {
            var name = $"{entry.Id} {entry.Version}";
            var path = Path.Combine(results, $"{entry.Id}.{entry.Version}.ssa.json");
            if (File.Exists(path))
            {
                var cached = JsonSerializer.Deserialize<SsaPackageResult>(File.ReadAllText(path), PackageReachResult.JsonOptions)!;
                if (cached.Identity != identity)
                    throw new InvalidOperationException($"{path} is from another build ({cached.Identity}, not {identity}); use another --results directory.");
                done.Add(cached);
                continue;
            }
            var nupkg = CachedNupkg.PathOf(cacheRoot, entry);
            if (!File.Exists(nupkg))
            {
                notCached++;
                continue;
            }
            if (measured >= maxPackages || clock.Elapsed >= maxTime)
            {
                pending++;
                continue;
            }

            progress.Write($"[{number}/{manifest.Entries.Count}] {name} ... ");
            var result = Measure(name, nupkg, harness, childTimeout, identity);
            PackageReachResult.WriteAtomically(path, JsonSerializer.Serialize(result, PackageReachResult.JsonOptions));
            done.Add(result);
            measured++;
            // The package's reports are garbage now; give the memory back before the next, so the guard sees one package's peak.
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            progress.WriteLine($"join {result.JoinStatus} {result.JoinWallMs} ms ({result.JoinPeakWorkingSet / (1024 * 1024)} MB); worker {result.WorkerStatus} " +
                $"off {result.OffMs} on {result.OnMs} repeat {result.RepeatMs} off {result.Off2Ms} ms; peak {result.OnPeakWorkingSet / (1024 * 1024)} MB; folders {result.Folders.Count}");
        }

        if (pending > 0 || notCached > 0)
            return ([], pending, notCached, 0);
        var (paths, problems) = SsaReport.Write(manifest, cacheRoot, results, outputDirectory, date, identity, done);
        return (paths, 0, 0, problems);
    }

    private static SsaPackageResult Measure(string name, string nupkg, string harness, TimeSpan childTimeout, string identity)
    {
        var (joinStatus, join, joinMs, joinPeak) = RunJoin(harness, nupkg, childTimeout);
        var off = Worker(nupkg, null);
        var on = Worker(nupkg, SsaFactBounds.Default);
        var repeat = Worker(nupkg, SsaFactBounds.Default);
        // Timed only: its report is not retained after the pass (it is live, with the other three, while the pass finishes).
        var off2 = Worker(nupkg, null, keep: false);
        var status = new[] { off.Status, on.Status, repeat.Status, off2.Status }.All(s => s == "ok") ? "ok" : $"{off.Status}/{on.Status}/{repeat.Status}/{off2.Status}";

        var rows = new List<SsaFolderRow>();
        var offFolders = off.Report?.Folders ?? [];
        var onFolders = on.Report?.Folders ?? [];
        var repeatFolders = repeat.Report?.Folders ?? [];
        var joined = (join?.Folders ?? []).GroupBy(f => f.Folder, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);
        for (var i = 0; i < Math.Max(offFolders.Count, onFolders.Count); i++)
        {
            var a = i < offFolders.Count ? offFolders[i] : null;
            var b = i < onFolders.Count ? onFolders[i] : null;
            var c = i < repeatFolders.Count ? repeatFolders[i] : null;
            rows.Add(Row(a, b, c, joined.GetValueOrDefault((a ?? b)!.Folder)));
        }
        return new SsaPackageResult(name, identity, Configuration, joinStatus, joinMs, joinPeak, join, status,
            off.WallMs, on.WallMs, repeat.WallMs, off2.WallMs, Math.Max(off.PeakWorkingSet, off2.PeakWorkingSet), Math.Max(on.PeakWorkingSet, repeat.PeakWorkingSet),
            Math.Max(on.PeakPrivate, repeat.PeakPrivate), rows);
    }

    private static SsaFolderRow Row(FolderReachability? off, FolderReachability? on, FolderReachability? repeat, SsaJoinFolder[]? join)
    {
        var differs = new List<string>();
        if (off is null || on is null)
            differs.Add("folder");
        else
        {
            if (off.Folder != on.Folder) differs.Add("folder");
            if (off.Outcome != on.Outcome) differs.Add("outcome");
            if (WorkerParity.Serialize(off.Report) != WorkerParity.Serialize(on.Report)) differs.Add("report");
            if (!off.Assemblies.SequenceEqual(on.Assemblies, StringComparer.Ordinal)) differs.Add("assemblies");
            if (!off.LoadFailures.SequenceEqual(on.LoadFailures)) differs.Add("load-failures");
            if (off.Reason != on.Reason) differs.Add("reason");
            if (off.SameAs != on.SameAs) differs.Add("same-as");
            if (off.Nodes != on.Nodes || off.Edges != on.Edges) differs.Add("size");
            if (off.Ssa is not null) differs.Add("ssa-when-off");
        }

        // The child builds every folder itself, a SameAs copy included: the worker's graph must be there exactly when the
        // child's is, the same size, so a worker that never analyses anything cannot pass as additive.
        var child = off is null || join is not [var mine, ..] ? "n/a"
            : mine.Built == (off.Outcome == FolderOutcome.Analyzed) && mine.Nodes == off.Nodes && mine.Edges == off.Edges ? "equal"
            : "differs";

        var ssa = on?.Ssa;
        var facts = ssa?.Facts;
        var again = repeat?.Ssa;
        var cut = facts?.TimeBudget == true || again?.Facts?.TimeBudget == true
            || ssa?.Outcome == SsaFolderOutcome.TimedOut || again?.Outcome == SsaFolderOutcome.TimedOut;
        var repeatState = ssa is null || again is null || (facts is null && again.Facts is null && ssa.Outcome == again.Outcome) ? "n/a"
            : repeat!.Folder != on!.Folder ? "differs"
            : cut ? "cut"
            : ssa.Outcome == again.Outcome && ssa.Reason == again.Reason && SsaJoinChild.Digest(facts) == SsaJoinChild.Digest(again.Facts) ? "equal"
            : "differs";
        var inProcess = facts is null || join is not [var own, ..] ? "n/a"
            : facts.TimeBudget || facts.MethodBudget || own.FactsCut ? "cut"
            : own.FactsDigest is null && facts.SitesTotal == 0 ? "equal"
            : own.FactsDigest == SsaJoinChild.Digest(facts) ? "equal" : "differs";

        var sites = facts?.Sites ?? [];
        var analyzed = sites.Where(s => s.Status == SsaSiteStatus.Analyzed).ToArray();
        static bool Constant(SsaValue v) => v.Kind is SsaValueKind.Constant or SsaValueKind.OneOf;
        var withConstant = analyzed.Where(s => s.Arguments.Any(Constant)).ToArray();
        var targets = analyzed.Select(s => s.Target).OfType<SsaReflectionTarget>().ToArray();
        return new SsaFolderRow(
            (off ?? on)!.Folder, off?.Outcome.ToString() ?? "missing", on?.Outcome.ToString() ?? "missing", differs, child, on?.SameAs,
            ssa?.Outcome.ToString() ?? "none", ssa?.Reason is { } reason ? Program.Redact(reason) : null, repeatState, inProcess,
            facts?.SitesTotal ?? 0, sites.Count, facts?.Truncated ?? false, facts?.MethodBudget ?? false, facts?.TimeBudget ?? false,
            facts?.TextBudget ?? false, facts?.AssembliesLost ?? 0, facts?.MethodsLifted ?? 0,
            Counts(sites.Select(s => s.Status.ToString())),
            Counts(sites.Where(s => s.Status == SsaSiteStatus.NotJoined).Select(s => s.Reason ?? "?")),
            Counts(facts?.Unknown.SelectMany(u => Enumerable.Repeat(u.Kind.ToString(), u.Methods)) ?? []),
            withConstant.Length,
            Counts(withConstant.Select(s => $"{s.Site.Capability}\t{s.Site.CalleeKey}")),
            targets.Length,
            targets.Count(t => Constant(t.Type)),
            targets.Count(t => t.Member is { } m && Constant(m)),
            targets.Count(t => t.Candidates.Count > 0),
            targets.Count(t => t.CandidatesGap is not null),
            facts is null ? 0 : JsonSerializer.Serialize(facts, SsaJoinChild.FactsOptions).Length,
            facts is null ? SsaObservedBounds.None : Observe(facts));
    }

    // The largest argument count, OneOf width, constant text, candidate list and site name, and the ill-formed strings.
    private static SsaObservedBounds Observe(SsaFolderFacts facts)
    {
        var values = facts.Sites.SelectMany(s => s.Arguments.Concat(new[] { s.Receiver, s.Target?.Type, s.Target?.Member, s.Target?.Assembly }.OfType<SsaValue>())).ToArray();
        var texts = values.SelectMany(v => v.Constants.Select(c => c.Text))
            .Concat(facts.Sites.SelectMany(s => new[] { s.Site.NodeId, s.Site.Callee, s.Site.CalleeKey, s.Reason ?? "" }))
            .Concat(facts.Sites.SelectMany(s => s.Target?.Candidates ?? []));
        return new SsaObservedBounds(
            facts.Sites.Select(s => s.Arguments.Count).DefaultIfEmpty().Max(),
            values.Select(v => v.Constants.Count).DefaultIfEmpty().Max(),
            values.SelectMany(v => v.Constants).Select(c => c.Text.Length).DefaultIfEmpty().Max(),
            facts.Sites.Select(s => s.Target?.Candidates.Count ?? 0).DefaultIfEmpty().Max(),
            facts.Sites.SelectMany(s => new[] { s.Site.NodeId.Length, s.Site.Callee.Length, s.Site.CalleeKey.Length }).DefaultIfEmpty().Max(),
            texts.Count(t => !WellFormed(t)));
    }

    private static bool WellFormed(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                i++;
            else if (char.IsSurrogate(text[i]))
                return false;
        }
        return true;
    }

    private static Dictionary<string, int> Counts(IEnumerable<string> keys) =>
        keys.GroupBy(k => k, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

    // The join child, bounded by `timeout`, with its peak working set (as the OS keeps it, read while it lives).
    private static (string Status, SsaJoinPayload? Payload, long WallMs, long PeakWorkingSet) RunJoin(string harness, string nupkg, TimeSpan timeout)
    {
        var (status, payload, wall) = RunJoin(harness, nupkg, timeout, out var peak);
        return (status, payload, wall, peak);
    }

    private static (string Status, SsaJoinPayload? Payload, long WallMs) RunJoin(string harness, string nupkg, TimeSpan timeout, out long peak)
    {
        peak = 0;
        var payloadPath = Path.Combine(Path.GetTempPath(), $"silvergun-ssa-join-{Guid.NewGuid():N}.json");
        var psi = new ProcessStartInfo(harness)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(SsaJoinChild.Verb);
        psi.ArgumentList.Add(nupkg);
        psi.ArgumentList.Add(payloadPath);

        var clock = Stopwatch.StartNew();
        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start '{harness}'.");
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            var limit = ReachabilityChildRunner.TimeoutMilliseconds(timeout);
            while (!process.WaitForExit(100))
            {
                try
                {
                    process.Refresh();
                    peak = Math.Max(peak, process.PeakWorkingSet64);
                }
                catch (InvalidOperationException)
                {
                    // Exited between the wait and the read.
                }
                if (clock.ElapsedMilliseconds < limit)
                    continue;
                try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                process.WaitForExit(10_000);
                ReachabilityChildRunner.RemoveExtraction(stderr.Wait(10_000) ? stderr.Result : string.Empty);
                return ("timeout", null, clock.ElapsedMilliseconds);
            }
            var wallMs = clock.ElapsedMilliseconds;
            var errors = stderr.GetAwaiter().GetResult();
            if (process.ExitCode != 0)
            {
                ReachabilityChildRunner.RemoveExtraction(errors);
                var why = errors.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("FAILED", StringComparison.Ordinal)) ?? "";
                return ($"crashed:{process.ExitCode} {Program.Redact(why)}", null, wallMs);
            }
            if (!stdout.GetAwaiter().GetResult().Split('\n').Select(l => l.TrimEnd('\r')).Contains("DONE") || !File.Exists(payloadPath))
                return ("incomplete", null, wallMs);
            return ("ok", JsonSerializer.Deserialize<SsaJoinPayload>(File.ReadAllText(payloadPath), PackageReachResult.JsonOptions), wallMs);
        }
        catch (JsonException)
        {
            return ("unreadable", null, clock.ElapsedMilliseconds);
        }
        finally
        {
            File.Delete(payloadPath);
        }
    }

    // One worker pass over a fresh extraction, with the workers' peak memory sampled.
    private static (string Status, PackageReachabilityReport? Report, long WallMs, long PeakWorkingSet, long PeakPrivate) Worker(string nupkg, SsaFactBounds? ssa, bool keep = true)
    {
        var opened = NuGetPackage.Open(nupkg);
        if (!opened.IsSuccess)
            return ("open-failed", null, 0, 0, 0);
        using var package = opened.Value;
        using var sampler = new WorkerSampler();
        var clock = Stopwatch.StartNew();
        var report = PackageReachability.Analyze(package, PackageReachabilityOptions.Default with { Ssa = ssa });
        var wall = clock.ElapsedMilliseconds;
        sampler.Stop();
        return ("ok", keep ? report : null, wall, sampler.PeakWorkingSet, sampler.PeakPrivate);
    }
    #endregion

    #region Child types
    /// <summary>
    /// Samples every <c>Silvergun.CLI</c> process this harness started (its parent is this process) after it, every 50 ms:
    /// the OS's own peak working set and peak pagefile-backed (private) bytes, so a peak between samples is still seen
    /// while the process lives. Windows only; elsewhere both stay 0.
    /// </summary>
    private sealed class WorkerSampler : IDisposable
    {
        #region Constructors
        public WorkerSampler()
        {
            started = DateTime.Now.AddSeconds(-1);
            thread = new Thread(Loop) { IsBackground = true, Name = "worker-sampler" };
            thread.Start();
        }
        #endregion

        #region Properties
        public long PeakWorkingSet { get; private set; }

        public long PeakPrivate { get; private set; }
        #endregion

        #region Methods
        public void Stop()
        {
            stop.Set();
            thread.Join();
        }

        public void Dispose()
        {
            if (!stop.IsSet)
                Stop();
            stop.Dispose();
        }

        private void Loop()
        {
            do
            {
                foreach (var process in Process.GetProcessesByName("Silvergun.CLI"))
                {
                    using (process)
                    {
                        try
                        {
                            if (!OperatingSystem.IsWindows() || process.StartTime < started || ParentOf(process) != Environment.ProcessId)
                                continue;
                            PeakWorkingSet = Math.Max(PeakWorkingSet, process.PeakWorkingSet64);
                            PeakPrivate = Math.Max(PeakPrivate, process.PeakPagedMemorySize64);
                        }
                        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                        {
                            // Exited between the listing and the read.
                        }
                    }
                }
            }
            while (!stop.Wait(50));
        }

        // The process id of the process that started `process`, or -1.
        private static int ParentOf(Process process)
        {
            var info = default(ProcessBasicInformation);
            return NtQueryInformationProcess(process.Handle, 0, ref info, Marshal.SizeOf<ProcessBasicInformation>(), out _) == 0
                ? (int)info.InheritedFromUniqueProcessId : -1;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr process, int informationClass, ref ProcessBasicInformation information, int length, out int returned);
        #endregion

        #region Fields
        private readonly DateTime started;
        private readonly Thread thread;
        private readonly ManualResetEventSlim stop = new(false);
        #endregion

        #region Child types
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessBasicInformation
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }
        #endregion
    }
    #endregion
}
