namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>What became of one package folder's graph pass (<see cref="PackageReachability"/>).</summary>
public enum FolderOutcome
{
    /// <summary>The graph was built and analysed; the report says whether it is truncated or partial.</summary>
    Analyzed,

    /// <summary>No assembly of the folder loaded; <see cref="FolderReachability.LoadFailures"/> says why.</summary>
    NothingLoaded,

    /// <summary>
    /// The worker died or broke protocol while on this folder (ADR 0021: unanalyzable, and suspect). The reason names
    /// the exit code.
    /// </summary>
    Crashed,

    /// <summary>The folder timeout, or the package budget, ran out while the worker was on this folder.</summary>
    TimedOut,

    /// <summary>
    /// Never started, or its record was not kept: the package budget was spent, the folder cap or the record byte limit
    /// (<see cref="PackageReachabilityOptions.MaxReportBytes"/>) was reached, or no worker could start.
    /// </summary>
    NotRun,
}

/// <summary>
/// One package folder's graph pass. <see cref="Assemblies"/> are the assemblies loaded into its graph (for an outcome
/// other than <see cref="FolderOutcome.Analyzed"/> or <see cref="FolderOutcome.NothingLoaded"/>, the folder's assemblies,
/// none of them analysed), <see cref="LoadFailures"/> the ones that did not load. <see cref="Report"/> is present exactly
/// when the outcome is <see cref="FolderOutcome.Analyzed"/>; <see cref="Reason"/> exactly when it is Crashed, TimedOut or
/// NotRun. <see cref="SameAs"/> names the folder whose identical files were built for this one. <see cref="Nodes"/> and
/// <see cref="Edges"/> are the graph's size, 0 without one.
/// </summary>
public sealed record FolderReachability(
    string Folder,
    IReadOnlyList<string> Assemblies,
    IReadOnlyList<PackageGraphLoadFailure> LoadFailures,
    FolderOutcome Outcome,
    ReachabilityReport? Report,
    string? Reason,
    string? SameAs,
    int Nodes,
    int Edges);

/// <summary>Every folder of one package that holds assemblies, in <see cref="PackageGraphs"/>' order.</summary>
public sealed record PackageReachabilityReport(IReadOnlyList<FolderReachability> Folders);

/// <summary>
/// The limits of one package's graph pass (<c>docs/agent/tasks/graph-worker.md</c>, G3). <see cref="FolderTimeout"/> is
/// what one folder may take; <see cref="PackageBudget"/> what every folder together may take, across worker restarts;
/// <see cref="MaxFolders"/> how many distinct folders are built at all; <see cref="WorkerMemoryBytes"/> each worker
/// process's memory limit (0 for none); <see cref="Graph"/> each folder's graph budget; <see cref="MaxReportBytes"/>
/// how many bytes of folder records one package's pass keeps (a caller holding several packages' reports holds that
/// many). A negative time is zero. A run can outlast <see cref="PackageBudget"/> by its fixed ending waits (for
/// <c>done</c>, the exit, a kill), about 17 s at most per worker.
/// </summary>
public sealed record PackageReachabilityOptions(
    TimeSpan FolderTimeout,
    TimeSpan PackageBudget,
    int MaxFolders,
    long WorkerMemoryBytes,
    GraphBudget Graph)
{
    #region Properties
    /// <summary>
    /// 120 s per folder, 600 s per package, 256 folders, 4 GiB per worker, <see cref="GraphBudget.Default"/>, 128 MiB of
    /// folder records.
    /// </summary>
    public static PackageReachabilityOptions Default { get; } =
        new(TimeSpan.FromSeconds(120), TimeSpan.FromSeconds(600), 256, 4L * 1024 * 1024 * 1024, GraphBudget.Default);

    /// <summary>
    /// The most line bytes of folder records accepted from workers over the whole package (0 or less for no limit): each
    /// record is bounded by <see cref="GraphWorkerProtocol.MaxRecordLineBytes"/>, but names in a report are not, so without
    /// this a package of many distinct folders could fill this process (review round 2, W-A). Parsed, a record takes about
    /// twice its line in memory. The folder whose record would pass it, and every folder after it, is NotRun.
    /// </summary>
    public long MaxReportBytes { get; init; } = 128L * 1024 * 1024;
    #endregion
}

/// <summary>
/// Capability reachability over every folder of a package, built in worker processes (ADR 0021 Tier 2 for the graph
/// pass; <c>docs/agent/tasks/graph-worker.md</c>). The folders are <see cref="PackageGraphs"/>' folders, in its order;
/// one worker takes them in turn and answers each with its <see cref="Reachability"/> report. A worker that dies, hangs
/// or breaks protocol costs the folder it was on (<see cref="FolderOutcome.Crashed"/> or
/// <see cref="FolderOutcome.TimedOut"/>), and a new worker takes the folders after it, within the package budget.
/// <para>
/// Folders whose ordered (file name, SHA-256) lists are equal are built once and share the result, with their own paths:
/// a report depends on the files' bytes, not where they lie, so one budget-maxing DLL copied into many folders costs one
/// build. A folder that could not be analysed never reads as clean: it carries its outcome and reason, and no report.
/// The worker is never replaced by in-process analysis. Never throws.
/// </para>
/// </summary>
public static class PackageReachability
{
    #region Methods
    /// <summary>The graph pass over <paramref name="package"/>'s folders, within <paramref name="options"/> (default <see cref="PackageReachabilityOptions.Default"/>).</summary>
    public static PackageReachabilityReport Analyze(NuGetPackage package, PackageReachabilityOptions? options = null) =>
        Analyze(package.Assemblies, options);

    /// <summary>The graph pass over the folders <paramref name="assemblies"/> lie in.</summary>
    public static PackageReachabilityReport Analyze(IEnumerable<PackageAssembly> assemblies, PackageReachabilityOptions? options = null)
    {
        var settings = options ?? PackageReachabilityOptions.Default;
        return Analyze(assemblies, settings, GraphWorkerLaunch.Cli(settings.WorkerMemoryBytes));
    }

    /// <summary>The graph pass with workers started by <paramref name="launch"/>.</summary>
    internal static PackageReachabilityReport Analyze(IEnumerable<PackageAssembly> assemblies, PackageReachabilityOptions options, GraphWorkerLaunch launch)
    {
        var folders = PackageGraphs.Folders(assemblies);
        var results = new FolderReachability?[folders.Count];
        try
        {
            // Each folder is either a primary (built), a copy of an earlier primary, or not run.
            var primaries = new List<int>();
            var copyOf = new Dictionary<int, int>();
            var byContent = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < folders.Count; i++)
            {
                var (folder, members) = folders[i];
                var key = ContentKey(members);
                if (Unsendable(members) is { } why)
                    results[i] = NotRun(folder, members, why);
                else if (key is not null && byContent.TryGetValue(key, out var first))
                    copyOf[i] = first;
                else if (primaries.Count >= options.MaxFolders)
                    results[i] = NotRun(folder, members, $"the package has more than {options.MaxFolders} distinct folders with assemblies; only the first {options.MaxFolders} are built");
                else
                {
                    primaries.Add(i);
                    if (key is not null)
                        byContent[key] = i;
                }
            }

            Build(folders, primaries, results, options, launch);
            foreach (var (copy, first) in copyOf)
                results[copy] = Copy(results[first]!, folders[first].Members, folders[copy]);
            return new([.. results.Select(r => r!)]);
        }
        catch (Exception ex)
        {
            // Never throws: a failure here is a bug in this class, and every folder not yet decided is reported unrun.
            Runtime.Warn("Graph pass over the package failed: {0}", WorkerProtocol.Safe(ex.Message, 300));
            return new([.. folders.Select((f, i) => results[i] ?? NotRun(f.Folder, f.Members, $"the graph pass failed: {ex.GetType().Name}: {ex.Message}"))]);
        }
    }

    // Runs workers over the primary folders in order: a failed run blames the folder in flight and a new worker takes the
    // ones after it, until all are answered, the budget is spent, or a worker cannot start.
    private static void Build(IReadOnlyList<(string Folder, PackageAssembly[] Members)> folders, List<int> primaries, FolderReachability?[] results, PackageReachabilityOptions options, GraphWorkerLaunch launch)
    {
        // A budget too large to be a timestamp offset is no deadline at all.
        var deadline = options.PackageBudget >= MaxBudget ? long.MaxValue
            : Stopwatch.GetTimestamp() + (long)(Math.Max(0, options.PackageBudget.TotalSeconds) * Stopwatch.Frequency);
        var budget = GraphWorkerBudget.Of(options.Graph);
        var reportBytesLeft = options.MaxReportBytes > 0 ? options.MaxReportBytes : long.MaxValue;
        var pending = primaries;
        while (pending.Count > 0)
        {
            if (Stopwatch.GetTimestamp() >= deadline)
            {
                Unrun(folders, pending, results, $"the package budget of {options.PackageBudget.TotalSeconds:0} s was spent before it was started");
                return;
            }

            var request = new GraphWorkerRequest(GraphWorkerProtocol.Version, budget,
                [.. pending.Select(i => new GraphWorkerFolderRequest(folders[i].Folder, [.. folders[i].Members.Select(m => new GraphWorkerAssembly(m.RelativePath, m.FullPath))]))]);
            var run = GraphWorkerProcess.Run(launch, request, options.FolderTimeout > TimeSpan.Zero ? options.FolderTimeout : TimeSpan.Zero, deadline, reportBytesLeft);
            reportBytesLeft -= run.AnsweredBytes;
            for (var k = 0; k < run.Answered.Count; k++)
                results[pending[k]] = Answered(run.Answered[k]);

            switch (run.Failure)
            {
                case null:
                    return;
                case GraphWorkerFailureKind.AfterAll:
                    // Every folder's record was received and checked; only the child's ending was wrong.
                    Runtime.Warn("Graph worker: {0}; its {1} folder record(s) are kept.", run.Reason!, run.Answered.Count);
                    return;
                case GraphWorkerFailureKind.NotStarted:
                    Unrun(folders, pending.Skip(run.Answered.Count), results, $"the graph worker could not run: {run.Reason}");
                    return;
                case GraphWorkerFailureKind.ReportsSpent:
                    // The record was built but not kept: the folder was not analysed here, and neither is any after it. The
                    // run only knew the bytes left, so the reason names the package's limit here.
                    var full = pending[run.Answered.Count];
                    var over = $"its record would take the package's folder records over {options.MaxReportBytes} bytes, so it was not kept";
                    results[full] = NotRun(folders[full].Folder, folders[full].Members, over);
                    Runtime.Warn("Graph worker: folder {0}: {1}", WorkerProtocol.Safe(folders[full].Folder, 200), over);
                    Unrun(folders, pending.Skip(run.Answered.Count + 1), results, $"the package's folder records reached their limit of {options.MaxReportBytes} bytes before it was started");
                    return;
                default:
                    var blamed = pending[run.Answered.Count];
                    var outcome = run.Failure == GraphWorkerFailureKind.Crashed ? FolderOutcome.Crashed : FolderOutcome.TimedOut;
                    results[blamed] = Failed(folders[blamed].Folder, folders[blamed].Members, outcome, run.Reason!);
                    Runtime.Warn("Graph worker: folder {0} is {1}: {2}", WorkerProtocol.Safe(folders[blamed].Folder, 200), outcome, run.Reason!);
                    pending = [.. pending.Skip(run.Answered.Count + 1)];
                    if (run.Failure == GraphWorkerFailureKind.BudgetSpent)
                    {
                        Unrun(folders, pending, results, $"the package budget of {options.PackageBudget.TotalSeconds:0} s was spent before it was started");
                        return;
                    }
                    break;
            }
        }
    }

    // A folder record as a result: Analyzed with its report, or NothingLoaded.
    private static FolderReachability Answered(GraphWorkerFolder record) =>
        new(record.Folder, record.Assemblies, record.LoadFailures,
            record.Report is null ? FolderOutcome.NothingLoaded : FolderOutcome.Analyzed, record.Report, null, null, record.Nodes, record.Edges);

    // A copy of `first`'s result for `copy`, whose members have the same file names in the same order: every path is
    // mapped to the copy's own, in the reasons too (they name assemblies by package path, review W3). One pass, longest
    // path first at each position, so a replacement is never rewritten again (review round 2, N1).
    private static FolderReachability Copy(FolderReachability first, PackageAssembly[] firstMembers, (string Folder, PackageAssembly[] Members) copy)
    {
        var map = firstMembers.Select(m => m.RelativePath).Zip(copy.Members.Select(m => m.RelativePath)).ToDictionary(p => p.First, p => p.Second, StringComparer.Ordinal);
        var paths = new Regex(string.Join("|", map.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape)), RegexOptions.CultureInvariant);
        string Remap(string text) => paths.Replace(text, m => map[m.Value]);
        return first with
        {
            Folder = copy.Folder,
            Assemblies = [.. first.Assemblies.Select(a => map.GetValueOrDefault(a, a))],
            LoadFailures = [.. first.LoadFailures.Select(f => new PackageGraphLoadFailure(map.GetValueOrDefault(f.RelativePath, f.RelativePath), Remap(f.Reason)))],
            Reason = first.Reason is null ? null : Remap(first.Reason),
            SameAs = first.SameAs ?? first.Folder,
        };
    }

    // The ordered (file name, SHA-256) list of a folder's members, or null when a hash is missing (no sharing then).
    private static string? ContentKey(PackageAssembly[] members) =>
        members.Any(m => string.IsNullOrEmpty(m.Sha256)) ? null
        : string.Join("\n", members.Select(m => Path.GetFileName(m.RelativePath) + "\t" + m.Sha256));

    // Why a folder cannot go on the wire, or null: every path must be absolute and well-formed UTF-16.
    private static string? Unsendable(PackageAssembly[] members) =>
        members.Any(m => !Path.IsPathFullyQualified(m.FullPath)) ? "an assembly of the folder has no absolute path on disk"
        : members.Any(m => !WorkerProtocol.IsWellFormedUtf16(m.FullPath) || !WorkerProtocol.IsWellFormedUtf16(m.RelativePath))
            ? "an assembly path of the folder is not well-formed UTF-16, so it cannot be sent to the graph worker"
        : null;

    private static void Unrun(IReadOnlyList<(string Folder, PackageAssembly[] Members)> folders, IEnumerable<int> which, FolderReachability?[] results, string reason)
    {
        foreach (var i in which)
            results[i] = NotRun(folders[i].Folder, folders[i].Members, reason);
    }

    private static FolderReachability NotRun(string folder, PackageAssembly[] members, string reason) =>
        Failed(folder, members, FolderOutcome.NotRun, reason);

    private static FolderReachability Failed(string folder, PackageAssembly[] members, FolderOutcome outcome, string reason) =>
        new(folder, [.. members.Select(m => m.RelativePath)], [], outcome, null, reason, null, 0, 0);
    #endregion

    #region Fields
    private static readonly TimeSpan MaxBudget = TimeSpan.FromDays(365);
    #endregion
}
