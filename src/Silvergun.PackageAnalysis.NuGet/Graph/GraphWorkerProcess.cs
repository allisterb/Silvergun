namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>How to start a graph worker: the executable (or why there is none), its arguments, and its memory limit.</summary>
internal sealed record GraphWorkerLaunch(string? Executable, string? Problem, IReadOnlyList<string> Arguments, long MemoryLimitBytes)
{
    #region Methods
    /// <summary>
    /// The production launch: the Silvergun CLI apphost (this process's own executable when it is that apphost, else the
    /// one in the application directory; never PATH, never <c>dotnet</c>) with <see cref="GraphWorkerProtocol.Arguments"/>.
    /// The rule is the YARA worker's (ADR 0033 amendment (o)); that class is Windows-only, this one is not.
    /// </summary>
    internal static GraphWorkerLaunch Cli(long memoryLimitBytes)
    {
        var (path, problem) = Resolve(Environment.ProcessPath, AppContext.BaseDirectory);
        return new(path, problem, GraphWorkerProtocol.Arguments, memoryLimitBytes);
    }

    /// <summary>The worker executable from <paramref name="processPath"/> and <paramref name="baseDirectory"/>, or why there is none.</summary>
    internal static (string? Path, string? Problem) Resolve(string? processPath, string? baseDirectory)
    {
        if (processPath is not null && Path.IsPathFullyQualified(processPath)
            && string.Equals(Path.GetFileName(processPath), CliApphost, StringComparison.OrdinalIgnoreCase))
            return (processPath, null);

        var beside = baseDirectory is not null && Path.IsPathFullyQualified(baseDirectory) ? Path.Combine(baseDirectory, CliApphost) : null;
        return beside is not null && File.Exists(beside)
            ? (beside, null)
            : (null, $"there is no graph worker executable: this process is not the Silvergun CLI apphost at an absolute path, and there is no {CliApphost} in '{WorkerProtocol.Safe(baseDirectory, 200)}'");
    }
    #endregion

    #region Fields
    private static readonly string CliApphost = OperatingSystem.IsWindows() ? "Silvergun.CLI.exe" : "Silvergun.CLI";
    #endregion
}

/// <summary>
/// One graph worker child over one request (<c>docs/agent/tasks/graph-worker.md</c>, G2 and G3). It starts the child,
/// contains it (a kill-on-close Job Object with a per-process memory limit on Windows; a GC heap hard limit everywhere),
/// sends the request and reads the answers under bounded clocks, checking each record against the request. Never throws
/// for anything the child does; the child is dead or has exited when <see cref="Run"/> returns.
/// </summary>
internal static class GraphWorkerProcess
{
    #region Properties
    // How every `fatal` record's line begins.
    private static ReadOnlySpan<byte> FatalPrefix => "{\"type\":\"fatal\""u8;
    #endregion

    #region Methods
    /// <summary>
    /// Runs one child over <paramref name="request"/>. Each folder gets <paramref name="folderTimeout"/> from the record
    /// before it, but never past <paramref name="deadline"/> (a <see cref="Stopwatch"/> timestamp, the package budget).
    /// Folder records are accepted while their line bytes total at most <paramref name="maxReportBytes"/>. When the request
    /// asks for SSA, each folder's ssa record gets <paramref name="folderTimeout"/> from its folder record, never past
    /// <paramref name="ssaDeadline"/>, and is accepted while ssa line bytes total at most <paramref name="maxSsaBytes"/>: SSA
    /// spends budgets of its own, and <paramref name="deadline"/> moves back by the time it takes
    /// (<see cref="GraphWorkerRun.SsaTicks"/>), so it never costs a graph. A run that an SSA failure forced (decided at
    /// <paramref name="restartedFrom"/>, a <see cref="Stopwatch"/> timestamp; 0 for none) waits for <c>ready</c> up to
    /// <see cref="ReadyTimeout"/> whatever <paramref name="deadline"/> says, and counts the time from that failure to its
    /// <c>ready</c> as SSA's.
    /// </summary>
    internal static GraphWorkerRun Run(GraphWorkerLaunch launch, GraphWorkerRequest request, TimeSpan folderTimeout, long deadline, long maxReportBytes = long.MaxValue,
        long ssaDeadline = long.MaxValue, long maxSsaBytes = long.MaxValue, long restartedFrom = 0)
    {
        if (launch.Executable is null || !Path.IsPathFullyQualified(launch.Executable))
            return GraphWorkerRun.NotStarted(launch.Problem ?? "the graph worker executable's path is unknown or not absolute");

        using var process = new Process { StartInfo = StartInfo(launch) };
        try
        {
            if (!process.Start())
                return GraphWorkerRun.NotStarted("the graph worker process did not start");
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or PlatformNotSupportedException)
        {
            return GraphWorkerRun.NotStarted($"the graph worker process could not be started ({Describe(ex)})");
        }

        var job = Contain(process, launch.MemoryLimitBytes, out var uncontained);
        using var stop = new CancellationTokenSource();
        // At most two records wait to be read (review C1): a child that floods after `done`, or while a record is parsed,
        // blocks in its own write instead of filling the parent's memory. The pump reads no more lines than the protocol
        // has (ready, the folder and ssa records, done), and a cancelled token frees it from a blocked Add.
        using var lines = new BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)>(boundedCapacity: 2);
        Task[] background = [];
        try
        {
            if (uncontained is not null)
            {
                Kill(process);
                return GraphWorkerRun.NotStarted(uncontained);
            }

            // One ready clock from the start (review round 2, N6): reading the request and sending `ready` share it.
            var readyBound = Bound(ReadyTimeout, restartedFrom != 0 ? long.MaxValue : deadline);
            var readyBy = Stopwatch.GetTimestamp() + (long)(readyBound.TotalSeconds * Stopwatch.Frequency);
            var sending = Background(() => Send(process, request));
            background =
            [
                sending,
                Background(() => RelayStderr(process.StandardError.BaseStream)),
                Background(() => Pump(new WorkerLineReader(process.StandardOutput.BaseStream, GraphWorkerProtocol.MaxRecordLineBytes), lines,
                    request.Folders.Count * (request.Ssa is null ? 1 : 2) + 2, stop.Token)),
            ];
            // The request is written off this thread (review W2): a child that never reads stdin would otherwise block the
            // write forever once the request outgrows the pipe's buffer.
            return !sending.Wait(readyBound) ? GraphWorkerRun.NotStarted($"the graph worker did not read its request within {Seconds(readyBound)} s")
                : sending.Result is { } unsent ? GraphWorkerRun.NotStarted(unsent)
                : Read(process, request, lines, folderTimeout, deadline, readyBound, readyBy, maxReportBytes, ssaDeadline, maxSsaBytes, restartedFrom);
        }
        finally
        {
            Kill(process);
            stop.Cancel();
            CloseInput(process);
            WaitQuietly(background, DrainTimeout);
            job?.Dispose();
        }
    }

    // The read loop: ready, one folder record per request folder in order (each followed by its ssa record when the request
    // asks for SSA), done, a prompt exit. Every wait is bounded.
    private static GraphWorkerRun Read(Process process, GraphWorkerRequest request, BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)> lines,
        TimeSpan folderTimeout, long deadline, TimeSpan readyBound, long readyBy, long maxReportBytes, long ssaDeadline, long maxSsaBytes, long restartedFrom)
    {
        var answered = new List<GraphWorkerFolder>();
        var ssa = new List<GraphWorkerSsa>();
        long used = 0, ssaUsed = 0, ssaTicks = 0;
        if (Next(lines, readyBound, readyBy) is not { } first)
            return GraphWorkerRun.NotStarted($"the graph worker sent no 'ready' within {Seconds(readyBound)} s");
        if (ReadyProblem(Parse(first), request) is { } notReady)
            return GraphWorkerRun.NotStarted($"the graph worker did not start: {notReady}{ExitNote(process)}");
        var readyAt = Stopwatch.GetTimestamp();
        // A restart an SSA failure forced: from that failure to this `ready` (the kill, the drain, the spawn) is SSA's time.
        if (restartedFrom != 0 && readyAt > restartedFrom)
        {
            ssaTicks += readyAt - restartedFrom;
            deadline = Later(deadline, readyAt - restartedFrom);
        }

        while (answered.Count < request.Folders.Count)
        {
            var i = answered.Count;
            var budgetLeft = Remaining(deadline);
            if (Next(lines, folderTimeout, deadline) is not { } line)
                return budgetLeft <= folderTimeout
                    ? Stop(GraphWorkerFailureKind.BudgetSpent, "the package budget ran out while it was being built, so the worker was killed")
                    : Stop(GraphWorkerFailureKind.TimedOut, $"it was not built within {Seconds(folderTimeout)} s, so the worker was killed");
            if (line.Status != WorkerLineStatus.Line)
                return Stop(GraphWorkerFailureKind.Crashed, $"the graph worker stopped while building it: {Ending(line.Status)}{ExitNote(process)}");
            // Checked before parsing, which roughly doubles a record's size in memory (review round 2, W-A). A `fatal` is
            // not kept, so it is exempt: a package cannot turn its Crashed folder into NotRun by spending the limit first.
            // The discriminator must come first (GraphWorkerJsonContext), so the prefix is exact.
            if (!line.Bytes.AsSpan().StartsWith(FatalPrefix) && line.Bytes.Length > maxReportBytes - used)
                return Stop(GraphWorkerFailureKind.ReportsSpent, $"its record would take this run's folder records over {maxReportBytes} bytes, so it was not kept");
            var (message, problem) = Parse(line);
            if (message is GraphWorkerFatal fatal)
                return Stop(GraphWorkerFailureKind.Crashed, $"the graph worker failed while building it: {WorkerProtocol.Safe(fatal.Reason, ReasonChars)}");
            if ((problem ?? Mismatch(message, i, request.Folders[i])) is { } wrong)
                return Stop(GraphWorkerFailureKind.Crashed, $"the graph worker's record for it broke protocol v{GraphWorkerProtocol.Version}: {wrong}");
            answered.Add((GraphWorkerFolder)message!);
            used += line.Bytes.Length;
            if (request.Ssa is null)
                continue;
            // The SSA phase's time is its own: the graph's deadline moves back by it.
            var phase = Stopwatch.GetTimestamp();
            var failed = ReadSsa(i);
            var spent = Stopwatch.GetTimestamp() - phase;
            ssaTicks += spent;
            deadline = Later(deadline, spent);
            if (failed is not null)
                return failed with { SsaTicks = ssaTicks };
        }

        if (Next(lines, ExitTimeout, long.MaxValue) is not { Status: WorkerLineStatus.Line } last
            || Parse(last) is not (GraphWorkerDone done, _) || done.Count != request.Folders.Count)
            return Stop(GraphWorkerFailureKind.AfterAll, "the graph worker did not end with a valid 'done'");
        return !process.WaitForExit(ExitTimeout) ? Stop(GraphWorkerFailureKind.AfterAll, $"the graph worker did not exit within {Seconds(ExitTimeout)} s of 'done'")
            : process.ExitCode != GraphWorkerProtocol.ExitDone ? Stop(GraphWorkerFailureKind.AfterAll, $"the graph worker exited with {DescribeExit(process.ExitCode)} after 'done'")
            : GraphWorkerRun.Complete(answered) with { Ssa = ssa, AnsweredBytes = used, SsaBytes = ssaUsed, SsaTicks = ssaTicks, ReadyAt = readyAt };

        // Folder i's ssa record, on a folder timeout of its own from its folder record and within SSA's own budgets; null
        // once it is accepted. A failure here costs folder i's SSA only: its graph record stands.
        GraphWorkerRun? ReadSsa(int i)
        {
            var budgetLeft = Remaining(ssaDeadline);
            if (Next(lines, folderTimeout, ssaDeadline) is not { } line)
                return budgetLeft <= folderTimeout
                    ? StopSsa(GraphWorkerFailureKind.BudgetSpent, "the package's SSA budget ran out while its SSA facts were being extracted, so the worker was killed")
                    : StopSsa(GraphWorkerFailureKind.TimedOut, $"its SSA facts were not extracted within {Seconds(folderTimeout)} s, so the worker was killed");
            if (line.Status != WorkerLineStatus.Line)
                return StopSsa(GraphWorkerFailureKind.Crashed, $"the graph worker stopped while extracting its SSA facts: {Ending(line.Status)}{ExitNote(process)}");
            if (!line.Bytes.AsSpan().StartsWith(FatalPrefix) && line.Bytes.Length > maxSsaBytes - ssaUsed)
                return StopSsa(GraphWorkerFailureKind.ReportsSpent, $"its SSA record would take this run's SSA records over {maxSsaBytes} bytes, so it was not kept");
            var (message, problem) = Parse(line);
            if (message is GraphWorkerFatal fatal)
                return StopSsa(GraphWorkerFailureKind.Crashed, $"the graph worker failed while extracting its SSA facts: {WorkerProtocol.Safe(fatal.Reason, ReasonChars)}");
            if ((problem ?? SsaMismatch(message, i, answered[i], request.Ssa!)) is { } wrong)
                return StopSsa(GraphWorkerFailureKind.Crashed, $"the graph worker's SSA record for it broke protocol v{GraphWorkerProtocol.Version}: {wrong}");
            ssa.Add((GraphWorkerSsa)message!);
            ssaUsed += line.Bytes.Length;
            return null;
        }

        GraphWorkerRun Stop(GraphWorkerFailureKind kind, string reason) =>
            GraphWorkerRun.Failed(answered, kind, reason) with { Ssa = ssa, AnsweredBytes = used, SsaBytes = ssaUsed, SsaTicks = ssaTicks, ReadyAt = readyAt };

        GraphWorkerRun StopSsa(GraphWorkerFailureKind kind, string reason) => Stop(kind, reason) with { InSsa = true, FailedAt = Stopwatch.GetTimestamp() };
    }

    /// <summary><paramref name="deadline"/> (a <see cref="Stopwatch"/> timestamp, or none) moved back by <paramref name="ticks"/>.</summary>
    internal static long Later(long deadline, long ticks) =>
        deadline == long.MaxValue || ticks >= long.MaxValue - deadline ? long.MaxValue : deadline + Math.Max(0, ticks);

    // Why `message` is not the ssa record for request folder `index`, whose folder record was `folder`, or null: the right
    // type and index, facts exactly when Analyzed and a reason otherwise, nothing analysed for a folder with no graph, no
    // null list element, and the counts consistent and within `bounds`.
    private static string? SsaMismatch(GraphWorkerMessage? message, int index, GraphWorkerFolder folder, GraphWorkerSsaBounds bounds)
    {
        if (message is not GraphWorkerSsa record)
            return $"expected the 'ssa' record for index {index}, got '{message?.GetType().Name ?? "null"}'";
        if (record.Index != index)
            return $"its index is {record.Index}, expected {index}";
        if (record.Outcome is not (SsaFolderOutcome.Analyzed or SsaFolderOutcome.NotRun or SsaFolderOutcome.Crashed))
            return $"its outcome is {record.Outcome}, which only the parent decides";
        if ((record.Outcome == SsaFolderOutcome.Analyzed) != (record.Facts is not null) || (record.Facts is null) != (record.Reason is not null))
            return "it must carry facts exactly when Analyzed, and a reason otherwise";
        if (folder.Report is null && record.Outcome == SsaFolderOutcome.Analyzed)
            return "it has facts for a folder whose graph was not analysed";
        if (record.Facts is not { } facts)
            return null;
        if (HasNullElement(facts))
            return "it holds a null list element";
        if (facts.Sites.Count > bounds.MaxSites || facts.Sites.Count > facts.SitesTotal || facts.Truncated != (facts.SitesTotal > facts.Sites.Count)
            || facts.MethodsLifted < 0 || facts.AssembliesLost < 0 || facts.Unknown.Any(u => u.Methods <= 0)
            || facts.Unknown.Select(u => u.Kind).Distinct().Count() < facts.Unknown.Count)
            return "its folder counts are inconsistent or over the request's bounds";
        if (facts.AssembliesLost > 0 && (facts.MethodsLifted > 0 || facts.Sites.Any(s => s is not { Status: SsaSiteStatus.MethodUnknown, FailureKind: SsaFailureKind.Unreadable })))
            return "it lost assemblies but did not read every site MethodUnknown";
        if (facts.Sites.Any(s => s.Status == SsaSiteStatus.NotRun) && !facts.MethodBudget && !facts.TimeBudget)
            return "it has a NotRun site but no budget was spent";
        // A lift cut by its deadline cuts the folder by time: its kind never reaches a fact.
        if (facts.Unknown.Any(u => u.Kind == SsaFailureKind.TimedOut) || facts.Sites.Any(s => s.FailureKind == SsaFailureKind.TimedOut))
            return "it reports a TimedOut lift as a fact";
        return facts.Sites.Select(s => SiteProblem(s, bounds)).FirstOrDefault(p => p is not null);
    }

    // Why one site breaks SsaSinkFact's contract, or null: values only when Analyzed, a reason (and for MethodUnknown a
    // kind) otherwise, counts within the bounds, every value well-formed, and its names bounded.
    private static string? SiteProblem(SsaSinkFact site, GraphWorkerSsaBounds bounds)
    {
        if (new[] { site.Site.NodeId, site.Site.Callee, site.Site.CalleeKey }.Any(n => n.Length > MaxSiteNameChars))
            return "a site's names are over their bound";
        if (site.Import is { } import && (import.Length > MaxSiteNameChars || UntrustedText.Escape(import) != import))
            return "a site's import name is over its bound or not escaped";
        if (site.Status != SsaSiteStatus.Analyzed)
            return site.Reason is null || (site.Status == SsaSiteStatus.MethodUnknown) != (site.FailureKind is not null)
                    || site.Reason.Length > MaxReasonTextChars
                    || site.Receiver is not null || site.Target is not null || site.Import is not null || site.Arguments.Count > 0 || site.ArgumentCount != 0 || site.Merged
                ? $"a {site.Status} site carries values, or lacks its reason or failure kind"
                : null;
        if (site.Reason is not null || site.FailureKind is not null || site.ArgumentCount < 0 || site.Arguments.Count != Math.Min(site.ArgumentCount, bounds.MaxArguments))
            return "an Analyzed site carries a reason, or its argument counts are inconsistent";
        if (new[] { site.Receiver }.Concat(site.Arguments).Any(v => v is not null && ValueProblem(v, bounds)))
            return "a site holds a malformed value";
        return site.Target is { } t
               && (ValueProblem(t.Type, bounds) || t.Assembly is { } a && ValueProblem(a, bounds) || t.Member is { } m && ValueProblem(m, bounds)
                   || t.Kind is SsaTargetKind.Type or SsaTargetKind.Constructor && t.Member is not null
                   || t.CandidatesTotal < t.Candidates.Count || t.Candidates.Count > bounds.MaxCandidates || t.Candidates.Any(c => c.Length > MaxSiteNameChars))
            ? "a site's reflection target is malformed"
            : null;
    }

    // Whether a value breaks SsaValue's contract: one constant, 2 to MaxAlternatives, a parameter index, or an origin, by
    // kind; constant text bounded, holding nothing the escaper would still escape, and with no backslash outside an escape.
    private static bool ValueProblem(SsaValue value, GraphWorkerSsaBounds bounds) =>
        value.Kind switch
        {
            SsaValueKind.Constant => value.Constants.Count != 1 || value.Parameter is not null || value.Origin is not null,
            SsaValueKind.OneOf => value.Constants.Count < 2 || value.Constants.Count > bounds.MaxAlternatives || value.Parameter is not null || value.Origin is not null,
            SsaValueKind.Parameter => value.Constants.Count != 0 || value.Parameter is not >= 0 || value.Origin is not null,
            _ => value.Constants.Count != 0 || value.Parameter is not null || value.Origin is null,
        }
        || value.Constants.Any(c => c.Text.Length > bounds.MaxTextChars + MaxSuffixChars || UntrustedText.Escape(c.Text) != c.Text || !escapedText.IsMatch(c.Text));

    // Whether any list in the facts holds a null element.
    private static bool HasNullElement(SsaFolderFacts facts)
    {
        static bool Bad(SsaValue? value) => value is not null && value.Constants.Any(c => c is null);
        return facts.Unknown.Any(u => u is null)
            || facts.Sites.Any(s => s is null || Bad(s.Receiver) || s.Arguments.Any(a => a is null || Bad(a))
                || s.Target is { } t && (Bad(t.Assembly) || Bad(t.Type) || Bad(t.Member) || t.Candidates.Any(c => c is null)));
    }

    // Why the first record is not the 'ready' for this request, or null.
    private static string? ReadyProblem((GraphWorkerMessage? Message, string? Problem) first, GraphWorkerRequest request) => first switch
    {
        (_, { } problem) => problem,
        (GraphWorkerFatal fatal, _) => $"it refused the request: {WorkerProtocol.Safe(fatal.Reason, ReasonChars)}",
        (GraphWorkerReady { Protocol: not GraphWorkerProtocol.Version } ready, _) => $"its 'ready' is for protocol {ready.Protocol}",
        (GraphWorkerReady ready, _) when ready.Folders != request.Folders.Count => $"its 'ready' announces {ready.Folders} folder(s), not {request.Folders.Count}",
        (GraphWorkerReady, _) => null,
        (var other, _) => $"its first record is '{other?.GetType().Name ?? "null"}', not 'ready'",
    };

    // Why `message` is not the record for request folder `index`, or null: the right type, index and folder, and every
    // requested assembly exactly once, either loaded or failed, with a report exactly when one loaded.
    private static string? Mismatch(GraphWorkerMessage? message, int index, GraphWorkerFolderRequest folder)
    {
        if (message is not GraphWorkerFolder record)
            return $"expected the 'folder' record for index {index}, got '{message?.GetType().Name ?? "null"}'";
        if (record.Index != index)
            return $"its index is {record.Index}, expected {index}";
        if (!string.Equals(record.Folder, folder.Folder, StringComparison.Ordinal))
            return "it names another folder";
        // System.Text.Json checks nullability of members, not of list elements (review W1).
        if (HasNullElement(record))
            return "it holds a null list element";
        var requested = folder.Assemblies.Select(a => a.RelativePath).Order(StringComparer.Ordinal);
        var reported = record.Assemblies.Concat(record.LoadFailures.Select(f => f.RelativePath)).Order(StringComparer.Ordinal);
        if (!requested.SequenceEqual(reported, StringComparer.Ordinal))
            return "its assemblies and load failures are not the folder's assemblies, each once";
        if ((record.Report is null) != (record.Assemblies.Count == 0))
            return record.Report is null ? "it loaded assemblies but has no report" : "it has a report but loaded nothing";
        return record.Nodes < 0 || record.Edges < 0 ? "its graph size is negative" : null;
    }

    // Whether any list in the record, its report included, holds a null element.
    private static bool HasNullElement(GraphWorkerFolder record) =>
        record.Assemblies.Any(a => a is null) || record.LoadFailures.Any(f => f is null)
        || record.Report is { } report
           && (report.Reaches.Any(r => r is null || r.Examples.Any(p => p is null || p.Hops.Any(h => h is null)))
               || report.Profiles.Any(p => p is null)
               || report.Classes.Any(c => c is null || c.Reasons.Any(r => r is null))
               || report.IgnoredEdges.Any(e => e is null));

    // A record and why it is not one: a line that is not a valid protocol record carries the reason instead.
    private static (GraphWorkerMessage? Message, string? Problem) Parse((WorkerLineStatus Status, byte[] Bytes) line)
    {
        if (line.Status != WorkerLineStatus.Line)
            return (null, Ending(line.Status));
        try
        {
            return JsonSerializer.Deserialize(line.Bytes, GraphWorkerJsonContext.Default.GraphWorkerMessage) is { } message
                ? (message, null)
                : (null, "the record is null");
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            // NotSupportedException is how System.Text.Json refuses a polymorphic record whose "type" is missing or not first.
            return (null, $"the record is not valid JSON for the protocol ({WorkerProtocol.Safe(ex.Message, ReasonChars)}): '{WorkerLineReader.Excerpt(line.Bytes)}'");
        }
    }

    // The next line, waiting at most `bound` and never past `deadline`; null when none arrived in time.
    private static (WorkerLineStatus Status, byte[] Bytes)? Next(BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)> lines, TimeSpan bound, long deadline)
    {
        try
        {
            return lines.TryTake(out var line, Bound(bound, deadline)) ? line
                : lines.IsCompleted ? (WorkerLineStatus.Eof, [])
                : null;
        }
        catch (InvalidOperationException)
        {
            return (WorkerLineStatus.Eof, []);   // completed and empty
        }
    }

    // The reading thread: at most `maxLines` lines (bytes after them are never read), or fewer and the terminal status,
    // then completion. Stops when `stop` is cancelled, even while blocked handing a line over.
    private static void Pump(WorkerLineReader reader, BlockingCollection<(WorkerLineStatus Status, byte[] Bytes)> lines, int maxLines, CancellationToken stop)
    {
        try
        {
            for (var read = 0; read < maxLines; read++)
            {
                var line = reader.ReadLine();
                lines.Add(line, stop);
                if (line.Status != WorkerLineStatus.Line)
                    return;
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException or OperationCanceledException)
        {
            /* the pipe broke, or the run is over: the reader sees completion as the end */
        }
        finally
        {
            try { lines.CompleteAdding(); }
            catch (ObjectDisposedException) { /* the run is over */ }
        }
    }

    // Writes the request line and keeps stdin open: the worker exits as soon as stdin ends (its watchdog). Null on success.
    private static string? Send(Process process, GraphWorkerRequest request)
    {
        try
        {
            new GraphWorkerWriter(process.StandardInput.BaseStream, GraphWorkerProtocol.MaxRequestLineBytes).Write(request);
            return null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return $"the request could not be sent to the graph worker ({Describe(ex)})";
        }
    }

    // The worker's stderr: diagnostics only. The first MaxStderrBytes are relayed at Debug, escaped and bounded per line;
    // the rest is read and dropped so a flood never blocks the worker.
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
                Runtime.Debug("[graph-worker] {0}", WorkerProtocol.Safe(text, StderrLineChars));
        if (discarded > 0)
            Runtime.Debug("[graph-worker] (stderr exceeded {0} bytes; {1} more byte(s) discarded)", MaxStderrBytes, discarded);
    }

    private static ProcessStartInfo StartInfo(GraphWorkerLaunch launch)
    {
        var info = new ProcessStartInfo(launch.Executable!)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // Process wraps stdin in a StreamWriter that would emit a BOM; only the raw BaseStream is used.
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        };
        foreach (var argument in launch.Arguments)
            info.ArgumentList.Add(argument);
        // A managed allocation past ¾ of the limit fails as an OutOfMemoryException in the child, which costs the folder,
        // before the Job Object's hard limit (Windows) can cost the process. Elsewhere it is the only memory bound.
        if (launch.MemoryLimitBytes > 0)
            info.Environment["DOTNET_GCHeapHardLimit"] = "0x" + (launch.MemoryLimitBytes / 4 * 3).ToString("x", CultureInfo.InvariantCulture);
        return info;
    }

    // Places the child in its own kill-on-close Job Object with a per-process memory limit (Windows), or explains why it
    // could not be. Elsewhere there is no Job Object, and the stdin watchdog and the kill below are the containment.
    private static IDisposable? Contain(Process process, long memoryLimitBytes, out string? uncontained)
    {
        uncontained = null;
#if WINDOWS
        WorkerJobObject? job = null;
        try
        {
            job = WorkerJobObject.Create(memoryLimitBytes > 0 ? (ulong)memoryLimitBytes : 0);
            job.Assign(process);
            return job;
        }
        catch (Exception ex) when (ex is Win32Exception or ObjectDisposedException or InvalidOperationException)
        {
            job?.Dispose();
            if (!process.HasExited)
                uncontained = $"the graph worker could not be placed in a kill-on-close Job Object ({Describe(ex)}), so it was killed";
            return null;
        }
#else
        return null;
#endif
    }

    // Kills the child and anything it started, then waits (bounded) for it to go. Never throws.
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
            /* already gone, or the job's close takes it */
        }
    }

    private static void CloseInput(Process process)
    {
        try
        {
            process.StandardInput.Close();
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            /* the pipe is already gone */
        }
    }

    // "; it exited with <code>" when the child has gone (waiting briefly), else empty.
    private static string ExitNote(Process process)
    {
        try
        {
            return process.WaitForExit(ExitNoteWait) ? $"; it exited with {DescribeExit(process.ExitCode)}" : string.Empty;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return string.Empty;
        }
    }

    /// <summary>An exit code, in hex, with what it means when it is one a crashed .NET process is known to leave.</summary>
    internal static string DescribeExit(int code) =>
        $"code {code} (0x{code:X8}" + (unchecked((uint)code) switch
        {
            0xC00000FD => ", a stack overflow",
            0xC0000005 => ", an access violation",
            0x80131623 => ", Environment.FailFast",
            0xC0000409 => ", a fail-fast (stack buffer overrun or __fastfail)",
            0xE0434352 => ", an unhandled .NET exception",
            0xC0000017 or 0x8007000E => ", out of memory",
            134 => ", SIGABRT",
            137 => ", SIGKILL",
            139 => ", SIGSEGV",
            GraphWorkerProtocol.ExitFatal => ", the worker's fatal",
            GraphWorkerProtocol.ExitParentGone => ", the worker saw its stdin end",
            _ => string.Empty,
        }) + ")";

    private static string Ending(WorkerLineStatus status) => status switch
    {
        WorkerLineStatus.Eof => "its output ended",
        WorkerLineStatus.Truncated => "its output ended part-way through a record",
        WorkerLineStatus.TooLong => $"it sent a record over {GraphWorkerProtocol.MaxRecordLineBytes} bytes",
        WorkerLineStatus.InvalidUtf8 => "it sent a record that is not UTF-8",
        _ => "its output pipe broke",
    };

    private static TimeSpan Remaining(long deadline) =>
        deadline == long.MaxValue ? TimeSpan.MaxValue : Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline) is var left && left > TimeSpan.Zero ? left : TimeSpan.Zero;

    // `bound`, cut to what is left before `deadline` and to what BlockingCollection accepts, never negative.
    private static TimeSpan Bound(TimeSpan bound, long deadline) =>
        new[] { bound, Remaining(deadline), MaxWait }.Min() is var cut && cut > TimeSpan.Zero ? cut : TimeSpan.Zero;

    private static Task Background(Action action) =>
        Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    private static Task<T> Background<T>(Func<T> function) =>
        Task.Factory.StartNew(function, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    private static void WaitQuietly(Task[] tasks, TimeSpan bound)
    {
        try
        {
            Task.WaitAll(tasks, bound);
        }
        catch (AggregateException)
        {
            /* each background task reports its own failure */
        }
    }

    private static string Seconds(TimeSpan bound) => bound.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture);

    private static string Describe(Exception ex) => WorkerProtocol.Safe($"{ex.GetType().Name}: {ex.Message}", ReasonChars);
    #endregion

    #region Fields
    /// <summary>How long a started child has to read the request and send <c>ready</c>.</summary>
    internal static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(30);

    /// <summary>How long a child has, after its last folder (or ssa) record, for <c>done</c>, and then to exit.</summary>
    internal static readonly TimeSpan ExitTimeout = TimeSpan.FromSeconds(5);

    private static readonly TimeSpan KillWait = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ExitNoteWait = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxWait = TimeSpan.FromMilliseconds(int.MaxValue - 1);

    private const int MaxStderrBytes = 64 * 1024;
    private const int StderrChunkBytes = 4096;
    private const int StderrLineChars = 1024;
    private const int ReasonChars = 300;

    // Amendment a5's suffix ("…[+N chars, sha256:<8 hex>]") is at most 40 chars; a name or text may end with one.
    private const int MaxSuffixChars = 48;
    private const int MaxSiteNameChars = Reachability.MaxNameChars + MaxSuffixChars;

    // Text as UntrustedText.EscapeBounded writes it: every backslash starts one of its escapes, so a quote the summary
    // escapes can never be preceded by a lone backslash that a reader pairs with it (S5 review round 2, N1).
    private static readonly Regex escapedText = new(@"\A(?:[^\\]|\\(?:\\|[nrt]|x[0-9a-f]{2}|u[0-9a-fA-F]{4}|U[0-9A-F]{8}))*\z", RegexOptions.CultureInvariant);

    // A site's reason: fixed text with up to three bounded names (a lost-assemblies reason).
    private const int MaxReasonTextChars = 4 * MaxSiteNameChars;
    #endregion
}

/// <summary>Why a graph worker run stopped short of a clean <c>done</c>.</summary>
internal enum GraphWorkerFailureKind
{
    /// <summary>The child failed before <c>ready</c>: no folder is to blame.</summary>
    NotStarted,

    /// <summary>The child died or broke protocol on the folder in flight.</summary>
    Crashed,

    /// <summary>The folder in flight outran the folder timeout.</summary>
    TimedOut,

    /// <summary>The package budget ran out on the folder in flight.</summary>
    BudgetSpent,

    /// <summary>The folder in flight's record would take the package's accepted records over their byte limit.</summary>
    ReportsSpent,

    /// <summary>Every folder was answered, but the child did not end cleanly.</summary>
    AfterAll,
}

/// <summary>
/// What one graph worker run produced: the folder records accepted in order, and why the run stopped short (null only for
/// <c>done</c> and exit 0). On a failure other than <see cref="GraphWorkerFailureKind.NotStarted"/> or
/// <see cref="GraphWorkerFailureKind.AfterAll"/>, the folder in flight is request folder <c>Answered.Count</c>, unless
/// <see cref="InSsa"/>: then it is the last answered folder, whose SSA phase failed and whose graph record stands.
/// </summary>
internal sealed record GraphWorkerRun(IReadOnlyList<GraphWorkerFolder> Answered, GraphWorkerFailureKind? Failure, string? Reason)
{
    #region Properties
    /// <summary>The line bytes of <see cref="Answered"/>' records.</summary>
    internal long AnsweredBytes { get; init; }

    /// <summary>The line bytes of <see cref="Ssa"/>'s records, counted apart.</summary>
    internal long SsaBytes { get; init; }

    /// <summary>The <see cref="Stopwatch"/> ticks spent waiting on ssa records, by which the graph deadline moved back.</summary>
    internal long SsaTicks { get; init; }

    /// <summary>The ssa records accepted, in order: one per answered folder, but for the last when <see cref="InSsa"/>.</summary>
    internal IReadOnlyList<GraphWorkerSsa> Ssa { get; init; } = [];

    /// <summary>The run failed in the last answered folder's SSA phase.</summary>
    internal bool InSsa { get; init; }

    /// <summary>When the child's <c>ready</c> arrived (a <see cref="Stopwatch"/> timestamp), or 0 when it did not.</summary>
    internal long ReadyAt { get; init; }

    /// <summary>When an <see cref="InSsa"/> failure was decided (a <see cref="Stopwatch"/> timestamp), or 0.</summary>
    internal long FailedAt { get; init; }
    #endregion

    #region Methods
    internal static GraphWorkerRun Complete(IReadOnlyList<GraphWorkerFolder> answered) => new(answered, null, null);

    internal static GraphWorkerRun Failed(IReadOnlyList<GraphWorkerFolder> answered, GraphWorkerFailureKind kind, string reason) => new(answered, kind, reason);

    internal static GraphWorkerRun NotStarted(string reason) => new([], GraphWorkerFailureKind.NotStarted, reason);
    #endregion
}
