namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Threading;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// The worker side of graph worker protocol v1 (<c>docs/agent/tasks/graph-worker.md</c>): the loop behind the hidden
/// <c>__worker graph</c> CLI verb. It reads one request, answers <c>ready</c>, builds each folder's graph with
/// <see cref="PackageGraphs"/> and its <see cref="Reachability"/> report in order, sends one <c>folder</c> record per
/// folder, then <c>done</c>. Only plain data leaves: the graph itself is dropped after each folder.
/// <para>
/// stdout carries protocol records only. Anything that goes wrong after the arguments are read ends the session with
/// <c>fatal</c> and <see cref="GraphWorkerProtocol.ExitFatal"/>, so a folder whose record cannot be written is never
/// skipped silently: the parent blames the folder in flight. What this loop cannot catch (a stack overflow, a process
/// kill) is what the process boundary is for.
/// </para>
/// </summary>
public static class GraphWorker
{
    #region Methods
    /// <summary>
    /// Runs one session over <paramref name="stdin"/> and <paramref name="stdout"/>. When <paramref name="parentGone"/>
    /// is given, a background thread keeps reading stdin after the request and calls it as soon as stdin ends or carries
    /// anything more: the parent is gone or has given up (the CLI exits with
    /// <see cref="GraphWorkerProtocol.ExitParentGone"/>). Returns <see cref="GraphWorkerProtocol.ExitDone"/> or
    /// <see cref="GraphWorkerProtocol.ExitFatal"/>. Never throws, except for an out-of-memory condition.
    /// </summary>
    public static int Run(string? protocol, Stream stdin, Stream stdout, Action? parentGone = null)
    {
        var writer = new GraphWorkerWriter(stdout, GraphWorkerProtocol.MaxRecordLineBytes);
        var finished = false;
        Exception? outOfMemory = null;
        EventHandler<FirstChanceExceptionEventArgs> watch = NoteOutOfMemory;
        try
        {
            if (protocol != SupportedProtocol)
                return Fatal(writer, protocol is null
                    ? $"missing --protocol; this build speaks {GraphWorkerProtocol.Version}"
                    : $"unsupported protocol '{WorkerProtocol.Safe(protocol, ArgumentChars)}'; this build speaks {GraphWorkerProtocol.Version}");

            var reader = new WorkerLineReader(stdin, GraphWorkerProtocol.MaxRequestLineBytes);
            var (status, line) = reader.ReadLine();
            if (status != WorkerLineStatus.Line)
                return Fatal(writer, $"no request line ({status})");

            GraphWorkerRequest? request;
            try
            {
                request = JsonSerializer.Deserialize(line, GraphWorkerJsonContext.Default.GraphWorkerRequest);
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
                return Fatal(writer, $"the request is not valid JSON for protocol {GraphWorkerProtocol.Version}: {ex.Message}");
            }
            if (Problem(request) is { } problem)
                return Fatal(writer, "the request is out of contract: " + problem);

            // Once the session is over, the watchdog no longer speaks for it (review N1): stdin closing then is no news.
            if (parentGone is not null)
                new Thread(() => Watch(reader, () => { if (!Volatile.Read(ref finished)) parentGone(); }))
                    { IsBackground = true, Name = "graph-worker stdin watchdog" }.Start();

            writer.Write(new GraphWorkerReady(GraphWorkerProtocol.Version, request!.Folders.Count));
            var budget = request.Budget.ToBudget();
            // The IL library's catch-alls turn an OutOfMemoryException under the GC heap hard limit into a load or
            // disassembly failure, so a folder could read as analysed with parts silently missing (review round 2). Any
            // out-of-memory thrown while a folder is built, caught or not, fails that folder: memory pressure, the Job
            // Object's limit met inside an OS call, and also an allocation over a size limit (an array past
            // Array.MaxLength), which in-process is a load failure but here makes the folder Crashed, the suspect side.
            // The handler must not allocate.
            AppDomain.CurrentDomain.FirstChanceException += watch;
            for (var i = 0; i < request.Folders.Count; i++)
            {
                Volatile.Write(ref outOfMemory, null);
                var (record, failure) = Build(i, request.Folders[i], budget);
                if (Interlocked.Exchange(ref outOfMemory, null) is { } oom)
                    return Fatal(writer, $"the folder's graph could not be built: {oom.GetType().Name}: {oom.Message}");
                // A build that failed as a whole (review W4) is the worker failing on this folder, not a folder with
                // nothing to load: the parent blames it, and a fresh worker takes the folders after it.
                if (failure is not null)
                    return Fatal(writer, failure);
                writer.Write(record);
            }
            writer.Write(new GraphWorkerDone(request.Folders.Count));
            return GraphWorkerProtocol.ExitDone;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return TryFatal(writer, $"the worker failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= watch;
            Volatile.Write(ref finished, true);
        }

        void NoteOutOfMemory(object? sender, FirstChanceExceptionEventArgs e)
        {
            if (IsOutOfMemory(e.Exception))
                Interlocked.CompareExchange(ref outOfMemory, e.Exception, null);
        }
    }

    // An OutOfMemoryException, or an OS call failing for want of memory or commit (review round 2, N2). Type and field
    // tests only: this runs while memory is exhausted.
    private static bool IsOutOfMemory(Exception ex) =>
        ex is OutOfMemoryException
        || ex is Win32Exception { NativeErrorCode: ErrorNotEnoughMemory or ErrorOutOfMemory or ErrorCommitmentLimit }
        || ex.HResult is unchecked((int)0x80070008) or unchecked((int)0x8007000E) or unchecked((int)0x800705AF);

    /// <summary>
    /// Ends a session that never started, a command line that did not parse, with one <c>fatal</c> record carrying
    /// <paramref name="reason"/> (escaped and bounded here). Returns <see cref="GraphWorkerProtocol.ExitFatal"/>. Never throws,
    /// except for an out-of-memory condition.
    /// </summary>
    public static int Refuse(Stream stdout, string reason) =>
        TryFatal(new GraphWorkerWriter(stdout, GraphWorkerProtocol.MaxRecordLineBytes), reason);

    // One folder's graph pass, or why its build failed as a whole. PackageGraphs.BuildFolder never throws; Analyze returns
    // a partial report on failure.
    private static (GraphWorkerFolder Record, string? Failure) Build(int index, GraphWorkerFolderRequest folder, GraphBudget budget)
    {
        var built = PackageGraphs.BuildFolder(folder.Folder, [.. folder.Assemblies.Select(a => (a.RelativePath, a.FullPath))], budget, CapabilityMap.Default);
        var report = built.Graph is { } graph ? Reachability.Analyze(graph) : null;
        return (new GraphWorkerFolder(index, built.Folder, built.Assemblies, built.LoadFailures, report,
            built.Graph?.Nodes.Count ?? 0, built.Graph?.Edges.Count ?? 0), built.BuildFailure);
    }

    // Why the request cannot be served, or null. Paths come from the parent, which extracted the package; they are checked
    // only for the shape this loop relies on.
    private static string? Problem(GraphWorkerRequest? request) =>
        request is null ? "it is null"
        : request.Protocol != GraphWorkerProtocol.Version ? $"protocol {request.Protocol}, not {GraphWorkerProtocol.Version}"
        : request.Budget is not { MaxNodes: > 0, MaxEdges: > 0, MaxDispatchWork: > 0 } ? "the graph budget is not positive"
        : request.Folders.Any(f => f.Assemblies.Count == 0) ? "a folder has no assemblies"
        : request.Folders.SelectMany(f => f.Assemblies).Any(a => !Path.IsPathFullyQualified(a.FullPath)) ? "an assembly path is not absolute"
        : null;

    // The stdin watchdog: whatever the next read returns (EOF, a broken pipe, or any byte at all after the request, with
    // or without a newline), the parent is no longer holding this session open.
    private static void Watch(WorkerLineReader reader, Action parentGone)
    {
        try
        {
            reader.WaitForMore();
        }
        finally
        {
            parentGone();
        }
    }

    private static int Fatal(GraphWorkerWriter writer, string reason)
    {
        writer.Write(new GraphWorkerFatal(WorkerProtocol.Safe(reason, GraphWorkerProtocol.MaxReasonChars)));
        return GraphWorkerProtocol.ExitFatal;
    }

    // A fatal when stdout may itself be what failed: the exit code says it either way.
    private static int TryFatal(GraphWorkerWriter writer, string reason)
    {
        try
        {
            return Fatal(writer, reason);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return GraphWorkerProtocol.ExitFatal;
        }
    }
    #endregion

    #region Fields
    private const string SupportedProtocol = "1";
    private const int ArgumentChars = 64;
    private const int ErrorNotEnoughMemory = 8;
    private const int ErrorOutOfMemory = 14;
    private const int ErrorCommitmentLimit = 1455;
    #endregion
}
