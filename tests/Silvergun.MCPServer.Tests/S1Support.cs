namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The tests that count processes (kills, hard kill, no child before the first tool call). They run alone, after every
/// parallel collection, so a process seen under the test host or a server is one of theirs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessCountingCollection
{
    public const string Name = "MCP process counting";
}

/// <summary>.nupkg fixtures built in code with BCL zip (as the CLI tests build theirs): no NuGet client, no network.</summary>
internal static class Fixtures
{
    #region Methods
    /// <summary>A package with a root <c>&lt;id&gt;.nuspec</c> and <paramref name="entries"/>, written to <paramref name="dir"/>.</summary>
    public static string Nupkg(string dir, string id, params (string Entry, byte[] Bytes)[] entries)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>MCP server S1 fixture.</description>
              </metadata>
            </package>
            """;
        var path = Path.Combine(dir, id + ".1.0.0.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, id + ".nuspec", Encoding.UTF8.GetBytes(nuspec));
            foreach (var (entry, bytes) in entries)
                Write(zip, entry, bytes);
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    /// <summary>One small managed assembly: a job of a second or two.</summary>
    public static string Small(string dir, string id = "mcp.small") => Nupkg(dir, id, Lib("Nuclear.SemVer.dll"));

    /// <summary>Four large managed assemblies: a standard job of about ten seconds, long enough to cancel or kill mid-run.</summary>
    public static string Slow(string dir, string id = "mcp.slow") =>
        Nupkg(dir, id, Lib("Silvergun.PackageAnalysis.NuGet.dll"), Lib("Microsoft.Cci.NET6.dll"), Lib("SharpCompress.dll"), Lib("NuGet.Protocol.dll"));

    /// <summary>A <c>.dll</c> that is no loadable assembly: an MZ header and then garbage.</summary>
    public static string Unloadable(string dir, string id = "mcp.unloadable")
    {
        var bytes = new byte[512];
        new Random(7).NextBytes(bytes);
        (bytes[0], bytes[1]) = ((byte)'M', (byte)'Z');
        return Nupkg(dir, id, ("lib/netstandard2.0/Broken.dll", bytes));
    }

    public static string Sha256Of(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    public static void CopyDirectory(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var file in Directory.GetFiles(from))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (var dir in Directory.GetDirectories(from))
            CopyDirectory(dir, Path.Combine(to, Path.GetFileName(dir)));
    }

    private static (string, byte[]) Lib(string dll) => ("lib/netstandard2.0/" + dll, File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, dll)));
    #endregion
}

/// <summary>A <see cref="JobManager"/> or <see cref="JobTools"/> in this process, whose jobs run in the real CLI apphost.</summary>
internal static class InProcess
{
    #region Methods
    public static McpServerSettings Settings(TestDirs dirs, string? cacheDir = null, int maxJobs = 1, string? root = null)
    {
        var settings = McpServerSettings.Create([root ?? dirs.Root], false, maxJobs, cacheDir ?? dirs.Cache, McpServerSettings.DefaultCacheMaxGb, dirs.Logs, false);
        Assert.True(settings.IsSuccess, settings.Message);
        return settings.Value;
    }

    public static JobManager Manager(TestDirs dirs, string? root = null) => new(Settings(dirs, root: root), CliLaunch);

    public static JobTools Tools(TestDirs dirs, out JobManager manager, string? root = null)
    {
        var settings = Settings(dirs, root: root);
        manager = new JobManager(settings, CliLaunch);
        return new JobTools(manager, new ServerState(settings));
    }

    /// <summary>Submits and waits until the job ends (bounded by <see cref="JobTimeout"/>).</summary>
    public static async Task<JobView> RunToEndAsync(JobManager manager, string path, JobDepth depth = JobDepth.Standard)
    {
        var (view, status, problem) = await manager.SubmitAsync(path, depth, CancellationToken.None);
        Assert.True(view is not null, $"submit refused: {status} {problem}");
        return await WaitToEndAsync(manager, view!.JobId);
    }

    public static async Task<JobView> WaitToEndAsync(JobManager manager, string jobId)
    {
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var (view, status, problem) = await manager.WaitAsync(jobId, TimeSpan.FromSeconds(10), null, CancellationToken.None);
            Assert.True(view is not null, $"wait: {status} {problem}");
            if (view!.State is JobState.Completed or JobState.Failed or JobState.Cancelled)
                return view;
            if (clock.Elapsed > JobTimeout)
                throw new TimeoutException($"job {jobId} still {view.State} after {JobTimeout}");
        }
    }

    /// <summary>A tool result's structuredContent.</summary>
    public static JsonElement S(ModelContextProtocol.Protocol.CallToolResult result) => result.StructuredContent!.Value;

    /// <summary>The single text block of a tool result.</summary>
    public static string Text(ModelContextProtocol.Protocol.CallToolResult result) =>
        Assert.IsType<ModelContextProtocol.Protocol.TextContentBlock>(Assert.Single(result.Content)).Text;
    #endregion

    #region Fields
    public static readonly JobLaunch CliLaunch = new(McpCli.Exe, null, JobProtocol.Arguments);

    public static readonly TimeSpan JobTimeout = TimeSpan.FromMinutes(5);
    #endregion
}

/// <summary>One tool result read off the wire: structuredContent, isError and the text block.</summary>
internal sealed record ToolCall(JsonElement S, bool IsError, string Text)
{
    public string Status => S.GetProperty("status").GetString()!;

    public bool Retry => S.GetProperty("retry").GetBoolean();

    public string? Str(string name) => S.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public bool Flag(string name) => S.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
}

/// <summary>An initialized MCP server child, driven by hand-written JSON-RPC over <see cref="McpChildProcess"/>.</summary>
internal sealed class McpRpc : IDisposable
{
    #region Constructors
    private McpRpc(McpChildProcess child) => Child = child;
    #endregion

    #region Properties
    public McpChildProcess Child { get; }
    #endregion

    #region Methods
    public static async Task<McpRpc> StartAsync(string[] args, string workingDirectory)
    {
        var rpc = new McpRpc(McpChildProcess.Start(args, workingDirectory));
        rpc.Child.Send("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"silvergun-mcp-tests","version":"1.0.0"}}}""");
        var init = await rpc.Child.WaitForResponseAsync(1);
        Assert.True(init.TryGetProperty("result", out _), $"initialize failed: {init}");
        rpc.Child.Send("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");
        return rpc;
    }

    /// <summary>One tools/call; a JSON-RPC error (not a tool error) fails the test.</summary>
    public async Task<ToolCall> CallAsync(string tool, JsonObject? arguments = null, string? progressToken = null)
    {
        var id = Interlocked.Increment(ref next);
        var parameters = new JsonObject { ["name"] = tool, ["arguments"] = arguments ?? new JsonObject() };
        if (progressToken is not null)
            parameters["_meta"] = new JsonObject { ["progressToken"] = progressToken };
        Child.Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = "tools/call", ["params"] = parameters }.ToJsonString());
        var response = await Child.WaitForResponseAsync(id);
        Assert.True(response.TryGetProperty("result", out var result), $"{tool}: a JSON-RPC error: {response}");
        var text = result.GetProperty("content").EnumerateArray().Single().GetProperty("text").GetString()!;
        return new ToolCall(result.GetProperty("structuredContent").Clone(), result.TryGetProperty("isError", out var e) && e.GetBoolean(), text);
    }

    public Task<ToolCall> AnalyzeAsync(string path, string depth = "standard") =>
        CallAsync(ToolNames.AnalyzePackage, new JsonObject { ["path"] = path, ["depth"] = depth });

    /// <summary>wait_for_job until <c>retry</c> is false (bounded by <see cref="InProcess.JobTimeout"/>).</summary>
    public async Task<ToolCall> WaitToEndAsync(string jobId)
    {
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var wait = await CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = jobId, ["maxWaitSeconds"] = 10 });
            if (!wait.Retry)
                return wait;
            if (clock.Elapsed > InProcess.JobTimeout)
                throw new TimeoutException($"job {jobId} still {wait.Status} after {InProcess.JobTimeout}");
        }
    }

    /// <summary>wait_for_job (1 s at a time) until the job is running a stage of its own, not queued or waiting on a peer.</summary>
    public async Task<ToolCall> WaitUntilRunningAsync(string jobId)
    {
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var wait = await CallAsync(ToolNames.WaitForJob, new JsonObject { ["jobId"] = jobId, ["maxWaitSeconds"] = 1 });
            Assert.True(wait.Retry, $"the job ended before it could be observed running: {wait.S}");
            if (wait.Str("state") == "running" && wait.Str("stage") is { } stage && stage != "elsewhere")
                return wait;
            if (clock.Elapsed > McpCli.Timeout)
                throw new TimeoutException($"job {jobId} never ran a stage: {wait.S}");
        }
    }

    public void Dispose() => Child.Dispose();
    #endregion

    #region Fields
    private int next = 100;
    #endregion
}

/// <summary>One process, identified by id and start time so a reused id is never mistaken for it.</summary>
internal sealed record TrackedProcess(int Pid, string Name, DateTime? StartTime)
{
    public bool IsAlive
    {
        get
        {
            try
            {
                using var p = Process.GetProcessById(Pid);
                return !p.HasExited && (StartTime is null || ProcessTree.StartOf(p) == StartTime);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                return false;
            }
        }
    }

    public override string ToString() => $"{Name} ({Pid})";
}

/// <summary>Process listing: (pid, parent pid, name) from a Toolhelp snapshot on Windows or <c>/proc</c> on Linux.</summary>
internal static class ProcessTree
{
    #region Methods
    public static bool Supported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux();

    /// <summary>
    /// Every live descendant of <paramref name="root"/> (started at <paramref name="rootStart"/>). A child joins only if it
    /// started no earlier than its parent, so a reused parent id cannot pull an unrelated process in.
    /// </summary>
    public static List<TrackedProcess> Descendants(int root, DateTime? rootStart)
    {
        var all = Snapshot();
        var found = new List<TrackedProcess>();
        var frontier = new Queue<(int Pid, DateTime? Start)>([(root, rootStart)]);
        var seen = new HashSet<int> { root };
        while (frontier.Count > 0)
        {
            var (parent, parentStart) = frontier.Dequeue();
            foreach (var (pid, _, name) in all.Where(p => p.ParentPid == parent && !seen.Contains(p.Pid)))
            {
                var start = StartOf(pid);
                if (start is not null && parentStart is not null && start < parentStart)
                    continue;
                seen.Add(pid);
                found.Add(new TrackedProcess(pid, name, start));
                frontier.Enqueue((pid, start));
            }
        }
        return found;
    }

    public static DateTime? StartOf(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return StartOf(p);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    public static DateTime? StartOf(Process p)
    {
        try { return p.StartTime.ToUniversalTime(); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return null; }
    }

    /// <summary>True for the OS's console host, which Windows attaches to a console process: not a process of ours.</summary>
    public static bool IsConsoleHost(TrackedProcess p) => p.Name.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase);

    public static bool IsCli(TrackedProcess p) => p.Name.StartsWith("Silvergun.CLI", StringComparison.OrdinalIgnoreCase);

    private static List<(int Pid, int ParentPid, string Name)> Snapshot() => OperatingSystem.IsWindows() ? WindowsSnapshot() : LinuxSnapshot();

    private static List<(int, int, string)> LinuxSnapshot()
    {
        var list = new List<(int, int, string)>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid))
                continue;
            try
            {
                var stat = File.ReadAllText(Path.Combine(dir, "stat"));
                var open = stat.IndexOf('(');
                var close = stat.LastIndexOf(')');
                var rest = stat[(close + 2)..].Split(' ');
                list.Add((pid, int.Parse(rest[1]), stat[(open + 1)..close]));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or IndexOutOfRangeException or ArgumentOutOfRangeException)
            {
                /* it exited while listed */
            }
        }
        return list;
    }

    private static List<(int, int, string)> WindowsSnapshot()
    {
        var list = new List<(int, int, string)>();
        var snapshot = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snapshot == InvalidHandle)
            throw new InvalidOperationException($"CreateToolhelp32Snapshot failed ({Marshal.GetLastWin32Error()})");
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            for (var ok = Process32FirstW(snapshot, ref entry); ok; ok = Process32NextW(snapshot, ref entry))
                list.Add(((int)entry.ProcessId, (int)entry.ParentProcessId, entry.ExeFile));
        }
        finally
        {
            CloseHandle(snapshot);
        }
        return list;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    #endregion

    #region Nested types
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }
    #endregion

    #region Fields
    private const uint SnapProcess = 0x00000002;
    private static readonly IntPtr InvalidHandle = new(-1);
    #endregion
}

/// <summary>
/// Samples a process's descendants every 100 ms and keeps every one it ever saw, so a tree can be checked after its root
/// is gone. Sampling can miss a process that lives under 100 ms.
/// </summary>
internal sealed class TreeWatcher : IDisposable
{
    #region Constructors
    /// <param name="ignoreExisting">Ignore descendants already alive now (the test host's own console host, say).</param>
    public TreeWatcher(int root, bool ignoreExisting = false)
    {
        this.root = root;
        rootStart = ProcessTree.StartOf(root);
        if (ignoreExisting)
            foreach (var p in ProcessTree.Descendants(root, rootStart))
                ignored.Add((p.Pid, p.StartTime));
        loop = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                Sample();
                try { await Task.Delay(100, stop.Token); } catch (OperationCanceledException) { }
            }
        });
    }
    #endregion

    #region Properties
    public IReadOnlyList<TrackedProcess> Seen
    {
        get { lock (seen) return [.. seen.Values]; }
    }
    #endregion

    #region Methods
    /// <summary>Waits until a descendant matching <paramref name="match"/> has been seen.</summary>
    public async Task<TrackedProcess> WaitForAsync(Func<TrackedProcess, bool> match, TimeSpan timeout)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            if (Seen.FirstOrDefault(match) is { } found)
                return found;
            await Task.Delay(50);
        }
        throw new TimeoutException($"no matching descendant of {root} within {timeout}; seen: {string.Join(", ", Seen)}");
    }

    /// <summary>Stops sampling, then asserts every process ever seen has exited within <paramref name="grace"/>.</summary>
    public async Task AssertAllGoneAsync(TimeSpan grace, string what)
    {
        Stop();
        var clock = Stopwatch.StartNew();
        List<TrackedProcess> alive;
        while ((alive = [.. Seen.Where(p => p.IsAlive)]).Count > 0 && clock.Elapsed < grace)
            await Task.Delay(100);
        Assert.True(alive.Count == 0, $"{what}: still alive after {grace.TotalSeconds:0.#} s: {string.Join(", ", alive)} (seen: {string.Join(", ", Seen)})");
    }

    public void Stop()
    {
        stop.Cancel();
        try { loop.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
    }

    public void Dispose() => Stop();

    private void Sample()
    {
        try
        {
            foreach (var p in ProcessTree.Descendants(root, rootStart).Where(p => !ignored.Contains((p.Pid, p.StartTime))))
                lock (seen)
                    seen.TryAdd((p.Pid, p.StartTime), p);
        }
        catch (InvalidOperationException) { /* a failed snapshot; the next sample retries */ }
    }
    #endregion

    #region Fields
    private readonly int root;
    private readonly DateTime? rootStart;
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;
    private readonly Dictionary<(int, DateTime?), TrackedProcess> seen = [];
    private readonly HashSet<(int, DateTime?)> ignored = [];
    #endregion
}

/// <summary>A fact that needs process listing (Windows or Linux); a skip elsewhere.</summary>
public sealed class ProcessListingFactAttribute : FactAttribute
{
    public ProcessListingFactAttribute()
    {
        if (!ProcessTree.Supported)
            Skip = "Process listing is implemented for Windows and Linux only.";
    }
}

/// <summary>The local package corpus the corpus tests read; they skip when it is absent.</summary>
internal static class Corpus
{
    public const string Dir = @"C:\Temp\silvergun-corpus";

    public static bool Present => Directory.Exists(Dir);
}

/// <summary>A corpus fact: skipped when <see cref="Corpus.Dir"/> is absent.</summary>
public sealed class CorpusFactAttribute : FactAttribute
{
    public CorpusFactAttribute()
    {
        if (!Corpus.Present)
            Skip = $"The package corpus ({Corpus.Dir}) is absent.";
    }
}

/// <summary>A corpus theory: skipped when <see cref="Corpus.Dir"/> is absent.</summary>
public sealed class CorpusTheoryAttribute : TheoryAttribute
{
    public CorpusTheoryAttribute()
    {
        if (!Corpus.Present)
            Skip = $"The package corpus ({Corpus.Dir}) is absent.";
    }
}
