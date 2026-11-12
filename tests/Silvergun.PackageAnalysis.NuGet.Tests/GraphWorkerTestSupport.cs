namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>
/// A script for the FakeYaraProbe's <c>--fake-graph-worker</c> role (<c>FakeGraphWorker</c> in that project) and the
/// <see cref="GraphWorkerLaunch"/> that runs it. Every section records the worker's PID (so starts are counted and orphans
/// checked), the request line it read, and each folder it answered (so "built once" is observed on the worker's side).
/// </summary>
internal sealed class FakeGraphScript : IDisposable
{
    #region Constructors
    public FakeGraphScript(string purpose)
    {
        Assert.True(File.Exists(ProbePath), $"the FakeYaraProbe apphost is missing at '{ProbePath}'");
        Root = Directory.CreateTempSubdirectory("silvergun-graphfake-" + purpose + "-").FullName;
        ScriptPath = Combine("worker.script");
        PidFile = Combine("pids.txt");
        RequestLog = Combine("requests.txt");
        AnsweredLog = Combine("answered.txt");
    }
    #endregion

    #region Properties
    public static string ProbePath { get; } = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe");

    public string Root { get; }

    public string ScriptPath { get; }

    public string PidFile { get; }

    public string RequestLog { get; }

    public string AnsweredLog { get; }

    /// <summary>Every worker this script ran, in start order.</summary>
    public int[] Pids => GraphFiles.Lines(PidFile).Select(int.Parse).ToArray();

    /// <summary>The folder names of every request the parent sent, one array per start.</summary>
    public string[][] RequestedFolders => GraphFiles.Lines(RequestLog).Select(l =>
    {
        using var request = JsonDocument.Parse(l);
        return request.RootElement.GetProperty("folders").EnumerateArray().Select(f => f.GetProperty("folder").GetString()!).ToArray();
    }).ToArray();

    /// <summary>Every folder the fake answered (built or not), across all starts.</summary>
    public string[] Answered => GraphFiles.Lines(AnsweredLog);
    #endregion

    #region Methods
    public string Combine(string name) => Path.Combine(Root, name);

    /// <summary>The section for start <paramref name="run"/> (1-based).</summary>
    public FakeGraphScript Run(int run, params string[] commands) => Section(run.ToString(System.Globalization.CultureInfo.InvariantCulture), commands);

    /// <summary>The section for every start without its own.</summary>
    public FakeGraphScript Otherwise(params string[] commands) => Section("*", commands);

    /// <summary>A genuine worker for every start: every folder built for real.</summary>
    public FakeGraphScript Genuine() => Otherwise("request", "ready", "build", "done");

    /// <summary>A worker for every start that answers every folder "nothing loaded" (cheap: no CCI).</summary>
    public FakeGraphScript Empty() => Otherwise("request", "ready", "empty", "done");

    /// <summary>Writes the script and returns the launch that runs it.</summary>
    public GraphWorkerLaunch Launch(long memoryLimitBytes = 0)
    {
        File.WriteAllLines(ScriptPath, lines);
        return new GraphWorkerLaunch(ProbePath, null, ["--fake-graph-worker", ScriptPath], memoryLimitBytes);
    }

    /// <summary>No worker this script started (nor any PID in <paramref name="more"/>) is still running.</summary>
    public void AssertNoOrphans(params int[] more) => GraphProcesses.AssertGone(Pids.Concat(more));

    public void Dispose() => GraphFiles.DeleteTree(Root);

    private FakeGraphScript Section(string run, string[] commands)
    {
        lines.Add("@run " + run);
        lines.Add("pid " + PidFile);
        lines.Add("requests " + RequestLog);
        lines.Add("answered " + AnsweredLog);
        lines.AddRange(commands);
        return this;
    }
    #endregion

    #region Fields
    private readonly List<string> lines = [];
    #endregion
}

/// <summary>Package folders staged on disk as <see cref="PackageAssembly"/> records, with real SHA-256s, under one temp root.</summary>
internal sealed class GraphStage : IDisposable
{
    #region Constructors
    public GraphStage(string purpose) => Root = Directory.CreateTempSubdirectory("silvergun-graphstage-" + purpose + "-").FullName;
    #endregion

    #region Properties
    public string Root { get; }

    public static byte[] Mechanism { get; } = File.ReadAllBytes(Beside(MechanismFixture));

    public static byte[] Dependency { get; } = File.ReadAllBytes(Beside(MechanismDependency));

    public static byte[] Shared { get; } = File.ReadAllBytes(Beside(SharedFixture));

    /// <summary>The mechanism fixture's host stubs: a loadable assembly whose graph has no sink site.</summary>
    public static byte[] HostStubs { get; } = File.ReadAllBytes(Beside(HostStubsFixture));
    #endregion

    #region Methods
    /// <summary>One file at <c>&lt;folder&gt;/&lt;name&gt;</c>, as the package's assembly; <paramref name="hash"/> false leaves its hash empty.</summary>
    public PackageAssembly Put(string folder, string name, byte[] bytes, bool hash = true)
    {
        var full = Path.Combine(Directory.CreateDirectory(Path.Combine(Root, folder.Replace('/', Path.DirectorySeparatorChar))).FullName, name);
        File.WriteAllBytes(full, bytes);
        return new PackageAssembly($"{folder}/{name}", full, null, PackageItemRole.Lib, hash ? Convert.ToHexStringLower(SHA256.HashData(bytes)) : string.Empty);
    }

    /// <summary>
    /// The mechanism fixture and its Dependency in <paramref name="folder"/>: a folder whose graph has the CrossAssembly path.
    /// In ordinal order of their package paths, as <see cref="PackageGraphs"/> loads them ('D' &lt; 'd').
    /// </summary>
    public PackageAssembly[] Mechanisms(string folder) =>
        [Put(folder, MechanismDependency, Dependency), Put(folder, MechanismFixture, Mechanism)];

    /// <summary>A small distinct folder: one file of <paramref name="bytes"/> (garbage by default, so it never loads).</summary>
    public PackageAssembly[] Small(string folder, string name = "a.dll", byte[]? bytes = null) =>
        [Put(folder, name, bytes ?? Encoding.UTF8.GetBytes("not a portable executable: " + folder))];

    public void Dispose() => GraphFiles.DeleteTree(Root);

    // A fixture DLL next to this test assembly (copied there by its ProjectReference); fails loudly if missing.
    internal static string Beside(string file)
    {
        var path = Path.Combine(AppContext.BaseDirectory, file);
        return File.Exists(path) ? path : throw new InvalidOperationException($"'{file}' was not found in '{AppContext.BaseDirectory}'.");
    }
    #endregion

    #region Fields
    internal const string SharedFixture = "Silvergun.CodeAnalysis.IL.Tests.Fixture.dll";
    internal const string MechanismFixture = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.dll";
    internal const string MechanismDependency = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.Dependency.dll";
    internal const string HostStubsFixture = "Silvergun.CodeAnalysis.IL.Tests.MechanismFixture.HostStubs.dll";
    #endregion
}

/// <summary>Protocol-level helpers: the expected in-process answer for a folder, and canonical JSON of reports.</summary>
internal static class GraphJson
{
    #region Methods
    /// <summary>A report as the protocol writes it (the strict source-generated context), or "null".</summary>
    public static string Of(ReachabilityReport? report) =>
        report is null ? "null" : JsonSerializer.Serialize(report, GraphWorkerJsonContext.Default.ReachabilityReport);

    /// <summary>A message as the protocol writes it.</summary>
    public static string Of(GraphWorkerMessage message) => JsonSerializer.Serialize(message, GraphWorkerJsonContext.Default.GraphWorkerMessage);

    /// <summary>A folder's SSA result as the protocol would write it in an <c>ssa</c> record at index 0, or "null".</summary>
    public static string Of(FolderSsa? ssa) =>
        ssa is null ? "null" : Of(new GraphWorkerSsa(0, ssa.Outcome, ssa.Facts, ssa.Reason));

    /// <summary>
    /// Every field of a folder but its SSA result, the report serialized by the protocol's context: two passes whose
    /// folders give equal strings agree on the graph pass byte for byte (<c>ssa-facts-s4.md</c>, additivity).
    /// </summary>
    public static string GraphOf(FolderReachability f) =>
        string.Join("|", f.Folder, f.Outcome, string.Join(",", f.Assemblies), string.Join(",", f.LoadFailures.Select(l => l.RelativePath + ":" + l.Reason)),
            Of(f.Report), f.Reason, f.SameAs, f.Nodes, f.Edges);

    /// <summary>The in-process answer for request folder <paramref name="index"/>: PackageGraphs.BuildFolder, then Reachability.Analyze.</summary>
    public static GraphWorkerFolder InProcess(int index, string folder, IReadOnlyList<(string RelativePath, string FullPath)> members, GraphBudget? budget = null)
    {
        var built = PackageGraphs.BuildFolder(folder, members, budget ?? GraphBudget.Default, CapabilityMap.Default);
        var report = built.Graph is { } graph ? Reachability.Analyze(graph) : null;
        return new GraphWorkerFolder(index, built.Folder, built.Assemblies, built.LoadFailures, report, built.Graph?.Nodes.Count ?? 0, built.Graph?.Edges.Count ?? 0);
    }

    /// <summary>A protocol request over <paramref name="folders"/> with the default graph budget.</summary>
    public static GraphWorkerRequest Request(params (string Folder, PackageAssembly[] Members)[] folders) =>
        new(GraphWorkerProtocol.Version, GraphWorkerBudget.Of(GraphBudget.Default),
            [.. folders.Select(f => new GraphWorkerFolderRequest(f.Folder, [.. f.Members.Select(m => new GraphWorkerAssembly(m.RelativePath, m.FullPath))]))]);

    /// <summary>One request as a UTF-8 line.</summary>
    public static byte[] Line(GraphWorkerRequest request) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, GraphWorkerJsonContext.Default.GraphWorkerRequest) + "\n");
    #endregion
}

/// <summary>Process checks by PID, for "no worker outlives the run".</summary>
internal static class GraphProcesses
{
    #region Methods
    internal static void AssertGone(IEnumerable<int> pids, TimeSpan? within = null)
    {
        var deadline = DateTime.UtcNow + (within ?? TimeSpan.FromSeconds(5));
        foreach (var pid in pids)
            while (IsAlive(pid))
            {
                if (DateTime.UtcNow > deadline)
                {
                    Kill(pid);
                    Assert.Fail($"worker process {pid} was still running after the run returned: an orphan (killed by the test).");
                }
                Thread.Sleep(50);
            }
    }

    // A running fake (a reused PID is some other process name, so not alive in this sense).
    internal static bool IsAlive(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited && string.Equals(process.ProcessName, FakeName, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    // Kills `pid` only while it is still a fake worker: a PID the OS has reused for another process is left alone.
    private static void Kill(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            if (!string.Equals(process.ProcessName, FakeName, StringComparison.OrdinalIgnoreCase))
                return;
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            /* already gone */
        }
    }
    #endregion

    #region Fields
    private const string FakeName = "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe";
    #endregion
}

internal static class GraphFiles
{
    #region Methods
    // The complete lines of a file a running fake may be appending to (a final line without its \n is left out).
    internal static string[] Lines(string path)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                if (!File.Exists(path))
                    return [];
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var text = new StreamReader(stream).ReadToEnd();
                var complete = text.LastIndexOf('\n') is var end and >= 0 ? text[..end] : string.Empty;
                return complete.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToArray();
            }
            catch (IOException) when (attempt < 100)
            {
                Thread.Sleep(10);
            }
        }
    }

    internal static void DeleteTree(string root)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                if (Directory.Exists(root))
                    Directory.Delete(root, recursive: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(100);
            }
        }
    }
    #endregion
}
