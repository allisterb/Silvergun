#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// A script for the FakeYaraProbe's <c>--fake-worker</c> role (see <c>FakeWorker</c> in that project) plus the
/// <see cref="YaraXWorkerScanner"/> that runs it, through the parent's internal test constructor (ADR 0033 decision 8).
/// Run 1 of every scanner is its availability probe (a zero-file run); run 2 is the first scan. Every section records the
/// worker's PID (for the orphan check) and every request the parent actually SENT (so "refused, with no request sent" is
/// observed on the worker's side of the pipe, not inferred from the parent's message).
/// </summary>
internal sealed class FakeWorkerScript : IDisposable
{
    #region Constructors
    public FakeWorkerScript(string purpose)
    {
        Assert.True(File.Exists(FakeYaraBinary.ProbePath), $"the FakeYaraProbe apphost is missing at '{FakeYaraBinary.ProbePath}'");
        dir = new YaraXTempDir("fw-" + purpose);
        ScriptPath = dir.Combine("worker.script");
        PidFile = dir.Combine("pids.txt");
        RequestLog = dir.Combine("requests.txt");
    }
    #endregion

    #region Properties
    public string ScriptPath { get; }

    public string PidFile { get; }

    public string RequestLog { get; }

    /// <summary>The <c>rulesSha256</c> a genuine worker must announce: the parent's own hash of its embedded rules (G9).</summary>
    public static string Expected =>
        YaraXWorkerScanner.ExpectedRulesSha256 ?? throw new InvalidOperationException("the parent could not hash its embedded rules");

    /// <summary>Every worker process the scanner started, in start order.</summary>
    public int[] Pids => ReadLines(PidFile).Select(int.Parse).ToArray();

    /// <summary>Every path the parent sent, in order, across all runs.</summary>
    public string[] SentPaths => ReadLines(RequestLog).Select(l =>
    {
        using var request = JsonDocument.Parse(l);
        return request.RootElement.GetProperty("path").GetString()!;
    }).ToArray();
    #endregion

    #region Methods
    /// <summary>A genuine <c>ready</c> line, with any one field overridden.</summary>
    public static string Ready(string engine = "yara-x", string canary = "passed", int ruleCount = 5, string? sha = null, int ruleSourceErrors = 0) =>
        $"{{\"type\":\"ready\",\"protocol\":1,\"engine\":{J(engine)},\"engineVersion\":\"1.22.0\",\"ruleCount\":{ruleCount},\"rulesSha256\":{J(sha ?? Expected)},\"canary\":{J(canary)},\"ruleSourceErrors\":{ruleSourceErrors}}}";

    public static string Fatal(string reason) => $"{{\"type\":\"fatal\",\"reason\":{J(reason)}}}";

    public static string Scanned(int index, params string[] rules) =>
        $"{{\"type\":\"result\",\"index\":{index},\"status\":\"scanned\",\"hits\":[{string.Join(",", rules.Select(r => $"{{\"rule\":{J(r)},\"namespace\":\"default\",\"tags\":[]}}"))}]}}";

    /// <summary>The section for run <paramref name="run"/> (1 is the availability probe).</summary>
    public FakeWorkerScript Run(int run, params string[] commands) => Section(run.ToString(System.Globalization.CultureInfo.InvariantCulture), commands);

    /// <summary>The section for every run without its own.</summary>
    public FakeWorkerScript Otherwise(params string[] commands) => Section("*", commands);

    /// <summary>Run 1 is a genuine, empty probe: ready, then done(0) once stdin closes.</summary>
    public FakeWorkerScript GenuineProbe() => Run(1, "out " + Ready(), "readall", "done");

    /// <summary>A genuine worker for every run: ready, then every request answered with a hit named for its file.</summary>
    public FakeWorkerScript GenuineThroughout() => Otherwise("out " + Ready(), "answer", "done");

    /// <summary>Writes the script to <see cref="ScriptPath"/>, for a worker started by something other than <see cref="Scanner"/>.</summary>
    public FakeWorkerScript Save()
    {
        File.WriteAllLines(ScriptPath, lines);
        return this;
    }

    /// <summary>The scanner under test, running this script. The script is written now.</summary>
    public YaraXWorkerScanner Scanner(int engineTimeoutSeconds = 30, double readySeconds = 20, double graceSeconds = 5, double exitSeconds = 5)
    {
        Save();
        return new YaraXWorkerScanner(FakeYaraBinary.ProbePath, ["--fake-worker", ScriptPath], engineTimeoutSeconds,
            TimeSpan.FromSeconds(readySeconds), TimeSpan.FromSeconds(graceSeconds), TimeSpan.FromSeconds(exitSeconds));
    }

    /// <summary>No worker this script started is still running (checked by PID and process name).</summary>
    public void AssertNoOrphans() => WorkerProcesses.AssertGone(Pids, WorkerProcesses.FakeWorkerName);

    public void Dispose() => dir.Dispose();

    private FakeWorkerScript Section(string run, string[] commands)
    {
        lines.Add("@run " + run);
        lines.Add("pid " + PidFile);
        lines.Add("requests " + RequestLog);
        lines.AddRange(commands);
        return this;
    }

    private static string J(string text) => JsonSerializer.Serialize(text);

    // The complete lines of a file a running fake worker may be appending to: read with write sharing, retried while the
    // writer briefly holds it exclusively, and a final line without its \n (mid-append) left out.
    private static string[] ReadLines(string path)
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
                return complete.Split('\n').Where(l => l.Length > 0).ToArray();
            }
            catch (IOException) when (attempt < 100)
            {
                Thread.Sleep(10);
            }
        }
    }
    #endregion

    #region Fields
    private readonly YaraXTempDir dir;
    private readonly List<string> lines = [];
    #endregion
}

/// <summary>Process checks by PID: a worker the parent started must never outlive the scan that started it.</summary>
internal static class WorkerProcesses
{
    #region Methods
    /// <summary>Fails when any of <paramref name="pids"/> is still a running <paramref name="processName"/> after <paramref name="within"/>.</summary>
    internal static void AssertGone(IEnumerable<int> pids, string processName, TimeSpan? within = null)
    {
        var deadline = DateTime.UtcNow + (within ?? TimeSpan.FromSeconds(10));
        foreach (var pid in pids)
            while (IsAlive(pid, processName))
            {
                if (DateTime.UtcNow > deadline)
                    Assert.Fail($"worker process {pid} ({processName}) is still running: an orphan.");
                Thread.Sleep(50);
            }
    }

    /// <summary><c>true</c> when <paramref name="pid"/> is a running process named <paramref name="processName"/> (a reused PID is not).</summary>
    internal static bool IsAlive(int pid, string processName)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited && string.Equals(process.ProcessName, processName, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
    #endregion

    #region Fields
    internal const string FakeWorkerName = "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe";

    internal const string CliName = "Silvergun.CLI";
    #endregion
}

/// <summary>Reflection over the parent's private state, for what is not observable from outside (named so a rename fails loudly).</summary>
internal static class ScannerInternals
{
    #region Methods
    internal static T Field<T>(object target, string name)
    {
        var field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.True(field is not null, $"{target.GetType().Name}.{name} is gone; this test reads it.");
        return (T)field!.GetValue(target)!;
    }

    internal static object? FieldOrNull(object target, string name)
    {
        var field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.True(field is not null, $"{target.GetType().Name}.{name} is gone; this test reads it.");
        return field!.GetValue(target);
    }
    #endregion
}

/// <summary>A tree of files under a <c>silvergun-yara-x-...</c> temp root, removed without following any link inside it.</summary>
internal sealed class ScanTree : IDisposable
{
    #region Constructors
    public ScanTree(string purpose)
    {
        dir = new YaraXTempDir(purpose);
        Root = dir.Combine("root");
        Directory.CreateDirectory(Root);
        Outside = dir.Combine("outside");
        Directory.CreateDirectory(Outside);
    }
    #endregion

    #region Properties
    /// <summary>The directory a scan is pointed at.</summary>
    public string Root { get; }

    /// <summary>A sibling of <see cref="Root"/>, outside it: where links point.</summary>
    public string Outside { get; }
    #endregion

    #region Methods
    /// <summary>Writes <paramref name="relative"/> under the root through its <c>\\?\</c> form (so <c>nul.txt</c>, <c>foo.</c> are names, not devices) and returns its plain path.</summary>
    public string Write(string relative, byte[]? bytes = null)
    {
        var path = Path.Combine(Root, relative);
        Directory.CreateDirectory(@"\\?\" + Path.GetDirectoryName(path)!);
        File.WriteAllBytes(@"\\?\" + path, bytes ?? [1, 2, 3]);
        return path;
    }

    /// <summary>
    /// Makes <paramref name="relative"/> (created through <c>\\?\</c>, so <c>con</c> and <c>bar.</c> are real names) a
    /// junction to a fresh directory outside the root holding <c>secret.bin</c>; returns the target.
    /// </summary>
    public string Junction(string relative)
    {
        var target = Path.Combine(Outside, "t" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(target);
        File.WriteAllBytes(Path.Combine(target, "secret.bin"), [9, 9, 9]);
        var link = @"\\?\" + Path.Combine(Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        WindowsFileSystem.CreateJunction(link, target);
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"the junction '{relative}' was not created");
        junctions.Add(link);
        return target;
    }

    // Junctions are removed first, as links (a non-recursive delete of a reparse point removes the link only), so the
    // recursive delete that follows never walks into a target. Everything goes through \\?\ (YaraXTempDir).
    public void Dispose()
    {
        foreach (var link in junctions)
            try { Directory.Delete(link, recursive: false); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        dir.Dispose();
    }
    #endregion

    #region Fields
    private readonly YaraXTempDir dir;
    private readonly List<string> junctions = [];
    #endregion
}
#endif
