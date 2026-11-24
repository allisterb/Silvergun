#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// The gate of the real-engine YARA-X tests on Linux (<c>docs/agent/tasks/yarax-worker-linux.md</c>, Phase 1): they run
/// only on Linux with <c>libyara_x_capi.so</c> in this test output (the product's csproj copies it when building on Linux;
/// the in-process engine tests load it from here) and the <c>Silvergun.CLI</c> apphost, with its own
/// <c>libyara_x_capi.so</c>, in the CLI's output directory <c>src/Silvergun.CLI/bin/&lt;configuration&gt;/net10.0/</c>
/// (<see cref="LinuxYaraX.CliDirectory"/>). This project's Linux-only CLI ProjectReference only builds the CLI: the apphost
/// is deleted from this test output, which must hold none (see the csproj). Anywhere else they are a VISIBLE skip with the reason, never an early-return pass. <c>SILVERGUN_REQUIRE_YARAX=1</c>
/// turns a Linux skip (a missing library or apphost) into a run, so the tests fail on what is missing.
/// </summary>
public sealed class LinuxYaraXFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxYaraXFactAttribute() => Skip = LinuxYaraX.SkipReason;
    #endregion
}

/// <summary>The <see cref="TheoryAttribute"/> twin of <see cref="LinuxYaraXFactAttribute"/>.</summary>
public sealed class LinuxYaraXTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public LinuxYaraXTheoryAttribute() => Skip = LinuxYaraX.SkipReason;
    #endregion
}

/// <summary>Where the Linux real-engine tests find the engine and the worker, and the helpers they share.</summary>
internal static class LinuxYaraX
{
    #region Properties
    /// <summary>The pinned YARA-X C API library in the test output.</summary>
    internal static string LibraryPath => Path.Combine(AppContext.BaseDirectory, "libyara_x_capi.so");

    /// <summary>
    /// The net10.0 CLI's own output directory, <c>src/Silvergun.CLI/bin/&lt;configuration&gt;/net10.0/</c>, for this test
    /// output's configuration (<c>tests/&lt;project&gt;/bin/&lt;configuration&gt;/net10.0/</c>). Not this test output: that
    /// must hold no CLI apphost (see the csproj), so the worker is launched from where the CLI is built, with its own
    /// <c>libyara_x_capi.so</c> beside it. <c>null</c> when the repository root cannot be found above this test output.
    /// </summary>
    internal static string? CliDirectory { get; } = FindCliDirectory();

    /// <summary>The net10.0 CLI apphost (amendment (o): the worker the parent runs), or a path that does not exist.</summary>
    internal static string CliPath => Path.Combine(CliDirectory ?? AppContext.BaseDirectory, "Silvergun.CLI");

    /// <summary>Why the gate skips, or <c>null</c> to run.</summary>
    internal static string? SkipReason =>
        !OperatingSystem.IsLinux()
            ? "YARA-X worker on Linux (docs/agent/tasks/yarax-worker-linux.md): Linux only. Run the net10.0 suite under WSL "
              + "(tests/scripts/wsl-test.ps1) for this to execute; Windows has YaraWorkerVerbWindowsTests."
            : Required ? null
            : !File.Exists(LibraryPath)
                ? $"YARA-X worker on Linux: '{LibraryPath}' is missing (build/fetch-yara.ps1 -Engine YaraXCapi -Platform linux-x64, "
                  + $"then build on Linux). Set {RequireVar}=1 to make this a FAILURE instead of a skip."
            : !File.Exists(CliPath) || !File.Exists(Path.Combine(CliDirectory!, "libyara_x_capi.so"))
                ? $"YARA-X worker on Linux: the CLI apphost '{CliPath}' or the libyara_x_capi.so beside it is missing (the "
                  + $"Linux-only Silvergun.CLI ProjectReference builds it). Set {RequireVar}=1 to make this a FAILURE instead of a skip."
            : null;

    private static bool Required =>
        string.Equals(Environment.GetEnvironmentVariable(RequireVar), "1", StringComparison.Ordinal);
    #endregion

    #region Methods
    /// <summary>
    /// A production-shaped scanner over the real worker at <see cref="CliPath"/>: the production launch arguments and
    /// engine timeout, through the test constructor only because the worker is not in <see cref="AppContext.BaseDirectory"/>
    /// (the production constructor's step 2 is pinned by <see cref="YaraXWorkerScanner.ResolveWorkerExecutable"/> instead).
    /// The ready bound is generous: every Linux worker compiles the rules (no cache, L6).
    /// </summary>
    internal static YaraXWorkerScanner Scanner(int engineTimeoutSeconds = WorkerProtocol.DefaultTimeoutSeconds, double graceSeconds = 5) =>
        new(CliPath, WorkerProtocol.YaraWorkerLaunchArguments(engineTimeoutSeconds), engineTimeoutSeconds,
            TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(graceSeconds), TimeSpan.FromSeconds(5));

    // bin/<configuration>/net10.0/ of this test output, mapped onto the CLI project under the repository root.
    private static string? FindCliDirectory()
    {
        var output = new DirectoryInfo(AppContext.BaseDirectory);
        var configuration = output.Parent?.Name;
        for (var dir = output; dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "src", "Silvergun.sln")))
                return configuration is null ? null : Path.Combine(dir.FullName, "src", "Silvergun.CLI", "bin", configuration, "net10.0");
        return null;
    }

    /// <summary>The kernel's view of <paramref name="pid"/>: its command name, state and parent, or <c>null</c> when it is gone.</summary>
    internal static (string Comm, char State, int ParentPid)? Stat(int pid)
    {
        string text;
        try
        {
            text = File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/stat");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        var (open, close) = (text.IndexOf('('), text.LastIndexOf(')'));
        var fields = text[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return (text[(open + 1)..close], fields[0][0], int.Parse(fields[1], CultureInfo.InvariantCulture));
    }

    /// <summary><c>true</c> while <paramref name="pid"/> is a live (not zombie) process named <paramref name="comm"/>.</summary>
    internal static bool IsAlive(int pid, string comm) =>
        Stat(pid) is { } stat && stat.State is not ('Z' or 'X') && stat.Comm == comm;

    /// <summary>Every live <c>Silvergun.CLI</c> process whose parent is this test host.</summary>
    internal static int[] ChildWorkers() =>
        Directory.EnumerateDirectories("/proc")
            .Select(Path.GetFileName)
            .Where(n => n is not null && n.All(char.IsAsciiDigit))
            .Select(n => int.Parse(n!, CultureInfo.InvariantCulture))
            .Where(pid => Stat(pid) is { } s && s.ParentPid == Environment.ProcessId && s.Comm == WorkerComm && s.State is not ('Z' or 'X'))
            .ToArray();

    /// <summary>
    /// <c>true</c> while some thread of <paramref name="pid"/> sleeps in the kernel's FIFO open (<c>wait_for_partner</c>):
    /// it is blocked opening a FIFO that has no writer.
    /// </summary>
    internal static bool IsBlockedOpeningAFifo(int pid)
    {
        try
        {
            return Directory.EnumerateDirectories($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/task")
                .Any(task => File.ReadAllText(Path.Combine(task, "wchan")).Trim() == "wait_for_partner");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>A FIFO at <paramref name="path"/> (opening it for read blocks until a writer comes, which none does).</summary>
    internal static void MakeFifo(string path)
    {
        using var mkfifo = Process.Start(new ProcessStartInfo("mkfifo") { ArgumentList = { "--", path }, UseShellExecute = false })!;
        Assert.True(mkfifo.WaitForExit(10_000) && mkfifo.ExitCode == 0, $"mkfifo '{path}' failed");
    }

    internal static byte[] Requests(params string[] paths) =>
        Utf8(string.Concat(paths.Select((p, i) => $"{{\"index\":{i},\"path\":{JsonSerializer.Serialize(p)}}}\n")));

    internal static byte[] Utf8(string text) => new UTF8Encoding(false).GetBytes(text);

    /// <summary>
    /// One run of the real CLI's <c>__worker yara</c> (or any other) command line, driven as the parent drives it: an
    /// argument array, raw redirected streams, stdin written on its own task and then closed. <paramref name="env"/> sets
    /// (or, with a null value, removes) variables after the defaults; <c>SILVERGUN_YARA_ENGINE</c>,
    /// <c>SILVERGUN_YARA_PATH</c> and <c>DOTNET_STARTUP_HOOKS</c> are removed by default.
    /// </summary>
    internal static LinuxWorkerRun Run(IReadOnlyList<string> args, byte[] stdin, string? workingDirectory = null, IReadOnlyDictionary<string, string?>? env = null)
    {
        Assert.True(File.Exists(CliPath), $"the net10.0 CLI apphost is not at '{CliPath}'.");
        var psi = new ProcessStartInfo(CliPath)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = workingDirectory ?? AppContext.BaseDirectory,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        psi.Environment.Remove("SILVERGUN_YARA_ENGINE");
        psi.Environment.Remove(YaraCliScanner.YaraPathVar);
        foreach (var (key, value) in env ?? new Dictionary<string, string?>())
            if (value is null)
                psi.Environment.Remove(key);
            else
                psi.Environment[key] = value;

        using var process = Process.Start(psi)!;
        var stdout = new MemoryStream();
        var readOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var readErr = process.StandardError.ReadToEndAsync();
        var write = Task.Run(() =>
        {
            try
            {
                process.StandardInput.BaseStream.Write(stdin);
                process.StandardInput.BaseStream.Flush();
                process.StandardInput.Close();
            }
            catch (IOException) { /* the worker stopped reading (fatal) and exited */ }
        });

        if (!process.WaitForExit(120_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the CLI did not exit within 120 s and was killed");
        }
        process.WaitForExit();
        readOut.GetAwaiter().GetResult();
        write.GetAwaiter().GetResult();
        return new LinuxWorkerRun(process.ExitCode, stdout.ToArray(), readErr.GetAwaiter().GetResult(), process.Id);
    }

    /// <summary>Every line \n-terminated, BOM-free UTF-8, no \r.</summary>
    internal static string[] Lines(LinuxWorkerRun run)
    {
        Assert.False(run.StdoutBytes is [0xEF, 0xBB, 0xBF, ..], "stdout starts with a BOM");
        Assert.True(run.StdoutBytes.Length > 0 && run.StdoutBytes[^1] == (byte)'\n', "stdout does not end with a newline: " + run.Stderr);
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(run.StdoutBytes);
        Assert.DoesNotContain('\r', text);
        return text[..^1].Split('\n');
    }

    /// <summary>The worker's stdout through the parent's own strict reader, flattened for assertions.</summary>
    internal static LinuxWorkerOutcome Outcome(LinuxWorkerRun run, int requests)
    {
        var outcome = new Yara.Worker.WorkerResponseReader(new MemoryStream(run.StdoutBytes), requests).ReadToEnd();
        return new(outcome.IsComplete, outcome.Results.Select(r => new LinuxWorkerFile(
            r.Status.ToString().ToLowerInvariant(), r.Reason, (r.Hits ?? []).Select(h => h.Rule).ToArray())).ToArray());
    }

    internal static void AssertNoCanary(IEnumerable<string> rules) =>
        Assert.DoesNotContain(rules, r => r.StartsWith(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase));
    #endregion

    #region Fields
    internal const string RequireVar = "SILVERGUN_REQUIRE_YARAX";

    /// <summary>The worker's <c>/proc/[pid]/stat</c> command name (the apphost's file name; under the 15-char limit).</summary>
    internal const string WorkerComm = "Silvergun.CLI";

    internal static readonly string[] WorkerArgs = ["__worker", "yara", "--protocol", "1"];
    #endregion
}

internal sealed record LinuxWorkerRun(int Exit, byte[] StdoutBytes, string Stderr, int Pid)
{
    public string Stdout => Encoding.UTF8.GetString(StdoutBytes);
}

internal sealed record LinuxWorkerFile(string Status, string? Reason, string[] Rules);

internal sealed record LinuxWorkerOutcome(bool Done, LinuxWorkerFile[] Results);

/// <summary>
/// A tree under a <c>silvergun-yara-x-…</c> temp root: <see cref="Root"/> (scanned) and <see cref="Outside"/> (where links
/// point). Links are removed as links first, so the recursive delete never walks into a target.
/// </summary>
internal sealed class LinuxScanTree : IDisposable
{
    #region Constructors
    public LinuxScanTree(string purpose)
    {
        Base = Path.Combine(Path.GetTempPath(), $"silvergun-yara-x-{purpose}-{Guid.NewGuid():N}");
        Root = Path.Combine(Base, "root");
        Outside = Path.Combine(Base, "outside");
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Outside);
    }
    #endregion

    #region Properties
    public string Base { get; }

    public string Root { get; }

    public string Outside { get; }
    #endregion

    #region Methods
    /// <summary>Writes <paramref name="relative"/> ('/'-separated; a backslash is part of a name) under the root.</summary>
    public string Write(string relative, byte[]? bytes = null) => WriteAt(Path.Combine(Root, relative), bytes);

    /// <summary>Writes <paramref name="relative"/> under <see cref="Outside"/>.</summary>
    public string WriteOutside(string relative, byte[]? bytes = null) => WriteAt(Path.Combine(Outside, relative), bytes);

    /// <summary>Makes <paramref name="relative"/> under the root a symbolic link to <paramref name="target"/>; returns the link.</summary>
    public string Symlink(string relative, string target)
    {
        var link = Path.Combine(Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        if (Directory.Exists(target))
            Directory.CreateSymbolicLink(link, target);
        else
            File.CreateSymbolicLink(link, target);
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"the symlink '{relative}' is not reported as a link");
        links.Add(link);
        return link;
    }

    public void Dispose()
    {
        foreach (var link in links)
            try { File.Delete(link); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        try { Directory.Delete(Base, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static string WriteAt(string path, byte[]? bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes ?? [1, 2, 3]);
        return path;
    }
    #endregion

    #region Fields
    private readonly List<string> links = [];
    #endregion
}
#endif
