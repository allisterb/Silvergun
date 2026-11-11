namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Win32.SafeHandles;

using Xunit;

/// <summary>
/// The product wiring of <c>WorkerErrorReporting.OptOut</c> (review W1): <c>Program.Main</c> opts every <c>__worker</c>
/// command line out of Windows Error Reporting before any work, and never the CLI's own verbs. Observed from outside the
/// real CLI child (net10.0, as <see cref="GraphWorkerVerbCliTests"/> and <see cref="YaraWorkerVerbCliTests"/> start it) by
/// reading its error mode through its process handle.
///
/// <para><b>Reading another process's mode.</b> <c>NtQueryInformationProcess(ProcessDefaultHardErrorMode = 12)</c> returns
/// the kernel's value, which is GetErrorMode with bit 0 (SEM_FAILCRITICALERRORS) INVERTED: a child whose GetErrorMode is
/// 0x8000 reads 0x8001, 0x8003 reads 0x8002. Bit 0x2 (SEM_NOGPFAULTERRORBOX, the WER bit) reads directly, so only it is
/// asserted. The value lives in the process object, so it can still be read after the child exits while the
/// <see cref="Process"/> holds its handle: that final read is how the children that exit at once are observed (the yara
/// worker on this build answers "engine unavailable" without reading stdin; an argument error is one fatal and exit 3).</para>
///
/// <para><b>Why the bit proves the call.</b> A child inherits its parent's error mode; the test host's measured 0x00000001
/// (SEM_FAILCRITICALERRORS only) has no 0x2, and <see cref="AssertTheHostPassesNoWerBitDown"/> re-checks that every run.
/// The negative controls (the same executable, a non-worker command line) end with 0x2 clear, and <c>Program.Main</c> is
/// the only caller of <c>OptOut</c> in <c>src/</c>, so a set bit in a worker child is that call's doing.</para>
/// </summary>
public sealed class WorkerErrorModeCliTests
{
    #region Methods
    /// <summary>The graph worker, stdin held open so it waits for its request: opted out while it waits, before any work.</summary>
    [WindowsErrorModeFact]
    public void GraphWorker_WaitingForItsRequest_IsAlreadyOptedOut()
    {
        AssertTheHostPassesNoWerBitDown();

        var run = Observe(["__worker", "graph", "--protocol", "1"]);

        Assert.True(run.SeenWhileAlive, $"0x2 was not set while the graph worker waited (last live read 0x{run.LastLiveMode:X8}, final 0x{run.FinalMode:X8})\n{run.Stderr}");
        Assert.True((run.FinalMode & NoGpFaultErrorBox) != 0, $"the graph worker ended with mode 0x{run.FinalMode:X8}: not opted out\n{run.Stderr}");
        Assert.True(run.Exit == 3, $"the graph worker: exit {run.Exit}\n{run.Stderr}");   // stdin closed with no request: "no request line (Eof)"
    }

    /// <summary>The yara worker. This build has no engine and exits at once, so it is read after exit if not before.</summary>
    [WindowsErrorModeFact]
    public void YaraWorker_IsOptedOut()
    {
        AssertTheHostPassesNoWerBitDown();

        var run = Observe(["__worker", "yara", "--protocol", "1"]);

        Assert.True((run.FinalMode & NoGpFaultErrorBox) != 0, $"the yara worker ended with mode 0x{run.FinalMode:X8}: not opted out\n{run.Stderr}");
        Assert.True(run.Exit == 3, $"the yara worker: exit {run.Exit}\n{run.Stderr}");   // engine unavailable on this platform
    }

    public static TheoryData<string[]> WorkerArgumentErrors() => new()
    {
        { ["__worker", "graph", "--bogus"] },
        { ["__worker", "graph", "--protocol", "2"] },
        { ["__worker", "yara", "--protocol", "1", "--bogus"] },
        { ["__worker", "yara", "--protocol", "1", "--timeout", "0"] },
        { ["__worker"] },
        { ["__worker", "il", "--protocol", "1"] },
    };

    /// <summary>Every argument-error path under <c>__worker</c> (both protocols' fatals) is opted out too.</summary>
    [WindowsErrorModeTheory]
    [MemberData(nameof(WorkerArgumentErrors))]
    public void Worker_AnArgumentError_IsOptedOut(string[] args)
    {
        AssertTheHostPassesNoWerBitDown();

        var run = Observe(args);

        Assert.True((run.FinalMode & NoGpFaultErrorBox) != 0, $"{string.Join(' ', args)}: ended with mode 0x{run.FinalMode:X8}, not opted out\n{run.Stderr}");
        Assert.True(run.Exit == 3, $"{string.Join(' ', args)}: exit {run.Exit}\n{run.Stderr}");
    }

    public static TheoryData<string, string[], int> NonWorkerCommandLines() => new()
    {
        { "root --help", ["--help"], 0 },
        { "a normal verb's parse error", ["scan-package", "x.nupkg", "--bogus"], 1 },
        { "analyze, run to completion", ["analyze", Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll"), "--json"], 0 },
    };

    /// <summary>Negative control: the CLI's own command lines never opt out, from start to exit.</summary>
    [WindowsErrorModeTheory]
    [MemberData(nameof(NonWorkerCommandLines))]
    public void NonWorker_DoesNotOptOut(string what, string[] args, int exit)
    {
        AssertTheHostPassesNoWerBitDown();

        var run = Observe(args);

        Assert.False(run.SeenWhileAlive, $"{what}: 0x2 was set while it ran (0x{run.LastLiveMode:X8})");
        Assert.True((run.FinalMode & NoGpFaultErrorBox) == 0, $"{what}: ended with mode 0x{run.FinalMode:X8}, opted out");
        Assert.True(run.Exit == exit, $"{what}: exit {run.Exit}\n{run.Stderr}");
    }
    #endregion

    #region Methods: helpers
    // The child inherits this host's mode: were 0x2 already set here, every child would start opted out and the positive
    // tests would prove nothing.
    private static void AssertTheHostPassesNoWerBitDown() =>
        Assert.True((GetErrorMode() & NoGpFaultErrorBox) == 0, $"the test host's own error mode is 0x{GetErrorMode():X8}: it would pass SEM_NOGPFAULTERRORBOX down");

    // One child run. stdin stays open (a worker waits for its request) while the child's mode is polled until 0x2 is set,
    // the child exits, or PollMs pass; the bit only goes from clear to set, so the poll cannot miss it. Then stdin is closed
    // (the "parent gone" signal), the child is waited for (killed on timeout), and the mode is read once more, final.
    private static Observation Observe(IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");

        using var process = Process.Start(psi)!;
        var readOut = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
        var readErr = process.StandardError.ReadToEndAsync();

        var seenWhileAlive = false;
        var lastLive = 0u;
        var clock = Stopwatch.StartNew();
        while (clock.ElapsedMilliseconds < PollMs)
        {
            var mode = ReadMode(process);
            if (process.HasExited)   // read before this check: perhaps after exit, so not "while alive"
                break;
            lastLive = mode;
            if ((mode & NoGpFaultErrorBox) != 0)
            {
                seenWhileAlive = true;
                break;
            }
            Thread.Sleep(10);
        }

        try { process.StandardInput.Close(); } catch (IOException) { /* it already exited */ }
        var exited = process.WaitForExit(TimeoutMs);
        if (!exited)
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
        process.WaitForExit();
        Task.WaitAll(readOut, readErr);
        Assert.True(exited, $"{string.Join(' ', args)}: did not exit within {TimeoutMs} ms and was killed");

        return new Observation(seenWhileAlive, lastLive, ReadMode(process), process.ExitCode, readErr.GetAwaiter().GetResult());
    }

    // The kernel's hard-error mode of `process`: GetErrorMode with bit 0 inverted (see the class remarks); 0x2 reads directly.
    private static uint ReadMode(Process process)
    {
        var status = NtQueryInformationProcess(process.SafeHandle, ProcessDefaultHardErrorMode, out var mode, sizeof(uint), out _);
        Assert.True(status == 0, $"NtQueryInformationProcess(ProcessDefaultHardErrorMode) failed: NTSTATUS 0x{status:X8}");
        return mode;
    }

    // DllImport: blittable but for the SafeHandle, and this project does not allow unsafe code.
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(SafeProcessHandle process, int informationClass, out uint information, int length, out int returnLength);

    [DllImport("kernel32.dll")]
    private static extern uint GetErrorMode();
    #endregion

    #region Nested types
    // SeenWhileAlive: 0x2 was read while the child was still running. LastLiveMode: the last such read (raw kernel value).
    // FinalMode: read after exit through the retained handle.
    private sealed record Observation(bool SeenWhileAlive, uint LastLiveMode, uint FinalMode, int Exit, string Stderr);
    #endregion

    #region Fields
    private const int ProcessDefaultHardErrorMode = 12;

    private const uint NoGpFaultErrorBox = 0x0002;   // SEM_NOGPFAULTERRORBOX

    // The live poll's limit. Generous for a slow machine: the poll stops at the first set bit or at the child's exit, so a
    // passing run (and every negative control, whose child exits by itself) never waits for it.
    private const int PollMs = 30_000;

    private const int TimeoutMs = 60_000;

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");
    #endregion
}

/// <summary>Runs a <see cref="WorkerErrorModeCliTests"/> fact on Windows only; a skip elsewhere, so the output says it did not run.</summary>
public sealed class WindowsErrorModeFactAttribute : FactAttribute
{
    #region Constructors
    public WindowsErrorModeFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "The process error mode (and WER) is Windows only.";
    }
    #endregion
}

/// <summary>The theory twin of <see cref="WindowsErrorModeFactAttribute"/>.</summary>
public sealed class WindowsErrorModeTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public WindowsErrorModeTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "The process error mode (and WER) is Windows only.";
    }
    #endregion
}
