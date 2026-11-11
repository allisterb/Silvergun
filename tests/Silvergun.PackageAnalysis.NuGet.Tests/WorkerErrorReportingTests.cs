namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;

/// <summary>
/// <see cref="WorkerErrorReporting"/>: a worker keeps its own crash out of Windows Error Reporting, so it is gone at once and
/// its parent reads Crashed, not TimedOut. The error mode is process-wide (and a crash in the xunit host must stay
/// reported), so it is observed in a fresh child: the FakeYaraProbe's <c>--error-reporting</c> role, which on Windows
/// first clears both bits OptOut sets and sets <c>SEM_NOOPENFILEERRORBOX</c>, so the starting point does not depend on the
/// mode the child inherited from this host (measured 2026-11-10 under vstest: 0x00000001, SEM_FAILCRITICALERRORS only, so
/// not opted out; the reset keeps the test right if a host ever passes the WER bit down).
/// </summary>
public sealed class WorkerErrorReportingTests
{
    #region Methods
    /// <summary>Windows: not opted out from the known start, opted out after OptOut, and still after a second call.</summary>
    [ErrorModeFact(onWindows: true)]
    public void OptOut_OnWindows_SetsTheBit_AndASecondCallKeepsIt()
    {
        var run = RunProbe();

        Assert.Equal(0, run.Exit);
        Assert.Equal(("False", "True", "True"), (run["before"], run["after"], run["again"]));
    }

    /// <summary>Windows: OptOut adds SEM_FAILCRITICALERRORS and SEM_NOGPFAULTERRORBOX and keeps a bit it does not own.</summary>
    [ErrorModeFact(onWindows: true)]
    public void OptOut_OnWindows_AddsItsBits_AndKeepsTheRestOfTheMode()
    {
        var run = RunProbe();

        var mode = uint.Parse(run["mode"]![2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        Assert.Equal(0x8003u, mode & 0x8003u);
    }

    /// <summary>Off Windows: OptOut does nothing and never throws, and IsOptedOut is false throughout.</summary>
    [ErrorModeFact(onWindows: false)]
    public void OptOut_OffWindows_DoesNothing_AndNeverThrows()
    {
        var run = RunProbe();

        Assert.Equal(0, run.Exit);
        Assert.Equal(("False", "False", "False", "False"), (run["inherited"], run["before"], run["after"], run["again"]));
        Assert.Equal("-", run["mode"]);
    }
    #endregion

    #region Methods: helpers
    private static ProbeRun RunProbe()
    {
        var psi = new ProcessStartInfo(FakeYaraBinary.ProbePath) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add("--error-reporting");

        using var process = Process.Start(psi)!;
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the error-reporting probe did not exit within 60 s");
        }
        process.WaitForExit();

        var values = stdout.GetAwaiter().GetResult().Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Split('=', 2))
            .Where(p => p.Length == 2)
            .ToDictionary(p => p[0], p => p[1].TrimEnd('\r'), StringComparer.Ordinal);
        Assert.True(process.ExitCode == 0, $"the probe exited {process.ExitCode}: {stderr.GetAwaiter().GetResult()}");
        return new ProbeRun(process.ExitCode, values);
    }
    #endregion

    #region Nested types
    private sealed record ProbeRun(int Exit, IReadOnlyDictionary<string, string> Values)
    {
        public string? this[string key] => Values.TryGetValue(key, out var value) ? value : null;
    }
    #endregion
}

/// <summary>
/// Runs a <see cref="WorkerErrorReportingTests"/> fact only on Windows (<paramref name="onWindows"/> true) or only elsewhere;
/// a skip, not an early return, so the output says which half ran.
/// </summary>
public sealed class ErrorModeFactAttribute : FactAttribute
{
    #region Constructors
    public ErrorModeFactAttribute(bool onWindows)
    {
        if (OperatingSystem.IsWindows() != onWindows)
            Skip = onWindows
                ? "The error mode is Windows only; the other half is OptOut_OffWindows_DoesNothing_AndNeverThrows."
                : "Off Windows only: run the suite under WSL (dotnet test <proj> -f net10.0) for this to execute.";
    }
    #endregion
}
