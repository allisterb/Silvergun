namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System;
using System.Runtime.InteropServices;

/// <summary>
/// Keeps a worker process's crash out of Windows Error Reporting, so a dying worker is gone at once and its parent blames
/// the folder as Crashed (ADR 0021), not TimedOut while WER holds the process (seconds, tens of seconds for a stack
/// overflow). It also keeps the worker's memory, which held hostile package bytes, out of WER reports and dumps (.NET's own
/// event 1026 is still logged). Process-wide: call it first in a worker process, never in a host. Measurements, and why
/// the Job Object flag is not used: <c>docs/agent/tasks/graph-worker.md</c>, "Amendment: workers opt out of WER".
/// </summary>
public static class WorkerErrorReporting
{
    #region Methods
    /// <summary>
    /// Adds <c>SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX</c> to this process's error mode on Windows; elsewhere does
    /// nothing. The exit code of a crash is unchanged. Never throws.
    /// </summary>
    public static void OptOut()
    {
        if (!OperatingSystem.IsWindows())
            return;
        try
        {
            SetErrorMode(GetErrorMode() | FailCriticalErrors | NoGpFaultErrorBox);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            /* not a usable kernel32: nothing to opt out of */
        }
    }

    /// <summary>Whether this process's error mode keeps a crash out of WER (always false off Windows).</summary>
    public static bool IsOptedOut() => OperatingSystem.IsWindows() && (GetErrorMode() & NoGpFaultErrorBox) != 0;

    // DllImport, not LibraryImport: blittable, and the net10.0 target does not allow unsafe code.
    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);

    [DllImport("kernel32.dll")]
    private static extern uint GetErrorMode();
    #endregion

    #region Fields
    private const uint FailCriticalErrors = 0x0001;   // SEM_FAILCRITICALERRORS
    private const uint NoGpFaultErrorBox = 0x0002;    // SEM_NOGPFAULTERRORBOX
    #endregion
}
