namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Diagnostics;

/// <summary>
/// Runs a probe executable <b>out of process</b> and captures what came back. This exists because certain CCI
/// failure modes (ADR-0021, extended by ADR-0022) are <c>Environment.FailFast</c> — process exit 35, no
/// managed exception, no <c>catch</c>/<c>finally</c> anywhere in the calling process runs. <c>Assert.Throws</c>
/// and <c>Record.Exception</c> cannot observe that. The only way to turn it into an ordinary, attributable
/// xUnit assertion is to run the suspect code in a <b>child</b> process and inspect its exit code and output —
/// never call the crashing path in-process "to see what happens": a FailFast there kills the entire test host
/// and every other test result in the run along with it.
/// <para>
/// Deliberately small — a timeout, the captured exit code, and both streams as text. Extend this only when a
/// second caller needs something it does not already give you; ADR-0021/0022 both expect more probes like
/// this one.
/// </para>
/// </summary>
public static class ChildProcessProbe
{
    #region Methods
    /// <summary>
    /// Starts <paramref name="executablePath"/> with stdin closed (so a probe that accidentally reads stdin
    /// deadlocks instead of hanging the timeout indefinitely) and both output streams redirected and drained
    /// asynchronously (avoids a full-buffer deadlock on a chatty probe). Never throws for a normal, abnormal,
    /// or timed-out child — those are all reported through <see cref="ProbeResult"/>; only a failure to start
    /// the process at all throws.
    /// </summary>
    public static ProbeResult Run(string executablePath, TimeSpan timeout, params string[] arguments)
    {
        var psi = new ProcessStartInfo(executablePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Could not start probe process '{executablePath}'.");

        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit((int)timeout.TotalMilliseconds);

        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return new ProbeResult(ExitCode: null, StandardOutput: string.Empty, StandardError: string.Empty, TimedOut: true);
        }

        return new ProbeResult(
            process.ExitCode,
            stdout.GetAwaiter().GetResult(),
            stderr.GetAwaiter().GetResult(),
            TimedOut: false);
    }
    #endregion
}

/// <summary>
/// Outcome of a <see cref="ChildProcessProbe.Run"/> call. <see cref="ExitCode"/> is <see langword="null"/> only
/// when <see cref="TimedOut"/> is <see langword="true"/> — the process never reported one because it was
/// killed first. It is <b>never</b> null after a FailFast: FailFast is uncatchable by the child's own code, not
/// invisible to its parent — the OS still assigns the child an exit code (35 on .NET), which shows up here like
/// any other exit code.
/// </summary>
public sealed record ProbeResult(int? ExitCode, string StandardOutput, string StandardError, bool TimedOut)
{
    #region Properties
    /// <summary>
    /// <see langword="true"/> only for a normal, successful (<c>exit 0</c>) completion. <see langword="false"/>
    /// for a nonzero exit, a FailFast-shaped abnormal exit, or a timeout — a caller that needs to tell those
    /// apart (e.g. to assert specifically "did not FailFast") should inspect <see cref="ExitCode"/> and
    /// <see cref="TimedOut"/> directly rather than relying on this alone.
    /// </summary>
    public bool ExitedCleanly => !TimedOut && ExitCode == 0;
    #endregion

    #region Methods
    /// <summary>
    /// A diagnostic-friendly summary for an assertion failure message, so a regression reads as "the probe
    /// terminated abnormally: exit 35, stderr: ..." rather than an opaque "expected 0, got 35" — the exit code
    /// alone does not say whether 35 means anything without this context, and a bare mismatch would not point
    /// at ADR-0021 the way this does.
    /// </summary>
    public string Describe() =>
        TimedOut
            ? "the probe process did not exit within the timeout and was killed."
            : $"the probe process exited with code {ExitCode} (0 = success; any other code — especially an " +
              "unfamiliar one such as 35 — may indicate an ABNORMAL TERMINATION such as Environment.FailFast, " +
              $"not a normal managed return; see ADR-0021). stderr:{Environment.NewLine}{StandardError}";
    #endregion
}
