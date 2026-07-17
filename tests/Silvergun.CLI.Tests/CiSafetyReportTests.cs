namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Text;

using Xunit;

/// <summary>
/// CI-safety smoke tests for the Spectre.Console human reports (ADR 0013/0014): running a verb with stdout
/// redirected (non-interactive) and <c>NO_COLOR=1</c> must complete promptly — never blocking on stdin,
/// which is the only real CI-hang risk. In the <b>default</b> (no <c>--rich</c>) mode the output must be
/// pure 7-bit ASCII with no ANSI escape bytes (<c>0x1b</c>); with <c>--rich</c> it may carry ANSI/Unicode
/// but must still complete without hanging. Also asserts the <c>--json</c>/<c>--rich</c> mutual-exclusion
/// validator rejects the combination before any handler runs. Exercises the built <c>Silvergun.CLI</c>
/// entrypoint end-to-end.
/// </summary>
public sealed class CiSafetyReportTests
{
    #region Methods
    [Fact]
    public void Analyze_Redirected_NoColor_CompletesWithoutHangAndWithoutAnsi()
    {
        var (exit, output, _, exited) = RunCli("analyze", TargetAssembly);

        Assert.True(exited, "CLI did not exit within the timeout — a redirected run must never block on stdin.");
        Assert.Equal(0, exit);
        Assert.NotEmpty(output);
        Assert.DoesNotContain(EscByte, output);
    }

    [Fact]
    public void Analyze_DefaultMode_EmitsSevenBitAsciiOnly()
    {
        var (exit, output, _, exited) = RunCli("analyze", TargetAssembly);

        Assert.True(exited, "CLI did not exit within the timeout — a redirected run must never block on stdin.");
        Assert.Equal(0, exit);
        Assert.NotEmpty(output);
        // ADR 0014: default human output is forced ASCII-only (no ANSI, no Unicode glyphs), regardless of TTY.
        var offender = Array.Find(output, b => b > MaxAsciiByte);
        Assert.True(offender == 0, $"default output must be 7-bit ASCII; found byte 0x{offender:x2}.");
    }

    [Fact]
    public void Analyze_Rich_Redirected_CompletesWithoutHang()
    {
        // --rich may emit ANSI/Unicode when redirected (expected); the invariant here is only CI-safety:
        // it must still complete promptly with stdin closed and produce a report (no interactive widgets).
        var (exit, output, _, exited) = RunCli("analyze", TargetAssembly, "--rich");

        Assert.True(exited, "CLI did not exit within the timeout — a --rich run must never block on stdin.");
        Assert.Equal(0, exit);
        Assert.NotEmpty(output);
    }

    [Fact]
    public void Analyze_JsonAndRich_IsRejectedBeforeHandlerRuns()
    {
        // --json and --rich are mutually-exclusive format selectors (ADR 0014). The parse validator must
        // reject the combination with a non-zero exit and a message on stderr, keeping stdout clean.
        // (RejectJsonWithRich is a local function inside Program.Main, so the smallest reachable seam is the
        //  parser via the process boundary — there is no unit-level IsValid*-style hook to call directly.)
        var (exit, output, error, exited) = RunCli("analyze", TargetAssembly, "--json", "--rich");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.NotEqual(0, exit);
        Assert.Contains("--json", error);
        Assert.Contains("--rich", error);
        Assert.DoesNotContain(EscByte, output);   // stdout stays clean on a parse error
    }
    #endregion

    #region Fields
    // Path to the CLI apphost copied next to the test assembly by the project reference.
    private static readonly string CliExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe");

    // A managed assembly guaranteed present in the test output (referenced transitively) to analyze.
    private static readonly string TargetAssembly = Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.dll");

    private const byte EscByte = 0x1b;
    private const byte MaxAsciiByte = 0x7f;
    private const int TimeoutMs = 60_000;
    #endregion

    #region Child types
    // Launches the CLI with stdout/stderr captured as raw bytes, stdin closed (so any stdin read would deadlock —
    // proving CI-safety when it doesn't), and NO_COLOR set so even a TTY-style run stays plain. Both streams are
    // drained asynchronously to avoid a full-buffer deadlock.
    private static (int Exit, byte[] Output, string Error, bool Exited) RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.Latin1,   // 1:1 byte<->char so the 0x1b / >0x7f scan is exact
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit(TimeoutMs);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return (-1, Array.Empty<byte>(), string.Empty, false);
        }

        var bytes = Encoding.Latin1.GetBytes(stdout.GetAwaiter().GetResult());
        return (process.ExitCode, bytes, stderr.GetAwaiter().GetResult(), true);
    }
    #endregion
}
