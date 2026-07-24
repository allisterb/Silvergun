namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Text;

using Xunit;

/// <summary>
/// Parse-level tests for the <c>scan-package --depth</c> option (resolver-lite, ADR 0018). Like the
/// <c>--json</c>/<c>--rich</c> mutual-exclusion validator in <see cref="CiSafetyReportTests"/>, the negative-depth
/// rejection is a <see cref="System.CommandLine"/> validator declared as a local inside <c>Program.Main</c>, so the
/// smallest reachable seam is the parser via the process boundary — there is no unit-level hook to call directly. The
/// validator must reject a negative depth with a non-zero exit and a message on stderr <b>before</b> any handler runs,
/// so no package is opened and no network is touched.
///
/// The positive-depth clamp to <c>MaxResolveDepth</c> (8) is NOT unit-testable: it lives inside <c>RunScanPackage</c>,
/// which constructs <c>new NuGetPackageDependencyFetcher()</c> / <c>new OsvClient()</c> directly (no injection seam),
/// so exercising it is a live-network path. It is therefore covered by inspection only (same posture as the OSV
/// <c>RunScanPackage</c> glue), never by a network test here.
/// </summary>
public sealed class DepthOptionTests
{
    #region Methods
    [Fact]
    public void Depth_Negative_IsParseError()
    {
        // A negative --depth must be rejected at parse time: non-zero exit, a message naming --depth on stderr, and no
        // scan output on stdout (the handler never runs). The nupkg path need not exist — the parse error preempts the
        // handler, so no package is opened and no OSV/resolver network is touched.
        var (exit, stdout, error, exited) = RunCli("scan-package", "does-not-exist.nupkg", "--depth", "-1");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.NotEqual(0, exit);
        Assert.Contains("--depth", error);              // the validator's message identifies the offending option
        Assert.Contains("0 or greater", error);         // ... and states the constraint
        Assert.DoesNotContain("Assessment", stdout);    // no report section — the handler never ran
    }

    [Fact]
    public void Depth_NonNumeric_IsParseError()
    {
        // A non-integer --depth is a type-conversion parse error (System.CommandLine), also rejected before the handler:
        // non-zero exit, stderr diagnostic, clean stdout. Confirms --depth is a strict int option, not free-form.
        var (exit, stdout, error, exited) = RunCli("scan-package", "does-not-exist.nupkg", "--depth", "abc");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.NotEqual(0, exit);
        Assert.NotEmpty(error);
        Assert.DoesNotContain("Assessment", stdout);
    }
    #endregion

    #region Child types
    // Launches the CLI with stdout/stderr captured and stdin closed (so a stray stdin read would deadlock rather than
    // silently pass), draining both streams asynchronously to avoid a full-buffer deadlock. Mirrors the runner in
    // CiSafetyReportTests; stdout is decoded as text since these tests assert on substrings, not raw bytes.
    private static (int Exit, string Stdout, string Error, bool Exited) RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
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
            return (-1, string.Empty, string.Empty, false);
        }

        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }
    #endregion

    #region Fields
    // Path to the CLI apphost copied next to the test assembly by the project reference.
    private static readonly string CliExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe");

    private const int TimeoutMs = 60_000;
    #endregion
}
