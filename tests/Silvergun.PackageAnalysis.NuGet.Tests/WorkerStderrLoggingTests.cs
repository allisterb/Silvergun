namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun;

using Xunit;

/// <summary>
/// <see cref="Runtime.WithStderrLogging"/>, worker-mode logging (ADR 0033: "stdout is protocol only; stderr is
/// diagnostics, ≤ 64 KiB in total; no file sink"). The logger is process-wide and <c>Runtime.Initialize</c> runs once
/// per process, so it is observed in a fresh child process: the FakeYaraProbe's <c>--stderr-logging</c> role, which
/// configures worker-mode logging with every level enabled and then logs.
/// </summary>
public sealed class WorkerStderrLoggingTests
{
    #region Methods
    [Fact]
    public void EveryLevel_GoesToStderr_AndNothingToStdout()
    {
        var run = RunProbe("levels");

        Assert.Equal(0, run.Exit);
        foreach (var (level, text) in new[] { ("DBG", "probe-debug 1"), ("INF", "probe-info 2"), ("WRN", "probe-warn 3"), ("ERR", "probe-error 4"), ("FTL", "probe-fatal 5") })
            Assert.Contains($"[{level}] {text}", run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("probe-", run.Stdout, StringComparison.Ordinal);
        Assert.StartsWith("stdout-only\n", run.Stdout, StringComparison.Ordinal);
        Assert.Contains("truncated=False", run.Stdout, StringComparison.Ordinal);
    }

    // No file sink: nothing is created in the working directory, and no log file named for this run appears next to the
    // binary (where Runtime.WithFileLogging would put one).
    [Fact]
    public void WorkerModeLogging_CreatesNoLogFile()
    {
        var run = RunProbe("levels");

        Assert.Equal(0, run.Exit);
        Assert.NotEmpty(run.Stderr);
        Assert.Equal(0, run.WorkingDirectoryEntries);
        Assert.Empty(Directory.EnumerateFiles(Path.GetDirectoryName(FakeYaraBinary.ProbePath)!, $"*{run.LogName}*"));
    }

    // 5,000 warnings of ~130 bytes each is ~10x the cap: the process's stderr carries at most 64 KiB, ends with the one
    // truncation marker, and a direct Console.Error write after the flood is capped too (the writer is installed as
    // Console.Error, so nothing in the process can bypass it).
    [Fact]
    public void AFlood_IsCappedAt64KiB_IncludingDirectConsoleErrorWrites()
    {
        var run = RunProbe("flood");

        Assert.Equal(0, run.Exit);
        Assert.True(run.StderrBytes.Length <= Runtime.WorkerStderrCapBytes, $"stderr carried {run.StderrBytes.Length} bytes");
        Assert.True(run.StderrBytes.Length > Runtime.WorkerStderrCapBytes - 1024, $"stderr carried only {run.StderrBytes.Length} bytes; was it cut early?");
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(run.StderrBytes);
        Assert.EndsWith(CappedTextWriter.TruncationMarker, text, StringComparison.Ordinal);
        Assert.Equal(text.IndexOf(CappedTextWriter.TruncationMarker, StringComparison.Ordinal), text.LastIndexOf(CappedTextWriter.TruncationMarker, StringComparison.Ordinal));
        Assert.DoesNotContain("probe-direct-after-flood", text, StringComparison.Ordinal);
        Assert.Contains("[WRN] probe-flood 0 ", text, StringComparison.Ordinal);
        Assert.Contains("truncated=True", run.Stdout, StringComparison.Ordinal);
        Assert.Contains($"capped-bytes={run.StderrBytes.Length}", run.Stdout, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: helpers
    private static ProbeRun RunProbe(string mode)
    {
        var logName = $"stderr-probe-{Guid.NewGuid():N}";
        var cwd = Path.Combine(Path.GetTempPath(), $"silvergun-yara-x-stderr-{Guid.NewGuid():N}");
        Directory.CreateDirectory(cwd);
        try
        {
            var psi = new ProcessStartInfo(FakeYaraBinary.ProbePath)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WorkingDirectory = cwd,
            };
            foreach (var arg in new[] { "--stderr-logging", logName, mode })
                psi.ArgumentList.Add(arg);

            using var process = Process.Start(psi)!;
            var stderr = new MemoryStream();
            var readErr = process.StandardError.BaseStream.CopyToAsync(stderr);
            var stdout = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(60_000))
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                Assert.Fail("the logging probe did not exit within 60 s");
            }
            process.WaitForExit();
            readErr.GetAwaiter().GetResult();

            var entries = Directory.EnumerateFileSystemEntries(cwd).Count();
            return new ProbeRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.ToArray(), logName, entries);
        }
        finally
        {
            Directory.Delete(cwd, recursive: true);
        }
    }
    #endregion

    #region Nested types
    // The child's working directory is deleted before the test asserts, so what it held is captured as a count.
    private sealed record ProbeRun(int Exit, string Stdout, byte[] StderrBytes, string LogName, int WorkingDirectoryEntries)
    {
        public string Stderr => Encoding.UTF8.GetString(StderrBytes);
    }
    #endregion
}
