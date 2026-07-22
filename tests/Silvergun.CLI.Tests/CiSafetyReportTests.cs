namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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

    [Fact]
    public void ScanPackage_DefaultMode_EmitsSevenBitAsciiOnly()
    {
        // A benign minimal package (nuspec-only, no assemblies/scripts) yields a clean report. In default
        // (no --rich) mode its human rendering must be pure 7-bit ASCII with no ANSI (ADR 0014), and the
        // redirected/stdin-closed run must complete without hanging.
        var nupkg = BuildMinimalNupkg();
        try
        {
            var (exit, output, _, exited) = RunCli("scan-package", nupkg, "--no-vulns");

            Assert.True(exited, "CLI did not exit within the timeout — a redirected run must never block on stdin.");
            Assert.Equal(0, exit);
            Assert.NotEmpty(output);
            var offender = Array.Find(output, b => b > MaxAsciiByte);
            Assert.True(offender == 0, $"default output must be 7-bit ASCII; found byte 0x{offender:x2}.");
            Assert.DoesNotContain(EscByte, output);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    [Fact]
    public void ScanPackage_Rich_Redirected_CompletesWithoutHang()
    {
        // --rich may emit ANSI/Unicode when redirected (expected); the invariant here is only CI-safety:
        // scan-package must still complete promptly with stdin closed and produce a report (no interactive widgets).
        var nupkg = BuildMinimalNupkg();
        try
        {
            var (exit, output, _, exited) = RunCli("scan-package", nupkg, "--no-vulns", "--rich");

            Assert.True(exited, "CLI did not exit within the timeout — a --rich run must never block on stdin.");
            Assert.Equal(0, exit);
            Assert.NotEmpty(output);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    [Fact]
    public void Health_JsonAndRich_IsRejectedBeforeHandlerRuns()
    {
        // The health verb shares the same --json/--rich mutual-exclusion validator (ADR 0015 is advisory but still
        // supports both format selectors). The combination must be rejected at parse time — non-zero exit, message on
        // stderr, stdout clean — BEFORE the handler runs, so no nuget.org/GitHub network is ever touched. A plausible
        // package id is passed only to satisfy the required argument; the parse error fires before it is used.
        var (exit, output, error, exited) = RunCli("health", "Newtonsoft.Json", "--json", "--rich");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.NotEqual(0, exit);
        Assert.Contains("--json", error);
        Assert.Contains("--rich", error);
        Assert.DoesNotContain(EscByte, output);   // stdout stays clean on a parse error
    }

    [Fact]
    public void ScanPackage_JsonAndRich_IsRejectedBeforeHandlerRuns()
    {
        // --json and --rich are mutually-exclusive format selectors (ADR 0014); the scan-package verb shares the
        // same parse validator as analyze. The combination must be rejected with a non-zero exit and a message on
        // stderr, keeping stdout clean — before any handler (or package open) runs.
        var nupkg = BuildMinimalNupkg();
        try
        {
            var (exit, output, error, exited) = RunCli("scan-package", nupkg, "--json", "--rich");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.NotEqual(0, exit);
            Assert.Contains("--json", error);
            Assert.Contains("--rich", error);
            Assert.DoesNotContain(EscByte, output);   // stdout stays clean on a parse error
        }
        finally
        {
            TryDelete(nupkg);
        }
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

    // Standard nuspec namespace required by NuGet's NuspecReader (used by NuGetPackage.Open to read identity).
    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
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

    // Writes a minimal, valid .nupkg to a unique temp path using pure BCL zip — no NuGet client, no network,
    // no project reference to the PackageAnalysis test harness. The only structure NuGetPackage.Open needs is a
    // root-level "<id>.nuspec" carrying the standard nuspec namespace plus id/version (authors/description keep
    // the identity read clean; the empty dependency group matches a real manifest). No payload dll is included:
    // a nuspec-only package opens fine and produces a clean, finding-free report — ideal for the ASCII assertion.
    private static string BuildMinimalNupkg()
    {
        const string id = "SilvergunCiSmoke";
        const string nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>CI-safety smoke package.</description>
                <dependencies>
                  <group targetFramework="netstandard2.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-cismoke-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry($"{id}.nuspec");
            using var s = entry.Open();
            var bytes = Encoding.UTF8.GetBytes(nuspec);
            s.Write(bytes, 0, bytes.Length);
        }
        return path;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion
}
