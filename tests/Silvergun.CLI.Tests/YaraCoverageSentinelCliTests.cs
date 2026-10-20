namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using Xunit;

/// <summary>
/// ADR 0032 decision 9 through the real <c>scan-package</c> verb, in a child process: <b>the coverage sentinel is
/// never a finding on any surface</b> — the human report, <c>--json</c>, or the stderr advisory. The YARA backend in
/// the child is the CLI backend pointed at the NuGet suite's <c>FakeYaraProbe</c>, which — like real yara — prints a
/// <c>SilvergunCoverageSentinel_&lt;32 hex&gt; [] &lt;file&gt;</c> line for every file its recursive pass "scans" (the
/// name read from the rules file the scanner hands it), so the batch output these runs parse is dense with sentinel
/// records. See <see cref="YaraIncompleteScanCliTests"/> for why this needs a child process.
///
/// <para>Two shapes: every file covered (Completed, one finding), and one file whose coverage line is withheld — the
/// file a real <c>yara -r</c> drops at its global <c>--timeout</c> deadline — so it is re-scanned individually and its
/// hit joins the report (Completed, two findings). The second is red against the pre-decision-9 CLI by assertion: it
/// reported one finding.</para>
/// </summary>
public sealed class YaraCoverageSentinelCliTests
{
    #region Methods
    [Fact]
    public void ScanPackage_WhenEveryFileIsCovered_NoSurfaceShowsTheSentinel()
    {
        var human = Run(withheld: false);
        var json = Run(withheld: false, "--json");

        Assert.True(human.Exited && json.Exited, "CLI did not exit within the timeout.");
        AssertNoSentinel(human);
        AssertNoSentinel(json);
        Assert.Contains("Fake_Rule", human.Output, StringComparison.Ordinal);
        Assert.Equal(new (string?, string?)[] { ("Fake_Rule", "content/payload.bin") }, Findings(json.Output, out var status));
        Assert.Equal("Completed", status);
    }

    [Fact]
    public void ScanPackage_WhenAFileHasNoCoverageLine_ReScansItAndNoSurfaceShowsTheSentinel()
    {
        var human = Run(withheld: true);
        var json = Run(withheld: true, "--json");

        Assert.True(human.Exited && json.Exited, "CLI did not exit within the timeout.");
        AssertNoSentinel(human);
        AssertNoSentinel(json);
        Assert.Contains("late.bin", human.Output, StringComparison.Ordinal);
        Assert.Equal(new (string?, string?)[] { ("Fake_Rule", "content/late.bin"), ("Fake_Rule", "content/payload.bin") }, Findings(json.Output, out var status));
        Assert.Equal("Completed", status);
    }
    #endregion

    #region Methods — helpers
    private static void AssertNoSentinel(CliRun run)
    {
        Assert.DoesNotContain(SentinelPrefix, run.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(SentinelPrefix, run.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static (string?, string?)[] Findings(string json, out string? status)
    {
        using var doc = JsonDocument.Parse(json);
        status = doc.RootElement.GetProperty("YaraScanStatus").GetString();
        return doc.RootElement.GetProperty("YaraFindings").EnumerateArray()
            .Select(f => (f.GetProperty("RuleName").GetString(), f.GetProperty("RelativePath").GetString()))
            .OrderBy(f => f.Item2, StringComparer.Ordinal)
            .ToArray();
    }

    // One scan-package run of a fresh package (nuspec + content/payload.bin + content/late.bin). The probe prints a
    // batch hit on payload.bin and, on a single-file scan, a hit on whatever it is handed; `withheld` withholds
    // late.bin's coverage line so the scanner has to re-scan it on its own.
    private static CliRun Run(bool withheld, params string[] flags)
    {
        var nupkg = BuildNupkg("SilvergunYaraSentinel");
        try
        {
            var psi = new ProcessStartInfo(CliExe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                StandardOutputEncoding = Encoding.Latin1,
                StandardErrorEncoding = Encoding.Latin1,
            };
            foreach (var arg in new[] { "scan-package", nupkg, "--no-vulns" }.Concat(flags))
                psi.ArgumentList.Add(arg);

            // Built explicitly: nothing YARA-related is inherited from this host.
            psi.Environment["NO_COLOR"] = "1";
            psi.Environment["SILVERGUN_YARA_PATH"] = ProbeExe;
            psi.Environment.Remove("SILVERGUN_YARAC_PATH");
            foreach (var knob in psi.Environment.Keys.Where(k => k.StartsWith("SILVERGUN_FAKEYARA_", StringComparison.Ordinal)).ToArray())
                psi.Environment.Remove(knob);
            psi.Environment["SILVERGUN_FAKEYARA_EXIT_CODE"] = "0";
            psi.Environment["SILVERGUN_FAKEYARA_BATCH_ECHO_RULE"] = "Fake_Rule";
            psi.Environment["SILVERGUN_FAKEYARA_BATCH_ECHO_NAME"] = "payload.bin";
            psi.Environment["SILVERGUN_FAKEYARA_ECHO_RULE"] = "Fake_Rule";
            if (withheld)
                psi.Environment["SILVERGUN_FAKEYARA_SENTINEL_SKIP"] = "late.bin";

            using var process = Process.Start(psi)!;
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return new CliRun(-1, string.Empty, string.Empty, false);
            }

            return new CliRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
        }
        finally
        {
            try { if (File.Exists(nupkg)) File.Delete(nupkg); } catch { /* best-effort temp cleanup */ }
        }
    }

    private static string BuildNupkg(string id)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>ADR 0032 decision 9 coverage-sentinel test package.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-yara-sentinel-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            Write(zip, "content/payload.bin", Encoding.UTF8.GetBytes("ordinary content, nothing real matches this\n"));
            Write(zip, "content/late.bin", Encoding.UTF8.GetBytes("ordinary content, nothing real matches this either\n"));
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }
    #endregion

    #region Nested types
    private sealed record CliRun(int Exit, string Output, string Error, bool Exited);
    #endregion

    #region Fields
    private const string SentinelPrefix = "SilvergunCoverageSentinel_";

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe");

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
