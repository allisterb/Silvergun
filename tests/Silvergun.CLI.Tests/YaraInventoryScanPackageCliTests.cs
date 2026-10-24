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
/// ADR 0034 through the real <c>scan-package</c> verb, in a child process: <b>an extracted file deleted before YARA
/// reaches it makes the YARA scan incomplete on every surface</b> — the stderr advisory says "did NOT complete" (with the
/// other files' matches) or "did NOT run" (when nothing was left to match), <c>--json</c> reads <c>Unavailable</c> with a
/// reason that names the file as removed (leading with "… no longer exists (removed after it was listed)", I4), and
/// <c>--strict</c> exits non-zero.
///
/// <para><b>How a file is deleted mid-run in a process we do not control.</b> The child is the real CLI (net10.0, so its
/// backend is <c>YaraCliScanner</c>) pointed at the NuGet suite's <c>FakeYaraProbe</c> as both <c>yara</c> and
/// <c>yarac</c>. The probe's <c>SILVERGUN_FAKEYARA_YARAC_DELETE</c> knob deletes the named extracted files when the
/// scanner compiles its batch ruleset — the first thing a YARA scan does, after <c>NuGetPackage.Open</c> took the
/// package's YARA inventory and before any enumeration of the backend's own. That is exactly the gap the inventory
/// covers: wired back to <c>ScanDirectory</c>, the backend would enumerate after the deletion and the package would read
/// Completed. The child gets a private temp directory (TEMP, TMP, TMPDIR), so its extraction directory is the only one
/// the knob can see, and it is removed afterwards.</para>
///
/// <para><c>--no-vulns</c> keeps every run offline and leaves the known-vulnerability check NotChecked, which is itself an
/// incompleteness (so <c>--strict</c> is never 0 here); the advisory and the report's YARA status are what tell the
/// cases apart, and the control run (nothing deleted) shows the advisory is about the deletion.</para>
/// </summary>
public sealed class YaraInventoryScanPackageCliTests
{
    #region Methods
    // One extracted file deleted, another still matching: "did NOT complete; 1 match(es)", and --strict gates on the match.
    [Fact]
    public void ScanPackage_WhenAnExtractedFileIsDeletedBeforeYara_SaysDidNotComplete_AndStrictExitsNonZero()
    {
        var run = Run(delete: "gone.bin", "--strict");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.True(run.Exit == 2, $"expected exit 2 (a YARA match gates --strict), got {run.Exit}.\nstderr:\n{run.Error}");
        var advisory = Advisory(run);
        Assert.StartsWith("scan-package: YARA malware-signature scanning did NOT complete; 1 match(es) were found in the files that were scanned", advisory, StringComparison.Ordinal);
        Assert.Contains("did not cover: 1 of them no longer exists (removed after it was listed): '", advisory, StringComparison.Ordinal);
        Assert.Contains("gone.bin", advisory[advisory.IndexOf("no longer exists", StringComparison.Ordinal)..], StringComparison.Ordinal);
    }

    // The same run's report: Unavailable, the surviving file's finding kept, the reason naming the gone file as removed.
    [Fact]
    public void ScanPackage_WhenAnExtractedFileIsDeletedBeforeYara_TheJsonReportIsUnavailable_WithTheFindingAndTheReason()
    {
        var run = Run(delete: "gone.bin", "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        using var json = JsonDocument.Parse(run.Output);
        var root = json.RootElement;
        Assert.Equal("Unavailable", root.GetProperty("YaraScanStatus").GetString());
        var finding = Assert.Single(root.GetProperty("YaraFindings").EnumerateArray().ToArray());
        Assert.Equal("content/payload.bin", finding.GetProperty("RelativePath").GetString());
        var reason = root.GetProperty("YaraUnavailableReason").GetString()!;
        // The missing clause leads the message (I4, N2), so the bounded reason keeps it.
        Assert.StartsWith("YARA could not scan 1 of 1 file(s) that its recursive pass did not cover: 1 of them no longer exists (removed after it was listed): '", reason, StringComparison.Ordinal);
        Assert.Contains("gone.bin", reason[reason.IndexOf("no longer exists", StringComparison.Ordinal)..], StringComparison.Ordinal);
        Assert.DoesNotContain("the others", reason, StringComparison.Ordinal);
    }

    // Every extracted file deleted: nothing left to match, so "did NOT run" — never a clean, completed scan — and --strict
    // exits 3 (incomplete).
    [Fact]
    public void ScanPackage_WhenEveryExtractedFileIsDeletedBeforeYara_SaysDidNotRun_AndStrictExitsNonZero()
    {
        var run = Run(delete: "*", "--strict");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.True(run.Exit == 3, $"expected exit 3 (incomplete), got {run.Exit}.\nstderr:\n{run.Error}");
        var advisory = Advisory(run);
        Assert.StartsWith("scan-package: YARA malware-signature scanning did NOT run", advisory, StringComparison.Ordinal);
        Assert.Contains("could not scan 4 of 4 file(s)", advisory, StringComparison.Ordinal);
        // The reason is bounded, and since I4 (N2) the missing clause leads it, so the advisory still says why.
        Assert.Contains("did not cover: 4 of them no longer exist (each removed after it was listed): '", advisory, StringComparison.Ordinal);
    }

    [Fact]
    public void ScanPackage_WhenEveryExtractedFileIsDeletedBeforeYara_TheJsonReportIsUnavailable_WithNoFindings()
    {
        var run = Run(delete: "*", "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        using var json = JsonDocument.Parse(run.Output);
        Assert.Equal("Unavailable", json.RootElement.GetProperty("YaraScanStatus").GetString());
        Assert.Empty(json.RootElement.GetProperty("YaraFindings").EnumerateArray());
    }

    // The control: the same package, fake and knobs, with nothing deleted (the knob names no file in it). YARA completes
    // with the payload's finding and there is no YARA advisory at all — so the advisories above are the deletion's.
    [Fact]
    public void ScanPackage_WhenNothingIsDeleted_YaraCompletes_AndThereIsNoYaraAdvisory()
    {
        var run = Run(delete: "no-such-file.bin", "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.DoesNotContain("YARA malware-signature scanning did NOT", run.Error, StringComparison.Ordinal);
        using var json = JsonDocument.Parse(run.Output);
        Assert.Equal("Completed", json.RootElement.GetProperty("YaraScanStatus").GetString());
        Assert.Equal("content/payload.bin", Assert.Single(json.RootElement.GetProperty("YaraFindings").EnumerateArray().ToArray()).GetProperty("RelativePath").GetString());
    }
    #endregion

    #region Methods — helpers
    private static string Advisory(CliRun run)
    {
        var line = Assert.Single(run.Error.Split('\n'), l => l.StartsWith("scan-package: YARA malware-signature scanning did NOT", StringComparison.Ordinal)).TrimEnd('\r');
        var offender = line.FirstOrDefault(c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F);
        Assert.True(offender == '\0', $"the advisory carried raw control character U+{(int)offender:X4}.");
        return line;
    }

    // One scan-package run of a fresh package (nuspec, content/payload.bin which the fake engine "matches",
    // content/gone.bin, content/notes.txt) in a private temp directory, with `delete` handed to the probe's yarac.
    private static CliRun Run(string delete, params string[] flags)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"silvergun-yara-inv-cli-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);
        try
        {
            var nupkg = BuildNupkg(temp, "SgInv");   // short: the report's reason is bounded to 512 chars
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

            // The child's environment is built explicitly: nothing YARA-related is inherited from this host.
            psi.Environment["NO_COLOR"] = "1";
            foreach (var variable in new[] { "TEMP", "TMP", "TMPDIR" })
                psi.Environment[variable] = temp;
            foreach (var knob in ProbeKnobs)
                psi.Environment.Remove(knob);
            psi.Environment["SILVERGUN_YARA_PATH"] = ProbeExe;
            psi.Environment["SILVERGUN_YARAC_PATH"] = ProbeExe;
            psi.Environment["SILVERGUN_FAKEYARA_EXIT_CODE"] = "0";
            psi.Environment["SILVERGUN_FAKEYARA_BATCH_ECHO_RULE"] = "Fake_Rule";
            psi.Environment["SILVERGUN_FAKEYARA_BATCH_ECHO_NAME"] = "payload.bin";
            psi.Environment["SILVERGUN_FAKEYARA_YARAC_DELETE"] = delete;

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
            try { Directory.Delete(temp, recursive: true); } catch { /* best-effort temp cleanup */ }
        }
    }

    private static string BuildNupkg(string dir, string id)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>ADR 0034 extraction-inventory test package.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(dir, $"{id}.1.0.0.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            Write(zip, "content/payload.bin", Encoding.UTF8.GetBytes("ordinary content, nothing real matches this\n"));
            Write(zip, "content/gone.bin", Encoding.UTF8.GetBytes("ordinary content, deleted before YARA runs\n"));
            Write(zip, "content/notes.txt", Encoding.UTF8.GetBytes("ordinary text\n"));
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
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private static readonly string ProbeExe =
        ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe");

    private static readonly string[] ProbeKnobs =
    [
        "SILVERGUN_FAKEYARA_EXIT_CODE", "SILVERGUN_FAKEYARA_SLEEP_MS", "SILVERGUN_FAKEYARA_LOG", "SILVERGUN_FAKEYARA_STDOUT",
        "SILVERGUN_FAKEYARA_ECHO_RULE", "SILVERGUN_FAKEYARA_BATCH_ECHO_RULE", "SILVERGUN_FAKEYARA_BATCH_ECHO_NAME",
        "SILVERGUN_FAKEYARA_BATCH_GHOST", "SILVERGUN_FAKEYARA_BATCH_STDERR", "SILVERGUN_FAKEYARA_SENTINEL_SKIP",
        "SILVERGUN_FAKEYARA_SENTINEL_FORGE", "SILVERGUN_FAKEYARA_SENTINEL_GHOST", "SILVERGUN_FAKEYARA_SINGLE_EXIT_CODE",
        "SILVERGUN_FAKEYARA_YARAC_EXIT_CODE", "SILVERGUN_FAKEYARA_SINGLE_SLEEP_MS", "SILVERGUN_FAKEYARA_SINGLE_FAIL",
        "SILVERGUN_FAKEYARA_BATCH_ECHO_REPEAT", "SILVERGUN_FAKEYARA_YARAC_DELETE",
    ];

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
