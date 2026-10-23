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
/// ADR 0032 through the real <c>scan-package</c> verb, in a child process: <b>a YARA scan that could not finish but
/// did find something must gate <c>--strict</c> (exit 2), even with <c>--allow-incomplete</c></b>, and must say so on
/// every surface — the exit code, the stderr advisory, the human report and <c>--json</c>.
///
/// <para><b>Why a child process.</b> The stderr advisory is written inline in <c>Program.RunScanPackage</c>, and the
/// YARA backend there is the process-wide <c>YaraScannerFactory.Shared</c>, which reads <c>SILVERGUN_YARA_PATH</c>
/// once per process — so neither can be steered from inside this test host. The child is the real CLI (net10.0, so
/// its backend is <c>YaraCliScanner</c>) pointed at the NuGet suite's <c>FakeYaraProbe</c> as its <c>yara</c>, which
/// stages the recursive pass's output at run time: a hit on the package's <c>content/payload.bin</c>, plus a hit on a
/// sibling <c>ghost.bin</c> that does not exist. That second line trips the ADR 0029 decision 17 guard — the scan is
/// genuinely incomplete — and is itself reported as a finding under the echoed path (ADR 0032 decision 4). Nothing
/// is analysed in-process and nothing real matches: the payload is plain text. Runs on every platform.</para>
///
/// <para><b>Discriminating against the pre-ADR-0032 code by assertion, not by compile error.</b> Nothing here uses
/// an API that ADR 0032 added. Before it, the same staged run reported <c>Unavailable</c> with zero findings, so
/// <c>--strict</c> exited 3 and <c>--strict --allow-incomplete</c> exited 0 — the ADR's exact Context.</para>
///
/// <para><c>--no-vulns</c> keeps every run offline; it also leaves the known-vulnerability check NotChecked, which is
/// itself an incompleteness. That does not weaken anything below: the exit-2 assertions are the discriminating ones
/// (a tripped gate beats incompleteness), and the exit-3 case is 3 for both reasons.</para>
/// </summary>
public sealed class YaraIncompleteScanCliTests
{
    #region Methods — Unavailable WITH findings
    // The ADR's headline row: without --strict the incomplete scan is exit 3, as before.
    [Fact]
    public void ScanPackage_IncompleteYaraScanWithHits_WithoutStrict_ExitsThree()
    {
        var run = Run(withHits: true);

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(3, run.Exit);
    }

    // --strict: a YARA hit gates, however incomplete the rest of the scan. Was 3 before ADR 0032 (zero findings).
    [Fact]
    public void ScanPackage_IncompleteYaraScanWithHits_WithStrict_ExitsTwo()
    {
        var run = Run(withHits: true, "--strict");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.True(run.Exit == 2, $"expected exit 2, got {run.Exit}.\nstderr:\n{run.Error}");
    }

    // --strict --allow-incomplete: --allow-incomplete suppresses only the INCOMPLETENESS gate, so it can no longer turn
    // a detection into a pass. Was 0 before ADR 0032 — the most dangerous row of the ADR's Context.
    [Fact]
    public void ScanPackage_IncompleteYaraScanWithHits_WithStrictAndAllowIncomplete_ExitsTwo()
    {
        var run = Run(withHits: true, "--strict", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.True(run.Exit == 2, $"expected exit 2, got {run.Exit}.\nstderr:\n{run.Error}");
    }

    // The stderr advisory says what actually happened — the scan did not complete, and found N matches — rather than
    // the "did NOT run" line, which would contradict the findings printed in the same run.
    [Fact]
    public void ScanPackage_IncompleteYaraScanWithHits_StderrSaysIncompleteWithTheMatchCount()
    {
        var run = Run(withHits: true);

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Contains(
            "scan-package: YARA malware-signature scanning did NOT complete; 2 match(es) were found in the files that were scanned",
            run.Error, StringComparison.Ordinal);
        Assert.DoesNotContain("did NOT run", run.Error, StringComparison.Ordinal);
        AssertNoRawControlCharacters(run.Error);
    }

    // The human report (default, no --rich) shows the findings — both of them, the unattributable one under its
    // echoed path — together with the incomplete warning, and stays 7-bit ASCII with no raw control characters.
    // Phrases are asserted as short tokens: the child's console width is not ours to set, so long lines may wrap
    // (exact wording is pinned in-process by YaraIncompleteScanRendererTests).
    [Fact]
    public void ScanPackage_IncompleteYaraScanWithHits_HumanReportShowsTheFindingsAndTheWarning()
    {
        var run = Run(withHits: true);

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Contains("Fake_Rule", run.Output, StringComparison.Ordinal);
        Assert.Contains("payload.bin", run.Output, StringComparison.Ordinal);
        Assert.Contains("ghost.bin", run.Output, StringComparison.Ordinal);
        Assert.Contains("INCOMPLETE", run.Output, StringComparison.Ordinal);
        Assert.Contains("[!]", run.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("scan did NOT run", run.Output, StringComparison.Ordinal);
        var offender = run.Output.FirstOrDefault(c => c > (char)0x7F);
        Assert.True(offender == '\0', $"default output must be 7-bit ASCII; found U+{(int)offender:X4}.");
        AssertNoRawControlCharacters(run.Output);
    }

    // --json carries the findings WITH status Unavailable — the combination a consumer must read as "these hits are
    // real; the rest is not verified" (ADR 0032 decision 3: no new enum value).
    [Fact]
    public void ScanPackage_IncompleteYaraScanWithHits_JsonCarriesTheFindingsWithStatusUnavailable()
    {
        var run = Run(withHits: true, "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, run.Exit);   // no --strict, and --allow-incomplete: the gate is off, the facts are not
        AssertNoRawControlCharacters(run.Output);
        using var json = JsonDocument.Parse(run.Output);
        var root = json.RootElement;
        Assert.Equal("Unavailable", root.GetProperty("YaraScanStatus").GetString());
        var paths = root.GetProperty("YaraFindings").EnumerateArray()
            .Select(f => (Rule: f.GetProperty("RuleName").GetString(), Path: f.GetProperty("RelativePath").GetString()))
            .OrderBy(f => f.Path, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new (string?, string?)[] { ("Fake_Rule", "content/ghost.bin"), ("Fake_Rule", "content/payload.bin") }, paths);
    }
    #endregion

    #region Methods — Unavailable WITHOUT findings (unchanged)
    // The control. The same fake made to exit non-zero: the batch pass produced no usable run, nothing was found, and
    // every surface must read exactly as it did before ADR 0032 — "did NOT run" on stderr, --strict does not gate
    // (exit 3 for incompleteness), and --allow-incomplete still suppresses that to 0.
    [Fact]
    public void ScanPackage_UnavailableYaraScanWithoutHits_IsUnchanged()
    {
        var plain = Run(withHits: false);
        var strict = Run(withHits: false, "--strict");
        var allowed = Run(withHits: false, "--strict", "--allow-incomplete");

        Assert.True(plain.Exited && strict.Exited && allowed.Exited, "CLI did not exit within the timeout.");
        Assert.Equal(3, plain.Exit);
        Assert.Equal(3, strict.Exit);
        Assert.Equal(0, allowed.Exit);
        Assert.Contains(
            "scan-package: YARA malware-signature scanning did NOT run (backend unavailable or failed to initialize)",
            plain.Error, StringComparison.Ordinal);
        Assert.DoesNotContain("did NOT complete", plain.Error, StringComparison.Ordinal);
        Assert.DoesNotContain("Fake_Rule", plain.Output, StringComparison.Ordinal);
    }
    #endregion

    #region Methods — the advisory says why (ADR 0033 polish round)
    // Both variants of the stderr advisory end with " Reason: " and the report's YaraUnavailableReason (escaped and
    // bounded to 512 by the report), on the one advisory line, with no raw control character. --json puts the report on
    // stdout, so the advisory's reason can be compared with the report's own.
    [Theory]
    [InlineData(true, "scan-package: YARA malware-signature scanning did NOT complete; 2 match(es) were found")]
    [InlineData(false, "scan-package: YARA malware-signature scanning did NOT run (backend unavailable or failed to initialize)")]
    public void ScanPackage_TheYaraAdvisory_EndsWithTheReportsReason(bool withHits, string advisoryStart)
    {
        var run = Run(withHits, "--json", "--allow-incomplete");

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        using var json = JsonDocument.Parse(run.Output);
        var reason = json.RootElement.GetProperty("YaraUnavailableReason").GetString();
        Assert.False(string.IsNullOrEmpty(reason), "an Unavailable report carries no reason");
        Assert.True(reason!.Length <= 512, $"the reason is {reason.Length} chars");
        var advisory = Assert.Single(run.Error.Split('\n'), l => l.StartsWith("scan-package: YARA malware-signature scanning did NOT", StringComparison.Ordinal)).TrimEnd('\r');
        Assert.StartsWith(advisoryStart, advisory, StringComparison.Ordinal);
        Assert.EndsWith(" Reason: " + reason, advisory, StringComparison.Ordinal);
        AssertNoRawControlCharacters(advisory);
        AssertNoRawControlCharacters(reason);
    }

    // The reason quotes what the engine reported, which the package controls: here the unattributable hit's file name
    // carries ESC and a bidi override. They reach the advisory and the report escaped, never raw.
    [Fact]
    public void ScanPackage_TheYaraAdvisorysReason_IsEscaped_WhenTheEngineOutputIsHostile()
    {
        var run = RunCore(withHits: true, ghost: "gh" + (char)0x1B + "[31m" + (char)0x202E + "ost.bin", ["--json", "--allow-incomplete"]);

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        var advisory = Assert.Single(run.Error.Split('\n'), l => l.StartsWith("scan-package: YARA malware-signature scanning did NOT", StringComparison.Ordinal)).TrimEnd('\r');
        Assert.Contains(" Reason: ", advisory, StringComparison.Ordinal);
        Assert.Contains(@"gh\x1b[31m", advisory[advisory.IndexOf(" Reason: ", StringComparison.Ordinal)..], StringComparison.Ordinal);   // it IS quoted, escaped
        AssertNoRawControlCharacters(advisory);   // U+202E as UTF-8 read through Latin-1 includes U+0080, which this rejects
        AssertNoRawControlCharacters(run.Output);
    }
    #endregion

    #region Methods — helpers
    // One scan-package run of a fresh package (nuspec + content/payload.bin) against the probe. withHits stages the
    // payload hit plus the unattributable ghost hit; otherwise the probe exits 3 and prints nothing.
    private static CliRun Run(bool withHits, params string[] flags) => RunCore(withHits, "ghost.bin", flags);

    private static CliRun RunCore(bool withHits, string ghost, string[] flags)
    {
        var nupkg = BuildNupkg("SilvergunYaraIncomplete");
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

            // The child's environment is built explicitly: nothing YARA-related is inherited from this host.
            psi.Environment["NO_COLOR"] = "1";
            psi.Environment["SILVERGUN_YARA_PATH"] = ProbeExe;
            psi.Environment.Remove("SILVERGUN_YARAC_PATH");
            foreach (var knob in ProbeKnobs)
                psi.Environment.Remove(knob);
            psi.Environment["SILVERGUN_FAKEYARA_EXIT_CODE"] = withHits ? "0" : "3";
            if (withHits)
            {
                psi.Environment["SILVERGUN_FAKEYARA_BATCH_ECHO_RULE"] = "Fake_Rule";
                psi.Environment["SILVERGUN_FAKEYARA_BATCH_ECHO_NAME"] = "payload.bin";
                psi.Environment["SILVERGUN_FAKEYARA_BATCH_GHOST"] = ghost;
            }

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

    // Everything but CR/LF (and TAB, which a table renderer may legitimately emit) is a raw control character here.
    private static void AssertNoRawControlCharacters(string text)
    {
        var offender = text.FirstOrDefault(c => (c < ' ' && c is not '\r' and not '\n' and not '\t') || c is >= (char)0x7F and <= (char)0x9F);
        Assert.True(offender == '\0', $"output carried raw control character U+{(int)offender:X4}.");
    }

    // A minimal valid .nupkg: the nuspec plus one plain-text content file the fake engine "matches". Pure BCL zip.
    private static string BuildNupkg(string id)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>ADR 0032 incomplete-YARA-scan test package.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-yara-incomplete-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            Write(zip, "content/payload.bin", Encoding.UTF8.GetBytes("ordinary content, nothing real matches this\n"));
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
        "SILVERGUN_FAKEYARA_YARAC_EXIT_CODE",
    ];

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
