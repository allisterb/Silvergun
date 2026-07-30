namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

/// <summary>
/// End-to-end (child-process) tests for the ADR 0024 exit-code contract and the additive <c>--json</c> completeness
/// block. These exercise the real <c>Silvergun.CLI</c> entrypoint, so they cover the wiring that the in-process seam
/// tests (<see cref="CompletenessExitCodeTests"/>) replicate: option parsing for <c>--allow-incomplete</c>, the
/// assessment reaching both the renderer and the exit code, and the stderr disclosure.
/// <para>
/// Every scan runs <c>--no-vulns --no-yara</c> so the run is fully offline and deterministic; the packages are built
/// with pure BCL zip. Each CLI invocation is its own process, which is also the only safe way to run analysis over a
/// hostile/non-PE input: a CCI <c>Debug.Assert</c> routes to <c>Environment.FailFast</c> (ADR 0021, measured exit 35)
/// and would take the whole test run down in-process.
/// </para>
/// </summary>
public sealed class CompletenessCliTests
{
    #region Methods — exit 3 end-to-end
    // The vulnerability check did not run, nothing was found, --strict was NOT passed: exit 3 anyway. Exit 3 is a
    // statement about the tool's coverage, not a policy verdict, so it is deliberately not gated on --strict.
    [Fact]
    public void ScanPackage_WhenVulnerabilityCheckDidNotRun_ExitsThreeWithoutStrict()
    {
        var nupkg = BuildNupkg("SilvergunCompletenessEmpty");
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("scan-package", nupkg, "--no-vulns", "--no-yara");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            // The whole verdict LINE (see FooterHeadline), in the plain-ASCII form NO_COLOR selects: this states the
            // headline itself reads "Not verified" and names the gap, where Contains("Not verified") was a statement
            // about stdout as a whole.
            Assert.Equal(
                FooterHeadline.NotVerified(rich: false, "the known-vulnerability check did not run"),
                FooterHeadline.Of(stdout));
            // The stderr disclosure is exact (it is not width-wrapped like the report), so it pins the wording.
            Assert.Contains(
                "scan-package: analysis INCOMPLETE - the known-vulnerability check did not run.", stderr);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    // --allow-incomplete suppresses the GATE, never the DISCLOSURE: exit 0, but the report still says "Not verified"
    // and stderr still names the gap (and says the exit code was not gated on it).
    [Fact]
    public void ScanPackage_WithAllowIncomplete_ExitsZeroAndStillDisclosesCaveats()
    {
        var nupkg = BuildNupkg("SilvergunCompletenessAllowed");
        try
        {
            var (exit, stdout, stderr, exited) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--allow-incomplete");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
            Assert.Equal(                                                                   // disclosure in the report
                FooterHeadline.NotVerified(rich: false, "the known-vulnerability check did not run"),
                FooterHeadline.Of(stdout));
            Assert.Contains("the known-vulnerability check did not run", stderr);          // ... and on stderr
            Assert.Contains("--allow-incomplete given; exit code NOT gated on this.", stderr);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    // A package whose only binary is not a loadable managed assembly: nothing was looked inside it. Before ADR 0024
    // this read "Clean" — native payloads are a known malware vector, so that was a false all-clear. The caveat must
    // state only the fact ("could not be analysed"), leaving the verbatim reason to the per-assembly tree node.
    [Fact]
    public void ScanPackage_WhenOnlyBinaryCouldNotBeAnalysed_IsNotVerifiedAndExitsThree()
    {
        var nupkg = BuildNupkg(
            "SilvergunCompletenessNative", ("lib/net10.0/notmanaged.dll", NotManagedBytes));
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("scan-package", nupkg, "--no-vulns", "--no-yara");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            // Two caveats (the unanalysable file AND --no-vulns) make this headline longer than the report width, so
            // it wraps and cannot be compared whole; the verdict is asserted on the single glyph-prefixed line
            // instead of by DoesNotContain("Clean"), which the caveat's own file path could defeat.
            Assert.True(
                FooterHeadline.IsNotVerified(FooterHeadline.Of(stdout)),
                "the scan-package footer's verdict is not 'Not verified'.");
            Assert.Contains("1 of 1 file(s) could not be analysed", stderr);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    // The 1-beats-3 boundary, and the reason the failed-metadata-read caveat has no end-to-end analyze test.
    // Measured 2026-07-29: Program.RunAnalyze reads metadata only AFTER AssemblyAnalyzer.Load has succeeded, and the
    // two apply the SAME acceptance test to the same path — a fresh PeReader.DefaultHost plus an identical
    // Dummy.Module/Dummy.Assembly rejection (AssemblyAnalyzer.cs:61-77 vs AssemblyMetadata.cs:37-50). So an input the
    // metadata read cannot handle fails the load FIRST: exit 1 with NO report at all, never exit 3 (ADR 0024: "1 beats
    // both — if we could not produce a report there is nothing to qualify"). The metadata caveat itself is therefore
    // covered at the assessment/footer/seam level, not faked here.
    // CI-relevant consequence, asserted below: exit 1 emits no report, so a missing or empty report must never be
    // read as clean.
    [Fact]
    public void Analyze_WhenTheInputCannotBeLoaded_ExitsOneWithNoReport()
    {
        var path = Path.Combine(Path.GetTempPath(), $"silvergun-notmanaged-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(path, NotManagedBytes);
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("analyze", path);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(1, exit);
            // No verdict of ANY kind was printed — a stronger statement than "the words Clean / Not verified are
            // absent from stdout", and one the rejected file's own path cannot trip.
            Assert.Empty(FooterHeadline.AllIn(stdout));
            Assert.DoesNotContain("Assessment", stdout);          // no footer, because there is no report
            Assert.Contains("not a valid CLR module or assembly", stderr);
        }
        finally
        {
            TryDelete(path);
        }
    }

    // Scope boundary (ADR 0024 non-goals): --allow-incomplete exists on analyze and scan-package ONLY. check-squat's
    // popularity-source availability and the advisory health verb are explicitly out of scope, so the flag must not
    // quietly appear there — an accepted-but-ignored flag would imply a completeness contract those verbs do not have.
    // The parse error fires before any handler, so neither nuget.org nor the GitHub API is touched.
    [Theory]
    [InlineData("check-squat")]
    [InlineData("health")]
    public void AllowIncomplete_IsNotAnOptionOnVerbsWithoutACompletenessContract(string verb)
    {
        var (exit, _, stderr, exited) = RunCli(verb, "Newtonsoft.Json", "--allow-incomplete");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.NotEqual(0, exit);
        Assert.Contains("--allow-incomplete", stderr);
    }
    #endregion

    #region Methods — --json golden stability (spec criterion 6)
    // The completeness block is spliced in TEXTUALLY (Program.WithCompleteness): the report's own canonical JSON is
    // carried over verbatim and one "Completeness" object is inserted before its final "}", so nothing re-serializes
    // the pre-existing properties and their names, values, order and exact bytes are preserved BY CONSTRUCTION. These
    // tests pin that construction rather than trusting it — --json byte-stability is a documented contract (ADR 0024:
    // "additive schema change — do not reorder or rename existing fields"), and it is the kind of property that a
    // later "tidy this up by round-tripping through JsonNode" would silently break. Two separate assertions per verb,
    // deliberately:
    //   1. the additive STRUCTURE (Completeness appended last, exactly once) — order/name stability;
    //   2. the byte stability of the existing fields — formatting stability.
    // Splitting them keeps a failure of one from masking the other. The degenerate/encoder cases of the splice itself
    // are unit-tested in CompletenessJsonSpliceTests.

    [Fact]
    public void Analyze_Json_AppendsCompletenessAsTheLastPropertyOnly()
    {
        var emitted = AnalyzeJson();

        AssertCompletenessIsAppendedLast(emitted);
    }

    [Fact]
    public void Analyze_Json_KeepsExistingFieldsByteStable()
    {
        var emitted = AnalyzeJson();
        var restored = AssemblyAnalysisReport.FromJson(emitted);
        Assert.NotNull(restored);

        AssertExistingFieldsAreAByteStablePrefix(restored!.ToJson(), emitted);
    }

    [Fact]
    public void ScanPackage_Json_AppendsCompletenessAsTheLastPropertyOnly()
    {
        var emitted = ScanPackageJson();

        AssertCompletenessIsAppendedLast(emitted);
    }

    [Fact]
    public void ScanPackage_Json_KeepsExistingFieldsByteStable()
    {
        var emitted = ScanPackageJson();
        var restored = PackageCapabilityReport.FromJson(emitted);
        Assert.NotNull(restored);

        AssertExistingFieldsAreAByteStablePrefix(restored!.ToJson(), emitted);
    }

    // Spec criterion 5: the coverage numbers must be machine-readable, not merely printed — CI reads JSON.
    [Fact]
    public void Analyze_Json_CompletenessCarriesCoverageNumbers()
    {
        using var doc = JsonDocument.Parse(AnalyzeJson());
        var completeness = doc.RootElement.GetProperty("Completeness");

        Assert.True(completeness.GetProperty("IsComplete").GetBoolean());   // exit 0 above ⇒ the assessment agrees
        Assert.True(completeness.GetProperty("MethodsTotal").GetInt32() > 0);
        Assert.Equal(
            completeness.GetProperty("MethodsTotal").GetInt32(),
            completeness.GetProperty("MethodsAnalyzed").GetInt32() + completeness.GetProperty("MethodsSkipped").GetInt32());
        Assert.Empty(completeness.GetProperty("Caveats").EnumerateArray());
    }

    // The canonical serializer output, minus its closing brace, must be a byte-exact prefix of the emitted JSON.
    // Divergences are reported by offset with a context window (and counted) so a failure names the offending
    // property and its class of difference, instead of dumping 100 KB of JSON into the test log.
    private static void AssertExistingFieldsAreAByteStablePrefix(string canonical, string emitted)
    {
        var prefix = canonical[..canonical.LastIndexOf('}')].TrimEnd();
        Assert.True(
            emitted.Length >= prefix.Length,
            $"emitted --json is shorter than the canonical report JSON ({emitted.Length} < {prefix.Length}).");

        var divergences = Divergences(prefix, emitted);
        var shown = string.Join(
            "; ",
            divergences.Take(2).Select(i => $"offset {i}: canonical '{Window(prefix, i)}' vs emitted '{Window(emitted, i)}'"));
        // Diagnostic only (the assertion below is on the RAW comparison): a single inserted escape shifts every later
        // character, so the raw count overstates the number of distinct problems. Re-comparing with "+" mapped
        // back to "+" attributes the divergence: if that count is 0, the ONLY instability is the JSON writer escaping
        // '+' — which STJ's DateTimeOffset converter writes literally but its string writer escapes.
        var afterUnescapingPlus = Divergences(prefix, emitted.Replace("\\u002B", "+")).Length;

        Assert.True(
            divergences.Length == 0,
            $"--json is NOT byte-stable for pre-existing fields: {divergences.Length} differing character(s) "
            + $"({afterUnescapingPlus} remain after mapping \\u002B back to '+'). {shown}");

        // Nothing but the additive property may follow the pre-existing fields.
        Assert.StartsWith(",", emitted[prefix.Length..], StringComparison.Ordinal);
    }

    // One analyze --json run, validated as a successful, complete analysis (so the golden assertions are comparing
    // a real report and not an error path).
    private static string AnalyzeJson()
    {
        var (exit, stdout, _, exited) = RunCli("analyze", TargetAssembly, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, exit);
        return stdout.TrimEnd('\r', '\n');   // Console.WriteLine's trailing newline is not part of the report
    }

    private static string ScanPackageJson()
    {
        var nupkg = BuildNupkg("SilvergunCompletenessJson");
        try
        {
            var (exit, stdout, _, exited) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--json", "--allow-incomplete");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
            return stdout.TrimEnd('\r', '\n');
        }
        finally
        {
            TryDelete(nupkg);
        }
    }

    private static void AssertCompletenessIsAppendedLast(string emitted)
    {
        using var doc = JsonDocument.Parse(emitted);
        var properties = doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray();

        Assert.Equal("Completeness", properties[^1]);                  // appended, never inserted
        Assert.Single(properties, name => name == "Completeness");     // and exactly once
    }

    // Offsets at which the expected prefix and the actual text differ (a shorter actual counts as differing).
    private static int[] Divergences(string expectedPrefix, string actual) =>
        [.. Enumerable.Range(0, expectedPrefix.Length)
            .Where(i => i >= actual.Length || expectedPrefix[i] != actual[i])];

    private static string Window(string text, int index) =>
        text.Substring(Math.Max(0, index - 30), Math.Min(60, text.Length - Math.Max(0, index - 30)));
    #endregion

    #region Methods — process/package helpers
    // Launches the CLI with both streams captured and stdin closed (so a stdin read would deadlock rather than pass),
    // NO_COLOR set, and both streams drained asynchronously to avoid a full-buffer deadlock. Latin1 keeps the
    // byte<->char mapping 1:1, which the --json golden comparison relies on (the serializer escapes non-ASCII).
    private static (int Exit, string Output, string Error, bool Exited) RunCli(params string[] args)
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
        var exited = process.WaitForExit(TimeoutMs);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return (-1, string.Empty, string.Empty, false);
        }

        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }

    // Writes a minimal valid .nupkg (root "<id>.nuspec" with the standard namespace) plus the given extra entries,
    // using pure BCL zip — no NuGet client, no network. Mirrors CiSafetyReportTests.BuildMinimalNupkg.
    private static string BuildNupkg(string id, params (string Entry, byte[] Bytes)[] extra)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>Completeness contract test package.</description>
                <dependencies>
                  <group targetFramework="netstandard2.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-completeness-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            foreach (var (entry, bytes) in extra)
                Write(zip, entry, bytes);
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    // A managed assembly guaranteed present in the test output (referenced transitively) to analyze.
    private static readonly string TargetAssembly =
        Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.dll");

    // Arbitrary non-PE bytes standing in for a native/unmanaged dll: inventoried as an assembly by extension, but
    // no managed load can succeed, so PackageScanner records a SkipReason and produces no CapabilityReport.
    private static readonly byte[] NotManagedBytes = [0x00, 0x01, 0x02, 0x03, 0x2A, 0x7F, 0x55, 0xAA, 0x13, 0x37];

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;
    #endregion
}
