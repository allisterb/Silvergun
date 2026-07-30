namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// The payoff criterion of <c>docs/agent/tasks/per-method-body-read-granularity.md</c>, end to end and out of
/// process: an assembly with <b>one</b> unreadable method body must now exit <b>3</b> (analysis incomplete) with a
/// report, where it previously exited <b>1</b> with no report at all — the ADR 0024 completeness wiring finally
/// carrying the signal the IL fix produces. This is the assertion that ties the two tasks together; the IL suite
/// proves the report is produced, and this proves CI is told about it.
/// <para>
/// Run through the real CLI in a child process, both because that is the contract under test (an exit code) and
/// because a neighbouring CCI failure mode is <c>Environment.FailFast</c> (ADR 0021, exit 35), which in-process
/// would take the whole test host down rather than fail one test.
/// </para>
/// <para>
/// The subject is <c>Silvergun.CLI.Tests.BenignFixture</c>, corrupted at test time by
/// <see cref="FatHeaderPatcher"/> — never a committed binary. That fixture is finding-free by construction, which
/// is what lets the footer move cleanly from <b>Clean</b> to <b>Not verified</b>: an assembly with findings would
/// print "Findings present" in both runs and could not tell the two states apart.
/// </para>
/// </summary>
public sealed class UnreadableMethodBodyCliTests : IClassFixture<UnreadableMethodBodyCliTests.PatchedAssembly>
{
    public UnreadableMethodBodyCliTests(PatchedAssembly patched) => this.patched = patched;

    #region Methods — the payoff: exit 3, not 1
    // The control, and the baseline every other assertion is measured against: untouched, the fixture analyses
    // completely and reports Clean. Without this, an exit 3 below could just mean "this assembly never analysed".
    [Fact]
    public void Analyze_OnTheUntouchedFixture_ExitsZeroAndReportsClean()
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", PatchedAssembly.CleanPath);

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, exit);

        // The whole headline LINE, not the bare token: "Clean" anywhere in stdout would also be satisfied by an
        // unrelated occurrence (a type named Cleanup in the findings table, a future section header), so a bare
        // Contains could pass while the headline said something else entirely.
        Assert.Equal(CleanHeadline, Headline(stdout));
        Assert.DoesNotContain("analysis INCOMPLETE", stderr);
    }

    // THE criterion (spec acceptance criterion 2). Pre-fix this exited 1 with no report; it must now exit 3 with a
    // report whose footer discloses the gap. The caveat's count is built from the CLEAN run's own MethodsTotal
    // rather than hard-coded, so the assertion also states that the denominator did not move — and so that adding a
    // method to the fixture cannot turn this into a stale-number failure.
    [Fact]
    public void Analyze_WhenOneMethodBodyIsUnreadable_ExitsThreeAndTheFooterSaysNotVerified()
    {
        var total = CleanMethodsTotal();

        var (exit, stdout, stderr, exited) = RunCli("analyze", patched.PatchedPath);

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(3, exit);

        // Exact headline equality states BOTH halves at once — it says "Not verified", with the measured caveat,
        // and it is therefore not the Clean headline. Asserting DoesNotContain("Clean") instead would be a
        // different (and wrong) statement: it fires on any future line merely containing that substring.
        Assert.Equal(
            FooterHeadline.NotVerified(rich: false, $"1 of {total} method(s) could not be analyzed"),
            Headline(stdout));
        Assert.NotEqual(CleanHeadline, Headline(stdout));
        Assert.Contains($"{total - 1}/{total} (1 not analyzed)", stdout);

        // stderr is not width-wrapped like the report, so it pins the exact wording, the count, and the remedy.
        Assert.Contains(
            $"analyze: analysis INCOMPLETE - 1 of {total} method(s) could not be analyzed. "
            + "Exit code 3; pass --allow-incomplete to downgrade it to 0.",
            stderr);
    }

    // --allow-incomplete suppresses the GATE, never the DISCLOSURE: exit 0, with the same caveat still printed in
    // the report and on stderr.
    [Fact]
    public void Analyze_WhenOneMethodBodyIsUnreadableWithAllowIncomplete_ExitsZeroAndStillDisclosesTheCaveat()
    {
        var total = CleanMethodsTotal();

        var (exit, stdout, stderr, exited) = RunCli("analyze", patched.PatchedPath, "--allow-incomplete");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, exit);
        Assert.Equal(
            FooterHeadline.NotVerified(rich: false, $"1 of {total} method(s) could not be analyzed"),
            Headline(stdout));
        Assert.Contains($"1 of {total} method(s) could not be analyzed", stderr);
        Assert.Contains("--allow-incomplete given; exit code NOT gated on this.", stderr);
    }

    // The machine-readable half of the same run — CI reads JSON, not a footer. Pins the whole coverage shape at
    // once: the denominator is unchanged from the clean run, exactly one method was skipped, the skip entry names
    // the method, and the obfuscation analysis (the second consumer of the same seam) still produced a report
    // instead of collapsing to null.
    [Fact]
    public void Analyze_Json_WhenOneMethodBodyIsUnreadable_ReportsOneSkippedMethodAndAnUnchangedTotal()
    {
        var total = CleanMethodsTotal();

        var (exit, stdout, _, exited) = RunCli("analyze", patched.PatchedPath, "--json");
        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(3, exit);

        using var document = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
        var root = document.RootElement;
        var capabilities = root.GetProperty("Capabilities");
        var completeness = root.GetProperty("Completeness");

        Assert.Equal(total, capabilities.GetProperty("MethodsTotal").GetInt32());
        Assert.Equal(1, capabilities.GetProperty("MethodsSkipped").GetInt32());
        Assert.Equal(total - 1, capabilities.GetProperty("MethodsAnalyzed").GetInt32());
        Assert.Contains(
            PatchedAssembly.PatchedMethodQualifiedName,
            capabilities.GetProperty("SkippedMethods").EnumerateArray().Single().GetString()!);

        Assert.False(completeness.GetProperty("IsComplete").GetBoolean());
        Assert.Equal(
            $"1 of {total} method(s) could not be analyzed",
            completeness.GetProperty("Caveats").EnumerateArray().Single().GetString());

        // The second consumer, still producing a report: a null here would be the obfuscation caveat instead.
        Assert.Equal(JsonValueKind.Object, root.GetProperty("Obfuscation").ValueKind);
    }
    #endregion

    #region Methods — helpers
    // The report's three-tier assessment headline, isolated as a whole LINE so the tests above can assert on it
    // exactly instead of grepping stdout for a bare token. The extraction now lives in the shared FooterHeadline
    // helper, which every CLI footer assertion uses — one definition of "the headline", and Assert.Single there
    // still fails loudly if a report ever prints two verdicts.
    private static string Headline(string stdout) => FooterHeadline.Of(stdout);

    // MethodsTotal of the UNPATCHED fixture, read from its own --json run. Used as the expected denominator so the
    // patched run's numbers are compared against a measurement rather than a literal that could go stale.
    private static int CleanMethodsTotal()
    {
        var (exit, stdout, _, exited) = RunCli("analyze", PatchedAssembly.CleanPath, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(0, exit);

        using var document = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));
        var completeness = document.RootElement.GetProperty("Completeness");

        Assert.True(completeness.GetProperty("IsComplete").GetBoolean(), "The unpatched fixture is not analysing completely.");
        Assert.Equal(0, completeness.GetProperty("MethodsSkipped").GetInt32());
        return completeness.GetProperty("MethodsTotal").GetInt32();
    }

    // Same shape as CompletenessCliTests.RunCli: both streams captured and drained asynchronously, stdin closed so
    // an accidental read deadlocks visibly rather than passing, and NO_COLOR set so the footer text is plain.
    private static (int Exit, string Output, string Error, bool Exited) RunCli(params string[] args)
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

    #region Child types
    /// <summary>
    /// Builds the hostile input once for the class: a temp-directory copy of the benign fixture assembly in which
    /// <c>BenignArithmetic.Accumulate</c>'s fat-header <c>CodeSize</c> is out of range, so CCI throws when — and
    /// only when — that one body is read.
    /// </summary>
    public sealed class PatchedAssembly : IDisposable
    {
        public PatchedAssembly()
        {
            directory = Path.Combine(Path.GetTempPath(), $"silvergun-unreadable-body-cli-{Guid.NewGuid():N}");
            PatchedPath = FatHeaderPatcher.WriteCopyWithUnreadableBody(
                CleanPath,
                Path.Combine(directory, Path.GetFileName(CleanPath)),
                "BenignArithmetic",
                "Accumulate");
        }

        /// <summary>The corrupted copy.</summary>
        public string PatchedPath { get; }

        /// <summary>The untouched fixture assembly, as the build produced it.</summary>
        public static readonly string CleanPath =
            Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll");

        /// <summary>How the skip entry names the corrupted method.</summary>
        public const string PatchedMethodQualifiedName =
            "Silvergun.CLI.Tests.BenignFixture.BenignArithmetic.Accumulate";

        public void Dispose()
        {
            try { Directory.Delete(directory, recursive: true); } catch { /* best-effort temp cleanup */ }
        }

        private readonly string directory;
    }
    #endregion

    #region Fields
    private readonly PatchedAssembly patched;

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    /// <summary>
    /// The one headline an <c>analyze</c> run is allowed to print when the analysis was complete and found nothing,
    /// in the plain-ASCII form <c>NO_COLOR</c> selects. Pinned whole because the point of ADR 0024 is that this exact
    /// line is what "exit 0" means to a reader.
    /// </summary>
    private static readonly string CleanHeadline =
        FooterHeadline.Clean(rich: false, FooterHeadline.AssemblyCleanDetail);

    private const int TimeoutMs = 120_000;
    #endregion
}
