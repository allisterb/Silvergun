namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <b>The CLI-level pin on how many findings <c>analyze</c> reports</b>, added because capability-map phase 2
/// moved <c>analyze Silvergun.CodeAnalysis.IL.dll</c> from 9 findings to 10 and <em>nothing anywhere asserted
/// it</em>: every completeness test builds a synthetic <c>CapabilityReport</c>, so the number moved silently on a
/// verb whose exit code depends on findings (ADR 0024). A detection change is allowed to move this number — it
/// must not move it unnoticed.
/// <para>
/// Two complementary shapes, deliberately, because neither alone is enough:
/// </para>
/// <list type="number">
/// <item><description><b>Derived</b> — the CLI's count must equal what <see cref="CapabilityAnalysis"/> reports
/// for the same file. That never goes stale and catches the CLI dropping, duplicating or re-filtering findings on
/// the way to the report, but it moves silently with detection because both sides move together.</description></item>
/// <item><description><b>Pinned</b> — the exact set of <c>CalledApi</c> values, which is what actually notices a
/// detection change. Asserted as a set rather than a bare count so a failure names <em>which</em> API appeared or
/// disappeared; updating it is then a one-line, reviewable statement about what changed and why.</description></item>
/// </list>
/// <para>
/// Every CLI invocation is its own process, as in <see cref="CompletenessCliTests"/>: that is the contract under
/// test, and a CCI <c>Debug.Assert</c> routes to <c>Environment.FailFast</c> (ADR 0021, exit 35), which in-process
/// would take the whole run down. The one in-process scan here is of our own library — the same file the child
/// just scanned successfully.
/// </para>
/// </summary>
public sealed class AnalyzeFindingCountTests
{
    #region Methods
    /// <summary>
    /// The derived half: the report the CLI emits carries exactly the findings the library produces for the same
    /// assembly — same count and same rendered set, so a divergence names the finding rather than a delta.
    /// </summary>
    [Fact]
    public void Analyze_Json_CarriesExactlyTheFindingsCapabilityAnalysisProducesForTheSameAssembly()
    {
        var reported = FindingsFromCli(TargetAssembly);
        var measured = FindingsInProcess(TargetAssembly);

        Assert.NotEmpty(measured);
        Assert.Equal(measured, reported);
    }

    /// <summary>
    /// The pinned half — the one that notices a detection change. Measured 2026-07-31, after capability-map
    /// phase 2: <b>10</b> findings, all <see cref="Capability.FileSystem"/>, from the library's own path handling.
    /// <para>
    /// <b>The tenth is the phase-2 delta itself</b>: <c>System.IO.StreamReader..ctor</c> in
    /// <c>CapabilityMap.LoadDefault</c> — the map's own loader, newly classified because
    /// <c>capability System.IO.StreamReader..ctor FileSystem</c> is a map entry with no counterpart in the legacy
    /// 32-entry catalog. Before phase 2 there were 9. Anything that moves this set again must say what changed.
    /// </para>
    /// </summary>
    [Fact]
    public void Analyze_OnTheIlLibrary_ReportsTheMeasuredFindingSet()
    {
        Assert.Equal(MeasuredIlLibraryFindings, FindingsFromCli(TargetAssembly));
    }

    /// <summary>
    /// The negative control the pin above needs: the findings-free fixture stays findings-free, exits <b>0</b>,
    /// and its report's completeness block agrees the analysis was complete. Without it, "10 findings" could
    /// drift together with a change that made <em>every</em> assembly report more.
    /// <para>
    /// The exit code is asserted <b>in this body</b>, not only inside the shared helper: it is half of what the
    /// name promises, and ADR 0024 put findings on the exit-code path, so "no findings" and "exit 0" are two facts
    /// about the same run that must be seen to agree here rather than in a helper any future refactor of the
    /// helper could quietly loosen.
    /// </para>
    /// </summary>
    [Fact]
    public void Analyze_OnTheBenignFixture_ReportsNoFindingsAndExitsZero()
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", BenignFixture, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.True(exit == 0, $"analyze exited {exit} on the findings-free fixture. stderr:{Environment.NewLine}{stderr}");

        Assert.Empty(FindingsIn(stdout));
        Assert.Empty(FindingsInProcess(BenignFixture));
    }
    #endregion

    #region Methods — helpers
    // "Capability Kind CalledApi" for every finding in a real `analyze --json` run, ordered. Renders the tuple
    // rather than the count so an assertion failure prints the disagreement itself.
    private static string[] FindingsFromCli(string assemblyPath)
    {
        var (exit, stdout, stderr, exited) = RunCli("analyze", assemblyPath, "--json");

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.True(exit == 0, $"analyze exited {exit}. stderr:{Environment.NewLine}{stderr}");

        return FindingsIn(stdout);
    }

    // The findings of one `analyze --json` report, ordered. Split out of FindingsFromCli so a caller that needs to
    // assert on the exit code itself can run the CLI once and still parse the same report.
    private static string[] FindingsIn(string stdout)
    {
        using var document = JsonDocument.Parse(stdout.TrimEnd('\r', '\n'));

        // Complete analysis, so a finding cannot be missing merely because a method was skipped.
        Assert.True(document.RootElement.GetProperty("Completeness").GetProperty("IsComplete").GetBoolean());

        return [.. document.RootElement.GetProperty("Capabilities").GetProperty("Findings").EnumerateArray()
            .Select(f => $"{Text(f, "Capability")} {Text(f, "Kind")} {Text(f, "CalledApi")}")
            .Order(StringComparer.Ordinal)];
    }

    // The same rendering, straight from the library, with no CLI in between.
    private static string[] FindingsInProcess(string assemblyPath)
    {
        Runtime.Initialize("Silvergun", "TESTS");

        var create = AssemblyAnalyzer.Load(assemblyPath);
        Assert.True(create.IsSuccess, create.Message);
        using var cci = create.Value;

        var result = new CapabilityAnalysis(cci).Analyze();
        Assert.True(result.IsSuccess, result.Message);

        return [.. result.Value.Findings
            .Select(f => $"{f.Capability} {f.Kind} {f.CalledApi}")
            .Order(StringComparer.Ordinal)];
    }

    private static string Text(JsonElement finding, string property) => finding.GetProperty(property).GetString()!;

    // Same shape as CompletenessCliTests.RunCli: both streams captured and drained asynchronously, stdin closed,
    // NO_COLOR set.
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

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    /// <summary>The analysis library itself — a real, non-trivial managed assembly always in the test output.</summary>
    private static readonly string TargetAssembly =
        Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.dll");

    /// <summary>The findings-free fixture, the negative control.</summary>
    private static readonly string BenignFixture =
        Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.Tests.BenignFixture.dll");

    /// <summary>
    /// The measured set for <c>Silvergun.CodeAnalysis.IL.dll</c>, ordered ordinally. Nine of these predate
    /// capability-map phase 2; <c>System.IO.StreamReader..ctor</c> is the one it added.
    /// <para>
    /// The two <c>System.IO.File.OpenRead</c> calls (12 findings, re-measured 2026-11-05) are the library's own metadata
    /// side readers, each opening the assembly file it is about to read: <c>TypeForwarders.Read</c> (added in
    /// <c>f528fe8</c>, CHA begin) and <c>ModuleMetadata.Read</c> (<c>994a097</c>, A2 S3), both classified by
    /// <c>capability System.IO.File FileSystem</c>. The pin had not been updated since <c>4e092e0</c>, before either.
    /// </para>
    /// <para>
    /// <c>System.Security.Cryptography.SHA256.HashData</c> (13 findings, re-measured 2026-11-06) is reachability R2b S1's
    /// name bounding (ADR 0037 amendment a5): <c>Reachability.BoundName</c> ends a name cut at <c>MaxNameChars</c> with the
    /// first 8 hex of its SHA-256, a Cryptography call by the map's <c>System.Security.Cryptography.*</c> entry. The S2 map
    /// moves nothing here: the library calls no <c>Marshal</c>, <c>GCHandle</c> or <c>Directory.GetParent</c>.
    /// </para>
    /// <para>
    /// <c>System.Runtime.InteropServices.MemoryMarshal.AsBytes</c> (14 findings, re-measured 2026-11-06) is the S0-S3 review's
    /// Nit 1: <c>Reachability.BoundName</c> now hashes the name's UTF-16 code units, read as bytes through
    /// <c>MemoryMarshal.AsBytes</c>, instead of its UTF-8. UnsafeMemory by the map's <c>System.Runtime.InteropServices.MemoryMarshal</c>
    /// entry; the only call of it in the library.
    /// </para>
    /// </summary>
    private static readonly string[] MeasuredIlLibraryFindings =
    [
        "Cryptography Call System.Security.Cryptography.SHA256.HashData",
        "FileSystem Call System.IO.Directory.EnumerateFiles",
        "FileSystem Call System.IO.Directory.Exists",
        "FileSystem Call System.IO.File.Exists",
        "FileSystem Call System.IO.File.Exists",
        "FileSystem Call System.IO.File.Exists",
        "FileSystem Call System.IO.File.OpenRead",
        "FileSystem Call System.IO.File.OpenRead",
        "FileSystem Call System.IO.FileInfo.get_Directory",
        "FileSystem Call System.IO.FileSystemInfo.get_FullName",
        "FileSystem Call System.IO.FileSystemInfo.get_FullName",
        "FileSystem Construct System.IO.FileInfo..ctor",
        "FileSystem Construct System.IO.StreamReader..ctor",
        "UnsafeMemory Call System.Runtime.InteropServices.MemoryMarshal.AsBytes",
    ];

    private const int TimeoutMs = 120_000;
    #endregion
}
