namespace Silvergun.MCPServer.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// S1 Accept against the local package corpus (skipped when it is absent): a job's <c>report.json</c> is exactly
/// <c>scan-package --json --no-vulns</c> on the same package, once the run-specific values are masked (S1 acceptance
/// amendment: <c>AnalyzedAt</c>, <c>FullPath</c>, <c>AssemblyPath</c> and any occurrence of an extraction directory);
/// and the largest package's summary fits its budget. One CLI process per package, each with its own exit code checked.
/// </summary>
[Trait("Category", "Corpus")]
public sealed class JobCorpusTests
{
    #region Methods
    // Ten small corpus packages of different shapes; the last carries a native binary (the SNI runtime).
    public static TheoryData<string> Packages() =>
    [
        "Swashbuckle.AspNetCore.10.2.3.nupkg",
        "xunit.2.9.3.nupkg",
        "Microsoft.NET.Sdk.Android.Manifest-8.0.100.34.0.154.nupkg",
        "Serilog.Sinks.Debug.3.0.0.nupkg",
        "Microsoft.SqlServer.Server.1.0.0.nupkg",
        "Serilog.Formatting.Compact.3.0.0.nupkg",
        "Microsoft.AspNetCore.Mvc.NewtonsoftJson.10.0.11.nupkg",
        "Azure.Identity.1.21.0.nupkg",
        "Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions.10.0.11.nupkg",
        "runtime.win-x64.runtime.native.System.Data.SqlClient.sni.4.4.0.nupkg",
    ];

    [CorpusTheory]
    [MemberData(nameof(Packages))]
    public async Task ReportJson_EqualsScanPackageJson_Masked(string name)
    {
        var package = Path.Combine(Corpus.Dir, name);
        Assert.True(File.Exists(package), $"the corpus has no {name}");
        using var dirs = new TestDirs();
        var manager = InProcess.Manager(dirs, root: Corpus.Dir);

        var view = await InProcess.RunToEndAsync(manager, package);
        Assert.True(view.State == JobState.Completed, $"{name}: the job {view.State}: {view.Reason}");
        var job = File.ReadAllText(Path.Combine(view.EntryDir!, JobProtocol.ReportFile), Encoding.UTF8);
        var (exit, cli, stderr) = await ScanPackageAsync(package);
        Assert.True(exit is 0 or 1 or 2 or 3, $"{name}: scan-package exited {exit}\n{stderr}");

        var (a, b) = (Mask(cli.TrimEnd()), Mask(job.TrimEnd()));
        if (a != b)
        {
            var (al, bl) = (a.Split('\n'), b.Split('\n'));
            var i = Enumerable.Range(0, Math.Min(al.Length, bl.Length)).FirstOrDefault(k => al[k] != bl[k], Math.Min(al.Length, bl.Length));
            Assert.Fail($"{name}: report.json differs from scan-package --json --no-vulns at line {i + 1} ({al.Length} vs {bl.Length} lines)\n" +
                $" cli: {Excerpt(al, i)}\n job: {Excerpt(bl, i)}");
        }
    }

    [CorpusFact]
    public async Task TheLargestPackage_SummaryFitsItsBudget_AndSoDoesGetSummary()
    {
        var package = new DirectoryInfo(Corpus.Dir).GetFiles("*.nupkg").MaxBy(f => f.Length)!.FullName;
        using var dirs = new TestDirs();
        var tools = InProcess.Tools(dirs, out var manager, root: Corpus.Dir);

        var view = await InProcess.RunToEndAsync(manager, package);
        Assert.True(view.State == JobState.Completed, $"{Path.GetFileName(package)}: {view.State} {view.Reason}");
        var summaryChars = File.ReadAllText(Path.Combine(view.EntryDir!, JobProtocol.SummaryFile), Encoding.UTF8).Length;
        Assert.True(summaryChars <= PackageSummary.BudgetChars, $"summary.json is {summaryChars} chars (budget {PackageSummary.BudgetChars})");

        var result = tools.GetSummary(view.JobId);

        Assert.False(result.IsError, InProcess.Text(result));
        var text = InProcess.Text(result);
        Assert.True(text.Length <= McpLimits.ResponseBudgetChars, $"the get_summary text block is {text.Length} chars (budget {McpLimits.ResponseBudgetChars})");
        Assert.Contains(InProcess.S(result).GetProperty("summary").GetProperty("truncated").ValueKind, new[] { JsonValueKind.True, JsonValueKind.False });
    }
    #endregion

    #region Methods: helpers
    private static async Task<(int Exit, string Stdout, string Stderr)> ScanPackageAsync(string package)
    {
        var psi = new ProcessStartInfo(McpCli.Exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        foreach (var arg in new[] { "scan-package", package, "--json", "--no-vulns" })
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromMinutes(10)))
        {
            p.Kill(entireProcessTree: true);
            Assert.Fail($"scan-package {Path.GetFileName(package)} did not finish in 10 minutes");
        }
        return (p.ExitCode, await stdout, await stderr);
    }

    // The run-specific values: the analysis time and the absolute extraction paths (one run's temporary directory, the
    // other's job directory), wherever a JSON string holds a path under the temp root.
    private static string Mask(string json)
    {
        var masked = runSpecific.Replace(json.Replace("\r\n", "\n"), m => $"\"{m.Groups[1].Value}\": \"*\"");
        return tempRooted.Replace(masked, "<tmp>");
    }

    private static string Excerpt(string[] lines, int i) => i < lines.Length ? lines[i].Trim()[..Math.Min(lines[i].Trim().Length, 240)] : "<end>";
    #endregion

    #region Fields
    private static readonly Regex runSpecific = new("\"(AnalyzedAt|FullPath|AssemblyPath)\":\\s*\"(?:[^\"\\\\]|\\\\.)*\"", RegexOptions.CultureInvariant);

    private static readonly Regex tempRooted = new(Regex.Escape(JsonEncodedText.Encode(Path.GetTempPath()).ToString()) + "(?:[^\"\\\\]|\\\\.)*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    #endregion
}
