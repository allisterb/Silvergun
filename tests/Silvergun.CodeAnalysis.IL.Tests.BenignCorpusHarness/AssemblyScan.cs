namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

/// <summary>One capability finding as it crossed the child-process boundary - strings only, deliberately.</summary>
public sealed record ScannedFinding(
    string Capability, string Kind, string CallerType, string CallerMethod, string CalledApi);

/// <summary>
/// What one child process reported about one assembly. <see cref="ExitCode"/> is null only for
/// <see cref="TimedOut"/>. <see cref="Completed"/> is the coverage gate: a child that exited 0 but never printed
/// <c>DONE</c> was cut short and its findings are a floor, not a total.
/// </summary>
public sealed record AssemblyScan(
    string AssemblyFile,
    int? ExitCode,
    bool TimedOut,
    bool Completed,
    int MethodsTotal,
    int MethodsAnalyzed,
    int MethodsSkipped,
    IReadOnlyList<ScannedFinding> Findings,
    string? Failure)
{
    #region Properties
    /// <summary>True only for a clean, complete scan: exit 0, <c>DONE</c> seen, no reported failure.</summary>
    public bool Ok => ExitCode == 0 && Completed && Failure is null;

    /// <summary>Why this scan is not <see cref="Ok"/>, phrased for the coverage-honesty table.</summary>
    public string Reason =>
        TimedOut ? "child timed out and was killed"
        : ExitCode != 0 ? $"child exited {ExitCode}" +
            (ExitCode == 35 ? " (35 = Environment.FailFast - uncatchable, see ADR-0021)" : string.Empty) +
            (Failure is null ? string.Empty : $": {Failure}")
        : !Completed ? "child exited 0 without printing DONE (cut short)"
        : Failure ?? "ok";
    #endregion
}

/// <summary>
/// The child half of the harness: loads <b>one</b> assembly and runs <see cref="CapabilityAnalysis"/> over it, in
/// its own process. ADR-0021 is the whole reason for the split - a CCI <c>Debug.Assert</c>/<c>Debug.Fail</c> is
/// <c>Environment.FailFast</c> (exit 35, no managed exception, no <c>catch</c>), so one hostile or merely unlucky
/// assembly run in-process would take the entire corpus run with it. "Benign by assumption" is not "benign by
/// proof": these are unaudited third-party binaries and they get the same containment as the pathological fixtures.
/// <para>Output contract (stdout, one tab-separated record per line):</para>
/// <list type="bullet">
/// <item><description><c>META\t&lt;total&gt;\t&lt;analyzed&gt;\t&lt;skipped&gt;</c> - once.</description></item>
/// <item><description><c>FINDING\t&lt;capability&gt;\t&lt;kind&gt;\t&lt;callerType&gt;\t&lt;callerMethod&gt;\t&lt;calledApi&gt;</c>
/// - once per finding, in <see cref="CapabilityAnalysis"/>'s own deterministic order.</description></item>
/// <item><description><c>DONE</c> - the last line on a clean run; its absence, even with exit 0, means the process
/// was cut short.</description></item>
/// </list>
/// <para>Exit codes - never 35 on purpose, so an abnormal termination is distinguishable by exit code alone:
/// <c>0</c> clean, <c>1</c> catchable failure (load/analysis <c>Result.Failure</c> or managed exception),
/// <c>2</c> bad usage.</para>
/// </summary>
public static class ChildScan
{
    #region Methods
    /// <summary>
    /// Child entry point: <c>&lt;harness&gt; scan &lt;assembly-path&gt;</c>. Not named <c>Main</c> - the assembly
    /// already has one in <see cref="Program"/>, which dispatches here.
    /// </summary>
    public static int Execute(string[] args)
    {
        try
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("USAGE: <harness> scan <assembly-path>");
                return 2;
            }

            // Null logging: a skip warning must not become the thing that fails - or pollutes the stdout protocol.
            Runtime.Initialize("Silvergun", "CORPUS");

            var loaded = AssemblyAnalyzer.Load(args[1]);
            if (!loaded.IsSuccess)
            {
                Console.Error.WriteLine($"LOAD-FAILED {loaded.Message}");
                return 1;
            }

            using var analyzer = loaded.Value;

            var capabilities = new CapabilityAnalysis(analyzer).Analyze();
            if (!capabilities.IsSuccess)
            {
                Console.Error.WriteLine($"CAPABILITY-ANALYSIS-FAILED {capabilities.Message}");
                return 1;
            }

            var report = capabilities.Value;
            Console.WriteLine(string.Join('\t',
                "META", report.MethodsTotal, report.MethodsAnalyzed, report.MethodsSkipped));

            foreach (var f in report.Findings)
                Console.WriteLine(string.Join('\t',
                    "FINDING", f.Capability, f.Kind, Clean(f.CallerType), Clean(f.CallerMethod), Clean(f.CalledApi)));

            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            // A managed exception here is informative in itself: the failure was CATCHABLE, i.e. not the
            // uncatchable termination this process split exists to contain.
            Console.Error.WriteLine($"UNHANDLED {ex}");
            return 1;
        }
    }

    // Metadata is attacker-influenced text; a stray tab or newline in a type name would silently corrupt the
    // record layout (and therefore the counts) rather than fail loudly.
    private static string Clean(string value) =>
        value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    #endregion

    #region Fields
    public const string Verb = "scan";
    #endregion
}

/// <summary>
/// The parent half: spawns <see cref="ChildScan"/> and turns its exit code and stdout into an
/// <see cref="AssemblyScan"/>. Shaped after <c>Silvergun.CodeAnalysis.IL.Tests.ChildProcessProbe</c> and
/// deliberately duplicated rather than shared - that type lives in an xUnit test assembly this console harness has
/// no reason to reference (same call the codebase already makes for <c>ApphostPath</c>).
/// </summary>
public static class ChildScanRunner
{
    #region Methods
    /// <summary>
    /// Runs <paramref name="harnessExecutable"/> <c>scan &lt;assemblyPath&gt;</c> with stdin closed and both output
    /// streams drained asynchronously. Never throws for an abnormal or timed-out child - only a failure to start
    /// the process at all.
    /// </summary>
    public static AssemblyScan Run(string harnessExecutable, string assemblyPath, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(harnessExecutable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(ChildScan.Verb);
        psi.ArgumentList.Add(assemblyPath);

        var file = System.IO.Path.GetFileName(assemblyPath);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Could not start '{harnessExecutable}'.");

        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return new AssemblyScan(file, null, TimedOut: true, Completed: false, 0, 0, 0, [], "timed out");
        }

        return Parse(file, process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }

    private static AssemblyScan Parse(string file, int exitCode, string stdout, string stderr)
    {
        var lines = stdout.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToArray();
        var meta = lines.FirstOrDefault(l => l.StartsWith("META\t", StringComparison.Ordinal))?.Split('\t');

        var findings = lines
            .Where(l => l.StartsWith("FINDING\t", StringComparison.Ordinal))
            .Select(l => l.Split('\t'))
            .Where(f => f.Length == 6)
            .Select(f => new ScannedFinding(f[1], f[2], f[3], f[4], f[5]))
            .ToArray();

        return new AssemblyScan(
            file,
            exitCode,
            TimedOut: false,
            Completed: lines.Contains("DONE"),
            MethodsTotal: Number(meta, 1),
            MethodsAnalyzed: Number(meta, 2),
            MethodsSkipped: Number(meta, 3),
            findings,
            Failure: exitCode == 0 ? null : FirstLine(stderr));
    }

    private static int Number(string[]? fields, int index) =>
        fields is not null && fields.Length > index
        && int.TryParse(fields[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : 0;

    private static string? FirstLine(string text) =>
        text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
    #endregion
}
