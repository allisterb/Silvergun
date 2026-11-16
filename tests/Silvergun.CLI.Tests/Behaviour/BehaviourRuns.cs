namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>One CLI run: exit code, stdout, stderr, where its JSON was kept.</summary>
public sealed record BehaviourRun(int Exit, string Output, string Error, string JsonPath);

/// <summary>
/// Every package run once through the real CLI (<c>scan-package &lt;nupkg&gt; --json --strict --reachability --ssa --no-vulns
/// --allow-incomplete</c>; YARA stays on and its status is recorded), cached by key, one child process at a time. The
/// per-run <c>.json</c> and <c>.txt</c> files are kept in the fixed <see cref="ResultsDirectory"/> and overwritten on each run
/// (the results document cites them); only the nupkgs are deleted on dispose. Set <c>SILVERGUN_BEHAVIOUR_DUMP</c> to a file path to append each observation as a pinned-table line.
/// </summary>
public sealed class BehaviourRuns : IDisposable
{
    #region Constructors
    public BehaviourRuns()
    {
        Directory.CreateDirectory(ResultsDirectory);
        Directory.CreateDirectory(Path.Combine(ResultsDirectory, "pkg"));
    }
    #endregion

    #region Properties
    /// <summary>Stable across runs, so the results document can find the JSON.</summary>
    public static string ResultsDirectory { get; } = Path.Combine(Path.GetTempPath(), "silvergun-behaviour-recall");
    #endregion

    #region Methods
    /// <summary>The cached run of a package; fails the test if the CLI was killed or exited with anything but 0, 2 or 3.</summary>
    public BehaviourRun Run(PackageDef package)
    {
        var run = runs.GetOrAdd(package.Key, _ => new Lazy<BehaviourRun>(() => Start(package, json: true))).Value;
        AssertExited(package.Key, run);
        return run;
    }

    /// <summary>The observation of a package, as the pinned table records it.</summary>
    public Observation Observe(PackageDef package) => observations.GetOrAdd(package.Key, _ =>
    {
        var observation = BehaviourObserver.Observe(Run(package));
        if (Environment.GetEnvironmentVariable(DumpVariable) is { Length: > 0 } dump)
            lock (observations)
                File.AppendAllText(dump, BehaviourObserver.PinnedLine(package.Key, observation) + Environment.NewLine);
        return observation;
    });

    /// <summary>The human-report run (no --json) of a package, for the attention parity check.</summary>
    public BehaviourRun RunHuman(PackageDef package)
    {
        var run = humanRuns.GetOrAdd(package.Key, _ => new Lazy<BehaviourRun>(() => Start(package, json: false))).Value;
        AssertExited(package.Key, run);
        return run;
    }

    public void Dispose()
    {
        foreach (var file in nupkgs)
            try { if (File.Exists(file)) File.Delete(file); } catch { /* best-effort temp cleanup */ }
    }

    private static void AssertExited(string key, BehaviourRun run)
    {
        Assert.True(run.Exit >= 0, $"{key}: the CLI did not exit within {TimeoutMs} ms and was killed");
        Assert.True(run.Exit is 0 or 2 or 3, $"{key}: unexpected exit {run.Exit}\nstderr:\n{run.Error}");
    }

    private BehaviourRun Start(PackageDef package, bool json)
    {
        var directory = Path.Combine(ResultsDirectory, "pkg");
        var nupkg = BehaviourPackages.WriteNupkg(package, directory);
        nupkgs.Add(nupkg);

        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in new[] { "scan-package", nupkg }.Concat(json ? ["--json"] : []).Concat(["--strict", "--reachability", "--ssa", "--no-vulns", "--allow-incomplete"]))
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment.Remove("DOTNET_STARTUP_HOOKS");
        // These numbers are recall with YARA off: no SILVERGUN_* variable (YARA path/engine, API keys, the dump hook) reaches the child.
        foreach (var name in psi.Environment.Keys.Where(k => k.StartsWith("SILVERGUN_", StringComparison.OrdinalIgnoreCase)).ToList())
            psi.Environment.Remove(name);

        lock (processGate)   // one CLI process at a time, across both run kinds
        {
            using var process = Process.Start(psi)!;
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return new BehaviourRun(-1, string.Empty, string.Empty, string.Empty);
            }

            process.WaitForExit();
            var output = stdout.GetAwaiter().GetResult();
            var path = Path.Combine(ResultsDirectory, $"{package.Id}.{package.Side}{(json ? ".json" : ".txt")}");
            File.WriteAllText(path, output, new UTF8Encoding(false));
            return new BehaviourRun(process.ExitCode, output, stderr.GetAwaiter().GetResult(), path);
        }
    }
    #endregion

    #region Fields
    public const string DumpVariable = "SILVERGUN_BEHAVIOUR_DUMP";

    private const int TimeoutMs = 300_000;

    private static readonly object processGate = new();

    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private readonly ConcurrentDictionary<string, Lazy<BehaviourRun>> runs = new(StringComparer.Ordinal);

    private readonly ConcurrentDictionary<string, Lazy<BehaviourRun>> humanRuns = new(StringComparer.Ordinal);

    private readonly ConcurrentDictionary<string, Observation> observations = new(StringComparer.Ordinal);

    private readonly ConcurrentBag<string> nupkgs = [];
    #endregion
}

/// <summary>
/// Turns one run's JSON into an <see cref="Observation"/>. Attention is the footer's predicate
/// (<c>PackageReportRenderer.Footer</c>) over the JSON: any capability, script, obfuscation, YARA or vulnerability
/// finding, or a finding in a category <see cref="ReportTheme.IsDiscriminatingIndicatorCategory"/> names.
/// </summary>
public static class BehaviourObserver
{
    #region Methods
    public static Observation Observe(BehaviourRun run)
    {
        var root = JsonNode.Parse(run.Output)!.AsObject();
        var assemblies = root["Assemblies"]!.AsArray().Select(a => a!.AsObject()).ToList();
        var signals = new List<Signal>();

        var capabilities = assemblies.SelectMany(a => Items(a["Report"], "Findings")).Select(f => f["Capability"]!.GetValue<string>()).ToList();
        signals.AddRange(capabilities.Select(c => new Signal(Detector.Capability, c)));

        var indicators = assemblies.SelectMany(a => Items(a["Indicators"], "Findings")).Select(f => f["Category"]!.GetValue<string>()).ToList();
        signals.AddRange(indicators.Select(c => new Signal(Detector.Indicator, c)));

        var obfuscation = assemblies.SelectMany(a => Items(a["Obfuscation"], "Findings"))
            .Select(f => $"{f["Kind"]!.GetValue<string>()}/{f["DetectedAs"]!.GetValue<string>()}").ToList();
        signals.AddRange(obfuscation.Select(k => new Signal(Detector.Obfuscation, k)));

        var scripts = Items(root, "ScriptFindings").Select(f => f["RuleId"]!.GetValue<string>()).ToList();
        signals.AddRange(scripts.Select(r => new Signal(Detector.ScriptRule, r)));

        var yara = Items(root, "YaraFindings").Select(f => f["RuleName"]!.GetValue<string>()).ToList();
        signals.AddRange(yara.Select(r => new Signal(Detector.Yara, r)));

        signals.AddRange(Items(root, "PackagingAnomalies").Select(a => new Signal(Detector.Anomaly, a["Category"]!.GetValue<string>())));

        var folders = Items(root["Reachability"], "Folders").ToList();
        foreach (var statement in folders.SelectMany(f => Items(f, "Statements")))
        {
            var kind = statement["Kind"]!.GetValue<string>() == "Trigger" ? Detector.ReachTrigger : Detector.ReachInfo;
            var capability = statement["Capability"]?.GetValue<string>();
            var direct = statement["Direct"]?.GetValue<bool>() == true ? "/Direct" : string.Empty;
            // A co-reach statement names the capability it was reached together with (recall-levers-1 §1): another key than the plain reach.
            var with = statement["With"]?.GetValue<string>() is { } partner ? $"+{partner}" : string.Empty;
            signals.Add(new Signal(kind, $"{statement["Class"]!.GetValue<string>()}{direct}>{capability ?? "None"}{with}"));
        }

        // A folder's SSA value signals (recall-levers-1 §2): the signal and how it is presented.
        signals.AddRange(folders.SelectMany(f => Items(f["Ssa"], "Signals")).Select(s =>
            new Signal(Detector.ValueSignal, $"{s["Signal"]!.GetValue<string>()}/{s["Kind"]!.GetValue<string>()}")));

        // The rendered call, and " => " the resolved reflection target when SSA found one.
        signals.AddRange(folders.SelectMany(f => Items(f["Ssa"], "Sites")).Select(s =>
            new Signal(Detector.SsaSite, s["Call"]!.GetValue<string>() + (s["Target"]?["Text"]?.GetValue<string>() is { } target ? $" => {target}" : string.Empty))));

        return new Observation(
            run.Exit,
            HasAttention(root),
            [.. signals.Distinct().OrderBy(s => s.Detector).ThenBy(s => s.Key, StringComparer.Ordinal)],
            root["YaraScanStatus"]!.GetValue<string>(),
            root["Completeness"]!["IsComplete"]!.GetValue<bool>());
    }

    /// <summary>The footer's attention predicate over a scan-package JSON document, one clause per finding class.</summary>
    public static bool HasAttention(JsonObject root)
    {
        var assemblies = Items(root, "Assemblies").ToList();
        return assemblies.SelectMany(a => Items(a["Report"], "Findings")).Any()
            || Items(root, "ScriptFindings").Any()
            || assemblies.SelectMany(a => Items(a["Obfuscation"], "Findings")).Any()
            || Items(root, "YaraFindings").Any()
            || Items(root, "Vulnerabilities").Any()
            || assemblies.SelectMany(a => Items(a["Indicators"], "Findings"))
                .Any(f => ReportTheme.IsDiscriminatingIndicatorCategory(Enum.Parse<IndicatorCategory>(f["Category"]!.GetValue<string>())));
    }

    /// <summary>The pinned-table line for an observation (what <c>BehaviourMeasured</c> holds).</summary>
    public static string PinnedLine(string key, Observation observation) =>
        $"        [{Literal(key)}] = Obs({observation.Exit}, {Bool(observation.Attention)}, {Bool(observation.Complete)}, {Literal(observation.YaraStatus)}"
        + string.Concat(observation.Signals.Select(s => $",{Environment.NewLine}            {Literal(s.ToString())}")) + "),";

    private static string Bool(bool value) => value ? "true" : "false";

    private static string Literal(string text)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in text)
            sb.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                >= ' ' and < (char)0x7F => c.ToString(),
                _ => $"\\u{(int)c:x4}",
            });
        return sb.Append('"').ToString();
    }

    // The child items of node[name] when it is an array; empty when absent, null or not an array.
    private static IEnumerable<JsonObject> Items(JsonNode? node, string name) =>
        node?[name] is JsonArray array ? array.Select(i => i!.AsObject()) : [];
    #endregion
}
