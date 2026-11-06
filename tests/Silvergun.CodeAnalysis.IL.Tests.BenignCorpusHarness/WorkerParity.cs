namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>A load failure of the in-process pass: the assembly's package path and the reason.</summary>
public sealed record ParityFailure(string RelativePath, string Reason);

/// <summary>
/// One folder of the in-process pass: its outcome, the assemblies loaded and the ones that failed (with reasons), its report
/// serialized by <see cref="WorkerParity.Serialize"/>, and its graph size.
/// </summary>
public sealed record ParityFolder(string Folder, string Outcome, IReadOnlyList<string> Assemblies, IReadOnlyList<ParityFailure> LoadFailures, string? Report, int Nodes, int Edges);

/// <summary>What the in-process child measured for one package.</summary>
public sealed record ParityPayload(IReadOnlyList<ParityFolder> Folders, long OpenMs, long BuildMs);

/// <summary>
/// The child half of <c>--worker-parity</c> (<c>docs/agent/tasks/graph-worker.md</c> S3): the in-process graph pass over
/// <b>one</b> cached <c>.nupkg</c> in its own process (ADR 0021: a CCI <c>FailFast</c> costs one package), the way the
/// worker would do it: <see cref="PackageGraphs.Build(NuGetPackage, GraphBudget?, CapabilityMap?)"/>, then
/// <see cref="Reachability.Analyze"/> per folder.
/// <para>
/// Protocol: <c>&lt;harness&gt; parity-inproc &lt;nupkg&gt; &lt;out-json&gt;</c> writes a <see cref="ParityPayload"/> to
/// <c>out-json</c>, then prints <c>DONE</c>; the extraction directory is named on stderr as for <c>reach</c>. Exit codes: 0
/// done; 1 a catchable failure; 2 bad usage.
/// </para>
/// </summary>
public static class WorkerParityChild
{
    #region Methods
    public static int Execute(string[] args)
    {
        try
        {
            if (args.Length != 3)
            {
                Console.Error.WriteLine($"USAGE: <harness> {Verb} <nupkg> <out-json>");
                return 2;
            }

            Runtime.Initialize("Silvergun", "CORPUS");
            var payload = Measure(args[1], dir => Console.Error.WriteLine($"{ReachabilityChild.ExtractionMarker}\t{dir}"));
            PackageReachResult.WriteAtomically(args[2], JsonSerializer.Serialize(payload, PackageReachResult.JsonOptions));
            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>The in-process pass over the package at <paramref name="nupkgPath"/>. Unguarded: only ever called in a child.</summary>
    public static ParityPayload Measure(string nupkgPath, Action<string>? reportExtraction = null)
    {
        var open = Stopwatch.StartNew();
        var opened = NuGetPackage.Open(nupkgPath);
        if (!opened.IsSuccess)
            throw new InvalidOperationException($"the package could not be opened: {opened.Message}");
        var openMs = open.ElapsedMilliseconds;

        using var package = opened.Value;
        reportExtraction?.Invoke(package.ExtractionDir);
        var build = Stopwatch.StartNew();
        var folders = PackageGraphs.Build(package).Select(g =>
        {
            var report = g.Graph is { } graph ? Reachability.Analyze(graph) : null;
            return new ParityFolder(g.Folder, report is null ? nameof(FolderOutcome.NothingLoaded) : nameof(FolderOutcome.Analyzed),
                [.. g.Assemblies], [.. g.LoadFailures.Select(f => new ParityFailure(f.RelativePath, f.Reason))],
                WorkerParity.Serialize(report), g.Graph?.Nodes.Count ?? 0, g.Graph?.Edges.Count ?? 0);
        }).ToList();
        return new ParityPayload(folders, openMs, build.ElapsedMilliseconds);
    }
    #endregion

    #region Fields
    public const string Verb = "parity-inproc";
    #endregion
}

/// <summary>
/// The parent half of <c>--worker-parity</c>: per cached package (offline; a missing one is <c>not-cached</c>), the in-process
/// pass in a <see cref="WorkerParityChild"/>, then <see cref="PackageReachability.Analyze(NuGetPackage, PackageReachabilityOptions?)"/>
/// through the real CLI worker beside this harness. Writes <c>worker-parity-&lt;date&gt;.tsv</c> (one row per folder),
/// <c>worker-parity-&lt;date&gt;-packages.tsv</c> (one row per package, with wall times) and
/// <c>worker-parity-&lt;date&gt;.md</c> (the summary). Every package-controlled string is made one printable line first.
/// </summary>
public static class WorkerParity
{
    #region Methods
    /// <summary>A report as both halves serialize it for comparison (compact, camelCase, enum names, computed properties left out), or null.</summary>
    public static string? Serialize(ReachabilityReport? report) => report is null ? null : JsonSerializer.Serialize(report, ReportOptions);

    public static (IReadOnlyList<string> Paths, int Mismatches, int Measured, int NotCached, IReadOnlyList<string> Incomplete) Run(
        CorpusManifest manifest, string cacheRoot, string harness, TimeSpan childTimeout, string outputDirectory, DateOnly date, TextWriter progress)
    {
        var folderRows = new List<string> { string.Join('\t', FolderColumns) };
        var packageRows = new List<string> { string.Join('\t', PackageColumns) };
        var mismatches = new List<string>();
        var incomplete = new List<string>();
        var totals = new Totals();

        foreach (var (entry, number) in manifest.Entries.Select((e, i) => (e, i + 1)))
        {
            var name = $"{entry.Id} {entry.Version}";
            var nupkg = CachedNupkg.PathOf(cacheRoot, entry);
            if (!File.Exists(nupkg))
            {
                totals.NotCached++;
                packageRows.Add(Row(name, "not-cached", "", "", "", "", "", "0"));
                continue;
            }

            progress.Write($"[{number}/{manifest.Entries.Count}] {name} ... ");
            var inProcess = RunChild(harness, nupkg, childTimeout);
            var worker = RunWorker(nupkg);
            totals.Packages++;
            totals.InProcessWallMs += inProcess.WallMs;
            totals.InProcessBuildMs += inProcess.Payload?.BuildMs ?? 0;
            totals.WorkerWallMs += worker.WallMs;
            totals.WorkerAnalyzeMs += worker.AnalyzeMs;
            // A half that did not finish compares nothing, even when neither half yielded a folder row (final review).
            if (inProcess.Status != "ok" || worker.Status != "ok")
                incomplete.Add($"{Clean(name)} (in-process {Clean(inProcess.Status)}, worker {Clean(worker.Status)})");

            var mine = inProcess.Payload?.Folders ?? [];
            var theirs = worker.Report?.Folders ?? [];
            for (var i = 0; i < Math.Max(mine.Count, theirs.Count); i++)
            {
                var a = i < mine.Count ? mine[i] : null;
                var b = i < theirs.Count ? theirs[i] : null;
                var folder = a?.Folder ?? b!.Folder;
                var inOutcome = a?.Outcome ?? $"missing ({inProcess.Status})";
                var workerOutcome = b?.Outcome.ToString() ?? $"missing ({worker.Status})";
                var equal = a is null || b is null ? "no"
                    : !string.Equals(a.Folder, b.Folder, StringComparison.Ordinal) ? "folder-mismatch"
                    : a.Report is null && b.Report is null ? "n/a"
                    : string.Equals(a.Report, Serialize(b.Report), StringComparison.Ordinal) ? "yes"
                    : "no";
                // Everything else a folder result carries (review N8): what loaded, what failed and why, and the graph size.
                var differs = a is null || b is null ? new List<string> { "folder" } : Differences(a, b);
                var agrees = equal is "yes" or "n/a" && differs.Count == 0 && string.Equals(inOutcome, workerOutcome, StringComparison.Ordinal);
                totals.Folders++;
                totals.Agreeing += agrees ? 1 : 0;
                totals.ReportsEqual += equal == "yes" ? 1 : 0;
                totals.SharedFolders += b?.SameAs is null ? 0 : 1;
                if (!agrees)
                    mismatches.Add($"{Clean(name)} {Clean(folder)}: in-process {Clean(inOutcome)}, worker {Clean(workerOutcome)}, reports-equal {equal}" +
                        (differs.Count > 0 ? $", differs in {string.Join(",", differs)}" : string.Empty) +
                        (b?.Reason is { } reason ? $" ({Clean(reason)})" : string.Empty));
                folderRows.Add(Row(name, folder, inOutcome, workerOutcome, equal, differs.Count == 0 ? "" : string.Join(",", differs),
                    Num(b?.Nodes), Num(b?.Edges), Num(a?.Nodes), Num(a?.Edges), b?.SameAs ?? "", b?.Reason ?? ""));
            }

            packageRows.Add(Row(name, inProcess.Status, Num(inProcess.WallMs), Num(inProcess.Payload?.BuildMs), worker.Status,
                Num(worker.WallMs), Num(worker.AnalyzeMs), Num(Math.Max(mine.Count, theirs.Count))));
            progress.WriteLine($"{inProcess.Status} / {worker.Status} folders={Math.Max(mine.Count, theirs.Count)} in-process={inProcess.WallMs} ms worker={worker.WallMs} ms");
        }

        Directory.CreateDirectory(outputDirectory);
        var stem = Path.Combine(outputDirectory, $"worker-parity-{date:yyyy-MM-dd}");
        PackageReachResult.WriteAtomically(stem + ".tsv", string.Join("\n", folderRows) + "\n");
        PackageReachResult.WriteAtomically(stem + "-packages.tsv", string.Join("\n", packageRows) + "\n");
        PackageReachResult.WriteAtomically(stem + ".md", Summary(manifest, cacheRoot, date, totals, mismatches, incomplete));
        return ([stem + ".tsv", stem + "-packages.tsv", stem + ".md"], mismatches.Count, totals.Packages, totals.NotCached, incomplete);
    }

    // Which of a folder's other fields differ between the two passes: assemblies (in order), load failures (paths and
    // reasons, in order), nodes, edges. Empty when they all agree.
    private static List<string> Differences(ParityFolder a, FolderReachability b)
    {
        var differs = new List<string>();
        if (!a.Assemblies.SequenceEqual(b.Assemblies, StringComparer.Ordinal))
            differs.Add("assemblies");
        if (!a.LoadFailures.Select(f => (f.RelativePath, f.Reason)).SequenceEqual(b.LoadFailures.Select(f => (f.RelativePath, f.Reason))))
            differs.Add("load-failures");
        if (a.Nodes != b.Nodes)
            differs.Add("nodes");
        if (a.Edges != b.Edges)
            differs.Add("edges");
        return differs;
    }

    // The in-process pass in its own process, bounded by `timeout`.
    private static (string Status, ParityPayload? Payload, long WallMs) RunChild(string harness, string nupkg, TimeSpan timeout)
    {
        var payloadPath = Path.Combine(Path.GetTempPath(), $"silvergun-worker-parity-{Guid.NewGuid():N}.json");
        var psi = new ProcessStartInfo(harness)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(WorkerParityChild.Verb);
        psi.ArgumentList.Add(nupkg);
        psi.ArgumentList.Add(payloadPath);

        var clock = Stopwatch.StartNew();
        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start '{harness}'.");
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            if (!process.WaitForExit(ReachabilityChildRunner.TimeoutMilliseconds(timeout)))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                process.WaitForExit(10_000);
                ReachabilityChildRunner.RemoveExtraction(stderr.Wait(10_000) ? stderr.Result : string.Empty);
                return ("timeout", null, clock.ElapsedMilliseconds);
            }
            var wallMs = clock.ElapsedMilliseconds;
            var errors = stderr.GetAwaiter().GetResult();
            if (process.ExitCode != 0)
            {
                ReachabilityChildRunner.RemoveExtraction(errors);
                return ($"crashed:{process.ExitCode}", null, wallMs);
            }
            if (!stdout.GetAwaiter().GetResult().Split('\n').Select(l => l.TrimEnd('\r')).Contains("DONE") || !File.Exists(payloadPath))
                return ("incomplete", null, wallMs);
            return ("ok", JsonSerializer.Deserialize<ParityPayload>(File.ReadAllText(payloadPath), PackageReachResult.JsonOptions), wallMs);
        }
        catch (JsonException)
        {
            return ("unreadable", null, clock.ElapsedMilliseconds);
        }
        finally
        {
            File.Delete(payloadPath);
        }
    }

    // The worker pass in this process: open (an extraction, as in the child), then the out-of-process graph pass.
    private static (string Status, PackageReachabilityReport? Report, long WallMs, long AnalyzeMs) RunWorker(string nupkg)
    {
        var clock = Stopwatch.StartNew();
        var opened = NuGetPackage.Open(nupkg);
        if (!opened.IsSuccess)
            return ("open-failed", null, clock.ElapsedMilliseconds, 0);
        using var package = opened.Value;
        var analyze = Stopwatch.StartNew();
        var report = PackageReachability.Analyze(package);
        return ("ok", report, clock.ElapsedMilliseconds, analyze.ElapsedMilliseconds);
    }

    private static string Summary(CorpusManifest manifest, string cacheRoot, DateOnly date, Totals totals, List<string> mismatches, List<string> incomplete)
    {
        var text = new StringBuilder();
        text.AppendLine($"# Graph worker parity, {date:yyyy-MM-dd}");
        text.AppendLine();
        text.AppendLine("Measured by the benign-corpus harness `--worker-parity` (docs/agent/tasks/graph-worker.md, S3): per cached package, the");
        text.AppendLine("in-process `PackageGraphs.Build` + `Reachability.Analyze` (in a harness child) against `PackageReachability.Analyze`");
        text.AppendLine("through the real `Silvergun.CLI __worker graph` beside the harness, default options.");
        text.AppendLine();
        text.AppendLine($"- manifest: `{Path.GetFileName(manifest.Path)}`, hash `{manifest.Hash}`, {manifest.Entries.Count} entr(ies)");
        text.AppendLine($"- cache: `{cacheRoot}` (read only; nothing downloaded)");
        text.AppendLine($"- packages measured: {totals.Packages}; not cached: {totals.NotCached}");
        text.AppendLine($"- folders: {totals.Folders}; agree in outcome, report, assemblies, load failures (paths and reasons), nodes and edges: {totals.Agreeing}; reports byte-equal: {totals.ReportsEqual}; shared (SameAs): {totals.SharedFolders}");
        text.AppendLine($"- mismatches: {mismatches.Count}");
        if (totals.Packages == 0 || totals.NotCached > 0)
            text.AppendLine($"- **NOT COMPARABLE**: {(totals.Packages == 0 ? "no package was measured" : $"{totals.NotCached} manifest entr(ies) not cached")}, so this run is no evidence of parity.");
        if (incomplete.Count > 0)
            text.AppendLine($"- **NOT COMPARABLE**: {incomplete.Count} package(s) where a half did not finish: {string.Join("; ", incomplete.Take(MaxListed))}");
        text.AppendLine();
        text.AppendLine("| Wall time (sum over packages) | ms |");
        text.AppendLine("|---|---:|");
        text.AppendLine($"| in-process child, whole process (start, open, build, analyze) | {totals.InProcessWallMs.ToString(CultureInfo.InvariantCulture)} |");
        text.AppendLine($"| in-process build + analyze only | {totals.InProcessBuildMs.ToString(CultureInfo.InvariantCulture)} |");
        text.AppendLine($"| worker, open + `PackageReachability.Analyze` | {totals.WorkerWallMs.ToString(CultureInfo.InvariantCulture)} |");
        text.AppendLine($"| worker, `PackageReachability.Analyze` only | {totals.WorkerAnalyzeMs.ToString(CultureInfo.InvariantCulture)} |");
        text.AppendLine();
        text.AppendLine("Peak worker memory is not observed here: the harness cannot see the worker processes `PackageReachability` starts.");
        if (mismatches.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("## Mismatches");
            text.AppendLine();
            foreach (var line in mismatches.Take(MaxListed))
                text.AppendLine($"- {line}");
            if (mismatches.Count > MaxListed)
                text.AppendLine($"- ... and {mismatches.Count - MaxListed} more (see the TSV)");
        }
        return text.ToString();
    }

    private static string Row(params string[] cells) => string.Join('\t', cells.Select(Clean));

    private static string Num(long? value) => value?.ToString(CultureInfo.InvariantCulture) ?? "";

    // One printable line from package-controlled text: control, bidi and zero-width characters become '?', and it is bounded.
    private static string Clean(string text)
    {
        var chars = text.Select(c => char.IsControl(c) || c is >= '​' and <= '‏' or >= '‪' and <= '‮' or >= '⁦' and <= '⁩' or '﻿' or '­' ? '?' : c).ToArray();
        return chars.Length <= MaxCellChars ? new string(chars) : new string(chars, 0, MaxCellChars) + "...";
    }
    #endregion

    #region Fields
    private const int MaxListed = 100;
    private const int MaxCellChars = 400;

    private static readonly string[] FolderColumns =
        ["package", "folder", "inprocess_outcome", "worker_outcome", "reports_equal", "other_differences", "worker_nodes", "worker_edges", "inprocess_nodes", "inprocess_edges", "same_as", "worker_reason"];

    private static readonly string[] PackageColumns =
        ["package", "inprocess_status", "inprocess_wall_ms", "inprocess_build_ms", "worker_status", "worker_wall_ms", "worker_analyze_ms", "folders"];

    private static readonly JsonSerializerOptions ReportOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        IgnoreReadOnlyProperties = true,
        Converters = { new JsonStringEnumConverter() },
    };
    #endregion

    #region Nested types
    private sealed class Totals
    {
        public int Packages;
        public int NotCached;
        public int Folders;
        public int Agreeing;
        public int ReportsEqual;
        public int SharedFolders;
        public long InProcessWallMs;
        public long InProcessBuildMs;
        public long WorkerWallMs;
        public long WorkerAnalyzeMs;
    }
    #endregion
}
