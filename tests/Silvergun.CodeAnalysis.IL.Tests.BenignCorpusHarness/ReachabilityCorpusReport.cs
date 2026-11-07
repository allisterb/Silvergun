namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>What the report is rendered from, besides the results. <see cref="OracleName"/>: the oracle file's name (<c>--oracle</c>).</summary>
public sealed record ReachabilityReportContext(
    DateOnly Date, CorpusManifest Manifest, string CacheRoot, BuildIdentity Identity, TimeSpan ChildTimeout, PresenceOracle Oracle,
    string OracleName = Program.OracleFileName);

/// <summary>
/// Renders reachability R2's artifacts: <c>reachability-benign-&lt;date&gt;.md</c> (sections 1-12 of the spec) and
/// <c>.tsv</c>, which are deterministic - no clock (the date comes from <c>--date</c>), no results or output path, ordinal
/// ordering, invariant numbers, <c>\n</c> line ends - and <c>reachability-benign-&lt;date&gt;-cost.md</c>, which holds every
/// measured time and working set and is <b>not</b> part of the determinism check.
/// </summary>
public static class ReachabilityCorpusReport
{
    #region Methods
    public static string MarkdownName(DateOnly date) => $"reachability-benign-{date:yyyy-MM-dd}.md";

    public static string TsvName(DateOnly date) => $"reachability-benign-{date:yyyy-MM-dd}.tsv";

    public static string CostName(DateOnly date) => $"reachability-benign-{date:yyyy-MM-dd}-cost.md";

    /// <summary>
    /// Writes the three files into <paramref name="outputDirectory"/>. Returns their paths, and why the run is not
    /// comparable (<see cref="ReachabilityAggregation.NotComparable"/>), null when it is.
    /// </summary>
    public static (IReadOnlyList<string> Paths, string? NotComparable) Write(string outputDirectory, ReachabilityReportContext context, IReadOnlyList<PackageReachResult> results)
    {
        ReachabilityAggregation.EnsureOneBuild(results.Where(r => r.Status != PackageReachResult.NotCached), context.Identity);
        Directory.CreateDirectory(outputDirectory);
        var md = Path.Combine(outputDirectory, MarkdownName(context.Date));
        var tsv = Path.Combine(outputDirectory, TsvName(context.Date));
        var cost = Path.Combine(outputDirectory, CostName(context.Date));
        WriteLines(md, Markdown(context, results));
        WriteLines(tsv, Tsv(results));
        WriteLines(cost, Cost(context, results));
        return ([md, tsv, cost], NotComparable(context, results));
    }

    /// <summary>Why no verdict may be read off these results, or null (review W2).</summary>
    public static string? NotComparable(ReachabilityReportContext context, IReadOnlyList<PackageReachResult> results) =>
        ReachabilityAggregation.NotComparable(
            ReachabilityAggregation.CompareOracle(context.Oracle, ReachabilityAggregation.View(results, Population.Plib), context.Manifest.Hash),
            results.Count(r => r.Status == PackageReachResult.NotCached));

    /// <summary>The deterministic report, sections 1-12.</summary>
    public static IReadOnlyList<string> Markdown(ReachabilityReportContext context, IReadOnlyList<PackageReachResult> results)
    {
        var plib = ReachabilityAggregation.View(results, Population.Plib);
        var pall = ReachabilityAggregation.View(results, Population.Pall);
        var roles = ReachabilityAggregation.Roles(results);
        var notComparable = NotComparable(context, results);
        var lines = new List<string>();

        lines.AddRange([
            $"# Reachability R2b - the benign-corpus measurement ({context.Date:yyyy-MM-dd})",
            string.Empty,
            "**A measurement, not a feature** (`docs/agent/tasks/reachability-r2.md`, `reachability-r2b.md`). It changes no CLI,",
            "report, gate or map. The expectations it judges (E1, E2) and their thresholds were pre-registered in the specs before",
            "any corpus run. A reachable capability is possible, not proven; a benign package's label is \"overwhelmingly not",
            "malware\" by download count, not by audit.",
            string.Empty,
        ]);

        Parameters(lines, context, results, plib, pall);
        Oracle(lines, context, plib, notComparable);
        E1Section(lines, plib, pall, notComparable);
        E2Section(lines, plib, pall, notComparable);
        Matrix(lines, results, plib, pall, roles);
        Q2(lines, plib, pall);
        Q3(lines, plib, pall);
        Q4(lines, plib, pall);
        Q5(lines, results);
        Q6(lines, context, results);
        EvidenceSection(lines, results);
        Coverage(lines, results);
        return lines;
    }

    /// <summary>
    /// The classified data, one record per line, ordinal: <c>status</c> per package, <c>roots</c> per folder and class,
    /// <c>reach</c> per folder, class and sink (with its Direct count), <c>presence</c> per folder assembly, capability and kind.
    /// </summary>
    public static IReadOnlyList<string> Tsv(IReadOnlyList<PackageReachResult> results)
    {
        string Row(params object?[] fields) => string.Join('\t', fields.Select(f => Tab(Convert.ToString(f, CultureInfo.InvariantCulture) ?? "-")));
        var rows = results.SelectMany(r =>
            new[] { Row("status", r.Id, r.Version, "-", "-", "-", "-", "-", r.Status, "-", "-", "-", "-") }
            .Concat(r.Folders.SelectMany(f =>
                f.RootCounts.Select(c => Row("roots", r.Id, r.Version, f.Folder, f.Role, f.IsPlib ? "yes" : "no", c.Class, "-", "-", c.Roots, "-", "-", "-"))
                .Concat(f.Reaches.Select(x => Row("reach", r.Id, r.Version, f.Folder, f.Role, f.IsPlib ? "yes" : "no", x.Class, SinkName(x.Capability), "-", x.Roots, x.Bound, x.Instantiated, x.Direct)))
                .Concat(f.Presence.SelectMany(p => p.Findings.Select(n =>
                    Row("presence", r.Id, r.Version, f.Folder, f.Role, f.IsPlib ? "yes" : "no", p.Assembly, n.Capability, n.Kind, n.Findings, "-", "-", "-")))))))
            .Order(StringComparer.Ordinal);
        return [Row("Record", "Package", "Version", "Folder", "Role", "PLib", "ClassOrAssembly", "Capability", "KindOrStatus", "Count", "Bound", "Instantiated", "Direct"), .. rows];
    }

    /// <summary>The cost file: every time and working set. Not deterministic, and not part of the determinism check.</summary>
    public static IReadOnlyList<string> Cost(ReachabilityReportContext context, IReadOnlyList<PackageReachResult> results)
    {
        var lines = new List<string>
        {
            $"# Reachability R2 - cost ({context.Date:yyyy-MM-dd})",
            string.Empty,
            $"Companion of `{MarkdownName(context.Date)}` (spec Q6). Measured times and working sets vary run to run, so they",
            "live here and not in the report, which must be byte-identical across cold runs. Build = `PackageGraphs.Build`'s",
            "step for the folder; Analyze = `Reachability.Analyze`; Presence = `CapabilityAnalysis` over the folder's assemblies.",
            "Peak working set is the child's own `Process.PeakWorkingSet64` at the end of its run.",
            string.Empty,
            "## Distribution",
            string.Empty,
        };

        // Every child that finished: scanned, graph-failed or no-assemblies.
        var children = results.Where(r => r.Measured || r.Status == PackageReachResult.NoAssemblies).ToArray();
        var peaks = children.Select(r => r.Cost.PeakWorkingSetBytes / (1024.0 * 1024.0)).Order().ToArray();
        var folders = children.SelectMany(r => r.Cost.Folders.Select(f => (r.Id, Cost: f))).ToArray();
        var ratios = folders.Where(f => f.Cost.BuildMs > 0).Select(f => (double)f.Cost.AnalyzeMs / f.Cost.BuildMs).Order().ToArray();
        lines.AddRange([
            "| Quantity | n | Median | p90 | Max |",
            "| --- | ---: | ---: | ---: | ---: |",
            $"| Peak working set per child (MB) | {peaks.Length} | {F1(ReachabilityAggregation.Median(peaks))} | {F1(ReachabilityAggregation.P90(peaks))} | {F1(peaks.LastOrDefault())} |",
            $"| Analyze / Build per folder (folders with Build > 0 ms) | {ratios.Length} | {F2(ReachabilityAggregation.Median(ratios))} | {F2(ReachabilityAggregation.P90(ratios))} | {F2(ratios.LastOrDefault())} |",
            string.Empty,
            $"Totals: Build {folders.Sum(f => f.Cost.BuildMs)} ms, Analyze {folders.Sum(f => f.Cost.AnalyzeMs)} ms, Presence {folders.Sum(f => f.Cost.PresenceMs)} ms, " +
            $"child wall {results.Sum(r => r.Cost.ChildWallMs)} ms.",
            string.Empty,
            "## Per package",
            string.Empty,
            "| Package | Version | Status | Child wall ms | Child total ms | Open ms | Peak working set MB |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: |",
        ]);
        lines.AddRange(results.Select(r =>
            $"| {r.Id} | {r.Version} | {r.Status} | {r.Cost.ChildWallMs} | {r.Cost.ChildTotalMs} | {r.Cost.OpenMs} | {F1(r.Cost.PeakWorkingSetBytes / (1024.0 * 1024.0))} |"));
        lines.AddRange([
            string.Empty,
            "## Per folder",
            string.Empty,
            "| Package | Folder | Build ms | Analyze ms | Presence ms | Analyze / Build | Working set after (MB) |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]);
        lines.AddRange(folders.Select(f =>
            $"| {f.Id} | {Escape(f.Cost.Folder)} | {f.Cost.BuildMs} | {f.Cost.AnalyzeMs} | {f.Cost.PresenceMs} | " +
            $"{(f.Cost.BuildMs > 0 ? F2((double)f.Cost.AnalyzeMs / f.Cost.BuildMs) : "-")} | {F1(f.Cost.WorkingSetAfterBytes / (1024.0 * 1024.0))} |"));
        return lines;
    }

    private static void Parameters(List<string> lines, ReachabilityReportContext context, IReadOnlyList<PackageReachResult> results, PopulationView plib, PopulationView pall)
    {
        int Status(string status) => results.Count(r => r.Status == status);
        var withTfm = results.Count(r => r.Measured && r.LibTfm is not null);
        lines.AddRange([
            "## 1. Parameters",
            string.Empty,
            "| Parameter | Value |",
            "| --- | --- |",
            $"| Manifest | `{Path.GetFileName(context.Manifest.Path)}` |",
            $"| Manifest hash (sha256 of normalized `id,version` list) | `{context.Manifest.Hash}` |",
            $"| Manifest entries | {context.Manifest.Entries.Count} |",
            $"| Cache root (read only; no download in this mode) | `{Program.DisplayPath(context.CacheRoot)}` |",
            $"| Harness build: `git describe --always --dirty --abbrev=40`, `-dirty` also when `src/`, `ext/` or `tests/` has untracked files | `{SafeCommit(context.Identity.Commit)}`" +
            $"{(context.Identity.Commit.EndsWith(BuildIdentities.DirtySuffix, StringComparison.Ordinal) ? " **(uncommitted changes: not a corpus-run build)**" : string.Empty)} |",
            $"| Harness build: sha256 of the output directory's top-level assemblies | `{context.Identity.AssembliesSha256}` |",
            $"| Date (`--date`) | {context.Date:yyyy-MM-dd} |",
            $"| Child timeout | {context.ChildTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture)} s |",
            $"| Status: scanned / graph-failed / no-assemblies / crashed / timeout / incomplete / not-cached | {Status(PackageReachResult.Scanned)} / " +
            $"{Status(PackageReachResult.GraphFailed)} / {Status(PackageReachResult.NoAssemblies)} / " +
            $"{Status(PackageReachResult.Crashed)} / {Status(PackageReachResult.Timeout)} / {Status(PackageReachResult.Incomplete)} / {Status(PackageReachResult.NotCached)} |",
            $"| Measured packages with a lib TFM (`TfmSelection`) | {withTfm} |",
            $"| Unmeasured floor packages (crashed / timeout / incomplete): in P-all / in P-lib (a lib TFM by `TfmSelection` over the `.nupkg`, or unknown) | " +
            $"{pall.Units.Count(u => u.Result.UnmeasuredFloor)} / {plib.Units.Count(u => u.Result.UnmeasuredFloor)} |",
            $"| **P-lib denominator** (the P-lib folder is one either side read: graph or presence) | **{plib.Denominator}** |",
            $"| **P-all denominator** (some folder is one either side read: graph or presence) | **{pall.Denominator}** |",
            $"| Names cut at {Reachability.MaxNameChars} chars (amendment a5; distinct per folder, summed over every folder; per folder in section 12) | {NamesCutText(NamesCutTotal(results))} |",
            $"| Signal capabilities | {string.Join(", ", ReachabilityChild.SignalCapabilities)} |",
            $"| Trigger classes | {string.Join(", ", ReachabilityChild.TriggerClasses)} |",
            $"| Judged in this run (P-lib and P-all, both must pass) | {string.Join(", ", ReachabilityAggregation.RuntimeClasses)} |",
            $"| Judged by `--combine` only (P-all over C100 and C-build) | {string.Join(", ", ReachabilityAggregation.CombineClasses)} |",
            $"| Labels (each (class, label) its own verdict) | {string.Join(", ", ReachabilityAggregation.Labels)} |",
            $"| Presence oracle (`--oracle`) | `{Escape(context.OracleName)}` |",
            $"| Judged when presence is at least | {ReachabilityAggregation.MinimumJudgedPresence} packages in the population |",
            "| E1 | per judged signal capability: reach share (ChaOnly) <= 0.5 x presence share |",
            "| E2 | packages with a class profile holding >= 2 distinct signal capabilities (Unseen-inclusive) <= 10% |",
            string.Empty,
            "**Populations.** P-lib: per package, the folder `lib/<TfmSelection.Choose>` (highest `net<x>.<y>`, else",
            "`netstandard2.0`), the presence baseline's folder. P-all: every folder either side read (a built graph, or a",
            "graph-failed folder presence scanned, which makes its package a floor package); a package counts",
            "for (class, capability) when any of its folders does. A crashed, timed-out or incomplete package is a floor",
            "package with unmeasured presence and reach: in P-all always, in P-lib when its `.nupkg` has a lib TFM (or its file",
            "list is unreadable, so that is unknown), and in no role table. Presence is the raw-CCI `CapabilityAnalysis`, all finding",
            "kinds, over each folder's assemblies, recomputed in the same child. Reach share = packages where a root of the",
            "class reaches the capability at ChaOnly (`CapabilityReach.Roots > 0`); Bound share uses `Bound > 0`; Direct share",
            "uses `Direct > 0`, the roots reaching it with no `Ldftn`, `Ldvirtftn` or `LoadToken` edge (ADR 0037 amendment a2).",
            string.Empty,
            "### Per package",
            string.Empty,
            "| Package | Version | Status | Lib TFM | Folders | Loaded folders | Roles | P-lib |",
            "| --- | --- | --- | --- | ---: | ---: | --- | --- |",
        ]);
        var inPlib = plib.Units.Select(u => u.Id).ToHashSet(StringComparer.Ordinal);
        lines.AddRange(results.Select(r =>
            $"| {r.Id} | {r.Version} | {r.Status} | {r.LibTfm ?? "-"} | {r.Folders.Count} | {r.BuiltFolders.Count()} | " +
            $"{Escape(string.Join(", ", r.BuiltFolders.Select(f => f.Role).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)))} | " +
            $"{(inPlib.Contains(r.Id) ? "yes" : "no")} |"));
        lines.Add(string.Empty);
    }

    private static void Oracle(List<string> lines, ReachabilityReportContext context, PopulationView plib, string? notComparable)
    {
        var comparison = ReachabilityAggregation.CompareOracle(context.Oracle, plib, context.Manifest.Hash);
        var nonDll = plib.Units.SelectMany(u => u.Folders.SelectMany(f => f.Presence.Where(p => !p.Assembly.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            .Select(p => $"{u.Id}: {p.Assembly}"))).ToArray();
        lines.AddRange([
            $"## 2. Regression oracle (P-lib presence against `{Escape(context.OracleName)}`)",
            string.Empty,
            "P-lib presence, every finding kind, over the P-lib folders' `.dll` assemblies (the baseline's rule), against the",
            "presence oracle (`--oracle`; the file's header names the report it was copied from): the denominator, assemblies,",
            "methods analysed, findings, the per-capability package counts and totals, and per package its TFM, assemblies,",
            "methods and findings per capability. R2 used `presence-oracle-2026-08-21.tsv`; R2b's default, on the S2 map, is",
            "`presence-oracle-2026-11-06.tsv`. A crashed, timed-out or",
            "incomplete package in P-lib (a lib TFM, or an unknown one) has no measured presence, so it always makes the oracle",
            "a MISMATCH, and the run then gives no verdict (by design: R2's pre-registered rule, the conservative direction).",
            string.Empty,
            comparison.Full
                ? $"**Result: {(comparison.Match ? "MATCH" : "MISMATCH")}** ({comparison.PackagesCompared} packages compared, totals included)."
                : $"**Result: {(comparison.Match ? "MATCH" : "MISMATCH")} on the {comparison.PackagesCompared} package(s) both hold; totals not applicable** " +
                  $"(this manifest's hash is not the oracle's `{context.Oracle.ManifestHash}`).",
            string.Empty,
        ]);
        if (comparison.Differences.Count > 0)
        {
            lines.Add("Differences:");
            lines.Add(string.Empty);
            lines.AddRange(comparison.Differences.Select(d => $"- {Escape(d)}"));
            lines.Add(string.Empty);
        }
        lines.Add(nonDll.Length == 0
            ? "No P-lib folder holds a non-`.dll` assembly, so P-lib presence and the oracle's presence are the same set."
            : $"P-lib folders hold {nonDll.Length} non-`.dll` assembl(ies), outside the oracle but inside P-lib presence: {Escape(string.Join("; ", nonDll))}.");
        lines.Add(string.Empty);
        lines.Add(notComparable is null
            ? "**The population is comparable:** the oracle is a full MATCH and no entry is `not-cached`, so the verdicts below stand."
            : $"**No verdict: {notComparable}.** Every E1 and E2 cell and every class verdict below reads so; the shares are shown, " +
              "but nothing may be concluded from them (spec, \"No verdict without a comparable population\").");
        lines.Add(string.Empty);
    }

    private static void E1Section(List<string> lines, PopulationView plib, PopulationView pall, string? notComparable)
    {
        lines.AddRange([
            "## 3. E1 - trigger reach shares against presence",
            string.Empty,
            "Judged symmetrically. A floor package has Partial reachability, an assembly only presence saw (graph-failed folders",
            "included), or an assembly only the graph loaded, or its child crashed, timed out or stopped short (presence and",
            "reach unmeasured); it stays in the denominator. A cell **fails** only in its best",
            "case: reach from built graphs, against presence from every scoped folder plus each floor package whose presence",
            "could not be measured. It **passes** only in its worst case: every floor package not already reaching counted as",
            "reaching, against presence from the graph-loaded assemblies only. Otherwise it is **Floor**, not a pass.",
            string.Empty,
            "**Unmeasured packages and the verdict.** A crashed, timed-out or incomplete package in P-lib (its `.nupkg` has a",
            "lib TFM, or whether it has one is unknown) makes the regression oracle a MISMATCH (section 2), so no verdict is",
            "given at all. Of the unmeasured packages, therefore, only the P-all floors of packages with no lib TFM ever feed a",
            "verdict; the P-lib floor rule is applied, but cannot decide one.",
            string.Empty,
            "**Labels and populations (R2b).** Each trigger class is judged at two labels, each (class, label) its own verdict:",
            "**ChaOnly**, R2's cell (reach = `CapabilityReach.Roots > 0`), and **Direct** (reach counts only the roots reaching",
            "the capability without a deferred edge (Ldftn, Ldvirtftn, LoadToken), `CapabilityReach.Direct > 0`; E2 counts only the profiles' Direct sets).",
            $"{string.Join(", ", ReachabilityAggregation.RuntimeClasses)} are judged on this run, in P-lib and P-all: a (class,",
            $"label) passes only if it passes in both. {string.Join(" and ", ReachabilityAggregation.CombineClasses)} are judged on P-all only, over C100",
            $"and C-build as one population, by `--combine` alone: here their cells are data and read \"{ClassVerdict.JudgedByCombine}\",",
            "never a verdict.",
            string.Empty,
        ]);
        foreach (var view in new[] { plib, pall })
        {
            lines.AddRange([$"### {view.Name} (denominator {view.Denominator}; floor packages {view.Units.Count(u => u.Floor)})", string.Empty]);
            foreach (var label in ReachabilityAggregation.Labels)
                E1Table(lines, view, label, ReachabilityChild.TriggerClasses, (k, text) => ReachabilityAggregation.JudgedInSingleRun(k) ? notComparable ?? text : ClassVerdict.JudgedByCombine);
        }

        string Cell(RootClass k, Outcome? outcome) => !ReachabilityAggregation.JudgedInSingleRun(k) ? ClassVerdict.JudgedByCombine : notComparable ?? Render(outcome!.Value);
        lines.AddRange([
            "### Per-class verdict (a fail of E1 or E2 in either population = does not discriminate; any Floor = undecided)",
            string.Empty,
            "| Class | Label | P-lib E1 | P-lib E2 | P-all E1 | P-all E2 | Verdict |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            .. ReachabilityChild.TriggerClasses.SelectMany(k => ReachabilityAggregation.Labels.Select(l => ReachabilityAggregation.Verdicts(plib, pall, l).Single(v => v.Class == k)))
                .Select(v => $"| {v.Class} | {v.Label} | {Cell(v.Class, v.PlibE1)} | {Cell(v.Class, v.PlibE2)} | {Cell(v.Class, v.PallE1)} | {Cell(v.Class, v.PallE2)} | " +
                    $"{(ReachabilityAggregation.JudgedInSingleRun(v.Class) ? notComparable ?? v.Verdict : ClassVerdict.JudgedByCombine)} |"),
            string.Empty,
        ]);
    }

    /// <summary>
    /// One E1 table at <paramref name="label"/> over <paramref name="classes"/>: per signal capability, presence and per class
    /// its reach (ChaOnly also its Bound share) and cell; then each class's roots and outcome. <paramref name="judge"/> turns a
    /// rendered cell or outcome of a class into what the report may show (a not-comparable reason, "judged by --combine").
    /// </summary>
    internal static void E1Table(List<string> lines, PopulationView view, ReachLabel label, IReadOnlyList<RootClass> classes, Func<RootClass, string, string> judge)
    {
        var results = classes.Select(k => ReachabilityAggregation.E1(view, k, label)).ToArray();
        var bound = label == ReachLabel.ChaOnly;
        lines.AddRange([
            $"#### {view.Name} - {label}",
            string.Empty,
            "| Signal capability | Presence | " + string.Join(" | ", results.Select(r => bound ? $"{r.Class} reach | {r.Class} Bound | {r.Class} E1" : $"{r.Class} Direct reach | {r.Class} E1")) + " |",
            "| --- | ---: |" + string.Concat(results.Select(_ => bound ? " ---: | ---: | --- |" : " ---: | --- |")),
        ]);
        foreach (var capability in ReachabilityChild.SignalCapabilities)
        {
            var cells = results.Select(r => r.Cells.Single(c => c.Capability == capability)).ToArray();
            lines.Add($"| {capability} | {cells[0].Presence} | " + string.Join(" | ", cells.Zip(results).Select(x =>
                $"{x.First.Reach} | {(bound ? $"{x.First.Bound} | " : string.Empty)}" +
                judge(x.Second.Class, x.Second.Outcome == Outcome.NoData ? "no data"
                    : x.First.PossiblyJudged ? (x.First.WorstCasePasses ? "Pass (may be judged)" : "Floor (may be judged)")
                    : !x.First.Judged ? "too rare to judge"
                    : x.First.Outcome == Outcome.Floor ? $"Floor ({x.First.FloorPackages} floor package(s); presence best {x.First.PresenceBest}, seen {x.First.PresenceSeen})"
                    : Render(x.First.Outcome)))) + " |");
        }
        lines.AddRange([
            string.Empty,
            "| Class | Roots | E1 |",
            "| --- | ---: | --- |",
            .. results.Select(r => $"| {r.Class} | {r.Roots} | {judge(r.Class, Render(r.Outcome))} |"),
            string.Empty,
        ]);
    }

    private static void E2Section(List<string> lines, PopulationView plib, PopulationView pall, string? notComparable)
    {
        lines.AddRange([
            "## 4. E2 - trigger compositions",
            string.Empty,
            "Packages with a profile (`ReachProfile`) of the class holding two or more distinct signal capabilities. The judged",
            "column counts every such profile; the next two split it by whether the profile also reaches Unseen. Floor packages",
            "are those not counted whose class profiles were cut at 64, or whose reaches are a floor; E2 fails when",
            "`10 x counted > denominator`, passes only when `10 x (counted + floor) <= denominator`, and is otherwise Floor. At",
            "Direct a profile counts by its Direct capability set (`ReachProfile.DirectCapabilities`, `DirectUnseen`).",
            string.Empty,
        ]);
        foreach (var view in new[] { plib, pall })
            E2Table(lines, view, ReachabilityChild.TriggerClasses,
                (k, text) => ReachabilityAggregation.JudgedInSingleRun(k) ? notComparable ?? text : ClassVerdict.JudgedByCombine);
    }

    /// <summary>One E2 table over <paramref name="classes"/>, a row per (class, label); <paramref name="judge"/> as in <see cref="E1Table"/>.</summary>
    internal static void E2Table(List<string> lines, PopulationView view, IReadOnlyList<RootClass> classes, Func<RootClass, string, string> judge) =>
        lines.AddRange([
            $"### {view.Name} (denominator {view.Denominator})",
            string.Empty,
            "| Class | Label | Roots | >= 2 signals (Unseen-inclusive, judged) | Without Unseen | With Unseen | Class profiles cut at 64 (packages) | Floor packages | E2 |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
            .. classes.SelectMany(k => ReachabilityAggregation.Labels.Select(l => ReachabilityAggregation.E2(view, k, l))).Select(e =>
                $"| {e.Class} | {e.Label} | {e.Roots} | {e.Inclusive} | {e.Exclusive} | {e.WithUnseen} | " +
                $"{(e.TruncatedPackages > 0 ? $"**{e.TruncatedPackages}**" : "0")} | {e.FloorPackages} | {judge(e.Class, Render(e.Outcome))} |"),
            string.Empty,
        ]);

    private static void Matrix(List<string> lines, IReadOnlyList<PackageReachResult> results, PopulationView plib, PopulationView pall, IReadOnlyList<string> roles)
    {
        lines.AddRange([
            "## 5. Class x capability reach shares",
            string.Empty,
            "Cells are `share (packages)` over the stated denominator. Presence has no Unseen column. A role table counts only",
            "that role's folders, over the packages that have one. \"Unmeasured\" is how many packages of the denominator",
            "crashed, timed out or stopped short: they are counted in it, but contribute no presence or reach. Direct counts",
            "`CapabilityReach.Direct > 0`: a root reaching the sink with no deferred edge (Ldftn, Ldvirtftn, LoadToken).",
            string.Empty,
        ]);
        var sinks = Enum.GetValues<Capability>().Select(c => (Capability?)c).Append(null).ToArray();
        foreach (var view in new[] { plib, pall }.Concat(roles.Select(r => ReachabilityAggregation.View(results, Population.Pall, r))))
            foreach (var (name, reach) in new (string, Func<RootClass, Capability?, Share>)[]
            {
                (nameof(Tier.ChaOnly), (k, s) => ReachabilityAggregation.Reach(view, k, s, Tier.ChaOnly)),
                (nameof(Tier.Bound), (k, s) => ReachabilityAggregation.Reach(view, k, s, Tier.Bound)),
                (nameof(ReachLabel.Direct), (k, s) => ReachabilityAggregation.Reach(view, k, s, ReachLabel.Direct)),
            })
            {
                lines.AddRange([
                    $"### {Escape(view.Name)} - {name} (denominator {view.Denominator}; unmeasured {view.Unmeasured})",
                    string.Empty,
                    "| Row | " + string.Join(" | ", sinks.Select(SinkName)) + " |",
                    "| --- |" + string.Concat(sinks.Select(_ => " ---: |")),
                    "| presence | " + string.Join(" | ", sinks.Select(s => s is { } c ? Cell(ReachabilityAggregation.Presence(view, c)) : "-")) + " |",
                    .. ReachabilityChild.AllClasses.Select(k =>
                        $"| {k} | " + string.Join(" | ", sinks.Select(s => Cell(reach(k, s)))) + " |"),
                    string.Empty,
                ]);
            }
    }

    private static void Q2(List<string> lines, PopulationView plib, PopulationView pall)
    {
        lines.AddRange([
            "## 6. Q2 - PublicContract against PublicApi and Hidden",
            string.Empty,
            "Per package, a class's roots over its own methods (summed over the population's folders); median and p90",
            "(nearest-rank) over the packages with own methods. A method may carry several classes; Hidden carries no other.",
            string.Empty,
        ]);
        foreach (var view in new[] { plib, pall })
        {
            var own = view.Units.Sum(u => u.Folders.Sum(f => f.OwnMethods));
            lines.AddRange([
                $"### {view.Name} (denominator {view.Denominator}; unmeasured {view.Unmeasured}; {own} own methods; " +
                $"{view.Units.Sum(u => u.Folders.Sum(f => f.PublicContractOnly))} PublicContract-only, {view.Units.Sum(u => u.Folders.Sum(f => f.HiddenOnly))} Hidden)",
                string.Empty,
                "| Class | Packages | Median share of own methods | p90 |",
                "| --- | ---: | ---: | ---: |",
                .. ReachabilityChild.AllClasses.Select(k => ReachabilityAggregation.RootShares(view, k)).Select(s =>
                    $"| {s.Class} | {s.Packages} | {Pct(s.Median)} | {Pct(s.P90)} |"),
                string.Empty,
                "| Capability | PublicApi reach | PublicContract reach | Hidden reach |",
                "| --- | ---: | ---: | ---: |",
                .. Enum.GetValues<Capability>().Select(c =>
                    $"| {c} | {ReachabilityAggregation.Reach(view, RootClass.PublicApi, c)} | {ReachabilityAggregation.Reach(view, RootClass.PublicContract, c)} | " +
                    $"{ReachabilityAggregation.Reach(view, RootClass.Hidden, c)} |"),
                string.Empty,
            ]);
        }
    }

    private static void Q3(List<string> lines, PopulationView plib, PopulationView pall)
    {
        lines.AddRange([
            "## 7. Q3 - evidence tiers",
            string.Empty,
            "Per class, the reached (package, capability) pairs (any capability, ChaOnly), by the strongest tier any of the",
            "package's folders reaches the capability on.",
            string.Empty,
        ]);
        foreach (var view in new[] { plib, pall })
            lines.AddRange([
                $"### {view.Name} (denominator {view.Denominator})",
                string.Empty,
                "| Class | Reached pairs | Bound | Instantiated, not Bound | ChaOnly only |",
                "| --- | ---: | ---: | ---: | ---: |",
                .. ReachabilityChild.AllClasses.Select(k => ReachabilityAggregation.Tiers(view, k)).Select(t =>
                    $"| {t.Class} | {t.Pairs} | {new Share(t.Bound, t.Pairs)} | {new Share(t.InstantiatedNotBound, t.Pairs)} | {new Share(t.ChaOnlyOnly, t.Pairs)} |"),
                string.Empty,
            ]);
    }

    private static void Q4(List<string> lines, PopulationView plib, PopulationView pall)
    {
        lines.AddRange([
            "## 8. Q4 - Unknown",
            string.Empty,
            "Unknown = packages with a folder whose verdict for the class is `Unknown`. Reasons count the packages with an",
            "Unknown folder giving each reason. `unseen` is split by how the class's Unseen example paths (up to three per",
            "folder) end: at an opacity site (by kind), an own InternalCall, or an external the map marks `unanalyzed`. Load",
            "failures are not in any verdict yet (R3 carry) and are counted separately. A crashed, timed-out or incomplete",
            $"package is Unknown for every class, with the reason `{ReachabilityAggregation.UnmeasuredReason}`.",
            string.Empty,
        ]);
        foreach (var view in new[] { plib, pall })
        {
            var unseen = view.Units.SelectMany(u => u.Folders).Select(f => f.Unseen).OfType<UnseenBreakdown>().ToArray();
            lines.AddRange([
                $"### {view.Name} (denominator {view.Denominator})",
                string.Empty,
                "| Class | Unknown | Reasons (packages) | Unseen example ends (packages) | Packages with load failures |",
                "| --- | ---: | --- | --- | ---: |",
                .. ReachabilityChild.AllClasses.Select(k => ReachabilityAggregation.Unknown(view, k)).Select(u =>
                    $"| {u.Class} | {u.Unknown} | {Counts(u.Reasons)} | {Counts(u.UnseenEnds)} | {u.PackagesWithLoadFailures} |"),
                string.Empty,
                $"Unseen sinks in the population's folders: opacity sites {Counts([.. unseen.SelectMany(b => b.OpacitySites).GroupBy(s => s.Name, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => new NamedCount(g.Key, g.Sum(s => s.Count)))])}; " +
                $"InternalCall nodes {unseen.Sum(b => b.InternalCallNodes)}; `unanalyzed` externals {unseen.Sum(b => b.UnanalyzedExternals)}.",
                string.Empty,
            ]);
        }
    }

    private static void Q5(List<string> lines, IReadOnlyList<PackageReachResult> results)
    {
        var parity = ReachabilityAggregation.Parity(results);
        var notExact = parity.Where(p => p.Parity.Verdict != "EXACT").ToArray();
        lines.AddRange([
            "## 9. Q5 - presence parity per folder (ADR 0037 decision 9)",
            string.Empty,
            "The rule of `PresenceParityTests`: distinct (caller, capability, callee) triples of the scanner's Call, Construct,",
            "MethodPointerLoad and NativeImport findings against the graph's capability sink edges and NativeImport facts. A",
            "scanner-only triple is NameShadowed when the graph has a call-site edge from that caller to an own node keyed as",
            "the callee. EXACT = no difference; NAMED = only NameShadowed; DIFFERS = an unexplained difference. Lists keep 50",
            "items; counts are true.",
            string.Empty,
            $"Folders compared: {parity.Count}; EXACT {parity.Count(p => p.Parity.Verdict == "EXACT")}; NAMED {parity.Count(p => p.Parity.Verdict == "NAMED")}; " +
            $"DIFFERS {parity.Count(p => p.Parity.Verdict == "DIFFERS")}. Triples matched {parity.Sum(p => p.Parity.Matched)}, NameShadowed " +
            $"{parity.Sum(p => p.Parity.NameShadowed.Count)}, scanner-only {parity.Sum(p => p.Parity.ScannerOnly.Count)}, graph-only {parity.Sum(p => p.Parity.GraphOnly.Count)}.",
            string.Empty,
        ]);
        if (notExact.Length == 0)
        {
            lines.AddRange(["*Every folder is EXACT.*", string.Empty]);
            return;
        }
        lines.AddRange([
            "| Package | Version | Folder | Parity | Matched | NameShadowed | Scanner only | Graph only |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
            .. notExact.Select(p => $"| {p.Package} | {p.Version} | {Escape(p.Folder)} | {p.Parity.Verdict} | {p.Parity.Matched} | {p.Parity.NameShadowed.Count} | " +
                $"{p.Parity.ScannerOnly.Count} | {p.Parity.GraphOnly.Count} |"),
            string.Empty,
        ]);
        foreach (var p in notExact)
        {
            lines.Add($"#### {p.Package} {p.Version} `{Escape(p.Folder)}`");
            lines.Add(string.Empty);
            foreach (var (name, list) in new[] { ("NameShadowed", p.Parity.NameShadowed), ("Scanner only", p.Parity.ScannerOnly), ("Graph only", p.Parity.GraphOnly) })
                if (list.Count > 0)
                {
                    lines.Add($"- {name} ({list.Count}{(list.Count > list.Items.Count ? $", first {list.Items.Count} listed" : string.Empty)}):");
                    lines.AddRange(list.Items.Select(i => $"  - {Escape(i)}"));
                }
            lines.Add(string.Empty);
        }
    }

    private static void Q6(List<string> lines, ReachabilityReportContext context, IReadOnlyList<PackageReachResult> results)
    {
        var failed = results.Where(r => r.Status is not PackageReachResult.Scanned).ToArray();
        var loadFailures = results.SelectMany(r => r.Folders.SelectMany(f => f.LoadFailures.Select(l => (r, f, l)))).ToArray();
        var scanFailures = results.SelectMany(r => r.Folders.SelectMany(f => f.Presence.Where(p => !p.Ok || p.MethodsSkipped > 0).Select(p => (r, f, p)))).ToArray();
        lines.AddRange([
            "## 10. Q6 - cost, crashes, timeouts, not-cached packages and load failures",
            string.Empty,
            $"Analyze and build times and peak working sets are in `{CostName(context.Date)}`, kept out of this file so that it",
            "stays byte-identical across cold runs.",
            string.Empty,
            "### Packages not scanned",
            string.Empty,
        ]);
        if (failed.Length == 0)
            lines.Add("*None: every manifest entry was scanned.*");
        else
            lines.AddRange([
                "| Package | Version | Status | Exit code | Detail |",
                "| --- | --- | --- | ---: | --- |",
                .. failed.Select(r => $"| {r.Id} | {r.Version} | {r.Status} | {(r.ExitCode is { } e ? e.ToString(CultureInfo.InvariantCulture) : "-")} | {Escape(Deterministic(r.Detail ?? "-"))} |"),
            ]);
        lines.AddRange([string.Empty, $"### Load failures ({loadFailures.Length})", string.Empty]);
        if (loadFailures.Length == 0)
            lines.Add("*None.*");
        else
            lines.AddRange([
                "| Package | Version | Folder | Assembly | Reason |",
                "| --- | --- | --- | --- | --- |",
                .. loadFailures.Select(x => $"| {x.r.Id} | {x.r.Version} | {Escape(x.f.Folder)} | {Escape(x.l.RelativePath)} | {Escape(Deterministic(x.l.Reason))} |"),
            ]);
        lines.AddRange([string.Empty, $"### Presence scans failed or partial ({scanFailures.Length})", string.Empty]);
        if (scanFailures.Length == 0)
            lines.Add("*None.*");
        else
            lines.AddRange([
                "| Package | Version | Folder | Assembly | Failure | Methods skipped |",
                "| --- | --- | --- | --- | --- | ---: |",
                .. scanFailures.Select(x => $"| {x.r.Id} | {x.r.Version} | {Escape(x.f.Folder)} | {Escape(x.p.Assembly)} | {Escape(Deterministic(x.p.Failure ?? "-"))} | {x.p.MethodsSkipped} |"),
            ]);
        lines.Add(string.Empty);
    }

    private static void EvidenceSection(List<string> lines, IReadOnlyList<PackageReachResult> results)
    {
        var evidence = ReachabilityAggregation.TriggerEvidence(results);
        lines.AddRange([
            $"## 11. Trigger-class evidence ({evidence.Count})",
            string.Empty,
            "Every trigger-class x signal-capability reach of every loaded folder, with its first example path (strongest",
            "tier first, at most 64 hops: the first 62 and the last two). This is the list a human reads to judge each hit.",
            "\"Direct path\": the example has no deferred edge. \"Direct reach\": the folder's row counts a Direct root, so the",
            "reach is in the Direct cells. They can differ: the Direct pass is over ChaOnly edges, while the example is the",
            "strongest tier's path (R2b S1, known limit), so a Direct reach can show a delegate path.",
            string.Empty,
        ]);
        if (evidence.Count == 0)
        {
            lines.AddRange(["*None: no trigger-class root reaches a signal capability.*", string.Empty]);
            return;
        }
        lines.AddRange([
            "| Class | Capability | Package | Version | Folder | P-lib | Root | Evidence | Direct path | Direct reach | Length | Path |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- |",
            .. evidence.Select(e =>
                $"| {e.Example.Class} | {e.Example.Capability} | {e.Package} | {e.Version} | {Escape(e.Folder)} | {(e.IsPlib ? "yes" : "no")} | {Escape(e.Example.Root)} | " +
                $"{e.Example.Evidence} | {(e.Example.Direct ? "yes" : "no")} | {(e.DirectReach ? "yes" : "no")} | " +
                $"{e.Example.Length}{(e.Example.Truncated ? " (truncated)" : string.Empty)} | {Escape(PathText(e.Example))} |"),
            string.Empty,
        ]);
    }

    private static void Coverage(List<string> lines, IReadOnlyList<PackageReachResult> results)
    {
        var rows = results.SelectMany(Floors).ToArray();
        lines.AddRange([
            "## 12. Coverage honesty (ADR-0024)",
            string.Empty,
            "Every package or folder whose numbers above are a floor, not a total, and why. Unknown verdicts are already",
            "counted in section 8 and are not repeated here.",
            string.Empty,
        ]);
        if (rows.Length == 0)
            lines.Add("*None.*");
        else
            lines.AddRange([
                "| Package | Version | Folder | Why |",
                "| --- | --- | --- | --- |",
                .. rows.Select(x => $"| {x.Package} | {x.Version} | {Escape(x.Folder)} | {Escape(Deterministic(x.Why))} |"),
            ]);
        lines.AddRange([
            string.Empty,
            $"Names cut at {Reachability.MaxNameChars} chars (amendment a5), over every folder: {NamesCutText(NamesCutTotal(results))}. A folder that cut",
            "any is listed above with its count; a cut changes the names reported, never a count.",
        ]);
    }

    /// <summary>The distinct names cut (<see cref="FolderResult.NamesCut"/>), summed over every folder of <paramref name="results"/>.</summary>
    public static int NamesCutTotal(IEnumerable<PackageReachResult> results) => results.SelectMany(r => r.Folders).Sum(f => f.NamesCut);

    /// <summary>A names-cut total as the reports show it: <c>0</c>, or bold with a note, so a nonzero total is never missed.</summary>
    public static string NamesCutText(int total) =>
        total == 0 ? "0" : $"**{total.ToString(CultureInfo.InvariantCulture)}** (some reported names are bounded, not whole)";

    private static IEnumerable<(string Package, string Version, string Folder, string Why)> Floors(PackageReachResult r)
    {
        if (r.UnmeasuredFloor)
            yield return (r.Id, r.Version, r.LibTfm is { } tfm ? $"lib/{tfm}" : "-",
                $"{r.Status}: {r.Detail ?? "-"}; {UnmeasuredFloorText(r.LibTfmState)}");
        else if (r.Status != PackageReachResult.Scanned)
            yield return (r.Id, r.Version, "-", $"{r.Status}: {r.Detail ?? "-"}");
        if (!r.Measured)
            yield break;
        if (r.LibTfm is not null && !r.PlibFolders.Any(f => f.Read))
            yield return (r.Id, r.Version, $"lib/{r.LibTfm}", "lib TFM chosen, but no P-lib folder either side read: the package is outside P-lib");
        else if (r.LibTfm is not null && !r.PlibFolders.Any(f => f.GraphBuilt))
            yield return (r.Id, r.Version, $"lib/{r.LibTfm}", "P-lib folder graph-failed (floor package)");
        foreach (var f in r.Folders)
        {
            var why = new List<string>();
            if (!f.GraphBuilt)
                why.Add("no assembly of the folder loaded: no graph");
            if (f.LoadFailures.Count > 0)
                why.Add($"{f.LoadFailures.Count} assembl(ies) not loaded");
            if (f.Coverage is { } c)
            {
                if (c.Truncated)
                    why.Add($"graph truncated: {c.TruncatedBy}");
                if (!c.IndexComplete)
                    why.Add($"member index incomplete (assemblies {c.AssembliesUnreadable}, types {c.TypesSkipped}, methods {c.IndexMethodsSkipped}, forwarders {c.ForwardersUnreadable}, supertypes {c.SupertypesUnresolved})");
                if (c.BodiesFailed > 0)
                    why.Add($"{c.BodiesFailed} bod(ies) unreadable");
            }
            if (f.PresenceOnly.Count > 0)
                why.Add($"{PackageReachResult.PresenceOnlyText(f.PresenceOnly.Count)}: its reaches are a floor (E1 and E2 floor package)");
            if (f.PresenceUnmeasured.Count > 0)
                why.Add($"{f.PresenceUnmeasured.Count} assembl(ies) in the graph but not scanned by presence (E1 and E2 floor package)");
            if (f.ReachPartial)
                why.Add($"reachability partial: {f.PartialReason} (E1 and E2 floor package)");
            if (f.ProfilesTruncatedClasses.Count > 0)
                why.Add($"profiles cut at 64 for {string.Join(", ", f.ProfilesTruncatedClasses)}: E2 for those classes is a floor");
            if (f.Presence.Any(p => !p.Ok))
                why.Add($"presence scan failed for {f.Presence.Count(p => !p.Ok)} assembl(ies)");
            if (f.Presence.Sum(p => p.MethodsSkipped) is var skipped and > 0)
                why.Add($"presence skipped {skipped} method(s)");
            if (f.NamesCut > 0)
                why.Add($"{f.NamesCut} name(s) cut at {Reachability.MaxNameChars} chars (amendment a5): reported names bounded, counts whole");
            if (why.Count > 0)
                yield return (r.Id, r.Version, f.Folder, string.Join("; ", why));
        }
    }

    /// <summary>Section 12's wording for a crashed, timed-out or incomplete package, by its <c>.nupkg</c>'s lib TFM state.</summary>
    public static string UnmeasuredFloorText(LibTfmState libTfm) =>
        "floor package, presence and reach unmeasured (E1 and E2 floor package): in P-all" + libTfm switch
        {
            LibTfmState.Chosen => " and P-lib",
            LibTfmState.Unknown => " and P-lib, since whether it has a lib TFM is unknown",
            _ => "; not in P-lib, TfmSelection over the .nupkg finds no lib TFM",
        };

    private static string PathText(ExampleRecord example) =>
        string.Join(" ", example.Hops.Select((h, i) => i == 0 ? h.NodeId : $"-{h.Via}-> {h.NodeId}"));

    internal static string Render(Outcome outcome) => outcome switch
    {
        Outcome.Pass => "pass",
        Outcome.Fail => "**FAIL**",
        Outcome.NoData => "no data",
        Outcome.Floor => "Floor (not a pass)",
        _ => "nothing judged",
    };

    private static string SinkName(Capability? capability) => capability?.ToString() ?? "Unseen";

    private static string Cell(Share share) => $"{share.Percent.ToString("F1", CultureInfo.InvariantCulture)}% ({share.Count})";

    private static string Counts(IReadOnlyList<NamedCount> counts) =>
        counts.Count == 0 ? "-" : string.Join("; ", counts.Select(c => $"{c.Name} {c.Count}"));

    private static string Pct(double fraction) => (100 * fraction).ToString("F1", CultureInfo.InvariantCulture) + "%";

    private static string F1(double value) => value.ToString("F1", CultureInfo.InvariantCulture);

    private static string F2(double value) => value.ToString("F2", CultureInfo.InvariantCulture);

    /// <summary>
    /// Package-derived text for a markdown cell. Each character is mapped once, so <c>\</c> is escaped before anything it
    /// could combine with: <c>\</c>, <c>|</c>, <c>&lt;</c>, backtick, <c>[</c>, <c>]</c>, <c>!</c>, <c>:</c> and <c>@</c>
    /// get a backslash, and control, format, line- and paragraph-separator and unassigned characters (bidi overrides,
    /// zero-width characters, soft hyphens, the Tag block, U+0085, U+2028, U+2029) become <c>\u{XXXX}</c>. So a crafted
    /// name can neither split a table row (a <c>\|</c> in the name renders as <c>\\\|</c>), nor open an HTML tag, code
    /// span, link or image, nor become a scheme or e-mail autolink (the <c>:</c> and <c>@</c> those need are escaped),
    /// nor hide text. A bare <c>www.</c> name can still be autolinked by a GFM viewer: a link, never a fetch.
    /// </summary>
    public static string Escape(string value)
    {
        var text = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
            text.Append(rune.Value switch
            {
                '\\' or '|' or '<' or '`' or '[' or ']' or '!' or ':' or '@' => "\\" + (char)rune.Value,
                _ when Hidden(rune) => $"\\u{{{rune.Value:x4}}}",
                _ => rune.ToString(),
            });
        return text.ToString();
    }

    /// <summary>
    /// The identity's commit for a code span, where backslash escapes do not work (review N-d): only <c>[0-9a-f-]</c> is
    /// kept, then <c>-dirty</c> is put back when the commit carried it; <c>unknown</c> when nothing is left.
    /// </summary>
    public static string SafeCommit(string commit)
    {
        var dirty = commit.EndsWith(BuildIdentities.DirtySuffix, StringComparison.Ordinal);
        var core = dirty ? commit[..^BuildIdentities.DirtySuffix.Length] : commit;
        var kept = new string([.. core.Where(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or '-')]).Trim('-');
        return kept.Length == 0 ? BuildIdentities.Unknown : dirty ? kept + BuildIdentities.DirtySuffix : kept;
    }

    /// <summary>
    /// Masks what differs between two runs on one machine (the temp directory, a package's random extraction name),
    /// then any remaining profile path (<see cref="Program.Redact(string)"/>).
    /// </summary>
    public static string Deterministic(string text) =>
        Program.Redact(randomExtraction.Replace(text.Replace(Path.GetTempPath(), "<temp>/", StringComparison.OrdinalIgnoreCase), "pkg-<random>"));

    /// <summary>
    /// A TSV field: metadata is attacker-influenced text, so a tab, CR or LF becomes a space (it would corrupt the record
    /// layout), and every other hidden or line-breaking character - control (incl. U+0085), format (bidi controls,
    /// zero-width characters, the Tag block), U+2028, U+2029, unassigned - becomes <c>\u{XXXX}</c>.
    /// </summary>
    public static string Tab(string value)
    {
        var text = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
            text.Append(rune.Value switch
            {
                '\t' or '\r' or '\n' => " ",
                _ when Hidden(rune) => $"\\u{{{rune.Value:x4}}}",
                _ => rune.ToString(),
            });
        return text.ToString();
    }

    private static bool Hidden(Rune rune) =>
        Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator or UnicodeCategory.OtherNotAssigned;

    internal static void WriteLines(string path, IEnumerable<string> lines) =>
        File.WriteAllText(path, string.Join('\n', lines) + '\n', new UTF8Encoding(false));
    #endregion

    #region Fields
    private static readonly Regex randomExtraction = new(@"pkg-[A-Za-z0-9]{12}", RegexOptions.CultureInvariant);
    #endregion
}
