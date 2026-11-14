namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// The <c>--ssa</c> report (S4.5): <c>ssa-facts-&lt;manifest&gt;-&lt;configuration&gt;-&lt;date&gt;.md</c>, with
/// <c>-folders.tsv</c>, <c>-packages.tsv</c>, <c>-join-examples.tsv</c> and <c>-constant-sinks.tsv</c>. Problems are what
/// the acceptance criteria forbid outright: nothing measured or no facts at all, a folder not additive or whose graph is not
/// the join child's, a repeat or in-process difference, a join miss of a class not <see cref="Explained"/>, a product fact
/// misaligned with its site, an ill-formed string, an observed value past its bound, a default budget spent, a pass that
/// did not finish, a crashed, timed-out or not-run SSA phase of an analysed folder.
/// </summary>
public static class SsaReport
{
    #region Methods
    public static (IReadOnlyList<string> Paths, int Problems) Write(CorpusManifest manifest, string cacheRoot, string results, string outputDirectory,
        DateOnly date, string identity, IReadOnlyList<SsaPackageResult> packages)
    {
        Directory.CreateDirectory(outputDirectory);
        var stem = Path.Combine(outputDirectory, $"ssa-facts-{Path.GetFileNameWithoutExtension(manifest.Path)}-{SsaMeasure.Configuration.ToLowerInvariant()}-{date:yyyy-MM-dd}");
        var folders = packages.SelectMany(p => p.Folders.Select(f => (Package: p.Package, Folder: f))).ToArray();
        var joins = packages.SelectMany(p => (p.Join?.Folders ?? []).Select(f => (Package: p.Package, Folder: f))).ToArray();
        var bounds = SsaFactBounds.Default;
        var options = PackageReachabilityOptions.Default;
        var problems = new List<string>();

        // Problems.
        if (packages.Count == 0 || folders.Length == 0)
            problems.Add("nothing was measured");
        if (!folders.Any(f => f.Folder.SsaOutcome == nameof(SsaFolderOutcome.Analyzed) && f.Folder.SitesTotal > 0))
            problems.Add("no folder has SSA facts for a sink site, so nothing about them is shown");
        foreach (var p in packages.Where(p => p.JoinStatus != "ok" || p.WorkerStatus != "ok"))
            problems.Add($"{Clean(p.Package)}: join {Clean(p.JoinStatus)}, worker {Clean(p.WorkerStatus)}");
        foreach (var (package, f) in joins)
        {
            var unexplained = f.SsaMisses.Concat(f.EdgeMisses).Concat(f.NotJoinedByClass).Where(m => !Explained(m.Key)).ToArray();
            if (unexplained.Length > 0)
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: join misses of unexplained classes ({string.Join(", ", unexplained.Select(m => $"{m.Key} {m.Value}"))})");
            if (f.Misaligned > 0)
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: {f.Misaligned} product fact(s) did not match their raw site");
        }
        foreach (var (package, f) in folders)
        {
            if (f.Differs.Count > 0)
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: not additive ({string.Join(",", f.Differs)})");
            if (f.Child != "equal")
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: the worker's graph is not the join child's ({f.Child}; off {f.OffOutcome})");
            if (f.Repeat == "differs")
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: the repeat's facts differ");
            if (f.InProcess == "differs")
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: the worker's facts differ from the in-process facts");
            if (f.OnOutcome == nameof(FolderOutcome.Analyzed) && f.SsaOutcome != nameof(SsaFolderOutcome.Analyzed))
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: SSA {f.SsaOutcome} ({Clean(f.SsaReason ?? "")})");
            if (f.Truncated || f.MethodBudget || f.TimeBudget || f.TextBudget)
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: a default budget did not hold (truncated {f.Truncated}, method {f.MethodBudget}, time {f.TimeBudget}, text {f.TextBudget})");
            var o = f.Observed;
            if (o.IllFormed > 0 || o.Arguments > bounds.MaxArguments || o.Alternatives > bounds.MaxAlternatives
                || o.ConstantChars > bounds.MaxTextChars + SuffixAllowance || o.Candidates > bounds.MaxCandidates
                || o.SiteNameChars > Reachability.MaxNameChars + SuffixAllowance || f.SitesKept > bounds.MaxSites)
                problems.Add($"{Clean(package)} {Clean(f.Folder)}: a bound was passed or a string is ill-formed ({o})");
        }

        var text = new StringBuilder();
        void Line(string line = "") => text.AppendLine(line);
        string N(long n) => n.ToString("N0", CultureInfo.InvariantCulture);
        string Pct(long part, long whole) => whole == 0 ? "n/a" : (100.0 * part / whole).ToString("0.000", CultureInfo.InvariantCulture) + "%";

        Line($"# SSA facts, S4.5, {Path.GetFileName(manifest.Path)}, {SsaMeasure.Configuration}, {date:yyyy-MM-dd}");
        Line();
        Line("Measured by the benign-corpus harness `--ssa` (docs/agent/tasks/ssa-facts-s4.md, S4.5). Per cached package: the `ssa-join`");
        Line("child (every folder's graph, every method lifted and joined to the graph's call-site edges by node id and IL offset, then");
        Line("the product path's facts in a fresh session), and `PackageReachability.Analyze` through the real `Silvergun.CLI` worker");
        Line("with default options: SSA off, on (`SsaFactBounds.Default`), and on again over a second extraction.");
        Line();
        Line($"- manifest: `{Path.GetFileName(manifest.Path)}`, hash `{manifest.Hash}`, {manifest.Entries.Count} entr(ies)");
        Line($"- cache: `{Program.DisplayPath(cacheRoot)}` (read only; nothing downloaded); results: `{Program.DisplayPath(results)}`");
        Line($"- build: {SsaMeasure.Configuration}, identity `{identity}`");
        Line($"- packages: {packages.Count}; folders: {folders.Length}; join-child folders: {joins.Length}");
        Line($"- **problems: {problems.Count}**");
        foreach (var problem in problems.Take(MaxListed))
            Line($"  - {problem}");
        Line();

        // Additivity.
        Line("## Additivity (AC1)");
        Line();
        Line($"- folders compared: {folders.Length}; identical with SSA off and on (outcome, serialized report, assemblies, load failures, reason, SameAs, size): {folders.Count(f => f.Folder.Differs.Count == 0)}");
        Line($"- graph outcomes with SSA on: {Tally(folders.Select(f => f.Folder.OnOutcome))}");
        Line($"- SSA outcomes: {Tally(folders.Select(f => f.Folder.SsaOutcome))}");
        Line();

        // Join.
        var j = joins.Select(x => x.Folder).ToArray();
        long Sum(Func<SsaJoinFolder, long> pick) => j.Sum(pick);
        Line("## The per-site join (AC4), every method lifted");
        Line();
        Line("| Measure | Count | Rate |");
        Line("|---|---:|---:|");
        Line($"| Method definitions with a body | {N(Sum(f => f.Methods))} | |");
        Line($"| Lifted | {N(Sum(f => f.Lifted))} | {Pct(Sum(f => f.Lifted), Sum(f => f.Methods))} |");
        Line($"| Lifted, node id an own graph node (node-id join) | {N(Sum(f => f.LiftedInGraph))} | {Pct(Sum(f => f.LiftedInGraph), Sum(f => f.Lifted))} |");
        Line($"| Unknown | {N(Sum(f => f.Unknown))} | |");
        Line($"| Unknown, node id an own graph node | {N(Sum(f => f.UnknownInGraph))} | {Pct(Sum(f => f.UnknownInGraph), Sum(f => f.Unknown))} |");
        Line($"| Own graph nodes with a body | {N(Sum(f => f.OwnBodies))} | |");
        Line($"| ... with an SSA outcome under their node id | {N(Sum(f => f.OwnBodiesInSsa))} | {Pct(Sum(f => f.OwnBodiesInSsa), Sum(f => f.OwnBodies))} |");
        Line($"| SSA call sites (call, newobj, ldftn, ldvirtftn) of lifted methods in the graph | {N(Sum(f => f.SsaSites))} | |");
        Line($"| ... joined to an edge of the same kind group and callee key | {N(Sum(f => f.SsaSitesJoined))} | {Pct(Sum(f => f.SsaSitesJoined), Sum(f => f.SsaSites))} |");
        Line($"| ... and of the same exact kind (call vs callvirt) | {N(Sum(f => f.SsaSitesKindExact))} | {Pct(Sum(f => f.SsaSitesKindExact), Sum(f => f.SsaSitesJoined))} |");
        var allEdgeSites = Sum(f => f.EdgeSites) + Sum(f => f.EdgeSitesOfUnknownNodes) + Sum(f => f.EdgeSitesOfNodesNotInSsa);
        Line($"| Edge sites (node, offset, kind group) of own nodes | {N(allEdgeSites)} | |");
        Line($"| ... of nodes with a lifted definition (checked) | {N(Sum(f => f.EdgeSites))} | {Pct(Sum(f => f.EdgeSites), allEdgeSites)} |");
        Line($"| ... ... joined to an SSA site | {N(Sum(f => f.EdgeSitesJoined))} | {Pct(Sum(f => f.EdgeSitesJoined), Sum(f => f.EdgeSites))} |");
        Line($"| ... ... with more than one callee (Ambiguous) | {N(Sum(f => f.EdgeSitesAmbiguous))} | |");
        Line($"| ... of nodes with only Unknown definitions (not checked) | {N(Sum(f => f.EdgeSitesOfUnknownNodes))} | {Pct(Sum(f => f.EdgeSitesOfUnknownNodes), allEdgeSites)} |");
        Line($"| ... of nodes with no SSA outcome (a miss class) | {N(Sum(f => f.EdgeSitesOfNodesNotInSsa))} | |");
        Line($"| Graph-truncated folders | {j.Count(f => f.GraphTruncated)} | |");
        Line($"| Folders where SSA lost an assembly | {j.Count(f => f.AssembliesLost > 0)} | |");
        Line();
        Line("Misses by class (examples in the `-join-examples.tsv`):");
        Line();
        Line("| Class | Count | Folders | Explained |");
        Line("|---|---:|---:|---|");
        foreach (var (key, count, where) in Classes(j.Select(f => f.SsaMisses).Concat(j.Select(f => f.EdgeMisses)).Concat(j.Select(f => f.NotJoinedByClass))))
            Line($"| `{Clean(key)}` | {N(count)} | {where} | {(Explained(key) ? "yes" : "**no**")} |");
        Line($"- folders whose graph is not the join child's: {folders.Count(f => f.Folder.Child != "equal")}; product facts misaligned with their raw sites: {Sum(f => f.Misaligned)}");
        Line();

        // Coverage.
        var f2 = folders.Select(x => x.Folder).ToArray();
        var status = Merge(f2.Select(f => f.ByStatus));
        var analyzed = status.GetValueOrDefault(nameof(SsaSiteStatus.Analyzed));
        Line("## Sink coverage (worker, SSA on)");
        Line();
        Line($"- sink sites: {N(f2.Sum(f => (long)f.SitesTotal))}; kept: {N(f2.Sum(f => (long)f.SitesKept))}; truncated folders: {f2.Count(f => f.Truncated)}");
        Line($"- by status: {string.Join(", ", status.OrderBy(s => s.Key, StringComparer.Ordinal).Select(s => $"{s.Key} {N(s.Value)}"))}");
        Line($"- Analyzed with at least one Constant or OneOf argument: {N(f2.Sum(f => (long)f.AnalyzedWithConstantArgument))} ({Pct(f2.Sum(f => (long)f.AnalyzedWithConstantArgument), analyzed)} of Analyzed)");
        Line($"- MethodUnknown by failure kind (methods lifted for sinks): {Tally(f2.SelectMany(f => f.UnknownKinds.SelectMany(u => Enumerable.Repeat(u.Key, u.Value))))}");
        Line($"- NotJoined by reason: {string.Join("; ", Merge(f2.Select(f => f.NotJoinedReasons)).OrderByDescending(r => r.Value).Select(r => $"{Clean(r.Key)}: {N(r.Value)}"))}");
        Line();
        var constants = folders.SelectMany(x => x.Folder.ConstantSinks.Select(c => (x.Package, c.Key, c.Value)))
            .GroupBy(c => c.Key, StringComparer.Ordinal)
            .Select(g => (Key: g.Key, Sites: g.Sum(c => c.Value), Packages: g.Select(c => c.Package).Distinct().Count()))
            .OrderByDescending(c => c.Sites).ThenBy(c => c.Key, StringComparer.Ordinal).ToArray();
        Line($"Top constant-bearing sinks (Analyzed sites with a Constant or OneOf argument; counts only; all {constants.Length} in the `-constant-sinks.tsv`):");
        Line();
        Line("| Capability | Callee | Sites | Packages |");
        Line("|---|---|---:|---:|");
        foreach (var c in constants.Take(TopSinks))
        {
            var parts = c.Key.Split('\t');
            Line($"| {Clean(parts[0])} | `{Clean(parts[^1])}` | {N(c.Sites)} | {c.Packages} |");
        }
        Line();

        // Reflection.
        Line("## Reflection targets");
        Line();
        var reflection = f2.Sum(f => (long)f.ReflectionSites);
        Line($"- Analyzed reflection sites with a target: {N(reflection)}");
        Line($"- type resolved (Constant or OneOf): {N(f2.Sum(f => (long)f.TypeResolved))} ({Pct(f2.Sum(f => (long)f.TypeResolved), reflection)})");
        Line($"- member resolved: {N(f2.Sum(f => (long)f.MemberResolved))} ({Pct(f2.Sum(f => (long)f.MemberResolved), reflection)})");
        Line($"- with own ByName candidates: {N(f2.Sum(f => (long)f.WithCandidates))} ({Pct(f2.Sum(f => (long)f.WithCandidates), reflection)}); with a candidates gap: {N(f2.Sum(f => (long)f.CandidatesGap))}");
        Line();

        // Cost.
        Line("## Cost and the defaults (AC5)");
        Line();
        Line("| Wall time, sum over packages | ms |");
        Line("|---|---:|");
        Line($"| worker pass, SSA off (first) | {N(packages.Sum(p => p.OffMs))} |");
        Line($"| worker pass, SSA off (last) | {N(packages.Sum(p => p.Off2Ms))} |");
        Line($"| worker pass, SSA on | {N(packages.Sum(p => p.OnMs))} |");
        Line($"| worker pass, SSA on, repeat | {N(packages.Sum(p => p.RepeatMs))} |");
        Line($"| worker pass, the faster off against the faster on, per package | {N(packages.Sum(p => Math.Min(p.OffMs, p.Off2Ms)))} against {N(packages.Sum(p => Math.Min(p.OnMs, p.RepeatMs)))} |");
        Line($"| join child, whole process | {N(packages.Sum(p => p.JoinWallMs))} |");
        Line($"| join child, graphs | {N(Sum(f => f.GraphMs))} |");
        Line($"| join child, every method lifted and joined | {N(Sum(f => f.LiftAllMs))} |");
        Line($"| join child, product facts (sink methods only; SSA's own cost) | {N(Sum(f => f.FactsMs))} |");
        Line();
        if (packages.Count > 0 && folders.Length > 0)
        {
            var slowest = packages.OrderByDescending(p => Math.Max(p.OnMs, p.RepeatMs)).Take(5).ToArray();
            Line($"- slowest packages with SSA on (budget {options.PackageBudget.TotalSeconds:0} s): {string.Join("; ", slowest.Select(p => $"{Clean(p.Package)} {N(Math.Max(p.OnMs, p.RepeatMs))} ms (off {N(Math.Max(p.OffMs, p.Off2Ms))})"))}");
            var slowFacts = joins.OrderByDescending(x => x.Folder.FactsMs).Take(5).ToArray();
            Line($"- slowest folders' product facts in the child (worker backstop {bounds.FolderTime.TotalSeconds:0} s, folder timeout {options.FolderTimeout.TotalSeconds:0} s): {string.Join("; ", slowFacts.Select(x => $"{Clean(x.Package)} {Clean(x.Folder.Folder)} {N(x.Folder.FactsMs)} ms"))}");
            var peak = packages.OrderByDescending(p => p.OnPeakWorkingSet).First();
            Line($"- peak worker working set with SSA on: {N(peak.OnPeakWorkingSet / (1024 * 1024))} MB ({Clean(peak.Package)}); peak private {N(packages.Max(p => p.OnPeakPrivate) / (1024 * 1024))} MB; with SSA off {N(packages.Max(p => p.OffPeakWorkingSet) / (1024 * 1024))} MB (limit {N(options.WorkerMemoryBytes / (1024 * 1024))} MB)");
            var joinPeak = packages.OrderByDescending(p => p.JoinPeakWorkingSet).First();
            Line($"- peak join child working set (graph data held while every method lifts): {N(joinPeak.JoinPeakWorkingSet / (1024 * 1024))} MB ({Clean(joinPeak.Package)})");
            var biggest = folders.OrderByDescending(x => x.Folder.RecordChars).First();
            Line($"- largest folder facts: {N(biggest.Folder.RecordChars)} chars of JSON ({Clean(biggest.Package)} {Clean(biggest.Folder.Folder)}); per package at most {N(packages.Max(p => p.Folders.Sum(f => f.RecordChars)))} (SSA record budget {N(options.MaxReportBytes)} bytes, record line limit {N(GraphWorkerProtocol.MaxRecordLineBytes)} bytes)");
            Line($"- most sites in a folder: {N(f2.Max(f => f.SitesTotal))} (MaxSites {N(bounds.MaxSites)}); most methods lifted for sinks: {N(f2.Max(f => f.MethodsLifted))} (MaxLiftedMethods {N(bounds.MaxLiftedMethods)})");
        }
        Line($"- folders cut: truncated {f2.Count(f => f.Truncated)}, method budget {f2.Count(f => f.MethodBudget)}, time budget {f2.Count(f => f.TimeBudget)}, text budget {f2.Count(f => f.TextBudget)}");
        var observed = f2.Aggregate(SsaObservedBounds.None, (a, f) => a.Max(f.Observed));
        Line($"- largest observed: arguments {observed.Arguments} (MaxArguments {bounds.MaxArguments}), OneOf {observed.Alternatives} (MaxAlternatives {bounds.MaxAlternatives}), constant text {observed.ConstantChars} chars (MaxTextChars {bounds.MaxTextChars}, plus the cut suffix), candidates {observed.Candidates} (MaxCandidates {bounds.MaxCandidates}), site name {observed.SiteNameChars} chars (MaxNameChars {Reachability.MaxNameChars}, plus the cut suffix); ill-formed strings {observed.IllFormed}");
        Line();

        // Determinism.
        Line("## Determinism (AC6)");
        Line();
        Line($"- SSA on, twice, over separate extractions: {Tally(f2.Select(f => f.Repeat))}");
        Line($"- worker facts against the join child's in-process facts: {Tally(f2.Select(f => f.InProcess))}");
        Line();

        var md = stem + ".md";
        PackageReachResult.WriteAtomically(md, text.ToString());
        PackageReachResult.WriteAtomically(stem + "-folders.tsv", Tsv(
            ["package", "folder", "off", "on", "differs", "child", "same_as", "ssa", "repeat", "in_process", "sites","kept", "analyzed", "method_unknown", "not_joined", "not_run", "with_constant", "reflection", "record_chars", "ssa_reason"],
            folders.Select(x => new[]
            {
                x.Package, x.Folder.Folder, x.Folder.OffOutcome, x.Folder.OnOutcome, string.Join(",", x.Folder.Differs), x.Folder.Child, x.Folder.SameAs ?? "", x.Folder.SsaOutcome,
                x.Folder.Repeat, x.Folder.InProcess, I(x.Folder.SitesTotal), I(x.Folder.SitesKept),
                I(x.Folder.ByStatus.GetValueOrDefault("Analyzed")), I(x.Folder.ByStatus.GetValueOrDefault("MethodUnknown")),
                I(x.Folder.ByStatus.GetValueOrDefault("NotJoined")), I(x.Folder.ByStatus.GetValueOrDefault("NotRun")),
                I(x.Folder.AnalyzedWithConstantArgument), I(x.Folder.ReflectionSites), I(x.Folder.RecordChars), x.Folder.SsaReason ?? "",
            })));
        PackageReachResult.WriteAtomically(stem + "-packages.tsv", Tsv(
            ["package", "join", "worker", "join_ms", "join_peak_ws", "off_ms", "on_ms", "repeat_ms", "off2_ms", "off_peak_ws", "on_peak_ws", "on_peak_private", "folders"],
            packages.Select(p => new[]
            {
                p.Package, p.JoinStatus, p.WorkerStatus, I(p.JoinWallMs), I(p.JoinPeakWorkingSet), I(p.OffMs), I(p.OnMs), I(p.RepeatMs), I(p.Off2Ms),
                I(p.OffPeakWorkingSet), I(p.OnPeakWorkingSet),
                I(p.OnPeakPrivate), I(p.Folders.Count),
            })));
        PackageReachResult.WriteAtomically(stem + "-join-examples.tsv", Tsv(
            ["package", "folder", "class", "example"],
            joins.SelectMany(x => x.Folder.Examples.Select(e => e.Split('\t', 2)).Select(e => new[] { x.Package, x.Folder.Folder, e[0], e.Length > 1 ? e[1] : "" }))));
        PackageReachResult.WriteAtomically(stem + "-constant-sinks.tsv", Tsv(
            ["capability", "callee", "sites", "packages"],
            constants.Select(c => c.Key.Split('\t')).Zip(constants, (k, c) => new[] { k[0], k[^1], I(c.Sites), I(c.Packages) })));
        return ([md, stem + "-folders.tsv", stem + "-packages.tsv", stem + "-join-examples.tsv", stem + "-constant-sinks.tsv"], problems.Count);
    }

    /// <summary>
    /// Whether a join miss class is explained (docs/agent/tasks/ssa-facts-s4.md, S4.1 and S4.5): an
    /// <c>InitializeArray</c> call is Cilica's intrinsic, not a call (S3); an MD-array accessor is CCI's <c>Array_*</c>
    /// pseudo-operation with no edge (S4.1); a node merged from several definitions, one of which did not lift, has edges
    /// from that one with no SSA site; a truncated graph lacks what it did not reach; the Model drops the module type, so
    /// <c>&lt;Module&gt;</c> methods are not graph nodes (module-type). Every other class is a problem, pointer-as-byref
    /// included: ModelNames rendered <c>[Out]</c> pointer parameters as by-refs until S4.5 fixed it.
    /// </summary>
    public static bool Explained(string @class) =>
        (@class.StartsWith("truncated:", StringComparison.Ordinal) && !@class.EndsWith("sink:unexplained", StringComparison.Ordinal)) || explained.Contains(@class);

    private static IEnumerable<(string Key, long Count, int Folders)> Classes(IEnumerable<Dictionary<string, int>> perFolder) =>
        perFolder.SelectMany(d => d)
            .GroupBy(p => p.Key, StringComparer.Ordinal)
            .Select(g => (g.Key, g.Sum(p => (long)p.Value), g.Count()))
            .OrderBy(c => c.Item1, StringComparer.Ordinal);

    private static Dictionary<string, long> Merge(IEnumerable<Dictionary<string, int>> counts) =>
        counts.SelectMany(d => d).GroupBy(p => p.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Sum(p => (long)p.Value), StringComparer.Ordinal);

    private static string Tally(IEnumerable<string> values) =>
        string.Join(", ", values.GroupBy(v => v, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => $"{Clean(g.Key)} {g.Count().ToString("N0", CultureInfo.InvariantCulture)}"));

    private static string Tsv(string[] header, IEnumerable<string[]> rows) =>
        string.Join("\n", new[] { string.Join('\t', header) }.Concat(rows.Select(r => string.Join('\t', r.Select(Clean))))) + "\n";

    private static string I(long value) => value.ToString(CultureInfo.InvariantCulture);

    // One printable line from package-controlled text: control, bidi and zero-width characters become '?', and it is bounded;
    // backticks and pipes too, so Markdown cells hold.
    private static string Clean(string text)
    {
        var chars = text.Select(c => char.IsControl(c) || char.IsSurrogate(c) || c is '`' or '|' or (char)0x00AD or (char)0xFEFF
            or >= (char)0x200B and <= (char)0x200F or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069 ? '?' : c).ToArray();
        return chars.Length <= MaxCellChars ? new string(chars) : new string(chars, 0, MaxCellChars) + "...";
    }
    #endregion

    #region Fields
    private const int MaxListed = 100;
    private const int MaxCellChars = 400;
    private const int TopSinks = 25;

    private static readonly HashSet<string> explained =
        [
            "edge:initialize-array-intrinsic", "site:no-edge(md-array-accessor)", "edge:node-partly-lifted",
            "method:lifted-node-not-in-graph(module-type)", "method:unknown-node-not-in-graph(module-type)",
        ];

    // The cut suffix a bounded text may end with, "…[+N chars, sha256:<8 hex>]", at most this long.
    private const int SuffixAllowance = 48;
    #endregion
}
