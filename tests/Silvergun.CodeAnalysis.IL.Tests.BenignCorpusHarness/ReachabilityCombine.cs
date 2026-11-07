namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

/// <summary>
/// One manifest's side of <c>--combine</c>: the cached results of its run (<see cref="Results"/>, manifest order), the
/// entries with no result of this schema there (<see cref="NotCached"/>), and how its repeat run differs, per package
/// (<see cref="RepeatDifferences"/>; empty when the two runs are identical).
/// </summary>
public sealed record CombineSide(string Name, CorpusManifest Manifest, IReadOnlyList<PackageReachResult> Results, IReadOnlyList<ManifestEntry> NotCached,
    IReadOnlyList<string> RepeatDifferences)
{
    #region Properties
    public bool RepeatIdentical => RepeatDifferences.Count == 0;
    #endregion
}

/// <summary>
/// What <c>--combine</c> found: both sides, the C100 oracle comparison recomputed from C100's cached results, the ids
/// both manifests hold, the union P-all population, why no verdict may be read off it (null when every gate holds), and
/// the hash C-build's manifest was required to have.
/// </summary>
public sealed record CombineResult(
    CombineSide C100, CombineSide Cbuild, OracleComparison Oracle, IReadOnlyList<string> Overlap, PopulationView Union, string? NotComparable,
    string PinnedCbuildHash)
{
    #region Properties
    /// <summary>Whether C-build's manifest is the pinned one.</summary>
    public bool CbuildPinned => string.Equals(Cbuild.Manifest.Hash, PinnedCbuildHash, StringComparison.Ordinal);
    #endregion

    #region Methods
    /// <summary>The HostContract and LoadTime verdicts at <paramref name="label"/> over <see cref="Union"/>.</summary>
    public IReadOnlyList<ClassVerdict> Verdicts(ReachLabel label) => ReachabilityAggregation.PallVerdicts(Union, label);
    #endregion
}

/// <summary>
/// The <c>--combine</c> mode (R2b S4, "the combine step"): offline, it reads the cached results of the C100 run and its
/// repeat, and of the C-build run and its repeat, and never constructs a <see cref="PackageCache"/> or runs a child. It
/// judges HostContract and LoadTime, at ChaOnly and Direct, on P-all over C100 and C-build as one population with one
/// denominator, every floor package of both runs counted by the floor rule. Gates, each giving no verdict when it fails:
/// <list type="number">
/// <item><description>C100's oracle comparison, recomputed from its cached results, is a full MATCH, with 0 not-cached.</description></item>
/// <item><description>C-build has 0 not-cached: every entry accounted for (crashed, timeout and incomplete are unmeasured
/// P-all floors, R2b S0).</description></item>
/// <item><description>Each run and its repeat hold identical results per package (<see cref="Comparable"/>).</description></item>
/// <item><description>No id is in both manifests.</description></item>
/// <item><description>The C-build manifest is the pinned one: its hash is <see cref="PinnedCbuildManifestHash"/> (S0-S3 review,
/// Nit 5b). The CLI passes that constant and has no flag to change it; a re-pin is a source change.</description></item>
/// </list>
/// Results of another build than the harness's refuse the run (<see cref="MixedBuildException"/>), as in <c>--reachability</c>.
/// </summary>
public static class ReachabilityCombine
{
    #region Methods
    /// <summary>
    /// Reads one side: each entry's result in <paramref name="resultsDir"/> (<see cref="CachedResults"/>: missing, or of
    /// another schema, is not cached), and its repeat in <paramref name="repeatDir"/>, compared by <see cref="Comparable"/>.
    /// </summary>
    public static CombineSide ReadSide(string name, CorpusManifest manifest, string resultsDir, string repeatDir)
    {
        var results = new List<PackageReachResult>();
        var notCached = new List<ManifestEntry>();
        var differences = new List<string>();
        foreach (var entry in manifest.Entries)
        {
            var first = CachedResults.Load(resultsDir, entry);
            var repeat = CachedResults.Load(repeatDir, entry);
            if (first is null)
                notCached.Add(entry);
            else
                results.Add(first);

            var difference = (first, repeat) switch
            {
                (null, null) => null,
                (_, null) => "no result in the repeat run",
                (null, _) => "no result in the first run",
                _ => string.Equals(Comparable(first), Comparable(repeat), StringComparison.Ordinal) ? null : "the two runs' results differ",
            };
            if (difference is not null)
                differences.Add($"{entry.Id} {entry.Version}: {difference}");
        }
        return new CombineSide(name, manifest, results, notCached, differences);
    }

    /// <summary>
    /// A result as two runs of one build must reproduce it: its JSON without <see cref="PackageReachResult.Cost"/> (times and
    /// working sets differ run to run), with the temp directory and random extraction names masked, as the report masks
    /// them (<see cref="ReachabilityCorpusReport.Deterministic"/>). So the per-package files are compared on everything the
    /// report is rendered from.
    /// </summary>
    public static string Comparable(PackageReachResult result)
    {
        var json = (result with { Cost = PackageCost.None }).ToJson();
        var temp = JsonSerializer.Serialize(Path.GetTempPath(), PackageReachResult.JsonOptions)[1..^1];
        return randomExtraction.Replace(json.Replace(temp, "<temp>/", StringComparison.OrdinalIgnoreCase), "pkg-<random>");
    }

    /// <summary>The ids both manifests hold, NuGet ids compared case-insensitively, each with both versions.</summary>
    public static IReadOnlyList<string> Overlap(CorpusManifest c100, CorpusManifest cbuild) =>
        [.. c100.Entries.Join(cbuild.Entries, e => e.Id, e => e.Id, (a, b) => $"{a.Id} (C100 {a.Version}, C-build {b.Version})", StringComparer.OrdinalIgnoreCase)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];

    /// <summary>
    /// The combine step over two read sides: refuses results of another build than <paramref name="identity"/>, applies the
    /// five gates, and forms the union P-all population (C100's results, then C-build's). <paramref name="pinnedCbuildHash"/>
    /// is the hash C-build's manifest must have: <see cref="PinnedCbuildManifestHash"/> from the CLI.
    /// </summary>
    public static CombineResult Combine(CombineSide c100, CombineSide cbuild, PresenceOracle oracle, BuildIdentity identity, string pinnedCbuildHash)
    {
        ReachabilityAggregation.EnsureOneBuild(c100.Results.Concat(cbuild.Results), identity);
        var comparison = ReachabilityAggregation.CompareOracle(oracle, ReachabilityAggregation.View(c100.Results, Population.Plib), c100.Manifest.Hash);
        var overlap = Overlap(c100.Manifest, cbuild.Manifest);

        var why = new List<string>();
        if (!string.Equals(cbuild.Manifest.Hash, pinnedCbuildHash, StringComparison.Ordinal))
            why.Add("C-build manifest is not the pinned one");   // CombineResult.CbuildPinned
        if (!comparison.Full)
            why.Add("C100 oracle not applicable: another manifest");
        else if (!comparison.Match)
            why.Add("C100 oracle MISMATCH");
        if (c100.NotCached.Count > 0)
            why.Add($"C100 not-cached {c100.NotCached.Count}");
        if (cbuild.NotCached.Count > 0)
            why.Add($"C-build not-cached {cbuild.NotCached.Count}");
        foreach (var side in new[] { c100, cbuild }.Where(s => !s.RepeatIdentical))
            why.Add($"{side.Name} run and repeat differ ({side.RepeatDifferences.Count} package(s))");
        if (overlap.Count > 0)
            why.Add($"id overlap between the manifests ({overlap.Count})");

        return new CombineResult(c100, cbuild, comparison, overlap,
            ReachabilityAggregation.View(c100.Results.Concat(cbuild.Results), Population.Pall),
            why.Count == 0 ? null : $"not comparable ({string.Join("; ", why)})", pinnedCbuildHash);
    }

    public static string MarkdownName(DateOnly date) => $"reachability-combine-{date:yyyy-MM-dd}.md";

    /// <summary>Writes the combine report into <paramref name="outputDirectory"/>; returns its path.</summary>
    public static string Write(string outputDirectory, DateOnly date, string oracleName, BuildIdentity identity, CombineResult result)
    {
        Directory.CreateDirectory(outputDirectory);
        var md = Path.Combine(outputDirectory, MarkdownName(date));
        ReachabilityCorpusReport.WriteLines(md, Markdown(date, oracleName, identity, result));
        return md;
    }

    /// <summary>The combine report: deterministic (no clock, no directory paths), ordinal, invariant.</summary>
    public static IReadOnlyList<string> Markdown(DateOnly date, string oracleName, BuildIdentity identity, CombineResult result)
    {
        var (c100, cbuild, union, notComparable) = (result.C100, result.Cbuild, result.Union, result.NotComparable);
        string Judge(RootClass _, string text) => notComparable ?? text;
        string Escape(string text) => ReachabilityCorpusReport.Escape(text);
        int Status(CombineSide side, string status) => side.Results.Count(r => r.Status == status);
        string Statuses(CombineSide side) =>
            string.Join(" / ", new[] { PackageReachResult.Scanned, PackageReachResult.GraphFailed, PackageReachResult.NoAssemblies, PackageReachResult.Crashed,
                PackageReachResult.Timeout, PackageReachResult.Incomplete }.Select(s => Status(side, s).ToString(CultureInfo.InvariantCulture)))
            + $" / {side.NotCached.Count}";
        // By reference: the run a unit came from, even were an id in both manifests.
        var fromC100 = new HashSet<PackageReachResult>(c100.Results, ReferenceEqualityComparer.Instance);

        var lines = new List<string>
        {
            $"# Reachability R2b - the combine step ({date:yyyy-MM-dd})",
            string.Empty,
            "**A measurement, not a feature** (`docs/agent/tasks/reachability-r2b.md`, S4). HostContract and LoadTime, at ChaOnly",
            "and Direct, judged on P-all only over C100 and C-build as one population with one denominator, by the rules R2",
            "pre-registered (E1, E2, the judged gate, the symmetric floor rule). The runtime classes are judged by `--reachability`",
            "on C100 alone. Read offline from the cached results of both runs and their repeats: nothing was measured or fetched.",
            string.Empty,
            "## 1. Parameters",
            string.Empty,
            "| Parameter | C100 | C-build |",
            "| --- | --- | --- |",
            $"| Manifest | `{Escape(Path.GetFileName(c100.Manifest.Path))}` | `{Escape(Path.GetFileName(cbuild.Manifest.Path))}` |",
            $"| Manifest hash | `{c100.Manifest.Hash}` | `{cbuild.Manifest.Hash}` |",
            $"| Manifest entries | {c100.Manifest.Entries.Count} | {cbuild.Manifest.Entries.Count} |",
            $"| Names cut at {Reachability.MaxNameChars} chars (amendment a5; distinct per folder, summed over every folder) | " +
            $"{ReachabilityCorpusReport.NamesCutText(ReachabilityCorpusReport.NamesCutTotal(c100.Results))} | {ReachabilityCorpusReport.NamesCutText(ReachabilityCorpusReport.NamesCutTotal(cbuild.Results))} |",
            $"| Status: scanned / graph-failed / no-assemblies / crashed / timeout / incomplete / not-cached | {Statuses(c100)} | {Statuses(cbuild)} |",
            $"| In P-all (the union's denominator, by run) | {union.Units.Count(u => fromC100.Contains(u.Result))} | {union.Units.Count(u => !fromC100.Contains(u.Result))} |",
            string.Empty,
            "| Parameter | Value |",
            "| --- | --- |",
            $"| Harness build | `{ReachabilityCorpusReport.SafeCommit(identity.Commit)}`" +
            $"{(identity.Commit.EndsWith(BuildIdentities.DirtySuffix, StringComparison.Ordinal) ? " **(uncommitted changes: not a corpus-run build)**" : string.Empty)} |",
            $"| Harness assemblies sha256 | `{identity.AssembliesSha256}` |",
            $"| Date (`--date`) | {date:yyyy-MM-dd} |",
            $"| Presence oracle (`--oracle`, C100's side) | `{Escape(oracleName)}` |",
            $"| **P-all denominator** (C100 and C-build, one population) | **{union.Denominator}** |",
            $"| Floor packages in P-all (both runs) | {union.Units.Count(u => u.Floor)}, of which unmeasured {union.Unmeasured} |",
            $"| Classes judged | {string.Join(", ", ReachabilityAggregation.CombineClasses)} |",
            $"| Labels | {string.Join(", ", ReachabilityAggregation.Labels)} |",
            string.Empty,
            "## 2. Gates",
            string.Empty,
            "| Gate | Result |",
            "| --- | --- |",
            $"| C-build manifest is the pinned `{ReachabilityCorpusReport.Escape(Program.CbuildManifestFileName)}` (hash `{result.PinnedCbuildHash}`) | " +
            $"{(result.CbuildPinned ? "yes" : $"**no** (hash `{cbuild.Manifest.Hash}`)")} |",
            $"| C100 oracle, recomputed from the cached results (a full MATCH) | {(result.Oracle.Full ? result.Oracle.Match ? "MATCH" : "MISMATCH" : "not applicable: another manifest")} " +
            $"({result.Oracle.PackagesCompared} packages compared) |",
            $"| C100 not-cached (0) | {c100.NotCached.Count} |",
            $"| C-build not-cached (0; crashed, timeout and incomplete are unmeasured P-all floors) | {cbuild.NotCached.Count} |",
            $"| C100 run and repeat identical per package (results without cost, temp paths masked) | {(c100.RepeatIdentical ? "yes" : $"**no** ({c100.RepeatDifferences.Count})")} |",
            $"| C-build run and repeat identical per package | {(cbuild.RepeatIdentical ? "yes" : $"**no** ({cbuild.RepeatDifferences.Count})")} |",
            $"| Ids in both manifests (none) | {(result.Overlap.Count == 0 ? "none" : $"**{result.Overlap.Count}**")} |",
            string.Empty,
        };
        foreach (var (title, items) in new (string, IEnumerable<string>)[]
        {
            ("Oracle differences", result.Oracle.Differences),
            ("C100 not-cached", c100.NotCached.Select(e => $"{e.Id} {e.Version}")),
            ("C-build not-cached", cbuild.NotCached.Select(e => $"{e.Id} {e.Version}")),
            ("C100 repeat differences", c100.RepeatDifferences),
            ("C-build repeat differences", cbuild.RepeatDifferences),
            ("Ids in both manifests", result.Overlap),
        })
            if (items.ToArray() is { Length: > 0 } listed)
                lines.AddRange([$"{title}:", string.Empty, .. listed.Select(i => $"- {Escape(i)}"), string.Empty]);
        lines.AddRange([
            notComparable is null
                ? "**Every gate holds:** the verdicts below stand."
                : $"**No verdict: {notComparable}.** Every E1 and E2 cell and every verdict below reads so; the shares are shown, but nothing may be concluded from them.",
            string.Empty,
            "## 3. E1 - P-all over C100 and C-build",
            string.Empty,
            "As in `--reachability`, section 3: a cell fails only in its best case and passes only in its worst case, every floor",
            "package of either run (Partial reachability, an assembly only one side read, a partial presence scan, or a crashed,",
            "timed-out or incomplete child) counted against the expectation; otherwise it is Floor, not a pass.",
            string.Empty,
            $"### {union.Name} (denominator {union.Denominator}; floor packages {union.Units.Count(u => u.Floor)})",
            string.Empty,
        ]);
        foreach (var label in ReachabilityAggregation.Labels)
            ReachabilityCorpusReport.E1Table(lines, union, label, ReachabilityAggregation.CombineClasses, Judge);
        lines.AddRange(["## 4. E2 - P-all over C100 and C-build", string.Empty]);
        ReachabilityCorpusReport.E2Table(lines, union, ReachabilityAggregation.CombineClasses, Judge);
        lines.AddRange([
            "## 5. Verdicts (P-all only: a fail of E1 or E2 = does not discriminate; any Floor = undecided)",
            string.Empty,
            "| Class | Label | P-all E1 | P-all E2 | Verdict |",
            "| --- | --- | --- | --- | --- |",
            .. ReachabilityAggregation.CombineClasses.SelectMany(k => ReachabilityAggregation.Labels.Select(l => result.Verdicts(l).Single(v => v.Class == k)))
                .Select(v => $"| {v.Class} | {v.Label} | {notComparable ?? ReachabilityCorpusReport.Render(v.PallE1)} | {notComparable ?? ReachabilityCorpusReport.Render(v.PallE2)} | {notComparable ?? v.Verdict} |"),
            string.Empty,
            "## 6. Floor packages (both runs)",
            string.Empty,
        ]);
        var floors = union.Units.Where(u => u.Floor || ReachabilityAggregation.CombineClasses.Any(u.ProfileFloor)).ToArray();
        if (floors.Length == 0)
            lines.Add("*None.*");
        else
            lines.AddRange([
                "| Run | Package | Version | Why |",
                "| --- | --- | --- | --- |",
                .. floors.Select(u => $"| {(fromC100.Contains(u.Result) ? c100.Name : cbuild.Name)} | {u.Id} | {u.Result.Version} | {Escape(ReachabilityCorpusReport.Deterministic(FloorWhy(u)))} |"),
            ]);
        lines.Add(string.Empty);
        return lines;
    }

    // Why a union unit is a floor package, from the data the floor rule reads.
    private static string FloorWhy(PackageUnit unit)
    {
        if (unit.Result.UnmeasuredFloor)
            return $"{unit.Result.Status}: {unit.Result.Detail ?? "-"}; presence and reach unmeasured";
        var why = unit.Folders.SelectMany(f => new[]
            {
                f.ReachPartial ? $"{f.Folder}: reachability partial ({f.PartialReason})" : null,
                f.PresenceOnly.Count > 0 ? $"{f.Folder}: {PackageReachResult.PresenceOnlyText(f.PresenceOnly.Count)}" : null,
                f.PresenceUnmeasured.Count > 0 ? $"{f.Folder}: {f.PresenceUnmeasured.Count} assembl(ies) in the graph but not scanned by presence" : null,
                f.PresencePartial.Count > 0 ? $"{f.Folder}: {f.PresencePartial.Count} assembl(ies) scanned by presence only partly" : null,
            })
            .OfType<string>()
            .Concat(ReachabilityAggregation.CombineClasses.Where(k => unit.TruncatedClasses.Contains(k)).Select(k => $"{k} profiles cut at 64 (E2 floor)"))
            .ToArray();
        return string.Join("; ", why);
    }
    #endregion

    #region Fields
    public const string C100Name = "C100";

    public const string CbuildName = "C-build";

    /// <summary>
    /// The <see cref="CorpusManifest.Hash"/> of the checked-in <c>data/corpus/c-build.manifest</c> (R2b S3, as corrected;
    /// see <c>c-build.provenance.md</c> beside it), which <c>--combine</c> requires of its C-build manifest. Pinned by a
    /// test against the file, so changing the manifest without re-pinning here fails the build's tests.
    /// </summary>
    public const string PinnedCbuildManifestHash = "cd9ade3633e1e3eb87e51a887afd08550769a7043e12b8e10ce148e4b74a6af0";

    private static readonly Regex randomExtraction = new(@"pkg-[A-Za-z0-9]{12}", RegexOptions.CultureInvariant);
    #endregion
}
