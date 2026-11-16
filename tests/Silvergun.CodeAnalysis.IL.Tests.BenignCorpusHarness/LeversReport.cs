namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

using static Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness.SsaReport;

/// <summary>
/// One co-reach cell or value signal over a corpus (<c>docs/agent/tasks/recall-levers-1.md</c> §4's inputs, not its
/// verdict): <paramref name="Measured"/> packages with a report; <paramref name="Fired"/> of them where it fired, named in
/// <paramref name="FiredPackages"/>; <paramref name="FloorPackages"/> the packages where it did not fire but could have
/// (a floor, or no report at all), which the rule counts in the worst case; <paramref name="Sites"/> the signal's sites (0 for a cell).
/// </summary>
public sealed record LeversTally(string Name, int Measured, int Fired, long Sites, List<string> FiredPackages, List<string> FloorPackages)
{
    /// <summary>Fired plus floor: the most packages it could have fired in.</summary>
    public int WorstCase => Fired + FloorPackages.Count;
}

/// <summary>
/// The <c>--levers</c> report: <c>levers-&lt;manifest&gt;-&lt;configuration&gt;-&lt;date&gt;.md</c> with <c>-cells.tsv</c>,
/// <c>-signals.tsv</c>, <c>-examples.tsv</c>, <c>-packages.tsv</c> and <c>-constant-sinks.tsv</c> (the format of
/// <c>--ssa</c>'s). Counts and names only; the verdict is the architect's. Package-controlled text is cleaned (control,
/// bidi and zero-width characters, backticks and pipes) and bounded before it is written; cache paths are shown redacted.
/// Problems are packages with no report, the one thing that makes a result unreadable.
/// </summary>
public static class LeversReport
{
    #region Methods
    public static (IReadOnlyList<string> Paths, int Problems) Write(CorpusManifest manifest, string cacheRoot, string results, string outputDirectory,
        DateOnly date, string identity, IReadOnlyList<LeversPackageResult> packages)
    {
        Directory.CreateDirectory(outputDirectory);
        var stem = Path.Combine(outputDirectory, $"levers-{Path.GetFileNameWithoutExtension(manifest.Path)}-{LeversMeasure.Configuration.ToLowerInvariant()}-{date:yyyy-MM-dd}");
        var problems = packages.Where(p => p.Status != "ok").Select(p => $"{Clean(p.Package)}: {Clean(p.Status)}").ToList();
        if (packages.Count == 0)
            problems.Add("nothing was measured");

        var cells = CellTallies(packages);
        var signals = SignalTallies(packages);
        var text = new StringBuilder();
        void Line(string line = "") => text.AppendLine(line);
        string N(long n) => n.ToString("N0", CultureInfo.InvariantCulture);

        Line($"# Recall levers 1, {Path.GetFileName(manifest.Path)}, {LeversMeasure.Configuration}, {date:yyyy-MM-dd}");
        Line();
        Line("Measured by the benign-corpus harness `--levers` (docs/agent/tasks/recall-levers-1.md, L2). Per cached package: one");
        Line("`PackageReachability.Analyze` pass through the real `Silvergun.CLI` worker with SSA on (`SsaFactBounds.Default`), then");
        Line("`ReachabilitySummary.From`. Counts and names only: the verdict by §4's rule is not made here.");
        Line();
        Line($"- manifest: `{Clean(Path.GetFileName(manifest.Path))}`, hash `{manifest.Hash}`, {manifest.Entries.Count} entr(ies)");
        Line($"- cache: `{Program.DisplayPath(cacheRoot)}` (read only; nothing downloaded); results: `{Program.DisplayPath(results)}`");
        Line($"- build: {LeversMeasure.Configuration}, identity `{Clean(identity)}`");
        Line($"- packages: {packages.Count}; with a report: {packages.Count(p => p.Status == "ok")}; folders: {N(packages.Sum(p => (long)p.Folders))}; " +
             $"packages whose summary dropped statements: {packages.Count(p => p.StatementsDropped > 0)}");
        Line($"- **problems: {problems.Count}**");
        foreach (var problem in problems.Take(MaxListed))
            Line($"  - {problem}");
        Line();
        Line("A **floor** package is one where the cell or signal did not fire but could have: a folder was not analysed, a class was");
        Line("Unknown, the profiles were cut, the summary dropped statements, or SSA was incomplete or absent in a folder. A package with no");
        Line("report is a floor for everything. *Worst case* is fired plus floor.");
        Line();

        Line("## Co-reach cells (class x collection + Network x label)");
        Line();
        Line("| Cell | Measured | Fired | Floor | Worst case | Fired in |");
        Line("|---|---:|---:|---:|---:|---|");
        foreach (var c in cells)
            Line($"| {c.Name} | {N(c.Measured)} | {N(c.Fired)} | {N(c.FloorPackages.Count)} | {N(c.WorstCase)} | {Names(c.FiredPackages)} |");
        Line();
        Line("Floor packages per cell are in `-cells.tsv` (`floor` yes, `fired` no).");
        Line();

        Line("## Value signals");
        Line();
        Line("| Signal | Measured | Packages fired | Sites | Floor | Worst case | Fired in |");
        Line("|---|---:|---:|---:|---:|---:|---|");
        foreach (var s in signals)
            Line($"| {s.Name} | {N(s.Measured)} | {N(s.Fired)} | {N(s.Sites)} | {N(s.FloorPackages.Count)} | {N(s.WorstCase)} | {Names(s.FiredPackages)} |");
        Line();

        var examples = packages.SelectMany(p => p.Examples.Select(e => (Package: p.Package, Example: e))).ToArray();
        Line("## Signal sites (the summary's listed sites; all in `-examples.tsv`)");
        Line();
        Line($"{N(examples.Length)} listed site(s) with a signal in {N(examples.Select(e => e.Package).Distinct().Count())} package(s). The sites past the summary's caps are counted above, not listed.");
        Line();
        Line("| Package | Signal | Folder | Callee | Call |");
        Line("|---|---|---|---|---|");
        foreach (var (package, e) in examples.OrderBy(x => x.Example.Signal, StringComparer.Ordinal).ThenBy(x => x.Package, StringComparer.Ordinal).Take(MaxExamples))
            Line($"| {Clean(package)} | {Clean(e.Signal)} | {Clean(e.Folder)} | `{Clean(e.Callee)}` | `{Clean(e.Call)}` |");
        if (examples.Length > MaxExamples)
            Line($"| ... {N(examples.Length - MaxExamples)} more | | | | |");
        Line();

        var constants = ConstantSinks(packages);
        Line($"## Constant-bearing sinks (Analyzed sites with a Constant or OneOf argument; all {constants.Count} in `-constant-sinks.tsv`)");
        Line();
        Line("The same rule and format as `--ssa`'s: diff the TSV against a committed `ssa-facts-<manifest>-<configuration>-<date>-constant-sinks.tsv` to see what folding moved.");
        Line();
        Line("| Capability | Callee | Sites | Packages |");
        Line("|---|---|---:|---:|");
        foreach (var c in constants.Take(TopSinks))
        {
            var parts = c.Key.Split('\t');
            Line($"| {Clean(parts[0])} | `{Clean(parts[^1])}` | {N(c.Sites)} | {c.Packages} |");
        }
        Line();

        var md = stem + ".md";
        PackageReachResult.WriteAtomically(md, text.ToString());
        PackageReachResult.WriteAtomically(stem + "-cells.tsv", Tsv(
            ["package", "class", "collection", "label", "fired", "roots", "floor"],
            packages.SelectMany(p => p.Cells.Select(c => new[] { p.Package, c.Class, c.Collection, c.Label, Yes(c.Fired), I(c.Roots), Yes(c.Floor) }))));
        PackageReachResult.WriteAtomically(stem + "-signals.tsv", Tsv(
            ["package", "signal", "sites", "floor"],
            packages.SelectMany(p => p.Signals.Select(s => new[] { p.Package, s.Signal, I(s.Sites), Yes(s.Floor) }))));
        PackageReachResult.WriteAtomically(stem + "-examples.tsv", Tsv(
            ["package", "folder", "signal", "caller", "callee", "call"],
            examples.Select(x => new[] { x.Package, x.Example.Folder, x.Example.Signal, x.Example.Caller, x.Example.Callee, x.Example.Call })));
        PackageReachResult.WriteAtomically(stem + "-packages.tsv", Tsv(
            ["package", "status", "wall_ms", "folders", "statements_dropped"],
            packages.Select(p => new[] { p.Package, p.Status, I(p.WallMs), I(p.Folders), I(p.StatementsDropped) })));
        PackageReachResult.WriteAtomically(stem + "-constant-sinks.tsv", ConstantSinksTsv(packages));
        return ([md, stem + "-cells.tsv", stem + "-signals.tsv", stem + "-examples.tsv", stem + "-packages.tsv", stem + "-constant-sinks.tsv"], problems.Count);
    }

    /// <summary>Per cell, in the measurement's order (class, collection, label): see <see cref="LeversTally"/>.</summary>
    public static IReadOnlyList<LeversTally> CellTallies(IReadOnlyList<LeversPackageResult> packages) =>
        [.. packages.SelectMany(p => p.Cells.Select(c => (Package: p, Cell: c)))
            .GroupBy(x => (x.Cell.Class, x.Cell.Collection, x.Cell.Label))
            .OrderBy(g => Array.IndexOf(Order(), g.Key.Class)).ThenBy(g => g.Key.Collection, StringComparer.Ordinal).ThenBy(g => g.Key.Label == LeversMeasure.DirectLabel ? 0 : 1)
            .Select(g => Tally($"{g.Key.Class} {g.Key.Collection}+Network {g.Key.Label}", packages, g.Select(x => (x.Package, x.Cell.Fired, x.Cell.Floor, 0L))))];

    /// <summary>Per signal, in enum order: see <see cref="LeversTally"/>.</summary>
    public static IReadOnlyList<LeversTally> SignalTallies(IReadOnlyList<LeversPackageResult> packages) =>
        [.. packages.SelectMany(p => p.Signals.Select(s => (Package: p, Signal: s)))
            .GroupBy(x => x.Signal.Signal, StringComparer.Ordinal)
            .OrderBy(g => Enum.TryParse<Silvergun.CodeAnalysis.IL.Ssa.SsaSignal>(g.Key, out var s) ? (int)s : int.MaxValue)
            .Select(g => Tally(g.Key, packages, g.Select(x => (x.Package, x.Signal.Sites > 0, x.Signal.Floor, (long)x.Signal.Sites))))];

    /// <summary>
    /// The constant-sinks table: per <c>Capability\tCallee</c>, the sites and the packages with any, by sites descending then
    /// key ordinal, exactly as <c>--ssa</c> orders it.
    /// </summary>
    public static IReadOnlyList<(string Key, long Sites, int Packages)> ConstantSinks(IReadOnlyList<LeversPackageResult> packages) =>
        [.. packages.SelectMany(p => p.ConstantSinks.Select(c => (p.Package, c.Key, c.Value)))
            .GroupBy(c => c.Key, StringComparer.Ordinal)
            .Select(g => (Key: g.Key, Sites: g.Sum(c => (long)c.Value), Packages: g.Select(c => c.Package).Distinct().Count()))
            .OrderByDescending(c => c.Sites).ThenBy(c => c.Key, StringComparer.Ordinal)];

    /// <summary>The <c>-constant-sinks.tsv</c> of <see cref="ConstantSinks"/>: header <c>capability callee sites packages</c>, tab separated, LF.</summary>
    public static string ConstantSinksTsv(IReadOnlyList<LeversPackageResult> packages) =>
        Tsv(["capability", "callee", "sites", "packages"], ConstantSinks(packages).Select(c => { var k = c.Key.Split('\t'); return new[] { k[0], k[^1], I(c.Sites), I(c.Packages) }; }));

    private static LeversTally Tally(string name, IReadOnlyList<LeversPackageResult> all, IEnumerable<(LeversPackageResult Package, bool Fired, bool Floor, long Sites)> rows)
    {
        var list = rows.ToArray();
        return new(name, all.Count(p => p.Status == "ok"), list.Count(r => r.Fired), list.Sum(r => r.Sites),
            [.. list.Where(r => r.Fired).Select(r => r.Package.Package).Order(StringComparer.Ordinal)],
            [.. list.Where(r => !r.Fired && r.Floor).Select(r => r.Package.Package).Order(StringComparer.Ordinal)]);
    }

    private static string[] Order() => [.. LeversMeasure.Classes.Select(c => c.ToString())];

    private static string Names(IReadOnlyList<string> names) =>
        names.Count == 0 ? "-" : string.Join(", ", names.Take(MaxNames).Select(Clean)) + (names.Count > MaxNames ? $", ... {names.Count - MaxNames} more" : string.Empty);

    private static string Yes(bool value) => value ? "yes" : "no";
    #endregion

    #region Fields
    private const int MaxListed = 100;
    private const int MaxNames = 60;
    private const int MaxExamples = 60;
    private const int TopSinks = 25;
    #endregion
}
