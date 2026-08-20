namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL;

/// <summary>One row of the headline density table - the answer to "can this capability gate anything?".</summary>
public sealed record CapabilityDensity(
    string Capability,
    int TotalFindings,
    int PackagesAffected,
    double SharePercent,
    double Median,
    int P90);

/// <summary>
/// One row of the indicator headline density table - the answer to "how common is this
/// <see cref="Silvergun.CodeAnalysis.IL.IndicatorCategory"/> in ordinary benign code?". <see cref="TotalFindings"/>
/// and per-package median/p90 are counted in raw <em>occurrences</em> (summed
/// <see cref="ScannedIndicator.Occurrences"/>), the same unit <c>IndicatorAnalysis</c> aggregates on, so this
/// table and the per-package table agree. <see cref="DistinctValues"/> is the size of the corpus-wide distinct
/// value set for the category (e.g. how many different hosts <c>GenericUrl</c> actually names) - the number that
/// makes the share interpretable together with table 2.
/// </summary>
public sealed record IndicatorCategoryDensity(
    string Category,
    int TotalFindings,
    int PackagesAffected,
    double SharePercent,
    int DistinctValues,
    double Median,
    int P90);

/// <summary>One of the 10 most widespread distinct values for one indicator category - the table that makes the
/// density share interpretable (is <c>GenericUrl</c> boilerplate, or is it not?).</summary>
public sealed record TopIndicatorValue(string Category, string Value, int PackageCount, int TotalOccurrences);

/// <summary>
/// Turns a corpus run into the two artifacts a later risk-scoring ADR consumes: a classified findings <c>.tsv</c>
/// and a density/coverage <c>.md</c>.
/// <para>
/// <b>Determinism is a property of these files, not an aspiration.</b> Nothing here reads the clock (the run date
/// appears only in the file name and a single header line), no absolute path reaches the TSV, every ordering is
/// <see cref="StringComparer.Ordinal"/>, every number is formatted with <see cref="CultureInfo.InvariantCulture"/>,
/// and the line separator is a literal <c>\n</c>. Two runs of the same manifest must produce byte-identical TSVs;
/// if they do not, the numbers are not evidence.
/// </para>
/// </summary>
public static class CorpusReport
{
    #region Methods
    /// <summary>
    /// Per-capability density over the packages that actually contributed data (<see cref="PackageResult.Counted"/>).
    /// The denominator is that set, not the manifest - a share computed over packages that were never scanned would
    /// understate every capability. Median and p90 are taken over <b>all</b> counted packages including the zeros,
    /// so "half the corpus has none of this" is visible rather than averaged away. p90 is nearest-rank
    /// (<c>ceil(0.9n)</c> on the ascending list), stated because the alternatives differ on small n.
    /// </summary>
    public static IReadOnlyList<CapabilityDensity> Density(IReadOnlyList<PackageResult> results)
    {
        var counted = results.Where(r => r.Counted).ToArray();
        var names = Enum.GetNames<Capability>()
            .Concat(counted.SelectMany(r => r.Findings).Select(f => f.Capability))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal);

        return names.Select(name =>
        {
            var perPackage = counted
                .Select(r => r.Findings.Count(f => string.Equals(f.Capability, name, StringComparison.Ordinal)))
                .OrderBy(n => n)
                .ToArray();
            var affected = perPackage.Count(n => n > 0);

            return new CapabilityDensity(
                name,
                perPackage.Sum(),
                affected,
                counted.Length == 0 ? 0 : 100.0 * affected / counted.Length,
                Median(perPackage),
                P90(perPackage));
        }).ToArray();
    }

    /// <summary>
    /// Per-<see cref="Silvergun.CodeAnalysis.IL.IndicatorCategory"/> density, the indicator analogue of
    /// <see cref="Density"/>. <see cref="IndicatorCategoryDensity.TotalFindings"/> and the per-package median/p90
    /// are counted in raw occurrences (<see cref="ScannedIndicator.Occurrences"/> summed per package), not in
    /// distinct-aggregate rows - <c>IndicatorAnalysis</c> already aggregates by (Category, Value, CallerType,
    /// CallerMethod) with an occurrence count, so counting occurrences here is what makes "total findings" mean
    /// "total <c>ldstr</c> hits", the same unit the capability table's finding count already uses (capability
    /// findings are never aggregated, so there the raw count and the row count coincide).
    /// </summary>
    public static IReadOnlyList<IndicatorCategoryDensity> IndicatorDensity(IReadOnlyList<PackageResult> results)
    {
        var counted = results.Where(r => r.Counted).ToArray();
        var names = Enum.GetNames<IndicatorCategory>()
            .Concat(counted.SelectMany(r => r.Indicators).Select(f => f.Category))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal);

        return names.Select(name =>
        {
            var matching = counted
                .Select(r => r.Indicators.Where(f => string.Equals(f.Category, name, StringComparison.Ordinal)).ToArray())
                .ToArray();
            var perPackage = matching.Select(f => f.Sum(x => x.Occurrences)).OrderBy(n => n).ToArray();
            var affected = perPackage.Count(n => n > 0);
            var distinctValues = matching
                .SelectMany(f => f)
                .Select(f => f.Value)
                .Distinct(StringComparer.Ordinal)
                .Count();

            return new IndicatorCategoryDensity(
                name,
                perPackage.Sum(),
                affected,
                counted.Length == 0 ? 0 : 100.0 * affected / counted.Length,
                distinctValues,
                Median(perPackage),
                P90(perPackage));
        }).ToArray();
    }

    /// <summary>
    /// The 10 most widespread distinct (Category, Value) pairs per category, ranked by
    /// <see cref="TopIndicatorValue.PackageCount"/> - the number of DISTINCT counted packages carrying at least one
    /// finding of that value, not the raw occurrence count. This is the table that makes table 1's shares
    /// interpretable: a category can be near-universal because of one boilerplate value repeated everywhere, or
    /// because of many genuinely distinct values, and only this table tells the two apart. Ties broken by total
    /// occurrences, then the value itself (<see cref="StringComparer.Ordinal"/>), so the ranking is deterministic.
    /// </summary>
    public static IReadOnlyList<TopIndicatorValue> TopIndicatorValues(IReadOnlyList<PackageResult> results, int topN = 10)
    {
        var counted = results.Where(r => r.Counted).ToArray();

        var rows = counted
            .SelectMany(r => r.Indicators.Select(f => (r.Entry.Id, f.Category, f.Value, f.Occurrences)))
            .GroupBy(x => (x.Category, x.Value))
            .Select(g => new TopIndicatorValue(
                g.Key.Category,
                g.Key.Value,
                g.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count(),
                g.Sum(x => x.Occurrences)))
            .ToArray();

        return rows
            .GroupBy(r => r.Category, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .SelectMany(g => g
                .OrderByDescending(r => r.PackageCount)
                .ThenByDescending(r => r.TotalOccurrences)
                .ThenBy(r => r.Value, StringComparer.Ordinal)
                .Take(topN))
            .ToArray();
    }

    /// <summary>
    /// Writes the classified findings TSV - one line per finding, with the package, pinned version, chosen TFM and
    /// assembly file it came from. No path, no timestamp, no machine-specific text: this file is the determinism
    /// gate.
    /// </summary>
    public static void WriteFindingsTsv(string path, IReadOnlyList<PackageResult> results)
    {
        var rows = results
            .Where(r => r.Counted)
            .SelectMany(r => r.Scans.SelectMany(s => s.Findings.Select(f => string.Join('\t',
                r.Entry.Id, r.Entry.Version, r.Tfm.Tfm, s.AssemblyFile,
                f.Capability, f.Kind, f.CallerType, f.CallerMethod, f.CalledApi))))
            .OrderBy(l => l, StringComparer.Ordinal);

        Write(path, new[]
        {
            string.Join('\t', "Package", "Version", "Tfm", "Assembly",
                "Capability", "Kind", "CallerType", "CallerMethod", "CalledApi")
        }.Concat(rows));
    }

    /// <summary>
    /// Writes the classified indicator findings TSV - one line per aggregated indicator, mirroring
    /// <see cref="WriteFindingsTsv"/>. <see cref="ScannedIndicator.Occurrences"/> and
    /// <see cref="ScannedIndicator.Excerpt"/> are the two fields with no capability-TSV analogue: occurrences
    /// because indicators are aggregated (constraint 5 of the classifier spec) and capability findings are not;
    /// excerpt because a category like <c>ReflectionTypeName</c> or <c>GenericUrl</c> is only interpretable with a
    /// little surrounding context.
    /// </summary>
    public static void WriteIndicatorFindingsTsv(string path, IReadOnlyList<PackageResult> results)
    {
        var rows = results
            .Where(r => r.Counted)
            .SelectMany(r => r.Scans.SelectMany(s => s.Indicators.Select(f => string.Join('\t',
                r.Entry.Id, r.Entry.Version, r.Tfm.Tfm, s.AssemblyFile,
                f.Category, f.Value, f.CallerType, f.CallerMethod,
                f.Occurrences.ToString(CultureInfo.InvariantCulture), f.Excerpt))))
            .OrderBy(l => l, StringComparer.Ordinal);

        Write(path, new[]
        {
            string.Join('\t', "Package", "Version", "Tfm", "Assembly",
                "Category", "Value", "CallerType", "CallerMethod", "Occurrences", "Excerpt")
        }.Concat(rows));
    }

    /// <summary>Writes the density + per-package + coverage-honesty markdown next to the TSV.</summary>
    public static void WriteMarkdown(
        string path, string tsvName, DateOnly date, CorpusManifest manifest, string cacheRoot,
        IReadOnlyList<PackageResult> results)
    {
        var counted = results.Where(r => r.Counted).ToArray();
        var density = Density(results);
        var caps = density.Select(d => d.Capability).ToArray();
        var abbreviations = Abbreviate(caps);
        var lines = new List<string>();

        lines.AddRange([
            $"# Benign corpus - capability density ({date:yyyy-MM-dd})",
            string.Empty,
            "**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is",
            "\"overwhelmingly not malware\" by download count, not by audit (ADR-0021: benign by assumption is not",
            "benign by proof). The question answered here is *precision*: which capabilities are so common in benign",
            "code that they cannot gate anything. Nothing in `--strict`, the `Catalog`, `capabilities.cm` or any",
            "scoring was changed to produce these numbers.",
            string.Empty,
            "| Parameter | Value |",
            "| --- | --- |",
            $"| Manifest | `{Path.GetFileName(manifest.Path)}` |",
            $"| Manifest hash (sha256 of normalized `id,version` list) | `{manifest.Hash}` |",
            $"| Packages in manifest (after `--take`) | {manifest.Entries.Count} |",
            $"| Packages contributing to density | {counted.Length} |",
            $"| Assemblies scanned | {counted.Sum(r => r.Scans.Count(s => s.Ok))} |",
            $"| Methods analysed | {counted.Sum(r => r.MethodsAnalyzed)} |",
            $"| Methods skipped | {counted.Sum(r => r.MethodsSkipped)} |",
            $"| Total findings | {counted.Sum(r => r.Findings.Count())} |",
            $"| Cache root (outside the repo; no `.nupkg` is ever written into it) | `{cacheRoot}` |",
            $"| Classified findings | `{tsvName}` |",
            string.Empty,
            "## Method",
            string.Empty,
            "- **TFM selection.** Per package, among `lib/<tfm>/` folders holding at least one `.dll`: the highest",
            "  `net<major>.<minor>` (no platform suffix), else exactly `netstandard2.0`, else the package is reported",
            "  as `no-scannable-tfm` and contributes nothing. The chosen TFM is recorded on every row below, because",
            "  comparing a `net10.0` surface against a `netstandard2.0` one silently would make the corpus",
            "  incomparable with itself.",
            "- **Process isolation.** One child process per assembly, exit code checked (ADR-0021). A child that",
            "  exits non-zero, times out, or exits 0 without printing `DONE` is reported below, never silently lost.",
            "- **Denominator.** Shares are over the packages that contributed data, listed as `scanned` or",
            "  `scanned-partial`. Median and p90 are over that same set *including packages with zero findings*;",
            "  p90 is nearest-rank.",
            string.Empty,
            "## Capability density - the calibration answer",
            string.Empty,
            $"Share = packages with at least one finding of that capability, out of the {counted.Length} that",
            "contributed data. A capability with a high share cannot gate anything on its own.",
            string.Empty,
            "| Capability | Packages with >=1 | Share of corpus | Total findings | Median/pkg | p90/pkg |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]);

        lines.AddRange(density
            .OrderByDescending(d => d.SharePercent)
            .ThenBy(d => d.Capability, StringComparer.Ordinal)
            .Select(d => $"| {d.Capability} | {d.PackagesAffected} | {Percent(d.SharePercent)} | " +
                         $"{d.TotalFindings} | {Fixed1(d.Median)} | {d.P90} |"));

        // The bottom line for --strict, which gates on ANY finding: how much of a benign corpus it fails.
        var totals = counted.Select(r => r.Findings.Count()).OrderBy(n => n).ToArray();
        var anyPackages = totals.Count(n => n > 0);
        lines.Add(
            $"| **(any capability - what `--strict` gates on today)** | **{anyPackages}** | " +
            $"**{Percent(counted.Length == 0 ? 0 : 100.0 * anyPackages / counted.Length)}** | " +
            $"**{totals.Sum()}** | **{Fixed1(Median(totals))}** | **{P90(totals)}** |");

        lines.AddRange([
            string.Empty,
            "## Per package",
            string.Empty,
            "| Package | Version | TFM | Status | Assemblies | Methods analysed | Methods skipped | Findings |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
        ]);

        lines.AddRange(results.Select(r =>
            $"| {r.Entry.Id} | {r.Entry.Version} | {r.Tfm.Tfm ?? "-"} | {r.Status} | {r.Scans.Count} | " +
            $"{r.MethodsAnalyzed} | {r.MethodsSkipped} | {r.Findings.Count()} |"));

        lines.AddRange([
            string.Empty,
            "## Findings by capability, per package",
            string.Empty,
            $"Columns are the first four letters of each capability: {string.Join(", ", caps.Select(c => $"`{abbreviations[c]}` = {c}"))}.",
            string.Empty,
            $"| Package | {string.Join(" | ", caps.Select(c => abbreviations[c]))} |",
            $"| --- |{string.Concat(caps.Select(_ => " ---: |"))}",
        ]);

        lines.AddRange(counted.Select(r => $"| {r.Entry.Id} | " + string.Join(" | ", caps.Select(c =>
            r.Findings.Count(f => string.Equals(f.Capability, c, StringComparison.Ordinal)))) + " |"));

        var incomplete = results.Where(r => r.Status != PackageResult.Scanned).ToArray();
        lines.AddRange([
            string.Empty,
            "## Coverage honesty (ADR-0024)",
            string.Empty,
            $"{results.Count - incomplete.Length} of {results.Count} manifest entries were scanned completely.",
            "Everything below is a package whose numbers above are a **floor, not a total** - or that produced no",
            "numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the",
            "partiality is stated alongside it.",
            string.Empty,
        ]);

        if (incomplete.Length == 0)
            lines.Add("*None: every manifest entry was scanned completely.*");
        else
        {
            lines.AddRange([
                "| Package | Version | Status | Counted in density | Reason |",
                "| --- | --- | --- | --- | --- |",
            ]);
            lines.AddRange(incomplete.Select(r =>
                $"| {r.Entry.Id} | {r.Entry.Version} | {r.Status} | {(r.Counted ? "yes" : "**no**")} | " +
                $"{r.Note ?? "-"} |"));
        }

        Write(path, lines);
    }

    /// <summary>
    /// Writes the indicator-prevalence markdown next to <see cref="WriteIndicatorFindingsTsv"/>'s TSV: the four
    /// tables the calibration task asks for (per-category prevalence, top distinct values, per-package, and the
    /// explicit CallbackDomain/ExfilSink/DynamicDns call-out), plus truncation and coverage-honesty sections. This
    /// is a data-only artifact - it changes no threshold and proposes no gate.
    /// </summary>
    public static void WriteIndicatorMarkdown(
        string path, string tsvName, DateOnly date, CorpusManifest manifest, string cacheRoot,
        IReadOnlyList<PackageResult> results)
    {
        var counted = results.Where(r => r.Counted).ToArray();
        var density = IndicatorDensity(results);
        var top = TopIndicatorValues(results);
        var truncatedPackages = results.Where(r => r.IndicatorTruncated).ToArray();
        var lines = new List<string>();

        lines.AddRange([
            $"# Benign corpus - indicator prevalence ({date:yyyy-MM-dd})",
            string.Empty,
            "**A measurement, not a gate.** These are ordinary, widely-used NuGet packages; their label is",
            "\"overwhelmingly not malware\" by download count, not by audit (ADR-0021: benign by assumption is not",
            "benign by proof). The question answered here is *precision*: which `IndicatorCategory` values are so",
            "common in benign code that they carry no gating signal on their own. Nothing in `--strict`, the",
            "`IndicatorAnalysis` classifier, or any threshold was changed to produce these numbers - the gating",
            "decision (if any) is a separate ADR, written from this data.",
            string.Empty,
            "| Parameter | Value |",
            "| --- | --- |",
            $"| Manifest | `{Path.GetFileName(manifest.Path)}` |",
            $"| Manifest hash (sha256 of normalized `id,version` list) | `{manifest.Hash}` |",
            $"| Packages in manifest (after `--take`) | {manifest.Entries.Count} |",
            $"| Packages contributing to prevalence | {counted.Length} |",
            $"| Assemblies scanned | {counted.Sum(r => r.Scans.Count(s => s.Ok))} |",
            $"| Methods analysed | {counted.Sum(r => r.MethodsAnalyzed)} |",
            $"| Methods skipped | {counted.Sum(r => r.MethodsSkipped)} |",
            $"| Total indicator findings (raw occurrences) | {counted.Sum(r => r.Indicators.Sum(f => f.Occurrences))} |",
            $"| Distinct-indicator cap (10,000/assembly) hit anywhere | {(truncatedPackages.Length == 0 ? "no" : $"**yes - {truncatedPackages.Length} package(s), see Truncation below**")} |",
            $"| Cache root (outside the repo; no `.nupkg` is ever written into it) | `{cacheRoot}` |",
            $"| Classified indicator findings | `{tsvName}` |",
            string.Empty,
            "## Method",
            string.Empty,
            "- **TFM selection.** Per package, among `lib/<tfm>/` folders holding at least one `.dll`: the highest",
            "  `net<major>.<minor>` (no platform suffix), else exactly `netstandard2.0`, else the package is reported",
            "  as `no-scannable-tfm` and contributes nothing. The chosen TFM is recorded on every row below, because",
            "  comparing a `net10.0` surface against a `netstandard2.0` one silently would make the corpus",
            "  incomparable with itself.",
            "- **Process isolation.** One child process per assembly, exit code checked (ADR-0021). A child that",
            "  exits non-zero, times out, or exits 0 without printing `DONE` is reported below, never silently lost.",
            "- **Denominator.** Shares are over the packages that contributed data, listed as `scanned` or",
            "  `scanned-partial`. Median and p90 are over that same set *including packages with zero findings*;",
            "  p90 is nearest-rank.",
            "- **Occurrence counting.** `IndicatorAnalysis` aggregates per (Category, Value, CallerType,",
            "  CallerMethod) with an `Occurrences` count (constraint 5 of the classifier spec); \"total findings\",",
            "  and the per-package median/p90 below, sum `Occurrences`, so they count raw `ldstr` hits, not",
            "  aggregated rows. \"Distinct values\" counts the aggregated rows' distinct `Value`s instead - the size",
            "  of the corpus-wide value set for that category.",
            "- **Truncation.** `IndicatorReport.Truncated` (the 10,000-distinct-indicator-per-assembly cap) is",
            "  checked per assembly; if it fired anywhere, every number below for the affected package is a",
            "  **floor, not a total** - see Truncation below.",
            string.Empty,
            "## Indicator prevalence - the calibration answer",
            string.Empty,
            $"Share = packages with at least one finding of that category, out of the {counted.Length} that",
            "contributed data. A category with a high share cannot gate anything on its own.",
            string.Empty,
            "| Category | Packages with >=1 | Share of corpus | Total findings | Distinct values | Median/pkg | p90/pkg |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]);

        lines.AddRange(density
            .OrderByDescending(d => d.SharePercent)
            .ThenBy(d => d.Category, StringComparer.Ordinal)
            .Select(d => $"| {d.Category} | {d.PackagesAffected} | {Percent(d.SharePercent)} | " +
                         $"{d.TotalFindings} | {d.DistinctValues} | {Fixed1(d.Median)} | {d.P90} |"));

        // The bottom line for the eventual gate question: how much of a benign corpus carries ANY indicator.
        var totals = counted.Select(r => r.Indicators.Sum(f => f.Occurrences)).OrderBy(n => n).ToArray();
        var anyPackages = totals.Count(n => n > 0);
        var anyDistinct = counted.SelectMany(r => r.Indicators).Select(f => (f.Category, f.Value)).Distinct().Count();
        lines.Add(
            $"| **(any indicator)** | **{anyPackages}** | " +
            $"**{Percent(counted.Length == 0 ? 0 : 100.0 * anyPackages / counted.Length)}** | " +
            $"**{totals.Sum()}** | **{anyDistinct}** | **{Fixed1(Median(totals))}** | **{P90(totals)}** |");

        lines.AddRange([
            string.Empty,
            "## Top 10 most widespread distinct values, per category",
            string.Empty,
            "Ranked by number of DISTINCT counted packages carrying the value (not raw occurrences); ties broken by",
            "total occurrences, then the value itself. This is the table that makes the shares above interpretable -",
            "without it a high share is just a number.",
            string.Empty,
            "| Category | Value | Packages | Total occurrences |",
            "| --- | --- | ---: | ---: |",
        ]);

        if (top.Count == 0)
            lines.Add("*No indicator findings in the corpus.*");
        else
            lines.AddRange(top.Select(t => $"| {t.Category} | {Escape(t.Value)} | {t.PackageCount} | {t.TotalOccurrences} |"));

        lines.AddRange([
            string.Empty,
            "## Per package",
            string.Empty,
            "| Package | Version | TFM | Status | Assemblies | Indicator findings | Truncated | Cap-hit |",
            "| --- | --- | --- | --- | ---: | ---: | --- | --- |",
        ]);

        lines.AddRange(results.Select(r =>
            $"| {r.Entry.Id} | {r.Entry.Version} | {r.Tfm.Tfm ?? "-"} | {r.Status} | {r.Scans.Count} | " +
            $"{r.Indicators.Sum(f => f.Occurrences)} | {(r.IndicatorTruncated ? "**yes**" : "no")} | " +
            $"{(r.Findings.Any() ? "yes" : "no")} |"));

        lines.AddRange([
            string.Empty,
            "## CallbackDomain / ExfilSink / DynamicDns - every hit, individually",
            string.Empty,
            "A benign package tripping one of these three categories is either a false positive in our domain list",
            "or a genuinely interesting package; either way it must be visible by name, not buried in a count.",
            string.Empty,
        ]);

        var sinkCategories = new[] { "CallbackDomain", "ExfilSink", "DynamicDns" };
        var sinkHits = counted
            .SelectMany(r => r.Scans.SelectMany(s => s.Indicators
                .Where(f => sinkCategories.Contains(f.Category, StringComparer.Ordinal))
                .Select(f => (Package: r.Entry.Id, Version: r.Entry.Version, Assembly: s.AssemblyFile, Finding: f))))
            .OrderBy(x => x.Finding.Category, StringComparer.Ordinal)
            .ThenBy(x => x.Package, StringComparer.Ordinal)
            .ThenBy(x => x.Finding.Value, StringComparer.Ordinal)
            .ThenBy(x => x.Finding.CallerType, StringComparer.Ordinal)
            .ThenBy(x => x.Finding.CallerMethod, StringComparer.Ordinal)
            .ToArray();

        if (sinkHits.Length == 0)
            lines.Add(
                "*None: no package in the corpus produced a CallbackDomain, ExfilSink, or DynamicDns finding.*");
        else
        {
            lines.AddRange([
                "| Category | Package | Version | Assembly | Value | CallerType | CallerMethod | Occurrences |",
                "| --- | --- | --- | --- | --- | --- | --- | ---: |",
            ]);
            lines.AddRange(sinkHits.Select(x =>
                $"| {x.Finding.Category} | {x.Package} | {x.Version} | {x.Assembly} | {Escape(x.Finding.Value)} | " +
                $"{Escape(x.Finding.CallerType)} | {Escape(x.Finding.CallerMethod)} | {x.Finding.Occurrences} |"));
        }

        lines.AddRange([
            string.Empty,
            "## Truncation",
            string.Empty,
        ]);

        if (truncatedPackages.Length == 0)
            lines.Add(
                "*None: the 10,000-distinct-indicator-per-assembly cap was not reached by any assembly in the " +
                "corpus - every number above is a total, not a floor.*");
        else
        {
            lines.AddRange([
                "The distinct-indicator cap was reached for the assemblies below. Every indicator number for the",
                "affected package above is a **floor, not a total**.",
                string.Empty,
                "| Package | Version | Assembly |",
                "| --- | --- | --- |",
            ]);
            lines.AddRange(truncatedPackages.SelectMany(r => r.Scans
                .Where(s => s.IndicatorTruncated)
                .Select(s => $"| {r.Entry.Id} | {r.Entry.Version} | {s.AssemblyFile} |")));
        }

        var incomplete = results.Where(r => r.Status != PackageResult.Scanned).ToArray();
        lines.AddRange([
            string.Empty,
            "## Coverage honesty (ADR-0024)",
            string.Empty,
            $"{results.Count - incomplete.Length} of {results.Count} manifest entries were scanned completely.",
            "Everything below is a package whose numbers above are a **floor, not a total** - or that produced no",
            "numbers at all. A corpus statistic computed over partially-analysed input is a lie unless the",
            "partiality is stated alongside it.",
            string.Empty,
        ]);

        if (incomplete.Length == 0)
            lines.Add("*None: every manifest entry was scanned completely.*");
        else
        {
            lines.AddRange([
                "| Package | Version | Status | Counted in prevalence | Reason |",
                "| --- | --- | --- | --- | --- |",
            ]);
            lines.AddRange(incomplete.Select(r =>
                $"| {r.Entry.Id} | {r.Entry.Version} | {r.Status} | {(r.Counted ? "yes" : "**no**")} | " +
                $"{r.Note ?? "-"} |"));
        }

        Write(path, lines);
    }

    /// <summary>Nearest-rank p90 of an <b>ascending</b> list; 0 for an empty one.</summary>
    public static int P90(IReadOnlyList<int> ascending) =>
        ascending.Count == 0 ? 0 : ascending[Math.Min(ascending.Count - 1, (int)Math.Ceiling(0.9 * ascending.Count) - 1)];

    /// <summary>Median of an <b>ascending</b> list (mean of the two middles when even); 0 for an empty one.</summary>
    public static double Median(IReadOnlyList<int> ascending) =>
        ascending.Count == 0 ? 0
        : ascending.Count % 2 == 1 ? ascending[ascending.Count / 2]
        : (ascending[ascending.Count / 2 - 1] + ascending[ascending.Count / 2]) / 2.0;

    // Distinct 4-letter column heads, or the full names when four letters would collide (a future appended
    // capability must not silently share a column with an existing one).
    private static IReadOnlyDictionary<string, string> Abbreviate(IReadOnlyList<string> capabilities)
    {
        var shortened = capabilities.ToDictionary(c => c, c => c[..Math.Min(4, c.Length)], StringComparer.Ordinal);
        return shortened.Values.Distinct(StringComparer.Ordinal).Count() == capabilities.Count
            ? shortened
            : capabilities.ToDictionary(c => c, c => c, StringComparer.Ordinal);
    }

    private static string Percent(double value) => value.ToString("F1", CultureInfo.InvariantCulture) + "%";

    // Indicator values/type names/method names are attacker-influenced text and can legitimately contain '|',
    // which would otherwise silently corrupt a markdown table's column layout.
    private static string Escape(string value) => value.Replace("|", "\\|", StringComparison.Ordinal);

    private static string Fixed1(double value) => value.ToString("F1", CultureInfo.InvariantCulture);

    // Explicit \n and no BOM: the determinism check is a byte comparison, and Environment.NewLine is not a constant.
    private static void Write(string path, IEnumerable<string> lines) =>
        File.WriteAllText(path, string.Join('\n', lines) + '\n', new UTF8Encoding(false));
    #endregion
}
