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

    private static string Fixed1(double value) => value.ToString("F1", CultureInfo.InvariantCulture);

    // Explicit \n and no BOM: the determinism check is a byte comparison, and Environment.NewLine is not a constant.
    private static void Write(string path, IEnumerable<string> lines) =>
        File.WriteAllText(path, string.Join('\n', lines) + '\n', new UTF8Encoding(false));
    #endregion
}
