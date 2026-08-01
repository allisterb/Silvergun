namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>Everything measured about one manifest entry, including the entries that could not be measured.</summary>
public sealed record PackageResult(
    ManifestEntry Entry,
    string Status,
    TfmChoice Tfm,
    IReadOnlyList<AssemblyScan> Scans,
    string? Note)
{
    #region Properties
    /// <summary>Packages that contributed to the density numbers: at least one assembly scanned successfully.</summary>
    public bool Counted => Status is Scanned or Partial;

    public int MethodsAnalyzed => Scans.Sum(s => s.MethodsAnalyzed);

    public int MethodsSkipped => Scans.Sum(s => s.MethodsSkipped);

    public IEnumerable<ScannedFinding> Findings => Scans.SelectMany(s => s.Findings);
    #endregion

    #region Fields
    public const string Scanned = "scanned";
    public const string Partial = "scanned-partial";
    public const string NoTfm = "no-scannable-tfm";
    public const string DownloadFailed = "download-failed";
    public const string NoAssemblies = "no-assemblies";
    public const string ScanFailed = "scan-failed";
    #endregion
}

/// <summary>
/// Walks the manifest: acquire, choose a TFM, scan every assembly of that TFM in its own child process, and record
/// the outcome - including for the packages that never got scanned. <b>No manifest entry is ever dropped</b>: an
/// entry that could not be downloaded, has no scannable TFM, or whose child died still comes back as a
/// <see cref="PackageResult"/> with a status and a reason, because a corpus statistic computed over silently
/// partial input is a lie (ADR-0024).
/// </summary>
public sealed class CorpusDriver(PackageCache cache, string harnessExecutable, TimeSpan childTimeout)
{
    #region Methods
    /// <summary>Runs the whole manifest, sequentially and in manifest order, so runs are comparable.</summary>
    public IReadOnlyList<PackageResult> Run(CorpusManifest manifest, TextWriter progress)
    {
        var results = new List<PackageResult>();

        foreach (var (entry, index) in manifest.Entries.Select((e, i) => (e, i + 1)))
        {
            progress.Write($"[{index}/{manifest.Entries.Count}] {entry.Id} {entry.Version} ... ");
            var result = RunOne(entry);
            results.Add(result);
            progress.WriteLine(
                $"{result.Status} tfm={result.Tfm.Tfm ?? "-"} asm={result.Scans.Count} " +
                $"findings={result.Findings.Count()} skipped-methods={result.MethodsSkipped}");
        }

        return results;
    }

    private PackageResult RunOne(ManifestEntry entry)
    {
        var cached = cache.AcquireAsync(entry).GetAwaiter().GetResult();

        if (cached.Failure is not null)
            return new PackageResult(entry, PackageResult.DownloadFailed, cached.Tfm, [], cached.Failure);

        if (cached.Tfm.IsEmpty)
            return new PackageResult(entry, PackageResult.NoTfm, cached.Tfm, [],
                cached.Tfm.Available.Count == 0
                    ? "package ships no lib/<tfm>/*.dll at all"
                    : $"lib TFMs on offer: {string.Join(", ", cached.Tfm.Available)}");

        if (cached.AssemblyPaths.Count == 0)
            return new PackageResult(entry, PackageResult.NoAssemblies, cached.Tfm, [],
                $"lib/{cached.Tfm.Tfm} contained no extractable assembly");

        // One child per assembly, exit code checked (ADR-0021): a FailFast costs one assembly, not the run.
        var scans = cached.AssemblyPaths
            .OrderBy(p => Path.GetFileName(p), StringComparer.Ordinal)
            .Select(p => ChildScanRunner.Run(harnessExecutable, p, childTimeout))
            .ToArray();

        var status =
            scans.All(s => s.Ok) && scans.Sum(s => s.MethodsSkipped) == 0 ? PackageResult.Scanned
            : scans.Any(s => s.Ok) ? PackageResult.Partial
            : PackageResult.ScanFailed;

        var note = status == PackageResult.Scanned
            ? null
            : string.Join("; ", scans.Where(s => !s.Ok || s.MethodsSkipped > 0)
                .Select(s => $"{s.AssemblyFile}: " +
                             (s.Ok ? $"{s.MethodsSkipped} method(s) skipped" : s.Reason)));

        return new PackageResult(entry, status, cached.Tfm, scans, note);
    }
    #endregion
}
