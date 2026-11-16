namespace Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// One package's S5 presentation (<c>docs/agent/tasks/ssa-facts-s5.md</c>, S5.3), from the worker passes <c>--ssa</c>
/// already runs: <see cref="ReachabilitySummary.From"/> of the off, on and repeat reports, serialized as scan-package's
/// <c>--json</c> writes them.
/// <list type="bullet">
/// <item><description><see cref="Status"/>: "ok", or why there is nothing to compare (a pass without a report).</description></item>
/// <item><description><see cref="Additive"/>: the on summary with every <c>Ssa</c> removed is byte for byte the off
/// summary; <see cref="Mismatches"/> names where it is not (bounded, escaped). <see cref="CompleteEqual"/>: the two
/// <c>Complete</c> flags agree.</description></item>
/// <item><description>Bytes: <see cref="OffBytes"/> and <see cref="OnBytes"/> are the summaries' UTF-8 JSON;
/// <see cref="SsaBytes"/> is what the <c>Ssa</c> objects add to the on summary (on less the stripped on).</description></item>
/// <item><description>Sites: <see cref="SitesListed"/> and <see cref="SitesDropped"/> after both caps;
/// <see cref="FolderCapHits"/> folders with more resolved sites than the per-folder cap; <see cref="PackageCapHit"/> when
/// the package cap dropped any.</description></item>
/// <item><description><see cref="FoldersIncomplete"/> by <see cref="FolderSsaSummary.Incomplete"/>, a folder without
/// SSA counted; <see cref="GapKinds"/>: folders per gap kind, as the section lists them.</description></item>
/// <item><description><see cref="SectionLines"/>: the terminal section's logical lines, estimated from the summary as
/// <c>SsaSectionRenderer</c> writes them (that class is internal to the CLI): at most 10 sites per folder, each with its
/// target line, then one "N more site(s) ... in --json" line; a narrow terminal wraps more.</description></item>
/// <item><description><see cref="Determinism"/>: "equal" when the on and repeat summaries' <c>Ssa</c> JSON match, "cut"
/// when they differ only where a folder's time backstop or timeout cut either run, otherwise "differs"; "n/a" without a
/// repeat.</description></item>
/// </list>
/// </summary>
public sealed record SsaPresentation(
    string Status,
    bool Additive,
    bool CompleteEqual,
    List<string> Mismatches,
    long OffBytes,
    long OnBytes,
    long SsaBytes,
    int Folders,
    int FoldersWithSsa,
    int Copies,
    int SitesListed,
    int SitesDropped,
    int FolderCapHits,
    bool PackageCapHit,
    int FoldersIncomplete,
    Dictionary<string, int> GapKinds,
    int SectionLines,
    string Determinism)
{
    #region Methods
    /// <summary>The presentation of one package's passes. Never throws: a failure is its <see cref="Status"/>.</summary>
    public static SsaPresentation Of(PackageReachabilityReport? off, PackageReachabilityReport? on, PackageReachabilityReport? repeat)
    {
        if (off is null || on is null)
            return Empty($"n/a: no {(off is null ? "off" : "on")} report");
        try
        {
            var offSummary = ReachabilitySummary.From(off);
            var onSummary = ReachabilitySummary.From(on);
            var stripped = onSummary with { Folders = [.. onSummary.Folders.Select(f => f with { Ssa = null })] };
            var offJson = Json(offSummary);
            var onJson = Json(onSummary);
            var strippedJson = Json(stripped);

            var mismatches = new List<string>();
            if (offSummary.Folders.Count != stripped.Folders.Count)
                mismatches.Add($"folders: {offSummary.Folders.Count} off, {stripped.Folders.Count} on");
            for (var i = 0; i < Math.Min(offSummary.Folders.Count, stripped.Folders.Count); i++)
                if (Json(offSummary.Folders[i]) != Json(stripped.Folders[i]))
                    mismatches.Add($"folder {i} {Program.Redact(offSummary.Folders[i].Folder)}: off {offSummary.Folders[i].Outcome}, on {stripped.Folders[i].Outcome}");
            if (offSummary.StatementsDropped != stripped.StatementsDropped)
                mismatches.Add($"statements dropped: {offSummary.StatementsDropped} off, {stripped.StatementsDropped} on");
            if (offSummary.Complete != stripped.Complete)
                mismatches.Add($"complete: {offSummary.Complete} off, {stripped.Complete} on");
            var additive = offJson == strippedJson;
            if (!additive && mismatches.Count == 0)
                mismatches.Add("the JSON differs outside the folders");

            var ssa = onSummary.Folders.Where(f => f.Ssa is not null).ToArray();
            // Each folder before the package cap: what the per-folder cap alone keeps and drops.
            var uncapped = on.Folders.Select((f, i) => SsaSummary.Of(f?.Ssa, copy: i < onSummary.Folders.Count && onSummary.Folders[i].SameAs is not null)).ToArray();
            var gaps = onSummary.Folders
                .SelectMany(f => f.Ssa is { } s ? Gaps(s).Select(g => g.Kind).Distinct() : ["no-ssa"])
                .GroupBy(k => k, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

            return new(
                "ok", additive, offSummary.Complete == onSummary.Complete, [.. mismatches.Take(MaxMismatches)],
                Bytes(offJson), Bytes(onJson), Bytes(onJson) - Bytes(strippedJson),
                onSummary.Folders.Count, ssa.Length, ssa.Count(IsCopy),
                ssa.Sum(f => f.Ssa!.Sites.Count), ssa.Sum(f => f.Ssa!.SitesDropped),
                uncapped.Count(s => s is not null && s.SitesDropped > 0),
                uncapped.Sum(s => s?.Sites.Count ?? 0) > SsaSummary.MaxSites,
                onSummary.Folders.Count(f => f.Ssa?.Incomplete() ?? true),
                gaps, Lines(onSummary), Repeat(onSummary, on, repeat));
        }
        catch (Exception ex)
        {
            return Empty($"failed: {ex.GetType().Name}: {Program.Redact(ex.Message)}");
        }
    }

    private static SsaPresentation Empty(string status) => new(status, false, false, [], 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, [], 0, "n/a");

    // The on and repeat summaries' Ssa parts, folder by folder.
    private static string Repeat(ReachabilitySummary onSummary, PackageReachabilityReport on, PackageReachabilityReport? repeat)
    {
        if (repeat is null)
            return "n/a";
        var again = ReachabilitySummary.From(repeat);
        if (again.Folders.Count != onSummary.Folders.Count)
            return "differs";
        var cut = false;
        for (var i = 0; i < onSummary.Folders.Count; i++)
        {
            if (Json(onSummary.Folders[i].Ssa) == Json(again.Folders[i].Ssa))
                continue;
            if (!Cut(on, i) && !Cut(repeat, i))
                return "differs";
            cut = true;
        }
        return cut ? "cut" : "equal";
    }

    private static bool Cut(PackageReachabilityReport report, int index) =>
        index < report.Folders.Count && report.Folders[index]?.Ssa is { } ssa
        && (ssa.Outcome == SsaFolderOutcome.TimedOut || ssa.Facts?.TimeBudget == true);

    // The section's logical lines, as SsaSectionRenderer.Write writes them: the title rule and the count line, then per
    // folder listed (a copy, resolved sites, or SSA-incomplete) its header, the copy line, its first TerminalSites sites
    // each with its target line, the "N more site(s) ... in --json" line past them, the summary caps' dropped line and
    // each gap.
    private static int Lines(ReachabilitySummary summary) =>
        2 + summary.Folders.Where(f => f.Ssa is { } s && (IsCopy(f) || Resolved(s) > 0 || s.Incomplete()))
            .Sum(f => 1 + (IsCopy(f) ? 1 : 0)
                + f.Ssa!.Sites.Take(TerminalSites).Sum(s => s.Target is null ? 1 : 2) + (f.Ssa.Sites.Count > TerminalSites ? 1 : 0)
                + (f.Ssa.SitesDropped > 0 ? 1 : 0) + (f.Ssa.Signals is { Count: > 0 } ? 1 : 0) + Gaps(f.Ssa).Count());

    private static bool IsCopy(FolderReachSummary folder) => folder.SameAs is not null && folder.Ssa?.Outcome == SsaFolderOutcome.Analyzed;

    private static int Resolved(FolderSsaSummary ssa) => ssa.Sites.Count + ssa.SitesDropped;

    // The section's gap lines of one folder, by kind, in its order.
    private static IEnumerable<(string Kind, int Line)> Gaps(FolderSsaSummary ssa)
    {
        if (ssa.Outcome != SsaFolderOutcome.Analyzed || ssa.Counts is not { } c)
        {
            yield return ($"not-analysed:{ssa.Outcome}", 1);
            yield break;
        }
        if (c.AssembliesLost > 0)
            yield return ("assemblies-lost", 1);
        if (c.MethodUnknown > 0)
            yield return ("method-unknown", 1);
        if (c.NotJoined > 0)
            yield return ("not-joined", 1);
        if (c.NotRun > 0 || c.MethodBudget || c.TimeBudget)
            yield return (c.TimeBudget ? "time-budget" : "method-budget", 1);
        if (c.TextBudget)
            yield return ("text-budget", 1);
        if (c.Truncated)
            yield return ("truncated", 1);
    }

    private static string Json<T>(T value) => JsonSerializer.Serialize(value, ReportOptions);

    private static long Bytes(string json) => Encoding.UTF8.GetByteCount(json);
    #endregion

    #region Fields
    private const int MaxMismatches = 10;

    // Sites the terminal lists per folder: SsaSectionRenderer.MaxSitesPerFolder, internal to the CLI, so restated here.
    private const int TerminalSites = 10;

    // PackageCapabilityReport's own options (PackageModel.cs, jsonOptions, private there): what scan-package --json writes.
    private static readonly JsonSerializerOptions ReportOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
    #endregion
}
