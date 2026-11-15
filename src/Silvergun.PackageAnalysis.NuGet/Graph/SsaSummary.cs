namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

/// <summary>A folder's sink sites by <see cref="SsaSiteStatus"/>, with the extraction's own counts and flags.</summary>
public sealed record SsaCounts(
    int Analyzed,
    int MethodUnknown,
    int NotJoined,
    int NotRun,
    int SitesTotal,
    bool Truncated,
    int MethodsLifted,
    IReadOnlyList<SsaFailureCount> Unknown,
    bool MethodBudget,
    bool TimeBudget,
    bool TextBudget,
    int AssembliesLost);

/// <summary>
/// What a reflection sink acts on, as SSA read it: <paramref name="Text"/> is the kind, type and member rendered as
/// <see cref="SsaSummary"/> renders values; <paramref name="Candidates"/> the first own node ids matched by name, of
/// <paramref name="CandidatesTotal"/>, never claimed unique or complete (<paramref name="CandidatesGap"/>).
/// </summary>
public sealed record SsaTargetSummary(SsaTargetKind Kind, string Text, IReadOnlyList<string> Candidates, int CandidatesTotal, string? CandidatesGap);

/// <summary>
/// One sink site with a value SSA resolved: <paramref name="Call"/> is the callee's key with its arguments rendered
/// (<c>System.Diagnostics.Process.Start("cmd.exe", _)</c>), <paramref name="Caller"/> and <paramref name="Callee"/> node
/// ids, <paramref name="Offset"/> the call's IL offset in the caller. Every string is escaped and bounded.
/// </summary>
public sealed record SsaSiteSummary(string Caller, string Callee, Capability Capability, uint Offset, string Call, SsaTargetSummary? Target, bool Merged);

/// <summary>
/// One folder's SSA facts as presented (ADR 0038: SSA-derived, informational): the outcome, the counts, and only the
/// Analyzed sites with a constant argument or receiver or a constant reflection target (<see cref="Sites"/>), at most
/// <see cref="SsaSummary.MaxSitesPerFolder"/>, <see cref="SitesDropped"/> counting the rest. A site that was not analysed
/// is counted, never listed: it says nothing about its values. A copy of another folder lists no sites.
/// </summary>
public sealed record FolderSsaSummary(SsaFolderOutcome Outcome, string? Reason, SsaCounts? Counts, IReadOnlyList<SsaSiteSummary> Sites, int SitesDropped)
{
    #region Methods
    /// <summary>
    /// Whether SSA left anything of the folder unsaid: an outcome other than Analyzed, no counts, a budget or bound hit
    /// (the text budget too: later constants keep only their hash), an assembly lost, or a site MethodUnknown, NotJoined
    /// or NotRun.
    /// </summary>
    public bool Incomplete() =>
        Outcome != SsaFolderOutcome.Analyzed || Counts is not { } c
        || c.Truncated || c.MethodBudget || c.TimeBudget || c.TextBudget || c.AssembliesLost > 0
        || c.MethodUnknown + c.NotJoined + c.NotRun > 0;
    #endregion
}

/// <summary>
/// Builds <see cref="FolderSsaSummary"/> from a folder's <see cref="FolderSsa"/> (<c>docs/agent/tasks/ssa-facts-s5.md</c>).
/// Deterministic; never throws. Every string is escaped again for display (<see cref="UntrustedText.Escape"/>, which
/// leaves the worker's already escaped text unchanged) and bounded.
/// </summary>
public static class SsaSummary
{
    #region Methods
    /// <summary>The summary of <paramref name="ssa"/>, or null when SSA was not asked for. A <paramref name="copy"/> lists no sites.</summary>
    public static FolderSsaSummary? Of(FolderSsa? ssa, bool copy)
    {
        if (ssa is null)
            return null;
        try
        {
            if (ssa.Facts is not { } facts)
                return new(ssa.Outcome, Name(ssa.Reason ?? "no reason was given"), null, [], 0);
            var counts = new SsaCounts(
                facts.Count(SsaSiteStatus.Analyzed), facts.Count(SsaSiteStatus.MethodUnknown), facts.Count(SsaSiteStatus.NotJoined),
                facts.Count(SsaSiteStatus.NotRun), facts.SitesTotal, facts.Truncated, facts.MethodsLifted, facts.Unknown,
                facts.MethodBudget, facts.TimeBudget, facts.TextBudget, facts.AssembliesLost);
            SsaSinkFact[] resolved = copy ? [] : [.. facts.Sites.Where(Resolved)];
            var sites = resolved
                .OrderBy(s => TargetResolved(s.Target) ? 0 : 1)
                .ThenBy(s => s.Site.Capability)
                .ThenBy(s => s.Site.NodeId, StringComparer.Ordinal)
                .ThenBy(s => s.Site.Offset)
                .ThenBy(s => s.Site.Callee, StringComparer.Ordinal)
                .Take(MaxSitesPerFolder)
                .Select(Site)
                .ToArray();
            var reason = ssa.Outcome == SsaFolderOutcome.Analyzed ? null : Name(ssa.Reason ?? "no reason was given");
            return new(ssa.Outcome, reason, counts, sites, resolved.Length - sites.Length);
        }
        catch (Exception ex)
        {
            return new(SsaFolderOutcome.Crashed, Name($"the folder's SSA summary could not be built: {ex.GetType().Name}: {ex.Message}"), null, [], 0);
        }
    }

    /// <summary>
    /// <paramref name="folders"/> with at most <see cref="MaxSites"/> sites listed over the package, in folder order; each
    /// folder's <see cref="FolderSsaSummary.SitesDropped"/> counts what it lost.
    /// </summary>
    public static IReadOnlyList<FolderReachSummary> Capped(IReadOnlyList<FolderReachSummary> folders)
    {
        var left = MaxSites;
        var capped = new FolderReachSummary[folders.Count];
        for (var i = 0; i < folders.Count; i++)
        {
            var folder = folders[i];
            if (folder.Ssa is { } ssa && ssa.Sites.Count > left)
                folder = folder with { Ssa = ssa with { Sites = [.. ssa.Sites.Take(left)], SitesDropped = ssa.SitesDropped + ssa.Sites.Count - left } };
            left -= folder.Ssa?.Sites.Count ?? 0;
            capped[i] = folder;
        }
        return capped;
    }

    /// <summary>A value for display: see <c>ssa-facts-s5.md</c> §3. Not yet escaped or bounded.</summary>
    internal static string Value(SsaValue? value) => value switch
    {
        null => "_",
        { Kind: SsaValueKind.Constant, Constants: [var c] } => Constant(c),
        { Kind: SsaValueKind.OneOf } => "one of " + string.Join(" | ", value.Constants.Select(Constant)),
        { Kind: SsaValueKind.Parameter, Parameter: { } n } => $"arg {n} of the caller",
        _ => "_",
    };

    // An Analyzed site with something resolved to list.
    private static bool Resolved(SsaSinkFact fact) =>
        fact.Status == SsaSiteStatus.Analyzed
        && (IsConstant(fact.Receiver) || fact.Arguments.Any(IsConstant) || TargetResolved(fact.Target));

    private static bool TargetResolved(SsaReflectionTarget? target) => target is not null && (IsConstant(target.Type) || IsConstant(target.Member));

    private static bool IsConstant(SsaValue? value) => value?.Kind is SsaValueKind.Constant or SsaValueKind.OneOf;

    private static SsaSiteSummary Site(SsaSinkFact fact)
    {
        var arguments = fact.Arguments.Select(Value).ToList();
        if (fact.ArgumentCount > fact.Arguments.Count)
            arguments.Add("…");
        var call = $"{fact.Site.CalleeKey}({string.Join(", ", arguments)})" + (IsConstant(fact.Receiver) ? $" on {Value(fact.Receiver)}" : string.Empty);
        return new(Name(fact.Site.NodeId), Name(fact.Site.Callee), fact.Site.Capability, fact.Site.Offset, Bound(call, MaxCallChars),
            fact.Target is { } target ? Target(target) : null, fact.Merged);
    }

    private static SsaTargetSummary Target(SsaReflectionTarget target)
    {
        var text = $"{target.Kind} {Value(target.Type)}"
            + (target.Member is { } member ? $" :: {Value(member)}" : string.Empty)
            + (target.Assembly is { } assembly ? $" in assembly {Value(assembly)}" : string.Empty);
        return new(target.Kind, Bound(text, MaxCallChars), [.. target.Candidates.Take(MaxCandidates).Select(Name)], target.CandidatesTotal,
            target.CandidatesGap is { } gap ? Name(gap) : null);
    }

    // A constant as source would spell it. String text and Type names (attacker-named metadata) are both quoted with an
    // inner quote escaped, so no constant reads as two arguments or forges a clause (the worker already doubled
    // backslashes). Int, Float and Null text is the worker's own rendering.
    private static string Constant(SsaConstant constant) => constant.Kind switch
    {
        SsaConstantKind.String => Text(constant, "string "),
        SsaConstantKind.Type => $"typeof({Text(constant, "type ")})",
        SsaConstantKind.Null => "null",
        _ => constant.Text,
    };

    // Quoted text. A cut text keeps its hash suffix outside the quotes, and one cut to the suffix alone (past the text
    // budget) is the suffix after `kind`, never an empty literal. Only a tail that is exactly the worker's suffix is
    // split off; anything else is quoted whole.
    private static string Text(SsaConstant constant, string kind) =>
        constant.Cut && cutSuffix.Match(constant.Text) is { Success: true } suffix
            ? (suffix.Index == 0 ? kind : Quoted(constant.Text[..suffix.Index])) + suffix.Value
            : Quoted(constant.Text);

    private static string Quoted(string text) => "\"" + text.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    // Attacker-authored text, escaped for display (idempotent on the worker's escaped text), then bounded.
    private static string Name(string? text) => Bound(text, ReachabilitySummary.MaxNameChars);

    private static string Bound(string? text, int maxChars) => Reachability.BoundNameTo(UntrustedText.Escape(text), maxChars);
    #endregion

    #region Fields
    /// <summary>Resolved sites listed per folder.</summary>
    public const int MaxSitesPerFolder = 100;

    /// <summary>Resolved sites listed per package.</summary>
    public const int MaxSites = 1_000;

    /// <summary>Chars of a rendered call or target kept whole.</summary>
    public const int MaxCallChars = 1_024;

    /// <summary>Candidate names listed per target.</summary>
    public const int MaxCandidates = 8;

    // UntrustedText's suffix, exactly, at the end of the text.
    private static readonly Regex cutSuffix = new(@"…\[\+\d+ chars, sha256:[0-9a-f]{8}\]\z", RegexOptions.CultureInvariant);
    #endregion
}
