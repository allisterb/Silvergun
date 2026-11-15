namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>Whether a scan's reachability pass ran, and whether every folder and presented class came out decided.</summary>
public enum ReachabilityScanStatus
{
    /// <summary>The pass was not asked for.</summary>
    NotRun,

    /// <summary>Every folder was analysed, nothing failed to load, and no presented class is <see cref="RootClassVerdict.Unknown"/>.</summary>
    Completed,

    /// <summary>Some folder was not analysed, an assembly did not load, a report is partial, or a presented class is Unknown.</summary>
    Incomplete
}

/// <summary>How a <see cref="ReachStatement"/> is presented (<see cref="ReachabilityPresentation"/>).</summary>
public enum ReachStatementKind
{
    /// <summary>A cell R2b measured as discriminating, in the folder roles it triggers in: a signal worth a reviewer's look.</summary>
    Trigger,

    /// <summary>Anything else: true of the package, but common in benign ones.</summary>
    Informational
}

/// <summary>
/// One example path, root first and sink last, bounded to <see cref="ReachabilitySummary.MaxHops"/> hops: the first ones
/// and the last two, <paramref name="HiddenHops"/> left out between. <paramref name="Unseen"/> names what an unseen
/// reach ended in.
/// </summary>
public sealed record ReachExample(ReachEvidence Evidence, IReadOnlyList<string> Hops, int HiddenHops, string? Unseen);

/// <summary>
/// <paramref name="Roots"/> roots of <paramref name="Class"/> reach <paramref name="Capability"/> (null: code the graph
/// cannot see), directly or, when not <paramref name="Direct"/>, only through a delegate or method handle they create.
/// <paramref name="Example"/> is null when the report kept no example with this label. A reach is possible, not proven.
/// </summary>
public sealed record ReachStatement(ReachStatementKind Kind, RootClass Class, Capability? Capability, bool Direct, int Roots, string Text, ReachExample? Example);

/// <summary>A presented class's verdict in one folder, with every reason it is <see cref="RootClassVerdict.Unknown"/>.</summary>
public sealed record ReachClassVerdict(RootClass Class, int Roots, RootClassVerdict Verdict, IReadOnlyList<string> Reasons);

/// <summary>
/// One package folder's reachability, as presented. A folder that was not <see cref="FolderOutcome.Analyzed"/> has a
/// <paramref name="Reason"/> and nothing else. A folder with the same files as an earlier one names it in
/// <paramref name="SameAs"/> and carries no classes, notes or statements of its own. <paramref name="Ssa"/> is present
/// exactly when SSA facts were asked for; it never changes anything else here.
/// </summary>
public sealed record FolderReachSummary(
    string Folder,
    PackageItemRole Role,
    FolderOutcome Outcome,
    string? Reason,
    string? SameAs,
    IReadOnlyList<ReachClassVerdict> Classes,
    IReadOnlyList<string> Notes,
    IReadOnlyList<ReachStatement> Statements,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] FolderSsaSummary? Ssa = null);

/// <summary>
/// A <see cref="PackageReachabilityReport"/> projected for a scan report (<c>docs/agent/tasks/reachability-r3.md</c>):
/// the presented root classes only, worded by <see cref="ReachabilityPresentation"/>, small whatever the package.
/// Every name is escaped and cut to <see cref="MaxNameChars"/>; at most <see cref="MaxStatements"/> statements are kept,
/// triggers first, and <see cref="StatementsDropped"/> counts the rest. <see cref="Complete"/> is false when anything
/// was not analysed or is Unknown, so nothing that was not seen reads clean. Deterministic.
/// </summary>
public sealed record ReachabilitySummary(IReadOnlyList<FolderReachSummary> Folders, int StatementsDropped, bool Complete)
{
    #region Methods
    /// <summary><see cref="ReachabilityScanStatus.Completed"/> or <see cref="ReachabilityScanStatus.Incomplete"/>.</summary>
    public ReachabilityScanStatus Status() => Complete ? ReachabilityScanStatus.Completed : ReachabilityScanStatus.Incomplete;

    /// <summary>The summary of <paramref name="report"/>. Never throws.</summary>
    public static ReachabilitySummary From(PackageReachabilityReport report)
    {
        try
        {
            var byName = report.Folders.Where(f => f?.Folder is not null).GroupBy(f => f.Folder, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
            var folders = report.Folders.Select(f => Summarize(f, byName)).ToArray();
            var all = folders.SelectMany((f, i) => f.Folder.Statements.Select((s, j) => (Folder: i, Index: j, s.Kind))).ToArray();
            var triggers = all.Where(t => t.Kind == ReachStatementKind.Trigger).Take(MaxStatements).ToArray();
            var kept = triggers
                .Concat(all.Where(t => t.Kind != ReachStatementKind.Trigger).Take(MaxStatements - triggers.Length))
                .Select(t => (t.Folder, t.Index))
                .ToHashSet();
            return new(
                SsaSummary.Capped([.. folders.Select((f, i) => f.Folder with { Statements = [.. f.Folder.Statements.Where((_, j) => kept.Contains((i, j)))] })]),
                all.Length - kept.Count,
                folders.All(f => f.Complete));
        }
        catch (Exception ex)
        {
            return Failed($"the reachability summary could not be built: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// The summary of a pass that failed as a whole: Incomplete, with one NotRun folder named "" (the package) carrying
    /// <paramref name="reason"/>, escaped and cut.
    /// </summary>
    internal static ReachabilitySummary Failed(string reason) =>
        new([new(string.Empty, PackageItemRole.Other, FolderOutcome.NotRun, Name(reason), null, [], [], [])], 0, false);

    // One folder with its SSA summary, if asked for. SSA never moves Complete (ssa-facts-s5.md D4), and its own failure
    // costs only its own summary (SsaSummary.Of never throws).
    private static (FolderReachSummary Folder, bool Complete) Summarize(FolderReachability folder, IReadOnlyDictionary<string, FolderReachability> byName)
    {
        var (summary, complete) = SummarizeGraph(folder, byName);
        return (summary with { Ssa = SsaSummary.Of(folder?.Ssa, copy: summary.SameAs is not null) }, complete);
    }

    // One folder, and whether it is complete. A failure here costs only this folder, which then reads not analysed.
    // `byName` finds a SameAs copy's primary: the copy is summarized in full when its trigger role differs (review C1).
    private static (FolderReachSummary Folder, bool Complete) SummarizeGraph(FolderReachability folder, IReadOnlyDictionary<string, FolderReachability> byName)
    {
        try
        {
            var role = NuGetPackage.RoleOf(folder.Folder);
            var triggerRole = TriggerRole(folder);
            // A copy whose role makes other cells triggers than its primary's is no copy for the summary: it is listed in
            // full, so deduplication can never turn a lib trigger into its build-folder primary's information.
            // Only an analysed copy has statements for its role to change, so a not-analysed copy keeps its SameAs.
            var divergent = folder.SameAs is { } primaryName && folder.Outcome == FolderOutcome.Analyzed && folder.Report is not null
                && !(byName.TryGetValue(primaryName, out var primary) && ReachabilityPresentation.SameKinds(triggerRole, TriggerRole(primary)));
            var sameAs = folder.SameAs is null || divergent ? null : Name(folder.SameAs);
            var failed = LoadFailures(folder.LoadFailures);
            if (folder.Outcome != FolderOutcome.Analyzed)
            {
                var reason = folder.Outcome switch
                {
                    FolderOutcome.Crashed => $"the graph worker failed on this folder, so it is unanalysable, and suspect: {folder.Reason ?? "no reason was given"}",
                    FolderOutcome.NothingLoaded => failed ?? "no assembly of the folder loaded",
                    _ => folder.Reason ?? "no reason was given",
                };
                return (new(Name(folder.Folder), role, folder.Outcome, Name(reason), sameAs, [], [], []), false);
            }
            if (folder.Report is not { } report)
            {
                // Analyzed in name only: every class says it is Unknown, so the folder never reads clean on its own.
                var reason = Name(failed is null ? "the folder has no reachability report" : $"the folder has no reachability report; {failed}");
                return (new(Name(folder.Folder), role, folder.Outcome, reason, sameAs, Unknowns(reason), [], []), false);
            }

            // The folder's own causes lead every class's reasons, so the reason cap never hides them (S0 tests).
            var folderReasons = new[] { failed, report.Partial ? $"the report is partial: {report.PartialReason ?? "no reason was given"}" : null }
                .OfType<string>().ToArray();
            var classes = ReachabilityPresentation.Classes
                .Select(cls => report.Classes.FirstOrDefault(s => s.Class == cls) is { } status
                    ? Verdict(cls, status.Roots, folderReasons.Length > 0 ? RootClassVerdict.Unknown : status.Verdict, [.. folderReasons, .. status.Reasons])
                    : Verdict(cls, 0, RootClassVerdict.Unknown, [.. folderReasons, "the report has no verdict for this class"]))
                .ToArray();
            var complete = classes.All(c => c.Verdict is RootClassVerdict.None or RootClassVerdict.Reaches);
            if (sameAs is not null)
                return (new(Name(folder.Folder), role, folder.Outcome, null, sameAs, [], [], []), complete);

            var statements = report.Reaches
                .Where(r => classOrder.ContainsKey(r.Class))
                .SelectMany(r => new[] { (Direct: true, Roots: r.Direct), (Direct: false, Roots: r.Roots - r.Direct) }
                    .Where(l => l.Roots > 0)
                    .Select(l => Statement(r, l.Direct, l.Roots, triggerRole)))
                .OrderBy(s => s.Kind)
                .ThenBy(s => classOrder[s.Class])
                .ThenBy(s => s.Capability is { } c ? (int)c : int.MaxValue)
                .ThenBy(s => !s.Direct)
                .ToArray();
            var notes = divergent
                ? [.. LoadTimeNotes(report), Name($"listed in full because its folder role changes which statements are triggers; same files as {folder.SameAs}")]
                : LoadTimeNotes(report);
            return (new(Name(folder.Folder), role, folder.Outcome, null, null, classes, notes, statements), complete);
        }
        catch (Exception ex)
        {
            var reason = Name($"the folder's reachability summary could not be built: {ex.GetType().Name}: {ex.Message}");
            return (new(Name(folder?.Folder), PackageItemRole.Other, folder?.Outcome ?? FolderOutcome.NotRun, reason, null, Unknowns(reason), [], []), false);
        }
    }

    // The role a folder's statements are judged by: its own, or a member's (review W1: an entry named `lib%2Fnet8.0%2FA.dll`
    // is extracted outside lib/ but installed into it, and RoleOf %-unescapes the member's path; the path is already
    // display-escaped, which can only make a member look like lib, the fail-safe direction).
    private static PackageItemRole TriggerRole(FolderReachability folder) =>
        ReachabilityPresentation.TriggerRole(NuGetPackage.RoleOf(folder.Folder), folder.Assemblies.OfType<string>().Select(NuGetPackage.RoleOf));

    // Every presented class Unknown for one reason, already escaped and bounded.
    private static ReachClassVerdict[] Unknowns(string reason) =>
        [.. ReachabilityPresentation.Classes.Select(c => new ReachClassVerdict(c, 0, RootClassVerdict.Unknown, [reason]))];

    private static ReachStatement Statement(CapabilityReach reach, bool direct, int roots, PackageItemRole role)
    {
        var labelled = reach.Examples.Where(e => e.Direct == direct).ToArray();
        // Only the label's own examples name what was unseen: another label's path is not evidence for this one.
        var sink = reach.Capability?.ToString()
            ?? (labelled.Select(UnseenOf).Distinct().ToArray() is { Length: > 0 } kinds
                ? $"code the graph cannot see ({string.Join(", ", kinds)})"
                : "code the graph cannot see");
        return new(ReachabilityPresentation.KindOf(reach.Class, reach.Capability, direct, role), reach.Class, reach.Capability, direct, roots,
            ReachabilityPresentation.Text(reach.Class, sink, direct),
            labelled.Length > 0 ? Example(labelled[0], reach.Capability is null) : null);
    }

    // The path's first MaxHops - 2 hops and its last two. The report's own path keeps more of both ends, so this is the
    // real path's first and last hops, and HiddenHops counts the rest of its whole length.
    private static ReachExample Example(ReachPath path, bool unseen)
    {
        var hops = path.Hops.Count <= MaxHops ? path.Hops : [.. path.Hops.Take(MaxHops - 2), .. path.Hops.TakeLast(2)];
        return new(path.Evidence, [.. hops.Select(h => Name(h.NodeId))], Math.Max(0, path.Length - hops.Count), unseen ? UnseenOf(path) : null);
    }

    private static string UnseenOf(ReachPath path) =>
        ReachabilityPresentation.Unseen(path.EndsInOpacity, path.Hops.Count > 0 && path.Hops[^1].Assembly is not null);

    private static ReachClassVerdict Verdict(RootClass cls, int roots, RootClassVerdict verdict, IReadOnlyList<string> reasons)
    {
        var distinct = reasons.Select(Name).Distinct(StringComparer.Ordinal).ToArray();
        return new(cls, roots, verdict,
            distinct.Length <= MaxReasons ? distinct : [.. distinct.Take(MaxReasons), $"and {distinct.Length - MaxReasons} more reason(s)"]);
    }

    // The LoadTime class's module-initializer gaps, said plainly: they are invisible to the model, not absent.
    private static IReadOnlyList<string> LoadTimeNotes(ReachabilityReport report)
    {
        var reasons = report.Classes.FirstOrDefault(s => s.Class == RootClass.LoadTime)?.Reasons ?? [];
        var hidden = reasons.Count(r => r.EndsWith(": " + GraphFacts.ModuleInitializerGap, StringComparison.Ordinal));
        var unreadable = reasons.Count(r => r.EndsWith(": " + GraphFacts.ModuleUnreadableGap, StringComparison.Ordinal));
        return new[]
        {
            hidden > 0 ? $"load-time code present, not visible to the model ({hidden} assembly(ies) with a module initializer)" : null,
            unreadable > 0 ? $"whether load-time code is present is unknown ({unreadable} assembly(ies) with unreadable module metadata)" : null,
        }.OfType<string>().ToArray();
    }

    private static string? LoadFailures(IReadOnlyList<PackageGraphLoadFailure> failures) =>
        failures.Count == 0 ? null
        : $"{failures.Count} assembly(ies) did not load: {string.Join(", ", failures.Take(MaxListed).Select(f => f.RelativePath))}"
          + (failures.Count > MaxListed ? $", and {failures.Count - MaxListed} more" : string.Empty);

    // Attacker-authored text, escaped (bidi, zero-width, Tag-block and control characters made visible), then bounded.
    private static string Name(string? text) => Reachability.BoundNameTo(YaraPathSafety.Escape(text), MaxNameChars);
    #endregion

    #region Fields
    /// <summary>The statements a summary keeps over the whole package.</summary>
    public const int MaxStatements = 2000;

    /// <summary>The hops an example keeps: the first <c>MaxHops - 2</c> and the last two.</summary>
    public const int MaxHops = 8;

    /// <summary>The chars of a name or reason a summary keeps whole (<see cref="Reachability.BoundNameTo"/>).</summary>
    public const int MaxNameChars = 256;

    /// <summary>The reasons a class verdict lists before summarizing the rest.</summary>
    public const int MaxReasons = 8;

    private const int MaxListed = 3;

    private static readonly Dictionary<RootClass, int> classOrder =
        ReachabilityPresentation.Classes.Select((c, i) => (c, i)).ToDictionary(p => p.c, p => p.i);
    #endregion
}
