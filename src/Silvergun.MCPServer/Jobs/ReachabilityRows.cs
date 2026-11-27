namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Graph;

/// <summary>
/// The reachability row file (task S2's <c>get_reachability</c>), from the report's <see cref="ReachabilitySummary"/>: per
/// folder, one <c>folder</c> row (outcome, class verdicts with their reasons, notes, SSA outcome and counts), then its
/// <c>statement</c> rows (a root class reaching a capability, with an example path), then its <c>ssaSite</c> rows (a sink
/// call with the argument values SSA resolved). Empty when the job did not run reachability. Statement wording is
/// Silvergun's; every name, node id, reason and value is <c>{"untrusted": …}</c>.
/// </summary>
public static class ReachabilityRows
{
    #region Methods
    /// <summary>Writes the rows; returns the index entry, with the pass's status and what the summary already dropped.</summary>
    public static JsonObject Write(string dir, PackageCapabilityReport report, IReadOnlyList<(string Path, string Label)> hostPaths)
    {
        JsonObject R(string text) => U(HostPaths.Reduce(text, hostPaths), ReasonChars);
        using var writer = new RowWriter(dir, JobProtocol.ReachabilityFile);
        var summary = report.Reachability;
        foreach (var row in (summary?.Folders ?? []).SelectMany(f => Rows(f, R)))
            if (!writer.Add(row, filterKeys, Text(row["type"]) == "folder" ? WithoutReasons : null))
                break;
        writer.Commit();

        var entry = writer.Index();
        entry["status"] = Name(report.ReachabilityStatus);
        if (summary is not null)
        {
            entry["statementsDropped"] = summary.StatementsDropped;
            entry["sitesDropped"] = summary.Folders.Sum(f => f.Ssa?.SitesDropped ?? 0);
        }
        return entry;
    }

    private static IEnumerable<JsonObject> Rows(FolderReachSummary f, Func<string, JsonObject> reason)
    {
        var folder = new JsonObject
        {
            ["type"] = "folder",
            ["folder"] = U(f.Folder, PathChars),
            ["role"] = Name(f.Role),
            ["outcome"] = Name(f.Outcome),
            ["classes"] = new JsonArray([.. f.Classes.Select(c => (JsonNode)new JsonObject
            {
                ["class"] = Name(c.Class),
                ["roots"] = c.Roots,
                ["verdict"] = Name(c.Verdict),
                ["reasons"] = new JsonArray([.. c.Reasons.Take(MaxReasons).Select(r => (JsonNode)reason(r))]),
                ["reasonsTotal"] = c.Reasons.Count,
            })]),
            ["notes"] = new JsonArray([.. f.Notes.Take(MaxReasons).Select(n => (JsonNode)reason(n))]),
            ["notesTotal"] = f.Notes.Count,
            ["statements"] = f.Statements.Count,
        };
        if (f.Reason is { } why)
            folder["reason"] = reason(why);
        if (f.SameAs is { } sameAs)
            folder["sameAs"] = U(sameAs, PathChars);
        if (f.Ssa is { } ssa)
        {
            var node = new JsonObject
            {
                ["outcome"] = Name(ssa.Outcome),
                ["incomplete"] = ssa.Incomplete(),
                ["counts"] = ssa.Counts is null ? null : JsonSerializer.SerializeToNode(ssa.Counts, JobProtocol.JsonOptions),
                ["sites"] = ssa.Sites.Count,
                ["sitesDropped"] = ssa.SitesDropped,
                ["signals"] = ssa.Signals is null ? null : JsonSerializer.SerializeToNode(ssa.Signals, JobProtocol.JsonOptions),
            };
            if (ssa.Reason is { } ssaWhy)
                node["reason"] = reason(ssaWhy);
            folder["ssa"] = node;
        }
        yield return folder;

        foreach (var s in f.Statements)
            yield return new JsonObject
            {
                ["type"] = "statement",
                ["folder"] = U(f.Folder, PathChars),
                ["kind"] = Name(s.Kind),
                ["class"] = Name(s.Class),
                ["capability"] = s.Capability is { } c ? Name(c) : null,
                ["with"] = s.With is { } w ? Name(w) : null,
                ["direct"] = s.Direct,
                ["roots"] = s.Roots,
                ["text"] = s.Text,
                ["example"] = s.Example is { } e ? new JsonObject
                {
                    ["evidence"] = Name(e.Evidence),
                    ["hops"] = new JsonArray([.. e.Hops.Select(h => (JsonNode)U(h, NameChars))]),
                    ["hiddenHops"] = e.HiddenHops,
                    ["unseen"] = e.Unseen,
                } : null,
            };

        foreach (var site in f.Ssa?.Sites ?? [])
            yield return new JsonObject
            {
                ["type"] = "ssaSite",
                ["folder"] = U(f.Folder, PathChars),
                ["capability"] = Name(site.Capability),
                ["caller"] = U(site.Caller, NameChars),
                ["callee"] = U(site.Callee, NameChars),
                ["offset"] = site.Offset,
                ["call"] = U(site.Call, CallChars),
                ["target"] = site.Target is { } t ? new JsonObject
                {
                    ["kind"] = Name(t.Kind),
                    ["text"] = U(t.Text, CallChars),
                    ["candidates"] = new JsonArray([.. t.Candidates.Select(c => (JsonNode)U(c, NameChars))]),
                    ["candidatesTotal"] = t.CandidatesTotal,
                    ["gap"] = t.CandidatesGap is { } gap ? U(gap, ReasonChars) : null,
                } : null,
                ["merged"] = site.Merged,
                ["signals"] = site.Signals is null ? null : new JsonArray([.. site.Signals.Select(g => (JsonNode)Name(g))]),
            };
    }

    // A folder row that no cut fits, with its verdicts kept and its reasons and notes dropped; the totals say how many.
    private static JsonObject WithoutReasons(JsonObject folder)
    {
        foreach (var cls in folder["classes"]!.AsArray().OfType<JsonObject>())
            cls["reasons"] = new JsonArray();
        folder["notes"] = new JsonArray();
        folder["reasonsCut"] = true;
        return folder;
    }

    private static string? Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    private static JsonObject U(string text, int maxChars) => ToolEnvelope.Untrusted(text, maxChars);

    private static string Name<T>(T value) where T : struct, Enum => JsonNamingPolicy.CamelCase.ConvertName(value.ToString());
    #endregion

    #region Fields
    // The summary already bounds names to ReachabilitySummary.MaxNameChars; a kept folder then always leaves room for the rest.
    private const int PathChars = ReachabilitySummary.MaxNameChars;
    private const int NameChars = ReachabilitySummary.MaxNameChars;
    private const int CallChars = 1024;
    private const int ReasonChars = 200;
    private const int MaxReasons = 4;

    // The key get_reachability matches exactly: never cut to fit a row (S2 review C1).
    private static readonly IReadOnlySet<string> filterKeys = new HashSet<string>(StringComparer.Ordinal) { "folder" };
    #endregion
}
