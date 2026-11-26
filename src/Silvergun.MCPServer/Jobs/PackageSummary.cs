namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// <c>summary.json</c>, what <c>get_summary</c> serves (task S1, D10): identity, each pass's status beside its count, the
/// gate, per-assembly capability counts, and highlights. Built in the job child from the typed report, so the server only
/// reads it. Every package-derived string is <c>{"untrusted": …}</c> (D6.2). A count that can be zero because nothing was
/// read is <c>null</c>, with the reason beside it. The whole object fits <see cref="BudgetChars"/>: lists shrink, and
/// <c>truncated</c> says so, until it does.
/// </summary>
public static class PackageSummary
{
    #region Methods
    /// <summary>The summary, with every free-text reason and caveat stripped of <paramref name="hostPaths"/> (D6.5) before it is escaped.</summary>
    public static JsonObject Build(PackageCapabilityReport report, JobGate gate, JobDepth depth, IReadOnlySet<IndicatorCategory> gatingIndicators,
        IReadOnlyList<(string Path, string Label)> hostPaths)
    {
        for (var cap = MaxListItems; ; cap = cap / 2)
        {
            var summary = Build(report, gate, depth, gatingIndicators, hostPaths, cap);
            if (cap == 0 || summary.ToJsonString(JobProtocol.JsonOptions).Length <= BudgetChars)
                return summary;
        }
    }

    private static JsonObject Build(PackageCapabilityReport report, JobGate gate, JobDepth depth, IReadOnlySet<IndicatorCategory> gating,
        IReadOnlyList<(string Path, string Label)> hostPaths, int cap)
    {
        string? R(string? text) => text is null ? null : HostPaths.Reduce(text, hostPaths);
        var files = report.Assemblies.Where(a => !a.NotInventoried).ToList();
        var analyzed = files.Where(a => a.Report is not null).ToList();
        var indicators = report.Assemblies
            .SelectMany(a => (a.Indicators?.Findings ?? []).Where(f => gating.Contains(f.Category)).Select(f => (a, f)))
            .ToList();
        var lists = new[] { files.Count, report.YaraFindings.Count, report.ScriptFindings.Count, indicators.Count, report.NativeBinaries.Count,
            report.PackagingAnomalies.Count, report.Vulnerabilities.Count, gate.Caveats.Count };

        return new JsonObject
        {
            ["package"] = new JsonObject
            {
                ["id"] = U(report.Package.Id, ShortChars),
                ["version"] = U(report.Package.Version, ShortChars),
                ["authors"] = report.Package.Authors is { } authors ? U(authors, ShortChars) : null,
                ["dependencies"] = report.Package.Dependencies.Count,
            },
            ["analyzedAt"] = report.AnalyzedAt.UtcDateTime.ToString("O"),
            ["depth"] = JobStore.DepthName(depth),
            ["gate"] = new JsonObject
            {
                ["strictExitCode"] = gate.StrictExitCode,
                ["defaultExitCode"] = gate.DefaultExitCode,
                ["strictReasons"] = new JsonArray([.. gate.StrictReasons.Select(r => JsonValue.Create(r))]),
                ["complete"] = gate.Complete,
                ["caveats"] = new JsonArray([.. gate.Caveats.Take(cap).Select(c => U(R(c)!, ReasonChars))]),
                ["caveatsTotal"] = gate.Caveats.Count,
            },
            ["passes"] = new JsonObject
            {
                ["assemblies"] = new JsonObject
                {
                    ["files"] = files.Count,
                    ["analyzed"] = analyzed.Count,
                    ["notAnalyzed"] = files.Count - analyzed.Count,
                    ["notExtracted"] = report.Assemblies.Count(a => a.NotInventoried),
                    ["methodsTotal"] = analyzed.Sum(a => a.Report!.MethodsTotal),
                    ["methodsSkipped"] = analyzed.Sum(a => a.Report!.MethodsSkipped),
                },
                ["scripts"] = Pass(Name(report.ScriptScanStatus), report.ScriptScanStatus != ScriptScanStatus.NotRun, report.ScriptFindings.Count, R(report.ScriptScanUnavailableReason),
                    ("files", report.Scripts.Count)),
                ["yara"] = Pass(Name(report.YaraScanStatus), report.YaraScanStatus != Silvergun.PackageAnalysis.NuGet.Yara.YaraScanStatus.NotRun, report.YaraFindings.Count, R(report.YaraUnavailableReason)),
                ["native"] = Pass(Name(report.NativeBinaryScanStatus), report.NativeBinaryScanStatus != NativeBinaryScanStatus.NotRun, report.NativeBinaries.Count, R(report.NativeBinaryScanUnavailableReason)),
                ["vulnerabilities"] = Pass(Name(report.VulnerabilitiesStatus), report.VulnerabilitiesStatus == Silvergun.Intel.VulnerabilityScanStatus.Completed, report.Vulnerabilities.Count, null),
                ["packagingAnomalies"] = new JsonObject { ["count"] = report.PackagingAnomalies.Count },
                ["reachability"] = new JsonObject { ["status"] = Name(report.ReachabilityStatus) },
            },
            ["assembliesTotal"] = files.Count,
            ["assemblies"] = new JsonArray([.. files.Take(cap).Select(a => Assembly(a, R))]),
            ["highlights"] = new JsonObject
            {
                ["yara"] = Items(report.YaraFindings, cap, y => new JsonObject
                {
                    ["rule"] = U(y.RuleName, ShortChars),
                    ["family"] = y.MalwareFamily is { } family ? U(family, ShortChars) : null,
                    ["path"] = U(y.RelativePath, PathChars),
                }),
                ["scripts"] = Items(report.ScriptFindings, cap, s => new JsonObject
                {
                    ["ruleId"] = U(s.RuleId, ShortChars),
                    ["severity"] = U(s.Severity, ShortChars),
                    ["source"] = Name(s.Source),
                    ["path"] = U(s.RelativePath, PathChars),
                    ["line"] = s.StartLine,
                    ["occurrences"] = s.Occurrences,
                }),
                ["gatingIndicators"] = Items(indicators, cap, x => new JsonObject
                {
                    ["category"] = Name(x.f.Category),
                    ["value"] = U(x.f.Value, ShortChars),
                    ["assembly"] = U(x.a.Assembly.RelativePath, PathChars),
                }),
                ["native"] = Items(report.NativeBinaries, cap, n => new JsonObject
                {
                    ["path"] = U(n.RelativePath, PathChars),
                    ["format"] = Name(n.Format),
                    ["kind"] = Name(n.Kind),
                    ["code"] = Name(n.Code),
                }),
                ["anomalies"] = Items(report.PackagingAnomalies, cap, p => new JsonObject
                {
                    ["category"] = Name(p.Category),
                    ["entry"] = U(p.EntryName, PathChars),
                }),
                ["vulnerabilities"] = Items(report.Vulnerabilities, cap, v => new JsonObject
                {
                    ["id"] = U(v.Id, ShortChars),
                    ["severity"] = v.Severity is { } severity ? U(severity, ShortChars) : null,
                    ["package"] = U(v.PackageId, ShortChars),
                }),
            },
            ["truncated"] = lists.Any(n => n > cap),
        };
    }

    // One assembly: what it holds, or why nothing was read, beside counts that are then null rather than 0 (D10).
    private static JsonObject Assembly(AssemblyScanResult a, Func<string?, string?> reduce) => new()
    {
        ["path"] = U(a.Assembly.RelativePath, PathChars),
        ["tfm"] = a.Assembly.TargetFramework is { } tfm ? U(tfm, ShortChars) : null,
        ["role"] = Name(a.Assembly.Role),
        ["loaded"] = a.Report is not null,
        ["reason"] = reduce(a.SkipReason) is { } reason ? U(reason, ReasonChars) : null,
        ["capabilityCount"] = a.Report?.Findings.Count,
        ["capabilities"] = a.Report is { } r
            ? new JsonObject(r.Findings.GroupBy(f => f.Capability).OrderBy(g => g.Key).Select(g => KeyValuePair.Create(Name(g.Key), (JsonNode?)g.Count())))
            : null,
        ["methodsSkipped"] = a.Report?.MethodsSkipped,
        ["indicatorCount"] = a.Indicators?.Findings.Count,
        ["obfuscationCount"] = a.Obfuscation?.Findings.Count,
    };

    // A pass's status, with its count only when the pass ran (null otherwise), and its reason when it did not complete.
    private static JsonObject Pass(string status, bool ran, int count, string? reason, params (string Name, int Value)[] extra)
    {
        var pass = new JsonObject { ["status"] = status, ["findings"] = ran ? count : null };
        foreach (var (name, value) in extra)
            pass[name] = value;
        if (reason is not null)
            pass["reason"] = U(reason, ReasonChars);
        return pass;
    }

    private static JsonArray Items<T>(IEnumerable<T> items, int cap, Func<T, JsonObject> item) => new([.. items.Take(cap).Select(item)]);

    private static JsonObject U(string text, int maxChars) => ToolEnvelope.Untrusted(text, maxChars);

    private static string Name<T>(T value) where T : struct, Enum => JsonNamingPolicy.CamelCase.ConvertName(value.ToString());
    #endregion

    #region Fields
    /// <summary>
    /// The summary's serialized size cap. A tool result carries it twice (structured and text), so this is under half of
    /// <see cref="McpLimits.ResponseBudgetChars"/>, leaving room for the envelope.
    /// </summary>
    public const int BudgetChars = McpLimits.ResponseBudgetChars / 2 - 1_000;

    private const int MaxListItems = 40;
    private const int ShortChars = 120;
    private const int PathChars = 200;
    private const int ReasonChars = 300;
    #endregion
}
