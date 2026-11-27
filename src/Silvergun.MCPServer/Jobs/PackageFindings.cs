namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>The finding kinds <c>get_findings</c> serves (task S2), one row file each.</summary>
public enum FindingKind { Capabilities, Indicators, HiddenContent, Scripts, Yara, Native, Anomalies, Vulnerabilities }

/// <summary>
/// The finding row files (task S2), built in the job child from the typed report, so the server never reads
/// <c>report.json</c> (and never sees its absolute paths). Every package-derived string is <c>{"untrusted": …}</c> (D6.2);
/// a file is named by its <c>list_files</c> path when the inventory lists it, else by the report's form, and
/// <c>pathForm: "report"</c> says so. Each kind's index entry carries its pass's status beside its row count (D10).
/// </summary>
public static class PackageFindings
{
    #region Methods
    public static string Name(FindingKind kind) => kind == FindingKind.HiddenContent ? "hidden-content" : kind.ToString().ToLowerInvariant();

    public static bool TryParse(string? name, out FindingKind kind)
    {
        kind = default;
        if (name is null)
            return false;
        foreach (var k in Enum.GetValues<FindingKind>())
            if (string.Equals(Name(k), name.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                kind = k;
                return true;
            }
        return false;
    }

    /// <summary>Whether the kind's rows each belong to one assembly (so <c>assembly</c> can filter them).</summary>
    public static bool PerAssembly(FindingKind kind) => kind is FindingKind.Capabilities or FindingKind.Indicators or FindingKind.HiddenContent;

    public static string FileName(FindingKind kind) => $"findings-{Name(kind)}.jsonl";

    /// <summary>Writes every kind's rows into <paramref name="dir"/>; returns their index entries, by kind name.</summary>
    public static JsonObject Write(string dir, PackageCapabilityReport report, IReadOnlySet<IndicatorCategory> gating, PackagePaths paths,
        IReadOnlyList<(string Path, string Label)> hostPaths)
    {
        JsonObject? R(string? reason) => reason is null ? null : U(HostPaths.Reduce(reason, hostPaths), ReasonChars);
        var files = report.Assemblies.Where(a => !a.NotInventoried).ToList();
        JsonObject Assemblies(Func<AssemblyScanResult, bool> analyzed, Func<AssemblyScanResult, bool>? truncated = null)
        {
            var pass = new JsonObject { ["assemblies"] = files.Count, ["analyzed"] = files.Count(analyzed), ["notAnalyzed"] = files.Count(a => !analyzed(a)) };
            if (truncated is not null)
                pass["truncatedAssemblies"] = files.Count(truncated);
            return pass;
        }
        JsonObject Status<T>(T status, string? reason, params (string Key, int Value)[] extra) where T : struct, Enum
        {
            var pass = new JsonObject { ["status"] = EnumName(status) };
            foreach (var (key, value) in extra)
                pass[key] = value;
            if (R(reason) is { } r)
                pass["reason"] = r;
            return pass;
        }

        var index = new JsonObject();
        void Emit(FindingKind kind, JsonObject pass, IEnumerable<JsonObject> rows)
        {
            using var writer = new RowWriter(dir, FileName(kind));
            foreach (var row in rows)
                if (!writer.Add(row, filterKeys, WithoutLists))
                    break;
            writer.Commit();
            var entry = writer.Index();
            entry["pass"] = pass;
            index[Name(kind)] = entry;
        }

        // Methods the per-method guard skipped are not in the list: their count sits beside it (D10).
        var capabilities = Assemblies(a => a.Report is not null);
        capabilities["methodsTotal"] = files.Sum(a => a.Report?.MethodsTotal ?? 0);
        capabilities["methodsSkipped"] = files.Sum(a => a.Report?.MethodsSkipped ?? 0);
        Emit(FindingKind.Capabilities, capabilities,
            from a in report.Assemblies where a.Report is not null
            from f in a.Report!.Findings
            select WithPath(new JsonObject
            {
                ["capability"] = EnumName(f.Capability),
                ["kind"] = EnumName(f.Kind),
                ["callerType"] = U(f.CallerType, NameChars),
                ["callerMethod"] = U(f.CallerMethod, NameChars),
                ["calledApi"] = U(f.CalledApi, NameChars),
            }, "assembly", paths.OfFile(a.Assembly.FullPath), a.Assembly.RelativePath));

        Emit(FindingKind.Indicators, Assemblies(a => a.Indicators is not null, a => a.Indicators?.Truncated == true),
            from a in report.Assemblies where a.Indicators is not null
            from f in a.Indicators!.Findings
            select WithPath(new JsonObject
            {
                ["category"] = EnumName(f.Category),
                ["gates"] = gating.Contains(f.Category),
                ["value"] = U(f.Value, NameChars),
                ["excerpt"] = U(f.Excerpt, NameChars),
                ["callerType"] = U(f.CallerType, NameChars),
                ["callerMethod"] = U(f.CallerMethod, NameChars),
                ["occurrences"] = f.Occurrences,
            }, "assembly", paths.OfFile(a.Assembly.FullPath), a.Assembly.RelativePath));

        Emit(FindingKind.HiddenContent, Assemblies(a => a.Obfuscation is not null, a => a.Obfuscation?.Truncated == true),
            from a in report.Assemblies where a.Obfuscation is not null
            from f in a.Obfuscation!.Findings
            select WithPath(new JsonObject
            {
                ["kind"] = EnumName(f.Kind),
                ["detectedAs"] = U(f.DetectedAs, ShortChars),
                ["source"] = EnumName(f.Source),
                ["callerType"] = U(f.CallerType, NameChars),
                ["callerMethod"] = U(f.CallerMethod, NameChars),
                ["encodedLength"] = f.EncodedLength,
                ["entropy"] = double.IsFinite(f.Entropy) ? Math.Round(f.Entropy, 3) : (double?)null,
            }, "assembly", paths.OfFile(a.Assembly.FullPath), a.Assembly.RelativePath));

        Emit(FindingKind.Scripts, Status(report.ScriptScanStatus, report.ScriptScanUnavailableReason, ("files", report.Scripts.Count)),
            report.ScriptFindings.Select(s => WithPath(new JsonObject
            {
                ["ruleId"] = U(s.RuleId, ShortChars),
                ["ruleName"] = U(s.RuleName, NameChars),
                ["severity"] = U(s.Severity, ShortChars),
                ["confidence"] = U(s.Confidence, ShortChars),
                ["source"] = EnumName(s.Source),
                ["line"] = s.StartLine,
                ["occurrences"] = s.Occurrences,
                ["excerpt"] = s.Excerpt is { } excerpt ? U(excerpt, ExcerptChars) : null,
                ["tags"] = List(s.Tags),
                ["tagsTotal"] = s.Tags?.Count ?? 0,
            }, "path", paths.OfReported(s.RelativePath), s.RelativePath)));

        Emit(FindingKind.Yara, Status(report.YaraScanStatus, report.YaraUnavailableReason),
            report.YaraFindings.Select(y => WithPath(new JsonObject
            {
                ["rule"] = U(y.RuleName, ShortChars),
                ["namespace"] = y.Namespace is { } ns ? U(ns, ShortChars) : null,
                ["family"] = y.MalwareFamily is { } family ? U(family, ShortChars) : null,
                ["detection"] = y.DetectionName is { } detection ? U(detection, ShortChars) : null,
                ["category"] = y.Category is { } category ? U(category, ShortChars) : null,
                ["tags"] = List(y.Tags),
                ["tagsTotal"] = y.Tags?.Count ?? 0,
            }, "path", paths.OfReported(y.RelativePath), y.RelativePath)));

        Emit(FindingKind.Native, Status(report.NativeBinaryScanStatus, report.NativeBinaryScanUnavailableReason),
            report.NativeBinaries.Select(n => WithPath(new JsonObject
            {
                ["format"] = EnumName(n.Format),
                ["kind"] = EnumName(n.Kind),
                ["architecture"] = n.Architecture is { } arch ? U(arch, ShortChars) : null,
                ["code"] = EnumName(n.Code),
                ["role"] = EnumName(n.Role),
                ["size"] = n.Size,
                ["sha256"] = n.Sha256,
                ["dotNetHost"] = EnumName(n.DotNetHost),
                ["bundledFiles"] = n.BundledFiles,
            }, "path", paths.OfReported(n.RelativePath), n.RelativePath)));

        // The entry-name pass always runs; its rows name declared entries, which need not be files.
        Emit(FindingKind.Anomalies, new JsonObject { ["status"] = "completed" },
            report.PackagingAnomalies.Select(p => new JsonObject
            {
                ["category"] = EnumName(p.Category),
                ["entry"] = U(p.EntryName, PathChars),
                ["detail"] = U(p.Detail, NameChars),
            }));

        Emit(FindingKind.Vulnerabilities, Status(report.VulnerabilitiesStatus, null),
            report.Vulnerabilities.Select(v => new JsonObject
            {
                ["id"] = U(v.Id, ShortChars),
                ["aliases"] = List(v.Aliases),
                ["aliasesTotal"] = v.Aliases?.Count ?? 0,
                ["summary"] = v.Summary is { } summary ? U(summary, ExcerptChars) : null,
                ["severity"] = v.Severity is { } severity ? U(severity, ShortChars) : null,
                ["package"] = U(v.PackageId, ShortChars),
                ["version"] = U(v.PackageVersion, ShortChars),
                ["dependency"] = v.IsDependency,
                ["references"] = List(v.References, PathChars),
                ["referencesTotal"] = v.References?.Count ?? 0,
            }));

        return index;
    }

    // `row` with the file it names put first, by its served path, or by the report's form (and said so) when unlisted.
    private static JsonObject WithPath(JsonObject row, string key, string? served, string reported)
    {
        var withPath = new JsonObject { [key] = served is not null ? new JsonObject { ["untrusted"] = served } : U(reported, PathChars) };
        if (served is null)
            withPath["pathForm"] = "report";
        foreach (var (name, value) in row.ToArray())
        {
            row.Remove(name);
            withPath[name] = value;
        }
        return withPath;
    }

    // A row that no cut fits (non-ASCII values at every bound): its short lists emptied, their totals kept, `listsCut` set,
    // so the finding is still listed (S2 tests: a worst-case YARA row).
    private static JsonObject WithoutLists(JsonObject row)
    {
        foreach (var key in row.Where(p => p.Value is JsonArray).Select(p => p.Key).ToArray())
            row[key] = new JsonArray();
        row["listsCut"] = true;
        return row;
    }

    private static JsonArray List(IEnumerable<string>? items, int maxChars = ShortChars) =>
        new([.. (items ?? []).Take(MaxListItems).Select(t => (JsonNode)U(t ?? string.Empty, maxChars))]);

    private static JsonObject U(string text, int maxChars) => ToolEnvelope.Untrusted(text, maxChars);

    private static string EnumName<T>(T value) where T : struct, Enum => JsonNamingPolicy.CamelCase.ConvertName(value.ToString());
    #endregion

    #region Fields
    private const int ShortChars = 120;
    private const int NameChars = 512;
    private const int PathChars = 512;
    private const int ReasonChars = 400;
    private const int ExcerptChars = 1024;
    private const int MaxListItems = 8;

    // The keys get_findings matches exactly: never cut to fit a row (S2 review C1).
    private static readonly IReadOnlySet<string> filterKeys = new HashSet<string>(StringComparer.Ordinal) { "assembly", "path" };
    #endregion
}
