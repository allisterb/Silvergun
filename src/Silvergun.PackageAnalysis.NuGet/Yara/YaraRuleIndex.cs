namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Reflection;
using System.Text.RegularExpressions;

/// <summary>
/// The rule-metadata extracted from a single YARA rule's <c>meta:</c> block (ADR 0016). Neither the classic
/// CLI backend nor the in-process backend reliably surfaces rule metadata (the CLI's <c>-m</c> output is
/// brittle), so Silvergun reads it once from the embedded rule sources here and enriches each finding by rule
/// name. Every field is optional — a rule may declare only some (or none) of these keys.
/// </summary>
public sealed record YaraRuleInfo(
    string? MalwareFamily,
    string? DetectionName,
    string? Category,
    string? Description);

/// <summary>
/// Parses the embedded ReversingLabs + custom <c>.yara</c> sources once into a <c>ruleName → </c>
/// <see cref="YaraRuleInfo"/> lookup, used (Phase 3) to enrich a raw <see cref="YaraMatch"/> into the report
/// DTO <see cref="YaraFinding"/>. ReversingLabs rules carry meta keys <c>malware</c>, <c>tc_detection_name</c>,
/// <c>category</c> and <c>description</c>; those map to the corresponding <see cref="YaraRuleInfo"/> fields.
///
/// Parsing is defensive and <b>never throws</b>: a rule with no <c>meta:</c> block is simply absent from the
/// index (a lookup returns <c>null</c> and the finding keeps its rule name), and a malformed source is skipped.
/// </summary>
public sealed class YaraRuleIndex
{
    #region Constructors
    private YaraRuleIndex(IReadOnlyDictionary<string, YaraRuleInfo> byName) => _byName = byName;
    #endregion

    #region Properties
    /// <summary>The lazily built index over every embedded rule source.</summary>
    public static YaraRuleIndex Shared => shared.Value;

    /// <summary>The number of indexed rules (those that declared a <c>meta:</c> block).</summary>
    public int Count => _byName.Count;
    #endregion

    #region Methods
    /// <summary>Returns the metadata for <paramref name="ruleName"/>, or <c>null</c> when the rule is unknown.</summary>
    public YaraRuleInfo? Lookup(string? ruleName) =>
        !string.IsNullOrEmpty(ruleName) && _byName.TryGetValue(ruleName, out var info) ? info : null;

    /// <summary>Builds an index from every embedded <c>.yara</c> rule source in the given (or this) assembly.</summary>
    public static YaraRuleIndex Build(Assembly? assembly = null)
    {
        var byName = new Dictionary<string, YaraRuleInfo>(StringComparer.Ordinal);
        foreach (var (_, text) in YaraRuleResources.ReadAll(assembly))
            foreach (var (name, info) in ParseSource(text))
                byName[name] = info;   // last definition wins on the rare duplicate rule name
        return new YaraRuleIndex(byName);
    }

    /// <summary>
    /// Parses one <c>.yara</c> source text into <c>(ruleName, metadata)</c> pairs — one per rule that declares a
    /// <c>meta:</c> block. Rules without metadata are omitted. Never throws; unrecognized text yields nothing.
    /// </summary>
    public static IEnumerable<(string Name, YaraRuleInfo Info)> ParseSource(string? text)
    {
        if (string.IsNullOrEmpty(text))
            yield break;

        foreach (Match rule in RuleWithMeta.Matches(text))
        {
            var name = rule.Groups["name"].Value;
            if (name.Length == 0)
                continue;

            var meta = ParseMeta(rule.Groups["meta"].Value);
            yield return (name, new YaraRuleInfo(
                MalwareFamily: Get(meta, "malware"),
                DetectionName: Get(meta, "tc_detection_name"),
                Category: Get(meta, "category"),
                Description: Get(meta, "description")));
        }
    }

    // Extracts every  key = "value"  pair from a rule's meta block into a case-insensitive map. Numeric meta
    // values (e.g. tc_detection_factor) are ignored — the four keys Silvergun surfaces are all string-valued.
    private static Dictionary<string, string> ParseMeta(string metaBlock)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match kv in MetaPair.Matches(metaBlock))
        {
            var key = kv.Groups["key"].Value;
            if (!map.ContainsKey(key))
                map[key] = kv.Groups["val"].Value;
        }
        return map;
    }

    private static string? Get(Dictionary<string, string> meta, string key) =>
        meta.TryGetValue(key, out var v) && v.Length > 0 ? v : null;
    #endregion

    #region Fields
    private readonly IReadOnlyDictionary<string, YaraRuleInfo> _byName;

    private static readonly Lazy<YaraRuleIndex> shared = new(() => Build());

    // A rule declaration with a meta block: "rule NAME [: tags] { ... meta: <meta> (strings:|condition:) ...".
    // [^\{]* consumes the optional ": tags" up to the rule body's opening brace; the lazy .*? then reaches the
    // meta section, whose body runs up to the next section keyword. Rules lacking a meta block do not match.
    private static readonly Regex RuleWithMeta = new(
        @"rule\s+(?<name>[A-Za-z_]\w*)[^\{]*\{.*?\bmeta:\s*(?<meta>.*?)(?:\bstrings:|\bcondition:)",
        RegexOptions.Compiled | RegexOptions.Singleline);

    // A single  key = "value"  pair (value may contain escaped quotes) within a meta block.
    private static readonly Regex MetaPair = new(
        "(?<key>[A-Za-z_]\\w*)\\s*=\\s*\"(?<val>(?:[^\"\\\\]|\\\\.)*)\"",
        RegexOptions.Compiled);
    #endregion
}
