// Ported from reference/projects/Yara/YaraModels.cs (Camel.DFIR.Toolkits.Models.YaraMatch.ParseAll) —
// user approved copying reference/ into src/ on 2026-07-17 (CLAUDE.md). Adapted for Silvergun: the source
// produced a mutable YaraMatch class carrying a Target path and raw meta/string lines; here the same header
// and detail regexes are mapped onto the Phase-1 immutable POCOs (YaraMatch / YaraStringMatch). The header's
// permissive rule/tags/target shape matches arbitrary prose, so the scan target path is retained (not discarded)
// and returned alongside each match for the caller to validate against the file it actually scanned; rule
// metadata is supplied by YaraRuleIndex (not the CLI's -m output). Detail lines emitted by -s are parsed into
// (identifier, offset) instead of raw strings.

namespace Silvergun.PackageAnalysis.NuGet.Yara;

using System.Globalization;
using System.Text.RegularExpressions;

/// <summary>
/// Parses classic <c>yara</c> CLI stdout into backend-neutral <see cref="YaraMatch"/> POCOs. The output is a
/// sequence of header lines <c>[namespace:]rule [tags] target</c>, each optionally followed by <c>-s</c> detail
/// lines <c>0xOFFSET:$identifier: data</c>. Parsing is defensive — unrecognized lines are ignored — so hostile
/// or truncated output never throws.
/// </summary>
public static class YaraCliOutput
{
    #region Methods
    /// <summary>
    /// Parses the full stdout of a <c>yara</c> scan into zero or more rule hits, each paired with the scan
    /// <c>Target</c> path echoed on its header line. The caller validates the target against the file it actually
    /// scanned before trusting the hit — a permissive header regex otherwise matches arbitrary prose. Never throws.
    /// </summary>
    public static IReadOnlyList<(YaraMatch Match, string Target)> ParseAll(string? output)
    {
        if (string.IsNullOrEmpty(output))
            return Array.Empty<(YaraMatch, string)>();

        var matches = new List<(YaraMatch, string)>();
        string? ns = null;
        var rule = string.Empty;
        var target = string.Empty;
        var tags = Array.Empty<string>();
        var strings = new List<YaraStringMatch>();
        var have = false;

        void Flush()
        {
            if (have)
                matches.Add((new YaraMatch(rule, ns, tags, strings.ToArray()), target));
        }

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Length == 0)
                continue;

            if (Detail.IsMatch(line))
            {
                if (have && TryParseDetail(line, out var sm))
                    strings.Add(sm);
                continue;
            }

            var m = Header.Match(line);
            if (!m.Success)
                continue;

            Flush();   // a new header ends the previous match
            ns = m.Groups["ns"].Success ? m.Groups["ns"].Value : null;
            rule = m.Groups["rule"].Value;
            target = m.Groups["target"].Value;
            strings = new List<YaraStringMatch>();
            have = true;

            var parsedTags = new List<string>();
            foreach (Match b in Bracket.Matches(m.Groups["brackets"].Value))
            {
                var inner = b.Groups[1].Value;
                if (inner.Contains('='))
                    continue;   // a meta bracket (key=value) — metadata comes from YaraRuleIndex, not here
                parsedTags.AddRange(inner.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
            }
            tags = parsedTags.ToArray();
        }

        Flush();
        return matches;
    }

    // Parses a -s detail line "0x<hex>:$<id>: <data>" into an identifier + byte offset. Only the first two
    // colon-delimited fields are used; the trailing matched data is discarded (report is strings-only, ADR 0002).
    private static bool TryParseDetail(string line, out YaraStringMatch match)
    {
        match = default!;
        var parts = line.Split(':', 3);
        if (parts.Length < 2)
            return false;

        var offsetText = parts[0].Trim();
        if (offsetText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            offsetText = offsetText[2..];
        if (!long.TryParse(offsetText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset))
            return false;

        var identifier = parts[1].Trim();
        if (identifier.Length == 0)
            return false;

        match = new YaraStringMatch(identifier, offset);
        return true;
    }
    #endregion

    #region Fields
    // Header: "[namespace:]rule [tags] target". A tags bracket has no '='; a meta bracket does.
    private static readonly Regex Header = new(
        @"^(?:(?<ns>[^:\s\[]+):)?(?<rule>[A-Za-z_]\w*)(?<brackets>(?:\s+\[[^\]]*\])*)\s+(?<target>.+)$",
        RegexOptions.Compiled);

    // Detail line emitted by -s, e.g. "0x6:$a: CamelForensics".
    private static readonly Regex Detail = new(@"^0x[0-9a-fA-F]+:", RegexOptions.Compiled);

    private static readonly Regex Bracket = new(@"\[([^\]]*)\]", RegexOptions.Compiled);
    #endregion
}
