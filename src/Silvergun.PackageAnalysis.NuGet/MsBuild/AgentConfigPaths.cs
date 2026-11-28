namespace Silvergun.PackageAnalysis.NuGet.MsBuild;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

/// <summary>One agent-configuration path, with where it was verified (<c>Resources/AgentConfig/agent_config_paths.json</c>).</summary>
public sealed record AgentConfigPath(string Token, string Agent, string Controls, string Status, string? Source, string? Fetched)
{
    #region Properties
    /// <summary>A directory token ends in <c>/</c>; it names everything under it.</summary>
    public bool IsDirectory => Token.EndsWith('/');

    /// <summary>The token's segments, e.g. <c>[".vscode", "mcp.json"]</c>.</summary>
    public IReadOnlyList<string> Parts => Token.TrimEnd('/').Split('/');
    #endregion
}

/// <summary>
/// The paths that control what an AI coding agent loads, is told or may run (MCP task S4, after
/// <c>agent-config-write-rule.md</c>): a write into one at build time is a channel for agent instructions and tool access.
/// The list is data; matching is on normalized path segments, case-insensitively.
/// </summary>
public static class AgentConfigPaths
{
    #region Properties
    public static IReadOnlyList<AgentConfigPath> All => all.Value;
    #endregion

    #region Methods
    /// <summary>
    /// The tokens <paramref name="segments"/> names. <paramref name="isFolder"/>: the path is a directory, so a file token
    /// cannot name it and a directory token may end it.
    /// </summary>
    public static IReadOnlyList<string> Named(IReadOnlyList<string> segments, bool isFolder) =>
        [.. All.Where(p => Names(p, segments, isFolder)).Select(p => p.Token)];

    /// <summary>The tokens any path-like word of <paramref name="text"/> names, wherever they sit in it.</summary>
    public static IReadOnlyList<string> Mentioned(string text)
    {
        // Each distinct word is split once, and only tokens whose first part one of its segments equals are tried: linear
        // in the text (S4 tests: a 2 MB command took 15 s word by token).
        var found = new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var word in text.Split([' ', '\t', '\r', '\n', '"', '\'', ';', '>', '<', '|', '&', ',', '(', ')', '='], StringSplitOptions.RemoveEmptyEntries))
        {
            if (!seen.Add(word))
                continue;
            var segments = Segments(word);
            // Each candidate token is tried once per word, however often its first part recurs.
            var candidates = new HashSet<AgentConfigPath>();
            foreach (var segment in segments)
                if (byFirstPart.Value.TryGetValue(AsWindowsNames(segment), out var starting))
                    candidates.UnionWith(starting.Where(p => !found.Contains(p.Token)));
            foreach (var p in candidates)
                if (Names(p, segments, isFolder: true) || Names(p, segments, isFolder: false))
                    found.Add(p.Token);
            if (found.Count == All.Count)
                break;
        }
        return [.. All.Where(p => found.Contains(p.Token)).Select(p => p.Token)];
    }

    /// <summary>A path's segments, split on either separator, empty ones dropped.</summary>
    public static IReadOnlyList<string> Segments(string path) => path.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);

    private static bool Names(AgentConfigPath p, IReadOnlyList<string> segments, bool isFolder)
    {
        var parts = p.Parts;
        for (var i = 0; i + parts.Count <= segments.Count; i++)
        {
            if (!parts.Select((part, k) => string.Equals(part, AsWindowsNames(segments[i + k]), StringComparison.OrdinalIgnoreCase)).All(m => m))
                continue;
            var last = i + parts.Count == segments.Count;
            if (p.IsDirectory ? isFolder || !last : !isFolder && last)
                return true;
        }
        return false;
    }

    // The name Windows creates for a segment: an NTFS stream suffix dropped, then trailing dots and spaces (S4 review W4; ADR 0030).
    private static string AsWindowsNames(string segment) =>
        (segment.IndexOf(':') is var colon and > 0 ? segment[..colon] : segment).TrimEnd('.', ' ');

    private static IReadOnlyList<AgentConfigPath> Load()
    {
        var assembly = typeof(AgentConfigPaths).Assembly;
        var name = assembly.GetManifestResourceNames().Single(n => n.EndsWith(".AgentConfig.agent_config_paths.json", StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var document = JsonDocument.Parse(stream);
        return [.. document.RootElement.GetProperty("paths").EnumerateArray().Select(e => new AgentConfigPath(
            e.GetProperty("token").GetString()!,
            e.GetProperty("agent").GetString()!,
            e.GetProperty("controls").GetString()!,
            e.GetProperty("status").GetString()!,
            e.TryGetProperty("source", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null,
            e.TryGetProperty("fetched", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() : null))];
    }
    #endregion

    #region Fields
    private static readonly Lazy<IReadOnlyList<AgentConfigPath>> all = new(Load);

    // The tokens by their first part, case-insensitively, so a segment finds the tokens it could start.
    private static readonly Lazy<Dictionary<string, AgentConfigPath[]>> byFirstPart = new(() =>
        All.GroupBy(p => p.Parts[0], StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase));
    #endregion
}
