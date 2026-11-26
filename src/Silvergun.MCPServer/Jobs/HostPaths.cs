namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>
/// Keeps host paths out of what agents read (task D6.5). Analysis messages quote the files they opened, which live under
/// the job directory, the temp directory or the user's profile. <see cref="Reduce"/> replaces each known directory with a
/// label, longest first; the package's content root becomes nothing, so a file reads as its package-relative path.
/// </summary>
public static class HostPaths
{
    #region Methods
    /// <summary>The prefixes a job child knows: the content root, the bundle root, <c>files/</c>, the job directory, then the machine's.</summary>
    public static IReadOnlyList<(string Path, string Label)> ForJob(string jobDir, string filesDir, string? contentRoot) =>
        [.. new (string?, string)[]
        {
            (contentRoot is null ? null : contentRoot + Path.DirectorySeparatorChar, ""),
            (filesDir + "-bundles", "<bundles>"),
            (filesDir, "<files>"),
            (jobDir, "<job>"),
        }.Where(p => p.Item1 is { Length: > 0 }).Select(p => (p.Item1!, p.Item2)).Concat(Machine())];

    /// <summary>The prefixes the server knows: its cache root, then the machine's.</summary>
    public static IReadOnlyList<(string Path, string Label)> ForServer(string cacheRoot) => [(cacheRoot, "<cache>"), .. Machine()];

    /// <summary>
    /// <paramref name="text"/> with every known prefix replaced by its label, longest prefix first, case-insensitively on
    /// Windows. Both spellings are replaced: as written, and with backslashes doubled (as a lossless escape writes them).
    /// A prefix matches only as a whole path: not preceded by a word character or a separator, and (unless it ends with
    /// one) followed by a separator, a quote, whitespace or the end. So <c>/tmp</c> never touches <c>lib/tmp.dll</c>
    /// (S1 review round 2, W1).
    /// </summary>
    public static string Reduce(string text, IReadOnlyList<(string Path, string Label)> known)
    {
        var options = RegexOptions.CultureInvariant | (OperatingSystem.IsWindows() ? RegexOptions.IgnoreCase : RegexOptions.None);
        foreach (var (path, label) in known.OrderByDescending(k => k.Path.Length))
            // As a file:/// URI (scheme included), in the \\?\ form, as written, with backslashes doubled, and with forward slashes.
            foreach (var spelling in new[] { "file:///" + path.Replace('\\', '/').TrimStart('/'), @"\\?\" + path, path, path.Replace("\\", "\\\\"), path.Replace('\\', '/') }.Distinct())
            {
                var after = spelling.EndsWith('/') || spelling.EndsWith('\\') ? "" : @"(?=[\\/""'\s.,;:)\]}]|$)";
                text = Regex.Replace(text, @"(?<![\w/\\])" + Regex.Escape(spelling) + after, label.Replace("$", "$$"), options, MatchTimeout);
            }
        return text;
    }

    /// <summary>
    /// <see cref="Reduce"/> applied in place to the free text of a served summary only: every string under a
    /// <c>reason</c> or <c>caveats</c> key. Package paths and names elsewhere are evidence and are never rewritten.
    /// </summary>
    public static JsonNode? ReduceReasons(JsonNode? node, IReadOnlyList<(string Path, string Label)> known)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(p => p.Key).ToArray())
                    if (key is "reason" or "caveats")
                    {
                        if (Reduced(obj[key], known) is { } value)
                            obj[key] = value;
                        else
                            ReduceAll(obj[key], known);
                    }
                    else
                        ReduceReasons(obj[key], known);
                return obj;
            case JsonArray array:
                foreach (var item in array)
                    ReduceReasons(item, known);
                return array;
            default:
                return node;
        }
    }

    /// <summary>
    /// <paramref name="node"/> with <see cref="Reduce"/> applied to every string leaf, in place: only string values are
    /// replaced, and containers stay where they are (a node cannot be re-assigned under its own parent).
    /// </summary>
    public static JsonNode? ReduceAll(JsonNode? node, IReadOnlyList<(string Path, string Label)> known)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(p => p.Key).ToArray())
                    if (Reduced(obj[key], known) is { } value)
                        obj[key] = value;
                    else
                        ReduceAll(obj[key], known);
                return obj;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                    if (Reduced(array[i], known) is { } value)
                        array[i] = value;
                    else
                        ReduceAll(array[i], known);
                return array;
            default:
                return Reduced(node, known) ?? node;
        }
    }

    // A new value for a string leaf, or null when `node` is not one.
    private static JsonValue? Reduced(JsonNode? node, IReadOnlyList<(string Path, string Label)> known) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? JsonValue.Create(Reduce(s, known)) : null;

    // The temp directory and the user's profile, without trailing separators; a root ("/", "C:\") is never one.
    private static IEnumerable<(string, string)> Machine() =>
        new[] { (Path.TrimEndingDirectorySeparator(Path.GetTempPath()), "<temp>"), (Runtime.UserHomeDir, "<home>") }
            .Where(p => p.Item1.Length > 0 && Path.GetPathRoot(p.Item1) is { } root && Path.TrimEndingDirectorySeparator(root) != p.Item1);
    #endregion

    #region Fields
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(1);
    #endregion
}
