namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

/// <summary>
/// The data-driven capability map (ADR 0019): a pure, <b>model-agnostic</b> function from a
/// <see cref="CanonicalName.ClassificationKey(MethodIdentity)"/> to a <see cref="CapabilityVerdict"/>. It names no
/// CCI or Analysis.Net type, so the raw-CCI scanner and the Analysis.Net call graph classify a given method
/// identically (ADR 0019 decision 3).
/// <para>Line-oriented text, <c>#</c> comments (to end of line), blank lines ignored:</para>
/// <code>
/// capability  &lt;pattern&gt; &lt;CAPABILITY&gt;
/// safe        &lt;pattern&gt;
/// unspecified &lt;pattern&gt;
/// unanalyzed  &lt;pattern&gt;
/// ignore-edge &lt;caller-pattern&gt; &lt;callee-pattern&gt;
/// </code>
/// <para>Three pattern forms, matched against a classification key:</para>
/// <list type="bullet">
/// <item><description><c>Ns.Type</c> — that type, all of its members.</description></item>
/// <item><description><c>Ns.Type.Method</c> — one method, <em>all</em> of its overloads (the key is
/// signature-free by design).</description></item>
/// <item><description><c>Ns.Prefix.*</c> — the subtree: any key starting with <c>Ns.Prefix.</c>.</description></item>
/// </list>
/// <para>
/// <b>Precedence is most-specific-wins</b> — exact type+method, then exact type, then the <em>longest</em>
/// matching subtree prefix — which replaces the order-dependent first-match scan of the original hard-coded
/// catalog. At equal specificity the <b>last entry loaded wins</b>, so an override layered over the built-in map
/// (<see cref="Load"/>'s <c>baseMap</c>) beats it while every entry it does not mention survives.
/// </para>
/// <para>
/// <b>Never throws.</b> A malformed line is skipped with a warning and recorded in <see cref="Stats"/>; the rest
/// of the file still loads, and an override that is wholly unparseable simply leaves the base map in place. A
/// scan must never fail because of the map. Loading is deterministic: the same input yields the same verdicts and
/// the same <see cref="Stats"/>.
/// </para>
/// </summary>
public sealed class CapabilityMap
{
    #region Constructors
    private CapabilityMap(
        Dictionary<string, CapabilityVerdict> exact,
        Dictionary<string, CapabilityVerdict> prefixes,
        IReadOnlyList<(string Caller, string Callee)> ignoredEdges,
        IReadOnlyList<string> rejectedLines)
    {
        this.exact = exact;
        this.prefixes = prefixes;
        this.ignoredEdges = ignoredEdges;

        // Longest prefix first, so the first subtree that matches is the most specific one. Two distinct
        // prefixes of equal length can never match the same key, so the ordinal tie-break is only there to keep
        // the order reproducible across loads.
        orderedPrefixes = prefixes
            .OrderByDescending(p => p.Key.Length)
            .ThenBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => (p.Key, p.Value))
            .ToArray();

        var verdicts = exact.Values.Concat(prefixes.Values).ToArray();
        Stats = new CapabilityMapStats(
            verdicts.Count(v => v.Class == CapabilityClass.Capability),
            verdicts.Count(v => v.Class == CapabilityClass.Safe),
            verdicts.Count(v => v.Class == CapabilityClass.Unspecified),
            verdicts.Count(v => v.Class == CapabilityClass.Unanalyzed),
            ignoredEdges.Count,
            rejectedLines);
    }
    #endregion

    #region Properties
    /// <summary>
    /// The built-in map, parsed once from the embedded <c>Resources/capabilities.cm</c>. Lazy and never throws —
    /// a missing or unreadable resource yields an empty map with the failure recorded in <see cref="Stats"/>.
    /// </summary>
    public static CapabilityMap Default => defaultMap.Value;

    /// <summary>Entry counts by class and the lines rejected while building this map.</summary>
    public CapabilityMapStats Stats { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Parses a map from <paramref name="reader"/>, optionally layered over <paramref name="baseMap"/>: entries
    /// read here replace base entries with the same pattern, and every other base entry survives.
    /// <paramref name="sourceName"/> only labels rejected lines. Never throws — a read failure part-way through
    /// keeps everything parsed so far and is recorded as a reject.
    /// </summary>
    public static CapabilityMap Load(TextReader reader, string sourceName, CapabilityMap? baseMap = null)
    {
        var source = string.IsNullOrWhiteSpace(sourceName) ? UnnamedSource : sourceName;
        var exact = Copy(baseMap?.exact);
        var prefixes = Copy(baseMap?.prefixes);
        var edges = new List<(string Caller, string Callee)>(baseMap?.ignoredEdges ?? []);
        var edgeSet = new HashSet<(string, string)>(edges);
        var rejected = new List<string>(baseMap?.Stats.RejectedLines ?? []);

        void Reject(string reason)
        {
            var entry = $"{source}: {reason}";
            Runtime.Warn("Capability map: ignoring {0}", entry);
            rejected.Add(entry);
        }

        if (reader is null)
            Reject("no map source to read");
        else
            try
            {
                var number = 0;
                for (var line = reader.ReadLine(); line is not null; line = reader.ReadLine())
                {
                    number++;
                    var directive = ParseLine(line);

                    if (directive.Error is { } error)
                        Reject($"({number}): {error}");
                    else if (directive.Edge is { } edge)
                    {
                        if (edgeSet.Add(edge))
                            edges.Add(edge);
                    }
                    else if (directive.Pattern is { } pattern)
                        // A subtree key keeps its trailing dot; an exact key never ends in one, which is what
                        // separates the two indexes.
                        (pattern[^1] == NestingSeparator ? prefixes : exact)[pattern] = directive.Verdict;
                }
            }
            catch (Exception ex)
            {
                Reject($"read failed: {ex.Message}");
            }

        return new CapabilityMap(exact, prefixes, edges, rejected);
    }

    /// <summary>
    /// The most-specific verdict for <paramref name="classificationKey"/> (exact type+method, else exact type,
    /// else the longest matching subtree), or <see cref="CapabilityVerdict.None"/> if nothing matches. A null,
    /// empty or whitespace key yields <see cref="CapabilityVerdict.None"/>. Never throws.
    /// </summary>
    public CapabilityVerdict Classify(string classificationKey)
    {
        if (string.IsNullOrWhiteSpace(classificationKey))
            return CapabilityVerdict.None;

        if (exact.TryGetValue(classificationKey, out var method))
            return method;

        if (DeclaringType(classificationKey) is { } type && exact.TryGetValue(type, out var declaring))
            return declaring;

        foreach (var (prefix, verdict) in orderedPrefixes)
            if (classificationKey.StartsWith(prefix, StringComparison.Ordinal))
                return verdict;

        return CapabilityVerdict.None;
    }

    /// <summary>
    /// Whether an <c>ignore-edge</c> rule suppresses the call edge <paramref name="callerKey"/> →
    /// <paramref name="calleeKey"/>. Both sides accept every pattern form. Parsed and exposed now; the
    /// reachability walk consumes it later. Never throws.
    /// </summary>
    public bool IsIgnoredEdge(string callerKey, string calleeKey) =>
        ignoredEdges.Count > 0 &&
        !string.IsNullOrWhiteSpace(callerKey) && !string.IsNullOrWhiteSpace(calleeKey) &&
        ignoredEdges.Any(e => Matches(e.Caller, callerKey) && Matches(e.Callee, calleeKey));

    // One line: its comment stripped, then split on whitespace. A blank or comment-only line is ignored; an
    // unknown directive, a wrong argument count, a malformed pattern or an unknown capability name is rejected
    // with a reason and never throws.
    private static Directive ParseLine(string line)
    {
        var text = line.IndexOf(CommentMarker) is var comment && comment >= 0 ? line[..comment] : line;
        var tokens = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
            return Directive.Ignored;

        var directive = tokens[0].ToLowerInvariant();
        if (Arity(directive) is not { } arity)
            return Directive.Malformed($"unknown directive '{tokens[0]}'");
        if (tokens.Length != arity)
            return Directive.Malformed($"'{directive}' takes {arity - 1} argument(s), got {tokens.Length - 1}");

        if (Key(tokens[1]) is not { } pattern)
            return Directive.Malformed($"malformed pattern '{tokens[1]}'");

        return directive switch
        {
            CapabilityDirective =>
                capabilityNames.TryGetValue(tokens[2], out var capability)
                    ? new Directive(pattern, new CapabilityVerdict(CapabilityClass.Capability, capability))
                    : Directive.Malformed($"unknown capability '{tokens[2]}'"),
            SafeDirective => new Directive(pattern, new CapabilityVerdict(CapabilityClass.Safe, null)),
            UnspecifiedDirective => new Directive(pattern, new CapabilityVerdict(CapabilityClass.Unspecified, null)),
            UnanalyzedDirective => new Directive(pattern, new CapabilityVerdict(CapabilityClass.Unanalyzed, null)),
            _ => Key(tokens[2]) is { } callee
                    ? new Directive(Edge: (pattern, callee))
                    : Directive.Malformed($"malformed pattern '{tokens[2]}'"),
        };
    }

    // The token count a directive expects (including the directive itself), or null if it is not a directive.
    private static int? Arity(string directive) => directive switch
    {
        CapabilityDirective or IgnoreEdgeDirective => 3,
        SafeDirective or UnspecifiedDirective or UnanalyzedDirective => 2,
        _ => null,
    };

    // The storage key of a pattern: the pattern itself for a type or type+method entry, or the subtree prefix
    // WITH its trailing dot ("System.Net.Sockets.*" -> "System.Net.Sockets.") for a subtree entry. Null when the
    // pattern is malformed — empty, leading-dot, trailing-dot, or with a '*' anywhere but as a trailing ".*".
    private static string? Key(string pattern)
    {
        if (pattern.Length == 0 || pattern[0] == NestingSeparator)
            return null;

        if (pattern.EndsWith(SubtreeSuffix, StringComparison.Ordinal))
            return pattern[..^1] is { Length: > 1 } prefix && !prefix.Contains(Wildcard) ? prefix : null;

        return pattern.Contains(Wildcard) || pattern[^1] == NestingSeparator ? null : pattern;
    }

    // The declaring type of a classification key ("Ns.Type.Method" -> "Ns.Type"), or null if it has no dot to
    // split on. A metadata method name may itself begin with a dot (".ctor"/".cctor"), which renders as
    // "Ns.Type..ctor", so an immediately preceding dot is stepped over rather than left dangling.
    private static string? DeclaringType(string key)
    {
        var last = key.LastIndexOf(NestingSeparator);
        if (last > 0 && key[last - 1] == NestingSeparator)
            last--;
        return last > 0 ? key[..last] : null;
    }

    // Whether a stored pattern key addresses a classification key: a subtree prefix by StartsWith, an exact key
    // by the key itself or by its declaring type.
    private static bool Matches(string pattern, string key) =>
        pattern[^1] == NestingSeparator
            ? key.StartsWith(pattern, StringComparison.Ordinal)
            : key == pattern || DeclaringType(key) == pattern;

    // Reads the built-in map from the embedded resource. Never throws: a missing or unreadable resource yields
    // an empty map whose Stats record why.
    private static CapabilityMap LoadDefault()
    {
        try
        {
            var assembly = typeof(CapabilityMap).Assembly;
            var name = assembly.GetManifestResourceNames()
                .Where(n => n.EndsWith(ResourceSuffix, StringComparison.Ordinal))
                .OrderBy(n => n, StringComparer.Ordinal)
                .FirstOrDefault();

            using var stream = name is null ? null : assembly.GetManifestResourceStream(name);
            if (stream is null)
            {
                Runtime.Warn("Capability map: embedded resource {0} not found; classification is disabled.", ResourceSuffix);
                return Empty([$"{DefaultSourceName}: embedded resource not found"]);
            }

            using var reader = new StreamReader(stream);
            return Load(reader, DefaultSourceName);
        }
        catch (Exception ex)
        {
            Runtime.Warn("Capability map: could not read the embedded map: {0}", ex.Message);
            return Empty([$"{DefaultSourceName}: {ex.Message}"]);
        }
    }

    private static CapabilityMap Empty(IReadOnlyList<string>? rejected = null) =>
        new(new(StringComparer.Ordinal), new(StringComparer.Ordinal), [], rejected ?? []);

    private static Dictionary<string, CapabilityVerdict> Copy(Dictionary<string, CapabilityVerdict>? entries) =>
        entries is null ? new(StringComparer.Ordinal) : new(entries, StringComparer.Ordinal);
    #endregion

    #region Fields
    // Exact type and type+method entries; subtree entries keyed by their prefix (trailing dot included).
    private readonly Dictionary<string, CapabilityVerdict> exact;
    private readonly Dictionary<string, CapabilityVerdict> prefixes;
    private readonly (string Prefix, CapabilityVerdict Verdict)[] orderedPrefixes;
    private readonly IReadOnlyList<(string Caller, string Callee)> ignoredEdges;

    private static readonly Lazy<CapabilityMap> defaultMap = new(LoadDefault, isThreadSafe: true);

    // Capability names are matched case-insensitively; the lookup also rejects the numeric strings
    // Enum.TryParse would otherwise accept, so "capability X 3" is a reject rather than a silent Registry.
    private static readonly Dictionary<string, Capability> capabilityNames =
        Enum.GetValues<Capability>().ToDictionary(c => c.ToString(), c => c, StringComparer.OrdinalIgnoreCase);

    private const string CapabilityDirective = "capability";
    private const string SafeDirective = "safe";
    private const string UnspecifiedDirective = "unspecified";
    private const string UnanalyzedDirective = "unanalyzed";
    private const string IgnoreEdgeDirective = "ignore-edge";

    private const string ResourceSuffix = ".Resources.capabilities.cm";
    private const string DefaultSourceName = "capabilities.cm";
    private const string UnnamedSource = "<map>";
    private const string SubtreeSuffix = ".*";
    private const char NestingSeparator = '.';
    private const char CommentMarker = '#';
    private const char Wildcard = '*';
    #endregion

    #region Child types
    // One parsed line: either a classification entry (Pattern + Verdict), an ignore-edge rule (Edge), a rejection
    // (Error), or nothing at all (a blank or comment-only line).
    private readonly record struct Directive(
        string? Pattern = null,
        CapabilityVerdict Verdict = default,
        (string Caller, string Callee)? Edge = null,
        string? Error = null)
    {
        #region Properties
        public static Directive Ignored => default;
        #endregion

        #region Methods
        public static Directive Malformed(string reason) => new(Error: reason);
        #endregion
    }
    #endregion
}
