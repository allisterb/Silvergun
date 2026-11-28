namespace Silvergun.PackageAnalysis.NuGet.MsBuild;

using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// Expands MSBuild values the way a reader of the package's own files can (MCP task S4): <c>$(P)</c> to each package
/// definition of <c>P</c> (any condition, so a value has candidates), known properties to an <see cref="MsBuildAnchor"/>,
/// <c>@(I)</c> to the package's own items, and an item transform to its expanded body. Everything else stays as text and
/// marks the value unresolved. Bounded by candidates, depth and a package-wide budget of chars; never throws.
/// </summary>
public sealed class MsBuildExpander
{
    #region Constructors
    /// <summary>
    /// <paramref name="properties"/> and <paramref name="items"/>: every definition in the package's files, by name
    /// (case-insensitive), with the package-relative name of the file that defines it.
    /// </summary>
    public MsBuildExpander(string packageId, IReadOnlyDictionary<string, List<(string Value, string File)>> properties,
        IReadOnlyDictionary<string, List<(string Value, string File)>> items, long budgetChars = DefaultBudgetChars, IReadOnlySet<string>? dropped = null,
        bool anyProperty = false)
    {
        this.dropped = dropped ?? new HashSet<string>();
        this.anyProperty = anyProperty;
        this.properties = properties;
        this.items = items;
        budget = budgetChars;
        pkgProperty = "Pkg" + packageId.Replace('.', '_').Replace('-', '_');
    }
    #endregion

    #region Properties
    /// <summary>NuGet's <c>Pkg&lt;Id&gt;</c> property for this package, which points at its root.</summary>
    public string PkgProperty => pkgProperty;

    /// <summary>The budget ran out: values after that point were left unexpanded (and unresolved).</summary>
    public bool BudgetSpent { get; private set; }

    /// <summary>
    /// How many times a value was cut short: candidates or definitions past a cap, an over-long value, or a value's own
    /// budget. Each cut value is unresolved; a pass with cuts is incomplete.
    /// </summary>
    public int Cuts { get; private set; }
    #endregion

    #region Methods
    /// <summary>The candidate expansions of <paramref name="value"/> as written in <paramref name="file"/> (package-relative).</summary>
    public IReadOnlyList<(string Text, bool Unresolved)> Expand(string value, string file)
    {
        (valueBudget, valueSpent) = (MaxValueBudgetChars, false);
        return ExpandText(value, file, 0, []);
    }

    /// <summary>
    /// Every path of an expanded list value (split on <c>;</c>), normalized. <paramref name="relativeDir"/>: the package
    /// directory a relative path is relative to (an <c>Import</c> or a task assembly is the declaring file's), else the project.
    /// </summary>
    public static IReadOnlyList<MsBuildPath> Paths(string expanded, bool unresolved, string? relativeDir = null) =>
        [.. SplitList(expanded).Select(p => Normalize(p, unresolved, relativeDir))];

    /// <summary><paramref name="expanded"/> as a task receives it, with anchors shown as <c>{name}</c>: for text matching.</summary>
    public static string Display(string expanded) => Unescape(Shown(expanded));

    /// <summary>One expanded path: its anchor, the rest normalized, and its climbs above the anchor.</summary>
    public static MsBuildPath Normalize(string expanded, bool unresolved, string? relativeDir = null)
    {
        var t = expanded.Trim().Trim('"', '\'').Trim();
        MsBuildAnchor anchor;
        string rest;
        if (t.Length > 1 && t[0] == Mark && t.IndexOf(Mark, 1) is var close and > 0 && Enum.TryParse<MsBuildAnchor>(t[1..close], true, out var marked))
            (anchor, rest) = (marked, t[(close + 1)..]);
        else if (t.Length > 2 && t[0] == '%' && t.IndexOf('%', 1) is var end and > 1 && environment.TryGetValue(t[1..end], out var env))
            (anchor, rest) = (env, t[(end + 1)..]);
        else if (t.StartsWith("~/", StringComparison.Ordinal) || t.StartsWith("~\\", StringComparison.Ordinal))
            (anchor, rest) = (MsBuildAnchor.Home, t[1..]);
        else if (t.StartsWith('/') || t.StartsWith('\\') || (t.Length > 1 && char.IsAsciiLetter(t[0]) && t[1] == ':'))
            (anchor, rest) = (MsBuildAnchor.Absolute, t);
        else if (t.StartsWith("$(", StringComparison.Ordinal) || t.StartsWith("@(", StringComparison.Ordinal) || t.StartsWith("%(", StringComparison.Ordinal))
            (anchor, rest) = (MsBuildAnchor.Unknown, t);
        else if (relativeDir is not null)
            (anchor, rest) = (MsBuildAnchor.Package, relativeDir + "/" + t);
        else
            (anchor, rest) = (MsBuildAnchor.Project, t);

        var stray = rest.Contains(Mark);
        rest = Unescape(Shown(rest));
        var segments = new List<string>();
        var climbs = 0;
        foreach (var s in rest.Split('/', '\\'))
        {
            if (s.Length == 0 || s == ".")
                continue;
            if (s == "..")
            {
                // Climbing over a segment Silvergun could not resolve lands somewhere it cannot say (S4 review C4).
                if (segments.Count > 0 && Gap(segments[^1]))
                    stray = true;
                if (segments.Count > 0)
                    segments.RemoveAt(segments.Count - 1);
                else
                    climbs++;
                continue;
            }
            segments.Add(s);
        }
        var path = string.Join('/', segments);
        return new(anchor, path, climbs, unresolved || Gap(path) || stray);
    }

    // Whether text holds a reference Silvergun left unexpanded; a scalar ($(Configuration)) is a segment, not a gap.
    private static bool Gap(string text)
    {
        var gaps = scalarReference.Replace(text, "");
        return gaps.Contains("$(", StringComparison.Ordinal) || gaps.Contains("@(", StringComparison.Ordinal) || gaps.Contains("%(", StringComparison.Ordinal);
    }

    /// <summary>
    /// The anchored paths inside an expanded command line: from each anchor to its closing quote when it is quoted, else to
    /// the first space or shell separator.
    /// </summary>
    public static IEnumerable<MsBuildPath> AnchoredPaths(string expandedCommand, bool unresolved)
    {
        var at = 0;
        while ((at = expandedCommand.IndexOf(Mark, at)) >= 0 && expandedCommand.IndexOf(Mark, at + 1) is var close and > 0)
        {
            var quote = at > 0 && expandedCommand[at - 1] is '"' or '\'' ? expandedCommand[at - 1] : '\0';
            var end = close + 1;
            while (end < expandedCommand.Length && (quote != '\0' ? expandedCommand[end] != quote : !IsCommandBreak(expandedCommand[end])) && expandedCommand[end] != Mark)
                end++;
            yield return Normalize(expandedCommand[at..end], unresolved);
            at = end;
        }
    }

    /// <summary>The first word of an expanded command, as rows show it: an anchored path's display, else the word, bounded.</summary>
    public static string? Program(string expandedCommand)
    {
        var t = expandedCommand.TrimStart();
        if (t.Length == 0)
            return null;
        var quote = t[0] is '"' or '\'' ? t[0] : '\0';
        var start = quote == '\0' ? 0 : 1;
        var end = start;
        while (end < t.Length && (quote != '\0' ? t[end] != quote : !char.IsWhiteSpace(t[end])))
            end++;
        var word = t[start..end];
        var shown = word.Contains(Mark) ? Normalize(word, false).Display : word;
        return shown.Length > MaxProgramChars ? shown[..MaxProgramChars] : shown;
    }

    /// <summary><paramref name="expanded"/> with each anchor shown as <c>{name}</c>, for display and text matching.</summary>
    public static string Shown(string expanded)
    {
        if (!expanded.Contains(Mark))
            return expanded;
        var sb = new StringBuilder(expanded.Length);
        var i = 0;
        while (i < expanded.Length)
        {
            if (expanded[i] == Mark && expanded.IndexOf(Mark, i + 1) is var close and > 0)
            {
                var name = expanded[(i + 1)..close];
                sb.Append('{').Append(Enum.TryParse<MsBuildAnchor>(name, true, out var anchor) ? MsBuildPath.Name(anchor) : name).Append('}');
                i = close + 1;
                continue;
            }
            sb.Append(expanded[i++]);
        }
        return sb.ToString();
    }

    /// <summary>Items of an MSBuild list (<c>;</c>-separated), trimmed, empty ones dropped.</summary>
    public static IEnumerable<string> SplitList(string value) =>
        value.Split(';').Select(s => s.Trim()).Where(s => s.Length > 0);

    private IReadOnlyList<(string Text, bool Unresolved)> ExpandText(string s, string file, int depth, HashSet<string> active)
    {
        // Every text expanded is package text (a value, a definition, an argument): none may carry the mark (S4 tests).
        // Too long to expand: charged and cut before any pass over it (S4 review round 4, C2); its raw text is matched elsewhere.
        if (s.Length > MaxValueChars)
        {
            Cuts++;
            Spend(CallChars);
            return [(GapText, true)];
        }
        s = Sanitize(s);
        // A call's own work (its set, its match table) is charged too, so the budget follows the real cost (S4 tests).
        if (!Spend(s.Length + CallChars))
            return [(s, true)];
        List<Candidate> results = [new()];
        var literal = new StringBuilder();
        // Every '(' matched in one pass: a rescan per reference made unclosed "$(" runs quadratic (S4 review C1).
        var matches = Matches(s);
        var i = 0;
        while (i < s.Length)
        {
            if (i + 1 < s.Length && s[i + 1] == '(' && s[i] is '$' or '@' or '%' && matches[i + 1] is var close and > 0)
            {
                var inner = s[(i + 2)..close];
                IReadOnlyList<(string, bool)> parts = s[i] switch
                {
                    '$' => ExpandProperty(inner, file, depth, active),
                    '@' => ExpandItem(inner, file, depth, active),
                    // Metadata stays as text, and is a gap: even %(Filename) can be ".." (S4 review round 2, C1).
                    _ => [(s[i..(close + 1)], true)],
                };
                Append(results, literal);
                results = Product(results, parts);
                i = close + 1;
                continue;
            }
            literal.Append(s[i++]);
        }
        Append(results, literal);
        return [.. results.Select(c => (c.Text.ToString(), c.Unresolved))];
    }

    private IReadOnlyList<(string Text, bool Unresolved)> ExpandProperty(string inner, string file, int depth, HashSet<string> active)
    {
        // Once a budget is spent a reference costs nothing more: no definition is walked or hashed (S4 review round 4, C2/S2).
        if (valueSpent || budget < 0)
            return [(GapText, true)];
        if (inner.StartsWith('['))
            return ExpandFunction(inner, file, depth, active);
        var name = Identifier(inner);
        if (name.Length == 0 || name.Length != inner.Length)
            return [("$(" + First(ExpandText(inner, file, depth + 1, active)) + ")", true)];

        var dir = file.Contains('/') ? file[..file.LastIndexOf('/')] : "";
        var fileName = file[(file.LastIndexOf('/') + 1)..];
        if (name.Equals("MSBuildThisFileDirectory", StringComparison.OrdinalIgnoreCase) || name.Equals("MSBuildThisFileDirectoryNoRoot", StringComparison.OrdinalIgnoreCase))
            return [(Anchor(MsBuildAnchor.Package) + "/" + dir + (dir.Length > 0 ? "/" : ""), false)];
        if (name.Equals("MSBuildThisFileFullPath", StringComparison.OrdinalIgnoreCase))
            return [(Anchor(MsBuildAnchor.Package) + "/" + file, false)];
        if (name.Equals("MSBuildThisFile", StringComparison.OrdinalIgnoreCase))
            return [(fileName, false)];
        if (name.Equals("MSBuildThisFileName", StringComparison.OrdinalIgnoreCase))
            return [(System.IO.Path.GetFileNameWithoutExtension(fileName), false)];
        if (name.Equals("MSBuildThisFileExtension", StringComparison.OrdinalIgnoreCase))
            return [(System.IO.Path.GetExtension(fileName), false)];
        // $(Pkg<Id>) is NuGet's, set only when empty: a package's own definition counts too (S4 review round 5, W).
        (string Text, bool Unresolved)? builtIn = name.Equals(pkgProperty, StringComparison.OrdinalIgnoreCase) ? (Anchor(MsBuildAnchor.Package) + "/", false)
            : anchors.TryGetValue(name, out var known) ? (Anchor(known.Anchor) + known.Suffix, false)
            : scalars.Contains(name) ? ("$(" + name + ")", false)
            : null;
        // MSBuild's reserved properties cannot be set; any other may be, by the package, and then its value counts too (S4 review C5).
        // A name a task sets unseen (dropped) counts as defined, so its built-in reading is never the only one (S4 review round 3, C1).
        var unseen = dropped.Contains(name) || anyProperty;
        var defined = (properties.TryGetValue(name, out var definitions) || unseen) && !Reserved(name);
        definitions ??= [];
        if (!defined)
            return [builtIn ?? ("$(" + name + ")", true)];
        // A reference to a property inside its own definition is its earlier value, which is usually empty.
        if (active.Contains(name))
            return [builtIn ?? ("", false)];
        if (depth >= MaxDepth)
            return [("$(" + name + ")", true)];

        // The last definition is the one MSBuild keeps when every condition holds, so the latest come first (S4 review C6).
        var nested = new HashSet<string>(active, StringComparer.OrdinalIgnoreCase) { name };
        var all = definitions.AsEnumerable().Reverse().SelectMany(d => ExpandText(d.Value, d.File, depth + 1, nested)).Distinct().ToList();
        if (builtIn is { } b)
            all.Insert(0, b);
        // Definitions the package had past the cap, or a value a task sets unseen, could be the one MSBuild keeps (S4 tests).
        if (unseen)
            all.Add(("$(" + name + ")", true));
        if (all.Count <= MaxCandidates)
            return all;
        Cuts++;
        return [.. all.Take(MaxCandidates - 1), ("$(" + name + ")", true)];
    }

    /// <summary>Whether a property is one of MSBuild's reserved ones, which a package cannot set.</summary>
    public static bool Reserved(string name) => reserved.Contains(name);

    /// <summary>Whether a package that sets <paramref name="name"/> overrides a place or name Silvergun otherwise reads as known.</summary>
    public static bool Overrides(string name) => !Reserved(name) && (anchors.ContainsKey(name) || scalars.Contains(name));

    private IReadOnlyList<(string Text, bool Unresolved)> ExpandItem(string inner, string file, int depth, HashSet<string> active)
    {
        var name = Identifier(inner);
        var rest = inner[name.Length..].TrimStart();
        if (name.Length > 0 && rest.StartsWith("->", StringComparison.Ordinal))
        {
            // A transform: each item's value has the shape of its body; the metadata in it stays unresolved.
            var body = rest[2..].TrimStart();
            var q = body.Length > 0 ? body[0] : '\0';
            var bodyEnd = q is '\'' or '"' ? body.IndexOf(q, 1) : -1;
            if (bodyEnd < 0)
                return [("@(" + inner + ")", true)];
            // Its body's metadata is a gap: ExpandText marks it unresolved.
            return ExpandText(body[1..bodyEnd], file, depth + 1, active);
        }
        if (name.Length == 0 || rest.Length > 0 || !items.TryGetValue(name, out var definitions) || depth >= MaxDepth)
            return [("@(" + inner + ")", true)];
        var expanded = definitions.Select(d => ExpandText(d.Value, d.File, depth + 1, active)).ToList();
        return [(string.Join(';', expanded.Select(First)), dropped.Contains(name) || expanded.Any(e => e.Count != 1 || e[0].Unresolved))];
    }

    // `[Type]::Method(args)`: the path functions are evaluated on their expanded arguments; any other stays as text.
    private IReadOnlyList<(string Text, bool Unresolved)> ExpandFunction(string inner, string file, int depth, HashSet<string> active)
    {
        var typeEnd = inner.IndexOf(']');
        var open = inner.IndexOf('(');
        if (typeEnd < 0 || open < typeEnd || !inner.EndsWith(')') || MatchParen(inner, open) != inner.Length - 1
            || !inner.AsSpan(typeEnd + 1).StartsWith("::"))
            return [("$(" + First(ExpandText(inner, file, depth + 1, active)) + ")", true)];
        var type = inner[1..typeEnd].Trim();
        var method = inner[(typeEnd + 3)..open].Trim();
        var args = SplitArguments(inner[(open + 1)..^1]).Select(a => ExpandText(Unquote(a), file, depth + 1, active)).ToList();
        var first = args.Select(a => a.Count > 0 ? a[0] : ("", true)).ToList();
        var unresolved = first.Any(a => a.Item2);
        var texts = first.Select(a => a.Item1).ToList();
        string? value = (type.ToLowerInvariant(), method.ToLowerInvariant()) switch
        {
            ("msbuild", "normalizedirectory") => Combine(texts) + "/",
            ("msbuild", "normalizepath") => Combine(texts),
            ("msbuild", "ensuretrailingslash") when texts.Count == 1 => texts[0] + "/",
            ("system.io.path", "combine") => Combine(texts),
            ("system.io.path", "getfullpath") when texts.Count == 1 => texts[0],
            _ => null,
        };
        return value is null
            ? [("$([" + type + "]::" + method + "(" + string.Join(", ", texts) + "))", true)]
            : [(value, unresolved)];
    }

    // Path.Combine's rule: a later rooted (or anchored) part starts the path again.
    private static string Combine(IReadOnlyList<string> parts)
    {
        var sb = new StringBuilder();
        foreach (var p in parts.Where(p => p.Length > 0))
        {
            if (p[0] is '/' or '\\' or Mark || (p.Length > 1 && p[1] == ':'))
                sb.Clear();
            else if (sb.Length > 0 && sb[^1] is not ('/' or '\\'))
                sb.Append('/');
            sb.Append(p);
        }
        return sb.ToString();
    }

    private void Append(List<Candidate> results, StringBuilder literal)
    {
        if (literal.Length == 0)
            return;
        var text = literal.ToString();
        literal.Clear();
        foreach (var c in results)
            Add(c, text, false);
    }

    // Each left candidate followed by each right one. One right candidate is appended in place; more copy the left, and
    // the copy is charged, so the budget is the true cost (S4 review round 2, W1).
    private List<Candidate> Product(List<Candidate> left, IReadOnlyList<(string Text, bool Unresolved)> right)
    {
        if (right.Count == 1)
        {
            foreach (var c in left)
                Add(c, right[0].Text, right[0].Unresolved);
            return left;
        }
        var product = new List<Candidate>();
        foreach (var l in left)
            foreach (var r in right)
            {
                if (product.Count >= MaxCandidates)
                {
                    // Candidates past the cap are not seen: the last kept one says so (S4 review C6).
                    Cuts++;
                    product[^1].Unresolved = true;
                    return product;
                }
                if (!Spend(l.Text.Length))
                {
                    l.Unresolved = true;
                    return [.. product, l];
                }
                var copy = new Candidate { Unresolved = l.Unresolved };
                copy.Text.Append(l.Text);
                Add(copy, r.Text, r.Unresolved);
                product.Add(copy);
            }
        return product.Count == 0 ? [new() { Unresolved = true }] : product;
    }

    // Appends `text` within MaxExpandedChars; a cut is counted, so it never reads as whole (S4 review round 2, C3).
    private void Add(Candidate c, string text, bool unresolved)
    {
        c.Unresolved |= unresolved;
        var room = MaxExpandedChars - c.Text.Length;
        var take = Math.Min(room, text.Length);
        if (!Spend(take + 1))
        {
            c.Unresolved = true;
            return;
        }
        c.Text.Append(text, 0, Math.Max(0, take));
        if (take < text.Length && !c.Cut)
        {
            c.Cut = c.Unresolved = true;
            Cuts++;
        }
    }

    // Charges the package's budget and the value's own, so one value cannot starve the rest (S4 review).
    private bool Spend(long chars)
    {
        // A spent value charges the package nothing more (S4 review round 3, W1).
        if (valueSpent)
            return false;
        budget -= chars;
        valueBudget -= chars;
        if (budget < 0)
        {
            BudgetSpent = true;
            return false;
        }
        if (valueBudget >= 0)
            return true;
        // One value spent is one cut, however many charges it then fails.
        if (!valueSpent)
            Cuts++;
        valueSpent = true;
        return false;
    }

    // For each '(' of `s`, the index of the ')' that closes it outside quotes, else -1; one pass.
    private static int[] Matches(string s)
    {
        var matches = new int[s.Length];
        var open = new Stack<int>();
        var quote = '\0';
        for (var i = 0; i < s.Length; i++)
        {
            matches[i] = -1;
            var c = s[i];
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
            }
            else if (c is '\'' or '`' && open.Count > 0)
                quote = c;
            else if (c == '(')
                open.Push(i);
            else if (c == ')' && open.Count > 0)
                matches[open.Pop()] = i;
        }
        return matches;
    }

    // The index of the ')' closing the '(' at `open`, outside quotes; -1 when there is none.
    private static int MatchParen(string s, int open)
    {
        var depth = 0;
        var quote = '\0';
        for (var i = open; i < s.Length; i++)
        {
            var c = s[i];
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
            }
            else if (c is '\'' or '`' && i > open)
                quote = c;
            else if (c == '(')
                depth++;
            else if (c == ')' && --depth == 0)
                return i;
        }
        return -1;
    }

    // Top-level comma-separated arguments, outside quotes and parentheses.
    private static IEnumerable<string> SplitArguments(string args)
    {
        var (depth, quote, start) = (0, '\0', 0);
        for (var i = 0; i < args.Length; i++)
        {
            var c = args[i];
            if (quote != '\0')
            {
                if (c == quote)
                    quote = '\0';
            }
            else if (c is '\'' or '"' or '`')
                quote = c;
            else if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
            else if (c == ',' && depth == 0)
            {
                yield return args[start..i];
                start = i + 1;
            }
        }
        if (args.Trim().Length > 0)
            yield return args[start..];
    }

    private static string Unquote(string arg)
    {
        var t = arg.Trim();
        return t.Length >= 2 && t[0] is '\'' or '"' or '`' && t[^1] == t[0] ? t[1..^1] : t;
    }

    private static string Identifier(string s)
    {
        var n = 0;
        // A '-' that starts a transform's "->" ends the name.
        while (n < s.Length && (char.IsAsciiLetter(s[n]) || s[n] == '_'
            || (n > 0 && (char.IsAsciiDigit(s[n]) || (s[n] == '-' && !(n + 1 < s.Length && s[n + 1] == '>'))))))
            n++;
        return s[..n];
    }

    // MSBuild's %XX escapes, decoded once, as tasks receive them; a '%(' is metadata, never an escape.
    internal static string Unescape(string s)
    {
        if (!s.Contains('%'))
            return s;
        var sb = new StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
            if (s[i] == '%' && i + 2 < s.Length && char.IsAsciiHexDigit(s[i + 1]) && char.IsAsciiHexDigit(s[i + 2]))
            {
                sb.Append((char)int.Parse(s.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                i += 2;
            }
            else
                sb.Append(s[i]);
        return sb.ToString();
    }

    private static bool IsCommandBreak(char c) => char.IsWhiteSpace(c) || c is '"' or '\'' or '<' or '>' or '|' or '&' or ';' or ',' or '(' or ')';

    private static string First(IReadOnlyList<(string Text, bool Unresolved)> candidates) => candidates.Count > 0 ? candidates[0].Text : "";

    // Package text cannot forge an anchor: the mark is Silvergun's own.
    private static string Sanitize(string value) => value.Replace(Mark, (char)0xFFFD);

    private static string Anchor(MsBuildAnchor anchor) => $"{Mark}{anchor}{Mark}";
    #endregion

    #region Types
    // One candidate expansion being built.
    private sealed class Candidate
    {
        public StringBuilder Text { get; } = new();
        public bool Unresolved { get; set; }
        public bool Cut { get; set; }
    }
    #endregion

    #region Fields
    public const long DefaultBudgetChars = 8L * 1024 * 1024;
    public const int MaxCandidates = 8;
    public const int MaxDepth = 8;
    public const int MaxExpandedChars = 16 * 1024;
    /// <summary>A value longer than this is not expanded: it stays as text, unresolved.</summary>
    public const int MaxValueChars = 64 * 1024;
    /// <summary>The chars one value's expansion may spend of the package's budget.</summary>
    public const long MaxValueBudgetChars = 1024 * 1024;
    private const int MaxProgramChars = 256;
    private const int CallChars = 256;
    // What a value Silvergun gave up on reads as: a gap, never an empty value, which a list would drop and a write would
    // then read as writing nowhere (S4 review round 5, C1).
    private const string GapText = "$(?)";
    // Brackets an anchor inside an expanded value; package text never carries it (Sanitize).
    private const char Mark = (char)0xE000;

    private readonly IReadOnlyDictionary<string, List<(string Value, string File)>> properties;
    private readonly IReadOnlyDictionary<string, List<(string Value, string File)>> items;
    private readonly string pkgProperty;
    private readonly IReadOnlySet<string> dropped;
    private readonly bool anyProperty;
    private long budget;
    private long valueBudget = MaxValueBudgetChars;
    private bool valueSpent;

    // Properties MSBuild, the SDK or the environment set, by what they point into.
    private static readonly Dictionary<string, (MsBuildAnchor Anchor, string Suffix)> anchors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MSBuildProjectDirectory"] = (MsBuildAnchor.Project, "/"),
        ["ProjectDir"] = (MsBuildAnchor.Project, "/"),
        ["MSBuildStartupDirectory"] = (MsBuildAnchor.Project, "/"),
        ["MSBuildProjectFullPath"] = (MsBuildAnchor.Project, "/$(MSBuildProjectFile)"),
        ["ProjectPath"] = (MsBuildAnchor.Project, "/$(MSBuildProjectFile)"),
        ["SolutionDir"] = (MsBuildAnchor.Solution, "/"),
        ["SolutionPath"] = (MsBuildAnchor.Solution, "/$(SolutionFileName)"),
        ["USERPROFILE"] = (MsBuildAnchor.Home, "/"),
        ["HOME"] = (MsBuildAnchor.Home, "/"),
        ["APPDATA"] = (MsBuildAnchor.AppData, "/"),
        ["LOCALAPPDATA"] = (MsBuildAnchor.LocalAppData, "/"),
        ["TEMP"] = (MsBuildAnchor.Temp, "/"),
        ["TMP"] = (MsBuildAnchor.Temp, "/"),
        ["TMPDIR"] = (MsBuildAnchor.Temp, "/"),
        ["windir"] = (MsBuildAnchor.System, "/"),
        ["SystemRoot"] = (MsBuildAnchor.System, "/"),
        ["ProgramFiles"] = (MsBuildAnchor.System, "/"),
        ["ProgramData"] = (MsBuildAnchor.System, "/"),
        ["ProgramW6432"] = (MsBuildAnchor.System, "/"),
        ["OutputPath"] = (MsBuildAnchor.Output, "/"),
        ["OutDir"] = (MsBuildAnchor.Output, "/"),
        ["TargetDir"] = (MsBuildAnchor.Output, "/"),
        ["BaseOutputPath"] = (MsBuildAnchor.Output, "/"),
        ["PublishDir"] = (MsBuildAnchor.Output, "/"),
        ["PackageOutputPath"] = (MsBuildAnchor.Output, "/"),
        ["TargetPath"] = (MsBuildAnchor.Output, "/$(TargetFileName)"),
        ["IntermediateOutputPath"] = (MsBuildAnchor.Intermediate, "/"),
        ["BaseIntermediateOutputPath"] = (MsBuildAnchor.Intermediate, "/"),
        ["MSBuildProjectExtensionsPath"] = (MsBuildAnchor.Intermediate, "/"),
        ["IntDir"] = (MsBuildAnchor.Intermediate, "/"),
        ["NuGetPackageRoot"] = (MsBuildAnchor.NuGetPackages, "/"),
        ["NuGetPackageFolders"] = (MsBuildAnchor.NuGetPackages, "/"),
        ["MSBuildExtensionsPath"] = (MsBuildAnchor.MsBuild, "/"),
        ["MSBuildExtensionsPath32"] = (MsBuildAnchor.MsBuild, "/"),
        ["MSBuildExtensionsPath64"] = (MsBuildAnchor.MsBuild, "/"),
        ["MSBuildBinPath"] = (MsBuildAnchor.MsBuild, "/"),
        ["MSBuildToolsPath"] = (MsBuildAnchor.MsBuild, "/"),
        ["MSBuildSDKsPath"] = (MsBuildAnchor.MsBuild, "/"),
        ["DOTNET_HOST_PATH"] = (MsBuildAnchor.Dotnet, ""),
        ["NetCoreRoot"] = (MsBuildAnchor.Dotnet, "/"),
        ["DOTNET_ROOT"] = (MsBuildAnchor.Dotnet, "/"),
        ["NetCoreTargetingPackRoot"] = (MsBuildAnchor.Dotnet, "/"),
    };

    // `%NAME%` at the start of a command-line path.
    private static readonly Dictionary<string, MsBuildAnchor> environment = new(StringComparer.OrdinalIgnoreCase)
    {
        ["USERPROFILE"] = MsBuildAnchor.Home,
        ["HOME"] = MsBuildAnchor.Home,
        ["HOMEPATH"] = MsBuildAnchor.Home,
        ["APPDATA"] = MsBuildAnchor.AppData,
        ["LOCALAPPDATA"] = MsBuildAnchor.LocalAppData,
        ["TEMP"] = MsBuildAnchor.Temp,
        ["TMP"] = MsBuildAnchor.Temp,
        ["windir"] = MsBuildAnchor.System,
        ["SystemRoot"] = MsBuildAnchor.System,
        ["ProgramFiles"] = MsBuildAnchor.System,
        ["ProgramData"] = MsBuildAnchor.System,
    };

    // Properties whose value is a name, not a place: a path segment, never a reason to call the path unresolved.
    private static readonly HashSet<string> scalars = new(StringComparer.OrdinalIgnoreCase)
    {
        "Configuration", "Platform", "TargetFramework", "TargetFrameworks", "TargetFrameworkIdentifier", "TargetFrameworkVersion", "RuntimeIdentifier",
        "AssemblyName", "TargetName", "TargetFileName", "TargetExt", "MSBuildProjectName", "MSBuildProjectFile", "MSBuildProjectExtension", "ProjectName",
        "RootNamespace", "Version", "PackageId", "PackageVersion", "OS", "MSBuildRuntimeType", "NETCoreSdkRuntimeIdentifier", "SolutionName", "SolutionFileName",
    };

    // A scalar property. Item metadata is never one: even %(Filename) can be ".." (S4 review round 2, C1, measured on MSBuild).
    private static readonly Regex scalarReference = new(
        @"\$\((?:" + string.Join('|', scalars.Select(Regex.Escape)) + @")\)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // MSBuild's reserved properties, which a project cannot set (MSB4004). Not every MSBuild* is: ProjectExtensionsPath,
    // ExtensionsPath(32/64) and SDKsPath can be, measured (S4 review round 2, C2).
    private static readonly HashSet<string> reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "MSBuildProjectDirectory", "MSBuildProjectDirectoryNoRoot", "MSBuildProjectFile", "MSBuildProjectExtension", "MSBuildProjectFullPath",
        "MSBuildProjectName", "MSBuildThisFile", "MSBuildThisFileDirectory", "MSBuildThisFileDirectoryNoRoot", "MSBuildThisFileExtension",
        "MSBuildThisFileFullPath", "MSBuildThisFileName", "MSBuildBinPath", "MSBuildToolsPath", "MSBuildToolsVersion", "MSBuildStartupDirectory",
        "MSBuildNodeCount", "MSBuildLastTaskResult", "MSBuildProgramFiles32", "MSBuildVersion", "MSBuildRuntimeType", "MSBuildFileVersion",
        "MSBuildSemanticVersion", "MSBuildAssemblyVersion", "MSBuildInteractive", "MSBuildProjectDefaultTargets", "MSBuildOverrideTasksPath",
    };
    #endregion
}
