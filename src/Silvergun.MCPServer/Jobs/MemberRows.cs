namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// The member and string row files (task S3), from one walk of every assembly the capability pass read, in the job child:
/// each method with its token, flags and the findings that name it, and each distinct <c>ldstr</c> constant per method. The
/// walk also gives each capability, indicator and hidden-content finding its <see cref="CallerTokens"/>. It streams: a
/// method's strings are written and dropped as it is read, and only the evidence a finding of the same caller name could
/// use is kept, within <see cref="MaxEvidence"/> (S3 review C1, C2).
/// </summary>
public sealed class MemberRows
{
    #region Constructors
    private MemberRows(JsonObject members, JsonObject strings, Dictionary<object, (uint[] First, int Total)> tokens)
    {
        Members = members;
        Strings = strings;
        this.tokens = tokens;
    }
    #endregion

    #region Properties
    /// <summary>The members list's index entry, with the walk's pass.</summary>
    public JsonObject Members { get; }

    /// <summary>The strings list's index entry, with the same pass.</summary>
    public JsonObject Strings { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Walks the assemblies, writes both row files into <paramref name="dir"/>, and keeps each finding's caller tokens.
    /// <paramref name="maxEvidence"/> and <paramref name="maxNarrowing"/> are the package's budgets (tests spend them).
    /// </summary>
    public static MemberRows Write(string dir, PackageCapabilityReport report, PackagePaths paths, long maxEvidence = MaxEvidence, long maxNarrowing = MaxNarrowing)
    {
        var tokens = new Dictionary<object, (uint[] First, int Total)>(ReferenceEqualityComparer.Instance);
        var (read, notRead, unreadable, incomplete) = (0, 0, 0, 0);
        var budget = new Budget { Evidence = maxEvidence, Narrowing = maxNarrowing };
        var assemblies = report.Assemblies.Where(a => a.Report is not null).ToList();
        using var members = new RowWriter(dir, JobProtocol.MembersFile);
        using var strings = new RowWriter(dir, JobProtocol.StringsFile);
        var (membersOpen, stringsOpen) = (true, true);
        foreach (var a in assemblies)
        {
            var loaded = AssemblyAnalyzer.Load(a.Assembly.FullPath);
            if (!loaded.IsSuccess)
            {
                notRead++;
                continue;
            }
            var served = paths.OfFile(a.Assembly.FullPath);
            JsonObject Located(JsonObject row) => PackageFindings.WithPath(row, "assembly", served, a.Assembly.RelativePath);

            var targets = Targets(a);
            var walked = new List<Walked>();
            var status = new MemberWalkStatus();
            using (var assembly = loaded.Value)
                foreach (var m in AssemblyMembers.Walk(assembly, AssemblyMembers.DefaultMaxMembers, status))
                {
                    foreach (var s in m.Strings)
                        if (stringsOpen)
                            stringsOpen = strings.Add(Located(new JsonObject
                            {
                                ["value"] = U(s.Text, ValueChars),
                                ["length"] = s.Text.Length,
                                ["callerToken"] = Hex(m.Token),
                                ["callerType"] = U(m.Type, NameChars),
                                ["callerMethod"] = U(m.Name, NameChars),
                                ["offset"] = s.Offset,
                                ["occurrences"] = s.Occurrences,
                            }), stringKeys);
                    // The method's strings and calls go no further than its evidence.
                    walked.Add(new(m with { CalledApis = noCalls, Strings = [] }, EvidenceOf(m, targets.GetValueOrDefault((m.Type, m.Name)), budget)));
                }
            read++;
            unreadable += status.Unreadable;
            incomplete += status.Problem is null ? 0 : 1;

            var attribution = Attribute(a, walked, tokens, budget);
            foreach (var w in walked.OrderBy(w => w.Facts.Token))
                if (membersOpen)
                    membersOpen = members.Add(Located(Member(w.Facts, attribution)), memberKeys);
        }
        members.Commit();
        strings.Commit();

        var pass = new JsonObject
        {
            ["assemblies"] = assemblies.Count,
            ["read"] = read,
            ["notRead"] = notRead,
            ["methodsUnreadable"] = unreadable,
        };
        if (incomplete > 0)
            pass["assembliesNotWhole"] = incomplete;
        var membersIndex = members.Index();
        membersIndex["pass"] = pass;
        var stringsIndex = strings.Index();
        stringsIndex["pass"] = pass.DeepClone();
        return new MemberRows(membersIndex, stringsIndex, tokens);
    }

    /// <summary>
    /// The methods <paramref name="finding"/> (a capability, indicator or hidden-content finding of the report) may be in,
    /// as <c>"0x06…"</c>, at most <paramref name="max"/>, and how many there are; null when its assembly was not walked.
    /// </summary>
    public (JsonArray Tokens, int Total)? CallerTokens(object finding, int max) =>
        tokens.TryGetValue(finding, out var found) ? (new([.. found.First.Take(max).Select(t => (JsonNode)Hex(t))]), found.Total) : null;

    /// <summary>A MethodDef token as tools show and take it.</summary>
    public static string Hex(uint token) => $"0x{token:x8}";

    // What the findings of one caller name could be told apart by: the APIs they call, the indicator values and the lengths
    // of the whole constants they come from.
    private static Dictionary<(string Type, string Method), Target> Targets(AssemblyScanResult a)
    {
        var targets = new Dictionary<(string Type, string Method), Target>();
        Target At(string type, string method) => targets.TryGetValue((type, method), out var t) ? t : targets[(type, method)] = new Target();
        foreach (var f in a.Report!.Findings)
            At(f.CallerType, f.CallerMethod).Apis.Add(f.CalledApi);
        foreach (var f in a.Indicators?.Findings ?? [])
            At(f.CallerType, f.CallerMethod).Values.Add(f.Value);
        foreach (var f in a.Obfuscation?.Findings ?? [])
            if (f.Source == HiddenContentSource.Constant)
                At(f.CallerType, f.CallerMethod).Lengths.Add(f.EncodedLength);
        return targets;
    }

    // What of `target` the method carries, or null when there is no target or the evidence budget is spent (then nothing
    // narrows among its overloads). Classifying a method's strings costs what the indicator pass already spent on them.
    private static Evidence? EvidenceOf(MemberFacts m, Target? target, Budget budget)
    {
        if (target is null || budget.Evidence <= 0)
            return null;
        var evidence = new Evidence(
            [.. m.CalledApis.Where(target.Apis.Contains)],
            target.Values.Count == 0 ? [] : [.. m.Strings.SelectMany(s => IndicatorAnalysis.ValuesIn(s.Text)).Where(target.Values.Contains)],
            [.. m.Strings.Select(s => s.Text.Length).Where(target.Lengths.Contains)]);
        budget.Evidence -= 1 + evidence.Apis.Count + evidence.Values.Count + evidence.Lengths.Count;
        return evidence;
    }

    // Each finding's callers, by type and method name as the analyses name them; among overloads, those whose evidence has the
    // finding's, when all were given evidence and the narrowing budget lasts. A field or resource finding has none (W5). A
    // narrowed finding counts toward each of its methods; one that is not counts once toward its whole name, which each of
    // those members adds when its row is written, so counting costs O(1) per finding (S3 review round 2, C1).
    private static Attribution Attribute(AssemblyScanResult a, List<Walked> walked, Dictionary<object, (uint[] First, int Total)> tokens, Budget budget)
    {
        var byName = walked.GroupBy(w => (w.Facts.Type, w.Facts.Name)).ToDictionary(g => g.Key, g => g.ToArray());
        var attribution = new Attribution();
        // `has` reads a member's evidence, so it narrows only when every overload was given some; a flag every member keeps
        // (a P/Invoke, a native export) narrows always. Every pass over the overloads is charged to the narrowing budget first.
        Counts Callers(object finding, string type, string method, Func<Walked, bool>? has, bool byEvidence = true)
        {
            var named = byName.GetValueOrDefault((type, method)) ?? [];
            if (named.Length > 1 && has is not null && (budget.Narrowing -= 2L * named.Length) >= 0
                && (!byEvidence || named.All(w => w.Evidence is not null))
                && named.Where(has).ToArray() is { } narrowed && narrowed.Length > 0 && narrowed.Length < named.Length)
            {
                tokens[finding] = ([.. narrowed.Take(MaxTokens).Select(w => w.Facts.Token)], narrowed.Length);
                return new Counts.Many(narrowed.Select(w => attribution.Of(w.Facts.Token)));
            }
            tokens[finding] = ([.. named.Take(MaxTokens).Select(w => w.Facts.Token)], named.Length);
            return named.Length == 0 ? new Counts() : attribution.OfName((type, method));
        }

        foreach (var f in a.Report!.Findings)
            (f.Kind switch
            {
                ApiCallKind.NativeImport => Callers(f, f.CallerType, f.CallerMethod, w => w.Facts.Special == MemberSpecial.PInvoke, byEvidence: false),
                ApiCallKind.NativeExport => Callers(f, f.CallerType, f.CallerMethod, w => w.Facts.Special == MemberSpecial.NativeExport, byEvidence: false),
                _ => Callers(f, f.CallerType, f.CallerMethod, w => w.Evidence!.Apis.Contains(f.CalledApi)),
            }).AddCapability(f.Capability);
        foreach (var f in a.Indicators?.Findings ?? [])
            Callers(f, f.CallerType, f.CallerMethod, w => w.Evidence!.Values.Contains(f.Value)).AddIndicator();
        foreach (var f in a.Obfuscation?.Findings ?? [])
            if (f.Source is HiddenContentSource.FieldData or HiddenContentSource.Resource)
                tokens[f] = ([], 0);
            else
                Callers(f, f.CallerType, f.CallerMethod, f.Source == HiddenContentSource.Constant ? w => w.Evidence!.Lengths.Contains(f.EncodedLength) : null).AddHiddenContent();
        return attribution;
    }

    private static JsonObject Member(MemberFacts m, Attribution attribution)
    {
        var counts = Counts.Sum(attribution.Own(m.Token), attribution.Named((m.Type, m.Name)));
        var row = new JsonObject
        {
            ["token"] = Hex(m.Token),
            // A filter key, kept whole: bounded as reachability names are, so a whole worst-case assembly path and type still
            // leave room for the rest of the row (S3 tests).
            ["type"] = U(m.Type, TypeChars),
            ["name"] = U(m.Name, NameChars),
            ["id"] = U(m.Id, IdChars),
            ["visibility"] = EnumName(m.Visibility),
        };
        // Flags only when set: a list of thousands of methods pages in fewer calls.
        foreach (var (flag, set) in new[] { ("static", m.IsStatic), ("virtual", m.IsVirtual), ("abstract", m.IsAbstract) })
            if (set)
                row[flag] = true;
        if (m.Special != MemberSpecial.None)
            row["special"] = m.Special == MemberSpecial.PInvoke ? "pinvoke" : EnumName(m.Special);
        row["body"] = EnumName(m.Body);
        row["ilBytes"] = m.IlBytes;
        if (counts?.Capabilities.Count > 0)
            row["capabilities"] = new JsonObject([.. counts.Capabilities.OrderBy(c => c.Key).Select(c => KeyValuePair.Create(EnumName(c.Key), (JsonNode?)c.Value))]);
        if (counts?.Indicators > 0)
            row["indicators"] = counts.Indicators;
        if (counts?.HiddenContent > 0)
            row["hiddenContent"] = counts.HiddenContent;
        return row;
    }

    private static JsonObject U(string text, int maxChars) => ToolEnvelope.Untrusted(text, maxChars);

    private static string EnumName<T>(T value) where T : struct, Enum => JsonNamingPolicy.CamelCase.ConvertName(value.ToString());
    #endregion

    #region Fields
    /// <summary>Evidence entries kept across the package, and overload checks made, before narrowing stops (S3 review C2).</summary>
    public const int MaxEvidence = 1_000_000;
    public const int MaxNarrowing = 20_000_000;

    private const int NameChars = 512;
    private const int TypeChars = 256;
    private const int IdChars = 1024;
    private const int ValueChars = 1024;
    // A finding's served callerTokens are at most 8: no more are kept.
    private const int MaxTokens = 8;

    // The keys list_members and search_strings match exactly or by substring: never cut to fit a row (S2 review C1).
    private static readonly IReadOnlySet<string> memberKeys = new HashSet<string>(StringComparer.Ordinal) { "assembly", "type" };
    private static readonly IReadOnlySet<string> stringKeys = new HashSet<string>(StringComparer.Ordinal) { "assembly" };
    private static readonly IReadOnlySet<string> noCalls = new HashSet<string>();

    private readonly Dictionary<object, (uint[] First, int Total)> tokens;
    #endregion

    #region Types
    private sealed record Walked(MemberFacts Facts, Evidence? Evidence);

    private sealed record Evidence(HashSet<string> Apis, HashSet<string> Values, HashSet<int> Lengths);

    private sealed class Target
    {
        public HashSet<string> Apis { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Values { get; } = new(StringComparer.Ordinal);
        public HashSet<int> Lengths { get; } = [];
    }

    private sealed class Budget
    {
        public long Evidence { get; set; }
        public long Narrowing { get; set; }
    }

    // Finding counts: one method's, one caller name's, or (Many) a narrowed finding's methods' together.
    private class Counts
    {
        public Dictionary<Capability, int> Capabilities { get; } = [];
        public int Indicators { get; private set; }
        public int HiddenContent { get; private set; }

        public virtual void AddCapability(Capability capability) => Capabilities[capability] = Capabilities.GetValueOrDefault(capability) + 1;
        public virtual void AddIndicator() => Indicators++;
        public virtual void AddHiddenContent() => HiddenContent++;

        // A member's own counts and its name's, or null when it has neither.
        public static Counts? Sum(Counts? own, Counts? named)
        {
            if (own is null || named is null)
                return own ?? named;
            var sum = new Counts { Indicators = own.Indicators + named.Indicators, HiddenContent = own.HiddenContent + named.HiddenContent };
            foreach (var (capability, n) in own.Capabilities.Concat(named.Capabilities))
                sum.Capabilities[capability] = sum.Capabilities.GetValueOrDefault(capability) + n;
            return sum;
        }

        public sealed class Many(IEnumerable<Counts> each) : Counts
        {
            public override void AddCapability(Capability capability) { foreach (var c in all) c.AddCapability(capability); }
            public override void AddIndicator() { foreach (var c in all) c.AddIndicator(); }
            public override void AddHiddenContent() { foreach (var c in all) c.AddHiddenContent(); }

            private readonly Counts[] all = [.. each];
        }
    }

    // One assembly's counts, by method token and by caller name.
    private sealed class Attribution
    {
        public Counts Of(uint token) => byToken.TryGetValue(token, out var c) ? c : byToken[token] = new Counts();
        public Counts OfName((string Type, string Method) name) => byName.TryGetValue(name, out var c) ? c : byName[name] = new Counts();
        public Counts? Own(uint token) => byToken.GetValueOrDefault(token);
        public Counts? Named((string Type, string Method) name) => byName.GetValueOrDefault(name);

        private readonly Dictionary<uint, Counts> byToken = [];
        private readonly Dictionary<(string Type, string Method), Counts> byName = [];
    }
    #endregion
}
