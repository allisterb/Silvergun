namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>What a reflection lookup's result or a reflection target is.</summary>
internal enum ReflectionKind
{
    Assembly,
    Type,
    Method,
    Constructor,
    Property,
    Field,
    Member,
}

/// <summary>The part of a lookup or target a binding supplies (see <c>Resources/reflection.rm</c>).</summary>
internal enum ReflectionRole
{
    Assembly,
    Type,
    TypeName,
    Name,
    Member,
}

/// <summary>One role at one position: <see cref="This"/>, an argument index from 0, or the callee's generic argument.</summary>
internal sealed record ReflectionPart(ReflectionRole Role, int Position, bool Generic)
{
    #region Fields
    public const int This = -1;
    #endregion
}

/// <summary>A lookup or target: its kind, and its bindings in order, each a group of parts applied together.</summary>
internal sealed record ReflectionRule(ReflectionKind Kind, IReadOnlyList<IReadOnlyList<ReflectionPart>> Bindings);

/// <summary>
/// The data-driven reflection API list (S4.3, D4): <c>lookup</c> calls whose result is an assembly, a type or a member,
/// and <c>target</c> sinks with what they act on, each keyed by an exact classification key. Parsed in the capability
/// map's style from the embedded <c>Resources/reflection.rm</c>, whose header is the grammar. Never throws.
/// </summary>
public sealed class ReflectionMap
{
    #region Constructors
    private ReflectionMap(Dictionary<string, ReflectionRule> lookups, Dictionary<string, ReflectionRule> targets, IReadOnlyList<string> rejected)
    {
        this.lookups = lookups;
        this.targets = targets;
        RejectedLines = rejected;
    }
    #endregion

    #region Properties
    /// <summary>The built-in list, parsed once; an unreadable resource gives an empty list with the reason rejected.</summary>
    public static ReflectionMap Default => defaultMap.Value;

    /// <summary>The lines rejected while parsing, each with its source, line number and reason.</summary>
    public IReadOnlyList<string> RejectedLines { get; }

    /// <summary>How many lookups and targets were read.</summary>
    public (int Lookups, int Targets) Count => (lookups.Count, targets.Count);
    #endregion

    #region Methods
    /// <summary>Parses a list from <paramref name="reader"/>; <paramref name="sourceName"/> labels rejected lines.</summary>
    public static ReflectionMap Load(TextReader reader, string sourceName)
    {
        var source = string.IsNullOrWhiteSpace(sourceName) ? "<unnamed>" : sourceName;
        var lookups = new Dictionary<string, ReflectionRule>(StringComparer.Ordinal);
        var targets = new Dictionary<string, ReflectionRule>(StringComparer.Ordinal);
        var rejected = new List<string>();
        void Reject(string reason)
        {
            var entry = $"{source}: {reason}";
            Runtime.Warn("Reflection map: ignoring {0}", entry);
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
                    var (entry, error) = ParseLine(line);
                    if (error is not null)
                        Reject($"({number}): {error}");
                    else if (entry is not null)
                        (entry.Target ? targets : lookups)[entry.Key] = entry.Rule;
                }
            }
            catch (Exception ex)
            {
                Reject($"read failed: {ex.Message}");
            }
        return new ReflectionMap(lookups, targets, rejected);
    }

    /// <summary>The lookup for a call to <paramref name="key"/>, if it is one.</summary>
    internal ReflectionRule? Lookup(string? key) => key is null ? null : lookups.GetValueOrDefault(key);

    /// <summary>The target rule for a sink whose classification key is <paramref name="key"/>, if it has one.</summary>
    internal ReflectionRule? Target(string? key) => key is null ? null : targets.GetValueOrDefault(key);

    // One line: its entry, nothing for a blank or comment-only line, or why it is rejected.
    private static (Entry? Entry, string? Error) ParseLine(string line)
    {
        var text = line.IndexOf('#') is var comment and >= 0 ? line[..comment] : line;
        var tokens = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
            return (null, null);
        var directive = tokens[0].ToLowerInvariant();
        if (directive is not (LookupDirective or TargetDirective))
            return (null, $"unknown directive '{tokens[0]}'");
        if (tokens.Length < 4)
            return (null, $"'{directive}' takes a key, a kind and at least one binding");
        var key = tokens[1];
        if (key.Contains('*') || key[0] == '.' || key[^1] == '.' || !key.Contains('.'))
            return (null, $"malformed key '{key}'");
        if (!kinds.TryGetValue(tokens[2], out var kind))
            return (null, $"unknown kind '{tokens[2]}'");
        if (directive == TargetDirective && kind == ReflectionKind.Assembly)
            return (null, "a target cannot be an Assembly");

        var bindings = new List<IReadOnlyList<ReflectionPart>>();
        foreach (var token in tokens[3..])
        {
            var parts = token.Split(',').Select(Part).ToArray();
            if (parts.FirstOrDefault(p => p.Error is not null).Error is { } error)
                return (null, error);
            if (parts.Select(p => p.Part!.Role).Distinct().Count() < parts.Length)
                return (null, $"binding '{token}' names a role twice");
            bindings.Add([.. parts.Select(p => p.Part!)]);
        }
        return (new Entry(directive == TargetDirective, key, new ReflectionRule(kind, bindings)), null);
    }

    // One role=position pair.
    private static (ReflectionPart? Part, string? Error) Part(string pair)
    {
        var at = pair.IndexOf('=');
        if (at <= 0 || at == pair.Length - 1)
            return (null, $"malformed binding '{pair}'");
        var (name, position) = (pair[..at].ToLowerInvariant(), pair[(at + 1)..]);
        if (!roles.TryGetValue(name, out var role))
            return (null, $"unknown role '{pair[..at]}'");
        if (position.Equals("this", StringComparison.OrdinalIgnoreCase))
            return (new ReflectionPart(role, ReflectionPart.This, false), null);
        var generic = position.StartsWith("!!", StringComparison.Ordinal);
        if (generic && role != ReflectionRole.Type)
            return (null, $"only the type role takes a generic argument, in '{pair}'");
        var digits = generic ? position[2..] : position;
        return digits.Length is > 0 and <= 2 && digits.All(char.IsAsciiDigit)
            ? (new ReflectionPart(role, int.Parse(digits), generic), null)
            : (null, $"malformed position '{position}'");
    }

    private static ReflectionMap LoadDefault()
    {
        try
        {
            var assembly = typeof(ReflectionMap).Assembly;
            var name = assembly.GetManifestResourceNames().Where(n => n.EndsWith(ResourceSuffix, StringComparison.Ordinal)).Order(StringComparer.Ordinal).FirstOrDefault();
            using var stream = name is null ? null : assembly.GetManifestResourceStream(name);
            if (stream is null)
                return new ReflectionMap(new(StringComparer.Ordinal), new(StringComparer.Ordinal), [$"{DefaultSourceName}: embedded resource not found"]);
            using var reader = new StreamReader(stream);
            return Load(reader, DefaultSourceName);
        }
        catch (Exception ex)
        {
            return new ReflectionMap(new(StringComparer.Ordinal), new(StringComparer.Ordinal), [$"{DefaultSourceName}: {ex.Message}"]);
        }
    }
    #endregion

    #region Fields
    private const string LookupDirective = "lookup";
    private const string TargetDirective = "target";
    private const string ResourceSuffix = "reflection.rm";
    private const string DefaultSourceName = "<built-in reflection.rm>";

    private static readonly Dictionary<string, ReflectionRole> roles = new(StringComparer.Ordinal)
    {
        ["assembly"] = ReflectionRole.Assembly,
        ["type"] = ReflectionRole.Type,
        ["type-name"] = ReflectionRole.TypeName,
        ["name"] = ReflectionRole.Name,
        ["member"] = ReflectionRole.Member,
    };

    private static readonly Dictionary<string, ReflectionKind> kinds =
        Enum.GetValues<ReflectionKind>().ToDictionary(k => k.ToString(), k => k, StringComparer.OrdinalIgnoreCase);

    private static readonly Lazy<ReflectionMap> defaultMap = new(LoadDefault);

    private readonly Dictionary<string, ReflectionRule> lookups;
    private readonly Dictionary<string, ReflectionRule> targets;
    #endregion

    #region Child types
    private sealed record Entry(bool Target, string Key, ReflectionRule Rule);
    #endregion
}
