namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

using Cilica.AsmIO;
using Cilica.IR;

using Silvergun.CodeAnalysis.IL;

// Reflection targets (S4.3, D4): our own read-only walk back from a reflection sink's operands through the lookups of the
// reflection map, intraprocedurally, over the same values the argument facts read.
public static partial class SsaSinkFacts
{
    #region Methods
    // Two definitions' targets of one site: the parts union as values do, and differing kinds read Member. The type names
    // union too, while the type is still constant.
    private static TargetParts Union(TargetParts a, TargetParts b, int maxAlternatives)
    {
        SsaValue? Either(SsaValue? x, SsaValue? y) => x is null && y is null ? null
            : Union(x ?? SsaValue.OfDynamic(SsaDynamicOrigin.Other), y ?? SsaValue.OfDynamic(SsaDynamicOrigin.Other), maxAlternatives);
        var type = Either(a.Type, b.Type)!;
        var (types, cut) = Constants(type).Any() ? Capped(a.Types.Concat(b.Types)) : ([], false);
        return new TargetParts(a.Kind == b.Kind ? a.Kind : ReflectionKind.Member, Either(a.Assembly, b.Assembly), type, Either(a.Member, b.Member),
            types, cut || Constants(type).Any() && (a.TypesCut || b.TypesCut));
    }

    // The target of a site: its by-name candidates, then its text charged to the folder budget. Its gap names holes in
    // the index and type names left unsearched.
    private static SsaReflectionTarget Target(TargetParts parts, OwnMembers members, SsaFactBounds bounds, TextBudget budget)
    {
        var (candidates, total) = Candidates(parts, members, bounds.MaxCandidates);
        string?[] gaps = [members.Gap, parts.TypesCut ? $"the type stands for more than {MaxTypes} type names, and only the first {MaxTypes} were searched" : null];
        return new SsaReflectionTarget(Kind(parts.Kind), parts.Assembly is null ? null : budget.Charge(parts.Assembly), budget.Charge(parts.Type!),
            parts.Member is null ? null : budget.Charge(parts.Member), SsaCandidateMatch.ByName,
            budget.Charge([.. candidates.Select(Reachability.BoundName)]), total,
            gaps.OfType<string>().ToArray() is { Length: > 0 } found ? string.Join("; ", found) : null);
    }

    // The first max candidates, ordinal, and how many there are. Each (type, key) list is ordinal and a node is under one
    // only, so the lists are disjoint and merged k-way: at most MaxTypes x 12 lookups and max dequeues per site.
    private static (string[] Candidates, int Total) Candidates(TargetParts parts, OwnMembers members, int max)
    {
        var names = Constants(parts.Member).Where(c => c.Kind == SsaConstantKind.String && Whole(c)).Select(c => c.Text).ToArray();
        string[] methods = parts.Kind switch
        {
            ReflectionKind.Constructor => [".ctor"],
            ReflectionKind.Method => names,
            ReflectionKind.Property => [.. names.SelectMany(n => new[] { "get_" + n, "set_" + n })],
            ReflectionKind.Member => [.. names.SelectMany(n => new[] { n, "get_" + n, "set_" + n })],
            _ => [],
        };
        var lists = (parts.Kind == ReflectionKind.Type
                ? parts.Types.Select(t => members.Types(t.NodeId))
                : parts.Types.SelectMany(t => methods.Select(m => members.Methods(t.NodeId, t.Key + "." + m))))
            .Where(l => l.Count > 0)
            // Case-variant lookups return the same list.
            .Distinct(ReferenceEqualityComparer.Instance)
            .Cast<IReadOnlyList<string>>()
            .ToArray();

        var queue = new PriorityQueue<(int List, int Index), string>(StringComparer.Ordinal);
        for (var i = 0; i < lists.Length; i++)
            queue.Enqueue((i, 0), lists[i][0]);
        var first = new List<string>();
        while (first.Count < max && queue.TryDequeue(out var at, out var id))
        {
            first.Add(id);
            if (at.Index + 1 < lists[at.List].Count)
                queue.Enqueue((at.List, at.Index + 1), lists[at.List][at.Index + 1]);
        }
        return ([.. first], lists.Sum(l => l.Count));
    }

    // At most MaxTypes type names, ordinal, so the candidate lookups per site stay bounded; Cut when any were left out.
    private static (TypeName[] Types, bool Cut) Capped(IEnumerable<TypeName> types)
    {
        var kept = types.Distinct().OrderBy(t => t.NodeId, StringComparer.Ordinal).ThenBy(t => t.Key, StringComparer.Ordinal).Take(MaxTypes + 1).ToArray();
        return kept.Length > MaxTypes ? (kept[..MaxTypes], true) : (kept, false);
    }

    private static IEnumerable<SsaConstant> Constants(SsaValue? value) =>
        value is { Kind: SsaValueKind.Constant or SsaValueKind.OneOf } ? value.Constants : [];

    // Text that is the raw string: not cut, and no escape (every escape starts with a backslash).
    private static bool Whole(SsaConstant constant) => !constant.Cut && !constant.Text.Contains('\\');

    private static SsaTargetKind Kind(ReflectionKind kind) => kind switch
    {
        ReflectionKind.Type => SsaTargetKind.Type,
        ReflectionKind.Method => SsaTargetKind.Method,
        ReflectionKind.Constructor => SsaTargetKind.Constructor,
        ReflectionKind.Property => SsaTargetKind.Property,
        ReflectionKind.Field => SsaTargetKind.Field,
        _ => SsaTargetKind.Member,
    };
    #endregion

    #region Fields
    // Type names a target matches candidates under: real ones have one or two (a parsed and a literal spelling).
    private const int MaxTypes = 16;
    #endregion

    #region Child types
    // A type's definition by name: its node id and classification key, raw.
    private sealed record TypeName(string NodeId, string Key);

    // The parts of a target or a lookup's result, as values; Type is set once resolved. Types: the definitions its
    // constant type names, read in the body that named them.
    // TypesCut: more type names than MaxTypes, so some were not kept.
    private sealed record TargetParts(ReflectionKind Kind, SsaValue? Assembly, SsaValue? Type, SsaValue? Member, IReadOnlyList<TypeName> Types, bool TypesCut)
    {
        #region Constructors
        public TargetParts(ReflectionKind kind, SsaValue? assembly, SsaValue? type, SsaValue? member) : this(kind, assembly, type, member, [], false) { }
        #endregion
    }

    // Resolves a call's parts by its rule, following its operands back through the map's lookups. Lookups are memoised
    // per body (Reset with the value walker), so a chain shared by many sites is read once, and nesting is bounded.
    private sealed class ChainWalker(ReflectionMap map, ValueWalker values)
    {
        #region Methods
        // A site's target, with the type names its constant type stands for: a typeof's definitions in this body (by
        // reference, so two types rendered alike both count), and a String's spellings.
        public TargetParts? Target(Instruction instruction, ReflectionRule? rule)
        {
            if (rule is null || instruction is not CallInst call)
                return null;
            var parts = Resolve(call, rule, 0);
            var (types, cut) = Capped(Constants(parts.Type).SelectMany(c => c.Kind switch
            {
                SsaConstantKind.Type => values.DefinitionsOf(c),
                SsaConstantKind.String => ReflectionNames.Parse(c),
                _ => [],
            }));
            return parts with { Types = types, TypesCut = cut };
        }

        public void Reset() => lookups.Clear();

        private TargetParts Resolve(CallInst call, ReflectionRule rule, int depth)
        {
            if (depth > MaxDepth)
                return Finished(rule.Kind, null, SsaValue.OfDynamic(SsaDynamicOrigin.TooDeep), SsaValue.OfDynamic(SsaDynamicOrigin.TooDeep));
            var (kind, assembly, type, member) = (rule.Kind, (SsaValue?)null, (SsaValue?)null, (SsaValue?)null);
            bool Supplied(ReflectionRole role) => role switch
            {
                ReflectionRole.Assembly => assembly is not null,
                ReflectionRole.Type or ReflectionRole.TypeName => type is not null,
                ReflectionRole.Name => member is not null,
                _ => type is not null || member is not null,
            };

            foreach (var binding in rule.Bindings)
            {
                if (binding.Any(p => Supplied(p.Role)))
                    continue;
                var operands = binding.Select(p => (Part: p, Operand: Operand(call, p))).ToArray();
                if (operands.Any(o => !o.Operand.Fits))
                    continue;
                foreach (var (part, operand) in operands)
                {
                    switch (part.Role)
                    {
                        case ReflectionRole.Assembly:
                            assembly = operand.Declared == StringKey ? values.Of(operand.Value!) : AssemblyOf(operand.Value!, depth);
                            break;
                        case ReflectionRole.Type when part.Generic:
                            type = values.OfType(call.Method.GenericParams[part.Position]);
                            break;
                        case ReflectionRole.Type:
                            var (chainAssembly, chainType) = TypeOf(operand.Value!, depth);
                            (assembly, type) = (assembly ?? chainAssembly, chainType);
                            break;
                        case ReflectionRole.TypeName:
                            type = values.Of(operand.Value!);
                            break;
                        case ReflectionRole.Name:
                            member = values.Of(operand.Value!);
                            break;
                        case ReflectionRole.Member:
                            var found = MemberOf(operand.Value!, depth, kind);
                            (kind, assembly, type, member) = (found.Kind, assembly ?? found.Assembly, found.Type, found.Member);
                            break;
                    }
                }
            }
            return Finished(kind, assembly, type, member);
        }

        // An Assembly: through its lookup, else as a value.
        private SsaValue AssemblyOf(Value value, int depth) =>
            Lookup(value, depth, k => k == ReflectionKind.Assembly) is { } parts ? parts.Assembly ?? SsaValue.OfDynamic(SsaDynamicOrigin.Other) : values.Of(value);

        // A Type and the assembly its chain names: through its lookup, else as a value (typeof is a Type constant).
        private (SsaValue? Assembly, SsaValue Type) TypeOf(Value value, int depth) =>
            Lookup(value, depth, k => k == ReflectionKind.Type) is { } parts ? (parts.Assembly, parts.Type!) : (null, values.Of(value));

        // A member: through its lookup, else as a value standing for both its type and its name.
        private TargetParts MemberOf(Value value, int depth, ReflectionKind kind)
        {
            if (Lookup(value, depth, k => k is not (ReflectionKind.Assembly or ReflectionKind.Type)) is { } parts)
                return parts;
            var of = values.Of(value);
            return Finished(kind, null, of, of);
        }

        // The parts of a call the map lists as a lookup of a wanted kind, memoised; null for anything else.
        private TargetParts? Lookup(Value value, int depth, Func<ReflectionKind, bool> wanted)
        {
            if (ValueWalker.Strip(value) is not CallInst call || map.Lookup(ClassificationKey(call.Method)) is not { } rule || !wanted(rule.Kind))
                return null;
            // By depth too, so a result cut by the nesting bound never stands for the call reached shallower.
            if (!lookups.TryGetValue((call, depth), out var parts))
                lookups[(call, depth)] = parts = Resolve(call, rule, depth + 1);
            return parts;
        }

        // A part's operand and its declared type's key, and whether the role fits it.
        private static (bool Fits, Value? Value, string? Declared) Operand(CallInst call, ReflectionPart part)
        {
            try
            {
                if (part.Generic)
                    return (part.Position < call.Method.GenericParams.Count, null, null);
                var index = part.Position == ReflectionPart.This ? 0 : part.Position + (call.IsStatic ? 0 : 1);
                if (part.Position == ReflectionPart.This && call.IsStatic || index >= call.Args.Length || index >= call.Method.ParamSig.Count)
                    return (false, null, null);
                var declared = TypeNames.Identity(call.Method.ParamSig[index].Type) is { } identity ? CanonicalName.ClassificationKey(identity) : null;
                return (declared is not null && fits[part.Role].Contains(declared), call.Args[index], declared);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return (false, null, null);
            }
        }

        // Every target names a type, Dynamic when its chain does not; only member kinds name a member.
        private static TargetParts Finished(ReflectionKind kind, SsaValue? assembly, SsaValue? type, SsaValue? member) =>
            new(kind, assembly, type ?? SsaValue.OfDynamic(SsaDynamicOrigin.Other),
                kind is ReflectionKind.Assembly or ReflectionKind.Type or ReflectionKind.Constructor ? null : member ?? SsaValue.OfDynamic(SsaDynamicOrigin.Other));
        #endregion

        #region Fields
        // Lookups nested inside one another; real chains are two or three deep.
        private const int MaxDepth = 8;
        private const string StringKey = "System.String";

        // The declared types each role reads.
        private static readonly Dictionary<ReflectionRole, HashSet<string>> fits = new()
        {
            [ReflectionRole.Assembly] = new(StringComparer.Ordinal) { StringKey, "System.Reflection.Assembly" },
            [ReflectionRole.Type] = new(StringComparer.Ordinal) { "System.Type", "System.Reflection.TypeInfo" },
            [ReflectionRole.TypeName] = new(StringComparer.Ordinal) { StringKey },
            [ReflectionRole.Name] = new(StringComparer.Ordinal) { StringKey },
            [ReflectionRole.Member] = new(StringComparer.Ordinal)
            {
                "System.Reflection.MemberInfo", "System.Reflection.MethodBase", "System.Reflection.MethodInfo",
                "System.Reflection.ConstructorInfo", "System.Reflection.PropertyInfo", "System.Reflection.FieldInfo",
            },
        };

        private readonly Dictionary<(CallInst Call, int Depth), TargetParts> lookups = new(new CallAtDepth());
        #endregion
    }

    // A call by reference, at a nesting depth.
    private sealed class CallAtDepth : IEqualityComparer<(CallInst Call, int Depth)>
    {
        #region Methods
        public bool Equals((CallInst Call, int Depth) x, (CallInst Call, int Depth) y) => ReferenceEquals(x.Call, y.Call) && x.Depth == y.Depth;

        public int GetHashCode((CallInst Call, int Depth) obj) => HashCode.Combine(RuntimeHelpers.GetHashCode(obj.Call), obj.Depth);
        #endregion
    }

    // Type names as reflection spells them (Ns.Outer+Inner`1[[Arg]], Assembly), read into canonical form.
    private static class ReflectionNames
    {
        #region Methods
        // The definitions a whole String constant may name: its canonical form (each link's `N arity removed and summed),
        // and its literal form for a type whose name carries a tick of its own. None for an array, pointer or by-ref, or
        // a name not read.
        public static IEnumerable<TypeName> Parse(SsaConstant constant)
        {
            if (!Whole(constant))
                return [];
            var name = Unqualified(constant.Text).Trim();
            var open = name.IndexOf('[');
            if (open >= 0)
            {
                if (open + 1 >= name.Length || name[open + 1] is ']' or ',' or '*' || Close(name, open) != name.Length - 1)
                    return [];
                name = name[..open].TrimEnd();
            }
            if (name.Length == 0 || name[^1] is '*' or '&' || name.Contains(']'))
                return [];
            var links = name.Split('+');
            if (links.Any(string.IsNullOrWhiteSpace))
                return [];
            var arity = 0;
            var key = string.Join('.', links.Select(link =>
            {
                var tick = link.LastIndexOf('`');
                if (tick <= 0 || tick == link.Length - 1 || link.Length - tick > 6 || !link[(tick + 1)..].All(char.IsAsciiDigit))
                    return link;
                arity += int.Parse(link[(tick + 1)..]);
                return link[..tick];
            }));
            var literal = string.Join('.', links);
            return arity > 0 ? [new TypeName($"{key}`{arity}", key), new TypeName(literal, literal)] : [new TypeName(key, key)];
        }

        // The type part of an assembly-qualified name: up to the first comma outside brackets.
        private static string Unqualified(string text)
        {
            var depth = 0;
            for (var i = 0; i < text.Length; i++)
            {
                switch (text[i])
                {
                    case '[':
                        depth++;
                        break;
                    case ']':
                        depth--;
                        break;
                    case ',' when depth == 0:
                        return text[..i];
                }
            }
            return text;
        }

        // The index of the bracket closing the one at open; -1 when it is not closed.
        private static int Close(string text, int open)
        {
            var depth = 0;
            for (var i = open; i < text.Length; i++)
            {
                if (text[i] == '[')
                    depth++;
                else if (text[i] == ']' && --depth == 0)
                    return i;
            }
            return -1;
        }
        #endregion
    }
    #endregion
}
