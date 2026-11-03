namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

using Model.Types;

/// <summary>How <see cref="MemberIndex.Resolve"/> settled a method reference.</summary>
public enum ResolutionKind
{
    /// <summary>
    /// The reference's declaring type is not an instantiation, so its signature is the definition's: its node id named
    /// exactly one indexed definition.
    /// </summary>
    Exact,

    /// <summary>
    /// The reference came through a generic type instantiation (<c>Box&lt;int&gt;.Run</c>), whose parameter types CCI
    /// has already substituted. Exactly one indexed definition, with its type parameters replaced by the
    /// instantiation's arguments, renders the same signature.
    /// </summary>
    Substituted,

    /// <summary>
    /// The declaring type lives in an assembly that was not indexed, or an indexed one forwards it there: a platform
    /// or dependency leaf.
    /// </summary>
    External,

    /// <summary>
    /// More than one indexed definition matched, or a type forwarder makes the reference land in more than one place.
    /// Recorded as opacity, never guessed.
    /// </summary>
    Ambiguous,

    /// <summary>
    /// The declaring assembly is indexed but no definition matched, or the reference (or its declaring assembly) was
    /// unreadable.
    /// </summary>
    Unresolved
}

/// <summary>
/// The outcome of resolving one method reference against a <see cref="MemberIndex"/>. <see cref="NodeId"/> is the
/// definition's node id when <see cref="Definition"/> is set, otherwise the reference's own; <see cref="Assembly"/> is
/// the reference's declaring assembly, when it could be read. <see cref="Candidates"/> holds the node ids of every
/// indexed definition that matched — one when resolved, several when <see cref="ResolutionKind.Ambiguous"/>.
/// </summary>
public sealed record MethodResolution(
    ResolutionKind Kind,
    string NodeId,
    string ClassificationKey,
    string? Assembly,
    MethodDefinition? Definition,
    IReadOnlyList<string> Candidates,
    string? Reason)
{
    #region Properties
    /// <summary>True when the reference resolved to a definition in an indexed assembly.</summary>
    public bool IsOwn => Definition is not null;
    #endregion
}

/// <summary>
/// What could not be indexed. Nothing is skipped silently (ADR 0020 decision 8). <see cref="ForwardersUnreadable"/>
/// counts assemblies whose type forwarders could not be read: no reference into one resolves to own code.
/// </summary>
public sealed record IndexCoverage(int AssembliesUnreadable, int TypesSkipped, int MethodsSkipped, int ForwardersUnreadable = 0)
{
    #region Properties
    /// <summary>True when every assembly, type, method and forwarder table was read.</summary>
    public bool IsComplete => AssembliesUnreadable == 0 && TypesSkipped == 0 && MethodsSkipped == 0 && ForwardersUnreadable == 0;
    #endregion
}

/// <summary>
/// A definition-level index over one or more loaded assemblies (ADR 0020, phase A1): types and methods by their
/// <see cref="CanonicalName"/> node ids, each type's base and interfaces, the reverse (direct-subtype) map, and
/// <see cref="Resolve"/>, which maps a call-site reference to the definition it names.
/// <para>
/// It exists because Analysis.Net's own resolution cannot be used in a traversal: <c>Host.ResolveReference</c> is a
/// linear <c>SingleOrDefault</c> scan per lookup (measured 500x slower on one assembly) and throws on an ambiguous
/// match, and <c>Helper.FindMethodImplementation</c> and <c>IBasicType.ResolvedType</c> go through it (ADR 0020
/// amendment items 3 and 7). Nothing here touches <c>ResolvedMethod</c>, <c>ResolvedType</c> or
/// <c>ResolveReference</c>.
/// </para>
/// <para>
/// Node ids are not assembly-qualified, so ownership is decided on the reference's declaring assembly name. A type
/// declared by an unindexed assembly whose node id is also an indexed one (a package shipping its own
/// <c>System.IDisposable</c>) is given the <see cref="Qualified"/> id, so the two can never be conflated. Every
/// collection is ordinal-sorted, so two builds over the same input are identical. Never throws.
/// </para>
/// <para>
/// A reference into an indexed assembly that forwards the reference's type (<see cref="TypeForwarders"/>) is followed
/// to where the CLR sends it, so a package cannot hide a platform call behind a forwarder and a same-named decoy.
/// </para>
/// </summary>
public sealed class MemberIndex
{
    #region Constructors
    private MemberIndex(
        IReadOnlyList<string> assemblies,
        IReadOnlyDictionary<string, IReadOnlyList<IndexedType>> types,
        IReadOnlyList<IndexedMethod> methods,
        IReadOnlyDictionary<string, IReadOnlyList<string>> subtypes,
        IReadOnlyDictionary<string, TypeForwarders> forwarders,
        IndexCoverage coverage)
    {
        Assemblies = assemblies;
        this.types = types;
        Methods = methods;
        this.subtypes = subtypes;
        this.forwarders = forwarders;
        Coverage = coverage;
        assemblySet = new HashSet<string>(assemblies, StringComparer.OrdinalIgnoreCase);
        byNodeId = Group(methods, m => m.NodeId);
        byShape = Group(methods, m => Shape(m.DeclaringTypeId, m.Definition.Name, m.Identity.GenericArity, m.Identity.ParameterTypes.Count));
        // By reference: Model's MethodDefinition has no value equality worth trusting. Build removes duplicate assembly
        // instances, and the first entry wins anyway, so a definition reachable twice cannot throw here.
        ownMethods = methods.GroupBy<IndexedMethod, MethodDefinition>(m => m.Definition, ReferenceEqualityComparer.Instance)
            .ToDictionary<IGrouping<MethodDefinition, IndexedMethod>, MethodDefinition, IndexedMethod>(g => g.Key, g => g.First(), ReferenceEqualityComparer.Instance);
    }
    #endregion

    #region Properties
    /// <summary>The indexed assemblies' names, ordinal-sorted.</summary>
    public IReadOnlyList<string> Assemblies { get; }

    /// <summary>Every indexed method definition, ordered by node id, then assembly.</summary>
    public IReadOnlyList<IndexedMethod> Methods { get; }

    /// <summary>Every indexed type node id, ordinal-sorted.</summary>
    public IEnumerable<string> TypeIds => types.Keys.Order(StringComparer.Ordinal);

    /// <summary>What could not be indexed.</summary>
    public IndexCoverage Coverage { get; }
    #endregion

    #region Methods
    /// <summary>Indexes the loaded assemblies of <paramref name="assemblies"/>, with the forwarders read from their files.</summary>
    public static MemberIndex Build(IEnumerable<AssemblyDisassembler> assemblies) =>
        Build(assemblies.Where(d => d is not null).Select(d => (d.Assembly, d.Forwarders)));

    /// <summary>
    /// Indexes every type and method definition of <paramref name="assemblies"/>, each with its type forwarders —
    /// <see cref="TypeForwarders.None"/> only for an assembly that has no file (a synthetic one). An assembly, type or
    /// method whose metadata cannot be read is skipped on its own and counted in <see cref="Coverage"/>, and so is a
    /// forwarder table that is unreadable or missing (null).
    /// </summary>
    public static MemberIndex Build(IEnumerable<(Model.Assembly Assembly, TypeForwarders Forwarders)> assemblies)
    {
        var inputs = assemblies.Where(a => a.Assembly is not null).DistinctBy(a => (object)a.Assembly, ReferenceEqualityComparer.Instance).ToArray();
        var loaded = inputs.Select(a => a.Assembly).ToArray();
        var typeLists = loaded
            .Select(a => (Assembly: a.Name ?? CanonicalName.UnknownPart, Types: Guard<ITypeDefinition[]?>(() => a.RootNamespace.GetAllTypes().ToArray(), null)))
            .ToArray();
        var assemblyNames = CanonicalNames(typeLists.Select(t => t.Assembly));
        var assemblySet = new HashSet<string>(assemblyNames, StringComparer.OrdinalIgnoreCase);

        var typeCandidates = typeLists
            .SelectMany(l => (l.Types ?? []).Select(t => (l.Assembly, Type: t, NodeId: Guard<string?>(() => CanonicalName.NodeId(ModelNames.Of(t)), null))))
            .ToArray();
        var ownTypeIds = typeCandidates.Where(t => t.NodeId is not null).Select(t => t.NodeId!).ToHashSet(StringComparer.Ordinal);

        var indexedTypes = typeCandidates
            .Where(t => t.NodeId is not null)
            .Select(t => Guard<IndexedType?>(() => IndexType(t.Assembly, t.NodeId!, t.Type, assemblySet, ownTypeIds), null))
            .ToArray();
        var types = indexedTypes.OfType<IndexedType>()
            .OrderBy(t => t.NodeId, StringComparer.Ordinal).ThenBy(t => t.Assembly, StringComparer.Ordinal)
            .ToArray();

        var methodCandidates = types
            .Select(t => (Type: t, Methods: Guard<MethodDefinition[]?>(() => t.Definition.Members.OfType<MethodDefinition>().ToArray(), null)))
            .ToArray();
        var indexedMethods = methodCandidates
            .SelectMany(x => (x.Methods ?? []).Select(m => Guard<IndexedMethod?>(() => IndexMethod(x.Type, m), null)))
            .ToArray();
        var methods = indexedMethods.OfType<IndexedMethod>()
            .OrderBy(m => m.NodeId, StringComparer.Ordinal).ThenBy(m => m.Assembly, StringComparer.Ordinal)
            .ToArray();

        var subtypes = types
            .SelectMany(t => t.Supertypes.Select(super => (Super: super, Sub: t.NodeId)))
            .GroupBy(x => x.Super, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyList<string>)g.Select(x => x.Sub).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                StringComparer.Ordinal);

        // Per assembly name, like ownership: one name loaded twice forwards what either copy forwards.
        var forwarders = inputs
            .GroupBy(a => a.Assembly.Name ?? CanonicalName.UnknownPart, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => TypeForwarders.Merge(g.Select(a => a.Forwarders)), StringComparer.OrdinalIgnoreCase);

        var coverage = new IndexCoverage(
            typeLists.Count(l => l.Types is null),
            typeCandidates.Count(t => t.NodeId is null) + indexedTypes.Count(t => t is null) + methodCandidates.Count(x => x.Methods is null),
            indexedMethods.Count(m => m is null),
            inputs.Count(a => a.Forwarders is not { IsReadable: true }));

        return new MemberIndex(assemblyNames, Group(types, t => t.NodeId), methods, subtypes, forwarders, coverage);
    }

    /// <summary>
    /// The node id under which a type or method that is <em>not</em> a verified own definition is kept when its bare
    /// <paramref name="nodeId"/> is also an indexed one: <c>[assembly]nodeId</c>. That is a type or method of an
    /// unindexed <paramref name="assembly"/>, and in the graph also an Unresolved reference into an indexed one (its
    /// id matching an own method is textual only). The brackets cannot start a legal CLR name, so a qualified id
    /// never collides with a bare one.
    /// </summary>
    public static string Qualified(string? assembly, string nodeId) => $"[{assembly ?? CanonicalName.UnknownPart}]{nodeId}";

    /// <summary>True when <paramref name="nodeId"/> names a method defined in an indexed assembly.</summary>
    public bool IsOwnMethod(string nodeId) => byNodeId.ContainsKey(nodeId);

    /// <summary>
    /// Resolves a call-site reference to the indexed definition it names, or says why it cannot. A generic method
    /// instance is resolved through its unspecialized <see cref="IMethodReference.GenericMethod"/>. A reference through
    /// a generic type instantiation is matched by substituting the instantiation's arguments into each candidate's
    /// parameters and comparing the rendered signatures exactly; anything left over is <see cref="ResolutionKind.Ambiguous"/>
    /// rather than guessed. A reference whose type the declaring assembly forwards is followed to the forward's target;
    /// if the type is also defined along the way, both are kept as <see cref="ResolutionKind.Ambiguous"/>. Results are
    /// memoized. Never throws.
    /// </summary>
    public MethodResolution Resolve(IMethodReference? reference)
    {
        if (reference is null)
            return new(ResolutionKind.Unresolved, CanonicalName.UnknownPart, CanonicalName.UnknownPart, null, null, [], "null reference");

        var identity = ModelNames.Of(reference);
        var nodeId = CanonicalName.NodeId(identity);
        var key = CanonicalName.ClassificationKey(identity);

        if (reference is MethodDefinition definition && ownMethods.TryGetValue(definition, out var own))
            return Own(ResolutionKind.Exact, key, own);

        if (Guard<string?>(() => reference.ContainingType?.ContainingAssembly?.Name, null) is not { } assembly)
            return new(ResolutionKind.Unresolved, nodeId, key, null, null, [], "declaring assembly unreadable");
        if (!assemblySet.Contains(assembly))
            return new(ResolutionKind.External, nodeId, key, assembly, null, [], null);

        var target = Guard<IMethodReference?>(() => reference.GenericMethod, null) ?? reference;
        var targetIdentity = ReferenceEquals(target, reference) ? identity : ModelNames.Of(target);
        var site = new Site(nodeId, key, targetIdentity, ModelNames.TypeArguments(Guard<IBasicType?>(() => target.ContainingType, null)));

        return forwarders.GetValueOrDefault(assembly) is { IsReadable: true, Count: 0 } ? Defined(assembly, site) : Follow(assembly, site);
    }

    /// <summary>The node ids of the types that directly extend or implement <paramref name="typeNodeId"/>.</summary>
    public IReadOnlyList<string> DirectSubtypes(string typeNodeId) =>
        subtypes.TryGetValue(typeNodeId, out var found) ? found : [];

    /// <summary>The indexed definitions of <paramref name="typeNodeId"/> (more than one only across assemblies).</summary>
    public IReadOnlyList<IndexedType> Types(string typeNodeId) =>
        types.TryGetValue(typeNodeId, out var found) ? found : [];

    // Into an indexed assembly that forwards types. The CLR resolves a reference from another assembly through the
    // forwarder even when the assembly also defines the type, but binds a MethodDef token inside the assembly to that
    // definition - and Model renders both alike. So every place the reference can land is collected, walking forwards
    // (each assembly once, so a cycle or a fan-out terminates): the definitions of any assembly on the way, and where the
    // walk ends - a definition, an unindexed leaf, or Unresolved. A forward back to an assembly already visited is an
    // Unresolved place (the CLR throws on a cycle), and so is an export from another module file, which CCI never loads
    // (the CLR follows that export too, and .NET Framework runs it). One place is the answer; several are Ambiguous with
    // every one kept, a non-own place as a Qualified leaf so it can never merge into a same-named own node. A table that
    // cannot be read, or a declaring type too unreadable to look up, ends the walk Unresolved: never Own on a guess.
    private MethodResolution Follow(string assembly, Site site)
    {
        var places = new List<MethodResolution>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { assembly };
        var queue = new Queue<string>([assembly]);
        var forwards = false;
        while (queue.TryDequeue(out var current))
        {
            if (!assemblySet.Contains(current))
            {
                places.Add(new(ResolutionKind.External, site.NodeId, site.Key, current, null, [], null));
                continue;
            }

            var table = forwarders.GetValueOrDefault(current) ?? TypeForwarders.Unreadable;
            var outermost = site.Outermost;
            if (!table.IsReadable || (table.Count > 0 && outermost is null))
            {
                places.Add(Unresolved(current, site, table.IsReadable
                    ? $"the declaring type could not be read, and {current} forwards types"
                    : $"the type forwarders of {current} could not be read"));
                continue;
            }

            var onward = table.Count == 0 ? [] : table.Targets(outermost!.Value.Namespace, outermost.Value.Name);
            var modules = table.Count == 0 ? [] : table.Modules(outermost!.Value.Namespace, outermost.Value.Name);
            forwards |= onward.Count > 0;
            var defined = Defined(current, site);
            if ((onward.Count == 0 && modules.Count == 0) || defined.Kind != ResolutionKind.Unresolved)
                places.Add(defined);
            places.AddRange(modules.Select(m => Unresolved(current, site, $"{current} exports this type from module file {m}, which is not indexed")));
            places.AddRange(onward.Where(next => seen.Contains(next))
                .Select(next => Unresolved(next, site, $"the type forwarders of {current} lead back to {next}: a cycle, or a second way into it")));
            foreach (var next in onward.Where(seen.Add))
                queue.Enqueue(next);
        }

        // Worded by what was followed: a forwarder (even back into the same assembly), or only a module export.
        var forwarded = forwards ? $"forwarded by {assembly}" : null;
        return places switch
        {
            [var only] => only with { Reason = only.Reason is null ? forwarded : forwarded is null ? only.Reason : $"{forwarded}; {only.Reason}" },
            _ => new(ResolutionKind.Ambiguous, site.NodeId, site.Key, assembly, null,
                places.SelectMany(p => Candidates(p, site)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                string.Join("; ", [
                    $"{assembly} {(forwards ? "forwards" : "exports")} this type, and it resolves into {string.Join(", ", places.Select(p => p.Assembly).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal))}",
                    .. places.Select(p => p.Reason).OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)])),
        };
    }

    // The memoized definition-level answer for one indexed assembly, rebound to the reference's own id and key. Keyed on
    // every input ResolveOwn reads, each part separately (a node id alone is not injective: names may contain '.' and
    // '`'), with counts so the variable-length lists cannot run into each other.
    private MethodResolution Defined(string assembly, Site site)
    {
        var memo = Key([
            assembly,
            CanonicalName.NodeId(site.Target),
            CanonicalName.NodeId(site.Target.DeclaringType),
            site.Target.MethodName ?? CanonicalName.UnknownPart,
            site.Target.GenericArity.ToString(CultureInfo.InvariantCulture),
            site.Target.ParameterTypes.Count.ToString(CultureInfo.InvariantCulture),
            .. site.Target.ParameterTypes,
            site.TypeArguments is null ? "?" : "=",
            .. site.TypeArguments ?? [],
        ]);
        var found = resolved.GetOrAdd(memo, _ => ResolveOwn(assembly, site.NodeId, site.Key, site.Target, site.TypeArguments));

        return found with { NodeId = found.Definition is null ? site.NodeId : found.NodeId, ClassificationKey = site.Key };
    }

    private static MethodResolution Unresolved(string assembly, Site site, string reason) =>
        new(ResolutionKind.Unresolved, site.NodeId, site.Key, assembly, null, [], reason);

    // The graph nodes a place stands for in an Ambiguous result.
    private static IEnumerable<string> Candidates(MethodResolution place, Site site) =>
        place.IsOwn ? [place.NodeId]
        : place.Kind == ResolutionKind.Ambiguous ? place.Candidates
        : [Qualified(place.Assembly, site.NodeId)];

    // Into an indexed assembly. Not an instantiation: the reference's signature is the definition's, so only an exact
    // node id can match. An instantiation: CCI has substituted the type arguments into the reference's parameters
    // (and kept no unspecialized version), so every same-shaped candidate is rendered with the same substitution and
    // compared exactly. A candidate is never excluded on a guess: two that render alike stay Ambiguous. When nothing
    // can be checked - arguments that cannot be recovered, or a substituted signature that rendered <unknown> (CCI's
    // reference truncates at its real depth, the substituted candidate at another, so a text match on it proves
    // nothing) - nothing is excluded: every same-shaped candidate is kept, and even a lone one is Ambiguous. The
    // exact branch needs no such guard: the true definition renders exactly as its own reference does.
    private MethodResolution ResolveOwn(string assembly, string nodeId, string key, MethodIdentity target, IReadOnlyList<string>? typeArguments)
    {
        var cannotCheck = typeArguments switch
        {
            null => "the instantiation's type arguments could not be recovered",
            { Count: > 0 } when target.ParameterTypes.Any(p => p.Contains(CanonicalName.UnknownPart, StringComparison.Ordinal))
                => "the instantiated signature could not be read in full",
            _ => null,
        };
        var sameShape = typeArguments is { Count: 0 }
            ? []
            : InAssembly(byShape, Shape(CanonicalName.NodeId(target.DeclaringType), target.MethodName, target.GenericArity, target.ParameterTypes.Count), assembly);
        var matches = cannotCheck is not null || typeArguments is null ? sameShape
            : typeArguments.Count == 0 ? InAssembly(byNodeId, CanonicalName.NodeId(target), assembly)
            : sameShape.Where(m => ModelNames.ParameterTypes(m.Definition, typeArguments).SequenceEqual(target.ParameterTypes, StringComparer.Ordinal)).ToArray();

        return (matches.Length, cannotCheck) switch
        {
            (0, null) => new(ResolutionKind.Unresolved, nodeId, key, assembly, null, [], "no indexed definition matches"),
            (0, _) => new(ResolutionKind.Unresolved, nodeId, key, assembly, null, [], $"no indexed definition has this shape; {cannotCheck}"),
            (1, null) => Own(typeArguments is { Count: 0 } ? ResolutionKind.Exact : ResolutionKind.Substituted, key, matches[0]),
            _ => new(ResolutionKind.Ambiguous, nodeId, key, assembly, null,
                matches.Select(m => m.NodeId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                cannotCheck ?? (typeArguments is { Count: 0 } ? "several definitions share this node id" : "several definitions match the instantiated signature")),
        };
    }

    private static IndexedType IndexType(string assembly, string nodeId, ITypeDefinition type, HashSet<string> assemblies, HashSet<string> ownTypeIds)
    {
        var supertypes = type switch
        {
            ClassDefinition c => Prepend(c.Base, c.Interfaces),
            StructDefinition s => s.Interfaces.AsEnumerable(),
            InterfaceDefinition i => i.Interfaces.AsEnumerable(),
            _ => [],
        };
        return new IndexedType(
            assembly,
            nodeId,
            type,
            supertypes.Select(s => SupertypeId(s, assemblies, ownTypeIds)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
    }

    // A supertype declared by an unindexed assembly keeps its bare id unless an indexed type shares it - then the
    // platform System.IDisposable and a package's own System.IDisposable must stay two different supertypes.
    private static string SupertypeId(IBasicType supertype, HashSet<string> assemblies, HashSet<string> ownTypeIds)
    {
        var id = CanonicalName.NodeId(ModelNames.Of(supertype));
        var assembly = Guard<string?>(() => supertype.ContainingAssembly?.Name, null);
        return ownTypeIds.Contains(id) && (assembly is null || !assemblies.Contains(assembly)) ? Qualified(assembly, id) : id;
    }

    private static IndexedMethod IndexMethod(IndexedType type, MethodDefinition method)
    {
        var identity = ModelNames.Of(method);
        return new IndexedMethod(type.Assembly, CanonicalName.NodeId(identity), type.NodeId, identity, method);
    }

    // Assembly names compare case-insensitively; the spelling kept for each is the ordinal-least one, so the result
    // does not depend on input order.
    private static string[] CanonicalNames(IEnumerable<string> names) =>
        names.GroupBy(n => n, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Order(StringComparer.Ordinal).First())
            .Order(StringComparer.Ordinal)
            .ToArray();

    private static IEnumerable<IBasicType> Prepend(IBasicType? first, IEnumerable<IBasicType> rest) =>
        first is null ? rest : rest.Prepend(first);

    private static MethodResolution Own(ResolutionKind kind, string key, IndexedMethod method) =>
        new(kind, method.NodeId, key, method.Assembly, method.Definition, [method.NodeId], null);

    private static IndexedMethod[] InAssembly(IReadOnlyDictionary<string, IReadOnlyList<IndexedMethod>> lookup, string key, string assembly) =>
        lookup.TryGetValue(key, out var found)
            ? found.Where(m => string.Equals(m.Assembly, assembly, StringComparison.OrdinalIgnoreCase)).ToArray()
            : [];

    private static string Shape(string typeNodeId, string? name, int arity, int parameters) =>
        Key([typeNodeId, name ?? CanonicalName.UnknownPart, arity.ToString(CultureInfo.InvariantCulture), parameters.ToString(CultureInfo.InvariantCulture)]);

    // Length-prefixed, so no choice of part contents (metadata names may hold any character) makes two different
    // part lists one key.
    private static string Key(IEnumerable<string> parts) =>
        string.Concat(parts.Select(p => $"{p.Length.ToString(CultureInfo.InvariantCulture)}:{p}"));

    private static IReadOnlyDictionary<string, IReadOnlyList<T>> Group<T>(IEnumerable<T> items, Func<T, string> key) =>
        items.GroupBy(key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => (IReadOnlyList<T>)g.ToArray(), StringComparer.Ordinal);

    // Upholds the never-throws contract: Model resolves lazily against a host, so any read can fault on a corrupt or
    // hostile module.
    private static T Guard<T>(Func<T> read, T fallback)
    {
        try
        {
            return read();
        }
        catch (Exception)
        {
            return fallback;
        }
    }
    #endregion

    #region Fields
    private readonly IReadOnlyDictionary<string, IReadOnlyList<IndexedType>> types;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> subtypes;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<IndexedMethod>> byNodeId;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<IndexedMethod>> byShape;
    private readonly IReadOnlyDictionary<MethodDefinition, IndexedMethod> ownMethods;
    private readonly HashSet<string> assemblySet;
    private readonly IReadOnlyDictionary<string, TypeForwarders> forwarders;

    // Resolution of a reference into an indexed assembly, keyed on every input ResolveOwn reads (see Defined) and
    // rebound to each reference's own id and key on a hit; memoized so a repeated call site costs one candidate scan.
    private readonly ConcurrentDictionary<string, MethodResolution> resolved = new(StringComparer.Ordinal);
    #endregion

    #region Child types
    /// <summary>An indexed type definition and the definition-normalized node ids of its base and interfaces.</summary>
    public sealed record IndexedType(string Assembly, string NodeId, ITypeDefinition Definition, IReadOnlyList<string> Supertypes);

    /// <summary>An indexed method definition with its identity, node id and declaring type's node id.</summary>
    public sealed record IndexedMethod(string Assembly, string NodeId, string DeclaringTypeId, MethodIdentity Identity, MethodDefinition Definition);

    // One reference being resolved: its own id and key, the definition-level identity behind it, and the
    // instantiation's type arguments.
    private readonly record struct Site(string NodeId, string Key, MethodIdentity Target, IReadOnlyList<string>? TypeArguments)
    {
        // The outermost declaring type, which is what a forwarder names; null when unreadable or truncated.
        public (string Namespace, string Name)? Outermost =>
            Target.DeclaringType.NestingChain is [var name, ..] && name != CanonicalName.UnknownPart
                ? (Target.DeclaringType.Namespace ?? string.Empty, name)
                : null;
    }
    #endregion
}
