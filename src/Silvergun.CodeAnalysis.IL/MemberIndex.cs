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
/// <see cref="SupertypesUnresolved"/> counts base-type and interface references that did not land on one known place
/// (an unreadable assembly, a forwarder cycle, a type missing from the indexed assembly that should define it); each
/// is kept under its bare id as well, so CHA over-approximates rather than loses the subtype.
/// </summary>
public sealed record IndexCoverage(int AssembliesUnreadable, int TypesSkipped, int MethodsSkipped, int ForwardersUnreadable = 0, int SupertypesUnresolved = 0)
{
    #region Properties
    /// <summary>True when every assembly, type, method, forwarder table and supertype was read.</summary>
    public bool IsComplete => AssembliesUnreadable == 0 && TypesSkipped == 0 && MethodsSkipped == 0 && ForwardersUnreadable == 0 && SupertypesUnresolved == 0;
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
/// Supertypes are keyed by the same walk, so the subtype map and a call site's declared type agree on every key.
/// </para>
/// <para>
/// <see cref="DispatchTargets"/> is class-hierarchy analysis (phase A2): the own overrides and implementations a
/// virtual call may run, matched by name and shape over the subtype map.
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
        TypeScope scope,
        IReadOnlySet<string> open,
        IndexCoverage coverage)
    {
        Assemblies = assemblies;
        this.types = types;
        Methods = methods;
        this.subtypes = subtypes;
        this.forwarders = forwarders;
        this.scope = scope;
        this.open = open;
        Coverage = coverage;
        assemblySet = new HashSet<string>(assemblies, StringComparer.OrdinalIgnoreCase);
        byNodeId = Group(methods, m => m.NodeId);
        byShape = Group(methods, m => Shape(m.DeclaringTypeId, m.Definition.Name, m.Identity.GenericArity, m.Identity.ParameterTypes.Count));
        byImplementedShape = Group(methods, m => ImplementedShape(ImplementedName(m.Definition.Name), m.Identity.GenericArity, m.Identity.ParameterTypes.Count));
        // By reference: Model's MethodDefinition has no value equality worth trusting. Build removes duplicate assembly
        // instances, and the first entry wins anyway, so a definition reachable twice cannot throw here.
        ownMethods = methods.GroupBy<IndexedMethod, MethodDefinition>(m => m.Definition, ReferenceEqualityComparer.Instance)
            .ToDictionary<IGrouping<MethodDefinition, IndexedMethod>, MethodDefinition, IndexedMethod>(g => g.Key, g => g.First(), ReferenceEqualityComparer.Instance);
        // Per id, not per definition: one file may define an id many times over, and CHA asks these per candidate and
        // per step, so a scan of the definitions there would be uncharged work (review S1 round 4 W1-r4).
        interfaceIds = types.Where(t => t.Value.Any(d => d.Definition is InterfaceDefinition)).Select(t => t.Key).ToHashSet(StringComparer.Ordinal);
        classIds = types.Where(t => t.Value.Any(d => d.Definition is not InterfaceDefinition)).Select(t => t.Key).ToHashSet(StringComparer.Ordinal);
        supertypes = types.ToDictionary(
            t => t.Key,
            t => (IReadOnlyList<string>)t.Value.SelectMany(d => d.Supertypes).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)
                .Concat(implicitSupertypes.GetValueOrDefault(t.Key) ?? []).Distinct(StringComparer.Ordinal).ToArray(),
            StringComparer.Ordinal);
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

        // Per assembly name, like ownership: one name loaded twice forwards what either copy forwards.
        var forwarders = inputs
            .GroupBy(a => a.Assembly.Name ?? CanonicalName.UnknownPart, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => TypeForwarders.Merge(g.Select(a => a.Forwarders)), StringComparer.OrdinalIgnoreCase);

        var typeCandidates = typeLists
            .SelectMany(l => (l.Types ?? []).Select(t => (l.Assembly, Type: t, NodeId: Guard<string?>(() => CanonicalName.NodeId(ModelNames.Of(t)), null))))
            .ToArray();
        var definedIn = typeCandidates
            .Where(t => t.NodeId is not null)
            .GroupBy(t => t.NodeId!, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(t => t.Assembly).ToHashSet(StringComparer.OrdinalIgnoreCase), StringComparer.Ordinal);
        var scope = new TypeScope(assemblySet, forwarders, definedIn);

        var indexedTypes = typeCandidates
            .Where(t => t.NodeId is not null)
            .Select(t => Guard<(IndexedType Type, int Unresolved)?>(() => IndexType(t.Assembly, t.NodeId!, t.Type, scope), null))
            .ToArray();
        var types = indexedTypes.OfType<(IndexedType Type, int Unresolved)>().Select(t => t.Type)
            .OrderBy(t => t.NodeId, StringComparer.Ordinal).ThenBy(t => t.Assembly, StringComparer.Ordinal)
            .ToArray();
        var typesById = Group(types, t => t.NodeId);

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

        var coverage = new IndexCoverage(
            typeLists.Count(l => l.Types is null),
            typeCandidates.Count(t => t.NodeId is null) + indexedTypes.Count(t => t is null) + methodCandidates.Count(x => x.Methods is null),
            indexedMethods.Count(m => m is null),
            inputs.Count(a => a.Forwarders is not { IsReadable: true }),
            indexedTypes.Sum(t => t?.Unresolved ?? 0));

        return new MemberIndex(assemblyNames, typesById, methods, subtypes, forwarders, scope, OpenTypes(typesById, scope), coverage);
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
    /// parameters and comparing the rendered signatures exactly, return type included; anything left over is
    /// <see cref="ResolutionKind.Ambiguous"/> rather than guessed, and so is a match on a signature that renders
    /// truncated or clamped. A reference whose type the declaring assembly forwards is followed to the forward's target;
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
        var site = new Site(nodeId, key, targetIdentity, ModelNames.ReturnType(target, []), ModelNames.TypeArguments(Guard<IBasicType?>(() => target.ContainingType, null)));

        return forwarders.GetValueOrDefault(assembly) is { IsReadable: true, Count: 0 } ? Defined(assembly, site) : Follow(assembly, site);
    }

    /// <summary>The node ids of the types that directly extend or implement <paramref name="typeNodeId"/>.</summary>
    public IReadOnlyList<string> DirectSubtypes(string typeNodeId) =>
        subtypes.TryGetValue(typeNodeId, out var found) ? found : [];

    /// <summary>
    /// The indexed definitions of <paramref name="typeNodeId"/>: more than one across assemblies, or when one file
    /// defines the same name more than once.
    /// </summary>
    public IReadOnlyList<IndexedType> Types(string typeNodeId) =>
        types.TryGetValue(typeNodeId, out var found) ? found : [];

    /// <summary>
    /// Class-hierarchy analysis for one call site: the node ids of the own methods that <paramref name="reference"/>
    /// may also run, besides its <paramref name="resolution"/>. Null when the site does not dispatch: a verified
    /// definition that is neither virtual nor abstract runs as named, and a non-virtual site (<paramref name="virtualSite"/>
    /// false) dispatches only to a static member of a type that may be an interface and has own subtypes (a static
    /// abstract interface member, called through a dropped <c>constrained.</c> prefix).
    /// <para>
    /// The targets are the own methods that match the declared method's name (or end in it, as a C# explicit
    /// implementation does), generic arity and parameter count, are instance and virtual or abstract (static, for a
    /// static site), and are declared below the declared type. Below an interface or an external type, a method a class
    /// inherits also counts when an own subtype of that class takes on the declared type (<c>class C : B, IProbe</c>
    /// runs <c>B.Run</c>), and so does every <see cref="IsOpen">open</see> type, whose platform supertypes the subtype
    /// map cannot see. Parameter types narrow the match only below an own class, and only where both sides are
    /// concrete; Model carries neither <c>newslot</c> nor <c>sealed</c>. All of this over-matches, which costs
    /// precision only, since these targets are added beside the resolution, never in its place. Hierarchy walks are
    /// bounded and count as a match past the bound. Memoized per declared shape. Never throws.
    /// </para>
    /// <para>
    /// The search is charged to <paramref name="work"/> (unlimited when null) per candidate considered and per hierarchy
    /// step, in proportion to the text hashed and compared. A memoized answer is charged what it cost to compute, once
    /// per <paramref name="work"/>; a repeat within it is free. Once <paramref name="work"/> is <see cref="DispatchWork.Exhausted">exhausted</see>
    /// this returns null for every call, so the caller must check it.
    /// </para>
    /// </summary>
    public IReadOnlyList<string>? DispatchTargets(IMethodReference? reference, MethodResolution resolution, bool virtualSite, DispatchWork? work = null)
    {
        if (reference is null || resolution.Definition is { IsVirtual: false, IsAbstract: false })
            return null;
        var isStatic = Guard(() => reference.IsStatic, false);
        if (!virtualSite && !isStatic)
            return null;

        var target = Guard<IMethodReference?>(() => reference.GenericMethod, null) ?? reference;
        var identity = ModelNames.Of(target);
        var declared = scope.Of(Guard<string?>(() => target.ContainingType?.ContainingAssembly?.Name, null), identity.DeclaringType).Keys;
        // Static virtual members exist only on interfaces: a static call into anything else is a plain call
        // (String.Concat, object.Equals), and so is one into a type nothing own derives from.
        if (!virtualSite && !declared.Any(k => MayBeInterface(k) && subtypes.ContainsKey(k)))
            return null;
        var name = ImplementedName(identity.MethodName);
        var arity = identity.GenericArity;
        var parameterTypes = identity.ParameterTypes;

        var memo = Key([declared.Count.ToString(CultureInfo.InvariantCulture), .. declared, name, arity.ToString(CultureInfo.InvariantCulture),
                        parameterTypes.Count.ToString(CultureInfo.InvariantCulture), .. parameterTypes, isStatic ? "static" : "instance"]);
        work ??= new DispatchWork(long.MaxValue);
        if (work.Exhausted)
            return null;
        // A memoized answer is charged what it cost to compute, once per build, so a build's work and where it runs out
        // do not depend on what earlier builds over this index computed.
        if (dispatched.TryGetValue(memo, out var known))
            return work.ChargeOnce(memo, known.Cost) ? known.Targets : null;
        var before = work.Spent;
        try
        {
            var targets = Dispatch(declared, name, arity, parameterTypes, isStatic, work);
            work.ChargeOnce(memo, 0);
            return dispatched.GetOrAdd(memo, new DispatchAnswer(targets, work.Spent - before)).Targets;
        }
        catch (WorkExhaustedException)
        {
            // Abandoned part-way: nothing is memoized, so a build with more work can still answer it.
            return null;
        }
    }

    /// <summary>
    /// True when <paramref name="typeNodeId"/> is an own class whose base-class chain leaves the index at a platform or
    /// dependency class other than <c>System.Object</c>, <c>System.ValueType</c>, <c>System.Enum</c> or a delegate
    /// base (<c>EnvStream : MemoryStream</c>): it may override a virtual of a type the subtype map never links it to.
    /// Over-approximate: a base that cannot be read, or a base chain that may run past 256 classes, also counts as open,
    /// and so does every type below an open one.
    /// </summary>
    public bool IsOpen(string typeNodeId) => open.Contains(typeNodeId);

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
        var (places, forwards) = Walk(
            assembly,
            Outermost(site.Target.DeclaringType),
            assemblySet,
            forwarders,
            current => new MethodResolution(ResolutionKind.External, site.NodeId, site.Key, current, null, [], null),
            current => Defined(current, site),
            place => place.Kind == ResolutionKind.Unresolved,
            (current, reason) => Unresolved(current, site, reason));

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

    // The forwarder walk behind Follow and TypeScope, over places of any kind: from an indexed assembly, breadth-first
    // over the forwards of the outermost type, each assembly once. An unindexed assembly is an external place; an indexed
    // one contributes its own definition (kept when it is not unresolved, or when nothing leads on), an unresolved place
    // per module export and per forward back to an assembly already visited, and ends unresolved when its table cannot
    // be read or the type is too unreadable to look up while it forwards anything.
    private static (List<T> Places, bool Forwards) Walk<T>(
        string assembly,
        (string Namespace, string Name)? outermost,
        HashSet<string> assemblies,
        IReadOnlyDictionary<string, TypeForwarders> forwarders,
        Func<string, T> external,
        Func<string, T> defined,
        Func<T, bool> isUnresolved,
        Func<string, string, T> unresolved)
    {
        var places = new List<T>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { assembly };
        var queue = new Queue<string>([assembly]);
        var forwards = false;
        while (queue.TryDequeue(out var current))
        {
            if (!assemblies.Contains(current))
            {
                places.Add(external(current));
                continue;
            }

            var table = forwarders.GetValueOrDefault(current) ?? TypeForwarders.Unreadable;
            if (!table.IsReadable || (table.Count > 0 && outermost is null))
            {
                places.Add(unresolved(current, table.IsReadable
                    ? $"the declaring type could not be read, and {current} forwards types"
                    : $"the type forwarders of {current} could not be read"));
                continue;
            }

            var onward = table.Count == 0 ? [] : table.Targets(outermost!.Value.Namespace, outermost.Value.Name);
            var modules = table.Count == 0 ? [] : table.Modules(outermost!.Value.Namespace, outermost.Value.Name);
            forwards |= onward.Count > 0;
            var here = defined(current);
            if ((onward.Count == 0 && modules.Count == 0) || !isUnresolved(here))
                places.Add(here);
            places.AddRange(modules.Select(m => unresolved(current, $"{current} exports this type from module file {m}, which is not indexed")));
            places.AddRange(onward.Where(next => seen.Contains(next))
                .Select(next => unresolved(next, $"the type forwarders of {current} lead back to {next}: a cycle, or a second way into it")));
            foreach (var next in onward.Where(seen.Add))
                queue.Enqueue(next);
        }
        return (places, forwards);
    }

    // The outermost declaring type, which is what a forwarder names; null when unreadable or truncated.
    private static (string Namespace, string Name)? Outermost(TypeIdentity type) =>
        type.NestingChain is [var name, ..] && name != CanonicalName.UnknownPart ? (type.Namespace ?? string.Empty, name) : null;

    // DispatchTargets for one declared shape. Starts from the methods of that shape, so the cost follows the candidates,
    // not the size of the hierarchy, and nothing per hierarchy is kept (review S1 W1). Each candidate and each hierarchy
    // step is charged to work, which throws WorkExhaustedException once spent: many unrelated types sharing one method
    // name make every shape scan every candidate, quadratic in a crafted assembly (review S1 round 2 W-A). The charge
    // follows the text hashed and compared (Units), since names cost an attacker almost nothing (round 3 W1).
    private IReadOnlyList<string> Dispatch(IReadOnlyList<string> declared, string name, int arity, IReadOnlyList<string> parameterTypes, bool isStatic, DispatchWork work)
    {
        var keys = declared.ToHashSet(StringComparer.Ordinal);
        // Only an own class hierarchy is narrowed by parameter types: an interface may be variant (IComparer<in T> runs
        // Compare(object, object) for a Compare(string, string) call), and an external type may be an interface.
        var narrow = declared.All(k => types.ContainsKey(k) && !interfaceIds.Contains(k));
        var external = !isStatic && declared.Any(k => !types.ContainsKey(k));
        // A static abstract member may be implemented by a static method inherited from a base class too (W-B).
        var inherited = declared.Any(MayBeInterface);
        // Nothing can be below a type nothing derives from: the common call on a leaf class costs nothing.
        if (!external && !inherited && !declared.Any(subtypes.ContainsKey))
            return [];

        var candidates = byImplementedShape.GetValueOrDefault(ImplementedShape(name, arity, parameterTypes.Count)) ?? [];
        // Each candidate's type id is hashed a few times, and under narrow MayOverride scans both sides' parameter types.
        var compared = narrow ? parameterTypes.Sum(Units) : 0;
        work.Charge(candidates.Sum(m => Units(m.DeclaringTypeId) + (narrow ? compared + m.Identity.ParameterTypes.Sum(Units) : 0)));
        var walk = new HierarchyWalk(this, keys, work);

        // A candidate declared in the declared type itself is the site's own target, not a dispatch target.
        return candidates
            .Where(m => !keys.Contains(m.DeclaringTypeId))
            .Where(m => isStatic ? m.Definition.IsStatic : !m.Definition.IsStatic && (m.Definition.IsVirtual || m.Definition.IsAbstract))
            .Where(m => !narrow || MayOverride(parameterTypes, m.Identity.ParameterTypes))
            .Where(m => walk.Below(m.DeclaringTypeId)
                || (external && open.Contains(m.DeclaringTypeId))
                || (inherited && walk.InheritedBelow(m.DeclaringTypeId)))
            .Select(m => m.NodeId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private IReadOnlyList<string> Supertypes(string key) =>
        supertypes.GetValueOrDefault(key) ?? implicitSupertypes.GetValueOrDefault(key) ?? [];

    // An external type might be one; an own type is one if any definition of it is; a platform root is not.
    private bool MayBeInterface(string key) =>
        !closedRoots.Contains(key) && (!types.ContainsKey(key) || interfaceIds.Contains(key));

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
            site.ReturnType,
            site.TypeArguments is null ? "?" : "=",
            .. site.TypeArguments ?? [],
        ]);
        var found = resolved.GetOrAdd(memo, _ => ResolveOwn(assembly, site.NodeId, site.Key, site.Target, site.ReturnType, site.TypeArguments));

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
    // compared exactly, return type included. A candidate is never excluded on a guess: two that render alike stay
    // Ambiguous. The return type is not in a node id, so it is what separates a sibling that shares one (an own
    // `int Q()` beside the `string Q()` a reference names, which the CLR looks up in a base type instead: review S1
    // C2); no match at all is Unresolved. When nothing can be checked - arguments that cannot be recovered, or a
    // signature that rendered truncated (<unknown>) or with a clamped array rank, so that a text match proves nothing
    // (CCI's reference truncates at its real depth, a candidate at another) - nothing is excluded: every same-shaped
    // candidate is kept, and even a lone one is Ambiguous.
    private MethodResolution ResolveOwn(string assembly, string nodeId, string key, MethodIdentity target, string returnType, IReadOnlyList<string>? typeArguments)
    {
        var truncated = target.ParameterTypes.Any(IsTruncated) || IsTruncated(returnType);
        var cannotCheck = typeArguments switch
        {
            null => "the instantiation's type arguments could not be recovered",
            { Count: > 0 } when truncated => "the instantiated signature could not be read in full",
            { Count: 0 } when truncated => "the signature could not be read in full",
            _ => null,
        };
        var sameShape = typeArguments is { Count: 0 } && cannotCheck is null
            ? []
            : InAssembly(byShape, Shape(CanonicalName.NodeId(target.DeclaringType), target.MethodName, target.GenericArity, target.ParameterTypes.Count), assembly);
        var matches = cannotCheck is not null || typeArguments is null ? sameShape
            : typeArguments.Count == 0
                ? InAssembly(byNodeId, CanonicalName.NodeId(target), assembly)
                    .Where(m => ModelNames.ReturnType(m.Definition, []) == returnType).ToArray()
            : sameShape.Where(m => ModelNames.ParameterTypes(m.Definition, typeArguments).SequenceEqual(target.ParameterTypes, StringComparer.Ordinal)
                && ModelNames.ReturnType(m.Definition, typeArguments) == returnType).ToArray();

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

    // A supertype is keyed where the CLR lands it (TypeScope). A struct's base, System.ValueType, is implicit in Model;
    // it is what makes a struct's ToString an override of Object's.
    private static (IndexedType Type, int Unresolved) IndexType(string assembly, string nodeId, ITypeDefinition type, TypeScope scope)
    {
        var supertypes = (type switch
        {
            ClassDefinition c => Prepend(c.Base, c.Interfaces),
            StructDefinition s => s.Interfaces.AsEnumerable(),
            InterfaceDefinition i => i.Interfaces.AsEnumerable(),
            _ => [],
        }).Select(scope.Of).ToArray();
        IEnumerable<string> implicitBase = type is StructDefinition ? ["System.ValueType"] : [];
        return (
            new IndexedType(
                assembly,
                nodeId,
                type,
                supertypes.SelectMany(s => s.Keys).Concat(implicitBase).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray()),
            supertypes.Count(s => s.Unresolved));
    }

    // See IsOpen. An id is open when a base of any of its definitions is unreadable or leaves the index at anything but a
    // closed root, when any indexed base is open, or when a base chain from it may run past MaxBaseDepth (over-
    // approximate); a base-class cycle alone is closed. Linear in definitions and base links: one file may define an id
    // many times over, and a walk per type was quadratic in that and in chain length (review S1 round 5 W1-r5).
    private static HashSet<string> OpenTypes(IReadOnlyDictionary<string, IReadOnlyList<IndexedType>> types, TypeScope scope)
    {
        var ids = types.Keys.Order(StringComparer.Ordinal).ToArray();
        var position = ids.Select((id, i) => (id, i)).ToDictionary(p => p.id, p => p.i, StringComparer.Ordinal);
        var open = new bool[ids.Length];
        var bases = new int[ids.Length][];
        for (var i = 0; i < ids.Length; i++)
        {
            var keys = types[ids[i]]
                .Select(t => Guard<IReadOnlyList<string>?>(() => t.Definition is ClassDefinition { Base: { } b } ? scope.Of(b).Keys : [], null))
                .ToArray();
            var distinct = keys.SelectMany(k => k ?? []).Distinct(StringComparer.Ordinal).ToArray();
            open[i] = keys.Any(k => k is null) || distinct.Any(k => !types.ContainsKey(k) && !closedRoots.Contains(k));
            bases[i] = distinct.Where(types.ContainsKey).Select(k => position[k]).ToArray();
        }

        // Open-ness flows from a base to every type below it, each type once.
        var height = BaseHeights(bases, MaxBaseDepth + 1);
        var below = Enumerable.Range(0, ids.Length).SelectMany(i => bases[i].Select(b => (Base: b, Sub: i))).ToLookup(p => p.Base, p => p.Sub);
        var queue = new Queue<int>(Enumerable.Range(0, ids.Length).Where(i => open[i] || height[i] > MaxBaseDepth));
        foreach (var i in queue)
            open[i] = true;
        while (queue.TryDequeue(out var i))
            foreach (var sub in below[i].Where(sub => !open[sub]))
            {
                open[sub] = true;
                queue.Enqueue(sub);
            }
        return ids.Where((_, i) => open[i]).ToHashSet(StringComparer.Ordinal);
    }

    // Per node, an upper bound on how deep a walk along next can reach before repeating a node, saturating at cap: up to
    // n edges inside a strongly connected component of n nodes that holds a cycle, a self-loop included (back round to
    // the start, as the old per-type walk counted one), none in a single node without one, plus one edge out to the
    // highest component below it. Tarjan's
    // algorithm, iterative since the graph is attacker-controlled; it completes every component below one before that
    // one, so each height is final when read.
    private static int[] BaseHeights(int[][] next, int cap)
    {
        var count = next.Length;
        var order = Enumerable.Repeat(-1, count).ToArray();
        var low = new int[count];
        var component = Enumerable.Repeat(-1, count).ToArray();
        var height = new int[count];
        var onStack = new bool[count];
        var stack = new Stack<int>();
        var visited = 0;
        var components = 0;
        for (var root = 0; root < count; root++)
        {
            if (order[root] >= 0)
                continue;
            var frames = new Stack<(int Node, int Edge)>([(root, 0)]);
            order[root] = low[root] = visited++;
            stack.Push(root);
            onStack[root] = true;
            while (frames.TryPop(out var frame))
            {
                var (node, edge) = frame;
                if (edge < next[node].Length)
                {
                    frames.Push((node, edge + 1));
                    var to = next[node][edge];
                    if (order[to] < 0)
                    {
                        order[to] = low[to] = visited++;
                        stack.Push(to);
                        onStack[to] = true;
                        frames.Push((to, 0));
                    }
                    else if (onStack[to])
                        low[node] = Math.Min(low[node], order[to]);
                    continue;
                }
                if (frames.TryPeek(out var parent))
                    low[parent.Node] = Math.Min(low[parent.Node], low[node]);
                if (low[node] != order[node])
                    continue;

                var members = new List<int>();
                int member;
                do
                {
                    member = stack.Pop();
                    onStack[member] = false;
                    component[member] = components;
                    members.Add(member);
                }
                while (member != node);
                var exit = members.SelectMany(m => next[m]).Where(to => component[to] != components).Select(to => 1 + height[to]).DefaultIfEmpty(0).Max();
                var cyclic = members.Count > 1 || next[node].Contains(node);
                var bound = Math.Min(cap, (cyclic ? members.Count : 0) + exit);
                foreach (var m in members)
                    height[m] = bound;
                components++;
            }
        }
        return height;
    }

    // The DispatchWork units for hashing or scanning text once: one per UnitLength characters, at least one.
    private static long Units(string text) => 1 + text.Length / UnitLength;

    // An override's parameters are the declared method's, exactly, after substitution - but a reference carries
    // substitutions the override does not (A1 review C1), so a position settles only when both sides are concrete: a
    // generic parameter (!0, !!0) or an unreadable part on either side matches anything. Over-matches only.
    private static bool MayOverride(IReadOnlyList<string> declared, IReadOnlyList<string> candidate) =>
        declared.Zip(candidate).All(p => p.First == p.Second || IsUnsettled(p.First) || IsUnsettled(p.Second));

    private static bool IsUnsettled(string rendered) =>
        rendered.Contains('!', StringComparison.Ordinal) || IsTruncated(rendered);

    // A rendering that stands for more than one type: cut at the depth bound, or an array rank clamped to the maximum.
    private static bool IsTruncated(string rendered) =>
        rendered.Contains(CanonicalName.UnknownPart, StringComparison.Ordinal) || rendered.Contains(clampedRank, StringComparison.Ordinal);

    // The name a method implements: its own, or the last segment of a C# explicit implementation's
    // ("System.Collections.Generic.IEnumerator<System.String>.get_Current" implements "get_Current"). Dots inside <...>
    // and a leading dot (".ctor") do not count.
    private static string ImplementedName(string? name)
    {
        if (name is null)
            return CanonicalName.UnknownPart;
        var depth = 0;
        for (var i = name.Length - 1; i > 0; i--)
        {
            switch (name[i])
            {
                case '>':
                    depth++;
                    break;
                case '<':
                    depth--;
                    break;
                case '.' when depth == 0:
                    return name[(i + 1)..];
            }
        }
        return name;
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

    private static string ImplementedShape(string name, int arity, int parameters) =>
        Key([name, arity.ToString(CultureInfo.InvariantCulture), parameters.ToString(CultureInfo.InvariantCulture)]);

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
    private readonly IReadOnlyDictionary<string, IReadOnlyList<IndexedMethod>> byImplementedShape;
    private readonly HashSet<string> assemblySet;
    private readonly IReadOnlyDictionary<string, TypeForwarders> forwarders;
    private readonly TypeScope scope;
    private readonly IReadOnlySet<string> open;
    private readonly HashSet<string> interfaceIds;
    private readonly HashSet<string> classIds;
    // Per type id: the distinct supertypes of all its definitions, ordinal-sorted so the walk does not depend on row
    // order, then its implicitSupertypes.
    private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> supertypes;

    // Resolution of a reference into an indexed assembly, keyed on every input ResolveOwn reads (see Defined) and
    // rebound to each reference's own id and key on a hit; memoized so a repeated call site costs one candidate scan.
    private readonly ConcurrentDictionary<string, MethodResolution> resolved = new(StringComparer.Ordinal);

    // DispatchTargets per (declared type keys, implemented name, arity, parameter types, static), with its cost.
    private readonly ConcurrentDictionary<string, DispatchAnswer> dispatched = new(StringComparer.Ordinal);

    // Platform bases an open-ness walk stops at: every own type's chain may end in one without hiding a supertype
    // (implicitSupertypes links each to System.Object).
    private static readonly HashSet<string> closedRoots = new(
        ["System.Object", "System.ValueType", "System.Enum", "System.Delegate", "System.MulticastDelegate"], StringComparer.Ordinal);

    // Supertypes of platform types the index cannot see, under their bare ids (generic arguments stripped, like every
    // key): the value-type and delegate roots, which Model leaves implicit (IndexType adds a struct's ValueType), and
    // the BCL collection interfaces, whose bases a hand-written InterfaceImpl may omit (review S1 W2, W3). Other
    // external interfaces' bases stay unknown. A package shadowing these names is not modelled.
    private static readonly Dictionary<string, string[]> implicitSupertypes = new(StringComparer.Ordinal)
    {
        ["System.ValueType"] = ["System.Object"],
        ["System.Enum"] = ["System.ValueType"],
        ["System.Delegate"] = ["System.Object"],
        ["System.MulticastDelegate"] = ["System.Delegate"],
        ["System.Collections.ICollection"] = ["System.Collections.IEnumerable"],
        ["System.Collections.IList"] = ["System.Collections.ICollection"],
        ["System.Collections.IDictionary"] = ["System.Collections.ICollection"],
        ["System.Collections.Generic.IEnumerable`1"] = ["System.Collections.IEnumerable"],
        ["System.Collections.Generic.IEnumerator`1"] = ["System.Collections.IEnumerator", "System.IDisposable"],
        ["System.Collections.Generic.ICollection`1"] = ["System.Collections.Generic.IEnumerable`1"],
        ["System.Collections.Generic.IList`1"] = ["System.Collections.Generic.ICollection`1"],
        ["System.Collections.Generic.ISet`1"] = ["System.Collections.Generic.ICollection`1"],
        ["System.Collections.Generic.IDictionary`2"] = ["System.Collections.Generic.ICollection`1"],
        ["System.Collections.Generic.IReadOnlyCollection`1"] = ["System.Collections.Generic.IEnumerable`1"],
        ["System.Collections.Generic.IReadOnlyList`1"] = ["System.Collections.Generic.IReadOnlyCollection`1"],
        ["System.Collections.Generic.IReadOnlyDictionary`2"] = ["System.Collections.Generic.IReadOnlyCollection`1"],
        ["System.Collections.Generic.IAsyncEnumerator`1"] = ["System.IAsyncDisposable"],
    };

    // The array suffix every rank at or above CanonicalName's clamp renders as.
    private static readonly string clampedRank = CanonicalName.ArrayOf("T", int.MaxValue)[1..];

    private const int MaxBaseDepth = 256;
    private const int MaxHierarchyWalk = 4096;
    private const int UnitLength = 64;
    #endregion

    #region Child types
    /// <summary>
    /// An indexed type definition and the subtype-map keys of its base and interfaces: definition-normalized node ids,
    /// following forwarders, <see cref="Qualified"/> when external and shadowed by an own type.
    /// </summary>
    public sealed record IndexedType(string Assembly, string NodeId, ITypeDefinition Definition, IReadOnlyList<string> Supertypes);

    /// <summary>An indexed method definition with its identity, node id and declaring type's node id.</summary>
    public sealed record IndexedMethod(string Assembly, string NodeId, string DeclaringTypeId, MethodIdentity Identity, MethodDefinition Definition);

    /// <summary>
    /// An allowance of class-hierarchy-analysis work shared by the <see cref="DispatchTargets"/> calls of one graph
    /// build: one unit per candidate considered and per hierarchy step, and one more per 64 characters of the type ids and
    /// parameter types each one hashes or compares; each declared shape charged once. Not thread-safe; one build at a time.
    /// </summary>
    public sealed class DispatchWork(long limit)
    {
        #region Properties
        /// <summary>The units allowed; a negative limit counts as 0.</summary>
        public long Limit { get; } = Math.Max(limit, 0);

        /// <summary>The units charged so far; <see cref="Limit"/> once <see cref="Exhausted"/>.</summary>
        public long Spent { get; private set; }

        /// <summary>True once a charge would have gone over <see cref="Limit"/>.</summary>
        public bool Exhausted { get; private set; }
        #endregion

        #region Methods
        // Charges units, abandoning the Dispatch in progress once the allowance is spent.
        internal void Charge(long units)
        {
            if (!Add(units))
                throw new WorkExhaustedException();
        }

        // Charges a memoized shape's cost unless this build already paid for it; false once the allowance is spent.
        internal bool ChargeOnce(string shape, long units) => !charged.Add(shape) ? !Exhausted : Add(units);

        // Capped at the limit, so where the work runs out never depends on how far past it the last charge reached.
        private bool Add(long units)
        {
            if (Exhausted || units > Limit - Spent)
            {
                Exhausted = true;
                Spent = Limit;
                return false;
            }
            Spent += units;
            return true;
        }
        #endregion

        #region Fields
        private readonly HashSet<string> charged = new(StringComparer.Ordinal);
        #endregion
    }

    // One reference being resolved: its own id and key, the definition-level identity behind it, and the
    // instantiation's type arguments.
    private readonly record struct Site(string NodeId, string Key, MethodIdentity Target, string ReturnType, IReadOnlyList<string>? TypeArguments);

    // Where a type reference lands, as subtype-map keys (A2 spec §1). One answer for supertypes and for a call site's
    // declared type, so CHA joins them on the same key: a type the CLR finds in an indexed assembly (following its
    // forwarders, as Follow does for methods) keeps its bare id; one in an unindexed assembly keeps it too, unless an own
    // type shares it, then it is Qualified by that assembly. A place the walk cannot settle is unresolved and keyed by
    // the bare id (and the Qualified one, when shadowed and the assembly is unreadable): over-approximate, and counted.
    private sealed class TypeScope(HashSet<string> assemblies, IReadOnlyDictionary<string, TypeForwarders> forwarders, IReadOnlyDictionary<string, HashSet<string>> definedIn)
    {
        #region Methods
        public TypeKeys Of(IBasicType? type) =>
            Of(Guard<string?>(() => type?.ContainingAssembly?.Name, null), ModelNames.Of(type));

        public TypeKeys Of(string? assembly, TypeIdentity identity)
        {
            var id = CanonicalName.NodeId(identity);
            if (assembly is null)
                return new(definedIn.ContainsKey(id) ? [id, Qualified(null, id)] : [id], true);
            var chain = identity.NestingChain ?? [];
            return memo.GetOrAdd(
                Key([assembly, identity.Namespace ?? string.Empty, chain.Count.ToString(CultureInfo.InvariantCulture), .. chain, identity.GenericArity.ToString(CultureInfo.InvariantCulture)]),
                _ => Land(assembly, id, identity));
        }

        private TypeKeys Land(string assembly, string id, TypeIdentity identity)
        {
            if (!assemblies.Contains(assembly))
                return new([External(assembly, id)], false);
            var (places, _) = Walk<string?>(
                assembly,
                Outermost(identity),
                assemblies,
                forwarders,
                current => External(current, id),
                current => definedIn.TryGetValue(id, out var where) && where.Contains(current) ? id : null,
                place => place is null,
                (_, _) => null);
            return new(places.Select(p => p ?? id).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(), places.Any(p => p is null));
        }

        private string External(string assembly, string id) => definedIn.ContainsKey(id) ? Qualified(assembly, id) : id;
        #endregion

        #region Fields
        private readonly ConcurrentDictionary<string, TypeKeys> memo = new(StringComparer.Ordinal);
        #endregion
    }

    // The subtype-map keys a type reference stands for, and whether any place it lands was unresolved.
    private sealed record TypeKeys(IReadOnlyList<string> Keys, bool Unresolved);

    // Thrown by DispatchWork.Charge once the work is spent, to abandon a Dispatch part-way; DispatchTargets catches it.
    private sealed class WorkExhaustedException : Exception;

    // A memoized DispatchTargets answer and the work it took to compute.
    private sealed record DispatchAnswer(IReadOnlyList<string> Targets, long Cost);

    // The hierarchy questions of one Dispatch, against one set of declared keys. What a walk settles is kept for the
    // next candidate - every type on a path that reaches a key is below it, every type of a walk that finds none is
    // not - so a long chain is walked about once per declared shape, not once per candidate (review S1 W1, case H).
    // Each walk is bounded, since the hierarchy is attacker-controlled: past the bound it counts as a match, and that
    // walk records nothing - though an InheritedBelow walk that takes such a Below as its hit records its own path, which
    // costs precision only (review S1 round 2 N-B). Every step is charged to work. Lives for one Dispatch only, so
    // nothing per hierarchy is retained.
    private sealed class HierarchyWalk(MemberIndex index, IReadOnlySet<string> keys, DispatchWork work)
    {
        #region Methods
        // True when typeId is a proper subtype of a key: up the indexed supertypes and the fixed platform links.
        public bool Below(string typeId) =>
            Search(typeId, index.Supertypes, t => keys.Contains(t) || below.Contains(t), below, notBelow);

        // True when typeId is an own class (not a declared type) with an own subtype below a key: the CLR fills an
        // interface slot from a method the subtype inherits (review S1 C1).
        public bool InheritedBelow(string typeId) =>
            !keys.Contains(typeId)
            && index.classIds.Contains(typeId)
            && Search(typeId, index.DirectSubtypes, t => inherits.Contains(t) || keys.Contains(t) || Below(t), inherits, inheritsNot);

        // Breadth-first from start (exclusive) along next, until a type satisfies hit. On a hit, start and every type on
        // the path to the hit are recorded in yes; on a full search without one, every type seen is recorded in no.
        private bool Search(string start, Func<string, IEnumerable<string>> next, Func<string, bool> hit, HashSet<string> yes, HashSet<string> no)
        {
            if (yes.Contains(start))
                return true;
            if (no.Contains(start))
                return false;
            var parent = new Dictionary<string, string?>(StringComparer.Ordinal) { [start] = null };
            var queue = new Queue<string>([start]);
            while (queue.TryDequeue(out var current))
            {
                foreach (var step in next(current))
                {
                    work.Charge(Units(step));
                    if (!parent.TryAdd(step, current))
                        continue;
                    if (hit(step))
                    {
                        for (string? node = current; node is not null; node = parent[node])
                            yes.Add(node);
                        return true;
                    }
                    if (parent.Count > MaxHierarchyWalk)
                        return true;
                    if (!no.Contains(step))
                        queue.Enqueue(step);
                }
            }
            no.UnionWith(parent.Keys);
            return false;
        }
        #endregion

        #region Fields
        private readonly HashSet<string> below = new(StringComparer.Ordinal);
        private readonly HashSet<string> notBelow = new(StringComparer.Ordinal);
        private readonly HashSet<string> inherits = new(StringComparer.Ordinal);
        private readonly HashSet<string> inheritsNot = new(StringComparer.Ordinal);
        #endregion
    }
    #endregion
}
