namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Model.Types;

/// <summary>
/// The kinds of entry point an own method is (ADR 0037 decision 4). Every own method stays a root; these say who can make
/// it run. A method may carry several; <see cref="Hidden"/> exactly when it carries no other.
/// </summary>
[Flags]
public enum RootClass
{
    /// <summary>No class: only ever the value of an empty mask.</summary>
    None = 0,

    /// <summary>Runs when its assembly loads: a <c>root-attribute … LoadTime</c> method (C#'s <c>[ModuleInitializer]</c>).</summary>
    LoadTime = 1,

    /// <summary>Called by a build host (MSBuild, the compiler, the IDE): every method of an own type below a <c>host-contract</c> type.</summary>
    HostContract = 2,

    /// <summary>Called by the runtime: a <c>.cctor</c>, a <c>Finalize</c> override, a <c>root-attribute … RuntimeInvoked</c> method.</summary>
    RuntimeInvoked = 4,

    /// <summary>Callable by a consumer: externally visible on an externally visible type, or an explicit implementation on one.</summary>
    PublicApi = 8,

    /// <summary>
    /// Reachable by a consumer through a visible virtual slot: an own override or implementation CHA finds below a
    /// <see cref="PublicApi"/> virtual, or one filling a slot declared outside the index (<see cref="MemberIndex.ImplementsExternalSlot"/>).
    /// </summary>
    PublicContract = 16,

    /// <summary>None of the above: reachable only from code no consumer can name (reflection, serialization), or dead.</summary>
    Hidden = 32
}

/// <summary>
/// What reachability needs to know about one own graph node. <paramref name="Assembly"/> is the ordinal-least assembly
/// defining it. <paramref name="NativeImport"/> marks a P/Invoke and <paramref name="ComImport"/> a body-less member of a
/// <c>[ComImport]</c> type (a COM call), both <c>NativeInterop</c> sinks. <paramref name="InternalCall"/> marks any other
/// concrete body-less extern but a delegate's runtime methods (an <c>internalcall</c> a Mono or Unity host may bind to
/// native code), an unseen sink.
/// </summary>
public sealed record OwnMethodFacts(string NodeId, string Assembly, string DeclaringTypeId, RootClass Roots, bool NativeImport, bool IsStatic, bool InternalCall = false, bool ComImport = false);

/// <summary>
/// One own type. <paramref name="Live"/>: it, or an own subtype, is concrete and either instantiated by the package
/// (<c>newobj</c>), a value type, or constructible by a consumer — so a dispatch to it may really happen (the RTA tier).
/// </summary>
public sealed record OwnTypeFacts(string TypeId, string Assembly, bool Live);

/// <summary>A root class that could not be computed in full for <paramref name="Assembly"/>, with why.</summary>
public sealed record RootGap(string Assembly, RootClass Class, string Reason);

/// <summary>
/// The per-node and per-type facts of a <see cref="MethodGraph"/>, captured at build while the <see cref="MemberIndex"/>
/// is alive (a <see cref="PackageGraph"/> outlives its index). Each list is ordinal-sorted.
/// </summary>
public sealed record GraphFacts(IReadOnlyList<OwnMethodFacts> Methods, IReadOnlyList<OwnTypeFacts> Types, IReadOnlyList<RootGap> Gaps)
{
    #region Properties
    /// <summary>No facts.</summary>
    public static GraphFacts None { get; } = new([], [], []);
    #endregion

    #region Methods
    /// <summary>
    /// Collects the facts of the own nodes <paramref name="ownNodeIds"/> from <paramref name="index"/>: root classes from
    /// visibility, the map's <c>root-attribute</c> and <c>host-contract</c> entries, and CHA. The slot check
    /// (<see cref="MemberIndex.ImplementsExternalSlot"/>) and the CHA targets are each charged to their own fresh
    /// <see cref="MemberIndex.DispatchWork"/> of <paramref name="maxDispatchWork"/>. Type liveness comes from the
    /// <c>NewObj</c> targets in <paramref name="edges"/>. Unknown visibility counts as visible, and every root class
    /// left uncertain is a <see cref="RootGap"/>. Never throws: a method whose facts cannot be read is tagged
    /// <see cref="RootClass.PublicApi"/> and counted in a gap.
    /// </summary>
    internal static GraphFacts Collect(MemberIndex index, IReadOnlySet<string> ownNodeIds, IEnumerable<MethodEdge> edges, CapabilityMap map, long maxDispatchWork)
    {
        try
        {
            return new Collector(index, map, maxDispatchWork).Run(ownNodeIds, edges);
        }
        catch (Exception ex)
        {
            // Nothing known, so nothing may read as None: every node a PublicApi root, every type live, every class a gap.
            return new GraphFacts(
                [.. ownNodeIds.Order(StringComparer.Ordinal).Select(id => new OwnMethodFacts(id, CanonicalName.UnknownPart, CanonicalName.UnknownPart, RootClass.PublicApi, false, false))],
                [.. (Fallback(() => index.TypeIds.ToArray()) ?? []).Select(id => new OwnTypeFacts(id, CanonicalName.UnknownPart, true))],
                [new RootGap(CanonicalName.UnknownPart, AllClasses, $"root facts could not be collected: {ex.Message}")]);
        }
    }

    private static T? Fallback<T>(Func<T> read) where T : class
    {
        try
        {
            return read();
        }
        catch (Exception)
        {
            return null;
        }
    }
    #endregion

    #region Fields
    private static readonly HashSet<string> delegateRuntimeMethods = new(StringComparer.Ordinal) { ".ctor", "Invoke", "BeginInvoke", "EndInvoke" };

    private const RootClass AllClasses =
        RootClass.LoadTime | RootClass.HostContract | RootClass.RuntimeInvoked | RootClass.PublicApi | RootClass.PublicContract | RootClass.Hidden;
    #endregion

    #region Child types
    private sealed class Collector(MemberIndex index, CapabilityMap map, long maxDispatchWork)
    {
        #region Methods
        public GraphFacts Run(IReadOnlySet<string> ownNodeIds, IEnumerable<MethodEdge> edges)
        {
            var methods = index.Methods.Where(m => ownNodeIds.Contains(m.NodeId)).ToArray();
            var hostTypes = map.HostContracts.SelectMany(index.TypesBelow).ToHashSet(StringComparer.Ordinal);

            // Paired, not keyed by method: one file may define a method twice, and Model's definitions compare by signature.
            // A slot declared outside the index (rule b) is computed first, so its own overrides are CHA targets too (rule a).
            var classified = methods
                .Select(m => (Method: m, Roots: Classify(m, hostTypes)))
                .Select(c => (c.Method, c.Roots, ExternalSlot: !c.Roots.HasFlag(RootClass.PublicApi) && Guard(() => index.ImplementsExternalSlot(c.Method, slotWork), true)))
                .ToArray();
            var contracts = ContractTargets(classified.Where(c => c.Roots.HasFlag(RootClass.PublicApi) || c.ExternalSlot).Select(c => c.Method));

            var facts = classified
                .GroupBy(c => c.Method.NodeId, StringComparer.Ordinal)
                .Select(g =>
                {
                    var first = g.First().Method;
                    var mask = g.Aggregate(RootClass.None, (acc, c) => acc | c.Roots);
                    if (!mask.HasFlag(RootClass.PublicApi) && (contracts.Contains(g.Key) || g.Any(c => c.ExternalSlot)))
                        mask |= RootClass.PublicContract;
                    return new OwnMethodFacts(g.Key, first.Assembly, first.DeclaringTypeId, mask == RootClass.None ? RootClass.Hidden : mask,
                        g.Any(c => Guard(() => c.Method.Definition.IsExternal && c.Method.Definition.IsPlatformInvoke, false)),
                        g.Any(c => Guard(() => c.Method.Definition.IsStatic, false)),
                        g.Any(c => Guard(() => IsInternalCall(c.Method.Definition), true)),
                        g.Any(c => Guard(() => IsComCall(c.Method.Definition), false)));
                })
                .OrderBy(f => f.NodeId, StringComparer.Ordinal)
                .ToArray();

            var instantiated = edges.Where(e => e.Kind == MethodEdgeKind.NewObj)
                .SelectMany(e => index.Definitions(e.To).Select(m => m.DeclaringTypeId))
                .ToHashSet(StringComparer.Ordinal);
            var types = LiveTypes(instantiated);

            var gaps = unknownVisibility
                .Select(u => new RootGap(u.Key, RootClass.PublicApi | RootClass.Hidden, $"visibility unknown for {u.Value} method(s); counted as PublicApi"))
                .Concat(unreadable.Select(u => new RootGap(u.Key, RootClass.PublicApi | RootClass.Hidden, $"root facts unreadable for {u.Value} method(s); counted as PublicApi")))
                .Concat(index.Assemblies.Select(a => (Assembly: a, Module: index.Module(a))).SelectMany(ModuleGaps))
                .Concat(dispatchWork.Exhausted
                    ? [new RootGap(CanonicalName.UnknownPart, RootClass.PublicContract, "dispatch work budget reached while finding PublicContract targets")]
                    : [])
                // Past its budget every remaining virtual counts as filling an external slot: more PublicContract roots,
                // so a capability reached only from Hidden ones may be missed.
                .Concat(slotWork.Exhausted
                    ? [new RootGap(CanonicalName.UnknownPart, RootClass.Hidden, "slot work budget reached; the remaining virtual methods were counted as PublicContract")]
                    : [])
                .OrderBy(g => g.Assembly, StringComparer.Ordinal).ThenBy(g => g.Class).ThenBy(g => g.Reason, StringComparer.Ordinal)
                .ToArray();

            return new GraphFacts(facts, types, gaps);
        }

        private RootClass Classify(MemberIndex.IndexedMethod method, IReadOnlySet<string> hostTypes)
        {
            var mask = RootClass.None;
            try
            {
                var definition = method.Definition;
                foreach (var attribute in Attributes(definition))
                    if (map.RootAttributes.TryGetValue(attribute, out var conferred) && (conferred != RootClass.LoadTime || definition.IsStatic))
                        mask |= conferred;
                if (hostTypes.Contains(method.DeclaringTypeId))
                    mask |= RootClass.HostContract;
                if (IsTypeInitializer(definition) || IsFinalizer(method))
                    mask |= RootClass.RuntimeInvoked;

                switch (MethodVisible(definition))
                {
                    case true:
                        mask |= RootClass.PublicApi;
                        break;
                    case null:
                        mask |= RootClass.PublicApi;
                        Count(unknownVisibility, method.Assembly);
                        break;
                }
                return mask;
            }
            catch (Exception)
            {
                // Keep what was already found; what was not is assumed callable.
                Count(unreadable, method.Assembly);
                return mask | RootClass.PublicApi;
            }
        }

        // Own methods CHA finds below each visible virtual or abstract own method: what a consumer's call through the
        // visible slot may run.
        private HashSet<string> ContractTargets(IEnumerable<MemberIndex.IndexedMethod> visible) =>
            visible
                .Where(m => Guard(() => !m.Definition.IsStatic && (m.Definition.IsVirtual || m.Definition.IsAbstract), false))
                .SelectMany(m => Guard(() => index.DispatchTargets(m.Definition, index.Resolve(m.Definition), virtualSite: true, dispatchWork), null) ?? [])
                .ToHashSet(StringComparer.Ordinal);

        // A type is live when it or an own subtype is concrete and instantiated, a value type, or constructible from
        // outside: seeded at those types and propagated up their own supertypes.
        private OwnTypeFacts[] LiveTypes(IReadOnlySet<string> instantiated)
        {
            var ids = index.TypeIds.ToArray();
            var live = new HashSet<string>(StringComparer.Ordinal);
            var queue = new Queue<string>();
            foreach (var id in ids)
                if (index.Types(id).Any(t => Guard(() => IsLiveSeed(t.Definition, instantiated.Contains(id)), true)) && live.Add(id))
                    queue.Enqueue(id);
            while (queue.TryDequeue(out var id))
                foreach (var super in index.SupertypeKeys(id))
                    if (index.Types(super).Count > 0 && live.Add(super))
                        queue.Enqueue(super);
            return ids.Select(id => new OwnTypeFacts(id, index.Types(id).Select(t => t.Assembly).Order(StringComparer.Ordinal).First(), live.Contains(id))).ToArray();
        }

        private static bool IsLiveSeed(ITypeDefinition type, bool instantiated) => type switch
        {
            StructDefinition or EnumDefinition => true,
            ClassDefinition { IsAbstract: false } c => instantiated || IsConstructible(c),
            _ => false,
        };

        // Externally visible (or unknown) with an instance constructor a consumer may call, directly or from a subclass.
        private static bool IsConstructible(ClassDefinition type) =>
            TypeVisible(type) != false
            && type.Methods.Any(m => m.IsConstructor && !m.IsStatic && MemberVisible(m.Visibility, IsSealed(type)) != false);

        private static IEnumerable<RootGap> ModuleGaps((string Assembly, ModuleMetadata Module) module) =>
            !module.Module.IsReadable
                ? [new RootGap(module.Assembly, RootClass.LoadTime, "module metadata unreadable: whether a module initializer runs at load is unknown")]
                : module.Module.HasModuleInitializer
                    ? [new RootGap(module.Assembly, RootClass.LoadTime, "<Module>..cctor runs at load and is invisible to the model")]
                    : [];

        private static IEnumerable<string> Attributes(MethodDefinition method) =>
            method.Attributes.Select(a => a.Type is IBasicType type ? CanonicalName.ClassificationKey(ModelNames.Of(type)) : null).OfType<string>();

        // External but no P/Invoke or COM call: internalcall, runtime-implemented, or a concrete method with no IL. CCI's
        // IsExternal is also true of every abstract and interface method (RVA 0), which has no body to run. A delegate's
        // runtime methods run what the delegate was bound to, which the graph already follows from the ldftn; any other
        // member of a delegate type, or one of those names flagged internalcall or not runtime-implemented, is not exempt.
        private static bool IsInternalCall(MethodDefinition method) =>
            method.IsExternal && !method.IsAbstract && !method.IsPlatformInvoke && !IsComCall(method) && !IsDelegateRuntimeMethod(method);

        // A body-less member of a [ComImport] class or interface: the runtime sends the call to a COM object.
        private static bool IsComCall(MethodDefinition method) =>
            method.IsExternal && method.ContainingType is ClassDefinition { IsComImport: true } or InterfaceDefinition { IsComImport: true };

        private static bool IsDelegateRuntimeMethod(MethodDefinition method) =>
            method is { IsStatic: false, IsRuntimeImplemented: true, IsRuntimeInternal: false, ContainingType: ClassDefinition { IsDelegate: true } }
            && delegateRuntimeMethods.Contains(method.Name);

        private static bool IsTypeInitializer(MethodDefinition method) =>
            method.IsStatic && method.Name == ".cctor" && method.Parameters.Count == 0;

        // Overrides Object.Finalize: instance, virtual, not newslot, no parameters, not generic.
        private static bool IsFinalizer(MemberIndex.IndexedMethod method) =>
            method.Definition is { Name: "Finalize", IsStatic: false, IsVirtual: true, IsNewSlot: false }
            && method.Identity.ParameterTypes.Count == 0 && method.Identity.GenericArity == 0;

        // A consumer can call it: visible on a visible type, or a private explicit implementation on a visible type.
        // Null when visibility is unknown somewhere on the way.
        private static bool? MethodVisible(MethodDefinition method)
        {
            var type = method.ContainingType;
            var member = method.Visibility == VisibilityKind.Private && MemberIndex.ImplementedName(method.Name) != method.Name
                ? true
                : MemberVisible(method.Visibility, IsSealed(type));
            return And(member, TypeVisible(type));
        }

        // A namespace type is visible when public; a nested one when visible as a member of a visible container.
        private static bool? TypeVisible(ITypeDefinition? type)
        {
            var depth = 0;
            bool? visible = true;
            for (var t = type; t is not null && visible != false; t = t.ContainingType)
            {
                if (++depth > MaxNesting)
                    return null;
                visible = And(visible, t.ContainingType is null
                    ? t.Visibility switch { VisibilityKind.Public => true, VisibilityKind.Unknown => null, _ => false }
                    : MemberVisible(t.Visibility, IsSealed(t.ContainingType)));
            }
            return visible;
        }

        // Family members are reachable from outside only through a subclass, so not on a sealed type.
        private static bool? MemberVisible(VisibilityKind visibility, bool sealedContainer) => visibility switch
        {
            VisibilityKind.Public => true,
            VisibilityKind.Family or VisibilityKind.FamilyOrAssembly => !sealedContainer,
            VisibilityKind.Unknown => null,
            _ => false,
        };

        private static bool IsSealed(ITypeDefinition? type) =>
            type is ClassDefinition { IsSealed: true } or StructDefinition or EnumDefinition;

        private static bool? And(bool? a, bool? b) => a == false || b == false ? false : a is null || b is null ? null : true;

        private static void Count(SortedDictionary<string, int> counts, string assembly) =>
            counts[assembly] = counts.GetValueOrDefault(assembly) + 1;

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
        // Separate allowances, so a crafted hierarchy that exhausts one still leaves the other its full budget.
        private readonly MemberIndex.DispatchWork dispatchWork = new(maxDispatchWork);
        private readonly MemberIndex.DispatchWork slotWork = new(maxDispatchWork);
        private readonly SortedDictionary<string, int> unknownVisibility = new(StringComparer.Ordinal);
        private readonly SortedDictionary<string, int> unreadable = new(StringComparer.Ordinal);

        private const int MaxNesting = 256;
        #endregion
    }
    #endregion
}
