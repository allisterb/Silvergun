namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// A <b>test-side</b>, deliberately naive view of the mechanism fixture's own methods and their <em>direct</em>
/// call sites, read from raw CCI through <see cref="CciNames"/>/<see cref="CanonicalName"/> — the same naming the
/// CHA graph keys on. It exists so the ground-truth table can be checked against the real fixture before any graph
/// exists: every waypoint must name a real node, every sink must classify as intended, every twin must call only
/// safe or unclassified platform APIs.
/// <para>
/// It is <b>not</b> a call graph and must not grow into one: no CHA, no state-machine or type-initializer edges,
/// no resolution. A call site through a generic instantiation is mapped back to its definition with the
/// reference-side <see cref="IGenericMethodInstanceReference.GenericMethod"/> /
/// <see cref="ISpecializedMethodReference.UnspecializedVersion"/> links only, so <c>Box&lt;int&gt;.Run</c> is named
/// <c>Box`1.Run()</c>. Safe to name signatures with <see cref="CciNames.Of(IMethodReference)"/> here (the
/// <c>TypedReference</c> FailFast of ADR-0021 needs a signature this fixture does not contain).
/// </para>
/// </summary>
public sealed class MechanismCallSites
{
    #region Constructors
    private MechanismCallSites(
        IReadOnlyDictionary<string, OwnMethod> definitions,
        IReadOnlyDictionary<string, string> targets,
        IReadOnlyDictionary<string, IReadOnlyList<string>> edges,
        IReadOnlyList<Site> sites)
    {
        Definitions = definitions;
        Targets = targets;
        Edges = edges;
        Sites = sites;
    }
    #endregion

    #region Properties
    /// <summary>Every method DEFINED in the read assemblies (bodied, abstract and extern alike), by node id.</summary>
    public IReadOnlyDictionary<string, OwnMethod> Definitions { get; }

    /// <summary>Every call-site target (call, callvirt, newobj, ldftn, ldvirtftn) → its classification key.</summary>
    public IReadOnlyDictionary<string, string> Targets { get; }

    /// <summary>Own method node id → the node ids its body directly references, in IL order, de-duplicated.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Edges { get; }

    /// <summary>
    /// Every call-site instruction, one record each, in read order: the caller, the IL offset, and the node id of the
    /// definition CCI says it names (instantiations mapped back via <c>UnspecializedVersion</c>/<c>GenericMethod</c>).
    /// The per-site, resolution-free oracle the A1 graph is checked against.
    /// </summary>
    public IReadOnlyList<Site> Sites { get; }

    /// <summary>Every node id known here — definitions and call-site targets — ordinally sorted.</summary>
    public IReadOnlyList<string> AllNodeIds =>
        Definitions.Keys.Union(Targets.Keys, StringComparer.Ordinal).OrderBy(id => id, StringComparer.Ordinal).ToArray();
    #endregion

    #region Methods
    /// <summary>Reads every type and method of <paramref name="assemblies"/>. Throws on anything unexpected.</summary>
    public static MechanismCallSites Read(params AssemblyAnalyzer[] assemblies)
    {
        var definitions = new Dictionary<string, OwnMethod>(StringComparer.Ordinal);
        var targets = new Dictionary<string, string>(StringComparer.Ordinal);
        var edges = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        var sites = new List<Site>();

        foreach (var method in assemblies.SelectMany(a => a.Module.GetAllTypes()).SelectMany(t => t.Methods))
        {
            var identity = CciNames.Of(method);
            var nodeId = CanonicalName.NodeId(identity);
            var read = AssemblyAnalyzer.TryReadBody(method);
            if (read.IsUnreadable)
                throw new InvalidOperationException($"Fixture method '{nodeId}' has an unreadable body: {read.Error}");

            var own = new OwnMethod(
                nodeId,
                CanonicalName.ClassificationKey(identity),
                AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition),
                method.Name.Value,
                read.Body is not null);

            if (!definitions.TryAdd(nodeId, own))
                throw new InvalidOperationException($"Two fixture methods share the node id '{nodeId}'.");

            if (read.Body is null)
                continue;

            var successors = new List<string>();
            foreach (var op in read.Body.Operations)
            {
                if (!IsCallSite(op.OperationCode) || op.Value is not IMethodReference reference)
                    continue;

                var target = CciNames.Of(Definition(reference));
                var targetId = CanonicalName.NodeId(target);
                targets[targetId] = CanonicalName.ClassificationKey(target);
                sites.Add(new Site(nodeId, op.Offset, targetId));
                if (!successors.Contains(targetId, StringComparer.Ordinal))
                    successors.Add(targetId);
            }

            edges[nodeId] = successors;
        }

        return new MechanismCallSites(definitions, targets, edges, sites);
    }

    /// <summary>
    /// Every node reachable from <paramref name="start"/> over direct edges (start included), ordinally sorted.
    /// Visited-set bounded; a strict under-approximation of what the CHA graph will reach.
    /// </summary>
    public IReadOnlyList<string> DirectlyReachable(string start)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { start };
        var queue = new Queue<string>([start]);
        while (queue.Count > 0)
            foreach (var next in Edges.GetValueOrDefault(queue.Dequeue()) ?? [])
                if (seen.Add(next))
                    queue.Enqueue(next);

        return seen.OrderBy(id => id, StringComparer.Ordinal).ToArray();
    }

    private static bool IsCallSite(OperationCode code) =>
        code is OperationCode.Call or OperationCode.Callvirt or OperationCode.Newobj
            or OperationCode.Ldftn or OperationCode.Ldvirtftn;

    // Reference-side only: the generic method behind an instantiation, the unspecialized member behind a member
    // of a generic type instance. Bounded, since the links are attacker-shaped in general (not here).
    private static IMethodReference Definition(IMethodReference method)
    {
        for (var depth = 0; depth < MaxDepth; depth++)
        {
            if (method is IGenericMethodInstanceReference instance) method = instance.GenericMethod;
            else if (method is ISpecializedMethodReference specialized) method = specialized.UnspecializedVersion;
            else break;
        }

        return method;
    }
    #endregion

    #region Fields
    private const int MaxDepth = 8;
    #endregion

    #region Child types
    /// <summary>
    /// One own method: its node id and classification key, the (CallerType, CallerMethod) pair
    /// <see cref="CapabilityAnalysis"/> attributes findings to, and whether it has an IL body.
    /// </summary>
    public sealed record OwnMethod(string NodeId, string ClassificationKey, string CallerType, string CallerMethod, bool HasBody);

    /// <summary>One call-site instruction: its caller, IL offset, and the node id of the definition it names.</summary>
    public sealed record Site(string Caller, uint Offset, string Target);
    #endregion
}
