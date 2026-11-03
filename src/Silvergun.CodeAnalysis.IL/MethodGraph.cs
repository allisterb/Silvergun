namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Model.Bytecode;
using Model.Types;

/// <summary>What a <see cref="MethodNode"/> stands for.</summary>
public enum MethodNodeKind
{
    /// <summary>A method defined in an indexed assembly, with a body that is walked.</summary>
    OwnWithBody,

    /// <summary>A method defined in an indexed assembly with no body: abstract, interface, extern or P/Invoke.</summary>
    OwnBodyless,

    /// <summary>A leaf outside the indexed assemblies (the platform or an unindexed dependency), or a site we could not resolve.</summary>
    External
}

/// <summary>Why one method leads to another.</summary>
public enum MethodEdgeKind
{
    /// <summary>A <c>call</c> (or <c>jmp</c>) to its static target.</summary>
    Call,

    /// <summary>A <c>callvirt</c> to its declared target; overrides are added by CHA in phase A2.</summary>
    CallVirt,

    /// <summary>A <c>newobj</c> to the constructor.</summary>
    NewObj,

    /// <summary>An <c>ldftn</c>: the method becomes a delegate or function pointer, so it may run.</summary>
    Ldftn,

    /// <summary>An <c>ldvirtftn</c> to its declared target.</summary>
    Ldvirtftn,

    /// <summary>From an async/iterator stub to its compiler-generated <c>MoveNext</c> (phase A2).</summary>
    StateMachine,

    /// <summary>From a method that touches a type to that type's static constructor (phase A2).</summary>
    TypeInitializer
}

/// <summary>Why part of the program could not be followed. Opacity is reported, never dropped.</summary>
public enum OpacityKind
{
    /// <summary>A <c>calli</c> through a function pointer: the target is not in the instruction.</summary>
    IndirectCall,

    /// <summary>A call into an indexed assembly that named no definition we could find.</summary>
    Unresolved,

    /// <summary>A call that matched several definitions, or that a type forwarder sends somewhere besides a definition.</summary>
    Ambiguous,

    /// <summary>The module initializer is absent from the Analysis.Net model (phase A2).</summary>
    ModuleInitializerInvisible,

    /// <summary>A body whose instructions could not be read.</summary>
    BodyUnreadable,

    /// <summary>
    /// A call into an unindexed assembly whose node id is also an own method's — a package defining its own
    /// <c>System.Environment.GetEnvironmentVariable</c>, say. The two are kept apart (the external one under a
    /// <see cref="MemberIndex.Qualified"/> id) and the collision is reported: shadowing a platform name is a signal.
    /// </summary>
    NameShadowed
}

/// <summary>A method in the graph, keyed by its <see cref="CanonicalName"/> node id.</summary>
public sealed record MethodNode(string NodeId, string ClassificationKey, MethodNodeKind Kind);

/// <summary>One call site: <paramref name="From"/> leads to <paramref name="To"/> at IL offset <paramref name="Offset"/>.</summary>
public sealed record MethodEdge(string From, string To, MethodEdgeKind Kind, uint Offset);

/// <summary>A site the graph could not see through, with the reason.</summary>
public sealed record GraphOpacity(string Site, uint Offset, OpacityKind Kind, string Detail);

/// <summary>
/// Explicit size limits. A graph that reaches one is returned marked <see cref="GraphCoverage.Truncated"/> — one
/// 6.7 MB assembly alone peaked at 816 MB (ADR 0020 amendment item 5), so an unbounded build is not an option.
/// </summary>
public sealed record GraphBudget(int MaxNodes, int MaxEdges)
{
    #region Properties
    /// <summary>Generous defaults for a single package's own assemblies.</summary>
    public static GraphBudget Default { get; } = new(1_000_000, 5_000_000);
    #endregion
}

/// <summary>How each call-site reference was resolved (<see cref="ResolutionKind"/>).</summary>
public sealed record ResolutionCounts(int Exact, int Substituted, int External, int Ambiguous, int Unresolved)
{
    #region Properties
    /// <summary>All zero.</summary>
    public static ResolutionCounts None { get; } = new(0, 0, 0, 0, 0);
    #endregion

    #region Methods
    /// <summary>These counts with one more <paramref name="kind"/>.</summary>
    public ResolutionCounts Add(ResolutionKind kind) => kind switch
    {
        ResolutionKind.Exact => this with { Exact = Exact + 1 },
        ResolutionKind.Substituted => this with { Substituted = Substituted + 1 },
        ResolutionKind.External => this with { External = External + 1 },
        ResolutionKind.Ambiguous => this with { Ambiguous = Ambiguous + 1 },
        _ => this with { Unresolved = Unresolved + 1 },
    };
    #endregion
}

/// <summary>
/// What the build saw and what it could not see. "Could not analyze" must never read as "no capability", so this is a
/// first-class part of the graph (ADR 0020 decision 8). <see cref="Index"/> carries what the member index itself
/// could not read.
/// </summary>
public sealed record GraphCoverage(
    IndexCoverage Index,
    int MethodsIndexed,
    int BodiesRead,
    int BodiesFailed,
    int CallSites,
    ResolutionCounts Resolutions,
    bool Truncated,
    string? TruncatedBy);

/// <summary>
/// A call graph over the methods of a <see cref="MemberIndex"/> (ADR 0020). Phase A1 records each call site's
/// <b>static</b> target from Analysis.Net's bytecode instructions — the rung below three-address code, which needs no
/// stack simulation — and never runs the <c>Disassembler</c>. CHA fan-out of virtual calls, state-machine edges and
/// type-initializer edges are added in phase A2.
/// <para>
/// Every collection is ordinal-sorted, so two builds over the same input are identical. Unresolved and ambiguous
/// sites keep an edge to the reference's own node id as well as an opacity record, so no site is lost. Never throws.
/// </para>
/// </summary>
public sealed class MethodGraph
{
    #region Constructors
    private MethodGraph(IReadOnlyList<MethodNode> nodes, IReadOnlyList<MethodEdge> edges, IReadOnlyList<GraphOpacity> opacities, GraphCoverage coverage)
    {
        Nodes = nodes;
        Edges = edges;
        Opacities = opacities;
        Coverage = coverage;
        nodesById = nodes.ToDictionary(n => n.NodeId, StringComparer.Ordinal);
        successors = edges.GroupBy(e => e.From, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<MethodEdge>)g.ToArray(), StringComparer.Ordinal);
    }
    #endregion

    #region Properties
    /// <summary>Every node, ordered by node id.</summary>
    public IReadOnlyList<MethodNode> Nodes { get; }

    /// <summary>Every edge, ordered by source, target, kind and offset.</summary>
    public IReadOnlyList<MethodEdge> Edges { get; }

    /// <summary>Every opacity record, ordered by site, offset and kind.</summary>
    public IReadOnlyList<GraphOpacity> Opacities { get; }

    /// <summary>What was and was not analysed.</summary>
    public GraphCoverage Coverage { get; }
    #endregion

    #region Methods
    /// <summary>The node with <paramref name="nodeId"/>, or null.</summary>
    public MethodNode? Node(string nodeId) => nodesById.GetValueOrDefault(nodeId);

    /// <summary>The edges leaving <paramref name="nodeId"/>, in order.</summary>
    public IReadOnlyList<MethodEdge> Successors(string nodeId) => successors.GetValueOrDefault(nodeId) ?? [];

    /// <summary>
    /// Builds the static-target graph of <paramref name="index"/>. Stops adding when <paramref name="budget"/> is
    /// reached and marks the result truncated.
    /// </summary>
    public static MethodGraph Build(MemberIndex index, GraphBudget? budget = null)
    {
        var builder = new Builder(budget ?? GraphBudget.Default);
        foreach (var method in index.Methods)
            builder.AddOwn(method);
        foreach (var method in index.Methods.Where(m => m.Definition.HasBody))
            builder.Walk(index, method);
        return builder.ToGraph(index.Coverage, index.Methods.Count);
    }
    #endregion

    #region Fields
    private readonly IReadOnlyDictionary<string, MethodNode> nodesById;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<MethodEdge>> successors;
    #endregion

    #region Child types
    // The mutable half of the build, kept private so the graph itself is immutable.
    private sealed class Builder(GraphBudget budget)
    {
        #region Methods
        public void AddOwn(MemberIndex.IndexedMethod method)
        {
            var kind = method.Definition.HasBody ? MethodNodeKind.OwnWithBody : MethodNodeKind.OwnBodyless;
            // Methods differing only by return type share a node id (ADR 0019): merge them, keeping a body if any has one.
            if (nodes.TryGetValue(method.NodeId, out var existing))
            {
                if (kind == MethodNodeKind.OwnWithBody)
                    nodes[method.NodeId] = existing with { Kind = kind };
            }
            else if (Room(nodes.Count, budget.MaxNodes, "nodes"))
                nodes[method.NodeId] = new MethodNode(method.NodeId, CanonicalName.ClassificationKey(method.Identity), kind);
        }

        public void Walk(MemberIndex index, MemberIndex.IndexedMethod method)
        {
            if (truncatedBy is not null)
                return;

            Model.IInstruction[] instructions;
            try
            {
                if (method.Definition.Body.Kind != MethodBodyKind.Bytecode)
                    throw new InvalidOperationException($"body is {method.Definition.Body.Kind}, not bytecode");
                instructions = [.. method.Definition.Body.Instructions];
            }
            catch (Exception ex)
            {
                bodiesFailed++;
                opacities.Add(new GraphOpacity(method.NodeId, 0, OpacityKind.BodyUnreadable, ex.Message));
                return;
            }

            bodiesRead++;
            foreach (var instruction in instructions)
                Visit(index, method.NodeId, instruction);
        }

        public MethodGraph ToGraph(IndexCoverage index, int methodsIndexed) =>
            new(
                [.. nodes.Values.OrderBy(n => n.NodeId, StringComparer.Ordinal)],
                [.. edges.OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Kind).ThenBy(e => e.Offset)],
                [.. opacities.OrderBy(o => o.Site, StringComparer.Ordinal).ThenBy(o => o.Offset).ThenBy(o => o.Kind).ThenBy(o => o.Detail, StringComparer.Ordinal)],
                new GraphCoverage(index, methodsIndexed, bodiesRead, bodiesFailed, callSites, resolutions, truncatedBy is not null, truncatedBy));

        private void Visit(MemberIndex index, string caller, Model.IInstruction instruction)
        {
            var offset = instruction is Instruction bytecode ? bytecode.Offset : 0;
            switch (instruction)
            {
                case MethodCallInstruction call:
                    AddCall(index, caller, offset, call.Method, call.Operation == MethodCallOperation.Virtual ? MethodEdgeKind.CallVirt : MethodEdgeKind.Call);
                    break;
                case CreateObjectInstruction create:
                    AddCall(index, caller, offset, create.Constructor, MethodEdgeKind.NewObj);
                    break;
                case LoadMethodAddressInstruction load:
                    AddCall(index, caller, offset, load.Method, load.Operation == LoadMethodAddressOperation.Virtual ? MethodEdgeKind.Ldvirtftn : MethodEdgeKind.Ldftn);
                    break;
                case IndirectMethodCallInstruction when truncatedBy is null:
                    callSites++;
                    opacities.Add(new GraphOpacity(caller, offset, OpacityKind.IndirectCall, "calli through a function pointer"));
                    break;
            }
        }

        private void AddCall(MemberIndex index, string caller, uint offset, IMethodReference target, MethodEdgeKind kind)
        {
            if (truncatedBy is not null)
                return;

            callSites++;
            var resolution = index.Resolve(target);
            resolutions = resolutions.Add(resolution.Kind);

            // An own target, or every candidate of an ambiguous one (over-approximate: never pick one and drop the
            // rest; a candidate that is not own code - the target of a type forwarder - is already Qualified).
            // Anything else is a leaf under the reference's own id - qualified by its assembly when that id is also
            // an own method's, so an external sink can never merge into a same-named own node and be walked through
            // its body instead of being classified. An Unresolved site is qualified the same way (even by an
            // indexed assembly's name): its id matching an own method is textual, not a verified resolution, so it
            // stays a separate leaf - it already carries an Unresolved opacity, so no NameShadowed is added.
            var shadowed = !resolution.IsOwn && resolution.Kind != ResolutionKind.Ambiguous && index.IsOwnMethod(resolution.NodeId);
            var leaf = shadowed ? MemberIndex.Qualified(resolution.Assembly, resolution.NodeId) : resolution.NodeId;

            if (resolution.Kind is ResolutionKind.Unresolved or ResolutionKind.Ambiguous)
                opacities.Add(new GraphOpacity(
                    caller,
                    offset,
                    resolution.Kind == ResolutionKind.Ambiguous ? OpacityKind.Ambiguous : OpacityKind.Unresolved,
                    $"{(resolution.Kind == ResolutionKind.Ambiguous ? resolution.NodeId : leaf)}: {resolution.Reason}"));
            if (shadowed && resolution.Kind == ResolutionKind.External)
                opacities.Add(new GraphOpacity(caller, offset, OpacityKind.NameShadowed,
                    $"{resolution.NodeId} in {resolution.Assembly} shares its name with an own method{(resolution.Reason is { } reason ? $" ({reason})" : "")}"));

            IReadOnlyList<string> targets = resolution.Kind == ResolutionKind.Ambiguous && resolution.Candidates.Count > 0
                ? resolution.Candidates
                : [leaf];

            foreach (var to in targets)
            {
                if (!nodes.ContainsKey(to))
                {
                    if (!Room(nodes.Count, budget.MaxNodes, "nodes"))
                        return;
                    nodes[to] = new MethodNode(to, resolution.ClassificationKey, MethodNodeKind.External);
                }

                if (!Room(edges.Count, budget.MaxEdges, "edges"))
                    return;
                edges.Add(new MethodEdge(caller, to, kind, offset));
            }
        }

        // True while there is room; the first time a budget is hit the build is marked truncated and stops.
        private bool Room(int count, int max, string what)
        {
            if (count < max)
                return true;
            truncatedBy ??= $"{what} budget of {max} reached";
            return false;
        }
        #endregion

        #region Fields
        private readonly Dictionary<string, MethodNode> nodes = new(StringComparer.Ordinal);
        private readonly List<MethodEdge> edges = [];
        private readonly List<GraphOpacity> opacities = [];
        private ResolutionCounts resolutions = ResolutionCounts.None;
        private int bodiesRead;
        private int bodiesFailed;
        private int callSites;
        private string? truncatedBy;
        #endregion
    }
    #endregion
}
