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

    /// <summary>A <c>callvirt</c> to its declared target; overrides are <see cref="Dispatch"/> edges.</summary>
    CallVirt,

    /// <summary>A <c>newobj</c> to the constructor.</summary>
    NewObj,

    /// <summary>An <c>ldftn</c>: the method becomes a delegate or function pointer, so it may run.</summary>
    Ldftn,

    /// <summary>An <c>ldvirtftn</c> to its declared target.</summary>
    Ldvirtftn,

    /// <summary>
    /// From a method that creates a state machine (<c>newobj</c>) or names one as a generic argument (an async stub's
    /// <c>Start&lt;S&gt;</c>) to its <c>MoveNext</c>, which no instruction calls (<see cref="MemberIndex.StateMachineTargets"/>).
    /// At the instruction's offset; not a call site.
    /// </summary>
    StateMachine,

    /// <summary>
    /// From a method that touches a static field of an own type, or calls one of its static methods or constructors, to
    /// that type's static constructor (<see cref="MemberIndex.TypeInitializerTargets(IFieldReference)"/>), at the
    /// instruction's offset; and from each instance method of an own value type to its type's, at offset 0
    /// (<see cref="MemberIndex.InstanceInitializerTargets"/>). Not a call site.
    /// </summary>
    TypeInitializer,

    /// <summary>
    /// From a virtual (or static abstract) call site to an own override or implementation it may run instead of its
    /// declared target, by class-hierarchy analysis (<see cref="MemberIndex.DispatchTargets"/>). Added beside the
    /// site's own edge, at the same offset.
    /// </summary>
    Dispatch,

    /// <summary>
    /// An <c>ldtoken</c> of a method: the handle can become a <c>MethodInfo</c> that runs (an expression tree's
    /// <c>Expression.Call</c>). Resolved like a call site, but counted in <see cref="GraphCoverage.TokenSites"/>, not
    /// <see cref="GraphCoverage.CallSites"/>.
    /// </summary>
    LoadToken
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

    /// <summary>
    /// An assembly's module initializer (<c>&lt;Module&gt;..cctor</c>), which runs when it loads, is absent from the
    /// Analysis.Net model, and so is every other method of <c>&lt;Module&gt;</c>; or its module metadata could not be
    /// read, so whether it has one is unknown. Sited at <c>[assembly]&lt;Module&gt;</c> (<see cref="MemberIndex.Qualified"/>).
    /// </summary>
    ModuleInitializerInvisible,

    /// <summary>A body whose instructions could not be read.</summary>
    BodyUnreadable,

    /// <summary>
    /// A call into an unindexed assembly whose node id is also an own method's — a package defining its own
    /// <c>System.Environment.GetEnvironmentVariable</c>, say. The two are kept apart (the external one under a
    /// <see cref="MemberIndex.Qualified"/> id) and the collision is reported: shadowing a platform name is a signal.
    /// </summary>
    NameShadowed,

    /// <summary>
    /// An assembly has MethodImpl rows that bind an implementation whose name is not the declared method's (VB
    /// <c>Implements</c>, hand-written IL), which CHA's name match does not follow (decision D3). One per assembly,
    /// sited at <c>[assembly]&lt;Module&gt;</c>, naming the count.
    /// </summary>
    RenamedImplementation
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
/// <see cref="MaxDispatchWork"/> bounds class-hierarchy analysis (<see cref="MemberIndex.DispatchWork"/>), which a
/// crafted assembly can make quadratic without producing a single edge; reaching it stops only the
/// <see cref="MethodEdgeKind.Dispatch"/> fan-out, so every static edge is still added.
/// </summary>
public sealed record GraphBudget(int MaxNodes, int MaxEdges, long MaxDispatchWork = GraphBudget.DefaultDispatchWork)
{
    #region Properties
    /// <summary>Generous defaults for a single package's own assemblies.</summary>
    public static GraphBudget Default { get; } = new(1_000_000, 5_000_000);
    #endregion

    #region Fields
    /// <summary>
    /// The default <see cref="MaxDispatchWork"/>: about 60 times what the largest measured assembly spends
    /// (Microsoft.CodeAnalysis.CSharp 4.14, 344,965 units; A2 spec, S1 review 3).
    /// </summary>
    public const long DefaultDispatchWork = 20_000_000;
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
/// could not read. <see cref="DispatchSites"/> counts the call sites CHA fanned out from (including those it found no
/// override for), <see cref="DispatchEdges"/> the <see cref="MethodEdgeKind.Dispatch"/> edges they produced, and
/// <see cref="DispatchWork"/> the <see cref="MemberIndex.DispatchWork"/> units it spent. Once the dispatch work budget
/// is reached, sites are no longer fanned out or counted, so both counts are then lower bounds.
/// <see cref="TokenSites"/> counts the <c>ldtoken</c>s of methods, which are resolved but are not in
/// <see cref="CallSites"/> or <see cref="Resolutions"/>; a token that does not resolve carries the same Unresolved or
/// Ambiguous opacity a call site would, so those opacities can outnumber the matching <see cref="Resolutions"/>. <see cref="ModuleInitializers"/> counts the assemblies whose
/// module initializer the model cannot show, <see cref="RenamedImplementations"/> the MethodImpl rows CHA cannot follow,
/// and <see cref="ModulesUnreadable"/> the assemblies for which neither is known — never counted as having none.
/// </summary>
public sealed record GraphCoverage(
    IndexCoverage Index,
    int MethodsIndexed,
    int BodiesRead,
    int BodiesFailed,
    int CallSites,
    ResolutionCounts Resolutions,
    int DispatchSites,
    int DispatchEdges,
    long DispatchWork,
    int TokenSites,
    int ModuleInitializers,
    int RenamedImplementations,
    int ModulesUnreadable,
    bool Truncated,
    string? TruncatedBy);

/// <summary>
/// A call graph over the methods of a <see cref="MemberIndex"/> (ADR 0020). Each call site's <b>static</b> target comes
/// from Analysis.Net's bytecode instructions — the rung below three-address code, which needs no stack simulation —
/// and the <c>Disassembler</c> is never run. A virtual site, or a static call to an interface member, also gets a
/// <see cref="MethodEdgeKind.Dispatch"/> edge to every own override or implementation CHA finds, and a site that creates
/// or names an own state machine a <see cref="MethodEdgeKind.StateMachine"/> edge to its <c>MoveNext</c>. A static
/// member access gets a <see cref="MethodEdgeKind.TypeInitializer"/> edge to its type's static constructor, and an
/// <c>ldtoken</c> of a method a <see cref="MethodEdgeKind.LoadToken"/> edge to it. What the model drops from each
/// module (the module initializer, renamed implementations) is reported as opacity.
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
    /// Builds the static-target graph of <paramref name="index"/>. Stops adding when the node or edge budget of
    /// <paramref name="budget"/> is reached, and only stops the Dispatch fan-out when its dispatch work budget is; either
    /// way the result is marked truncated.
    /// </summary>
    public static MethodGraph Build(MemberIndex index, GraphBudget? budget = null)
    {
        var builder = new Builder(budget ?? GraphBudget.Default);
        foreach (var method in index.Methods)
            builder.AddOwn(method);
        foreach (var method in index.Methods.Where(m => m.Definition.HasBody))
            builder.Walk(index, method);
        foreach (var assembly in index.Assemblies)
            builder.AddModule(assembly, index.Module(assembly));
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
            // A value type's instance method may run its type's initializer itself, however it is reached.
            AddImplied(method.NodeId, 0, MethodEdgeKind.TypeInitializer, (index, method), static s => s.index.InstanceInitializerTargets(s.method));
            foreach (var instruction in instructions)
                Visit(index, method.NodeId, instruction);
        }

        public MethodGraph ToGraph(IndexCoverage index, int methodsIndexed) =>
            new(
                [.. nodes.Values.OrderBy(n => n.NodeId, StringComparer.Ordinal)],
                [.. edges.OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ThenBy(e => e.Kind).ThenBy(e => e.Offset)],
                [.. opacities.OrderBy(o => o.Site, StringComparer.Ordinal).ThenBy(o => o.Offset).ThenBy(o => o.Kind).ThenBy(o => o.Detail, StringComparer.Ordinal)],
                new GraphCoverage(index, methodsIndexed, bodiesRead, bodiesFailed, callSites, resolutions, dispatchSites, dispatchEdges,
                    dispatchWork.Spent, tokenSites, moduleInitializers, renamedImplementations, modulesUnreadable,
                    truncatedBy is not null || dispatchTruncatedBy is not null,
                    truncatedBy is null ? dispatchTruncatedBy : dispatchTruncatedBy is null ? truncatedBy : $"{dispatchTruncatedBy}; {truncatedBy}"));

        private void Visit(MemberIndex index, string caller, Model.IInstruction instruction)
        {
            var offset = instruction is Instruction bytecode ? bytecode.Offset : 0;
            switch (instruction)
            {
                case MethodCallInstruction call:
                    AddCall(index, caller, offset, call.Method, call.Operation == MethodCallOperation.Virtual ? MethodEdgeKind.CallVirt : MethodEdgeKind.Call);
                    AddImplied(caller, offset, MethodEdgeKind.StateMachine, (index, call.Method), static s => s.index.StateMachineTargets(s.Method, construction: false));
                    AddImplied(caller, offset, MethodEdgeKind.TypeInitializer, (index, call.Method), static s => s.index.TypeInitializerTargets(s.Method));
                    break;
                case CreateObjectInstruction create:
                    AddCall(index, caller, offset, create.Constructor, MethodEdgeKind.NewObj);
                    AddImplied(caller, offset, MethodEdgeKind.StateMachine, (index, create.Constructor), static s => s.index.StateMachineTargets(s.Constructor, construction: true));
                    AddImplied(caller, offset, MethodEdgeKind.TypeInitializer, (index, create.Constructor), static s => s.index.TypeInitializerTargets(s.Constructor));
                    break;
                case LoadMethodAddressInstruction load:
                    AddCall(index, caller, offset, load.Method, load.Operation == LoadMethodAddressOperation.Virtual ? MethodEdgeKind.Ldvirtftn : MethodEdgeKind.Ldftn);
                    AddImplied(caller, offset, MethodEdgeKind.TypeInitializer, (index, load.Method), static s => s.index.TypeInitializerTargets(s.Method));
                    break;
                case LoadFieldInstruction field:
                    AddImplied(caller, offset, MethodEdgeKind.TypeInitializer, (index, field.Field), static s => s.index.TypeInitializerTargets(s.Field));
                    break;
                case StoreFieldInstruction field:
                    AddImplied(caller, offset, MethodEdgeKind.TypeInitializer, (index, field.Field), static s => s.index.TypeInitializerTargets(s.Field));
                    break;
                case LoadTokenInstruction { Token: IMethodReference method }:
                    AddToken(index, caller, offset, method);
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
            if (!AddResolved(index, caller, offset, resolution, kind))
                return;

            // CHA: the overrides this site may run instead. Own methods only, all already nodes. Once the work budget is
            // spent no further fan-out is added, but the walk goes on for the static edges.
            var overrides = index.DispatchTargets(target, resolution, kind is MethodEdgeKind.CallVirt or MethodEdgeKind.Ldvirtftn, dispatchWork);
            if (dispatchWork.Exhausted)
                dispatchTruncatedBy ??= $"dispatch work budget of {dispatchWork.Limit} reached";
            if (overrides is null)
                return;
            dispatchSites++;
            foreach (var to in overrides)
            {
                if (!Room(edges.Count, budget.MaxEdges, "edges"))
                    return;
                edges.Add(new MethodEdge(caller, to, MethodEdgeKind.Dispatch, offset));
                dispatchEdges++;
            }
        }

        // An ldtoken of a method: resolved and recorded like a call site's static target, with the same opacity, but
        // not a call site, and never fanned out.
        private void AddToken(MemberIndex index, string caller, uint offset, IMethodReference method)
        {
            if (truncatedBy is not null)
                return;
            tokenSites++;
            AddResolved(index, caller, offset, index.Resolve(method), MethodEdgeKind.LoadToken);
        }

        // The edges of one resolved reference, and its opacity; false once a budget is reached.
        private bool AddResolved(MemberIndex index, string caller, uint offset, MethodResolution resolution, MethodEdgeKind kind)
        {
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
                        return false;
                    nodes[to] = new MethodNode(to, resolution.ClassificationKey, MethodNodeKind.External);
                }

                if (!Room(edges.Count, budget.MaxEdges, "edges"))
                    return false;
                edges.Add(new MethodEdge(caller, to, kind, offset));
            }
            return true;
        }

        // Edges an instruction implies rather than names: a state machine's MoveNext, a type's .cctor. Own methods only,
        // all already nodes; targets are asked for only while the build has room, through a static lambda over state, so
        // no closure is allocated per instruction (S3 review N5). A method implying itself (a MoveNext naming its own
        // state machine, a .cctor touching its own type's statics) adds no self-edge.
        private void AddImplied<T>(string caller, uint offset, MethodEdgeKind kind, T state, Func<T, IReadOnlyList<string>> targets)
        {
            if (truncatedBy is not null)
                return;
            foreach (var to in targets(state).Where(to => to != caller))
            {
                if (!Room(edges.Count, budget.MaxEdges, "edges"))
                    return;
                edges.Add(new MethodEdge(caller, to, kind, offset));
            }
        }

        // What the model drops from one assembly's module, as opacity: facts, not graph work, so recorded even after
        // truncation. Unreadable metadata is its own record, never read as "no module initializer".
        public void AddModule(string assembly, ModuleMetadata module)
        {
            var site = MemberIndex.Qualified(assembly, "<Module>");
            if (!module.IsReadable)
            {
                modulesUnreadable++;
                opacities.Add(new GraphOpacity(site, 0, OpacityKind.ModuleInitializerInvisible,
                    "the module metadata could not be read: whether it has a module initializer or renamed implementations is unknown"));
                return;
            }
            if (module.HasModuleInitializer)
            {
                moduleInitializers++;
                opacities.Add(new GraphOpacity(site, 0, OpacityKind.ModuleInitializerInvisible,
                    $"<Module> has a module initializer, which runs when the assembly loads, and {Count(module.ModuleMethods, "method")}; the model loads none of them"));
            }
            if (module.RenamedImplementations > 0)
            {
                renamedImplementations += module.RenamedImplementations;
                opacities.Add(new GraphOpacity(site, 0, OpacityKind.RenamedImplementation,
                    $"MethodImpl rows that bind an implementation whose name is not the declared method's, which CHA does not follow: {module.RenamedImplementations}"));
            }
        }

        private static string Count(int count, string noun) => $"{count} {noun}{(count == 1 ? "" : "s")}";

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
        private readonly MemberIndex.DispatchWork dispatchWork = new(budget.MaxDispatchWork);
        private ResolutionCounts resolutions = ResolutionCounts.None;
        private int bodiesRead;
        private int bodiesFailed;
        private int callSites;
        private int dispatchSites;
        private int dispatchEdges;
        private int tokenSites;
        private int moduleInitializers;
        private int renamedImplementations;
        private int modulesUnreadable;
        // The build stops at truncatedBy, but only the fan-out stops at dispatchTruncatedBy.
        private string? truncatedBy;
        private string? dispatchTruncatedBy;
        #endregion
    }
    #endregion
}
