namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

using Cilica.AsmIO;
using Cilica.IR;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// What SSA proves about the arguments of each sink site of a folder (ADR 0038, S4): constants, one of a few constants,
/// the caller's own parameter, or dynamic with an origin, read intraprocedurally off the verified SSA body; and for a
/// reflection sink, the target its lookup chain names (S4.3). Only the methods holding sites are lifted, node by node in
/// ordinal order, and each body is dropped once read. Joined to the graph by node id and IL offset
/// (<see cref="SsaMethodOutcome.ILOffsets"/>).
/// </summary>
public static partial class SsaSinkFacts
{
    #region Methods
    /// <summary>
    /// The facts of <paramref name="sites"/> (as <see cref="SinkSites.Of"/> gives them) over <paramref name="session"/>'s
    /// folder, which must be opened on the files the graph read, bounded by <paramref name="bounds"/> (default
    /// <see cref="SsaFactBounds.Default"/>), timed by <paramref name="clock"/> (default the system's: its timestamps between
    /// methods and sites, and a timer of it inside a lift, so a fake clock must fake both). Reflection targets
    /// follow <paramref name="reflection"/> (default <see cref="ReflectionMap.Default"/>) and take their candidates from
    /// <paramref name="members"/> (<see cref="OwnMembers.Of"/> of the same graph; default none). When the session lost an
    /// assembly, any node may have an unread definition in it, so nothing is lifted and every site reads MethodUnknown.
    /// Deterministic but for <see cref="SsaFactBounds.FolderTime"/>. Nothing about the input throws.
    /// </summary>
    public static SsaFolderFacts Extract(SsaSession session, IReadOnlyList<SinkSite> sites, SsaFactBounds? bounds = null, TimeProvider? clock = null,
        OwnMembers? members = null, ReflectionMap? reflection = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(sites);
        bounds = (bounds ?? SsaFactBounds.Default).Validated();
        clock ??= TimeProvider.System;
        members ??= OwnMembers.None;
        reflection ??= ReflectionMap.Default;
        var started = clock.GetTimestamp();

        var ordered = sites.Distinct()
            .OrderBy(s => s.NodeId, StringComparer.Ordinal).ThenBy(s => s.Offset).ThenBy(s => s.Callee, StringComparer.Ordinal).ThenBy(s => s.EdgeKind)
            .ThenBy(s => s.CalleeKey, StringComparer.Ordinal).ThenBy(s => s.Capability)
            .ToArray();
        var kept = ordered.Take(bounds.MaxSites).ToArray();
        var lost = session.Assemblies.Where(a => !a.IsLoaded).ToArray();
        if (lost.Length > 0)
            return Lost(kept, ordered.Length, lost);

        var siteIndex = kept.Select((s, i) => (s, i)).ToDictionary(p => p.s, p => p.i);
        var byNode = kept.GroupBy(s => s.NodeId, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);

        var walker = new ValueWalker(bounds);
        var chains = new ChainWalker(reflection, walker);
        var nodes = new Dictionary<string, NodeState>(StringComparer.Ordinal);
        var unknown = new SortedDictionary<SsaFailureKind, int>();
        var (tried, lifted, methodBudget, timeBudget) = (0, 0, false, false);
        string? current = null;
        // The first node id not read whole when a budget stopped: nodes come in ordinal order, so one before it with no
        // outcome was reached and had no method, and one from it on was not read.
        string? cutAt = null;
        // The same budget inside a lift, so one crafted method cannot outlast it (SsaFailureKind.TimedOut): a timer of the
        // same clock. Past a timer's longest due time (about 49.7 days) only the checks between nodes and sites apply.
        var left = bounds.FolderTime - clock.GetElapsedTime(started);
        using var deadline = left <= maxTimerDelay ? new CancellationTokenSource(left > TimeSpan.Zero ? left : TimeSpan.FromTicks(1), clock) : new CancellationTokenSource();
        foreach (var outcome in session.Lift(identity => byNode.ContainsKey(CanonicalName.NodeId(identity)), deadline.Token))
        {
            var nodeId = outcome.NodeId;
            if (nodeId != current)
            {
                // The method budget only between node ids, so a node's definitions are lifted all together or not at all.
                methodBudget = tried >= bounds.MaxLiftedMethods;
                timeBudget = !methodBudget && clock.GetElapsedTime(started) >= bounds.FolderTime;
                if (methodBudget || timeBudget)
                {
                    cutAt = nodeId;
                    break;
                }
                current = nodeId;
                nodes[nodeId] = new NodeState();
            }
            if (outcome.Failure is { Kind: SsaFailureKind.TimedOut })
            {
                // Cut as the between-site check cuts: this node and every one after it read NotRun.
                timeBudget = true;
                cutAt = nodeId;
                nodes.Remove(nodeId);
                break;
            }
            tried++;
            var state = nodes[nodeId];
            if (outcome.Failure is { } failure)
            {
                unknown[failure.Kind] = unknown.GetValueOrDefault(failure.Kind) + 1;
                state.Failure ??= new SsaFailure(failure.Kind, Reachability.BoundName(UntrustedText.Escape(failure.Reason)));
                continue;
            }
            lifted++;
            var definition = ++state.Definitions;
            var calls = CallsByOffset(outcome);
            walker.Reset();
            chains.Reset();
            walker.Prime(outcome);
            foreach (var site in byNode[nodeId])
            {
                // The time budget also between sites, so one costly node ends the folder gracefully: its sites read NotRun.
                if (clock.GetElapsedTime(started) >= bounds.FolderTime)
                {
                    timeBudget = true;
                    cutAt = nodeId;
                    nodes.Remove(nodeId);
                    break;
                }
                if (site.Offset > int.MaxValue || !calls.TryGetValue((int)site.Offset, out var atOffset))
                    continue;
                foreach (var call in atOffset)
                {
                    if (Callee(site.EdgeKind, call) is not { } callee)
                        continue;
                    if (ClassificationKey(callee) == site.CalleeKey)
                        state.Add(siteIndex[site], definition, Read(call, walker, bounds) with { Target = chains.Target(call, reflection.Target(site.CalleeKey)) });
                    else
                        state.OtherCallee.Add(siteIndex[site]);
                }
            }
            if (timeBudget)
                break;
        }
        walker.Reset();
        chains.Reset();

        var budget = new TextBudget(bounds.MaxFactTextChars, walker.HashOnly);
        SsaReflectionTarget TargetOf(TargetParts parts) => Target(parts, members, bounds, budget);
        var facts = kept.Select((site, i) => Fact(site, i, nodes, cutAt, timeBudget, bounds, budget, TargetOf)).ToArray();
        return new SsaFolderFacts(facts, ordered.Length, ordered.Length > kept.Length, lifted,
            [.. unknown.Select(u => new SsaFailureCount(u.Key, u.Value))], methodBudget, timeBudget, budget.Spent, 0);
    }

    /// <summary>
    /// The call sites of a lifted body, as <see cref="Extract"/> joins them to graph edges: every <c>CallInst</c>,
    /// <c>NewObjInst</c> and <c>FuncAddrInst</c> with an IL offset, in body order. Empty when not lifted.
    /// </summary>
    public static IReadOnlyList<SsaCallSite> CallSites(SsaMethodOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        if (outcome.Body is not { } body)
            return [];
        return
        [
            .. body.Instructions()
                .Select(i => (Kind: KindOf(i), Offset: outcome.OffsetOf(i), Callee: CalleeOf(i)))
                .Where(c => c.Kind is not null && c.Offset is not null)
                .Select(c => new SsaCallSite(c.Offset!.Value, c.Kind!.Value, ClassificationKey(c.Callee!))),
        ];
    }

    // The edge kind an instruction's opcode makes, or null for an instruction that is not a call site.
    private static MethodEdgeKind? KindOf(Instruction instruction) => instruction switch
    {
        CallInst call => call.IsVirtual ? MethodEdgeKind.CallVirt : MethodEdgeKind.Call,
        NewObjInst => MethodEdgeKind.NewObj,
        FuncAddrInst address => address.IsVirtual ? MethodEdgeKind.Ldvirtftn : MethodEdgeKind.Ldftn,
        _ => null,
    };

    private static MethodDesc? CalleeOf(Instruction instruction) => instruction switch
    {
        CallInst call => call.Method,
        NewObjInst create => create.Constructor,
        FuncAddrInst address => address.Method,
        _ => null,
    };

    // Every site MethodUnknown, naming the assemblies the session could not read (up to three).
    private static SsaFolderFacts Lost(SinkSite[] kept, int total, SsaAssembly[] lost)
    {
        var names = string.Join(", ", lost.Take(3).Select(a => "'" + Reachability.BoundName(UntrustedText.Escape(Path.GetFileName(a.Path))) + "'"))
            + (lost.Length > 3 ? $", and {lost.Length - 3} more" : "");
        var reason = $"SSA could not read {lost.Length} of the folder's assemblies ({names}), any of which may define a method under its node id";
        return new SsaFolderFacts(
            [.. kept.Select(site => new SsaSinkFact(Bounded(site), SsaSiteStatus.MethodUnknown, null, [], 0, false, SsaFailureKind.Unreadable, reason))],
            total, total > kept.Length, 0, [], false, false, false, lost.Length);
    }

    private static SinkSite Bounded(SinkSite site) => site with
    {
        NodeId = Reachability.BoundName(site.NodeId),
        Callee = Reachability.BoundName(site.Callee),
        CalleeKey = Reachability.BoundName(site.CalleeKey),
    };

    // The call, newobj and ldftn instructions of a lifted body by IL offset, in body order.
    private static Dictionary<int, List<Instruction>> CallsByOffset(SsaMethodOutcome outcome)
    {
        var calls = new Dictionary<int, List<Instruction>>();
        foreach (var instruction in outcome.Body!.Instructions())
        {
            if (instruction is CallInst or NewObjInst or FuncAddrInst && outcome.ILOffsets.TryGetValue(instruction, out var offset))
            {
                if (!calls.TryGetValue(offset, out var list))
                    calls[offset] = list = [];
                list.Add(instruction);
            }
        }
        return calls;
    }

    // The callee of an instruction of the edge's kind; null for another kind. It joins only with the site's classification
    // key: an instruction at the same offset of another definition merged under the node id may call something else.
    private static MethodDesc? Callee(MethodEdgeKind kind, Instruction instruction) => (kind, instruction) switch
    {
        (MethodEdgeKind.Call or MethodEdgeKind.CallVirt, CallInst call) => call.Method,
        (MethodEdgeKind.NewObj, NewObjInst create) => create.Constructor,
        (MethodEdgeKind.Ldftn, FuncAddrInst { IsVirtual: false } address) => address.Method,
        (MethodEdgeKind.Ldvirtftn, FuncAddrInst { IsVirtual: true } address) => address.Method,
        _ => null,
    };

    // A method's classification key, as CanonicalName gives it from metadata; null when it cannot be read.
    private static string? ClassificationKey(MethodDesc method)
    {
        try
        {
            return TypeNames.Identity(method.DeclaringType) is { } type
                ? CanonicalName.ClassificationKey(new MethodIdentity(type, method.Name, 0, []))
                : null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    // One instruction's receiver and arguments; a static call, newobj or ldftn has no receiver.
    private static Contribution Read(Instruction instruction, ValueWalker walker, SsaFactBounds bounds)
    {
        (Value? Receiver, Value[] Arguments) parts = instruction switch
        {
            CallInst { IsStatic: false } call => (call.Args[0], call.Args[1..].ToArray()),
            CallInst call => (null, call.Args.ToArray()),
            NewObjInst create => (null, create.Args.ToArray()),
            FuncAddrInst address => (address.Object, []),
            _ => (null, []),
        };
        return new Contribution(
            parts.Receiver is null ? null : walker.Of(parts.Receiver),
            [.. parts.Arguments.Take(bounds.MaxArguments).Select(walker.Of)],
            parts.Arguments.Length);
    }

    private static SsaSinkFact Fact(SinkSite site, int index, Dictionary<string, NodeState> nodes, string? cutAt, bool byTime, SsaFactBounds bounds, TextBudget budget,
        Func<TargetParts, SsaReflectionTarget> targetOf)
    {
        var bounded = Bounded(site);
        SsaSinkFact Without(SsaSiteStatus status, string reason, SsaFailureKind? kind = null) => new(bounded, status, null, [], 0, false, kind, reason);

        if (!nodes.TryGetValue(site.NodeId, out var state))
            return cutAt is not null && string.CompareOrdinal(site.NodeId, cutAt) >= 0
                ? Without(SsaSiteStatus.NotRun, byTime ? "the folder's SSA time budget was spent before its method" : "the folder's SSA method budget was spent before its method")
                : Without(SsaSiteStatus.NotJoined, "no method with a body lifted under its node id");
        if (state.Failure is { } failure)
            return Without(SsaSiteStatus.MethodUnknown, failure.Reason, failure.Kind);
        if (!state.Sites.TryGetValue(index, out var contributions))
            return Without(SsaSiteStatus.NotJoined, state.OtherCallee.Contains(index)
                ? $"the {site.EdgeKind} instruction at this offset in the lifted body calls a method with another classification key"
                : $"no {site.EdgeKind} instruction at this offset in the lifted body");

        var receivers = contributions.Select(c => c.Value.Receiver).OfType<SsaValue>().ToArray();
        var count = contributions.Max(c => c.Value.Count);
        var arguments = Enumerable.Range(0, Math.Min(count, bounds.MaxArguments))
            .Select(i => contributions.Where(c => i < c.Value.Arguments.Count).Select(c => c.Value.Arguments[i]).Aggregate((a, b) => Union(a, b, bounds.MaxAlternatives)))
            .ToArray();
        var receiver = receivers.Length == 0 ? null : receivers.Aggregate((a, b) => Union(a, b, bounds.MaxAlternatives));
        var targets = contributions.Select(c => c.Value.Target).OfType<TargetParts>().ToArray();
        // Charged in argument order: the receiver, the arguments, then the target.
        return new SsaSinkFact(bounded, SsaSiteStatus.Analyzed, receiver is null ? null : budget.Charge(receiver), [.. arguments.Select(budget.Charge)],
            count, contributions.Select(c => c.Definition).Distinct().Count() > 1, null, null,
            targets.Length == 0 ? null : targetOf(targets.Aggregate((a, b) => Union(a, b, bounds.MaxAlternatives))));
    }

    // Two values of one position, from two definitions or two phi inputs: constants union (sorted, up to the bound),
    // one parameter stays itself, and anything else is Dynamic, keeping the first Dynamic's origin.
    private static SsaValue Union(SsaValue a, SsaValue b, int maxAlternatives)
    {
        if (a.SameAs(b))
            return a;
        if (a.Kind is SsaValueKind.Constant or SsaValueKind.OneOf && b.Kind is SsaValueKind.Constant or SsaValueKind.OneOf)
        {
            var constants = a.Constants.Concat(b.Constants).Distinct()
                .OrderBy(c => c.Kind).ThenBy(c => c.Text, StringComparer.Ordinal).ToArray();
            return constants.Length > maxAlternatives ? SsaValue.OfDynamic(SsaDynamicOrigin.TooManyAlternatives)
                : constants.Length == 1 ? SsaValue.OfConstant(constants[0])
                : new SsaValue(SsaValueKind.OneOf, constants, null, null);
        }
        return SsaValue.OfDynamic(a.Origin ?? b.Origin ?? SsaDynamicOrigin.Other);
    }
    #endregion

    #region Fields
    // A timer's longest due time (uint.MaxValue - 1 milliseconds).
    private static readonly TimeSpan maxTimerDelay = TimeSpan.FromMilliseconds(uint.MaxValue - 1d);
    #endregion

    #region Child types
    // One instruction's values at a site, from one definition, and its reflection target's parts.
    private sealed record Contribution(SsaValue? Receiver, IReadOnlyList<SsaValue> Arguments, int Count, TargetParts? Target = null);

    // What the definitions under one node id gave: the first failure, and per site (by index) each joined instruction's
    // values with the definition it came from.
    private sealed class NodeState
    {
        #region Properties
        public SsaFailure? Failure { get; set; }

        public int Definitions { get; set; }

        public Dictionary<int, List<(int Definition, Contribution Value)>> Sites { get; } = [];

        // The sites (by index) with an instruction of their kind at their offset that calls another key.
        public HashSet<int> OtherCallee { get; } = [];
        #endregion

        #region Methods
        public void Add(int site, int definition, Contribution value)
        {
            if (!Sites.TryGetValue(site, out var list))
                Sites[site] = list = [];
            list.Add((definition, value));
        }
        #endregion
    }

    // The folder's text budget, spent in site order: a String or Type constant past it keeps only its hash suffix, and a
    // target's candidate names are dropped whole.
    private sealed class TextBudget(int maxChars, IReadOnlyDictionary<SsaConstant, string> hashOnly)
    {
        #region Properties
        public bool Spent { get; private set; }
        #endregion

        #region Methods
        public SsaValue Charge(SsaValue value) =>
            value.Constants.Count == 0 ? value : value with { Constants = [.. value.Constants.Select(Charge)] };

        public IReadOnlyList<string> Charge(IReadOnlyList<string> names)
        {
            var chars = names.Sum(n => (long)n.Length);
            if (!Spent && used + chars <= maxChars)
            {
                used += chars;
                return names;
            }
            Spent |= names.Count > 0;
            return [];
        }

        private SsaConstant Charge(SsaConstant constant)
        {
            if (constant.Kind is not (SsaConstantKind.String or SsaConstantKind.Type))
                return constant;
            if (!Spent && used + constant.Text.Length <= maxChars)
            {
                used += constant.Text.Length;
                return constant;
            }
            Spent = true;
            return constant with { Text = hashOnly.GetValueOrDefault(constant) ?? UntrustedText.HashOnly(constant.Text), Cut = true };
        }
        #endregion

        #region Fields
        private long used;
        #endregion
    }

    // Classifies one SSA value: constants and type tokens, the caller's arguments, and a cycle-safe, bounded walk of phi
    // webs. Retyping casts and boxes are looked through; nothing is folded. Values (by reference), strings (by content)
    // and types (by reference) are memoised per body, Reset between bodies, so a web or a long string used at many sites
    // is read once.
    private sealed class ValueWalker(SsaFactBounds bounds)
    {
        #region Properties
        // Each String or Type constant made, to its hash-only form.
        public Dictionary<SsaConstant, string> HashOnly { get; } = [];
        #endregion

        #region Methods
        public SsaValue Of(Value value)
        {
            if (!values.TryGetValue(value, out var result))
                values[value] = result = Strip(value) is PhiInst phi ? Phi(phi) : Leaf(value);
            return result;
        }

        // The definitions of the named types this body renders as constant (several when distinct types render alike).
        public IEnumerable<TypeName> DefinitionsOf(SsaConstant constant) => definitions.GetValueOrDefault(constant) ?? [];

        // Reads every typeof of a lifted body before its sites, so each site's DefinitionsOf sees all of them, whatever
        // the site order.
        public void Prime(SsaMethodOutcome outcome)
        {
            foreach (var instruction in outcome.Body!.Instructions())
                if (instruction is CallInst call && TypeToken(call) is { } type)
                    OfType(type);
        }

        // A type as a value: a Type constant, made once per body for its type, whose definition (a named type's) is kept
        // for reflection candidates; a bare generic parameter is Dynamic, since the caller's caller picks it.
        public SsaValue OfType(TypeDesc type)
        {
            if (type is GenericParamType)
                return SsaValue.OfDynamic(SsaDynamicOrigin.TypeParameter);
            if (!types.TryGetValue(type, out var constant))
            {
                var (name, whole) = TypeNames.Name(type);
                types[type] = constant = Make(SsaConstantKind.Type, name, whole);
                if (TypeNames.DefinitionName(type) is { } definition)
                {
                    if (!definitions.TryGetValue(constant, out var named))
                        definitions[constant] = named = [];
                    named.Add(definition);
                }
            }
            return SsaValue.OfConstant(constant);
        }

        // Forgets the body's values, so its IR can be collected.
        public void Reset()
        {
            values.Clear();
            strings.Clear();
            types.Clear();
            definitions.Clear();
        }

        // Breadth first over the phis reachable from root, each once: depth and inputs read bounded, stopping at the first
        // value that makes the result Dynamic.
        private SsaValue Phi(PhiInst root)
        {
            var visited = new HashSet<PhiInst>(ReferenceEqualityComparer.Instance) { root };
            var queue = new Queue<(PhiInst Phi, int Depth)>([(root, 1)]);
            SsaValue? result = null;
            var inputs = 0;
            while (queue.TryDequeue(out var item))
            {
                for (var i = 0; i < item.Phi.NumArgs; i++)
                {
                    if (++inputs > bounds.MaxPhiInputs)
                        return SsaValue.OfDynamic(SsaDynamicOrigin.TooDeep);
                    var incoming = Strip(item.Phi.GetValue(i));
                    if (incoming is PhiInst next)
                    {
                        if (visited.Contains(next))
                            continue;
                        if (item.Depth >= bounds.MaxPhiDepth)
                            return SsaValue.OfDynamic(SsaDynamicOrigin.TooDeep);
                        visited.Add(next);
                        queue.Enqueue((next, item.Depth + 1));
                        continue;
                    }
                    var leaf = Leaf(incoming);
                    result = result is null ? leaf : Union(result, leaf, bounds.MaxAlternatives);
                    if (result.Kind == SsaValueKind.Dynamic)
                        return result;
                }
            }
            // Only phis, all already seen: a cycle with no way in.
            return result ?? SsaValue.OfDynamic(SsaDynamicOrigin.Other);
        }

        private SsaValue Leaf(Value value) => Strip(value) switch
        {
            ConstString text => Constant(text.Value),
            ConstInt number => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Int,
                number.IsUnsigned ? number.UValue.ToString(CultureInfo.InvariantCulture) : number.Value.ToString(CultureInfo.InvariantCulture))),
            ConstFloat number => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Float, number.Value.ToString("R", CultureInfo.InvariantCulture))),
            ConstNull => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Null, "null")),
            Argument argument => SsaValue.OfParameter(argument.Index),
            CallInst call when TypeToken(call) is { } type => OfType(type),
            CallInst or NewObjInst or CilIntrinsic.CallIndirect => SsaValue.OfDynamic(SsaDynamicOrigin.CallResult),
            LoadInst load => SsaValue.OfDynamic(Strip(load.Address) switch
            {
                FieldAddrInst => SsaDynamicOrigin.FieldLoad,
                ArrayAddrInst => SsaDynamicOrigin.ArrayElement,
                _ => SsaDynamicOrigin.Memory,
            }),
            FieldExtractInst => SsaValue.OfDynamic(SsaDynamicOrigin.FieldLoad),
            _ => SsaValue.OfDynamic(SsaDynamicOrigin.Other),
        };

        // A String constant, made once per body for its content: CCI reads each ldstr into a new string, and escaping and
        // hashing one cost its length, which an ordinal lookup costs a fraction of.
        private SsaValue Constant(string text)
        {
            if (!strings.TryGetValue(text, out var constant))
                strings[text] = constant = Make(SsaConstantKind.String, text);
            return SsaValue.OfConstant(constant);
        }

        // A text that is not whole (a type name past its budget) is always cut, so it reads Cut with the suffix whatever
        // MaxTextChars is; its hash is over the text rendered. When MaxTextChars would have kept all of that text, the cut
        // drops its last char, so the suffix reads "+1 chars": the name was cut before, by its budget.
        private SsaConstant Make(SsaConstantKind kind, string raw, bool whole = true)
        {
            var max = whole ? bounds.MaxTextChars : Math.Max(1, Math.Min(bounds.MaxTextChars, raw.Length - 1));
            var constant = new SsaConstant(kind, UntrustedText.EscapeBounded(raw, max, out var hashOnly, out var cut), cut);
            HashOnly.TryAdd(constant, hashOnly);
            return constant;
        }

        // typeof(T): Type.GetTypeFromHandle (CoreLib's) of an ldtoken of a type.
        private static TypeDesc? TypeToken(CallInst call)
        {
            try
            {
                return call.Method.Name == "GetTypeFromHandle" && call.Method.DeclaringType.IsCorelibType(typeof(Type))
                    && call.Args is [CilIntrinsic.LoadHandle { Entity: TypeDesc type }] ? type : null;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return null;
            }
        }

        // A retyping cast or a box stands for its operand.
        public static Value Strip(Value value)
        {
            for (var i = 0; i < MaxStrip && value is CilIntrinsic.RefCast or CilIntrinsic.Box; i++)
                value = ((IntrinsicInst)value).Args[0];
            return value;
        }

        #endregion

        #region Fields
        private const int MaxStrip = 16;

        private readonly Dictionary<Value, SsaValue> values = new(ReferenceEqualityComparer.Instance);
        private readonly Dictionary<string, SsaConstant> strings = new(StringComparer.Ordinal);
        private readonly Dictionary<TypeDesc, SsaConstant> types = new(ReferenceEqualityComparer.Instance);
        private readonly Dictionary<SsaConstant, HashSet<TypeName>> definitions = [];
        #endregion
    }

    // Canonical names (ADR 0025) of Cilica's types, as CciNames renders them from metadata. Known divergences, on hostile
    // metadata only: a nested type with a namespace, a name ending `0, and function pointers (rendered <unknown>).
    private static class TypeNames
    {
        #region Methods
        // T as a signature type, and whether it is whole; <unknown> for what cannot be read. Metadata may name a TypeSpec
        // inside another's signature, so types can share parts and a name can double per level: each type is rendered once
        // per call, its chars charged as rendered, and once MaxNameChars are spent the rest render <unknown> (not whole).
        public static (string Name, bool Whole) Name(TypeDesc type)
        {
            var renderer = new Renderer();
            var name = renderer.Name(type, 0);
            return (name, !renderer.Spent);
        }

        // The identity of a named type's definition; null for any other type.
        public static TypeIdentity? Identity(TypeDesc type) => type switch
        {
            TypeDefOrSpec named => Definition(named.Definition),
            PrimType primitive => new TypeIdentity(primitive.Namespace, [primitive.Name], 0),
            _ => null,
        };

        // A named type's definition by name; null for any other type, or one that cannot be read.
        public static TypeName? DefinitionName(TypeDesc type)
        {
            try
            {
                return Identity(type) is { } identity ? new TypeName(CanonicalName.NodeId(identity), CanonicalName.ClassificationKey(identity)) : null;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return null;
            }
        }

        // Its nesting chain with each link's own arity suffix removed, the outermost namespace, and the whole chain's
        // arity; a chain past the bound is CanonicalName.Truncated.
        private static TypeIdentity Definition(TypeDef definition)
        {
            var chain = new List<string>();
            var space = string.Empty;
            var type = definition;
            for (var depth = 0; type is not null && depth < MaxDepth; depth++)
            {
                var outer = type.DeclaringType;
                chain.Insert(0, Unmangled(type.Name, Own(type)));
                if (outer is null)
                    space = type.Namespace ?? string.Empty;
                type = outer;
            }
            return type is not null ? CanonicalName.Truncated(chain) : new TypeIdentity(space, chain, definition.GenericParams.Length);
        }

        // CciNames' rule: a link contributes its own arguments only when it is instantiated itself (has generic parameters
        // of its own), and then after its container's; so List<int>.Enumerator has none. Cilica's spec holds them all.
        private static IEnumerable<TypeDesc> Arguments(TypeSpec spec)
        {
            var all = spec.GenericParams;
            var ranges = new List<(int Start, int End)>();
            for (var link = spec.Definition; link is not null && ranges.Count < MaxDepth && Own(link) > 0; link = link.DeclaringType)
                ranges.Insert(0, (link.GenericParams.Length - Own(link), link.GenericParams.Length));
            return ranges.SelectMany(r => Enumerable.Range(r.Start, r.End - r.Start)).Where(i => i < all.Count).Select(i => all[i]);
        }

        private static int Own(TypeDef type) => type.GenericParams.Length - (type.DeclaringType?.GenericParams.Length ?? 0);

        // The metadata name without the `N suffix a type with N generic parameters of its own carries.
        private static string Unmangled(string name, int own) =>
            own > 0 && name.EndsWith("`" + own.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal) ? name[..name.LastIndexOf('`')] : name;
        #endregion

        #region Fields
        private const int MaxDepth = 64;

        // Chars one name renders before the rest are <unknown>.
        private const int MaxNameChars = 4_096;
        #endregion

        #region Child types
        // One name's rendering: each type once (by reference), every char charged as it is rendered (a part, or what a
        // container adds around its parts), so the work is bounded by the budget, never by the metadata's ranks or names.
        private sealed class Renderer
        {
            #region Properties
            // The budget ran out, so some part reads <unknown>.
            public bool Spent { get; private set; }
            #endregion

            #region Methods
            public string Name(TypeDesc type, int depth)
            {
                if (depth > MaxDepth)
                    return CanonicalName.UnknownPart;
                if (left <= 0)
                {
                    Spent = true;
                    return CanonicalName.UnknownPart;
                }
                if (rendered.TryGetValue(type, out var known))
                    return Charge(known);
                string name;
                try
                {
                    name = type switch
                    {
                        ByrefType byref => Wrapped(Name(byref.ElemType, depth + 1), CanonicalName.ByRefTo),
                        PointerType pointer => Wrapped(Name(pointer.ElemType, depth + 1), CanonicalName.PointerTo),
                        MDArrayType array => Wrapped(Name(array.ElemType, depth + 1), e => CanonicalName.ArrayOf(e, array.Rank)),
                        ArrayType array => Wrapped(Name(array.ElemType, depth + 1), e => CanonicalName.ArrayOf(e)),
                        GenericParamType parameter => Charge(parameter.IsMethodParam
                            ? CanonicalName.MethodGenericParameter(parameter.Index)
                            : CanonicalName.TypeGenericParameter(parameter.Index)),
                        PrimType primitive => Charge(CanonicalName.NodeId(Identity(primitive)!.Value)),
                        TypeSpec spec => Instance(spec, depth),
                        TypeDef definition => Charge(CanonicalName.NodeId(Definition(definition))),
                        _ => CanonicalName.UnknownPart,
                    };
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    name = CanonicalName.UnknownPart;
                }
                rendered[type] = name;
                return name;
            }

            // The definition's name is charged before its arguments are rendered.
            private string Instance(TypeSpec spec, int depth)
            {
                var definition = Charge(CanonicalName.NodeId(Definition(spec.Definition)));
                var arguments = Arguments(spec).Select(a => Name(a, depth + 1)).ToArray();
                var name = CanonicalName.GenericInstance(definition, arguments);
                left -= name.Length - definition.Length - arguments.Sum(a => (long)a.Length);
                return name;
            }

            private string Wrapped(string inner, Func<string, string> wrap)
            {
                var name = wrap(inner);
                left -= name.Length - inner.Length;
                return name;
            }

            // A part that does not fit what is left reads <unknown>.
            private string Charge(string part)
            {
                if (part.Length > left)
                {
                    Spent = true;
                    left = 0;
                    return CanonicalName.UnknownPart;
                }
                left -= part.Length;
                return part;
            }
            #endregion

            #region Fields
            private readonly Dictionary<TypeDesc, string> rendered = new(ReferenceEqualityComparer.Instance);
            private long left = MaxNameChars;
            #endregion
        }
        #endregion
    }
    #endregion
}
