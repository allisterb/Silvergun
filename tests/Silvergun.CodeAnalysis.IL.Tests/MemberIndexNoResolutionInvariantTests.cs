namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase A1 acceptance criterion 3, pinned <b>structurally</b> — the same stance as
/// <see cref="ReferenceSideNamingInvariantTests"/> (names come from references, never from resolved definitions) and
/// the same technique as <see cref="CapabilityKeyCompositionArchitectureTests"/> (read the compiled IL of our own
/// library): no <c>src/</c> code path used by <see cref="MemberIndex"/> or <see cref="MethodGraph"/> touches
/// <c>ResolvedMethod</c>, <c>ResolvedType</c> or <c>ResolveReference</c>.
/// <para>
/// <b>Why it matters.</b> <c>Host.ResolveReference</c> is a linear <c>SingleOrDefault</c> scan per lookup (measured
/// 500x slower on one assembly) that THROWS on an ambiguous match, and both <c>Resolved*</c> properties go through it
/// (ADR-0020 amendment items 3 and 7). One such read inside the traversal makes the graph quadratic and turns an
/// ambiguous reference — routine in real packages — into an exception. No behavioural test sees it: the fixture
/// graph comes out identical, only slower.
/// </para>
/// <para>
/// <b>How.</b> Every method of the A1 types (and of their nested and compiler-generated types: lambdas, display
/// classes, the private <c>Builder</c>) is a root. From there the walk follows every call, <c>newobj</c> and
/// <c>ldftn</c> whose target is defined in <c>Silvergun.CodeAnalysis.IL.dll</c> — so <c>ModelNames</c>,
/// <c>CanonicalName</c> and anything else they reach are scanned too — and records every member referenced along
/// the way. Safe in-process: the assembly read is our own, built from ordinary C#.
/// </para>
/// <para>
/// <b>Limit.</b> Static: a call through an interface or a delegate is followed to its declared target only, and
/// Analysis.Net's own code (<c>ext/</c>) is not walked; the guard covers what <c>src/</c> calls directly.
/// </para>
/// </summary>
public sealed class MemberIndexNoResolutionInvariantTests : IClassFixture<AssemblyAnalyzerFixture>, IDisposable
{
    #region Constructors
    /// <summary>The shared fixture is taken only to initialize the Silvergun runtime; the subject is our own library.</summary>
    public MemberIndexNoResolutionInvariantTests(AssemblyAnalyzerFixture fixture)
    {
        _ = fixture;

        var load = AssemblyAnalyzer.Load(typeof(MemberIndex).Assembly.Location);
        Assert.True(load.IsSuccess, load.Message);
        library = load.Value;
        closure = Walk(library);
    }
    #endregion

    #region Methods
    /// <summary>THE GUARD: nothing reachable from the A1 types references a resolving member.</summary>
    [Fact]
    public void MemberIndexAndMethodGraph_NeverReferenceResolvedMethodResolvedTypeOrResolveReference()
    {
        var hits = closure.References
            .Where(r => Forbidden.Contains(Bare(r.Member)))
            .Select(r => $"{r.From} references {r.Member}")
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            hits.Length == 0,
            "A1's member index / graph must never resolve through Analysis.Net (ADR-0020 amendment items 3 and 7):"
                + Environment.NewLine + string.Join(Environment.NewLine, hits));
    }

    /// <summary>
    /// Non-vacuity: the roots exist, the walk leaves the two A1 files (it reaches the naming code the index is built
    /// on), and the members it inspects include Analysis.Net <c>Model</c> reads — the population a forbidden read would
    /// belong to. A rename or a broken walk fails here as "the guard lost its subject", not as a silent pass.
    /// </summary>
    [Fact]
    public void Walk_CoversTheA1TypesAndTheSrcCodeTheyReach()
    {
        foreach (var root in RootTypes)
            Assert.Contains(closure.Methods, m => m.StartsWith(root + ".", StringComparison.Ordinal));

        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.Resolve(", StringComparison.Ordinal));
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.MethodGraph.Builder.Walk(", StringComparison.Ordinal));
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.ModelNames.", StringComparison.Ordinal));
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.CanonicalName.", StringComparison.Ordinal));
        // Compiler-generated lambda bodies are walked too (Guard(() => ...) in MemberIndex).
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.<>c", StringComparison.Ordinal));

        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == "ContainingType");
        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == "GenericMethod");
        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Bytecode.", StringComparison.Ordinal));
    }

    /// <summary>
    /// A2 S1 (spec acceptance 4): the guard covers the CHA code — DispatchTargets and everything it reaches since S1b
    /// (the forwarder-aware type key, the shared forwarder walk, the candidate filter <c>Dispatch</c> with the bounded,
    /// per-Dispatch memoized walks of the nested <c>HierarchyWalk</c> — <c>Below</c> up <c>Supertypes</c>,
    /// <c>InheritedBelow</c> down the subtype map, both through its shared <c>Search</c> — <c>MayBeInterface</c>, the parameter
    /// and name matchers), the return-type check of <c>ResolveOwn</c>, the open-type walk, the S1d work budget
    /// (<c>DispatchWork</c>'s <c>Charge</c>, <c>ChargeOnce</c>, <c>Add</c>), and the graph's fan-out —
    /// and that code reads the Model members a forbidden read would sit beside (<c>IsVirtual</c>, <c>IsAbstract</c>,
    /// <c>IsStatic</c>, <c>Base</c>).
    /// </summary>
    [Fact]
    public void Walk_CoversTheChaCode()
    {
        foreach (var method in ChaMethods)
            Assert.Contains(closure.Methods, m => m.StartsWith(method, StringComparison.Ordinal));

        foreach (var member in new[] { "IsVirtual", "IsAbstract", "IsStatic", "Base" })
            Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == member);
    }

    /// <summary>
    /// A2 S2 (spec acceptance 4): the guard covers the state-machine code — <c>StateMachineTargets</c>, the precomputed
    /// <c>StateMachines</c> walk down the subtype map, and the graph's <c>AddImplied&lt;T&gt;</c> (S3's name for S2's
    /// <c>AddStateMachines</c>, which the state-machine and type-initializer edges now share; generic since S3 review N5,
    /// taking a STATIC lambda per call) — and that code reads the Model members a forbidden read would sit beside
    /// (<c>ContainingType</c> and <c>GenericArguments</c> of the reference, <c>IsStatic</c> of the candidate
    /// <c>MoveNext</c>). The static lambdas that ask the index are walked too: one in the builder's lambda class
    /// references <c>StateMachineTargets</c>.
    /// </summary>
    [Fact]
    public void Walk_CoversTheStateMachineCode()
    {
        foreach (var method in StateMachineMethods)
            Assert.Contains(closure.Methods, m => m.StartsWith(method, StringComparison.Ordinal));
        Assert.Contains(closure.References, r => r.From.StartsWith(BuilderLambdas, StringComparison.Ordinal) &&
                                                 r.Member.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.StateMachineTargets(", StringComparison.Ordinal));

        foreach (var member in new[] { "ContainingType", "GenericArguments", "IsStatic" })
            Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == member);
    }

    /// <summary>
    /// A2 S3 (spec acceptance 4): the guard covers the type-initializer, <c>ldtoken</c> and module code — both
    /// <c>TypeInitializerTargets</c> overloads, S3 review W3's <c>InstanceInitializerTargets</c>, the shared <c>Lookup</c>,
    /// <c>Module</c>, and the graph's <c>AddImplied&lt;T&gt;</c>, <c>AddToken</c>, <c>AddResolved</c> and <c>AddModule</c>
    /// — and reaches <see cref="ModuleMetadata"/>'s own code through them, and the builder's static lambdas that ask
    /// <c>TypeInitializerTargets</c> and <c>InstanceInitializerTargets</c>. That code reads the Model members a forbidden
    /// read would sit beside: a field reference's <c>IsStatic</c> and <c>ContainingType</c>, a method reference's
    /// <c>Name</c>, and <c>LoadTokenInstruction.Token</c>.
    /// </summary>
    [Fact]
    public void Walk_CoversTheTypeInitializerTokenAndModuleCode()
    {
        foreach (var method in S3Methods)
            Assert.Contains(closure.Methods, m => m.StartsWith(method, StringComparison.Ordinal));
        foreach (var asked in new[] { "TypeInitializerTargets(", "InstanceInitializerTargets(" })
            Assert.Contains(closure.References, r => r.From.StartsWith(BuilderLambdas, StringComparison.Ordinal) &&
                                                     r.Member.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex." + asked, StringComparison.Ordinal));

        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.IFieldReference.", StringComparison.Ordinal) && Bare(r.Member) == "IsStatic");
        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == "Name");
        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Bytecode.LoadTokenInstruction.", StringComparison.Ordinal) && Bare(r.Member) == "Token");
    }

    /// <summary>
    /// The guard can go red. A MUTANT library is emitted (<see cref="EmittedAssembly"/>; read as metadata only) with the
    /// root types' names: its <c>MemberIndex.DispatchTargets</c> reads <c>IMethodReference.ResolvedMethod</c> directly,
    /// and its <c>MemberIndex.OpenTypes</c> reaches <c>IBasicType.ResolvedType</c> only through a helper in a NON-root
    /// type. Since A2 S2 it also has the state-machine shapes: <c>MemberIndex.StateMachineTargets</c> reads
    /// <c>IBasicType.ResolvedType</c> directly, and <c>MemberIndex.StateMachines</c> reaches it only through a helper of
    /// its own. Since A2 S3 it has the type-initializer, token and module shapes too: <c>MemberIndex.TypeInitializerTargets</c>
    /// in two overloads (one reading <c>ResolvedType</c>, one <c>ResolvedMethod</c>), <c>MemberIndex.Lookup</c> through a
    /// helper of its own, and a nested <c>MethodGraph.Builder</c> whose <c>AddToken</c> reads <c>ResolvedMethod</c> and
    /// whose <c>AddModule</c> goes through another helper. The same walk that guards the real library names all of them —
    /// so a read like any of these, added to the real CHA, state-machine, type-initializer, token or module code (whose
    /// methods <see cref="Walk_CoversTheChaCode"/>, <see cref="Walk_CoversTheStateMachineCode"/> and
    /// <see cref="Walk_CoversTheTypeInitializerTokenAndModuleCode"/> show are walked), turns <see cref="MemberIndexAndMethodGraph_NeverReferenceResolvedMethodResolvedTypeOrResolveReference"/> red.
    /// </summary>
    [Fact]
    public void Walk_OverAMutantThatResolves_FindsTheForbiddenReads()
    {
        using var emitted = new EmittedAssembly();
        var path = emitted.Save("Silvergun.CodeAnalysis.IL", DefineMutant);
        var load = AssemblyAnalyzer.Load(path);
        Assert.True(load.IsSuccess, load.Message);
        using var mutant = load.Value;

        var mutantClosure = Walk(mutant);
        var hits = mutantClosure.References.Where(r => Forbidden.Contains(Bare(r.Member))).Select(r => $"{r.From} -> {Bare(r.Member)}").ToArray();

        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.DispatchTargets(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedMethod", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.Peek(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(mutantClosure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.Peek(", StringComparison.Ordinal));
        Assert.DoesNotContain(mutantClosure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.Unreached(", StringComparison.Ordinal));

        // A2 S2: the state-machine shapes.
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.StateMachineTargets(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekMachine(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(mutantClosure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekMachine(", StringComparison.Ordinal));
        Assert.Contains(mutantClosure.References, r => r.From.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.StateMachines(", StringComparison.Ordinal) &&
                                                       r.Member.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekMachine(", StringComparison.Ordinal));

        // A2 S3: the type-initializer, token and module shapes.
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.TypeInitializerTargets(Model.Types.IBasicType)", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.TypeInitializerTargets(Model.Types.IMethodReference)", StringComparison.Ordinal) && h.EndsWith("-> ResolvedMethod", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekLookup(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(mutantClosure.References, r => r.From.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.Lookup(", StringComparison.Ordinal) &&
                                                       r.Member.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekLookup(", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddToken(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedMethod", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekModule(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(mutantClosure.References, r => r.From.StartsWith("Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddModule(", StringComparison.Ordinal) &&
                                                       r.Member.StartsWith("Silvergun.CodeAnalysis.IL.Helpers.PeekModule(", StringComparison.Ordinal));

        // S3 review: InstanceInitializerTargets (W3), and a resolving read inside one of the builder's static lambdas (N5).
        Assert.Contains(hits, h => h.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.InstanceInitializerTargets(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith(BuilderLambdas + "<Visit>b__0_0(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedMethod", StringComparison.Ordinal));
    }

    // MemberIndex.DispatchTargets(IMethodReference) => _ = reference.ResolvedMethod; MemberIndex.OpenTypes(IBasicType)
    // => Helpers.Peek(type); Helpers.Peek(IBasicType) => _ = type.ResolvedType; Helpers.Unreached(IBasicType) likewise,
    // but nothing calls it (the walk must not start outside the roots). A2 S2: MemberIndex.StateMachineTargets(IBasicType)
    // => _ = type.ResolvedType; MemberIndex.StateMachines(IBasicType) => Helpers.PeekMachine(type), which reads it. A2 S3:
    // MemberIndex.TypeInitializerTargets(IBasicType) => _ = type.ResolvedType; TypeInitializerTargets(IMethodReference) =>
    // _ = method.ResolvedMethod; MemberIndex.Lookup(IBasicType) => Helpers.PeekLookup(type); and the nested
    // MethodGraph.Builder's AddToken(IMethodReference) => _ = method.ResolvedMethod, AddModule(IBasicType) =>
    // Helpers.PeekModule(type), each Peek reading ResolvedType. S3 review: MemberIndex.InstanceInitializerTargets(IBasicType)
    // => _ = type.ResolvedType; and a lambda class MethodGraph.Builder.<>c whose <Visit>b__0_0(IMethodReference) reads
    // method.ResolvedMethod, the shape of the builder's static lambdas.
    private static void DefineMutant(System.Reflection.Emit.ModuleBuilder module)
    {
        const System.Reflection.MethodAttributes Static = System.Reflection.MethodAttributes.Public | System.Reflection.MethodAttributes.Static;
        var resolvedMethod = typeof(Model.Types.IMethodReference).GetProperty(nameof(Model.Types.IMethodReference.ResolvedMethod))!.GetGetMethod()!;
        var resolvedType = typeof(Model.Types.IBasicType).GetProperty(nameof(Model.Types.IBasicType.ResolvedType))!.GetGetMethod()!;

        var helpers = module.DefineType("Silvergun.CodeAnalysis.IL.Helpers", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Class);
        System.Reflection.Emit.MethodBuilder Reads(string name)
        {
            var method = helpers.DefineMethod(name, Static, typeof(void), [typeof(Model.Types.IBasicType)]);
            var il = method.GetILGenerator();
            il.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
            il.Emit(System.Reflection.Emit.OpCodes.Callvirt, resolvedType);
            il.Emit(System.Reflection.Emit.OpCodes.Pop);
            il.Emit(System.Reflection.Emit.OpCodes.Ret);
            return method;
        }
        var peek = Reads("Peek");
        Reads("Unreached");
        var peekMachine = Reads("PeekMachine");
        var peekLookup = Reads("PeekLookup");
        var peekModule = Reads("PeekModule");

        var index = module.DefineType("Silvergun.CodeAnalysis.IL.MemberIndex", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Class);
        var dispatch = index.DefineMethod("DispatchTargets", Static, typeof(void), [typeof(Model.Types.IMethodReference)]).GetILGenerator();
        dispatch.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
        dispatch.Emit(System.Reflection.Emit.OpCodes.Callvirt, resolvedMethod);
        dispatch.Emit(System.Reflection.Emit.OpCodes.Pop);
        dispatch.Emit(System.Reflection.Emit.OpCodes.Ret);
        var open = index.DefineMethod("OpenTypes", Static, typeof(void), [typeof(Model.Types.IBasicType)]).GetILGenerator();
        open.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
        open.Emit(System.Reflection.Emit.OpCodes.Call, peek);
        open.Emit(System.Reflection.Emit.OpCodes.Ret);
        var targets = index.DefineMethod("StateMachineTargets", Static, typeof(void), [typeof(Model.Types.IBasicType)]).GetILGenerator();
        targets.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
        targets.Emit(System.Reflection.Emit.OpCodes.Callvirt, resolvedType);
        targets.Emit(System.Reflection.Emit.OpCodes.Pop);
        targets.Emit(System.Reflection.Emit.OpCodes.Ret);
        var machines = index.DefineMethod("StateMachines", Static, typeof(void), [typeof(Model.Types.IBasicType)]).GetILGenerator();
        machines.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
        machines.Emit(System.Reflection.Emit.OpCodes.Call, peekMachine);
        machines.Emit(System.Reflection.Emit.OpCodes.Ret);

        // A2 S3. One body per shape: read `resolving` on the argument directly, or call a helper that does.
        void Reads2(System.Reflection.Emit.TypeBuilder owner, string name, Type parameter, System.Reflection.MethodInfo through, bool call)
        {
            var il = owner.DefineMethod(name, Static, typeof(void), [parameter]).GetILGenerator();
            il.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
            if (call)
            {
                il.Emit(System.Reflection.Emit.OpCodes.Call, through);
            }
            else
            {
                il.Emit(System.Reflection.Emit.OpCodes.Callvirt, through);
                il.Emit(System.Reflection.Emit.OpCodes.Pop);
            }
            il.Emit(System.Reflection.Emit.OpCodes.Ret);
        }
        Reads2(index, "TypeInitializerTargets", typeof(Model.Types.IBasicType), resolvedType, call: false);
        Reads2(index, "TypeInitializerTargets", typeof(Model.Types.IMethodReference), resolvedMethod, call: false);
        Reads2(index, "Lookup", typeof(Model.Types.IBasicType), peekLookup, call: true);
        var graph = module.DefineType("Silvergun.CodeAnalysis.IL.MethodGraph", System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Class);
        var builder = graph.DefineNestedType("Builder", System.Reflection.TypeAttributes.NestedPrivate | System.Reflection.TypeAttributes.Class);
        Reads2(builder, "AddToken", typeof(Model.Types.IMethodReference), resolvedMethod, call: false);
        Reads2(builder, "AddModule", typeof(Model.Types.IBasicType), peekModule, call: true);
        Reads2(index, "InstanceInitializerTargets", typeof(Model.Types.IBasicType), resolvedType, call: false);
        var lambdas = builder.DefineNestedType("<>c", System.Reflection.TypeAttributes.NestedPrivate | System.Reflection.TypeAttributes.Class);
        Reads2(lambdas, "<Visit>b__0_0", typeof(Model.Types.IMethodReference), resolvedMethod, call: false);

        helpers.CreateType();
        index.CreateType();
        graph.CreateType();
        builder.CreateType();
        lambdas.CreateType();
    }

    public void Dispose() => library.Dispose();

    // Every method reachable from the roots by call/callvirt/newobj/ldftn/ldvirtftn within this library, and every
    // method or field it references (wherever that member lives).
    private static Closure Walk(AssemblyAnalyzer library)
    {
        var definitions = library.Module.GetAllTypes().SelectMany(t => t.Methods).ToArray();
        var byId = definitions.GroupBy(Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);

        var queue = new Queue<IMethodDefinition>(definitions.Where(m => RootTypes.Any(root => Id(m).StartsWith(root + ".", StringComparison.Ordinal))));
        var seen = new HashSet<string>(queue.Select(Id), StringComparer.Ordinal);
        var references = new List<(string From, string Member)>();

        while (queue.Count > 0)
        {
            var method = queue.Dequeue();
            var from = Id(method);
            var body = AssemblyAnalyzer.TryReadBody(method);
            Assert.False(body.IsUnreadable, $"{from}: {body.Error}");

            foreach (var value in body.Body?.Operations.Select(op => op.Value) ?? [])
            {
                switch (value)
                {
                    case IMethodReference callee:
                        var id = Id(callee);
                        references.Add((from, id));
                        foreach (var next in byId.GetValueOrDefault(id) ?? [])
                            if (seen.Add(Id(next)))
                                queue.Enqueue(next);
                        break;
                    case IFieldReference field:
                        references.Add((from, $"{CciNames.TypeName(field.ContainingType)}.{field.Name.Value}"));
                        break;
                }
            }
        }

        return new Closure(seen, references);
    }

    // The definition behind a reference, by the same reference-side links MechanismCallSites uses, then its node id.
    private static string Id(IMethodReference method)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            if (method is IGenericMethodInstanceReference instance) method = instance.GenericMethod;
            else if (method is ISpecializedMethodReference specialized) method = specialized.UnspecializedVersion;
            else break;
        }

        return CanonicalName.NodeId(CciNames.Of(method));
    }

    // "Ns.Type.get_ResolvedType()" -> "ResolvedType"; "Ns.Type.ResolveMethod" (a field) -> "ResolveMethod".
    private static string Bare(string member)
    {
        var name = member.Split('(')[0];
        name = name[(name.LastIndexOf('.') + 1)..];
        return name.StartsWith("get_", StringComparison.Ordinal) || name.StartsWith("set_", StringComparison.Ordinal) ? name[4..] : name;
    }
    #endregion

    #region Fields
    /// <summary>The types declared in <c>MemberIndex.cs</c> and <c>MethodGraph.cs</c> that carry code.</summary>
    private static readonly string[] RootTypes =
    [
        "Silvergun.CodeAnalysis.IL.MemberIndex",
        "Silvergun.CodeAnalysis.IL.MethodResolution",
        "Silvergun.CodeAnalysis.IL.IndexCoverage",
        "Silvergun.CodeAnalysis.IL.MethodGraph",
        "Silvergun.CodeAnalysis.IL.MethodNode",
        "Silvergun.CodeAnalysis.IL.MethodEdge",
        "Silvergun.CodeAnalysis.IL.GraphOpacity",
        "Silvergun.CodeAnalysis.IL.GraphBudget",
        "Silvergun.CodeAnalysis.IL.ResolutionCounts",
        "Silvergun.CodeAnalysis.IL.GraphCoverage",
    ];

    /// <summary>The A2 S1 (CHA) methods the walk must reach, by node-id prefix.</summary>
    private static readonly string[] ChaMethods =
    [
        "Silvergun.CodeAnalysis.IL.MemberIndex.DispatchTargets(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.IsOpen(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.OpenTypes(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.Dispatch(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.HierarchyWalk.Below(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.HierarchyWalk.InheritedBelow(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.HierarchyWalk.Search(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.MayBeInterface(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.Supertypes(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.ResolveOwn(",
        "Silvergun.CodeAnalysis.IL.ModelNames.ReturnType(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.MayOverride(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.ImplementedName(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.IndexType(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.Walk`1(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.TypeScope.Of(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.TypeScope.Land(",
        "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddCall(",
        // S1d (review 2, W-A): the CHA work budget charged by DispatchTargets, Dispatch and HierarchyWalk.Search.
        "Silvergun.CodeAnalysis.IL.MemberIndex.DispatchWork.Charge(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.DispatchWork.ChargeOnce(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.DispatchWork.Add(",
    ];

    /// <summary>The A2 S2 (state-machine edge) methods the walk must reach, by node-id prefix.</summary>
    private static readonly string[] StateMachineMethods =
    [
        "Silvergun.CodeAnalysis.IL.MemberIndex.StateMachineTargets(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.StateMachines(",
        "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddImplied`1(",
    ];

    /// <summary>The compiler's class for the graph builder's (static) lambdas, by node-id prefix.</summary>
    private const string BuilderLambdas = "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.<>c.";

    /// <summary>The A2 S3 (type-initializer, ldtoken and module) methods the walk must reach, by node-id prefix.</summary>
    private static readonly string[] S3Methods =
    [
        "Silvergun.CodeAnalysis.IL.MemberIndex.TypeInitializerTargets(Model.Types.IFieldReference)",
        "Silvergun.CodeAnalysis.IL.MemberIndex.TypeInitializerTargets(Model.Types.IMethodReference)",
        "Silvergun.CodeAnalysis.IL.MemberIndex.InstanceInitializerTargets(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.Lookup(",
        "Silvergun.CodeAnalysis.IL.MemberIndex.Module(",
        "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddImplied`1(",
        "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddToken(",
        "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddResolved(",
        "Silvergun.CodeAnalysis.IL.MethodGraph.Builder.AddModule(",
        "Silvergun.CodeAnalysis.IL.ModuleMetadata.Merge(",
    ];

    /// <summary>
    /// The resolving members of Analysis.Net's <c>Model</c> (and their CCI namesakes): the two lazy properties, the
    /// host lookup they call, and the backing delegates behind the properties.
    /// </summary>
    private static readonly HashSet<string> Forbidden = new(StringComparer.Ordinal)
    {
        "ResolvedMethod", "ResolvedType", "ResolveReference", "ResolveMethod", "ResolveType",
    };

    private readonly AssemblyAnalyzer library;
    private readonly Closure closure;
    #endregion

    #region Child types
    private sealed record Closure(IReadOnlySet<string> Methods, IReadOnlyList<(string From, string Member)> References);
    #endregion
}
