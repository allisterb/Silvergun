namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

/// <summary>
/// The folders the S4.3 reflection-target tests read (docs/agent/tasks/ssa-facts-s4.md §3, "Reflection targets", D4),
/// each built once as a <see cref="MethodGraph"/> (sites: <see cref="SinkSites.Of"/>; candidates' oracle:
/// <see cref="OwnMembers.Of"/> and the graph's own nodes) and opened once as an <see cref="SsaSession"/>, read as metadata
/// only:
/// <list type="bullet">
/// <item><description><c>SsaReflection</c>, emitted with <see cref="PersistedAssemblyBuilder"/>: the own targets
/// (<c>Own.Target</c> with two constructors, three <c>Run</c> overloads, <c>Solo</c>, a method and a get-only property both
/// named <c>Dual</c>, a property <c>P</c> and a field <c>F</c>; <c>Own.Outer+Inner</c>, <c>Own.Outer+Nested`1</c>,
/// <c>Own.G`1</c>, and <c>Own.Long</c> with a method whose node id is past <see cref="Reachability.MaxNameChars"/>), and
/// <c>Refl.Calls</c>, one method per chain shape, each ending in a real reflection sink of the built-in capability
/// map;</description></item>
/// <item><description>the merge folder, <c>SsaReflMergeA</c> and <c>SsaReflMergeB</c>, which both define
/// <c>Merge.Calls</c>: <c>Run</c> names a different type in each (A defines <c>Merge.Alpha</c>, B <c>Merge.Beta</c>), and
/// <c>Mixed</c> invokes <c>Merge.Shared.Solo</c> through <c>GetMethod</c> in A and its constructor through
/// <c>GetConstructor</c> in B, at the same offsets.</description></item>
/// </list>
/// Types stay shallow (CLAUDE.md): one generic argument, one nesting level, no arrays of arrays.
/// </summary>
public sealed class SsaReflectionFixture : IDisposable
{
    #region Constructors
    public SsaReflectionFixture()
    {
        Path = emitted.Save(AssemblyName, Define);
        MergePaths = [emitted.Save("SsaReflMergeA", m => DefineMerged(m, first: true), "merge"), emitted.Save("SsaReflMergeB", m => DefineMerged(m, first: false), "merge")];
        Graph = Build(Path);
        MergeGraph = Build(MergePaths);
        Sites = SinkSites.Of(Graph);
        MergeSites = SinkSites.Of(MergeGraph);
        Members = OwnMembers.Of(Graph);
        MergeMembers = OwnMembers.Of(MergeGraph);

        Session = SsaSession.Open([Path]);
        Facts = SsaSinkFacts.Extract(Session, Sites, members: Members);
        MergeSession = SsaSession.Open(MergePaths);
        MergeFacts = SsaSinkFacts.Extract(MergeSession, MergeSites, members: MergeMembers);
    }
    #endregion

    #region Properties
    public string Path { get; }

    public string[] MergePaths { get; }

    public MethodGraph Graph { get; }

    public MethodGraph MergeGraph { get; }

    public IReadOnlyList<SinkSite> Sites { get; }

    public IReadOnlyList<SinkSite> MergeSites { get; }

    public OwnMembers Members { get; }

    public OwnMembers MergeMembers { get; }

    public SsaSession Session { get; }

    public SsaSession MergeSession { get; }

    /// <summary><see cref="Sites"/>' facts under the default bounds and map, with <see cref="Members"/>.</summary>
    public SsaFolderFacts Facts { get; }

    public SsaFolderFacts MergeFacts { get; }
    #endregion

    #region Methods
    /// <summary>The node id of <c>Refl.Calls.<paramref name="method"/></c> (no overloads among the callers).</summary>
    public string NodeIdOf(string method) => NodeIdIn(Graph, CallsType + "." + method);

    public string MergeNodeIdOf(string method) => NodeIdIn(MergeGraph, MergeCallsType + "." + method);

    /// <summary>The one site of <paramref name="method"/> whose callee key is <paramref name="calleeKey"/>.</summary>
    public SinkSite SiteOf(string method, string calleeKey) => SiteAt(CallsType + "." + method, calleeKey);

    /// <summary>The one site of the own method whose classification key is <paramref name="methodKey"/>, calling <paramref name="calleeKey"/>.</summary>
    public SinkSite SiteAt(string methodKey, string calleeKey)
    {
        var id = NodeIdIn(Graph, methodKey);
        var method = methodKey;
        var sites = Sites.Where(s => s.NodeId == id && s.CalleeKey == calleeKey).ToArray();
        return sites.Length == 1 ? sites[0] : throw new InvalidOperationException($"{method} has {sites.Length} sites calling {calleeKey}, not one.");
    }

    /// <summary>The own node ids of <paramref name="graph"/> with classification key <paramref name="key"/>, ordinal: the candidates' oracle.</summary>
    public static string[] OwnNodes(MethodGraph graph, string key) =>
        [.. graph.Nodes.Where(n => n.Kind != MethodNodeKind.External && n.ClassificationKey == key).Select(n => n.NodeId).Order(StringComparer.Ordinal)];

    public void Dispose()
    {
        Session.Dispose();
        MergeSession.Dispose();
        emitted.Dispose();
    }

    private static string NodeIdIn(MethodGraph graph, string key)
    {
        var nodes = OwnNodes(graph, key);
        return nodes.Length == 1 ? nodes[0] : throw new InvalidOperationException($"{key} has {nodes.Length} own nodes, not one.");
    }

    private static MethodGraph Build(params string[] paths)
    {
        using var model = ModelAssemblies.Load(paths);
        return MethodGraph.Build(model.Index());
    }

    private static void Define(ModuleBuilder module)
    {
        // ---- The own targets ----
        var target = module.DefineType(TargetType, TypeAttributes.Public | TypeAttributes.Class);
        Body(target.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        Body(target.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, [typeof(int)]), Ret);
        Body(Static(target, "Run", typeof(void)), Ret);
        Body(Static(target, "Run", typeof(void), typeof(int)), Ret);
        Body(Static(target, "Run", typeof(void), typeof(string)), Ret);
        Body(Static(target, "Solo", typeof(void)), Ret);
        Body(Static(target, "Dual", typeof(void)), Ret);
        var getDual = Static(target, "get_Dual", typeof(int));
        Body(getDual, ReturnZero);
        target.DefineProperty("Dual", PropertyAttributes.None, typeof(int), null).SetGetMethod(getDual);
        var getP = Static(target, "get_P", typeof(int));
        Body(getP, ReturnZero);
        var setP = Static(target, "set_P", typeof(void), typeof(int));
        Body(setP, Ret);
        var p = target.DefineProperty("P", PropertyAttributes.None, typeof(int), null);
        p.SetGetMethod(getP);
        p.SetSetMethod(setP);
        target.DefineField("F", typeof(int), FieldAttributes.Public | FieldAttributes.Static);

        var outer = module.DefineType("Own.Outer", TypeAttributes.Public | TypeAttributes.Class);
        Body(outer.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        var inner = outer.DefineNestedType("Inner", TypeAttributes.NestedPublic | TypeAttributes.Class);
        Body(inner.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        var nested = outer.DefineNestedType("Nested`1", TypeAttributes.NestedPublic | TypeAttributes.Class);
        nested.DefineGenericParameters("T");
        Body(nested.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        var generic = module.DefineType("Own.G`1", TypeAttributes.Public | TypeAttributes.Class);
        generic.DefineGenericParameters("T");
        Body(generic.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        Body(Static(generic, "Run", typeof(void)), Ret);
        var longType = module.DefineType("Own.Long", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        Body(Static(longType, LongName, typeof(void)), Ret);
        // A non-generic type whose own name carries a tick (W2's literal spelling).
        var ticked = module.DefineType(TickedType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        Body(Static(ticked, "Run", typeof(void)), Ret);
        // W1: Own.Foo<int> and a non-generic type literally named Foo`1<System.Int32> render alike as typeof constants.
        var foo = module.DefineType("Own.Foo`1", TypeAttributes.Public | TypeAttributes.Class);
        foo.DefineGenericParameters("T");
        Body(Static(foo, "Run", typeof(void)), Ret);
        var alias = module.DefineType(AliasType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        Body(Static(alias, "Run", typeof(void)), Ret);
        Body(Static(alias, "Run", typeof(void), typeof(int)), Ret);
        var fooOfInt = foo.MakeGenericType(typeof(int));

        // ---- The callers ----
        var calls = module.DefineType(CallsType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var methodField = calls.DefineField("Method", typeof(MethodInfo), FieldAttributes.Public | FieldAttributes.Static);
        var typeField = calls.DefineField("TypeField", typeof(Type), FieldAttributes.Public | FieldAttributes.Static);
        var nothing = Static(calls, "Nothing", typeof(void));
        Body(nothing, Ret);
        var makeMethod = Static(calls, "MakeMethod", typeof(MethodInfo));
        Body(makeMethod, il =>
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ret);
        });

        // Type.GetType("Own.Target").GetMethod("Run").Invoke(null, null).
        Caller(calls, "GetTypeGetMethodInvoke", il =>
        {
            GetTypeOf(il, TargetType);
            GetMethod(il, "Run");
            Invoke(il);
        });
        // Activator.CreateInstance(typeof(Own.Target)).
        Caller(calls, "TypeofCreateInstance", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Target).GetMethod("Run").Invoke(null, null).
        Caller(calls, "TypeofGetMethodInvoke", il =>
        {
            Typeof(il, target);
            GetMethod(il, "Run");
            Invoke(il);
        });
        // Method.Invoke(null, null), Method a static field.
        Caller(calls, "FieldInvoke", il =>
        {
            il.Emit(OpCodes.Ldsfld, methodField);
            Invoke(il);
        });
        // TypeField.GetMethod("Run").Invoke(null, null).
        Caller(calls, "FieldTypeGetMethodInvoke", il =>
        {
            il.Emit(OpCodes.Ldsfld, typeField);
            GetMethod(il, "Run");
            Invoke(il);
        });
        // MakeMethod().Invoke(null, null): an own call, not a lookup.
        Caller(calls, "CallResultInvoke", il =>
        {
            il.Emit(OpCodes.Call, makeMethod);
            Invoke(il);
        });
        // m.Invoke(null, null), m the caller's argument 0.
        Body(Static(calls, "ParameterInvoke", typeof(void), typeof(MethodInfo)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            Invoke(il);
            il.Emit(OpCodes.Ret);
        });
        // t.GetMethod("Run").Invoke(null, null), t the caller's argument 0.
        Body(Static(calls, "ParameterTypeGetMethodInvoke", typeof(void), typeof(Type)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            GetMethod(il, "Run");
            Invoke(il);
            il.Emit(OpCodes.Ret);
        });
        // Type.GetType("System.String").GetMethod("Concat").Invoke(null, null), and Activator.CreateInstance(typeof(object)).
        Caller(calls, "ExternalGetMethodInvoke", il =>
        {
            GetTypeOf(il, "System.String");
            GetMethod(il, "Concat");
            Invoke(il);
        });
        Caller(calls, "TypeofExternalCreateInstance", il =>
        {
            Typeof(il, typeof(object));
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
        });
        // Assembly.Load("X").GetType("Ns.T").GetMethod("M").Invoke(null, null).
        Caller(calls, "AssemblyLoadGetTypeInvoke", il =>
        {
            il.Emit(OpCodes.Ldstr, "X");
            il.Emit(OpCodes.Call, Apis.AssemblyLoad);
            il.Emit(OpCodes.Ldstr, "Ns.T");
            il.Emit(OpCodes.Callvirt, Apis.AssemblyGetType);
            GetMethod(il, "M");
            Invoke(il);
        });
        // Activator.CreateInstance(Assembly.Load("Asm").GetType("Own.Target")).
        Caller(calls, "AssemblyLoadCreateInstance", il =>
        {
            il.Emit(OpCodes.Ldstr, "Asm");
            il.Emit(OpCodes.Call, Apis.AssemblyLoad);
            il.Emit(OpCodes.Ldstr, TargetType);
            il.Emit(OpCodes.Callvirt, Apis.AssemblyGetType);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
        });
        // Activator.CreateInstance("Asm", "Own.Target").
        Caller(calls, "CreateInstanceByNames", il =>
        {
            il.Emit(OpCodes.Ldstr, "Asm");
            il.Emit(OpCodes.Ldstr, TargetType);
            il.Emit(OpCodes.Call, Apis.CreateInstanceByNames);
            il.Emit(OpCodes.Pop);
        });
        // Activator.CreateInstance<Own.Target>().
        Caller(calls, "CreateInstanceGeneric", il =>
        {
            il.Emit(OpCodes.Call, Apis.CreateInstanceOfT.MakeGenericMethod(target));
            il.Emit(OpCodes.Pop);
        });
        // Activator.CreateInstance(typeof(Own.Target), true).
        Caller(calls, "CreateInstanceNonPublic", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Call, Apis.CreateInstanceNonPublic);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Target).GetConstructor(Type.EmptyTypes), then MethodBase.Invoke(null, null) or ConstructorInfo.Invoke(null).
        Caller(calls, "GetConstructorInvoke", il =>
        {
            GetConstructor(il, target);
            Invoke(il);
        });
        Caller(calls, "GetConstructorConstructorInvoke", il =>
        {
            GetConstructor(il, target);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, Apis.ConstructorInvoke);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Target).GetProperty("P").GetValue(null), and .GetField("F").GetValue(null).
        Caller(calls, "PropertyGetValue", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Ldstr, "P");
            il.Emit(OpCodes.Callvirt, Apis.GetProperty);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, Apis.PropertyGetValue);
            il.Emit(OpCodes.Pop);
        });
        Caller(calls, "FieldGetValue", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Ldstr, "F");
            il.Emit(OpCodes.Callvirt, Apis.GetField);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, Apis.FieldGetValue);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Target).InvokeMember("Dual", InvokeMethod, null, null, null).
        Caller(calls, "InvokeMember", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Ldstr, "Dual");
            il.Emit(OpCodes.Ldc_I4, (int)BindingFlags.InvokeMethod);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, Apis.InvokeMember);
            il.Emit(OpCodes.Pop);
        });
        // Delegate.CreateDelegate(typeof(Action), typeof(Own.Target).GetMethod("Solo")).
        Caller(calls, "CreateDelegateOfMethodInfo", il =>
        {
            Typeof(il, typeof(Action));
            Typeof(il, target);
            il.Emit(OpCodes.Ldstr, "Solo");
            il.Emit(OpCodes.Callvirt, Apis.GetMethod);
            il.Emit(OpCodes.Call, Apis.CreateDelegateOfMethodInfo);
            il.Emit(OpCodes.Pop);
        });
        // Delegate.CreateDelegate(typeof(Action), typeof(Own.Target), "Solo").
        Caller(calls, "CreateDelegateOfTypeAndName", il =>
        {
            Typeof(il, typeof(Action));
            Typeof(il, target);
            il.Emit(OpCodes.Ldstr, "Solo");
            il.Emit(OpCodes.Call, Apis.CreateDelegateOfTypeAndName);
            il.Emit(OpCodes.Pop);
        });
        // Delegate.CreateDelegate(typeof(Action), null, "Solo"): the (Type, object, string) overload names no type.
        Caller(calls, "CreateDelegateOfObjectAndName", il =>
        {
            Typeof(il, typeof(Action));
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldstr, "Solo");
            il.Emit(OpCodes.Call, Apis.CreateDelegateOfObjectAndName);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Target).GetMethod("Solo").CreateDelegate(typeof(Action)).
        Caller(calls, "MethodInfoCreateDelegate", il =>
        {
            Typeof(il, target);
            GetMethod(il, "Solo");
            Typeof(il, typeof(Action));
            il.Emit(OpCodes.Callvirt, Apis.MethodInfoCreateDelegate);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Target).GetRuntimeMethod("Solo", Type.EmptyTypes).Invoke(null, null).
        Caller(calls, "RuntimeMethodInvoke", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Ldstr, "Solo");
            il.Emit(OpCodes.Ldsfld, Apis.EmptyTypes);
            il.Emit(OpCodes.Call, Apis.GetRuntimeMethod);
            Invoke(il);
        });
        // typeof(Own.Target).GetTypeInfo().GetDeclaredMethod("Solo").Invoke(null, null).
        Caller(calls, "DeclaredMethodInvoke", il =>
        {
            Typeof(il, target);
            il.Emit(OpCodes.Call, Apis.GetTypeInfo);
            il.Emit(OpCodes.Ldstr, "Solo");
            il.Emit(OpCodes.Callvirt, Apis.GetDeclaredMethod);
            Invoke(il);
        });
        // Type.GetType(b ? "Own.Target" : "Own.Outer+Inner"), alone and passed to Activator.CreateInstance.
        Body(Static(calls, "PhiOfNames", typeof(void), typeof(bool)), il =>
        {
            NamePhi(il);
            il.Emit(OpCodes.Call, Apis.TypeGetType);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(calls, "PhiOfNamesCreateInstance", typeof(void), typeof(bool)), il =>
        {
            NamePhi(il);
            il.Emit(OpCodes.Call, Apis.TypeGetType);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        // Activator.CreateInstance(b ? Type.GetType("Own.Target") : Type.GetType("Own.Outer+Inner")): a phi of lookups.
        Body(Static(calls, "PhiOfLookups", typeof(void), typeof(bool)), il =>
        {
            var other = il.DefineLabel();
            var join = il.DefineLabel();
            il.DeclareLocal(typeof(Type));
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brfalse_S, other);
            GetTypeOf(il, TargetType);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Br_S, join);
            il.MarkLabel(other);
            GetTypeOf(il, InnerName);
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(join);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        // Activator.CreateInstance(typeof(Own.Target)) through N lookups, alternating GetTypeInfo and AsType: at the nesting
        // bound and one past it.
        foreach (var lookups in new[] { MaxNesting, MaxNesting + 1 })
        {
            Caller(calls, "Nest" + lookups, il =>
            {
                Typeof(il, target);
                for (var i = 0; i < lookups; i++)
                    il.Emit(i % 2 == 0 ? OpCodes.Call : OpCodes.Callvirt, i % 2 == 0 ? Apis.GetTypeInfo : Apis.AsType);
                il.Emit(OpCodes.Call, Apis.CreateInstance);
                il.Emit(OpCodes.Pop);
            });
        }
        // Activator.CreateInstance(typeof(Own.G<int>)) and (typeof(Own.G<>)).
        Caller(calls, "TypeofGenericCreateInstance", il =>
        {
            Typeof(il, generic.MakeGenericType(typeof(int)));
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
        });
        Caller(calls, "TypeofOpenGenericCreateInstance", il =>
        {
            Typeof(il, generic);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
        });
        // typeof(Own.Long).GetMethod(LongName).Invoke(null, null).
        Caller(calls, "LongNameInvoke", il =>
        {
            Typeof(il, longType);
            GetMethod(il, LongName);
            Invoke(il);
        });
        // Type.GetType(name), one method per reflection name.
        for (var i = 0; i < Names.Length; i++)
        {
            var name = Names[i].Name;
            Caller(calls, "Name" + i, il =>
            {
                il.Emit(OpCodes.Ldstr, name);
                il.Emit(OpCodes.Call, Apis.TypeGetType);
                il.Emit(OpCodes.Pop);
            });
        }
        // m.Invoke as an ldvirtftn: a sink site, but not a call.
        Body(Static(calls, "LdvirtftnInvoke", typeof(void), typeof(MethodInfo)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldvirtftn, Apis.Invoke);
            il.Emit(OpCodes.Newobj, typeof(Func<object, object[], object>).GetConstructor([typeof(object), typeof(IntPtr)])!);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        // Type.GetType("own.target", false, true).GetMethod("RUN", Public | Static | IgnoreCase).Invoke(null, null).
        Caller(calls, "CaseInsensitiveInvoke", il =>
        {
            il.Emit(OpCodes.Ldstr, "own.target");
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Call, Apis.TypeGetTypeIgnoringCase);
            il.Emit(OpCodes.Ldstr, "RUN");
            il.Emit(OpCodes.Ldc_I4, (int)(BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase));
            il.Emit(OpCodes.Callvirt, Apis.GetMethodWithFlags);
            Invoke(il);
        });
        // Type.GetType("Ns.Bar`1").GetMethod("Run").Invoke(null, null): Bar`1 is not generic.
        Caller(calls, "LiteralTickInvoke", il =>
        {
            GetTypeOf(il, TickedType);
            GetMethod(il, "Run");
            Invoke(il);
        });
        // typeof(Own.Foo<int>) and typeof(Foo`1<System.Int32>), each .GetMethod("Run").Invoke(null, null): apart, and in one body.
        Caller(calls, "AliasGeneric", il =>
        {
            Typeof(il, fooOfInt);
            GetMethod(il, "Run");
            Invoke(il);
        });
        Caller(calls, "AliasLiteral", il =>
        {
            Typeof(il, alias);
            GetMethod(il, "Run");
            Invoke(il);
        });
        Caller(calls, "AliasBoth", il =>
        {
            Typeof(il, fooOfInt);
            GetMethod(il, "Run");
            Invoke(il);
            Typeof(il, alias);
            GetMethod(il, "Run");
            Invoke(il);
        });
        // W4: generic parameters as types. CreateInstance<T>() and CreateInstance(typeof(T)) in a generic method, and
        // CreateInstance(typeof(T)) in a generic type's method.
        var ofT = Static(calls, "GenericCreateInstanceOfT", typeof(void));
        var ofTParameter = ofT.DefineGenericParameters("T")[0];
        Body(ofT, il =>
        {
            il.Emit(OpCodes.Call, Apis.CreateInstanceOfT.MakeGenericMethod(ofTParameter));
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        var typeofT = Static(calls, "GenericTypeofCreateInstance", typeof(void));
        var typeofTParameter = typeofT.DefineGenericParameters("T")[0];
        Body(typeofT, il =>
        {
            Typeof(il, typeofTParameter);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        var holder = module.DefineType(HolderType + "`1", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var holderParameter = holder.DefineGenericParameters("T")[0];
        Caller(holder, "Make", il =>
        {
            Typeof(il, holderParameter);
            il.Emit(OpCodes.Call, Apis.CreateInstance);
            il.Emit(OpCodes.Pop);
        });
        // W5: Type.GetType of a phi of tick-bearing names (each a parsed and a literal type name), alone and then
        // .GetMethod("Run").Invoke(null, null): 9 names with Own.G`1 sorting first or last, and 8 with it first.
        foreach (var (name, names) in new[] { ("TickedOwnFirst9", TickedOwnFirst9), ("TickedOwnLast9", TickedOwnLast9), ("TickedOwnFirst8", TickedOwnFirst8) })
        {
            Body(Static(calls, name, typeof(void), typeof(int)), il =>
            {
                NameSwitch(il, names);
                il.Emit(OpCodes.Call, Apis.TypeGetType);
                il.Emit(OpCodes.Pop);
                il.Emit(OpCodes.Ret);
            });
            Body(Static(calls, name + "Invoke", typeof(void), typeof(int)), il =>
            {
                NameSwitch(il, names);
                il.Emit(OpCodes.Call, Apis.TypeGetType);
                GetMethod(il, "Run");
                Invoke(il);
                il.Emit(OpCodes.Ret);
            });
        }
        // File.ReadAllText("x"): a sink with no target line.
        Caller(calls, "NotReflection", il =>
        {
            il.Emit(OpCodes.Ldstr, "x");
            il.Emit(OpCodes.Call, Apis.ReadAllText);
            il.Emit(OpCodes.Pop);
        });
        // Type.GetType("Own.Target"), then jmp: valid IL that Cilica's importer does not take, so the method is Unknown.
        Body(Static(calls, "Unknowable", typeof(void)), il =>
        {
            GetTypeOf(il, TargetType);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Jmp, nothing);
        });

        target.CreateType();
        outer.CreateType();
        inner.CreateType();
        nested.CreateType();
        generic.CreateType();
        longType.CreateType();
        ticked.CreateType();
        foo.CreateType();
        alias.CreateType();
        holder.CreateType();
        calls.CreateType();
    }

    /// <summary>
    /// <c>Own.Many</c> with <see cref="ManyOverloads"/> overloads <c>Run(Own.P&lt;i&gt;, Own.P&lt;j&gt;)</c> over 50 empty own
    /// types (flat: no nesting), and <c>Refl.Many.Calls</c> with <see cref="ManyMethods"/> methods of
    /// <see cref="ManySitesPerMethod"/> <c>typeof(Own.Many).GetMethod("Run").Invoke(null, null)</c> sites each.
    /// </summary>
    public static void DefineMany(ModuleBuilder module)
    {
        var parameters = Enumerable.Range(0, 50).Select(i => module.DefineType("Own.P" + i, TypeAttributes.Public | TypeAttributes.Class)).ToArray();
        var many = module.DefineType(ManyType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        for (var i = 0; i < ManyOverloads / parameters.Length; i++)
            foreach (var second in parameters)
                Body(Static(many, "Run", typeof(void), parameters[i], second), Ret);
        var calls = module.DefineType("Refl.Many.Calls", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        for (var m = 0; m < ManyMethods; m++)
        {
            Caller(calls, "Sites" + m, il =>
            {
                for (var s = 0; s < ManySitesPerMethod; s++)
                {
                    Typeof(il, many);
                    GetMethod(il, "Run");
                    Invoke(il);
                }
            });
        }
        foreach (var parameter in parameters)
            parameter.CreateType();
        many.CreateType();
        calls.CreateType();
    }

    // Merge.Calls, as one of the two merge assemblies defines it; A defines Merge.Alpha, B Merge.Beta, both Merge.Shared.
    private static void DefineMerged(ModuleBuilder module, bool first)
    {
        var own = module.DefineType(first ? "Merge.Alpha" : "Merge.Beta", TypeAttributes.Public | TypeAttributes.Class);
        Body(own.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        var shared = module.DefineType("Merge.Shared", TypeAttributes.Public | TypeAttributes.Class);
        Body(shared.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, Type.EmptyTypes), Ret);
        Body(Static(shared, "Solo", typeof(void)), Ret);

        var calls = module.DefineType(MergeCallsType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var nameField = calls.DefineField("Name", typeof(string), FieldAttributes.Public | FieldAttributes.Static);
        Caller(calls, "Run", il =>
        {
            GetTypeOf(il, first ? "Merge.Alpha" : "Merge.Beta");
            il.Emit(OpCodes.Pop);
        });
        // Type.GetType("Merge.Alpha") in A, Type.GetType(Name) in B (ldstr and ldsfld are both five bytes): the union is Dynamic.
        Caller(calls, "Swerve", il =>
        {
            if (first)
                il.Emit(OpCodes.Ldstr, "Merge.Alpha");
            else
                il.Emit(OpCodes.Ldsfld, nameField);
            il.Emit(OpCodes.Call, Apis.TypeGetType);
            il.Emit(OpCodes.Pop);
        });
        // W5 across a merge: A's 9 names (18 type names, the ordinal-last name's two cut) and B's first 8 of them plus a
        // repeat (16 type names, none cut), at one layout. The union's kept names are 16; only A's flag says some were cut.
        Body(Static(calls, "Ticked", typeof(void), typeof(int)), il =>
        {
            NameSwitch(il, first ? MergeTicked : [.. MergeTicked[..8], MergeTicked[0]]);
            il.Emit(OpCodes.Call, Apis.TypeGetType);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        // ldstr and ldsfld are both five bytes, as are the two callvirts: the Invoke is at one offset in both.
        Caller(calls, "Mixed", il =>
        {
            Typeof(il, shared);
            if (first)
                GetMethod(il, "Solo");
            else
            {
                il.Emit(OpCodes.Ldsfld, Apis.EmptyTypes);
                il.Emit(OpCodes.Callvirt, Apis.GetConstructor);
            }
            Invoke(il);
        });
        own.CreateType();
        shared.CreateType();
        calls.CreateType();
    }

    // local = names[0]; switch (arg0) { case i: local = names[i]; } for i in 1..; ldloc local. Each ldstr is five bytes, so
    // two lists of one length give one layout.
    private static void NameSwitch(ILGenerator il, string[] names)
    {
        var join = il.DefineLabel();
        var cases = Enumerable.Range(1, names.Length - 1).Select(_ => il.DefineLabel()).ToArray();
        il.DeclareLocal(typeof(string));
        il.Emit(OpCodes.Ldstr, names[0]);
        il.Emit(OpCodes.Stloc_0);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Switch, cases);
        il.Emit(OpCodes.Br, join);
        for (var i = 0; i < cases.Length; i++)
        {
            il.MarkLabel(cases[i]);
            il.Emit(OpCodes.Ldstr, names[i + 1]);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Br, join);
        }
        il.MarkLabel(join);
        il.Emit(OpCodes.Ldloc_0);
    }

    // local = arg0 ? "Own.Target" : "Own.Outer+Inner"; ldloc local.
    private static void NamePhi(ILGenerator il)
    {
        var other = il.DefineLabel();
        var join = il.DefineLabel();
        il.DeclareLocal(typeof(string));
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse_S, other);
        il.Emit(OpCodes.Ldstr, TargetType);
        il.Emit(OpCodes.Stloc_0);
        il.Emit(OpCodes.Br_S, join);
        il.MarkLabel(other);
        il.Emit(OpCodes.Ldstr, InnerName);
        il.Emit(OpCodes.Stloc_0);
        il.MarkLabel(join);
        il.Emit(OpCodes.Ldloc_0);
    }

    // Type.GetType(name), left on the stack.
    private static void GetTypeOf(ILGenerator il, string name)
    {
        il.Emit(OpCodes.Ldstr, name);
        il.Emit(OpCodes.Call, Apis.TypeGetType);
    }

    // typeof(type), left on the stack.
    private static void Typeof(ILGenerator il, Type type)
    {
        il.Emit(OpCodes.Ldtoken, type);
        il.Emit(OpCodes.Call, Apis.GetTypeFromHandle);
    }

    // (the Type on the stack).GetMethod(name).
    private static void GetMethod(ILGenerator il, string name)
    {
        il.Emit(OpCodes.Ldstr, name);
        il.Emit(OpCodes.Callvirt, Apis.GetMethod);
    }

    // typeof(type).GetConstructor(Type.EmptyTypes), left on the stack.
    private static void GetConstructor(ILGenerator il, Type type)
    {
        Typeof(il, type);
        il.Emit(OpCodes.Ldsfld, Apis.EmptyTypes);
        il.Emit(OpCodes.Callvirt, Apis.GetConstructor);
    }

    // (the MethodBase on the stack).Invoke(null, null); pop.
    private static void Invoke(ILGenerator il)
    {
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Callvirt, Apis.Invoke);
        il.Emit(OpCodes.Pop);
    }

    // A public static void parameterless caller: emit, then return.
    private static void Caller(TypeBuilder type, string name, Action<ILGenerator> emit) =>
        Body(Static(type, name, typeof(void)), il =>
        {
            emit(il);
            il.Emit(OpCodes.Ret);
        });

    private static void Ret(ILGenerator il) => il.Emit(OpCodes.Ret);

    private static void ReturnZero(ILGenerator il)
    {
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ret);
    }

    private static MethodBuilder Static(TypeBuilder type, string name, Type returns, params Type[] parameters) =>
        type.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, returns, parameters);

    private static void Body(MethodBuilder method, Action<ILGenerator> emit) => emit(method.GetILGenerator());

    private static void Body(ConstructorBuilder constructor, Action<ILGenerator> emit) => emit(constructor.GetILGenerator());
    #endregion

    #region Fields
    public const string AssemblyName = "SsaReflection";
    public const string CallsType = "Refl.Calls";
    public const string MergeCallsType = "Merge.Calls";
    public const string TargetType = "Own.Target";
    public const string InnerName = "Own.Outer+Inner";
    public const string TickedType = "Ns.Bar`1";
    public const string AliasType = "Own.Foo`1<System.Int32>";
    public const string HolderType = "Refl.Holder";
    public const string ManyType = "Own.Many";
    public const int ManyOverloads = 2_000;
    public const int ManyMethods = 20;
    public const int ManySitesPerMethod = 100;

    /// <summary>Type names a target is matched under at most (W5); each tick-bearing name gives two.</summary>
    public const int MaxTypeNames = 16;

    /// <summary>Own.G`1 and 8 others sorting after it: 18 type names, Own.G`1's two among the first 16.</summary>
    public static readonly string[] TickedOwnFirst9 = ["Own.G`1", .. Enumerable.Range(0, 8).Select(i => $"Zz.T{i}`1")];

    /// <summary>8 others sorting before Own.G`1: 18 type names, Own.G`1's two the ones cut.</summary>
    public static readonly string[] TickedOwnLast9 = [.. Enumerable.Range(0, 8).Select(i => $"Aa.T{i}`1"), "Own.G`1"];

    /// <summary>Own.G`1 and 7 others: 16 type names, none cut.</summary>
    public static readonly string[] TickedOwnFirst8 = TickedOwnFirst9[..8];

    /// <summary>The merge folder's 9 tick-bearing names, ordinal; none is own.</summary>
    public static readonly string[] MergeTicked = [.. Enumerable.Range(0, 9).Select(i => $"Merge.T{i}`1")];

    /// <summary>The chain walk's nesting bound (lookups inside one another).</summary>
    public const int MaxNesting = 8;

    /// <summary>A method name long enough that <c>Own.Long.&lt;it&gt;()</c> is past <see cref="Reachability.MaxNameChars"/>.</summary>
    public static readonly string LongName = "L" + new string('o', Reachability.MaxNameChars + 16);

    /// <summary>
    /// The reflection names <c>Refl.Calls.Name&lt;i&gt;</c> passes to <c>Type.GetType</c>, each with the own type id it
    /// names, or null when it names none (an array, pointer or by-ref; a malformed name; an escape; no such own type).
    /// </summary>
    public static readonly (string Name, string? TypeId)[] Names =
    [
        ("Own.Target", "Own.Target"),
        ("Own.Outer+Inner", "Own.Outer.Inner"),
        ("Own.G`1", "Own.G`1"),
        ("Own.G`1[[System.Int32, System.Private.CoreLib]]", "Own.G`1"),
        ("Own.G`1[System.Int32]", "Own.G`1"),
        ("Own.Outer+Nested`1[[System.String]]", "Own.Outer.Nested`1"),
        ("Own.Target, SsaReflection", "Own.Target"),
        ("Own.Target, SsaReflection, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null", "Own.Target"),
        ("Own.G`1[[System.Int32, System.Private.CoreLib]], SsaReflection", "Own.G`1"),
        (" Own.Target ", "Own.Target"),
        ("Own.Target[]", null),
        ("Own.Target[,]", null),
        ("Own.Target[*]", null),
        ("Own.Target*", null),
        ("Own.Target&", null),
        ("Own.G`1[[System.Int32]][]", null),
        ("Own.Outer+", null),
        ("+Inner", null),
        ("Own.Missing", null),
        // W2: reflection may ignore case, and a by-name candidate over-approximates.
        ("own.target", "Own.Target"),
        ("OWN.OUTER+INNER", "Own.Outer.Inner"),
        ("Own.Target`1", null),
        ("Own.G", null),
        ("Own.Ta" + "\\" + "rget", null),
        ("", null),
    ];

    private readonly EmittedAssembly emitted = new();
    #endregion

    #region Child types
    /// <summary>The reflection APIs and helpers the fixture's IL calls.</summary>
    public static class Apis
    {
        public static readonly MethodInfo TypeGetType = typeof(Type).GetMethod(nameof(Type.GetType), [typeof(string)])!;
        public static readonly MethodInfo TypeGetTypeIgnoringCase = typeof(Type).GetMethod(nameof(Type.GetType), [typeof(string), typeof(bool), typeof(bool)])!;
        public static readonly MethodInfo GetMethodWithFlags = typeof(Type).GetMethod(nameof(Type.GetMethod), [typeof(string), typeof(BindingFlags)])!;
        public static readonly MethodInfo GetTypeFromHandle = typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), [typeof(RuntimeTypeHandle)])!;
        public static readonly MethodInfo GetMethod = typeof(Type).GetMethod(nameof(Type.GetMethod), [typeof(string)])!;
        public static readonly MethodInfo GetConstructor = typeof(Type).GetMethod(nameof(Type.GetConstructor), [typeof(Type[])])!;
        public static readonly MethodInfo GetProperty = typeof(Type).GetMethod(nameof(Type.GetProperty), [typeof(string)])!;
        public static readonly MethodInfo GetField = typeof(Type).GetMethod(nameof(Type.GetField), [typeof(string)])!;
        public static readonly MethodInfo InvokeMember = typeof(Type).GetMethod(nameof(Type.InvokeMember),
            [typeof(string), typeof(BindingFlags), typeof(Binder), typeof(object), typeof(object[])])!;
        public static readonly FieldInfo EmptyTypes = typeof(Type).GetField(nameof(Type.EmptyTypes))!;
        public static readonly MethodInfo Invoke = typeof(MethodBase).GetMethod(nameof(MethodBase.Invoke), [typeof(object), typeof(object[])])!;
        public static readonly MethodInfo ConstructorInvoke = typeof(ConstructorInfo).GetMethod(nameof(ConstructorInfo.Invoke), [typeof(object[])])!;
        public static readonly MethodInfo PropertyGetValue = typeof(PropertyInfo).GetMethod(nameof(PropertyInfo.GetValue), [typeof(object)])!;
        public static readonly MethodInfo FieldGetValue = typeof(FieldInfo).GetMethod(nameof(FieldInfo.GetValue), [typeof(object)])!;
        public static readonly MethodInfo MethodInfoCreateDelegate = typeof(MethodInfo).GetMethod(nameof(MethodInfo.CreateDelegate), [typeof(Type)])!;
        public static readonly MethodInfo CreateDelegateOfMethodInfo = typeof(Delegate).GetMethod(nameof(Delegate.CreateDelegate), [typeof(Type), typeof(MethodInfo)])!;
        public static readonly MethodInfo CreateDelegateOfTypeAndName = typeof(Delegate).GetMethod(nameof(Delegate.CreateDelegate), [typeof(Type), typeof(Type), typeof(string)])!;
        public static readonly MethodInfo CreateDelegateOfObjectAndName = typeof(Delegate).GetMethod(nameof(Delegate.CreateDelegate), [typeof(Type), typeof(object), typeof(string)])!;
        public static readonly MethodInfo CreateInstance = typeof(Activator).GetMethod(nameof(Activator.CreateInstance), [typeof(Type)])!;
        public static readonly MethodInfo CreateInstanceNonPublic = typeof(Activator).GetMethod(nameof(Activator.CreateInstance), [typeof(Type), typeof(bool)])!;
        public static readonly MethodInfo CreateInstanceByNames = typeof(Activator).GetMethod(nameof(Activator.CreateInstance), [typeof(string), typeof(string)])!;
        public static readonly MethodInfo CreateInstanceOfT = typeof(Activator).GetMethods().Single(m => m.Name == nameof(Activator.CreateInstance) && m.IsGenericMethodDefinition);
        public static readonly MethodInfo AssemblyLoad = typeof(Assembly).GetMethod(nameof(Assembly.Load), [typeof(string)])!;
        public static readonly MethodInfo AssemblyGetType = typeof(Assembly).GetMethod(nameof(Assembly.GetType), [typeof(string)])!;
        public static readonly MethodInfo GetTypeInfo = typeof(IntrospectionExtensions).GetMethod(nameof(IntrospectionExtensions.GetTypeInfo), [typeof(Type)])!;
        public static readonly MethodInfo AsType = typeof(TypeInfo).GetMethod(nameof(TypeInfo.AsType), Type.EmptyTypes)!;
        public static readonly MethodInfo GetDeclaredMethod = typeof(TypeInfo).GetMethod(nameof(TypeInfo.GetDeclaredMethod), [typeof(string)])!;
        public static readonly MethodInfo GetRuntimeMethod = typeof(RuntimeReflectionExtensions).GetMethod(nameof(RuntimeReflectionExtensions.GetRuntimeMethod),
            [typeof(Type), typeof(string), typeof(Type[])])!;
        public static readonly MethodInfo ReadAllText = typeof(File).GetMethod(nameof(File.ReadAllText), [typeof(string)])!;
    }
    #endregion
}
