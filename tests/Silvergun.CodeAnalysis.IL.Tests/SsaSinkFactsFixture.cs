namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

/// <summary>
/// The folders the S4.2 sink-fact tests read (docs/agent/tasks/ssa-facts-s4.md), each built once as a
/// <see cref="MethodGraph"/> (the oracle for sites: <see cref="SinkSites.Of"/> over it) and opened once as an
/// <see cref="SsaSession"/>, all read as metadata only:
/// <list type="bullet">
/// <item><description><c>SsaSinkFacts</c>, emitted with <see cref="PersistedAssemblyBuilder"/>: <c>Facts.Sites</c>, one
/// method per value shape, each passing it to a real capability sink of the built-in map (<c>File.ReadAllText</c>,
/// <c>Process.Start</c>, <c>MethodBase.Invoke</c>, <c>Activator.CreateInstance</c>, <c>new FileStream</c>), through every
/// call-site kind; a sink caller that does not lift (<c>jmp</c>); and non-sink methods, one of which does not lift
/// either;</description></item>
/// <item><description>the merge folder, <c>SsaMergeA</c> and <c>SsaMergeB</c>, which both define <c>Facts.Merged</c>, so
/// their methods share node ids: <c>Run</c> with a different constant in each, <c>Shifted</c> with its call at different
/// offsets, <c>Mixed</c> that lifts in B only, <c>Swerve</c> that calls the sink in A and another method at the same
/// offset in B, and <c>Walk</c> in A only.</description></item>
/// </list>
/// Types stay shallow (CLAUDE.md): no array, generic or pointer nesting past one level.
/// </summary>
public sealed class SsaSinkFactsFixture : IDisposable
{
    #region Constructors
    public SsaSinkFactsFixture()
    {
        SitesPath = emitted.Save("SsaSinkFacts", DefineSites);
        MergePaths = [emitted.Save("SsaMergeA", m => DefineMerged(m, "alpha", first: true), "merge"), emitted.Save("SsaMergeB", m => DefineMerged(m, "beta", first: false), "merge")];
        Graph = Build(SitesPath);
        MergeGraph = Build(MergePaths);
        Sites = SinkSites.Of(Graph);
        MergeSites = SinkSites.Of(MergeGraph);

        using (var lifted = new SsaLifted([SitesPath]))
            Outcomes = [.. lifted.Outcomes.Select(o => new LiftSummary(o.NodeId, o.Method.MethodName, o.Failure))];
        Session = SsaSession.Open([SitesPath]);
        Facts = SsaSinkFacts.Extract(Session, Sites);
        MergeSession = SsaSession.Open(MergePaths);
        MergeFacts = SsaSinkFacts.Extract(MergeSession, MergeSites);
    }
    #endregion

    #region Properties
    public string SitesPath { get; }

    public string[] MergePaths { get; }

    public MethodGraph Graph { get; }

    public MethodGraph MergeGraph { get; }

    public IReadOnlyList<SinkSite> Sites { get; }

    public IReadOnlyList<SinkSite> MergeSites { get; }

    /// <summary>Every method of <see cref="SitesPath"/> with a body, as <see cref="SsaSession.Lift()"/> gives it.</summary>
    public IReadOnlyList<LiftSummary> Outcomes { get; }

    public SsaSession Session { get; }

    public SsaSession MergeSession { get; }

    /// <summary><see cref="Sites"/>' facts under the default bounds.</summary>
    public SsaFolderFacts Facts { get; }

    public SsaFolderFacts MergeFacts { get; }
    #endregion

    #region Methods
    /// <summary>The node id of <c>Facts.Sites.<paramref name="method"/></c> (no overloads in the fixture).</summary>
    public string NodeIdOf(string method) => NodeIdIn(Graph, SitesType, method);

    public string MergeNodeIdOf(string method) => NodeIdIn(MergeGraph, MergedType, method);

    /// <summary>The one site of <paramref name="method"/>.</summary>
    public SinkSite SiteOf(string method)
    {
        var id = NodeIdOf(method);
        var sites = Sites.Where(s => s.NodeId == id).ToArray();
        return sites.Length == 1 ? sites[0] : throw new InvalidOperationException($"{method} has {sites.Length} sink sites, not one.");
    }

    public void Dispose()
    {
        Session.Dispose();
        MergeSession.Dispose();
        emitted.Dispose();
    }

    private static string NodeIdIn(MethodGraph graph, string type, string method)
    {
        var nodes = graph.Nodes.Where(n => n.Kind != MethodNodeKind.External && n.ClassificationKey == type + "." + method).ToArray();
        return nodes.Length == 1 ? nodes[0].NodeId : throw new InvalidOperationException($"{type}.{method} has {nodes.Length} own nodes, not one.");
    }

    private static MethodGraph Build(params string[] paths)
    {
        using var model = ModelAssemblies.Load(paths);
        return MethodGraph.Build(model.Index());
    }

    private static void DefineSites(ModuleBuilder module)
    {
        var generic = module.DefineType("Facts.G`1", TypeAttributes.Public | TypeAttributes.Class);
        generic.DefineGenericParameters("T");
        var outer = module.DefineType("Facts.Outer", TypeAttributes.Public | TypeAttributes.Class);
        var inner = outer.DefineNestedType("Inner", TypeAttributes.NestedPublic | TypeAttributes.Class);
        // GOuter<T>.Inner<U>, and GOuter<T>.Plain.Deep<U> (Plain has no parameters of its own); nested types redeclare
        // their containers' parameters, as csc writes them.
        var gOuter = module.DefineType("Facts.GOuter`1", TypeAttributes.Public | TypeAttributes.Class);
        gOuter.DefineGenericParameters("T");
        var gInner = gOuter.DefineNestedType("Inner`1", TypeAttributes.NestedPublic | TypeAttributes.Class);
        gInner.DefineGenericParameters("T", "U");
        var plain = gOuter.DefineNestedType("Plain", TypeAttributes.NestedPublic | TypeAttributes.Class);
        plain.DefineGenericParameters("T");
        var deep = plain.DefineNestedType("Deep`1", TypeAttributes.NestedPublic | TypeAttributes.Class);
        deep.DefineGenericParameters("T", "U");
        var nestedInGeneric = new (string Name, Type Type)[]
        {
            ("Enumerator", typeof(List<int>.Enumerator)),
            ("KeyCollection", typeof(Dictionary<string, int>.KeyCollection)),
            ("OwnNested", gInner.MakeGenericType(typeof(int), typeof(string))),
            ("Deep", deep.MakeGenericType(typeof(int), typeof(bool))),
        };

        var sites = module.DefineType(SitesType, TypeAttributes.Public | TypeAttributes.Class);
        sites.DefineDefaultConstructor(MethodAttributes.Public);
        var pathField = sites.DefineField("Path", typeof(string), FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.InitOnly);
        var nameField = sites.DefineField("Name", typeof(string), FieldAttributes.Public);

        var target = Static(sites, "Target", typeof(void));
        Body(target, il => il.Emit(OpCodes.Ret));
        var touch = Static(sites, "Touch", typeof(void), typeof(string).MakeByRefType());
        Body(touch, il => il.Emit(OpCodes.Ret));
        var make = Static(sites, "Make", typeof(string));
        Body(make, il =>
        {
            il.Emit(OpCodes.Ldstr, "m");
            il.Emit(OpCodes.Ret);
        });
        Body(sites.DefineTypeInitializer(), il =>
        {
            il.Emit(OpCodes.Ldstr, "f");
            il.Emit(OpCodes.Stsfld, pathField);
            il.Emit(OpCodes.Ret);
        });

        // ---- Constants, directly and through a promoted local ----
        Body(Static(sites, "ReadsConstant", typeof(void)), il => ReadAll(il, "x"));
        Body(Static(sites, "StartsCmd", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "cmd.exe");
            il.Emit(OpCodes.Call, Apis.StartFile);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "TwoSites", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "one");
            il.Emit(OpCodes.Call, Apis.ReadAllText);
            il.Emit(OpCodes.Pop);
            ReadAll(il, "two");
        });
        Body(Static(sites, "PromotedLocal", typeof(void), typeof(bool)), il =>
        {
            var join = il.DefineLabel();
            il.DeclareLocal(typeof(string));
            il.Emit(OpCodes.Ldstr, PromotedText);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brfalse_S, join);
            il.Emit(OpCodes.Nop);
            il.MarkLabel(join);
            il.Emit(OpCodes.Ldloc_0);
            ReadAllOfStack(il);
        });
        Body(Static(sites, "HugeConstant", typeof(void)), il => ReadAll(il, HugeText));
        Body(Static(sites, "Hostile", typeof(void)), il => ReadAll(il, HostileText));

        // ---- Phi webs ----
        Body(Static(sites, "PhiOfTwo", typeof(void), typeof(bool)), il => IfElse(il, typeof(string), i => i.Emit(OpCodes.Ldstr, "alpha"), i => i.Emit(OpCodes.Ldstr, "Zeta")));
        Body(Static(sites, "PhiOfFour", typeof(void), typeof(int)), il => Switch(il, 4));
        Body(Static(sites, "PhiOfFive", typeof(void), typeof(int)), il => Switch(il, 5));
        Body(Static(sites, "PhiCycle", typeof(void), typeof(int)), il =>
        {
            var top = il.DefineLabel();
            var skip = il.DefineLabel();
            il.DeclareLocal(typeof(string));
            il.Emit(OpCodes.Ldstr, "a");
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(top);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.And);
            il.Emit(OpCodes.Brfalse_S, skip);
            il.Emit(OpCodes.Ldstr, "b");
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(skip);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Sub);
            il.Emit(OpCodes.Starg_S, (byte)0);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brtrue_S, top);
            il.Emit(OpCodes.Ldloc_0);
            ReadAllOfStack(il);
        });
        // m.Invoke(b ? "s" : null, null).
        Body(Static(sites, "PhiStringOrNull", typeof(void), typeof(MethodInfo), typeof(bool)), il =>
        {
            var other = il.DefineLabel();
            var join = il.DefineLabel();
            il.DeclareLocal(typeof(object));
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Brfalse_S, other);
            il.Emit(OpCodes.Ldstr, "s");
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Br_S, join);
            il.MarkLabel(other);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(join);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, Apis.Invoke);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "PhiConstantOrCall", typeof(void), typeof(bool)), il => IfElse(il, typeof(string), i => i.Emit(OpCodes.Ldstr, "a"), i =>
        {
            i.Emit(OpCodes.Ldstr, "b");
            i.Emit(OpCodes.Ldstr, "c");
            i.Emit(OpCodes.Call, Apis.Concat);
        }));
        Body(Static(sites, "PhiConstantOrParameter", typeof(void), typeof(bool), typeof(string)), il => IfElse(il, typeof(string), i => i.Emit(OpCodes.Ldstr, "a"), i => i.Emit(OpCodes.Ldarg_1)));
        Body(Static(sites, "PhiSameParameter", typeof(void), typeof(bool), typeof(string)), il => IfElse(il, typeof(string), i => i.Emit(OpCodes.Ldarg_1), i => i.Emit(OpCodes.Ldarg_1)));

        // ---- Leaves ----
        Body(Static(sites, "AddressTaken", typeof(void)), il =>
        {
            il.DeclareLocal(typeof(string));
            il.Emit(OpCodes.Ldstr, "x");
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldloca_S, (byte)0);
            il.Emit(OpCodes.Call, touch);
            il.Emit(OpCodes.Ldloc_0);
            ReadAllOfStack(il);
        });
        Body(Static(sites, "OwnParameter", typeof(void), typeof(string), typeof(string)), il =>
        {
            il.Emit(OpCodes.Ldarg_1);
            ReadAllOfStack(il);
        });
        Body(sites.DefineMethod("InstanceParameter", MethodAttributes.Public, typeof(void), [typeof(string)]), il =>
        {
            il.Emit(OpCodes.Ldarg_1);
            ReadAllOfStack(il);
        });
        // m.Invoke(this, null), in an instance method: this is argument 0, m argument 1.
        Body(sites.DefineMethod("InvokeOnThis", MethodAttributes.Public, typeof(void), [typeof(MethodInfo)]), il =>
        {
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, Apis.Invoke);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "StaticField", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldsfld, pathField);
            ReadAllOfStack(il);
        });
        Body(sites.DefineMethod("InstanceField", MethodAttributes.Public, typeof(void), Type.EmptyTypes), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldfld, nameField);
            ReadAllOfStack(il);
        });
        Body(Static(sites, "ConcatOfConstants", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "a");
            il.Emit(OpCodes.Ldstr, "b");
            il.Emit(OpCodes.Call, Apis.Concat);
            ReadAllOfStack(il);
        });
        Body(Static(sites, "CalliResult", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldftn, make);
            il.EmitCalli(OpCodes.Calli, CallingConventions.Standard, typeof(string), Type.EmptyTypes, null);
            ReadAllOfStack(il);
        });
        Body(Static(sites, "ArrayElement", typeof(void), typeof(string[])), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldelem_Ref);
            ReadAllOfStack(il);
        });
        Body(Static(sites, "NewFileStream", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "f");
            il.Emit(OpCodes.Ldc_I4_3);
            il.Emit(OpCodes.Newobj, Apis.FileStreamOf);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "FileStreamArithmetic", typeof(void), typeof(int)), il =>
        {
            il.Emit(OpCodes.Ldstr, "f");
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Add);
            il.Emit(OpCodes.Newobj, Apis.FileStreamOf);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "InvokeFloat", typeof(void), typeof(MethodInfo)), il => InvokeBoxed(il, i => i.Emit(OpCodes.Ldc_R8, 2.5), typeof(double)));
        Body(Static(sites, "InvokeNegative", typeof(void), typeof(MethodInfo)), il => InvokeBoxed(il, i => i.Emit(OpCodes.Ldc_I4_S, (sbyte)-7), typeof(int)));
        Body(Static(sites, "WritesTwo", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "p");
            il.Emit(OpCodes.Ldstr, "c");
            il.Emit(OpCodes.Call, Apis.WriteAllText);
            il.Emit(OpCodes.Ret);
        });

        // ---- typeof(T) ----
        Body(Static(sites, "TypeofString", typeof(void)), il => CreateInstanceOf(il, typeof(string)));
        Body(Static(sites, "TypeofInt", typeof(void)), il => CreateInstanceOf(il, typeof(int)));
        Body(Static(sites, "TypeofNested", typeof(void)), il => CreateInstanceOf(il, inner));
        Body(Static(sites, "TypeofOwnGeneric", typeof(void)), il => CreateInstanceOf(il, generic.MakeGenericType(typeof(int))));
        Body(Static(sites, "TypeofListOfString", typeof(void)), il => CreateInstanceOf(il, typeof(List<string>)));
        Body(Static(sites, "TypeofOpenList", typeof(void)), il => CreateInstanceOf(il, typeof(List<>)));
        Body(Static(sites, "TypeofArray", typeof(void)), il => CreateInstanceOf(il, typeof(string[])));
        Body(Static(sites, "TypeofMatrix", typeof(void)), il => CreateInstanceOf(il, typeof(int[,])));
        // typeof of a type nested in a generic one, and (the oracle) a method taking it, whose node id CciNames renders.
        foreach (var (name, type) in nestedInGeneric)
        {
            Body(Static(sites, "Typeof" + name, typeof(void)), il => CreateInstanceOf(il, type));
            Body(Static(sites, "Takes" + name, typeof(void), type), il => il.Emit(OpCodes.Ret));
        }
        Body(Static(sites, "SpellsSuffix", typeof(void)), il => ReadAll(il, SpelledSuffix));

        // ---- Receivers, per call-site kind ----
        Body(Static(sites, "StartInstance", typeof(void), typeof(Process)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Callvirt, Apis.StartInstance);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "StartInstanceCall", typeof(void), typeof(Process)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, Apis.StartInstance);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "LdftnSink", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldftn, Apis.ReadAllText);
            il.Emit(OpCodes.Newobj, typeof(Func<string, string>).GetConstructor([typeof(object), typeof(IntPtr)])!);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(sites, "LdvirtftnSink", typeof(void), typeof(MethodInfo)), il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldvirtftn, Apis.Invoke);
            il.Emit(OpCodes.Newobj, typeof(Func<object, object[], object>).GetConstructor([typeof(object), typeof(IntPtr)])!);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });

        // ---- Did not lift, and not sinks ----
        // jmp: valid IL that Cilica's importer does not take, so the method is Unknown; its sink call is still an edge.
        Body(Static(sites, "Unknowable", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "u");
            il.Emit(OpCodes.Call, Apis.ReadAllText);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Jmp, target);
        });
        Body(Static(sites, "NotASinkJumper", typeof(void)), il => il.Emit(OpCodes.Jmp, target));
        Body(Static(sites, "NoSink", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "n");
            il.Emit(OpCodes.Call, Apis.IsNullOrEmpty);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });

        generic.CreateType();
        outer.CreateType();
        inner.CreateType();
        gOuter.CreateType();
        gInner.CreateType();
        plain.CreateType();
        deep.CreateType();
        sites.CreateType();
    }

    // Facts.Merged, as one of the two merge assemblies defines it.
    private static void DefineMerged(ModuleBuilder module, string constant, bool first)
    {
        var merged = module.DefineType(MergedType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var target = Static(merged, "Target", typeof(void));
        Body(target, il => il.Emit(OpCodes.Ret));
        Body(Static(merged, "Run", typeof(void)), il => ReadAll(il, constant));
        Body(Static(merged, "Shifted", typeof(void)), il =>
        {
            if (!first)
                il.Emit(OpCodes.Nop);
            ReadAll(il, "s-" + constant);
        });
        Body(Static(merged, "Mixed", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "m");
            il.Emit(OpCodes.Call, Apis.ReadAllText);
            il.Emit(OpCodes.Pop);
            if (first)
                il.Emit(OpCodes.Jmp, target);
            else
                il.Emit(OpCodes.Ret);
        });
        // Same offsets in both: A calls the sink at the call's offset, B calls string.IsNullOrEmpty there.
        Body(Static(merged, "Swerve", typeof(void)), il =>
        {
            il.Emit(OpCodes.Ldstr, "v-" + constant);
            il.Emit(OpCodes.Call, first ? Apis.ReadAllText : Apis.IsNullOrEmpty);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        if (first)
            Body(Static(merged, "Walk", typeof(void)), il => ReadAll(il, "w"));
        merged.CreateType();
    }

    /// <summary>
    /// <c>Facts.Repeats.Many()</c>: <see cref="RepeatSites"/> separate <c>ldstr</c>s of <see cref="RepeatedText"/>, each
    /// passed straight to <c>File.ReadAllText</c> (no local, no phi); and <c>Facts.Repeats.Twice()</c>, two more in another
    /// body. The #US heap holds the text once; CCI reads each <c>ldstr</c> into a new string.
    /// </summary>
    public static void DefineRepeats(ModuleBuilder module)
    {
        var repeats = module.DefineType("Facts.Repeats", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        foreach (var (name, count) in new[] { ("Many", RepeatSites), ("Twice", 2) })
        {
            Body(Static(repeats, name, typeof(void)), il =>
            {
                for (var i = 0; i < count; i++)
                {
                    il.Emit(OpCodes.Ldstr, RepeatedText);
                    il.Emit(OpCodes.Call, Apis.ReadAllText);
                    il.Emit(OpCodes.Pop);
                }
                il.Emit(OpCodes.Ret);
            });
        }
        repeats.CreateType();
    }

    /// <summary>
    /// <c>Facts.Many.Wide(int)</c>: a local set to "a" or "b" in each of <see cref="WideArms"/> switch arms (one phi of
    /// that many inputs and one more), then passed to <c>File.ReadAllText</c> at <see cref="WideSites"/> sites. Flat.
    /// </summary>
    public static void DefineWide(ModuleBuilder module)
    {
        var many = module.DefineType("Facts.Many", TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        Body(Static(many, "Wide", typeof(void), typeof(int)), il =>
        {
            var join = il.DefineLabel();
            var arms = Enumerable.Range(0, WideArms).Select(_ => il.DefineLabel()).ToArray();
            il.DeclareLocal(typeof(string));
            il.Emit(OpCodes.Ldstr, "a");
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Switch, arms);
            il.Emit(OpCodes.Br, join);
            for (var i = 0; i < arms.Length; i++)
            {
                il.MarkLabel(arms[i]);
                il.Emit(OpCodes.Ldstr, i % 2 == 0 ? "a" : "b");
                il.Emit(OpCodes.Stloc_0);
                il.Emit(OpCodes.Br, join);
            }
            il.MarkLabel(join);
            for (var i = 0; i < WideSites; i++)
            {
                il.Emit(OpCodes.Ldloc_0);
                il.Emit(OpCodes.Call, Apis.ReadAllText);
                il.Emit(OpCodes.Pop);
            }
            il.Emit(OpCodes.Ret);
        });
        many.CreateType();
    }

    // File.ReadAllText(text); return.
    private static void ReadAll(ILGenerator il, string text)
    {
        il.Emit(OpCodes.Ldstr, text);
        ReadAllOfStack(il);
    }

    // File.ReadAllText(the string on the stack); return.
    private static void ReadAllOfStack(ILGenerator il)
    {
        il.Emit(OpCodes.Call, Apis.ReadAllText);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
    }

    // local = arg0 ? then : otherwise; File.ReadAllText(local).
    private static void IfElse(ILGenerator il, Type local, Action<ILGenerator> then, Action<ILGenerator> otherwise)
    {
        var other = il.DefineLabel();
        var join = il.DefineLabel();
        il.DeclareLocal(local);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse_S, other);
        then(il);
        il.Emit(OpCodes.Stloc_0);
        il.Emit(OpCodes.Br_S, join);
        il.MarkLabel(other);
        otherwise(il);
        il.Emit(OpCodes.Stloc_0);
        il.MarkLabel(join);
        il.Emit(OpCodes.Ldloc_0);
        ReadAllOfStack(il);
    }

    // local = "c0"; switch (arg0) { case i: local = "ci"; } for i in 1..count-1; File.ReadAllText(local): count constants.
    private static void Switch(ILGenerator il, int count)
    {
        var join = il.DefineLabel();
        var cases = Enumerable.Range(1, count - 1).Select(_ => il.DefineLabel()).ToArray();
        il.DeclareLocal(typeof(string));
        il.Emit(OpCodes.Ldstr, "c0");
        il.Emit(OpCodes.Stloc_0);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Switch, cases);
        il.Emit(OpCodes.Br, join);
        for (var i = 0; i < cases.Length; i++)
        {
            il.MarkLabel(cases[i]);
            il.Emit(OpCodes.Ldstr, "c" + (i + 1));
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Br, join);
        }
        il.MarkLabel(join);
        il.Emit(OpCodes.Ldloc_0);
        ReadAllOfStack(il);
    }

    // m.Invoke((object)value, null), m argument 0.
    private static void InvokeBoxed(ILGenerator il, Action<ILGenerator> value, Type boxed)
    {
        il.Emit(OpCodes.Ldarg_0);
        value(il);
        il.Emit(OpCodes.Box, boxed);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Callvirt, Apis.Invoke);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
    }

    // Activator.CreateInstance(typeof(type)).
    private static void CreateInstanceOf(ILGenerator il, Type type)
    {
        il.Emit(OpCodes.Ldtoken, type);
        il.Emit(OpCodes.Call, Apis.GetTypeFromHandle);
        il.Emit(OpCodes.Call, Apis.CreateInstance);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
    }

    private static MethodBuilder Static(TypeBuilder type, string name, Type returns, params Type[] parameters) =>
        type.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, returns, parameters);

    private static void Body(MethodBuilder method, Action<ILGenerator> emit) => emit(method.GetILGenerator());

    private static void Body(ConstructorBuilder constructor, Action<ILGenerator> emit) => emit(constructor.GetILGenerator());

    private static string C(int codeUnit) => ((char)codeUnit).ToString();
    #endregion

    #region Fields
    public const string SitesType = "Facts.Sites";
    public const string MergedType = "Facts.Merged";
    public const string Bs = "\\";

    /// <summary><c>C:\secret.txt</c>, and as the facts render it: the backslash doubled.</summary>
    public const string PromotedText = "C:" + Bs + "secret.txt";
    public const string PromotedEscaped = "C:" + Bs + Bs + "secret.txt";

    public const int WideArms = 1000;
    public const int WideSites = 1000;
    public const int RepeatSites = 200;

    /// <summary>64K chars, with a backslash every 64 so escaping does work on it.</summary>
    public static readonly string RepeatedText = string.Concat(Enumerable.Repeat(new string('r', 63) + Bs, 1024));

    public static readonly string HugeText = new('A', 300);

    /// <summary>A raw constant that spells a cut suffix: it was not cut.</summary>
    public static readonly string SpelledSuffix = C(0x2026) + "[+7 chars, sha256:0123abcd]";

    /// <summary>
    /// A lone high surrogate, an RLO, a line feed, a backslash, a lone low surrogate and a Tag-block letter (a valid pair),
    /// built from code points.
    /// </summary>
    public static readonly string HostileText =
        "a" + C(0xD800) + "b" + C(0x202E) + "c" + C(0x0A) + Bs + C(0xDC00) + char.ConvertFromUtf32(0xE0041) + "d";

    public static readonly string HostileEscaped =
        "a" + Bs + "uD800" + "b" + Bs + "u202e" + "c" + Bs + "n" + Bs + Bs + Bs + "uDC00" + Bs + "U000E0041" + "d";

    /// <summary>The methods of <see cref="SitesType"/> that call a capability sink: every one has a site.</summary>
    public static readonly string[] SinkCallers =
    [
        "ReadsConstant", "StartsCmd", "TwoSites", "PromotedLocal", "HugeConstant", "Hostile",
        "PhiOfTwo", "PhiOfFour", "PhiOfFive", "PhiCycle", "PhiStringOrNull", "PhiConstantOrCall", "PhiConstantOrParameter", "PhiSameParameter",
        "AddressTaken", "OwnParameter", "InstanceParameter", "InvokeOnThis", "StaticField", "InstanceField", "ConcatOfConstants", "CalliResult",
        "ArrayElement", "NewFileStream", "FileStreamArithmetic", "InvokeFloat", "InvokeNegative", "WritesTwo",
        "TypeofString", "TypeofInt", "TypeofNested", "TypeofOwnGeneric", "TypeofListOfString", "TypeofOpenList", "TypeofArray", "TypeofMatrix",
        "TypeofEnumerator", "TypeofKeyCollection", "TypeofOwnNested", "TypeofDeep", "SpellsSuffix",
        "StartInstance", "StartInstanceCall", "LdftnSink", "LdvirtftnSink", "Unknowable",
    ];

    /// <summary>The methods of <see cref="SitesType"/> with a body that call no sink.</summary>
    public static readonly string[] NonSinkMethods =
        ["Target", "Touch", "Make", ".cctor", ".ctor", "NotASinkJumper", "NoSink", "TakesEnumerator", "TakesKeyCollection", "TakesOwnNested", "TakesDeep"];

    private readonly EmittedAssembly emitted = new();
    #endregion

    #region Child types
    /// <summary>What one method's lift gave, without its body.</summary>
    public sealed record LiftSummary(string NodeId, string MethodName, SsaFailure? Failure);

    /// <summary>The sink APIs and helpers the fixture's IL calls.</summary>
    public static class Apis
    {
        public static readonly MethodInfo ReadAllText = typeof(File).GetMethod(nameof(File.ReadAllText), [typeof(string)])!;
        public static readonly MethodInfo WriteAllText = typeof(File).GetMethod(nameof(File.WriteAllText), [typeof(string), typeof(string)])!;
        public static readonly MethodInfo StartFile = typeof(Process).GetMethod(nameof(Process.Start), [typeof(string)])!;
        public static readonly MethodInfo StartInstance = typeof(Process).GetMethod(nameof(Process.Start), Type.EmptyTypes)!;
        public static readonly MethodInfo Invoke = typeof(MethodBase).GetMethod(nameof(MethodBase.Invoke), [typeof(object), typeof(object[])])!;
        public static readonly MethodInfo CreateInstance = typeof(Activator).GetMethod(nameof(Activator.CreateInstance), [typeof(Type)])!;
        public static readonly MethodInfo GetTypeFromHandle = typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), [typeof(RuntimeTypeHandle)])!;
        public static readonly MethodInfo Concat = typeof(string).GetMethod(nameof(string.Concat), [typeof(string), typeof(string)])!;
        public static readonly MethodInfo IsNullOrEmpty = typeof(string).GetMethod(nameof(string.IsNullOrEmpty), [typeof(string)])!;
        public static readonly ConstructorInfo FileStreamOf = typeof(FileStream).GetConstructor([typeof(string), typeof(FileMode)])!;
    }
    #endregion
}
