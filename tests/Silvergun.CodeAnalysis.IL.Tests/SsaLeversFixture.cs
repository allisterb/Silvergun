namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// The recall-levers-1 L1 folder (docs/agent/tasks/recall-levers-1.md §2-3), emitted with <see cref="PersistedAssemblyBuilder"/>
/// and read as metadata only (never loaded or executed):
/// <list type="bullet">
/// <item><description><c>Levers.Folds</c>: one method per string.Concat shape, each passing its result to <c>File.ReadAllText</c>
/// (or <c>Process.Start</c> for the shell one), flat IL: chains of calls, no type nesting;</description></item>
/// <item><description><c>Levers.Native</c>: own P/Invokes (one with a renamed entry point, one with a hostile and one with an
/// overlong entry name) and <c>Levers.Calls</c>, the callers that make them sink sites.</description></item>
/// </list>
/// </summary>
public sealed class SsaLeversFixture : IDisposable
{
    #region Constructors
    public SsaLeversFixture()
    {
        Path = emitted.Save("SsaLevers", Define);
        using (var model = ModelAssemblies.Load(Path))
            Graph = MethodGraph.Build(model.Index());
        Sites = SinkSites.Of(Graph);
        Session = SsaSession.Open([Path]);
        Facts = SsaSinkFacts.Extract(Session, Sites);
    }
    #endregion

    #region Properties
    public string Path { get; }

    public MethodGraph Graph { get; }

    public IReadOnlyList<SinkSite> Sites { get; }

    public SsaSession Session { get; }

    public SsaFolderFacts Facts { get; }
    #endregion

    #region Methods
    /// <summary>The one fact of <c>Levers.Folds.<paramref name="method"/></c> or <c>Levers.Calls.<paramref name="method"/></c>.</summary>
    public SsaSinkFact Fact(string method) => Assert.Single(Facts.Sites, f => f.Site.NodeId == NodeIdOf(method));

    /// <summary>Every fact of one method, by IL offset.</summary>
    public SsaSinkFact[] FactsOf(string method) => [.. Facts.Sites.Where(f => f.Site.NodeId == NodeIdOf(method)).OrderBy(f => f.Site.Offset)];

    /// <summary>The facts of every site, the sites handed over in reverse order.</summary>
    public SsaFolderFacts ExtractReversed() => SsaSinkFacts.Extract(Session, [.. Sites.Reverse()]);

    /// <summary>The facts of <see cref="Sites"/> under <paramref name="bounds"/>.</summary>
    public SsaFolderFacts Extract(SsaFactBounds bounds) => SsaSinkFacts.Extract(Session, Sites, bounds);

    public string NodeIdOf(string method)
    {
        var nodes = Graph.Nodes.Where(n => n.Kind != MethodNodeKind.External && (n.ClassificationKey == FoldsType + "." + method || n.ClassificationKey == CallsType + "." + method)).ToArray();
        return nodes.Length == 1 ? nodes[0].NodeId : throw new InvalidOperationException($"{method} has {nodes.Length} own nodes, not one.");
    }

    public void Dispose()
    {
        Session.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        var folds = module.DefineType(FoldsType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);

        Body(Static(folds, "Concat2", typeof(void)), il => Sink(il, i => Concat(i, ["ab", "cd"])));
        Body(Static(folds, "Concat3", typeof(void)), il => Sink(il, i => Concat(i, ["a", "b", "c"])));
        Body(Static(folds, "Concat4", typeof(void)), il => Sink(il, i => Concat(i, ["a", "b", "c", "d"])));
        // Concat(Concat("a", "b"), Concat("c", "d")).
        Body(Static(folds, "Nested", typeof(void)), il => Sink(il, i =>
        {
            Concat(i, ["a", "b"]);
            Concat(i, ["c", "d"]);
            i.Emit(OpCodes.Call, ConcatOf(2));
        }));
        // Concat(Concat(Concat("a", "b"), "b"), "b") ...: MaxFoldDepth (8) calls fold, a ninth does not.
        Body(Static(folds, "Chain8", typeof(void)), il => Sink(il, i => Chain(i, 8)));
        Body(Static(folds, "Chain9", typeof(void)), il => Sink(il, i => Chain(i, 9)));
        Body(Static(folds, "NullArgument", typeof(void)), il => Sink(il, i =>
        {
            i.Emit(OpCodes.Ldstr, "a");
            i.Emit(OpCodes.Ldnull);
            i.Emit(OpCodes.Call, ConcatOf(2));
        }));
        // Concat("a", b ? "b" : "c").
        Body(Static(folds, "PhiArgument", typeof(void), typeof(bool)), il =>
        {
            var other = il.DefineLabel();
            var join = il.DefineLabel();
            il.DeclareLocal(typeof(string));
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brfalse_S, other);
            il.Emit(OpCodes.Ldstr, "b");
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Br_S, join);
            il.MarkLabel(other);
            il.Emit(OpCodes.Ldstr, "c");
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(join);
            Sink(il, i =>
            {
                i.Emit(OpCodes.Ldstr, "a");
                i.Emit(OpCodes.Ldloc_0);
                i.Emit(OpCodes.Call, ConcatOf(2));
            });
        });
        Body(Static(folds, "ParameterArgument", typeof(void), typeof(string)), il => Sink(il, i =>
        {
            i.Emit(OpCodes.Ldstr, "a");
            i.Emit(OpCodes.Ldarg_0);
            i.Emit(OpCodes.Call, ConcatOf(2));
        }));
        Body(Static(folds, "ConcatObjects", typeof(void)), il => Sink(il, i =>
        {
            i.Emit(OpCodes.Ldstr, "a");
            i.Emit(OpCodes.Ldstr, "b");
            i.Emit(OpCodes.Call, typeof(string).GetMethod(nameof(string.Concat), [typeof(object), typeof(object)])!);
        }));
        Body(Static(folds, "ConcatArray", typeof(void)), il => Sink(il, i =>
        {
            i.Emit(OpCodes.Ldc_I4_2);
            i.Emit(OpCodes.Newarr, typeof(string));
            foreach (var (index, text) in new[] { (0, "a"), (1, "b") })
            {
                i.Emit(OpCodes.Dup);
                i.Emit(OpCodes.Ldc_I4, index);
                i.Emit(OpCodes.Ldstr, text);
                i.Emit(OpCodes.Stelem_Ref);
            }
            i.Emit(OpCodes.Call, typeof(string).GetMethod(nameof(string.Concat), [typeof(string[])])!);
        }));
        Body(Static(folds, "AtLengthBound", typeof(void)), il => Sink(il, i => Concat(i, [new string('x', 512), new string('y', 512)])));
        Body(Static(folds, "OverLengthBound", typeof(void)), il => Sink(il, i => Concat(i, [new string('x', 512), new string('y', 513)])));
        // Concat(Concat(512 x, 512 y), "z"): the inner one folds, the outer one is one char over.
        Body(Static(folds, "OverLengthNested", typeof(void)), il => Sink(il, i =>
        {
            Concat(i, [new string('x', 512), new string('y', 512)]);
            i.Emit(OpCodes.Ldstr, "z");
            i.Emit(OpCodes.Call, ConcatOf(2));
        }));
        // b ? Concat("a", "b") : "c".
        Body(Static(folds, "PhiOfConcat", typeof(void), typeof(bool)), il =>
        {
            var other = il.DefineLabel();
            var join = il.DefineLabel();
            il.DeclareLocal(typeof(string));
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brfalse_S, other);
            Concat(il, ["a", "b"]);
            il.Emit(OpCodes.Stloc_0);
            il.Emit(OpCodes.Br_S, join);
            il.MarkLabel(other);
            il.Emit(OpCodes.Ldstr, "c");
            il.Emit(OpCodes.Stloc_0);
            il.MarkLabel(join);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Call, ReadAllText);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        Body(Static(folds, "Backslash", typeof(void)), il => Sink(il, i => Concat(i, ["C:" + Bs, "x.txt"])));
        Body(Static(folds, "StartsShell", typeof(void)), il =>
        {
            Concat(il, ["cm", "d.exe"]);
            il.Emit(OpCodes.Call, typeof(System.Diagnostics.Process).GetMethod(nameof(System.Diagnostics.Process.Start), [typeof(string)])!);
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
        });
        // Two sites of one body on one chain: c3 (Concat of "a" and three "b"s) read directly, and c9 (six more Concats on it).
        // The order of the two sites differs; c3's value must not depend on whether c9's walk (too high) came first.
        Body(Static(folds, "OrderLowFirst", typeof(void)), il => TwoOnAChain(il, lowFirst: true));
        Body(Static(folds, "OrderHighFirst", typeof(void)), il => TwoOnAChain(il, lowFirst: false));
        // c = Concat("a", "b"); Concat(c, c): one Concat as two arguments of another.
        Body(Static(folds, "Diamond", typeof(void)), il => Doubling(il, 1));
        // The same, doubling 7 times (height 8, 256 chars: folds) and 8 times (height 9: does not). Naively 2^8 walks.
        Body(Static(folds, "Diamond7", typeof(void)), il => Doubling(il, 7));
        Body(Static(folds, "Diamond8", typeof(void)), il => Doubling(il, 8));
        folds.CreateType();

        var native = module.DefineType(NativeType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        var ints = new[] { typeof(int), typeof(int), typeof(int), typeof(int) };
        var plain = PInvoke(native, "VirtualAlloc", "VirtualAlloc", ints);
        var renamed = PInvoke(native, "Reserve", "VirtualAlloc", ints);
        var other = PInvoke(native, "Tick", "GetTickCount", []);
        var hostile = PInvoke(native, "Hostile", HostileEntry, []);
        var overlong = PInvoke(native, "Overlong", OverlongEntry, []);
        native.CreateType();

        var calls = module.DefineType(CallsType, TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Abstract | TypeAttributes.Sealed);
        Body(Static(calls, "CallsPlain", typeof(void)), il => CallNative(il, plain, 4));
        Body(Static(calls, "CallsRenamed", typeof(void)), il => CallNative(il, renamed, 4));
        Body(Static(calls, "CallsOther", typeof(void)), il => CallNative(il, other, 0));
        Body(Static(calls, "CallsHostile", typeof(void)), il => CallNative(il, hostile, 0));
        Body(Static(calls, "CallsOverlong", typeof(void)), il => CallNative(il, overlong, 0));
        Body(Static(calls, "ReadsFile", typeof(void)), il => Sink(il, i => i.Emit(OpCodes.Ldstr, "x")));
        calls.CreateType();
    }

    private static MethodBuilder PInvoke(TypeBuilder type, string name, string entry, Type[] parameters)
    {
        var method = type.DefinePInvokeMethod(name, "kernel32.dll", entry, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl,
            CallingConventions.Standard, typeof(int), parameters, CallingConvention.Winapi, CharSet.Unicode);
        method.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        return method;
    }

    // Pushes 0, 4096, 12288, 64 (the first <count>), calls the P/Invoke, pops its result.
    private static void CallNative(ILGenerator il, MethodInfo native, int count)
    {
        foreach (var value in new[] { 0, 4096, 12288, 64 }.Take(count))
            il.Emit(OpCodes.Ldc_I4, value);
        il.Emit(OpCodes.Call, native);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
    }

    // local = c3; then File.ReadAllText(c3) and File.ReadAllText(c9 = c3 + six more Concats), in the order asked; return.
    private static void TwoOnAChain(ILGenerator il, bool lowFirst)
    {
        il.DeclareLocal(typeof(string));
        Chain(il, 3);
        il.Emit(OpCodes.Stloc_0);
        void Low()
        {
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Call, ReadAllText);
            il.Emit(OpCodes.Pop);
        }
        void High()
        {
            il.Emit(OpCodes.Ldloc_0);
            for (var i = 0; i < 6; i++)
            {
                il.Emit(OpCodes.Ldstr, "b");
                il.Emit(OpCodes.Call, ConcatOf(2));
            }
            il.Emit(OpCodes.Call, ReadAllText);
            il.Emit(OpCodes.Pop);
        }
        if (lowFirst)
        {
            Low();
            High();
        }
        else
        {
            High();
            Low();
        }
        il.Emit(OpCodes.Ret);
    }

    // local = Concat("a", "b"), then <doublings> times local = Concat(local, local); File.ReadAllText(local); return.
    private static void Doubling(ILGenerator il, int doublings)
    {
        il.DeclareLocal(typeof(string));
        Concat(il, ["a", "b"]);
        il.Emit(OpCodes.Stloc_0);
        for (var i = 0; i < doublings; i++)
        {
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Call, ConcatOf(2));
            il.Emit(OpCodes.Stloc_0);
        }
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Call, ReadAllText);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
    }

    // File.ReadAllText(<push>); return.
    private static void Sink(ILGenerator il, Action<ILGenerator> push)
    {
        push(il);
        il.Emit(OpCodes.Call, ReadAllText);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
    }

    private static MethodInfo ConcatOf(int count) =>
        typeof(string).GetMethod(nameof(string.Concat), [.. Enumerable.Repeat(typeof(string), count)])!;

    // ldstr each, then string.Concat of that many strings.
    private static void Concat(ILGenerator il, string[] parts)
    {
        foreach (var part in parts)
            il.Emit(OpCodes.Ldstr, part);
        il.Emit(OpCodes.Call, ConcatOf(parts.Length));
    }

    // "a" then <calls> times: ldstr "b"; Concat(2).
    private static void Chain(ILGenerator il, int calls)
    {
        il.Emit(OpCodes.Ldstr, "a");
        for (var i = 0; i < calls; i++)
        {
            il.Emit(OpCodes.Ldstr, "b");
            il.Emit(OpCodes.Call, ConcatOf(2));
        }
    }

    private static MethodBuilder Static(TypeBuilder type, string name, Type returns, params Type[] parameters) =>
        type.DefineMethod(name, MethodAttributes.Public | MethodAttributes.Static, returns, parameters);

    private static void Body(MethodBuilder method, Action<ILGenerator> emit) => emit(method.GetILGenerator());
    #endregion

    #region Fields
    public const string FoldsType = "Levers.Folds";
    public const string NativeType = "Levers.Native";
    public const string CallsType = "Levers.Calls";
    public const string Bs = "\\";

    /// <summary>An entry name with a bidirectional override, a line feed and a backslash, built from code points.</summary>
    public static readonly string HostileEntry = "E" + (char)0x202E + "x" + (char)0x0A + Bs + "y";

    public static readonly string OverlongEntry = new('E', 3000);

    private static readonly MethodInfo ReadAllText = typeof(File).GetMethod(nameof(File.ReadAllText), [typeof(string)])!;

    private readonly EmittedAssembly emitted = new();
    #endregion
}
