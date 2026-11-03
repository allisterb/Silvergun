namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The A2 S1 review fixes (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md, "S1 review 1 … (S1b)") over an
/// EMITTED assembly, <c>ChaReview</c> (<see cref="DispatchReviewFixture"/>), with the CLR as the oracle for what runs:
/// W2 (a type listing only <c>IEnumerator&lt;string&gt;</c>), W3 (a delegate type's <c>ToString</c>), W4 (static calls
/// to <c>System.Object</c>), the static rule never adding open types, and no parameter narrowing through an external
/// (variant) interface. C1 is a ground-truth row (InheritedImpl), C2 is <see cref="ReturnTypeResolutionTests"/>, and
/// the bounded walks are in <see cref="DispatchRobustnessTests"/>.
/// </summary>
public sealed class DispatchReviewFixesTests : IClassFixture<DispatchReviewFixture>
{
    #region Constructors
    public DispatchReviewFixesTests(DispatchReviewFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---- W2: inherited BCL interfaces omitted from InterfaceImpl --------------------------------------------------

    /// <summary>
    /// The premise and the oracle: <c>Seq</c>'s metadata lists ONE InterfaceImpl, <c>IEnumerator&lt;string&gt;</c> — yet
    /// the CLR gives it <c>IEnumerator</c> and <c>IDisposable</c> too, and a <c>callvirt</c> through either runs Seq's own
    /// method (its body throws a marker).
    /// </summary>
    [Theory]
    [InlineData("CallsMoveNext", "SEQ-MOVENEXT")]
    [InlineData("CallsDispose", "SEQ-DISPOSE")]
    public void Runtime_ATypeListingOnlyIEnumeratorOfT_IsReachedThroughItsBaseInterfaces(string caller, string marker)
    {
        using (var pe = new PEReader(File.OpenRead(fixture.Path)))
        {
            var metadata = pe.GetMetadataReader();
            var seq = metadata.TypeDefinitions.Select(metadata.GetTypeDefinition).Single(t => metadata.GetString(t.Name) == "Seq");
            Assert.Single(seq.GetInterfaceImplementations());
        }

        using var context = new IsolatedLoadContext();
        var assembly = context.LoadBytes(fixture.Path);
        var type = assembly.GetType("W.Seq", throwOnError: true)!;
        Assert.Contains(typeof(IEnumerator), type.GetInterfaces());
        Assert.Contains(typeof(IDisposable), type.GetInterfaces());
        var thrown = Assert.Throws<TargetInvocationException>(() =>
            assembly.GetType("W.Callers", throwOnError: true)!.GetMethod(caller)!.Invoke(null, [Activator.CreateInstance(type)]));
        Assert.Equal(marker, thrown.InnerException!.Message);
    }

    /// <summary>
    /// W2: the index keeps only the listed supertype, and the fixed BCL table links <c>IEnumerator`1</c> to
    /// <c>IEnumerator</c> and <c>IDisposable</c>, so both calls reach Seq's methods.
    /// </summary>
    [Theory]
    [InlineData("CallsMoveNext", "W.Seq.MoveNext()")]
    [InlineData("CallsDispose", "W.Seq.Dispose()")]
    public void DispatchTargets_ThroughABaseInterfaceTheTypeDoesNotList_ReachIt(string caller, string target)
    {
        Assert.Equal(["System.Collections.Generic.IEnumerator`1", "System.Object"], Assert.Single(fixture.Index.Types("W.Seq")).Supertypes);

        Assert.Contains(target, fixture.Site(caller).DispatchTargets(fixture.Index)!);
    }

    // ---- W3: delegate bases ----------------------------------------------------------------------------------------

    /// <summary>
    /// W3: an own delegate type (<c>Del : MulticastDelegate</c>) overriding <c>ToString</c> runs it for
    /// <c>callvirt Object::ToString</c> (the oracle), and CHA reaches it: <c>MulticastDelegate</c> → <c>Delegate</c> →
    /// <c>Object</c> by the fixed table. The delegate type is not open.
    /// </summary>
    [Fact]
    public void DispatchTargets_FromObjectToString_ReachADelegateTypesOverride()
    {
        using (var context = new IsolatedLoadContext())
        {
            var assembly = context.LoadBytes(fixture.Path);
            var callers = assembly.GetType("W.Callers", throwOnError: true)!;
            var del = Delegate.CreateDelegate(assembly.GetType("W.Del", throwOnError: true)!, callers.GetMethod("Nop")!);
            Assert.Equal("DEL", callers.GetMethod("CallsToString")!.Invoke(null, [del]));
        }

        Assert.False(fixture.Index.IsOpen("W.Del"));
        Assert.Contains("W.Del.ToString()", fixture.Site("CallsToString").DispatchTargets(fixture.Index)!);
    }

    // ---- W4 and the static rule ------------------------------------------------------------------------------------

    /// <summary>
    /// W4: a static call into <c>System.Object</c> (<c>Equals(object, object)</c>, <c>ReferenceEquals</c>) or
    /// <c>System.String</c> is a plain call — null, not an empty dispatch — even though an own type (<c>Pair</c>) defines a
    /// same-shaped static <c>Equals(object, object)</c> and every own class is below <c>System.Object</c>. Such a site
    /// is not a <see cref="GraphCoverage.DispatchSites"/> either.
    /// </summary>
    [Theory]
    [InlineData("CallsObjectEquals")]
    [InlineData("CallsReferenceEquals")]
    [InlineData("CallsConcat")]
    public void DispatchTargets_AStaticCallIntoAPlatformClass_IsNull(string caller)
    {
        Assert.True(fixture.Index.IsOwnMethod("W.Pair.Equals(System.Object,System.Object)"));
        var site = fixture.Site(caller);
        Assert.True(site.Target.IsStatic);

        Assert.Null(site.DispatchTargets(fixture.Index));
    }

    /// <summary>
    /// The static rule never adds the open types (replaces S1's vacuous version, whose external declared type had no own
    /// subtypes and so never dispatched at all). <c>constrained. !!T call IParsable&lt;!!T&gt;::Parse(string,
    /// IFormatProvider)</c> goes through an EXTERNAL interface that own types implement, so it does dispatch: to
    /// <c>Parser.Parse</c> and to <c>OpenParser.Parse</c> (an open type, reached because it implements the interface) —
    /// but never to the same-shaped static <c>OpenThing.Parse</c>, an open type that does not.
    /// </summary>
    [Fact]
    public void DispatchTargets_AStaticCallThroughAnExternalInterface_ReachesImplementorsButNeverAddsOpenTypes()
    {
        Assert.True(fixture.Index.IsOpen("W.OpenThing"));
        Assert.True(fixture.Index.IsOpen("W.OpenParser"));
        Assert.Contains("System.IParsable`1", Assert.Single(fixture.Index.Types("W.Parser")).Supertypes);
        var site = fixture.Site("ParseIt");
        Assert.Equal(MethodEdgeKind.Call, site.Kind);

        Assert.Equal(
            ["W.OpenParser.Parse(System.String,System.IFormatProvider)", "W.Parser.Parse(System.String,System.IFormatProvider)"],
            site.DispatchTargets(fixture.Index));
    }

    // ---- no narrowing through an external interface -----------------------------------------------------------------

    /// <summary>
    /// Variance: <c>callvirt IComparer&lt;string&gt;::Compare(string, string)</c> on an own <c>IComparer&lt;object&gt;</c>
    /// runs its <c>Compare(object, object)</c> (the oracle). Parameter narrowing is applied below own classes only, so
    /// CHA reaches it although no parameter type matches.
    /// </summary>
    [Fact]
    public void DispatchTargets_ThroughAnExternalInterface_AreNotNarrowedByParameterTypes()
    {
        using (var context = new IsolatedLoadContext())
        {
            var assembly = context.LoadBytes(fixture.Path);
            var comparer = Activator.CreateInstance(assembly.GetType("W.ObjectComparer", throwOnError: true)!);
            Assert.Equal(42, assembly.GetType("W.Callers", throwOnError: true)!.GetMethod("CallsCompare")!.Invoke(null, [comparer]));
        }

        var site = fixture.Site("CallsCompare");
        Assert.Equal(["System.String", "System.String"], ModelNames.Of(site.Target).ParameterTypes);

        Assert.Contains("W.ObjectComparer.Compare(System.Object,System.Object)", site.DispatchTargets(fixture.Index)!);
    }

    // ---- W1: cost ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// W1, the reviewer's cases (spec S1b): <b>D</b> — one Base with n distinct virtual names, n subclasses, one
    /// <c>callvirt</c> per name; <b>H</b> — a chain of n classes, each declaring one <c>virtual newslot</c> method called
    /// once. Neither has a single Dispatch edge, so the edge budget never sees the work. The graph build must scale
    /// about linearly: from n = 1000 to n = 4000 (both inside the 4096-visit walk bound) the best-of-3 time may grow by
    /// less than 8x (linear: 4x, quadratic: 16x), and n = 4000 must finish within 5 s.
    /// </summary>
    [Theory]
    [Trait("Category", "Cost")]
    [InlineData("D")]
    [InlineData("H")]
    public void Build_TheReviewersCostCases_ScaleAboutLinearly(string shape)
    {
        using var emitted = new EmittedAssembly();
        _ = Time(emitted, shape, 200);   // JIT warm-up

        var small = Time(emitted, shape, 1000);
        var large = Time(emitted, shape, 4000);

        Assert.True(large.TotalSeconds < 5 && large.Ticks < 8 * small.Ticks,
            $"case {shape}: n=1000 {small.TotalMilliseconds:F0} ms, n=4000 {large.TotalMilliseconds:F0} ms (x{(double)large.Ticks / small.Ticks:F1}); expected under x8 and under 5 s.");
    }

    // The best of three MethodGraph.Build times over a fresh index (cold memo) of the shape at size n.
    private static TimeSpan Time(EmittedAssembly emitted, string shape, int n)
    {
        var path = emitted.Save($"ChaCost{shape}{n}", module => (shape == "D" ? (Action<ModuleBuilder, int>)DefineD : DefineH)(module, n), $"{shape}{n}");
        using var loaded = ModelAssemblies.Load(path);
        var best = TimeSpan.MaxValue;
        for (var run = 0; run < 3; run++)
        {
            var index = loaded.Index();
            var watch = Stopwatch.StartNew();
            var graph = MethodGraph.Build(index);
            watch.Stop();
            Assert.Equal(0, graph.Coverage.DispatchEdges);
            Assert.False(graph.Coverage.Truncated);
            best = watch.Elapsed < best ? watch.Elapsed : best;
        }
        return best;
    }

    // D: Cost.Base { virtual newslot void m0()..m(n-1)() }, Cost.S0..S(n-1) : Base, Cost.Callers.CallsAll(Base) calling each.
    private static void DefineD(ModuleBuilder module, int n)
    {
        var @base = module.DefineType("Cost.Base", TypeAttributes.Public | TypeAttributes.Class);
        var methods = Enumerable.Range(0, n).Select(j => Empty(@base.DefineMethod("m" + j, NewVirtual, typeof(void), Type.EmptyTypes))).ToArray();
        @base.CreateType();
        for (var i = 0; i < n; i++)
            module.DefineType("Cost.S" + i, TypeAttributes.Public | TypeAttributes.Class, @base).CreateType();
        CallsAll(module, @base, methods);
    }

    // H: Cost.C0 <- C1 <- ... <- C(n-1), each declaring virtual newslot void m_i(); Cost.Callers.CallsAll(C(n-1)) calling each.
    private static void DefineH(ModuleBuilder module, int n)
    {
        var methods = new MethodBuilder[n];
        var parent = typeof(object);
        TypeBuilder? last = null;
        for (var i = 0; i < n; i++)
        {
            last = module.DefineType("Cost.C" + i, TypeAttributes.Public | TypeAttributes.Class, parent);
            methods[i] = Empty(last.DefineMethod("m" + i, NewVirtual, typeof(void), Type.EmptyTypes));
            last.CreateType();
            parent = last;
        }
        CallsAll(module, last!, methods);
    }

    private static void CallsAll(ModuleBuilder module, Type receiver, MethodBuilder[] methods)
    {
        var callers = module.DefineType("Cost.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        var il = callers.DefineMethod("CallsAll", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [receiver]).GetILGenerator();
        foreach (var method in methods)
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Callvirt, method);
        }
        il.Emit(OpCodes.Ret);
        callers.CreateType();
    }

    private static MethodBuilder Empty(MethodBuilder method)
    {
        method.GetILGenerator().Emit(OpCodes.Ret);
        return method;
    }
    #endregion

    #region Fields
    private const MethodAttributes NewVirtual = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot;

    private readonly DispatchReviewFixture fixture;
    #endregion
}

/// <summary>
/// One emitted assembly, <c>ChaReview</c>, namespace <c>W</c> (read as metadata; loaded only from bytes into an
/// <see cref="IsolatedLoadContext"/> for the CLR oracle):
/// <list type="bullet">
/// <item><description><c>Seq</c>, whose ONLY InterfaceImpl row is <c>IEnumerator&lt;string&gt;</c>; its members throw a marker;</description></item>
/// <item><description><c>Del : MulticastDelegate</c> overriding <c>ToString</c> (returns <c>"DEL"</c>);</description></item>
/// <item><description><c>Pair</c> with a static <c>Equals(object, object)</c>;</description></item>
/// <item><description><c>Parser : IParsable&lt;Parser&gt;</c>, <c>OpenParser : MemoryStream, IParsable&lt;OpenParser&gt;</c>
/// and <c>OpenThing : MemoryStream</c>, each with a static <c>Parse(string, IFormatProvider)</c>;</description></item>
/// <item><description><c>ObjectComparer : IComparer&lt;object&gt;</c> whose <c>Compare</c> returns 42;</description></item>
/// <item><description><c>Callers</c>: one static method per site.</description></item>
/// </list>
/// </summary>
public sealed class DispatchReviewFixture : IDisposable
{
    #region Constructors
    public DispatchReviewFixture()
    {
        emitted = new EmittedAssembly();
        try
        {
            Path = emitted.Save("ChaReview", Define);
            Assemblies = ModelAssemblies.Load(Path);
            Index = Assemblies.Index();
            Sites = ModelCallSite.All(Index);
        }
        catch (Exception)
        {
            Assemblies?.Dispose();
            emitted.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public string Path { get; }

    public ModelAssemblies Assemblies { get; }

    public MemberIndex Index { get; }

    public IReadOnlyList<ModelCallSite> Sites { get; }
    #endregion

    #region Methods
    /// <summary>The single call site of <c>W.Callers.{caller}</c> (generic or not).</summary>
    public ModelCallSite Site(string caller) =>
        Assert.Single(Sites, s => s.Caller.NodeId.StartsWith($"W.Callers.{caller}(", StringComparison.Ordinal) ||
                                  s.Caller.NodeId.StartsWith($"W.Callers.{caller}`1(", StringComparison.Ordinal));

    public void Dispose()
    {
        Assemblies.Dispose();
        emitted.Dispose();
    }

    private static void Define(ModuleBuilder module)
    {
        // W2: a type listing only IEnumerator<string>.
        var seq = module.DefineType("W.Seq", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IEnumerator<string>)]);
        seq.DefineDefaultConstructor(MethodAttributes.Public);
        Throwing(seq.DefineMethod("Dispose", Implementation, typeof(void), Type.EmptyTypes), "SEQ-DISPOSE");
        Throwing(seq.DefineMethod("MoveNext", Implementation, typeof(bool), Type.EmptyTypes), "SEQ-MOVENEXT");
        Throwing(seq.DefineMethod("Reset", Implementation, typeof(void), Type.EmptyTypes), "SEQ-RESET");
        Throwing(seq.DefineMethod("get_Current", Implementation, typeof(string), Type.EmptyTypes), "SEQ-CURRENT");
        var objectCurrent = seq.DefineMethod("ObjectCurrent", MethodAttributes.Private | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final,
            typeof(object), Type.EmptyTypes);
        Throwing(objectCurrent, "SEQ-OBJECT-CURRENT");
        seq.DefineMethodOverride(objectCurrent, typeof(IEnumerator).GetProperty(nameof(IEnumerator.Current))!.GetGetMethod()!);
        seq.CreateType();

        // W3: an own delegate type overriding ToString.
        var del = module.DefineType("W.Del", TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.Class, typeof(MulticastDelegate));
        del.DefineConstructor(MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.RTSpecialName | MethodAttributes.SpecialName,
            CallingConventions.Standard, [typeof(object), typeof(IntPtr)]).SetImplementationFlags(MethodImplAttributes.Runtime | MethodImplAttributes.Managed);
        del.DefineMethod("Invoke", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot, typeof(void), Type.EmptyTypes)
            .SetImplementationFlags(MethodImplAttributes.Runtime | MethodImplAttributes.Managed);
        Returns(del.DefineMethod("ToString", Override, typeof(string), Type.EmptyTypes), "DEL");
        del.CreateType();

        // W4: an own static Equals(object, object).
        var pair = module.DefineType("W.Pair", TypeAttributes.Public | TypeAttributes.Class);
        Returns(pair.DefineMethod("Equals", StaticMethod, typeof(bool), [typeof(object), typeof(object)]), false);
        pair.CreateType();

        // The static rule: implementors of the external IParsable<T>, one of them open, and an open non-implementor.
        foreach (var (name, parent, implements) in new[] { ("W.Parser", typeof(object), true), ("W.OpenParser", typeof(MemoryStream), true), ("W.OpenThing", typeof(MemoryStream), false) })
        {
            var type = module.DefineType(name, TypeAttributes.Public | TypeAttributes.Class, parent);
            if (implements)
                type.AddInterfaceImplementation(typeof(IParsable<>).MakeGenericType(type));
            Returns(type.DefineMethod("Parse", StaticMethod, type, [typeof(string), typeof(IFormatProvider)]), null);
            type.CreateType();
        }

        // Variance: an own IComparer<object>.
        var comparer = module.DefineType("W.ObjectComparer", TypeAttributes.Public | TypeAttributes.Class, typeof(object), [typeof(IComparer<object>)]);
        comparer.DefineDefaultConstructor(MethodAttributes.Public);
        Returns(comparer.DefineMethod("Compare", Implementation, typeof(int), [typeof(object), typeof(object)]), 42);
        comparer.CreateType();

        var callers = module.DefineType("W.Callers", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.Class);
        Caller(callers, "CallsMoveNext", typeof(bool), [typeof(IEnumerator)], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, typeof(IEnumerator).GetMethod(nameof(IEnumerator.MoveNext))!); });
        Caller(callers, "CallsDispose", typeof(void), [typeof(IDisposable)], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, typeof(IDisposable).GetMethod(nameof(IDisposable.Dispose))!); });
        Caller(callers, "CallsToString", typeof(string), [typeof(object)], il => { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Callvirt, typeof(object).GetMethod(nameof(ToString), Type.EmptyTypes)!); });
        Caller(callers, "Nop", typeof(void), [], _ => { });
        Caller(callers, "CallsObjectEquals", typeof(bool), [typeof(object), typeof(object)], il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Call, typeof(object).GetMethod(nameof(Equals), BindingFlags.Public | BindingFlags.Static, [typeof(object), typeof(object)])!);
        });
        Caller(callers, "CallsReferenceEquals", typeof(bool), [typeof(object), typeof(object)], il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Call, typeof(object).GetMethod(nameof(ReferenceEquals))!);
        });
        Caller(callers, "CallsConcat", typeof(string), [typeof(string), typeof(string)], il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Call, typeof(string).GetMethod(nameof(string.Concat), [typeof(string), typeof(string)])!);
        });
        Caller(callers, "CallsCompare", typeof(int), [typeof(IComparer<string>)], il =>
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, typeof(IComparer<string>).GetMethod(nameof(IComparer<string>.Compare))!);
        });

        // static T ParseIt<T>() where T : IParsable<T> => constrained. !!T call IParsable<!!T>::Parse("1", null)
        var parseIt = callers.DefineMethod("ParseIt", StaticMethod, typeof(void), Type.EmptyTypes);
        var t = parseIt.DefineGenericParameters("T")[0];
        var parsable = typeof(IParsable<>).MakeGenericType(t);
        t.SetInterfaceConstraints(parsable);
        parseIt.SetReturnType(t);
        var parse = parseIt.GetILGenerator();
        parse.Emit(OpCodes.Ldstr, "1");
        parse.Emit(OpCodes.Ldnull);
        parse.Emit(OpCodes.Constrained, t);
        parse.Emit(OpCodes.Call, TypeBuilder.GetMethod(parsable, typeof(IParsable<>).GetMethod(nameof(IParsable<int>.Parse))!));
        parse.Emit(OpCodes.Ret);

        callers.CreateType();
    }

    private static void Caller(TypeBuilder callers, string name, Type returns, Type[] parameters, Action<ILGenerator> emit)
    {
        var il = callers.DefineMethod(name, StaticMethod, returns, parameters).GetILGenerator();
        emit(il);
        il.Emit(OpCodes.Ret);
    }

    private static void Throwing(MethodBuilder method, string marker)
    {
        var il = method.GetILGenerator();
        il.Emit(OpCodes.Ldstr, marker);
        il.Emit(OpCodes.Newobj, typeof(InvalidOperationException).GetConstructor([typeof(string)])!);
        il.Emit(OpCodes.Throw);
    }

    // A body returning the constant `value` (int, bool, string, or null).
    private static void Returns(MethodBuilder method, object? value)
    {
        var il = method.GetILGenerator();
        switch (value)
        {
            case int number:
                il.Emit(OpCodes.Ldc_I4, number);
                break;
            case bool flag:
                il.Emit(flag ? OpCodes.Ldc_I4_1 : OpCodes.Ldc_I4_0);
                break;
            case string text:
                il.Emit(OpCodes.Ldstr, text);
                break;
            default:
                il.Emit(OpCodes.Ldnull);
                break;
        }
        il.Emit(OpCodes.Ret);
    }
    #endregion

    #region Fields
    private const MethodAttributes Override = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual;
    private const MethodAttributes Implementation = MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Final;
    private const MethodAttributes StaticMethod = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig;

    private readonly EmittedAssembly emitted;
    #endregion
}
