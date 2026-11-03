namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

/// <summary>What a <see cref="MechanismPath"/> row asserts (docs/agent/tasks/capslock-mechanism-fixtures-and-a1.md §1.4).</summary>
public enum Expectation
{
    /// <summary>Some path visits every waypoint in order; if a capability is set, the map classifies the final node as it.</summary>
    Present,

    /// <summary>No path from any node matching the first waypoint to any node classified as the capability (null = any).</summary>
    Absent,

    /// <summary>Asserted as <see cref="Present"/> — that is what CHA does; the row's note states the ideal is Absent.</summary>
    KnownImprecision,

    /// <summary>Asserted as "this waypoint path does not exist"; the note states the ideal is Present and the lever.</summary>
    KnownGap,
}

/// <summary>
/// The call-graph phase from which a row is checked. Ordered: a row is active when <c>ActiveFrom &lt;= CurrentPhase</c>.
/// <see cref="A2Dispatch"/> is phase A2's first slice (S1: CHA fan-out, <c>MethodEdgeKind.Dispatch</c>); <see cref="A2"/>
/// is the whole phase, reached once the state-machine and type-initializer edges land too
/// (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md).
/// </summary>
public enum Phase
{
    Baseline,
    A1,
    A2Dispatch,
    A2,
    A2Multi,
    Reachability,
}

/// <summary>
/// One ground-truth call path. <paramref name="Waypoints"/> are regexes over <see cref="CanonicalName.NodeId(MethodIdentity)"/>
/// strings, matched <b>in order, not necessarily consecutively</b> (Capslock's semantics); the last is usually the
/// platform sink. Own waypoints name <b>definitions</b> (<c>!0</c>/<c>!!0</c>), never a call site's instantiation.
/// </summary>
public sealed record MechanismPath(
    string Id,
    string Mechanism,
    string[] Waypoints,
    Capability? Capability,
    Expectation Expect,
    Phase ActiveFrom,
    string Note);

/// <summary>
/// An opacity record the graph must carry for a call site it cannot resolve (§1.4: the function-pointer row is
/// "Present via ldftn <b>and</b> an opacity record for the calli site — both, asserted separately").
/// </summary>
public sealed record MechanismOpacity(string Id, string Mechanism, string Site, OpacityKind Kind, Phase ActiveFrom, string Note);

/// <summary>
/// The ground truth for the mechanism fixtures (<c>tests/Silvergun.CodeAnalysis.IL.Tests.MechanismFixture</c>):
/// data, not prose. Every node id below was read from the BUILT fixture, not guessed — and
/// <c>MechanismFixtureSanityTests</c> fails if any waypoint stops naming a real node.
/// <para>
/// <b>Expectations are design decisions</b> (spec §1.4's decision table). Do not edit one to make a test pass;
/// changing one is recorded in the spec. Notes follow a checked convention: a KnownImprecision note says
/// <c>ideal: Absent</c>; a KnownGap note says <c>ideal: Present</c> and names the <c>lever:</c> that would close it.
/// </para>
/// </summary>
public static class MechanismGroundTruth
{
    #region Properties
    /// <summary>
    /// The phase the call graph has reached. Each row is tagged with the EARLIEST phase at which it holds, and
    /// <c>MechanismGroundTruthTests</c> checks that every still-pending row really fails today. At
    /// <see cref="Phase.A1"/> the static call-site targets (both fixture assemblies in one <see cref="MemberIndex"/>)
    /// satisfied every row but the A2 and Reachability ones. Phase A2 ratchets in slices: <see cref="Phase.A2Dispatch"/>
    /// (S1, CHA fan-out) activated the seven CHA rows and the S1 dispatch mechanisms (ObjectVirtual, ExplicitImpl,
    /// GenericInterface, StaticAbstract, OpenHierarchy); bumping this to <see cref="Phase.A2"/> once the
    /// state-machine and type-initializer edges land is the red-to-green moment of the rest of the phase.
    /// </summary>
    public static Phase CurrentPhase => Phase.A2Dispatch;

    /// <summary>The path rows active at <see cref="CurrentPhase"/>.</summary>
    public static IReadOnlyList<MechanismPath> ActivePaths => Paths.Where(p => p.ActiveFrom <= CurrentPhase).ToArray();

    /// <summary>The opacity rows active at <see cref="CurrentPhase"/>.</summary>
    public static IReadOnlyList<MechanismOpacity> ActiveOpacities => Opacities.Where(o => o.ActiveFrom <= CurrentPhase).ToArray();

    /// <summary>Every path row, in catalogue order.</summary>
    public static IReadOnlyList<MechanismPath> Paths { get; } =
    [
        // ---- Direct ------------------------------------------------------------------------------------------
        new("Direct.ReadsEnv", "Direct", [Own("Direct.Probes.ReadsEnv()"), GetEnv], Env, Expectation.Present, Phase.A1,
            "Plain call to the sink: the floor every other mechanism builds on."),
        new("Direct.ReadsEnvSafe", "Direct", [Own("Direct.Probes.ReadsEnvSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin: the sink replaced by safe System.String.Concat."),

        // ---- Transitive --------------------------------------------------------------------------------------
        new("Transitive.Outer", "Transitive",
            [Own("Transitive.Chain.Outer()"), Own("Transitive.Chain.Middle()"), Own("Transitive.Chain.Inner()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "Three own call hops; only Inner touches the sink."),
        new("Transitive.OuterSafe", "Transitive", [Own("Transitive.Chain.OuterSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin chain ending in safe System.String.Concat."),

        // ---- CrossAssembly -----------------------------------------------------------------------------------
        new("CrossAssembly.UsesDependency", "CrossAssembly",
            [Own("CrossAssembly.Callers.UsesDependency()"), Own("Dependency.EnvReader.Read()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "The sink is in the Dependency assembly: only a graph holding both assemblies sees the path. Holds from A1, whose MemberIndex already joins both."),
        new("CrossAssembly.UsesDependencySafe", "CrossAssembly", [Own("CrossAssembly.Callers.UsesDependencySafe()")], null,
            Expectation.Absent, Phase.A1,
            "Twin: Dependency.EnvReader.ReadSafe calls safe System.String.Concat. Active from A1, whose index holds both assemblies, so the Absent is meaningful."),

        // ---- DelegateLocal -----------------------------------------------------------------------------------
        new("DelegateLocal.InvokesLocalDelegate", "DelegateLocal",
            [Own("DelegateLocal.LocalDelegates.InvokesLocalDelegate()"), Own("DelegateLocal.LocalDelegates.ReadsEnv()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "ldftn ReadsEnv and Func<string>.Invoke in the same method: the ldftn edge alone recovers the path (ADR-0020 decision 5)."),
        new("DelegateLocal.InvokesLocalDelegateSafe", "DelegateLocal", [Own("DelegateLocal.LocalDelegates.InvokesLocalDelegateSafe()")], null,
            Expectation.Absent, Phase.A1,
            "Twin: the delegate targets ReadsEnvSafe."),

        // ---- DelegateField -----------------------------------------------------------------------------------
        new("DelegateField.Store", "DelegateField",
            [Own("DelegateField.Holder.Store()"), Own("DelegateField.Holder.ReadsEnv()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "The storing method holds the ldftn, so storing -> target is an ldftn edge."),
        new("DelegateField.Fire", "DelegateField",
            [Own("DelegateField.Holder.Fire()"), Own("DelegateField.Holder.ReadsEnv()"), GetEnv],
            Env, Expectation.KnownGap, Phase.A1,
            "Fire only calls the platform's Func<string>.Invoke on a field, which names no target. ideal: Present. " +
            "lever: a delegate-target set (any ldftn-loaded method whose signature matches the invoked delegate; research §5.4.4)."),
        new("DelegateField.StoreSafe", "DelegateField", [Own("DelegateField.SafeHolder.StoreSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin storing method: its ldftn targets ReadsEnvSafe. Separate field, so it cannot alias the interesting one."),
        new("DelegateField.FireSafe", "DelegateField", [Own("DelegateField.SafeHolder.FireSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin invoking method: Func<string>.Invoke is a platform leaf."),

        // ---- Interface ---------------------------------------------------------------------------------------
        new("Interface.CallsThroughInterface", "Interface",
            [Own("Interface.Dispatch.CallsThroughInterface()"), Own("Interface.EnvProbe.Run()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "callvirt IProbe.Run; CHA fans out to every IProbe implementor, EnvProbe.Run among them."),
        new("Interface.ShouldHaveNoCapability", "Interface",
            [Own("Interface.Dispatch.ShouldHaveNoCapability()"), Own("Interface.EnvProbe.Run()"), GetEnv],
            Env, Expectation.KnownImprecision, Phase.A2Dispatch,
            "The receiver is only ever a QuietProbe, but CHA fans IProbe.Run out to EnvProbe.Run too (Capslock's ShouldHaveNoCapabilities). ideal: Absent."),
        new("Interface.CallsThroughSafeInterface", "Interface", [Own("Interface.Dispatch.CallsThroughSafeInterface()")], null,
            Expectation.Absent, Phase.A1,
            "Twin: ISafeProbe's only implementor (SafeProbe) is benign, so even CHA finds nothing."),

        // ---- Virtual -----------------------------------------------------------------------------------------
        new("Virtual.CallsThroughBase", "Virtual",
            [Own("Virtual.Callers.CallsThroughBase()"), Own("Virtual.EnvWorker.Run()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "callvirt Worker.Run (benign) on a Worker-typed receiver; CHA adds the EnvWorker override."),
        new("Virtual.CallsThroughSafeBase", "Virtual", [Own("Virtual.Callers.CallsThroughSafeBase()")], null, Expectation.Absent, Phase.A1,
            "Twin hierarchy: neither SafeWorker.Run nor its override reaches a sink."),

        // ---- TypeTest ----------------------------------------------------------------------------------------
        new("TypeTest.CallsMaybeTouch", "TypeTest",
            [Own("TypeTest.Inspector.CallsMaybeTouch()"), Own("TypeTest.Inspector.MaybeTouch(System.Object)"),
             Own("TypeTest.FileToucher.Touch()"), Platform("System.IO.File.ReadAllText(System.String)")],
            Capability.FileSystem, Expectation.KnownImprecision, Phase.A2Dispatch,
            "`o is IFileToucher t` guards t.Touch(), and nothing ever passes an IFileToucher (Capslock's MaybeChmod); CHA still reaches FileToucher.Touch. ideal: Absent."),
        new("TypeTest.CallsMaybeTouchSafe", "TypeTest", [Own("TypeTest.Inspector.CallsMaybeTouchSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin: ISafeToucher's only implementor is benign."),

        // ---- StaticInit --------------------------------------------------------------------------------------
        new("StaticInit.FieldInitializer", "StaticInit", [Own("StaticInit.FieldInit..cctor()"), GetEnv], Env, Expectation.Present, Phase.A1,
            "A static field initializer compiles to .cctor, which is an entry point (ADR-0020 decision 6)."),
        new("StaticInit.ExplicitConstructor", "StaticInit", [Own("StaticInit.ExplicitInit..cctor()"), GetEnv], Env, Expectation.Present, Phase.A1,
            "An explicit static constructor (no beforefieldinit) is the same .cctor entry point."),
        new("StaticInit.TriggersInit", "StaticInit",
            [Own("StaticInit.Triggers.TriggersInit()"), Own("StaticInit.FieldInit..cctor()"), GetEnv],
            Env, Expectation.Present, Phase.A2,
            "TriggersInit only does ldsfld FieldInit.Value - no call instruction at all. A2 adds a TypeInitializer edge to the .cctor of any own type whose static member is referenced."),
        new("StaticInit.TriggersExplicitInit", "StaticInit",
            [Own("StaticInit.Triggers.TriggersExplicitInit()"), Own("StaticInit.ExplicitInit..cctor()"), GetEnv],
            Env, Expectation.Present, Phase.A2,
            "Same TypeInitializer edge, for a type without beforefieldinit."),
        new("StaticInit.SafeFieldInitializer", "StaticInit", [Own("StaticInit.SafeFieldInit..cctor()")], null, Expectation.Absent, Phase.A1,
            "Twin .cctor: safe System.String.Concat initializer."),
        new("StaticInit.TriggersSafeInit", "StaticInit", [Own("StaticInit.Triggers.TriggersSafeInit()")], null, Expectation.Absent, Phase.A1,
            "Twin trigger: its TypeInitializer edge leads only to the benign SafeFieldInit..cctor."),

        // ---- ModuleInit --------------------------------------------------------------------------------------
        new("ModuleInit.Init", "ModuleInit", [Own("ModuleInit.Startup.Init()"), GetEnv], Env, Expectation.Present, Phase.A1,
            "[ModuleInitializer] runs at load (install-time vector). Its only IL caller is <Module>..cctor(), which the analysis-net model drops - so the graph must treat Init itself as an entry point."),
        new("ModuleInit.InitSafe", "ModuleInit", [Own("ModuleInit.SafeStartup.InitSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin module initializer with a benign body."),

        // ---- Lambda ------------------------------------------------------------------------------------------
        new("Lambda.Linq", "Lambda",
            [Own("Lambda.LinqCase.CountsSetVariables(System.String[])"), Own("Lambda.LinqCase.<>c.<CountsSetVariables>b__0_0(System.String)"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "Non-capturing lambda cached in <>c, handed to safe System.Linq.Enumerable.Where: enclosing -> lambda is an ldftn edge."),
        new("Lambda.LinqSafe", "Lambda", [Own("Lambda.LinqCase.CountsSetVariablesSafe(System.String[])")], null, Expectation.Absent, Phase.A1,
            "Twin LINQ lambda."),
        new("Lambda.Capture", "Lambda",
            [Own("Lambda.CaptureCase.Captures(System.String)"), Own("Lambda.CaptureCase.<>c__DisplayClass0_0.<Captures>b__0()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "Capturing lambda: newobj <>c__DisplayClass0_0 then ldftn of its <Captures>b__0 (no method-ordinal suffix on display-class lambdas)."),
        new("Lambda.CaptureSafe", "Lambda", [Own("Lambda.CaptureCase.CapturesSafe(System.String)")], null, Expectation.Absent, Phase.A1,
            "Twin capturing lambda."),
        new("Lambda.Lazy", "Lambda",
            [Own("Lambda.LazyCase.LazyFactory()"), Own("Lambda.LazyCase.<>c.<LazyFactory>b__0_0()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "Lazy<string> factory: the platform invokes it later from get_Value; the ldftn is in LazyFactory."),
        new("Lambda.LazySafe", "Lambda", [Own("Lambda.LazyCase.LazyFactorySafe()")], null, Expectation.Absent, Phase.A1,
            "Twin Lazy<string> factory."),
        new("Lambda.TaskRun", "Lambda",
            [Own("Lambda.TaskRunCase.RunsOnThreadPool()"), Own("Lambda.TaskRunCase.<>c.<RunsOnThreadPool>b__0_0()"),
             Platform("System.Diagnostics.Process.Start(System.String)")],
            Capability.ProcessExecution, Expectation.Present, Phase.A1,
            "Task.Run(() => Process.Start(...)): the thread pool invokes the lambda; the ldftn is in RunsOnThreadPool."),
        new("Lambda.TaskRunSafe", "Lambda", [Own("Lambda.TaskRunCase.RunsOnThreadPoolSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin Task.Run lambda."),
        new("Lambda.Sort", "Lambda",
            [Own("Lambda.SortCase.SortsWithLambda(System.Collections.Generic.List`1<System.String>)"),
             Own("Lambda.SortCase.<>c.<SortsWithLambda>b__0_0(System.String,System.String)"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "List<T>.Sort(Comparison<T>) with a lambda (System.Collections.* is safe): ldftn edge."),
        new("Lambda.SortSafe", "Lambda", [Own("Lambda.SortCase.SortsWithLambdaSafe(System.Collections.Generic.List`1<System.String>)")], null,
            Expectation.Absent, Phase.A1,
            "Twin Comparison lambda."),
        new("Lambda.EventSubscribe", "Lambda",
            [Own("Lambda.Publisher.Subscribe()"), Own("Lambda.Publisher.OnRaised()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "`Raised += OnRaised`: the subscriber holds the ldftn of the handler."),
        new("Lambda.EventRaise", "Lambda",
            [Own("Lambda.Publisher.Raise()"), Own("Lambda.Publisher.OnRaised()"), GetEnv],
            Env, Expectation.KnownGap, Phase.A1,
            "Raise only calls the platform's Action.Invoke on the backing field, in a different method from the subscription. ideal: Present. " +
            "lever: a delegate-target set (as DelegateField.Fire; research §5.4.4)."),
        new("Lambda.EventSubscribeSafe", "Lambda", [Own("Lambda.SafePublisher.SubscribeSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin subscriber: the handler is benign."),
        new("Lambda.EventRaiseSafe", "Lambda", [Own("Lambda.SafePublisher.RaiseSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin raiser: Action.Invoke is a platform leaf."),

        // ---- PlatformCallback --------------------------------------------------------------------------------
        new("PlatformCallback.ArraySortComparer", "PlatformCallback",
            [Own("PlatformCallback.Callbacks.SortsWithComparer(System.String[])"), Own("PlatformCallback.EnvComparer.Compare(System.String,System.String)"), GetEnv],
            Env, Expectation.KnownGap, Phase.A1,
            "Array.Sort (safe, a platform leaf - ADR-0020 decision 7) is what calls EnvComparer.Compare; the caller only does newobj EnvComparer. ideal: Present. " +
            "lever: `newobj T` => edges to T's overrides of platform virtuals - decide in the reachability ADR."),
        new("PlatformCallback.ConcatToString", "PlatformCallback",
            [Own("PlatformCallback.Callbacks.ConcatsObject()"), Own("PlatformCallback.EnvToString.ToString()"), GetEnv],
            Env, Expectation.KnownGap, Phase.A1,
            "string.Concat(object) calls the ToString override inside the platform. ideal: Present. " +
            "lever: `newobj T` => edges to T's overrides of platform virtuals - decide in the reachability ADR."),
        new("PlatformCallback.CompareIsEntryPoint", "PlatformCallback",
            [Own("PlatformCallback.EnvComparer.Compare(System.String,System.String)"), GetEnv], Env, Expectation.Present, Phase.A1,
            "Why the gap above is survivable: Compare is itself an entry point, so the capability is still reported - without the provenance."),
        new("PlatformCallback.ToStringIsEntryPoint", "PlatformCallback",
            [Own("PlatformCallback.EnvToString.ToString()"), GetEnv], Env, Expectation.Present, Phase.A1,
            "Same for the ToString override."),
        new("PlatformCallback.ArraySortComparerSafe", "PlatformCallback", [Own("PlatformCallback.Callbacks.SortsWithComparerSafe(System.String[])")], null,
            Expectation.Absent, Phase.A1,
            "Twin comparer."),
        new("PlatformCallback.ConcatToStringSafe", "PlatformCallback", [Own("PlatformCallback.Callbacks.ConcatsObjectSafe()")], null,
            Expectation.Absent, Phase.A1,
            "Twin ToString override."),

        // ---- LocalFunction -----------------------------------------------------------------------------------
        new("LocalFunction.CallsLocal", "LocalFunction",
            [Own("LocalFunction.LocalCalls.CallsLocal()"), Own("LocalFunction.LocalCalls.<CallsLocal>g__Read|0_0()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "A static local function called directly: a plain call to a compiler-named method on the containing type."),
        new("LocalFunction.ConvertsLocal", "LocalFunction",
            [Own("LocalFunction.LocalCalls.ConvertsLocal()"), Own("LocalFunction.LocalCalls.<ConvertsLocal>g__Read|1_0()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "A local function converted to Func<string>: ldftn edge."),
        new("LocalFunction.CallsLocalSafe", "LocalFunction", [Own("LocalFunction.LocalCalls.CallsLocalSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin."),
        new("LocalFunction.ConvertsLocalSafe", "LocalFunction", [Own("LocalFunction.LocalCalls.ConvertsLocalSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin."),

        // ---- Generics ----------------------------------------------------------------------------------------
        new("Generics.ConstrainedCall", "Generics",
            [Own("Generics.Constrained.Bar()"), Own("Generics.Constrained.Foo`1(!!0)"), Own("Generics.A.Baz()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "Bar calls Foo<A>(A) - an instantiation whose call-site name is Foo`1(MechanismFixture.Generics.A); the waypoint is the definition Foo`1(!!0). " +
            "Inside, `constrained. !!T callvirt IBaz.Baz` fans out by CHA to A.Baz."),
        new("Generics.ConstrainedCallSafe", "Generics", [Own("Generics.Constrained.BarSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin: ISafeBaz's only implementor is benign."),
        new("Generics.GenericOwnType", "Generics",
            [Own("Generics.Boxes.RunsBox()"), Own("Generics.Box`1.Run()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "callvirt Box<int>.Run - the known 95-99% join miss: the reference is through the instantiation Box`1<System.Int32>, the definition is Box`1.Run()."),
        new("Generics.GenericOwnTypeSafe", "Generics", [Own("Generics.Boxes.RunsSafeBox()")], null, Expectation.Absent, Phase.A1,
            "Twin generic type."),
        new("Generics.LambdaInGenericMethod", "Generics",
            [Own("Generics.Closures.WrapsInt()"), Own("Generics.Closures.Wraps`1(!!0,System.String)"),
             Own("Generics.Closures.<>c__DisplayClass0_0`1.<Wraps>b__0()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "A capturing lambda inside generic Wraps<T>: its display class is itself generic (<>c__DisplayClass0_0`1), and the ldftn names it through an instantiation."),
        new("Generics.LambdaInGenericMethodSafe", "Generics", [Own("Generics.Closures.WrapsIntSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin generic-closure lambda."),

        // ---- Async -------------------------------------------------------------------------------------------
        new("Async.Method", "Async",
            [Own("Async.AsyncProbes.Probe()"), Own("Async.AsyncProbes.<Probe>d__0.MoveNext()"), GetEnv],
            Env, Expectation.Present, Phase.A2,
            "The stub only calls AsyncTaskMethodBuilder`1.Start`1(!!0&) on a STRUCT state machine (Release). A2's state-machine edge: stub -> MoveNext (ADR-0020 amendment 1)."),
        new("Async.MethodSafe", "Async", [Own("Async.AsyncProbes.ProbeSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin async method."),
        new("Async.Lambda", "Async",
            [Own("Async.AsyncLambdaCase.RunsAsyncLambda()"), Own("Async.AsyncLambdaCase.<>c.<RunsAsyncLambda>b__0_0()"),
             Own("Async.AsyncLambdaCase.<>c.<<RunsAsyncLambda>b__0_0>d.MoveNext()"), GetEnv],
            Env, Expectation.Present, Phase.A2,
            "Async lambda passed to Task.Run: ldftn to the lambda, then the lambda's own state machine <<RunsAsyncLambda>b__0_0>d (nested in <>c, no __N suffix)."),
        new("Async.LambdaSafe", "Async", [Own("Async.AsyncLambdaCase.RunsAsyncLambdaSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin async lambda."),
        new("Async.LocalFunction", "Async",
            [Own("Async.AsyncLocalCase.CallsAsyncLocal()"), Own("Async.AsyncLocalCase.<CallsAsyncLocal>g__Read|0_0()"),
             Own("Async.AsyncLocalCase.<<CallsAsyncLocal>g__Read|0_0>d.MoveNext()"), GetEnv],
            Env, Expectation.Present, Phase.A2,
            "Async local function: plain call to <CallsAsyncLocal>g__Read|0_0, whose state machine is <<CallsAsyncLocal>g__Read|0_0>d. A name heuristic would miss this mangling."),
        new("Async.LocalFunctionSafe", "Async", [Own("Async.AsyncLocalCase.CallsAsyncLocalSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin async local function."),

        // ---- Iterator ----------------------------------------------------------------------------------------
        new("Iterator.Stub", "Iterator",
            [Own("Iterator.Sequences.Enum()"), Own("Iterator.Sequences.<Enum>d__0.MoveNext()"), GetEnv],
            Env, Expectation.Present, Phase.A2,
            "The stub only does newobj <Enum>d__0(System.Int32); A2: newobj of an IEnumerator closure type => edge to its MoveNext."),
        new("Iterator.StubSafe", "Iterator", [Own("Iterator.Sequences.EnumSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin iterator stub: newobj <EnumSafe>d__1, whose MoveNext is benign."),
        new("Iterator.Consumer", "Iterator",
            [Own("Iterator.Consumers.Consumes(System.Collections.Generic.IEnumerable`1<System.String>)"),
             Own("Iterator.Sequences.<Enum>d__0.MoveNext()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "The consumer receives IEnumerable<string> as a parameter and never names the iterator; its callvirt System.Collections.IEnumerator.MoveNext reaches <Enum>d__0.MoveNext by CHA."),
        new("Iterator.ConsumerOfSafeSequence", "Iterator",
            [Own("Iterator.Consumers.ConsumesEnumSafe()"), Own("Iterator.Consumers.Consumes(System.Collections.Generic.IEnumerable`1<System.String>)"),
             Own("Iterator.Sequences.<Enum>d__0.MoveNext()"), GetEnv],
            Env, Expectation.KnownImprecision, Phase.A2Dispatch,
            "Twin DRIVER: hands the shared consumer only EnumSafe(), but the consumer's IEnumerator.MoveNext fans out by CHA to every own iterator, the interesting one included. " +
            "Not in the spec's decision table (which says twins are Absent): an iterator consumer's twin cannot be Absent under CHA. ideal: Absent."),

        // ---- Opacity -----------------------------------------------------------------------------------------
        new("Opacity.ReflectionInvoke", "Opacity",
            [Own("Opacity.Reflective.InvokesByName()"), Platform("System.Reflection.MethodBase.Invoke(System.Object,System.Object[])")],
            Capability.ReflectionInvocation, Expectation.Present, Phase.A1,
            "MethodInfo.Invoke on a method looked up by name string; C# binds it to MethodBase.Invoke. The map classifies the platform node; there is no edge to Targets.ReadsEnv at all."),
        new("Opacity.ReflectionInvokeSafe", "Opacity", [Own("Opacity.Reflective.InvokesByNameSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin: the same Type.GetMethod lookup without the Invoke (GetTypeFromHandle and GetMethod are unclassified)."),
        new("Opacity.FunctionPointer", "Opacity",
            [Own("Opacity.Pointers.CallsThroughPointer()"), Own("Opacity.Targets.ReadsEnv()"), GetEnv],
            Env, Expectation.Present, Phase.A1,
            "`delegate*<string> fp = &Targets.ReadsEnv; fp()`: ldftn + calli. Present via the ldftn; the calli site is a separate opacity row (Opacity.FunctionPointerCalli)."),
        new("Opacity.FunctionPointerSafe", "Opacity", [Own("Opacity.Pointers.CallsThroughPointerSafe()")], null, Expectation.Absent, Phase.A1,
            "Twin: the pointer targets ReadsEnvSafe."),
        new("Opacity.Dynamic", "Opacity",
            [Own("Opacity.Dynamic.CallsDynamic(System.Object)"), "^" + Regex.Escape("Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember(")],
            Capability.DynamicCodeLoading, Expectation.Present, Phase.A1,
            "`dynamic d = target; d.Run()` compiles to Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember (+ CSharpArgumentInfo.Create, CallSite`1.Create): classified by the map. " +
            "The waypoint is a prefix regex, so the binder's long signature is not restated."),
        new("Opacity.DynamicSafe", "Opacity", [Own("Opacity.Dynamic.CallsStatically(MechanismFixture.Opacity.Runner)")], null, Expectation.Absent, Phase.A1,
            "Twin: the same call statically bound to the benign Runner.Run."),
        new("Opacity.PInvokePath", "Opacity",
            [Own("Opacity.Native.CallsNative()"), Own("Opacity.Native.getpid()")],
            null, Expectation.Present, Phase.A1,
            "A plain call to the bodyless [DllImport] extern: A1's static graph already has the edge to its OwnBodyless node. " +
            "No capability is asserted here - that is Opacity.PInvokeCapability (Reachability)."),
        new("Opacity.PInvokeCapability", "Opacity",
            [Own("Opacity.Native.CallsNative()"), Own("Opacity.Native.getpid()")],
            Capability.NativeInterop, Expectation.Present, Phase.Reachability,
            "The same path WITH NativeInterop on the final node: classifying a bodyless extern belongs to the reachability ADR (the map does not classify own externs). " +
            "Until then only CapabilityAnalysis's metadata seam (NativeImport on getpid itself) reports it."),
        new("Opacity.PInvokeSafe", "Opacity", [Own("Opacity.Native.CallsManaged()")], null, Expectation.Absent, Phase.A1,
            "Twin: a managed computation (safe System.Math.Abs) in place of the native call."),

        // ---- Safe --------------------------------------------------------------------------------------------
        new("Safe.SafeOnly", "Safe", [Own("Safe.Pure.SafeOnly(System.String)")], null, Expectation.Absent, Phase.A1,
            "Only safe APIs: System.String, System.Math, System.Collections.Generic.List`1."),

        // ---- ExpressionTree ----------------------------------------------------------------------------------
        // Both rows are about EnvironmentProbe specifically: both methods call Expression`1.Compile, which the map
        // classifies DynamicCodeLoading, so "any capability" would hold for the twin too and prove nothing.
        new("ExpressionTree.CompilesEnvTree", "ExpressionTree", [Own("ExpressionTree.Trees.CompilesEnvTree()"), GetEnv],
            Env, Expectation.KnownGap, Phase.A1,
            "`Expression<Func<string>> e = () => Environment.GetEnvironmentVariable(...); e.Compile()()`: the lambda is never an own method - " +
            "the IL is `ldtoken GetEnvironmentVariable` + MethodBase.GetMethodFromHandle + Expression.Call + Expression.Lambda + Compile + Invoke, " +
            "so no call/callvirt/newobj/ldftn names the sink and the static graph has no edge to it. ideal: Present. " +
            "lever: an `ldtoken` method edge (A2 decides)."),
        new("ExpressionTree.CompilesSafeTree", "ExpressionTree", [Own("ExpressionTree.Trees.CompilesSafeTree()")], Env, Expectation.Absent, Phase.A1,
            "Twin: the same tree shape with ldtoken System.String.Concat. Scoped to EnvironmentProbe because Compile (DynamicCodeLoading) is reached by both; " +
            "stays Absent even once an ldtoken edge lands, since Concat is safe."),

        // ---- A2 S1 dispatch mechanisms (cha-a2-dispatch-and-implicit-edges.md §8) -----------------------------
        // Tagged A2Dispatch, the phase they are about: the Absent rows hold vacuously on the static graph, and only
        // mean something once Dispatch edges exist.

        // ---- ObjectVirtual -----------------------------------------------------------------------------------
        new("ObjectVirtual.DescribesEnv", "ObjectVirtual",
            [Own("ObjectVirtual.Describers.DescribesEnv()"), Own("ObjectVirtual.Describers.Describe(System.Object)"),
             Own("ObjectVirtual.EnvDescribed.ToString()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "Describe(object o) => o.ToString() is callvirt System.Object.ToString, a platform-declared virtual: decision D1 fans it out to every own ToString override, EnvDescribed.ToString among them."),
        new("ObjectVirtual.DescribesSafe", "ObjectVirtual",
            [Own("ObjectVirtual.Describers.DescribesSafe()"), Own("ObjectVirtual.Describers.DescribeSafe(System.Object)"),
             Own("ObjectVirtual.EnvDescribed.ToString()"), GetEnv],
            Env, Expectation.KnownImprecision, Phase.A2Dispatch,
            "Twin DRIVER: DescribeSafe is only ever handed a SafeDescribed, but its callvirt Object.ToString fans out to every own override (D1; the receiver cannot be narrowed without TAC). ideal: Absent."),
        new("ObjectVirtual.DescribesNumber", "ObjectVirtual", [Own("ObjectVirtual.Describers.DescribesNumber(System.Int32)")], null,
            Expectation.Absent, Phase.A2Dispatch,
            "number.ToString() on an int is a plain `call System.Int32.ToString` (a value-type receiver needs no dispatch), so it never fans out to the own ToString overrides."),

        // ---- ExplicitImpl ------------------------------------------------------------------------------------
        new("ExplicitImpl.CallsExplicit", "ExplicitImpl",
            [Own("ExplicitImpl.Callers.CallsExplicit()"),
             Own("ExplicitImpl.EnvExplicitProbe.MechanismFixture.ExplicitImpl.IExplicitProbe.Run()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "callvirt IExplicitProbe.Run; the implementation is the explicit `string IExplicitProbe.Run()`, whose metadata name is interface-qualified - CHA matches it by its last segment."),
        new("ExplicitImpl.CallsSafeExplicit", "ExplicitImpl", [Own("ExplicitImpl.Callers.CallsSafeExplicit()")], null,
            Expectation.Absent, Phase.A2Dispatch,
            "Twin: ISafeExplicitProbe's only implementor (an explicit, benign SafeExplicitProbe.Run) reaches no sink."),

        // ---- GenericInterface --------------------------------------------------------------------------------
        new("GenericInterface.ComparesThroughInterface", "GenericInterface",
            [Own("GenericInterface.Sorters.ComparesThroughInterface()"),
             Own("GenericInterface.EnvOrder.Compare(System.String,System.String)"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "callvirt IComparer<string>.Compare - a platform generic interface instantiation - fans out under the definition key IComparer`1 to own implementors (PlatformCallback.EnvComparer too)."),
        new("GenericInterface.ComparesThroughSafeInterface", "GenericInterface", [Own("GenericInterface.Sorters.ComparesThroughSafeInterface()")], null,
            Expectation.Absent, Phase.A2Dispatch,
            "Twin: the same Compare shape through the own generic ISafeComparer<string>, whose only implementor is benign (the twin needs no platform interface, so it is Absent with its own, per A1 spec §1.7)."),

        // ---- StaticAbstract ----------------------------------------------------------------------------------
        new("StaticAbstract.BuildsEnv", "StaticAbstract",
            [Own("StaticAbstract.Builders.BuildsEnv()"), Own("StaticAbstract.Builders.Build`1()"),
             Own("StaticAbstract.EnvFactory.Make()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "T.Make() compiles to `constrained. !!T call IFactory::Make()`; CCIProvider drops the prefix, so Model sees a static call to the abstract interface member, which CHA's static rule fans out to EnvFactory.Make."),
        new("StaticAbstract.BuildsSafe", "StaticAbstract", [Own("StaticAbstract.Builders.BuildsSafe()")], null,
            Expectation.Absent, Phase.A2Dispatch,
            "Twin: ISafeFactory's only implementor SafeFactory.Make is benign."),

        // ---- OpenHierarchy -----------------------------------------------------------------------------------
        new("OpenHierarchy.FlushesEnvStream", "OpenHierarchy",
            [Own("OpenHierarchy.Flushers.FlushesEnvStream()"), Own("OpenHierarchy.Flushers.FlushIt(System.IO.Stream)"),
             Own("OpenHierarchy.EnvStream.Flush()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "EnvStream : MemoryStream overrides Stream.Flush; the subtype map never learns MemoryStream : Stream, so callvirt Stream.Flush reaches it only by decision D2 (an external declared type also fans out to every open own type)."),
        new("OpenHierarchy.FlushesSafeStream", "OpenHierarchy",
            [Own("OpenHierarchy.Flushers.FlushesSafeStream()"), Own("OpenHierarchy.Flushers.FlushItSafe(System.IO.Stream)"),
             Own("OpenHierarchy.EnvStream.Flush()"), GetEnv],
            Env, Expectation.KnownImprecision, Phase.A2Dispatch,
            "Twin DRIVER: FlushItSafe is only ever handed a SafeStream, but D2 fans its callvirt Stream.Flush out to every open type's Flush, EnvStream's included. ideal: Absent."),
        new("OpenHierarchy.FlushesJournal", "OpenHierarchy", [Own("OpenHierarchy.Flushers.FlushesJournal()")], null,
            Expectation.Absent, Phase.A2Dispatch,
            "callvirt Journal.Flush has an OWN declared type, so the open-type rule does not apply: only Journal's own subtype SafeJournal is reached, never the same-shaped EnvStream.Flush."),

        // ---- InheritedImpl (A2 S1 review C1) -----------------------------------------------------------------
        new("InheritedImpl.CallsInherited", "InheritedImpl",
            [Own("InheritedImpl.Callers.CallsInherited()"), Own("InheritedImpl.EnvBase.Run()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "class EnvInheritor : EnvBase, IInheritedProbe declares no Run: the CLR fills the interface slot with the inherited EnvBase.Run, whose type is not below IInheritedProbe. Reached by S1b's InheritedBelow rule."),
        new("InheritedImpl.CallsPlainInherited", "InheritedImpl",
            [Own("InheritedImpl.Callers.CallsPlainInherited()"), Own("InheritedImpl.PlainBase.Run()"), GetEnv],
            Env, Expectation.Present, Phase.A2Dispatch,
            "The same through a base method that is NOT virtual in source: Roslyn emits PlainBase.Run `virtual final` so it can fill PlainInheritor's IPlainProbe slot, so it is a dispatch candidate like any virtual."),
        new("InheritedImpl.CallsSafeInherited", "InheritedImpl", [Own("InheritedImpl.Callers.CallsSafeInherited()")], null,
            Expectation.Absent, Phase.A2Dispatch,
            "Twin: SafeInheritor inherits a benign SafeBase.Run for ISafeInheritedProbe; EnvBase.Run is inherited only below IInheritedProbe, so it is not reached."),
    ];

    /// <summary>Every opacity row.</summary>
    public static IReadOnlyList<MechanismOpacity> Opacities { get; } =
    [
        new("Opacity.FunctionPointerCalli", "Opacity", Own("Opacity.Pointers.CallsThroughPointer()"), OpacityKind.IndirectCall, Phase.A1,
            "The calli in CallsThroughPointer has no target in IL: it must be recorded as an IndirectCall opacity, never dropped - asserted separately from the ldftn path (Opacity.FunctionPointer)."),
    ];

    /// <summary>
    /// The mechanisms of the spec's §1.3 catalogue, in its order, then ExpressionTree (added with S1 from review 1's
    /// suggestions, spec §2.5), then the A2 S1 dispatch mechanisms (cha-a2-dispatch-and-implicit-edges.md §8).
    /// </summary>
    public static IReadOnlyList<string> Mechanisms { get; } =
    [
        "Direct", "Transitive", "CrossAssembly", "DelegateLocal", "DelegateField", "Interface", "Virtual", "TypeTest",
        "StaticInit", "ModuleInit", "Lambda", "PlatformCallback", "LocalFunction", "Generics", "Async", "Iterator",
        "Opacity", "Safe", "ExpressionTree",
        "ObjectVirtual", "ExplicitImpl", "GenericInterface", "StaticAbstract", "OpenHierarchy", "InheritedImpl",
    ];
    #endregion

    #region Methods
    /// <summary>An anchored, escaped waypoint for an own fixture method, given its node id without the root namespace.</summary>
    public static string Own(string nodeIdWithoutRoot) => "^" + Regex.Escape(RootNamespace + "." + nodeIdWithoutRoot) + "$";

    /// <summary>An anchored, escaped waypoint for a platform method's full node id.</summary>
    public static string Platform(string nodeId) => "^" + Regex.Escape(nodeId) + "$";

    /// <summary>Whether a waypoint regex addresses an own fixture method (as opposed to a platform method).</summary>
    public static bool IsOwn(string waypoint) => waypoint.StartsWith("^" + Regex.Escape(RootNamespace + "."), StringComparison.Ordinal);
    #endregion

    #region Fields
    /// <summary>The root namespace of both mechanism-fixture assemblies.</summary>
    public const string RootNamespace = "MechanismFixture";

    // A property, not a static readonly field: Paths' initializer runs first in textual order and would see null.
    private static string GetEnv => Platform("System.Environment.GetEnvironmentVariable(System.String)");
    private const Capability Env = Capability.EnvironmentProbe;
    #endregion
}
