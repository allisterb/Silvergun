namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Spec §1.5 test 3 — the presence baseline (<see cref="Phase.Baseline"/>): what the EXISTING, reachability-free
/// <see cref="CapabilityAnalysis"/> reports over the mechanism fixture today, pinned per row. For every row asserted
/// as present (Present / KnownImprecision, with a capability): does the method that calls the sink directly (the
/// penultimate waypoint) carry the capability, and does the row's first waypoint? The gap between the two columns is
/// exactly what reachability will add.
/// <para>
/// The values in <see cref="Measured"/> were MEASURED, not written from the spec's expectation. Where one
/// disagrees with "direct caller: yes; multi-hop start: no", that is a finding to report — the table is not to be
/// "fixed" to match.
/// </para>
/// </summary>
public sealed class MechanismPresenceBaselineTests : IClassFixture<MechanismFixtureFixture>
{
    public MechanismPresenceBaselineTests(MechanismFixtureFixture fixture) => this.fixture = fixture;

    /// <summary>
    /// Row id → (the direct caller has the row's capability, the first waypoint has it), as measured on the built
    /// fixture. For a two-waypoint row the direct caller IS the first waypoint, so the columns agree.
    /// </summary>
    public static IReadOnlyDictionary<string, (bool DirectCaller, bool FirstWaypoint)> Measured { get; } =
        new Dictionary<string, (bool, bool)>(StringComparer.Ordinal)
        {
            ["Direct.ReadsEnv"] = (true, true),
            ["Transitive.Outer"] = (true, false),
            ["CrossAssembly.UsesDependency"] = (true, false),
            ["DelegateLocal.InvokesLocalDelegate"] = (true, false),
            ["DelegateField.Store"] = (true, false),
            ["Interface.CallsThroughInterface"] = (true, false),
            ["Interface.ShouldHaveNoCapability"] = (true, false),
            ["Virtual.CallsThroughBase"] = (true, false),
            ["TypeTest.CallsMaybeTouch"] = (true, false),
            ["StaticInit.FieldInitializer"] = (true, true),
            ["StaticInit.ExplicitConstructor"] = (true, true),
            ["StaticInit.TriggersInit"] = (true, false),
            ["StaticInit.TriggersExplicitInit"] = (true, false),
            ["ModuleInit.Init"] = (true, true),
            ["Lambda.Linq"] = (true, false),
            ["Lambda.Capture"] = (true, false),
            ["Lambda.Lazy"] = (true, false),
            ["Lambda.TaskRun"] = (true, false),
            ["Lambda.Sort"] = (true, false),
            ["Lambda.EventSubscribe"] = (true, false),
            ["PlatformCallback.CompareIsEntryPoint"] = (true, true),
            ["PlatformCallback.ToStringIsEntryPoint"] = (true, true),
            ["LocalFunction.CallsLocal"] = (true, false),
            ["LocalFunction.ConvertsLocal"] = (true, false),
            ["Generics.ConstrainedCall"] = (true, false),
            ["Generics.GenericOwnType"] = (true, false),
            ["Generics.LambdaInGenericMethod"] = (true, false),
            ["Async.Method"] = (true, false),
            ["Async.Lambda"] = (true, false),
            ["Async.LocalFunction"] = (true, false),
            ["Iterator.Stub"] = (true, false),
            ["Iterator.Consumer"] = (true, false),
            ["Iterator.ConsumerOfSafeSequence"] = (true, false),
            ["Opacity.ReflectionInvoke"] = (true, true),
            ["Opacity.FunctionPointer"] = (true, false),
            ["Opacity.Dynamic"] = (true, true),
            // DISAGREES with "the direct caller has the capability": CapabilityAnalysis puts NativeInterop on the
            // bodyless getpid DECLARATION (a NativeImport metadata finding), not on CallsNative, which calls it.
            // Expected by the spec's decision table (extern classification belongs to the reachability ADR).
            ["Opacity.PInvokeCapability"] = (false, false),
            // A2 S1 dispatch mechanisms (measured 2026-11-02): the override/implementation that calls the sink has
            // the finding; the caller that only dispatches to it does not.
            ["ObjectVirtual.DescribesEnv"] = (true, false),
            ["ObjectVirtual.DescribesSafe"] = (true, false),
            ["ExplicitImpl.CallsExplicit"] = (true, false),
            ["GenericInterface.ComparesThroughInterface"] = (true, false),
            ["StaticAbstract.BuildsEnv"] = (true, false),
            ["OpenHierarchy.FlushesEnvStream"] = (true, false),
            ["OpenHierarchy.FlushesSafeStream"] = (true, false),
            // S1b (review C1), measured 2026-11-03: the inherited base method has the finding, the caller does not.
            ["InheritedImpl.CallsInherited"] = (true, false),
            ["InheritedImpl.CallsPlainInherited"] = (true, false),
            // A2 S2 state-machine mechanisms, measured 2026-11-03: the MoveNext that calls the sink has the finding;
            // the stub, the consumer and the twin driver, which reach it only through state-machine and dispatch
            // edges, do not.
            ["AsyncIterator.Stub"] = (true, false),
            ["AsyncIterator.Consumer"] = (true, false),
            ["AsyncIterator.ConsumerOfSafeSequence"] = (true, false),
            ["Debug.AsyncMethod"] = (true, false),
            ["Debug.AsyncLambda"] = (true, false),
            ["Debug.IteratorStub"] = (true, false),
            // A2 S3, measured 2026-11-03. The newobj row is like the trigger rows: Constructed..cctor has the finding,
            // CreatesExplicitInit does not. DISAGREES with "the direct caller has the capability": CompilesEnvTree's
            // only reference to the sink is an ldtoken, which the scanner, unlike the A2 graph, does not treat as a use
            // (it reports DynamicCodeLoading for the Compile call there, not EnvironmentProbe).
            ["StaticInit.CreatesExplicitInit"] = (true, false),
            // S3 review W3, measured 2026-11-03: ValueInit..cctor (the penultimate waypoint) has the finding.
            ["StaticInit.CallsValueMember"] = (true, false),
            ["ExpressionTree.CompilesEnvTree"] = (false, false),
        };

    public static TheoryData<string> PresentRowsWithCapability() =>
        Ids(MechanismGroundTruth.Paths.Where(IsAssertedPresentWithCapability));

    public static TheoryData<string> AbsentRows() =>
        Ids(MechanismGroundTruth.Paths.Where(p => p.Expect == Expectation.Absent));

    [Fact]
    public void Measured_CoversExactlyThePresentRowsWithACapability() =>
        Assert.Equal(
            MechanismGroundTruth.Paths.Where(IsAssertedPresentWithCapability).Select(p => p.Id).OrderBy(id => id, StringComparer.Ordinal),
            Measured.Keys.OrderBy(id => id, StringComparer.Ordinal));

    [Theory]
    [MemberData(nameof(PresentRowsWithCapability))]
    public void Baseline_PresentRow_MatchesTheMeasuredPresence(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var capability = row.Capability!.Value;

        var actual = (HasCapability(row.Waypoints[^2], capability), HasCapability(row.Waypoints[0], capability));

        Assert.Equal(Measured[id], actual);
    }

    [Fact]
    public void Baseline_MultiHopStarts_NeverCarryTheCapabilityToday()
    {
        // The spec's "the first waypoint of every multi-hop row does not" - holds without exception.
        var multiHop = MechanismGroundTruth.Paths.Where(p => IsAssertedPresentWithCapability(p) && p.Waypoints.Length > 2);

        Assert.All(multiHop, row => Assert.False(Measured[row.Id].FirstWaypoint, row.Id));
    }

    [Fact]
    public void Baseline_DirectCallers_CarryTheCapability_ExceptThePInvokeCallerAndTheTokenUser()
    {
        // The spec's "the method that calls the sink directly has the capability" - holds for every row except the
        // P/Invoke one, whose capability the scanner attributes to the extern declaration instead, and (since A2 S3
        // promoted it to Present) ExpressionTree.CompilesEnvTree, which only ldtokens the sink: the scanner sees no use.
        var exceptions = Measured.Where(m => !m.Value.DirectCaller).Select(m => m.Key).Order(StringComparer.Ordinal);

        Assert.Equal(["ExpressionTree.CompilesEnvTree", "Opacity.PInvokeCapability"], exceptions);
    }

    /// <summary>
    /// An Absent row's start has no finding at all — or, for a row scoped to one capability (only
    /// ExpressionTree.CompilesSafeTree, whose Compile call is a DynamicCodeLoading finding by design), none of THAT
    /// capability.
    /// </summary>
    [Theory]
    [MemberData(nameof(AbsentRows))]
    public void Baseline_AbsentRowStart_HasNoFindingOfItsCapability(string id)
    {
        var row = MechanismGroundTruth.Paths.Single(p => p.Id == id);
        var start = Definition(row.Waypoints[0]);

        Assert.DoesNotContain(fixture.Findings, f =>
            f.CallerType == start.CallerType && f.CallerMethod == start.CallerMethod && (row.Capability is null || f.Capability == row.Capability));
    }

    [Fact]
    public void Baseline_DirectCallSitesAlone_SatisfyEveryPresentRowExceptThosePinnedHere()
    {
        // Not a call graph: the test-side view of DIRECT call/callvirt/newobj/ldftn sites (MechanismCallSites, all
        // three assemblies, instantiations mapped to definitions, map-only classification). The rows it cannot satisfy
        // are exactly the ones that need what A2 adds beyond plain edges - CHA fan-out, the state-machine edge, the
        // TypeInitializer edge - or the reachability phase's extern classification. Measured.
        var needMore = MechanismGroundTruth.Paths
            .Where(p => p.Expect is Expectation.Present or Expectation.KnownImprecision)
            .Where(p => !WaypointMatcher.Evaluate(p, fixture.GroundTruthCallSites.Edges, MapCapability).Holds)
            .Select(p => p.Id)
            .OrderBy(id => id, StringComparer.Ordinal);

        Assert.Equal(
            new[]
            {
                "Async.Lambda",                       // state-machine edge
                "Async.LocalFunction",                // state-machine edge
                "Async.Method",                       // state-machine edge
                "AsyncIterator.Consumer",             // state-machine edges + CHA from IAsyncEnumerator`1.MoveNextAsync
                "AsyncIterator.ConsumerOfSafeSequence", // state-machine edges + CHA from IAsyncEnumerator`1.MoveNextAsync
                "AsyncIterator.Stub",                 // newobj async-iterator class => MoveNext edge
                "Debug.AsyncLambda",                  // state-machine edge (Debug: newobj + Start<S>)
                "Debug.AsyncMethod",                  // state-machine edge (Debug: newobj + Start<S>)
                "Debug.IteratorStub",                 // newobj closure => MoveNext edge
                "ExplicitImpl.CallsExplicit",         // CHA: explicit implementation name
                "ExpressionTree.CompilesEnvTree",     // LoadToken edge (ldtoken is not a call site)
                "GenericInterface.ComparesThroughInterface", // CHA from IComparer<string>.Compare
                "Generics.ConstrainedCall",           // CHA: constrained callvirt IBaz.Baz -> A.Baz
                "InheritedImpl.CallsInherited",       // CHA: interface slot filled by an inherited method (C1)
                "InheritedImpl.CallsPlainInherited",  // CHA: the same, base method non-virtual in source (C1)
                "Interface.CallsThroughInterface",    // CHA
                "Interface.ShouldHaveNoCapability",   // CHA
                "Iterator.Consumer",                  // CHA from System.Collections.IEnumerator.MoveNext
                "Iterator.ConsumerOfSafeSequence",    // CHA from System.Collections.IEnumerator.MoveNext
                "Iterator.Stub",                      // newobj closure => MoveNext edge
                "ObjectVirtual.DescribesEnv",         // CHA from System.Object.ToString (D1)
                "ObjectVirtual.DescribesSafe",        // CHA from System.Object.ToString (D1)
                "Opacity.PInvokeCapability",          // extern classification (Reachability)
                "OpenHierarchy.FlushesEnvStream",     // CHA open-type rule from System.IO.Stream.Flush (D2)
                "OpenHierarchy.FlushesSafeStream",    // CHA open-type rule from System.IO.Stream.Flush (D2)
                "StaticAbstract.BuildsEnv",           // CHA static rule: constrained. call IFactory.Make
                "StaticInit.CallsValueMember",        // TypeInitializer edge (a value type's instance method)
                "StaticInit.CreatesExplicitInit",     // TypeInitializer edge (from newobj)
                "StaticInit.TriggersExplicitInit",    // TypeInitializer edge
                "StaticInit.TriggersInit",            // TypeInitializer edge
                "TypeTest.CallsMaybeTouch",           // CHA
                "Virtual.CallsThroughBase",           // CHA
            },
            needMore);
    }

    [Fact]
    public void Baseline_AllFindingsOverTheFixture_ArePinned()
    {
        // The whole scanner output, so a fixture edit that adds or loses a finding anywhere is noticed here and the
        // per-row pins above are re-measured rather than trusted.
        var rendered = fixture.Findings
            .Select(f => $"{f.Capability} {f.Kind} {f.CallerType}::{f.CallerMethod} -> {f.CalledApi}")
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToArray();

        // Name the difference first: xUnit's collection diff truncates these long strings.
        var missing = ExpectedFindings.Except(rendered, StringComparer.Ordinal).ToArray();
        var unexpected = rendered.Except(ExpectedFindings, StringComparer.Ordinal).ToArray();
        Assert.True(missing.Length == 0 && unexpected.Length == 0,
            $"Missing:{Environment.NewLine}{string.Join(Environment.NewLine, missing)}{Environment.NewLine}" +
            $"Unexpected:{Environment.NewLine}{string.Join(Environment.NewLine, unexpected)}");
        Assert.Equal(ExpectedFindings.OrderBy(s => s, StringComparer.Ordinal), rendered);
    }

    private static TheoryData<string> Ids(IEnumerable<MechanismPath> rows)
    {
        var data = new TheoryData<string>();
        foreach (var row in rows)
            data.Add(row.Id);
        return data;
    }

    private static bool IsAssertedPresentWithCapability(MechanismPath row) =>
        row.Expect is Expectation.Present or Expectation.KnownImprecision && row.Capability is not null;

    // Whether CapabilityAnalysis attributed `capability` to the single own method the waypoint names. Findings are
    // keyed (CallerType, CallerMethod), which is unambiguous here: the fixture has no overloads.
    private bool HasCapability(string waypoint, Capability capability)
    {
        var method = Definition(waypoint);
        return fixture.Findings.Any(f =>
            f.Capability == capability && f.CallerType == method.CallerType && f.CallerMethod == method.CallerMethod);
    }

    private Capability? MapCapability(string nodeId) =>
        fixture.GroundTruthCallSites.Targets.TryGetValue(nodeId, out var key) &&
        CapabilityMap.Default.Classify(key) is { Class: CapabilityClass.Capability, Capability: { } capability }
            ? capability
            : null;

    private MechanismCallSites.OwnMethod Definition(string waypoint)
    {
        var pattern = new Regex(waypoint);
        return fixture.GroundTruthCallSites.Definitions.Values.Single(d => pattern.IsMatch(d.NodeId));
    }

    private static readonly string[] ExpectedFindings =
    [
        // S1's ExpressionTree pair: both bodies callvirt Expression`1.Compile (DynamicCodeLoading). There is NO
        // EnvironmentProbe finding for CompilesEnvTree - its only reference to the sink is an ldtoken, which the
        // scanner, like the A1 graph, does not treat as a call (row ExpressionTree.CompilesEnvTree: KnownGap until A2
        // S3's LoadToken edge, Present since - in the graph, not here).
        "DynamicCodeLoading Call MechanismFixture.ExpressionTree.Trees::CompilesEnvTree -> System.Linq.Expressions.Expression<System.Func<System.String>>.Compile",
        "DynamicCodeLoading Call MechanismFixture.ExpressionTree.Trees::CompilesSafeTree -> System.Linq.Expressions.Expression<System.Func<System.String>>.Compile",
        "DynamicCodeLoading Call MechanismFixture.Opacity.Dynamic::CallsDynamic -> Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember",
        "DynamicCodeLoading Call MechanismFixture.Opacity.Dynamic::CallsDynamic -> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.Create",
        "EnvironmentProbe Call MechanismFixture.Async.AsyncLambdaCase.<>c.<<RunsAsyncLambda>b__0_0>d::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Async.AsyncLocalCase.<<CallsAsyncLocal>g__Read|0_0>d::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Async.AsyncProbes.<Probe>d__0::MoveNext -> System.Environment.GetEnvironmentVariable",
        // A2 S2: the async iterator's MoveNext, and the Debug-built fixture's three state machines (one sink each,
        // none on the twins).
        "EnvironmentProbe Call MechanismFixture.AsyncIterator.Sequences.<Env>d__0::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Debug.Async.AsyncLambdaCase.<>c.<<RunsAsyncLambda>b__0_0>d::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Debug.Async.AsyncProbes.<Probe>d__0::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Debug.Iterator.Sequences.<Enum>d__0::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.DelegateField.Holder::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.DelegateLocal.LocalDelegates::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Dependency.EnvReader::Read -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Direct.Probes::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        // A2 S1's dispatch mechanisms: one sink per interesting override/implementation, none on the twins.
        "EnvironmentProbe Call MechanismFixture.ExplicitImpl.EnvExplicitProbe::MechanismFixture.ExplicitImpl.IExplicitProbe.Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.GenericInterface.EnvOrder::Compare -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.InheritedImpl.EnvBase::Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.InheritedImpl.PlainBase::Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.ObjectVirtual.EnvDescribed::ToString -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.OpenHierarchy.EnvStream::Flush -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.StaticAbstract.EnvFactory::Make -> System.Environment.GetEnvironmentVariable",
        // A2 S1 review 2 (W-B): SB.Make calls the sink directly; SC inherits it as IFactory's static implementation.
        "EnvironmentProbe Call MechanismFixture.StaticInherited.SB::Make -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Generics.A::Baz -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Generics.Box::Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Generics.Closures.<>c__DisplayClass0_0::<Wraps>b__0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Interface.EnvProbe::Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Iterator.Sequences.<Enum>d__0::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Lambda.CaptureCase.<>c__DisplayClass0_0::<Captures>b__0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Lambda.LazyCase.<>c::<LazyFactory>b__0_0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Lambda.LinqCase.<>c::<CountsSetVariables>b__0_0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Lambda.Publisher::OnRaised -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Lambda.SortCase.<>c::<SortsWithLambda>b__0_0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.LocalFunction.LocalCalls::<CallsLocal>g__Read|0_0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.LocalFunction.LocalCalls::<ConvertsLocal>g__Read|1_0 -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.ModuleInit.Startup::Init -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Opacity.Targets::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.PlatformCallback.EnvComparer::Compare -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.PlatformCallback.EnvToString::ToString -> System.Environment.GetEnvironmentVariable",
        // A2 S3's newobj case: the explicit static constructor of the type CreatesExplicitInit constructs.
        "EnvironmentProbe Call MechanismFixture.StaticInit.Constructed::.cctor -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.StaticInit.ExplicitInit::.cctor -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.StaticInit.FieldInit::.cctor -> System.Environment.GetEnvironmentVariable",
        // S3 review W3: the value type's static constructor.
        "EnvironmentProbe Call MechanismFixture.StaticInit.ValueInit::.cctor -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Transitive.Chain::Inner -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Virtual.EnvWorker::Run -> System.Environment.GetEnvironmentVariable",
        "FileSystem Call MechanismFixture.TypeTest.FileToucher::Touch -> System.IO.File.ReadAllText",
        "NativeInterop NativeImport MechanismFixture.Opacity.Native::getpid -> libc!getpid",
        "ProcessExecution Call MechanismFixture.Lambda.TaskRunCase.<>c::<RunsOnThreadPool>b__0_0 -> System.Diagnostics.Process.Start",
        "ProcessExecution Call MechanismFixture.Lambda.TaskRunCase.<>c::<RunsOnThreadPool>b__0_0 -> System.Diagnostics.Process.get_Id",
        "ReflectionInvocation Call MechanismFixture.Opacity.Reflective::InvokesByName -> System.Reflection.MethodBase.Invoke",
        // Reachability R1 S3's root-class and tier cases (MechanismFixture.Roots, measured 2026-11-05): one sink in each
        // interesting case, none in a twin; and both [UnmanagedCallersOnly] exports, the twin's included, carry the
        // scanner's NativeExport finding for the export itself (no call site).
        "EnvironmentProbe Call MechanismFixture.Roots.Host.EnvAnalyzer::.ctor -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Roots.Host.EnvTask::Execute -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Roots.Runtime.EnvFinalized::Finalize -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Roots.Runtime.Exports::ExportsEnv -> System.Environment.GetEnvironmentVariable",
        "NativeInterop NativeExport MechanismFixture.Roots.Runtime.Exports::ExportsEnv -> <managed>!ExportsEnv",
        "NativeInterop NativeExport MechanismFixture.Roots.Runtime.Exports::ExportsSafe -> <managed>!ExportsSafe",
        "EnvironmentProbe Call MechanismFixture.Roots.Tiers.MadeProbe::Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Roots.Tiers.UnmadeProbe::Run -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Roots.Visibility.EnvGauge::Read -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Roots.Visibility.EnvLabel::ToString -> System.Environment.GetEnvironmentVariable",
        "Network Call MechanismFixture.Roots.Visibility.NetResolver::MechanismFixture.Roots.Visibility.IResolver.Resolve -> System.Net.Dns.GetHostAddresses",
        "EnvironmentProbe Call MechanismFixture.Roots.Visibility.Unreached::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        // S3's parity call kinds (MechanismFixture.Parity): the fixture's first Construct and MethodPointerLoad findings.
        "FileSystem Construct MechanismFixture.Parity.Kinds::ConstructsFileInfo -> System.IO.FileInfo..ctor",
        "EnvironmentProbe MethodPointerLoad MechanismFixture.Parity.Kinds::LoadsEnvPointer -> System.Environment.GetEnvironmentVariable",
    ];

    private readonly MechanismFixtureFixture fixture;
}
