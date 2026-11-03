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
    public void Baseline_DirectCallers_CarryTheCapability_ExceptThePInvokeCaller()
    {
        // The spec's "the method that calls the sink directly has the capability" - holds for every row except the
        // P/Invoke one, whose capability the scanner attributes to the extern declaration instead.
        var exceptions = Measured.Where(m => !m.Value.DirectCaller).Select(m => m.Key);

        Assert.Equal(["Opacity.PInvokeCapability"], exceptions);
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
        // Not a call graph: the test-side view of DIRECT call/callvirt/newobj/ldftn sites (MechanismCallSites, both
        // assemblies, instantiations mapped to definitions, map-only classification). The rows it cannot satisfy are
        // exactly the ones that need what A2 adds beyond plain edges - CHA fan-out, the state-machine edge, the
        // TypeInitializer edge - or the reachability phase's extern classification. Measured.
        var needMore = MechanismGroundTruth.Paths
            .Where(p => p.Expect is Expectation.Present or Expectation.KnownImprecision)
            .Where(p => !WaypointMatcher.Evaluate(p, fixture.CallSites.Edges, MapCapability).Holds)
            .Select(p => p.Id)
            .OrderBy(id => id, StringComparer.Ordinal);

        Assert.Equal(
            new[]
            {
                "Async.Lambda",                       // state-machine edge
                "Async.LocalFunction",                // state-machine edge
                "Async.Method",                       // state-machine edge
                "Generics.ConstrainedCall",           // CHA: constrained callvirt IBaz.Baz -> A.Baz
                "Interface.CallsThroughInterface",    // CHA
                "Interface.ShouldHaveNoCapability",   // CHA
                "Iterator.Consumer",                  // CHA from System.Collections.IEnumerator.MoveNext
                "Iterator.ConsumerOfSafeSequence",    // CHA from System.Collections.IEnumerator.MoveNext
                "Iterator.Stub",                      // newobj closure => MoveNext edge
                "Opacity.PInvokeCapability",          // extern classification (Reachability)
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
        fixture.CallSites.Targets.TryGetValue(nodeId, out var key) &&
        CapabilityMap.Default.Classify(key) is { Class: CapabilityClass.Capability, Capability: { } capability }
            ? capability
            : null;

    private MechanismCallSites.OwnMethod Definition(string waypoint)
    {
        var pattern = new Regex(waypoint);
        return fixture.CallSites.Definitions.Values.Single(d => pattern.IsMatch(d.NodeId));
    }

    private static readonly string[] ExpectedFindings =
    [
        // S1's ExpressionTree pair: both bodies callvirt Expression`1.Compile (DynamicCodeLoading). There is NO
        // EnvironmentProbe finding for CompilesEnvTree - its only reference to the sink is an ldtoken, which the
        // scanner, like the A1 graph, does not treat as a call (row ExpressionTree.CompilesEnvTree, KnownGap).
        "DynamicCodeLoading Call MechanismFixture.ExpressionTree.Trees::CompilesEnvTree -> System.Linq.Expressions.Expression<System.Func<System.String>>.Compile",
        "DynamicCodeLoading Call MechanismFixture.ExpressionTree.Trees::CompilesSafeTree -> System.Linq.Expressions.Expression<System.Func<System.String>>.Compile",
        "DynamicCodeLoading Call MechanismFixture.Opacity.Dynamic::CallsDynamic -> Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember",
        "DynamicCodeLoading Call MechanismFixture.Opacity.Dynamic::CallsDynamic -> Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.Create",
        "EnvironmentProbe Call MechanismFixture.Async.AsyncLambdaCase.<>c.<<RunsAsyncLambda>b__0_0>d::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Async.AsyncLocalCase.<<CallsAsyncLocal>g__Read|0_0>d::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Async.AsyncProbes.<Probe>d__0::MoveNext -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.DelegateField.Holder::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.DelegateLocal.LocalDelegates::ReadsEnv -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Dependency.EnvReader::Read -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Direct.Probes::ReadsEnv -> System.Environment.GetEnvironmentVariable",
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
        "EnvironmentProbe Call MechanismFixture.StaticInit.ExplicitInit::.cctor -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.StaticInit.FieldInit::.cctor -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Transitive.Chain::Inner -> System.Environment.GetEnvironmentVariable",
        "EnvironmentProbe Call MechanismFixture.Virtual.EnvWorker::Run -> System.Environment.GetEnvironmentVariable",
        "FileSystem Call MechanismFixture.TypeTest.FileToucher::Touch -> System.IO.File.ReadAllText",
        "NativeInterop NativeImport MechanismFixture.Opacity.Native::getpid -> libc!getpid",
        "ProcessExecution Call MechanismFixture.Lambda.TaskRunCase.<>c::<RunsOnThreadPool>b__0_0 -> System.Diagnostics.Process.Start",
        "ProcessExecution Call MechanismFixture.Lambda.TaskRunCase.<>c::<RunsOnThreadPool>b__0_0 -> System.Diagnostics.Process.get_Id",
        "ReflectionInvocation Call MechanismFixture.Opacity.Reflective::InvokesByName -> System.Reflection.MethodBase.Invoke",
    ];

    private readonly MechanismFixtureFixture fixture;
}
