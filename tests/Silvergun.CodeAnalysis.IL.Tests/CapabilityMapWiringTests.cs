namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Capability-map <b>phase 2</b> at the shipping seam (<c>docs/agent/tasks/capability-map.md</c>):
/// <c>CapabilityAnalysis.Match</c> now consults <c>CapabilityMap.Default.Classify(...)</c> keyed on
/// <c>CanonicalName.ClassificationKey</c>, replacing the legacy <c>StartsWith</c> scan over
/// <see cref="CapabilityAnalysis.Catalog"/>. Every fact here goes through a <b>real scan of a real assembly</b>
/// rather than calling <c>Classify</c> directly — <see cref="CapabilityMapDataTests"/> already covers the map as a
/// pure function, and what was never covered is that the scan actually reaches it and builds the key the way
/// ADR-0021 requires.
/// <para>
/// The subject is the net10.0 test assembly itself, loaded through the self-load pattern
/// (<see cref="Net10OnlyGapOps"/> uses the same one), so the shapes in <see cref="MapWiringOps"/> and
/// <see cref="Microsoft.Win32.Registry"/> can be added without moving the exact measured baselines the shared
/// netstandard2.0 fixture and the TFM matrix fixture carry.
/// </para>
/// </summary>
public sealed class CapabilityMapWiringTests : IClassFixture<AssemblyAnalyzerFixture>
{
    #region Constructors
    public CapabilityMapWiringTests(AssemblyAnalyzerFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the matcher is the map, not the catalog
    /// <summary>
    /// The map is live: <c>System.GC.Collect</c>/<c>CollectionCount</c> classify as
    /// <see cref="Capability.RuntimeControl"/> even though <c>System.GC</c> appears nowhere in
    /// <see cref="CapabilityAnalysis.Catalog"/> — asserted, so this is a statement about the map being consulted
    /// and not about the catalog having quietly grown an entry.
    /// </summary>
    [Fact]
    public void Analyze_AMapOnlyApi_ProducesAFindingTheLegacyCatalogCouldNotHaveProduced()
    {
        Assert.DoesNotContain(
            CapabilityAnalysis.Catalog,
            api => "System.GC.Collect".StartsWith(api.TypePrefix, StringComparison.Ordinal));

        Assert.Equal(
            ["RuntimeControl,Call,System.GC.Collect", "RuntimeControl,Call,System.GC.CollectionCount"],
            Rendered(nameof(MapWiringOps.TriggersGarbageCollection)));
    }

    /// <summary>
    /// The other direction, and the head of the phase-2 known-delta table: <c>new FileNotFoundException(...)</c>
    /// produced a <see cref="Capability.FileSystem"/> finding under the legacy matcher, because
    /// <c>"System.IO.FileNotFoundException".StartsWith("System.IO.File")</c> — asserted here, so the near-miss is
    /// real — and produces none under the map, which has no entry for the exception type. An exception type is
    /// not a filesystem capability; the loss is a precision fix, not a regression.
    /// </summary>
    [Fact]
    public void Analyze_AnApiOnlyTheLegacyPrefixMatched_ProducesNoFinding()
    {
        Assert.Contains(
            CapabilityAnalysis.Catalog,
            api => api.Capability == Capability.FileSystem &&
                   FileNotFoundExceptionCtor.StartsWith(api.TypePrefix, StringComparison.Ordinal));

        Assert.Empty(Rendered(nameof(MapWiringOps.CreatesFileNotFoundException)));

        // ...and nowhere else in the assembly either, so this is not merely "that one caller was not scanned".
        Assert.DoesNotContain(SelfFindings, f => f.CalledApi == FileNotFoundExceptionCtor);
    }
    #endregion

    #region Methods — architect decision 2: a state machine nested under a catalogued type
    /// <summary>
    /// DECISION 2, the negative half: the <c>newobj</c> of a compiler-generated state machine nested inside a
    /// catalogued type produces <b>no</b> finding. The legacy prefix matcher reached into nested compiler types
    /// (that is how CoreLib's <c>System.IO.File.&lt;IterateFileLinesAsync&gt;d__124..ctor</c> was reported as
    /// <see cref="Capability.FileSystem"/>); the map's exact-type form does not, because a type entry covers a
    /// type's own members and never its nested types. The near-miss is asserted rather than described: the state
    /// machine's rendered name really does prefix-match the catalogued name.
    /// </summary>
    [Fact]
    public void Analyze_StateMachineNestedUnderACataloguedType_IsNotFlaggedViaItsConstructor()
    {
        var stateMachine = StateMachineTypeName();

        // The near-miss is real: the legacy matcher WOULD have classified this declaring type.
        Assert.StartsWith(CataloguedType, stateMachine, StringComparison.Ordinal);
        Assert.Contains(
            CapabilityAnalysis.Catalog,
            api => api.Capability == Capability.Registry && stateMachine.StartsWith(api.TypePrefix, StringComparison.Ordinal));

        // ...and the map does not: the declaring type is the NESTED one, which carries no entry.
        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify($"{stateMachine}..ctor"));

        // At the shipping seam: the kickoff method's only call site is that .ctor, and it yields nothing.
        // CS0436: the fixture type deliberately shadows the real Microsoft.Win32.Registry — see
        // CataloguedTypeStateMachineOps.cs. The compiler binds to the fixture, which is what this needs.
#pragma warning disable CS0436
        Assert.DoesNotContain(SelfFindings, f => f.CallerMethod == nameof(Microsoft.Win32.Registry.IterateLines));
#pragma warning restore CS0436
        Assert.DoesNotContain(SelfFindings, f => f.CalledApi == $"{stateMachine}..ctor");
    }

    /// <summary>
    /// DECISION 2, the positive half — the reason accepting the loss above is safe: the <em>real</em> catalogued
    /// call inside the state machine's <c>MoveNext</c> is a separate call site and is still detected.
    /// </summary>
    [Fact]
    public void Analyze_RealCallInsideAStateMachineMoveNext_IsStillDetected()
    {
        var finding = Assert.Single(
            SelfFindings,
            f => f.CallerType == StateMachineTypeName() && f.CalledApi == "System.IO.File.ReadLines");

        Assert.Equal(Capability.FileSystem, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("MoveNext", finding.CallerMethod);
    }

    /// <summary>
    /// The control that stops the decision-2 pin from passing vacuously: an ordinary call to a member of the same
    /// catalogued type DOES classify. Without it, "the nested state machine produces no finding" would be equally
    /// satisfied by the catalogued name matching nothing at all in this assembly.
    /// </summary>
    [Fact]
    public void Analyze_AnOrdinaryMemberOfTheSameCataloguedType_StillClassifies()
    {
        Assert.Equal(
            [$"Registry,Call,{CataloguedType}.ReadsValue"],
            Rendered(nameof(MapWiringOps.CallsCataloguedTypeMember)));
    }
    #endregion

    #region Methods — carve-out precedence, end to end
    /// <summary>
    /// The carve-outs behind the 12 changed-capability call sites of the phase-2 measurement, asserted through a
    /// real scan rather than through <c>Classify</c>: a <c>Ns.Type.Method</c> entry beats the <c>Ns.Type</c> entry
    /// it is carved out of, and the sibling that is <em>not</em> carved out still reaches the type entry. Both
    /// halves of each pair, because a re-widened carve-out and a deleted type entry look identical from one side.
    /// </summary>
    [Theory]
    [InlineData(nameof(MapWiringOps.ProbesCurrentDirectory), "EnvironmentProbe,Call,System.IO.Directory.GetCurrentDirectory")]
    [InlineData(nameof(MapWiringOps.ChecksDirectoryExists), "FileSystem,Call,System.IO.Directory.Exists")]
    [InlineData(nameof(MapWiringOps.ProbesCurrentProcess), "EnvironmentProbe,Call,System.Diagnostics.Process.GetCurrentProcess")]
    [InlineData(nameof(MapWiringOps.StartsProcess), "ProcessExecution,Call,System.Diagnostics.Process.Start")]
    public void Analyze_CarveOutAndItsSibling_TakeTheirOwnSidesOfTheTypeEntry(string caller, string expected)
    {
        Assert.Equal([expected], Rendered(caller));
    }
    #endregion

    #region Methods — safe / unspecified / unanalyzed produce no finding
    /// <summary>
    /// Only <c>CapabilityClass.Capability</c> produces an <c>ApiCallFinding</c> in this task. A <c>safe</c> key
    /// (<c>System.IO.Path.Combine</c>) and an <c>unspecified</c> one
    /// (<c>System.Text.Json.JsonSerializer.Serialize</c>) are both classified by the map — asserted, so this is
    /// not "the map never saw them" — and neither yields a finding.
    /// </summary>
    [Theory]
    [InlineData(nameof(MapWiringOps.CombinesPaths), "System.IO.Path.Combine", CapabilityClass.Safe)]
    [InlineData(nameof(MapWiringOps.SerializesJson), "System.Text.Json.JsonSerializer.Serialize", CapabilityClass.Unspecified)]
    public void Analyze_ANonSinkClassification_ProducesNoFinding(string caller, string key, CapabilityClass expected)
    {
        Assert.Equal(expected, CapabilityMap.Default.Classify(key).Class);

        Assert.Empty(Rendered(caller));
    }

    /// <summary>
    /// The positive control for the pair above, and the second half of the <c>safe System.IO.Path</c> carve-out:
    /// <c>Path.GetTempFileName</c> creates a file, so its method entry beats the allowlisted type and it DOES
    /// produce a <see cref="Capability.FileSystem"/> finding. Without this, "safe yields nothing" would be
    /// satisfied by a scan that yields nothing at all.
    /// </summary>
    [Fact]
    public void Analyze_TheCarveOutFromAnAllowlistedType_StillProducesAFinding()
    {
        Assert.Equal(
            ["FileSystem,Call,System.IO.Path.GetTempFileName"],
            Rendered(nameof(MapWiringOps.CreatesTempFile)));
    }

    /// <summary>
    /// <c>unanalyzed</c> is deliberately NOT covered through a scan, and that is recorded here rather than left as
    /// a silent hole: the built-in map ships <b>zero</b> <c>unanalyzed</c> entries, and <c>Match</c> consults
    /// <c>CapabilityMap.Default</c> only (there is no override seam yet — it is an out-of-scope follow-up), so no
    /// assembly can reach that class through a real scan. The directive's parsing and classification are covered
    /// as a pure function in <see cref="CapabilityMapTests"/>. If the built-in map ever gains an
    /// <c>unanalyzed</c> entry this fails, and a scan-level assertion becomes both possible and required.
    /// </summary>
    [Fact]
    public void Default_ShipsNoUnanalyzedEntries_SoNoScanCanReachThatClass()
    {
        Assert.Equal(0, CapabilityMap.Default.Stats.UnanalyzedEntries);
    }
    #endregion

    #region Methods — CalledApi rendering is unchanged and is NOT the key
    /// <summary>
    /// <c>ApiCallFinding.CalledApi</c> keeps its pre-phase-2 rendering — <c>AssemblyAnalyzer.TypeName</c> (CCI's
    /// <c>NameFormattingOptions.None</c>) plus the method name — and is a display/JSON field, not the
    /// classification key. The generic case is the one that proves the two are different strings: the callee's
    /// declaring type renders with its argument list inline, while the key the map matched has all generic
    /// decoration stripped. Both are asserted, on the same call site, so a future "tidy-up" that made
    /// <c>CalledApi</c> the key would fail here rather than silently changing report back-compat.
    /// </summary>
    [Fact]
    public void Analyze_CalledApiOfAGenericDeclaringType_RendersArgumentsInlineAndIsNotTheClassificationKey()
    {
        var finding = Assert.Single(
            FixtureFindings,
            f => f.CallerMethod == nameof(Fixture.DynamicCodeOps.CompilesExpression));

        Assert.Equal(Capability.DynamicCodeLoading, finding.Capability);
        Assert.Equal(GenericCompileApi, finding.CalledApi);

        // The rendering is NOT the key: it is not what the map matched, and the map does not match it.
        Assert.NotEqual(GenericCompileKey, finding.CalledApi);
        Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify(finding.CalledApi));
        Assert.Equal(
            new CapabilityVerdict(CapabilityClass.Capability, Capability.DynamicCodeLoading),
            CapabilityMap.Default.Classify(GenericCompileKey));
    }
    #endregion

    #region Methods — the metadata seam is a different seam and did not move
    /// <summary>
    /// <c>ScanInteropDeclarations</c> never consults the map, so the phase-2 switch could not have moved it. Stated
    /// as a mechanism rather than as a count: every interop finding's <c>CalledApi</c> is a
    /// <c>module!entryPoint</c> string that classifies as <see cref="CapabilityVerdict.None"/>, yet each finding
    /// carries <see cref="Capability.NativeInterop"/> — so the capability cannot have come from the map. The
    /// measured corpus-wide totals (625 <c>NativeImport</c> + 30 <c>NativeExport</c> = 655, byte-identical in
    /// <c>capmap-before.tsv</c> and <c>capmap-after.tsv</c>) are the evidence; this is the part of it that is
    /// reproducible without a NuGet-cached runtime package.
    /// </summary>
    [Fact]
    public void Analyze_InteropSeamFindings_CarryNativeInteropWithoutTheMapClassifyingThem()
    {
        var interop = FixtureFindings
            .Where(f => f.Kind is ApiCallKind.NativeImport or ApiCallKind.NativeExport)
            .ToArray();

        Assert.NotEmpty(interop);
        Assert.All(interop, f =>
        {
            Assert.Equal(Capability.NativeInterop, f.Capability);
            Assert.Equal(CapabilityVerdict.None, CapabilityMap.Default.Classify(f.CalledApi));
        });
    }

    /// <summary>
    /// The same seam pinned by its <em>derivation</em> rather than by a literal, so a detection change in the map
    /// cannot move it and a fixture change cannot make it stale: the number of <c>NativeImport</c> findings equals
    /// the number of <c>pinvokeimpl</c> declarations CCI reports for the assembly, counted independently of
    /// <c>CapabilityAnalysis</c>.
    /// </summary>
    [Fact]
    public void Analyze_NativeImportCount_EqualsThePlatformInvokeDeclarationCount()
    {
        var declarations = fixture.Assembly.Module.GetAllTypes()
            .SelectMany(t => t.Methods)
            .Count(m => m.IsPlatformInvoke);

        Assert.True(declarations > 0, "The fixture assembly declares no P/Invoke, so this assertion is vacuous.");
        Assert.Equal(declarations, FixtureFindings.Count(f => f.Kind == ApiCallKind.NativeImport));
    }
    #endregion

    #region Methods — helpers
    // The findings of one MapWiringOps method, rendered as "Capability,Kind,CalledApi" and ordered, so a failure
    // prints the whole disagreement instead of "expected 1, got 2".
    private string[] Rendered(string callerMethod) =>
        [.. SelfFindings
            .Where(f => f.CallerType == MapWiringOpsType && f.CallerMethod == callerMethod)
            .Select(f => $"{f.Capability},{f.Kind},{f.CalledApi}")
            .Order(StringComparer.Ordinal)];

    // The rendered name of the compiler-generated iterator state machine nested under the catalogued type, read
    // from the scan rather than hardcoded: its "d__N" suffix is a Roslyn implementation detail, and pinning the
    // literal would make these tests fail on a compiler change for no reason connected to what they assert.
    private string StateMachineTypeName()
    {
        var nested = SelfFindings
            .Select(f => f.CallerType)
            .Where(t => t.StartsWith(CataloguedType + ".", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return Assert.Single(nested);
    }

    // The net10.0 test assembly itself, scanned once per test class. Holds MapWiringOps and Microsoft.Win32.Registry.
    private IReadOnlyList<ApiCallFinding> SelfFindings => selfFindings ??= Findings(typeof(MapWiringOps).Assembly.Location);

    // The shared netstandard2.0 fixture assembly, for the pre-existing generic and interop shapes.
    private IReadOnlyList<ApiCallFinding> FixtureFindings => fixtureFindings ??= Analyze(fixture.Assembly);

    private static IReadOnlyList<ApiCallFinding> Findings(string path)
    {
        var create = AssemblyAnalyzer.Load(path);
        Assert.True(create.IsSuccess, create.Message);
        using var cci = create.Value;

        return Analyze(cci);
    }

    private static IReadOnlyList<ApiCallFinding> Analyze(AssemblyAnalyzer assembly)
    {
        var result = new CapabilityAnalysis(assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value.Findings;
    }
    #endregion

    #region Fields
    private const string MapWiringOpsType = "Silvergun.CodeAnalysis.IL.Tests.MapWiringOps";
    private const string CataloguedType = "Microsoft.Win32.Registry";
    private const string FileNotFoundExceptionCtor = "System.IO.FileNotFoundException..ctor";

    /// <summary>
    /// The <c>CalledApi</c> of <c>Expression&lt;Func&lt;int&gt;&gt;.Compile()</c>: the closed generic declaring
    /// type with its argument list rendered inline and no arity suffix, per the measured
    /// <c>AssemblyAnalyzer.TypeName</c> contract (<see cref="CapabilityMatcherSeamTests"/>).
    /// </summary>
    private const string GenericCompileApi = "System.Linq.Expressions.Expression<System.Func<System.Int32>>.Compile";

    /// <summary>The classification key for the same call site: all generic decoration stripped.</summary>
    private const string GenericCompileKey = "System.Linq.Expressions.Expression.Compile";

    private readonly AssemblyAnalyzerFixture fixture;
    private IReadOnlyList<ApiCallFinding>? selfFindings;
    private IReadOnlyList<ApiCallFinding>? fixtureFindings;
    #endregion
}
