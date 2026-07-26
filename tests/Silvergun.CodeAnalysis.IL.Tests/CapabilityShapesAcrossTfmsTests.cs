namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

using Xunit;

/// <summary>
/// Phase 2 of <c>docs/agent/tasks/capability-shapes-across-tfms.md</c>: assertions over the capability call
/// sites in <see cref="CapabilityShapes"/>, one representative per <see cref="Capability"/> value, present on
/// every matrix flavour where the underlying API exists. Reuses <see cref="TargetFrameworkMatrixFixture"/> — the
/// same loaded-and-analyzed reports <see cref="TargetFrameworkMatrixTests"/> uses — rather than analyzing again.
/// <para>
/// <b>Item 0 (spec) — the pre-existing cross-TFM subset invariant already extends to capability shapes, for
/// free, with no change needed in <see cref="TargetFrameworkMatrixTests"/>.</b> That invariant
/// (<c>Analyze_UnguardedDeclarations_ProduceIdenticalFindingsOnEveryTargetFramework</c> and
/// <c>Analyze_Net472Findings_AreExactlyTheUnguardedSubsetOfTheModernFindings</c>) compares the full
/// <c>(Kind, CallerType, CallerMethod, CalledApi)</c> tuple over <em>every</em> finding in the assembly, keyed off
/// <c>TargetFrameworkMatrixTests.GuardedDeclarations</c> — a list of method names known to be <c>#if</c>-guarded.
/// <see cref="CapabilityShapes"/>' 9 unguarded methods are not in that list, so their findings are already
/// classified "unguarded" and were already required to be identical across every flavour before this file
/// existed; the full suite run confirms both tests still pass unmodified with <see cref="CapabilityShapes"/> in
/// the assembly. See <see cref="Analyze_CapabilityShapesFindings_AreNonEmptyAndAlreadyCoveredByTheExistingUnguardedInvariant"/>
/// for the explicit, scoped restatement of that fact, and its remarks for the one forward-looking risk it does
/// NOT yet cover.
/// </para>
/// <para>
/// <b>What <c>CalledApi</c> looks like across the matrix for a shared shape (spec's "be careful" note).</b>
/// Measured directly (see <see cref="Analyze_SharedCapabilityShapes_ProduceIdenticalFindingsAcrossEveryTargetFramework"/>):
/// <c>CalledApi</c> is <c>ApiCallFinding</c>'s <c>"{AssemblyAnalyzer.TypeName(callee.ContainingType)}.{callee.Name.Value}"</c>
/// (<see cref="Capabilities"/>' <c>CalledApi</c>/<c>NativeTarget</c> helpers), which carries <b>no assembly
/// qualification at all</b> — just the CLR type's full name and member name (e.g.
/// <c>"System.IO.File.ReadAllBytes"</c>). Unlike the interop matrix's native targets (which are genuinely
/// TFM-invariant strings from PE metadata), a shared capability shape's <c>CalledApi</c> could in principle
/// differ across TFMs if a BCL type's full name changed between <c>[mscorlib]</c> and <c>[System.Runtime]</c> —
/// it does not here, because <c>System.IO.File</c>, <c>System.Net.WebClient</c>, etc. keep the same namespace and
/// simple name on both reference assemblies; only the owning assembly differs, and that is exactly the part
/// <c>CalledApi</c> never renders. So the genuinely-invariant property asserted below is the full
/// <c>(Capability, Kind, CallerMethod, CalledApi)</c> tuple, unchanged — no normalization needed, because there
/// was nothing assembly-qualified to normalize away in the first place. That absence of assembly-qualification
/// is itself worth flagging: two BCL types of the same full name in different reference assemblies are treated
/// as the same <c>CalledApi</c>, which is correct for this matrix (same source, same logical API) but would be
/// worth revisiting the day two genuinely different APIs collide on a full name.
/// </para>
/// </summary>
public sealed class CapabilityShapesAcrossTfmsTests : IClassFixture<TargetFrameworkMatrixFixture>
{
    #region Constructors
    public CapabilityShapesAcrossTfmsTests(TargetFrameworkMatrixFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Item 0 (spec) — explicit, scoped confirmation that the existing invariant already covers this file.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// <see cref="CapabilityShapes"/> really does contribute findings on every discovered flavour (not vacuous),
    /// and — as the class remarks document — every one of those findings is already covered by the pre-existing
    /// <c>TargetFrameworkMatrixTests</c> cross-TFM subset invariant with no change needed there. The one thing
    /// that invariant does NOT yet police: if a future change makes any of the three TFM-divergent guarded shapes
    /// (<c>CreatesNetDataContractSerializer</c>, <c>GetsDefaultAssemblyLoadContext</c>, <c>SizeOfInt32</c>) start
    /// producing a finding (see the known-gap fact below — today none of them do), those method names would need
    /// adding to <c>TargetFrameworkMatrixTests.GuardedDeclarations</c>, or the invariant would wrongly demand
    /// net472 and net10.0 agree on a shape that is deliberately framework-divergent.
    /// </summary>
    [Fact]
    public void Analyze_CapabilityShapesFindings_AreNonEmptyAndAlreadyCoveredByTheExistingUnguardedInvariant()
    {
        Assert.All(
            MatrixFixtureAssemblies.ByTargetFramework.Keys,
            targetFramework => Assert.NotEmpty(ShapesFindings(targetFramework)));
    }

    // ---------------------------------------------------------------------------------------------------
    // Item 1 (spec) — per-TFM capability presence, driven from MatrixFixtureAssemblies.ByTargetFramework.
    //
    // Scoped to the 8 representative shapes CapabilityAnalysis actually detects TODAY. RuntimeControl
    // (TriggersGarbageCollection / System.GC.Collect) is deliberately excluded here — see the known-gap fact
    // below for why, and why asserting its detection would be asserting something false rather than reporting
    // it honestly.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// Every capability the legacy <see cref="CapabilityAnalysis.Catalog"/> can actually reach today is detected,
    /// with the expected <see cref="Capability"/>, <see cref="ApiCallKind"/> and <c>CalledApi</c>, on every
    /// discovered target framework — never a hardcoded TFM list.
    /// </summary>
    [Theory]
    [MemberData(nameof(TargetFrameworkMatrixTests.TargetFrameworks), MemberType = typeof(TargetFrameworkMatrixTests))]
    public void Analyze_EveryDetectedCapabilityShape_IsPresentWithItsExpectedShapeOnEveryTargetFramework(string targetFramework)
    {
        var findings = ShapesFindings(targetFramework);

        Assert.All(DetectedSharedShapes, shape =>
        {
            var finding = Assert.Single(findings, f => f.CallerMethod == shape.CallerMethod);

            Assert.Equal(shape.Capability, finding.Capability);
            Assert.Equal(shape.Kind, finding.Kind);
            Assert.Equal(shape.CalledApi, finding.CalledApi);
        });
    }

    // ---------------------------------------------------------------------------------------------------
    // Item 2 (spec) — the headline property: same source ⇒ same capability findings, regardless of TFM.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// <b>Same source ⇒ same capability findings, regardless of target framework.</b> The 9 unguarded
    /// <see cref="CapabilityShapes"/> methods — the ones every flavour of the matrix actually compiles — produce
    /// a byte-identical <c>(Capability, Kind, CallerMethod, CalledApi)</c> set on every discovered flavour. The
    /// three TFM-divergent guarded methods are excluded by name (mirroring
    /// <c>TargetFrameworkMatrixTests.GuardedDeclarations</c>'s own convention), so a real divergence there is
    /// never mistaken for a failure of this test.
    /// </summary>
    [Fact]
    public void Analyze_SharedCapabilityShapes_ProduceIdenticalFindingsAcrossEveryTargetFramework()
    {
        var byTargetFramework = fixture.Reports.Keys.ToDictionary(
            targetFramework => targetFramework,
            targetFramework => ShapesFindings(targetFramework)
                .Where(f => !GuardedShapeMethods.Contains(f.CallerMethod, StringComparer.Ordinal))
                .Select(Render)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            StringComparer.Ordinal);

        // Not vacuous: the shared shapes really are present on every flavour.
        Assert.All(byTargetFramework, entry => Assert.NotEmpty(entry.Value));

        var reference = byTargetFramework.Values.First();
        Assert.All(byTargetFramework, entry => Assert.Equal(reference, entry.Value));
    }

    // ---------------------------------------------------------------------------------------------------
    // Items 3 & 4 (spec) — the TFM-divergent shapes: IL-level shape existence, proven directly from CCI
    // rather than assumed from the source's #if guard.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// <see cref="CapabilityShapes.CreatesNetDataContractSerializer"/> — guarded to <c>#if NETFRAMEWORK</c> —
    /// really does compile into the net472 flavour's IL and really is absent from net10.0's, proven from CCI
    /// directly rather than assumed from the source guard.
    /// </summary>
    [Fact]
    public void Analyze_NetDataContractSerializerShape_ExistsOnlyInNet472Il()
    {
        Assert.True(
            fixture.HasBodiedMethod(Legacy, ShapesType, "CreatesNetDataContractSerializer"),
            "CreatesNetDataContractSerializer must compile on net472 — the Framework-only deserialization-gadget " +
            "vector this task exists to prove is detectable on a real net472 assembly.");
        Assert.False(
            fixture.HasBodiedMethod(Modern, ShapesType, "CreatesNetDataContractSerializer"),
            "NetDataContractSerializer never shipped outside .NET Framework, so its shape must not exist in the net10.0 build.");
    }

    /// <summary>
    /// <see cref="CapabilityShapes.GetsDefaultAssemblyLoadContext"/> and <see cref="CapabilityShapes.SizeOfInt32"/>
    /// — both guarded to <c>#if NET5_0_OR_GREATER</c> — really do compile into the net10.0 flavour's IL and
    /// really are absent from net472's, proven from CCI directly.
    /// </summary>
    [Theory]
    [InlineData("GetsDefaultAssemblyLoadContext")]
    [InlineData("SizeOfInt32")]
    public void Analyze_ModernOnlyShapes_ExistOnlyInNet10Il(string methodName)
    {
        Assert.True(
            fixture.HasBodiedMethod(Modern, ShapesType, methodName),
            $"{methodName} must compile on net10.0 — it is guarded to NET5_0_OR_GREATER.");
        Assert.False(
            fixture.HasBodiedMethod(Legacy, ShapesType, methodName),
            $"{methodName} must not exist on net472: net472 has no managed AssemblyLoadContext abstraction, and " +
            $"System.Runtime.CompilerServices.Unsafe would need the separate NuGet package the no-new-packages " +
            $"guardrail forbids.");
    }

    // ---------------------------------------------------------------------------------------------------
    // KNOWN GAP — not introduced by this task; pre-existing and tracked in docs/agent/tasks/capability-map.md.
    //
    // CapabilityAnalysis today matches call sites ONLY against the legacy 32-entry Catalog
    // (CapabilityAnalysis.Catalog) — it does not yet consult capabilities.cm / CapabilityMap
    // (docs/agent/tasks/capability-map.md, "Phase 2 Ready", not started as of this writing). The Catalog has NO
    // entry at all for System.GC, System.Runtime.Serialization.NetDataContractSerializer,
    // System.Runtime.Loader.AssemblyLoadContext, or System.Runtime.CompilerServices.Unsafe. So — even though every
    // one of these shapes genuinely exists in the compiled IL of the flavour(s) it targets (proven above,
    // independent of detection) — NONE of TriggersGarbageCollection (RuntimeControl), CreatesNetDataContractSerializer
    // (DynamicCodeLoading), GetsDefaultAssemblyLoadContext (RuntimeControl) or SizeOfInt32 (UnsafeMemory) produces
    // a CapabilityAnalysis finding TODAY, on either target framework.
    //
    // This directly affects two of the spec's stated goals: item 1's claim that "every capability in the table is
    // detected" does not hold for RuntimeControl, and items 3/4's claim that NetDataContractSerializer/
    // AssemblyLoadContext/Unsafe are "detected" (vs. merely present in IL) does not hold either — asserting
    // detection here would assert something false. This fact pins today's true (negative) behaviour instead, as a
    // canary: it must start FAILING — and be revisited, replaced by the positive assertions the original spec
    // items describe — the day capability-map.md Phase 2 wires CapabilityAnalysis onto the map.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// Pins today's actual (negative) capability-detection behaviour for the four map-only shapes, on every
    /// discovered target framework, so a reader — and this suite — knows exactly which findings are still missing
    /// and why, rather than silently assuming the spec's aspirational claim already holds.
    /// </summary>
    [Fact]
    public void Analyze_MapOnlyCapabilities_AreNotYetDetectedByTheLegacyCatalog_KnownGapPendingCapabilityMapPhase2()
    {
        Assert.All(MatrixFixtureAssemblies.ByTargetFramework.Keys, targetFramework =>
        {
            var findings = ShapesFindings(targetFramework);

            Assert.DoesNotContain(findings, f => f.CallerMethod == "TriggersGarbageCollection");
            Assert.DoesNotContain(findings, f => f.CallerMethod == "CreatesNetDataContractSerializer");
            Assert.DoesNotContain(findings, f => f.CallerMethod == "GetsDefaultAssemblyLoadContext");
            Assert.DoesNotContain(findings, f => f.CallerMethod == "SizeOfInt32");
        });
    }

    private ApiCallFinding[] ShapesFindings(string targetFramework) =>
        fixture.Report(targetFramework).Findings.Where(f => f.CallerType == ShapesType).ToArray();

    private static string Render(ApiCallFinding finding) =>
        $"{finding.Capability},{finding.Kind},{finding.CallerMethod},{finding.CalledApi}";
    #endregion

    #region Fields
    private const string Legacy = "net472";
    private const string Modern = "net10.0";
    private const string ShapesType = TargetFrameworkMatrixFixture.FixtureNamespace + "CapabilityShapes";

    /// <summary>
    /// The three <c>#if</c>-guarded <see cref="CapabilityShapes"/> methods, named the same way
    /// <c>TargetFrameworkMatrixTests.GuardedDeclarations</c> names its own guarded methods — by method name, not
    /// by TFM, since "guarded" is a fact about the source, not about which flavour happens to be running.
    /// </summary>
    private static readonly string[] GuardedShapeMethods =
    [
        "CreatesNetDataContractSerializer",     // #if NETFRAMEWORK
        "GetsDefaultAssemblyLoadContext",       // #if NET5_0_OR_GREATER
        "SizeOfInt32",                          // #if NET5_0_OR_GREATER
    ];

    /// <summary>
    /// The representative shapes <see cref="CapabilityAnalysis.Catalog"/> actually reaches today, measured
    /// against the fixture rather than assumed from <c>capabilities.cm</c>. <c>RuntimeControl</c>
    /// (<c>TriggersGarbageCollection</c> / <c>System.GC.Collect</c>) is deliberately absent — see the
    /// known-gap fact.
    /// </summary>
    private static readonly CapabilityShape[] DetectedSharedShapes =
    [
        new(Capability.FileSystem, "ReadsFileBytes", ApiCallKind.Call, "System.IO.File.ReadAllBytes"),
        new(Capability.Network, "CreatesWebClient", ApiCallKind.Construct, "System.Net.WebClient..ctor"),
        new(Capability.ProcessExecution, "StartsProcess", ApiCallKind.Call, "System.Diagnostics.Process.Start"),
        new(Capability.EnvironmentProbe, "ProbesEnvironment", ApiCallKind.Call, "System.Environment.GetEnvironmentVariable"),
        new(Capability.DynamicCodeLoading, "LoadsAssembly", ApiCallKind.Call, "System.Reflection.Assembly.Load"),
        new(Capability.ReflectionInvocation, "InvokesViaReflection", ApiCallKind.Call, "System.Reflection.MethodBase.Invoke"),
        new(Capability.NativeInterop, "AllocatesUnmanagedMemory", ApiCallKind.Call, "System.Runtime.InteropServices.Marshal.AllocHGlobal"),
        new(Capability.Cryptography, "CreatesAes", ApiCallKind.Call, "System.Security.Cryptography.Aes.Create"),
    ];

    private readonly TargetFrameworkMatrixFixture fixture;
    #endregion

    #region Child types
    private sealed record CapabilityShape(Capability Capability, string CallerMethod, ApiCallKind Kind, string CalledApi);
    #endregion
}
