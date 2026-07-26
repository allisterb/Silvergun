namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

using Xunit;

/// <summary>
/// The metadata/attribute detection seam (<c>CapabilityAnalysis.ScanInteropDeclarations</c>) over the
/// <b>net10.0</b> fixture: modern P/Invoke (<c>[LibraryImport]</c>), the <c>[DllImport]</c> control, and reverse
/// P/Invoke (<c>[UnmanagedCallersOnly]</c>). None of these declarations is ever called, so nothing here can be
/// found through a call site — only through metadata.
/// <para>
/// This is the first coverage in the repo of current Roslyn output; every other IL analysis test reads the
/// netstandard2.0 fixture, which cannot express <c>[LibraryImport]</c> (net7+) or <c>[UnmanagedCallersOnly]</c>
/// (net5+) at all.
/// </para>
/// </summary>
public sealed class ModernInteropDeclarationTests : IClassFixture<ModernInteropFixture>
{
    #region Constructors
    public ModernInteropDeclarationTests(ModernInteropFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // [LibraryImport] — the modern, source-generated P/Invoke.
    //
    // It surfaces through the SAME pinvokeimpl seam as [DllImport], because the generator always emits the
    // native declaration as a pinvokeimpl method. But it does so along TWO different codegen paths, and which
    // one is taken decides what CallerMethod reads:
    //
    //   * blittable signature  -> DIRECT FORWARDER: the user's own partial method IS the pinvokeimpl, so
    //                             attribution lands on the name the developer wrote (1a).
    //   * needs marshalling    -> STUB: the declared method gets a real body that marshals arguments and calls
    //                             a nested local function which carries the pinvokeimpl, so attribution lands
    //                             on a compiler-mangled name (1b).
    //
    // Both are covered deliberately: a fixture with only blittable signatures would hide the mangled shape, and
    // a real package will contain both.
    // ---------------------------------------------------------------------------------------------------

    // 1a — blittable signature, direct-forwarder path: clean attribution to the declared method name, with the
    // native target taken from the attribute's EntryPoint rather than the managed name.
    [Fact]
    public void Analyze_LibraryImportWithBlittableSignature_SurfacesNativeImportUnderTheDeclaredName()
    {
        var report = Analyze();

        // The three P/Invoke declarations are `internal` (as real ones usually are), so they are named by
        // literal here rather than by nameof — which is also the point: only metadata sees them.
        var finding = Assert.Single(report.Findings, f => f.CallerMethod == "CurrentProcessId");

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(ApiCallKind.NativeImport, finding.Kind);
        Assert.Equal(OpsType, finding.CallerType);
        Assert.Equal("kernel32.dll!GetCurrentProcessId", finding.CalledApi);
    }

    // 1b — a signature needing marshalling takes the stub path, so the pinvokeimpl lives on the generated local
    // function and CallerMethod is its mangled name. CalledApi is still the correct native target, which is what
    // detection turns on; the mangled caller is a reporting-quality wart, recorded rather than papered over.
    //
    // The findings are filtered to the seam kind because the generated stub BODY calls Utf8StringMarshaller
    // helpers, and those are ordinary Call findings under the declared name "DebugMessage".
    [Fact]
    public void Analyze_LibraryImportRequiringMarshalling_SurfacesNativeImportUnderTheGeneratedStubName()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f =>
            f.Kind == ApiCallKind.NativeImport &&
            f.CalledApi == "kernel32.dll!OutputDebugStringA");

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(OpsType, finding.CallerType);

        // Prefix only: the full name is "<DebugMessage>g____PInvoke|<declOrdinal>_<localOrdinal>", and the
        // ordinals shift whenever a member is reordered or inserted in the fixture. The load-bearing part is
        // that the mangled name still identifies the declaring method.
        Assert.StartsWith("<DebugMessage>g__", finding.CallerMethod, StringComparison.Ordinal);
    }

    // 1c — control: the classic [DllImport] extern on a modern TFM behaves exactly as it does on netstandard2.0,
    // so the two attributes are not distinguished by the seam and neither shadows the other.
    [Fact]
    public void Analyze_DllImportOnModernTarget_SurfacesNativeImportUnderTheDeclaredName()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f => f.CallerMethod == "CurrentThreadId");

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(ApiCallKind.NativeImport, finding.Kind);
        Assert.Equal(OpsType, finding.CallerType);
        Assert.Equal("kernel32.dll!GetCurrentThreadId", finding.CalledApi);
    }

    // 1d — the whole import seam of this type at once: exactly the three declared native targets, each exactly
    // once. Pins that neither [LibraryImport] shape is double-counted (the stub path produces two methods for one
    // declaration) and that no fourth pinvokeimpl is invented.
    //
    // Scoped to ModernInteropOps because the fixture assembly also carries HostileInteropNames, whose deliberately
    // malformed declarations are covered by HostileInteropNameSanitizationTests. The scope is by declaring type,
    // which is exactly the set this test is about — an invented or duplicated pinvokeimpl in this type still fails.
    [Fact]
    public void Analyze_NativeImports_AreExactlyTheThreeDeclaredNativeTargets()
    {
        var targets = Analyze().Findings
            .Where(f => f.Kind == ApiCallKind.NativeImport && f.CallerType == OpsType)
            .Select(f => f.CalledApi)
            .ToArray();

        Assert.Equal(
            ["kernel32.dll!GetCurrentProcessId", "kernel32.dll!GetCurrentThreadId", "kernel32.dll!OutputDebugStringA"],
            targets.Order(StringComparer.Ordinal));
    }

    // ---------------------------------------------------------------------------------------------------
    // [UnmanagedCallersOnly] — reverse P/Invoke: native code calling INTO the assembly. IsPlatformInvoke does
    // not cover it, so it is detected by reading the method's custom attributes in the same pass.
    // ---------------------------------------------------------------------------------------------------

    // 2a — the attribute's optional EntryPoint named argument names the export, so it (not the managed method
    // name) is what native code calls the method by.
    [Fact]
    public void Analyze_UnmanagedCallersOnlyWithEntryPoint_SurfacesNativeExportUnderTheEntryPointName()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f => f.CallerMethod == nameof(ModernInteropOps.NamedCallback));

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(ApiCallKind.NativeExport, finding.Kind);
        Assert.Equal(OpsType, finding.CallerType);
        Assert.Equal("<managed>!silvergun_callback", finding.CalledApi);
    }

    // 2b — with no EntryPoint argument the entry point falls back to the method's own name. Same finding shape,
    // so a reader cannot tell (and does not need to tell) which form the source used.
    [Fact]
    public void Analyze_UnmanagedCallersOnlyWithoutEntryPoint_FallsBackToTheMethodName()
    {
        var report = Analyze();

        var finding = Assert.Single(report.Findings, f => f.CallerMethod == nameof(ModernInteropOps.UnnamedCallback));

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(ApiCallKind.NativeExport, finding.Kind);
        Assert.Equal(OpsType, finding.CallerType);
        Assert.Equal($"<managed>!{nameof(ModernInteropOps.UnnamedCallback)}", finding.CalledApi);
    }

    // 2c — negative control: an ordinary static method in the same type, with no interop attribute and no
    // sensitive call, produces NO finding of any kind. The attribute read must not fire on every method.
    [Fact]
    public void Analyze_MethodWithoutAnInteropAttribute_ProducesNoFinding()
    {
        var report = Analyze();

        Assert.DoesNotContain(report.Findings, f => f.CallerMethod == nameof(ModernInteropOps.Clean));
    }

    // 2d — the shared renderer contract, pinned in one place for BOTH metadata seams: CalledApi is
    // "<owner>!<entryPoint>" with exactly one '!', so a renderer splitting on '!' always gets two segments. The
    // left segment names the side that owns the entry point — the native module for an import, the literal
    // "<managed>" sentinel for an export, which is how a renderer tells the two directions apart without
    // consulting Kind.
    [Fact]
    public void Analyze_MetadataSeamFindings_UseTheSingleBangOwnerEntryPointShape()
    {
        var seam = Analyze().Findings
            .Where(f => f.Kind is ApiCallKind.NativeImport or ApiCallKind.NativeExport)
            .ToArray();

        Assert.NotEmpty(seam);
        Assert.All(seam, f =>
        {
            var segments = f.CalledApi.Split('!');

            Assert.Equal(2, segments.Length);
            Assert.NotEmpty(segments[0]);
            Assert.NotEmpty(segments[1]);

            if (f.Kind == ApiCallKind.NativeExport)
                Assert.Equal("<managed>", segments[0]);
            else
                Assert.NotEqual("<managed>", segments[0]);
        });
    }

    // 2e — the owning type and method are carried by CallerType/CallerMethod and are NOT duplicated into
    // CalledApi: an export's CalledApi names only the sentinel and the native-visible entry point.
    [Fact]
    public void Analyze_NativeExports_CarryTheOwnerInCallerFieldsRatherThanInCalledApi()
    {
        // Scoped to ModernInteropOps: HostileInteropNames in the same fixture assembly also declares exports.
        var exports = Analyze().Findings
            .Where(f => f.Kind == ApiCallKind.NativeExport && f.CallerType == OpsType)
            .ToArray();

        Assert.Equal(2, exports.Length);
        Assert.All(exports, f =>
        {
            Assert.Equal(OpsType, f.CallerType);
            Assert.DoesNotContain(nameof(ModernInteropOps), f.CalledApi, StringComparison.Ordinal);
            Assert.DoesNotContain(f.CallerType, f.CalledApi, StringComparison.Ordinal);
        });

        Assert.Equal(
            [nameof(ModernInteropOps.NamedCallback), nameof(ModernInteropOps.UnnamedCallback)],
            exports.Select(f => f.CallerMethod).Order(StringComparer.Ordinal));
    }

    // 2f — coverage bookkeeping is untouched by the export seam. Unlike a P/Invoke extern (bodyless, hence never
    // in AssemblyAnalyzer.Methods), an [UnmanagedCallersOnly] method HAS a body and is walked normally, so its
    // export finding is additive: the method is still analyzed exactly once, nothing is skipped, and the export
    // cannot be a double-count of a call site because there is no call site.
    //
    // The count is assembly-wide (MethodsTotal has no per-type form), so it names every bodied method in the
    // fixture assembly: ModernInteropOps' DebugMessage marshalling stub, NamedCallback, UnnamedCallback and
    // Clean, plus the three [UnmanagedCallersOnly] methods on HostileInteropNames. The bodyless pinvokeimpl
    // declarations are absent by construction. Adding a bodied method to the fixture must fail this test.
    [Fact]
    public void Analyze_UnmanagedCallersOnlyMethods_AreStillAnalyzedExactlyOnceAndSkipNothing()
    {
        var report = Analyze();

        Assert.Equal(BodiedFixtureMethods, report.MethodsTotal);
        Assert.Equal(BodiedFixtureMethods, report.MethodsAnalyzed);
        Assert.Equal(0, report.MethodsSkipped);
        Assert.Empty(report.SkippedMethods);
    }

    // 2g — the type name the fixture assembly reports through CCI is the same full name reflection gives, so the
    // literal used throughout this class is not a private convention. Every finding in the fixture assembly is
    // attributed to one of its two declaring types and nothing else — no compiler-generated or invented owner.
    [Fact]
    public void Analyze_CallerType_IsTheReflectionFullNameOfTheDeclaringType()
    {
        Assert.Equal(OpsType, typeof(ModernInteropOps).FullName);
        Assert.Equal(HostileType, typeof(HostileInteropNames).FullName);

        Assert.All(Analyze().Findings, f => Assert.Contains(f.CallerType, new[] { OpsType, HostileType }));
    }

    private CapabilityReport Analyze()
    {
        var result = new CapabilityAnalysis(fixture.Assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }
    #endregion

    #region Fields
    private const string OpsType = "Silvergun.CodeAnalysis.IL.Tests.MatrixFixture.ModernInteropOps";
    private const string HostileType = "Silvergun.CodeAnalysis.IL.Tests.MatrixFixture.HostileInteropNames";

    // Every method in the fixture assembly that carries a body, hence every method the call-site pass walks.
    private const int BodiedFixtureMethods = 7;

    private readonly ModernInteropFixture fixture;
    #endregion
}
