namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

using Xunit;

/// <summary>
/// Regression coverage for <c>CalledApi</c> sanitization in the interop metadata seam, over the <b>net10.0</b>
/// fixture type <see cref="HostileInteropNames"/>.
/// <para>
/// <c>CapabilityAnalysis</c> composes <c>CalledApi</c> as <c>module!entryPoint</c> for an import and
/// <c>&lt;managed&gt;!entryPoint</c> for an export. Both components come straight from metadata, which in an
/// untrusted package is attacker-controlled: plain C# puts <c>'!'</c>, CR, LF and TAB into either of them, and
/// Roslyn compiles it without complaint. Unsanitized, a second <c>'!'</c> breaks the documented "exactly one
/// <c>'!'</c>" split contract and a newline breaks a report table's row layout.
/// </para>
/// <para>
/// The contract under test is narrow and deliberate: <c>'!'</c> becomes <c>'_'</c>, control characters are
/// dropped, and <b>nothing else changes</b> — see
/// <see cref="Analyze_LegitimateInteropNames_AreLeftByteForByteUnchanged"/>.
/// </para>
/// </summary>
public sealed class HostileInteropNameSanitizationTests : IClassFixture<ModernInteropFixture>
{
    #region Constructors
    public HostileInteropNameSanitizationTests(ModernInteropFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // '!' injection — the split contract. A renderer that splits CalledApi on '!' to show "where" and "what"
    // must always get exactly two segments, whatever the metadata says.
    // ---------------------------------------------------------------------------------------------------

    // 1a — worst case on the import side: an injected '!' in BOTH composed components. Unsanitized this would
    // read "evil!mod.dll!also!bad" — four segments, and a renderer would show the module as "evil".
    [Fact]
    public void Analyze_DllImportWithBangInModuleAndEntryPoint_RendersBothInjectedBangsAsUnderscores()
    {
        var finding = ImportOf("BangInModuleAndEntryPoint");

        Assert.Equal("evil_mod.dll!also_bad", finding.CalledApi);
        Assert.Equal(1, CountBangs(finding.CalledApi));
    }

    // 1b — '!' in the native module name alone: the separator that survives is the composed one, and the
    // injected one is neutralised in place rather than by truncating or dropping the name.
    [Fact]
    public void Analyze_DllImportWithBangInModuleName_KeepsExactlyOneSeparatorAndPreservesTheRestOfTheName()
    {
        var finding = ImportOf("BangInModuleName");

        Assert.Equal("evil_mod.dll!fn", finding.CalledApi);
        Assert.Equal(1, CountBangs(finding.CalledApi));
    }

    // 1c — the export side: an injected '!' must not let an entry point forge a second separator, because the
    // left segment is what tells a renderer this is an export at all. It stays exactly the "<managed>" sentinel.
    [Fact]
    public void Analyze_UnmanagedCallersOnlyWithBangInEntryPoint_KeepsTheManagedSentinelAsTheOwnerSegment()
    {
        var finding = ExportOf(nameof(HostileInteropNames.BangInExportEntryPoint));

        Assert.Equal("<managed>!evil_injected", finding.CalledApi);

        var segments = finding.CalledApi.Split('!');
        Assert.Equal(2, segments.Length);
        Assert.Equal("<managed>", segments[0]);
    }

    // ---------------------------------------------------------------------------------------------------
    // Control characters — the report-row-layout guarantee.
    //
    // CalledApi is rendered as a cell in line-oriented report tables (CLI text output, and the WPF grid). A raw
    // CR/LF in the string would split one finding across two rows, letting a hostile package forge what looks
    // like an extra report row — or hide the rest of its own row. A TAB shifts every following column. So the
    // guarantee asserted here is not "the string looks tidy": it is that CalledApi can never contain a control
    // character, hence can never restructure a report.
    // ---------------------------------------------------------------------------------------------------

    // 2a — CRLF inside a DllImport EntryPoint is stripped; the surrounding characters are kept, so the name is
    // still recognisable to a human reading the report.
    [Fact]
    public void Analyze_DllImportWithControlCharactersInEntryPoint_StripsThemFromCalledApi()
    {
        var finding = ImportOf("ControlCharactersInEntryPoint");

        Assert.Equal("evil.dll!fnx", finding.CalledApi);
        Assert.DoesNotContain(finding.CalledApi, char.IsControl);
    }

    // 2b — the same on the export side, with CR, LF and TAB in one entry point.
    [Fact]
    public void Analyze_UnmanagedCallersOnlyWithControlCharactersInEntryPoint_StripsThemFromCalledApi()
    {
        var finding = ExportOf(nameof(HostileInteropNames.ControlCharactersInExportEntryPoint));

        Assert.Equal("<managed>!evilinjectedmore", finding.CalledApi);
        Assert.DoesNotContain(finding.CalledApi, char.IsControl);
    }

    // ---------------------------------------------------------------------------------------------------
    // Degenerate names — sanitization can empty a component entirely, and an empty segment would be a
    // second way to break the two-segment shape ("evil.dll!" has an empty right side). Both seams fall back
    // to the managed method name instead, which is metadata the attacker also controls but which the CLR
    // constrains far more tightly.
    // ---------------------------------------------------------------------------------------------------

    // 3a — import side: an EntryPoint of nothing but control characters sanitizes to empty, so the native
    // target falls back to the declaring method's own name.
    [Fact]
    public void Analyze_DllImportWithEntryPointOfOnlyControlCharacters_FallsBackToTheMethodName()
    {
        var finding = ImportOf("OnlyControlCharactersInEntryPoint");

        Assert.Equal("evil.dll!OnlyControlCharactersInEntryPoint", finding.CalledApi);
        Assert.Equal(1, CountBangs(finding.CalledApi));
    }

    // 3b — export side: the same degenerate EntryPoint falls back to the method name, exactly as an absent
    // EntryPoint does. The two seams must not disagree about what "no usable name" means.
    [Fact]
    public void Analyze_UnmanagedCallersOnlyWithEntryPointOfOnlyControlCharacters_FallsBackToTheMethodName()
    {
        var name = nameof(HostileInteropNames.OnlyControlCharactersInExportEntryPoint);
        var finding = ExportOf(name);

        Assert.Equal($"<managed>!{name}", finding.CalledApi);
        Assert.Equal(1, CountBangs(finding.CalledApi));
    }

    // ---------------------------------------------------------------------------------------------------
    // Identity on legitimate names, and the assembly-wide invariant.
    // ---------------------------------------------------------------------------------------------------

    // 4 — SANITIZATION IS IDENTITY FOR REAL NAMES. No real native module or export name contains '!' or a
    // control character, so the mapping must lose nothing legitimate: the clean fixture's targets come through
    // byte for byte. This is the guard against a future "tighten the sanitizer" change (stripping punctuation,
    // case-folding, length-capping, escaping) quietly mangling real names — which would be far worse than the
    // injection it was meant to stop, because it would corrupt every honest package's report.
    [Theory]
    [InlineData("kernel32.dll!GetCurrentProcessId")]
    [InlineData("kernel32.dll!GetCurrentThreadId")]
    [InlineData("kernel32.dll!OutputDebugStringA")]
    [InlineData("<managed>!silvergun_callback")]
    [InlineData("<managed>!UnnamedCallback")]
    public void Analyze_LegitimateInteropNames_AreLeftByteForByteUnchanged(string expected)
    {
        var seam = MetadataSeamFindings();

        Assert.Single(seam, f => string.Equals(f.CalledApi, expected, StringComparison.Ordinal));
    }

    // 5 — the invariant the two fixes exist to make true, asserted over EVERY metadata-seam finding in the
    // fixture assembly at once (well-formed and hostile alike) rather than case by case: exactly one '!', and
    // no control character anywhere. A new hostile shape added to the fixture is covered by this test for free.
    [Fact]
    public void Analyze_EveryMetadataSeamFinding_HasExactlyOneBangAndNoControlCharacters()
    {
        var seam = MetadataSeamFindings();

        // Both hostile and well-formed declarations are in scope, so this is not vacuous.
        Assert.Contains(seam, f => f.CallerType.EndsWith(nameof(HostileInteropNames), StringComparison.Ordinal));
        Assert.Contains(seam, f => f.CallerType.EndsWith(nameof(ModernInteropOps), StringComparison.Ordinal));

        Assert.All(seam, f =>
        {
            Assert.Equal(1, CountBangs(f.CalledApi));
            Assert.False(f.CalledApi.Any(char.IsControl), $"Control character in CalledApi: {f.CalledApi}");

            var segments = f.CalledApi.Split('!');
            Assert.NotEmpty(segments[0]);
            Assert.NotEmpty(segments[1]);
        });
    }

    // The hostile P/Invoke declarations are `internal` extern methods, so they are named by literal: only
    // metadata ever sees them, which is the point of the seam.
    private ApiCallFinding ImportOf(string callerMethod) => SeamFinding(ApiCallKind.NativeImport, callerMethod);

    private ApiCallFinding ExportOf(string callerMethod) => SeamFinding(ApiCallKind.NativeExport, callerMethod);

    private ApiCallFinding SeamFinding(ApiCallKind kind, string callerMethod)
    {
        var finding = Assert.Single(
            MetadataSeamFindings(),
            f => f.Kind == kind && f.CallerType == HostileType && f.CallerMethod == callerMethod);

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        return finding;
    }

    private ApiCallFinding[] MetadataSeamFindings() => Analyze().Findings
        .Where(f => f.Kind is ApiCallKind.NativeImport or ApiCallKind.NativeExport)
        .ToArray();

    private CapabilityReport Analyze()
    {
        var result = new CapabilityAnalysis(fixture.Assembly).Analyze();
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }

    private static int CountBangs(string value) => value.Count(c => c == '!');
    #endregion

    #region Fields
    private const string HostileType = "Silvergun.CodeAnalysis.IL.Tests.MatrixFixture.HostileInteropNames";

    private readonly ModernInteropFixture fixture;
    #endregion
}
