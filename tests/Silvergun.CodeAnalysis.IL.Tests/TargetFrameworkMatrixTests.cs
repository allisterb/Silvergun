namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The cross-target-framework contract: one source set (<c>Silvergun.CodeAnalysis.IL.Tests.MatrixFixture</c>)
/// compiled for <c>net472</c> and <c>net10.0</c>, analyzed through the same seams, must agree. We scan
/// <em>other people's</em> assemblies, which range from net472 through net10.0, so "same source ⇒ same findings
/// regardless of target framework" is the property that decides whether an analysis result means anything at
/// all on an old package. See <c>docs/agent/tasks/tfm-matrix-tests.md</c>.
/// <para>
/// Every theory here is driven from <see cref="MatrixFixtureAssemblies.ByTargetFramework"/> rather than from a
/// hardcoded list, so adding a flavour to the fixture extends coverage automatically;
/// <see cref="MatrixFixtureAssembliesTests"/> guards against the matrix silently shrinking instead.
/// </para>
/// </summary>
public sealed class TargetFrameworkMatrixTests : IClassFixture<TargetFrameworkMatrixFixture>
{
    #region Constructors
    public TargetFrameworkMatrixTests(TargetFrameworkMatrixFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // A — shape inventory per target framework.
    //
    // The fixture's shapes are NOT identical across the matrix, deliberately: [LibraryImport] is net7+ and
    // [UnmanagedCallersOnly] is net5+, so each is #if-guarded. Everything available everywhere ([DllImport],
    // and the Clean negative control) is unguarded. Each number below is derived from that, so a future change
    // to the fixture forces a deliberate update here rather than drifting silently.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// The measured shape inventory of each flavour. Driven from the discovered matrix, with the baseline
    /// looked up per target framework: a flavour added to the fixture with no baseline recorded here fails
    /// rather than passing untested.
    /// </summary>
    [Theory]
    [MemberData(nameof(TargetFrameworks))]
    public void Analyze_ShapeInventory_MatchesTheBaselineForThatTargetFramework(string targetFramework)
    {
        Assert.True(
            Baselines.TryGetValue(targetFramework, out var expected),
            $"No shape baseline recorded for '{targetFramework}'. A target framework was added to the matrix " +
            $"fixture without extending {nameof(TargetFrameworkMatrixTests)}; record its measured shapes here.");

        var report = fixture.Report(targetFramework);

        Assert.Equal(expected.NativeImports, report.Findings.Count(f => f.Kind == ApiCallKind.NativeImport));
        Assert.Equal(expected.NativeExports, report.Findings.Count(f => f.Kind == ApiCallKind.NativeExport));

        Assert.Equal(expected.MethodsTotal, report.MethodsTotal);
        Assert.Equal(expected.MethodsTotal, report.MethodsAnalyzed);
        Assert.Equal(0, report.MethodsSkipped);
        Assert.Empty(report.SkippedMethods);

        // MethodsTotal is assembly-wide and therefore counts compiler-synthesized types too (see the baseline
        // comment). Splitting out the fixture's OWN bodied methods keeps the number that describes the source
        // separate from the number that describes the toolchain.
        Assert.Equal(expected.AuthoredBodiedMethods, fixture.AuthoredBodiedMethods(targetFramework));
    }

    /// <summary>
    /// The inventory above is a count; this names the shapes behind it, so a failure says <em>which</em>
    /// declaration went missing rather than only that a number moved. net472 carries the unguarded
    /// <c>[DllImport]</c>s and nothing else; net10.0 adds the guarded <c>[LibraryImport]</c> and
    /// <c>[UnmanagedCallersOnly]</c> shapes.
    /// </summary>
    [Fact]
    public void Analyze_Net472_CarriesTheUnguardedDllImportsAndNoManagedExports()
    {
        var report = fixture.Report(Legacy);

        Assert.Equal(
            [
                "evil.dll!OnlyControlCharactersInEntryPoint",
                "evil.dll!fnx",
                "evil_mod.dll!also_bad",
                "evil_mod.dll!fn",
                "kernel32.dll!GetCurrentThreadId",
            ],
            report.Findings.Where(f => f.Kind == ApiCallKind.NativeImport)
                .Select(f => f.CalledApi).Order(StringComparer.Ordinal));

        // [UnmanagedCallersOnly] does not exist on net472 — there is no managed-export mechanism at all.
        Assert.DoesNotContain(report.Findings, f => f.Kind == ApiCallKind.NativeExport);
    }

    /// <summary>
    /// The modern counterpart: net10.0 adds exactly the two <c>[LibraryImport]</c> targets on the import side
    /// and the five <c>[UnmanagedCallersOnly]</c> exports.
    /// </summary>
    [Fact]
    public void Analyze_Modern_AddsTheLibraryImportTargetsAndTheManagedExports()
    {
        var report = fixture.Report(Modern);

        var imports = report.Findings.Where(f => f.Kind == ApiCallKind.NativeImport)
            .Select(f => f.CalledApi).ToHashSet(StringComparer.Ordinal);
        var legacyImports = fixture.Report(Legacy).Findings.Where(f => f.Kind == ApiCallKind.NativeImport)
            .Select(f => f.CalledApi).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            ["kernel32.dll!GetCurrentProcessId", "kernel32.dll!OutputDebugStringA"],
            imports.Except(legacyImports, StringComparer.Ordinal).Order(StringComparer.Ordinal));

        Assert.Equal(
            [
                "<managed>!OnlyControlCharactersInExportEntryPoint",
                "<managed>!UnnamedCallback",
                "<managed>!evil_injected",
                "<managed>!evilinjectedmore",
                "<managed>!silvergun_callback",
            ],
            report.Findings.Where(f => f.Kind == ApiCallKind.NativeExport)
                .Select(f => f.CalledApi).Order(StringComparer.Ordinal));
    }

    // ---------------------------------------------------------------------------------------------------
    // B — the cross-TFM subset invariant, the highest-value assertion here.
    //
    // Compared on the full (Kind, CallerType, CallerMethod, CalledApi) tuple rather than on counts: a count
    // match can hide two findings swapping places, and it tells a reader nothing about WHAT was found. On
    // failure the symmetric difference is printed, so the message names the offending findings.
    //
    // "Guarded" is defined by the #if blocks in the fixture source, which is the robust direction: a NEW
    // UNGUARDED shape added to the fixture appears on both sides and needs no change here, while a new guarded
    // shape is a deliberate matrix decision that should force one.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// <b>Same source ⇒ same findings, regardless of target framework.</b> The findings produced by unguarded
    /// declarations — the ones every flavour of the matrix actually compiles — must be byte-identical across
    /// every flavour. Any difference is a target-framework-sensitive read somewhere in the analyzer.
    /// </summary>
    [Fact]
    public void Analyze_UnguardedDeclarations_ProduceIdenticalFindingsOnEveryTargetFramework()
    {
        var byTargetFramework = fixture.Reports.ToDictionary(
            entry => entry.Key,
            entry => Tuples(entry.Value.Findings.Where(IsUnguarded)),
            StringComparer.Ordinal);

        // Not vacuous: the unguarded shapes really are present.
        Assert.All(byTargetFramework, entry => Assert.NotEmpty(entry.Value));

        var reference = byTargetFramework[Legacy];
        var differences = byTargetFramework
            .Where(entry => !entry.Value.SetEquals(reference))
            .Select(entry => Difference($"unguarded findings, {Legacy} vs {entry.Key}", reference, entry.Value))
            .ToArray();

        Assert.True(differences.Length == 0, string.Join(Environment.NewLine, differences));
    }

    /// <summary>
    /// The spec's exact statement: net472's finding set is <em>exactly</em> the subset of net10.0's whose
    /// caller is an unguarded declaration. Both directions are asserted — a net472 finding missing from
    /// net10.0 would mean the old target invents something, and an unguarded net10.0 finding missing from
    /// net472 would mean the old target loses something.
    /// </summary>
    [Fact]
    public void Analyze_Net472Findings_AreExactlyTheUnguardedSubsetOfTheModernFindings()
    {
        var legacy = Tuples(fixture.Report(Legacy).Findings);
        var modern = fixture.Report(Modern).Findings;

        var unguardedModern = Tuples(modern.Where(IsUnguarded));

        Assert.True(
            legacy.SetEquals(unguardedModern),
            Difference($"{Legacy} findings vs the unguarded subset of {Modern}", unguardedModern, legacy));

        // ...and the subset is proper, so the comparison above is not the trivial "both sets are everything".
        Assert.True(legacy.IsProperSubsetOf(Tuples(modern)));
    }

    /// <summary>
    /// The partition the invariant above rests on, pinned from the other side: net472 compiles <em>no</em>
    /// guarded declaration, so its guarded partition is empty, while net10.0's is not. Without this, an
    /// <see cref="IsUnguarded"/> that accidentally matched everything would make the invariant vacuous.
    /// </summary>
    [Fact]
    public void Analyze_GuardedDeclarations_AreAbsentFromNet472AndPresentOnTheModernTarget()
    {
        Assert.DoesNotContain(fixture.Report(Legacy).Findings, f => !IsUnguarded(f));
        Assert.Contains(fixture.Report(Modern).Findings, f => !IsUnguarded(f));
    }

    // ---------------------------------------------------------------------------------------------------
    // C — sanitization equivalence across the matrix.
    //
    // The four hostile [DllImport] declarations are UNGUARDED, so they exist on every flavour: their sanitized
    // CalledApi must come out byte-identical everywhere. A divergence means target-framework-sensitive
    // metadata reading or sanitization — which, since the names are attacker-controlled, is exactly the class
    // of bug this matrix exists to catch.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// Each hostile <c>[DllImport]</c> sanitizes to the same <c>CalledApi</c>, exactly once, on every flavour
    /// of the matrix.
    /// </summary>
    [Theory]
    [MemberData(nameof(TargetFrameworksAndHostileImports))]
    public void Analyze_HostileDllImportName_SanitizesIdenticallyOnEveryTargetFramework(string targetFramework, string calledApi)
    {
        var report = fixture.Report(targetFramework);

        var finding = Assert.Single(
            report.Findings,
            f => f.Kind == ApiCallKind.NativeImport && string.Equals(f.CalledApi, calledApi, StringComparison.Ordinal));

        Assert.Equal(Capability.NativeInterop, finding.Capability);
        Assert.Equal(TargetFrameworkMatrixFixture.FixtureNamespace + "HostileInteropNames", finding.CallerType);
    }

    /// <summary>
    /// The same statement as a set, so an <em>extra</em> hostile import invented on one flavour fails too:
    /// every flavour's hostile-type import set is exactly the four sanitized names and nothing else.
    /// </summary>
    [Theory]
    [MemberData(nameof(TargetFrameworks))]
    public void Analyze_HostileImportSeam_IsExactlyTheFourSanitizedNamesOnEveryTargetFramework(string targetFramework)
    {
        var hostile = fixture.Report(targetFramework).Findings
            .Where(f => f.Kind == ApiCallKind.NativeImport &&
                        f.CallerType == TargetFrameworkMatrixFixture.FixtureNamespace + "HostileInteropNames")
            .Select(f => f.CalledApi)
            .Order(StringComparer.Ordinal);

        Assert.Equal(HostileImports.Order(StringComparer.Ordinal), hostile);
    }

    // ---------------------------------------------------------------------------------------------------
    // D — the renderer contract, over the UNION of every flavour.
    //
    // CalledApi is rendered as a cell in line-oriented report tables (CLI text output, the WPF grid) and is
    // split on '!' to show "where" and "what". Asserting over the union means adding a target framework
    // extends this coverage for free.
    // ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// Every metadata-seam finding of every flavour: exactly one <c>'!'</c>, both segments non-empty, and no
    /// control character anywhere — so a hostile package can neither forge a second separator nor restructure
    /// a report row, on any target framework.
    /// </summary>
    [Fact]
    public void Analyze_EveryMetadataSeamFindingOfEveryTargetFramework_HasExactlyOneBangAndNoControlCharacters()
    {
        var seam = fixture.AllFindings
            .Where(entry => entry.Finding.Kind is ApiCallKind.NativeImport or ApiCallKind.NativeExport)
            .ToArray();

        // Non-vacuous, and every flavour of the discovered matrix really did contribute.
        Assert.NotEmpty(seam);
        Assert.Equal(
            MatrixFixtureAssemblies.ByTargetFramework.Keys.Order(StringComparer.Ordinal),
            seam.Select(entry => entry.TargetFramework).Distinct().Order(StringComparer.Ordinal));

        Assert.All(seam, entry =>
        {
            var api = entry.Finding.CalledApi;
            var segments = api.Split('!');

            Assert.True(segments.Length == 2, $"[{entry.TargetFramework}] expected exactly one '!' in '{api}'.");
            Assert.False(string.IsNullOrEmpty(segments[0]), $"[{entry.TargetFramework}] empty owner segment in '{api}'.");
            Assert.False(string.IsNullOrEmpty(segments[1]), $"[{entry.TargetFramework}] empty entry-point segment in '{api}'.");
            Assert.False(api.Any(char.IsControl), $"[{entry.TargetFramework}] control character in '{api}'.");
        });
    }

    /// <summary>
    /// The direction marker the renderer uses to tell an import from an export without consulting
    /// <see cref="ApiCallKind"/>, asserted across the whole matrix: the owner segment is the literal
    /// <c>&lt;managed&gt;</c> sentinel for an export and the native module name for an import.
    /// </summary>
    [Fact]
    public void Analyze_MetadataSeamOwnerSegment_DistinguishesImportsFromExportsOnEveryTargetFramework()
    {
        var seam = fixture.AllFindings
            .Where(entry => entry.Finding.Kind is ApiCallKind.NativeImport or ApiCallKind.NativeExport)
            .ToArray();

        Assert.All(seam, entry =>
        {
            var owner = entry.Finding.CalledApi.Split('!')[0];

            if (entry.Finding.Kind == ApiCallKind.NativeExport)
                Assert.Equal(ManagedExportOwner, owner);
            else
                Assert.NotEqual(ManagedExportOwner, owner);
        });
    }

    /// <summary>
    /// No flavour attributes a finding to a type the fixture does not declare, and none is skipped: the union
    /// carries only the fixture's own two types, whatever the toolchain synthesized alongside them.
    /// </summary>
    [Fact]
    public void Analyze_EveryFindingOfEveryTargetFramework_IsAttributedToAFixtureType()
    {
        Assert.All(fixture.AllFindings, entry =>
            Assert.StartsWith(TargetFrameworkMatrixFixture.FixtureNamespace, entry.Finding.CallerType, StringComparison.Ordinal));

        Assert.All(fixture.Reports, entry =>
        {
            Assert.Equal(0, entry.Value.MethodsSkipped);
            Assert.Empty(entry.Value.SkippedMethods);
        });
    }

    // A finding comes from an unguarded declaration when its caller is not one of the #if-guarded members —
    // including the compiler-generated members derived from one, such as the [LibraryImport] marshalling stub
    // "<DebugMessage>g____PInvoke|N_M".
    private static bool IsUnguarded(ApiCallFinding finding) =>
        !GuardedDeclarations.Any(name =>
            string.Equals(finding.CallerMethod, name, StringComparison.Ordinal) ||
            finding.CallerMethod.Contains($"<{name}>", StringComparison.Ordinal));

    private static HashSet<(ApiCallKind, string, string, string)> Tuples(IEnumerable<ApiCallFinding> findings) =>
        [.. findings.Select(f => (f.Kind, f.CallerType, f.CallerMethod, f.CalledApi))];

    // Reports the symmetric difference so a failure names the offending findings instead of just "sets differ".
    private static string Difference(
        string what,
        IReadOnlySet<(ApiCallKind, string, string, string)> expected,
        IReadOnlySet<(ApiCallKind, string, string, string)> actual)
    {
        var missing = expected.Except(actual).Select(Render).Order(StringComparer.Ordinal).ToArray();
        var extra = actual.Except(expected).Select(Render).Order(StringComparer.Ordinal).ToArray();

        return $"{what}: {expected.Count} expected vs {actual.Count} actual; " +
            $"{missing.Length} missing, {extra.Length} unexpected." +
            List("  missing:    ", missing) +
            List("  unexpected: ", extra);
    }

    private static string Render((ApiCallKind Kind, string CallerType, string CallerMethod, string CalledApi) tuple) =>
        $"{tuple.Kind} {tuple.CallerType}.{tuple.CallerMethod} -> {tuple.CalledApi}";

    private static string List(string label, IReadOnlyList<string> lines) =>
        lines.Count == 0
            ? string.Empty
            : Environment.NewLine + string.Join(Environment.NewLine, lines.Select(line => label + line));
    #endregion

    #region Properties
    /// <summary>Every discovered flavour, so adding one to the fixture extends every matrix theory.</summary>
    public static TheoryData<string> TargetFrameworks =>
        [.. MatrixFixtureAssemblies.ByTargetFramework.Keys.Order(StringComparer.Ordinal)];

    /// <summary>The discovered flavours crossed with the four sanitized hostile import names.</summary>
    public static TheoryData<string, string> TargetFrameworksAndHostileImports
    {
        get
        {
            var data = new TheoryData<string, string>();

            foreach (var targetFramework in MatrixFixtureAssemblies.ByTargetFramework.Keys.Order(StringComparer.Ordinal))
                foreach (var calledApi in HostileImports)
                    data.Add(targetFramework, calledApi);

            return data;
        }
    }
    #endregion

    #region Fields
    private const string Legacy = "net472";
    private const string Modern = "net10.0";
    private const string ManagedExportOwner = "<managed>";

    /// <summary>
    /// Declarations inside an <c>#if</c> block in the fixture source, hence present on some flavours only:
    /// <c>[LibraryImport]</c> is <c>NET7_0_OR_GREATER</c> and <c>[UnmanagedCallersOnly]</c> is
    /// <c>NET5_0_OR_GREATER</c>. Everything else the fixture declares is unguarded and must behave identically
    /// everywhere.
    /// </summary>
    private static readonly string[] GuardedDeclarations =
    [
        // ModernInteropOps, #if NET7_0_OR_GREATER
        "CurrentProcessId",
        "DebugMessage",
        // ModernInteropOps, #if NET5_0_OR_GREATER
        "NamedCallback",
        "UnnamedCallback",
        // HostileInteropNames, #if NET5_0_OR_GREATER
        "BangInExportEntryPoint",
        "ControlCharactersInExportEntryPoint",
        "OnlyControlCharactersInExportEntryPoint",
    ];

    /// <summary>
    /// The sanitized native targets of the four hostile <c>[DllImport]</c> declarations. They are unguarded,
    /// so every flavour of the matrix must produce exactly these, byte for byte.
    /// </summary>
    private static readonly string[] HostileImports =
    [
        "evil_mod.dll!also_bad",                        // '!' injected into BOTH module and entry point
        "evil_mod.dll!fn",                              // '!' injected into the module name only
        "evil.dll!fnx",                                 // CRLF stripped from the entry point
        "evil.dll!OnlyControlCharactersInEntryPoint",    // entry point sanitized to empty, falls back to the method name
    ];

    /// <summary>
    /// The measured shape inventory per flavour.
    /// <list type="bullet">
    /// <item><description><b>net472</b> — 5 <c>NativeImport</c>: the four hostile unguarded
    /// <c>[DllImport]</c>s plus <c>CurrentThreadId</c>. <b>0</b> <c>NativeExport</c>: no
    /// <c>[UnmanagedCallersOnly]</c> on net472, so no managed-export mechanism at all.</description></item>
    /// <item><description><b>net10.0</b> — 7 <c>NativeImport</c>: net472's 5 plus the two
    /// <c>[LibraryImport]</c> targets (<c>CurrentProcessId</c> direct-forwarder and the <c>DebugMessage</c>
    /// marshalling stub). 5 <c>NativeExport</c>: <c>NamedCallback</c>, <c>UnnamedCallback</c> and the three
    /// hostile export names.</description></item>
    /// </list>
    /// <para>
    /// <b>MethodsTotal counts bodied methods assembly-wide, not just the fixture's own.</b> On net10.0 the
    /// authored 7 (the <c>DebugMessage</c> stub, the five <c>[UnmanagedCallersOnly]</c> methods, and
    /// <c>Clean</c>) are the whole assembly. On net472 the fixture authors exactly <b>one</b> bodied method,
    /// <c>Clean</c> — every other declaration is a bodyless <c>extern</c> — but the report counts <b>3</b>,
    /// because Roslyn embeds <c>Microsoft.CodeAnalysis.EmbeddedAttribute</c> and
    /// <c>System.Runtime.CompilerServices.RefSafetyRulesAttribute</c> into the assembly when the target
    /// framework's BCL lacks them, and each carries a bodied constructor. That is real compiler output the
    /// analyzer reads correctly, not an analyzer difference — see
    /// <see cref="TargetFrameworkMatrixFixture.AuthoredBodiedMethods"/>, which is 1 on net472 as expected.
    /// </para>
    /// </summary>
    private static readonly IReadOnlyDictionary<string, ShapeInventory> Baselines =
        new Dictionary<string, ShapeInventory>(StringComparer.Ordinal)
        {
            [Legacy] = new(NativeImports: 5, NativeExports: 0, MethodsTotal: 3, AuthoredBodiedMethods: 1),
            [Modern] = new(NativeImports: 7, NativeExports: 5, MethodsTotal: 7, AuthoredBodiedMethods: 7),
        };

    private readonly TargetFrameworkMatrixFixture fixture;
    #endregion

    #region Child types
    /// <summary>The shapes one flavour of the matrix is expected to produce.</summary>
    public sealed record ShapeInventory(int NativeImports, int NativeExports, int MethodsTotal, int AuthoredBodiedMethods);
    #endregion
}
