namespace Silvergun.CLI.Tests;

using System.Collections.Generic;
using System.Linq;

using Silvergun.CLI;
using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// ADR 0026 ("FINAL DECISION AS ACCEPTED — 2026-08-20") narrowed what used to be an absolute rule — "indicator
/// findings never move the exit code" — into a strict subset. <b>This file's premise changed</b>, so it no longer
/// pins that absolute invariant; it pins the surviving, narrower one:
/// <list type="bullet">
/// <item><b>Non-gating indicator categories never affect any exit code</b>, under EVERY combination of
/// <c>--strict</c> / <c>--allow-incomplete</c>, for either verb. This is the noisy tier
/// (<see cref="IndicatorCategory.ReflectionTypeName"/>, <see cref="IndicatorCategory.GenericUrl"/>,
/// <see cref="IndicatorCategory.PrivateIpLiteral"/>) PLUS the four discriminating-but-refused categories
/// (<see cref="IndicatorCategory.ExfilSink"/>, <see cref="IndicatorCategory.RawCodeHost"/>,
/// <see cref="IndicatorCategory.PublicIpLiteral"/>, <see cref="IndicatorCategory.AutorunRegistry"/>) — these set the
/// report headline (<see cref="ReportTheme.IsDiscriminatingIndicatorCategory"/>) but were deliberately, evidentially
/// refused a gate (see the ADR's "Explicitly NOT gating" table).</item>
/// <item><b>Gating indicator categories DO gate, but ONLY under <c>--strict</c></b>:
/// <see cref="IndicatorCategory.CallbackDomain"/>, <see cref="IndicatorCategory.DynamicDns"/>, and
/// <see cref="IndicatorCategory.CredentialPath"/> (<see cref="ReportTheme.IsGatingIndicatorCategory"/>). Exit 2 under
/// <c>--strict</c>, exit 0 (indicator-wise) without it — the pre-existing exit-code contract, no new code.</item>
/// </list>
/// Where the surviving invariant is an equality (non-gating tiers), assertions stay "same exit code with and without
/// the finding attached" so they cannot drift from what the gate predicate does. Where the behavior is a genuine
/// change (the three gating categories), the expectations are literal integers, because an equality assertion there
/// would silently launder the very policy shift this file exists to pin.
/// </summary>
public sealed class IndicatorExitCodeInvarianceTests
{
    #region Methods — D: the gating set, derived from the enum itself
    // The exact gating set, enumerated from Enum.GetValues<IndicatorCategory> rather than any hardcoded count — a
    // future 11th category is automatically included in `all` and must be classified one way or the other by
    // IsGatingIndicatorCategory; this test does not need editing for that to be exercised.
    [Fact]
    public void IsGatingIndicatorCategory_ExactlyCallbackDomainDynamicDnsAndCredentialPathGate()
    {
        var expectedGating = new[]
        {
            IndicatorCategory.CallbackDomain, IndicatorCategory.DynamicDns, IndicatorCategory.CredentialPath,
        };
        var all = System.Enum.GetValues<IndicatorCategory>();

        var actualGating = all.Where(ReportTheme.IsGatingIndicatorCategory).OrderBy(c => c).ToArray();

        Assert.Equal(expectedGating.OrderBy(c => c).ToArray(), actualGating);
        // Every OTHER category in the live enum — whatever it currently contains — must NOT gate. This is the half
        // of the assertion that catches a future append landing in the gating set by accident.
        Assert.All(
            all.Except(expectedGating),
            category => Assert.False(
                ReportTheme.IsGatingIndicatorCategory(category), $"{category} unexpectedly gates --strict"));
    }

    public static IEnumerable<object[]> AllIndicatorCategories() =>
        System.Enum.GetValues<IndicatorCategory>().Select(c => new object[] { c });

    // The structural invariant ADR 0026 requires "expressed in one place": a category can never gate without also
    // being discriminating. Enumerated over the live enum (MemberData), not a fixed list, for the same reason as above.
    [Theory]
    [MemberData(nameof(AllIndicatorCategories))]
    public void IsGatingIndicatorCategory_ImpliesIsDiscriminatingIndicatorCategory(IndicatorCategory category)
    {
        if (ReportTheme.IsGatingIndicatorCategory(category))
            Assert.True(ReportTheme.IsDiscriminatingIndicatorCategory(category));
    }
    #endregion

    #region Methods — B: positive gating — analyze, each gating category individually
    // Each of the three gating categories, entirely alone (no capability/obfuscation/script/YARA/vulnerability
    // findings): 2 under --strict, 0 without. Three separate tests (not one parameterized over the category) because
    // the task is explicit that DynamicDns and CredentialPath were never previously exercised and must each be
    // covered by name, not folded into a loop that could pass with only one of the three actually wired.
    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void AnalyzeExitCode_CallbackDomainOnly_GatesOnlyUnderStrict(bool strict, int expected) =>
        Assert.Equal(
            expected,
            Program.AnalyzeExitCode(
                CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.CallbackDomain) },
                strict,
                allowIncomplete: false));

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void AnalyzeExitCode_DynamicDnsOnly_GatesOnlyUnderStrict(bool strict, int expected) =>
        Assert.Equal(
            expected,
            Program.AnalyzeExitCode(
                CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.DynamicDns) },
                strict,
                allowIncomplete: false));

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void AnalyzeExitCode_CredentialPathOnly_GatesOnlyUnderStrict(bool strict, int expected) =>
        Assert.Equal(
            expected,
            Program.AnalyzeExitCode(
                CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.CredentialPath) },
                strict,
                allowIncomplete: false));
    #endregion

    #region Methods — B: positive gating — scan-package, each gating category individually
    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void ScanPackageExitCode_CallbackDomainOnly_GatesOnlyUnderStrict(bool strict, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.CallbackDomain), strict, allowIncomplete: false));

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void ScanPackageExitCode_DynamicDnsOnly_GatesOnlyUnderStrict(bool strict, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.DynamicDns), strict, allowIncomplete: false));

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void ScanPackageExitCode_CredentialPathOnly_GatesOnlyUnderStrict(bool strict, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.CredentialPath), strict, allowIncomplete: false));
    #endregion

    #region Methods — C: the refusals, pinned as hard as the inclusions — analyze
    // ExfilSink, RawCodeHost, PublicIpLiteral, AutorunRegistry: discriminating (they set the headline) but
    // DELIBERATELY, evidentially refused a gate. Asserted as a literal 0 under BOTH --strict and not — not merely
    // "equal to the bare report" — so that a future change which makes any of these gate (the failure mode the task
    // spec calls out as most likely to erode) fails here with an unambiguous wrong number, by name.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnalyzeExitCode_ExfilSinkOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.AnalyzeExitCode(
            CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.ExfilSink) }, strict, allowIncomplete: false));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnalyzeExitCode_RawCodeHostOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.AnalyzeExitCode(
            CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.RawCodeHost) }, strict, allowIncomplete: false));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnalyzeExitCode_PublicIpLiteralOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.AnalyzeExitCode(
            CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.PublicIpLiteral) }, strict, allowIncomplete: false));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnalyzeExitCode_AutorunRegistryOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.AnalyzeExitCode(
            CleanAssembly() with { Indicators = SoleFinding(IndicatorCategory.AutorunRegistry) }, strict, allowIncomplete: false));
    #endregion

    #region Methods — C: the refusals, pinned as hard as the inclusions — scan-package
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanPackageExitCode_ExfilSinkOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.ExfilSink), strict, allowIncomplete: false));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanPackageExitCode_RawCodeHostOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.RawCodeHost), strict, allowIncomplete: false));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanPackageExitCode_PublicIpLiteralOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.PublicIpLiteral), strict, allowIncomplete: false));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanPackageExitCode_AutorunRegistryOnly_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWithSoleFinding(IndicatorCategory.AutorunRegistry), strict, allowIncomplete: false));
    #endregion

    #region Methods — analyze: exit code is invariant to NON-GATING indicator findings, across every flag combination
    // The surviving equality invariant, re-aimed: noisy findings AND the four refused-but-discriminating categories,
    // alone or mixed, must never change the exit code, under every strict/allow-incomplete combination. (The old
    // "discriminating"/"mixed" tier names are retired here because they used to carry a CallbackDomain finding, which
    // is now a gating category and therefore is no longer part of this invariant's premise — see the gating-specific
    // regions above and the precedence region below.)
    public static IEnumerable<object[]> AnalyzeNonGatingFlagMatrix() =>
        from strict in Flags
        from allow in Flags
        from tier in NonGatingTiers
        select new object[] { strict, allow, tier };

    [Theory]
    [MemberData(nameof(AnalyzeNonGatingFlagMatrix))]
    public void AnalyzeExitCode_IsUnaffectedByNonGatingIndicatorFindings(bool strict, bool allowIncomplete, string tier)
    {
        var bare = CleanAssembly();
        var withIndicators = bare with { Indicators = NonGatingIndicatorsFor(tier) };

        var bareExit = Program.AnalyzeExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.AnalyzeExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }

    // The same invariant when the assembly ALSO has real (capability) findings and/or is incomplete — non-gating
    // indicators must not change the answer even when other gates are already in play.
    public static IEnumerable<object[]> AnalyzeNonGatingFlagMatrixWithOtherFindings() =>
        from strict in Flags
        from allow in Flags
        from tier in NonGatingTiers
        from shape in new[] { "findings", "incomplete", "findings+incomplete" }
        select new object[] { strict, allow, tier, shape };

    [Theory]
    [MemberData(nameof(AnalyzeNonGatingFlagMatrixWithOtherFindings))]
    public void AnalyzeExitCode_IsUnaffectedByNonGatingIndicatorFindings_EvenAlongsideOtherGatesOrIncompleteness(
        bool strict, bool allowIncomplete, string tier, string shape)
    {
        var bare = shape switch
        {
            "findings" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0, findings: [CapabilityFinding]),
            "incomplete" => AssemblyReport(methodsTotal: 10, methodsSkipped: 3),
            "findings+incomplete" => AssemblyReport(methodsTotal: 10, methodsSkipped: 3, findings: [CapabilityFinding]),
            _ => throw new System.ArgumentOutOfRangeException(nameof(shape)),
        };
        var withIndicators = bare with { Indicators = NonGatingIndicatorsFor(tier) };

        var bareExit = Program.AnalyzeExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.AnalyzeExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }
    #endregion

    #region Methods — scan-package: exit code is invariant to NON-GATING indicator findings, across every flag combination
    public static IEnumerable<object[]> PackageNonGatingFlagMatrix() =>
        from strict in Flags
        from allow in Flags
        from tier in NonGatingTiers
        select new object[] { strict, allow, tier };

    [Theory]
    [MemberData(nameof(PackageNonGatingFlagMatrix))]
    public void ScanPackageExitCode_IsUnaffectedByNonGatingIndicatorFindings(bool strict, bool allowIncomplete, string tier)
    {
        var bare = CleanPackage();
        var withIndicators = CleanPackage(tier);

        var bareExit = Program.ScanPackageExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.ScanPackageExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }

    // Same invariant with a package that ALSO has other gates tripped (capability finding, or is incomplete via an
    // unavailable vulnerability check) — non-gating indicators must not move the answer in the presence of every
    // other gate.
    public static IEnumerable<object[]> PackageNonGatingFlagMatrixWithOtherFindings() =>
        from strict in Flags
        from allow in Flags
        from tier in NonGatingTiers
        from shape in new[] { "findings", "incomplete", "vuln-status" }
        select new object[] { strict, allow, tier, shape };

    [Theory]
    [MemberData(nameof(PackageNonGatingFlagMatrixWithOtherFindings))]
    public void ScanPackageExitCode_IsUnaffectedByNonGatingIndicatorFindings_EvenAlongsideOtherGatesOrIncompleteness(
        bool strict, bool allowIncomplete, string tier, string shape)
    {
        var analyzed = shape switch
        {
            "findings" => Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0, findings: [CapabilityFinding]),
            "incomplete" => Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 3),
            "vuln-status" => Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0),
            _ => throw new System.ArgumentOutOfRangeException(nameof(shape)),
        };
        var vulnStatus = shape == "vuln-status" ? VulnerabilityScanStatus.Unavailable : VulnerabilityScanStatus.Completed;

        var bare = PackageWith([analyzed], vulnStatus: vulnStatus);
        var withIndicators = PackageWith(
            [analyzed with { Indicators = NonGatingIndicatorsFor(tier, "lib/net10.0/A.dll") }], vulnStatus: vulnStatus);

        var bareExit = Program.ScanPackageExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.ScanPackageExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }
    #endregion

    #region Methods — E: precedence, "2 beats 3" for a gating indicator finding
    // Mirrors CompletenessExitCodeTests.ScanExitCode_FullTruthTable's precedence row, but for the indicator gate
    // specifically: a CallbackDomain finding is present in EVERY row here (it is the fixture's constant), so under
    // --strict the gate always trips regardless of the incompleteness/allow-incomplete axes — including the row that
    // would otherwise have been exit 3. --allow-incomplete downgrades 3 -> 0 when nothing else gates, but it must NOT
    // undo an already-tripped --strict gate (it suppresses the COVERAGE code, not the VERDICT). One representative
    // gating category is used because the structural test above already proves the three gating categories are
    // exactly interchangeable at this predicate (IsGatingIndicatorCategory checks Category membership only).
    [Theory]
    [InlineData(false, false, false, 0)]
    [InlineData(false, false, true, 0)]
    [InlineData(false, true, false, 3)]
    [InlineData(false, true, true, 0)]
    [InlineData(true, false, false, 2)]
    [InlineData(true, false, true, 2)]
    [InlineData(true, true, false, 2)]   // PRECEDENCE: the gating indicator finding beats incompleteness — 2 beats 3
    [InlineData(true, true, true, 2)]    // --allow-incomplete does not undo an already-tripped --strict gate
    public void AnalyzeExitCode_GatingIndicatorFinding_PrecedesIncompleteness(
        bool strict, bool incomplete, bool allowIncomplete, int expected)
    {
        var report = AssemblyReport(methodsTotal: 10, methodsSkipped: incomplete ? 3 : 0) with
        {
            Indicators = SoleFinding(IndicatorCategory.CallbackDomain)
        };

        Assert.Equal(expected, Program.AnalyzeExitCode(report, strict, allowIncomplete));
    }

    // The scan-package projection of the same precedence rule, using the package-level incompleteness source
    // (an unavailable vulnerability check) rather than a skipped method.
    [Theory]
    [InlineData(false, false, false, 0)]
    [InlineData(false, false, true, 0)]
    [InlineData(false, true, false, 3)]
    [InlineData(false, true, true, 0)]
    [InlineData(true, false, false, 2)]
    [InlineData(true, false, true, 2)]
    [InlineData(true, true, false, 2)]   // PRECEDENCE: 2 beats 3
    [InlineData(true, true, true, 2)]    // --allow-incomplete does not undo an already-tripped --strict gate
    public void ScanPackageExitCode_GatingIndicatorFinding_PrecedesIncompleteness(
        bool strict, bool incomplete, bool allowIncomplete, int expected)
    {
        var analyzed = Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0) with
        {
            Indicators = SoleFinding(IndicatorCategory.CallbackDomain, "lib/net10.0/A.dll")
        };
        var report = PackageWith(
            [analyzed], vulnStatus: incomplete ? VulnerabilityScanStatus.Unavailable : VulnerabilityScanStatus.Completed);

        Assert.Equal(expected, Program.ScanPackageExitCode(report, strict, allowIncomplete));
    }
    #endregion

    #region Methods — F: package-level aggregation of a gating finding
    // A package with one gating-clean assembly and one gating-tripped assembly (DynamicDns, to exercise a category
    // other than CallbackDomain here too) gates as a whole — mirrors AllFindings'/ScanPackageExitCode's own "across
    // every analyzed assembly" posture.
    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void ScanPackageExitCode_OneCleanAssemblyAndOneGatingTrippedAssembly_GatesAsAWhole(bool strict, int expected)
    {
        const string cleanPath = "lib/net10.0/A.dll";
        const string trippedPath = "lib/net10.0/B.dll";
        var clean = Analyzed(cleanPath, methodsTotal: 5, methodsSkipped: 0) with
        {
            Indicators = new IndicatorReport(cleanPath, cleanPath, Epoch, [], Truncated: false)
        };
        var tripped = Analyzed(trippedPath, methodsTotal: 5, methodsSkipped: 0) with
        {
            Indicators = SoleFinding(IndicatorCategory.DynamicDns, trippedPath)
        };
        var report = Package(clean, tripped);

        Assert.Equal(expected, Program.ScanPackageExitCode(report, strict, allowIncomplete: false));
    }

    // The truncated-indicator-report fixture's single finding is a CallbackDomain — a gating category. Truncation
    // means the report is a FLOOR, not that its findings are provisional: the one finding it DID record is real, so
    // it gates under --strict exactly like an untruncated report would. Deliberately pinned as a genuine gate, not
    // as "unaffected" (which is what this same fixture used to assert, before ADR 0026 narrowed the gate).
    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void AnalyzeExitCode_TruncatedIndicatorReport_CallbackDomainFinding_GatesUnderStrict(bool strict, int expected)
    {
        var report = CleanAssembly() with
        {
            Indicators = new IndicatorReport(
                "Sample.dll", "lib/net10.0/Sample.dll", Epoch, [FindingOf(IndicatorCategory.CallbackDomain)], Truncated: true)
        };

        Assert.Equal(expected, Program.AnalyzeExitCode(report, strict, allowIncomplete: false));
    }

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 0)]
    public void ScanPackageExitCode_TruncatedIndicatorReport_CallbackDomainFinding_GatesUnderStrict(bool strict, int expected)
    {
        const string relativePath = "lib/net10.0/A.dll";
        var analyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0) with
        {
            Indicators = new IndicatorReport(
                relativePath, relativePath, Epoch, [FindingOf(IndicatorCategory.CallbackDomain)], Truncated: true)
        };
        var report = Package(analyzed);

        Assert.Equal(expected, Program.ScanPackageExitCode(report, strict, allowIncomplete: false));
    }
    #endregion

    #region Methods — helpers
    private static AssemblyAnalysisReport CleanAssembly() => AssemblyReport(methodsTotal: 5, methodsSkipped: 0);

    private static PackageCapabilityReport CleanPackage(string? tier = null)
    {
        const string relativePath = "lib/net10.0/A.dll";
        var analyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0);
        if (tier is not null)
            analyzed = analyzed with { Indicators = NonGatingIndicatorsFor(tier, relativePath) };
        return Package(analyzed);
    }

    // A package carrying exactly one packaged assembly whose Indicators are exactly one finding of the given
    // category — the scan-package projection of SoleFinding, used by the per-category positive/refusal tests above.
    private static PackageCapabilityReport PackageWithSoleFinding(IndicatorCategory category)
    {
        const string relativePath = "lib/net10.0/A.dll";
        var analyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0) with
        {
            Indicators = SoleFinding(category, relativePath)
        };
        return Package(analyzed);
    }

    // An IndicatorReport carrying exactly one finding of the given category — isolates the category under test from
    // every other source, per the task's "no capability, obfuscation, script, YARA or vulnerability findings" premise.
    private static IndicatorReport SoleFinding(IndicatorCategory category, string path = "lib/net10.0/Sample.dll") =>
        new(path, path, Epoch, [FindingOf(category)], Truncated: false);

    private static IndicatorFinding FindingOf(IndicatorCategory category) =>
        new(category, SampleValueFor(category), $"see {SampleValueFor(category)}", "Evil.Loader", "M", 1);

    // Category-appropriate placeholder values. IsGatingIndicatorCategory / IsDiscriminatingIndicatorCategory key ONLY
    // on IndicatorFinding.Category (see ReportTheme.cs), never on Value, so these values are arbitrary and chosen
    // purely for readability — not load-bearing for any assertion in this file.
    private static string SampleValueFor(IndicatorCategory category) => category switch
    {
        IndicatorCategory.CallbackDomain => "x.pipedream.net",
        IndicatorCategory.DynamicDns => "x.ngrok-free.app",
        IndicatorCategory.CredentialPath => ".aws/credentials",
        IndicatorCategory.ExfilSink => "https://discord.com/api/webhooks/1/2",
        IndicatorCategory.RawCodeHost => "https://raw.githubusercontent.com/x/y/main/icon.png",
        IndicatorCategory.PublicIpLiteral => "8.8.8.8",
        IndicatorCategory.AutorunRegistry => @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        IndicatorCategory.GenericUrl => "example.com",
        IndicatorCategory.PrivateIpLiteral => "10.0.0.5",
        IndicatorCategory.ReflectionTypeName => "System.Net.WebClient",
        _ => throw new System.ArgumentOutOfRangeException(nameof(category)),
    };

    // The non-gating tier names covered by the invariance matrices above: the noisy tier plus each of the four
    // discriminating-but-refused categories individually, plus a mix of several of them together.
    private static readonly string[] NonGatingTiers =
        ["noisy", "exfilsink", "rawcodehost", "publicip", "autorun", "mixed-non-gating"];

    private static IndicatorReport NonGatingIndicatorsFor(string tier, string path = "lib/net10.0/Sample.dll") => tier switch
    {
        "noisy" => new IndicatorReport(path, path, Epoch, [FindingOf(IndicatorCategory.GenericUrl)], Truncated: false),
        "exfilsink" => new IndicatorReport(path, path, Epoch, [FindingOf(IndicatorCategory.ExfilSink)], Truncated: false),
        "rawcodehost" => new IndicatorReport(path, path, Epoch, [FindingOf(IndicatorCategory.RawCodeHost)], Truncated: false),
        "publicip" => new IndicatorReport(path, path, Epoch, [FindingOf(IndicatorCategory.PublicIpLiteral)], Truncated: false),
        "autorun" => new IndicatorReport(path, path, Epoch, [FindingOf(IndicatorCategory.AutorunRegistry)], Truncated: false),
        "mixed-non-gating" => new IndicatorReport(
            path, path, Epoch,
            [
                FindingOf(IndicatorCategory.GenericUrl),
                FindingOf(IndicatorCategory.ExfilSink),
                FindingOf(IndicatorCategory.PublicIpLiteral),
                FindingOf(IndicatorCategory.PrivateIpLiteral),
            ],
            Truncated: false),
        _ => throw new System.ArgumentOutOfRangeException(nameof(tier)),
    };
    #endregion

    #region Fields
    private static readonly bool[] Flags = [false, true];

    private static readonly ApiCallFinding CapabilityFinding =
        new(Capability.FileSystem, ApiCallKind.Call, "T", "M", "System.IO.File.ReadAllText");
    #endregion
}
