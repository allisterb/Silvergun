namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CLI;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// ADR 0031 decision 3 is a <b>promise</b>: "<c>--strict</c> is NOT changed by this ADR", because nothing gates
/// until its benign prevalence is measured on the top-100 corpus. A promise kept only by everyone remembering it is
/// not kept, so this file is the promise written down as executable assertions — the same shape
/// <see cref="IndicatorExitCodeInvarianceTests"/> uses for the indicator categories that were evidentially refused
/// a gate.
///
/// <para>Two complementary forms, deliberately:
/// <list type="bullet">
/// <item>an <b>equality</b> over the whole flag matrix ("same exit code with and without the anomalies attached"),
/// so it cannot drift from whatever the gate predicate currently does; and</item>
/// <item>a <b>literal 0</b> for a clean, fully-verified package whose only findings are anomalies, so a future
/// change that makes any category gate fails here with an unambiguous wrong number rather than quietly satisfying
/// an equality against a baseline that moved with it.</item>
/// </list></para>
///
/// <para>If a follow-up ADR promotes a category to gating after prevalence is measured, this file and
/// <see cref="PackagingAnomaliesReportRendererTests.PackageRenderer_WithPackagingAnomalies_StillReportsTheCleanVerdict"/>
/// are the two places that must change together — and changing them should be a deliberate act, which is the
/// point.</para>
/// </summary>
public sealed class PackagingAnomalyExitCodeInvarianceTests
{
    #region Methods — literal 0: no category gates, under --strict or otherwise
    // Each category entirely alone, on a clean and fully-verified package: 0 under --strict and 0 without.
    // Enumerated from the live enum, so a category added later is covered without editing this test — and lands
    // here as a FAILURE if it was wired into the gate.
    public static IEnumerable<object[]> EveryCategoryAndStrictFlag() =>
        from category in Enum.GetValues<PackagingAnomalyCategory>()
        from strict in Flags
        select new object[] { category, strict };

    [Theory]
    [MemberData(nameof(EveryCategoryAndStrictFlag))]
    public void ScanPackageExitCode_ASingleAnomalyOfAnyCategory_NeverGatesEvenUnderStrict(
        PackagingAnomalyCategory category, bool strict) =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            CleanPackage() with { PackagingAnomalies = [AnomalyOf(category)] }, strict, allowIncomplete: false));

    // ...and all seven at once, several times over, is still 0. A gate keyed on "any anomaly at all" (rather than on
    // one category) would survive the per-category test above only if it also survived this one.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ScanPackageExitCode_EveryCategoryAtOnce_NeverGatesEvenUnderStrict(bool strict) =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            CleanPackage() with { PackagingAnomalies = AllCategories() }, strict, allowIncomplete: false));
    #endregion

    #region Methods — equality: attaching anomalies never changes the answer, whatever else is going on
    // The surviving equality invariant across the full flag matrix and every base shape: a package that is clean,
    // one that already has capability findings, one that is incomplete (an unavailable OSV check), and one that is
    // both. Anomalies must not move the exit code in ANY of them — including the rows where another gate has
    // already tripped, where an accidental contribution would be invisible to a "compare against 0" test.
    //
    // ⚠️ The "findings" shape does NOT reach exit 2: its capability finding stopped gating in ADR 0027, so before
    // the YARA and vulnerability shapes were added this equality never once spanned the gated row it advertised —
    // every one of its rows compared 0 against 0 or 3 against 3. Shapes_SpanEveryExitCode below is what keeps that
    // from silently happening again.
    public static IEnumerable<object[]> FlagMatrixAndShapes() =>
        from strict in Flags
        from allow in Flags
        from shape in Shapes
        select new object[] { strict, allow, shape };

    [Theory]
    [MemberData(nameof(FlagMatrixAndShapes))]
    public void ScanPackageExitCode_IsUnaffectedByPackagingAnomalies(bool strict, bool allowIncomplete, string shape)
    {
        var bare = PackageOfShape(shape);
        var withAnomalies = bare with { PackagingAnomalies = AllCategories() };

        Assert.Equal(
            Program.ScanPackageExitCode(bare, strict, allowIncomplete),
            Program.ScanPackageExitCode(withAnomalies, strict, allowIncomplete));
    }

    // The same equality per category, so a single mis-wired category cannot hide behind the six others in the
    // all-at-once fixture above.
    public static IEnumerable<object[]> EveryCategoryAndFlagMatrix() =>
        from category in Enum.GetValues<PackagingAnomalyCategory>()
        from strict in Flags
        from allow in Flags
        select new object[] { category, strict, allow };

    [Theory]
    [MemberData(nameof(EveryCategoryAndFlagMatrix))]
    public void ScanPackageExitCode_IsUnaffectedByAnyOneCategory(
        PackagingAnomalyCategory category, bool strict, bool allowIncomplete)
    {
        var bare = CleanPackage();
        var withAnomaly = bare with { PackagingAnomalies = [AnomalyOf(category)] };

        Assert.Equal(
            Program.ScanPackageExitCode(bare, strict, allowIncomplete),
            Program.ScanPackageExitCode(withAnomaly, strict, allowIncomplete));
    }

    // The guard on the fixture itself, and the reason the two gating shapes exist: the shape set must actually
    // REACH every exit code this equality claims to span. Written as a set assertion over the whole matrix so a
    // shape that stops gating (as "findings" did the day ADR 0027 landed) turns this red instead of quietly
    // reducing the invariance tests above to "0 equals 0".
    [Fact]
    public void Shapes_SpanEveryExitCode()
    {
        var codes = (from strict in Flags
                     from allow in Flags
                     from shape in Shapes
                     select Program.ScanPackageExitCode(PackageOfShape(shape), strict, allow))
                    .Distinct()
                    .Order()
                    .ToArray();

        Assert.Equal([0, 2, 3], codes);
    }

    // ...and specifically: the gating shapes gate under --strict and only under --strict, so the equality rows that
    // carry them are genuinely exercising the exit-2 branch rather than a coincidence of some other gate.
    [Theory]
    [InlineData("yara")]
    [InlineData("vulnerable")]
    public void ScanPackageExitCode_ForAGatingShape_IsTwoUnderStrictAndZeroWithout(string shape)
    {
        Assert.Equal(2, Program.ScanPackageExitCode(PackageOfShape(shape), strict: true, allowIncomplete: false));
        Assert.Equal(0, Program.ScanPackageExitCode(PackageOfShape(shape), strict: false, allowIncomplete: false));
    }

    // The exit-2 row of the equality, stated on its own: a package whose YARA hit has already tripped the gate
    // must return the SAME 2 with seven packaging anomalies bolted on. An accidental contribution from an anomaly
    // is invisible in a comparison against 0, which is exactly the row that was missing.
    [Theory]
    [InlineData("yara", true, false)]
    [InlineData("yara", true, true)]
    [InlineData("vulnerable", true, false)]
    [InlineData("yara+incomplete", true, false)]
    [InlineData("yara+incomplete", true, true)]
    public void ScanPackageExitCode_OnAnAlreadyGatedPackage_StaysTwoWithAnomaliesAttached(
        string shape, bool strict, bool allowIncomplete)
    {
        var bare = PackageOfShape(shape);
        var withAnomalies = bare with { PackagingAnomalies = AllCategories() };

        Assert.Equal(2, Program.ScanPackageExitCode(bare, strict, allowIncomplete));
        Assert.Equal(2, Program.ScanPackageExitCode(withAnomalies, strict, allowIncomplete));
    }

    // An anomaly must not turn a merely-INCOMPLETE package (exit 3) into a findings verdict (exit 2), nor suppress
    // the incompleteness code: the coverage answer and the verdict answer are independent of this finding class.
    [Theory]
    [InlineData(false, false, 3)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 3)]
    [InlineData(true, true, 0)]
    public void ScanPackageExitCode_AnomaliesOnAnIncompletePackage_LeaveTheCoverageCodeIntact(
        bool strict, bool allowIncomplete, int expected) =>
        Assert.Equal(expected, Program.ScanPackageExitCode(
            PackageOfShape("incomplete") with { PackagingAnomalies = AllCategories() }, strict, allowIncomplete));
    #endregion

    #region Methods — helpers
    private static PackageCapabilityReport CleanPackage() =>
        PackageWith([Analyzed("lib/net10.0/A.dll", methodsTotal: 5, methodsSkipped: 0)]);

    private static PackageCapabilityReport PackageOfShape(string shape) => shape switch
    {
        "clean" => CleanPackage(),
        "findings" => PackageWith([Analyzed("lib/net10.0/A.dll", 10, 0, findings: [CapabilityFinding])]),
        "incomplete" => PackageWith(
            [Analyzed("lib/net10.0/A.dll", 10, 0)], vulnStatus: VulnerabilityScanStatus.Unavailable),
        "findings+incomplete" => PackageWith(
            [Analyzed("lib/net10.0/A.dll", 10, 0, findings: [CapabilityFinding])],
            vulnStatus: VulnerabilityScanStatus.Unavailable),
        // The two shapes that actually GATE (ADR 0027 narrowed the gate to YARA hits, known vulnerabilities and
        // three indicator categories), so the equality above spans the exit-2 row it always claimed to. The
        // "findings" shape above does not: its capability finding stopped gating and now only sets the headline.
        "yara" => CleanPackage() with { YaraFindings = [YaraHit] },
        "vulnerable" => CleanPackage() with { Vulnerabilities = [Vulnerability] },
        "yara+incomplete" => PackageWith(
            [Analyzed("lib/net10.0/A.dll", 10, 0)], vulnStatus: VulnerabilityScanStatus.Unavailable)
            with { YaraFindings = [YaraHit] },
        _ => throw new ArgumentOutOfRangeException(nameof(shape)),
    };

    private static PackagingAnomaly[] AllCategories() =>
        [.. Enum.GetValues<PackagingAnomalyCategory>().Select(AnomalyOf)];

    // The values are arbitrary: nothing in Program.ScanPackageExitCode reads them (that is the point), so they are
    // chosen only to look like what the analyzer really emits — escaped text, never a raw hostile character.
    private static PackagingAnomaly AnomalyOf(PackagingAnomalyCategory category) =>
        new(category, @"content/pay\nload.bin", $"{category} detail");
    #endregion

    #region Fields
    private static readonly bool[] Flags = [false, true];

    private static readonly string[] Shapes =
        ["clean", "findings", "incomplete", "findings+incomplete", "yara", "vulnerable", "yara+incomplete"];

    private static readonly ApiCallFinding CapabilityFinding =
        new(Capability.FileSystem, ApiCallKind.Call, "T", "M", "System.IO.File.ReadAllText");

    // A malware-signature hit and a known CVE: the two report-level findings that still fail a --strict build
    // (ADR 0027). The path is written the way the analyzer emits it — escaped, never a raw hostile character.
    private static readonly YaraFinding YaraHit =
        new("Silvergun_Test_Rule", null, "LIMERAT", "LimeRAT", "MALWARE", ["malicious"], @"content/pay\nload.bin");

    private static readonly VulnerabilityFinding Vulnerability =
        new("GHSA-xxxx-yyyy-zzzz", ["CVE-2026-0001"], "A known vulnerability.", "HIGH",
            "Some.Package", "1.0.0", IsDependency: false, References: []);
    #endregion
}
