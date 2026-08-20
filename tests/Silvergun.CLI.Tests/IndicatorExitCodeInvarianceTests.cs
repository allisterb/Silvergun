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
/// <b>The highest-value test in the indicator-cli-integration change</b> (the task spec's own words): indicator
/// findings must never move <see cref="Program.AnalyzeExitCode"/> or <see cref="Program.ScanPackageExitCode"/>,
/// under EVERY combination of <c>--strict</c> / <c>--allow-incomplete</c>, for EITHER tier
/// (<see cref="ReportTheme.IsDiscriminatingIndicatorCategory"/>). Out of scope per the task spec — "the gating
/// decision belongs to an ADR written from the prevalence data" — and the 2026-08-03 ARCHITECT DECISION that widened
/// the headline was explicit that this stays true: <em>"Neither group affects any exit code. Unchanged, and still
/// out of scope."</em>
/// <para>
/// Every assertion here is an EQUALITY between the exit code of a report WITH indicator findings attached and the
/// SAME report WITHOUT them — never a hand-picked expected literal — so the test cannot silently drift from what the
/// gate predicate actually does; it can only ever assert "indicators changed nothing".
/// </para>
/// </summary>
public sealed class IndicatorExitCodeInvarianceTests
{
    #region Methods — analyze: exit code is invariant to Indicators, across every flag combination
    public static IEnumerable<object[]> AnalyzeFlagMatrix() =>
        from strict in Flags
        from allow in Flags
        from tier in new[] { "discriminating", "noisy", "mixed" }
        select new object[] { strict, allow, tier };

    [Theory]
    [MemberData(nameof(AnalyzeFlagMatrix))]
    public void AnalyzeExitCode_IsUnaffectedByIndicatorFindings(bool strict, bool allowIncomplete, string tier)
    {
        var bare = CleanAssembly();
        var withIndicators = bare with { Indicators = IndicatorsFor(tier) };

        var bareExit = Program.AnalyzeExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.AnalyzeExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }

    // The same invariant when the assembly ALSO has real (capability) findings and/or is incomplete — indicators
    // must not change the answer even when other gates are already in play, not just on an otherwise-clean report.
    public static IEnumerable<object[]> AnalyzeFlagMatrixWithOtherFindings() =>
        from strict in Flags
        from allow in Flags
        from tier in new[] { "discriminating", "noisy", "mixed" }
        from shape in new[] { "findings", "incomplete", "findings+incomplete" }
        select new object[] { strict, allow, tier, shape };

    [Theory]
    [MemberData(nameof(AnalyzeFlagMatrixWithOtherFindings))]
    public void AnalyzeExitCode_IsUnaffectedByIndicatorFindings_EvenAlongsideOtherGatesOrIncompleteness(
        bool strict, bool allowIncomplete, string tier, string shape)
    {
        var bare = shape switch
        {
            "findings" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0, findings: [CapabilityFinding]),
            "incomplete" => AssemblyReport(methodsTotal: 10, methodsSkipped: 3),
            "findings+incomplete" => AssemblyReport(methodsTotal: 10, methodsSkipped: 3, findings: [CapabilityFinding]),
            _ => throw new System.ArgumentOutOfRangeException(nameof(shape)),
        };
        var withIndicators = bare with { Indicators = IndicatorsFor(tier) };

        var bareExit = Program.AnalyzeExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.AnalyzeExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }

    // A Truncated indicator report is itself a form of "could not analyse everything" for INDICATORS specifically —
    // but the task spec is explicit that wiring Truncated into completeness/the exit code is OUT OF SCOPE for this
    // task (a separate, seventh caveat source). Pinned as its own case so a future accidental wiring shows up here.
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void AnalyzeExitCode_TruncatedIndicatorReport_DoesNotChangeTheExitCode(bool strict, bool allowIncomplete)
    {
        var bare = CleanAssembly();
        var truncated = bare with
        {
            Indicators = new IndicatorReport(
                "Sample.dll", "lib/net10.0/Sample.dll", Epoch, [Callback("x.pipedream.net")], Truncated: true)
        };

        Assert.Equal(
            Program.AnalyzeExitCode(bare, strict, allowIncomplete),
            Program.AnalyzeExitCode(truncated, strict, allowIncomplete));
    }
    #endregion

    #region Methods — scan-package: exit code is invariant to Indicators, across every flag combination
    public static IEnumerable<object[]> PackageFlagMatrix() =>
        from strict in Flags
        from allow in Flags
        from tier in new[] { "discriminating", "noisy", "mixed" }
        select new object[] { strict, allow, tier };

    [Theory]
    [MemberData(nameof(PackageFlagMatrix))]
    public void ScanPackageExitCode_IsUnaffectedByIndicatorFindings(bool strict, bool allowIncomplete, string tier)
    {
        var bare = CleanPackage();
        var withIndicators = CleanPackage(tier);

        var bareExit = Program.ScanPackageExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.ScanPackageExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }

    // Same invariant with a package that ALSO has other gates tripped (capability finding, YARA, vulnerability,
    // script finding) or is incomplete — indicators must not move the answer in the presence of every other gate.
    public static IEnumerable<object[]> PackageFlagMatrixWithOtherFindings() =>
        from strict in Flags
        from allow in Flags
        from tier in new[] { "discriminating", "noisy", "mixed" }
        from shape in new[] { "findings", "incomplete", "vuln-status" }
        select new object[] { strict, allow, tier, shape };

    [Theory]
    [MemberData(nameof(PackageFlagMatrixWithOtherFindings))]
    public void ScanPackageExitCode_IsUnaffectedByIndicatorFindings_EvenAlongsideOtherGatesOrIncompleteness(
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
            [analyzed with { Indicators = IndicatorsFor(tier, "lib/net10.0/A.dll") }], vulnStatus: vulnStatus);

        var bareExit = Program.ScanPackageExitCode(bare, strict, allowIncomplete);
        var withIndicatorsExit = Program.ScanPackageExitCode(withIndicators, strict, allowIncomplete);

        Assert.Equal(bareExit, withIndicatorsExit);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ScanPackageExitCode_TruncatedIndicatorReport_DoesNotChangeTheExitCode(bool strict, bool allowIncomplete)
    {
        const string relativePath = "lib/net10.0/A.dll";
        var bareAnalyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0);
        var truncatedAnalyzed = bareAnalyzed with
        {
            Indicators = new IndicatorReport(relativePath, relativePath, Epoch, [Callback("x.pipedream.net")], Truncated: true)
        };

        var bare = Package(bareAnalyzed);
        var truncated = Package(truncatedAnalyzed);

        Assert.Equal(
            Program.ScanPackageExitCode(bare, strict, allowIncomplete),
            Program.ScanPackageExitCode(truncated, strict, allowIncomplete));
    }
    #endregion

    #region Methods — helpers
    private static AssemblyAnalysisReport CleanAssembly() => AssemblyReport(methodsTotal: 5, methodsSkipped: 0);

    private static PackageCapabilityReport CleanPackage(string? tier = null)
    {
        const string relativePath = "lib/net10.0/A.dll";
        var analyzed = Analyzed(relativePath, methodsTotal: 5, methodsSkipped: 0);
        if (tier is not null)
            analyzed = analyzed with { Indicators = IndicatorsFor(tier, relativePath) };
        return Package(analyzed);
    }

    private static IndicatorReport IndicatorsFor(string tier, string path = "lib/net10.0/Sample.dll") => tier switch
    {
        "discriminating" => new IndicatorReport(path, path, Epoch, [Callback("x.pipedream.net")], Truncated: false),
        "noisy" => new IndicatorReport(
            path, path, Epoch, [new IndicatorFinding(IndicatorCategory.GenericUrl, "example.com", "see example.com", "T", "M", 1)], Truncated: false),
        "mixed" => new IndicatorReport(
            path, path, Epoch,
            [Callback("x.pipedream.net"), new IndicatorFinding(IndicatorCategory.GenericUrl, "example.com", "see example.com", "T", "M", 1)],
            Truncated: false),
        _ => throw new System.ArgumentOutOfRangeException(nameof(tier)),
    };

    private static IndicatorFinding Callback(string host) =>
        new(IndicatorCategory.CallbackDomain, host, $"beacon to {host}", "Evil.Loader", "Beacon", 1);
    #endregion

    #region Fields
    private static readonly bool[] Flags = [false, true];

    private static readonly ApiCallFinding CapabilityFinding =
        new(Capability.FileSystem, ApiCallKind.Call, "T", "M", "System.IO.File.ReadAllText");
    #endregion
}
