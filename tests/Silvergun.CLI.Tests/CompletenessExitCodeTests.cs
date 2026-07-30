namespace Silvergun.CLI.Tests;

using System.Collections.Generic;
using System.IO;
using System.Linq;

using Spectre.Console;

using Silvergun.CLI;
using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// Tests for the exit-code half of ADR 0024: the pure <see cref="Program.ScanExitCode"/> truth table (including the
/// <b>2 beats 3</b> precedence and the two new defaulted parameters), the <c>analyze</c> scenarios that produce
/// exit 3, and — the highest-value test in the set — the <b>mechanical invariant</b> that stops the exit code and the
/// report footer drifting apart.
/// <para>
/// <b>Why the analyze scenarios construct a <see cref="CapabilityReport"/> directly.</b> ⚠️ The original rationale
/// here — "<c>MethodsSkipped &gt; 0</c> is not reachable from any fixture assembly, because
/// <c>AssemblyAnalyzer.Methods</c> dereferences <c>m.Body</c> while building the method list, so a body that cannot
/// be read fails the whole assembly (exit 1, no report)" — was true when measured on 2026-07-29 and is <b>no longer
/// true</b>. <c>docs/agent/tasks/per-method-body-read-granularity.md</c> made <c>Methods</c> a metadata-only
/// candidate set and moved the body read into each consumer's per-method guard
/// (<c>AssemblyAnalyzer.TryReadBody</c>), so an unreadable body is now counted and skipped rather than fatal, and
/// <c>MethodsSkipped &gt; 0</c> <b>is</b> reachable — from an assembly with an out-of-range fat-header
/// <c>CodeSize</c>, patched at test time and driven end-to-end in <see cref="UnreadableMethodBodyCliTests"/>
/// (measured 2026-07-30: exit 3, "Not verified", <c>2/3 (1 not analyzed)</c>).
/// </para>
/// <para>
/// Constructed report data remains the right shape <b>for these particular tests</b>, on different grounds: they
/// pin the <em>truth table</em> of a pure predicate over arbitrary <c>(MethodsTotal, MethodsSkipped)</c> pairs and
/// flag combinations. Driving that from real analysis would tie the table to whatever one fixture happens to
/// measure, make the numbers move whenever a fixture gains a method, and cost a child process per row. The
/// reachability of the state these tests describe is covered where it belongs — end to end, in the CLI tests above.
/// </para>
/// <para>
/// <b>NOTE ON SHAPE:</b> these tests call the SHIPPED seams <see cref="Program.AnalyzeExitCode"/> and
/// <see cref="Program.ScanPackageExitCode"/> — the very methods <c>Program.RunAnalyze</c>/<c>RunScanPackage</c> return.
/// They used to hold hand-written replicas of those two call sites, which made the "mechanical invariant" below a
/// check between two test-local definitions: a THIRD copy of the gate predicate that could silently drift from what
/// ships. Both seams take <c>strict</c> and <c>allowIncomplete</c> WITHOUT defaults, so every call below states which
/// gate it is exercising.
/// </para>
/// </summary>
public sealed class CompletenessExitCodeTests
{
    #region Methods — ScanExitCode pure seam (full truth table)
    // Every combination of (strict, a finding gate, incomplete, allow-incomplete). Expectations are written out
    // literally rather than computed, so the table is an independent statement of the contract:
    //   strict && a gate  => 2 (and it BEATS 3);  else incomplete && !allow => 3;  else 0.
    [Theory]
    [InlineData(false, false, false, false, 0)]
    [InlineData(false, false, false, true, 0)]
    [InlineData(false, false, true, false, 3)]   // exit 3 is NOT gated on --strict
    [InlineData(false, false, true, true, 0)]    // --allow-incomplete downgrades 3 -> 0
    [InlineData(false, true, false, false, 0)]   // findings without --strict never gate (ADR 0003)
    [InlineData(false, true, false, true, 0)]
    [InlineData(false, true, true, false, 3)]
    [InlineData(false, true, true, true, 0)]
    [InlineData(true, false, false, false, 0)]
    [InlineData(true, false, false, true, 0)]
    [InlineData(true, false, true, false, 3)]
    [InlineData(true, false, true, true, 0)]
    [InlineData(true, true, false, false, 2)]
    [InlineData(true, true, false, true, 2)]
    [InlineData(true, true, true, false, 2)]     // PRECEDENCE: a tripped gate is accurate and actionable — 2 beats 3
    [InlineData(true, true, true, true, 2)]
    public void ScanExitCode_FullTruthTable(bool strict, bool gate, bool incomplete, bool allow, int expected) =>
        Assert.Equal(expected, Program.ScanExitCode(
            strict, hasCapabilityFindings: gate, hasObfuscation: false, hasScriptFindings: false,
            hasYaraFindings: false, hasVulnerabilities: false,
            isIncomplete: incomplete, allowIncomplete: allow));

    // The precedence rule must hold for EVERY gate, not just the capability one: whichever gate trips, the verdict
    // (2) is reported and the incompleteness stays a caveat in the report rather than hiding it behind 3.
    [Theory]
    [InlineData(true, false, false, false, false)]   // capability
    [InlineData(false, true, false, false, false)]   // obfuscation
    [InlineData(false, false, true, false, false)]   // script
    [InlineData(false, false, false, true, false)]   // YARA
    [InlineData(false, false, false, false, true)]   // known vulnerability
    public void ScanExitCode_StrictGateBeatsIncomplete_ForEveryGate(
        bool cap, bool obf, bool script, bool yara, bool vuln) =>
        Assert.Equal(2, Program.ScanExitCode(
            strict: true, cap, obf, script, yara, vuln, isIncomplete: true, allowIncomplete: false));

    // Exit 3 is a statement about the TOOL, not a policy verdict, so it does not need --strict: someone who opted out
    // of findings gating has not opted out of being told coverage was partial.
    [Fact]
    public void ScanExitCode_IncompleteWithoutStrictAndWithoutAnyFinding_ReturnsThree() =>
        Assert.Equal(3, Program.ScanExitCode(
            strict: false, hasCapabilityFindings: false, hasObfuscation: false, hasScriptFindings: false,
            hasYaraFindings: false, hasVulnerabilities: false, isIncomplete: true));

    // The two new parameters default to false, so every pre-existing caller (check-squat, and the shipped tests)
    // keeps its exact result: omitting them must equal the 6-argument call.
    [Theory]
    [InlineData(true, false, false, false, false, false)]
    [InlineData(true, true, false, false, false, false)]
    [InlineData(false, true, true, true, true, true)]
    [InlineData(true, false, false, false, true, true)]
    public void ScanExitCode_IncompletenessArgsDefaultFalse_MatchesSixArgOverload(
        bool strict, bool cap, bool obf, bool script, bool yara, bool vuln) =>
        Assert.Equal(
            Program.ScanExitCode(strict, cap, obf, script, yara, vuln),
            Program.ScanExitCode(strict, cap, obf, script, yara, vuln, isIncomplete: false, allowIncomplete: false));
    #endregion

    #region Methods — analyze scenarios (the live false-clean, now exit 3)
    // The headline case: an assembly where some methods could not be analyzed and nothing was found is NOT clean.
    // Before ADR 0024 this exited 0 with a "Clean" footer.
    [Fact]
    public void Analyze_WhenMethodsCouldNotBeAnalyzedAndNoFindings_ExitsThree()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 3);

        Assert.Equal(3, Program.AnalyzeExitCode(report, strict: false, allowIncomplete: false));
    }

    // --allow-incomplete suppresses the GATE, never the DISCLOSURE: exit 0, but the footer still reads "Not verified"
    // and still names the gap. (The renderer takes no allow-incomplete argument at all, so the disclosure is
    // structurally unsuppressible — that is the design, and this test pins it.)
    [Fact]
    public void Analyze_WhenIncompleteWithAllowIncomplete_ExitsZeroButStillPrintsCaveats()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 3);
        var (console, writer) = PlainConsole();

        var exit = Program.AnalyzeExitCode(report, strict: false, allowIncomplete: true);
        AssemblyReportRenderer.Render(console, report);

        Assert.Equal(0, exit);
        // The disclosure, asserted as the whole verdict LINE (see FooterHeadline): the exit code was un-gated, the
        // headline still reads "Not verified" and still names the gap.
        Assert.Equal(
            FooterHeadline.NotVerified(console, "3 of 120 method(s) could not be analyzed"),
            FooterHeadline.Of(writer));
        Assert.Contains("117/120", writer.ToString());
    }

    // Precedence end-to-end on the analyze call site: a tripped --strict gate reports 2 even though the analysis was
    // also incomplete. The caveat is still in the report; the verdict is not hidden behind a coverage code.
    [Fact]
    public void Analyze_WhenStrictGateTripsAndAnalysisIncomplete_ExitsTwo()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 3, findings: [CapabilityFinding]);

        Assert.Equal(2, Program.AnalyzeExitCode(report, strict: true, allowIncomplete: false));
    }

    [Fact]
    public void Analyze_WhenCompleteAndNoFindings_ExitsZero()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 0);

        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: false, allowIncomplete: false));
        Assert.Equal(0, Program.AnalyzeExitCode(report, strict: true, allowIncomplete: false));
    }

    // A failed obfuscation analysis alone is enough: "best-effort" is not "verified".
    [Fact]
    public void Analyze_WhenObfuscationAnalysisDidNotComplete_ExitsThree()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 0, obfuscation: false);

        Assert.Equal(3, Program.AnalyzeExitCode(report, strict: false, allowIncomplete: false));
    }

    // The sixth caveat source at the exit-code seam, and a failed metadata read alone is enough for the same reason:
    // a report cannot claim "Clean" when the identity facts it prints were never read.
    //
    // ⚠️ WHY THIS IS COVERED AT THE SEAM AND NOT END-TO-END (measured 2026-07-29): the metadata read in
    // Program.RunAnalyze runs only AFTER AssemblyAnalyzer.Load has already succeeded, and the two apply the SAME
    // acceptance test to the SAME path — a fresh PeReader.DefaultHost plus an identical Dummy.Module/Dummy.Assembly
    // rejection (AssemblyAnalyzer.cs:61-77 vs AssemblyMetadata.cs:37-50). Every input whose metadata read fails
    // therefore fails the load FIRST and exits 1 with no report at all (pinned end-to-end by
    // CompletenessCliTests.Analyze_WhenTheInputCannotBeLoaded_ExitsOneWithNoReport). Reaching only the metadata read
    // would need a module CCI loads but whose reference/custom-attribute projection throws — a hand-crafted hostile
    // PE, which is not faked here.
    [Fact]
    public void Analyze_WhenAssemblyMetadataCouldNotBeRead_ExitsThree()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 0, metadata: false);

        Assert.Equal(3, Program.AnalyzeExitCode(report, strict: false, allowIncomplete: false));
    }

    // ... and --allow-incomplete downgrades that 3 to 0 while the footer still says "Not verified" and names the gap.
    [Fact]
    public void Analyze_WhenMetadataCouldNotBeReadWithAllowIncomplete_ExitsZeroButStillPrintsCaveats()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 0, metadata: false);
        var (console, writer) = PlainConsole();

        var exit = Program.AnalyzeExitCode(report, strict: false, allowIncomplete: true);
        AssemblyReportRenderer.Render(console, report);

        Assert.Equal(0, exit);
        Assert.Equal(
            FooterHeadline.NotVerified(console, "the assembly metadata could not be read"),
            FooterHeadline.Of(writer));
    }
    #endregion

    #region Methods — scan-package scenarios
    [Theory]
    [InlineData(VulnerabilityScanStatus.Unavailable)]
    [InlineData(VulnerabilityScanStatus.NotChecked)]
    public void ScanPackage_WhenVulnerabilityDataNotObtained_ExitsThree(VulnerabilityScanStatus status) =>
        Assert.Equal(3, Program.ScanPackageExitCode(
            PackageWith(vulnStatus: status), strict: false, allowIncomplete: false));

    [Fact]
    public void ScanPackage_WhenTransitiveWalkPartial_ExitsThree() =>
        Assert.Equal(3, Program.ScanPackageExitCode(
            PackageWith(resolution: DependencyResolutionStatus.Partial), strict: false, allowIncomplete: false));

    [Fact]
    public void ScanPackage_WhenOneAssemblyHasSkippedMethods_ExitsThree() =>
        Assert.Equal(3, Program.ScanPackageExitCode(
            Package(
                Analyzed("lib/net10.0/A.dll", methodsTotal: 20, methodsSkipped: 0),
                Analyzed("lib/net10.0/B.dll", methodsTotal: 10, methodsSkipped: 2)),
            strict: false, allowIncomplete: false));

    // A package of only native binaries: nothing was looked inside, so it must not be reported as a clean run.
    [Fact]
    public void ScanPackage_WhenOnlyContentCouldNotBeAnalysed_ExitsThree() =>
        Assert.Equal(3, Program.ScanPackageExitCode(
            Package(Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly.")),
            strict: false, allowIncomplete: false));

    // One packaged assembly whose metadata read failed while its capability analysis succeeded (PackageScanner reads
    // metadata best-effort in every path) — the package projection of the sixth caveat source.
    [Fact]
    public void ScanPackage_WhenOneAssemblysMetadataCouldNotBeRead_ExitsThree() =>
        Assert.Equal(3, Program.ScanPackageExitCode(
            Package(
                Analyzed("lib/net10.0/A.dll", methodsTotal: 20, methodsSkipped: 0),
                Analyzed("lib/net10.0/B.dll", methodsTotal: 10, methodsSkipped: 0, metadata: false)),
            strict: false, allowIncomplete: false));

    [Fact]
    public void ScanPackage_WhenCompleteAndNoFindings_ExitsZero() =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 7, methodsSkipped: 0)),
            strict: false, allowIncomplete: false));

    [Fact]
    public void ScanPackage_WhenIncompleteWithAllowIncomplete_ExitsZero() =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWith(vulnStatus: VulnerabilityScanStatus.NotChecked), strict: false, allowIncomplete: true));
    #endregion

    #region Methods — the mechanical invariant (spec criterion 3)
    // ADR 0024's load-bearing claim is that the exit code and the footer are two projections of ONE predicate. This
    // is the test that stops them drifting: over a matrix of real report shapes crossed with every flag combination,
    // "exit 0" is checked against the assessment AND against what the footer actually printed. The exit code comes
    // from the SHIPPED seams (Program.AnalyzeExitCode/ScanPackageExitCode) — with a test-local replica of the gate
    // this would only ever have compared two copies of the same test's own arithmetic.
    //
    // The equivalence is stated per flag combination, because each flag opts out of one projection:
    //   (strict, !allow)   exit 0 <=> IsComplete && !attention   <-- THE ADR 0024 invariant: exit 0 <=> footer "Clean"
    //   (!strict, !allow)  exit 0 <=> IsComplete                 findings do not gate without --strict (ADR 0003)
    //   (strict, allow)    exit 0 <=> !attention                 --allow-incomplete drops the coverage gate only
    //   (!strict, allow)   exit 0 always                         both gates off; only exit 1 remains reachable
    // Writing the unqualified "exit 0 <=> IsComplete && !attention" for all four would be FALSE for three of them —
    // ADR 0003 deliberately exits 0 on an informational run that found something.
    //
    // The shapes use Script-sourced script findings on purpose: findings from the .nuspec (Source=PackageMetadata) are
    // advisory and show in the footer WITHOUT gating --strict (docs/agent/tasks/script-rule-precision.md), a separate
    // pre-existing divergence that is not what this invariant is about.

    public static IEnumerable<object[]> AssemblyMatrix() =>
        from shape in new[]
        {
            "complete", "complete+findings", "skipped-methods", "skipped-methods+findings",
            "obfuscation-null", "obfuscation-null+findings", "metadata-null", "metadata-null+findings",
        }
        from strict in Flags
        from allow in Flags
        select new object[] { shape, strict, allow };

    [Theory]
    [MemberData(nameof(AssemblyMatrix))]
    public void Invariant_Analyze_ExitZeroMatchesTheAssessmentAndTheFooter(string shape, bool strict, bool allow)
    {
        var report = AssemblyShape(shape);
        var assessment = CompletenessAssessment.ForAssembly(report);
        var attention = report.Capabilities.Findings.Count > 0 || (report.Obfuscation?.Findings.Count ?? 0) > 0;
        var (console, writer) = PlainConsole();

        var exit = Program.AnalyzeExitCode(report, strict, allow);
        AssemblyReportRenderer.Render(console, report);

        AssertInvariant(shape, strict, allow, exit, assessment.IsComplete, attention, writer.ToString());
    }

    public static IEnumerable<object[]> PackageMatrix() =>
        from shape in new[]
        {
            "complete", "complete+findings", "not-checked", "not-checked+findings", "skipped-file",
            "skipped-file+script-findings", "partial-transitive", "metadata-null",
        }
        from strict in Flags
        from allow in Flags
        select new object[] { shape, strict, allow };

    [Theory]
    [MemberData(nameof(PackageMatrix))]
    public void Invariant_ScanPackage_ExitZeroMatchesTheAssessmentAndTheFooter(string shape, bool strict, bool allow)
    {
        var report = PackageShape(shape);
        var assessment = CompletenessAssessment.ForPackage(report);
        var attention = report.AllFindings.Any() || report.ScriptFindings.Count > 0
            || report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0)
            || report.YaraFindings.Count > 0 || report.Vulnerabilities.Count > 0;
        var (console, writer) = PlainConsole();

        var exit = Program.ScanPackageExitCode(report, strict, allow);
        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        AssertInvariant(shape, strict, allow, exit, assessment.IsComplete, attention, writer.ToString());
    }

    private static void AssertInvariant(
        string shape, bool strict, bool allow, int exit, bool isComplete, bool attention, string output)
    {
        var expectZero = (strict, allow) switch
        {
            (true, false) => isComplete && !attention,
            (false, false) => isComplete,
            (true, true) => !attention,
            (false, true) => true,
        };
        var because = $"shape '{shape}' with strict={strict}, allow-incomplete={allow} (complete={isComplete}, attention={attention})";

        Assert.True(expectZero == (exit == 0), $"exit {exit} disagrees with the assessment for {because}.");
        Assert.Equal(strict && attention ? 2 : expectZero ? 0 : 3, exit);   // 2 beats 3; nothing else is reachable here

        // The footer half of the same predicate: "Clean" exactly when complete and nothing gated, "Not verified"
        // exactly when finding-free but incomplete. Under (strict, !allow) these two assertions together ARE
        // "exit 0 <=> the footer says Clean".
        //
        // Asserted on the ONE verdict headline, not on the whole report: a substring test would be satisfied (or
        // defeated) by the token appearing in any caveat, path or table cell, and FooterHeadline.Of also states that
        // the report printed exactly one verdict — two verdicts in one report would be a defect of its own.
        var headline = FooterHeadline.Of(output);
        Assert.True(
            (isComplete && !attention) == FooterHeadline.IsClean(headline),
            $"footer headline '{headline}' disagrees with a Clean verdict for {because}.");
        Assert.True(
            (!isComplete && !attention) == FooterHeadline.IsNotVerified(headline),
            $"footer headline '{headline}' disagrees with a Not-verified verdict for {because}.");
    }

    private static AssemblyAnalysisReport AssemblyShape(string shape) => shape switch
    {
        "complete" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0),
        "complete+findings" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0, findings: [CapabilityFinding]),
        "skipped-methods" => AssemblyReport(methodsTotal: 10, methodsSkipped: 4),
        "skipped-methods+findings" => AssemblyReport(methodsTotal: 10, methodsSkipped: 4, findings: [CapabilityFinding]),
        "obfuscation-null" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0, obfuscation: false),
        "obfuscation-null+findings" => AssemblyReport(
            methodsTotal: 10, methodsSkipped: 0, obfuscation: false, findings: [CapabilityFinding]),
        "metadata-null" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0, metadata: false),
        "metadata-null+findings" => AssemblyReport(
            methodsTotal: 10, methodsSkipped: 0, metadata: false, findings: [CapabilityFinding]),
        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "unknown assembly shape"),
    };

    private static PackageCapabilityReport PackageShape(string shape) => shape switch
    {
        "complete" => Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0)),
        "complete+findings" => Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0, findings: [CapabilityFinding])),
        "not-checked" => PackageWith(vulnStatus: VulnerabilityScanStatus.NotChecked),
        "not-checked+findings" => PackageWith(
            new[] { Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0, findings: [CapabilityFinding]) },
            vulnStatus: VulnerabilityScanStatus.NotChecked),
        "skipped-file" => Package(Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly.")),
        "skipped-file+script-findings" => PackageWith(
            new[] { Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly.") },
            scriptFindings: [ScriptContentFinding]),
        "partial-transitive" => PackageWith(resolution: DependencyResolutionStatus.Partial),
        "metadata-null" => Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0, metadata: false)),
        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "unknown package shape"),
    };
    #endregion

    #region Methods — console helper
    private static (IAnsiConsole Console, StringWriter Writer) PlainConsole()
    {
        var writer = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });
        console.Profile.Width = 240;
        return (console, writer);
    }
    #endregion

    #region Fields
    private static readonly bool[] Flags = [false, true];

    private static readonly ApiCallFinding CapabilityFinding =
        new(Capability.FileSystem, ApiCallKind.Call, "T", "M", "System.IO.File.ReadAllText");

    private static readonly ScriptFinding ScriptContentFinding = new(
        "SIL9001", "A rule", "Critical", "High", "tools/install.ps1", 3, "excerpt", [],
        Occurrences: 1, Source: ScriptFindingSource.Script);
    #endregion
}
