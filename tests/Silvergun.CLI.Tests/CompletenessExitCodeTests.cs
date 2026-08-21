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
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static Silvergun.CLI.Tests.AnalysisCompletenessTests;

/// <summary>
/// Tests for the exit-code half of ADR 0024 (amended by ADR-0027): the pure <see cref="Program.ScanExitCode"/> truth
/// table over its three surviving gate sources (<b>vulnerabilities, YARA findings, gating indicator findings</b> —
/// capability/obfuscation/Script-sourced-script findings were removed from its signature entirely, not defaulted;
/// see <see cref="ProgramTests"/> for those exclusions pinned by name), including the <b>2 beats 3</b> precedence,
/// the <c>analyze</c>/<c>scan-package</c> scenarios that produce exit 3 (including ADR-0027 decision 4's new YARA
/// completeness caveat), and — the highest-value test in the set — the <b>mechanical invariant</b> that stops the
/// exit code and the report footer drifting apart.
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
    // One representative surviving gate (hasYaraFindings) stands in for "a finding gate is set" — the three
    // surviving sources are OR'd together identically (see the predicate), and each is exercised alone/interacting
    // with the others in ProgramTests and ScanExitCode_StrictGateBeatsIncomplete_ForEveryGate below.
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
            strict, hasYaraFindings: gate, hasVulnerabilities: false, hasGatingIndicatorFindings: false,
            isIncomplete: incomplete, allowIncomplete: allow));

    // The precedence rule must hold for EVERY surviving gate (ADR-0027 narrowed this from five sources to three):
    // whichever gate trips, the verdict (2) is reported and the incompleteness stays a caveat in the report rather
    // than hiding it behind 3.
    [Theory]
    [InlineData(true, false, false)]   // YARA finding
    [InlineData(false, true, false)]   // known vulnerability
    [InlineData(false, false, true)]   // gating indicator finding (ADR 0026)
    public void ScanExitCode_StrictGateBeatsIncomplete_ForEveryGate(bool yara, bool vuln, bool gatingIndicator) =>
        Assert.Equal(2, Program.ScanExitCode(
            strict: true, yara, vuln, gatingIndicator, isIncomplete: true, allowIncomplete: false));

    // Exit 3 is a statement about the TOOL, not a policy verdict, so it does not need --strict: someone who opted out
    // of findings gating has not opted out of being told coverage was partial.
    [Fact]
    public void ScanExitCode_IncompleteWithoutStrictAndWithoutAnyFinding_ReturnsThree() =>
        Assert.Equal(3, Program.ScanExitCode(
            strict: false, hasYaraFindings: false, hasVulnerabilities: false, hasGatingIndicatorFindings: false,
            isIncomplete: true, allowIncomplete: false));

    // ⚠️ NOTE ON WHAT USED TO LIVE HERE: a prior test ("...DefaultsFalse...") pinned that two trailing parameters
    // defaulted to false so every pre-existing caller kept its exact result when omitting them. ADR-0027 removed
    // ALL default values from this signature — every one of its six parameters is now mandatory (the point being
    // that a caller CANNOT silently omit a gate source and have it default to "off"; it must say so explicitly).
    // There is therefore no default-argument behavior left to test, and no replacement is added: the compiler itself
    // is the enforcement now — omitting any argument is a compile error, not a defaulted false.
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
    //
    // ⚠️ Uses a GATING INDICATOR finding (ADR 0026), not a capability finding: ADR-0027 stopped capability presence
    // from gating --strict at all (67-81% benign prevalence, Table C), so a capability finding here would no longer
    // trip anything — see ProgramTests.AnalyzeExitCode_CapabilityFindingsAlone_DoesNotGateStrict for that pin. This
    // test is about the 2-beats-3 PRECEDENCE, which still needs a source that actually gates.
    [Fact]
    public void Analyze_WhenStrictGateTripsAndAnalysisIncomplete_ExitsTwo()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 3) with
        {
            Indicators = new IndicatorReport(
                "Sample.dll", "lib/net10.0/Sample.dll", Epoch,
                [new IndicatorFinding(IndicatorCategory.CallbackDomain, "x.pipedream.net", "see x.pipedream.net", "Evil.Loader", "M", 1)],
                Truncated: false)
        };

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

    // ADR-0027 decision 4: a YARA scan that was REQUESTED but could not actually run (the native libyara backend
    // failing to initialize/select) is NOT a clean result — YaraScanStatus.Unavailable is wired into
    // CompletenessAssessment.ForPackage exactly like VulnerabilityScanStatus.Unavailable above, so it exits 3 on its
    // own even with zero YaraFindings and every other analysis complete.
    [Fact]
    public void ScanPackage_WhenYaraScanUnavailable_ExitsThree() =>
        Assert.Equal(3, Program.ScanPackageExitCode(
            PackageWith(yaraStatus: YaraScanStatus.Unavailable), strict: false, allowIncomplete: false));

    // --allow-incomplete downgrades that 3 to 0 exactly like every other completeness caveat — the gate is
    // suppressed, not the underlying fact (CompletenessFooterTests pins that the caveat still PRINTS).
    [Fact]
    public void ScanPackage_WhenYaraScanUnavailableWithAllowIncomplete_ExitsZero() =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWith(yaraStatus: YaraScanStatus.Unavailable), strict: false, allowIncomplete: true));

    // NotRun is the explicit --no-yara opt-out, not an outage: an operator who deliberately skipped the scan has not
    // left a gap the tool failed to fill, so it must NOT raise the completeness caveat or move the exit code — this
    // is the deliberate distinction ADR-0027 draws between "did not run because asked not to" and "did not complete".
    [Fact]
    public void ScanPackage_WhenYaraScanNotRun_ExitsZero() =>
        Assert.Equal(0, Program.ScanPackageExitCode(
            PackageWith(yaraStatus: YaraScanStatus.NotRun), strict: false, allowIncomplete: false));
    #endregion

    #region Methods — the mechanical invariant (spec criterion 3)
    // ADR 0024's load-bearing claim was that the exit code and the footer are two projections of ONE predicate —
    // "exit 0 <=> footer Clean". ADR-0027 DELIBERATELY LOOSENS that for exactly the three de-gated sources: a
    // capability/obfuscation/Script-sourced-script finding still sets "attention" (the footer reads "Findings
    // present", never "Clean"), but no longer sets the "gate" that the exit code actually keys on — so a --strict
    // run with ONLY a capability finding can exit 0 while the footer does NOT say "Clean". That is not a bug this
    // test papers over; it is the intended, evidence-backed shape of ADR-0027, so this invariant now tracks TWO
    // predicates instead of one:
    //   attention — sets the footer headline ("Findings present" vs "Clean"/"Not verified"): capability findings,
    //               obfuscation findings, discriminating indicator categories, script findings, YARA findings,
    //               vulnerabilities — UNCHANGED from before ADR-0027 (reporting is unchanged, per the ADR).
    //   gate      — actually trips the exit code under --strict: ONLY YARA findings, vulnerabilities, and ADR-0026's
    //               three gating indicator categories (Program.ScanExitCode's three surviving parameters).
    // gate implies attention (a gating indicator category is always also a discriminating one — see
    // IndicatorExitCodeInvarianceTests' structural test), but NOT the reverse: a shape can have attention=true,
    // gate=false (any "+findings"/"+script-findings" shape below), and that is exactly where exit-0-but-not-Clean
    // becomes reachable and is asserted explicitly.
    //
    // The equivalence is stated per flag combination, because each flag opts out of one projection:
    //   (strict, !allow)   exit 0 <=> IsComplete && !gate
    //   (!strict, !allow)  exit 0 <=> IsComplete                 findings do not gate without --strict (ADR 0003)
    //   (strict, allow)    exit 0 <=> !gate                      --allow-incomplete drops the coverage gate only
    //   (!strict, allow)   exit 0 always                         both gates off; only exit 1 remains reachable
    //
    // The exit code comes from the SHIPPED seams (Program.AnalyzeExitCode/ScanPackageExitCode) — with a test-local
    // replica of the gate arithmetic this would only ever have compared two copies of the same test's own math; only
    // the INPUT booleans (attention, gate) are read directly off the report here, the same way the real renderers
    // and Program.AnalyzeExitCode/ScanPackageExitCode do internally.
    //
    // Two shapes per matrix ("gating-indicator"/"gating-indicator+incomplete") carry a genuine ADR-0026 gating
    // indicator finding so this table still exercises a REAL --strict trip (exit 2) and the "2 beats 3" precedence —
    // every other shape here is deliberately gate=false, to pin the ADR-0027 divergence on the sources that matter.

    public static IEnumerable<object[]> AssemblyMatrix() =>
        from shape in new[]
        {
            "complete", "complete+findings", "skipped-methods", "skipped-methods+findings",
            "obfuscation-null", "obfuscation-null+findings", "metadata-null", "metadata-null+findings",
            "gating-indicator", "gating-indicator+incomplete",
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
        var attention = report.Capabilities.Findings.Count > 0 || (report.Obfuscation?.Findings.Count ?? 0) > 0
            || (report.Indicators?.Findings.Any(f => ReportTheme.IsDiscriminatingIndicatorCategory(f.Category)) ?? false);
        var gate = report.Indicators?.Findings.Any(f => ReportTheme.IsGatingIndicatorCategory(f.Category)) ?? false;
        var (console, writer) = PlainConsole();

        var exit = Program.AnalyzeExitCode(report, strict, allow);
        AssemblyReportRenderer.Render(console, report);

        AssertInvariant(shape, strict, allow, exit, assessment.IsComplete, attention, gate, writer.ToString());
    }

    public static IEnumerable<object[]> PackageMatrix() =>
        from shape in new[]
        {
            "complete", "complete+findings", "not-checked", "not-checked+findings", "skipped-file",
            "skipped-file+script-findings", "partial-transitive", "metadata-null",
            "gating-indicator", "gating-indicator+incomplete",
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
        var packageIndicatorFindings = report.Assemblies
            .Where(a => a.Indicators is not null)
            .SelectMany(a => a.Indicators!.Findings)
            .ToList();
        var attention = report.AllFindings.Any() || report.ScriptFindings.Count > 0
            || report.Assemblies.Any(a => (a.Obfuscation?.Findings.Count ?? 0) > 0)
            || packageIndicatorFindings.Any(f => ReportTheme.IsDiscriminatingIndicatorCategory(f.Category))
            || report.YaraFindings.Count > 0 || report.Vulnerabilities.Count > 0;
        var gate = packageIndicatorFindings.Any(f => ReportTheme.IsGatingIndicatorCategory(f.Category))
            || report.YaraFindings.Count > 0 || report.Vulnerabilities.Count > 0;
        var (console, writer) = PlainConsole();

        var exit = Program.ScanPackageExitCode(report, strict, allow);
        PackageReportRenderer.Render(console, report, "Some.Package.1.0.0.nupkg");

        AssertInvariant(shape, strict, allow, exit, assessment.IsComplete, attention, gate, writer.ToString());
    }

    private static void AssertInvariant(
        string shape, bool strict, bool allow, int exit, bool isComplete, bool attention, bool gate, string output)
    {
        var expectZero = (strict, allow) switch
        {
            (true, false) => isComplete && !gate,
            (false, false) => isComplete,
            (true, true) => !gate,
            (false, true) => true,
        };
        var because = $"shape '{shape}' with strict={strict}, allow-incomplete={allow} " +
            $"(complete={isComplete}, attention={attention}, gate={gate})";

        Assert.True(expectZero == (exit == 0), $"exit {exit} disagrees with the assessment for {because}.");
        Assert.Equal(strict && gate ? 2 : expectZero ? 0 : 3, exit);   // 2 beats 3; nothing else is reachable here

        // The footer half: "Clean" exactly when complete and nothing sets attention, "Not verified" exactly when
        // attention-free but incomplete. This is a statement about the FOOTER alone — under ADR-0027 it is NO LONGER
        // equivalent to "exit 0" whenever attention and gate diverge (any attention=true, gate=false shape): the
        // dedicated assertion below states that divergence explicitly rather than leaving it implicit.
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

        // ⇒ THE ADR-0027 DIVERGENCE, PINNED EXPLICITLY: whenever a shape has attention (footer says "Findings
        // present") but no real gate, a --strict/complete run still exits 0 even though the footer is NOT "Clean".
        // Before ADR-0027 this combination was unreachable (attention and gate were the same predicate); it is now
        // the expected, evidence-backed shape of the policy, not a defect.
        if (strict && !allow && isComplete && attention && !gate)
            Assert.True(exit == 0 && !FooterHeadline.IsClean(headline),
                $"expected the ADR-0027 divergence (exit 0, footer NOT Clean) for {because}, but got exit {exit} " +
                $"with headline '{headline}'.");
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
        "gating-indicator" => AssemblyReport(methodsTotal: 10, methodsSkipped: 0) with
        {
            Indicators = GatingIndicatorReport("Sample.dll")
        },
        "gating-indicator+incomplete" => AssemblyReport(methodsTotal: 10, methodsSkipped: 4) with
        {
            Indicators = GatingIndicatorReport("Sample.dll")
        },
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
        "gating-indicator" => Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0) with
        {
            Indicators = GatingIndicatorReport("lib/net10.0/A.dll")
        }),
        "gating-indicator+incomplete" => Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 4) with
        {
            Indicators = GatingIndicatorReport("lib/net10.0/A.dll")
        }),
        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "unknown package shape"),
    };

    // A single ADR-0026 gating-category finding (CallbackDomain), isolated from every other source — the smallest
    // shape that makes Program.AnalyzeExitCode/ScanPackageExitCode's "gate" input true.
    private static IndicatorReport GatingIndicatorReport(string path) =>
        new(path, path, Epoch, [new IndicatorFinding(
            IndicatorCategory.CallbackDomain, "x.pipedream.net", "see x.pipedream.net", "Evil.Loader", "M", 1)],
            Truncated: false);
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
