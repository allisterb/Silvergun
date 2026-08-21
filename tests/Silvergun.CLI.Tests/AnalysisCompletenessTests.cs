namespace Silvergun.CLI.Tests;

using System;
using System.Collections.Generic;
using System.Text.Json;

using Silvergun.CLI.Reports;
using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for <see cref="CompletenessAssessment"/> — the single "did we fully analyse this?" predicate that
/// ADR 0024 makes the source of BOTH the report footer and the process exit code.
/// <para>
/// The caveat strings are asserted by <b>equality</b>, not substring: they are the only place a reviewer is told
/// what was not done, and three earlier drafts named a <em>cause we had not established</em> ("IL lifting failed",
/// "--no-vulns", "not a managed assembly"). Each of those would steer a reviewer away from the more suspicious
/// reading of the same signal, so the absence of those words is pinned as a regression assertion, not padding.
/// The z/s spelling split ("analyzed" for methods, "analysed" for files) is inherited from the shipped model and
/// deliberately left alone.
/// </para>
/// </summary>
public sealed class AnalysisCompletenessTests
{
    #region Methods — ForAssembly
    // The live false-clean ADR 0024 exists to remove: methods that could not be analyzed make the assembly
    // INCOMPLETE, and the caveat states only the fact (count of total) with no cause attached.
    [Fact]
    public void ForAssembly_WhenMethodsSkipped_IsIncompleteWithCountCaveat()
    {
        var report = AssemblyReport(methodsTotal: 120, methodsSkipped: 3);

        var assessment = CompletenessAssessment.ForAssembly(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { "3 of 120 method(s) could not be analyzed" }, assessment.Caveats);
    }

    // A method is counted as skipped for ANY throw in CapabilityAnalysis.ScanMethod's per-method guard — including the
    // metadata reads that run BEFORE the body is touched — so naming lifting would assert a cause we do not know, and
    // on hostile input the metadata-read case is the MORE suspicious one. The word must not come back.
    [Fact]
    public void ForAssembly_MethodCaveat_NamesNoCauseSuchAsLifting()
    {
        var assessment = CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 9, methodsSkipped: 9));

        var caveat = Assert.Single(assessment.Caveats);
        Assert.DoesNotContain("lifting", caveat, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lift", caveat, StringComparison.OrdinalIgnoreCase);
    }

    // The coverage numbers are carried on the assessment itself (they were computed and dropped on the floor before
    // ADR 0024), so both the footer line and --json can render them from the one predicate.
    [Fact]
    public void ForAssembly_CarriesCoverageNumbersFromTheCapabilityReport()
    {
        var assessment = CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 120, methodsSkipped: 3));

        Assert.Equal(120, assessment.MethodsTotal);
        Assert.Equal(117, assessment.MethodsAnalyzed);
        Assert.Equal(3, assessment.MethodsSkipped);
    }

    // Obfuscation analysis is best-effort and leaves the report null on failure (Program.RunAnalyze); a null is
    // "we did not look", which is exactly an incompleteness.
    [Fact]
    public void ForAssembly_WhenObfuscationNull_IsIncompleteWithObfuscationCaveat()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0, obfuscation: false);

        var assessment = CompletenessAssessment.ForAssembly(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { "the obfuscation analysis did not complete" }, assessment.Caveats);
    }

    // Both gaps at once: two caveats, each naming its own specific gap (no merging into one vague sentence).
    [Fact]
    public void ForAssembly_WhenMethodsSkippedAndObfuscationNull_ReportsBothCaveats()
    {
        var assessment = CompletenessAssessment.ForAssembly(
            AssemblyReport(methodsTotal: 4, methodsSkipped: 1, obfuscation: false));

        Assert.Equal(
            new[] { "1 of 4 method(s) could not be analyzed", "the obfuscation analysis did not complete" },
            assessment.Caveats);
    }

    // The sixth caveat source: AssemblyMetadata.Read is best-effort and leaves Metadata null on ANY failure
    // (Program.RunAnalyze). Exempting it would let a report whose identity facts — strong-name signature, public key
    // token, entry point — were never read still claim "Clean", and a reviewer reasonably assumes those were checked.
    // Like every other caveat it states only what was not done: the cause (malformed module? unreadable file?) is
    // not established here, so it must not be named.
    [Fact]
    public void ForAssembly_WhenMetadataNull_IsIncompleteWithMetadataCaveat()
    {
        var report = AssemblyReport(methodsTotal: 5, methodsSkipped: 0, metadata: false);

        var assessment = CompletenessAssessment.ForAssembly(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { "the assembly metadata could not be read" }, assessment.Caveats);
    }

    // The complement, and the reason both fixtures default to metadata: PRESENT — a read that succeeded contributes
    // NO caveat, so each gap test isolates exactly the one caveat it is about.
    [Fact]
    public void ForAssembly_WhenMetadataWasRead_ReportsNoMetadataCaveat()
    {
        var assessment = CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 9, methodsSkipped: 2));

        var caveat = Assert.Single(assessment.Caveats);
        Assert.Equal("2 of 9 method(s) could not be analyzed", caveat);
        Assert.DoesNotContain("metadata", caveat, StringComparison.OrdinalIgnoreCase);
    }

    // Every assembly-level caveat source at once, in the order the footer prints them — pins that each gap keeps its
    // own sentence and documents the sequence (methods, obfuscation, metadata).
    [Fact]
    public void ForAssembly_WithEveryGap_ReportsEachCaveatSeparately()
    {
        var assessment = CompletenessAssessment.ForAssembly(
            AssemblyReport(methodsTotal: 4, methodsSkipped: 1, obfuscation: false, metadata: false));

        Assert.Equal(
            new[]
            {
                "1 of 4 method(s) could not be analyzed",
                "the obfuscation analysis did not complete",
                "the assembly metadata could not be read",
            },
            assessment.Caveats);
    }

    // A findings-free report whose analyses all RAN is the only shape allowed to be complete — an empty
    // ObfuscationReport means "ran, found nothing", which is different from a null one.
    [Fact]
    public void ForAssembly_WhenEveryAnalysisRan_IsComplete()
    {
        var assessment = CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 5, methodsSkipped: 0));

        Assert.True(assessment.IsComplete);
        Assert.Empty(assessment.Caveats);
    }
    #endregion

    #region Methods — ForPackage
    // IL coverage aggregates over the packaged assemblies, and the package caveat additionally NAMES where the
    // skipped methods live (the assembly renderer has only one assembly, so it does not).
    [Fact]
    public void ForPackage_WhenOneAssemblyHasSkippedMethods_IsIncompleteAndNamesThatAssembly()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 20, methodsSkipped: 0),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 10, methodsSkipped: 2));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(
            new[] { "2 of 30 method(s) could not be analyzed in lib/net10.0/B.dll" },
            assessment.Caveats);
        Assert.Equal(30, assessment.MethodsTotal);
        Assert.Equal(28, assessment.MethodsAnalyzed);
        Assert.Equal(2, assessment.MethodsSkipped);
    }

    // An inventoried file that produced no analysis at all is a WHOLE binary unanalysed. Without this caveat a
    // package of only native DLLs reads "Clean" — the precise failure ADR 0024 exists to remove.
    [Fact]
    public void ForPackage_WhenAFileCouldNotBeAnalysed_IsIncompleteWithFileCaveat()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 8, methodsSkipped: 0),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 2, methodsSkipped: 0),
            Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly."));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(
            new[] { "1 of 3 file(s) could not be analysed: runtimes/win-x64/native/n.dll" },
            assessment.Caveats);
    }

    // PackageScanner sets SkipReason both for a file nothing could be read out of AND for a valid managed assembly
    // whose capability analysis threw — the second being the MORE security-relevant case. Saying "not a managed
    // assembly" would invite a reviewer to dismiss it as benign packaging, so that diagnosis must stay out.
    [Fact]
    public void ForPackage_FileCaveat_NamesNoCauseSuchAsNotManaged()
    {
        var assessment = CompletenessAssessment.ForPackage(
            Package(Skipped("lib/net10.0/A.dll", "Capability analysis failed.")));

        var caveat = Assert.Single(assessment.Caveats);
        Assert.DoesNotContain("managed", caveat, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("native", caveat, StringComparison.OrdinalIgnoreCase);
    }

    // The aggregation cap: at most three paths are named, then "and N more", so one pathological package cannot
    // produce a multi-kilobyte footer line. The denominator is the whole inventory, not just the skipped subset.
    [Fact]
    public void ForPackage_WhenManyFilesCouldNotBeAnalysed_NamesThreeThenCountsTheRest()
    {
        var report = Package(
            Skipped("a.dll", "no"), Skipped("b.dll", "no"), Skipped("c.dll", "no"),
            Skipped("d.dll", "no"), Skipped("e.dll", "no"),
            Analyzed("lib/net10.0/Ok.dll", methodsTotal: 1, methodsSkipped: 0));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.Equal(
            new[] { "5 of 6 file(s) could not be analysed: a.dll, b.dll, c.dll and 2 more" },
            assessment.Caveats);
    }

    [Fact]
    public void ForPackage_WhenOneAssemblysObfuscationFailed_CaveatIsSingular()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 3, methodsSkipped: 0, obfuscation: false),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 3, methodsSkipped: 0));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.Equal(
            new[] { "the obfuscation analysis did not complete for 1 assembly" },
            assessment.Caveats);
    }

    [Fact]
    public void ForPackage_WhenTwoAssembliesObfuscationFailed_CaveatIsPlural()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 3, methodsSkipped: 0, obfuscation: false),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 3, methodsSkipped: 0, obfuscation: false));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.Equal(
            new[] { "the obfuscation analysis did not complete for 2 assemblies" },
            assessment.Caveats);
    }

    // The package projection of the metadata caveat counts assemblies, so it needs the same singular/plural care as
    // the obfuscation one.
    [Fact]
    public void ForPackage_WhenOneAssemblysMetadataCouldNotBeRead_CaveatIsSingular()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 3, methodsSkipped: 0, metadata: false),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 3, methodsSkipped: 0));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(
            new[] { "the assembly metadata could not be read for 1 assembly" },
            assessment.Caveats);
    }

    [Fact]
    public void ForPackage_WhenTwoAssembliesMetadataCouldNotBeRead_CaveatIsPlural()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 3, methodsSkipped: 0, metadata: false),
            Analyzed("lib/net10.0/B.dll", methodsTotal: 3, methodsSkipped: 0, metadata: false));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.Equal(
            new[] { "the assembly metadata could not be read for 2 assemblies" },
            assessment.Caveats);
    }

    // The load-bearing non-double-report case. PackageScanner.ScanAssembly reads metadata BEFORE the load, so a file
    // nothing could be read out of has Report AND Metadata null. That is ONE gap — a whole binary nobody looked
    // inside — and the metadata caveat is counted only over assemblies that produced a report, so it must not appear
    // here. Counting it would tell a reviewer there were two distinct blind spots where there is one, and would make
    // "N of M assemblies" a number that no longer corresponds to anything analysed.
    [Fact]
    public void ForPackage_WhenTheOnlyFileWasSkipped_ReportsTheFileCaveatAndNoMetadataCaveat()
    {
        var assessment = CompletenessAssessment.ForPackage(
            Package(Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly.")));

        Assert.False(assessment.IsComplete);
        Assert.Equal(
            new[] { "1 of 1 file(s) could not be analysed: runtimes/win-x64/native/n.dll" },
            assessment.Caveats);
        Assert.DoesNotContain("metadata", Assert.Single(assessment.Caveats), StringComparison.OrdinalIgnoreCase);
    }

    // ADR-0027 decision 4: a YARA scan that was REQUESTED but could not actually run (no backend selected, or a
    // selected backend that threw during init/scan — the native libyara.NET defect the measurement exposed) is NOT
    // a clean result: an empty YaraFindings list here is not evidence of a clean package, so it must be incomplete
    // with its own caveat, exactly mirroring the pre-existing VulnerabilityScanStatus.Unavailable caveat below.
    [Fact]
    public void ForPackage_WhenYaraScanUnavailable_IsIncompleteWithDidNotCompleteCaveat()
    {
        var report = PackageWith(yaraStatus: YaraScanStatus.Unavailable);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { "the YARA malware-signature scan did not complete" }, assessment.Caveats);
    }

    // NotRun is the explicit --no-yara opt-out, a DIFFERENT statement from Unavailable ("did not run because asked
    // not to" vs "did not run despite being asked to"): the caller chose to skip the scan, so it must NOT raise the
    // caveat — an operator who opted out has not left a gap the tool failed to fill.
    [Fact]
    public void ForPackage_WhenYaraScanNotRun_ReportsNoYaraCaveat()
    {
        var assessment = CompletenessAssessment.ForPackage(PackageWith(yaraStatus: YaraScanStatus.NotRun));

        Assert.True(assessment.IsComplete);
        Assert.Empty(assessment.Caveats);
    }

    // Resolver-lite (ADR 0018): a Partial transitive walk means the coverage claim does not extend to the
    // dependency closure.
    [Fact]
    public void ForPackage_WhenTransitiveWalkPartial_IsIncompleteWithTransitiveCaveat()
    {
        var report = PackageWith(resolution: DependencyResolutionStatus.Partial);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(
            new[] { "transitive dependencies were not fully resolved (coverage incomplete)" },
            assessment.Caveats);
    }

    // ADR 0017: an OSV outage is NOT a clean result. "did not complete" — the check was attempted and failed.
    [Fact]
    public void ForPackage_WhenVulnerabilityCheckUnavailable_IsIncompleteWithDidNotCompleteCaveat()
    {
        var report = PackageWith(vulnStatus: VulnerabilityScanStatus.Unavailable);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { "the known-vulnerability check did not complete" }, assessment.Caveats);
    }

    // NotChecked is a DIFFERENT statement from Unavailable ("did not run" vs "did not complete") and must not name
    // --no-vulns: it is the field's DEFAULT, so a report written before the status existed lands here with nobody
    // having opted out of anything (see ForPackage_LegacyJsonWithoutStatus_... below).
    [Fact]
    public void ForPackage_WhenVulnerabilityCheckNotChecked_IsIncompleteWithDidNotRunCaveat()
    {
        var report = PackageWith(vulnStatus: VulnerabilityScanStatus.NotChecked);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Equal(new[] { "the known-vulnerability check did not run" }, assessment.Caveats);
        Assert.DoesNotContain("--no-vulns", Assert.Single(assessment.Caveats));
    }

    // The specific regression the flag-free wording prevents, reached the way it actually happens in the wild:
    // deserializing a package report that predates BOTH the VulnerabilitiesStatus field AND the YaraScanStatus field
    // (ADR-0027 decision 4 — the same JSON that predates OSV tracking necessarily predates YARA tracking too, since
    // YaraScanStatus was added later). NotChecked/Unavailable are their respective defaults, so a LEGACY report must
    // never be told an operator passed --no-vulns/--no-yara, and — the genuinely NEW behavior ADR-0027 adds, not a
    // regression — it now carries TWO caveats instead of one: the YARA default is Unavailable rather than NotRun
    // specifically so old data (including every report the libyara.NET native-dependency defect silently produced,
    // per PackageModel.cs) reads as "not verified", never a false "Completed". This is the fail-closed direction the
    // ADR calls out as correct and NOT to be changed.
    [Fact]
    public void ForPackage_LegacyJsonWithoutStatus_YieldsFlagFreeCaveats()
    {
        const string legacyJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.0.0",
                "Authors": "Old Author",
                "Description": "A report serialized before the OSV/YARA status fields existed.",
                "Dependencies": []
              },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": []
            }
            """;
        var restored = PackageCapabilityReport.FromJson(legacyJson);

        var assessment = CompletenessAssessment.ForPackage(restored!);

        Assert.Equal(VulnerabilityScanStatus.NotChecked, restored!.VulnerabilitiesStatus);
        Assert.Equal(YaraScanStatus.Unavailable, restored!.YaraScanStatus);
        Assert.Equal(
            new[]
            {
                "the known-vulnerability check did not run",
                "the YARA malware-signature scan did not complete",
            },
            assessment.Caveats);
        Assert.DoesNotContain("--no-vulns", string.Join("; ", assessment.Caveats));
        Assert.DoesNotContain("--no-yara", string.Join("; ", assessment.Caveats));
    }

    // Non-double-counting: a file that produced NO report is its own (larger) caveat, so it must not also skew the
    // method-coverage ratio or inflate the obfuscation/metadata counts — its Report, Obfuscation and Metadata are all
    // null by construction, and counting them there would report one gap twice and make the coverage numbers meaningless.
    [Fact]
    public void ForPackage_SkippedFile_IsNotAlsoCountedInCoverageOrObfuscation()
    {
        var report = Package(
            Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 0),
            Skipped("runtimes/win-x64/native/n.dll", "Failed to load assembly."));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.Equal(10, assessment.MethodsTotal);       // only the assembly that produced a report
        Assert.Equal(10, assessment.MethodsAnalyzed);
        Assert.Equal(0, assessment.MethodsSkipped);
        Assert.Equal(                                    // and exactly ONE caveat: the file, not an obfuscation failure
            new[] { "1 of 2 file(s) could not be analysed: runtimes/win-x64/native/n.dll" },
            assessment.Caveats);
    }

    // All SIX caveat sources at once, in the order the footer will print them — pins that each gap keeps its own
    // sentence rather than collapsing into one, and documents the sequence. Note the metadata caveat says "1 assembly"
    // while two files are unanalysed: the skipped file's null Metadata is NOT counted (its whole-binary gap is the
    // preceding caveat), so the two counts are deliberately different numbers.
    [Fact]
    public void ForPackage_WithEveryGap_ReportsEachCaveatSeparately()
    {
        var report = PackageWith(
            new[]
            {
                Analyzed("lib/net10.0/A.dll", methodsTotal: 10, methodsSkipped: 4, obfuscation: false, metadata: false),
                Skipped("content/n.dll", "Failed to load assembly."),
            },
            vulnStatus: VulnerabilityScanStatus.Unavailable,
            resolution: DependencyResolutionStatus.Partial);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.Equal(
            new[]
            {
                "4 of 10 method(s) could not be analyzed in lib/net10.0/A.dll",
                "1 of 2 file(s) could not be analysed: content/n.dll",
                "the obfuscation analysis did not complete for 1 assembly",
                "the assembly metadata could not be read for 1 assembly",
                "transitive dependencies were not fully resolved (coverage incomplete)",
                "the known-vulnerability check did not complete",
            },
            assessment.Caveats);
    }

    // A package is complete only when every analysis RAN: all assemblies produced a report, obfuscation ran on each,
    // the OSV check completed, and no transitive walk was left Partial.
    [Fact]
    public void ForPackage_WhenEveryAnalysisRan_IsComplete()
    {
        var report = Package(Analyzed("lib/net10.0/A.dll", methodsTotal: 7, methodsSkipped: 0));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.True(assessment.IsComplete);
        Assert.Empty(assessment.Caveats);
        Assert.Equal(7, assessment.MethodsTotal);
    }

    // An empty package (nothing to analyse) with a completed vuln check is complete and reports 0/0 coverage —
    // "we analysed everything there was", not a silent gap.
    [Fact]
    public void ForPackage_WithNoAssemblies_IsCompleteWithZeroCoverage()
    {
        var assessment = CompletenessAssessment.ForPackage(Package());

        Assert.True(assessment.IsComplete);
        Assert.Equal(0, assessment.MethodsTotal);
        Assert.Equal(0, assessment.MethodsAnalyzed);
    }
    #endregion

    #region Methods — ToJson (the additive --json projection)
    // The coverage numbers and every caveat must be machine-readable, not just printed (spec criterion 5): CI reads
    // JSON, and a caveat a pipeline cannot see is a caveat nobody acts on.
    [Fact]
    public void ToJson_EmitsCompletenessFlagCoverageNumbersAndCaveats()
    {
        var assessment = CompletenessAssessment.ForAssembly(
            AssemblyReport(methodsTotal: 120, methodsSkipped: 3, obfuscation: false));

        using var doc = JsonDocument.Parse(assessment.ToJson());
        var root = doc.RootElement;

        Assert.False(root.GetProperty("IsComplete").GetBoolean());
        Assert.Equal(120, root.GetProperty("MethodsTotal").GetInt32());
        Assert.Equal(117, root.GetProperty("MethodsAnalyzed").GetInt32());
        Assert.Equal(3, root.GetProperty("MethodsSkipped").GetInt32());
        Assert.Equal(
            new[] { "3 of 120 method(s) could not be analyzed", "the obfuscation analysis did not complete" },
            root.GetProperty("Caveats").EnumerateArray().Select(e => e.GetString()!));
    }

    [Fact]
    public void ToJson_WhenComplete_EmitsAnEmptyCaveatArray()
    {
        var assessment = CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 2, methodsSkipped: 0));

        using var doc = JsonDocument.Parse(assessment.ToJson());

        Assert.True(doc.RootElement.GetProperty("IsComplete").GetBoolean());
        Assert.Empty(doc.RootElement.GetProperty("Caveats").EnumerateArray());
    }

    // The whole property SET, so a rename or a dropped field fails here rather than in some consumer later. Compared
    // ORDER-INSENSITIVELY (sorted) on purpose: the block is new and nothing consumes it yet, so its internal order is
    // not a contract — pinning it would only invite churn (Caveats already moved to last when the getter that
    // normalizes null was added). The byte-stability contract is about the PRE-EXISTING report fields, and
    // CompletenessCliTests asserts that separately.
    [Fact]
    public void ToJson_EmitsEveryCompletenessProperty_WithoutPinningTheirOrder()
    {
        using var doc = JsonDocument.Parse(
            CompletenessAssessment.ForAssembly(AssemblyReport(methodsTotal: 3, methodsSkipped: 1)).ToJson());

        Assert.Equal(
            new[] { "Caveats", "IsComplete", "MethodsAnalyzed", "MethodsSkipped", "MethodsTotal" },
            doc.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
    }
    #endregion

    #region Methods — default(CompletenessAssessment) (fail closed on an unreachable path)
    // Nothing constructs the default today — both factories always build a real assessment — but a record STRUCT makes
    // it representable, and `default` runs no constructor, which is why Caveats has to coalesce in its GETTER.
    [Fact]
    public void Default_HasEmptyCaveatsRatherThanNull()
    {
        var assessment = default(CompletenessAssessment);

        Assert.NotNull(assessment.Caveats);
        Assert.Empty(assessment.Caveats);
    }

    // The actual safety property of the default: IsComplete is false, so the unreachable path fails CLOSED. A default
    // that read "complete" would be a false clean handed out by a value nobody deliberately created.
    [Fact]
    public void Default_IsNotComplete() =>
        Assert.False(default(CompletenessAssessment).IsComplete);

    [Fact]
    public void Default_ReportsZeroCoverageRatherThanThrowing()
    {
        var assessment = default(CompletenessAssessment);

        Assert.Equal(0, assessment.MethodsTotal);
        Assert.Equal(0, assessment.MethodsAnalyzed);
        Assert.Equal(0, assessment.MethodsSkipped);
    }
    #endregion

    #region Methods — fixtures
    // An analyze report with the given IL coverage. obfuscation:true attaches a findings-free ObfuscationReport,
    // which means "the analysis RAN and found nothing" — deliberately distinct from the null that means it failed;
    // metadata:true likewise attaches a metadata snapshot that WAS read.
    // Both default to PRESENT because a null of either is itself a caveat source: with them absent, every gap test
    // below would see its own caveat plus two unrelated ones and could no longer isolate the gap it is about.
    internal static AssemblyAnalysisReport AssemblyReport(
        int methodsTotal, int methodsSkipped, bool obfuscation = true, bool metadata = true,
        params ApiCallFinding[] findings) =>
        new(
            metadata ? MetadataInfo("Sample.dll") : null,
            new CapabilityReport(
                "Sample.dll", "lib/net10.0/Sample.dll", Epoch, findings,
                methodsTotal, methodsTotal - methodsSkipped, methodsSkipped,
                Enumerable.Range(0, methodsSkipped).Select(i => $"T.M{i}: reason").ToArray()),
            obfuscation ? new ObfuscationReport("Sample.dll", "lib/net10.0/Sample.dll", Epoch, []) : null);

    // A packaged assembly that produced a capability report. obfuscation:false leaves the Obfuscation null and
    // metadata:false leaves the Metadata null (the best-effort side analysis / read failed) while the capability
    // report still exists — the package-level analogue of AssemblyReport(obfuscation:/metadata: false).
    internal static AssemblyScanResult Analyzed(
        string relativePath, int methodsTotal, int methodsSkipped, bool obfuscation = true, bool metadata = true,
        params ApiCallFinding[] findings) =>
        new(
            new PackageAssembly(relativePath, $"/x/{relativePath}", "net10.0", PackageItemRole.Lib, "hash"),
            new CapabilityReport(
                relativePath, relativePath, Epoch, findings,
                methodsTotal, methodsTotal - methodsSkipped, methodsSkipped, []),
            null,
            metadata ? MetadataInfo(relativePath) : null,
            obfuscation ? new ObfuscationReport(relativePath, relativePath, Epoch, []) : null);

    // A metadata read that SUCCEEDED (AssemblyMetadata.Read's success case). The values are arbitrary but ASCII and
    // markup-free, so the renderer-level ASCII / no-leftover-markup assertions stay statements about the footer.
    internal static AssemblyMetadataInfo MetadataInfo(string name) => new(
        Name: name, Version: "1.0.0.0", Culture: null, PublicKeyToken: null,
        IsStrongNameSigned: false, ModuleKind: "DynamicallyLinkedLibrary",
        IsILOnly: true, Requires32Bit: false, Requires64Bit: false,
        RequiresAmdInstructionSet: false, ContainsForeignTypes: false,
        HasEntryPoint: false, TargetRuntimeVersion: "v4.0.30319",
        DebugInformationLocation: null, CustomAttributes: [], References: []);

    // An inventoried file that produced NO analysis: Report is null and SkipReason carries the verbatim reason
    // (which PackageScanner sets both for an unreadable file and for a managed assembly whose analysis threw).
    // Metadata is null as well — PackageScanner.ScanAssembly reads metadata BEFORE the load, so for a file nothing
    // could be read out of both are null. That shape is the double-report trap: the whole-binary gap must be reported
    // ONCE (as the file caveat), never also as a failed metadata read.
    internal static AssemblyScanResult Skipped(string relativePath, string reason) =>
        new(
            new PackageAssembly(relativePath, $"/x/{relativePath}", null, PackageItemRole.Other, "hash"),
            null,
            reason,
            null,
            null);

    internal static PackageCapabilityReport Package(params AssemblyScanResult[] assemblies) =>
        PackageWith(assemblies);

    // A scan-package report defaulting to "the vuln check completed and found nothing", "no transitive walk was
    // asked for", and "the YARA scan completed and found nothing" (yaraStatus:), so each test's caveat is the ONLY
    // one and the assertions stay unconfounded.
    //
    // ⚠️ yaraStatus defaults to Completed HERE, deliberately different from PackageCapabilityReport's own record
    // default (YaraScanStatus.Unavailable — see PackageModel.cs, and that default is CORRECT and must not change: it
    // is what makes pre-ADR-0027 legacy JSON read as "not verified" rather than falsely clean). A fresh test fixture
    // is not legacy JSON — it is a report this file is constructing on purpose, so it must say what it means: tests
    // about something else default to a completed, clean YARA scan (matching vulnStatus's existing precedent below),
    // and tests ABOUT the YARA caveat pass yaraStatus explicitly (see the ForPackage_WhenYaraScan... tests below and
    // CompletenessExitCodeTests.ScanPackage_WhenYaraScanUnavailable_ExitsThree). Leaving every fixture at the
    // record's own default made every package fixture in this suite silently incomplete/"Not verified" the moment
    // ADR-0027 wired Unavailable into CompletenessAssessment.ForPackage — this default is the fix.
    internal static PackageCapabilityReport PackageWith(
        IEnumerable<AssemblyScanResult>? assemblies = null,
        VulnerabilityScanStatus vulnStatus = VulnerabilityScanStatus.Completed,
        DependencyResolutionStatus resolution = DependencyResolutionStatus.NotRun,
        IEnumerable<ScriptFinding>? scriptFindings = null,
        YaraScanStatus yaraStatus = YaraScanStatus.Completed) =>
        new(
            new PackageIdentityInfo("Some.Package", "1.0.0", "Author", "A package.", []),
            Epoch,
            assemblies?.ToArray() ?? [],
            [],
            scriptFindings?.ToArray() ?? [],
            VulnerabilitiesStatus: vulnStatus,
            DependencyResolution: resolution,
            YaraScanStatus: yaraStatus);
    #endregion

    #region Fields
    internal static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;
    #endregion
}
