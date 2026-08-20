namespace Silvergun.CLI.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

using Silvergun.CLI;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// End-to-end (child-process) coverage for <c>docs/agent/tasks/capability-diff-versions.md</c>: the real
/// <c>Silvergun.CLI</c> entrypoint driving <c>--snapshot</c> on <c>analyze</c>/<c>scan-package</c> (Area A) and the
/// full <c>capability-diff</c> exit-code / refusal-precedence contract (Area C). Snapshot input files are built
/// directly via the public <see cref="CapabilitySnapshot"/> API — the verb's OWN job is comparing whatever snapshot
/// files a user hands it, so crafting them synthetically tests that contract precisely, the same posture Area B's
/// IL-level <see cref="Silvergun.CodeAnalysis.IL.Tests.CapabilityDiffTests"/> takes toward
/// <see cref="CapabilityDiffReport.Compare"/> itself.
/// <para>
/// Each CLI invocation is its own process (ADR 0021), mirroring <see cref="CompletenessCliTests"/>/
/// <see cref="IndicatorEndToEndTests"/>.
/// </para>
/// </summary>
public sealed class CapabilityDiffCliTests
{
    #region Methods — A: --snapshot emission
    [Fact]
    public void Analyze_WithSnapshot_WritesOneElementArray()
    {
        var snapshotPath = TempPath("json");
        try
        {
            var (exit, _, stderr, exited) = RunCli("analyze", TargetAssembly, "--snapshot", snapshotPath);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.True(exit is 0 or 2 or 3, $"unexpected exit {exit}. stderr:{Environment.NewLine}{stderr}");
            Assert.True(File.Exists(snapshotPath), "the --snapshot file was not written.");

            var snapshots = ReadSnapshotFile(snapshotPath);
            var only = Assert.Single(snapshots);
            Assert.Equal(CapabilitySnapshot.CurrentSchemaVersion, only.SchemaVersion);
            Assert.Null(only.TargetFramework);   // analyze never knows a TFM (accepted-as-is, task spec)
            Assert.Null(only.PackageId);
            Assert.False(string.IsNullOrEmpty(only.AssemblyName));
        }
        finally
        {
            TryDelete(snapshotPath);
        }
    }

    [Fact]
    public void ScanPackage_WithSnapshot_WritesOneElementPerScannedAssembly()
    {
        var nupkg = BuildNupkg(
            "SilvergunCapDiffSnapshot",
            ("lib/net10.0/A.dll", File.ReadAllBytes(TargetAssembly)),
            ("lib/netstandard2.0/B.dll", File.ReadAllBytes(FixtureDll)));
        var snapshotPath = TempPath("json");
        try
        {
            var (exit, _, stderr, exited) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--allow-incomplete", "--snapshot", snapshotPath);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.True(exit is 0 or 2 or 3, $"unexpected exit {exit}. stderr:{Environment.NewLine}{stderr}");
            Assert.True(File.Exists(snapshotPath), "the --snapshot file was not written.");

            var snapshots = ReadSnapshotFile(snapshotPath);
            Assert.Equal(2, snapshots.Count);   // one element per scanned (loadable) assembly
            Assert.Contains(snapshots, s => s.TargetFramework == "net10.0");
            Assert.Contains(snapshots, s => s.TargetFramework == "netstandard2.0");
            Assert.All(snapshots, s => Assert.Equal("SilvergunCapDiffSnapshot", s.PackageId));
        }
        finally
        {
            TryDelete(nupkg);
            TryDelete(snapshotPath);
        }
    }

    [Fact]
    public void Analyze_Snapshot_DoesNotChangeStdoutOrExitCode()
    {
        var (exitWithout, stdoutWithout, _, exitedWithout) = RunCli("analyze", TargetAssembly);
        var snapshotPath = TempPath("json");
        try
        {
            var (exitWith, stdoutWith, _, exitedWith) = RunCli("analyze", TargetAssembly, "--snapshot", snapshotPath);

            Assert.True(exitedWithout && exitedWith, "CLI did not exit within the timeout.");
            Assert.Equal(exitWithout, exitWith);
            Assert.Equal(NormalizeVolatile(stdoutWithout), NormalizeVolatile(stdoutWith));
        }
        finally
        {
            TryDelete(snapshotPath);
        }
    }

    // The --json report carries its own wall-clock AnalyzedAt (unrelated to --snapshot, which deliberately carries
    // NO timestamp), which differs between the two separate process runs this comparison needs — normalized out
    // before comparing, same as the plain-report comparison above.
    [Fact]
    public void Analyze_Snapshot_DoesNotChangeJsonOutput()
    {
        var (exitWithout, jsonWithout, _, exitedWithout) = RunCli("analyze", TargetAssembly, "--json");
        var snapshotPath = TempPath("json");
        try
        {
            var (exitWith, jsonWith, _, exitedWith) = RunCli("analyze", TargetAssembly, "--json", "--snapshot", snapshotPath);

            Assert.True(exitedWithout && exitedWith, "CLI did not exit within the timeout.");
            Assert.Equal(exitWithout, exitWith);
            Assert.Equal(NormalizeVolatile(jsonWithout), NormalizeVolatile(jsonWith));
        }
        finally
        {
            TryDelete(snapshotPath);
        }
    }

    [Fact]
    public void ScanPackage_Snapshot_DoesNotChangeStdoutOrExitCode()
    {
        var nupkg = BuildNupkg("SilvergunCapDiffUnchanged", ("lib/net10.0/A.dll", File.ReadAllBytes(TargetAssembly)));
        var snapshotPath = TempPath("json");
        try
        {
            var (exitWithout, stdoutWithout, _, exitedWithout) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--allow-incomplete");
            var (exitWith, stdoutWith, _, exitedWith) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--allow-incomplete", "--snapshot", snapshotPath);

            Assert.True(exitedWithout && exitedWith, "CLI did not exit within the timeout.");
            Assert.Equal(exitWithout, exitWith);
            Assert.Equal(NormalizeVolatile(stdoutWithout), NormalizeVolatile(stdoutWith));
        }
        finally
        {
            TryDelete(nupkg);
            TryDelete(snapshotPath);
        }
    }

    [Fact]
    public void Analyze_SnapshotToPathInNonexistentDirectory_ExitsOne()
    {
        var badPath = Path.Combine(Path.GetTempPath(), $"silvergun-nonexistent-{Guid.NewGuid():N}", "out.json");

        var (exit, stdout, stderr, exited) = RunCli("analyze", TargetAssembly, "--snapshot", badPath);

        Assert.True(exited, "CLI did not exit within the timeout.");
        Assert.Equal(1, exit);
        Assert.Contains("Failed to write snapshot", stderr);
        Assert.False(File.Exists(badPath));
        Assert.NotEmpty(stdout);   // the human report WAS printed before the snapshot write failed
    }

    [Fact]
    public void ScanPackage_SnapshotToPathInNonexistentDirectory_ExitsOne()
    {
        var nupkg = BuildNupkg("SilvergunCapDiffBadPath", ("lib/net10.0/A.dll", File.ReadAllBytes(TargetAssembly)));
        var badPath = Path.Combine(Path.GetTempPath(), $"silvergun-nonexistent-{Guid.NewGuid():N}", "out.json");
        try
        {
            var (exit, _, stderr, exited) =
                RunCli("scan-package", nupkg, "--no-vulns", "--no-yara", "--allow-incomplete", "--snapshot", badPath);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(1, exit);
            Assert.Contains("Failed to write snapshot", stderr);
        }
        finally
        {
            TryDelete(nupkg);
        }
    }
    #endregion

    #region Methods — C: exit codes and refusal precedence
    [Fact]
    public void CapabilityDiff_UnknownSchemaVersion_ExitsOneWithNoReportEmitted()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()) with { SchemaVersion = CapabilitySnapshot.CurrentSchemaVersion + 1 });
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(1, exit);
            Assert.Contains("schema version", stderr, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Assessment", stdout);   // no report was produced at all
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]   // unconditional: --allow-tfm-mismatch does NOT bypass the empty-array refusal
    public void CapabilityDiff_EmptyBaselineArray_ExitsThreeRegardlessOfAllowTfmMismatch(bool allowTfmMismatch)
    {
        var baseline = WriteSnapshotFile();   // empty array
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        try
        {
            var args = allowTfmMismatch
                ? new[] { "capability-diff", baseline, candidate, "--allow-tfm-mismatch" }
                : new[] { "capability-diff", baseline, candidate };
            var (exit, stdout, stderr, exited) = RunCli(args);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            Assert.Contains("no assemblies to compare", stderr);
            Assert.DoesNotContain("Assessment", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_EmptyCandidateArray_ExitsThree()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        var candidate = WriteSnapshotFile();   // empty array
        try
        {
            var (exit, _, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            Assert.Contains("candidate", stderr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_VacuousDiff_DisjointTfms_ExitsThreeWithoutOverride()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "netstandard2.0", Complete()));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net8.0", Complete()));
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            Assert.Contains("NOTHING MATCHED", stderr);
            Assert.DoesNotContain("Assessment", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_VacuousDiff_WithAllowTfmMismatch_ExitsZero_AndShowsNothingMatchedBanner()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "netstandard2.0", Complete()));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net8.0", Complete()));
        try
        {
            var (exit, stdout, stderr, exited) =
                RunCli("capability-diff", baseline, candidate, "--allow-tfm-mismatch");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
            Assert.Contains("NOTHING MATCHED", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    // Regression for the "⇒ CRITICAL (2026-08-20, code review)" section: the SECOND broken implementation
    // encoded a null TargetFramework in-band as a sentinel string holding a single NUL character (code point
    // zero), on the (false, for untrusted input) reasoning that a real TFM moniker can never contain one. Under
    // that encoding, a null TFM and a crafted literal-NUL-character TFM for the same assembly name both encode
    // to the SAME sentinel, so they would (wrongly) MATCH each other as though they were the same target
    // framework — a hostile snapshot's forged NUL-character TFM becomes indistinguishable from a genuinely null
    // one. With the current out-of-band ValueTuple key, null and a NUL-character string are fully distinct, so
    // (name, null) and (name, NUL-character) never match — with only one TFM value per side here, that means
    // NOTHING matches, tripping the vacuous-diff refusal (exit 3) by default. This is exactly the shape a
    // broken in-band encoding would get wrong: it would report a spurious match (and likely "no capability
    // changes") instead of refusing.
    [Fact]
    public void CapabilityDiff_NullTfmVsLiteralNulCharacterTfm_AreDistinct_ExitsThreeWithoutOverride()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", null, Complete()));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", NulTfm, Complete()));
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);   // vacuous diff: null and the NUL-character TFM did NOT match
            Assert.Contains("NOTHING MATCHED", stderr);
            Assert.DoesNotContain("Assessment", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    // Companion to the test above, with the override given: null and the NUL-character TFM are reported as TWO
    // SEPARATE target-framework identities for the same assembly (one dropped — the null side — one added — the
    // NUL-character side), never silently collapsed or matched. A broken in-band-sentinel implementation would
    // instead treat them as the SAME identity here (both sides "match", nothing added/dropped, --allow-tfm-
    // mismatch has nothing to override) — the opposite of this assertion.
    [Fact]
    public void CapabilityDiff_NullTfmVsLiteralNulCharacterTfm_WithOverride_ReportsTwoSeparateTfmIdentities_ExitsZero()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", null, Complete()));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", NulTfm, Complete()));
        try
        {
            var (exit, stdout, stderr, exited) =
                RunCli("capability-diff", baseline, candidate, "--allow-tfm-mismatch");

            Assert.True(exited, $"CLI did not exit within the timeout (crashed?). stderr:{Environment.NewLine}{stderr}");
            Assert.Equal(0, exit);
            Assert.Contains("NOTHING MATCHED", stdout);                 // vacuous diff, overridden
            Assert.Contains("Target frameworks added / dropped", stdout);
            Assert.Contains("A.dll (unknown)", stdout);                 // the null-TFM side, dropped
            Assert.Contains($"A.dll ({NulTfm})", stdout);                // the NUL-character-TFM side, added — a
                                                                          // DISTINCT entry from the line above
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    // The fixture itself, verified: guards against the exact failure mode the task write-up warns about (the
    // Write/Edit tool silently turning a typed 4-hex-digit unicode escape sequence into something other than a
    // real NUL character — a plain space was observed). NulTfm is built from a character code point at runtime,
    // never typed as an escape sequence in this file; this test asserts, on every run, that it truly is a single
    // NUL character (code point 0), not an empty string, not a space, and not some other value.
    [Fact]
    public void NulTfmFixture_IsActuallyASingleNulCharacter_NotASpaceOrEmptyString()
    {
        Assert.Equal(1, NulTfm.Length);
        Assert.Equal('\0', NulTfm[0]);
        Assert.Equal(0, NulTfm[0]);
        Assert.NotEqual(string.Empty, NulTfm);
        Assert.NotEqual(" ", NulTfm);
    }

    [Fact]
    public void CapabilityDiff_IncompleteScanOnCandidate_ExitsThree_ButStillRendersTheRealChange()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        var incomplete = new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 4, MethodsSkipped: 1, AssemblyLoadFailures: 0);
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", incomplete, Capability.ProcessExecution));
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            Assert.Contains("ProcessExecution", stdout);        // the real change still renders (trap 1)
            Assert.Contains("Candidate scan INCOMPLETE", stdout);
            Assert.Contains("capability(ies) added", stdout);   // findings still win the headline over the caveat
            Assert.DoesNotContain("Cannot compare", stdout);    // that wording is reserved for the no-changes-at-all case
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_IncompleteScan_WithAllowIncomplete_ExitsZero_StillRendersChangeAndCaveat()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        var incomplete = new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 4, MethodsSkipped: 1, AssemblyLoadFailures: 0);
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", incomplete, Capability.ProcessExecution));
        try
        {
            var (exit, stdout, _, exited) = RunCli("capability-diff", baseline, candidate, "--allow-incomplete");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
            Assert.Contains("ProcessExecution", stdout);
            Assert.Contains("Candidate scan INCOMPLETE", stdout);   // caveat still disclosed, only the gate suppressed
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_AddedCapability_WithStrict_ExitsTwo()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete(), Capability.ProcessExecution));
        try
        {
            var (exit, stdout, _, exited) = RunCli("capability-diff", baseline, candidate, "--strict");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(2, exit);
            Assert.Contains("capability(ies) added", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_AddedCapability_WithoutStrict_ExitsZero()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete(), Capability.ProcessExecution));
        try
        {
            var (exit, stdout, _, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
            Assert.Contains("capability(ies) added", stdout);   // still reported, just does not gate
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_IdenticalSnapshots_ExitsZero_AndReportsNoCapabilityChanges()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete(), Capability.Network));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete(), Capability.Network));
        try
        {
            var (exit, stdout, _, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
            Assert.Contains("No capability changes.", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_MissingBaselineFile_ExitsOne()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"silvergun-missing-{Guid.NewGuid():N}.json");
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        try
        {
            var (exit, _, stderr, exited) = RunCli("capability-diff", missing, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(1, exit);
            Assert.Contains("does not exist", stderr);
        }
        finally
        {
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_MalformedJsonFile_ExitsOne()
    {
        var baseline = TempPath("json");
        File.WriteAllText(baseline, "{ this is not valid json ");
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        try
        {
            var (exit, _, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(1, exit);
            Assert.Contains("Could not read snapshot file", stderr);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_JsonLiteralNull_ExitsOne()
    {
        var baseline = TempPath("json");
        File.WriteAllText(baseline, "null");
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        try
        {
            var (exit, _, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(1, exit);
            Assert.Contains("empty or JSON 'null'", stderr);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    // Precedence: overriding the vacuous-diff gate does not also override the incompleteness gate — they are
    // independent refusals with independent overrides.
    [Fact]
    public void CapabilityDiff_VacuousAndIncomplete_AllowTfmMismatchAlone_StillExitsThreeForIncompleteness()
    {
        var incomplete = new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 4, MethodsSkipped: 1, AssemblyLoadFailures: 0);
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "netstandard2.0", incomplete));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net8.0", Complete()));
        try
        {
            var (exit, stdout, stderr, exited) = RunCli("capability-diff", baseline, candidate, "--allow-tfm-mismatch");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(3, exit);
            // Overriding the vacuous gate lets the report render (the disjoint TFMs show up as a structural
            // target-framework add/drop, so HasAnyChange is true and the "Cannot compare" wording — reserved for
            // the truly-nothing-to-report case — is NOT what appears here); what matters is that the incomplete
            // side is still disclosed and the exit code is still 3 despite --allow-tfm-mismatch.
            Assert.Contains("NOTHING MATCHED", stdout);
            Assert.Contains("Baseline scan INCOMPLETE", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    [Fact]
    public void CapabilityDiff_VacuousAndIncomplete_BothAllowFlags_ExitsZero()
    {
        var incomplete = new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 4, MethodsSkipped: 1, AssemblyLoadFailures: 0);
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "netstandard2.0", incomplete));
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net8.0", Complete()));
        try
        {
            var (exit, _, _, exited) =
                RunCli("capability-diff", baseline, candidate, "--allow-tfm-mismatch", "--allow-incomplete");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(0, exit);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    // Precedence: --strict beats incompleteness (mirrors AnalyzeExitCode/ScanExitCode — a tripped gate is
    // accurate and actionable even when coverage was partial).
    [Fact]
    public void CapabilityDiff_StrictAddedCapabilityBeatsIncompleteness_ExitsTwoNotThree()
    {
        var baseline = WriteSnapshotFile(Snapshot("A.dll", "net10.0", Complete()));
        var incomplete = new ScanCompleteness(false, MethodsTotal: 5, MethodsAnalyzed: 4, MethodsSkipped: 1, AssemblyLoadFailures: 0);
        var candidate = WriteSnapshotFile(Snapshot("A.dll", "net10.0", incomplete, Capability.ProcessExecution));
        try
        {
            var (exit, stdout, _, exited) = RunCli("capability-diff", baseline, candidate, "--strict");

            Assert.True(exited, "CLI did not exit within the timeout.");
            Assert.Equal(2, exit);   // NOT 3, even though the candidate side is incomplete
            Assert.Contains("Candidate scan INCOMPLETE", stdout);   // still disclosed
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }

    // ⚠️ REGRESSION DISCOVERED WHILE WRITING THIS SUITE — see the final report. `analyze --snapshot` ALWAYS
    // writes TargetFramework: null (documented in the task spec's "Accepted as-is, not fixed" section, which
    // states "The composite key handles it correctly — null is just another framework value"). It does not:
    // CapabilityDiffReport.Compare's private ByAssemblyNameAndFramework groups by TargetFramework into a
    // Dictionary<string?, CapabilitySnapshot>, and .NET's Dictionary&lt;TKey,TValue&gt; throws
    // ArgumentNullException on ANY null key at runtime regardless of TKey's nullable-reference annotation — the
    // method's own comment ("Dictionary<TKey, TValue> accepts a null key at runtime for a reference-type TKey")
    // is factually wrong. The result: comparing two real `analyze --snapshot` outputs — the single most ordinary
    // use of this verb — throws an unhandled exception instead of returning any of the documented exit codes.
    // This test pins the CORRECT expected contract (exit 0, "no capability changes", per acceptance criterion 2)
    // and is expected to FAIL until src/Silvergun.CodeAnalysis.IL/CapabilityDiff.cs is fixed; it must not be
    // weakened to match the crash.
    [Fact]
    public void CapabilityDiff_TwoIdenticalAnalyzeSnapshots_BothNullTargetFramework_ExitsZero()
    {
        var baseline = TempPath("json");
        var candidate = TempPath("json");
        try
        {
            var (analyzeExit, _, _, analyzeExited) = RunCli("analyze", TargetAssembly, "--snapshot", baseline);
            Assert.True(analyzeExited, "the setup `analyze --snapshot` run did not exit within the timeout.");
            Assert.True(analyzeExit is 0 or 2 or 3, $"the setup `analyze --snapshot` run exited unexpectedly ({analyzeExit}).");
            File.Copy(baseline, candidate, overwrite: true);   // an IDENTICAL second snapshot, same TargetFramework: null

            var (exit, stdout, stderr, exited) = RunCli("capability-diff", baseline, candidate);

            Assert.True(exited, $"the CLI did not exit within the timeout (crashed?). stderr:{Environment.NewLine}{stderr}");
            Assert.True(exit == 0, $"expected exit 0 but got {exit}. stderr:{Environment.NewLine}{stderr}");
            Assert.Contains("No capability changes.", stdout);
        }
        finally
        {
            TryDelete(baseline);
            TryDelete(candidate);
        }
    }
    #endregion

    #region Methods — C: CapabilityDiffExitCode pure seam (fast, in-process; mirrors CompletenessExitCodeTests' style)
    [Theory]
    [InlineData(false, false, false, false, 0)]
    [InlineData(false, true, false, false, 0)]   // added capability present but NOT strict => 0
    [InlineData(true, true, false, false, 2)]    // strict + added capability => 2
    [InlineData(false, false, true, false, 3)]   // incomplete, not allowed => 3
    [InlineData(false, false, true, true, 0)]    // incomplete allowed => 0
    [InlineData(true, false, true, false, 3)]    // strict but no added capability => falls through to incomplete gate
    [InlineData(true, false, true, true, 0)]     // strict, no added capability, incomplete allowed => 0
    [InlineData(true, true, true, false, 2)]     // PRECEDENCE: strict + added BEATS incomplete
    [InlineData(true, true, true, true, 2)]      // ... even when --allow-incomplete is also given
    public void CapabilityDiffExitCode_FollowsStrictThenIncompletePrecedence(
        bool strict, bool hasAdded, bool isIncomplete, bool allowIncomplete, int expected)
    {
        var diff = hasAdded
            ? new CapabilityDiffReport([new AssemblyCapabilityDiff("A.dll", "net10.0", [Capability.Network], [], [])], [], [], [], [], MatchedPairCount: 1)
            : new CapabilityDiffReport([], [], [], [], [], MatchedPairCount: 1);

        Assert.Equal(expected, Program.CapabilityDiffExitCode(diff, strict, isIncomplete, allowIncomplete));
    }
    #endregion

    #region Methods — fixtures / helpers
    private static CapabilitySnapshot Snapshot(string assemblyName, string? targetFramework, ScanCompleteness completeness, params Capability[] present)
    {
        var presentSet = present.ToHashSet();
        var entries = Enum.GetValues<Capability>()
            .Select(c => new CapabilityManifestEntry(c, presentSet.Contains(c), presentSet.Contains(c) ? 1 : 0))
            .ToArray();
        return new CapabilitySnapshot(
            CapabilitySnapshot.CurrentSchemaVersion, PackageId: null, PackageVersion: null,
            AssemblyName: assemblyName, TargetFramework: targetFramework,
            Manifest: new CapabilityManifest(entries), Completeness: completeness);
    }

    private static ScanCompleteness Complete() => new(true, MethodsTotal: 5, MethodsAnalyzed: 5, MethodsSkipped: 0, AssemblyLoadFailures: 0);

    private static string WriteSnapshotFile(params CapabilitySnapshot[] snapshots)
    {
        var path = TempPath("json");
        File.WriteAllText(path, JsonSerializer.Serialize(snapshots, SnapshotJsonOptions));
        return path;
    }

    private static System.Collections.Generic.List<CapabilitySnapshot> ReadSnapshotFile(string path) =>
        JsonSerializer.Deserialize<System.Collections.Generic.List<CapabilitySnapshot>>(File.ReadAllText(path), SnapshotJsonOptions)!;

    private static string TempPath(string extension) =>
        Path.Combine(Path.GetTempPath(), $"silvergun-capdiff-{Guid.NewGuid():N}.{extension}");

    // Strips the two kinds of wall-clock content that legitimately differ between two otherwise-identical CLI
    // runs (a console-logging "[HH:mm:ss LVL]" line prefix, and a --json report's ISO-8601 AnalyzedAt) so an
    // "unchanged by --snapshot" comparison isn't flaky across the two separate process invocations it requires.
    private static string NormalizeVolatile(string text) =>
        TimestampPrefix.Replace(Iso8601.Replace(text, "TIMESTAMP"), "[TIME]");

    private static readonly Regex TimestampPrefix = new(@"\[\d{2}:\d{2}:\d{2} [A-Z]{3}\]", RegexOptions.Compiled);
    private static readonly Regex Iso8601 = new(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)", RegexOptions.Compiled);

    // Same shape as CompletenessCliTests.RunCli/IndicatorEndToEndTests.RunCli: both streams captured and drained
    // asynchronously, stdin closed, NO_COLOR set. Latin1 keeps the byte<->char mapping 1:1, which the
    // "stdout unchanged" comparisons rely on (no re-encoding surprises across two separate process runs).
    private static (int Exit, string Output, string Error, bool Exited) RunCli(params string[] args)
    {
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.Latin1,
            StandardErrorEncoding = Encoding.Latin1,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit(TimeoutMs);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return (-1, string.Empty, string.Empty, false);
        }

        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }

    // Writes a minimal valid .nupkg (root "<id>.nuspec") plus the given extra entries, using pure BCL zip.
    // Mirrors CompletenessCliTests.BuildNupkg/IndicatorEndToEndTests.BuildNupkgWithFixtureAssembly.
    private static string BuildNupkg(string id, params (string Entry, byte[] Bytes)[] extra)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{id}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>capability-diff-versions test package.</description>
                <dependencies>
                  <group targetFramework="netstandard2.0" />
                </dependencies>
              </metadata>
            </package>
            """;

        var path = Path.Combine(Path.GetTempPath(), $"silvergun-capdiff-{Guid.NewGuid():N}.nupkg");
        using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec));
            foreach (var (entry, bytes) in extra)
                Write(zip, entry, bytes);
        }
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private static readonly string CliExe = ApphostPath.Resolve(AppContext.BaseDirectory, "Silvergun.CLI");

    private static readonly string TargetAssembly = Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.dll");

    private static readonly string FixtureDll =
        Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.Fixture.dll");

    private static readonly JsonSerializerOptions SnapshotJsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    private const int TimeoutMs = 120_000;

    // A single NUL character (Unicode code point 0), used as an untrusted, hostile TargetFramework value in the
    // "⇒ CRITICAL (2026-08-20)" regression tests above. Built at runtime from a character code point rather than
    // typed as an escape sequence — see NulTfmFixture_IsActuallyASingleNulCharacter_NotASpaceOrEmptyString for
    // why, and for the runtime proof that this really is what it claims to be.
    private static readonly string NulTfm = new string((char)0, 1);
    #endregion
}
