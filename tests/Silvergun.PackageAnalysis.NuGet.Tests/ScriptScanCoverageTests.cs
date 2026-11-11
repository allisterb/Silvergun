namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// ADR 0035 decision 1 (S1, <c>docs/agent/tasks/script-scan-coverage.md</c>): <see cref="ScriptRuleScanner"/> reports
/// which script/manifest files it could NOT scan, and why, through the internal <see cref="ScriptScanOutcome"/> path
/// (<see cref="ScriptRuleScanner.ScanWithCoverage"/>, <see cref="ScriptRuleScanner.ScanPackageMetadataWithCoverage"/>),
/// while the public findings-only entry points keep their behaviour. One test per failure path of the task's table
/// (F1 missing, F2 over the size cap, F3 unreadable, F4 redaction failure, F6 no ruleset loaded), the public-parity pin,
/// and the ordering, grouping, escaping and bounding of <see cref="ScriptRuleScanner.DescribeUnscanned"/>, whose output
/// leads the report's 512-char reason.
///
/// <para>All staged content is ordinary: a <c>Write-Host</c> line, plain comment filler, and the existing
/// <see cref="PackageFixture"/> scripts where a real finding is needed. F5 (the engine throwing) has no seam: the engine
/// is the shared, process-wide processor, and no benign input makes it throw.</para>
/// </summary>
public sealed class ScriptScanCoverageTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public ScriptScanCoverageTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: F1, a listed file that is missing
    // The ADR 0034 window on the script side: listed at extraction, gone at scan time. It is named with ADR 0034's own
    // wording, and the finding of the file that WAS scanned is kept beside it (ADR 0032).
    [Fact]
    public void ScanWithCoverage_WhenAListedScriptIsDeletedBeforeTheScan_NamesItAsNoLongerExisting_AndKeepsTheOtherFindings()
    {
        using var tree = new TempTree();
        var kept = tree.Write("tools/kept.ps1", PackageFixture.SmallMatchingPs1);
        var gone = tree.Write("tools/gone.ps1", "Write-Host 'listed, then removed'\n");
        File.Delete(gone);

        var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/kept.ps1", kept), Script("tools/gone.ps1", gone)]);

        Assert.Equal(new[] { ("tools/gone.ps1", YaraPathSafety.NoLongerExists) }, outcome.Unscanned);
        Assert.Contains(outcome.Findings, f => f.RelativePath == "tools/kept.ps1");
        Assert.DoesNotContain(outcome.Findings, f => f.RelativePath == "tools/gone.ps1");
    }

    // A whole directory removed is just as gone (YaraTree.Missing answers DirectoryNotFoundException for it).
    [Fact]
    public void ScanWithCoverage_WhenAListedScriptsDirectoryIsDeleted_NamesItAsNoLongerExisting()
    {
        using var tree = new TempTree();
        var gone = tree.Write("tools/sub/gone.ps1", "Write-Host 'listed, then removed'\n");
        Directory.Delete(Path.Combine(tree.Root, "tools", "sub"), recursive: true);

        var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/sub/gone.ps1", gone)]);

        Assert.Equal(new[] { ("tools/sub/gone.ps1", YaraPathSafety.NoLongerExists) }, outcome.Unscanned);
        Assert.Empty(outcome.Findings);
    }

    // A path that is not a path at all is not "removed after it was listed": nothing confirms it ever existed, so it
    // keeps NotFound — which deliberately does not claim the file is gone — on both entry points.
    [Theory]
    [InlineData("empty")]
    [InlineData("null")]
    [InlineData("nul character")]
    public void ScanWithCoverage_ForAnEmptyOrMalformedPath_IsNotFound(string kind)
    {
        var path = kind switch
        {
            "empty" => string.Empty,
            "null" => null!,
            _ => "tools" + (char)0 + "bad.ps1",
        };
        var scanner = new ScriptRuleScanner();

        var script = scanner.ScanWithCoverage([Script("tools/odd.ps1", path)]);
        var nuspec = scanner.ScanPackageMetadataWithCoverage(path, "Odd.nuspec");

        Assert.Equal(new[] { ("tools/odd.ps1", "not found or not accessible") }, script.Unscanned);
        Assert.Equal(new[] { ("Odd.nuspec", "not found or not accessible") }, nuspec.Unscanned);
    }

    // The S5 wording, pinned literally: NotFound says only what is known ("not found or not accessible"), never ADR
    // 0034's "no longer exists", which is reserved for a file confirmed deleted after it was listed.
    [Fact]
    public void NotFound_IsNotFoundOrNotAccessible_AndIsDistinctFromNoLongerExists()
    {
        Assert.Equal("not found or not accessible", ScriptRuleScanner.NotFound);
        Assert.NotEqual(YaraPathSafety.NoLongerExists, ScriptRuleScanner.NotFound);
    }

    // Both reasons side by side in one call: the empty path is NotFound, the confirmed-deleted file is still
    // NoLongerExists — the wording change did not merge the two.
    [Fact]
    public void ScanWithCoverage_AnEmptyPathIsNotFound_WhileAConfirmedDeletedFileStillNoLongerExists()
    {
        using var tree = new TempTree();
        var gone = tree.Write("tools/gone.ps1", "Write-Host 'listed, then removed'\n");
        File.Delete(gone);

        var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/empty.ps1", string.Empty), Script("tools/gone.ps1", gone)]);

        Assert.Equal(
            new[] { ("tools/empty.ps1", "not found or not accessible"), ("tools/gone.ps1", YaraPathSafety.NoLongerExists) },
            outcome.Unscanned);
    }
    #endregion

    #region Methods: F2, over the size cap (plain filler text, written at test time)
    // The steerable skip (a package controls its scripts' size): named with the file's REAL byte count and the cap.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanWithCoverage_ForAScriptOverTheSizeCap_NamesItWithItsRealByteCount()
    {
        using var tree = new TempTree();
        var big = tree.Write("tools/big.ps1", Filler(OverCapBytes));
        var kept = tree.Write("tools/kept.ps1", PackageFixture.SmallMatchingPs1);
        Assert.Equal(OverCapBytes, new FileInfo(big).Length);   // precondition: over the cap by a non-round amount

        var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/big.ps1", big), Script("tools/kept.ps1", kept)]);

        Assert.Equal(
            new[] { ("tools/big.ps1", $"is {OverCapBytes} bytes, over the 5242880-byte script cap") },
            outcome.Unscanned);
        Assert.Contains(outcome.Findings, f => f.RelativePath == "tools/kept.ps1");
    }

    // The manifest goes through the same cap on its own entry point.
    [Fact]
    [Trait("Category", "Slow")]
    public void ScanPackageMetadataWithCoverage_ForAManifestOverTheSizeCap_NamesItWithItsRealByteCount()
    {
        using var tree = new TempTree();
        var big = tree.Write("Big.nuspec", Filler(OverCapBytes));

        var outcome = new ScriptRuleScanner().ScanPackageMetadataWithCoverage(big, "Big.nuspec");

        Assert.Equal(new[] { ("Big.nuspec", $"is {OverCapBytes} bytes, over the 5242880-byte script cap") }, outcome.Unscanned);
        Assert.Empty(outcome.Findings);
    }
    #endregion

    #region Methods: F3, a file that exists but cannot be read
#if WINDOWS
    // A Deny-everything ACE on the file only: its parent still lists it, so it exists and its length is known, but the
    // read is refused. The reason is the exception's type name. Staged under a ControlledTempDir; the ACE is removed again.
    [Fact]
    public void ScanWithCoverage_OnWindows_ForAScriptTheUserMayNotRead_NamesTheExceptionType()
    {
        using var dir = new ControlledTempDir("script-deny");
        var file = Path.Combine(dir.CreateDirectory("tools"), "denied.ps1");
        File.WriteAllText(file, "Write-Host 'unreadable'\n");
        RawAcl.SetDacl(file, $"D:P(D;;FA;;;{Sids.User().Value})");
        try
        {
            Assert.True(File.Exists(file), "precondition: the denied file must still be visible through its parent");
            Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(file));

            var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/denied.ps1", file)]);

            Assert.Equal(new[] { ("tools/denied.ps1", nameof(UnauthorizedAccessException)) }, outcome.Unscanned);
        }
        finally
        {
            RawAcl.SetDacl(file, RawAcl.OwnerOnlyDacl());
        }
    }
#endif

    // The Linux twin: mode 000 on the file. stat still works (the parent is searchable); the open is refused.
    [LinuxPermissionsFact]
    public void ScanWithCoverage_OnLinux_ForAMode000Script_NamesTheExceptionType()
    {
        using var tree = new TempTree();
        var file = tree.Write("tools/denied.ps1", "Write-Host 'unreadable'\n");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxPermissionsFact] must have gated this test to Linux.");
        File.SetUnixFileMode(file, UnixFileMode.None);
        try
        {
            Assert.True(File.Exists(file));
            Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(file));   // precondition (not running as root)

            var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/denied.ps1", file)]);

            Assert.Equal(new[] { ("tools/denied.ps1", nameof(UnauthorizedAccessException)) }, outcome.Unscanned);
        }
        finally
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
    #endregion

    #region Methods: F4, a transform that throws (reached through the private Run, there is no public seam)
    // RedactProse never throws, so the path is unreachable through the public API; the shared Run is driven directly
    // with a transform that does. The file is skipped, never scanned unredacted.
    [Fact]
    public void Run_WhenTheTransformThrows_NamesTheFileAsRedactionFailed_AndScansNothing()
    {
        using var tree = new TempTree();
        var nuspec = tree.Write("Some.nuspec", PackageFixture.SmallMatchingPs1);
        var run = typeof(ScriptRuleScanner).GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Static)!;
        Func<string, string> throwing = _ => throw new InvalidOperationException("redaction failed on purpose");

        var outcome = (ScriptScanOutcome)run.Invoke(null, [new[] { (nuspec, "Some.nuspec") }, throwing, ScriptFindingSource.PackageMetadata])!;

        Assert.Equal(new[] { ("Some.nuspec", "content redaction failed") }, outcome.Unscanned);
        Assert.Empty(outcome.Findings);
    }
    #endregion

    #region Methods: F6, no ruleset loaded
    // F6 is reachable without a src change: a second copy of this library, loaded into its own AssemblyLoadContext with
    // its rule resources renamed, has its OWN sharedProcessor, whose BuildProcessor genuinely finds no ruleset and
    // returns null — the real production path, without touching the shared processor every other test uses. Every
    // file, even one that would match, is then unscanned with "no script rules loaded" (the observable that replaced
    // the removed ScriptScanOutcome.EngineAvailable flag: no engine means every handed-in file is NoRulesLoaded).
    [Fact]
    public void ScanWithCoverage_WhenNoRulesetLoads_EveryFileIsUnscannedWithNoRulesLoaded()
    {
        using var tree = new TempTree();
        var a = tree.Write("tools/install.ps1", PackageFixture.MaliciousPs1);
        var b = tree.Write("build/x.targets", PackageFixture.MaliciousTargets);
        using var warnings = new WarningCapture();
        using var isolated = new RulelessCopy();

        var outcome = isolated.ScanWithCoverage(("tools/install.ps1", a), ("build/x.targets", b));

        Assert.Equal(2, outcome.Unscanned.Count);   // every file handed in ...
        Assert.All(outcome.Unscanned, u => Assert.Equal(ScriptRuleScanner.NoRulesLoaded, u.Reason));   // ... is NoRulesLoaded
        Assert.Equal(0, outcome.FindingCount);
        Assert.Equal(new[] { ("tools/install.ps1", "no script rules loaded"), ("build/x.targets", "no script rules loaded") }, outcome.Unscanned);
        Assert.Single(warnings.Warnings, w => w.Contains("No backdoor rulesets loaded; script content scanning is disabled.", StringComparison.Ordinal));
        Assert.Equal("no script rules loaded: 'tools/install.ps1', 'build/x.targets'", ScriptRuleScanner.DescribeUnscanned(outcome.Unscanned));
    }

    // ... and through PackageScanner of the same copy: the whole package is Unavailable, every file (the nuspec too)
    // named under the one no-rules clause, and there are no findings.
    [Fact]
    public void PackageScanner_WhenNoRulesetLoads_ReportsUnavailableNamingEveryFile()
    {
        using var isolated = new RulelessCopy();

        var (status, reason, findings) = isolated.ScanPackage(fixture.PkgScriptPath);

        Assert.Equal(nameof(ScriptScanStatus.Unavailable), status);
        Assert.Equal(0, findings);
        Assert.StartsWith("4 of 4 script/manifest file(s) were not scanned: no script rules loaded: '", reason, StringComparison.Ordinal);
        Assert.Contains($"'{PackageFixture.PkgScriptId}.nuspec'", reason, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: the public entry points are unchanged
    // Scan, ScanFile and ScanPackageMetadata return exactly the findings their coverage twins carry, for every script and
    // the manifest of the fixture whose content trips the rules — and those are not empty, so the comparison has teeth.
    [Fact]
    public void ThePublicEntryPoints_ReturnTheSameFindingsAsTheirCoverageTwins()
    {
        var open = NuGetPackage.Open(fixture.PkgNuspecMatchPath);
        Assert.True(open.IsSuccess, open.Message);
        using var nuspecPackage = open.Value;
        var opened = NuGetPackage.Open(fixture.PkgScriptPath);
        Assert.True(opened.IsSuccess, opened.Message);
        using var package = opened.Value;
        var scanner = new ScriptRuleScanner();

        var coverage = scanner.ScanWithCoverage(package.Scripts);
        var metadata = scanner.ScanPackageMetadataWithCoverage(nuspecPackage.NuspecPath!, fixture.NuspecMatchFileName);

        Assert.NotEmpty(coverage.Findings);
        Assert.NotEmpty(metadata.Findings);
        Assert.Empty(coverage.Unscanned);
        Assert.Empty(metadata.Unscanned);
        Assert.Equal(Json(coverage.Findings), Json(scanner.Scan(package.Scripts)));
        Assert.Equal(Json(metadata.Findings), Json(scanner.ScanPackageMetadata(nuspecPackage.NuspecPath!, fixture.NuspecMatchFileName)));
        foreach (var script in package.Scripts)
            Assert.Equal(Json(scanner.ScanWithCoverage([script]).Findings), Json(scanner.ScanFile(script.FullPath, script.RelativePath)));
    }

    // The public entry points still never throw and still return no findings for a file they could not scan.
    [Fact]
    public void ThePublicEntryPoints_ForAMissingFile_ReturnNoFindingsAndDoNotThrow()
    {
        using var tree = new TempTree();
        var missing = Path.Combine(tree.Root, "missing.ps1");
        var scanner = new ScriptRuleScanner();

        Assert.Empty(scanner.Scan([Script("missing.ps1", missing)]));
        Assert.Empty(scanner.ScanFile(missing, "missing.ps1"));
        Assert.Empty(scanner.ScanPackageMetadata(missing, "missing.nuspec"));
    }
    #endregion

    #region Methods: DescribeUnscanned
    // The most actionable clause first, whatever order the files came in: over the cap (steerable), then no rules, then
    // the files that are gone, then everything else with its reason. A reasoned item is quoted WITH its reason
    // ('path (reason)'), the format YaraXWorkerScanner's reasoned clause uses; the grouped clauses quote paths alone.
    [Fact]
    public void DescribeUnscanned_OrdersTheClauses_OverCapThenNoRulesThenGoneThenOthers()
    {
        var described = ScriptRuleScanner.DescribeUnscanned(
        [
            ("tools/locked.ps1", nameof(UnauthorizedAccessException)),
            ("tools/gone.ps1", YaraPathSafety.NoLongerExists),
            ("tools/norules.ps1", ScriptRuleScanner.NoRulesLoaded),
            ("tools/odd.ps1", ScriptRuleScanner.NotFound),
            ("tools/big.ps1", $"is 6000000 bytes{ScriptRuleScanner.OverCapSuffix}"),
        ]);

        Assert.Equal(
            "'tools/big.ps1 (is 6000000 bytes, over the 5242880-byte script cap)'; "
            + "no script rules loaded: 'tools/norules.ps1'; "
            + "1 of them no longer exists (removed after it was listed): 'tools/gone.ps1'; "
            + "'tools/locked.ps1 (UnauthorizedAccessException)', 'tools/odd.ps1 (not found or not accessible)'",
            described);
    }

    // An over-cap file listed LAST, after several other failures, still leads.
    [Fact]
    public void DescribeUnscanned_AnOverCapFileLeads_EvenWhenListedAfterOtherFailures()
    {
        var unscanned = Enumerable.Range(1, 12).Select(i => ($"tools/f{i:D2}.ps1", nameof(IOException)))
            .Append(("tools/padded.ps1", $"is 9999999 bytes{ScriptRuleScanner.OverCapSuffix}"))
            .ToArray();

        var described = ScriptRuleScanner.DescribeUnscanned(unscanned);

        Assert.StartsWith("'tools/padded.ps1 (is 9999999 bytes, over the 5242880-byte script cap)'; ", described, StringComparison.Ordinal);
    }

    // The files that are gone are grouped under one clause, with the count pluralised, never repeated per file.
    [Fact]
    public void DescribeUnscanned_GroupsTheGoneFilesAndPluralises()
    {
        var described = ScriptRuleScanner.DescribeUnscanned(
        [
            ("tools/a.ps1", YaraPathSafety.NoLongerExists),
            ("tools/b.ps1", nameof(IOException)),
            ("tools/c.ps1", YaraPathSafety.NoLongerExists),
        ]);

        Assert.Equal(
            "2 of them no longer exist (each removed after it was listed): 'tools/a.ps1', 'tools/c.ps1'; 'tools/b.ps1 (IOException)'",
            described);
    }

    // A hostile relative path — a line break, ESC and a bidi override, built from code points — is escaped in the
    // description, both when DescribeUnscanned is handed it raw and when it comes out of the scanner itself.
    [Fact]
    public void DescribeUnscanned_EscapesAHostileRelativePath()
    {
        var hostile = "tools/pay" + (char)0x0A + "lo" + (char)0x1B + "[31m" + Rlo + "ad.ps1";

        var described = ScriptRuleScanner.DescribeUnscanned([(hostile, ScriptRuleScanner.NotFound)]);

        Assert.Equal(@"'tools/pay\nlo\x1b[31m" + EscapedRlo + "ad.ps1 (not found or not accessible)'", described);
        AssertNoRawControl(described);
    }

    [Fact]
    public void ScanWithCoverage_EscapesTheUnscannedRelativePath()
    {
        using var tree = new TempTree();
        var hostile = "tools/pay" + (char)0x0A + "load" + Rlo + ".ps1";

        var outcome = new ScriptRuleScanner().ScanWithCoverage([Script(hostile, Path.Combine(tree.Root, "missing.ps1"))]);

        var (relativePath, _) = Assert.Single(outcome.Unscanned);
        Assert.Equal(@"tools/pay\nload" + EscapedRlo + ".ps1", relativePath);
        AssertNoRawControl(ScriptRuleScanner.DescribeUnscanned(outcome.Unscanned));
    }

    // Each list is bounded: ten names, then ", and N more" — in a reasoned clause and in a grouped one.
    [Fact]
    public void DescribeUnscanned_BoundsEachListToTenAndCountsTheRest()
    {
        var others = Enumerable.Range(1, 13).Select(i => ($"tools/o{i:D2}.ps1", nameof(IOException)));
        var gone = Enumerable.Range(1, 12).Select(i => ($"tools/g{i:D2}.ps1", YaraPathSafety.NoLongerExists));

        var described = ScriptRuleScanner.DescribeUnscanned(others.Concat(gone).ToArray());

        var clauses = described.Split("; ");
        Assert.Equal(2, clauses.Length);
        Assert.StartsWith("12 of them no longer exist (each removed after it was listed): 'tools/g01.ps1', ", clauses[0], StringComparison.Ordinal);
        Assert.EndsWith("'tools/g10.ps1', and 2 more", clauses[0], StringComparison.Ordinal);
        Assert.DoesNotContain("g11", clauses[0], StringComparison.Ordinal);
        Assert.EndsWith("'tools/o10.ps1 (IOException)', and 3 more", clauses[1], StringComparison.Ordinal);
        Assert.DoesNotContain("o11", clauses[1], StringComparison.Ordinal);
    }

    [Fact]
    public void DescribeUnscanned_ForNothingUnscanned_IsEmpty() =>
        Assert.Equal(string.Empty, ScriptRuleScanner.DescribeUnscanned([]));
    #endregion

    #region Methods: N4, the per-file warnings escape what the package authored (ADR 0031 decision 4)
    // The F1 warning: a hostile relative path (a line break that would forge a log line, ESC, a bidi override, all built
    // from code points) reaches the log escaped, with the S5 NotFound wording.
    [Fact]
    public void ScanWithCoverage_ForAMissingScriptWithAHostileRelativePath_WarnsWithThePathEscaped()
    {
        var hostile = "tools/pay" + (char)0x0A + "[ERR] forged" + (char)0x1B + "[31m" + Rlo + "x.ps1";
        using var warnings = new WarningCapture();

        new ScriptRuleScanner().ScanWithCoverage([Script(hostile, string.Empty)]);

        var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Skipping rule scan for", StringComparison.Ordinal));
        Assert.Equal(@"Skipping rule scan for tools/pay\n[ERR] forged\x1b[31m" + EscapedRlo + "x.ps1: not found or not accessible.", warning);
        AssertNoRawControl(warning);
    }

    // The F4 warning: both the relative path AND the exception message (which, in general, can quote package content)
    // are escaped. Reached through the private Run, as in the F4 test above.
    [Fact]
    public void Run_WhenTheTransformThrowsAHostileMessage_WarnsWithThePathAndTheMessageEscaped()
    {
        using var tree = new TempTree();
        var nuspec = tree.Write("Some.nuspec", "<package />\n");
        var hostilePath = "Some" + (char)0x0D + (char)0x0A + Rlo + ".nuspec";
        var hostileMessage = "bad" + (char)0x0A + "[ERR] forged" + (char)0x1B + "[2J" + Rlo;
        var run = typeof(ScriptRuleScanner).GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Static)!;
        Func<string, string> throwing = _ => throw new InvalidOperationException(hostileMessage);
        using var warnings = new WarningCapture();

        var outcome = (ScriptScanOutcome)run.Invoke(null, [new[] { (nuspec, hostilePath) }, throwing, ScriptFindingSource.PackageMetadata])!;

        Assert.Equal(new[] { (@"Some\r\n" + EscapedRlo + ".nuspec", ScriptRuleScanner.RedactionFailed) }, outcome.Unscanned);
        var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Skipping rule scan for", StringComparison.Ordinal));
        Assert.Equal(
            @"Skipping rule scan for Some\r\n" + EscapedRlo + @".nuspec: content redaction failed (bad\n[ERR] forged\x1b[2J" + EscapedRlo + ").",
            warning);
        AssertNoRawControl(warning);
    }

#if WINDOWS
    // The catch-all warning ("Rule scan failed for …: {message}"): the exception's message quotes the full path, so a
    // bidi override in the file name (legal on NTFS) would reach the log raw. Staged as F3 is: a Deny ACE, removed again.
    [Fact]
    public void ScanWithCoverage_OnWindows_WhenTheReadFailsOnAFileWithABidiName_WarnsWithTheMessageEscaped()
    {
        using var dir = new ControlledTempDir("script-deny-bidi");
        var file = Path.Combine(dir.CreateDirectory("tools"), "de" + Rlo + "nied.ps1");
        File.WriteAllText(file, "Write-Host 'unreadable'\n");
        RawAcl.SetDacl(file, $"D:P(D;;FA;;;{Sids.User().Value})");
        try
        {
            var raw = Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(file)).Message;
            Assert.Contains(Rlo, raw);   // precondition: the message really does quote the raw name
            using var warnings = new WarningCapture();

            var outcome = new ScriptRuleScanner().ScanWithCoverage([Script("tools/de" + Rlo + "nied.ps1", file)]);

            Assert.Equal(new[] { ("tools/de" + EscapedRlo + "nied.ps1", nameof(UnauthorizedAccessException)) }, outcome.Unscanned);
            var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Rule scan failed for", StringComparison.Ordinal));
            Assert.Equal($"Rule scan failed for tools/de{EscapedRlo}nied.ps1: {YaraPathSafety.Escape(raw)}", warning);
            Assert.Contains("de" + EscapedRlo + "nied.ps1", warning, StringComparison.Ordinal);
            AssertNoRawControl(warning);
        }
        finally
        {
            RawAcl.SetDacl(file, RawAcl.OwnerOnlyDacl());
        }
    }
#endif

    // The Linux twin: a mode-000 file whose name carries a line break and a bidi override (both legal there).
    [LinuxPermissionsFact]
    public void ScanWithCoverage_OnLinux_WhenTheReadFailsOnAFileWithAHostileName_WarnsWithTheMessageEscaped()
    {
        using var tree = new TempTree();
        var name = "de" + (char)0x0A + Rlo + "nied.ps1";
        var file = tree.Write("tools/" + name, "Write-Host 'unreadable'\n");
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxPermissionsFact] must have gated this test to Linux.");
        File.SetUnixFileMode(file, UnixFileMode.None);
        try
        {
            var raw = Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(file)).Message;   // precondition (not root)
            using var warnings = new WarningCapture();

            new ScriptRuleScanner().ScanWithCoverage([Script("tools/" + name, file)]);

            var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Rule scan failed for", StringComparison.Ordinal));
            Assert.Equal($@"Rule scan failed for tools/de\n{EscapedRlo}nied.ps1: {YaraPathSafety.Escape(raw)}", warning);
            AssertNoRawControl(warning);
        }
        finally
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
    #endregion

    #region Methods: helpers
    private static PackageScript Script(string relativePath, string fullPath) => new(relativePath, fullPath, PackageItemRole.Tools);

    // Ordinary PowerShell comment lines, cut to exactly `length` bytes. Plain text by design (no random padding): this
    // file is written straight to disk, never zipped, so its compressibility does not matter.
    internal static byte[] Filler(long length)
    {
        var line = Encoding.ASCII.GetBytes("# filler comment line for the script size cap test\n");
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i += line.Length)
            line.AsSpan(0, (int)Math.Min(line.Length, bytes.Length - i)).CopyTo(bytes.AsSpan(i));
        return bytes;
    }

    private static string Json(IReadOnlyList<ScriptFinding> findings) => JsonSerializer.Serialize(findings);

    private static void AssertNoRawControl(string text) =>
        Assert.DoesNotContain(text, c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F || c == Rlo);
    #endregion

    #region Nested types
    /// <summary>
    /// A second copy of <c>Silvergun.PackageAnalysis.NuGet</c> in its own collectible <see cref="AssemblyLoadContext"/>,
    /// with the UTF-8 names of its embedded rule resources changed (<c>.Resources.BackdoorRules.</c> /
    /// <c>.Resources.SilvergunRules.</c>, one letter each) so its BuildProcessor's resource filter matches none of them.
    /// The markers in its code are UTF-16 user strings and are untouched. Its dependencies resolve from the default
    /// context. Its statics (the shared processor among them) are its own, so nothing the other tests use changes.
    /// </summary>
    private sealed class RulelessCopy : IDisposable
    {
        public RulelessCopy()
        {
            var image = File.ReadAllBytes(typeof(ScriptRuleScanner).Assembly.Location);
            foreach (var marker in Markers)
                Assert.True(Rename(image, marker) > 0, $"precondition: no resource name carries '{marker}'");
            context = new AssemblyLoadContext("silvergun-f6-" + Guid.NewGuid().ToString("N"), isCollectible: true);
            assembly = context.LoadFromStream(new MemoryStream(image));
            Assert.DoesNotContain(assembly.GetManifestResourceNames(), n => Markers.Any(n.Contains));   // precondition
            Assert.Contains(typeof(ScriptRuleScanner).Assembly.GetManifestResourceNames(), n => Markers.Any(n.Contains));
        }

        public (int FindingCount, IReadOnlyList<(string RelativePath, string Reason)> Unscanned) ScanWithCoverage(
            params (string RelativePath, string FullPath)[] files)
        {
            var scannerType = Type("ScriptRuleScanner");
            var scriptType = Type("PackageScript");
            var tools = Enum.Parse(Type("PackageItemRole"), nameof(PackageItemRole.Tools));
            var scripts = Array.CreateInstance(scriptType, files.Length);
            for (var i = 0; i < files.Length; i++)
                scripts.SetValue(Activator.CreateInstance(scriptType, files[i].RelativePath, files[i].FullPath, tools), i);

            var outcome = scannerType.GetMethod("ScanWithCoverage", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(Activator.CreateInstance(scannerType), [scripts])!;
            return (
                ((IEnumerable)Property(outcome, "Findings")!).Cast<object>().Count(),
                (IReadOnlyList<(string, string)>)Property(outcome, "Unscanned")!);
        }

        public (string? Status, string? Reason, int FindingCount) ScanPackage(string nupkg)
        {
            // Reflection passes every parameter, the optional ones too: (path, resolveReferences, runYara, yaraScanner,
            // runReachability). The internal overload taking a reachability delegate is not Public, so this stays unique.
            var scan = Type("PackageScanner").GetMethod("Scan", BindingFlags.Public | BindingFlags.Static)!
                .Invoke(null, [nupkg, false, false, null, false])!;
            Assert.True((bool)Property(scan, "IsSuccess")!, (string?)Property(scan, "Message"));
            var report = Property(scan, "Value")!;
            return (
                Property(report, "ScriptScanStatus")?.ToString(),
                (string?)Property(report, "ScriptScanUnavailableReason"),
                ((IEnumerable)Property(report, "ScriptFindings")!).Cast<object>().Count());
        }

        public void Dispose() => context.Unload();

        private Type Type(string name) => assembly.GetType("Silvergun.PackageAnalysis.NuGet." + name, throwOnError: true)!;

        // A public property, or (Result<T>.Message) a public field.
        private static object? Property(object target, string name) =>
            target.GetType().GetProperty(name) is { } property ? property.GetValue(target) : target.GetType().GetField(name)!.GetValue(target);

        // Rewrites every UTF-8 occurrence of `marker` in place, "Rules." -> "Rulez." (same length); how many it rewrote.
        private static int Rename(byte[] image, string marker)
        {
            var from = Encoding.UTF8.GetBytes(marker);
            var to = Encoding.UTF8.GetBytes(marker.Replace("Rules.", "Rulez.", StringComparison.Ordinal));
            var count = 0;
            for (int start = 0, at; (at = image.AsSpan(start).IndexOf(from)) >= 0; start += at + from.Length, count++)
                to.CopyTo(image, start + at);
            return count;
        }

        private static readonly string[] Markers = [".Resources.BackdoorRules.", ".Resources.SilvergunRules."];

        private readonly AssemblyLoadContext context;
        private readonly Assembly assembly;
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    // 5 MiB + 1234: over the cap by an amount that is not a round number, so the reason must carry the real count.
    private const long OverCapBytes = 5L * 1024 * 1024 + 1234;

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw.
    private const char Rlo = (char)0x202E;

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries that sequence.
    private const string EscapedRlo = @"\" + "u202e";
    #endregion
}

/// <summary>
/// A Linux-only fact for a scenario that needs POSIX permission bits (mode 000 on a file the current user owns). A
/// VISIBLE skip elsewhere; the Windows twin uses a Deny ACE.
/// </summary>
public sealed class LinuxPermissionsFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxPermissionsFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "Needs POSIX permission bits (chmod 000) to stage a file the current user cannot read; the Windows twin uses a Deny ACE. Run the suite under WSL (dotnet test <proj> -f net10.0) for this to execute.";
    }
    #endregion
}
