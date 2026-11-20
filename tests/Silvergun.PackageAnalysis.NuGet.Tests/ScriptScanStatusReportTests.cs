namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// ADR 0035 decision 1 at the report: <see cref="PackageCapabilityReport.ScriptScanStatus"/> and
/// <see cref="PackageCapabilityReport.ScriptScanUnavailableReason"/>, mirroring the YARA pair
/// (<see cref="YaraUnavailableReasonTests"/>). Two contracts.
///
/// <para><b>Who sets them.</b> <see cref="PackageScanner.Scan"/>: <see cref="ScriptScanStatus.Completed"/> exactly when
/// no script/manifest file (the <c>.nuspec</c> counted) went unscanned, otherwise
/// <see cref="ScriptScanStatus.Unavailable"/> with the findings of the files that did scan KEPT, a reason leading with
/// "{unscanned} of {total}", and ONE summary warning per package.</para>
///
/// <para><b>The report.</b> The status is always written; the reason is escaped and bounded to 512 on every
/// assignment (FromJson included), idempotently, and omitted when null. JSON that predates both reads as
/// <see cref="ScriptScanStatus.Unavailable"/> with no reason (ADR 0035 review N5: a report older than the field was
/// produced by a scanner whose failures were silent zeros, so "not verified" is the honest reading — as for YARA).</para>
///
/// <para><b>The manifest that never reached disk</b> (ADR 0035 review W1): <see cref="NuGetPackage.Open"/> succeeds only
/// when NuGet's reader found a root <c>.nuspec</c> in the zip, so a null <see cref="NuGetPackage.NuspecPath"/> is an
/// unscanned manifest, never an absent one: it is listed as <see cref="ScriptRuleScanner.ManifestPlaceholder"/> with
/// <see cref="ScriptRuleScanner.ManifestNotOnDisk"/>, and the total is always the scripts plus one. Staged naturally on
/// Windows (a root <c>CON.nuspec</c>, which the extractor cannot create), with its Linux twin, and on every platform by
/// handing <c>PackageScanner.ScanScripts</c> a package built with a null manifest path.</para>
///
/// <para>The over-cap packages are the existing <see cref="PackageFixture"/> ones (PkgOversize, PkgNuspecOversize):
/// their padding is random so the zipped entry clears the extractor's ratio cap.</para>
/// </summary>
public sealed class ScriptScanStatusReportTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public ScriptScanStatusReportTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: PackageScanner
    // A package whose every script and manifest scanned: Completed, and the JSON carries the status but no reason.
    [Theory]
    [InlineData(PackageFixture.PkgAId)]
    [InlineData(PackageFixture.PkgScriptId)]
    public void Scan_WhenEveryFileScanned_IsCompleted_WithNoReasonInTheJson(string id)
    {
        using var warnings = new WarningCapture();

        var report = Scan(id == PackageFixture.PkgAId ? fixture.PkgAPath : fixture.PkgScriptPath);

        Assert.Equal(ScriptScanStatus.Completed, report.ScriptScanStatus);
        Assert.Null(report.ScriptScanUnavailableReason);
        var json = report.ToJson();
        Assert.Contains("\"ScriptScanStatus\": \"Completed\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ScriptScanUnavailableReason", json, StringComparison.Ordinal);
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("Script content scanning INCOMPLETE", StringComparison.Ordinal));
    }

    // One script over the cap beside one that matches: Unavailable, the match KEPT (a real detection), and the reason
    // leads with "1 of {scripts + nuspec}" and names the skipped file with its real size.
    [Fact]
    public void Scan_WithOneUnscannedScriptAndOneThatMatches_IsUnavailable_KeepsTheFinding_AndLeadsWithTheCount()
    {
        var report = Scan(fixture.PkgOversizePath);

        Assert.Equal(3, report.Scripts.Count);   // precondition: big.ps1, malformed.ps1, small.ps1 (+ the nuspec)
        var big = Assert.Single(report.Scripts, s => s.RelativePath.EndsWith("big.ps1", StringComparison.Ordinal)).RelativePath;
        Assert.Equal(ScriptScanStatus.Unavailable, report.ScriptScanStatus);
        Assert.Contains(report.ScriptFindings, f => f.RelativePath.EndsWith("small.ps1", StringComparison.Ordinal));
        Assert.Equal(
            $"1 of 4 script/manifest file(s) were not scanned: '{big} (is {5 * 1024 * 1024 + 4096} bytes, over the 5242880-byte script cap)'",
            report.ScriptScanUnavailableReason);
    }

    // The manifest is one of the files: an over-cap nuspec alone makes the scan Unavailable, the total counts it
    // (1 script + the nuspec = 2), and the script's finding is kept.
    [Fact]
    public void Scan_WhenOnlyTheNuspecIsUnscanned_IsUnavailable_AndTheTotalCountsTheNuspec()
    {
        var report = Scan(fixture.PkgNuspecOversizePath);

        Assert.Single(report.Scripts);   // precondition: tools/keep.ps1 only
        Assert.Equal(ScriptScanStatus.Unavailable, report.ScriptScanStatus);
        Assert.Matches(
            $"^1 of 2 script/manifest file\\(s\\) were not scanned: '{fixture.NuspecOversizeFileName} \\(is [0-9]+ bytes, over the 5242880-byte script cap\\)'$",
            report.ScriptScanUnavailableReason);
        Assert.Contains(report.ScriptFindings, f => f.RelativePath.EndsWith("keep.ps1", StringComparison.Ordinal));
    }

    // One summary warning per incomplete package, never one per file, naming the package, the count and the finding
    // count; the reason in it is escaped (and the scanner's own per-file warnings stay).
    [Fact]
    public void Scan_WhenIncomplete_LogsExactlyOneSummaryWarning()
    {
        using var warnings = new WarningCapture();

        var report = Scan(fixture.PkgOversizePath);

        var summary = Assert.Single(warnings.Warnings, w => w.Contains("Script content scanning INCOMPLETE", StringComparison.Ordinal));
        Assert.StartsWith($"Script content scanning INCOMPLETE for {PackageFixture.PkgOversizeId}: 1 of 4 script/manifest file(s) were not scanned: ", summary, StringComparison.Ordinal);
        Assert.Contains($"{report.ScriptFindings.Count} finding(s) from the files that were scanned are reported", summary, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w.StartsWith("Skipping rule scan for", StringComparison.Ordinal));
    }

    // The report's reason is the scanner's description verbatim after the count, so the clause ordering carries through.
    [Fact]
    public void Scan_TheReasonIsTheCountThenTheScannersDescription()
    {
        var report = Scan(fixture.PkgOversizePath);
        var big = report.Scripts.Single(s => s.RelativePath.EndsWith("big.ps1", StringComparison.Ordinal)).RelativePath;

        var description = ScriptRuleScanner.DescribeUnscanned([(big, $"is {5 * 1024 * 1024 + 4096} bytes{ScriptRuleScanner.OverCapSuffix}")]);

        Assert.Equal("1 of 4 script/manifest file(s) were not scanned: " + description, report.ScriptScanUnavailableReason);
    }
    #endregion

    #region Methods: the report's init accessor
    [Fact]
    public void TheReason_IsEscapedAndBoundedOnConstruction()
    {
        var report = Report() with { ScriptScanUnavailableReason = Hostile };

        var reason = report.ScriptScanUnavailableReason!;
        Assert.Equal(512, PackageCapabilityReport.MaxScriptScanUnavailableReasonChars);
        Assert.Equal(PackageCapabilityReport.MaxScriptScanUnavailableReasonChars, reason.Length);
        Assert.StartsWith(EscapedHostile, reason, StringComparison.Ordinal);
        Assert.EndsWith("...", reason, StringComparison.Ordinal);
        AssertNoRawControl(reason);
    }

    [Fact]
    public void AnOrdinaryReason_IsKeptVerbatim()
    {
        var report = Report() with { ScriptScanUnavailableReason = "1 of 2 script/manifest file(s) were not scanned: 'a.ps1 (not found or not accessible)'" };

        Assert.Equal("1 of 2 script/manifest file(s) were not scanned: 'a.ps1 (not found or not accessible)'", report.ScriptScanUnavailableReason);
    }

    // JSON is input too: FromJson goes through the same accessor, so raw control and bidi characters (JSON escapes that
    // decode to the raw characters) and an over-long value come out escaped and cut.
    [Fact]
    public void FromJson_EscapesAndBoundsTheReason()
    {
        var json = Report().ToJson().TrimEnd().TrimEnd('}') + $",\n  \"ScriptScanUnavailableReason\": {JsonSerializer.Serialize(Hostile)}\n}}";
        Assert.Contains("\\n", json, StringComparison.Ordinal);   // precondition: JSON-escaped, so it decodes to a raw LF

        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(PackageCapabilityReport.MaxScriptScanUnavailableReasonChars, restored.ScriptScanUnavailableReason!.Length);
        Assert.StartsWith(EscapedHostile, restored.ScriptScanUnavailableReason, StringComparison.Ordinal);
        AssertNoRawControl(restored.ScriptScanUnavailableReason);
    }

    [Fact]
    public void ARoundTrip_LeavesTheStatusTheReasonAndTheJsonUnchanged()
    {
        var report = Report() with { ScriptScanUnavailableReason = Hostile };

        var json = report.ToJson();
        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(ScriptScanStatus.Unavailable, restored.ScriptScanStatus);
        Assert.Equal(report.ScriptScanUnavailableReason, restored.ScriptScanUnavailableReason);
        Assert.Equal(json, restored.ToJson());
    }

    // The status is always written, as its enum name; a null reason is absent and a set one present.
    [Fact]
    public void TheStatusIsAlwaysInTheJson_AndANullReasonIsAbsent()
    {
        var plain = Report(ScriptScanStatus.Completed);
        var withReason = Report() with { ScriptScanUnavailableReason = "why" };

        Assert.Contains("\"ScriptScanStatus\": \"Completed\"", plain.ToJson(), StringComparison.Ordinal);
        Assert.DoesNotContain("ScriptScanUnavailableReason", plain.ToJson(), StringComparison.Ordinal);
        Assert.Contains("\"ScriptScanStatus\": \"Unavailable\"", withReason.ToJson(), StringComparison.Ordinal);
        Assert.Contains("\"ScriptScanUnavailableReason\": \"why\"", withReason.ToJson(), StringComparison.Ordinal);
    }

    // JSON written before the field existed: Unavailable (the record parameter default since S5/N5, exactly as
    // YaraScanStatus), with no reason — the CLI then raises the script caveat for it (pinned in the CLI suite).
    [Fact]
    public void LegacyJson_WithoutTheFields_IsUnavailableWithANullReason()
    {
        const string legacyJson = """
            {
              "Package": { "Id": "Legacy.Package", "Version": "1.0.0", "Authors": "Old Author", "Description": "Old.", "Dependencies": [] },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": []
            }
            """;

        var restored = PackageCapabilityReport.FromJson(legacyJson)!;

        Assert.Equal(ScriptScanStatus.Unavailable, restored.ScriptScanStatus);
        Assert.Null(restored.ScriptScanUnavailableReason);
    }

    // An explicit "NotRun" in JSON is still honoured as NotRun: the default only fills a MISSING field.
    [Fact]
    public void Json_WithAnExplicitNotRun_IsStillNotRun()
    {
        var json = Report(ScriptScanStatus.Completed).ToJson()
            .Replace("\"ScriptScanStatus\": \"Completed\"", "\"ScriptScanStatus\": \"NotRun\"", StringComparison.Ordinal);
        Assert.Contains("\"ScriptScanStatus\": \"NotRun\"", json, StringComparison.Ordinal);   // precondition

        Assert.Equal(ScriptScanStatus.NotRun, PackageCapabilityReport.FromJson(json)!.ScriptScanStatus);
    }

    // The record parameter default itself (what a hand-built report that omits the argument gets): Unavailable.
    [Fact]
    public void TheRecordDefault_IsUnavailable()
    {
        var report = new PackageCapabilityReport(
            new PackageIdentityInfo("Default.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch, Array.Empty<AssemblyScanResult>(), Array.Empty<PackageScript>(), Array.Empty<ScriptFinding>());

        Assert.Equal(ScriptScanStatus.Unavailable, report.ScriptScanStatus);
        Assert.Null(report.ScriptScanUnavailableReason);
    }
    #endregion

    #region Methods: W1, a manifest that never reached disk
    // The natural trigger: a root CON.nuspec. NuGet's reader reads it from the zip, so Open succeeds, but Windows cannot
    // create a file named after a reserved device, so the manifest never reaches disk and NuspecPath is null. The
    // package is Unavailable, its two scripts still scanned, and the manifest counted in the total (2 scripts + 1).
    [WindowsExtractionFact("Windows cannot create a file named after a reserved DOS device, so a root CON.nuspec never reaches disk")]
    public void Scan_OnWindows_ForARootConNuspec_IsUnavailable_NamingTheManifestAsNotOnDisk()
    {
        using var tree = new TempTree();
        var nupkg = ConNuspecPackage(tree);
        using (var opened = OpenPackage(nupkg))
        {
            Assert.Null(opened.NuspecPath);            // precondition: the manifest really never reached disk
            Assert.Equal(2, opened.Scripts.Count);     // ... while the scripts did
        }
        using var warnings = new WarningCapture();

        var report = Scan(nupkg);

        Assert.Equal(ScriptScanStatus.Unavailable, report.ScriptScanStatus);
        Assert.Equal(ManifestNotOnDiskReason(total: 3), report.ScriptScanUnavailableReason);
        // N-3 (ADR 0035 S5 review): the rendered shape, with no stacked brackets around the placeholder. The wording is
        // the constant's (tasks/entry-aliasing-coverage.md: "not matched on disk", since it also covers name mismatches),
        // and the constant itself is pinned literally once here so an edit to it stays visible.
        Assert.Equal("not matched on disk", ScriptRuleScanner.ManifestNotOnDisk);
        Assert.Contains($"'package manifest ({ScriptRuleScanner.ManifestNotOnDisk})'", report.ScriptScanUnavailableReason, StringComparison.Ordinal);
        Assert.DoesNotContain("(package manifest)", report.ScriptScanUnavailableReason, StringComparison.Ordinal);
        Assert.Contains(report.ScriptFindings, f => f.RelativePath == "tools/match.ps1");   // the scanned script's hit is kept
        Assert.Single(warnings.Warnings, w => w.StartsWith($"Script content scanning INCOMPLETE for {ConNuspecId}: 1 of 3 ", StringComparison.Ordinal));
    }

    // The Linux twin: CON is an ordinary name there, so the very same package's manifest reaches disk and is scanned.
    [LinuxExtractionFact("Linux has no reserved device names, so the very same root CON.nuspec reaches disk and is scanned")]
    public void Scan_OnLinux_ForARootConNuspec_IsCompleted()
    {
        using var tree = new TempTree();
        var nupkg = ConNuspecPackage(tree);
        using (var opened = OpenPackage(nupkg))
            Assert.NotNull(opened.NuspecPath);

        var report = Scan(nupkg);

        Assert.Equal(ScriptScanStatus.Completed, report.ScriptScanStatus);
        Assert.Null(report.ScriptScanUnavailableReason);
    }

    // The same fact on every platform, through the private ScanScripts with a package whose manifest path is null.
    // A matching script's finding is kept beside the unscanned manifest (ADR 0032).
    [Fact]
    public void ScanScripts_WhenTheNuspecPathIsNull_IsUnavailable_AndCountsTheManifestInTheTotal()
    {
        using var tree = new TempTree();
        var match = tree.Write("content/tools/match.ps1", PackageFixture.SmallMatchingPs1);
        var plain = tree.Write("content/tools/plain.ps1", "Write-Host 'installing'\n");

        var (findings, status, reason) = ScanScripts(tree, "Null.Nuspec", [Tools("tools/match.ps1", match), Tools("tools/plain.ps1", plain)]);

        Assert.Equal(ScriptScanStatus.Unavailable, status);
        Assert.Equal(ManifestNotOnDiskReason(total: 3), reason);
        Assert.Contains(findings, f => f.RelativePath == "tools/match.ps1");
    }

    // No scripts at all: the manifest alone is still a file, so 1 of 1 — never a Completed scan of nothing.
    [Fact]
    public void ScanScripts_WhenTheNuspecPathIsNullAndThereAreNoScripts_IsOneOfOne()
    {
        using var tree = new TempTree();

        var (findings, status, reason) = ScanScripts(tree, "Null.Nuspec", []);

        Assert.Equal(ScriptScanStatus.Unavailable, status);
        Assert.Equal(ManifestNotOnDiskReason(total: 1), reason);
        Assert.Empty(findings);
    }

    // N-3 (ADR 0035 S5 review) on every platform: the manifest entry renders as the ADR spells it, literally, with no
    // brackets stacked around the placeholder (it was "'(package manifest) (its .nuspec ...)'").
    [Fact]
    public void ScanScripts_WhenTheNuspecPathIsNull_RendersTheManifestEntryWithoutStackedBrackets()
    {
        using var tree = new TempTree();

        var (_, _, reason) = ScanScripts(tree, "Null.Nuspec", []);

        Assert.Equal($"1 of 1 script/manifest file(s) were not scanned: 'package manifest ({ScriptRuleScanner.ManifestNotOnDisk})'", reason);
        Assert.DoesNotContain("(package manifest)", reason, StringComparison.Ordinal);
    }

    // Beside a script that could not be scanned either: both are counted (2 of 2) and both named, the manifest too.
    [Fact]
    public void ScanScripts_WhenTheNuspecPathIsNullAndAScriptIsUnscanned_CountsBoth()
    {
        using var tree = new TempTree();

        var (_, status, reason) = ScanScripts(tree, "Null.Nuspec", [Tools("tools/odd.ps1", string.Empty)]);

        Assert.Equal(ScriptScanStatus.Unavailable, status);
        Assert.Equal(
            "2 of 2 script/manifest file(s) were not scanned: 'tools/odd.ps1 (not found or not accessible)', "
            + $"'{ScriptRuleScanner.ManifestPlaceholder} ({ScriptRuleScanner.ManifestNotOnDisk})'",
            reason);
    }

    // The control: the manifest IS on disk (an ordinary package) — Completed, no reason, and the manifest scanned.
    [Fact]
    public void Scan_WhenTheNuspecIsOnDisk_IsCompletedWithNoReason()
    {
        using (var opened = OpenPackage(fixture.PkgScriptPath))
            Assert.NotNull(opened.NuspecPath);   // precondition

        var report = Scan(fixture.PkgScriptPath);

        Assert.Equal(ScriptScanStatus.Completed, report.ScriptScanStatus);
        Assert.Null(report.ScriptScanUnavailableReason);
    }

    // N4 at the package level: the summary warning escapes the package Id (nuspec content, attacker-authored).
    [Fact]
    public void ScanScripts_WhenIncomplete_EscapesThePackageIdInTheSummaryWarning()
    {
        using var tree = new TempTree();
        var hostileId = "Evil" + (char)0x0A + "[ERR] forged" + (char)0x1B + "[31m" + Rlo + ".Pkg";
        using var warnings = new WarningCapture();

        ScanScripts(tree, hostileId, []);

        var summary = Assert.Single(warnings.Warnings, w => w.StartsWith("Script content scanning INCOMPLETE for", StringComparison.Ordinal));
        Assert.StartsWith(@"Script content scanning INCOMPLETE for Evil\n[ERR] forged\x1b[31m" + EscapedRlo + ".Pkg: 1 of 1 ", summary, StringComparison.Ordinal);
        AssertNoRawControl(summary);
    }

    // ... and the F7 warning (the outer catch) escapes it too. A package whose script list is null makes the scanner's
    // enumeration throw inside ScanScripts' try: Unavailable with the exception type, no findings, one escaped warning.
    [Fact]
    public void ScanScripts_WhenTheScanThrows_IsUnavailable_AndEscapesThePackageIdInTheWarning()
    {
        using var tree = new TempTree();
        var hostileId = "Evil" + (char)0x0A + Rlo + ".Pkg";
        using var warnings = new WarningCapture();

        var (findings, status, reason) = ScanScripts(tree, hostileId, scripts: null);

        Assert.Equal(ScriptScanStatus.Unavailable, status);
        Assert.Empty(findings);
        Assert.StartsWith(nameof(ArgumentNullException) + ": ", reason, StringComparison.Ordinal);
        var warning = Assert.Single(warnings.Warnings, w => w.StartsWith("Script rule scanning failed for", StringComparison.Ordinal));
        Assert.StartsWith(@"Script rule scanning failed for Evil\n" + EscapedRlo + ".Pkg: ", warning, StringComparison.Ordinal);
        AssertNoRawControl(warning);
    }
    #endregion

    #region Methods: helpers
    private static PackageCapabilityReport Scan(string nupkg)
    {
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private static NuGetPackage OpenPackage(string nupkg)
    {
        var open = NuGetPackage.Open(nupkg);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    // A valid package whose ONLY manifest is a root "CON.nuspec", beside one benign-but-matching script and one plain one.
    private static string ConNuspecPackage(TempTree tree)
    {
        var path = Path.Combine(tree.Root, $"{ConNuspecId}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path,
        [
            ("CON.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                ConNuspecId, "1.0.0", "Silvergun Tests", "ADR 0035 W1 test package: a root CON.nuspec.", "net8.0", []))),
            ("tools/match.ps1", Encoding.UTF8.GetBytes(PackageFixture.SmallMatchingPs1)),
            ("tools/plain.ps1", Encoding.UTF8.GetBytes("Write-Host 'installing'\n")),
        ]);
        return path;
    }

    // PackageScanner.ScanScripts (private) over a NuGetPackage built through its private constructor with a NULL manifest
    // path — the state Open produces when the root nuspec never reaches disk — so W1 is pinned on every platform. The
    // package's extraction directory is a fresh one under the tree (its Dispose deletes it).
    private static (IReadOnlyList<ScriptFinding> Findings, ScriptScanStatus Status, string? Reason) ScanScripts(
        TempTree tree, string id, PackageScript[]? scripts)
    {
        var extraction = Directory.CreateDirectory(Path.Combine(tree.Root, "extraction-" + Guid.NewGuid().ToString("N"))).FullName;
        var ctor = Assert.Single(typeof(NuGetPackage).GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance));
        using var package = (NuGetPackage)ctor.Invoke(
        [
            new PackageIdentityInfo(id, "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            Array.Empty<PackageAssembly>(),
            scripts,
            null,                                   // NuspecPath: the manifest never reached disk
            extraction,
            extraction,
            Array.Empty<string>(),
            Array.Empty<(string, string)>(),
            Array.Empty<string>(),
            Array.Empty<NativeBinary>(),            // NativeBinaries (native-binaries-1)
            Array.Empty<string>(),                  // NativeBinaryUnreadFiles
            Array.Empty<UnextractedBundleRow>(),    // UnextractedBundleEntries (native-binaries-3)
            Array.Empty<BundleFile>(),              // BundleYaraInventory (native-binaries-4)
        ]);
        Assert.Null(package.NuspecPath);            // precondition
        var scanScripts = typeof(PackageScanner).GetMethod("ScanScripts", BindingFlags.NonPublic | BindingFlags.Static)!;
        return ((IReadOnlyList<ScriptFinding>, ScriptScanStatus, string?))scanScripts.Invoke(null, [package])!;
    }

    private static PackageScript Tools(string relativePath, string fullPath) => new(relativePath, fullPath, PackageItemRole.Tools);

    // The reason when the manifest is the ONLY unscanned file, out of `total` (the scripts + 1).
    private static string ManifestNotOnDiskReason(int total) =>
        $"1 of {total} script/manifest file(s) were not scanned: '{ScriptRuleScanner.ManifestPlaceholder} ({ScriptRuleScanner.ManifestNotOnDisk})'";

    private static PackageCapabilityReport Report(ScriptScanStatus status = ScriptScanStatus.Unavailable) =>
        new(new PackageIdentityInfo("Reason.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch, Array.Empty<AssemblyScanResult>(), Array.Empty<PackageScript>(), Array.Empty<ScriptFinding>(),
            YaraScanStatus: YaraScanStatus.Completed, ScriptScanStatus: status);

    // No C0 control, no DEL or C1 control, no bidi override.
    private static void AssertNoRawControl(string text) =>
        Assert.DoesNotContain(text, c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F || c == Rlo);
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    private const string ConNuspecId = "SilvergunConNuspec";

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw.
    private const char Rlo = (char)0x202E;

    // A reason quoting a hostile path: a line break, a forged log level, a bidi override and an ANSI escape, and far
    // past the 512-char bound.
    private static readonly string Hostile = "1 of 1 script/manifest file(s) were not scanned: 'tools/a\n[ERR] forged" + Rlo + (char)0x1B + "[31m" + new string('z', 2000);

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries that sequence.
    private const string EscapedRlo = @"\" + "u202e";

    // How Hostile's start reads once escaped.
    private const string EscapedHostile = @"1 of 1 script/manifest file(s) were not scanned: 'tools/a\n[ERR] forged" + EscapedRlo + @"\x1b[31m";
    #endregion
}
