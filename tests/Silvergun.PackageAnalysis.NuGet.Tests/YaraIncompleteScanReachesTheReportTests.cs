namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0032 end to end: <b>a hit found by a scan that could not finish reaches the package report</b>, alongside
/// <see cref="YaraScanStatus.Unavailable"/>, for every way a real backend can end up incomplete. Each test drives
/// <see cref="PackageScanner.Scan"/> over a real <c>.nupkg</c> and asserts on <see cref="PackageCapabilityReport"/>
/// alone — the report is the contract the CLI's exit code and renderer consume.
///
/// <para><b>Deliberately written against the public surface that predates ADR 0032.</b> Nothing here touches
/// <see cref="YaraScanIncompleteException.PartialFindings"/>: the scanners are real (the default
/// <see cref="IYaraScanner.ScanDirectory"/> loop, and <see cref="YaraCliScanner"/> over a stand-in engine), and the
/// fakes throw only through the constructors that already existed. That is what lets this file be compiled against
/// the pre-change code and shown to go RED there by assertion — every one of these shapes reported
/// <c>Unavailable</c> with <b>zero</b> findings before the fix — rather than merely failing to compile. The
/// before/after record is in the Round B report for <c>docs/agent/tasks/yara-partial-findings.md</c>.</para>
///
/// <para>The headline is the Linux-only shape from the ADR's Context: a matching payload plus 65 junk files whose
/// names carry a control character (one more than <c>MaxIndividualScans</c> = 64). Before the fix that package
/// reported zero findings, so <c>--strict</c> exited 3 instead of 2 and <c>--strict --allow-incomplete</c> exited
/// 0. A file name NTFS cannot hold cannot be staged on Windows, so those tests are visible skips there.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraIncompleteScanReachesTheReportTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public YaraIncompleteScanReachesTheReportTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // --- The default ScanDirectory loop (LibYaraScanner's, the explicit Windows fallback), platform-neutral ------
    // (Since ADR 0033 T6b the Windows default is YaraXWorkerScanner, which overrides ScanDirectory with one worker run.)

    // One file the backend could not scan (it throws the per-file "not scanned" exception, ADR 0032 decision 5) must
    // not take the payload's hit with it. The loop keeps going past the failing file, the hit travels out in the
    // exception, and PackageScanner reports it. Before ADR 0032 the first throw aborted the loop and ScanYara mapped
    // it to (empty, Unavailable) — and which files had been scanned before it depended on enumeration order.
    [Fact]
    public void Scan_WhenTheDefaultLoopCannotScanOneFile_StillReportsTheOtherFilesHit()
    {
        var backend = new PerFileBackend(
            hitOn: fixture.FixtureDllName, rule: RlRuleName, notScanned: "init.ps1");

        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal($"lib/netstandard2.0/{fixture.FixtureDllName}", finding.RelativePath);
        Assert.Equal(RlRuleName, finding.RuleName);
        Assert.Equal("LIMERAT", finding.MalwareFamily);   // enriched, like any other hit
        // ...because the loop went past the failing file, whichever order the filesystem enumerated them in.
        Assert.Contains(backend.Visited, f => Path.GetFileName(f) == "init.ps1");
        Assert.Contains(backend.Visited, f => Path.GetFileName(f) == fixture.FixtureDllName);
    }

    // ADR 0032 decision 6, the timeout half, at the report (review item N3). The backend's own wall-clock bound is
    // reached on the SECOND file, after the first one matched. The loop stops there (the engine's health can no longer
    // be vouched for), but the hit it already had is real and must reach the report alongside Unavailable. Before ADR
    // 0032 the raw TimeoutException escaped the default loop and ScanYara mapped it to (empty, Unavailable): the hit
    // was gone. Enumeration order is the filesystem's, so the fake keys on the CALL number, not a file name, and the
    // assertions are phrased over what it actually visited. Uses no API added by ADR 0032.
    [Fact]
    public void Scan_WhenTheDefaultLoopTimesOutAfterAHit_ReportsThatHitAlongsideUnavailable()
    {
        var backend = new TimesOutOnSecondCallBackend(RlRuleName);

        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(2, backend.Visited.Count);   // stopped at the timeout: nothing after the second file was scanned
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal(RlRuleName, finding.RuleName);
        Assert.Equal("LIMERAT", finding.MalwareFamily);   // enriched, like any other hit
        Assert.EndsWith(Path.GetFileName(backend.Visited[0]), finding.RelativePath, StringComparison.Ordinal);
    }

    // --- The classic-CLI backend ------------------------------------------------------------------------------

    // ADR 0029 decision 17 / ADR 0032 decision 4, platform-neutral (the FakeYaraProbe stages the recursive pass's
    // output at run time, so the extraction root need not be known in advance). The batch pass reports the payload,
    // which it can attribute, and a sibling that does not exist, which it cannot. The guard fails the scan closed —
    // but the unattributable hit is a DETECTION whose attribution is uncertain, and the attributed one is certain:
    // both are reported, the ghost under the path yara echoed. Before ADR 0032 both were thrown away.
    [Fact]
    public void Scan_WhenTheBatchPassReportsAnUnattributableHit_ReportsItAndTheAttributedHit()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgUnattributable", [("content/payload.bin", "ordinary content\n")]);
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", batchGhost: "ghost.bin");

        using var scanner = new YaraCliScanner();
        Assert.True(scanner.Available);

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: scanner);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal(2, scan.Value.YaraFindings.Count);
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == "content/payload.bin" && f.RuleName == "Fake_Rule");
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == "content/ghost.bin" && f.RuleName == "Fake_Rule");
    }

    // THE ADR 0032 shape. A payload the batch pass matches, plus 65 junk entries whose names carry a newline: each
    // must be re-scanned individually, the recovery pass stops at MaxIndividualScans = 64, and the 65th is therefore
    // unrecovered — so the scan is (correctly) incomplete. What must NOT happen is the payload's hit disappearing
    // with it, which is exactly what did happen: Unavailable, zero findings, `--strict` exit 3 instead of 2.
    [LinuxFact]
    public void Scan_WithAPayloadPlus65UnsafeNames_ReportsThePayloadHitAlongsideUnavailable()
    {
        using var tree = new TempTree();
        var junk = Enumerable.Range(0, 65).Select(i => ($"content/junk\n{i:D2}.bin", "nothing here\n")).ToArray();
        var nupkg = WritePackage(tree, "PkgSixtyFive", [("content/payload.bin", "ordinary content\n")], junk);
        using var engine = new ScriptedYaraStandIn("Fake_Rule", "content/payload.bin");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/payload.bin", finding.RelativePath);
        Assert.Equal("Fake_Rule", finding.RuleName);
    }

    // The same, with ONE unsafe-named entry whose individual re-scan fails outright (the stand-in exits non-zero on
    // every single-file scan). One unrecoverable file must cost the package its "Completed", never the payload hit
    // the batch pass already had in hand.
    [LinuxFact]
    public void Scan_WhenOneUnsafeNamedFileCannotBeRecovered_ReportsTheBatchHitAlongsideUnavailable()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(
            tree, "PkgOneUnrecoverable", [("content/payload.bin", "ordinary content\n")], [("content/n\nl.bin", "nothing here\n")]);
        using var engine = new ScriptedYaraStandIn("Fake_Rule", "content/payload.bin", singleFileExitCode: 3);

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("content/payload.bin", finding.RelativePath);
    }

    // The control for the two tests above: the same stand-in over the same payload with NO unsafe name completes,
    // and reports the hit as Completed. Without it, "Unavailable + 1 finding" could be an artefact of the stand-in.
    [LinuxFact]
    public void Scan_WithThePayloadAndNoUnsafeNames_CompletesWithTheHit()
    {
        using var tree = new TempTree();
        var nupkg = WritePackage(tree, "PkgControl", [("content/payload.bin", "ordinary content\n")]);
        using var engine = new ScriptedYaraStandIn("Fake_Rule", "content/payload.bin");

        using var cli = new YaraCliScanner();
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: cli);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Equal("content/payload.bin", Assert.Single(scan.Value.YaraFindings).RelativePath);
    }
    #endregion

    #region Helpers
    private static string WritePackage(
        TempTree tree, string id, (string Name, string Text)[] entries, (string Name, string Text)[]? rawEntries = null)
    {
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "ADR 0032 incomplete-scan package.", "netstandard2.0", []))),
                .. entries.Select(e => (e.Name, Encoding.UTF8.GetBytes(e.Text))),
            ],
            (rawEntries ?? []).Select(e => (e.Name, Encoding.UTF8.GetBytes(e.Text))));
        return nupkg;
    }
    #endregion

    #region Nested types
    // A healthy backend that implements ONLY ScanFile, so ScanDirectory is the interface's default loop — the path of
    // the in-process LibYaraScanner, the explicit Windows fallback (SILVERGUN_YARA_ENGINE=libyara; the default since ADR
    // 0033 T6b is YaraXWorkerScanner, which overrides the loop). It hits on one file name, reports another as not scanned (the ADR 0032
    // decision 5 exception, through its original one-argument constructor), and finds nothing elsewhere.
    private sealed class PerFileBackend(string hitOn, string rule, string notScanned) : IYaraScanner
    {
        public bool Available => true;

        public List<string> Visited { get; } = [];

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
        {
            Visited.Add(fullPath);
            var name = Path.GetFileName(fullPath);
            return name == notScanned
                ? throw new YaraScanIncompleteException($"YARA did not scan '{name}'. This file was NOT scanned and must not be reported as clean.")
                : name == hitOn
                    ? [new YaraMatch(rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>())]
                    : [];
        }
    }

    // A healthy per-file backend (ScanDirectory is the interface's default loop) that matches on its first call and
    // reaches its own wall-clock bound on the second — the LibYaraScanner TimeoutException contract (ADR 0028
    // decision 10). It throws only BCL types, so it compiles against the pre-ADR-0032 code.
    private sealed class TimesOutOnSecondCallBackend(string rule) : IYaraScanner
    {
        public bool Available => true;

        public List<string> Visited { get; } = [];

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath)
        {
            Visited.Add(fullPath);
            return Visited.Count switch
            {
                1 => [new YaraMatch(rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>())],
                2 => throw new TimeoutException("The backend's own wall-clock bound was reached."),
                _ => [],
            };
        }
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    // A real embedded ReversingLabs rule, so the partial hit's enrichment is observable (see YaraScanPackageWiringTests).
    private const string RlRuleName = "ByteCode_MSIL_Backdoor_LimeRAT";
    #endregion
}
