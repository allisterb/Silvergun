namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c> <b>"Review 5" (C1-r5): an entry that ESCAPES the content root is
/// lost coverage.</b> It is still never inventoried (ADR 0008, unchanged), but RecursiveExtractor clamps its bytes onto
/// a path INSIDE the root, last-wins, while NuGet installs the FIRST copy (<c>CopyToFile</c> skips an existing file), or
/// refuses the package. Before Review 5 the escaping name was never even considered by the lost-entry rule.
///
/// <para><b>Measured by the reviewer (scratchpad <c>s11a-run.txt</c> on Windows, <c>s11a-linux-raw.txt</c> under WSL,
/// pre-fix code):</b> <c>build/Some.Package.targets</c> (hook) followed by <c>/build/Some.Package.targets</c> (decoy)
/// left the decoy on disk, scanned <c>[OK] Clean</c> with 0 findings and exited 0 under <c>--strict</c>, while NuGet
/// installed the hook. <c>/Real.nuspec</c> and <c>/content/payload.bin</c> did the same to the manifest and to YARA's
/// scope. <c>C:/build/…</c> and <c>\build\…</c> decoys were clamped over the same file on BOTH platforms (on Windows
/// NuGet refuses them; on Linux it installs both), and a lone <c>/build/Some.Package.targets</c> was written inside the
/// root and never script-scanned. Every on-disk statement below is that measurement, asserted rather than assumed.</para>
///
/// <para><b>S8 (ADR 0036, the content check):</b> where the decoy comes AFTER the real entry, the real entry is lost
/// too. It still claims the file, but that file now holds the decoy's bytes, not the ones NuGet installs for it, so its
/// content check fails. Both names are reported, in archive order. Where the decoy comes first, the real entry is written
/// last, its bytes are on disk, and only the decoy is lost.</para>
///
/// <para><b>Accepted cost, pinned deliberately:</b> every PathTraversal package now reads incomplete (exit 3 under
/// <c>--strict</c>). The flipped zip-slip expectations live with their originals (<c>UninventoriedEntryTests</c>,
/// <c>ContainmentClaimTests</c>, <c>NuGetPackageYaraInventoryTests</c>).</para>
///
/// <para>The decision is lexical (<see cref="NuGetPackage.EscapesContentRoot"/>), so every test here runs ungated except
/// the real-CLI child process, which only the <c>net10.0-windows</c> build carries; the CLI suite's
/// <c>EntryAliasingReview2CliTests</c> pins the same exit code in-process on any platform. Content is benign: the hook is
/// <see cref="PackageFixture.MaliciousTargets"/>, the real manifest carries <see cref="PackageFixture.NuspecMatchProjectUrl"/>.</para>
/// </summary>
public sealed class EntryAliasingEscapingEntryTests : IClassFixture<EntryAliasProbePackageFixture>
{
    #region Constructors
    public EntryAliasingEscapingEntryTests(EntryAliasProbePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: a rooted decoy after the real .targets (the headline)
    // Ground truth first: the decoy's bytes are what is on disk under the real name, and the real entry still claims
    // (and the script inventory still lists) that file. The escaping decoy claimed nothing, and the real entry's file
    // fails its content check (it holds the decoy, NuGet installs the hook): both are lost (ADR 0036).
    [Fact]
    public void Open_ForARootedDecoyAfterATargetsFile_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        using var pkg = Open(fixture.RootedTargetsAfterPath);

        AssertBuildFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
        Assert.Contains(pkg.Scripts, s => s.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        Assert.Equal([EntryAliasPackageFixture.TargetsEntry, EntryAliasProbePackageFixture.RootedTargets], pkg.UninventoriedEntryNames);
    }

    // The decoy is what was script-scanned (0 findings, as measured), and both entries are not-inventoried rows, so the
    // package is incomplete. Role Other for the decoy: the first segment of "/build/…" is empty.
    [Fact]
    public void Scan_ForARootedDecoyAfterATargetsFile_IsIncompleteWithTheOverwrittenEntryAndTheDecoyAsItsSkipRows()
    {
        var scan = Scan(fixture.RootedTargetsAfterPath);

        AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build), (EntryAliasProbePackageFixture.RootedTargets, PackageItemRole.Other));
        Assert.Empty(scan.ScriptFindings);
    }

    // The reverse order is the one that tells "escaping entries never claim" apart from "the first claimant wins": the
    // decoy comes FIRST, so if it were allowed to claim the key it would steal it, and the REAL entry (whose bytes are on
    // disk, and whose findings are reported) would be the one named lost. NuGet installs the decoy here (first copy).
    [Fact]
    public void OpenAndScan_ForARootedDecoyBeforeATargetsFile_ScanTheRealFileAndStillReportTheDecoyLost()
    {
        using (var pkg = Open(fixture.RootedTargetsBeforePath))
        {
            AssertBuildFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Equal([EntryAliasProbePackageFixture.RootedTargets], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.RootedTargetsBeforePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        AssertNotInventoriedRows(scan, (EntryAliasProbePackageFixture.RootedTargets, PackageItemRole.Other));
    }
    #endregion

    #region Methods: a rooted decoy after the manifest, and after a content file
    [Fact]
    public void OpenAndScan_ForARootedDecoyAfterTheManifest_ScanTheDecoyAndReportItAndTheManifestLost()
    {
        using (var pkg = Open(fixture.RootedManifestAfterPath))
        {
            Assert.Equal([EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
            Assert.Equal(EntryAliasPackageFixture.RealManifest, Path.GetFileName(pkg.NuspecPath));
            Assert.DoesNotContain(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
            Assert.Equal([EntryAliasPackageFixture.RealManifest, EntryAliasProbePackageFixture.RootedManifest], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.RootedManifestAfterPath);
        AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.RealManifest, PackageItemRole.Other), (EntryAliasProbePackageFixture.RootedManifest, PackageItemRole.Other));
        Assert.DoesNotContain(scan.ScriptFindings, f => f.Source == ScriptFindingSource.PackageMetadata);
    }

    // The steal shape again, for the manifest: the rooted decoy FIRST. The real manifest is written last, so it is what
    // is on disk and scanned (its finding is reported), and the decoy — never allowed to claim — is the entry lost. Were
    // escaping names allowed to claim, the decoy would take Real.nuspec's key and the real manifest would read lost.
    [Fact]
    public void OpenAndScan_ForARootedDecoyBeforeTheManifest_ScanTheRealManifestAndStillReportTheDecoyLost()
    {
        using (var pkg = Open(fixture.RootedManifestBeforePath))
        {
            Assert.Equal([EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
            Assert.Contains(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
            Assert.Equal([EntryAliasProbePackageFixture.RootedManifest], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.RootedManifestBeforePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.RealManifest && f.Source == ScriptFindingSource.PackageMetadata);
        AssertNotInventoriedRows(scan, (EntryAliasProbePackageFixture.RootedManifest, PackageItemRole.Other));
    }

    // YARA's scope: a non-binary content file. The decoy is what is on disk, so what YARA would scan is the decoy.
    [Fact]
    public void OpenAndScan_ForARootedDecoyAfterAContentFile_ReportTheOverwrittenEntryAndTheDecoyLost()
    {
        using (var pkg = Open(fixture.RootedContentAfterPath))
        {
            Assert.Equal([EntryAliasProbePackageFixture.PayloadEntry], ContentFiles(pkg));
            Assert.Equal(EntryAliasProbePackageFixture.DecoyContent, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "payload.bin")));
            Assert.Equal([EntryAliasProbePackageFixture.PayloadEntry, EntryAliasProbePackageFixture.RootedContent], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.RootedContentAfterPath),
            (EntryAliasProbePackageFixture.PayloadEntry, PackageItemRole.Content), (EntryAliasProbePackageFixture.RootedContent, PackageItemRole.Other));
    }
    #endregion

    #region Methods: a lone rooted entry, and the drive and backslash-rooted decoys
    // A lone "/build/Some.Package.targets": its bytes ARE written inside the root (ground truth), but it is never
    // inventoried, so it is never script-scanned (no script, no finding) — exactly why it must read lost.
    [Fact]
    public void OpenAndScan_ForALoneRootedTargetsEntry_ReportItLostAndScanNothing()
    {
        using (var pkg = Open(fixture.RootedTargetsSolePath))
        {
            AssertBuildFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Empty(pkg.Scripts);
            Assert.Equal([EntryAliasProbePackageFixture.RootedTargets], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.RootedTargetsSolePath);
        AssertNotInventoriedRows(scan, (EntryAliasProbePackageFixture.RootedTargets, PackageItemRole.Other));
        Assert.Empty(scan.ScriptFindings);
    }

    // "C:/build/…" is drive-qualified, so it escapes on every platform, and the extractor drops the drive segment and
    // writes it over the real file on BOTH (measured: on Linux NuGet installs it as a separate "C:/build/…" file).
    [Fact]
    public void Open_ForADriveQualifiedDecoyAfterATargetsFile_ReportsTheOverwrittenEntryAndTheDecoyLostOnEveryPlatform()
    {
        AssertDecoyClampedOverTheTargetsFileAndLost(fixture.DriveTargetsAfterPath, EntryAliasProbePackageFixture.DriveTargets);
    }

    // "\build\…" is backslash-rooted: it escapes on every platform, and lands over the real file on both (measured).
    [Fact]
    public void Open_ForABackslashRootedDecoyAfterATargetsFile_ReportsTheOverwrittenEntryAndTheDecoyLostOnEveryPlatform()
    {
        AssertDecoyClampedOverTheTargetsFileAndLost(fixture.BackslashRootedTargetsAfterPath, EntryAliasProbePackageFixture.BackslashRootedTargets);
    }
    #endregion

#if WINDOWS
    #region Methods: the real CLI, end to end (net10.0-windows carries the CLI)
    [Fact]
    public void ScanPackageCli_ForARootedDecoyAfterATargetsFile_StrictExitsThreeAndNamesTheDecoy()
    {
        AssertCliIncompleteNaming(fixture.RootedTargetsAfterPath, EntryAliasProbePackageFixture.RootedTargets);
    }

    [Fact]
    public void ScanPackageCli_ForARootedDecoyAfterTheManifest_StrictExitsThreeAndNamesTheDecoy()
    {
        AssertCliIncompleteNaming(fixture.RootedManifestAfterPath, EntryAliasProbePackageFixture.RootedManifest);
    }

    [Fact]
    public void ScanPackageCli_ForARootedDecoyAfterAContentFile_StrictExitsThreeAndNamesTheDecoy()
    {
        AssertCliIncompleteNaming(fixture.RootedContentAfterPath, EntryAliasProbePackageFixture.RootedContent);
    }
    #endregion
#endif

    #region Methods: helpers
    // The build directory holds exactly the one real-named file, with these bytes.
    private static void AssertBuildFileHolds(NuGetPackage pkg, string content)
    {
        Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
        Assert.Equal(content, File.ReadAllText(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
    }

    // The decoy is on disk under the real name: the real entry fails its content check, the decoy claimed nothing.
    private static void AssertDecoyClampedOverTheTargetsFileAndLost(string nupkgPath, string decoy)
    {
        using (var pkg = Open(nupkgPath))
        {
            Assert.True(NuGetPackage.EscapesContentRoot(decoy), $"precondition: '{decoy}' escapes the content root.");
            AssertBuildFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry, decoy], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build), (decoy, PackageItemRole.Other));
        Assert.Empty(scan.ScriptFindings);
    }
    #endregion

    #region Fields
    private readonly EntryAliasProbePackageFixture fixture;
    #endregion
}
