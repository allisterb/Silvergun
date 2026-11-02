namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;

using global::NuGet.Packaging;

using Silvergun;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c> (ADR 0030), rule (a) of Review 1 as finalised by Reviews 4 and 5:
/// <b>every declared file entry (non-empty, not ending in <c>'/'</c>) that is a duplicate, escapes the content root, or
/// claimed no extracted file is lost coverage, whatever its kind and whatever its name's shape, decided with no
/// filesystem access.</b> The escaping half (Review 5, C1-r5) is in <see cref="EntryAliasingEscapingEntryTests"/>.
/// An entry that claimed nothing was never written as a file of its own: it was dropped, renamed, or written OVER another
/// entry's file. In the last case the overwritten entry still claims the file, so before this rule the package read
/// complete while every scanner saw the decoy's bytes.
///
/// <para><b>Shapes, measured 2026-11-01 on Windows 10 (NTFS, 8.3 generation on) and WSL (ext4), current tree
/// (re-measured under Review 4's rule, scratchpad <c>ea5-probe-win.txt</c> / <c>ea5-probe-linux.txt</c>):</b></para>
/// <list type="table">
/// <listheader><term>shape</term><description>Windows / Linux</description></listheader>
/// <item><term>8.3 alias after the long name (<c>build/SOMEPA~1.TAR</c>, <c>REAL~1.NUS</c>)</term>
/// <description>written over the long-named file, alias lost / a separate file, nothing lost</description></item>
/// <item><term>8.3 alias BEFORE the long name</term><description>two files, nothing lost / the same</description></item>
/// <item><term>trailing dot or space (<c>Real.nuspec.</c>, <c>Real.nuspec </c>), either order</term>
/// <description>one file, the trailing-name entry lost / separate files, nothing lost</description></item>
/// <item><term>leading drive segment (<c>./C:/Real.nuspec</c>), either order</term>
/// <description>the extractor drops <c>C:</c> on BOTH platforms, so the drive entry is lost on both</description></item>
/// <item><term><c>content/a:b.bin</c>, <c>a&lt;b</c>, <c>a?b</c>, <c>a|b</c> beside <c>content/a_b.bin</c>, either order</term>
/// <description>mapped to <c>a_b.bin</c>, the alias lost / written verbatim, nothing lost except the <c>':'</c> entry,
/// which since S10 (review 9, C1) is lost on every platform</description></item>
/// <item><term><c>content/CON.txt</c></term><description>never written, lost / an ordinary file, nothing lost</description></item>
/// <item><term>a LONE <c>content/readme.txt </c> or <c>content/readme.txt.</c></term>
/// <description>trimmed onto a NEW file, reported lost (the accepted, fail-closed cost) / verbatim, nothing lost</description></item>
/// <item><term><c>./C:/Windows/win.ini</c> + <c>./C:/Windows/nonexistent-xyz.ini</c></term>
/// <description>both written under the content root, both lost, on both platforms (review C1)</description></item>
/// </list>
///
/// <para><b>Reviews 2-4 (2026-11-01).</b> C3: an exact DUPLICATE name is lost too, reported once. The extractor keeps the
/// LAST copy on disk while NuGet installs the FIRST, so a matching <c>.targets</c> followed by a <c>&lt;Project /&gt;</c>
/// of the same name used to scan the decoy and read complete. W2: a lost row is told apart from a file by
/// <see cref="AssemblyScanResult.NotInventoried"/>, and the CLI reports it under its own caveat ("N declared package
/// entr(ies) were never extracted as …own file") rather than as "N of M file(s) could not be analysed" (the report-side
/// half is in the CLI suite's <c>EntryAliasingReview2CliTests</c>, the flag itself in <see cref="NotInventoriedRowTests"/>).
/// Review 2's W1 (a <c>'\'</c>-terminated name is a directory) and Review 3's narrower "<c>'\'</c>-terminated AND its key
/// absent from the inventory" exemption were both REMOVED by Review 4: there is no exemption by name shape at all. The
/// <c>'\'</c>, duplicate, C1-r4 and <c>'/'</c>-terminated shapes are in <see cref="EntryAliasingBackslashAndDuplicateTests"/>.</para>
///
/// <para><b>S8 (ADR 0036, the content check).</b> Every entry that claims a file must also hold the bytes NuGet installs
/// for it. So wherever an alias is written AFTER the real entry, over its file, the real entry is lost as well as the
/// alias: it claims a file holding the alias's bytes. The table's "alias lost" therefore reads "the real entry and the
/// alias lost" for every after-order row; the before-order rows are unchanged, because the real entry is written last
/// and holds its own bytes.</para>
///
/// <para><b>Gates.</b> The 8.3 tests need Windows AND live 8.3 name generation where <see cref="NuGetPackage.Open"/>
/// extracts (under <c>%TEMP%</c>), probed by <see cref="ShortNameAliasFactAttribute"/>. Other OS-decided shapes use the
/// <see cref="WindowsExtractionFactAttribute"/>/<see cref="LinuxExtractionFactAttribute"/> pair; the drive-segment, C1,
/// <c>%</c>-manifest and ordinary-package statements hold on both platforms and run ungated.</para>
///
/// <para>Content is benign throughout: the matching <c>.targets</c> is <see cref="PackageFixture.MaliciousTargets"/>
/// (a certutil token against <c>malicious.example</c>), the matching manifest carries
/// <see cref="PackageFixture.NuspecMatchProjectUrl"/>, everything else is short plain text. No network. No host file is
/// ever read: the C1 entries are package entries extracted under the content root.</para>
/// </summary>
public sealed class EntryAliasingCoverageTests : IClassFixture<EntryAliasPackageFixture>
{
    #region Constructors
    public EntryAliasingCoverageTests(EntryAliasPackageFixture fixture) => this.fixture = fixture;
    #endregion

#if WINDOWS
    #region Methods: an 8.3 short-name alias after a .targets file (Windows, 8.3 generation on)
    // The headline. The alias was written over the .targets file's bytes (ground truth, asserted so the test cannot pass
    // vacuously on a volume that did not alias), it claimed nothing, and it is reported lost although its extension (.TAR)
    // is no kind the old filter knew. The real entry is lost too: its file holds the alias's bytes (ADR 0036).
    [ShortNameAliasFact("the extractor writes build/SOMEPA~1.TAR through the short name of build/Some.Package.targets")]
    public void Open_OnWindows_ForAShortNameAliasAfterATargetsFile_ReportsTheOverwrittenEntryAndTheAliasUninventoried()
    {
        using var pkg = Open(fixture.TargetsAliasAfterPath);

        var build = Path.Combine(pkg.ContentRoot, "build");
        Assert.Equal(["Some.Package.targets"], Directory.GetFiles(build).Select(Path.GetFileName));
        Assert.Equal(EntryAliasPackageFixture.DecoyTargets, File.ReadAllText(Path.Combine(build, "Some.Package.targets")));

        Assert.Equal([EntryAliasPackageFixture.TargetsEntry, EntryAliasPackageFixture.TargetsShortAlias], pkg.UninventoriedEntryNames);
        Assert.Contains(pkg.Scripts, s => s.RelativePath == EntryAliasPackageFixture.TargetsEntry);
    }

    // The skip rows, and the reason's wording (review W3, then S8): it says the entry was never written as a file of its
    // own, which is what an alias written over someone else's file is, or was written with bytes other than NuGet's,
    // which is what the overwritten entry was.
    [ShortNameAliasFact("only an aliased package has a lost entry to synthesize a skip row for")]
    public void Scan_OnWindows_ForAShortNameAliasAfterATargetsFile_HasNotInventoriedSkipRowsSayingWhy()
    {
        var scan = Scan(fixture.TargetsAliasAfterPath);

        var rows = AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build), (EntryAliasPackageFixture.TargetsShortAlias, PackageItemRole.Build));
        Assert.All(rows, row =>
        {
            Assert.Contains("written over another entry's file", row.SkipReason, StringComparison.Ordinal);
            Assert.Contains("written with bytes other than those NuGet installs", row.SkipReason, StringComparison.Ordinal);
        });
        Assert.Empty(scan.ScriptFindings);   // the decoy is what was scanned: the skip rows are the only disclosure
    }

    // The CLI half, end to end in a child process: --strict exits 3, and the JSON's Completeness names the alias. The
    // exit code alone would not discriminate (--no-vulns leaves its own NotChecked caveat, so this run is never 0); the
    // caveat naming the alias is what the kind-filtered code could not produce.
    [ShortNameAliasFact("only an aliased package is incomplete on account of the alias")]
    public void ScanPackageCli_OnWindows_ForAShortNameAliasAfterATargetsFile_StrictExitsThreeAndNamesTheAlias()
    {
        AssertCliIncompleteNaming(fixture.TargetsAliasAfterPath, EntryAliasPackageFixture.TargetsShortAlias);
    }
    #endregion

    #region Methods: an 8.3 short-name alias after the manifest (Windows, 8.3 generation on)
    [ShortNameAliasFact("the extractor writes REAL~1.NUS through the short name of Real.nuspec")]
    public void Open_OnWindows_ForAShortNameAliasAfterTheManifest_ReportsTheManifestAndTheAliasUninventoried()
    {
        AssertManifestOverwrittenAndAliasLost(fixture.NuspecShortAfterPath, EntryAliasPackageFixture.ManifestShortAlias);
    }

    [ShortNameAliasFact("only an aliased package has a lost entry to synthesize a skip row for")]
    public void Scan_OnWindows_ForAShortNameAliasAfterTheManifest_HasNotInventoriedSkipRowsForTheManifestAndTheAlias()
    {
        var scan = Scan(fixture.NuspecShortAfterPath);

        AssertManifestAndAliasRows(scan, EntryAliasPackageFixture.ManifestShortAlias);
        Assert.DoesNotContain(scan.ScriptFindings, f => f.Source == ScriptFindingSource.PackageMetadata);
    }

    [ShortNameAliasFact("only an aliased package is incomplete on account of the alias")]
    public void ScanPackageCli_OnWindows_ForAShortNameAliasAfterTheManifest_StrictExitsThreeAndNamesTheAlias()
    {
        AssertCliIncompleteNaming(fixture.NuspecShortAfterPath, EntryAliasPackageFixture.ManifestShortAlias);
    }
    #endregion

    #region Methods: a trailing dot or space after the manifest (Windows)
    // Win32 drops the trailing dot/space, so "Real.nuspec." / "Real.nuspec " is written over Real.nuspec. Pre-fix the only
    // disclosure was the non-gating TrailingSpaceOrDot anomaly.
    [WindowsExtractionFact("Windows drops the trailing dot, so Real.nuspec. is written over Real.nuspec")]
    public void Open_OnWindows_ForATrailingDotAliasAfterTheManifest_ReportsTheManifestAndTheAliasUninventoried()
    {
        AssertManifestOverwrittenAndAliasLost(fixture.NuspecTrailingDotAfterPath, EntryAliasPackageFixture.ManifestTrailingDot);
    }

    [WindowsExtractionFact("Windows drops the trailing space, so 'Real.nuspec ' is written over Real.nuspec")]
    public void Open_OnWindows_ForATrailingSpaceAliasAfterTheManifest_ReportsTheManifestAndTheAliasUninventoried()
    {
        AssertManifestOverwrittenAndAliasLost(fixture.NuspecTrailingSpaceAfterPath, EntryAliasPackageFixture.ManifestTrailingSpace);
    }

    [WindowsExtractionFact("only Windows loses the trailing-dot entry, so only there are there skip rows")]
    public void Scan_OnWindows_ForATrailingDotAliasAfterTheManifest_HasNotInventoriedSkipRowsForTheManifestAndTheAlias()
    {
        AssertManifestAndAliasRows(Scan(fixture.NuspecTrailingDotAfterPath), EntryAliasPackageFixture.ManifestTrailingDot);
    }

    [WindowsExtractionFact("only Windows loses the trailing-space entry, so only there are there skip rows")]
    public void Scan_OnWindows_ForATrailingSpaceAliasAfterTheManifest_HasNotInventoriedSkipRowsForTheManifestAndTheAlias()
    {
        AssertManifestAndAliasRows(Scan(fixture.NuspecTrailingSpaceAfterPath), EntryAliasPackageFixture.ManifestTrailingSpace);
    }

    [WindowsExtractionFact("only Windows loses the trailing-dot entry, so only there is the package incomplete")]
    public void ScanPackageCli_OnWindows_ForATrailingDotAliasAfterTheManifest_StrictExitsThreeAndNamesTheAlias()
    {
        AssertCliIncompleteNaming(fixture.NuspecTrailingDotAfterPath, EntryAliasPackageFixture.ManifestTrailingDot);
    }

    // The trailing dot FIRST still lands both names on one file, just the other way round: the real manifest overwrites
    // the decoy, so the manifest scanned is the real one (its finding is reported), and what is lost is the trailing-dot
    // entry's own bytes, which a Linux consumer ships as a separate file and nothing here scanned.
    [WindowsExtractionFact("Windows drops the trailing dot, so both entries land on Real.nuspec")]
    public void OpenAndScan_OnWindows_ForATrailingDotAliasBeforeTheManifest_ScanTheRealManifestAndReportTheOverwrittenEntry()
    {
        using (var pkg = Open(fixture.NuspecTrailingDotBeforePath))
        {
            Assert.Equal([EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
            Assert.Contains(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
            Assert.Equal([EntryAliasPackageFixture.ManifestTrailingDot], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.NuspecTrailingDotBeforePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.RealManifest && f.Source == ScriptFindingSource.PackageMetadata);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.ManifestTrailingDot, PackageItemRole.Other));
    }
    #endregion

    #region Methods: the extractor's character renames (Windows)
    // RecursiveExtractor maps ':' '<' '?' '|' to '_' on Windows, so every one of these four entries is written over
    // content/a_b.bin, which the real entry claims. All four aliases claimed nothing and all four are lost. Non-binary
    // (.bin): the kind filter missed every one of them, while YARA scanned whichever bytes were written last. Those are a
    // decoy's, so the real entry fails its content check and is lost too, first in archive order (ADR 0036).
    [WindowsExtractionFact("the extractor maps : < ? | to _ on Windows, onto content/a_b.bin")]
    public void Open_OnWindows_ForCharacterRenameAliases_ReportsTheOverwrittenEntryAndEveryAliasUninventoried()
    {
        using var pkg = Open(fixture.RenameAliasesPath);

        Assert.Equal([EntryAliasPackageFixture.RenameTarget], ContentFiles(pkg));
        Assert.Equal("decoy content\n", File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "a_b.bin")));
        Assert.Equal(EntryAliasPackageFixture.RenameAliases.Prepend(EntryAliasPackageFixture.RenameTarget), pkg.UninventoriedEntryNames);
    }

    [WindowsExtractionFact("only Windows renames these entries, so only there are there skip rows")]
    public void Scan_OnWindows_ForCharacterRenameAliases_HasOneContentSkipRowPerAliasAndOneForTheOverwrittenEntry()
    {
        var scan = Scan(fixture.RenameAliasesPath);

        AssertNotInventoriedRows(scan,
            EntryAliasPackageFixture.RenameAliases.Prepend(EntryAliasPackageFixture.RenameTarget).Select(a => (a, PackageItemRole.Content)).ToArray());
    }

    // The reverse order is NOT a control for a rename the way it is for 8.3: the alias is still never written under its
    // own name, so it still claims nothing and is still lost, whichever entry's bytes survive.
    [WindowsExtractionFact("the extractor maps ':' to '_' on Windows whatever the archive order")]
    public void Open_OnWindows_ForAColonRenameAliasBeforeTheRealEntry_StillReportsTheAliasUninventoried()
    {
        using var pkg = Open(fixture.ColonAliasBeforePath);

        Assert.Equal([EntryAliasPackageFixture.RenameTarget], ContentFiles(pkg));
        Assert.Equal([EntryAliasPackageFixture.ColonAlias], pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods: a device name, and the accepted cost (Windows)
    // A non-binary device-named entry: its bytes never reach disk at all. The kind filter let it go unreported.
    [WindowsExtractionFact("Windows cannot create a file named after a reserved DOS device")]
    public void OpenAndScan_OnWindows_ForADeviceNamedTextEntry_ReportIt()
    {
        using (var pkg = Open(fixture.DeviceTextPath))
        {
            Assert.Empty(ContentFiles(pkg));
            Assert.Equal([EntryAliasPackageFixture.DeviceTextEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.DeviceTextPath), (EntryAliasPackageFixture.DeviceTextEntry, PackageItemRole.Content));
    }

    // The ACCEPTED COST of rule (a) (Review 1), pinned so it changes only on purpose: a LONE trailing-space or
    // trailing-dot entry is trimmed onto a NEW file, so its bytes WERE written (and YARA scanned them under the trimmed
    // name), but the entry claimed nothing and so reads lost. That is fail-closed, deliberately: telling "renamed onto a
    // new file" from "renamed onto another entry's file" would need the filesystem probe review C1 removed, and such names
    // are already TrailingSpaceOrDot anomalies.
    [WindowsExtractionFact("Windows trims a trailing space onto a new file, which the entry does not claim")]
    public void OpenAndScan_OnWindows_ForALoneTrailingSpaceTextEntry_ReportItLostFailClosed()
    {
        AssertLoneTrailingNameLost(fixture.LoneTrailingSpacePath, EntryAliasPackageFixture.LoneTrailingSpaceEntry);
    }

    [WindowsExtractionFact("Windows trims a trailing dot onto a new file, which the entry does not claim")]
    public void OpenAndScan_OnWindows_ForALoneTrailingDotTextEntry_ReportItLostFailClosed()
    {
        AssertLoneTrailingNameLost(fixture.LoneTrailingDotPath, EntryAliasPackageFixture.LoneTrailingDotEntry);
    }
    #endregion

    #region Methods: the 8.3 alias first (controls, Windows)
    // The 8.3 alias first: no file has that short name yet, so the extractor creates a file literally named SOMEPA~1.TAR,
    // and the long name then gets a short name of its own. Two files, both claimed, nothing overwritten, nothing lost; the
    // real .targets is the one scanned and its findings are reported. The rule does not over-fire on it.
    [ShortNameAliasFact("the control for the 8.3 alias: it only means something where 8.3 names are generated")]
    public void OpenAndScan_OnWindows_ForAShortNameAliasBeforeTheTargetsFile_LoseNothingAndScanTheRealFile()
    {
        using (var pkg = Open(fixture.TargetsAliasBeforePath))
        {
            var build = Path.Combine(pkg.ContentRoot, "build");
            Assert.Equal(
                [EntryAliasPackageFixture.TargetsShortAliasFileName, "Some.Package.targets"],
                Directory.GetFiles(build).Select(Path.GetFileName).Order(StringComparer.Ordinal));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.TargetsAliasBeforePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        Assert.Empty(scan.Assemblies);
    }

    [ShortNameAliasFact("the control for the 8.3 alias: it only means something where 8.3 names are generated")]
    public void OpenAndScan_OnWindows_ForAShortNameAliasBeforeTheManifest_LoseNothingAndScanTheRealManifest()
    {
        using (var pkg = Open(fixture.NuspecShortBeforePath))
        {
            Assert.Equal([EntryAliasPackageFixture.ManifestShortAlias, EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
            Assert.Equal(EntryAliasPackageFixture.RealManifest, Path.GetFileName(pkg.NuspecPath));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.NuspecShortBeforePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.RealManifest && f.Source == ScriptFindingSource.PackageMetadata);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
        Assert.Empty(scan.Assemblies);
    }
    #endregion
#endif

    #region Methods: a leading drive segment (every platform)
    // Review C2. The extractor drops a leading drive segment on BOTH platforms (measured), so "./C:/Real.nuspec" is written
    // to Real.nuspec. After the real manifest, it overwrites it: the decoy is what is scanned, the manifest finding is gone,
    // and the disclosure is the drive entry (which claimed nothing) and the manifest (whose file holds the decoy, S8).
    [Fact]
    public void Open_ForADriveSegmentAliasAfterTheManifest_ReportsTheManifestAndTheAliasUninventoried()
    {
        AssertManifestOverwrittenAndAliasLost(fixture.DriveManifestAfterPath, EntryAliasPackageFixture.ManifestDriveAlias);
    }

    [Fact]
    public void Scan_ForADriveSegmentAliasAfterTheManifest_IsIncompleteWithTheManifestAndTheAliasAsItsSkipRows()
    {
        var scan = Scan(fixture.DriveManifestAfterPath);

        AssertManifestAndAliasRows(scan, EntryAliasPackageFixture.ManifestDriveAlias);
        Assert.DoesNotContain(scan.ScriptFindings, f => f.Source == ScriptFindingSource.PackageMetadata);
    }

    // In the reverse order the real manifest overwrites the decoy (its finding is reported), and the drive entry's own
    // bytes are what is lost: still disclosed.
    [Fact]
    public void OpenAndScan_ForADriveSegmentAliasBeforeTheManifest_ScanTheRealManifestAndReportTheOverwrittenEntry()
    {
        using (var pkg = Open(fixture.DriveManifestBeforePath))
        {
            Assert.Equal([EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
            Assert.Contains(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
            Assert.Equal([EntryAliasPackageFixture.ManifestDriveAlias], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.DriveManifestBeforePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.RealManifest && f.Source == ScriptFindingSource.PackageMetadata);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.ManifestDriveAlias, PackageItemRole.Other));
    }

#if WINDOWS
    [Fact]
    public void ScanPackageCli_ForADriveSegmentAliasAfterTheManifest_StrictExitsThreeAndNamesTheAlias()
    {
        AssertCliIncompleteNaming(fixture.DriveManifestAfterPath, EntryAliasPackageFixture.ManifestDriveAlias);
    }
#endif
    #endregion

    #region Methods: review C1, the report never depends on the scanning host (every platform)
    // The probe that was fixed. A drive-qualified key ("C:/Windows/win.ini") once reached File.Exists(Path.Combine(root,
    // key)), where Path.Combine discards the root, so whether an entry was reported depended on whether that path existed
    // ON THE SCANNING HOST. One of these two exists on any Windows host and the other on none; both must be reported the
    // same way. Only existence is ever asked of the host here (to show the pair really straddles it); no host file is read.
    [Fact]
    public void Open_ForDriveQualifiedEntriesOnlyOneOfWhichExistsOnTheHost_ReportsBothTheSameWay()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.True(File.Exists(@"C:\Windows\win.ini"), "precondition: the host path one entry names exists.");
            Assert.False(File.Exists(@"C:\Windows\nonexistent-xyz.ini"), "precondition: the other entry's host path does not.");
        }

        using var pkg = Open(fixture.HostProbePath);

        // Ground truth: both were extracted INSIDE the content root, with the drive segment dropped.
        Assert.Equal(["Windows/nonexistent-xyz.ini", "Windows/win.ini"], ContentRootFiles(pkg).Where(f => f.StartsWith("Windows/", StringComparison.Ordinal)));
        Assert.Equal(EntryAliasPackageFixture.HostProbeEntries, pkg.UninventoriedEntryNames);
    }

    [Fact]
    public void Scan_ForDriveQualifiedEntriesOnlyOneOfWhichExistsOnTheHost_GivesBothTheSameSkipRow()
    {
        var scan = Scan(fixture.HostProbePath);

        var rows = AssertNotInventoriedRows(scan, EntryAliasPackageFixture.HostProbeEntries.Select(e => (e, PackageItemRole.Other)).ToArray());
        Assert.Single(rows.Select(r => r.SkipReason).Distinct());
    }
    #endregion

    #region Methods: an ordinary package (every platform)
    // The control every rule must leave alone: a manifest, a script, a build file and a text file, each claiming its own
    // file. Nothing lost, nothing skipped, the scan Completed.
    [Fact]
    public void OpenAndScan_ForAnOrdinaryPackage_LoseNothing()
    {
        using (var pkg = Open(fixture.OrdinaryPath))
            Assert.Empty(pkg.UninventoriedEntryNames);

        var scan = Scan(fixture.OrdinaryPath);
        Assert.Empty(scan.Assemblies);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
    }
    #endregion

    #region Methods: Linux, where these names are written verbatim
    // ext4 has no short names, keeps a trailing dot or space, holds ':' '<' '?' '|' and device names: every such entry is
    // a file of its own, claims it, nothing is lost, and the real file keeps its real bytes, which is what is scanned.
    // The one exception is a ':' (review 9, C1, below): lost on every platform.
    [LinuxExtractionFact("ext4 has no 8.3 names, so build/SOMEPA~1.TAR is a separate file")]
    public void OpenAndScan_OnLinux_ForAShortNameAliasAfterATargetsFile_LoseNothingAndScanTheRealFile()
    {
        using (var pkg = Open(fixture.TargetsAliasAfterPath))
        {
            var build = Path.Combine(pkg.ContentRoot, "build");
            Assert.Equal(
                [EntryAliasPackageFixture.TargetsShortAliasFileName, "Some.Package.targets"],
                Directory.GetFiles(build).Select(Path.GetFileName).Order(StringComparer.Ordinal));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.TargetsAliasAfterPath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        Assert.Empty(scan.Assemblies);
    }

    [LinuxExtractionFact("ext4 has no 8.3 names, so REAL~1.NUS is a separate file")]
    public void OpenAndScan_OnLinux_ForAShortNameAliasAfterTheManifest_LoseNothingAndScanTheRealManifest()
    {
        AssertNothingLostAndRealManifestScanned(fixture.NuspecShortAfterPath, EntryAliasPackageFixture.ManifestShortAlias);
    }

    // The trailing-dot/-space entry claims its OWN file on Linux (measured): pinned, so the Windows report above reads as
    // the OS aliasing being disclosed, not as Silvergun distrusting the name.
    [LinuxExtractionFact("ext4 keeps the trailing dot, so Real.nuspec. is a separate file it claims")]
    public void OpenAndScan_OnLinux_ForATrailingDotAliasAfterTheManifest_LoseNothingAndScanTheRealManifest()
    {
        AssertNothingLostAndRealManifestScanned(fixture.NuspecTrailingDotAfterPath, EntryAliasPackageFixture.ManifestTrailingDot);
    }

    [LinuxExtractionFact("ext4 keeps the trailing space, so 'Real.nuspec ' is a separate file it claims")]
    public void OpenAndScan_OnLinux_ForATrailingSpaceAliasAfterTheManifest_LoseNothingAndScanTheRealManifest()
    {
        AssertNothingLostAndRealManifestScanned(fixture.NuspecTrailingSpaceAfterPath, EntryAliasPackageFixture.ManifestTrailingSpace);
    }

    [LinuxExtractionFact("ext4 keeps the trailing dot, so Real.nuspec. is a separate file it claims")]
    public void OpenAndScan_OnLinux_ForATrailingDotAliasBeforeTheManifest_LoseNothingAndScanTheRealManifest()
    {
        AssertNothingLostAndRealManifestScanned(fixture.NuspecTrailingDotBeforePath, EntryAliasPackageFixture.ManifestTrailingDot);
    }

    // ext4 writes every one of them verbatim, so the extractor renames nothing and '<' '?' '|' claim their own files. The
    // ':' entry is lost all the same since S10 (entry-aliasing review 9, C1): a ':' is an NTFS stream separator to a
    // Windows consumer, so the file a Linux scan host reads under that name is not what Windows NuGet installs. It is
    // lost before it can claim anything, so the real a_b.bin keeps its claim and its bytes.
    [LinuxExtractionFact("ext4 holds : < ? | verbatim, so the extractor renames nothing")]
    public void Open_OnLinux_ForCharacterRenameAliases_WritesEachVerbatimAndLosesOnlyTheColonEntry()
    {
        using var pkg = Open(fixture.RenameAliasesPath);

        Assert.Equal(
            EntryAliasPackageFixture.RenameAliases.Append(EntryAliasPackageFixture.RenameTarget).Order(StringComparer.Ordinal),
            ContentFiles(pkg));
        Assert.Equal("real content\n", File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "a_b.bin")));
        Assert.Equal([EntryAliasPackageFixture.ColonAlias], pkg.UninventoriedEntryNames);
    }

    [LinuxExtractionFact("ext4 holds ':' verbatim whatever the archive order")]
    public void Open_OnLinux_ForAColonRenameAliasBeforeTheRealEntry_LosesOnlyTheColonEntry()
    {
        using var pkg = Open(fixture.ColonAliasBeforePath);

        Assert.Equal(
            new[] { EntryAliasPackageFixture.ColonAlias, EntryAliasPackageFixture.RenameTarget }.Order(StringComparer.Ordinal),
            ContentFiles(pkg));
        Assert.Equal([EntryAliasPackageFixture.ColonAlias], pkg.UninventoriedEntryNames);
    }

    [LinuxExtractionFact("Linux has no reserved device names, so content/CON.txt is an ordinary file")]
    public void Open_OnLinux_ForADeviceNamedTextEntry_LosesNothing()
    {
        using var pkg = Open(fixture.DeviceTextPath);

        Assert.Equal([EntryAliasPackageFixture.DeviceTextEntry], ContentFiles(pkg));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    // The accepted cost is Windows-only: ext4 writes the lone trailing-name entry verbatim and it claims its own file.
    [LinuxExtractionFact("ext4 keeps the trailing space, so the entry claims its own file")]
    public void Open_OnLinux_ForALoneTrailingSpaceTextEntry_LosesNothing()
    {
        using var pkg = Open(fixture.LoneTrailingSpacePath);

        Assert.Equal([EntryAliasPackageFixture.LoneTrailingSpaceEntry], ContentFiles(pkg));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    [LinuxExtractionFact("ext4 keeps the trailing dot, so the entry claims its own file")]
    public void Open_OnLinux_ForALoneTrailingDotTextEntry_LosesNothing()
    {
        using var pkg = Open(fixture.LoneTrailingDotPath);

        Assert.Equal([EntryAliasPackageFixture.LoneTrailingDotEntry], ContentFiles(pkg));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods: a %-escaped manifest name (every platform)
    // NuGet unescapes entry names, so the manifest it read is "My Pkg.nuspec", while the extractor writes the entry
    // verbatim as "My%20Pkg.nuspec". Before IsManifestName's unescape clause the ordinal match failed and the manifest
    // went unscanned (Unavailable). The package holds the manifest ALONE, so nothing else can make the scan Completed.
    [Fact]
    public void NuGetsReader_ForAPercentEscapedManifestName_ReadsTheUnescapedName()
    {
        using var reader = new PackageArchiveReader(fixture.PercentManifestPath);

        Assert.Equal(EntryAliasPackageFixture.PercentManifestUnescaped, reader.GetNuspecFile());
    }

    [Fact]
    public void Open_ForAPercentEscapedManifestName_SelectsIt()
    {
        using var pkg = Open(fixture.PercentManifestPath);

        Assert.NotNull(pkg.NuspecPath);
        Assert.Equal(EntryAliasPackageFixture.PercentManifest, Path.GetFileName(pkg.NuspecPath));
        Assert.Contains(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath), StringComparison.Ordinal);
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    [Fact]
    public void Scan_ForAPercentEscapedManifestName_IsCompletedWithItsFindings()
    {
        var scan = Scan(fixture.PercentManifestPath);

        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
        Assert.Null(scan.ScriptScanUnavailableReason);
        var manifestFindings = scan.ScriptFindings.Where(f => f.RelativePath == EntryAliasPackageFixture.PercentManifest).ToArray();
        Assert.NotEmpty(manifestFindings);
        Assert.All(manifestFindings, f => Assert.Equal(ScriptFindingSource.PackageMetadata, f.Source));
    }
    #endregion

    #region Methods: helpers (the shared ones are in EntryAliasingSupport)
    // The real manifest's file holds the decoy (no matching projectUrl), it is still the manifest selected, and both are
    // lost, in archive order: the manifest because its file does not hold NuGet's bytes (ADR 0036), the alias because it
    // claimed nothing.
    private static void AssertManifestOverwrittenAndAliasLost(string nupkgPath, string alias)
    {
        using var pkg = Open(nupkgPath);

        Assert.Equal([EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
        Assert.Equal(EntryAliasPackageFixture.RealManifest, Path.GetFileName(pkg.NuspecPath));
        Assert.DoesNotContain(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
        Assert.Equal([EntryAliasPackageFixture.RealManifest, alias], pkg.UninventoriedEntryNames);
    }

    // The skip rows of an overwritten manifest: the manifest's, then the alias's, both role Other (root entries).
    private static void AssertManifestAndAliasRows(PackageCapabilityReport scan, string alias) =>
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.RealManifest, PackageItemRole.Other), (alias, PackageItemRole.Other));

    private static void AssertNothingLostAndRealManifestScanned(string nupkgPath, string alias)
    {
        using (var pkg = Open(nupkgPath))
        {
            Assert.Contains(alias, RootEntries(pkg));     // ground truth: the alias is a file of its own here
            Assert.Equal(EntryAliasPackageFixture.RealManifest, Path.GetFileName(pkg.NuspecPath));
            Assert.Contains(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.RealManifest && f.Source == ScriptFindingSource.PackageMetadata);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
        Assert.Empty(scan.Assemblies);
    }

#if WINDOWS
    // The bytes were written, under the trimmed name; the entry claimed nothing, so it is lost and has a skip row.
    private static void AssertLoneTrailingNameLost(string nupkgPath, string entry)
    {
        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal([EntryAliasPackageFixture.LoneTrimmedFile], ContentFiles(pkg));
            Assert.Equal([entry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(nupkgPath), (entry, PackageItemRole.Content));
    }
#endif
    #endregion

    #region Fields
    private readonly EntryAliasPackageFixture fixture;
    #endregion
}

/// <summary>
/// The helpers <see cref="EntryAliasingCoverageTests"/> and <see cref="EntryAliasingBackslashAndDuplicateTests"/> share:
/// a real <see cref="NuGetPackage.Open"/> / <see cref="PackageScanner.Scan"/>, views of the extracted tree, the exact
/// shape of a not-inventoried skip row, and (Windows) the real CLI run as a child process.
/// </summary>
internal static class EntryAliasingSupport
{
    #region Methods
    public static NuGetPackage Open(string nupkgPath)
    {
        var open = NuGetPackage.Open(nupkgPath);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    public static PackageCapabilityReport Scan(string nupkgPath)
    {
        var scan = PackageScanner.Scan(nupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    // The files and directories at the content root, by name, ordinal order.
    public static string[] RootEntries(NuGetPackage pkg) =>
        Directory.GetFileSystemEntries(pkg.ContentRoot).Select(f => Path.GetFileName(f)!).Order(StringComparer.Ordinal).ToArray();

    // Every file under the content root, relative, forward-slashed, ordinal order.
    public static string[] ContentRootFiles(NuGetPackage pkg) =>
        Directory.GetFiles(pkg.ContentRoot, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(pkg.ContentRoot, f).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();

    // The files under content/, as ContentRootFiles spells them.
    public static string[] ContentFiles(NuGetPackage pkg) =>
        ContentRootFiles(pkg).Where(f => f.StartsWith("content/", StringComparison.Ordinal)).ToArray();

    // The files under build/, as ContentRootFiles spells them.
    public static string[] BuildFiles(NuGetPackage pkg) =>
        ContentRootFiles(pkg).Where(f => f.StartsWith("build/", StringComparison.Ordinal)).ToArray();

    // Exactly these skip rows, each a DECLARED ENTRY never written as a file of its own (entry-aliasing review 2, W2:
    // NotInventoried, empty FullPath and Sha256, no report) and saying so; returned in order.
    public static AssemblyScanResult[] AssertNotInventoriedRows(PackageCapabilityReport scan, params (string Entry, PackageItemRole Role)[] expected)
    {
        var rows = scan.Assemblies.Where(a => a.SkipReason is not null).ToArray();
        Assert.Equal(expected.Select(e => e.Entry), rows.Select(r => r.Assembly.RelativePath));
        foreach (var (row, (_, role)) in rows.Zip(expected))
        {
            Assert.Contains("NOT inventoried", row.SkipReason, StringComparison.Ordinal);
            Assert.Contains("never written as an extracted file of its own", row.SkipReason, StringComparison.Ordinal);
            Assert.True(row.NotInventoried, $"'{row.Assembly.RelativePath}' is a lost entry, so it must read NotInventoried.");
            Assert.Null(row.Report);
            Assert.Equal(role, row.Assembly.Role);
            Assert.Equal(string.Empty, row.Assembly.FullPath);
            Assert.Equal(string.Empty, row.Assembly.Sha256);
        }
        return rows;
    }

#if WINDOWS
    // The real net10.0-windows CLI (copied into this bin by the ProjectReference), offline: --no-vulns --no-yara, --json
    // --strict. Exit 3, and the JSON's Completeness is incomplete with the NEVER-EXTRACTED caveat naming the entry. Since
    // entry-aliasing review 2 (W2) a lost entry is not a file, so it must not be counted under "N of M file(s) could not
    // be analysed" (a three-entry package used to read "1 of 1 file(s)"). The exit code alone would not discriminate
    // (--no-vulns leaves its own NotChecked caveat, so this run is never 0); the caveat naming the entry is the statement.
    public static void AssertCliIncompleteNaming(string nupkgPath, string entry)
    {
        var run = RunCli(nupkgPath);

        Assert.True(run.Exited, "CLI did not exit within the timeout.");
        Assert.True(run.Exit == 3, $"expected exit 3 (incomplete), got {run.Exit}.\nstderr:\n{run.Error}");
        using var doc = JsonDocument.Parse(run.Output);
        var completeness = doc.RootElement.GetProperty("Completeness");
        Assert.False(completeness.GetProperty("IsComplete").GetBoolean());
        var caveats = completeness.GetProperty("Caveats").EnumerateArray().Select(e => e.GetString() ?? string.Empty).ToArray();
        Assert.Contains(caveats, c => c.Contains("never extracted as", StringComparison.Ordinal) && c.Contains(entry, StringComparison.Ordinal));
        Assert.DoesNotContain(caveats, c => c.Contains("file(s) could not be analysed", StringComparison.Ordinal) && c.Contains(entry, StringComparison.Ordinal));
    }

    private static CliRun RunCli(string nupkgPath)
    {
        Assert.True(File.Exists(CliExe), $"the net10.0-windows CLI apphost is not at '{CliExe}'.");
        var psi = new ProcessStartInfo(CliExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in new[] { "scan-package", nupkgPath, "--no-vulns", "--no-yara", "--json", "--strict" })
            psi.ArgumentList.Add(arg);
        psi.Environment["NO_COLOR"] = "1";

        using var process = Process.Start(psi)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(CliTimeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            return new CliRun(-1, string.Empty, string.Empty, false);
        }

        return new CliRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult(), true);
    }
#endif
    #endregion

    #region Nested types
    private sealed record CliRun(int Exit, string Output, string Error, bool Exited);
    #endregion

    #region Fields
    private static readonly string CliExe = Path.Combine(AppContext.BaseDirectory, "Silvergun.CLI.exe");
    private const int CliTimeoutMs = 120_000;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="EntryAliasingCoverageTests"/> with pure BCL zip (raw entry names, stored
/// verbatim by <see cref="NupkgBuilder"/>), in the archive order each test depends on. The shapes are the reviewers'
/// probes (<c>s6r-probe</c>, <c>s7a-probe</c>) with the probes' webhook URL replaced by the suite's benign fixtures.
/// </summary>
public sealed class EntryAliasPackageFixture : IDisposable
{
    #region Constructors
    public EntryAliasPackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        var realTargets = Text(PackageFixture.MaliciousTargets);
        var decoyTargets = Text(DecoyTargets);
        var plainNuspec = (Name: "PkgAlias.nuspec", Bytes: Nuspec("PkgAlias", projectUrl: null));

        TargetsAliasAfterPath = Write("TargetsAliasAfter", [plainNuspec, (TargetsEntry, realTargets), (TargetsShortAlias, decoyTargets)]);
        TargetsAliasBeforePath = Write("TargetsAliasBefore", [plainNuspec, (TargetsShortAlias, decoyTargets), (TargetsEntry, realTargets)]);

        var realManifest = Nuspec("Real", PackageFixture.NuspecMatchProjectUrl);
        var decoyManifest = Nuspec("Real", projectUrl: null);
        var script = (Name: "tools/plain.ps1", Bytes: Text("Write-Host 'installing'\n"));

        NuspecShortAfterPath = Write("NuspecShortAfter", [(RealManifest, realManifest), (ManifestShortAlias, decoyManifest), script]);
        NuspecShortBeforePath = Write("NuspecShortBefore", [(ManifestShortAlias, decoyManifest), (RealManifest, realManifest), script]);
        NuspecTrailingDotAfterPath = Write("NuspecTrailingDotAfter", [(RealManifest, realManifest), (ManifestTrailingDot, decoyManifest), script]);
        NuspecTrailingSpaceAfterPath = Write("NuspecTrailingSpaceAfter", [(RealManifest, realManifest), (ManifestTrailingSpace, decoyManifest), script]);
        NuspecTrailingDotBeforePath = Write("NuspecTrailingDotBefore", [(ManifestTrailingDot, decoyManifest), (RealManifest, realManifest), script]);
        DriveManifestAfterPath = Write("DriveManifestAfter", [(RealManifest, realManifest), (ManifestDriveAlias, decoyManifest), script]);
        DriveManifestBeforePath = Write("DriveManifestBefore", [(ManifestDriveAlias, decoyManifest), (RealManifest, realManifest), script]);

        RenameAliasesPath = Write("RenameAliases",
            [plainNuspec, (RenameTarget, Text("real content\n")), .. RenameAliases.Select(a => (a, Text("decoy content\n")))]);
        ColonAliasBeforePath = Write("ColonAliasBefore", [plainNuspec, (ColonAlias, Text("decoy content\n")), (RenameTarget, Text("real content\n"))]);

        DeviceTextPath = Write("DeviceText", [plainNuspec, (DeviceTextEntry, Text("hello\n"))]);
        LoneTrailingSpacePath = Write("LoneTrailingSpace", [plainNuspec, (LoneTrailingSpaceEntry, Text("hello\n"))]);
        LoneTrailingDotPath = Write("LoneTrailingDot", [plainNuspec, (LoneTrailingDotEntry, Text("hello\n"))]);
        HostProbePath = Write("HostProbe", [plainNuspec, .. HostProbeEntries.Select(e => (e, Text("hello\n")))]);
        OrdinaryPath = Write("Ordinary",
            [plainNuspec, script, ("build/PkgAlias.targets", decoyTargets), ("content/readme.txt", Text("hello\n"))]);

        PercentManifestPath = Write("PercentManifest", [(PercentManifest, Nuspec("EscPkg", PackageFixture.NuspecMatchProjectUrl))]);
    }
    #endregion

    #region Properties
    /// <summary>The real build file: its bytes are <see cref="PackageFixture.MaliciousTargets"/>, which yields findings.</summary>
    public const string TargetsEntry = "build/Some.Package.targets";

    /// <summary>The first 8.3 short name NTFS generates for <see cref="TargetsEntry"/> in a fresh directory.</summary>
    public const string TargetsShortAlias = "build/SOMEPA~1.TAR";

    /// <summary><see cref="TargetsShortAlias"/>'s file name, as it appears on disk where it is a file of its own.</summary>
    public const string TargetsShortAliasFileName = "SOMEPA~1.TAR";

    /// <summary>The decoy written through an alias: an empty project, no findings.</summary>
    public const string DecoyTargets = "<Project />\n";

    /// <summary>The real manifest: NuGet's manifest, carrying <see cref="PackageFixture.NuspecMatchProjectUrl"/>.</summary>
    public const string RealManifest = "Real.nuspec";

    /// <summary>The first 8.3 short name NTFS generates for <see cref="RealManifest"/> in a fresh directory.</summary>
    public const string ManifestShortAlias = "REAL~1.NUS";

    /// <summary><see cref="RealManifest"/> with a trailing dot, which Win32 drops.</summary>
    public const string ManifestTrailingDot = "Real.nuspec.";

    /// <summary><see cref="RealManifest"/> with a trailing space, which Win32 drops.</summary>
    public const string ManifestTrailingSpace = "Real.nuspec ";

    /// <summary><see cref="RealManifest"/> behind a leading drive segment, which the extractor drops on both platforms.</summary>
    public const string ManifestDriveAlias = "./C:/Real.nuspec";

    /// <summary>The real entry the character-rename aliases land on, on Windows.</summary>
    public const string RenameTarget = "content/a_b.bin";

    /// <summary>The ':' alias of <see cref="RenameTarget"/>.</summary>
    public const string ColonAlias = "content/a:b.bin";

    /// <summary>A device-named text entry, which Windows never writes.</summary>
    public const string DeviceTextEntry = "content/CON.txt";

    /// <summary>A lone text entry with a trailing space, trimmed by Windows onto <see cref="LoneTrimmedFile"/>.</summary>
    public const string LoneTrailingSpaceEntry = "content/readme.txt ";

    /// <summary>A lone text entry with a trailing dot, trimmed by Windows onto <see cref="LoneTrimmedFile"/>.</summary>
    public const string LoneTrailingDotEntry = "content/readme.txt.";

    /// <summary>The file Windows writes for either lone trailing-name entry.</summary>
    public const string LoneTrimmedFile = "content/readme.txt";

    /// <summary>An old OPC-escaped manifest name, written verbatim by the extractor.</summary>
    public const string PercentManifest = "My%20Pkg.nuspec";

    /// <summary>What NuGet reads <see cref="PercentManifest"/> as.</summary>
    public const string PercentManifestUnescaped = "My Pkg.nuspec";

    /// <summary>The ':' '&lt;' '?' '|' aliases of <see cref="RenameTarget"/>, in archive order (after it).</summary>
    public static readonly string[] RenameAliases = ["content/a:b.bin", "content/a<b.bin", "content/a?b.bin", "content/a|b.bin"];

    /// <summary>Review C1's pair, in archive order: one names a host path that exists on Windows, the other one that does not.</summary>
    public static readonly string[] HostProbeEntries = ["./C:/Windows/win.ini", "./C:/Windows/nonexistent-xyz.ini"];

    public string TargetsAliasAfterPath { get; }
    public string TargetsAliasBeforePath { get; }
    public string NuspecShortAfterPath { get; }
    public string NuspecShortBeforePath { get; }
    public string NuspecTrailingDotAfterPath { get; }
    public string NuspecTrailingSpaceAfterPath { get; }
    public string NuspecTrailingDotBeforePath { get; }
    public string DriveManifestAfterPath { get; }
    public string DriveManifestBeforePath { get; }
    public string RenameAliasesPath { get; }
    public string ColonAliasBeforePath { get; }
    public string DeviceTextPath { get; }
    public string LoneTrailingSpacePath { get; }
    public string LoneTrailingDotPath { get; }
    public string HostProbePath { get; }
    public string OrdinaryPath { get; }
    public string PercentManifestPath { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Nuspec(string id, string? projectUrl) => Text(NupkgBuilder.NuspecXml(
        id, "1.0.0", "Silvergun Tests", "Entry-aliasing coverage test package.", "net8.0", [], projectUrl: projectUrl));

    // Every name passed as NupkgBuilder's raw list, in the given archive order (the order is the point here).
    private string Write(string name, (string Name, byte[] Bytes)[] entries)
    {
        var path = Path.Combine(rootDir, $"{name}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [], entries);
        return path;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}

#if WINDOWS
/// <summary>
/// Gates a test to Windows <b>with 8.3 short-name generation live</b> where <see cref="NuGetPackage.Open"/> extracts.
/// Generation is a per-volume setting (<c>fsutil 8dot3name</c>, which needs elevation to query), so it is probed rather
/// than assumed: long-named files are created in a fresh directory under <see cref="Path.GetTempPath"/>, the same place
/// extraction happens, and their expected short names must resolve. Skip, never an early return (see
/// <see cref="WindowsExtractionFactAttribute"/>).
/// </summary>
public sealed class ShortNameAliasFactAttribute : FactAttribute
{
    #region Constructors
    public ShortNameAliasFactAttribute(string because)
    {
        if (ShortNameProbe.WhyUnavailable is { } why)
            Skip = $"Needs Windows 8.3 short-name generation ({because}): {why}.";
    }
    #endregion
}

/// <summary>Whether 8.3 short names are generated where packages are extracted; probed once per process.</summary>
internal static class ShortNameProbe
{
    #region Properties
    /// <summary>Null when short names resolve; otherwise the reason they cannot be relied on.</summary>
    public static string? WhyUnavailable => probe.Value;
    #endregion

    #region Methods
    private static string? Probe()
    {
        if (!OperatingSystem.IsWindows())
            return "not Windows";

        var dir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias", "shortname-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            foreach (var (longName, shortName) in new[] { ("Some.Package.targets", "SOMEPA~1.TAR"), ("Real.nuspec", "REAL~1.NUS") })
            {
                File.WriteAllBytes(Path.Combine(dir, longName), []);
                if (!File.Exists(Path.Combine(dir, shortName)))
                    return $"8.3 short-name generation is off under {Path.GetTempPath()} ({longName} has no short name {shortName})";
            }
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"the probe could not run: {ex.GetType().Name}";
        }
        finally
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
        }
    }
    #endregion

    #region Fields
    private static readonly Lazy<string?> probe = new(Probe);
    #endregion
}
#endif
