namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c>, the shapes Reviews 2-4 turned on: <b>exact duplicate names (C3),
/// <c>'\'</c>-terminated names (Review 3, then Review 4's C1-r4), and the <c>'/'</c>-terminated controls.</b>
///
/// <para><b>The rule (Review 4/5):</b> every non-empty declared name not ending in <c>'/'</c> is lost if it is a
/// duplicate, escapes the root, or claimed no extracted file. There is NO exemption by name shape: Review 2's W1 (a
/// <c>'\'</c>-terminated name is a directory) reopened a silent overwrite (C1-r3: the extractor writes a NON-empty
/// <c>x\</c> as the FILE <c>x</c>), and Review 3's narrower "<c>'\'</c>-terminated and its key absent from the inventory"
/// was fooled by every rename, because a renamed entry's key is absent BECAUSE it was written elsewhere (C1-r4).</para>
///
/// <para><b>S8 (ADR 0036, the content check) replaces "a duplicate is lost":</b> a name's FIRST occurrence must hold the
/// bytes NuGet installs (its first copy), and later occurrences are not weighed on their own. A differing later copy is
/// still caught, because the extractor writes it over the first. The same check means that wherever a decoy is written
/// over a real entry's file, the entry that CLAIMS that file is lost too, alongside the decoy: the real entry when the
/// decoy comes after it, and a <c>'\'</c> entry that claimed the key first when the real name comes after.</para>
///
/// <para><b>Measured by the reviewer</b> (scratchpad <c>s11a-run.txt</c> on Windows 10 with 8.3 generation on,
/// <c>s11a-linux-raw.txt</c> under WSL; the <c>y-*</c>/<c>z-*</c>/<c>q-*</c>/<c>x-dup-*</c> cases): which bytes are on
/// disk, and that NuGet installs the OTHER copy (the first, or both). Each test asserts that ground truth before the
/// verdict, so it cannot pass vacuously on a filesystem that behaved differently. Accepted, fail-closed costs, pinned
/// so they change only on purpose: an empty <c>content\</c> beside <c>content\a.txt</c> is lost (Review 4), and a
/// zero-length <c>x\</c> beside <c>x</c> is lost, even when the real bytes were scanned (Review 4, N1).</para>
///
/// <para>Content is benign throughout: the hook is <see cref="PackageFixture.MaliciousTargets"/>, the decoy an empty
/// project, the real manifest carries <see cref="PackageFixture.NuspecMatchProjectUrl"/>.</para>
/// </summary>
public sealed class EntryAliasingBackslashAndDuplicateTests : IClassFixture<EntryAliasProbePackageFixture>
{
    #region Constructors
    public EntryAliasingBackslashAndDuplicateTests(EntryAliasProbePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: C1-r4, a leading drive segment AND a trailing '\' (every platform)
    // The reviewer's Linux headline for C1-r4: the extractor drops "./C:" and the trailing '\', writing the decoy over the
    // hook, while the entry's key ("C:/build/…") is absent from the inventory — which Review 3's exemption read as "a
    // directory". Measured on both platforms: the decoy is on disk and scanned (0 findings), NuGet installs the hook. The
    // real entry claims a file holding the decoy, so it is lost too (S8).
    [Fact]
    public void OpenAndScan_ForADriveSegmentAndBackslashDecoyAfterATargetsFile_ReportTheOverwrittenEntryAndTheDecoyLost()
    {
        using (var pkg = Open(fixture.DriveBackslashTargetsAfterPath))
        {
            AssertTheTargetsFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry, EntryAliasProbePackageFixture.DriveBackslashTargets], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.DriveBackslashTargetsAfterPath);
        AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build), (EntryAliasProbePackageFixture.DriveBackslashTargets, PackageItemRole.Other));
        Assert.Empty(scan.ScriptFindings);
    }

    [Fact]
    public void OpenAndScan_ForADriveSegmentAndBackslashDecoyAfterTheManifest_ReportTheManifestAndTheDecoyLost()
    {
        using (var pkg = Open(fixture.DriveBackslashManifestAfterPath))
        {
            Assert.Equal([EntryAliasPackageFixture.RealManifest, "tools"], RootEntries(pkg));
            Assert.Equal(EntryAliasPackageFixture.RealManifest, Path.GetFileName(pkg.NuspecPath));
            Assert.DoesNotContain(PackageFixture.NuspecMatchProjectUrl, File.ReadAllText(pkg.NuspecPath!), StringComparison.Ordinal);
            Assert.Equal([EntryAliasPackageFixture.RealManifest, EntryAliasProbePackageFixture.DriveBackslashManifest], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.DriveBackslashManifestAfterPath);
        AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.RealManifest, PackageItemRole.Other), (EntryAliasProbePackageFixture.DriveBackslashManifest, PackageItemRole.Other));
        Assert.DoesNotContain(scan.ScriptFindings, f => f.Source == ScriptFindingSource.PackageMetadata);
    }
    #endregion

    #region Methods: C1-r4, a Windows rename AND a trailing '\' (Windows)
    // Each alias is written, minus its '\' and through the OS's rename, over the hook's file; its own key names no file
    // on disk. Measured: the decoy is on disk and scanned. The alias claimed nothing, and the real entry claims a file
    // holding the decoy (S8): both are lost.
    [WindowsExtractionFact("NTFS is case-insensitive, so build/Some.Package.targets\\ lands on build/some.package.targets")]
    public void Open_OnWindows_ForACaseRenamedBackslashDecoy_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        AssertWindowsAliasLost(fixture.CaseBackslashAfterPath, EntryAliasProbePackageFixture.CaseBackslashAlias, "build/some.package.targets");
    }

#if WINDOWS
    [ShortNameAliasFact("the extractor writes build/SOMEPA~1.TAR\\ through the short name of build/Some.Package.targets")]
    public void Open_OnWindows_ForAShortNameBackslashDecoy_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        AssertWindowsAliasLost(fixture.ShortBackslashAfterPath, EntryAliasProbePackageFixture.ShortBackslashAlias, EntryAliasPackageFixture.TargetsEntry);
    }
#endif

    [WindowsExtractionFact("Windows drops the trailing dot of build/Some.Package.targets.\\")]
    public void Open_OnWindows_ForATrailingDotBackslashDecoy_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        AssertWindowsAliasLost(fixture.DotBackslashAfterPath, EntryAliasProbePackageFixture.DotBackslashAlias, EntryAliasPackageFixture.TargetsEntry);
    }

    [WindowsExtractionFact("Windows drops the trailing space of 'build/Some.Package.targets \\'")]
    public void Open_OnWindows_ForATrailingSpaceBackslashDecoy_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        AssertWindowsAliasLost(fixture.SpaceBackslashAfterPath, EntryAliasProbePackageFixture.SpaceBackslashAlias, EntryAliasPackageFixture.TargetsEntry);
    }

    [WindowsExtractionFact("the extractor maps ':' to '_' on Windows, so content/a:b.bin\\ lands on content/a_b.bin")]
    public void Open_OnWindows_ForAColonRenamedBackslashDecoy_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        using (var pkg = Open(fixture.ColonBackslashAfterPath))
        {
            Assert.Equal([EntryAliasPackageFixture.RenameTarget], ContentFiles(pkg));
            Assert.Equal(EntryAliasProbePackageFixture.DecoyContent, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "a_b.bin")));
            Assert.Equal([EntryAliasPackageFixture.RenameTarget, EntryAliasProbePackageFixture.ColonBackslashAlias], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.ColonBackslashAfterPath),
            (EntryAliasPackageFixture.RenameTarget, PackageItemRole.Content), (EntryAliasProbePackageFixture.ColonBackslashAlias, PackageItemRole.Content));
    }

    [WindowsExtractionFact("NTFS is case-insensitive, so build/Some.Package.targets\\\\ lands on build/some.package.targets")]
    public void Open_OnWindows_ForACaseRenamedDoubleBackslashDecoy_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        AssertWindowsAliasLost(fixture.CaseDoubleBackslashAfterPath, EntryAliasProbePackageFixture.CaseDoubleBackslashAlias, "build/some.package.targets");
    }

#if WINDOWS
    // The CLI end to end, for the headline Windows alias.
    [WindowsExtractionFact("only Windows renames the case alias onto the hook's file")]
    public void ScanPackageCli_OnWindows_ForACaseRenamedBackslashDecoy_StrictExitsThreeAndNamesTheDecoy()
    {
        AssertCliIncompleteNaming(fixture.CaseBackslashAfterPath, EntryAliasProbePackageFixture.CaseBackslashAlias);
    }
#endif
    #endregion

    // The Linux side of the Windows-only aliases above: ext4 keeps case, ':', a trailing dot or space, and has no 8.3
    // names, so each alias is a file of its own (minus the '\'), claims it, and nothing is lost (measured). The ':' alias
    // is the exception since S10 (entry-aliasing review 9, C1): any ':' in NuGet's name is lost on every platform, before
    // it can claim anything, so it alone is lost and the real entry keeps its claim.
    [LinuxExtractionFact("ext4 holds each alias as a file of its own, so no rename lands it on the hook")]
    public void Open_OnLinux_ForTheWindowsRenameBackslashDecoys_LosesOnlyTheColonAlias()
    {
        foreach (var path in fixture.WindowsOnlyBackslashAliasPaths)
        {
            using var pkg = Open(path);
            var expected = path == fixture.ColonBackslashAfterPath ? new[] { EntryAliasProbePackageFixture.ColonBackslashAlias } : Array.Empty<string>();
            Assert.True(pkg.UninventoriedEntryNames.SequenceEqual(expected),
                $"{Path.GetFileName(path)}: lost [{string.Join(", ", pkg.UninventoriedEntryNames)}], expected [{string.Join(", ", expected)}].");
        }
    }

    // The ':' alias's ground truth on Linux: written verbatim (minus the '\') as a file of its own, beside the real entry,
    // which keeps its real bytes.
    [LinuxExtractionFact("ext4 holds ':' verbatim, so content/a:b.bin\\ is written as content/a:b.bin")]
    public void Open_OnLinux_ForAColonBackslashDecoy_WritesItVerbatimAndLosesOnlyIt()
    {
        using var pkg = Open(fixture.ColonBackslashAfterPath);

        Assert.Equal(
            new[] { EntryAliasPackageFixture.ColonAlias, EntryAliasPackageFixture.RenameTarget }.Order(StringComparer.Ordinal),
            ContentFiles(pkg));
        Assert.NotEqual(EntryAliasProbePackageFixture.DecoyContent, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "a_b.bin")));
        Assert.Equal([EntryAliasProbePackageFixture.ColonBackslashAlias], pkg.UninventoriedEntryNames);
    }

    #region Methods: Review 3's backslash shapes (every platform)
    // C1-r3: a NON-empty "x\" is written as the FILE "x", over the real one. After the hook: the decoy is on disk, the
    // backslash entry, whose key the hook already claimed, is lost, and so is the hook, whose file holds the decoy (S8).
    // Measured on both platforms.
    [Fact]
    public void OpenAndScan_ForABackslashDecoyAfterATargetsFile_ReportTheOverwrittenEntryAndTheDecoyLost()
    {
        using (var pkg = Open(fixture.BackslashTargetsAfterPath))
        {
            AssertTheTargetsFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry, EntryAliasProbePackageFixture.BackslashTargets], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.BackslashTargetsAfterPath);
        AssertNotInventoriedRows(scan,
            (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build), (EntryAliasProbePackageFixture.BackslashTargets, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }

    // Before the real name: the backslash entry claims the file first, so the real-named entry (written over it) claims
    // nothing and is lost; and the backslash entry is lost too, because the file it claimed holds the real-named
    // entry's decoy, not its own bytes (S8).
    [Fact]
    public void Open_ForABackslashHookBeforeTheRealName_ReportsBothNamesLost()
    {
        using var pkg = Open(fixture.BackslashTargetsBeforePath);

        AssertTheTargetsFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
        Assert.Equal([EntryAliasProbePackageFixture.BackslashTargets, EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
    }

    [Fact]
    public void Open_ForABackslashDecoyAfterAContentFile_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        using var pkg = Open(fixture.BackslashContentAfterPath);

        Assert.Equal([EntryAliasProbePackageFixture.PayloadEntry], ContentFiles(pkg));
        Assert.Equal(EntryAliasProbePackageFixture.DecoyContent, File.ReadAllText(Path.Combine(pkg.ContentRoot, "content", "payload.bin")));
        Assert.Equal([EntryAliasProbePackageFixture.PayloadEntry, EntryAliasProbePackageFixture.BackslashContent], pkg.UninventoriedEntryNames);
    }

    [Fact]
    public void Open_ForADoubleBackslashDecoyAfterATargetsFile_ReportsTheOverwrittenEntryAndTheDecoyLost()
    {
        using var pkg = Open(fixture.DoubleBackslashTargetsAfterPath);

        AssertTheTargetsFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
        Assert.Equal([EntryAliasPackageFixture.TargetsEntry, EntryAliasProbePackageFixture.DoubleBackslashTargets], pkg.UninventoriedEntryNames);
    }

    // The control Review 3 kept and Review 4 did not break: a SOLE non-empty "x\" is written as "x", claims it, and is
    // inventoried and scanned like any file — its findings are reported, nothing is lost.
    [Fact]
    public void OpenAndScan_ForASoleBackslashTargetsEntry_ScanItAndLoseNothing()
    {
        using (var pkg = Open(fixture.BackslashTargetsSolePath))
        {
            AssertTheTargetsFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.Scripts.Select(s => s.RelativePath));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.BackslashTargetsSolePath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        Assert.Empty(scan.Assemblies);
    }

    // Zero-length "x\" entries (Review 4, N1): no exemption, so they are lost — fail-closed, even where the hook's bytes
    // are the ones on disk and its findings ARE reported (measured).
    [Fact]
    public void OpenAndScan_ForAZeroLengthBackslashEntryAfterATargetsFile_ReportItLostAndStillScanTheHook()
    {
        using (var pkg = Open(fixture.ZeroBackslashAfterPath))
        {
            AssertTheTargetsFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Equal([EntryAliasProbePackageFixture.BackslashTargets], pkg.UninventoriedEntryNames);
        }

        Assert.Contains(Scan(fixture.ZeroBackslashAfterPath).ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
    }

    // Before: the empty "x\" claims the key first and its file holds the hook, not its own zero bytes (S8), and the
    // real name then claims nothing. Both are lost; the hook's findings are still reported.
    [Fact]
    public void OpenAndScan_ForAZeroLengthBackslashEntryBeforeATargetsFile_ReportBothNamesLostAndStillScanTheHook()
    {
        using (var pkg = Open(fixture.ZeroBackslashBeforePath))
        {
            AssertTheTargetsFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Equal([EntryAliasProbePackageFixture.BackslashTargets, EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        Assert.Contains(Scan(fixture.ZeroBackslashBeforePath).ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
    }

    [Fact]
    public void Open_ForASoleZeroLengthBackslashEntry_ReportsItLost()
    {
        using var pkg = Open(fixture.ZeroBackslashSolePath);

        Assert.Empty(BuildFiles(pkg));
        Assert.Equal([EntryAliasProbePackageFixture.BackslashTargets], pkg.UninventoriedEntryNames);
    }

    // Review 4's accepted cost, pinned: an EMPTY "content\" (as old Windows zip tools write directories) beside
    // "content\a.txt" claims no file, so it is lost — fail-closed (0 such names in the 100-package benign corpus).
    [Fact]
    public void OpenAndScan_ForAnEmptyBackslashDirectoryEntry_ReportItLostFailClosed()
    {
        using (var pkg = Open(fixture.BackslashDirectoryPath))
        {
            Assert.Equal(["content/a.txt"], ContentFiles(pkg));
            Assert.Equal([EntryAliasProbePackageFixture.BackslashDirectory], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.BackslashDirectoryPath), (EntryAliasProbePackageFixture.BackslashDirectory, PackageItemRole.Content));
    }
    #endregion

    #region Methods: C3, exact duplicate names whose copies differ (every platform)
    // The C3 headline: the extractor keeps the LAST copy (the decoy), NuGet installs the FIRST (the hook). Since S8 the
    // name is lost because its first occurrence's file fails the content check (it holds the decoy), not because it is
    // a duplicate: byte-identical copies are not lost (EntryAliasingIdenticalDuplicateTests). Lost once, the decoy is
    // what was scanned (0 findings), and the package is incomplete.
    [Fact]
    public void OpenAndScan_ForADuplicateTargetsName_ReportTheNameLostOnce()
    {
        using (var pkg = Open(fixture.DuplicateTargetsPath))
        {
            Assert.Equal(2, pkg.DeclaredEntryNames.Count(n => n == EntryAliasPackageFixture.TargetsEntry));
            AssertTheTargetsFileHolds(pkg, EntryAliasPackageFixture.DecoyTargets);
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(fixture.DuplicateTargetsPath);
        AssertNotInventoriedRows(scan, (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }

    [Fact]
    public void Open_ForADuplicateNonBinaryName_ReportsTheNameLostOnce()
    {
        using var pkg = Open(fixture.DuplicateContentPath);

        Assert.Equal([EntryAliasProbePackageFixture.PayloadEntry], ContentFiles(pkg));
        Assert.Equal([EntryAliasProbePackageFixture.PayloadEntry], pkg.UninventoriedEntryNames);
    }

    // Three copies: still one name lost, one skip row.
    [Fact]
    public void OpenAndScan_ForATriplicateTargetsName_ReportTheNameLostOnceWithOneRow()
    {
        using (var pkg = Open(fixture.TriplicateTargetsPath))
        {
            Assert.Equal(3, pkg.DeclaredEntryNames.Count(n => n == EntryAliasPackageFixture.TargetsEntry));
            Assert.Equal([EntryAliasPackageFixture.TargetsEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.TriplicateTargetsPath), (EntryAliasPackageFixture.TargetsEntry, PackageItemRole.Build));
    }

    // Duplicated AND unclaimed: Windows writes neither copy of a device name, so the name is lost twice over, and is
    // still one row. (Linux writes it, so there it is lost once, as a duplicate: the same one row.)
    [WindowsExtractionFact("Windows cannot create content/CON.txt, so both copies are also unclaimed")]
    public void OpenAndScan_OnWindows_ForADuplicatedDeviceName_ReportItOnceWithOneRow()
    {
        using (var pkg = Open(fixture.DuplicateDevicePath))
        {
            Assert.Empty(ContentFiles(pkg));
            Assert.Equal([EntryAliasPackageFixture.DeviceTextEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.DuplicateDevicePath), (EntryAliasPackageFixture.DeviceTextEntry, PackageItemRole.Content));
    }

    [LinuxExtractionFact("ext4 writes content/CON.txt, so only the duplicate is lost")]
    public void OpenAndScan_OnLinux_ForADuplicatedDeviceName_ReportItOnceWithOneRow()
    {
        using (var pkg = Open(fixture.DuplicateDevicePath))
        {
            Assert.Equal([EntryAliasPackageFixture.DeviceTextEntry], ContentFiles(pkg));
            Assert.Equal([EntryAliasPackageFixture.DeviceTextEntry], pkg.UninventoriedEntryNames);
        }

        AssertNotInventoriedRows(Scan(fixture.DuplicateDevicePath), (EntryAliasPackageFixture.DeviceTextEntry, PackageItemRole.Content));
    }

#if WINDOWS
    [Fact]
    public void ScanPackageCli_ForADuplicateTargetsName_StrictExitsThreeAndNamesIt()
    {
        AssertCliIncompleteNaming(fixture.DuplicateTargetsPath, EntryAliasPackageFixture.TargetsEntry);
    }
#endif
    #endregion

    #region Methods: '/'-terminated entries stay sound (every platform)
    // The one shape the rule does not count (Review 5): measured under every rename, the extractor writes no bytes for a
    // '/'-terminated entry, even a NON-empty one. Beside the real file it changes nothing: the hook's bytes stay on
    // disk, its findings are reported, and nothing is lost.
    [Fact]
    public void OpenAndScan_ForANonEmptySlashTerminatedTwinAfterATargetsFile_LoseNothingAndReportTheHooksFindings()
    {
        AssertHookScannedAndNothingLost(fixture.SlashTwinAfterPath);
    }

    [Fact]
    public void OpenAndScan_ForANonEmptyDriveSegmentSlashTerminatedTwinAfterATargetsFile_LoseNothingAndReportTheHooksFindings()
    {
        AssertHookScannedAndNothingLost(fixture.DriveSlashTwinAfterPath);
    }
    #endregion

    #region Methods: helpers
    // The build directory holds exactly the one real-named file, with these bytes.
    private static void AssertTheTargetsFileHolds(NuGetPackage pkg, string content)
    {
        Assert.Equal([EntryAliasPackageFixture.TargetsEntry], BuildFiles(pkg));
        Assert.Equal(content, File.ReadAllText(Path.Combine(pkg.ContentRoot, "build", "Some.Package.targets")));
    }

    private static void AssertHookScannedAndNothingLost(string nupkgPath)
    {
        using (var pkg = Open(nupkgPath))
        {
            AssertTheTargetsFileHolds(pkg, PackageFixture.MaliciousTargets);
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == EntryAliasPackageFixture.TargetsEntry);
        Assert.Empty(scan.Assemblies);
    }

    // Exactly one file under build/, spelled as the OS kept it (it is also the real entry's name), holding the decoy;
    // the real entry (content check, S8) and the alias (claimed nothing) are lost, in archive order.
    private static void AssertWindowsAliasLost(string nupkgPath, string alias, string fileOnDisk)
    {
        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal([fileOnDisk], BuildFiles(pkg));
            Assert.Equal(EntryAliasPackageFixture.DecoyTargets, File.ReadAllText(Path.Combine(pkg.ContentRoot, fileOnDisk)));
            Assert.Equal([fileOnDisk, alias], pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        AssertNotInventoriedRows(scan, (fileOnDisk, PackageItemRole.Build), (alias, PackageItemRole.Build));
        Assert.Empty(scan.ScriptFindings);
    }
    #endregion

    #region Fields
    private readonly EntryAliasProbePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the reviewer's s11a probe shapes for <see cref="EntryAliasingEscapingEntryTests"/> and
/// <see cref="EntryAliasingBackslashAndDuplicateTests"/> with pure BCL zip (raw names, stored verbatim by
/// <see cref="NupkgBuilder"/>), in the archive order each test depends on. The probe's webhook <c>.targets</c> and
/// <c>projectUrl</c> are replaced by the suite's benign fixtures; the shape names in comments are the probe's.
/// </summary>
public sealed class EntryAliasProbePackageFixture : IDisposable
{
    #region Constructors
    public EntryAliasProbePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias-probe", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        const string targets = EntryAliasPackageFixture.TargetsEntry;
        var hook = Text(PackageFixture.MaliciousTargets);
        var decoy = Text(EntryAliasPackageFixture.DecoyTargets);
        var nuspec = (Name: "PkgProbe.nuspec", Bytes: Nuspec("PkgProbe", projectUrl: null));
        var realManifest = (Name: EntryAliasPackageFixture.RealManifest, Bytes: Nuspec("Real", PackageFixture.NuspecMatchProjectUrl));
        var decoyManifest = Nuspec("Real", projectUrl: null);
        var script = (Name: "tools/plain.ps1", Bytes: Text("Write-Host 'installing'\n"));
        var realContent = Text(RealContent);
        var decoyContent = Text(DecoyContent);

        // Review 5 (C1-r5): escaping decoys. x-esc-root-targets, e-root-targets-before, x-esc-root-nuspec,
        // x-esc-root-content, e-root-sole-targets, x-esc-drive-targets, e-bsroot-targets.
        RootedTargetsAfterPath = Write("RootedTargetsAfter", [nuspec, (targets, hook), (RootedTargets, decoy)]);
        RootedTargetsBeforePath = Write("RootedTargetsBefore", [nuspec, (RootedTargets, decoy), (targets, hook)]);
        RootedManifestAfterPath = Write("RootedManifestAfter", [realManifest, (RootedManifest, decoyManifest), script]);
        RootedManifestBeforePath = Write("RootedManifestBefore", [(RootedManifest, decoyManifest), realManifest, script]);
        RootedContentAfterPath = Write("RootedContentAfter", [nuspec, (PayloadEntry, realContent), (RootedContent, decoyContent)]);
        RootedTargetsSolePath = Write("RootedTargetsSole", [nuspec, (RootedTargets, hook)]);
        DriveTargetsAfterPath = Write("DriveTargetsAfter", [nuspec, (targets, hook), (DriveTargets, decoy)]);
        BackslashRootedTargetsAfterPath = Write("BackslashRootedTargetsAfter", [nuspec, (targets, hook), (BackslashRootedTargets, decoy)]);

        // Review 4 (C1-r4): a rename AND a trailing '\'. q-drv-bs-after, q-drv-bs-nuspec, then the Windows-only q-case-bs-after,
        // q-short-bs-after, q-dot-bs-after, q-sp-bs-after, q-colon-bs-after, q-case-bs2-after.
        DriveBackslashTargetsAfterPath = Write("DriveBackslashTargetsAfter", [nuspec, (targets, hook), (DriveBackslashTargets, decoy)]);
        DriveBackslashManifestAfterPath = Write("DriveBackslashManifestAfter", [realManifest, (DriveBackslashManifest, decoyManifest), script]);
        CaseBackslashAfterPath = Write("CaseBackslashAfter", [nuspec, ("build/some.package.targets", hook), (CaseBackslashAlias, decoy)]);
        ShortBackslashAfterPath = Write("ShortBackslashAfter", [nuspec, (targets, hook), (ShortBackslashAlias, decoy)]);
        DotBackslashAfterPath = Write("DotBackslashAfter", [nuspec, (targets, hook), (DotBackslashAlias, decoy)]);
        SpaceBackslashAfterPath = Write("SpaceBackslashAfter", [nuspec, (targets, hook), (SpaceBackslashAlias, decoy)]);
        ColonBackslashAfterPath = Write("ColonBackslashAfter", [nuspec, (EntryAliasPackageFixture.RenameTarget, realContent), (ColonBackslashAlias, decoyContent)]);
        CaseDoubleBackslashAfterPath = Write("CaseDoubleBackslashAfter", [nuspec, ("build/some.package.targets", hook), (CaseDoubleBackslashAlias, decoy)]);

        // Review 3's backslash shapes. y-bs-file-after/-before, z-bs-content-after, z-bs-2-after, y-bs-file-sole,
        // z-bs-zero-after/-before/-sole, fp-bsdir.
        BackslashTargetsAfterPath = Write("BackslashTargetsAfter", [nuspec, (targets, hook), (BackslashTargets, decoy)]);
        BackslashTargetsBeforePath = Write("BackslashTargetsBefore", [nuspec, (BackslashTargets, hook), (targets, decoy)]);
        BackslashContentAfterPath = Write("BackslashContentAfter", [nuspec, (PayloadEntry, realContent), (BackslashContent, decoyContent)]);
        DoubleBackslashTargetsAfterPath = Write("DoubleBackslashTargetsAfter", [nuspec, (targets, hook), (DoubleBackslashTargets, decoy)]);
        BackslashTargetsSolePath = Write("BackslashTargetsSole", [nuspec, (BackslashTargets, hook)]);
        ZeroBackslashAfterPath = Write("ZeroBackslashAfter", [nuspec, (targets, hook), (BackslashTargets, [])]);
        ZeroBackslashBeforePath = Write("ZeroBackslashBefore", [nuspec, (BackslashTargets, []), (targets, hook)]);
        ZeroBackslashSolePath = Write("ZeroBackslashSole", [nuspec, (BackslashTargets, [])]);
        BackslashDirectoryPath = Write("BackslashDirectory", [nuspec, (BackslashDirectory, []), ("content\\a.txt", Text("hello\n"))]);

        // C3: exact duplicates. x-dup-targets, x-dup-content, y-dup-three, and CON.txt twice.
        DuplicateTargetsPath = Write("DuplicateTargets", [nuspec, (targets, hook), (targets, decoy)]);
        DuplicateContentPath = Write("DuplicateContent", [nuspec, (PayloadEntry, realContent), (PayloadEntry, decoyContent)]);
        TriplicateTargetsPath = Write("TriplicateTargets", [nuspec, (targets, hook), (targets, decoy), (targets, decoy)]);
        DuplicateDevicePath = Write("DuplicateDevice",
            [nuspec, (EntryAliasPackageFixture.DeviceTextEntry, Text("hello\n")), (EntryAliasPackageFixture.DeviceTextEntry, Text("other\n"))]);

        // '/'-terminated controls. y-sl-file-after, r-drv-sl-after.
        SlashTwinAfterPath = Write("SlashTwinAfter", [nuspec, (targets, hook), ("build/Some.Package.targets/", decoy)]);
        DriveSlashTwinAfterPath = Write("DriveSlashTwinAfter", [nuspec, (targets, hook), ("./C:/build/Some.Package.targets/", decoy)]);
    }
    #endregion

    #region Properties
    /// <summary><see cref="EntryAliasPackageFixture.TargetsEntry"/> rooted with '/': escapes, clamped over the real file.</summary>
    public const string RootedTargets = "/build/Some.Package.targets";

    /// <summary>The manifest name rooted with '/'.</summary>
    public const string RootedManifest = "/Real.nuspec";

    /// <summary>A plain content file, YARA's scope.</summary>
    public const string PayloadEntry = "content/payload.bin";

    /// <summary><see cref="PayloadEntry"/> rooted with '/'.</summary>
    public const string RootedContent = "/content/payload.bin";

    /// <summary>The targets name, drive-qualified.</summary>
    public const string DriveTargets = "C:/build/Some.Package.targets";

    /// <summary>The targets name, rooted with '\' and backslash-separated.</summary>
    public const string BackslashRootedTargets = "\\build\\Some.Package.targets";

    /// <summary>A leading drive segment AND a trailing '\' (C1-r4, every platform).</summary>
    public const string DriveBackslashTargets = "./C:/build/Some.Package.targets\\";

    /// <summary>The manifest behind a leading drive segment, with a trailing '\'.</summary>
    public const string DriveBackslashManifest = "./C:/Real.nuspec\\";

    /// <summary>A case alias of "build/some.package.targets" with a trailing '\'.</summary>
    public const string CaseBackslashAlias = "build/Some.Package.targets\\";

    /// <summary>The 8.3 short name of the targets file, with a trailing '\'.</summary>
    public const string ShortBackslashAlias = "build/SOMEPA~1.TAR\\";

    /// <summary>The targets name with a trailing dot, then '\'.</summary>
    public const string DotBackslashAlias = "build/Some.Package.targets.\\";

    /// <summary>The targets name with a trailing space, then '\'.</summary>
    public const string SpaceBackslashAlias = "build/Some.Package.targets \\";

    /// <summary>The ':' alias of <see cref="EntryAliasPackageFixture.RenameTarget"/>, with a trailing '\'.</summary>
    public const string ColonBackslashAlias = "content/a:b.bin\\";

    /// <summary>A case alias of "build/some.package.targets" with TWO trailing backslashes.</summary>
    public const string CaseDoubleBackslashAlias = "build/Some.Package.targets\\\\";

    /// <summary>The real targets name with a trailing '\': written as the FILE "build/Some.Package.targets".</summary>
    public const string BackslashTargets = "build/Some.Package.targets\\";

    /// <summary>The real targets name with two trailing backslashes.</summary>
    public const string DoubleBackslashTargets = "build/Some.Package.targets\\\\";

    /// <summary><see cref="PayloadEntry"/> with a trailing '\'.</summary>
    public const string BackslashContent = "content/payload.bin\\";

    /// <summary>An empty directory entry as old Windows zip tools write it.</summary>
    public const string BackslashDirectory = "content\\";

    /// <summary>The real content file's bytes.</summary>
    public const string RealContent = "real content\n";

    /// <summary>A content decoy's bytes.</summary>
    public const string DecoyContent = "decoy content\n";

    public string RootedTargetsAfterPath { get; }
    public string RootedTargetsBeforePath { get; }
    public string RootedManifestAfterPath { get; }
    public string RootedManifestBeforePath { get; }
    public string RootedContentAfterPath { get; }
    public string RootedTargetsSolePath { get; }
    public string DriveTargetsAfterPath { get; }
    public string BackslashRootedTargetsAfterPath { get; }
    public string DriveBackslashTargetsAfterPath { get; }
    public string DriveBackslashManifestAfterPath { get; }
    public string CaseBackslashAfterPath { get; }
    public string ShortBackslashAfterPath { get; }
    public string DotBackslashAfterPath { get; }
    public string SpaceBackslashAfterPath { get; }
    public string ColonBackslashAfterPath { get; }
    public string CaseDoubleBackslashAfterPath { get; }
    public string BackslashTargetsAfterPath { get; }
    public string BackslashTargetsBeforePath { get; }
    public string BackslashContentAfterPath { get; }
    public string DoubleBackslashTargetsAfterPath { get; }
    public string BackslashTargetsSolePath { get; }
    public string ZeroBackslashAfterPath { get; }
    public string ZeroBackslashBeforePath { get; }
    public string ZeroBackslashSolePath { get; }
    public string BackslashDirectoryPath { get; }
    public string DuplicateTargetsPath { get; }
    public string DuplicateContentPath { get; }
    public string TriplicateTargetsPath { get; }
    public string DuplicateDevicePath { get; }
    public string SlashTwinAfterPath { get; }
    public string DriveSlashTwinAfterPath { get; }

    /// <summary>The C1-r4 packages whose alias only Windows renames onto the real file.</summary>
    public string[] WindowsOnlyBackslashAliasPaths =>
    [
        CaseBackslashAfterPath, ShortBackslashAfterPath, DotBackslashAfterPath, SpaceBackslashAfterPath,
        ColonBackslashAfterPath, CaseDoubleBackslashAfterPath,
    ];
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
        id, "1.0.0", "Silvergun Tests", "Entry-aliasing probe-shape test package.", "net8.0", [], projectUrl: projectUrl));

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
