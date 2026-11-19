namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Xunit;

using static NativeHeaderBuilder;
using static SingleFileBundleBuilder;

/// <summary>Runs alone (xunit runs a collection that disables parallelization after all the others): these tests write
/// thousands of files (the 4096-entry limit test), and that disk load made the timing-sensitive yara CLI tests fail in
/// full runs.</summary>
[CollectionDefinition(nameof(BundleUnpackCollection), DisableParallelization = true)]
public sealed class BundleUnpackCollection;

/// <summary>
/// native-binaries-3 at the package level: a native PE host carrying a single-file bundle is unpacked by
/// <see cref="NuGetPackage.Open"/>. Entries are classified by CONTENT (an IL-only entry named <c>x.txt</c> is an
/// assembly; a text entry is nothing; a native PE entry is a native binary; an R2R entry is both) at escaped
/// <c>host!/entry</c> paths with the host's role and no TFM, and the IL-only ones are CIL-analysed by
/// <see cref="PackageScanner.Scan"/>. Every entry that is not extracted is a skipped <see cref="AssemblyScanResult"/>
/// listed with the files (not NotInventoried). Managed hosts carrying a bundle header, nested bundles, and bundles past
/// the per-package limit are not unpacked. Plus the real Clowd.Squirrel 2.11.1 package when it is on disk.
/// </summary>
[Collection(nameof(BundleUnpackCollection))]
public sealed class BundleUnpackPackageTests : IDisposable
{
    #region Methods: what an unpacked bundle contributes
    [Fact]
    public void Open_AnIlOnlyBundleEntry_IsAnAssemblyAtTheHostBangPath()
    {
        using var package = Open(AcceptancePackage());

        var assembly = Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/X.dll");
        Assert.Equal(PackageItemRole.Tools, assembly.Role);
        Assert.Null(assembly.TargetFramework);
        Assert.Equal(Sha256(Managed), assembly.Sha256);
        Assert.Equal(Managed, File.ReadAllBytes(assembly.FullPath));
        Assert.StartsWith(Path.Combine(package.ExtractionDir + "-bundles", "0") + Path.DirectorySeparatorChar, assembly.FullPath, StringComparison.Ordinal);
    }

    // IL-only entries belong to the CIL analysis alone, as IL-only .dll files at the top level do.
    [Fact]
    public void Open_AnIlOnlyBundleEntry_IsNotANativeBinary()
    {
        using var package = Open(AcceptancePackage());

        Assert.DoesNotContain(package.NativeBinaries, b => b.RelativePath == Host + "!/X.dll" || b.RelativePath == Host + "!/x.txt");
    }

    // Content, not name: the same IL-only bytes named x.txt are an assembly too.
    [Fact]
    public void Open_AnIlOnlyBundleEntryNamedTxt_IsStillAnAssembly()
    {
        using var package = Open(AcceptancePackage());

        var assembly = Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/x.txt");
        Assert.Equal(Sha256(Managed), assembly.Sha256);
    }

    // The native entry's name carries a bidi override: it is listed as a native binary at an escaped path, with the
    // host's role, its own size and hash, and it is not an assembly.
    [Fact]
    public void Open_ANativeBundleEntry_IsANativeBinaryAtAnEscapedPath()
    {
        using var package = Open(AcceptancePackage());

        var native = Assert.Single(package.NativeBinaries, b => b.RelativePath == Host + "!/nat" + EscapedRlo + "ive.dll");
        Assert.Equal(NativeBinaryFormat.PE, native.Format);
        Assert.Equal(NativeBinaryKind.SharedLibrary, native.Kind);
        Assert.Equal(NativeBinaryCode.Native, native.Code);
        Assert.Equal(PackageItemRole.Tools, native.Role);
        Assert.Equal(NativeDll.Length, native.Size);
        Assert.Equal(Sha256(NativeDll), native.Sha256);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.Contains("ive.dll", StringComparison.Ordinal));
    }

    [Fact]
    public void Open_NoReportedPath_CarriesARawBidiOverride()
    {
        using var package = Open(AcceptancePackage());

        Assert.All(package.Assemblies, a => Assert.DoesNotContain(Rlo, a.RelativePath));
        Assert.All(package.NativeBinaries, b => Assert.DoesNotContain(Rlo, b.RelativePath));
    }

    [Fact]
    public void Open_ATextBundleEntry_IsNeitherAnAssemblyNorANativeBinary()
    {
        using var package = Open(AcceptancePackage());

        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.Contains("readme", StringComparison.Ordinal));
        Assert.DoesNotContain(package.NativeBinaries, b => b.RelativePath.Contains("readme", StringComparison.Ordinal));
    }

    // The host itself is unchanged by unpacking: still the labelled bundle with its count, the whole file's hash.
    [Fact]
    public void Open_TheHost_IsStillALabelledSingleFileBundle_AndNothingIsUnextracted()
    {
        using var package = Open(AcceptancePackage());

        var host = Assert.Single(package.NativeBinaries, b => b.RelativePath == Host);
        Assert.Equal(DotNetHost.SingleFileBundle, host.DotNetHost);
        Assert.Equal(AcceptanceEntries.Length, host.BundledFiles);
        Assert.Equal(Sha256(AcceptanceHost), host.Sha256);
        Assert.Empty(package.UnextractedBundleEntries);
    }

    // Exactly the two IL-only entries are added to the assemblies and exactly the native one to the native binaries.
    [Fact]
    public void Open_TheBundle_AddsExactlyItsCodeEntries()
    {
        using var package = Open(AcceptancePackage());

        Assert.Equal(
            new[] { Host + "!/X.dll", Host + "!/x.txt" },
            package.Assemblies.Select(a => a.RelativePath).Where(p => p.Contains("!/", StringComparison.Ordinal)).Order(StringComparer.Ordinal));
        Assert.Equal(
            new[] { Host + "!/nat" + EscapedRlo + "ive.dll" },
            package.NativeBinaries.Select(b => b.RelativePath).Where(p => p.Contains("!/", StringComparison.Ordinal)));
    }

    // A ReadyToRun entry has both IL and native code: it is analysed AND listed.
    [Fact]
    public void Open_AReadyToRunBundleEntry_IsBothAnAssemblyAndANativeBinary()
    {
        var r2r = ManagedPe.Patch(flags: CorILLibrary | CorStrongNameSigned, managedNativeHeader: (0x2000, 0x50));
        using var package = Open(Package("PkgBundleR2R", (Host, Hosted(NativeExe, [new("R2R.dll", r2r, Compress: true)]))));

        Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/R2R.dll");
        Assert.Equal(NativeBinaryCode.ReadyToRun, Assert.Single(package.NativeBinaries, b => b.RelativePath == Host + "!/R2R.dll").Code);
    }

    // The host's path is escaped too, on both sides of "!/".
    [Fact]
    public void Open_AHostWhoseNameCarriesABidiOverride_IsEscapedInEveryInnerPath()
    {
        using var package = Open(Package("PkgBundleBidiHost", ("tools/A" + Rlo + "pp.exe", Hosted(NativeExe, [new("X.dll", Managed)]))));

        Assert.Single(package.Assemblies, a => a.RelativePath == "tools/A" + EscapedRlo + "pp.exe!/X.dll");
    }

    // The role is the host's: a host under lib/ gives Lib entries.
    [Fact]
    public void Open_TheEntriesRole_IsTheHosts()
    {
        using var package = Open(Package("PkgBundleLibHost", ("lib/net8.0/App.exe", Hosted(NativeExe, [new("X.dll", Managed)]))));

        Assert.Equal(PackageItemRole.Lib, Assert.Single(package.Assemblies, a => a.RelativePath == "lib/net8.0/App.exe!/X.dll").Role);
    }

    // Dispose removes the extracted bundle files and their sibling root.
    [Fact]
    public void Dispose_RemovesTheExtractedBundleFiles()
    {
        var package = Open(AcceptancePackage());
        var extracted = Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/X.dll").FullPath;
        var bundleRoot = package.ExtractionDir + "-bundles";
        Assert.True(File.Exists(extracted));
        Assert.True(Directory.Exists(bundleRoot));

        package.Dispose();

        Assert.False(File.Exists(extracted));
        Assert.False(Directory.Exists(bundleRoot));
        Assert.False(Directory.Exists(package.ExtractionDir));
    }

    // W1: unpacking writes nothing under ExtractionDir (whose tree is the YARA inventory and the content root): every
    // bundled file lives under the sibling <ExtractionDir>-bundles, and the extraction tree holds only package entries.
    [Fact]
    public void Open_UnpackedFiles_LiveOnlyUnderTheSiblingBundleRoot()
    {
        using var package = Open(AcceptancePackage());

        var bundleRoot = package.ExtractionDir + "-bundles" + Path.DirectorySeparatorChar;
        var bundled = package.Assemblies.Where(a => a.RelativePath.Contains("!/", StringComparison.Ordinal)).Select(a => a.FullPath).ToArray();
        Assert.Equal(2, bundled.Length);
        Assert.All(bundled, p => Assert.StartsWith(bundleRoot, p, StringComparison.Ordinal));
        var underExtraction = Directory.GetFiles(package.ExtractionDir, "*", SearchOption.AllDirectories);
        Assert.DoesNotContain(underExtraction, f => f.Contains(Path.DirectorySeparatorChar + ".bundles", StringComparison.Ordinal));
        Assert.Equal(package.YaraInventory.Order(StringComparer.Ordinal), underExtraction.Order(StringComparer.Ordinal));
        // Everything extracted from the bundle (code or not) is under the sibling root: 4 entries, one directory.
        Assert.Equal(4, Directory.GetFiles(Path.Combine(package.ExtractionDir + "-bundles", "0")).Length);
    }
    #endregion

    #region Methods: PackageScanner.Scan
    [Fact]
    public void Scan_TheBundlesIlOnlyEntries_AreCilAnalysed()
    {
        var report = Scan(AcceptancePackage());

        foreach (var path in new[] { Host + "!/X.dll", Host + "!/x.txt" })
        {
            var result = Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == path);
            Assert.NotNull(result.Report);
            Assert.Null(result.SkipReason);
            Assert.True(result.Report!.MethodsAnalyzed > 0, path);
        }
    }

    [Fact]
    public void Scan_TheBundlesNativeEntry_ReachesTheReport()
    {
        var report = Scan(AcceptancePackage());

        Assert.Single(report.NativeBinaries, b => b.RelativePath == Host + "!/nat" + EscapedRlo + "ive.dll");
        Assert.Equal(NativeBinaryScanStatus.Completed, report.NativeBinaryScanStatus);
    }

    [Fact]
    public void Scan_AnUnpackedBundle_AddsNoSkippedResult()
    {
        var report = Scan(AcceptancePackage());

        Assert.DoesNotContain(report.Assemblies, a => a.SkipReason is not null && a.Assembly.RelativePath.Contains("!/", StringComparison.Ordinal));
    }
    #endregion

    #region Methods: entries that are not extracted
    [Fact]
    public void Open_AFailingEntry_IsAnUnextractedRow()
    {
        using var package = Open(FailingEntryPackage());

        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Equal(Host + "!/bad.dll", row.Reported);
        Assert.Equal(PackageItemRole.Tools, row.Role);
        Assert.StartsWith(package.ExtractionDir + Path.DirectorySeparatorChar, row.HostFullPath, StringComparison.Ordinal);
        Assert.EndsWith(Path.Combine("tools", "App.exe"), row.HostFullPath, StringComparison.Ordinal);
        Assert.True(File.Exists(row.HostFullPath));
        Assert.StartsWith("single-file bundle entry was NOT extracted: the entry could not be inflated", row.Reason, StringComparison.Ordinal);
        Assert.Contains("not a clean result", row.Reason, StringComparison.Ordinal);
        // The good entry beside it is still unpacked.
        Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/X.dll");
    }

    // The gap reaches the report as a skipped result, listed with the files (FullPath = the host, so not NotInventoried),
    // which is what makes CompletenessAssessment read the package as not complete.
    [Fact]
    public void Scan_AFailingEntry_IsASkippedResultListedWithTheFiles()
    {
        var report = Scan(FailingEntryPackage());

        var result = Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == Host + "!/bad.dll");
        Assert.Null(result.Report);
        Assert.StartsWith("single-file bundle entry was NOT extracted: ", result.SkipReason, StringComparison.Ordinal);
        Assert.False(result.NotInventoried);
        Assert.EndsWith(Path.Combine("tools", "App.exe"), result.Assembly.FullPath, StringComparison.Ordinal);
        Assert.Equal(string.Empty, result.Assembly.Sha256);
        Assert.Equal(PackageItemRole.Tools, result.Assembly.Role);
        Assert.NotNull(Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == Host + "!/X.dll").Report);
    }

    // A manifest that cannot be read is one row for the whole bundle: "host!/".
    [Fact]
    public void Open_AnUnreadableManifest_IsOneRowForTheWholeBundle()
    {
        // Cut 12 bytes into the manifest: the scanner's count is still plausible, the bundle id is gone.
        var host = Hosted(NativeExe, [new("X.dll", Managed)], truncateManifestAt: 12);
        using var package = Open(Package("PkgBundleCutManifest", (Host, host)));

        Assert.Equal(DotNetHost.SingleFileBundle, Assert.Single(package.NativeBinaries).DotNetHost);
        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Equal(Host + "!/", row.Reported);
        Assert.Contains("the bundle manifest could not be read", row.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.Contains("!/", StringComparison.Ordinal));
    }

    // A raw manifest name in a failure row is escaped like any other inner path.
    [Fact]
    public void Open_AFailingEntryWithABidiName_IsEscapedInItsRow()
    {
        var bad = new Entry("b" + Rlo + "ad.dll", new byte[100], Compress: true) { Stored = InvalidDeflate };
        using var package = Open(Package("PkgBundleBadBidi", (Host, Hosted(NativeExe, [bad]))));

        Assert.Equal(Host + "!/b" + EscapedRlo + "ad.dll", Assert.Single(package.UnextractedBundleEntries).Reported);
    }

    // Bundles past the per-package limit (32) are not unpacked; each one is a whole-bundle row.
    [Fact]
    public void Open_MoreThan32Bundles_TheRestAreWholeBundleRows()
    {
        var hosts = Enumerable.Range(0, 33)
            .Select(i => ($"tools/h{i:D2}.exe", Hosted(NativeExe, [new("n.dll", NativeDll)])))
            .ToArray();
        using var package = Open(Package("PkgBundle33", hosts));

        Assert.Equal(32, package.NativeBinaries.Count(b => b.RelativePath.EndsWith("!/n.dll", StringComparison.Ordinal)));
        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Matches(@"^tools/h\d\d\.exe!/$", row.Reported);
        Assert.Contains("more than 32 bundles in the package", row.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(package.NativeBinaries, b => b.RelativePath == row.Reported + "n.dll");
    }
    #endregion

    #region Methods: what is not unpacked
    // A managed PE that merely carries the signature and a valid bundle header is not a host, so it is not unpacked; the
    // same bundle on a native host in the same package is.
    [Theory]
    [InlineData("tools/payload", "ILOnly")]
    [InlineData("lib/net8.0/r2r.dll", "ReadyToRun")]
    [InlineData("lib/net8.0/mixed.dll", "MixedMode")]
    public void Open_AManagedPeCarryingABundle_IsNotUnpacked(string path, string code)
    {
        var image = Enum.Parse<NativeBinaryCode>(code) switch
        {
            NativeBinaryCode.ReadyToRun => ManagedPe.Patch(flags: CorILLibrary | CorStrongNameSigned, managedNativeHeader: (0x2000, 0x50)),
            NativeBinaryCode.ILOnly => ManagedPe.Patch(flags: CorILOnly, managedNativeHeader: (0, 0)),
            _ => ManagedPe.Patch(flags: CorStrongNameSigned, managedNativeHeader: (0, 0)),
        };
        var entries = new Entry[] { new("Hidden.dll", Managed), new("hidden.so", NativeDll) };
        using var package = Open(Package("PkgBundleManagedHost", (path, Hosted(image, entries)), (Host, Hosted(NativeExe, entries))));

        Assert.Equal(DotNetHost.None, Assert.Single(package.NativeBinaries, b => b.RelativePath == path).DotNetHost);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.StartsWith(path + "!/", StringComparison.Ordinal));
        Assert.DoesNotContain(package.NativeBinaries, b => b.RelativePath.StartsWith(path + "!/", StringComparison.Ordinal));
        Assert.Empty(package.UnextractedBundleEntries);
        Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/Hidden.dll");
    }

    // A bundle inside a bundle is labelled but not unpacked, and (review round 1) that is a coverage gap: one row at the
    // nested bundle's own path. Its contents were never analysed, so the package must not read complete.
    [Fact]
    public void Open_ANestedBundle_IsLabelledNotUnpacked_AndIsAGapRow()
    {
        using var package = Open(NestedBundlePackage());

        var nested = Assert.Single(package.NativeBinaries, b => b.RelativePath == Host + "!/inner.exe");
        Assert.Equal(DotNetHost.SingleFileBundle, nested.DotNetHost);
        Assert.Equal(1, nested.BundledFiles);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.Contains("Deep", StringComparison.Ordinal));
        Assert.DoesNotContain(package.NativeBinaries, b => b.RelativePath.Contains("inner.exe!/", StringComparison.Ordinal));
        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Equal(Host + "!/inner.exe", row.Reported);
        Assert.Equal(PackageItemRole.Tools, row.Role);
        Assert.Contains("nested bundles are not unpacked", row.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Scan_ANestedBundle_IsASkippedResultListedWithTheFiles()
    {
        var report = Scan(NestedBundlePackage());

        var result = Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == Host + "!/inner.exe");
        Assert.Null(result.Report);
        Assert.Contains("nested bundles are not unpacked", result.SkipReason, StringComparison.Ordinal);
        Assert.False(result.NotInventoried);
        Assert.Single(report.NativeBinaries, b => b.RelativePath == Host + "!/inner.exe");
    }

    // W5: a native bundle whose header failed its checks (here it sits BEFORE the signature, which the bundler never
    // writes) cannot be unpacked: it is one whole-bundle row, not a labelled bundle that reads complete.
    [Fact]
    public void Open_ABundleWhoseHeaderPrecedesTheSignature_IsAWholeBundleRow()
    {
        using var package = Open(Package("PkgBundleHeaderFirst", (Host, HeaderBeforeSignature())));

        var host = Assert.Single(package.NativeBinaries);
        Assert.Equal((DotNetHost.SingleFileBundle, (int?)null), (host.DotNetHost, host.BundledFiles));
        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Equal(Host + "!/", row.Reported);
        Assert.Contains("the bundle header could not be located or failed its checks", row.Reason, StringComparison.Ordinal);
    }

    // The same for an implausible header after the signature (major 65).
    [Fact]
    public void Open_ABundleWithAnImplausibleHeader_IsAWholeBundleRow()
    {
        var bytes = Hosted(NativeExe, [new("X.dll", Managed)]);
        BitConverter.GetBytes(65u).CopyTo(bytes, (int)BitConverter.ToInt64(bytes, NativeExe.Length));
        using var package = Open(Package("PkgBundleMajor65", (Host, bytes)));

        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Equal(Host + "!/", row.Reported);
        Assert.Contains("failed its checks", row.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.Contains("!/", StringComparison.Ordinal));
    }

    [Fact]
    public void Scan_ABundleWhoseHeaderPrecedesTheSignature_IsASkippedResult()
    {
        var report = Scan(Package("PkgBundleHeaderFirstScan", (Host, HeaderBeforeSignature())));

        var result = Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == Host + "!/");
        Assert.Null(result.Report);
        Assert.NotNull(result.SkipReason);
        Assert.False(result.NotInventoried);
    }

    // An AppHost (signature, zero offset) has no bundle to unpack.
    [Fact]
    public void Open_AnAppHost_IsNotUnpacked()
    {
        var apphost = NativeExe.Concat(new byte[8]).Concat(Signature).ToArray();
        using var package = Open(Package("PkgAppHostOnly", (Host, apphost)));

        Assert.Equal(DotNetHost.AppHost, Assert.Single(package.NativeBinaries).DotNetHost);
        Assert.DoesNotContain(package.Assemblies, a => a.RelativePath.Contains("!/", StringComparison.Ordinal));
        Assert.Empty(package.UnextractedBundleEntries);
    }
    #endregion

    #region Methods: reported paths are unique (review W3)
    // Two entries with the same name: the first keeps host!/X.dll, the second gets "#<its index>".
    [Fact]
    public void Open_DuplicateNamesInABundle_GetDistinctReportedPaths()
    {
        using var package = Open(Package("PkgBundleDupNames", (Host, Hosted(NativeExe, [new("X.dll", Managed), new("X.dll", Managed)]))));

        Assert.Equal(
            new[] { Host + "!/X.dll", Host + "!/X.dll#1" },
            package.Assemblies.Select(a => a.RelativePath).Where(p => p.Contains("!/", StringComparison.Ordinal)).Order(StringComparer.Ordinal));
    }

    // A top-level package entry literally at tools/App.exe!/X.dll keeps that path; the bundled X.dll is made distinct.
    [Fact]
    public void Open_ATopLevelEntryAtTheBundlePath_KeepsIt_AndTheBundledEntryIsDistinct()
    {
        using var package = Open(Package("PkgBundleTopClash",
            (Host, Hosted(NativeExe, [new("X.dll", Managed)])), (Host + "!/X.dll", Managed)));

        var paths = package.Assemblies.Select(a => a.RelativePath).Where(p => p.Contains("!/", StringComparison.Ordinal)).ToArray();
        Assert.Equal(new[] { Host + "!/X.dll", Host + "!/X.dll#0" }, paths.Order(StringComparer.Ordinal));
        // The unsuffixed path is the top-level entry's own file, not the bundled one.
        Assert.StartsWith(package.ExtractionDir + Path.DirectorySeparatorChar,
            Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/X.dll").FullPath, StringComparison.Ordinal);
        Assert.StartsWith(package.ExtractionDir + "-bundles" + Path.DirectorySeparatorChar,
            Assert.Single(package.Assemblies, a => a.RelativePath == Host + "!/X.dll#0").FullPath, StringComparison.Ordinal);
    }

    // The "#<index>" fallback must itself be unique: an entry literally named "X.dll#1" after two X.dll entries must not
    // share a reported path with the second X.dll.
    [Fact]
    public void Open_AnEntryNamedLikeTheClashSuffix_StillGetsADistinctPath()
    {
        using var package = Open(Package("PkgBundleSuffixClash",
            (Host, Hosted(NativeExe, [new("X.dll", Managed), new("X.dll", Managed), new("X.dll#1", Managed)]))));

        var paths = package.Assemblies.Select(a => a.RelativePath).Where(p => p.Contains("!/", StringComparison.Ordinal)).ToArray();
        Assert.Equal(3, paths.Length);
        Assert.Equal(paths.Length, paths.Distinct(StringComparer.Ordinal).Count());
    }

    // Reported paths are unique across failure rows too: two failing entries with one name are two rows.
    [Fact]
    public void Open_TwoFailingEntriesWithOneName_AreTwoDistinctRows()
    {
        var bad = new Entry("bad.dll", new byte[100], Compress: true) { Stored = InvalidDeflate };
        using var package = Open(Package("PkgBundleDupBad", (Host, Hosted(NativeExe, [bad, bad]))));

        Assert.Equal(
            new[] { Host + "!/bad.dll", Host + "!/bad.dll#1" },
            package.UnextractedBundleEntries.Select(r => r.Reported).Order(StringComparer.Ordinal));
    }
    #endregion

    #region Methods: the package-wide entry limit (review W4)
    // Two bundles of 3000 tiny entries: 4096 are attempted in total, the first bundle whole and 1096 of the second; the
    // remaining 1904 are ONE summary row for the second bundle.
    [Fact]
    public void Open_TwoBundlesOf3000Entries_Attempt4096_AndSummariseTheRest()
    {
        var entries = Enumerable.Range(0, 3000).Select(i => new Entry($"e{i}.txt", [(byte)'t'])).ToArray();
        var bundle = Hosted(NativeExe, entries);
        using var package = Open(Package("PkgBundle6000", ("tools/a.exe", bundle), ("tools/b.exe", bundle)));

        var row = Assert.Single(package.UnextractedBundleEntries);
        Assert.Matches(@"^tools/[ab]\.exe!/$", row.Reported);
        Assert.Contains("1904 entr(ies) past the package-wide limit on bundle entries were not extracted", row.Reason, StringComparison.Ordinal);
        var root = package.ExtractionDir + "-bundles";
        Assert.Equal(4096, Directory.GetFiles(root, "*", SearchOption.AllDirectories).Length);
    }
    #endregion

    #region Methods: InventoryNativeBinaries' bundle hosts
    [Fact]
    public void InventoryNativeBinaries_ReturnsANativeBundleHost_WithItsHeaderOffset()
    {
        var bundle = Hosted(NativeExe, [new("X.dll", Managed)]);
        var full = tree.Write("tools/App.exe", bundle);
        var apphost = tree.Write("tools/Plain.exe", NativeExe.Concat(new byte[8]).Concat(Signature).ToArray());

        var (found, unread, bundles) = Inventory([(full, "tools/App.exe"), (apphost, "tools/Plain.exe")]);

        Assert.Equal(2, found.Count);
        Assert.Empty(unread);
        var host = Assert.Single(bundles);
        Assert.Equal(new BundleHost(full, "tools/App.exe", PackageItemRole.Tools, BitConverter.ToInt64(bundle, NativeExe.Length)), host);
    }

    [Fact]
    public void InventoryNativeBinaries_AManagedPeWithABundleHeader_IsNoBundleHost()
    {
        var image = ManagedPe.Patch(flags: CorILOnly, managedNativeHeader: (0, 0));
        var full = tree.Write("tools/payload", Hosted(image, [new("X.dll", Managed)]));

        var (found, _, bundles) = Inventory([(full, "tools/payload")]);

        Assert.Single(found);
        Assert.Empty(bundles);
    }
    #endregion

    #region Methods: the real Clowd.Squirrel package (read-only, skipped when absent)
    // Measured in the spec: Squirrel.exe and Update.exe bundle 116 and 81 assemblies; every entry extracts.
    [SquirrelPackageFact]
    public void Open_ClowdSquirrel_UnpacksBothBundlesCompletely()
    {
        using var package = Open(SquirrelPackageFactAttribute.PackagePath);

        var perHost = package.Assemblies
            .Where(a => a.RelativePath.Contains("!/", StringComparison.Ordinal))
            .GroupBy(a => a.RelativePath[..a.RelativePath.IndexOf("!/", StringComparison.Ordinal)])
            .ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(2, perHost.Count);
        Assert.Equal(116, Assert.Single(perHost, kv => kv.Key.EndsWith("/Squirrel.exe", StringComparison.Ordinal)).Value);
        Assert.Equal(81, Assert.Single(perHost, kv => kv.Key.EndsWith("/Update.exe", StringComparison.Ordinal)).Value);
        Assert.Empty(package.UnextractedBundleEntries);
    }
    #endregion

    #region Methods: helpers
    public void Dispose() => tree.Dispose();

    private static NuGetPackage Open(string nupkg)
    {
        var open = NuGetPackage.Open(nupkg);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private static PackageCapabilityReport Scan(string nupkg)
    {
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private static (IReadOnlyList<NativeBinary> Found, IReadOnlyList<string> Unread, IReadOnlyList<BundleHost> Bundles) Inventory(
        (string full, string rel)[] files)
    {
        var method = typeof(NuGetPackage).GetMethod("InventoryNativeBinaries", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return ((IReadOnlyList<NativeBinary>, IReadOnlyList<string>, IReadOnlyList<BundleHost>))method.Invoke(null, [files])!;
    }

    private string Package(string id, params (string Path, byte[] Bytes)[] files)
    {
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(id, "1.0.0", "Silvergun Tests", "native-binaries-3 test package.", "net8.0", []))),
            .. files,
        ]);
        return nupkg;
    }

    // The acceptance bundle: an IL-only assembly (compressed), a native PE whose name carries a bidi override (stored),
    // a text file, and the IL-only bytes again under a .txt name.
    private string AcceptancePackage() => Package("PkgBundleAcceptance", (Host, AcceptanceHost));

    // A good IL-only entry and one whose deflate data is invalid.
    private string FailingEntryPackage() => Package("PkgBundleBadEntry",
        (Host, Hosted(NativeExe, [new("X.dll", Managed), new("bad.dll", new byte[100], Compress: true) { Stored = InvalidDeflate }])));

    // A bundle nested in a bundle: the inner one holds an IL-only Deep.dll.
    private string NestedBundlePackage() => Package("PkgBundleNested",
        (Host, Hosted(NativeExe, [new("inner.exe", Hosted(NativeExe, [new("Deep.dll", Managed)]), Compress: true)])));

    // A native host whose overlay is [plausible bundle header][8-byte offset -> that header][signature]: the scanner labels
    // it a bundle (non-zero offset) but refuses the header, since the bundler always writes it after the signature.
    private static byte[] HeaderBeforeSignature()
    {
        var header = new byte[16];
        BitConverter.GetBytes(6u).CopyTo(header, 0);
        BitConverter.GetBytes(0u).CopyTo(header, 4);
        BitConverter.GetBytes(3).CopyTo(header, 8);
        return [.. NativeExe, .. header, .. BitConverter.GetBytes((long)NativeExe.Length), .. Signature, .. new byte[64]];
    }

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    #endregion

    #region Fields
    private readonly TempTree tree = new();

    private const string Host = "tools/App.exe";

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw.
    private const char Rlo = (char)0x202E;

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries that sequence.
    private const string EscapedRlo = @"\" + "u202e";

    private static readonly byte[] Managed = ManagedPe.Bytes;
    private static readonly byte[] NativeExe = Pe(MachineAmd64, CharExecutable, pe32Plus: true);
    private static readonly byte[] NativeDll = Pe(MachineAmd64, CharDll | CharExecutable, pe32Plus: true);

    // A reserved deflate block type (BFINAL=1, BTYPE=11): the inflater rejects it.
    private static readonly byte[] InvalidDeflate = [0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    private static readonly Entry[] AcceptanceEntries =
    [
        new("X.dll", Managed, Compress: true),
        new("nat" + Rlo + "ive.dll", NativeDll, Type: 2),
        new("readme.txt", Encoding.UTF8.GetBytes("Just a readme.\n"), Type: 0),
        new("x.txt", Managed, Type: 0),
    ];

    private static readonly byte[] AcceptanceHost = Hosted(NativeExe, AcceptanceEntries);
    #endregion
}

/// <summary>Skips unless the benign corpus's Clowd.Squirrel 2.11.1 package is on disk (read-only use; untrusted data).</summary>
internal sealed class SquirrelPackageFactAttribute : FactAttribute
{
    public SquirrelPackageFactAttribute()
    {
        if (!File.Exists(PackagePath))
            Skip = $"{PackagePath} is not present.";
    }

    internal static string PackagePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Silvergun", "benign-corpus", "packages", "Clowd.Squirrel.2.11.1.nupkg");
}
