namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static NativeHeaderBuilder;
using static SingleFileBundleBuilder;

/// <summary>
/// native-binaries-4: YARA over the files unpacked from single-file bundles. <see cref="NuGetPackage.Open"/> lists every
/// extracted bundle entry, of any kind, in <see cref="NuGetPackage.BundleYaraInventory"/> with its escaped
/// <c>host!/entry</c> path; <see cref="PackageScanner.Scan"/> runs a second YARA pass over
/// <see cref="NuGetPackage.BundleRoot"/> with exactly those files and reports its hits at those paths. Each pass fails
/// closed on its own: one failing never costs the other its hits, and the package is Completed only when both are.
/// The fake-backend tests pin the wiring; on net10.0-windows the in-process LibYaraScanner pins a real rule hit and the
/// ADR 0034 deletion semantics through the bundle pass.
/// </summary>
[Collection(nameof(BundleUnpackCollection))]
public sealed class BundleYaraPackageTests : IDisposable
{
    #region Methods: the bundle YARA inventory
    [Fact]
    public void Open_TheBundleYaraInventory_IsEveryExtractedEntry_AtItsEscapedBangPath()
    {
        using var package = Open(AcceptancePackage());

        Assert.Equal(
            new[] { Host + "!/X.dll", Host + "!/nat" + EscapedRlo + "ive.dll", Host + "!/pay" + EscapedRlo + "load.txt", Host + "!/readme.txt" }
                .Order(StringComparer.Ordinal),
            package.BundleYaraInventory.Select(f => f.Reported).Order(StringComparer.Ordinal));
        Assert.All(package.BundleYaraInventory, f => Assert.DoesNotContain(Rlo, f.Reported));
    }

    [Fact]
    public void Open_TheBundleYaraInventory_IsExactlyTheFilesUnderTheBundleRoot()
    {
        using var package = Open(AcceptancePackage());

        Assert.Equal(package.ExtractionDir + "-bundles", package.BundleRoot);
        Assert.Equal(
            Directory.GetFiles(package.BundleRoot, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal),
            package.BundleYaraInventory.Select(f => f.FullPath).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(package.BundleYaraInventory, f => package.YaraInventory.Contains(f.FullPath, StringComparer.Ordinal));
    }

    [Fact]
    public void Open_APackageWithoutABundle_HasAnEmptyBundleYaraInventory()
    {
        using var package = Open(NoBundlePackage());

        Assert.Empty(package.BundleYaraInventory);
    }

    // An entry that failed to extract is a gap row, not a YARA file; the good entry beside it is listed.
    [Fact]
    public void Open_AnEntryThatWasNotExtracted_IsNotInTheBundleYaraInventory()
    {
        var bad = new Entry("bad.dll", new byte[100], Compress: true) { Stored = InvalidDeflate };
        using var package = Open(Package("PkgBundleYaraBad", (Host, Hosted(NativeExe, [new("X.dll", Managed), bad]))));

        Assert.Equal(Host + "!/X.dll", Assert.Single(package.BundleYaraInventory).Reported);
    }

    // A nested bundle is not unpacked, but its own file was extracted, so YARA scans its bytes.
    [Fact]
    public void Open_ANestedBundleFile_IsInTheBundleYaraInventory()
    {
        using var package = Open(Package("PkgBundleYaraNested",
            (Host, Hosted(NativeExe, [new("inner.exe", Hosted(NativeExe, [new("Deep.dll", Managed)]), Compress: true)]))));

        Assert.Equal(Host + "!/inner.exe", Assert.Single(package.BundleYaraInventory).Reported);
    }

    // Duplicate names keep distinct reported paths in the YARA inventory too, so a hit is attributable to one entry.
    [Fact]
    public void Open_DuplicateEntryNames_GetDistinctReportedPathsInTheBundleYaraInventory()
    {
        using var package = Open(Package("PkgBundleYaraDup",
            (Host, Hosted(NativeExe, [new("a.txt", "one"u8.ToArray(), Type: 0), new("a.txt", "two"u8.ToArray(), Type: 0)]))));

        Assert.Equal(
            new[] { Host + "!/a.txt", Host + "!/a.txt#1" },
            package.BundleYaraInventory.Select(f => f.Reported).Order(StringComparer.Ordinal));
    }

    // Review W1: bundle paths are unique against EVERY extracted top-level file, not only assemblies and natives. A
    // top-level TEXT entry literally at "tools/App.exe!/readme.txt" keeps that path; the bundled readme.txt is suffixed.
    [Fact]
    public void Open_ATopLevelTextEntryAtTheBundlePath_KeepsIt_AndTheBundledEntryIsSuffixed()
    {
        using var package = Open(TopLevelClashPackage());

        Assert.Equal(Host + "!/readme.txt#0", Assert.Single(package.BundleYaraInventory).Reported);
    }

    [Fact]
    public void Scan_HitsOnATopLevelTextEntryAndTheBundledEntryAtTheSamePath_HaveDistinctRelativePaths()
    {
        var fake = new RecordingScanner(onCall: (_, _, files) => HitsOn(files, ReadmeBytes, Rule));

        var report = Scan(TopLevelClashPackage(), fake);

        Assert.Equal(
            new[] { Host + "!/readme.txt", Host + "!/readme.txt#0" },
            report.YaraFindings.Select(f => f.RelativePath).Order(StringComparer.Ordinal));
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }

    // Review S5: Unique runs for every extracted entry, so a binary entry after a same-named text entry is suffixed,
    // both as an assembly (IL-only) and as a native binary.
    [Fact]
    public void Open_AnIlOnlyEntryAfterASameNamedTextEntry_IsSuffixed()
    {
        using var package = Open(Package("PkgBundleYaraS5Il",
            (Host, Hosted(NativeExe, [new("X.dll", ReadmeBytes, Type: 0), new("X.dll", Managed, Compress: true)]))));

        Assert.Equal(Host + "!/X.dll#1", Assert.Single(package.Assemblies, a => a.RelativePath.Contains("!/", StringComparison.Ordinal)).RelativePath);
        Assert.Equal(
            new[] { Host + "!/X.dll", Host + "!/X.dll#1" },
            package.BundleYaraInventory.Select(f => f.Reported).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Open_ANativeEntryAfterASameNamedTextEntry_IsSuffixed()
    {
        using var package = Open(Package("PkgBundleYaraS5Native",
            (Host, Hosted(NativeExe, [new("n.dll", ReadmeBytes, Type: 0), new("n.dll", NativeDll, Type: 2)]))));

        Assert.Equal(Host + "!/n.dll#1", Assert.Single(package.NativeBinaries, b => b.RelativePath.Contains("!/", StringComparison.Ordinal)).RelativePath);
    }
    #endregion

    #region Methods: the second pass (fake backend)
    // Review S3: a bundle-pass hit on a path the pass was not handed is reported under "<bundles>/", relative to the
    // bundle root with forward slashes, never at a package-relative path it could alias.
    [Fact]
    public void Scan_ABundleHitOnAnUnlistedPath_IsReportedUnderTheBundlesMarker()
    {
        var fake = new RecordingScanner(onCall: (i, root, _) => i == 1 ? [(Path.Combine(root, "0", "ghost.bin"), Match(Rule))] : []);

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal("<bundles>/0/ghost.bin", Assert.Single(report.YaraFindings).RelativePath);
    }

    [Fact]
    public void Scan_ABundlePackage_MakesASecondScanFilesCall_UnderTheBundleRoot()
    {
        var fake = new RecordingScanner();

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(2, fake.Calls.Count);
        Assert.Equal(fake.Calls[0].Root + "-bundles", fake.Calls[1].Root);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
        Assert.Null(report.YaraUnavailableReason);
    }

    // Exactly the extracted files, of every kind: the IL-only assembly, the native PE, and both text entries.
    [Fact]
    public void Scan_TheSecondCall_ReceivesExactlyTheExtractedBundleFiles()
    {
        var fake = new RecordingScanner();

        Scan(AcceptancePackage(), fake);

        var call = fake.Calls[1];
        Assert.Equal(call.OnDisk.Order(StringComparer.Ordinal), call.Files.Order(StringComparer.Ordinal));
        Assert.Equal(AcceptanceEntries.Length, call.Files.Length);
        Assert.Equal(
            AcceptanceEntries.Select(e => Convert.ToHexString(e.Bytes)).Order(StringComparer.Ordinal),
            call.Contents.Select(Convert.ToHexString).Order(StringComparer.Ordinal));
    }

    // The first pass is unchanged: the extraction inventory, with no bundle file in it.
    [Fact]
    public void Scan_TheFirstCall_ListsNoBundleFile()
    {
        var fake = new RecordingScanner();

        Scan(AcceptancePackage(), fake);

        var bundleRoot = fake.Calls[1].Root + Path.DirectorySeparatorChar;
        Assert.NotEmpty(fake.Calls[0].Files);
        Assert.DoesNotContain(fake.Calls[0].Files, f => f.StartsWith(bundleRoot, StringComparison.Ordinal));
    }

    [Fact]
    public void Scan_APackageWithoutABundle_MakesOneScanFilesCall()
    {
        var fake = new RecordingScanner();

        var report = Scan(NoBundlePackage(), fake);

        Assert.Single(fake.Calls);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }

    // The Available gate runs once, before either pass.
    [Fact]
    public void Scan_AnUnavailableBackend_IsNeverCalled_ForEitherPass()
    {
        var fake = new RecordingScanner(available: false, onCall: HitBundleText(ReadmeBytes));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Empty(fake.Calls);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Empty(report.YaraFindings);
    }

    [Fact]
    public void Scan_AHitOnABundledTextEntry_IsReportedAtItsBangPath_AndCompleted()
    {
        var fake = new RecordingScanner(onCall: HitBundleText(ReadmeBytes));

        var report = Scan(AcceptancePackage(), fake);

        var finding = Assert.Single(report.YaraFindings);
        Assert.Equal((Rule, Host + "!/readme.txt"), (finding.RuleName, finding.RelativePath));
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }

    [Fact]
    public void Scan_AHitOnABundledAssemblyEntry_IsReportedAtItsBangPath()
    {
        var fake = new RecordingScanner(onCall: HitBundleText(Managed));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(Host + "!/X.dll", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }

    // The entry's name carries U+202E; on disk it is a neutral name, and the finding is at the ESCAPED reported path.
    [Fact]
    public void Scan_AHitOnABidiNamedBundleEntry_IsReportedAtTheEscapedPath()
    {
        var fake = new RecordingScanner(onCall: HitBundleText(BidiBytes));

        var report = Scan(AcceptancePackage(), fake);

        var finding = Assert.Single(report.YaraFindings);
        Assert.Equal(Host + "!/pay" + EscapedRlo + "load.txt", finding.RelativePath);
        Assert.DoesNotContain(finding.RelativePath, c => c < ' ' || c == Rlo);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }

    // Enrichment applies to bundle hits exactly as to top-level ones.
    [Fact]
    public void Scan_ABundleHitOnAKnownRule_IsEnriched()
    {
        var fake = new RecordingScanner(onCall: (i, _, files) => i == 1 ? HitsOn(files, ReadmeBytes, RlRuleName) : []);

        var report = Scan(AcceptancePackage(), fake);

        var finding = Assert.Single(report.YaraFindings);
        Assert.Equal(("LIMERAT", "LimeRAT", "MALWARE"), (finding.MalwareFamily, finding.DetectionName, finding.Category));
    }

    // Top-level-only hits are unchanged by the second pass.
    [Fact]
    public void Scan_ATopLevelHitInABundlePackage_IsReportedAtItsPackagePath()
    {
        var fake = new RecordingScanner(onCall: HitTop);

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal("content/notes.txt", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }

    [Fact]
    public void Scan_HitsInBothPasses_AreAllReported()
    {
        var fake = new RecordingScanner(onCall: (i, root, files) => i == 0 ? HitTop(i, root, files) : HitsOn(files, ReadmeBytes, Rule));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(
            new[] { "content/notes.txt", Host + "!/readme.txt" },
            report.YaraFindings.Select(f => f.RelativePath).Order(StringComparer.Ordinal));
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
    }
    #endregion

    #region Methods: each pass fails closed on its own (fake backend)
    [Fact]
    public void Scan_WhenTheBundlePassIsIncompleteWithPartialHits_KeepsBothPassesHits_AndIsUnavailable()
    {
        var fake = new RecordingScanner(onCall: (i, root, files) => i == 0
            ? HitTop(i, root, files)
            : throw new YaraScanIncompleteException(BundleMessage, null, HitsOn(files, ReadmeBytes, Rule)));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(
            new[] { "content/notes.txt", Host + "!/readme.txt" },
            report.YaraFindings.Select(f => f.RelativePath).Order(StringComparer.Ordinal));
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Equal(BundlePrefix + BundleMessage, report.YaraUnavailableReason);
    }

    // A partial hit on a bidi-named entry is escaped like a completed scan's.
    [Fact]
    public void Scan_APartialBundleHitOnABidiNamedEntry_IsReportedAtTheEscapedPath()
    {
        var fake = new RecordingScanner(onCall: (i, _, files) => i == 0
            ? []
            : throw new YaraScanIncompleteException(BundleMessage, null, HitsOn(files, BidiBytes, Rule)));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(Host + "!/pay" + EscapedRlo + "load.txt", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
    }

    [Fact]
    public void Scan_WhenTheBundlePassThrowsANonContractException_KeepsTheTopHits_AndIsUnavailable()
    {
        var fake = new RecordingScanner(onCall: (i, root, files) => i == 0
            ? HitTop(i, root, files)
            : throw new InvalidOperationException("bundle backend failure"));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal("content/notes.txt", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Equal(BundlePrefix + "InvalidOperationException: bundle backend failure", report.YaraUnavailableReason);
    }

    [Fact]
    public void Scan_WhenTheTopPassIsIncomplete_AndTheBundlePassIsClean_KeepsTheBundleHits_AndIsUnavailable()
    {
        var fake = new RecordingScanner(onCall: (i, _, files) => i == 0
            ? throw new YaraScanIncompleteException(TopMessage)
            : HitsOn(files, ReadmeBytes, Rule));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(2, fake.Calls.Count);   // the top pass failing does not skip the bundle pass
        Assert.Equal(Host + "!/readme.txt", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Equal(TopMessage, report.YaraUnavailableReason);
    }

    [Fact]
    public void Scan_WhenTheTopPassThrowsANonContractException_TheBundlePassStillRuns()
    {
        var fake = new RecordingScanner(onCall: (i, _, files) => i == 0
            ? throw new InvalidOperationException("top backend failure")
            : HitsOn(files, ReadmeBytes, Rule));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(Host + "!/readme.txt", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Equal("InvalidOperationException: top backend failure", report.YaraUnavailableReason);
    }

    [Fact]
    public void Scan_WhenBothPassesAreIncomplete_JoinsBothReasons_AndKeepsEveryPartialHit()
    {
        var fake = new RecordingScanner(onCall: (i, root, files) => i == 0
            ? throw new YaraScanIncompleteException(TopMessage, null, HitTop(i, root, files))
            : throw new YaraScanIncompleteException(BundleMessage, null, HitsOn(files, ReadmeBytes, Rule)));

        var report = Scan(AcceptancePackage(), fake);

        Assert.Equal(2, report.YaraFindings.Count);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Equal(TopMessage + "; " + BundlePrefix + BundleMessage, report.YaraUnavailableReason);
    }
    #endregion

#if WINDOWS
    #region Methods: a real engine (LibYaraScanner, net10.0-windows)
    // The HermeticWiper positive control, compressed into the bundle so the host's own bytes cannot match: hits only by
    // the bundle pass, on a non-binary entry, on an IL-only assembly carrying it as overlay, and on a bidi-named entry.
    [Fact]
    public void LibYara_Scan_ARuleMatchInsideABundle_IsReportedAtTheBangPaths_AndCompleted()
    {
        var inner = new LibYaraScanner();
        Assert.True(inner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        var nupkg = Package("PkgBundleYaraReal", (Host, Hosted(NativeExe,
        [
            new("payload.bin", HermeticWiperSample.Bytes, Compress: true, Type: 0),
            new("Evil.dll", [.. Managed, .. HermeticWiperSample.Bytes.AsSpan(2)], Compress: true),
            new("w" + Rlo + "iper.bin", HermeticWiperSample.Bytes, Compress: true, Type: 0),
            new("readme.txt", ReadmeBytes, Type: 0),
        ])));

        var report = Scan(nupkg, inner);

        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
        Assert.Equal(
            new[] { Host + "!/Evil.dll", Host + "!/payload.bin", Host + "!/w" + EscapedRlo + "iper.bin" }.Order(StringComparer.Ordinal),
            report.YaraFindings.Select(f => f.RelativePath).Order(StringComparer.Ordinal));
        Assert.All(report.YaraFindings, f => Assert.Equal(HermeticWiperSample.RuleName, f.RuleName));
        Assert.All(report.YaraFindings, f => Assert.Equal("HERMETICWIPER", f.MalwareFamily));
    }

    // ADR 0034 through the bundle pass: an extracted bundle file deleted before YARA reaches it is unscanned, so the
    // package is Unavailable (prefixed reason), and the real hit in the other bundled file is kept.
    [Fact]
    public void LibYara_Scan_WhenAnExtractedBundleFileIsDeletedBeforeYara_IsUnavailable_AndKeepsTheRealFinding()
    {
        var inner = new LibYaraScanner();
        Assert.True(inner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        var backend = new YaraInventoryPackageScannerTests.DeletingScanner(inner, "vanish.bin");

        var report = Scan(DeletionPackage("PkgBundleYaraVanish"), backend);

        Assert.Equal(1, backend.Deleted);   // deleted in the bundle pass (the top tree has no vanish.bin), so not vacuous
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        var finding = Assert.Single(report.YaraFindings);
        Assert.Equal((HermeticWiperSample.RuleName, Host + "!/payload.bin"), (finding.RuleName, finding.RelativePath));
        var reason = report.YaraUnavailableReason!;
        Assert.StartsWith(BundlePrefix, reason, StringComparison.Ordinal);
        Assert.Contains("1 of them no longer exists (removed after it was listed)", reason, StringComparison.Ordinal);
    }

    // The control: the same package and backend, nothing deleted, is Completed with the finding.
    [Fact]
    public void LibYara_Scan_WhenNoBundleFileIsDeleted_IsCompleted_WithTheFinding()
    {
        var inner = new LibYaraScanner();
        Assert.True(inner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        var backend = new YaraInventoryPackageScannerTests.DeletingScanner(inner, "no-such-file");

        var report = Scan(DeletionPackage("PkgBundleYaraKeep"), backend);

        Assert.Equal(0, backend.Deleted);
        Assert.Equal(YaraScanStatus.Completed, report.YaraScanStatus);
        Assert.Equal(Host + "!/payload.bin", Assert.Single(report.YaraFindings).RelativePath);
        Assert.Null(report.YaraUnavailableReason);
    }

    // Every bundle file gone: Unavailable with nothing found from the bundle, never Completed-and-clean.
    [Fact]
    public void LibYara_Scan_WhenEveryBundleFileIsDeletedBeforeYara_IsUnavailable_NotCompletedAndClean()
    {
        var inner = new LibYaraScanner();
        Assert.True(inner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        var backend = new BundleOnlyDeletingScanner(inner);

        var report = Scan(DeletionPackage("PkgBundleYaraVanishAll"), backend);

        Assert.Equal(2, backend.Deleted);
        Assert.Equal(YaraScanStatus.Unavailable, report.YaraScanStatus);
        Assert.Empty(report.YaraFindings);
        Assert.StartsWith(BundlePrefix, report.YaraUnavailableReason, StringComparison.Ordinal);
    }

    private string DeletionPackage(string id) => Package(id, (Host, Hosted(NativeExe,
    [
        new("payload.bin", HermeticWiperSample.Bytes, Compress: true, Type: 0),
        new("vanish.bin", ReadmeBytes, Type: 0),
    ])));
    #endregion
#endif

    #region Methods: helpers
    public void Dispose() => tree.Dispose();

    private static NuGetPackage Open(string nupkg)
    {
        var open = NuGetPackage.Open(nupkg);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private static PackageCapabilityReport Scan(string nupkg, IYaraScanner scanner)
    {
        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: scanner);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private string Package(string id, params (string Path, byte[] Bytes)[] files)
    {
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(id, "1.0.0", "Silvergun Tests", "native-binaries-4 test package.", "net8.0", []))),
            .. files,
        ]);
        return nupkg;
    }

    // The bundle (an IL-only assembly, a native PE and a text entry whose names carry a bidi override, a plain text
    // entry) beside a top-level text file the fake can hit in the first pass.
    private string AcceptancePackage() => Package("PkgBundleYara", (Host, Hosted(NativeExe, AcceptanceEntries)), ("content/notes.txt", NotesBytes));

    // A bundled readme.txt and a top-level text entry literally named "tools/App.exe!/readme.txt", same bytes.
    private string TopLevelClashPackage() => Package("PkgBundleYaraTopClash",
        (Host, Hosted(NativeExe, [new("readme.txt", ReadmeBytes, Type: 0)])), (Host + "!/readme.txt", ReadmeBytes));

    private string NoBundlePackage() => Package("PkgNoBundleYara", ("content/notes.txt", NotesBytes));

    // Hits every listed file whose bytes are `content`, under `rule`.
    private static IReadOnlyList<(string FullPath, YaraMatch Match)> HitsOn(IReadOnlyList<string> files, byte[] content, string rule) =>
        [.. files.Where(f => File.ReadAllBytes(f).AsSpan().SequenceEqual(content)).Select(f => (f, Match(rule)))];

    private static Func<int, string, IReadOnlyList<string>, IReadOnlyList<(string FullPath, YaraMatch Match)>> HitBundleText(byte[] content) =>
        (i, _, files) => i == 1 ? HitsOn(files, content, Rule) : [];

    private static IReadOnlyList<(string FullPath, YaraMatch Match)> HitTop(int call, string root, IReadOnlyList<string> files) =>
        call == 0 ? HitsOn(files, NotesBytes, Rule) : [];

    private static YaraMatch Match(string rule) => new(rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>());
    #endregion

    #region Nested types
    /// <summary>Records every <see cref="IYaraScanner.ScanFiles"/> call (root, the list, what was on disk under the root,
    /// and the listed files' bytes) and answers with <c>onCall(callIndex, root, files)</c>, which may throw.</summary>
    private sealed class RecordingScanner(
        Func<int, string, IReadOnlyList<string>, IReadOnlyList<(string FullPath, YaraMatch Match)>>? onCall = null,
        bool available = true) : IYaraScanner
    {
        public bool Available => available;

        public List<(string Root, string[] Files, string[] OnDisk, byte[][] Contents)> Calls { get; } = [];

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => [];

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            Calls.Add((rootDir, [.. files], Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories), [.. files.Select(File.ReadAllBytes)]));
            return onCall?.Invoke(Calls.Count - 1, rootDir, files) ?? [];
        }
    }

    /// <summary>Deletes every file under the root on the way into the bundle pass (the root ending "-bundles") only, then
    /// delegates unchanged; the top-level pass is left intact.</summary>
    private sealed class BundleOnlyDeletingScanner(IYaraScanner inner) : IYaraScanner
    {
        public bool Available => inner.Available;

        public int Deleted { get; private set; }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => inner.ScanFile(fullPath);

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            if (rootDir.EndsWith("-bundles", StringComparison.Ordinal))
                foreach (var file in Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories))
                {
                    File.Delete(file);
                    Deleted++;
                }
            return inner.ScanFiles(rootDir, files);
        }
    }
    #endregion

    #region Fields
    private readonly TempTree tree = new();

    private const string Host = "tools/App.exe";
    private const string Rule = "Silvergun_Bundle_Test_Rule";
    private const string BundlePrefix = "unpacked single-file bundle files: ";
    private const string TopMessage = "top-level YARA scan was incomplete.";
    private const string BundleMessage = "bundle YARA scan was incomplete.";

    // A real embedded ReversingLabs rule with family/detection-name/category meta (see YaraScanPackageWiringTests).
    private const string RlRuleName = "ByteCode_MSIL_Backdoor_LimeRAT";

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw, and the backslash-u
    // form YaraPathSafety.Escape renders it as.
    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";

    private static readonly byte[] Managed = ManagedPe.Bytes;
    private static readonly byte[] NativeExe = Pe(MachineAmd64, CharExecutable, pe32Plus: true);
    private static readonly byte[] NativeDll = Pe(MachineAmd64, CharDll | CharExecutable, pe32Plus: true);
    private static readonly byte[] ReadmeBytes = Encoding.UTF8.GetBytes("bundle readme marker\n");
    private static readonly byte[] BidiBytes = Encoding.UTF8.GetBytes("bidi-named bundle entry marker\n");
    private static readonly byte[] NotesBytes = Encoding.UTF8.GetBytes("top-level notes marker\n");

    // A reserved deflate block type (BFINAL=1, BTYPE=11): the inflater rejects it.
    private static readonly byte[] InvalidDeflate = [0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    private static readonly Entry[] AcceptanceEntries =
    [
        new("X.dll", Managed, Compress: true),
        new("nat" + Rlo + "ive.dll", NativeDll, Type: 2),
        new("readme.txt", ReadmeBytes, Type: 0),
        new("pay" + Rlo + "load.txt", BidiBytes, Type: 0),
    ];
    #endregion
}
