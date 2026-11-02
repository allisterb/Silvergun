namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// The package-level half of ADR 0030's sixth instance: <b>a declared entry that never reached the inventory is
/// coverage we did not deliver, and it must be impossible for it to read as clean.</b>
///
/// <para>Three distinct outcomes are pinned here, and keeping them apart is the whole point:</para>
/// <list type="number">
/// <item><b>Inventoried.</b> The entry is analysed. <c>./lib/…</c> and <c>content/../…</c> now land here (they used
/// to be dropped silently — a second, pre-existing loss found while fixing the first).</item>
/// <item><b>Uninventoried.</b> The entry is contained, but no extracted file exists for it, because the OS or the
/// extractor would not create one. It appears in <see cref="NuGetPackage.UninventoriedEntryNames"/>, gets its own
/// warning, and <see cref="PackageScanner"/> turns it into a skipped <see cref="AssemblyScanResult"/>.</item>
/// <item><b>Zip-slip excluded.</b> The entry escapes the content root, so it is never inventoried (ADR 0008) and the
/// FILE the extractor clamped into the root is skipped with a <i>different</i> warning — containment working, never
/// confusable with (2). Since <c>tasks/entry-aliasing-coverage.md</c> "Review 5" (C1-r5) the escaping ENTRY is also
/// reported lost, as in (2): its bytes were clamped inside the root, last-wins, over whatever file shares that path,
/// while NuGet installs the first copy. So a zip-slip package now reads incomplete; the two warnings stay distinct,
/// one about the clamped file and one about the declared entry.</item>
/// </list>
///
/// <para><b>Platform divergence is pinned, not hidden.</b> Whether a contained entry can be written to disk is an
/// OS question: Windows refuses reserved DOS device names, case-only duplicates and control characters in file
/// names, and RecursiveExtractor then skips or renames the entry while still returning <c>Ok</c> (measured
/// 2026-08-22, both platforms). So <c>lib/net8.0/COM1.dll</c> is outcome (2) on Windows and outcome (1) on Linux,
/// and both are asserted, by the paired <see cref="WindowsExtractionFactAttribute"/>/
/// <see cref="LinuxExtractionFactAttribute"/> gates. The NUL-bearing entry name is outcome (2) on <b>both</b>
/// platforms (also measured), which is what lets the escaping, the synthesized skip result and the warning text be
/// asserted without a platform gate at all.</para>
/// </summary>
public sealed class UninventoriedEntryTests : IClassFixture<UninventoriedPackageFixture>
{
    #region Constructors
    public UninventoriedEntryTests(UninventoriedPackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — outcome 1: the two containment-key readings (the second, pre-existing loss)
    // "./lib/net8.0/Dotted.dll" and "content/../Folded.dll" are both contained, and the extractor writes them to
    // "lib/net8.0/Dotted.dll" and "content/Folded.dll" — it DROPS the ".." segment where resolving it would give
    // "Folded.dll" at the root. Containment therefore accepts an extracted file under either lexical reading.
    // Without that, both files are extracted, never inventoried and never IL-analysed: measured on both platforms
    // before this test was written, and asserted on both here.
    [Fact]
    public void Open_ForDotSlashAndDotDotFoldedEntryNames_InventoriesBothOnEveryPlatform()
    {
        using var pkg = Open(fixture.FoldedPath);

        Assert.Contains(pkg.Assemblies, a => a.RelativePath == "lib/net8.0/Dotted.dll");
        Assert.Contains(pkg.Assemblies, a => a.RelativePath == "content/Folded.dll");
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    // ...and neither of those names escapes the content root, on either platform. This is the containment half of
    // the same statement: the entries are inventoried because they are CONTAINED, not because some gate was
    // loosened. A ".." that walks back inside the root is not zip slip.
    [Fact]
    public void Open_ForTheFoldedPackage_NoDeclaredFileEntryEscapesTheContentRoot()
    {
        using var pkg = Open(fixture.FoldedPath);

        Assert.All(
            pkg.DeclaredEntryNames.Where(n => !n.EndsWith('/')),
            n => Assert.False(NuGetPackage.EscapesContentRoot(n), $"'{n}' must be contained."));
    }

    // Both files are genuinely analysed end to end, not merely listed: the inventory entry is worth nothing if the
    // capability analysis never runs over it.
    [Fact]
    public void Scan_ForDotSlashAndDotDotFoldedEntryNames_AnalysesBothWithNoSkipReason()
    {
        var scan = PackageScanner.Scan(fixture.FoldedPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        foreach (var rel in new[] { "lib/net8.0/Dotted.dll", "content/Folded.dll" })
        {
            var result = Assert.Single(scan.Value.Assemblies, a => a.Assembly.RelativePath == rel);
            Assert.Null(result.SkipReason);
            Assert.NotNull(result.Report);
        }
    }
    #endregion

    #region Methods — outcome 2: the device name (the divergence, pinned on both sides)
    // Windows: RecursiveExtractor cannot create "COM1.dll" and silently returns Ok, so the entry is contained but
    // never inventoried. Before the fix it was dropped as if it had escaped, and NOTHING said so — the run reported
    // clean. Now it is absent from Assemblies AND named in UninventoriedEntryNames, which is what makes the report
    // say coverage was lost.
    [WindowsExtractionFact("Windows cannot create a file named after a reserved DOS device, so the extractor skips it")]
    public void Open_OnWindows_ForADeviceNamedEntry_ReportsItUninventoriedAndLeavesItOutOfAssemblies()
    {
        using var pkg = Open(fixture.DevicePath);

        Assert.Contains(UninventoriedPackageFixture.DeviceEntry, pkg.UninventoriedEntryNames);
        Assert.DoesNotContain(pkg.Assemblies, a => a.RelativePath == UninventoriedPackageFixture.DeviceEntry);
        // The ordinary assembly alongside it is unaffected — one lost entry must not cost the rest of the package.
        Assert.Contains(pkg.Assemblies, a => a.RelativePath == UninventoriedPackageFixture.OrdinaryEntry);
    }

    // Linux: the same package extracts completely, so the payload IS inventoried and there is no coverage loss to
    // report. This is the assertion that says the Windows result above is an OS limitation being disclosed, not
    // Silvergun deciding to skip a file.
    [LinuxExtractionFact("Linux has no reserved device names, so the very same entry extracts and is analysed")]
    public void Open_OnLinux_ForADeviceNamedEntry_InventoriesItAndReportsNoCoverageLoss()
    {
        using var pkg = Open(fixture.DevicePath);

        Assert.Contains(pkg.Assemblies, a => a.RelativePath == UninventoriedPackageFixture.DeviceEntry);
        Assert.Contains(pkg.Assemblies, a => a.RelativePath == UninventoriedPackageFixture.OrdinaryEntry);
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    // The Linux end-to-end statement: the device-named payload is not just inventoried, it is ANALYSED. The
    // fixture assembly carries known SensitiveOps findings, so "did we look inside it?" is answerable.
    [LinuxExtractionFact("only Linux can hold a file named COM1.dll, so only there can it be analysed")]
    public void Scan_OnLinux_ForADeviceNamedEntry_ProducesARealCapabilityReportForIt()
    {
        var scan = PackageScanner.Scan(fixture.DevicePath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        var device = Assert.Single(
            scan.Value.Assemblies, a => a.Assembly.RelativePath == UninventoriedPackageFixture.DeviceEntry);
        Assert.Null(device.SkipReason);
        Assert.NotNull(device.Report);
    }

    // The Windows twin of the above, at the scanner: a synthesized skip result, so completeness cannot claim
    // complete. Role and TFM are derived from the entry name exactly like an inventoried file's, and the file
    // fields are empty BY CONSTRUCTION — there is no file.
    [WindowsExtractionFact("only Windows produces an uninventoried entry for a reserved device name")]
    public void Scan_OnWindows_ForADeviceNamedEntry_SynthesizesASkipResultNamingIt()
    {
        var scan = PackageScanner.Scan(fixture.DevicePath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        var lost = Assert.Single(
            scan.Value.Assemblies, a => a.Assembly.RelativePath == UninventoriedPackageFixture.DeviceEntry);
        AssertLostCoverageResult(lost, expectedRole: PackageItemRole.Lib, expectedTfm: "net8.0");
    }
    #endregion

    #region Methods — outcome 2 without a platform gate: a name NEITHER filesystem will write
    // An embedded NUL is refused by Windows AND by Linux (measured 2026-08-22: RecursiveExtractor renames it to
    // "nul_byte"-style on both), so this package produces the "declared but not inventoried" outcome everywhere.
    // That is what makes the rest of this region a cross-platform assertion rather than a Windows one.
    [Fact]
    public void Open_ForAnEntryNoFilesystemCanWrite_ReportsItUninventoriedOnEveryPlatform()
    {
        using var pkg = Open(fixture.HostileNamePath);

        var lost = Assert.Single(pkg.UninventoriedEntryNames);
        Assert.Equal(UninventoriedPackageFixture.HostileEntryEscaped, lost);
        Assert.Contains(pkg.Assemblies, a => a.RelativePath == UninventoriedPackageFixture.OrdinaryEntry);
    }

    // ADR 0031 decision 4 at this boundary: the name is attacker-authored, so what we PUBLISH is the escaped form —
    // in the property, in the warning, and (see the CLI suite) in the report. The raw name carries a newline and a
    // NUL; either one raw in a log line is a forged line, which is the ADR 0029 attack.
    [Fact]
    public void Open_ForAnUninventoriedEntryWithControlCharacters_PublishesOnlyTheEscapedName()
    {
        var (pkg, warnings) = OpenCapturingWarnings(fixture.HostileNamePath);
        using var _ = pkg;

        var lost = Assert.Single(pkg.UninventoriedEntryNames);
        Assert.Equal(UninventoriedPackageFixture.HostileEntryEscaped, lost);
        AssertNoRawControlCharacter(lost, "UninventoriedEntryNames");

        var warning = CoverageLostWarning(warnings, UninventoriedPackageFixture.HostileEntryEscaped);
        Assert.Contains(UninventoriedPackageFixture.HostileEntryEscaped, warning, StringComparison.Ordinal);
        AssertNoRawControlCharacter(warning, "the coverage-loss warning");
    }

    // The scanner half, cross-platform: one synthesized skip result per uninventoried entry, carrying the DECLARED
    // (escaped) name, a non-null SkipReason, no CapabilityReport, and role/TFM derived from the name.
    [Fact]
    public void Scan_ForAnUninventoriedEntry_SynthesizesOneSkipResultCarryingTheDeclaredName()
    {
        var scan = PackageScanner.Scan(fixture.HostileNamePath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        var lost = Assert.Single(
            scan.Value.Assemblies, a => a.Assembly.RelativePath == UninventoriedPackageFixture.HostileEntryEscaped);
        AssertLostCoverageResult(lost, expectedRole: PackageItemRole.Lib, expectedTfm: "net8.0");

        // ...alongside the ordinary assembly, which is still fully analysed.
        var ordinary = Assert.Single(
            scan.Value.Assemblies, a => a.Assembly.RelativePath == UninventoriedPackageFixture.OrdinaryEntry);
        Assert.Null(ordinary.SkipReason);
        Assert.NotNull(ordinary.Report);
    }

    // Nothing that reaches the report carries a raw control character, in ANY field of ANY result — the report is
    // JSON and terminal output, and this is where an attacker-authored name would land in both.
    [Fact]
    public void Scan_ForAnUninventoriedEntryWithControlCharacters_EmitsNoRawControlCharacterInTheReport()
    {
        var scan = PackageScanner.Scan(fixture.HostileNamePath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        foreach (var result in scan.Value.Assemblies)
        {
            AssertNoRawControlCharacter(result.Assembly.RelativePath, nameof(PackageAssembly.RelativePath));
            AssertNoRawControlCharacter(result.SkipReason ?? string.Empty, nameof(AssemblyScanResult.SkipReason));
        }
    }
    #endregion

    #region Methods — outcome 3: zip slip stays excluded, and says something DIFFERENT
    // ADR 0008 is intact: an entry named "../../<file>" is dropped from the contained set, the file the extractor
    // clamped into the archive root is skipped, and nothing about it is inventoried.
    [Fact]
    public void Open_ForAZipSlipEntry_StillExcludesItFromTheInventory()
    {
        using var pkg = Open(fixture.SlipPath);

        Assert.DoesNotContain(pkg.Assemblies, a => a.RelativePath.Contains(fixture.SlipFileName, StringComparison.Ordinal));
        Assert.Contains(pkg.Assemblies, a => a.RelativePath == UninventoriedPackageFixture.OrdinaryEntry);
        Assert.False(
            File.Exists(Path.GetFullPath(Path.Combine(pkg.ExtractionDir, fixture.SlipEntry))),
            "the zip-slip entry escaped the extraction directory.");
    }

    // The distinction this fix added, and the one that must never blur. The clamped on-disk FILE gets "no contained
    // package entry declares this path" — containment WORKING. A declared ENTRY that was lost gets "was NOT
    // inventoried … coverage NOT delivered" — analysis that did not happen. The old code emitted only the first
    // message for both situations, which is precisely why a payload named COM1.dll read as a zip-slip drop.
    //
    // Since "Review 5" (tasks/entry-aliasing-coverage.md, C1-r5) a zip-slip package emits BOTH, about two different
    // things: the clamped file (named by its on-disk relative path) and the escaping entry (named as declared, with its
    // "../../"), which is now lost coverage. Deliberately flipped from "no coverage-lost warning, nothing lost".
    [Fact]
    public void Open_ForAZipSlipEntry_WarnsThatNoEntryDeclaresTheClampedFile_AndThatTheEntryWasLost()
    {
        var (pkg, warnings) = OpenCapturingWarnings(fixture.SlipPath);
        using var _ = pkg;

        Assert.Contains(warnings, w =>
            w.Contains(ClampedPhrase, StringComparison.Ordinal) &&
            w.Contains(fixture.SlipFileName, StringComparison.Ordinal) &&
            !w.Contains(fixture.SlipEntry, StringComparison.Ordinal));
        CoverageLostWarning(warnings, fixture.SlipEntry);
        Assert.Equal([fixture.SlipEntry], pkg.UninventoriedEntryNames);
    }

    // The two messages, side by side, must not be confusable: neither contains the other's distinguishing phrase.
    // They mean different things — one is a guard firing on a file, the other is a hole in coverage. Since Review 5 the
    // zip-slip package itself carries one of each (the file and the entry), so it is checked on both; the NUL-named
    // entry's warning is the coverage-lost message with no zip slip anywhere near it.
    [Fact]
    public void TheClampedAndCoverageLostWarnings_ShareNoDistinguishingPhrase()
    {
        var slip = OpenCapturingWarnings(fixture.SlipPath);
        using var slipPackage = slip.Package;
        var hostile = OpenCapturingWarnings(fixture.HostileNamePath);
        using var hostilePackage = hostile.Package;

        var naming = slip.Warnings.Where(w => w.Contains(fixture.SlipFileName, StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, naming.Length);
        var clamped = Assert.Single(naming, w => !w.Contains(fixture.SlipEntry, StringComparison.Ordinal));
        var slipLost = Assert.Single(naming, w => w.Contains(fixture.SlipEntry, StringComparison.Ordinal));
        var hostileLost = CoverageLostWarning(hostile.Warnings, UninventoriedPackageFixture.HostileEntryEscaped);

        Assert.Contains(ClampedPhrase, clamped, StringComparison.Ordinal);
        Assert.DoesNotContain(CoverageLostPhrase, clamped, StringComparison.Ordinal);
        foreach (var lost in new[] { slipLost, hostileLost })
        {
            Assert.Contains(CoverageLostPhrase, lost, StringComparison.Ordinal);
            Assert.DoesNotContain(ClampedPhrase, lost, StringComparison.Ordinal);
        }
    }

    // The scanner half. The escaping ENTRY is one not-inventoried row (no file, no report, role Other: ".." is no role
    // segment) and the clamped FILE is no row at all — it is never inventoried, so never analysed under any name.
    // Deliberately flipped by "Review 5" (C1-r5): this used to assert NO skip row, calling one an over-firing guard; the
    // measurement showed the entry's bytes land inside the root over a real file of that name, so its presence is
    // coverage not delivered and every PathTraversal package reads incomplete — the accepted cost.
    [Fact]
    public void Scan_ForAZipSlipEntry_SynthesizesOneNotInventoriedRowForTheEntryAndNoneForTheClampedFile()
    {
        var scan = PackageScanner.Scan(fixture.SlipPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);

        var row = Assert.Single(
            scan.Value.Assemblies,
            a => a.Assembly.RelativePath.Contains(fixture.SlipFileName, StringComparison.Ordinal));
        Assert.Equal(fixture.SlipEntry, row.Assembly.RelativePath);
        Assert.True(row.NotInventoried);
        AssertLostCoverageResult(row, expectedRole: PackageItemRole.Other, expectedTfm: null);

        var ordinary = Assert.Single(
            scan.Value.Assemblies, a => a.Assembly.RelativePath == UninventoriedPackageFixture.OrdinaryEntry);
        Assert.Null(ordinary.SkipReason);
        Assert.NotNull(ordinary.Report);
    }
    #endregion

    #region Methods — outcome 2 again: the case-only collision (Windows)
    // NTFS holds one of "lib/A.dll" and "lib/a.dll", so the extractor silently overwrites — the file scanned is not
    // the file shipped, and the OTHER entry is analysis that never happened. Which of the two survives is the
    // extractor's business; that exactly one does, and the other is reported, is ours.
    [WindowsExtractionFact("NTFS is case-insensitive, so one of two case-only-distinct entries is overwritten")]
    public void Open_OnWindows_ForACaseOnlyCollision_InventoriesOneAndReportsTheOtherUninventoried()
    {
        using var pkg = Open(fixture.CaseOnlyPath);

        var names = UninventoriedPackageFixture.CaseOnlyEntries;
        var inventoried = pkg.Assemblies.Select(a => a.RelativePath).Where(names.Contains).ToArray();
        var lost = pkg.UninventoriedEntryNames.Where(names.Contains).ToArray();

        Assert.Single(inventoried);
        Assert.Single(lost);
        Assert.NotEqual(inventoried[0], lost[0]);
    }

    // Linux keeps both, so nothing is lost — the same package, the same code, a different filesystem.
    [LinuxExtractionFact("ext4 is case-sensitive, so both case-only-distinct entries are written and analysed")]
    public void Open_OnLinux_ForACaseOnlyCollision_InventoriesBoth()
    {
        using var pkg = Open(fixture.CaseOnlyPath);

        Assert.Equal(
            UninventoriedPackageFixture.CaseOnlyEntries.Order(StringComparer.Ordinal),
            pkg.Assemblies.Select(a => a.RelativePath).Order(StringComparer.Ordinal));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods — helpers
    private static NuGetPackage Open(string nupkgPath)
    {
        var open = NuGetPackage.Open(nupkgPath);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    // The warnings the single Open call logs, through the shared WarningCapture: Runtime.logger is process-global, and
    // this class used to swap it in and out itself, which could displace a YARA test's capture running in parallel (and
    // be displaced by it). The capture is scoped to this test's own flow, so another test's warnings cannot land in it.
    private static (NuGetPackage Package, IReadOnlyList<string> Warnings) OpenCapturingWarnings(string nupkgPath)
    {
        using var capture = new WarningCapture();
        return (Open(nupkgPath), capture.Warnings);
    }

    // Everything an uninventoried entry's synthesized result must say: no analysis, a reason that says so, and the
    // same role/TFM derivation an inventoried file gets — with empty file fields, because there is no file.
    private static void AssertLostCoverageResult(
        AssemblyScanResult result, PackageItemRole expectedRole, string? expectedTfm)
    {
        Assert.Null(result.Report);
        Assert.NotNull(result.SkipReason);
        Assert.Contains("NOT inventoried", result.SkipReason, StringComparison.Ordinal);
        Assert.Equal(expectedRole, result.Assembly.Role);
        Assert.Equal(expectedTfm, result.Assembly.TargetFramework);
        Assert.Equal(string.Empty, result.Assembly.FullPath);
        Assert.Equal(string.Empty, result.Assembly.Sha256);
    }

    // The one coverage-loss warning for a given (escaped) entry name. Filtered by the name as well as the phrase, so
    // the assertion names exactly the entry it is about even though the capture holds every warning Open logged.
    private static string CoverageLostWarning(IEnumerable<string> warnings, string escapedEntryName) =>
        Assert.Single(
            warnings,
            w => w.Contains(CoverageLostPhrase, StringComparison.Ordinal)
              && w.Contains(escapedEntryName, StringComparison.Ordinal));

    private static void AssertNoRawControlCharacter(string text, string what)
    {
        var offender = text.FirstOrDefault(c => c < ' ' || c == (char)0x7F);
        Assert.True(offender == '\0' && !text.Contains('\0'), $"{what} carried raw U+{(int)offender:X4}.");
    }
    #endregion

    #region Fields
    // The phrase unique to "the extractor put a file here that no contained entry declares" (containment working).
    private const string ClampedPhrase = "no contained package entry declares this path";

    // The phrase unique to "this declared entry was never written as a file of its own, so nothing looked at its
    // bytes" (coverage lost) — contained or, since Review 5, escaping.
    private const string CoverageLostPhrase = "was NOT inventoried";

    private readonly UninventoriedPackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="UninventoriedEntryTests"/> with pure BCL zip (see
/// <see cref="NupkgBuilder"/>) — no NuGet client, no network. Every payload is a copy of the real fixture assembly,
/// so an inventoried entry produces a genuine capability report and "was it actually analysed?" is answerable.
/// </summary>
public sealed class UninventoriedPackageFixture : IDisposable
{
    #region Constructors
    public UninventoriedPackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-uninventoried", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var fixtureBytes = File.ReadAllBytes(typeof(Shapes).Assembly.Location);

        // A reserved DOS device name alongside an ordinary assembly: the ADR 0030 sixth-instance package.
        DevicePath = Write("PkgDevice", [], [(OrdinaryEntry, fixtureBytes), (DeviceEntry, fixtureBytes)]);

        // The two ".."/"." readings the extractor and a resolver disagree about.
        FoldedPath = Write("PkgFolded", [],
            [("./lib/net8.0/Dotted.dll", fixtureBytes), ("content/../Folded.dll", fixtureBytes)]);

        // A name NEITHER filesystem will write verbatim: an embedded NUL (plus an LF, so "no raw CR/LF anywhere"
        // is a statement about a name that actually contains one).
        HostileNamePath = Write("PkgHostileName", [], [(OrdinaryEntry, fixtureBytes), (HostileEntry, fixtureBytes)]);

        // Two entries differing only in case.
        CaseOnlyPath = Write("PkgCaseOnly", [], [(CaseOnlyEntries[0], fixtureBytes), (CaseOnlyEntries[1], fixtureBytes)]);

        // Zip slip. The guid keeps the traversal target unique so a regression cannot collide on a stray file.
        SlipFileName = $"silvergun-uninv-slip-{Guid.NewGuid():N}.dll";
        SlipEntry = "../../" + SlipFileName;
        SlipPath = Write("PkgSlip", [(OrdinaryEntry, fixtureBytes)], [(SlipEntry, fixtureBytes)]);
    }
    #endregion

    #region Properties
    /// <summary>An ordinary lib assembly present in most of these packages — one lost entry must not cost the rest.</summary>
    public const string OrdinaryEntry = "lib/net8.0/Ordinary.dll";

    /// <summary>The reserved-DOS-device payload name: <c>lib/net8.0/COM1.dll</c>.</summary>
    public const string DeviceEntry = "lib/net8.0/COM1.dll";

    /// <summary>A declared name with an LF and a NUL in it — refused by both filesystems, so lost on both.</summary>
    public const string HostileEntry = "lib/net8.0/pay\nlo\0ad.dll";

    /// <summary>What <see cref="HostileEntry"/> must look like everywhere it is published (escaped, per ADR 0031 decision 4).</summary>
    public const string HostileEntryEscaped = @"lib/net8.0/pay\nlo\x00ad.dll";

    /// <summary>Two entries equal under Windows' case-insensitive filesystem and distinct everywhere else.</summary>
    public static readonly string[] CaseOnlyEntries = ["lib/A.dll", "lib/a.dll"];

    public string DevicePath { get; }
    public string FoldedPath { get; }
    public string HostileNamePath { get; }
    public string CaseOnlyPath { get; }
    public string SlipPath { get; }

    /// <summary>Bare file name of the zip-slip entry (e.g. <c>silvergun-uninv-slip-&lt;guid&gt;.dll</c>).</summary>
    public string SlipFileName { get; }

    /// <summary>The zip-slip entry as packaged — <c>../../&lt;SlipFileName&gt;</c>.</summary>
    public string SlipEntry { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }

        // Belt and braces, exactly as PackageFixture does it: a regression that let the traversal entry out would
        // drop it one level above each pkg-* extraction dir, i.e. directly under the temp path.
        try
        {
            var stray = Path.Combine(Path.GetTempPath(), SlipFileName);
            if (File.Exists(stray)) File.Delete(stray);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    // Writes "<id>.1.0.0.nupkg" with a valid root nuspec plus the given entries. `raw` exists only to document that
    // those names are hostile/unnormalized; NupkgBuilder stores every name verbatim either way.
    private string Write(
        string id, (string Name, byte[] Bytes)[] entries, (string Name, byte[] Bytes)[] raw)
    {
        var nuspec = NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", $"ADR 0030 uninventoried-entry test package ({id}).", "net8.0", []);
        var path = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            path,
            [($"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec)), .. entries],
            raw);
        return path;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
