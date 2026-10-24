namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0034, I5 W-b: <c>NuGetPackage.ContentRoot</c>, the ONE directory every package-relative path is taken against,
/// computed once by <see cref="NuGetPackage.Open"/> through <c>ContentRootOf(extractionDir, nupkgPath)</c> and spelled as it
/// is on disk:
/// <list type="number">
///   <item><c>Path.Combine(extractionDir, GetFileName(nupkgPath))</c> when it is among the top-level directories (ordinal);</item>
///   <item>else the single top-level directory, as spelled on disk;</item>
///   <item>else <c>extractionDir</c>.</item>
/// </list>
/// <c>PackageScanner</c>'s YARA hit paths use it too, so a <c>.nupkg</c> path ending in a dot (Win32 trims it when the
/// extractor creates the directory) no longer renders its hits ABSOLUTE, carrying the user's temp layout into the report.
///
/// <para>The cross-platform half pins what an ordinary package produces — byte-identical shapes against expected values
/// derived from the fixture's own entries — so the single content root cannot have changed any ordinary output. The
/// <c>#if WINDOWS</c> half covers the trailing-dot path end to end and each rule of <c>ContentRootOf</c> on crafted
/// directories under a <c>ControlledTempDir</c>.</para>
/// </summary>
public sealed class NuGetPackageContentRootTests(PackageFixture fixture) : IClassFixture<PackageFixture>
{
    #region Methods: an ordinary package is unchanged (regression pin)
    [Fact]
    public void Open_OnAnOrdinaryPackage_TheContentRootIsTheDirectoryNamedAfterTheNupkg()
    {
        using var pkg = Open(fixture.PkgAPath);

        Assert.Equal(Path.Combine(pkg.ExtractionDir, $"{PackageFixture.PkgAId}.{PackageFixture.PkgAVersion}.nupkg"), pkg.ContentRoot);
        Assert.Equal(Path.Combine(pkg.ExtractionDir, Path.GetFileName(fixture.PkgAPath)), pkg.ContentRoot);
    }

    // PkgA's inventories, pinned whole against what its five declared entries must produce: the two assemblies with their
    // TFM, role and hash; the two scripts; the nuspec; nothing uninventoried; and a YARA inventory of exactly the five files.
    // Every FullPath is the content root joined with the entry, exactly as the pre-I5 Path.Combine spelled it.
    [Fact]
    public void Open_OnAnOrdinaryPackage_TheInventoriesAreExactlyTheExpectedShapes()
    {
        using var pkg = Open(fixture.PkgAPath);
        var root = pkg.ContentRoot;
        var dll = $"lib/netstandard2.0/{fixture.FixtureDllName}";

        Assert.Equal(
            new[]
            {
                $"content/notmanaged.dll||{PackageItemRole.Content}|{Sha256(NupkgBuilder.NotManagedBytes)}|{Full(root, "content/notmanaged.dll")}",
                $"{dll}|netstandard2.0|{PackageItemRole.Lib}|{fixture.ExpectedFixtureSha256}|{Full(root, dll)}",
            },
            pkg.Assemblies.Select(a => $"{a.RelativePath}|{a.TargetFramework}|{a.Role}|{a.Sha256}|{a.FullPath}").Order(StringComparer.Ordinal));
        Assert.Equal(
            new[]
            {
                $"build/{PackageFixture.PkgAId}.targets|{PackageItemRole.Build}|{Full(root, $"build/{PackageFixture.PkgAId}.targets")}",
                $"tools/init.ps1|{PackageItemRole.Tools}|{Full(root, "tools/init.ps1")}",
            },
            pkg.Scripts.Select(s => $"{s.RelativePath}|{s.Role}|{s.FullPath}").Order(StringComparer.Ordinal));
        Assert.Equal(Full(root, $"{PackageFixture.PkgAId}.nuspec"), pkg.NuspecPath);
        Assert.Empty(pkg.UninventoriedEntryNames);
        Assert.Equal(
            PkgAEntries(fixture).Select(e => Full(root, e)).Order(StringComparer.Ordinal),
            pkg.YaraInventory.Order(StringComparer.Ordinal));
    }

    // The YARA hit paths of an ordinary package, through PackageScanner with a double that hits EVERY listed file: each is
    // the entry name, package-relative and forward-slashed — on both exits of ScanYara.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scan_OnAnOrdinaryPackage_EveryYaraHitPathIsTheEntryName(bool incomplete)
    {
        var scanner = new HittingScanner(_ => true, incomplete);

        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false, yaraScanner: scanner);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(incomplete ? YaraScanStatus.Unavailable : YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Equal(
            PkgAEntries(fixture).Order(StringComparer.Ordinal),
            scan.Value.YaraFindings.Select(f => f.RelativePath).Order(StringComparer.Ordinal));
        Assert.All(scan.Value.YaraFindings, f => Assert.Equal(HittingScanner.Rule, f.RuleName));
    }
    #endregion

#if WINDOWS
    #region Methods: a trailing-dot nupkg path (Windows: Win32 trims the dot)
    // Rule 2: the expected spelling "x.nupkg." is not on disk; the content root is the extractor's directory as the
    // filesystem spelled it, "x.nupkg" — the spelling every inventoried path carries.
    [WindowsExtractionFact("Win32 path normalization trims a trailing dot; on Linux 'x.nupkg.' is simply another, missing, file")]
    public void Open_ThroughATrailingDotPath_TheContentRootIsTheOnDiskSpelling()
    {
        var dotted = fixture.PkgAPath + ".";
        Assert.True(File.Exists(dotted), "precondition: Win32 resolves the trailing-dot path to the package");

        using var pkg = Open(dotted);

        Assert.Equal(Path.Combine(pkg.ExtractionDir, Path.GetFileName(fixture.PkgAPath)), pkg.ContentRoot);
        Assert.NotEqual(Path.Combine(pkg.ExtractionDir, Path.GetFileName(dotted)), pkg.ContentRoot);
        Assert.Equal(new[] { pkg.ContentRoot }, Directory.GetDirectories(pkg.ExtractionDir));   // as spelled on disk
        Assert.All(pkg.YaraInventory, f => Assert.StartsWith(pkg.ContentRoot + Path.DirectorySeparatorChar, f, StringComparison.Ordinal));
    }

    // W-b end to end: the YARA finding's RelativePath through the trailing-dot path is the package-relative one — equal to
    // the plain path's, and carrying none of the extraction directory, the temp layout or the user's name. Both exits:
    // Completed, and Unavailable with the hit carried as a partial finding.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scan_ThroughATrailingDotPath_TheYaraHitPathIsPackageRelative_AsThroughThePlainPath(bool incomplete)
    {
        using var tree = new TempTree();
        var nupkg = YaraInventoryPackageScannerTests.Package(tree, "PkgDotted", "ordinary content\n"u8.ToArray());
        var dotted = nupkg + ".";
        Assert.True(File.Exists(dotted), "precondition: Win32 resolves the trailing-dot path to the package");

        var plain = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: new HittingScanner(IsPayload, incomplete));
        var viaDotScanner = new HittingScanner(IsPayload, incomplete);
        var viaDot = PackageScanner.Scan(dotted, resolveReferences: false, yaraScanner: viaDotScanner);

        Assert.True(plain.IsSuccess, plain.Message);
        Assert.True(viaDot.IsSuccess, viaDot.Message);
        var expected = incomplete ? YaraScanStatus.Unavailable : YaraScanStatus.Completed;
        Assert.Equal(expected, plain.Value.YaraScanStatus);
        Assert.Equal(expected, viaDot.Value.YaraScanStatus);
        var path = Assert.Single(viaDot.Value.YaraFindings).RelativePath;
        Assert.Equal("content/payload.bin", Assert.Single(plain.Value.YaraFindings).RelativePath);
        Assert.Equal("content/payload.bin", path);
        Assert.False(Path.IsPathRooted(path), $"'{path}' is rooted");
        Assert.DoesNotContain(viaDotScanner.ExtractionDir!, path, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Temp", path, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Environment.UserName, path, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(":", path, StringComparison.Ordinal);

        static bool IsPayload(string file) => Path.GetFileName(file) == "payload.bin";
    }
    #endregion

    #region Methods: each rule of ContentRootOf, on crafted directories
    [Fact]
    public void ContentRootOf_Rule1_TheDirectoryNamedAfterTheNupkg_WinAmongSeveral()
    {
        using var dir = new ControlledTempDir("croot-r1");
        var extraction = dir.CreateDirectory("ext");
        Directory.CreateDirectory(Path.Combine(extraction, "other"));
        var expected = Directory.CreateDirectory(Path.Combine(extraction, "x.nupkg")).FullName;

        Assert.Equal(expected, ContentRootOf(extraction, Path.Combine(dir.Root, "x.nupkg")));
    }

    // Rule 1 is ORDINAL: a single directory whose name differs only in case does not match it, and is then taken by rule
    // 2 under its own on-disk spelling, never under the nupkg's.
    [Fact]
    public void ContentRootOf_Rule1IsOrdinal_ACaseVariantIsTakenByRule2_AsSpelledOnDisk()
    {
        using var dir = new ControlledTempDir("croot-case");
        var extraction = dir.CreateDirectory("ext");
        var onDisk = Directory.CreateDirectory(Path.Combine(extraction, "X.NUPKG")).FullName;

        var root = ContentRootOf(extraction, Path.Combine(dir.Root, "x.nupkg"));

        Assert.Equal(onDisk, root);
        Assert.EndsWith(@"\X.NUPKG", root, StringComparison.Ordinal);
    }

    [Fact]
    public void ContentRootOf_Rule2_TheSingleTopLevelDirectory_ForATrailingDotName()
    {
        using var dir = new ControlledTempDir("croot-r2");
        var extraction = dir.CreateDirectory("ext");
        var onDisk = Directory.CreateDirectory(Path.Combine(extraction, "x.nupkg")).FullName;

        Assert.Equal(onDisk, ContentRootOf(extraction, Path.Combine(dir.Root, "x.nupkg.")));
    }

    [Fact]
    public void ContentRootOf_Rule3_WithNoTopLevelDirectory_IsTheExtractionDir()
    {
        using var dir = new ControlledTempDir("croot-r3a");
        var extraction = dir.CreateDirectory("ext");
        File.WriteAllBytes(Path.Combine(extraction, "loose.bin"), [1]);   // a file is not a directory

        Assert.Equal(extraction, ContentRootOf(extraction, Path.Combine(dir.Root, "x.nupkg.")));
    }

    [Fact]
    public void ContentRootOf_Rule3_WithSeveralTopLevelDirectoriesAndNoMatch_IsTheExtractionDir()
    {
        using var dir = new ControlledTempDir("croot-r3b");
        var extraction = dir.CreateDirectory("ext");
        Directory.CreateDirectory(Path.Combine(extraction, "x.nupkg"));
        Directory.CreateDirectory(Path.Combine(extraction, "y.nupkg"));

        Assert.Equal(extraction, ContentRootOf(extraction, Path.Combine(dir.Root, "x.nupkg.")));
    }
    #endregion
#endif

    #region Helpers
    private static NuGetPackage Open(string nupkg)
    {
        var opened = NuGetPackage.Open(nupkg);
        Assert.True(opened.IsSuccess, opened.Message);
        return opened.Value;
    }

    // PkgA's five declared entries (PackageFixture), '/'-separated and package-relative.
    private static string[] PkgAEntries(PackageFixture fixture) =>
    [
        $"{PackageFixture.PkgAId}.nuspec",
        $"lib/netstandard2.0/{fixture.FixtureDllName}",
        "tools/init.ps1",
        $"build/{PackageFixture.PkgAId}.targets",
        "content/notmanaged.dll",
    ];

    private static string Full(string root, string entry) => Path.Combine(root, entry.Replace('/', Path.DirectorySeparatorChar));

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    // NuGetPackage.ContentRootOf (private static), by reflection.
    private static string ContentRootOf(string extractionDir, string nupkgPath)
    {
        var method = typeof(NuGetPackage).GetMethod("ContentRootOf", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.True(method is not null, "NuGetPackage.ContentRootOf is gone; the content-root rules are no longer testable.");
        return (string)method!.Invoke(null, [extractionDir, nupkgPath])!;
    }
    #endregion

    #region Nested types
    /// <summary>
    /// A backend that "matches" every listed file <c>hits</c> selects, under <see cref="Rule"/>, and either returns those
    /// hits (Completed) or throws them as the partial findings of an incomplete scan (Unavailable). It records the root
    /// it was handed, so a test can check the report carries none of it.
    /// </summary>
    private sealed class HittingScanner(Func<string, bool> hits, bool incomplete) : IYaraScanner
    {
        public const string Rule = "ContentRoot_Test_Rule";

        public bool Available => true;

        public string? ExtractionDir { get; private set; }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => throw new NotSupportedException("ScanYara calls ScanFiles");

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            ExtractionDir = rootDir;
            var found = files.Where(hits).Select(f => (f, new YaraMatch(Rule, null, [], []))).ToArray();
            return incomplete
                ? throw new YaraScanIncompleteException("YARA could not scan 'something'.", null, found)
                : found;
        }
    }
    #endregion
}
