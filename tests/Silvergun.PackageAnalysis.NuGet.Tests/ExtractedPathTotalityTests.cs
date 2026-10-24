namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// <b>Deriving a package-relative path must be TOTAL and must not consult the platform path normalizer.</b>
/// <see cref="NuGetPackage.RelativeUnderRoot"/> is the one computation both the inventory and
/// <c>PackageScanner.PackageRelativePath</c> (the YARA hit attribution) use, and both of the things it replaced
/// were defects:
///
/// <list type="bullet">
/// <item><see cref="Path.GetRelativePath"/> resolves both operands through the normalizer, which on Windows
/// redirects DOS device names — measured on this machine, it answers <c>\\.\COM1</c> for a file named
/// <c>COM1.dll</c> under the content root, a value that matches no declared entry and silently costs the file its
/// inventory slot (ADR 0030, sixth instance).</item>
/// <item>It also THROWS on a pathological name (measured: <c>ArgumentException</c> for an embedded NUL). In the
/// YARA path that throw was caught by <c>ScanYara</c> and turned a real, attributable hit into a package-wide
/// <c>Unavailable</c> — ADR 0030's converse, a detection downgraded to "we don't know". The try/catch is gone
/// because the computation can no longer fail, so this file is what says it cannot.</item>
/// </list>
/// </summary>
public sealed class ExtractedPathTotalityTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public ExtractedPathTotalityTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the derivation itself (cross-platform)
    // A device-named file under the root gets its plain relative path, on every platform. This is the value the
    // inventory gate matches declared entries on, and the one a YARA finding is attributed to.
    [Theory]
    [InlineData("lib/net8.0/COM1.dll")]
    [InlineData("CON.txt")]
    [InlineData("content/NUL/a.bin")]
    [InlineData("tools/LPT9")]
    [InlineData("lib/net8.0/Ordinary.dll")]
    public void RelativeUnderRoot_ForAFileUnderTheRoot_IsThePlainForwardSlashRelativePath(string relative)
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relunder-probe");
        var full = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));

        var derived = NuGetPackage.RelativeUnderRoot(root, full);

        Assert.Equal(relative, derived);
        Assert.DoesNotContain(@"\\.\", derived, StringComparison.Ordinal);
    }

    // Total: no name sinks it. Every row here is one the platform normalizer refuses or rewrites — an embedded
    // NUL throws ArgumentException out of Path.GetRelativePath (measured), and this is called from inside
    // NuGetPackage.Open, where a throw costs the whole package its analysis.
    [Fact]
    public void RelativeUnderRoot_ForPathologicalNames_NeverThrows()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relunder-probe");
        string[] names =
        [
            "lib/pay\0load.dll", "lib/net8.0/COM1.dll", "lib/pay\nload.dll", "con", "x.dll ", "x.dll.",
            new string('a', 40_000), "\U0000202E.dll", "",
        ];

        // Concatenated, not Path.Combine'd: the point is to hand the derivation a name the BCL's own path APIs
        // dislike, so it must not be laundered through one on the way in.
        var thrown = Record.Exception(() =>
        {
            foreach (var name in names)
                _ = NuGetPackage.RelativeUnderRoot(root, root + Path.DirectorySeparatorChar + name);
        });

        Assert.Null(thrown);
    }

    // A path that is somehow NOT under the root comes back unchanged rather than mis-attributed: it then matches
    // no containment key and is skipped with a warning, which is the honest outcome. Silently rewriting it into
    // something that LOOKS relative is how a file gets attributed to the wrong entry.
    [Fact]
    public void RelativeUnderRoot_ForAPathOutsideTheRoot_ReturnsItUnchanged()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relunder-probe");
        var outside = Path.Combine(Path.GetTempPath(), "elsewhere", "x.dll");

        Assert.Equal(outside.Replace('\\', '/'), NuGetPackage.RelativeUnderRoot(root, outside));
    }
    #endregion

    #region Methods — the platform facts that made the old derivation wrong (pinned on both sides)
    // The measurement, pinned: Windows' normalizer redirects a device-named path, so Path.GetRelativePath answers
    // "\\.\COM1" — and Path.GetFullPath agrees, which is what makes this a normalizer behaviour rather than a
    // GetRelativePath quirk. If anyone re-derives an extracted path through either API, this turns red.
    [WindowsExtractionFact("the DOS device-name redirect is a Windows path-normalizer behaviour")]
    public void RelativeUnderRoot_OnWindows_DisagreesWithThePlatformPathNormalizer()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relunder-probe");
        var full = Path.Combine(root, "lib", "net8.0", "COM1.dll");

        Assert.Equal(@"\\.\COM1", Path.GetRelativePath(root, full));               // ground truth: the redirect
        Assert.Equal("lib/net8.0/COM1.dll", NuGetPackage.RelativeUnderRoot(root, full));
    }

    // ...and the throw, which is the other half of why the try/catch could be removed. GetRelativePath refuses an
    // embedded NUL outright; the string-prefix computation just answers.
    [Fact]
    public void RelativeUnderRoot_WhereThePlatformNormalizerThrows_StillAnswers()
    {
        var root = Path.Combine(Path.GetTempPath(), "silvergun-relunder-probe");
        var full = root + Path.DirectorySeparatorChar + "lib" + Path.DirectorySeparatorChar + "pay\0load.dll";

        Assert.NotNull(Record.Exception(() => Path.GetRelativePath(root, full)));   // ground truth: it throws
        Assert.Equal("lib/pay\0load.dll", NuGetPackage.RelativeUnderRoot(root, full));
    }

    // The Linux half of the same measurement, so both runs state the platform fact instead of one being silent:
    // there is no redirect there, and the lexical answer is the SAME one Windows gives.
    [LinuxExtractionFact("the absence of a device-name redirect is the Linux half of the same measurement")]
    public void RelativeUnderRoot_OnLinux_AgreesWithThePlatformPathNormalizer()
    {
        const string root = "/tmp/silvergun-relunder-probe";

        Assert.Equal("lib/net8.0/COM1.dll", Path.GetRelativePath(root, root + "/lib/net8.0/COM1.dll"));
        Assert.Equal("lib/net8.0/COM1.dll", NuGetPackage.RelativeUnderRoot(root, root + "/lib/net8.0/COM1.dll"));
    }
    #endregion

    #region Methods — the YARA attribution seam that consumes it
    // PackageScanner.PackageRelativePath is private, so it is exercised where it ships: a backend hit on a
    // device-named file inside the extraction dir. The finding must carry the plain relative path — not
    // "\\.\COM1", not the absolute path, and not a package-wide Unavailable from a throw that used to be caught.
    [Fact]
    public void Scan_WhenAYaraHitLandsOnADeviceNamedFile_AttributesItToThePlainRelativePath()
    {
        var fake = new SyntheticHitScanner("lib/net8.0/COM1.dll");

        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("lib/net8.0/COM1.dll", finding.RelativePath);
        Assert.DoesNotContain(@"\\.\", finding.RelativePath, StringComparison.Ordinal);
    }

    // The same seam for a name the normalizer refuses outright: the hit is still attributed (escaped, per ADR 0031
    // decision 4) and the package is still Completed. A throw here would have discarded a real detection.
    [Fact]
    public void Scan_WhenAYaraHitLandsOnAControlCharacterNamedFile_StillAttributesItAndStaysCompleted()
    {
        var fake = new SyntheticHitScanner("lib/net8.0/pay\0load.dll");

        var scan = PackageScanner.Scan(fixture.PkgAPath, resolveReferences: false, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal("lib/net8.0/pay\\x00load.dll", finding.RelativePath);
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;
    #endregion

    #region Child types
    // A backend that reports exactly one hit at a caller-chosen path UNDER the scanned root, without needing the
    // file to exist — which is the only way to drive the attribution seam with a name Windows cannot create.
    private sealed class SyntheticHitScanner : IYaraScanner
    {
        public SyntheticHitScanner(string relativePath) => this.relativePath = relativePath;

        public bool Available => true;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => Array.Empty<YaraMatch>();

        // PackageScanner scans the extraction inventory through ScanFiles (ADR 0034); the hit is synthesized the same way
        // whichever entry is used, and deliberately not from the list (its file need not exist).
        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files) =>
            ScanDirectory(rootDir);

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
        {
            // The scanner is handed the extraction dir; the inventory convention nests entries one level down,
            // under a directory named after the .nupkg — so the hit is placed exactly where a real one would be.
            var contentRoot = Directory.EnumerateDirectories(rootDir).FirstOrDefault() ?? rootDir;
            var full = contentRoot + Path.DirectorySeparatorChar
                + relativePath.Replace('/', Path.DirectorySeparatorChar);
            var match = new YaraMatch("Silvergun_Synthetic_Rule", null, Array.Empty<string>(), Array.Empty<YaraStringMatch>());
            return [(full, match)];
        }

        private readonly string relativePath;
    }
    #endregion
}
