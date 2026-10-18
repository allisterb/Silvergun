namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// ADR 0031 decision 4 at the DTO boundary: <b>every entry name that leaves the analyzer is escaped, and it is
/// escaped where the DTO is BUILT, not where it is rendered.</b> <see cref="YaraFinding.RelativePath"/> was already
/// covered; <see cref="PackageAssembly.RelativePath"/>, <see cref="PackageScript.RelativePath"/> and
/// <see cref="ScriptFinding.RelativePath"/> were still raw, and a renderer that only escapes Spectre markup would
/// let <c>tools/pay&lt;LF&gt;load.ps1</c> split a table row and <b>forge report lines</b>.
///
/// <para><b>Why the central shape here is a bidi override, not a control character.</b> The control-character shape
/// is Linux-only: measured 2026-08-22, RecursiveExtractor writes <c>pay&lt;LF&gt;load.dll</c> verbatim on Linux but
/// RENAMES it to <c>pay_load.dll</c> on Windows, where the entry is then lost rather than inventoried — so on
/// Windows no raw C0 character can reach a DTO through extraction at all. U+202E is legal in a filename on BOTH
/// platforms and is written verbatim by both (measured the same day), so the bidi shape asserts the same statement
/// everywhere, and the two platform-gated tests pin the divergence itself instead of hiding it.</para>
///
/// <para>The escaper's own alphabet is exhaustively property-tested in <c>YaraPathSafetyTests</c>; what is under
/// test here is only that these three DTOs go through it.</para>
/// </summary>
public sealed class EntryNameEscapingAtTheDtoBoundaryTests : IClassFixture<HostileEntryNamePackageFixture>
{
    #region Constructors
    public EntryNameEscapingAtTheDtoBoundaryTests(HostileEntryNamePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — PackageAssembly.RelativePath (cross-platform: a bidi override survives extraction everywhere)
    // The inventoried assembly's RelativePath is the ESCAPED name, while the file it came from still carries the
    // raw override on disk — which is what says the escaping happens at the DTO and not by accident of extraction.
    [Fact]
    public void Open_ForABidiOverrideInAnAssemblyEntryName_EscapesTheAssemblyRelativePath()
    {
        using var pkg = Open(fixture.BidiPath);

        Assert.Contains(
            ExtractedRelativePaths(pkg),
            p => p.Contains(HostileEntryNamePackageFixture.Rlo, StringComparison.Ordinal));   // ground truth: raw on disk...

        var assembly = Assert.Single(pkg.Assemblies);
        Assert.Equal(HostileEntryNamePackageFixture.BidiAssemblyEscaped, assembly.RelativePath);   // ...escaped in the DTO
        AssertNoRawHostileText(assembly.RelativePath, nameof(PackageAssembly.RelativePath));
    }

    // FullPath is deliberately NOT escaped: it is used to open the file, so it must stay a real path. Pinned so a
    // well-meaning "escape everything" change cannot break the read while looking like a hardening.
    [Fact]
    public void Open_ForABidiOverrideInAnAssemblyEntryName_LeavesFullPathOpenable()
    {
        using var pkg = Open(fixture.BidiPath);

        var assembly = Assert.Single(pkg.Assemblies);
        Assert.Contains(HostileEntryNamePackageFixture.Rlo, assembly.FullPath, StringComparison.Ordinal);
        Assert.True(File.Exists(assembly.FullPath), "FullPath must remain a real, openable path.");
        Assert.NotEqual(string.Empty, assembly.Sha256);
    }
    #endregion

    #region Methods — PackageScript.RelativePath and ScriptFinding.RelativePath
    [Fact]
    public void Open_ForABidiOverrideInAScriptEntryName_EscapesTheScriptRelativePath()
    {
        using var pkg = Open(fixture.BidiPath);

        var script = Assert.Single(pkg.Scripts);
        Assert.Equal(HostileEntryNamePackageFixture.BidiScriptEscaped, script.RelativePath);
        AssertNoRawHostileText(script.RelativePath, nameof(PackageScript.RelativePath));
    }

    // The script findings are the report's most quoted path field, and they are built by a different code path
    // (ScriptRuleScanner.MapFinding) than the inventory — so the escaping is asserted there too, on real findings
    // produced by the real ruleset over a rule-matching script.
    [Fact]
    public void Scan_ForABidiOverrideInAScriptEntryName_EscapesEveryScriptFindingRelativePath()
    {
        var report = Scan(fixture.BidiPath);

        Assert.NotEmpty(report.ScriptFindings);
        Assert.All(
            report.ScriptFindings,
            f => Assert.Equal(HostileEntryNamePackageFixture.BidiScriptEscaped, f.RelativePath));
    }

    // The same statement about the OTHER entry point into the rule scanner — the one that takes an arbitrary
    // relative path rather than a PackageScript built by NuGetPackage. It runs on every platform because the
    // hostile text is supplied by the caller instead of having to survive a filesystem, which is what makes the
    // control-character case assertable on Windows at all.
    [Fact]
    public void ScanFile_ForARelativePathCarryingAControlCharacter_EscapesItInEveryFinding()
    {
        var findings = new ScriptRuleScanner().ScanFile(fixture.LooseScriptPath, "tools/pay\nload.ps1");

        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("tools/pay\\nload.ps1", f.RelativePath));
    }
    #endregion

    #region Methods — nothing hostile anywhere in the report
    // The sweep: no field of any DTO the report carries may hold a raw control, C1, separator or bidi character.
    // One field left raw is one forged report line, so this is asserted over the whole report rather than per DTO.
    [Fact]
    public void Scan_ForABidiOverridePackage_EmitsNoRawHostileTextInAnyReportedPath()
    {
        var report = Scan(fixture.BidiPath);

        foreach (var result in report.Assemblies)
            AssertNoRawHostileText(result.Assembly.RelativePath, nameof(PackageAssembly.RelativePath));
        foreach (var script in report.Scripts)
            AssertNoRawHostileText(script.RelativePath, nameof(PackageScript.RelativePath));
        foreach (var finding in report.ScriptFindings)
            AssertNoRawHostileText(finding.RelativePath, nameof(ScriptFinding.RelativePath));

        // ...and the package really did carry the override, else the sweep is vacuous.
        Assert.Contains(report.Assemblies, a => a.Assembly.RelativePath.Contains("u202e", StringComparison.Ordinal));
    }

    // The anomaly analyzer reports the same package's names as a BidiControl finding, so the two halves of ADR 0031
    // agree: the construction is escaped where it is carried AND reported where it is found.
    [Fact]
    public void Scan_ForABidiOverridePackage_AlsoReportsItAsAPackagingAnomaly()
    {
        var report = Scan(fixture.BidiPath);

        Assert.Equal(2, report.PackagingAnomalies.Count(a => a.Category == PackagingAnomalyCategory.BidiControl));
        Assert.All(report.PackagingAnomalies, a => AssertNoRawHostileText(a.EntryName, nameof(PackagingAnomaly.EntryName)));
    }
    #endregion

    #region Methods — the control-character shape, pinned on both platforms
    // Linux writes a C0 character in a filename verbatim, so this is the only platform where a raw control
    // character can reach a DTO through extraction — and the only place the assembly/script escaping can be
    // asserted against a real newline rather than a bidi override.
    [LinuxExtractionFact("only Linux writes a control character in a file name verbatim, so only there is the entry inventoried")]
    public void Open_OnLinux_ForAControlCharacterInEntryNames_InventoriesThemWithEscapedRelativePaths()
    {
        using var pkg = Open(fixture.ControlCharPath);

        Assert.Equal(
            [HostileEntryNamePackageFixture.LfAssemblyEscaped],
            pkg.Assemblies.Select(a => a.RelativePath));
        Assert.Equal(
            [HostileEntryNamePackageFixture.LfScriptEscaped],
            pkg.Scripts.Select(s => s.RelativePath));
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    [LinuxExtractionFact("only Linux inventories a control-character-named script, so only there does it produce findings")]
    public void Scan_OnLinux_ForAControlCharacterInAScriptEntryName_EscapesEveryScriptFindingRelativePath()
    {
        var report = Scan(fixture.ControlCharPath);

        Assert.NotEmpty(report.ScriptFindings);
        Assert.All(
            report.ScriptFindings,
            f => Assert.Equal(HostileEntryNamePackageFixture.LfScriptEscaped, f.RelativePath));
    }

    // The Windows twin, which is why the test above is gated: the extractor RENAMES both entries (to "pay_load"),
    // so neither is inventoried and both are disclosed as lost coverage instead — under their escaped declared
    // names. Stating it here keeps the divergence measured rather than assumed.
    [WindowsExtractionFact("Windows cannot hold a control character in a file name, so the extractor renames the entry")]
    public void Open_OnWindows_ForAControlCharacterInEntryNames_ReportsThemLostUnderTheirEscapedNames()
    {
        using var pkg = Open(fixture.ControlCharPath);

        Assert.Empty(pkg.Assemblies);
        Assert.Empty(pkg.Scripts);
        Assert.Equal(
            [HostileEntryNamePackageFixture.LfAssemblyEscaped, HostileEntryNamePackageFixture.LfScriptEscaped],
            pkg.UninventoriedEntryNames);
    }
    #endregion

    #region Methods — helpers
    private static NuGetPackage Open(string nupkgPath)
    {
        var open = NuGetPackage.Open(nupkgPath);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }

    private static PackageCapabilityReport Scan(string nupkgPath)
    {
        var scan = PackageScanner.Scan(nupkgPath, resolveReferences: false, runYara: false);
        Assert.True(scan.IsSuccess, scan.Message);
        return scan.Value;
    }

    private static string[] ExtractedRelativePaths(NuGetPackage pkg)
    {
        var contentRoot = Directory.EnumerateDirectories(pkg.ExtractionDir).FirstOrDefault() ?? pkg.ExtractionDir;
        return Directory.EnumerateFiles(contentRoot, "*", SearchOption.AllDirectories)
            .Select(f => f[(contentRoot.Length + 1)..].Replace(Path.DirectorySeparatorChar, '/'))
            .ToArray();
    }

    private static void AssertNoRawHostileText(string text, string what)
    {
        var offender = text.FirstOrDefault(IsHostile);
        Assert.True(offender == '\0' && !text.Contains('\0'), $"{what} carried raw U+{(int)offender:X4}: '{text}'.");
    }

    // C0, DEL and the C1 controls, the Unicode line/paragraph separators, and the bidi embeddings/overrides and
    // isolates — the alphabet YaraPathSafety.Escape is defined to remove.
    private static bool IsHostile(char c) =>
        c <= (char)0x1F
        || c is >= (char)0x7F and <= (char)0x9F
             or (char)0x2028 or (char)0x2029
             or >= (char)0x202A and <= (char)0x202E
             or >= (char)0x2066 and <= (char)0x2069;
    #endregion

    #region Fields
    private readonly HostileEntryNamePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the hostile-entry-name packages for <see cref="EntryNameEscapingAtTheDtoBoundaryTests"/> with pure BCL
/// zip. The assembly payload is the real fixture assembly (so it analyses) and the script payload carries the same
/// LOLBAS token <see cref="PackageFixture"/> uses (so it produces real rule findings to check the path field of).
/// </summary>
public sealed class HostileEntryNamePackageFixture : IDisposable
{
    #region Constructors
    public HostileEntryNamePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-hostile-names", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var payload = File.ReadAllBytes(typeof(Shapes).Assembly.Location);
        var script = Encoding.UTF8.GetBytes(PackageFixture.MaliciousPs1);

        BidiPath = Write("PkgBidiName", [(BidiAssemblyEntry, payload), (BidiScriptEntry, script)]);
        ControlCharPath = Write("PkgControlName", [(LfAssemblyEntry, payload), (LfScriptEntry, script)]);

        // A plainly-named script on disk, handed to ScriptRuleScanner.ScanFile with a hostile RELATIVE path — the
        // entry point whose escaping is testable on every platform because no filesystem has to hold the name.
        LooseScriptPath = Path.Combine(rootDir, "loose.ps1");
        File.WriteAllBytes(LooseScriptPath, script);
    }
    #endregion

    #region Properties
    /// <summary>U+202E RIGHT-TO-LEFT OVERRIDE — legal in a file name on both platforms, written verbatim by both.</summary>
    public const string Rlo = "\U0000202E";

    public const string BidiAssemblyEntry = "lib/net8.0/pay" + Rlo + "load.dll";
    public const string BidiScriptEntry = "tools/pay" + Rlo + "load.ps1";

    /// <summary>What <see cref="BidiAssemblyEntry"/> must look like in every DTO that carries it.</summary>
    public const string BidiAssemblyEscaped = "lib/net8.0/pay\\u202eload.dll";

    /// <summary>What <see cref="BidiScriptEntry"/> must look like in every DTO that carries it.</summary>
    public const string BidiScriptEscaped = "tools/pay\\u202eload.ps1";

    public const string LfAssemblyEntry = "lib/net8.0/pay\nload.dll";
    public const string LfScriptEntry = "tools/pay\nload.ps1";

    public const string LfAssemblyEscaped = "lib/net8.0/pay\\nload.dll";
    public const string LfScriptEscaped = "tools/pay\\nload.ps1";

    public string BidiPath { get; }
    public string ControlCharPath { get; }
    public string LooseScriptPath { get; }
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

    private string Write(string id, (string Name, byte[] Bytes)[] raw)
    {
        var nuspec = NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", $"ADR 0031 entry-name escaping test package ({id}).", "net8.0", []);
        var path = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [($"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec))], raw);
        return path;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
