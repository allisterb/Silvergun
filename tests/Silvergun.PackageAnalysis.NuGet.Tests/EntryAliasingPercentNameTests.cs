namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using global::NuGet.Packaging;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

using static EntryAliasingSupport;

/// <summary>
/// <c>docs/agent/tasks/entry-aliasing-coverage.md</c> <b>Review 8</b>, fixed by <b>S9</b> (the ADR 0036 amendment): what
/// an entry IS is decided on the name NuGet installs it under. NuGet unescapes <c>%xx</c> in entry names
/// (<c>PackageArchiveReader.UnescapePath</c>); RecursiveExtractor writes the raw name. Measured by the reviewer on both
/// platforms (scratchpad <c>s14a-probe</c>, <c>s14a-run.txt</c> / <c>s14a-linux.txt</c>), each <c>--strict</c> exit 0
/// before S9: a lone <c>build/Some.Package%2Etargets</c> holding a hook is installed by NuGet as
/// <c>build/Some.Package.targets</c>, yet it was never script-scanned, because the kind test read the raw name; likewise a
/// <c>%2E</c>-named <c>.ps1</c>, <c>.props</c> and <c>.dll</c>.
///
/// <para>Now <c>NuGetPackage.NuGetName</c> drives the kind, role, TFM and manifest decisions, while the paths read and
/// reported stay RAW (they are the files on disk). Each package below first asserts NuGet's own view (the unescaped name,
/// via <see cref="PackageArchiveReader.GetFiles()"/>) and the extractor's (the raw name on disk, holding the hook), so no
/// test can pass vacuously against a reader that stopped unescaping.</para>
///
/// <para>Content is benign: the hook is <see cref="PackageFixture.MaliciousTargets"/> /
/// <see cref="PackageFixture.MaliciousPs1"/> (certutil tokens against <c>malicious.example</c>), the decoy an empty
/// project, and the assembly the suite's own IL fixture. Every shape runs on both platforms except the case-folding one,
/// which is Windows-only by construction.</para>
/// </summary>
public sealed class EntryAliasingPercentNameTests : IClassFixture<PercentNamePackageFixture>
{
    #region Constructors
    public EntryAliasingPercentNameTests(PercentNamePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: NuGetName, as NuGet unescapes (unit)
    [Theory]
    [InlineData("build/Some.Package.targets", "build/Some.Package.targets")]                 // no '%': unchanged
    [InlineData("build/Some.Package%2Etargets", "build/Some.Package.targets")]               // upper-case hex
    [InlineData("build/Some.Package%2etargets", "build/Some.Package.targets")]               // lower-case hex
    [InlineData("content/a%zzb.txt", "content/a%zzb.txt")]                                    // not an escape: left as-is
    [InlineData("content/100%", "content/100%")]                                              // a trailing lone '%'
    [InlineData("lib/portable-net45%2Bwin8/A.dll", "lib/portable-net45+win8/A.dll")]         // the corpus's %2B TFMs
    [InlineData("build/Some.Package%252Etargets", "build/Some.Package%2Etargets")]           // one level only, like NuGet
    [InlineData("lib%2Fnet8.0%2FA.dll", "lib/net8.0/A.dll")]                                  // an escaped separator
    public void NuGetName_UnescapesPercentSequencesOnceAndLeavesTheRestAlone(string entry, string expected)
    {
        Assert.Equal(expected, NuGetPackage.NuGetName(entry));
    }

    // The premise: NuGetName is NuGet's own reading, checked against NuGet's reader for every shape above that is a file.
    [Theory]
    [InlineData("build/Some.Package%2Etargets")]
    [InlineData("build/Some.Package%2etargets")]
    [InlineData("content/a%zzb.txt")]
    [InlineData("content/100%")]
    [InlineData("lib/portable-net45%2Bwin8/A.dll")]
    [InlineData("build/Some.Package%252Etargets")]
    [InlineData("lib%2Fnet8.0%2FA.dll")]
    public void NuGetName_AgreesWithNuGetsOwnReader(string entry)
    {
        var path = fixture.WriteOneEntryPackage(entry);
        using var reader = new PackageArchiveReader(path);

        Assert.Contains(NuGetPackage.NuGetName(entry), reader.GetFiles());
    }

    [Theory]
    [InlineData("lib/portable-net45%2Bwin8/A.dll", PackageItemRole.Lib, "portable-net45+win8")]
    [InlineData("lib/portable-net45%2bwin8/A.dll", PackageItemRole.Lib, "portable-net45+win8")]
    [InlineData("lib%2Fnet8.0%2FA.dll", PackageItemRole.Lib, "net8.0")]
    [InlineData("build%2FSome.Package.targets", PackageItemRole.Build, null)]
    [InlineData("runtimes/win-x64/lib/net45%2Bwin8/A.dll", PackageItemRole.Runtimes, "net45+win8")]
    [InlineData("lib/net8.0/A%2Edll", PackageItemRole.Lib, "net8.0")]
    public void RoleAndTargetFramework_AreDecidedOnTheUnescapedName(string entry, PackageItemRole role, string? tfm)
    {
        Assert.Equal(role, NuGetPackage.RoleOf(entry));
        Assert.Equal(tfm, NuGetPackage.TargetFrameworkOf(entry, role));
    }
    #endregion

    #region Methods: a %2E-named script is a script (every platform)
    // p-pct-sole-targets: the hook under an escaped dot, alone. NuGet installs build/Some.Package.targets = the hook.
    [Fact]
    public void OpenAndScan_ForALoneEscapedDotTargets_InventoryItAsABuildScriptAndReportTheHooksFindings()
    {
        AssertScriptAnalysed(fixture.SoleTargetsPath, PercentNamePackageFixture.EscapedTargets, EntryAliasPackageFixture.TargetsEntry,
            PackageItemRole.Build, PackageFixture.MaliciousTargets);
    }

    // p-pct-before-targets: the hook under the escaped name FIRST (what NuGet installs, first-wins), the decoy under the
    // plain name after. Both raw names are their own files; the hook's is now scanned.
    [Fact]
    public void OpenAndScan_ForAnEscapedDotHookBeforeAPlainDecoy_ReportTheHooksFindings()
    {
        AssertNuGetInstalls(fixture.BeforeTargetsPath, EntryAliasPackageFixture.TargetsEntry, PackageFixture.MaliciousTargets);
        AssertScriptAnalysed(fixture.BeforeTargetsPath, PercentNamePackageFixture.EscapedTargets, EntryAliasPackageFixture.TargetsEntry,
            PackageItemRole.Build, PackageFixture.MaliciousTargets, otherScripts: [EntryAliasPackageFixture.TargetsEntry]);
    }

    // The reverse (p-pct-after-targets): the hook under the plain name first. Scanned before S9 too; must stay so.
    [Fact]
    public void OpenAndScan_ForAPlainHookBeforeAnEscapedDotDecoy_ReportTheHooksFindings()
    {
        AssertNuGetInstalls(fixture.AfterTargetsPath, EntryAliasPackageFixture.TargetsEntry, PackageFixture.MaliciousTargets);
        AssertScriptAnalysed(fixture.AfterTargetsPath, EntryAliasPackageFixture.TargetsEntry, EntryAliasPackageFixture.TargetsEntry,
            PackageItemRole.Build, PackageFixture.MaliciousTargets, otherScripts: [PercentNamePackageFixture.EscapedTargets]);
    }

    // p-pctlow-before: the same with lower-case hex.
    [Fact]
    public void OpenAndScan_ForALowerCaseEscapedDotHookBeforeAPlainDecoy_ReportTheHooksFindings()
    {
        AssertNuGetInstalls(fixture.LowerBeforeTargetsPath, EntryAliasPackageFixture.TargetsEntry, PackageFixture.MaliciousTargets);
        AssertScriptAnalysed(fixture.LowerBeforeTargetsPath, PercentNamePackageFixture.EscapedLowerTargets, EntryAliasPackageFixture.TargetsEntry,
            PackageItemRole.Build, PackageFixture.MaliciousTargets, otherScripts: [EntryAliasPackageFixture.TargetsEntry]);
    }

    // p-pct-sole-ps1.
    [Fact]
    public void OpenAndScan_ForALoneEscapedDotPs1_InventoryItAsAToolsScriptAndReportItsFindings()
    {
        AssertScriptAnalysed(fixture.SolePs1Path, PercentNamePackageFixture.EscapedPs1, "tools/install.ps1",
            PackageItemRole.Tools, PackageFixture.MaliciousPs1);
    }

    // p-pct-sole-props.
    [Fact]
    public void OpenAndScan_ForALoneEscapedDotProps_InventoryItAsABuildTransitiveScriptAndReportItsFindings()
    {
        AssertScriptAnalysed(fixture.SolePropsPath, PercentNamePackageFixture.EscapedProps, "buildTransitive/Some.Package.props",
            PackageItemRole.BuildTransitive, PackageFixture.MaliciousTargets);
    }
    #endregion

    #region Methods: a %2E-named assembly is an assembly, and a %2B TFM reads as NuGet spells it (every platform)
    // p-pct-sole-dll, with a real assembly: inventoried as lib/net8.0, and IL-analysed.
    [Fact]
    public void OpenAndScan_ForALoneEscapedDotDll_InventoryItAsALibAssemblyAndAnalyseItsIL()
    {
        AssertNuGetInstalls(fixture.SoleDllPath, "lib/net8.0/A.dll", fixture.FixtureBytes);

        using (var pkg = Open(fixture.SoleDllPath))
        {
            Assert.Equal(fixture.FixtureBytes, File.ReadAllBytes(Path.Combine(pkg.ContentRoot, "lib", "net8.0", "A%2Edll")));
            var assembly = Assert.Single(pkg.Assemblies);
            Assert.Equal(PercentNamePackageFixture.EscapedDll, assembly.RelativePath);
            Assert.Equal(PackageItemRole.Lib, assembly.Role);
            Assert.Equal("net8.0", assembly.TargetFramework);
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        AssertFixtureAnalysed(Scan(fixture.SoleDllPath), PercentNamePackageFixture.EscapedDll, "net8.0");
    }

    // The visible effect of S9 on benign packages (256 in the local cache): a %2B TFM is displayed as NuGet spells it,
    // while the path stays the raw one on disk.
    [Fact]
    public void OpenAndScan_ForAnAssemblyUnderAPercentEscapedPlusTfm_ReportTheTfmWithAPlusAndTheRawPath()
    {
        AssertNuGetInstalls(fixture.PlusTfmDllPath, "lib/portable-net45+win8/A.dll", fixture.FixtureBytes);

        using (var pkg = Open(fixture.PlusTfmDllPath))
        {
            var assembly = Assert.Single(pkg.Assemblies);
            Assert.Equal(PercentNamePackageFixture.PlusTfmDll, assembly.RelativePath);
            Assert.Equal("portable-net45+win8", assembly.TargetFramework);
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        AssertFixtureAnalysed(Scan(fixture.PlusTfmDllPath), PercentNamePackageFixture.PlusTfmDll, "portable-net45+win8");
    }
    #endregion

    #region Methods: case folding (Windows)
    // p-pctcase-before: an upper-case escaped hook first, the plain decoy after. On Windows NuGet installs
    // build/SOME.PACKAGE.TARGETS = the hook and skips the decoy (case-insensitive, first-wins); the extractor writes two
    // files, since the raw names differ by more than case. The hook's raw file must be scanned.
    [WindowsExtractionFact("NuGet's install folds the plain decoy onto the escaped hook's name only on a case-insensitive filesystem")]
    public void OpenAndScan_ForAnUpperCaseEscapedHookBeforeAPlainDecoy_ReportTheHooksFindings()
    {
        AssertNuGetInstalls(fixture.CaseBeforeTargetsPath, "build/SOME.PACKAGE.TARGETS", PackageFixture.MaliciousTargets);
        AssertScriptAnalysed(fixture.CaseBeforeTargetsPath, PercentNamePackageFixture.EscapedUpperTargets, "build/SOME.PACKAGE.TARGETS",
            PackageItemRole.Build, PackageFixture.MaliciousTargets, otherScripts: [EntryAliasPackageFixture.TargetsEntry]);
    }
    #endregion

    #region Methods: helpers
    // NuGet's view: the FIRST entry whose unescaped name is `nugetName` holds `content` (NuGet is first-wins).
    private static void AssertNuGetInstalls(string nupkgPath, string nugetName, string content) =>
        AssertNuGetInstalls(nupkgPath, nugetName, Encoding.UTF8.GetBytes(content));

    private static void AssertNuGetInstalls(string nupkgPath, string nugetName, byte[] content)
    {
        using var reader = new PackageArchiveReader(nupkgPath);
        Assert.Contains(nugetName, reader.GetFiles());
        using var stream = reader.GetStream(nugetName);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        Assert.Equal(content, buffer.ToArray());
    }

    // The script at raw name `raw` (NuGet's `nugetName`) is on disk verbatim holding `content`, is inventoried with `role`,
    // and its findings are reported under the raw name; nothing is lost and the script scan completed.
    private static void AssertScriptAnalysed(
        string nupkgPath, string raw, string nugetName, PackageItemRole role, string content, string[]? otherScripts = null)
    {
        using (var reader = new PackageArchiveReader(nupkgPath))
            Assert.Contains(nugetName, reader.GetFiles());

        using (var pkg = Open(nupkgPath))
        {
            Assert.Equal(content, File.ReadAllText(Path.Combine(pkg.ContentRoot, raw)));
            var script = Assert.Single(pkg.Scripts, s => s.RelativePath == raw);
            Assert.Equal(role, script.Role);
            Assert.Equal(
                new[] { raw }.Concat(otherScripts ?? []).Order(StringComparer.Ordinal),
                pkg.Scripts.Select(s => s.RelativePath).Order(StringComparer.Ordinal));
            Assert.Empty(pkg.UninventoriedEntryNames);
        }

        var scan = Scan(nupkgPath);
        Assert.Contains(scan.ScriptFindings, f => f.RelativePath == raw && f.Source == ScriptFindingSource.Script);
        Assert.Equal(ScriptScanStatus.Completed, scan.ScriptScanStatus);
        Assert.DoesNotContain(scan.Assemblies, a => a.SkipReason is not null);
    }

    // The fixture assembly at `relativePath` was IL-analysed: a report with the SensitiveOps FileSystem finding, no skip.
    private static void AssertFixtureAnalysed(PackageCapabilityReport scan, string relativePath, string tfm)
    {
        var row = Assert.Single(scan.Assemblies);
        Assert.Equal(relativePath, row.Assembly.RelativePath);
        Assert.Equal(tfm, row.Assembly.TargetFramework);
        Assert.Null(row.SkipReason);
        Assert.NotNull(row.Report);
        Assert.Contains(row.Report!.Findings,
            f => f.Capability == Capability.FileSystem && f.CallerType.EndsWith("SensitiveOps", StringComparison.Ordinal));
    }
    #endregion

    #region Fields
    private readonly PercentNamePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages review 8's <c>p-*</c> probe shapes (<c>s14a-probe\Program.cs</c>) for <see cref="EntryAliasingPercentNameTests"/>
/// with pure BCL zip (raw names stored verbatim by <see cref="NupkgBuilder"/>), the probe's webhook hook replaced by the
/// suite's benign fixtures and its <c>MZ-not-really</c> bytes by the real IL fixture assembly.
/// </summary>
public sealed class PercentNamePackageFixture : IDisposable
{
    #region Constructors
    public PercentNamePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-entry-alias", "percent-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        const string plain = EntryAliasPackageFixture.TargetsEntry;
        var hook = Text(PackageFixture.MaliciousTargets);
        var decoy = Text(EntryAliasPackageFixture.DecoyTargets);
        FixtureBytes = File.ReadAllBytes(typeof(Shapes).Assembly.Location);

        SoleTargetsPath = Write("SoleTargets", [(EscapedTargets, hook)]);
        BeforeTargetsPath = Write("BeforeTargets", [(EscapedTargets, hook), (plain, decoy)]);
        AfterTargetsPath = Write("AfterTargets", [(plain, hook), (EscapedTargets, decoy)]);
        LowerBeforeTargetsPath = Write("LowerBeforeTargets", [(EscapedLowerTargets, hook), (plain, decoy)]);
        CaseBeforeTargetsPath = Write("CaseBeforeTargets", [(EscapedUpperTargets, hook), (plain, decoy)]);
        SolePs1Path = Write("SolePs1", [(EscapedPs1, Text(PackageFixture.MaliciousPs1))]);
        SolePropsPath = Write("SoleProps", [(EscapedProps, hook)]);
        SoleDllPath = Write("SoleDll", [(EscapedDll, FixtureBytes)]);
        PlusTfmDllPath = Write("PlusTfmDll", [(PlusTfmDll, FixtureBytes)]);
    }
    #endregion

    #region Properties
    /// <summary><see cref="EntryAliasPackageFixture.TargetsEntry"/> with its last dot escaped (upper-case hex).</summary>
    public const string EscapedTargets = "build/Some.Package%2Etargets";

    /// <summary>The same, lower-case hex.</summary>
    public const string EscapedLowerTargets = "build/Some.Package%2etargets";

    /// <summary>The same, upper-cased throughout: NuGet's <c>build/SOME.PACKAGE.TARGETS</c>.</summary>
    public const string EscapedUpperTargets = "build/SOME.PACKAGE%2ETARGETS";

    /// <summary>NuGet's <c>tools/install.ps1</c>.</summary>
    public const string EscapedPs1 = "tools/install%2Eps1";

    /// <summary>NuGet's <c>buildTransitive/Some.Package.props</c>.</summary>
    public const string EscapedProps = "buildTransitive/Some.Package%2Eprops";

    /// <summary>NuGet's <c>lib/net8.0/A.dll</c>.</summary>
    public const string EscapedDll = "lib/net8.0/A%2Edll";

    /// <summary>NuGet's <c>lib/portable-net45+win8/A.dll</c>, the shape of every <c>%</c> name in the local cache.</summary>
    public const string PlusTfmDll = "lib/portable-net45%2Bwin8/A.dll";

    public string SoleTargetsPath { get; }
    public string BeforeTargetsPath { get; }
    public string AfterTargetsPath { get; }
    public string LowerBeforeTargetsPath { get; }
    public string CaseBeforeTargetsPath { get; }
    public string SolePs1Path { get; }
    public string SolePropsPath { get; }
    public string SoleDllPath { get; }
    public string PlusTfmDllPath { get; }

    /// <summary>The IL fixture assembly's bytes (<see cref="Shapes"/>'s assembly).</summary>
    public byte[] FixtureBytes { get; }
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

    /// <summary>A package with the manifest and one text entry named <paramref name="entry"/>; returns its path.</summary>
    public string WriteOneEntryPackage(string entry) =>
        Write("One-" + Guid.NewGuid().ToString("N"), [(entry, Text("hello\n"))]);

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    // The manifest first, then the entries in the given archive order (the order is the point in the before/after pairs).
    private string Write(string name, (string Name, byte[] Bytes)[] entries)
    {
        var path = Path.Combine(rootDir, $"{name}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [], [(Manifest, nuspec), .. entries]);
        return path;
    }
    #endregion

    #region Fields
    private const string Manifest = "PkgPercent.nuspec";

    private static readonly byte[] nuspec = Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
        "PkgPercent", "1.0.0", "Silvergun Tests", "Percent-escaped entry-name test package.", "net8.0", []));

    private readonly string rootDir;
    #endregion
}
