namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Xunit;

/// <summary>
/// Nuspec content rule scanning (ADR 0012 follow-up / <c>docs/agent/tasks/nuspec-content-scan.md</c>): the package
/// manifest (<c>.nuspec</c>) is deliberately kept out of the script inventory but is still rule-scanned by the
/// <see cref="ScriptRuleScanner"/> during the open-package session. Any match folds into the report's
/// <see cref="PackageCapabilityReport.ScriptFindings"/> with <see cref="ScriptFinding.RelativePath"/> equal to the
/// nuspec's file name. Packages are staged by <see cref="PackageFixture"/> from pure BCL-built zips — no network;
/// all package content is untrusted per the project threat model.
/// </summary>
public sealed class NuspecContentScanTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public NuspecContentScanTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // Acceptance criterion: a manifest whose <description> carries a rule-matching token (certutil LOLBAS) yields
    // >=1 finding attributed to the nuspec file name with a non-empty RuleId. The package has no scripts, so any
    // finding must originate from the nuspec scan.
    [Fact]
    public void Scan_PkgNuspecMatch_FlagsNuspec_WithNuspecRelativePathAndRuleId()
    {
        var scan = PackageScanner.Scan(fixture.PkgNuspecMatchPath);
        Assert.True(scan.IsSuccess, scan.Message);

        var nuspecFindings = scan.Value.ScriptFindings
            .Where(f => Norm(f.RelativePath).Equals(fixture.NuspecMatchFileName, StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(nuspecFindings);
        Assert.All(nuspecFindings, f => Assert.False(string.IsNullOrEmpty(f.RuleId)));
    }

    // A clean nuspec (PkgB carries only benign identity, no scripts) produces zero nuspec-attributed findings and
    // an entirely empty — never null — ScriptFindings list.
    [Fact]
    public void Scan_PkgB_CleanNuspec_ProducesNoNuspecFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath);
        Assert.True(scan.IsSuccess, scan.Message);

        Assert.NotNull(scan.Value.ScriptFindings);
        Assert.DoesNotContain(
            scan.Value.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(scan.Value.ScriptFindings);
    }

    // A benign-but-scripted package (PkgA) whose nuspec matches nothing: the nuspec contributes no finding even
    // though the package is otherwise inventoried normally.
    [Fact]
    public void Scan_PkgA_CleanNuspec_NoNuspecAttributedFinding()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath);
        Assert.True(scan.IsSuccess, scan.Message);

        Assert.DoesNotContain(
            scan.Value.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
    }

    // The manifest is scanned but NOT inventoried: for a normal package (PkgA) NuspecPath is non-null and points to
    // an existing on-disk file, while the Scripts inventory excludes the nuspec entirely (ADR 0012).
    [Fact]
    public void Open_PkgA_ExposesNuspecPath_ButExcludesItFromScripts()
    {
        var open = NuGetPackage.Open(fixture.PkgAPath);
        Assert.True(open.IsSuccess, open.Message);
        using var pkg = open.Value;

        Assert.NotNull(pkg.NuspecPath);
        Assert.True(File.Exists(pkg.NuspecPath));
        Assert.EndsWith(".nuspec", pkg.NuspecPath!, StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            pkg.Scripts,
            s => Norm(s.RelativePath).EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(pkg.Scripts); // scripts still inventoried; only the nuspec is excluded
    }

    // Never-throws: an oversized (>5 MiB) but valid nuspec must be skipped by the size cap without crashing Scan.
    // The scan returns success, the oversized nuspec contributes no finding, and a small matching script's finding
    // (proving other findings stay intact) survives.
    [Fact]
    public void Scan_PkgNuspecOversize_SkipsNuspec_ButKeepsOtherFindings()
    {
        var scan = default(Silvergun.Result<PackageCapabilityReport>);
        var ex = Record.Exception(() => scan = PackageScanner.Scan(fixture.PkgNuspecOversizePath));

        Assert.Null(ex);
        Assert.True(scan.IsSuccess, scan.Message);
        var report = scan.Value;

        // The oversized nuspec (skipped by the size cap) contributes no finding ...
        Assert.DoesNotContain(
            report.ScriptFindings,
            f => Norm(f.RelativePath).Equals(fixture.NuspecOversizeFileName, StringComparison.Ordinal));

        // ... while the small matching script's finding survives intact.
        Assert.Contains(
            report.ScriptFindings,
            f => Norm(f.RelativePath).EndsWith("/keep.ps1", StringComparison.Ordinal) && !string.IsNullOrEmpty(f.RuleId));
    }

    // Containment gate for the manifest selector (adversarial): a package that carries a malicious *.nuspec whose
    // declared entry name escapes the extraction dir via "../../" — alongside a benign, valid top-level manifest.
    // NuspecPath is selected only from the already-containment-validated file set (the same IsContained zip-slip gate
    // used for assemblies/scripts), so the escaping nuspec must never be selected. The package still opens (its valid
    // manifest lets NuGet read identity) and NuspecPath resolves to that benign manifest — never the traversal entry.
    //
    // NOTE ON SHAPE (documented per the task): the ideal "Open succeeds AND NuspecPath == null" is unreachable here —
    // a package whose ONLY nuspec is an escaping entry fails to open outright (NuGet's manifest reader requires a
    // root-level nuspec), so a valid manifest is retained. This mirrors the PkgD zip-slip fixture exactly (benign
    // entry survives, escaping entry skipped) and directly exercises the manifest-selection-over-contained-set path.
    // The invariant asserted is the one that matters: the escaping nuspec never becomes the scanned NuspecPath.
    [Fact]
    public void Open_PkgNuspecSlip_DoesNotSelectEscapingNuspec_AsNuspecPath()
    {
        var open = NuGetPackage.Open(fixture.PkgNuspecSlipPath);
        Assert.True(open.IsSuccess, open.Message);
        using var pkg = open.Value;

        // The manifest selector resolves to the benign, contained top-level nuspec ...
        Assert.NotNull(pkg.NuspecPath);
        Assert.True(File.Exists(pkg.NuspecPath));
        Assert.Equal(fixture.NuspecSlipManifestFileName, Path.GetFileName(pkg.NuspecPath!));

        // ... and never the escaping "../../<guid>.nuspec" traversal entry, by file name or anywhere in the path.
        Assert.NotEqual(fixture.NuspecSlipEntryFileName, Path.GetFileName(pkg.NuspecPath!));
        Assert.DoesNotContain(fixture.NuspecSlipEntryFileName, Norm(pkg.NuspecPath!));

        // Defense in depth: the selected manifest stays under the extraction sandbox, and the traversal target
        // was never written to its escaping "../../" location on disk.
        var root = Path.GetFullPath(pkg.ExtractionDir);
        if (!root.EndsWith(Path.DirectorySeparatorChar))
            root += Path.DirectorySeparatorChar;
        Assert.StartsWith(root, Path.GetFullPath(pkg.NuspecPath!), StringComparison.Ordinal);

        var strayTarget = Path.GetFullPath(Path.Combine(pkg.ExtractionDir, fixture.NuspecSlipRelativeEntry));
        Assert.False(File.Exists(strayTarget), $"Escaping nuspec escaped to {strayTarget}.");
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    private static string Norm(string path) => path.Replace('\\', '/');
    #endregion
}
