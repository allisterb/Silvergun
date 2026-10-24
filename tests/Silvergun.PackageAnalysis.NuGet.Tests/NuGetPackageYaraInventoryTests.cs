namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Xunit;

/// <summary>
/// ADR 0034 decision 1: <c>NuGetPackage.YaraInventory</c>, the expected set YARA coverage is judged against. It is every
/// file under <see cref="NuGetPackage.ExtractionDir"/>, listed by <see cref="NuGetPackage.Open"/> straight after
/// extraction with the backends' own enumeration (<c>Directory.GetFiles(root, "*", AllDirectories)</c>), and it is
/// deliberately <b>unfiltered</b> by containment: YARA's scope is every extracted byte, including a file no contained
/// entry declares (which the assembly and script inventories drop).
/// </summary>
public sealed class NuGetPackageYaraInventoryTests(PackageFixture fixture) : IClassFixture<PackageFixture>
{
    #region Methods
    [Fact]
    public void Open_TheYaraInventory_IsExactlyTheFilesOnDiskUnderTheExtractionDir()
    {
        using var pkg = Open(fixture.PkgAPath);

        var onDisk = Directory.GetFiles(pkg.ExtractionDir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal);
        Assert.Equal(onDisk, pkg.YaraInventory.Order(StringComparer.Ordinal));
        Assert.Equal(pkg.YaraInventory.Count, pkg.YaraInventory.Distinct(StringComparer.Ordinal).Count());
        Assert.All(pkg.YaraInventory, f => Assert.True(Path.IsPathFullyQualified(f), $"'{f}' is not absolute"));
        // Every packaged entry is in it: nuspec, the lib dll, the two scripts and the content dll (plus whatever the
        // extractor itself writes there, which is on disk and therefore in it too).
        Assert.True(pkg.YaraInventory.Count >= 5, $"only {pkg.YaraInventory.Count} file(s) inventoried");
        foreach (var name in new[] { $"{PackageFixture.PkgAId}.nuspec", fixture.FixtureDllName, "init.ps1", $"{PackageFixture.PkgAId}.targets", "notmanaged.dll" })
            Assert.Contains(pkg.YaraInventory, f => Path.GetFileName(f) == name);
    }

    // No containment filter: PkgD's "../../<name>.dll" entry escapes the content root, so containment keeps it out of the
    // assembly inventory — but the extractor clamps it to a real file under the extraction dir, and YARA must still see
    // those bytes. It is in the YARA inventory.
    [Fact]
    public void Open_TheYaraInventory_IncludesAFileContainmentKeepsOutOfTheAssemblyInventory()
    {
        using var pkg = Open(fixture.PkgDPath);

        var clamped = Assert.Single(pkg.YaraInventory, f => Path.GetFileName(f) == fixture.ZipSlipFileName);
        Assert.True(File.Exists(clamped));
        Assert.DoesNotContain(pkg.Assemblies, a => a.RelativePath.Contains(fixture.ZipSlipFileName, StringComparison.Ordinal));
        Assert.Equal(
            Directory.GetFiles(pkg.ExtractionDir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal),
            pkg.YaraInventory.Order(StringComparer.Ordinal));
    }

    // It is a record of what was extracted, taken once: a file deleted afterwards is still in it — which is the whole
    // point (a later walk would simply not see the file).
    [Fact]
    public void Open_TheYaraInventory_IsASnapshot_AFileDeletedAfterOpenIsStillListed()
    {
        using var pkg = Open(fixture.PkgAPath);
        var victim = pkg.YaraInventory.First(f => Path.GetFileName(f) == "init.ps1");

        File.Delete(victim);

        Assert.Contains(victim, pkg.YaraInventory);
        Assert.False(File.Exists(victim));
    }

    // A package with nothing but its manifest: the manifest is still a file YARA must account for.
    [Fact]
    public void Open_TheYaraInventory_OfANuspecOnlyPackage_HoldsTheNuspec()
    {
        using var pkg = Open(fixture.PkgBPath);

        Assert.Contains(pkg.YaraInventory, f => Path.GetFileName(f) == $"{PackageFixture.PkgBId}.nuspec");
        Assert.Empty(pkg.Assemblies);
    }
    #endregion

    #region Methods: Open derives the content root's files from the inventory (I3 review N8)
    // The claim N8 rests on: the inventory's files under the content root (by the ordinal prefix) are EXACTLY the
    // sequence a walk of the content root yields — same files, same order — so deriving them is not a behaviour change.
    // Measured on a package with a zip-slip entry (clamped to a real file) and a case-only collision.
    [Fact]
    public void Open_TheInventoryUnderTheContentRoot_IsExactlyAWalkOfTheContentRoot_InOrder()
    {
        using var tree = new TempTree();
        var nupkg = N8Package(tree, out var slipName);
        try
        {
            using var pkg = Open(nupkg);
            var contentRoot = Path.Combine(pkg.ExtractionDir, Path.GetFileName(nupkg));
            Assert.True(Directory.Exists(contentRoot), "precondition: the extractor nests the entries under a directory named after the .nupkg");

            var underRoot = pkg.YaraInventory.Where(f => f.StartsWith(contentRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal)).ToArray();

            Assert.Equal(Directory.EnumerateFiles(contentRoot, "*", SearchOption.AllDirectories), underRoot);
            Assert.NotEmpty(underRoot);
        }
        finally
        {
            RemoveStray(slipName);
        }
    }

    // What Open hands out on that package, pinned: the lib dll and the case-collision survivor(s) as assemblies, the
    // script, the nuspec, and (Windows only, where NTFS overwrites one of the pair) the lost twin as uninventoried. The
    // zip-slip entry is never an assembly and never uninventoried, but its clamped bytes ARE in the YARA inventory, which
    // is still every file on disk under the extraction dir.
    [Fact]
    public void Open_OnAPackageWithAZipSlipEntryAndACaseCollision_InventoriesAsBefore_AndTheYaraInventoryIsUnchanged()
    {
        using var tree = new TempTree();
        var nupkg = N8Package(tree, out var slipName);
        try
        {
            using var pkg = Open(nupkg);

            var assemblies = pkg.Assemblies.Select(a => a.RelativePath).Order(StringComparer.Ordinal).ToArray();
            Assert.Contains($"lib/netstandard2.0/{fixture.FixtureDllName}", assemblies);
            Assert.DoesNotContain(assemblies, a => a.Contains(slipName, StringComparison.Ordinal));
            Assert.Equal(["tools/init.ps1"], pkg.Scripts.Select(s => s.RelativePath));
            Assert.Equal("PkgN8.nuspec", Path.GetFileName(pkg.NuspecPath));
            if (OperatingSystem.IsWindows())
            {
                var survivor = Assert.Single(assemblies, a => a.StartsWith("lib/net8.0/", StringComparison.Ordinal));
                Assert.Equal(CaseTwins.Single(t => t != survivor), Assert.Single(pkg.UninventoriedEntryNames));
            }
            else
            {
                Assert.Equal(CaseTwins.Order(StringComparer.Ordinal), assemblies.Where(a => a.StartsWith("lib/net8.0/", StringComparison.Ordinal)));
                Assert.Empty(pkg.UninventoriedEntryNames);
            }

            Assert.Equal(
                Directory.GetFiles(pkg.ExtractionDir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal),
                pkg.YaraInventory.Order(StringComparer.Ordinal));
            Assert.Single(pkg.YaraInventory, f => Path.GetFileName(f) == slipName);
        }
        finally
        {
            RemoveStray(slipName);
        }
    }

    // ContentRoot rule 2 (I5 W-b; it replaced N8's fallback walk). Given "x.nupkg." Win32 trims the dot, so the extractor's
    // directory is "x.nupkg", and the expected spelling Path.Combine(extractionDir, "x.nupkg.") is not among the top-level
    // directories: rule 1 misses, and the content root is the single top-level directory as spelled on disk. A root spelled
    // "x.nupkg." would match NO inventory path by prefix, and every entry would read uninventoried with 0 assemblies.
    // Opened through the trailing-dot path, the package must inventory exactly what it does through its plain path: the
    // same assemblies, scripts, nuspec and uninventoried entries.
    [WindowsExtractionFact("Win32 path normalization trims a trailing dot; on Linux 'x.nupkg.' is simply another, missing, file")]
    public void Open_OnWindows_ThroughATrailingDotPath_InventoriesWhatThePlainPathDoes()
    {
        using var tree = new TempTree();
        var nupkg = N8Package(tree, out var slipName);
        try
        {
            var dotted = nupkg + ".";
            Assert.True(File.Exists(dotted), "precondition: Win32 resolves the trailing-dot path to the package");

            using var plain = Open(nupkg);
            using var viaDot = Open(dotted);

            // Precondition: the expected spelling really does match nothing, so this exercises rule 2, not rule 1.
            var dottedRoot = Path.Combine(viaDot.ExtractionDir, Path.GetFileName(dotted));
            Assert.DoesNotContain(viaDot.YaraInventory, f => f.StartsWith(dottedRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal));

            Assert.True(viaDot.Assemblies.Count >= 2, $"only {viaDot.Assemblies.Count} assembl(ies) inventoried through the trailing-dot path");
            Assert.Equal(Shape(plain.Assemblies), Shape(viaDot.Assemblies));
            Assert.Equal(plain.Scripts.Select(s => (s.RelativePath, s.Role)), viaDot.Scripts.Select(s => (s.RelativePath, s.Role)));
            Assert.Equal(Path.GetFileName(plain.NuspecPath), Path.GetFileName(viaDot.NuspecPath));
            Assert.Equal(plain.UninventoriedEntryNames, viaDot.UninventoriedEntryNames);
            Assert.Equal(
                Directory.GetFiles(viaDot.ExtractionDir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal),
                viaDot.YaraInventory.Order(StringComparer.Ordinal));
        }
        finally
        {
            RemoveStray(slipName);
        }

        static string[] Shape(IEnumerable<PackageAssembly> assemblies) =>
            assemblies.Select(a => $"{a.RelativePath}|{a.TargetFramework}|{a.Role}|{a.Sha256}").ToArray();
    }
    #endregion

    #region Helpers
    private static NuGetPackage Open(string nupkg)
    {
        var opened = NuGetPackage.Open(nupkg);
        Assert.True(opened.IsSuccess, opened.Message);
        return opened.Value;
    }

    // The N8 package: the nuspec, a lib dll, a script, a "../../" zip-slip entry (its name unique per run) and two lib dlls
    // whose names differ only in case.
    private string N8Package(TempTree tree, out string slipName)
    {
        slipName = $"silvergun-n8slip-{Guid.NewGuid():N}.dll";
        var dll = File.ReadAllBytes(fixture.FixtureDllPath);
        var nupkg = Path.Combine(tree.Root, "PkgN8.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ("PkgN8.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml("PkgN8", "1.0.0", "Silvergun Tests", "ADR 0034 N8 package.", "netstandard2.0", []))),
                ($"lib/netstandard2.0/{fixture.FixtureDllName}", dll),
                ("tools/init.ps1", Encoding.UTF8.GetBytes("Write-Host 'installing'\n")),
                (CaseTwins[0], dll),
                (CaseTwins[1], dll),
            ],
            [("../../" + slipName, NupkgBuilder.NotManagedBytes)]);
        return nupkg;
    }

    // Should a regression ever let the traversal entry escape, it lands above the extraction dir: remove it, so a failing
    // run cannot leave a file loose in the shared temp directory.
    private static void RemoveStray(string slipName)
    {
        foreach (var dir in new[] { Path.GetTempPath(), Path.Combine(Path.GetTempPath(), "silvergun") })
            try { File.Delete(Path.Combine(dir, slipName)); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static readonly string[] CaseTwins = ["lib/net8.0/Twin.dll", "lib/net8.0/twin.dll"];
    #endregion
}
