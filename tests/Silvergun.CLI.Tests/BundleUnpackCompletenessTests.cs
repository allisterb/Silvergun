namespace Silvergun.CLI.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Silvergun.CLI.Reports;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Tests;

using Xunit;

using static Silvergun.PackageAnalysis.NuGet.Tests.NativeHeaderBuilder;
using static Silvergun.PackageAnalysis.NuGet.Tests.SingleFileBundleBuilder;

/// <summary>
/// native-binaries-3 through <see cref="CompletenessAssessment.ForPackage"/>: a single-file bundle entry that could not
/// be extracted is a file that produced no analysis, so the package is not complete and the caveat names the
/// <c>host!/entry</c> path; it is not counted as a never-extracted declared entry. A bundle that unpacks fully adds no
/// file caveat. In-process <see cref="PackageScanner.Scan"/> over synthetic packages (no vulns, no YARA).
/// </summary>
public sealed class BundleUnpackCompletenessTests
{
    #region Methods
    [Fact]
    public void ForPackage_AnUnextractedBundleEntry_MakesThePackageIncomplete()
    {
        var bad = new Entry("bad.dll", new byte[100], Compress: true) { Stored = [0x07, 0xFF, 0xFF, 0xFF] };
        var report = Scan("PkgBundleIncomplete", Hosted(NativeExe, [new("X.dll", ManagedPe.Bytes), bad]));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        // The extensionless host is not an assembly: the files are X.dll (analysed) and bad.dll (not).
        Assert.Contains("1 of 2 file(s) could not be analysed: tools/app!/bad.dll", assessment.Caveats);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("never extracted", StringComparison.Ordinal));
    }

    [Fact]
    public void ForPackage_AFullyUnpackedBundle_AddsNoFileCaveat()
    {
        var report = Scan("PkgBundleComplete", Hosted(NativeExe, [new("X.dll", ManagedPe.Bytes, Compress: true)]));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.NotNull(Assert.Single(report.Assemblies, a => a.Assembly.RelativePath == "tools/app!/X.dll").Report);
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("could not be analysed", StringComparison.Ordinal));
        Assert.DoesNotContain(assessment.Caveats, c => c.Contains("never extracted", StringComparison.Ordinal));
    }

    // Review round 1: a bundle nested in a bundle is labelled, not unpacked, and its contents were never analysed.
    [Fact]
    public void ForPackage_ANestedBundle_MakesThePackageIncomplete()
    {
        var inner = Hosted(NativeExe, [new("Deep.dll", ManagedPe.Bytes)]);
        var report = Scan("PkgBundleNestedIncomplete", Hosted(NativeExe, [new("X.dll", ManagedPe.Bytes), new("inner.exe", inner)]));

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Contains("1 of 2 file(s) could not be analysed: tools/app!/inner.exe", assessment.Caveats);
    }

    // W5: a bundle whose header failed its checks (placed before the signature) is one whole-bundle gap.
    [Fact]
    public void ForPackage_ABundleWhoseHeaderFailedItsChecks_MakesThePackageIncomplete()
    {
        var header = new byte[16];
        BitConverter.GetBytes(6u).CopyTo(header, 0);
        BitConverter.GetBytes(3).CopyTo(header, 8);
        byte[] host = [.. NativeExe, .. header, .. BitConverter.GetBytes((long)NativeExe.Length), .. Signature, .. new byte[64]];
        var report = Scan("PkgBundleHeaderFailed", host);

        var assessment = CompletenessAssessment.ForPackage(report);

        Assert.False(assessment.IsComplete);
        Assert.Contains("1 of 1 file(s) could not be analysed: tools/app!/", assessment.Caveats);
    }
    #endregion

    #region Methods: helpers
    private static PackageCapabilityReport Scan(string id, byte[] host)
    {
        var nupkg = Path.Combine(Path.GetTempPath(), $"silvergun-bundle-{Guid.NewGuid():N}.nupkg");
        try
        {
            using (var zip = new ZipArchive(new FileStream(nupkg, FileMode.Create, FileAccess.Write), ZipArchiveMode.Create))
            {
                Write(zip, $"{id}.nuspec", Encoding.UTF8.GetBytes($"""
                    <?xml version="1.0" encoding="utf-8"?>
                    <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                      <metadata>
                        <id>{id}</id>
                        <version>1.0.0</version>
                        <authors>Silvergun Tests</authors>
                        <description>native-binaries-3 test package.</description>
                      </metadata>
                    </package>
                    """));
                Write(zip, "tools/app", host);
            }

            var scan = PackageScanner.Scan(nupkg, resolveReferences: false, runYara: false);
            Assert.True(scan.IsSuccess, scan.Message);
            return scan.Value;
        }
        finally
        {
            try { File.Delete(nupkg); } catch (IOException) { /* best-effort temp cleanup */ }
        }

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }
    #endregion

    #region Fields
    private static readonly byte[] NativeExe = Pe(MachineAmd64, CharExecutable, pe32Plus: true);
    #endregion
}
