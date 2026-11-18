namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static NativeHeaderBuilder;

/// <summary>
/// native-binaries-2 at the package and report level: a minimal native PE (or ELF) carrying the .NET host marker gets
/// its <see cref="NativeBinary.DotNetHost"/> / <see cref="NativeBinary.BundledFiles"/> from
/// <see cref="NuGetPackage.Open"/> and <see cref="PackageScanner.Scan"/>, whatever its name; the hash is still the whole
/// file's; and the JSON contract (round trip; legacy NativeBinary JSON without the fields reads None/null).
/// </summary>
public sealed class DotNetHostPackageTests
{
    #region Methods: NuGetPackage.Open
    [Fact]
    public void Open_HostMarkedBinaries_CarryTheirDotNetHost_WhateverTheirName()
    {
        using var tree = new TempTree();
        using var package = Open(HostPackage(tree));

        Assert.Equal(5, package.NativeBinaries.Count);
        Assert.Equal((DotNetHost.AppHost, (int?)null), HostOf(package, "tools/mytool"));
        Assert.Equal((DotNetHost.AppHost, (int?)null), HostOf(package, "tools/MyTool.exe"));
        Assert.Equal((DotNetHost.SingleFileBundle, (int?)3), HostOf(package, "tools/Bundle.exe"));
        Assert.Equal((DotNetHost.HostTemplate, (int?)null), HostOf(package, "tools/apphost.exe"));
        Assert.Equal((DotNetHost.None, (int?)null), HostOf(package, "tools/native.exe"));
    }

    // The marker is a label only: an apphost is still a native PE executable with the whole file's size and hash.
    [Fact]
    public void Open_AnAppHost_IsStillANativeExecutableWithTheWholeFilesHash()
    {
        using var tree = new TempTree();
        using var package = Open(HostPackage(tree));

        var apphost = Assert.Single(package.NativeBinaries, b => b.RelativePath == "tools/mytool");
        Assert.Equal(NativeBinaryFormat.PE, apphost.Format);
        Assert.Equal(NativeBinaryKind.Executable, apphost.Kind);
        Assert.Equal(NativeBinaryCode.Native, apphost.Code);
        Assert.Equal(PackageItemRole.Tools, apphost.Role);
        Assert.Equal(AppHostBytes.Length, apphost.Size);
        Assert.Equal(Sha256(AppHostBytes), apphost.Sha256);

        var bundle = Assert.Single(package.NativeBinaries, b => b.RelativePath == "tools/Bundle.exe");
        Assert.Equal(BundleBytes.Length, bundle.Size);
        Assert.Equal(Sha256(BundleBytes), bundle.Sha256);
    }

    // A Linux apphost is an ELF: the scan runs for every detected binary, not just PEs.
    [Fact]
    public void Open_AnElfCarryingTheSignature_IsAnAppHost()
    {
        using var tree = new TempTree();
        var elf = WithOverlay(Elf(true, true, EtDyn, EmX64, [PtLoad, PtInterp]));
        var nupkg = Path.Combine(tree.Root, "PkgElfHost.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg, [Nuspec("PkgElfHost"), ("tools/linux-x64/mytool", elf)]);

        using var package = Open(nupkg);

        var binary = Assert.Single(package.NativeBinaries);
        Assert.Equal(NativeBinaryFormat.Elf, binary.Format);
        Assert.Equal(DotNetHost.AppHost, binary.DotNetHost);
        Assert.Equal(Sha256(elf), binary.Sha256);
    }

    // Review W1: a managed PE that merely holds the signature as data (Microsoft.NET.HostModel.dll, ReadyToRun in SDK 8+)
    // is not a host. Only a Native-code binary is labelled; ReadyToRun, ILOnly and MixedMode read None / null, whatever
    // the offset says. The same overlay on a native PE in the same package is still an AppHost.
    [Theory]
    [InlineData("lib/net8.0/Microsoft.NET.HostModel.dll", "ReadyToRun", false)]
    [InlineData("lib/net8.0/Microsoft.NET.HostModel.dll", "ReadyToRun", true)]
    [InlineData("tools/payload", "ILOnly", false)]
    [InlineData("tools/payload", "ILOnly", true)]
    [InlineData("lib/net8.0/mixed.dll", "MixedMode", false)]
    [InlineData("lib/net8.0/mixed.dll", "MixedMode", true)]
    public void Open_AManagedPeCarryingTheSignature_IsNotAHost(string path, string code, bool bundleOffset)
    {
        var expected = Enum.Parse<NativeBinaryCode>(code);
        var image = expected switch
        {
            NativeBinaryCode.ReadyToRun => ManagedPe.Patch(flags: CorILLibrary | CorStrongNameSigned, managedNativeHeader: (0x2000, 0x50)),
            NativeBinaryCode.ILOnly => ManagedPe.Patch(flags: CorILOnly, managedNativeHeader: (0, 0)),
            _ => ManagedPe.Patch(flags: CorStrongNameSigned, managedNativeHeader: (0, 0)),
        };
        var managed = bundleOffset ? WithOverlay(image, header: (6, 3)) : WithOverlay(image);
        using var tree = new TempTree();
        const string id = "PkgManagedSig";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg, [Nuspec(id), (path, managed), ("tools/mytool", AppHostBytes)]);
        // The scanner alone does see the marker: it is the Code gate that drops it.
        Assert.Equal(bundleOffset ? DotNetHost.SingleFileBundle : DotNetHost.AppHost, ScanBytes(managed));

        using var package = Open(nupkg);

        var binary = Assert.Single(package.NativeBinaries, b => b.RelativePath == path);
        Assert.Equal(expected, binary.Code);
        Assert.Equal(DotNetHost.None, binary.DotNetHost);
        Assert.Null(binary.BundledFiles);
        Assert.Equal(managed.Length, binary.Size);
        Assert.Equal(Sha256(managed), binary.Sha256);
        Assert.Equal((DotNetHost.AppHost, (int?)null), HostOf(package, "tools/mytool"));
    }

    // The marker alone does not make a file a native binary: a text file carrying it is not listed.
    [Fact]
    public void Open_ANonBinaryCarryingTheSignature_IsNotListed()
    {
        using var tree = new TempTree();
        var text = WithOverlay(Encoding.ASCII.GetBytes("just text, not a binary\n"));
        var nupkg = Path.Combine(tree.Root, "PkgTextSig.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg, [Nuspec("PkgTextSig"), ("tools/readme", text)]);

        using var package = Open(nupkg);

        Assert.Empty(package.NativeBinaries);
    }
    #endregion

    #region Methods: PackageScanner.Scan and JSON
    [Fact]
    public void Scan_HostMarkedBinaries_ReachTheReport()
    {
        using var tree = new TempTree();

        var report = Scan(HostPackage(tree));

        Assert.Equal(NativeBinaryScanStatus.Completed, report.NativeBinaryScanStatus);
        var bundle = Assert.Single(report.NativeBinaries, b => b.RelativePath == "tools/Bundle.exe");
        Assert.Equal(DotNetHost.SingleFileBundle, bundle.DotNetHost);
        Assert.Equal(3, bundle.BundledFiles);
        Assert.Equal(2, report.NativeBinaries.Count(b => b.DotNetHost == DotNetHost.AppHost));
    }

    [Fact]
    public void ARoundTrip_PreservesDotNetHostAndBundledFiles()
    {
        using var tree = new TempTree();
        var report = Scan(HostPackage(tree));

        var json = report.ToJson();
        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(report.NativeBinaries, restored.NativeBinaries);
        Assert.Equal(json, restored.ToJson());
        Assert.Contains("\"DotNetHost\": \"SingleFileBundle\"", json, StringComparison.Ordinal);
        Assert.Contains("\"DotNetHost\": \"HostTemplate\"", json, StringComparison.Ordinal);
        Assert.Contains("\"BundledFiles\": 3", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ARoundTrip_OfAHandBuiltBundleWithNoCount_KeepsTheNullCount()
    {
        var binary = new NativeBinary("tools/Squirrel.exe", NativeBinaryFormat.PE, NativeBinaryKind.Executable, "x86",
            NativeBinaryCode.Native, PackageItemRole.Tools, 7_000_000, new string('a', 64), DotNetHost.SingleFileBundle, null);

        var restored = PackageCapabilityReport.FromJson(Report(binary).ToJson())!;

        Assert.Equal(binary, Assert.Single(restored.NativeBinaries));
    }

    // A NativeBinary written before native-binaries-2 has neither field: it reads None / null.
    [Fact]
    public void LegacyNativeBinaryJson_WithoutTheFields_ReadsNoneAndNull()
    {
        const string legacyJson = """
            {
              "Package": { "Id": "Legacy.Package", "Version": "1.0.0", "Authors": "Old Author", "Description": "Old.", "Dependencies": [] },
              "AnalyzedAt": "2020-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": [],
              "NativeBinaryScanStatus": "Completed",
              "NativeBinaries": [
                {
                  "RelativePath": "tools/mytool",
                  "Format": "PE",
                  "Kind": "Executable",
                  "Architecture": "x64",
                  "Code": "Native",
                  "Role": "Tools",
                  "Size": 1024,
                  "Sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
              ]
            }
            """;

        var restored = PackageCapabilityReport.FromJson(legacyJson)!;

        var binary = Assert.Single(restored.NativeBinaries);
        Assert.Equal("tools/mytool", binary.RelativePath);
        Assert.Equal(1024, binary.Size);
        Assert.Equal(DotNetHost.None, binary.DotNetHost);
        Assert.Null(binary.BundledFiles);
    }
    #endregion

    #region Methods: helpers
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

    private static (DotNetHost, int?) HostOf(NuGetPackage package, string path)
    {
        var b = Assert.Single(package.NativeBinaries, b => b.RelativePath == path);
        return (b.DotNetHost, b.BundledFiles);
    }

    // An extensionless apphost and a .exe apphost, a bundle, a host template, and a plain native exe.
    private static string HostPackage(TempTree tree)
    {
        const string id = "PkgDotNetHosts";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(nupkg,
        [
            Nuspec(id),
            ("tools/mytool", AppHostBytes),
            ("tools/MyTool.exe", AppHostBytes),
            ("tools/Bundle.exe", BundleBytes),
            ("tools/apphost.exe", TemplateBytes),
            ("tools/native.exe", PlainExe),
        ]);
        return nupkg;
    }

    // `image` (unchanged, so its headers parse as before) followed by an overlay:
    // [8-byte offset][signature][optional placeholder][bundle header slot, 16 bytes]. With a header the offset points at
    // that slot, AFTER the signature as the bundler lays it out; otherwise the offset is 0.
    private static byte[] WithOverlay(byte[] image, (uint Major, int Count)? header = null, bool placeholder = false)
    {
        var signatureAt = image.Length + 8;
        var headerAt = signatureAt + 32 + (placeholder ? 64 : 0);
        var bytes = image.Concat(new byte[headerAt - image.Length + 16]).ToArray();
        DotNetHostScannerTests.Put(bytes, signatureAt, header is null ? 0 : headerAt);
        if (header is { } h)
            DotNetHostScannerTests.Header(bytes, headerAt, h.Major, 0, h.Count);
        if (placeholder)
            DotNetHostScannerTests.Placeholder.CopyTo(bytes, signatureAt + 32);
        return bytes;
    }

    private static (string, byte[]) Nuspec(string id) =>
        ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", "native-binaries-2 test package.", "net8.0", [])));

    private static PackageCapabilityReport Report(params NativeBinary[] binaries) =>
        new(new PackageIdentityInfo("Host.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch, Array.Empty<AssemblyScanResult>(), Array.Empty<PackageScript>(), Array.Empty<ScriptFinding>(),
            YaraScanStatus: YaraScanStatus.Completed, ScriptScanStatus: ScriptScanStatus.Completed,
            NativeBinaries: binaries, NativeBinaryScanStatus: NativeBinaryScanStatus.Completed);

    private static DotNetHost ScanBytes(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        return DotNetHostScanner.HashAndScan(stream).Host;
    }

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    #endregion

    #region Fields
    private static readonly byte[] PlainExe = Pe(MachineAmd64, CharExecutable, pe32Plus: true);
    private static readonly byte[] AppHostBytes = WithOverlay(PlainExe);
    private static readonly byte[] BundleBytes = WithOverlay(PlainExe, header: (6, 3));
    private static readonly byte[] TemplateBytes = WithOverlay(PlainExe, placeholder: true);
    #endregion
}
