namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

/// <summary>
/// Shared xUnit class fixture: initializes the Silvergun runtime once and stages the test
/// <c>.nupkg</c> files in a temp directory (built with pure BCL zip — see <see cref="NupkgBuilder"/>).
/// The staged packages reuse the real fixture assembly so end-to-end capability findings are known.
/// Disposal removes the temp directory.
/// </summary>
public sealed class PackageFixture : IDisposable
{
    #region Constructors
    public PackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-pkgtests", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        FixtureDllPath = typeof(Shapes).Assembly.Location;
        FixtureDllName = Path.GetFileName(FixtureDllPath);
        FixtureAssemblyName = typeof(Shapes).Assembly.GetName().Name!;
        var fixtureBytes = File.ReadAllBytes(FixtureDllPath);
        ExpectedFixtureSha256 = Convert.ToHexString(SHA256.HashData(fixtureBytes)).ToLowerInvariant();

        // PkgA: rich package — lib dll, tools script, build script, fake native content dll.
        var pkgANuspec = NupkgBuilder.NuspecXml(
            PkgAId, PkgAVersion, PkgAAuthors, PkgADescription, "netstandard2.0", DependencyIds);
        PkgAPath = Path.Combine(rootDir, $"{PkgAId}.{PkgAVersion}.nupkg");
        NupkgBuilder.WriteNupkg(PkgAPath,
        [
            ($"{PkgAId}.nuspec", Encoding.UTF8.GetBytes(pkgANuspec)),
            ($"lib/netstandard2.0/{FixtureDllName}", fixtureBytes),
            ("tools/init.ps1", Encoding.UTF8.GetBytes("Write-Host 'installing'\n")),
            ($"build/{PkgAId}.targets", Encoding.UTF8.GetBytes("<Project></Project>\n")),
            ("content/notmanaged.dll", NupkgBuilder.NotManagedBytes),
        ]);

        // PkgB: nuspec only — no assemblies, no scripts, no dependencies.
        var pkgBNuspec = NupkgBuilder.NuspecXml(
            PkgBId, PkgBVersion, "Silvergun Tests", "Empty test package.", "netstandard2.0", []);
        PkgBPath = Path.Combine(rootDir, $"{PkgBId}.{PkgBVersion}.nupkg");
        NupkgBuilder.WriteNupkg(PkgBPath,
        [
            ($"{PkgBId}.nuspec", Encoding.UTF8.GetBytes(pkgBNuspec)),
        ]);

        // PkgC: unconventional-layout package for intake-gap coverage (ADR 0004 §3 as amended).
        //  - a root-level dll (Role=Other, no TFM) — a concealment vector that must still be inventoried/scanned;
        //  - a runtimes RID/TFM path (Role=Runtimes, TargetFramework="net6.0");
        //  - a .props build script (Role=Build).
        // Both dlls are copies of the real fixture assembly so their capability findings are known.
        var pkgCNuspec = NupkgBuilder.NuspecXml(
            PkgCId, PkgCVersion, "Silvergun Tests", "Unconventional-layout test package.", "net6.0", []);
        PkgCPath = Path.Combine(rootDir, $"{PkgCId}.{PkgCVersion}.nupkg");
        NupkgBuilder.WriteNupkg(PkgCPath,
        [
            ($"{PkgCId}.nuspec", Encoding.UTF8.GetBytes(pkgCNuspec)),
            (HiddenDllName, fixtureBytes),
            ($"runtimes/win-x64/lib/net6.0/{FixtureDllName}", fixtureBytes),
            ($"build/{PkgCId}.props", Encoding.UTF8.GetBytes("<Project></Project>\n")),
        ]);

        // PkgD: zip-slip regression package. One benign lib dll plus one malicious entry whose name escapes
        // the extraction dir via "../../". The extractor must skip the traversal entry (never writing it to
        // disk, never inventorying it) while still extracting the benign lib. The guid keeps the traversal
        // target unique so parallel/repeated runs cannot collide on the same stray file.
        ZipSlipFileName = $"silvergun-zipslip-{Guid.NewGuid():N}.dll";
        ZipSlipRelativeEntry = "../../" + ZipSlipFileName;
        var pkgDNuspec = NupkgBuilder.NuspecXml(
            PkgDId, PkgDVersion, "Silvergun Tests", "Zip-slip regression test package.", "netstandard2.0", []);
        PkgDPath = Path.Combine(rootDir, $"{PkgDId}.{PkgDVersion}.nupkg");
        NupkgBuilder.WriteNupkg(
            PkgDPath,
            [
                ($"{PkgDId}.nuspec", Encoding.UTF8.GetBytes(pkgDNuspec)),
                ($"lib/netstandard2.0/{FixtureDllName}", fixtureBytes),
            ],
            [
                (ZipSlipRelativeEntry, NupkgBuilder.NotManagedBytes),
            ]);

        // PkgE: backslash-separator regression package. Its single lib assembly is written with a raw entry
        // name using BACKSLASH separators — `lib\netstandard2.0\<fixture dll>` — as produced by some Windows
        // packing tools. Role/TFM derivation must split on '\' as well as '/' (Role=Lib, TFM=netstandard2.0),
        // the stored RelativePath must be canonicalized to forward slashes, and the entry must still extract
        // and scan. The dll is a copy of the SensitiveOps-bearing fixture so its findings are known.
        var pkgENuspec = NupkgBuilder.NuspecXml(
            PkgEId, PkgEVersion, "Silvergun Tests", "Backslash-separator regression test package.", "netstandard2.0", []);
        PkgEPath = Path.Combine(rootDir, $"{PkgEId}.{PkgEVersion}.nupkg");
        NupkgBuilder.WriteNupkg(
            PkgEPath,
            [
                ($"{PkgEId}.nuspec", Encoding.UTF8.GetBytes(pkgENuspec)),
            ],
            [
                ($"lib\\netstandard2.0\\{FixtureDllName}", fixtureBytes),
            ]);

        // PkgBomb: decompression-bomb regression package (ADR 0008). A single, highly compressible payload
        // entry of ~50 MB of zero bytes — it zips to a few KB, giving a compression ratio in the thousands:1,
        // far above the extractor's 200:1 cap. RecursiveExtractor's resource governor must abort extraction
        // before materializing the payload, so NuGetPackage.Open returns a failure Result (never throws / OOMs).
        // Payload bytes are all zero: tiny to allocate here, but their decompressed size is what trips the cap.
        var pkgBombNuspec = NupkgBuilder.NuspecXml(
            BombId, BombVersion, "Silvergun Tests", "Decompression-bomb regression test package.", "netstandard2.0", []);
        BombPath = Path.Combine(rootDir, $"{BombId}.{BombVersion}.nupkg");
        NupkgBuilder.WriteNupkg(BombPath,
        [
            ($"{BombId}.nuspec", Encoding.UTF8.GetBytes(pkgBombNuspec)),
            ("content/bomb.bin", new byte[50_000_000]),
        ]);

        // Broken inputs: a text file renamed .nupkg, and a path that does not exist.
        FakeTextNupkgPath = Path.Combine(rootDir, "fake.nupkg");
        File.WriteAllText(FakeTextNupkgPath, "this is plain text, not a zip archive at all");
        MissingNupkgPath = Path.Combine(rootDir, $"missing-{Guid.NewGuid():N}.nupkg");
    }
    #endregion

    #region Properties
    // PkgA identity (must match the built nuspec).
    public const string PkgAId = "PkgA";
    public const string PkgAVersion = "1.2.3";
    public const string PkgAAuthors = "Silvergun Tests";
    public const string PkgADescription = "Rich test package with lib, tools, build and content payloads.";

    public const string PkgBId = "PkgB";
    public const string PkgBVersion = "2.0.0";

    public const string PkgCId = "PkgC";
    public const string PkgCVersion = "3.4.5";

    public const string PkgDId = "PkgD";
    public const string PkgDVersion = "4.5.6";

    public const string PkgEId = "PkgE";
    public const string PkgEVersion = "5.6.7";

    public const string BombId = "PkgBomb";
    public const string BombVersion = "6.7.8";

    /// <summary>Root-level dll in PkgC (no folder segment) — classifies as <c>Role=Other</c>.</summary>
    public const string HiddenDllName = "hidden.dll";

    /// <summary>The two declared dependencies of PkgA (id, version).</summary>
    public static readonly (string Id, string Version)[] DependencyIds =
        [("Newtonsoft.Json", "13.0.1"), ("Serilog", "3.1.1")];

    public string PkgAPath { get; }
    public string PkgBPath { get; }
    public string PkgCPath { get; }
    public string PkgDPath { get; }
    public string PkgEPath { get; }

    /// <summary>Decompression-bomb package: one ~50 MB all-zero entry that zips tiny (ratio far above the 200:1 cap).</summary>
    public string BombPath { get; }

    public string FakeTextNupkgPath { get; }
    public string MissingNupkgPath { get; }

    /// <summary>Bare file name of PkgD's malicious traversal entry (e.g. <c>silvergun-zipslip-&lt;guid&gt;.dll</c>).</summary>
    public string ZipSlipFileName { get; }

    /// <summary>PkgD's malicious entry name as packaged — <c>../../&lt;ZipSlipFileName&gt;</c>.</summary>
    public string ZipSlipRelativeEntry { get; }

    public string FixtureDllPath { get; }
    public string FixtureDllName { get; }

    /// <summary>Simple assembly name of the fixture dll (no extension), e.g. <c>Silvergun.CodeAnalysis.IL.Tests.Fixture</c>.</summary>
    public string FixtureAssemblyName { get; }

    /// <summary>Lowercase-hex SHA-256 of the fixture dll bytes as packaged into PkgA.</summary>
    public string ExpectedFixtureSha256 { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir))
                Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }

        // Belt-and-braces: if a regression ever let PkgD's traversal entry escape, it lands one level above
        // each pkg-* extraction dir — i.e. directly under the temp path. Remove any such stray so a failing
        // run cannot leave a file loose in the shared temp directory.
        try
        {
            var stray = Path.Combine(Path.GetTempPath(), ZipSlipFileName);
            if (File.Exists(stray))
                File.Delete(stray);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
