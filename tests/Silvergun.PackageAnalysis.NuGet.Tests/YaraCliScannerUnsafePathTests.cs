namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Regression tests for the ADR 0029 fix in <see cref="YaraCliScanner"/> — the
/// control-character-in-an-entry-name false negative — plus the <c>ScanFile</c>/<c>ScanOne</c> null-vs-empty
/// refactor that shipped with it.
///
/// <para><b>Two tiers, on purpose.</b> The <see cref="FactAttribute"/> tests need no engine at all: they point
/// <c>SILVERGUN_YARA_PATH</c> at a placeholder file so the scanner reports <c>Available</c>, prepares its ruleset
/// and then genuinely fails to launch a process. They run everywhere. The <see cref="LinuxYaraFactAttribute"/>
/// tests drive a <b>real</b> <c>yara</c> over a directory containing a file whose name holds a newline; that name
/// cannot exist on NTFS, so those tests are skipped (visibly, in the run's <c>Skipped</c> count) on Windows and
/// must be executed under WSL for this ADR to have any regression coverage at all.</para>
///
/// <para>The positive control they scan is derived from the embedded rule at run time — see
/// <see cref="HermeticWiperSample"/> for what it is and where it comes from.</para>
///
/// <para><b>What is deliberately NOT here.</b> This class used to assert that a <c>ScanDirectory</c> whose engine
/// could not be launched, or whose engine exited non-zero, <i>returned an empty list</i>. Those two tests pinned
/// the fail-open behaviour that ADR 0029's amendment identifies as attacker-reachable, and the rationale attached
/// to them ("already covered by <c>Available</c> / the Unavailable status") was simply untrue. They are replaced,
/// not softened, by <see cref="YaraCliFailClosedTests"/>, which asserts <c>Unavailable</c> for each of the five
/// ways a directory scan can fail to happen.</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraCliScannerUnsafePathTests
{
    #region Constructors
    public YaraCliScannerUnsafePathTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods
    // --- Recovery and attribution, real engine, Linux only ---------------------------------------------------

    // THE ADR 0029 regression. A directory holding one safe-named matching file and one matching file whose name
    // contains a newline: `yara -r` echoes the scanned path on each header line and YaraCliOutput.ParseAll splits
    // stdout on LF, so before the fix the newline-named file's hit was split across two physical lines, failed
    // TargetMatches and was silently dropped — 1 finding instead of 2, status Completed. After the fix the batch
    // pass attributes only safe-named files and the newline-named file is re-scanned through a safely named copy,
    // so BOTH hits are present, each attributed to its ORIGINAL path, and neither is double-counted.
    [LinuxYaraFact]
    public void ScanDirectory_WithControlCharacterNamedMatch_RecoversTheHitAgainstTheOriginalPathExactlyOnce()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var safe = tree.Write("lib/net8.0/safe.bin", HermeticWiperSample.Bytes);
        var hostile = tree.Write("lib/net8.0/n\nl.bin", HermeticWiperSample.Bytes);
        tree.Write("lib/net8.0/clean.txt", "no signature here\n");

        var scanner = new YaraCliScanner();
        Assert.True(scanner.Available, "The Linux integration tier requires a real yara binary.");

        var hits = scanner.ScanDirectory(tree.Root);

        // Exactly two hits: one per matching file, and the recovered one is NOT counted twice (the whole reason
        // unsafe-named files are excluded from batch attribution rather than merely re-scanned in addition).
        Assert.Equal(2, hits.Count);
        Assert.Single(hits, h => h.FullPath == safe);
        Assert.Single(hits, h => h.FullPath == hostile);
        Assert.All(hits, h => Assert.Equal(HermeticWiperSample.RuleName, h.Match.Rule));

        // The recovered hit is attributed to the ORIGINAL path, not to the temp copy the engine actually saw.
        var recovered = hits.Single(h => h.FullPath == hostile);
        Assert.Contains("\n", recovered.FullPath, StringComparison.Ordinal);
        Assert.True(File.Exists(recovered.FullPath), "The attributed path must be the real file on disk.");
    }

    // Recovery that finds nothing is still recovery: a control-character-named file that does NOT match must leave
    // the scan complete (no throw, no phantom hit) while a safe-named file's genuine hit still comes back. Without
    // this, "fail closed" could be implemented as "throw whenever an unsafe name exists", which would turn every
    // hostile-but-clean package into an Unavailable scan.
    [LinuxYaraFact]
    public void ScanDirectory_WithControlCharacterNamedNonMatch_CompletesWithoutThrowing()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var safe = tree.Write("lib/net8.0/safe.bin", HermeticWiperSample.Bytes);
        tree.Write("content/be\rnign.bin", "nothing matching in here at all\n");
        tree.Write("content/car\nriage.txt", "still nothing\n");

        var scanner = new YaraCliScanner();

        var hits = scanner.ScanDirectory(tree.Root);

        var hit = Assert.Single(hits);
        Assert.Equal(safe, hit.FullPath);
        Assert.Equal(HermeticWiperSample.RuleName, hit.Match.Rule);
    }

    // ADR 0029 decision 13 at its source. When an unsafe-named file cannot be copied to a safely named temp file
    // it was never scanned, so ScanDirectory must throw rather than return a partial list. The unreadable file is
    // staged with mode 000 (this suite does not run as root), which makes File.Copy fail deterministically.
    //
    // The message is asserted to carry NO raw control character: it is built from attacker-authored path text and
    // is logged verbatim, so a raw newline in it would let a package forge a line in our own log.
    [LinuxYaraFact]
    public void ScanDirectory_WhenAnUnsafeNamedFileCannotBeRecovered_ThrowsWithAFullyEscapedMessage()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        tree.Write("lib/net8.0/safe.bin", HermeticWiperSample.Bytes);
        var unreadable = tree.Write("lib/net8.0/un\nreadable.bin", HermeticWiperSample.Bytes);
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("[LinuxYaraFact] must have gated this test to Linux.");
        File.SetUnixFileMode(unreadable, UnixFileMode.None);
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllBytes(unreadable));

        var scanner = new YaraCliScanner();

        var ex = Assert.Throws<YaraScanIncompleteException>(() => scanner.ScanDirectory(tree.Root));

        // Every character of the message is printable: no C0, no DEL/C1, no separators, no bidi controls.
        Assert.All(ex.Message, c => Assert.False(
            c < ' ' || c is >= (char)0x7F and <= (char)0x9F or (char)0x2028 or (char)0x2029
                        or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069,
            $"YaraScanIncompleteException.Message carried raw U+{(int)c:X4}."));

        // ...and it still identifies the offending entry, escaped, so the message is actionable rather than merely safe.
        Assert.Contains(@"un\nreadable.bin", ex.Message, StringComparison.Ordinal);
    }

    // The same recovery, driven end to end through PackageScanner over a real .nupkg whose entry name carries a
    // newline (legal in a zip entry; RecursiveExtractor writes it to disk verbatim). This is the shape the ADR was
    // found in: before the fix the report read Completed with the hostile file's hit missing. The injected
    // YaraCliScanner bypasses the process-wide memoized factory so the backend under test is unambiguous.
    [LinuxYaraFact]
    public void Scan_PackageWithControlCharacterEntryName_ReportsBothHitsAndCompletes()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        const string id = "PkgUnsafeName";
        var nupkg = Path.Combine(tree.Root, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(
            nupkg,
            [
                ($"{id}.nuspec", Encoding.UTF8.GetBytes(NupkgBuilder.NuspecXml(
                    id, "1.0.0", "Silvergun Tests", "Control-character entry-name regression package.",
                    "netstandard2.0", []))),
                ("content/safe.bin", HermeticWiperSample.Bytes),
            ],
            [
                ("content/n\nl.bin", HermeticWiperSample.Bytes),
            ]);

        var scan = PackageScanner.Scan(nupkg, runYara: true, yaraScanner: new YaraCliScanner());

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Equal(2, scan.Value.YaraFindings.Count);
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == "content/safe.bin");
        // Escaped at the report boundary (ADR 0031 decision 4): the newline is a literal backslash-n here, which is
        // precisely the wart ADR 0029 left open (a raw newline reaching the report layer). The recovery behaviour
        // this test pins is unchanged — BOTH hits are present and the scan still reads Completed.
        Assert.Single(scan.Value.YaraFindings, f => f.RelativePath == @"content/n\nl.bin");
        Assert.All(scan.Value.YaraFindings, f => Assert.Equal(HermeticWiperSample.RuleName, f.RuleName));
    }

    // --- ScanFile's null-vs-empty contract, everywhere -------------------------------------------------------

    // The refactor that shipped with ADR 0029 moved ScanFile onto a ScanOne that returns NULL for "did not scan"
    // (so the recovery pass can tell that apart from "scanned, no hits"). ScanFile must still flatten null to an
    // empty list: a missing file is a per-file error the never-throws contract requires it to swallow.
    [Fact]
    public void ScanFile_WhenTheFileIsMissing_ReturnsEmptyAndDoesNotThrow()
    {
        using var fake = new PlaceholderYaraBinary();
        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available, "A SILVERGUN_YARA_PATH that resolves to an existing file reads as available.");
        Assert.Empty(scanner.ScanFile(Path.Combine(fake.Directory, "no-such-file-" + Guid.NewGuid().ToString("N") + ".bin")));
    }

    // Degenerate paths take the same swallowed route — empty, never null, never a throw.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ScanFile_ForDegeneratePaths_ReturnsEmptyAndDoesNotThrow(string path)
    {
        using var fake = new PlaceholderYaraBinary();

        Assert.Empty(new YaraCliScanner().ScanFile(path));
    }

    // The yara "binary" exists (so the backend reports Available) but cannot be launched. ScanFile must return
    // empty rather than propagating the Win32Exception — unlike ScanDirectory, which fails closed for the same
    // condition (YaraCliFailClosedTests).
    [Fact]
    public void ScanFile_WhenTheYaraBinaryCannotBeLaunched_ReturnsEmptyAndDoesNotThrow()
    {
        using var fake = new PlaceholderYaraBinary();
        using var tree = new TempTree();
        var target = tree.Write("lib/net8.0/payload.bin", HermeticWiperSample.Bytes);

        var scanner = new YaraCliScanner();

        Assert.True(scanner.Available);
        Assert.Empty(scanner.ScanFile(target));
    }

    // --- The two directory cases that are genuinely "nothing to scan" ----------------------------------------

    // A missing root is not an incomplete scan: there was nothing under it to miss. Empty, no throw.
    [Fact]
    public void ScanDirectory_WhenTheDirectoryIsMissing_ReturnsEmptyAndDoesNotThrow()
    {
        using var fake = new PlaceholderYaraBinary();
        var missing = Path.Combine(Path.GetTempPath(), "silvergun-no-such-dir-" + Guid.NewGuid().ToString("N"));

        Assert.Empty(new YaraCliScanner().ScanDirectory(missing));
    }

    // An empty directory is a completed scan with no hits — the trivial base case that must not be confused with
    // an incomplete one now that ScanDirectory has a throwing path. Note that it also spends no process: with
    // nothing to attribute there is nothing for a recursive pass to do.
    [Fact]
    public void ScanDirectory_OverAnEmptyDirectory_ReturnsEmptyAndDoesNotThrow()
    {
        using var fake = new PlaceholderYaraBinary();
        using var tree = new TempTree();

        Assert.Empty(new YaraCliScanner().ScanDirectory(tree.Root));
    }

    // The name predicate the partition depends on agrees with the fixture this suite stages: if this ever read
    // false, the Linux tests above would silently degrade into ordinary batch scans and stop testing the ADR.
    [Fact]
    public void TheStagedHostileName_IsClassifiedUnsafe()
    {
        Assert.True(YaraPathSafety.IsUnsafeName("/tmp/pkg/lib/net8.0/n\nl.bin"));
        Assert.False(YaraPathSafety.IsUnsafeName("/tmp/pkg/lib/net8.0/safe.bin"));
    }
    #endregion
}
