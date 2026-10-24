namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// ADR 0034 end to end, through <see cref="PackageScanner.Scan"/>: <b>a file extracted from the package and deleted before
/// YARA reaches it makes the package <see cref="YaraScanStatus.Unavailable"/>, never <see cref="YaraScanStatus.Completed"/>
/// — and never Completed-and-clean when every file is gone.</b> That is the Storage Sense shape of the ADR's Context:
/// files under <c>%TEMP%</c> with package-chosen timestamps, swept while the CIL analysis runs.
///
/// <para>The backend is a <see cref="DeletingScanner"/> wrapped around a REAL one: on the way into either scan entry it
/// deletes the chosen extracted files, then delegates unchanged. Deleting in <c>ScanDirectory</c> too is what makes these
/// the main red-proof for <c>PackageScanner.ScanYara</c>: wired back to <c>ScanDirectory(root)</c>, the backend's own walk
/// simply never sees the file, and the package reads Completed. The real backends: the classic CLI (the FakeYaraProbe as
/// its yara on every platform; the real yara under WSL) and, on net10.0-windows, the in-process LibYaraScanner. The
/// default Windows backend, the YARA-X worker, is driven the same way from a child process in
/// <see cref="YaraInventoryYaraXTests"/> (it must not use the user's rules cache).</para>
/// </summary>
[Collection(YaraEnvCollection.Name)]
public sealed class YaraInventoryPackageScannerTests
{
    #region Constructors
    public YaraInventoryPackageScannerTests() => YaraCliProbe.EnforceBinaryRequirement();
    #endregion

    #region Methods: the classic CLI backend (FakeYaraProbe)
    [Fact]
    public void Scan_WhenAnExtractedFileIsDeletedBeforeYara_IsUnavailable_NamesItAsGone_AndKeepsTheOtherFinding()
    {
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvCliOne", "ordinary content\n"u8.ToArray());
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var inner = new YaraCliScanner();
        var backend = new DeletingScanner(inner, VanishName);

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(1, backend.Deleted);   // the double really did delete one extracted file, so this is not vacuous
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal(("Fake_Rule", "content/payload.bin"), (finding.RuleName, finding.RelativePath));
        var reason = scan.Value.YaraUnavailableReason!;
        Assert.StartsWith(YaraInventoryCliTests.Lead(1, 1) + "1 of them no longer exists (removed after it was listed): '", reason, StringComparison.Ordinal);
        Assert.Contains("vanish" + EscapedRlo + ".bin'", reason[reason.IndexOf("no longer exist", StringComparison.Ordinal)..], StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(reason);
    }

    // The 512-char cap on YaraUnavailableReason (N2): with several LONG missing names — and another unrecovered file
    // besides — the reason still says WHY, because the missing clause now leads the message. With the old trailing
    // clause these names filled the bound first and the cause was cut off (the shape of the test below this one).
    [Fact]
    public void Scan_WithSeveralLongMissingNames_TheBoundedReasonStillCarriesTheNoLongerExistClause()
    {
        using var tree = new TempTree();
        var longNames = Enumerable.Range(0, 5).Select(i => $"long-{i}-" + new string('n', 110) + ".bin").ToArray();
        var nupkg = YaraCliStderrErrorLineTests.WritePackageBytes(tree, "PkgInvCap",
        [
            ("content/payload.bin", "ordinary content\n"u8.ToArray()),
            ("content/stuck.bin", "ordinary content\n"u8.ToArray()),
            .. longNames.Select(n => ($"content/{n}", "ordinary content\n"u8.ToArray())),
        ], []);
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin", sentinelSkip: "stuck.bin", singleFileFail: "stuck.bin");
        using var inner = new YaraCliScanner();
        var backend = new DeletingScanner(inner, "long-*");

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(5, backend.Deleted);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal(("Fake_Rule", "content/payload.bin"), (Assert.Single(scan.Value.YaraFindings).RuleName, scan.Value.YaraFindings[0].RelativePath));
        var reason = scan.Value.YaraUnavailableReason!;
        Assert.Equal(PackageCapabilityReport.MaxYaraUnavailableReasonChars, reason.Length);   // precondition: the bound did cut
        Assert.Contains("5 of them no longer exist (each removed after it was listed)", reason, StringComparison.Ordinal);   // survived the cut
        Assert.StartsWith(YaraInventoryCliTests.Lead(6, 6) + "5 of them no longer exist (each removed after it was listed): '", reason, StringComparison.Ordinal);
    }

    // Every extracted file gone (the nuspec too): Unavailable with nothing found — not Completed with an empty list,
    // which is the clean report ADR 0030 exists to prevent.
    [Fact]
    public void Scan_WhenEveryExtractedFileIsDeletedBeforeYara_IsUnavailable_NotCompletedAndClean()
    {
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvCliAll", "ordinary content\n"u8.ToArray());
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var inner = new YaraCliScanner();
        var backend = new DeletingScanner(inner, "*");
        using var warnings = new Silvergun.Tests.Shared.WarningCapture();

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(4, backend.Deleted);   // nuspec, payload, vanish, notes
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
        // The report's reason is bounded to 512 chars, which four long names can fill; the missing clause leads (N2), so
        // the bounded reason still says why, and the (unbounded) warning carries the whole message.
        Assert.StartsWith(YaraInventoryCliTests.Lead(4, 4) + "4 of them no longer exist (each removed after it was listed): ", scan.Value.YaraUnavailableReason, StringComparison.Ordinal);
        Assert.Contains(warnings.Warnings, w => w.StartsWith("YARA scanning UNAVAILABLE for PkgInvCliAll", StringComparison.Ordinal)
                                                && w.Contains("4 of them no longer exist (each removed after it was listed)", StringComparison.Ordinal));
    }

    // The control: the same package and backend, nothing deleted, completes with the payload's finding — so the two tests
    // above are about the deletion, not about this package or this fake.
    [Fact]
    public void Scan_WhenNothingIsDeleted_IsCompleted_WithTheFinding()
    {
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvCliNone", "ordinary content\n"u8.ToArray());
        using var fake = new FakeYaraBinary(batchEchoRule: "Fake_Rule", batchEchoName: "payload.bin");
        using var inner = new YaraCliScanner();

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: new DeletingScanner(inner, "no-such-file"));

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Equal("content/payload.bin", Assert.Single(scan.Value.YaraFindings).RelativePath);
        Assert.Null(scan.Value.YaraUnavailableReason);
    }
    #endregion

    #region Methods: the real yara (WSL)
    [LinuxYaraFact]
    public void RealYara_Scan_WhenAnExtractedFileIsDeletedBeforeYara_IsUnavailable_AndKeepsTheRealFinding()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvRealYara", HermeticWiperSample.Bytes);
        using var inner = new YaraCliScanner();
        Assert.True(inner.Available, "The Linux integration tier requires a real yara binary.");
        var backend = new DeletingScanner(inner, VanishName);

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(1, backend.Deleted);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal((HermeticWiperSample.RuleName, "content/payload.bin"), (finding.RuleName, finding.RelativePath));
        Assert.StartsWith(YaraInventoryCliTests.Lead(1, 1) + "1 of them no longer exists (removed after it was listed): ", scan.Value.YaraUnavailableReason, StringComparison.Ordinal);
    }

    [LinuxYaraFact]
    public void RealYara_Scan_WhenEveryExtractedFileIsDeletedBeforeYara_IsUnavailable_NotCompletedAndClean()
    {
        using var env = new YaraEnvScope(YaraCliProbe.YaraBinary, YaraCliProbe.YaracBinary);
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvRealYaraAll", HermeticWiperSample.Bytes);
        using var inner = new YaraCliScanner();
        Assert.True(inner.Available, "The Linux integration tier requires a real yara binary.");

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: new DeletingScanner(inner, "*"));

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
    }
    #endregion

#if WINDOWS
    #region Methods: the in-process LibYaraScanner (net10.0-windows)
    // Through LibYaraScanner's ScanFiles (the shared per-file loop, YaraScanLoop.Run) with libyara itself. Since I4 its
    // per-file exception carries the FileNotFound that proves the file gone, so the loop's message LEADS with it, named
    // (escaped) under the "no longer exists" clause.
    [Fact]
    public void LibYara_Scan_WhenAnExtractedFileIsDeletedBeforeYara_IsUnavailable_NamesIt_AndKeepsTheRealFinding()
    {
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvLibYara", HermeticWiperSample.Bytes);
        var inner = new LibYaraScanner();
        Assert.True(inner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        var backend = new DeletingScanner(inner, VanishName);

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(1, backend.Deleted);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal((HermeticWiperSample.RuleName, "content/payload.bin"), (finding.RuleName, finding.RelativePath));
        var reason = scan.Value.YaraUnavailableReason!;
        Assert.Contains("could not scan 1 of 4 file(s)", reason, StringComparison.Ordinal);
        var clause = reason.IndexOf("': 1 of them no longer exists (removed after it was listed): '", StringComparison.Ordinal);
        Assert.True(clause >= 0, reason);
        Assert.Contains("vanish" + EscapedRlo + ".bin'", reason[clause..], StringComparison.Ordinal);
        Assert.DoesNotContain("the others", reason, StringComparison.Ordinal);
        YaraCliStderrErrorLineTests.AssertNoRawControlOrBidi(reason);
    }

    [Fact]
    public void LibYara_Scan_WhenEveryExtractedFileIsDeletedBeforeYara_IsUnavailable_NotCompletedAndClean()
    {
        using var tree = new TempTree();
        var nupkg = Package(tree, "PkgInvLibYaraAll", HermeticWiperSample.Bytes);
        var inner = new LibYaraScanner();
        Assert.True(inner.Available, "The in-process engine did not build; every assertion below would be vacuous.");
        var backend = new DeletingScanner(inner, "*");

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(4, backend.Deleted);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Contains("could not scan 4 of 4 file(s)", scan.Value.YaraUnavailableReason, StringComparison.Ordinal);
        Assert.Contains("': 4 of them no longer exist (each removed after it was listed): '", scan.Value.YaraUnavailableReason, StringComparison.Ordinal);
    }
    #endregion
#endif

    #region Helpers
    // A package of: the nuspec, content/payload.bin (`payload`), content/vanish<RLO>.bin (the file the tests delete; the
    // bidi override makes its name attacker-shaped) and content/notes.txt.
    internal static string Package(TempTree tree, string id, byte[] payload) =>
        YaraCliStderrErrorLineTests.WritePackageBytes(tree, id,
        [
            ("content/payload.bin", payload),
            ($"content/{VanishName}", payload),
            ("content/notes.txt", Encoding.UTF8.GetBytes("ordinary text\n")),
        ], []);

    internal static readonly string VanishName = "vanish" + Rlo + ".bin";

    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion

    #region Nested types
    /// <summary>
    /// The Storage Sense double: on the way into <see cref="IYaraScanner.ScanFiles"/> or
    /// <see cref="IYaraScanner.ScanDirectory"/> it deletes every file under the root named <c>delete</c> (<c>*</c>: every
    /// file; a trailing <c>*</c>: every file whose name starts with what precedes it), counts them, and delegates to the
    /// real backend unchanged.
    /// </summary>
    internal sealed class DeletingScanner(IYaraScanner inner, string delete) : IYaraScanner
    {
        public bool Available => inner.Available;

        public string? UnavailableReason => inner.UnavailableReason;

        public int Deleted { get; private set; }

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => inner.ScanFile(fullPath);

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
        {
            Delete(rootDir);
            return inner.ScanDirectory(rootDir);
        }

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            Delete(rootDir);
            return inner.ScanFiles(rootDir, files);
        }

        private void Delete(string rootDir)
        {
            foreach (var file in Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories)
                         .Where(f => delete == "*"
                                     || (delete.EndsWith('*')
                                         ? Path.GetFileName(f).StartsWith(delete[..^1], StringComparison.Ordinal)
                                         : string.Equals(Path.GetFileName(f), delete, StringComparison.Ordinal))))
            {
                File.Delete(file);
                Deleted++;
            }
        }
    }
    #endregion
}
