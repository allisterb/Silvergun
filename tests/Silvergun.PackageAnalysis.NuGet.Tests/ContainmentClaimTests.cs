namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// <b>One extracted file may be claimed by at most ONE declared entry.</b> The critical defect this file pins:
/// <see cref="NuGetPackage.UninventoriedEntryNames"/> used to ask, per entry and independently, "does any key of
/// this entry exist on disk?" — and DIFFERENT declared names fold to the SAME extracted path, so both entries
/// matched the one surviving file and NEITHER was reported.
///
/// <code>
/// E1 = "content/../X.dll"  (payload)  folds to -> content/X.dll
/// E2 = "content/X.dll"     (benign)   folds to -> content/X.dll
/// </code>
///
/// <para>The extractor writes both to <c>content/X.dll</c>, one silently overwrites the other, and the pre-fix
/// analyzer reported an EMPTY <c>UninventoriedEntryNames</c>: the package read complete and the run exited 0, with
/// the attacker choosing the archive order that leaves the benign bytes on disk. That is
/// <see cref="PackagingAnomalyCategory.CaseOnlyCollision"/>'s failure mode — <i>the file scanned is not the file
/// shipped</i> — with the collision invisible to every check we had (ADR 0030).</para>
///
/// <para><b>Both archive orders are asserted</b>, because claim-once is order-based and the two orders report
/// different names. Whichever entry could not claim the file is the one reported; that the COUNT is the same in
/// both orders is the invariant, and the identity of the reported name is pinned so a later change of claim policy
/// is a deliberate act. (Reporting the folding PAIR as its own anomaly category is a separate, open follow-up.)</para>
///
/// <para><b>No platform gate anywhere in this file.</b> Folding is lexical, and RecursiveExtractor's dot-stripping
/// is the same on both platforms (measured 2026-08-22 on Windows and under WSL: all four of <c>content/X.dll</c>,
/// <c>content/./X.dll</c>, <c>content//X.dll</c> and <c>content/../X.dll</c> land on the single path
/// <c>content/X.dll</c>). Every test here therefore states the same expectation on every platform, and each one
/// asserts the on-disk ground truth it depends on rather than assuming it.</para>
/// </summary>
public sealed class ContainmentClaimTests : IClassFixture<ClaimOncePackageFixture>
{
    #region Constructors
    public ContainmentClaimTests(ClaimOncePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — the C1 folding collision, in both archive orders
    // Payload FIRST: "content/../X.dll" claims the single extracted file, so the benign "content/X.dll" declared
    // after it is the coverage that was lost. Pre-fix this list was EMPTY and the package read complete.
    [Fact]
    public void Open_ForTwoEntriesFoldingToOneKey_WithThePayloadFirst_ReportsTheUnclaimedEntry()
    {
        using var pkg = Open(fixture.PayloadFirstPath);

        AssertExactlyOneExtractedFileNamed(pkg, "content/X.dll");
        Assert.Equal(["content/X.dll"], pkg.UninventoriedEntryNames);
        Assert.Equal(["content/X.dll"], pkg.Assemblies.Select(a => a.RelativePath));
    }

    // Payload SECOND: the benign entry claims the file first, so the payload entry is the one reported. Same
    // package content, reversed central directory — and the attacker picks which of the two this is.
    [Fact]
    public void Open_ForTwoEntriesFoldingToOneKey_WithThePayloadSecond_ReportsTheUnclaimedEntry()
    {
        using var pkg = Open(fixture.PayloadSecondPath);

        AssertExactlyOneExtractedFileNamed(pkg, "content/X.dll");
        Assert.Equal(["content/../X.dll"], pkg.UninventoriedEntryNames);
        Assert.Equal(["content/X.dll"], pkg.Assemblies.Select(a => a.RelativePath));
    }

    // The order-INDEPENDENT statement, which is the one that actually closes the hole: whichever order the two
    // entries are declared in, exactly one of them is reported lost. An analyzer that lets archive order decide
    // whether a collision is disclosed at all is one the attacker simply re-orders around.
    [Fact]
    public void Open_ForTwoEntriesFoldingToOneKey_ReportsExactlyOneLostEntryInEitherOrder()
    {
        using var first = Open(fixture.PayloadFirstPath);
        using var second = Open(fixture.PayloadSecondPath);

        foreach (var pkg in new[] { first, second })
        {
            var lost = Assert.Single(pkg.UninventoriedEntryNames);
            Assert.Contains(lost, pkg.DeclaredEntryNames);      // ...and it is a name the author actually wrote
            Assert.Single(pkg.Assemblies);
        }
    }

    // The scanner half: a lost entry becomes a skipped AssemblyScanResult, so completeness cannot read the package
    // as fully analysed. The surviving file is still analysed — the fix must not cost the package its real coverage.
    [Fact]
    public void Scan_ForTwoEntriesFoldingToOneKey_SynthesizesOneSkipResultAlongsideTheAnalysedFile()
    {
        var scan = Scan(fixture.PayloadFirstPath);

        var skipped = Assert.Single(scan.Assemblies, a => a.SkipReason is not null);
        Assert.Contains("NOT inventoried", skipped.SkipReason!, StringComparison.Ordinal);
        Assert.Null(skipped.Report);

        var analysed = Assert.Single(scan.Assemblies, a => a.SkipReason is null);
        Assert.NotNull(analysed.Report);
    }

    // The control, and the before/after in one assertion: the SAME package with only the benign entry has nothing
    // to disclose. This is exactly the report the pre-fix code produced for the colliding package above, which is
    // what made the collision read as clean.
    [Fact]
    public void Open_ForTheSameEntryWithoutItsFoldingTwin_ReportsNoLoss()
    {
        using var pkg = Open(fixture.SingleEntryPath);

        Assert.Empty(pkg.UninventoriedEntryNames);
        Assert.Equal(["content/X.dll"], pkg.Assemblies.Select(a => a.RelativePath));
    }
    #endregion

    #region Methods — one extracted file cannot be claimed twice (or four times)
    // Four declared names, one extracted file: three of them are coverage that was never delivered. Under the
    // pre-fix independent test ALL FOUR matched the single file and the package reported complete.
    [Fact]
    public void Open_ForFourEntriesFoldingToOneKey_ReportsTheThreeThatCouldNotClaimTheFile()
    {
        using var pkg = Open(fixture.ThreeWayFoldPath);

        AssertExactlyOneExtractedFileNamed(pkg, "content/X.dll");
        Assert.Equal(
            ["content/./X.dll", "content//X.dll", "content/../X.dll"],
            pkg.UninventoriedEntryNames);
        Assert.Single(pkg.Assemblies);
    }

    // ...and all four names are CONTAINED, on every platform. The three reported ones are not zip-slip drops (a
    // guard working); they are analysis that did not happen (ADR 0030), and the two must never be confused.
    [Fact]
    public void Open_ForFourEntriesFoldingToOneKey_NoneOfThemEscapesTheContentRoot() =>
        Assert.All(
            ClaimOncePackageFixture.FoldingEntries,
            name => Assert.False(NuGetPackage.EscapesContentRoot(name), $"'{name}' names a file inside the root."));

    // The scanner half of the three-way fold: three skip results, one analysed file. A count is the assertion that
    // matters here — the defect was one file silently answering for four declared entries.
    [Fact]
    public void Scan_ForFourEntriesFoldingToOneKey_SynthesizesThreeSkipResults()
    {
        var scan = Scan(fixture.ThreeWayFoldPath);

        Assert.Equal(3, scan.Assemblies.Count(a => a.SkipReason is not null));
        Assert.Single(scan.Assemblies, a => a.SkipReason is null);
    }
    #endregion

    #region Methods — byte-identical duplicate names are ONE entry, not a collision
    // A name declared twice, verbatim, is one entry declared twice: it claims once and the second occurrence is not
    // coverage lost. This is the deliberate carve-out in the claim-once rule, and it has to agree with
    // PackageEntryNameAnalyzer, which rules exact ordinal duplicates out of CaseOnlyCollision's scope for the same
    // reason — otherwise a merely sloppy package would report a phantom lost binary and exit 3.
    [Fact]
    public void Open_ForTheSameEntryNameDeclaredTwice_ClaimsOnceAndReportsNoLoss()
    {
        using var pkg = Open(fixture.ExactDuplicatePath);

        // Ground truth: the archive really does declare the name twice, else this test is vacuous.
        Assert.Equal(2, pkg.DeclaredEntryNames.Count(n => n == "content/X.dll"));
        Assert.Empty(pkg.UninventoriedEntryNames);
        Assert.Equal(["content/X.dll"], pkg.Assemblies.Select(a => a.RelativePath));
    }

    // ...and the analyzer agrees: an exact duplicate is not a case-only collision either.
    [Fact]
    public void Analyze_ForTheDuplicatePackagesDeclaredNames_ReportsNoAnomaly()
    {
        using var pkg = Open(fixture.ExactDuplicatePath);

        Assert.Empty(PackageEntryNameAnalyzer.Analyze(pkg.DeclaredEntryNames));
    }
    #endregion

    #region Methods — the dropped `resolvedKey` reading: a clamped zip-slip file stays out of the inventory
    // The hole the speculative second containment key opened. For "content/../<name>" the RESOLVED key is
    // "<name>" at the archive root — so a SEPARATE escaping entry "../<name>", correctly dropped by
    // EscapesContentRoot, was clamped by the extractor into that very path, matched the resolved key, and got
    // INVENTORIED. "Escaping entries are never inventoried" (ADR 0008) was broken to buy a reading never observed
    // on disk. With one key — the measured, dot-STRIPPED one — the clamped file matches nothing.
    [Fact]
    public void Open_ForAZipSlipEntryClampedOntoTheResolvedKeyOfAContainedTwin_DoesNotInventoryIt()
    {
        using var pkg = Open(fixture.ClampedTwinPath);

        // Ground truth: the extractor really did clamp "../<name>" into the archive root, so there IS a file there
        // for a resolved-key reading to have matched.
        Assert.Contains(fixture.ClampedFileName, ExtractedRelativePaths(pkg));

        Assert.Equal(["content/" + fixture.ClampedFileName], pkg.Assemblies.Select(a => a.RelativePath));
        Assert.DoesNotContain(pkg.Assemblies, a => a.RelativePath == fixture.ClampedFileName);
    }

    // ...and the contained twin still claims its own extracted file, so nothing is reported lost. The fix must
    // close the hole without inventing a phantom coverage gap on a package that lost nothing (ADR 0030's converse).
    [Fact]
    public void Open_ForAZipSlipEntryClampedOntoAContainedTwin_ReportsNoCoverageLoss()
    {
        using var pkg = Open(fixture.ClampedTwinPath);

        Assert.Empty(pkg.UninventoriedEntryNames);
        Assert.True(
            NuGetPackage.EscapesContentRoot("../" + fixture.ClampedFileName),
            "ground truth: the twin entry escapes the content root and must never be inventoried.");
        Assert.False(NuGetPackage.EscapesContentRoot("content/../" + fixture.ClampedFileName));
    }

    // End to end: the escaping entry produces no scan result at all (it is containment working, not lost
    // coverage), and the contained one is genuinely analysed.
    [Fact]
    public void Scan_ForAZipSlipEntryClampedOntoAContainedTwin_AnalysesOnlyTheContainedFile()
    {
        var scan = Scan(fixture.ClampedTwinPath);

        var analysed = Assert.Single(scan.Assemblies);
        Assert.Equal("content/" + fixture.ClampedFileName, analysed.Assembly.RelativePath);
        Assert.Null(analysed.SkipReason);
        Assert.NotNull(analysed.Report);
    }
    #endregion

    #region Methods — dedupe on the RAW name, escape afterwards
    // Escape is not injective: a name carrying a REAL line feed and a name carrying the two literal characters
    // backslash-n both render as "\n". Deduplicating the lost list on the ESCAPED text therefore collapsed two
    // genuinely distinct lost entries into one — an undercount in the list whose entire job is counting coverage
    // that was not delivered. Both entries also carry a NUL, which neither filesystem will write (measured
    // 2026-08-22), so both are lost on every platform and this test needs no gate.
    [Fact]
    public void Open_ForTwoDistinctLostNamesThatEscapeToTheSameText_ReportsBothOfThem()
    {
        using var pkg = Open(fixture.CollidingEscapePath);

        // Ground truth: the two declared names are DIFFERENT strings that escape to the SAME text.
        Assert.NotEqual(ClaimOncePackageFixture.RealLineFeedEntry, ClaimOncePackageFixture.LiteralBackslashNEntry);
        Assert.Equal(2, pkg.UninventoriedEntryNames.Count);
        Assert.All(
            pkg.UninventoriedEntryNames,
            n => Assert.Equal(ClaimOncePackageFixture.BothEntriesEscaped, n));
    }

    // ...and the scanner emits TWO skip results, not one. A single result would say one binary went un-analysed
    // when two did, which is the whole point of the list.
    [Fact]
    public void Scan_ForTwoDistinctLostNamesThatEscapeToTheSameText_SynthesizesTwoSkipResults()
    {
        var scan = Scan(fixture.CollidingEscapePath);

        Assert.Equal(2, scan.Assemblies.Count(a => a.SkipReason is not null));
        Assert.All(
            scan.Assemblies.Where(a => a.SkipReason is not null),
            a => Assert.Equal(ClaimOncePackageFixture.BothEntriesEscaped, a.Assembly.RelativePath));
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

    // The premise every folding test rests on, asserted rather than assumed: the extractor really did write the
    // colliding entries to ONE path. If a future extractor version stopped folding them, these tests would still
    // pass on the counts while testing nothing — this is what fails instead.
    private static void AssertExactlyOneExtractedFileNamed(NuGetPackage pkg, string relativePath)
    {
        var payloads = ExtractedRelativePaths(pkg).Where(p => !p.EndsWith(".nuspec", StringComparison.Ordinal)).ToArray();

        Assert.Equal([relativePath], payloads);
    }

    // Every extracted file under the package's content root, forward-slash relative, in sorted order.
    private static string[] ExtractedRelativePaths(NuGetPackage pkg)
    {
        var contentRoot = Directory.EnumerateDirectories(pkg.ExtractionDir).FirstOrDefault() ?? pkg.ExtractionDir;
        return Directory.EnumerateFiles(contentRoot, "*", SearchOption.AllDirectories)
            .Select(f => f[(contentRoot.Length + 1)..].Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }
    #endregion

    #region Fields
    private readonly ClaimOncePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="ContainmentClaimTests"/> with pure BCL zip (see
/// <see cref="NupkgBuilder"/>) — no NuGet client, no network. Payloads are copies of the real fixture assembly, so
/// an inventoried entry produces a genuine capability report and "was this actually analysed?" is answerable.
/// </summary>
public sealed class ClaimOncePackageFixture : IDisposable
{
    #region Constructors
    public ClaimOncePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-claim-once", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var payload = File.ReadAllBytes(typeof(Shapes).Assembly.Location);

        // The C1 shape, in both archive orders. The bytes are identical here because what is under test is the
        // NAME matching, not which copy survived — the attack is that neither name is reported at all.
        PayloadFirstPath = Write("PkgFoldPayloadFirst", [("content/../X.dll", payload), ("content/X.dll", payload)]);
        PayloadSecondPath = Write("PkgFoldPayloadSecond", [("content/X.dll", payload), ("content/../X.dll", payload)]);

        // The control: the same benign entry with no folding twin, which must report nothing.
        SingleEntryPath = Write("PkgFoldSingle", [("content/X.dll", payload)]);

        // Four names, one extracted file: "." and empty segments fold exactly like "..".
        ThreeWayFoldPath = Write("PkgFoldFourWay", [.. FoldingEntries.Select(name => (name, payload))]);

        // The same name declared twice, verbatim — one entry, one claim, no loss.
        ExactDuplicatePath = Write("PkgFoldDuplicate", [("content/X.dll", payload), ("content/X.dll", payload)]);

        // The resolved-key hole: a contained "content/../<name>" whose resolved reading is "<name>" at the archive
        // root, alongside a genuine zip-slip "../<name>" that the extractor clamps into exactly that path. The guid
        // keeps the clamped file unique so no stray file from another test can satisfy the assertions.
        ClampedFileName = $"Slip-{Guid.NewGuid():N}.dll";
        ClampedTwinPath = Write(
            "PkgClampedTwin", [("content/../" + ClampedFileName, payload), ("../" + ClampedFileName, payload)]);

        // Two DISTINCT raw names that YaraPathSafety.Escape renders identically; both carry a NUL, so both are
        // refused by both filesystems and are lost on every platform.
        CollidingEscapePath = Write(
            "PkgEscapeCollision",
            [(OrdinaryEntry, payload), (RealLineFeedEntry, payload), (LiteralBackslashNEntry, payload)]);
    }
    #endregion

    #region Properties
    /// <summary>An ordinary lib assembly — one lost entry must never cost the rest of the package its analysis.</summary>
    public const string OrdinaryEntry = "lib/net8.0/Ordinary.dll";

    /// <summary>
    /// A name carrying a REAL line feed (and a NUL, so it is lost on every platform). Deliberately NOT the same
    /// text as <c>UninventoriedPackageFixture.HostileEntry</c>: warning-capture tests in that file swap the
    /// process-wide logger and filter by the escaped name, so a shared name would let these packages' warnings
    /// leak into their assertions when the two classes run in parallel.
    /// </summary>
    public const string RealLineFeedEntry = "lib/net8.0/esc\nco\0llide.dll";

    /// <summary>The same shape with the two LITERAL characters backslash and 'n' where the line feed was.</summary>
    public const string LiteralBackslashNEntry = "lib/net8.0/esc\\nco\0llide.dll";

    /// <summary>What BOTH of the above render as — the collision that made a dedupe-after-escape undercount.</summary>
    public const string BothEntriesEscaped = "lib/net8.0/esc\\nco\\x00llide.dll";

    /// <summary>Four declared names that all fold to the single extracted path <c>content/X.dll</c>.</summary>
    public static readonly string[] FoldingEntries =
        ["content/X.dll", "content/./X.dll", "content//X.dll", "content/../X.dll"];

    public string PayloadFirstPath { get; }
    public string PayloadSecondPath { get; }
    public string SingleEntryPath { get; }
    public string ThreeWayFoldPath { get; }
    public string ExactDuplicatePath { get; }
    public string ClampedTwinPath { get; }
    public string CollidingEscapePath { get; }

    /// <summary>Bare file name of the zip-slip twin, e.g. <c>Slip-&lt;guid&gt;.dll</c>.</summary>
    public string ClampedFileName { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }

        // Belt and braces: a regression that let the traversal entry out of the extraction dir would drop it one
        // level above each pkg-* directory, i.e. straight into the temp path.
        try
        {
            var stray = Path.Combine(Path.GetTempPath(), ClampedFileName);
            if (File.Exists(stray)) File.Delete(stray);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    // Writes "<id>.1.0.0.nupkg" with a valid root nuspec plus the given entries, every name stored VERBATIM (they
    // are passed as NupkgBuilder's `raw` list to document that they are unnormalized by design).
    private string Write(string id, (string Name, byte[] Bytes)[] raw)
    {
        var nuspec = NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", $"ADR 0030 claim-once test package ({id}).", "net8.0", []);
        var path = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [($"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec))], raw);
        return path;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
