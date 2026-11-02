namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

using Silvergun;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;
using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Round 3 of the containment work, W1 and N1: <b>a trailing space or dot must not buy a silent coverage loss, and
/// the skip row a lost entry produces must describe the name the author WROTE.</b>
///
/// <para><b>W1 — the hole.</b> Windows drops a trailing space or dot when it creates a file (measured 2026-08-22:
/// <c>File.Create("X.dll ")</c> and <c>File.Create("Y.dll.")</c> silently produce <c>X.dll</c> and <c>Y.dll</c>).
/// So a declared <c>lib/net8.0/evil.dll </c> is extracted as <c>lib/net8.0/evil.dll</c>, whose relative path matches
/// no containment key and is dropped by the inventory gate; the entry's own key never appears on disk, so it reaches
/// the lost-kind test — where <c>"…/evil.dll ".EndsWith(".dll")</c> is <b>false</b>. The payload was extracted, never
/// analysed, and the package reported complete, exit 0, <i>even under <c>--strict</c></i>. The kind test now runs on
/// <c>key.TrimEnd(' ', '.')</c> while the REPORTED name stays the declared one.</para>
///
/// <para><b>The kind guard.</b> Trimming decides a KIND, and widening the kind set would inventory benign
/// <c>content/readme.txt </c> as a phantom binary. That guard stands. What changed (2026-11-01,
/// <c>tasks/entry-aliasing-coverage.md</c>, Review 1 rule (a)) is the LOST list: it no longer filters by kind, so on
/// Windows a non-binary trailing-name entry, which claims no file, is now reported lost — the accepted, fail-closed cost
/// of that rule. <see cref="Open_OnWindows_ForATrailingSpaceOnAnUninventoriedKind_ReportsItLostButInventoriesNoBinary"/>
/// pins both halves, and the Linux twins catch the whole fix over-firing on the platform that can hold these names.</para>
///
/// <para><b>N1 — role and TFM came off the ESCAPED name.</b> <see cref="YaraPathSafety.Escape"/> emits backslashes
/// and the segment splitter treats a backslash as a separator, so the escaped form RE-SEGMENTS: measured, raw
/// <c>lib/pay&lt;LF&gt;load.dll</c> has two segments (Lib, no TFM) and its escape has three, which reads the TFM off
/// as <b>"pay"</b>. That is an INVENTED target framework in a report field, not a display wart — a reader cannot tell
/// it from a real one. Role and TFM are now derived from the raw name, and the derived TFM is escaped at the DTO
/// boundary because it is still attacker-authored text a renderer prints.</para>
///
/// <para><b>Platform gates.</b> Whether these names survive extraction is an OS question, measured on both platforms
/// 2026-08-22: Windows silently strips the trailing space/dot and rewrites a control character to <c>_</c>, Linux
/// writes all three verbatim. So the trailing-name and re-segmenting packages are lost on Windows and not on Linux,
/// and both sides are asserted. The NUL-bearing package (<see cref="TrailingNamePackageFixture.TfmEscapeEntry"/>) is
/// refused by BOTH filesystems, which is what lets the TFM-escaping statement run ungated.</para>
/// </summary>
public sealed class TrailingSpaceOrDotCoverageTests : IClassFixture<TrailingNamePackageFixture>
{
    #region Constructors
    public TrailingSpaceOrDotCoverageTests(TrailingNamePackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods — W1: the trailing space and the trailing dot (Windows)
    // The headline. Both entries are declared, contained, and extracted under a name Windows chose instead — so
    // neither claims a file, and both must be disclosed. Pre-fix this list was EMPTY: the raw keys do not end in
    // ".dll", so the kind test called them uninteresting and the package read complete.
    [WindowsExtractionFact("Windows silently drops a trailing space or dot when it creates the file")]
    public void Open_OnWindows_ForTrailingSpaceAndDotEntries_ReportsBothUninventoried()
    {
        using var pkg = Open(fixture.TrailingPath);

        // Ground truth for the whole shape: the bytes DID reach disk, under the trimmed names — which is why the
        // extracted files match no containment key and the declared entries claim nothing.
        var onDisk = ExtractedRelativePaths(pkg);
        Assert.Contains("lib/net8.0/trailspace.dll", onDisk);
        Assert.Contains("lib/net8.0/traildot.dll", onDisk);

        Assert.Equal(
            [TrailingNamePackageFixture.TrailingSpaceEntry, TrailingNamePackageFixture.TrailingDotEntry],
            pkg.UninventoriedEntryNames);
        // ...and the entry that CAN be written is unaffected: one lost entry must not cost the rest its analysis.
        Assert.Equal([TrailingNamePackageFixture.OrdinaryEntry], pkg.Assemblies.Select(a => a.RelativePath));
    }

    // The scanner half: one skip row EACH, carrying the declared name verbatim (a trailing space needs no escaping,
    // so declared and reported coincide here) and the role/TFM an inventoried file would have got.
    [WindowsExtractionFact("only Windows loses these entries, so only there is there a skip row to synthesize")]
    public void Scan_OnWindows_ForTrailingSpaceAndDotEntries_SynthesizesOneSkipRowEach()
    {
        var scan = Scan(fixture.TrailingPath);

        foreach (var name in new[]
                 { TrailingNamePackageFixture.TrailingSpaceEntry, TrailingNamePackageFixture.TrailingDotEntry })
        {
            var row = Assert.Single(scan.Assemblies, a => a.Assembly.RelativePath == name);
            Assert.Null(row.Report);
            Assert.NotNull(row.SkipReason);
            Assert.Contains("NOT inventoried", row.SkipReason, StringComparison.Ordinal);
            Assert.Equal(PackageItemRole.Lib, row.Assembly.Role);
            Assert.Equal("net8.0", row.Assembly.TargetFramework);
        }

        Assert.Equal(2, scan.Assemblies.Count(a => a.SkipReason is not null));
    }

    // The over-firing guard. ext4 holds "evil.dll " and "evil.dll." verbatim, so each entry claims its own extracted
    // file and there is nothing to disclose — the same package, the same code, a different filesystem. A fix that
    // reported these on Linux would be manufacturing a coverage gap out of a name the platform handled fine.
    //
    // "Nothing was lost" is only worth asserting alongside "and here is the coverage that was delivered": the empty
    // lost-list on its own was true BEFORE the inventory gate learned to trim, while both payloads sat extracted on
    // disk and were never inventoried, never IL-analysed and never mentioned — contained, present, invisible
    // (ADR 0030). A test that is green either way is not a test of this fix, so both halves are pinned here.
    [LinuxExtractionFact("ext4 holds a trailing space or dot verbatim, so each entry claims its own file")]
    public void Open_OnLinux_ForTrailingSpaceAndDotEntries_ReportsNoCoverageLoss()
    {
        using var pkg = Open(fixture.TrailingPath);

        // Ground truth: both names really were written VERBATIM here, which is what makes the claim succeed.
        var onDisk = ExtractedRelativePaths(pkg);
        Assert.Contains(TrailingNamePackageFixture.TrailingSpaceEntry, onDisk);
        Assert.Contains(TrailingNamePackageFixture.TrailingDotEntry, onDisk);

        Assert.Empty(pkg.UninventoriedEntryNames);

        // ...and the positive half: not lost BECAUSE inventoried, which is the only reading of "no coverage loss"
        // that means anything. Pre-fix this list held ONLY the ordinary entry.
        var inventoried = pkg.Assemblies.Select(a => a.RelativePath).ToArray();
        Assert.Contains(TrailingNamePackageFixture.TrailingSpaceEntry, inventoried);
        Assert.Contains(TrailingNamePackageFixture.TrailingDotEntry, inventoried);
        Assert.Contains(TrailingNamePackageFixture.OrdinaryEntry, inventoried);
        Assert.Equal(3, inventoried.Length);

        // Each inventory row is backed by a real file with real bytes — an entry present in the list but pointing at
        // nothing would be the skip-row shape wearing the inventory's clothes.
        Assert.All(pkg.Assemblies, a =>
        {
            Assert.True(File.Exists(a.FullPath), $"inventoried {a.RelativePath} has no file at {a.FullPath}.");
            Assert.NotEmpty(a.Sha256);
        });
    }

    // The script half of the same statement, in the package that stages it. Scripts are an inventoried kind, they run
    // at install time, and pre-fix "tools/init.ps1 " was extracted verbatim on Linux and then declined by the gate —
    // the same silent hole one extension over. Paired with the Windows twin, which asserts it is REPORTED lost there.
    [LinuxExtractionFact("ext4 holds a trailing space verbatim, so the script entry claims its own extracted file")]
    public void Open_OnLinux_ForATrailingSpaceOnAScript_InventoriesIt()
    {
        using var pkg = Open(fixture.ScriptPath);

        Assert.Contains(TrailingNamePackageFixture.TrailingScriptEntry, ExtractedRelativePaths(pkg));  // ground truth

        Assert.Empty(pkg.UninventoriedEntryNames);
        var script = Assert.Single(
            pkg.Scripts, s => s.RelativePath == TrailingNamePackageFixture.TrailingScriptEntry);
        Assert.Equal(PackageItemRole.Tools, script.Role);
        Assert.True(File.Exists(script.FullPath));
    }

    // Forward-looking pin (green before this fix and after it): the trimmed form must exist ONLY inside the kind
    // decision. What is published is the name the package DECLARES and, on this platform, the name on disk — so
    // "lib/net8.0/trailspace.dll " keeps its trailing space, and a reviewer grepping the report for the name they
    // saw in the archive finds it. Trimming the reported path would be an easy tidy-up that silently rewrites
    // evidence and makes the report disagree with both the zip and the filesystem; nothing else pins it.
    [LinuxExtractionFact("only here is the untrimmed name the one that reaches the inventory")]
    public void Open_OnLinux_ForATrailingSpaceEntry_PublishesTheUntrimmedNameAsItsRelativePath()
    {
        using var pkg = Open(fixture.TrailingPath);

        var inventoried = pkg.Assemblies.Select(a => a.RelativePath).ToArray();
        Assert.Contains("lib/net8.0/trailspace.dll ", inventoried);     // spelled out: the trailing space is the point
        Assert.DoesNotContain("lib/net8.0/trailspace.dll", inventoried);
        Assert.Contains("lib/net8.0/traildot.dll.", inventoried);
        Assert.DoesNotContain("lib/net8.0/traildot.dll", inventoried);
    }

    // The scanner half of the Linux side. "No skip row" was ASSERTED OVER A ONE-ELEMENT LIST that did not contain
    // either payload — vacuously true while the fix's whole subject was missing from the report. The count and the
    // two payloads' rows are pinned first; only then does Assert.All say anything.
    [LinuxExtractionFact("ext4 holds a trailing space or dot verbatim, so nothing is lost and nothing is skipped")]
    public void Scan_OnLinux_ForTrailingSpaceAndDotEntries_SynthesizesNoSkipRow()
    {
        var scan = Scan(fixture.TrailingPath);

        Assert.Equal(3, scan.Assemblies.Count);
        foreach (var name in new[]
                 { TrailingNamePackageFixture.OrdinaryEntry,
                   TrailingNamePackageFixture.TrailingSpaceEntry,
                   TrailingNamePackageFixture.TrailingDotEntry })
        {
            var row = Assert.Single(scan.Assemblies, a => a.Assembly.RelativePath == name);
            Assert.Null(row.SkipReason);
            // A row with a null Report is a file nothing was read out of — indistinguishable in a count from one
            // that analysed. These payloads are real managed assemblies, so both must be there.
            Assert.NotNull(row.Report);
            Assert.NotNull(row.Metadata);
        }

        Assert.All(scan.Assemblies, a => Assert.Null(a.SkipReason));
    }
    #endregion

    #region Methods — W1's kind guard: trimming must not widen the KIND set (and rule (a)'s accepted cost)
    // Windows strips the trailing space from "content/readme.txt " exactly as it does from "evil.dll ", so the extracted
    // file is dropped by the inventory gate. Two statements, and they used to be one:
    //   * the KIND guard, unchanged: ".txt" is not a kind we inventory, trimmed or not, so no phantom binary appears.
    //     "content/evil.dll.txt " is the sharper half: it CONTAINS ".dll" and trims to a name that still does not END
    //     in one, so a naive Contains-based kind test would fire on it;
    //   * the LOST list, changed on purpose (tasks/entry-aliasing-coverage.md, Review 1 rule (a), 2026-11-01): every
    //     contained entry that claimed no file is lost whatever its kind, decided without touching the filesystem, so
    //     these three now read lost on Windows although their bytes were written under the trimmed names. That is the
    //     ACCEPTED cost: fail-closed, and every such name is already a TrailingSpaceOrDot anomaly. Telling "trimmed onto
    //     a new file" from "trimmed onto another entry's file" (Real.nuspec. over Real.nuspec) would take the host probe
    //     review C1 removed.
    [WindowsExtractionFact("only Windows strips the trailing space, so only there does the entry claim no file")]
    public void Open_OnWindows_ForATrailingSpaceOnAnUninventoriedKind_ReportsItLostButInventoriesNoBinary()
    {
        using var pkg = Open(fixture.UninventoriedKindPath);

        // Ground truth: these entries DID lose their trailing space/dot on disk — without this the test would pass
        // vacuously on a platform that wrote them verbatim.
        var onDisk = ExtractedRelativePaths(pkg);
        Assert.Contains("content/readme.txt", onDisk);
        Assert.Contains("content/notes.txt", onDisk);
        Assert.Contains("content/evil.dll.txt", onDisk);

        Assert.Equal(["content/readme.txt ", "content/notes.txt.", "content/evil.dll.txt "], pkg.UninventoriedEntryNames);
        Assert.Equal([TrailingNamePackageFixture.OrdinaryEntry], pkg.Assemblies.Select(a => a.RelativePath));
        Assert.Empty(pkg.Scripts);
    }

    // The Linux twin, and the half the trim at the GATE newly puts at risk. On Windows these entries never reach the
    // gate — the extracted names lost their trailing space and match no containment key. On Linux ext4 holds
    // "content/readme.txt ", "content/notes.txt." and "content/evil.dll.txt " verbatim, so all three ARE contained,
    // ARE on disk, and are handed to the very kind test that now trims. Trimming may only strip a suffix that is not
    // part of an extension we match; if it ever widened the kind set, these would be inventoried as binaries and
    // every benign package with a stray trailing space would start reporting phantom content. Verified by CLI run
    // when the fix landed, unpinned until now.
    [LinuxExtractionFact("only here are these names held verbatim, so only here do they reach the trimming kind test")]
    public void Open_OnLinux_ForATrailingSpaceOnAnUninventoriedKind_LeavesThemOutOfTheInventory()
    {
        using var pkg = Open(fixture.UninventoriedKindPath);

        // Ground truth: all three really are contained and on disk under their declared names, so the exclusion
        // below is the kind test deciding, not the file being absent.
        var onDisk = ExtractedRelativePaths(pkg);
        Assert.Contains("content/readme.txt ", onDisk);
        Assert.Contains("content/notes.txt.", onDisk);
        Assert.Contains("content/evil.dll.txt ", onDisk);

        Assert.Equal([TrailingNamePackageFixture.OrdinaryEntry], pkg.Assemblies.Select(a => a.RelativePath));
        Assert.Empty(pkg.Scripts);
        Assert.Empty(pkg.UninventoriedEntryNames);
    }

    // ...and end to end on Windows: the ordinary assembly is the one thing ANALYSED (no phantom binary), and each lost
    // text entry is a skip row of role Content, so the package is incomplete (the exit-code half is in the CLI suite,
    // where CompletenessAssessment lives). The accepted cost of rule (a), see above.
    [WindowsExtractionFact("only Windows strips the trailing space, so only there are the entries lost")]
    public void Scan_OnWindows_ForATrailingSpaceOnAnUninventoriedKind_AnalysesOnlyTheAssemblyAndSkipsEachLostEntry()
    {
        var scan = Scan(fixture.UninventoriedKindPath);

        var analysed = Assert.Single(scan.Assemblies, a => a.SkipReason is null);
        Assert.Equal(TrailingNamePackageFixture.OrdinaryEntry, analysed.Assembly.RelativePath);
        Assert.NotNull(analysed.Report);

        var skipped = scan.Assemblies.Where(a => a.SkipReason is not null).ToArray();
        Assert.Equal(["content/readme.txt ", "content/notes.txt.", "content/evil.dll.txt "], skipped.Select(a => a.Assembly.RelativePath));
        Assert.All(skipped, a =>
        {
            Assert.Contains("NOT inventoried", a.SkipReason, StringComparison.Ordinal);
            Assert.Equal(PackageItemRole.Content, a.Assembly.Role);
            Assert.Null(a.Report);
        });
    }

    // The Linux twin: each entry claims its own verbatim file, so there is no skip row and nothing the trim widened into
    // a kind — one ordinary assembly, analysed.
    [LinuxExtractionFact("ext4 holds the trailing space or dot verbatim, so each entry claims its own file")]
    public void Scan_OnLinux_ForATrailingSpaceOnAnUninventoriedKind_SynthesizesNoSkipRow()
    {
        var scan = Scan(fixture.UninventoriedKindPath);

        // The list the Assert.All ranges over, named — one ordinary assembly and nothing the trim widened into a
        // kind. Without this the statement below is vacuous over whatever happens to be there.
        var analysed = Assert.Single(scan.Assemblies);
        Assert.Equal(TrailingNamePackageFixture.OrdinaryEntry, analysed.Assembly.RelativePath);
        Assert.All(scan.Assemblies, a => Assert.Null(a.SkipReason));
    }

    // The trim applies to SCRIPTS too — they are an inventoried kind, they execute on install, and "tools/init.ps1 "
    // is the same evasion one extension over. Role comes off the raw name, and a tools/ script has no TFM.
    [WindowsExtractionFact("only Windows strips the trailing space, so only there is the script entry lost")]
    public void Open_OnWindows_ForATrailingSpaceOnAScript_ReportsItUninventoried()
    {
        using var pkg = Open(fixture.ScriptPath);

        Assert.Contains("tools/init.ps1", ExtractedRelativePaths(pkg));    // ground truth: the space was dropped
        Assert.Equal([TrailingNamePackageFixture.TrailingScriptEntry], pkg.UninventoriedEntryNames);
        Assert.DoesNotContain(pkg.Scripts, s => s.RelativePath.StartsWith("tools/init.ps1", StringComparison.Ordinal));
    }

    [WindowsExtractionFact("only Windows loses the script entry, so only there is there a skip row")]
    public void Scan_OnWindows_ForATrailingSpaceOnAScript_SynthesizesASkipRowWithTheToolsRole()
    {
        var scan = Scan(fixture.ScriptPath);

        var row = Assert.Single(
            scan.Assemblies, a => a.Assembly.RelativePath == TrailingNamePackageFixture.TrailingScriptEntry);
        Assert.Null(row.Report);
        Assert.NotNull(row.SkipReason);
        Assert.Equal(PackageItemRole.Tools, row.Assembly.Role);
        Assert.Null(row.Assembly.TargetFramework);
    }
    #endregion

    #region Methods — N1: role and TFM come off the RAW name, never the escaped one
    // The data-integrity statement, and the most valuable test here. Raw "lib/pay<LF>load.dll" is TWO segments, so
    // the TFM is absent — segments.Length >= 3 is false. Its ESCAPE is "lib/pay\nload.dll", which the splitter reads
    // as THREE segments (backslash is a separator), and the pre-fix derivation therefore published
    // TargetFramework == "pay": a target framework that appears nowhere in the package, indistinguishable in the
    // report from one the author actually wrote. A missing TFM is honest; an invented one is a lie in a data field.
    [WindowsExtractionFact("Windows rewrites the control character, so only there is this entry lost and synthesized")]
    public void Scan_OnWindows_ForALostEntryWhoseEscapeReSegments_DerivesRoleAndTfmFromTheRawName()
    {
        var scan = Scan(fixture.ReSegmentingPath);

        var row = Assert.Single(
            scan.Assemblies, a => a.Assembly.RelativePath == TrailingNamePackageFixture.ReSegmentingEntryEscaped);

        Assert.Equal(PackageItemRole.Lib, row.Assembly.Role);
        Assert.Null(row.Assembly.TargetFramework);
        Assert.NotEqual("pay", row.Assembly.TargetFramework);   // the escaped-derivation answer, named explicitly
        // ...while what is PUBLISHED is still the escaped name (ADR 0031 decision 4) — the fix moves the DERIVATION
        // to the raw name, not the reported one.
        Assert.Equal(TrailingNamePackageFixture.ReSegmentingEntryEscaped, row.Assembly.RelativePath);
        Assert.DoesNotContain('\n', row.Assembly.RelativePath);
    }

    // The premise the test above rests on, stated as a property of the two pure helpers rather than assumed: the
    // escaped name really does re-segment, and really does yield the invented "pay".
    [Fact]
    public void RoleAndTargetFramework_DerivedFromTheEscapedName_InventATfmTheRawNameDoesNotHave()
    {
        var raw = TrailingNamePackageFixture.ReSegmentingEntry;
        var escaped = YaraPathSafety.Escape(raw);

        Assert.Null(NuGetPackage.TargetFrameworkOf(raw, NuGetPackage.RoleOf(raw)));
        Assert.Equal("pay", NuGetPackage.TargetFrameworkOf(escaped, NuGetPackage.RoleOf(escaped)));
    }

    // The other side of "derive from the raw name": the raw name is attacker-authored, so a TFM read OFF it is too,
    // and it is escaped where the DTO is built. This entry carries a NUL — refused by both filesystems (measured) —
    // so it is lost on every platform and this statement needs no gate.
    [Fact]
    public void Scan_ForALostEntryWithAnEscapableCharacterInItsTfmSegment_PublishesAnEscapedTfm()
    {
        var scan = Scan(fixture.TfmEscapePath);

        var row = Assert.Single(
            scan.Assemblies, a => a.Assembly.RelativePath == TrailingNamePackageFixture.TfmEscapeEntryEscaped);

        Assert.Equal(PackageItemRole.Lib, row.Assembly.Role);
        Assert.Equal(@"net\t8.0", row.Assembly.TargetFramework);
        AssertNoRawControlCharacter(row.Assembly.TargetFramework!, nameof(PackageAssembly.TargetFramework));
    }
    #endregion

    #region Methods — the invariant the fix exists to establish: the gate and the lost-test must agree
    // THE statement, and the one worth having above every instance of it: an entry that names a binary or an
    // install-time script is EITHER inventoried (we analysed it) OR reported lost (we said we did not) — exactly one,
    // never neither, on every platform. "Neither" is the ADR 0030 shape in its general form: coverage that was not
    // delivered and not disclosed, the package reading complete with a payload on disk that nothing ever opened.
    //
    // The gate and the lost-test are now literally the same predicate (NuGetPackage.KindKey), so this holds by
    // construction — which is precisely why it is worth pinning: the two were separate copies that agreed by
    // convention until they quietly stopped, and re-splitting them is a one-line edit. This test fails the moment
    // they disagree, for ANY reason and on ANY entry in the corpus, rather than only for the trailing-space
    // instances the tests above enumerate.
    //
    // Two deliberate choices. Containment is asked of NuGetPackage.EscapesContentRoot — it is not what is under test
    // here, and a second copy of it would be the very defect this test exists to catch. The KIND, by contrast, is
    // restated independently below, because agreeing with the implementation's own kind test would make the
    // assertion circular. Entries are matched by their escaped name, which is what both sides publish; that relies
    // on the declared name and the extracted path coinciding, true for every package staged here (none of them
    // folds a "..", the case CaseOnlyCollision/PathFoldingCollision own).
    //
    // ONE carve-out, and it is not a weakening: a name declared MORE THAN ONCE. Since tasks/entry-aliasing-coverage.md
    // Review 2 (C3) such a name is always lost — the extractor kept the last copy, NuGet installs the first, so one copy
    // was written over the other — while the surviving file is still inventoried and analysed. "Both" is therefore the
    // correct answer for it (one copy analysed, one not), and the requirement there is the stronger "must be lost",
    // which still rules out "neither". Review 3 N3 recorded this listing and left naming the pair to DuplicateEntryName.
    [Fact]
    public void Open_ForEveryStagedPackage_PutsEveryInventoriableEntryInExactlyOneOfInventoryAndLost()
    {
        foreach (var path in fixture.AllPackagePaths)
        {
            using var pkg = Open(path);

            var inventoried = pkg.Assemblies.Select(a => a.RelativePath)
                .Concat(pkg.Scripts.Select(s => s.RelativePath))
                .ToHashSet(StringComparer.Ordinal);
            var lost = pkg.UninventoriedEntryNames.ToHashSet(StringComparer.Ordinal);

            var owed = pkg.DeclaredEntryNames
                .Where(n => !n.EndsWith('/') && !NuGetPackage.EscapesContentRoot(n) && NamesAnInventoriableKind(n))
                .GroupBy(n => n, StringComparer.Ordinal);

            foreach (var declared in owed)
            {
                var reported = YaraPathSafety.Escape(declared.Key);
                var isInventoried = inventoried.Contains(reported);
                var isLost = lost.Contains(reported);

                if (declared.Count() > 1)
                    Assert.True(
                        isLost,
                        $"{Path.GetFileName(path)}: entry '{reported}' is declared {declared.Count()} times but lost={isLost} " +
                        "— a duplicated name had one copy written over the other, so it must be reported lost (C3).");
                else
                    Assert.True(
                        isInventoried ^ isLost,
                        $"{Path.GetFileName(path)}: entry '{reported}' is inventoried={isInventoried}, " +
                        $"lost={isLost} — it must be in EXACTLY one. 'Neither' is a payload we neither analysed nor " +
                        "disclosed; 'both' is a report that contradicts itself.");
            }
        }
    }

    // The cheapest instance of the invariant, on the smallest package that can express it: one entry, whose name
    // ends in a space. On Linux it is held verbatim, so the answer must be "inventoried" — and the pre-fix answer
    // was "neither", a one-assembly package that reported zero assemblies, zero lost entries and exit 0.
    [LinuxExtractionFact("ext4 holds the trailing space verbatim, so the sole entry claims its own extracted file")]
    public void Open_OnLinux_ForAPackageWhoseOnlyEntryHasATrailingSpace_ReportsItNeitherLostNorAbsent()
    {
        using var pkg = Open(fixture.SoleTrailingSpacePath);

        Assert.Contains(TrailingNamePackageFixture.SoleTrailingSpaceEntry, ExtractedRelativePaths(pkg));

        Assert.Empty(pkg.UninventoriedEntryNames);                                     // not lost...
        var only = Assert.Single(pkg.Assemblies);                                      // ...and not absent
        Assert.Equal(TrailingNamePackageFixture.SoleTrailingSpaceEntry, only.RelativePath);
    }
    #endregion

    #region Methods — the two published members must not drift apart
    // UninventoriedEntryNames is now a projection of a second, internal member rather than the list itself. Two
    // parallel collections is exactly the shape that drifts, and the drift would be silent: a skip row synthesized
    // from a pair that the published list does not contain, or vice versa. Asserted over every staged package,
    // including the ones with two lost entries, so ORDER and COUNT are both pinned and not just set equality.
    [Fact]
    public void Open_ForEveryStagedPackage_PublishesExactlyTheReportedProjectionOfTheDeclaredPairs()
    {
        foreach (var path in fixture.AllPackagePaths)
        {
            using var pkg = Open(path);

            Assert.Equal(
                pkg.UninventoriedDeclaredEntries.Select(e => e.Reported),
                pkg.UninventoriedEntryNames);
            // ...and every pair really is (raw, escape-of-raw): the projection is only meaningful if Reported is
            // the escaped form of the Declared name it travels with.
            Assert.All(
                pkg.UninventoriedDeclaredEntries,
                e => Assert.Equal(YaraPathSafety.Escape(e.Declared), e.Reported));
        }
    }

    // One skip row per published name, in the same order — the wiring that makes the invariant above observable in
    // the report rather than only on the package object.
    [WindowsExtractionFact("the package with more than one lost entry only has them on Windows")]
    public void Scan_OnWindows_ForTwoLostEntries_EmitsOneSkipRowPerPublishedNameInOrder()
    {
        using var pkg = Open(fixture.TrailingPath);
        var scan = Scan(fixture.TrailingPath);

        Assert.Equal(
            pkg.UninventoriedEntryNames,
            scan.Assemblies.Where(a => a.SkipReason is not null).Select(a => a.Assembly.RelativePath));
    }
    #endregion

    #region Methods — a duplicate name with DIFFERENT bytes: the survivor analysed, the name lost once (C3)
    // Zip permits two entries with the same name and different bytes, and they resolve differently — re-measured on
    // .NET 10, both platforms, 2026-08-22 and asserted below: ZipArchive.GetEntry returns the FIRST while a
    // sequential extract-all leaves the LAST on disk. So a consumer reading by name and Silvergun reading the
    // extraction can see different bytes: "the file scanned is not the file shipped" again.
    //
    // This region used to pin a carve-out (claim once, report nothing) and said it was the test that "must change,
    // consciously". It has: tasks/entry-aliasing-coverage.md Review 2 (C3) measured a webhook .targets followed by a
    // "<Project />" of the same name scanning clean while NuGet installed the webhook, and made a duplicate name lost
    // ONCE. The analyzer's CaseOnlyCollision still ignores exact duplicates; naming the PAIR stays DuplicateEntryName's.
    [Fact]
    public void Open_ForADuplicateNameWithDifferentBytes_InventoriesTheSurvivorAndReportsTheNameLostOnce()
    {
        using var pkg = Open(fixture.DuplicateDifferentBytesPath);

        // Ground truth: the archive really does declare one name twice, with different content.
        var declared = pkg.DeclaredEntryNames.Where(n => n == TrailingNamePackageFixture.DuplicateEntry).ToArray();
        Assert.Equal(2, declared.Length);

        Assert.Equal([TrailingNamePackageFixture.DuplicateEntry], pkg.UninventoriedEntryNames);
        Assert.Equal([TrailingNamePackageFixture.DuplicateEntry], pkg.Assemblies.Select(a => a.RelativePath));
    }

    // The measurement itself, pinned where the reasoning above can be checked against reality: first by name, last
    // on disk. It is the whole reason the pair is a finding-in-waiting rather than "one entry declared twice".
    [Fact]
    public void Extraction_ForADuplicateNameWithDifferentBytes_LeavesTheLastWhileGetEntryReturnsTheFirst()
    {
        using var pkg = Open(fixture.DuplicateDifferentBytesPath);

        using (var zip = ZipFile.OpenRead(fixture.DuplicateDifferentBytesPath))
        {
            var byName = zip.GetEntry(TrailingNamePackageFixture.DuplicateEntry);
            Assert.NotNull(byName);
            Assert.Equal(fixture.ShadowedLength, byName.Length);      // the FIRST entry — the padded one
        }

        var extracted = Assert.Single(pkg.Assemblies, a => a.RelativePath == TrailingNamePackageFixture.DuplicateEntry);
        Assert.Equal(fixture.SurvivingLength, new FileInfo(extracted.FullPath).Length);   // the LAST entry
        Assert.NotEqual(fixture.ShadowedLength, fixture.SurvivingLength);
    }

    // ...and the surviving file is still genuinely analysed — C3 must not cost the package the coverage it does have —
    // next to exactly ONE not-inventoried row for the name (the overwritten copy), so the package reads incomplete.
    [Fact]
    public void Scan_ForADuplicateNameWithDifferentBytes_AnalysesTheSurvivingFileAndAddsOneNotInventoriedRow()
    {
        var scan = Scan(fixture.DuplicateDifferentBytesPath);

        Assert.Equal(2, scan.Assemblies.Count);
        Assert.All(scan.Assemblies, a => Assert.Equal(TrailingNamePackageFixture.DuplicateEntry, a.Assembly.RelativePath));

        var analysed = Assert.Single(scan.Assemblies, a => !a.NotInventoried);
        Assert.Null(analysed.SkipReason);
        Assert.NotNull(analysed.Report);

        var lost = Assert.Single(scan.Assemblies, a => a.NotInventoried);
        Assert.Contains("NOT inventoried", lost.SkipReason, StringComparison.Ordinal);
        Assert.Null(lost.Report);
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

    // Every extracted file under the package's content root, forward-slash relative — the on-disk ground truth each
    // platform-gated assertion here depends on, asserted rather than assumed.
    private static string[] ExtractedRelativePaths(NuGetPackage pkg)
    {
        var contentRoot = Directory.EnumerateDirectories(pkg.ExtractionDir).FirstOrDefault() ?? pkg.ExtractionDir;
        return Directory.EnumerateFiles(contentRoot, "*", SearchOption.AllDirectories)
            .Select(f => f[(contentRoot.Length + 1)..].Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    // An INDEPENDENT restatement of what the package owes an answer for: a name that ends in one of the extensions
    // the inventory carries, ignoring the trailing spaces and dots Windows cannot store. Written out here rather
    // than delegated to NuGetPackage's own kind test on purpose — the invariant above is about the implementation's
    // two kind tests agreeing WITH EACH OTHER AND WITH THE SPEC, and asking the implementation would make it agree
    // with itself by definition.
    private static bool NamesAnInventoriableKind(string entry)
    {
        var name = entry.TrimEnd(' ', '.');
        return InventoriedExtensions.Any(ext => name.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
    }

    private static void AssertNoRawControlCharacter(string text, string what)
    {
        var offender = text.FirstOrDefault(c => c < ' ' || c == (char)0x7F);
        Assert.True(offender == '\0' && !text.Contains('\0'), $"{what} carried raw U+{(int)offender:X4}.");
    }
    #endregion

    #region Fields
    // The extensions NuGetPackage inventories, per its own doc comment — assemblies and install-time scripts.
    private static readonly string[] InventoriedExtensions = [".dll", ".exe", ".ps1", ".psm1", ".targets", ".props"];

    private readonly TrailingNamePackageFixture fixture;
    #endregion
}

/// <summary>
/// Stages the <c>.nupkg</c> files for <see cref="TrailingSpaceOrDotCoverageTests"/> with pure BCL zip (see
/// <see cref="NupkgBuilder"/>) — no NuGet client, no network. Payloads are copies of the real fixture assembly, so an
/// inventoried entry produces a genuine capability report and "was it actually analysed?" is answerable.
///
/// <para><b>These fixtures cannot be staged from Windows PowerShell 5.1</b> (measured 2026-08-22): its
/// <c>ZipArchive.CreateEntry</c> throws <c>ArgumentException("Illegal characters in path")</c> for a
/// control-character entry name, and its <c>ZipArchive</c> silently TRUNCATES enumeration at such a name — so a
/// PowerShell-built archive would be missing entries without saying so. Built from .NET 10, which stores every name
/// verbatim.</para>
/// </summary>
public sealed class TrailingNamePackageFixture : IDisposable
{
    #region Constructors
    public TrailingNamePackageFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-trailing", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var payload = File.ReadAllBytes(typeof(Shapes).Assembly.Location);

        // W1: an inventoried kind whose trailing space / trailing dot Windows drops on the way to disk.
        TrailingPath = Write("PkgTrailingName",
            [(OrdinaryEntry, payload), (TrailingSpaceEntry, payload), (TrailingDotEntry, payload)]);

        // The false-positive guard: the SAME OS behaviour on kinds we do not inventory. "evil.dll.txt " contains
        // ".dll" and trims to a name that still does not end in one.
        UninventoriedKindPath = Write("PkgTrailingText",
            [(OrdinaryEntry, payload),
             ("content/readme.txt ", Text("readme")),
             ("content/notes.txt.", Text("notes")),
             ("content/evil.dll.txt ", Text("not an assembly"))]);

        // Scripts are an inventoried kind too, and they execute on install.
        ScriptPath = Write("PkgTrailingScript", [(OrdinaryEntry, payload), (TrailingScriptEntry, Text("Write-Host 1"))]);

        // N1: a lost entry whose ESCAPE re-segments. Windows rewrites the LF to '_', so the extracted name matches no
        // containment key and the entry is lost; Linux writes it verbatim and inventories it.
        ReSegmentingPath = Write("PkgReSegmenting", [(OrdinaryEntry, payload), (ReSegmentingEntry, payload)]);

        // N1's other half: an escapable character in the TFM SEGMENT. The NUL in the file segment is what makes this
        // one lost on both platforms (measured), so the escaping statement needs no platform gate.
        TfmEscapePath = Write("PkgTfmEscape", [(OrdinaryEntry, payload), (TfmEscapeEntry, payload)]);

        // W2's regression pin: one name, twice, with DIFFERENT bytes. The padded copy is declared FIRST so the
        // pristine one is what a sequential extract-all leaves on disk and therefore what gets analysed.
        var padded = payload.Concat(new byte[PadBytes]).ToArray();
        ShadowedLength = padded.Length;
        SurvivingLength = payload.Length;
        DuplicateDifferentBytesPath = Write("PkgDuplicateBytes", [(DuplicateEntry, padded), (DuplicateEntry, payload)]);

        // The smallest package that can express the gate/lost-test agreement: ONE entry, ending in a space. With
        // nothing else in it, "inventoried" and "reported lost" are the only two answers available, and the pre-fix
        // Linux answer was neither.
        SoleTrailingSpacePath = Write("PkgSoleTrailingSpace", [(SoleTrailingSpaceEntry, payload)]);

        AllPackagePaths =
        [
            TrailingPath, UninventoriedKindPath, ScriptPath, ReSegmentingPath, TfmEscapePath,
            DuplicateDifferentBytesPath, SoleTrailingSpacePath,
        ];
    }
    #endregion

    #region Properties
    /// <summary>An ordinary lib assembly — one lost entry must never cost the rest of the package its analysis.</summary>
    public const string OrdinaryEntry = "lib/net8.0/Ordinary.dll";

    /// <summary>An assembly entry with a TRAILING SPACE: Windows writes it as <c>trailspace.dll</c>.</summary>
    public const string TrailingSpaceEntry = "lib/net8.0/trailspace.dll ";

    /// <summary>An assembly entry with a TRAILING DOT: Windows writes it as <c>traildot.dll</c>.</summary>
    public const string TrailingDotEntry = "lib/net8.0/traildot.dll.";

    /// <summary>An install-time script entry with a trailing space — the same evasion, one extension over.</summary>
    public const string TrailingScriptEntry = "tools/init.ps1 ";

    /// <summary>
    /// A name whose escape RE-SEGMENTS: raw it is <c>lib</c> + <c>pay&lt;LF&gt;load.dll</c> (two segments, no TFM),
    /// escaped it is <c>lib\pay\nload.dll</c>-shaped (three segments, TFM "pay").
    /// </summary>
    public const string ReSegmentingEntry = "lib/pay\nload.dll";

    /// <summary>What <see cref="ReSegmentingEntry"/> must look like wherever it is published.</summary>
    public const string ReSegmentingEntryEscaped = @"lib/pay\nload.dll";

    /// <summary>A TAB in the TFM segment and a NUL in the file segment: lost on every platform, TFM needs escaping.</summary>
    public const string TfmEscapeEntry = "lib/net\t8.0/pay\0load.dll";

    /// <summary>What <see cref="TfmEscapeEntry"/> must look like wherever it is published.</summary>
    public const string TfmEscapeEntryEscaped = @"lib/net\t8.0/pay\x00load.dll";

    /// <summary>The name declared twice, with different bytes behind each occurrence.</summary>
    public const string DuplicateEntry = "content/X.dll";

    /// <summary>The ONLY entry of <see cref="SoleTrailingSpacePath"/> — the minimal gate/lost-test agreement case.</summary>
    public const string SoleTrailingSpaceEntry = "lib/net8.0/x.dll ";

    public string TrailingPath { get; }
    public string UninventoriedKindPath { get; }
    public string ScriptPath { get; }
    public string ReSegmentingPath { get; }
    public string TfmEscapePath { get; }
    public string DuplicateDifferentBytesPath { get; }
    public string SoleTrailingSpacePath { get; }

    /// <summary>Every package staged here — the corpus the two-member drift invariant is asserted over.</summary>
    public IReadOnlyList<string> AllPackagePaths { get; }

    /// <summary>Byte length of the duplicate occurrence that <c>GetEntry</c> returns and extraction discards.</summary>
    public long ShadowedLength { get; }

    /// <summary>Byte length of the duplicate occurrence that extraction leaves on disk and Silvergun analyses.</summary>
    public long SurvivingLength { get; }
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

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    // Writes "<id>.1.0.0.nupkg" with a valid root nuspec plus the given entries, every name stored VERBATIM (passed
    // as NupkgBuilder's `raw` list to document that they are unnormalized by design).
    private string Write(string id, (string Name, byte[] Bytes)[] raw)
    {
        var nuspec = NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", $"Round 3 trailing-space/dot test package ({id}).", "net8.0", []);
        var path = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [($"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec))], raw);
        return path;
    }
    #endregion

    #region Fields
    // Enough trailing padding to change the length and the hash while leaving the PE itself intact — the shadowed
    // copy is never analysed anyway (extraction keeps the last), so only "different bytes" matters.
    private const int PadBytes = 64;

    private readonly string rootDir;
    #endregion
}
