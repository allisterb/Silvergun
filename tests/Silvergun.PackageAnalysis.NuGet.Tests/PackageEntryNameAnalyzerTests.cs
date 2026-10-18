namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Xunit;

/// <summary>
/// Unit tests for <see cref="PackageEntryNameAnalyzer"/> (ADR 0031). The analyzer is a <b>pure function over
/// strings</b> — no filesystem, no archive, no ambient state — which is the architectural point of the ADR: unlike
/// everything in ADR 0029, this detection is testable on <b>every</b> platform. So there is no Linux gate, no fake
/// binary and no temp tree anywhere in this file, and if one ever appears here it means the detection has leaked
/// back into filesystem behaviour and the ADR's premise has been lost.
///
/// <para><b>The false-positive guard is the load-bearing half.</b> Every category was chosen because a legitimate
/// package essentially never trips it (ADR 0031 decision 2), so a category that fires on <c>_rels/.rels</c>, on a
/// <c>content/uni-café/</c> folder or on <c>content/COMPANY.dll</c> is not "noisy", it is <b>wrong</b> — it would be
/// a bug in the category, not a reason to relax it. <see cref="Analyze_ForOrdinaryPackageEntryNames_FindsNothing"/>
/// and its exact-set table are therefore weighted at least as heavily as the positive cases.</para>
///
/// <para><b>Platform pin.</b> <see cref="Analyze_ForEachRepresentativeName_ProducesExactlyTheseCategories"/> asserts
/// the <b>exact</b> category set for every row and is run unchanged on Windows and on Linux, so the two runs
/// together are the cross-platform agreement assertion. The row that matters most is <c>content/CON.txt</c>: on
/// Windows <c>Path.GetFullPath(@"C:\root\content\CON.txt")</c> is <c>\\.\CON</c> (measured, both platforms, before
/// this file was written), so a containment probe run unguarded would report every reserved-device entry as
/// traversal on Windows and not on Linux. See <see cref="Analyze_ForAReservedDeviceNameUnderAFolder_IsNotAlsoPathTraversal"/>.</para>
/// </summary>
public sealed class PackageEntryNameAnalyzerTests
{
    #region Methods — ControlCharacter (the ADR 0029 attack, now reported)
    // C0 (U+0000-U+001F) and DEL anywhere in the name: file name, directory segment, leading or trailing. LF is the
    // character that produced the measured ADR 0029 false negative and is the reason this category exists at all.
    [Theory]
    [InlineData("content/pay\nload.bin")]
    [InlineData("content/pay\rload.bin")]
    [InlineData("content/pay\tload.bin")]
    [InlineData("content/pay\0load.bin")]
    [InlineData("content/pay\u0001load.bin")]
    [InlineData("content/pay\u001Fload.bin")]
    [InlineData("content/pay\u007Fload.bin")]
    [InlineData("content/di\nr/a.bin")]
    [InlineData("\ncontent/a.bin")]
    [InlineData("content/a.bin\n")]
    public void Analyze_WhenAnEntryNameCarriesAControlCharacter_FlagsControlCharacter(string name) =>
        Assert.Contains(PackagingAnomalyCategory.ControlCharacter, CategoriesOf(name));

    // The detail names the offending code point, so a reviewer can tell a newline from a NUL without the raw
    // character ever being printed.
    [Fact]
    public void Analyze_ForAControlCharacter_NamesTheOffendingCodePointInTheDetail()
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze(["content/pay\nload.bin"]));

        Assert.Equal(PackagingAnomalyCategory.ControlCharacter, anomaly.Category);
        Assert.Contains("U+000A", anomaly.Detail, StringComparison.Ordinal);
    }

    // DEL is in the category (ADR 0031 decision 2 widens the ADR 0029 "unsafe name" range by U+007F), but the C1
    // controls and the Unicode line/paragraph separators are NOT — they are a logging concern, already handled by
    // the escaper, and were deliberately left out of the phase-1 categories.
    [Theory]
    [InlineData("content/nel\u0085.bin")]
    [InlineData("content/c1\u009F.bin")]
    [InlineData("content/ls\u2028.bin")]
    [InlineData("content/ps\u2029.bin")]
    public void Analyze_ForC1ControlsAndUnicodeSeparators_DoesNotFlagControlCharacter(string name) =>
        Assert.DoesNotContain(PackagingAnomalyCategory.ControlCharacter, CategoriesOf(name));
    #endregion

    #region Methods — BidiControl ("Trojan Source")
    // The embeddings/overrides (U+202A-U+202E) and the isolates (U+2066-U+2069): the characters that make
    // "…exe.txt" display as "…txt.exe".
    [Theory]
    [InlineData("content/\u202Anib.exe")]
    [InlineData("content/\u202Bnib.exe")]
    [InlineData("content/\u202Cnib.exe")]
    [InlineData("content/\u202Dnib.exe")]
    [InlineData("content/gnp\u202Ecod.exe")]
    [InlineData("content/\u2066nib.exe")]
    [InlineData("content/\u2067nib.exe")]
    [InlineData("content/\u2068nib.exe")]
    [InlineData("content/\u2069nib.exe")]
    public void Analyze_WhenAnEntryNameCarriesABidiControl_FlagsBidiControl(string name) =>
        Assert.Contains(PackagingAnomalyCategory.BidiControl, CategoriesOf(name));

    // The neighbouring, non-hostile formatting characters are NOT bidi controls: U+2029 is a separator (escaped in
    // logs, not a category) and U+206A-U+206F are deprecated formatting characters outside the ADR's list.
    [Theory]
    [InlineData("content/a\u2029b.bin")]
    [InlineData("content/a\u206Ab.bin")]
    [InlineData("content/a\u206Fb.bin")]
    public void Analyze_ForCharactersOutsideTheBidiRanges_DoesNotFlagBidiControl(string name) =>
        Assert.DoesNotContain(PackagingAnomalyCategory.BidiControl, CategoriesOf(name));

    // A bidi control leaves the analyzer escaped, so the reordering attack cannot survive into the report — the
    // rendered entry name shows "\u202e", not an override that flips the rest of the line.
    [Fact]
    public void Analyze_ForABidiControl_EscapesItOutOfTheReportedEntryName()
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze(["content/gnp\u202Ecod.exe"]));

        Assert.Equal(@"content/gnp\u202ecod.exe", anomaly.EntryName);
        Assert.DoesNotContain("\u202E", anomaly.EntryName, StringComparison.Ordinal);
    }
    #endregion

    #region Methods — InvisibleCharacter (zero-width, soft hyphen, and the ASTRAL Tag block)
    [Theory]
    [InlineData("content/a\u200Bb.bin")]   // ZERO WIDTH SPACE
    [InlineData("content/a\u200Cb.bin")]   // ZERO WIDTH NON-JOINER
    [InlineData("content/a\u200Db.bin")]   // ZERO WIDTH JOINER
    [InlineData("content/a\uFEFFb.bin")]   // ZERO WIDTH NO-BREAK SPACE / BOM
    [InlineData("content/a\u00ADb.bin")]   // SOFT HYPHEN
    public void Analyze_WhenAnEntryNameCarriesAnInvisibleCharacter_FlagsInvisibleCharacter(string name) =>
        Assert.Contains(PackagingAnomalyCategory.InvisibleCharacter, CategoriesOf(name));

    // The Unicode Tag block (U+E0000-U+E007F) is ASTRAL: it exists in the string only as a surrogate PAIR, so a
    // per-char scan would see two lone surrogates and match nothing. This is the case that proves the analyzer
    // enumerates runes, and it is the one an attacker reaches for precisely because it is a full invisible ASCII
    // alphabet. U+E0041 is TAG LATIN CAPITAL LETTER A.
    [Theory]
    [InlineData("content/a\U000E0001b.bin")]   // LANGUAGE TAG (first of the block)
    [InlineData("content/a\U000E0041b.bin")]   // TAG LATIN CAPITAL LETTER A
    [InlineData("content/a\U000E007Fb.bin")]   // CANCEL TAG (last of the block)
    public void Analyze_WhenAnEntryNameCarriesAnAstralTagBlockCharacter_FlagsInvisibleCharacter(string name) =>
        Assert.Contains(PackagingAnomalyCategory.InvisibleCharacter, CategoriesOf(name));

    // ...and the detail names the ASTRAL code point, not one of its surrogate halves (U+D800/U+DC41) — the tell
    // that the scan is by rune. U+E0041 needs five hex digits, so a four-digit-only formatter would show it wrong.
    [Fact]
    public void Analyze_ForAnAstralTagBlockCharacter_NamesTheAstralCodePointNotASurrogateHalf()
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze(["content/a\U000E0041b.bin"]));

        Assert.Equal(PackagingAnomalyCategory.InvisibleCharacter, anomaly.Category);
        Assert.Contains("U+E0041", anomaly.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("U+DB40", anomaly.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("U+DC41", anomaly.Detail, StringComparison.Ordinal);
    }

    // A LONE surrogate is a malformed name, not one of these seven anomalies. It must not throw, must not be
    // mistaken for the Tag block (its high half sits in the same D800-DBFF range the astral pair is built from),
    // and must not be reported: "the author wrote ill-formed UTF-16" is a different observation from any category
    // in ADR 0031 decision 2, and inventing a finding for it would be a false positive.
    //
    // A [Fact], not an [InlineData]: xUnit serializes theory arguments through XML, and a lone surrogate is not
    // representable there.
    [Fact]
    public void Analyze_ForALoneSurrogate_ReportsNothingAndDoesNotThrow()
    {
        var names = new[] { "content/a\uD800b.bin", "content/a\uDC41b.bin", "content/\uDBFF.bin" };

        var thrown = Record.Exception(() => { PackageEntryNameAnalyzer.Analyze(names); });

        Assert.Null(thrown);
        Assert.Empty(PackageEntryNameAnalyzer.Analyze(names));
    }
    #endregion

    #region Methods — PathTraversal (the detection ADR 0008 found and then discarded)
    // Three shapes, all reported under one category: a name that walks up out of the content root, a ROOTED
    // (absolute) name, and a DRIVE-QUALIFIED one. The last two are asserted on both platforms deliberately — on
    // Unix "C:\evil.dll" is a perfectly legal relative filename, so a containment probe alone would call it
    // contained; the analyzer tests them structurally so a package cannot be reported differently depending on
    // which machine happened to scan it.
    [Theory]
    [InlineData("../../evil.dll")]
    [InlineData("..\\..\\evil.dll")]
    [InlineData("../content/a.bin")]
    [InlineData("content/../../evil.dll")]
    [InlineData("/etc/cron.d/payload")]
    [InlineData("\\\\server\\share\\evil.dll")]
    [InlineData("/absolute.bin")]
    [InlineData("C:\\Windows\\System32\\evil.dll")]
    [InlineData("c:/windows/system32/evil.dll")]
    [InlineData("D:evil.dll")]
    public void Analyze_WhenAnEntryTargetEscapesTheContentRoot_FlagsPathTraversal(string name) =>
        Assert.Contains(PackagingAnomalyCategory.PathTraversal, CategoriesOf(name));

    // A ".." that is CONTAINED is not traversal. "content/../a.bin" resolves back inside the root, and a package
    // that merely writes an ugly-but-contained path is not attacking anyone — flagging it would be exactly the
    // kind of false positive ADR 0031 says is a bug in the category.
    [Theory]
    [InlineData("content/../a.bin")]
    [InlineData("content/sub/../a.bin")]
    [InlineData("content/./a.bin")]
    [InlineData("./content/a.bin")]
    [InlineData("content/..evil/a.bin")]     // a segment that merely STARTS with dots is not a ".." segment
    [InlineData("content/a..b/x.bin")]
    public void Analyze_WhenAnEntryTargetStaysInsideTheContentRoot_DoesNotFlagPathTraversal(string name) =>
        Assert.DoesNotContain(PackagingAnomalyCategory.PathTraversal, CategoriesOf(name));

    // THE regression pin, and the reason the containment probe is guarded by a ".." pre-test.
    //
    // Measured on both platforms before this test was written:
    //   Windows  Path.GetFullPath(@"C:\silvergun\probe\content\CON.txt") == @"\\.\CON"          (escapes the root)
    //   Linux    Path.GetFullPath("/silvergun/probe/content/CON.txt")    == the path itself      (contained)
    // Windows' path normalizer redirects DOS device names, so an unguarded probe reports EVERY reserved-device
    // entry as traversal — on Windows only. That is a false positive, and a platform-dependent one, in an analyzer
    // whose entire premise is being a pure function over strings. This test runs on both platforms and must give
    // the same answer on each: ReservedDeviceName, and nothing else.
    [Theory]
    [InlineData("content/CON.txt")]
    [InlineData("content/con")]
    [InlineData("content/nul.log")]
    [InlineData("content/PRN.dat")]
    [InlineData("content/aux.bin")]
    [InlineData("content/COM1.dll")]
    [InlineData("content/LPT9")]
    [InlineData("CON.txt")]
    [InlineData("content/CON/a.bin")]
    // The row that was a WINDOWS-ONLY DIVERGENCE until the dos-device-name fix (ADR 0030, sixth instance). A ".."
    // segment defeats the pre-test above, so containment was consulted, and on Windows
    // Path.GetFullPath(@"C:\root\content\..\CON.txt") is @"\\.\CON" — "escapes" — while Linux answered "contained".
    // The same package therefore reported PathTraversal on one OS and not on the other, in a function documented as
    // platform-independent. Containment is lexical now, so both platforms say ReservedDeviceName and nothing else.
    [InlineData("content/../CON.txt")]
    [InlineData("content/../COM1.dll")]
    public void Analyze_ForAReservedDeviceNameUnderAFolder_IsNotAlsoPathTraversal(string name)
    {
        var categories = CategoriesOf(name);

        Assert.Equal(new[] { PackagingAnomalyCategory.ReservedDeviceName }, categories);
        Assert.DoesNotContain(PackagingAnomalyCategory.PathTraversal, categories);
    }

    // The degenerate name that resolves to the ROOT ITSELF. NuGetPackage.EscapesContentRoot answers "true" for it —
    // correctly, since it names no file strictly under the root and so can never be inventoried — but that is not
    // the same statement as "this entry attacks the extraction directory". The analyzer's ".." pre-test is what
    // keeps a malformed name out of the report, and the ground-truth assertion here is what says the pre-test is
    // still load-bearing rather than dead code.
    [Fact]
    public void Analyze_ForADegenerateNameThatResolvesToTheRootItself_DoesNotFlagPathTraversal()
    {
        Assert.True(
            NuGetPackage.EscapesContentRoot("."),
            "ground truth: '.' names no file strictly under the content root, so containment excludes it.");

        Assert.Empty(PackageEntryNameAnalyzer.Analyze(["."]));
    }

    // The same carve-out for the name the ".." pre-test never caught, and the one the doc used to claim was
    // already handled: "content/.." resolves to the content root ITSELF. NuGetPackage.EscapesContentRoot answers
    // true for it — correctly, since it names no file strictly under the root and can never be inventoried — but
    // "names nothing" is not "attacks the extraction directory", and PathTraversal is defined as the latter (ADR
    // 0031 decision 2). Reporting it would be a false positive in a category chosen for precision. The carve-out
    // is resolved-depth == 0, so every spelling of "back to exactly the root" is covered, not just the two literals.
    [Theory]
    [InlineData(".")]
    [InlineData("content/..")]
    [InlineData("content\\..")]
    [InlineData("content/sub/../..")]
    [InlineData("content/./..")]
    [InlineData("a/b/c/../../..")]
    public void Analyze_ForANameThatResolvesToTheContentRootItself_ReportsNothing(string name)
    {
        Assert.Equal(0, NuGetPackage.ResolvedDepth(name));   // ground truth: it resolves TO the root, not above it
        Assert.True(
            NuGetPackage.EscapesContentRoot(name),
            "ground truth: containment still excludes it — it names no file that could be inventoried.");

        Assert.Empty(PackageEntryNameAnalyzer.Analyze([name]));
    }

    // ...and one segment further up is a real attack again. The carve-out is exactly depth 0: anything that walks
    // ABOVE the root is still PathTraversal, so the fix for the false positive cannot have opened a false negative.
    [Theory]
    [InlineData("content/../..")]
    [InlineData("content/../../x.dll")]
    [InlineData("content/sub/../../../x.dll")]
    [InlineData("..")]
    [InlineData("../x.dll")]
    public void Analyze_ForANameThatWalksAboveTheContentRoot_StillFlagsPathTraversal(string name)
    {
        Assert.Equal(-1, NuGetPackage.ResolvedDepth(name));   // ground truth: it really does leave the root

        Assert.Contains(PackagingAnomalyCategory.PathTraversal, CategoriesOf(name));
    }

    // A name that BOTH escapes the root and is a reserved device is reported as both — the guard suppresses the
    // spurious probe, it does not suppress real traversal. "../CON.txt" genuinely leaves the root on both
    // platforms (measured), so this row is platform-independent too.
    [Fact]
    public void Analyze_ForAReservedDeviceNameThatAlsoEscapesTheRoot_FlagsBoth()
    {
        Assert.Equal(
            new[] { PackagingAnomalyCategory.PathTraversal, PackagingAnomalyCategory.ReservedDeviceName },
            CategoriesOf("../CON.txt"));
    }
    #endregion

    #region Methods — CaseOnlyCollision
    // Two entries differing only by case: on a Windows extraction one silently overwrites the other, so the file
    // scanned is not the file shipped. Reported ONCE for the group, at the group's first member.
    [Fact]
    public void Analyze_ForTwoEntriesDifferingOnlyByCase_ReportsOneCollisionNamingThePartner()
    {
        var anomaly = Assert.Single(
            PackageEntryNameAnalyzer.Analyze(["lib/net10.0/A.dll", "lib/net10.0/a.dll"]));

        Assert.Equal(PackagingAnomalyCategory.CaseOnlyCollision, anomaly.Category);
        Assert.Equal("lib/net10.0/A.dll", anomaly.EntryName);            // the group's FIRST member
        Assert.Contains("lib/net10.0/a.dll", anomaly.Detail, StringComparison.Ordinal);   // ...naming the partner
    }

    // A group of THREE is still one finding, and it names BOTH partners — not one, and not three separate
    // findings that a reviewer would have to reassemble.
    [Fact]
    public void Analyze_ForThreeEntriesDifferingOnlyByCase_ReportsOneCollisionNamingBothPartners()
    {
        var anomaly = Assert.Single(
            PackageEntryNameAnalyzer.Analyze(["lib/A.dll", "lib/a.dll", "lib/A.DLL"]));

        Assert.Equal(PackagingAnomalyCategory.CaseOnlyCollision, anomaly.Category);
        Assert.Equal("lib/A.dll", anomaly.EntryName);
        Assert.Contains("lib/a.dll", anomaly.Detail, StringComparison.Ordinal);
        Assert.Contains("lib/A.DLL", anomaly.Detail, StringComparison.Ordinal);
    }

    // Two INDEPENDENT colliding groups produce two findings, one per group — the grouping is per name, not global.
    [Fact]
    public void Analyze_ForTwoSeparateCollidingGroups_ReportsOneFindingPerGroup()
    {
        var anomalies = PackageEntryNameAnalyzer.Analyze(
            ["lib/A.dll", "lib/B.dll", "lib/a.dll", "lib/b.dll"]);

        Assert.Equal(2, anomalies.Count);
        Assert.All(anomalies, a => Assert.Equal(PackagingAnomalyCategory.CaseOnlyCollision, a.Category));
        Assert.Equal(new[] { "lib/A.dll", "lib/B.dll" }, anomalies.Select(a => a.EntryName));
    }

    // EXACT (ordinal) duplicates are NOT a case-only collision. Two entries with byte-identical names is a
    // different packaging defect, deliberately out of ADR 0031's scope — reporting it here would fire this
    // category on a class of package it was not chosen for.
    [Fact]
    public void Analyze_ForExactOrdinalDuplicateEntryNames_ReportsNoCollision()
    {
        Assert.Empty(PackageEntryNameAnalyzer.Analyze(["lib/A.dll", "lib/A.dll", "lib/A.dll"]));
    }

    // An exact duplicate alongside a genuine case-only partner is still ONE finding — the duplicate must not
    // produce a second copy of the group's anomaly.
    [Fact]
    public void Analyze_ForAnExactDuplicateAlongsideACaseOnlyPartner_StillReportsOneCollision()
    {
        var anomaly = Assert.Single(
            PackageEntryNameAnalyzer.Analyze(["lib/A.dll", "lib/A.dll", "lib/a.dll"]));

        Assert.Equal(PackagingAnomalyCategory.CaseOnlyCollision, anomaly.Category);
        Assert.Equal("lib/A.dll", anomaly.EntryName);
    }

    // Names that differ by more than case are not a collision, however similar they look.
    [Fact]
    public void Analyze_ForNamesDifferingByMoreThanCase_ReportsNoCollision()
    {
        Assert.Empty(PackageEntryNameAnalyzer.Analyze(
            ["lib/A.dll", "lib/A2.dll", "lib/net10.0/A.dll", "lib/A.dl"]));
    }

    // The group size is ATTACKER-CHOSEN — a package may declare a thousand case variants of one name — and every
    // partner is an attacker-chosen string, so an uncapped detail puts all of them into one log line, one JSON
    // field and one table cell. At most four partners are named and the rest collapse to ", and N more", the same
    // bound CodePointDetail applies for the same reason. Ten variants: nine partners, four shown, five counted.
    [Fact]
    public void Analyze_ForACollisionGroupOfTenCaseVariants_NamesAtMostFourPartnersAndCountsTheRest()
    {
        var names = CaseVariants("lib/collide.dll", 10);

        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze(names));

        Assert.Equal(PackagingAnomalyCategory.CaseOnlyCollision, anomaly.Category);
        Assert.Equal(4, names.Count(n => anomaly.Detail.Contains(n, StringComparison.Ordinal) && n != anomaly.EntryName));
        Assert.EndsWith(", and 5 more", anomaly.Detail, StringComparison.Ordinal);
    }

    // The cap is a BOUND, not a fixed shape: a bigger group produces a longer count, not a longer list. Two group
    // sizes are compared so a detail that grew with N would fail even if it happened to end with ", and N more".
    [Fact]
    public void Analyze_ForEverLargerCollisionGroups_KeepsTheDetailBounded()
    {
        var ten = Assert.Single(PackageEntryNameAnalyzer.Analyze(CaseVariants("lib/collide.dll", 10)));
        var sixty = Assert.Single(PackageEntryNameAnalyzer.Analyze(CaseVariants("lib/collide.dll", 60)));

        Assert.EndsWith(", and 55 more", sixty.Detail, StringComparison.Ordinal);   // 59 partners, 4 shown
        Assert.True(
            sixty.Detail.Length <= ten.Detail.Length + 2,
            $"a six-fold larger group grew the detail from {ten.Detail.Length} to {sixty.Detail.Length} characters.");
    }

    // A group of exactly five (four partners) is the boundary: every partner fits, so nothing is elided and no
    // spurious ", and 0 more" appears.
    [Fact]
    public void Analyze_ForACollisionGroupAtTheCap_NamesEveryPartnerWithNoElision()
    {
        var names = CaseVariants("lib/collide.dll", 5);

        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze(names));

        Assert.Equal(4, names.Count(n => anomaly.Detail.Contains(n, StringComparison.Ordinal) && n != anomaly.EntryName));
        Assert.DoesNotContain(" more", anomaly.Detail, StringComparison.Ordinal);
    }

    // A colliding partner is attacker-authored text like any other name, so it is escaped where it appears inside
    // the DETAIL string too (ADR 0031 decision 4) — not only in EntryName.
    [Fact]
    public void Analyze_ForACollisionWhosePartnerIsHostile_EscapesThePartnerInTheDetail()
    {
        var anomalies = PackageEntryNameAnalyzer.Analyze(["lib/a\u202Eb.dll", "lib/A\u202EB.dll"]);

        var collision = Assert.Single(anomalies, a => a.Category == PackagingAnomalyCategory.CaseOnlyCollision);
        Assert.DoesNotContain('\u202E', collision.Detail);
        Assert.Contains(@"lib/A\u202eB.dll", collision.Detail, StringComparison.Ordinal);
    }
    #endregion

    #region Methods — TrailingSpaceOrDot
    // Windows silently strips a trailing space or '.', so "evil.dll " and "evil.dll" are the same file there and
    // different everywhere else. Any SEGMENT counts, not just the last one.
    [Theory]
    [InlineData("content/evil.dll ")]
    [InlineData("content/evil.dll.")]
    [InlineData("content /evil.dll")]
    [InlineData("content./evil.dll")]
    [InlineData("a/b /c.bin")]
    public void Analyze_WhenAPathSegmentEndsWithASpaceOrDot_FlagsTrailingSpaceOrDot(string name) =>
        Assert.Contains(PackagingAnomalyCategory.TrailingSpaceOrDot, CategoriesOf(name));

    // The "." and ".." segments are NAVIGATION, not names. Flagging them would make every "content/./a.bin" an
    // anomaly and would duplicate what PathTraversal already reasons about — so they are excluded, and a
    // contained "content/../a.bin" produces nothing at all.
    [Theory]
    [InlineData("content/./a.bin")]
    [InlineData("content/../a.bin")]
    [InlineData("./a.bin")]
    [InlineData("../../evil.dll")]      // reported as PathTraversal, but never as TrailingSpaceOrDot
    [InlineData("content/./sub/../a.bin")]
    public void Analyze_ForDotAndDotDotSegments_DoesNotFlagTrailingSpaceOrDot(string name) =>
        Assert.DoesNotContain(PackagingAnomalyCategory.TrailingSpaceOrDot, CategoriesOf(name));

    // A leading dot, an interior dot and an interior space are all ordinary — only the segment's LAST character
    // matters. "_rels/.rels" and "[Content_Types].xml" are in every real nupkg ever published.
    [Theory]
    [InlineData("_rels/.rels")]
    [InlineData("content/.gitignore")]
    [InlineData("content/with space.bin")]
    [InlineData("content/dot.in.middle.bin")]
    [InlineData("content/ leading.bin")]
    public void Analyze_ForOrdinaryDotsAndSpaces_DoesNotFlagTrailingSpaceOrDot(string name) =>
        Assert.DoesNotContain(PackagingAnomalyCategory.TrailingSpaceOrDot, CategoriesOf(name));
    #endregion

    #region Methods — ReservedDeviceName
    // The stem (the text before the first '.') of ANY segment, case-insensitive, with or without an extension.
    [Theory]
    [InlineData("CON")]
    [InlineData("content/CON.txt")]
    [InlineData("content/con.txt")]
    [InlineData("content/CoN.tXt")]
    [InlineData("content/PRN")]
    [InlineData("content/aux.config")]
    [InlineData("content/NUL.log")]
    [InlineData("content/COM1.dll")]
    [InlineData("content/COM9")]
    [InlineData("content/LPT1.txt")]
    [InlineData("content/LPT9")]
    [InlineData("content/NUL/a.bin")]           // in a DIRECTORY segment
    [InlineData("content/con.tar.gz")]          // stem is the text before the FIRST dot
    public void Analyze_WhenAPathSegmentIsAReservedDeviceName_FlagsReservedDeviceName(string name) =>
        Assert.Contains(PackagingAnomalyCategory.ReservedDeviceName, CategoriesOf(name));

    // Names that merely START with a reserved stem, or that use an out-of-range ordinal, are ordinary — and
    // "content/COMPANY.dll" is exactly the kind of real package file this category must never fire on.
    [Theory]
    [InlineData("content/COMPANY.dll")]
    [InlineData("content/CONSOLE.dll")]
    [InlineData("content/console/app.bin")]
    [InlineData("content/CON2.txt")]
    [InlineData("content/COM0.dll")]
    [InlineData("content/COM10.dll")]
    [InlineData("content/LPT0.txt")]
    [InlineData("content/AUXILIARY.bin")]
    [InlineData("content/NULL.bin")]
    [InlineData("content/PRNTR.bin")]
    [InlineData("content/my-con.txt")]
    [InlineData("_rels/.rels")]                 // stem is the EMPTY string, which is not a device name
    public void Analyze_ForNamesThatMerelyResembleADeviceName_DoesNotFlagReservedDeviceName(string name) =>
        Assert.DoesNotContain(PackagingAnomalyCategory.ReservedDeviceName, CategoriesOf(name));
    #endregion

    #region Methods — the false-positive guard (weighted above every positive case above)
    // Ordinary package entry names — including the structural files every real .nupkg ships, non-ASCII folder and
    // file names, emoji, backslash separators (some Windows packing tools emit them) and directory entries — must
    // produce NOTHING. A category that fires here is a bug in the category, not a tuning problem (ADR 0031).
    [Theory]
    [InlineData("lib/net10.0/Silvergun.Runtime.dll")]
    [InlineData("Silvergun.Runtime.nuspec")]
    [InlineData("_rels/.rels")]
    [InlineData("[Content_Types].xml")]
    [InlineData("package/services/metadata/core-properties/8f3a1c9b.psmdcp")]
    [InlineData(".signature.p7s")]
    [InlineData("content/COMPANY.dll")]
    [InlineData("content/uni-caf\u00E9/a.bin")]
    [InlineData("content/\u65E5\u672C\u8A9E/\u30C7\u30FC\u30BF.bin")]
    [InlineData("content/\u4E2D\u6587\u76EE\u5F55/x.bin")]
    [InlineData("content/\uD55C\uAD6D\uC5B4.bin")]
    [InlineData("content/\U0001F600.bin")]
    [InlineData("content/with space.bin")]
    [InlineData("content/dot.in.middle.bin")]
    [InlineData("lib\\netstandard2.0\\Foo.dll")]
    [InlineData("content/")]
    [InlineData("lib/net10.0/")]
    [InlineData("tools/net472/install.ps1")]
    [InlineData("build/Silvergun.props")]
    [InlineData("content/../a.bin")]
    [InlineData("readme.md")]
    public void Analyze_ForOrdinaryPackageEntryNames_FindsNothing(string name) =>
        Assert.Empty(PackageEntryNameAnalyzer.Analyze([name]));

    // The same guard over a whole realistic package listing at once, so a cross-entry category (CaseOnlyCollision)
    // is exercised against a benign corpus too rather than only against single names.
    [Fact]
    public void Analyze_ForARealisticBenignPackageListing_FindsNothing()
    {
        string[] listing =
        [
            "_rels/.rels",
            "[Content_Types].xml",
            "package/services/metadata/core-properties/8f3a1c9b.psmdcp",
            "Contoso.Widgets.nuspec",
            "lib/netstandard2.0/Contoso.Widgets.dll",
            "lib/netstandard2.0/Contoso.Widgets.xml",
            "lib/net10.0/Contoso.Widgets.dll",
            "lib/net10.0/Contoso.Widgets.xml",
            "build/Contoso.Widgets.props",
            "build/Contoso.Widgets.targets",
            "tools/net472/install.ps1",
            "content/uni-caf\u00E9/readme.txt",
            "content/\u65E5\u672C\u8A9E/readme.txt",
            "content/COMPANY.dll",
            "icon.png",
            "README.md",
        ];

        Assert.Empty(PackageEntryNameAnalyzer.Analyze(listing));
    }
    #endregion

    #region Methods — the exact-category table (run unchanged on Windows and Linux — the platform pin)
    // One row per representative name with the EXACT set of categories it must produce. Exactness is the point:
    // "contains X" would let a Windows-only extra category (the \\.\CON redirect) slip through unnoticed, which is
    // precisely the regression this table exists to catch. Executed on both platforms; agreement between the two
    // runs is the cross-platform assertion.
    //
    // A single [Fact] with an in-code table rather than [InlineData] rows: the failure message can then name every
    // divergent row at once, which is what a platform comparison actually needs.
    [Fact]
    public void Analyze_ForEachRepresentativeName_ProducesExactlyTheseCategories()
    {
        (string Name, PackagingAnomalyCategory[] Expected)[] table =
        [
            // --- the seven categories, one at a time ---
            ("content/pay\nload.bin",   [PackagingAnomalyCategory.ControlCharacter]),
            ("content/gnp\u202Ecod.exe", [PackagingAnomalyCategory.BidiControl]),
            ("content/a\u200Bb.bin",    [PackagingAnomalyCategory.InvisibleCharacter]),
            ("content/a\U000E0041b.bin", [PackagingAnomalyCategory.InvisibleCharacter]),
            ("../../evil.dll",          [PackagingAnomalyCategory.PathTraversal]),
            ("/etc/cron.d/payload",     [PackagingAnomalyCategory.PathTraversal]),
            ("C:\\Windows\\evil.dll",   [PackagingAnomalyCategory.PathTraversal]),
            ("content/evil.dll ",       [PackagingAnomalyCategory.TrailingSpaceOrDot]),
            ("content/evil.dll.",       [PackagingAnomalyCategory.TrailingSpaceOrDot]),
            ("content/CON.txt",         [PackagingAnomalyCategory.ReservedDeviceName]),   // <- the Windows pin
            ("content/../CON.txt",      [PackagingAnomalyCategory.ReservedDeviceName]),   // <- ...and its ".." twin
            ("content/nul.log",         [PackagingAnomalyCategory.ReservedDeviceName]),
            ("content/LPT9",            [PackagingAnomalyCategory.ReservedDeviceName]),

            // --- combinations ---
            ("../CON.txt", [PackagingAnomalyCategory.PathTraversal, PackagingAnomalyCategory.ReservedDeviceName]),
            ("content/pay\nload\u202E.bin",
                [PackagingAnomalyCategory.ControlCharacter, PackagingAnomalyCategory.BidiControl]),
            ("../content/pay\nload\u202E\u200B.dll ",
            [
                PackagingAnomalyCategory.ControlCharacter,
                PackagingAnomalyCategory.BidiControl,
                PackagingAnomalyCategory.InvisibleCharacter,
                PackagingAnomalyCategory.PathTraversal,
                PackagingAnomalyCategory.TrailingSpaceOrDot,
            ]),

            // --- nothing at all ---
            ("lib/net10.0/Foo.dll",     []),
            ("_rels/.rels",             []),
            ("[Content_Types].xml",     []),
            ("content/COMPANY.dll",     []),
            ("content/uni-caf\u00E9/a.bin", []),
            ("content/\u65E5\u672C\u8A9E/x.bin", []),
            ("content/../a.bin",        []),
            ("content/./a.bin",         []),
            (".",                       []),   // degenerate, not an attack: never PathTraversal
            ("content/..",              []),   // ...and so is every other spelling of "resolves to the root"
            ("content/sub/../..",       []),
            ("content/../../evil.dll",  [PackagingAnomalyCategory.PathTraversal]),   // one segment further: an attack
            ("lib\\netstandard2.0\\Foo.dll", []),
        ];

        var divergent = table
            .Select(row => (row.Name, row.Expected, Actual: CategoriesOf(row.Name)))
            .Where(row => !row.Expected.SequenceEqual(row.Actual))
            .Select(row => $"  '{Printable(row.Name)}': expected [{string.Join(", ", row.Expected)}], got [{string.Join(", ", row.Actual)}]")
            .ToArray();

        Assert.True(
            divergent.Length == 0,
            $"{divergent.Length} entry name(s) produced the wrong category set on {PlatformName}:\n"
            + string.Join('\n', divergent));
    }
    #endregion

    #region Methods — multi-category names and result ordering
    // One entry may yield several anomalies, and they come back in PackagingAnomalyCategory DECLARATION order —
    // stable, so a report diff between two scans of the same package is empty.
    [Fact]
    public void Analyze_ForAMultiCategoryName_ReturnsTheCategoriesInDeclarationOrder()
    {
        var anomalies = PackageEntryNameAnalyzer.Analyze(["../content/pay\nload\u202E\u200B.dll "]);

        Assert.Equal(
            new[]
            {
                PackagingAnomalyCategory.ControlCharacter,
                PackagingAnomalyCategory.BidiControl,
                PackagingAnomalyCategory.InvisibleCharacter,
                PackagingAnomalyCategory.PathTraversal,
                PackagingAnomalyCategory.TrailingSpaceOrDot,
            },
            anomalies.Select(a => a.Category));

        // Every anomaly for one entry names that same (escaped) entry, so a reviewer can group them by eye.
        //
        // ALL THREE hostile code points come back escaped: U+000A as "\n", U+202E as "\u202e" and U+200B as
        // "\u200b", so the reported name carries no raw invisible or reordering character at all.
        //
        // This literal used to end in a RAW U+200B, defended by a comment asserting that zero-width was outside
        // the escaper's alphabet and "survives verbatim". That was the ADR 0031 decision 4 defect measured in
        // docs/agent/measurements/packaging-anomalies-top100-2026-08-22.md, not a property worth pinning: an
        // InvisibleCharacter anomaly whose EntryName still contains the invisible character reports nothing a
        // reader can see. A raw U+200B here is therefore a REGRESSION, never a literal to re-baseline.
        const string expectedEntryName = @"../content/pay\nload\u202e\u200b.dll ";
        Assert.All(anomalies, a => Assert.Equal(expectedEntryName, a.EntryName));
        Assert.All(anomalies, a => Assert.False(
            a.EntryName.Contains('\u200b'), "the reported entry name still carried a raw U+200B."));
    }

    // Anomalies come back in INPUT order across entries — the archive order the central directory was read in, so
    // the report reads in the order the package was written.
    [Fact]
    public void Analyze_AcrossSeveralEntries_ReturnsAnomaliesInInputOrder()
    {
        var anomalies = PackageEntryNameAnalyzer.Analyze(
            ["lib/ok.dll", "content/a\nb.bin", "lib/fine.dll", "../../evil.dll", "content/c\u202Ed.bin"]);

        Assert.Equal(
            new[] { @"content/a\nb.bin", "../../evil.dll", @"content/c\u202ed.bin" },
            anomalies.Select(a => a.EntryName));
    }

    // Order-stability the other way round: the SAME names in a different order produce the same anomalies, just
    // re-ordered to match. Nothing depends on hashing order or on which entry happened to come first.
    [Fact]
    public void Analyze_ForTheSameNamesInADifferentOrder_ProducesTheSameAnomalySet()
    {
        string[] forward = ["content/a\nb.bin", "../../evil.dll", "content/CON.txt"];
        string[] reversed = [.. forward.Reverse()];

        var a = PackageEntryNameAnalyzer.Analyze(forward);
        var b = PackageEntryNameAnalyzer.Analyze(reversed);

        Assert.Equal(
            a.OrderBy(x => x.EntryName, StringComparer.Ordinal).ToArray(),
            b.OrderBy(x => x.EntryName, StringComparer.Ordinal).ToArray());
        Assert.Equal(a.Reverse().ToArray(), b);
    }

    // Determinism: the same input always yields the same output, value-for-value. The analyzer takes no clock, no
    // random source and no ambient state, and this is what says so.
    [Fact]
    public void Analyze_ForTheSameInputTwice_IsDeterministic()
    {
        string[] names =
        [
            "content/pay\nload.bin", "lib/A.dll", "lib/a.dll", "../../evil.dll",
            "content/CON.txt", "content/evil.dll ", "content/a\u200Bb.bin", "lib/ok.dll",
        ];

        var first = PackageEntryNameAnalyzer.Analyze(names);
        var second = PackageEntryNameAnalyzer.Analyze(names);

        Assert.Equal(first, second);
        Assert.Equal(first.Count, second.Count);
    }
    #endregion

    #region Methods — degenerate input and the never-throws contract
    [Fact]
    public void Analyze_ForNull_ReturnsEmpty() => Assert.Empty(PackageEntryNameAnalyzer.Analyze(null));

    [Fact]
    public void Analyze_ForAnEmptyList_ReturnsEmpty() =>
        Assert.Empty(PackageEntryNameAnalyzer.Analyze(Array.Empty<string>()));

    // Null and empty NAMES are ignored rather than reported: a zip can declare one, and "the entry has no name" is
    // not one of ADR 0031's seven categories.
    [Fact]
    public void Analyze_ForNullOrEmptyEntryNames_IgnoresThemAndDoesNotThrow()
    {
        var anomalies = PackageEntryNameAnalyzer.Analyze([null!, string.Empty, "lib/ok.dll", null!]);

        Assert.Empty(anomalies);
    }

    // Degenerate names alongside a real one: the real anomaly still surfaces.
    [Fact]
    public void Analyze_ForNullNamesAlongsideAHostileOne_StillReportsTheHostileOne()
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze([null!, "content/pay\nload.bin", string.Empty]));

        Assert.Equal(PackagingAnomalyCategory.ControlCharacter, anomaly.Category);
    }

    // Never throws, whatever the package author wrote — including the names the platform's own path normalizer
    // refuses outright (an embedded NUL after a ".."), a very long name, and separators-only names. The analyzer
    // runs inside PackageScanner.Scan, so a throw here would sink an entire package scan.
    [Fact]
    public void Analyze_ForPathologicalNames_NeverThrows()
    {
        string[] pathological =
        [
            "../pay\0load.bin",                       // GetFullPath refuses an embedded NUL — must be swallowed
            "..\0/..\0/evil.dll",
            new string('a', 40_000),
            "../" + new string('b', 40_000) + "/x.bin",
            "/", "\\", "//", "..", ".", "...", "....",
            "://", "C:", "c:", "1:x", ":", " ", "   ",
            "\u202E", "\u200B", "\uFEFF", "\0",
            "con", "CON.", "CON ",
            "a/".PadRight(4000, 'x'),
        ];

        var thrown = Record.Exception(() => { PackageEntryNameAnalyzer.Analyze(pathological); });

        Assert.Null(thrown);
    }
    #endregion

    #region Methods — escaping at the boundary (ADR 0031 decision 4)
    // Nothing that leaves the analyzer — neither EntryName nor Detail — may carry a raw control character, DEL, a
    // C1 control, a line/paragraph separator or a bidi control. This is the report/renderer/log boundary: an
    // unescaped name here is a forged log line or a reordered terminal, which is the whole reason the ADR routes
    // every string through YaraPathSafety.Escape.
    [Fact]
    public void Analyze_ForHostileNames_NeverEmitsRawControlOrBidiTextInAnyField()
    {
        string[] hostile =
        [
            "content/pay\nload.bin", "content/pay\rload.bin", "content/pay\0load.bin",
            "content/de\u007Fl.bin", "content/c1\u009F.bin", "content/ls\u2028.bin",
            "content/gnp\u202Ecod.exe", "content/iso\u2066late.bin",
            "../../ev\nil.dll", "lib/a\u202Eb.dll", "lib/A\u202EB.dll",
            "content/CON\n.txt", "content/evil.dll\t ",
        ];

        var anomalies = PackageEntryNameAnalyzer.Analyze(hostile);

        Assert.NotEmpty(anomalies);
        foreach (var anomaly in anomalies)
        {
            AssertNoRawHostileText(anomaly.EntryName, nameof(anomaly.EntryName), anomaly);
            AssertNoRawHostileText(anomaly.Detail, nameof(anomaly.Detail), anomaly);
        }
    }

    // Escaping ADDS, it never strips: the surrounding, legitimate path text survives so the reported name is still
    // recognisable as the entry it came from. A detector that simply deleted the hostile characters would satisfy
    // the property above and make the report useless.
    [Fact]
    public void Analyze_ForAHostileName_KeepsTheOrdinaryPathTextAroundTheEscape()
    {
        var anomaly = Assert.Single(PackageEntryNameAnalyzer.Analyze(["lib/net10.0/rep\nort.bin"]));

        Assert.Equal(@"lib/net10.0/rep\nort.bin", anomaly.EntryName);
    }

    // Every anomaly carries a non-empty detail — the category alone does not tell a reviewer WHICH code point,
    // segment or partner tripped it, and "packaging anomaly, no further information" is not a finding.
    [Fact]
    public void Analyze_ForEveryAnomaly_CarriesANonEmptyDetail()
    {
        var anomalies = PackageEntryNameAnalyzer.Analyze(
        [
            "content/pay\nload.bin", "content/gnp\u202Ecod.exe", "content/a\u200Bb.bin",
            "../../evil.dll", "lib/A.dll", "lib/a.dll", "content/evil.dll ", "content/CON.txt",
        ]);

        // One per category — the fixture above is built to trip all seven exactly once.
        Assert.Equal(
            Enum.GetValues<PackagingAnomalyCategory>(),
            anomalies.Select(a => a.Category).Distinct().Order().ToArray());
        Assert.All(anomalies, a => Assert.False(string.IsNullOrWhiteSpace(a.Detail), $"{a.Category} carried an empty detail."));
    }
    #endregion

    #region Methods — helpers
    private static PackagingAnomalyCategory[] CategoriesOf(string name) =>
        [.. PackageEntryNameAnalyzer.Analyze([name]).Select(a => a.Category)];

    // <paramref name="count"/> distinct names differing from <paramref name="name"/> ONLY by the case of its ASCII
    // letters — one colliding group of exactly that size, with the all-lowercase form first (so the group's
    // reported member is predictable). This is what an attacker inflating a detail string would ship.
    private static string[] CaseVariants(string name, int count) =>
        [.. Enumerable.Range(0, count).Select(mask => CaseVariant(name, mask))];

    private static string CaseVariant(string name, int mask)
    {
        var chars = name.ToCharArray();
        var bit = 0;
        for (var i = 0; i < chars.Length; i++)
        {
            if (!char.IsAsciiLetter(chars[i])) continue;
            chars[i] = ((mask >> bit) & 1) == 1 ? char.ToUpperInvariant(chars[i]) : char.ToLowerInvariant(chars[i]);
            bit++;
        }
        return new string(chars);
    }

    private static void AssertNoRawHostileText(string text, string field, PackagingAnomaly anomaly)
    {
        var offender = text.FirstOrDefault(IsHostile);
        Assert.True(
            offender == '\0' && !text.Contains('\0'),
            $"{anomaly.Category}.{field} carried raw U+{(int)offender:X4}.");
    }

    // C0, DEL and the C1 controls, the Unicode line/paragraph separators, and the bidi embeddings/overrides and
    // isolates — the same alphabet YaraPathSafety.Escape is defined to remove.
    private static bool IsHostile(char c) =>
        c <= (char)0x1F
        || c is >= (char)0x7F and <= (char)0x9F
             or (char)0x2028 or (char)0x2029
             or >= (char)0x202A and <= (char)0x202E
             or >= (char)0x2066 and <= (char)0x2069;

    // A name rendered safe for an ASSERTION MESSAGE. The table's rows are hostile by construction, and a failure
    // message is text a human reads in a terminal — it gets the same treatment the analyzer's own output does.
    private static string Printable(string name) =>
        string.Concat(name.Select(c => IsHostile(c) ? $"<U+{(int)c:X4}>" : c.ToString()));

    private static string PlatformName =>
        OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsLinux() ? "Linux" : "this platform";
    #endregion
}
