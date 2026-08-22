namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit coverage for the two functions the ADR 0029 partition is built out of:
/// <c>YaraPathSafety.TruncateAtFirstControl</c> and the <b>echo key</b> —
/// <c>TryNormalize(TruncateAtFirstControl(path))</c>, i.e. the most of a path a <c>yara -r</c> header line can
/// still carry once <c>YaraCliOutput.ParseAll</c> has split stdout on LF and trimmed the line.
///
/// <para>The echo key is what decides whether a file may be attributed from the cheap batch pass at all: two
/// entries that share one are indistinguishable in that output, so the package would otherwise choose which of
/// its files a hit is blamed on. <c>YaraCliScanner.EchoKey</c> is private, so this class composes the same two
/// internal primitives it composes; the wiring between them and the partition is pinned behaviourally by
/// <see cref="YaraCliRecoveryBoundsTests"/> and <see cref="YaraCliAttributionTests"/>.</para>
/// </summary>
public sealed class YaraEchoKeyTests
{
    #region Methods
    // A name with no control character survives untouched — the overwhelmingly common case, and the one that must
    // not be perturbed (a truncation here would silently drop real files out of the batch pass).
    [Theory]
    [InlineData("lib/net8.0/ordinary.dll")]
    [InlineData("content/ünïcode segment/a.bin")]
    [InlineData("")]
    [InlineData("trailing space ")]
    public void TruncateAtFirstControl_ForANameWithoutControlCharacters_IsIdentity(string path)
    {
        Assert.Equal(path, YaraPathSafety.TruncateAtFirstControl(path));
    }

    // The truncation is the attacker's chosen prefix: everything from the first C0 character on is what a parsed
    // header line loses. Every C0 character counts, not just LF and CR.
    [Theory]
    [InlineData("content/a.bin\nZZZ", "content/a.bin")]
    [InlineData("content/a.bin\rZZZ", "content/a.bin")]
    [InlineData("content/a.bin\tZZZ", "content/a.bin")]
    [InlineData("content/a.bin\0ZZZ", "content/a.bin")]
    [InlineData("content/a.bin\u001fZZZ", "content/a.bin")]
    [InlineData("content/a\nb\nc.bin", "content/a")]
    [InlineData("\ncontent/a.bin", "")]
    public void TruncateAtFirstControl_CutsAtTheFirstC0Character(string path, string expected)
    {
        Assert.Equal(expected, YaraPathSafety.TruncateAtFirstControl(path));
    }

    // THE collision the amendment is about: a hostile entry and a real sibling whose name is its truncation share
    // an echo key, so neither may be attributed from the batch pass.
    [Fact]
    public void EchoKey_ForAHostileNameAndTheSiblingItTruncatesOnto_IsShared()
    {
        var innocent = Rooted("content/a.bin");
        var hostile = Rooted("content/a.bin") + "\nZZZ";

        Assert.NotNull(EchoKey(innocent));
        Assert.Equal(EchoKey(innocent), EchoKey(hostile));
    }

    // The same collision with no control character in sight: the parser trims each line, so a trailing space is
    // invisible in the echo. This is why the partition is computed on the echoed form rather than on the raw name
    // — exact-ordinal attribution alone cannot tell these two apart.
    [Fact]
    public void EchoKey_ForNamesDifferingOnlyByTrailingWhitespace_IsShared()
    {
        var plain = Rooted("content/x.bin");

        Assert.Equal(EchoKey(plain), EchoKey(plain + " "));
    }

    // ...and the case that ADR 0029 round 3 turned around. The two keys really are ordinally distinct — the bytes
    // yara echoes differ — but that is a fact about STRINGS, not about the partition, and the partition is what
    // decides whether a file may be attributed from the batch pass.
    //
    // This test used to assert only the NotEqual below, under a comment concluding that the two names are
    // "therefore NOT ambiguous and keep their place in the single cheap pass". The assertion stayed green while
    // that conclusion became false, which is precisely the failure mode ADR 0030 decision 6 warns about: the
    // partition now groups with OrdinalIgnoreCase — one comparer for the grouping, the `forged` veto, the
    // attribution fallback and TargetMatches alike (decision 16) — because mixing an ordinal grouping with a
    // case-folded veto is what let an empty `content/MAL.dll\nx` decoy silence a real hit on `content/mal.dll`.
    // So both lines below are asserted, and the SECOND one is the one that matters: under the comparer the
    // partition uses, these two names collide.
    //
    // The behaviour that follows from it — both files leave the batch pass and are re-scanned individually — is
    // pinned in YaraCliRecoveryBoundsTests.ScanDirectory_WithACaseOnlyDuplicatePair_MovesBothFilesIntoTheRecoveryPassAndNothingElse.
    [Fact]
    public void EchoKey_ForNamesDifferingOnlyByCase_CollidesUnderTheComparerThePartitionUses()
    {
        var lower = EchoKey(Rooted("content/a.bin"));
        var upper = EchoKey(Rooted("content/A.bin"));

        Assert.NotNull(lower);
        Assert.NotNull(upper);
        Assert.NotEqual(lower, upper);
        Assert.True(
            StringComparer.OrdinalIgnoreCase.Equals(lower, upper),
            $"'{lower}' and '{upper}' must be the SAME echo key to the partition, or a case-only decoy is "
            + "attributable while the veto and the attribution fallback still conflate it.");
    }

    // A file whose name is nothing but control characters has no echoed form at all, so it can never be
    // attributed from batch output — it has to be recovered individually or counted unrecovered.
    [Fact]
    public void EchoKey_ForANameThatIsEntirelyControlCharacters_IsNull()
    {
        Assert.Null(YaraCliScanner.TryNormalize(YaraPathSafety.TruncateAtFirstControl("\n\r\t")));
    }

    // "No comparable normalised form" is the precondition of two fail-closed decisions, so it is pinned directly:
    // the partition drops such a file out of the batch pass (its echo key is null, so it can never be matched
    // against anything), and ScanOne REFUSES TO SCAN it at all — returning null, which counts as unrecovered and
    // makes the package Unavailable. That refusal matters because the alternative is worse than a skip: yara would
    // run, every line it printed would fail TargetMatches, and the empty result would read as "scanned, nothing
    // found" rather than "we cannot verify anything about this file".
    //
    // Note on reachability, so the next reader does not go looking: this guard cannot currently be reached from a
    // real filesystem path, because ScanOne's File.Exists check runs first and File.Exists is false for every
    // input TryNormalize rejects (both are Path.GetFullPath underneath). It is defence in depth against a future
    // caller that has already established the file exists by other means, and the contract below is the part that
    // is genuinely testable.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n")]
    [InlineData("/tmp/x/a\0b.bin")]
    public void TryNormalize_ForTextWithNoComparableForm_IsNull(string? path)
    {
        Assert.Null(YaraCliScanner.TryNormalize(path));
    }

    // The echo key as YaraCliScanner computes it: the truncation, normalized (which trims, exactly as the
    // parser's per-line TrimEnd does).
    private static string? EchoKey(string path) =>
        YaraCliScanner.TryNormalize(YaraPathSafety.TruncateAtFirstControl(path));

    // An absolute path under the temp directory, so Path.GetFullPath inside TryNormalize has something rooted and
    // platform-appropriate to work with on both Windows and Linux.
    private static string Rooted(string relative) => Path.Combine(Path.GetTempPath(), "silvergun-echo-key", relative);
    #endregion
}
