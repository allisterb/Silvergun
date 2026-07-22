namespace Silvergun.PackageAnalysis.NuGet.Tests;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Direct unit tests for the security-relevant path-anchoring filter
/// <see cref="YaraCliScanner.TargetMatches(string?, string)"/> (ADR 0016 / task
/// <c>docs/agent/tasks/yara-scanning.md</c>). <see cref="YaraCliOutput.ParseAll"/> retains the target echoed on a
/// yara header line verbatim (the header regex is permissive enough to match arbitrary prose), so
/// <see cref="YaraCliScanner"/> relies on <c>TargetMatches</c> to confirm a parsed hit really belongs to the file it
/// handed yara before surfacing it as a finding. That anchoring is the last line of defense against a garbage or
/// foreign target being accepted as the scanned file, so these tests assert the INTENDED anchoring semantics — not
/// the current implementation shape.
///
/// The over-match probes below are deliberately adversarial: a target that is only a raw string-suffix of the
/// scanned path across a filename-character boundary (a real file <c>ab.dll</c> is NOT the file <c>b.dll</c>) must be
/// rejected. If a probe were accepted, <c>TargetMatches</c> would have a segment-boundary-unaware over-match bug.
/// </summary>
public sealed class YaraTargetMatchesTests
{
    #region Methods
    [Theory]
    // --- True: the target genuinely names the scanned file -------------------------------------------------------
    // Exact full-path match.
    [InlineData("/tmp/x/a.dll", "/tmp/x/a.dll", true)]
    // Case-insensitive: yara/OS may echo a differently-cased path (Windows paths are case-insensitive).
    [InlineData("/TMP/X/A.DLL", "/tmp/x/a.dll", true)]
    // NOTE: the slash-direction ('\' vs '/') case is OS-dependent and lives in its own test below.
    // Defensive case: yara echoes the path exactly as it was passed on the command line.
    [InlineData("/tmp/x/deep/module.dll", "/tmp/x/deep/module.dll", true)]

    // --- False: the target does NOT name the scanned file --------------------------------------------------------
    // Null / empty / whitespace target ⇒ no anchoring, never a match.
    [InlineData(null, "/tmp/x/a.dll", false)]
    [InlineData("", "/tmp/x/a.dll", false)]
    [InlineData("   ", "/tmp/x/a.dll", false)]
    // A clearly different file in the same directory.
    [InlineData("/tmp/x/other.dll", "/tmp/x/a.dll", false)]
    // Over-match probe (relative bare filename): scanned "ab.dll" is not the file "b.dll".
    [InlineData("b.dll", "/tmp/x/ab.dll", false)]
    // Over-match probe (rooted, crosses a filename-character boundary): "/tmp/x/b.dll" is not "/tmp/x/ab.dll".
    [InlineData("/tmp/x/b.dll", "/tmp/x/ab.dll", false)]
    public void TargetMatches_AnchorsHitToScannedFile(string? target, string fullPath, bool expected)
    {
        Assert.Equal(expected, YaraCliScanner.TargetMatches(target, fullPath));
    }

    /// <summary>
    /// Slash-direction equivalence is OS-dependent. On Windows '\' is a path separator, so
    /// <c>\tmp\x\a.dll</c> and <c>/tmp/x/a.dll</c> name the same file and anchoring must accept the target.
    /// On Linux/macOS '\' is a legal filename character, so those are genuinely different paths and
    /// <c>TargetMatches</c> must reject the target. The expected result therefore tracks
    /// <see cref="OperatingSystem.IsWindows"/> (mirroring <c>YaraCliScanner.Normalize</c>, which only
    /// backslash-normalizes on Windows).
    /// </summary>
    [Fact]
    public void TargetMatches_SlashDirection_IsOsDependent()
    {
        Assert.Equal(
            OperatingSystem.IsWindows(),
            YaraCliScanner.TargetMatches(@"\tmp\x\a.dll", "/tmp/x/a.dll"));
    }
    #endregion
}
