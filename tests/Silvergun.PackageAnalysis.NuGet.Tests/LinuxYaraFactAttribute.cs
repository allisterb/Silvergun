namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// A <see cref="FactAttribute"/> for the ADR 0029 scenarios that <b>can only exist on Linux</b>: an extracted file
/// name containing a control character, a trailing space, or two names differing only in case. NTFS can represent
/// none of them, so those scenarios cannot be staged on Windows at all — not "are untested there",
/// <i>cannot exist</i> there.
///
/// The attribute sets <see cref="FactAttribute.Skip"/> rather than letting the test body early-return, and that
/// choice is the point: an early return reports <b>Passed</b> on Windows for a test that never executed, which is
/// exactly the false-assurance failure mode ADR 0029 was found by (a Windows-only run can never surface this
/// defect). Setting <c>Skip</c> makes the Windows run say <c>Skipped: n</c>, so "did this actually run?" is
/// answerable from the test output alone: these tests must appear in the <b>passed</b> count on Linux/WSL and in
/// the <b>skipped</b> count on Windows.
/// </summary>
public sealed class LinuxYaraFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxYaraFactAttribute() =>
        Skip = YaraCliProbe.SkipReason(
            OperatingSystem.IsLinux(), YaraCliProbe.YaraBinary is not null, YaraCliProbe.BinaryRequired);
    #endregion
}

/// <summary>
/// The <see cref="TheoryAttribute"/> twin of <see cref="LinuxYaraFactAttribute"/>, for the real-engine scenarios
/// that must be exercised over a <b>set</b> of hostile characters rather than one representative.
///
/// <para>That distinction is not cosmetic: ADR 0029's decision 17a defect was a whole <i>class</i> of control
/// characters (TAB and 0x01–0x08 / 0x0B / 0x0C / 0x0E–0x1F) going unhandled while the two the suite happened to
/// stage — LF and CR — worked. A single representative is exactly what let it through, so the regression guard
/// is parameterized.</para>
///
/// <para>Note for anyone reconciling test counts across platforms: xunit collapses a skipped theory into
/// <b>one</b> skipped test case without enumerating its data, so a five-case theory shows as 1 skipped on Windows
/// and 5 passed on Linux. The Linux total is therefore legitimately larger than the Windows total.</para>
/// </summary>
public sealed class LinuxYaraTheoryAttribute : TheoryAttribute
{
    #region Constructors
    public LinuxYaraTheoryAttribute() =>
        Skip = YaraCliProbe.SkipReason(
            OperatingSystem.IsLinux(), YaraCliProbe.YaraBinary is not null, YaraCliProbe.BinaryRequired);
    #endregion
}

/// <summary>
/// The same Linux gate for the scenarios that need a hostile <b>name</b> but no real engine — the recovery pass's
/// bounds, the staging directory's permissions, and which files stay in the cheap batch pass. They drive the
/// <c>FakeYaraProbe</c> (or a trivial POSIX binary) instead, so they run on any Linux box.
/// </summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    #region Constructors
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "ADR 0029 regression: requires an extracted file name that NTFS cannot represent (a control "
                 + "character, a trailing space, or a case-only duplicate), so the file cannot even be staged on "
                 + "Windows. Run the suite under WSL (dotnet test <proj> -f net10.0) for this to execute.";
    }
    #endregion
}

/// <summary>
/// Locates the real classic <c>yara</c>/<c>yarac</c> binaries for the Linux-only integration tests. Prefers the
/// usual distro locations, else an explicitly configured <c>SILVERGUN_YARA_PATH</c>. Resolution happens once, at
/// type initialization, so <see cref="LinuxYaraFactAttribute"/> (evaluated at discovery) and the test bodies
/// (evaluated at run time) always agree — a test must never be skipped for a reason that no longer holds when it
/// would have run, nor run without the binary the attribute promised.
/// </summary>
internal static class YaraCliProbe
{
    #region Properties
    /// <summary>Where a distro-installed <c>yara</c> lives. An expression-bodied property, not a static field:
    /// static field initializers run in declaration order, and the resolutions below must not read a null array.</summary>
    internal static string[] CandidatePaths => ["/usr/bin/yara", "/usr/local/bin/yara", "/bin/yara"];

    private static string[] CandidateYaracPaths => ["/usr/bin/yarac", "/usr/local/bin/yarac", "/bin/yarac"];

    /// <summary>The opt-in that turns "this Linux box has no yara" from a skip into a failure.</summary>
    internal const string RequireVar = "SILVERGUN_REQUIRE_YARA";

    /// <summary>Absolute path to a real <c>yara</c> binary, or <c>null</c> when none was found.</summary>
    internal static string? YaraBinary { get; } = Resolve(
        Environment.GetEnvironmentVariable(YaraCliScanner.YaraPathVar), CandidatePaths);

    /// <summary>Absolute path to a real <c>yarac</c> compiler, or <c>null</c> — the scanner degrades to uncompiled rules.</summary>
    internal static string? YaracBinary { get; } = Resolve(
        Environment.GetEnvironmentVariable(YaraCliScanner.YaracPathVar), CandidateYaracPaths);

    /// <summary>
    /// <c>true</c> when <c>SILVERGUN_REQUIRE_YARA=1</c> — the CI opt-in of review item W4. A Linux box without the
    /// binary otherwise reports a green run in which this ADR's <b>only real coverage</b> was skipped, and a skip
    /// is easy to stop reading. With it set, <see cref="LinuxYaraFactAttribute"/> stops skipping and
    /// <see cref="EnforceBinaryRequirement"/> fails the affected classes outright.
    /// </summary>
    internal static bool BinaryRequired { get; } =
        string.Equals(Environment.GetEnvironmentVariable(RequireVar), "1", StringComparison.Ordinal);

    /// <summary>A trivial POSIX binary that ignores its arguments and exits 0 — the cheapest possible stand-in for
    /// <c>yara</c> when a test cares only about how many files the scanner tried to scan, not about what it found.</summary>
    internal static string? AlwaysSucceedingBinary { get; } =
        new[] { "/bin/true", "/usr/bin/true" }.FirstOrDefault(File.Exists);
    #endregion

    #region Methods
    /// <summary>
    /// Why <see cref="LinuxYaraFactAttribute"/> would skip, or <c>null</c> to run. Taken as parameters rather than
    /// read from the ambient state so the decision — in particular the <c>SILVERGUN_REQUIRE_YARA</c> opt-in, whose
    /// whole purpose is to change what a box <i>without</i> yara does — is testable on a box that has one.
    /// </summary>
    internal static string? SkipReason(bool isLinux, bool haveBinary, bool required) =>
        !isLinux
            ? "ADR 0029 regression: requires an extracted file name that NTFS cannot represent (a control "
              + "character, a trailing space, or a case-only duplicate). Run the suite under WSL "
              + "(dotnet test <proj> -f net10.0) for this to execute."
            : haveBinary || required
                ? null
                : $"ADR 0029 regression: requires a real yara binary (set {YaraCliScanner.YaraPathVar}, or install "
                  + "yara at one of " + string.Join(", ", CandidatePaths) + $"). Set {RequireVar}=1 to make this a "
                  + "FAILURE instead of a skip.";

    /// <summary>
    /// Called from the constructor of every class whose coverage depends on a real engine. Throws when the opt-in
    /// is set on a Linux box that has no <c>yara</c>, so the run is RED rather than quietly short of coverage.
    /// (When the opt-in is not set, <see cref="LinuxYaraFactAttribute"/> has already turned those tests into
    /// visible skips and this constructor never runs for them.)
    /// </summary>
    internal static void EnforceBinaryRequirement() =>
        Enforce(BinaryRequired, OperatingSystem.IsLinux(), YaraBinary is not null);

    /// <summary>The pure half of <see cref="EnforceBinaryRequirement"/>; see <see cref="SkipReason"/> for why.</summary>
    internal static void Enforce(bool required, bool isLinux, bool haveBinary)
    {
        if (required && isLinux && !haveBinary)
            throw new InvalidOperationException(
                $"{RequireVar}=1 demands a real yara binary for the ADR 0029 integration tier, but none was found "
                + $"at any of {string.Join(", ", CandidatePaths)} nor at {YaraCliScanner.YaraPathVar}. Install yara "
                + $"or unset {RequireVar} (which downgrades this coverage to a visible skip).");
    }

    // Distro locations are tried FIRST and the environment variable only as a fallback. That looks backwards, and
    // is deliberate: sibling tests in this assembly legitimately point SILVERGUN_YARA_PATH at a dummy file or at
    // the FakeYaraProbe for the duration of a test, and this type's one-time initialization must not be able to
    // latch onto one of those and hand a fake "yara" to the integration tests.
    private static string? Resolve(string? configured, string[] candidates) =>
        candidates.FirstOrDefault(File.Exists)
        ?? (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured) ? configured : null);
    #endregion
}

/// <summary>
/// Coverage for the gate itself (review item W4). A Linux CI box without <c>yara</c> silently skipped this ADR's
/// only real coverage and still reported green; the <c>SILVERGUN_REQUIRE_YARA=1</c> opt-in turns that into a
/// failure. Both halves of the decision are pure functions precisely so this can be asserted on a box that
/// <i>does</i> have the binary — otherwise the opt-in would itself be untested until the day it mattered.
/// </summary>
public sealed class LinuxYaraGateTests
{
    #region Methods
    // Off Linux the scenario cannot be staged at all, so it is always a visible skip — the opt-in does not (and
    // must not) override that: there is no defect to catch on Windows, only a name NTFS cannot hold.
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void SkipReason_OffLinux_AlwaysSkipsAndSaysWhy(bool haveBinary, bool required)
    {
        var reason = YaraCliProbe.SkipReason(isLinux: false, haveBinary, required);

        Assert.NotNull(reason);
        Assert.Contains("NTFS cannot represent", reason);
    }

    // The healthy Linux box: the test runs.
    [Fact]
    public void SkipReason_OnLinuxWithABinary_Runs()
    {
        Assert.Null(YaraCliProbe.SkipReason(isLinux: true, haveBinary: true, required: false));
    }

    // The default posture on a Linux box with no engine: a visible skip that names the opt-in.
    [Fact]
    public void SkipReason_OnLinuxWithoutABinary_SkipsAndAdvertisesTheOptIn()
    {
        var reason = YaraCliProbe.SkipReason(isLinux: true, haveBinary: false, required: false);

        Assert.NotNull(reason);
        Assert.Contains(YaraCliProbe.RequireVar + "=1", reason);
    }

    // With the opt-in set, the same box does NOT skip — it runs, and the class constructor then fails it. That
    // pairing is the point: a skip is easy to stop reading, a red test is not.
    [Fact]
    public void SkipReason_OnLinuxWithoutABinary_WithTheOptIn_RunsSoThatItCanFail()
    {
        Assert.Null(YaraCliProbe.SkipReason(isLinux: true, haveBinary: false, required: true));
    }

    // ...and the constructor guard is what makes the failure happen, with a message that says how to fix it.
    [Fact]
    public void Enforce_OnLinuxWithoutABinary_WithTheOptIn_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => YaraCliProbe.Enforce(required: true, isLinux: true, haveBinary: false));

        Assert.Contains(YaraCliProbe.RequireVar, ex.Message);
    }

    // Every other combination must stay silent — the opt-in must never fail a box that has the binary, nor a
    // platform where the scenario cannot exist.
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, false)]
    public void Enforce_ForEveryOtherCombination_DoesNotThrow(bool required, bool isLinux, bool haveBinary)
    {
        YaraCliProbe.Enforce(required, isLinux, haveBinary);
    }
    #endregion
}
