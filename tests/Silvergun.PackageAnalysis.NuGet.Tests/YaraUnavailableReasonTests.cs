namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// The additive <see cref="PackageCapabilityReport.YaraUnavailableReason"/> (ADR 0033 polish round): why YARA did not
/// complete, for a CI log. Two contracts.
///
/// <para><b>The report.</b> Every assignment, including <see cref="PackageCapabilityReport.FromJson"/>, escapes the text
/// (it quotes package paths and engine output) and bounds it to 512 chars, idempotently, so a round trip is unchanged.
/// It is omitted from the JSON when null, so a Completed or NotRun report's JSON is exactly what it was before.</para>
///
/// <para><b>Who sets it.</b> <see cref="PackageScanner.Scan"/>, exactly when the status is Unavailable, on each of the
/// three ways there: the backend is not <see cref="IYaraScanner.Available"/> (its <see cref="IYaraScanner.UnavailableReason"/>,
/// or a generic one when it gives none), an incomplete scan (the exception's message), and any other exception (its type
/// and message). Completed and NotRun leave it null.</para>
/// </summary>
public sealed class YaraUnavailableReasonTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public YaraUnavailableReasonTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods: the report's init accessor
    [Fact]
    public void TheReason_IsEscapedAndBoundedOnConstruction()
    {
        var report = Report() with { YaraUnavailableReason = Hostile };

        var reason = report.YaraUnavailableReason!;
        Assert.Equal(PackageCapabilityReport.MaxYaraUnavailableReasonChars, reason.Length);
        Assert.StartsWith(EscapedHostile, reason, StringComparison.Ordinal);
        Assert.EndsWith("...", reason, StringComparison.Ordinal);
        AssertNoRawControl(reason);
    }

    // A short, harmless reason is kept as it is.
    [Fact]
    public void AnOrdinaryReason_IsKeptVerbatim()
    {
        var report = Report() with { YaraUnavailableReason = "no working YARA backend: the YARA-X DLL is missing" };

        Assert.Equal("no working YARA backend: the YARA-X DLL is missing", report.YaraUnavailableReason);
    }

    // JSON is input too (a report from elsewhere): FromJson goes through the same accessor, so raw control and bidi
    // characters (here as JSON escapes, which decode to the raw characters) and an over-long value come out escaped and cut.
    [Fact]
    public void FromJson_EscapesAndBoundsTheReason()
    {
        var json = Report().ToJson().TrimEnd().TrimEnd('}') + $",\n  \"YaraUnavailableReason\": {JsonSerializer.Serialize(Hostile)}\n}}";
        Assert.Contains("\\n", json, StringComparison.Ordinal);   // the precondition: JSON-escaped, so it decodes to a raw LF

        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(PackageCapabilityReport.MaxYaraUnavailableReasonChars, restored.YaraUnavailableReason!.Length);
        Assert.StartsWith(EscapedHostile, restored.YaraUnavailableReason, StringComparison.Ordinal);
        AssertNoRawControl(restored.YaraUnavailableReason);
    }

    // Escaping and bounding are idempotent: an already safe, already bounded reason survives ToJson/FromJson unchanged,
    // and so does the JSON.
    [Fact]
    public void ARoundTrip_LeavesTheReasonAndTheJsonUnchanged()
    {
        var report = Report() with { YaraUnavailableReason = Hostile };

        var json = report.ToJson();
        var restored = PackageCapabilityReport.FromJson(json)!;

        Assert.Equal(report.YaraUnavailableReason, restored.YaraUnavailableReason);
        Assert.Equal(json, restored.ToJson());
    }

    [Fact]
    public void ANullReason_IsAbsentFromTheJson_AndASetOneIsPresent()
    {
        var plain = Report();
        var withReason = Report() with { YaraUnavailableReason = "why" };

        Assert.Null(plain.YaraUnavailableReason);
        Assert.DoesNotContain("YaraUnavailableReason", plain.ToJson(), StringComparison.Ordinal);
        Assert.Contains("\"YaraUnavailableReason\": \"why\"", withReason.ToJson(), StringComparison.Ordinal);
        Assert.Null(PackageCapabilityReport.FromJson(plain.ToJson())!.YaraUnavailableReason);   // old JSON: null
    }
    #endregion

    #region Methods: PackageScanner sets it exactly for Unavailable
    // 1. Not Available: the backend's own reason, escaped and bounded, prefixed; and the warning names it, escaped.
    [Fact]
    public void Scan_WhenTheBackendIsUnavailable_TheReasonIsItsOwn_EscapedAndBounded()
    {
        using var warnings = new WarningCapture();

        var scan = PackageScanner.Scan(fixture.PkgBPath, resolveReferences: false, yaraScanner: new Unavailable(Hostile));

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var reason = scan.Value.YaraUnavailableReason!;
        Assert.StartsWith("no working YARA backend: " + EscapedHostile, reason, StringComparison.Ordinal);
        Assert.Equal(PackageCapabilityReport.MaxYaraUnavailableReasonChars, reason.Length);
        AssertNoRawControl(reason);
        var warning = Assert.Single(warnings.Warnings, w => w.Contains("YARA scanning UNAVAILABLE for", StringComparison.Ordinal));
        Assert.Contains("no working backend (" + EscapedHostile, warning, StringComparison.Ordinal);
        AssertNoRawControl(warning);
    }

    // A backend that does not say why (the interface's default, null) still yields a reason, never an empty one.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Scan_WhenTheBackendIsUnavailableAndSaysNothing_TheReasonIsGeneric(string? backendReason)
    {
        var backend = backendReason is null ? (IYaraScanner)new SilentUnavailable() : new Unavailable(backendReason);

        var scan = PackageScanner.Scan(fixture.PkgBPath, resolveReferences: false, yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal("no working YARA backend: the YARA backend did not say why", scan.Value.YaraUnavailableReason);
    }

    // The no-engine backend of non-Windows builds says what to configure.
    [Fact]
    public void Scan_WithTheNullScanner_TheReasonNamesTheVariable()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath, resolveReferences: false, yaraScanner: NullYaraScanner.Instance);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.StartsWith("no working YARA backend: no YARA engine is configured", scan.Value.YaraUnavailableReason, StringComparison.Ordinal);
        Assert.Contains("SILVERGUN_YARA_PATH", scan.Value.YaraUnavailableReason, StringComparison.Ordinal);
    }

    // 2. An incomplete scan: its message, escaped and bounded.
    [Fact]
    public void Scan_WhenTheScanIsIncomplete_TheReasonIsItsMessage_EscapedAndBounded()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath, resolveReferences: false,
            yaraScanner: new Throwing(new YaraScanIncompleteException(Hostile)));

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var reason = scan.Value.YaraUnavailableReason!;
        Assert.StartsWith(EscapedHostile, reason, StringComparison.Ordinal);
        Assert.Equal(PackageCapabilityReport.MaxYaraUnavailableReasonChars, reason.Length);
        AssertNoRawControl(reason);
    }

    // 3. Any other exception: its type and message, escaped.
    [Fact]
    public void Scan_WhenTheBackendThrowsAnythingElse_TheReasonIsItsTypeAndMessage_Escaped()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath, resolveReferences: false,
            yaraScanner: new Throwing(new InvalidOperationException("boom\nline two" + Rlo)));

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal(@"InvalidOperationException: boom\nline two" + EscapedRlo, scan.Value.YaraUnavailableReason);
    }

    // Completed (an available backend that scanned, with or without hits) and NotRun (runYara: false) leave it null, and
    // their JSON has no such property, so the existing report shape is unchanged.
    [Theory]
    [InlineData("completed clean")]
    [InlineData("completed with a hit")]
    [InlineData("not run")]
    public void Scan_WhenCompletedOrNotRun_TheReasonIsNull_AndAbsentFromTheJson(string outcome)
    {
        var backend = new Healthy(withHit: outcome == "completed with a hit");

        var scan = PackageScanner.Scan(fixture.PkgBPath, resolveReferences: false, runYara: outcome != "not run", yaraScanner: backend);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(outcome == "not run" ? YaraScanStatus.NotRun : YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Null(scan.Value.YaraUnavailableReason);
        Assert.DoesNotContain("YaraUnavailableReason", scan.Value.ToJson(), StringComparison.Ordinal);
    }
    #endregion

    #region Methods: helpers
    private static PackageCapabilityReport Report() =>
        new(new PackageIdentityInfo("Reason.Package", "1.0.0", "Author", "desc", Array.Empty<PackageDependencyInfo>()),
            DateTimeOffset.UnixEpoch, Array.Empty<AssemblyScanResult>(), Array.Empty<PackageScript>(), Array.Empty<ScriptFinding>(),
            YaraScanStatus: YaraScanStatus.Unavailable);

    // No C0 control, no DEL or C1 control, no bidi override.
    private static void AssertNoRawControl(string text) =>
        Assert.DoesNotContain(text, c => c < ' ' || c is >= (char)0x7F and <= (char)0x9F || c == Rlo);
    #endregion

    #region Nested types
    private sealed class Unavailable(string reason) : IYaraScanner
    {
        public bool Available => false;

        public string? UnavailableReason => reason;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => throw new InvalidOperationException("an unavailable backend was asked to scan");
    }

    // Uses the interface's default UnavailableReason (null).
    private sealed class SilentUnavailable : IYaraScanner
    {
        public bool Available => false;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => throw new InvalidOperationException("an unavailable backend was asked to scan");
    }

    // Available, and says (wrongly, for a healthy one) that it has a reason: PackageScanner must not use it.
    private sealed class Healthy(bool withHit) : IYaraScanner
    {
        public bool Available => true;

        public string? UnavailableReason => "a reason an available backend must never contribute";

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => [];

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) =>
            withHit ? [(System.IO.Path.Combine(rootDir, "x.bin"), new YaraMatch("Some_Rule", null, [], []))] : [];
    }

    private sealed class Throwing(Exception ex) : IYaraScanner
    {
        public bool Available => true;

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => throw ex;

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) => throw ex;
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so this source never carries it raw.
    private const char Rlo = (char)0x202E;

    // A reason with a line break, a forged log level, a bidi override and an ANSI escape, and far past the 512-char bound.
    private static readonly string Hostile = "dll\n[ERR] forged" + Rlo + (char)0x1B + "[31m" + new string('z', 2000);

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries that sequence.
    private const string EscapedRlo = @"\" + "u202e";

    // How Hostile's start reads once escaped: the line break, the bidi override and ESC as printable escapes.
    private const string EscapedHostile = @"dll\n[ERR] forged" + EscapedRlo + @"\x1b[31m";
    #endregion
}
