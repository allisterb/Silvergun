namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Wiring tests for <see cref="PackageScanner.Scan"/>'s YARA integration (ADR 0016 Phase 3). The scanner now takes an
/// optional <see cref="IYaraScanner"/> injection seam — when supplied, <c>ScanYara</c> drives that backend (else the
/// static <see cref="Silvergun.PackageAnalysis.NuGet.Yara.YaraScannerFactory.Shared"/>). A <b>fake scanner</b> (no
/// libyara, no <c>yara</c> CLI, no network) lets these tests assert the full match flow offline: a backend hit over an
/// extracted file is enriched via <see cref="YaraRuleIndex.Shared"/> (family/detection-name/category by rule name) and
/// carries a forward-slash, package-relative path matching the <see cref="PackageAssembly.RelativePath"/> convention.
/// The opt-out (<c>runYara: false</c>) never touches the injected backend, and a throwing backend is swallowed
/// (never-throws) leaving the rest of the report intact.
/// </summary>
public sealed class YaraScanPackageWiringTests : IClassFixture<PackageFixture>
{
    #region Constructors
    public YaraScanPackageWiringTests(PackageFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    // Full match flow: the injected backend reports a hit on the extracted fixture dll with a REAL embedded RL rule
    // name; the finding preserves the rule name, enriches family/detection-name/category from YaraRuleIndex.Shared,
    // and carries the package-relative (forward-slash) path matching that assembly's RelativePath convention.
    [Fact]
    public void Scan_WithFakeScannerHittingExtractedDll_YieldsEnrichedFindingWithRelativePath()
    {
        var fake = FakeYaraScanner.HittingFileNamed(fixture.FixtureDllName, RlRuleName, tags: new[] { "malicious" });

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.Invoked, "The injected backend should have been driven by ScanYara.");

        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal(RlRuleName, finding.RuleName);
        Assert.Equal(new[] { "malicious" }, finding.Tags);

        // The package-relative path matches the inventory convention: forward-slash and equal to the fixture
        // assembly's own RelativePath (e.g. "lib/netstandard2.0/<fixture>.dll").
        var fixtureAssembly = scan.Value.Assemblies
            .Single(a => Path.GetFileName(a.Assembly.RelativePath) == fixture.FixtureDllName);
        Assert.Equal(fixtureAssembly.Assembly.RelativePath, finding.RelativePath);
        Assert.DoesNotContain('\\', finding.RelativePath);

        // Enrichment is sourced from the embedded rule index by rule name — assert against the index and pin the
        // known RL meta values so a regression in either the wiring or the rule source surfaces clearly.
        var expected = YaraRuleIndex.Shared.Lookup(RlRuleName);
        Assert.NotNull(expected);
        Assert.Equal(expected!.MalwareFamily, finding.MalwareFamily);
        Assert.Equal(expected.DetectionName, finding.DetectionName);
        Assert.Equal(expected.Category, finding.Category);
        Assert.Equal("LIMERAT", finding.MalwareFamily);
        Assert.Equal("LimeRAT", finding.DetectionName);
        Assert.Equal("MALWARE", finding.Category);
    }

    // Enrichment coupling is not required for a finding to form: an unknown (made-up) rule name is absent from the
    // index, so the finding keeps its rule name/path but its metadata fields are null.
    [Fact]
    public void Scan_WithFakeScannerUnknownRule_YieldsFindingWithNullMetadata()
    {
        const string unknownRule = "Silvergun_Made_Up_Rule_That_Is_Not_Embedded";
        var fake = FakeYaraScanner.HittingFileNamed(fixture.FixtureDllName, unknownRule, tags: Array.Empty<string>());

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal(unknownRule, finding.RuleName);
        Assert.Null(finding.MalwareFamily);
        Assert.Null(finding.DetectionName);
        Assert.Null(finding.Category);
    }

    // runYara: false short-circuits before the backend is touched — even a supplied fake is never invoked, and
    // YaraFindings is empty (never null).
    [Fact]
    public void Scan_WithRunYaraFalse_AndFakeScanner_NeverInvokesBackend()
    {
        var fake = FakeYaraScanner.HittingFileNamed(fixture.FixtureDllName, RlRuleName, tags: Array.Empty<string>());

        var scan = PackageScanner.Scan(fixture.PkgAPath, runYara: false, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.False(fake.Invoked, "runYara: false must short-circuit before touching the backend.");
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
    }

    // A backend that throws from ScanDirectory is swallowed (never-throws): Scan still succeeds with empty
    // YaraFindings and the rest of the report intact (identity + inventoried assemblies).
    [Fact]
    public void Scan_WithThrowingFakeScanner_SwallowsFailure_ReportIntact()
    {
        var fake = FakeYaraScanner.Throwing();

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.Invoked, "The throwing backend should have been reached before it faulted.");
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);

        // The rest of the report is untouched by the YARA failure.
        Assert.Equal(PackageFixture.PkgAId, scan.Value.Package.Id);
        Assert.Contains(scan.Value.Assemblies, a => Path.GetFileName(a.Assembly.RelativePath) == fixture.FixtureDllName);
    }

    // --no-yara (runYara: false) short-circuits before any backend is touched: findings are empty, never null.
    [Fact]
    public void Scan_WithRunYaraFalse_YieldsEmptyNonNullYaraFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath, runYara: false);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
    }

    // The opt-out path on a package with no assemblies is equally empty and safe (no engine, no throw).
    [Fact]
    public void Scan_EmptyPackage_WithRunYaraFalse_YieldsEmptyYaraFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath, runYara: false);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Empty(scan.Value.YaraFindings);
    }

    // Whatever the backend outcome, YaraFindings is a non-null list — the default runYara path never leaves it null.
    // (Offline with no engine configured this is also empty; on a real engine it is engine-dependent, so only the
    // non-null contract is asserted here — the injected-fake match flow above validates enrichment deterministically.)
    [Fact]
    public void Scan_DefaultRunYara_LeavesYaraFindingsNonNull()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.NotNull(scan.Value.YaraFindings);
    }
    #endregion

    #region Nested types
    // A configurable fake IYaraScanner with no real engine. It overrides ScanDirectory to (optionally) enumerate the
    // real extraction dir and report a single hit against a chosen file, or to throw. It records whether it ran so a
    // test can assert the short-circuit / reached-before-fault paths. ScanFile is unused by these tests.
    private sealed class FakeYaraScanner : IYaraScanner
    {
        private FakeYaraScanner(string? fileName, string rule, IReadOnlyList<string> tags, bool @throw)
        {
            _fileName = fileName;
            _rule = rule;
            _tags = tags;
            _throw = @throw;
        }

        public bool Invoked { get; private set; }

        public static FakeYaraScanner HittingFileNamed(string fileName, string rule, IReadOnlyList<string> tags) =>
            new(fileName, rule, tags, @throw: false);

        public static FakeYaraScanner Throwing() =>
            new(fileName: null, rule: string.Empty, Array.Empty<string>(), @throw: true);

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => Array.Empty<YaraMatch>();

        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir)
        {
            Invoked = true;
            if (_throw)
                throw new InvalidOperationException("simulated backend failure");

            var target = Directory
                .EnumerateFiles(rootDir, "*", SearchOption.AllDirectories)
                .FirstOrDefault(f => string.Equals(Path.GetFileName(f), _fileName, StringComparison.Ordinal));
            if (target is null)
                return Array.Empty<(string, YaraMatch)>();

            var match = new YaraMatch(_rule, null, _tags, Array.Empty<YaraStringMatch>());
            return new[] { (target, match) };
        }

        private readonly string? _fileName;
        private readonly string _rule;
        private readonly IReadOnlyList<string> _tags;
        private readonly bool _throw;
    }
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    // A real embedded ReversingLabs rule whose meta block declares malware / tc_detection_name / category — the
    // enrichment source asserted above (ext/reversinglabs-yara-rules/yara/backdoor/ByteCode.MSIL.Backdoor.LimeRAT.yara).
    private const string RlRuleName = "ByteCode_MSIL_Backdoor_LimeRAT";
    #endregion
}
