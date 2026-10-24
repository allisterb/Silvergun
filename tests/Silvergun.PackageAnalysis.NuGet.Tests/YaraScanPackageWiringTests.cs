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
/// <para>
/// This class deliberately does <b>not</b> join <see cref="YaraEnvCollection"/>, even though one test
/// (<c>Scan_DefaultRunYara_LeavesYaraFindingsNonNull</c>) touches the process-wide memoized
/// <c>YaraScannerFactory.Shared</c>, which reads <c>SILVERGUN_YARA_PATH</c> once. That test asserts only that the
/// findings list is non-null precisely because what the factory latched onto is not knowable from here — so the
/// race is already designed around, and serializing this (slow, package-scanning) class against every YARA test
/// would cost far more run time than it buys. Any test that wants a defined backend injects one.
/// </para>
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
        // Available + findings returned => Completed (ADR 0027 decision 4 status matrix).
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);

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
        // runYara: false => NotRun, the explicit opt-out — never touched, never Completed/Unavailable.
        Assert.Equal(YaraScanStatus.NotRun, scan.Value.YaraScanStatus);
    }

    // A backend that throws from ScanDirectory is swallowed (never-throws): Scan still succeeds with empty
    // YaraFindings and the rest of the report intact (identity + inventoried assemblies). This is the regression pin
    // for the real LibYaraScanner-with-missing-native shape (ADR 0027 decision 4): Available reports true (the fake
    // never says otherwise), but the call itself faults, and the try/catch in PackageScanner.ScanYara — defense in
    // depth, not the primary detection mechanism — must still map that to Unavailable, not Completed.
    [Fact]
    public void Scan_WithThrowingFakeScanner_SwallowsFailure_ReportIntact()
    {
        var fake = FakeYaraScanner.Throwing();

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.Invoked, "The throwing backend should have been reached before it faulted.");
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);

        // The rest of the report is untouched by the YARA failure.
        Assert.Equal(PackageFixture.PkgAId, scan.Value.Package.Id);
        Assert.Contains(scan.Value.Assemblies, a => Path.GetFileName(a.Assembly.RelativePath) == fixture.FixtureDllName);
    }

    // ADR 0029 decision 13 — the fail-closed wiring test. A backend that reports Available == true but throws
    // YaraScanIncompleteException from ScanDirectory is saying "specific files under this root are KNOWN not to have
    // been scanned". PackageScanner.ScanYara must report that as Unavailable — never as Completed over a partial
    // list, which is exactly the attacker-controlled false negative ADR 0029 exists to close.
    //
    // NARROWED by ADR 0032 (renamed from ..._YieldsUnavailableWithZeroFindings). This used to be the only incomplete-
    // scan wiring test and it pinned "Unavailable => zero findings", which ADR 0030 decision 6 calls pinning the
    // defect. It now covers the case where that is still true: the exception carries NO partial hits (this fake
    // computes one but deliberately does not pass it), so there is nothing real to report and PackageScanner must
    // not invent anything. The case that used to be lost — an exception that DOES carry hits — is the next test.
    // Still discriminating against a backend that returns its partial list instead of throwing: that regression
    // reads Completed with one finding here.
    [Fact]
    public void Scan_WithFakeScannerReportingIncompleteScanWithoutPartialHits_YieldsUnavailableWithZeroFindings()
    {
        var fake = FakeYaraScanner.PartialThenIncomplete(fixture.FixtureDllName, RlRuleName);

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.Invoked, "The backend should have been reached before it reported an incomplete scan.");
        Assert.True(fake.FoundHitBeforeFailing, "The fake must have had a real hit to withhold, else this test is vacuous.");

        // Fail closed: a scan known to be missing hits must never read as a clean, completed scan.
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);

        // ...and the incompleteness is confined to YARA: the rest of the report is intact.
        Assert.Equal(PackageFixture.PkgAId, scan.Value.Package.Id);
        Assert.Contains(scan.Value.Assemblies, a => Path.GetFileName(a.Assembly.RelativePath) == fixture.FixtureDllName);
    }

    // ADR 0032 decision 2 — the converse of the test above, and the defect it closes. The incomplete scan DID find
    // the payload before it could not finish, and says so in PartialFindings. That hit is a real detection:
    // PackageScanner must report it, enriched exactly like a completed scan's, ALONGSIDE Unavailable (the rest is
    // still not verified). Before ADR 0032 it mapped every exception to (empty, Unavailable), so a package could
    // erase its own detection by making the scan incomplete — `--strict` then exited 3 instead of 2.
    [Fact]
    public void Scan_WithFakeScannerReportingIncompleteScanWithAPartialHit_YieldsUnavailableAndThatFinding()
    {
        var fake = FakeYaraScanner.IncompleteCarryingTheHit(fixture.FixtureDllName, RlRuleName);

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.FoundHitBeforeFailing, "The fake must have had a real hit to carry, else this test is vacuous.");
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);

        var finding = Assert.Single(scan.Value.YaraFindings);
        var fixtureAssembly = scan.Value.Assemblies
            .Single(a => Path.GetFileName(a.Assembly.RelativePath) == fixture.FixtureDllName);
        Assert.Equal(fixtureAssembly.Assembly.RelativePath, finding.RelativePath);
        Assert.Equal(RlRuleName, finding.RuleName);
        // Enriched the same way as a completed scan's hit — not a bare rule name.
        Assert.Equal("LIMERAT", finding.MalwareFamily);
        Assert.Equal("LimeRAT", finding.DetectionName);
        Assert.Equal("MALWARE", finding.Category);
    }

    // The partial hits' paths are raw (they must resolve against the extraction root) and attacker-authored, so they
    // are escaped at the report boundary exactly like a completed scan's (ADR 0031 decision 4). The carried path is
    // lexical only — no file of that name exists — which is precisely the shape of an unattributable batch hit
    // reported under yara's echoed target (ADR 0032 decision 4), and a newline is NTFS-unrepresentable anyway.
    [Fact]
    public void Scan_WithAPartialHitOnAHostilePath_ReportsItEscaped()
    {
        var fake = FakeYaraScanner.IncompleteCarrying(fixture.FixtureDllName, target =>
            [(Path.Combine(Path.GetDirectoryName(target)!, $"pay\nload{Rlo}.bin"), Match(RlRuleName))]);

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        var finding = Assert.Single(scan.Value.YaraFindings);
        Assert.Equal(@"lib/netstandard2.0/pay\nload" + EscapedRlo + ".bin", finding.RelativePath);
        Assert.DoesNotContain(finding.RelativePath, c => c < ' ' || c == Rlo);
    }

    // The catch path must itself be total (ADR 0032 decision 2). A partial hit that cannot be enriched — here a null
    // Match, which makes enrichment throw — must degrade to (empty, Unavailable): still fail-closed, and never
    // escaping to fail the whole package scan (which would lose the capability, script and anomaly results too).
    [Fact]
    public void Scan_WhenAPartialHitCannotBeEnriched_DegradesToUnavailableWithoutFailingTheScan()
    {
        var fake = FakeYaraScanner.IncompleteCarrying(fixture.FixtureDllName, target =>
            [(target, Match(RlRuleName)), (target, null!)]);

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.Invoked);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Equal(PackageFixture.PkgAId, scan.Value.Package.Id);
        Assert.Contains(scan.Value.Assemblies, a => Path.GetFileName(a.Assembly.RelativePath) == fixture.FixtureDllName);
    }

    // The exception's own contract at the boundary PackageScanner sees: YaraScanIncompleteException is an Exception,
    // so it reaches the existing catch in ScanYara rather than needing a new status channel (ADR 0029 decision 13
    // deliberately reuses that seam). Pinning the base type stops a well-meaning refactor from re-parenting it under
    // something the catch does not observe.
    [Fact]
    public void YaraScanIncompleteException_IsAPlainException_SoTheExistingCatchSeesIt()
    {
        var inner = new IOException("copy failed");
        var ex = new YaraScanIncompleteException("2 of 3 file(s) were not scanned", inner);

        Assert.IsAssignableFrom<Exception>(ex);
        Assert.Equal("2 of 3 file(s) were not scanned", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    // Available == false: PackageScanner.ScanYara must gate on the health signal BEFORE calling ScanDirectory at
    // all — not merely discard whatever it returns. Made discriminating per the task brief: the unavailable fake
    // still carries a real fileName/rule pair that WOULD produce a non-empty hit if ScanDirectory were called, so a
    // regression that skips the Available check (and calls ScanDirectory anyway) would surface as a NON-EMPTY
    // YaraFindings list here, not merely a wrong status enum.
    [Fact]
    public void Scan_WithUnavailableFakeScanner_NeverCallsScanDirectory_AndStatusIsUnavailable()
    {
        var fake = FakeYaraScanner.Unavailable(fixture.FixtureDllName, RlRuleName);

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.False(fake.Invoked, "An unavailable backend's ScanFiles/ScanDirectory must never be called.");
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
    }

    // Available == true, but nothing in the tree matches: a healthy backend that scanned and found nothing must
    // read Completed, not Unavailable — this is the "scanned, clean" case that must stay distinguishable from
    // "did not scan" (the whole point of YaraScanStatus existing).
    [Fact]
    public void Scan_WithAvailableFakeScannerAndNoMatches_YieldsCompletedWithEmptyFindings()
    {
        var fake = FakeYaraScanner.NoMatches();

        var scan = PackageScanner.Scan(fixture.PkgAPath, yaraScanner: fake);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.True(fake.Invoked, "An available backend must be driven by ScanYara.");
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
    }

    // --no-yara (runYara: false) short-circuits before any backend is touched: findings are empty, never null.
    [Fact]
    public void Scan_WithRunYaraFalse_YieldsEmptyNonNullYaraFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgAPath, runYara: false);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.NotNull(scan.Value.YaraFindings);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Equal(YaraScanStatus.NotRun, scan.Value.YaraScanStatus);
    }

    // The opt-out path on a package with no assemblies is equally empty and safe (no engine, no throw).
    [Fact]
    public void Scan_EmptyPackage_WithRunYaraFalse_YieldsEmptyYaraFindings()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath, runYara: false);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Empty(scan.Value.YaraFindings);
        Assert.Equal(YaraScanStatus.NotRun, scan.Value.YaraScanStatus);
    }

    // Whatever the backend outcome, YaraFindings is a non-null list — the default runYara path never leaves it null.
    // (Offline with no engine configured this is also empty; on a real engine it is engine-dependent, so only the
    // non-null contract is asserted here — the injected-fake match flow above validates enrichment deterministically.)
    // Deliberately NOT asserting YaraScanStatus here: this path drives the process-wide
    // YaraScannerFactory.Shared, memoized on first touch by ANY test in this process from whatever
    // SILVERGUN_YARA_PATH happened to be set at that moment (unlike YaraScannerTests, which scopes the env var
    // per-test) — pinning a status here would coincidentally reflect execution order/host environment rather than
    // this test's own behavior. NullYaraScanner/YaraCliScanner's own Available signal is pinned directly and
    // deterministically in YaraScannerTests instead.
    [Fact]
    public void Scan_DefaultRunYara_LeavesYaraFindingsNonNull()
    {
        var scan = PackageScanner.Scan(fixture.PkgBPath);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.NotNull(scan.Value.YaraFindings);
    }
    #endregion

    #region Nested types
    // A configurable fake IYaraScanner with no real engine. It overrides ScanFiles (what ScanYara calls since ADR 0034;
    // ScanDirectory enumerates and delegates to it) to (optionally) find a chosen file in the list it is handed and
    // report a single hit against it, or to throw. It records whether it ran so a
    // test can assert the short-circuit / reached-before-fault paths. ScanFile is unused by these tests.
    //
    // Available is an explicit, constructible flag (ADR 0027 decision 4 code-review fix) so both the healthy and
    // unhealthy paths are exercisable from the same fake. Unavailable() deliberately still wires a real
    // fileName/rule pair, so ScanDirectory would return a NON-EMPTY hit if it were ever called — the point being to
    // prove PackageScanner.ScanYara gates on Available BEFORE calling ScanDirectory at all, rather than merely
    // discarding whatever ScanDirectory happens to return.
    private sealed class FakeYaraScanner : IYaraScanner
    {
        private FakeYaraScanner(
            string? fileName, string rule, IReadOnlyList<string> tags, bool @throw, bool available,
            Func<string, IReadOnlyList<(string FullPath, YaraMatch Match)>, YaraScanIncompleteException>? incomplete = null)
        {
            _fileName = fileName;
            _rule = rule;
            _tags = tags;
            _throw = @throw;
            _incomplete = incomplete;
            Available = available;
        }

        public bool Available { get; }

        public bool Invoked { get; private set; }

        // True once ScanFiles has actually located its target file — i.e. the incomplete-scan fake really did
        // have a hit to discard, so Scan_WithFakeScannerReportingIncompleteScan is not passing vacuously.
        public bool FoundHitBeforeFailing { get; private set; }

        public static FakeYaraScanner HittingFileNamed(string fileName, string rule, IReadOnlyList<string> tags) =>
            new(fileName, rule, tags, @throw: false, available: true);

        // Available, but nothing in the tree matches _fileName (null) — a healthy backend that scanned and found
        // nothing, distinguishable from "did not scan at all" only by YaraScanStatus.Completed.
        public static FakeYaraScanner NoMatches() =>
            new(fileName: null, rule: string.Empty, Array.Empty<string>(), @throw: false, available: true);

        public static FakeYaraScanner Throwing() =>
            new(fileName: null, rule: string.Empty, Array.Empty<string>(), @throw: true, available: true);

        // ADR 0029 decision 13's shape with NO partial hits carried: the fake computes a hit (and records having found
        // it) but throws an exception that does not carry it. Since ADR 0032 that is a backend bug rather than the
        // design, but it is still the right input for "an incomplete scan with nothing to report yields nothing" —
        // and a regression which returns the partial list instead of throwing shows up as a NON-EMPTY, Completed
        // report rather than merely a different enum.
        public static FakeYaraScanner PartialThenIncomplete(string fileName, string rule) =>
            new(fileName, rule, Array.Empty<string>(), @throw: false, available: true,
                incomplete: (_, _) => new YaraScanIncompleteException(IncompleteMessage));

        // ADR 0032 decision 1: the same incomplete scan, but the exception carries the hit it found — what every
        // backend now does with the hits in hand.
        public static FakeYaraScanner IncompleteCarryingTheHit(string fileName, string rule) =>
            new(fileName, rule, Array.Empty<string>(), @throw: false, available: true,
                incomplete: (_, partial) => new YaraScanIncompleteException(IncompleteMessage, null, partial));

        // An incomplete scan whose PartialFindings are whatever the test builds from the located target path.
        public static FakeYaraScanner IncompleteCarrying(
            string fileName, Func<string, IReadOnlyList<(string FullPath, YaraMatch Match)>> carried) =>
            new(fileName, string.Empty, Array.Empty<string>(), @throw: false, available: true,
                incomplete: (_, partial) => new YaraScanIncompleteException(IncompleteMessage, null, carried(partial[0].FullPath)));

        // Unhealthy: Available is false, so PackageScanner.ScanYara must never reach ScanDirectory at all. If it
        // were (incorrectly) called anyway, this still reports a real hit — making a wiring regression that skips
        // the Available check fail loudly (non-empty findings from a status that must read Unavailable) rather than
        // passing by coincidence because the fake had nothing to find.
        public static FakeYaraScanner Unavailable(string fileName, string rule) =>
            new(fileName, rule, Array.Empty<string>(), @throw: false, available: false);

        public IReadOnlyList<YaraMatch> ScanFile(string fullPath) => Array.Empty<YaraMatch>();

        // A direct caller's entry: enumerate, then the same logic as ScanFiles.
        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanDirectory(string rootDir) =>
            ScanFiles(rootDir, Directory.GetFiles(rootDir, "*", SearchOption.AllDirectories));

        // What PackageScanner.ScanYara calls since ADR 0034: the package's extraction inventory. The target is located
        // in THAT list (not by walking rootDir again), so these tests also pin that the inventory reaches the backend.
        public IReadOnlyList<(string FullPath, YaraMatch Match)> ScanFiles(string rootDir, IReadOnlyList<string> files)
        {
            Invoked = true;
            if (_throw)
                throw new InvalidOperationException("simulated backend failure");

            var target = files
                .FirstOrDefault(f => string.Equals(Path.GetFileName(f), _fileName, StringComparison.Ordinal));
            if (target is null)
                return Array.Empty<(string, YaraMatch)>();

            var match = new YaraMatch(_rule, null, _tags, Array.Empty<YaraStringMatch>());
            var partial = new[] { (target, match) };

            if (_incomplete is null)
                return partial;

            // The ADR 0029 shape: real hits in hand, but a control-character-named file was never scanned, so the
            // scan is reported incomplete — carrying the hits or not, as the factory chose. (`partial` is
            // deliberately built first — mutating this to `return partial;` is the regression the wiring tests must
            // go red against.)
            FoundHitBeforeFailing = partial.Length > 0;
            throw _incomplete(target, partial);
        }

        private const string IncompleteMessage =
            @"YARA could not scan 1 of 1 file(s) whose names contain control characters, so this package was NOT fully scanned and must not be reported as clean. Path(s), control characters escaped: 'lib/net8.0/n\nl.bin'";

        private readonly string? _fileName;
        private readonly string _rule;
        private readonly IReadOnlyList<string> _tags;
        private readonly bool _throw;
        private readonly Func<string, IReadOnlyList<(string FullPath, YaraMatch Match)>, YaraScanIncompleteException>? _incomplete;
    }

    private static YaraMatch Match(string rule) =>
        new(rule, null, Array.Empty<string>(), Array.Empty<YaraStringMatch>());
    #endregion

    #region Fields
    private readonly PackageFixture fixture;

    // A real embedded ReversingLabs rule whose meta block declares malware / tc_detection_name / category — the
    // enrichment source asserted above (ext/reversinglabs-yara-rules/yara/backdoor/ByteCode.MSIL.Backdoor.LimeRAT.yara).
    private const string RlRuleName = "ByteCode_MSIL_Backdoor_LimeRAT";

    // U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so the source itself never carries it raw, and the
    // backslash-u form YaraPathSafety.Escape renders it as.
    private const char Rlo = (char)0x202E;
    private const string EscapedRlo = @"\" + "u202e";
    #endregion
}
