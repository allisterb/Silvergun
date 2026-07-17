namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Silvergun;
using Silvergun.PackageAnalysis.NuGet.Squats;

using Xunit;

/// <summary>
/// Typosquat detection (task <c>docs/agent/tasks/squat-detection.md</c>): the ported OSSGadget
/// mutator engine, the NuGet-tuned <see cref="SquatCandidateGenerator"/>, and the network-agnostic
/// <see cref="SquatChecker"/>. All cases are deterministic and offline — the popularity source is an
/// in-memory fake (<see cref="FakePopularitySource"/>), never <c>api.nuget.org</c>. Covers the seven
/// cases in the spec's "Test cases" section.
/// </summary>
public sealed class SquatDetectionTests
{
    #region Constructors
    public SquatDetectionTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods
    // Case 1 — AsciiHomoglyph on "nuget": the verbatim table maps 'n' => 'r','m','u', so the swaps
    // "ruget" (n=>r) and "muget" (n=>m) must both be produced, each with a populated Reason and the
    // AsciiHomoglyph kind, and the Original preserved.
    [Fact]
    public void AsciiHomoglyph_Generate_Nuget_YieldsNToRAndNToMSwaps()
    {
        var mutations = new AsciiHomoglyphMutator().Generate("nuget").ToArray();

        Assert.Contains(mutations, m => m.Mutated == "ruget");
        Assert.Contains(mutations, m => m.Mutated == "muget");
        Assert.All(mutations, m =>
        {
            Assert.Equal("nuget", m.Original);
            Assert.Equal(MutatorType.AsciiHomoglyph, m.Mutator);
            Assert.False(string.IsNullOrWhiteSpace(m.Reason));
        });
    }

    // Case 2 — the generator over "Newtonsoft.Json" returns a non-empty, name-distinct set that excludes
    // the input, includes the separator-removed "NewtonsoftJson" and at least one homoglyph variant, and
    // annotates every candidate with a Reason and a set Mutator.
    [Fact]
    public void Generate_NewtonsoftJson_ProducesDistinctAnnotatedCandidatesExcludingInput()
    {
        var candidates = SquatCandidateGenerator.Generate("Newtonsoft.Json");

        Assert.NotEmpty(candidates);

        // Names are distinct.
        Assert.Equal(
            candidates.Count,
            candidates.Select(c => c.Name).Distinct(StringComparer.Ordinal).Count());

        // The input itself is never a candidate (case-insensitive).
        Assert.DoesNotContain(candidates, c => string.Equals(c.Name, "Newtonsoft.Json", StringComparison.OrdinalIgnoreCase));

        // Separator-removed and a homoglyph variant are both present.
        Assert.Contains(candidates, c => c.Name == "NewtonsoftJson");
        Assert.Contains(candidates, c => c.Mutator == MutatorType.AsciiHomoglyph);

        // Every candidate carries a human-readable reason and a defined, set mutator.
        Assert.All(candidates, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Reason));
            Assert.True(Enum.IsDefined(c.Mutator));
            Assert.NotEqual(MutatorType.Unspecified, c.Mutator);
        });
    }

    // Case 3 — the NuGet preset drops the '.'-separator mutation (OSSGadget tuning): the SeparatorChanged
    // mutator must not swap the '.' for another separator. Under the NuGet preset the '.'-separator variants
    // (e.g. "Newtonsoft-Json", "Newtonsoft_Json") are excluded — ReplaceCharacter skips '-'/'_' and so cannot
    // produce them either. Since '.' is the input's only separator, the SeparatorChanged mutator contributes
    // nothing here.
    [Fact]
    public void Generate_NewtonsoftJson_ExcludesDotSeparatorMutation()
    {
        var candidates = SquatCandidateGenerator.Generate("Newtonsoft.Json");

        Assert.DoesNotContain(candidates, c => c.Mutator == MutatorType.SeparatorChanged);
    }

    // Case 4 — determinism: two Generate calls produce identical, equally-ordered sequences.
    [Fact]
    public void Generate_IsDeterministic_AcrossCalls()
    {
        var first = SquatCandidateGenerator.Generate("Newtonsoft.Json");
        var second = SquatCandidateGenerator.Generate("Newtonsoft.Json");

        Assert.Equal(first.ToArray(), second.ToArray());
    }

    // Case 5 — target "Newtonsft.Json" (a typo of the popular "Newtonsoft.Json") with fake data where the
    // real package has 1e9 downloads and the target has 5 → a single finding naming "Newtonsoft.Json" as
    // the squatted, far-more-popular candidate.
    [Fact]
    public async Task CheckAsync_TypoOfPopularPackage_FlagsEstablishedCandidate()
    {
        const string target = "Newtonsft.Json";
        const string popular = "Newtonsoft.Json";
        const long popularDownloads = 1_000_000_000L;
        const long targetDownloads = 5L;

        var source = new FakePopularitySource(new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
        {
            [target] = targetDownloads,
            [popular] = popularDownloads,
        });
        var checker = new SquatChecker(source);

        var result = await checker.CheckAsync(target);

        Assert.True(result.IsSuccess, result.Message);
        var finding = Assert.Single(result.Value);
        Assert.Equal(target, finding.TargetId);
        Assert.Equal(popular, finding.SquattedCandidate, ignoreCase: true);
        Assert.Equal(targetDownloads, finding.TargetDownloads);
        Assert.Equal(popularDownloads, finding.CandidateDownloads);
        Assert.False(string.IsNullOrWhiteSpace(finding.Reason));
    }

    // Case 6 — a benign, unique id whose near-neighbors either don't exist or are not >= threshold-x more
    // popular than the target yields no findings.
    [Fact]
    public async Task CheckAsync_BenignId_WithNoDominantNeighbor_ReturnsNoFindings()
    {
        const string target = "Silvergun.Unique.Testpkg.Zzz";
        const long targetDownloads = 1_000_000L;

        // One real-but-not-dominant neighbor (exists, only 2x the target — below the 10x threshold); every
        // other candidate is absent from the feed.
        var neighbor = SquatCandidateGenerator.Generate(target).First().Name;
        var belowThreshold = targetDownloads * 2;   // 2x < PopularityRatioThreshold (10x)
        Assert.True(belowThreshold < targetDownloads * SquatChecker.PopularityRatioThreshold);

        var source = new FakePopularitySource(new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
        {
            [target] = targetDownloads,
            [neighbor] = belowThreshold,
        });
        var checker = new SquatChecker(source);

        var result = await checker.CheckAsync(target);

        Assert.True(result.IsSuccess, result.Message);
        Assert.Empty(result.Value);
    }

    // Case 7 — a popularity source that throws for one candidate lookup must not sink CheckAsync: the
    // failure is skipped and the remaining candidates are still evaluated (the "Newtonsoft.Json" finding
    // still surfaces).
    [Fact]
    public async Task CheckAsync_WhenSourceThrowsForOneCandidate_SkipsItAndEvaluatesTheRest()
    {
        const string target = "Newtonsft.Json";
        const string popular = "Newtonsoft.Json";

        // Choose a real candidate (other than the popular one) to fail on.
        var throwOn = SquatCandidateGenerator.Generate(target)
            .First(c => !string.Equals(c.Name, popular, StringComparison.OrdinalIgnoreCase))
            .Name;

        var source = new FakePopularitySource(
            new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
            {
                [target] = 5L,
                [popular] = 1_000_000_000L,
            },
            throwFor: new[] { throwOn });
        var checker = new SquatChecker(source);

        Result<IReadOnlyList<SquatFinding>> result = default;
        var ex = await Record.ExceptionAsync(async () => result = await checker.CheckAsync(target));

        Assert.Null(ex);   // never throws
        Assert.True(result.IsSuccess, result.Message);
        Assert.Contains(result.Value, f => string.Equals(f.SquattedCandidate, popular, StringComparison.OrdinalIgnoreCase));
        Assert.True(source.WasQueried(throwOn), "The throwing candidate should still have been looked up.");
    }

    // Regression — absent target with a low-download near-neighbor: the target is unknown to the feed (fake
    // returns null => treated as 0 downloads) and a real near-neighbor exists but sits below the absolute
    // MinCandidateDownloads floor (500 < 10_000). Pre-fix the ratio-only condition (candidateDownloads >=
    // 10 * 0) flagged EVERY neighbor of an absent target; the added floor eliminates that false positive.
    [Fact]
    public async Task CheckAsync_AbsentTarget_WithLowDownloadNeighbor_ReturnsNoFindings()
    {
        const string target = "Newtonsft.Json";
        const string neighbor = "Newtonsoft.Json";
        const long neighborDownloads = 500L;   // below MinCandidateDownloads (10_000)

        Assert.True(neighborDownloads < SquatChecker.MinCandidateDownloads);

        // Target intentionally omitted from the feed => null => 0 downloads.
        var source = new FakePopularitySource(new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
        {
            [neighbor] = neighborDownloads,
        });
        var checker = new SquatChecker(source);

        var result = await checker.CheckAsync(target);

        Assert.True(result.IsSuccess, result.Message);
        Assert.Empty(result.Value);
    }

    // Regression — absent target with a genuinely popular near-neighbor: the target is unknown to the feed
    // (null => 0 downloads) but a real near-neighbor is hugely popular (5e6, well above MinCandidateDownloads).
    // A brand-new squat of a popular package must still be caught — the absolute floor is met and 5e6 >= 10*0.
    [Fact]
    public async Task CheckAsync_AbsentTarget_WithPopularNeighbor_FlagsThatNeighbor()
    {
        const string target = "Newtonsft.Json";
        const string popular = "Newtonsoft.Json";
        const long popularDownloads = 5_000_000L;   // well above MinCandidateDownloads (10_000)

        Assert.True(popularDownloads >= SquatChecker.MinCandidateDownloads);

        // Target intentionally omitted from the feed => null => 0 downloads.
        var source = new FakePopularitySource(new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
        {
            [popular] = popularDownloads,
        });
        var checker = new SquatChecker(source);

        var result = await checker.CheckAsync(target);

        Assert.True(result.IsSuccess, result.Message);
        var finding = Assert.Single(result.Value);
        Assert.Equal(target, finding.TargetId);
        Assert.Equal(popular, finding.SquattedCandidate, ignoreCase: true);
        Assert.Equal(0L, finding.TargetDownloads);
        Assert.Equal(popularDownloads, finding.CandidateDownloads);
        Assert.False(string.IsNullOrWhiteSpace(finding.Reason));
    }
    // SquatCheckReport (ADR 0010) — the CLI's JSON wrapper for check-squat. A report carrying a couple of
    // findings must round-trip through ToJson/FromJson preserving PackageId, CheckedAt and the findings
    // element-wise, with the MutatorType enum serialized by name (not a bare number).
    [Fact]
    public void SquatCheckReport_JsonRoundTrip_PreservesFindingsAndUsesEnumNames()
    {
        var findings = new[]
        {
            new SquatFinding("Newtonsft.Json", "Newtonsoft.Json", 5L, 1_000_000_000L, "homoglyph swap", MutatorType.AsciiHomoglyph),
            new SquatFinding("Newtonsft.Json", "NewtonsoftJson", 5L, 250_000L, "separator removed", MutatorType.SeparatorRemoved),
        };
        var report = new SquatCheckReport("Newtonsft.Json", DateTimeOffset.UtcNow, findings);

        var json = report.ToJson();
        var restored = SquatCheckReport.FromJson(json);

        Assert.NotNull(restored);
        Assert.Equal(report.PackageId, restored!.PackageId);
        Assert.Equal(report.CheckedAt, restored.CheckedAt);
        Assert.Equal(report.Findings, restored.Findings);   // record equality incl. Mutator

        // MutatorType serialized as names, not bare numbers.
        Assert.Contains("\"AsciiHomoglyph\"", json);
        Assert.DoesNotMatch(new Regex("\"Mutator\"\\s*:\\s*\\d"), json);
    }

    #endregion

    #region Types
    /// <summary>
    /// In-memory <see cref="IPackagePopularitySource"/> test double. Returns the configured download count
    /// for known ids (null for unknown ones), and optionally throws for a configured set of ids to exercise
    /// the checker's best-effort, never-throw contract. Case-insensitive on package id.
    /// </summary>
    private sealed class FakePopularitySource : IPackagePopularitySource
    {
        #region Constructors
        public FakePopularitySource(IReadOnlyDictionary<string, long> downloads, IEnumerable<string>? throwFor = null)
        {
            this.downloads = downloads;
            this.throwFor = new HashSet<string>(throwFor ?? [], StringComparer.OrdinalIgnoreCase);
        }
        #endregion

        #region Methods
        public Task<long?> GetDownloadCountAsync(string packageId, CancellationToken ct = default)
        {
            queried.Add(packageId);
            if (throwFor.Contains(packageId))
                throw new InvalidOperationException($"Simulated lookup failure for '{packageId}'.");

            return Task.FromResult(downloads.TryGetValue(packageId, out var count) ? count : (long?)null);
        }

        public bool WasQueried(string packageId) => queried.Contains(packageId);
        #endregion

        #region Fields
        private readonly IReadOnlyDictionary<string, long> downloads;
        private readonly HashSet<string> throwFor;
        private readonly HashSet<string> queried = new(StringComparer.OrdinalIgnoreCase);
        #endregion
    }
    #endregion
}
