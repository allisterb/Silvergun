namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="ProjectHealthScorer.Score"/> (ADR 0015 / task
/// <c>docs/agent/tasks/project-health-intel.md</c>, Phase 1). The scorer is pure and deterministic given an
/// injected reference clock (<c>now</c>). These tests pin the observable contract — abandonment overrides,
/// band boundaries, the missing-license penalty, the staleness flag, determinism, and the [0,100] clamp — not
/// the internal formula constants (which the ADR reserves the right to tune).
/// </summary>
public sealed class ProjectHealthScorerTests
{
    #region Methods
    // Archived repos are treated as abandoned: activity is forced to 0, an "archived" red flag is raised, and the
    // overall verdict is clamped to the Poor band no matter how popular/mature the repo is.
    [Fact]
    public void Score_ArchivedPopularRepo_ZeroActivityArchivedFlagPoorBand()
    {
        var health = ProjectHealthScorer.Score(
            Repo, stars: 50_000, forks: 8_000, subscribers: 1_200, watchers: 50_000, openIssues: 100, sizeKb: 24_000,
            createdAt: Now.AddDays(-4000), pushedAt: Now.AddDays(-5), license: "MIT",
            archived: true, disabled: false, hasIssues: true, defaultBranch: "main", now: Now);

        Assert.Equal(0, health.ActivityScore);
        Assert.Contains("archived", health.RedFlags);
        Assert.Equal(HealthBand.Poor, health.Band);
        Assert.True(health.OverallScore < 15);
    }

    // Disabled repos are abandoned in the same way as archived ones.
    [Fact]
    public void Score_DisabledPopularRepo_ZeroActivityDisabledFlagPoorBand()
    {
        var health = ProjectHealthScorer.Score(
            Repo, stars: 50_000, forks: 8_000, subscribers: 1_200, watchers: 50_000, openIssues: 100, sizeKb: 24_000,
            createdAt: Now.AddDays(-4000), pushedAt: Now.AddDays(-5), license: "MIT",
            archived: false, disabled: true, hasIssues: true, defaultBranch: "main", now: Now);

        Assert.Equal(0, health.ActivityScore);
        Assert.Contains("disabled", health.RedFlags);
        Assert.Equal(HealthBand.Poor, health.Band);
        Assert.True(health.OverallScore < 15);
    }

    // A freshly-pushed, popular, mature, licensed repo lands in the Healthy band with no red flags.
    [Fact]
    public void Score_FreshPopularLicensedRepo_HealthyBandNoFlags()
    {
        var health = ProjectHealthScorer.Score(
            Repo, stars: 30_000, forks: 6_000, subscribers: 1_500, watchers: 30_000, openIssues: 200, sizeKb: 12_000,
            createdAt: Now.AddDays(-4000), pushedAt: Now.AddDays(-5), license: "MIT",
            archived: false, disabled: false, hasIssues: true, defaultBranch: "main", now: Now);

        Assert.Equal(HealthBand.Healthy, health.Band);
        Assert.True(health.OverallScore >= 70);
        Assert.Empty(health.RedFlags);
    }

    // A missing license costs exactly 10 overall points (relative to an otherwise-identical licensed repo) and
    // raises a "no license" flag. The scenario is chosen so neither score is clamped, so the delta is exact.
    [Fact]
    public void Score_MissingLicense_AppliesTenPointPenaltyAndFlag()
    {
        var licensed = ScoreModerate(license: "MIT");
        var unlicensed = ScoreModerate(license: null);

        Assert.Equal(10, licensed.OverallScore - unlicensed.OverallScore);
        Assert.Contains("no license", unlicensed.RedFlags);
        Assert.DoesNotContain("no license", licensed.RedFlags);
    }

    // A push older than two years zeroes activity and raises the "no push in 2+ years" flag (without implying
    // archival/disablement).
    [Fact]
    public void Score_PushOlderThanTwoYears_LowActivityAndStaleFlag()
    {
        var health = ProjectHealthScorer.Score(
            Repo, stars: 500, forks: 40, subscribers: 10, watchers: 500, openIssues: 5, sizeKb: 800,
            createdAt: Now.AddDays(-2000), pushedAt: Now.AddDays(-800), license: "MIT",
            archived: false, disabled: false, hasIssues: true, defaultBranch: "main", now: Now);

        Assert.Equal(0, health.ActivityScore);
        Assert.Contains("no push in 2+ years", health.RedFlags);
        Assert.DoesNotContain("archived", health.RedFlags);
        Assert.DoesNotContain("disabled", health.RedFlags);
    }

    // Determinism: identical inputs plus a fixed clock produce identical scores, band, and flags every time.
    // (Record equality can't be used directly because RedFlags is a fresh list per call, so compare field-wise.)
    [Fact]
    public void Score_SameInputsAndClock_IsDeterministic()
    {
        var a = ScoreModerate(license: "MIT");
        var b = ScoreModerate(license: "MIT");

        Assert.Equal(a.ActivityScore, b.ActivityScore);
        Assert.Equal(a.PopularityScore, b.PopularityScore);
        Assert.Equal(a.MaturityScore, b.MaturityScore);
        Assert.Equal(a.OverallScore, b.OverallScore);
        Assert.Equal(a.Band, b.Band);
        Assert.Equal(a.RedFlags, b.RedFlags);
    }

    // Every sub-score and the overall score stay within [0,100] even for degenerate inputs — negative/huge stars,
    // and null dates.
    [Theory]
    [InlineData(-100, -100, -100)]
    [InlineData(0, 0, 0)]
    [InlineData(int.MaxValue, int.MaxValue, int.MaxValue)]
    public void Score_ExtremeInputs_AllScoresWithinZeroToHundred(int stars, int forks, int subscribers)
    {
        var health = ProjectHealthScorer.Score(
            Repo, stars, forks, subscribers, watchers: null, openIssues: null, sizeKb: null,
            createdAt: null, pushedAt: null, license: null,
            archived: false, disabled: false, hasIssues: false, defaultBranch: null, now: Now);

        Assert.InRange(health.ActivityScore, 0, 100);
        Assert.InRange(health.PopularityScore, 0, 100);
        Assert.InRange(health.MaturityScore, 0, 100);
        Assert.InRange(health.OverallScore, 0, 100);
    }
    #endregion

    #region Helpers
    // A mid-range, unclamped scenario (activity 50 / popularity 59 / maturity 50) used by the penalty and
    // determinism tests; only the license varies.
    private static ProjectHealth ScoreModerate(string? license) =>
        ProjectHealthScorer.Score(
            Repo, stars: 100, forks: 10, subscribers: 5, watchers: 100, openIssues: 3, sizeKb: 400,
            createdAt: Now.AddDays(-730), pushedAt: Now.AddDays(-380), license: license,
            archived: false, disabled: false, hasIssues: true, defaultBranch: "main", now: Now);
    #endregion

    #region Fields
    private static readonly RepositoryRef Repo = new("github", "dotnet", "runtime");
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    #endregion
}
