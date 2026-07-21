namespace Silvergun.Intel;

using System;
using System.Collections.Generic;

/// <summary>
/// Silvergun's own project-health scoring (ADR 0015 — deliberately <b>not</b> a port of OSSGadget's formulas).
/// Pure and deterministic: given the raw GitHub fields plus a reference <c>now</c>, it produces the same
/// <see cref="ProjectHealth"/> every time. All constants are named and documented so they can be tuned without
/// changing the shape of the contract. Every sub-score is clamped to [0,100].
/// </summary>
public static class ProjectHealthScorer
{
    #region Methods
    /// <summary>
    /// Computes a <see cref="ProjectHealth"/> from the raw repository fields. <paramref name="now"/> is the clock
    /// reference for recency/age (injected for determinism). Abandonment (<paramref name="archived"/>/
    /// <paramref name="disabled"/>) zeroes activity and clamps the overall verdict to the Poor band; a missing
    /// <paramref name="license"/> applies a penalty; a push older than two years is flagged and yields low activity.
    /// </summary>
    public static ProjectHealth Score(
        RepositoryRef repository,
        int? stars,
        int? forks,
        int? subscribers,
        int? watchers,
        int? openIssues,
        int? sizeKb,
        DateTimeOffset? createdAt,
        DateTimeOffset? pushedAt,
        string? license,
        bool archived,
        bool disabled,
        bool hasIssues,
        string? defaultBranch,
        DateTimeOffset now)
    {
        var activity = ActivityScoreFor(pushedAt, archived, disabled, now);
        var popularity = PopularityScoreFor(stars, forks, subscribers);
        var maturity = MaturityScoreFor(createdAt, now);

        // Weighted mean — activity dominates because staleness is the strongest abandonment signal.
        var overall = ActivityWeight * activity + PopularityWeight * popularity + MaturityWeight * maturity;

        var missingLicense = string.IsNullOrWhiteSpace(license);
        if (missingLicense)
            overall -= NoLicensePenalty;

        var stalePush = pushedAt is { } p && (now - p).TotalDays >= StaleDays;

        var flags = new List<string>();
        if (archived) flags.Add(ArchivedFlag);
        if (disabled) flags.Add(DisabledFlag);
        if (missingLicense) flags.Add(NoLicenseFlag);
        if (stalePush) flags.Add(StalePushFlag);

        var overallScore = Clamp(overall);
        // Abandonment overrides the arithmetic: an archived/disabled repo can never be better than Poor.
        if (archived || disabled)
            overallScore = Math.Min(overallScore, PoorCeiling);

        var band = BandFor(overallScore, archived, disabled);

        return new ProjectHealth(
            repository, stars, forks, subscribers, watchers, openIssues, sizeKb,
            createdAt, pushedAt, license, archived, disabled, hasIssues, defaultBranch,
            activity, popularity, maturity, overallScore, band, flags);
    }

    // Recency of the last push: full credit within FreshDays, linear decay to 0 at StaleDays (~2 years).
    // Abandonment or unknown recency ⇒ 0.
    private static int ActivityScoreFor(DateTimeOffset? pushedAt, bool archived, bool disabled, DateTimeOffset now)
    {
        if (archived || disabled)
            return 0;
        if (pushedAt is not { } p)
            return 0;

        var days = (now - p).TotalDays;
        if (days <= FreshDays)
            return 100;
        if (days >= StaleDays)
            return 0;
        return Clamp(100.0 * (StaleDays - days) / (StaleDays - FreshDays));
    }

    // Log-scaled popularity: stars dominate, forks/subscribers add a smaller signal. Diminishing returns keep
    // a handful of mega-repos from pinning everything else to 0.
    private static int PopularityScoreFor(int? stars, int? forks, int? subscribers)
    {
        var s = Math.Max(0, stars ?? 0);
        var f = Math.Max(0, forks ?? 0);
        var w = Math.Max(0, subscribers ?? 0);
        var score = StarWeight * Math.Log10(1 + s)
                  + ForkWeight * Math.Log10(1 + f)
                  + SubscriberWeight * Math.Log10(1 + w);
        return Clamp(score);
    }

    // Repo age in years, capped: an established project reaches the ceiling after 100/MaturityPerYear years.
    private static int MaturityScoreFor(DateTimeOffset? createdAt, DateTimeOffset now)
    {
        if (createdAt is not { } c)
            return 0;
        var years = Math.Max(0.0, (now - c).TotalDays / DaysPerYear);
        return Clamp(years * MaturityPerYear);
    }

    private static HealthBand BandFor(int overall, bool archived, bool disabled)
    {
        if (archived || disabled)
            return HealthBand.Poor;
        if (overall >= HealthyThreshold)
            return HealthBand.Healthy;
        if (overall >= ModerateThreshold)
            return HealthBand.Moderate;
        if (overall >= LowThreshold)
            return HealthBand.Low;
        return HealthBand.Poor;
    }

    private static int Clamp(double value) =>
        (int)Math.Round(Math.Clamp(value, 0.0, 100.0), MidpointRounding.AwayFromZero);
    #endregion

    #region Fields
    // Overall weighting (sums to 1.0).
    private const double ActivityWeight = 0.45;
    private const double PopularityWeight = 0.30;
    private const double MaturityWeight = 0.25;

    // Activity decay window.
    private const double FreshDays = 30.0;    // pushed within a month ⇒ full activity credit
    private const double StaleDays = 730.0;   // ~2 years with no push ⇒ zero activity (and a red flag)

    // Popularity log weights.
    private const double StarWeight = 25.0;        // 25*log10(1+stars): ~10k stars ⇒ 100 on its own
    private const double ForkWeight = 5.0;
    private const double SubscriberWeight = 5.0;

    // Maturity.
    private const double MaturityPerYear = 25.0;   // ~4 years ⇒ full maturity credit
    private const double DaysPerYear = 365.25;

    // Penalties.
    private const double NoLicensePenalty = 10.0;

    // Band thresholds (on the 0–100 overall score).
    private const int HealthyThreshold = 70;
    private const int ModerateThreshold = 40;
    private const int LowThreshold = 15;
    private const int PoorCeiling = LowThreshold - 1;   // archived/disabled overall is clamped at/below this

    // Red-flag labels.
    private const string ArchivedFlag = "archived";
    private const string DisabledFlag = "disabled";
    private const string NoLicenseFlag = "no license";
    private const string StalePushFlag = "no push in 2+ years";
    #endregion
}
