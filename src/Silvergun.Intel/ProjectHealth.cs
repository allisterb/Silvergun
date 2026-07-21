namespace Silvergun.Intel;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>Coarse health verdict for a source project, derived from <see cref="ProjectHealth.OverallScore"/>.</summary>
public enum HealthBand { Healthy, Moderate, Low, Poor }

/// <summary>
/// A serializable project-health signal for a single GitHub repository (ADR 0015). Carries the raw GitHub fields
/// (all nullable — a source fills only what it knows) alongside Silvergun's own derived sub-scores, an overall
/// score, a <see cref="HealthBand"/>, and human-readable <see cref="RedFlags"/>. Strings/enums/numbers only
/// (ADR 0002). A <c>null</c> <see cref="ProjectHealth"/> means "health unavailable/unknown".
/// </summary>
public sealed record ProjectHealth(
    RepositoryRef Repository,
    int? Stars,
    int? Forks,
    int? Subscribers,
    int? Watchers,
    int? OpenIssues,
    int? SizeKb,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? PushedAt,
    string? License,
    bool Archived,
    bool Disabled,
    bool HasIssues,
    string? DefaultBranch,
    int ActivityScore,       // 0–100: recency of the last push
    int PopularityScore,     // 0–100: log-scaled stars/forks/subscribers
    int MaturityScore,       // 0–100: repo age
    int OverallScore,        // 0–100: weighted mean, after red-flag penalties
    HealthBand Band,
    IReadOnlyList<string> RedFlags)
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="ProjectHealth"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static ProjectHealth? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<ProjectHealth>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
