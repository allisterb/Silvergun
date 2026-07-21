namespace Silvergun.Intel;

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// A serializable project-health result for the <c>health</c> verb (ADR 0015): the queried <see cref="PackageId"/>
/// (when applicable), the resolved <see cref="Repository"/> (or <c>null</c>), the scored <see cref="Health"/> (or
/// <c>null</c> when unavailable), a human-readable <see cref="UnavailableReason"/> for the null-health case, and the
/// <see cref="GeneratedAt"/> timestamp. Advisory only; strings/enums/numbers/records (ADR 0002). Mirrors
/// <see cref="ProjectHealth"/>'s JSON conventions.
/// </summary>
public sealed record ProjectHealthReport(
    string? PackageId,
    RepositoryRef? Repository,
    ProjectHealth? Health,
    string? UnavailableReason,
    DateTimeOffset GeneratedAt)
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="ProjectHealthReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static ProjectHealthReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<ProjectHealthReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
