namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// A serializable result of a <see cref="SquatChecker"/> run for one target package id (ADR 0010): the id checked,
/// when it was checked, and the flagged <see cref="SquatFinding"/>s (possibly empty). String/enum-only (ADR 0002).
/// </summary>
public sealed record SquatCheckReport(
    string PackageId,
    DateTimeOffset CheckedAt,
    IReadOnlyList<SquatFinding> Findings)
{
    #region Methods
    /// <summary>Serializes this report to indented JSON with enums written as their names.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, jsonOptions);

    /// <summary>
    /// Deserializes a <see cref="SquatCheckReport"/> from JSON produced by <see cref="ToJson"/>.
    /// Returns <c>null</c> for <c>null</c> input; malformed JSON throws.
    /// </summary>
    public static SquatCheckReport? FromJson(string json) =>
        json is null ? null : JsonSerializer.Deserialize<SquatCheckReport>(json, jsonOptions);
    #endregion

    #region Fields
    private static readonly JsonSerializerOptions jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
    #endregion
}
