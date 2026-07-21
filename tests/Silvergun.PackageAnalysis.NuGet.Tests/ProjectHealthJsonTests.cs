namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="ProjectHealth.ToJson"/>/<see cref="ProjectHealth.FromJson"/> (ADR 0015 / task
/// <c>docs/agent/tasks/project-health-intel.md</c>, Phase 1). Verifies a lossless round-trip — the
/// <see cref="HealthBand"/> is written as its name (not a number), nullable raw fields survive as
/// <c>null</c>, and the <see cref="ProjectHealth.RedFlags"/> list is preserved in order. By design
/// <see cref="ProjectHealth.FromJson"/> throws on malformed input, so that is not asserted here.
/// </summary>
public sealed class ProjectHealthJsonTests
{
    #region Methods
    // Full round-trip: every field (including null raw fields, the DateTimeOffset that is set, the RepositoryRef,
    // and the ordered RedFlags) survives ToJson => FromJson unchanged.
    [Fact]
    public void ToJson_ThenFromJson_PreservesAllFields()
    {
        var original = SampleHealth();

        var restored = ProjectHealth.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(original.Repository, restored!.Repository);
        Assert.Null(restored.Stars);                       // nullable raw field stays null
        Assert.Equal(10, restored.Forks);
        Assert.Null(restored.Subscribers);
        Assert.Equal(42, restored.Watchers);
        Assert.Null(restored.OpenIssues);
        Assert.Equal(2_000, restored.SizeKb);
        Assert.Null(restored.CreatedAt);                   // nullable date stays null
        Assert.Equal(original.PushedAt, restored.PushedAt); // set date round-trips exactly
        Assert.Null(restored.License);
        Assert.False(restored.Archived);
        Assert.False(restored.Disabled);
        Assert.True(restored.HasIssues);
        Assert.Equal("main", restored.DefaultBranch);
        Assert.Equal(50, restored.ActivityScore);
        Assert.Equal(55, restored.PopularityScore);
        Assert.Equal(30, restored.MaturityScore);
        Assert.Equal(48, restored.OverallScore);
        Assert.Equal(HealthBand.Moderate, restored.Band);
        Assert.Equal(original.RedFlags, restored.RedFlags); // list preserved in order
    }

    // The band is serialized as its enum name, not its underlying integer.
    [Fact]
    public void ToJson_WritesBandAsName()
    {
        var json = SampleHealth().ToJson();

        Assert.Contains("\"Band\": \"Moderate\"", json);
        Assert.DoesNotContain("\"Band\": 1", json);
    }

    // FromJson(null) is a defined no-op that returns null (only malformed non-null input throws).
    [Fact]
    public void FromJson_NullInput_ReturnsNull()
    {
        Assert.Null(ProjectHealth.FromJson(null!));
    }
    #endregion

    #region Helpers
    // A report with a deliberate mix of null and non-null raw fields plus a two-entry RedFlags list.
    private static ProjectHealth SampleHealth() =>
        new(
            new RepositoryRef("github", "dotnet", "runtime"),
            Stars: null, Forks: 10, Subscribers: null, Watchers: 42, OpenIssues: null, SizeKb: 2_000,
            CreatedAt: null, PushedAt: new DateTimeOffset(2024, 6, 1, 0, 0, 0, TimeSpan.Zero),
            License: null, Archived: false, Disabled: false, HasIssues: true, DefaultBranch: "main",
            ActivityScore: 50, PopularityScore: 55, MaturityScore: 30, OverallScore: 48,
            Band: HealthBand.Moderate, RedFlags: new[] { "no license", "no push in 2+ years" });
    #endregion
}
