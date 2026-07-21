namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// JSON serialization contract for the Phase 2 project-health report surface (ADR 0015): the new
/// <see cref="ProjectHealthReport"/> (health verb) round-trips with and without a resolved repository/health,
/// <see cref="PackageCapabilityReport"/> round-trips with a non-null additive <see cref="PackageCapabilityReport.ProjectHealth"/>,
/// and — crucially — pre-ADR-0015 JSON that omits the additive fields (<c>RepositoryUrl</c>/<c>ProjectUrl</c> on the
/// identity, <c>ProjectHealth</c> on the report) still deserializes with those fields defaulting to <c>null</c>.
/// </summary>
public sealed class ProjectHealthReportJsonTests
{
    #region Methods — ProjectHealthReport
    // A fully-populated health report (resolved repository + scored health) survives ToJson => FromJson unchanged.
    [Fact]
    public void ProjectHealthReport_WithHealthAndRepository_RoundTrips()
    {
        var original = new ProjectHealthReport(
            PackageId: "Some.Package",
            Repository: new RepositoryRef("github", "dotnet", "runtime"),
            Health: SampleHealth(),
            UnavailableReason: null,
            GeneratedAt: new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero));

        var restored = ProjectHealthReport.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal(original.PackageId, restored!.PackageId);
        Assert.Equal(original.Repository, restored.Repository);
        Assert.Null(restored.UnavailableReason);
        Assert.Equal(original.GeneratedAt, restored.GeneratedAt);
        Assert.NotNull(restored.Health);
        Assert.Equal(original.Health!.OverallScore, restored.Health!.OverallScore);
        Assert.Equal(original.Health.Band, restored.Health.Band);
        Assert.Equal(original.Health.RedFlags, restored.Health.RedFlags);
    }

    // The "unavailable" outcome (no health, a reason string, repository may be null) is a normal, lossless round-trip.
    [Fact]
    public void ProjectHealthReport_Unavailable_RoundTrips()
    {
        var original = new ProjectHealthReport(
            PackageId: "No.Repo.Package",
            Repository: null,
            Health: null,
            UnavailableReason: "no GitHub repository resolved",
            GeneratedAt: DateTimeOffset.UnixEpoch);

        var restored = ProjectHealthReport.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal("No.Repo.Package", restored!.PackageId);
        Assert.Null(restored.Repository);
        Assert.Null(restored.Health);
        Assert.Equal("no GitHub repository resolved", restored.UnavailableReason);
        Assert.Equal(DateTimeOffset.UnixEpoch, restored.GeneratedAt);
    }

    // FromJson(null) is a defined no-op returning null (only malformed non-null input throws).
    [Fact]
    public void ProjectHealthReport_FromJson_NullInput_ReturnsNull()
    {
        Assert.Null(ProjectHealthReport.FromJson(null!));
    }
    #endregion

    #region Methods — PackageCapabilityReport additive ProjectHealth
    // The additive ProjectHealth on a scan-package report round-trips: a non-null health survives with its scores,
    // band, repository, and red flags intact.
    [Fact]
    public void PackageCapabilityReport_WithProjectHealth_RoundTrips()
    {
        var pkg = new PackageIdentityInfo(
            "Health.Package", "2.0.0", "Author", "desc", [],
            RepositoryUrl: "https://github.com/owner/repo", ProjectUrl: "https://example.org");
        var original = new PackageCapabilityReport(pkg, DateTimeOffset.UnixEpoch, [], [], [], SampleHealth());

        var restored = PackageCapabilityReport.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Equal("https://github.com/owner/repo", restored!.Package.RepositoryUrl);
        Assert.Equal("https://example.org", restored.Package.ProjectUrl);
        Assert.NotNull(restored.ProjectHealth);
        Assert.Equal(original.ProjectHealth!.Repository, restored.ProjectHealth!.Repository);
        Assert.Equal(original.ProjectHealth.OverallScore, restored.ProjectHealth.OverallScore);
        Assert.Equal(original.ProjectHealth.Band, restored.ProjectHealth.Band);
        Assert.Equal(original.ProjectHealth.RedFlags, restored.ProjectHealth.RedFlags);
    }

    // Default (no --health) scan-package reports leave ProjectHealth null; that survives the round-trip as null.
    [Fact]
    public void PackageCapabilityReport_WithoutProjectHealth_RoundTripsAsNull()
    {
        var pkg = new PackageIdentityInfo("Plain.Package", "1.0.0", "Author", null, []);
        var original = new PackageCapabilityReport(pkg, DateTimeOffset.UnixEpoch, [], [], []);

        var restored = PackageCapabilityReport.FromJson(original.ToJson());

        Assert.NotNull(restored);
        Assert.Null(restored!.ProjectHealth);
        Assert.Null(restored.Package.RepositoryUrl);
        Assert.Null(restored.Package.ProjectUrl);
    }
    #endregion

    #region Methods — back-compat (old JSON without the additive fields)
    // Pre-ADR-0015 JSON: a scan-package report whose Package omits RepositoryUrl/ProjectUrl and whose body omits
    // ProjectHealth must still deserialize (additive/optional), with every new field defaulting to null.
    [Fact]
    public void PackageCapabilityReport_OldJsonWithoutAdditiveFields_Deserializes()
    {
        const string oldJson = """
            {
              "Package": {
                "Id": "Legacy.Package",
                "Version": "1.2.3",
                "Authors": "Legacy Author",
                "Description": null,
                "Dependencies": []
              },
              "AnalyzedAt": "1970-01-01T00:00:00+00:00",
              "Assemblies": [],
              "Scripts": [],
              "ScriptFindings": []
            }
            """;

        var restored = PackageCapabilityReport.FromJson(oldJson);

        Assert.NotNull(restored);
        Assert.Equal("Legacy.Package", restored!.Package.Id);
        Assert.Null(restored.Package.RepositoryUrl);   // additive field absent in old JSON => null
        Assert.Null(restored.Package.ProjectUrl);
        Assert.Null(restored.ProjectHealth);           // additive field absent in old JSON => null
    }
    #endregion

    #region Helpers
    // A ProjectHealth with a mix of null/non-null raw fields and a two-entry ordered RedFlags list.
    private static ProjectHealth SampleHealth() =>
        new(
            new RepositoryRef("github", "dotnet", "runtime"),
            Stars: 1_000, Forks: 200, Subscribers: null, Watchers: 1_000, OpenIssues: 50, SizeKb: 4_096,
            CreatedAt: new DateTimeOffset(2016, 1, 1, 0, 0, 0, TimeSpan.Zero),
            PushedAt: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
            License: "MIT", Archived: false, Disabled: false, HasIssues: true, DefaultBranch: "main",
            ActivityScore: 90, PopularityScore: 80, MaturityScore: 100, OverallScore: 88,
            Band: HealthBand.Healthy, RedFlags: new[] { "no push in 2+ years", "no license" });
    #endregion
}
