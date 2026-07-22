namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="OsvQueryBuilder.Build"/> (ADR 0017 Phase 2 / task
/// <c>docs/agent/tasks/osv-vulnerability-intel.md</c>). The builder projects a scanned package's local nuspec
/// identity into the OSV query set: the package itself at its exact version (<see cref="OsvQuery.IsDependency"/>
/// <c>false</c>) plus each declared dependency at its version-range floor (<c>IsDependency</c> <c>true</c>).
/// These tests assert the INTENDED projection contract — exact-version self-query, floor-resolved deps, skipping of
/// unbounded/empty/malformed ranges, case-insensitive (id, version) dedupe, empty for null/empty input, and the
/// never-throws guarantee — not the current implementation shape.
/// </summary>
public sealed class OsvQueryBuilderTests
{
    #region Methods
    // The package itself is always queried FIRST at its exact nuspec version, marked as NOT a dependency.
    [Fact]
    public void Build_EmitsPackageAtExactVersion_AsNonDependency()
    {
        var package = Identity("Test.Package", "1.2.3");

        var queries = OsvQueryBuilder.Build(package);

        var self = Assert.Single(queries);
        Assert.Equal("Test.Package", self.PackageId);
        Assert.Equal("1.2.3", self.Version);      // exact version, verbatim from the nuspec
        Assert.False(self.IsDependency);
    }

    // Each declared dependency is queried at the normalized MINIMUM (floor) of its version range, marked as a
    // dependency. "[1.2.3,2.0.0)" floors to 1.2.3; the partial "1.0" normalizes to 1.0.0.
    [Fact]
    public void Build_EmitsDependenciesAtRangeFloor_NormalizedAsDependencies()
    {
        var package = Identity(
            "Root", "1.0.0",
            Dep("Dep.Bounded", "[1.2.3,2.0.0)"),
            Dep("Dep.Partial", "1.0"));

        var queries = OsvQueryBuilder.Build(package);

        var bounded = Assert.Single(queries, q => q.PackageId == "Dep.Bounded");
        Assert.Equal("1.2.3", bounded.Version);
        Assert.True(bounded.IsDependency);

        var partial = Assert.Single(queries, q => q.PackageId == "Dep.Partial");
        Assert.Equal("1.0.0", partial.Version);   // MinVersion.ToNormalizedString() fills the patch component
        Assert.True(partial.IsDependency);
    }

    // A dependency whose range has NO lower bound (unbounded-below), an EMPTY range, or a MALFORMED range yields no
    // resolvable floor, so it is skipped entirely — only the package self-query remains.
    [Theory]
    [InlineData("(,2.0.0)")]      // unbounded below — MinVersion is null
    [InlineData("")]              // empty range
    [InlineData("   ")]           // whitespace range
    [InlineData("not-a-version")] // malformed / unparseable
    [InlineData("[1.0.0")]        // malformed — unterminated bracket
    public void Build_SkipsDependencyWithUnresolvableFloor(string range)
    {
        var package = Identity("Root", "1.0.0", Dep("Dep.Skipped", range));

        var queries = OsvQueryBuilder.Build(package);

        var self = Assert.Single(queries);                 // only the package remains
        Assert.Equal("Root", self.PackageId);
        Assert.DoesNotContain(queries, q => q.PackageId == "Dep.Skipped");
    }

    // Two dependencies with the SAME id in different case and the same resolved floor collapse to a single query:
    // NuGet ids are case-insensitive, so the (id, version) dedupe key ignores case.
    [Fact]
    public void Build_DedupesDependenciesByCaseInsensitiveIdAndVersion()
    {
        var package = Identity(
            "Root", "1.0.0",
            Dep("Newtonsoft.Json", "[13.0.1]"),
            Dep("newtonsoft.json", "[13.0.1]"));

        var queries = OsvQueryBuilder.Build(package);

        Assert.Equal(2, queries.Count);   // package + exactly one deduped dependency
        var dep = Assert.Single(queries, q => string.Equals(q.PackageId, "Newtonsoft.Json", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("13.0.1", dep.Version);
        Assert.True(dep.IsDependency);
    }

    // A null package produces an empty query set (no self-query, no throw).
    [Fact]
    public void Build_NullPackage_ReturnsEmpty()
    {
        var queries = OsvQueryBuilder.Build(null!);

        Assert.Empty(queries);
    }

    // A null Dependencies list is tolerated: the package still self-queries and nothing throws.
    [Fact]
    public void Build_NullDependencies_YieldsOnlyPackageSelfQuery()
    {
        var package = new PackageIdentityInfo("Root", "1.0.0", "Author", "desc", null!);

        var queries = OsvQueryBuilder.Build(package);

        var self = Assert.Single(queries);
        Assert.Equal("Root", self.PackageId);
        Assert.False(self.IsDependency);
    }

    // An empty Dependencies list yields only the package self-query.
    [Fact]
    public void Build_EmptyDependencies_YieldsOnlyPackageSelfQuery()
    {
        var package = Identity("Root", "1.0.0");

        var self = Assert.Single(OsvQueryBuilder.Build(package));

        Assert.Equal("Root", self.PackageId);
    }

    // Adversarial input — a package with a missing version and a mix of bad dependency ranges — must never throw;
    // the missing-version self-query is simply not emitted and the bad deps are skipped.
    [Fact]
    public void Build_AdversarialInput_NeverThrows_AndSkipsUnqueryable()
    {
        var package = new PackageIdentityInfo(
            "Root", "", "Author", "desc",
            new[]
            {
                Dep("", "[1.0.0]"),                 // blank id
                Dep("Dep.Bad", "(,1.0.0)"),         // unbounded below
                Dep("Dep.Good", "[2.0.0,3.0.0)"),   // resolvable => floor 2.0.0
            });

        var queries = OsvQueryBuilder.Build(package);

        // The package self-query is dropped (blank version); only the single resolvable dependency survives.
        var good = Assert.Single(queries);
        Assert.Equal("Dep.Good", good.PackageId);
        Assert.Equal("2.0.0", good.Version);
        Assert.True(good.IsDependency);
    }
    #endregion

    #region Helpers
    private static PackageDependencyInfo Dep(string id, string range) =>
        new(id, range, "net10.0");

    private static PackageIdentityInfo Identity(string id, string version, params PackageDependencyInfo[] deps) =>
        new(id, version, "Author", "desc", deps);
    #endregion
}
