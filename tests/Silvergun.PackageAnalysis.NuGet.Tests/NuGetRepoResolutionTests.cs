namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Text;

using Silvergun;
using Silvergun.Intel;

using Xunit;

/// <summary>
/// Offline nuspec repo-hint extraction (ADR 0015, Phase 2): <see cref="NuGetPackage.Open"/> reads the nuspec's
/// <c>&lt;repository url&gt;</c> into <see cref="PackageIdentityInfo.RepositoryUrl"/> and its <c>&lt;projectUrl&gt;</c>
/// into <see cref="PackageIdentityInfo.ProjectUrl"/> — both additive and both <c>null</c> for a package that declares
/// neither (back-compat). Also confirms a github repository URL resolves through <see cref="GitHubRepoUrl.TryParse"/>
/// to a <see cref="RepositoryRef"/>. Packages are built with pure BCL zip (<see cref="NupkgBuilder"/>) — no network.
/// </summary>
public sealed class NuGetRepoResolutionTests : IDisposable
{
    #region Constructors
    public NuGetRepoResolutionTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        rootDir = Path.Combine(Path.GetTempPath(), "silvergun-repotests", "root-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
    }
    #endregion

    #region Methods
    // A nuspec carrying BOTH <repository url> and <projectUrl> populates both identity hints verbatim, and the
    // github repository URL resolves to owner/repo via GitHubRepoUrl.TryParse.
    [Fact]
    public void Open_NuspecWithRepositoryAndProjectUrl_PopulatesBothHints()
    {
        const string repoUrl = "https://github.com/owner/repo";
        const string projectUrl = "https://example.org/project";
        using var pkg = OpenPackage("PkgRepo", repoUrl, projectUrl);

        Assert.Equal(repoUrl, pkg.Identity.RepositoryUrl);
        Assert.Equal(projectUrl, pkg.Identity.ProjectUrl);

        Assert.True(GitHubRepoUrl.TryParse(pkg.Identity.RepositoryUrl, out var repo));
        Assert.Equal("github", repo.Host);
        Assert.Equal("owner", repo.Owner);
        Assert.Equal("repo", repo.Repo);
    }

    // A nuspec with only <projectUrl> (no <repository>) leaves RepositoryUrl null while ProjectUrl is populated.
    [Fact]
    public void Open_NuspecWithProjectUrlOnly_PopulatesProjectUrl_AndLeavesRepositoryNull()
    {
        const string projectUrl = "https://github.com/acme/widget";
        using var pkg = OpenPackage("PkgProjectOnly", repositoryUrl: null, projectUrl: projectUrl);

        Assert.Null(pkg.Identity.RepositoryUrl);
        Assert.Equal(projectUrl, pkg.Identity.ProjectUrl);
    }

    // Back-compat: a nuspec declaring neither hint yields two nulls (the pre-ADR-0015 shape), never throwing.
    [Fact]
    public void Open_NuspecWithoutRepoHints_LeavesBothNull()
    {
        using var pkg = OpenPackage("PkgNoHints", repositoryUrl: null, projectUrl: null);

        Assert.Null(pkg.Identity.RepositoryUrl);
        Assert.Null(pkg.Identity.ProjectUrl);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(rootDir))
                Directory.Delete(rootDir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort temp cleanup */ }
    }

    // Builds a minimal nuspec-only package with the given repo hints, opens it, and returns the opened package.
    private NuGetPackage OpenPackage(string id, string? repositoryUrl, string? projectUrl)
    {
        var nuspec = NupkgBuilder.NuspecXml(
            id, "1.0.0", "Silvergun Tests", "Repo-hint extraction test package.", "netstandard2.0", [],
            repositoryUrl, projectUrl);
        var path = Path.Combine(rootDir, $"{id}.1.0.0.nupkg");
        NupkgBuilder.WriteNupkg(path, [($"{id}.nuspec", Encoding.UTF8.GetBytes(nuspec))]);

        var open = NuGetPackage.Open(path);
        Assert.True(open.IsSuccess, open.Message);
        return open.Value;
    }
    #endregion

    #region Fields
    private readonly string rootDir;
    #endregion
}
