namespace Silvergun.PackageAnalysis.NuGet.Tests;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// Unit tests for <see cref="GitHubRepoUrl.TryParse"/> (ADR 0015 / task
/// <c>docs/agent/tasks/project-health-intel.md</c>, Phase 1). Covers every URL shape a nuspec
/// <c>&lt;repository&gt;</c>/<c>&lt;projectUrl&gt;</c> or nuget.org metadata takes — <c>https</c> (with
/// <c>.git</c> suffix and trailing path/query/fragment), <c>git+https</c>, <c>git</c>, and SSH
/// <c>[email protected]:owner/repo.git</c> — plus <c>www.</c> and case-insensitive host matching, and the
/// rejection cases (non-github host, null/blank, &lt;2 path segments). Never throws.
/// </summary>
public sealed class GitHubRepoUrlTests
{
    #region Methods
    // Every accepted URL form resolves to Host "github" with the owner/repo taken from the first two path
    // segments, a trailing ".git" stripped, and any deeper path/query/fragment ignored. Host case is ignored,
    // owner/repo case is preserved.
    [Theory]
    [InlineData("https://github.com/dotnet/runtime", "dotnet", "runtime")]
    [InlineData("https://github.com/dotnet/runtime.git", "dotnet", "runtime")]
    [InlineData("https://github.com/dotnet/runtime/tree/main", "dotnet", "runtime")]
    [InlineData("https://github.com/dotnet/runtime.git/tree/main", "dotnet", "runtime")]
    [InlineData("https://github.com/dotnet/runtime?tab=readme", "dotnet", "runtime")]
    [InlineData("https://github.com/dotnet/runtime#section", "dotnet", "runtime")]
    [InlineData("http://github.com/dotnet/runtime", "dotnet", "runtime")]
    [InlineData("git+https://github.com/dotnet/runtime.git", "dotnet", "runtime")]
    [InlineData("git://github.com/dotnet/runtime.git", "dotnet", "runtime")]
    [InlineData("git@" + "github.com:dotnet/runtime.git", "dotnet", "runtime")]
    [InlineData("git@" + "github.com:dotnet/runtime", "dotnet", "runtime")]
    [InlineData("https://www.github.com/dotnet/runtime", "dotnet", "runtime")]
    [InlineData("  https://github.com/dotnet/runtime  ", "dotnet", "runtime")]
    [InlineData("https://GitHub.COM/Dotnet/Runtime", "Dotnet", "Runtime")]
    public void TryParse_AcceptedUrlForms_ReturnsGitHubRef(string url, string expectedOwner, string expectedRepo)
    {
        var ok = GitHubRepoUrl.TryParse(url, out var repo);

        Assert.True(ok);
        Assert.NotNull(repo);
        Assert.Equal("github", repo.Host);
        Assert.Equal(expectedOwner, repo.Owner);
        Assert.Equal(expectedRepo, repo.Repo);
    }

    // Non-github hosts, null/blank input, and URLs without at least two path segments are rejected — false,
    // never an exception. The out ref is left null on failure.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("https://gitlab.com/dotnet/runtime")]
    [InlineData("https://bitbucket.org/dotnet/runtime")]
    [InlineData("git@" + "gitlab.com:dotnet/runtime.git")]
    [InlineData("https://github.com/onlyowner")]
    [InlineData("https://github.com/")]
    [InlineData("https://github.com")]
    [InlineData("not a url at all")]
    [InlineData("ftp://github.com/dotnet/runtime")]
    public void TryParse_RejectedInput_ReturnsFalse(string? url)
    {
        var ok = GitHubRepoUrl.TryParse(url, out var repo);

        Assert.False(ok);
        Assert.Null(repo);
    }
    #endregion
}
