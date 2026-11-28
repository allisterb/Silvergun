namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// <see cref="GitHubRepoUrl.TryParse"/> enforces GitHub's owner and repository name rules (MCP task S5 review W1): an owner is
/// <c>[A-Za-z0-9][A-Za-z0-9-]{0,38}</c>, a repository <c>[A-Za-z0-9._-]{1,100}</c> other than <c>.</c> and <c>..</c>. A hostile
/// SSH URL such as <c>git@github.com:../user</c> once made the health request <c>GET /repos/../user</c>, which resolves to
/// <c>/user</c> and sent the token there. The SSH form is split (<c>"git@" + …</c>) so no address-like token is written.
/// </summary>
public sealed class GitHubRepoNameRuleTests
{
    #region Methods
    [Theory]
    [InlineData(Ssh + "../user")]
    [InlineData(Ssh + "../meta")]
    [InlineData(Ssh + "owner/..")]
    [InlineData(Ssh + "owner/.")]
    [InlineData(Ssh + "owner/...git")]   // ".." once ".git" is stripped
    [InlineData(Ssh + "./repo")]
    [InlineData("https://github.com/owner/..%2F..%2Fuser")]
    [InlineData("https://github.com/-owner/repo")]
    [InlineData("https://github.com/my_org/repo")]
    [InlineData("https://github.com/own.er/repo")]
    [InlineData("https://github.com/owner/re%20po")]
    [InlineData("https://github.com/owner/re$po")]
    public void TryParse_ANameGitHubWouldNotAllow_IsRejected(string url)
    {
        Assert.False(GitHubRepoUrl.TryParse(url, out var repo));
        Assert.Null(repo);
    }

    [Fact]
    public void TryParse_AnOwnerOver39Chars_OrARepoOver100Chars_IsRejected()
    {
        Assert.False(GitHubRepoUrl.TryParse("https://github.com/" + new string('o', 40) + "/repo", out _));
        Assert.False(GitHubRepoUrl.TryParse("https://github.com/owner/" + new string('r', 101), out _));
    }

    [Theory]
    [InlineData("https://github.com/a/b", "a", "b")]
    [InlineData("https://github.com/dotnet-foundation/runtime.tests", "dotnet-foundation", "runtime.tests")]
    [InlineData("https://github.com/owner/.github", "owner", ".github")]
    [InlineData("https://github.com/owner/repo_name-1.2", "owner", "repo_name-1.2")]
    [InlineData(Ssh + "Owner9/Repo.git", "Owner9", "Repo")]
    public void TryParse_NamesGitHubAllows_AreAccepted(string url, string owner, string name)
    {
        Assert.True(GitHubRepoUrl.TryParse(url, out var repo));
        Assert.Equal((owner, name), (repo.Owner, repo.Repo));
    }

    [Fact]
    public void TryParse_TheLongestNames_AreAccepted()
    {
        var owner = "o" + new string('-', 37) + "o";
        var name = new string('r', 100);

        Assert.True(GitHubRepoUrl.TryParse($"https://github.com/{owner}/{name}", out var repo));
        Assert.Equal((owner, name), (repo.Owner, repo.Repo));
    }
    #endregion

    #region Fields
    private const string Ssh = "git@" + "github.com:";
    #endregion
}
