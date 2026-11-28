namespace Silvergun.Intel;

using System;
using System.Text.RegularExpressions;

/// <summary>
/// A resolved source-repository reference. <paramref name="Host"/> is <c>"github"</c> in v1 (the only host
/// Silvergun resolves for project-health intel); other forges parse to no ref and are reported as "unavailable".
/// </summary>
public sealed record RepositoryRef(string Host, string Owner, string Repo);

/// <summary>
/// Parses the many shapes a GitHub repository URL takes in nuspec <c>&lt;repository&gt;</c>/<c>&lt;projectUrl&gt;</c>
/// and nuget.org metadata into a <see cref="RepositoryRef"/>. Best-effort and total: any non-github or unparseable
/// input yields <c>false</c> and never throws.
/// </summary>
public static class GitHubRepoUrl
{
    #region Methods
    /// <summary>
    /// Attempts to parse <paramref name="url"/> into a github <see cref="RepositoryRef"/>. Accepts
    /// <c>https://github.com/{owner}/{repo}</c> (with optional <c>.git</c> suffix and trailing path/query/fragment),
    /// <c>git+https://…</c>, <c>git://github.com/…</c>, and SSH <c>[email protected]:{owner}/{repo}.git</c>. Host matching
    /// (<c>github.com</c>/<c>www.github.com</c>) is case-insensitive. Returns <c>false</c> for null/blank, non-github,
    /// or otherwise unparseable input; never throws.
    /// </summary>
    public static bool TryParse(string? url, out RepositoryRef repo)
    {
        repo = null!;
        if (string.IsNullOrWhiteSpace(url))
            return false;

        var s = url.Trim();

        // SSH scp-like form: [email protected]:owner/repo.git — no URI scheme, ':' separates host from path.
        if (s.StartsWith(SshPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var rest = s.Substring(SshPrefix.Length);
            var colon = rest.IndexOf(':');
            if (colon <= 0)
                return false;
            return IsGitHubHost(rest.Substring(0, colon))
                && TryParseOwnerRepo(rest.Substring(colon + 1), out repo);
        }

        // "git+https://…" — a PEP-508/SPDX style VCS prefix; drop it and parse the underlying URI.
        if (s.StartsWith(GitPlusPrefix, StringComparison.OrdinalIgnoreCase))
            s = s.Substring(GitPlusPrefix.Length);

        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri))
            return false;

        var scheme = uri.Scheme;
        var schemeOk = scheme == Uri.UriSchemeHttp || scheme == Uri.UriSchemeHttps || scheme == "git";
        return schemeOk
            && IsGitHubHost(uri.Host)
            && TryParseOwnerRepo(uri.AbsolutePath, out repo);
    }

    // Extracts owner/repo from the first two path segments, stripping a trailing ".git" and ignoring any
    // deeper path (…/tree/main). Requires both segments non-empty.
    private static bool TryParseOwnerRepo(string path, out RepositoryRef repo)
    {
        repo = null!;
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2)
            return false;

        var owner = segments[0];
        var name = segments[1];
        if (name.EndsWith(GitSuffix, StringComparison.OrdinalIgnoreCase))
            name = name.Substring(0, name.Length - GitSuffix.Length);

        // GitHub's own name rules, so a segment can never be "." or ".." and redirect an API path (S5 review W1).
        if (!ownerPattern.IsMatch(owner) || !repoPattern.IsMatch(name) || name is "." or "..")
            return false;

        repo = new RepositoryRef(GitHubHost, owner, name);
        return true;
    }

    private static bool IsGitHubHost(string host) =>
        host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
        || host.Equals("www.github.com", StringComparison.OrdinalIgnoreCase);
    #endregion

    #region Fields
    private const string GitHubHost = "github";
    private const string SshPrefix = "git@";
    private const string GitPlusPrefix = "git+";
    private const string GitSuffix = ".git";

    private static readonly Regex ownerPattern = new(@"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\z", RegexOptions.CultureInvariant);
    private static readonly Regex repoPattern = new(@"\A[A-Za-z0-9._-]{1,100}\z", RegexOptions.CultureInvariant);
    #endregion
}
