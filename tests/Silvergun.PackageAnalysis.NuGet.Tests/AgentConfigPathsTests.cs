namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;

using Silvergun.PackageAnalysis.NuGet.MsBuild;

using Xunit;

/// <summary>
/// <see cref="AgentConfigPaths"/> (MCP task S4): the data file loads whole, every entry records where it came from (or is
/// <c>unverified</c>, and the README says why), every token names the path it stands for, and near misses name nothing.
/// Matching is on normalized path segments, case-insensitively.
/// </summary>
public sealed class AgentConfigPathsTests
{
    #region Methods
    [Fact]
    public void All_IsEveryEntryOfTheDataFile_InOrder()
    {
        using var data = JsonDocument.Parse(File.ReadAllText(Path.Combine(ResourceDir, "agent_config_paths.json")));

        var tokens = data.RootElement.GetProperty("paths").EnumerateArray().Select(e => e.GetProperty("token").GetString()).ToList();

        Assert.Equal(tokens, AgentConfigPaths.All.Select(p => p.Token));
        Assert.Equal(tokens.Count, tokens.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.True(tokens.Count >= 20, $"{tokens.Count} tokens");
    }

    public static TheoryData<string> Tokens() => [.. AgentConfigPaths.All.Select(p => p.Token)];

    [Theory]
    [MemberData(nameof(Tokens))]
    public void EveryEntry_HasItsProvenance_UnlessItIsUnverified(string token)
    {
        var entry = Assert.Single(AgentConfigPaths.All, p => p.Token == token);

        Assert.False(string.IsNullOrWhiteSpace(entry.Agent));
        Assert.False(string.IsNullOrWhiteSpace(entry.Controls));
        Assert.Contains(entry.Status, new[] { "verified", "unverified" });
        if (entry.Status == "unverified")
        {
            Assert.Null(entry.Source);
            Assert.Null(entry.Fetched);
            return;
        }
        Assert.NotNull(entry.Source);
        Assert.True(Uri.TryCreate(entry.Source, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps, $"{token}: source {entry.Source}");
        Assert.True(DateOnly.TryParseExact(entry.Fetched, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _), $"{token}: fetched {entry.Fetched}");
    }

    [Theory]
    [MemberData(nameof(Tokens))]
    public void EveryToken_NamesThePathItStandsFor(string token)
    {
        var entry = Assert.Single(AgentConfigPaths.All, p => p.Token == token);
        var parts = entry.Parts.ToList();

        if (entry.IsDirectory)
        {
            Assert.Contains(token, AgentConfigPaths.Named(["repo", .. parts, "x.md"], isFolder: false));
            Assert.Contains(token, AgentConfigPaths.Named(["repo", .. parts], isFolder: true));
            Assert.Contains(token, AgentConfigPaths.Named([.. parts.Select(p => p.ToUpperInvariant()), "sub", "y.json"], isFolder: false));
            Assert.DoesNotContain(token, AgentConfigPaths.Named(["repo", .. parts], isFolder: false));
        }
        else
        {
            Assert.Contains(token, AgentConfigPaths.Named(["repo", .. parts], isFolder: false));
            Assert.Contains(token, AgentConfigPaths.Named([.. parts.Select(p => p.ToUpperInvariant())], isFolder: false));
            Assert.DoesNotContain(token, AgentConfigPaths.Named(["repo", .. parts], isFolder: true));
        }
        Assert.Contains(token, AgentConfigPaths.Mentioned("cp x {solution}/" + string.Join('/', parts) + (entry.IsDirectory ? "/y" : "")));
    }

    [Theory]
    [InlineData(".claudette/notes.md")]
    [InlineData("my.mcp.json.bak")]
    [InlineData("XAGENTS.md")]
    [InlineData("AGENTS.md.txt")]
    [InlineData(".vscode/settings.json")]
    [InlineData(".vscode/tasks.json")]
    [InlineData(".github/workflows/ci.yml")]
    [InlineData(".github/CODEOWNERS")]
    [InlineData("claude/settings.json")]
    [InlineData("mcp.json")]
    [InlineData("docs/CLAUDE.mdx")]
    [InlineData(".cursorrules.bak")]
    public void ANearMiss_NamesNothing(string path)
    {
        var segments = AgentConfigPaths.Segments(path);

        Assert.Empty(AgentConfigPaths.Named(segments, isFolder: false));
        Assert.Empty(AgentConfigPaths.Named(segments, isFolder: true));
        Assert.Empty(AgentConfigPaths.Mentioned("copy a " + path));
    }

    [Theory]
    [InlineData("{project}/../.claude/skills", true, ".claude/")]
    [InlineData("{solution}/.vscode/mcp.json", false, ".vscode/mcp.json")]
    [InlineData("{solution}\\.github\\copilot-instructions.md", false, ".github/copilot-instructions.md")]
    [InlineData("{home}/.cursor/mcp.json", false, ".cursor/")]
    [InlineData("{solution}/agents.md", false, "AGENTS.md")]
    [InlineData("{solution}/.github/prompts", true, ".github/prompts/")]
    public void Named_MatchesOnSegments_CaseInsensitively(string path, bool isFolder, string token) =>
        Assert.Contains(token, AgentConfigPaths.Named(AgentConfigPaths.Segments(path), isFolder));

    /// <summary>Each segment as Windows creates it: trailing dots and spaces dropped, an NTFS stream suffix dropped (S4 review W4).</summary>
    [Theory]
    [InlineData(".claude./skills/x", false, ".claude/")]
    [InlineData(".claude /x", false, ".claude/")]
    [InlineData(".claude . ./x", false, ".claude/")]
    [InlineData("repo/CLAUDE.md::$DATA", false, "CLAUDE.md")]
    [InlineData("repo/AGENTS.md:evil", false, "AGENTS.md")]
    [InlineData("repo/.mcp.json.", false, ".mcp.json")]
    [InlineData(".vscode /mcp.json ", false, ".vscode/mcp.json")]
    [InlineData("repo/.cursor.", true, ".cursor/")]
    public void Named_MatchesEachSegmentAsWindowsNamesIt(string path, bool isFolder, string token)
    {
        Assert.Contains(token, AgentConfigPaths.Named(AgentConfigPaths.Segments(path), isFolder));
        if (!path.Contains(' '))
            Assert.Contains(token, AgentConfigPaths.Mentioned("cp x " + path));
    }

    [Theory]
    [InlineData("repo/CLAUDE.md.txt::$DATA")]
    [InlineData("repo/.claudex./x")]
    [InlineData("repo/x:CLAUDE.md")]
    [InlineData("repo/.mcp.json.bak.")]
    public void Named_AWindowsNameNearMiss_NamesNothing(string path)
    {
        Assert.Empty(AgentConfigPaths.Named(AgentConfigPaths.Segments(path), isFolder: false));
        Assert.Empty(AgentConfigPaths.Named(AgentConfigPaths.Segments(path), isFolder: true));
    }

    /// <summary>Windows separators too: a command's path is matched as written, before any normalization.</summary>
    [Fact]
    public void Segments_SplitsOnBothSeparators() =>
        Assert.Equal([".claude", "skills", "x.md"], AgentConfigPaths.Segments(".claude\\skills/x.md"));

    [Fact]
    public void TheReadme_MentionsEveryUnverifiedToken()
    {
        var readme = File.ReadAllText(Path.Combine(ResourceDir, "README.md"));

        var unverified = AgentConfigPaths.All.Where(p => p.Status == "unverified").ToList();

        Assert.NotEmpty(unverified);
        Assert.All(unverified, p => Assert.True(readme.Contains("`" + p.Token + "`", StringComparison.Ordinal), $"README.md does not mention {p.Token}"));
    }
    #endregion

    #region Methods: helpers
    // The source folder of the data file: the embedded copy is what loads, the folder's README is what records why.
    private static string ResourceDir
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            {
                var candidate = Path.Combine(dir.FullName, "src", "Silvergun.PackageAnalysis.NuGet", "Resources", "AgentConfig");
                if (Directory.Exists(candidate))
                    return candidate;
            }
            throw new DirectoryNotFoundException("the repository's src/Silvergun.PackageAnalysis.NuGet/Resources/AgentConfig");
        }
    }
    #endregion
}
