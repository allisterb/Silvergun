namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using NuGet.Packaging;

using Silvergun.Intel;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Squats;

/// <summary>
/// The job child's network intel (task S5), written to <c>intel.json</c>: the source project's health (GitHub, from the
/// nuspec's repository or project URL), a bounded squat check (two nuget.org searches scored by <see cref="SquatChecker"/>),
/// and the OSV status the scan already has. Every request goes through one <see cref="PoliteHttpHandler"/>. Each part has
/// its own status beside its numbers (D10); package and remote strings are <c>{"untrusted": …}</c>. Never throws except to
/// honour cancellation.
/// </summary>
public static class JobIntel
{
    #region Methods
    /// <summary>The <c>intel.json</c> of a job that may not use the network.</summary>
    public static JsonObject NotChecked() => new() { ["status"] = "notChecked" };

    /// <summary>
    /// Gathers intel for <paramref name="report"/> over the job's one client <paramref name="http"/> and its handler
    /// <paramref name="polite"/> (which also carried the scan's OSV requests, so <c>requests</c> and <c>refusals</c> count them),
    /// within <see cref="Budget"/>. <paramref name="stoppedBefore"/>: hosts the server had already seen refuse.
    /// </summary>
    public static JsonObject Gather(PackageCapabilityReport report, HttpClient http, PoliteHttpHandler polite, IReadOnlyList<string> stoppedBefore, string? githubToken,
        CancellationToken ct = default)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(Budget);
        var fetchedAt = DateTimeOffset.UtcNow;
        var health = Part(() => HealthAsync(report.Package, http, polite, githubToken, budget.Token), ct);
        var squat = Part(() => SquatAsync(report.Package.Id, http, polite, stoppedBefore, budget.Token), ct);
        var vulns = report.VulnerabilitiesStatus;

        var intel = new JsonObject
        {
            ["status"] = "checked",
            ["fetchedAt"] = fetchedAt.UtcDateTime.ToString("O"),
            ["vulnerabilities"] = new JsonObject
            {
                ["status"] = Camel(vulns.ToString()),
                // A count is a fact only when the check completed (D10); a partial one says what it saw beside the status.
                ["count"] = vulns == VulnerabilityScanStatus.Completed ? report.Vulnerabilities.Count : null,
            },
            ["health"] = health,
            ["squat"] = squat,
            ["requests"] = polite.Requests,
            ["refusals"] = new JsonArray([.. polite.Refusals.Select(r => (JsonNode)new JsonObject { ["host"] = r.Host, ["why"] = r.Why })]),
        };
        if (vulns == VulnerabilityScanStatus.Unavailable && report.Vulnerabilities.Count > 0)
            intel["vulnerabilities"]!["partialCount"] = report.Vulnerabilities.Count;
        if (stoppedBefore.Count > 0)
            intel["stoppedBefore"] = new JsonArray([.. stoppedBefore.Take(NetworkAccess.MaxStops).Select(h => (JsonNode)U(h))]);
        return intel;
    }

    // One part of the intel, on its own: running out of budget, or any fault, costs that part only and says so.
    private static JsonObject Part(Func<Task<JsonObject>> part, CancellationToken ct)
    {
        try
        {
            return part().GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new JsonObject { ["status"] = "unavailable", ["why"] = "budget" };
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            Runtime.Warn("job worker: an intel part failed ({0}).", ex.GetType().Name);
            return new JsonObject { ["status"] = "unavailable", ["why"] = "fault" };
        }
    }

    private static async Task<JsonObject> HealthAsync(PackageIdentityInfo package, HttpClient http, PoliteHttpHandler polite, string? token, CancellationToken ct)
    {
        RepositoryRef? repo = null;
        string? from = null;
        foreach (var (url, name) in new[] { (package.RepositoryUrl, "repository"), (package.ProjectUrl, "projectUrl") })
            if (GitHubRepoUrl.TryParse(url, out var parsed))
            {
                (repo, from) = (parsed, name);
                break;
            }
        if (repo is null)
            return new JsonObject { ["status"] = "noRepository" };

        var health = await new GitHubProjectHealthSource(token, http).GetHealthAsync(repo, ct);
        var result = new JsonObject
        {
            ["repository"] = new JsonObject { ["host"] = "github", ["owner"] = U(repo.Owner), ["repo"] = U(repo.Repo), ["from"] = from },
        };
        if (health is null)
        {
            result["status"] = polite.Refused(GitHubHost) ? "refused" : "unavailable";
            return result;
        }
        result["status"] = "checked";
        result["stars"] = health.Stars;
        result["forks"] = health.Forks;
        result["subscribers"] = health.Subscribers;
        result["openIssues"] = health.OpenIssues;
        result["createdAt"] = health.CreatedAt?.UtcDateTime.ToString("O");
        result["pushedAt"] = health.PushedAt?.UtcDateTime.ToString("O");
        result["license"] = health.License is { } license ? U(license) : null;
        result["archived"] = health.Archived;
        result["disabled"] = health.Disabled;
        result["scores"] = new JsonObject
        {
            ["activity"] = health.ActivityScore,
            ["popularity"] = health.PopularityScore,
            ["maturity"] = health.MaturityScore,
            ["overall"] = health.OverallScore,
        };
        result["band"] = Camel(health.Band.ToString());
        result["redFlags"] = new JsonArray([.. health.RedFlags.Select(f => (JsonNode)f)]);
        return result;
    }

    private static async Task<JsonObject> SquatAsync(string packageId, HttpClient http, PoliteHttpHandler polite, IReadOnlyList<string> stoppedBefore, CancellationToken ct)
    {
        if (packageId.Length > MaxIdChars || !PackageIdValidator.IsValidPackageId(packageId))
            return new JsonObject { ["status"] = "invalidId" };
        var search = new NuGetSearchClient(http);
        var (ok, target) = await search.ExactAsync(packageId, ct);
        var neighbours = ok ? await search.SearchAsync(packageId, SearchTake, ct) : null;
        if (!ok || neighbours is null)
            return new JsonObject { ["status"] = polite.Refusals.Select(r => r.Host).Concat(stoppedBefore).Any(IsNuGetHost) ? "refused" : "unavailable" };

        var candidates = SquatCandidateGenerator.Generate(packageId);
        var names = candidates.Select(c => c.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var seen = neighbours.Where(h => names.Contains(h.Id)).GroupBy(h => h.Id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().TotalDownloads, StringComparer.OrdinalIgnoreCase);
        var checker = await new SquatChecker(new SeenPopularity(packageId, target?.TotalDownloads, seen)).CheckAsync(packageId, ct);
        if (!checker.IsSuccess)
            return new JsonObject { ["status"] = "unavailable" };
        var findings = checker.Value;
        return new JsonObject
        {
            ["status"] = "checked",
            ["method"] = "searchNeighbours",
            ["searched"] = SearchTake,
            ["returned"] = neighbours.Count,
            ["candidatesGenerated"] = candidates.Count,
            ["candidatesSeen"] = seen.Count,
            ["targetListed"] = target is not null,
            ["targetDownloads"] = target?.TotalDownloads,
            ["findings"] = new JsonArray([.. findings.Take(MaxFindings).Select(f => (JsonNode)new JsonObject
            {
                ["candidate"] = U(f.SquattedCandidate),
                ["candidateDownloads"] = f.CandidateDownloads,
                ["mutator"] = Camel(f.Mutator.ToString()),
                ["reason"] = U(f.Reason),
            })]),
            ["findingsTotal"] = findings.Count,
        };
    }

    private static bool IsNuGetHost(string host) => host == "nuget.org" || host.EndsWith(".nuget.org", StringComparison.Ordinal);

    private static JsonObject U(string text) => ToolEnvelope.Untrusted(text, MaxChars);

    private static string Camel(string name) => JsonNamingPolicy.CamelCase.ConvertName(name);
    #endregion

    #region Fields
    /// <summary>The whole intel stage's wall clock.</summary>
    public static readonly TimeSpan Budget = TimeSpan.FromSeconds(120);

    /// <summary>How many free-text search results the squat check scores.</summary>
    public const int SearchTake = 100;

    private const string GitHubHost = "api.github.com";
    private const int MaxIdChars = 100;
    // Sized so the whole document fits get_intel's page budget, carried twice, even with every char escaped (S5 review S3).
    private const int MaxFindings = 5;
    private const int MaxChars = 120;
    #endregion

    #region Types
    // Popularity from the two searches only: the target's, and the candidates the free-text search returned; any other is unknown.
    private sealed class SeenPopularity(string target, long? targetDownloads, IReadOnlyDictionary<string, long?> seen) : IPackagePopularitySource
    {
        public Task<PackagePopularity?> GetPopularityAsync(string packageId, CancellationToken ct = default) =>
            Task.FromResult<PackagePopularity?>(
                string.Equals(packageId, target, StringComparison.OrdinalIgnoreCase) ? new PackagePopularity(targetDownloads)
                : seen.TryGetValue(packageId, out var downloads) ? new PackagePopularity(downloads)
                : null);
    }
    #endregion
}
