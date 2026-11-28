namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;
using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.Squats;

/// <summary>
/// <see cref="JobIntel.Gather"/> (task S5) over <see cref="FakeWeb"/>: project health (checked, noRepository, unavailable,
/// refused; the repository URL first, then the project URL), the bounded squat check (two nuget.org searches scored by
/// <see cref="SquatChecker"/>: checked with a planted neighbour, refused, unavailable, invalidId), the OSV status copied from the
/// report, package and remote strings wrapped as untrusted, and an output <see cref="JobArtifacts.ReadIntel"/> accepts within
/// <see cref="JobArtifacts.MaxIntelBytes"/>. Each Gather spaces its requests 1 s per host, so a test takes a second or two.
/// </summary>
public sealed class JobIntelTests
{
    #region Methods: health
    [Fact]
    public void Gather_WithAGitHubRepositoryUrl_ChecksHealth()
    {
        var web = new FakeWeb { GitHub = r => r.RequestUri!.AbsolutePath == "/repos/owner/repo" ? FakeWeb.Json(FakeWeb.Repo(stars: 4321)) : FakeWeb.Status(HttpStatusCode.NotFound) };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo.git"), web.Handler);

        Assert.Equal("checked", Str(intel["status"]));
        var health = intel["health"]!;
        Assert.Equal("checked", Str(health["status"]));
        Assert.Equal("owner", U(health["repository"]!["owner"]));
        Assert.Equal("repo", U(health["repository"]!["repo"]));
        Assert.Equal("repository", Str(health["repository"]!["from"]));
        Assert.Equal("github", Str(health["repository"]!["host"]));
        Assert.Equal(4321, health["stars"]!.GetValue<int>());
        Assert.Equal(56, health["forks"]!.GetValue<int>());
        Assert.Equal("MIT", U(health["license"]));
        Assert.False(health["archived"]!.GetValue<bool>());
        Assert.NotNull(Str(health["band"]));
        Assert.IsType<JsonArray>(health["redFlags"]);
        Assert.All(new[] { "activity", "popularity", "maturity", "overall" }, k => Assert.NotNull(health["scores"]![k]));
        Assert.Empty(web.Unexpected);
    }

    [Fact]
    public void Gather_WhenTheRepositoryUrlIsNotGitHub_UsesTheProjectUrl()
    {
        var web = new FakeWeb { GitHub = _ => FakeWeb.Json(FakeWeb.Repo()) };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://gitlab.example/owner/other", projectUrl: "https://github.com/proj/site"), web.Handler);

        var health = intel["health"]!;
        Assert.Equal("checked", Str(health["status"]));
        Assert.Equal("projectUrl", Str(health["repository"]!["from"]));
        Assert.Equal("proj", U(health["repository"]!["owner"]));
        Assert.Contains(web.Handler.Urls, u => u.Host == "api.github.com" && u.AbsolutePath == "/repos/proj/site");
    }

    [Fact]
    public void Gather_WithNoGitHubUrl_IsNoRepository_AndAsksGitHubNothing()
    {
        var web = new FakeWeb { GitHub = _ => throw new InvalidOperationException("GitHub must not be asked") };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://gitlab.example/a/b", projectUrl: "https://contoso.example/"), web.Handler);

        Assert.Equal("noRepository", Str(intel["health"]!["status"]));
        Assert.Null(intel["health"]!["repository"]);
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host == "api.github.com");
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public void Gather_WhenGitHubFails_HealthIsUnavailable_WithTheRepositoryStillNamed(HttpStatusCode status)
    {
        var web = new FakeWeb { GitHub = _ => FakeWeb.Status(status) };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), web.Handler);

        Assert.Equal("unavailable", Str(intel["health"]!["status"]));
        Assert.Equal("owner", U(intel["health"]!["repository"]!["owner"]));
        Assert.Empty(intel["refusals"]!.AsArray());
    }

    [Theory]
    [InlineData("403", "403")]
    [InlineData("429", "429")]
    [InlineData("challenge", "challenge")]
    public void Gather_WhenGitHubRefuses_HealthIsRefused_AndTheRefusalIsListed(string answer, string why)
    {
        var web = new FakeWeb
        {
            GitHub = _ => answer switch
            {
                "403" => FakeWeb.Status(HttpStatusCode.Forbidden),
                "429" => FakeWeb.Status(HttpStatusCode.TooManyRequests),
                _ => new HttpResponseMessage(HttpStatusCode.Accepted),
            },
        };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), web.Handler);

        Assert.Equal("refused", Str(intel["health"]!["status"]));
        var refusal = Assert.Single(intel["refusals"]!.AsArray());
        Assert.Equal("api.github.com", Str(refusal!["host"]));
        Assert.Equal(why, Str(refusal["why"]));
        Assert.Equal("checked", Str(intel["squat"]!["status"]));   // nuget.org is another host: not stopped
    }

    [Fact]
    public void Gather_SendsTheGitHubToken_OnlyToGitHub()
    {
        var auth = new List<(string Host, string? Scheme)>();
        var handler = new FakeHttp(r =>
        {
            lock (auth)
                auth.Add((r.RequestUri!.Host, r.Headers.Authorization?.Scheme));
            return r.RequestUri!.Host == "api.github.com" ? FakeWeb.Json(FakeWeb.Repo()) : FakeWeb.Json(r.RequestUri.AbsolutePath == "/v3/index.json" ? FakeWeb.GoodIndex : """{"data":[]}""");
        });

        S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), handler, token: "test-token-value");

        Assert.Contains(auth, a => a.Host == "api.github.com" && a.Scheme == "Bearer");
        Assert.All(auth.Where(a => a.Host != "api.github.com"), a => Assert.Null(a.Scheme));
    }
    #endregion

    #region Methods: squat
    [Fact]
    public void Gather_WithAPlantedPopularNeighbour_FindsTheSquat()
    {
        const string target = "Contoso.Widgets";
        var candidates = SquatCandidateGenerator.Generate(target);
        var planted = candidates[0].Name;
        var obscure = candidates[1].Name;
        var web = new FakeWeb
        {
            Exact = () => FakeWeb.Json(FakeWeb.Hits((target, 100))),
            // The planted neighbour; an obscure neighbour (under the floor); a popular package that is no neighbour.
            Neighbours = () => FakeWeb.Json(FakeWeb.Hits((planted, 1_000_000_000), (obscure, 50), ("Totally.Unrelated.Package", 2_000_000_000), (target, 100))),
        };

        var intel = S5.Gather(S5.Report(target), web.Handler);

        var squat = intel["squat"]!;
        Assert.Equal("checked", Str(squat["status"]));
        Assert.Equal("searchNeighbours", Str(squat["method"]));
        Assert.Equal(JobIntel.SearchTake, squat["searched"]!.GetValue<int>());
        Assert.Equal(4, squat["returned"]!.GetValue<int>());
        Assert.Equal(candidates.Count, squat["candidatesGenerated"]!.GetValue<int>());
        Assert.Equal(2, squat["candidatesSeen"]!.GetValue<int>());
        Assert.True(squat["targetListed"]!.GetValue<bool>());
        Assert.Equal(100, squat["targetDownloads"]!.GetValue<long>());
        var finding = Assert.Single(squat["findings"]!.AsArray());
        Assert.Equal(planted, U(finding!["candidate"]));
        Assert.Equal(1_000_000_000, finding["candidateDownloads"]!.GetValue<long>());
        Assert.Equal(candidates[0].Reason, U(finding["reason"]));
        Assert.Equal(JsonNamingPolicy.CamelCase.ConvertName(candidates[0].Mutator.ToString()), Str(finding["mutator"]));
        Assert.Equal(1, squat["findingsTotal"]!.GetValue<int>());

        // Two searches: the exact id, then the id as free text with take=100.
        var searches = web.Handler.Urls.Where(u => u.Host == FakeWeb.SearchHost).Select(u => Uri.UnescapeDataString(u.Query)).ToList();
        Assert.Equal(2, searches.Count);
        Assert.Contains("q=packageid:" + target, searches[0]);
        Assert.Contains("take=1&", searches[0]);
        Assert.Contains("q=" + target + "&", searches[1]);
        Assert.Contains($"take={JobIntel.SearchTake}&", searches[1]);
    }

    [Fact]
    public void Gather_WhenTheTargetIsNotListed_TargetListedIsFalse_AndAPopularNeighbourStillFlags()
    {
        const string target = "Contoso.Widgets";
        var planted = SquatCandidateGenerator.Generate(target)[0].Name;
        var web = new FakeWeb { Neighbours = () => FakeWeb.Json(FakeWeb.Hits((planted, 50_000))) };

        var squat = S5.Gather(S5.Report(target), web.Handler)["squat"]!;

        Assert.False(squat["targetListed"]!.GetValue<bool>());
        Assert.Null(squat["targetDownloads"]);
        Assert.Equal(planted, U(Assert.Single(squat["findings"]!.AsArray())!["candidate"]));
    }

    [Fact]
    public void Gather_AnEstablishedTargetNearAnotherPackage_HasNoFinding()
    {
        const string target = "Contoso.Widgets";
        var near = SquatCandidateGenerator.Generate(target)[0].Name;
        var web = new FakeWeb
        {
            Exact = () => FakeWeb.Json(FakeWeb.Hits((target, 900_000_000))),
            Neighbours = () => FakeWeb.Json(FakeWeb.Hits((near, 1_000_000_000))),   // popular, but not 10x the target
        };

        var squat = S5.Gather(S5.Report(target), web.Handler)["squat"]!;

        Assert.Equal("checked", Str(squat["status"]));
        Assert.Empty(squat["findings"]!.AsArray());
        Assert.Equal(0, squat["findingsTotal"]!.GetValue<int>());
        Assert.Equal(1, squat["candidatesSeen"]!.GetValue<int>());
    }

    [Fact]
    public void Gather_ManyFindings_AreCutToFive_WithTheTotalBeside_AndTheOutputFitsItsCap()
    {
        // A near-maximal id, every one of its candidates planted as hugely popular.
        var target = "Contoso." + string.Concat(Enumerable.Repeat("Widget.", 11)) + "Extensions";
        Assert.True(target.Length is > 90 and <= 100, $"{target.Length} chars");
        var candidates = SquatCandidateGenerator.Generate(target);
        Assert.True(candidates.Count > 10, $"{candidates.Count} candidates");
        var web = new FakeWeb { Neighbours = () => FakeWeb.Json(FakeWeb.Hits([.. candidates.Take(JobIntel.SearchTake).Select(c => (c.Name, (long?)1_000_000_000))])) };

        var intel = S5.Gather(S5.Report(target, repositoryUrl: "https://github.com/owner/repo"), web.Handler);

        var squat = intel["squat"]!;
        // 5 since S5 review round 1 (S3: the whole document must fit get_intel's page budget twice); 10 before.
        Assert.Equal(5, squat["findings"]!.AsArray().Count);
        Assert.Equal(Math.Min(candidates.Count, JobIntel.SearchTake), squat["findingsTotal"]!.GetValue<int>());
        var bytes = Encoding.UTF8.GetBytes(intel.ToJsonString(JobProtocol.JsonOptions));
        Assert.True(bytes.Length <= JobArtifacts.MaxIntelBytes, $"intel.json is {bytes.Length} bytes");
        AssertReadable(intel);
    }

    /// <summary>
    /// The largest document the child can write still fits <see cref="JobArtifacts.MaxIntelBytes"/>: every finding listed,
    /// the most and longest stopped hosts, a remote licence of characters that all escape, and every string at its cut.
    /// </summary>
    [Fact]
    public void Gather_TheLargestDocument_FitsTheIntelCap_AndEveryStringIsCut()
    {
        var target = "Contoso." + string.Concat(Enumerable.Repeat("Widget.", 11)) + "Extensions";
        var candidates = SquatCandidateGenerator.Generate(target);
        var stopped = Enumerable.Range(0, NetworkAccess.MaxStops).Select(i => $"h{i:D2}." + new string('a', 249)).ToList();
        Assert.All(stopped, h => Assert.Equal(253, h.Length));
        var hostile = string.Concat(Enumerable.Repeat("\\" + Hostile.Rlo + Hostile.Tag + "\"", 600));
        var web = new FakeWeb
        {
            GitHub = _ => FakeWeb.Json(FakeWeb.Repo(license: hostile)),
            Neighbours = () => FakeWeb.Json(FakeWeb.Hits([.. candidates.Take(JobIntel.SearchTake).Select(c => (c.Name, (long?)long.MaxValue))])),
        };

        var intel = S5.Gather(S5.Report(target, repositoryUrl: "https://github.com/" + new string('o', 39) + "/" + new string('r', 100),
            vulnerabilities: VulnerabilityScanStatus.Unavailable, vulnerabilityCount: 9), web.Handler, stopped);

        var bytes = Encoding.UTF8.GetBytes(intel.ToJsonString(JobProtocol.JsonOptions));
        Assert.True(bytes.Length <= JobArtifacts.MaxIntelBytes, $"intel.json is {bytes.Length} bytes, over {JobArtifacts.MaxIntelBytes}");
        Assert.Equal(NetworkAccess.MaxStops, intel["stoppedBefore"]!.AsArray().Count);
        // Each string is cut at 120 chars (with the suffix that describes the whole input), never served whole.
        Assert.Equal(stopped.Select(h => ToolEnvelope.Escaped(h, 120)), intel["stoppedBefore"]!.AsArray().Select(U));
        Assert.All(intel["stoppedBefore"]!.AsArray(), h => Assert.True(U(h)!.Length < 253, U(h)));
        Assert.Equal(ToolEnvelope.Escaped(hostile, 120), U(intel["health"]!["license"]));
        Hostile.AssertNoneRaw(intel.ToJsonString(JobProtocol.JsonOptions), "intel.json");
        AssertReadable(intel);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests, "429")]
    [InlineData(HttpStatusCode.Forbidden, "403")]
    public void Gather_WhenNuGetOrgRefuses_SquatIsRefused_AndNothingMoreIsSentThere(HttpStatusCode status, string why)
    {
        var web = new FakeWeb { Index = () => FakeWeb.Status(status) };

        var intel = S5.Gather(S5.Report("Contoso.Widgets"), web.Handler);

        Assert.Equal("refused", Str(intel["squat"]!["status"]));
        var refusal = Assert.Single(intel["refusals"]!.AsArray());
        Assert.Equal("api.nuget.org", Str(refusal!["host"]));
        Assert.Equal(why, Str(refusal["why"]));
        Assert.Single(web.Handler.Urls, u => u.Host.EndsWith("nuget.org", StringComparison.Ordinal));
        Assert.Equal(1, intel["requests"]!.GetValue<int>());
    }

    [Fact]
    public void Gather_WhenTheSearchItselfRefuses_SquatIsRefused()
    {
        var web = new FakeWeb { Exact = () => FakeWeb.Status(HttpStatusCode.TooManyRequests) };

        var intel = S5.Gather(S5.Report("Contoso.Widgets"), web.Handler);

        Assert.Equal("refused", Str(intel["squat"]!["status"]));
        Assert.Equal(FakeWeb.SearchHost, Str(Assert.Single(intel["refusals"]!.AsArray())!["host"]));
    }

    [Theory]
    [InlineData("index 500")]
    [InlineData("malformed index")]
    [InlineData("search 500")]
    [InlineData("neighbours malformed")]
    [InlineData("index off nuget.org")]
    public void Gather_WhenNuGetOrgFails_SquatIsUnavailable(string what)
    {
        var web = new FakeWeb();
        switch (what)
        {
            case "index 500": web.Index = () => FakeWeb.Status(HttpStatusCode.InternalServerError); break;
            case "malformed index": web.Index = () => FakeWeb.Json("{\"resources\":"); break;
            case "search 500": web.Exact = () => FakeWeb.Status(HttpStatusCode.InternalServerError); break;
            case "neighbours malformed": web.Neighbours = () => FakeWeb.Json("""{"data":7}"""); break;
            case "index off nuget.org": web.Index = () => FakeWeb.Json("""{"resources":[{"@id":"https://search.evil.test/query","@type":"SearchQueryService"}]}"""); break;
        }

        var intel = S5.Gather(S5.Report("Contoso.Widgets"), web.Handler);

        Assert.Equal("unavailable", Str(intel["squat"]!["status"]));
        Assert.Empty(intel["refusals"]!.AsArray());
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host == "search.evil.test");
        AssertReadable(intel);
    }

    [Theory]
    [InlineData("bad id with spaces")]
    [InlineData("../escape")]
    public void Gather_WithAnInvalidId_IsInvalidId_AndSearchesNothing(string id)
    {
        var web = new FakeWeb();

        var intel = S5.Gather(S5.Report(id), web.Handler);

        Assert.Equal("invalidId", Str(intel["squat"]!["status"]));
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host.EndsWith("nuget.org", StringComparison.Ordinal));
        AssertReadable(intel);
    }

    [Fact]
    public void Gather_WithAnOverlongId_IsInvalidId()
    {
        var web = new FakeWeb();

        var intel = S5.Gather(S5.Report(new string('a', 101)), web.Handler);

        Assert.Equal("invalidId", Str(intel["squat"]!["status"]));
        Assert.Equal(0, web.Handler.Calls);
    }
    #endregion

    #region Methods: S5 review round 1
    /// <summary>W1: an SSH URL whose owner or repo is "." or ".." names no repository, so no GitHub request (and no token) goes anywhere.</summary>
    [Theory]
    [InlineData("../user")]
    [InlineData("../meta")]
    [InlineData("owner/..")]
    public void Gather_AHostileSshRepositoryUrl_IsNoRepository_AndAsksGitHubNothing(string path)
    {
        var web = new FakeWeb { GitHub = _ => throw new InvalidOperationException("GitHub must not be asked") };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "git@" + "github.com:" + path, projectUrl: "git@" + "github.com:" + path), web.Handler, token: "test-token-value");

        Assert.Equal("noRepository", Str(intel["health"]!["status"]));
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host == "api.github.com");
    }

    /// <summary>W2: a redirect (a renamed repository) is not followed; health reads unavailable.</summary>
    [Fact]
    public void Gather_ARedirectFromGitHub_IsUnavailable_AndNotFollowed()
    {
        var web = new FakeWeb
        {
            GitHub = _ =>
            {
                var moved = FakeWeb.Status(HttpStatusCode.MovedPermanently);
                moved.Headers.Location = new Uri("https://api.github.com/user");
                return moved;
            },
        };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), web.Handler);

        Assert.Equal("unavailable", Str(intel["health"]!["status"]));
        Assert.Single(web.Handler.Urls, u => u.Host == "api.github.com");
        Assert.True(NetworkAccess.DefaultHandler() is SocketsHttpHandler { AllowAutoRedirect: false }, "the real transport follows redirects");
    }

    [Fact]
    public void Gather_HostsStoppedBefore_AreNeverAsked_AndAreListedAsUntrusted()
    {
        var web = new FakeWeb { GitHub = _ => throw new InvalidOperationException("GitHub must not be asked") };

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), web.Handler, ["api.github.com", "api.nuget.org"]);

        Assert.Equal("refused", Str(intel["health"]!["status"]));
        Assert.Equal("refused", Str(intel["squat"]!["status"]));   // the index host was stopped before this job
        Assert.Equal(0, web.Handler.Calls);
        Assert.Equal(0, intel["requests"]!.GetValue<int>());
        Assert.Empty(intel["refusals"]!.AsArray());   // this job's own refusals: none
        Assert.Equal(new string?[] { "api.github.com", "api.nuget.org" }, intel["stoppedBefore"]!.AsArray().Select(U));
        AssertReadable(intel);
    }

    [Fact]
    public void Gather_WithNothingStoppedBefore_HasNoStoppedBefore()
    {
        var intel = S5.Gather(S5.Report("Contoso.Widgets"), new FakeWeb().Handler);

        Assert.False(intel.ContainsKey("stoppedBefore"));
    }

    [Fact]
    public void Gather_ASearchHostStoppedBefore_MakesSquatRefused()
    {
        var web = new FakeWeb();

        var intel = S5.Gather(S5.Report("Contoso.Widgets"), web.Handler, [FakeWeb.SearchHost]);

        Assert.Equal("refused", Str(intel["squat"]!["status"]));
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host == FakeWeb.SearchHost);
    }

    /// <summary>Review suggestion: a fault in one part costs that part only.</summary>
    [Fact]
    public void Gather_AFaultInTheSquatPart_IsUnavailableFault_AndHealthIsUnaffected()
    {
        var web = new FakeWeb { GitHub = _ => FakeWeb.Json(FakeWeb.Repo()) };
        var report = S5.Report("x", repositoryUrl: "https://github.com/owner/repo");
        report = report with { Package = report.Package with { Id = null! } };   // the squat check cannot read a null id

        var intel = S5.Gather(report, web.Handler);

        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"unavailable","why":"fault"}"""), intel["squat"]), intel["squat"]!.ToJsonString());
        Assert.Equal("checked", Str(intel["health"]!["status"]));
        AssertReadable(intel);
    }

    [Fact]
    public void Gather_AFaultInBothParts_IsTwoFaults_AndStillADocument()
    {
        var report = S5.Report("x") with { Package = null! };

        var intel = S5.Gather(report, new FakeWeb().Handler);

        Assert.Equal("fault", Str(intel["health"]!["why"]));
        Assert.Equal("fault", Str(intel["squat"]!["why"]));
        Assert.Equal("checked", Str(intel["status"]));
        AssertReadable(intel);
    }
    #endregion

    #region Methods: the whole document
    [Theory]
    [InlineData(VulnerabilityScanStatus.NotChecked, 0, "notChecked")]
    [InlineData(VulnerabilityScanStatus.Completed, 3, "completed")]
    [InlineData(VulnerabilityScanStatus.Completed, 0, "completed")]
    [InlineData(VulnerabilityScanStatus.Unavailable, 0, "unavailable")]
    [InlineData(VulnerabilityScanStatus.Unavailable, 2, "unavailable")]
    public void Gather_CopiesTheVulnerabilityStatus_AndACountOnlyWhenCompleted(VulnerabilityScanStatus status, int count, string expected)
    {
        var intel = S5.Gather(S5.Report("Contoso.Widgets", vulnerabilities: status, vulnerabilityCount: count), new FakeWeb().Handler);

        var vulnerabilities = intel["vulnerabilities"]!;
        Assert.Equal(expected, Str(vulnerabilities["status"]));
        // S5 review W5: a count is a fact only when the check completed (re-pinned: Unavailable once read 0); a partial
        // check says what it saw as partialCount, and only when it saw something.
        if (status == VulnerabilityScanStatus.Completed)
            Assert.Equal(count, vulnerabilities["count"]!.GetValue<int>());
        else
            Assert.Null(vulnerabilities["count"]);
        if (status == VulnerabilityScanStatus.Unavailable && count > 0)
            Assert.Equal(count, vulnerabilities["partialCount"]!.GetValue<int>());
        else
            Assert.False(vulnerabilities.AsObject().ContainsKey("partialCount"));
    }

    [Fact]
    public void Gather_DatesItself_AndCountsItsRequests()
    {
        var web = new FakeWeb { GitHub = _ => FakeWeb.Json(FakeWeb.Repo()) };
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);

        var intel = S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), web.Handler);

        var fetchedAt = DateTimeOffset.Parse(Str(intel["fetchedAt"])!);
        Assert.True(fetchedAt >= before && fetchedAt <= DateTimeOffset.UtcNow.AddSeconds(1), $"fetchedAt {fetchedAt:O}");
        Assert.EndsWith("Z", Str(intel["fetchedAt"]));
        Assert.Equal(web.Handler.Calls, intel["requests"]!.GetValue<int>());
        Assert.Equal(4, web.Handler.Calls);   // GitHub, the index, two searches
        AssertReadable(intel);
    }

    /// <summary>Remote text (a licence from GitHub) and package text (the repository owner, the squat candidate) are wrapped and escaped.</summary>
    [Fact]
    public void Gather_RemoteAndPackageStrings_AreUntrusted_AndCarryNoRawHostileCharacter()
    {
        const string target = "Contoso.Widgets";
        var planted = SquatCandidateGenerator.Generate(target)[0].Name;
        var web = new FakeWeb
        {
            GitHub = _ => FakeWeb.Json(FakeWeb.Repo(license: Hostile.Mix)),
            Neighbours = () => FakeWeb.Json(FakeWeb.Hits((planted, 1_000_000_000))),
        };

        var intel = S5.Gather(S5.Report(target, repositoryUrl: "https://github.com/owner/repo"), web.Handler);

        var health = intel["health"]!;
        Assert.IsType<JsonObject>(health["license"]);
        Assert.IsType<JsonObject>(health["repository"]!["owner"]);
        Assert.IsType<JsonObject>(health["repository"]!["repo"]);
        var finding = intel["squat"]!["findings"]![0]!;
        Assert.IsType<JsonObject>(finding["candidate"]);
        Assert.IsType<JsonObject>(finding["reason"]);
        var license = U(health["license"])!;
        Assert.StartsWith("x", license, StringComparison.Ordinal);   // the text is kept, escaped
        Assert.Contains("UNTRUSTED", license, StringComparison.Ordinal);
        foreach (var text in S5.UntrustedStrings(intel))
            Hostile.AssertNoneRaw(text, "intel");
        Hostile.AssertNoneRaw(intel.ToJsonString(JobProtocol.JsonOptions), "intel.json");
    }

    [Fact]
    public void Gather_WhenCancelled_Throws()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            S5.Gather(S5.Report("Contoso.Widgets", repositoryUrl: "https://github.com/owner/repo"), new FakeWeb().Handler, ct: cancelled.Token));
    }

    [Fact]
    public void NotChecked_IsTheStatusAlone_AndReadable()
    {
        var intel = JobIntel.NotChecked();

        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"status":"notChecked"}"""), intel));
        AssertReadable(intel);
    }
    #endregion

    #region Methods: helpers
    internal static string? Str(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    internal static string? U(JsonNode? node) => node is JsonObject o ? Str(o["untrusted"]) : null;

    private static void AssertReadable(JsonObject intel)
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "intel-" + Guid.NewGuid().ToString("N"))).FullName;
        try
        {
            JobArtifacts.WriteAtomic(dir, JobProtocol.IntelFile, Encoding.UTF8.GetBytes(intel.ToJsonString(JobProtocol.JsonOptions)));
            var (read, problem) = JobArtifacts.ReadIntel(dir);
            Assert.True(read is not null, problem);
            Assert.True(JsonNode.DeepEquals(intel, read));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
    #endregion
}

/// <summary>
/// <see cref="JobArtifacts.ReadIntel"/> (schema 5): <c>{"status":"notChecked"}</c>, or <c>checked</c> with vulnerabilities, health
/// and squat objects that each have a status; anything else, a missing file, or one over its cap, is a problem.
/// </summary>
public sealed class ReadIntelTests : IDisposable
{
    #region Methods
    [Fact]
    public void ReadIntel_AcceptsACheckedDocument()
    {
        Write(Checked().ToJsonString());

        var (intel, problem) = JobArtifacts.ReadIntel(dir);

        Assert.Null(problem);
        Assert.Equal("checked", JobIntelTests.Str(intel!["status"]));
    }

    public static TheoryData<string> Bad() =>
    [
        "missing", "not JSON", "an array", "no status", "an unknown status", "a status that is a number", "checked without squat",
        "checked without health", "checked without vulnerabilities", "a part without its status", "a part that is a string", "over its cap",
    ];

    [Theory]
    [MemberData(nameof(Bad))]
    public void ReadIntel_RefusesAnyOtherShape(string what)
    {
        var intel = Checked();
        string? text = what switch
        {
            "missing" => null,
            "not JSON" => "{\"status\":",
            "an array" => "[]",
            "no status" => Change(intel, i => i.Remove("status")),
            "an unknown status" => Change(intel, i => i["status"] = "maybe"),
            "a status that is a number" => Change(intel, i => i["status"] = 1),
            "checked without squat" => Change(intel, i => i.Remove("squat")),
            "checked without health" => Change(intel, i => i.Remove("health")),
            "checked without vulnerabilities" => Change(intel, i => i.Remove("vulnerabilities")),
            "a part without its status" => Change(intel, i => i["health"]!.AsObject().Remove("status")),
            "a part that is a string" => Change(intel, i => i["squat"] = "checked"),
            "over its cap" => Change(intel, i => i["pad"] = new string(' ', (int)JobArtifacts.MaxIntelBytes)),
            _ => throw new ArgumentException(what),
        };
        if (text is not null)
            Write(text);

        var (read, problem) = JobArtifacts.ReadIntel(dir);

        Assert.Null(read);
        Assert.False(string.IsNullOrWhiteSpace(problem), what);
    }

    [Fact]
    public void MaxIntelBytes_Is16KiB() => Assert.Equal(16 * 1024, JobArtifacts.MaxIntelBytes);   // 64 KiB before S5 review round 1 (S3)

    public void Dispose()
    {
        try { Directory.Delete(dir, recursive: true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    #endregion

    #region Methods: helpers
    private static JsonObject Checked() => new()
    {
        ["status"] = "checked",
        ["vulnerabilities"] = new JsonObject { ["status"] = "notChecked", ["count"] = null },
        ["health"] = new JsonObject { ["status"] = "noRepository" },
        ["squat"] = new JsonObject { ["status"] = "invalidId" },
        ["requests"] = 0,
        ["refusals"] = new JsonArray(),
    };

    private static string Change(JsonObject intel, Action<JsonObject> change)
    {
        change(intel);
        return intel.ToJsonString();
    }

    private void Write(string text) => File.WriteAllText(Path.Combine(dir, JobProtocol.IntelFile), text);
    #endregion

    #region Fields
    private readonly string dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests", "readintel-" + Guid.NewGuid().ToString("N"))).FullName;
    #endregion
}

/// <summary>
/// <see cref="NuGetDownload"/> (task S5): the identity check and its normalization, the download over <see cref="FakeWeb"/>
/// (404, success hashed as it streams, an over-cap or failing body deleted, a refusal named, an index pointing off nuget.org),
/// and the download record's round trip and its refusal of a tampered record.
/// </summary>
public sealed class NuGetDownloadTests : IDisposable
{
    #region Methods: check
    [Theory]
    [InlineData("Newtonsoft.Json", "13.0.3-Beta+abc", "newtonsoft.json", "13.0.3-beta")]
    [InlineData("Newtonsoft.Json", "13.0.3", "newtonsoft.json", "13.0.3")]
    [InlineData(" Contoso.Widgets ", " 1.0 ", "contoso.widgets", "1.0.0")]
    [InlineData("a_b-c.D", "1.2.3.4", "a_b-c.d", "1.2.3.4")]
    [InlineData("x", "01.002.0003", "x", "1.2.3")]
    [InlineData("x", "1.0.0-RC.1.Alpha", "x", "1.0.0-rc.1.alpha")]
    public void Check_AcceptsAndNormalizes(string id, string version, string expectedId, string expectedVersion)
    {
        var (lowerId, lowerVersion, problem) = NuGetDownload.Check(id, version);

        Assert.Null(problem);
        Assert.Equal(expectedId, lowerId);
        Assert.Equal(expectedVersion, lowerVersion);
    }

    [Fact]
    public void Check_AcceptsAHundredCharId() => Assert.Null(NuGetDownload.Check(new string('a', 100), "1.0.0").Problem);

    public static TheoryData<string?, string?> BadIdentities() => new()
    {
        { null, "1.0.0" },
        { "", "1.0.0" },
        { "   ", "1.0.0" },
        { "bad id", "1.0.0" },
        { "../escape", "1.0.0" },
        { "a/b", "1.0.0" },
        { "a\\b", "1.0.0" },
        { ".leading", "1.0.0" },
        { "x" + (char)0x202E + "y", "1.0.0" },
        { new string('a', 101), "1.0.0" },
        { "ok.id", null },
        { "ok.id", "" },
        { "ok.id", "not-a-version" },
        { "ok.id", "1.0.0/../x" },
        { "ok.id", "1." + new string('1', 63) },
        { "ok.id", "1.0.0 1" },
        { "N" + (char)0x0435 + "wtonsoft.Json", "13.0.3" },   // a Cyrillic homoglyph (S5 review S6)
        { "Newtonsoft" + (char)0x00E9 + ".Json", "13.0.3" },
        { "Newtonsoft.Js" + (char)0x0301 + "on", "13.0.3" },   // a combining mark
    };

    [Theory]
    [MemberData(nameof(BadIdentities))]
    public void Check_RefusesABadIdOrVersion(string? id, string? version)
    {
        var (lowerId, lowerVersion, problem) = NuGetDownload.Check(id, version);

        Assert.Null(lowerId);
        Assert.Null(lowerVersion);
        Assert.False(string.IsNullOrWhiteSpace(problem));
    }
    #endregion

    #region Methods: fetch
    [Fact]
    public async Task FetchAsync_Downloads_AndHashesTheBytesItWrote()
    {
        var bytes = PackageBytes();
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) } };
        var (http, polite) = Client(web);
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.True(status == ToolStatus.Succeeded, problem);
        Assert.Null(problem);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), source!.Sha256);
        Assert.Equal(bytes.Length, source.Bytes);
        Assert.Equal(bytes, File.ReadAllBytes(Destination));
        Assert.Equal("contoso.widgets", source.Id);
        Assert.Equal("1.0.0", source.Version);
        Assert.Equal(FakeWeb.FlatContainer + "contoso.widgets/1.0.0/contoso.widgets.1.0.0.nupkg", source.Url);
        Assert.True(source.FetchedAt >= before);
        Assert.Equal(new[] { new Uri(NuGetSearchClient.DefaultServiceIndex), new Uri(source.Url) }, web.Handler.Urls);
    }

    [Fact]
    public async Task FetchAsync_UsesTheGivenServiceIndexUrl()
    {
        var handler = new FakeHttp(r => r.RequestUri!.Host == "index.example.test"
            ? FakeWeb.Json(FakeWeb.GoodIndex)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(PackageBytes()) });
        using var http = new HttpClient(handler);

        var (source, status, _) = await NuGetDownload.FetchAsync(http, null, "contoso.widgets", "1.0.0", Destination, CancellationToken.None, "https://index.example.test/v3/index.json");

        Assert.Equal(ToolStatus.Succeeded, status);
        Assert.NotNull(source);
        Assert.Equal(new Uri("https://index.example.test/v3/index.json"), handler.Urls[0]);
    }

    [Fact]
    public async Task FetchAsync_A404_IsNotFound_AndLeavesNoFile()
    {
        var (http, polite) = Client(new FakeWeb());

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "9.9.9", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.NotFound, status);
        Assert.Contains("contoso.widgets 9.9.9", problem);
        Assert.False(File.Exists(Destination));
    }

    [Fact]
    public async Task FetchAsync_ADeclaredSizeOverTheCap_IsFailed_AndLeavesNoFile()
    {
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new DeclaredOnly(PackageInput.MaxPackageBytes + 1) } };
        var (http, polite) = Client(web);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Contains("IOException", problem);
        Assert.False(File.Exists(Destination));
    }

    [Fact]
    public async Task FetchAsync_ABodyThatFailsMidStream_IsFailed_AndDeletesThePartialFile()
    {
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new FailingStream(4096)) } };
        var (http, polite) = Client(web);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Contains("IOException", problem);
        Assert.False(File.Exists(Destination), "the partial download was left behind");
    }

    [Fact]
    public async Task FetchAsync_TooFewBytes_IsFailed_AndDeletesTheFile()
    {
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[21]) } };
        var (http, polite) = Client(web);

        var (source, status, _) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.False(File.Exists(Destination));
    }

    [Fact]
    public async Task FetchAsync_ARefusal_IsFailed_NamesTheRefusal_AndTheNextFetchSendsNothing()
    {
        var web = new FakeWeb { Package = _ => FakeWeb.Status(HttpStatusCode.TooManyRequests) };
        var (http, polite) = Client(web);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Contains("429", problem);
        Assert.Contains("api.nuget.org refused", problem);
        Assert.False(File.Exists(Destination));
        var calls = web.Handler.Calls;

        var again = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "2.0.0", Destination, CancellationToken.None);

        Assert.Equal(ToolStatus.Failed, again.Status);
        Assert.Contains("refused", again.Problem);
        Assert.Equal(calls, web.Handler.Calls);   // the stopped host was sent nothing
    }

    [Fact]
    public async Task FetchAsync_AnIndexWhosePackageAddressIsOffNuGetOrg_IsFailed_AndThatHostIsNeverAsked()
    {
        var web = new FakeWeb { Index = () => FakeWeb.Json("""{"resources":[{"@id":"https://packages.evil.test/flat/","@type":"PackageBaseAddress/3.0.0"},{"@id":"http://api.nuget.org/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}""") };
        var (http, polite) = Client(web);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Contains("service index", problem);
        Assert.Equal(1, web.Handler.Calls);
        Assert.Empty(web.Unexpected);
        Assert.False(File.Exists(Destination));
    }

    [Fact]
    public async Task FetchAsync_ATransportFailure_IsFailed()
    {
        var handler = new FakeHttp(r => r.RequestUri!.AbsolutePath == "/v3/index.json" ? FakeWeb.Json(FakeWeb.GoodIndex) : throw new HttpRequestException("socket"));
        using var http = new HttpClient(handler);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, null, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Contains("HttpRequestException", problem);
        Assert.False(File.Exists(Destination));
    }

    /// <summary>W6: a caller cancelling mid-stream gets the cancellation, and the partial file is gone.</summary>
    [Fact]
    public async Task FetchAsync_CancelledAfterTheFirstChunk_Throws_AndDeletesThePartialFile()
    {
        using var cts = new CancellationTokenSource();
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new ScriptedStream(4096, () => cts.Cancel())) } };
        var (http, polite) = Client(web);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, cts.Token));

        Assert.True(cts.IsCancellationRequested);
        Assert.False(File.Exists(Destination), "the partial download was left behind");
    }

    /// <summary>W6: an unexpected fault is a Failed value, never a throw, and the partial file is gone.</summary>
    [Fact]
    public async Task FetchAsync_AnUnexpectedFaultMidStream_IsFailed_AndDeletesThePartialFile()
    {
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new ScriptedStream(4096, () => throw new NotSupportedException("odd"))) } };
        var (http, polite) = Client(web);

        var (source, status, problem) = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None);

        Assert.Null(source);
        Assert.Equal(ToolStatus.Failed, status);
        Assert.Contains("NotSupportedException", problem);
        Assert.False(File.Exists(Destination), "the partial download was left behind");
    }

    [Fact]
    public async Task FetchAsync_UsesAGivenIndexClient_WithoutReadingTheIndexAgain()
    {
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(PackageBytes()) } };
        var (http, polite) = Client(web);
        var index = new NuGetSearchClient(http);
        Assert.NotNull(await index.ResourceAsync(NuGetSearchClient.PackageBaseAddressType));

        var first = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, CancellationToken.None, index: index);
        File.Delete(Destination);
        var second = await NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "2.0.0", Destination, CancellationToken.None, index: index);

        Assert.Equal(ToolStatus.Succeeded, first.Status);
        Assert.Equal(ToolStatus.Succeeded, second.Status);
        Assert.Single(web.Handler.Urls, u => u.AbsolutePath == "/v3/index.json");
    }

    [Fact]
    public async Task FetchAsync_WhenCancelled_Throws()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var (http, polite) = Client(new FakeWeb());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NuGetDownload.FetchAsync(http, polite, "contoso.widgets", "1.0.0", Destination, cancelled.Token));
    }
    #endregion

    #region Methods: record
    [Fact]
    public void RecordAndRecorded_RoundTrip()
    {
        var source = Source();

        NuGetDownload.Record(dirs.Cache, source);

        Assert.Equal(source, NuGetDownload.Recorded(dirs.Cache, source.Id, source.Version));
        Assert.True(File.Exists(RecordPath(source.Id, source.Version)));
        Assert.Null(NuGetDownload.Recorded(dirs.Cache, source.Id, "2.0.0"));
        Assert.Null(NuGetDownload.Recorded(dirs.Cache, "other.id", source.Version));
    }

    [Fact]
    public void Recorded_WithNoRecord_IsNull() => Assert.Null(NuGetDownload.Recorded(dirs.Cache, "contoso.widgets", "1.0.0"));

    public static TheoryData<string> Tampering() =>
    [
        "another id", "another version", "schema 2", "an uppercase sha", "a short sha", "no sha", "zero bytes", "no url", "not JSON", "over 4 KiB", "null",
    ];

    [Theory]
    [MemberData(nameof(Tampering))]
    public void Recorded_RefusesATamperedRecord(string what)
    {
        var source = Source();
        NuGetDownload.Record(dirs.Cache, source);
        var path = RecordPath(source.Id, source.Version);
        var record = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var text = what switch
        {
            "another id" => Change(record, r => r["id"] = "evil.id"),
            "another version" => Change(record, r => r["version"] = "6.6.6"),
            "schema 2" => Change(record, r => r["schema"] = 2),
            "an uppercase sha" => Change(record, r => r["sha256"] = source.Sha256.ToUpperInvariant()),
            "a short sha" => Change(record, r => r["sha256"] = source.Sha256[..63]),
            "no sha" => Change(record, r => r.Remove("sha256")),
            "zero bytes" => Change(record, r => r["bytes"] = 0),
            "no url" => Change(record, r => r.Remove("url")),
            "not JSON" => "{\"schema\":",
            "over 4 KiB" => Change(record, r => r["pad"] = new string(' ', 5000)),
            "null" => "null",
            _ => throw new ArgumentException(what),
        };
        File.WriteAllText(path, text);

        Assert.Null(NuGetDownload.Recorded(dirs.Cache, source.Id, source.Version));
    }

    public void Dispose() => dirs.Dispose();
    #endregion

    #region Methods: helpers
    private string Destination => Path.Combine(dirs.Base, "incoming.nupkg");

    private static (HttpClient Http, PoliteHttpHandler Polite) Client(FakeWeb web)
    {
        var polite = new PoliteHttpHandler(web.Handler, TimeSpan.Zero);
        return (new HttpClient(polite), polite);
    }

    private static byte[] PackageBytes() => [.. Enumerable.Range(0, 10_000).Select(i => (byte)(i * 31 % 251))];

    private static NuGetSource Source() =>
        new(1, "contoso.widgets", "1.0.0", new string('a', 64), 1234, FakeWeb.FlatContainer + "contoso.widgets/1.0.0/contoso.widgets.1.0.0.nupkg", DateTimeOffset.UtcNow);

    private string RecordPath(string id, string version) =>
        Path.Combine(dirs.Cache, "nuget", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(id + "/" + version))) + ".json");

    private static string Change(JsonObject record, Action<JsonObject> change)
    {
        change(record);
        return record.ToJsonString();
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion

    #region Types
    // Declares `length` bytes and never sends any: the cap must refuse it from the header.
    private sealed class DeclaredOnly(long length) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) => throw new InvalidOperationException("the body must not be read");

        protected override bool TryComputeLength(out long length1)
        {
            length1 = length;
            return true;
        }
    }

    // `first` bytes, then `then` runs and the stream goes on with `first` more bytes each read.
    private sealed class ScriptedStream(int first, Action then) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => reads; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (reads++ > 0)
                then();
            var n = Math.Min(count, first);
            Array.Fill(buffer, (byte)'P', offset, n);
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private int reads;
    }

    // `good` bytes, then an IOException.
    private sealed class FailingStream(int good) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (position >= good)
                throw new IOException("the connection dropped");
            var n = (int)Math.Min(count, good - position);
            Array.Fill(buffer, (byte)'P', offset, n);
            position += n;
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private long position;
    }
    #endregion
}
