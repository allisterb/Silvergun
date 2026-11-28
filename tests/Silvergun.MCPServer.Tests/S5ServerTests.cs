namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.CodeAnalysis.IL;
using Silvergun.Intel;
using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// The S5 acceptance with the network off: <c>analyze_package {id, version}</c> and <c>get_intel</c> refuse with
/// <c>NotPermitted</c> before anything is checked, and the network handler is never created (no socket). Also the argument
/// rules every server applies: path or id and version, never both, never neither.
/// </summary>
public sealed class S5NetworkOffTests : IDisposable
{
    #region Constructors
    public S5NetworkOffTests() => factory = new CountingFactory(web.Handler);
    #endregion

    #region Methods
    public static TheoryData<string?, string?> Identities() => new()
    {
        { "Newtonsoft.Json", "13.0.3" },
        { "bad id with spaces", "13.0.3" },   // refused before the id is checked
        { "Newtonsoft.Json", null },
        { null, "13.0.3" },
    };

    [Theory]
    [MemberData(nameof(Identities))]
    public async Task AnalyzePackage_ById_WithTheNetworkOff_IsNotPermitted_AndCreatesNoHandler(string? id, string? version)
    {
        var (_, jobs, _, access) = S5.Server(dirs, network: false, factory, S5.NoLaunch);

        var result = await jobs.AnalyzePackage(id: id, version: version);

        Assert.True(result.IsError, InProcess.Text(result));
        Assert.Equal("NotPermitted", Drill.Status(result));
        Assert.False(Drill.S(result).GetProperty("retry").GetBoolean());
        Assert.Contains("--no-network", Drill.S(result).GetProperty("message").GetString());
        AssertNoSocket(access);
        Assert.False(Directory.Exists(Path.Combine(dirs.Cache, "nuget")), "a download record was written");
    }

    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000-standard")]
    [InlineData("../not-a-job")]
    public void GetIntel_WithTheNetworkOff_IsNotPermitted_AndCreatesNoHandler(string jobId)
    {
        var (_, _, drill, access) = S5.Server(dirs, network: false, factory, S5.NoLaunch);

        var result = drill.GetIntel(jobId);

        Assert.True(result.IsError);
        Assert.Equal("NotPermitted", Drill.Status(result));
        Assert.Equal(JobManager.NetworkOff, Drill.S(result).GetProperty("message").GetString());
        AssertNoSocket(access);
    }

    [Fact]
    public async Task SubmitPackageAsync_WithTheNetworkOff_IsNotPermitted()
    {
        var (manager, _, _, access) = S5.Server(dirs, network: false, factory, S5.NoLaunch);

        var (view, source, downloaded, status, problem) = await manager.SubmitPackageAsync("newtonsoft.json", "13.0.3", JobDepth.Standard, CancellationToken.None);

        Assert.Null(view);
        Assert.Null(source);
        Assert.False(downloaded);
        Assert.Equal(ToolStatus.NotPermitted, status);
        Assert.Equal(JobManager.NetworkOff, problem);
        AssertNoSocket(access);
    }

    [Fact]
    public void NetworkAccess_WhenOff_ThrowsOnClient_AndNeverCallsItsFactory()
    {
        var access = new NetworkAccess(false, factory.Create);

        Assert.Throws<InvalidOperationException>(() => access.Client());
        Assert.False(access.Enabled);
        AssertNoSocket(access);
    }

    [Fact]
    public void NetworkAccess_WhenOn_CreatesOneClientLazily_OverThePoliteHandler()
    {
        var access = new NetworkAccess(true, factory.Create);
        Assert.Equal(0, access.HandlersCreated);
        Assert.Null(access.Polite);

        var first = access.Client();
        var second = access.Client();

        Assert.Same(first, second);
        Assert.Equal(1, access.HandlersCreated);
        Assert.Equal(1, factory.Calls);
        Assert.NotNull(access.Polite);
        Assert.Equal(TimeSpan.FromSeconds(1), access.Polite!.MinInterval);
        Assert.Equal(NetworkAccess.RequestTimeout, first.Timeout);
    }

    [Fact]
    public void JobManager_TakesItsNetworkFromTheSettings_WhenNoneIsGiven()
    {
        Assert.False(new JobManager(S5.Settings(dirs, network: false), S5.NoLaunch).Network.Enabled);
        Assert.True(new JobManager(S5.Settings(dirs, network: true), S5.NoLaunch).Network.Enabled);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnalyzePackage_PathAndId_IsInvalidArgument(bool network)
    {
        var (_, jobs, _, access) = S5.Server(dirs, network, factory, S5.NoLaunch);
        var package = Fixtures.Small(dirs.Root);

        foreach (var (id, version) in new (string?, string?)[] { ("mcp.small", "1.0.0"), ("mcp.small", null), (null, "1.0.0") })
        {
            var result = await jobs.AnalyzePackage(package, id: id, version: version);

            Assert.Equal("InvalidArgument", Drill.Status(result));
            Assert.Contains("not both", Drill.S(result).GetProperty("message").GetString());
        }
        AssertNoSocket(access);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnalyzePackage_NeitherPathNorId_IsInvalidArgument(bool network)
    {
        var (_, jobs, _, access) = S5.Server(dirs, network, factory, S5.NoLaunch);

        var result = await jobs.AnalyzePackage();

        Assert.Equal("InvalidArgument", Drill.Status(result));
        Assert.Contains("path, or id and version", Drill.S(result).GetProperty("message").GetString());
        AssertNoSocket(access);
    }

    [Theory]
    [InlineData("bad id", "1.0.0")]
    [InlineData("ok.id", "not.a.version")]
    [InlineData("ok.id", null)]
    [InlineData(null, "1.0.0")]
    public async Task AnalyzePackage_ABadIdentity_WithTheNetworkOn_IsInvalidArgument_AndSendsNothing(string? id, string? version)
    {
        var (_, jobs, _, access) = S5.Server(dirs, network: true, factory, S5.NoLaunch);

        var result = await jobs.AnalyzePackage(id: id, version: version);

        Assert.Equal("InvalidArgument", Drill.Status(result));
        AssertNoSocket(access);
    }

    public void Dispose() => dirs.Dispose();
    #endregion

    #region Methods: helpers
    private void AssertNoSocket(NetworkAccess access)
    {
        Assert.Equal(0, access.HandlersCreated);
        Assert.Equal(0, factory.Calls);
        Assert.Equal(0, web.Handler.Calls);
        Assert.Null(access.Polite);
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    private readonly FakeWeb web = new();
    private readonly CountingFactory factory;
    #endregion
}

/// <summary>
/// <c>analyze_package {id, version}</c> and <c>get_intel</c> with the network on, over <see cref="FakeWeb"/>: a download is
/// recorded and queued (its children are a <see cref="FakeChild"/>, which never reaches a network); a repeat whose entry is
/// complete is served with no request; a refusal stops the host for the server's lifetime; get_intel serves the entry's
/// <c>intel.json</c> and refuses a corrupt one.
/// </summary>
public sealed class S5NetworkOnTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>, IDisposable
{
    #region Methods
    [Fact]
    public async Task AnalyzePackage_ById_DownloadsRecordsAndQueuesAJob()
    {
        var bytes = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("source")));
        var web = new FakeWeb { Package = r => r.RequestUri!.AbsolutePath == "/v3-flatcontainer/mcp.small/1.0.0/mcp.small.1.0.0.nupkg"
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }
            : FakeWeb.Status(HttpStatusCode.NotFound) };
        var factory = new CountingFactory(web.Handler);
        var child = new FakeChild(dirs, [FakeChild.Ready], exitCode: JobProtocol.ExitFatal);
        var (manager, jobs, _, access) = S5.Server(dirs, network: true, factory, child.Launch);
        var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));

        var result = await jobs.AnalyzePackage(id: "MCP.Small", version: "1.0.0");

        var s = Drill.S(result);
        Assert.True(s.GetProperty("ok").GetBoolean(), s.ToString());
        Assert.Contains(Drill.Status(result), new[] { "Queued", "Running" });
        Assert.Equal(JobManager.JobId(sha, JobDepth.Standard), s.GetProperty("jobId").GetString());
        Assert.True(s.GetProperty("downloaded").GetBoolean());
        var source = s.GetProperty("source");
        Assert.Equal("nuget.org", source.GetProperty("registry").GetString());
        Assert.Equal("mcp.small", source.GetProperty("id").GetString());
        Assert.Equal("1.0.0", source.GetProperty("version").GetString());
        Assert.Equal(FakeWeb.FlatContainer + "mcp.small/1.0.0/mcp.small.1.0.0.nupkg", source.GetProperty("url").GetProperty("untrusted").GetString());
        Assert.EndsWith("Z", source.GetProperty("fetchedAt").GetString());
        Assert.Equal(1, access.HandlersCreated);
        Assert.Equal(2, web.Handler.Calls);   // the index, then the package
        Assert.Empty(web.Unexpected);
        var recorded = NuGetDownload.Recorded(dirs.Cache, "mcp.small", "1.0.0");
        Assert.Equal(sha, recorded?.Sha256);
        Assert.Equal(bytes.Length, recorded!.Bytes);

        await InProcess.WaitToEndAsync(manager, s.GetProperty("jobId").GetString()!);
        child.AssertAllGone();
    }

    [Fact]
    public async Task AnalyzePackage_ById_ARepeatWithACompletedEntry_SendsNoRequest()
    {
        var jobId = NetEntry();
        var bytes = File.ReadAllBytes(fixture.Package);
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) } };
        var (_, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), S5.NoLaunch);

        var first = Drill.S(await jobs.AnalyzePackage(id: "mcp.small", version: "1.0.0"));

        Assert.Equal("Succeeded", first.GetProperty("status").GetString());
        Assert.Equal(jobId, first.GetProperty("jobId").GetString());
        Assert.True(first.GetProperty("downloaded").GetBoolean());   // downloaded now, then found in the cache
        Assert.True(first.GetProperty("cached").GetBoolean());
        var calls = web.Handler.Calls;
        Assert.Equal(2, calls);

        var again = Drill.S(await jobs.AnalyzePackage(id: "Mcp.Small", version: "1.0.0"));

        Assert.Equal("Succeeded", again.GetProperty("status").GetString());
        Assert.Equal(jobId, again.GetProperty("jobId").GetString());
        Assert.False(again.TryGetProperty("downloaded", out _), again.ToString());
        Assert.True(again.GetProperty("cached").GetBoolean());
        Assert.Equal(first.GetProperty("source").GetProperty("fetchedAt").GetString(), again.GetProperty("source").GetProperty("fetchedAt").GetString());
        Assert.Equal(calls, web.Handler.Calls);   // no request at all
    }

    /// <summary>A recorded download whose entry is complete is served by a fresh server without creating its handler.</summary>
    [Fact]
    public async Task AnalyzePackage_ById_ARecordedCompleteEntry_IsServedByANewServer_WithNoHandler()
    {
        var jobId = NetEntry();
        NuGetDownload.Record(dirs.Cache, new NuGetSource(1, "mcp.small", "1.0.0", fixture.Sha256, new FileInfo(fixture.Package).Length,
            FakeWeb.FlatContainer + "mcp.small/1.0.0/mcp.small.1.0.0.nupkg", DateTimeOffset.UtcNow.AddDays(-1)));
        var web = new FakeWeb();
        var (_, jobs, _, access) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), S5.NoLaunch);

        var result = Drill.S(await jobs.AnalyzePackage(id: "mcp.small", version: "1.0.0"));

        Assert.Equal("Succeeded", result.GetProperty("status").GetString());
        Assert.Equal(jobId, result.GetProperty("jobId").GetString());
        Assert.False(result.TryGetProperty("downloaded", out _));
        Assert.Equal(0, access.HandlersCreated);
        Assert.Equal(0, web.Handler.Calls);
    }

    [Fact]
    public async Task AnalyzePackage_ById_A404_IsNotFound()
    {
        var web = new FakeWeb();
        var (_, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), S5.NoLaunch);

        var result = await jobs.AnalyzePackage(id: "no.such.package", version: "1.0.0");

        Assert.True(result.IsError);
        Assert.Equal("NotFound", Drill.Status(result));
        Assert.Null(NuGetDownload.Recorded(dirs.Cache, "no.such.package", "1.0.0"));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dirs.Cache, "incoming")));
    }

    [Fact]
    public async Task AnalyzePackage_ById_ARefusal_IsFailed_AndTheServerSendsThatHostNothingMore()
    {
        var web = new FakeWeb { Package = _ => FakeWeb.Status(HttpStatusCode.TooManyRequests) };
        var (_, jobs, _, access) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), S5.NoLaunch);

        var first = await jobs.AnalyzePackage(id: "contoso.widgets", version: "1.0.0");

        Assert.True(first.IsError);
        Assert.Equal("Failed", Drill.Status(first));
        Assert.Contains("refused", Drill.S(first).GetProperty("message").GetString());
        var calls = web.Handler.Calls;

        var second = await jobs.AnalyzePackage(id: "contoso.other", version: "2.0.0");

        Assert.Equal("Failed", Drill.Status(second));
        Assert.Equal(calls, web.Handler.Calls);
        Assert.Equal([("api.nuget.org", "429")], access.Polite!.Refusals);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dirs.Cache, "incoming")));
    }

    [Fact]
    public async Task GetIntel_ServesTheEntrysIntel_AndRefusesACorruptOne()
    {
        var jobId = NetEntry();
        var entry = Path.Combine(dirs.Cache, fixture.Sha256, JobStore.EntryName(JobDepth.Standard, network: true));
        var web = new FakeWeb { GitHub = _ => FakeWeb.Json(FakeWeb.Repo(stars: 77)) };
        var (_, _, drill, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), S5.NoLaunch);

        // The offline entry's copy says notChecked.
        var notChecked = Drill.Checked(drill.GetIntel(jobId));
        Assert.Equal("Succeeded", Drill.Status(notChecked));
        Assert.Equal("notChecked", Drill.S(notChecked).GetProperty("intel").GetProperty("status").GetString());
        Assert.Equal(jobId, Drill.S(notChecked).GetProperty("jobId").GetString());

        // As a networked child would have written it.
        var gathered = S5.Gather(S5.Report("mcp.small", repositoryUrl: "https://github.com/owner/repo"), web.Handler);
        JobArtifacts.WriteAtomic(entry, JobProtocol.IntelFile, Encoding.UTF8.GetBytes(gathered.ToJsonString(JobProtocol.JsonOptions)));
        var served = Drill.Checked(drill.GetIntel(jobId));
        Assert.Equal("Succeeded", Drill.Status(served));
        var intel = JsonNode.Parse(Drill.S(served).GetProperty("intel").GetRawText())!;
        Assert.True(JsonNode.DeepEquals(gathered, intel), intel.ToJsonString());
        Assert.Equal(77, intel["health"]!["stars"]!.GetValue<int>());

        File.WriteAllText(Path.Combine(entry, JobProtocol.IntelFile), """{"status":"checked"}""");
        var corrupt = drill.GetIntel(jobId);
        // An unusable entry is not served (as for any other artifact, it is NotFound to Find, and re-run by analyze_package).
        Assert.True(corrupt.IsError);
        Assert.Contains(Drill.Status(corrupt), new[] { "NotFound", "Failed" });
        Assert.False(Drill.S(corrupt).TryGetProperty("intel", out _));
    }

    [Fact]
    public void GetIntel_ForAnUnknownJob_IsNotFound()
    {
        var (_, _, drill, _) = S5.Server(dirs, network: true, new CountingFactory(new FakeWeb().Handler), S5.NoLaunch);

        Assert.Equal("NotFound", Drill.Status(drill.GetIntel(new string('0', 64) + "-standard")));
        Assert.Equal("InvalidArgument", Drill.Status(drill.GetIntel("../job")));
    }

    public void Dispose() => dirs.Dispose();
    #endregion

    #region Methods: helpers
    // The fixture's offline entry, copied under the networked name and recorded as networked; its jobId.
    private string NetEntry()
    {
        fixture.CopyInto(dirs);
        var netEntry = Path.Combine(dirs.Cache, fixture.Sha256, JobStore.EntryName(JobDepth.Standard, network: true));
        Fixtures.CopyDirectory(fixture.EntryIn(dirs), netEntry);
        var jobFile = Path.Combine(netEntry, JobProtocol.JobFile);
        var record = JsonNode.Parse(File.ReadAllText(jobFile))!.AsObject();
        record["network"] = true;
        File.WriteAllText(jobFile, record.ToJsonString());
        return fixture.JobId;
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion
}

/// <summary>
/// <see cref="JobWorker.Run(string?, Stream, Stream, JobScan, Action, Func{HttpMessageHandler}?)"/> in-process (task S5 and its
/// review round 1): a request without network gives the scan no client, writes <c>{"status":"notChecked"}</c> and never calls
/// the handler factory; one with network builds one polite client, seeded with the request's stopped hosts and spaced at its
/// interval, which the scan (OSV) and the intel stage share. The request's new fields are checked. The scan is a stand-in (a
/// nuspec-only package): no assembly is read.
/// </summary>
public sealed class S5WorkerTests : IDisposable
{
    #region Methods
    [Fact]
    public void Run_WithoutNetwork_GivesTheScanNoClient_WritesNotChecked_AndNeverCallsTheFactory()
    {
        var web = new FakeWeb();
        var factory = new CountingFactory(web.Handler);
        var dir = JobDir();
        HttpClient? given = null;
        var scanned = false;

        var (exit, records) = Run(dir, network: false, factory, scan: http => { (given, scanned) = (http, true); });

        Assert.Equal(JobProtocol.ExitDone, exit);
        Assert.True(scanned);
        Assert.Null(given);
        Assert.Equal(0, factory.Calls);
        Assert.Equal(0, web.Handler.Calls);
        var (intel, problem) = JobArtifacts.ReadIntel(dir);
        Assert.True(intel is not null, problem);
        Assert.True(JsonNode.DeepEquals(JobIntel.NotChecked(), intel));
        Assert.DoesNotContain("intel", Stages(records));
    }

    [Fact]
    public void Run_WithNetwork_GivesTheScanTheJobsClient_AndRunsTheIntelStage_ThroughTheFactory()
    {
        var web = new FakeWeb { GitHub = _ => FakeWeb.Json(FakeWeb.Repo(stars: 9)) };
        var factory = new CountingFactory(web.Handler);
        var dir = JobDir();
        HttpClient? given = null;

        var (exit, records) = Run(dir, network: true, factory, scan: http => given = http);

        Assert.True(exit == JobProtocol.ExitDone, string.Join("\n", records));
        Assert.NotNull(given);
        Assert.Equal(1, factory.Calls);
        var (intel, problem) = JobArtifacts.ReadIntel(dir);
        Assert.True(intel is not null, problem);
        Assert.Equal("checked", JobIntelTests.Str(intel!["status"]));
        Assert.Equal("checked", JobIntelTests.Str(intel["health"]!["status"]));
        Assert.Equal(9, intel["health"]!["stars"]!.GetValue<int>());
        Assert.Equal("checked", JobIntelTests.Str(intel["squat"]!["status"]));
        Assert.Equal(web.Handler.Calls, intel["requests"]!.GetValue<int>());
        Assert.False(intel.ContainsKey("stoppedBefore"));
        Assert.Contains("intel", Stages(records));
        Assert.Empty(web.Unexpected);
        Assert.Null(JobArtifacts.MissingArtifact(dir));
    }

    /// <summary>C1: the scan's OSV requests go through the job's polite client, so a refusal stops that host and intel names it.</summary>
    [Fact]
    public void Run_AnOsvRefusalInTheScan_StopsThatHost_AndIntelCountsAndNamesIt()
    {
        var osvCalls = 0;
        var web = new FakeWeb
        {
            Other = r => r.RequestUri!.Host == "api.osv.dev" ? Counted(ref osvCalls, FakeWeb.Status(HttpStatusCode.TooManyRequests)) : null,
        };
        var factory = new CountingFactory(web.Handler);
        var dir = JobDir();
        var statuses = new List<HttpStatusCode>();

        var (exit, records) = Run(dir, network: true, factory, scan: http =>
        {
            for (var i = 0; i < 3; i++)
            {
                using var response = http!.PostAsync("https://api.osv.dev/v1/querybatch", new StringContent("{}")).GetAwaiter().GetResult();
                statuses.Add(response.StatusCode);
            }
        });

        Assert.True(exit == JobProtocol.ExitDone, string.Join("\n", records));
        Assert.Equal(1, Volatile.Read(ref osvCalls));
        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.TooManyRequests, s));
        var intel = JobArtifacts.ReadIntel(dir).Intel!;
        var refusal = Assert.Single(intel["refusals"]!.AsArray());
        Assert.Equal("api.osv.dev", JobIntelTests.Str(refusal!["host"]));
        Assert.Equal("429", JobIntelTests.Str(refusal["why"]));
        Assert.Equal(web.Handler.Calls, intel["requests"]!.GetValue<int>());   // the OSV request is counted with intel's
        Assert.Contains(web.Handler.Urls, u => u.Host == "api.github.com");   // other hosts are still asked
    }

    /// <summary>W4: hosts the server already saw refuse are never asked by the child, and intel lists them as stoppedBefore.</summary>
    [Fact]
    public void Run_SeededStoppedHosts_AreNeverAsked_AndAreListedAsStoppedBefore()
    {
        var web = new FakeWeb { GitHub = _ => throw new InvalidOperationException("GitHub must not be asked") };
        var factory = new CountingFactory(web.Handler);
        var dir = JobDir();
        HttpStatusCode? osv = null;

        var (exit, records) = Run(dir, network: true, factory, stoppedHosts: ["api.github.com", "api.osv.dev"], scan: http =>
        {
            using var response = http!.GetAsync("https://api.osv.dev/v1/vulns/x").GetAwaiter().GetResult();
            osv = response.StatusCode;
        });

        Assert.True(exit == JobProtocol.ExitDone, string.Join("\n", records));
        Assert.Equal(HttpStatusCode.TooManyRequests, osv);
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host is "api.github.com" or "api.osv.dev");
        var intel = JobArtifacts.ReadIntel(dir).Intel!;
        Assert.Equal("refused", JobIntelTests.Str(intel["health"]!["status"]));
        Assert.Equal("checked", JobIntelTests.Str(intel["squat"]!["status"]));
        Assert.Equal(new string?[] { "api.github.com", "api.osv.dev" }, intel["stoppedBefore"]!.AsArray().Select(JobIntelTests.U));
        Assert.Empty(intel["refusals"]!.AsArray());
    }

    /// <summary>Round 2: a seeded host matches whatever its case, as the handler's own lookups are lowercased.</summary>
    [Fact]
    public void Run_SeededStoppedHosts_MatchInAnyCase()
    {
        var web = new FakeWeb { GitHub = _ => throw new InvalidOperationException("GitHub must not be asked") };
        var dir = JobDir();

        var (exit, records) = Run(dir, network: true, new CountingFactory(web.Handler), stoppedHosts: ["API.GitHub.COM"]);

        Assert.True(exit == JobProtocol.ExitDone, string.Join("\n", records));
        Assert.DoesNotContain(web.Handler.Urls, u => u.Host == "api.github.com");
        Assert.Equal("refused", JobIntelTests.Str(JobArtifacts.ReadIntel(dir).Intel!["health"]!["status"]));
    }

    [Fact]
    public void Run_SpacesRequestsAtTheRequestsInterval()
    {
        var web = new FakeWeb();
        var dir = JobDir();
        var at = new List<long>();

        var (exit, _) = Run(dir, network: true, new CountingFactory(web.Handler), minIntervalMs: 300, scan: http =>
        {
            for (var i = 0; i < 3; i++)
            {
                http!.GetAsync("https://api.nuget.org/v3/index.json").GetAwaiter().GetResult().Dispose();
                at.Add(Stopwatch.GetTimestamp());
            }
        });

        Assert.Equal(JobProtocol.ExitDone, exit);
        for (var i = 1; i < at.Count; i++)
            Assert.True(Stopwatch.GetElapsedTime(at[i - 1], at[i]) >= TimeSpan.FromMilliseconds(280), $"requests {i - 1} and {i} were {Stopwatch.GetElapsedTime(at[i - 1], at[i]).TotalMilliseconds:0} ms apart");
    }

    public static TheoryData<string, string> BadRequests() => new()
    {
        { "an interval under 0", """{"minIntervalMs":-1}""" },
        { "an interval over 60 s", """{"minIntervalMs":60001}""" },
        { "65 stopped hosts", "{\"stoppedHosts\":[" + string.Join(",", Enumerable.Range(0, 65).Select(i => $"\"h{i}.test\"")) + "]}" },
        { "a null stopped host", """{"stoppedHosts":["a.test",null]}""" },
        { "an empty stopped host", """{"stoppedHosts":[""]}""" },
        { "a 254-char stopped host", "{\"stoppedHosts\":[\"" + new string('h', 254) + "\"]}" },
    };

    [Theory]
    [MemberData(nameof(BadRequests))]
    public void Run_ARequestWithBadNetworkFields_IsOneFatal_BeforeAnythingIsScannedOrCreated(string what, string fields)
    {
        var factory = new CountingFactory(new FakeWeb().Handler);
        var dir = JobDir();
        var request = JsonNode.Parse(JsonSerializer.Serialize(new JobRequest(JobProtocol.Version, dir, JobDepth.Standard, true), JobProtocol.JsonOptions))!.AsObject();
        foreach (var (key, value) in JsonNode.Parse(fields)!.AsObject().ToList())
            request[key] = value?.DeepClone();

        var (exit, records) = RunRaw(request.ToJsonString(), factory, (_, _, _, _, _) => throw new InvalidOperationException($"{what}: the scan must not run"));

        Assert.Equal(JobProtocol.ExitFatal, exit);
        var fatal = JsonNode.Parse(Assert.Single(records))!;
        Assert.Equal("fatal", JobIntelTests.Str(fatal["type"]));
        Assert.DoesNotContain("the scan must not run", JobIntelTests.Str(fatal["reason"]));
        Assert.Equal(0, factory.Calls);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(60_000, 64)]
    public void Run_TheBoundaryNetworkFields_AreAccepted(int minIntervalMs, int hosts)
    {
        var web = new FakeWeb();
        var dir = JobDir();
        var stopped = Enumerable.Range(0, hosts).Select(i => i == 0 ? new string('h', 253) : $"h{i}.test").ToList();
        var scanned = false;

        // Every intel host is stopped or unasked, so the 60 s spacing is never waited out.
        var (exit, records) = Run(dir, network: true, new CountingFactory(web.Handler), stoppedHosts: hosts > 0 ? [.. stopped.Take(61), "api.nuget.org", FakeWeb.SearchHost, "api.github.com"] : null,
            minIntervalMs: minIntervalMs, scan: _ => scanned = true);

        Assert.True(exit == JobProtocol.ExitDone, string.Join("\n", records));
        Assert.True(scanned);
    }

    public void Dispose() => dirs.Dispose();
    #endregion

    #region Methods: helpers
    private string JobDir()
    {
        var dir = dirs.NewDir("job-" + Guid.NewGuid().ToString("N")[..8]);
        File.Copy(Fixtures.Nupkg(dirs.NewDir("pkg-" + Guid.NewGuid().ToString("N")[..8]), "mcp.intel"), Path.Combine(dir, JobProtocol.PackageFile));
        return dir;
    }

    private static HttpResponseMessage Counted(ref int calls, HttpResponseMessage response)
    {
        Interlocked.Increment(ref calls);
        return response;
    }

    // The scan stand-in: runs `scan` with the client it was given, extracts the package and reports it with a GitHub repository.
    private static JobScan Scan(Action<HttpClient?> scan) => (nupkg, files, depth, network, progress) =>
    {
        scan(network);
        ZipFile.ExtractToDirectory(nupkg, files);
        var report = S5.Report("mcp.intel", repositoryUrl: "https://github.com/owner/repo");
        return Result.Success(new JobScanOutput(report, report.ToJson(), new JobGate(0, 0, [], true, []), new HashSet<IndicatorCategory>()));
    };

    private static (int Exit, List<string> Records) Run(string dir, bool network, CountingFactory factory, Action<HttpClient?>? scan = null,
        IReadOnlyList<string>? stoppedHosts = null, int minIntervalMs = 0) =>
        RunRaw(JsonSerializer.Serialize(new JobRequest(JobProtocol.Version, dir, JobDepth.Standard, network, stoppedHosts, minIntervalMs), JobProtocol.JsonOptions),
            factory, Scan(scan ?? (_ => { })));

    private static (int Exit, List<string> Records) RunRaw(string requestLine, CountingFactory factory, JobScan scan)
    {
        using var stdin = new MemoryStream(Encoding.UTF8.GetBytes(requestLine + "\n"));
        using var stdout = new MemoryStream();
        var exit = JobWorker.Run(JobProtocol.Version.ToString(), stdin, stdout, scan, () => { }, factory.Create);
        return (exit, [.. Encoding.UTF8.GetString(stdout.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries)]);
    }

    private static List<string> Stages(List<string> records) =>
        [.. records.Select(r => JsonNode.Parse(r)!).Where(r => JobIntelTests.Str(r["type"]) == "done")
            .SelectMany(r => r["stages"]!.AsArray().Select(s => JobIntelTests.Str(s!["stage"])!))];
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion
}

/// <summary>
/// The server side of S5 review round 1: <see cref="NetworkAccess"/>'s transport and stop set; <see cref="JobManager"/> refusing a
/// network access that disagrees with its settings, learning a finished job's refusals, sending the next child its stopped hosts
/// and spacing, joining a download whose job is in flight, one download per package and two at a time, and one service-index
/// read per server. Every handler is a <see cref="FakeWeb"/>; children are scripted and never reach a network.
/// </summary>
public sealed class S5ReviewServerTests(CompletedEntryFixture fixture) : IClassFixture<CompletedEntryFixture>, IDisposable
{
    #region Methods: NetworkAccess
    [Fact]
    public void DefaultHandler_FollowsNoRedirect_AndKeepsNoCookies()
    {
        using var handler = NetworkAccess.DefaultHandler();

        var sockets = Assert.IsType<SocketsHttpHandler>(handler);
        Assert.False(sockets.AllowAutoRedirect);
        Assert.False(sockets.UseCookies);
        Assert.Equal(TimeSpan.FromSeconds(15), sockets.ConnectTimeout);
    }

    [Fact]
    public void Stop_RecordsWellFormedHostsLowercased_AndIgnoresTheRest()
    {
        var access = new NetworkAccess(true, new CountingFactory(new FakeWeb().Handler).Create);

        access.Stop("API.NuGet.org", "429");
        access.Stop("api.github.com", "403");
        access.Stop("api.github.com", "challenge");   // the first reason stays
        foreach (var bad in new[] { "", "bad host", "a/b", "x" + (char)0x202E + "y", "h:443", new string('h', 254), ((char)0x0430) + "pi.test" })
            access.Stop(bad, "429");

        Assert.Equal(new[] { "api.github.com", "api.nuget.org" }, access.StoppedHosts);
        Assert.Equal(0, access.HandlersCreated);   // stopping a host creates no client
    }

    [Fact]
    public void Stop_IsIgnoredPastMaxStops()
    {
        var access = new NetworkAccess(true);

        for (var i = 0; i < NetworkAccess.MaxStops + 10; i++)
            access.Stop($"h{i:D3}.test", "429");

        Assert.Equal(64, NetworkAccess.MaxStops);
        Assert.Equal(NetworkAccess.MaxStops, access.StoppedHosts.Count);
        Assert.Contains("h000.test", access.StoppedHosts);
        Assert.DoesNotContain($"h{NetworkAccess.MaxStops:D3}.test", access.StoppedHosts);
    }

    [Fact]
    public async Task AStoppedHost_IsSentNothing_ByTheServersOwnDownloads()
    {
        var web = new FakeWeb();
        var (manager, jobs, _, access) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), S5.NoLaunch);
        access.Stop("api.nuget.org", "429");

        var result = await jobs.AnalyzePackage(id: "contoso.widgets", version: "1.0.0");

        Assert.Equal("Failed", Drill.Status(result));
        Assert.Contains("api.nuget.org refused an earlier job's request", Drill.S(result).GetProperty("message").GetString());
        Assert.Equal(0, web.Handler.Calls);
        Assert.True(access.Polite!.Refused("api.nuget.org"));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dirs.Cache, "incoming")));
        Assert.Null(NuGetDownload.Recorded(manager.Store.Root, "contoso.widgets", "1.0.0"));
    }
    #endregion

    #region Methods: JobManager
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void JobManager_RefusesANetworkAccessThatDisagreesWithTheSettings(bool settingsNetwork, bool accessEnabled)
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new JobManager(S5.Settings(dirs, settingsNetwork), S5.NoLaunch, network: new NetworkAccess(accessEnabled)));

        Assert.Equal("network", error.ParamName);
    }

    /// <summary>W4: a finished job's refusals join the server's stop set, and the next child is told them, spaced for every job at once.</summary>
    [WindowsFact]
    public async Task AFinishedJobsRefusals_AreLearned_AndSentToTheNextChild_WithTheScaledSpacing()
    {
        var child = new ArtifactChild(dirs, FixtureEntry, ArtifactChild.Intel(("api.github.com", "403"), ("bad host!", "429"), ("API.OSV.dev", "429")));
        var (manager, _, _, access) = S5.Server(dirs, network: true, new CountingFactory(new FakeWeb().Handler), child.Launch, maxJobs: 2);

        var first = await InProcess.RunToEndAsync(manager, Fixtures.Small(dirs.Root, "mcp.first"));
        Assert.True(first.State == JobState.Completed, $"{first.State} {first.Reason}");
        Assert.Equal(new[] { "api.github.com", "api.osv.dev" }, access.StoppedHosts);   // the malformed host is not learned

        var second = await InProcess.RunToEndAsync(manager, Fixtures.Small(dirs.Root, "mcp.second"));
        Assert.True(second.State == JobState.Completed, $"{second.State} {second.Reason}");

        var requests = child.Requests;
        Assert.Equal(2, requests.Count);
        Assert.True(requests[0]["network"]!.GetValue<bool>());
        Assert.Empty(requests[0]["stoppedHosts"]!.AsArray());
        Assert.Equal(3000, requests[0]["minIntervalMs"]!.GetValue<int>());   // 1000 * (maxJobs + 1)
        Assert.Equal(new[] { "api.github.com", "api.osv.dev" }, requests[1]["stoppedHosts"]!.AsArray().Select(h => h!.GetValue<string>()));
        Assert.Equal(3000, requests[1]["minIntervalMs"]!.GetValue<int>());
        Assert.Equal(0, access.HandlersCreated);   // learning a stop creates no client
    }

    [WindowsFact]
    public async Task WithTheNetworkOff_TheChildsRequest_HasNoStoppedHosts_AndTheDefaultSpacing()
    {
        var child = new ArtifactChild(dirs, FixtureEntry, JobIntel.NotChecked());
        var (manager, _, _, access) = S5.Server(dirs, network: false, new CountingFactory(new FakeWeb().Handler), child.Launch, maxJobs: 3);

        var view = await InProcess.RunToEndAsync(manager, Fixtures.Small(dirs.Root, "mcp.offline"));

        Assert.True(view.State == JobState.Completed, $"{view.State} {view.Reason}");
        var request = Assert.Single(child.Requests);
        Assert.False(request["network"]!.GetValue<bool>());
        Assert.True(request["stoppedHosts"] is null, request.ToJsonString());
        Assert.Equal(1000, request["minIntervalMs"]!.GetValue<int>());
        Assert.Empty(access.StoppedHosts);
    }

    [Fact]
    public async Task ARecordedDownloadWhoseJobIsStillRunning_IsJoined_WithNoNewRequest()
    {
        var bytes = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("source"), "mcp.join"));
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) } };
        var child = new FakeChild(dirs, [FakeChild.Ready], sleep: true);
        var (manager, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), child.Launch);

        var first = Drill.S(await jobs.AnalyzePackage(id: "mcp.join", version: "1.0.0"));
        var jobId = first.GetProperty("jobId").GetString()!;
        try
        {
            Assert.True(first.GetProperty("downloaded").GetBoolean());
            var calls = web.Handler.Calls;

            var again = Drill.S(await jobs.AnalyzePackage(id: "mcp.join", version: "1.0.0"));

            Assert.Equal(jobId, again.GetProperty("jobId").GetString());
            Assert.Contains(again.GetProperty("status").GetString(), new[] { "Queued", "Running" });
            Assert.False(again.TryGetProperty("downloaded", out _), again.ToString());
            Assert.Equal(first.GetProperty("source").GetProperty("fetchedAt").GetString(), again.GetProperty("source").GetProperty("fetchedAt").GetString());
            Assert.Equal(calls, web.Handler.Calls);
        }
        finally
        {
            await jobs.CancelJob(jobId);
            await InProcess.WaitToEndAsync(manager, jobId);
            child.AssertAllGone();
        }
    }

    [Fact]
    public async Task ASecondRequestForAPackageBeingDownloaded_IsBusy_AndSendsNothing()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var bytes = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("source"), "mcp.slowdl"));
        var web = new FakeWeb { PackageGate = release.Task, Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) } };
        var child = new FakeChild(dirs, [FakeChild.Ready], exitCode: JobProtocol.ExitFatal);
        var (manager, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), child.Launch);

        var first = Task.Run(() => jobs.AnalyzePackage(id: "mcp.slowdl", version: "1.0.0"));
        try
        {
            await web.PackageEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
            var calls = web.Handler.Calls;

            var second = await jobs.AnalyzePackage(id: "MCP.SlowDL", version: "1.0.0");

            Assert.Equal("Busy", Drill.Status(second));
            Assert.True(Drill.S(second).GetProperty("retry").GetBoolean());
            Assert.Contains("already being downloaded", Drill.S(second).GetProperty("message").GetString());
            Assert.Equal(calls, web.Handler.Calls);
        }
        finally
        {
            release.TrySetResult();
        }
        var done = Drill.S(await first);
        Assert.True(done.GetProperty("downloaded").GetBoolean(), done.ToString());
        await InProcess.WaitToEndAsync(manager, done.GetProperty("jobId").GetString()!);
    }

    [Fact]
    public async Task AThirdConcurrentDownload_IsBusy_TwoAtATime()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var packages = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var id in new[] { "mcp.dla", "mcp.dlb", "mcp.dlc" })
            packages[id] = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("src-" + id), id));
        var web = new FakeWeb
        {
            PackageGate = release.Task,
            Package = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(packages[r.RequestUri!.Segments[2].TrimEnd('/')]) },
        };
        var child = new FakeChild(dirs, [FakeChild.Ready], exitCode: JobProtocol.ExitFatal);
        var (manager, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), child.Launch, maxJobs: 2);

        var a = Task.Run(() => jobs.AnalyzePackage(id: "mcp.dla", version: "1.0.0"));
        Task<ModelContextProtocol.Protocol.CallToolResult>? b = null;
        try
        {
            await web.PackageEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
            b = Task.Run(() => jobs.AnalyzePackage(id: "mcp.dlb", version: "1.0.0"));
            await Task.Delay(1_000);   // b takes the second download slot, then waits behind a for the host

            var c = await jobs.AnalyzePackage(id: "mcp.dlc", version: "1.0.0");

            Assert.Equal("Busy", Drill.Status(c));
            Assert.Contains("downloads are already in progress", Drill.S(c).GetProperty("message").GetString());
        }
        finally
        {
            release.TrySetResult();
        }
        foreach (var t in new[] { a, b! })
        {
            var s = Drill.S(await t);
            Assert.True(s.GetProperty("downloaded").GetBoolean(), s.ToString());
            await InProcess.WaitToEndAsync(manager, s.GetProperty("jobId").GetString()!);
        }
    }

    [Fact]
    public async Task TheServiceIndex_IsReadOncePerServer()
    {
        var packages = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var id in new[] { "mcp.ixa", "mcp.ixb" })
            packages[id] = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("src-" + id), id));
        var web = new FakeWeb { Package = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(packages[r.RequestUri!.Segments[2].TrimEnd('/')]) } };
        var child = new FakeChild(dirs, [FakeChild.Ready], exitCode: JobProtocol.ExitFatal);
        var (manager, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), child.Launch, maxJobs: 2);

        foreach (var id in packages.Keys)
        {
            var s = Drill.S(await jobs.AnalyzePackage(id: id, version: "1.0.0"));
            Assert.True(s.GetProperty("downloaded").GetBoolean(), s.ToString());
            await InProcess.WaitToEndAsync(manager, s.GetProperty("jobId").GetString()!);
        }

        Assert.Single(web.Handler.Urls, u => u.AbsolutePath == "/v3/index.json");
        Assert.Equal(2, web.Handler.Urls.Count(u => u.AbsolutePath.EndsWith(".nupkg", StringComparison.Ordinal)));
    }

    public void Dispose() => dirs.Dispose();
    #endregion

    #region Methods: S5 review round 2
    /// <summary>S-A: the server's own handler is spaced as each child is, 1000 x (maxJobs + 1) ms.</summary>
    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 3)]
    [InlineData(4, 5)]
    public void TheDefaultNetworkAccess_IsSpacedForEveryJobAtOnce(int maxJobs, int seconds)
    {
        var manager = new JobManager(S5.Settings(dirs, network: true, maxJobs), S5.NoLaunch);

        manager.Network.Client();   // builds the client over the real transport; nothing is sent

        Assert.Equal(TimeSpan.FromSeconds(seconds), manager.Network.Polite!.MinInterval);
    }

    [Fact]
    public async Task TheServersDownloads_ToOneHost_AreSpacedAtItsInterval()
    {
        var packages = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var id in new[] { "mcp.spa", "mcp.spb" })
            packages[id] = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("src-" + id), id));
        var web = new FakeWeb { Package = r => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(packages[r.RequestUri!.Segments[2].TrimEnd('/')]) } };
        var child = new FakeChild(dirs, [FakeChild.Ready], exitCode: JobProtocol.ExitFatal);
        var interval = TimeSpan.FromMilliseconds(400);
        var (manager, jobs, _, access) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), child.Launch, maxJobs: 2, minInterval: interval);

        foreach (var id in packages.Keys)
        {
            var s = Drill.S(await jobs.AnalyzePackage(id: id, version: "1.0.0"));
            Assert.True(s.GetProperty("downloaded").GetBoolean(), s.ToString());
            await InProcess.WaitToEndAsync(manager, s.GetProperty("jobId").GetString()!);
        }

        Assert.Equal(interval, access.Polite!.MinInterval);
        var times = web.Handler.Times;
        Assert.Equal(3, times.Count);   // the index once, then two packages, all on api.nuget.org
        for (var i = 1; i < times.Count; i++)
        {
            var gap = Stopwatch.GetElapsedTime(times[i - 1], times[i]);
            Assert.True(gap >= interval - TimeSpan.FromMilliseconds(20), $"requests {i - 1} and {i} were {gap.TotalMilliseconds:0} ms apart");
        }
    }

    /// <summary>S-C: an unusable incoming/ is a Failed value, sends nothing, and leaves no in-flight key behind.</summary>
    [Fact]
    public async Task AnUnusableIncomingDirectory_IsFailed_AndARetryIsNotBusy()
    {
        var bytes = File.ReadAllBytes(Fixtures.Small(dirs.NewDir("source"), "mcp.incoming"));
        var web = new FakeWeb { Package = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) } };
        var child = new FakeChild(dirs, [FakeChild.Ready], exitCode: JobProtocol.ExitFatal);
        var (manager, jobs, _, _) = S5.Server(dirs, network: true, new CountingFactory(web.Handler), child.Launch);
        var incoming = Path.Combine(dirs.Cache, "incoming");
        File.WriteAllText(incoming, "a file where the directory should be");

        var failed = await jobs.AnalyzePackage(id: "mcp.incoming", version: "1.0.0");

        Assert.Equal("Failed", Drill.Status(failed));
        Assert.Contains("incoming directory is not usable", Drill.S(failed).GetProperty("message").GetString());
        Assert.Equal(0, web.Handler.Calls);

        File.Delete(incoming);
        var retry = Drill.S(await jobs.AnalyzePackage(id: "mcp.incoming", version: "1.0.0"));

        Assert.NotEqual("Busy", retry.GetProperty("status").GetString());
        Assert.True(retry.GetProperty("downloaded").GetBoolean(), retry.ToString());
        await InProcess.WaitToEndAsync(manager, retry.GetProperty("jobId").GetString()!);
    }

    /// <summary>The server's own handler adds stops to the same set: StoppedHosts still sends a child only well-formed hosts, at most 64.</summary>
    [Fact]
    public async Task StoppedHosts_FromTheServersOwnRequests_AreFilteredAndCapped()
    {
        var fake = new FakeHttp(_ => FakeWeb.Status(HttpStatusCode.TooManyRequests));
        var access = new NetworkAccess(true, () => fake, TimeSpan.Zero);
        var http = access.Client();

        foreach (var host in Enumerable.Range(0, NetworkAccess.MaxStops + 6).Select(i => $"h{i:D3}.test").Append("a_b.test"))
            (await http.GetAsync($"https://{host}/")).Dispose();

        Assert.True(access.Polite!.Refused("a_b.test"));   // stopped, but not a host a child may be sent
        var stopped = access.StoppedHosts;
        Assert.Equal(NetworkAccess.MaxStops, stopped.Count);
        Assert.DoesNotContain("a_b.test", stopped);
        Assert.Equal(stopped.Order(StringComparer.Ordinal), stopped);
    }
    #endregion

    #region Properties
    private string FixtureEntry => Path.Combine(fixture.CacheDir, fixture.Sha256, JobStore.EntryName(JobDepth.Standard));
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion
}

/// <summary>
/// The CLI's <c>mcp</c> verb (task S5): the network is on by default, <c>--network</c> is still accepted, <c>--no-network</c>
/// turns it off, and both together are a parse error that writes nothing to stdout. A server with the network on sends nothing
/// until a network tool is called, so these children reach no host.
/// </summary>
public sealed class S5McpVerbTests
{
    #region Methods
    [Fact]
    public async Task NetworkAndNoNetwork_Together_AreAParseError_WithNothingOnStdout()
    {
        using var dirs = new TestDirs();
        using var child = McpChildProcess.Start(["mcp", "--root", dirs.Root, "--cache-dir", dirs.Cache, "--log-dir", dirs.Logs, "--network", "--no-network"], dirs.Root);

        var exit = await child.CloseStdinAndWaitForExitAsync();

        Assert.True(exit.Exited, $"did not exit within {McpCli.Timeout}\n{exit.Stderr}");
        Assert.True(exit.ExitCode != 0, $"exit 0\n{exit.Stderr}");
        Assert.True(child.RawStdout.Length == 0, $"{child.RawStdout.Length} bytes on stdout: {Encoding.UTF8.GetString(child.RawStdout)}");
        Assert.Contains("--network and --no-network cannot both be given", exit.Stderr);
        Assert.False(Directory.EnumerateFileSystemEntries(dirs.Cache).Any(), "the cache was touched");
    }

    [Theory]
    [InlineData(new string[0], true)]
    [InlineData(new[] { "--network" }, true)]
    [InlineData(new[] { "--no-network" }, false)]
    public async Task TheNetworkSetting_DefaultsToOn(string[] flags, bool expected)
    {
        using var dirs = new TestDirs();
        using var rpc = await McpRpc.StartAsync(["mcp", "--root", dirs.Root, "--cache-dir", dirs.Cache, "--log-dir", dirs.Logs, .. flags], dirs.Root);

        var info = await rpc.CallAsync(ToolNames.GetServerInfo);

        Assert.False(info.IsError, info.Text);
        Assert.Equal(expected, info.S.GetProperty("settings").GetProperty("network").GetBoolean());
    }

    /// <summary>End to end over the real CLI with <c>--no-network</c>: both network tools refuse as tool errors.</summary>
    [Fact]
    public async Task WithNoNetwork_TheNetworkTools_RefuseNotPermitted_OverTheWire()
    {
        using var dirs = new TestDirs();
        using var rpc = await McpRpc.StartAsync(McpCli.Args(dirs), dirs.Root);

        var analyze = await rpc.CallAsync(ToolNames.AnalyzePackage, new JsonObject { ["id"] = "Newtonsoft.Json", ["version"] = "13.0.3" });
        var intel = await rpc.CallAsync(ToolNames.GetIntel, new JsonObject { ["jobId"] = new string('0', 64) + "-standard" });

        foreach (var call in new[] { analyze, intel })
        {
            Assert.True(call.IsError, call.Text);
            Assert.Equal("NotPermitted", call.Status);
            Assert.False(call.Retry);
        }
        Assert.False(Directory.Exists(Path.Combine(dirs.Cache, "nuget")));
    }
    #endregion
}
