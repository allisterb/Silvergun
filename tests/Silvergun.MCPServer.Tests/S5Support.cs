namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;
using Silvergun.MCPServer.Jobs;
using Silvergun.PackageAnalysis.NuGet;

/// <summary>
/// A fake web for task S5: nuget.org's service index, search and flat container, and GitHub's repository API, each answered
/// by a settable function. Any other URL is a 404 and is recorded in <see cref="Unexpected"/>. No test reaches a real host:
/// every handler a test passes to Silvergun is <see cref="Handler"/>, or a counting factory over it.
/// </summary>
internal sealed class FakeWeb
{
    #region Constructors
    public FakeWeb() => Handler = new FakeHttp(Respond, async r =>
    {
        // Awaited, not blocked on: a held download must not tie up a thread-pool thread other tests need.
        if (r.RequestUri!.AbsolutePath.StartsWith("/v3-flatcontainer/", StringComparison.Ordinal) && PackageGate is { } gate)
        {
            PackageEntered.TrySetResult();
            await gate.WaitAsync(TimeSpan.FromSeconds(30));
        }
    });
    #endregion

    #region Properties
    public FakeHttp Handler { get; }

    /// <summary>When set, every package GET waits for it (asynchronously) after signalling <see cref="PackageEntered"/>.</summary>
    public Task? PackageGate { get; set; }

    /// <summary>Completed when the first package GET reaches <see cref="PackageGate"/>.</summary>
    public TaskCompletionSource PackageEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>The service index (default: <see cref="GoodIndex"/>).</summary>
    public Func<HttpResponseMessage> Index { get; set; } = () => Json(GoodIndex);

    /// <summary>The <c>packageid:</c> search (default: no hit).</summary>
    public Func<HttpResponseMessage> Exact { get; set; } = () => Json("""{"data":[]}""");

    /// <summary>The free-text search (default: no hit).</summary>
    public Func<HttpResponseMessage> Neighbours { get; set; } = () => Json("""{"data":[]}""");

    /// <summary>GitHub's <c>GET /repos/{owner}/{repo}</c> (default: 404).</summary>
    public Func<HttpRequestMessage, HttpResponseMessage> GitHub { get; set; } = _ => new HttpResponseMessage(HttpStatusCode.NotFound);

    /// <summary>A flat-container <c>.nupkg</c> GET (default: 404).</summary>
    public Func<HttpRequestMessage, HttpResponseMessage> Package { get; set; } = _ => new HttpResponseMessage(HttpStatusCode.NotFound);

    /// <summary>Any other host (an OSV stand-in, say); null answers 404 and records the URL as unexpected.</summary>
    public Func<HttpRequestMessage, HttpResponseMessage?>? Other { get; set; }

    public IReadOnlyList<Uri> Unexpected { get { lock (unexpected) return [.. unexpected]; } }
    #endregion

    #region Methods
    public static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Status(HttpStatusCode status) => new(status) { Content = new StringContent("") };

    /// <summary>A search result: one <c>data</c> entry per hit.</summary>
    public static string Hits(params (string Id, long? Downloads)[] hits) =>
        new JsonObject
        {
            ["totalHits"] = hits.Length,
            ["data"] = new JsonArray([.. hits.Select(h => (JsonNode)new JsonObject { ["id"] = h.Id, ["totalDownloads"] = h.Downloads })]),
        }.ToJsonString();

    /// <summary>A GitHub repository document with the fields the health source reads.</summary>
    public static string Repo(int stars = 1234, string? license = "MIT", bool archived = false) =>
        new JsonObject
        {
            ["stargazers_count"] = stars,
            ["forks_count"] = 56,
            ["subscribers_count"] = 7,
            ["watchers_count"] = stars,
            ["open_issues_count"] = 8,
            ["size"] = 900,
            ["created_at"] = "2015-01-01T00:00:00Z",
            ["pushed_at"] = DateTimeOffset.UtcNow.AddDays(-3).ToString("O"),
            ["license"] = license is null ? null : new JsonObject { ["spdx_id"] = license, ["name"] = license },
            ["archived"] = archived,
            ["disabled"] = false,
            ["has_issues"] = true,
            ["default_branch"] = "main",
        }.ToJsonString();

    private HttpResponseMessage Respond(HttpRequestMessage request)
    {
        var url = request.RequestUri!;
        var path = url.AbsolutePath;
        return (url.Host, path) switch
        {
            ("api.nuget.org", "/v3/index.json") => Index(),
            ("api.nuget.org", _) when path.StartsWith("/v3-flatcontainer/", StringComparison.Ordinal) => Package(request),
            (SearchHost, "/query") => Uri.UnescapeDataString(url.Query).Contains("q=packageid:", StringComparison.Ordinal) ? Exact() : Neighbours(),
            ("api.github.com", _) when path.StartsWith("/repos/", StringComparison.Ordinal) => GitHub(request),
            _ => Other?.Invoke(request) ?? Unknown(url),
        };
    }

    private HttpResponseMessage Unknown(Uri url)
    {
        lock (unexpected)
            unexpected.Add(url);
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
    #endregion

    #region Fields
    public const string SearchHost = "azuresearch-usnc.nuget.org";
    public const string FlatContainer = "https://api.nuget.org/v3-flatcontainer/";

    public static readonly string GoodIndex = $$"""
        {"version":"3.0.0","resources":[
          {"@id":"https://{{SearchHost}}/query","@type":"SearchQueryService"},
          {"@id":"{{FlatContainer}}","@type":"PackageBaseAddress/3.0.0"}]}
        """;

    private readonly List<Uri> unexpected = [];
    #endregion
}

/// <summary>An <see cref="HttpMessageHandler"/> that answers with a function and records every request (thread-safe).</summary>
internal sealed class FakeHttp(Func<HttpRequestMessage, HttpResponseMessage> respond, Func<HttpRequestMessage, Task>? before = null) : HttpMessageHandler
{
    #region Properties
    public int Calls { get { lock (urls) return urls.Count; } }

    public IReadOnlyList<Uri> Urls { get { lock (urls) return [.. urls]; } }

    /// <summary>When each request arrived (<see cref="System.Diagnostics.Stopwatch"/> timestamps), in the order of <see cref="Urls"/>.</summary>
    public IReadOnlyList<long> Times { get { lock (urls) return [.. times]; } }
    #endregion

    #region Methods
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (urls)
        {
            urls.Add(request.RequestUri!);
            times.Add(System.Diagnostics.Stopwatch.GetTimestamp());
        }
        if (before is not null)
            await before(request);
        var response = respond(request);
        response.RequestMessage ??= request;
        return response;
    }

    // The handler is shared by the tests that reuse it; disposing a client over it must not dispose it.
    protected override void Dispose(bool disposing) { }
    #endregion

    #region Fields
    private readonly List<Uri> urls = [];
    private readonly List<long> times = [];
    #endregion
}

/// <summary>A handler factory that counts its calls: the S5 "no socket" seam, checked from both sides.</summary>
internal sealed class CountingFactory(HttpMessageHandler handler)
{
    #region Properties
    public int Calls => calls;

    public Func<HttpMessageHandler> Create => () =>
    {
        Interlocked.Increment(ref calls);
        return handler;
    };
    #endregion

    #region Fields
    private int calls;
    #endregion
}

/// <summary>
/// A scripted job child (PowerShell, so Windows only) that completes: it saves the request line it was sent, copies a template
/// of valid artifacts into the request's job directory, then reports ready and done. Its <c>intel.json</c> is whatever the test
/// put in the template, so a test controls the refusals the server learns. It never reaches a network.
/// </summary>
internal sealed class ArtifactChild
{
    #region Constructors
    public ArtifactChild(TestDirs dirs, string completedEntry, JsonObject intel)
    {
        var dir = dirs.NewDir("artifact-child-" + Guid.NewGuid().ToString("N")[..8]);
        Template = Directory.CreateDirectory(Path.Combine(dir, "template")).FullName;
        RequestDir = Directory.CreateDirectory(Path.Combine(dir, "requests")).FullName;
        foreach (var file in Directory.GetFiles(completedEntry).Where(f => Path.GetFileName(f) is not (JobProtocol.JobFile or JobProtocol.PackageFile) && !Path.GetFileName(f).StartsWith('.')))
            File.Copy(file, Path.Combine(Template, Path.GetFileName(file)));
        File.WriteAllText(Path.Combine(Template, JobProtocol.IntelFile), intel.ToJsonString(JobProtocol.JsonOptions));
        var ready = Path.Combine(dir, "ready.txt");
        var done = Path.Combine(dir, "done.txt");
        File.WriteAllBytes(ready, Encoding.UTF8.GetBytes(FakeChild.Ready + "\n"));
        File.WriteAllBytes(done, Encoding.UTF8.GetBytes(FakeChild.ValidDone + "\n"));
        var nl = (char)10;
        var script = new StringBuilder()
            .Append("$line = [Console]::In.ReadLine()").Append(nl)
            .Append("[IO.File]::WriteAllText((Join-Path '").Append(RequestDir).Append("' ([DateTime]::UtcNow.Ticks.ToString() + '-' + $PID + '.json')), $line)").Append(nl)
            .Append("$job = ($line | ConvertFrom-Json).jobDir").Append(nl)
            .Append("Get-ChildItem -LiteralPath '").Append(Template).Append("' -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $job $_.Name) }").Append(nl)
            .Append("$o = [Console]::OpenStandardOutput()").Append(nl)
            .Append("$b = [IO.File]::ReadAllBytes('").Append(ready).Append("'); $o.Write($b, 0, $b.Length); $o.Flush()").Append(nl)
            .Append("$b = [IO.File]::ReadAllBytes('").Append(done).Append("'); $o.Write($b, 0, $b.Length); $o.Flush()").Append(nl)
            .Append("exit 0").Append(nl);
        var path = Path.Combine(dir, "child.ps1");
        File.WriteAllText(path, script.ToString(), new UTF8Encoding(false));
        Launch = new JobLaunch(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), null,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]);
    }
    #endregion

    #region Properties
    public JobLaunch Launch { get; }

    public string Template { get; }

    public string RequestDir { get; }

    /// <summary>Every request line received, oldest first.</summary>
    public IReadOnlyList<JsonObject> Requests =>
        [.. Directory.GetFiles(RequestDir).Order(StringComparer.Ordinal).Select(f => JsonNode.Parse(File.ReadAllText(f))!.AsObject())];
    #endregion

    #region Methods
    /// <summary>A checked intel document whose refusals are <paramref name="refusals"/>.</summary>
    public static JsonObject Intel(params (string Host, string Why)[] refusals) => new()
    {
        ["status"] = "checked",
        ["vulnerabilities"] = new JsonObject { ["status"] = "completed", ["count"] = 0 },
        ["health"] = new JsonObject { ["status"] = "refused" },
        ["squat"] = new JsonObject { ["status"] = "checked" },
        ["requests"] = refusals.Length,
        ["refusals"] = new JsonArray([.. refusals.Select(r => (JsonNode)new JsonObject { ["host"] = r.Host, ["why"] = r.Why })]),
    };
    #endregion
}

/// <summary>A fact that needs Windows PowerShell (the scripted <see cref="ArtifactChild"/>); a skip elsewhere.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "The scripted artifact child is a Windows PowerShell script.";
    }
}

/// <summary>Reports and settings for the S5 tests.</summary>
internal static class S5
{
    #region Methods
    /// <summary>A scanned package's report with only what <see cref="JobIntel"/> reads.</summary>
    public static PackageCapabilityReport Report(string id, string? repositoryUrl = null, string? projectUrl = null,
        VulnerabilityScanStatus vulnerabilities = VulnerabilityScanStatus.NotChecked, int vulnerabilityCount = 0) =>
        new(new PackageIdentityInfo(id, "1.0.0", "Tests", "S5 fixture.", [], repositoryUrl, projectUrl), DateTimeOffset.UtcNow, [], [], [],
            Vulnerabilities: [.. Enumerable.Range(0, vulnerabilityCount).Select(i => new VulnerabilityFinding($"GHSA-{i}", [], null, null, id, "1.0.0", false, []))],
            VulnerabilitiesStatus: vulnerabilities);

    /// <summary>
    /// <see cref="JobIntel.Gather"/> as the job child calls it: one client over one polite handler on <paramref name="handler"/>
    /// (unspaced here, to keep tests fast), seeded with <paramref name="stoppedBefore"/> as the worker seeds it.
    /// </summary>
    public static JsonObject Gather(PackageCapabilityReport report, HttpMessageHandler handler, IReadOnlyList<string>? stoppedBefore = null, string? token = null,
        CancellationToken ct = default)
    {
        var stops = new System.Collections.Concurrent.ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        foreach (var host in stoppedBefore ?? [])
            stops.TryAdd(host, "earlier");
        var polite = new PoliteHttpHandler(handler, TimeSpan.Zero, stops);
        using var http = new HttpClient(polite) { Timeout = NetworkAccess.RequestTimeout };
        return JobIntel.Gather(report, http, polite, stoppedBefore ?? [], token, ct);
    }

    public static McpServerSettings Settings(TestDirs dirs, bool network, int maxJobs = 1)
    {
        var settings = McpServerSettings.Create([dirs.Root], network, maxJobs, dirs.Cache, McpServerSettings.DefaultCacheMaxGb, dirs.Logs, false);
        Assert.True(settings.IsSuccess, settings.Message);
        return settings.Value;
    }

    /// <summary>A manager whose network is <paramref name="network"/>, with its children launched by <paramref name="launch"/>.</summary>
    public static (JobManager Manager, JobTools Jobs, DrillTools Drill, NetworkAccess Network) Server(TestDirs dirs, bool network, CountingFactory factory, JobLaunch launch,
        int maxJobs = 1, TimeSpan? minInterval = null)
    {
        var settings = Settings(dirs, network, maxJobs);
        var access = new NetworkAccess(network, factory.Create, minInterval);
        var manager = new JobManager(settings, launch, network: access);
        return (manager, new JobTools(manager, new ServerState(settings)), new DrillTools(manager), access);
    }

    /// <summary>A launch that must never run: a test that only checks refusals.</summary>
    public static readonly JobLaunch NoLaunch = new(Path.Combine(Path.GetTempPath(), "silvergun-no-such-child-" + Guid.NewGuid().ToString("N")), null, []);

    /// <summary>Every <c>{"untrusted": …}</c> string under <paramref name="node"/>.</summary>
    public static IEnumerable<string> UntrustedStrings(JsonNode? node) => node switch
    {
        JsonObject o when o.Count == 1 && o["untrusted"] is JsonValue v && v.TryGetValue<string>(out var s) => [s],
        JsonObject o => o.SelectMany(p => UntrustedStrings(p.Value)),
        JsonArray a => a.SelectMany(UntrustedStrings),
        _ => [],
    };
    #endregion
}
