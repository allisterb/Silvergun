namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// <see cref="OsvClient"/>'s <c>maxDetails</c> (MCP task S5 review C1): at most that many <c>/v1/vulns/{id}</c> lookups per query;
/// ids past it become id-only findings without a request, and none is dropped. A fake handler serves every response.
/// </summary>
public sealed class OsvClientMaxDetailsTests
{
    #region Methods
    [Theory]
    [InlineData(0, 0)]
    [InlineData(2, 2)]
    [InlineData(3, 3)]
    [InlineData(50, 3)]
    public async Task QueryAsync_LooksUpAtMostMaxDetails_AndKeepsEveryFinding(int maxDetails, int lookups)
    {
        var fake = new Fake();
        var client = new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test", maxDetails: maxDetails);

        var result = await client.QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)]);

        Assert.True(result.Queried);
        Assert.Equal(lookups, fake.Details);
        Assert.Equal(new[] { "GHSA-1", "GHSA-2", "GHSA-3" }, result.Findings.Select(f => f.Id).Order());
        Assert.Equal(lookups, result.Findings.Count(f => f.Summary is not null));
        Assert.All(result.Findings, f => Assert.Equal("VulnPkg", f.PackageId));
    }

    [Fact]
    public async Task QueryAsync_ByDefault_LooksUpEveryId()
    {
        var fake = new Fake();

        var result = await new OsvClient(new HttpClient(fake), baseUrl: "https://osv.test").QueryAsync([new OsvQuery("VulnPkg", "1.0.0", IsDependency: false)]);

        Assert.Equal(3, fake.Details);
        Assert.All(result.Findings, f => Assert.NotNull(f.Summary));
    }
    #endregion

    #region Types
    // A batch with three vulnerability ids for the one query; each detail answers with a summary.
    private sealed class Fake : HttpMessageHandler
    {
        public int Details => details;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/querybatch", StringComparison.Ordinal))
                return Task.FromResult(Ok("""{"results":[{"vulns":[{"id":"GHSA-1"},{"id":"GHSA-2"},{"id":"GHSA-3"}]}]}"""));
            Interlocked.Increment(ref details);
            var id = Uri.UnescapeDataString(path[(path.LastIndexOf('/') + 1)..]);
            return Task.FromResult(Ok($$"""{"id":"{{id}}","summary":"Detail of {{id}}."}"""));
        }

        private static HttpResponseMessage Ok(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json) };

        private int details;
    }
    #endregion
}
