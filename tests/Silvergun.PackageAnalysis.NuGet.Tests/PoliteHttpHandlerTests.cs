namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Silvergun.Intel;

using Xunit;

/// <summary>
/// <see cref="PoliteHttpHandler"/> (MCP task S5): per-host spacing (and no spacing across hosts), the stop on a 429, a 403
/// or a bot challenge (later requests to that host are answered with a synthesized 429 and never sent; each stop recorded
/// once), and the response body cap (by Content-Length at send, by counting on read, raised or lowered per request). Every
/// response comes from <see cref="FakeHandler"/>: there is never a real network call.
/// </summary>
public sealed class PoliteHttpHandlerTests
{
    #region Methods: spacing
    [Fact]
    public async Task SendAsync_SameHost_SequentialRequestsAreAtLeastMinIntervalApart()
    {
        var fake = new FakeHandler(_ => Ok("x"));
        using var http = Invoker(fake, Interval);

        for (var i = 0; i < 3; i++)
            (await Get(http, "https://a.test/" + i)).Dispose();

        AssertSpaced(fake.Sent, Interval);
    }

    [Fact]
    public async Task SendAsync_SameHost_ConcurrentRequestsAreSerializedAndSpaced()
    {
        var fake = new FakeHandler(_ => Ok("x"));
        using var http = Invoker(fake, Interval);

        var responses = await Task.WhenAll(Enumerable.Range(0, 3).Select(i => Get(http, "https://a.test/" + i)));
        foreach (var r in responses)
            r.Dispose();

        Assert.Equal(3, fake.Calls);
        AssertSpaced(fake.Sent, Interval);
    }

    [Fact]
    public async Task SendAsync_HostIsMatchedCaseInsensitively_ForSpacing()
    {
        var fake = new FakeHandler(_ => Ok("x"));
        using var http = Invoker(fake, Interval);

        (await Get(http, "https://a.test/1")).Dispose();
        (await Get(http, "https://A.TEST/2")).Dispose();

        AssertSpaced(fake.Sent, Interval);
    }

    [Fact]
    public async Task SendAsync_DifferentHosts_AreNotSpacedAgainstEachOther()
    {
        var fake = new FakeHandler(_ => Ok("x"));
        var interval = TimeSpan.FromSeconds(3);
        using var http = Invoker(fake, interval);

        var clock = Stopwatch.StartNew();
        foreach (var host in new[] { "a.test", "b.test", "c.test" })
            (await Get(http, $"https://{host}/")).Dispose();

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1.5), $"three hosts took {clock.Elapsed.TotalMilliseconds:0} ms with a {interval.TotalSeconds} s interval");
        Assert.Equal(3, fake.Calls);
    }

    [Fact]
    public void MinInterval_DefaultsToOneSecond()
    {
        using var polite = new PoliteHttpHandler(new FakeHandler(_ => Ok("x")));

        Assert.Equal(TimeSpan.FromSeconds(1), polite.MinInterval);
        Assert.Equal(8L * 1024 * 1024, PoliteHttpHandler.DefaultMaxResponseBytes);
    }

    [Fact]
    public async Task SendAsync_CancelledWhileWaitingForItsSlot_ThrowsAndSendsNothingMore()
    {
        var fake = new FakeHandler(_ => Ok("x"));
        using var http = Invoker(fake, TimeSpan.FromSeconds(30));
        (await Get(http, "https://a.test/1")).Dispose();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        var clock = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Get(http, "https://a.test/2", cts.Token));

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"the cancelled wait took {clock.Elapsed}");
        Assert.Equal(1, fake.Calls);
    }
    #endregion

    #region Methods: stops
    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests, "429")]
    [InlineData(HttpStatusCode.Forbidden, "403")]
    public async Task SendAsync_429Or403_StopsTheHost_LaterRequestsAreSynthesizedAndNeverSent(HttpStatusCode status, string why)
    {
        var fake = new FakeHandler(r => r.RequestUri!.Host == "a.test" ? new HttpResponseMessage(status) : Ok("fine"));
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        using var first = await Get(http, "https://a.test/1");
        Assert.Equal(status, first.StatusCode);   // the refusal itself is passed on as it came
        Assert.True(polite.Refused("a.test"));
        Assert.True(polite.Refused("A.Test"));

        for (var i = 0; i < 3; i++)
        {
            using var later = await Get(http, "https://a.test/again" + i);
            AssertSynthesized(later);
        }

        Assert.Equal(1, fake.Calls);
        Assert.Equal(1, polite.Requests);
        Assert.Equal([("a.test", why)], polite.Refusals);

        using var other = await Get(http, "https://b.test/");
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);   // only the refusing host is stopped
        Assert.False(polite.Refused("b.test"));
        Assert.Equal(2, fake.Calls);
        Assert.Equal(2, polite.Requests);
    }

    public static TheoryData<string> Challenges() => ["x-amzn-waf-action", "cf-mitigated: challenge", "202 with an empty body", "202 with no content"];

    [Theory]
    [MemberData(nameof(Challenges))]
    public async Task SendAsync_ABotChallenge_IsReplacedByASynthesized429_AndStopsTheHost(string what)
    {
        var fake = new FakeHandler(r =>
        {
            if (r.RequestUri!.Host != "a.test")
                return Ok("fine");
            HttpResponseMessage challenge = what switch
            {
                "x-amzn-waf-action" => Ok("<html>solve me</html>"),
                "cf-mitigated: challenge" => new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("<html>challenge</html>") },
                "202 with an empty body" => new HttpResponseMessage(HttpStatusCode.Accepted) { Content = new ByteArrayContent([]) },
                "202 with no content" => new HttpResponseMessage(HttpStatusCode.Accepted),
                _ => throw new ArgumentException(what),
            };
            if (what == "x-amzn-waf-action")
                challenge.Headers.TryAddWithoutValidation("x-amzn-waf-action", "challenge");
            if (what == "cf-mitigated: challenge")
                challenge.Headers.TryAddWithoutValidation("cf-mitigated", "challenge");
            return challenge;
        });
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        using var first = await Get(http, "https://a.test/1");
        AssertSynthesized(first);   // the challenge page itself never reaches the caller
        Assert.Equal("", await first.Content.ReadAsStringAsync());

        using var later = await Get(http, "https://a.test/2");
        AssertSynthesized(later);
        Assert.Equal(1, fake.Calls);
        Assert.Equal([("a.test", "challenge")], polite.Refusals);

        using var other = await Get(http, "https://b.test/");
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task SendAsync_A202WithABody_IsNotAChallenge()
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.Accepted) { Content = new StringContent("{\"queued\":true}") });
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        using var first = await Get(http, "https://a.test/1");
        using var second = await Get(http, "https://a.test/2");

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal("{\"queued\":true}", await first.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        Assert.Equal(2, fake.Calls);
        Assert.Empty(polite.Refusals);
        Assert.False(polite.Refused("a.test"));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task SendAsync_OtherFailures_DoNotStopTheHost(HttpStatusCode status)
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(status));
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        (await Get(http, "https://a.test/1")).Dispose();
        using var second = await Get(http, "https://a.test/2");

        Assert.Equal(status, second.StatusCode);
        Assert.Equal(2, fake.Calls);
        Assert.Empty(polite.Refusals);
    }

    [Fact]
    public async Task Refusals_AreRecordedOncePerHost_InOrder()
    {
        var fake = new FakeHandler(r => r.RequestUri!.Host switch
        {
            "a.test" => new HttpResponseMessage(HttpStatusCode.TooManyRequests),
            "b.test" => new HttpResponseMessage(HttpStatusCode.Forbidden),
            _ => Ok("fine"),
        });
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        foreach (var url in new[] { "https://a.test/1", "https://a.test/2", "https://b.test/1", "https://a.test/3", "https://b.test/2", "https://c.test/" })
            (await Get(http, url)).Dispose();

        Assert.Equal([("a.test", "429"), ("b.test", "403")], polite.Refusals);
        Assert.Equal(3, fake.Calls);   // a once, b once, c once
        Assert.Equal(3, polite.Requests);
    }

    /// <summary>Requests queued behind the one that is refused are answered by the stop, not sent.</summary>
    [Fact]
    public async Task SendAsync_ConcurrentRequestsBehindARefusal_AreNotSent()
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests));
        using var polite = new PoliteHttpHandler(fake, TimeSpan.FromMilliseconds(50));
        using var http = new HttpMessageInvoker(polite);

        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(i => Get(http, "https://a.test/" + i)));

        Assert.Equal(1, fake.Calls);
        Assert.Single(polite.Refusals);
        Assert.Single(responses, r => r.ReasonPhrase != Stopped);
        Assert.Equal(4, responses.Count(r => r.ReasonPhrase == Stopped && r.StatusCode == HttpStatusCode.TooManyRequests));
        foreach (var r in responses)
            r.Dispose();
    }

    /// <summary>
    /// A request issued after a challenge response has come back, but before the handler has finished judging it, must not be
    /// sent: the stop covers "all later requests to that host" (S5 design). The challenge here is a 202 whose Content-Length
    /// takes a moment to compute, which holds the first request between the slot's release and the stop being recorded.
    /// </summary>
    [Fact]
    public async Task SendAsync_ARequestIssuedWhileAChallengeIsBeingJudged_IsNotSent()
    {
        using var judging = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var fake = new FakeHandler(r => r.RequestUri!.AbsolutePath == "/1"
            ? new HttpResponseMessage(HttpStatusCode.Accepted) { Content = new SlowEmptyContent(judging, release) }
            : Ok("sent"));
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        var first = Task.Run(() => Get(http, "https://a.test/1"));
        Assert.True(judging.Wait(TimeSpan.FromSeconds(10)), "the first response was never judged");
        var second = Task.Run(() => Get(http, "https://a.test/2"));
        var sentEarly = await Task.WhenAny(second, Task.Delay(TimeSpan.FromSeconds(2))) == second;
        release.Set();
        using var r1 = await first;
        using var r2 = await second;

        AssertSynthesized(r1);
        Assert.False(sentEarly && r2.ReasonPhrase != Stopped, $"the second request was sent ({fake.Calls} sends) before the challenge's stop was recorded");
        Assert.Equal(1, fake.Calls);
        AssertSynthesized(r2);
    }
    #endregion

    #region Methods: shared stops (S5 review W4)
    [Fact]
    public async Task ASharedStopSet_MakesAStopVisibleToEveryHandlerOverIt()
    {
        var stops = new System.Collections.Concurrent.ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests));
        using var first = new PoliteHttpHandler(fake, TimeSpan.Zero, stops);
        using var second = new PoliteHttpHandler(fake, TimeSpan.Zero, stops);
        using var a = new HttpMessageInvoker(first, disposeHandler: false);
        using var b = new HttpMessageInvoker(second, disposeHandler: false);

        (await Get(a, "https://a.test/1")).Dispose();
        using var later = await Get(b, "https://a.test/2");

        AssertSynthesized(later);
        Assert.Equal(1, fake.Calls);
        Assert.True(second.Refused("a.test"));
        Assert.Equal("429", stops["a.test"]);
        Assert.Equal([("a.test", "429")], first.Refusals);
        Assert.Empty(second.Refusals);   // Refusals are the stops this handler made
    }

    [Fact]
    public async Task ASeededStop_IsRefused_AndNeverAsked()
    {
        var stops = new System.Collections.Concurrent.ConcurrentDictionary<string, string>(StringComparer.Ordinal) { ["a.test"] = "earlier" };
        var fake = new FakeHandler(_ => Ok("x"));
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero, stops);
        using var http = new HttpMessageInvoker(polite);

        Assert.True(polite.Refused("a.test"));
        Assert.True(polite.Refused("A.TEST"));
        using var response = await Get(http, "https://a.test/");

        AssertSynthesized(response);
        Assert.Equal(0, fake.Calls);
        Assert.Equal(0, polite.Requests);
        Assert.Empty(polite.Refusals);
    }
    #endregion

    #region Methods: capped error bodies (S5 review W3)
    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task AStreamedRefusalBodyPastTheCap_FailsTheRead_AndTheHostStaysStopped(HttpStatusCode status)
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(status) { Content = new StreamContent(new ZeroStream(20L * 1024 * 1024)) });
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        using var response = await Get(http, "https://a.test/");
        Assert.Equal(status, response.StatusCode);
        await using var body = await response.Content.ReadAsStreamAsync();

        await Assert.ThrowsAsync<IOException>(() => body.CopyToAsync(Stream.Null));
        Assert.True(polite.Refused("a.test"));
    }

    [Fact]
    public async Task ARefusalWithADeclaredOverCapBody_Throws_AfterTheStopIsRecorded()
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new ByteArrayContent(new byte[101]) });
        using var polite = new PoliteHttpHandler(fake, TimeSpan.Zero);
        using var http = new HttpMessageInvoker(polite);

        await Assert.ThrowsAsync<IOException>(() => Get(http, "https://a.test/1", max: 100));

        Assert.True(polite.Refused("a.test"));
        Assert.Equal([("a.test", "429")], polite.Refusals);
        AssertSynthesized(await Get(http, "https://a.test/2"));
        Assert.Equal(1, fake.Calls);
    }
    #endregion

    #region Methods: body cap
    [Fact]
    public async Task SendAsync_AContentLengthOverTheDefaultCap_ThrowsIOException()
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[PoliteHttpHandler.DefaultMaxResponseBytes + 1]) });
        using var http = Invoker(fake, TimeSpan.Zero);

        await Assert.ThrowsAsync<IOException>(() => Get(http, "https://a.test/big"));
    }

    [Fact]
    public async Task SendAsync_AContentLengthAtTheCap_IsServed()
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[100]) });
        using var http = Invoker(fake, TimeSpan.Zero);

        using var response = await Get(http, "https://a.test/", max: 100);

        Assert.Equal(100, (await response.Content.ReadAsByteArrayAsync()).Length);
    }

    [Fact]
    public async Task SendAsync_ARequestOptionCanLowerTheCap()
    {
        var fake = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[101]) });
        using var http = Invoker(fake, TimeSpan.Zero);

        await Assert.ThrowsAsync<IOException>(() => Get(http, "https://a.test/", max: 100));
    }

    [Fact]
    public async Task ReadingAStreamedBodyPastTheDefaultCap_ThrowsIOException()
    {
        var fake = new FakeHandler(_ => Streamed(PoliteHttpHandler.DefaultMaxResponseBytes + 1));
        using var http = Invoker(fake, TimeSpan.Zero);

        using var response = await Get(http, "https://a.test/stream");
        Assert.Null(response.Content.Headers.ContentLength);   // the cap could not be checked up front
        await using var body = await response.Content.ReadAsStreamAsync();

        await Assert.ThrowsAsync<IOException>(() => body.CopyToAsync(Stream.Null));
    }

    [Fact]
    public async Task ReadingAStreamedBodyPastARequestCap_ThrowsIOException_EvenWithSyncReads()
    {
        var fake = new FakeHandler(_ => Streamed(1_001));
        using var http = Invoker(fake, TimeSpan.Zero);

        using var response = await Get(http, "https://a.test/stream", max: 1_000);
        await using var body = await response.Content.ReadAsStreamAsync();

        Assert.Throws<IOException>(() => body.CopyTo(Stream.Null));
    }

    [Fact]
    public async Task ReadingAStreamedBodyExactlyAtTheCap_Succeeds()
    {
        var fake = new FakeHandler(_ => Streamed(1_000));
        using var http = Invoker(fake, TimeSpan.Zero);

        using var response = await Get(http, "https://a.test/stream", max: 1_000);

        Assert.Equal(1_000, (await response.Content.ReadAsByteArrayAsync()).Length);
    }

    [Fact]
    public async Task MaxResponseBytesOption_RaisesTheCap_ForStreamedAndDeclaredBodies()
    {
        var size = PoliteHttpHandler.DefaultMaxResponseBytes + 1;
        var fake = new FakeHandler(r => r.RequestUri!.AbsolutePath == "/stream"
            ? Streamed(size)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[size]) });
        using var http = Invoker(fake, TimeSpan.Zero);

        using var streamed = await Get(http, "https://a.test/stream", max: size * 2);
        using var declared = await Get(http, "https://b.test/declared", max: size * 2);

        Assert.Equal(size, await Drain(streamed));
        Assert.Equal(size, await Drain(declared));
    }

    [Fact]
    public async Task TheCappedBody_KeepsTheContentHeaders()
    {
        var fake = new FakeHandler(_ => Ok("{\"a\":1}", "application/json"));
        using var http = Invoker(fake, TimeSpan.Zero);

        using var response = await Get(http, "https://a.test/");

        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(7, response.Content.Headers.ContentLength);
        Assert.Equal("{\"a\":1}", await response.Content.ReadAsStringAsync());
    }
    #endregion

    #region Methods: helpers
    private static HttpMessageInvoker Invoker(HttpMessageHandler fake, TimeSpan interval) => new(new PoliteHttpHandler(fake, interval));

    private static async Task<HttpResponseMessage> Get(HttpMessageInvoker http, string url, CancellationToken ct = default, long? max = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (max is { } m)
            request.Options.Set(PoliteHttpHandler.MaxResponseBytesOption, m);
        return await http.SendAsync(request, ct);
    }

    private static Task<HttpResponseMessage> Get(HttpMessageInvoker http, string url, long max) => Get(http, url, default, max);

    private static HttpResponseMessage Ok(string body, string mediaType = "text/plain") =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, mediaType) };

    // A body with no Content-Length: a non-seekable stream of `bytes` zeros.
    private static HttpResponseMessage Streamed(long bytes) => new(HttpStatusCode.OK) { Content = new StreamContent(new ZeroStream(bytes)) };

    private static async Task<long> Drain(HttpResponseMessage response)
    {
        await using var body = await response.Content.ReadAsStreamAsync();
        var buffer = new byte[81920];
        long total = 0;
        int n;
        while ((n = await body.ReadAsync(buffer)) > 0)
            total += n;
        return total;
    }

    private static void AssertSynthesized(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal(Stopped, response.ReasonPhrase);
        Assert.NotNull(response.RequestMessage);
    }

    // Each send at least `interval` after the one before, less the timer's granularity.
    private static void AssertSpaced(IReadOnlyList<(long At, Uri Url)> sent, TimeSpan interval)
    {
        var at = sent.Select(s => s.At).Order().ToList();
        for (var i = 1; i < at.Count; i++)
        {
            var gap = Stopwatch.GetElapsedTime(at[i - 1], at[i]);
            Assert.True(gap >= interval - Slack, $"sends {i - 1} and {i} were {gap.TotalMilliseconds:0} ms apart; the interval is {interval.TotalMilliseconds:0} ms");
        }
    }
    #endregion

    #region Fields
    private const string Stopped = "stopped by Silvergun";

    private static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan Slack = TimeSpan.FromMilliseconds(20);
    #endregion

    #region Types
    /// <summary>Answers every request with <c>respond</c>, recording when each was sent and to where.</summary>
    internal sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int Calls { get { lock (sent) return sent.Count; } }

        public IReadOnlyList<(long At, Uri Url)> Sent { get { lock (sent) return [.. sent]; } }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sent)
                sent.Add((Stopwatch.GetTimestamp(), request.RequestUri!));
            var response = respond(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }

        private readonly List<(long, Uri)> sent = [];
    }

    /// <summary>An empty body whose length is computed only when <c>release</c> is set, signalling <c>judging</c> when asked.</summary>
    private sealed class SlowEmptyContent(ManualResetEventSlim judging, ManualResetEventSlim release) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.CompletedTask;

        protected override bool TryComputeLength(out long length)
        {
            judging.Set();
            release.Wait(TimeSpan.FromSeconds(10));
            length = 0;
            return true;
        }
    }

    /// <summary>A read-only, non-seekable stream of <c>length</c> zero bytes.</summary>
    private sealed class ZeroStream(long length) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = (int)Math.Min(count, length - position);
            Array.Clear(buffer, offset, n);
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
