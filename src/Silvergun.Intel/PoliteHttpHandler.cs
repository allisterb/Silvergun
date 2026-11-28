namespace Silvergun.Intel;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// The external-service rules for every Silvergun request (MCP task S5): requests to one host are at least
/// <see cref="MinInterval"/> apart; a 429, a 403 or a bot challenge stops every later request to that host (each is answered
/// with a synthesized 429 and nothing is sent); every response body, error bodies included, is capped at
/// <see cref="DefaultMaxResponseBytes"/>, or a request's <see cref="MaxResponseBytesOption"/>, and a body past its cap fails
/// the read with an <see cref="IOException"/>. <paramref name="stops"/> may be shared, so stops outlive one handler (the
/// server's set, or the hosts a job child was told were stopped). The inner handler must not follow redirects.
/// </summary>
public sealed class PoliteHttpHandler(HttpMessageHandler inner, TimeSpan? minInterval = null, ConcurrentDictionary<string, string>? stops = null) : DelegatingHandler(inner)
{
    #region Properties
    /// <summary>The least time between two requests to one host.</summary>
    public TimeSpan MinInterval { get; } = minInterval ?? TimeSpan.FromSeconds(1);

    /// <summary>The requests sent on (not those answered by a stop).</summary>
    public int Requests => requests;

    /// <summary>Every stop this handler made, in order: the host and what stopped it (<c>429</c>, <c>403</c> or <c>challenge</c>).</summary>
    public IReadOnlyList<(string Host, string Why)> Refusals
    {
        get { lock (refusals) return [.. refusals]; }
    }
    #endregion

    #region Methods
    /// <summary>Whether requests to <paramref name="host"/> are stopped, by this handler or by a shared stop.</summary>
    public bool Refused(string host) => stopped.ContainsKey(host.ToLowerInvariant());

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var host = request.RequestUri?.IdnHost.ToLowerInvariant() ?? "";
        if (stopped.ContainsKey(host))
            return Synthesized(request);

        var slot = slots.GetOrAdd(host, _ => new Slot());
        await slot.Gate.WaitAsync(cancellationToken);
        HttpResponseMessage response;
        // The response is judged before the gate is released, so a request queued behind a refusal never goes out.
        try
        {
            if (stopped.ContainsKey(host))
                return Synthesized(request);
            if (slot.Last is { } last && Stopwatch.GetElapsedTime(last) is var since && since < MinInterval)
                await Task.Delay(MinInterval - since, cancellationToken);
            Interlocked.Increment(ref requests);
            try
            {
                response = await base.SendAsync(request, cancellationToken);
            }
            finally
            {
                slot.Last = Stopwatch.GetTimestamp();
            }

            if (Stop(response) is { } why)
            {
                if (stopped.TryAdd(host, why))
                    lock (refusals)
                        refusals.Add((host, why));
                if (why == ChallengeStop)
                {
                    response.Dispose();
                    return Synthesized(request);
                }
            }
        }
        finally
        {
            slot.Gate.Release();
        }

        var max = request.Options.TryGetValue(MaxResponseBytesOption, out var raised) ? raised : DefaultMaxResponseBytes;
        if (response.Content.Headers.ContentLength > max)
        {
            response.Dispose();
            throw new IOException($"the response is over {max} bytes");
        }
        var capped = new StreamContent(new CappedStream(await response.Content.ReadAsStreamAsync(cancellationToken), max));
        foreach (var header in response.Content.Headers)
            capped.Headers.TryAddWithoutValidation(header.Key, header.Value);
        response.Content = capped;
        return response;
    }

    // What stops the host, if anything.
    private static string? Stop(HttpResponseMessage response) =>
        response.Headers.Contains("x-amzn-waf-action")
            || (response.Headers.TryGetValues("cf-mitigated", out var mitigated) && mitigated.Any(v => v.Contains("challenge", StringComparison.OrdinalIgnoreCase)))
            || (response.StatusCode == HttpStatusCode.Accepted && response.Content.Headers.ContentLength is null or 0)
            ? ChallengeStop
        : response.StatusCode == HttpStatusCode.TooManyRequests ? "429"
        : response.StatusCode == HttpStatusCode.Forbidden ? "403"
        : null;

    private static HttpResponseMessage Synthesized(HttpRequestMessage request) =>
        new(HttpStatusCode.TooManyRequests) { RequestMessage = request, ReasonPhrase = "stopped by Silvergun", Content = new ByteArrayContent([]) };
    #endregion

    #region Fields
    public const long DefaultMaxResponseBytes = 8 * 1024 * 1024;

    /// <summary>A request option that raises (or lowers) the response body cap for that request.</summary>
    public static readonly HttpRequestOptionsKey<long> MaxResponseBytesOption = new("Silvergun.MaxResponseBytes");

    private const string ChallengeStop = "challenge";

    private readonly ConcurrentDictionary<string, Slot> slots = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> stopped = stops ?? new(StringComparer.Ordinal);
    private readonly List<(string Host, string Why)> refusals = [];
    private int requests;
    #endregion

    #region Types
    private sealed class Slot
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public long? Last { get; set; }
    }

    // A read-only stream that fails once more than `max` bytes have been read.
    private sealed class CappedStream(Stream inner, long max) : Stream
    {
        #region Properties
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => read; set => throw new NotSupportedException(); }
        #endregion

        #region Methods
        public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            Count(await inner.ReadAsync(buffer, cancellationToken));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                inner.Dispose();
            base.Dispose(disposing);
        }

        private int Count(int n)
        {
            read += n;
            return read > max ? throw new IOException($"the response is over {max} bytes") : n;
        }
        #endregion

        #region Fields
        private long read;
        #endregion
    }
    #endregion
}
