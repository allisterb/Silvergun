namespace Silvergun.MCPServer.Jobs;

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;

using Silvergun.Intel;

/// <summary>
/// The server's one way onto the network (task S5): an <see cref="HttpClient"/> over <see cref="PoliteHttpHandler"/>, created on
/// first use from <paramref name="handler"/> (the test seam). Its stop set is the server's: hosts its own requests saw refuse,
/// and those its job children reported (<see cref="Stop"/>), so no job asks a host that refused an earlier one. When the server
/// runs with <c>--no-network</c> no client is ever created, and <see cref="Client"/> throws: a tool must refuse before it asks.
/// </summary>
public sealed class NetworkAccess(bool enabled, Func<HttpMessageHandler>? handler = null, TimeSpan? minInterval = null)
{
    #region Properties
    public bool Enabled { get; } = enabled;

    /// <summary>How many times the handler factory was called (0 or 1).</summary>
    public int HandlersCreated => created;

    /// <summary>The polite handler, once a client exists; null before.</summary>
    public PoliteHttpHandler? Polite => client?.Polite;

    /// <summary>Every host the server will not ask again, at most <see cref="MaxStops"/>.</summary>
    public IReadOnlyList<string> StoppedHosts => [.. stops.Keys.Where(h => hostPattern.IsMatch(h)).Order(StringComparer.Ordinal).Take(MaxStops)];
    #endregion

    #region Methods
    /// <summary>The shared client. Throws when the network is off.</summary>
    public HttpClient Client()
    {
        if (!Enabled)
            throw new InvalidOperationException("the network is off (--no-network)");
        return LazyInitializer.EnsureInitialized(ref client, ref sync, () =>
        {
            Interlocked.Increment(ref created);
            var polite = new PoliteHttpHandler((handler ?? DefaultHandler)(), minInterval, stops);
            return new Shared(new HttpClient(polite) { Timeout = RequestTimeout }, polite);
        }).Http;
    }

    /// <summary>Records a host a job child saw refuse; ignored past <see cref="MaxStops"/> or for a malformed host.</summary>
    public void Stop(string host, string why)
    {
        if (stops.Count < MaxStops && hostPattern.IsMatch(host))
            stops.TryAdd(host.ToLowerInvariant(), why);
    }

    /// <summary>
    /// A fresh handler with Silvergun's transport settings: no cookies, no redirects (a hop would skip the per-host spacing, the
    /// stop set and the host checks; a 3xx is a failure), bounded connect time.
    /// </summary>
    public static HttpMessageHandler DefaultHandler() => new SocketsHttpHandler
    {
        UseCookies = false,
        AllowAutoRedirect = false,
        AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    };
    #endregion

    #region Fields
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(60);
    public const int MaxStops = 64;

    private static readonly System.Text.RegularExpressions.Regex hostPattern =
        new(@"\A[A-Za-z0-9.-]{1,253}\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private readonly ConcurrentDictionary<string, string> stops = new(StringComparer.Ordinal);
    private Shared? client;
    private object? sync;
    private int created;
    #endregion

    #region Types
    private sealed record Shared(HttpClient Http, PoliteHttpHandler Polite);
    #endregion
}
