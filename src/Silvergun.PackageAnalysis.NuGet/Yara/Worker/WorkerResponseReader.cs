namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

/// <summary>
/// The parent's reader of a worker's stdout (worker protocol v1). The worker is <b>hostile</b>: every limit and
/// ordering rule of the contract is enforced here, and the first breach ends the stream with a
/// <see cref="WorkerStreamTerminal.Violation"/>, which is always distinguishable from a clean end
/// (<see cref="WorkerStreamTerminal.Done"/>) and from a stream that simply stopped (<see cref="WorkerStreamTerminal.Eof"/>).
/// Records accepted before the breach stay in <see cref="Results"/> (ADR 0032 partial findings); the record that broke
/// the contract is never accepted. Pull-based so the caller can run its own backstop clock between lines: call
/// <see cref="Next"/> until it returns <c>null</c>, or <see cref="ReadToEnd"/>. Not thread-safe.
///
/// <b>Callers must catch around <see cref="Next"/> and <see cref="ReadToEnd"/></b> (review N9). Every protocol breach
/// and every ordinary pipe failure (<see cref="IOException"/>, <see cref="ObjectDisposedException"/>,
/// <see cref="OperationCanceledException"/>) ends the stream as a terminal rather than an exception, but a fault outside
/// that set — another exception type out of the underlying stream, an out-of-memory condition — still propagates. A
/// caller must treat any exception as an incomplete stream (the files without an accepted result are unscanned), never
/// let it escape as a scan that happened; <c>YaraXWorkerScanner</c> does exactly that.
/// </summary>
public sealed class WorkerResponseReader
{
    #region Constructors
    /// <param name="workerStdout">The worker's standard output.</param>
    /// <param name="requestCount">n, the number of requests the parent sends (indices 0..n−1).</param>
    public WorkerResponseReader(Stream workerStdout, int requestCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(requestCount);
        lines = new WorkerLineReader(workerStdout);
        RequestCount = requestCount;
    }
    #endregion

    #region Properties
    public int RequestCount { get; }

    /// <summary>The accepted <c>ready</c> record; null until one arrives.</summary>
    public WorkerReady? Ready { get; private set; }

    /// <summary>The accepted results so far, in index order: an immutable snapshot, never changed by later reads.</summary>
    public IReadOnlyList<WorkerResult> Results => results;

    /// <summary>How the stream ended; null while it is still open.</summary>
    public WorkerStreamTerminal? Terminal { get; private set; }

    /// <summary>
    /// The outcome so far; its terminal is <see cref="WorkerStreamTerminal.Eof"/> while the stream is still open. O(1)
    /// (review N8): the results are held in an immutable list, so the snapshot shares it rather than copying it, and
    /// polling this after every line costs O(n) over a run, not O(n²).
    /// </summary>
    public WorkerStreamOutcome Outcome => new(Ready, results, Terminal ?? new WorkerStreamTerminal.Eof("stream still open"));
    #endregion

    #region Methods
    /// <summary>
    /// Reads and checks one line. Returns the accepted <see cref="WorkerReady"/> or <see cref="WorkerResult"/>, or
    /// <c>null</c> once the stream has ended (see <see cref="Terminal"/>); later calls return <c>null</c> without reading.
    /// </summary>
    public WorkerMessage? Next()
    {
        if (Terminal is not null)
            return null;

        var (status, bytes) = lines.ReadLine();
        if (status != WorkerLineStatus.Line)
            return End(LineTerminal(status, lines.MaxLineBytes));

        var (message, error) = Parse(bytes, WorkerJsonContext.Default.WorkerMessage);
        if (message is null)
            return End(new WorkerStreamTerminal.Violation(error!));

        return (message switch
        {
            WorkerReady ready => Accept(ready),
            WorkerResult result => Accept(result),
            WorkerDone done => Accept(done),
            WorkerFatal fatal => Accept(fatal),
            _ => "unknown record",
        }) is { } violation
            ? End(new WorkerStreamTerminal.Violation(violation))
            : Terminal is null ? message : null;
    }

    /// <summary>Reads to the terminal record or the end of the stream.</summary>
    public WorkerStreamOutcome ReadToEnd()
    {
        while (Next() is not null) { }
        return Outcome;
    }

    /// <summary>The terminal for a line read that produced no line.</summary>
    internal static WorkerStreamTerminal LineTerminal(WorkerLineStatus status, int maxLineBytes) => status switch
    {
        WorkerLineStatus.Eof => new WorkerStreamTerminal.Eof(),
        WorkerLineStatus.IoError => new WorkerStreamTerminal.Eof("read failed"),
        WorkerLineStatus.Truncated => new WorkerStreamTerminal.Violation("truncated line: the stream ended without a terminating newline"),
        WorkerLineStatus.TooLong => new WorkerStreamTerminal.Violation($"line exceeds {maxLineBytes} bytes"),
        WorkerLineStatus.InvalidUtf8 => new WorkerStreamTerminal.Violation("line is not valid UTF-8"),
        _ => new WorkerStreamTerminal.Violation("unexpected line status"),
    };

    /// <summary>One line as a <typeparamref name="T"/>, or null and a safe-to-log reason.</summary>
    internal static (T? Value, string? Error) Parse<T>(byte[] bytes, JsonTypeInfo<T> typeInfo) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize(bytes, typeInfo) is { } value
                ? (value, null)
                : (null, "record is JSON null");
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return (null, $"malformed record ({WorkerProtocol.Safe(ex.Message, ErrorChars)}): {WorkerLineReader.Excerpt(bytes)}");
        }
    }

    // Each Accept returns null when the record is valid in the current state (and applies it), else the violation.
    private string? Accept(WorkerReady ready) =>
        Ready is not null ? "a second ready"
        : ready.Protocol != WorkerProtocol.Version ? $"ready announces protocol {ready.Protocol}, expected {WorkerProtocol.Version}"
        : ready.RuleCount < 0 ? "ready has a negative ruleCount"
        : ready.RuleSourceErrors < 0 ? "ready has a negative ruleSourceErrors"
        : new[] { ready.Engine, ready.EngineVersion, ready.RulesSha256, ready.Canary }.Any(s => s.Length > WorkerProtocol.MaxNameChars)
            ? $"a ready field exceeds {WorkerProtocol.MaxNameChars} chars"
        : Apply(() => Ready = ready);

    private string? Accept(WorkerResult result) =>
        Ready is null ? "a result before ready"
        : result.Index < 0 || result.Index >= RequestCount ? $"result index {result.Index} out of range 0..{RequestCount - 1}"
        : result.Index != results.Count ? $"result index {result.Index} out of order (expected {results.Count})"
        : ResultShapeViolation(result) ?? Apply(() => results = results.Add(result));

    private string? Accept(WorkerDone done) =>
        Ready is null ? "done before ready"
        : done.Count != RequestCount ? $"done count {done.Count} but {RequestCount} requests were sent"
        : results.Count != RequestCount ? $"done after {results.Count} of {RequestCount} results"
        : Apply(() => Terminal = new WorkerStreamTerminal.Done(done));

    private string? Accept(WorkerFatal fatal) =>
        fatal.Reason.Length > WorkerProtocol.MaxReasonChars ? $"fatal reason exceeds {WorkerProtocol.MaxReasonChars} chars"
        : Apply(() => Terminal = new WorkerStreamTerminal.Fatal(WorkerProtocol.Safe(fatal.Reason)));

    private static string? ResultShapeViolation(WorkerResult result) =>
        result.Reason?.Length > WorkerProtocol.MaxReasonChars ? $"result {result.Index}: reason exceeds {WorkerProtocol.MaxReasonChars} chars"
        : result.Status == WorkerScanStatus.Scanned
            ? result.Reason is not null ? $"result {result.Index}: a scanned result carries a reason"
              : result.Hits is null ? $"result {result.Index}: a scanned result has no hits array"
              : result.Hits.Count > WorkerProtocol.MaxHitsPerFile ? $"result {result.Index}: more than {WorkerProtocol.MaxHitsPerFile} hits"
              : result.Hits.Select(HitViolation).FirstOrDefault(v => v is not null) is { } hit ? $"result {result.Index}: {hit}"
              : null
            : result.Hits is not null ? $"result {result.Index}: a {StatusName(result.Status)} result carries hits"
              : result.Reason is null ? $"result {result.Index}: a {StatusName(result.Status)} result has no reason"
              : null;

    // Elements of a JSON array are not covered by RespectNullableAnnotations, so a null hit or tag is checked here.
    private static string? HitViolation(WorkerHit? hit) =>
        hit is null ? "a null hit"
        : hit.Rule.Length == 0 ? "a hit with an empty rule name"
        : hit.Rule.Length > WorkerProtocol.MaxNameChars ? $"a rule name exceeds {WorkerProtocol.MaxNameChars} chars"
        : hit.Namespace.Length > WorkerProtocol.MaxNameChars ? $"a namespace exceeds {WorkerProtocol.MaxNameChars} chars"
        : hit.Tags.Count > WorkerProtocol.MaxTagsPerHit ? $"a hit has more than {WorkerProtocol.MaxTagsPerHit} tags"
        : hit.Tags.Any(t => t is null) ? "a null tag"
        : hit.Tags.Any(t => t.Length > WorkerProtocol.MaxNameChars) ? $"a tag exceeds {WorkerProtocol.MaxNameChars} chars"
        : null;

    private static string StatusName(WorkerScanStatus status) => status.ToString().ToLowerInvariant();

    private static string? Apply(Action accept)
    {
        accept();
        return null;
    }

    private WorkerMessage? End(WorkerStreamTerminal terminal)
    {
        Terminal = terminal;
        return null;
    }
    #endregion

    #region Fields
    private const int ErrorChars = 160;

    private readonly WorkerLineReader lines;
    private ImmutableList<WorkerResult> results = [];
    #endregion
}
