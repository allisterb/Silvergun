namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Globalization;
using System.Text.Json;

/// <summary>
/// The engine behind <c>__worker yara</c>: set up once, then answer one request at a time on a single thread.
/// </summary>
public interface IYaraWorkerEngine
{
    /// <summary>Loads the rules and runs the canary: a <see cref="WorkerReady"/>, or a <see cref="WorkerFatal"/> on failure.</summary>
    WorkerMessage Start();

    /// <summary>The result for <paramref name="request"/>; its <see cref="WorkerResult.Index"/> is the request's.</summary>
    WorkerResult Scan(WorkerRequest request);
}

/// <summary>
/// The T1 stand-in engine (ADR 0033): no rules, no canary, no scanning, and no reference to any analysis code. Every
/// request is answered <c>skipped</c> with reason <c>no engine</c>. A test double only: production runs
/// <see cref="YaraWorkerEngines.ForPlatform"/>, and the parent never treats a stub's run as scanned (amendment G1).
/// </summary>
public sealed class StubYaraWorkerEngine : IYaraWorkerEngine
{
    #region Methods
    public WorkerMessage Start() =>
        new WorkerReady(WorkerProtocol.Version, "stub", EngineVersion: "", RuleCount: 0, RulesSha256: "", WorkerProtocol.CanarySkipped);

    public WorkerResult Scan(WorkerRequest request) => new(request.Index, WorkerScanStatus.Skipped, "no engine");
    #endregion
}

/// <summary>
/// The worker side of worker protocol v1 (ADR 0033 FINAL FORM): the loop behind the hidden <c>__worker yara</c> CLI
/// verb. stdout carries protocol records only; diagnostics go to the (capped, stderr-only) runtime logger. Kept out of
/// the CLI so it runs, and is testable, over any pair of streams.
///
/// <para>Every record it writes is within the contract whatever the engine returns (amendment G6): a result the
/// contract cannot carry — too many hits, an over-long or ill-formed field, an undefined status, a line over
/// <see cref="WorkerProtocol.MaxResultLineBytes"/> — is sent as that file's <c>error</c>, never as an out-of-contract line
/// and never as <c>scanned</c>. No exception other than an out-of-memory condition ever leaves <c>Run</c> (amendment
/// W-C): anything that goes wrong after the arguments are read ends the session with <c>fatal</c> where stdout still
/// takes it, and with <see cref="WorkerProtocol.ExitFatal"/> either way.</para>
/// </summary>
public static class YaraWorker
{
    #region Methods
    /// <summary>
    /// Runs one worker session with <paramref name="engine"/>, which the caller owns, and the default timeout. See
    /// <see cref="Run(string?, string?, Stream, Stream, Func{int, IYaraWorkerEngine})"/>.
    /// </summary>
    public static int Run(string? protocol, Stream stdin, Stream stdout, IYaraWorkerEngine engine) =>
        Run(protocol, timeout: null, stdin, stdout, _ => engine, disposeEngine: false);

    /// <summary>
    /// Runs one worker session: <c>ready</c> (or <c>fatal</c>), one <c>result</c> per request in order, then <c>done</c>.
    /// <paramref name="timeout"/> is the <c>--timeout</c> value: whole seconds in [<see cref="WorkerProtocol.MinTimeoutSeconds"/>,
    /// <see cref="WorkerProtocol.MaxTimeoutSeconds"/>], or <c>null</c> for <see cref="WorkerProtocol.DefaultTimeoutSeconds"/>
    /// (amendments G3, (i), W-D). The engine is created by <paramref name="createEngine"/> with that timeout, after the
    /// arguments are checked, and disposed at the end when it is <see cref="IDisposable"/>. Returns
    /// <see cref="WorkerProtocol.ExitDone"/>, or <see cref="WorkerProtocol.ExitFatal"/> after a <c>fatal</c> — for an
    /// unsupported <paramref name="protocol"/>, an invalid <paramref name="timeout"/>, an engine that cannot be created or
    /// fails (or throws) on start, a malformed request stream, stdin that cannot be read, or any other failure (W-C) — or
    /// when stdout can no longer be written. Never throws, except for an out-of-memory condition.
    /// </summary>
    public static int Run(string? protocol, string? timeout, Stream stdin, Stream stdout, Func<int, IYaraWorkerEngine> createEngine) =>
        Run(protocol, timeout, stdin, stdout, createEngine, disposeEngine: true);

    private static int Run(string? protocol, string? timeout, Stream stdin, Stream stdout, Func<int, IYaraWorkerEngine> createEngine, bool disposeEngine)
    {
        var writer = new WorkerProtocolWriter(stdout);
        IYaraWorkerEngine? engine = null;
        try
        {
            if (protocol != SupportedProtocol)
                return Fatal(writer, protocol is null
                    ? $"missing --protocol; this build speaks {WorkerProtocol.Version}"
                    : $"unsupported protocol '{WorkerProtocol.Safe(protocol, ArgumentChars)}'; this build speaks {WorkerProtocol.Version}");

            if (TimeoutSeconds(timeout) is not { } seconds)
                return Fatal(writer, $"invalid --timeout '{WorkerProtocol.Safe(timeout, ArgumentChars)}'; expected whole seconds from {WorkerProtocol.MinTimeoutSeconds} to {WorkerProtocol.MaxTimeoutSeconds}");

            WorkerMessage start;
            try
            {
                engine = createEngine(seconds);
                start = engine.Start();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return Fatal(writer, $"the engine failed to start: {ex.GetType().Name}: {ex.Message}");
            }

            switch (start)
            {
                case WorkerFatal fatal:
                    return Fatal(writer, fatal.Reason);
                case WorkerReady ready when ReadyProblem(ready) is { } problem:
                    return Fatal(writer, "the engine's ready record is out of contract: " + problem);
                case WorkerReady ready:
                    writer.Write(ready);
                    break;
                default:
                    return Fatal(writer, $"the engine answered start with a '{start.GetType().Name}' record");
            }

            var requests = new WorkerRequestReader(stdin);
            while (requests.Next() is { } request)
                writer.Write(ScanOne(engine, request));

            switch (requests.Terminal)
            {
                case WorkerStreamTerminal.Violation violation:
                    return Fatal(writer, "malformed request stream: " + violation.Reason);
                case WorkerStreamTerminal.Eof { Detail: { } detail }:
                    return Fatal(writer, "could not read the request stream: " + detail);
            }

            writer.Write(new WorkerDone(requests.Count));
            return WorkerProtocol.ExitDone;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // W-C, widening (p): the writer refusing an ill-formed string (ArgumentException), serialization failing
            // (JsonException), the engine, the request reader or the pipe — whatever it is, the session ends as fatal.
            return TryFatal(writer, $"the worker failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            if (disposeEngine)
                DisposeQuietly(engine);
        }
    }

    /// <summary>
    /// The <c>--timeout</c> value in seconds: <see cref="WorkerProtocol.DefaultTimeoutSeconds"/> when absent, <c>null</c>
    /// when it is not whole seconds in [<see cref="WorkerProtocol.MinTimeoutSeconds"/>, <see cref="WorkerProtocol.MaxTimeoutSeconds"/>].
    /// </summary>
    internal static int? TimeoutSeconds(string? timeout) =>
        timeout is null ? WorkerProtocol.DefaultTimeoutSeconds
        : int.TryParse(timeout, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
          && seconds is >= WorkerProtocol.MinTimeoutSeconds and <= WorkerProtocol.MaxTimeoutSeconds ? seconds
        : null;

    // An engine that throws costs that one file (an error result), never the protocol stream.
    private static WorkerResult ScanOne(IYaraWorkerEngine engine, WorkerRequest request)
    {
        try
        {
            return Conform(engine.Scan(request), request.Index);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Error(request.Index, $"engine error: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // G6: the record to send for `result`, always within the contract. Only a `scanned` whose hits all fit (count, field
    // lengths, well-formed text, and the whole line: "G4 vs (h)", at most MaxResultLineBytes) stays `scanned`; any other
    // `scanned`, and any status the protocol has no name for, becomes this file's `error`. A non-scanned result always
    // carries an escaped, bounded reason and never hits.
    private static WorkerResult Conform(WorkerResult? result, int index)
    {
        if (result is null)
            return Error(index, "the engine returned no result");
        if (!Enum.IsDefined(result.Status))
            return Error(index, $"the engine returned an undefined status ({(int)result.Status})");
        if (result.Status != WorkerScanStatus.Scanned)
            return result with { Index = index, Reason = WorkerProtocol.Safe(string.IsNullOrEmpty(result.Reason) ? "no reason given" : result.Reason), Hits = null };

        var scanned = result with { Index = index, Reason = null };
        var problem = HitsProblem(scanned.Hits)
            ?? (LineBytes(scanned) > WorkerProtocol.MaxResultLineBytes ? $"the result line would exceed {WorkerProtocol.MaxResultLineBytes} bytes" : null);
        return problem is null ? scanned
            : Error(index, "the matches cannot be reported within the protocol's limits, so the file is not reported as scanned: " + problem);
    }

    // Null when every hit fits the contract; otherwise which limit the hits break.
    private static string? HitsProblem(IReadOnlyList<WorkerHit>? hits)
    {
        if (hits is null)
            return "the engine reported a scan without a hit list";
        if (hits.Count > WorkerProtocol.MaxHitsPerFile)
            return $"{hits.Count} hits, over the limit of {WorkerProtocol.MaxHitsPerFile} per file";

        for (var i = 0; i < hits.Count; i++)
        {
            var hit = hits[i];
            var problem = hit is null ? "is missing"
                : hit.Rule is not { Length: > 0 } ? "has no rule name"
                : !Fits(hit.Rule) ? "has a rule name that is too long or ill-formed"
                : hit.Namespace is null || !Fits(hit.Namespace) ? "has a namespace that is too long or ill-formed"
                : hit.Tags is null ? "has no tag list"
                : hit.Tags.Count > WorkerProtocol.MaxTagsPerHit ? $"has {hit.Tags.Count} tags, over the limit of {WorkerProtocol.MaxTagsPerHit}"
                : !hit.Tags.All(t => t is not null && Fits(t)) ? "has a tag that is too long or ill-formed"
                : null;
            if (problem is not null)
                return $"hit {i} {problem} (limit {WorkerProtocol.MaxNameChars} UTF-16 code units per name)";
        }
        return null;
    }

    // Contract (c)/(d) for the one ready record the engine produced.
    private static string? ReadyProblem(WorkerReady ready) =>
        ready.Protocol != WorkerProtocol.Version ? $"protocol {ready.Protocol}"
        : ready.RuleCount < 0 ? "a negative rule count"
        : ready.RuleSourceErrors < 0 ? "a negative rule source error count"
        : new[] { ready.Engine, ready.EngineVersion, ready.RulesSha256, ready.Canary }.All(s => s is not null && Fits(s)) ? null
        : "a field that is missing, too long or ill-formed";

    private static bool Fits(string text) => text.Length <= WorkerProtocol.MaxNameChars && WellFormed(text);

    // Every surrogate is part of a pair: the text has an exact UTF-8 encoding (the writer must never substitute U+FFFD).
    private static bool WellFormed(string text)
    {
        for (var i = 0; i < text.Length; i++)
            if (char.IsSurrogate(text[i]) && !(char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[++i])))
                return false;
        return true;
    }

    // The record's UTF-8 length on the wire, excluding its \n (the same serializer and options as WorkerProtocolWriter).
    // A hit-less result is a few dozen bytes, so only one with hits is measured.
    private static long LineBytes(WorkerResult result) =>
        result.Hits is not { Count: > 0 } ? 0 : JsonSerializer.SerializeToUtf8Bytes<WorkerMessage>(result, WorkerJsonContext.Default.WorkerMessage).LongLength;

    private static WorkerResult Error(int index, string reason) => new(index, WorkerScanStatus.Error, WorkerProtocol.Safe(reason));

    private static int Fatal(WorkerProtocolWriter writer, string reason)
    {
        var safe = WorkerProtocol.Safe(reason);
        Runtime.Error("yara worker: fatal: {0}", safe);
        writer.Write(new WorkerFatal(safe));
        return WorkerProtocol.ExitFatal;
    }

    // W-C: a fatal that may itself fail (stdout gone, or whatever broke the session breaks this too). Never throws, except
    // for an out-of-memory condition; the exit code is the fatal one either way.
    private static int TryFatal(WorkerProtocolWriter writer, string reason)
    {
        try
        {
            return Fatal(writer, reason);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Quietly(() => Runtime.Error("yara worker: cannot write to stdout ({0}).", ex.GetType().Name));
            return WorkerProtocol.ExitFatal;
        }
    }

    private static void DisposeQuietly(IYaraWorkerEngine? engine) =>
        Quietly(() => (engine as IDisposable)?.Dispose());

    // Runs a cleanup or last-resort log step whose own failure must not replace the session's exit code.
    private static void Quietly(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            /* nothing more can be reported: stdout is the protocol's, and the logger is what failed or is not needed */
        }
    }
    #endregion

    #region Fields
    private const string SupportedProtocol = "1";
    private const int ArgumentChars = 32;
    #endregion
}
