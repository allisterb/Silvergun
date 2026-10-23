namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// A worker → parent record of worker protocol v1 (ADR 0033; the contract is <c>docs/agent/tasks/yarax-worker.md</c>).
/// One JSON object per <c>\n</c>-terminated line, discriminated by its leading <c>"type"</c> property. Reading these
/// from a worker's stdout goes through <see cref="WorkerResponseReader"/>, which enforces the contract's limits;
/// never deserialize them directly from untrusted output.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(WorkerReady), "ready")]
[JsonDerivedType(typeof(WorkerFatal), "fatal")]
[JsonDerivedType(typeof(WorkerResult), "result")]
[JsonDerivedType(typeof(WorkerDone), "done")]
public abstract record WorkerMessage;

/// <summary>
/// <c>{"type":"ready",...}</c>: the rules are loaded and the canary has run. Always the first record. <see cref="Canary"/>
/// is <see cref="WorkerProtocol.CanaryPassed"/> for a real engine; the T1 stub sends <see cref="WorkerProtocol.CanarySkipped"/>.
/// </summary>
public sealed record WorkerReady(
    int Protocol, string Engine, string EngineVersion, int RuleCount, string RulesSha256, string Canary) : WorkerMessage
{
    #region Properties
    /// <summary>
    /// <c>ruleSourceErrors</c> (amendment G1, 2026-10-22 (e)): how many rule sources had compile errors or were dropped,
    /// ≥ 0. Required on the wire (a <c>ready</c> without it is malformed); the parent trusts a run only when it is 0. Not a
    /// positional parameter so that existing constructions keep compiling; an engine that loads rules must set it.
    /// </summary>
    [JsonRequired]
    public int RuleSourceErrors { get; init; }
    #endregion
}

/// <summary><c>{"type":"fatal","reason":...}</c>: the worker cannot continue and exits 3. <see cref="Reason"/> is escaped and bounded by the sender.</summary>
public sealed record WorkerFatal(string Reason) : WorkerMessage;

/// <summary>
/// <c>{"type":"result",...}</c>: the outcome for the request with the same <see cref="Index"/>. <see cref="Hits"/> is
/// present (possibly empty) only when <see cref="Status"/> is <see cref="WorkerScanStatus.Scanned"/>; <see cref="Reason"/>
/// is present exactly when it is not. Both are raw worker output: escape before logging.
/// </summary>
public sealed record WorkerResult(int Index, WorkerScanStatus Status, string? Reason = null, IReadOnlyList<WorkerHit>? Hits = null) : WorkerMessage;

/// <summary><c>{"type":"done","count":n}</c>: every request has been answered; the worker exits 0.</summary>
public sealed record WorkerDone(int Count) : WorkerMessage;

/// <summary>One rule match inside a <see cref="WorkerResult"/>.</summary>
public sealed record WorkerHit(string Rule, string Namespace, IReadOnlyList<string> Tags);

/// <summary>A parent → worker request, <c>{"index":i,"path":"&lt;full path&gt;"}</c>, with <c>i</c> = 0..n−1 in order.</summary>
public sealed record WorkerRequest(int Index, string Path);

/// <summary>The per-file outcome of a <see cref="WorkerResult"/>, serialized as its exact lower-case name.</summary>
[JsonConverter(typeof(WorkerScanStatusConverter))]
public enum WorkerScanStatus
{
    Scanned,
    Timeout,
    Error,
    Skipped,
}

/// <summary>
/// Exact-name converter for <see cref="WorkerScanStatus"/>. Deliberately not <see cref="JsonStringEnumConverter"/>,
/// which also accepts integers, any letter case and comma-joined names: the protocol admits exactly four strings.
/// </summary>
internal sealed class WorkerScanStatusConverter : JsonConverter<WorkerScanStatus>
{
    #region Methods
    public override WorkerScanStatus Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String
            ? reader.GetString() switch
            {
                "scanned" => WorkerScanStatus.Scanned,
                "timeout" => WorkerScanStatus.Timeout,
                "error" => WorkerScanStatus.Error,
                "skipped" => WorkerScanStatus.Skipped,
                _ => throw new JsonException("unknown status"),
            }
            : throw new JsonException("status is not a string");

    public override void Write(Utf8JsonWriter writer, WorkerScanStatus value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value switch
        {
            WorkerScanStatus.Scanned => "scanned",
            WorkerScanStatus.Timeout => "timeout",
            WorkerScanStatus.Error => "error",
            WorkerScanStatus.Skipped => "skipped",
            _ => throw new JsonException("unknown status"),
        });
    #endregion
}

/// <summary>
/// Source-generated serialization for the protocol. Strict by configuration: unknown members, missing constructor
/// parameters, nulls in non-nullable members and duplicate properties are all errors; property names are matched
/// case-sensitively; the <c>"type"</c> discriminator must come first.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    AllowDuplicateProperties = false,
    MaxDepth = 8)]
[JsonSerializable(typeof(WorkerMessage))]
[JsonSerializable(typeof(WorkerRequest))]
internal sealed partial class WorkerJsonContext : JsonSerializerContext;
