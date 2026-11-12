namespace Silvergun.PackageAnalysis.NuGet.Graph;

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// The constants of graph worker protocol v2 (<c>docs/agent/tasks/graph-worker.md</c>, G2; <c>ssa-facts-s4.md</c> §4): one
/// request line from the parent, then <c>ready</c>, one <c>folder</c> record per requested folder in order, and <c>done</c>
/// from the worker. When the request carries <c>ssa</c> bounds, each <c>folder</c> record is followed by that folder's
/// <c>ssa</c> record; without them the records are v1's.
/// </summary>
public static class GraphWorkerProtocol
{
    #region Properties
    /// <summary>The worker's launch arguments after the executable.</summary>
    public static IReadOnlyList<string> Arguments { get; } = ["__worker", "graph", "--protocol", "2"];
    #endregion

    #region Fields
    /// <summary>The protocol version this build speaks.</summary>
    public const int Version = 2;

    /// <summary>Exit code after <c>done</c>.</summary>
    public const int ExitDone = 0;

    /// <summary>Exit code after <c>fatal</c>.</summary>
    public const int ExitFatal = 3;

    /// <summary>Exit code when stdin ended or carried more than the request: the parent is gone or has given up.</summary>
    public const int ExitParentGone = 4;

    /// <summary>Max bytes in the request line, excluding its <c>\n</c> (64 MiB).</summary>
    public const int MaxRequestLineBytes = 64 * 1024 * 1024;

    /// <summary>
    /// Max bytes in one worker record, excluding its <c>\n</c> (16 MiB). <see cref="Reachability"/> bounds a report's
    /// counts (paths of at most <see cref="Reachability.MaxPathHops"/> hops, three examples per class and sink, 64 profiles
    /// per class) and each name (<see cref="Reachability.MaxNameChars"/>), which bounds a report but not under this
    /// limit (8 classes × 12 sinks × 3 examples × 64 hops of two bounded names is ~40 M chars), nor the record's
    /// assembly and load-failure lists: a record over this is not sent, and the worker sends <c>fatal</c> instead, so
    /// that folder is Crashed, never silently cut.
    /// </summary>
    public const int MaxRecordLineBytes = 16 * 1024 * 1024;

    /// <summary>Max chars in a <c>fatal</c> reason.</summary>
    public const int MaxReasonChars = 512;
    #endregion
}

/// <summary>
/// A worker → parent record of graph worker protocol v1: one JSON object per <c>\n</c>-terminated line, discriminated by
/// its leading <c>"type"</c>. The parent reads them through <see cref="GraphWorkerProcess"/>, which bounds and checks them;
/// every string in them is raw (attacker-shaped metadata names): escape before logging.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(GraphWorkerReady), "ready")]
[JsonDerivedType(typeof(GraphWorkerFolder), "folder")]
[JsonDerivedType(typeof(GraphWorkerSsa), "ssa")]
[JsonDerivedType(typeof(GraphWorkerDone), "done")]
[JsonDerivedType(typeof(GraphWorkerFatal), "fatal")]
public abstract record GraphWorkerMessage;

/// <summary><c>ready</c>: the request was read and is valid; <see cref="Folders"/> folder records follow.</summary>
public sealed record GraphWorkerReady(int Protocol, int Folders) : GraphWorkerMessage;

/// <summary>
/// <c>folder</c>: request folder <see cref="Index"/>'s graph pass, as <see cref="PackageGraphs"/> builds it: the
/// assemblies loaded, the ones that were not and why, and the reachability report (null exactly when nothing loaded).
/// <see cref="Nodes"/> and <see cref="Edges"/> are the graph's size, 0 without a graph.
/// </summary>
public sealed record GraphWorkerFolder(
    int Index,
    string Folder,
    IReadOnlyList<string> Assemblies,
    IReadOnlyList<PackageGraphLoadFailure> LoadFailures,
    ReachabilityReport? Report,
    int Nodes,
    int Edges) : GraphWorkerMessage;

/// <summary>
/// <c>ssa</c>: request folder <see cref="Index"/>'s SSA facts (ADR 0038), sent after its <c>folder</c> record when the
/// request asked for them. The worker sends <see cref="SsaFolderOutcome.Analyzed"/> with <see cref="Facts"/>, or
/// <see cref="SsaFolderOutcome.NotRun"/> or <see cref="SsaFolderOutcome.Crashed"/> with a <see cref="Reason"/> (escaped and
/// bounded by the worker) and no facts.
/// </summary>
public sealed record GraphWorkerSsa(int Index, SsaFolderOutcome Outcome, SsaFolderFacts? Facts, string? Reason) : GraphWorkerMessage;

/// <summary><c>done</c>: every folder was answered; the worker exits 0.</summary>
public sealed record GraphWorkerDone(int Count) : GraphWorkerMessage;

/// <summary><c>fatal</c>: the worker cannot go on and exits 3. <see cref="Reason"/> is escaped and bounded by the worker.</summary>
public sealed record GraphWorkerFatal(string Reason) : GraphWorkerMessage;

/// <summary>
/// The parent → worker request: the folders of one package to build, in order, the per-folder graph budget, and the SSA
/// fact bounds when SSA facts are wanted (null: off, and the worker sends v1's records).
/// </summary>
public sealed record GraphWorkerRequest(int Protocol, GraphWorkerBudget Budget, IReadOnlyList<GraphWorkerFolderRequest> Folders, GraphWorkerSsaBounds? Ssa = null);

/// <summary>A <see cref="SsaFactBounds"/> on the wire, its folder time in milliseconds.</summary>
public sealed record GraphWorkerSsaBounds(
    int MaxSites,
    int MaxArguments,
    int MaxAlternatives,
    int MaxPhiDepth,
    int MaxPhiInputs,
    int MaxTextChars,
    int MaxFactTextChars,
    int MaxLiftedMethods,
    long FolderTimeMilliseconds,
    int MaxCandidates)
{
    #region Methods
    /// <summary>The wire form of <paramref name="bounds"/>.</summary>
    public static GraphWorkerSsaBounds Of(SsaFactBounds bounds) => new(bounds.MaxSites, bounds.MaxArguments, bounds.MaxAlternatives, bounds.MaxPhiDepth,
        bounds.MaxPhiInputs, bounds.MaxTextChars, bounds.MaxFactTextChars, bounds.MaxLiftedMethods, (long)Math.Ceiling(bounds.FolderTime.TotalMilliseconds), bounds.MaxCandidates);

    /// <summary>These bounds as a <see cref="SsaFactBounds"/>; throws when one is not positive.</summary>
    public SsaFactBounds ToBounds() => new SsaFactBounds
    {
        MaxSites = MaxSites,
        MaxArguments = MaxArguments,
        MaxAlternatives = MaxAlternatives,
        MaxPhiDepth = MaxPhiDepth,
        MaxPhiInputs = MaxPhiInputs,
        MaxTextChars = MaxTextChars,
        MaxFactTextChars = MaxFactTextChars,
        MaxLiftedMethods = MaxLiftedMethods,
        FolderTime = TimeSpan.FromMilliseconds(Math.Min(FolderTimeMilliseconds, MaxFolderTimeMilliseconds)),
        MaxCandidates = MaxCandidates,
    }.Validated();
    #endregion

    #region Fields
    // A year: longer is no bound at all, and TimeSpan cannot hold every long of milliseconds.
    private const long MaxFolderTimeMilliseconds = 365L * 24 * 60 * 60 * 1000;
    #endregion
}

/// <summary>A <see cref="GraphBudget"/> on the wire.</summary>
public sealed record GraphWorkerBudget(int MaxNodes, int MaxEdges, long MaxDispatchWork)
{
    #region Methods
    /// <summary>The wire form of <paramref name="budget"/>.</summary>
    public static GraphWorkerBudget Of(GraphBudget budget) => new(budget.MaxNodes, budget.MaxEdges, budget.MaxDispatchWork);

    /// <summary>This budget as a <see cref="GraphBudget"/>.</summary>
    public GraphBudget ToBudget() => new(MaxNodes, MaxEdges, MaxDispatchWork);
    #endregion
}

/// <summary>One folder to build: its package path and its assemblies, in the order <see cref="PackageGraphs"/> loads them.</summary>
public sealed record GraphWorkerFolderRequest(string Folder, IReadOnlyList<GraphWorkerAssembly> Assemblies);

/// <summary>An assembly of a folder: its path inside the package and its absolute path on disk.</summary>
public sealed record GraphWorkerAssembly(string RelativePath, string FullPath);

/// <summary>
/// Writes protocol records and requests as compact JSON lines, UTF-8 without a BOM, each handed to the stream in one write
/// and flushed. A record is serialized whole before anything is written, so one that cannot be (a string that is not
/// well-formed UTF-16, or a line over <paramref name="maxLineBytes"/>) throws and writes nothing. Not thread-safe.
/// </summary>
internal sealed class GraphWorkerWriter(Stream stream, int maxLineBytes)
{
    #region Methods
    public void Write(GraphWorkerMessage message) => WriteLine(message, GraphWorkerJsonContext.Default.GraphWorkerMessage);

    public void Write(GraphWorkerRequest request) => WriteLine(request, GraphWorkerJsonContext.Default.GraphWorkerRequest);

    private void WriteLine<T>(T value, JsonTypeInfo<T> typeInfo)
    {
        buffer.ResetWrittenCount();
        try
        {
            using (var json = new Utf8JsonWriter(buffer))
                JsonSerializer.Serialize(json, value, typeInfo);
            if (buffer.WrittenCount > maxLineBytes)
                throw new InvalidDataException($"the record is {buffer.WrittenCount} bytes, over the protocol's {maxLineBytes}");
            buffer.Write("\n"u8);
            stream.Write(buffer.WrittenSpan);
            stream.Flush();
        }
        finally
        {
            // One huge record must not pin its buffer for the rest of the session.
            if (buffer.Capacity > KeptBufferBytes)
                buffer = new();
        }
    }
    #endregion

    #region Fields
    private const int KeptBufferBytes = 1024 * 1024;

    private ArrayBufferWriter<byte> buffer = new();
    #endregion
}

/// <summary>
/// An enum on the wire as exactly one of its defined names: never an integer, another letter case, or a comma-joined
/// flags combination (the reason ADR 0033 kept <see cref="JsonStringEnumConverter"/> off its protocol). Writing a value
/// that is no single defined member throws, so the record is not sent.
/// </summary>
internal sealed class ExactEnumConverter<T> : JsonConverter<T> where T : struct, Enum
{
    #region Methods
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String && reader.GetString() is { } name && byName.TryGetValue(name, out var value)
            ? value
            : throw new JsonException($"not a {typeof(T).Name} name");

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) =>
        writer.WriteStringValue(byValue.TryGetValue(value, out var name) ? name : throw new JsonException($"{value} is not a single {typeof(T).Name} member"));
    #endregion

    #region Fields
    private static readonly Dictionary<string, T> byName = Enum.GetNames<T>().ToDictionary(n => n, Enum.Parse<T>, StringComparer.Ordinal);
    // An aliased value writes as one fixed name of it, and reads from any.
    private static readonly Dictionary<T, string> byValue = byName.GroupBy(p => p.Value).ToDictionary(g => g.Key, g => g.First().Key);
    #endregion
}

/// <summary>
/// Strings on the wire must be well-formed UTF-16: one that is not (a lone surrogate) throws on writing, so the record is
/// not sent, rather than being silently replaced with U+FFFD and so differing from what was analysed.
/// </summary>
internal sealed class WellFormedStringConverter : JsonConverter<string>
{
    #region Methods
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String ? reader.GetString() : throw new JsonException("not a string");

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) =>
        writer.WriteStringValue(WorkerProtocol.IsWellFormedUtf16(value) ? value : throw new JsonException("a string is not well-formed UTF-16"));
    #endregion
}

/// <summary>
/// Source-generated serialization for the protocol, strict by configuration: unknown members, missing constructor
/// parameters, nulls in non-nullable members and duplicate properties are errors; names match case-sensitively; the
/// <c>"type"</c> discriminator must come first; nulls are written, never omitted (but a member with a default, such as
/// <see cref="GraphWorkerRequest.Ssa"/>, <see cref="SsaConstant.Cut"/> or <see cref="SsaSinkFact.Target"/>, may be
/// absent and reads as that default); enums are exact names
/// (<see cref="ExactEnumConverter{T}"/>) and strings well-formed (<see cref="WellFormedStringConverter"/>). Computed
/// (get-only) properties such as <see cref="IndexCoverage.IsComplete"/> are not written.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    IgnoreReadOnlyProperties = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    AllowDuplicateProperties = false,
    MaxDepth = 16,
    Converters =
    [
        typeof(WellFormedStringConverter),
        typeof(ExactEnumConverter<RootClass>),
        typeof(ExactEnumConverter<RootClassVerdict>),
        typeof(ExactEnumConverter<Capability>),
        typeof(ExactEnumConverter<ReachEvidence>),
        typeof(ExactEnumConverter<MethodEdgeKind>),
        typeof(ExactEnumConverter<OpacityKind>),
        typeof(ExactEnumConverter<SsaFolderOutcome>),
        typeof(ExactEnumConverter<SsaSiteStatus>),
        typeof(ExactEnumConverter<SsaValueKind>),
        typeof(ExactEnumConverter<SsaConstantKind>),
        typeof(ExactEnumConverter<SsaDynamicOrigin>),
        typeof(ExactEnumConverter<SsaFailureKind>),
        typeof(ExactEnumConverter<SsaTargetKind>),
        typeof(ExactEnumConverter<SsaCandidateMatch>),
    ])]
[JsonSerializable(typeof(GraphWorkerMessage))]
[JsonSerializable(typeof(GraphWorkerRequest))]
internal sealed partial class GraphWorkerJsonContext : JsonSerializerContext;
