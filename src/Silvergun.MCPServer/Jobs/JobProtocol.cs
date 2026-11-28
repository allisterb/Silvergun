namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>How much analysis a job runs (task D3).</summary>
public enum JobDepth
{
    /// <summary>The <c>scan-package</c> passes.</summary>
    Standard,

    /// <summary>The standard passes plus reachability and SSA.</summary>
    Deep
}

/// <summary>
/// Job worker protocol v1 (task S1): the server starts <c>Silvergun.CLI __worker job --protocol 1</c>, writes one
/// <see cref="JobRequest"/> line to its stdin and keeps stdin open; the child answers on stdout with <c>ready</c>, any
/// number of <c>progress</c> records, then <c>done</c> or <c>fatal</c>, one JSON object per line. The child writes its
/// artifacts into the job directory before <c>done</c>; the server trusts none of them until it has checked them.
/// </summary>
public static class JobProtocol
{
    #region Properties
    /// <summary>The child's arguments after the CLI executable.</summary>
    public static IReadOnlyList<string> Arguments { get; } = ["__worker", "job", "--protocol", "1"];

    /// <summary>The serializer options for every record and artifact: camelCase, enums by name, compact.</summary>
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        WriteIndented = false,
    };

    /// <summary>How every artifact is parsed back: a duplicate key at any depth is invalid JSON, never a later throw.</summary>
    public static JsonDocumentOptions DocumentOptions { get; } = new() { AllowDuplicateProperties = false };
    #endregion

    #region Fields
    public const int Version = 1;

    public const int ExitDone = 0;
    public const int ExitFatal = 3;
    /// <summary>The child saw its stdin end: the server is gone.</summary>
    public const int ExitParentGone = 4;

    public const int MaxRequestLineBytes = 16 * 1024;
    public const int MaxRecordLineBytes = 16 * 1024;
    public const int MaxReasonChars = 400;

    public const string PackageFile = "package.nupkg";
    public const string FilesDir = "files";
    public const string ReportFile = "report.json";
    public const string GateFile = "gate.json";
    public const string SummaryFile = "summary.json";
    /// <summary>The inventory, one row per line (<see cref="RowFile"/>), as are the finding and reachability lists.</summary>
    public const string InventoryFile = "inventory.jsonl";
    public const string ReachabilityFile = "reachability.jsonl";
    /// <summary>Every method of every assembly the capability pass read, and their string constants (task S3).</summary>
    public const string MembersFile = "members.jsonl";
    public const string StringsFile = "strings.jsonl";
    /// <summary>The package's MSBuild integration facts (task S4).</summary>
    public const string MsBuildFile = "msbuild.jsonl";
    /// <summary>Network intel: project health, squat check, vulnerability status (task S5).</summary>
    public const string IntelFile = "intel.json";
    /// <summary>Each row file's count and cut, and each finding kind's pass status: written last of the child's artifacts.</summary>
    public const string IndexFile = "index.json";
    public const string JobFile = "job.json";
    #endregion
}

/// <summary>
/// Inspect worker protocol v1 (task S3): <c>__worker inspect --protocol 1</c> reads one <see cref="InspectRequest"/> line
/// and answers with <c>ready</c>, then <see cref="JobInspected"/> or <c>fatal</c>, on the job protocol's records. Its stdin
/// ending after the request means the server is gone.
/// </summary>
public static class InspectProtocol
{
    #region Properties
    public static IReadOnlyList<string> Arguments { get; } = ["__worker", "inspect", "--protocol", "1"];
    #endregion

    #region Fields
    public const int Version = 1;
    /// <summary>A result line: a listing within the bulk budget, each non-ASCII char as <c>\uXXXX</c>, with room.</summary>
    public const int MaxResultLineBytes = 256 * 1024;
    /// <summary>The least a listing page may be given: its bounded header and one bounded instruction always fit.</summary>
    public const int MinChars = 8_000;
    public const int MaxChars = 64 * 1024;
    #endregion
}

/// <summary>
/// The one request line: the job directory (holding <see cref="JobProtocol.PackageFile"/>), the depth, and whether the network may
/// be used (task S5). <see cref="StoppedHosts"/> are hosts the server has already seen refuse, which the child never asks;
/// <see cref="MinIntervalMs"/> is the child's spacing per host, scaled so all of the server's jobs together keep about one
/// request a second.
/// </summary>
public sealed record JobRequest(int Protocol, string JobDir, JobDepth Depth, bool Network, IReadOnlyList<string>? StoppedHosts = null, int MinIntervalMs = 1000);

/// <summary>An inspect request: list the method with MethodDef <see cref="Token"/> of <see cref="Assembly"/> (an absolute path) from IL offset <see cref="Offset"/>, in at most <see cref="MaxChars"/>.</summary>
public sealed record InspectRequest(int Protocol, string Assembly, uint Token, uint Offset, int MaxChars);

/// <summary>One record on the child's stdout.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(JobReady), "ready")]
[JsonDerivedType(typeof(JobProgress), "progress")]
[JsonDerivedType(typeof(JobDone), "done")]
[JsonDerivedType(typeof(JobFatal), "fatal")]
[JsonDerivedType(typeof(JobInspected), "inspected")]
public abstract record JobMessage;

/// <summary>
/// An inspect child's answer (<see cref="Silvergun.CodeAnalysis.IL.MethodListingPage"/>): whether the token names a method,
/// its names and listing already escaped for display, and the CCI assertions that failed while it was read. Not <c>Type</c>:
/// that is the records' discriminator.
/// </summary>
public sealed record JobInspected(bool Found, string? DeclaringType, string? Name, string? Id, Silvergun.CodeAnalysis.IL.MemberBody Body, uint IlBytes, int MaxStack,
    int Locals, int Instructions, int Shown, uint? Next, string Listing, int ReaderAssertions, int HandlersNotShown = 0) : JobMessage;

/// <summary>The child read a valid request and is starting.</summary>
public sealed record JobReady(int Protocol) : JobMessage;

/// <summary>A stage started, or moved on: <see cref="Done"/> of <see cref="Total"/> units finished.</summary>
public sealed record JobProgress(string Stage, int Done, int Total) : JobMessage;

/// <summary>Every artifact is written. Per-stage wall-clock times, in the order the stages ran.</summary>
public sealed record JobDone(long ElapsedMs, IReadOnlyList<JobStageTime> Stages) : JobMessage;

/// <summary>The job could not complete. <see cref="Reason"/> is escaped and bounded by the child, and checked again by the server.</summary>
public sealed record JobFatal(string Reason) : JobMessage;

/// <summary>How long one stage took.</summary>
public sealed record JobStageTime(string Stage, long ElapsedMs);
