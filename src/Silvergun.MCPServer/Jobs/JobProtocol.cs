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
    /// <summary>Each row file's count and cut, and each finding kind's pass status: written last of the child's artifacts.</summary>
    public const string IndexFile = "index.json";
    public const string JobFile = "job.json";
    #endregion
}

/// <summary>The one request line: the job directory (holding <see cref="JobProtocol.PackageFile"/>), the depth, and whether OSV may run.</summary>
public sealed record JobRequest(int Protocol, string JobDir, JobDepth Depth, bool Network);

/// <summary>One record on the child's stdout.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(JobReady), "ready")]
[JsonDerivedType(typeof(JobProgress), "progress")]
[JsonDerivedType(typeof(JobDone), "done")]
[JsonDerivedType(typeof(JobFatal), "fatal")]
public abstract record JobMessage;

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
