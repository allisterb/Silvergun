namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>
/// What <c>--strict</c> and the incompleteness gate decide for a package (task D8), computed by the CLI's own exit-code
/// seam in the job child. <see cref="StrictReasons"/> are fixed tokens (<see cref="YaraReason"/> and the others);
/// <see cref="Caveats"/> may quote package text and paths: they are bounded but raw here, and the summary strips host paths
/// and escapes them once.
/// </summary>
public sealed record JobGate(int StrictExitCode, int DefaultExitCode, IReadOnlyList<string> StrictReasons, bool Complete, IReadOnlyList<string> Caveats)
{
    #region Fields
    public const string YaraReason = "yaraFindings";
    public const string VulnerabilityReason = "vulnerabilities";
    public const string IndicatorReason = "gatingIndicators";
    #endregion
}

/// <summary>
/// <c>job.json</c>: a completed entry's provenance (task D4), written by the server after it has checked the child's
/// artifacts, and the last file into the entry before it is renamed into place. Read back only through
/// <see cref="JobArtifacts.ReadRecord"/>, which refuses anything this build did not write.
/// </summary>
public sealed record JobRecord(
    int SchemaVersion,
    string Sha256,
    JobDepth Depth,
    string BuildKey,
    string SilvergunVersion,
    string RulesHash,
    bool Network,
    int BudgetSeconds,
    long MemoryLimitBytes,
    DateTimeOffset StartedAt,
    DateTimeOffset AnalyzedAt,
    long ElapsedMs,
    IReadOnlyList<JobStageTime> Stages,
    long PackageBytes,
    long EntryBytes);

/// <summary>
/// Reads the files a job left on disk. The cache directory is Silvergun's, but its contents are files on disk: every read
/// is size-capped and shape-checked, and anything unexpected is a reason, never an exception (task D4).
/// </summary>
public static class JobArtifacts
{
    #region Methods
    /// <summary><paramref name="entryDir"/>'s <c>job.json</c>, or why it is not one this build wrote for <paramref name="sha256"/>, <paramref name="depth"/> and <paramref name="buildKey"/>.</summary>
    public static (JobRecord? Record, string? Problem) ReadRecord(string entryDir, string sha256, JobDepth depth, string buildKey)
    {
        var (record, problem) = Read<JobRecord>(Path.Combine(entryDir, JobProtocol.JobFile), MaxRecordBytes);
        return record is null ? (null, problem)
            : RecordProblem(record, sha256, depth, buildKey) is { } wrong ? (null, wrong)
            : (MissingArtifact(entryDir) ?? ReadGate(entryDir).Problem ?? ReadSummary(entryDir).Problem) is { } bad ? (null, bad)
            : (record, null);
    }

    /// <summary>
    /// The summary a child wrote, or why it is not usable: an object with <c>package</c> and <c>gate</c> objects, within
    /// the summary budget (with room for the budget's own rounding).
    /// </summary>
    public static (JsonObject? Summary, string? Problem) ReadSummary(string dir)
    {
        var (bytes, problem) = ReadBounded(Path.Combine(dir, JobProtocol.SummaryFile), MaxSummaryBytes);
        if (bytes is null)
            return (null, problem);
        try
        {
            return JsonNode.Parse(bytes) is JsonObject { } summary && summary["package"] is JsonObject && summary["gate"] is JsonObject
                    && bytes.Length <= PackageSummary.BudgetChars * 2
                ? (summary, null)
                : (null, "summary.json does not have the expected shape");
        }
        catch (JsonException)
        {
            return (null, "summary.json is not valid JSON");
        }
    }

    /// <summary>The gate a child wrote, or why it is not usable.</summary>
    public static (JobGate? Gate, string? Problem) ReadGate(string dir)
    {
        var (gate, problem) = Read<JobGate>(Path.Combine(dir, JobProtocol.GateFile), MaxGateBytes);
        return gate is null ? (null, problem)
            : gate.StrictReasons is null || gate.Caveats is null || gate.StrictReasons.Any(r => r is not (JobGate.YaraReason or JobGate.VulnerabilityReason or JobGate.IndicatorReason))
                || gate.Caveats.Any(c => c is null || c.Length > MaxCaveatChars) || gate.Caveats.Count > MaxCaveats
                ? (null, "gate.json does not have the expected shape")
            : (gate, null);
    }

    /// <summary>The first artifact the child must have written that is missing or over its size cap, or null.</summary>
    public static string? MissingArtifact(string dir) =>
        caps.Select(c => (c.Name, Info: new FileInfo(Path.Combine(dir, c.Name)), c.Max))
            .Where(c => !c.Info.Exists || c.Info.Length > c.Max || (c.Info.Attributes & FileAttributes.ReparsePoint) != 0)
            .Select(c => c.Info.Exists ? $"{c.Name} is over {c.Max} bytes or is a link" : $"{c.Name} is missing")
            .FirstOrDefault();

    /// <summary><paramref name="path"/>'s bytes, when it is a regular file of at most <paramref name="maxBytes"/>.</summary>
    public static (byte[]? Bytes, string? Problem) ReadBounded(string path, long maxBytes)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return (null, $"{info.Name} is missing");
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > maxBytes)
                return (null, $"{info.Name} is over {maxBytes} bytes or is a link");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var bytes = new byte[Math.Min(stream.Length, maxBytes + 1)];
            stream.ReadExactly(bytes);
            return stream.ReadByte() < 0 ? (bytes, null) : (null, $"{info.Name} grew past {maxBytes} bytes while it was read");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, $"{Path.GetFileName(path)} could not be read ({ex.GetType().Name})");
        }
    }

    /// <summary>Writes <paramref name="bytes"/> to <paramref name="dir"/>/<paramref name="name"/> through a temporary sibling and a rename.</summary>
    public static void WriteAtomic(string dir, string name, ReadOnlySpan<byte> bytes)
    {
        var temp = Path.Combine(dir, "." + name + ".tmp");
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temp, Path.Combine(dir, name), overwrite: true);
    }

    private static (T? Value, string? Problem) Read<T>(string path, long maxBytes) where T : class
    {
        var (bytes, problem) = ReadBounded(path, maxBytes);
        if (bytes is null)
            return (null, problem);
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, JobProtocol.JsonOptions) is { } value ? (value, null) : (null, $"{Path.GetFileName(path)} is null");
        }
        catch (JsonException)
        {
            return (null, $"{Path.GetFileName(path)} is not valid JSON for its schema");
        }
    }

    private static string? RecordProblem(JobRecord r, string sha256, JobDepth depth, string buildKey) =>
        r.SchemaVersion != SchemaVersion ? $"job.json is schema {r.SchemaVersion}, not {SchemaVersion}"
        : r.Sha256 != sha256 || r.Depth != depth || r.BuildKey != buildKey ? "job.json names another package, depth or build"
        : r.Stages is null || r.Stages.Count > MaxStages || r.Stages.Any(s => s is null || s.Stage is null || !stageName.IsMatch(s.Stage) || s.ElapsedMs < 0)
            || r.ElapsedMs < 0 || r.EntryBytes < 0 || r.PackageBytes < 0 || r.SilvergunVersion is null || r.RulesHash is null
            ? "job.json does not have the expected shape"
        : null;
    #endregion

    #region Fields
    /// <summary>The artifact schema this build writes and reads. A cache entry of any other version is re-run, never half-read.</summary>
    public const int SchemaVersion = 1;

    public const long MaxRecordBytes = 64 * 1024;
    public const long MaxGateBytes = 256 * 1024;
    public const long MaxSummaryBytes = 1024 * 1024;
    public const long MaxReportBytes = 512L * 1024 * 1024;
    public const long MaxInventoryBytes = 128L * 1024 * 1024;

    private const int MaxStages = 16;
    private const int MaxCaveats = 64;
    private const int MaxCaveatChars = 2048;

    private static readonly (string Name, long Max)[] caps =
    [
        (JobProtocol.ReportFile, MaxReportBytes),
        (JobProtocol.GateFile, MaxGateBytes),
        (JobProtocol.SummaryFile, MaxSummaryBytes),
        (JobProtocol.InventoryFile, MaxInventoryBytes),
    ];

    private static readonly Regex stageName = new("^[a-z]{1,16}$", RegexOptions.CultureInvariant);
    #endregion
}
