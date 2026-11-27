namespace Silvergun.MCPServer;

using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

/// <summary>Tools about the server itself.</summary>
[McpServerToolType]
public sealed class ServerTools(ServerState state)
{
    #region Methods
    [McpServerTool(Name = ToolNames.GetServerInfo, Title = "Silvergun server info", ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Versions, the limits this server enforces, and the boundaries the person who started it set (input roots, by "
        + "name only; network access; job concurrency). The agent cannot change these. Read the silvergun://guide resource for "
        + "how to investigate a package.")]
    public CallToolResult GetServerInfo(McpServer server)
    {
        var elapsed = Stopwatch.StartNew();
        var settings = state.Settings;
        return ToolEnvelope.Create(ToolNames.GetServerInfo, ToolStatus.Succeeded, elapsed, new JsonObject
        {
            ["instanceId"] = state.InstanceId,
            ["startedAt"] = state.StartedAt.UtcDateTime.ToString("O"),
            ["uptimeMs"] = state.UptimeMs,
            ["versions"] = new JsonObject
            {
                ["silvergun"] = ServerState.SilvergunVersion,
                ["mcpSdk"] = ServerState.SdkVersion,
                ["protocol"] = server.NegotiatedProtocolVersion,
                ["rulesHash"] = Jobs.BuildIdentity.RulesHash,
                ["cacheBuildKey"] = Jobs.BuildIdentity.BuildKey
            },
            ["settings"] = new JsonObject
            {
                ["roots"] = new JsonArray([.. settings.Roots.Select(r => JsonValue.Create(UntrustedText.Escape(Path.GetFileName(r) is { Length: > 0 } name ? name : r)))]),
                ["network"] = settings.Network,
                ["maxJobs"] = settings.MaxJobs,
                ["cacheMaxGb"] = settings.CacheMaxGb
            },
            ["limits"] = new JsonObject
            {
                ["responseBudgetChars"] = McpLimits.ResponseBudgetChars,
                ["maxQueuedJobs"] = McpLimits.MaxQueuedJobs,
                ["defaultWaitSeconds"] = McpLimits.DefaultWaitSeconds,
                ["maxWaitSeconds"] = McpLimits.MaxWaitSeconds,
                ["standardJobBudgetSeconds"] = McpLimits.StandardJobBudgetSeconds,
                ["deepJobBudgetSeconds"] = McpLimits.DeepJobBudgetSeconds,
                ["jobMemoryBytes"] = McpLimits.JobMemoryBytes,
                ["deepJobMemoryBytes"] = McpLimits.DeepJobMemoryBytes
            }
        });
    }
    #endregion
}

/// <summary>One constant per tool name, used by the attribute and by log lines alike (task D10).</summary>
public static class ToolNames
{
    #region Fields
    public const string GetServerInfo = "get_server_info";
    public const string AnalyzePackage = "analyze_package";
    public const string WaitForJob = "wait_for_job";
    public const string CancelJob = "cancel_job";
    public const string GetSummary = "get_summary";
    public const string ListFiles = "list_files";
    public const string ReadFile = "read_file";
    public const string GetFindings = "get_findings";
    public const string GetReachability = "get_reachability";
    #endregion
}

/// <summary>The limits the server enforces (tasks D1, D3, D5).</summary>
public static class McpLimits
{
    #region Fields
    public const int ResponseBudgetChars = 20_000;
    /// <summary>The chars a page of rows may take: a result carries it twice (structured and text), with room for the envelope.</summary>
    public const int PageBudgetChars = ResponseBudgetChars / 2 - 1_000;
    /// <summary>The chars a fenced bulk text block may take (task D6.3): it is carried once, beside small metadata.</summary>
    public const int BulkBudgetChars = 12_000;
    /// <summary>The most bytes <c>read_file</c> reads in one call; what is returned is also cut to <see cref="BulkBudgetChars"/>.</summary>
    public const int MaxReadBytes = 64 * 1024;
    public const int MaxQueuedJobs = 8;
    public const int DefaultWaitSeconds = 25;
    public const int MaxWaitSeconds = 55;
    public const int StandardJobBudgetSeconds = 900;
    public const int DeepJobBudgetSeconds = 1_500;
    /// <summary>A standard job's whole process tree (Windows Job Object).</summary>
    public const long JobMemoryBytes = 4L * 1024 * 1024 * 1024;
    /// <summary>A deep job's tree: the child's heap plus the graph worker's own 4 GiB process limit, with room for YARA-X.</summary>
    public const long DeepJobMemoryBytes = 8L * 1024 * 1024 * 1024;
    /// <summary>The job child's own GC heap hard limit, at either depth (the only memory bound on Linux).</summary>
    public const long JobHeapBytes = 3L * 1024 * 1024 * 1024;
    #endregion
}
