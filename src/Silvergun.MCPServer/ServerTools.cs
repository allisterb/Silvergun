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
                ["protocol"] = server.NegotiatedProtocolVersion
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
                ["jobMemoryBytes"] = McpLimits.JobMemoryBytes
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
    #endregion
}

/// <summary>The limits the server enforces (tasks D1, D3, D5).</summary>
public static class McpLimits
{
    #region Fields
    public const int ResponseBudgetChars = 20_000;
    public const int MaxQueuedJobs = 8;
    public const int DefaultWaitSeconds = 25;
    public const int MaxWaitSeconds = 55;
    public const int StandardJobBudgetSeconds = 900;
    public const int DeepJobBudgetSeconds = 1_500;
    public const long JobMemoryBytes = 4L * 1024 * 1024 * 1024;
    #endregion
}
