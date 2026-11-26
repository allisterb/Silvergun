namespace Silvergun.MCPServer;

using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;

using ModelContextProtocol.Server;

/// <summary>Process-wide facts every tool may report. Holds no job state: that lives on disk (task D4a).</summary>
public sealed class ServerState
{
    #region Constructors
    public ServerState(McpServerSettings settings)
    {
        Settings = settings;
        StartedAt = DateTimeOffset.UtcNow;
        uptime = Stopwatch.StartNew();
        InstanceId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
    }
    #endregion

    #region Properties
    public McpServerSettings Settings { get; }

    public DateTimeOffset StartedAt { get; }

    public long UptimeMs => uptime.ElapsedMilliseconds;

    /// <summary>
    /// A random id for this process, reported by <c>get_server_info</c> and never logged: a log that contains it holds a
    /// tool result, which is how the tests catch a JSON-RPC body leaking into the log (task S0).
    /// </summary>
    public string InstanceId { get; }

    public static string SilvergunVersion { get; } = InformationalVersion(typeof(ServerState).Assembly);

    public static string SdkVersion { get; } = InformationalVersion(typeof(McpServer).Assembly);
    #endregion

    #region Methods
    private static string InformationalVersion(Assembly assembly) =>
        assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? assembly.GetName().Version?.ToString() ?? "unknown";
    #endregion

    #region Fields
    private readonly Stopwatch uptime;
    #endregion
}
