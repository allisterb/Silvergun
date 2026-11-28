namespace Silvergun.MCPServer;

using System.ComponentModel;
using System.Diagnostics;

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

using Silvergun.MCPServer.Jobs;

/// <summary>The network intel tool (task S5), served from the <c>intel.json</c> the job child wrote.</summary>
public sealed partial class DrillTools
{
    #region Methods
    [McpServerTool(Name = ToolNames.GetIntel, Title = "Get network intel on an analysed package", ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = true)]
    [Description("A completed job's network intel, gathered when the job ran (fetchedAt): vulnerabilities (the OSV check's status and "
        + "count; the findings are get_findings kind vulnerabilities); health (the source project on GitHub, from the package's "
        + "repository or project URL: stars, forks, last push, licence, archived, Silvergun's scores and red flags); squat (nuget.org "
        + "packages whose ids are near this one and far more downloaded, from one search: a near id outside its results is not seen). "
        + "Each part's status says whether it was checked; refusals lists hosts that refused, after which Silvergun sent them nothing "
        + "more. Only when the server runs with network access. " + UntrustedNote)]
    public CallToolResult GetIntel([Description("The jobId from analyze_package.")] string jobId)
    {
        var elapsed = Stopwatch.StartNew();
        if (!jobs.Network.Enabled)
            return ToolEnvelope.Create(ToolNames.GetIntel, ToolStatus.NotPermitted, elapsed, message: JobManager.NetworkOff);
        var (entry, refusal) = Open(ToolNames.GetIntel, jobId, elapsed);
        if (entry is null)
            return refusal!;

        var (intel, bad) = JobArtifacts.ReadIntel(entry.Dir);
        if (intel is null)
            return ToolEnvelope.Create(ToolNames.GetIntel, ToolStatus.Failed, elapsed, Data(entry),
                message: $"the cached intel is not readable ({bad}); {Discard(entry)}");
        var data = Data(entry);
        data["intel"] = intel;
        return ToolEnvelope.Create(ToolNames.GetIntel, ToolStatus.Succeeded, elapsed, data);
    }
    #endregion
}
