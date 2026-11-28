namespace Silvergun.MCPServer;

using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text.Json.Nodes;

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

using Silvergun.MCPServer.Jobs;

/// <summary>The MSBuild integration tool (task S4), served from the <c>msbuild.jsonl</c> rows the job child wrote.</summary>
public sealed partial class DrillTools
{
    #region Methods
    [McpServerTool(Name = ToolNames.GetBuildIntegration, Title = "Get an analysed package's MSBuild integration", ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("A completed job's MSBuild facts, from every .targets and .props file in the package. Row types: file (whether NuGet "
        + "imports it automatically (load: auto), an Import reaches it (imported) or nothing does (none), and whether it was parsed); "
        + "target (BeforeTargets, AfterTargets, DependsOnTargets, conditions, Inputs, Outputs, and whether a task in it writes its "
        + "Outputs); exec (the command, its first word, ContinueOnError and the other flags, the package files it names, and any "
        + "agent-configuration path it mentions); write (Copy, Move, WriteLinesToFile, WriteCodeFragment, MakeDir, Delete, RemoveDir, "
        + "Touch, Unzip, ZipDirectory, DownloadFile, XmlPoke: each destination expanded to an anchor such as {project} or {output}, "
        + "whether it is outside the build output, and any agent-configuration path it names); usingTask (task assemblies and "
        + "inline task code); import; property (properties that change restore or build, and redefinitions of output paths and "
        + "other built-in properties). totals count the notable facts over every file, even when the list is cut. Values "
        + "are expanded across the package's own files; unresolved: true means part of a "
        + "value could not be. These are facts about text, not a record of what a build would do. Paged: while truncated is true, "
        + "call again with cursor set to next. " + UntrustedNote)]
    public CallToolResult GetBuildIntegration(
        [Description("The jobId from analyze_package.")] string jobId,
        [Description("Only rows about this file, by its list_files path, e.g. \"build/Some.Package.targets\".")] string? file = null,
        [Description("Only rows of this type: file, target, exec, write, usingTask, import or property. file rows are always kept.")] string? type = null,
        [Description("The next value of the previous page; omit it for the first page.")] string? cursor = null)
    {
        var elapsed = Stopwatch.StartNew();
        var rowType = type is { Length: > 0 } ? buildRowTypes.FirstOrDefault(t => string.Equals(t, type.Trim(), StringComparison.OrdinalIgnoreCase)) : null;
        if (type is { Length: > 0 } && rowType is null)
            return Invalid(ToolNames.GetBuildIntegration, elapsed, $"type must be one of: {string.Join(", ", buildRowTypes)}");
        if (TooLong(file) || TooLong(cursor))
            return Invalid(ToolNames.GetBuildIntegration, elapsed, $"file and cursor are at most {MaxArgumentChars} chars");
        var (entry, refusal) = Open(ToolNames.GetBuildIntegration, jobId, elapsed);
        if (entry is null)
            return refusal!;

        var list = entry.Index["msbuild"]!.AsObject();
        var data = Data(entry);
        data["pass"] = HostPaths.ReduceReasons(list["pass"]!.DeepClone(), HostPaths.ForServer(jobs.Store.Root));
        data["totals"] = list["totals"]?.DeepClone();
        bool Keep(JsonObject row) =>
            (file is not { Length: > 0 } || RowFile.UntrustedValue(row, "file") == file)
            && (rowType is null || Text(row["type"]) is "file" || Text(row["type"]) == rowType);
        return Serve(ToolNames.GetBuildIntegration, entry, elapsed, JobProtocol.MsBuildFile, list,
            PageCursor.Query(entry.View.JobId, ToolNames.GetBuildIntegration, file, rowType), cursor, Keep, null, data);
    }
    #endregion

    #region Fields
    private static readonly string[] buildRowTypes = ["file", "target", "exec", "write", "usingTask", "import", "property"];
    #endregion
}
