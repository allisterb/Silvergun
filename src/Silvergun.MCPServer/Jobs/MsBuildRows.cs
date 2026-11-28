namespace Silvergun.MCPServer.Jobs;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using Silvergun.PackageAnalysis.NuGet;
using Silvergun.PackageAnalysis.NuGet.MsBuild;

/// <summary>
/// The MSBuild row file (task S4, <c>get_build_integration</c>), from <see cref="MsBuildAnalysis"/> in the job child: per
/// package <c>.targets</c>/<c>.props</c> file, one <c>file</c> row (how it is loaded, whether it was parsed), then its
/// <c>target</c>, <c>exec</c>, <c>write</c>, <c>usingTask</c>, <c>import</c> and <c>property</c> rows. Every package string is
/// <c>{"untrusted": …}</c>; anchors, flags and agent-configuration tokens are Silvergun's own.
/// </summary>
public static class MsBuildRows
{
    #region Methods
    /// <summary>Analyses and writes the rows; returns the index entry, with the pass.</summary>
    public static JsonObject Write(string dir, PackageCapabilityReport report, string contentRoot, IEnumerable<string> packageFiles, PackagePaths paths)
    {
        using var writer = new RowWriter(dir, JobProtocol.MsBuildFile);
        MsBuildIntegration integration;
        try
        {
            integration = MsBuildAnalysis.Analyze(report.Package.Id, contentRoot, report.Scripts, packageFiles);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A fault in the pass costs the pass, never the job: the list is empty and says why.
            writer.Commit();
            var failed = writer.Index();
            failed["pass"] = new JsonObject { ["status"] = "failed", ["reason"] = U($"the MSBuild pass failed ({ex.GetType().Name})", ShortChars) };
            return failed;
        }
        var reported = report.Scripts.ToDictionary(s => s.FullPath, s => s.RelativePath, StringComparer.Ordinal);
        JsonObject Served(string full) => paths.OfFile(full) is { } served ? new JsonObject { ["untrusted"] = served } : U(reported.GetValueOrDefault(full) ?? "<unlisted>", PathChars);

        foreach (var row in integration.Files.SelectMany(f => Rows(f, Served)))
        {
            var full = Of(row);
            if (!writer.Add(PackageFindings.WithPath(row, "file", paths.OfFile(full), reported.GetValueOrDefault(full) ?? "<unlisted>"), filterKeys))
                break;
        }
        writer.Commit();

        var pass = integration.Pass;
        var entry = writer.Index();
        entry["pass"] = new JsonObject
        {
            ["status"] = pass.Complete ? "completed" : "incomplete",
            ["files"] = pass.Files,
            ["parsed"] = pass.Parsed,
            ["notParsed"] = pass.NotParsed,
            ["notProject"] = pass.NotProject,
            ["expansionBudgetSpent"] = pass.ExpansionBudgetSpent,
            ["factsCut"] = pass.FactsCut,
            ["valuesCut"] = pass.ValuesCut,
            ["anyPropertySet"] = pass.AnyPropertySet,
        };
        // Over every fact, whatever the rows could hold (S4 review W2).
        var t = integration.Totals;
        entry["totals"] = new JsonObject
        {
            ["agentConfigWrites"] = t.AgentConfigWrites,
            ["outsideOutputWrites"] = t.OutsideOutputWrites,
            ["unknownDestinationWrites"] = t.UnknownDestinationWrites,
            ["packageFileExecs"] = t.PackageFileExecs,
            ["inlineTasks"] = t.InlineTasks,
            ["loaded"] = new JsonObject
            {
                ["agentConfigWrites"] = t.LoadedAgentConfigWrites,
                ["outsideOutputWrites"] = t.LoadedOutsideOutputWrites,
                ["unknownDestinationWrites"] = t.LoadedUnknownDestinationWrites,
                ["packageFileExecs"] = t.LoadedPackageFileExecs,
                ["inlineTasks"] = t.LoadedInlineTasks,
            },
        };
        return entry;
    }

    private static IEnumerable<JsonObject> Rows(MsBuildFileFacts f, Func<string, JsonObject> served)
    {
        JsonObject Row(string type, int line) => new() { [FileKey] = f.FullPath, ["type"] = type, ["line"] = line };
        JsonArray Files(IReadOnlyList<string> files) => new([.. files.Take(MaxList).Select(p => (JsonNode)served(p))]);

        var file = new JsonObject
        {
            [FileKey] = f.FullPath,
            ["type"] = "file",
            ["status"] = Name(f.Status),
            ["load"] = Name(f.Load),
            ["autoImport"] = f.AutoImport is { } auto ? new JsonObject { ["folder"] = auto.Folder, ["tfm"] = auto.Tfm is { } tfm ? U(tfm, ShortChars) : null } : null,
            ["importedBy"] = Files(f.ImportedBy),
            ["importedByTotal"] = f.ImportedBy.Count,
            ["counts"] = new JsonObject
            {
                ["targets"] = f.Targets.Count,
                ["execs"] = f.Execs.Count,
                ["writes"] = f.Writes.Count,
                ["usingTasks"] = f.UsingTasks.Count,
                ["imports"] = f.Imports.Count,
                ["properties"] = f.Properties.Count,
            },
        };
        if (f.Reason is { } reason)
            file["reason"] = U(reason, ShortChars);
        if (f.FactsCut > 0)
            file["factsCut"] = f.FactsCut;
        yield return file;

        // What runs and writes first, so a row cap costs the targets and properties before it costs them (S4 review W2).
        foreach (var e in f.Execs)
        {
            var row = Row("exec", e.Line);
            Optional(row, "target", e.Target);
            row["command"] = U(e.Command, CommandChars);
            Optional(row, "program", e.Program);
            Optional(row, "continueOnError", e.ContinueOnError);
            Optional(row, "ignoreExitCode", e.IgnoreExitCode);
            Optional(row, "ignoreStandardErrorWarningFormat", e.IgnoreStandardErrorWarningFormat);
            Optional(row, "workingDirectory", e.WorkingDirectory);
            Conditions(row, e.Conditions);
            row["packageFiles"] = Files(e.PackageFiles);
            row["packageFilesTotal"] = e.PackageFiles.Count;
            row["agentConfigMentioned"] = Tokens(e.AgentConfigMentioned);
            row["unresolved"] = e.Unresolved;
            yield return row;
        }

        foreach (var w in f.Writes.OrderByDescending(w => w.AgentConfig.Count > 0).ThenByDescending(w => w.OutsideOutput == true))
        {
            var row = Row("write", w.Line);
            Optional(row, "target", w.Target);
            row["task"] = w.Task;
            row["attribute"] = w.Attribute;
            row["value"] = U(w.Value, ValueChars);
            Conditions(row, w.Conditions);
            row["destinations"] = new JsonArray([.. w.Destinations.Take(MaxList).Select(d => (JsonNode)new JsonObject
            {
                ["anchor"] = MsBuildPath.Name(d.Anchor),
                ["path"] = U(d.Display, ValueChars),
                ["outsideOutput"] = d.OutsideOutput,
                ["unresolved"] = d.Unresolved,
            })]);
            row["destinationsTotal"] = w.Destinations.Count;
            if (w.DestinationsCut)
                row["destinationsCut"] = true;
            row["outsideOutput"] = w.OutsideOutput;
            row["agentConfig"] = Tokens(w.AgentConfig);
            row["packageSources"] = Files(w.PackageSources);
            row["packageSourcesTotal"] = w.PackageSources.Count;
            yield return row;
        }

        foreach (var u in f.UsingTasks)
        {
            var row = Row("usingTask", u.Line);
            row["taskName"] = U(u.TaskName, NameChars);
            Optional(row, "assemblyFile", u.AssemblyFile);
            Optional(row, "assemblyName", u.AssemblyName);
            Optional(row, "taskFactory", u.TaskFactory);
            Conditions(row, u.Conditions);
            row["packageFiles"] = Files(u.PackageFiles);
            row["inline"] = u.Inline;
            Optional(row, "codeType", u.CodeType);
            Optional(row, "codeLanguage", u.CodeLanguage);
            Optional(row, "codeSource", u.CodeSource);
            if (u.Body is { } body)
            {
                row["body"] = U(body, BodyChars);
                row["bodyChars"] = u.BodyChars;
            }
            row["agentConfigMentioned"] = Tokens(u.AgentConfigMentioned);
            row["invoked"] = u.Invoked;
            yield return row;
        }

        foreach (var i in f.Imports)
        {
            var row = Row("import", i.Line);
            row["project"] = U(i.Project, ValueChars);
            Optional(row, "sdk", i.Sdk);
            Conditions(row, i.Conditions);
            row["resolved"] = new JsonArray([.. i.Resolved.Take(MaxList).Select(r => (JsonNode)U(r.Display, ValueChars))]);
            row["resolvedTotal"] = i.Resolved.Count;
            row["packageFiles"] = Files(i.PackageFiles);
            yield return row;
        }

        foreach (var t in f.Targets)
        {
            var row = Row("target", t.Line);
            row["name"] = U(t.Name, NameChars);
            Optional(row, "beforeTargets", t.BeforeTargets);
            Optional(row, "afterTargets", t.AfterTargets);
            Optional(row, "dependsOnTargets", t.DependsOnTargets);
            Conditions(row, t.Conditions);
            Optional(row, "inputs", t.Inputs);
            Optional(row, "outputs", t.Outputs);
            row["outputsWritten"] = t.OutputsWritten;
            yield return row;
        }

        foreach (var p in f.Properties)
        {
            var row = Row("property", p.Line);
            Optional(row, "target", p.Target);
            row["name"] = U(p.Name, NameChars);
            row["value"] = U(p.Value, ValueChars);
            Conditions(row, p.Conditions);
            yield return row;
        }
    }

    // The raw full path a row carries until WithPath replaces it with the served one.
    private static string Of(JsonObject row)
    {
        var full = row[FileKey]!.GetValue<string>();
        row.Remove(FileKey);
        return full;
    }

    private static void Optional(JsonObject row, string key, string? value)
    {
        if (value is not null)
            row[key] = U(value, ValueChars);
    }

    private static void Conditions(JsonObject row, IReadOnlyList<string> conditions)
    {
        row["conditions"] = new JsonArray([.. conditions.Take(MaxList).Select(c => (JsonNode)U(c, ValueChars))]);
        if (conditions.Count > MaxList)
            row["conditionsTotal"] = conditions.Count;
    }

    private static JsonArray Tokens(IReadOnlyList<string> tokens) => new([.. tokens.Select(t => (JsonNode)t)]);

    private static JsonObject U(string text, int maxChars) => ToolEnvelope.Untrusted(text, maxChars);

    private static string Name<T>(T value) where T : struct, Enum => JsonNamingPolicy.CamelCase.ConvertName(value.ToString());
    #endregion

    #region Fields
    // The raw path's key while a row is built; never written.
    private const string FileKey = "rawFile";
    private const int PathChars = 512;
    private const int NameChars = 256;
    private const int ShortChars = 200;
    private const int ValueChars = 1024;
    private const int CommandChars = 2048;
    private const int BodyChars = 4096;
    private const int MaxList = 4;

    // The key get_build_integration matches exactly: never cut to fit a row.
    private static readonly IReadOnlySet<string> filterKeys = new HashSet<string>(StringComparer.Ordinal) { "file" };
    #endregion
}
