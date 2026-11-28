namespace Silvergun.PackageAnalysis.NuGet.MsBuild;

using System.Collections.Generic;

/// <summary>Whether a package MSBuild file was read (MCP task S4).</summary>
public enum MsBuildFileStatus
{
    Parsed,

    /// <summary>Not read: over a cap, not well-formed XML, a DTD, or unreadable. <see cref="MsBuildFileFacts.Reason"/> says which.</summary>
    NotParsed,

    /// <summary>Well-formed XML whose root is not <c>Project</c>: MSBuild would refuse to import it.</summary>
    NotProject
}

/// <summary>How a file comes into a consumer's build.</summary>
public enum MsBuildLoad
{
    /// <summary>NuGet imports it: <c>build/</c>, <c>buildTransitive/</c> or <c>buildMultiTargeting/</c>, named for the package.</summary>
    Auto,

    /// <summary>An <c>Import</c> in a file that is loaded reaches it.</summary>
    Imported,

    /// <summary>Nothing Silvergun saw loads it.</summary>
    None
}

/// <summary>
/// What a path is relative to, once its properties are expanded (<see cref="MsBuildExpander"/>). A relative path is
/// <see cref="Project"/>'s, as MSBuild tasks run in the project directory.
/// </summary>
public enum MsBuildAnchor
{
    Package,
    Project,
    Solution,
    Home,
    AppData,
    LocalAppData,
    Temp,
    System,
    Output,
    Intermediate,
    NuGetPackages,
    MsBuild,
    Dotnet,
    Absolute,

    /// <summary>It starts with something Silvergun could not resolve.</summary>
    Unknown
}

/// <summary>
/// One expanded path: its anchor, the normalized rest (forward slashes, no <c>.</c>, <c>..</c> applied), how many
/// <c>..</c> climbed above the anchor, and whether any part stayed unresolved. A package path is package-relative.
/// </summary>
public sealed record MsBuildPath(MsBuildAnchor Anchor, string Path, int Climbs, bool Unresolved)
{
    #region Properties
    /// <summary>The path as rows show it: <c>{project}/../.claude/skills</c>.</summary>
    public string Display => "{" + Name(Anchor) + "}" + string.Concat(Enumerable.Repeat("/..", Climbs)) + (Path.Length > 0 ? "/" + Path : "");

    /// <summary>
    /// Whether the path is outside the build output: false only under <see cref="MsBuildAnchor.Output"/> or
    /// <see cref="MsBuildAnchor.Intermediate"/> without climbing out; null when the anchor is unknown or a part is unresolved,
    /// which could lead anywhere (S4 review C4).
    /// </summary>
    public bool? OutsideOutput => Anchor == MsBuildAnchor.Unknown || Unresolved ? null : !(Anchor is MsBuildAnchor.Output or MsBuildAnchor.Intermediate && Climbs == 0);
    #endregion

    #region Methods
    /// <summary>An anchor's name as rows show it (camelCase).</summary>
    public static string Name(MsBuildAnchor anchor) => System.Text.Json.JsonNamingPolicy.CamelCase.ConvertName(anchor.ToString());
    #endregion
}

/// <summary>The NuGet folder that imports a file automatically, and the TFM folder it sits in, if any.</summary>
public sealed record MsBuildAutoImport(string Folder, string? Tfm);

/// <summary>A target, with the attributes that decide when it runs.</summary>
public sealed record MsBuildTargetFact(int Line, string Name, string? BeforeTargets, string? AfterTargets, string? DependsOnTargets, IReadOnlyList<string> Conditions,
    string? Inputs, string? Outputs, bool? OutputsWritten);

/// <summary>
/// An <c>Exec</c> task. <see cref="Program"/> is the command's first word, expanded. <see cref="PackageFiles"/> are the package
/// files its command names (full paths); <see cref="AgentConfigMentioned"/> the agent-configuration tokens in its text.
/// </summary>
public sealed record MsBuildExecFact(int Line, string? Target, string Command, string? ContinueOnError, string? IgnoreExitCode, string? IgnoreStandardErrorWarningFormat,
    string? WorkingDirectory, IReadOnlyList<string> Conditions, string? Program, IReadOnlyList<string> PackageFiles, IReadOnlyList<string> AgentConfigMentioned, bool Unresolved);

/// <summary>
/// A file-writing task's destination: <see cref="Task"/> (<c>Copy</c>, <c>WriteLinesToFile</c>, …) and the
/// <see cref="Attribute"/> that names where it writes, with its expanded <see cref="Destinations"/>. <see cref="AgentConfig"/>
/// are the agent-configuration tokens a destination names; <see cref="PackageSources"/> the package files it copies.
/// </summary>
public sealed record MsBuildWriteFact(int Line, string? Target, string Task, string Attribute, string Value, IReadOnlyList<string> Conditions,
    IReadOnlyList<MsBuildPath> Destinations, IReadOnlyList<string> AgentConfig, IReadOnlyList<string> PackageSources)
{
    #region Properties
    /// <summary>
    /// True when any destination is outside the build output; null when none is known outside and some is unknown, there
    /// is none at all, or the destinations were cut.
    /// </summary>
    public bool? OutsideOutput => Destinations.Any(d => d.OutsideOutput == true) ? true
        : Destinations.Count == 0 || Destinations.Any(d => d.OutsideOutput is null) || DestinationsCut ? null : false;

    /// <summary>The value had more destinations than Silvergun lists (<see cref="MsBuildAnalysis.MaxDestinations"/>).</summary>
    public bool DestinationsCut { get; init; }
    #endregion
}

/// <summary>
/// A <c>UsingTask</c>. An inline task (<see cref="Inline"/>) carries its <c>Code</c> element's <see cref="Body"/>, at most
/// <see cref="MsBuildAnalysis.MaxBodyChars"/>. <see cref="Invoked"/> counts the package's own calls of the task.
/// </summary>
public sealed record MsBuildUsingTaskFact(int Line, string TaskName, string? AssemblyFile, string? AssemblyName, string? TaskFactory, IReadOnlyList<string> Conditions,
    IReadOnlyList<string> PackageFiles, bool Inline, string? CodeType, string? CodeLanguage, string? CodeSource, string? Body, int BodyChars, int Invoked)
{
    #region Properties
    /// <summary>The agent-configuration tokens anywhere in the whole body, served or not (S4 review W9).</summary>
    public IReadOnlyList<string> AgentConfigMentioned { get; init; } = [];
    #endregion
}

/// <summary>An <c>Import</c>, with the package files it reaches (full paths) and its expanded targets.</summary>
public sealed record MsBuildImportFact(int Line, string Project, string? Sdk, IReadOnlyList<string> Conditions, IReadOnlyList<MsBuildPath> Resolved, IReadOnlyList<string> PackageFiles);

/// <summary>An assignment to a property that changes restore or build behaviour (<see cref="MsBuildAnalysis.NotableProperties"/>).</summary>
public sealed record MsBuildPropertyFact(int Line, string? Target, string Name, string Value, IReadOnlyList<string> Conditions);

/// <summary>
/// One package MSBuild file's facts. <see cref="FullPath"/> is the extracted file; <see cref="Name"/> its package-relative
/// name as NuGet installs it. <see cref="ImportedBy"/> are the full paths of package files whose imports reach it.
/// <see cref="FactsCut"/>: elements past the per-file cap, not reported.
/// </summary>
public sealed record MsBuildFileFacts(string FullPath, string Name, MsBuildFileStatus Status, string? Reason, MsBuildAutoImport? AutoImport, MsBuildLoad Load,
    IReadOnlyList<string> ImportedBy, IReadOnlyList<MsBuildTargetFact> Targets, IReadOnlyList<MsBuildExecFact> Execs, IReadOnlyList<MsBuildWriteFact> Writes,
    IReadOnlyList<MsBuildUsingTaskFact> UsingTasks, IReadOnlyList<MsBuildImportFact> Imports, IReadOnlyList<MsBuildPropertyFact> Properties, int FactsCut);

/// <summary>
/// The pass over a package's MSBuild files: how many there were, how many were parsed, and whether expansion stopped at
/// its budget (later values stay unexpanded and say so).
/// </summary>
public sealed record MsBuildPass(int Files, int Parsed, int NotParsed, int NotProject, bool ExpansionBudgetSpent)
{
    #region Properties
    /// <summary>Elements past a cap (per file, per package, nesting), not reported.</summary>
    public int FactsCut { get; init; }

    /// <summary>Values cut short (<see cref="MsBuildExpander.Cuts"/>, destinations, definitions, globs): each is unresolved.</summary>
    public int ValuesCut { get; init; }

    /// <summary>
    /// A task or item metadata in the package can set properties Silvergun cannot name (for an MSBuild call, a project
    /// reference, …): every settable property may then be anything, so its writes read as unknown (S4 review round 6, W1).
    /// </summary>
    public bool AnyPropertySet { get; init; }

    /// <summary>Every file was parsed, every element reported and every value expanded whole (S4 review W1).</summary>
    public bool Complete => NotParsed == 0 && !ExpansionBudgetSpent && FactsCut == 0 && ValuesCut == 0;
    #endregion
}

/// <summary>
/// Counts over every fact of the package, whatever the row file could hold (S4 review W2): writes naming an agent-configuration
/// path, writes outside the build output, Exec tasks that name a package file, and inline tasks; in loaded files and in all.
/// </summary>
public sealed record MsBuildTotals(int AgentConfigWrites, int OutsideOutputWrites, int PackageFileExecs, int InlineTasks, int LoadedAgentConfigWrites,
    int LoadedOutsideOutputWrites, int LoadedPackageFileExecs, int LoadedInlineTasks)
{
    #region Properties
    /// <summary>Writes whose destination could be anywhere (<see cref="MsBuildWriteFact.OutsideOutput"/> null).</summary>
    public int UnknownDestinationWrites { get; init; }

    public int LoadedUnknownDestinationWrites { get; init; }
    #endregion
}

/// <summary>A package's MSBuild integration facts (MCP task S4).</summary>
public sealed record MsBuildIntegration(IReadOnlyList<MsBuildFileFacts> Files, MsBuildPass Pass, MsBuildTotals Totals);
