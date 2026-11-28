namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

/// <summary>
/// The S4 fixture package (MSBuild integration facts): an auto-imported <c>build/mcp.build.targets</c> with a target after
/// Build whose output nothing creates, an Exec of <c>dotnet</c> on a package DLL with ContinueOnError, Copies of a package
/// file into <c>.claude/skills</c> (directly and through a property), a <c>.mcp.json</c> write, an inline task whose body is
/// hostile text, a task from a package DLL, notable properties and an Import; the imported <c>build/inner.targets</c> with
/// enough targets to page; an unreferenced <c>tools/x.targets</c>; and <c>build/dtd.props</c> with a DTD, never parsed.
/// </summary>
internal static class BuildFixtures
{
    #region Methods
    public static string Package(string dir) =>
        DrillFixtures.Nupkg(dir, Id, "Build fixture.",
        [
            (AutoFile, Encoding.UTF8.GetBytes(Auto)),
            (InnerFile, Encoding.UTF8.GetBytes(Inner())),
            (OrphanFile, Encoding.UTF8.GetBytes(Orphan)),
            (DtdFile, Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?>\n<!DOCTYPE Project [<!ENTITY e \"boom\">]>\n<Project><PropertyGroup><X>&e;</X></PropertyGroup></Project>\n")),
            (ToolDll, File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Nuclear.SemVer.dll"))),
            (TaskDll, File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Nuclear.SemVer.dll"))),
            (SkillFile, Encoding.UTF8.GetBytes("# a skill\n")),
        ]);

    private static string Inner()
    {
        var body = new StringBuilder("<Project>\n");
        for (var i = 0; i < InnerTargets; i++)
            body.Append($"  <Target Name=\"Inner{i:D3}\" BeforeTargets=\"CoreCompile\"><Exec Command=\"echo {i} {new string('w', 200)}\" /></Target>\n");
        return body.Append("</Project>\n").ToString();
    }
    #endregion

    #region Fields
    public const string Id = "mcp.build";
    public const string AutoFile = "build/mcp.build.targets";
    public const string InnerFile = "build/inner.targets";
    public const string OrphanFile = "tools/x.targets";
    public const string DtdFile = "build/dtd.props";
    public const string ToolDll = "lib/net8.0/Tool.dll";
    public const string TaskDll = "tools/T.dll";
    public const string SkillFile = "content/skill.md";
    public const int InnerTargets = 60;

    /// <summary>The inline task's body: <see cref="Hostile.Mix"/>, in CDATA so its forged fences stay literal.</summary>
    public static readonly string InlineBody = "Log.LogMessage(\"" + Hostile.Mix + "\");";

    public static readonly string Auto = $"""
        <Project>
          <PropertyGroup>
            <SkillDir>$(SolutionDir).claude\skills\</SkillDir>
            <RestoreAdditionalProjectSources>https://feed.example/v3/index.json</RestoreAdditionalProjectSources>
            <RestoreSources>https://other.example/v3/index.json</RestoreSources>
            <DisableFastUpToDateCheck>true</DisableFastUpToDateCheck>
          </PropertyGroup>
          <Import Project="$(MSBuildThisFileDirectory)inner.targets" />
          <UsingTask TaskName="AcmeInline" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
            <Task><Code Type="Fragment" Language="cs"><![CDATA[{InlineBody}]]></Code></Task>
          </UsingTask>
          <UsingTask TaskName="Acme.T" AssemblyFile="$(MSBuildThisFileDirectory)..\tools\T.dll" />
          <Target Name="RunTool" AfterTargets="Build" Inputs="$(MSBuildProjectFullPath)" Outputs="$(IntermediateOutputPath)acme.stamp">
            <Delete Files="$(TEMP)acme.tmp" />
            <Exec Command="dotnet &quot;$(MSBuildThisFileDirectory)../lib/net8.0/Tool.dll&quot;" ContinueOnError="true" />
            <Copy SourceFiles="$(MSBuildThisFileDirectory)../content/skill.md" DestinationFolder="$(MSBuildProjectDirectory)/../.claude/skills/" />
            <Copy SourceFiles="$(MSBuildThisFileDirectory)../content/skill.md" DestinationFolder="$(SkillDir)" />
            <Copy SourceFiles="$(MSBuildThisFileDirectory)../content/skill.md" DestinationFolder="$(OutputPath)skills" />
            <WriteLinesToFile File="$(SolutionDir).mcp.json" Lines="x" />
            <AcmeInline />
            <Acme.T />
          </Target>
        </Project>
        """;

    /// <summary>The orphan's inline body: a <c>.claude/</c> mention past the row's 4,096-char body bound (S4 review W9).</summary>
    public static readonly string OrphanBody = "// " + new string('x', 5_000) + "\nSystem.IO.File.WriteAllText(\".claude/skills/x.md\", \"\");";

    /// <summary>
    /// The unreferenced file: an inline task, a write to <c>AGENTS.md</c>, and a Delete of 264 output paths, past the
    /// destination cap (eight definitions of 33 paths each, so no value's own budget is spent).
    /// </summary>
    public static readonly string Orphan = $"""
        <Project>
          <PropertyGroup>
            {string.Concat(Enumerable.Range(0, 8).Select(k => "<Many>" + string.Join(';', Enumerable.Range(0, 33).Select(i => $"$(OutDir)d{k}p{i}")) + "</Many>"))}
          </PropertyGroup>
          <UsingTask TaskName="OrphanInline" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
            <Task><Code Type="Fragment" Language="cs"><![CDATA[{OrphanBody}]]></Code></Task>
          </UsingTask>
          <Target Name="Orphan">
            <WriteLinesToFile File="$(SolutionDir)AGENTS.md" Lines="x" />
            <Delete Files="$(Many)" />
          </Target>
        </Project>
        """;
    #endregion
}

/// <summary>The S4 tests that share <see cref="BuildFixture"/>'s entry; they run one after another.</summary>
[CollectionDefinition(Name)]
public sealed class BuildCollection : ICollectionFixture<BuildFixture>
{
    public const string Name = "MCP S4 build entry";
}

/// <summary>One completed standard entry of <see cref="BuildFixtures.Package"/>, made once by a real job.</summary>
public sealed class BuildFixture : IAsyncLifetime
{
    #region Properties
    public string Package { get; private set; } = "";

    public string Sha256 { get; private set; } = "";

    public string JobId => JobManager.JobId(Sha256, JobDepth.Standard);

    public string EntryDir { get; private set; } = "";

    internal DrillTools Tools { get; private set; } = null!;

    internal JobTools JobTools { get; private set; } = null!;
    #endregion

    #region Methods
    public async Task InitializeAsync()
    {
        Package = BuildFixtures.Package(dirs.Root);
        Sha256 = Fixtures.Sha256Of(Package);
        JobTools = InProcess.Tools(dirs, out var manager);
        Tools = new DrillTools(manager);
        var view = await InProcess.RunToEndAsync(manager, Package);
        Assert.True(view.State == JobState.Completed, $"the build job did not complete: {view.State} {view.Reason}");
        EntryDir = view.EntryDir!;
    }

    /// <summary>The stored MSBuild rows that <paramref name="keep"/> accepts.</summary>
    internal List<System.Text.Json.Nodes.JsonNode> Rows(Func<System.Text.Json.Nodes.JsonObject, bool>? keep = null) => Drill.Lines(EntryDir, JobProtocol.MsBuildFile, keep);

    public Task DisposeAsync()
    {
        dirs.Dispose();
        return Task.CompletedTask;
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion
}
