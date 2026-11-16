namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.Cci;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Every behaviour fixture tests something (task section 4.1): the sink call, <c>ldstr</c> or resource its row depends on is
/// in the COMPILED IL (read with the repo's own CCI reader, never reflection or loading), <c>Arm.Armed</c> is a real field
/// load and not a folded constant, and each twin's replacement is there too. Fails if Roslyn optimised a payload away, which
/// is what making <c>Arm.Armed</c> a <c>const</c> does.
/// <para>
/// Facts are tokens: <c>call:Type.Method</c> (call, callvirt or newobj), <c>str:text</c> (an ldstr containing the text),
/// <c>fld:Type.Field</c> (ldsfld), <c>pinvoke:Import</c>, <c>attr:Type</c>, <c>method:Name</c> and <c>res:Name</c>.
/// </para>
/// </summary>
[Trait("Category", "Behaviour")]
[Collection(BehaviourInertnessGuard.CollectionName)]
public sealed class BehaviourFixtureSanityTests
{
    #region Constructors
    static BehaviourFixtureSanityTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods
    public static IEnumerable<object[]> Projects => Expected.Keys.Select(k => new object[] { k });

    [Fact]
    public void Fixtures_AreTheThirtyEightAssemblies_OneForEveryPackageSide()
    {
        Assert.Equal(38, Expected.Count);
        Assert.Equal(23, Expected.Keys.Count(k => k.EndsWith(".Malicious", StringComparison.Ordinal)));
        Assert.Equal(15, Expected.Keys.Count(k => k.EndsWith(".Twin", StringComparison.Ordinal)));
        Assert.All(Expected.Keys, p => Assert.True(File.Exists(BehaviourPackages.AssemblyPath(p)), $"{p}: not built next to the tests"));
    }

    [Theory]
    [MemberData(nameof(Projects))]
    public void Fixture_CompiledIl_HoldsEverythingItsRowDependsOn(string project)
    {
        var facts = ReadFacts(BehaviourPackages.AssemblyPath(project));

        var missing = Expected[project].Prepend("fld:Arm.Armed").Where(token => !Holds(facts, token)).ToList();

        Assert.True(missing.Count == 0,
            $"{project}: not in the compiled IL: {string.Join(", ", missing)}\nfound:\n  {string.Join("\n  ", facts.OrderBy(f => f, StringComparer.Ordinal).Take(80))}");
    }

    // The gate is a real static readonly field that is never set true (a const would be a literal, never a field load).
    [Theory]
    [MemberData(nameof(Projects))]
    public void Fixture_ArmedGate_IsAStaticReadonlyFieldNeverSetTrue(string project)
    {
        using var assembly = Load(BehaviourPackages.AssemblyPath(project));
        var arm = assembly.Module.GetAllTypes().Single(t => t.Name.Value == "Arm");
        var field = Assert.Single(arm.Fields, f => f.Name.Value == "Armed");

        Assert.True(field.IsStatic && field.IsReadOnly && !field.IsCompileTimeConstant, $"{project}: Arm.Armed is not a static readonly field");
        // Roslyn drops an `= false` initialiser, so there may be no static constructor; if there is one it never loads a 1.
        foreach (var cctor in arm.Methods.Where(m => m.Name.Value == ".cctor"))
            Assert.DoesNotContain(AssemblyAnalyzer.TryReadBody(cctor).Body!.Operations, o => o.OperationCode is OperationCode.Ldc_I4_1 or OperationCode.Ldc_I4 or OperationCode.Ldc_I4_S);
    }

    [Fact]
    public void Fixtures_HaveNoPackageReference_AndOnlyAsciiSource()
    {
        var root = FixtureSourceRoot();
        if (root is null)
            return;   // the sources are not beside the tests (a binary-only run); the build itself enforces no package restore

        foreach (var csproj in Directory.EnumerateFiles(root, "*.csproj", SearchOption.AllDirectories))
            Assert.DoesNotContain("PackageReference", File.ReadAllText(csproj), StringComparison.Ordinal);
        Assert.DoesNotContain("PackageReference", File.ReadAllText(Path.Combine(root, "Directory.Build.props")), StringComparison.Ordinal);

        foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories).Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
            Assert.True(File.ReadAllBytes(file).All(b => b < 0x80), $"{file}: a non-ASCII byte");
    }

    private static bool Holds(HashSet<string> facts, string token) =>
        token.StartsWith("str:", StringComparison.Ordinal)
            ? facts.Any(f => f.StartsWith("str:", StringComparison.Ordinal) && f.Contains(token[4..], StringComparison.Ordinal))
            : facts.Contains(token);

    private static AssemblyAnalyzer Load(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        Assert.True(result.IsSuccess, $"{path}: {result.Message}");
        return result.Value;
    }

    // Every call-site target, ldstr, static-field load, P/Invoke import, method attribute, finalizer and managed resource.
    private static HashSet<string> ReadFacts(string path)
    {
        using var assembly = Load(path);
        var facts = new HashSet<string>(StringComparer.Ordinal);

        foreach (var method in assembly.Module.GetAllTypes().SelectMany(t => t.Methods))
        {
            if (method.IsPlatformInvoke)
                facts.Add($"pinvoke:{method.PlatformInvokeData.ImportName.Value}");
            facts.Add($"method:{method.Name.Value}");
            foreach (var attribute in method.Attributes)
                facts.Add($"attr:{AssemblyAnalyzer.TypeName(attribute.Type)}");

            var read = AssemblyAnalyzer.TryReadBody(method);
            Assert.False(read.IsUnreadable, $"{path}: unreadable body of {method.Name.Value}: {read.Error}");
            if (read.Body is null)
                continue;

            foreach (var op in read.Body.Operations)
                switch (op.Value)
                {
                    case string text when op.OperationCode == OperationCode.Ldstr:
                        facts.Add($"str:{text}");
                        break;
                    case IFieldReference field when op.OperationCode == OperationCode.Ldsfld:
                        facts.Add($"fld:{AssemblyAnalyzer.TypeName(field.ContainingType)}.{field.Name.Value}");
                        break;
                    case IMethodReference call when op.OperationCode is OperationCode.Call or OperationCode.Callvirt or OperationCode.Newobj:
                        facts.Add($"call:{AssemblyAnalyzer.TypeName(call.ContainingType)}.{call.Name.Value}");
                        break;
                }
        }

        foreach (var resource in assembly.Module.ContainingAssembly.Resources)
            facts.Add($"res:{resource.Name.Value}");
        return facts;
    }

    // tests/BehaviourFixtures, found by walking up from the test output (null when the sources are not there).
    private static string? FixtureSourceRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Path.Combine(dir.FullName, "BehaviourFixtures") is { } candidate && File.Exists(Path.Combine(candidate, "Directory.Build.props")))
                return candidate;
        return null;
    }
    #endregion

    #region Fields
    private const string Post = "call:System.Net.Http.HttpClient.PostAsync";
    private const string Start = "call:System.Diagnostics.Process.Start";
    private const string EnvAll = "call:System.Environment.GetEnvironmentVariables";
    private const string Special = "call:System.Environment.GetFolderPath";
    private const string Secrets = "str:GITHUB_TOKEN";

    // The tokens each fixture needs beyond the Arm.Armed load (every assembly also needs that).
    private static readonly IReadOnlyDictionary<string, string[]> Expected = new Dictionary<string, string[]>
    {
        ["BF04.Malicious"] = [EnvAll, Post, "str:silvergun-behaviour-suite/collect", "method:Execute"],
        ["BF04.Twin"] = ["call:System.Environment.GetEnvironmentVariable", "call:System.IO.File.WriteAllText", "method:Execute"],
        ["BF05.Malicious"] = ["call:System.IO.Directory.GetFiles", Special, Post, "method:Initialize"],
        ["BF05.Twin"] = ["call:System.IO.File.ReadAllText", "str:analyzer.settings.json", "call:System.IO.Directory.GetFiles", Special, "method:Initialize"],
        ["BF06.Malicious"] = ["call:System.IO.Directory.GetFileSystemEntries", Special, Post, "call:Behaviour.ModuleStart.Run"],
        ["BF06.Twin"] = ["str:identity", "call:System.IO.Directory.GetFiles", "call:Behaviour.ModuleStart.Run"],
        ["BF07a.Malicious"] = ["call:System.IO.File.ReadAllBytes", "str:Login Data"],
        ["BF07b.Malicious"] = ["call:System.IO.File.ReadAllText", "str:.ssh/id_rsa"],
        ["BF07c.Malicious"] = ["call:System.IO.File.ReadAllText", "str:.aws/credentials"],
        ["BF07.Twin"] = ["call:System.IO.File.ReadAllText", "str:appsettings.json"],
        ["BF08a.Malicious"] = [Post, "str:https://discord.com/api/webhooks/0/0"],
        ["BF08b.Malicious"] = [Post, "str:https://api.telegram.org/bot0:0/sendMessage"],
        ["BF08c.Malicious"] = [Post, "str:.m.pipedream.net/"],
        ["BF08d.Malicious"] = [Post, "str:.ngrok-free.app/"],
        ["BF08.Twin"] = [Post, "str:https://telemetry.example.test/v1"],
        ["BF09.Malicious"] = ["call:System.Net.Http.HttpClient.GetByteArrayAsync", "str:https://raw.githubusercontent.com/", "call:System.Reflection.Assembly.Load"],
        ["BF09.Twin"] = ["call:System.Reflection.Assembly.LoadFrom", "str:plugin.dll"],
        ["BF10.Malicious"] = [Start, "str:powershell", "str:-NoP -W Hidden -Enc VwByAGkAdABl"],
        ["BF10.Twin"] = [Start, "str:git", "str:--version"],
        ["BF11.Malicious"] = ["call:Microsoft.Win32.RegistryKey.SetValue", "call:Microsoft.Win32.RegistryKey.OpenSubKey", @"str:Software\Microsoft\Windows\CurrentVersion\Run"],
        ["BF11.Twin"] = ["call:Microsoft.Win32.RegistryKey.GetValue", "call:Microsoft.Win32.RegistryKey.OpenSubKey", @"str:Software\SilvergunBehaviourVendor\Settings"],
        ["BF12a.Malicious"] = ["call:System.Convert.FromBase64String", "str:TVoAAAAA", "call:System.IO.File.WriteAllBytes", Start],
        ["BF12b.Malicious"] = ["call:System.Convert.FromBase64String", "str:TVoAAAAAAAAAAAAA", "call:System.String.Concat", "call:System.IO.File.WriteAllBytes", Start],
        ["BF12c.Malicious"] = ["call:System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray", "call:System.IO.File.WriteAllBytes", Start],
        ["BF12d.Malicious"] = ["res:payload.bin", "call:System.Reflection.Assembly.GetManifestResourceStream", "call:System.IO.File.WriteAllBytes", Start],
        ["BF12.Twin"] = ["call:System.Convert.FromBase64String", "str:iVBORw0KGgo", "call:System.IO.MemoryStream..ctor"],
        ["BF13.Malicious"] = ["call:System.Type.GetType", "str:System.IO.File", "str:ReadAllBytes", "call:System.Reflection.MethodBase.Invoke", "str:Post", Post],
        ["BF13.Twin"] = ["call:System.Type.GetProperties", "str:Validate", "call:System.Reflection.MethodBase.Invoke"],
        ["BF14.Malicious"] = ["pinvoke:VirtualAlloc", "pinvoke:CreateThread", "call:System.Runtime.InteropServices.Marshal.Copy"],
        ["BF14.Twin"] = ["pinvoke:GetTickCount64", "call:System.Runtime.InteropServices.Marshal.Copy"],
        ["BF15.Malicious"] = ["attr:System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute", EnvAll],
        ["BF15.Twin"] = ["attr:System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute"],
        ["BF16.Malicious"] = ["method:Finalize", Start],
        ["BF16.Twin"] = ["method:Finalize", "call:System.Runtime.InteropServices.GCHandle.Free"],
        ["BF17.Malicious"] = [EnvAll, Secrets, "str:NUGET_API_KEY", "str:AWS_SECRET_ACCESS_KEY", "str:TOKEN", "str:KEY", Post],
        ["BF17.Twin"] = [EnvAll, "str:ASPNETCORE_ENVIRONMENT", "str:DOTNET_CLI_TELEMETRY_OPTOUT"],
        ["BF18.Malicious"] = ["call:System.Diagnostics.Debugger.get_IsAttached", "call:System.Environment.get_ProcessorCount", "call:System.Environment.get_MachineName", "str:SANDBOX", EnvAll, Secrets, Post],
        ["BF18.Twin"] = ["call:System.Diagnostics.Debugger.get_IsAttached", "call:System.Environment.get_ProcessorCount", "call:System.Environment.get_MachineName", "str:SANDBOX", "str:ASPNETCORE_ENVIRONMENT"],
    };
    #endregion
}
