namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

using Xunit;

// Aliases, not `using Microsoft.Cci`: CCI's namespace would put its own metadata-reader vocabulary beside SRM's.
using CciAssertions = Microsoft.Cci.CciAssertions;
using CciDebug = Microsoft.Cci.CciDebug;

/// <summary>
/// ADR 0022 Stage 1, read out of the BUILT CCI assembly (<c>Microsoft.Cci.NET6.dll</c>, the copy next to this test
/// assembly) with <see cref="System.Reflection.Metadata"/>, never by loading or running it:
/// <list type="bullet">
/// <item><description>the rebinding is complete, and covers the whole load path (review round 1 W1): no ext assembly
/// Analysis.Net runs while loading (CCI, the DiaSymReader converter, Model, CCIProvider, Backend, Nuclear.*) references
/// <c>Debug</c>/<c>Trace</c> <c>Assert</c>/<c>Fail</c>, <c>Debugger.Break</c>/<c>Launch</c> or
/// <c>Environment.FailFast</c>, so no future upstream merge can bring back a fully qualified call (as
/// <c>MoveNext.cs:279</c> was) that the <c>global using Debug = Microsoft.Cci.CciDebug</c> alias does not catch, nor a
/// DEBUG build of a compilation it never covered;</description></item>
/// <item><description>the rebinding is live: CCI's IL does call <see cref="CciDebug"/>. Those are method DEFINITIONS of the
/// same assembly, so they appear as call operands, not member references; every method body is decoded with an opcode
/// table built from <see cref="OpCodes"/> (no byte-pattern guessing) and the call tokens are resolved;</description></item>
/// <item><description>the module initializer is wired: <c>&lt;Module&gt;..cctor</c>, which the CLR runs before any other
/// code of the module, calls <c>CciAssertions.Install</c>.</description></item>
/// </list>
/// The call count is not pinned (it moves with upstream code), only that there is one; measured 2026-11-05 it was 96,
/// the spec's count of compiled <c>Debug.*</c> sites.
/// </summary>
public sealed class CciDebugRebindingTests
{
    #region Methods
    [Fact]
    public void Premise_TheAssemblyReadIsTheBuiltCciNextToThisTestAssembly()
    {
        Assert.Equal("Microsoft.Cci.NET6.dll", Path.GetFileName(CciPath));
        Assert.Equal(Path.GetFullPath(AppContext.BaseDirectory), Path.GetFullPath(Path.GetDirectoryName(CciPath)! + Path.DirectorySeparatorChar), ignoreCase: true);
    }

    /// <summary>
    /// Review round 1 W1: the ext assemblies on the load path (everything Analysis.Net calls while reading an assembly)
    /// are found next to this test assembly by name, so a dropped copy fails here rather than shrinking the scan.
    /// </summary>
    [Fact]
    public void Premise_EveryLoadPathAssemblyIsNextToThisTestAssembly()
    {
        var missing = LoadPath.Where(name => !File.Exists(Path.Combine(AppContext.BaseDirectory, name + ".dll"))).ToArray();

        Assert.True(missing.Length == 0, $"Not next to the test assembly: {string.Join(", ", missing)}.");
        Assert.Contains(LoadPath, name => name.StartsWith("Nuclear.", StringComparison.Ordinal));
    }

    /// <summary>
    /// No assembly on the load path references an API that ends the process uncatchably or stops for a debugger:
    /// <c>Debug</c>/<c>Trace</c> <c>Assert</c>/<c>Fail</c> (<c>Environment.FailFast</c> on .NET, ADR 0021),
    /// <c>Debugger.Break</c>/<c>Launch</c> and <c>Environment.FailFast</c> itself. In CCI a fully qualified
    /// <c>System.Diagnostics.Debug</c> call would bypass the <c>CciDebug</c> alias; the DiaSymReader converter is a
    /// separate compilation the alias never covered (review round 1 C1), which is why it must build without DEBUG.
    /// </summary>
    [Theory]
    [MemberData(nameof(LoadPathAssemblies))]
    public void ALoadPathAssembly_HasNoMemberReferenceToAProcessEndingOrDebuggerApi(string assembly)
    {
        var offenders = MemberReferencesOf(assembly)
            .Where(IsBanned)
            .Select(r => $"{r.Namespace}.{r.Type}::{r.Member}")
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.True(offenders.Length == 0,
            $"{assembly}.dll references {string.Join(", ", offenders)}: each can end or stop the process uncatchably (ADR 0021). In CCI, write Debug.* (the CciDebug alias); elsewhere, remove the call or build the project without DEBUG.");
    }

    /// <summary>Non-vacuity for the test above: in each assembly the member-reference reader does see BCL references.</summary>
    [Theory]
    [MemberData(nameof(LoadPathAssemblies))]
    public void Premise_TheMemberReferenceReaderSeesSystemReferences(string assembly) =>
        Assert.Contains(MemberReferencesOf(assembly), r => r.Namespace == "System" || r.Namespace.StartsWith("System.", StringComparison.Ordinal));

    /// <summary>Non-vacuity for the ban itself: it flags each banned API, and not its harmless neighbours.</summary>
    [Fact]
    public void Premise_TheBanFlagsADebuggerOrFailFastReference()
    {
        Assert.True(IsBanned(new MemberRef("System.Diagnostics", "Debugger", "Break")));
        Assert.True(IsBanned(new MemberRef("System", "Environment", "FailFast")));
        Assert.True(IsBanned(new MemberRef("System.Diagnostics", "Trace", "Fail")));
        Assert.False(IsBanned(new MemberRef("System.Diagnostics", "Debug", "WriteLine")));
        Assert.False(IsBanned(new MemberRef("System", "Environment", "GetEnvironmentVariable")));
    }

    public static TheoryData<string> LoadPathAssemblies => [.. LoadPath];

    [Fact]
    public void TheBuiltCci_DefinesCciDebug_WithEveryAssertAndFailOverload()
    {
        var overloads = cci.Value.CciDebugMethods.Values.Select(m => $"{m.Name}/{m.Parameters}").Order(StringComparer.Ordinal);

        Assert.Equal(["Assert/1", "Assert/2", "Assert/3", "Fail/1", "Fail/2"], overloads);
    }

    [Fact]
    public void TheBuiltCci_CallsCciDebug_FromItsOwnCode()
    {
        // Real CCI call sites: CciDebug's public methods call only its private helper, never each other, so all of these are.
        var calls = cci.Value.CallsToCciDebug;

        Assert.True(calls.Count > 0, "No method of Microsoft.Cci.NET6.dll calls Microsoft.Cci.CciDebug: the Debug alias did not take effect (or DEBUG is not defined in CCI's build).");
        Assert.DoesNotContain(calls, c => c.CallerType == nameof(CciDebug));
    }

    [Fact]
    public void TheBuiltCci_ModuleInitializer_CallsCciAssertionsInstall()
    {
        Assert.Contains("Microsoft.Cci.CciAssertions::Install", cci.Value.ModuleConstructorCallees);
    }

    private static bool IsBanned(MemberRef r) => (r.Namespace, r.Type, r.Member) switch
    {
        ("System.Diagnostics", "Debug" or "Trace", "Assert" or "Fail") => true,
        ("System.Diagnostics", "Debugger", "Break" or "Launch") => true,
        ("System", "Environment", "FailFast") => true,
        _ => false,
    };

    private static IReadOnlyList<MemberRef> MemberReferencesOf(string assembly) =>
        CciMetadata.MemberReferencesOf(Path.Combine(AppContext.BaseDirectory, assembly + ".dll"));
    #endregion

    #region Fields
    private static readonly string CciPath = typeof(CciAssertions).Assembly.Location;

    // The ext assemblies Analysis.Net runs while loading an assembly: CCI and the DiaSymReader converter it calls for
    // PDBs, Model, CCIProvider, Backend, and every Nuclear.* assembly beside this one (Nuclear.Assemblies is ext; the rest
    // come with it).
    private static readonly string[] LoadPath =
    [
        "Microsoft.Cci.NET6", "Microsoft.DiaSymReader.Converter", "Model.NET6", "CCIProvider.NET6", "Backend.NET6",
        .. Directory.EnumerateFiles(AppContext.BaseDirectory, "Nuclear.*.dll").Select(Path.GetFileNameWithoutExtension).OfType<string>().Order(StringComparer.Ordinal),
    ];

    private static readonly Lazy<CciMetadata> cci = new(() => CciMetadata.Read(CciPath));
    #endregion

    #region Child types
    private sealed record MemberRef(string Namespace, string Type, string Member);

    private sealed record DefinedMethod(string Name, int Parameters);

    private sealed record Call(string CallerType, string CallerMethod);

    private sealed record CciMetadata(
        IReadOnlyList<MemberRef> MemberReferences,
        IReadOnlyDictionary<MethodDefinitionHandle, DefinedMethod> CciDebugMethods,
        IReadOnlyList<Call> CallsToCciDebug,
        IReadOnlyList<string> ModuleConstructorCallees)
    {
        public static CciMetadata Read(string path)
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            var md = pe.GetMetadataReader();
            var references = MemberReferencesOf(md);

            var cciDebug = md.TypeDefinitions.Select(md.GetTypeDefinition)
                .Single(t => md.GetString(t.Namespace) == "Microsoft.Cci" && md.GetString(t.Name) == nameof(CciDebug));
            // The public surface the alias binds to; CciDebug's own private helper (Failed) is not a Debug.* replacement.
            var debugMethods = cciDebug.GetMethods()
                .Where(h => (md.GetMethodDefinition(h).Attributes & MethodAttributes.MemberAccessMask) == MethodAttributes.Public)
                .ToDictionary(h => h, h =>
                {
                    var method = md.GetMethodDefinition(h);
                    return new DefinedMethod(md.GetString(method.Name), method.GetParameters().Count);
                });

            var calls = new List<Call>();
            var moduleCallees = new List<string>();
            foreach (var typeHandle in md.TypeDefinitions)
            {
                var type = md.GetTypeDefinition(typeHandle);
                foreach (var methodHandle in type.GetMethods())
                {
                    var method = md.GetMethodDefinition(methodHandle);
                    if (method.RelativeVirtualAddress == 0)
                        continue;
                    var callees = MethodOperands(pe.GetMethodBody(method.RelativeVirtualAddress).GetILContent());
                    calls.AddRange(callees
                        .Where(token => token.Kind == HandleKind.MethodDefinition && debugMethods.ContainsKey((MethodDefinitionHandle)token))
                        .Select(_ => new Call(md.GetString(type.Name), md.GetString(method.Name))));
                    if (md.GetString(type.Name) == "<Module>" && md.GetString(method.Name) == ".cctor")
                        moduleCallees.AddRange(callees.Where(token => token.Kind == HandleKind.MethodDefinition).Select(token => Name(md, (MethodDefinitionHandle)token)));
                }
            }

            return new CciMetadata(references, debugMethods, calls, moduleCallees);
        }

        public static IReadOnlyList<MemberRef> MemberReferencesOf(string path)
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            return MemberReferencesOf(pe.GetMetadataReader());
        }

        // Member references whose parent is a type reference: how a call into another assembly is written.
        private static MemberRef[] MemberReferencesOf(MetadataReader md) =>
            md.MemberReferences
                .Select(md.GetMemberReference)
                .Where(r => r.Parent.Kind == HandleKind.TypeReference)
                .Select(r =>
                {
                    var type = md.GetTypeReference((TypeReferenceHandle)r.Parent);
                    return new MemberRef(md.GetString(type.Namespace), md.GetString(type.Name), md.GetString(r.Name));
                })
                .ToArray();

        private static string Name(MetadataReader md, MethodDefinitionHandle handle)
        {
            var method = md.GetMethodDefinition(handle);
            var type = md.GetTypeDefinition(method.GetDeclaringType());
            return $"{md.GetString(type.Namespace)}.{md.GetString(type.Name)}::{md.GetString(method.Name)}";
        }

        // Every InlineMethod operand (call, callvirt, newobj, ldftn, ldvirtftn, jmp) of one IL body, decoded instruction
        // by instruction with operand sizes from System.Reflection.Emit.OpCodes, so no operand byte is read as an opcode.
        private static IEnumerable<EntityHandle> MethodOperands(ImmutableArray<byte> il)
        {
            var found = new List<EntityHandle>();
            for (var i = 0; i < il.Length;)
            {
                var value = il[i] == 0xFE ? unchecked((short)(0xFE00 | il[i + 1])) : il[i];
                i += il[i] == 0xFE ? 2 : 1;
                var operand = operandTypes.TryGetValue(value, out var known)
                    ? known
                    : throw new InvalidOperationException($"Unknown IL opcode 0x{value:X4} at offset {i}: the decoder is out of step.");
                if (operand == OperandType.InlineMethod)
                    found.Add(MetadataTokens.EntityHandle(Int32At(il, i)));
                i += operand switch
                {
                    OperandType.InlineNone => 0,
                    OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                    OperandType.InlineVar => 2,
                    OperandType.InlineI8 or OperandType.InlineR => 8,
                    OperandType.InlineSwitch => 4 + 4 * Int32At(il, i),
                    _ => 4,
                };
            }
            return found;
        }

        private static int Int32At(ImmutableArray<byte> il, int offset) => BitConverter.ToInt32(il.AsSpan()[offset..(offset + 4)]);

        private static readonly IReadOnlyDictionary<short, OperandType> operandTypes = typeof(OpCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(f => (OpCode)f.GetValue(null)!)
            .DistinctBy(o => o.Value)
            .ToDictionary(o => o.Value, o => o.OperandType);
    }
    #endregion
}
