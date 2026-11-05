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
/// <item><description>the rebinding is complete: no member reference to <c>System.Diagnostics.Debug</c>'s (or
/// <c>Trace</c>'s) <c>Assert</c>/<c>Fail</c> survives, so no future upstream merge can bring back a fully qualified call
/// (as <c>MoveNext.cs:279</c> was) that the <c>global using Debug = Microsoft.Cci.CciDebug</c> alias does not
/// catch;</description></item>
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

    [Fact]
    public void TheBuiltCci_HasNoMemberReferenceToSystemDiagnosticsDebugOrTraceAssertOrFail()
    {
        var offenders = cci.Value.MemberReferences
            .Where(r => r.Namespace == "System.Diagnostics" && r.Type is "Debug" or "Trace" && r.Member is "Assert" or "Fail")
            .Select(r => $"{r.Namespace}.{r.Type}::{r.Member}")
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.True(offenders.Length == 0,
            $"Microsoft.Cci.NET6.dll still calls {string.Join(", ", offenders)}: on .NET that is Environment.FailFast (ADR 0021). A fully qualified call bypasses the CciDebug alias; write it as Debug.*.");
    }

    /// <summary>Non-vacuity for the test above: the member-reference reader does see the BCL references CCI makes.</summary>
    [Fact]
    public void Premise_TheMemberReferenceReaderSeesSystemReferences() =>
        Assert.Contains(cci.Value.MemberReferences, r => r.Namespace == "System" && r.Type == "Object" && r.Member == ".ctor");

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
    #endregion

    #region Fields
    private static readonly string CciPath = typeof(CciAssertions).Assembly.Location;

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

            // Member references whose parent is a type reference: how a call into another assembly is written.
            var references = md.MemberReferences
                .Select(md.GetMemberReference)
                .Where(r => r.Parent.Kind == HandleKind.TypeReference)
                .Select(r =>
                {
                    var type = md.GetTypeReference((TypeReferenceHandle)r.Parent);
                    return new MemberRef(md.GetString(type.Namespace), md.GetString(type.Name), md.GetString(r.Name));
                })
                .ToArray();

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
