namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

/// <summary>
/// The no-resolution invariant (ADR-0020 amendment items 3 and 7; IL's <c>MemberIndexNoResolutionInvariantTests</c>)
/// for <see cref="PackageGraphs"/> (CHA A2Multi S1), which lives in this assembly rather than in
/// <c>Silvergun.CodeAnalysis.IL.dll</c>, the one the IL walk reads. The same structural check: every method of
/// <c>PackageGraphs</c> (its lambda classes included) is a root, the walk follows calls within
/// <c>Silvergun.PackageAnalysis.NuGet.dll</c>, and no member it references may be <c>ResolvedMethod</c>,
/// <c>ResolvedType</c> or <c>ResolveReference</c> (or their backing delegates). What it calls in the IL library
/// (<c>MemberIndex.Build</c>, <c>MethodGraph.Build</c>, <c>AssemblyDisassembler</c>) is guarded by the IL walk. Read as
/// metadata through <see cref="AssemblyAnalyzer"/>, never loaded anew.
/// </summary>
public sealed class PackageGraphsNoResolutionInvariantTests
{
    #region Methods
    /// <summary>THE GUARD, plus non-vacuity: the walk reaches <c>BuildFolder</c> and sees its calls into the IL library.</summary>
    [Fact]
    public void PackageGraphs_NeverReferencesAResolvingMember()
    {
        var closure = Walk(typeof(PackageGraphs).Assembly.Location);

        var hits = closure.References.Where(r => Forbidden.Contains(Bare(r.Member))).Select(r => $"{r.From} references {r.Member}").Distinct().ToArray();

        Assert.True(hits.Length == 0, string.Join(Environment.NewLine, hits));
        Assert.Contains(closure.Methods, m => m.StartsWith(Root + ".BuildFolder(", StringComparison.Ordinal));
        Assert.Contains(closure.References, r => r.Member.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.Build(", StringComparison.Ordinal));
        Assert.Contains(closure.References, r => r.Member.StartsWith("Silvergun.CodeAnalysis.IL.MethodGraph.Build(", StringComparison.Ordinal));
        Assert.Contains(closure.References, r => r.Member.StartsWith("Silvergun.CodeAnalysis.IL.AssemblyDisassembler.Create(", StringComparison.Ordinal));
    }

    /// <summary>
    /// The guard can go red: a MUTANT <c>Silvergun.PackageAnalysis.NuGet</c> whose <c>PackageGraphs.BuildFolder</c> reads
    /// <c>IBasicType.ResolvedType</c> directly, and whose lambda-class method reaches <c>IMethodReference.ResolvedMethod</c>
    /// through a helper in a non-root type, is caught by the same walk on both counts.
    /// </summary>
    [Fact]
    public void Walk_OverAMutantThatResolves_FindsTheForbiddenReads()
    {
        var directory = Directory.CreateTempSubdirectory("silvergun-pkggraphs-mutant-").FullName;
        try
        {
            var path = Path.Combine(directory, "Silvergun.PackageAnalysis.NuGet.dll");
            var builder = new PersistedAssemblyBuilder(new AssemblyName("Silvergun.PackageAnalysis.NuGet"), typeof(object).Assembly);
            DefineMutant(builder.DefineDynamicModule("Silvergun.PackageAnalysis.NuGet"));
            builder.Save(path);

            var closure = Walk(path);
            var hits = closure.References.Where(r => Forbidden.Contains(Bare(r.Member))).Select(r => $"{r.From} -> {Bare(r.Member)}").ToArray();

            Assert.Contains(hits, h => h.StartsWith(Root + ".BuildFolder(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedType", StringComparison.Ordinal));
            Assert.Contains(hits, h => h.StartsWith("Silvergun.PackageAnalysis.NuGet.Helpers.Peek(", StringComparison.Ordinal) && h.EndsWith("-> ResolvedMethod", StringComparison.Ordinal));
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    // PackageGraphs.BuildFolder(IBasicType) => _ = type.ResolvedType; PackageGraphs.<>c.<Build>b__0_0(IMethodReference) =>
    // Helpers.Peek(method); Helpers.Peek(IMethodReference) => _ = method.ResolvedMethod.
    private static void DefineMutant(ModuleBuilder module)
    {
        const MethodAttributes Static = MethodAttributes.Public | MethodAttributes.Static;
        var resolvedType = typeof(Model.Types.IBasicType).GetProperty(nameof(Model.Types.IBasicType.ResolvedType))!.GetGetMethod()!;
        var resolvedMethod = typeof(Model.Types.IMethodReference).GetProperty(nameof(Model.Types.IMethodReference.ResolvedMethod))!.GetGetMethod()!;

        var helpers = module.DefineType("Silvergun.PackageAnalysis.NuGet.Helpers", TypeAttributes.Public | TypeAttributes.Class);
        var peek = helpers.DefineMethod("Peek", Static, typeof(void), [typeof(Model.Types.IMethodReference)]);
        var il = peek.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Callvirt, resolvedMethod);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var graphs = module.DefineType(Root, TypeAttributes.Public | TypeAttributes.Class);
        il = graphs.DefineMethod("BuildFolder", Static, typeof(void), [typeof(Model.Types.IBasicType)]).GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Callvirt, resolvedType);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        var lambdas = graphs.DefineNestedType("<>c", TypeAttributes.NestedPrivate | TypeAttributes.Class);
        il = lambdas.DefineMethod("<Build>b__0_0", Static, typeof(void), [typeof(Model.Types.IMethodReference)]).GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, peek);
        il.Emit(OpCodes.Ret);

        helpers.CreateType();
        graphs.CreateType();
        lambdas.CreateType();
    }

    // Every method reachable from PackageGraphs' methods by any method-reference operand within the assembly at `path`,
    // and every method or field each references (wherever it lives).
    private static Closure Walk(string path)
    {
        Runtime.Initialize("Silvergun", "TESTS");
        var load = AssemblyAnalyzer.Load(path);
        Assert.True(load.IsSuccess, load.Message);
        using var library = load.Value;
        var definitions = library.Module.GetAllTypes().SelectMany(t => t.Methods).ToArray();
        var byId = definitions.GroupBy(Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);

        var queue = new Queue<IMethodDefinition>(definitions.Where(m => Id(m).StartsWith(Root + ".", StringComparison.Ordinal)));
        var seen = new HashSet<string>(queue.Select(Id), StringComparer.Ordinal);
        var references = new List<(string From, string Member)>();
        while (queue.Count > 0)
        {
            var method = queue.Dequeue();
            var from = Id(method);
            var body = AssemblyAnalyzer.TryReadBody(method);
            Assert.False(body.IsUnreadable, $"{from}: {body.Error}");
            foreach (var value in body.Body?.Operations.Select(op => op.Value) ?? [])
            {
                switch (value)
                {
                    case IMethodReference callee:
                        var id = Id(callee);
                        references.Add((from, id));
                        foreach (var next in byId.GetValueOrDefault(id) ?? [])
                            if (seen.Add(Id(next)))
                                queue.Enqueue(next);
                        break;
                    case IFieldReference field:
                        references.Add((from, $"{CciNames.TypeName(field.ContainingType)}.{field.Name.Value}"));
                        break;
                }
            }
        }
        Assert.NotEmpty(seen);
        return new Closure(seen, references);
    }

    // The definition behind a reference (generic instance / specialized member), then its node id.
    private static string Id(IMethodReference method)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            if (method is IGenericMethodInstanceReference instance) method = instance.GenericMethod;
            else if (method is ISpecializedMethodReference specialized) method = specialized.UnspecializedVersion;
            else break;
        }
        return CanonicalName.NodeId(CciNames.Of(method));
    }

    // "Ns.Type.get_ResolvedType()" -> "ResolvedType"; a field "Ns.Type.ResolveMethod" -> "ResolveMethod".
    private static string Bare(string member)
    {
        var name = member.Split('(')[0];
        name = name[(name.LastIndexOf('.') + 1)..];
        return name.StartsWith("get_", StringComparison.Ordinal) || name.StartsWith("set_", StringComparison.Ordinal) ? name[4..] : name;
    }
    #endregion

    #region Fields
    private const string Root = "Silvergun.PackageAnalysis.NuGet.PackageGraphs";

    /// <summary>The resolving members of Analysis.Net's Model (and their CCI namesakes), as in the IL walk.</summary>
    private static readonly HashSet<string> Forbidden = new(StringComparer.Ordinal)
    {
        "ResolvedMethod", "ResolvedType", "ResolveReference", "ResolveMethod", "ResolveType",
    };
    #endregion

    #region Child types
    private sealed record Closure(IReadOnlySet<string> Methods, IReadOnlyList<(string From, string Member)> References);
    #endregion
}
