namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase A1 acceptance criterion 3, pinned <b>structurally</b> — the same stance as
/// <see cref="ReferenceSideNamingInvariantTests"/> (names come from references, never from resolved definitions) and
/// the same technique as <see cref="CapabilityKeyCompositionArchitectureTests"/> (read the compiled IL of our own
/// library): no <c>src/</c> code path used by <see cref="MemberIndex"/> or <see cref="MethodGraph"/> touches
/// <c>ResolvedMethod</c>, <c>ResolvedType</c> or <c>ResolveReference</c>.
/// <para>
/// <b>Why it matters.</b> <c>Host.ResolveReference</c> is a linear <c>SingleOrDefault</c> scan per lookup (measured
/// 500x slower on one assembly) that THROWS on an ambiguous match, and both <c>Resolved*</c> properties go through it
/// (ADR-0020 amendment items 3 and 7). One such read inside the traversal makes the graph quadratic and turns an
/// ambiguous reference — routine in real packages — into an exception. No behavioural test sees it: the fixture
/// graph comes out identical, only slower.
/// </para>
/// <para>
/// <b>How.</b> Every method of the A1 types (and of their nested and compiler-generated types: lambdas, display
/// classes, the private <c>Builder</c>) is a root. From there the walk follows every call, <c>newobj</c> and
/// <c>ldftn</c> whose target is defined in <c>Silvergun.CodeAnalysis.IL.dll</c> — so <c>ModelNames</c>,
/// <c>CanonicalName</c> and anything else they reach are scanned too — and records every member referenced along
/// the way. Safe in-process: the assembly read is our own, built from ordinary C#.
/// </para>
/// <para>
/// <b>Limit.</b> Static: a call through an interface or a delegate is followed to its declared target only, and
/// Analysis.Net's own code (<c>ext/</c>) is not walked; the guard covers what <c>src/</c> calls directly.
/// </para>
/// </summary>
public sealed class MemberIndexNoResolutionInvariantTests : IClassFixture<AssemblyAnalyzerFixture>, IDisposable
{
    #region Constructors
    /// <summary>The shared fixture is taken only to initialize the Silvergun runtime; the subject is our own library.</summary>
    public MemberIndexNoResolutionInvariantTests(AssemblyAnalyzerFixture fixture)
    {
        _ = fixture;

        var load = AssemblyAnalyzer.Load(typeof(MemberIndex).Assembly.Location);
        Assert.True(load.IsSuccess, load.Message);
        library = load.Value;
        closure = Walk(library);
    }
    #endregion

    #region Methods
    /// <summary>THE GUARD: nothing reachable from the A1 types references a resolving member.</summary>
    [Fact]
    public void MemberIndexAndMethodGraph_NeverReferenceResolvedMethodResolvedTypeOrResolveReference()
    {
        var hits = closure.References
            .Where(r => Forbidden.Contains(Bare(r.Member)))
            .Select(r => $"{r.From} references {r.Member}")
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            hits.Length == 0,
            "A1's member index / graph must never resolve through Analysis.Net (ADR-0020 amendment items 3 and 7):"
                + Environment.NewLine + string.Join(Environment.NewLine, hits));
    }

    /// <summary>
    /// Non-vacuity: the roots exist, the walk leaves the two A1 files (it reaches the naming code the index is built
    /// on), and the members it inspects include Analysis.Net <c>Model</c> reads — the population a forbidden read would
    /// belong to. A rename or a broken walk fails here as "the guard lost its subject", not as a silent pass.
    /// </summary>
    [Fact]
    public void Walk_CoversTheA1TypesAndTheSrcCodeTheyReach()
    {
        foreach (var root in RootTypes)
            Assert.Contains(closure.Methods, m => m.StartsWith(root + ".", StringComparison.Ordinal));

        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.Resolve(", StringComparison.Ordinal));
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.MethodGraph.Builder.Walk(", StringComparison.Ordinal));
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.ModelNames.", StringComparison.Ordinal));
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.CanonicalName.", StringComparison.Ordinal));
        // Compiler-generated lambda bodies are walked too (Guard(() => ...) in MemberIndex).
        Assert.Contains(closure.Methods, m => m.StartsWith("Silvergun.CodeAnalysis.IL.MemberIndex.<>c", StringComparison.Ordinal));

        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == "ContainingType");
        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Types.", StringComparison.Ordinal) && Bare(r.Member) == "GenericMethod");
        Assert.Contains(closure.References, r => r.Member.StartsWith("Model.Bytecode.", StringComparison.Ordinal));
    }

    public void Dispose() => library.Dispose();

    // Every method reachable from the roots by call/callvirt/newobj/ldftn/ldvirtftn within this library, and every
    // method or field it references (wherever that member lives).
    private static Closure Walk(AssemblyAnalyzer library)
    {
        var definitions = library.Module.GetAllTypes().SelectMany(t => t.Methods).ToArray();
        var byId = definitions.GroupBy(Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);

        var queue = new Queue<IMethodDefinition>(definitions.Where(m => RootTypes.Any(root => Id(m).StartsWith(root + ".", StringComparison.Ordinal))));
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

        return new Closure(seen, references);
    }

    // The definition behind a reference, by the same reference-side links MechanismCallSites uses, then its node id.
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

    // "Ns.Type.get_ResolvedType()" -> "ResolvedType"; "Ns.Type.ResolveMethod" (a field) -> "ResolveMethod".
    private static string Bare(string member)
    {
        var name = member.Split('(')[0];
        name = name[(name.LastIndexOf('.') + 1)..];
        return name.StartsWith("get_", StringComparison.Ordinal) || name.StartsWith("set_", StringComparison.Ordinal) ? name[4..] : name;
    }
    #endregion

    #region Fields
    /// <summary>The types declared in <c>MemberIndex.cs</c> and <c>MethodGraph.cs</c> that carry code.</summary>
    private static readonly string[] RootTypes =
    [
        "Silvergun.CodeAnalysis.IL.MemberIndex",
        "Silvergun.CodeAnalysis.IL.MethodResolution",
        "Silvergun.CodeAnalysis.IL.IndexCoverage",
        "Silvergun.CodeAnalysis.IL.MethodGraph",
        "Silvergun.CodeAnalysis.IL.MethodNode",
        "Silvergun.CodeAnalysis.IL.MethodEdge",
        "Silvergun.CodeAnalysis.IL.GraphOpacity",
        "Silvergun.CodeAnalysis.IL.GraphBudget",
        "Silvergun.CodeAnalysis.IL.ResolutionCounts",
        "Silvergun.CodeAnalysis.IL.GraphCoverage",
    ];

    /// <summary>
    /// The resolving members of Analysis.Net's <c>Model</c> (and their CCI namesakes): the two lazy properties, the
    /// host lookup they call, and the backing delegates behind the properties.
    /// </summary>
    private static readonly HashSet<string> Forbidden = new(StringComparer.Ordinal)
    {
        "ResolvedMethod", "ResolvedType", "ResolveReference", "ResolveMethod", "ResolveType",
    };

    private readonly AssemblyAnalyzer library;
    private readonly Closure closure;
    #endregion

    #region Child types
    private sealed record Closure(IReadOnlySet<string> Methods, IReadOnlyList<(string From, string Member)> References);
    #endregion
}
