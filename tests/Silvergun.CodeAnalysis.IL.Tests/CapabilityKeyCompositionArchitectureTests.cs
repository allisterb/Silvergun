namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// ADR-0021's hard requirement at the call-site scanner, pinned <b>architecturally</b>: capability-map phase 2
/// requires <c>CapabilityAnalysis</c> to build its map key from the callee's <b>ContainingType</b>
/// (<c>CciNames.Of(ITypeReference)</c>) and never from the callee itself
/// (<c>CciNames.Of(IMethodReference)</c>, which eagerly evaluates <c>method.Parameters</c> and drives CCI's
/// signature parser for every callee of every scanned assembly).
/// <para>
/// <b>Why this class exists rather than a behavioural test.</b> The two compositions produce the <em>same
/// string</em> — <c>ClassificationKey(MethodIdentity)</c> is signature-free — so no assertion over findings can
/// tell them apart. The difference is only a crash hazard, and since ADR-0022 Stage 0 taught CCI's
/// <c>GetTypeReference()</c> the <c>TypedReference</c> case, even the pathological probe assembly no longer
/// crashes under the forbidden composition (measured at the phase-2 review gate: it exits 0). So
/// <see cref="TypedReferencePointerRegressionTests"/> cannot discriminate the two, and this can: it reads the
/// <em>compiled IL of our own library</em> and asserts which overload the key composition actually calls. It goes
/// red the instant someone writes <c>CciNames.Of(callee)</c>.
/// </para>
/// <para>
/// <b>Safe in-process</b>, unlike the probe: the assembly whose parameter lists are read here is
/// <c>Silvergun.CodeAnalysis.IL.dll</c>, built by us from ordinary C#, with no <c>TypedReference</c> anywhere in
/// its signatures. The hazard ADR-0021 describes belongs to hostile <em>input</em> assemblies, not to this one.
/// </para>
/// </summary>
public sealed class CapabilityKeyCompositionArchitectureTests : IClassFixture<AssemblyAnalyzerFixture>, IDisposable
{
    #region Constructors
    /// <summary>
    /// The shared fixture is taken only for its side effect of initializing the Silvergun runtime; the subject is
    /// our own analysis library, not the netstandard2.0 fixture assembly it holds.
    /// </summary>
    public CapabilityKeyCompositionArchitectureTests(AssemblyAnalyzerFixture fixture)
    {
        _ = fixture;

        var create = AssemblyAnalyzer.Load(typeof(CapabilityAnalysis).Assembly.Location);
        Assert.True(create.IsSuccess, create.Message);
        library = create.Value;
    }
    #endregion

    #region Methods
    /// <summary>
    /// THE GUARD. Every <c>CciNames.Of</c> call site inside the map-key composition takes the
    /// <c>ITypeReference</c> overload — asserted as set equality, so it also fails if the composition stops calling
    /// <c>CciNames.Of</c> at all (a vacuous pass) as well as if it starts calling the <c>IMethodReference</c> one.
    /// </summary>
    [Fact]
    public void MapKeyComposition_CallsTheTypeOverloadOfCciNamesOf_AndNeverTheMethodReferenceOverload()
    {
        var overloads = KeyCompositionCallees
            .Where(callee => Name(callee) == "Of" && AssemblyAnalyzer.TypeName(callee.ContainingType) == CciNamesType)
            .Select(Signature)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal([$"{CciNamesType}.Of({TypeReference})"], overloads);
    }

    /// <summary>
    /// The same requirement stated at its root cause, so a hand-rolled read is caught as well as the overload:
    /// nothing in the map-key composition reads a method reference's parameter list. <c>Parameters</c> is the
    /// property whose evaluation drives CCI's signature parser into <c>GetTypeReference()</c>; the key is
    /// signature-free by design, so a read of it would be both fatal on hostile input and pointless.
    /// </summary>
    [Fact]
    public void MapKeyComposition_NeverReadsACalleesParameterList()
    {
        var reads = KeyCompositionCallees
            .Where(callee => Name(callee) == "get_Parameters")
            .Select(Signature)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            reads.Length == 0,
            "The capability-map key composition reads a parameter list, which ADR-0021 forbids at this seam: "
                + string.Join(", ", reads));
    }

    /// <summary>
    /// Non-vacuity for both guards above, asserted separately so a rename fails as "the guard lost its subject"
    /// rather than as "the forbidden call is absent". <c>Match</c> and <c>ClassificationKey</c> are the two private
    /// members that compose and consume the map key; if either is renamed, inlined or split, this guard must be
    /// re-pointed at whatever composes the key now — it must not simply be deleted.
    /// </summary>
    [Fact]
    public void MapKeyComposition_SubjectMethodsExistAndCarryCallSites()
    {
        Assert.Equal(KeyCompositionMethods.Order(StringComparer.Ordinal), FoundMethodNames());

        Assert.NotEmpty(KeyCompositionCallees);
    }
    #endregion

    #region Methods — helpers
    // Every method reference on the far side of a call site in the map-key composition, read once per test class.
    private IReadOnlyList<IMethodReference> KeyCompositionCallees =>
        callees ??= [.. KeyCompositionMethods.SelectMany(CalleesOf)];

    // The callees of one named method of CapabilityAnalysis, read out of its compiled body.
    private IReadOnlyList<IMethodReference> CalleesOf(string methodName)
    {
        var subject = Assert.Single(SubjectMethods(methodName));

        var body = AssemblyAnalyzer.TryReadBody(subject).Body;
        Assert.NotNull(body);

        return [.. body!.Operations.Select(op => op.Value).OfType<IMethodReference>()];
    }

    private IMethodDefinition[] SubjectMethods(string methodName) =>
        [.. library.Methods.Where(m =>
            AssemblyAnalyzer.SafeName(m) == methodName &&
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition) == SubjectType)];

    private string[] FoundMethodNames() =>
        [.. KeyCompositionMethods.Where(name => SubjectMethods(name).Length > 0).Order(StringComparer.Ordinal)];

    // "Ns.Type.Method(Ns.Param, ...)" — the parameter list is what distinguishes the two CciNames.Of overloads,
    // and rendering it means a failure names the overload that was called instead of just a count.
    private static string Signature(IMethodReference callee) =>
        $"{AssemblyAnalyzer.TypeName(callee.ContainingType)}.{Name(callee)}"
            + $"({string.Join(", ", callee.Parameters.Select(p => AssemblyAnalyzer.TypeName(p.Type)))})";

    private static string Name(IMethodReference callee) => callee.Name?.Value ?? string.Empty;

    public void Dispose() => library.Dispose();
    #endregion

    #region Fields
    private const string SubjectType = "Silvergun.CodeAnalysis.IL.CapabilityAnalysis";
    private const string CciNamesType = "Silvergun.CodeAnalysis.IL.CciNames";
    private const string TypeReference = "Microsoft.Cci.ITypeReference";

    /// <summary>
    /// The two members of <see cref="CapabilityAnalysis"/> that compose and consume the map key. Private, so they
    /// cannot be named with <c>nameof</c> — the string is the point of contact, and the non-vacuity fact above
    /// exists precisely so a rename cannot silently empty this guard.
    /// </summary>
    private static readonly string[] KeyCompositionMethods = ["ClassificationKey", "Match"];

    private readonly AssemblyAnalyzer library;
    private IReadOnlyList<IMethodReference>? callees;
    #endregion
}
