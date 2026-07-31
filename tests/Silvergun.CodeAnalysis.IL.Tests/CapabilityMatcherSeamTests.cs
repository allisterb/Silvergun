namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Pins the <b>live</b> capability-matching seam: <see cref="CapabilityAnalysis.Catalog"/> prefix-matches
/// against <see cref="AssemblyAnalyzer.TypeName"/> (which delegates to CCI's
/// <c>TypeHelper.GetTypeName(type, NameFormattingOptions.None)</c>), and <em>nothing pinned that renderer's
/// output before this class</em>.
/// <para>
/// This is a different seam from <see cref="CanonicalName.ClassificationKey(MethodIdentity)"/> — that one is
/// what the (still inert) <c>capabilities.cm</c> map keys on, and it renders a <c>`N</c> arity suffix and no
/// generic arguments at all. The matcher that actually runs today is the hard-coded catalog against
/// <em>this</em> string, so its shape is a contract: a silent change to it changes which capability fires, or
/// whether one fires at all.
/// </para>
/// <para>
/// <b>The measured contract</b> (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.1 and §2.10 items
/// 1–2, over 604,115 entities): generic <em>arguments</em> render inline, generic <em>parameters</em> render by
/// metadata name, arguments are joined with <c>", "</c>, and there is <b>no</b> <c>`N</c> arity suffix. The
/// consequence the spike leaned on to explain <b>0 verdict changes across 43,107 verdicts</b> is structural,
/// not luck: every naming divergence it found lay strictly inside a <c>&lt;…&gt;</c> argument list, and no
/// catalog prefix contains <c>&lt;</c>, so <see cref="string.StartsWith(string, StringComparison)"/> can never
/// reach it. Both halves are asserted here.
/// </para>
/// </summary>
public sealed class CapabilityMatcherSeamTests : IClassFixture<AssemblyAnalyzerFixture>
{
    #region Constructors
    public CapabilityMatcherSeamTests(AssemblyAnalyzerFixture fixture) => this.fixture = fixture;
    #endregion

    #region Methods
    /// <summary>
    /// RENDERING CONTRACT — a <b>closed</b> generic declaring type renders its argument inline, fully qualified,
    /// and carries no arity suffix. <c>System.Collections.Generic.List&lt;System.Diagnostics.Process&gt;</c>, not
    /// <c>System.Collections.Generic.List`1</c> and not <c>System.Collections.Generic.List</c>.
    /// </summary>
    [Fact]
    public void TypeName_OfAClosedGenericDeclaringType_RendersTheArgumentInlineWithNoAritySuffix()
    {
        var declaringTypes = DeclaringTypeNamesIn(nameof(GenericCapabilityOps.HoldsProcessesAndStartsOne));

        Assert.Contains(ListOfProcess, declaringTypes);
        Assert.DoesNotContain(declaringTypes, name => name.Contains('`', StringComparison.Ordinal));
    }

    /// <summary>
    /// RENDERING CONTRACT — a <b>multi-argument</b> generic joins its arguments with <c>", "</c>: a comma
    /// followed by exactly one space. The delimiter is asserted as a literal because it is what any
    /// reimplementation of this renderer has to reproduce; CCI picks it from
    /// <c>NameFormattingOptions.OmitWhiteSpaceAfterListDelimiter</c>, which
    /// <see cref="NameFormattingOptions.None"/> leaves unset.
    /// </summary>
    [Fact]
    public void TypeName_OfAMultiArgumentGeneric_JoinsArgumentsWithCommaSpace()
    {
        var declaringTypes = DeclaringTypeNamesIn(nameof(GenericCapabilityOps.MapsProcessesByName));

        Assert.Contains(DictionaryOfStringToProcess, declaringTypes);
        Assert.Contains(", ", DictionaryOfStringToProcess);
        Assert.DoesNotContain(",S", DictionaryOfStringToProcess);
        Assert.DoesNotContain(" ,", DictionaryOfStringToProcess);
    }

    /// <summary>
    /// RENDERING CONTRACT — an <b>open</b> generic declaring type renders its generic parameters <em>by
    /// metadata name</em> (<c>T</c>, <c>TValue</c>), never positionally as <c>!0</c>/<c>!!0</c> and never as
    /// arity. A type parameter and a <em>method</em> type parameter sit side by side in the second case, so both
    /// kinds are covered. This is the shape the spike measured 14,645 times.
    /// </summary>
    [Fact]
    public void TypeName_OfAnOpenGenericDeclaringType_RendersGenericParametersByName()
    {
        Assert.Contains(ListOfT, DeclaringTypeNamesIn(nameof(GenericCallSiteHolder<int>.CollectsOne)));
        Assert.Contains(DictionaryOfTToTValue, DeclaringTypeNamesIn(nameof(GenericCallSiteHolder<int>.PairsWith)));

        Assert.DoesNotContain("!", ListOfT);
        Assert.DoesNotContain("!", DictionaryOfTToTValue);
        Assert.DoesNotContain("`", DictionaryOfTToTValue);
    }

    /// <summary>
    /// RENDERING CONTRACT — a generic type <b>definition</b> (which is what <c>ApiCallFinding.CallerType</c> is
    /// built from, via <c>TypeName(method.ContainingTypeDefinition)</c>) renders with <em>neither</em> arguments
    /// nor arity: <c>…GenericCallSiteHolder</c>, not <c>…GenericCallSiteHolder&lt;T&gt;</c> and not
    /// <c>…GenericCallSiteHolder`1</c>. The arity is asserted to be non-zero so this is a statement about a
    /// genuinely generic type.
    /// </summary>
    [Fact]
    public void TypeName_OfAGenericTypeDefinition_OmitsBothArgumentsAndArity()
    {
        var definition = Assert.Single(
            fixture.Assembly.Module.GetAllTypes().OfType<INamedTypeDefinition>(),
            type => AssemblyAnalyzer.TypeName(type) == GenericHolderDefinition);

        Assert.True(definition.GenericParameterCount > 0, "The subject must be a generic type for this to mean anything.");
        Assert.Equal(GenericHolderDefinition, AssemblyAnalyzer.TypeName(definition));
    }

    /// <summary>
    /// RENDERING CONTRACT — a <b>nested</b> generic instantiation joins its chain with <c>.</c> and renders each
    /// link's own arguments at that link, still with no arity suffix anywhere. The second shape is the one whose
    /// middle link is not itself instantiated, so it carries fewer arguments than the chain's cumulative arity —
    /// a CCI quirk pinned in <see cref="CanonicalNameParityTests"/> at the canonical-name layer, and pinned here
    /// at the layer the catalog actually matches.
    /// </summary>
    [Fact]
    public void TypeName_OfANestedGenericInstantiation_RendersArgumentsAtEachLinkOfADotJoinedChain()
    {
        var declaringTypes = DeclaringTypeNamesIn(nameof(CanonicalShapes.UsesOwnGenerics));

        Assert.Contains("Silvergun.CodeAnalysis.IL.Tests.Fixture.GenericOuter<System.Int32>.Inner<System.String>", declaringTypes);
        Assert.Contains("Silvergun.CodeAnalysis.IL.Tests.Fixture.GenericOuter<System.Int32>.Inner.Innermost<System.Boolean>", declaringTypes);
        Assert.DoesNotContain(declaringTypes, name => name.Contains('`', StringComparison.Ordinal));
    }

    /// <summary>
    /// RENDERING CONTRACT, corpus-wide: <b>no</b> call site anywhere in the fixture assembly renders an arity
    /// suffix. The non-vacuity guard is that a good number of them do render an argument list — otherwise
    /// "nothing contains a backtick" would be trivially true of a corpus with no generics in it.
    /// </summary>
    [Fact]
    public void TypeName_OfEveryCallSiteInTheFixture_NeverEmitsAnAritySuffix()
    {
        var declaringTypes = AllDeclaringTypeNames();

        Assert.True(
            declaringTypes.Count(name => name.Contains('<', StringComparison.Ordinal)) >= 10,
            "Too few generic declaring types in the corpus for the arity assertion to be meaningful.");
        Assert.DoesNotContain(declaringTypes, name => name.Contains('`', StringComparison.Ordinal));
    }

    /// <summary>
    /// THE STRUCTURAL INVARIANT behind the spike's "0 verdict changes across 43,107 verdicts": no catalog prefix
    /// contains <c>&lt;</c>, so a prefix match can never begin, let alone end, inside a generic argument list.
    /// Everything downstream in this class is a consequence of this one line.
    /// </summary>
    [Fact]
    public void Catalog_ContainsNoPrefixWithAnAngleBracket()
    {
        Assert.NotEmpty(CapabilityAnalysis.Catalog);
        Assert.DoesNotContain(
            CapabilityAnalysis.Catalog,
            api => api.TypePrefix.Contains('<', StringComparison.Ordinal) ||
                   api.TypePrefix.Contains('>', StringComparison.Ordinal));
    }

    /// <summary>
    /// THE CONSEQUENCE, at the shipping seam: holding a <see cref="System.Diagnostics.Process"/> in a
    /// <c>List&lt;&gt;</c> is not process execution. The declaring type of the <c>List&lt;Process&gt;</c> call
    /// sites literally contains the catalogued name <c>System.Diagnostics.Process</c> — asserted, so the test is
    /// about a real near-miss — but only inside the argument list, where <c>StartsWith</c> cannot see it.
    /// <para>
    /// The <see cref="System.Diagnostics.Process.Start(string)"/> call in the same body is the positive control:
    /// exactly one finding comes out of this method, and it is the real one. Without it the assertion would pass
    /// just as well on a method nobody scanned.
    /// </para>
    /// </summary>
    [Fact]
    public void Analyze_ACallOnAListOfProcess_IsNotClassifiedAsProcessExecution()
    {
        var declaringTypes = DeclaringTypeNamesIn(nameof(GenericCapabilityOps.HoldsProcessesAndStartsOne));

        // The near-miss is real: the catalogued name IS present in the rendering, just not at the front.
        Assert.Contains(ProcessPrefix, ListOfProcess);
        Assert.True(ListOfProcess.IndexOf(ProcessPrefix, StringComparison.Ordinal) > ListOfProcess.IndexOf('<'));
        // Three: the .ctor (newobj), Add and get_Count — re-derivable from the fixture source.
        Assert.Equal(3, declaringTypes.Count(name => name == ListOfProcess));

        var finding = Assert.Single(
            Report.Findings,
            f => f.CallerMethod == nameof(GenericCapabilityOps.HoldsProcessesAndStartsOne));

        // POSITIVE CONTROL: the one finding is the genuine Process.Start call, not a List<Process> call site.
        Assert.Equal(Capability.ProcessExecution, finding.Capability);
        Assert.Equal(ApiCallKind.Call, finding.Kind);
        Assert.Equal("System.Diagnostics.Process.Start", finding.CalledApi);
    }

    /// <summary>
    /// The same point with the catalogued type in the <b>second</b> argument position, and with no control call
    /// at all: a method that only builds and fills a
    /// <c>Dictionary&lt;System.String, System.Diagnostics.Process&gt;</c> yields <b>no</b> finding. The
    /// non-vacuity guard is the assertion that its three call sites exist and do carry the catalogued name.
    /// </summary>
    [Fact]
    public void Analyze_ADictionaryValuedByProcess_ProducesNoFindingAtAll()
    {
        var declaringTypes = DeclaringTypeNamesIn(nameof(GenericCapabilityOps.MapsProcessesByName));

        Assert.Equal(3, declaringTypes.Count(name => name == DictionaryOfStringToProcess));
        Assert.Contains(ProcessPrefix, DictionaryOfStringToProcess);

        Assert.DoesNotContain(
            Report.Findings,
            f => f.CallerMethod == nameof(GenericCapabilityOps.MapsProcessesByName));
    }

    /// <summary>
    /// Generalised over the whole fixture assembly: wherever a declaring type renders an argument list, any
    /// catalog prefix that matches it must lie entirely in the <em>head</em>, before the first <c>&lt;</c>. A
    /// match that extended past that point would mean the catalog had reached inside a generic argument — the
    /// exact false positive this seam is protected from only by <see cref="Catalog_ContainsNoPrefixWithAnAngleBracket"/>.
    /// </summary>
    [Fact]
    public void CatalogMatch_NeverExtendsPastTheFirstAngleBracketOfADeclaringType()
    {
        var generic = AllDeclaringTypeNames()
            .Where(name => name.Contains('<', StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.NotEmpty(generic);

        var reaching = generic
            .SelectMany(name => CapabilityAnalysis.Catalog
                .Where(api => name.StartsWith(api.TypePrefix, StringComparison.Ordinal) &&
                              api.TypePrefix.Length > name.IndexOf('<', StringComparison.Ordinal))
                .Select(api => $"[{api.TypePrefix}] reached into [{name}]"))
            .ToArray();

        Assert.Empty(reaching);
    }
    #endregion

    #region Methods (helpers)
    // The declaring-type rendering of every call site in the single fixture method of this name, read exactly
    // the way CapabilityAnalysis.Match reads it.
    private string[] DeclaringTypeNamesIn(string methodName)
    {
        var method = Assert.Single(fixture.Assembly.Methods, m => m.Name.Value == methodName);
        var body = AssemblyAnalyzer.TryReadBody(method).Body;

        Assert.NotNull(body);

        return CallSiteDeclaringTypeNames(body!).ToArray();
    }

    // The same, for every readable body in the assembly.
    private string[] AllDeclaringTypeNames() =>
        fixture.Assembly.Methods
            .Select(AssemblyAnalyzer.TryReadBody)
            .Where(read => read.Body is not null)
            .SelectMany(read => CallSiteDeclaringTypeNames(read.Body!))
            .ToArray();

    private static IEnumerable<string> CallSiteDeclaringTypeNames(IMethodBody body) =>
        body.Operations
            .Where(op => IsCallSite(op.OperationCode) && op.Value is IMethodReference)
            .Select(op => AssemblyAnalyzer.TypeName(((IMethodReference)op.Value!).ContainingType));

    // Verbatim the predicate the shipping scan uses (CapabilityAnalysis.Callee).
    private static bool IsCallSite(OperationCode code) =>
        code is OperationCode.Call or OperationCode.Callvirt or OperationCode.Newobj
             or OperationCode.Ldftn or OperationCode.Ldvirtftn;

    private CapabilityReport Report
    {
        get
        {
            var result = new CapabilityAnalysis(fixture.Assembly).Analyze();
            Assert.True(result.IsSuccess, result.Message);
            return result.Value;
        }
    }
    #endregion

    #region Fields
    private const string ProcessPrefix = "System.Diagnostics.Process";
    private const string ListOfProcess = "System.Collections.Generic.List<System.Diagnostics.Process>";
    private const string ListOfT = "System.Collections.Generic.List<T>";
    private const string DictionaryOfStringToProcess = "System.Collections.Generic.Dictionary<System.String, System.Diagnostics.Process>";
    private const string DictionaryOfTToTValue = "System.Collections.Generic.Dictionary<T, TValue>";
    private const string GenericHolderDefinition = "Silvergun.CodeAnalysis.IL.Tests.Fixture.GenericCallSiteHolder";

    private readonly AssemblyAnalyzerFixture fixture;
    #endregion
}
