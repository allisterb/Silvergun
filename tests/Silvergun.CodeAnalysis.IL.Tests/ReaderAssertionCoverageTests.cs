namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture;
using Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

using Xunit;

using CciAssertions = Microsoft.Cci.CciAssertions;
using CciDebug = Microsoft.Cci.CciDebug;
using ModelTypes = Model.Types;

/// <summary>
/// ADR 0022 Stage 1's coverage wiring (<c>docs/agent/tasks/cci-assertions-stage1.md</c>, acceptance criterion 3): a
/// failed CCI assertion is counted where the read happened — <see cref="AssemblyDisassembler.ReaderAssertions"/> for a
/// load, <see cref="IndexCoverage.ReaderAssertions"/> for an index (the loads' sum plus any raised while indexing) — and
/// a count above 0 makes the index incomplete, so no graph over degraded metadata can read as clean.
/// <para>
/// <b>The baseline.</b> Every compiled fixture this suite reads trips no assertion, through the graph loader
/// (<see cref="AssemblyDisassembler"/>) and through the raw-CCI scanner (<see cref="AssemblyAnalyzer"/> plus
/// <see cref="CapabilityAnalysis"/>, observed through a scope since it does not count them itself yet: Stage 1b). Before
/// Stage 1 a failed assertion killed the host, so 0 was implied; now one would be recorded and the read would go on, so
/// it is pinned here. <see cref="ModelAssemblies.Load"/> enforces the same on every load it makes, emitted assemblies
/// included.
/// </para>
/// </summary>
public sealed class ReaderAssertionCoverageTests
{
    #region Constructors
    public ReaderAssertionCoverageTests() => Runtime.Initialize("Silvergun", "TESTS");
    #endregion

    #region Methods
    // ---- IndexCoverage -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    public void IndexCoverage_IsComplete_OnlyWithoutReaderAssertions(int readerAssertions, bool complete) =>
        Assert.Equal(complete, new IndexCoverage(0, 0, 0, ReaderAssertions: readerAssertions).IsComplete);

    /// <summary>The count is the last parameter and defaults to 0, so every existing construction means "none failed".</summary>
    [Fact]
    public void IndexCoverage_WithoutAReaderAssertionCount_CountsNone() =>
        Assert.Equal(new IndexCoverage(0, 0, 0, 0, 0, 0), new IndexCoverage(0, 0, 0));

    /// <summary>
    /// "Plus any raised during the index build": a failure raised while <c>MemberIndex.Build</c> reads the model is
    /// counted in its coverage. Synthetic: an assembly reference whose name, read when a base type is
    /// keyed, fails a <see cref="CciDebug"/> assertion and returns normally — what a lazy CCI read inside Model could do.
    /// </summary>
    [Fact]
    public void MemberIndexBuild_CountsAFailureRaisedWhileIndexing()
    {
        var index = MemberIndex.Build([(AssertingAssembly(), TypeForwarders.None, ModuleMetadata.None)]);

        Assert.True(index.Coverage.ReaderAssertions >= 1, $"ReaderAssertions is {index.Coverage.ReaderAssertions}.");
        Assert.False(index.Coverage.IsComplete);
        Assert.Equal(new IndexCoverage(0, 0, 0, ReaderAssertions: index.Coverage.ReaderAssertions), index.Coverage);   // nothing else is missing
        Assert.Contains("Synthetic.Callers", index.TypeIds);   // and the type was still indexed
    }

    /// <summary>Twin: the same assembly with a reference that does not assert has a complete index.</summary>
    [Fact]
    public void MemberIndexBuild_WithoutAFailure_IsComplete()
    {
        var index = MemberIndex.Build([(AssertingAssembly(assert: false), TypeForwarders.None, ModuleMetadata.None)]);

        Assert.Equal(new IndexCoverage(0, 0, 0), index.Coverage);
    }

    // ---- the baseline over every compiled fixture ----------------------------------------------------------------

    public static TheoryData<string> CompiledFixtures => [.. fixtures.Select(f => f.Name)];

    /// <summary>Loaded alone through the graph loader, and indexed: no reader assertion, a complete index.</summary>
    [Theory]
    [MemberData(nameof(CompiledFixtures))]
    public void EveryCompiledFixture_LoadsAndIndexes_WithNoReaderAssertion(string fixture)
    {
        var created = AssemblyDisassembler.Create(PathOf(fixture));
        Assert.True(created.IsSuccess, created.Message);
        using var disassembler = created.Value;

        var index = MemberIndex.Build([disassembler]);

        Assert.Equal(0, disassembler.ReaderAssertions);
        Assert.Equal(0, index.Coverage.ReaderAssertions);
    }

    /// <summary>Read by the raw-CCI scanner, as the presence scan does: no assertion is raised on this flow.</summary>
    [Theory]
    [MemberData(nameof(CompiledFixtures))]
    public void EveryCompiledFixture_IsScannedByTheRawCciScanner_WithNoReaderAssertion(string fixture)
    {
        using var scope = CciAssertions.BeginScope();

        var loaded = AssemblyAnalyzer.Load(PathOf(fixture));
        Assert.True(loaded.IsSuccess, loaded.Message);
        using (var analyzer = loaded.Value)
            Assert.True(new CapabilityAnalysis(analyzer).Analyze().IsSuccess);

        Assert.True(scope.Count == 0, $"{fixture}: {scope.Count} CCI assertion(s) failed; first: {scope.Records.FirstOrDefault()}");
    }

    /// <summary>The fixtures that are indexed together (the mechanism trio, as MechanismGraphSource loads them) sum to 0 as well.</summary>
    [Fact]
    public void TheMechanismFixturesIndexedTogether_HaveNoReaderAssertion()
    {
        using var loaded = ModelAssemblies.Load(MechanismFixtureAssemblies.Fixture, MechanismFixtureAssemblies.Dependency, MechanismFixtureAssemblies.DebugFixture);

        Assert.All(loaded.Disassemblers, d => Assert.Equal(0, d.ReaderAssertions));
        Assert.Equal(0, loaded.Index().Coverage.ReaderAssertions);
    }

    private static string PathOf(string fixture) => fixtures.Single(f => f.Name == fixture).Path();

    // One class Synthetic.Callers whose base type's assembly name fails an assertion each time it is read (or not).
    private static Model.Assembly AssertingAssembly(bool assert = true)
    {
        var assembly = SyntheticModel.CallerAssembly("Silvergun.Tests.AssertingAssembly");
        var type = (ModelTypes.ClassDefinition)assembly.RootNamespace.Namespaces.Single().Types.Single();
        type.Base = new ModelTypes.BasicType("Base") { ContainingNamespace = "Elsewhere", ContainingAssembly = new AssertingAssemblyReference(assert) };
        return assembly;
    }
    #endregion

    #region Fields
    // Every compiled fixture of this suite that is read as an assembly (the patched and emitted ones are made per test;
    // ModelAssemblies.Load covers the emitted ones). The CyclicEnumProbe's PATCHED copy is excluded by construction: it
    // overflows the stack, which is no assertion and is covered out of process.
    private static readonly (string Name, Func<string> Path)[] fixtures =
    [
        ("Fixture", () => SharedFixtureMethodGraphFixture.Path),
        ("MechanismFixture", () => MechanismFixtureAssemblies.Fixture),
        ("MechanismFixture.Dependency", () => MechanismFixtureAssemblies.Dependency),
        ("MechanismFixture.Debug", () => MechanismFixtureAssemblies.DebugFixture),
        ("MechanismFixture.HostStubs", () => MechanismFixtureAssemblies.HostStubs),
        ("RootFixture", () => RootFixtureAssemblies.Fixture),
        ("RootFixture.HostStubs", () => RootFixtureAssemblies.HostStubs),
        ("RootFixture.Other", () => RootFixtureAssemblies.Other),
        ("ShadowFixture", () => ShadowFixtureAssembly.Path),
        ("MatrixFixture/net472", () => MatrixFixtureAssemblies.For("net472")),
        ("MatrixFixture/net10.0", () => MatrixFixtureAssemblies.For("net10.0")),
        ("VoidReturnFixture/net472", () => VoidReturnFixtureAssemblies.Net472),
        ("VoidReturnFixture/net10.0", () => VoidReturnFixtureAssemblies.Net10),
        ("MetadataShapesFixture", () => typeof(ThreeApis).Assembly.Location),
        ("IndicatorCapFixture", () => typeof(IndicatorCapPayloads).Assembly.Location),
        ("PathologicalSignatureProbe", () => typeof(PathologicalSignatureProbe.PathologicalShapes).Assembly.Location),
        // By path, not typeof: only its clean, uncorrupted build output, with its clean pdb beside it.
        ("AliasedPdbFixture", () => System.IO.Path.Combine(AppContext.BaseDirectory, "Silvergun.CodeAnalysis.IL.Tests.AliasedPdbFixture.dll")),
    ];
    #endregion

    #region Child types
    /// <summary>An assembly reference whose name read fails a CCI assertion first (when told to), then answers normally.</summary>
    private sealed class AssertingAssemblyReference(bool assert) : Model.IAssemblyReference
    {
        public string Name
        {
            get
            {
                CciDebug.Assert(!assert, "synthetic assertion while indexing");
                return "Elsewhere.Assembly";
            }
        }
    }
    #endregion
}
