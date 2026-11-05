namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.PackageAnalysis.NuGet;

using Xunit;

using CciAssertionMode = Microsoft.Cci.CciAssertionMode;
using CciAssertions = Microsoft.Cci.CciAssertions;

/// <summary>
/// ADR 0022 Stage 1, acceptance criterion 1, in process (<c>docs/agent/tasks/cci-assertions-stage1.md</c>): the cached,
/// third-party <c>Microsoft.Extensions.ApiDescription.Server</c> 10.0.11, whose <c>tools/net462</c> load used to die
/// with <c>0x80131623</c> (<c>Environment.FailFast</c>, "Assumption failed" in <c>CoreTypeReference.ResolvedType</c> via
/// <c>TypeBase.IsDelegate</c>, during <c>AssemblyDisassembler.Create</c>). Now <see cref="NuGetPackage.Open"/> plus
/// <see cref="PackageGraphs.Build(NuGetPackage, GraphBudget?, CapabilityMap?)"/> completes; both <c>tools</c> graphs count
/// the failed assertions in <see cref="IndexCoverage.ReaderAssertions"/>, every class of them reads Unknown with the
/// reader reason, the culprit assembly is pinned, and the raw-CCI scanner reads it too.
/// <para>
/// <b>In process, deliberately, and what guards it.</b> This suite has no child-process probe that runs the graph
/// pipeline; the crash-regression twin that runs it in a CHILD is <c>ReaderAssertionReproChildTests</c> in
/// Silvergun.CodeAnalysis.IL.Tests (the R2 child over the same package), so a regression to FailFast fails one test there.
/// Here, every test first asserts <see cref="CciAssertions.IsInstalled"/> and the default mode: the handler that turns a
/// failed contract from FailFast into a record is what makes running this in a test host survivable at all, and a
/// premise failure is what a missing one should produce, before the package is read.
/// </para>
/// <para>
/// Gated on the benign-corpus cache (skipped when absent, never downloaded). The package is read from the cache in place
/// and extracted to a temp directory by <see cref="NuGetPackage.Open"/>; nothing of it enters the repository.
/// </para>
/// </summary>
public sealed class ReaderAssertionReproTests : IClassFixture<ReaderAssertionRepro>
{
    #region Constructors
    public ReaderAssertionReproTests(ReaderAssertionRepro repro) => this.repro = repro;
    #endregion

    #region Methods
    [CachedCorpusPackageFact(ReproPackage)]
    public void OpenAndBuild_CompleteInProcess_AndOnlyTheTwoToolsGraphsCountReaderAssertions()
    {
        AssertContained();

        var graphs = repro.Graphs;

        // Measured 2026-11-05: exactly these two folders trip the reader; every other folder of the package is clean.
        Assert.Equal(DegradedFolders, graphs.Where(g => g.Graph is { Coverage.Index.ReaderAssertions: > 0 }).Select(g => g.Folder));
        foreach (var folder in DegradedFolders)
        {
            var graph = Assert.Single(graphs, g => g.Folder == folder);
            Assert.Empty(graph.LoadFailures);
            Assert.NotNull(graph.Graph);
            Assert.False(graph.Graph!.Coverage.Index.IsComplete);
        }
    }

    [CachedCorpusPackageFact(ReproPackage)]
    public void Reachability_OverEachToolsGraph_GivesEveryClassUnknown_WithTheReaderReason()
    {
        AssertContained();

        foreach (var graph in repro.Graphs.Where(g => DegradedFolders.Contains(g.Folder)))
        {
            var coverage = graph.Graph!.Coverage.Index;
            var report = Reachability.Analyze(graph.Graph);

            Assert.Equal(6, report.Classes.Count);
            Assert.All(report.Classes, c =>
            {
                Assert.Equal(RootClassVerdict.Unknown, c.Verdict);
                Assert.Contains($"the metadata reader failed {coverage.ReaderAssertions} assertion(s): the model may be degraded", c.Reasons);
                // The incomplete-index reason is for the index's other gaps only.
                Assert.Equal(!(coverage with { ReaderAssertions = 0 }).IsComplete,
                    c.Reasons.Any(r => r.StartsWith("the member index is incomplete", StringComparison.Ordinal)));
            });
        }
    }

    /// <summary>
    /// Which assembly trips it: each member of each <c>tools</c> folder loaded ALONE, so the count is that file's. Exactly
    /// <see cref="Culprit"/> in each, and the folder graph's count is at least that load's (the index adds any raised
    /// while indexing).
    /// </summary>
    [CachedCorpusPackageFact(ReproPackage)]
    public void TheCulprit_IsTheOneToolsAssemblyWhoseLoadFailsAnAssertion()
    {
        AssertContained();
        var graphs = repro.Graphs.Where(g => DegradedFolders.Contains(g.Folder)).ToDictionary(g => g.Folder);

        foreach (var folder in DegradedFolders)
        {
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var member in repro.Package.Assemblies.Where(a => Path.GetDirectoryName(a.RelativePath)!.Replace('\\', '/') == folder))
            {
                var created = AssemblyDisassembler.Create(member.FullPath);
                if (!created.IsSuccess)
                    continue;   // a native binary or a resource assembly: not loadable, so no reader to fail
                using var disassembler = created.Value;
                counts[Path.GetFileName(member.RelativePath)] = disassembler.ReaderAssertions;
            }

            Assert.Equal([Culprit], counts.Where(c => c.Value > 0).Select(c => c.Key));
            Assert.True(graphs[folder].Graph!.Coverage.Index.ReaderAssertions >= counts[Culprit],
                $"{folder}: the graph counts {graphs[folder].Graph!.Coverage.Index.ReaderAssertions}, the culprit's load alone {counts[Culprit]}.");
        }
    }

    /// <summary>
    /// The raw-CCI scanner (<see cref="AssemblyAnalyzer.Load"/> plus <see cref="CapabilityAnalysis"/>) over the culprit
    /// completes too: Stage 1 is that it no longer dies; reporting the count is Stage 1b.
    /// </summary>
    [CachedCorpusPackageFact(ReproPackage)]
    public void TheRawCciScanner_OverTheCulprit_Completes()
    {
        AssertContained();

        foreach (var folder in DegradedFolders)
        {
            var culprit = Assert.Single(repro.Package.Assemblies, a => a.RelativePath == $"{folder}/{Culprit}");
            var loaded = AssemblyAnalyzer.Load(culprit.FullPath);
            Assert.True(loaded.IsSuccess, loaded.Message);
            using var analyzer = loaded.Value;

            var analysis = new CapabilityAnalysis(analyzer).Analyze();

            Assert.True(analysis.IsSuccess, analysis.Message);
            Assert.True(analysis.Value.MethodsAnalyzed > 0);
        }
    }

    // The premises that make reading this package in a test host survivable: the handler is subscribed, and a failure
    // continues rather than throwing.
    private static void AssertContained()
    {
        Assert.True(CciAssertions.IsInstalled, "CCI's contract-failure handler is not installed: reading the repro in process would FailFast the test host.");
        Assert.True(CciAssertions.Mode == CciAssertionMode.RecordAndContinue,
            $"CciAssertions.Mode is {CciAssertions.Mode}: is {CciAssertions.ModeVariable} set in this environment?");
    }
    #endregion

    #region Fields
    /// <summary>The cached repro package (benign-corpus cache, <c>packages/</c>).</summary>
    public const string ReproPackage = "Microsoft.Extensions.ApiDescription.Server.10.0.11.nupkg";

    /// <summary>
    /// The assembly of <c>tools/net462</c> and <c>tools/net462-x86</c> whose load fails a CCI assertion, found by
    /// <see cref="TheCulprit_IsTheOneToolsAssemblyWhoseLoadFailsAnAssertion"/> (measured 2026-11-05).
    /// </summary>
    public const string Culprit = "Microsoft.OpenApi.dll";

    private static readonly string[] DegradedFolders = ["tools/net462", "tools/net462-x86"];

    private readonly ReaderAssertionRepro repro;
    #endregion
}

/// <summary>
/// The repro package opened once and its graphs built once (eagerly, every folder) for <see cref="ReaderAssertionReproTests"/>.
/// Lazy, so a run in which the gate skips every test never touches the cache, and so each test's containment premise is
/// checked before the package is first read. Released, with its temp extraction, when the class is done.
/// </summary>
public sealed class ReaderAssertionRepro : IDisposable
{
    #region Constructors
    public ReaderAssertionRepro()
    {
        state = new(() =>
        {
            Runtime.Initialize("Silvergun", "TESTS");
            var opened = NuGetPackage.Open(CachedCorpusPackageFactAttribute.PathOf(ReaderAssertionReproTests.ReproPackage));
            Assert.True(opened.IsSuccess, opened.Message);
            return (opened.Value, PackageGraphs.Build(opened.Value).ToArray());
        });
    }
    #endregion

    #region Properties
    public NuGetPackage Package => state.Value.Package;

    public IReadOnlyList<PackageGraph> Graphs => state.Value.Graphs;
    #endregion

    #region Methods
    public void Dispose()
    {
        if (state.IsValueCreated)
            state.Value.Package.Dispose();
    }
    #endregion

    #region Fields
    private readonly Lazy<(NuGetPackage Package, PackageGraph[] Graphs)> state;
    #endregion
}

/// <summary>
/// Gates a test on a package in the benign-corpus cache (<c>%LOCALAPPDATA%/Silvergun/benign-corpus/packages</c>, the
/// benign-corpus harness's default <c>--cache</c>): skipped, never downloaded, when it is absent. Skip, never an early
/// return (see <see cref="WindowsExtractionFactAttribute"/>). <c>LocalApplicationData</c> is this host's real one on
/// net10.0-windows too: <c>TestHostProfile</c> resolves it before it moves <c>USERPROFILE</c>.
/// </summary>
public sealed class CachedCorpusPackageFactAttribute : FactAttribute
{
    #region Constructors
    public CachedCorpusPackageFactAttribute(string fileName)
    {
        if (!File.Exists(PathOf(fileName)))
            Skip = $"Needs {fileName} in the benign-corpus cache ({PathOf(fileName)}), and it is not there. Run the benign-corpus harness to fill it.";
    }
    #endregion

    #region Methods
    public static string PathOf(string fileName) =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify) is { Length: > 0 } local ? local : Path.GetTempPath(),
            "Silvergun", "benign-corpus", "packages", fileName);
    #endregion
}
