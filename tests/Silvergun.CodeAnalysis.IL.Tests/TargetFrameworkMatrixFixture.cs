namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Loads and analyzes <b>every</b> flavour of the multi-targeted fixture assembly
/// (<c>Silvergun.CodeAnalysis.IL.Tests.MatrixFixture</c>) once — one <see cref="AssemblyAnalyzer"/> and one
/// <see cref="CapabilityReport"/> per target framework — so the matrix tests can compare the analysis of the
/// <em>same source</em> as compiled by each flavour of the toolchain. See
/// <c>docs/agent/tasks/tfm-matrix-tests.md</c>.
/// <para>
/// It analyzes whatever <see cref="MatrixFixtureAssemblies.ByTargetFramework"/> discovered and deliberately does
/// <b>not</b> assert the matrix is complete: that is <see cref="MatrixFixtureAssembliesTests"/>' job, and it is a
/// separate test class with no fixture precisely so a shrunken matrix fails as <em>one</em> clear failure rather
/// than as every matrix test at once.
/// </para>
/// </summary>
public sealed class TargetFrameworkMatrixFixture : IDisposable
{
    #region Constructors
    public TargetFrameworkMatrixFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        var analyzers = new Dictionary<string, AssemblyAnalyzer>(StringComparer.Ordinal);
        var reports = new Dictionary<string, CapabilityReport>(StringComparer.Ordinal);

        // A partially constructed fixture is never disposed by xUnit, so anything already loaded must be
        // released before the failure escapes.
        try
        {
            foreach (var (targetFramework, path) in MatrixFixtureAssemblies.ByTargetFramework)
            {
                var loaded = AssemblyAnalyzer.Load(path);
                if (!loaded.IsSuccess)
                {
                    throw new InvalidOperationException(
                        $"Failed to load the {targetFramework} matrix fixture '{path}': {loaded.Message}", loaded.Exception);
                }

                analyzers[targetFramework] = loaded.Value;

                var analyzed = new CapabilityAnalysis(loaded.Value).Analyze();
                if (!analyzed.IsSuccess)
                {
                    throw new InvalidOperationException(
                        $"CapabilityAnalysis failed for the {targetFramework} matrix fixture '{path}': {analyzed.Message}",
                        analyzed.Exception);
                }

                reports[targetFramework] = analyzed.Value;
            }
        }
        catch (Exception)
        {
            foreach (var analyzer in analyzers.Values)
                analyzer.Dispose();
            throw;
        }

        this.analyzers = analyzers;
        Reports = reports;
    }
    #endregion

    #region Properties
    /// <summary>Target framework moniker to the capability report of the fixture assembly built for it.</summary>
    public IReadOnlyDictionary<string, CapabilityReport> Reports { get; }

    /// <summary>Every finding of every flavour, tagged with the target framework it came from.</summary>
    public IEnumerable<(string TargetFramework, ApiCallFinding Finding)> AllFindings =>
        Reports.SelectMany(entry => entry.Value.Findings.Select(finding => (entry.Key, finding)));
    #endregion

    #region Methods
    /// <summary>The report for <paramref name="targetFramework"/>; throws naming what was found if absent.</summary>
    public CapabilityReport Report(string targetFramework) =>
        Reports.TryGetValue(targetFramework, out var report)
            ? report
            : throw new InvalidOperationException(
                $"No capability report for '{targetFramework}'; the matrix holds " +
                $"[{string.Join(", ", Reports.Keys.OrderBy(k => k, StringComparer.Ordinal))}].");

    /// <summary>
    /// Bodied methods declared by the fixture's <em>own</em> source, i.e. excluding the types Roslyn synthesizes
    /// into the assembly when the target framework's BCL lacks them. <see cref="CapabilityReport.MethodsTotal"/>
    /// has no per-type form, so this is read from the analyzer directly.
    /// </summary>
    public int AuthoredBodiedMethods(string targetFramework) =>
        Analyzer(targetFramework).Methods.Count(m =>
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition).StartsWith(FixtureNamespace, StringComparison.Ordinal));

    /// <summary>
    /// Whether the flavour built for <paramref name="targetFramework"/> compiled a bodied method named
    /// <paramref name="methodName"/> on <paramref name="declaringTypeFullName"/>. Reads CCI directly (the same
    /// source <see cref="AuthoredBodiedMethods"/> reads), so it reflects what the toolchain actually emitted for
    /// that flavour rather than assuming it from the source's <c>#if</c> guard — used to confirm a TFM-divergent
    /// shape genuinely does or does not exist in one flavour's IL, independent of any capability-detection seam.
    /// </summary>
    public bool HasBodiedMethod(string targetFramework, string declaringTypeFullName, string methodName) =>
        Analyzer(targetFramework).Methods.Any(m =>
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition) == declaringTypeFullName &&
            m.Name.Value == methodName);

    public void Dispose()
    {
        foreach (var analyzer in analyzers.Values)
            analyzer.Dispose();
    }

    private AssemblyAnalyzer Analyzer(string targetFramework) =>
        analyzers.TryGetValue(targetFramework, out var analyzer)
            ? analyzer
            : throw new InvalidOperationException($"No analyzer for '{targetFramework}'.");
    #endregion

    #region Fields
    /// <summary>Namespace of every type the fixture project's source declares.</summary>
    public const string FixtureNamespace = "Silvergun.CodeAnalysis.IL.Tests.MatrixFixture.";

    private readonly IReadOnlyDictionary<string, AssemblyAnalyzer> analyzers;
    #endregion
}
