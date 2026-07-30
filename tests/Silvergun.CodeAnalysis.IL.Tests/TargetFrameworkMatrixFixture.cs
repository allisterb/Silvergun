namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

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
    /// Methods with a readable IL body declared by the fixture's <em>own</em> source, i.e. excluding the types
    /// Roslyn synthesizes into the assembly when the target framework's BCL lacks them.
    /// <see cref="CapabilityReport.MethodsTotal"/> has no per-type form, so this is read from the analyzer directly.
    /// <para>
    /// <b>"Bodied" is asserted, not assumed.</b> <see cref="AssemblyAnalyzer.Methods"/> is a body-read
    /// <em>candidate</em> set (<c>!IsAbstract &amp;&amp; !IsExternal</c>, no <c>Body</c> dereference — see
    /// <c>docs/agent/tasks/per-method-body-read-granularity.md</c>), which is a superset in general, so the body is
    /// taken through <see cref="AssemblyAnalyzer.TryReadBody"/> to keep this counting what its name says. The
    /// counts this member returns — net472 11, net10.0 18, measured — are pinned by
    /// <c>TargetFrameworkMatrixTests.Baselines</c> as <c>AuthoredBodiedMethods</c>. What makes the word "bodied" in
    /// this member's name accurate is a different pin: <c>Analyze_EveryCandidateMethodHasAReadableBody</c> asserts
    /// the candidate and bodied sets coincide exactly, assembly-wide (net472 13, net10.0 18 — assembly-wide, so
    /// unlike the counts above they include the Roslyn-synthesized types this member filters out). So this filter
    /// is a no-op today and exists so that a future bodiless candidate changes the count instead of quietly
    /// redefining the baseline.
    /// </para>
    /// </summary>
    public int AuthoredBodiedMethods(string targetFramework) =>
        BodiedMethods(targetFramework).Count(m =>
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition).StartsWith(FixtureNamespace, StringComparison.Ordinal));

    /// <summary>
    /// Whether the flavour built for <paramref name="targetFramework"/> compiled a bodied method named
    /// <paramref name="methodName"/> on <paramref name="declaringTypeFullName"/>. Reads CCI directly (the same
    /// source <see cref="AuthoredBodiedMethods"/> reads, through the same <see cref="AssemblyAnalyzer.TryReadBody"/>
    /// seam), so it reflects what the toolchain actually emitted for that flavour rather than assuming it from the
    /// source's <c>#if</c> guard — used to confirm a TFM-divergent shape genuinely does or does not exist in one
    /// flavour's IL, independent of any capability-detection seam.
    /// </summary>
    public bool HasBodiedMethod(string targetFramework, string declaringTypeFullName, string methodName) =>
        BodiedMethods(targetFramework).Any(m =>
            AssemblyAnalyzer.TypeName(m.ContainingTypeDefinition) == declaringTypeFullName &&
            m.Name.Value == methodName);

    /// <summary>
    /// Every method of the flavour's assembly that has an IL body the analyzer can actually read: the candidate set
    /// narrowed through <see cref="AssemblyAnalyzer.TryReadBody"/>. Both a missing body and an unreadable one are
    /// excluded — neither is a method whose IL a shape assertion could be measured from.
    /// </summary>
    public IEnumerable<IMethodDefinition> BodiedMethods(string targetFramework) =>
        Analyzer(targetFramework).Methods.Where(m => AssemblyAnalyzer.TryReadBody(m).Body is not null);

    /// <summary>Every method the flavour's assembly offers as a body-read candidate, before any body is read.</summary>
    public IEnumerable<IMethodDefinition> CandidateMethods(string targetFramework) => Analyzer(targetFramework).Methods;

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
