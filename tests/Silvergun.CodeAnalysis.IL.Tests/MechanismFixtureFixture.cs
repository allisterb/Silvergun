namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Shared xUnit class fixture for the mechanism-fixture tests: initializes the runtime once, loads the three
/// mechanism-fixture assemblies with <see cref="AssemblyAnalyzer"/> (raw CCI, by path — see
/// <see cref="MechanismFixtureAssemblies"/>), reads their direct call sites (<see cref="MechanismCallSites"/>), and
/// runs the <b>existing</b> <see cref="CapabilityAnalysis"/> over each once.
/// <para>
/// Two call-site views: <see cref="CallSites"/> over the Release fixture and its Dependency — the raw-CCI oracle of
/// <see cref="MechanismMethodGraphFixture"/>'s graph, which indexes exactly those two — and
/// <see cref="GroundTruthCallSites"/> over all three, the Debug-built fixture (A2 S2) included: what the ground-truth
/// table is written against, like <see cref="MechanismGraphSource"/>, whose index holds all three.
/// </para>
/// </summary>
public sealed class MechanismFixtureFixture : IDisposable
{
    #region Constructors
    public MechanismFixtureFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        Fixture = Load(MechanismFixtureAssemblies.Fixture);
        try
        {
            Dependency = Load(MechanismFixtureAssemblies.Dependency);
            Debug = Load(MechanismFixtureAssemblies.DebugFixture);
            CallSites = MechanismCallSites.Read(Fixture, Dependency);
            GroundTruthCallSites = MechanismCallSites.Read(Fixture, Dependency, Debug);
            Findings = [.. Analyze(Fixture), .. Analyze(Dependency), .. Analyze(Debug)];
        }
        catch (Exception)
        {
            // A partially constructed fixture is never disposed by xUnit; release what already loaded.
            Fixture.Dispose();
            Dependency?.Dispose();
            Debug?.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public AssemblyAnalyzer Fixture { get; }

    public AssemblyAnalyzer Dependency { get; }

    /// <summary>The Debug-built fixture (<c>MechanismFixture.Debug</c>, Optimize off).</summary>
    public AssemblyAnalyzer Debug { get; }

    /// <summary>The Release fixture and its Dependency: the oracle for the two-assembly acceptance graph.</summary>
    public MechanismCallSites CallSites { get; }

    /// <summary>All three assemblies: the view every ground-truth row is checked against.</summary>
    public MechanismCallSites GroundTruthCallSites { get; }

    /// <summary>Every <see cref="CapabilityAnalysis"/> finding over all three assemblies.</summary>
    public IReadOnlyList<ApiCallFinding> Findings { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Fixture.Dispose();
        Dependency.Dispose();
        Debug.Dispose();
    }

    private static AssemblyAnalyzer Load(string path)
    {
        var result = AssemblyAnalyzer.Load(path);
        return result.IsSuccess
            ? result.Value
            : throw new InvalidOperationException($"Failed to load '{path}': {result.Message}", result.Exception);
    }

    private static IReadOnlyList<ApiCallFinding> Analyze(AssemblyAnalyzer assembly)
    {
        var result = new CapabilityAnalysis(assembly).Analyze();
        if (!result.IsSuccess)
            throw new InvalidOperationException($"CapabilityAnalysis failed on '{assembly.AssemblyPath}': {result.Message}", result.Exception);
        if (result.Value.MethodsSkipped != 0)
            throw new InvalidOperationException(
                $"CapabilityAnalysis skipped methods of '{assembly.AssemblyName}': {string.Join("; ", result.Value.SkippedMethods)}");

        return result.Value.Findings.ToArray();
    }
    #endregion
}
