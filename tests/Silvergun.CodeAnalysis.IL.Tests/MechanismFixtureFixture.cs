namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Shared xUnit class fixture for the mechanism-fixture tests: initializes the runtime once, loads both
/// mechanism-fixture assemblies with <see cref="AssemblyAnalyzer"/> (raw CCI, by path — see
/// <see cref="MechanismFixtureAssemblies"/>), reads their direct call sites (<see cref="MechanismCallSites"/>), and
/// runs the <b>existing</b> <see cref="CapabilityAnalysis"/> over each once.
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
            CallSites = MechanismCallSites.Read(Fixture, Dependency);
            Findings = [.. Analyze(Fixture), .. Analyze(Dependency)];
        }
        catch (Exception)
        {
            // A partially constructed fixture is never disposed by xUnit; release what already loaded.
            Fixture.Dispose();
            Dependency?.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public AssemblyAnalyzer Fixture { get; }

    public AssemblyAnalyzer Dependency { get; }

    public MechanismCallSites CallSites { get; }

    /// <summary>Every <see cref="CapabilityAnalysis"/> finding over both assemblies.</summary>
    public IReadOnlyList<ApiCallFinding> Findings { get; }
    #endregion

    #region Methods
    public void Dispose()
    {
        Fixture.Dispose();
        Dependency.Dispose();
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
