namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

/// <summary>
/// Shared xUnit class fixture: initializes the Silvergun runtime (null logging) once and holds a single
/// successfully-loaded <see cref="AssemblyAnalyzer"/> over the fixture assembly for the capability-scan tests.
/// This is the CCI-direct counterpart of <see cref="AssemblyDisassemblerFixture"/> (ADR 0009): the capability analysis
/// now reads CCI directly rather than lifting through Analysis.Net.
/// </summary>
public sealed class AssemblyAnalyzerFixture : IDisposable
{
    public AssemblyAnalyzerFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        FixturePath = typeof(Shapes).Assembly.Location;

        var result = AssemblyAnalyzer.Load(FixturePath);
        if (!result.IsSuccess)
        {
            throw new InvalidOperationException(
                $"Failed to load AssemblyAnalyzer for '{FixturePath}': {result.Message}",
                result.Exception);
        }

        Assembly = result.Value;
    }

    public AssemblyAnalyzer Assembly { get; }

    public string FixturePath { get; }

    public void Dispose() => Assembly.Dispose();
}
