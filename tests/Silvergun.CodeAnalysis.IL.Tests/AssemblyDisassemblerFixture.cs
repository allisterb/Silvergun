namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Model.Types;

/// <summary>
/// Shared xUnit class fixture: initializes the Silvergun runtime (null logging) once
/// and holds a single successfully-created <see cref="AssemblyDisassembler"/> over the
/// fixture assembly for the read-only tests.
/// </summary>
public sealed class AssemblyDisassemblerFixture : IDisposable
{
    public AssemblyDisassemblerFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        FixturePath = typeof(Shapes).Assembly.Location;

        var result = AssemblyDisassembler.Create(FixturePath);
        if (!result.IsSuccess)
        {
            throw new InvalidOperationException(
                $"Failed to create AssemblyDisassembler for '{FixturePath}': {result.Message}",
                result.Exception);
        }

        Analyzer = result.Value;
    }

    public AssemblyDisassembler Analyzer { get; }

    public string FixturePath { get; }

    /// <summary>Fixture methods declared on the <c>Shapes</c> type.</summary>
    public IEnumerable<MethodDefinition> ShapesMethods =>
        Analyzer.Methods.Where(m => m.ContainingType.Name == nameof(Shapes));

    public MethodDefinition Method(string name) =>
        ShapesMethods.Single(m => m.Name == name);

    public void Dispose() => Analyzer.Dispose();
}
