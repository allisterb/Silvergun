namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

using Model.Types;

/// <summary>
/// Shared xUnit class fixture: initializes the Silvergun runtime once and holds one
/// <see cref="AssemblyDisassembler"/> per flavour of <c>Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture</c>
/// (net472 and net10.0, built from identical source) for the TAC void-return regression tests. See
/// <c>docs/agent/measurements/tac-platformtypes-spike.md</c>.
/// </summary>
public sealed class VoidReturnFixtureFixture : IDisposable
{
    #region Constructors
    public VoidReturnFixtureFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        Net10 = Load(VoidReturnFixtureAssemblies.Net10);

        try
        {
            Net472 = Load(VoidReturnFixtureAssemblies.Net472);
        }
        catch (Exception)
        {
            // A partially constructed fixture is never disposed by xUnit; release what already loaded.
            Net10.Dispose();
            throw;
        }
    }
    #endregion

    #region Properties
    public AssemblyDisassembler Net10 { get; }

    public AssemblyDisassembler Net472 { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Disassembles <paramref name="typeName"/>.<paramref name="methodName"/> (declared directly on the
    /// fixture, not inherited) via <paramref name="analyzer"/>. Throws with a descriptive message rather than
    /// returning a failure <c>Result</c>: every fixture method here is expected to lift cleanly, so a failure
    /// is itself the regression these tests exist to catch, and it should surface as loudly as an assertion.
    /// </summary>
    public MethodBody Disassemble(AssemblyDisassembler analyzer, string typeName, string methodName)
    {
        var method = analyzer.Methods.SingleOrDefault(m => m.ContainingType.Name == typeName && m.Name == methodName)
            ?? throw new InvalidOperationException(
                $"No method '{typeName}.{methodName}' found in '{analyzer.AssemblyPath}'.");

        var result = analyzer.DisassembleMethod(method);
        if (!result.IsSuccess)
        {
            throw new InvalidOperationException(
                $"Failed to disassemble '{typeName}.{methodName}' in '{analyzer.AssemblyPath}': {result.Message}",
                result.Exception);
        }

        return result.Value;
    }

    public void Dispose()
    {
        Net10.Dispose();
        Net472.Dispose();
    }

    private static AssemblyDisassembler Load(string path)
    {
        var result = AssemblyDisassembler.Create(path);
        if (!result.IsSuccess)
        {
            throw new InvalidOperationException(
                $"Failed to create AssemblyDisassembler for '{path}': {result.Message}", result.Exception);
        }

        return result.Value;
    }
    #endregion
}
