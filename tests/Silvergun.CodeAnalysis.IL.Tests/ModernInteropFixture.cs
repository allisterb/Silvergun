namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.MatrixFixture;

/// <summary>
/// Shared xUnit class fixture over the <b>net10.0</b> fixture assembly
/// (<c>Silvergun.CodeAnalysis.IL.Tests.MatrixFixture</c>), the CCI-direct counterpart of
/// <see cref="AssemblyAnalyzerFixture"/> for interop declaration shapes.
/// <para>
/// It exists because the shared fixture is netstandard2.0, where <c>[LibraryImport]</c> (net7+) and
/// <c>[UnmanagedCallersOnly]</c> (net5+) cannot be expressed at all. Loaded the same way — from
/// <c>typeof(ModernInteropOps).Assembly.Location</c> — so the tests read a real compiler output, including the
/// <c>[LibraryImport]</c> generator's emitted stubs, rather than a hand-written approximation of one.
/// </para>
/// </summary>
public sealed class ModernInteropFixture : IDisposable
{
    #region Constructors
    public ModernInteropFixture()
    {
        Runtime.Initialize("Silvergun", "TESTS");

        FixturePath = typeof(ModernInteropOps).Assembly.Location;

        var result = AssemblyAnalyzer.Load(FixturePath);
        if (!result.IsSuccess)
        {
            throw new InvalidOperationException(
                $"Failed to load AssemblyAnalyzer for '{FixturePath}': {result.Message}",
                result.Exception);
        }

        Assembly = result.Value;
    }
    #endregion

    #region Properties
    public AssemblyAnalyzer Assembly { get; }

    public string FixturePath { get; }
    #endregion

    #region Methods
    public void Dispose() => Assembly.Dispose();
    #endregion
}
