namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun;

using Xunit;

/// <summary>
/// Failure-path behavior. Each test creates its own analyzer (no shared fixture) and
/// asserts that <see cref="AssemblyDisassembler.Create"/> returns a failure Result rather
/// than throwing. Covers acceptance cases 2 and 3.
/// </summary>
public sealed class AssemblyDisassemblerFailureTests
{
    public AssemblyDisassemblerFailureTests() => Runtime.Initialize("Silvergun", "TESTS");

    // Case 2
    [Fact]
    public void Create_WithNonexistentPath_ReturnsFailureAndDoesNotThrow()
    {
        var path = Path.Combine(Path.GetTempPath(), $"silvergun_missing_{Guid.NewGuid():N}.dll");

        var result = AssemblyDisassembler.Create(path);

        Assert.False(result.IsSuccess);
    }

    // Case 3
    [Fact]
    public void Create_WithNonManagedPeFile_ReturnsFailure()
    {
        var path = Path.Combine(Path.GetTempPath(), $"silvergun_notpe_{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "this is not a managed PE file");

        try
        {
            var result = AssemblyDisassembler.Create(path);
            Assert.False(result.IsSuccess);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
