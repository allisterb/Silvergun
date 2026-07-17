namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Contract-level behavior for <see cref="AssemblyAnalyzer"/> itself (ADR 0009): its <see cref="AssemblyAnalyzer.Load"/>
/// factory (never throws), the exposed <c>AssemblyName</c>/<c>AssemblyPath</c>/<c>Methods</c> properties,
/// idempotent <see cref="AssemblyAnalyzer.Dispose"/>, and the static <see cref="AssemblyAnalyzer.TypeName"/> helper.
/// Each test creates its own instance (no shared fixture) and stays offline — local paths only.
/// This is the CCI-direct counterpart of <see cref="AssemblyDisassemblerTests"/>/<see cref="AssemblyDisassemblerFailureTests"/>.
/// </summary>
public sealed class AssemblyAnalyzerTests
{
    public AssemblyAnalyzerTests() => Runtime.Initialize("Silvergun", "TESTS");

    // 1 — happy path: a valid managed assembly loads and exposes coherent metadata.
    [Fact]
    public void Load_WithValidAssembly_ExposesNamePathAndMethods()
    {
        var fixturePath = typeof(Shapes).Assembly.Location;

        var result = AssemblyAnalyzer.Load(fixturePath);

        Assert.True(result.IsSuccess, result.Message);
        using var cci = result.Value;

        Assert.Equal("Silvergun.CodeAnalysis.IL.Tests.Fixture", cci.AssemblyName);
        Assert.True(Path.IsPathRooted(cci.AssemblyPath), $"AssemblyPath is not absolute: {cci.AssemblyPath}");
        Assert.True(File.Exists(cci.AssemblyPath), $"AssemblyPath does not exist: {cci.AssemblyPath}");
        Assert.NotEmpty(cci.Methods);
    }

    // 2 — missing file: a failure Result, never an exception.
    [Fact]
    public void Load_WithNonexistentPath_ReturnsFailureAndDoesNotThrow()
    {
        var path = Path.Combine(Path.GetTempPath(), $"silvergun_cci_missing_{Guid.NewGuid():N}.dll");

        Result<AssemblyAnalyzer> result = default!;
        var thrown = Record.Exception(() => result = AssemblyAnalyzer.Load(path));

        Assert.Null(thrown);
        Assert.False(result.IsSuccess);
    }

    // 3 — non-CLR file: a failure Result without throwing. Temp file removed in a finally.
    [Fact]
    public void Load_WithNonManagedFile_ReturnsFailureAndDoesNotThrow()
    {
        var path = Path.Combine(Path.GetTempPath(), $"silvergun_cci_notclr_{Guid.NewGuid():N}.dll");
        File.WriteAllText(path, "this is not a valid CLR module or assembly");

        try
        {
            Result<AssemblyAnalyzer> result = default!;
            var thrown = Record.Exception(() => result = AssemblyAnalyzer.Load(path));

            Assert.Null(thrown);
            Assert.False(result.IsSuccess);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // 4 — Dispose is idempotent: a second call must be a no-op and must not throw.
    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var result = AssemblyAnalyzer.Load(typeof(Shapes).Assembly.Location);
        Assert.True(result.IsSuccess, result.Message);

        var cci = result.Value;
        cci.Dispose();

        var second = Record.Exception(() => cci.Dispose());
        Assert.Null(second);
    }

    // 5 — TypeName produces a namespace-qualified full name with no assembly-qualifier noise.
    [Fact]
    public void TypeName_OnFixtureTypeReference_IsNamespaceQualifiedWithoutAssemblyNoise()
    {
        const string expected = "Silvergun.CodeAnalysis.IL.Tests.Fixture.Shapes";

        var result = AssemblyAnalyzer.Load(typeof(Shapes).Assembly.Location);
        Assert.True(result.IsSuccess, result.Message);
        using var cci = result.Value;

        // Reach a type reference through a loaded method's ContainingType.
        var name = cci.Methods
            .Select(m => AssemblyAnalyzer.TypeName(m.ContainingType))
            .First(n => n == expected);

        Assert.Equal(expected, name);
        Assert.Contains(".", name);
        Assert.DoesNotContain(",", name);   // no ", Assembly, Version=..." qualifier
        Assert.DoesNotContain("[", name);   // no generic-parameter / array noise
    }
}
