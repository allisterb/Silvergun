namespace Silvergun.CodeAnalysis.IL.Tests;

using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Model.Types;

using Xunit;

/// <summary>
/// Read-only behavior over a single, shared, successfully-loaded analyzer
/// (fixture assembly). Covers acceptance cases 1 and 4-9.
/// </summary>
public sealed class AssemblyAnalyzerTests : IClassFixture<AnalyzerFixture>
{
    public AssemblyAnalyzerTests(AnalyzerFixture fixture) => this.fixture = fixture;

    // Case 1
    [Fact]
    public void Create_WithValidPath_LoadsAssemblyAndPath()
    {
        var result = AssemblyAnalyzer.Create(fixture.FixturePath);

        Assert.True(result.IsSuccess, result.Message);
        using var analyzer = result.Value;
        Assert.NotNull(analyzer.Assembly);
        Assert.Equal(fixture.FixturePath, analyzer.AssemblyPath);
    }

    // Case 4
    [Fact]
    public void Types_ContainsShapes_AndMethodsContainAllFiveFixtureMethods()
    {
        Assert.Contains(fixture.Analyzer.Types, t => t.Name == nameof(Shapes));

        var names = fixture.ShapesMethods.Select(m => m.Name).ToHashSet();
        Assert.Contains(nameof(Shapes.Straight), names);
        Assert.Contains(nameof(Shapes.Branch), names);
        Assert.Contains(nameof(Shapes.Loop), names);
        Assert.Contains(nameof(Shapes.TryCatch), names);
        Assert.Contains(nameof(Shapes.Calls), names);
    }

    // Case 5
    [Fact]
    public void DisassembleMethod_OnBranch_ProducesThreeAddressCodeWithInstructions()
    {
        var result = fixture.Analyzer.DisassembleMethod(fixture.Method(nameof(Shapes.Branch)));

        Assert.True(result.IsSuccess, result.Message);
        Assert.Equal(MethodBodyKind.ThreeAddressCode, result.Value.Kind);
        Assert.True(result.Value.Instructions.Count > 0);
    }

    // Case 6
    [Fact]
    public void DisassembleMethod_IsIdempotent_ReturnsSameTacBody()
    {
        var method = fixture.Method(nameof(Shapes.Loop));

        var first = fixture.Analyzer.DisassembleMethod(method);
        Assert.True(first.IsSuccess, first.Message);

        var second = fixture.Analyzer.DisassembleMethod(method);
        Assert.True(second.IsSuccess, second.Message);
        Assert.Equal(MethodBodyKind.ThreeAddressCode, second.Value.Kind);
        Assert.Same(first.Value, second.Value);
    }

    // Case 7
    [Fact]
    public void ControlFlowGraph_HasEntryExit_AndBranchLoopHaveMoreNodesThanStraight()
    {
        var straight = fixture.Analyzer.ControlFlowGraph(fixture.Method(nameof(Shapes.Straight)));
        var branch = fixture.Analyzer.ControlFlowGraph(fixture.Method(nameof(Shapes.Branch)));
        var loop = fixture.Analyzer.ControlFlowGraph(fixture.Method(nameof(Shapes.Loop)));

        Assert.True(straight.IsSuccess, straight.Message);
        Assert.True(branch.IsSuccess, branch.Message);
        Assert.True(loop.IsSuccess, loop.Message);

        Assert.NotNull(straight.Value.Entry);
        Assert.NotNull(straight.Value.Exit);

        Assert.True(branch.Value.Nodes.Count > straight.Value.Nodes.Count);
        Assert.True(loop.Value.Nodes.Count > straight.Value.Nodes.Count);
    }

    // Case 8
    [Fact]
    public void ControlFlowGraph_CalledTwice_ReturnsCachedInstance()
    {
        var method = fixture.Method(nameof(Shapes.Branch));

        var first = fixture.Analyzer.ControlFlowGraph(method);
        var second = fixture.Analyzer.ControlFlowGraph(method);

        Assert.True(first.IsSuccess, first.Message);
        Assert.True(second.IsSuccess, second.Message);
        Assert.Same(first.Value, second.Value);
    }

    // Case 9
    [Fact]
    public void DisassembleMethod_AllFiveFixtureMethods_Succeed()
    {
        foreach (var method in fixture.ShapesMethods)
        {
            var result = fixture.Analyzer.DisassembleMethod(method);
            Assert.True(result.IsSuccess, $"{method.Name}: {result.Message}");
            Assert.Equal(MethodBodyKind.ThreeAddressCode, result.Value.Kind);
        }
    }

    // Edge: Dispose is idempotent — a second call must be a no-op and must not throw.
    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var result = AssemblyAnalyzer.Create(fixture.FixturePath);
        Assert.True(result.IsSuccess, result.Message);

        var analyzer = result.Value;
        analyzer.Dispose();

        var second = Record.Exception(() => analyzer.Dispose());
        Assert.Null(second);
    }

    // Edge: a MethodDefinition without a body must return a failure Result, not throw.
    [Fact]
    public void DisassembleMethod_OnBodylessMethod_ReturnsFailureAndDoesNotThrow()
    {
        // A freshly constructed MethodDefinition has Body == null (HasBody == false).
        var returnType = fixture.Method(nameof(Shapes.Straight)).ReturnType;
        var bodyless = new MethodDefinition("Bodyless", returnType);
        Assert.False(bodyless.HasBody);

        var result = fixture.Analyzer.DisassembleMethod(bodyless);

        Assert.False(result.IsSuccess);
    }

    private readonly AnalyzerFixture fixture;
}
