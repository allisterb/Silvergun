namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using Xunit;

/// <summary>
/// Determinism (docs/agent/tasks/ssa-adapter.md, acceptance criterion 6): two sessions over the same folder give the same
/// per-method outcomes, in the same order: node id, kind and reason. The folder mixes lifted methods and every kind of
/// Unknown the fixtures produce (stubs, emitted operand shapes, and a compiled netstandard2.0 assembly).
/// </summary>
[Collection(SsaSessionCollection.Name)]
public sealed class SsaDeterminismTests
{
    #region Methods
    [Fact]
    public void TwoSessionsOverOneFolder_GiveIdenticalOutcomes()
    {
        using var emitted = new EmittedAssembly();
        var paths = Folder(emitted);

        string[] Run()
        {
            using var lifted = new SsaLifted(paths);
            return lifted.Outcomes.Select(o => $"{o.NodeId} | {o.Failure?.Kind.ToString() ?? "Lifted"} | {o.Failure?.Reason}").ToArray();
        }
        var first = Run();
        var second = Run();

        Assert.True(first.Length > 50, $"Only {first.Length} outcomes: the folder is too small to say much.");
        Assert.Contains(first, o => o.Contains("| Lifted |", StringComparison.Ordinal));
        Assert.Contains(first, o => o.Contains("| UnresolvedFact |", StringComparison.Ordinal));
        Assert.Equal(first, second);
    }

    /// <summary>The same, across processes: nothing in an outcome depends on the process (hash seeds, load order).</summary>
    [Fact]
    public void TwoProcessesOverOneFolder_PrintIdenticalOutcomes()
    {
        using var emitted = new EmittedAssembly();
        var paths = Folder(emitted);

        string Run()
        {
            var result = ChildProcessProbe.Run(SsaHostileShapeTests.ProbeExe, TimeSpan.FromSeconds(180), [SsaLiftProbe.Verb, "0", "0", .. paths]);
            Assert.True(result.ExitedCleanly, result.Describe());
            return result.StandardOutput;
        }
        var first = Run();

        Assert.EndsWith("DONE", first.TrimEnd());
        Assert.Equal(first, Run());
    }

    // StubUser, SsaOperands and a copy of the compiled fixture, all in one directory.
    private static string[] Folder(EmittedAssembly emitted)
    {
        var operands = emitted.Save("SsaOperands", SsaBodyFixture.DefineOperands);
        var stubs = SsaStubFixture.WriteStubUser(emitted.Directory);
        var compiled = Path.Combine(emitted.Directory, Path.GetFileName(SsaBodyFixture.CompiledFixturePath));
        File.Copy(SsaBodyFixture.CompiledFixturePath, compiled);
        return [operands, stubs, compiled];
    }
    #endregion
}
