namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Linq;
using System.Threading.Tasks;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Regression cover for the race in <see cref="AssemblyDisassembler.Create"/> over Analysis.Net's
/// process-wide, non-concurrent static state (<c>CCIProvider.TypeExtractor.attributesCache</c> and the
/// shared <c>Model.Types.PlatformTypes</c> instances). The load sequence is now serialized on a shared
/// lock, so <see cref="AssemblyDisassembler.Create"/> is documented safe to call concurrently. Pre-fix, many
/// parallel loads reliably threw <see cref="System.InvalidOperationException"/> from a corrupted
/// non-concurrent <c>Dictionary</c>; post-fix every concurrent create must succeed.
/// </summary>
public sealed class AssemblyDisassemblerConcurrencyTests
{
    public AssemblyDisassemblerConcurrencyTests() => Runtime.Initialize("Silvergun", "TESTS");

    [Fact]
    public async Task Create_CalledConcurrently_AllSucceedWithoutCorruptingSharedState()
    {
        const int degreeOfParallelism = 32;
        var fixturePath = typeof(Shapes).Assembly.Location;

        var tasks = Enumerable.Range(0, degreeOfParallelism)
            .Select(_ => Task.Run(() => AssemblyDisassembler.Create(fixturePath)))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        try
        {
            // Every concurrent load must succeed — no exception surfaced as a failure Result either.
            Assert.All(results, r => Assert.True(r.IsSuccess, r.Message));
        }
        finally
        {
            foreach (var result in results.Where(r => r.IsSuccess))
            {
                result.Value.Dispose();
            }
        }
    }
}
