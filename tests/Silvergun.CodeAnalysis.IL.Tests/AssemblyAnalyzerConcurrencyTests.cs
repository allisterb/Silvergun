namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Linq;
using System.Threading.Tasks;

using Silvergun;
using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Tests.Fixture;

using Xunit;

/// <summary>
/// Load-safety smoke for the CCI-direct path (ADR 0009). Each <see cref="AssemblyAnalyzer.Load"/> creates a
/// fresh <c>PeReader.DefaultHost</c> and touches no process-wide CCI statics, so — unlike
/// <see cref="AssemblyDisassembler.Create"/>, which serializes on a shared lock to guard Analysis.Net's
/// non-concurrent statics — it needs no lock. Many parallel loads must all succeed.
/// </summary>
public sealed class AssemblyAnalyzerConcurrencyTests
{
    public AssemblyAnalyzerConcurrencyTests() => Runtime.Initialize("Silvergun", "TESTS");

    [Fact]
    public async Task Load_CalledConcurrently_AllSucceed()
    {
        const int degreeOfParallelism = 32;
        var fixturePath = typeof(Shapes).Assembly.Location;

        var tasks = Enumerable.Range(0, degreeOfParallelism)
            .Select(_ => Task.Run(() => AssemblyAnalyzer.Load(fixturePath)))
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
