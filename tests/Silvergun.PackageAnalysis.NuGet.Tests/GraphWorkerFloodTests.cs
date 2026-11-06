namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Graph;

using Xunit;

/// <summary>Runs alone (xunit runs a collection that disables parallelization after all the others), so a process-wide allocation count is this test's.</summary>
[CollectionDefinition(nameof(GraphWorkerFloodCollection), DisableParallelization = true)]
public sealed class GraphWorkerFloodCollection;

/// <summary>
/// Review C1: a worker that floods stdout after <c>done</c> must not fill the parent's memory. The parent's pump reads no more
/// lines than the protocol has (ready, the folders, done) and hands them over through a bounded queue, so the flood is never
/// read: the child blocks in its own write, misses its exit, and the run ends AfterAll with every record kept.
/// <para>Measured with <see cref="GC.GetTotalAllocatedBytes(bool)"/> across the call, which counts every thread of this
/// process; the collection runs alone so nothing else allocates meanwhile. A parent that read the flood would allocate at
/// least one 16 MiB line array per line, at pipe speed, for the 5 s it waits for the exit: gigabytes.</para>
/// </summary>
[Collection(nameof(GraphWorkerFloodCollection))]
public sealed class GraphWorkerFloodTests : IDisposable
{
    #region Constructors
    public GraphWorkerFloodTests()
    {
        Runtime.Initialize("Silvergun", "TESTS");
        stage = new GraphStage("flood");
    }
    #endregion

    #region Methods
    [Theory]
    [InlineData("floodlines 16777000")]   // lines just within the 16 MiB record limit, forever
    [InlineData("flood")]                 // one endless line
    public void AFloodAfterDone_IsNeverRead_AndTheRecordsAreKept(string flood)
    {
        using var script = new FakeGraphScript("flood-after-done").Otherwise("request", "ready", "empty", "done", flood);
        var options = PackageReachabilityOptions.Default with { WorkerMemoryBytes = 0 };
        var launch = script.Launch();
        var a = stage.Small("lib/a");
        GC.Collect();
        var before = GC.GetTotalAllocatedBytes(precise: true);
        var clock = Stopwatch.StartNew();

        var report = PackageReachability.Analyze(a, options, launch);

        var allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"took {clock.Elapsed}");
        Assert.Equal(FolderOutcome.NothingLoaded, Assert.Single(report.Folders).Outcome);
        Assert.True(allocated < 64L * 1024 * 1024, $"the parent allocated {allocated / (1024 * 1024)} MiB during the run");
        Assert.Single(script.Pids);
        script.AssertNoOrphans();
    }

    /// <summary>
    /// The same flood in place of the folder record: the first oversized-or-junk line fails the folder, and the queue's bound
    /// keeps what the parent holds to a few records however fast the child writes.
    /// </summary>
    [Fact]
    public void AFloodOfRecordSizedLines_InsteadOfARecord_IsCrashed_AndBounded()
    {
        using var script = new FakeGraphScript("flood-records")
            .Run(1, "request", "ready", "floodlines 16777000")
            .Otherwise("request", "ready", "empty", "done");
        var options = PackageReachabilityOptions.Default with { WorkerMemoryBytes = 0 };
        var launch = script.Launch();
        var folders = new[] { stage.Small("lib/a"), stage.Small("lib/b") }.SelectMany(f => f).ToArray();
        GC.Collect();
        var before = GC.GetTotalAllocatedBytes(precise: true);

        var report = PackageReachability.Analyze(folders, options, launch);

        var allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
        Assert.Equal([FolderOutcome.Crashed, FolderOutcome.NothingLoaded], report.Folders.Select(f => f.Outcome));
        Assert.True(allocated < 256L * 1024 * 1024, $"the parent allocated {allocated / (1024 * 1024)} MiB during the run");
        script.AssertNoOrphans();
    }

    public void Dispose() => stage.Dispose();
    #endregion

    #region Fields
    private readonly GraphStage stage;
    #endregion
}
