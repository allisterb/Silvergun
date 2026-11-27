namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using Silvergun.MCPServer.Jobs;

using Xunit.Abstractions;

/// <summary>A completed standard entry of <see cref="InspectFixtures.SmallPackage"/>, for the timing test.</summary>
public sealed class InspectTimingFixture : IAsyncLifetime
{
    #region Properties
    public string JobId { get; private set; } = "";

    internal DrillTools Tools { get; private set; } = null!;
    #endregion

    #region Methods
    public async Task InitializeAsync()
    {
        var manager = InProcess.Manager(dirs);
        Tools = new DrillTools(manager);
        var view = await InProcess.RunToEndAsync(manager, InspectFixtures.SmallPackage(dirs.Root));
        Assert.True(view.State == JobState.Completed, $"{view.State} {view.Reason}");
        JobId = view.JobId;
    }

    public Task DisposeAsync()
    {
        dirs.Dispose();
        return Task.CompletedTask;
    }
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    #endregion
}

/// <summary>
/// Accept (task S3): one inspect child process per <c>disassemble</c> costs a median of under 1.5 s. Runs in the
/// non-parallel collection, alone, so other suites' processes do not crowd it; one warm-up call is discarded (the first run
/// of the apphost pays the OS file cache); the median of <see cref="Calls"/> calls is robust to a few slow ones. The
/// measurements go to the test output and to <c>%TEMP%/silvergun-mcp-tests/inspect-timing.txt</c> (measured, not quoted).
/// </summary>
[Collection(ProcessCountingCollection.Name)]
public sealed class InspectTimingTests(InspectTimingFixture fixture, ITestOutputHelper output) : IClassFixture<InspectTimingFixture>
{
    #region Methods
    [Fact]
    public async Task Disassemble_OneInspectChildPerCall_HasAMedianUnderOneAndAHalfSeconds()
    {
        await Call();
        var times = new List<double>();
        for (var i = 0; i < Calls; i++)
        {
            var clock = Stopwatch.StartNew();
            await Call();
            times.Add(clock.Elapsed.TotalSeconds);
        }

        var sorted = times.Order().ToList();
        var median = (sorted[Calls / 2] + sorted[(Calls - 1) / 2]) / 2;
        var report = string.Create(CultureInfo.InvariantCulture,
            $"{DateTime.UtcNow:O} {Environment.OSVersion.Platform}: median {median:0.000} s, min {sorted[0]:0.000} s, max {sorted[^1]:0.000} s over {Calls} calls: {string.Join(", ", times.Select(t => t.ToString("0.000", CultureInfo.InvariantCulture)))}");
        output.WriteLine(report);
        try
        {
            var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "silvergun-mcp-tests")).FullName;
            File.AppendAllText(Path.Combine(dir, "inspect-timing.txt"), report + Environment.NewLine);
        }
        catch (IOException) { /* the record is a convenience; the assertion is the test */ }
        Assert.True(median < 1.5, report);
    }
    #endregion

    #region Methods: helpers
    private async Task Call()
    {
        var result = Drill.Checked(await fixture.Tools.Disassemble(fixture.JobId, InspectFixtures.FixtureDll, "0x06000002"));
        Assert.True(Drill.Status(result) == "Succeeded", Drill.S(result).ToString());
    }
    #endregion

    #region Fields
    private const int Calls = 15;
    #endregion
}
