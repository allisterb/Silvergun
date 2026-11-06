#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.Threading.Tasks;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;

/// <summary>
/// <c>WorkerJobObject.Create(processMemoryLimit)</c> (<c>docs/agent/tasks/graph-worker.md</c> G3): a process in a job with a
/// per-process memory limit cannot commit past it; the same allocation in a job without one succeeds. The fake graph
/// worker waits for a line on stdin, so it is in the job before it allocates, then commits 512 MiB of native memory
/// (which no GC limit sees) and prints whether it could.
/// </summary>
public sealed class WorkerJobObjectMemoryLimitTests
{
    #region Methods
    [Theory]
    [InlineData(256UL * 1024 * 1024, "alloc-failed")]
    [InlineData(0UL, "alloc-ok")]
    public async Task AProcessInTheJob_CannotCommitPastItsLimit(ulong limit, string expected)
    {
        using var script = new FakeGraphScript("job").Otherwise("wait", "tryalloc native 512");
        script.Launch();
        var info = new ProcessStartInfo(FakeGraphScript.ProbePath) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        info.ArgumentList.Add("--fake-graph-worker");
        info.ArgumentList.Add(script.ScriptPath);
        using var job = WorkerJobObject.Create(limit);
        using var process = Process.Start(info)!;
        try
        {
            job.Assign(process);
            await process.StandardInput.WriteLineAsync("go");
            await process.StandardInput.FlushAsync();
            var output = process.StandardOutput.ReadToEndAsync();

            Assert.True(process.WaitForExit(60_000), "the fake did not exit");
            Assert.Equal(expected, (await output).Trim());
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
    }
    #endregion
}
#endif
