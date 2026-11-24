namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using Xunit;

/// <summary>
/// <see cref="WorkerParentWatch"/> (<c>docs/agent/tasks/yarax-worker-linux.md</c>, L4): the parent pid it reads from a
/// <c>/proc/[pid]/stat</c> line, which must survive a command name holding spaces and parentheses (the kernel does not
/// escape it), and that it never starts off Linux. The end-to-end behaviour (a worker whose parent is SIGKILLed exits)
/// is <c>YaraWorkerVerbLinuxTests.WhenTheParentIsKilled_TheWorkerExits_WithinAboutTwoSeconds</c>.
/// </summary>
public sealed class WorkerParentWatchTests
{
    #region Methods: ParseParentPid
    [Theory]
    [InlineData("1234 (bash) S 1000 1234 1234 34816 1240 4194560 2052 0 0 0 1 0 0 0 20 0 1 0 2620 8892416 1271 18446744073709551615\n", 1000)]
    [InlineData("4242 (Silvergun.CLI) S 4100 4242 4100 0 -1 4194304 31 0 0 0 0 0 0 0 20 0 9 0 99 0 0", 4100)]
    [InlineData("7 (a b c) R 3 7 7", 3)]
    [InlineData("42 (x) (y) S 99 42 42", 99)]                // a command name holding ") ("
    [InlineData("42 ()) S 5 42 42", 5)]                      // a command name that is ")"
    [InlineData("42 (evil) 1 2 3) S 77 42", 77)]             // a forged field run inside the name: the LAST ')' ends it
    [InlineData("42 (  ) S 8 42", 8)]                        // a command name of spaces
    [InlineData("42 (x)   S    9   42", 9)]                  // runs of spaces between fields
    [InlineData("1 (init) S 0 1 1", 0)]                      // pid 1's parent
    [InlineData("42 (x) S 2147483647 42", int.MaxValue)]
    public void ParseParentPid_ReadsFieldFour_AfterTheLastParenthesis(string stat, int expected) =>
        Assert.Equal(expected, WorkerParentWatch.ParseParentPid(stat));

    [Theory]
    [InlineData("")]
    [InlineData("1234 bash S 1000")]                          // no parenthesised name
    [InlineData("1234 (bash)")]                               // nothing after the name
    [InlineData("1234 (bash) S")]                             // no parent field
    [InlineData("1234 (bash) S abc 1")]
    [InlineData("1234 (bash) S -1 1")]
    [InlineData("1234 (bash) S +5 1")]
    [InlineData("1234 (bash) S 1.5 1")]
    [InlineData("1234 (bash) S 2147483648 1")]                // overflow
    [InlineData("1234 (bash) S 99999999999 1")]
    [InlineData("1234 (a) S 1000) S")]                        // the last ')' leaves no parent field
    public void ParseParentPid_IsNull_ForWhatIsNotAStatLine(string stat) =>
        Assert.Null(WorkerParentWatch.ParseParentPid(stat));
    #endregion

    #region Methods: ParentPid and Start
    // On Linux the pid read from /proc/self/stat is the kernel's PPid (read independently from /proc/self/status);
    // elsewhere there is no /proc, and it is null rather than an exception.
    [Fact]
    public void ParentPid_IsTheKernelsPPid_OnLinux_AndNullElsewhere()
    {
        var parent = WorkerParentWatch.ParentPid();

        if (OperatingSystem.IsLinux())
        {
            var status = File.ReadAllLines("/proc/self/status").Single(l => l.StartsWith("PPid:", StringComparison.Ordinal));
            Assert.Equal(int.Parse(status["PPid:".Length..].Trim(), System.Globalization.CultureInfo.InvariantCulture), parent);
        }
        else
        {
            Assert.Null(parent);
        }
    }

    // Off Linux the watch never starts (the Job Object contains the worker on Windows); the orphan action can never run.
    // (On Linux, Start in this host would spend the once-per-process watch; it is covered end to end there instead.)
    [NonLinuxFact]
    public void Start_OffLinux_DoesNothing()
    {
        var ran = false;
        Assert.False(WorkerParentWatch.Start(TimeSpan.FromMilliseconds(10), () => ran = true));
        Assert.False(ran);
    }
    #endregion
}
