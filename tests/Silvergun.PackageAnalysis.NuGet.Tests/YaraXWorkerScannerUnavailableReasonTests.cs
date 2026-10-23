#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

using static FakeWorkerScript;

/// <summary>
/// <see cref="YaraXWorkerScanner.UnavailableReason"/> (ADR 0033 polish round): why the backend is not
/// <see cref="YaraXWorkerScanner.Available"/>, for an operator to act on. It is the availability probe's failure (the
/// worker's <c>fatal</c>, no worker executable, a worker that is not genuine), or that the scanner was disposed; and
/// <c>null</c> exactly when it is available. Descriptive only, never a health signal: <see cref="YaraXWorkerScanner.Available"/>
/// stays the gate. Driven through the internal test constructor against the FakeYaraProbe's scripted worker.
/// </summary>
public sealed class YaraXWorkerScannerUnavailableReasonTests
{
    #region Methods
    [Fact]
    public void UnavailableReason_WhenAvailable_IsNull()
    {
        using var script = new FakeWorkerScript("reason-ok").GenuineThroughout();
        using var scanner = script.Scanner();

        Assert.True(scanner.Available);
        Assert.Null(scanner.UnavailableReason);
        script.AssertNoOrphans();
    }

    // The probe's failure, verbatim from the backend's own warning: here the worker's fatal for a missing DLL.
    [Fact]
    public void UnavailableReason_WhenTheProbeSendsFatal_IsTheProbesFailure()
    {
        using var script = new FakeWorkerScript("reason-fatal").Run(1, "out " + Fatal("engine unavailable: yara_x_capi.dll is not in the application directory"), "exit 3");
        using var scanner = script.Scanner();

        var reason = scanner.UnavailableReason;   // reading it runs the probe

        Assert.False(scanner.Available);
        Assert.Equal("the worker reported a fatal error: engine unavailable: yara_x_capi.dll is not in the application directory", reason);
        Assert.Single(script.Pids);   // the probe ran once, for both reads
        script.AssertNoOrphans();
    }

    // The worker's text is hostile: its fatal reason reaches UnavailableReason escaped, never raw.
    [Fact]
    public void UnavailableReason_FromAHostileFatal_IsEscaped()
    {
        using var script = new FakeWorkerScript("reason-hostile").Run(1, "out " + Fatal("dll\n[ERR] forged" + (char)0x202E + (char)0x1B + "[31m"), "exit 3");
        using var scanner = script.Scanner();

        var reason = scanner.UnavailableReason;

        Assert.NotNull(reason);
        Assert.Equal(@"the worker reported a fatal error: dll\n[ERR] forged" + EscapedRlo + @"\x1b[31m", reason);
        Assert.DoesNotContain(reason!, c => c < ' ' || c == (char)0x202E);
        script.AssertNoOrphans();
    }

    [Fact]
    public void UnavailableReason_WithNoWorkerExecutable_SaysSo()
    {
        using var scanner = new YaraXWorkerScanner(null, ["--fake-worker", "unused"], 30,
            TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

        Assert.False(scanner.Available);
        Assert.Equal("the worker executable's path is unknown or not absolute", scanner.UnavailableReason);
    }

    // After Dispose the backend is unavailable, and says it was disposed, whether or not it had been available.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void UnavailableReason_AfterDispose_SaysItWasDisposed(bool probedFirst)
    {
        using var script = new FakeWorkerScript("reason-disposed").GenuineThroughout();
        var scanner = script.Scanner();
        if (probedFirst)
            Assert.True(scanner.Available);

        scanner.Dispose();

        Assert.False(scanner.Available);
        Assert.Equal("the scanner has been disposed", scanner.UnavailableReason);
        Assert.Equal(probedFirst ? 1 : 0, script.Pids.Length);   // asking a disposed scanner runs no probe
        script.AssertNoOrphans();
    }

    // The backslash-u form YaraPathSafety.Escape renders U+202E as, built so this source never carries the escape
    // sequence (or the character) itself.
    private const string EscapedRlo = @"\" + "u202e";

    // Through PackageScanner: the report carries the backend's reason, prefixed, and the warning names it.
    [Fact]
    public void PackageScanner_WithAnUnavailableWorker_ReportsTheBackendsReason()
    {
        using var script = new FakeWorkerScript("reason-pkg").Run(1, "out " + Fatal("engine unavailable: yara_x_capi.dll is not in the application directory"), "exit 3");
        using var dir = new YaraXTempDir("reason-pkg");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunReasonPackage");
        using var scanner = script.Scanner();

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false, yaraScanner: scanner);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Unavailable, scan.Value.YaraScanStatus);
        Assert.Equal("no working YARA backend: the worker reported a fatal error: engine unavailable: yara_x_capi.dll is not in the application directory",
            scan.Value.YaraUnavailableReason);
        script.AssertNoOrphans();
    }
    #endregion
}
#endif
