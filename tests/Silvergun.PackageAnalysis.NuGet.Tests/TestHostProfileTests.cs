#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The test host's own default YARA path since T6b (see <see cref="TestHostProfile"/>): a scan that injects no backend
/// runs the real YARA-X worker, and that worker's rules cache is in the host's private profile, never the user's.
/// </summary>
public sealed class TestHostProfileTests
{
    #region Methods
    // Children inherit the private profile; this process's own known folders are untouched by it.
    [Fact]
    public void TheTestHost_GivesItsChildrenAPrivateUserProfile_WithoutMovingItsOwnKnownFolders()
    {
        Assert.Equal(TestHostProfile.Root, Environment.GetEnvironmentVariable("USERPROFILE"));
        Assert.True(Directory.Exists(TestHostProfile.Root));
        foreach (var folder in new[] { Environment.SpecialFolder.UserProfile, Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.ApplicationData })
            Assert.DoesNotContain(TestHostProfile.Root, Environment.GetFolderPath(folder, Environment.SpecialFolderOption.DoNotVerify), StringComparison.OrdinalIgnoreCase);
    }

    // The default backend really runs here (the worker is the Silvergun.CLI.exe in this test bin, amendment (o) step 2),
    // completes, and keeps its compiled rules in the private profile's cache.
    [Fact]
    public void ADefaultScanInTheTestHost_RunsTheYaraXWorker_WithItsRulesCacheInThePrivateProfile()
    {
        var engine = Environment.GetEnvironmentVariable(YaraXWorkerScanner.EngineVar);
        Assert.True(YaraScannerFactory.Shared is YaraXWorkerScanner,
            $"the test host's shared backend is {YaraScannerFactory.Shared.GetType().Name}, not the default YARA-X worker ({YaraXWorkerScanner.EngineVar}='{engine}')");
        using var dir = new YaraXTempDir("testhost-default");
        var nupkg = YaraXWorkerScannerProtocolTests.Nupkg(dir, "SilvergunTestHostDefault");

        var scan = PackageScanner.Scan(nupkg, resolveReferences: false);

        Assert.True(scan.IsSuccess, scan.Message);
        Assert.Equal(YaraScanStatus.Completed, scan.Value.YaraScanStatus);
        Assert.Empty(scan.Value.YaraFindings);
        var cache = Path.Combine(TestHostProfile.Root, "AppData", "Local", "Silvergun", "yara-x-rules");
        Assert.True(Directory.Exists(cache) && Directory.GetFiles(cache, "rules-*.sgyx").Length > 0,
            $"the worker's rules cache is not under the test host's private profile '{TestHostProfile.Root}'");
    }
    #endregion
}
#endif
