#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.Worker;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;

/// <summary>
/// The worker's engine on the net10.0 build (<c>docs/agent/tasks/yarax-worker-linux.md</c>, Phases 1 and 2). Which engine
/// the verb gets is pinned on every OS this build runs on (L1; Phase 2 replaced L6's "no cache" with the secure-path
/// <see cref="YaraXLinuxRulesCache"/>). The real-engine timeout runs the worker's own <see cref="YaraXWorkerEngine"/> in
/// this test host over the real <c>libyara_x_capi.so</c>: the embedded rules hold nothing slow, so the slow ruleset reaches
/// the engine through the <see cref="IYaraXRulesCache"/> seam instead of a planted cache entry (the Windows twin's way).
/// </summary>
public sealed class YaraXWorkerEngineLinuxTests
{
    #region Methods: L1 / Phase 2, the engine for this build
    // Linux: the YARA-X engine with the Linux rules cache at its default location (Phase 2, P3). Windows net10.0 (no YARA-X
    // library in this TFM's output) and anything else: the Unavailable engine. (That constructing the cache creates nothing
    // is pinned on a private location by YaraXLinuxRulesCacheTests: the default one here is shared with every real worker
    // this host runs in parallel, so its existence cannot be compared before and after.)
    [Fact]
    public void ForPlatform_IsTheYaraXEngineWithTheLinuxCacheAtItsDefaultLocation_OnLinux_AndUnavailableElsewhere()
    {
        var location = OperatingSystem.IsLinux() ? YaraXLinuxRulesCache.DefaultDirectory() : null;

        var engine = YaraWorkerEngines.ForPlatform(5);

        if (OperatingSystem.IsLinux())
        {
            var yarax = Assert.IsType<YaraXWorkerEngine>(engine);
            var cache = typeof(YaraXWorkerEngine).GetField("cache", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.True(cache is not null, "YaraXWorkerEngine.cache is gone; this test reads it.");
            var linux = Assert.IsType<YaraXLinuxRulesCache>(cache!.GetValue(yarax));
            Assert.NotNull(linux.Location);
            Assert.Equal(location, linux.Location);
        }
        else
        {
            Assert.IsType<UnavailableYaraWorkerEngine>(engine);
        }
    }

    // The verb's fatal on a build with no engine names where the engine does run.
    [Fact]
    public void TheUnavailableEngine_SendsTheFatalThatNamesWindowsAndLinux()
    {
        var fatal = Assert.IsType<WorkerFatal>(new UnavailableYaraWorkerEngine().Start());

        Assert.Equal("engine unavailable on this platform: the YARA-X worker engine runs on Windows and Linux only", fatal.Reason);
        Assert.Equal(UnavailableYaraWorkerEngine.Reason, fatal.Reason);
    }

    // L2: chosen by the OS at run time, not by the TFM (this net10.0 build also runs on Windows).
    [Fact]
    public void TheLibraryFileName_IsTheDllOnWindows_AndTheSharedObjectElsewhere() =>
        Assert.Equal(OperatingSystem.IsWindows() ? "yara_x_capi.dll" : "libyara_x_capi.so", YaraXNative.LibraryFileName);
    #endregion

    #region Methods: G3 on Linux, a timeout file is `timeout`
    // The ruleset holds the quadratic slow rule plus a marker rule. With a 2 s engine timeout the slow file is `timeout`
    // with the engine's own wording, never scanned or an error, and the file after it is still scanned on the same scanner.
    [LinuxYaraXFact]
    [Trait("Category", "Slow")]
    public void Timeout_ASlowFileTimesOut_AndTheNextIsStillScanned()
    {
        var marker = RandomNumberGenerator.GetBytes(32);
        var planted = new PlantedRules(
            "rule slow_quadratic { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( uint8(i) == 1 and uint8(j) == 2 ) ) }",
            $"rule after_the_timeout {{ strings: $m = {{ {Convert.ToHexString(marker)} }} condition: $m }}");
        using var tree = new LinuxScanTree("engine-linux-timeout");
        var slow = tree.Write("slow.bin", new byte[64 * 1024]);
        var next = tree.Write("next.bin", marker);
        using var engine = new YaraXWorkerEngine(2, planted);

        var ready = Assert.IsType<WorkerReady>(engine.Start());
        var timedOut = engine.Scan(new WorkerRequest(0, slow));
        var scanned = engine.Scan(new WorkerRequest(1, next));

        Assert.Equal((2, WorkerProtocol.CanaryPassed, 0), (ready.RuleCount, ready.Canary, ready.RuleSourceErrors));
        Assert.Equal(new[] { YaraXRules.SourcesSha256Of(YaraRuleResources.ReadAll()) }, planted.Asked);   // the embedded rules' key
        Assert.Equal((WorkerScanStatus.Timeout, "the scan did not finish within the engine timeout of 2 s"), (timedOut.Status, timedOut.Reason));
        Assert.Equal(WorkerScanStatus.Scanned, scanned.Status);
        Assert.Equal(new[] { "after_the_timeout" }, scanned.Hits!.Select(h => h.Rule));
    }
    #endregion

    #region Nested types
    // A rules "cache" that always answers with one fixed ruleset (compiled now, with its own canary) and stores nothing.
    private sealed class PlantedRules : IYaraXRulesCache
    {
        public PlantedRules(params string[] sources)
        {
            Assert.True(YaraXNative.TryLoad(out var failure), $"the YARA-X engine did not load: {failure}");
            rules = YaraXRules.Compile(sources.Select((text, i) => ($"planted-{i}.yar", text)).ToArray(), out var compileFailure)
                ?? throw new InvalidOperationException($"the planted rules did not compile: {compileFailure}");
        }

        public List<string> Asked { get; } = [];

        public YaraXRules? TryLoad(string sourcesSha256)
        {
            Asked.Add(sourcesSha256);
            return rules;
        }

        public bool Store(YaraXRules rules) => false;

        private readonly YaraXRules rules;
    }
    #endregion
}
#endif
