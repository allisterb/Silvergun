#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

using Xunit;
using Xunit.Abstractions;

/// <summary>
/// Bringing the YARA-X engine up (ADR 0033 T2): <see cref="YaraXEngine.Load(YaraXRulesCache?)"/> over the REAL embedded
/// rules into a temp cache, and the DLL loader's process-wide, first-call-decides behaviour, which is observed in fresh
/// child processes (the <c>Silvergun.PackageAnalysis.NuGet.Tests.YaraXProbe</c> fixture) because the test host loaded
/// the engine long ago.
/// </summary>
public sealed class YaraXEngineTests(ITestOutputHelper output)
{
    #region Methods: the embedded rules
    // The real ruleset compiles with the canary, passes it, finds the HermeticWiper positive control (built from the
    // embedded rule at run time, see HermeticWiperSample), never reports the canary, and is cached: the second load comes
    // from the cache and behaves the same.
    [Fact]
    public void Load_TheEmbeddedRules_CompilesFindsThePositive_ThenLoadsFromTheCache()
    {
        YaraX.EnsureEngine();
        using var dir = new YaraXTempDir("engine");
        var cache = new YaraXRulesCache(dir.Combine("rules"));

        var clock = Stopwatch.StartNew();
        var compiled = YaraXEngine.Load(cache);
        var compileMs = clock.ElapsedMilliseconds;
        Assert.True(compiled.Rules is not null, compiled.Failure);
        clock.Restart();
        var cached = YaraXEngine.Load(cache);
        var cachedMs = clock.ElapsedMilliseconds;
        Assert.True(cached.Rules is not null, cached.Failure);
        output.WriteLine($"compile {compileMs} ms, cache load {cachedMs} ms, {compiled.Rules!.RuleCount} rules");

        using (compiled.Rules)
        using (cached.Rules)
        {
            Assert.False(compiled.FromCache);
            Assert.True(cached.FromCache);
            Assert.Equal(compiled.Rules.RuleCount, cached.Rules!.RuleCount);
            Assert.True(compiled.Rules.RuleCount > 300, $"only {compiled.Rules.RuleCount} embedded rules compiled");
            foreach (var rules in new[] { compiled.Rules, cached.Rules })
            {
                using var scanner = rules.CreateScanner(30);
                var hits = YaraX.Hits(scanner.Scan(HermeticWiperSample.Bytes));
                Assert.Contains(HermeticWiperSample.RuleName, hits);
                Assert.DoesNotContain(hits, h => h.StartsWith(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase));
                Assert.Empty(YaraX.Hits(scanner.Scan(rules.Canary.Marker)));
                Assert.Null(scanner.CheckCanary());
            }
        }
    }

    // No shipped rule may use the reserved prefix (Compile would refuse the whole set if one did).
    [Fact]
    public void TheEmbeddedRules_DoNotUseTheReservedCanaryPrefix()
    {
        var offenders = YaraRuleResources.ReadAll()
            .Where(r => r.Text.Contains(YaraXCanary.Prefix, StringComparison.OrdinalIgnoreCase))
            .Select(r => r.ResourceName)
            .ToArray();

        Assert.Empty(offenders);
    }

    [Fact]
    public void Load_WithNoSources_FailsAsAValue()
    {
        YaraX.EnsureEngine();

        var result = YaraXEngine.Load([], cache: null);

        Assert.Null(result.Rules);
        Assert.StartsWith("the YARA rules did not compile: there are no embedded YARA rule sources", result.Failure, StringComparison.Ordinal);
    }
    #endregion

    #region Methods: loading the DLL (child processes)
    // ADR 0033 T2: a missing DLL is "engine unavailable", returned, never a crash. The probe runs from a copy of this test
    // output WITHOUT yara_x_capi.dll; its first call is the production entry YaraXEngine.Load(cache), and after that the
    // engine stays unavailable for the whole process, even when asked to load from a directory that has the DLL.
    [Fact]
    public void WithTheDllMissing_LoadAndTryLoadReportEngineUnavailable_AndNothingCrashes()
    {
        using var copy = new YaraXTempDir("nodll");
        foreach (var file in Directory.EnumerateFiles(AppContext.BaseDirectory, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(AppContext.BaseDirectory, file);
            if (relative.Equals(YaraXNative.LibraryFileName, StringComparison.OrdinalIgnoreCase) || relative.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
                continue;
            Directory.CreateDirectory(Path.GetDirectoryName(copy.Combine(relative))!);
            File.Copy(file, copy.Combine(relative));
        }

        var run = Probe(Path.Combine(copy.Root, ProbeExeName), "missing", AppContext.BaseDirectory);

        Assert.Equal("False", run["dllpresent"]);
        Assert.Equal("null", run["load.rules"]);
        Assert.StartsWith("engine unavailable: yara_x_capi.dll is not in the application directory", run["load.failure"], StringComparison.Ordinal);
        Assert.Equal("False", run["tryload"]);
        Assert.Equal(run["load.failure"], run["tryload.failure"]);
        Assert.Equal("False", run["tryload.other"]);
        Assert.Equal("threw:InvalidOperationException", run["compile"]);
        Assert.Equal("0", run["modules"]);
    }

    [Fact]
    public void ARelativeApplicationDirectory_IsRefused_WithoutLoadingAnything()
    {
        var run = Probe(ProbeExe, "relative");

        Assert.Equal("False", run["tryload"]);
        Assert.Contains("is not an absolute path", run["tryload.failure"], StringComparison.Ordinal);
        Assert.Equal("0", run["modules"]);
    }

    // The import resolver hands back exactly the module loaded by absolute path, and never lets the runtime fall back to
    // its default search order. The probe runs from this output directory, which ALSO holds yara_x_capi.dll, and loads
    // the engine from a copy elsewhere: after a compile and a canary scan through the imports, the only yara_x_capi.dll
    // in the process must be that copy. A fallback would have mapped the application directory's DLL as a second module.
    [Fact]
    public void TheImportsBindOnlyToTheDllLoadedByAbsolutePath()
    {
        using var copy = new YaraXTempDir("dllcopy");
        File.Copy(Path.Combine(AppContext.BaseDirectory, YaraXNative.LibraryFileName), copy.Combine(YaraXNative.LibraryFileName));

        var run = Probe(ProbeExe, "resolver", copy.Root);

        Assert.Equal("True", run["tryload"]);
        Assert.Equal("ok", run["compile"]);
        Assert.Equal("passed", run["canary"]);
        var module = Assert.Single(run.All("module"));
        Assert.Equal(copy.Combine(YaraXNative.LibraryFileName), module, ignoreCase: true);
    }
    #endregion

    #region Methods: helpers
    private ProbeRun Probe(string exe, params string[] args)
    {
        Assert.True(File.Exists(exe), $"the YARA-X probe was not found at '{exe}'; it is a net10.0-windows ProjectReference of this test project.");
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            Assert.Fail("the YARA-X probe did not exit within 120 s");
        }
        process.WaitForExit();
        var run = new ProbeRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        output.WriteLine(run.Report);
        Assert.True(run.Exit == 0, $"the probe exited {run.Exit} (0 = ran to the end; anything else is a crash).\n{run.Report}");
        return run;
    }
    #endregion

    #region Nested types
    private sealed record ProbeRun(int Exit, string Stdout, string Stderr)
    {
        public string? this[string key] => All(key).FirstOrDefault();

        public string[] All(string key) =>
            Stdout.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.StartsWith(key + "=", StringComparison.Ordinal)).Select(l => l[(key.Length + 1)..]).ToArray();

        public string Report => $"exit={Exit}\nstdout:\n{Stdout}\nstderr:\n{Stderr}";
    }
    #endregion

    #region Fields
    private const string ProbeExeName = "Silvergun.PackageAnalysis.NuGet.Tests.YaraXProbe.exe";

    private static readonly string ProbeExe = Path.Combine(AppContext.BaseDirectory, ProbeExeName);
    #endregion
}
#endif
