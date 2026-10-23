#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Reflection;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;
using Silvergun.PackageAnalysis.NuGet.Yara.YaraX;
using Silvergun.Tests.Shared;

using Xunit;

/// <summary>
/// ADR 0033, amendment of 2026-10-22 (user decision, option A): the rules cache has no user-configurable location.
/// <c>SILVERGUN_YARA_RULES_CACHE</c> once moved it (into a <c>silvergun-yara-x-rules</c> subdirectory of the named
/// directory) and was removed before it was ever committed. This guards against it coming back, at the layer a worker
/// builds its cache in: <see cref="YaraWorkerEngines.ForPlatform"/>. The other layers have one guard each: the parent's
/// constructor in <see cref="YaraXWorkerScannerProcessTests"/>, and a real worker run in
/// <see cref="YaraWorkerVerbWindowsTests"/>.
///
/// <para>Only a value is asserted: the engine is constructed and never started, so nothing reads or writes the default
/// location (in this host that is the developer's REAL <c>%LOCALAPPDATA%\Silvergun\yara-x-rules</c>; see
/// <see cref="TestHostProfile"/>). The variable is process-global and every worker this host starts inherits it, so it is
/// set only inside a non-parallel collection, and always restored.</para>
/// </summary>
[Collection(RulesCacheEnvCollection.Name)]
public sealed class YaraXRulesCacheNoOverrideTests
{
    #region Methods
    // Set to a directory only the user controls (the old code accepted exactly this, and would have put the cache in its
    // silvergun-yara-x-rules subdirectory): the worker engine's cache is the default location regardless, nothing is
    // created in the named directory, and nothing is warned about.
    [Fact]
    public void TheWorkerEngine_WithTheRemovedVariableSet_UsesTheDefaultLocation_CreatesNothing_AndWarnsNothing()
    {
        using var named = new ControlledTempDir("no-override-engine");
        using var warnings = new WarningCapture();
        string? location;
        string? plain;

        var previous = Environment.GetEnvironmentVariable(RemovedVariable);
        Environment.SetEnvironmentVariable(RemovedVariable, named.Root);
        try
        {
            var engine = Assert.IsType<YaraXWorkerEngine>(YaraWorkerEngines.ForPlatform(5));
            location = CacheOf(engine).Location;
            plain = new YaraXRulesCache().Location;
            engine.Dispose();
        }
        finally
        {
            Environment.SetEnvironmentVariable(RemovedVariable, previous);
        }

        Assert.NotNull(YaraXRulesCache.DefaultDirectory());
        Assert.Equal(YaraXRulesCache.DefaultDirectory(), location);
        Assert.Equal(YaraXRulesCache.DefaultDirectory(), plain);
        Assert.False(location!.StartsWith(named.Root, StringComparison.OrdinalIgnoreCase), $"the cache is under the named directory: {location}");
        Assert.Empty(Directory.EnumerateFileSystemEntries(named.Root));
        Assert.DoesNotContain(warnings.Warnings, w => w.Contains("rules cache", StringComparison.OrdinalIgnoreCase)
            || w.Contains(RemovedVariable, StringComparison.Ordinal));
    }
    #endregion

    #region Methods: helpers
    // The engine's cache (YaraXWorkerEngine.cache, private).
    private static YaraXRulesCache CacheOf(YaraXWorkerEngine engine)
    {
        var field = typeof(YaraXWorkerEngine).GetField("cache", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.True(field is not null, "YaraXWorkerEngine.cache is gone; this test reads the engine's cache location through it.");
        return Assert.IsType<YaraXRulesCache>(field!.GetValue(engine));
    }
    #endregion

    #region Fields
    private const string RemovedVariable = "SILVERGUN_YARA_RULES_CACHE";
    #endregion
}

/// <summary>
/// Tests that set the process-global <c>SILVERGUN_YARA_RULES_CACHE</c>. Every YARA-X worker this host starts inherits it,
/// so parallelization is disabled: xunit runs this collection after all parallel ones, alone.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class RulesCacheEnvCollection
{
    public const string Name = "yara-rules-cache-env";
}
#endif
