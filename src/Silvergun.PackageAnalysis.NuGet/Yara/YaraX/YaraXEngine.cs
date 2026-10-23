#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.YaraX;

/// <summary>
/// The outcome of <see cref="YaraXEngine.Load(YaraXRulesCache?)"/>: rules whose canary passed, or why there are none.
/// <see cref="Failure"/> is escaped and bounded, and is set exactly when <see cref="Rules"/> is <c>null</c>.
/// </summary>
internal sealed record YaraXLoadResult(YaraXRules? Rules, bool FromCache, string? Failure);

/// <summary>
/// Brings the YARA-X engine up for the <c>__worker yara</c> verb (ADR 0033), and for nothing else: this is the one entry
/// point into the binding, and nothing calls it outside the worker. It loads <c>yara_x_capi.dll</c> from the application
/// directory, then the rules — from the cache when an entry verifies, otherwise compiled from the embedded sources and
/// cached — and passes them only after their canary rule hits its marker.
/// </summary>
internal static class YaraXEngine
{
    #region Methods
    /// <summary>
    /// <see cref="Load(IReadOnlyList{ValueTuple{string, string}}, YaraXRulesCache?)"/> over the embedded rule sources
    /// (<see cref="YaraRuleResources.ReadAll"/>). Never throws.
    /// </summary>
    internal static YaraXLoadResult Load(YaraXRulesCache? cache)
    {
        try
        {
            return Load(YaraRuleResources.ReadAll().ToArray(), cache);
        }
        catch (Exception ex)
        {
            return Failed($"could not read the embedded YARA rules: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Loads the engine, then rules for <paramref name="sources"/> whose canary passed: a verified
    /// <paramref name="cache"/> entry when there is one (an entry whose canary fails is recompiled over), otherwise a fresh
    /// compile, which is then written to the cache. No cache when <paramref name="cache"/> is <c>null</c>. Never throws:
    /// a missing DLL is the failure "engine unavailable: …".
    /// </summary>
    internal static YaraXLoadResult Load(IReadOnlyList<(string Name, string Text)> sources, YaraXRulesCache? cache)
    {
        try
        {
            if (!YaraXNative.TryLoad(out var unavailable))
                return Failed(unavailable ?? "engine unavailable");

            if (cache?.TryLoad(YaraXRules.SourcesSha256Of(sources)) is { } cached)
            {
                if (Canary(cached) is not { } cachedFailure)
                    return new(cached, FromCache: true, Failure: null);

                Runtime.Warn("YARA-X rules cache: the cached rules failed their canary ({0}); recompiling.", cachedFailure);
                cached.Dispose();
            }

            var compiled = YaraXRules.Compile(sources, out var compileFailure);
            if (compiled is null)
                return Failed($"the YARA rules did not compile: {compileFailure}");

            if (Canary(compiled) is { } canaryFailure)
            {
                compiled.Dispose();
                return Failed($"the compiled YARA rules failed their canary: {canaryFailure}");
            }

            cache?.Store(compiled);
            return new(compiled, FromCache: false, Failure: null);
        }
        catch (Exception ex)
        {
            return Failed($"the YARA-X engine failed to start: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // Null when the canary passes on a scanner of its own over `rules`; otherwise why not. Never throws, so the caller
    // always gets to dispose rules that failed.
    private static string? Canary(YaraXRules rules)
    {
        try
        {
            using var scanner = rules.CreateScanner(CanaryTimeoutSeconds);
            return scanner.CheckCanary();
        }
        catch (Exception ex)
        {
            return YaraXText.Bounded($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static YaraXLoadResult Failed(string reason) => new(null, FromCache: false, YaraXText.Bounded(reason));
    #endregion

    #region Fields
    /// <summary>The canary scans 32 bytes; anything near this bound means the rules are not usable.</summary>
    internal const int CanaryTimeoutSeconds = 5;
    #endregion
}
#endif
