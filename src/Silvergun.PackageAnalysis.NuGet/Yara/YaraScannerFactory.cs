namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Selects and exposes the single, process-wide <see cref="IYaraScanner"/> so the embedded ruleset is compiled
/// exactly ONCE (ADR 0016; review note #3). On the <c>net10.0-windows</c> build (<c>#if WINDOWS</c>) this is the
/// in-process <see cref="LibYaraScanner"/> (whose engine is already static/shared); everywhere else it is a shared
/// <see cref="YaraCliScanner"/> when <c>SILVERGUN_YARA_PATH</c> is set and valid, otherwise the
/// <see cref="NullYaraScanner"/>. Selection happens once, lazily, on first use.
/// </summary>
public static class YaraScannerFactory
{
    #region Properties
    /// <summary>The shared scanner for the whole process — the ruleset it wraps is compiled once.
    /// <c>SILVERGUN_YARA_PATH</c> (and <c>SILVERGUN_YARAC_PATH</c>) are read exactly ONCE, when this property is
    /// first touched: the backend selected then is the backend for the rest of the process lifetime, and changing
    /// either variable afterwards has no effect on it. There is deliberately no reset hook — a security backend
    /// that can be re-pointed mid-process is a backend an in-process caller can swap out.</summary>
    public static IYaraScanner Shared => shared.Value;

    /// <summary>
    /// <c>true</c> when a real YARA backend was SELECTED (Windows in-process, or a valid classic-CLI path);
    /// <c>false</c> only when scanning degrades to <see cref="NullYaraScanner"/> because no engine is configured
    /// (e.g. non-Windows with <c>SILVERGUN_YARA_PATH</c> unset). <b>This does not prove the backend actually
    /// works</b> — the Windows in-process backend is always "selected" even when its native <c>libyara.NET</c>
    /// dependency fails to load. The CLI's advisory note is keyed on <see cref="PackageCapabilityReport.YaraScanStatus"/>
    /// instead (the real, per-run outcome), not on this property.
    /// </summary>
    public static bool BackendAvailable => Shared is not NullYaraScanner;
    #endregion

    #region Methods
    private static IYaraScanner Create()
    {
#if WINDOWS
        // The in-process backend's compiled ruleset is a static Lazy, so a single instance suffices.
        return new LibYaraScanner();
#else
        // Process-lifetime and never disposed (callers share it, and any of them may be mid-scan): YaraCliScanner deletes
        // its temp rules dirs at process exit instead. A no-engine instance created no dirs, so dropping it is enough.
        var cli = new YaraCliScanner();
        return cli.Available ? cli : NullYaraScanner.Instance;
#endif
    }
    #endregion

    #region Fields
    private static readonly Lazy<IYaraScanner> shared = new(Create);
    #endregion
}
