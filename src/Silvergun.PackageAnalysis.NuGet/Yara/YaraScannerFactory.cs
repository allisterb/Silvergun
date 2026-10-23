namespace Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// Selects and exposes the single, process-wide <see cref="IYaraScanner"/> so the embedded ruleset is compiled
/// exactly ONCE (ADR 0016; review note #3). On the <c>net10.0-windows</c> build (<c>#if WINDOWS</c>) this is the
/// out-of-process <c>YaraXWorkerScanner</c> (ADR 0033) by default — <c>SILVERGUN_YARA_ENGINE</c> unset, empty or
/// <c>yarax</c> — or, only when <c>SILVERGUN_YARA_ENGINE=libyara</c> asks for it, the in-process
/// <see cref="LibYaraScanner"/> (whose engine is already static/shared), an explicit fallback until its package is
/// removed. Neither ever falls back to the other. Everywhere else it is a shared <see cref="YaraCliScanner"/> when
/// <c>SILVERGUN_YARA_PATH</c> is set and valid, otherwise the <see cref="NullYaraScanner"/>. Selection happens once,
/// lazily, on first use.
/// </summary>
public static class YaraScannerFactory
{
    #region Properties
    /// <summary>The shared scanner for the whole process — the ruleset it wraps is compiled once.
    /// <c>SILVERGUN_YARA_ENGINE</c>, <c>SILVERGUN_YARA_PATH</c> (and <c>SILVERGUN_YARAC_PATH</c>) are read exactly ONCE, when this property is
    /// first touched: the backend selected then is the backend for the rest of the process lifetime, and changing
    /// either variable afterwards has no effect on it. There is deliberately no reset hook — a security backend
    /// that can be re-pointed mid-process is a backend an in-process caller can swap out.</summary>
    public static IYaraScanner Shared => shared.Value;

    /// <summary>
    /// <c>true</c> when a real YARA backend was SELECTED (a Windows backend, or a valid classic-CLI path);
    /// <c>false</c> only when scanning degrades to <see cref="NullYaraScanner"/> because no engine is configured
    /// (e.g. non-Windows with <c>SILVERGUN_YARA_PATH</c> unset). <b>This does not prove the backend actually
    /// works</b> — a Windows backend is always "selected" even when it cannot run (the YARA-X worker's executable or
    /// DLL is missing, or the in-process engine's native <c>libyara.NET</c> dependency fails to load). The CLI's advisory note is keyed on <see cref="PackageCapabilityReport.YaraScanStatus"/>
    /// instead (the real, per-run outcome), not on this property.
    /// </summary>
    public static bool BackendAvailable => Shared is not NullYaraScanner;
    #endregion

    #region Methods
    private static IYaraScanner Create()
    {
        var engine = Environment.GetEnvironmentVariable(EngineVar);
#if WINDOWS
        // The out-of-process YARA-X worker (ADR 0033) is the default since the T6 gate passed (docs/agent/tasks/yarax-worker.md);
        // SILVERGUN_YARA_ENGINE=libyara selects the in-process engine as an explicit fallback until T7 removes its package.
        // Neither ever falls back to the other: a chosen backend that is not Available reports YaraScanStatus.Unavailable,
        // which is the honest answer for the engine that was asked for (ADR 0027 decision 4). Both are process-lifetime and
        // never disposed, like the other shared backends: the worker's Job Object closes with the process, and the in-process
        // backend's compiled ruleset is a static Lazy, so a single instance suffices.
        if (string.Equals(engine, LibYaraEngineValue, StringComparison.OrdinalIgnoreCase))
            return new LibYaraScanner();

        if (!string.Equals(engine, YaraXEngineValue, StringComparison.OrdinalIgnoreCase))
            WarnIfUnrecognised(engine, $"the recognised values are '{YaraXEngineValue}' and '{LibYaraEngineValue}'");

        return new YaraXWorkerScanner();
#else
        // `yarax` and `libyara` are real values, just not for this build: say so rather than call them unrecognised.
        if (string.Equals(engine, YaraXEngineValue, StringComparison.OrdinalIgnoreCase) || string.Equals(engine, LibYaraEngineValue, StringComparison.OrdinalIgnoreCase))
            Runtime.Warn("{0}='{1}' has no effect on this build (it selects a Windows backend); using the default YARA backend.",
                EngineVar, Worker.WorkerProtocol.Safe(engine, MaxEngineValueChars));
        else
            WarnIfUnrecognised(engine, "this build has no alternative YARA backend to select");

        // Process-lifetime and never disposed (callers share it, and any of them may be mid-scan): YaraCliScanner deletes
        // its temp rules dirs at process exit instead. A no-engine instance created no dirs, so dropping it is enough.
        var cli = new YaraCliScanner();
        return cli.Available ? cli : NullYaraScanner.Instance;
#endif
    }

    // A set but unrecognised SILVERGUN_YARA_ENGINE is said out loud (escaped and bounded: it is environment text), never
    // silently ignored; the default backend is kept.
    private static void WarnIfUnrecognised(string? engine, string why)
    {
        if (!string.IsNullOrEmpty(engine))
            Runtime.Warn("{0}='{1}' is not recognised ({2}); using the default YARA backend.",
                EngineVar, Worker.WorkerProtocol.Safe(engine, MaxEngineValueChars), why);
    }
    #endregion

    #region Fields
    /// <summary>The environment variable that selects the Windows YARA backend (unset or empty: the default).</summary>
    internal const string EngineVar = "SILVERGUN_YARA_ENGINE";

    /// <summary>The <see cref="EngineVar"/> value that selects the out-of-process YARA-X worker backend (Windows; the default).</summary>
    internal const string YaraXEngineValue = "yarax";

    /// <summary>The <see cref="EngineVar"/> value that selects the in-process libyara.NET backend (Windows; an explicit fallback).</summary>
    internal const string LibYaraEngineValue = "libyara";

    private const int MaxEngineValueChars = 64;

    private static readonly Lazy<IYaraScanner> shared = new(Create);
    #endregion
}
