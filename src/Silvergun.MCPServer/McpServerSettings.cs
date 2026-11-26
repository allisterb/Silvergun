namespace Silvergun.MCPServer;

using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// The server's boundaries (ADR 0039 decision 8, task D1), fixed at start-up: no tool can change them. Build with
/// <see cref="Create"/>, which validates and normalises.
/// </summary>
public sealed record McpServerSettings
{
    #region Constructors
    private McpServerSettings(IReadOnlyList<string> roots, bool network, int maxJobs, string cacheDir, int cacheMaxGb, string? logDir, bool debug) =>
        (Roots, Network, MaxJobs, CacheDir, CacheMaxGb, LogDir, Debug) = (roots, network, maxJobs, cacheDir, cacheMaxGb, logDir, debug);
    #endregion

    #region Properties
    /// <summary>Full, distinct paths of the directories inputs must lie under.</summary>
    public IReadOnlyList<string> Roots { get; }

    /// <summary>Whether network intel (S5) is enabled.</summary>
    public bool Network { get; }

    /// <summary>Jobs that may run at once, 1 to <see cref="MaxJobsCap"/>.</summary>
    public int MaxJobs { get; }

    /// <summary>Full path of the job cache.</summary>
    public string CacheDir { get; }

    /// <summary>Cache size cap in GiB.</summary>
    public int CacheMaxGb { get; }

    /// <summary>Full path of the log directory, or <c>null</c> for the CLI's usual one.</summary>
    public string? LogDir { get; }

    public bool Debug { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Validated settings. <paramref name="roots"/> empty means the working directory; each root must be an existing
    /// directory. <paramref name="cacheDir"/> <c>null</c> means <see cref="DefaultCacheDir"/>. Failure messages quote the
    /// operator's own arguments, escaped.
    /// </summary>
    public static Result<McpServerSettings> Create(IReadOnlyList<string> roots, bool network, int maxJobs, string? cacheDir, int cacheMaxGb, string? logDir, bool debug)
    {
        try
        {
            var full = (roots.Count == 0 ? [Directory.GetCurrentDirectory()] : roots)
                .Select(r => Path.TrimEndingDirectorySeparator(Path.GetFullPath(r)))
                .Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
                .ToArray();
            var cache = cacheDir ?? DefaultCacheDir();
            return full.FirstOrDefault(r => !Directory.Exists(r)) is { } missing ? Fail($"--root '{UntrustedText.Escape(missing)}' is not an existing directory")
                : maxJobs is < 1 or > MaxJobsCap ? Fail($"--max-jobs must be 1 to {MaxJobsCap}")
                : cacheMaxGb is < 1 or > MaxCacheGb ? Fail($"--cache-max-gb must be 1 to {MaxCacheGb}")
                // With no home directory the default would resolve under the working directory, the default input root.
                : cacheDir is null && !Path.IsPathRooted(cache) ? Fail("there is no user cache directory to default to; pass --cache-dir")
                : Result.Success(new McpServerSettings(full, network, maxJobs, Path.GetFullPath(cache), cacheMaxGb,
                    logDir is null ? null : Path.GetFullPath(logDir), debug));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or IOException or UnauthorizedAccessException)
        {
            return Fail($"a path argument is not usable ({ex.GetType().Name})");
        }
    }

    /// <summary>
    /// <c>%LOCALAPPDATA%\Silvergun\mcp</c> on Windows; elsewhere <c>$XDG_CACHE_HOME/silvergun/mcp</c>, falling back to
    /// <c>~/.cache/silvergun/mcp</c> when it is unset or relative (the XDG spec says to ignore a relative value).
    /// </summary>
    public static string DefaultCacheDir() =>
        OperatingSystem.IsWindows() ? Path.Combine(Runtime.SilvergunDir, "mcp")
        : Path.Combine(Environment.GetEnvironmentVariable("XDG_CACHE_HOME") is { Length: > 0 } xdg && Path.IsPathRooted(xdg) ? xdg : Path.Combine(Runtime.UserHomeDir, ".cache"),
            "silvergun", "mcp");

    /// <summary>
    /// <c>null</c> when <paramref name="dir"/> exists, or can be created, and a file can be created in it; otherwise why
    /// not. The file log is the record (task D9) and Serilog fails silently, so the server checks before it starts.
    /// </summary>
    public static string? LogDirectoryProblem(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            // CreateNew (O_EXCL) on a random name: never follows a planted symlink, never collides with a stale probe.
            var probe = Path.Combine(dir, $".silvergun-mcp-probe-{Guid.NewGuid():N}");
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
            return null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException or UnauthorizedAccessException)
        {
            return $"the log directory '{UntrustedText.Escape(dir)}' is not writable ({ex.GetType().Name})";
        }
    }

    private static Result<McpServerSettings> Fail(string message) => Result.Failure<McpServerSettings>(message);
    #endregion

    #region Fields
    public const int DefaultMaxJobs = 1;
    public const int MaxJobsCap = 4;
    public const int DefaultCacheMaxGb = 5;
    private const int MaxCacheGb = 1024;
    #endregion
}
