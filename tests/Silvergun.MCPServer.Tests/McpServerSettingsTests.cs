namespace Silvergun.MCPServer.Tests;

using System;
using System.IO;
using System.Linq;

/// <summary>D1's settings, in-process: <see cref="McpServerSettings.Create"/> validates and normalises; <see cref="McpServerSettings.DefaultCacheDir"/>.</summary>
public sealed class McpServerSettingsTests
{
    #region Methods
    [Fact]
    public void Create_WithNoRoots_UsesTheWorkingDirectory()
    {
        using var dirs = new TestDirs();

        var settings = Create([], dirs);

        Assert.True(settings.IsSuccess, settings.Message);
        Assert.Equal([Path.TrimEndingDirectorySeparator(Directory.GetCurrentDirectory())], settings.Value.Roots);
    }

    [Fact]
    public void Create_CollapsesDuplicateRoots()
    {
        using var dirs = new TestDirs();
        var spellings = OperatingSystem.IsWindows()
            ? new[] { dirs.Root, dirs.Root + Path.DirectorySeparatorChar, Path.Combine(dirs.Root, "."), dirs.Root.ToUpperInvariant() }
            : new[] { dirs.Root, dirs.Root + Path.DirectorySeparatorChar, Path.Combine(dirs.Root, ".") };

        var settings = Create(spellings, dirs);

        Assert.True(settings.IsSuccess, settings.Message);
        var root = Assert.Single(settings.Value.Roots);
        Assert.Equal(Path.GetFullPath(dirs.Root), root, ignoreCase: OperatingSystem.IsWindows());
    }

    [Fact]
    public void Create_KeepsDistinctRootsInOrder_AsFullPaths()
    {
        using var dirs = new TestDirs();
        var second = dirs.NewDir("second");

        var settings = Create([second, dirs.Root], dirs);

        Assert.True(settings.IsSuccess, settings.Message);
        Assert.Equal([second, dirs.Root], settings.Value.Roots);
    }

    [Fact]
    public void Create_WithANonexistentRoot_Fails()
    {
        using var dirs = new TestDirs();

        var settings = Create([dirs.Root, Path.Combine(dirs.Base, "no-such-root")], dirs);

        Assert.False(settings.IsSuccess);
        Assert.Contains("--root", settings.Message);
    }

    [Fact]
    public void Create_WithAFileAsRoot_Fails()
    {
        using var dirs = new TestDirs();
        var file = Path.Combine(dirs.Base, "a-file");
        File.WriteAllText(file, "x");

        var settings = Create([file], dirs);

        Assert.False(settings.IsSuccess);
        Assert.Contains("--root", settings.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(5)]
    public void Create_WithMaxJobsOutOfRange_Fails(int maxJobs)
    {
        using var dirs = new TestDirs();

        var settings = Create([dirs.Root], dirs, maxJobs: maxJobs);

        Assert.False(settings.IsSuccess);
        Assert.Contains("--max-jobs", settings.Message);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void Create_WithMaxJobsAtTheBounds_Succeeds(int maxJobs)
    {
        using var dirs = new TestDirs();

        var settings = Create([dirs.Root], dirs, maxJobs: maxJobs);

        Assert.True(settings.IsSuccess, settings.Message);
        Assert.Equal(maxJobs, settings.Value.MaxJobs);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Create_WithCacheMaxGbBelowOne_Fails(int cacheMaxGb)
    {
        using var dirs = new TestDirs();

        var settings = Create([dirs.Root], dirs, cacheMaxGb: cacheMaxGb);

        Assert.False(settings.IsSuccess);
        Assert.Contains("--cache-max-gb", settings.Message);
    }

    [Fact]
    public void Create_KeepsTheOtherOptions_AsGiven()
    {
        using var dirs = new TestDirs();

        var settings = McpServerSettings.Create([dirs.Root], network: true, maxJobs: 3, dirs.Cache, cacheMaxGb: 7, dirs.Logs, debug: true);

        Assert.True(settings.IsSuccess, settings.Message);
        var s = settings.Value;
        Assert.True(s.Network);
        Assert.Equal(3, s.MaxJobs);
        Assert.Equal(dirs.Cache, s.CacheDir);
        Assert.Equal(7, s.CacheMaxGb);
        Assert.Equal(dirs.Logs, s.LogDir);
        Assert.True(s.Debug);
    }

    [Fact]
    public void Create_WithNoCacheOrLogDir_UsesTheDefaults()
    {
        using var dirs = new TestDirs();

        var settings = McpServerSettings.Create([dirs.Root], false, McpServerSettings.DefaultMaxJobs, null, McpServerSettings.DefaultCacheMaxGb, null, false);

        Assert.True(settings.IsSuccess, settings.Message);
        Assert.Equal(Path.GetFullPath(McpServerSettings.DefaultCacheDir()), settings.Value.CacheDir);
        Assert.Null(settings.Value.LogDir);
    }

    [Fact]
    public void LogDirectoryProblem_AWritableDirectory_IsNone_AndLeavesNoProbeFile()
    {
        using var dirs = new TestDirs();

        Assert.Null(McpServerSettings.LogDirectoryProblem(dirs.Logs));
        Assert.Empty(Directory.GetFileSystemEntries(dirs.Logs));
    }

    [Fact]
    public void LogDirectoryProblem_RepeatedCalls_AllSucceed_AndLeaveNoProbeFile()
    {
        using var dirs = new TestDirs();

        var problems = Enumerable.Range(0, 20).Select(_ => McpServerSettings.LogDirectoryProblem(dirs.Logs)).ToArray();

        Assert.All(problems, Assert.Null);
        Assert.Empty(Directory.GetFileSystemEntries(dirs.Logs));
    }

    [Fact]
    public void LogDirectoryProblem_AMissingButCreatableDirectory_IsNone_AndCreatesIt()
    {
        using var dirs = new TestDirs();
        var logDir = Path.Combine(dirs.Base, "new", "logs");

        Assert.Null(McpServerSettings.LogDirectoryProblem(logDir));
        Assert.True(Directory.Exists(logDir));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LogDirectoryProblem_AFileOrAPathUnderAFile_IsAReason(bool underTheFile)
    {
        using var dirs = new TestDirs();
        var file = Path.Combine(dirs.Base, "not-a-dir");
        File.WriteAllText(file, "x");

        var problem = McpServerSettings.LogDirectoryProblem(underTheFile ? Path.Combine(file, "logs") : file);

        Assert.False(string.IsNullOrWhiteSpace(problem));
        Assert.Contains("not writable", problem);
    }

    [Fact]
    public void LogDirectoryProblem_QuotesTheDirectoryEscaped()
    {
        using var dirs = new TestDirs();
        var file = Path.Combine(dirs.Base, "not-a-dir");
        File.WriteAllText(file, "x");
        var rlo = (char)0x202E;

        var problem = McpServerSettings.LogDirectoryProblem(Path.Combine(file, "x" + rlo + "y"));

        Assert.NotNull(problem);
        Assert.DoesNotContain(rlo, problem);
    }

    [WindowsOnlyFact]
    public void DefaultCacheDir_OnWindows_IsUnderLocalAppData() =>
        Assert.Equal(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Silvergun", "mcp"),
            McpServerSettings.DefaultCacheDir());

    [NonWindowsFact]
    public void DefaultCacheDir_HonoursAnAbsoluteXdgCacheHome()
    {
        using var dirs = new TestDirs();
        WithXdgCacheHome(dirs.Cache, () =>
            Assert.Equal(Path.Combine(dirs.Cache, "silvergun", "mcp"), McpServerSettings.DefaultCacheDir()));
    }

    [NonWindowsFact]
    public void DefaultCacheDir_IgnoresARelativeXdgCacheHome() =>
        WithXdgCacheHome("relative/cache", () =>
            Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache", "silvergun", "mcp"),
                McpServerSettings.DefaultCacheDir()));

    [NonWindowsFact]
    public void DefaultCacheDir_WithNoXdgCacheHome_UsesDotCache() =>
        WithXdgCacheHome(null, () =>
            Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache", "silvergun", "mcp"),
                McpServerSettings.DefaultCacheDir()));
    #endregion

    #region Methods: helpers
    private static Result<McpServerSettings> Create(string[] roots, TestDirs dirs, int maxJobs = McpServerSettings.DefaultMaxJobs,
        int cacheMaxGb = McpServerSettings.DefaultCacheMaxGb) =>
        McpServerSettings.Create(roots, false, maxJobs, dirs.Cache, cacheMaxGb, dirs.Logs, false);

    // XDG_CACHE_HOME is read only by DefaultCacheDir, and every other test here passes an explicit cache dir; this class's
    // tests run serially, so the process-wide change is restored before any other reader could see it.
    private static void WithXdgCacheHome(string? value, Action assert)
    {
        var saved = Environment.GetEnvironmentVariable(XdgCacheHome);
        Environment.SetEnvironmentVariable(XdgCacheHome, value);
        try
        {
            assert();
        }
        finally
        {
            Environment.SetEnvironmentVariable(XdgCacheHome, saved);
        }
    }
    #endregion

    #region Fields
    private const string XdgCacheHome = "XDG_CACHE_HOME";
    #endregion
}

/// <summary>A fact that runs on Windows only; a skip elsewhere, so the output says it did not run.</summary>
public sealed class WindowsOnlyFactAttribute : FactAttribute
{
    #region Constructors
    public WindowsOnlyFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows only.";
    }
    #endregion
}

/// <summary>A fact that runs off Windows only (the XDG branch of the default cache dir); a skip on Windows.</summary>
public sealed class NonWindowsFactAttribute : FactAttribute
{
    #region Constructors
    public NonWindowsFactAttribute()
    {
        if (OperatingSystem.IsWindows())
            Skip = "Not on Windows: the XDG branch is the non-Windows one.";
    }
    #endregion
}
