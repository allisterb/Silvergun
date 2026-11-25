#if !WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.IO;
using System.Runtime.CompilerServices;

/// <summary>
/// The Linux twin of <c>TestHostProfile</c>: keeps the YARA-X workers this test host starts away from the real user's
/// rules cache (docs/agent/tasks/yarax-worker-linux.md, Phase 2).
///
/// <para><b>Why.</b> Since Phase 2 a Linux worker reads and writes <c>$XDG_CACHE_HOME/silvergun/yara-x-rules</c>, or
/// <c>~/.cache/silvergun/yara-x-rules</c> (<c>YaraXLinuxRulesCache.DefaultDirectory</c>), and a worker inherits this
/// process's environment. Left alone, every real-worker test (<c>YaraWorkerVerbLinuxTests</c>,
/// <c>YaraXWorkerScannerLinuxTests</c>, …) reads the developer's real cache and writes an entry there whenever it has
/// none for the current rules.</para>
///
/// <para><b>What.</b> On Linux, before any test runs, <c>XDG_CACHE_HOME</c> for this process (and so for every child that
/// does not set its own) is a private <c>silvergun-yara-x-testhost-xdg-*</c> directory directly under the sticky
/// <c>/tmp</c>, mode 700 (so the cache's walk accepts it), removed at exit. Nothing else in this host reads
/// <c>XDG_CACHE_HOME</c>: .NET's known folders and NuGet's caches use <c>HOME</c> and <c>XDG_DATA_HOME</c>. Tests that
/// need a cache of their own (a first run that compiles) give the child their own <c>XDG_CACHE_HOME</c>.</para>
/// </summary>
internal static class TestHostXdgCache
{
    #region Properties
    /// <summary>The private <c>XDG_CACHE_HOME</c> every worker this host starts inherits, or <c>null</c> off Linux.</summary>
    internal static string? Root { get; private set; }
    #endregion

    #region Methods
#pragma warning disable CA2255 // a test assembly's process-wide setup, before xunit runs anything: the intended use
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Isolate()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var root = $"/tmp/silvergun-yara-x-testhost-xdg-{Guid.NewGuid():N}";
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Environment.SetEnvironmentVariable("XDG_CACHE_HOME", root);
        Root = root;
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { Directory.Delete(root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        };
    }
    #endregion
}
#endif
