namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.Globalization;

/// <summary>
/// The worker's half of containment on Linux, where there is no kill-on-close Job Object (docs/agent/tasks/yarax-worker-linux.md,
/// L4). A background thread reads the parent pid once a second; when it changes (the parent died and the worker was
/// reparented), the process exits at once with <see cref="WorkerProtocol.ExitFatal"/>. Not <c>PR_SET_PDEATHSIG</c>: that
/// fires when the THREAD that forked the worker exits, and .NET forks from whichever thread calls <c>Process.Start</c>.
/// A parent that died before <see cref="Start"/> read its pid is not detected; the worker then ends when its stdout
/// breaks or its requests run out.
/// </summary>
public static class WorkerParentWatch
{
    #region Methods
    /// <summary>Starts the watch on Linux (once per process); does nothing elsewhere, or when the parent pid is unreadable.</summary>
    public static void Start() => Start(TimeSpan.FromSeconds(1), () => Environment.Exit(WorkerProtocol.ExitFatal));

    /// <summary>The watch with its period and orphan action as test seams. <c>false</c> when it was not started.</summary>
    internal static bool Start(TimeSpan period, Action orphaned)
    {
        if (!OperatingSystem.IsLinux() || Interlocked.Exchange(ref started, 1) == 1)
            return false;
        if (ParentPid() is not { } parent)
        {
            Runtime.Warn("yara worker: could not read the parent pid from /proc/self/stat, so this worker will not exit on its own if its parent dies.");
            return false;
        }

        new Thread(() =>
        {
            while (true)
            {
                Thread.Sleep(period);
                if (ParentPid() != parent)
                {
                    Runtime.Warn("yara worker: the parent process (pid {0}) is gone; exiting.", parent);
                    orphaned();
                    return;
                }
            }
        })
        { IsBackground = true, Name = "yara-worker-parent-watch" }.Start();
        return true;
    }

    /// <summary>
    /// This process's parent pid from <c>/proc/self/stat</c> (field 4, after the parenthesised command name, which may
    /// itself contain spaces and parentheses), or <c>null</c> when it cannot be read.
    /// </summary>
    internal static int? ParentPid()
    {
        try
        {
            return ParseParentPid(File.ReadAllText("/proc/self/stat"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Field 4 of a <c>/proc/[pid]/stat</c> line, or <c>null</c> when it is not one.</summary>
    internal static int? ParseParentPid(string stat)
    {
        var close = stat.LastIndexOf(')');
        var fields = close < 0 ? [] : stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length > 1 && int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? pid : null;
    }
    #endregion

    #region Fields
    private static int started;
    #endregion
}
