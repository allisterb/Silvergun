using System.Diagnostics;

/// <summary>
/// The startup hook the runtime calls before <c>Main</c> when this assembly is named in <c>DOTNET_STARTUP_HOOKS</c>. It
/// must be a type called <c>StartupHook</c> in the global namespace with a static <c>Initialize</c>. It registers one
/// <see cref="AppDomain.ProcessExit"/> handler that writes, one per line, <c>A|&lt;simple name&gt;|&lt;location&gt;</c> for
/// every loaded managed assembly and <c>M|&lt;module file name&gt;|&lt;path&gt;</c> for every native module, to the file named
/// by <c>SILVERGUN_TEST_LOADED_MODULES_OUT</c>. Two more opt-in records, each off unless its variable is set:
/// <c>SILVERGUN_TEST_PID_OUT</c> (this process's PID and name, at start) and <c>SILVERGUN_TEST_CONSOLE_OUT_AT_EXIT</c> (text
/// written through <see cref="Console.Out"/> at exit, for the worker's W2 stdout check). Nothing else: it touches no
/// Silvergun type, so it loads nothing the observed process would not have loaded itself (apart from this assembly and the
/// BCL types used here).
/// </summary>
internal static class StartupHook
{
    public static void Initialize()
    {
        // SILVERGUN_TEST_PID_OUT: append `<pid>|<process name>` at start, so a test can check by PID that a child this
        // process starts (and that inherits the hook through the environment) is gone afterwards.
        var pids = Environment.GetEnvironmentVariable("SILVERGUN_TEST_PID_OUT");
        if (!string.IsNullOrEmpty(pids))
            using (var self = Process.GetCurrentProcess())
                AppendShared(pids, $"{Environment.ProcessId}|{self.ProcessName}\n");

        // SILVERGUN_TEST_CONSOLE_OUT_AT_EXIT: write this text through Console.Out when the process exits, i.e. after the
        // program's own code has finished. In `__worker yara` mode Console.Out must be TextWriter.Null by then (W2), so the
        // text must never reach stdout.
        var leak = Environment.GetEnvironmentVariable("SILVERGUN_TEST_CONSOLE_OUT_AT_EXIT");
        if (!string.IsNullOrEmpty(leak))
            AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            {
                Console.Out.Write(leak);
                Console.Out.Flush();
            };

        // A `{pid}` in the path is replaced by this process's id, so a parent and the children that inherit the variable
        // (e.g. a scan-package and its `__worker yara`) each write their own record.
        var output = Environment.GetEnvironmentVariable("SILVERGUN_TEST_LOADED_MODULES_OUT");
        if (string.IsNullOrEmpty(output))
            return;

        output = output.Replace("{pid}", Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Write(output);
    }

    // Appends under a retry: two processes may start at once.
    private static void AppendShared(string path, string text)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None);
                var bytes = System.Text.Encoding.UTF8.GetBytes(text);
                stream.Write(bytes, 0, bytes.Length);
                return;
            }
            catch (IOException) when (attempt < 50)
            {
                Thread.Sleep(20);
            }
        }
    }

    private static void Write(string output)
    {
        var lines = new List<string>();
        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            lines.Add($"A|{assembly.GetName().Name}|{(assembly.IsDynamic ? "<dynamic>" : assembly.Location)}");

        using (var self = Process.GetCurrentProcess())
            foreach (ProcessModule module in self.Modules)
                lines.Add($"M|{module.ModuleName}|{module.FileName}");

        File.WriteAllLines(output, lines);
    }
}
