namespace Silvergun.PackageAnalysis.NuGet.Tests.YaraXProbe;

using System.Diagnostics;
using System.Reflection;

using Silvergun.PackageAnalysis.NuGet.Yara.Worker;

/// <summary>
/// A fresh process for the YARA-X binding's load-once behaviour (ADR 0033 T2: "load <c>yara_x_capi.dll</c> from the app
/// directory only … no default search path"). <c>YaraXNative.TryLoad</c>'s first call decides for the whole process, so
/// each mode below makes that first call itself and prints <c>key=value</c> lines for the test to assert on. Exit 0 means
/// the probe ran to the end (whatever it found); anything else is a crash, which is exactly what "nothing crashes" rules
/// out. The binding is internal, so it is reached by reflection; a missing member fails loudly (exit 2).
///
/// <list type="bullet">
/// <item><c>missing &lt;dirWithTheDll&gt;</c> — run from a copy of the test output WITHOUT the DLL: the production entry
/// <c>YaraXEngine.Load(cache)</c> first, then <c>TryLoad</c> again, then <c>TryLoad</c> from a directory that does hold
/// the DLL (still refused: the first call decided), then a compile (refused by <c>EnsureLoaded</c>).</item>
/// <item><c>relative</c> — the first <c>TryLoad</c> names a relative directory.</item>
/// <item><c>resolver &lt;dirWithACopyOfTheDll&gt;</c> — run from the test output (which ALSO holds the DLL): the first
/// <c>TryLoad</c> names the other copy, then a compile and a canary scan run, and every loaded <c>yara_x_capi.dll</c> module
/// is listed. If the import resolver ever let the runtime fall back to its default search order, the application
/// directory's copy would be loaded as a second module.</item>
/// <item><c>parent</c>, <c>failfast</c>, <c>production</c>, <c>factory</c>, <c>factory-scan</c>, <c>resolve</c> — a fresh
/// process hosting the PARENT backend, <c>YaraXWorkerScanner</c> (task T4), for what the xunit host cannot observe or must
/// not do: its Debug-level relay of the worker's stderr, a parent that dies by <c>Environment.FailFast</c> with a worker
/// running, the production constructor with a private rules cache, the process-wide factory's one-time choice (and a
/// package scan through it, T6b), and resolution under a chosen <c>PATH</c>. See <see cref="ParentHost"/>.</item>
/// </list>
/// </summary>
internal static class Program
{
    #region Methods
    private static int Main(string[] args)
    {
        try
        {
            return args switch
            {
                ["missing", var other] => Missing(other),
                ["relative"] => Relative(),
                ["resolver", var copy] => Resolver(copy),
                ["parent", var worker, var script, var root, var timeout, var readyMs, var graceMs, var exitMs] =>
                    ParentHost.Parent(worker, script, root, int.Parse(timeout), Ms(readyMs), Ms(graceMs), Ms(exitMs)),
                ["failfast", var worker, var script, var root, var pidFile] => ParentHost.FailFast(worker, script, root, pidFile),
                ["production", var root] => ParentHost.Production(root),
                ["factory"] => ParentHost.Factory(),
                ["factory-scan", var nupkg] => ParentHost.FactoryScan(nupkg),
                ["resolve", var processPath, var baseDirectory] => ParentHost.Resolve(processPath, baseDirectory),
                _ => Usage(),
            };
        }
        catch (MissingMemberException ex)
        {
            Console.WriteLine($"reflection-failed={ex.Message}");
            return 2;
        }
    }

    private static int Missing(string dirWithDll)
    {
        Console.WriteLine($"basedir={AppContext.BaseDirectory}");
        Console.WriteLine($"dllpresent={File.Exists(Path.Combine(AppContext.BaseDirectory, "yara_x_capi.dll"))}");

        var load = Call(YaraXType("YaraXEngine"), "Load", [YaraXType("YaraXRulesCache")], [null])!;
        Console.WriteLine($"load.rules={(Property(load, "Rules") is null ? "null" : "set")}");
        Console.WriteLine($"load.failure={Line(Property(load, "Failure"))}");

        var (ok, failure) = TryLoad(null);
        Console.WriteLine($"tryload={ok}");
        Console.WriteLine($"tryload.failure={Line(failure)}");

        var (okOther, _) = TryLoad(dirWithDll);
        Console.WriteLine($"tryload.other={okOther}");

        Console.WriteLine($"compile={Outcome(() => Compile(out _))}");
        Console.WriteLine($"modules={YaraXModules().Length}");
        return 0;
    }

    private static int Relative()
    {
        var (ok, failure) = TryLoad("relative" + Path.DirectorySeparatorChar + "dir");
        Console.WriteLine($"tryload={ok}");
        Console.WriteLine($"tryload.failure={Line(failure)}");
        Console.WriteLine($"modules={YaraXModules().Length}");
        return 0;
    }

    private static int Resolver(string copy)
    {
        var (ok, failure) = TryLoad(copy);
        Console.WriteLine($"tryload={ok}");
        Console.WriteLine($"tryload.failure={Line(failure)}");
        if (!ok)
            return 0;

        var rules = Compile(out var compileFailure);
        Console.WriteLine($"compile={(rules is null ? "null: " + Line(compileFailure) : "ok")}");
        if (rules is not null)
        {
            var scanner = rules.GetType().GetMethod("CreateScanner", BindingFlags.Instance | BindingFlags.NonPublic, [typeof(int)])
                ?? throw new MissingMethodException("YaraXRules.CreateScanner(int)");
            using var created = (IDisposable)scanner.Invoke(rules, [5])!;
            var check = created.GetType().GetMethod("CheckCanary", BindingFlags.Instance | BindingFlags.NonPublic, Type.EmptyTypes)
                ?? throw new MissingMethodException("YaraXScanner.CheckCanary()");
            Console.WriteLine($"canary={Line((string?)check.Invoke(created, []) ?? "passed")}");
            ((IDisposable)rules).Dispose();
        }

        foreach (var module in YaraXModules())
            Console.WriteLine($"module={module}");
        return 0;
    }

    private static int Usage()
    {
        Console.Error.WriteLine("usage: missing <dirWithDll> | relative | resolver <dirWithACopyOfTheDll> | parent ... | failfast ... | production <root> | factory | factory-scan <nupkg> | resolve <processPath> <baseDirectory>");
        return 64;
    }

    private static TimeSpan Ms(string milliseconds) => TimeSpan.FromMilliseconds(int.Parse(milliseconds));

    // YaraXNative.TryLoad(out string?) when directory is null, else TryLoad(string, out string?).
    private static (bool Ok, string? Failure) TryLoad(string? directory)
    {
        var native = YaraXType("YaraXNative");
        var byRef = typeof(string).MakeByRefType();
        object?[] args = directory is null ? [null] : [directory, null];
        var ok = (bool)Call(native, "TryLoad", directory is null ? [byRef] : [typeof(string), byRef], args)!;
        return (ok, (string?)args[^1]);
    }

    // YaraXRules.Compile over one tiny rule (a plain text string), the binding's own compile path.
    private static object? Compile(out string? failure)
    {
        IReadOnlyList<(string Name, string Text)> sources = [("probe.yar", "rule probe_rule { strings: $a = \"silvergun yarax probe\" condition: $a }")];
        object?[] args = [sources, null];
        var rules = Call(YaraXType("YaraXRules"), "Compile", [typeof(IReadOnlyList<(string, string)>), typeof(string).MakeByRefType()], args);
        failure = (string?)args[1];
        return rules;
    }

    private static string Outcome(Action action)
    {
        try
        {
            action();
            return "returned";
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            return "threw:" + ex.InnerException.GetType().Name;
        }
    }

    private static string[] YaraXModules()
    {
        using var self = Process.GetCurrentProcess();
        return self.Modules.Cast<ProcessModule>()
            .Where(m => string.Equals(m.ModuleName, "yara_x_capi.dll", StringComparison.OrdinalIgnoreCase))
            .Select(m => m.FileName)
            .ToArray();
    }

    private static Type YaraXType(string name) =>
        Product.GetType("Silvergun.PackageAnalysis.NuGet.Yara.YaraX." + name)
        ?? throw new MissingMemberException($"type YaraX.{name}");

    private static object? Call(Type type, string name, Type[] signature, object?[] args) =>
        (type.GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public, signature)
            ?? throw new MissingMethodException($"{type.Name}.{name}"))
        .Invoke(null, args);

    private static object? Property(object target, string name) =>
        (target.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMemberException($"{target.GetType().Name}.{name}"))
        .GetValue(target);

    // One printable line: the binding's messages are already escaped, but a key=value protocol must never be split.
    private static string Line(object? value) => (value?.ToString() ?? "<null>").Replace('\r', ' ').Replace('\n', ' ');
    #endregion

    #region Fields
    private static readonly Assembly Product = typeof(WorkerProtocol).Assembly;
    #endregion
}
