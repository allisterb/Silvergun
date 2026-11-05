namespace Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using System;
using System.Diagnostics.Contracts;

using Microsoft.Cci;

/// <summary>
/// The <c>assertions</c> verb (ADR 0022 Stage 1, <c>docs/agent/tasks/cci-assertions-stage1.md</c>): what a failed CCI
/// assertion does in a <b>fresh</b> process, where nothing has opened a <see cref="CciAssertionScope"/> or touched the
/// CCI assembly before. Before Stage 1 the first failed <c>Contract.Assume</c> here was <c>Environment.FailFast</c>; a
/// regression (the module initializer gone, the handler not subscribed) makes it one again, which only a parent can see,
/// as this process's exit code. So it runs as a child, never in a test host.
/// <para>Output contract (stdout, one record per line):</para>
/// <list type="bullet">
/// <item><description><c>INSTALLED &lt;bool&gt;</c> — <see cref="CciAssertions.IsInstalled"/>, read as this process's
/// FIRST use of the CCI assembly: true only if the module initializer subscribed the handler.</description></item>
/// <item><description><c>DEBUG &lt;bool&gt;</c> — whether this probe was compiled with <c>DEBUG</c>, so the
/// <c>[Conditional("DEBUG")]</c> calls below exist at all.</description></item>
/// <item><description><c>MODE &lt;mode&gt;</c> — <see cref="CciAssertions.Mode"/> as the environment set it.</description></item>
/// <item><description><c>&lt;CHANNEL&gt; CONTINUED</c> or <c>&lt;CHANNEL&gt; THREW &lt;type&gt;</c> per channel:
/// <c>ASSUME</c>, <c>ASSERT</c> (contracts), <c>DEBUG-ASSERT</c> (<see cref="CciDebug"/>).</description></item>
/// <item><description><c>RECORDED &lt;n&gt;</c> — the rise in <see cref="CciAssertions.Total"/>, then <c>DONE</c>.</description></item>
/// </list>
/// Exit 0 when <c>DONE</c> is printed; a FailFast never gets there.
/// </summary>
public static class AssertionProbe
{
    #region Methods
    public static int Run()
    {
        // Must stay the first CCI access in this process: see the class remarks.
        Console.WriteLine($"INSTALLED {CciAssertions.IsInstalled}");
        Console.WriteLine($"DEBUG {DebugDefined}");
        Console.WriteLine($"MODE {CciAssertions.Mode}");
        var before = CciAssertions.Total;

        Channel("ASSUME", () => Contract.Assume(false, "probe-assume"));
        Channel("ASSERT", () => Contract.Assert(false, "probe-assert"));
        Channel("DEBUG-ASSERT", () => CciDebug.Assert(false, "probe-debug-assert"));

        Console.WriteLine($"RECORDED {CciAssertions.Total - before}");
        Console.WriteLine("DONE");
        return 0;
    }

    private static void Channel(string name, Action fail)
    {
        try
        {
            fail();
            Console.WriteLine($"{name} CONTINUED");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{name} THREW {ex.GetType().Name}");
        }
    }
    #endregion

    #region Fields
    public const string Verb = "assertions";

#if DEBUG
    private const bool DebugDefined = true;
#else
    private const bool DebugDefined = false;
#endif
    #endregion
}
