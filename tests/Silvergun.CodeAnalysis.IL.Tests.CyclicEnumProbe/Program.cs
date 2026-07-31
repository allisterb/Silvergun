namespace Silvergun.CodeAnalysis.IL.Tests.CyclicEnumProbe;

using System;
using System.Linq;

using Microsoft.Cci;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Out-of-process probe that drives the shipping scan path over an assembly given on the command line. It
/// exists for the self-referential enum (<c>docs/agent/tasks/self-referential-enum-stack-overflow.md</c>): an
/// enum whose <c>value__</c> is typed as the enum itself is a <b>cycle in the type graph</b>, and any walk
/// that chases <c>UnderlyingType</c> would recurse until the stack overflows. A stack overflow — like the
/// <c>FailFast</c> of ADR-0021 — cannot be caught: run in-process it kills the xUnit host and every other
/// result in the run, so it must be observed as a child process's exit code instead.
/// <para>Output contract (stdout, one record per line, so a parent test can assert on exact text):</para>
/// <list type="bullet">
/// <item><description><c>LOADED &lt;assemblyName&gt; &lt;typeCount&gt;</c> — once, after
/// <see cref="AssemblyAnalyzer.Load"/> succeeds and the type list has been materialized.</description></item>
/// <item><description><c>ENUM &lt;type&gt; -&gt; &lt;underlyingType&gt;</c> — once per enum, the underlying
/// type rendered through <see cref="AssemblyAnalyzer.TypeName"/>. Reaching this line at all is the assertion:
/// it is the call the cycle would make non-terminating.</description></item>
/// <item><description><c>METHOD &lt;nodeId&gt;</c> — once per analyzable method, through
/// <c>CciNames.Of</c>, so the signature decode of the pathological enums is exercised too.</description></item>
/// <item><description><c>CAPABILITY-ANALYSIS-OK &lt;findings&gt; &lt;analyzed&gt; &lt;skipped&gt;</c> — once,
/// after <see cref="CapabilityAnalysis.Analyze"/> succeeds.</description></item>
/// <item><description><c>DONE</c> — the last line on a clean run; its absence (even with exit 0) means the
/// process was cut short.</description></item>
/// </list>
/// <para>Exit codes — <b>never 35</b> on purpose, so a parent test can tell "fine" apart from an abnormal
/// termination by exit code alone:</para>
/// <list type="bullet">
/// <item><description><c>0</c> — completed cleanly, <c>DONE</c> printed.</description></item>
/// <item><description><c>1</c> — a catchable failure: a <c>Result.Failure</c> or a managed exception.
/// Distinct from a stack overflow or a <c>FailFast</c>, neither of which reaches a <c>return</c> at all.
/// </description></item>
/// <item><description><c>2</c> — bad usage (no assembly path given).</description></item>
/// </list>
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("USAGE: <probe> <assembly-path>");
                return 2;
            }

            // The scan analyses log through the runtime; initializing with null logging keeps a skip warning
            // from being the thing that fails the probe.
            Runtime.Initialize("Silvergun", "PROBE");

            var loaded = AssemblyAnalyzer.Load(args[0]);
            if (!loaded.IsSuccess)
            {
                Console.Error.WriteLine($"LOAD-FAILED {loaded.Message}");
                return 1;
            }

            using var analyzer = loaded.Value;

            var types = analyzer.Module.GetAllTypes().ToArray();
            Console.WriteLine($"LOADED {analyzer.AssemblyName} {types.Length}");

            // THE subject: rendering an enum's underlying type when that type is the enum itself (or its
            // partner in a two-step cycle). TypeHelper.GetTypeName renders a name and does not chase
            // UnderlyingType, so this must return after one step.
            foreach (var type in types.Where(t => t.IsEnum))
                Console.WriteLine($"ENUM {AssemblyAnalyzer.TypeName(type)} -> {AssemblyAnalyzer.TypeName(type.UnderlyingType)}");

            foreach (var method in analyzer.Methods)
                Console.WriteLine($"METHOD {CanonicalName.NodeId(CciNames.Of(method))}");

            var capabilities = new CapabilityAnalysis(analyzer).Analyze();
            if (!capabilities.IsSuccess)
            {
                Console.Error.WriteLine($"CAPABILITY-ANALYSIS-FAILED {capabilities.Message}");
                return 1;
            }

            var report = capabilities.Value;
            Console.WriteLine(
                $"CAPABILITY-ANALYSIS-OK {report.Findings.Count} {report.MethodsAnalyzed} {report.MethodsSkipped}");

            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            // A managed exception here is itself informative: the failure was CATCHABLE, i.e. not the
            // uncatchable termination this probe exists to rule out.
            Console.Error.WriteLine($"UNHANDLED {ex}");
            return 1;
        }
    }
}
