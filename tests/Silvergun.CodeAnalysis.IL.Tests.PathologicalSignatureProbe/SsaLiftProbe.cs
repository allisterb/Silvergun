namespace Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using System;
using System.Globalization;
using System.Linq;
using System.Text;

using Silvergun.CodeAnalysis.IL.Ssa;

/// <summary>
/// The <c>ssa-lift &lt;max-depth&gt; &lt;max-instructions&gt; &lt;assembly&gt;...</c> verb: one <see cref="SsaSession"/> over
/// the given assemblies, with those <see cref="SsaBounds"/> (0 keeps a default). Hostile inputs to the SSA adapter
/// (docs/agent/tasks/ssa-adapter.md S2) run here, in a child, so a stack overflow or a FailFast costs one test, not the
/// test host (ADR 0021).
/// <para>Output, one record per line, every name and reason escaped to printable ASCII (spaces too, so a field never
/// splits):</para>
/// <list type="bullet">
/// <item><description><c>ASSEMBLY &lt;loaded&gt; &lt;name-or-error&gt;</c>, per assembly, in the session's order;</description></item>
/// <item><description><c>OUTCOME &lt;Namespace.Type::Method&gt; &lt;Lifted|kind&gt; &lt;reason&gt;</c>, per method, in lift
/// order (<c>Type</c> is the nesting chain joined by <c>/</c>; the reason is <c>-</c> when lifted);</description></item>
/// <item><description><c>DONE</c>, last.</description></item>
/// </list>
/// Exit 0 when <c>DONE</c> is printed, 1 on a managed exception out of the session (which the adapter promises never
/// happens), 2 on bad usage.
/// </summary>
public static class SsaLiftProbe
{
    #region Methods
    public static int Run(string[] args)
    {
        if (args.Length < 4 || !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var depth)
            || !int.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var instructions))
        {
            Console.Error.WriteLine("USAGE: ssa-lift <max-depth> <max-instructions> <assembly>...");
            return 2;
        }
        try
        {
            var bounds = SsaBounds.Default with
            {
                MaxDepth = depth > 0 ? depth : SsaBounds.Default.MaxDepth,
                MaxInstructions = instructions > 0 ? instructions : SsaBounds.Default.MaxInstructions,
            };
            using var session = SsaSession.Open(args.Skip(3), bounds);
            foreach (var assembly in session.Assemblies)
                Console.WriteLine($"ASSEMBLY {assembly.IsLoaded} {Escape(assembly.Name ?? assembly.Error ?? "?")}");
            foreach (var outcome in session.Lift())
            {
                var type = outcome.Method.DeclaringType;
                var method = (type.Namespace.Length > 0 ? type.Namespace + "." : "") + string.Join("/", type.NestingChain) + "::" + outcome.Method.MethodName;
                Console.WriteLine(outcome.Failure is { } failure
                    ? $"OUTCOME {Escape(method)} {failure.Kind} {Escape(failure.Reason)}"
                    : $"OUTCOME {Escape(method)} Lifted -");
            }
            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"UNHANDLED {Escape(ex.ToString())}");
            return 1;
        }
    }

    /// <summary>Printable ASCII only: anything else, and the space and backslash, as <c>\uXXXX</c>.</summary>
    public static string Escape(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if (c is > ' ' and < (char)0x7F and not '\\')
                builder.Append(c);
            else
                builder.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
        }
        return builder.ToString();
    }
    #endregion

    #region Fields
    public const string Verb = "ssa-lift";
    #endregion
}
