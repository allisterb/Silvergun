namespace Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

/// <summary>
/// Declarations that only exist to reach the CCI signature decoder's corners — the "pathological/hostile
/// signature shapes" home ADR-0022 asks for. Every entry is a normal, Roslyn-compilable declaration that any
/// attacker-authored NuGet package could carry unmodified; none of these methods is ever called, only
/// analyzed, because the defect lives entirely in <b>metadata reading</b>, not execution.
/// <para>
/// <b>Adding a new case is cheap by design.</b> Declare it here with a doc comment naming the ADR/defect it
/// pins, and <see cref="Program"/> picks it up automatically — it walks every method definition in this
/// assembly through <c>CciNames.Of</c> rather than naming methods individually, so no wiring is needed
/// elsewhere.
/// </para>
/// </summary>
public static class PathologicalShapes
{
    /// <summary>
    /// SUBJECT — ADR-0021 / ADR-0022 Stage 0. <c>TypedReference</c> nested one level under <c>Pointer</c>
    /// reaches <c>SignatureConverter.GetTypeReference()</c>'s recursive <c>default:</c> arm, which was
    /// <c>Debug.Fail("?!?")</c> — <c>Environment.FailFast</c> on .NET (exit 35, no managed exception, no
    /// <c>catch</c>: see ADR-0021). The 2-line fix added <c>case ElementType.TypedReference</c> so it returns
    /// <c>PlatformType.SystemTypedReference</c> instead, matching the three existing top-level peeks. Compiles
    /// with warning <c>CS8500</c>, not an error — trivially reachable from plain C#, no IL emitter required.
    /// Declared, never called: only the signature is under test.
    /// </summary>
    public static unsafe void TypedReferencePointer(TypedReference* reference) { }

    /// <summary>
    /// NEGATIVE CONTROL — an ordinary managed parameter, analyzed the same way as
    /// <see cref="TypedReferencePointer"/>. Exists so a decoder-wide degradation (e.g. every parameter
    /// rendering as <c>&lt;unknown&gt;</c>) cannot be mistaken for this fixture specifically exercising the
    /// <c>TypedReference*</c> arm. Declared, never called.
    /// </summary>
    public static void Clean(string value) { }
}

/// <summary>
/// Out-of-process probe for the CCI signature decoder's pathological corners (ADR-0021/0022). This process
/// must be spawned as a <b>child</b>, never run in-process by a test host: the whole point of the shapes in
/// <see cref="PathologicalShapes"/> is that a regression makes the CCI reader call
/// <c>Environment.FailFast</c> — exit 35, no managed exception, nothing a <c>try</c>/<c>catch</c> in this or
/// any calling process can observe. Run in-process, that kill takes the entire xUnit host down with it; run
/// out-of-process, it is just an abnormal child exit the parent can assert on.
/// <para>
/// Drives the same call path a regression would break (<c>CciNames.Of</c>, which eagerly reads
/// <c>IMethodReference.Parameters</c> — see ADR-0021 Tier 1) plus the two product entry points the ADR-0022
/// sweep found were never affected (<see cref="AssemblyAnalyzer.Load"/> and
/// <see cref="CapabilityAnalysis.Analyze"/>), so a caller can pin that boundary too on the same fixture.
/// </para>
/// <para>Output contract (stdout, one record per line, so a parent test can assert on exact text):</para>
/// <list type="bullet">
/// <item><description><c>PARAM &lt;method&gt; &lt;index&gt; &lt;rendered-type&gt;</c> — once per parameter of
/// every analyzable method in this assembly, in declaration order.</description></item>
/// <item><description><c>CAPABILITY-ANALYSIS-OK &lt;findingCount&gt;</c> — once, after
/// <see cref="CapabilityAnalysis.Analyze"/> succeeds.</description></item>
/// <item><description><c>DONE</c> — the last line on a clean run; its absence (even with exit 0) means the
/// process was cut short.</description></item>
/// </list>
/// <para>Exit codes — <b>never 35</b> on purpose, so a parent test can tell "fine" apart from "FailFast" by
/// exit code alone without needing to know the OS-specific FailFast value:</para>
/// <list type="bullet">
/// <item><description><c>0</c> — completed cleanly, <c>DONE</c> was printed.</description></item>
/// <item><description><c>1</c> — a catchable failure: <see cref="AssemblyAnalyzer.Load"/> or
/// <see cref="CapabilityAnalysis.Analyze"/> returned <c>Result.Failure</c>, or an unexpected managed exception
/// was thrown. Distinct from a FailFast, which never reaches this <c>return</c> at all.</description></item>
/// </list>
/// </summary>
public static class Program
{
    public static int Main()
    {
        try
        {
            var path = typeof(Program).Assembly.Location;

            var loaded = AssemblyAnalyzer.Load(path);
            if (!loaded.IsSuccess)
            {
                Console.Error.WriteLine($"LOAD-FAILED {loaded.Message}");
                return 1;
            }

            using var analyzer = loaded.Value;

            // The product entry points ADR-0022's sweep pinned as clean on this shape family: exercised here
            // on the exact same fixture the CciNames.Of walk below uses, not a separate assembly.
            var capabilities = new CapabilityAnalysis(analyzer).Analyze();
            if (!capabilities.IsSuccess)
            {
                Console.Error.WriteLine($"CAPABILITY-ANALYSIS-FAILED {capabilities.Message}");
                return 1;
            }
            Console.WriteLine($"CAPABILITY-ANALYSIS-OK {capabilities.Value.Findings.Count}");

            // The crashing call path: CciNames.Of eagerly reads IMethodReference.Parameters for every method
            // definition in the module, PathologicalShapes included.
            foreach (var method in analyzer.Methods)
            {
                var identity = CciNames.Of(method);
                for (var i = 0; i < identity.ParameterTypes.Count; i++)
                    Console.WriteLine($"PARAM {identity.MethodName} {i} {identity.ParameterTypes[i]}");
            }

            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            // A managed exception here is itself informative: it means the failure was CATCHABLE, i.e. not
            // the FailFast this probe exists to detect. A FailFast never reaches this catch (ADR-0021).
            Console.Error.WriteLine($"UNHANDLED {ex}");
            return 1;
        }
    }
}
