namespace Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe;

using System;

/// <summary>
/// The <c>obfuscation-scan &lt;assembly&gt;</c> verb (hidden-payloads-1, review round 1 C1/C2): one
/// <see cref="ObfuscationAnalysis"/> run over a hostile assembly, in a child. Mutually recursive value types in RVA field
/// data and an AssemblyRef resource loop entered from outside the scanned row (A to B to C to B) once meant an uncatchable stack overflow, so this never runs in a test
/// host.
/// <para>
/// Output, one record per line: <c>FINDING\tKind\tDetectedAs\tSource\tCallerType\tCallerMethod\tEncodedLength</c>, then
/// <c>TRUNCATED &lt;bool&gt;</c>, then <c>DONE</c>. Exit 0 once <c>DONE</c> is printed, 1 on a catchable failure; a crash
/// never gets that far.
/// </para>
/// </summary>
public static class ObfuscationProbe
{
    #region Methods
    public static int Run(string assemblyPath)
    {
        try
        {
            Runtime.Initialize("Silvergun", "PROBE");
            var loaded = AssemblyAnalyzer.Load(assemblyPath);
            if (!loaded.IsSuccess)
            {
                Console.Error.WriteLine($"LOAD-FAILED {loaded.Message}");
                return 1;
            }

            using var analyzer = loaded.Value;
            var result = new ObfuscationAnalysis(analyzer).Analyze();
            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"ANALYSIS-FAILED {result.Message}");
                return 1;
            }

            foreach (var f in result.Value.Findings)
                Console.WriteLine($"FINDING\t{f.Kind}\t{f.DetectedAs}\t{f.Source}\t{f.CallerType}\t{f.CallerMethod}\t{f.EncodedLength}");
            Console.WriteLine($"TRUNCATED {result.Value.Truncated}");
            Console.WriteLine("DONE");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"UNHANDLED {ex}");
            return 1;
        }
    }
    #endregion

    #region Fields
    public const string Verb = "obfuscation-scan";
    #endregion
}
