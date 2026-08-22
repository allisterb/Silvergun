namespace Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe;

using System.Diagnostics;
using System.Reflection;

using libyaraNET;

using Silvergun.PackageAnalysis.NuGet.Yara;

/// <summary>
/// ADR 0028 decision 9, mutation-tested OUT OF PROCESS: hand the product's startup canary a ruleset built
/// EXACTLY the way the defect built one — all embedded sources into ONE <see cref="Compiler"/>, swallow the
/// <c>CompilationException</c>, call <c>GetRules()</c> on that errored compiler anyway — and require it to
/// refuse to publish it, within its own bound.
///
/// <para><b>Why this is not an xUnit test.</b> The check is only meaningful if the poisoned ruleset is
/// actually scanned, and the canary's bound expires while the native <c>yr_rules_scan_mem</c> call is still
/// walking a corrupt <c>YR_RULES</c>. That call cannot be cancelled from managed code, so the thread is
/// abandoned and keeps running. ADR 0028 states walking a corrupt <c>YR_RULES</c> is <b>undefined
/// behaviour</b>, not merely slow: if that thread ever faults it is an uncatchable native crash (the
/// ADR 0021 hazard class) that would take the whole test host down with no failing test to point at.
/// Confining it to this short-lived child process costs one <see cref="Process"/> and makes a crash
/// attributable — the driving test sees the exit code and reports it.</para>
///
/// <para>The verdict is reported ONLY through the exit code (see the constants below); stdout carries the
/// human-readable detail and the driving test echoes it into its assertion message. The process exits the
/// instant the verdict is known, because every additional millisecond alive is exposure to the abandoned
/// thread.</para>
///
/// <para>Driven by
/// <c>tests/Silvergun.PackageAnalysis.NuGet.Tests/LibYaraScannerPoisoningTests.cs</c>
/// (<c>Canary_OnARulesetBuiltFromAnErroredCompiler_RefusesToPublishIt</c>).</para>
/// </summary>
internal static class PoisonCanaryCheck
{
    #region Methods
    /// <summary>
    /// Builds the poisoned ruleset, runs the product's own canary over it and returns the verdict as one of
    /// the exit codes below. Never throws: an unexpected fault is reported as <see cref="Unexpected"/>.
    /// </summary>
    public static int Run()
    {
        Console.WriteLine("[poison-canary] ADR 0028 decision 9 mutation check, isolated in this process.");
        try
        {
            // Reflected because the canary and its bound are private statics with no injection seam. Each
            // lookup is checked, so a rename fails loudly here instead of silently skipping the check.
            var canary = typeof(LibYaraScanner).GetMethod(
                "CanaryScanCompletes", BindingFlags.NonPublic | BindingFlags.Static, binder: null, [typeof(Rules), typeof(Scanner)], modifiers: null);
            if (canary is null)
                return Fail(MemberGone, "LibYaraScanner.CanaryScanCompletes(Rules, Scanner) is gone; the ADR 0028 guard it backs is no longer testable.");

            var boundField = typeof(LibYaraScanner).GetField("canaryTimeout", BindingFlags.NonPublic | BindingFlags.Static);
            if (boundField is null)
                return Fail(MemberGone, "LibYaraScanner.canaryTimeout is gone; the ADR 0028 bound it backs is no longer testable.");

            var bound = (TimeSpan)boundField.GetValue(null)!;

            // yr_initialize. Rooted for the process lifetime and deliberately never finalized: yr_finalize
            // while the abandoned scan below is still in flight would be a use-after-free.
            roots.Add(new YaraContext());

            var rules = BuildPoisonedRuleset(out var swallowed);
            Console.WriteLine($"[poison-canary] poisoned ruleset built from ONE errored compiler: {swallowed} swallowed compile error(s).");
            if (swallowed == 0)
                return Fail(NotPoisoned, "No embedded rule source failed to compile, so this ruleset is not poisoned and the check proves nothing.");

            var sw = Stopwatch.StartNew();
            var completed = (bool)canary.Invoke(null, [rules, new Scanner()])!;
            sw.Stop();
            Console.WriteLine($"[poison-canary] canary returned {completed} after {sw.ElapsedMilliseconds} ms (its own bound is {bound}).");

            if (completed)
                return Fail(CanaryAcceptedPoison, "The startup canary ACCEPTED a ruleset built from an errored compiler; ADR 0028 decision 9's guard no longer goes red.");

            // Refusing is not enough: an unbounded canary is the hang it exists to prevent.
            if (sw.Elapsed >= bound + Slack)
                return Fail(CanaryUnbounded, $"The canary took {sw.Elapsed} to give up on a poisoned ruleset, past its own {bound} bound plus {Slack} of slack.");

            Console.WriteLine("[poison-canary] PASS: the canary refused the poisoned ruleset, within its bound.");
            return Ok;
        }
        catch (Exception ex)
        {
            return Fail(Unexpected, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    // Rebuilds the ADR 0028 defect on purpose: ONE compiler, every embedded source, swallow each per-source
    // CompilationException, then ask that errored compiler for rules. Nothing is disposed — the Compiler owns
    // native state the Rules reference.
    private static Rules BuildPoisonedRuleset(out int swallowed)
    {
        var compiler = new Compiler();
        roots.Add(compiler);

        var errors = 0;
        foreach (var text in RuleSources())
        {
            try
            {
                compiler.AddRuleString(text);
            }
            catch
            {
                errors++;
            }
        }

        swallowed = errors;
        var rules = compiler.GetRules();
        roots.Add(rules);
        return rules;
    }

    // The embedded rule sources, read exactly as LibYaraScanner.BuildEngine reads them. Read here rather than
    // through YaraRuleResources because that type is internal and this probe is not named in the product's
    // InternalsVisibleTo.
    private static IEnumerable<string> RuleSources()
    {
        var assembly = typeof(LibYaraScanner).Assembly;
        foreach (var name in assembly.GetManifestResourceNames()
            .Where(n => n.Contains(RuleResourceMarker) && n.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream is null) continue;
            using var reader = new StreamReader(stream);
            yield return reader.ReadToEnd();
        }
    }

    private static int Fail(int code, string reason)
    {
        Console.Error.WriteLine($"[poison-canary] FAIL({code}): {reason}");
        return code;
    }
    #endregion

    #region Fields
    /// <summary>The argument that selects this check. Anything else is the timing probe's own command line.</summary>
    public const string Switch = "--poison-canary";

    /// <summary>The canary refused the poisoned ruleset, within its own bound. The only passing outcome.</summary>
    public const int Ok = 0;

    /// <summary>No embedded source failed to compile, so the "poisoned" ruleset is not poisoned.</summary>
    public const int NotPoisoned = 20;

    /// <summary>The canary returned <c>true</c> for a ruleset built from an errored compiler.</summary>
    public const int CanaryAcceptedPoison = 21;

    /// <summary>The canary refused, but took far longer than its own bound to do it.</summary>
    public const int CanaryUnbounded = 22;

    /// <summary>A reflected member the check depends on is gone (renamed or removed).</summary>
    public const int MemberGone = 23;

    /// <summary>Anything else the check threw.</summary>
    public const int Unexpected = 24;

    /// <summary>The native <c>libyara.NET</c> assembly could not be loaded at all (raised from <c>Program</c>).</summary>
    public const int NativeLoadFailed = 25;

    private const string RuleResourceMarker = ".Resources.YaraRules.";

    // How far past its own bound the canary may run before this counts as unbounded. Matches the driving
    // test's healthy-scan slack: the bound is enforced by a Thread.Join, so only scheduling noise separates
    // "expired on time" from "not enforced at all".
    private static readonly TimeSpan Slack = TimeSpan.FromSeconds(5);

    // Keeps the YaraContext and the deliberately poisoned native objects alive for the process lifetime.
    private static readonly List<object> roots = [];
    #endregion
}
