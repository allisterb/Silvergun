namespace Silvergun.CodeAnalysis.IL.Tests.IndicatorCapFixture;

/// <summary>
/// A small, deliberately isolated fixture assembly for <c>IndicatorAnalysisTruncationTests</c>' injected-cap
/// coverage. Replaces the deleted <c>Silvergun.CodeAnalysis.IL.Tests.BulkIndicatorFixture</c> (10,010
/// machine-generated constants): now that <c>IndicatorAnalysis</c> accepts an injectable
/// <c>maxDistinctIndicators</c> override, the real (10,000-constant) cap no longer needs to be tripped at all
/// — a small cap over a dozen hand-written constants is enough, exactly as
/// <c>IndicatorAnalysis</c>'s constructor doc comment anticipates.
/// <para>
/// Kept as its own tiny assembly — rather than added to <see cref="Fixture.IndicatorPayloads"/> in the shared
/// <c>Silvergun.CodeAnalysis.IL.Tests.Fixture</c> project — for one reason: the distinct-indicator cap is a
/// GLOBAL, assembly-wide count (<c>IndicatorAnalysis.Analyze</c>'s <c>counts</c> dictionary spans every method
/// of every type CCI enumerates), so pinning an EXACT boundary (which host is the 6th, refused, distinct key;
/// which host's occurrences keep accumulating after that) requires an assembly with NOTHING else in it that
/// could also be classified as an indicator and silently consume cap slots in an order this suite does not
/// control. A single straight-line method's own <c>ldstr</c> operations are read in source order (CCI/
/// AssemblyAnalyzer.StringConstants walks Operations in emission order, and the C# compiler does not reorder
/// sequential local-variable initializations), so as long as this assembly contributes no OTHER
/// indicator-shaped constant, the six-hosts-then-two-repeats sequence below is discovered in exactly the
/// written order — which is what makes the cap-boundary and post-cap-accumulation assertions deterministic
/// rather than a guess about enumeration order.
/// </para>
/// </summary>
public class IndicatorCapPayloads
{
    /// <summary>
    /// Six distinct, genuinely public IPv4 literals (RFC 5737 TEST-NET-3, 203.0.113.0/24 — not
    /// RFC1918/loopback/link-local, so each classifies as <c>IndicatorCategory.PublicIpLiteral</c>), followed
    /// by two more constants embedding the FIRST host again. Locals + <see cref="string.Join(string, string[])"/>
    /// (not <c>+</c> on literal operands) deliberately: the C# compiler constant-folds literal concatenation
    /// into a single <c>ldstr</c>, which would collapse these eight separate constants into fewer than eight
    /// — the same technique <c>IndicatorPayloads.GetFiveCallbackConstants</c> already relies on.
    /// <para>
    /// With an injected cap of 5: the first five hosts (.1-.5) fill the cap; the sixth (.6) is a genuinely new
    /// distinct key offered AFTER the cap is full and is refused (<c>IndicatorReport.Truncated</c> becomes
    /// true); the two later repeats of .1 are for an ALREADY-tracked key and must still increment its
    /// <c>Occurrences</c> — the cap bounds distinct keys, not counting.
    /// </para>
    /// </summary>
    public string EmitCapBoundaryConstants()
    {
        var host1 = "beacon check-in to 203.0.113.1 now";
        var host2 = "beacon check-in to 203.0.113.2 now";
        var host3 = "beacon check-in to 203.0.113.3 now";
        var host4 = "beacon check-in to 203.0.113.4 now";
        var host5 = "beacon check-in to 203.0.113.5 now";
        var host6 = "beacon check-in to 203.0.113.6 now";
        var host1Repeat1 = "second check-in to 203.0.113.1 confirmed";
        var host1Repeat2 = "third check-in to 203.0.113.1 confirmed";
        return string.Join(",", host1, host2, host3, host4, host5, host6, host1Repeat1, host1Repeat2);
    }
}
