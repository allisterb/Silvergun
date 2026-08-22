namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// The inert positive control the real-engine YARA tests scan: an <c>MZ</c> prefix followed by the literal byte
/// pattern of the embedded <c>Win32_Trojan_HermeticWiper</c> rule with every <c>??</c> wildcard filled with
/// <c>0x00</c> — enough to satisfy that rule's condition (<c>uint16(0) == 0x5A4D</c> and the one hex string) and
/// nothing else. It is not a valid PE, has no entry point, and is never executed. It exists so that "the hit was
/// attributed to the right path" is a statement about a real engine's real output rather than about a fake.
///
/// <para><b>The pattern is derived from the embedded rule resource at run time, never transcribed.</b> A verbatim
/// copy drifts the moment the rule is updated (the submodule is upstream code), and the drift would only be
/// detectable in a WSL run, as a real-engine test quietly finding nothing and asserting nothing. Reading the rule
/// the scanner itself compiles removes that failure mode: if the rule changes shape, <see cref="Bytes"/> throws
/// with an explanation instead of yielding a sample that matches nothing.</para>
///
/// <para><b>Provenance.</b> The rule is
/// <c>ext/reversinglabs-yara-rules/yara/trojan/Win32.Trojan.HermeticWiper.yara</c>, from the ReversingLabs
/// yara-rules submodule, embedded into <c>Silvergun.PackageAnalysis.NuGet</c> by link under
/// <c>Resources/YaraRules/ReversingLabs/</c>; see the licence and attribution in
/// <c>src/Silvergun.PackageAnalysis.NuGet/Resources/YaraRules/NOTICE.md</c>. Nothing is copied into this
/// repository by this file — only read, at run time, out of the built assembly's manifest resources.</para>
/// </summary>
internal static class HermeticWiperSample
{
    #region Properties
    /// <summary>The rule the sample is built to satisfy — and the rule name every hit on it must carry.</summary>
    internal const string RuleName = "Win32_Trojan_HermeticWiper";

    /// <summary>The hex string inside that rule whose literal bytes the sample reproduces.</summary>
    internal const string StringName = "$corrupt_physical_drive";

    /// <summary>The sample bytes. Throws (loudly, once) if the embedded rule no longer has the expected shape.</summary>
    internal static byte[] Bytes => bytes.Value;
    #endregion

    #region Methods
    private static byte[] Build()
    {
        var source = YaraRuleResources.ReadAll(typeof(YaraCliScanner).Assembly)
            .Select(r => r.Text)
            .FirstOrDefault(t => t.Contains("rule " + RuleName, StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                $"No embedded YARA rule resource declares '{RuleName}'. The real-engine ADR 0029 tests build their "
                + "positive control from that rule, so it cannot be scanned for without it.");

        var name = source.IndexOf(StringName, StringComparison.Ordinal);
        var open = name < 0 ? -1 : source.IndexOf('{', name);
        var close = open < 0 ? -1 : source.IndexOf('}', open);
        if (close < 0)
            throw new InvalidOperationException(
                $"The embedded '{RuleName}' rule no longer contains a '{StringName} = {{ … }}' hex string. Update "
                + "this fixture to a string the rule actually declares rather than leaving the sample unmatched.");

        var bytes = new List<byte> { 0x4D, 0x5A };   // "MZ" — satisfies the rule's uint16(0) == 0x5A4D condition
        foreach (var token in source[(open + 1)..close].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (token == "??")
                bytes.Add(0x00);                     // a wildcard: any byte will do, so pick a boring one
            else if (token.Length == 2 && byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out var b))
                bytes.Add(b);
            else
                throw new InvalidOperationException(
                    $"The embedded '{RuleName}' rule's {StringName} carries the token '{token}', which this fixture "
                    + "cannot render as a literal byte (nibble wildcards, jumps and alternations are not handled). "
                    + "Pick another rule or teach the fixture that syntax — do not ship a sample that matches nothing.");
        }

        return bytes.ToArray();
    }
    #endregion

    #region Fields
    private static readonly Lazy<byte[]> bytes = new(Build);
    #endregion
}

/// <summary>
/// Guards the fixture above. If the derivation silently produced a dud, every real-engine test in this suite
/// would pass by finding nothing, on the one platform where they are the ADR's only coverage.
/// </summary>
public sealed class HermeticWiperSampleTests
{
    #region Methods
    // The sample is derived, not transcribed, so this pins the derivation itself: a real MZ prefix, a plausible
    // length, and no accidental truncation to the first few bytes of the rule's hex string.
    [Fact]
    public void Sample_IsDerivedFromTheEmbeddedRule_AndIsWellFormed()
    {
        var bytes = HermeticWiperSample.Bytes;

        Assert.Equal(0x4D, bytes[0]);
        Assert.Equal(0x5A, bytes[1]);
        Assert.True(bytes.Length > 400, $"The derived sample is only {bytes.Length} bytes; the rule's hex string is far longer.");
    }

    // The rule the sample targets must still be one the shipped index knows about — the same lookup the report
    // enrichment performs. A renamed rule would otherwise leave the Linux tests asserting against a rule name no
    // backend can ever emit.
    [Fact]
    public void TheTargetedRule_IsPresentInTheShippedRuleIndex()
    {
        var entry = YaraRuleIndex.Shared.Lookup(HermeticWiperSample.RuleName);

        Assert.NotNull(entry);
        Assert.Equal("HERMETICWIPER", entry!.MalwareFamily);
    }
    #endregion
}
