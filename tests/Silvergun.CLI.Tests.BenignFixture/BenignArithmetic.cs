namespace Silvergun.CLI.Tests.BenignFixture;

/// <summary>
/// A deliberately boring assembly: pure integer arithmetic, no string constants, and not one call into the
/// <c>CapabilityAnalysis</c> catalog (no file system, network, process, registry, environment, reflection,
/// interop or cryptography API). It exists so <c>Silvergun.CLI analyze</c> reports it <b>Clean</b> with exit 0.
/// <para>
/// That clean baseline is what makes the exit-3 test in <c>UnreadableMethodBodyCliTests</c> mean something: with a
/// single method body corrupted at test time, the ONLY thing that changes is coverage, so the footer must move from
/// "Clean" to "Not verified" and the exit code from 0 to 3. Analysing an assembly that already has findings would
/// print "Findings present" instead and could not distinguish the two.
/// </para>
/// <para>
/// <b>Do not add</b> string literals of 24+ characters (the obfuscation analysis would classify base64/hex-shaped
/// ones) or any BCL call outside <c>System.Object</c> — either would break the Clean baseline.
/// </para>
/// </summary>
public static class BenignArithmetic
{
    /// <summary>
    /// The method the CLI test corrupts. It carries locals and a loop, so Roslyn emits a <b>fat</b> method header —
    /// required, because only the fat format has the 4-byte <c>CodeSize</c> field the patch overwrites; a tiny
    /// header encodes its size in the header byte itself and cannot be corrupted the same way.
    /// </summary>
    public static int Accumulate(int count)
    {
        var sum = 0;
        var carry = 1;
        for (var i = 0; i < count; i++)
        {
            var scaled = (i * 3) + carry;
            carry = (carry + scaled) % 7;
            sum += scaled - (sum / 2);
        }
        return sum + carry;
    }

    /// <summary>
    /// A second bodied method, untouched by the patch. Its presence is what lets the coverage line read
    /// "N-1 of N" rather than "0 of 1" — i.e. the assembly still analyses successfully around the corrupted body.
    /// </summary>
    public static int Blend(int left, int right)
    {
        var mixed = (left * 31) ^ (right + 17);
        return mixed < 0 ? -mixed : mixed;
    }

    /// <summary>A trivial expression-bodied member, so the assembly holds a tiny-header method too.</summary>
    public static int Double(int value) => value * 2;
}
