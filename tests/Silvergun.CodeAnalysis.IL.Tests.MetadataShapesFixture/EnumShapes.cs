namespace Silvergun.CodeAnalysis.IL.Tests.MetadataShapesFixture;

/// <summary>
/// The <b>patch subject</b> for the self-referential-enum fixture
/// (<c>docs/agent/tasks/self-referential-enum-stack-overflow.md</c>,
/// <c>docs/agent/measurements/ilspy-provider-spike.md</c> §7). Roslyn will not emit an enum whose underlying
/// type is an enum, so the cycle is introduced <em>after</em> compilation by
/// <c>CyclicEnumPatcher</c>, which repoints each subject's <c>value__</c> field at the
/// <c>ELEMENT_TYPE_VALUETYPE</c> field signature the compiler already emitted for that enum's own literal
/// members. Nothing here is executed, and the patched copy is written to a temp directory at test time — no
/// crafted binary is committed.
/// </summary>
public enum SelfReferentialSubject
{
    /// <summary>A literal member — its field signature is <c>FIELD ELEMENT_TYPE_VALUETYPE SelfReferentialSubject</c>,
    /// which is exactly the signature the patcher moves onto <c>value__</c> to make the enum its own underlying type.</summary>
    Zero = 0,

    /// <summary>A second member, so the enum is not degenerate.</summary>
    One = 1,
}

/// <summary>One half of a two-step cycle: patched so its underlying type is <see cref="PongSubject"/>.</summary>
public enum PingSubject
{
    /// <summary>Literal member; source of the <c>valuetype PingSubject</c> signature <see cref="PongSubject"/> is patched to.</summary>
    Zero = 0,
}

/// <summary>The other half: patched so its underlying type is <see cref="PingSubject"/>.</summary>
public enum PongSubject
{
    /// <summary>Literal member; source of the <c>valuetype PongSubject</c> signature <see cref="PingSubject"/> is patched to.</summary>
    Zero = 0,
}

/// <summary>
/// CONTROL — never patched. Its underlying type stays <c>System.Int32</c>, so a whole-module degradation
/// cannot be mistaken for the cycle actually being read.
/// </summary>
public enum SaneControl
{
    /// <summary>Literal member.</summary>
    One = 1,
}

/// <summary>
/// Method bodies and signatures that mention the patched enums, so loading the patched module has to decode
/// the pathological types from a signature blob and from IL, not merely from the type table.
/// </summary>
public static class EnumOps
{
    /// <summary>Fat header (locals) whose parameters are all four enums.</summary>
    public static int Mix(SelfReferentialSubject self, PingSubject ping, PongSubject pong, SaneControl sane)
    {
        var accumulated = (int)self + (int)ping;
        accumulated += (int)pong + (int)sane;
        return accumulated * 2;
    }

    /// <summary>Returns a patched enum, so the return signature carries it too.</summary>
    public static SelfReferentialSubject Echo(SelfReferentialSubject value) => value;

    /// <summary>An array of a patched enum, so the array-element decode path sees it as well.</summary>
    public static int Count(SelfReferentialSubject[] values) => values is null ? 0 : values.Length;
}
