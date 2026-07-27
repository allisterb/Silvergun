// delegate* function pointers (C# 9, `unsafe`) are what makes the compiler emit a genuine `calli` IL
// instruction - fix site 3 (IndirectMethodCallInstruction) of the TAC void-return fix. This fixture pair
// only builds it for net10.0: net472 has no reason to differ (mscorlib was never affected by the bug), and
// keeping it out of that flavour avoids depending on delegate*'s behaviour under an older toolchain that
// this spike never measured. See docs/agent/measurements/tac-platformtypes-spike.md.
#if NET5_0_OR_GREATER
namespace Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture
{
    /// <summary>
    /// A genuine <c>calli</c> fixture. Nothing here is ever executed - it exists purely to give the
    /// disassembler a real indirect call to lift.
    /// </summary>
    public class CalliOps
    {
        public static void Target(int x)
        {
        }

        public unsafe void InvokeCalli()
        {
            delegate*<int, void> fp = &Target;
            fp(42);
        }
    }
}
#endif
