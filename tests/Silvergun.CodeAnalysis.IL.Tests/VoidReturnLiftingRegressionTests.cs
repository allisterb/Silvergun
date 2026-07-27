namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Linq;

using Model.Types;
using Tac = Model.ThreeAddressCode.Instructions;

using Xunit;

/// <summary>
/// Regression coverage for the TAC void-return fix in <c>ext/analysis-net</c>'s <c>Disassembler</c> (the new
/// <c>IsVoidReturn(IType)</c> helper) — see <c>docs/agent/measurements/tac-platformtypes-spike.md</c>.
/// <para>
/// Before the fix, every "is this void?" check compared against <c>PlatformTypes.Void</c>, which is
/// hard-coded to assembly <c>"mscorlib"</c> (<c>BasicType.Equals</c> compares <c>ContainingAssembly</c>), so
/// the comparison silently never matched on a modern (<c>[System.Runtime]</c>/
/// <c>[System.Private.CoreLib]</c>) corlib. Three sites were affected:
/// </para>
/// <list type="number">
/// <item><description>site 1, <c>ProcessReturn</c> — a void method's own <c>ret</c> popped an operand off an
/// empty stack;</description></item>
/// <item><description>site 2, direct <c>call</c>/<c>callvirt</c> — every call to a void method wrongly pushed
/// a phantom result nothing ever pops;</description></item>
/// <item><description>site 3, indirect <c>calli</c> — the same phantom push, for
/// <c>IndirectMethodCallInstruction</c>.</description></item>
/// </list>
/// <para>
/// <c>Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture</c>'s <c>Widget</c> is compiled twice from byte-for-byte
/// identical source — once <c>net472</c> (mscorlib, the control, never affected) and once <c>net10.0</c> (the
/// flavour that broke) — so these tests assert both TAC <em>correctness</em> on the fixed flavour (not merely
/// that lifting didn't throw) and that the two builds <em>agree</em>, which is the actual property the fix
/// restores.
/// </para>
/// </summary>
public sealed class VoidReturnLiftingRegressionTests : IClassFixture<VoidReturnFixtureFixture>
{
    public VoidReturnLiftingRegressionTests(VoidReturnFixtureFixture fixture) => this.fixture = fixture;

    public static TheoryData<string> VoidMethods => new()
    {
        "set_Count", "FillItems", "SafeClear", "RiskyOperation", "CallsHelper", "Helper",
    };

    // Site 1: a void method's own `ret` must carry no operand — the bug popped one off an empty stack.
    [Theory]
    [MemberData(nameof(VoidMethods))]
    public void DisassembleMethod_VoidMethod_Net10_ReturnHasNoOperand(string methodName)
    {
        var body = fixture.Disassemble(fixture.Net10, "Widget", methodName);

        var returns = body.Instructions.OfType<Tac.ReturnInstruction>().ToList();
        Assert.NotEmpty(returns);
        Assert.All(returns, r => Assert.False(r.HasOperand,
            $"{methodName}: void method's return has an operand ({r.Operand}) — the empty-stack-pop bug (site 1)."));
    }

    // Control: net472 (mscorlib) was never affected — PlatformTypes.Void's ContainingAssembly matches
    // directly. If this ever goes red, the control itself is broken, not the fix.
    [Theory]
    [MemberData(nameof(VoidMethods))]
    public void DisassembleMethod_VoidMethod_Net472_ReturnHasNoOperand(string methodName)
    {
        var body = fixture.Disassemble(fixture.Net472, "Widget", methodName);

        var returns = body.Instructions.OfType<Tac.ReturnInstruction>().ToList();
        Assert.NotEmpty(returns);
        Assert.All(returns, r => Assert.False(r.HasOperand,
            $"{methodName}: void method's return has an operand ({r.Operand}) on the net472 control build."));
    }

    // Positive control: a NON-void method's return must still carry an operand — proves the assertion above
    // is not vacuously true regardless of the method's signature.
    [Fact]
    public void DisassembleMethod_NonVoidGetter_Net10_ReturnHasOperand()
    {
        var body = fixture.Disassemble(fixture.Net10, "Widget", "get_Count");

        var ret = Assert.Single(body.Instructions.OfType<Tac.ReturnInstruction>());
        Assert.True(ret.HasOperand, "get_Count returns int, but its TAC return carries no operand.");
    }

    // Sites 2/3: every call to a void-returning method must be a bare statement — no result variable, since
    // nothing in the source consumes one. Before the fix, every such call wrongly allocated and pushed a
    // phantom result. IsVoidType below is this test's OWN oracle for "is this System.Void", independent of
    // the fix under test (name + namespace, ignoring assembly, which is the correct modern-IL definition).
    [Theory]
    [MemberData(nameof(VoidMethods))]
    public void DisassembleMethod_CallsToVoidMethods_Net10_HaveNoResult(string methodName)
    {
        var body = fixture.Disassemble(fixture.Net10, "Widget", methodName);

        var voidCalls = body.Instructions.OfType<Tac.MethodCallInstruction>()
            .Where(call => IsVoidType(call.Method.ReturnType))
            .ToList();

        Assert.All(voidCalls, call => Assert.False(call.HasResult,
            $"{methodName}: call to void method {call.Method.Name} wrongly has a result variable ({call.Result}) — the phantom-push bug (site 2)."));
    }

    [Theory]
    [MemberData(nameof(VoidMethods))]
    public void DisassembleMethod_CallsToVoidMethods_Net472_HaveNoResult(string methodName)
    {
        var body = fixture.Disassemble(fixture.Net472, "Widget", methodName);

        var voidCalls = body.Instructions.OfType<Tac.MethodCallInstruction>()
            .Where(call => IsVoidType(call.Method.ReturnType))
            .ToList();

        Assert.All(voidCalls, call => Assert.False(call.HasResult,
            $"{methodName}: call to void method {call.Method.Name} wrongly has a result variable ({call.Result}) on the net472 control build."));
    }

    // Positive control for the call-site check: CallsNonVoidMethod calls Math.Abs(int), which returns int —
    // that call's result MUST be non-null, proving the void-call assertion above isn't vacuously true.
    [Fact]
    public void DisassembleMethod_CallToNonVoidMethod_Net10_HasResult()
    {
        var body = fixture.Disassemble(fixture.Net10, "Widget", "CallsNonVoidMethod");

        var call = Assert.Single(body.Instructions.OfType<Tac.MethodCallInstruction>());
        Assert.True(call.HasResult, "Call to Math.Abs (int-returning) wrongly has no result variable.");
    }

    // Site 2, isolated: CallsHelper's single instruction is a direct call to Widget.Helper() (void), free of
    // any loop/EH shape that could mask a regression here behind one of the other methods.
    [Fact]
    public void DisassembleMethod_CallsHelper_Net10_CallHasNoResult()
    {
        var body = fixture.Disassemble(fixture.Net10, "Widget", "CallsHelper");

        var call = Assert.Single(body.Instructions.OfType<Tac.MethodCallInstruction>());
        Assert.Equal("Helper", call.Method.Name);
        Assert.False(call.HasResult, "Direct call to a void method wrongly has a result variable.");
    }

    // The property the whole fix restores: identical source, only the corlib differs, and the lifted TAC
    // shape must now agree instruction-for-instruction. Compared STRUCTURALLY (instruction types, return
    // operand-ness, call-target name and result-ness) rather than via ToString(): the pretty-printer has an
    // unrelated pre-existing rendering artifact on the first instruction of a catch/finally region (flagged
    // in the spike, not this fix's concern), and a text comparison would either false-fail on it or need to
    // special-case it, obscuring what's actually being asserted.
    [Theory]
    [MemberData(nameof(VoidMethods))]
    public void DisassembleMethod_Net472AndNet10_AgreeOnShape(string methodName)
    {
        var net10 = fixture.Disassemble(fixture.Net10, "Widget", methodName);
        var net472 = fixture.Disassemble(fixture.Net472, "Widget", methodName);

        Assert.Equal(net472.Instructions.Count, net10.Instructions.Count);

        foreach (var (a, b) in net472.Instructions.Zip(net10.Instructions))
        {
            Assert.Equal(a.GetType(), b.GetType());

            switch (a, b)
            {
                case (Tac.ReturnInstruction ra, Tac.ReturnInstruction rb):
                    Assert.Equal(ra.HasOperand, rb.HasOperand);
                    break;
                case (Tac.MethodCallInstruction ca, Tac.MethodCallInstruction cb):
                    Assert.Equal(ca.Method.Name, cb.Method.Name);
                    Assert.Equal(ca.HasResult, cb.HasResult);
                    break;
            }
        }
    }

    // Site 3 (calli): net10.0-only — a genuine function-pointer invocation (see CalliOps.cs, #if guarded to
    // net10.0). Widget.InvokeCalli lifts through IndirectMethodCallInstruction, not MethodCallInstruction —
    // the fix's third site, and the least-covered by the spike's own real-world corpus. No net472 equivalent
    // exists to compare against (the fixture deliberately doesn't attempt delegate* there), so this is an
    // absolute correctness assertion rather than a parity one.
    [Fact]
    public void DisassembleMethod_Calli_Net10_IndirectCallHasNoResult()
    {
        var body = fixture.Disassemble(fixture.Net10, "CalliOps", "InvokeCalli");

        var call = Assert.Single(body.Instructions.OfType<Tac.IndirectMethodCallInstruction>());
        Assert.False(call.HasResult, "calli to a void function pointer wrongly has a result variable — the phantom-push bug (site 3).");
    }

    private static bool IsVoidType(IType type) =>
        type is IBasicType basicType && basicType.Name == "Void" && basicType.ContainingNamespace == "System";

    private readonly VoidReturnFixtureFixture fixture;
}
