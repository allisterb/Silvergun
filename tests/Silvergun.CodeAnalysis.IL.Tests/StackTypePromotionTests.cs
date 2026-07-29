namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Reflection;

using Model;
using Model.Types;

using Xunit;

/// <summary>
/// Coverage for <see cref="StackTypePromotion.Combine"/> in <c>ext/analysis-net</c> — the ECMA-335
/// (6th ed., June 2012) Partition III §1.5 Table III.2 "Binary Numeric Operations" promotion that replaced
/// <c>TypeHelper.BinarySignedNumericOperationType</c>'s hand-rolled cascade. See
/// <c>docs/agent/tasks/ecma335-binary-numeric-promotion.md</c> and
/// <c>docs/agent/decisions/0023-ecma335-stack-type-promotion.md</c>.
/// <para>
/// The cascade this replaced was asymmetric on ~40% of <see cref="PlatformTypes"/> pairs. Because
/// <c>BinarySignedNumericOperationType</c> receives <b>no operator argument</b>, it is pure numeric promotion
/// and is <i>required</i> to be commutative — Table III.2's result table is symmetric; only the set of legal
/// instructions is not (<c>&amp; - int32</c> is legal, <c>int32 - &amp;</c> is not). That makes commutativity a
/// provable property needing no oracle, and it is the primary gate here
/// (<see cref="Combine_ForEveryOrderedPairOfOperands_IsCommutativeAndNeverThrows"/>).
/// </para>
/// <para>
/// Three further properties are pinned: <b>totality</b> (hostile and obfuscated assemblies are in scope, so no
/// input combination may throw — including unbound <see cref="BasicType"/> references, whose
/// <c>ResolvedType</c> throws <see cref="InvalidOperationException"/>, and partially built types that carry a
/// null <c>ContainingAssembly</c> into <c>Equals</c>); the <b>null contract</b> (<c>null</c> means "not yet
/// known", never <see cref="PlatformTypes.Unknown"/>, which would permanently pin a wrong answer in
/// <c>TypeInferenceAnalysis</c>'s fixed point — see <see cref="NullGuardRegressionTests"/>); and
/// <b>singleton identity</b> (the promotion returns the static <see cref="PlatformTypes"/> instances, which
/// <see cref="NullGuardRegressionTests"/>'s <c>Assert.Same</c> assertions depend on).
/// </para>
/// <para>
/// These are ordinary <c>Model</c> types built directly — no CCI, no host resolution — so they run in-process,
/// not via a child process like <see cref="TypedReferencePointerRegressionTests"/> (ADR-0021).
/// </para>
/// <para>
/// ⚠️ <b>Deliberately absent: a self-referential enum</b> (<c>enumDef.UnderlayingType = enumDef</c>). It causes
/// an uncatchable stack overflow that kills the whole test host process rather than failing a test — a known
/// open defect tracked in <c>docs/agent/tasks/self-referential-enum-stack-overflow.md</c>. Enum <i>chains</i>
/// (<c>E1 : E2 : int32</c>) are safe and are covered below. Do not add the self-referential case here.
/// </para>
/// </summary>
public sealed class StackTypePromotionTests
{
    #region The operand corpus (criterion 1: the exhaustive commutativity sweep)
    // Every reflected PlatformTypes IType field, plus the structural and degenerate shapes the promotion has
    // to classify without a resolved host: pointers, pointer-to-pointer, arrays, array-of-array, function
    // pointers, enums (int32-underlying, int64-underlying, null-underlying and a two-link chain), a generic
    // parameter, three flavours of unbound BasicType reference, and null.
    private static readonly IReadOnlyList<(string Name, IType? Type)> Operands = BuildOperands();

    private static IReadOnlyList<(string Name, IType? Type)> BuildOperands()
    {
        var operands = typeof(PlatformTypes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => typeof(IType).IsAssignableFrom(field.FieldType))
            .OrderBy(field => field.Name, StringComparer.Ordinal)
            .Select(field => ($"PlatformTypes.{field.Name}", (IType?)field.GetValue(null)))
            .ToList();

        var pointerToInt32 = new PointerType(PlatformTypes.Int32);
        var arrayOfInt32 = new ArrayType(PlatformTypes.Int32);

        operands.AddRange(new (string, IType?)[]
        {
            ("PointerType(Int32)", pointerToInt32),
            ("PointerType(PointerType(Int32))", new PointerType(pointerToInt32)),
            ("ArrayType(Int32)", arrayOfInt32),
            ("ArrayType(ArrayType(Int32))", new ArrayType(arrayOfInt32)),
            ("FunctionPointerType(Void)", new FunctionPointerType(PlatformTypes.Void)),
            ("EnumDefinition : Int32", MakeEnum("SampleEnumInt32", PlatformTypes.Int32)),
            ("EnumDefinition : Int64", MakeEnum("SampleEnumInt64", PlatformTypes.Int64)),
            ("EnumDefinition : <null underlying>", MakeEnum("SampleEnumNoUnderlyingType", null)),
            ("EnumDefinition chain E1 : E2 : Int32", MakeEnumChain()),
            ("GenericParameterReference", new GenericParameterReference(GenericParameterKind.Type, 0)),
            ("unbound BasicType (ValueType)", MakeUnboundValueType()),
            ("unbound BasicType (ReferenceType)", MakeUnboundReferenceType()),
            ("unbound BasicType (bare, no ContainingAssembly)", MakeUnboundBareType()),
            ("null", null),
        });

        return operands;
    }

    /// <summary>
    /// The primary gate (acceptance criterion 1). Every ordered pair over <see cref="Operands"/> must give the
    /// same answer in both directions, and none may throw. Commutativity is guaranteed <i>structurally</i> in
    /// <c>StackTypePromotion</c> — <c>Classify</c> is unary and the table is read after the pair is sorted by
    /// ordinal — so this test proves the structure holds rather than sampling for luck.
    /// </summary>
    [Fact]
    public void Combine_ForEveryOrderedPairOfOperands_IsCommutativeAndNeverThrows()
    {
        var asymmetric = new List<string>();
        var threw = new List<string>();
        var pairs = 0;

        foreach (var (leftName, left) in Operands)
        {
            foreach (var (rightName, right) in Operands)
            {
                pairs++;

                IType? forward;
                IType? backward;

                try
                {
                    forward = StackTypePromotion.Combine(left, right);
                    backward = StackTypePromotion.Combine(right, left);
                }
                catch (Exception exception)
                {
                    threw.Add($"({leftName}, {rightName}) threw {exception.GetType().Name}: {exception.Message}");
                    continue;
                }

                if (!SameResult(forward, backward))
                {
                    asymmetric.Add($"({leftName}, {rightName}) -> {Describe(forward)} but ({rightName}, {leftName}) -> {Describe(backward)}");
                }
            }
        }

        Assert.Empty(threw);      // Totality (criterion 3).
        Assert.Empty(asymmetric); // Commutativity (criterion 1): required result is 0 asymmetric pairs.

        // Pinned so the sweep can never silently shrink into a vacuous pass. 37 reflected PlatformTypes IType
        // fields + 14 constructed/degenerate operands (including null) = 51 operands = 2,601 ordered pairs.
        Assert.Equal(51, Operands.Count);
        Assert.Equal(2601, pairs);

        // PlatformTypes.Unknown must be one of the 37 reflected fields. It is: its declared field type is
        // UnknownType, which implements IType, so the IsAssignableFrom filter in BuildOperands already picks it
        // up (37 = 36 BasicType fields + Unknown). Pinned by reference rather than left implicit because the
        // UnknownType laundering defect (architect decision 6 / review W1) was a sentinel-shaped hole in this
        // corpus's *semantics*: Combine used to answer Unknown for (Unknown, Int32) and PlatformTypes.Object
        // for (Unknown, String), and BOTH orders agreed, so this sweep passed on it. Symmetric is not the same
        // as correct — see Combine_ForEveryOperandPairedWithTheUnknownSentinel_ReturnsNullInBothOrders below,
        // which is the assertion that actually catches it.
        Assert.Contains(Operands, operand => ReferenceEquals(operand.Type, PlatformTypes.Unknown));
    }
    #endregion

    #region Valid Table III.2 cells, both operand orders (criterion 2)
    [Fact]
    public void Combine_Int32TimesInt32_ReturnsInt32InBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.Int32, PlatformTypes.Int32, PlatformTypes.Int32);

    [Fact]
    public void Combine_Int32TimesNativeInt_ReturnsIntPtrInBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.IntPtr, PlatformTypes.Int32, PlatformTypes.IntPtr);

    [Fact]
    public void Combine_Int64TimesInt64_ReturnsInt64InBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.Int64, PlatformTypes.Int64, PlatformTypes.Int64);

    [Fact]
    public void Combine_NativeIntTimesNativeInt_ReturnsIntPtrInBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.IntPtr, PlatformTypes.IntPtr, PlatformTypes.IntPtr);

    [Fact]
    public void Combine_FloatTimesFloat_ReturnsDoubleInBothOrders() =>
        // ECMA's F is a single stack type; TypeHelper.StackType collapses float32 and float64 onto Float64.
        AssertCombinesToSameInstance(PlatformTypes.Float64, PlatformTypes.Float64, PlatformTypes.Float64);

    [Fact]
    public void Combine_Float32TimesFloat64_ReturnsDoubleInBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.Float64, PlatformTypes.Float32, PlatformTypes.Float64);

    [Fact]
    public void Combine_ManagedPointerTimesInt32_ReturnsThePointerInBothOrders()
    {
        // Table III.2: "& + int32 -> &". The pointer's target type is preserved, which is what the replaced
        // IReferenceType arms did and what pointer arithmetic in the TAC expects.
        var pointer = new PointerType(PlatformTypes.Int32);

        AssertCombinesToSameInstance(pointer, pointer, PlatformTypes.Int32);
    }

    [Fact]
    public void Combine_ManagedPointerTimesNativeInt_ReturnsThePointerInBothOrders()
    {
        var pointer = new PointerType(PlatformTypes.Int32);

        AssertCombinesToSameInstance(pointer, pointer, PlatformTypes.IntPtr);
    }

    [Fact]
    public void Combine_ManagedPointerTimesManagedPointer_ReturnsIntPtrInBothOrders()
    {
        // Table III.2: "& - & -> native int". Deliberate behaviour change from the replaced code, which chose
        // UIntPtr — one of its unsigned guesses. Signedness is out-of-band (ADR-0023 §2, re-applied by
        // TypeHelper.UnsignedEquivalent) and a pointer difference is signed anyway. Confirmed by the architect
        // in the task spec's "Architect decisions on the implementation report" §1.
        var left = new PointerType(PlatformTypes.Int32);
        var right = new PointerType(PlatformTypes.Byte);

        AssertCombinesToSameInstance(PlatformTypes.IntPtr, left, right);
    }
    #endregion

    #region Lenient cells — invalid ("--") in ECMA but reachable from hostile input (criterion 3 leniency)
    [Fact]
    public void Combine_Int32TimesInt64_ReturnsInt64InBothOrders() =>
        // "--" in Table III.2; widened to the larger integer per the documented Int32 < NativeInt < Int64 order.
        AssertCombinesToSameInstance(PlatformTypes.Int64, PlatformTypes.Int32, PlatformTypes.Int64);

    [Fact]
    public void Combine_NativeIntTimesInt64_ReturnsInt64InBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.Int64, PlatformTypes.IntPtr, PlatformTypes.Int64);

    [Fact]
    public void Combine_FloatTimesInt32_ReturnsDoubleInBothOrders() =>
        // "--" in Table III.2; F absorbs integers. This is the cell the original bug got wrong one way round.
        AssertCombinesToSameInstance(PlatformTypes.Float64, PlatformTypes.Float64, PlatformTypes.Int32);

    [Fact]
    public void Combine_FloatTimesManagedPointer_ReturnsDoubleInBothOrders()
    {
        // "--" in Table III.2; documented leniency precedence is O > F > & > integer widening.
        var pointer = new PointerType(PlatformTypes.Int32);

        AssertCombinesToSameInstance(PlatformTypes.Float64, PlatformTypes.Float64, pointer);
    }

    [Fact]
    public void Combine_ManagedPointerTimesInt64_ReturnsThePointerInBothOrders()
    {
        // "--" in Table III.2; treated as the "& +- native int" cell, so the pointer survives.
        var pointer = new PointerType(PlatformTypes.Int32);

        AssertCombinesToSameInstance(pointer, pointer, PlatformTypes.Int64);
    }

    [Fact]
    public void Combine_ObjectReferenceTimesInt32_ReturnsTheObjectOperandInBothOrders() =>
        // "--" in Table III.2; O absorbs everything, and the one O operand is kept.
        AssertCombinesToSameInstance(PlatformTypes.String, PlatformTypes.String, PlatformTypes.Int32);

    [Fact]
    public void Combine_ObjectReferenceTimesManagedPointer_ReturnsTheObjectOperandInBothOrders()
    {
        var pointer = new PointerType(PlatformTypes.Int32);

        AssertCombinesToSameInstance(PlatformTypes.String, PlatformTypes.String, pointer);
    }

    [Fact]
    public void Combine_ObjectReferenceTimesSameObjectReference_ReturnsThatTypeInBothOrders() =>
        AssertCombinesToSameInstance(PlatformTypes.String, PlatformTypes.String, PlatformTypes.String);

    [Fact]
    public void Combine_ObjectReferenceTimesDistinctObjectReference_ReturnsObjectInBothOrders() =>
        // Their common root System.Object is a constant, so the answer cannot depend on operand order.
        AssertCombinesToSameInstance(PlatformTypes.Object, PlatformTypes.String, PlatformTypes.Task);
    #endregion

    #region Regression pins for the deliberate behaviour changes (task spec's behaviour-change table)
    [Fact]
    public void Combine_ByteAndByte_ReturnsInt32BecauseEcmaStackTypeOfByteIsInt32NotUInt32()
    {
        // Was UInt32. C# `byte + byte` emits a plain `add`; ECMA-335 III.1.1.1 collapses u1 onto int32, and
        // signedness belongs on the `unsigned` flag the caller already passes (see the control below).
        AssertCombinesToSameInstance(PlatformTypes.Int32, PlatformTypes.Byte, PlatformTypes.Byte);

        Assert.NotSame(PlatformTypes.UInt32, StackTypePromotion.Combine(PlatformTypes.Byte, PlatformTypes.Byte));
    }

    [Fact]
    public void Combine_Float64AndInt32_ReturnsDoubleInBothOrders_TheOriginalAsymmetryBug()
    {
        // The confirmed root cause (former TypeHelper.cs:781-783): a Float32/Float64 left operand returned
        // `right` unconditionally, so (Float64, Int32) -> Int32 while (Int32, Float64) -> Float64. Both orders
        // must now be Double.
        Assert.Same(PlatformTypes.Double, StackTypePromotion.Combine(PlatformTypes.Float64, PlatformTypes.Int32));
        Assert.Same(PlatformTypes.Double, StackTypePromotion.Combine(PlatformTypes.Int32, PlatformTypes.Float64));
    }

    [Fact]
    public void Combine_UInt64AndInt32_ReturnsInt64BecauseSignednessMovesToUnsignedEquivalent()
    {
        // Was UInt64. The stack-type domain has no signed/unsigned axis (ECMA-335 III.1.1);
        // TypeInferenceAnalysis passes instruction.UnsignedOperands and TypeHelper.UnsignedEquivalent
        // re-applies it.
        AssertCombinesToSameInstance(PlatformTypes.Int64, PlatformTypes.UInt64, PlatformTypes.Int32);
    }

    [Fact]
    public void Combine_EnumInt32AndEnumInt32_ReturnsInt32BecauseStackTypeResolvesEnumsToTheirUnderlyingType()
    {
        // Was `left` (the enum itself). TypeHelper.StackType already looks through EnumDefinition.
        var first = MakeEnum("FirstEnum", PlatformTypes.Int32);
        var second = MakeEnum("SecondEnum", PlatformTypes.Int32);

        AssertCombinesToSameInstance(PlatformTypes.Int32, first, second);
        AssertCombinesToSameInstance(PlatformTypes.Int32, first, first);
    }

    [Fact]
    public void Combine_BooleanAndBoolean_ReturnsInt32BecauseEcmaCollapsesBooleanToInt32() =>
        // Was UInt32. ECMA-335 III.1.1.1: bool is tracked on the stack as int32.
        AssertCombinesToSameInstance(PlatformTypes.Int32, PlatformTypes.Boolean, PlatformTypes.Boolean);

    [Fact]
    public void Combine_CharAndChar_ReturnsInt32BecauseEcmaCollapsesCharToInt32() =>
        // Was UInt32. ECMA-335 III.1.1.1: char is tracked on the stack as int32.
        AssertCombinesToSameInstance(PlatformTypes.Int32, PlatformTypes.Char, PlatformTypes.Char);
    #endregion

    #region Controls: the surrounding TypeHelper layer is unchanged (criterion 5)
    [Fact]
    public void BinaryLogicalOperationType_WhenBothOperandsAreBoolean_StillReturnsBooleanWithoutDelegating()
    {
        // BinaryLogicalOperationType short-circuits on the boolean/boolean case BEFORE delegating, so the
        // promotion's Boolean -> Int32 collapse must not leak into it.
        var result = TypeHelper.BinaryLogicalOperationType(PlatformTypes.Boolean, PlatformTypes.Boolean);

        Assert.Same(PlatformTypes.Boolean, result);
    }

    [Fact]
    public void BinaryNumericOperationType_ByteAndByteUnsigned_StillReturnsUInt32ViaUnsignedEquivalent()
    {
        // The promotion answers Int32 (signedness is not in the stack-type domain); UnsignedEquivalent puts the
        // sign back. This is why Combine returning Int32 for (Byte, Byte) is not a loss of information.
        var result = TypeHelper.BinaryNumericOperationType(PlatformTypes.Byte, PlatformTypes.Byte, unsigned: true);

        Assert.Same(PlatformTypes.UInt32, result);
    }

    [Fact]
    public void BinaryNumericOperationType_ByteAndByteSigned_ReturnsInt32()
    {
        var result = TypeHelper.BinaryNumericOperationType(PlatformTypes.Byte, PlatformTypes.Byte, unsigned: false);

        Assert.Same(PlatformTypes.Int32, result);
    }
    #endregion

    #region Null contract (criterion 3) — "not yet known", never PlatformTypes.Unknown
    [Fact]
    public void Combine_WhenLeftIsNull_ReturnsNull() =>
        Assert.Null(StackTypePromotion.Combine(null, PlatformTypes.Int32));

    [Fact]
    public void Combine_WhenRightIsNull_ReturnsNull() =>
        Assert.Null(StackTypePromotion.Combine(PlatformTypes.Int32, null));

    [Fact]
    public void Combine_WhenBothOperandsAreNull_ReturnsNull() =>
        Assert.Null(StackTypePromotion.Combine(null, null));

    [Fact]
    public void Combine_WhenNeitherOperandIsNull_ReturnsNonNull() =>
        // Positive control: the guard must not have become an unconditional null return.
        Assert.NotNull(StackTypePromotion.Combine(PlatformTypes.Int32, PlatformTypes.Int32));

    [Fact]
    public void Combine_WhenAnOperandIsNull_DoesNotReturnPlatformTypesUnknown()
    {
        // Why null and not PlatformTypes.Unknown — corrected 2026-07-29 (review finding N4). This comment used
        // to say the fixed point "never overwrites an already-non-null Type". That is FALSE for this call path:
        // Visit(BinaryInstruction) assigns instruction.Result.Type unconditionally on every visit
        // (TypeInferenceAnalysis.cs:246 and :252), so the *result* slot is rewritten each iteration regardless.
        //
        // The real hazard is the operand BACK-propagation, which is fill-only and therefore one-way. Several
        // sites write an operand's Type; the ones that matter here are, e.g.:
        //   • Visit(ConditionalBranchInstruction) (TypeInferenceAnalysis.cs:295-304) copies one operand's type
        //     onto the other only while that other operand's Type is still null — no escape hatch at all;
        //   • Visit(LoadInstruction) (:147-154), Visit(StoreInstruction) (:170-176) and
        //     Visit(ReturnInstruction) (:182-189) copy the result/return type onto the operand only when the
        //     operand's Type is null OR equals Object, or when the incoming type is Boolean;
        //   • Visit(MethodCallInstruction) (:82-86) and Visit(IndirectMethodCallInstruction) (:106-110) fill an
        //     argument from the parameter type on the same shape, minus the Object disjunct.
        // (Not an exhaustive list of operand writes: Visit(BinaryInstruction)'s Eq/Neq arm (:264-271) assigns an
        // operand *unconditionally* — but only ever PlatformTypes.Boolean, so it cannot rescue a pinned slot to
        // anything else.)
        //
        // The Object disjunct is the crux of the argument. A slot already holding PlatformTypes.Object is still
        // RECOVERABLE: Equals(PlatformTypes.Object) is true, so a later iteration may overwrite it with the real
        // type. UnknownType does not override Equals (Model/Types/Types.cs:112-141), so an Unknown-pinned slot
        // is not null, does not equal Object, and is therefore UNRECOVERABLE at every fill-only site. A non-null
        // PlatformTypes.Unknown handed back from the promotion looks like a definite type, gets stored on a
        // variable, and then permanently blocks those sites from ever filling in the real type — permanently on
        // every non-Boolean path, the Boolean disjuncts being the only escape. null means "not yet known", keeps
        // the slot open, and TypeInferenceAnalysis.SameTypes treats two nulls as unchanged, so the fixed point
        // still terminates. See docs/agent/measurements/typeinference-nullguard-fixes.md.
        Assert.NotSame(PlatformTypes.Unknown, StackTypePromotion.Combine(null, PlatformTypes.Int32));
        Assert.NotSame(PlatformTypes.Unknown, StackTypePromotion.Combine(PlatformTypes.Int32, null));
        Assert.NotSame(PlatformTypes.Unknown, StackTypePromotion.Combine(null, null));
    }

    [Fact]
    public void BinarySignedNumericOperationType_WhenLeftIsNull_ReturnsNull() =>
        Assert.Null(TypeHelper.BinarySignedNumericOperationType(null, PlatformTypes.Int32));

    [Fact]
    public void BinarySignedNumericOperationType_WhenRightIsNull_ReturnsNull() =>
        Assert.Null(TypeHelper.BinarySignedNumericOperationType(PlatformTypes.Int32, null));

    [Fact]
    public void BinarySignedNumericOperationType_WhenBothOperandsAreNull_ReturnsNull() =>
        Assert.Null(TypeHelper.BinarySignedNumericOperationType(null, null));

    [Fact]
    public void BinarySignedNumericOperationType_WhenNeitherOperandIsNull_DelegatesToCombine()
    {
        // Positive control for the guard, and a check that the delegation is actually wired up: the old
        // cascade answered UInt32 here, the promotion answers Int32.
        Assert.Same(PlatformTypes.Int32, TypeHelper.BinarySignedNumericOperationType(PlatformTypes.Byte, PlatformTypes.Byte));
    }
    #endregion

    #region The UnknownType sentinel — Combine returns null, never Unknown, never Object (architect decision 6)
    // Review finding W1, resolved by the architect in the task spec's "Architect decisions" §6.
    //
    // PlatformTypes.Unknown is an UnknownType, NOT an IBasicType, so StackTypePromotion.Classify used to fall
    // through to its "anything outside the basic-type world is O" arm. That made the sentinel behave like an
    // object reference, and the O row of the table then produced two different flavours of wrong answer:
    //
    //   Combine(Unknown, Int32)  -> PlatformTypes.Unknown  (only one side is O, so "keep the O operand")
    //   Combine(Unknown, String) -> PlatformTypes.Object   (both sides O and unequal, so "common root")
    //
    // The second is the worse one: a sentinel laundered into a confident concrete type. Both orders agreed on
    // both answers, which is precisely why the commutativity sweep above could not see this.
    //
    // The fix returns null — and specifically NOT PlatformTypes.Unknown, which is what the reviewer originally
    // proposed and the architect rejected. See the corrected rationale on
    // Combine_WhenAnOperandIsNull_DoesNotReturnPlatformTypesUnknown above: a non-null Unknown looks like a
    // definite type to TypeInferenceAnalysis's fill-only operand back-propagation and permanently pins the
    // wrong answer, whereas null means "not yet known" and leaves the slot open for a later iteration.
    //
    // Every assertion below therefore pins all three facts: the result is null, it is NOT PlatformTypes.Unknown
    // and it is NOT PlatformTypes.Object. The latter two are implied by Assert.Null, and that redundancy is the
    // point — they name the two pre-fix answers, which is what makes these regression tests rather than a
    // restatement of the null contract.

    // Named rather than passed directly so the theory data stays serializable (xUnit can then discover and
    // re-run each case individually); NamedOperand below maps each name back to an IType. Covers the task's
    // required set: Int32, Int64, IntPtr, Float64, String, Object, a pointer type, an array type, and Unknown
    // itself. Single source of truth for both theory-data properties below — add a partner here only.
    private static readonly IReadOnlyList<string> UnknownPartnerNames =
    [
        "Int32",
        "Int64",
        "IntPtr",
        "Float64",
        "String",
        "Object",
        "PointerType(Int32)",
        "ArrayType(Int32)",
        UnknownPartnerName,
    ];

    private const string UnknownPartnerName = "Unknown";

    public static TheoryData<string> UnknownPartners => ToTheoryData(UnknownPartnerNames);

    // Derived, never hand-maintained: the same list minus the sentinel. These are the operands that must still
    // produce a real answer, so they double as the anti-vacuity controls for the theories above them. Filtering
    // rather than duplicating keeps the two lists from drifting when a partner is added.
    public static TheoryData<string> ConcreteUnknownPartners =>
        ToTheoryData(UnknownPartnerNames.Where(name => name != UnknownPartnerName));

    private static TheoryData<string> ToTheoryData(IEnumerable<string> names)
    {
        var data = new TheoryData<string>();

        foreach (var name in names) data.Add(name);

        return data;
    }

    [Theory]
    [MemberData(nameof(UnknownPartners))]
    public void Combine_WhenLeftOperandIsTheUnknownSentinel_ReturnsNullAndNeitherUnknownNorObject(string partnerName)
    {
        var partner = NamedOperand(partnerName);

        var result = StackTypePromotion.Combine(PlatformTypes.Unknown, partner);

        Assert.Null(result);
        Assert.NotSame(PlatformTypes.Unknown, result); // the pre-fix answer when the partner was not a reference type
        Assert.NotSame(PlatformTypes.Object, result);  // the pre-fix answer when it was — the laundering case
    }

    [Theory]
    [MemberData(nameof(UnknownPartners))]
    public void Combine_WhenRightOperandIsTheUnknownSentinel_ReturnsNullAndNeitherUnknownNorObject(string partnerName)
    {
        var partner = NamedOperand(partnerName);

        var result = StackTypePromotion.Combine(partner, PlatformTypes.Unknown);

        Assert.Null(result);
        Assert.NotSame(PlatformTypes.Unknown, result);
        Assert.NotSame(PlatformTypes.Object, result);
    }

    [Theory]
    [MemberData(nameof(ConcreteUnknownPartners))]
    public void Combine_WhenTheSentinelIsReplacedByARealType_ReturnsNonNull(string partnerName)
    {
        // Positive control for both theories above: with the sentinel swapped out for a genuine type these same
        // operands do produce an answer, so the nulls come from the UnknownType guard and not from the operands
        // being unclassifiable or from Combine having become an unconditional null return.
        var partner = NamedOperand(partnerName);

        Assert.NotNull(StackTypePromotion.Combine(PlatformTypes.Object, partner));
        Assert.NotNull(StackTypePromotion.Combine(partner, PlatformTypes.Object));
        Assert.NotNull(StackTypePromotion.Combine(partner, partner));
    }

    [Fact]
    public void Combine_UnknownAndInt32_ReturnsNullInsteadOfPropagatingTheSentinel()
    {
        // The "only one side is O, keep the O operand" arm. Pre-fix this returned PlatformTypes.Unknown itself.
        Assert.Null(StackTypePromotion.Combine(PlatformTypes.Unknown, PlatformTypes.Int32));
        Assert.Null(StackTypePromotion.Combine(PlatformTypes.Int32, PlatformTypes.Unknown));

        // Control: the same arm with a real reference type still keeps that operand.
        Assert.Same(PlatformTypes.String, StackTypePromotion.Combine(PlatformTypes.String, PlatformTypes.Int32));
    }

    [Fact]
    public void Combine_UnknownAndString_ReturnsNullInsteadOfLaunderingTheSentinelIntoObject()
    {
        // The "both sides O and unequal, fall back to the common root" arm — the laundering case. Pre-fix this
        // returned PlatformTypes.Object: a confident concrete type invented out of a sentinel.
        Assert.Null(StackTypePromotion.Combine(PlatformTypes.Unknown, PlatformTypes.String));
        Assert.Null(StackTypePromotion.Combine(PlatformTypes.String, PlatformTypes.Unknown));

        // Control: two genuinely distinct object references still collapse to their common root.
        Assert.Same(PlatformTypes.Object, StackTypePromotion.Combine(PlatformTypes.String, PlatformTypes.Task));
    }

    [Fact]
    public void Combine_UnknownAndUnknown_ReturnsNull()
    {
        // Pre-fix this hit the "both O and equal" arm and returned the sentinel. It is also the case that must
        // stay null-stable: TypeInferenceAnalysis.SameTypes treats two nulls as unchanged, so the fixed point
        // still terminates (see TypeInferenceTerminationRegressionTests).
        var result = StackTypePromotion.Combine(PlatformTypes.Unknown, PlatformTypes.Unknown);

        Assert.Null(result);
        Assert.NotSame(PlatformTypes.Unknown, result);
        Assert.NotSame(PlatformTypes.Object, result);
    }

    [Fact]
    public void Combine_ForEveryOperandPairedWithTheUnknownSentinel_ReturnsNullInBothOrders()
    {
        // The sweep-wide form: the whole 51-operand corpus, not just the nine named partners. Reported as a
        // list so a failure names every offending operand at once instead of stopping at the first.
        var offenders = new List<string>();
        var operandsChecked = 0;

        foreach (var (name, operand) in Operands)
        {
            operandsChecked++;

            var forward = StackTypePromotion.Combine(PlatformTypes.Unknown, operand);
            var backward = StackTypePromotion.Combine(operand, PlatformTypes.Unknown);

            if (forward is not null) offenders.Add($"(PlatformTypes.Unknown, {name}) -> {Describe(forward)}");
            if (backward is not null) offenders.Add($"({name}, PlatformTypes.Unknown) -> {Describe(backward)}");
        }

        Assert.Empty(offenders);
        Assert.Equal(51, operandsChecked); // same pin as the commutativity sweep; this cannot silently shrink either
    }

    [Theory]
    [MemberData(nameof(UnknownPartners))]
    public void BinarySignedNumericOperationType_WhenAnOperandIsTheUnknownSentinel_ReturnsNull(string partnerName)
    {
        // The delegation layer: TypeInferenceAnalysis.cs:246 reaches Combine through here, so the new
        // null-producing path has to survive the wrapper's own guard (which only tests for null, not Unknown).
        var partner = NamedOperand(partnerName);

        Assert.Null(TypeHelper.BinarySignedNumericOperationType(PlatformTypes.Unknown, partner));
        Assert.Null(TypeHelper.BinarySignedNumericOperationType(partner, PlatformTypes.Unknown));
    }

    [Theory]
    [MemberData(nameof(UnknownPartners))]
    public void BinaryNumericOperationType_WhenAnOperandIsTheUnknownSentinelAndUnsigned_ReturnsNull(string partnerName)
    {
        // unsigned: true routes the result through TypeHelper.UnsignedEquivalent, whose own null guard
        // (TypeHelper.cs:572) propagates rather than dereferences. Without it this path would NRE instead of
        // returning "not yet known".
        var partner = NamedOperand(partnerName);

        Assert.Null(TypeHelper.BinaryNumericOperationType(PlatformTypes.Unknown, partner, unsigned: true));
        Assert.Null(TypeHelper.BinaryNumericOperationType(partner, PlatformTypes.Unknown, unsigned: true));
    }

    [Theory]
    [MemberData(nameof(UnknownPartners))]
    public void BinaryNumericOperationType_WhenAnOperandIsTheUnknownSentinelAndSigned_ReturnsNull(string partnerName)
    {
        var partner = NamedOperand(partnerName);

        Assert.Null(TypeHelper.BinaryNumericOperationType(PlatformTypes.Unknown, partner, unsigned: false));
        Assert.Null(TypeHelper.BinaryNumericOperationType(partner, PlatformTypes.Unknown, unsigned: false));
    }

    [Theory]
    [MemberData(nameof(UnknownPartners))]
    public void BinaryLogicalOperationType_WhenAnOperandIsTheUnknownSentinel_ReturnsNull(string partnerName)
    {
        // The and/or/xor path (TypeInferenceAnalysis.cs:252). Its boolean/boolean short-circuit cannot fire when
        // one side is the sentinel, so it falls through to the promotion and must inherit the same null.
        var partner = NamedOperand(partnerName);

        Assert.Null(TypeHelper.BinaryLogicalOperationType(PlatformTypes.Unknown, partner));
        Assert.Null(TypeHelper.BinaryLogicalOperationType(partner, PlatformTypes.Unknown));
    }

    [Fact]
    public void BinaryNumericOperationType_WhenNeitherOperandIsTheUnknownSentinel_StillAppliesUnsignedEquivalent()
    {
        // Positive control for the two BinaryNumericOperationType theories: the unsigned re-application is
        // genuinely reached and produces a non-null answer, so their nulls are the sentinel guard and not a
        // wrapper that has quietly started returning null for everything.
        Assert.Same(PlatformTypes.UInt32, TypeHelper.BinaryNumericOperationType(PlatformTypes.Int32, PlatformTypes.Int32, unsigned: true));
        Assert.Same(PlatformTypes.UInt64, TypeHelper.BinaryNumericOperationType(PlatformTypes.Int64, PlatformTypes.Int32, unsigned: true));
        Assert.Same(PlatformTypes.UIntPtr, TypeHelper.BinaryNumericOperationType(PlatformTypes.IntPtr, PlatformTypes.Int32, unsigned: true));
        Assert.Same(PlatformTypes.Int32, TypeHelper.BinaryNumericOperationType(PlatformTypes.Int32, PlatformTypes.Int32, unsigned: false));
    }

    [Fact]
    public void BinarySignedNumericOperationTypeAndBinaryLogicalOperationType_WhenNeitherOperandIsTheUnknownSentinel_ReturnNonNull()
    {
        // Positive control for the BinarySignedNumericOperationType and BinaryLogicalOperationType theories.
        Assert.Same(PlatformTypes.Int32, TypeHelper.BinarySignedNumericOperationType(PlatformTypes.Int32, PlatformTypes.Int32));
        Assert.Same(PlatformTypes.Boolean, TypeHelper.BinaryLogicalOperationType(PlatformTypes.Boolean, PlatformTypes.Boolean));
        Assert.Same(PlatformTypes.Int32, TypeHelper.BinaryLogicalOperationType(PlatformTypes.Int32, PlatformTypes.Int32));
    }
    #endregion

    #region Totality on degenerate and hostile shapes (criterion 3)
    [Fact]
    public void Combine_WhenAnOperandIsAnUnboundBasicTypeReference_ClassifiesItAsObjectInsteadOfThrowing()
    {
        // BasicType.ResolvedType throws InvalidOperationException for a reference that was never bound to a
        // host (see the BasicType constructor in Types.cs); TypeHelper.StackType reads it to look through
        // enums. Classify guards that, so an operand it cannot classify is simply O.
        var unbound = MakeUnboundValueType();

        // The hazard is real, not hypothetical.
        Assert.Throws<InvalidOperationException>(() => { _ = unbound.ResolvedType; });
        Assert.Same(unbound, StackTypePromotion.Combine(unbound, PlatformTypes.Int32));
        Assert.Same(unbound, StackTypePromotion.Combine(PlatformTypes.Int32, unbound));
    }

    [Fact]
    public void Combine_WhenAnOperandIsABasicTypeWithNoContainingAssembly_DoesNotThrowFromEquals()
    {
        // Named/namespaced to collide with PlatformTypes.Int32 so BasicType.Equals gets past the name, arity
        // and namespace checks and dereferences its null ContainingAssembly — a partially built type, which
        // hostile or truncated metadata can produce.
        var bare = MakeUnboundBareType();

        Assert.NotNull(StackTypePromotion.Combine(bare, PlatformTypes.Int32));
        Assert.NotNull(StackTypePromotion.Combine(PlatformTypes.Int32, bare));
        Assert.NotNull(StackTypePromotion.Combine(bare, bare));
    }

    [Fact]
    public void Combine_WhenAnEnumHasNoUnderlyingType_ClassifiesItAsObjectInsteadOfThrowing()
    {
        var enumeration = MakeEnum("EnumWithNoUnderlyingType", null);

        Assert.Same(enumeration, StackTypePromotion.Combine(enumeration, PlatformTypes.Int32));
        Assert.Same(enumeration, StackTypePromotion.Combine(PlatformTypes.Int32, enumeration));
    }

    [Fact]
    public void Combine_WhenAnEnumUnderlyingTypeIsAnotherEnum_FollowsTheChainToInt32()
    {
        // E1 : E2 : int32. Chains are safe; a SELF-referential enum is not (uncatchable stack overflow — see
        // the class comment) and is deliberately not constructed anywhere in this file.
        var chained = MakeEnumChain();

        AssertCombinesToSameInstance(PlatformTypes.Int32, chained, PlatformTypes.Int32);
        AssertCombinesToSameInstance(PlatformTypes.Int32, chained, chained);
    }

    [Fact]
    public void Combine_WhenAnOperandIsAGenericParameter_ClassifiesItAsObjectInsteadOfThrowing()
    {
        var genericParameter = new GenericParameterReference(GenericParameterKind.Type, 0);

        Assert.Same(genericParameter, StackTypePromotion.Combine(genericParameter, PlatformTypes.Int32));
        Assert.Same(genericParameter, StackTypePromotion.Combine(PlatformTypes.Int32, genericParameter));
    }

    [Fact]
    public void Combine_WhenBothOperandsAreNestedStructuralTypes_ReturnsATypeInsteadOfThrowing()
    {
        var pointerToPointer = new PointerType(new PointerType(PlatformTypes.Int32));
        var arrayOfArray = new ArrayType(new ArrayType(PlatformTypes.Int32));
        var functionPointer = new FunctionPointerType(PlatformTypes.Void);

        // All three are IReferenceType, so all three are &: & x & -> native int (Table III.2).
        AssertCombinesToSameInstance(PlatformTypes.IntPtr, pointerToPointer, arrayOfArray);
        AssertCombinesToSameInstance(PlatformTypes.IntPtr, arrayOfArray, functionPointer);
        AssertCombinesToSameInstance(PlatformTypes.IntPtr, functionPointer, pointerToPointer);
    }
    #endregion

    #region Singleton identity (criterion 8)
    // NullGuardRegressionTests asserts with Assert.Same, so the promotion must return the static instances
    // rather than freshly constructed structurally equal BasicTypes.
    [Fact]
    public void Combine_ForEachIntegerAndFloatResult_ReturnsThePlatformTypesSingleton()
    {
        Assert.Same(PlatformTypes.Int32, StackTypePromotion.Combine(PlatformTypes.Int16, PlatformTypes.UInt8));
        Assert.Same(PlatformTypes.Int64, StackTypePromotion.Combine(PlatformTypes.Int64, PlatformTypes.UInt64));
        Assert.Same(PlatformTypes.IntPtr, StackTypePromotion.Combine(PlatformTypes.UIntPtr, PlatformTypes.IntPtr));
        Assert.Same(PlatformTypes.Double, StackTypePromotion.Combine(PlatformTypes.Single, PlatformTypes.Single));
    }
    #endregion

    #region Helpers
    // Resolves the serializable theory-data names used by the UnknownType sentinel region. Throws on an
    // unknown name rather than returning null, so a typo in the TheoryData surfaces as a failure instead of
    // quietly turning the case into a re-test of the (null, X) contract.
    private static IType NamedOperand(string name) => name switch
    {
        "Int32" => PlatformTypes.Int32,
        "Int64" => PlatformTypes.Int64,
        "IntPtr" => PlatformTypes.IntPtr,
        "Float64" => PlatformTypes.Float64,
        "String" => PlatformTypes.String,
        "Object" => PlatformTypes.Object,
        "PointerType(Int32)" => new PointerType(PlatformTypes.Int32),
        "ArrayType(Int32)" => new ArrayType(PlatformTypes.Int32),
        "Unknown" => PlatformTypes.Unknown,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unrecognized theory operand name."),
    };

    private static void AssertCombinesToSameInstance(IType expected, IType left, IType right)
    {
        Assert.Same(expected, StackTypePromotion.Combine(left, right));
        Assert.Same(expected, StackTypePromotion.Combine(right, left));
    }

    private static bool SameResult(IType? left, IType? right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;

        try
        {
            // Both directions: IType implementations here have partial Equals, and an asymmetric Equals must
            // not be allowed to mask an asymmetric Combine.
            return left.Equals(right) && right.Equals(left);
        }
        catch (Exception)
        {
            // A throwing Equals means "cannot prove these are the same answer" - report the pair rather than
            // silently passing it.
            return false;
        }
    }

    private static string Describe(IType? type)
    {
        if (type is null) return "null";

        try
        {
            return $"{type.GetType().Name}({type})";
        }
        catch (Exception)
        {
            return type.GetType().Name;
        }
    }

    private static EnumDefinition MakeEnum(string name, IBasicType? underlyingType) =>
        new(name) { UnderlayingType = underlyingType! };

    // E1 : E2 : int32. Never self-referential - see the class comment.
    private static EnumDefinition MakeEnumChain() =>
        MakeEnum("OuterChainedEnum", MakeEnum("InnerChainedEnum", PlatformTypes.Int32));

    private static BasicType MakeUnboundValueType() =>
        new("UnboundValueType", TypeKind.ValueType)
        {
            ContainingAssembly = new AssemblyReference("SomeThirdPartyAssembly"),
            ContainingNamespace = "SomeNamespace",
        };

    private static BasicType MakeUnboundReferenceType() =>
        new("UnboundReferenceType", TypeKind.ReferenceType)
        {
            ContainingAssembly = new AssemblyReference("SomeThirdPartyAssembly"),
            ContainingNamespace = "SomeNamespace",
        };

    // No ContainingAssembly at all, and deliberately shaped like System.Int32 so BasicType.Equals reaches the
    // null dereference instead of short-circuiting on the name.
    private static BasicType MakeUnboundBareType() =>
        new("Int32") { ContainingNamespace = "System" };
    #endregion
}
