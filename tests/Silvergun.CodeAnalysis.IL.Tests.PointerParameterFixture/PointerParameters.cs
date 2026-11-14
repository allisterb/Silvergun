namespace Silvergun.CodeAnalysis.IL.Tests.PointerParameterFixture;

using System.Runtime.InteropServices;

/// <summary>
/// One method per parameter shape, each with a trivial body, and <see cref="CallsEveryShape"/> calling every one of
/// them so each shape is also seen as a call-site <em>reference</em> (which never carries <c>[Out]</c>).
/// <para>
/// <b>Not by-ref</b> (render <c>T*</c>): <c>[Out] int*</c>, <c>[Out] byte**</c>, <c>[In, Out] int*</c> — CCIProvider gives
/// these <c>MethodParameterKind.Out</c>, which ModelNames used to render <c>T*&amp;</c> (ADR 0025).
/// <b>By-ref</b> (render <c>T&amp;</c>): <c>ref</c>, <c>out</c>, <c>in</c>, <c>ref readonly</c> (the virtual ones also carry
/// a <c>modreq</c>), <c>out byte*</c>, and a <c>ref int</c> inside a function pointer.
/// </para>
/// </summary>
public unsafe class PointerParameters
{
    public static int OutIntPointer([Out] int* p) => p == null ? 0 : 1;

    public static int OutBytePointerPointer([Out] byte** p) => p == null ? 0 : 1;

    public static int InOutIntPointer([In, Out] int* p) => p == null ? 0 : 1;

    public virtual int VirtualOutBytePointerPointer([Out] byte** p) => p == null ? 0 : 1;

    /// <summary>The corpus shape: a bodyless P/Invoke with an <c>[Out] byte**</c>. Never called at run time.</summary>
    [DllImport("silvergun-fixture-no-such-library")]
    public static extern int NativeOutBytePointerPointer([Out] byte** p);

    public static int RefInt(ref int x) => x;

    public static int OutInt(out int x)
    {
        x = 1;
        return 0;
    }

    public static int InInt(in int x) => x;

    public static int RefReadonlyInt(ref readonly int x) => x;

    public virtual int VirtualInInt(in int x) => x;

    public virtual int VirtualRefReadonlyInt(ref readonly int x) => x;

    public static int OutBytePointer(out byte* p)
    {
        p = null;
        return 0;
    }

    public static int FunctionPointerWithRefInt(delegate*<ref int, void> f) => f == null ? 0 : 1;

    public int CallsEveryShape()
    {
        var value = 0;
        byte* bytes = null;
        var ints = &value;
        var pointers = &bytes;

        return OutIntPointer(ints) + OutBytePointerPointer(pointers) + InOutIntPointer(ints)
            + VirtualOutBytePointerPointer(pointers) + NativeOutBytePointerPointer(pointers)
            + RefInt(ref value) + OutInt(out value) + InInt(in value) + RefReadonlyInt(in value)
            + VirtualInInt(in value) + VirtualRefReadonlyInt(in value) + OutBytePointer(out bytes)
            + FunctionPointerWithRefInt(null);
    }
}
