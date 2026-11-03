// Not a mechanism (no ground-truth row, no sink): call-site RESOLUTION shapes for the A1 member index
// (docs/agent/tasks/capslock-mechanism-fixtures-and-a1.md §2.2, "Generic instantiation"). A call through a generic
// type instance carries SUBSTITUTED parameter types, so its node id names no definition and the index must pick the
// one overload whose definition parameters fit. Measured on SixLabors.ImageSharp 4.0.0, whose
// ImageFrameCollection<TPixel> has exactly this pair: AddFrame(TPixel[]) and AddFrame(ImageFrame<TPixel>).
namespace MechanismFixture.Resolution
{
    public sealed class Frame<T>
    {
        public T Item;
    }

    // Same name, same arity, same parameter count: only the parameter SHAPE tells the overloads apart. The
    // definitions render Add(!0[]) and Add(MechanismFixture.Resolution.Frame`1<!0>).
    public sealed class Frames<T>
    {
        public int Add(T[] items) => items.Length;

        public int Add(Frame<T> frame) => frame is null ? 0 : 1;
    }

    public static class Callers
    {
        // Site: Frames`1<System.Int32>.Add(MechanismFixture.Resolution.Frame`1<System.Int32>) - only Add(Frame`1<!0>) fits.
        public static int AddsIntFrame() => new Frames<int>().Add(new Frame<int>());

        // Site: Frames`1<System.Int32>.Add(System.Int32[]) - only Add(!0[]) fits.
        public static int AddsIntArray() => new Frames<int>().Add(new int[1]);

        // Site through the caller's own METHOD type parameter: Add(MechanismFixture.Resolution.Frame`1<!!0>) - the
        // ImageSharp shape. Only Add(Frame`1<!0>) fits.
        public static int AddsGenericFrame<U>() => new Frames<U>().Add(new Frame<U>());

        public static int AddsGenericFrameOfString() => AddsGenericFrame<string>();
    }

    // ---- Wrong-definition shapes (spec §2.5, review 1: C1 and C3) --------------------------------------------------
    // Each site below is through a generic type instantiation, so CCI has SUBSTITUTED the instantiation's arguments
    // into the reference's parameters and Model keeps no unspecialized version. The true definition is known
    // independently from raw CCI (ISpecializedMethodReference.UnspecializedVersion), which is what the parity test in
    // MethodGraphAcceptanceTests checks the graph against. None of these is executed; none has a sink.

    // Set(T1) renders Set(!0), Set(T2) renders Set(!1). Legal C#: only Pair<X,X>.Set would be ambiguous.
    public sealed class Pair<T1, T2>
    {
        public int Set(T1 first) => 1;

        public int Set(T2 second) => 2;
    }

    // A generic TYPE, so inside it X is !0 and Y is !1. Pair<Y, X> swaps them: its T1 is the caller's !1.
    public sealed class Flip<X, Y>
    {
        // Binds Set(T1). The reference renders Pair`2<!1,!0>.Set(!1) - the CALLER's !1 - which is textually the node
        // id of the WRONG definition Set(T2) = Set(!1). Pre-S1 this Exact-matched Set(!1).
        public int BindsFirst(Y y) => new Pair<Y, X>().Set(y);

        // The mirror: binds Set(T2); renders Set(!0), textually the node id of the wrong Set(T1).
        public int BindsSecond(X x) => new Pair<Y, X>().Set(x);
    }

    // M(T) renders M(!0), M(int) renders M(System.Int32). On C<int> both become M(System.Int32): Model has lost which
    // one the IL names, so the honest answer is Ambiguous with both candidates.
    public sealed class Overloads<T>
    {
        public int M(T t) => 1;

        public int M(int i) => 2;
    }

    // `delegate*<T, void>` renders fnptr:System.Void(!0): the generic parameter sits INSIDE the function pointer.
    public sealed unsafe class PointerOverloads<T>
    {
        public int M(delegate*<T, void> callback) => 1;

        public int M(T value) => 2;
    }

    // Nested array ranks around T next to a bare T: the decorated one must be compared in full and not lose to the bare
    // T. Keep the nesting SHALLOW - a 40-rank version drove csc past 4 GB in 15 s (and the compiler server to ~50 GB).
    public sealed class DeepOverloads<T>
    {
        public int M(T[][][] deep) => deep is null ? 0 : 1;

        public int M(T value) => 2;
    }

    public static unsafe class WrongDefinitionCallers
    {
        public static int FlipsFirst() => new Flip<int, string>().BindsFirst("y");

        public static int FlipsSecond() => new Flip<int, string>().BindsSecond(1);

        // Named arguments pick the overload: `t:` exists only on M(T), `i:` only on M(int).
        public static int CallsGenericOverload() => new Overloads<int>().M(t: 1);

        public static int CallsIntOverload() => new Overloads<int>().M(i: 1);

        public static int CallsPointerOverload() => new PointerOverloads<int>().M(&Ignore);

        public static int CallsDeepOverload() => new DeepOverloads<int>().M(new int[1][][]);

        private static void Ignore(int value)
        {
        }
    }

    // ---- Nested generics (spec §2.6, review 2: S2, C-A and W-1) ----------------------------------------------------
    // CCIProvider prepends a containing type's arguments to a nested type's Model GenericArguments only when that link
    // is ITSELF instantiated, so a non-generic link in the chain hides every argument further out: Outer<int>.Nested
    // carries none, Outer4<string>.Mid.Inner<int>.Innermost<bool> carries [int, bool]. The outer arguments are only
    // reachable through ContainingType. Nesting is kept to 4 levels at most (CLAUDE.md / spec §2.5 fixture rule); deeper
    // chains are tested on synthetic Model objects, never compiled.

    // W-1: a NON-generic nested type of a generic type. Nested's definitions render M(!0) and M(System.String).
    public sealed class Outer<T>
    {
        public sealed class Nested
        {
            public int M(T t) => 1;

            public int M(string s) => 2;
        }
    }

    // C-A: generic -> NON-generic -> generic -> generic, four levels. In Innermost`3, T is !0, U is !1, V is !2, so M(T)
    // renders M(!0) and M(string) M(System.String). Through Outer4<string>.Mid.Inner<int>.Innermost<bool> BOTH render
    // M(System.String): Model has lost which one the IL names, and the honest answer is Ambiguous with both.
    public sealed class Outer4<T>
    {
        public sealed class Mid
        {
            public sealed class Inner<U>
            {
                public sealed class Innermost<V>
                {
                    public int M(T t) => 1;

                    public int M(string s) => 2;
                }

                // The lone variant: only M(T), so the one candidate that renders M(System.String) is the definition.
                public sealed class Lone<V>
                {
                    public int M(T t) => 1;
                }
            }
        }
    }

    // A generic TYPE calling through Outer<Y>.Nested: the reference renders Nested.M(!1) - the CALLER's !1 - which names
    // no definition; substituting the recovered argument [!1] into M(!0) renders exactly that.
    public sealed class NestedCaller<X, Y>
    {
        public int BindsThroughNested(Y y) => new Outer<Y>.Nested().M(y);
    }

    public static class NestedCallers
    {
        // Binds Nested.M(T); renders Outer`1.Nested.M(System.Int32), which names no definition.
        public static int CallsNestedGeneric() => new Outer<int>.Nested().M(1);

        // Binds Nested.M(string); renders Outer`1.Nested.M(System.String) - textually the definition's node id, which is
        // how the pre-S2 code (no arguments recovered) resolved it Exact by text alone.
        public static int CallsNestedString() => new Outer<int>.Nested().M("x");

        // Named arguments pick the overload: `t:` exists only on M(T), `s:` only on M(string).
        public static int CallsInnermostGeneric() => new Outer4<string>.Mid.Inner<int>.Innermost<bool>().M(t: "x");

        public static int CallsInnermostString() => new Outer4<string>.Mid.Inner<int>.Innermost<bool>().M(s: "x");

        public static int CallsLone() => new Outer4<string>.Mid.Inner<int>.Lone<bool>().M("x");

        public static int CallsThroughNestedCaller() => new NestedCaller<int, string>().BindsThroughNested("y");
    }
}
