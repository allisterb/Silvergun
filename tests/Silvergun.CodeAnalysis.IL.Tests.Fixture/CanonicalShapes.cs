namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

/// <summary>
/// Marker interface used to force an <b>explicit interface implementation</b> into the fixture
/// assembly — its metadata method name is the fully qualified
/// <c>Silvergun.CodeAnalysis.IL.Tests.Fixture.ICanonicalMarker.Mark</c>, one of the shapes the
/// canonical namer must carry through verbatim.
/// </summary>
public interface ICanonicalMarker
{
    /// <summary>Implemented explicitly by <see cref="CanonicalShapes"/>.</summary>
    void Mark();
}

/// <summary>
/// A generic type carrying the two nested shapes the cross-layer name reconciliation rests on:
/// <c>Outer&lt;T&gt;.Inner&lt;U&gt;</c> (both links instantiated) and
/// <c>Outer&lt;T&gt;.Inner.Innermost&lt;V&gt;</c> (a <em>non-instantiated</em> middle link, which is
/// where CCI and Analysis.Net's <c>Model</c> disagree structurally). Nothing here is ever executed —
/// the types exist only to be read out of metadata.
/// </summary>
/// <typeparam name="T">Outermost type parameter; renders positionally as <c>!0</c>.</typeparam>
public class GenericOuter<T>
{
    #region Methods
    /// <summary>Takes the outer type parameter, so its signature renders <c>(!0)</c>.</summary>
    public int TakesOuter(T outer) => outer == null ? 0 : 1;
    #endregion

    #region Types
    /// <summary>
    /// The generic middle link — <c>GenericOuter&lt;T&gt;.Inner&lt;U&gt;</c>, total arity 2.
    /// </summary>
    /// <typeparam name="U">Renders positionally as <c>!1</c>.</typeparam>
    public class Inner<U>
    {
        /// <summary>Signature renders <c>(!0,!1)</c> — the whole nesting chain is numbered flat.</summary>
        public int TakesBoth(T outer, U inner) => (outer == null ? 0 : 1) + (inner == null ? 0 : 2);
    }

    /// <summary>
    /// The <b>non-generic</b> middle link, whose own nested <see cref="Innermost{V}"/> is the depth-3
    /// generic shape phase 1 measured as fragile.
    /// </summary>
    public class Inner
    {
        /// <summary>A depth-3 nested generic: <c>GenericOuter`1.Inner.Innermost`1</c>, total arity 2.</summary>
        /// <typeparam name="V">Renders positionally as <c>!1</c>.</typeparam>
        public class Innermost<V>
        {
            /// <summary>Signature renders <c>(!0,!1)</c>.</summary>
            public int TakesOuterAndInnermost(T outer, V innermost) => (outer == null ? 0 : 1) + (innermost == null ? 0 : 2);
        }
    }
    #endregion
}

/// <summary>
/// A plain (non-generic) nesting chain at <b>depth 3</b>: <c>NestedRoot.Level2.Level3</c>. The
/// classification key must read outer to inner; the reversal in Analysis.Net's
/// <c>Extensions.GetFullName</c> is exactly the defect this fixture guards against.
/// </summary>
public class NestedRoot
{
    #region Types
    /// <summary>Second level of the plain nesting chain.</summary>
    public class Level2
    {
        #region Types
        /// <summary>Third level of the plain nesting chain.</summary>
        public class Level3
        {
            #region Methods
            /// <summary>A method at nesting depth 3.</summary>
            public int Deep() => 3;
            #endregion
        }
        #endregion
    }
    #endregion
}

/// <summary>
/// A generic type with a <b>generic method</b> — the arity suffixes must appear on both the declaring
/// type (<c>`1</c>) and the method (<c>`1</c>) in a node id, and on neither in a classification key.
/// </summary>
/// <typeparam name="T">The box's element type.</typeparam>
public class GenericBox<T>
{
    #region Methods
    /// <summary>A generic method on a generic type; its signature renders <c>(!0,!!0)</c>.</summary>
    public TOther Convert<TOther>(T value, TOther fallback) => fallback;

    /// <summary>Non-generic method on a generic type; signature <c>(!0)</c>.</summary>
    public bool Holds(T value) => value != null;

    /// <summary>
    /// Parameterless, so every instantiation of <see cref="GenericBox{T}"/> calls a site with the
    /// <em>same</em> node id — the proof that a declaring type's generic arguments are stripped.
    /// </summary>
    public int Size() => 1;
    #endregion
}

/// <summary>
/// The remaining edge shapes the canonical namer has to survive: property and event accessors, an
/// explicit interface implementation, a static constructor, a closure, an <c>async</c> state machine,
/// an iterator, an <b>async local function</b> (<c>&lt;&lt;X&gt;g__Y|0&gt;d</c>), overloads differing
/// only by parameter type (including only by <em>generic argument</em>), <c>out</c>/<c>ref</c>/<c>in</c>
/// parameters, a rank-2 array, a deeply nested generic parameter, and call sites instantiating this
/// assembly's own generic types. Analyzed statically, never executed.
/// </summary>
public class CanonicalShapes : ICanonicalMarker
{
    #region Constructors
    /// <summary>Forces a <c>.cctor</c> into the assembly.</summary>
    static CanonicalShapes() => Seed = 7;

    /// <summary>Forces a <c>.ctor</c> with a parameter.</summary>
    public CanonicalShapes(int value) => Value = value;
    #endregion

    #region Events
    /// <summary>Field-like event: emits <c>add_Changed</c>/<c>remove_Changed</c> accessors.</summary>
    public event EventHandler Changed;
    #endregion

    #region Properties
    /// <summary>Auto-property: emits <c>get_Value</c>/<c>set_Value</c> accessors.</summary>
    public int Value { get; set; }
    #endregion

    #region Methods
    /// <summary>Raises <see cref="Changed"/> so the event is not merely declared.</summary>
    public void RaiseChanged() => Changed?.Invoke(this, EventArgs.Empty);

    /// <summary>Explicit interface implementation — metadata name is namespace-qualified.</summary>
    void ICanonicalMarker.Mark() => Value++;

    /// <summary>Overload one of three differing only by parameter type.</summary>
    public string Describe(int value) => value.ToString();

    /// <summary>Overload two of three differing only by parameter type.</summary>
    public string Describe(string value) => value;

    /// <summary>Overload three of three — a rank-1 array parameter, rendered <c>System.Int32[]</c>.</summary>
    public string Describe(int[] values) => values.Length.ToString();

    /// <summary>
    /// Overload differing from <see cref="Accept(Nullable{bool})"/> only by a <em>generic argument</em>:
    /// the node id must retain <c>&lt;System.Int32&gt;</c> or the two collide.
    /// </summary>
    public int Accept(int? value) => value.HasValue ? 1 : 0;

    /// <summary>The generic-argument twin of <see cref="Accept(Nullable{int})"/>.</summary>
    public int Accept(bool? value) => value.HasValue ? 2 : 0;

    /// <summary><c>out</c>, <c>ref</c> and <c>in</c> parameters — all by-ref in metadata (<c>T&amp;</c>).</summary>
    public bool ByRefParts(int input, out int doubled, ref int accumulator, in int addend)
    {
        doubled = input * 2;
        accumulator += doubled + addend;
        return accumulator > 0;
    }

    /// <summary>A rank-2 array parameter, rendered <c>System.Int32[,]</c>.</summary>
    public int SumMatrix(int[,] matrix) => matrix.Length;

    /// <summary>A deeply nested generic parameter whose arguments must render recursively.</summary>
    public int CountNested(Dictionary<string, List<KeyValuePair<int, string>>> map) => map.Count;

    /// <summary>A closure over <paramref name="addend"/> — emits a <c>&lt;&gt;c__DisplayClass</c> type.</summary>
    public Func<int, int> MakeAdder(int addend) => value => value + addend;

    /// <summary>A cache-free lambda with no captures — emits the <c>&lt;&gt;c</c> singleton type.</summary>
    public Func<int, int> MakeDoubler() => value => value * 2;

    /// <summary>An <c>async</c> state machine — emits a <c>&lt;AddAsync&gt;d__N</c> nested type.</summary>
    public async Task<int> AddAsync(int a, int b)
    {
        await Task.Yield();
        return a + b;
    }

    /// <summary>An iterator — emits a <c>&lt;Counting&gt;d__N</c> nested type.</summary>
    public IEnumerable<int> Counting(int count)
    {
        for (var i = 0; i < count; i++)
        {
            yield return i * 3;
        }
    }

    /// <summary>
    /// An <b>async local function</b> — emits the <c>&lt;&lt;WithAsyncLocalFunction&gt;g__DoubleAsync|N&gt;d</c>
    /// state-machine type that <c>&gt;d__</c> heuristics miss.
    /// </summary>
    public async Task<int> WithAsyncLocalFunction(int seed)
    {
        async Task<int> DoubleAsync(int value)
        {
            await Task.Yield();
            return value * 2;
        }

        return await DoubleAsync(seed);
    }

    /// <summary>Call sites instantiating this assembly's own generic types.</summary>
    public int UsesOwnGenerics()
    {
        var box = new GenericBox<string>();
        var inner = new GenericOuter<int>.Inner<string>();
        var innermost = new GenericOuter<int>.Inner.Innermost<bool>();

        return box.Convert("value", 1) + inner.TakesBoth(1, "two") + innermost.TakesOuterAndInnermost(1, true);
    }

    /// <summary>
    /// Two <em>different</em> instantiations of the same own generic type calling the same parameterless
    /// member: both call sites must land on one node id.
    /// </summary>
    public int UsesTwoInstantiationsOfOwnGeneric() => new GenericBox<string>().Size() + new GenericBox<int>().Size();

    /// <summary>A signature mentioning this assembly's own generic type as a parameter.</summary>
    public bool TakesOwnGeneric(GenericBox<string> box) => box.Holds("value");

    /// <summary>
    /// Nested generic <b>instantiations in signature position</b> — the riskiest piece of the cross-layer
    /// reconciliation, because the CCI adapter has to reproduce <c>CCIProvider.TypeExtractor</c>'s argument
    /// accumulation exactly, quirk included: only a link that is <em>itself instantiated</em> contributes its
    /// arguments. So <c>GenericOuter&lt;int&gt;.Inner&lt;string&gt;</c> carries both arguments, the
    /// non-instantiated middle link of <c>GenericOuter&lt;int&gt;.Inner.Innermost&lt;bool&gt;</c> drops the
    /// outer one, and <c>GenericOuter&lt;int&gt;.Inner</c> carries none at all while still reporting the
    /// chain's cumulative arity. Never executed — the parameters exist only to be read out of metadata.
    /// </summary>
    public int TakesNestedGenericInstantiations(
        GenericOuter<int>.Inner<string> both,
        GenericOuter<int>.Inner.Innermost<bool> innermost,
        GenericOuter<int>.Inner middle) =>
        (both == null ? 0 : 1) + (innermost == null ? 0 : 2) + (middle == null ? 0 : 4);
    #endregion

    #region Fields
    /// <summary>Set by the static constructor.</summary>
    public static readonly int Seed;
    #endregion
}
