namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System.Collections.Generic;
using System.Diagnostics;

/// <summary>
/// Call sites whose <b>declaring type is a generic instance</b>, isolated so a test can pin the rendering
/// contract of <c>AssemblyAnalyzer.TypeName</c> — the string the hard-coded capability <c>Catalog</c>
/// prefix-matches, which is a different seam from <c>CanonicalName.ClassificationKey</c> and which nothing
/// pinned before (<c>docs/agent/measurements/ilspy-provider-spike.md</c> §2.1 and §2.10 items 1–2).
/// <para>
/// Measured over 604,115 entities, that renderer emits generic <em>arguments</em> inline, generic
/// <em>parameters</em> by metadata name, <c>", "</c> between arguments and <b>no</b> <c>`N</c> arity suffix.
/// The consequence these shapes exist to prove is that a catalog prefix can never reach inside a
/// <c>&lt;…&gt;</c> argument list: <c>System.Collections.Generic.List&lt;System.Diagnostics.Process&gt;</c>
/// starts with <c>System.Collections</c>, not with <c>System.Diagnostics.Process</c>, so holding a
/// <see cref="Process"/> in a list is not process execution.
/// </para>
/// Analyzed statically, never executed.
/// </summary>
public static class GenericCapabilityOps
{
    #region Methods
    /// <summary>
    /// A <c>System.Collections.Generic.List&lt;System.Diagnostics.Process&gt;</c> constructed and added to — two
    /// call sites whose declaring type mentions a catalogued type only <em>inside</em> its argument list — plus a
    /// real <see cref="Process.Start(string)"/> as the <b>positive control</b> in the same body, so a test
    /// asserting "exactly one finding here" cannot pass because the body went unscanned.
    /// </summary>
    public static int HoldsProcessesAndStartsOne(string fileName)
    {
        var processes = new List<Process>();
        processes.Add(Process.Start(fileName));
        return processes.Count;
    }

    /// <summary>
    /// The same point with the catalogued type in the <b>second</b> argument position —
    /// <c>System.Collections.Generic.Dictionary&lt;System.String, System.Diagnostics.Process&gt;</c> — which is
    /// also the multi-argument shape that pins the <c>", "</c> delimiter. No positive control here: the
    /// assertion is that this whole method contributes nothing.
    /// </summary>
    public static int MapsProcessesByName(string name, Process process)
    {
        var byName = new Dictionary<string, Process>();
        byName.Add(name, process);
        return byName.Count;
    }
    #endregion
}

/// <summary>
/// The <b>open</b> generic counterpart: call sites inside a generic type, where the declaring type's generic
/// arguments are the enclosing type's and method's own generic <em>parameters</em>. This is the shape the spike
/// measured 14,645 times (<c>Silvergun.Result&lt;T&gt;</c>, <c>System.Func&lt;T, U&gt;</c>) — CCI renders each
/// parameter by its metadata name, never positionally. Analyzed statically, never executed.
/// </summary>
/// <typeparam name="T">Rendered as <c>T</c> wherever it appears as a generic argument.</typeparam>
public sealed class GenericCallSiteHolder<T>
{
    #region Methods
    /// <summary>Call sites whose declaring type is <c>System.Collections.Generic.List&lt;T&gt;</c>.</summary>
    public int CollectsOne(T item)
    {
        var items = new List<T>();
        items.Add(item);
        return items.Count;
    }

    /// <summary>
    /// Call sites whose declaring type is <c>System.Collections.Generic.Dictionary&lt;T, TValue&gt;</c> — a type
    /// parameter and a <em>method</em> type parameter side by side, both by name, joined by <c>", "</c>.
    /// </summary>
    /// <typeparam name="TValue">Rendered as <c>TValue</c>.</typeparam>
    public int PairsWith<TValue>(T key, TValue value)
    {
        var pairs = new Dictionary<T, TValue>();
        pairs.Add(key, value);
        return pairs.Count;
    }
    #endregion
}
