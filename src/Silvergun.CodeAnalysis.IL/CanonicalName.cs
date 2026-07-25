namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// The single, pure formatter for type and method names — no I/O, no object model, no assembly loading, so
/// it is exhaustively unit-testable. Both object models Silvergun reads (raw CCI via <see cref="CciNames"/>
/// and Analysis.Net's <c>Model</c> via <see cref="ModelNames"/>) funnel their identities through here, which
/// is what guarantees the two layers render the same method to byte-identical strings.
/// <para>
/// Two distinct keys are produced, and they must not be conflated (ADR 0019):
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b><see cref="ClassificationKey(MethodIdentity)"/></b> — <c>Namespace.Outer.Inner.MethodName</c>, all
/// generic decoration stripped. Human-writable and prefix-matchable, so capability-catalog entries such as
/// <c>System.IO.File</c> and <c>System.Net.Sockets.</c> keep working. Non-unique by design: overloads share it.
/// </description></item>
/// <item><description>
/// <b><see cref="NodeId(MethodIdentity)"/></b> — the classification key plus generic arity and the parameter
/// signature, e.g. <c>Namespace.Outer.Inner`1.Method`1(System.String,System.Int32[])</c>. Unique enough to be
/// a graph node id (<c>Type.Method</c> alone collides on 10-17% of methods).
/// </description></item>
/// </list>
/// <para>Rendering rules:</para>
/// <list type="bullet">
/// <item><description>Nesting separator is <c>.</c>, in <b>outer to inner</b> order. Chosen over <c>+</c> so
/// map entries stay human-writable; the accepted, documented consequence is that a namespace/nested-type
/// name collision is theoretically possible and treated as negligible.</description></item>
/// <item><description>A <em>declared</em> type — a classification key, or the declaring type of a node id —
/// is normalized to its <em>definition</em>: generic arguments are stripped entirely, and arity appears as
/// <c>`N</c> in the node id only.</description></item>
/// <item><description>A type <em>inside a node id's signature</em> keeps its generic arguments
/// (<see cref="GenericInstance"/>): <c>System.Nullable`1&lt;System.Int32&gt;</c>, nested recursively as
/// <c>…Dictionary`2&lt;System.String,…List`1&lt;System.Int32&gt;&gt;</c>. Stripping them there merged
/// overloads that differ only by a generic argument (measured: up to 5.3% of a large assembly's methods),
/// which defeats the whole purpose of a node id. Classification keys are unaffected.</description></item>
/// <item><description>Generic parameters inside a signature are <b>positional</b> — <c>!0</c> for a type
/// parameter, <c>!!0</c> for a method parameter (ECMA-335/ILDasm convention) — because the Analysis.Net
/// layer does not preserve their names.</description></item>
/// <item><description>Method names are verbatim from metadata; arrays render <c>T[]</c> (rank <i>n</i> as
/// <c>T[,,]</c>), pointers <c>T*</c>, by-ref <c>T&amp;</c>.</description></item>
/// <item><description>Any name that is null, empty or unreadable renders as <see cref="UnknownPart"/> —
/// never as an empty string that could collide with a real name.</description></item>
/// <item><description>A nesting chain longer than an adapter's depth bound degrades to
/// <see cref="Truncated"/> — the same visible marker on both layers, never a silently shortened name.
/// </description></item>
/// </list>
/// <para>
/// Return types are deliberately not part of either key: two methods differing only by return type (legal in
/// CIL, not in C#) share a node id.
/// </para>
/// Never throws.
/// </summary>
public static class CanonicalName
{
    #region Methods
    /// <summary>
    /// The non-unique, prefix-matchable key of a type: <c>Namespace.Outer.Inner</c> with all generic
    /// decoration stripped (the global namespace yields just the nesting chain).
    /// </summary>
    public static string ClassificationKey(TypeIdentity type) =>
        // An absent namespace (the global one) contributes nothing; a present but unusable one - a
        // whitespace-only namespace is legal in hostile metadata - goes through the same guard as every other
        // name part, so it can never render as invisible padding around the separator.
        string.IsNullOrEmpty(type.Namespace) ? Nesting(type) : $"{Part(type.Namespace)}{NestingSeparator}{Nesting(type)}";

    /// <summary>
    /// The unique rendering of a type: <see cref="ClassificationKey(TypeIdentity)"/> plus the CLR arity
    /// suffix <c>`N</c> when the type (including its containing types) has generic parameters.
    /// </summary>
    public static string NodeId(TypeIdentity type) => ClassificationKey(type) + Arity(type.GenericArity);

    /// <summary>
    /// The non-unique, prefix-matchable key of a method: <c>Namespace.Outer.Inner.MethodName</c>. All
    /// overloads of a method share this key — that is correct for capability classification.
    /// </summary>
    public static string ClassificationKey(MethodIdentity method) =>
        $"{ClassificationKey(method.DeclaringType)}{NestingSeparator}{Part(method.MethodName)}";

    /// <summary>
    /// The unique identity of a method: the declaring type's <see cref="NodeId(TypeIdentity)"/>, the method
    /// name, its arity suffix and its parameter signature — e.g.
    /// <c>Namespace.Outer.Inner.Method`1(System.String,System.Int32[])</c>. Overloads differ here.
    /// </summary>
    public static string NodeId(MethodIdentity method) =>
        $"{NodeId(method.DeclaringType)}{NestingSeparator}{Part(method.MethodName)}{Arity(method.GenericArity)}{Signature(method.ParameterTypes)}";

    /// <summary>
    /// The deliberately degraded identity of a type whose nesting chain was longer than an adapter's depth
    /// bound: the partial chain that was read, with <see cref="UnknownPart"/> prepended as its outermost
    /// element and no namespace at all — a truncated walk never reaches the outermost type, so no namespace
    /// was ever legitimately read.
    /// <para>
    /// Both adapters must call this rather than invent their own degradation, because the depth bound is
    /// attacker-controlled: a chain deep enough to hit it would otherwise render differently on each side, and
    /// a silently namespace-less key stops matching a namespace-rooted catalog entry — an under-approximation,
    /// the unsafe direction for a scanner. Marking rather than collapsing to <see cref="TypeIdentity.Unknown"/>
    /// keeps the inner chain's discriminating power while being unmistakably not a real type, which is what our
    /// threat model demands: "could not analyze" must never look like a clean result. Arity is deliberately not
    /// a parameter — the two layers count it incompatibly on a partial chain (CCI sums the links it walked,
    /// <c>Model</c> reports the whole chain's cumulative count), so it is dropped rather than allowed to diverge.
    /// </para>
    /// </summary>
    public static TypeIdentity Truncated(IEnumerable<string>? chain) =>
        new(string.Empty, [UnknownPart, .. chain ?? []], 0);

    /// <summary>
    /// The dotted rendering of a namespace from its parts, outermost first; the empty string for the global
    /// namespace (no parts). Each part is guarded, so an unusable one renders as <see cref="UnknownPart"/>.
    /// </summary>
    public static string Namespace(IEnumerable<string>? parts) =>
        string.Join(NestingSeparator, (parts ?? []).Select(Part));

    /// <summary>
    /// A generic <em>instantiation</em> as it appears inside a node id's signature: the definition's node id
    /// followed by its arguments in angle brackets — <c>System.Nullable`1&lt;System.Int32&gt;</c>. Arguments
    /// are themselves rendered by this formatter, so nesting is recursive:
    /// <c>…Dictionary`2&lt;System.String,…List`1&lt;System.Int32&gt;&gt;</c>. With no arguments the
    /// definition is returned unchanged, so a non-generic type never grows an empty <c>&lt;&gt;</c>.
    /// </summary>
    public static string GenericInstance(string? definition, IEnumerable<string>? arguments) =>
        (arguments ?? []).Select(Part).ToArray() is { Length: > 0 } rendered
            ? $"{Part(definition)}{ArgumentsOpen}{string.Join(ParameterSeparator, rendered)}{ArgumentsClose}"
            : Part(definition);

    /// <summary>A parenthesized, comma-separated parameter list (no spaces); <c>()</c> when empty or null.</summary>
    public static string Signature(IEnumerable<string>? parameterTypes) =>
        $"({string.Join(ParameterSeparator, (parameterTypes ?? []).Select(Part))})";

    /// <summary>
    /// An array of <paramref name="elementType"/>: <c>T[]</c> for a vector, <c>T[,]</c>, <c>T[,,]</c>… for
    /// higher ranks. Ranks below 1 or absurdly large are clamped.
    /// </summary>
    public static string ArrayOf(string? elementType, int rank = 1) =>
        $"{Part(elementType)}[{new string(ParameterSeparator, Math.Clamp(rank, 1, MaxRank) - 1)}]";

    /// <summary>An unmanaged pointer to <paramref name="targetType"/>: <c>T*</c>.</summary>
    public static string PointerTo(string? targetType) => Part(targetType) + "*";

    /// <summary>A managed (by-ref) pointer to <paramref name="targetType"/>: <c>T&amp;</c>.</summary>
    public static string ByRefTo(string? targetType) => Part(targetType) + "&";

    /// <summary>The positional rendering of a type generic parameter: <c>!0</c>, <c>!1</c>…</summary>
    public static string TypeGenericParameter(int index) => "!" + Math.Max(0, index);

    /// <summary>The positional rendering of a method generic parameter: <c>!!0</c>, <c>!!1</c>…</summary>
    public static string MethodGenericParameter(int index) => "!!" + Math.Max(0, index);

    /// <summary>A function-pointer type: <c>fnptr:Ret(P1,P2)</c>.</summary>
    public static string FunctionPointer(string? returnType, IEnumerable<string>? parameterTypes) =>
        $"fnptr:{Part(returnType)}{Signature(parameterTypes)}";

    // The nesting chain, outer -> inner, dot separated; an absent chain degrades to the placeholder rather
    // than to an empty string.
    private static string Nesting(TypeIdentity type) =>
        type.NestingChain is not { Count: > 0 } chain ? UnknownPart : string.Join(NestingSeparator, chain.Select(Part));

    // Any unusable name part becomes the documented placeholder.
    private static string Part(string? name) => string.IsNullOrWhiteSpace(name) ? UnknownPart : name;

    // The CLR generic-arity suffix; nothing at all for non-generic (or nonsensical) arities.
    private static string Arity(int arity) => arity > 0 ? "`" + arity : string.Empty;
    #endregion

    #region Fields
    /// <summary>
    /// Rendered in place of any name that is null, empty or unreadable. Deliberately not an empty string, and
    /// deliberately bracketed so it cannot be produced by legal C# or by the compiler's own name mangling.
    /// </summary>
    public const string UnknownPart = "<unknown>";

    private const char NestingSeparator = '.';
    private const char ParameterSeparator = ',';
    private const char ArgumentsOpen = '<';
    private const char ArgumentsClose = '>';
    private const int MaxRank = 32;
    #endregion
}
