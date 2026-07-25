namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Neutral, model-agnostic description of a type — deliberately free of any CCI or Analysis.Net
/// (<c>Model</c>) type, so the same identity can be produced from either object model (see
/// <see cref="CciNames"/> and <see cref="ModelNames"/>) and rendered by the single formatter
/// <see cref="CanonicalName"/>.
/// </summary>
/// <param name="Namespace">
/// Containing namespace of the <em>outermost</em> type, without a trailing dot; empty for the global
/// namespace.
/// </param>
/// <param name="NestingChain">
/// The type-name chain in <b>outer to inner</b> order (<c>["Outer", "Middle", "Inner"]</c>), each element
/// being the bare metadata name with no generic decoration. Never reversed — the reversal in
/// Analysis.Net's <c>Extensions.GetFullName</c> is precisely the defect this type exists to avoid.
/// </param>
/// <param name="GenericArity">
/// Total number of generic parameters of the type <em>including</em> those of its containing types
/// (so <c>Outer&lt;T&gt;.Inner&lt;U&gt;</c> has arity 2). Rendered only into
/// <see cref="CanonicalName.NodeId(TypeIdentity)"/>, never into a classification key.
/// </param>
public readonly record struct TypeIdentity(
    string Namespace,
    IReadOnlyList<string> NestingChain,
    int GenericArity)
{
    #region Properties
    /// <summary>
    /// The placeholder identity used when a type reference is null, unresolvable or malformed. Renders as
    /// <see cref="CanonicalName.UnknownPart"/> rather than an empty string, so it can never collide with a
    /// real type name.
    /// </summary>
    public static TypeIdentity Unknown { get; } = new(string.Empty, [CanonicalName.UnknownPart], 0);
    #endregion

    #region Methods
    /// <summary>
    /// Structural equality: <see cref="NestingChain"/> is compared element-wise (ordinal), not by reference
    /// as the compiler-generated record equality would.
    /// </summary>
    public bool Equals(TypeIdentity other) =>
        GenericArity == other.GenericArity &&
        string.Equals(Namespace, other.Namespace, StringComparison.Ordinal) &&
        (NestingChain ?? []).SequenceEqual(other.NestingChain ?? [], StringComparer.Ordinal);

    /// <summary>Hash consistent with the element-wise <see cref="Equals(TypeIdentity)"/>.</summary>
    public override int GetHashCode() =>
        (NestingChain ?? []).Aggregate(HashCode.Combine(Namespace, GenericArity), HashCode.Combine);

    /// <summary>The unique <see cref="CanonicalName.NodeId(TypeIdentity)"/> rendering.</summary>
    public override string ToString() => CanonicalName.NodeId(this);
    #endregion
}

/// <summary>
/// Neutral, model-agnostic description of a method — the cross-layer seam both the capability map
/// (ADR 0019) and the CHA call graph (ADR 0020) key on. Produced by <see cref="CciNames.Of(Microsoft.Cci.IMethodReference)"/>
/// from raw CCI and by <see cref="ModelNames.Of(Model.Types.IMethodReference)"/> from Analysis.Net's
/// <c>Model</c>; both must yield byte-identical <see cref="CanonicalName"/> strings for the same method.
/// </summary>
/// <param name="DeclaringType">Identity of the containing type.</param>
/// <param name="MethodName">
/// The method name verbatim from metadata (<c>get_X</c>, <c>.ctor</c>, <c>.cctor</c>, explicit interface
/// implementations and compiler-generated names such as <c>&lt;M&gt;d__0</c> included).
/// </param>
/// <param name="GenericArity">
/// Number of generic parameters of the method itself; a generic method <em>instantiation</em> reports the
/// arity of its definition. Rendered only into <see cref="CanonicalName.NodeId(MethodIdentity)"/>.
/// </param>
/// <param name="ParameterTypes">
/// Already-rendered parameter type strings, in declaration order (see <see cref="CanonicalName"/> for the
/// decoration rules). Rendered only into <see cref="CanonicalName.NodeId(MethodIdentity)"/>.
/// </param>
public readonly record struct MethodIdentity(
    TypeIdentity DeclaringType,
    string MethodName,
    int GenericArity,
    IReadOnlyList<string> ParameterTypes)
{
    #region Properties
    /// <summary>
    /// The placeholder identity used when a method reference is null or wholly unreadable. Its parts render
    /// as <see cref="CanonicalName.UnknownPart"/>, never as empty strings.
    /// </summary>
    public static MethodIdentity Unknown { get; } = new(TypeIdentity.Unknown, CanonicalName.UnknownPart, 0, []);
    #endregion

    #region Methods
    /// <summary>
    /// Structural equality: <see cref="ParameterTypes"/> is compared element-wise (ordinal), not by reference
    /// as the compiler-generated record equality would.
    /// </summary>
    public bool Equals(MethodIdentity other) =>
        GenericArity == other.GenericArity &&
        DeclaringType.Equals(other.DeclaringType) &&
        string.Equals(MethodName, other.MethodName, StringComparison.Ordinal) &&
        (ParameterTypes ?? []).SequenceEqual(other.ParameterTypes ?? [], StringComparer.Ordinal);

    /// <summary>Hash consistent with the element-wise <see cref="Equals(MethodIdentity)"/>.</summary>
    public override int GetHashCode() =>
        (ParameterTypes ?? []).Aggregate(HashCode.Combine(DeclaringType, MethodName, GenericArity), HashCode.Combine);

    /// <summary>The unique <see cref="CanonicalName.NodeId(MethodIdentity)"/> rendering.</summary>
    public override string ToString() => CanonicalName.NodeId(this);
    #endregion
}
