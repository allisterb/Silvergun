namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

/// <summary>
/// Extracts a neutral <see cref="MethodIdentity"/>/<see cref="TypeIdentity"/> from <b>raw CCI</b>
/// (<see cref="IMethodReference"/>/<see cref="ITypeReference"/>) — the object model
/// <see cref="AssemblyAnalyzer"/> and the scan-layer analyses read. Its counterpart on the Analysis.Net
/// <c>Model</c> side is <see cref="ModelNames"/>; the two must produce identical
/// <see cref="CanonicalName"/> strings for the same method.
/// <para>
/// Where CCI and <c>Model</c> disagree structurally, this adapter follows <c>Model</c>'s (lossier) shape so
/// the layers can agree, because <c>Model</c> cannot recover the information:
/// </para>
/// <list type="bullet">
/// <item><description>A nested type's generic arity is the sum over its whole nesting chain, and a type
/// generic parameter's index is re-based by the arity of its defining type's containing types — so
/// <c>Outer&lt;T&gt;.Inner&lt;U&gt;</c> has arity 2 with parameters <c>!0</c> and <c>!1</c>. This mirrors
/// <c>CCIProvider.TypeExtractor</c>, which flattens both.</description></item>
/// <item><description>Generic type/method instantiations are normalized to their definition, and the arity
/// of a generic method instance is taken from its argument count (CCI reports 0).</description></item>
/// <item><description>In signature position a generic type instance keeps its arguments, accumulated over the
/// nesting chain exactly as <c>Model</c>'s <c>BasicType.GenericArguments</c> is — see
/// <see cref="CanonicalName.GenericInstance"/>.</description></item>
/// </list>
/// Never throws: a null, unresolvable or malformed piece degrades to <see cref="CanonicalName.UnknownPart"/>,
/// and every walk is depth-limited so a hostile, deeply nested or cyclic reference cannot overflow the stack —
/// a nesting chain that exceeds the bound degrades to <see cref="CanonicalName.Truncated"/>, the same visibly
/// marked identity <see cref="ModelNames"/> produces for it.
/// </summary>
public static class CciNames
{
    #region Methods
    /// <summary>
    /// The identity of <paramref name="method"/> — declaring type, verbatim metadata name, generic arity and
    /// rendered parameter types. Accepts method definitions too (<c>IMethodDefinition : IMethodReference</c>).
    /// Each part is read independently, so one unreadable part does not discard the rest.
    /// </summary>
    public static MethodIdentity Of(IMethodReference? method) =>
        method is null
            ? MethodIdentity.Unknown
            : new MethodIdentity(
                Guard(() => Of(method.ContainingType), TypeIdentity.Unknown),
                Guard(() => method.Name?.Value, null) ?? CanonicalName.UnknownPart,
                Guard(() => MethodArity(method), 0),
                Guard(() => ParameterNames(method), []));

    /// <summary>
    /// The identity of <paramref name="type"/>: containing namespace of the outermost type, the outer-to-inner
    /// nesting chain of bare metadata names, and the total generic arity. Generic instantiations, specialized
    /// nested types and custom-modified types are normalized to their definition.
    /// </summary>
    public static TypeIdentity Of(ITypeReference? type) => Guard(() => Walk(type), TypeIdentity.Unknown);

    /// <summary>
    /// Renders <paramref name="type"/> as it appears in a signature: arrays <c>T[]</c>, pointers <c>T*</c>,
    /// by-ref <c>T&amp;</c>, generic parameters positionally (<c>!0</c>/<c>!!0</c>), and any named type as its
    /// <see cref="CanonicalName.NodeId(TypeIdentity)"/>.
    /// </summary>
    public static string TypeName(ITypeReference? type) => Guard(() => TypeName(type, 0), CanonicalName.UnknownPart);

    // Walks the nesting chain outward, accumulating names (outer -> inner) and arity, and takes the namespace
    // from the outermost type. Depth-limited; an unnamed link ends the walk. Hitting the bound with links still
    // to walk degrades to CanonicalName.Truncated - the namespace lives on the outermost type, so a truncated
    // walk has none, and only an explicit shared marker keeps the two layers rendering such a chain alike.
    private static TypeIdentity Walk(ITypeReference? type)
    {
        var chain = new List<string>();
        var space = string.Empty;
        var arity = 0;
        var current = Definition(type);

        for (var depth = 0; current is INamedTypeReference named && depth < MaxDepth; depth++)
        {
            chain.Insert(0, named.Name?.Value ?? CanonicalName.UnknownPart);
            arity += named.GenericParameterCount;

            if (named is INestedTypeReference nested)
            {
                current = Definition(nested.ContainingType);
            }
            else
            {
                space = named is INamespaceTypeReference global ? Namespace(global.ContainingUnitNamespace) : string.Empty;
                current = null;
            }
        }

        // Any leftover is truncation, not just a named one: Definition can exhaust its own depth bound on a
        // single link and hand back an unnamed wrapper, which is just as much an unwalked remainder — and the
        // namespace lives on the outermost type, so either way what is left is a shortened, namespace-less
        // chain that must announce itself. An empty chain still lands on TypeIdentity.Unknown, since
        // Truncated([]) is exactly that identity.
        return current is not null ? CanonicalName.Truncated(chain)
            : chain.Count == 0 ? TypeIdentity.Unknown
            : new TypeIdentity(space, chain, arity);
    }

    // The generic definition behind an instantiated, specialized or custom-modified type reference.
    private static ITypeReference? Definition(ITypeReference? type)
    {
        for (var depth = 0; depth < MaxDepth; depth++)
        {
            if (type is IGenericTypeInstanceReference instance) type = instance.GenericType;
            else if (type is ISpecializedNestedTypeReference specialized) type = specialized.UnspecializedVersion;
            else if (type is IModifiedTypeReference modified) type = modified.UnmodifiedType;
            else break;
        }

        return type;
    }

    // Dotted namespace name of a unit namespace, outermost first; empty for the global namespace.
    private static string Namespace(IUnitNamespaceReference? space)
    {
        var parts = new List<string>();

        for (var depth = 0; space is INestedUnitNamespaceReference nested && depth < MaxDepth; depth++)
        {
            parts.Insert(0, nested.Name?.Value ?? CanonicalName.UnknownPart);
            space = nested.ContainingUnitNamespace;
        }

        // The separator itself is the formatter's business: every piece of name decoration lives in
        // CanonicalName, which is what stops the two adapters drifting apart.
        return CanonicalName.Namespace(parts);
    }

    // Arity of the method definition behind the reference: CCI reports 0 for a generic method instance, whose
    // arity is its argument count.
    private static int MethodArity(IMethodReference method) =>
        method.GenericParameterCount > 0 ? method.GenericParameterCount
        : method is IGenericMethodInstanceReference instance ? instance.GenericArguments.Count()
        : 0;

    // Rendered parameter types in declaration order; one unreadable parameter degrades on its own.
    private static IReadOnlyList<string> ParameterNames(IMethodReference method) =>
        method.Parameters.Select(p => Guard(() => ParameterName(p, 0), CanonicalName.UnknownPart)).ToArray();

    // CCI carries by-ref-ness as a flag on the parameter rather than as a managed pointer type.
    private static string ParameterName(IParameterTypeInformation parameter, int depth)
    {
        var name = TypeName(parameter.Type, depth + 1);
        return parameter.IsByReference ? CanonicalName.ByRefTo(name) : name;
    }

    // Case order mirrors CCIProvider.TypeExtractor.ExtractType so both layers classify a reference the same way.
    private static string TypeName(ITypeReference? type, int depth) =>
        type is null || depth > MaxDepth ? CanonicalName.UnknownPart
        : type switch
        {
            IArrayTypeReference array => CanonicalName.ArrayOf(TypeName(array.ElementType, depth + 1), (int)array.Rank),
            // Defensive only, and deliberately asymmetric: TypeExtractor maps a managed pointer to a
            // Model PointerType, so Model would render T*. Unreachable from C# - CCI carries by-ref-ness as a
            // flag on the parameter (see ParameterName), which both layers agree renders T&. Do not "align"
            // this with the Model side without a reachable case proving the two disagree in practice.
            IManagedPointerTypeReference pointer => CanonicalName.ByRefTo(TypeName(pointer.TargetType, depth + 1)),
            IPointerTypeReference pointer => CanonicalName.PointerTo(TypeName(pointer.TargetType, depth + 1)),
            IGenericTypeParameterReference parameter => CanonicalName.TypeGenericParameter(TypeParameterIndex(parameter)),
            IGenericMethodParameterReference parameter => CanonicalName.MethodGenericParameter(parameter.Index),
            IFunctionPointerTypeReference pointer => CanonicalName.FunctionPointer(
                TypeName(pointer.Type, depth + 1),
                pointer.Parameters.Select(p => ParameterName(p, depth + 1))),
            // Defensive only, and deliberately asymmetric: TypeExtractor.ExtractType has no case for a modified
            // type at all, so Model degrades it to <unknown>. Unreachable in the corpus measured - CCIProvider
            // strips custom modifiers before a signature type reaches the Model - so unwrapping to the useful
            // name is kept. Do not mirror Model's degradation here without a reachable disagreement.
            IModifiedTypeReference modified => TypeName(modified.UnmodifiedType, depth + 1),
            // Defensive only, and deliberately asymmetric: ModelNames' default is <unknown>, whereas any
            // remaining CCI reference is a named type and is worth naming. Unreachable divergence - every
            // reference that survives the cases above is an IBasicType on the Model side and takes its named
            // branch, not its default. Do not collapse this to <unknown> to "match" ModelNames.
            _ => CanonicalName.GenericInstance(CanonicalName.NodeId(Of(type)), GenericArguments(type, depth)),
        };

    // Generic arguments are kept in signature position (they are what makes a node id unique), and must be
    // accumulated exactly as CCIProvider.TypeExtractor does on the Model side: ExtractGenericType prepends the
    // containing type's arguments to each instantiation's own, so Outer<int>.Inner<string> reports both. The
    // quirk is faithfully reproduced too: only a link that is itself instantiated contributes, so the
    // non-instantiated Inner of Outer<int>.Inner.Innermost<bool> drops the outer argument on both sides.
    private static IReadOnlyList<string> GenericArguments(ITypeReference? type, int depth) =>
        depth > MaxDepth || type is not IGenericTypeInstanceReference instance
            ? []
            :
            [
                .. GenericArguments((instance.GenericType as INestedTypeReference)?.ContainingType, depth + 1),
                .. instance.GenericArguments.Select(argument => TypeName(argument, depth + 1)),
            ];

    // Type generic parameters are numbered across the whole nesting chain (CCI numbers them per type), so the
    // index is offset by the total arity of the defining type's containing types.
    private static int TypeParameterIndex(IGenericTypeParameterReference parameter) =>
        TotalGenericParameterCount(ContainerOf(parameter.DefiningType)) + parameter.Index;

    private static ITypeReference? ContainerOf(ITypeReference? type) =>
        ((type is IGenericTypeInstanceReference instance ? instance.GenericType : type) as INestedTypeReference)?.ContainingType;

    private static int TotalGenericParameterCount(ITypeReference? type)
    {
        var total = 0;

        for (var depth = 0; type is not null && depth < MaxDepth; depth++)
        {
            if (type is IGenericTypeInstanceReference instance) type = instance.GenericType;
            if (type is INamedTypeReference named) total += named.GenericParameterCount;
            if (type is not INestedTypeReference nested) break;
            type = nested.ContainingType;
        }

        return total;
    }

    // Upholds the never-throws contract: CCI resolves lazily, so any read can fault on a corrupt or hostile
    // module. Failures are silent by design — this runs per call site, and logging would flood.
    private static T Guard<T>(Func<T> read, T fallback)
    {
        try
        {
            return read();
        }
        catch (Exception)
        {
            return fallback;
        }
    }
    #endregion

    #region Fields
    // Bounds every walk over hostile metadata: nesting chains, namespace chains and type decoration are all
    // attacker-controlled, and a stack overflow cannot be caught.
    private const int MaxDepth = 64;
    #endregion
}
