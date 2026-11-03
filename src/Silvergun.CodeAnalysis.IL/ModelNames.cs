namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Model.Types;

/// <summary>
/// Extracts a neutral <see cref="MethodIdentity"/>/<see cref="TypeIdentity"/> from <b>Analysis.Net's
/// <c>Model</c></b> (<see cref="IMethodReference"/>/<see cref="IBasicType"/>) — the object model
/// <see cref="AssemblyDisassembler"/> exposes and the CHA call graph (ADR 0020) walks. Its counterpart on the
/// raw CCI side is <see cref="CciNames"/>; the two must produce identical <see cref="CanonicalName"/> strings
/// for the same method.
/// <para>
/// This deliberately does <b>not</b> use <c>IBasicType.GetFullName()</c>: that renders generic parameters as
/// the empty string and <em>reverses</em> the nesting chain at depth 3 or more — exactly the
/// compiler-generated async/iterator/lambda types the call graph depends on.
/// </para>
/// <para>Two <c>Model</c> quirks are compensated for here:</para>
/// <list type="bullet">
/// <item><description><c>CCIProvider</c> maps a by-ref parameter to a <see cref="PointerType"/> and records
/// the by-ref-ness only in <see cref="IMethodParameterReference.Kind"/>, so a non-<see cref="MethodParameterKind.In"/>
/// pointer parameter is unwrapped and rendered <c>T&amp;</c>, matching CCI's by-ref flag.</description></item>
/// <item><description>A type's <c>GenericParameterCount</c> is already cumulative over its nesting chain, so
/// arity is read from the innermost type only and never summed. Its <c>GenericArguments</c> are cumulative only
/// over links that are themselves instantiated; node ids take them as-is in signature position (CciNames
/// reproduces the same accumulation), and only <see cref="TypeArguments"/> walks outward to recover the
/// rest.</description></item>
/// </list>
/// Never throws: a null, unresolvable or malformed piece degrades to <see cref="CanonicalName.UnknownPart"/>,
/// and every walk is depth-limited so a hostile, deeply nested or cyclic reference cannot overflow the stack —
/// a nesting chain that exceeds the bound degrades to <see cref="CanonicalName.Truncated"/>, the same visibly
/// marked identity <see cref="CciNames"/> produces for it.
/// </summary>
public static class ModelNames
{
    #region Methods
    /// <summary>
    /// The identity of <paramref name="method"/> — declaring type, verbatim metadata name, generic arity and
    /// rendered parameter types. Accepts <see cref="MethodDefinition"/> too. Each part is read independently,
    /// so one unreadable part does not discard the rest.
    /// </summary>
    public static MethodIdentity Of(IMethodReference? method) =>
        method is null
            ? MethodIdentity.Unknown
            : new MethodIdentity(
                Guard(() => Of(method.ContainingType), TypeIdentity.Unknown),
                Guard(() => method.Name, null) ?? CanonicalName.UnknownPart,
                Guard(() => MethodArity(method), 0),
                Guard(() => ParameterNames(method, []), []));

    /// <summary>
    /// The identity of <paramref name="type"/>: containing namespace of the outermost type, the outer-to-inner
    /// nesting chain of bare metadata names, and the total generic arity. Generic arguments are ignored, so an
    /// instantiation yields the identity of its definition.
    /// </summary>
    public static TypeIdentity Of(IBasicType? type) => Guard(() => Walk(type), TypeIdentity.Unknown);

    /// <summary>
    /// Renders <paramref name="type"/> as it appears in a signature: arrays <c>T[]</c>, pointers <c>T*</c>,
    /// generic parameters positionally (<c>!0</c>/<c>!!0</c>), and any named type as its
    /// <see cref="CanonicalName.NodeId(TypeIdentity)"/>. By-ref is not visible on a type here — see
    /// <see cref="Of(IMethodReference)"/>, which recovers it from the parameter kind.
    /// </summary>
    public static string TypeName(IType? type) => Guard(() => TypeName(type, 0, []), CanonicalName.UnknownPart);

    /// <summary>
    /// The rendered parameter types of <paramref name="method"/> with every <em>type</em> generic parameter
    /// <c>!n</c> replaced by <paramref name="typeArguments"/>[n] — what a call site through the instantiation
    /// <c>Declaring&lt;typeArguments&gt;</c> names. Method generic parameters (<c>!!n</c>) and positions beyond the
    /// supplied arguments are left positional, and so is everything inside a function pointer type: CCI's
    /// specialization (<c>TypeHelper.SpecializeTypeReference</c>) has no function-pointer case, so a site keeps the
    /// definition's <c>!n</c> there. With no arguments this is exactly the
    /// <see cref="MethodIdentity.ParameterTypes"/> of <see cref="Of(IMethodReference)"/>.
    /// </summary>
    public static IReadOnlyList<string> ParameterTypes(IMethodReference? method, IReadOnlyList<string> typeArguments) =>
        method is null ? [] : Guard(() => ParameterNames(method, typeArguments), []);

    /// <summary>
    /// The rendered generic arguments of <paramref name="type"/>, cumulative over its nesting chain in signature
    /// position — one per type generic parameter <c>!n</c> of the definition; empty for a definition or a
    /// non-generic chain. Unlike the node-id rendering, this walks the chain outward: CCIProvider prepends a
    /// containing type's arguments only when that link is itself instantiated, so <c>Outer&lt;int&gt;.Inner.Innermost&lt;bool&gt;</c>
    /// carries only <c>[bool]</c> and <c>Outer&lt;int&gt;.Nested</c> none, while the instantiated outer link is
    /// still reachable through <see cref="IBasicType.ContainingType"/>. <c>null</c> when the arguments cannot be
    /// recovered (an unreadable type or argument, the depth bound, a chain that does not add up): the caller must
    /// then not treat the reference as a definition, nor guess an argument.
    /// </summary>
    public static IReadOnlyList<string>? TypeArguments(IBasicType? type) =>
        type is null ? null : Guard(() => Readable(CumulativeArguments(type, 0)), null);

    // Walks the nesting chain outward, accumulating names (outer -> inner), and takes the namespace from the
    // outermost type. Arity comes from the innermost type, which already counts the whole chain. Hitting the
    // depth bound with links still to walk degrades to CanonicalName.Truncated, exactly as CciNames.Walk does -
    // a truncated walk has no namespace, and only the shared marker keeps such a chain rendering alike on both
    // sides. Unlike CciNames there is no namespace to assemble: Model hands over ContainingNamespace already
    // joined, so CanonicalName.Namespace has no counterpart here.
    private static TypeIdentity Walk(IBasicType? type)
    {
        if (type is null)
            return TypeIdentity.Unknown;

        var chain = new List<string>();
        var space = string.Empty;
        var current = type;

        for (var depth = 0; current is not null && depth < MaxDepth; depth++)
        {
            chain.Insert(0, current.Name ?? CanonicalName.UnknownPart);
            space = current.ContainingNamespace ?? string.Empty;
            current = current.ContainingType;
        }

        return current is not null
            ? CanonicalName.Truncated(chain)
            : new TypeIdentity(space, chain, Math.Max(0, type.GenericParameterCount));
    }

    // Arity of the method definition behind the reference: a generic method instance reports 0 parameters and
    // carries its arity in the argument list.
    private static int MethodArity(IMethodReference method) =>
        method.GenericParameterCount > 0 ? method.GenericParameterCount : method.GenericArguments?.Count ?? 0;

    // Rendered parameter types in declaration order; one unreadable parameter degrades on its own. `substitution`
    // replaces type generic parameter !n by its n-th element (empty: render positionally).
    private static IReadOnlyList<string> ParameterNames(IMethodReference method, IReadOnlyList<string> substitution) =>
        method.Parameters.Select(p => Guard(() => ParameterName(p, 0, substitution), CanonicalName.UnknownPart)).ToArray();

    // CCIProvider erases by-ref into a PointerType and keeps the distinction only in the parameter kind.
    private static string ParameterName(IMethodParameterReference parameter, int depth, IReadOnlyList<string> substitution) =>
        parameter.Kind != MethodParameterKind.In && parameter.Type is PointerType byRef
            ? CanonicalName.ByRefTo(TypeName(byRef.TargetType, depth + 1, substitution))
            : TypeName(parameter.Type, depth + 1, substitution);

    // Case order mirrors CCIProvider.TypeExtractor.ExtractType so both layers classify a reference the same way.
    private static string TypeName(IType? type, int depth, IReadOnlyList<string> substitution) =>
        type is null || depth > MaxDepth ? CanonicalName.UnknownPart
        : type switch
        {
            ArrayType array => CanonicalName.ArrayOf(TypeName(array.ElementsType, depth + 1, substitution), (int)array.Rank),
            PointerType pointer => CanonicalName.PointerTo(TypeName(pointer.TargetType, depth + 1, substitution)),
            IGenericParameterReference parameter => parameter.Kind == GenericParameterKind.Method
                ? CanonicalName.MethodGenericParameter(parameter.Index)
                : parameter.Index < substitution.Count
                    ? substitution[parameter.Index]
                    : CanonicalName.TypeGenericParameter(parameter.Index),
            // Never substituted inside: CCI does not specialize function pointer types (see ParameterTypes).
            FunctionPointerType pointer => CanonicalName.FunctionPointer(
                TypeName(pointer.ReturnType, depth + 1, []),
                pointer.Parameters.Select(p => ParameterName(p, depth + 1, []))),
            IBasicType basic => CanonicalName.GenericInstance(CanonicalName.NodeId(Of(basic)), GenericArguments(basic, depth, substitution)),
            _ => CanonicalName.UnknownPart,
        };

    // Generic arguments are kept in signature position (they are what makes a node id unique). Model's list is
    // cumulative only over instantiated links - CCIProvider.TypeExtractor.ExtractGenericType prepends the
    // containing type's arguments, which a non-instantiated link does not carry. For node ids it is taken as-is,
    // never walked outward, because CciNames reproduces exactly this accumulation on the other side; recovering
    // the full list for substitution is CumulativeArguments' job.
    private static IReadOnlyList<string> GenericArguments(IBasicType type, int depth, IReadOnlyList<string> substitution) =>
        type.GenericArguments is not { Count: > 0 } arguments
            ? []
            : [.. arguments.Select(argument => TypeName(argument, depth + 1, substitution))];

    // A link's Model arguments are its container's Model arguments plus its own, and a container's Model list is
    // itself only a suffix of its full list whenever a link further out was not instantiated. So the arguments a
    // link carries are a suffix of its full list, and the missing prefix is the FRONT of the container's full list.
    // A chain with no instantiated link at all is a definition: empty. Anything that does not add up is null
    // (unknown) - never padded, never guessed.
    private static IReadOnlyList<string>? CumulativeArguments(IBasicType type, int depth)
    {
        var own = GenericArguments(type, depth, []);
        var missing = type.GenericParameterCount - own.Count;
        if (missing == 0)
            return own;
        if (missing < 0)
            return null;
        if (type.ContainingType is null)
            return own.Count == 0 ? [] : null;
        if (depth >= MaxDepth)
            return null;

        var outer = CumulativeArguments(type.ContainingType, depth + 1);
        return outer switch
        {
            null => null,
            [] when own.Count == 0 => [],
            _ when outer.Count >= missing => [.. outer.Take(missing), .. own],
            _ => null,
        };
    }

    // An argument that rendered <unknown> anywhere would be substituted as a guess and could exclude the true
    // candidate, so the whole list is unknown instead.
    private static IReadOnlyList<string>? Readable(IReadOnlyList<string>? arguments) =>
        arguments?.Any(a => a.Contains(CanonicalName.UnknownPart, StringComparison.Ordinal)) == true ? null : arguments;

    // Upholds the never-throws contract: Model resolves lazily against a host, so any read can fault on a
    // corrupt or hostile module. Failures are silent by design - this runs per call site, and logging would flood.
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
    // Bounds every walk over hostile metadata: nesting chains and type decoration are attacker-controlled, and
    // a stack overflow cannot be caught.
    private const int MaxDepth = 64;
    #endregion
}
