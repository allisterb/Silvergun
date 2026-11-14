namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

using Cilica.AsmIO;

using Microsoft.Cci;

/// <summary>Type and signature mapping: CCI references to Cilica types, as Cilica's own decoder would build them.</summary>
internal sealed partial class CciModuleSource
{
    #region Methods
    /// <summary>
    /// Maps a type in a position that carries no custom modifier. Generic parameters bind from <paramref name="ctx"/>, else
    /// stay unbound (Cilica's loader does the same: definitions bind, bodies and references do not). Depth-bounded.
    /// </summary>
    internal TypeDesc MapType(ITypeReference? type, GenericContext ctx, int depth)
    {
        universe.Cancellation.ThrowIfCancellationRequested();
        if (type is null or Dummy)
            throw new SsaAdapterException("An unreadable type reference");
        if (depth > universe.Bounds.MaxDepth)
            throw new SsaAdapterException($"A type nested deeper than {universe.Bounds.MaxDepth}", kind: SsaFailureKind.Bounds);
        switch (type)
        {
            case IModifiedTypeReference:
                throw new SsaAdapterException("A custom modifier in a position Cilica's model cannot keep");
            case IArrayTypeReference array:
            {
                var (element, mods) = MapElement(array.ElementType, ctx, depth + 1);
                if (array.IsVector)
                    return mods.IsDefaultOrEmpty ? element.CreateArray() : new ArrayType(element, mods);
                return new MDArrayType(element, checked((int)array.Rank), array.LowerBounds.ToImmutableArray(),
                    array.Sizes.Select(s => checked((int)s)).ToImmutableArray(), mods);
            }
            case IManagedPointerTypeReference pointer:
            {
                var (element, mods) = MapElement(pointer.TargetType, ctx, depth + 1);
                return mods.IsDefaultOrEmpty ? element.CreateByref() : new ByrefType(element, mods);
            }
            case IPointerTypeReference pointer:
            {
                var (element, mods) = MapElement(pointer.TargetType, ctx, depth + 1);
                return mods.IsDefaultOrEmpty ? element.CreatePointer() : new PointerType(element, mods);
            }
            case IFunctionPointerTypeReference function:
                return Bounded(new FuncPtrType(MapSignature(function, function.ExtraArgumentTypes, 0, ctx, depth + 1)));
            case IGenericTypeParameterReference parameter:
            {
                var index = TypeParameterIndex(parameter, depth);
                return ctx.GetArgument(index, false) ?? GenericParamType.GetUnbound(index, false);
            }
            case IGenericMethodParameterReference parameter:
                return ctx.GetArgument(parameter.Index, true) ?? GenericParamType.GetUnbound(parameter.Index, true);
            case IGenericTypeInstanceReference instance:
            {
                var definition = DefinitionOf(instance.GenericType, depth + 1);
                var arguments = Arguments(instance, ctx, depth + 1);
                // CCI takes as many arguments as the generic's name declares and drops the rest; the folder's own
                // instantiation counts (MetadataFacts) catch a blob that disagrees, which would otherwise read as another type.
                CheckInstantiation(instance.GenericType, definition, arguments.Length);
                return Instantiate(definition, arguments);
            }
            case ISpecializedNestedTypeReference specialized:
            {
                // CCI returns a bare specialized nested reference when the innermost type declares no parameters of its
                // own, having taken the container's from the blob: the same truncation can hide here.
                var definition = DefinitionOf(specialized, depth + 1);
                var arguments = ContainerArguments(specialized.ContainingType, ctx, depth + 1);
                CheckInstantiation(specialized, definition, arguments.Length);
                return Instantiate(definition, arguments);
            }
        }
        if (type.TypeCode == Microsoft.Cci.PrimitiveTypeCode.Invalid)
            throw new SsaAdapterException("An unreadable type reference");
        if (Primitive(type.TypeCode) is { } primitive)
        {
            // Only the host framework defines primitives: a folder module's own definition is never one, whatever CCI typed
            // it as (a weakly named folder "System.Private.CoreLib" with no core of its own is taken by CCI as the core).
            if (isFolder && type is INamedTypeDefinition own)
                return Definition(own, depth + 1);
            // CCI types a TypeRef as a primitive when it is scoped to the assembly it took as the core library (its own
            // guess); it is one only if that row names a framework assembly. Otherwise it binds by name like any other.
            if (type is INamedTypeReference reference and not INamedTypeDefinition
                && reference is IMetadataObjectWithToken { TokenValue: var token }
                && MetadataFacts.TableOf(token) == (int)TableIndex.TypeRef
                && !(RootAssembly(token) is { } root && universe.IsFramework(root)))
                return Definition(reference, depth + 1);
            return primitive;
        }
        return type switch
        {
            // A row-less platform reference may be an element type (ByName); everything else is its definition.
            INamedTypeReference named and not INamedTypeDefinition
                when named is not IMetadataObjectWithToken { TokenValue: var t } || MetadataFacts.TableOf(t) != (int)TableIndex.TypeRef
                => ByName(named, depth + 1),
            INamedTypeReference named => Definition(named, depth + 1),
            _ => throw new SsaAdapterException($"An unsupported kind of type reference ({type.GetType().Name})"),
        };
    }

    /// <summary>A signature type: leading modifiers, an optional by-ref, and the element's own modifiers inside it.</summary>
    internal TypeSig MapSig(IEnumerable<ICustomModifier>? modifiers, bool isByRef, ITypeReference type, GenericContext ctx, int depth)
    {
        if (isByRef)
        {
            var (element, inner) = MapElement(type, ctx, depth + 1);
            return new TypeSig(inner.IsDefaultOrEmpty ? element.CreateByref() : new ByrefType(element, inner), Modifiers(modifiers, ctx, depth));
        }
        return type is IModifiedTypeReference modified
            ? new TypeSig(MapType(modified.UnmodifiedType, ctx, depth + 1), Modifiers((modifiers ?? []).Concat(modified.CustomModifiers), ctx, depth))
            : new TypeSig(MapType(type, ctx, depth), Modifiers(modifiers, ctx, depth));
    }

    /// <summary>A method signature in Cilica's form: the instance parameter excluded, varargs after the required ones.</summary>
    internal MethodSig MapSignature(ISignature signature, IEnumerable<IParameterTypeInformation>? extra, int genericCount, GenericContext ctx, int depth)
    {
        var returnSig = MapSig(signature.ReturnValueCustomModifiers, signature.ReturnValueIsByRef, signature.Type, ctx, depth);
        var required = signature.Parameters.Select(p => MapSig(p.CustomModifiers, p.IsByReference, p.Type, ctx, depth)).ToArray();
        var extras = (extra ?? []).Select(p => MapSig(p.CustomModifiers, p.IsByReference, p.Type, ctx, depth)).ToArray();
        return new MethodSig(returnSig, [.. required, .. extras], Header(signature.CallingConvention), genericCount, required.Length);
    }

    /// <summary>The signature header CCI's calling convention encodes (its values are ECMA-335's).</summary>
    internal static SignatureHeader Header(CallingConvention convention)
    {
        var raw = (int)convention;
        var attributes = ((raw & 0x20) != 0 ? SignatureAttributes.Instance : 0)
            | ((raw & 0x40) != 0 ? SignatureAttributes.ExplicitThis : 0)
            | ((raw & 0x10) != 0 ? SignatureAttributes.Generic : 0);
        return new SignatureHeader(SignatureKind.Method, (SignatureCallingConvention)(raw & 0x0F), attributes);
    }

    internal ImmutableArray<GenericParamConstraint> Constraints(IGenericParameter parameter, GenericContext ctx) =>
        parameter.Constraints.Select(c => new GenericParamConstraint(SigOf(c, ctx, 0), Array.Empty<CustomAttrib>())).ToImmutableArray();

    /// <summary>A type with any top-level modifiers it carries (a constraint or a field type).</summary>
    internal TypeSig SigOf(ITypeReference type, GenericContext ctx, int depth) =>
        type is IModifiedTypeReference modified
            ? new TypeSig(MapType(modified.UnmodifiedType, ctx, depth + 1), Modifiers(modified.CustomModifiers, ctx, depth))
            : new TypeSig(MapType(type, ctx, depth));

    /// <summary>The generic definition a named reference denotes: a definition of this module, or a TypeRef resolved by name.</summary>
    internal TypeDef Definition(INamedTypeReference named, int depth)
    {
        if (depth > universe.Bounds.MaxDepth)
            throw new SsaAdapterException($"A type nested deeper than {universe.Bounds.MaxDepth}", kind: SsaFailureKind.Bounds);
        if (named is INamedTypeDefinition definition)
            return TypeOf(definition);
        var token = named is IMetadataObjectWithToken withToken ? withToken.TokenValue : uint.MaxValue;
        return MetadataFacts.TableOf(token) == (int)TableIndex.TypeRef ? ResolveTypeRef(token, depth) : ByNameDefinition(named, depth);
    }

    // A TypeRef row resolves by its exact names and scope, never by CCI's resolution (which probes its own way).
    private TypeDef ResolveTypeRef(uint token, int depth) => Memo(("typeref", token), _ =>
    {
        if (depth > universe.Bounds.MaxDepth)
            throw new SsaAdapterException("A TypeRef chain that is too deep or cyclic", kind: SsaFailureKind.Bounds) { IsPathDependent = true };
        var row = Facts.TypeRef(token);
        return row.Kind switch
        {
            TypeRefScope.Assembly => universe.TopLevel(row.AssemblyName!, row.Namespace, row.Name),
            TypeRefScope.TypeRef => universe.Nested(ResolveTypeRef(row.ParentToken, depth + 1), row.Name),
            TypeRefScope.Module => OwnType(row.Namespace, row.Name),
            _ => throw new UnresolvedFactException(UnresolvedFact.Type, (row.Namespace is null ? "" : row.Namespace + ".") + row.Name,
                "scoped to another module of the assembly, or to none"),
        };
    });

    // A top-level type of this module named by a reference scoped to the module itself.
    private TypeDef OwnType(string? ns, string name)
    {
        var display = (ns is null ? "" : ns + ".") + name;
        if (IsAmbiguous(null, ns, name))
            throw new UnresolvedFactException(UnresolvedFact.Type, display, "defined more than once in its own module");
        return Module.FindType(ns, name) ?? throw new UnresolvedFactException(UnresolvedFact.Type, display, "not in its own module");
    }

    // The assembly a TypeRef chain is scoped to, or null if it is scoped to anything else (or unreadably deep).
    private string? RootAssembly(uint token)
    {
        for (var depth = 0; depth <= universe.Bounds.MaxDepth; depth++)
        {
            var row = Facts.TypeRef(token);
            if (row.Kind != TypeRefScope.TypeRef)
                return row.Kind == TypeRefScope.Assembly ? row.AssemblyName : null;
            token = row.ParentToken;
        }
        return null;
    }

    // A named reference with no TypeRef row: CCI synthesises these for the platform types an element type denotes, scoped to
    // the assembly it took as the core. ELEMENT_TYPE_OBJECT and _TYPEDBYREF (the two with no primitive type code) mean those
    // types whatever that guess; anything else binds by CCI's names, the arity suffix restored.
    private TypeDesc ByName(INamedTypeReference named, int depth)
    {
        if (named is INamespaceTypeReference { GenericParameterCount: 0 } platform && Namespace(platform.ContainingUnitNamespace) == "System")
        {
            if (platform.Name.Value == "Object") return PrimType.Object;
            if (platform.Name.Value == "TypedReference") return PrimType.TypedRef;
        }
        return ByNameDefinition(named, depth);
    }

    private TypeDef ByNameDefinition(INamedTypeReference named, int depth)
    {
        var name = named.Name.Value + (named.MangleName && named.GenericParameterCount > 0 ? "`" + named.GenericParameterCount : "");
        switch (named)
        {
            case INestedTypeReference nested:
                return universe.Nested(DefinitionOf(nested.ContainingType, depth + 1), name);
            case INamespaceTypeReference top:
            {
                var ns = Namespace(top.ContainingUnitNamespace);
                return top.ContainingUnitNamespace.Unit switch
                {
                    IAssemblyReference assembly => universe.TopLevel(assembly.Name.Value, ns, name),
                    IModule self when ReferenceEquals(self, Cci.Module) => OwnType(ns, name),
                    _ => throw new UnresolvedFactException(UnresolvedFact.Type, (ns is null ? "" : ns + ".") + name, "scoped to another module"),
                };
            }
            default:
                throw new SsaAdapterException($"An unsupported kind of named type reference ({named.GetType().Name})");
        }
    }

    private string? Namespace(IUnitNamespaceReference space)
    {
        var parts = new List<string>();
        for (var depth = 0; space is INestedUnitNamespaceReference nested; depth++, space = nested.ContainingUnitNamespace)
        {
            if (depth > universe.Bounds.MaxDepth)
                throw new SsaAdapterException("A namespace nested too deep", kind: SsaFailureKind.Bounds);
            parts.Insert(0, nested.Name.Value);
        }
        return parts.Count == 0 ? null : string.Join(".", parts);
    }

    // CCI takes as many arguments as a generic's name declares and drops the rest; the folder's own instantiation counts
    // (MetadataFacts) catch a blob that disagrees, which would otherwise read as another type.
    private void CheckInstantiation(ITypeReference generic, TypeDef definition, int count)
    {
        if (Unwrap(generic) is IMetadataObjectWithToken { TokenValue: var token } && Facts.DisagreesWith(token, count))
            throw universe.IsStub(definition.Module)
                ? new UnresolvedFactException(UnresolvedFact.Arity, StubModuleSource.DisplayName(definition), "instantiated with differing numbers of arguments")
                : new SsaAdapterException($"'{definition.Name}' is instantiated with differing numbers of type arguments");
    }

    private TypeDesc Instantiate(TypeDef definition, ImmutableArray<TypeDesc> arguments)
    {
        if (definition.GenericParams.Length != arguments.Length)
            throw universe.IsStub(definition.Module)
                ? new UnresolvedFactException(UnresolvedFact.Arity, StubModuleSource.DisplayName(definition), $"used with {arguments.Length} type argument(s)")
                : new SsaAdapterException($"'{definition.Name}' takes {definition.GenericParams.Length} type argument(s), not {arguments.Length}");
        if (arguments.IsEmpty)
            return definition;
        // Interned here by argument identity before Cilica sees it: Cilica's own cache keys and comparisons walk the
        // arguments as trees, so a large instance named in many signatures would pay that walk at every use.
        var key = (definition, new TypeDescList(arguments));
        if (instances.TryGetValue(key, out var known))
            return known;
        // Checked before Cilica interns it.
        if (1 + arguments.Sum(Parts) > universe.Bounds.MaxTypeParts)
            throw TooManyParts(definition.Name);
        return instances[key] = definition.GetSpec(arguments);
    }

    private TypeDesc Bounded(TypeDesc type) => Parts(type) > universe.Bounds.MaxTypeParts ? throw TooManyParts(type.Name) : type;

    private SsaAdapterException TooManyParts(string name) =>
        new($"A type ('{name}') that expands to more than {universe.Bounds.MaxTypeParts} parts", kind: SsaFailureKind.Bounds);

    // The parts a type expands to as a tree, saturating past the bound. Specs are memoised by reference (Cilica interns
    // them), so the count costs the distinct types, not the tree; other compounds are new objects per mapping, not kept.
    private long Parts(TypeDesc type)
    {
        if (type is TypeSpec cached && typeParts.TryGetValue(cached, out var known))
            return known;
        var parts = Math.Min(universe.Bounds.MaxTypeParts + 1L, 1 + type switch
        {
            TypeSpec spec => spec.GenericParams.Sum(Parts),
            CompoundType compound => Parts(compound.ElemType),
            FuncPtrType function => Parts(function.Signature.ReturnType.Type) + function.Signature.ParamTypes.Sum(p => Parts(p.Type)),
            _ => 0,
        });
        if (type is TypeSpec instance)
            typeParts[instance] = parts;
        return parts;
    }

    // Type arguments mapped one by one, failing as soon as their parts pass the bound, so a wide instantiation of large
    // arguments stops at the first that does not fit rather than after mapping them all.
    private ImmutableArray<TypeDesc> BoundedArguments(IEnumerable<ITypeReference> references, GenericContext ctx, int depth, string owner, long parts = 1)
    {
        var arguments = ImmutableArray.CreateBuilder<TypeDesc>();
        foreach (var reference in references)
        {
            var argument = MapType(reference, ctx, depth);
            parts += Parts(argument);
            if (parts > universe.Bounds.MaxTypeParts)
                throw TooManyParts(owner);
            arguments.Add(argument);
        }
        return arguments.ToImmutable();
    }

    // The definition behind any named reference, specialized or instantiated ones included.
    private TypeDef DefinitionOf(ITypeReference type, int depth) =>
        Unwrap(type) is INamedTypeReference named and not ISpecializedNestedTypeReference and not IGenericTypeInstanceReference
            ? Definition(named, depth)
            : throw new SsaAdapterException("A generic type that is not a named type");

    // A generic instance's arguments: its containers' (a specialized nested type's) first, then its own, as metadata has them.
    private ImmutableArray<TypeDesc> Arguments(IGenericTypeInstanceReference instance, GenericContext ctx, int depth)
    {
        var containers = ContainerArguments((instance.GenericType as ISpecializedNestedTypeReference)?.ContainingType, ctx, depth + 1);
        return
        [
            .. containers,
            .. BoundedArguments(instance.GenericArguments, ctx, depth + 1, (Unwrap(instance.GenericType) as INamedTypeReference)?.Name.Value ?? "a generic type",
                1 + containers.Sum(Parts)),
        ];
    }

    private ImmutableArray<TypeDesc> ContainerArguments(ITypeReference? container, GenericContext ctx, int depth)
    {
        if (depth > universe.Bounds.MaxDepth)
            throw new SsaAdapterException("A generic container chain that is too deep", kind: SsaFailureKind.Bounds);
        return container switch
        {
            IGenericTypeInstanceReference instance => Arguments(instance, ctx, depth + 1),
            ISpecializedNestedTypeReference specialized => ContainerArguments(specialized.ContainingType, ctx, depth + 1),
            _ => [],
        };
    }

    // CCI numbers a type's generic parameters per type; metadata numbers them across the nesting chain.
    private int TypeParameterIndex(IGenericTypeParameterReference parameter, int depth)
    {
        var total = 0;
        var container = (Unwrap(parameter.DefiningType) as INestedTypeReference)?.ContainingType;
        for (var level = depth; container is not null; level++)
        {
            if (level > universe.Bounds.MaxDepth)
                throw new SsaAdapterException("A generic container chain that is too deep", kind: SsaFailureKind.Bounds);
            var named = Unwrap(container) as INamedTypeReference;
            total += named?.GenericParameterCount ?? 0;
            container = (named as INestedTypeReference)?.ContainingType;
        }
        return total + parameter.Index;
    }

    // The definition behind a generic instance or a specialized nested reference.
    private static ITypeReference Unwrap(ITypeReference type)
    {
        for (var i = 0; i < 4; i++)
        {
            if (type is IGenericTypeInstanceReference instance) type = instance.GenericType;
            else if (type is ISpecializedNestedTypeReference specialized) type = specialized.UnspecializedVersion;
            else break;
        }
        return type;
    }

    private (TypeDesc Type, ImmutableArray<TypeModifier> Modifiers) MapElement(ITypeReference type, GenericContext ctx, int depth) =>
        type is IModifiedTypeReference modified
            ? (MapType(modified.UnmodifiedType, ctx, depth + 1), Modifiers(modified.CustomModifiers, ctx, depth))
            : (MapType(type, ctx, depth), default);

    private ImmutableArray<TypeModifier> Modifiers(IEnumerable<ICustomModifier>? modifiers, GenericContext ctx, int depth) =>
        modifiers is null ? default : modifiers.Select(m => new TypeModifier(MapType(m.Modifier, ctx, depth + 1), !m.IsOptional)).ToImmutableArray();

    private static PrimType? Primitive(Microsoft.Cci.PrimitiveTypeCode code) => code switch
    {
        Microsoft.Cci.PrimitiveTypeCode.Boolean => PrimType.Bool,
        Microsoft.Cci.PrimitiveTypeCode.Char => PrimType.Char,
        Microsoft.Cci.PrimitiveTypeCode.Int8 => PrimType.SByte,
        Microsoft.Cci.PrimitiveTypeCode.UInt8 => PrimType.Byte,
        Microsoft.Cci.PrimitiveTypeCode.Int16 => PrimType.Int16,
        Microsoft.Cci.PrimitiveTypeCode.UInt16 => PrimType.UInt16,
        Microsoft.Cci.PrimitiveTypeCode.Int32 => PrimType.Int32,
        Microsoft.Cci.PrimitiveTypeCode.UInt32 => PrimType.UInt32,
        Microsoft.Cci.PrimitiveTypeCode.Int64 => PrimType.Int64,
        Microsoft.Cci.PrimitiveTypeCode.UInt64 => PrimType.UInt64,
        Microsoft.Cci.PrimitiveTypeCode.Float32 => PrimType.Single,
        Microsoft.Cci.PrimitiveTypeCode.Float64 => PrimType.Double,
        Microsoft.Cci.PrimitiveTypeCode.IntPtr => PrimType.IntPtr,
        Microsoft.Cci.PrimitiveTypeCode.UIntPtr => PrimType.UIntPtr,
        Microsoft.Cci.PrimitiveTypeCode.String => PrimType.String,
        Microsoft.Cci.PrimitiveTypeCode.Void => PrimType.Void,
        _ => null,
    };
    #endregion
}
