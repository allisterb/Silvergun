namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;

using Cilica.AsmIO;

using Microsoft.Cci;

using CallConvention = Cilica.AsmIO.CallConvention;
using MethodReference = Cilica.AsmIO.MethodReference;

/// <summary>Member definitions, and member references resolved the way Cilica's loader resolves them.</summary>
internal sealed partial class CciModuleSource
{
    #region Methods
    /// <summary>
    /// The Cilica method a CCI method reference denotes, resolved as Cilica's loader resolves a MemberRef: by name and
    /// signature up the base chain, keeping the call-site signature (a <c>MethodReference</c>) when no definition proves the
    /// target. A reference into a stub type is always such a reference.
    /// </summary>
    internal MethodDesc MapMethod(IMethodReference method, int depth)
    {
        if (depth > universe.Bounds.MaxDepth)
            throw new SsaAdapterException("A method reference nested too deep", kind: SsaFailureKind.Bounds);
        switch (method)
        {
            case IGenericMethodInstanceReference instance:
            {
                var generic = MapMethod(instance.GenericMethod, depth + 1);
                var arguments = instance.GenericArguments.Select(a => MapType(a, default, depth + 1)).ToImmutableArray();
                if (generic.GenericParams.Count != arguments.Length)
                    throw new SsaAdapterException($"'{generic.Name}' takes {generic.GenericParams.Count} method type argument(s), not {arguments.Length}");
                return generic.GetSpec(arguments);
            }
            case ISpecializedMethodReference specialized:
            {
                var unspecialized = specialized.UnspecializedVersion;
                return Resolve(MapType(specialized.ContainingType, default, depth + 1), unspecialized.Name.Value,
                    MapSignature(unspecialized, unspecialized.ExtraParameters, unspecialized.GenericParameterCount, default, depth + 1));
            }
            case IMethodDefinition definition when definition is not Dummy:
                return Method(definition);
            default:
                if (method is Dummy)
                    throw new SsaAdapterException("An unreadable method reference");
                return Resolve(MapType(method.ContainingType, default, depth + 1), method.Name.Value,
                    MapSignature(method, method.ExtraParameters, method.GenericParameterCount, default, depth + 1));
        }
    }

    /// <summary>
    /// The Cilica field a CCI field reference denotes, by name up the base chain (as Cilica's loader). A stub type's field is
    /// made from the reference; whether it is static comes from the opcode (<paramref name="isStatic"/>), and is unknown
    /// for <c>ldtoken</c>.
    /// </summary>
    internal FieldDesc MapField(IFieldReference field, bool? isStatic, int depth)
    {
        if (field is Dummy)
            throw new SsaAdapterException("An unreadable field reference");
        if (field is ISpecializedFieldReference specialized)
        {
            var unspecialized = specialized.UnspecializedVersion;
            return Resolve(MapType(specialized.ContainingType, default, depth + 1), unspecialized.Name.Value,
                () => FieldSig(unspecialized, default, depth + 1), isStatic);
        }
        if (field is IFieldDefinition definition)
        {
            _ = TypeOf(definition.ContainingTypeDefinition).Fields;
            return fields.TryGetValue(definition, out var def) ? def
                : omittedFields.TryGetValue(definition, out var why) ? throw Rethrow(why)
                : throw new SsaAdapterException("The field is not among its type's fields");
        }
        return Resolve(MapType(field.ContainingType, default, depth + 1), field.Name.Value, () => FieldSig(field, default, depth + 1), isStatic);
    }

    private MethodDef[] LoadMethodsCore(TypeDef type, Excused excused)
    {
        var list = new List<MethodDef>();
        foreach (var method in CciType(type).Methods)
        {
            // One unreadable method costs itself, not its type: it is left out, and anything that names it fails. Its
            // assertions are its own, so they do not also fail the list (Memo excuses them).
            using var reads = CciAssertions.BeginScope();
            try
            {
                var def = BuildMethod(type, method);
                if (reads.Count > 0)
                    throw new SsaAdapterException($"CCI failed {reads.Count} assertion(s) reading its signature", kind: SsaFailureKind.ReaderAssertion);
                list.Add(def);
                methods.Add(method, def);
                cciMethods.Add(def, method);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not InsufficientExecutionStackException
                and not SsaAdapterException { IsPathDependent: true })
            {
                var name = AssemblyAnalyzer.SafeName(method);
                // Without its type initializer the type would read as having none, which is a fact: the list fails instead.
                if (name == ".cctor")
                    throw new SsaAdapterException($"The type initializer of '{type.Name}' could not be read: {ex.Message}", ex);
                omittedMethods.TryAdd(method, ex);
                Omit(type, name);
            }
            finally
            {
                excused.Count += reads.Count;
            }
        }
        return [.. list];
    }

    private MethodDef BuildMethod(TypeDef type, IMethodDefinition method)
    {
        var (attributes, implAttributes) = Facts.Method(Token(method));
        var convention = (int)method.CallingConvention;
        if ((convention & 0x40) != 0)
            throw new SsaAdapterException("An explicit-this method signature");
        var isStatic = attributes.HasFlag(MethodAttributes.Static);
        if (isStatic == ((convention & 0x20) != 0))
            throw new SsaAdapterException("The method's static flag and its signature disagree");

        var genericParams = method.GenericParameters
            .Select((p, i) => new GenericParamType(i, true, p.Name.Value, Facts.GenericParameter(Token(p))))
            .ToArray();
        var ctx = new GenericContext(type.GenericParams, genericParams);
        foreach (var (parameter, cci) in genericParams.Zip(method.GenericParameters))
            parameter.Constraints = Constraints(cci, ctx);

        var returnSig = MapSig(method.ReturnValueCustomModifiers, method.ReturnValueIsByRef, method.Type, ctx, 0);
        var parameters = ImmutableArray.CreateBuilder<ParamDef>();
        if (!isStatic)
        {
            // As Cilica's loader: the instance parameter is the type specialised over its own parameters.
            var instance = type.GetSpec(GenericContext.Empty);
            parameters.Add(new ParamDef(instance.IsValueType ? instance.CreateByref() : instance, "this"));
        }
        foreach (var parameter in method.Parameters)
            parameters.Add(new ParamDef(MapSig(parameter.CustomModifiers, parameter.IsByReference, parameter.Type, ctx, 0),
                parameter.Name.Value is { Length: > 0 } name ? name : null, ParameterAttributesOf(parameter)));

        var def = new MethodDef(type, returnSig, parameters.ToImmutable(), method.Name.Value, attributes, implAttributes, genericParams)
        {
            CallConv = (CallConvention)(convention & 0x0F),
        };
        if (method.IsPlatformInvoke && Guard(() => method.PlatformInvokeData) is { } import)
            def.ImportInfo = new ImportDesc(import.ImportModule.Name.Value, import.ImportName.Value);
        return def;
    }

    private FieldDef[] LoadFieldsCore(TypeDef type, Excused excused)
    {
        var list = new List<FieldDef>();
        var ctx = new GenericContext(type);
        var cciType = CciType(type);
        var isEnum = IsEnum(type);
        foreach (var field in cciType.Fields)
        {
            using var reads = CciAssertions.BeginScope();
            try
            {
                var attributes = Facts.Field(Token(field));
                var def = new FieldDef(type, FieldSig(field, ctx, 0), field.Name.Value, attributes);
                // An enum's underlying type must be an integral primitive: Cilica derives the enum's stack type from it,
                // recursively, so an enum typed as another enum (or itself) would never return.
                if (!attributes.HasFlag(FieldAttributes.Static) && isEnum && def.Type is not PrimType { StackType: StackType.Int or StackType.Long or StackType.NInt })
                    throw new SsaAdapterException($"The underlying type of enum '{type.Name}' is not an integral primitive");
                if (attributes.HasFlag(FieldAttributes.HasDefault) && Guard(() => field.CompileTimeValue) is { } constant)
                    def.DefaultValue = constant.Value;
                if (def.HasLayoutOffset)
                    def.LayoutOffset = (int)Math.Min(field.Offset, int.MaxValue);
                if (attributes.HasFlag(FieldAttributes.HasFieldRVA))
                    def.MappedData = MappedData(field, def);
                if (reads.Count > 0)
                    throw new SsaAdapterException($"CCI failed {reads.Count} assertion(s) reading the field", kind: SsaFailureKind.ReaderAssertion);
                list.Add(def);
                fields.Add(field, def);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not InsufficientExecutionStackException
                and not SsaAdapterException { IsPathDependent: true })
            {
                omittedFields.TryAdd(field, ex);
                Omit(type, Guard(() => field.Name.Value) ?? "<unreadable>");
            }
            finally
            {
                excused.Count += reads.Count;
            }
        }
        return [.. list];
    }

    // Cilica's own predicate (base type is System.Enum), not CCI's narrower one (sealed, non-generic): Cilica derives the
    // stack type of whatever it calls an enum from its first instance field. A base that cannot be read fails Cilica's
    // IsEnum the same way, so no recursion can follow from it; a path-dependent failure is not an answer, and propagates.
    private bool IsEnum(TypeDef type)
    {
        try
        {
            return type.IsEnum;
        }
        catch (Exception ex) when (ex is UnresolvedFactException or SsaAdapterException { IsPathDependent: false })
        {
            return false;
        }
    }

    // RVA data, as Cilica's loader sizes it (the field type's layout size, else all of it), bounded per field and per
    // assembly; fields aliasing one block share one copy. An unreadable or over-budget block leaves the data unset: only an
    // importer use of it (array initialisation) then fails.
    private byte[]? MappedData(IFieldDefinition field, FieldDef def)
    {
        try
        {
            // Keyed by the field's RVA (a section block's offset is relative to its section, and CCI merges sections).
            var rva = Facts.FieldRva(Token(field));
            var block = field.FieldMapping;
            var size = FieldDef.GetMappedDataSize(def.Type);
            var key = (rva, block.Size, size);
            if (mappedData.TryGetValue(key, out var shared))
                return shared;
            // Both bounds are checked before anything is read: an over-cap block is refused (and the refusal kept), and a
            // spent budget costs no further reads. What is read is what is charged.
            var want = size > 0 ? size : (long)block.Size;
            if (want > universe.Bounds.MaxMappedDataBytes)
            {
                mappedData[key] = null;
                return null;
            }
            if (mappedBytes + want > universe.Bounds.MaxMappedDataBytesPerAssembly)
                return null;
            var data = block.Data.Take((int)want).ToArray();
            mappedBytes += data.Length;
            mappedData[key] = data;
            return data;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    private TypeSig FieldSig(IFieldReference field, GenericContext ctx, int depth) =>
        field.IsModified
            ? new TypeSig(MapType(field.Type, ctx, depth), Modifiers(field.CustomModifiers, ctx, depth))
            : SigOf(field.Type, ctx, depth);

    private MethodDesc Resolve(TypeDesc parent, string name, MethodSig sig)
    {
        if (parent is GenericParamType || parent is TypeDef { IsGeneric: true } || universe.IsStubType(parent))
            return new MethodReference(parent, name, sig);
        if (parent is MDArrayType array)
            return array.Methods.FirstOrDefault(m => m.Name == name && m.ParamSig.Count == sig.NumCallArgs)
                ?? throw new SsaAdapterException($"An array type has no method '{name}' of that arity");

        // Cilica's ModuleLoader.ResolveMethod, with the walk bounded, and a base outside the folder (a stub's unknown
        // supertype) ending it as "no definition proves the target".
        var visited = new HashSet<TypeDesc>();
        TypeDesc? current = parent;
        for (var depth = 0; current is not null; depth++)
        {
            if (depth > universe.Bounds.MaxDepth)
                throw new SsaAdapterException("A base-type chain too deep to search", kind: SsaFailureKind.Bounds);
            if (current is PrimType primitive)
                current = primitive.GetDefinition(universe);
            if (current is UnknownSupertype || !visited.Add(current))
                break;
            var method = current.FindMethod(name, sig, throwIfNotFound: false);
            // Checked once the type's methods are loaded: one left out under this name might be the target.
            if (method is null && current is TypeDefOrSpec owner && IsOmitted(owner, name))
                throw new SsaAdapterException($"A method named '{name}' of '{owner.Name}' could not be read");
            if (method is not null)
            {
                if (current != parent && parent is not PrimType)
                {
                    var generic = sig.ReturnType.Type.IsUnboundGeneric || sig.ParamTypes.Any(p => p.Type.IsUnboundGeneric);
                    var target = !generic || parent.GenericParams.SequenceEqual(current.GenericParams) ? method : null;
                    return new MethodReference(parent, name, sig, resolvedTarget: target);
                }
                return sig.CallConv == CallConvention.VarArgs ? new MethodReference(parent, name, sig, resolvedTarget: method) : method;
            }
            try
            {
                current = current.BaseType;
            }
            catch (UnresolvedFactException)
            {
                break;
            }
        }
        return new MethodReference(parent, name, sig);
    }

    private FieldDesc Resolve(TypeDesc parent, string name, Func<TypeSig> sig, bool? isStatic)
    {
        if (universe.IsStubType(parent))
        {
            var owner = (TypeDefOrSpec)parent;
            var stubField = universe.StubSource(owner.Module).Field(owner.Definition, name, sig(), isStatic);
            return parent is TypeSpec spec ? stubField.GetSpec(new GenericContext(spec)) : stubField;
        }
        TypeDesc? current = parent;
        for (var depth = 0; current is not null; depth++)
        {
            if (depth > universe.Bounds.MaxDepth)
                throw new SsaAdapterException("A base-type chain too deep to search", kind: SsaFailureKind.Bounds);
            if (current is PrimType primitive)
                current = primitive.GetDefinition(universe);
            // A stub ancestor's fields are only those other references happened to name: they prove nothing here.
            if (current is UnknownSupertype || universe.IsStubType(current))
                break;
            if (current.FindField(name, throwIfNotFound: false) is { } field)
                return field;
            if (current is TypeDefOrSpec owner && IsOmitted(owner, name))
                throw new SsaAdapterException($"A field named '{name}' of '{owner.Name}' could not be read");
            try
            {
                current = current.BaseType;
            }
            catch (UnresolvedFactException)
            {
                break;
            }
        }
        throw new UnresolvedFactException(UnresolvedFact.Member, parent.Name, $"no field '{name}'");
    }

    // Whether a member of this name was left out of its type's list because it could not be read (in any CCI module).
    private bool IsOmitted(TypeDefOrSpec type, string name) =>
        type is not UnknownSupertype && universe.IsOmitted(type.Definition, name);

    private void Omit(TypeDef type, string name)
    {
        if (!omittedNames.TryGetValue(type, out var names))
            omittedNames[type] = names = new HashSet<string>(StringComparer.Ordinal);
        names.Add(name);
    }

    /// <summary>Whether this module left a member of <paramref name="name"/> out of <paramref name="type"/>.</summary>
    internal bool HasOmitted(TypeDef type, string name) => omittedNames.TryGetValue(type, out var names) && names.Contains(name);

    private static ParameterAttributes ParameterAttributesOf(IParameterDefinition parameter) =>
        (parameter.IsIn ? ParameterAttributes.In : 0)
        | (parameter.IsOut ? ParameterAttributes.Out : 0)
        | (parameter.IsOptional ? ParameterAttributes.Optional : 0)
        | (parameter.HasDefaultValue ? ParameterAttributes.HasDefault : 0);
    #endregion
}
