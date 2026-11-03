namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;

using ModelBytecode = Model.Bytecode;
using ModelTypes = Model.Types;

/// <summary>
/// Hand-built Analysis.Net <c>Model</c> objects (public <c>BasicType</c>/<c>MethodReference</c>/<c>ClassDefinition</c>…,
/// no host, no metadata) for the shapes no compiled fixture can — or may — produce: chains that do not add up, chains
/// past the depth bound (never compiled: spec §2.5's fixture rule), reads that throw, metadata names holding U+0001.
/// Nothing here is resolved: <c>ResolvedType</c>/<c>ResolvedMethod</c> would throw, which is the point.
/// </summary>
internal static class SyntheticModel
{
    #region Methods
    /// <summary>
    /// A type reference: <paramref name="arity"/> is Model's CUMULATIVE <c>GenericParameterCount</c>, and
    /// <paramref name="arguments"/> its Model <c>GenericArguments</c> exactly as given (a suffix of the full list when an
    /// outer link is not instantiated — the CCIProvider quirk <see cref="ModelNames.TypeArguments"/> undoes).
    /// </summary>
    public static ModelTypes.BasicType TypeRef(
        string? space, string name, int arity = 0, ModelTypes.IBasicType? container = null, string? assembly = null, ModelTypes.IType[]? arguments = null)
    {
        var type = new ModelTypes.BasicType(name)
        {
            ContainingNamespace = space!,
            ContainingType = container!,
            GenericParameterCount = arity,
            ContainingAssembly = assembly is null ? null! : new Model.AssemblyReference(assembly),
        };
        foreach (var argument in arguments ?? [])
            type.GenericArguments.Add(argument);
        return type;
    }

    /// <summary>A method reference on <paramref name="declaring"/> with plain (<c>In</c>) parameters.</summary>
    public static ModelTypes.MethodReference Method(ModelTypes.IBasicType declaring, string name, params ModelTypes.IType[] parameters)
    {
        var method = new ModelTypes.MethodReference(name, ModelTypes.PlatformTypes.Int32) { ContainingType = declaring };
        for (var i = 0; i < parameters.Length; i++)
            method.Parameters.Add(new ModelTypes.MethodParameterReference((ushort)i, parameters[i]));
        return method;
    }

    /// <summary>
    /// A by-ref parameter as CCIProvider models it: a <see cref="ModelTypes.PointerType"/> whose by-ref-ness lives only
    /// in the parameter kind.
    /// </summary>
    public static ModelTypes.MethodParameterReference ByRef(ushort index, ModelTypes.IType target) =>
        new(index, new ModelTypes.PointerType(target)) { Kind = ModelTypes.MethodParameterKind.Ref };

    /// <summary>The positional type generic parameter <c>!index</c>.</summary>
    public static ModelTypes.GenericParameterReference TypeParameter(ushort index) => new(ModelTypes.GenericParameterKind.Type, index);

    /// <summary>The positional method generic parameter <c>!!index</c>.</summary>
    public static ModelTypes.GenericParameterReference MethodParameter(ushort index) => new(ModelTypes.GenericParameterKind.Method, index);

    /// <summary>A function pointer type <c>fnptr:returnType(parameters)</c>.</summary>
    public static ModelTypes.FunctionPointerType FunctionPointer(ModelTypes.IType returnType, params ModelTypes.IType[] parameters)
    {
        var pointer = new ModelTypes.FunctionPointerType(returnType);
        for (var i = 0; i < parameters.Length; i++)
            pointer.Parameters.Add(new ModelTypes.MethodParameterReference((ushort)i, parameters[i]));
        return pointer;
    }

    /// <summary>
    /// An assembly <paramref name="name"/> holding one class <c>Synthetic.Callers</c> with one static, parameterless,
    /// bytecode-bodied method per call: its body is the single instruction <c>call target</c> at <see cref="CallOffset"/>.
    /// Indexed next to real assemblies, it puts a hand-built reference into a graph.
    /// </summary>
    public static Model.Assembly CallerAssembly(string name, params (string Method, ModelTypes.IMethodReference Target)[] calls)
    {
        var assembly = new Model.Assembly(name);
        var root = new Model.Namespace(string.Empty) { ContainingAssembly = assembly };
        var space = new Model.Namespace(CallerNamespace) { ContainingAssembly = assembly, ContainingNamespace = root };
        root.Namespaces.Add(space);
        assembly.RootNamespace = root;

        var type = new ModelTypes.ClassDefinition(CallerType) { ContainingAssembly = assembly, ContainingNamespace = space };
        space.Types.Add(type);
        foreach (var (method, target) in calls)
        {
            var body = new ModelTypes.MethodBody(ModelTypes.MethodBodyKind.Bytecode);
            body.Instructions.Add(new ModelBytecode.MethodCallInstruction(CallOffset, ModelBytecode.MethodCallOperation.Static, target));
            type.Methods.Add(new ModelTypes.MethodDefinition(method, ModelTypes.PlatformTypes.Void) { ContainingType = type, IsStatic = true, Body = body });
        }

        return assembly;
    }

    /// <summary>The node id of a <see cref="CallerAssembly"/> method.</summary>
    public static string CallerId(string method) => $"{CallerNamespace}.{CallerType}.{method}()";
    #endregion

    #region Fields
    /// <summary>The IL offset of every synthetic call instruction.</summary>
    public const uint CallOffset = 0x10;

    private const string CallerNamespace = "Synthetic";
    private const string CallerType = "Callers";
    #endregion
}

/// <summary>
/// An <see cref="ModelTypes.IBasicType"/> that reads through to a <see cref="ModelTypes.BasicType"/> except for the reads
/// told to throw. These are DEFENSIVE tests of the never-throws contract (<see cref="ModelNames"/>,
/// <see cref="MemberIndex"/>), not a reproduction of a known fault: on <see cref="ModelTypes.BasicType"/>,
/// <c>GenericArguments</c>, <c>ContainingType</c> and <c>GenericParameterCount</c> are plain auto-properties
/// (<c>ext/analysis-net/Model/Types/Types.cs</c>), so today's CCIProvider objects cannot throw on these reads. The
/// guards stay because <see cref="ModelTypes.IBasicType"/> is an interface and the contract must not depend on which
/// implementation hands a reference over.
/// </summary>
internal sealed class ThrowingBasicType(ModelTypes.BasicType inner) : ModelTypes.IBasicType
{
    #region Properties
    public bool ThrowOnGenericArguments { get; init; }

    public bool ThrowOnContainingType { get; init; }

    public bool ThrowOnGenericParameterCount { get; init; }

    public ISet<ModelTypes.CustomAttribute> Attributes => inner.Attributes;

    public ModelTypes.TypeKind TypeKind => inner.TypeKind;

    public ModelTypes.IBasicType ContainingType => ThrowOnContainingType ? throw Unreadable(nameof(ContainingType)) : inner.ContainingType;

    public int GenericParameterCount => ThrowOnGenericParameterCount ? throw Unreadable(nameof(GenericParameterCount)) : inner.GenericParameterCount;

    public Model.IAssemblyReference ContainingAssembly => inner.ContainingAssembly;

    public string ContainingNamespace => inner.ContainingNamespace;

    public string Name => inner.Name;

    public string GenericName => inner.GenericName;

    public IList<ModelTypes.IType> GenericArguments => ThrowOnGenericArguments ? throw Unreadable(nameof(GenericArguments)) : inner.GenericArguments;

    public ModelTypes.IBasicType GenericType => inner.GenericType;

    public ModelTypes.ITypeDefinition ResolvedType => throw new InvalidOperationException("A synthetic type is never resolved.");
    #endregion

    #region Methods
    private static BadImageFormatException Unreadable(string what) => new($"unreadable {what} (synthetic)");
    #endregion
}
