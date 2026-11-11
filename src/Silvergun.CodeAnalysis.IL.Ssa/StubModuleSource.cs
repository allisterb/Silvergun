namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;

using Cilica.AsmIO;

/// <summary>
/// An assembly the folder does not contain and that is not framework (ruling D3). Its types are made on demand from the
/// references that name them, and state only what a reference proves: name, nesting, arity (by the name's suffix, the
/// convention every reference relies on), value-typeness from the folder's signature encodings, and member signatures. Any
/// other question throws <see cref="UnresolvedFactException"/>, which costs the asking method only.
/// </summary>
/// <remarks>
/// Some facts cannot be made to throw through Cilica's model, and read as defaults. None is consumed by import, verify or
/// SSA promotion (S2); S4 consumers must treat each as unknown for a stub type (<see cref="SsaUniverse.IsStubType"/>):
/// <list type="bullet">
/// <item><description><c>IsInterface</c> is false. Assignability of a class stub to anything but <c>object</c> still
/// throws (<see cref="UnknownSupertype"/>), but <c>IsAssignableTo(folderClass, stub)</c> reads false, so the importer may
/// insert an explicit unchecked reference cast where the IL relied on an interface or on variance.</description></item>
/// <item><description>Generic parameters are invariant and unconstrained.</description></item>
/// <item><description>No static constructor (<c>HasStaticConstructor</c>, hence <c>RequiresTypeInitialization</c>) and no
/// module initializer: a stub module has no <c>&lt;Module&gt;</c>.</description></item>
/// </list>
/// </remarks>
internal sealed class StubModuleSource : IModuleSource
{
    #region Constructors
    public StubModuleSource(SsaUniverse universe, string assemblyName)
    {
        this.universe = universe;
        AssemblyName = assemblyName;
    }
    #endregion

    #region Properties
    public string AssemblyName { get; }

    public ModuleDef Module { get; set; } = null!;
    #endregion

    #region Methods
    /// <summary>The top-level stub type <paramref name="ns"/>.<paramref name="name"/>, defined on first use.</summary>
    public TypeDef TopLevel(string? ns, string name) =>
        Module.FindType(ns, name, includeExports: false) ?? Define(ns, name, null);

    /// <summary>The stub type nested in <paramref name="parent"/> (a stub type) named <paramref name="name"/>.</summary>
    public TypeDef Nested(TypeDef parent, string name) => parent.FindNestedType(name) ?? Define(null, name, parent);

    /// <summary>A field the folder's references say the stub type has, keyed by name, signature and static-ness.</summary>
    public FieldDef Field(TypeDef type, string name, TypeSig sig, bool? isStatic)
    {
        if (isStatic is not { } stat)
            throw new UnresolvedFactException(UnresolvedFact.Member, DisplayName(type), $"whether field '{name}' is static");
        var key = (type, name, sig, stat);
        if (!fields.TryGetValue(key, out var field))
        {
            field = new FieldDef(type, sig, name, FieldAttributes.Public | (stat ? FieldAttributes.Static : 0));
            type.Fields.Add(field);
            fields.Add(key, field);
        }
        return field;
    }

    public TypeDefOrSpec? GetBaseType(TypeDef type) => universe.StubEncoding(type, AssemblyName) switch
    {
        TypeEncoding.Class => supertypes.TryGetValue(type, out var known) ? known : supertypes[type] = new UnknownSupertype(Module, DisplayName(type)),
        TypeEncoding.ValueType => throw new UnresolvedFactException(UnresolvedFact.EnumOrStruct, DisplayName(type)),
        _ => throw new UnresolvedFactException(UnresolvedFact.ValueTypeness, DisplayName(type)),
    };

    public void LoadGenericParams(TypeDef type, out GenericParamType[] genericParams) =>
        genericParams = Enumerable.Range(0, arities.GetValueOrDefault(type)).Select(i => new GenericParamType(i, false)).ToArray();

    public List<FieldDef> LoadFields(TypeDef type) => new();

    public List<MethodDef> LoadMethods(TypeDef type) => new();

    public List<TypeDesc> LoadInterfaces(TypeDef type) => throw new UnresolvedFactException(UnresolvedFact.Interfaces, DisplayName(type));

    public ILMethodBody? LoadBody(MethodDef method) => null;

    public TypeDef? FindExportedType(string? ns, string name) => TopLevel(ns, name);

    public Dictionary<MethodDesc, MethodDef> LoadMethodImpls(TypeDef type) =>
        throw new UnresolvedFactException(UnresolvedFact.Member, DisplayName(type), "method implementations");

    /// <summary>Namespace-qualified, nested with '/', raw.</summary>
    public static string DisplayName(TypeDef type)
    {
        var chain = new List<string>();
        var outer = type;
        for (var t = type; t is not null && chain.Count < 64; t = t.DeclaringType)
        {
            chain.Insert(0, t.Name);
            outer = t;
        }
        return (outer.Namespace is { } ns ? ns + "." : "") + string.Join("/", chain);
    }

    private TypeDef Define(string? ns, string name, TypeDef? parent)
    {
        var type = Module.DefineSourceType(ns, name, parent is null ? TypeAttributes.Public : TypeAttributes.NestedPublic, parent);
        arities[type] = (parent is null ? 0 : arities.GetValueOrDefault(parent)) + Arity(name);
        return type;
    }

    // The generic arity a reference's name declares (C#'s "Name`N"); none, or a malformed suffix, is 0.
    private static int Arity(string name)
    {
        var tick = name.LastIndexOf('`');
        return tick >= 0 && int.TryParse(name.AsSpan(tick + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n <= MaxArity ? n : 0;
    }
    #endregion

    #region Fields
    private const int MaxArity = 1_024;

    private readonly SsaUniverse universe;
    private readonly Dictionary<TypeDef, int> arities = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<(TypeDef, string, TypeSig, bool), FieldDef> fields = new();
    private readonly Dictionary<TypeDef, UnknownSupertype> supertypes = new(ReferenceEqualityComparer.Instance);
    #endregion
}

/// <summary>
/// The base type of a stub class: known only to be a reference type. It equals <c>object</c> (so a stub class is assignable
/// to <c>object</c>, D3's one trivial fact) and throws <see cref="UnresolvedFactException"/> for anything further: its own
/// base, interfaces and definition. It is never a value type, so the stub class it supports is not one either.
/// </summary>
internal sealed class UnknownSupertype : TypeDefOrSpec
{
    #region Constructors
    public UnknownSupertype(ModuleDef module, string ofType)
    {
        Module = module;
        this.ofType = ofType;
    }
    #endregion

    #region Properties
    public override ModuleDef Module { get; }

    public override TypeDef Definition => throw Unknown(UnresolvedFact.BaseType);

    public override TypeDefOrSpec? BaseType => throw Unknown(UnresolvedFact.BaseType);

    public override IReadOnlyList<TypeDesc> Interfaces => throw Unknown(UnresolvedFact.Interfaces);

    public override TypeAttributes Attribs
    {
        get => TypeAttributes.Public;
        set => throw new NotSupportedException();
    }

    public override TypeKind Kind => TypeKind.Object;

    public override StackType StackType => StackType.Object;

    public override bool IsValueType => false;

    public override string? Namespace => null;

    public override string Name => "<unknown supertype>";
    #endregion

    #region Methods
    public override TypeDefOrSpec GetSpec(GenericContext context) => this;

    // One-way on purpose: Cilica's base walks ask "parent == target" with the walked type on the left, which is all this
    // must answer. object.Equals(this) stays false, and the hash is not object's: never use this as a dictionary key.
    public override bool Equals(TypeDesc? other) =>
        ReferenceEquals(other, this) || ReferenceEquals(other, PrimType.Object) || other is TypeDef d && PrimType.Object.IsDefinition(d);

    public override int GetHashCode() => HashCode.Combine(Module, Name);

    private UnresolvedFactException Unknown(UnresolvedFact fact) => new(fact, ofType, "a type outside the folder");
    #endregion

    #region Fields
    private readonly string ofType;
    #endregion
}
