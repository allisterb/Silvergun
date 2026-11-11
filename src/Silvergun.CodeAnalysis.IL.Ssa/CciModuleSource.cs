namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

using Cilica.AsmIO;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// One CCI-read assembly (folder or framework) as the source of a Cilica module. The type table is defined eagerly, with
/// exact metadata names; members, base types, generic parameters and bodies are adapted when Cilica first asks, so the
/// cost tracks use. Every answer is memoised, failures included, so an input read once reads the same every time (a
/// failure that depends only on the path that reached it, a nesting bound, is not). A read that fails an assertion in CCI
/// is never published: it throws, and costs the methods that need it.
/// </summary>
internal sealed partial class CciModuleSource : IModuleSource, IDisposable
{
    #region Constructors
    public CciModuleSource(SsaUniverse universe, AssemblyAnalyzer cci, MetadataFacts facts, string path, bool isFolder)
    {
        this.universe = universe;
        Cci = cci;
        Facts = facts;
        Path = path;
        this.isFolder = isFolder;
    }
    #endregion

    #region Properties
    public AssemblyAnalyzer Cci { get; }

    public MetadataFacts Facts { get; }

    public string Path { get; }

    public ModuleDef Module { get; private set; } = null!;

    public Version? Version => Guard(() => Cci.Module.ContainingAssembly?.Version);

    /// <summary>CCI assertions raised while the type table was read: every method of the module reads as degraded.</summary>
    public int TableAssertions { get; private set; }

    /// <summary>
    /// Why CCI's view of this folder assembly's primitive types cannot be trusted, or null. CCI takes the "core" assembly
    /// by majority vote over the module's System.* references (or the module itself, if it defines System.Object), and
    /// types references scoped to it as primitives; unless that core is a framework assembly, every method is Unknown.
    /// </summary>
    public string? CoreProblem { get; private set; }
    #endregion

    #region Methods
    /// <summary>Binds the module created over this source and defines its whole type table.</summary>
    public void Attach(ModuleDef module)
    {
        Module = module;
        using var reads = CciAssertions.BeginScope();
        foreach (var type in Cci.Module.GetAllTypes())
            Define(type, 0);
        TableAssertions = reads.Count;
        if (isFolder)
            CoreProblem = CheckCore();
    }

    public TypeDefOrSpec? GetBaseType(TypeDef type) => Memo<TypeDefOrSpec?>((type, Load.Base), _ =>
    {
        var baseRef = CciType(type).BaseClasses.FirstOrDefault();
        if (baseRef is null)
            return null;
        var baseType = MapType(baseRef, new GenericContext(type), 0) as TypeDefOrSpec
            ?? throw new SsaAdapterException($"The base type of '{type.Name}' is not a class");
        ValidateChain(type, baseType);
        return baseType;
    });

    public void LoadGenericParams(TypeDef type, out GenericParamType[] genericParams)
    {
        // Publish before the constraints are mapped (IModuleSource's contract): a constraint may name the type itself.
        var (parameters, cci) = Memo((type, Load.GenericParams), _ =>
        {
            var chain = Chain(CciType(type));
            if (chain.OfType<INestedTypeDefinition>().Any(n => n.DoesNotInheritGenericParameters))
                throw new SsaAdapterException($"'{type.Name}' does not inherit its containers' generic parameters");
            // A nested type's inherited parameters are read from its containers' rows (CCI lists only a type's own), which
            // metadata requires to match the nested type's copies.
            var own = chain.SelectMany(t => t.GenericParameters).ToArray();
            return (own.Select((p, i) => new GenericParamType(i, false, p.Name.Value, Facts.GenericParameter(Token(p)))).ToArray(), own);
        });
        genericParams = parameters;
        var ctx = new GenericContext(parameters);
        Memo((type, Load.Constraints), _ =>
        {
            for (var i = 0; i < parameters.Length; i++)
                parameters[i].Constraints = Constraints(cci[i], ctx);
            return true;
        });
    }

    public List<FieldDef> LoadFields(TypeDef type) => new(Memo((type, Load.Fields), excused => LoadFieldsCore(type, excused)));

    public List<MethodDef> LoadMethods(TypeDef type) => new(Memo((type, Load.Methods), excused => LoadMethodsCore(type, excused)));

    public List<TypeDesc> LoadInterfaces(TypeDef type) => new(Memo((type, Load.Interfaces), _ =>
    {
        var ctx = new GenericContext(type);
        return CciType(type).Interfaces.Select(i => MapType(i, ctx, 0)).ToArray();
    }));

    public Dictionary<MethodDesc, MethodDef> LoadMethodImpls(TypeDef type) => new(Memo((type, Load.MethodImpls), _ =>
    {
        var map = new Dictionary<MethodDesc, MethodDef>();
        foreach (var impl in CciType(type).ExplicitImplementationOverrides)
        {
            var body = MapMethod(impl.ImplementingMethod, 0) as MethodDef
                ?? throw new SsaAdapterException($"A method implementation of '{type.Name}' is not a method definition");
            map.TryAdd(MapMethod(impl.ImplementedMethod, 0), body);
        }
        return map;
    }));

    public ILMethodBody? LoadBody(MethodDef method) =>
        cciMethods.TryGetValue(method, out var cci) ? Memo<ILMethodBody?>(method, _ => ConvertBody(cci)) : null;

    /// <summary>A type this assembly forwards, by its exported-type rows matched exactly (arity included).</summary>
    public TypeDef? FindExportedType(string? ns, string name)
    {
        if (Facts.ExportedTarget(ns, name) is not { } target)
            return null;
        var display = (ns is null ? "" : ns + ".") + name;
        // A forwarder chain that returns to a module it left is a cycle in the input (e.g. a folder's desktop facade
        // forwarding back to a host facade that forwarded to it): the type exists nowhere, whatever path reached it.
        if (!universe.TryForwarding(Module, ns, name, out var forwarding))
            throw new UnresolvedFactException(UnresolvedFact.Type, display, "its type forwarders form a cycle");
        using var cycle = forwarding;
        using var hop = universe.Forwarders.Enter($"'{display}' from '{Module.AsmName.Name}' to '{target}'");
        return universe.ModuleFor(target) == Module ? null : universe.TopLevel(target, ns, name);
    }

    /// <summary>The Cilica method of a CCI method definition of this module; throws the reason it could not be adapted.</summary>
    public MethodDef Method(IMethodDefinition method)
    {
        var type = TypeOf(method.ContainingTypeDefinition);
        _ = type.Methods;
        return methods.TryGetValue(method, out var def) ? def
            : omittedMethods.TryGetValue(method, out var why) ? throw Rethrow(why)
            : throw new SsaAdapterException("The method is not among its type's methods");
    }

    /// <summary>Whether a type of this name is defined more than once (in <paramref name="parent"/>, or at top level).</summary>
    public bool IsAmbiguous(TypeDef? parent, string? ns, string name) =>
        ambiguous.Contains(((object?)parent ?? Module, parent is null ? ns : null, name));

    public void Dispose()
    {
        Cci.Dispose();
        Facts.Dispose();
    }

    private string? CheckCore()
    {
        try
        {
            // No core at all (a module with no System.* references, e.g. interfaces only) is safe: no TypeRef can then be
            // typed as a primitive, and its element types (ELEMENT_TYPE_I4, ..._OBJECT) are unambiguous.
            var core = Cci.Module.CoreAssemblySymbolicIdentity;
            if (core is null || core == Dummy.AssemblyIdentity || core.Name.Value.Length == 0)
                return null;
            if (Cci.Module.ContainingAssembly?.AssemblyIdentity is { } own && own.Equals(core))
                return "it defines its own core library types";
            return universe.IsFramework(core.Name.Value) ? null : $"CCI takes '{core.Name.Value}', not a framework assembly, as its core library";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return "its core library could not be determined: " + ex.Message;
        }
    }

    // Defines a type of the table, its containers first. Exact names come from the metadata row (CCI drops the arity
    // suffix); a duplicate name, which the CLR would reject, is kept under a unique one and refused by name.
    private TypeDef? Define(INamedTypeDefinition type, int depth)
    {
        if (types.TryGetValue(type, out var known))
            return known;
        if (depth > universe.Bounds.MaxDepth)
            return null;
        try
        {
            var token = Token(type);
            var (ns, name, attributes) = Facts.TypeDef(token);
            TypeDef? parent = null;
            if (type is INestedTypeDefinition nested)
                parent = Define((INamedTypeDefinition)nested.ContainingTypeDefinition, depth + 1) ?? throw new SsaAdapterException("Its container could not be defined");
            // The nesting is CCI's (the NestedClass table); a visibility that disagrees with it is malformed, and is
            // corrected only so the type can be defined (it bears on no fact the lifter uses).
            var visibility = attributes & TypeAttributes.VisibilityMask;
            if (parent is not null && visibility < TypeAttributes.NestedPublic)
                attributes = (attributes & ~TypeAttributes.VisibilityMask) | TypeAttributes.NestedAssembly;
            else if (parent is null && visibility >= TypeAttributes.NestedPublic)
                attributes &= ~TypeAttributes.VisibilityMask;
            TypeDef def;
            try
            {
                def = Module.DefineSourceType(ns, name, attributes, parent);
            }
            catch (InvalidOperationException)
            {
                ambiguous.Add(((object?)parent ?? Module, parent is null ? ns : null, name));
                def = Module.DefineSourceType(ns, $"{name}<duplicate 0x{token:X8}>", attributes, parent);
            }
            // Only RVA-field data sizing reads the layout; an unreadable one leaves it unset rather than losing the type.
            try
            {
                def.LayoutSize = (int)Math.Min(type.SizeOf, int.MaxValue);
                def.LayoutPack = type.Alignment;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
            }
            types.Add(type, def);
            cciTypes.Add(def, type);
            return def;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            undefinable.TryAdd(type, ex);
            return null;
        }
    }

    // A base type is checked for a cycle and for length before it is published: Cilica walks base chains without bounds.
    // A cycle re-enters this type's check (refused, and memoised as such); the walk and the nesting are both bounded.
    private void ValidateChain(TypeDef type, TypeDefOrSpec baseType)
    {
        if (!validating.Add(type))
            throw new SsaAdapterException($"The base-type chain of '{type.Name}' is cyclic");
        try
        {
            using var nesting = universe.Bases.Enter();
            var steps = 0;
            for (TypeDesc? t = baseType; t is TypeDefOrSpec current && current is not UnknownSupertype && !universe.IsStub(current.Module);)
            {
                if (++steps > universe.Bounds.MaxDepth)
                    throw new SsaAdapterException($"The base-type chain of '{type.Name}' is longer than {universe.Bounds.MaxDepth}", kind: SsaFailureKind.Bounds);
                if (ReferenceEquals(current.Definition, type))
                    throw new SsaAdapterException($"The base-type chain of '{type.Name}' is cyclic");
                try
                {
                    t = current.BaseType;
                }
                catch (UnresolvedFactException)
                {
                    break;
                }
            }
        }
        finally
        {
            validating.Remove(type);
        }
    }

    private INamedTypeDefinition CciType(TypeDef type) =>
        cciTypes.TryGetValue(type, out var cci) ? cci : throw new SsaAdapterException($"'{type.Name}' is not a type of this module");

    private TypeDef TypeOf(ITypeDefinition type) =>
        type is INamedTypeDefinition named && types.TryGetValue(named, out var def) ? def
        : type is INamedTypeDefinition bad && undefinable.TryGetValue(bad, out var why) ? throw new SsaAdapterException("Its type could not be defined: " + why.Message, why)
        : throw new SsaAdapterException("A type definition that is not in this module's table");

    // Outer-to-inner nesting chain of a definition (bounded).
    private List<ITypeDefinition> Chain(ITypeDefinition type)
    {
        var chain = new List<ITypeDefinition>();
        for (ITypeDefinition? t = type; t is not null; t = (t as INestedTypeDefinition)?.ContainingTypeDefinition)
        {
            if (chain.Count >= universe.Bounds.MaxDepth)
                throw new SsaAdapterException("The nesting chain is too deep", kind: SsaFailureKind.Bounds);
            chain.Insert(0, t);
        }
        return chain;
    }

    private static uint Token(object entity) =>
        entity is IMetadataObjectWithToken { TokenValue: var token } && token != uint.MaxValue
            ? token
            : throw new SsaAdapterException("A definition without a metadata token");

    // Every source answer is memoised, failures too, and runs in its own CCI assertion scope: an answer read through a
    // failed assertion is never published. Assertions a member list already charged to one member (see LoadMethodsCore)
    // are excused. Nesting is bounded universe-wide, and the stack checked, so no recursion through Cilica's lazy getters
    // (a constraint chain, an enum or base cycle) can overflow it.
    // A module whose primitive types cannot be trusted (CoreProblem) answers nothing, to its own methods or to others.
    // A failure is memoised by an exception filter, never caught here: it unwinds once, however deep the nesting (a catch
    // and throw at every level re-dispatches it on an ever deeper stack). Only an exception that carries no kind is
    // wrapped, once, where it was raised, so every read of the same answer fails the same way.
    private T Memo<T>(object key, Func<Excused, T> read)
    {
        if (CoreProblem is { } problem)
            throw new SsaAdapterException($"Its assembly's primitive types cannot be trusted: {problem}");
        if (memo.TryGetValue(key, out var known))
            return known is ExceptionBox box ? throw Rethrow(box.Exception) : (T)known!;
        try
        {
            RuntimeHelpers.EnsureSufficientExecutionStack();
            using var nesting = universe.Sources.Enter();
            using var reads = CciAssertions.BeginScope();
            var excused = new Excused();
            T value;
            try
            {
                value = read(excused);
            }
            catch (Exception ex) when (ex is not (UnresolvedFactException or SsaAdapterException or OutOfMemoryException or InsufficientExecutionStackException))
            {
                throw Rethrow(ex);
            }
            if (reads.Count - excused.Count > 0)
                throw new SsaAdapterException($"CCI failed {reads.Count - excused.Count} assertion(s) reading it", kind: SsaFailureKind.ReaderAssertion);
            memo[key] = value;
            return value;
        }
        catch (Exception ex) when (Remember(key, ex))
        {
            throw; // never reached: Remember returns false
        }
    }

    private bool Remember(object key, Exception ex)
    {
        if (ex is not (OutOfMemoryException or InsufficientExecutionStackException or SsaAdapterException { IsPathDependent: true }))
            memo.TryAdd(key, new ExceptionBox(ex));
        return false;
    }

    // A memoised failure is re-raised as itself when it carries a kind, else wrapped (the stack trace is the re-raise's).
    private static Exception Rethrow(Exception ex) => ex switch
    {
        UnresolvedFactException or SsaAdapterException => ex,
        _ => new SsaAdapterException(ex.Message, ex, SsaFailureKind.Unreadable),
    };

    private static T? Guard<T>(Func<T?> read) where T : class
    {
        try { return read(); }
        catch (Exception) { return null; }
    }
    #endregion

    #region Fields
    private readonly SsaUniverse universe;
    private readonly bool isFolder;

    private readonly Dictionary<INamedTypeDefinition, TypeDef> types = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<TypeDef, INamedTypeDefinition> cciTypes = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<INamedTypeDefinition, Exception> undefinable = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<(object, string?, string)> ambiguous = new();
    private readonly Dictionary<IMethodDefinition, MethodDef> methods = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<MethodDef, IMethodDefinition> cciMethods = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<IMethodDefinition, Exception> omittedMethods = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<IFieldDefinition, FieldDef> fields = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<IFieldDefinition, Exception> omittedFields = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<TypeDef, Dictionary<string, Exception>> omittedNames = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<object, object?> memo = new();
    private readonly HashSet<TypeDef> validating = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<(int, uint, int), byte[]?> mappedData = new();
    private long mappedBytes;
    #endregion

    #region Child types
    private enum Load { Base, GenericParams, Constraints, Fields, Methods, Interfaces, MethodImpls }

    private sealed record ExceptionBox(Exception Exception);

    /// <summary>CCI assertions a read has already charged to a part of it (one member of a list), not to the whole.</summary>
    private sealed class Excused
    {
        public int Count { get; set; }
    }
    #endregion
}
