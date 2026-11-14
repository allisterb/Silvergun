namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

using Cilica.AsmIO;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// One Cilica resolver universe per package folder (one thread). Every module is created over an <see cref="IModuleSource"/>
/// (Cilica's own reader never runs on input). An assembly name binds, in order, to:
/// <list type="number">
/// <item><description>the host runtime's framework assembly of that name (CoreLib included), read through CCI; facades
/// resolve through their exported-type rows, never through in-package copies;</description></item>
/// <item><description>the folder's assembly of that name (the first by path, if names repeat);</description></item>
/// <item><description>a stub (ruling D3).</description></item>
/// </list>
/// Folder modules are cached under a name no framework or stub module can take, so a package cannot impersonate CoreLib.
/// The framework is the directory of the running CoreLib: a self-contained or single-file host is not supported.
/// </summary>
internal sealed class SsaUniverse : ModuleResolver
{
    #region Constructors
    public SsaUniverse(SsaBounds bounds) : base(null)
    {
        Bounds = bounds;
        framework = managedFramework.Value;
        Sources = new Nesting(bounds.MaxNesting, "Source reads nested");
        Bases = new Nesting(bounds.MaxDepth, "Base-type validations nested");
        Forwarders = new Nesting(bounds.MaxForwarderHops, "Type-forwarder hops");
    }
    #endregion

    #region Properties
    public SsaBounds Bounds { get; }

    /// <summary>Source answers in progress, one inside another (bounds every recursion through Cilica's lazy getters).</summary>
    public Nesting Sources { get; }

    /// <summary>Base-type chain validations in progress.</summary>
    public Nesting Bases { get; }

    /// <summary>Type-forwarder hops in progress.</summary>
    public Nesting Forwarders { get; }

    /// <summary>The lift in progress's deadline, checked as each type is mapped (<see cref="SsaSession.Lift(Func{MethodIdentity, bool}, CancellationToken)"/>).</summary>
    public CancellationToken Cancellation { get; set; }
    #endregion

    #region Methods
    /// <summary>The module an assembly reference of this name binds to.</summary>
    /// <remarks>A framework name never binds to the folder, even if the framework copy cannot be read: it is a stub then.</remarks>
    public ModuleDef ModuleFor(string assemblyName) =>
        IsFramework(assemblyName) ? Resolve(assemblyName, throwIfNotFound: false) ?? Stub(assemblyName).Module
        : folder.TryGetValue(assemblyName, out var source) ? source.Module
        : Stub(assemblyName).Module;

    /// <summary>Whether the name is a managed assembly of the host runtime directory (decided once, never by what was read).</summary>
    public bool IsFramework(string assemblyName) => framework.ContainsKey(assemblyName);

    public bool IsStub(ModuleDef module) => stubModules.Contains(module);

    public bool IsStubType(TypeDesc type) => type is TypeDefOrSpec t && t is not UnknownSupertype && stubModules.Contains(t.Module);

    /// <summary>A top-level type of the named assembly; throws <see cref="UnresolvedFactException"/> if it has none, or two.</summary>
    public TypeDef TopLevel(string assemblyName, string? ns, string name)
    {
        var module = ModuleFor(assemblyName);
        var display = (ns is null ? "" : ns + ".") + name;
        if (cciSources.TryGetValue(module, out var source) && source.IsAmbiguous(null, ns, name))
            throw new UnresolvedFactException(UnresolvedFact.Type, display, $"defined more than once in '{assemblyName}'");
        return module.FindType(ns, name) ?? throw new UnresolvedFactException(UnresolvedFact.Type, display, $"not in '{assemblyName}'");
    }

    /// <summary>The type nested in <paramref name="parent"/> named <paramref name="name"/>; stubs grow one on demand.</summary>
    public TypeDef Nested(TypeDef parent, string name)
    {
        if (stubModules.Contains(parent.Module))
            return stubSources[parent.Module].Nested(parent, name);
        var display = StubModuleSource.DisplayName(parent) + "/" + name;
        if (cciSources.TryGetValue(parent.Module, out var source) && source.IsAmbiguous(parent, null, name))
            throw new UnresolvedFactException(UnresolvedFact.Type, display, "defined more than once");
        return parent.FindNestedType(name) ?? throw new UnresolvedFactException(UnresolvedFact.Type, display);
    }

    public StubModuleSource StubSource(ModuleDef module) => stubSources[module];

    /// <summary>
    /// Marks a forwarded lookup of <paramref name="ns"/>.<paramref name="name"/> in <paramref name="module"/> as in progress;
    /// false if it already is (the forwarders form a cycle). Dispose <paramref name="scope"/> to end it.
    /// </summary>
    public bool TryForwarding(ModuleDef module, string? ns, string name, out ForwardingScope scope)
    {
        var key = ((object)module, ns, name);
        var added = forwarding.Add(key);
        // A refused lookup gets an inert scope: disposing it must not end the outer lookup that holds the key.
        scope = added ? new ForwardingScope(forwarding, key) : default;
        return added;
    }

    /// <summary>Why the CCI module defining <paramref name="type"/> left a member of this name out, or null if it did not.</summary>
    public Exception? Omitted(TypeDef type, string name) => cciSources.TryGetValue(type.Module, out var source) ? source.OmittedReason(type, name) : null;

    /// <summary>
    /// The CLASS/VALUETYPE encodings the folder's signatures use for references to this stub type, by its assembly, namespace
    /// and nesting; both, or neither, proves nothing.
    /// </summary>
    public TypeEncoding StubEncoding(TypeDef type, string assemblyName)
    {
        var chain = new List<string>();
        var outer = type;
        for (var t = type; t is not null && chain.Count <= Bounds.MaxDepth; t = t.DeclaringType)
        {
            chain.Insert(0, t.Name);
            outer = t;
        }
        var encoding = encodings.GetValueOrDefault(MetadataFacts.EncodingKey(assemblyName, outer.Namespace, string.Join("/", chain)));
        return encoding is TypeEncoding.Class or TypeEncoding.ValueType ? encoding : TypeEncoding.None;
    }

    /// <summary>
    /// Reads one folder assembly and adds it under a private cache name. Returns the source, or null with
    /// <paramref name="error"/> when the assembly is lost whole.
    /// </summary>
    public CciModuleSource? AddFolderAssembly(string path, int index, out string? error)
    {
        var source = Open(path, isFolder: true, out error);
        if (source is null)
            return null;
        try
        {
            var name = source.Cci.AssemblyName;
            var module = Create(new AssemblyName { Name = $"{name} [{index}]", Version = source.Version }, source, Path.GetFileName(path));
            cciSources.Add(module, source);
            source.Attach(module);
            if (!framework.ContainsKey(name))
                folder.TryAdd(name, source);
            folderSources.Add(source);
            return source;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            error = $"Could not build its type table: {ex.Message}";
            if (source.Module is null)
                source.Dispose();
            return null;
        }
    }

    /// <summary>Scans every folder assembly's signatures for TypeRef encodings; call once, after the folder is added.</summary>
    public void ScanEncodings()
    {
        foreach (var source in folderSources)
        {
            // A module with a blob the scan could not read marks its own TypeRefs conflicting (MetadataFacts.ScanEncodings).
            foreach (var (key, encoding) in source.Facts.ScanEncodings(Bounds))
                encodings[key] = encodings.GetValueOrDefault(key) | encoding;
        }
    }

    protected override ModuleDef? ResolveImpl(string name)
    {
        if (!framework.TryGetValue(name, out var path) || unreadableFramework.Contains(name))
            return null;
        var source = Open(path, isFolder: false, out _);
        if (source is null)
        {
            // Remember the miss rather than re-read the file for every reference.
            unreadableFramework.Add(name);
            return null;
        }
        try
        {
            var module = Create(new AssemblyName { Name = Path.GetFileNameWithoutExtension(path), Version = source.Version }, source, Path.GetFileName(path));
            cciSources.Add(module, source);
            source.Attach(module);
            return module;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (source.Module is null)
                source.Dispose();
            throw new SsaAdapterException($"Could not read framework assembly '{name}': {ex.Message}", ex);
        }
    }

    private static bool IsManagedAssembly(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var pe = new System.Reflection.PortableExecutable.PEReader(stream, System.Reflection.PortableExecutable.PEStreamOptions.LeaveOpen);
            return pe.HasMetadata && System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe).IsAssembly;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private StubModuleSource Stub(string assemblyName)
    {
        if (!stubs.TryGetValue(assemblyName, out var source))
        {
            source = new StubModuleSource(this, assemblyName);
            source.Module = Create(new AssemblyName { Name = $"{assemblyName} [stub]" }, source, assemblyName + ".dll");
            stubs.Add(assemblyName, source);
            stubSources.Add(source.Module, source);
            stubModules.Add(source.Module);
        }
        return source;
    }

    private CciModuleSource? Open(string path, bool isFolder, out string? error)
    {
        var cci = AssemblyAnalyzer.Load(path);
        if (!cci.IsSuccess)
        {
            error = cci.Message ?? "Not a readable CLR assembly";
            return null;
        }
        try
        {
            var facts = MetadataFacts.Open(path);
            error = null;
            return new CciModuleSource(this, cci.Value, facts, path, isFolder);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            cci.Value.Dispose();
            error = $"Its metadata tables could not be read: {ex.Message}";
            return null;
        }
    }
    #endregion

    #region Fields
    // The framework: the managed assemblies beside the running CoreLib, probed once per process. Native images there
    // (coreclr, clrjit, ...) are ordinary names, so a folder assembly so named binds like any other and cannot pose as one.
    private static readonly Lazy<Dictionary<string, string>> managedFramework = new(() =>
    {
        var coreLib = typeof(object).Assembly.Location;
        var runtime = coreLib.Length > 0 ? Path.GetDirectoryName(coreLib)! : RuntimeEnvironment.GetRuntimeDirectory();
        return Directory.EnumerateFiles(runtime, "*.dll")
            .Where(IsManagedAssembly)
            .ToDictionary(p => Path.GetFileNameWithoutExtension(p), p => p, StringComparer.OrdinalIgnoreCase);
    });

    private readonly Dictionary<string, string> framework;
    private readonly HashSet<string> unreadableFramework = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, CciModuleSource> folder = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<CciModuleSource> folderSources = new();
    private readonly Dictionary<ModuleDef, CciModuleSource> cciSources = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<string, StubModuleSource> stubs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<ModuleDef, StubModuleSource> stubSources = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<ModuleDef> stubModules = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<(string, string?, string), TypeEncoding> encodings = new();
    private readonly HashSet<(object, string?, string)> forwarding = new();
    #endregion

    #region Child types
    /// <summary>Ends a forwarded lookup (<see cref="TryForwarding"/>).</summary>
    internal readonly struct ForwardingScope(HashSet<(object, string?, string)> set, (object, string?, string) key) : IDisposable
    {
        public void Dispose() => set?.Remove(key);
    }

    /// <summary>
    /// A bounded count of nested calls on one thread. <see cref="Enter"/> throws past the bound (a path-dependent failure,
    /// so never memoised) and otherwise returns a scope that undoes exactly its own increment.
    /// </summary>
    internal sealed class Nesting(int max, string what)
    {
        public int Depth { get; private set; }

        public Scope Enter(string? detail = null)
        {
            if (Depth >= max)
                throw new SsaAdapterException($"{what} deeper than {max}" + (detail is null ? "" : $" ({detail})"), kind: SsaFailureKind.Bounds) { IsPathDependent = true };
            Depth++;
            return new Scope(this);
        }

        public readonly struct Scope(Nesting nesting) : IDisposable
        {
            public void Dispose() => nesting.Depth--;
        }
    }
    #endregion
}
