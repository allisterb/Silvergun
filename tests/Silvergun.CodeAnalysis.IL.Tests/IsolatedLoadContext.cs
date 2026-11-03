namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;

/// <summary>
/// A collectible <see cref="AssemblyLoadContext"/> that binds each assembly name in its map to one file — so the
/// test, not probing, decides which variant of an emitted assembly a reference lands in — and everything else to the
/// default context. Every assembly is loaded FROM BYTES, so no file stays locked and the owning
/// <see cref="EmittedAssembly"/> can still delete its directory. Disposing unloads the context.
/// <para>
/// Only for assemblies the test itself emitted: this is how the CLR is used as the oracle for which definition a
/// reference binds at run time (and how a caller is emitted against a stub without loading the stub into the
/// default context, where it could never be unloaded).
/// </para>
/// </summary>
internal sealed class IsolatedLoadContext : AssemblyLoadContext, IDisposable
{
    #region Constructors
    public IsolatedLoadContext(IReadOnlyDictionary<string, string>? paths = null)
        : base($"silvergun-isolated-{Guid.NewGuid():N}", isCollectible: true) =>
        this.paths = paths ?? new Dictionary<string, string>();
    #endregion

    #region Methods
    /// <summary>Loads the assembly at <paramref name="path"/> into this context from its bytes.</summary>
    public Assembly LoadBytes(string path)
    {
        using var stream = new MemoryStream(File.ReadAllBytes(path));
        return LoadFromStream(stream);
    }

    public void Dispose() => Unload();

    protected override Assembly? Load(AssemblyName name) =>
        name.Name is { } simple && paths.TryGetValue(simple, out var path) ? LoadBytes(path) : null;
    #endregion

    #region Fields
    private readonly IReadOnlyDictionary<string, string> paths;
    #endregion
}
