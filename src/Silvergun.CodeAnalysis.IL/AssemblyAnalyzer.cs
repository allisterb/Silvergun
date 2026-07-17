namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.Cci;

/// <summary>
/// A reusable CCI-loaded module (ADR 0009) — the shared foundation the scan-layer analyses read
/// directly, rather than through Analysis.Net's <c>Model</c>. Loads via a fresh
/// <see cref="PeReader.DefaultHost"/> per <see cref="Load"/> (the same pattern <see cref="AssemblyMetadata"/>
/// established): the host allocates its own <c>NameTable</c>/<c>InternFactory</c>, so a raw metadata read
/// touches no process-wide mutable CCI statics and needs no load lock (unlike <see cref="AssemblyDisassembler"/>,
/// whose Analysis.Net loader mutates shared static caches). <see cref="Load"/> never throws;
/// <see cref="Dispose"/> disposes the host and is idempotent.
/// </summary>
public sealed class AssemblyAnalyzer : Runtime, IDisposable
{
    #region Constructors
    private AssemblyAnalyzer(PeReader.DefaultHost host, IModule module, string assemblyPath)
    {
        this.host = host;
        Module = module;
        AssemblyPath = assemblyPath;
        AssemblyName = module.ContainingAssembly.Name.Value;
    }
    #endregion

    #region Properties
    /// <summary>Simple name of the loaded assembly (<c>module.ContainingAssembly.Name.Value</c>).</summary>
    public string AssemblyName { get; }

    /// <summary>Absolute path of the loaded assembly file.</summary>
    public string AssemblyPath { get; }

    /// <summary>The loaded CCI module.</summary>
    public IModule Module { get; }

    /// <summary>
    /// Every method definition across <see cref="IModule.GetAllTypes"/> (nested and compiler-generated
    /// types included) that has an IL body — i.e. is neither abstract nor external and whose
    /// <see cref="IMethodDefinition.Body"/> is not <see cref="Dummy.MethodBody"/>. Accessing <c>Body</c> is
    /// only valid for non-abstract/non-external methods, so those guards are evaluated first.
    /// </summary>
    public IEnumerable<IMethodDefinition> Methods =>
        Module.GetAllTypes()
            .SelectMany(type => type.Methods)
            .Where(m => !m.IsAbstract && !m.IsExternal && m.Body != Dummy.MethodBody);
    #endregion

    #region Methods
    /// <summary>
    /// Loads <paramref name="assemblyPath"/> via a fresh <see cref="PeReader.DefaultHost"/> and wraps its CCI
    /// <see cref="IModule"/>. Returns a failure <see cref="Result{T}"/> (never throws) when the file is missing
    /// or is not a valid CLR module/assembly; on failure the host is disposed before returning.
    /// </summary>
    public static Result<AssemblyAnalyzer> Load(string assemblyPath)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath) || !File.Exists(assemblyPath))
            return Result.Failure<AssemblyAnalyzer>($"Assembly file '{assemblyPath}' does not exist.");

        PeReader.DefaultHost? host = null;
        try
        {
            // A fresh DefaultHost is instance-scoped (its own NameTable + InternFactory), so this load
            // touches no process-wide mutable CCI statics — safe to run concurrently without a lock.
            host = new PeReader.DefaultHost();
            var module = host.LoadUnitFrom(Path.GetFullPath(assemblyPath)) as IModule;

            // Mirrors CCIProvider/Loader.cs:57 — reject non-CLR / unresolvable inputs.
            if (module is null || module == Dummy.Module || module.ContainingAssembly is null || module.ContainingAssembly == Dummy.Assembly)
            {
                host.Dispose();
                return Result.Failure<AssemblyAnalyzer>($"The file '{assemblyPath}' is not a valid CLR module or assembly.");
            }

            return Result.Success(new AssemblyAnalyzer(host, module, Path.GetFullPath(assemblyPath)));
        }
        catch (Exception ex)
        {
            host?.Dispose();
            return Result.Failure<AssemblyAnalyzer>($"Could not load assembly '{assemblyPath}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Namespace-qualified full name of a type reference (e.g. <c>System.IO.File</c>), matching the format the
    /// scan analyses emit and the strings the catalog matches against. Uses <see cref="TypeHelper.GetTypeName"/>
    /// with <see cref="NameFormattingOptions.None"/> — the same options <see cref="AssemblyMetadata"/> uses —
    /// which omits assembly qualification and generic-arity/parameter noise. Empty namespaces are handled by CCI.
    /// </summary>
    public static string TypeName(ITypeReference type) => TypeHelper.GetTypeName(type, NameFormattingOptions.None);

    /// <summary>Disposes the underlying CCI host. Idempotent.</summary>
    public void Dispose()
    {
        if (disposed) return;
        host.Dispose();
        disposed = true;
    }
    #endregion

    #region Fields
    private readonly PeReader.DefaultHost host;
    private bool disposed;
    #endregion
}
