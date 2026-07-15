namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using CCIProvider;
using Model.Types;
using Backend.Analyses;
using Backend.Transformations;

/// <summary>
/// Loads a .NET assembly via Analysis.Net, enumerates its types and methods, disassembles
/// method bodies to three-address code (TAC), and builds control-flow graphs. Per ADR 0001,
/// the public API exposes Analysis.Net <c>Model</c>/<c>Backend.Model</c> types directly.
/// Obtain an instance through the <see cref="Create"/> factory; the constructor is private.
/// </summary>
/// <remarks>Instances are not thread-safe; use a single instance from a single thread.</remarks>
public sealed class AssemblyAnalyzer : Runtime, IDisposable
{
    #region Constructors
    private AssemblyAnalyzer(Model.Host host, Loader loader, Model.Assembly assembly, string assemblyPath)
    {
        Host = host;
        this.loader = loader;
        Assembly = assembly;
        AssemblyPath = assemblyPath;
    }
    #endregion

    #region Properties
    /// <summary>The Analysis.Net host the target assembly (and platform types) are resolved into.</summary>
    public Model.Host Host { get; }

    /// <summary>The loaded target assembly.</summary>
    public Model.Assembly Assembly { get; }

    /// <summary>Absolute path of the loaded assembly file.</summary>
    public string AssemblyPath { get; }

    /// <summary>All type definitions in the assembly's root namespace, recursively.</summary>
    public IEnumerable<ITypeDefinition> Types => Assembly.RootNamespace.GetAllTypes();

    /// <summary>All method definitions across <see cref="Types"/> that have a body.</summary>
    public IEnumerable<MethodDefinition> Methods =>
        Types.SelectMany(t => t.Members.OfType<MethodDefinition>()).Where(m => m.HasBody);
    #endregion

    #region Methods
    /// <summary>
    /// Validates the file exists, creates a <see cref="Model.Host"/>, resolves the platform types,
    /// creates a <see cref="Loader"/>, and loads the assembly. Never throws: any failure (bad path,
    /// not a managed PE, CCI failure) is returned as a failure <see cref="Result{T}"/>.
    /// </summary>
    public static Result<AssemblyAnalyzer> Create(string assemblyPath)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath) || !File.Exists(assemblyPath))
            return Result.FailureWithError<AssemblyAnalyzer>($"Assembly file not found: {assemblyPath}.");

        var fullPath = assemblyPath;
        using var op = Begin("Loading assembly {0}", fullPath);
        Loader? loader = null;
        try
        {
            fullPath = Path.GetFullPath(assemblyPath);
            var host = new Model.Host();
            PlatformTypes.Resolve(host);
            loader = new Loader(host);
            var assembly = loader.LoadAssembly(fullPath);
            op.Complete();
            return Result.Success(new AssemblyAnalyzer(host, loader, assembly, fullPath));
        }
        catch (Exception ex)
        {
            loader?.Dispose();
            return Result.FailureWithError<AssemblyAnalyzer>($"Failed to load assembly {fullPath}.", ex);
        }
    }

    /// <summary>
    /// Lifts <paramref name="method"/>'s body to TAC via <see cref="Disassembler"/> and assigns it back.
    /// Idempotent: if the body is already <see cref="MethodBodyKind.ThreeAddressCode"/> the existing
    /// instance is returned unchanged. Never throws; failures are returned as a failure result.
    /// </summary>
    public Result<MethodBody> DisassembleMethod(MethodDefinition method)
    {
        if (method.Body is null)
            return Result.FailureWithError<MethodBody>($"Method {method.Name} has no body to disassemble.");

        if (method.Body.Kind == MethodBodyKind.ThreeAddressCode)
            return Result.Success(method.Body);

        try
        {
            var body = new Disassembler(method).Execute();
            method.Body = body;
            return Result.Success(body);
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<MethodBody>($"Failed to disassemble method {method.Name}.", ex);
        }
    }

    /// <summary>
    /// Ensures <paramref name="method"/> is in TAC (via <see cref="DisassembleMethod"/>) then builds its
    /// exceptional control-flow graph. Cached per <see cref="MethodDefinition"/> by reference, so repeated
    /// calls for the same method return the same <see cref="Backend.Model.ControlFlowGraph"/> instance.
    /// </summary>
    public Result<Backend.Model.ControlFlowGraph> ControlFlowGraph(MethodDefinition method)
    {
        if (cfgCache.TryGetValue(method, out var cached))
            return Result.Success(cached);

        var tac = DisassembleMethod(method);
        if (!tac.IsSuccess)
            return Result.Failure<Backend.Model.ControlFlowGraph>(tac.Message, tac.Exception);

        try
        {
            var cfg = new ControlFlowAnalysis(tac.Value).GenerateExceptionalControlFlow();
            cfgCache[method] = cfg;
            return Result.Success(cfg);
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<Backend.Model.ControlFlowGraph>(
                $"Failed to build control-flow graph for method {method.Name}.", ex);
        }
    }

    /// <summary>Disposes the underlying loader. Idempotent.</summary>
    public void Dispose()
    {
        if (disposed) return;
        loader.Dispose();
        disposed = true;
    }
    #endregion

    #region Fields
    private readonly Loader loader;

    // Reference-equality cache so distinct MethodDefinition instances never collide.
    private readonly Dictionary<MethodDefinition, Backend.Model.ControlFlowGraph> cfgCache =
        new(ReferenceEqualityComparer.Instance);

    private bool disposed;
    #endregion
}
