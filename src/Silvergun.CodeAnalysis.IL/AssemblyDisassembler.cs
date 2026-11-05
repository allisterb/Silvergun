namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

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
/// <remarks>
/// <see cref="Create"/> is safe to call concurrently from multiple threads: the load sequence
/// (host creation, platform-type resolution, and <c>LoadAssembly</c>) is serialized on a shared
/// lock because Analysis.Net's loader mutates process-wide static state during traversal
/// (notably <c>CCIProvider.TypeExtractor.attributesCache</c>, a non-concurrent <see cref="Dictionary{TKey,TValue}"/>,
/// and the shared static platform-type instances resolved by <c>Model.Types.PlatformTypes.Resolve</c>).
/// The returned instances are not thread-safe: use a single instance from a single thread, but
/// distinct instances (each with its own host) may be used in parallel.
/// </remarks>
public sealed class AssemblyDisassembler : Runtime, IDisposable
{
    #region Constructors
    private AssemblyDisassembler(Model.Host host, Loader loader, Model.Assembly assembly, string assemblyPath, TypeForwarders forwarders, ModuleMetadata module, int readerAssertions)
    {
        Host = host;
        this.loader = loader;
        Assembly = assembly;
        AssemblyPath = assemblyPath;
        Forwarders = forwarders;
        Module = module;
        ReaderAssertions = readerAssertions;
    }
    #endregion

    #region Properties
    /// <summary>The Analysis.Net host the target assembly (and platform types) are resolved into.</summary>
    public Model.Host Host { get; }

    /// <summary>The loaded target assembly.</summary>
    public Model.Assembly Assembly { get; }

    /// <summary>Absolute path of the loaded assembly file.</summary>
    public string AssemblyPath { get; }

    /// <summary>
    /// The assembly's type forwarders, read from the file at load time: <c>Model</c> does not carry them, and the CLR
    /// follows them (see <see cref="TypeForwarders"/>).
    /// </summary>
    public TypeForwarders Forwarders { get; }

    /// <summary>
    /// The assembly's module initializer and renamed implementations, read from the file at load time: <c>Model</c>
    /// carries neither (see <see cref="ModuleMetadata"/>).
    /// </summary>
    public ModuleMetadata Module { get; }

    /// <summary>
    /// The CCI assertions that failed while the assembly was loaded (ADR 0022 Stage 1). They no longer kill the process;
    /// each is recorded and the read continues, so more than 0 means the model may be degraded.
    /// </summary>
    public int ReaderAssertions { get; }

    /// <summary>All type definitions in the assembly's root namespace, recursively.</summary>
    public IEnumerable<ITypeDefinition> Types => Assembly.RootNamespace.GetAllTypes();

    /// <summary>All method definitions across <see cref="Types"/> that have a body.</summary>
    public IEnumerable<MethodDefinition> Methods =>
        Types.SelectMany(t => t.Members.OfType<MethodDefinition>()).Where(m => m.HasBody);
    #endregion

    #region Methods
    /// <summary>
    /// Validates the file exists, creates a <see cref="Model.Host"/>, resolves the platform types,
    /// creates a <see cref="Loader"/>, and loads the assembly, its <see cref="Forwarders"/> and its <see cref="Module"/>. Never throws: any failure (bad path,
    /// not a managed PE, CCI failure) is returned as a failure <see cref="Result{T}"/>.
    /// </summary>
    public static Result<AssemblyDisassembler> Create(string assemblyPath)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath) || !File.Exists(assemblyPath))
            return Result.FailureWithError<AssemblyDisassembler>($"Assembly file not found: {assemblyPath}.");

        var fullPath = assemblyPath;
        using var op = Begin("Loading assembly {0}", fullPath);
        Loader? loader = null;
        try
        {
            fullPath = Path.GetFullPath(assemblyPath);
            var forwarders = TypeForwarders.Read(fullPath);
            var module = ModuleMetadata.Read(fullPath);
            // Serialize host creation through LoadAssembly: Analysis.Net mutates non-concurrent
            // static state during the load (CCIProvider.TypeExtractor.attributesCache and the shared
            // Model.Types.PlatformTypes instances), so concurrent loads corrupt those collections.
            lock (loadLock)
            {
                // CCIProvider extracts the whole model here, so this is where CCI reads the file and may fail an assertion.
                using var reads = Microsoft.Cci.CciAssertions.BeginScope();
                var host = new Model.Host();
                PlatformTypes.Resolve(host);
                loader = new Loader(host);
                var assembly = loader.LoadAssembly(fullPath);
                if (reads.Count > 0)
                    Warn("Loading {0}: {1} CCI assertion(s) failed and were recorded; the model may be degraded. First: {2}", fullPath, reads.Count, reads.Records[0]);
                op.Complete();
                return Result.Success(new AssemblyDisassembler(host, loader, assembly, fullPath, forwarders, module, reads.Count));
            }
        }
        catch (Exception ex)
        {
            loader?.Dispose();
            return Result.FailureWithError<AssemblyDisassembler>($"Failed to load assembly {fullPath}.", ex);
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
    // Guards the load sequence in Create against concurrent access to Analysis.Net's process-wide
    // non-concurrent static state. Shared across all instances, hence static.
    private static readonly Lock loadLock = new();

    private readonly Loader loader;

    // Reference-equality cache so distinct MethodDefinition instances never collide.
    private readonly Dictionary<MethodDefinition, Backend.Model.ControlFlowGraph> cfgCache =
        new(ReferenceEqualityComparer.Instance);

    private bool disposed;
    #endregion
}
