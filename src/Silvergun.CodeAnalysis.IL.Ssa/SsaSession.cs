namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Cilica;
using Cilica.AsmIO;
using Cilica.Frontend;
using Cilica.IR.Utils;
using Cilica.Passes;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// Lifts the method bodies of one package folder to verified SSA with Cilica, over our CCI reader (ADR 0038 option 2;
/// docs/agent/tasks/ssa-adapter.md). For each method: import, verify, <c>SsaPromotion</c>, verify again. A method that
/// cannot lift is Unknown with a classified reason, and costs nothing else; nothing throws past a method. One thread per
/// session (Cilica's model has no locks); dispose to release the readers.
/// </summary>
/// <remarks>
/// On untrusted packages this runs only inside the graph worker (ADR 0021); until S4 wires it there, only the guarded
/// harness runs it. Opening installs a process-wide trap that turns a Debug build of Cilica's failed asserts into
/// exceptions (<see cref="CilicaAssertionException"/>).
/// </remarks>
public sealed class SsaSession : IDisposable
{
    #region Constructors
    private SsaSession(SsaUniverse universe, IReadOnlyList<SsaAssembly> assemblies, IReadOnlyList<(CciModuleSource Source, IMethodDefinition[] Methods)> modules)
    {
        this.universe = universe;
        Assemblies = assemblies;
        this.modules = modules;
    }
    #endregion

    #region Properties
    /// <summary>The folder's assemblies, ordinal by path: read, or lost whole with the reason.</summary>
    public IReadOnlyList<SsaAssembly> Assemblies { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Reads the folder's assemblies (each through its own CCI host, with the host runtime's framework as their references)
    /// and scans their signatures for the encodings stub types rest on. Throws only if the host runtime's CoreLib cannot be
    /// provisioned, which no input can cause.
    /// </summary>
    public static SsaSession Open(IEnumerable<string> assemblyPaths, SsaBounds? bounds = null)
    {
        CilicaAssertions.Install();
        var universe = new SsaUniverse((bounds ?? SsaBounds.Default).Validated());
        try
        {
            var assemblies = new List<SsaAssembly>();
            var modules = new List<(CciModuleSource, IMethodDefinition[])>();
            var paths = assemblyPaths.Select(Path.GetFullPath).Order(StringComparer.Ordinal)
                .Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal).ToArray();
            for (var index = 0; index < paths.Length; index++)
            {
                var source = universe.AddFolderAssembly(paths[index], index, out var error);
                if (source is null)
                {
                    assemblies.Add(new SsaAssembly(paths[index], null, error));
                    continue;
                }
                try
                {
                    modules.Add((source, source.Cci.Methods.ToArray()));
                    assemblies.Add(new SsaAssembly(paths[index], source.Cci.AssemblyName, null));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    assemblies.Add(new SsaAssembly(paths[index], source.Cci.AssemblyName, "Its methods could not be enumerated: " + ex.Message));
                }
            }
            universe.ScanEncodings();
            _ = universe.SysTypes;
            return new SsaSession(universe, assemblies, modules);
        }
        catch
        {
            universe.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Every method with a body, of every assembly that was read, in a fixed order (assembly path, then metadata order):
    /// verified SSA, or Unknown with the reason. A method with no body is not listed.
    /// </summary>
    public IEnumerable<SsaMethodOutcome> Lift()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        foreach (var (source, methods) in modules)
        {
            foreach (var method in methods)
            {
                if (Lift(source, method) is { } outcome)
                    yield return outcome;
            }
        }
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        universe.Dispose();
    }

    private SsaMethodOutcome? Lift(CciModuleSource source, IMethodDefinition method)
    {
        var identity = CciNames.Of(method);
        var token = method is IMetadataObjectWithToken { TokenValue: var t and not uint.MaxValue } ? t : 0u;
        SsaMethodOutcome Unknown(SsaFailureKind kind, string reason) => new(source.Path, token, identity, new SsaFailure(kind, reason), null);

        var read = AssemblyAnalyzer.TryReadBody(method);
        if (read.IsMissing)
            return null;
        if (read.IsUnreadable)
            return Unknown(SsaFailureKind.Unreadable, read.Error!);
        if (source.TableAssertions > 0)
            return Unknown(SsaFailureKind.ReaderAssertion, $"CCI failed {source.TableAssertions} assertion(s) reading the assembly's type table");
        if (source.CoreProblem is { } core)
            return Unknown(SsaFailureKind.Adapter, $"Its primitive types cannot be trusted: {core}");

        var stage = SsaFailureKind.Adapter;
        using var reads = CciAssertions.BeginScope();
        try
        {
            var definition = source.Method(method);
            if (definition.ILBody is null)
                return Unknown(SsaFailureKind.Adapter, "The body could not be adapted");
            stage = SsaFailureKind.Import;
            var body = ILImporter.ParseCode(definition);
            stage = SsaFailureKind.Verify;
            IRVerifier.Verify(body);
            stage = SsaFailureKind.Ssa;
            PassRunner.Run(new SsaPromotion(), new MethodTransformContext(CompilationOf(definition.Module), body));
            stage = SsaFailureKind.VerifyAfterSsa;
            IRVerifier.Verify(body);
            return reads.Count > 0
                ? Unknown(SsaFailureKind.ReaderAssertion, $"CCI failed {reads.Count} assertion(s) reading what the method needs")
                : new SsaMethodOutcome(source.Path, token, identity, null, body);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Unknown(Classify(ex, stage), Describe(ex));
        }
    }

    private Compilation CompilationOf(ModuleDef module)
    {
        if (!compilations.TryGetValue(module, out var compilation))
            compilations[module] = compilation = new Compilation(module, new VoidLogger(), new CompilationSettings());
        return compilation;
    }

    // The kind an exception carries (an adapter or unresolved-fact failure anywhere in the chain, or a reader assertion)
    // wins over the stage it surfaced in: a stub's unknown base thrown from inside the importer is an unresolved fact.
    internal static SsaFailureKind Classify(Exception ex, SsaFailureKind stage)
    {
        for (var (e, depth) = (ex, 0); e is not null && depth < 8; e = e.InnerException, depth++)
        {
            switch (e)
            {
                case UnresolvedFactException:
                    return SsaFailureKind.UnresolvedFact;
                case SsaAdapterException adapter:
                    return adapter.Kind;
                case CciAssertionException:
                    return SsaFailureKind.ReaderAssertion;
                case InsufficientExecutionStackException:
                    return SsaFailureKind.Bounds;
            }
        }
        return stage;
    }

    private static string Describe(Exception ex)
    {
        var line = ex.Message.Split('\n')[0].Trim();
        var text = $"{ex.GetType().Name}: {line}";
        return text.Length <= MaxReason ? text : text[..MaxReason] + "...";
    }
    #endregion

    #region Fields
    private const int MaxReason = 400;

    private readonly SsaUniverse universe;
    private readonly IReadOnlyList<(CciModuleSource Source, IMethodDefinition[] Methods)> modules;
    private readonly Dictionary<ModuleDef, Compilation> compilations = new(ReferenceEqualityComparer.Instance);
    private bool disposed;
    #endregion
}
