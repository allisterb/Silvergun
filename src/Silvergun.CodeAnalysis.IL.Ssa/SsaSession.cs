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
/// On untrusted packages this runs only inside the graph worker (ADR 0021). While a session is open, a process-wide trap
/// turns a Debug build's failed asserts into exceptions (<see cref="CilicaAssertionException"/>); disposing the last open
/// session removes it, so code running after SSA behaves as without it.
/// </remarks>
public sealed class SsaSession : IDisposable
{
    #region Constructors
    private SsaSession(SsaUniverse universe, IReadOnlyList<SsaAssembly> assemblies, IReadOnlyList<(CciModuleSource Source, IMethodDefinition[] Methods)> modules, IDisposable assertions)
    {
        this.universe = universe;
        Assemblies = assemblies;
        this.modules = modules;
        this.assertions = assertions;
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
        var assertions = CilicaAssertions.Acquire();
        SsaUniverse? universe = null;
        try
        {
            universe = new SsaUniverse((bounds ?? SsaBounds.Default).Validated());
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
            return new SsaSession(universe, assemblies, modules, assertions);
        }
        catch
        {
            try
            {
                universe?.Dispose();
            }
            finally
            {
                assertions.Dispose();
            }
            throw;
        }
    }

    /// <summary>
    /// Every method with a body, of every assembly that was read, in a fixed order (assembly path, then metadata order):
    /// verified SSA, or Unknown with the reason. A method with no body is not listed. In a spent session (see
    /// <see cref="Lift(Func{MethodIdentity, bool}, CancellationToken)"/>) every method is TimedOut.
    /// </summary>
    public IEnumerable<SsaMethodOutcome> Lift()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        foreach (var (source, methods) in modules)
        {
            foreach (var method in methods)
            {
                if (Lift(source, method, CciNames.Of(method), default) is { } outcome)
                    yield return outcome;
            }
        }
    }

    /// <summary>
    /// The methods <paramref name="select"/> accepts, lifted lazily as <see cref="Lift()"/> would, ordinal by node id and
    /// then in <see cref="Lift()"/>'s order, so all definitions sharing a node id come together. Each body is the caller's
    /// to drop once read. Once <paramref name="cancellation"/> is cancelled, the method being lifted, and each one after,
    /// is Unknown with <see cref="SsaFailureKind.TimedOut"/>. It is checked as each type is mapped, each instruction
    /// imported, and between stages; verification and SSA promotion are not interrupted. A cancellation that lands after
    /// adaptation began may be memoised as a failure inside the adapter, so the session is then spent: every later lift,
    /// with or without a token, is TimedOut too.
    /// </summary>
    public IEnumerable<SsaMethodOutcome> Lift(Func<MethodIdentity, bool> select, CancellationToken cancellation = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var selected = modules
            .SelectMany(m => m.Methods.Select(method => (m.Source, Method: method, Identity: CciNames.Of(method))))
            .Where(c => select(c.Identity))
            .OrderBy(c => CanonicalName.NodeId(c.Identity), StringComparer.Ordinal)
            .ToArray();
        return Lifted(selected, cancellation);
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        // The lease goes whatever the readers do, so the trap never outlives the session.
        try
        {
            universe.Dispose();
        }
        finally
        {
            assertions.Dispose();
        }
    }

    private IEnumerable<SsaMethodOutcome> Lifted((CciModuleSource Source, IMethodDefinition Method, MethodIdentity Identity)[] selected, CancellationToken cancellation)
    {
        foreach (var (source, method, identity) in selected)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (Lift(source, method, identity, cancellation) is { } outcome)
                yield return outcome;
        }
    }

    private SsaMethodOutcome? Lift(CciModuleSource source, IMethodDefinition method, MethodIdentity identity, CancellationToken cancellation)
    {
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

        if (spent)
            return Unknown(SsaFailureKind.TimedOut, "An earlier lift in this session was cut by its deadline while adapting, so what the session read may be partial");

        var stage = SsaFailureKind.Adapter;
        var adapting = false;
        using var reads = CciAssertions.BeginScope();
        universe.Cancellation = cancellation;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            adapting = true;
            var definition = source.Method(method);
            if (definition.ILBody is null)
                return Unknown(SsaFailureKind.Adapter, "The body could not be adapted");
            stage = SsaFailureKind.Import;
            var offsets = new Dictionary<Cilica.IR.Instruction, int>(ReferenceEqualityComparer.Instance);
            var body = ILImporter.ParseCode(definition, offsets, cancellation);
            stage = SsaFailureKind.Verify;
            cancellation.ThrowIfCancellationRequested();
            IRVerifier.Verify(body);
            stage = SsaFailureKind.Ssa;
            cancellation.ThrowIfCancellationRequested();
            PassRunner.Run(new SsaPromotion(), new MethodTransformContext(CompilationOf(definition.Module), body));
            stage = SsaFailureKind.VerifyAfterSsa;
            cancellation.ThrowIfCancellationRequested();
            IRVerifier.Verify(body);
            // Verify and promotion load lazily; a cancellation the adapter swallowed there may have truncated what they read.
            cancellation.ThrowIfCancellationRequested();
            return reads.Count > 0
                ? Unknown(SsaFailureKind.ReaderAssertion, $"CCI failed {reads.Count} assertion(s) reading what the method needs")
                : new SsaMethodOutcome(source.Path, token, identity, null, body) { ILOffsets = Surviving(offsets, body) };
        }
        // Cancelled however it surfaced (Cilica or the adapter may wrap it): the deadline, not the input, stopped it.
        catch (Exception ex) when (ex is not OutOfMemoryException && cancellation.IsCancellationRequested)
        {
            spent |= adapting;
            return Unknown(SsaFailureKind.TimedOut, $"The lift's deadline passed while it ran ({stage})");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Unknown(Classify(ex, stage), Describe(ex));
        }
        finally
        {
            universe.Cancellation = default;
        }
    }

    // The offsets of the instructions still in the body: promotion removes slot loads and stores the importer recorded.
    private static Dictionary<Cilica.IR.Instruction, int> Surviving(Dictionary<Cilica.IR.Instruction, int> offsets, Cilica.IR.MethodBody body)
    {
        var surviving = new Dictionary<Cilica.IR.Instruction, int>(offsets.Count, ReferenceEqualityComparer.Instance);
        foreach (var instruction in body.Instructions())
        {
            if (offsets.TryGetValue(instruction, out var offset))
                surviving[instruction] = offset;
        }
        return surviving;
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
    private readonly IDisposable assertions;
    private readonly IReadOnlyList<(CciModuleSource Source, IMethodDefinition[] Methods)> modules;
    private readonly Dictionary<ModuleDef, Compilation> compilations = new(ReferenceEqualityComparer.Instance);
    private bool disposed;

    // Set once a lift is cancelled after adaptation began: the adapter's memos may hold the cancellation as a failure.
    private bool spent;
    #endregion
}
