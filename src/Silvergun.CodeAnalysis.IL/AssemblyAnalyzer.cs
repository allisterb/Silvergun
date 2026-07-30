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
    /// The <b>candidate</b> set for a body read: every method definition across
    /// <see cref="IModule.GetAllTypes"/> (nested and compiler-generated types included) that is neither
    /// abstract nor external, i.e. every method that <em>may</em> carry an IL body. Both predicates are pure
    /// metadata flags, so enumerating this sequence never dereferences <see cref="IMethodDefinition.Body"/>
    /// — a candidate may still turn out to have no body (<see cref="Dummy.MethodBody"/>) or an
    /// <em>unreadable</em> one on a crafted module.
    /// <para>
    /// Read the body with <see cref="TryReadBody"/>: the dereference then happens per method, inside
    /// <see cref="TryReadBody"/>'s own guard, before the consumer's <c>try</c>. Dereferencing <c>Body</c> from the
    /// filter itself would instead make one hostile method body throw during enumeration and cost the caller the
    /// whole assembly rather than one method.
    /// Enumeration can still throw (it advances CCI's lazy type resolution), which is a genuinely
    /// assembly-wide failure and remains the consumer's outer-catch backstop.
    /// </para>
    /// </summary>
    public IEnumerable<IMethodDefinition> Methods =>
        Module.GetAllTypes()
            .SelectMany(type => type.Methods)
            .Where(m => !m.IsAbstract && !m.IsExternal);
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

    /// <summary>
    /// Best-effort method name (<c>&lt;unreadable&gt;</c> when the metadata read throws) — the same class of seam as
    /// <see cref="TryReadBody"/>: <c>method.Name.Value</c> is itself a metadata read a crafted module can make throw,
    /// so naming a method from inside the guard that is already reporting a failure must not be able to throw again
    /// and escape it. Use it wherever a name is needed for a skip reason or a warning. Never throws.
    /// </summary>
    public static string SafeName(IMethodDefinition method)
    {
        try
        {
            return method.Name.Value;
        }
        catch
        {
            return UnreadableName;
        }
    }

    /// <summary>
    /// Guarded per-method body read — the seam every consumer of <see cref="Methods"/> must go through, so a
    /// hostile body costs one method instead of the whole assembly. <c>Body</c> is a raw IL/metadata read
    /// (<c>PEFileReader.GetMethodIL</c>) that a crafted module can make throw, e.g. a fat header whose
    /// <c>CodeSize</c> runs past the section. Never throws; returns exactly one of three outcomes:
    /// <list type="bullet">
    /// <item><description><see cref="MethodBodyRead.IsMissing"/> — the method has no IL body
    /// (<see cref="Dummy.MethodBody"/>, <c>null</c>, or it is abstract/external). It is <em>not</em> a skip and
    /// must not count towards a method total. The <c>null</c> case is the sole known divergence from the
    /// body-dereferencing filter this replaced: there a null <c>Body</c> passed the <c>!= Dummy.MethodBody</c>
    /// test and became a <em>skip</em> via the NullReferenceException its <c>.Operations</c> read then threw,
    /// where it now leaves the denominator silently. CCI has not been observed to produce it (a 17-assembly
    /// corpus was diff-free).</description></item>
    /// <item><description><see cref="MethodBodyRead.IsUnreadable"/> — the read threw;
    /// <see cref="MethodBodyRead.Error"/> carries the exception message for the skip reason.</description></item>
    /// <item><description>otherwise <see cref="MethodBodyRead.Body"/> is the readable body.</description></item>
    /// </list>
    /// </summary>
    public static MethodBodyRead TryReadBody(IMethodDefinition method)
    {
        try
        {
            // The flags are re-checked here (Methods already filters on them) because reading Body is only
            // valid for non-abstract/non-external methods and this helper is callable on any method.
            if (method.IsAbstract || method.IsExternal)
                return default;

            var body = method.Body;
            return body is null || body == Dummy.MethodBody ? default : new MethodBodyRead(body, null);
        }
        catch (Exception ex)
        {
            return new MethodBodyRead(null, ex.Message);
        }
    }

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

    private const string UnreadableName = "<unreadable>";
    #endregion

    #region Child types
    /// <summary>
    /// The outcome of <see cref="TryReadBody"/>: a readable <see cref="Body"/>, or no body at all
    /// (both members null — <see cref="IsMissing"/>), or a failed read carrying the exception message in
    /// <see cref="Error"/> (<see cref="IsUnreadable"/>). The two failure shapes are deliberately
    /// distinct: "no body" is normal and must stay out of a method total, while "unreadable" is a skip that
    /// must be counted and reported (ADR-0024 completeness).
    /// <para>
    /// <b>Invariant: <see cref="Body"/> and <see cref="Error"/> are never both non-null</b> — exactly three states
    /// exist, and a value that was both readable and unreadable would be scanned <em>and</em> reported as a skip by
    /// consumers (both branch on <c>Body is null</c>). The invariant is <b>structural</b>, not conventional:
    /// <see cref="IsUnreadable"/> itself requires <c>Body is null</c>, so no reachable value is ever both scanned and
    /// skipped, whoever constructed it, and the property agrees with the <c>Body is null</c> test the consumers
    /// actually branch on. The <c>internal</c> constructor is defence in depth on top of that — it does not enforce
    /// the invariant, it only keeps construction inside this assembly, where <see cref="TryReadBody"/> is its sole
    /// caller.
    /// </para>
    /// </summary>
    public readonly record struct MethodBodyRead
    {
        #region Constructors
        internal MethodBodyRead(IMethodBody? body, string? error) => (Body, Error) = (body, error);
        #endregion

        #region Properties
        /// <summary>The readable body, or null when the method has none or the read threw.</summary>
        public IMethodBody? Body { get; }

        /// <summary>The exception message when the read threw, otherwise null.</summary>
        public string? Error { get; }

        /// <summary>The method has no IL body — neither scanned nor skipped.</summary>
        public bool IsMissing => Body is null && Error is null;

        /// <summary>
        /// The body dereference threw and yielded no body; <see cref="Error"/> holds the exception message.
        /// The <c>Body is null</c> conjunct is what makes the invariant above structural.
        /// </summary>
        public bool IsUnreadable => Body is null && Error is not null;
        #endregion
    }
    #endregion
}
