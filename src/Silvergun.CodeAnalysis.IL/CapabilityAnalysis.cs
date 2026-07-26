namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

/// <summary>
/// Scans an assembly for references to sensitive BCL APIs (per the static <see cref="Catalog"/>) and produces a
/// serializable <see cref="CapabilityReport"/>. Detection is catalog-driven and records capability presence, not
/// reachability — see ADR 0002. It reads CCI directly from a <see cref="AssemblyAnalyzer"/> (ADR 0009) — the same
/// bytecode-level view the TAC lifter chokes on for exception-handling-heavy IL (ADR 0005) — so no lifting is
/// involved.
/// <para>Detection has two seams:</para>
/// <list type="number">
/// <item><description><b>Call sites.</b> Each method's <em>CCI IL operations</em> are matched against the catalog:
/// constructor use (<c>newobj</c>), direct calls (<c>call</c>/<c>callvirt</c>) and method-pointer loads
/// (<c>ldftn</c>/<c>ldvirtftn</c>) are each surfaced with a distinct <see cref="ApiCallKind"/>.</description></item>
/// <item><description><b>Metadata and attributes.</b> <see cref="ScanInteropDeclarations"/> reads the interop
/// declarations that <em>need no call site at all</em>: <c>[DllImport]</c>/<c>[LibraryImport]</c> via CCI's
/// <c>IMethodDefinition.IsPlatformInvoke</c> flag (<see cref="ApiCallKind.NativeImport"/>) and
/// <c>[UnmanagedCallersOnly]</c> via a custom-attribute read (<see cref="ApiCallKind.NativeExport"/>). Both are
/// found from metadata alone, whether or not anything ever calls them.</description></item>
/// </list>
/// </summary>
public sealed class CapabilityAnalysis(AssemblyAnalyzer assembly)
{
    #region Properties
    /// <summary>The default sensitive-API catalog. Public for transparency and tests; immutable.</summary>
    public static IReadOnlyList<SensitiveApi> Catalog { get; } =
    [
        new(Capability.FileSystem, "System.IO.File"),
        new(Capability.FileSystem, "System.IO.Directory"),
        new(Capability.FileSystem, "System.IO.FileInfo"),
        new(Capability.FileSystem, "System.IO.DirectoryInfo"),
        new(Capability.FileSystem, "System.IO.FileStream"),
        new(Capability.Network, "System.Net.Http.HttpClient"),
        new(Capability.Network, "System.Net.WebClient"),
        new(Capability.Network, "System.Net.WebRequest"),
        new(Capability.Network, "System.Net.Dns"),
        new(Capability.Network, "System.Net.Sockets."),
        new(Capability.ProcessExecution, "System.Diagnostics.Process"),
        new(Capability.Registry, "Microsoft.Win32.Registry"),
        new(Capability.EnvironmentProbe, "System.Environment", "GetEnvironmentVariable"),
        new(Capability.EnvironmentProbe, "System.Environment", "GetEnvironmentVariables"),
        new(Capability.EnvironmentProbe, "System.Environment", "GetFolderPath"),
        new(Capability.EnvironmentProbe, "System.Environment", "get_UserName"),
        new(Capability.EnvironmentProbe, "System.Environment", "get_MachineName"),
        new(Capability.EnvironmentProbe, "System.Environment", "get_UserDomainName"),
        new(Capability.DynamicCodeLoading, "System.Reflection.Assembly", "Load"),
        new(Capability.DynamicCodeLoading, "System.Reflection.Assembly", "LoadFrom"),
        new(Capability.DynamicCodeLoading, "System.Reflection.Assembly", "LoadFile"),
        new(Capability.DynamicCodeLoading, "System.Reflection.Assembly", "UnsafeLoadFrom"),
        new(Capability.DynamicCodeLoading, "System.Activator", "CreateInstance"),
        new(Capability.DynamicCodeLoading, "System.Activator", "CreateInstanceFrom"),
        new(Capability.DynamicCodeLoading, "System.Reflection.Emit."),
        new(Capability.DynamicCodeLoading, "System.Linq.Expressions.Expression", "Compile"),
        new(Capability.ReflectionInvocation, "System.Reflection.MethodBase", "Invoke"),
        new(Capability.ReflectionInvocation, "System.Reflection.MethodInfo", "Invoke"),
        new(Capability.ReflectionInvocation, "System.Delegate", "DynamicInvoke"),
        new(Capability.NativeInterop, "System.Runtime.InteropServices.Marshal"),
        new(Capability.NativeInterop, "System.Runtime.InteropServices.NativeLibrary"),
        new(Capability.Cryptography, "System.Security.Cryptography."),
    ];
    #endregion

    #region Methods
    /// <summary>
    /// Runs both detection seams. First the <b>call-site</b> pass: scans <see cref="AssemblyAnalyzer.Methods"/> by
    /// reading each method's CCI <see cref="IMethodBody.Operations"/> and matching every call site
    /// (<c>call</c>/<c>callvirt</c>/<c>newobj</c>/<c>ldftn</c>/<c>ldvirtftn</c>) against <see cref="Catalog"/>; a
    /// method whose scan throws is skipped with a reason and a warning, never fatally (should be ~0 now — no
    /// disassembler). Then the <b>metadata/attribute</b> pass (<see cref="ScanInteropDeclarations"/>) over the
    /// module's full method set, which finds <c>[DllImport]</c>/<c>[LibraryImport]</c> declarations via
    /// <c>IsPlatformInvoke</c> and <c>[UnmanagedCallersOnly]</c> methods via a custom-attribute read — neither
    /// requires a call site, and neither affects the method-count bookkeeping. Findings from both seams are
    /// deduplicated on the full tuple and ordered deterministically by (CallerType, CallerMethod, CalledApi, Kind)
    /// with <see cref="StringComparer.Ordinal"/>. Never throws.
    /// </summary>
    public Result<CapabilityReport> Analyze()
    {
        try
        {
            // Materialize inside the guard: enumerating assembly.Methods advances CCI's lazy type
            // resolution, which can throw on a corrupt/hostile module — the outer catch upholds the
            // never-throws contract even for a top-level enumeration failure.
            var methods = assembly.Methods.ToArray();
            var findings = new List<ApiCallFinding>();
            var skipped = new List<string>();

            foreach (var method in methods)
            {
                var result = ScanMethod(method);
                if (result.Skip is not null)
                    skipped.Add(result.Skip);
                else
                    findings.AddRange(result.Findings);
            }

            // Interop declarations live in metadata, not in IL: a P/Invoke is an external method with no body,
            // so it never appears in assembly.Methods (which requires one) and the operation walk cannot see it
            // at all. Scan the full type/method set separately for the pinvokeimpl flag and for
            // [UnmanagedCallersOnly]. This adds only NativeImport/NativeExport findings and does not touch the
            // method-count bookkeeping, so it can never double-count a real call site.
            findings.AddRange(ScanInteropDeclarations());

            var ordered = findings
                .Distinct()
                .OrderBy(f => f.CallerType, StringComparer.Ordinal)
                .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
                .ThenBy(f => f.CalledApi, StringComparer.Ordinal)
                .ThenBy(f => f.Kind)
                .ToArray();

            var report = new CapabilityReport(
                assembly.AssemblyName,
                assembly.AssemblyPath,
                DateTimeOffset.UtcNow,
                ordered,
                MethodsTotal: methods.Length,
                MethodsAnalyzed: methods.Length - skipped.Count,
                MethodsSkipped: skipped.Count,
                SkippedMethods: skipped);

            return Result.Success(report);
        }
        catch (Exception ex)
        {
            return Result.FailureWithError<CapabilityReport>($"Failed to analyze {assembly.AssemblyName}.", ex);
        }
    }

    // Scans one method's CCI operations. Returns either its findings or a skip reason ("Type.Method: reason").
    // A method is skipped only when deriving the caller name or enumerating the body throws (a crafted or corrupt
    // body) — never fatally. Per-operation matching is per-op try/catch, so one throwing call site is dropped
    // individually while its siblings' findings are kept and the method still counts as analyzed (ADR 0005).
    private (IReadOnlyList<ApiCallFinding> Findings, string? Skip) ScanMethod(IMethodDefinition method)
    {
        // The seed qualifier is itself a metadata read that can throw on a crafted module, so it goes through
        // SafeName: reading method.Name.Value here directly would let the failure escape the per-method guard and
        // fail the whole analysis instead of skipping this one method. The name is re-read inside the guard below
        // to refine the qualifier to "Type.Method" for a well-formed method.
        string qualifier = SafeName(method);
        try
        {
            var callerType = AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition);
            var callerMethod = method.Name.Value;
            qualifier = $"{callerType}.{callerMethod}";

            var findings = method.Body.Operations
                .SelectMany(op => ScanOperation(op, callerType, callerMethod))
                .ToArray();

            return (findings, null);
        }
        catch (Exception ex)
        {
            return Skip(qualifier, "scan threw: " + ex.Message);
        }
    }

    // Matches a single operation against the catalog. Any exception at this call site is caught and logged so
    // the site is dropped individually without discarding the method's other findings or skipping the method.
    private static IReadOnlyList<ApiCallFinding> ScanOperation(IOperation op, string callerType, string callerMethod)
    {
        try
        {
            return Callee(op) is { } c && Match(c.Method) is { } capability
                ? new[] { new ApiCallFinding(capability, c.Kind, callerType, callerMethod, c.Api) }
                : Array.Empty<ApiCallFinding>();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping operation in {0}.{1}: {2}", callerType, callerMethod, ex.Message);
            return Array.Empty<ApiCallFinding>();
        }
    }

    // Scans every method definition (including external ones excluded from assembly.Methods) for the two
    // metadata interop seams — the pinvokeimpl flag (calls OUT to native) and [UnmanagedCallersOnly] (native
    // calls IN) — emitting one finding per declaration, independent of any call site. Uses CCI's
    // IMethodDefinition.IsPlatformInvoke / PlatformInvokeData (verified in ext/analysis-net/cci
    // Members.cs:948,1011) and IMethodDefinition.Attributes. Both seams are checked for every method: a method
    // carrying both declarations yields both findings. Enumeration and per-method reads are guarded so a
    // hostile/corrupt module drops individual entries without failing the pass.
    private IReadOnlyList<ApiCallFinding> ScanInteropDeclarations()
    {
        IMethodDefinition[] all;
        try
        {
            all = assembly.Module.GetAllTypes().SelectMany(t => t.Methods).ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Could not enumerate methods for the interop declaration scan: {0}", ex.Message);
            return Array.Empty<ApiCallFinding>();
        }

        return all.SelectMany(m => PlatformInvokeFinding(m).Concat(NativeExportFinding(m))).ToArray();
    }

    // A single NativeImport finding when the method is a P/Invoke declaration, or none otherwise. Any read
    // failure is caught and the declaration dropped individually — the scan never throws.
    private static IReadOnlyList<ApiCallFinding> PlatformInvokeFinding(IMethodDefinition method)
    {
        var name = SafeName(method);
        try
        {
            if (!method.IsPlatformInvoke)
                return Array.Empty<ApiCallFinding>();

            var callerType = AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition);
            var callerMethod = method.Name.Value;
            return new[] { new ApiCallFinding(Capability.NativeInterop, ApiCallKind.NativeImport, callerType, callerMethod, NativeTarget(method)) };
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping P/Invoke declaration {0}: {1}", name, ex.Message);
            return Array.Empty<ApiCallFinding>();
        }
    }

    // "module!entryPoint" native target from PlatformInvokeData (native module name + import name), falling
    // back to the managed method name when either part is unavailable. Both components are sanitized: see
    // Sanitize — they are attacker-controlled metadata, and a '!' smuggled into either would break the
    // single-'!' shape this composes.
    private static string NativeTarget(IMethodDefinition method)
    {
        var data = method.PlatformInvokeData;
        if (data is null || data == Dummy.PlatformInvokeInformation)
            return Sanitize(method.Name.Value);

        var module = Sanitize(data.ImportModule?.Name?.Value);
        var entry = Sanitize(data.ImportName?.Value);
        if (entry.Length == 0)
            entry = Sanitize(method.Name.Value);
        return module.Length == 0 ? entry : $"{module}!{entry}";
    }

    // A single NativeExport finding when the method carries [UnmanagedCallersOnly] — a managed method published
    // as a native-callable entry point, i.e. reverse P/Invoke, which IsPlatformInvoke does not cover. Any read
    // failure is caught and the declaration dropped individually — the scan never throws.
    private static IReadOnlyList<ApiCallFinding> NativeExportFinding(IMethodDefinition method)
    {
        var name = SafeName(method);
        try
        {
            var attribute = method.Attributes?.FirstOrDefault(IsUnmanagedCallersOnly);
            if (attribute is null)
                return Array.Empty<ApiCallFinding>();

            var callerType = AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition);
            var callerMethod = method.Name.Value;
            return new[] { new ApiCallFinding(Capability.NativeInterop, ApiCallKind.NativeExport, callerType, callerMethod, ExportedTarget(attribute, callerMethod)) };
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping [UnmanagedCallersOnly] declaration {0}: {1}", name, ex.Message);
            return Array.Empty<ApiCallFinding>();
        }
    }

    // The name is itself a metadata read that can throw on a crafted module. Capture it up front so the catch
    // blocks above can name the offender without re-reading it: evaluating method.Name.Value inside a catch would
    // let a failure to read the name escape the per-declaration guard and fail the whole analysis.
    private static string SafeName(IMethodDefinition method)
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

    // Runs once per attribute inside FirstOrDefault, so an attribute that throws while its type name is read would
    // abort the walk and silently drop a real [UnmanagedCallersOnly] declared after it — an evasion primitive on
    // crafted metadata. Treat an unreadable attribute as "not a match" so its siblings are still examined. The
    // Dummy.TypeReference guard is load-bearing: CCI returns exactly that sentinel (ext/analysis-net/cci
    // Attributes.cs:289-296) when the attribute constructor's containing type is null.
    private static bool IsUnmanagedCallersOnly(ICustomAttribute attribute)
    {
        try
        {
            return attribute?.Type is { } type &&
                type != Dummy.TypeReference &&
                AssemblyAnalyzer.TypeName(type) == UnmanagedCallersOnlyAttribute;
        }
        catch
        {
            return false;
        }
    }

    // "<managed>!entryPoint" for an exported entry point. NativeImport renders "module!entryPoint", and keeping
    // the same '!'-separated shape here means renderers that split on '!' to show "where" and "what" keep
    // working: the left side names the side that OWNS the entry point, and "<managed>" is a literal marker
    // distinguishing an export (this assembly) from an import (the native module name). The owning type and
    // method are not repeated here — they are already carried in the finding's CallerType/CallerMethod. The
    // right side is the name native code calls it by: the attribute's optional EntryPoint named argument, or
    // the method's own name when it is absent or unreadable. Sanitized for the same reason as NativeTarget.
    private static string ExportedTarget(ICustomAttribute attribute, string callerMethod)
    {
        var entry = attribute.NamedArguments?
            .FirstOrDefault(a => a?.ArgumentName?.Value == EntryPointArgument)?
            .ArgumentValue as IMetadataConstant;

        var name = Sanitize(entry?.Value as string);
        return $"{ManagedExportModule}!{(name.Length > 0 ? name : Sanitize(callerMethod))}";
    }

    // Makes one component of a '!'-composed CalledApi safe to compose with. Native module names and export names
    // are attacker-controlled metadata: nothing stops [DllImport("evil!mod.dll")] or EntryPoint = "evil!injected"
    // from smuggling a second '!' (breaking the "exactly one '!'" split contract renderers rely on), or a newline
    // from breaking a report's row layout. No real native module or export name contains '!' or a control
    // character, so mapping '!' to '_' and dropping control characters loses nothing legitimate — and it is what
    // makes the single-'!' contract actually hold rather than merely being expected.
    private static string Sanitize(string? component) =>
        string.IsNullOrEmpty(component)
            ? string.Empty
            : new string(component.Where(c => !char.IsControl(c)).Select(c => c == '!' ? '_' : c).ToArray());

    private static (IReadOnlyList<ApiCallFinding> Findings, string? Skip) Skip(string qualifier, string reason)
    {
        Runtime.Warn("Skipping method {0}: {1}", qualifier, reason);
        return (Array.Empty<ApiCallFinding>(), $"{qualifier}: {reason}");
    }

    // Maps a CCI operation to the referenced method, its call kind, and the CalledApi string, or null if the
    // operation is not a capability-bearing call site. Value casts follow CCIProvider/CodeProvider.cs.
    private static (IMethodReference Method, ApiCallKind Kind, string Api)? Callee(IOperation op) =>
        op.OperationCode switch
        {
            OperationCode.Call or OperationCode.Callvirt when op.Value is IMethodReference m =>
                (m, ApiCallKind.Call, CalledApi(m)),
            OperationCode.Newobj when op.Value is IMethodReference ctor =>
                (ctor, ApiCallKind.Construct, $"{AssemblyAnalyzer.TypeName(ctor.ContainingType)}..ctor"),
            OperationCode.Ldftn or OperationCode.Ldvirtftn when op.Value is IMethodReference m =>
                (m, ApiCallKind.MethodPointerLoad, CalledApi(m)),
            _ => null,
        };

    // The capability of the first catalog entry matching the callee, or null if none match.
    private static Capability? Match(IMethodReference callee)
    {
        var typeName = AssemblyAnalyzer.TypeName(callee.ContainingType);
        var entry = Catalog.FirstOrDefault(api =>
            typeName.StartsWith(api.TypePrefix, StringComparison.Ordinal) &&
            (api.Method is null || api.Method == callee.Name.Value));
        return entry?.Capability;
    }

    private static string CalledApi(IMethodReference callee) => $"{AssemblyAnalyzer.TypeName(callee.ContainingType)}.{callee.Name.Value}";
    #endregion

    #region Fields
    private const string UnmanagedCallersOnlyAttribute = "System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute";
    private const string EntryPointArgument = "EntryPoint";
    private const string ManagedExportModule = "<managed>";
    private const string UnreadableName = "<unreadable>";
    #endregion
}
