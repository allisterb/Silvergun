namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Cci;

/// <summary>
/// Scans every method's <em>CCI IL operations</em> for references to sensitive BCL APIs (per the static
/// <see cref="Catalog"/>) and produces a serializable <see cref="CapabilityReport"/>. Detection is
/// catalog-driven and observes call sites only (capability presence, not reachability) — see ADR 0002.
/// It reads CCI directly from a <see cref="AssemblyAnalyzer"/> (ADR 0009) — the same bytecode-level view the
/// TAC lifter chokes on for exception-handling-heavy IL (ADR 0005) — so no lifting is involved.
/// Constructor use (<c>newobj</c>), direct calls (<c>call</c>/<c>callvirt</c>) and method-pointer loads
/// (<c>ldftn</c>/<c>ldvirtftn</c>) are each surfaced with a distinct <see cref="ApiCallKind"/>.
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
    /// Scans <see cref="AssemblyAnalyzer.Methods"/> by reading each method's CCI <see cref="IMethodBody.Operations"/>
    /// and matching every call site (<c>call</c>/<c>callvirt</c>/<c>newobj</c>/<c>ldftn</c>/<c>ldvirtftn</c>)
    /// against <see cref="Catalog"/>. A method whose scan throws is skipped with a reason and a warning, never
    /// fatally (should be ~0 now — no disassembler). Findings are deduplicated on the full tuple and ordered
    /// deterministically by (CallerType, CallerMethod, CalledApi, Kind) with <see cref="StringComparer.Ordinal"/>.
    /// Never throws.
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

            // P/Invoke declarations are external methods with no IL body, so they never appear in
            // assembly.Methods (which requires a body) and the operation walk cannot see them. Scan the
            // full type/method set separately for the metadata pinvokeimpl flag. This adds only NativeImport
            // findings and does not touch the method-count bookkeeping, so it can never double-count a real
            // call site (a bodied method is never a P/Invoke).
            findings.AddRange(ScanPlatformInvokes());

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
        string qualifier = method.Name.Value;
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

    // Scans every method definition (including external ones excluded from assembly.Methods) for the metadata
    // pinvokeimpl flag and emits one NativeImport finding per P/Invoke declaration — detection through the
    // attribute/metadata seam, independent of any call site. Uses CCI's IMethodDefinition.IsPlatformInvoke /
    // PlatformInvokeData (verified in ext/analysis-net/cci Members.cs:948,1011). Enumeration and per-method
    // reads are guarded so a hostile/corrupt module drops individual entries without failing the pass.
    private IReadOnlyList<ApiCallFinding> ScanPlatformInvokes()
    {
        IMethodDefinition[] all;
        try
        {
            all = assembly.Module.GetAllTypes().SelectMany(t => t.Methods).ToArray();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Could not enumerate methods for P/Invoke scan: {0}", ex.Message);
            return Array.Empty<ApiCallFinding>();
        }

        return all.SelectMany(PlatformInvokeFinding).ToArray();
    }

    // A single NativeImport finding when the method is a P/Invoke declaration, or none otherwise. Any read
    // failure is caught and the declaration dropped individually — the scan never throws.
    private static IReadOnlyList<ApiCallFinding> PlatformInvokeFinding(IMethodDefinition method)
    {
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
            Runtime.Warn("Skipping P/Invoke declaration {0}: {1}", method.Name.Value, ex.Message);
            return Array.Empty<ApiCallFinding>();
        }
    }

    // "module!entryPoint" native target from PlatformInvokeData (native module name + import name), falling
    // back to the managed method name when either part is unavailable.
    private static string NativeTarget(IMethodDefinition method)
    {
        var data = method.PlatformInvokeData;
        if (data is null || data == Dummy.PlatformInvokeInformation)
            return method.Name.Value;

        var module = data.ImportModule?.Name?.Value;
        var entry = data.ImportName?.Value;
        if (string.IsNullOrEmpty(entry))
            entry = method.Name.Value;
        return string.IsNullOrEmpty(module) ? entry : $"{module}!{entry}";
    }

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
}
