namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Model;
using Model.Types;
using Bytecode = Model.Bytecode;

/// <summary>
/// Scans every method's <em>bytecode</em> body for references to sensitive BCL APIs (per the static
/// <see cref="Catalog"/>) and produces a serializable <see cref="CapabilityReport"/>. Detection is
/// catalog-driven and observes call sites only (capability presence, not reachability) — see ADR 0002.
/// It reads the CCI-produced <see cref="MethodBodyKind.Bytecode"/> body directly and never lifts to TAC,
/// because the TAC lifter throws on exception-handling-heavy IL (ADR 0005). Constructor use (<c>newobj</c>),
/// direct calls (<c>call</c>/<c>callvirt</c>) and method-pointer loads (<c>ldftn</c>/<c>ldvirtftn</c>) are
/// each surfaced with a distinct <see cref="ApiCallKind"/>.
/// </summary>
public sealed class CapabilityAnalysis(AssemblyAnalyzer analyzer)
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
        new(Capability.DynamicCodeLoading, "System.Activator", "CreateInstance"),
        new(Capability.NativeInterop, "System.Runtime.InteropServices.Marshal"),
        new(Capability.NativeInterop, "System.Runtime.InteropServices.NativeLibrary"),
        new(Capability.Cryptography, "System.Security.Cryptography."),
    ];
    #endregion

    #region Methods
    /// <summary>
    /// Scans <see cref="AssemblyAnalyzer.Methods"/> by reading each method's bytecode body and matching
    /// every call site (<c>call</c>/<c>callvirt</c>/<c>newobj</c>/<c>ldftn</c>) against <see cref="Catalog"/>.
    /// Methods without a bytecode body — or whose scan throws — are skipped with a reason and a warning,
    /// never fatally. Findings are deduplicated on the full tuple and ordered deterministically by
    /// (CallerType, CallerMethod, CalledApi, Kind) with <see cref="StringComparer.Ordinal"/>. Never throws.
    /// </summary>
    public Result<CapabilityReport> Analyze()
    {
        var methods = analyzer.Methods.ToArray();
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

        var ordered = findings
            .Distinct()
            .OrderBy(f => f.CallerType, StringComparer.Ordinal)
            .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
            .ThenBy(f => f.CalledApi, StringComparer.Ordinal)
            .ThenBy(f => f.Kind)
            .ToArray();

        var report = new CapabilityReport(
            analyzer.Assembly.Name,
            analyzer.AssemblyPath,
            DateTimeOffset.UtcNow,
            ordered,
            MethodsTotal: methods.Length,
            MethodsAnalyzed: methods.Length - skipped.Count,
            MethodsSkipped: skipped.Count,
            SkippedMethods: skipped);

        return Result.Success(report);
    }

    // Scans one method's bytecode body. Returns either its findings or a skip reason ("Type.Method: reason").
    // A method is skipped when it has no bytecode body, or when deriving the caller name / enumerating the body
    // throws (a crafted or corrupt method body) — in which case it counts as skipped, never fatally. Instruction
    // matching is per-instruction try/catch, so for the common case one throwing call site is dropped individually
    // while its siblings' findings are kept and the method still counts as analyzed (ADR 0005 threat model).
    private (IReadOnlyList<ApiCallFinding> Findings, string? Skip) ScanMethod(MethodDefinition method)
    {
        string qualifier = method.Name;
        try
        {
            var callerType = method.ContainingType is IBasicType type ? FullName(type) : "<unknown>";
            qualifier = $"{callerType}.{method.Name}";

            var body = method.Body;
            if (body is null)
                return Skip(qualifier, "method has no body");
            if (body.Kind != MethodBodyKind.Bytecode)
                return Skip(qualifier, $"body is {body.Kind}, expected Bytecode");

            var findings = body.Instructions
                .SelectMany(instruction => ScanInstruction(instruction, callerType, method.Name))
                .ToArray();

            return (findings, null);
        }
        catch (Exception ex)
        {
            return Skip(qualifier, "scan threw: " + ex.Message);
        }
    }

    // Matches a single instruction against the catalog. Any exception at this call site is caught and logged so
    // the site is dropped individually without discarding the method's other findings or skipping the method.
    private static IReadOnlyList<ApiCallFinding> ScanInstruction(IInstruction instruction, string callerType, string callerMethod)
    {
        try
        {
            return Callee(instruction) is { } c && Match(c.Method) is { } capability
                ? new[] { new ApiCallFinding(capability, c.Kind, callerType, callerMethod, c.Api) }
                : Array.Empty<ApiCallFinding>();
        }
        catch (Exception ex)
        {
            Runtime.Warn("Skipping instruction in {0}.{1}: {2}", callerType, callerMethod, ex.Message);
            return Array.Empty<ApiCallFinding>();
        }
    }

    private static (IReadOnlyList<ApiCallFinding> Findings, string? Skip) Skip(string qualifier, string reason)
    {
        Runtime.Warn("Skipping method {0}: {1}", qualifier, reason);
        return (Array.Empty<ApiCallFinding>(), $"{qualifier}: {reason}");
    }

    // Maps a bytecode instruction to the referenced method, its call kind, and the CalledApi string,
    // or null if the instruction is not a capability-bearing call site.
    private static (IMethodReference Method, ApiCallKind Kind, string Api)? Callee(IInstruction instruction) =>
        instruction switch
        {
            Bytecode.MethodCallInstruction call => (call.Method, ApiCallKind.Call, CalledApi(call.Method)),
            Bytecode.CreateObjectInstruction ctor =>
                (ctor.Constructor, ApiCallKind.Construct, $"{FullName(ctor.Constructor.ContainingType)}..ctor"),
            Bytecode.LoadMethodAddressInstruction load =>
                (load.Method, ApiCallKind.MethodPointerLoad, CalledApi(load.Method)),
            _ => null,
        };

    // The capability of the first catalog entry matching the callee, or null if none match.
    private static Capability? Match(IMethodReference callee)
    {
        var typeName = FullName(callee.ContainingType);
        var entry = Catalog.FirstOrDefault(api =>
            typeName.StartsWith(api.TypePrefix, StringComparison.Ordinal) &&
            (api.Method is null || api.Method == callee.Name));
        return entry?.Capability;
    }

    private static string CalledApi(IMethodReference callee) => $"{FullName(callee.ContainingType)}.{callee.Name}";

    private static string FullName(IBasicType type) =>
        string.IsNullOrEmpty(type.ContainingNamespace) ? type.Name : $"{type.ContainingNamespace}.{type.Name}";
    #endregion
}
