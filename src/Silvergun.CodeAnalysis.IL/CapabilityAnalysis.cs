namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

using Model.Types;
using Model.ThreeAddressCode.Instructions;

/// <summary>
/// Scans every method's three-address code for calls into sensitive BCL APIs (per the static
/// <see cref="Catalog"/>) and produces a serializable <see cref="CapabilityReport"/>. Detection is
/// catalog-driven and observes direct calls only (capability presence, not reachability) — see ADR 0002.
/// Constructor calls (<c>new X()</c>) surface in TAC as a <see cref="MethodCallInstruction"/> for the
/// type's <c>.ctor</c>, so prefix matching on the containing type catches them without special-casing
/// <c>CreateObjectInstruction</c>.
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
    /// Scans <see cref="AssemblyAnalyzer.Methods"/>: ensures each method is in TAC, then matches every
    /// <see cref="MethodCallInstruction"/> callee against <see cref="Catalog"/>. Methods that fail to
    /// disassemble are skipped with a warning — not fatal. Findings are deduplicated and ordered
    /// deterministically by (CallerType, CallerMethod, CalledApi). Never throws.
    /// </summary>
    public Result<CapabilityReport> Analyze()
    {
        var findings = analyzer.Methods
            .SelectMany(ScanMethod)
            .Distinct()
            .OrderBy(f => f.CallerType, StringComparer.Ordinal)
            .ThenBy(f => f.CallerMethod, StringComparer.Ordinal)
            .ThenBy(f => f.CalledApi, StringComparer.Ordinal)
            .ToArray();

        var report = new CapabilityReport(
            analyzer.Assembly.Name,
            analyzer.AssemblyPath,
            DateTimeOffset.UtcNow,
            findings);

        return Result.Success(report);
    }

    private IEnumerable<ApiCallFinding> ScanMethod(MethodDefinition method)
    {
        var tac = analyzer.DisassembleMethod(method);
        if (!tac.IsSuccess)
        {
            Runtime.Warn("Skipping method {0}: {1}", method.Name, tac.Message ?? "disassembly failed");
            return [];
        }

        var callerType = FullName((IBasicType)method.ContainingType);
        return tac.Value.Instructions
            .OfType<MethodCallInstruction>()
            .Select(call => (call.Method, Capability: Match(call.Method)))
            .Where(x => x.Capability is not null)
            .Select(x => new ApiCallFinding(x.Capability!.Value, callerType, method.Name, CalledApi(x.Method)));
    }

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
