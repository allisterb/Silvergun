// Portions adapted from Stratis.CodeAnalysis.IL (AssemblyMetadata.cs), the author's own prior
// MIT-licensed project. Copy authorized 2026-07-16 (ADR 0006). MIT License.
// Source: reference/projects/Stratis.CodeAnalysis.IL/AssemblyMetadata.cs
namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using Microsoft.Cci;

using Nuclear.Assemblies.Factories;
using Nuclear.Assemblies.ResolverData;
using Nuclear.Assemblies.Resolvers;
using Nuclear.Creation;

/// <summary>
/// Reads a .NET assembly's rich CCI metadata into a Silvergun-owned serializable <see cref="AssemblyMetadataInfo"/>
/// (ADR 0006). Loads via a fresh <see cref="PeReader.DefaultHost"/> per call — independent of the
/// Analysis.Net Model/CCIProvider load path — so it does not touch the shared static state that caused the
/// <c>AssemblyDisassembler.Create</c> concurrent-load race. Reference resolution (Nuclear.Assemblies) is
/// best-effort, local-only and non-fatal. <see cref="Read"/> never throws.
/// </summary>
public sealed class AssemblyMetadata : Runtime
{
    #region Methods
    /// <summary>
    /// Loads <paramref name="assemblyPath"/> via a fresh <see cref="PeReader.DefaultHost"/>, projects its CCI
    /// <c>IModule</c>/<c>IAssembly</c> into an <see cref="AssemblyMetadataInfo"/> and disposes the host. Returns a
    /// failure <see cref="Result{T}"/> (never throws) when the file is missing or is not a valid CLR module/assembly.
    /// When <paramref name="resolveReferences"/> is <c>false</c>, references are still listed but left unresolved.
    /// </summary>
    public static Result<AssemblyMetadataInfo> Read(string assemblyPath, bool resolveReferences = true)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath) || !File.Exists(assemblyPath))
            return Result.Failure<AssemblyMetadataInfo>($"Assembly file '{assemblyPath}' does not exist.");

        try
        {
            // DefaultHost allocates its own NameTable + InternFactory (instance-scoped), so the raw metadata
            // read touches no process-wide mutable statics — a fresh host per Read is fully isolated.
            using var host = new PeReader.DefaultHost();
            var module = host.LoadUnitFrom(assemblyPath) as IModule;
            var assembly = module?.ContainingAssembly;

            // Mirrors CCIProvider/Loader.cs:57 — reject non-CLR / unresolvable inputs.
            if (module is null || module == Dummy.Module || assembly is null || assembly == Dummy.Assembly)
                return Result.Failure<AssemblyMetadataInfo>($"The file '{assemblyPath}' is not a valid CLR module or assembly.");

            var directory = new FileInfo(assemblyPath).Directory?.FullName;

            var info = new AssemblyMetadataInfo(
                Name: assembly.Name.Value,
                Version: assembly.Version?.ToString(),
                Culture: NullIfEmpty(assembly.Culture),
                PublicKeyToken: HexToken(assembly.PublicKeyToken),
                IsStrongNameSigned: module.StrongNameSigned,
                ModuleKind: module.Kind.ToString(),
                IsILOnly: module.ILOnly,
                Requires32Bit: module.Requires32bits,
                Requires64Bit: module.Requires64bits,
                RequiresAmdInstructionSet: module.RequiresAmdInstructionSet,
                ContainsForeignTypes: assembly.ContainsForeignTypes,
                HasEntryPoint: module.EntryPoint is not null && module.EntryPoint != Dummy.MethodReference,
                TargetRuntimeVersion: NullIfEmpty(module.TargetRuntimeVersion),
                DebugInformationLocation: NullIfEmpty(module.DebugInformationLocation),
                CustomAttributes: CustomAttributeNames(assembly.AssemblyAttributes, module.ModuleAttributes),
                References: module.AssemblyReferences
                    .Select(r => Reference(r, resolveReferences ? directory : null))
                    .ToArray());

            return Result.Success(info);
        }
        catch (Exception ex)
        {
            return Result.Failure<AssemblyMetadataInfo>($"Could not read metadata from '{assemblyPath}': {ex.Message}", ex);
        }
    }

    // Projects one CCI IAssemblyReference to a serializable record, resolving its file best-effort when searchDir is set.
    private static AssemblyReferenceInfo Reference(IAssemblyReference r, string? searchDir)
    {
        var name = r.Name.Value;
        var token = HexToken(r.PublicKeyToken);
        var resolved = searchDir is null ? null : TryResolve(name, r.Version, token, searchDir);
        return new AssemblyReferenceInfo(name, r.Version?.ToString(), NullIfEmpty(r.Culture), token, resolved is not null, resolved);
    }

    // The distinct, ordinal-sorted TYPE full names of the given custom attributes (no argument decoding).
    private static IReadOnlyList<string> CustomAttributeNames(params IEnumerable<ICustomAttribute>[] sets) =>
        sets.SelectMany(s => s)
            .Where(a => a.Type is not null && a.Type != Dummy.TypeReference)
            .Select(a => TypeHelper.GetTypeName(a.Type))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

    // Best-effort, local-only, never-throwing resolution to a physical file. Probes the target directory first
    // (Stratis' DefaultResolver searched the target dir; the public IDefaultResolver only searches the entry
    // assembly's dir, so its equivalent is done directly here), then the local NuGet caches via NugetResolver.
    private static string? TryResolve(string name, Version? version, string? publicKeyToken, string searchDir)
    {
        try
        {
            if (Directory.Exists(searchDir))
            {
                var local = Directory.EnumerateFiles(searchDir, name + ".dll", SearchOption.TopDirectoryOnly).FirstOrDefault();
                if (local is not null)
                {
                    Debug("Resolved assembly {0} in {1}.", name, searchDir);
                    return local;
                }
            }

            var identity = new AssemblyName(name) { Version = version };
            if (publicKeyToken is not null)
                identity.SetPublicKeyToken(Convert.FromHexString(publicKeyToken));

            if (nugetResolver is not null && nugetResolver.TryResolve(identity, out var data) && data.FirstOrDefault() is { } d)
            {
                Debug("Resolved assembly {0} using NuGet resolver.", name);
                return d.File.FullName;
            }
        }
        catch (Exception ex)
        {
            Warn("Could not resolve assembly reference {0}: {1}", name, ex.Message);
        }
        return null;
    }

    // Lowercase-hex public-key-token, or null when the token is empty (unsigned).
    private static string? HexToken(IEnumerable<byte>? token)
    {
        var bytes = token?.ToArray();
        return bytes is null || bytes.Length == 0 ? null : Convert.ToHexStringLower(bytes);
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrEmpty(s) ? null : s;

    // Builds the NuGet resolver once via the public factory. NugetResolver reads only the local NuGet package
    // caches (verified: Nuclear's CoreNugetResolver enumerates cache dirs only — no network).
    private static INugetResolver? CreateNugetResolver()
    {
        try
        {
            return Factory.Instance.NugetResolver().TryCreate(out var resolver, VersionMatchingStrategies.SemVer, VersionMatchingStrategies.SemVer)
                ? resolver
                : null;
        }
        catch (Exception ex)
        {
            Warn("Could not create NuGet assembly resolver: {0}", ex.Message);
            return null;
        }
    }
    #endregion

    #region Fields
    private static readonly INugetResolver? nugetResolver = CreateNugetResolver();
    #endregion
}
