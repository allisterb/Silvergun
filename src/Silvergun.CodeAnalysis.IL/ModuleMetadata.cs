namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

/// <summary>
/// What Analysis.Net's <c>Model</c> drops from an assembly's manifest module, which phase A2 reports rather than follows
/// (A2 spec §6 and decision D3). It is read from the file itself, as <see cref="TypeForwarders"/> is.
/// <list type="bullet">
/// <item>The global type <c>&lt;Module&gt;</c> (TypeDef row 1): whether it has a static constructor, a module
/// initializer that runs when the assembly loads, and how many methods it has. Model loads none of them.</item>
/// <item>The MethodImpl rows whose implementing method's name neither is the declared method's name nor ends in it, as
/// a C# explicit implementation's does (VB <c>Implements</c>, hand-written IL). CHA matches by name, so it cannot follow
/// these rows.</item>
/// </list>
/// </summary>
public sealed class ModuleMetadata
{
    #region Constructors
    private ModuleMetadata(bool isReadable, bool hasModuleInitializer, int moduleMethods, int renamedImplementations)
    {
        IsReadable = isReadable;
        HasModuleInitializer = hasModuleInitializer;
        ModuleMethods = moduleMethods;
        RenamedImplementations = renamedImplementations;
    }
    #endregion

    #region Properties
    /// <summary>An assembly with no module initializer and no renamed implementations; for one that has no file (a synthetic one).</summary>
    public static ModuleMetadata None { get; } = new(true, false, 0, 0);

    /// <summary>An assembly whose module metadata could not be read: whether it has a module initializer is unknown.</summary>
    public static ModuleMetadata Unreadable { get; } = new(false, false, 0, 0);

    /// <summary>False when the metadata could not be read; the other properties are then 0 or false and mean nothing.</summary>
    public bool IsReadable { get; }

    /// <summary>True when <c>&lt;Module&gt;</c> has a static constructor.</summary>
    public bool HasModuleInitializer { get; }

    /// <summary>The number of methods <c>&lt;Module&gt;</c> defines, the module initializer included.</summary>
    public int ModuleMethods { get; }

    /// <summary>The number of MethodImpl rows whose implementation is renamed.</summary>
    public int RenamedImplementations { get; }
    #endregion

    #region Methods
    /// <summary>
    /// Reads the module metadata of the assembly file at <paramref name="path"/>. Never throws: a missing, unreadable or
    /// malformed file is <see cref="Unreadable"/>, never <see cref="None"/>.
    /// </summary>
    public static ModuleMetadata Read(string? path)
    {
        if (path is null)
            return Unreadable;
        try
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            if (!pe.HasMetadata)
                return Unreadable;
            var metadata = pe.GetMetadataReader(MetadataReaderOptions.None);
            var module = metadata.TypeDefinitions.Count == 0
                ? []
                : metadata.GetTypeDefinition(MetadataTokens.TypeDefinitionHandle(1)).GetMethods().Select(metadata.GetMethodDefinition).ToArray();
            // Static and named .cctor: the CLR also wants rtspecialname, so this over-reports only.
            var initializer = module.Any(m => (m.Attributes & MethodAttributes.Static) != 0 && metadata.StringComparer.Equals(m.Name, ".cctor"));
            return new(true, initializer, module.Length, RenamedRows(metadata));
        }
        catch (Exception)
        {
            return Unreadable;
        }
    }

    /// <summary>Module metadata from known facts, for an assembly built in memory.</summary>
    public static ModuleMetadata Of(bool hasModuleInitializer, int moduleMethods, int renamedImplementations) =>
        new(true, hasModuleInitializer, Math.Max(moduleMethods, 0), Math.Max(renamedImplementations, 0));

    /// <summary>
    /// The metadata of one assembly name loaded more than once: unreadable if any copy is, otherwise the most any copy
    /// reports.
    /// </summary>
    public static ModuleMetadata Merge(IEnumerable<ModuleMetadata?> modules)
    {
        var all = modules.ToArray();
        return all.Length == 0 ? None
            : all.Any(m => m is not { IsReadable: true }) ? Unreadable
            : new(true, all.Any(m => m!.HasModuleInitializer), all.Max(m => m!.ModuleMethods), all.Max(m => m!.RenamedImplementations));
    }

    // Every row of the MethodImpl table, not per type, each in its own try: a row that cannot be read counts as renamed,
    // and never costs the module facts above (S3 review W2). A row is renamed when either name did not decode cleanly
    // (counted, so a malformed row cannot hide), or when the two do not implement the same name by MemberIndex's
    // explicit-implementation rule, applied to both sides as CHA applies it. Each name string's facts are computed once
    // per StringHandle, and each pair of handles is judged once by an ordinal comparison of those facts (W1, W1-r2), so
    // the text scanned is bounded by the distinct MethodDef and MemberRef names, which loading the assembly decodes
    // anyway.
    private static int RenamedRows(MetadataReader metadata)
    {
        var facts = new Dictionary<StringHandle, (string Implemented, bool Clean)>();
        var verdicts = new Dictionary<(StringHandle Body, StringHandle Declared), bool>();

        (string Implemented, bool Clean) Facts(StringHandle name)
        {
            if (facts.TryGetValue(name, out var known))
                return known;
            var text = metadata.GetString(name);
            return facts[name] = (MemberIndex.ImplementedName(text), !text.Contains(replacement));
        }

        bool Differs(StringHandle body, StringHandle declared)
        {
            var (bodyName, bodyClean) = Facts(body);
            var (declaredName, declaredClean) = Facts(declared);
            return !bodyClean || !declaredClean || !string.Equals(bodyName, declaredName, StringComparison.Ordinal);
        }

        bool IsRenamed(int row)
        {
            try
            {
                var implementation = metadata.GetMethodImplementation(MetadataTokens.MethodImplementationHandle(row));
                var pair = (NameOf(metadata, implementation.MethodBody), NameOf(metadata, implementation.MethodDeclaration));
                return verdicts.TryGetValue(pair, out var renamed) ? renamed : verdicts[pair] = Differs(pair.Item1, pair.Item2);
            }
            catch (Exception)
            {
                return true;
            }
        }

        return Enumerable.Range(1, metadata.GetTableRowCount(TableIndex.MethodImpl)).Count(IsRenamed);
    }

    // The name of a MethodDefOrRef; anything else is malformed, and throws so its row counts as renamed.
    private static StringHandle NameOf(MetadataReader metadata, EntityHandle method) => method.Kind switch
    {
        HandleKind.MethodDefinition => metadata.GetMethodDefinition((MethodDefinitionHandle)method).Name,
        HandleKind.MemberReference => metadata.GetMemberReference((MemberReferenceHandle)method).Name,
        _ => throw new BadImageFormatException($"a MethodImpl names a {method.Kind}"),
    };
    #endregion

    #region Fields
    // U+FFFD, which the lenient decoder substitutes for invalid UTF-8; written as a number so the source stays ASCII.
    private const char replacement = (char)0xFFFD;
    #endregion
}
