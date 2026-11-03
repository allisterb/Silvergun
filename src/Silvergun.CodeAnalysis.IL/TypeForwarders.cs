namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

/// <summary>
/// The type forwarders of one assembly: the rows of its <c>ExportedType</c> table whose implementation is another
/// assembly, or another module file of this one. The CLR follows such a row when it resolves a reference into the
/// assembly — even when the assembly also defines a type of the same name — so a reference that names a forwarded type
/// does not run the code defined here. Analysis.Net's <c>Model</c> carries none of this, so it is read from the file
/// itself (ADR 0020, review 4 C-E).
/// <para>
/// Only top-level rows are kept: a nested type is exported with its outermost type. Names are matched coarsely — a
/// leading <c>.</c> of the namespace and everything from the first <c>`</c> of the name are ignored, on both sides —
/// because CCI drops exactly those parts of a reference's names (one leading dot; everything after the last backtick
/// that is not the final character). For that to over-match only, both sides must decode the same characters: CCI
/// decodes valid UTF-8 as .NET does but invalid bytes its own way, and drops the last byte of a string that runs to the
/// end of the <c>#Strings</c> heap with no NUL. A table where a kept row uses an invalid or such an unterminated
/// string is therefore <see cref="Unreadable"/> rather than compared (review 5 C-F, review 6 W-C). An over-match costs precision, never soundness (see
/// <see cref="MemberIndex.Resolve"/>).
/// </para>
/// </summary>
public sealed class TypeForwarders
{
    #region Constructors
    private TypeForwarders(IReadOnlyDictionary<(string Namespace, string Name), Exports>? exports) => this.exports = exports;
    #endregion

    #region Properties
    /// <summary>An assembly that forwards nothing.</summary>
    public static TypeForwarders None { get; } = new(new Dictionary<(string, string), Exports>());

    /// <summary>An assembly whose forwarders could not be read: whether it forwards a given type is unknown.</summary>
    public static TypeForwarders Unreadable { get; } = new(null);

    /// <summary>False when the forwarder table could not be read.</summary>
    public bool IsReadable => exports is not null;

    /// <summary>The number of forwarded or module-exported (coarse) type names.</summary>
    public int Count => exports?.Count ?? 0;
    #endregion

    #region Methods
    /// <summary>
    /// Reads the forwarders of the assembly file at <paramref name="path"/>. Never throws: a missing, unreadable or
    /// malformed file, or a forwarded name that is not valid UTF-8, is <see cref="Unreadable"/>, never <see cref="None"/>.
    /// </summary>
    public static TypeForwarders Read(string? path)
    {
        if (path is null)
            return Unreadable;
        try
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            if (!pe.HasMetadata)
                return Unreadable;
            // Raw rows: no WinRT projection, which CCI does not apply either.
            var metadata = pe.GetMetadataReader(MetadataReaderOptions.None, strictUtf8);
            var rows = metadata.ExportedTypes
                .Select(metadata.GetExportedType)
                .Where(e => e.Implementation.Kind is HandleKind.AssemblyReference or HandleKind.AssemblyFile)
                .Select(e => (e.Namespace, e.Name, IsModule: e.Implementation.Kind == HandleKind.AssemblyFile,
                    Target: e.Implementation.Kind == HandleKind.AssemblyFile
                        ? metadata.GetAssemblyFile((AssemblyFileHandle)e.Implementation).Name
                        : metadata.GetAssemblyReference((AssemblyReferenceHandle)e.Implementation).Name))
                .ToArray();
            var unterminated = UnterminatedFrom(pe, metadata);
            // A nil handle is the empty string at offset 0, which runs unterminated only in a heap with no NUL at all.
            if (rows.Any(r => new[] { r.Namespace, r.Name, r.Target }.Any(h => (!h.IsNil || unterminated == 0) && MetadataTokens.GetHeapOffset(h) >= unterminated)))
                return Unreadable;
            var decoded = rows
                .Select(r => (r.IsModule, Row: ((string?)metadata.GetString(r.Namespace), (string?)metadata.GetString(r.Name), (string?)metadata.GetString(r.Target))))
                .ToArray();
            return Of(decoded.Where(r => !r.IsModule).Select(r => r.Row), decoded.Where(r => r.IsModule).Select(r => r.Row));
        }
        catch (Exception)
        {
            return Unreadable;
        }
    }

    /// <summary>
    /// Forwarders from (namespace, type name, target assembly name) rows, and optionally (namespace, type name, module
    /// file name) rows for types exported from another module of the assembly. An unreadable part is kept as
    /// <see cref="CanonicalName.UnknownPart"/>.
    /// </summary>
    public static TypeForwarders Of(
        IEnumerable<(string? Namespace, string? Name, string? Assembly)> forwards,
        IEnumerable<(string? Namespace, string? Name, string? Module)>? modules = null) =>
        new(forwards.Select(f => (Key: Normalize(f.Namespace, f.Name), IsModule: false, Target: f.Assembly ?? CanonicalName.UnknownPart))
            .Concat((modules ?? []).Select(m => (Key: Normalize(m.Namespace, m.Name), IsModule: true, Target: m.Module ?? CanonicalName.UnknownPart)))
            .GroupBy(r => r.Key)
            .ToDictionary(g => g.Key, g => new Exports(
                Canonical(g.Where(r => !r.IsModule).Select(r => r.Target)),
                Canonical(g.Where(r => r.IsModule).Select(r => r.Target)))));

    /// <summary>The union of <paramref name="forwarders"/> (one assembly name loaded more than once); unreadable if any part is.</summary>
    public static TypeForwarders Merge(IEnumerable<TypeForwarders?> forwarders)
    {
        var all = forwarders.ToArray();
        return all.Any(f => f is not { IsReadable: true }) ? Unreadable
            : new(all.SelectMany(f => f!.exports!)
                .GroupBy(e => e.Key)
                .ToDictionary(g => g.Key, g => new Exports(
                    Canonical(g.SelectMany(e => e.Value.Assemblies)),
                    Canonical(g.SelectMany(e => e.Value.Modules)))));
    }

    /// <summary>
    /// The assemblies a reference to the outermost type <paramref name="namespace"/>.<paramref name="name"/> is forwarded
    /// to, ordinal-sorted; empty when it is not forwarded or the table is unreadable.
    /// </summary>
    public IReadOnlyList<string> Targets(string? @namespace, string? name) =>
        exports?.GetValueOrDefault(Normalize(@namespace, name))?.Assemblies ?? [];

    /// <summary>
    /// The module files of this assembly that export the outermost type <paramref name="namespace"/>.<paramref name="name"/>,
    /// ordinal-sorted. CCI loads only the manifest module, so such a type is never indexed.
    /// </summary>
    public IReadOnlyList<string> Modules(string? @namespace, string? name) =>
        exports?.GetValueOrDefault(Normalize(@namespace, name))?.Modules ?? [];

    private static (string, string) Normalize(string? @namespace, string? name)
    {
        var space = @namespace ?? CanonicalName.UnknownPart;
        var type = name ?? CanonicalName.UnknownPart;
        var tick = type.IndexOf('`');
        return (space.TrimStart('.'), tick < 0 ? type : type[..tick]);
    }

    // The heap offset from which a string runs to the end of the #Strings heap with no NUL: CCI's string reader drops
    // the last byte of such a string, so it would decode differently there than here. Only strings a kept row uses
    // matter (review 6 W-C: junk padding after the last terminator must not cost an assembly that forwards nothing).
    // SRM's heap size leaves out trailing NUL padding only, so a heap that ends in a terminator yields its size.
    private static int UnterminatedFrom(PEReader pe, MetadataReader metadata)
    {
        var size = metadata.GetHeapSize(HeapIndex.String);
        return pe.GetMetadata().GetContent(metadata.GetHeapMetadataOffset(HeapIndex.String), size).LastIndexOf((byte)0) + 1;
    }

    // File and assembly names compare case-insensitively, as everywhere in the index; the ordinal-least spelling is
    // kept, so the result does not depend on row order.
    private static string[] Canonical(IEnumerable<string> names) =>
        names.Order(StringComparer.Ordinal).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    #endregion

    #region Fields
    // Throws on invalid UTF-8 instead of substituting U+FFFD, which would make a name CCI decodes leniently compare
    // unequal (review 5 C-F); Read turns the throw into Unreadable.
    private static readonly MetadataStringDecoder strictUtf8 = new(new UTF8Encoding(false, true));

    private readonly IReadOnlyDictionary<(string Namespace, string Name), Exports>? exports;
    #endregion

    #region Child types
    private sealed record Exports(string[] Assemblies, string[] Modules);
    #endregion
}
