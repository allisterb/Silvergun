namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// The own types and methods of a <see cref="MethodGraph"/> by name, kept as plain data so a reflection target can list
/// its by-name candidates after the graph is dropped (ADR 0038, S4.3). Methods are keyed by their declaring type's node
/// id and their classification key, so overloads share an entry. Both lookups ignore case: reflection may, and a
/// by-name candidate over-approximates. Holds every own method's node id for as long as it lives.
/// </summary>
public sealed class OwnMembers
{
    #region Constructors
    private OwnMembers(Dictionary<string, string[]> types, Dictionary<(string Type, string Key), string[]> methods, string? gap)
    {
        this.types = types;
        this.methods = methods;
        Gap = gap;
    }
    #endregion

    #region Properties
    /// <summary>No members: nothing is a candidate, and <see cref="Gap"/> says so.</summary>
    public static OwnMembers None { get; } = new(new(StringComparer.OrdinalIgnoreCase), new(new IgnoreCase()), "no own-member index was given");

    /// <summary>Why the index may lack own members (a truncated graph, unreadable facts); null when it is whole.</summary>
    public string? Gap { get; }

    /// <summary>How many own types and methods are indexed.</summary>
    public (int Types, int Methods) Count => (types.Values.Sum(t => t.Length), methods.Values.Sum(m => m.Length));
    #endregion

    #region Methods
    /// <summary>The own types (<see cref="GraphFacts.Types"/>) and own method nodes of <paramref name="graph"/>.</summary>
    public static OwnMembers Of(MethodGraph graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        var methods = graph.Facts.Methods
            .Select(f => (Facts: f, Node: graph.Node(f.NodeId)))
            .Where(m => m.Node is { Kind: not MethodNodeKind.External })
            .GroupBy(m => (m.Facts.DeclaringTypeId, m.Node!.ClassificationKey), new IgnoreCase())
            .ToDictionary(g => g.Key, g => Sorted(g.Select(m => m.Facts.NodeId)), new IgnoreCase());
        var types = graph.Facts.Types
            .GroupBy(t => t.TypeId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => Sorted(g.Select(t => t.TypeId)), StringComparer.OrdinalIgnoreCase);
        var gap = graph.Coverage.Truncated ? "the graph was truncated, so some own members are not in it"
            : graph.Facts.Methods.Any(f => f.DeclaringTypeId == CanonicalName.UnknownPart) ? "some own methods' declaring types could not be read"
            : null;
        return new OwnMembers(types, methods, gap);
    }

    /// <summary>The own type node ids equal to <paramref name="typeId"/> but for case, ordinal.</summary>
    public IReadOnlyList<string> Types(string typeId) => types.GetValueOrDefault(typeId) ?? [];

    /// <summary>
    /// The node ids of the own methods whose declaring type id and classification key equal <paramref name="typeId"/>
    /// and <paramref name="key"/> but for case, ordinal. A node is under exactly one entry.
    /// </summary>
    public IReadOnlyList<string> Methods(string typeId, string key) => methods.GetValueOrDefault((typeId, key)) ?? [];

    private static string[] Sorted(IEnumerable<string> ids) => [.. ids.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    #endregion

    #region Fields
    private readonly Dictionary<string, string[]> types;
    private readonly Dictionary<(string Type, string Key), string[]> methods;
    #endregion

    #region Child types
    private sealed class IgnoreCase : IEqualityComparer<(string Type, string Key)>
    {
        #region Methods
        public bool Equals((string Type, string Key) x, (string Type, string Key) y) =>
            StringComparer.OrdinalIgnoreCase.Equals(x.Type, y.Type) && StringComparer.OrdinalIgnoreCase.Equals(x.Key, y.Key);

        public int GetHashCode((string Type, string Key) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Type), StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Key));
        #endregion
    }
    #endregion
}
