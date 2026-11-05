namespace Silvergun.CodeAnalysis.IL;

using System.Collections.Generic;

/// <summary>
/// How strong the evidence for a reached sink is (ADR 0037 decision 7): the weakest edge set it is reachable over.
/// Each set contains the one before it, so a <see cref="Bound"/> root is also reachable at both others.
/// </summary>
public enum ReachEvidence
{
    /// <summary>Without any <see cref="MethodEdgeKind.Dispatch"/> edge.</summary>
    Bound,

    /// <summary>With Dispatch edges only to live types (<see cref="OwnTypeFacts.Live"/>) or static targets: rapid type analysis, adapted to a library.</summary>
    Instantiated,

    /// <summary>Only with class-hierarchy analysis's full Dispatch fan-out.</summary>
    ChaOnly
}

/// <summary>What a root class reaches, said so that an analysis that could not see is never read as clean (ADR 0030).</summary>
public enum RootClassVerdict
{
    /// <summary>Its roots reach no capability, nothing was unseen, and its coverage is complete.</summary>
    None,

    /// <summary>Its roots reach at least one capability, and nothing made the class uncertain.</summary>
    Reaches,

    /// <summary>A gap, an unseen reach or a truncated graph: what it reaches may be more than reported.</summary>
    Unknown
}

/// <summary>One step of a <see cref="ReachPath"/>: the node, its assembly (own nodes only), and the edge that led to it (null on the root).</summary>
public sealed record ReachHop(string NodeId, string? Assembly, MethodEdgeKind? Via, uint Offset);

/// <summary>
/// An example path from <paramref name="Root"/> to a sink, over the edge set of <paramref name="Evidence"/>; the last hop
/// is the sink. <paramref name="Length"/> is the number of hops on the whole path. A path longer than
/// <see cref="Reachability.MaxPathHops"/> keeps its first hops and its last two (<paramref name="Truncated"/>), so a
/// report's size never grows with path length. <paramref name="EndsInOpacity"/> names what could not be seen when the
/// sink is an opacity site.
/// </summary>
public sealed record ReachPath(string Root, ReachEvidence Evidence, IReadOnlyList<ReachHop> Hops, int Length, bool Truncated, OpacityKind? EndsInOpacity);

/// <summary>A call edge the map's <c>ignore-edge</c> rules cut, by the classification keys of its two ends.</summary>
public sealed record IgnoredEdge(string Caller, string Callee);

/// <summary>
/// The roots of one <paramref name="Class"/> that reach one sink: <paramref name="Capability"/>, or code the graph cannot
/// see when null. <paramref name="Roots"/> counts them at <see cref="ReachEvidence.ChaOnly"/>; <paramref name="Bound"/> and
/// <paramref name="Instantiated"/> count those reaching it on the stronger edge sets. Up to three examples, strongest first.
/// </summary>
public sealed record CapabilityReach(RootClass Class, Capability? Capability, int Roots, int Bound, int Instantiated, IReadOnlyList<ReachPath> Examples);

/// <summary>
/// A composition: <paramref name="Roots"/> roots of <paramref name="Class"/> reach exactly <paramref name="Capabilities"/>
/// (and unseen code, when <paramref name="Unseen"/>) at <see cref="ReachEvidence.ChaOnly"/>. <paramref name="ExampleRoot"/> is the ordinal-least.
/// </summary>
public sealed record ReachProfile(RootClass Class, IReadOnlyList<Capability> Capabilities, bool Unseen, int Roots, string ExampleRoot);

/// <summary>One root class's verdict, how many roots it has, and why it is <see cref="RootClassVerdict.Unknown"/> when it is.</summary>
public sealed record RootClassStatus(RootClass Class, int Roots, RootClassVerdict Verdict, IReadOnlyList<string> Reasons);

/// <summary>
/// What one <see cref="MethodGraph"/>'s roots can reach (ADR 0037): per root class and sink, with examples
/// (<see cref="Reaches"/>; a null <see cref="CapabilityReach.Capability"/> is unseen code); the capability sets reached
/// together (<see cref="Profiles"/>, at most 64 per class, <see cref="ProfilesTruncated"/> when any class had more); a
/// verdict per class (<see cref="Classes"/>); and the <c>ignore-edge</c> cuts applied (<see cref="EdgesIgnored"/> edges,
/// <see cref="IgnoredEdges"/> distinct key pairs). <see cref="Partial"/> when the graph was truncated or the analysis
/// failed, with <see cref="PartialReason"/>. A reachable capability is possible, not proven.
/// </summary>
public sealed record ReachabilityReport(
    IReadOnlyList<CapabilityReach> Reaches,
    IReadOnlyList<ReachProfile> Profiles,
    bool ProfilesTruncated,
    IReadOnlyList<RootClassStatus> Classes,
    int EdgesIgnored,
    IReadOnlyList<IgnoredEdge> IgnoredEdges,
    GraphCoverage Graph,
    bool Partial,
    string? PartialReason);
