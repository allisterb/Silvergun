namespace Silvergun.CodeAnalysis.IL.Ssa;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

/// <summary>What SSA proves about one value at a sink site.</summary>
public enum SsaValueKind
{
    /// <summary>One constant (<see cref="SsaValue.Constants"/> holds it).</summary>
    Constant,
    /// <summary>One of two or more constants, through phis (<see cref="SsaValue.Constants"/>, sorted).</summary>
    OneOf,
    /// <summary>The caller's own argument (<see cref="SsaValue.Parameter"/>), directly or through phis of only it.</summary>
    Parameter,
    /// <summary>Anything else (<see cref="SsaValue.Origin"/> says where it came from).</summary>
    Dynamic,
}

/// <summary>The kind of an <see cref="SsaConstant"/>.</summary>
public enum SsaConstantKind
{
    String,
    /// <summary>An integer, bool or char, in decimal.</summary>
    Int,
    /// <summary>A floating-point number, round-trippable.</summary>
    Float,
    Null,
    /// <summary>A type token (<c>typeof(T)</c>), as T's canonical type name.</summary>
    Type,
}

/// <summary>Where a <see cref="SsaValueKind.Dynamic"/> value came from.</summary>
public enum SsaDynamicOrigin
{
    /// <summary>A call's or <c>newobj</c>'s result (constants are not folded, so <c>string.Concat</c> lands here).</summary>
    CallResult,
    /// <summary>A field's value, static or instance.</summary>
    FieldLoad,
    /// <summary>An array element.</summary>
    ArrayElement,
    /// <summary>A local or argument whose address was taken, or another memory read.</summary>
    Memory,
    /// <summary>A phi web of more distinct constants than <see cref="SsaFactBounds.MaxAlternatives"/>.</summary>
    TooManyAlternatives,
    /// <summary>A phi web deeper or wider than the walk's bound.</summary>
    TooDeep,
    /// <summary>Arithmetic, a conversion, an undefined value, or a mix of kinds.</summary>
    Other,
}

/// <summary>Whether a sink site was analysed. Every site in the table carries one; none is dropped (ADR 0030).</summary>
public enum SsaSiteStatus
{
    /// <summary>Its values are present.</summary>
    Analyzed,
    /// <summary>Its method (a definition under its node id) did not lift; the fact carries the kind and reason.</summary>
    MethodUnknown,
    /// <summary>The method lifted, but no instruction of the edge's kind carries the offset, or no method lifted under its node id.</summary>
    NotJoined,
    /// <summary>The method budget or the time budget was spent before its method.</summary>
    NotRun,
}

/// <summary>
/// A constant: <paramref name="Text"/> is escaped losslessly (<see cref="UntrustedText.EscapeBounded(string, int)"/>), bounded by
/// <see cref="SsaFactBounds.MaxTextChars"/>, and once the folder's text budget is spent only the hash suffix
/// (<see cref="UntrustedText.HashOnly"/>). <paramref name="Cut"/>: the text is not whole, so it ends with the suffix
/// (read this, never the text, to tell). Always well-formed. Still attacker text: escape it again for display.
/// </summary>
public sealed record SsaConstant(SsaConstantKind Kind, string Text, bool Cut = false);

/// <summary>
/// One value at a sink site. <see cref="Constants"/> holds one constant (<see cref="SsaValueKind.Constant"/>) or the
/// ordinal-sorted alternatives (<see cref="SsaValueKind.OneOf"/>), and is otherwise empty; <see cref="Parameter"/> is the
/// caller's IL argument index (0 is <c>this</c> in an instance method); <see cref="Origin"/> is set on a Dynamic value.
/// </summary>
public sealed record SsaValue(SsaValueKind Kind, IReadOnlyList<SsaConstant> Constants, int? Parameter, SsaDynamicOrigin? Origin)
{
    #region Methods
    public static SsaValue OfConstant(SsaConstant constant) => new(SsaValueKind.Constant, [constant], null, null);

    public static SsaValue OfParameter(int index) => new(SsaValueKind.Parameter, [], index, null);

    public static SsaValue OfDynamic(SsaDynamicOrigin origin) => new(SsaValueKind.Dynamic, [], null, origin);

    /// <summary>Structural equality, which a record over a list does not give.</summary>
    public bool SameAs(SsaValue other) =>
        Kind == other.Kind && Parameter == other.Parameter && Origin == other.Origin && Constants.SequenceEqual(other.Constants);
    #endregion
}

/// <summary>
/// What SSA proves at one sink site (ADR 0038; labelled SSA-derived wherever it is shown). <see cref="Site"/> names are
/// bounded like a report's (<see cref="Reachability.BoundName"/>). When <see cref="Status"/> is
/// <see cref="SsaSiteStatus.Analyzed"/>: <see cref="Receiver"/> is the instance a call or <c>ldvirtftn</c> is made on
/// (null for a static call, <c>newobj</c> or <c>ldftn</c>), and <see cref="Arguments"/> the first
/// <see cref="SsaFactBounds.MaxArguments"/> arguments in signature order, of <see cref="ArgumentCount"/>. Otherwise both
/// are empty and <see cref="Reason"/> says why (with <see cref="FailureKind"/> for MethodUnknown). <see cref="Merged"/>:
/// more than one definition under the node id contributed, and their values are unioned.
/// </summary>
public sealed record SsaSinkFact(
    SinkSite Site,
    SsaSiteStatus Status,
    SsaValue? Receiver,
    IReadOnlyList<SsaValue> Arguments,
    int ArgumentCount,
    bool Merged,
    SsaFailureKind? FailureKind,
    string? Reason);

/// <summary>One kind of lift failure and how many methods failed with it.</summary>
public sealed record SsaFailureCount(SsaFailureKind Kind, int Methods);

/// <summary>
/// The SSA facts of one folder: one <see cref="SsaSinkFact"/> per sink site kept, in site order. <see cref="SitesTotal"/>
/// counts the sites given; past <see cref="SsaFactBounds.MaxSites"/> the rest are cut (<see cref="Truncated"/>).
/// <see cref="MethodsLifted"/> and <see cref="Unknown"/> count the definitions tried; <see cref="MethodBudget"/> and
/// <see cref="TimeBudget"/> say a budget stopped the lifting (the sites not reached are NotRun; a folder cut by time is not
/// deterministic). <see cref="TextBudget"/>: the folder's text budget was spent, so later constants keep only their hash.
/// <see cref="AssembliesLost"/> counts the folder's assemblies the session could not read; when any was, nothing is
/// lifted and every site is MethodUnknown.
/// </summary>
public sealed record SsaFolderFacts(
    IReadOnlyList<SsaSinkFact> Sites,
    int SitesTotal,
    bool Truncated,
    int MethodsLifted,
    IReadOnlyList<SsaFailureCount> Unknown,
    bool MethodBudget,
    bool TimeBudget,
    bool TextBudget,
    int AssembliesLost)
{
    #region Methods
    /// <summary>How many sites have <paramref name="status"/>.</summary>
    public int Count(SsaSiteStatus status) => Sites.Count(s => s.Status == status);
    #endregion
}

/// <summary>Bounds on the SSA facts of one folder. Every cap but <see cref="FolderTime"/> is deterministic.</summary>
public sealed record SsaFactBounds
{
    #region Properties
    public static SsaFactBounds Default { get; } = new();

    /// <summary>Sink sites per folder; the rest are cut, flagged <see cref="SsaFolderFacts.Truncated"/>.</summary>
    public int MaxSites { get; init; } = 8_192;

    /// <summary>Arguments kept per site.</summary>
    public int MaxArguments { get; init; } = 8;

    /// <summary>Distinct constants a <see cref="SsaValueKind.OneOf"/> holds; more is <see cref="SsaDynamicOrigin.TooManyAlternatives"/>.</summary>
    public int MaxAlternatives { get; init; } = 4;

    /// <summary>Phis followed from a value, deep; past it the value is <see cref="SsaDynamicOrigin.TooDeep"/>.</summary>
    public int MaxPhiDepth { get; init; } = 16;

    /// <summary>Phi inputs read from one value in all; past it the value is <see cref="SsaDynamicOrigin.TooDeep"/>.</summary>
    public int MaxPhiInputs { get; init; } = 1_024;

    /// <summary>Chars of one constant's text, escaped (<see cref="UntrustedText.EscapeBounded(string, int)"/>).</summary>
    public int MaxTextChars { get; init; } = 256;

    /// <summary>
    /// Chars of String and Type constant text kept whole per folder; once spent, each further one keeps only its hash
    /// suffix (about 40 chars). So a folder's constant text is at most this plus 40 per constant beyond it, and a fact's
    /// names (three per site) at most <see cref="Reachability.MaxNameChars"/> plus 40 each.
    /// </summary>
    public int MaxFactTextChars { get; init; } = 1_000_000;

    /// <summary>
    /// Method definitions tried per folder, failures included; checked between node ids, so all of one node's are tried
    /// or none.
    /// </summary>
    public int MaxLiftedMethods { get; init; } = 50_000;

    /// <summary>Wall clock per folder, checked between node ids and between sites: the backstop.</summary>
    public TimeSpan FolderTime { get; init; } = TimeSpan.FromSeconds(60);
    #endregion

    #region Methods
    /// <summary>Throws if a bound is not positive.</summary>
    public SsaFactBounds Validated()
    {
        if (MaxSites <= 0 || MaxArguments <= 0 || MaxAlternatives <= 0 || MaxPhiDepth <= 0 || MaxPhiInputs <= 0
            || MaxTextChars <= 0 || MaxFactTextChars <= 0 || MaxLiftedMethods <= 0 || FolderTime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(SsaFactBounds), "Every bound must be positive");
        return this;
    }
    #endregion
}
