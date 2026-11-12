namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// <see cref="OwnMembers"/> (docs/agent/tasks/ssa-facts-s4.md §3, S4.3): the own types and methods of a graph by name,
/// kept so reflection candidates can be listed after the graph is dropped. Over hand-built graphs
/// (<see cref="MethodGraph.FromParts"/>); the emitted fixture's graph is covered in <see cref="SsaReflectionTargetTests"/>.
/// </summary>
public sealed class OwnMembersTests
{
    #region Methods
    // Overloads share their classification key under their declaring type, ordinal by node id.
    [Fact]
    public void Of_OverloadsGroupedUnderOneKey_Ordinal()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Equal(["App.T.M()", "App.T.M(System.Int32)", "App.T.M(System.String)"], members.Methods("App.T", "App.T.M"));
        Assert.Equal(["App.T.N()"], members.Methods("App.T", "App.T.N"));
    }

    // The same key under another declaring type is not an overload of it.
    [Fact]
    public void Of_KeyedByDeclaringType()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Equal(["App.U.M()"], members.Methods("App.U", "App.U.M"));
        Assert.Empty(members.Methods("App.U", "App.T.M"));
        Assert.Empty(members.Methods("App.T", "App.U.M"));
    }

    // An External node is never own, even with own facts; facts with no node at all are left out too.
    [Fact]
    public void Of_ExternalsAndNodelessFactsExcluded()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Empty(members.Methods("App.T", "Ext.X.M"));
        Assert.Empty(members.Methods("App.T", "App.T.Ghost"));
        Assert.Equal((2, 6), members.Count);
    }

    // A bodyless own method (extern, abstract) is still a member by name.
    [Fact]
    public void Of_BodylessOwnIncluded()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Equal(["App.T.Native()"], members.Methods("App.T", "App.T.Native"));
    }

    // Facts listed twice for one node give it once.
    [Fact]
    public void Of_DuplicateFacts_Distinct()
    {
        var parts = new Parts().Own("App.T.M()", "App.T.M", "App.T").Own("App.T.M()", "App.T.M", "App.T", node: false).Type("App.T");

        var members = OwnMembers.Of(parts.Graph());

        Assert.Equal(["App.T.M()"], members.Methods("App.T", "App.T.M"));
        Assert.Equal((1, 1), members.Count);
    }

    [Fact]
    public void Types_OwnTypesOnly()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Equal(["App.T"], members.Types("App.T"));
        Assert.Equal(["App.U"], members.Types("App.U"));
        Assert.Empty(members.Types("Ext.X"));
        Assert.Empty(members.Types(""));
    }

    // W2: reflection may ignore case, so the lookups do; a by-name candidate over-approximates.
    [Fact]
    public void Types_And_Methods_IgnoreCase()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Equal(["App.T"], members.Types("app.t"));
        Assert.Equal(["App.T"], members.Types("APP.T"));
        Assert.Equal(["App.T.M()", "App.T.M(System.Int32)", "App.T.M(System.String)"], members.Methods("app.t", "APP.T.m"));
    }

    // Case variants are one entry: both type ids under one lookup, and methods of either under one list, ordinal.
    [Fact]
    public void CaseVariants_OneListEach_Ordinal()
    {
        var parts = new Parts()
            .Own("App.T.M()", "App.T.M", "App.T")
            .Own("APP.T.m()", "APP.T.m", "APP.T")
            .Type("App.T")
            .Type("APP.T");

        var members = OwnMembers.Of(parts.Graph());

        Assert.Equal(["APP.T", "App.T"], members.Types("app.t"));
        Assert.Equal(["APP.T.m()", "App.T.M()"], members.Methods("App.T", "App.T.M"));
        Assert.Same(members.Methods("App.T", "App.T.M"), members.Methods("APP.T", "app.t.m"));
        Assert.Equal((2, 2), members.Count);
    }

    [Fact]
    public void Methods_UnknownKey_Empty()
    {
        var members = OwnMembers.Of(Graph());

        Assert.Empty(members.Methods("App.T", "App.T.Nothing"));
        Assert.Empty(members.Methods("App.Nowhere", "App.Nowhere.M"));
        Assert.Empty(members.Methods("App.T", "App.TM"));
    }

    [Fact]
    public void None_IsEmpty_WithAGap()
    {
        Assert.Equal((0, 0), OwnMembers.None.Count);
        Assert.Empty(OwnMembers.None.Types("App.T"));
        Assert.Empty(OwnMembers.None.Methods("App.T", "App.T.M"));
        Assert.Equal("no own-member index was given", OwnMembers.None.Gap);
        Assert.Same(OwnMembers.None, OwnMembers.None);
    }

    [Fact]
    public void Of_EmptyGraph_IsEmpty_NoGap()
    {
        var members = OwnMembers.Of(new Parts().Graph());

        Assert.Equal((0, 0), members.Count);
        Assert.Null(members.Gap);
    }

    // ---- Gap -----------------------------------------------------------------------------------------------------------

    [Fact]
    public void Gap_WholeGraph_Null() => Assert.Null(OwnMembers.Of(Graph()).Gap);

    [Fact]
    public void Gap_TruncatedGraph_SaysSo()
    {
        var members = OwnMembers.Of(new Parts().Own("App.T.M()", "App.T.M", "App.T").Type("App.T").Graph(truncated: true));

        Assert.Equal("the graph was truncated, so some own members are not in it", members.Gap);
        Assert.Equal(["App.T.M()"], members.Methods("App.T", "App.T.M"));
    }

    [Fact]
    public void Gap_UnreadableDeclaringType_SaysSo()
    {
        var members = OwnMembers.Of(new Parts().Own("App.T.M()", "App.T.M", "App.T").Own("App.X.N()", "App.X.N", CanonicalName.UnknownPart).Type("App.T").Graph());

        Assert.Equal("some own methods' declaring types could not be read", members.Gap);
        Assert.Equal(["App.T.M()"], members.Methods("App.T", "App.T.M"));
    }

    // An unreadable declaring type on an External node's facts still counts: the facts, not the nodes, are checked.
    [Fact]
    public void Gap_UnreadableDeclaringTypeOnAnyFacts_SaysSo() =>
        Assert.NotNull(OwnMembers.Of(new Parts().Own("Ext.X.M()", "Ext.X.M", CanonicalName.UnknownPart, MethodNodeKind.External).Graph()).Gap);

    // Truncation is named first when both hold.
    [Fact]
    public void Gap_TruncatedAndUnreadable_TruncationNamed() =>
        Assert.Equal("the graph was truncated, so some own members are not in it",
            OwnMembers.Of(new Parts().Own("App.X.N()", "App.X.N", CanonicalName.UnknownPart).Graph(truncated: true)).Gap);

    [Fact]
    public void Of_Null_Throws() => Assert.Throws<ArgumentNullException>(() => OwnMembers.Of(null!));

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    // App.T: M(), M(int), M(string) (listed out of order), N(), Native() (bodyless); App.U: M(); an External Ext.X.M() with
    // own facts naming App.T; facts for App.T.Ghost() with no node.
    private static MethodGraph Graph() => new Parts()
        .Own("App.T.M(System.String)", "App.T.M", "App.T")
        .Own("App.T.M()", "App.T.M", "App.T")
        .Own("App.T.M(System.Int32)", "App.T.M", "App.T")
        .Own("App.T.N()", "App.T.N", "App.T")
        .Own("App.T.Native()", "App.T.Native", "App.T", MethodNodeKind.OwnBodyless)
        .Own("App.U.M()", "App.U.M", "App.U")
        .Own("Ext.X.M()", "Ext.X.M", "App.T", MethodNodeKind.External)
        .Own("App.T.Ghost()", "App.T.Ghost", "App.T", node: false)
        .Type("App.T")
        .Type("App.U")
        .Graph();
    #endregion

    #region Fields
    private static readonly GraphCoverage complete = new(new IndexCoverage(0, 0, 0), 0, 0, 0, 0, ResolutionCounts.None, 0, 0, 0, 0, 0, 0, 0, false, null);
    #endregion

    #region Child types
    private sealed class Parts
    {
        public System.Collections.Generic.List<MethodNode> Nodes { get; } = [];
        public System.Collections.Generic.List<OwnMethodFacts> Methods { get; } = [];
        public System.Collections.Generic.List<OwnTypeFacts> Types { get; } = [];

        public Parts Own(string id, string key, string type, MethodNodeKind kind = MethodNodeKind.OwnWithBody, bool node = true)
        {
            if (node)
                Nodes.Add(new MethodNode(id, key, kind));
            Methods.Add(new OwnMethodFacts(id, "App.dll", type, RootClass.PublicApi, false, true));
            return this;
        }

        public Parts Type(string id)
        {
            Types.Add(new OwnTypeFacts(id, "App.dll", true));
            return this;
        }

        public MethodGraph Graph(bool truncated = false) =>
            MethodGraph.FromParts(Nodes, [], [], complete with { Truncated = truncated, TruncatedBy = truncated ? "test" : null }, new GraphFacts(Methods, Types, []));
    }
    #endregion
}
