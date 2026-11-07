namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// The two root-tagging directives of the capability map (reachability R1, S1.3; ADR 0037 decision 4):
/// <c>root-attribute &lt;AttributeType&gt; &lt;LoadTime|NativeEntry&gt;</c> and <c>host-contract &lt;Supertype&gt;</c>.
/// <para>
/// Same contracts as the classification directives (<see cref="CapabilityMapTests"/>): the loader never throws, a bad
/// line is rejected with a reason in <see cref="CapabilityMapStats.RejectedLines"/>, and an override layers over its
/// base. Root entries are not classification entries, so they never move <see cref="CapabilityMapStats.TotalEntries"/>
/// or a <see cref="CapabilityMap.Classify"/> verdict. Hermetic: no assembly is loaded.
/// </para>
/// </summary>
public sealed class CapabilityMapRootDirectiveTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Parse
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("LoadTime", RootClass.LoadTime)]
    [InlineData("NativeEntry", RootClass.NativeEntry)]
    public void Load_RootAttribute_RecordsTheAttributeWithItsClass(string name, RootClass expected)
    {
        var map = Map($"root-attribute Ns.StartAttribute {name}");

        Assert.Equal(new Dictionary<string, RootClass> { ["Ns.StartAttribute"] = expected }, map.RootAttributes.ToDictionary());
        Assert.Equal(1, map.Stats.RootAttributes);
        Assert.Empty(map.Stats.RejectedLines);
    }

    [Fact]
    public void Load_HostContract_RecordsTheSupertype()
    {
        var map = Map("host-contract Ns.IHostTask");

        Assert.Equal(["Ns.IHostTask"], map.HostContracts);
        Assert.Equal(1, map.Stats.HostContracts);
        Assert.Empty(map.Stats.RejectedLines);
    }

    // A generic contract is written with its CLR arity suffix: host contracts are matched by type node id.
    [Fact]
    public void Load_HostContractWithAnAritySuffix_IsAccepted()
    {
        var map = Map("host-contract Ns.IHost`1");

        Assert.Equal(["Ns.IHost`1"], map.HostContracts);
        Assert.Empty(map.Stats.RejectedLines);
    }

    // Root entries tag roots; they are not classification entries and must not leak into Classify or the entry counts.
    [Fact]
    public void Load_RootDirectives_AreNotClassificationEntries()
    {
        var map = Map(
            """
            root-attribute Ns.StartAttribute LoadTime
            host-contract  Ns.IHostTask
            """);

        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(0, map.Stats.IgnoredEdges);
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.StartAttribute..ctor"));
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.IHostTask.Execute"));
    }

    [Fact]
    public void Load_MixedWithClassificationDirectives_CountsEachKindSeparately()
    {
        var map = Map(
            """
            capability Ns.A Network
            root-attribute Ns.StartAttribute LoadTime
            root-attribute Ns.ExportAttribute NativeEntry
            safe Ns.B
            host-contract Ns.IHostTask
            host-contract Ns.HostBase
            host-contract Ns.IHostGenerator   # a trailing comment
            ignore-edge Ns.A Ns.B
            """);

        Assert.Equal(new CapabilityMapStats(1, 1, 0, 0, 1, [], 2, 3), map.Stats);
        Assert.Equal(["Ns.HostBase", "Ns.IHostGenerator", "Ns.IHostTask"], map.HostContracts);   // ordinal-sorted
    }

    // Directive keywords and the root-class name are matched case-insensitively, like a capability name; the type
    // name itself is a pattern, compared ordinally.
    [Theory]
    [InlineData("ROOT-ATTRIBUTE Ns.StartAttribute loadtime", RootClass.LoadTime)]
    [InlineData("Root-Attribute Ns.StartAttribute LOADTIME", RootClass.LoadTime)]
    [InlineData("root-attribute Ns.StartAttribute nativeentry", RootClass.NativeEntry)]
    [InlineData("root-attribute Ns.StartAttribute NATIVEENTRY", RootClass.NativeEntry)]
    public void Load_RootClassName_IsMatchedCaseInsensitively(string line, RootClass expected)
    {
        var map = Map(line);

        Assert.Empty(map.Stats.RejectedLines);
        Assert.Equal(expected, map.RootAttributes["Ns.StartAttribute"]);
    }

    [Fact]
    public void Load_HostContractKeyword_IsMatchedCaseInsensitively_AndTheTypeNameKeepsItsCase()
    {
        var map = Map("HOST-CONTRACT Ns.IHostTask");

        Assert.Empty(map.Stats.RejectedLines);
        Assert.Equal(["Ns.IHostTask"], map.HostContracts);
    }

    [Fact]
    public void Load_RootAttributeTypeName_IsKeptOrdinally()
    {
        var map = Map("root-attribute Ns.StartAttribute LoadTime");

        Assert.False(map.RootAttributes.ContainsKey("ns.startattribute"));
        Assert.True(map.RootAttributes.ContainsKey("Ns.StartAttribute"));
    }

    // ---------------------------------------------------------------------------------------------------
    // Reject, never throw
    // ---------------------------------------------------------------------------------------------------

    // Only LoadTime and NativeEntry may come from an attribute; every other class comes from structure (visibility,
    // contracts, .cctor, Finalize), so naming one here is a mistake, not an extension. A numeric value is never the enum
    // value (16 is NativeEntry's). RuntimeInvoked is gone (ADR 0037 amendment a1): a map still naming it is malformed.
    [Theory]
    [InlineData("PublicApi")]
    [InlineData("HostContract")]
    [InlineData("PublicContract")]
    [InlineData("Hidden")]
    [InlineData("None")]
    [InlineData("TypeInitializer")]
    [InlineData("Finalizer")]
    [InlineData("RuntimeInvoked")]
    [InlineData("runtimeinvoked")]
    [InlineData("LoadTime|NativeEntry")]
    [InlineData("LoadTime,NativeEntry")]
    [InlineData("1")]
    [InlineData("4")]
    [InlineData("16")]
    [InlineData("Telepathy")]
    public void Load_RootAttributeWithAnUnknownOrDisallowedClass_IsRejectedWithAReason(string name)
    {
        var map = Map($"root-attribute Ns.StartAttribute {name}");

        var reject = Assert.Single(map.Stats.RejectedLines);
        Assert.StartsWith("test.cm: (1): ", reject, StringComparison.Ordinal);
        Assert.Contains($"unknown root class '{name}'", reject, StringComparison.Ordinal);
        Assert.Empty(map.RootAttributes);
        Assert.Equal(0, map.Stats.RootAttributes);
    }

    // The old class name, exactly as a pre-amendment map wrote it: rejected with the new message, naming the two classes
    // an attribute may confer, and the attribute is not silently given another class.
    [Fact]
    public void Load_RootAttributeWithTheRetiredRuntimeInvokedClass_IsRejectedWithTheNewMessage()
    {
        var map = Map(
            """
            root-attribute Ns.StartAttribute LoadTime
            root-attribute Ns.ExportAttribute RuntimeInvoked
            """);

        var reject = Assert.Single(map.Stats.RejectedLines);
        Assert.Equal("test.cm: (2): unknown root class 'RuntimeInvoked' (expected LoadTime or NativeEntry)", reject);
        Assert.Equal(new Dictionary<string, RootClass> { ["Ns.StartAttribute"] = RootClass.LoadTime }, map.RootAttributes.ToDictionary());
    }

    [Theory]
    [InlineData("root-attribute")]
    [InlineData("root-attribute Ns.StartAttribute")]
    [InlineData("root-attribute Ns.StartAttribute LoadTime extra")]
    [InlineData("host-contract")]
    [InlineData("host-contract Ns.IHostTask extra")]
    [InlineData("host-contract Ns.IHostTask LoadTime")]
    public void Load_RootDirectiveWithTheWrongArity_IsRejectedWithAReason(string line)
    {
        var map = Map(line);

        var reject = Assert.Single(map.Stats.RejectedLines);
        Assert.Contains("argument", reject, StringComparison.Ordinal);
        Assert.Empty(map.RootAttributes);
        Assert.Empty(map.HostContracts);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("*")]
    [InlineData("a.*b")]
    [InlineData("*.Ns")]
    [InlineData("Ns.Type.")]
    [InlineData(".Ns.Type")]
    [InlineData(".*")]
    [InlineData("Ns.*.Type")]
    public void Load_RootDirectiveWithAMalformedPattern_IsRejectedWithAReason(string pattern)
    {
        var map = Map(
            $"""
            root-attribute {pattern} LoadTime
            host-contract {pattern}
            """);

        Assert.Equal(2, map.Stats.RejectedLineCount);
        Assert.All(map.Stats.RejectedLines, r => Assert.Contains("malformed pattern", r, StringComparison.Ordinal));
        Assert.Empty(map.RootAttributes);
        Assert.Empty(map.HostContracts);
    }

    // A subtree would tag whatever a package names into it - a package could make its own code a "host" root, or
    // shelter a namespace - so both directives take an exact type name only.
    [Theory]
    [InlineData("Ns.*")]
    [InlineData("Microsoft.Build.*")]
    [InlineData("Microsoft.CodeAnalysis.Diagnostics.*")]
    public void Load_RootDirectiveWithASubtreePattern_IsRejectedWithAReason(string pattern)
    {
        var map = Map(
            $"""
            root-attribute {pattern} NativeEntry
            host-contract {pattern}
            """);

        Assert.Equal(2, map.Stats.RejectedLineCount);
        Assert.All(map.Stats.RejectedLines, r => Assert.Contains("subtree", r, StringComparison.Ordinal));
        Assert.Empty(map.RootAttributes);
        Assert.Empty(map.HostContracts);
        Assert.Equal(0, map.Stats.TotalEntries);   // nor did the subtree slip in as a classification prefix
    }

    // A rejected root line never costs the lines around it.
    [Fact]
    public void Load_RejectedRootLine_DoesNotPreventTheRestOfTheFileFromLoading()
    {
        var map = Map(
            """
            root-attribute Ns.BeforeAttribute LoadTime
            root-attribute Ns.BrokenAttribute PublicApi
            host-contract Ns.*
            host-contract Ns.IAfter
            capability Ns.Sink Network
            """);

        Assert.Equal(new Dictionary<string, RootClass> { ["Ns.BeforeAttribute"] = RootClass.LoadTime }, map.RootAttributes.ToDictionary());
        Assert.Equal(["Ns.IAfter"], map.HostContracts);
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Sink.Member"));
        Assert.Equal(2, map.Stats.RejectedLineCount);
        Assert.StartsWith("test.cm: (2): ", map.Stats.RejectedLines[0], StringComparison.Ordinal);
        Assert.StartsWith("test.cm: (3): ", map.Stats.RejectedLines[1], StringComparison.Ordinal);
    }

    // Within one file the last line for an attribute wins, and a repeated host contract is one entry.
    [Fact]
    public void Load_RepeatedRootEntries_CollapseWithTheLastAttributeClassWinning()
    {
        var map = Map(
            """
            root-attribute Ns.StartAttribute LoadTime
            root-attribute Ns.StartAttribute NativeEntry
            host-contract Ns.IHostTask
            host-contract Ns.IHostTask
            """);

        Assert.Equal(RootClass.NativeEntry, map.RootAttributes["Ns.StartAttribute"]);
        Assert.Equal(1, map.Stats.RootAttributes);
        Assert.Equal(["Ns.IHostTask"], map.HostContracts);
        Assert.Equal(1, map.Stats.HostContracts);
        Assert.Empty(map.Stats.RejectedLines);
    }

    // ---------------------------------------------------------------------------------------------------
    // Layering over a base map
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Load_OverrideOverBase_AddsItsRootEntriesAndKeepsTheBases()
    {
        var baseMap = Map(
            """
            root-attribute Ns.BaseAttribute LoadTime
            host-contract Ns.IBaseHost
            """);

        var map = Map(
            """
            root-attribute Ns.AddedAttribute NativeEntry
            host-contract Ns.IAddedHost
            """,
            baseMap);

        Assert.Equal(
            new Dictionary<string, RootClass> { ["Ns.AddedAttribute"] = RootClass.NativeEntry, ["Ns.BaseAttribute"] = RootClass.LoadTime },
            map.RootAttributes.ToDictionary());
        Assert.Equal(["Ns.IAddedHost", "Ns.IBaseHost"], map.HostContracts);
        Assert.Equal((2, 2), (map.Stats.RootAttributes, map.Stats.HostContracts));
    }

    // Last wins for an attribute's class: the override re-classes the base's attribute, counted once.
    [Fact]
    public void Load_OverrideOverBase_ReplacesTheClassOfAnAttributeTheBaseNames()
    {
        var baseMap = Map("root-attribute Ns.StartAttribute LoadTime");

        var map = Map("root-attribute Ns.StartAttribute NativeEntry", baseMap);

        Assert.Equal(RootClass.NativeEntry, map.RootAttributes["Ns.StartAttribute"]);
        Assert.Equal(1, map.Stats.RootAttributes);

        // The base map itself is unaffected: layering builds a new map.
        Assert.Equal(RootClass.LoadTime, baseMap.RootAttributes["Ns.StartAttribute"]);
    }

    [Fact]
    public void Load_OverrideOverBase_RepeatingABaseHostContract_CountsItOnce()
    {
        var baseMap = Map("host-contract Ns.IHostTask");

        var map = Map("host-contract Ns.IHostTask", baseMap);

        Assert.Equal(["Ns.IHostTask"], map.HostContracts);
        Assert.Equal(1, map.Stats.HostContracts);
    }

    // A wholly unparseable override degrades to the base's roots rather than dropping them.
    [Fact]
    public void Load_RejectedOverrideLines_LeaveTheBasesRootEntriesInPlace()
    {
        var baseMap = Map(
            """
            root-attribute Ns.StartAttribute LoadTime
            host-contract Ns.IHostTask
            """);

        var map = Map(
            """
            root-attribute Ns.StartAttribute PublicApi
            host-contract Ns.*
            """,
            baseMap);

        Assert.Equal(RootClass.LoadTime, map.RootAttributes["Ns.StartAttribute"]);
        Assert.Equal(["Ns.IHostTask"], map.HostContracts);
        Assert.Equal(2, map.Stats.RejectedLineCount);
    }

    // The built-in map layered under an override still carries the built-in entries.
    [Fact]
    public void Load_OverrideOverTheDefault_KeepsTheBuiltInRootEntries()
    {
        var map = Map("host-contract Ns.IHostTask", CapabilityMap.Default);

        Assert.Contains("Microsoft.Build.Framework.ITask", map.HostContracts);
        Assert.Contains("Ns.IHostTask", map.HostContracts);
        Assert.Equal(CapabilityMap.Default.Stats.HostContracts + 1, map.Stats.HostContracts);
        Assert.Equal(CapabilityMap.Default.RootAttributes.ToDictionary(), map.RootAttributes.ToDictionary());
    }

    // ---------------------------------------------------------------------------------------------------
    // Determinism and Stats equality
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Load_TwiceFromTheSameInput_ProducesEqualStats()
    {
        const string text =
            """
            root-attribute Ns.StartAttribute LoadTime
            host-contract Ns.IHostTask
            host-contract Ns.*
            """;

        Assert.Equal(Map(text).Stats, Map(text).Stats);
        Assert.Equal(Map(text).Stats.GetHashCode(), Map(text).Stats.GetHashCode());
    }

    // The new counts take part in Stats equality: two maps differing only in root entries are not equal.
    [Fact]
    public void Stats_DifferingOnlyInRootCounts_AreNotEqual()
    {
        Assert.NotEqual(Map("host-contract Ns.IHostTask").Stats, Map(string.Empty).Stats);
        Assert.NotEqual(Map("root-attribute Ns.StartAttribute LoadTime").Stats, Map(string.Empty).Stats);
        Assert.NotEqual(Map("root-attribute Ns.StartAttribute LoadTime").Stats, Map("host-contract Ns.StartAttribute").Stats);
    }

    [Fact]
    public void Load_EmptyFile_HasNoRootEntries()
    {
        var map = Map(string.Empty);

        Assert.Empty(map.RootAttributes);
        Assert.Empty(map.HostContracts);
        Assert.Equal((0, 0), (map.Stats.RootAttributes, map.Stats.HostContracts));
    }

    private static CapabilityMap Map(string text, CapabilityMap? baseMap = null) =>
        CapabilityMap.Load(new StringReader(text), "test.cm", baseMap);
    #endregion
}
