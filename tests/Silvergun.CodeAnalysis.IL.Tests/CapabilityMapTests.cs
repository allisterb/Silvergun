namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Phase 1 of the capability map (docs/agent/tasks/capability-map.md): the line format's parser and the
/// most-specific-wins matcher. The map keys on plain <c>ClassificationKey</c> strings and names no CCI or
/// Analysis.Net type, so every test here is hermetic — no assembly is loaded and no runtime is initialized.
/// <para>
/// Two contracts dominate: the loader <b>never throws</b> (a bad line is skipped and counted in
/// <see cref="CapabilityMapStats.RejectedLines"/>, so a scan can never fail because of the map), and matching
/// is <b>most specific wins</b> — exact type+method, then exact type, then the longest subtree prefix — with
/// the last entry loaded winning at equal specificity so an override beats the built-in.
/// </para>
/// </summary>
public sealed class CapabilityMapTests
{
    #region Methods
    // ---------------------------------------------------------------------------------------------------
    // Parser — directives
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Load_CapabilityDirective_ClassifiesAsThatCapability()
    {
        var map = Map("capability Ns.Type Network");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Member"));
        Assert.Equal(0, map.Stats.RejectedLineCount);
    }

    [Fact]
    public void Load_SafeDirective_ClassifiesAsSafe()
    {
        var map = Map("safe Ns.Type");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Type.Member"));
        Assert.Equal(1, map.Stats.SafeEntries);
    }

    [Fact]
    public void Load_UnspecifiedDirective_ClassifiesAsUnspecified()
    {
        var map = Map("unspecified Ns.Type");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Unspecified, null), map.Classify("Ns.Type.Member"));
        Assert.Equal(1, map.Stats.UnspecifiedEntries);
    }

    [Fact]
    public void Load_UnanalyzedDirective_ClassifiesAsUnanalyzed()
    {
        var map = Map("unanalyzed Ns.Type");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Unanalyzed, null), map.Classify("Ns.Type.Member"));
        Assert.Equal(1, map.Stats.UnanalyzedEntries);
    }

    // An ignore-edge rule is an edge suppression, not a classification: it must not leak into Classify.
    [Fact]
    public void Load_IgnoreEdgeDirective_IsRecordedWithoutClassifyingEitherSide()
    {
        var map = Map("ignore-edge Ns.Caller Ns.Callee");

        Assert.Equal(1, map.Stats.IgnoredEdges);
        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Caller.Member"));
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Callee.Member"));
    }

    [Fact]
    public void Load_MixedDirectives_CountsEntriesByClass()
    {
        var map = Map(
            """
            capability Ns.A Network
            capability Ns.B FileSystem
            safe        Ns.C
            unspecified Ns.D
            unanalyzed  Ns.E
            ignore-edge Ns.A Ns.C
            """);

        Assert.Equal(2, map.Stats.CapabilityEntries);
        Assert.Equal(1, map.Stats.SafeEntries);
        Assert.Equal(1, map.Stats.UnspecifiedEntries);
        Assert.Equal(1, map.Stats.UnanalyzedEntries);
        Assert.Equal(5, map.Stats.TotalEntries);
        Assert.Equal(1, map.Stats.IgnoredEdges);
        Assert.Empty(map.Stats.RejectedLines);
    }

    // ---------------------------------------------------------------------------------------------------
    // Parser — comments, blanks and whitespace
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Load_CommentsAndBlankLines_AreIgnoredIncludingTrailingComments()
    {
        var map = Map(
            "# a leading comment\n" +
            "\n" +
            "   \n" +
            "\t\n" +
            "capability Ns.Type Network   # a trailing comment on a content line\n" +
            "   # an indented comment\n");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Member"));
        Assert.Equal(1, map.Stats.TotalEntries);
        Assert.Empty(map.Stats.RejectedLines);
    }

    [Fact]
    public void Load_EmptyFile_YieldsAnEmptyMapWithoutThrowing()
    {
        var map = Map(string.Empty);

        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(0, map.Stats.IgnoredEdges);
        Assert.Empty(map.Stats.RejectedLines);
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Member"));
    }

    [Fact]
    public void Load_WhitespaceOnlyFile_YieldsAnEmptyMapWithoutThrowing()
    {
        var map = Map("   \n\t\n \r\n\n");

        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Empty(map.Stats.RejectedLines);
    }

    // ---------------------------------------------------------------------------------------------------
    // Parser — rejections. Every one of these is counted, never thrown: a scan must survive a broken map.
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("frobnicate Ns.Type")]
    [InlineData("capabilities Ns.Type Network")]
    [InlineData("Ns.Type Network")]
    [InlineData("# not a comment marker in token position\nsafely Ns.Type")]
    public void Load_UnknownDirective_IsRejectedAndCountedNotThrown(string text)
    {
        var map = Map(text);

        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Equal(0, map.Stats.TotalEntries);
    }

    [Theory]
    [InlineData("capability Ns.Type")]                  // capability wants two arguments
    [InlineData("capability Ns.Type Network extra")]
    [InlineData("safe")]
    [InlineData("safe Ns.Type Network")]
    [InlineData("unspecified Ns.Type extra")]
    [InlineData("unanalyzed")]
    [InlineData("ignore-edge Ns.Caller")]
    [InlineData("ignore-edge Ns.Caller Ns.Callee Ns.Extra")]
    public void Load_WrongArity_IsRejectedAndCounted(string line)
    {
        var map = Map(line);

        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(0, map.Stats.IgnoredEdges);
    }

    [Fact]
    public void Load_UnknownCapabilityName_IsRejectedAndCounted()
    {
        var map = Map("capability Ns.Type Telepathy");

        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Member"));
    }

    // A numeric capability name must NOT be accepted as the enum's ordinal: "3" would silently become
    // Registry, which is a wrong finding rather than a missing one — the worse of the two failure modes.
    [Theory]
    [InlineData("3")]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("99")]
    public void Load_NumericCapabilityName_IsRejectedRatherThanParsedAsTheEnumOrdinal(string name)
    {
        var map = Map($"capability Ns.Type {name}");

        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Member"));
    }

    [Theory]
    [InlineData(".")]
    [InlineData("a.*b")]
    [InlineData("*")]
    [InlineData("*.Ns")]
    [InlineData("Ns.Type.")]
    [InlineData(".Ns.Type")]
    [InlineData(".*")]
    [InlineData("Ns.*.Type")]
    public void Load_MalformedPattern_IsRejectedAndCounted(string pattern)
    {
        var map = Map($"safe {pattern}");

        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Equal(0, map.Stats.TotalEntries);
    }

    [Theory]
    [InlineData("ignore-edge . Ns.Callee")]
    [InlineData("ignore-edge Ns.Caller *")]
    [InlineData("ignore-edge Ns.Caller Ns.Callee.")]
    public void Load_IgnoreEdgeWithMalformedPattern_IsRejectedAndCounted(string line)
    {
        var map = Map(line);

        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Equal(0, map.Stats.IgnoredEdges);
    }

    [Fact]
    public void Load_PureGarbage_YieldsAnEmptyMapAndRejectsEveryLine()
    {
        var map = Map(
            """
            {"json": true}
            <xml/>
            ¯\_(ツ)_/¯
            capability
            0110100001101001
            """);

        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(0, map.Stats.IgnoredEdges);
        Assert.Equal(5, map.Stats.RejectedLineCount);
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Member"));
    }

    // A rejection never costs the lines around it: everything else in the file still loads.
    [Fact]
    public void Load_MalformedLine_DoesNotPreventTheRestOfTheFileFromLoading()
    {
        var map = Map(
            """
            capability Ns.Before Network
            capability Ns.Broken Telepathy
            capability Ns.After FileSystem
            """);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Before.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem), map.Classify("Ns.After.Member"));
        Assert.Equal(1, map.Stats.RejectedLineCount);
        Assert.Contains("test.cm", map.Stats.RejectedLines.Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void Load_NullReader_RecordsARejectAndReturnsAnEmptyMap()
    {
        var map = CapabilityMap.Load(null!, "test.cm");

        Assert.Equal(0, map.Stats.TotalEntries);
        Assert.Equal(1, map.Stats.RejectedLineCount);
    }

    // A reader that dies part-way through is a read failure, not a parse failure: everything already parsed
    // stays, and the failure is surfaced as a reject rather than propagated to the caller.
    [Fact]
    public void Load_ReaderThatThrowsMidStream_KeepsPriorEntriesAndRecordsAReject()
    {
        var reader = new ThrowingReader("capability Ns.Before Network", "safe Ns.AlsoBefore");

        var map = CapabilityMap.Load(reader, "test.cm");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Before.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.AlsoBefore.Member"));
        Assert.Equal(2, map.Stats.TotalEntries);
        Assert.Equal(1, map.Stats.RejectedLineCount);
    }

    // ---------------------------------------------------------------------------------------------------
    // Parser — determinism
    // ---------------------------------------------------------------------------------------------------

    // Same input, same Stats — RejectedLines compared element-wise and in order, which is the loader's
    // determinism contract (CapabilityMapStats defines value equality precisely so this assertion works).
    [Fact]
    public void Load_TwiceFromTheSameInput_ProducesEqualStatsIncludingRejects()
    {
        const string text =
            """
            capability Ns.A Network
            safe Ns.B
            capability Ns.C Telepathy
            unspecified Ns.*
            bogus-directive Ns.D
            ignore-edge Ns.A Ns.B
            """;

        var first = Map(text);
        var second = Map(text);

        Assert.Equal(first.Stats, second.Stats);
        Assert.Equal(first.Stats.RejectedLines, second.Stats.RejectedLines);
        Assert.Equal(first.Stats.GetHashCode(), second.Stats.GetHashCode());
    }

    [Fact]
    public void Load_TwiceFromTheSameInput_ProducesTheSameVerdicts()
    {
        const string text =
            """
            safe Ns.*
            capability Ns.Deep.* Network
            capability Ns.Deep.Type FileSystem
            unspecified Ns.Deep.Type.Member
            """;

        string[] keys = ["Ns.Other.Member", "Ns.Deep.Other.Member", "Ns.Deep.Type.Other", "Ns.Deep.Type.Member"];

        var first = Map(text);
        var second = Map(text);

        Assert.All(keys, k => Assert.Equal(first.Classify(k), second.Classify(k)));
    }

    // ---------------------------------------------------------------------------------------------------
    // Matcher — precedence
    // ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("capability Ns.Type Network\nsafe Ns.Type.Member")]
    [InlineData("safe Ns.Type.Member\ncapability Ns.Type Network")]
    public void Classify_ExactMethodEntry_BeatsTypeEntryRegardlessOfFileOrder(string text)
    {
        var map = Map(text);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Type.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Other"));
    }

    [Theory]
    [InlineData("capability Ns.Sub.* Network\nsafe Ns.Sub.Type")]
    [InlineData("safe Ns.Sub.Type\ncapability Ns.Sub.* Network")]
    public void Classify_ExactTypeEntry_BeatsSubtreePrefixRegardlessOfFileOrder(string text)
    {
        var map = Map(text);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Sub.Type.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Sub.Other.Member"));
    }

    [Theory]
    [InlineData("safe Ns.*\ncapability Ns.Deep.* Network")]
    [InlineData("capability Ns.Deep.* Network\nsafe Ns.*")]
    public void Classify_LongestMatchingPrefix_WinsOverAShorterOne(string text)
    {
        var map = Map(text);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Deep.Type.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Shallow.Type.Member"));
    }

    // The trailing dot is load-bearing: "Ns.Prefix.*" is a subtree, and the bare type name "Ns.Prefix" is
    // outside it. Without this, a subtree entry would over-match a sibling type with a longer name.
    [Theory]
    [InlineData("Ns.Sub")]
    [InlineData("Ns.Subtle.Member")]
    [InlineData("Ns.SubClass")]
    public void Classify_KeyThatOnlyNearlyMatchesASubtreePrefix_DoesNotMatch(string key)
    {
        var map = Map("capability Ns.Sub.* Network");

        Assert.Equal(CapabilityVerdict.None, map.Classify(key));
    }

    // A metadata method name begins with a dot, so a constructor key renders as "Ns.Type..ctor". Both the
    // ctor-specific entry and the fall-back to its declaring type must resolve through the doubled dot.
    [Fact]
    public void Classify_ConstructorKey_ResolvesTheCtorEntryAndItsDeclaringType()
    {
        var map = Map(
            """
            capability Ns.Type..ctor FileSystem
            safe Ns.Other
            """);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem), map.Classify("Ns.Type..ctor"));
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Write"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Other..ctor"));
    }

    // ---------------------------------------------------------------------------------------------------
    // Matcher — the two behaviours the data file's header documents (Resources/capabilities.cm)
    // ---------------------------------------------------------------------------------------------------

    // A TYPE ENTRY DOES NOT COVER NESTED TYPES: matching strips exactly ONE trailing segment, while a
    // ClassificationKey renders nesting with '.', so "Ns.Type" reaches "Ns.Type.Member" but not
    // "Ns.Type.Nested.Member". This is a deliberate tightening of the legacy StartsWith behaviour, and it is
    // why a map author must write "Ns.Type.*" when a nested type has to be covered.
    [Fact]
    public void Classify_TypeEntry_CoversItsOwnMembersButNotThoseOfANestedType()
    {
        var map = Map("capability Ns.Type Network");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Member"));
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Nested.Member"));
        Assert.Equal(CapabilityVerdict.None, map.Classify("Ns.Type.Nested.Deeper.Member"));
    }

    // ...and the documented remedy works: the subtree form does reach the nested type.
    [Fact]
    public void Classify_SubtreeEntry_CoversNestedTypesThatATypeEntryWouldMiss()
    {
        var map = Map("capability Ns.Type.* Network");

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Nested.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Member"));
    }

    // CASE SENSITIVITY IS ASYMMETRIC, half one: directive keywords and capability names are matched
    // case-insensitively, so an oddly-cased but otherwise valid line still loads.
    [Theory]
    [InlineData("CAPABILITY Ns.Type filesystem")]
    [InlineData("Capability Ns.Type FILESYSTEM")]
    [InlineData("capability Ns.Type fileSystem")]
    public void Load_DirectiveKeywordAndCapabilityName_AreMatchedCaseInsensitively(string line)
    {
        var map = Map(line);

        Assert.Equal(0, map.Stats.RejectedLineCount);
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem), map.Classify("Ns.Type.Member"));
    }

    // ...half two, and the dangerous half: PATTERNS are compared ordinal case-SENSITIVELY, so a mis-cased
    // pattern loads cleanly and then silently matches nothing.
    [Theory]
    [InlineData("ns.type.M")]
    [InlineData("NS.TYPE.M")]
    [InlineData("Ns.type.M")]
    [InlineData("ns.Type.M")]
    public void Classify_MiscasedKey_DoesNotMatchAPatternThatDiffersOnlyInCase(string key)
    {
        var map = Map("capability Ns.Type Network");

        Assert.Equal(CapabilityVerdict.None, map.Classify(key));

        // Proof the entry itself is live: only the casing is what kept the key above from matching.
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.M"));
    }

    // The same ordinal comparison governs subtree prefixes.
    [Fact]
    public void Classify_MiscasedKey_DoesNotMatchASubtreePrefixThatDiffersOnlyInCase()
    {
        var map = Map("safe Ns.Sub.*");

        Assert.Equal(CapabilityVerdict.None, map.Classify("ns.sub.Type.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Sub.Type.Member"));
    }

    [Theory]
    [InlineData("capability Ns.Type Network\ncapability Ns.Type FileSystem", "Ns.Type.Member")]
    [InlineData("capability Ns.Sub.* Network\ncapability Ns.Sub.* FileSystem", "Ns.Sub.Type.Member")]
    [InlineData("safe Ns.Type.Member\ncapability Ns.Type.Member FileSystem", "Ns.Type.Member")]
    public void Classify_DuplicateKey_ResolvesToTheLastEntryLoaded(string text, string key)
    {
        var map = Map(text);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem), map.Classify(key));
        Assert.Equal(1, map.Stats.TotalEntries);   // the override replaces, it does not accumulate
    }

    [Fact]
    public void Classify_KeyMatchingNothing_ReturnsNone()
    {
        var map = Map("capability Ns.Type Network");

        Assert.Equal(CapabilityVerdict.None, map.Classify("Other.Type.Member"));
        Assert.Equal(CapabilityClass.None, map.Classify("Other.Type.Member").Class);
        Assert.Null(map.Classify("Other.Type.Member").Capability);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void Classify_NullOrBlankKey_ReturnsNoneWithoutThrowing(string? key)
    {
        var map = Map("safe Ns.*");

        Assert.Equal(CapabilityVerdict.None, map.Classify(key!));
    }

    // ---------------------------------------------------------------------------------------------------
    // Matcher — layering an override over a base map
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Load_OverrideOverBase_ReplacesMatchingEntriesAndKeepsTheRest()
    {
        var baseMap = Map(
            """
            capability Ns.Overridden Network
            capability Ns.Untouched Registry
            safe Ns.Sub.*
            """);

        var map = Map(
            """
            capability Ns.Overridden FileSystem
            unanalyzed Ns.Added
            """,
            baseMap);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.FileSystem), map.Classify("Ns.Overridden.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Registry), map.Classify("Ns.Untouched.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Safe, null), map.Classify("Ns.Sub.Type.Member"));
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Unanalyzed, null), map.Classify("Ns.Added.Member"));

        // The base map itself is unaffected — layering produces a new map rather than mutating the base.
        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), baseMap.Classify("Ns.Overridden.Member"));
    }

    [Fact]
    public void Load_OverrideOverBase_KeepsBaseIgnoredEdgesAndAddsItsOwn()
    {
        var baseMap = Map("ignore-edge Ns.A Ns.B");

        var map = Map("ignore-edge Ns.C Ns.D", baseMap);

        Assert.Equal(2, map.Stats.IgnoredEdges);
        Assert.True(map.IsIgnoredEdge("Ns.A.Member", "Ns.B.Member"));
        Assert.True(map.IsIgnoredEdge("Ns.C.Member", "Ns.D.Member"));
    }

    [Fact]
    public void Load_OverrideOverBase_PreservesTheBaseMapsRejectedLines()
    {
        var baseMap = Map("capability Ns.Broken Telepathy");
        Assert.Equal(1, baseMap.Stats.RejectedLineCount);

        var clean = Map("safe Ns.Fine", baseMap);
        var alsoBroken = Map("safe Ns.Type.", baseMap);

        Assert.Equal(baseMap.Stats.RejectedLines, clean.Stats.RejectedLines);
        Assert.Equal(2, alsoBroken.Stats.RejectedLineCount);
    }

    // A wholly unparseable override leaves the base map's classifications intact — the phase 1 constraint
    // that a broken user map degrades to the built-in rather than disabling classification.
    [Fact]
    public void Load_WhollyUnparseableOverride_LeavesTheBaseMapsClassificationsInPlace()
    {
        var baseMap = Map("capability Ns.Type Network");

        var map = Map("garbage\nmore garbage\ncapability\n", baseMap);

        Assert.Equal(new CapabilityVerdict(CapabilityClass.Capability, Capability.Network), map.Classify("Ns.Type.Member"));
        Assert.Equal(3, map.Stats.RejectedLineCount);
    }

    // ---------------------------------------------------------------------------------------------------
    // ignore-edge round-trips
    // ---------------------------------------------------------------------------------------------------

    [Fact]
    public void IsIgnoredEdge_ExactMethodPatternsOnBothSides_RoundTrips()
    {
        var map = Map("ignore-edge Ns.Caller.Invoke Ns.Callee.Run");

        Assert.True(map.IsIgnoredEdge("Ns.Caller.Invoke", "Ns.Callee.Run"));
        Assert.False(map.IsIgnoredEdge("Ns.Caller.Other", "Ns.Callee.Run"));
        Assert.False(map.IsIgnoredEdge("Ns.Caller.Invoke", "Ns.Callee.Other"));
    }

    [Fact]
    public void IsIgnoredEdge_TypePatternsOnBothSides_MatchAnyMemberOfThoseTypes()
    {
        var map = Map("ignore-edge Ns.Caller Ns.Callee");

        Assert.True(map.IsIgnoredEdge("Ns.Caller.Invoke", "Ns.Callee.Run"));
        Assert.True(map.IsIgnoredEdge("Ns.Caller..ctor", "Ns.Callee..ctor"));
        Assert.False(map.IsIgnoredEdge("Ns.Caller.Invoke", "Ns.Elsewhere.Run"));
    }

    [Fact]
    public void IsIgnoredEdge_SubtreePatternsOnBothSides_MatchAnythingInThoseSubtrees()
    {
        var map = Map("ignore-edge Ns.Callers.* Ns.Callees.*");

        Assert.True(map.IsIgnoredEdge("Ns.Callers.Deep.Type.Invoke", "Ns.Callees.Other.Type.Run"));
        Assert.False(map.IsIgnoredEdge("Ns.Callers", "Ns.Callees.Type.Run"));       // near-miss: no trailing dot
        Assert.False(map.IsIgnoredEdge("Ns.Callers.Type.Invoke", "Ns.Callees"));
    }

    [Fact]
    public void IsIgnoredEdge_MixedPatternForms_RoundTrip()
    {
        var map = Map("ignore-edge Ns.Callers.* Ns.Callee.Run");

        Assert.True(map.IsIgnoredEdge("Ns.Callers.Type.Invoke", "Ns.Callee.Run"));
        Assert.False(map.IsIgnoredEdge("Ns.Callers.Type.Invoke", "Ns.Callee.Other"));
    }

    [Theory]
    [InlineData(null, "Ns.Callee.Run")]
    [InlineData("Ns.Caller.Invoke", null)]
    [InlineData("", "Ns.Callee.Run")]
    [InlineData("Ns.Caller.Invoke", "   ")]
    public void IsIgnoredEdge_NullOrBlankKey_ReturnsFalseWithoutThrowing(string? caller, string? callee)
    {
        var map = Map("ignore-edge Ns.Caller.Invoke Ns.Callee.Run");

        Assert.False(map.IsIgnoredEdge(caller!, callee!));
    }

    [Fact]
    public void IsIgnoredEdge_OnAMapWithNoRules_IsAlwaysFalse()
    {
        var map = Map("capability Ns.Type Network");

        Assert.False(map.IsIgnoredEdge("Ns.Caller.Invoke", "Ns.Type.Member"));
    }

    private static CapabilityMap Map(string text, CapabilityMap? baseMap = null) =>
        CapabilityMap.Load(new StringReader(text), "test.cm", baseMap);
    #endregion

    #region Child types
    // A TextReader that yields a few lines and then fails, standing in for a truncated or unreadable stream.
    private sealed class ThrowingReader(params string[] lines) : TextReader
    {
        #region Methods
        public override string? ReadLine() =>
            index < lines.Length ? lines[index++] : throw new IOException("the stream went away");
        #endregion

        #region Fields
        private int index;
        #endregion
    }
    #endregion
}
