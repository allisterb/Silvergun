namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// <see cref="ReflectionMap"/> (docs/agent/tasks/ssa-facts-s4.md §3, D4: the API list is data): the built-in
/// <c>Resources/reflection.rm</c>, and <see cref="ReflectionMap.Load"/>'s grammar, as the resource's header states it.
/// Pure parsing: no assemblies are read.
/// </summary>
public sealed class ReflectionMapTests
{
    #region Methods
    // ---- The built-in map ----------------------------------------------------------------------------------------------

    [Fact]
    public void Default_LoadsWithNoRejectedLines()
    {
        var map = ReflectionMap.Default;

        Assert.Empty(map.RejectedLines);
        Assert.Same(map, ReflectionMap.Default);
    }

    // The counts are re-measured from the resource's own text, not trusted from a comment: one entry per directive line,
    // each key distinct.
    [Fact]
    public void Default_Count_IsOneEntryPerDirectiveLine()
    {
        var lines = DirectiveLines();
        var lookups = lines.Where(l => l.Directive == "lookup").Select(l => l.Key).ToArray();
        var targets = lines.Where(l => l.Directive == "target").Select(l => l.Key).ToArray();
        Assert.Equal(lookups.Length, lookups.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(targets.Length, targets.Distinct(StringComparer.Ordinal).Count());

        Assert.Equal((lookups.Length, targets.Length), ReflectionMap.Default.Count);
        // As measured on 2026-11-12 (S4.3's list: 22 lookups, 17 targets).
        Assert.Equal((22, 17), ReflectionMap.Default.Count);
    }

    // A target line for a key no capability sink has would never fire: every target is a ReflectionInvocation or
    // DynamicCodeLoading sink of the built-in capability map.
    [Fact]
    public void Default_EveryTargetIsAReflectionOrLoadingSink()
    {
        var targets = DirectiveLines().Where(l => l.Directive == "target").Select(l => l.Key).ToArray();
        Assert.NotEmpty(targets);

        Assert.All(targets, key =>
        {
            Assert.NotNull(ReflectionMap.Default.Target(key));
            var verdict = CapabilityMap.Default.Classify(key);
            Assert.True(verdict.Capability is Capability.ReflectionInvocation or Capability.DynamicCodeLoading, $"{key}: {verdict}");
        });
    }

    [Fact]
    public void Default_EveryLookupLineIsALookup()
    {
        var lookups = DirectiveLines().Where(l => l.Directive == "lookup").Select(l => l.Key).ToArray();

        Assert.All(lookups, key => Assert.NotNull(ReflectionMap.Default.Lookup(key)));
    }

    [Fact]
    public void Default_GetMethod_IsAMethodLookupOfTypeAndName()
    {
        var rule = ReflectionMap.Default.Lookup("System.Type.GetMethod")!;

        Assert.Equal(ReflectionKind.Method, rule.Kind);
        AssertBindings(rule, [Part(ReflectionRole.Type, ReflectionPart.This)], [Part(ReflectionRole.Name, 0)]);
    }

    // CreateInstance's four bindings: (Type), <T>, and the two name groups.
    [Fact]
    public void Default_CreateInstance_FourBindingsWithGroupsAndAGenericArgument()
    {
        var rule = ReflectionMap.Default.Target("System.Activator.CreateInstance")!;

        Assert.Equal(ReflectionKind.Constructor, rule.Kind);
        AssertBindings(rule,
            [Part(ReflectionRole.Type, 0)],
            [new ReflectionPart(ReflectionRole.Type, 0, true)],
            [Part(ReflectionRole.Assembly, 0), Part(ReflectionRole.TypeName, 1)],
            [Part(ReflectionRole.Assembly, 1), Part(ReflectionRole.TypeName, 2)]);
    }

    // Lookups and targets are separate tables: Type.GetType is both, MethodBase.Invoke only a target, GetMethod only a
    // lookup, Assembly.Load only a lookup (it is a sink, but names no target).
    [Fact]
    public void Default_LookupsAndTargetsAreSeparate()
    {
        var map = ReflectionMap.Default;

        Assert.Equal(ReflectionKind.Type, map.Lookup("System.Type.GetType")!.Kind);
        Assert.Equal(ReflectionKind.Type, map.Target("System.Type.GetType")!.Kind);
        Assert.Null(map.Lookup("System.Reflection.MethodBase.Invoke"));
        Assert.Equal(ReflectionKind.Member, map.Target("System.Reflection.MethodBase.Invoke")!.Kind);
        Assert.Null(map.Target("System.Type.GetMethod"));
        Assert.Equal(ReflectionKind.Assembly, map.Lookup("System.Reflection.Assembly.Load")!.Kind);
        Assert.Null(map.Target("System.Reflection.Assembly.Load"));
        Assert.Null(map.Lookup(null));
        Assert.Null(map.Target(null));
        Assert.Null(map.Target("System.IO.File.ReadAllText"));
    }

    // ---- Load: accepted lines --------------------------------------------------------------------------------------------

    [Fact]
    public void Load_ValidLines_Parsed()
    {
        var map = Load(
            "# a comment",
            "",
            "   ",
            "lookup A.B Type type-name=0   # trailing comment",
            "target A.C Member member=this type=1,name=2 type=!!0");

        Assert.Empty(map.RejectedLines);
        Assert.Equal((1, 1), map.Count);
        AssertBindings(map.Lookup("A.B")!, [Part(ReflectionRole.TypeName, 0)]);
        var target = map.Target("A.C")!;
        Assert.Equal(ReflectionKind.Member, target.Kind);
        AssertBindings(target,
            [Part(ReflectionRole.Member, ReflectionPart.This)],
            [Part(ReflectionRole.Type, 1), Part(ReflectionRole.Name, 2)],
            [new ReflectionPart(ReflectionRole.Type, 0, true)]);
    }

    // Directives, kinds, roles and 'this' are case-insensitive; keys are ordinal.
    [Fact]
    public void Load_DirectiveKindRoleCaseInsensitive_KeyCaseSensitive()
    {
        var map = Load("LOOKUP A.B cOnStRuCtOr TYPE=THIS Type-Name=0", "Target A.C property MEMBER=This");

        Assert.Empty(map.RejectedLines);
        Assert.Equal(ReflectionKind.Constructor, map.Lookup("A.B")!.Kind);
        AssertBindings(map.Lookup("A.B")!, [Part(ReflectionRole.Type, ReflectionPart.This)], [Part(ReflectionRole.TypeName, 0)]);
        Assert.Equal(ReflectionKind.Property, map.Target("A.C")!.Kind);
        Assert.Null(map.Lookup("a.b"));
        Assert.Null(map.Lookup("A.b"));
    }

    // Every kind; Assembly as a lookup only.
    [Theory]
    [InlineData("Assembly")]
    [InlineData("Type")]
    [InlineData("Method")]
    [InlineData("Constructor")]
    [InlineData("Property")]
    [InlineData("Field")]
    [InlineData("Member")]
    public void Load_EveryKind_AsALookup(string kind)
    {
        var map = Load($"lookup A.B {kind} name=0");

        Assert.Empty(map.RejectedLines);
        Assert.Equal(Enum.Parse<ReflectionKind>(kind), map.Lookup("A.B")!.Kind);
        Assert.Equal(7, Enum.GetValues<ReflectionKind>().Length);
    }

    // Positions: 'this', one or two digits, '!!N' on the type role.
    [Theory]
    [InlineData("type=this", "Type", -1, false)]
    [InlineData("assembly=0", "Assembly", 0, false)]
    [InlineData("type-name=7", "TypeName", 7, false)]
    [InlineData("name=99", "Name", 99, false)]
    [InlineData("member=05", "Member", 5, false)]
    [InlineData("type=!!0", "Type", 0, true)]
    [InlineData("type=!!12", "Type", 12, true)]
    public void Load_Positions_Parsed(string binding, string role, int position, bool generic)
    {
        Assert.Equal(-1, ReflectionPart.This);

        var map = Load($"lookup A.B Type {binding}");

        Assert.Empty(map.RejectedLines);
        AssertBindings(map.Lookup("A.B")!, [new ReflectionPart(Enum.Parse<ReflectionRole>(role), position, generic)]);
    }

    // A key's last line read wins; a lookup and a target of one key do not replace each other.
    [Fact]
    public void Load_LastLineForAKeyWins()
    {
        var map = Load("lookup A.B Type type-name=0", "target A.B Method member=this", "lookup A.B Method type=this name=0");

        Assert.Equal((1, 1), map.Count);
        Assert.Equal(ReflectionKind.Method, map.Lookup("A.B")!.Kind);
        AssertBindings(map.Lookup("A.B")!, [Part(ReflectionRole.Type, ReflectionPart.This)], [Part(ReflectionRole.Name, 0)]);
        Assert.Equal(ReflectionKind.Method, map.Target("A.B")!.Kind);
    }

    // A rejected line for a key leaves its earlier line standing, and later lines still load.
    [Fact]
    public void Load_RejectedLine_KeepsTheEarlierLineAndReadsOn()
    {
        var map = Load("lookup A.B Type type-name=0", "lookup A.B Type type=x", "lookup A.C Field name=0");

        Assert.Single(map.RejectedLines);
        AssertBindings(map.Lookup("A.B")!, [Part(ReflectionRole.TypeName, 0)]);
        Assert.Equal(ReflectionKind.Field, map.Lookup("A.C")!.Kind);
    }

    // ---- Load: rejected lines --------------------------------------------------------------------------------------------

    // Each malformed line is rejected with its source, its line number and the reason, and adds nothing.
    [Theory]
    [InlineData("lookups A.B Type type=0", "unknown directive 'lookups'")]
    [InlineData("capability A.B Type type=0", "unknown directive 'capability'")]
    [InlineData("lookup A.B Type", "'lookup' takes a key, a kind and at least one binding")]
    [InlineData("TARGET A.B", "'target' takes a key, a kind and at least one binding")]
    [InlineData("lookup System.Type.* Type type=0", "malformed key 'System.Type.*'")]
    [InlineData("lookup System.* Type type=0", "malformed key 'System.*'")]
    [InlineData("lookup .A.B Type type=0", "malformed key '.A.B'")]
    [InlineData("lookup A.B. Type type=0", "malformed key 'A.B.'")]
    [InlineData("lookup NoDot Type type=0", "malformed key 'NoDot'")]
    [InlineData("lookup A.B Event type=0", "unknown kind 'Event'")]
    [InlineData("target A.B Assembly assembly=0", "a target cannot be an Assembly")]
    [InlineData("target A.B assembly assembly=0", "a target cannot be an Assembly")]
    [InlineData("lookup A.B Type typename=0", "unknown role 'typename'")]
    [InlineData("lookup A.B Type Method=0", "unknown role 'Method'")]
    [InlineData("lookup A.B Type type", "malformed binding 'type'")]
    [InlineData("lookup A.B Type =0", "malformed binding '=0'")]
    [InlineData("lookup A.B Type type=", "malformed binding 'type='")]
    [InlineData("lookup A.B Type type=0,", "malformed binding ''")]
    [InlineData("lookup A.B Type type=x", "malformed position 'x'")]
    [InlineData("lookup A.B Type type=-1", "malformed position '-1'")]
    [InlineData("lookup A.B Type type=100", "malformed position '100'")]
    [InlineData("lookup A.B Type type=1a", "malformed position '1a'")]
    [InlineData("lookup A.B Type type=!!", "malformed position '!!'")]
    [InlineData("lookup A.B Type type=!!x", "malformed position '!!x'")]
    [InlineData("lookup A.B Type type=!0", "malformed position '!0'")]
    [InlineData("lookup A.B Type name=!!0", "only the type role takes a generic argument, in 'name=!!0'")]
    [InlineData("lookup A.B Type type-name=!!0", "only the type role takes a generic argument, in 'type-name=!!0'")]
    [InlineData("lookup A.B Type assembly=!!1", "only the type role takes a generic argument, in 'assembly=!!1'")]
    [InlineData("lookup A.B Type type=0,type=1", "binding 'type=0,type=1' names a role twice")]
    [InlineData("lookup A.B Type name=0,TYPE=1,Name=2", "binding 'name=0,TYPE=1,Name=2' names a role twice")]
    [InlineData("lookup A.B Type type=0 bogus=1", "unknown role 'bogus'")]
    public void Load_MalformedLine_RejectedWithReason(string line, string reason)
    {
        var map = Load("# header", line);

        Assert.Equal([$"test.rm: (2): {reason}"], map.RejectedLines);
        Assert.Equal((0, 0), map.Count);
        Assert.Null(map.Lookup("A.B"));
        Assert.Null(map.Target("A.B"));
    }

    // Twin: a group of distinct roles is not a role named twice.
    [Fact]
    public void Load_GroupOfDistinctRoles_Accepted()
    {
        var map = Load("lookup A.B Type type=0,type-name=1,name=2,assembly=3,member=4");

        Assert.Empty(map.RejectedLines);
        Assert.Single(map.Lookup("A.B")!.Bindings);
        Assert.Equal(5, map.Lookup("A.B")!.Bindings[0].Count);
    }

    [Fact]
    public void Load_NullReader_RejectedNotThrown()
    {
        var map = ReflectionMap.Load(null!, "src");

        Assert.Equal(["src: no map source to read"], map.RejectedLines);
        Assert.Equal((0, 0), map.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Load_NoSourceName_Unnamed(string? name)
    {
        var map = ReflectionMap.Load(new StringReader("bogus"), name!);

        Assert.Equal(["<unnamed>: (1): unknown directive 'bogus'"], map.RejectedLines);
    }

    // A reader that fails mid-way: the lines read before it stand, and the failure is rejected, not thrown.
    [Fact]
    public void Load_ReaderThrows_LinesBeforeKept_FailureRejected()
    {
        var map = ReflectionMap.Load(new FailingReader("lookup A.B Type type=0"), "src");

        Assert.Equal(["src: read failed: the disk went away"], map.RejectedLines);
        Assert.NotNull(map.Lookup("A.B"));
    }

    // Line numbers count every line, comments and blanks included.
    [Fact]
    public void Load_LineNumbersCountEveryLine()
    {
        var map = Load("# one", "", "lookup A.B Type type=0", "nope", "  # five", "target A.C Type x=0");

        Assert.Equal(["test.rm: (4): unknown directive 'nope'", "test.rm: (6): unknown role 'x'"], map.RejectedLines);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static ReflectionMap Load(params string[] lines) => ReflectionMap.Load(new StringReader(string.Join("\n", lines)), "test.rm");

    private static ReflectionPart Part(ReflectionRole role, int position) => new(role, position, false);

    private static void AssertBindings(ReflectionRule rule, params ReflectionPart[][] expected)
    {
        Assert.Equal(expected.Length, rule.Bindings.Count);
        for (var i = 0; i < expected.Length; i++)
            Assert.Equal(expected[i], rule.Bindings[i]);
    }

    // The built-in resource's directive lines, read independently of the parser: the first two tokens, comments removed.
    private static (string Directive, string Key)[] DirectiveLines()
    {
        var assembly = typeof(ReflectionMap).Assembly;
        var name = Assert.Single(assembly.GetManifestResourceNames(), n => n.EndsWith("reflection.rm", StringComparison.Ordinal));
        using var reader = new StreamReader(assembly.GetManifestResourceStream(name)!);
        return [.. reader.ReadToEnd().Split('\n')
            .Select(l => (l.IndexOf('#') is var at and >= 0 ? l[..at] : l).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .Where(t => t.Length > 0)
            .Select(t => (t[0].ToLowerInvariant(), t[1]))];
    }
    #endregion

    #region Child types
    // Gives one line, then fails.
    private sealed class FailingReader(string first) : TextReader
    {
        public override string? ReadLine() => read++ == 0 ? first : throw new IOException("the disk went away");

        private int read;
    }
    #endregion
}
