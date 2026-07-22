namespace Silvergun.PackageAnalysis.NuGet.Tests;

using System.Linq;

using Silvergun.PackageAnalysis.NuGet.Yara;

using Xunit;

/// <summary>
/// Unit tests for <see cref="YaraRuleIndex.ParseSource"/> and <see cref="YaraRuleIndex.Lookup"/> (ADR 0016 /
/// task <c>docs/agent/tasks/yara-scanning.md</c>, Phase 2). The index reads each embedded <c>.yara</c> source's
/// <c>meta:</c> block into <c>ruleName → </c><see cref="YaraRuleInfo"/> (malware family / detection name /
/// category / description). A rule without a <c>meta:</c> block is absent from the index, numeric meta values
/// are ignored, and parsing is defensive — garbage yields nothing and never throws.
/// </summary>
public sealed class YaraRuleIndexTests
{
    #region Methods
    // A ReversingLabs-style rule maps its four string meta keys onto the YaraRuleInfo fields; the numeric
    // tc_detection_factor is ignored (only quoted values are read).
    [Fact]
    public void ParseSource_RuleWithMetaBlock_MapsAllFields()
    {
        var source =
            "rule Win32_Trojan_Foo : trojan\n" +
            "{\n" +
            "    meta:\n" +
            "        malware = \"Foo\"\n" +
            "        tc_detection_name = \"Trojan.Win32.Foo\"\n" +
            "        category = \"MALWARE\"\n" +
            "        description = \"Detects the Foo trojan\"\n" +
            "        tc_detection_factor = 5\n" +
            "    strings:\n" +
            "        $a = \"bar\"\n" +
            "    condition:\n" +
            "        $a\n" +
            "}\n";

        var (name, info) = Assert.Single(YaraRuleIndex.ParseSource(source));

        Assert.Equal("Win32_Trojan_Foo", name);
        Assert.Equal("Foo", info.MalwareFamily);
        Assert.Equal("Trojan.Win32.Foo", info.DetectionName);
        Assert.Equal("MALWARE", info.Category);
        Assert.Equal("Detects the Foo trojan", info.Description);
    }

    // Tags after the rule-name colon are consumed by the parser and do not disturb the metadata mapping.
    [Fact]
    public void ParseSource_RuleWithTagsAfterColon_StillParsesMeta()
    {
        var source =
            "rule Tagged_Rule : suspicious packer\n" +
            "{\n" +
            "    meta:\n" +
            "        malware = \"Packed\"\n" +
            "    condition:\n" +
            "        true\n" +
            "}\n";

        var (name, info) = Assert.Single(YaraRuleIndex.ParseSource(source));

        Assert.Equal("Tagged_Rule", name);
        Assert.Equal("Packed", info.MalwareFamily);
    }

    // A rule with no meta: block is omitted from the parsed results entirely.
    [Fact]
    public void ParseSource_RuleWithoutMetaBlock_IsOmitted()
    {
        var source =
            "rule No_Meta_Rule\n" +
            "{\n" +
            "    strings:\n" +
            "        $a = \"x\"\n" +
            "    condition:\n" +
            "        $a\n" +
            "}\n";

        Assert.Empty(YaraRuleIndex.ParseSource(source));
    }

    // Missing individual keys stay null; only the declared string keys are populated.
    [Fact]
    public void ParseSource_PartialMeta_LeavesMissingFieldsNull()
    {
        var source =
            "rule Partial\n" +
            "{\n" +
            "    meta:\n" +
            "        category = \"PUA\"\n" +
            "    condition:\n" +
            "        true\n" +
            "}\n";

        var (_, info) = Assert.Single(YaraRuleIndex.ParseSource(source));

        Assert.Null(info.MalwareFamily);
        Assert.Null(info.DetectionName);
        Assert.Equal("PUA", info.Category);
        Assert.Null(info.Description);
    }

    // Multiple rules in one source each yield their own entry, in declaration order.
    [Fact]
    public void ParseSource_MultipleRules_YieldsEachRule()
    {
        var source =
            "rule First\n{\n    meta:\n        malware = \"One\"\n    condition:\n        true\n}\n" +
            "rule Second\n{\n    meta:\n        malware = \"Two\"\n    condition:\n        true\n}\n";

        var results = YaraRuleIndex.ParseSource(source).ToList();

        Assert.Equal(2, results.Count);
        Assert.Equal("First", results[0].Name);
        Assert.Equal("One", results[0].Info.MalwareFamily);
        Assert.Equal("Second", results[1].Name);
        Assert.Equal("Two", results[1].Info.MalwareFamily);
    }

    // Null, empty and garbage sources yield nothing and never throw.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("this is not a yara rule { nonsense }")]
    public void ParseSource_EmptyOrGarbage_ReturnsEmpty(string? source)
    {
        Assert.Empty(YaraRuleIndex.ParseSource(source));
    }

    // Lookup of an unknown rule name returns null (the finding keeps only its rule name).
    [Fact]
    public void Lookup_UnknownRule_ReturnsNull()
    {
        var index = YaraRuleIndex.Build();

        Assert.Null(index.Lookup("a_rule_that_does_not_exist_xyz_123"));
    }

    // Lookup of a null rule name returns null without throwing.
    [Fact]
    public void Lookup_NullRuleName_ReturnsNull()
    {
        var index = YaraRuleIndex.Build();

        Assert.Null(index.Lookup(null));
    }
    #endregion
}
